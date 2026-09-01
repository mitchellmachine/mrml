//! Immutable cache for exact Git pack representations.
//!
//! A hit requires equality of the complete canonical key. The digest accelerates
//! rejection but is never treated as sufficient identity. Candidate discovery,
//! adaptive codec selection, and storage-location ranking are deliberately out
//! of scope.

use mrml_crypto::Sha256;
use mrml_runtime::Vector;

use crate::{ObjectFormat, ObjectId, RepositoryGeneration};

pub const MAX_PACK_CACHE_OBJECTS_PER_SIDE: usize = 65_536;
pub const MAX_PACK_CACHE_KEY_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PACK_CACHE_ENTRIES: usize = 1_024;
pub const MAX_CACHED_PACK_BYTES: usize = 512 * 1024 * 1024;

const KEY_DOMAIN: &[u8; 8] = b"MRPCKEY1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackCacheError {
    Resource,
    ObjectFormat,
    InvalidVersion,
    AlreadyExists,
    Integrity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackCacheKey {
    object_format: ObjectFormat,
    wants: Vector<ObjectId>,
    haves: Vector<ObjectId>,
    repository_generation: RepositoryGeneration,
    pack_profile_version: u32,
    encoder_version: u32,
    digest: [u8; 32],
}

impl PackCacheKey {
    pub fn new(
        object_format: ObjectFormat,
        wants: Vector<ObjectId>,
        haves: Vector<ObjectId>,
        repository_generation: RepositoryGeneration,
        pack_profile_version: u32,
        encoder_version: u32,
    ) -> Result<Self, PackCacheError> {
        if wants.len() > MAX_PACK_CACHE_OBJECTS_PER_SIDE
            || haves.len() > MAX_PACK_CACHE_OBJECTS_PER_SIDE
        {
            return Err(PackCacheError::Resource);
        }
        if pack_profile_version == 0 || encoder_version == 0 {
            return Err(PackCacheError::InvalidVersion);
        }
        if wants
            .iter()
            .chain(haves.iter())
            .any(|id| id.format() != object_format)
        {
            return Err(PackCacheError::ObjectFormat);
        }
        let encoded = encode_key(
            object_format,
            &wants,
            &haves,
            repository_generation,
            pack_profile_version,
            encoder_version,
        )?;
        Ok(Self {
            object_format,
            wants,
            haves,
            repository_generation,
            pack_profile_version,
            encoder_version,
            digest: Sha256::digest(&encoded),
        })
    }

    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub const fn object_format(&self) -> ObjectFormat {
        self.object_format
    }

    pub fn wants(&self) -> &[ObjectId] {
        &self.wants
    }

    pub fn haves(&self) -> &[ObjectId] {
        &self.haves
    }

    pub const fn repository_generation(&self) -> RepositoryGeneration {
        self.repository_generation
    }

    pub const fn pack_profile_version(&self) -> u32 {
        self.pack_profile_version
    }

    pub const fn encoder_version(&self) -> u32 {
        self.encoder_version
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Entry {
    key: PackCacheKey,
    representation: Vector<u8>,
    representation_digest: [u8; 32],
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImmutablePackCache {
    entries: Vector<Entry>,
}

impl ImmutablePackCache {
    pub const fn new() -> Self {
        Self {
            entries: Vector::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Inserts a representation once. Even identical reinsertion is rejected,
    /// making mutation and overwrite attempts indistinguishable to callers.
    pub fn insert(
        &mut self,
        key: PackCacheKey,
        representation: Vector<u8>,
    ) -> Result<(), PackCacheError> {
        if representation.len() > MAX_CACHED_PACK_BYTES {
            return Err(PackCacheError::Resource);
        }
        if self.entries.len() >= MAX_PACK_CACHE_ENTRIES {
            return Err(PackCacheError::Resource);
        }
        if self
            .entries
            .iter()
            .any(|entry| entry.key.digest == key.digest && entry.key == key)
        {
            return Err(PackCacheError::AlreadyExists);
        }
        let representation_digest = Sha256::digest(&representation);
        self.entries.push(Entry {
            key,
            representation,
            representation_digest,
        });
        Ok(())
    }

    /// Returns only an exact full-key match and authenticates cached bytes on
    /// every read, rejecting corruption rather than returning suspect data.
    pub fn lookup(&self, key: &PackCacheKey) -> Result<Option<&[u8]>, PackCacheError> {
        let Some(entry) = self
            .entries
            .iter()
            .find(|entry| entry.key.digest == key.digest && entry.key == *key)
        else {
            return Ok(None);
        };
        if Sha256::digest(&entry.representation) != entry.representation_digest {
            return Err(PackCacheError::Integrity);
        }
        Ok(Some(&entry.representation))
    }
}

fn encode_key(
    object_format: ObjectFormat,
    wants: &[ObjectId],
    haves: &[ObjectId],
    repository_generation: RepositoryGeneration,
    pack_profile_version: u32,
    encoder_version: u32,
) -> Result<Vector<u8>, PackCacheError> {
    let object_bytes = wants
        .len()
        .checked_add(haves.len())
        .and_then(|count| count.checked_mul(object_format.hash_len()))
        .ok_or(PackCacheError::Resource)?;
    let capacity = KEY_DOMAIN
        .len()
        .checked_add(1 + 8 + 4 + 4 + 4 + 4)
        .and_then(|fixed| fixed.checked_add(object_bytes))
        .ok_or(PackCacheError::Resource)?;
    if capacity > MAX_PACK_CACHE_KEY_BYTES {
        return Err(PackCacheError::Resource);
    }
    let mut encoded = Vector::new();
    encoded
        .try_reserve_exact(capacity)
        .map_err(|_| PackCacheError::Resource)?;
    encoded.extend(KEY_DOMAIN.iter().copied());
    encoded.push(match object_format {
        ObjectFormat::Sha1 => 1,
        ObjectFormat::Sha256 => 2,
    });
    encoded.extend(repository_generation.0.to_be_bytes());
    encoded.extend(pack_profile_version.to_be_bytes());
    encoded.extend(encoder_version.to_be_bytes());
    encoded.extend(
        u32::try_from(wants.len())
            .map_err(|_| PackCacheError::Resource)?
            .to_be_bytes(),
    );
    for id in wants {
        encoded.extend(id.as_bytes().iter().copied());
    }
    encoded.extend(
        u32::try_from(haves.len())
            .map_err(|_| PackCacheError::Resource)?
            .to_be_bytes(),
    );
    for id in haves {
        encoded.extend(id.as_bytes().iter().copied());
    }
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(wants: &[u8], haves: &[u8], generation: u64) -> PackCacheKey {
        PackCacheKey::new(
            ObjectFormat::Sha256,
            wants
                .iter()
                .map(|byte| ObjectId::Sha256([*byte; 32]))
                .collect(),
            haves
                .iter()
                .map(|byte| ObjectId::Sha256([*byte; 32]))
                .collect(),
            RepositoryGeneration(generation),
            1,
            7,
        )
        .unwrap()
    }

    #[test]
    fn exact_ordered_key_controls_hits() {
        let exact = key(&[1, 2], &[3], 9);
        let reordered = key(&[2, 1], &[3], 9);
        let new_generation = key(&[1, 2], &[3], 10);
        assert_ne!(exact.digest(), reordered.digest());
        assert_ne!(exact.digest(), new_generation.digest());

        let mut cache = ImmutablePackCache::new();
        cache
            .insert(exact.clone(), Vector::from(*b"PACK representation"))
            .unwrap();
        assert_eq!(
            cache.lookup(&exact).unwrap(),
            Some(b"PACK representation".as_slice())
        );
        assert_eq!(cache.lookup(&reordered).unwrap(), None);
        assert_eq!(cache.lookup(&new_generation).unwrap(), None);
    }

    #[test]
    fn versions_and_format_are_bound() {
        let base = key(&[1], &[], 4);
        let profile = PackCacheKey::new(
            ObjectFormat::Sha256,
            Vector::from([ObjectId::Sha256([1; 32])]),
            Vector::new(),
            RepositoryGeneration(4),
            2,
            7,
        )
        .unwrap();
        let encoder = PackCacheKey::new(
            ObjectFormat::Sha256,
            Vector::from([ObjectId::Sha256([1; 32])]),
            Vector::new(),
            RepositoryGeneration(4),
            1,
            8,
        )
        .unwrap();
        assert_ne!(base.digest(), profile.digest());
        assert_ne!(base.digest(), encoder.digest());
        assert_eq!(
            PackCacheKey::new(
                ObjectFormat::Sha1,
                Vector::from([ObjectId::Sha256([1; 32])]),
                Vector::new(),
                RepositoryGeneration(4),
                1,
                7,
            ),
            Err(PackCacheError::ObjectFormat)
        );
    }

    #[test]
    fn insert_is_immutable_and_tampering_fails_closed() {
        let exact = key(&[1], &[2], 3);
        let mut cache = ImmutablePackCache::new();
        cache
            .insert(exact.clone(), Vector::from(*b"first"))
            .unwrap();
        assert_eq!(
            cache.insert(exact.clone(), Vector::from(*b"replacement")),
            Err(PackCacheError::AlreadyExists)
        );
        assert_eq!(cache.lookup(&exact).unwrap(), Some(b"first".as_slice()));

        cache.entries[0].representation[0] ^= 1;
        assert_eq!(cache.lookup(&exact), Err(PackCacheError::Integrity));
    }

    #[test]
    fn rejects_unbounded_and_invalid_inputs() {
        assert_eq!(
            PackCacheKey::new(
                ObjectFormat::Sha256,
                Vector::new(),
                Vector::new(),
                RepositoryGeneration(1),
                0,
                1,
            ),
            Err(PackCacheError::InvalidVersion)
        );
        let too_many: Vector<ObjectId> = (0..=MAX_PACK_CACHE_OBJECTS_PER_SIDE)
            .map(|_| ObjectId::Sha256([1; 32]))
            .collect();
        assert_eq!(
            PackCacheKey::new(
                ObjectFormat::Sha256,
                too_many,
                Vector::new(),
                RepositoryGeneration(1),
                1,
                1,
            ),
            Err(PackCacheError::Resource)
        );
    }
}
