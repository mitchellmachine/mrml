//! Canonical inactive pack-set manifest prerequisite.

use mrml_crypto::Sha256;
use mrml_runtime::Vector;

use crate::{
    ObjectFormat, ObjectId, PackGeneration, QuarantineTransactionId, RepositoryGeneration,
    RepositoryIdentity,
};

const MAGIC: &[u8; 8] = b"MRPKSET1";
const DIGEST_BYTES: usize = 32;
pub const MAX_PACK_SET_MANIFEST_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackSetLimits {
    pub max_packs: u32,
    pub max_objects: u64,
    pub max_pack_bytes: u64,
    pub max_index_bytes: u64,
    pub max_work_units: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackSetError {
    Malformed,
    Integrity,
    Resource,
    DuplicateObject,
    NonCanonical,
}

#[allow(dead_code)] // constructed by the future atomic pack-generation activation gate
pub(crate) struct AuthenticatedPackIndexSummary {
    pub transaction: QuarantineTransactionId,
    pub object_count: u32,
    pub pack_checksum: ObjectId,
    pub index_checksum: ObjectId,
    pub pack_bytes: u64,
    pub index_bytes: u64,
    pub work_units: u64,
    pub object_ids: Vector<ObjectId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackSetEntry {
    transaction: QuarantineTransactionId,
    object_count: u32,
    pack_checksum: ObjectId,
    index_checksum: ObjectId,
    pack_bytes: u64,
    index_bytes: u64,
    work_units: u64,
    object_ids: Vector<ObjectId>,
}

impl PackSetEntry {
    pub const fn transaction(&self) -> QuarantineTransactionId {
        self.transaction
    }
    pub const fn object_count(&self) -> u32 {
        self.object_count
    }
    pub const fn pack_checksum(&self) -> ObjectId {
        self.pack_checksum
    }
    pub const fn index_checksum(&self) -> ObjectId {
        self.index_checksum
    }
    pub const fn pack_bytes(&self) -> u64 {
        self.pack_bytes
    }
    pub const fn index_bytes(&self) -> u64 {
        self.index_bytes
    }
    pub const fn work_units(&self) -> u64 {
        self.work_units
    }
    pub fn object_ids(&self) -> &[ObjectId] {
        &self.object_ids
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackSetManifest {
    repository: RepositoryIdentity,
    repository_generation: RepositoryGeneration,
    pack_generation: PackGeneration,
    object_format: ObjectFormat,
    entries: Vector<PackSetEntry>,
}

impl PackSetManifest {
    pub fn repository(&self) -> &RepositoryIdentity {
        &self.repository
    }
    pub const fn repository_generation(&self) -> RepositoryGeneration {
        self.repository_generation
    }
    pub const fn pack_generation(&self) -> PackGeneration {
        self.pack_generation
    }
    pub const fn object_format(&self) -> ObjectFormat {
        self.object_format
    }
    pub fn entries(&self) -> &[PackSetEntry] {
        &self.entries
    }
    pub fn digest(&self) -> Result<[u8; 32], PackSetError> {
        let encoded = encode_pack_set_manifest(self)?;
        Ok(encoded[encoded.len() - DIGEST_BYTES..]
            .try_into()
            .map_err(|_| PackSetError::Malformed)?)
    }
}

#[allow(dead_code)] // construction remains private until its digest is active-state-bound
pub(crate) fn build_pack_set_manifest(
    repository: RepositoryIdentity,
    repository_generation: RepositoryGeneration,
    pack_generation: PackGeneration,
    object_format: ObjectFormat,
    summaries: Vector<AuthenticatedPackIndexSummary>,
    limits: PackSetLimits,
) -> Result<PackSetManifest, PackSetError> {
    let mut entries = Vector::new();
    for summary in summaries {
        entries.push(PackSetEntry {
            transaction: summary.transaction,
            object_count: summary.object_count,
            pack_checksum: summary.pack_checksum,
            index_checksum: summary.index_checksum,
            pack_bytes: summary.pack_bytes,
            index_bytes: summary.index_bytes,
            work_units: summary.work_units,
            object_ids: summary.object_ids,
        });
    }
    let manifest = PackSetManifest {
        repository,
        repository_generation,
        pack_generation,
        object_format,
        entries,
    };
    validate(&manifest, limits)?;
    Ok(manifest)
}

pub fn encode_pack_set_manifest(manifest: &PackSetManifest) -> Result<Vector<u8>, PackSetError> {
    validate(manifest, unlimited_limits())?;
    let mut out = Vector::new();
    put(&mut out, MAGIC)?;
    put_u16(&mut out, manifest.repository.as_str().len())?;
    put(&mut out, manifest.repository.as_str().as_bytes())?;
    put(&mut out, &manifest.repository_generation.0.to_be_bytes())?;
    put(&mut out, &manifest.pack_generation.0.to_be_bytes())?;
    out.push(match manifest.object_format {
        ObjectFormat::Sha1 => 1,
        ObjectFormat::Sha256 => 2,
    });
    put(&mut out, &(manifest.entries.len() as u32).to_be_bytes())?;
    for entry in &manifest.entries {
        put(&mut out, &entry.transaction.0)?;
        put(&mut out, &entry.object_count.to_be_bytes())?;
        put(&mut out, entry.pack_checksum.as_bytes())?;
        put(&mut out, entry.index_checksum.as_bytes())?;
        put(&mut out, &entry.pack_bytes.to_be_bytes())?;
        put(&mut out, &entry.index_bytes.to_be_bytes())?;
        put(&mut out, &entry.work_units.to_be_bytes())?;
        for id in &entry.object_ids {
            put(&mut out, id.as_bytes())?;
        }
    }
    if out
        .len()
        .checked_add(DIGEST_BYTES)
        .ok_or(PackSetError::Resource)?
        > MAX_PACK_SET_MANIFEST_BYTES
    {
        return Err(PackSetError::Resource);
    }
    let digest = Sha256::digest(&out);
    put(&mut out, &digest)?;
    Ok(out)
}

pub fn parse_pack_set_manifest(
    input: &[u8],
    limits: PackSetLimits,
) -> Result<PackSetManifest, PackSetError> {
    if input.len() < MAGIC.len() + DIGEST_BYTES || input.len() > MAX_PACK_SET_MANIFEST_BYTES {
        return Err(PackSetError::Malformed);
    }
    let body = input.len() - DIGEST_BYTES;
    if Sha256::digest(&input[..body]) != input[body..] {
        return Err(PackSetError::Integrity);
    }
    let mut c = Cursor {
        bytes: &input[..body],
        at: 0,
    };
    if c.take(8)? != MAGIC {
        return Err(PackSetError::Malformed);
    }
    let name_len = usize::from(c.u16()?);
    let name = core::str::from_utf8(c.take(name_len)?).map_err(|_| PackSetError::Malformed)?;
    let repository = RepositoryIdentity::parse(name).map_err(|_| PackSetError::Malformed)?;
    let repository_generation = RepositoryGeneration(c.u64()?);
    let pack_generation = PackGeneration(c.u64()?);
    let object_format = match c.u8()? {
        1 => ObjectFormat::Sha1,
        2 => ObjectFormat::Sha256,
        _ => return Err(PackSetError::Malformed),
    };
    let count = usize::try_from(c.u32()?).map_err(|_| PackSetError::Resource)?;
    if count == 0 || count > limits.max_packs as usize {
        return Err(PackSetError::Resource);
    }
    let mut entries = Vector::new();
    let mut parsed_objects = 0u64;
    for _ in 0..count {
        let mut transaction = [0; 16];
        transaction.copy_from_slice(c.take(16)?);
        let object_count = c.u32()?;
        parsed_objects = parsed_objects
            .checked_add(u64::from(object_count))
            .ok_or(PackSetError::Resource)?;
        if object_count == 0 || parsed_objects > limits.max_objects {
            return Err(PackSetError::Resource);
        }
        let pack_checksum = ObjectId::from_bytes(object_format, c.take(object_format.hash_len())?)
            .ok_or(PackSetError::Malformed)?;
        let index_checksum = ObjectId::from_bytes(object_format, c.take(object_format.hash_len())?)
            .ok_or(PackSetError::Malformed)?;
        let pack_bytes = c.u64()?;
        let index_bytes = c.u64()?;
        let work_units = c.u64()?;
        let mut object_ids = Vector::new();
        for _ in 0..object_count {
            object_ids.push(
                ObjectId::from_bytes(object_format, c.take(object_format.hash_len())?)
                    .ok_or(PackSetError::Malformed)?,
            );
        }
        entries.push(PackSetEntry {
            transaction: QuarantineTransactionId(transaction),
            object_count,
            pack_checksum,
            index_checksum,
            pack_bytes,
            index_bytes,
            work_units,
            object_ids,
        });
    }
    if c.at != c.bytes.len() {
        return Err(PackSetError::Malformed);
    }
    let manifest = PackSetManifest {
        repository,
        repository_generation,
        pack_generation,
        object_format,
        entries,
    };
    validate(&manifest, limits)?;
    if &*encode_pack_set_manifest(&manifest)? != input {
        return Err(PackSetError::NonCanonical);
    }
    Ok(manifest)
}

fn validate(m: &PackSetManifest, l: PackSetLimits) -> Result<(), PackSetError> {
    if m.repository_generation.0 == 0
        || m.pack_generation.0 == 0
        || m.entries.is_empty()
        || m.entries.len() > l.max_packs as usize
    {
        return Err(PackSetError::Resource);
    }
    let mut objects = 0u64;
    let mut pack_bytes = 0u64;
    let mut index_bytes = 0u64;
    let mut work = 0u64;
    let mut all = Vector::new();
    for (i, e) in m.entries.iter().enumerate() {
        if e.object_count == 0
            || e.object_ids.len() != e.object_count as usize
            || e.pack_checksum.is_zero()
            || e.index_checksum.is_zero()
            || e.pack_checksum.format() != m.object_format
            || e.index_checksum.format() != m.object_format
            || e.pack_bytes == 0
            || e.index_bytes == 0
            || e.work_units == 0
            || (i != 0 && m.entries[i - 1].transaction.0 >= e.transaction.0)
            || !e.object_ids.windows(2).all(|p| p[0] < p[1])
            || e.object_ids
                .iter()
                .any(|id| id.is_zero() || id.format() != m.object_format)
        {
            return Err(PackSetError::Malformed);
        }
        objects = objects
            .checked_add(e.object_count as u64)
            .ok_or(PackSetError::Resource)?;
        pack_bytes = pack_bytes
            .checked_add(e.pack_bytes)
            .ok_or(PackSetError::Resource)?;
        index_bytes = index_bytes
            .checked_add(e.index_bytes)
            .ok_or(PackSetError::Resource)?;
        work = work
            .checked_add(e.work_units)
            .ok_or(PackSetError::Resource)?;
        for id in &e.object_ids {
            if all.contains(id) {
                return Err(PackSetError::DuplicateObject);
            }
            all.push(*id);
        }
    }
    if objects > l.max_objects
        || pack_bytes > l.max_pack_bytes
        || index_bytes > l.max_index_bytes
        || work > l.max_work_units
    {
        return Err(PackSetError::Resource);
    }
    Ok(())
}

const fn unlimited_limits() -> PackSetLimits {
    PackSetLimits {
        max_packs: u32::MAX,
        max_objects: u64::MAX,
        max_pack_bytes: u64::MAX,
        max_index_bytes: u64::MAX,
        max_work_units: u64::MAX,
    }
}
fn put(out: &mut Vector<u8>, bytes: &[u8]) -> Result<(), PackSetError> {
    out.try_extend_from_slice(bytes)
        .map_err(|_| PackSetError::Resource)
}
fn put_u16(out: &mut Vector<u8>, value: usize) -> Result<(), PackSetError> {
    put(
        out,
        &u16::try_from(value)
            .map_err(|_| PackSetError::Resource)?
            .to_be_bytes(),
    )
}
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], PackSetError> {
        let end = self.at.checked_add(n).ok_or(PackSetError::Resource)?;
        let v = self
            .bytes
            .get(self.at..end)
            .ok_or(PackSetError::Malformed)?;
        self.at = end;
        Ok(v)
    }
    fn u8(&mut self) -> Result<u8, PackSetError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, PackSetError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| PackSetError::Malformed)?,
        ))
    }
    fn u32(&mut self) -> Result<u32, PackSetError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| PackSetError::Malformed)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, PackSetError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| PackSetError::Malformed)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> PackSetLimits {
        PackSetLimits {
            max_packs: 4,
            max_objects: 8,
            max_pack_bytes: 1000,
            max_index_bytes: 1000,
            max_work_units: 2000,
        }
    }
    fn summary(tx: u8, object: u8) -> AuthenticatedPackIndexSummary {
        AuthenticatedPackIndexSummary {
            transaction: QuarantineTransactionId([tx; 16]),
            object_count: 1,
            pack_checksum: ObjectId::Sha256([tx + 10; 32]),
            index_checksum: ObjectId::Sha256([tx + 20; 32]),
            pack_bytes: 100,
            index_bytes: 80,
            work_units: 200,
            object_ids: [ObjectId::Sha256([object; 32])].into(),
        }
    }
    fn manifest(
        summaries: Vector<AuthenticatedPackIndexSummary>,
    ) -> Result<PackSetManifest, PackSetError> {
        build_pack_set_manifest(
            RepositoryIdentity::parse("owner/repository").unwrap(),
            RepositoryGeneration(3),
            PackGeneration(4),
            ObjectFormat::Sha256,
            summaries,
            limits(),
        )
    }

    #[test]
    fn canonical_manifest_round_trips_and_binds_digest() {
        let value = manifest([summary(1, 1), summary(2, 2)].into()).unwrap();
        let encoded = encode_pack_set_manifest(&value).unwrap();
        assert_eq!(parse_pack_set_manifest(&encoded, limits()).unwrap(), value);
        assert_eq!(value.digest().unwrap(), encoded[encoded.len() - 32..]);
    }

    #[test]
    fn truncation_trailing_tamper_duplicates_and_limits_fail_closed() {
        let value = manifest([summary(1, 1), summary(2, 2)].into()).unwrap();
        let encoded = encode_pack_set_manifest(&value).unwrap();
        assert!(parse_pack_set_manifest(&encoded[..encoded.len() - 1], limits()).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(parse_pack_set_manifest(&trailing, limits()).is_err());
        let mut tampered = encoded.clone();
        tampered[20] ^= 1;
        assert_eq!(
            parse_pack_set_manifest(&tampered, limits()),
            Err(PackSetError::Integrity)
        );
        assert_eq!(
            manifest([summary(1, 1), summary(2, 1)].into()),
            Err(PackSetError::DuplicateObject)
        );
        let mut low = limits();
        low.max_pack_bytes = 199;
        assert_eq!(
            parse_pack_set_manifest(&encoded, low),
            Err(PackSetError::Resource)
        );
        assert!(manifest([summary(2, 1), summary(1, 2)].into()).is_err());
    }
}
