//! Crash-durable storage for immutable, exact-key pack representations.

use mrml_crypto::Sha256;
use mrml_runtime::{
    File, Text, Vector, canonical_path, create_dir_all, join_path, path_exists, path_is_directory,
    remove_file,
};

use crate::cache_pack::{MAX_CACHED_PACK_BYTES, MAX_PACK_CACHE_KEY_BYTES, encode_key};
use crate::{PackCacheError, PackCacheKey};

const MAGIC: &[u8; 8] = b"MRPCFIL1";
const DIGEST_BYTES: usize = 32;
const FIXED_BYTES: usize = MAGIC.len() + 4 + 8 + DIGEST_BYTES + DIGEST_BYTES;
const MAX_FILE_BYTES: usize = MAX_PACK_CACHE_KEY_BYTES + MAX_CACHED_PACK_BYTES + FIXED_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackCacheFileError {
    Resource,
    Io,
    AlreadyExists,
    Integrity,
    Key,
    Durability,
}

impl From<PackCacheError> for PackCacheFileError {
    fn from(error: PackCacheError) -> Self {
        match error {
            PackCacheError::Resource => Self::Resource,
            _ => Self::Key,
        }
    }
}

pub struct ImmutablePackCacheDirectory {
    root: Text,
}

impl ImmutablePackCacheDirectory {
    pub fn open(path: &str) -> Result<Self, PackCacheFileError> {
        create_dir_all(path).map_err(|_| PackCacheFileError::Io)?;
        let root = canonical_path(path).map_err(|_| PackCacheFileError::Io)?;
        if !path_is_directory(&root) {
            return Err(PackCacheFileError::Io);
        }
        Ok(Self { root })
    }

    pub fn insert(
        &self,
        key: &PackCacheKey,
        representation: &[u8],
    ) -> Result<(), PackCacheFileError> {
        let encoded = encode_record(key, representation)?;
        let path = self.path(key);
        let lock = self.lock_path(key);
        if path_exists(&path) {
            return Err(PackCacheFileError::AlreadyExists);
        }
        let lock_file = File::create_new(&lock).map_err(|_| PackCacheFileError::AlreadyExists)?;
        drop(lock_file);
        if path_exists(&path) {
            let _ = remove_file(&lock);
            return Err(PackCacheFileError::AlreadyExists);
        }
        let result = (|| {
            let mut file = File::create_new(&path)
                .map_err(|_| PackCacheFileError::AlreadyExists)?;
            file.write_all(&encoded).map_err(|_| PackCacheFileError::Io)?;
            file.sync().map_err(|_| PackCacheFileError::Durability)?;
            drop(file);
            sync_cache_directory(&self.root)?;
            // Success is reported only after reopening through the
            // regular-file path and authenticating the complete key and
            // representation.
            match read_record(&path, key)? {
                bytes if &bytes[..] == representation => Ok(()),
                _ => Err(PackCacheFileError::Integrity),
            }
        })();
        if result.is_err() {
            let _ = remove_file(&path);
        }
        remove_file(&lock).map_err(|_| PackCacheFileError::Durability)?;
        sync_cache_directory(&self.root)?;
        result
    }

    pub fn lookup(&self, key: &PackCacheKey) -> Result<Option<Vector<u8>>, PackCacheFileError> {
        let path = self.path(key);
        let lock = self.lock_path(key);
        if path_exists(&lock) {
            return Ok(None);
        }
        if !path_exists(&path) {
            return Ok(None);
        }
        match read_record(&path, key) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(_) if path_exists(&lock) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn path(&self, key: &PackCacheKey) -> Text {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut name = Text::new();
        for byte in key.digest() {
            name.push(HEX[(byte >> 4) as usize] as char);
            name.push(HEX[(byte & 15) as usize] as char);
        }
        name.push_str(".pack-cache");
        join_path(&self.root, &name)
    }

    fn lock_path(&self, key: &PackCacheKey) -> Text {
        let mut path = self.path(key);
        path.push_str(".lock");
        path
    }
}

fn read_record(path: &str, key: &PackCacheKey) -> Result<Vector<u8>, PackCacheFileError> {
    let mut file = File::open_regular(path).map_err(|_| PackCacheFileError::Integrity)?;
    let length = usize::try_from(file.len().map_err(|_| PackCacheFileError::Integrity)?)
        .map_err(|_| PackCacheFileError::Resource)?;
    if length > MAX_FILE_BYTES {
        return Err(PackCacheFileError::Resource);
    }
    let mut bytes = Vector::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| PackCacheFileError::Resource)?;
    bytes.resize(length, 0);
    file.read_exact(&mut bytes)
        .map_err(|_| PackCacheFileError::Integrity)?;
    parse_record(key, &bytes)
}

fn encode_record(
    key: &PackCacheKey,
    representation: &[u8],
) -> Result<Vector<u8>, PackCacheFileError> {
    if representation.len() > MAX_CACHED_PACK_BYTES {
        return Err(PackCacheFileError::Resource);
    }
    let key_bytes = encode_key(
        key.object_format(),
        key.wants(),
        key.haves(),
        key.repository_generation(),
        key.pack_profile_version(),
        key.encoder_version(),
    )?;
    let capacity = FIXED_BYTES
        .checked_add(key_bytes.len())
        .and_then(|value| value.checked_add(representation.len()))
        .ok_or(PackCacheFileError::Resource)?;
    let mut out = Vector::new();
    out.try_reserve_exact(capacity)
        .map_err(|_| PackCacheFileError::Resource)?;
    out.extend(MAGIC.iter().copied());
    out.extend(
        u32::try_from(key_bytes.len())
            .map_err(|_| PackCacheFileError::Resource)?
            .to_be_bytes(),
    );
    out.extend(key_bytes);
    out.extend(
        u64::try_from(representation.len())
            .map_err(|_| PackCacheFileError::Resource)?
            .to_be_bytes(),
    );
    out.extend(Sha256::digest(representation));
    out.extend(representation.iter().copied());
    let terminal = Sha256::digest(&out);
    out.extend(terminal);
    Ok(out)
}

fn parse_record(expected: &PackCacheKey, input: &[u8]) -> Result<Vector<u8>, PackCacheFileError> {
    if input.len() < FIXED_BYTES || input.len() > MAX_FILE_BYTES || &input[..8] != MAGIC {
        return Err(PackCacheFileError::Integrity);
    }
    let body_end = input.len() - DIGEST_BYTES;
    if Sha256::digest(&input[..body_end]) != input[body_end..] {
        return Err(PackCacheFileError::Integrity);
    }
    let mut cursor = 8usize;
    let key_length = take_u32(input, &mut cursor)? as usize;
    if key_length > MAX_PACK_CACHE_KEY_BYTES {
        return Err(PackCacheFileError::Resource);
    }
    let key_end = cursor
        .checked_add(key_length)
        .ok_or(PackCacheFileError::Resource)?;
    let stored_key = input
        .get(cursor..key_end)
        .ok_or(PackCacheFileError::Integrity)?;
    cursor = key_end;
    let expected_key = encode_key(
        expected.object_format(),
        expected.wants(),
        expected.haves(),
        expected.repository_generation(),
        expected.pack_profile_version(),
        expected.encoder_version(),
    )?;
    if stored_key != &expected_key[..] || Sha256::digest(stored_key) != expected.digest() {
        return Err(PackCacheFileError::Integrity);
    }
    let representation_length =
        usize::try_from(take_u64(input, &mut cursor)?).map_err(|_| PackCacheFileError::Resource)?;
    if representation_length > MAX_CACHED_PACK_BYTES {
        return Err(PackCacheFileError::Resource);
    }
    let digest_end = cursor
        .checked_add(DIGEST_BYTES)
        .ok_or(PackCacheFileError::Resource)?;
    let representation_digest = input
        .get(cursor..digest_end)
        .ok_or(PackCacheFileError::Integrity)?;
    cursor = digest_end;
    let representation_end = cursor
        .checked_add(representation_length)
        .ok_or(PackCacheFileError::Resource)?;
    if representation_end != body_end {
        return Err(PackCacheFileError::Integrity);
    }
    let representation = input
        .get(cursor..representation_end)
        .ok_or(PackCacheFileError::Integrity)?;
    if Sha256::digest(representation).as_slice() != representation_digest {
        return Err(PackCacheFileError::Integrity);
    }
    let mut result = Vector::new();
    result
        .try_reserve_exact(representation.len())
        .map_err(|_| PackCacheFileError::Resource)?;
    result.extend(representation.iter().copied());
    Ok(result)
}

fn take_u32(input: &[u8], cursor: &mut usize) -> Result<u32, PackCacheFileError> {
    let end = cursor.checked_add(4).ok_or(PackCacheFileError::Resource)?;
    let bytes: [u8; 4] = input
        .get(*cursor..end)
        .ok_or(PackCacheFileError::Integrity)?
        .try_into()
        .map_err(|_| PackCacheFileError::Integrity)?;
    *cursor = end;
    Ok(u32::from_be_bytes(bytes))
}

fn take_u64(input: &[u8], cursor: &mut usize) -> Result<u64, PackCacheFileError> {
    let end = cursor.checked_add(8).ok_or(PackCacheFileError::Resource)?;
    let bytes: [u8; 8] = input
        .get(*cursor..end)
        .ok_or(PackCacheFileError::Integrity)?
        .try_into()
        .map_err(|_| PackCacheFileError::Integrity)?;
    *cursor = end;
    Ok(u64::from_be_bytes(bytes))
}

#[cfg(unix)]
fn sync_cache_directory(path: &str) -> Result<(), PackCacheFileError> {
    mrml_runtime::sync_directory(path).map_err(|_| PackCacheFileError::Durability)
}

#[cfg(not(unix))]
fn sync_cache_directory(_: &str) -> Result<(), PackCacheFileError> {
    Err(PackCacheFileError::Durability)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::{ObjectFormat, ObjectId, RepositoryGeneration};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use mrml_runtime::Shared;

    fn key(generation: u64) -> PackCacheKey {
        PackCacheKey::new(
            ObjectFormat::Sha256,
            Vector::from([ObjectId::Sha256([1; 32]), ObjectId::Sha256([2; 32])]),
            Vector::from([ObjectId::Sha256([3; 32])]),
            RepositoryGeneration(generation),
            1,
            9,
        )
        .unwrap()
    }

    fn temporary_root(label: &str) -> Text {
        join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-pack-cache-{label}-{}", mrml_runtime::process_id()),
        )
    }

    #[test]
    fn persists_and_reopens_exact_representation() {
        let root = temporary_root("persist");
        let _ = mrml_runtime::remove_dir_all(&root);
        let exact = key(7);
        ImmutablePackCacheDirectory::open(&root)
            .unwrap()
            .insert(&exact, b"PACK exact bytes")
            .unwrap();
        let reopened = ImmutablePackCacheDirectory::open(&root).unwrap();
        assert_eq!(
            &reopened.lookup(&exact).unwrap().unwrap()[..],
            b"PACK exact bytes".as_slice()
        );
        assert_eq!(reopened.lookup(&key(8)).unwrap(), None);
        mrml_runtime::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn immutable_insert_rejects_overwrite() {
        let root = temporary_root("immutable");
        let _ = mrml_runtime::remove_dir_all(&root);
        let cache = ImmutablePackCacheDirectory::open(&root).unwrap();
        let exact = key(7);
        cache.insert(&exact, b"first").unwrap();
        assert_eq!(
            cache.insert(&exact, b"replacement"),
            Err(PackCacheFileError::AlreadyExists)
        );
        assert_eq!(
            &cache.lookup(&exact).unwrap().unwrap()[..],
            b"first".as_slice()
        );
        mrml_runtime::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn tampering_fails_closed() {
        let root = temporary_root("tamper");
        let _ = mrml_runtime::remove_dir_all(&root);
        let cache = ImmutablePackCacheDirectory::open(&root).unwrap();
        let exact = key(7);
        cache.insert(&exact, b"original").unwrap();
        let path = cache.path(&exact);
        let mut bytes = mrml_runtime::read_file_bounded(&path, MAX_FILE_BYTES).unwrap();
        let tampered = bytes.len() - DIGEST_BYTES - 1;
        bytes[tampered] ^= 1;
        mrml_runtime::write_file(&path, &bytes).unwrap();
        assert_eq!(cache.lookup(&exact), Err(PackCacheFileError::Integrity));
        mrml_runtime::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn concurrent_same_key_population_has_one_immutable_winner() {
        let root = temporary_root("concurrent");
        let _ = mrml_runtime::remove_dir_all(&root);
        let ready = Shared::new(AtomicUsize::new(0));
        let inserted = Shared::new(AtomicUsize::new(0));
        let contended = Shared::new(AtomicUsize::new(0));
        let unexpected = Shared::new(AtomicUsize::new(0));
        let mut workers = Vector::new();
        for _ in 0..6 {
            let worker_root = root.clone();
            let worker_ready = ready.clone();
            let worker_inserted = inserted.clone();
            let worker_contended = contended.clone();
            let worker_unexpected = unexpected.clone();
            let worker = mrml_runtime::spawn_joinable(move || {
                let cache = ImmutablePackCacheDirectory::open(&worker_root).unwrap();
                worker_ready.fetch_add(1, Ordering::AcqRel);
                while worker_ready.load(Ordering::Acquire) != 6 {
                    mrml_runtime::yield_now();
                }
                match cache.insert(&key(7), b"one canonical representation") {
                    Ok(()) => worker_inserted.fetch_add(1, Ordering::AcqRel),
                    Err(PackCacheFileError::AlreadyExists) => {
                        worker_contended.fetch_add(1, Ordering::AcqRel)
                    }
                    Err(_) => worker_unexpected.fetch_add(1, Ordering::AcqRel),
                };
            })
            .unwrap_or_else(|_| panic!("failed to start cache population worker"));
            workers.push(worker);
        }
        for worker in workers {
            assert!(worker.join());
        }
        assert_eq!(inserted.load(Ordering::Acquire), 1);
        assert_eq!(contended.load(Ordering::Acquire), 5);
        assert_eq!(unexpected.load(Ordering::Acquire), 0);
        let cache = ImmutablePackCacheDirectory::open(&root).unwrap();
        assert_eq!(
            &cache.lookup(&key(7)).unwrap().unwrap()[..],
            b"one canonical representation"
        );
        mrml_runtime::remove_dir_all(&root).unwrap();
    }
}
