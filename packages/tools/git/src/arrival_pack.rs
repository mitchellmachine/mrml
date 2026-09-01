//! Isolated, immutable arrival-pack staging and durable installation.

use mrml_runtime::{
    File, Text, Vector, canonical_path, create_dir_all, join_path, path_exists, path_is_directory,
    rename_file,
};

use crate::pack_file::validate_pack_file_with_bases;
use crate::sha1::GitObjectHasher;
use crate::{
    BoundedRead, DEFAULT_MAX_EXPANDED_OBJECT_BYTES, DEFAULT_MAX_INCOMING_PACK_BYTES,
    DEFAULT_MAX_INDIVIDUAL_OBJECT_BYTES, DurableFailure, GitdCoreError, ObjectFormat, ObjectId,
    PackError, QuarantineTransaction, QuarantineTransactionId, build_pack_index_v2, parse_pack_index_v2,
    parse_pack_with_index,
};

pub struct ArrivalPackStore {
    quarantine: Text,
    arrivals: Text,
    format: ObjectFormat,
    max_pack_bytes: u64,
}

impl ArrivalPackStore {
    /// Streams the exact already-admitted body into an isolated transaction
    /// directory. The directory is not part of normal object lookup and is
    /// fsynced before the lifecycle advances to `ObjectsQuarantined`.
    pub fn receive_pack_body(
        &self,
        transaction: &mut QuarantineTransaction,
        input: &mut dyn BoundedRead,
    ) -> Result<(), GitdCoreError> {
        let expected = transaction.reservation().incoming_pack_bytes();
        if expected == 0 || expected > self.max_pack_bytes || input.remaining() != expected {
            return Err(GitdCoreError::Resource);
        }
        let directory = self.quarantine_path(transaction.id());
        if path_exists(&directory) || path_exists(&self.arrival_path(transaction.id())) {
            return Err(GitdCoreError::Storage);
        }
        create_dir_all(&directory).map_err(|_| GitdCoreError::Storage)?;
        let incoming = join_path(&directory, "incoming.pack");
        let scratch = join_path(&directory, "objects");
        if path_exists(&scratch) {
            return Err(GitdCoreError::Storage);
        }
        create_dir_all(&scratch).map_err(|_| GitdCoreError::Storage)?;
        let mut file = File::create_new(&incoming).map_err(|_| GitdCoreError::Storage)?;
        let mut remaining = expected;
        let mut buffer = [0u8; 64 * 1024];
        while remaining != 0 {
            let wanted = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| GitdCoreError::Resource)?;
            let count = input.read(&mut buffer[..wanted])?;
            if count == 0 || count > wanted {
                return Err(GitdCoreError::MalformedInput);
            }
            file.write_all(&buffer[..count])
                .map_err(|_| GitdCoreError::Storage)?;
            remaining = remaining
                .checked_sub(count as u64)
                .ok_or(GitdCoreError::Resource)?;
        }
        if input.remaining() != 0 {
            return Err(GitdCoreError::MalformedInput);
        }
        file.sync().map_err(|_| GitdCoreError::Storage)?;
        sync_pack_directory(&directory).map_err(|_| GitdCoreError::Storage)?;
        sync_pack_directory(&self.quarantine).map_err(|_| GitdCoreError::Storage)?;
        transaction
            .objects_quarantined(expected)
            .map_err(|_| GitdCoreError::ObjectValidation)
    }

    /// Authenticates and indexes a previously streamed quarantine file, then
    /// binds its exact resource use into the transaction. This is presently a
    /// bounded whole-file validation pass; streaming object expansion remains
    /// a separate acceptance gate.
    pub fn validate_received_pack(
        &self,
        transaction: &mut QuarantineTransaction,
        required_tips: &[ObjectId],
    ) -> Result<(), GitdCoreError> {
        self.validate_received_pack_with_bases(transaction, required_tips, |_, _| Ok(None))
    }

    /// Completes thin REF deltas only from an exact authenticated object view.
    /// The callback receives a full object ID and the configured object limit;
    /// returned bytes are independently re-hashed by the pack validator.
    pub(crate) fn validate_received_pack_with_bases<B>(
        &self,
        transaction: &mut QuarantineTransaction,
        required_tips: &[ObjectId],
        mut external_base: B,
    ) -> Result<(), GitdCoreError>
    where
        B: FnMut(ObjectId, u64) -> Result<Option<(crate::ObjectKind, Vector<u8>)>, PackError>,
    {
        let directory = self.quarantine_path(transaction.id());
        let incoming = join_path(&directory, "incoming.pack");
        let scratch = join_path(&directory, "objects");
        let max_work = transaction
            .reservation()
            .incoming_pack_bytes()
            .checked_mul(2)
            .and_then(|value| value.checked_add(transaction.reservation().expanded_object_bytes()))
            .ok_or(GitdCoreError::Resource)?;
        let validated = validate_pack_file_with_bases(
            &incoming,
            self.format,
            transaction.reservation().incoming_pack_bytes(),
            transaction.reservation().object_count(),
            transaction.reservation().expanded_object_bytes(),
            transaction.reservation().individual_object_bytes(),
            max_work,
            &mut |id, kind, contents| {
                write_scratch_object(&scratch, id, kind, contents)
                    .map_err(|_| crate::PackError::TooLarge)
            },
            |id, limit| match read_scratch_object(&scratch, id, limit)? {
                Some(object) => Ok(Some(object)),
                None => {
                    let Some((kind, contents)) = external_base(id, limit)? else {
                        return Ok(None);
                    };
                    let header = mrml_runtime::mrml_format!("{} {}\0", kind.name(), contents.len());
                    let mut hash = GitObjectHasher::new(self.format);
                    hash.update(header.as_bytes());
                    hash.update(&contents);
                    if hash.finalize() != id {
                        return Err(PackError::ObjectId);
                    }
                    write_scratch_object(&scratch, id, kind, &contents)
                        .map_err(|_| PackError::MissingBase)?;
                    Ok(Some((kind, contents)))
                }
            },
        )
        .map_err(|_| GitdCoreError::ObjectValidation)?;
        if validated.objects.is_empty()
            || validated.largest_object > transaction.reservation().individual_object_bytes()
            || required_tips.is_empty()
            || required_tips.iter().any(|tip| {
                tip.format() != self.format || !validated.objects.iter().any(|(id, _)| id == tip)
            })
        {
            return Err(GitdCoreError::ObjectValidation);
        }
        let index = build_pack_index_v2(self.format, &validated.entries, validated.checksum)
            .map_err(|_| GitdCoreError::ObjectValidation)?;
        write_new_synced(&join_path(&directory, "objects.idx"), &index)
            .map_err(|_| GitdCoreError::Storage)?;
        rename_file(&incoming, &join_path(&directory, "objects.pack"))
            .map_err(|_| GitdCoreError::Storage)?;
        sync_pack_directory(&scratch).map_err(|_| GitdCoreError::Storage)?;
        sync_pack_directory(&directory).map_err(|_| GitdCoreError::Storage)?;
        transaction
            .objects_validated(validated.expanded_bytes, validated.objects.len() as u32)
            .map_err(|_| GitdCoreError::ObjectValidation)?;
        self.verify_directory(&directory, validated.objects.len() as u32)
            .map_err(|_| GitdCoreError::ObjectValidation)
    }

    pub fn open(
        root: &str,
        format: ObjectFormat,
        max_pack_bytes: u64,
    ) -> Result<Self, DurableFailure> {
        if max_pack_bytes == 0 || max_pack_bytes > DEFAULT_MAX_INCOMING_PACK_BYTES {
            return Err(DurableFailure::DiskFull);
        }
        create_dir_all(root).map_err(|_| DurableFailure::DiskFull)?;
        let root = canonical_path(root).map_err(|_| DurableFailure::Rename)?;
        if !path_is_directory(&root) {
            return Err(DurableFailure::Rename);
        }
        let quarantine = join_path(&root, "quarantine");
        let arrivals = join_path(&root, "arrivals");
        create_dir_all(&quarantine).map_err(|_| DurableFailure::DiskFull)?;
        create_dir_all(&arrivals).map_err(|_| DurableFailure::DiskFull)?;
        Ok(Self {
            quarantine,
            arrivals,
            format,
            max_pack_bytes,
        })
    }

    #[allow(dead_code)] // consumed by the protected receive compositor in the next gate
    pub(crate) fn read_quarantined_object(
        &self,
        transaction: QuarantineTransactionId,
        id: ObjectId,
        max_bytes: u64,
    ) -> Result<crate::Object, GitdCoreError> {
        if id.format() != self.format || max_bytes == 0 {
            return Err(GitdCoreError::ObjectValidation);
        }
        let path = join_path(
            &join_path(&self.quarantine_path(transaction), "objects"),
            &id.to_hex(),
        );
        let encoded = read_regular_bounded(
            &path,
            max_bytes.checked_add(1).ok_or(GitdCoreError::Resource)?,
        )
        .map_err(|_| GitdCoreError::ObjectValidation)?;
        let (&kind, contents) = encoded
            .split_first()
            .ok_or(GitdCoreError::ObjectValidation)?;
        let kind = decode_kind(kind)?;
        let header = mrml_runtime::mrml_format!("{} {}\0", kind.name(), contents.len());
        let mut hash = GitObjectHasher::new(self.format);
        hash.update(header.as_bytes());
        hash.update(contents);
        if hash.finalize() != id {
            return Err(GitdCoreError::ObjectValidation);
        }
        let mut copied = Vector::new();
        copied
            .try_extend_from_slice(contents)
            .map_err(|_| GitdCoreError::Resource)?;
        Ok(crate::Object {
            kind,
            contents: copied,
        })
    }

    pub fn stage(
        &self,
        transaction: &QuarantineTransaction,
        required_tips: &[ObjectId],
        pack: &[u8],
    ) -> Result<(), DurableFailure> {
        if u64::try_from(pack.len()).map_err(|_| DurableFailure::DiskFull)?
            != transaction.reservation().incoming_pack_bytes()
            || u64::try_from(pack.len()).map_err(|_| DurableFailure::DiskFull)?
                > self.max_pack_bytes
        {
            return Err(DurableFailure::DiskFull);
        }
        let (objects, entries) =
            parse_pack_with_index(pack, self.format).map_err(|_| DurableFailure::VerifierCrash)?;
        if objects.len()
            != usize::try_from(
                transaction
                    .validated_object_count()
                    .ok_or(DurableFailure::VerifierCrash)?,
            )
            .map_err(|_| DurableFailure::VerifierCrash)?
        {
            return Err(DurableFailure::VerifierCrash);
        }
        if required_tips.is_empty()
            || required_tips.iter().any(|tip| {
                tip.format() != self.format || !objects.iter().any(|object| object.id == *tip)
            })
        {
            return Err(DurableFailure::VerifierCrash);
        }
        let trailer =
            ObjectId::from_bytes(self.format, &pack[pack.len() - self.format.hash_len()..])
                .ok_or(DurableFailure::VerifierCrash)?;
        let index = build_pack_index_v2(self.format, &entries, trailer)
            .map_err(|_| DurableFailure::VerifierCrash)?;

        let directory = self.quarantine_path(transaction.id());
        if path_exists(&directory) || path_exists(&self.arrival_path(transaction.id())) {
            return Err(DurableFailure::StaleLock);
        }
        create_dir_all(&directory).map_err(|_| DurableFailure::DiskFull)?;
        write_new_synced(&join_path(&directory, "objects.pack"), pack)?;
        write_new_synced(&join_path(&directory, "objects.idx"), &index)?;
        sync_pack_directory(&directory)?;
        sync_pack_directory(&self.quarantine)?;
        self.verify_directory(&directory, transaction.reservation().object_count())?;
        Ok(())
    }

    pub fn install(
        &self,
        transaction: QuarantineTransactionId,
        object_count: u32,
    ) -> Result<(), DurableFailure> {
        let staged = self.quarantine_path(transaction);
        let installed = self.arrival_path(transaction);
        if path_exists(&installed) {
            return Err(DurableFailure::StaleLock);
        }
        self.verify_directory(&staged, object_count)?;
        rename_file(&staged, &installed).map_err(|_| DurableFailure::Rename)?;
        sync_pack_directory(&self.arrivals)?;
        sync_pack_directory(&self.quarantine)?;
        self.verify_directory(&installed, object_count)
    }

    pub fn verify_installed(
        &self,
        transaction: QuarantineTransactionId,
        object_count: u32,
    ) -> Result<(), DurableFailure> {
        self.verify_directory(&self.arrival_path(transaction), object_count)
    }

    fn verify_directory(&self, directory: &str, object_count: u32) -> Result<(), DurableFailure> {
        let max_work = self
            .max_pack_bytes
            .checked_mul(2)
            .and_then(|value| value.checked_add(DEFAULT_MAX_EXPANDED_OBJECT_BYTES))
            .ok_or(DurableFailure::DiskFull)?;
        let scratch = join_path(directory, "objects");
        let validated = validate_pack_file_with_bases(
            &join_path(directory, "objects.pack"),
            self.format,
            self.max_pack_bytes,
            object_count,
            DEFAULT_MAX_EXPANDED_OBJECT_BYTES,
            DEFAULT_MAX_INDIVIDUAL_OBJECT_BYTES,
            max_work,
            &mut |_, _, _| Ok(()),
            |id, limit| read_scratch_object(&scratch, id, limit),
        )
        .map_err(|_| DurableFailure::VerifierCrash)?;
        let per_object = u64::try_from(self.format.hash_len())
            .map_err(|_| DurableFailure::DiskFull)?
            .checked_add(16)
            .ok_or(DurableFailure::DiskFull)?;
        let index_limit = 8u64
            .checked_add(256 * 4)
            .and_then(|value| value.checked_add(u64::from(object_count).checked_mul(per_object)?))
            .and_then(|value| value.checked_add((self.format.hash_len() * 2) as u64))
            .ok_or(DurableFailure::DiskFull)?;
        let index = read_regular_bounded(&join_path(directory, "objects.idx"), index_limit)?;
        if validated.objects.len()
            != usize::try_from(object_count).map_err(|_| DurableFailure::VerifierCrash)?
        {
            return Err(DurableFailure::VerifierCrash);
        }
        let parsed = parse_pack_index_v2(self.format, &index, object_count)
            .map_err(|_| DurableFailure::VerifierCrash)?;
        if parsed.entries().len() != validated.entries.len()
            || validated.entries.iter().any(|expected| {
                parsed
                    .find(expected.id)
                    .is_none_or(|actual| actual != expected)
            })
        {
            return Err(DurableFailure::VerifierCrash);
        }
        if parsed.pack_checksum() != validated.checksum {
            return Err(DurableFailure::VerifierCrash);
        }
        Ok(())
    }

    fn quarantine_path(&self, transaction: QuarantineTransactionId) -> Text {
        join_path(&self.quarantine, &transaction_name(transaction))
    }
    fn arrival_path(&self, transaction: QuarantineTransactionId) -> Text {
        join_path(&self.arrivals, &transaction_name(transaction))
    }
}

fn read_scratch_object(
    directory: &str,
    id: ObjectId,
    max_bytes: u64,
) -> Result<Option<(crate::ObjectKind, Vector<u8>)>, PackError> {
    let path = join_path(directory, &id.to_hex());
    if !path_exists(&path) {
        return Ok(None);
    }
    let encoded = read_regular_bounded(
        &path,
        max_bytes.checked_add(1).ok_or(PackError::TooLarge)?,
    )
    .map_err(|_| PackError::MissingBase)?;
    let (&kind, contents) = encoded.split_first().ok_or(PackError::MissingBase)?;
    let kind = match kind {
        1 => crate::ObjectKind::Commit,
        2 => crate::ObjectKind::Tree,
        3 => crate::ObjectKind::Blob,
        4 => crate::ObjectKind::Tag,
        _ => return Err(PackError::ObjectType),
    };
    let mut copied = Vector::new();
    copied
        .try_extend_from_slice(contents)
        .map_err(|_| PackError::TooLarge)?;
    Ok(Some((kind, copied)))
}

fn write_new_synced(path: &str, bytes: &[u8]) -> Result<(), DurableFailure> {
    let mut file = File::create_new(path).map_err(|_| DurableFailure::StaleLock)?;
    file.write_all(bytes)
        .map_err(|_| DurableFailure::ShortWrite)?;
    file.sync().map_err(|_| DurableFailure::Fsync)
}

fn write_scratch_object(
    directory: &str,
    id: ObjectId,
    kind: crate::ObjectKind,
    contents: &[u8],
) -> Result<(), DurableFailure> {
    let mut file = File::create_new(&join_path(directory, &id.to_hex()))
        .map_err(|_| DurableFailure::StaleLock)?;
    let kind = match kind {
        crate::ObjectKind::Commit => 1,
        crate::ObjectKind::Tree => 2,
        crate::ObjectKind::Blob => 3,
        crate::ObjectKind::Tag => 4,
    };
    file.write_all(&[kind])
        .and_then(|_| file.write_all(contents))
        .map_err(|_| DurableFailure::ShortWrite)?;
    file.sync().map_err(|_| DurableFailure::Fsync)
}

#[allow(dead_code)]
fn decode_kind(kind: u8) -> Result<crate::ObjectKind, GitdCoreError> {
    match kind {
        1 => Ok(crate::ObjectKind::Commit),
        2 => Ok(crate::ObjectKind::Tree),
        3 => Ok(crate::ObjectKind::Blob),
        4 => Ok(crate::ObjectKind::Tag),
        _ => Err(GitdCoreError::ObjectValidation),
    }
}

fn read_regular_bounded(path: &str, limit: u64) -> Result<Vector<u8>, DurableFailure> {
    let mut file = File::open_regular(path).map_err(|_| DurableFailure::VerifierCrash)?;
    let length = file.len().map_err(|_| DurableFailure::VerifierCrash)?;
    if length > limit {
        return Err(DurableFailure::DiskFull);
    }
    let length = usize::try_from(length).map_err(|_| DurableFailure::DiskFull)?;
    let mut bytes = Vector::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| DurableFailure::DiskFull)?;
    bytes.resize(length, 0);
    file.read_exact(&mut bytes)
        .map_err(|_| DurableFailure::ShortWrite)?;
    Ok(bytes)
}

fn transaction_name(transaction: QuarantineTransactionId) -> Text {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = Text::new();
    for byte in transaction.0 {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 15) as usize] as char);
    }
    output
}

#[cfg(unix)]
fn sync_pack_directory(path: &str) -> Result<(), DurableFailure> {
    mrml_runtime::sync_directory(path).map_err(|_| DurableFailure::Fsync)
}
#[cfg(not(unix))]
fn sync_pack_directory(_: &str) -> Result<(), DurableFailure> {
    Err(DurableFailure::Fsync)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::{
        ObjectKind, PackObject, PushStorageForecast, QuarantineLimits, RepositoryGeneration,
        RepositoryIdentity, RevocationGeneration, TrustGeneration, encode_pack_with_format,
        reserve_push_disk,
    };

    fn root() -> Text {
        join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-arrival-{}", mrml_runtime::process_id()),
        )
    }

    struct Reader {
        bytes: Vector<u8>,
        offset: usize,
    }

    impl BoundedRead for Reader {
        fn remaining(&self) -> u64 {
            (self.bytes.len() - self.offset) as u64
        }

        fn read(&mut self, output: &mut [u8]) -> Result<usize, GitdCoreError> {
            let count = output.len().min(7).min(self.bytes.len() - self.offset);
            output[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
            self.offset += count;
            Ok(count)
        }
    }

    #[test]
    fn linux_arrival_pack_is_validated_indexed_and_installed_as_one_directory() {
        let root = root();
        let _ = mrml_runtime::remove_dir_all(&root);
        let object = PackObject {
            id: ObjectId::blob_with_format(ObjectFormat::Sha256, b"arrival"),
            kind: crate::ObjectKind::Blob,
            contents: Vector::from(*b"arrival"),
        };
        let object_id = object.id;
        let pack = encode_pack_with_format(&[object], ObjectFormat::Sha256).unwrap();
        let reservation = reserve_push_disk(
            QuarantineLimits {
                minimum_free_space_bytes: 0,
                ..QuarantineLimits::default()
            },
            PushStorageForecast {
                incoming_pack_bytes: pack.len() as u64,
                expanded_object_bytes: 7,
                largest_object_bytes: 7,
                object_count: 1,
                ref_count: 1,
                arrival_index_bytes: 4096,
                staging_metadata_bytes: 4096,
                audit_receipt_bytes: 4096,
                ordinary_free_bytes: 1_000_000,
            },
        )
        .unwrap();
        let mut transaction = QuarantineTransaction::begin(
            QuarantineTransactionId([12u8; 16]),
            RepositoryIdentity::parse("owner/repository").unwrap(),
            RepositoryGeneration(1),
            TrustGeneration(1),
            RevocationGeneration(1),
            reservation,
        )
        .unwrap();
        let store = ArrivalPackStore::open(&root, ObjectFormat::Sha256, 1024 * 1024).unwrap();
        let mut reader = Reader {
            bytes: pack,
            offset: 0,
        };
        store
            .receive_pack_body(&mut transaction, &mut reader)
            .unwrap();
        assert!(!path_exists(&store.arrival_path(transaction.id())));
        store
            .validate_received_pack(&mut transaction, &[object_id])
            .unwrap();
        assert_eq!(transaction.validated_object_count(), Some(1));
        assert_eq!(
            store
                .read_quarantined_object(transaction.id(), object_id, 1024)
                .unwrap(),
            crate::Object {
                kind: ObjectKind::Blob,
                contents: Vector::from(*b"arrival"),
            }
        );
        assert!(!path_exists(&store.arrival_path(transaction.id())));
        store.install(transaction.id(), 1).unwrap();
        store.verify_installed(transaction.id(), 1).unwrap();
        assert!(!path_exists(&store.quarantine_path(transaction.id())));
        assert!(matches!(
            store.receive_pack_body(&mut transaction, &mut reader),
            Err(GitdCoreError::Resource | GitdCoreError::Storage)
        ));
        mrml_runtime::remove_dir_all(&root).unwrap();
    }
}
