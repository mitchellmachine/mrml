use crate::{
    CommittedStoreReceipt, DurableError, DurableNamespace, DurableObjectId, DurableRecord,
    DurableStateStore, MAX_DURABLE_RECORD_BYTES, PreparedStoreReceipt,
};
use mrml_crypto::Sha256;
extern crate std;
use std::format;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::string::String;

const MAX_HOSTED_RECORD_FILES: usize = 512;

pub struct HostedDurableStateStore {
    root: PathBuf,
    pending: Option<PendingRecord>,
}

struct PendingRecord {
    receipt: PreparedStoreReceipt,
    prepared_path: PathBuf,
    committed_path: PathBuf,
}

impl HostedDurableStateStore {
    pub fn open(root: &Path) -> Result<Self, DurableError> {
        fs::create_dir_all(root).map_err(|_| DurableError::StoreUnavailable)?;
        let metadata = fs::symlink_metadata(root).map_err(|_| DurableError::StoreUnavailable)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(DurableError::StoreUnavailable);
        }
        Ok(Self {
            root: root.to_path_buf(),
            pending: None,
        })
    }

    pub fn load_authoritative(
        &self,
        namespace: DurableNamespace,
        object: DurableObjectId,
        output: &mut [u8],
    ) -> Result<Option<usize>, DurableError> {
        let Some((path, _)) = self.find_authoritative(namespace, object)? else {
            return Ok(None);
        };
        let mut file = open_regular_file(&path)?;
        let length = usize::try_from(
            file.metadata()
                .map_err(|_| DurableError::StoreUnavailable)?
                .len(),
        )
        .map_err(|_| DurableError::Malformed)?;
        if length > MAX_DURABLE_RECORD_BYTES || output.len() < length {
            return Err(DurableError::PayloadTooLarge);
        }
        file.read_exact(&mut output[..length])
            .map_err(|_| DurableError::StoreUnavailable)?;
        let mut extra = [0u8; 1];
        if file
            .read(&mut extra)
            .map_err(|_| DurableError::StoreUnavailable)?
            != 0
        {
            return Err(DurableError::Malformed);
        }
        Ok(Some(length))
    }

    fn find_authoritative(
        &self,
        namespace: DurableNamespace,
        object: DurableObjectId,
    ) -> Result<Option<(PathBuf, CommittedStoreReceipt)>, DurableError> {
        let prefix = record_prefix(namespace, object);
        let mut selected: Option<(PathBuf, CommittedStoreReceipt)> = None;
        let entries = fs::read_dir(&self.root).map_err(|_| DurableError::StoreUnavailable)?;
        for (index, entry) in entries.enumerate() {
            if index >= MAX_HOSTED_RECORD_FILES {
                return Err(DurableError::StoreUnavailable);
            }
            let entry = entry.map_err(|_| DurableError::StoreUnavailable)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.starts_with(&prefix) || !name.ends_with(".record") {
                continue;
            }
            let metadata = entry
                .metadata()
                .map_err(|_| DurableError::StoreUnavailable)?;
            if !metadata.is_file()
                || entry
                    .file_type()
                    .map_err(|_| DurableError::StoreUnavailable)?
                    .is_symlink()
            {
                return Err(DurableError::Malformed);
            }
            let receipt = inspect_record_file(&entry.path(), namespace, object)?;
            if selected
                .as_ref()
                .is_none_or(|(_, current)| receipt.generation > current.generation)
            {
                selected = Some((entry.path(), receipt));
            }
        }
        Ok(selected)
    }
}

impl DurableStateStore for HostedDurableStateStore {
    fn prepare(&mut self, record: &DurableRecord) -> Result<PreparedStoreReceipt, DurableError> {
        if self.pending.is_some() {
            return Err(DurableError::StoreUnavailable);
        }
        let current = self.find_authoritative(record.namespace, record.object)?;
        match current {
            Some((_, receipt)) if receipt.generation != record.previous_generation => {
                return Err(DurableError::InvalidGeneration);
            }
            None if record.previous_generation != 0 => {
                return Err(DurableError::InvalidGeneration);
            }
            _ => {}
        }
        let mut encoded = [0u8; MAX_DURABLE_RECORD_BYTES];
        let length = record.encode(&mut encoded)?;
        let base = record_file_name(record.namespace, record.object, record.generation);
        let prepared_path = self.root.join(format!("{base}.prepared"));
        let committed_path = self.root.join(format!("{base}.record"));
        write_prepared(&prepared_path, &encoded[..length])?;
        sync_directory(&self.root)?;
        let receipt = PreparedStoreReceipt {
            namespace: record.namespace,
            object: record.object,
            previous_generation: record.previous_generation,
            generation: record.generation,
            payload_digest: record.payload_digest,
            store_generation: record.generation,
        };
        self.pending = Some(PendingRecord {
            receipt,
            prepared_path,
            committed_path,
        });
        Ok(receipt)
    }

    fn commit(
        &mut self,
        prepared: PreparedStoreReceipt,
    ) -> Result<CommittedStoreReceipt, DurableError> {
        let pending = self.pending.take().ok_or(DurableError::InvalidGeneration)?;
        if pending.receipt != prepared {
            self.pending = Some(pending);
            return Err(DurableError::ReceiptMismatch);
        }
        if pending.committed_path.exists() {
            let existing =
                inspect_record_file(&pending.committed_path, prepared.namespace, prepared.object)?;
            if existing.generation != prepared.generation
                || existing.payload_digest != prepared.payload_digest
            {
                return Err(DurableError::ResolutionMismatch);
            }
            fs::remove_file(&pending.prepared_path).map_err(|_| DurableError::StoreUnavailable)?;
        } else {
            fs::rename(&pending.prepared_path, &pending.committed_path)
                .map_err(|_| DurableError::StoreUnavailable)?;
        }
        sync_directory(&self.root).map_err(|_| DurableError::CommitUncertain)?;
        Ok(CommittedStoreReceipt {
            namespace: prepared.namespace,
            object: prepared.object,
            generation: prepared.generation,
            payload_digest: prepared.payload_digest,
            store_generation: prepared.store_generation,
        })
    }

    fn authoritative(
        &mut self,
        namespace: DurableNamespace,
        object: DurableObjectId,
    ) -> Result<Option<CommittedStoreReceipt>, DurableError> {
        Ok(self
            .find_authoritative(namespace, object)?
            .map(|(_, receipt)| receipt))
    }
}

fn write_prepared(path: &Path, bytes: &[u8]) -> Result<(), DurableError> {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            file.write_all(bytes)
                .map_err(|_| DurableError::StoreUnavailable)?;
            file.sync_all().map_err(|_| DurableError::StoreUnavailable)
        }
        Err(_) => {
            let mut existing = [0u8; MAX_DURABLE_RECORD_BYTES];
            let mut file = open_regular_file(path)?;
            let length = usize::try_from(
                file.metadata()
                    .map_err(|_| DurableError::StoreUnavailable)?
                    .len(),
            )
            .map_err(|_| DurableError::Malformed)?;
            if length > existing.len() {
                return Err(DurableError::Malformed);
            }
            file.read_exact(&mut existing[..length])
                .map_err(|_| DurableError::StoreUnavailable)?;
            if length == bytes.len() && existing[..length] == *bytes {
                Ok(())
            } else {
                Err(DurableError::ResolutionMismatch)
            }
        }
    }
}

fn inspect_record_file(
    path: &Path,
    namespace: DurableNamespace,
    object: DurableObjectId,
) -> Result<CommittedStoreReceipt, DurableError> {
    let mut encoded = [0u8; MAX_DURABLE_RECORD_BYTES];
    let mut file = open_regular_file(path)?;
    let length = usize::try_from(
        file.metadata()
            .map_err(|_| DurableError::StoreUnavailable)?
            .len(),
    )
    .map_err(|_| DurableError::Malformed)?;
    if !(110..=MAX_DURABLE_RECORD_BYTES).contains(&length) {
        return Err(DurableError::Malformed);
    }
    file.read_exact(&mut encoded[..length])
        .map_err(|_| DurableError::StoreUnavailable)?;
    let encoded = &encoded[..length];
    if encoded.get(..8) != Some(b"MRMLCERT")
        || encoded[10] != namespace as u8
        || encoded.get(12..28) != Some(&object.0)
    {
        return Err(DurableError::Malformed);
    }
    let previous_generation = read_u64(&encoded[28..36])?;
    let generation = read_u64(&encoded[36..44])?;
    let payload_length = usize::from(u16::from_be_bytes([encoded[44], encoded[45]]));
    if generation != previous_generation.checked_add(1).unwrap_or(0)
        || length
            != 110usize
                .checked_add(payload_length)
                .ok_or(DurableError::Malformed)?
    {
        return Err(DurableError::Malformed);
    }
    let mut payload_digest = [0u8; 32];
    payload_digest.copy_from_slice(&encoded[46..78]);
    if payload_digest != Sha256::digest(&encoded[78..78 + payload_length]) {
        return Err(DurableError::Malformed);
    }
    Ok(CommittedStoreReceipt {
        namespace,
        object,
        generation,
        payload_digest,
        store_generation: generation,
    })
}

fn open_regular_file(path: &Path) -> Result<File, DurableError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| DurableError::StoreUnavailable)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(DurableError::Malformed);
    }
    File::open(path).map_err(|_| DurableError::StoreUnavailable)
}

fn sync_directory(path: &Path) -> Result<(), DurableError> {
    #[cfg(windows)]
    {
        let _ = path;
        return Ok(());
    }
    #[cfg(unix)]
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| DurableError::StoreUnavailable)
}

fn record_prefix(namespace: DurableNamespace, object: DurableObjectId) -> String {
    format!("n{:02x}-o{}-g", namespace as u8, hex_object(object))
}

fn record_file_name(
    namespace: DurableNamespace,
    object: DurableObjectId,
    generation: u64,
) -> String {
    format!("{}{:016x}", record_prefix(namespace, object), generation)
}

fn hex_object(object: DurableObjectId) -> String {
    let mut output = String::with_capacity(32);
    for byte in object.0 {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn read_u64(input: &[u8]) -> Result<u64, DurableError> {
    Ok(u64::from_be_bytes(
        input.try_into().map_err(|_| DurableError::Malformed)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DurableAuthenticator, DurableRecordKind, DurableRenewalCheckpointSink, DurableTransaction,
        ExpiryHealth, RenewalCheckpointSink, RenewalJournal, RenewalLease, RenewalSchedule,
        RenewalSource,
    };
    use mrml_acme::AriCertificateId;
    use mrml_crypto::hmac_sha256;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct Auth([u8; 32]);
    impl DurableAuthenticator for Auth {
        fn authenticate(&mut self, bytes: &[u8]) -> Result<[u8; 32], DurableError> {
            Ok(hmac_sha256(&self.0, &[bytes]))
        }
        fn verify(&mut self, bytes: &[u8], tag: &[u8; 32]) -> Result<bool, DurableError> {
            Ok(hmac_sha256(&self.0, &[bytes]) == *tag)
        }
    }

    fn temporary_directory() -> PathBuf {
        std::env::temp_dir().join(format!(
            "mrml-certd-store-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn committed_generation_reopens_and_authenticates_exact_bytes() {
        let root = temporary_directory();
        let object = DurableObjectId([7; 16]);
        let mut auth = Auth([9; 32]);
        let record = DurableRecord::prepare(
            DurableNamespace::PublicState,
            DurableRecordKind::Deployment,
            object,
            0,
            b"active-generation",
            &mut auth,
        )
        .unwrap();
        let mut store = HostedDurableStateStore::open(&root).unwrap();
        let mut transaction = DurableTransaction::prepare(&record, &mut store).unwrap();
        transaction.commit(&mut store).unwrap();
        drop(store);

        let reopened = HostedDurableStateStore::open(&root).unwrap();
        let mut encoded = [0u8; MAX_DURABLE_RECORD_BYTES];
        let length = reopened
            .load_authoritative(DurableNamespace::PublicState, object, &mut encoded)
            .unwrap()
            .unwrap();
        let recovered = DurableRecord::decode(&encoded[..length], &mut auth).unwrap();
        assert_eq!(recovered.payload(), b"active-generation");
        assert_eq!(recovered.generation, 1);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn wrong_generation_and_non_directory_root_fail_closed() {
        let root = temporary_directory();
        let mut auth = Auth([9; 32]);
        let object = DurableObjectId([7; 16]);
        let record = DurableRecord::prepare(
            DurableNamespace::PublicState,
            DurableRecordKind::Deployment,
            object,
            1,
            b"skipped",
            &mut auth,
        )
        .unwrap();
        let mut store = HostedDurableStateStore::open(&root).unwrap();
        assert!(matches!(
            store.prepare(&record),
            Err(DurableError::InvalidGeneration)
        ));
        fs::remove_dir_all(&root).unwrap();

        let file_root = temporary_directory();
        File::create(&file_root).unwrap();
        assert!(matches!(
            HostedDurableStateStore::open(&file_root),
            Err(DurableError::StoreUnavailable)
        ));
        fs::remove_file(file_root).unwrap();
    }

    #[test]
    fn renewal_checkpoint_reopens_from_authenticated_host_storage() {
        let root = temporary_directory();
        let object = DurableObjectId([4; 16]);
        let identity = crate::TlsIdentityId([3; 16]);
        let schedule = RenewalSchedule {
            identity,
            identity_generation: 1,
            policy_generation: 2,
            certificate_id: AriCertificateId::derive(&[1], &[2]).unwrap(),
            source: RenewalSource::Ari,
            renew_at_unix: 100,
            requery_ari_at_unix: 90,
            not_after_unix: 1_000,
            failure_count: 0,
            health: ExpiryHealth::Healthy,
        };
        let lease = RenewalLease {
            identity,
            identity_generation: 1,
            policy_generation: 2,
            lease_generation: 1,
            expires_at_unix: 160,
        };
        let journal = RenewalJournal::lease_acquired(lease, schedule, 0).unwrap();
        let mut auth = Auth([9; 32]);
        let mut store = HostedDurableStateStore::open(&root).unwrap();
        {
            let mut checkpoints = DurableRenewalCheckpointSink::new(object, &mut auth, &mut store);
            checkpoints.persist(journal).unwrap();
        }
        drop(store);

        let reopened = HostedDurableStateStore::open(&root).unwrap();
        let mut encoded = [0u8; MAX_DURABLE_RECORD_BYTES];
        let length = reopened
            .load_authoritative(DurableNamespace::PublicState, object, &mut encoded)
            .unwrap()
            .unwrap();
        let recovered = RenewalJournal::recover(&encoded[..length], object, &mut auth).unwrap();
        assert_eq!(recovered.stage, crate::DurableRenewalStage::LeaseAcquired);
        assert_eq!(recovered.record_generation, 1);
        assert!(recovered.previous == schedule);
        fs::remove_dir_all(&root).unwrap();
    }
}
