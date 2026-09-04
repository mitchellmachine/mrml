//! Crash-durable filesystem persistence for bounded receive journals.

use mrml_runtime::{
    File, Text, Vector, canonical_path, create_dir_all, join_path, path_is_directory,
    read_directory, remove_file, rename_file,
};

use crate::{
    DurableFailure, MAX_RECEIVE_JOURNAL_BYTES, QuarantineTransaction, QuarantineTransactionId,
    ReceiveJournalError, ReceiveJournalRecord, VerifiedRefTransaction, encode_receive_journal,
    parse_receive_journal,
};

pub struct ReceiveJournalDirectory {
    root: Text,
    retained: Option<mrml_runtime::DirectoryCapability>,
}

impl ReceiveJournalDirectory {
    /// Opens an owner-selected journal directory and retains its canonical
    /// location. The hosting service must hold exclusive filesystem authority
    /// over this directory for the lifetime of the store.
    pub fn open(path: &str) -> Result<Self, DurableFailure> {
        create_dir_all(path).map_err(|_| DurableFailure::DiskFull)?;
        let root = canonical_path(path).map_err(|_| DurableFailure::Rename)?;
        if !path_is_directory(&root) {
            return Err(DurableFailure::Rename);
        }
        Ok(Self {
            root,
            retained: None,
        })
    }

    #[cfg(target_os = "linux")]
    pub fn open_capability(
        root: mrml_runtime::DirectoryCapability,
    ) -> Result<Self, DurableFailure> {
        validate_directory(&root)?;
        Ok(Self {
            root: Text::new(),
            retained: Some(root),
        })
    }

    pub fn persist(
        &self,
        transaction: &QuarantineTransaction,
        verified: &VerifiedRefTransaction,
    ) -> Result<(), DurableFailure> {
        let encoded = encode_receive_journal(transaction, verified)
            .map_err(|_| DurableFailure::VerifierCrash)?;
        let final_name = record_name(transaction.id());
        let mut temporary_name = final_name.clone();
        temporary_name.push_str(".new");
        // Exclusive creation makes a stale/tampered temporary record a
        // recovery event, never something silently truncated or followed.
        let mut file = self.create_file(&temporary_name)?;
        if let Err(error) = file.write_all(&encoded) {
            drop(file);
            return Err(map_write(error));
        }
        file.sync().map_err(|_| DurableFailure::Fsync)?;
        drop(file);
        self.rename(&temporary_name, &final_name)?;
        self.sync()?;
        Ok(())
    }

    pub fn load(
        &self,
        transaction: QuarantineTransactionId,
    ) -> Result<ReceiveJournalRecord, ReceiveJournalError> {
        let mut file = self.open_file(&record_name(transaction))?;
        let length = usize::try_from(file.len().map_err(|_| ReceiveJournalError::Malformed)?)
            .map_err(|_| ReceiveJournalError::Resource)?;
        if length > MAX_RECEIVE_JOURNAL_BYTES {
            return Err(ReceiveJournalError::Resource);
        }
        let mut bytes = Vector::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| ReceiveJournalError::Resource)?;
        bytes.resize(length, 0);
        file.read_exact(&mut bytes)
            .map_err(|_| ReceiveJournalError::Malformed)?;
        let record = parse_receive_journal(&bytes)?;
        if record.transaction != transaction {
            return Err(ReceiveJournalError::Mismatch);
        }
        Ok(record)
    }

    /// Enumerates only exact canonical journal filenames. Symlinks, temporary
    /// records and unrelated entries are rejected so recovery cannot silently
    /// skip ambiguous state.
    pub fn load_all(&self) -> Result<Vector<ReceiveJournalRecord>, ReceiveJournalError> {
        let entries = self.entries()?;
        let mut records = Vector::new();
        for entry in entries {
            if entry.is_symlink || entry.is_directory || entry.name.ends_with(".new") {
                return Err(ReceiveJournalError::Malformed);
            }
            let transaction = parse_record_name(&entry.name)?;
            records
                .try_push(self.load(transaction)?)
                .map_err(|_| ReceiveJournalError::Resource)?;
        }
        records.sort_unstable_by_key(|record| record.transaction);
        Ok(records)
    }

    pub fn remove_exact(&self, expected: &ReceiveJournalRecord) -> Result<(), DurableFailure> {
        let reread = self
            .load(expected.transaction)
            .map_err(|_| DurableFailure::VerifierCrash)?;
        if &reread != expected {
            return Err(DurableFailure::VerifierCrash);
        }
        self.remove(&record_name(expected.transaction))?;
        self.sync()
    }

    #[cfg(test)]
    fn temporary_path(&self, transaction: QuarantineTransactionId) -> Text {
        let mut name = record_name(transaction);
        name.push_str(".new");
        join_path(&self.root, &name)
    }

    fn create_file(&self, name: &str) -> Result<File, DurableFailure> {
        match &self.retained {
            Some(root) => {
                let file = root
                    .create_new_file(name, 0o600)
                    .map_err(|_| DurableFailure::StaleLock)?;
                validate_file(root, &file)?;
                Ok(file)
            }
            None => File::create_new(&join_path(&self.root, name))
                .map_err(|_| DurableFailure::StaleLock),
        }
    }

    fn open_file(&self, name: &str) -> Result<File, ReceiveJournalError> {
        match &self.retained {
            Some(root) => {
                let file = root
                    .open_regular(name)
                    .map_err(|_| ReceiveJournalError::Malformed)?;
                validate_journal_file(root, &file)?;
                Ok(file)
            }
            None => File::open_regular(&join_path(&self.root, name))
                .map_err(|_| ReceiveJournalError::Malformed),
        }
    }

    fn rename(&self, existing: &str, replacement: &str) -> Result<(), DurableFailure> {
        match &self.retained {
            Some(root) => root
                .rename_child(existing, replacement)
                .map_err(|_| DurableFailure::Rename),
            None => rename_file(
                &join_path(&self.root, existing),
                &join_path(&self.root, replacement),
            )
            .map_err(|_| DurableFailure::Rename),
        }
    }

    fn remove(&self, name: &str) -> Result<(), DurableFailure> {
        match &self.retained {
            Some(root) => root.remove_file(name).map_err(|_| DurableFailure::Rename),
            None => remove_file(&join_path(&self.root, name)).map_err(|_| DurableFailure::Rename),
        }
    }

    fn entries(&self) -> Result<Vector<mrml_runtime::DirectoryEntry>, ReceiveJournalError> {
        match &self.retained {
            Some(root) => root
                .read_directory()
                .map_err(|_| ReceiveJournalError::Malformed),
            None => read_directory(&self.root).map_err(|_| ReceiveJournalError::Malformed),
        }
    }

    fn sync(&self) -> Result<(), DurableFailure> {
        match &self.retained {
            Some(root) => root.sync().map_err(|_| DurableFailure::Fsync),
            None => sync_journal_directory(&self.root),
        }
    }
}

#[cfg(target_os = "linux")]
fn validate_directory(root: &mrml_runtime::DirectoryCapability) -> Result<(), DurableFailure> {
    let metadata = root.metadata().map_err(|_| DurableFailure::VerifierCrash)?;
    if metadata.mode & 0o777 != 0o700 || metadata.links < 2 {
        return Err(DurableFailure::VerifierCrash);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_file(
    root: &mrml_runtime::DirectoryCapability,
    file: &File,
) -> Result<(), DurableFailure> {
    let parent = root.metadata().map_err(|_| DurableFailure::VerifierCrash)?;
    let metadata = file.metadata().map_err(|_| DurableFailure::VerifierCrash)?;
    if metadata.uid != parent.uid
        || metadata.gid != parent.gid
        || metadata.mode & 0o777 != 0o600
        || metadata.links != 1
    {
        return Err(DurableFailure::VerifierCrash);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_journal_file(
    root: &mrml_runtime::DirectoryCapability,
    file: &File,
) -> Result<(), ReceiveJournalError> {
    validate_file(root, file).map_err(|_| ReceiveJournalError::Malformed)
}

fn record_name(transaction: QuarantineTransactionId) -> Text {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = Text::new();
    for byte in transaction.0 {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 15) as usize] as char);
    }
    output.push_str(".journal");
    output
}

fn parse_record_name(name: &str) -> Result<QuarantineTransactionId, ReceiveJournalError> {
    let hex = name
        .strip_suffix(".journal")
        .filter(|value| value.len() == 32)
        .ok_or(ReceiveJournalError::Malformed)?;
    let mut bytes = [0u8; 16];
    for (index, output) in bytes.iter_mut().enumerate() {
        let high = hex_digit(hex.as_bytes()[index * 2]).ok_or(ReceiveJournalError::Malformed)?;
        let low = hex_digit(hex.as_bytes()[index * 2 + 1]).ok_or(ReceiveJournalError::Malformed)?;
        *output = high * 16 + low;
    }
    if bytes == [0u8; 16] {
        return Err(ReceiveJournalError::Malformed);
    }
    Ok(QuarantineTransactionId(bytes))
}

const fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn map_write(_: mrml_runtime::FileError) -> DurableFailure {
    DurableFailure::ShortWrite
}

#[cfg(unix)]
fn sync_journal_directory(path: &str) -> Result<(), DurableFailure> {
    mrml_runtime::sync_directory(path).map_err(|_| DurableFailure::Fsync)
}

#[cfg(not(unix))]
fn sync_journal_directory(_: &str) -> Result<(), DurableFailure> {
    // The runtime does not yet expose a Windows directory-handle flush. Do not
    // claim crash durability or return success without it.
    Err(DurableFailure::Fsync)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    extern crate std;
    use crate::{
        CandidateRefTransaction, CandidateRefUpdate, FullRefName, HistoryVerificationLimits,
        ObjectId, PushStorageForecast, QuarantineLimits, QuarantinePhase, RepositoryGeneration,
        RepositoryIdentity, RevocationGeneration, TrustGeneration,
        build_verified_fast_forward_transaction, reserve_push_disk, verify_introduced_history,
    };

    fn fixture() -> (QuarantineTransaction, VerifiedRefTransaction) {
        let repository = RepositoryIdentity::parse("owner/repository").unwrap();
        let old = ObjectId::Sha256([1u8; 32]);
        let new = ObjectId::Sha256([2u8; 32]);
        let range = verify_introduced_history(
            old,
            new,
            HistoryVerificationLimits::default(),
            |id| {
                Ok(if id == new {
                    [old].into()
                } else {
                    Vector::new()
                })
            },
            |_| Ok(()),
        )
        .unwrap();
        let verified = build_verified_fast_forward_transaction(
            CandidateRefTransaction {
                repository: repository.clone(),
                repository_generation: RepositoryGeneration(3),
                trust_generation: TrustGeneration(4),
                revocation_generation: RevocationGeneration(5),
                updates: [CandidateRefUpdate {
                    name: FullRefName::parse("refs/heads/main").unwrap(),
                    expected_old: Some(old),
                    proposed_new: Some(new),
                }]
                .into(),
            },
            &[range],
        )
        .unwrap();
        let reservation = reserve_push_disk(
            QuarantineLimits {
                minimum_free_space_bytes: 0,
                ..QuarantineLimits::default()
            },
            PushStorageForecast {
                incoming_pack_bytes: 10,
                expanded_object_bytes: 20,
                largest_object_bytes: 20,
                object_count: 1,
                ref_count: 1,
                arrival_index_bytes: 10,
                staging_metadata_bytes: 10,
                audit_receipt_bytes: 10,
                ordinary_free_bytes: 100,
            },
        )
        .unwrap();
        let mut transaction = QuarantineTransaction::begin(
            QuarantineTransactionId([11u8; 16]),
            repository,
            RepositoryGeneration(3),
            TrustGeneration(4),
            RevocationGeneration(5),
            reservation,
        )
        .unwrap();
        transaction.objects_quarantined(10).unwrap();
        transaction.objects_validated(20, 1).unwrap();
        transaction.history_verified(&verified).unwrap();
        transaction.ref_updates_prepared().unwrap();
        (transaction, verified)
    }

    #[test]
    fn linux_journal_uses_durable_replace_and_reopens_exact_state() {
        let root = join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-git-journal-{}", mrml_runtime::process_id()),
        );
        let _ = mrml_runtime::remove_dir_all(&root);
        let directory = ReceiveJournalDirectory::open(&root).unwrap();
        let (mut transaction, verified) = fixture();
        directory.persist(&transaction, &verified).unwrap();
        assert_eq!(
            directory.load(transaction.id()).unwrap().phase,
            QuarantinePhase::RefUpdatesPrepared
        );
        transaction.objects_durably_installed().unwrap();
        directory.persist(&transaction, &verified).unwrap();
        assert_eq!(
            directory.load_all().unwrap()[0].phase,
            QuarantinePhase::ObjectsDurablyInstalled
        );
        mrml_runtime::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn stale_temporary_record_is_preserved_and_blocks_overwrite() {
        let root = join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-git-journal-stale-{}", mrml_runtime::process_id()),
        );
        let _ = mrml_runtime::remove_dir_all(&root);
        let directory = ReceiveJournalDirectory::open(&root).unwrap();
        let (transaction, verified) = fixture();
        let temporary = directory.temporary_path(transaction.id());
        mrml_runtime::write_new_file(&temporary, b"partial").unwrap();
        assert_eq!(
            directory.persist(&transaction, &verified),
            Err(DurableFailure::StaleLock)
        );
        assert!(directory.load_all().is_err());
        mrml_runtime::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn retained_journal_root_survives_ambient_replacement() {
        use std::os::unix::fs::PermissionsExt;

        let root = join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-git-journal-retained-{}", mrml_runtime::process_id()),
        );
        let displaced = mrml_runtime::mrml_format!("{root}-displaced");
        let _ = mrml_runtime::remove_dir_all(&root);
        let _ = mrml_runtime::remove_dir_all(&displaced);
        mrml_runtime::create_dir_all(&root).unwrap();
        std::fs::set_permissions(root.as_str(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let capability = mrml_runtime::DirectoryCapability::open_root(&root).unwrap();
        let directory = ReceiveJournalDirectory::open_capability(capability).unwrap();
        mrml_runtime::rename_file(&root, &displaced).unwrap();
        mrml_runtime::create_dir_all(&root).unwrap();
        std::fs::set_permissions(root.as_str(), std::fs::Permissions::from_mode(0o700)).unwrap();

        let (transaction, verified) = fixture();
        directory.persist(&transaction, &verified).unwrap();
        let record = directory.load(transaction.id()).unwrap();
        assert_eq!(directory.load_all().unwrap(), &[record.clone()][..]);
        assert!(mrml_runtime::path_exists(&join_path(
            &displaced,
            &record_name(transaction.id()),
        )));
        assert!(!mrml_runtime::path_exists(&join_path(
            &root,
            &record_name(transaction.id()),
        )));
        directory.remove_exact(&record).unwrap();
        assert!(directory.load_all().unwrap().is_empty());
        mrml_runtime::remove_dir_all(&root).unwrap();
        mrml_runtime::remove_dir_all(&displaced).unwrap();
    }
}
