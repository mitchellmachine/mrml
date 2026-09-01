//! Crash-durable single-file activation for canonical active ref generations.

use mrml_runtime::{
    File, Text, Vector, canonical_path, create_dir_all, join_path, path_exists, path_is_directory,
    remove_file, rename_file,
};

use crate::{
    ActivationSnapshot, ActiveRefState, ActiveRefStateError, DurableFailure,
    MAX_ACTIVE_REF_STATE_BYTES, VerifiedRefTransaction, apply_verified_ref_transaction,
    encode_active_ref_state, parse_active_ref_state,
};

pub struct ActiveRefFile {
    directory: Text,
    active: Text,
    temporary: Text,
    lock: Text,
}

impl ActiveRefFile {
    pub fn initialize(directory: &str, state: &ActiveRefState) -> Result<Self, DurableFailure> {
        create_dir_all(directory).map_err(|_| DurableFailure::DiskFull)?;
        let store = Self::paths(directory)?;
        if path_exists(&store.active) {
            return Err(DurableFailure::StaleLock);
        }
        let encoded = encode_active_ref_state(state).map_err(|_| DurableFailure::VerifierCrash)?;
        let mut file = File::create_new(&store.temporary).map_err(|_| DurableFailure::StaleLock)?;
        file.write_all(&encoded)
            .map_err(|_| DurableFailure::ShortWrite)?;
        file.sync().map_err(|_| DurableFailure::Fsync)?;
        drop(file);
        rename_file(&store.temporary, &store.active).map_err(|_| DurableFailure::Rename)?;
        sync_ref_directory(&store.directory)?;
        let reread = store.load().map_err(|_| DurableFailure::VerifierCrash)?;
        if reread != *state {
            return Err(DurableFailure::VerifierCrash);
        }
        Ok(store)
    }

    pub fn open(directory: &str) -> Result<Self, ActiveRefStateError> {
        let store = Self::paths(directory).map_err(|_| ActiveRefStateError::Malformed)?;
        store.load()?;
        Ok(store)
    }

    pub fn load(&self) -> Result<ActiveRefState, ActiveRefStateError> {
        let mut file =
            File::open_regular(&self.active).map_err(|_| ActiveRefStateError::Malformed)?;
        let length = usize::try_from(file.len().map_err(|_| ActiveRefStateError::Malformed)?)
            .map_err(|_| ActiveRefStateError::Resource)?;
        if length > MAX_ACTIVE_REF_STATE_BYTES {
            return Err(ActiveRefStateError::Resource);
        }
        let mut bytes = Vector::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| ActiveRefStateError::Resource)?;
        bytes.resize(length, 0);
        file.read_exact(&mut bytes)
            .map_err(|_| ActiveRefStateError::Malformed)?;
        parse_active_ref_state(&bytes)
    }

    pub fn snapshot_for(
        &self,
        verified: &VerifiedRefTransaction,
    ) -> Result<ActivationSnapshot, DurableFailure> {
        let state = self.load().map_err(|_| DurableFailure::VerifierCrash)?;
        if &state.repository != verified.repository() {
            return Err(DurableFailure::StaleLock);
        }
        let mut refs = Vector::new();
        refs.try_reserve_exact(verified.updates().len())
            .map_err(|_| DurableFailure::DiskFull)?;
        for update in verified.updates() {
            let value = state
                .refs
                .iter()
                .find(|(name, _)| name == update.name())
                .map(|(_, id)| *id);
            refs.push((update.name().clone(), value));
        }
        Ok(ActivationSnapshot {
            repository_generation: state.repository_generation,
            trust_generation: state.trust_generation,
            revocation_generation: state.revocation_generation,
            refs,
        })
    }

    pub fn activate(
        &self,
        verified: &VerifiedRefTransaction,
    ) -> Result<ActiveRefState, DurableFailure> {
        let lock = File::create_new(&self.lock).map_err(|_| DurableFailure::StaleLock)?;
        lock.sync().map_err(|_| DurableFailure::Fsync)?;
        drop(lock);
        sync_ref_directory(&self.directory)?;

        let result = self.activate_while_locked(verified);
        match result {
            Ok(next) => {
                remove_file(&self.lock).map_err(|_| DurableFailure::Rename)?;
                sync_ref_directory(&self.directory)?;
                Ok(next)
            }
            Err(error) => {
                // Before rename, releasing a live lock is safe. Once rename may
                // have occurred, fsync/rename/re-read failures retain the lock
                // for recovery because the durable outcome may be uncertain.
                if matches!(
                    error,
                    DurableFailure::StaleLock
                        | DurableFailure::DiskFull
                        | DurableFailure::ShortWrite
                ) {
                    let _ = remove_file(&self.lock);
                    let _ = sync_ref_directory(&self.directory);
                }
                Err(error)
            }
        }
    }

    fn activate_while_locked(
        &self,
        verified: &VerifiedRefTransaction,
    ) -> Result<ActiveRefState, DurableFailure> {
        let current = self.load().map_err(|_| DurableFailure::VerifierCrash)?;
        let next =
            apply_verified_ref_transaction(&current, verified).map_err(|error| match error {
                ActiveRefStateError::Stale => DurableFailure::StaleLock,
                ActiveRefStateError::Resource => DurableFailure::DiskFull,
                _ => DurableFailure::VerifierCrash,
            })?;
        let encoded = encode_active_ref_state(&next).map_err(|_| DurableFailure::VerifierCrash)?;
        let mut temporary =
            File::create_new(&self.temporary).map_err(|_| DurableFailure::StaleLock)?;
        temporary
            .write_all(&encoded)
            .map_err(|_| DurableFailure::ShortWrite)?;
        temporary.sync().map_err(|_| DurableFailure::Fsync)?;
        drop(temporary);
        rename_file(&self.temporary, &self.active).map_err(|_| DurableFailure::Rename)?;
        sync_ref_directory(&self.directory)?;
        let reread = self.load().map_err(|_| DurableFailure::VerifierCrash)?;
        if reread != next {
            return Err(DurableFailure::VerifierCrash);
        }
        Ok(next)
    }

    fn paths(directory: &str) -> Result<Self, DurableFailure> {
        let directory = canonical_path(directory).map_err(|_| DurableFailure::Rename)?;
        if !path_is_directory(&directory) {
            return Err(DurableFailure::Rename);
        }
        Ok(Self {
            active: join_path(&directory, "active.refs"),
            temporary: join_path(&directory, "active.refs.new"),
            lock: join_path(&directory, "active.refs.lock"),
            directory,
        })
    }
}

#[cfg(unix)]
fn sync_ref_directory(path: &str) -> Result<(), DurableFailure> {
    mrml_runtime::sync_directory(path).map_err(|_| DurableFailure::Fsync)
}

#[cfg(not(unix))]
fn sync_ref_directory(_: &str) -> Result<(), DurableFailure> {
    Err(DurableFailure::Fsync)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::{
        CandidateRefTransaction, CandidateRefUpdate, FullRefName, HistoryVerificationLimits,
        ObjectFormat, ObjectId, PackGeneration, RepositoryGeneration, RepositoryIdentity,
        RevocationGeneration, TrustGeneration, build_verified_fast_forward_transaction,
        verify_introduced_history,
    };

    fn fixture() -> (ActiveRefState, VerifiedRefTransaction, ObjectId) {
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
                repository_generation: RepositoryGeneration(7),
                trust_generation: TrustGeneration(8),
                revocation_generation: RevocationGeneration(9),
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
        let state = ActiveRefState {
            repository,
            repository_generation: RepositoryGeneration(7),
            trust_generation: TrustGeneration(8),
            revocation_generation: RevocationGeneration(9),
            pack_generation: PackGeneration(1),
            object_format: ObjectFormat::Sha256,
            default_branch: FullRefName::parse("refs/heads/main").unwrap(),
            refs: [(FullRefName::parse("refs/heads/main").unwrap(), old)].into(),
        };
        (state, verified, new)
    }

    fn root(name: &str) -> Text {
        join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!("{name}-{}", mrml_runtime::process_id()),
        )
    }

    #[test]
    fn linux_activation_reopens_one_complete_next_generation() {
        let root = root("mrml-active-refs");
        let _ = mrml_runtime::remove_dir_all(&root);
        let (state, verified, new) = fixture();
        let store = ActiveRefFile::initialize(&root, &state).unwrap();
        let snapshot = store.snapshot_for(&verified).unwrap();
        assert_eq!(snapshot.refs[0].1, Some(state.refs[0].1));
        let next = store.activate(&verified).unwrap();
        assert_eq!(next.repository_generation, RepositoryGeneration(8));
        assert_eq!(next.refs[0].1, new);
        assert_eq!(ActiveRefFile::open(&root).unwrap().load().unwrap(), next);
        assert_eq!(store.activate(&verified), Err(DurableFailure::StaleLock));
        mrml_runtime::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn activation_lock_blocks_concurrent_or_crash_stale_writer() {
        let root = root("mrml-active-lock");
        let _ = mrml_runtime::remove_dir_all(&root);
        let (state, verified, _) = fixture();
        let store = ActiveRefFile::initialize(&root, &state).unwrap();
        mrml_runtime::write_new_file(&store.lock, b"").unwrap();
        assert_eq!(store.activate(&verified), Err(DurableFailure::StaleLock));
        assert_eq!(store.load().unwrap(), state);
        mrml_runtime::remove_dir_all(&root).unwrap();
    }
}
