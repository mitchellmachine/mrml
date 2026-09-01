//! Crash-durable single-file activation for canonical active ref generations.

use mrml_runtime::{
    File, Text, Vector, canonical_path, create_dir_all, join_path, path_exists, path_is_directory,
    remove_file, rename_file,
};

use crate::{
    ActivationSnapshot, ActiveRefState, ActiveRefStateError, DurableFailure,
    MAX_ACTIVE_REF_STATE_BYTES, MAX_PACK_SET_MANIFEST_BYTES, PackSetLimits, PackSetManifest,
    VerifiedRefTransaction, apply_verified_ref_transaction,
    apply_verified_ref_transaction_with_pack_set, encode_active_ref_state,
    encode_pack_set_manifest, parse_active_ref_state, parse_pack_set_manifest,
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

    /// Persists an immutable canonical manifest before atomically selecting its
    /// digest in the active-ref record. A crash before the ref rename can leave
    /// only an inert content-addressed manifest; a crash after rename is
    /// classified uncertain and retains the activation lock for recovery.
    pub fn activate_with_pack_set(
        &self,
        verified: &VerifiedRefTransaction,
        manifest: &PackSetManifest,
    ) -> Result<ActiveRefState, DurableFailure> {
        let lock = File::create_new(&self.lock).map_err(|_| DurableFailure::StaleLock)?;
        lock.sync().map_err(|_| DurableFailure::Fsync)?;
        drop(lock);
        sync_ref_directory(&self.directory)?;

        let result = self.activate_pack_set_while_locked(verified, manifest);
        match result {
            Ok(next) => {
                remove_file(&self.lock).map_err(|_| DurableFailure::Rename)?;
                sync_ref_directory(&self.directory)?;
                Ok(next)
            }
            Err(error) => {
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

    /// Opens only the manifest selected by the active record and rechecks its
    /// digest and every generation/identity dimension.
    pub fn load_selected_pack_set(
        &self,
        limits: PackSetLimits,
    ) -> Result<PackSetManifest, ActiveRefStateError> {
        let state = self.load()?;
        let path = self.pack_set_path(&state.pack_set_digest);
        let bytes = read_bounded(&path, MAX_PACK_SET_MANIFEST_BYTES)?;
        let manifest = parse_pack_set_manifest(&bytes, limits)
            .map_err(|_| ActiveRefStateError::Integrity)?;
        if manifest.digest().map_err(|_| ActiveRefStateError::Integrity)?
            != state.pack_set_digest
            || manifest.repository() != &state.repository
            || manifest.repository_generation() != state.repository_generation
            || manifest.pack_generation() != state.pack_generation
            || manifest.object_format() != state.object_format
        {
            return Err(ActiveRefStateError::Stale);
        }
        Ok(manifest)
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

    fn activate_pack_set_while_locked(
        &self,
        verified: &VerifiedRefTransaction,
        manifest: &PackSetManifest,
    ) -> Result<ActiveRefState, DurableFailure> {
        let current = self.load().map_err(|_| DurableFailure::VerifierCrash)?;
        let next = apply_verified_ref_transaction_with_pack_set(&current, verified, manifest)
            .map_err(|error| match error {
                ActiveRefStateError::Stale => DurableFailure::StaleLock,
                ActiveRefStateError::Resource => DurableFailure::DiskFull,
                _ => DurableFailure::VerifierCrash,
            })?;
        let manifest_bytes =
            encode_pack_set_manifest(manifest).map_err(|_| DurableFailure::VerifierCrash)?;
        let manifest_path = self.pack_set_path(&next.pack_set_digest);
        if path_exists(&manifest_path) {
            let existing = read_bounded(&manifest_path, MAX_PACK_SET_MANIFEST_BYTES)
                .map_err(|_| DurableFailure::VerifierCrash)?;
            if existing != manifest_bytes {
                return Err(DurableFailure::VerifierCrash);
            }
        } else {
            let mut file = File::create_new(&manifest_path).map_err(|_| DurableFailure::StaleLock)?;
            file.write_all(&manifest_bytes)
                .map_err(|_| DurableFailure::ShortWrite)?;
            file.sync().map_err(|_| DurableFailure::Fsync)?;
            drop(file);
            sync_ref_directory(&self.directory)?;
        }
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
        self.load_selected_pack_set(PackSetLimits {
            max_packs: u32::MAX,
            max_objects: u64::MAX,
            max_pack_bytes: u64::MAX,
            max_index_bytes: u64::MAX,
            max_work_units: u64::MAX,
        })
        .map_err(|_| DurableFailure::VerifierCrash)?;
        Ok(next)
    }

    fn pack_set_path(&self, digest: &[u8; 32]) -> Text {
        let mut name = Text::from("pack-set-");
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in digest {
            name.push(char::from(HEX[usize::from(byte >> 4)]));
            name.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        name.push_str(".manifest");
        join_path(&self.directory, &name)
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

fn read_bounded(path: &str, maximum: usize) -> Result<Vector<u8>, ActiveRefStateError> {
    let mut file = File::open_regular(path).map_err(|_| ActiveRefStateError::Malformed)?;
    let length = usize::try_from(file.len().map_err(|_| ActiveRefStateError::Malformed)?)
        .map_err(|_| ActiveRefStateError::Resource)?;
    if length == 0 || length > maximum {
        return Err(ActiveRefStateError::Resource);
    }
    let mut bytes = Vector::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| ActiveRefStateError::Resource)?;
    bytes.resize(length, 0);
    file.read_exact(&mut bytes)
        .map_err(|_| ActiveRefStateError::Malformed)?;
    Ok(bytes)
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
    use crate::pack_set::{AuthenticatedPackIndexSummary, build_pack_set_manifest};
    use crate::{
        CandidateRefTransaction, CandidateRefUpdate, FullRefName, HistoryVerificationLimits,
        ObjectFormat, ObjectId, PackGeneration, PackSetLimits, QuarantineTransactionId,
        RepositoryGeneration, RepositoryIdentity, RevocationGeneration, TrustGeneration,
        build_verified_fast_forward_transaction, verify_introduced_history,
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
            pack_set_digest: [1; 32],
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

    #[test]
    fn pack_set_is_durable_before_selection_and_reopens_by_exact_digest() {
        let root = root("mrml-active-pack-set");
        let _ = mrml_runtime::remove_dir_all(&root);
        let (state, verified, new) = fixture();
        let store = ActiveRefFile::initialize(&root, &state).unwrap();
        let limits = PackSetLimits {
            max_packs: 1,
            max_objects: 1,
            max_pack_bytes: 128,
            max_index_bytes: 128,
            max_work_units: 128,
        };
        let manifest = build_pack_set_manifest(
            state.repository.clone(),
            RepositoryGeneration(8),
            PackGeneration(2),
            state.object_format,
            [AuthenticatedPackIndexSummary {
                transaction: QuarantineTransactionId([7; 16]),
                object_count: 1,
                pack_checksum: ObjectId::Sha256([7; 32]),
                index_checksum: ObjectId::Sha256([8; 32]),
                pack_bytes: 64,
                index_bytes: 64,
                work_units: 64,
                object_ids: [new].into(),
            }]
            .into(),
            limits,
        )
        .unwrap();
        let next = store.activate_with_pack_set(&verified, &manifest).unwrap();
        assert_eq!(next.pack_set_digest, manifest.digest().unwrap());
        assert_eq!(store.load_selected_pack_set(limits).unwrap(), manifest);

        let selected = store.pack_set_path(&next.pack_set_digest);
        let mut bytes = read_bounded(&selected, MAX_PACK_SET_MANIFEST_BYTES).unwrap();
        bytes[16] ^= 1;
        mrml_runtime::remove_file(&selected).unwrap();
        let mut file = File::create_new(&selected).unwrap();
        file.write_all(&bytes).unwrap();
        file.sync().unwrap();
        assert_eq!(
            store.load_selected_pack_set(limits),
            Err(ActiveRefStateError::Integrity)
        );
        mrml_runtime::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn concurrent_same_and_distinct_repository_activations_are_isolated() {
        let same_root = root("mrml-active-concurrent-same");
        let _ = mrml_runtime::remove_dir_all(&same_root);
        let (same_state, same_verified, same_new) = fixture();
        ActiveRefFile::initialize(&same_root, &same_state).unwrap();
        let mut same_workers = Vector::new();
        for _ in 0..3 {
            let worker_root = same_root.clone();
            let worker_verified = same_verified.clone();
            let worker = match mrml_runtime::spawn_joinable(move || {
                    let _ = ActiveRefFile::open(&worker_root)
                        .unwrap()
                        .activate(&worker_verified);
                }) {
                Ok(worker) => worker,
                Err(_) => panic!("failed to start same-repository activation worker"),
            };
            same_workers.push(worker);
        }
        for worker in same_workers {
            assert!(worker.join());
        }
        let same_final = ActiveRefFile::open(&same_root).unwrap().load().unwrap();
        assert_eq!(same_final.repository_generation, RepositoryGeneration(8));
        assert_eq!(same_final.refs[0].1, same_new);

        let mut distinct_roots = Vector::new();
        let mut distinct_workers = Vector::new();
        for index in 0..3 {
            let worker_root = root(&mrml_runtime::mrml_format!(
                "mrml-active-concurrent-distinct-{index}"
            ));
            let _ = mrml_runtime::remove_dir_all(&worker_root);
            let (state, verified, _) = fixture();
            ActiveRefFile::initialize(&worker_root, &state).unwrap();
            distinct_roots.push(worker_root.clone());
            let worker = match mrml_runtime::spawn_joinable(move || {
                    ActiveRefFile::open(&worker_root)
                        .unwrap()
                        .activate(&verified)
                        .unwrap();
                }) {
                Ok(worker) => worker,
                Err(_) => panic!("failed to start distinct-repository activation worker"),
            };
            distinct_workers.push(worker);
        }
        for worker in distinct_workers {
            assert!(worker.join());
        }
        for worker_root in &distinct_roots {
            assert_eq!(
                ActiveRefFile::open(worker_root)
                    .unwrap()
                    .load()
                    .unwrap()
                    .repository_generation,
                RepositoryGeneration(8)
            );
        }

        mrml_runtime::remove_dir_all(&same_root).unwrap();
        for worker_root in distinct_roots {
            mrml_runtime::remove_dir_all(&worker_root).unwrap();
        }
    }
}
