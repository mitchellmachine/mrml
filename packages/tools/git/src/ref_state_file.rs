//! Crash-durable single-file activation for canonical active ref generations.

#[cfg(target_os = "linux")]
use mrml_runtime::DirectoryCapability;
use mrml_runtime::{
    File, Text, Vector, canonical_path, create_dir_all, join_path, path_exists, path_is_directory,
    remove_file, rename_file,
};

use crate::ref_state::apply_compaction_pack_set;
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
    #[cfg(target_os = "linux")]
    capability: Option<DirectoryCapability>,
}

impl ActiveRefFile {
    #[allow(dead_code)] // used by repository bootstrap once the compositor owns initialization
    pub(crate) fn initialize_with_pack_set(
        directory: &str,
        state: &ActiveRefState,
        manifest: &PackSetManifest,
    ) -> Result<Self, DurableFailure> {
        if manifest
            .digest()
            .map_err(|_| DurableFailure::VerifierCrash)?
            != state.pack_set_digest
            || manifest.repository() != &state.repository
            || manifest.repository_generation() != state.repository_generation
            || manifest.pack_generation() != state.pack_generation
            || manifest.object_format() != state.object_format
        {
            return Err(DurableFailure::VerifierCrash);
        }
        create_dir_all(directory).map_err(|_| DurableFailure::DiskFull)?;
        let store = Self::paths(directory)?;
        if path_exists(&store.active) {
            return Err(DurableFailure::StaleLock);
        }
        store.persist_manifest(manifest, &state.pack_set_digest)?;
        Self::initialize(directory, state)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn initialize_with_pack_set_capability(
        capability: DirectoryCapability,
        state: &ActiveRefState,
        manifest: &PackSetManifest,
    ) -> Result<Self, DurableFailure> {
        if manifest
            .digest()
            .map_err(|_| DurableFailure::VerifierCrash)?
            != state.pack_set_digest
            || manifest.repository() != &state.repository
            || manifest.repository_generation() != state.repository_generation
            || manifest.pack_generation() != state.pack_generation
            || manifest.object_format() != state.object_format
        {
            return Err(DurableFailure::VerifierCrash);
        }
        let store = Self::from_capability(capability).map_err(|_| DurableFailure::VerifierCrash)?;
        if store
            .capability
            .as_ref()
            .ok_or(DurableFailure::VerifierCrash)?
            .read_directory()
            .map_err(|_| DurableFailure::VerifierCrash)?
            .iter()
            .any(|entry| {
                entry.name.as_str() == store.active.as_str()
                    || entry.name.as_str() == store.temporary.as_str()
            })
        {
            return Err(DurableFailure::StaleLock);
        }
        store.persist_manifest(manifest, &state.pack_set_digest)?;
        let encoded = encode_active_ref_state(state).map_err(|_| DurableFailure::VerifierCrash)?;
        let mut temporary = store.create_new(&store.temporary, "active.refs.new")?;
        temporary
            .write_all(&encoded)
            .map_err(|_| DurableFailure::ShortWrite)?;
        temporary.sync().map_err(|_| DurableFailure::Fsync)?;
        drop(temporary);
        let capability = store
            .capability
            .as_ref()
            .ok_or(DurableFailure::VerifierCrash)?;
        if capability
            .hard_link_child("active.refs.new", "active.refs")
            .is_err()
        {
            let _ = capability.remove_file("active.refs.new");
            return Err(DurableFailure::StaleLock);
        }
        capability
            .remove_file("active.refs.new")
            .map_err(|_| DurableFailure::Fsync)?;
        store.sync_directory()?;
        if store.load().map_err(|_| DurableFailure::VerifierCrash)? != *state {
            return Err(DurableFailure::VerifierCrash);
        }
        store
            .load_selected_pack_set(PackSetLimits {
                max_packs: u32::MAX,
                max_objects: u64::MAX,
                max_pack_bytes: u64::MAX,
                max_index_bytes: u64::MAX,
                max_work_units: u64::MAX,
            })
            .map_err(|_| DurableFailure::VerifierCrash)?;
        Ok(store)
    }

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

    #[cfg(target_os = "linux")]
    pub fn open_capability(capability: DirectoryCapability) -> Result<Self, ActiveRefStateError> {
        let store = Self::from_capability(capability)?;
        store.load()?;
        Ok(store)
    }

    #[cfg(target_os = "linux")]
    fn from_capability(capability: DirectoryCapability) -> Result<Self, ActiveRefStateError> {
        let metadata = capability
            .metadata()
            .map_err(|_| ActiveRefStateError::Malformed)?;
        if metadata.mode & 0o022 != 0
            || metadata.mode & 0o500 != 0o500
            || metadata.mode & 0o200 == 0
            || metadata.links < 2
        {
            return Err(ActiveRefStateError::Malformed);
        }
        Ok(Self {
            directory: Text::new(),
            active: Text::from("active.refs"),
            temporary: Text::from("active.refs.new"),
            lock: Text::from("active.refs.lock"),
            capability: Some(capability),
        })
    }

    pub fn load(&self) -> Result<ActiveRefState, ActiveRefStateError> {
        let mut file = self.open_regular(&self.active, "active.refs")?;
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
        let lock = self.create_new(&self.lock, "active.refs.lock")?;
        lock.sync().map_err(|_| DurableFailure::Fsync)?;
        drop(lock);
        self.sync_directory()?;

        let result = self.activate_while_locked(verified);
        match result {
            Ok(next) => {
                self.remove(&self.lock, "active.refs.lock")?;
                self.sync_directory()?;
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
                    let _ = self.remove(&self.lock, "active.refs.lock");
                    let _ = self.sync_directory();
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
        let lock = self.create_new(&self.lock, "active.refs.lock")?;
        lock.sync().map_err(|_| DurableFailure::Fsync)?;
        drop(lock);
        self.sync_directory()?;

        let result = self.activate_pack_set_while_locked(verified, manifest);
        match result {
            Ok(next) => {
                self.remove(&self.lock, "active.refs.lock")?;
                self.sync_directory()?;
                Ok(next)
            }
            Err(error) => {
                if matches!(
                    error,
                    DurableFailure::StaleLock
                        | DurableFailure::DiskFull
                        | DurableFailure::ShortWrite
                ) {
                    let _ = self.remove(&self.lock, "active.refs.lock");
                    let _ = self.sync_directory();
                }
                Err(error)
            }
        }
    }

    /// Durably selects a compacted pack set under the same activation lock as
    /// pushes, then immediately reopens the exact next generation.
    #[allow(dead_code)] // invoked by the internal Linux compaction compositor
    pub(crate) fn activate_compaction(
        &self,
        manifest: &PackSetManifest,
    ) -> Result<ActiveRefState, DurableFailure> {
        let lock = self.create_new(&self.lock, "active.refs.lock")?;
        lock.sync().map_err(|_| DurableFailure::Fsync)?;
        drop(lock);
        self.sync_directory()?;
        let result = self.activate_compaction_while_locked(manifest);
        match result {
            Ok(next) => {
                self.remove(&self.lock, "active.refs.lock")?;
                self.sync_directory()?;
                Ok(next)
            }
            Err(error) => {
                if matches!(
                    error,
                    DurableFailure::StaleLock
                        | DurableFailure::DiskFull
                        | DurableFailure::ShortWrite
                ) {
                    let _ = self.remove(&self.lock, "active.refs.lock");
                    let _ = self.sync_directory();
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
        let name = Self::pack_set_name(&state.pack_set_digest);
        let path = self.pack_set_path(&state.pack_set_digest);
        let bytes = self.read_bounded(&path, &name, MAX_PACK_SET_MANIFEST_BYTES)?;
        let manifest =
            parse_pack_set_manifest(&bytes, limits).map_err(|_| ActiveRefStateError::Integrity)?;
        if manifest
            .digest()
            .map_err(|_| ActiveRefStateError::Integrity)?
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
        let mut temporary = self.create_new(&self.temporary, "active.refs.new")?;
        temporary
            .write_all(&encoded)
            .map_err(|_| DurableFailure::ShortWrite)?;
        temporary.sync().map_err(|_| DurableFailure::Fsync)?;
        drop(temporary);
        self.rename(
            &self.temporary,
            "active.refs.new",
            &self.active,
            "active.refs",
        )?;
        self.sync_directory()?;
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
        let manifest_name = Self::pack_set_name(&next.pack_set_digest);
        let manifest_path = self.pack_set_path(&next.pack_set_digest);
        self.persist_manifest_bytes(&manifest_path, &manifest_name, &manifest_bytes)?;
        let encoded = encode_active_ref_state(&next).map_err(|_| DurableFailure::VerifierCrash)?;
        let mut temporary = self.create_new(&self.temporary, "active.refs.new")?;
        temporary
            .write_all(&encoded)
            .map_err(|_| DurableFailure::ShortWrite)?;
        temporary.sync().map_err(|_| DurableFailure::Fsync)?;
        drop(temporary);
        self.rename(
            &self.temporary,
            "active.refs.new",
            &self.active,
            "active.refs",
        )?;
        self.sync_directory()?;
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

    #[allow(dead_code)] // invoked by activate_compaction once service wiring lands
    fn activate_compaction_while_locked(
        &self,
        manifest: &PackSetManifest,
    ) -> Result<ActiveRefState, DurableFailure> {
        let current = self.load().map_err(|_| DurableFailure::VerifierCrash)?;
        let next = apply_compaction_pack_set(&current, manifest).map_err(|error| match error {
            ActiveRefStateError::Stale => DurableFailure::StaleLock,
            ActiveRefStateError::Resource => DurableFailure::DiskFull,
            _ => DurableFailure::VerifierCrash,
        })?;
        let manifest_bytes =
            encode_pack_set_manifest(manifest).map_err(|_| DurableFailure::VerifierCrash)?;
        let manifest_name = Self::pack_set_name(&next.pack_set_digest);
        self.persist_manifest_bytes(
            &self.pack_set_path(&next.pack_set_digest),
            &manifest_name,
            &manifest_bytes,
        )?;
        let encoded = encode_active_ref_state(&next).map_err(|_| DurableFailure::VerifierCrash)?;
        let mut temporary = self.create_new(&self.temporary, "active.refs.new")?;
        temporary
            .write_all(&encoded)
            .map_err(|_| DurableFailure::ShortWrite)?;
        temporary.sync().map_err(|_| DurableFailure::Fsync)?;
        drop(temporary);
        self.rename(
            &self.temporary,
            "active.refs.new",
            &self.active,
            "active.refs",
        )?;
        self.sync_directory()?;
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
        join_path(&self.directory, &Self::pack_set_name(digest))
    }

    fn pack_set_name(digest: &[u8; 32]) -> Text {
        let mut name = Text::from("pack-set-");
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in digest {
            name.push(char::from(HEX[usize::from(byte >> 4)]));
            name.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        name.push_str(".manifest");
        name
    }

    #[allow(dead_code)]
    fn persist_manifest(
        &self,
        manifest: &PackSetManifest,
        digest: &[u8; 32],
    ) -> Result<(), DurableFailure> {
        let bytes =
            encode_pack_set_manifest(manifest).map_err(|_| DurableFailure::VerifierCrash)?;
        self.persist_manifest_bytes(
            &self.pack_set_path(digest),
            &Self::pack_set_name(digest),
            &bytes,
        )
    }

    fn persist_manifest_bytes(
        &self,
        path: &str,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), DurableFailure> {
        if self.open_regular(path, name).is_ok() {
            let existing = self
                .read_bounded(path, name, MAX_PACK_SET_MANIFEST_BYTES)
                .map_err(|_| DurableFailure::VerifierCrash)?;
            if existing != bytes {
                return Err(DurableFailure::VerifierCrash);
            }
            return Ok(());
        }
        let mut file = self.create_new(path, name)?;
        file.write_all(bytes)
            .map_err(|_| DurableFailure::ShortWrite)?;
        file.sync().map_err(|_| DurableFailure::Fsync)?;
        drop(file);
        self.sync_directory()
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
            #[cfg(target_os = "linux")]
            capability: None,
        })
    }

    fn open_regular(&self, path: &str, name: &str) -> Result<File, ActiveRefStateError> {
        #[cfg(target_os = "linux")]
        if let Some(capability) = &self.capability {
            let file = capability
                .open_regular(name)
                .map_err(|_| ActiveRefStateError::Malformed)?;
            let file_metadata = file
                .metadata()
                .map_err(|_| ActiveRefStateError::Malformed)?;
            let directory_metadata = capability
                .metadata()
                .map_err(|_| ActiveRefStateError::Malformed)?;
            if file_metadata.links != 1
                || file_metadata.uid != directory_metadata.uid
                || file_metadata.gid != directory_metadata.gid
                || file_metadata.mode & 0o022 != 0
            {
                return Err(ActiveRefStateError::Malformed);
            }
            return Ok(file);
        }
        File::open_regular(path).map_err(|_| ActiveRefStateError::Malformed)
    }

    fn create_new(&self, path: &str, name: &str) -> Result<File, DurableFailure> {
        #[cfg(target_os = "linux")]
        if let Some(capability) = &self.capability {
            return capability
                .create_new_file(name, 0o600)
                .map_err(|_| DurableFailure::StaleLock);
        }
        File::create_new(path).map_err(|_| DurableFailure::StaleLock)
    }

    fn rename(
        &self,
        existing_path: &str,
        existing_name: &str,
        replacement_path: &str,
        replacement_name: &str,
    ) -> Result<(), DurableFailure> {
        #[cfg(target_os = "linux")]
        if let Some(capability) = &self.capability {
            return capability
                .rename_child(existing_name, replacement_name)
                .map_err(|_| DurableFailure::Rename);
        }
        rename_file(existing_path, replacement_path).map_err(|_| DurableFailure::Rename)
    }

    fn remove(&self, path: &str, name: &str) -> Result<(), DurableFailure> {
        #[cfg(target_os = "linux")]
        if let Some(capability) = &self.capability {
            return capability
                .remove_file(name)
                .map_err(|_| DurableFailure::Rename);
        }
        remove_file(path).map_err(|_| DurableFailure::Rename)
    }

    fn sync_directory(&self) -> Result<(), DurableFailure> {
        #[cfg(target_os = "linux")]
        if let Some(capability) = &self.capability {
            return capability.sync().map_err(|_| DurableFailure::Fsync);
        }
        sync_ref_directory(&self.directory)
    }

    fn read_bounded(
        &self,
        path: &str,
        name: &str,
        maximum: usize,
    ) -> Result<Vector<u8>, ActiveRefStateError> {
        let mut file = self.open_regular(path, name)?;
        read_bounded_file(&mut file, maximum)
    }
}

#[cfg(test)]
fn read_bounded(path: &str, maximum: usize) -> Result<Vector<u8>, ActiveRefStateError> {
    let mut file = File::open_regular(path).map_err(|_| ActiveRefStateError::Malformed)?;
    read_bounded_file(&mut file, maximum)
}

fn read_bounded_file(file: &mut File, maximum: usize) -> Result<Vector<u8>, ActiveRefStateError> {
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
    extern crate std;
    use crate::pack_set::{AuthenticatedPackIndexSummary, build_pack_set_manifest};
    use crate::{
        CandidateRefTransaction, CandidateRefUpdate, FullRefName, HistoryVerificationLimits,
        ObjectFormat, ObjectId, PackGeneration, PackSetLimits, QuarantineTransactionId,
        RepositoryGeneration, RepositoryIdentity, RevocationGeneration, TrustGeneration,
        build_verified_fast_forward_transaction, verify_introduced_history,
    };
    use core::sync::atomic::{AtomicUsize, Ordering};
    use mrml_runtime::{Command, Shared, path_exists, process_id, read_directory, write_new_file};

    fn fixture() -> (ActiveRefState, VerifiedRefTransaction, ObjectId) {
        fixture_for("owner/repository")
    }

    fn fixture_for(identity: &str) -> (ActiveRefState, VerifiedRefTransaction, ObjectId) {
        let repository = RepositoryIdentity::parse(identity).unwrap();
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
    #[cfg(target_os = "linux")]
    fn capability_activation_survives_directory_swap_and_rejects_hard_links() {
        let root_path = root("mrml-active-capability");
        let displaced = root("mrml-active-capability-displaced");
        let _ = mrml_runtime::remove_dir_all(&root_path);
        let _ = mrml_runtime::remove_dir_all(&displaced);
        let (state, verified, new) = fixture();
        ActiveRefFile::initialize(&root_path, &state).unwrap();
        let capability = DirectoryCapability::open_root(&root_path).unwrap();
        let retained = ActiveRefFile::open_capability(capability).unwrap();
        mrml_runtime::rename_file(&root_path, &displaced).unwrap();
        ActiveRefFile::initialize(&root_path, &state).unwrap();

        let next = retained.activate(&verified).unwrap();
        assert_eq!(next.refs[0].1, new);
        assert_eq!(
            ActiveRefFile::open(&displaced).unwrap().load().unwrap(),
            next
        );
        assert_eq!(
            ActiveRefFile::open(&root_path).unwrap().load().unwrap(),
            state
        );
        drop(retained);
        mrml_runtime::remove_dir_all(&root_path).unwrap();
        mrml_runtime::remove_dir_all(&displaced).unwrap();

        let linked = root("mrml-active-capability-linked");
        let _ = mrml_runtime::remove_dir_all(&linked);
        ActiveRefFile::initialize(&linked, &state).unwrap();
        std::fs::hard_link(
            join_path(&linked, "active.refs").as_str(),
            join_path(&linked, "active.refs.link").as_str(),
        )
        .unwrap();
        assert!(
            ActiveRefFile::open_capability(DirectoryCapability::open_root(&linked).unwrap())
                .is_err()
        );
        mrml_runtime::remove_dir_all(&linked).unwrap();
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
    fn retained_initial_ref_and_pack_set_publication_survives_replacement() {
        let root = root("mrml-active-initialize-retained");
        let displaced = mrml_runtime::mrml_format!("{root}-displaced");
        let _ = mrml_runtime::remove_dir_all(&root);
        let _ = mrml_runtime::remove_dir_all(&displaced);
        mrml_runtime::create_dir_all(&root).unwrap();
        let capability = DirectoryCapability::open_root(&root).unwrap();
        mrml_runtime::rename_file(&root, &displaced).unwrap();
        mrml_runtime::create_dir_all(&root).unwrap();
        let (mut state, _, _) = fixture();
        let limits = PackSetLimits {
            max_packs: 1,
            max_objects: 1,
            max_pack_bytes: 128,
            max_index_bytes: 128,
            max_work_units: 128,
        };
        let manifest = build_pack_set_manifest(
            state.repository.clone(),
            state.repository_generation,
            state.pack_generation,
            state.object_format,
            Vector::new(),
            limits,
        )
        .unwrap();
        state.pack_set_digest = manifest.digest().unwrap();

        let store = ActiveRefFile::initialize_with_pack_set_capability(
            capability,
            &state,
            &manifest,
        )
        .unwrap();
        assert_eq!(store.load().unwrap(), state);
        assert_eq!(store.load_selected_pack_set(limits).unwrap(), manifest);
        assert!(path_exists(&join_path(&displaced, "active.refs")));
        assert!(!path_exists(&join_path(&root, "active.refs")));

        drop(store);
        mrml_runtime::remove_dir_all(&root).unwrap();
        mrml_runtime::remove_dir_all(&displaced).unwrap();
    }

    #[test]
    fn concurrent_same_and_distinct_repository_activations_are_isolated() {
        let same_root = root("mrml-active-concurrent-same");
        let other_root = root("mrml-active-concurrent-other");
        let _ = mrml_runtime::remove_dir_all(&same_root);
        let _ = mrml_runtime::remove_dir_all(&other_root);
        let (same_state, same_verified, same_new) = fixture();
        let (other_state, other_verified, other_new) = fixture_for("owner/other");
        ActiveRefFile::initialize(&same_root, &same_state).unwrap();
        ActiveRefFile::initialize(&other_root, &other_state).unwrap();
        let ready = Shared::new(AtomicUsize::new(0));
        let same_success = Shared::new(AtomicUsize::new(0));
        let same_stale = Shared::new(AtomicUsize::new(0));
        let unexpected = Shared::new(AtomicUsize::new(0));
        let other_success = Shared::new(AtomicUsize::new(0));
        let mut workers = Vector::new();
        for _ in 0..2 {
            let worker_root = same_root.clone();
            let worker_verified = same_verified.clone();
            let worker_ready = ready.clone();
            let worker_success = same_success.clone();
            let worker_stale = same_stale.clone();
            let worker_unexpected = unexpected.clone();
            let worker = match mrml_runtime::spawn_joinable(move || {
                worker_ready.fetch_add(1, Ordering::AcqRel);
                while worker_ready.load(Ordering::Acquire) != 3 {
                    mrml_runtime::yield_now();
                }
                match ActiveRefFile::open(&worker_root)
                    .unwrap()
                    .activate(&worker_verified)
                {
                    Ok(_) => {
                        worker_success.fetch_add(1, Ordering::AcqRel);
                    }
                    Err(DurableFailure::StaleLock) => {
                        worker_stale.fetch_add(1, Ordering::AcqRel);
                    }
                    Err(_) => {
                        worker_unexpected.fetch_add(1, Ordering::AcqRel);
                    }
                }
            }) {
                Ok(worker) => worker,
                Err(_) => panic!("failed to start same-repository activation worker"),
            };
            workers.push(worker);
        }
        let worker_ready = ready.clone();
        let worker_success = other_success.clone();
        let other_worker = match mrml_runtime::spawn_joinable(move || {
            worker_ready.fetch_add(1, Ordering::AcqRel);
            while worker_ready.load(Ordering::Acquire) != 3 {
                mrml_runtime::yield_now();
            }
            if ActiveRefFile::open(&other_root)
                .unwrap()
                .activate(&other_verified)
                .is_ok()
            {
                worker_success.fetch_add(1, Ordering::AcqRel);
            }
        }) {
            Ok(worker) => worker,
            Err(_) => panic!("failed to start distinct-repository activation worker"),
        };
        workers.push(other_worker);
        for worker in workers {
            assert!(worker.join());
        }
        assert_eq!(same_success.load(Ordering::Acquire), 1);
        assert_eq!(same_stale.load(Ordering::Acquire), 1);
        assert_eq!(unexpected.load(Ordering::Acquire), 0);
        assert_eq!(other_success.load(Ordering::Acquire), 1);
        let same_final = ActiveRefFile::open(&same_root).unwrap().load().unwrap();
        assert_eq!(
            (same_final.repository_generation, same_final.refs[0].1),
            (RepositoryGeneration(8), same_new)
        );
        let other_final = ActiveRefFile::open(&root("mrml-active-concurrent-other"))
            .unwrap()
            .load()
            .unwrap();
        assert_eq!(
            (other_final.repository_generation, other_final.refs[0].1),
            (RepositoryGeneration(8), other_new)
        );
        mrml_runtime::remove_dir_all(&same_root).unwrap();
        mrml_runtime::remove_dir_all(&root("mrml-active-concurrent-other")).unwrap();
    }

    #[test]
    fn child_process_attempts_one_marked_activation() {
        if !path_exists("run-multiprocess-helper") {
            return;
        }
        let (_, verified, _) = if path_exists("other-repository") {
            fixture_for("owner/other")
        } else {
            fixture()
        };
        let ready = mrml_runtime::mrml_format!("ready-{}", process_id());
        write_new_file(&ready, b"ready").unwrap();
        while !path_exists("release") {
            mrml_runtime::yield_now();
        }
        let outcome = match ActiveRefFile::open(".").unwrap().activate(&verified) {
            Ok(_) => "success",
            Err(DurableFailure::StaleLock) => "stale",
            Err(error) => panic!("unexpected activation result: {error:?}"),
        };
        let name = mrml_runtime::mrml_format!("outcome-{outcome}-{}", process_id());
        write_new_file(&name, b"complete").unwrap();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn separate_processes_serialize_same_repository_and_isolate_distinct_repository() {
        let same_root = root("mrml-active-process-same");
        let other_root = root("mrml-active-process-other");
        let _ = mrml_runtime::remove_dir_all(&same_root);
        let _ = mrml_runtime::remove_dir_all(&other_root);
        let (same_state, _, same_new) = fixture();
        let (other_state, _, other_new) = fixture_for("owner/other");
        ActiveRefFile::initialize(&same_root, &same_state).unwrap();
        ActiveRefFile::initialize(&other_root, &other_state).unwrap();
        write_new_file(&join_path(&same_root, "run-multiprocess-helper"), b"run").unwrap();
        write_new_file(&join_path(&other_root, "run-multiprocess-helper"), b"run").unwrap();
        write_new_file(&join_path(&other_root, "other-repository"), b"other").unwrap();

        let mut children = Vector::new();
        for directory in [&same_root, &same_root, &other_root] {
            let mut command = Command::new("/proc/self/exe");
            command
                .args([
                    "--exact",
                    "ref_state_file::tests::child_process_attempts_one_marked_activation",
                    "--nocapture",
                ])
                .current_dir(directory);
            children.push(command.spawn_silent().unwrap());
        }
        for _ in 0..1_000_000 {
            let same_ready = read_directory(&same_root)
                .unwrap()
                .iter()
                .filter(|entry| entry.name.starts_with("ready-"))
                .count();
            let other_ready = read_directory(&other_root)
                .unwrap()
                .iter()
                .filter(|entry| entry.name.starts_with("ready-"))
                .count();
            if same_ready == 2 && other_ready == 1 {
                break;
            }
            mrml_runtime::yield_now();
        }
        assert_eq!(
            read_directory(&same_root)
                .unwrap()
                .iter()
                .filter(|entry| entry.name.starts_with("ready-"))
                .count(),
            2
        );
        assert_eq!(
            read_directory(&other_root)
                .unwrap()
                .iter()
                .filter(|entry| entry.name.starts_with("ready-"))
                .count(),
            1
        );
        write_new_file(&join_path(&same_root, "release"), b"release").unwrap();
        write_new_file(&join_path(&other_root, "release"), b"release").unwrap();
        for mut child in children {
            assert!(child.wait().unwrap().success());
        }

        let same_entries = read_directory(&same_root).unwrap();
        assert_eq!(
            same_entries
                .iter()
                .filter(|entry| entry.name.starts_with("outcome-success-"))
                .count(),
            1
        );
        assert_eq!(
            same_entries
                .iter()
                .filter(|entry| entry.name.starts_with("outcome-stale-"))
                .count(),
            1
        );
        let other_entries = read_directory(&other_root).unwrap();
        assert_eq!(
            other_entries
                .iter()
                .filter(|entry| entry.name.starts_with("outcome-success-"))
                .count(),
            1
        );
        assert_eq!(
            other_entries
                .iter()
                .filter(|entry| entry.name.starts_with("outcome-stale-"))
                .count(),
            0
        );

        let same_final = ActiveRefFile::open(&same_root).unwrap().load().unwrap();
        assert_eq!(
            (same_final.repository_generation, same_final.refs[0].1),
            (RepositoryGeneration(8), same_new)
        );
        let other_final = ActiveRefFile::open(&other_root).unwrap().load().unwrap();
        assert_eq!(
            (other_final.repository_generation, other_final.refs[0].1),
            (RepositoryGeneration(8), other_new)
        );
        mrml_runtime::remove_dir_all(&same_root).unwrap();
        mrml_runtime::remove_dir_all(&other_root).unwrap();
    }
}
