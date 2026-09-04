//! Isolated, immutable arrival-pack staging and durable installation.

use core::sync::atomic::{AtomicU64, Ordering};
use mrml_runtime::{
    File, OrderedMap, SpinMutex, Text, Vector, canonical_path, create_dir_all, join_path,
    path_exists, path_is_directory, rename_file,
};

use crate::pack_file::validate_pack_file_with_bases_from_opener;
use crate::pack_set::AuthenticatedPackIndexSummary;
use crate::sha1::GitObjectHasher;
use crate::{
    BoundedRead, DEFAULT_MAX_EXPANDED_OBJECT_BYTES, DEFAULT_MAX_INCOMING_PACK_BYTES,
    DEFAULT_MAX_INDIVIDUAL_OBJECT_BYTES, DurableFailure, GitdCoreError, ObjectFormat, ObjectId,
    PackError, PackSetManifest, QuarantineTransaction, QuarantineTransactionId,
    build_pack_index_v2, parse_pack_index_v2, parse_pack_with_index,
};

enum ArrivalDirectory {
    Ambient(Text),
    #[cfg(target_os = "linux")]
    Retained(mrml_runtime::DirectoryCapability),
}

impl ArrivalDirectory {
    fn open_child(&self, name: &str) -> Result<Self, DurableFailure> {
        match self {
            Self::Ambient(path) => {
                let child = join_path(path, name);
                if !path_is_directory(&child) {
                    return Err(DurableFailure::VerifierCrash);
                }
                Ok(Self::Ambient(child))
            }
            #[cfg(target_os = "linux")]
            Self::Retained(directory) => {
                let parent = directory
                    .metadata()
                    .map_err(|_| DurableFailure::VerifierCrash)?;
                let child = directory
                    .open_directory(name)
                    .map_err(|_| DurableFailure::VerifierCrash)?;
                let metadata = child
                    .metadata()
                    .map_err(|_| DurableFailure::VerifierCrash)?;
                if metadata.uid != parent.uid
                    || metadata.gid != parent.gid
                    || metadata.mode & 0o777 != 0o700
                    || metadata.links < 2
                {
                    return Err(DurableFailure::VerifierCrash);
                }
                Ok(Self::Retained(child))
            }
        }
    }

    fn create_child(&self, name: &str) -> Result<Self, DurableFailure> {
        match self {
            Self::Ambient(path) => {
                let child = join_path(path, name);
                if path_exists(&child) {
                    return Err(DurableFailure::StaleLock);
                }
                create_dir_all(&child).map_err(|_| DurableFailure::DiskFull)?;
                Ok(Self::Ambient(child))
            }
            #[cfg(target_os = "linux")]
            Self::Retained(directory) => {
                let parent = directory
                    .metadata()
                    .map_err(|_| DurableFailure::VerifierCrash)?;
                let child = directory
                    .create_directory(name, 0o700)
                    .map_err(|_| DurableFailure::StaleLock)?;
                let metadata = child
                    .metadata()
                    .map_err(|_| DurableFailure::VerifierCrash)?;
                if metadata.uid != parent.uid
                    || metadata.gid != parent.gid
                    || metadata.mode & 0o777 != 0o700
                    || metadata.links < 2
                {
                    return Err(DurableFailure::VerifierCrash);
                }
                Ok(Self::Retained(child))
            }
        }
    }

    fn open_regular(&self, name: &str) -> Result<File, DurableFailure> {
        match self {
            Self::Ambient(path) => File::open_regular(&join_path(path, name))
                .map_err(|_| DurableFailure::VerifierCrash),
            #[cfg(target_os = "linux")]
            Self::Retained(directory) => {
                let parent = directory
                    .metadata()
                    .map_err(|_| DurableFailure::VerifierCrash)?;
                let file = directory
                    .open_regular(name)
                    .map_err(|_| DurableFailure::VerifierCrash)?;
                let metadata = file.metadata().map_err(|_| DurableFailure::VerifierCrash)?;
                if metadata.uid != parent.uid
                    || metadata.gid != parent.gid
                    || metadata.mode & 0o777 != 0o600
                    || metadata.links != 1
                {
                    return Err(DurableFailure::VerifierCrash);
                }
                Ok(file)
            }
        }
    }

    fn create_file(&self, name: &str) -> Result<File, DurableFailure> {
        match self {
            Self::Ambient(path) => {
                File::create_new(&join_path(path, name)).map_err(|_| DurableFailure::StaleLock)
            }
            #[cfg(target_os = "linux")]
            Self::Retained(directory) => {
                let parent = directory
                    .metadata()
                    .map_err(|_| DurableFailure::VerifierCrash)?;
                let file = directory
                    .create_new_file(name, 0o600)
                    .map_err(|_| DurableFailure::StaleLock)?;
                let metadata = file.metadata().map_err(|_| DurableFailure::VerifierCrash)?;
                if metadata.uid != parent.uid
                    || metadata.gid != parent.gid
                    || metadata.mode & 0o777 != 0o600
                    || metadata.links != 1
                {
                    return Err(DurableFailure::VerifierCrash);
                }
                Ok(file)
            }
        }
    }

    fn rename_child(&self, existing: &str, replacement: &str) -> Result<(), DurableFailure> {
        match self {
            Self::Ambient(path) => {
                rename_file(&join_path(path, existing), &join_path(path, replacement))
            }
            #[cfg(target_os = "linux")]
            Self::Retained(directory) => directory.rename_child(existing, replacement),
        }
        .map_err(|_| DurableFailure::Rename)
    }

    fn move_child_to(
        &self,
        existing: &str,
        destination: &Self,
        replacement: &str,
    ) -> Result<(), DurableFailure> {
        match (self, destination) {
            (Self::Ambient(source), Self::Ambient(destination)) => rename_file(
                &join_path(source, existing),
                &join_path(destination, replacement),
            ),
            #[cfg(target_os = "linux")]
            (Self::Retained(source), Self::Retained(destination)) => {
                source.rename_child_to(existing, destination, replacement)
            }
            #[cfg(target_os = "linux")]
            _ => return Err(DurableFailure::Rename),
        }
        .map_err(|_| DurableFailure::Rename)
    }

    fn sync(&self) -> Result<(), DurableFailure> {
        match self {
            Self::Ambient(path) => sync_pack_directory(path),
            #[cfg(target_os = "linux")]
            Self::Retained(directory) => directory.sync().map_err(|_| DurableFailure::Fsync),
        }
    }
}

pub struct ArrivalPackStore {
    quarantine: Text,
    arrivals: Text,
    retained: Option<RetainedArrivalDirectories>,
    format: ObjectFormat,
    max_pack_bytes: u64,
    selected: SpinMutex<Option<AuthenticatedSelectedPackSnapshot>>,
    statistics: ArrivalPackReadStatistics,
}

struct RetainedArrivalDirectories {
    quarantine: ArrivalDirectory,
    arrivals: ArrivalDirectory,
}

struct AuthenticatedSelectedPackSnapshot {
    manifest_digest: [u8; 32],
    repository_generation: crate::RepositoryGeneration,
    pack_generation: crate::PackGeneration,
    objects: OrderedMap<ObjectId, QuarantineTransactionId>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ArrivalPackReadStatisticsSnapshot {
    pub complete_pack_validations: u64,
    pub pack_index_parses: u64,
    pub object_lookups: u64,
    pub object_reads: u64,
    pub bytes_read: u64,
    pub hash_checks: u64,
}

#[derive(Default)]
struct ArrivalPackReadStatistics {
    complete_pack_validations: AtomicU64,
    pack_index_parses: AtomicU64,
    object_lookups: AtomicU64,
    object_reads: AtomicU64,
    bytes_read: AtomicU64,
    hash_checks: AtomicU64,
}

impl ArrivalPackStore {
    /// Stages an already independently verified compaction result using the
    /// same immutable directory format as a received pack. The transaction ID
    /// is derived by the compaction compositor, never supplied by an edge.
    #[allow(dead_code)] // invoked by the internal Linux compaction compositor
    pub(crate) fn stage_compacted_pack(
        &self,
        transaction: QuarantineTransactionId,
        pack: &[u8],
        expected_ids: &[ObjectId],
    ) -> Result<AuthenticatedPackIndexSummary, DurableFailure> {
        if expected_ids.is_empty()
            || u64::try_from(pack.len()).map_err(|_| DurableFailure::DiskFull)?
                > self.max_pack_bytes
        {
            return Err(DurableFailure::DiskFull);
        }
        let (objects, entries) =
            parse_pack_with_index(pack, self.format).map_err(|_| DurableFailure::VerifierCrash)?;
        if objects.len() != expected_ids.len()
            || objects
                .iter()
                .zip(expected_ids)
                .any(|(object, expected)| object.id != *expected)
        {
            return Err(DurableFailure::VerifierCrash);
        }
        let trailer = ObjectId::from_bytes(
            self.format,
            pack.get(pack.len().saturating_sub(self.format.hash_len())..)
                .ok_or(DurableFailure::VerifierCrash)?,
        )
        .ok_or(DurableFailure::VerifierCrash)?;
        let index = build_pack_index_v2(self.format, &entries, trailer)
            .map_err(|_| DurableFailure::VerifierCrash)?;
        if self.quarantine_directory(transaction).is_ok()
            || self.arrival_directory(transaction).is_ok()
        {
            return Err(DurableFailure::StaleLock);
        }
        let directory = self.create_quarantine_directory(transaction)?;
        let scratch = directory.create_child("objects")?;
        for object in &objects {
            write_scratch_object_to_directory(&scratch, object.id, object.kind, &object.contents)?;
        }
        write_new_synced_to_directory(&directory, "objects.pack", pack)?;
        write_new_synced_to_directory(&directory, "objects.idx", &index)?;
        scratch.sync()?;
        directory.sync()?;
        match &self.retained {
            Some(retained) => retained.quarantine.sync()?,
            None => sync_pack_directory(&self.quarantine)?,
        }
        let object_count = u32::try_from(objects.len()).map_err(|_| DurableFailure::DiskFull)?;
        self.summarize_arrival_directory(&directory, transaction, object_count)
    }

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
        if self.quarantine_directory(transaction.id()).is_ok()
            || self.arrival_directory(transaction.id()).is_ok()
        {
            return Err(GitdCoreError::Storage);
        }
        let directory = self
            .create_quarantine_directory(transaction.id())
            .map_err(|_| GitdCoreError::Storage)?;
        let scratch = directory
            .create_child("objects")
            .map_err(|_| GitdCoreError::Storage)?;
        let mut file = directory
            .create_file("incoming.pack")
            .map_err(|_| GitdCoreError::Storage)?;
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
        scratch.sync().map_err(|_| GitdCoreError::Storage)?;
        directory.sync().map_err(|_| GitdCoreError::Storage)?;
        match &self.retained {
            Some(retained) => retained
                .quarantine
                .sync()
                .map_err(|_| GitdCoreError::Storage)?,
            None => sync_pack_directory(&self.quarantine).map_err(|_| GitdCoreError::Storage)?,
        }
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
            .map(|_| ())
    }

    /// Completes thin REF deltas only from an exact authenticated object view.
    /// The callback receives a full object ID and the configured object limit;
    /// returned bytes are independently re-hashed by the pack validator.
    pub(crate) fn validate_received_pack_with_bases<B>(
        &self,
        transaction: &mut QuarantineTransaction,
        required_tips: &[ObjectId],
        mut external_base: B,
    ) -> Result<AuthenticatedPackIndexSummary, GitdCoreError>
    where
        B: FnMut(ObjectId, u64) -> Result<Option<(crate::ObjectKind, Vector<u8>)>, PackError>,
    {
        let directory = self
            .quarantine_directory(transaction.id())
            .map_err(|_| GitdCoreError::Storage)?;
        let scratch = directory
            .open_child("objects")
            .map_err(|_| GitdCoreError::Storage)?;
        let max_work = transaction
            .reservation()
            .incoming_pack_bytes()
            .checked_mul(2)
            .and_then(|value| value.checked_add(transaction.reservation().expanded_object_bytes()))
            .ok_or(GitdCoreError::Resource)?;
        let validated = validate_pack_file_with_bases_from_opener(
            || {
                directory
                    .open_regular("incoming.pack")
                    .map_err(|_| PackError::Truncated)
            },
            self.format,
            transaction.reservation().incoming_pack_bytes(),
            transaction.reservation().object_count(),
            transaction.reservation().expanded_object_bytes(),
            transaction.reservation().individual_object_bytes(),
            max_work,
            &mut |id, kind, contents| {
                write_scratch_object_to_directory(&scratch, id, kind, contents)
                    .map_err(|_| crate::PackError::TooLarge)
            },
            |id, limit| match read_scratch_object_from_directory(&scratch, id, limit)? {
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
                    write_scratch_object_to_directory(&scratch, id, kind, &contents)
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
        write_new_synced_to_directory(&directory, "objects.idx", &index)
            .map_err(|_| GitdCoreError::Storage)?;
        directory
            .rename_child("incoming.pack", "objects.pack")
            .map_err(|_| GitdCoreError::Storage)?;
        scratch.sync().map_err(|_| GitdCoreError::Storage)?;
        directory.sync().map_err(|_| GitdCoreError::Storage)?;
        transaction
            .objects_validated(validated.expanded_bytes, validated.objects.len() as u32)
            .map_err(|_| GitdCoreError::ObjectValidation)?;
        self.summarize_arrival_directory(
            &directory,
            transaction.id(),
            validated.objects.len() as u32,
        )
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
            retained: None,
            format,
            max_pack_bytes,
            selected: SpinMutex::new(None),
            statistics: ArrivalPackReadStatistics::default(),
        })
    }

    #[cfg(target_os = "linux")]
    pub fn open_capability(
        root: mrml_runtime::DirectoryCapability,
        format: ObjectFormat,
        max_pack_bytes: u64,
    ) -> Result<Self, DurableFailure> {
        if max_pack_bytes == 0 || max_pack_bytes > DEFAULT_MAX_INCOMING_PACK_BYTES {
            return Err(DurableFailure::DiskFull);
        }
        let root = ArrivalDirectory::Retained(root);
        let quarantine = match root.open_child("quarantine") {
            Ok(directory) => directory,
            Err(_) => root.create_child("quarantine")?,
        };
        let arrivals = match root.open_child("arrivals") {
            Ok(directory) => directory,
            Err(_) => root.create_child("arrivals")?,
        };
        root.sync()?;
        Ok(Self {
            quarantine: Text::new(),
            arrivals: Text::new(),
            retained: Some(RetainedArrivalDirectories {
                quarantine,
                arrivals,
            }),
            format,
            max_pack_bytes,
            selected: SpinMutex::new(None),
            statistics: ArrivalPackReadStatistics::default(),
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
        let directory = self
            .quarantine_directory(transaction)
            .map_err(|_| GitdCoreError::ObjectValidation)?
            .open_child("objects")
            .map_err(|_| GitdCoreError::ObjectValidation)?;
        let (kind, contents) = read_scratch_object_from_directory(&directory, id, max_bytes)
            .map_err(|_| GitdCoreError::ObjectValidation)?
            .ok_or(GitdCoreError::ObjectValidation)?;
        let header = mrml_runtime::mrml_format!("{} {}\0", kind.name(), contents.len());
        let mut hash = GitObjectHasher::new(self.format);
        hash.update(header.as_bytes());
        hash.update(&contents);
        if hash.finalize() != id {
            return Err(GitdCoreError::ObjectValidation);
        }
        let mut copied = Vector::new();
        copied
            .try_extend_from_slice(&contents)
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

        if self.quarantine_directory(transaction.id()).is_ok()
            || self.arrival_directory(transaction.id()).is_ok()
        {
            return Err(DurableFailure::StaleLock);
        }
        let directory = self.create_quarantine_directory(transaction.id())?;
        let scratch = directory.create_child("objects")?;
        for object in &objects {
            write_scratch_object_to_directory(&scratch, object.id, object.kind, &object.contents)
                .map_err(|_| DurableFailure::ShortWrite)?;
        }
        write_new_synced_to_directory(&directory, "objects.pack", pack)?;
        write_new_synced_to_directory(&directory, "objects.idx", &index)?;
        scratch.sync()?;
        directory.sync()?;
        match &self.retained {
            Some(retained) => retained.quarantine.sync()?,
            None => sync_pack_directory(&self.quarantine)?,
        }
        self.summarize_arrival_directory(
            &directory,
            transaction.id(),
            transaction.reservation().object_count(),
        )?;
        Ok(())
    }

    pub fn install(
        &self,
        transaction: QuarantineTransactionId,
        object_count: u32,
    ) -> Result<(), DurableFailure> {
        if self.arrival_directory(transaction).is_ok() {
            return Err(DurableFailure::StaleLock);
        }
        let staged = self.quarantine_directory(transaction)?;
        self.summarize_arrival_directory(&staged, transaction, object_count)?;
        let name = transaction_name(transaction);
        match &self.retained {
            Some(retained) => {
                retained
                    .quarantine
                    .move_child_to(&name, &retained.arrivals, &name)?
            }
            None => ArrivalDirectory::Ambient(self.quarantine.clone()).move_child_to(
                &name,
                &ArrivalDirectory::Ambient(self.arrivals.clone()),
                &name,
            )?,
        }
        match &self.retained {
            Some(retained) => {
                retained.arrivals.sync()?;
                retained.quarantine.sync()?;
            }
            None => {
                sync_pack_directory(&self.arrivals)?;
                sync_pack_directory(&self.quarantine)?;
            }
        }
        let installed = self.arrival_directory(transaction)?;
        self.summarize_arrival_directory(&installed, transaction, object_count)
            .map(|_| ())
    }

    pub fn verify_installed(
        &self,
        transaction: QuarantineTransactionId,
        object_count: u32,
    ) -> Result<(), DurableFailure> {
        let directory = self.arrival_directory(transaction)?;
        self.summarize_arrival_directory(&directory, transaction, object_count)
            .map(|_| ())
    }

    pub(crate) fn authenticated_installed_summary(
        &self,
        transaction: QuarantineTransactionId,
        object_count: u32,
    ) -> Result<AuthenticatedPackIndexSummary, DurableFailure> {
        let directory = self.arrival_directory(transaction)?;
        self.summarize_arrival_directory(&directory, transaction, object_count)
    }

    pub(crate) fn read_selected_object(
        &self,
        manifest: &PackSetManifest,
        id: ObjectId,
        max_bytes: u64,
    ) -> Result<crate::Object, GitdCoreError> {
        if manifest.object_format() != self.format || id.format() != self.format || max_bytes == 0 {
            return Err(GitdCoreError::ObjectValidation);
        }
        let digest = manifest
            .digest()
            .map_err(|_| GitdCoreError::ObjectValidation)?;
        self.activate_selected_snapshot(manifest, digest)?;
        self.read_authenticated_selected_object(digest, id, max_bytes)
    }

    pub(crate) fn selected_snapshot_matches(
        &self,
        repository_generation: crate::RepositoryGeneration,
        pack_generation: crate::PackGeneration,
        manifest_digest: [u8; 32],
    ) -> bool {
        self.selected.lock().as_ref().is_some_and(|snapshot| {
            snapshot.repository_generation == repository_generation
                && snapshot.pack_generation == pack_generation
                && snapshot.manifest_digest == manifest_digest
        })
    }

    pub(crate) fn activate_selected_snapshot(
        &self,
        manifest: &PackSetManifest,
        manifest_digest: [u8; 32],
    ) -> Result<(), GitdCoreError> {
        if manifest.object_format() != self.format
            || manifest
                .digest()
                .map_err(|_| GitdCoreError::ObjectValidation)?
                != manifest_digest
        {
            return Err(GitdCoreError::ObjectValidation);
        }
        if self.selected_snapshot_matches(
            manifest.repository_generation(),
            manifest.pack_generation(),
            manifest_digest,
        ) {
            return Ok(());
        }
        let mut objects = Vector::new();
        for entry in manifest.entries() {
            let summary = self
                .authenticated_installed_summary(entry.transaction(), entry.object_count())
                .map_err(|_| GitdCoreError::ObjectValidation)?;
            if summary.pack_checksum != entry.pack_checksum()
                || summary.index_checksum != entry.index_checksum()
                || summary.pack_bytes != entry.pack_bytes()
                || summary.index_bytes != entry.index_bytes()
                || summary.work_units != entry.work_units()
                || &*summary.object_ids != entry.object_ids()
            {
                return Err(GitdCoreError::ObjectValidation);
            }
            objects
                .try_reserve_exact(entry.object_ids().len())
                .map_err(|_| GitdCoreError::Resource)?;
            for id in entry.object_ids() {
                objects.push((*id, entry.transaction()));
            }
        }
        objects.sort_unstable_by_key(|(id, _)| *id);
        if objects.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(GitdCoreError::ObjectValidation);
        }
        let next = AuthenticatedSelectedPackSnapshot {
            manifest_digest,
            repository_generation: manifest.repository_generation(),
            pack_generation: manifest.pack_generation(),
            objects: OrderedMap::from_sorted_entries(objects),
        };
        let mut selected = self.selected.lock();
        let monotonic = selected.as_ref().is_none_or(|current| {
            let advances = current.repository_generation.0 < next.repository_generation.0
                || current.pack_generation.0 < next.pack_generation.0;
            advances
                && current.repository_generation.0 <= next.repository_generation.0
                && current.pack_generation.0 <= next.pack_generation.0
        });
        if monotonic {
            *selected = Some(next);
            Ok(())
        } else if selected.as_ref().is_some_and(|current| {
            current.repository_generation == next.repository_generation
                && current.pack_generation == next.pack_generation
                && current.manifest_digest == next.manifest_digest
        }) {
            Ok(())
        } else {
            Err(GitdCoreError::StaleGeneration)
        }
    }

    pub(crate) fn read_authenticated_selected_object(
        &self,
        manifest_digest: [u8; 32],
        id: ObjectId,
        max_bytes: u64,
    ) -> Result<crate::Object, GitdCoreError> {
        if id.format() != self.format || max_bytes == 0 {
            return Err(GitdCoreError::ObjectValidation);
        }
        self.statistics
            .object_lookups
            .fetch_add(1, Ordering::Relaxed);
        let transaction = {
            let selected = self.selected.lock();
            let snapshot = selected.as_ref().ok_or(GitdCoreError::StaleGeneration)?;
            if snapshot.manifest_digest != manifest_digest {
                return Err(GitdCoreError::StaleGeneration);
            }
            *snapshot
                .objects
                .get(&id)
                .ok_or(GitdCoreError::Unsupported)?
        };
        let arrival = self
            .arrival_directory(transaction)
            .map_err(|_| GitdCoreError::ObjectValidation)?;
        let objects = arrival
            .open_child("objects")
            .map_err(|_| GitdCoreError::ObjectValidation)?;
        let (kind, contents) = read_scratch_object_from_directory(&objects, id, max_bytes)
            .map_err(|_| GitdCoreError::ObjectValidation)?
            .ok_or(GitdCoreError::ObjectValidation)?;
        self.statistics.object_reads.fetch_add(1, Ordering::Relaxed);
        self.statistics
            .bytes_read
            .fetch_add(contents.len() as u64 + 1, Ordering::Relaxed);
        let header = mrml_runtime::mrml_format!("{} {}\0", kind.name(), contents.len());
        let mut hash = GitObjectHasher::new(self.format);
        hash.update(header.as_bytes());
        hash.update(&contents);
        self.statistics.hash_checks.fetch_add(1, Ordering::Relaxed);
        if hash.finalize() != id {
            return Err(GitdCoreError::ObjectValidation);
        }
        Ok(crate::Object { kind, contents })
    }

    pub fn read_statistics(&self) -> ArrivalPackReadStatisticsSnapshot {
        ArrivalPackReadStatisticsSnapshot {
            complete_pack_validations: self
                .statistics
                .complete_pack_validations
                .load(Ordering::Relaxed),
            pack_index_parses: self.statistics.pack_index_parses.load(Ordering::Relaxed),
            object_lookups: self.statistics.object_lookups.load(Ordering::Relaxed),
            object_reads: self.statistics.object_reads.load(Ordering::Relaxed),
            bytes_read: self.statistics.bytes_read.load(Ordering::Relaxed),
            hash_checks: self.statistics.hash_checks.load(Ordering::Relaxed),
        }
    }

    fn summarize_arrival_directory(
        &self,
        directory: &ArrivalDirectory,
        transaction: QuarantineTransactionId,
        object_count: u32,
    ) -> Result<AuthenticatedPackIndexSummary, DurableFailure> {
        self.statistics
            .complete_pack_validations
            .fetch_add(1, Ordering::Relaxed);
        let max_work = self
            .max_pack_bytes
            .checked_mul(2)
            .and_then(|value| value.checked_add(DEFAULT_MAX_EXPANDED_OBJECT_BYTES))
            .ok_or(DurableFailure::DiskFull)?;
        let scratch = directory.open_child("objects")?;
        let validated = validate_pack_file_with_bases_from_opener(
            || {
                directory
                    .open_regular("objects.pack")
                    .map_err(|_| PackError::Truncated)
            },
            self.format,
            self.max_pack_bytes,
            object_count,
            DEFAULT_MAX_EXPANDED_OBJECT_BYTES,
            DEFAULT_MAX_INDIVIDUAL_OBJECT_BYTES,
            max_work,
            &mut |_, _, _| Ok(()),
            |id, limit| read_scratch_object_from_directory(&scratch, id, limit),
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
        let index = read_open_file_bounded(directory.open_regular("objects.idx")?, index_limit)?;
        if validated.objects.len()
            != usize::try_from(object_count).map_err(|_| DurableFailure::VerifierCrash)?
        {
            return Err(DurableFailure::VerifierCrash);
        }
        let parsed = parse_pack_index_v2(self.format, &index, object_count)
            .map_err(|_| DurableFailure::VerifierCrash)?;
        self.statistics
            .pack_index_parses
            .fetch_add(1, Ordering::Relaxed);
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
        let pack_bytes = directory
            .open_regular("objects.pack")
            .and_then(|file| file.len().map_err(|_| DurableFailure::VerifierCrash))
            .map_err(|_| DurableFailure::VerifierCrash)?;
        let index_bytes = u64::try_from(index.len()).map_err(|_| DurableFailure::DiskFull)?;
        let index_checksum =
            ObjectId::from_bytes(self.format, &index[index.len() - self.format.hash_len()..])
                .ok_or(DurableFailure::VerifierCrash)?;
        let work_units = pack_bytes
            .checked_add(validated.expanded_bytes)
            .ok_or(DurableFailure::DiskFull)?;
        let mut object_ids = Vector::new();
        object_ids
            .try_reserve_exact(parsed.entries().len())
            .map_err(|_| DurableFailure::DiskFull)?;
        for entry in parsed.entries() {
            object_ids.push(entry.id);
        }
        Ok(AuthenticatedPackIndexSummary {
            transaction,
            object_count,
            pack_checksum: parsed.pack_checksum(),
            index_checksum,
            pack_bytes,
            index_bytes,
            work_units,
            object_ids,
        })
    }

    #[cfg(test)]
    fn quarantine_path(&self, transaction: QuarantineTransactionId) -> Text {
        join_path(&self.quarantine, &transaction_name(transaction))
    }
    #[cfg(test)]
    pub(crate) fn arrival_path(&self, transaction: QuarantineTransactionId) -> Text {
        join_path(&self.arrivals, &transaction_name(transaction))
    }

    fn quarantine_directory(
        &self,
        transaction: QuarantineTransactionId,
    ) -> Result<ArrivalDirectory, DurableFailure> {
        let name = transaction_name(transaction);
        match &self.retained {
            Some(retained) => retained.quarantine.open_child(&name),
            None => ArrivalDirectory::Ambient(self.quarantine.clone()).open_child(&name),
        }
    }

    fn create_quarantine_directory(
        &self,
        transaction: QuarantineTransactionId,
    ) -> Result<ArrivalDirectory, DurableFailure> {
        let name = transaction_name(transaction);
        match &self.retained {
            Some(retained) => retained.quarantine.create_child(&name),
            None => ArrivalDirectory::Ambient(self.quarantine.clone()).create_child(&name),
        }
    }

    fn arrival_directory(
        &self,
        transaction: QuarantineTransactionId,
    ) -> Result<ArrivalDirectory, DurableFailure> {
        let name = transaction_name(transaction);
        match &self.retained {
            Some(retained) => retained.arrivals.open_child(&name),
            None => ArrivalDirectory::Ambient(self.arrivals.clone()).open_child(&name),
        }
    }
}

pub(crate) fn read_scratch_object(
    directory: &str,
    id: ObjectId,
    max_bytes: u64,
) -> Result<Option<(crate::ObjectKind, Vector<u8>)>, PackError> {
    let path = join_path(directory, &id.to_hex());
    if !path_exists(&path) {
        return Ok(None);
    }
    let encoded = read_regular_bounded(&path, max_bytes.checked_add(1).ok_or(PackError::TooLarge)?)
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

fn read_scratch_object_from_directory(
    directory: &ArrivalDirectory,
    id: ObjectId,
    max_bytes: u64,
) -> Result<Option<(crate::ObjectKind, Vector<u8>)>, PackError> {
    let encoded = match directory.open_regular(&id.to_hex()) {
        Ok(file) => {
            read_open_file_bounded(file, max_bytes.checked_add(1).ok_or(PackError::TooLarge)?)
                .map_err(|_| PackError::MissingBase)?
        }
        Err(_) => return Ok(None),
    };
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

fn write_new_synced_to_directory(
    directory: &ArrivalDirectory,
    name: &str,
    bytes: &[u8],
) -> Result<(), DurableFailure> {
    let mut file = directory.create_file(name)?;
    file.write_all(bytes)
        .map_err(|_| DurableFailure::ShortWrite)?;
    file.sync().map_err(|_| DurableFailure::Fsync)
}

fn write_scratch_object_to_directory(
    directory: &ArrivalDirectory,
    id: ObjectId,
    kind: crate::ObjectKind,
    contents: &[u8],
) -> Result<(), DurableFailure> {
    let mut file = directory.create_file(&id.to_hex())?;
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

pub(crate) fn write_scratch_object(
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
    let file = File::open_regular(path).map_err(|_| DurableFailure::VerifierCrash)?;
    read_open_file_bounded(file, limit)
}

fn read_open_file_bounded(mut file: File, limit: u64) -> Result<Vector<u8>, DurableFailure> {
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

    #[test]
    fn retained_arrival_root_survives_ambient_directory_replacement() {
        let root = root();
        let displaced = mrml_runtime::mrml_format!("{root}-displaced");
        let _ = mrml_runtime::remove_dir_all(&root);
        let _ = mrml_runtime::remove_dir_all(&displaced);
        mrml_runtime::create_dir_all(&root).unwrap();
        let capability = mrml_runtime::DirectoryCapability::open_root(&root).unwrap();
        let store =
            ArrivalPackStore::open_capability(capability, ObjectFormat::Sha256, 1024 * 1024)
                .unwrap();
        mrml_runtime::rename_file(&root, &displaced).unwrap();
        mrml_runtime::create_dir_all(&join_path(&root, "quarantine")).unwrap();
        mrml_runtime::create_dir_all(&join_path(&root, "arrivals")).unwrap();

        let object = PackObject {
            id: ObjectId::blob_with_format(ObjectFormat::Sha256, b"retained arrival"),
            kind: ObjectKind::Blob,
            contents: Vector::from(*b"retained arrival"),
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
                expanded_object_bytes: 16,
                largest_object_bytes: 16,
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
            QuarantineTransactionId([13u8; 16]),
            RepositoryIdentity::parse("owner/repository").unwrap(),
            RepositoryGeneration(1),
            TrustGeneration(1),
            RevocationGeneration(1),
            reservation,
        )
        .unwrap();
        let mut reader = Reader {
            bytes: pack,
            offset: 0,
        };
        store
            .receive_pack_body(&mut transaction, &mut reader)
            .unwrap();
        store
            .validate_received_pack(&mut transaction, &[object_id])
            .unwrap();
        store.install(transaction.id(), 1).unwrap();
        store.verify_installed(transaction.id(), 1).unwrap();

        let transaction = transaction_name(transaction.id());
        assert!(path_is_directory(&join_path(
            &join_path(&displaced, "arrivals"),
            &transaction,
        )));
        assert!(!path_exists(&join_path(
            &join_path(&root, "arrivals"),
            &transaction,
        )));
        mrml_runtime::remove_dir_all(&root).unwrap();
        mrml_runtime::remove_dir_all(&displaced).unwrap();
    }
}
