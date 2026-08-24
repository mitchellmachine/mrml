use crate::{
    AllocationImage, AllocationKind, DIRECTORY_METADATA_BYTES, DirectoryImage, DirectoryMetadata,
    ExtentImage, FILE_METADATA_BYTES, FileMetadata, FileState, MetadataPointer,
    ObjectIdAllocatorImage, StorageObjectId, StorageObjectKind, Superblock, VolumeHeader,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveredSuperblock {
    block: u64,
    superblock: Superblock,
    fallback: bool,
}

/// One completely reachable filesystem generation selected by redundant-root
/// recovery. The contained file states are integrity-validated metadata, not
/// capabilities and not proof of owner approval or rollback freshness.
pub struct RecoveredReachableState<const E: usize, const O: usize> {
    selected: RecoveredSuperblock,
    files: [Option<FileState<E>>; O],
    file_count: usize,
}

/// Borrowed, non-authorizing proof that one exact file state was present in the
/// integrity-validated graph selected by redundant-root recovery.
#[derive(Clone, Copy)]
pub struct ReachableFileSelection<'a, const E: usize> {
    selected: RecoveredSuperblock,
    file: &'a FileState<E>,
}

impl<'a, const E: usize> ReachableFileSelection<'a, E> {
    pub const fn volume(&self) -> crate::VolumeId {
        self.selected.superblock.volume()
    }

    pub const fn root_generation(&self) -> u64 {
        self.selected.superblock.generation()
    }

    pub const fn object(&self) -> StorageObjectId {
        self.file.object()
    }

    pub const fn generation(&self) -> u64 {
        self.file.generation()
    }

    pub const fn file_state(self) -> &'a FileState<E> {
        self.file
    }
}

impl<const E: usize, const O: usize> RecoveredReachableState<E, O> {
    pub const fn selected(&self) -> RecoveredSuperblock {
        self.selected
    }

    pub fn file(&self, object: StorageObjectId) -> Option<&FileState<E>> {
        self.files[..self.file_count]
            .iter()
            .flatten()
            .find(|file| file.object() == object)
    }

    pub fn select_file(&self, object: StorageObjectId) -> Option<ReachableFileSelection<'_, E>> {
        self.file(object).map(|file| ReachableFileSelection {
            selected: self.selected,
            file,
        })
    }

    pub const fn file_count(&self) -> usize {
        self.file_count
    }
}

impl RecoveredSuperblock {
    pub const fn block(self) -> u64 {
        self.block
    }

    pub const fn superblock(self) -> Superblock {
        self.superblock
    }

    pub const fn used_fallback(self) -> bool {
        self.fallback
    }
}

/// Validates the complete metadata graph selected by a superblock candidate.
///
/// # Safety
///
/// An implementation must read only from the immutable device generation being
/// recovered and validate the candidate's complete reachable root and allocation
/// metadata, including all covered digests, identities, generations, bounds,
/// ownership, and cross-references. `Invalid` must mean the candidate was fully
/// examined and cannot be selected. Transient or indeterminate failures must be
/// returned as `Backend`, never downgraded to `Invalid` to permit silent rollback.
pub unsafe trait CowRecoveryValidator {
    type Error;

    fn validate_candidate(
        &mut self,
        block: u64,
        candidate: Superblock,
    ) -> Result<(), CandidateValidationError<Self::Error>>;
}

/// Immutable metadata reads used while validating one recovery candidate.
///
/// # Safety
///
/// Every read must come from the same immutable device generation as every
/// other read in the validation attempt, must fill the complete requested
/// metadata range exactly, and must not redirect a pointer or return stale,
/// shortened, or concurrently mutable bytes.
pub unsafe trait RecoveryMetadataBackend {
    type Error;

    fn read_metadata(
        &mut self,
        pointer: MetadataPointer,
        output: &mut [u8],
    ) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy)]
struct RecoveryNode {
    object: StorageObjectId,
    kind: StorageObjectKind,
    generation: u64,
    metadata: MetadataPointer,
    parent: Option<StorageObjectId>,
}

pub struct ReachableRecoveryValidator<
    'a,
    B,
    const A: usize,
    const D: usize,
    const E: usize,
    const O: usize,
> {
    header: VolumeHeader,
    backend: B,
    scratch: &'a mut [u8],
    files: [Option<FileState<E>>; O],
    file_count: usize,
}

impl<'a, B, const A: usize, const D: usize, const E: usize, const O: usize>
    ReachableRecoveryValidator<'a, B, A, D, E, O>
{
    pub fn new(header: VolumeHeader, backend: B, scratch: &'a mut [u8]) -> Self {
        Self {
            header,
            backend,
            scratch,
            files: [const { None }; O],
            file_count: 0,
        }
    }

    pub const fn backend(&self) -> &B {
        &self.backend
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    fn take_files(&mut self) -> ([Option<FileState<E>>; O], usize) {
        let count = self.file_count;
        self.file_count = 0;
        (
            core::mem::replace(&mut self.files, [const { None }; O]),
            count,
        )
    }
}

unsafe impl<
    B: RecoveryMetadataBackend,
    const A: usize,
    const D: usize,
    const E: usize,
    const O: usize,
> CowRecoveryValidator for ReachableRecoveryValidator<'_, B, A, D, E, O>
{
    type Error = B::Error;

    fn validate_candidate(
        &mut self,
        _block: u64,
        candidate: Superblock,
    ) -> Result<(), CandidateValidationError<Self::Error>> {
        self.files = [const { None }; O];
        self.file_count = 0;
        let header = self.header;
        if O == 0 || candidate.volume() != header.volume() {
            return Err(CandidateValidationError::Invalid);
        }
        let allocation_bytes = self.read(candidate.allocation_metadata())?;
        let allocation = AllocationImage::<A>::decode(
            header,
            candidate.generation(),
            candidate.allocation_metadata(),
            allocation_bytes,
        )
        .map_err(|_| CandidateValidationError::Invalid)?;
        if !allocation.is_self_owned_by(candidate.root()) {
            return Err(CandidateValidationError::Invalid);
        }
        let mut claimed = [false; A];
        let allocation_record = allocation
            .index()
            .exact_record_index(
                candidate.root(),
                candidate.generation(),
                candidate.allocation_metadata(),
                AllocationKind::AllocationMetadata,
            )
            .ok_or(CandidateValidationError::Invalid)?;
        claimed[allocation_record] = true;

        let mut allocator_record = None;
        for index in 0..allocation.index().len() {
            let record = allocation
                .index()
                .record(index)
                .ok_or(CandidateValidationError::Invalid)?;
            if record.kind() == AllocationKind::ObjectIdAllocatorMetadata {
                if allocator_record.is_some()
                    || record.owner() != candidate.root()
                    || record.owner_generation() != candidate.generation()
                {
                    return Err(CandidateValidationError::Invalid);
                }
                allocator_record = Some((index, record));
            }
        }
        let (allocator_record_index, allocator_record) =
            allocator_record.ok_or(CandidateValidationError::Invalid)?;
        let allocator_pointer =
            MetadataPointer::new(allocator_record.block(), allocator_record.block_count())
                .map_err(|_| CandidateValidationError::Invalid)?;
        let allocator_bytes = self.read(allocator_pointer)?;
        let allocator = ObjectIdAllocatorImage::decode(
            header,
            candidate.generation(),
            allocator_pointer,
            allocator_bytes,
        )
        .map_err(|_| CandidateValidationError::Invalid)?;
        claimed[allocator_record_index] = true;

        let mut nodes = [None; O];
        nodes[0] = Some(RecoveryNode {
            object: candidate.root(),
            kind: StorageObjectKind::Directory,
            generation: 0,
            metadata: candidate.root_metadata(),
            parent: None,
        });
        let mut count = 1;
        let mut cursor = 0;
        let mut maximum_local = candidate.root().local();
        while cursor < count {
            let node = nodes[cursor].ok_or(CandidateValidationError::Invalid)?;
            match node.kind {
                StorageObjectKind::Directory => {
                    let bytes = self.read(node.metadata)?;
                    let metadata = DirectoryMetadata::decode(
                        bytes
                            .get(..DIRECTORY_METADATA_BYTES)
                            .ok_or(CandidateValidationError::Invalid)?,
                        header,
                    )
                    .map_err(|_| CandidateValidationError::Invalid)?;
                    let primary_record = allocation
                        .index()
                        .exact_record_index(
                            node.object,
                            metadata.generation(),
                            node.metadata,
                            AllocationKind::ObjectMetadata,
                        )
                        .ok_or(CandidateValidationError::Invalid)?;
                    let entries_record = allocation
                        .index()
                        .exact_record_index(
                            node.object,
                            metadata.generation(),
                            metadata.entries(),
                            AllocationKind::DirectoryEntries,
                        )
                        .ok_or(CandidateValidationError::Invalid)?;
                    if bytes[DIRECTORY_METADATA_BYTES..]
                        .iter()
                        .any(|byte| *byte != 0)
                        || metadata.object() != node.object
                        || (node.generation != 0 && metadata.generation() != node.generation)
                        || metadata.parent() != node.parent
                    {
                        return Err(CandidateValidationError::Invalid);
                    }
                    claimed[primary_record] = true;
                    claimed[entries_record] = true;
                    let entries_bytes = self.read(metadata.entries())?;
                    let entries = DirectoryImage::<D>::decode(
                        header,
                        node.object,
                        metadata.generation(),
                        metadata.entries(),
                        entries_bytes,
                    )
                    .map_err(|_| CandidateValidationError::Invalid)?;
                    if entries.state().len()
                        != usize::try_from(metadata.entry_count())
                            .map_err(|_| CandidateValidationError::Invalid)?
                    {
                        return Err(CandidateValidationError::Invalid);
                    }
                    for index in 0..entries.state().len() {
                        let entry = entries
                            .state()
                            .entry(index)
                            .ok_or(CandidateValidationError::Invalid)?;
                        if count == O
                            || nodes[..count]
                                .iter()
                                .flatten()
                                .any(|prior| prior.object == entry.object())
                        {
                            return Err(CandidateValidationError::Invalid);
                        }
                        let metadata_pointer = allocation
                            .index()
                            .object_metadata(entry.object(), entry.metadata_generation())
                            .ok_or(CandidateValidationError::Invalid)?;
                        nodes[count] = Some(RecoveryNode {
                            object: entry.object(),
                            kind: entry.kind(),
                            generation: entry.metadata_generation(),
                            metadata: metadata_pointer,
                            parent: (entry.kind() == StorageObjectKind::Directory)
                                .then_some(node.object),
                        });
                        maximum_local = maximum_local.max(entry.object().local());
                        count += 1;
                    }
                }
                StorageObjectKind::File => {
                    let bytes = self.read(node.metadata)?;
                    let metadata = FileMetadata::decode(
                        bytes
                            .get(..FILE_METADATA_BYTES)
                            .ok_or(CandidateValidationError::Invalid)?,
                        header,
                    )
                    .map_err(|_| CandidateValidationError::Invalid)?;
                    let primary_record = allocation
                        .index()
                        .exact_record_index(
                            node.object,
                            node.generation,
                            node.metadata,
                            AllocationKind::ObjectMetadata,
                        )
                        .ok_or(CandidateValidationError::Invalid)?;
                    let extents_record = allocation
                        .index()
                        .exact_record_index(
                            node.object,
                            node.generation,
                            metadata.extents(),
                            AllocationKind::FileExtents,
                        )
                        .ok_or(CandidateValidationError::Invalid)?;
                    if bytes[FILE_METADATA_BYTES..].iter().any(|byte| *byte != 0)
                        || metadata.object() != node.object
                        || metadata.generation() != node.generation
                    {
                        return Err(CandidateValidationError::Invalid);
                    }
                    claimed[primary_record] = true;
                    claimed[extents_record] = true;
                    let extents_bytes = self.read(metadata.extents())?;
                    let extents = ExtentImage::<E>::decode(
                        header,
                        node.object,
                        node.generation,
                        metadata.length(),
                        metadata.extents(),
                        extents_bytes,
                    )
                    .map_err(|_| CandidateValidationError::Invalid)?;
                    if extents.map().len()
                        != usize::try_from(metadata.extent_count())
                            .map_err(|_| CandidateValidationError::Invalid)?
                    {
                        return Err(CandidateValidationError::Invalid);
                    }
                    for index in 0..extents.map().len() {
                        let extent = extents
                            .map()
                            .record(index)
                            .ok_or(CandidateValidationError::Invalid)?;
                        if extent.kind() == crate::ExtentKind::Data {
                            let record = allocation
                                .index()
                                .exact_range_index(
                                    extent.file(),
                                    extent.metadata_generation(),
                                    extent
                                        .physical_block()
                                        .ok_or(CandidateValidationError::Invalid)?,
                                    extent.block_count(),
                                    AllocationKind::FileData,
                                )
                                .ok_or(CandidateValidationError::Invalid)?;
                            claimed[record] = true;
                        }
                    }
                    if self.file_count == O {
                        return Err(CandidateValidationError::Invalid);
                    }
                    self.files[self.file_count] = Some(
                        FileState::new(
                            node.object,
                            node.generation,
                            metadata.length(),
                            extents.into_map(),
                        )
                        .map_err(|_| CandidateValidationError::Invalid)?,
                    );
                    self.file_count += 1;
                }
                StorageObjectKind::Volume => return Err(CandidateValidationError::Invalid),
            }
            cursor += 1;
        }
        match allocator.next_local() {
            Some(next_local) if next_local > maximum_local => {}
            None => {}
            Some(_) => return Err(CandidateValidationError::Invalid),
        }
        if claimed[..allocation.index().len()]
            .iter()
            .any(|claimed| !claimed)
        {
            return Err(CandidateValidationError::Invalid);
        }
        Ok(())
    }
}

impl<B: RecoveryMetadataBackend, const A: usize, const D: usize, const E: usize, const O: usize>
    ReachableRecoveryValidator<'_, B, A, D, E, O>
{
    fn read(
        &mut self,
        pointer: MetadataPointer,
    ) -> Result<&[u8], CandidateValidationError<B::Error>> {
        let length = usize::try_from(
            u64::from(self.header.block_size())
                .checked_mul(u64::from(pointer.blocks()))
                .ok_or(CandidateValidationError::Invalid)?,
        )
        .map_err(|_| CandidateValidationError::Invalid)?;
        let output = self
            .scratch
            .get_mut(..length)
            .ok_or(CandidateValidationError::Invalid)?;
        output.fill(0);
        self.backend
            .read_metadata(pointer, output)
            .map_err(CandidateValidationError::Backend)?;
        Ok(output)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateValidationError<E> {
    Invalid,
    Backend(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryError<E> {
    NoValidSuperblock,
    InconsistentSuperblocks,
    Backend(E),
}

pub fn recover_superblock<V: CowRecoveryValidator>(
    header: VolumeHeader,
    primary: &[u8],
    secondary: &[u8],
    validator: &mut V,
) -> Result<RecoveredSuperblock, RecoveryError<V::Error>> {
    let primary = decode_and_validate(header, header.primary_superblock(), primary, validator)?;
    let secondary =
        decode_and_validate(header, header.secondary_superblock(), secondary, validator)?;

    match (primary, secondary) {
        (None, None) => Err(RecoveryError::NoValidSuperblock),
        (Some(candidate), None) | (None, Some(candidate)) => Ok(RecoveredSuperblock {
            block: candidate.0,
            superblock: candidate.1,
            fallback: true,
        }),
        (Some(primary), Some(secondary)) => select_pair(primary, secondary),
    }
}

pub fn recover_reachable_superblock<
    B: RecoveryMetadataBackend,
    const A: usize,
    const D: usize,
    const E: usize,
    const O: usize,
>(
    header: VolumeHeader,
    primary: &[u8],
    secondary: &[u8],
    backend: B,
    scratch: &mut [u8],
) -> Result<RecoveredSuperblock, RecoveryError<B::Error>> {
    let mut validator = ReachableRecoveryValidator::<B, A, D, E, O>::new(header, backend, scratch);
    recover_superblock(header, primary, secondary, &mut validator)
}

/// Selects one redundant root and retains the exact file states discovered by
/// validation of that selected reachable graph. Both candidate snapshots are
/// kept separate until the ordinary generation-consistency selector chooses a
/// root, preventing metadata from the last-validated candidate being confused
/// with metadata from the selected candidate.
pub fn recover_reachable_state<
    B: RecoveryMetadataBackend,
    const A: usize,
    const D: usize,
    const E: usize,
    const O: usize,
>(
    header: VolumeHeader,
    primary: &[u8],
    secondary: &[u8],
    backend: B,
    scratch: &mut [u8],
) -> Result<RecoveredReachableState<E, O>, RecoveryError<B::Error>> {
    let mut validator = ReachableRecoveryValidator::<B, A, D, E, O>::new(header, backend, scratch);
    let primary =
        decode_reachable_candidate(header, header.primary_superblock(), primary, &mut validator)?;
    let secondary = decode_reachable_candidate(
        header,
        header.secondary_superblock(),
        secondary,
        &mut validator,
    )?;

    let selected = match (&primary, &secondary) {
        (None, None) => return Err(RecoveryError::NoValidSuperblock),
        (Some(candidate), None) | (None, Some(candidate)) => RecoveredSuperblock {
            block: candidate.0,
            superblock: candidate.1,
            fallback: true,
        },
        (Some(primary), Some(secondary)) => {
            select_pair((primary.0, primary.1), (secondary.0, secondary.1))?
        }
    };
    let (_, _, files, file_count) = if primary
        .as_ref()
        .is_some_and(|candidate| candidate.0 == selected.block)
    {
        primary.expect("selected primary candidate exists")
    } else {
        secondary.expect("selected secondary candidate exists")
    };
    Ok(RecoveredReachableState {
        selected,
        files,
        file_count,
    })
}

type ReachableCandidate<const E: usize, const O: usize> =
    (u64, Superblock, [Option<FileState<E>>; O], usize);

fn decode_reachable_candidate<
    B: RecoveryMetadataBackend,
    const A: usize,
    const D: usize,
    const E: usize,
    const O: usize,
>(
    header: VolumeHeader,
    block: u64,
    encoded: &[u8],
    validator: &mut ReachableRecoveryValidator<'_, B, A, D, E, O>,
) -> Result<Option<ReachableCandidate<E, O>>, RecoveryError<B::Error>> {
    let candidate = match Superblock::decode(encoded, header) {
        Ok(candidate) => candidate,
        Err(_) => return Ok(None),
    };
    match validator.validate_candidate(block, candidate) {
        Ok(()) => {
            let (files, file_count) = validator.take_files();
            Ok(Some((block, candidate, files, file_count)))
        }
        Err(CandidateValidationError::Invalid) => Ok(None),
        Err(CandidateValidationError::Backend(error)) => Err(RecoveryError::Backend(error)),
    }
}

fn decode_and_validate<V: CowRecoveryValidator>(
    header: VolumeHeader,
    block: u64,
    encoded: &[u8],
    validator: &mut V,
) -> Result<Option<(u64, Superblock)>, RecoveryError<V::Error>> {
    let candidate = match Superblock::decode(encoded, header) {
        Ok(candidate) => candidate,
        Err(_error) => return Ok(None),
    };
    match validator.validate_candidate(block, candidate) {
        Ok(()) => Ok(Some((block, candidate))),
        Err(CandidateValidationError::Invalid) => Ok(None),
        Err(CandidateValidationError::Backend(error)) => Err(RecoveryError::Backend(error)),
    }
}

fn select_pair<E>(
    primary: (u64, Superblock),
    secondary: (u64, Superblock),
) -> Result<RecoveredSuperblock, RecoveryError<E>> {
    let primary_generation = primary.1.generation();
    let secondary_generation = secondary.1.generation();
    if primary_generation == secondary_generation {
        if primary.1 != secondary.1 {
            return Err(RecoveryError::InconsistentSuperblocks);
        }
        return Ok(RecoveredSuperblock {
            block: primary.0,
            superblock: primary.1,
            fallback: false,
        });
    }
    let (newer, older) = if primary_generation > secondary_generation {
        (primary, secondary)
    } else {
        (secondary, primary)
    };
    if older.1.generation().checked_add(1) != Some(newer.1.generation()) {
        return Err(RecoveryError::InconsistentSuperblocks);
    }
    Ok(RecoveredSuperblock {
        block: newer.0,
        superblock: newer.1,
        fallback: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AllocationKind, AllocationRecord, AuthenticatedAuthorityRecoveryState,
        AuthorityCheckpointError, AuthorityCheckpointProofIssuer, AuthorityRecoveryGuard,
        AuthorityStorageError, DirectoryEntry, DirectoryImage, DirectoryMetadata, ExtentImage,
        ExtentRecord, FileMetadata, FileReadBackend, MetadataPointer,
        OwnerApprovedAuthorityCheckpoint, SUPERBLOCK_BYTES, StorageAuthorityTable, StorageName,
        StorageObjectId, StorageObjectKind, StoragePrincipal, StorageRights, VolumeId,
    };

    fn volume() -> VolumeId {
        VolumeId::new([7; 16]).unwrap()
    }

    fn header() -> VolumeHeader {
        VolumeHeader::new(volume(), 4096, 100, 1, 2).unwrap()
    }

    fn superblock(generation: u64, root_block: u64) -> Superblock {
        Superblock::new(
            header(),
            generation,
            generation - 1,
            StorageObjectId::new(volume(), 1).unwrap(),
            MetadataPointer::new(root_block, 1).unwrap(),
            MetadataPointer::new(root_block + 1, 1).unwrap(),
        )
        .unwrap()
    }

    fn encoded(candidate: Superblock) -> [u8; SUPERBLOCK_BYTES] {
        let mut encoded = [0; SUPERBLOCK_BYTES];
        candidate.encode(&mut encoded);
        encoded
    }

    struct Validator {
        invalid_generation: Option<u64>,
        calls: usize,
    }

    unsafe impl CowRecoveryValidator for Validator {
        type Error = ();

        fn validate_candidate(
            &mut self,
            _block: u64,
            candidate: Superblock,
        ) -> Result<(), CandidateValidationError<Self::Error>> {
            self.calls += 1;
            if self.invalid_generation == Some(candidate.generation()) {
                Err(CandidateValidationError::Invalid)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn selects_newest_adjacent_fully_valid_candidate() {
        let older = encoded(superblock(4, 10));
        let newer = encoded(superblock(5, 20));
        let mut validator = Validator {
            invalid_generation: None,
            calls: 0,
        };
        let recovered = recover_superblock(header(), &older, &newer, &mut validator).unwrap();
        assert_eq!(recovered.block(), 2);
        assert_eq!(recovered.superblock().generation(), 5);
        assert!(!recovered.used_fallback());
        assert_eq!(validator.calls, 2);
    }

    #[test]
    fn falls_back_only_after_candidate_is_proven_invalid() {
        let older = encoded(superblock(4, 10));
        let newer = encoded(superblock(5, 20));
        let mut validator = Validator {
            invalid_generation: Some(5),
            calls: 0,
        };
        let recovered = recover_superblock(header(), &older, &newer, &mut validator).unwrap();
        assert_eq!(recovered.superblock().generation(), 4);
        assert!(recovered.used_fallback());
    }

    #[test]
    fn rejects_corruption_and_inconsistent_valid_lineage() {
        let older = encoded(superblock(4, 10));
        let mut corrupt = encoded(superblock(5, 20));
        corrupt[48] ^= 1;
        let mut validator = Validator {
            invalid_generation: Some(4),
            calls: 0,
        };
        assert_eq!(
            recover_superblock(header(), &older, &corrupt, &mut validator),
            Err(RecoveryError::NoValidSuperblock)
        );

        let newer_with_gap = encoded(superblock(7, 20));
        let mut validator = Validator {
            invalid_generation: None,
            calls: 0,
        };
        assert_eq!(
            recover_superblock(header(), &older, &newer_with_gap, &mut validator),
            Err(RecoveryError::InconsistentSuperblocks)
        );

        let same_generation_different_root = encoded(superblock(4, 30));
        assert_eq!(
            recover_superblock(
                header(),
                &older,
                &same_generation_different_root,
                &mut validator,
            ),
            Err(RecoveryError::InconsistentSuperblocks)
        );
    }

    #[test]
    fn identical_same_generation_initial_roots_are_accepted_deterministically() {
        let candidate = encoded(superblock(1, 10));
        let mut validator = Validator {
            invalid_generation: None,
            calls: 0,
        };
        let recovered =
            recover_superblock(header(), &candidate, &candidate, &mut validator).unwrap();
        assert_eq!(recovered.block(), header().primary_superblock());
        assert_eq!(recovered.superblock().generation(), 1);
        assert!(!recovered.used_fallback());
    }

    #[test]
    fn backend_uncertainty_never_becomes_rollback() {
        struct Uncertain;
        unsafe impl CowRecoveryValidator for Uncertain {
            type Error = u8;

            fn validate_candidate(
                &mut self,
                _block: u64,
                _candidate: Superblock,
            ) -> Result<(), CandidateValidationError<Self::Error>> {
                Err(CandidateValidationError::Backend(9))
            }
        }

        assert_eq!(
            recover_superblock(
                header(),
                &encoded(superblock(4, 10)),
                &encoded(superblock(5, 20)),
                &mut Uncertain,
            ),
            Err(RecoveryError::Backend(9))
        );
    }

    struct MetadataBackend {
        root: [u8; 4096],
        entries: [u8; 4096],
        file: [u8; 4096],
        extents: [u8; 4096],
        allocation: [u8; 4096],
        object_ids: [u8; 4096],
    }

    unsafe impl RecoveryMetadataBackend for MetadataBackend {
        type Error = ();

        fn read_metadata(
            &mut self,
            pointer: MetadataPointer,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            let source = match pointer.block() {
                10 => &self.root,
                11 => &self.entries,
                12 => &self.file,
                13 => &self.extents,
                20 => &self.allocation,
                21 => &self.object_ids,
                _ => return Err(()),
            };
            if pointer.blocks() != 1 || output.len() != source.len() {
                return Err(());
            }
            output.copy_from_slice(source);
            Ok(())
        }
    }

    struct FailAfter {
        inner: MetadataBackend,
        calls: usize,
        successful_reads: usize,
    }

    unsafe impl RecoveryMetadataBackend for FailAfter {
        type Error = u8;

        fn read_metadata(
            &mut self,
            pointer: MetadataPointer,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            if self.calls == self.successful_reads {
                return Err(9);
            }
            self.calls += 1;
            self.inner.read_metadata(pointer, output).map_err(|_| 8)
        }
    }

    fn reachable_backend(
        include_data_owner: bool,
        include_orphan: bool,
    ) -> (Superblock, MetadataBackend) {
        let root = StorageObjectId::new(volume(), 1).unwrap();
        let file = StorageObjectId::new(volume(), 7).unwrap();
        let root_pointer = MetadataPointer::new(10, 1).unwrap();
        let entries_pointer = MetadataPointer::new(11, 1).unwrap();
        let extents_pointer = MetadataPointer::new(13, 1).unwrap();
        let allocation_pointer = MetadataPointer::new(20, 1).unwrap();
        let object_ids_pointer = MetadataPointer::new(21, 1).unwrap();
        let candidate =
            Superblock::new(header(), 5, 4, root, root_pointer, allocation_pointer).unwrap();

        let mut root_bytes = [0; 4096];
        DirectoryMetadata::new(header(), root, 2, None, 1, entries_pointer)
            .unwrap()
            .encode(
                (&mut root_bytes[..crate::DIRECTORY_METADATA_BYTES])
                    .try_into()
                    .unwrap(),
            );
        let entry = DirectoryEntry::new(
            StorageName::new("file").unwrap(),
            file,
            StorageObjectKind::File,
            3,
        )
        .unwrap();
        let mut entries = [0; 4096];
        DirectoryImage::<1>::build(header(), root, 2, entries_pointer, &[entry])
            .unwrap()
            .encode(&mut entries)
            .unwrap();
        let mut file_bytes = [0; 4096];
        FileMetadata::new(header(), file, 3, 4096, 1, extents_pointer, [9; 32])
            .unwrap()
            .encode(
                (&mut file_bytes[..crate::FILE_METADATA_BYTES])
                    .try_into()
                    .unwrap(),
            );
        let extent = ExtentRecord::data(file, 3, 0, 1, 30, [8; 32]).unwrap();
        let mut extents = [0; 4096];
        ExtentImage::<1>::build(header(), file, 3, 4096, extents_pointer, &[extent])
            .unwrap()
            .encode(&mut extents)
            .unwrap();

        let records = [
            AllocationRecord::new(root, 2, 10, 1, AllocationKind::ObjectMetadata).unwrap(),
            AllocationRecord::new(root, 2, 11, 1, AllocationKind::DirectoryEntries).unwrap(),
            AllocationRecord::new(file, 3, 12, 1, AllocationKind::ObjectMetadata).unwrap(),
            AllocationRecord::new(file, 3, 13, 1, AllocationKind::FileExtents).unwrap(),
            AllocationRecord::new(root, 5, 20, 1, AllocationKind::AllocationMetadata).unwrap(),
            AllocationRecord::new(root, 5, 21, 1, AllocationKind::ObjectIdAllocatorMetadata)
                .unwrap(),
            AllocationRecord::new(file, 3, 30, 1, AllocationKind::FileData).unwrap(),
            AllocationRecord::new(
                StorageObjectId::new(volume(), 99).unwrap(),
                1,
                40,
                1,
                AllocationKind::ObjectMetadata,
            )
            .unwrap(),
        ];
        let record_count = if include_orphan {
            8
        } else if include_data_owner {
            7
        } else {
            6
        };
        let mut allocation = [0; 4096];
        AllocationImage::<8>::build(header(), 5, allocation_pointer, &records[..record_count])
            .unwrap()
            .encode(&mut allocation)
            .unwrap();
        let mut object_ids = [0; 4096];
        ObjectIdAllocatorImage::build(header(), 5, Some(8), object_ids_pointer)
            .unwrap()
            .encode(&mut object_ids)
            .unwrap();
        (
            candidate,
            MetadataBackend {
                root: root_bytes,
                entries,
                file: file_bytes,
                extents,
                allocation,
                object_ids,
            },
        )
    }

    #[test]
    fn reachable_validator_checks_namespace_metadata_and_data_ownership() {
        let (candidate, backend) = reachable_backend(true, false);
        let mut scratch = [0; 4096];
        let mut validator =
            ReachableRecoveryValidator::<_, 8, 1, 1, 2>::new(header(), backend, &mut scratch);
        assert_eq!(validator.validate_candidate(1, candidate), Ok(()));

        let (candidate, backend) = reachable_backend(false, false);
        let mut scratch = [0; 4096];
        let mut validator =
            ReachableRecoveryValidator::<_, 8, 1, 1, 2>::new(header(), backend, &mut scratch);
        assert_eq!(
            validator.validate_candidate(1, candidate),
            Err(CandidateValidationError::Invalid)
        );

        let (candidate, backend) = reachable_backend(true, true);
        let mut scratch = [0; 4096];
        let mut validator =
            ReachableRecoveryValidator::<_, 8, 1, 1, 2>::new(header(), backend, &mut scratch);
        assert_eq!(
            validator.validate_candidate(1, candidate),
            Err(CandidateValidationError::Invalid)
        );
    }

    #[test]
    fn reachable_state_retains_only_selected_graph_file_states() {
        let (candidate, backend) = reachable_backend(true, false);
        let primary = encoded(candidate);
        let secondary = [0; SUPERBLOCK_BYTES];
        let mut scratch = [0; 4096];
        let recovered = recover_reachable_state::<_, 8, 1, 1, 2>(
            header(),
            &primary,
            &secondary,
            backend,
            &mut scratch,
        )
        .unwrap();

        assert_eq!(recovered.selected().block(), header().primary_superblock());
        assert!(recovered.selected().used_fallback());
        assert_eq!(recovered.file_count(), 1);
        let file = recovered
            .file(StorageObjectId::new(volume(), 7).unwrap())
            .unwrap();
        assert_eq!(file.generation(), 3);
        assert_eq!(file.length(), 4096);
        assert!(
            recovered
                .file(StorageObjectId::new(volume(), 8).unwrap())
                .is_none()
        );
        let selection = recovered
            .select_file(StorageObjectId::new(volume(), 7).unwrap())
            .unwrap();
        assert_eq!(selection.volume(), volume());
        assert_eq!(selection.root_generation(), 5);
        assert_eq!(
            selection.object(),
            StorageObjectId::new(volume(), 7).unwrap()
        );
        assert_eq!(selection.generation(), 3);
    }

    #[test]
    fn selected_authority_recovery_rejects_root_mismatch_before_file_read() {
        struct NoRead;
        unsafe impl FileReadBackend for NoRead {
            type Error = ();

            fn read_verified_extent(
                &mut self,
                _record: crate::ExtentRecord,
                _byte_offset: u64,
                _output: &mut [u8],
            ) -> Result<(), Self::Error> {
                panic!("root mismatch must fail before file I/O")
            }
        }

        let (candidate, backend) = reachable_backend(true, false);
        let mut scratch = [0; 4096];
        let reachable = recover_reachable_state::<_, 8, 1, 1, 2>(
            header(),
            &encoded(candidate),
            &[0; SUPERBLOCK_BYTES],
            backend,
            &mut scratch,
        )
        .unwrap();
        let selection = reachable
            .select_file(StorageObjectId::new(volume(), 7).unwrap())
            .unwrap();
        let principal = StoragePrincipal::new(1).unwrap();
        let mut bootstrap = StorageAuthorityTable::<1>::new();
        let handle = bootstrap
            .insert(
                selection.object(),
                StorageObjectKind::File,
                StorageRights::READ,
                principal,
            )
            .unwrap();
        let admission =
            unsafe { OwnerApprovedAuthorityCheckpoint::new(2, volume(), 6, 2, [0; 32]) };
        let mut issuer = AuthorityCheckpointProofIssuer::new(admission);
        let state = unsafe { AuthenticatedAuthorityRecoveryState::new(1, 1) };
        let mut guard = AuthorityRecoveryGuard::from_authenticated_state(state);
        let mut input = [0; 256];

        assert!(matches!(
            crate::recover_selected_stable_authorities::<1, 1, 1, _>(
                selection,
                &bootstrap,
                handle,
                principal,
                &mut guard,
                &mut issuer,
                &mut input,
                &mut NoRead,
            ),
            Err(AuthorityStorageError::Checkpoint(
                AuthorityCheckpointError::AuthenticationMismatch
            ))
        ));
    }

    #[test]
    fn reachable_validator_requires_unique_forward_allocator_state() {
        let (candidate, mut backend) = reachable_backend(true, false);
        ObjectIdAllocatorImage::build(header(), 5, None, MetadataPointer::new(21, 1).unwrap())
            .unwrap()
            .encode(&mut backend.object_ids)
            .unwrap();
        let mut scratch = [0; 4096];
        let mut validator =
            ReachableRecoveryValidator::<_, 8, 1, 1, 2>::new(header(), backend, &mut scratch);
        assert_eq!(validator.validate_candidate(1, candidate), Ok(()));

        let (candidate, mut backend) = reachable_backend(true, false);
        ObjectIdAllocatorImage::build(header(), 5, Some(7), MetadataPointer::new(21, 1).unwrap())
            .unwrap()
            .encode(&mut backend.object_ids)
            .unwrap();
        let mut validator =
            ReachableRecoveryValidator::<_, 8, 1, 1, 2>::new(header(), backend, &mut scratch);
        assert_eq!(
            validator.validate_candidate(1, candidate),
            Err(CandidateValidationError::Invalid)
        );

        let (candidate, mut backend) = reachable_backend(true, false);
        ObjectIdAllocatorImage::build(header(), 4, Some(8), MetadataPointer::new(21, 1).unwrap())
            .unwrap()
            .encode(&mut backend.object_ids)
            .unwrap();
        let mut validator =
            ReachableRecoveryValidator::<_, 8, 1, 1, 2>::new(header(), backend, &mut scratch);
        assert_eq!(
            validator.validate_candidate(1, candidate),
            Err(CandidateValidationError::Invalid)
        );

        let (candidate, mut backend) = reachable_backend(true, false);
        backend.object_ids[40] ^= 1;
        let mut validator =
            ReachableRecoveryValidator::<_, 8, 1, 1, 2>::new(header(), backend, &mut scratch);
        assert_eq!(
            validator.validate_candidate(1, candidate),
            Err(CandidateValidationError::Invalid)
        );

        let (candidate, mut backend) = reachable_backend(true, false);
        let allocation_pointer = candidate.allocation_metadata();
        let decoded = AllocationImage::<8>::decode(
            header(),
            candidate.generation(),
            allocation_pointer,
            &backend.allocation,
        )
        .unwrap();
        let first = decoded.index().record(0).unwrap();
        let mut without_allocator = [first; 8];
        let mut count = 0;
        for index in 0..decoded.index().len() {
            let record = decoded.index().record(index).unwrap();
            if record.kind() != AllocationKind::ObjectIdAllocatorMetadata {
                without_allocator[count] = record;
                count += 1;
            }
        }
        AllocationImage::<8>::build(
            header(),
            candidate.generation(),
            allocation_pointer,
            &without_allocator[..count],
        )
        .unwrap()
        .encode(&mut backend.allocation)
        .unwrap();
        let mut validator =
            ReachableRecoveryValidator::<_, 8, 1, 1, 2>::new(header(), backend, &mut scratch);
        assert_eq!(
            validator.validate_candidate(1, candidate),
            Err(CandidateValidationError::Invalid)
        );

        let (candidate, mut backend) = reachable_backend(true, false);
        let decoded = AllocationImage::<8>::decode(
            header(),
            candidate.generation(),
            candidate.allocation_metadata(),
            &backend.allocation,
        )
        .unwrap();
        let duplicate = AllocationRecord::new(
            candidate.root(),
            candidate.generation(),
            22,
            1,
            AllocationKind::ObjectIdAllocatorMetadata,
        )
        .unwrap();
        let first = decoded.index().record(0).unwrap();
        let mut duplicated = [first; 8];
        let mut count = 0;
        for index in 0..decoded.index().len() {
            let record = decoded.index().record(index).unwrap();
            if record.block() > duplicate.block() && count == index {
                duplicated[count] = duplicate;
                count += 1;
            }
            duplicated[count] = record;
            count += 1;
        }
        if count == decoded.index().len() {
            duplicated[count] = duplicate;
            count += 1;
        }
        AllocationImage::<8>::build(
            header(),
            candidate.generation(),
            candidate.allocation_metadata(),
            &duplicated[..count],
        )
        .unwrap()
        .encode(&mut backend.allocation)
        .unwrap();
        let mut validator =
            ReachableRecoveryValidator::<_, 8, 1, 1, 2>::new(header(), backend, &mut scratch);
        assert_eq!(
            validator.validate_candidate(1, candidate),
            Err(CandidateValidationError::Invalid)
        );
    }

    #[test]
    fn integrated_recovery_falls_back_from_newer_root_with_unpublished_metadata() {
        let (older, backend) = reachable_backend(true, false);
        let newer = Superblock::new(
            header(),
            6,
            5,
            older.root(),
            older.root_metadata(),
            older.allocation_metadata(),
        )
        .unwrap();
        let mut scratch = [0; 4096];
        let recovered = recover_reachable_superblock::<_, 8, 1, 1, 2>(
            header(),
            &encoded(older),
            &encoded(newer),
            backend,
            &mut scratch,
        )
        .unwrap();
        assert_eq!(recovered.superblock(), older);
        assert_eq!(recovered.block(), header().primary_superblock());
        assert!(recovered.used_fallback());
    }

    #[test]
    fn integrated_recovery_never_turns_newer_validation_io_error_into_rollback() {
        let (older, backend) = reachable_backend(true, false);
        let newer = Superblock::new(
            header(),
            6,
            5,
            older.root(),
            older.root_metadata(),
            older.allocation_metadata(),
        )
        .unwrap();
        let mut scratch = [0; 4096];
        assert_eq!(
            recover_reachable_superblock::<_, 8, 1, 1, 2>(
                header(),
                &encoded(older),
                &encoded(newer),
                FailAfter {
                    inner: backend,
                    calls: 0,
                    successful_reads: 6,
                },
                &mut scratch,
            ),
            Err(RecoveryError::Backend(9))
        );
    }
}
