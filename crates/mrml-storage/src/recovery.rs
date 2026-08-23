use crate::{
    AllocationImage, AllocationKind, DIRECTORY_METADATA_BYTES, DirectoryImage, DirectoryMetadata,
    ExtentImage, FILE_METADATA_BYTES, FileMetadata, MetadataPointer, StorageObjectId,
    StorageObjectKind, Superblock, VolumeHeader,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveredSuperblock {
    block: u64,
    superblock: Superblock,
    fallback: bool,
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
}

impl<'a, B, const A: usize, const D: usize, const E: usize, const O: usize>
    ReachableRecoveryValidator<'a, B, A, D, E, O>
{
    pub fn new(header: VolumeHeader, backend: B, scratch: &'a mut [u8]) -> Self {
        Self {
            header,
            backend,
            scratch,
        }
    }

    pub const fn backend(&self) -> &B {
        &self.backend
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
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
                }
                StorageObjectKind::Volume => return Err(CandidateValidationError::Invalid),
            }
            cursor += 1;
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
        AllocationKind, AllocationRecord, DirectoryEntry, DirectoryImage, DirectoryMetadata,
        ExtentImage, ExtentRecord, FileMetadata, MetadataPointer, SUPERBLOCK_BYTES, StorageName,
        StorageObjectId, VolumeId,
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
                _ => return Err(()),
            };
            if pointer.blocks() != 1 || output.len() != source.len() {
                return Err(());
            }
            output.copy_from_slice(source);
            Ok(())
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
            7
        } else if include_data_owner {
            6
        } else {
            5
        };
        let mut allocation = [0; 4096];
        AllocationImage::<7>::build(header(), 5, allocation_pointer, &records[..record_count])
            .unwrap()
            .encode(&mut allocation)
            .unwrap();
        (
            candidate,
            MetadataBackend {
                root: root_bytes,
                entries,
                file: file_bytes,
                extents,
                allocation,
            },
        )
    }

    #[test]
    fn reachable_validator_checks_namespace_metadata_and_data_ownership() {
        let (candidate, backend) = reachable_backend(true, false);
        let mut scratch = [0; 4096];
        let mut validator =
            ReachableRecoveryValidator::<_, 7, 1, 1, 2>::new(header(), backend, &mut scratch);
        assert_eq!(validator.validate_candidate(1, candidate), Ok(()));

        let (candidate, backend) = reachable_backend(false, false);
        let mut scratch = [0; 4096];
        let mut validator =
            ReachableRecoveryValidator::<_, 7, 1, 1, 2>::new(header(), backend, &mut scratch);
        assert_eq!(
            validator.validate_candidate(1, candidate),
            Err(CandidateValidationError::Invalid)
        );

        let (candidate, backend) = reachable_backend(true, true);
        let mut scratch = [0; 4096];
        let mut validator =
            ReachableRecoveryValidator::<_, 7, 1, 1, 2>::new(header(), backend, &mut scratch);
        assert_eq!(
            validator.validate_candidate(1, candidate),
            Err(CandidateValidationError::Invalid)
        );
    }
}
