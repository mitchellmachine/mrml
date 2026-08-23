use crate::{MetadataPointer, StorageObjectId, Superblock, VolumeHeader};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CowMetadataWrite {
    pointer: MetadataPointer,
    generation: u64,
    digest: [u8; 32],
}

impl CowMetadataWrite {
    pub const fn new(
        pointer: MetadataPointer,
        generation: u64,
        digest: [u8; 32],
    ) -> Result<Self, CowPlanError> {
        if generation == 0 {
            return Err(CowPlanError::InvalidGeneration);
        }
        Ok(Self {
            pointer,
            generation,
            digest,
        })
    }

    pub const fn pointer(self) -> MetadataPointer {
        self.pointer
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }
}

pub struct CowPublicationPlan<const N: usize> {
    writes: [Option<CowMetadataWrite>; N],
    write_count: usize,
    target_superblock_block: u64,
    next_superblock: Superblock,
}

impl<const N: usize> CowPublicationPlan<N> {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        header: VolumeHeader,
        active_superblock_block: u64,
        active: Superblock,
        root: StorageObjectId,
        root_metadata: MetadataPointer,
        allocation_metadata: MetadataPointer,
        writes: &[CowMetadataWrite],
        protected_active: &[MetadataPointer],
    ) -> Result<Self, CowPlanError> {
        if writes.is_empty() || writes.len() > N || protected_active.len() > N {
            return Err(CowPlanError::Capacity);
        }
        if active.volume() != header.volume() {
            return Err(CowPlanError::InvalidActiveSuperblock);
        }
        let target_superblock_block = if active_superblock_block == header.primary_superblock() {
            header.secondary_superblock()
        } else if active_superblock_block == header.secondary_superblock() {
            header.primary_superblock()
        } else {
            return Err(CowPlanError::InvalidActiveSuperblock);
        };
        let generation = active
            .generation()
            .checked_add(1)
            .ok_or(CowPlanError::GenerationExhausted)?;
        let next_superblock = Superblock::new(
            header,
            generation,
            active.generation(),
            root,
            root_metadata,
            allocation_metadata,
        )
        .map_err(|_| CowPlanError::InvalidNextSuperblock)?;

        let mut stored = [None; N];
        let mut has_root = false;
        let mut has_allocation = false;
        for (index, write) in writes.iter().copied().enumerate() {
            if write.generation != generation
                || !pointer_within_volume(write.pointer, header)
                || pointer_contains(write.pointer, 0)
                || pointer_contains(write.pointer, header.primary_superblock())
                || pointer_contains(write.pointer, header.secondary_superblock())
            {
                return Err(CowPlanError::InvalidWrite);
            }
            for prior in writes[..index].iter().copied() {
                if pointers_overlap(prior.pointer, write.pointer) {
                    return Err(CowPlanError::WriteOverlap);
                }
            }
            for protected in protected_active.iter().copied() {
                if pointers_overlap(protected, write.pointer) {
                    return Err(CowPlanError::OverwritesActiveMetadata);
                }
            }
            if pointers_overlap(active.root_metadata(), write.pointer)
                || pointers_overlap(active.allocation_metadata(), write.pointer)
            {
                return Err(CowPlanError::OverwritesActiveMetadata);
            }
            has_root |= write.pointer == root_metadata;
            has_allocation |= write.pointer == allocation_metadata;
            stored[index] = Some(write);
        }
        if !has_root || !has_allocation {
            return Err(CowPlanError::MissingPublicationRoot);
        }
        Ok(Self {
            writes: stored,
            write_count: writes.len(),
            target_superblock_block,
            next_superblock,
        })
    }

    pub const fn generation(&self) -> u64 {
        self.next_superblock.generation()
    }

    pub const fn target_superblock_block(&self) -> u64 {
        self.target_superblock_block
    }

    pub fn contains_write(&self, expected: CowMetadataWrite) -> bool {
        self.writes[..self.write_count]
            .iter()
            .flatten()
            .any(|write| *write == expected)
    }

    pub fn publish<B: CowPublicationBackend>(
        &self,
        backend: &mut B,
    ) -> Result<Superblock, CowPublishError<B::Error>> {
        for write in self.writes[..self.write_count].iter().flatten().copied() {
            backend
                .verify_new_metadata(write)
                .map_err(CowPublishError::Rejected)?;
        }
        backend
            .flush_new_metadata()
            .map_err(CowPublishError::Rejected)?;

        let mut encoded = [0; crate::SUPERBLOCK_BYTES];
        self.next_superblock.encode(&mut encoded);
        backend
            .replace_superblock(self.target_superblock_block, &encoded)
            .map_err(CowPublishError::FailStop)?;
        backend
            .flush_superblock()
            .map_err(CowPublishError::FailStop)?;
        Ok(self.next_superblock)
    }
}

/// Persistence boundary for copy-on-write metadata publication.
///
/// # Safety
///
/// An implementation must verify that each exact unreachable range already
/// contains the complete image whose SHA3-256 digest is supplied, make those
/// staged writes durable when `flush_new_metadata` succeeds, replace the
/// complete target superblock atomically or report an error, and make that
/// replacement durable when `flush_superblock` succeeds. It must not redirect,
/// merge, reorder, or acknowledge incomplete or mismatched images.
pub unsafe trait CowPublicationBackend {
    type Error;

    fn verify_new_metadata(&mut self, write: CowMetadataWrite) -> Result<(), Self::Error>;
    fn flush_new_metadata(&mut self) -> Result<(), Self::Error>;
    fn replace_superblock(
        &mut self,
        block: u64,
        encoded: &[u8; crate::SUPERBLOCK_BYTES],
    ) -> Result<(), Self::Error>;
    fn flush_superblock(&mut self) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CowPlanError {
    Capacity,
    InvalidGeneration,
    GenerationExhausted,
    InvalidActiveSuperblock,
    InvalidNextSuperblock,
    InvalidWrite,
    WriteOverlap,
    OverwritesActiveMetadata,
    MissingPublicationRoot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CowPublishError<E> {
    Rejected(E),
    FailStop(E),
}

fn pointer_within_volume(pointer: MetadataPointer, header: VolumeHeader) -> bool {
    pointer
        .block()
        .checked_add(u64::from(pointer.blocks()))
        .is_some_and(|end| end <= header.block_count())
}

fn pointer_contains(pointer: MetadataPointer, block: u64) -> bool {
    block >= pointer.block() && block < pointer.block() + u64::from(pointer.blocks())
}

fn pointers_overlap(left: MetadataPointer, right: MetadataPointer) -> bool {
    left.block() < right.block() + u64::from(right.blocks())
        && right.block() < left.block() + u64::from(left.blocks())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VolumeId;

    fn volume() -> VolumeId {
        VolumeId::new([3; 16]).unwrap()
    }

    fn object(local: u64) -> StorageObjectId {
        StorageObjectId::new(volume(), local).unwrap()
    }

    fn pointer(block: u64, blocks: u32) -> MetadataPointer {
        MetadataPointer::new(block, blocks).unwrap()
    }

    fn header() -> VolumeHeader {
        VolumeHeader::new(volume(), 4096, 1000, 1, 2).unwrap()
    }

    fn active() -> Superblock {
        Superblock::new(header(), 4, 3, object(1), pointer(10, 1), pointer(20, 1)).unwrap()
    }

    fn plan() -> CowPublicationPlan<3> {
        CowPublicationPlan::build(
            header(),
            1,
            active(),
            object(1),
            pointer(30, 1),
            pointer(40, 1),
            &[
                CowMetadataWrite::new(pointer(30, 1), 5, [1; 32]).unwrap(),
                CowMetadataWrite::new(pointer(40, 1), 5, [2; 32]).unwrap(),
            ],
            &[pointer(10, 1), pointer(20, 1)],
        )
        .unwrap()
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        Verify(u64),
        FlushMetadata,
        Replace(u64),
        FlushSuperblock,
    }

    struct Backend {
        events: [Option<Event>; 8],
        count: usize,
        fail_at: Option<usize>,
    }

    impl Backend {
        fn new(fail_at: Option<usize>) -> Self {
            Self {
                events: [None; 8],
                count: 0,
                fail_at,
            }
        }

        fn event(&mut self, event: Event) -> Result<(), usize> {
            let index = self.count;
            self.events[index] = Some(event);
            self.count += 1;
            if self.fail_at == Some(index) {
                Err(index)
            } else {
                Ok(())
            }
        }
    }

    unsafe impl CowPublicationBackend for Backend {
        type Error = usize;

        fn verify_new_metadata(&mut self, write: CowMetadataWrite) -> Result<(), Self::Error> {
            self.event(Event::Verify(write.pointer().block()))
        }

        fn flush_new_metadata(&mut self) -> Result<(), Self::Error> {
            self.event(Event::FlushMetadata)
        }

        fn replace_superblock(
            &mut self,
            block: u64,
            _encoded: &[u8; crate::SUPERBLOCK_BYTES],
        ) -> Result<(), Self::Error> {
            self.event(Event::Replace(block))
        }

        fn flush_superblock(&mut self) -> Result<(), Self::Error> {
            self.event(Event::FlushSuperblock)
        }
    }

    #[test]
    fn publication_orders_new_metadata_before_inactive_superblock() {
        let plan = plan();
        let mut backend = Backend::new(None);
        assert_eq!(plan.target_superblock_block(), 2);
        assert_eq!(plan.publish(&mut backend).unwrap().generation(), 5);
        assert_eq!(
            backend.events[..backend.count],
            [
                Some(Event::Verify(30)),
                Some(Event::Verify(40)),
                Some(Event::FlushMetadata),
                Some(Event::Replace(2)),
                Some(Event::FlushSuperblock),
            ]
        );
        let reverse = CowPublicationPlan::<2>::build(
            header(),
            2,
            active(),
            object(1),
            pointer(30, 1),
            pointer(40, 1),
            &[
                CowMetadataWrite::new(pointer(30, 1), 5, [1; 32]).unwrap(),
                CowMetadataWrite::new(pointer(40, 1), 5, [2; 32]).unwrap(),
            ],
            &[pointer(10, 1), pointer(20, 1)],
        )
        .unwrap();
        assert_eq!(reverse.target_superblock_block(), 1);
    }

    #[test]
    fn prepublication_failure_is_rejected_and_postpublication_is_fail_stop() {
        for failure in 0..3 {
            let mut backend = Backend::new(Some(failure));
            assert_eq!(
                plan().publish(&mut backend),
                Err(CowPublishError::Rejected(failure))
            );
            assert!(
                backend.events[..backend.count]
                    .iter()
                    .all(|event| !matches!(event, Some(Event::Replace(_))))
            );
        }
        for failure in 3..5 {
            let mut backend = Backend::new(Some(failure));
            assert_eq!(
                plan().publish(&mut backend),
                Err(CowPublishError::FailStop(failure))
            );
        }
    }

    #[test]
    fn plan_rejects_active_overwrite_overlap_and_missing_roots() {
        let overlapping = [
            CowMetadataWrite::new(pointer(30, 2), 5, [1; 32]).unwrap(),
            CowMetadataWrite::new(pointer(31, 1), 5, [2; 32]).unwrap(),
        ];
        assert!(matches!(
            CowPublicationPlan::<2>::build(
                header(),
                1,
                active(),
                object(1),
                pointer(30, 2),
                pointer(31, 1),
                &overlapping,
                &[pointer(10, 1), pointer(20, 1)],
            ),
            Err(CowPlanError::WriteOverlap)
        ));
        let overwrite = [
            CowMetadataWrite::new(pointer(10, 1), 5, [1; 32]).unwrap(),
            CowMetadataWrite::new(pointer(40, 1), 5, [2; 32]).unwrap(),
        ];
        assert!(matches!(
            CowPublicationPlan::<2>::build(
                header(),
                1,
                active(),
                object(1),
                pointer(10, 1),
                pointer(40, 1),
                &overwrite,
                &[],
            ),
            Err(CowPlanError::OverwritesActiveMetadata)
        ));
        let missing = [CowMetadataWrite::new(pointer(30, 1), 5, [1; 32]).unwrap()];
        assert!(matches!(
            CowPublicationPlan::<2>::build(
                header(),
                1,
                active(),
                object(1),
                pointer(30, 1),
                pointer(40, 1),
                &missing,
                &[pointer(10, 1), pointer(20, 1)],
            ),
            Err(CowPlanError::MissingPublicationRoot)
        ));
    }

    #[test]
    fn plan_rejects_wrong_generation_reserved_blocks_and_unknown_active_slot() {
        let wrong_generation = [
            CowMetadataWrite::new(pointer(30, 1), 4, [1; 32]).unwrap(),
            CowMetadataWrite::new(pointer(40, 1), 5, [2; 32]).unwrap(),
        ];
        assert!(matches!(
            CowPublicationPlan::<2>::build(
                header(),
                1,
                active(),
                object(1),
                pointer(30, 1),
                pointer(40, 1),
                &wrong_generation,
                &[pointer(10, 1), pointer(20, 1)]
            ),
            Err(CowPlanError::InvalidWrite)
        ));
        let reserved = [
            CowMetadataWrite::new(pointer(2, 1), 5, [1; 32]).unwrap(),
            CowMetadataWrite::new(pointer(40, 1), 5, [2; 32]).unwrap(),
        ];
        assert!(matches!(
            CowPublicationPlan::<2>::build(
                header(),
                1,
                active(),
                object(1),
                pointer(2, 1),
                pointer(40, 1),
                &reserved,
                &[pointer(10, 1), pointer(20, 1)]
            ),
            Err(CowPlanError::InvalidWrite)
        ));
        assert!(matches!(
            CowPublicationPlan::<2>::build(
                header(),
                9,
                active(),
                object(1),
                pointer(30, 1),
                pointer(40, 1),
                &[
                    CowMetadataWrite::new(pointer(30, 1), 5, [1; 32]).unwrap(),
                    CowMetadataWrite::new(pointer(40, 1), 5, [2; 32]).unwrap(),
                ],
                &[pointer(10, 1), pointer(20, 1)]
            ),
            Err(CowPlanError::InvalidActiveSuperblock)
        ));
        let exhausted = Superblock::new(
            header(),
            u64::MAX,
            u64::MAX - 1,
            object(1),
            pointer(10, 1),
            pointer(20, 1),
        )
        .unwrap();
        assert!(matches!(
            CowPublicationPlan::<2>::build(
                header(),
                1,
                exhausted,
                object(1),
                pointer(30, 1),
                pointer(40, 1),
                &[
                    CowMetadataWrite::new(pointer(30, 1), u64::MAX, [1; 32]).unwrap(),
                    CowMetadataWrite::new(pointer(40, 1), u64::MAX, [2; 32]).unwrap(),
                ],
                &[pointer(10, 1), pointer(20, 1)]
            ),
            Err(CowPlanError::GenerationExhausted)
        ));
    }
}
