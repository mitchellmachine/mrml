use crate::{
    CowMetadataImage, CowMetadataWrite, CowPublicationBackend, CowPublicationPlan, CowPublishError,
    PreparedAllocationUpdate, PreparedDirectoryUpdate, PreparedFileWrite, StorageObjectId,
    StorageObjectKind, VolumeId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageTransactionId(u64);

impl StorageTransactionId {
    pub const fn new(value: u64) -> Result<Self, TransactionError> {
        if value == 0 {
            Err(TransactionError::InvalidIdentity)
        } else {
            Ok(Self(value))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionParticipant {
    resource: TransactionResource,
    old_generation: u64,
    new_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionResource {
    Object {
        object: StorageObjectId,
        kind: StorageObjectKind,
    },
    Allocation(VolumeId),
}

impl TransactionParticipant {
    pub fn new(
        object: StorageObjectId,
        kind: StorageObjectKind,
        old_generation: u64,
        new_generation: u64,
    ) -> Result<Self, TransactionError> {
        if old_generation == 0
            || new_generation == 0
            || old_generation.checked_add(1) != Some(new_generation)
        {
            return Err(TransactionError::InvalidGeneration);
        }
        Ok(Self {
            resource: TransactionResource::Object { object, kind },
            old_generation,
            new_generation,
        })
    }

    pub fn allocation(
        volume: VolumeId,
        old_generation: u64,
        new_generation: u64,
    ) -> Result<Self, TransactionError> {
        if old_generation == 0
            || new_generation == 0
            || old_generation.checked_add(1) != Some(new_generation)
        {
            return Err(TransactionError::InvalidGeneration);
        }
        Ok(Self {
            resource: TransactionResource::Allocation(volume),
            old_generation,
            new_generation,
        })
    }

    pub const fn resource(self) -> TransactionResource {
        self.resource
    }

    pub const fn new_generation(self) -> u64 {
        self.new_generation
    }
}

pub struct StorageTransaction<const P: usize, const W: usize> {
    identity: StorageTransactionId,
    publication_generation: u64,
    participants: [Option<TransactionParticipant>; P],
    participant_count: usize,
    writes: [Option<CowMetadataWrite>; W],
    write_count: usize,
}

impl<const P: usize, const W: usize> StorageTransaction<P, W> {
    pub const fn new(
        identity: StorageTransactionId,
        publication_generation: u64,
    ) -> Result<Self, TransactionError> {
        if publication_generation == 0 {
            return Err(TransactionError::InvalidGeneration);
        }
        Ok(Self {
            identity,
            publication_generation,
            participants: [None; P],
            participant_count: 0,
            writes: [None; W],
            write_count: 0,
        })
    }

    pub fn admit_file<const N: usize>(
        &mut self,
        prepared: &PreparedFileWrite<N>,
    ) -> Result<(), TransactionError> {
        self.admit_parts(
            prepared.transaction_participant()?,
            prepared.metadata_images(),
        )
    }

    pub fn admit_allocation<const N: usize>(
        &mut self,
        prepared: &PreparedAllocationUpdate<N>,
    ) -> Result<(), TransactionError> {
        self.admit_parts(
            prepared.transaction_participant()?,
            prepared.metadata_images(),
        )
    }

    pub fn admit_directory<const N: usize>(
        &mut self,
        prepared: &PreparedDirectoryUpdate<N>,
    ) -> Result<(), TransactionError> {
        self.admit_parts(
            prepared.transaction_participant()?,
            prepared.metadata_images(),
        )
    }

    pub const fn participant_count(&self) -> usize {
        self.participant_count
    }

    pub fn publish<const M: usize, B: CowPublicationBackend>(
        &self,
        plan: &CowPublicationPlan<M>,
        backend: &mut B,
    ) -> Result<TransactionReceipt<P>, TransactionPublishError<B::Error>> {
        if self.participant_count == 0 || plan.generation() != self.publication_generation {
            return Err(TransactionPublishError::WrongPlan);
        }
        for write in self.writes[..self.write_count].iter().flatten().copied() {
            if !plan.contains_write(write) {
                return Err(TransactionPublishError::WrongPlan);
            }
        }
        plan.publish(backend)
            .map_err(TransactionPublishError::Publication)?;
        Ok(TransactionReceipt {
            identity: self.identity,
            publication_generation: self.publication_generation,
            participants: self.participants,
            remaining: self.participant_count,
        })
    }

    fn admit_parts<const I: usize>(
        &mut self,
        participant: TransactionParticipant,
        images: [CowMetadataImage; I],
    ) -> Result<(), TransactionError> {
        if self.participant_count == P || self.write_count.checked_add(I).is_none_or(|n| n > W) {
            return Err(TransactionError::Capacity);
        }
        if self.participants[..self.participant_count]
            .iter()
            .flatten()
            .any(|current| current.resource == participant.resource)
        {
            return Err(TransactionError::DuplicateObject);
        }
        let mut bound = [None; I];
        for (index, image) in images.into_iter().enumerate() {
            let write = image
                .bind(self.publication_generation)
                .map_err(|_| TransactionError::InvalidGeneration)?;
            if self.writes[..self.write_count]
                .iter()
                .flatten()
                .any(|current| current.pointer() == write.pointer())
                || bound[..index]
                    .iter()
                    .flatten()
                    .any(|current: &CowMetadataWrite| current.pointer() == write.pointer())
            {
                return Err(TransactionError::DuplicateMetadataRange);
            }
            bound[index] = Some(write);
        }

        self.participants[self.participant_count] = Some(participant);
        self.participant_count += 1;
        for write in bound.into_iter().flatten() {
            self.writes[self.write_count] = Some(write);
            self.write_count += 1;
        }
        Ok(())
    }
}

pub struct TransactionReceipt<const P: usize> {
    identity: StorageTransactionId,
    publication_generation: u64,
    participants: [Option<TransactionParticipant>; P],
    remaining: usize,
}

impl<const P: usize> TransactionReceipt<P> {
    pub const fn identity(&self) -> StorageTransactionId {
        self.identity
    }

    pub const fn publication_generation(&self) -> u64 {
        self.publication_generation
    }

    pub const fn remaining(&self) -> usize {
        self.remaining
    }

    pub fn consume(&mut self, expected: TransactionParticipant) -> Result<(), TransactionError> {
        let entry = self
            .participants
            .iter_mut()
            .find(|entry| **entry == Some(expected))
            .ok_or(TransactionError::ParticipantMismatch)?;
        *entry = None;
        self.remaining -= 1;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionError {
    InvalidIdentity,
    InvalidGeneration,
    Capacity,
    DuplicateObject,
    DuplicateMetadataRange,
    ParticipantMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionPublishError<E> {
    WrongPlan,
    Publication(CowPublishError<E>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MetadataPointer, Superblock, VolumeHeader, VolumeId};

    fn volume() -> VolumeId {
        VolumeId::new([6; 16]).unwrap()
    }

    fn object(local: u64) -> StorageObjectId {
        StorageObjectId::new(volume(), local).unwrap()
    }

    fn pointer(block: u64) -> MetadataPointer {
        MetadataPointer::new(block, 1).unwrap()
    }

    fn participant(local: u64, old: u64) -> TransactionParticipant {
        TransactionParticipant::new(object(local), StorageObjectKind::File, old, old + 1).unwrap()
    }

    struct Backend {
        verified: usize,
        replaced: usize,
    }

    unsafe impl CowPublicationBackend for Backend {
        type Error = ();

        fn verify_new_metadata(&mut self, _write: CowMetadataWrite) -> Result<(), Self::Error> {
            self.verified += 1;
            Ok(())
        }

        fn flush_new_metadata(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn replace_superblock(
            &mut self,
            block: u64,
            _encoded: &[u8; crate::SUPERBLOCK_BYTES],
        ) -> Result<(), Self::Error> {
            assert_eq!(block, 2);
            self.replaced += 1;
            Ok(())
        }

        fn flush_superblock(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn different_object_generations_publish_in_one_volume_generation() {
        let first = participant(10, 3);
        let second = participant(20, 8);
        let first_images = [
            CowMetadataImage::new(pointer(10), [1; 32]),
            CowMetadataImage::new(pointer(11), [2; 32]),
        ];
        let second_images = [
            CowMetadataImage::new(pointer(20), [3; 32]),
            CowMetadataImage::new(pointer(21), [4; 32]),
        ];
        let mut transaction =
            StorageTransaction::<2, 4>::new(StorageTransactionId::new(7).unwrap(), 10).unwrap();
        transaction.admit_parts(first, first_images).unwrap();
        transaction.admit_parts(second, second_images).unwrap();

        let header = VolumeHeader::new(volume(), 4096, 100, 1, 2).unwrap();
        let active = Superblock::new(header, 9, 8, object(1), pointer(50), pointer(60)).unwrap();
        let root = CowMetadataWrite::new(pointer(30), 10, [5; 32]).unwrap();
        let allocation = CowMetadataWrite::new(pointer(40), 10, [6; 32]).unwrap();
        let plan = CowPublicationPlan::<6>::build(
            header,
            1,
            active,
            object(1),
            root.pointer(),
            allocation.pointer(),
            &[
                first_images[0].bind(10).unwrap(),
                first_images[1].bind(10).unwrap(),
                second_images[0].bind(10).unwrap(),
                second_images[1].bind(10).unwrap(),
                root,
                allocation,
            ],
            &[pointer(50), pointer(60)],
        )
        .unwrap();
        let mut backend = Backend {
            verified: 0,
            replaced: 0,
        };
        let mut receipt = transaction.publish(&plan, &mut backend).unwrap();
        assert_eq!((backend.verified, backend.replaced), (6, 1));
        assert_eq!(receipt.remaining(), 2);
        assert_eq!(receipt.consume(first), Ok(()));
        assert_eq!(
            receipt.consume(first),
            Err(TransactionError::ParticipantMismatch)
        );
        assert_eq!(receipt.consume(second), Ok(()));
        assert_eq!(receipt.remaining(), 0);
    }

    #[test]
    fn duplicate_or_capacity_failure_leaves_transaction_unchanged() {
        let first = participant(10, 3);
        let images = [
            CowMetadataImage::new(pointer(10), [1; 32]),
            CowMetadataImage::new(pointer(11), [2; 32]),
        ];
        let mut transaction =
            StorageTransaction::<2, 3>::new(StorageTransactionId::new(8).unwrap(), 10).unwrap();
        transaction.admit_parts(first, images).unwrap();
        assert_eq!(
            transaction.admit_parts(first, [CowMetadataImage::new(pointer(12), [3; 32])]),
            Err(TransactionError::DuplicateObject)
        );
        assert_eq!(transaction.participant_count(), 1);
        assert_eq!(
            transaction.admit_parts(
                participant(20, 4),
                [
                    CowMetadataImage::new(pointer(20), [3; 32]),
                    CowMetadataImage::new(pointer(21), [4; 32]),
                ],
            ),
            Err(TransactionError::Capacity)
        );
        assert_eq!(transaction.participant_count(), 1);
    }

    #[test]
    fn missing_participant_metadata_rejects_before_backend() {
        let participant = participant(10, 3);
        let images = [
            CowMetadataImage::new(pointer(10), [1; 32]),
            CowMetadataImage::new(pointer(11), [2; 32]),
        ];
        let mut transaction =
            StorageTransaction::<1, 2>::new(StorageTransactionId::new(9).unwrap(), 10).unwrap();
        transaction.admit_parts(participant, images).unwrap();
        let header = VolumeHeader::new(volume(), 4096, 100, 1, 2).unwrap();
        let active = Superblock::new(header, 9, 8, object(1), pointer(50), pointer(60)).unwrap();
        let root = CowMetadataWrite::new(pointer(30), 10, [5; 32]).unwrap();
        let allocation = CowMetadataWrite::new(pointer(40), 10, [6; 32]).unwrap();
        let plan = CowPublicationPlan::<3>::build(
            header,
            1,
            active,
            object(1),
            root.pointer(),
            allocation.pointer(),
            &[images[0].bind(10).unwrap(), root, allocation],
            &[pointer(50), pointer(60)],
        )
        .unwrap();
        let mut backend = Backend {
            verified: 0,
            replaced: 0,
        };
        assert!(matches!(
            transaction.publish(&plan, &mut backend),
            Err(TransactionPublishError::WrongPlan)
        ));
        assert_eq!((backend.verified, backend.replaced), (0, 0));
    }
}
