use mrml_crypto::Sha3_256;

use crate::{
    AllocationKind, CowMetadataImage, MetadataPointer, PreparedAllocationUpdate, StorageObjectId,
    TransactionError, TransactionParticipant, TransactionReceipt, VolumeHeader, VolumeId,
};

pub const OBJECT_ID_ALLOCATOR_HEADER_BYTES: usize = 96;

const ALLOCATOR_MAGIC: [u8; 8] = *b"MRIDA001";
const ALLOCATOR_VERSION: u16 = 1;
const DIGEST_OFFSET: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectIdAllocatorImage {
    volume: VolumeId,
    generation: u64,
    next_local: Option<u64>,
    pointer: MetadataPointer,
    encoded_len: usize,
}

impl ObjectIdAllocatorImage {
    pub fn build(
        header: VolumeHeader,
        generation: u64,
        next_local: Option<u64>,
        pointer: MetadataPointer,
    ) -> Result<Self, ObjectIdAllocatorError> {
        if generation == 0 || next_local == Some(0) || !pointer_fits(header, pointer) {
            return Err(ObjectIdAllocatorError::InvalidImage);
        }
        Ok(Self {
            volume: header.volume(),
            generation,
            next_local,
            pointer,
            encoded_len: image_bytes(header, pointer)?,
        })
    }

    pub fn decode(
        header: VolumeHeader,
        generation: u64,
        pointer: MetadataPointer,
        input: &[u8],
    ) -> Result<Self, ObjectIdAllocatorError> {
        if input.len() != image_bytes(header, pointer)? {
            return Err(ObjectIdAllocatorError::Truncated);
        }
        if input[..8] != ALLOCATOR_MAGIC
            || get_u16(input, 10)? != OBJECT_ID_ALLOCATOR_HEADER_BYTES as u16
            || input[12..16].iter().any(|byte| *byte != 0)
            || input[60..DIGEST_OFFSET].iter().any(|byte| *byte != 0)
            || input[OBJECT_ID_ALLOCATOR_HEADER_BYTES..]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(ObjectIdAllocatorError::NonCanonical);
        }
        if get_u16(input, 8)? != ALLOCATOR_VERSION {
            return Err(ObjectIdAllocatorError::UnsupportedVersion);
        }
        if input[DIGEST_OFFSET..OBJECT_ID_ALLOCATOR_HEADER_BYTES] != image_digest(input) {
            return Err(ObjectIdAllocatorError::Corrupt);
        }
        let volume = read_volume(input, 16)?;
        let encoded_pointer = MetadataPointer::new(get_u64(input, 48)?, get_u32(input, 56)?)
            .map_err(|_| ObjectIdAllocatorError::InvalidImage)?;
        if volume != header.volume()
            || get_u64(input, 32)? != generation
            || encoded_pointer != pointer
            || !pointer_fits(header, pointer)
        {
            return Err(ObjectIdAllocatorError::InvalidImage);
        }
        let next_local = match get_u64(input, 40)? {
            0 => None,
            value => Some(value),
        };
        Self::build(header, generation, next_local, pointer)
    }

    pub const fn volume(&self) -> VolumeId {
        self.volume
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn next_local(&self) -> Option<u64> {
        self.next_local
    }

    pub const fn pointer(&self) -> MetadataPointer {
        self.pointer
    }

    pub fn next_object(&self) -> Result<StorageObjectId, ObjectIdAllocatorError> {
        StorageObjectId::new(
            self.volume,
            self.next_local
                .ok_or(ObjectIdAllocatorError::IdentityExhausted)?,
        )
        .map_err(|_| ObjectIdAllocatorError::IdentityExhausted)
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<(), ObjectIdAllocatorError> {
        if output.len() != self.encoded_len {
            return Err(ObjectIdAllocatorError::Truncated);
        }
        output.fill(0);
        output[..8].copy_from_slice(&ALLOCATOR_MAGIC);
        put_u16(output, 8, ALLOCATOR_VERSION);
        put_u16(output, 10, OBJECT_ID_ALLOCATOR_HEADER_BYTES as u16);
        output[16..32].copy_from_slice(&self.volume.bytes());
        put_u64(output, 32, self.generation);
        put_u64(output, 40, self.next_local.unwrap_or(0));
        put_u64(output, 48, self.pointer.block());
        put_u32(output, 56, self.pointer.blocks());
        let digest = image_digest(output);
        output[DIGEST_OFFSET..OBJECT_ID_ALLOCATOR_HEADER_BYTES].copy_from_slice(&digest);
        Ok(())
    }

    pub fn prepare_reservation<B: ObjectIdAllocatorWriteBackend>(
        &self,
        header: VolumeHeader,
        next_pointer: MetadataPointer,
        encoded: &mut [u8],
        backend: &mut B,
    ) -> Result<PreparedObjectIdReservation, ObjectIdAllocatorUpdateError<B::Error>> {
        if header.volume() != self.volume
            || !pointer_fits(header, next_pointer)
            || pointers_overlap(self.pointer, next_pointer)
        {
            return Err(ObjectIdAllocatorUpdateError::Planning(
                ObjectIdAllocatorError::InvalidImage,
            ));
        }
        let allocated = self
            .next_object()
            .map_err(ObjectIdAllocatorUpdateError::Planning)?;
        let generation =
            self.generation
                .checked_add(1)
                .ok_or(ObjectIdAllocatorUpdateError::Planning(
                    ObjectIdAllocatorError::GenerationExhausted,
                ))?;
        let successor = Self::build(
            header,
            generation,
            allocated.local().checked_add(1),
            next_pointer,
        )
        .map_err(ObjectIdAllocatorUpdateError::Planning)?;
        successor
            .encode(encoded)
            .map_err(ObjectIdAllocatorUpdateError::Planning)?;
        let metadata = CowMetadataImage::new(next_pointer, complete_digest(encoded));
        backend
            .stage_object_id_allocator(metadata, encoded)
            .map_err(ObjectIdAllocatorUpdateError::Backend)?;
        backend
            .flush_object_id_allocator()
            .map_err(ObjectIdAllocatorUpdateError::Backend)?;
        Ok(PreparedObjectIdReservation {
            old_generation: self.generation,
            allocated,
            successor,
            metadata,
        })
    }
}

pub struct PreparedObjectIdReservation {
    old_generation: u64,
    allocated: StorageObjectId,
    successor: ObjectIdAllocatorImage,
    metadata: CowMetadataImage,
}

impl PreparedObjectIdReservation {
    pub const fn allocated(&self) -> StorageObjectId {
        self.allocated
    }

    pub const fn generation(&self) -> u64 {
        self.successor.generation
    }

    pub const fn pointer(&self) -> MetadataPointer {
        self.successor.pointer
    }

    pub const fn metadata_image(&self) -> CowMetadataImage {
        self.metadata
    }

    /// Returns whether the prepared allocation successor owns this allocator
    /// image at its exact root anchor, generation, range, and allocation purpose.
    ///
    /// The root object anchors the lifetime accounting for this volume-scoped
    /// metadata. It does not grant authority to use either the root or the
    /// allocated object.
    pub fn allocation_owned_by<const N: usize>(
        &self,
        allocation: &PreparedAllocationUpdate<N>,
        root: StorageObjectId,
    ) -> bool {
        root.volume() == self.successor.volume
            && allocation.owns_image(
                root,
                self.successor.generation,
                self.successor.pointer,
                AllocationKind::ObjectIdAllocatorMetadata,
            )
    }

    pub(crate) fn transaction_participant(
        &self,
    ) -> Result<TransactionParticipant, TransactionError> {
        TransactionParticipant::object_id_allocator(
            self.successor.volume,
            self.old_generation,
            self.successor.generation,
        )
    }

    pub(crate) const fn metadata_images(&self) -> [CowMetadataImage; 1] {
        [self.metadata]
    }

    pub fn commit_transaction<const P: usize>(
        self,
        receipt: &mut TransactionReceipt<P>,
    ) -> Result<(ObjectIdAllocatorImage, StorageObjectId), TransactionError> {
        receipt.consume(self.transaction_participant()?)?;
        Ok((self.successor, self.allocated))
    }

    pub(crate) fn into_successor(self) -> (ObjectIdAllocatorImage, StorageObjectId) {
        (self.successor, self.allocated)
    }
}

/// Persistence boundary for an unreachable object-ID allocator successor.
///
/// # Safety
///
/// Implementations must write the complete supplied image to the exact range,
/// verify all bytes against the supplied digest, keep it unreachable from the
/// active root, and make it durable before `flush_object_id_allocator`
/// succeeds. They must not redirect, shorten, merge, or acknowledge stale or
/// partially written images.
pub unsafe trait ObjectIdAllocatorWriteBackend {
    type Error;

    fn stage_object_id_allocator(
        &mut self,
        image: CowMetadataImage,
        encoded: &[u8],
    ) -> Result<(), Self::Error>;

    fn flush_object_id_allocator(&mut self) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectIdAllocatorError {
    Truncated,
    UnsupportedVersion,
    NonCanonical,
    Corrupt,
    InvalidImage,
    Arithmetic,
    GenerationExhausted,
    IdentityExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectIdAllocatorUpdateError<E> {
    Planning(ObjectIdAllocatorError),
    Backend(E),
}

fn image_bytes(
    header: VolumeHeader,
    pointer: MetadataPointer,
) -> Result<usize, ObjectIdAllocatorError> {
    usize::try_from(
        u64::from(header.block_size())
            .checked_mul(u64::from(pointer.blocks()))
            .ok_or(ObjectIdAllocatorError::Arithmetic)?,
    )
    .map_err(|_| ObjectIdAllocatorError::Arithmetic)
}

fn pointer_fits(header: VolumeHeader, pointer: MetadataPointer) -> bool {
    pointer
        .block()
        .checked_add(u64::from(pointer.blocks()))
        .is_some_and(|end| end <= header.block_count())
        && !pointer_contains(pointer, 0)
        && !pointer_contains(pointer, header.primary_superblock())
        && !pointer_contains(pointer, header.secondary_superblock())
}

fn pointers_overlap(left: MetadataPointer, right: MetadataPointer) -> bool {
    left.block() < right.block() + u64::from(right.blocks())
        && right.block() < left.block() + u64::from(left.blocks())
}

fn pointer_contains(pointer: MetadataPointer, block: u64) -> bool {
    block >= pointer.block() && block < pointer.block() + u64::from(pointer.blocks())
}

fn image_digest(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(&input[..DIGEST_OFFSET]);
    hasher.update(&input[OBJECT_ID_ALLOCATOR_HEADER_BYTES..]);
    hasher.finalize()
}

fn complete_digest(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(input);
    hasher.finalize()
}

fn read_volume(input: &[u8], offset: usize) -> Result<VolumeId, ObjectIdAllocatorError> {
    let bytes: [u8; 16] = input
        .get(offset..offset + 16)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ObjectIdAllocatorError::Truncated)?;
    VolumeId::new(bytes).map_err(|_| ObjectIdAllocatorError::InvalidImage)
}

fn get_u16(input: &[u8], offset: usize) -> Result<u16, ObjectIdAllocatorError> {
    let bytes = input
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ObjectIdAllocatorError::Truncated)?;
    Ok(u16::from_le_bytes(bytes))
}

fn get_u32(input: &[u8], offset: usize) -> Result<u32, ObjectIdAllocatorError> {
    let bytes = input
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ObjectIdAllocatorError::Truncated)?;
    Ok(u32::from_le_bytes(bytes))
}

fn get_u64(input: &[u8], offset: usize) -> Result<u64, ObjectIdAllocatorError> {
    let bytes = input
        .get(offset..offset + 8)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ObjectIdAllocatorError::Truncated)?;
    Ok(u64::from_le_bytes(bytes))
}

fn put_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AllocationChange, AllocationImage, AllocationRecord, AllocationWriteBackend,
        CowMetadataWrite, CowPublicationBackend, CowPublicationPlan, StorageTransaction,
        StorageTransactionId, Superblock,
    };

    fn volume() -> VolumeId {
        VolumeId::new([11; 16]).unwrap()
    }

    fn object(local: u64) -> StorageObjectId {
        StorageObjectId::new(volume(), local).unwrap()
    }

    fn header() -> VolumeHeader {
        VolumeHeader::new(volume(), 4096, 100, 1, 2).unwrap()
    }

    fn pointer(block: u64) -> MetadataPointer {
        MetadataPointer::new(block, 1).unwrap()
    }

    struct Backend {
        staged: usize,
        flushed: usize,
        verified: usize,
        replaced: usize,
    }

    unsafe impl ObjectIdAllocatorWriteBackend for Backend {
        type Error = ();

        fn stage_object_id_allocator(
            &mut self,
            _image: CowMetadataImage,
            _encoded: &[u8],
        ) -> Result<(), Self::Error> {
            self.staged += 1;
            Ok(())
        }

        fn flush_object_id_allocator(&mut self) -> Result<(), Self::Error> {
            self.flushed += 1;
            Ok(())
        }
    }

    unsafe impl AllocationWriteBackend for Backend {
        type Error = ();

        fn stage_allocation_image(
            &mut self,
            _image: CowMetadataImage,
            _encoded: &[u8],
        ) -> Result<(), Self::Error> {
            self.staged += 1;
            Ok(())
        }

        fn flush_allocation_image(&mut self) -> Result<(), Self::Error> {
            self.flushed += 1;
            Ok(())
        }
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
    fn canonical_allocator_round_trip_rejects_corruption_and_padding() {
        assert_eq!(
            ObjectIdAllocatorImage::build(header(), 4, Some(0), pointer(30)),
            Err(ObjectIdAllocatorError::InvalidImage)
        );
        let image = ObjectIdAllocatorImage::build(header(), 4, Some(10), pointer(30)).unwrap();
        let mut encoded = [0; 4096];
        image.encode(&mut encoded).unwrap();
        assert_eq!(
            ObjectIdAllocatorImage::decode(header(), 4, pointer(30), &encoded),
            Ok(image.clone())
        );
        encoded[40] ^= 1;
        assert_eq!(
            ObjectIdAllocatorImage::decode(header(), 4, pointer(30), &encoded),
            Err(ObjectIdAllocatorError::Corrupt)
        );
        image.encode(&mut encoded).unwrap();
        encoded[4095] = 1;
        let digest = image_digest(&encoded);
        encoded[DIGEST_OFFSET..OBJECT_ID_ALLOCATOR_HEADER_BYTES].copy_from_slice(&digest);
        assert_eq!(
            ObjectIdAllocatorImage::decode(header(), 4, pointer(30), &encoded),
            Err(ObjectIdAllocatorError::NonCanonical)
        );
    }

    #[test]
    fn reservation_stages_successor_and_activates_once_from_exact_receipt() {
        let active = ObjectIdAllocatorImage::build(header(), 5, Some(10), pointer(30)).unwrap();
        let mut encoded = [0; 4096];
        let mut backend = Backend {
            staged: 0,
            flushed: 0,
            verified: 0,
            replaced: 0,
        };
        let prepared = active
            .prepare_reservation(header(), pointer(31), &mut encoded, &mut backend)
            .unwrap();
        assert_eq!(prepared.allocated(), object(10));
        assert_eq!(prepared.generation(), 6);
        assert_eq!(
            prepared.metadata_image().digest(),
            complete_digest(&encoded)
        );
        assert_eq!(active.next_local(), Some(10));
        assert_eq!((backend.staged, backend.flushed), (1, 1));

        let mut transaction =
            StorageTransaction::<1, 1>::new(StorageTransactionId::new(30).unwrap(), 6).unwrap();
        transaction.admit_object_id_allocator(&prepared).unwrap();
        let active_superblock =
            Superblock::new(header(), 5, 4, object(1), pointer(10), pointer(20)).unwrap();
        let allocator_write = prepared.metadata_image().bind(6).unwrap();
        let plan = CowPublicationPlan::<3>::build(
            header(),
            1,
            active_superblock,
            object(1),
            pointer(40),
            pointer(41),
            &[
                CowMetadataWrite::new(pointer(40), 6, [1; 32]).unwrap(),
                CowMetadataWrite::new(pointer(41), 6, [2; 32]).unwrap(),
                allocator_write,
            ],
            &[pointer(10), pointer(20), pointer(30)],
        )
        .unwrap();
        let mut receipt = transaction.publish(&plan, &mut backend).unwrap();
        let (successor, allocated) = prepared.commit_transaction(&mut receipt).unwrap();
        assert_eq!(allocated, object(10));
        assert_eq!(successor.next_local(), Some(11));
        assert_eq!(receipt.remaining(), 0);
        assert_eq!((backend.verified, backend.replaced), (3, 1));
    }

    #[test]
    fn reservation_requires_exact_allocator_metadata_ownership() {
        let active_allocator =
            ObjectIdAllocatorImage::build(header(), 5, Some(10), pointer(30)).unwrap();
        let root = object(1);
        let active_allocation = AllocationImage::<4>::build(
            header(),
            5,
            pointer(20),
            &[
                AllocationRecord::new(root, 2, 10, 1, AllocationKind::ObjectMetadata).unwrap(),
                AllocationRecord::new(root, 5, 20, 1, AllocationKind::AllocationMetadata).unwrap(),
            ],
        )
        .unwrap();
        let mut allocator_encoded = [0; 4096];
        let mut allocation_encoded = [0; 4096];
        let mut backend = Backend {
            staged: 0,
            flushed: 0,
            verified: 0,
            replaced: 0,
        };
        let reservation = active_allocator
            .prepare_reservation(header(), pointer(31), &mut allocator_encoded, &mut backend)
            .unwrap();
        let exact = AllocationRecord::new(
            root,
            reservation.generation(),
            reservation.pointer().block(),
            reservation.pointer().blocks(),
            AllocationKind::ObjectIdAllocatorMetadata,
        )
        .unwrap();
        let prepared_allocation = active_allocation
            .prepare_successor(
                header(),
                root,
                pointer(50),
                &[AllocationChange::Allocate(exact)],
                &mut allocation_encoded,
                &mut backend,
            )
            .unwrap();
        assert!(reservation.allocation_owned_by(&prepared_allocation, root));
        assert!(!reservation.allocation_owned_by(&prepared_allocation, object(2)));

        let wrong_kind = AllocationRecord::new(
            root,
            reservation.generation(),
            32,
            1,
            AllocationKind::ObjectMetadata,
        )
        .unwrap();
        let wrong_allocation = active_allocation
            .prepare_successor(
                header(),
                root,
                pointer(51),
                &[AllocationChange::Allocate(wrong_kind)],
                &mut allocation_encoded,
                &mut backend,
            )
            .unwrap();
        assert!(!reservation.allocation_owned_by(&wrong_allocation, root));
    }

    #[test]
    fn maximum_identity_is_reserved_once_and_failures_preserve_active_state() {
        let active =
            ObjectIdAllocatorImage::build(header(), 8, Some(u64::MAX), pointer(30)).unwrap();
        let mut encoded = [0; 4096];
        let mut backend = Backend {
            staged: 0,
            flushed: 0,
            verified: 0,
            replaced: 0,
        };
        let prepared = active
            .prepare_reservation(header(), pointer(31), &mut encoded, &mut backend)
            .unwrap();
        assert_eq!(prepared.allocated(), object(u64::MAX));
        assert_eq!(active.next_local(), Some(u64::MAX));
        assert_eq!(
            ObjectIdAllocatorImage::decode(header(), 9, pointer(31), &encoded)
                .unwrap()
                .next_local(),
            None
        );
        let exhausted = ObjectIdAllocatorImage::build(header(), 9, None, pointer(31)).unwrap();
        assert!(matches!(
            exhausted.prepare_reservation(header(), pointer(32), &mut encoded, &mut backend),
            Err(ObjectIdAllocatorUpdateError::Planning(
                ObjectIdAllocatorError::IdentityExhausted
            ))
        ));
        let generation_exhausted =
            ObjectIdAllocatorImage::build(header(), u64::MAX, Some(12), pointer(32)).unwrap();
        assert!(matches!(
            generation_exhausted.prepare_reservation(
                header(),
                pointer(33),
                &mut encoded,
                &mut backend
            ),
            Err(ObjectIdAllocatorUpdateError::Planning(
                ObjectIdAllocatorError::GenerationExhausted
            ))
        ));
        assert!(matches!(
            active.prepare_reservation(header(), pointer(30), &mut encoded, &mut backend),
            Err(ObjectIdAllocatorUpdateError::Planning(
                ObjectIdAllocatorError::InvalidImage
            ))
        ));
        assert_eq!(backend.staged, 1);
    }
}
