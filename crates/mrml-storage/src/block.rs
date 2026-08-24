use mrml_crypto::Sha3_256;

use crate::{
    AllocationWriteBackend, CowMetadataImage, CowMetadataWrite, CowPublicationBackend,
    DirectoryWriteBackend, InitialFileWriteBackend, MetadataPointer, ObjectIdAllocatorWriteBackend,
    RecoveryMetadataBackend, SUPERBLOCK_BYTES, Superblock, VolumeHeader,
};

/// Exact block-service operations used by the native storage metadata adapter.
///
/// # Safety
///
/// Reads and writes must transfer the complete supplied buffer at the exact
/// block, without redirection, shortening, stale completion, or hidden caching
/// across `flush`. `replace_superblock` must replace the complete canonical
/// record atomically or return an error. The caller holds exclusive access for
/// the complete validation or publication session.
pub unsafe trait StorageBlockDevice {
    type Error;

    fn read_blocks(&mut self, block: u64, output: &mut [u8]) -> Result<(), Self::Error>;
    fn write_blocks(&mut self, block: u64, input: &[u8]) -> Result<(), Self::Error>;
    fn flush(&mut self) -> Result<(), Self::Error>;
    fn replace_superblock(
        &mut self,
        block: u64,
        encoded: &[u8; SUPERBLOCK_BYTES],
    ) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockVolumeError<E> {
    InvalidScratch,
    InvalidRange,
    InvalidImage,
    DigestMismatch,
    ActiveSuperblock,
    InvalidSuperblock,
    InvalidState,
    Device(E),
}

/// Bounded adapter from canonical MRML metadata operations to exact block I/O.
pub struct BlockVolume<'a, D: StorageBlockDevice> {
    header: VolumeHeader,
    active_superblock: u64,
    pending_superblock: Option<u64>,
    poisoned: bool,
    device: D,
    scratch: &'a mut [u8],
}

impl<'a, D: StorageBlockDevice> BlockVolume<'a, D> {
    pub fn new(
        header: VolumeHeader,
        active_superblock: u64,
        device: D,
        scratch: &'a mut [u8],
    ) -> Result<Self, BlockVolumeError<D::Error>> {
        if scratch.len() < header.block_size() as usize {
            return Err(BlockVolumeError::InvalidScratch);
        }
        if active_superblock != header.primary_superblock()
            && active_superblock != header.secondary_superblock()
        {
            return Err(BlockVolumeError::ActiveSuperblock);
        }
        Ok(Self {
            header,
            active_superblock,
            pending_superblock: None,
            poisoned: false,
            device,
            scratch,
        })
    }

    pub const fn active_superblock(&self) -> u64 {
        self.active_superblock
    }

    pub const fn is_fail_stopped(&self) -> bool {
        self.poisoned
    }

    pub const fn device(&self) -> &D {
        &self.device
    }

    pub fn into_device(self) -> D {
        self.device
    }

    fn flush_staged(&mut self) -> Result<(), BlockVolumeError<D::Error>> {
        if self.poisoned || self.pending_superblock.is_some() {
            return Err(BlockVolumeError::InvalidState);
        }
        self.device.flush().map_err(BlockVolumeError::Device)
    }

    fn image_bytes(&self, pointer: MetadataPointer) -> Result<usize, BlockVolumeError<D::Error>> {
        if self.poisoned || self.pending_superblock.is_some() {
            return Err(BlockVolumeError::InvalidState);
        }
        let end = pointer
            .block()
            .checked_add(u64::from(pointer.blocks()))
            .ok_or(BlockVolumeError::InvalidRange)?;
        if end > self.header.block_count() {
            return Err(BlockVolumeError::InvalidRange);
        }
        usize::try_from(
            u64::from(self.header.block_size())
                .checked_mul(u64::from(pointer.blocks()))
                .ok_or(BlockVolumeError::InvalidRange)?,
        )
        .map_err(|_| BlockVolumeError::InvalidRange)
    }

    fn stage_complete(
        &mut self,
        image: CowMetadataImage,
        encoded: &[u8],
    ) -> Result<(), BlockVolumeError<D::Error>> {
        if encoded.len() != self.image_bytes(image.pointer())? || digest(encoded) != image.digest()
        {
            return Err(BlockVolumeError::InvalidImage);
        }
        self.device
            .write_blocks(image.pointer().block(), encoded)
            .map_err(BlockVolumeError::Device)?;
        self.verify(image.pointer(), image.digest())
    }

    fn stage_prefix(
        &mut self,
        image: CowMetadataImage,
        encoded: &[u8],
    ) -> Result<(), BlockVolumeError<D::Error>> {
        let image_bytes = self.image_bytes(image.pointer())?;
        let block_size = self.header.block_size() as usize;
        if encoded.len() > block_size || encoded.len() > image_bytes {
            return Err(BlockVolumeError::InvalidImage);
        }
        for offset in (0..image_bytes).step_by(block_size) {
            let block = &mut self.scratch[..block_size];
            block.fill(0);
            if offset == 0 {
                block[..encoded.len()].copy_from_slice(encoded);
            }
            let block_offset =
                u64::try_from(offset / block_size).map_err(|_| BlockVolumeError::InvalidRange)?;
            self.device
                .write_blocks(image.pointer().block() + block_offset, block)
                .map_err(BlockVolumeError::Device)?;
        }
        self.verify(image.pointer(), image.digest())
    }

    fn verify(
        &mut self,
        pointer: MetadataPointer,
        expected: [u8; 32],
    ) -> Result<(), BlockVolumeError<D::Error>> {
        self.image_bytes(pointer)?;
        let block_size = self.header.block_size() as usize;
        let mut hasher = Sha3_256::new();
        for offset in 0..u64::from(pointer.blocks()) {
            let block = &mut self.scratch[..block_size];
            self.device
                .read_blocks(pointer.block() + offset, block)
                .map_err(BlockVolumeError::Device)?;
            hasher.update(block);
        }
        if hasher.finalize() != expected {
            return Err(BlockVolumeError::DigestMismatch);
        }
        Ok(())
    }
}

unsafe impl<D: StorageBlockDevice> CowPublicationBackend for BlockVolume<'_, D> {
    type Error = BlockVolumeError<D::Error>;

    fn verify_new_metadata(&mut self, write: CowMetadataWrite) -> Result<(), Self::Error> {
        self.verify(write.pointer(), write.digest())
    }

    fn flush_new_metadata(&mut self) -> Result<(), Self::Error> {
        self.flush_staged()
    }

    fn replace_superblock(
        &mut self,
        block: u64,
        encoded: &[u8; SUPERBLOCK_BYTES],
    ) -> Result<(), Self::Error> {
        if block == self.active_superblock {
            return Err(BlockVolumeError::ActiveSuperblock);
        }
        if block != self.header.primary_superblock() && block != self.header.secondary_superblock()
        {
            return Err(BlockVolumeError::InvalidSuperblock);
        }
        Superblock::decode(encoded, self.header)
            .map_err(|_| BlockVolumeError::InvalidSuperblock)?;
        if self.poisoned || self.pending_superblock.is_some() {
            return Err(BlockVolumeError::InvalidState);
        }
        if let Err(error) = self.device.replace_superblock(block, encoded) {
            self.poisoned = true;
            return Err(BlockVolumeError::Device(error));
        }
        self.pending_superblock = Some(block);
        Ok(())
    }

    fn flush_superblock(&mut self) -> Result<(), Self::Error> {
        if self.poisoned {
            return Err(BlockVolumeError::InvalidState);
        }
        let pending = self
            .pending_superblock
            .ok_or(BlockVolumeError::InvalidState)?;
        if let Err(error) = self.device.flush() {
            self.poisoned = true;
            return Err(BlockVolumeError::Device(error));
        }
        self.active_superblock = pending;
        self.pending_superblock = None;
        Ok(())
    }
}

unsafe impl<D: StorageBlockDevice> RecoveryMetadataBackend for BlockVolume<'_, D> {
    type Error = BlockVolumeError<D::Error>;

    fn read_metadata(
        &mut self,
        pointer: MetadataPointer,
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        if output.len() != self.image_bytes(pointer)? {
            return Err(BlockVolumeError::InvalidRange);
        }
        self.device
            .read_blocks(pointer.block(), output)
            .map_err(BlockVolumeError::Device)
    }
}

unsafe impl<D: StorageBlockDevice> AllocationWriteBackend for BlockVolume<'_, D> {
    type Error = BlockVolumeError<D::Error>;

    fn stage_allocation_image(
        &mut self,
        image: CowMetadataImage,
        encoded: &[u8],
    ) -> Result<(), Self::Error> {
        self.stage_complete(image, encoded)
    }

    fn flush_allocation_image(&mut self) -> Result<(), Self::Error> {
        self.flush_staged()
    }
}

unsafe impl<D: StorageBlockDevice> ObjectIdAllocatorWriteBackend for BlockVolume<'_, D> {
    type Error = BlockVolumeError<D::Error>;

    fn stage_object_id_allocator(
        &mut self,
        image: CowMetadataImage,
        encoded: &[u8],
    ) -> Result<(), Self::Error> {
        self.stage_complete(image, encoded)
    }

    fn flush_object_id_allocator(&mut self) -> Result<(), Self::Error> {
        self.flush_staged()
    }
}

unsafe impl<D: StorageBlockDevice> DirectoryWriteBackend for BlockVolume<'_, D> {
    type Error = BlockVolumeError<D::Error>;

    fn stage_directory_metadata(
        &mut self,
        image: CowMetadataImage,
        encoded: &[u8; crate::DIRECTORY_METADATA_BYTES],
    ) -> Result<(), Self::Error> {
        self.stage_prefix(image, encoded)
    }

    fn stage_directory_entries(
        &mut self,
        image: CowMetadataImage,
        encoded: &[u8],
    ) -> Result<(), Self::Error> {
        self.stage_complete(image, encoded)
    }

    fn flush_directory_update(&mut self) -> Result<(), Self::Error> {
        self.flush_staged()
    }
}

unsafe impl<D: StorageBlockDevice> InitialFileWriteBackend for BlockVolume<'_, D> {
    type Error = BlockVolumeError<D::Error>;

    fn stage_initial_file_metadata(
        &mut self,
        image: CowMetadataImage,
        encoded: &[u8; crate::FILE_METADATA_BYTES],
    ) -> Result<(), Self::Error> {
        self.stage_prefix(image, encoded)
    }

    fn stage_initial_file_extents(
        &mut self,
        image: CowMetadataImage,
        encoded: &[u8],
    ) -> Result<(), Self::Error> {
        self.stage_complete(image, encoded)
    }

    fn flush_initial_file(&mut self) -> Result<(), Self::Error> {
        self.flush_staged()
    }
}

fn digest(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(input);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DirectoryWriteBackend, StorageObjectId, VolumeId};

    const BLOCK_SIZE: usize = 4096;
    const BLOCKS: usize = 32;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum DeviceError {
        Range,
        Flush,
    }

    struct Device {
        bytes: [u8; BLOCK_SIZE * BLOCKS],
        writes: usize,
        reads: usize,
        flushes: usize,
        replacements: usize,
        fail_flush: bool,
        corrupt_reads: bool,
    }

    impl Device {
        fn new() -> Self {
            Self {
                bytes: [0; BLOCK_SIZE * BLOCKS],
                writes: 0,
                reads: 0,
                flushes: 0,
                replacements: 0,
                fail_flush: false,
                corrupt_reads: false,
            }
        }

        fn range(&self, block: u64, length: usize) -> Result<core::ops::Range<usize>, DeviceError> {
            if length == 0 || !length.is_multiple_of(BLOCK_SIZE) {
                return Err(DeviceError::Range);
            }
            let start = usize::try_from(block)
                .ok()
                .and_then(|value| value.checked_mul(BLOCK_SIZE))
                .ok_or(DeviceError::Range)?;
            let end = start.checked_add(length).ok_or(DeviceError::Range)?;
            if end > self.bytes.len() {
                return Err(DeviceError::Range);
            }
            Ok(start..end)
        }
    }

    unsafe impl StorageBlockDevice for Device {
        type Error = DeviceError;

        fn read_blocks(&mut self, block: u64, output: &mut [u8]) -> Result<(), Self::Error> {
            let range = self.range(block, output.len())?;
            output.copy_from_slice(&self.bytes[range]);
            if self.corrupt_reads {
                output[0] ^= 1;
            }
            self.reads += 1;
            Ok(())
        }

        fn write_blocks(&mut self, block: u64, input: &[u8]) -> Result<(), Self::Error> {
            let range = self.range(block, input.len())?;
            self.bytes[range].copy_from_slice(input);
            self.writes += 1;
            Ok(())
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
            self.flushes += 1;
            if self.fail_flush {
                return Err(DeviceError::Flush);
            }
            Ok(())
        }

        fn replace_superblock(
            &mut self,
            block: u64,
            encoded: &[u8; SUPERBLOCK_BYTES],
        ) -> Result<(), Self::Error> {
            let range = self.range(block, BLOCK_SIZE)?;
            self.bytes[range.clone()].fill(0);
            self.bytes[range.start..range.start + SUPERBLOCK_BYTES].copy_from_slice(encoded);
            self.replacements += 1;
            Ok(())
        }
    }

    fn header() -> VolumeHeader {
        VolumeHeader::new(
            VolumeId::new([7; 16]).unwrap(),
            BLOCK_SIZE as u32,
            BLOCKS as u64,
            1,
            2,
        )
        .unwrap()
    }

    fn pointer(block: u64, blocks: u32) -> MetadataPointer {
        MetadataPointer::new(block, blocks).unwrap()
    }

    #[test]
    fn exact_metadata_staging_and_recovery_reads_share_one_adapter() {
        let mut scratch = [0xa5; BLOCK_SIZE];
        let mut volume = BlockVolume::new(header(), 1, Device::new(), &mut scratch).unwrap();

        let prefix = [0x5a; crate::DIRECTORY_METADATA_BYTES];
        let mut canonical = [0; BLOCK_SIZE * 2];
        canonical[..prefix.len()].copy_from_slice(&prefix);
        let image = CowMetadataImage::new(pointer(8, 2), digest(&canonical));
        DirectoryWriteBackend::stage_directory_metadata(&mut volume, image, &prefix).unwrap();
        DirectoryWriteBackend::flush_directory_update(&mut volume).unwrap();

        assert_eq!((volume.device().writes, volume.device().reads), (2, 2));
        assert_eq!(volume.device().flushes, 1);
        assert_eq!(
            &volume.device().bytes[8 * BLOCK_SIZE..10 * BLOCK_SIZE],
            &canonical
        );

        let mut recovered = [0; BLOCK_SIZE * 2];
        RecoveryMetadataBackend::read_metadata(&mut volume, pointer(8, 2), &mut recovered).unwrap();
        assert_eq!(recovered, canonical);
        let mut short = [0; BLOCK_SIZE];
        assert_eq!(
            RecoveryMetadataBackend::read_metadata(&mut volume, pointer(8, 2), &mut short),
            Err(BlockVolumeError::InvalidRange)
        );
    }

    #[test]
    fn publication_verifies_bytes_and_replaces_only_inactive_superblock() {
        let mut scratch = [0; BLOCK_SIZE];
        let mut device = Device::new();
        let metadata = [0x3c; BLOCK_SIZE];
        device.bytes[6 * BLOCK_SIZE..7 * BLOCK_SIZE].copy_from_slice(&metadata);
        let mut volume = BlockVolume::new(header(), 1, device, &mut scratch).unwrap();

        let write = CowMetadataWrite::new(pointer(6, 1), 4, digest(&metadata)).unwrap();
        CowPublicationBackend::verify_new_metadata(&mut volume, write).unwrap();
        CowPublicationBackend::flush_new_metadata(&mut volume).unwrap();
        let next = Superblock::new(
            header(),
            4,
            3,
            StorageObjectId::new(header().volume(), 1).unwrap(),
            pointer(6, 1),
            pointer(7, 1),
        )
        .unwrap();
        let mut encoded = [0; SUPERBLOCK_BYTES];
        next.encode(&mut encoded);
        assert_eq!(
            CowPublicationBackend::replace_superblock(&mut volume, 1, &encoded),
            Err(BlockVolumeError::ActiveSuperblock)
        );
        CowPublicationBackend::replace_superblock(&mut volume, 2, &encoded).unwrap();
        assert_eq!(volume.active_superblock(), 1);
        CowPublicationBackend::flush_superblock(&mut volume).unwrap();
        assert_eq!(volume.active_superblock(), 2);
        assert_eq!(
            (volume.device().replacements, volume.device().flushes),
            (1, 2)
        );
    }

    #[test]
    fn malformed_images_corruption_and_flush_failure_fail_closed() {
        let mut scratch = [0; BLOCK_SIZE];
        let mut volume = BlockVolume::new(header(), 1, Device::new(), &mut scratch).unwrap();
        let encoded = [9; BLOCK_SIZE];
        let wrong = CowMetadataImage::new(pointer(4, 1), [0; 32]);
        assert_eq!(
            AllocationWriteBackend::stage_allocation_image(&mut volume, wrong, &encoded),
            Err(BlockVolumeError::InvalidImage)
        );
        assert_eq!(volume.device().writes, 0);

        let image = CowMetadataImage::new(pointer(4, 1), digest(&encoded));
        let mut corrupt_device = Device::new();
        corrupt_device.corrupt_reads = true;
        let mut corrupt_scratch = [0; BLOCK_SIZE];
        let mut volume =
            BlockVolume::new(header(), 1, corrupt_device, &mut corrupt_scratch).unwrap();
        assert_eq!(
            AllocationWriteBackend::stage_allocation_image(&mut volume, image, &encoded),
            Err(BlockVolumeError::DigestMismatch)
        );
        let mut failing_device = Device::new();
        failing_device.fail_flush = true;
        let mut failing_scratch = [0; BLOCK_SIZE];
        let mut volume =
            BlockVolume::new(header(), 1, failing_device, &mut failing_scratch).unwrap();
        assert_eq!(
            AllocationWriteBackend::flush_allocation_image(&mut volume),
            Err(BlockVolumeError::Device(DeviceError::Flush))
        );
    }

    #[test]
    fn uncertain_superblock_flush_poisoning_is_permanent() {
        let mut scratch = [0; BLOCK_SIZE];
        let mut device = Device::new();
        device.fail_flush = true;
        let mut volume = BlockVolume::new(header(), 1, device, &mut scratch).unwrap();
        let next = Superblock::new(
            header(),
            2,
            1,
            StorageObjectId::new(header().volume(), 1).unwrap(),
            pointer(6, 1),
            pointer(7, 1),
        )
        .unwrap();
        let mut encoded = [0; SUPERBLOCK_BYTES];
        next.encode(&mut encoded);
        CowPublicationBackend::replace_superblock(&mut volume, 2, &encoded).unwrap();
        assert_eq!(
            CowPublicationBackend::flush_superblock(&mut volume),
            Err(BlockVolumeError::Device(DeviceError::Flush))
        );
        assert!(volume.is_fail_stopped());
        assert_eq!(
            RecoveryMetadataBackend::read_metadata(
                &mut volume,
                pointer(6, 1),
                &mut [0; BLOCK_SIZE]
            ),
            Err(BlockVolumeError::InvalidState)
        );
        assert_eq!(
            CowPublicationBackend::flush_superblock(&mut volume),
            Err(BlockVolumeError::InvalidState)
        );
    }

    #[test]
    fn constructor_rejects_undersized_scratch_and_unknown_active_slot() {
        let mut short = [0; BLOCK_SIZE - 1];
        assert!(matches!(
            BlockVolume::new(header(), 1, Device::new(), &mut short),
            Err(BlockVolumeError::InvalidScratch)
        ));
        let mut scratch = [0; BLOCK_SIZE];
        assert!(matches!(
            BlockVolume::new(header(), 3, Device::new(), &mut scratch),
            Err(BlockVolumeError::ActiveSuperblock)
        ));
    }
}
