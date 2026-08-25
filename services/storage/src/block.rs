use mrml_crypto::Sha3_256;

use crate::{
    AllocationWriteBackend, CowMetadataImage, CowMetadataWrite, CowPublicationBackend,
    DirectoryWriteBackend, ExtentKind, ExtentRecord, FileReadBackend, FileState, FileWriteBackend,
    InitialFileWriteBackend, MetadataPointer, ObjectIdAllocatorWriteBackend,
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

    fn ensure_open(&self) -> Result<(), BlockVolumeError<D::Error>> {
        if self.poisoned || self.pending_superblock.is_some() {
            return Err(BlockVolumeError::InvalidState);
        }
        Ok(())
    }

    fn read_block(
        &mut self,
        block: u64,
        output: &mut [u8],
    ) -> Result<(), BlockVolumeError<D::Error>> {
        self.ensure_open()?;
        if output.len() != self.header.block_size() as usize || block >= self.header.block_count() {
            return Err(BlockVolumeError::InvalidRange);
        }
        self.device
            .read_blocks(block, output)
            .map_err(BlockVolumeError::Device)
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

unsafe impl<D: StorageBlockDevice> FileReadBackend for BlockVolume<'_, D> {
    type Error = BlockVolumeError<D::Error>;

    fn read_verified_extent(
        &mut self,
        record: ExtentRecord,
        byte_offset: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        self.ensure_open()?;
        let physical = record
            .physical_block()
            .ok_or(BlockVolumeError::InvalidImage)?;
        let end_block = physical
            .checked_add(u64::from(record.block_count()))
            .ok_or(BlockVolumeError::InvalidRange)?;
        if record.kind() != ExtentKind::Data || end_block > self.header.block_count() {
            return Err(BlockVolumeError::InvalidRange);
        }
        let extent_bytes = u64::from(self.header.block_size())
            .checked_mul(u64::from(record.block_count()))
            .ok_or(BlockVolumeError::InvalidRange)?;
        let output_len = u64::try_from(output.len()).map_err(|_| BlockVolumeError::InvalidRange)?;
        let requested_end = byte_offset
            .checked_add(output_len)
            .ok_or(BlockVolumeError::InvalidRange)?;
        if requested_end > extent_bytes {
            return Err(BlockVolumeError::InvalidRange);
        }

        let block_size = self.header.block_size() as usize;
        let mut hasher = Sha3_256::new();
        for offset in 0..u64::from(record.block_count()) {
            let block = &mut self.scratch[..block_size];
            self.device
                .read_blocks(physical + offset, block)
                .map_err(BlockVolumeError::Device)?;
            hasher.update(block);
        }
        if hasher.finalize() != record.content_digest() {
            return Err(BlockVolumeError::DigestMismatch);
        }

        let request_start = byte_offset;
        let mut copied = 0usize;
        for offset in 0..u64::from(record.block_count()) {
            let block_start = offset * u64::from(self.header.block_size());
            let block_end = block_start + u64::from(self.header.block_size());
            let copy_start = block_start.max(request_start);
            let copy_end = block_end.min(requested_end);
            if copy_start >= copy_end {
                continue;
            }
            let block = &mut self.scratch[..block_size];
            self.device
                .read_blocks(physical + offset, block)
                .map_err(BlockVolumeError::Device)?;
            let source_start = usize::try_from(copy_start - block_start)
                .map_err(|_| BlockVolumeError::InvalidRange)?;
            let count = usize::try_from(copy_end - copy_start)
                .map_err(|_| BlockVolumeError::InvalidRange)?;
            output[copied..copied + count]
                .copy_from_slice(&block[source_start..source_start + count]);
            copied += count;
        }
        if copied != output.len() {
            output.fill(0);
            return Err(BlockVolumeError::InvalidRange);
        }
        Ok(())
    }
}

/// One bounded COW file-data session bound to an exact predecessor state.
pub struct BlockFileSession<'a, 'b, D: StorageBlockDevice, const OLD: usize, const NEXT: usize> {
    volume: &'a mut BlockVolume<'b, D>,
    predecessor: &'a FileState<OLD>,
    scratch: &'a mut [u8],
    staged: [Option<ExtentRecord>; NEXT],
    staged_count: usize,
    next_generation: Option<u64>,
    next_length: Option<u64>,
    flushed: bool,
}

impl<'a, 'b, D: StorageBlockDevice, const OLD: usize, const NEXT: usize>
    BlockFileSession<'a, 'b, D, OLD, NEXT>
{
    pub fn new(
        volume: &'a mut BlockVolume<'b, D>,
        predecessor: &'a FileState<OLD>,
        scratch: &'a mut [u8],
    ) -> Result<Self, BlockVolumeError<D::Error>> {
        if scratch.len() < volume.header.block_size() as usize {
            return Err(BlockVolumeError::InvalidScratch);
        }
        volume.ensure_open()?;
        if predecessor.object().volume() != volume.header.volume()
            || predecessor.extents().block_size() != volume.header.block_size()
        {
            return Err(BlockVolumeError::InvalidImage);
        }
        Ok(Self {
            volume,
            predecessor,
            scratch,
            staged: [None; NEXT],
            staged_count: 0,
            next_generation: None,
            next_length: None,
            flushed: false,
        })
    }

    pub const fn staged_count(&self) -> usize {
        self.staged_count
    }

    pub const fn is_flushed(&self) -> bool {
        self.flushed
    }

    fn validate_next(
        &self,
        next: ExtentRecord,
        new_length: u64,
    ) -> Result<(), BlockVolumeError<D::Error>> {
        let generation = self
            .predecessor
            .generation()
            .checked_add(1)
            .ok_or(BlockVolumeError::InvalidImage)?;
        if self.flushed
            || next.kind() != ExtentKind::Data
            || next.file() != self.predecessor.object()
            || next.metadata_generation() != generation
            || new_length == 0
        {
            return Err(BlockVolumeError::InvalidImage);
        }
        if self
            .next_generation
            .is_some_and(|current| current != generation)
            || self
                .next_length
                .is_some_and(|current| current != new_length)
        {
            return Err(BlockVolumeError::InvalidImage);
        }
        let logical_end = next
            .logical_block()
            .checked_add(u64::from(next.block_count()))
            .ok_or(BlockVolumeError::InvalidRange)?;
        let required_blocks = new_length.div_ceil(u64::from(self.volume.header.block_size()));
        if logical_end > required_blocks {
            return Err(BlockVolumeError::InvalidRange);
        }
        let physical = next
            .physical_block()
            .ok_or(BlockVolumeError::InvalidImage)?;
        let physical_end = physical
            .checked_add(u64::from(next.block_count()))
            .ok_or(BlockVolumeError::InvalidRange)?;
        if physical == 0
            || physical_end > self.volume.header.block_count()
            || (physical <= self.volume.header.primary_superblock()
                && self.volume.header.primary_superblock() < physical_end)
            || (physical <= self.volume.header.secondary_superblock()
                && self.volume.header.secondary_superblock() < physical_end)
        {
            return Err(BlockVolumeError::InvalidRange);
        }
        for index in 0..self.predecessor.extents().len() {
            let old = self
                .predecessor
                .extents()
                .record(index)
                .ok_or(BlockVolumeError::InvalidImage)?;
            if old.kind() == ExtentKind::Data {
                let old_start = old.physical_block().ok_or(BlockVolumeError::InvalidImage)?;
                let old_end = old_start + u64::from(old.block_count());
                if physical < old_end && old_start < physical_end {
                    return Err(BlockVolumeError::InvalidRange);
                }
            }
        }
        if let Some(previous) = self
            .staged_count
            .checked_sub(1)
            .and_then(|index| self.staged[index])
        {
            let previous_end = previous.logical_block() + u64::from(previous.block_count());
            if next.logical_block() < previous_end {
                return Err(BlockVolumeError::InvalidImage);
            }
        }
        for staged in self.staged[..self.staged_count].iter().flatten().copied() {
            let staged_start = staged
                .physical_block()
                .ok_or(BlockVolumeError::InvalidImage)?;
            let staged_end = staged_start + u64::from(staged.block_count());
            if physical < staged_end && staged_start < physical_end {
                return Err(BlockVolumeError::InvalidRange);
            }
        }
        Ok(())
    }

    fn construct_block(
        &mut self,
        logical_block: u64,
        new_length: u64,
        patch_offset: u64,
        patch: &[u8],
    ) -> Result<(), BlockVolumeError<D::Error>> {
        let block_size = self.volume.header.block_size() as usize;
        let block_start = logical_block
            .checked_mul(u64::from(self.volume.header.block_size()))
            .ok_or(BlockVolumeError::InvalidRange)?;
        let block_end = block_start
            .checked_add(u64::from(self.volume.header.block_size()))
            .ok_or(BlockVolumeError::InvalidRange)?;
        let output = &mut self.scratch[..block_size];
        output.fill(0);

        if block_start < self.predecessor.length() {
            let old_end = block_end.min(self.predecessor.length());
            let old_count = usize::try_from(old_end - block_start)
                .map_err(|_| BlockVolumeError::InvalidRange)?;
            let old = self
                .predecessor
                .extents()
                .record_for(logical_block)
                .map_err(|_| BlockVolumeError::InvalidImage)?;
            if old.kind() == ExtentKind::Data {
                let byte_offset = logical_block
                    .checked_sub(old.logical_block())
                    .and_then(|value| value.checked_mul(u64::from(self.volume.header.block_size())))
                    .ok_or(BlockVolumeError::InvalidRange)?;
                FileReadBackend::read_verified_extent(
                    self.volume,
                    old,
                    byte_offset,
                    &mut output[..old_count],
                )?;
            }
        }

        let patch_end = patch_offset
            .checked_add(u64::try_from(patch.len()).map_err(|_| BlockVolumeError::InvalidRange)?)
            .ok_or(BlockVolumeError::InvalidRange)?;
        let copy_start = block_start.max(patch_offset);
        let copy_end = block_end.min(patch_end).min(new_length);
        if copy_start < copy_end {
            let destination = usize::try_from(copy_start - block_start)
                .map_err(|_| BlockVolumeError::InvalidRange)?;
            let source = usize::try_from(copy_start - patch_offset)
                .map_err(|_| BlockVolumeError::InvalidRange)?;
            let count = usize::try_from(copy_end - copy_start)
                .map_err(|_| BlockVolumeError::InvalidRange)?;
            output[destination..destination + count]
                .copy_from_slice(&patch[source..source + count]);
        }
        if new_length < block_end && new_length > block_start {
            let valid = usize::try_from(new_length - block_start)
                .map_err(|_| BlockVolumeError::InvalidRange)?;
            output[valid..].fill(0);
        }
        Ok(())
    }

    fn verify_staged_extent(
        &mut self,
        record: ExtentRecord,
    ) -> Result<(), BlockVolumeError<D::Error>> {
        let physical = record
            .physical_block()
            .ok_or(BlockVolumeError::InvalidImage)?;
        let block_size = self.volume.header.block_size() as usize;
        let mut hasher = Sha3_256::new();
        for offset in 0..u64::from(record.block_count()) {
            let output = &mut self.scratch[..block_size];
            self.volume.read_block(physical + offset, output)?;
            hasher.update(output);
        }
        if hasher.finalize() != record.content_digest() {
            return Err(BlockVolumeError::DigestMismatch);
        }
        Ok(())
    }
}

unsafe impl<D: StorageBlockDevice, const OLD: usize, const NEXT: usize> FileWriteBackend
    for BlockFileSession<'_, '_, D, OLD, NEXT>
{
    type Error = BlockVolumeError<D::Error>;

    fn stage_new_extent(
        &mut self,
        file: crate::StorageObjectId,
        old_generation: u64,
        old_length: u64,
        next: ExtentRecord,
        new_length: u64,
        patch_offset: u64,
        patch: &[u8],
    ) -> Result<(), Self::Error> {
        if file != self.predecessor.object()
            || old_generation != self.predecessor.generation()
            || old_length != self.predecessor.length()
            || self.staged_count == NEXT
        {
            return Err(BlockVolumeError::InvalidImage);
        }
        self.validate_next(next, new_length)?;
        let mut expected = Sha3_256::new();
        for offset in 0..u64::from(next.block_count()) {
            self.construct_block(
                next.logical_block() + offset,
                new_length,
                patch_offset,
                patch,
            )?;
            expected.update(&self.scratch[..self.volume.header.block_size() as usize]);
        }
        if expected.finalize() != next.content_digest() {
            return Err(BlockVolumeError::DigestMismatch);
        }
        let physical = next
            .physical_block()
            .ok_or(BlockVolumeError::InvalidImage)?;
        let block_size = self.volume.header.block_size() as usize;
        for offset in 0..u64::from(next.block_count()) {
            self.construct_block(
                next.logical_block() + offset,
                new_length,
                patch_offset,
                patch,
            )?;
            self.volume
                .device
                .write_blocks(physical + offset, &self.scratch[..block_size])
                .map_err(BlockVolumeError::Device)?;
        }
        self.verify_staged_extent(next)?;
        self.staged[self.staged_count] = Some(next);
        self.staged_count += 1;
        self.next_generation = Some(next.metadata_generation());
        self.next_length = Some(new_length);
        Ok(())
    }

    fn flush_new_file_data(
        &mut self,
        file: crate::StorageObjectId,
        generation: u64,
        length: u64,
        content_digest: [u8; 32],
    ) -> Result<(), Self::Error> {
        if self.flushed
            || file != self.predecessor.object()
            || generation != self.predecessor.generation().checked_add(1).unwrap_or(0)
            || self
                .next_generation
                .is_some_and(|current| current != generation)
            || self.next_length.is_some_and(|current| current != length)
        {
            return Err(BlockVolumeError::InvalidState);
        }
        let block_size = self.volume.header.block_size() as usize;
        let logical_blocks = length.div_ceil(u64::from(self.volume.header.block_size()));
        let mut hasher = Sha3_256::new();
        let mut staged_index = 0usize;
        for logical in 0..logical_blocks {
            while staged_index < self.staged_count {
                let record = self.staged[staged_index].ok_or(BlockVolumeError::InvalidState)?;
                if logical < record.logical_block() + u64::from(record.block_count()) {
                    break;
                }
                staged_index += 1;
            }
            let output = &mut self.scratch[..block_size];
            output.fill(0);
            if let Some(record) = self.staged.get(staged_index).copied().flatten()
                && logical >= record.logical_block()
                && logical < record.logical_block() + u64::from(record.block_count())
            {
                let physical = record
                    .physical_block()
                    .ok_or(BlockVolumeError::InvalidImage)?
                    + (logical - record.logical_block());
                self.volume.read_block(physical, output)?;
            }
            let start = logical * u64::from(self.volume.header.block_size());
            let count =
                usize::try_from((length - start).min(u64::from(self.volume.header.block_size())))
                    .map_err(|_| BlockVolumeError::InvalidRange)?;
            hasher.update(&output[..count]);
        }
        if hasher.finalize() != content_digest {
            return Err(BlockVolumeError::DigestMismatch);
        }
        self.volume.flush_staged()?;
        self.flushed = true;
        Ok(())
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
    use crate::{
        DirectoryWriteBackend, ExtentMap, FileMetadata, StorageAuthorityTable, StorageObjectId,
        StorageObjectKind, StoragePrincipal, StorageRights, VolumeId,
    };

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

    fn object(local: u64) -> StorageObjectId {
        StorageObjectId::new(header().volume(), local).unwrap()
    }

    fn principal() -> StoragePrincipal {
        StoragePrincipal::new(17).unwrap()
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

    #[test]
    fn file_reads_verify_the_complete_extent_before_copying() {
        let mut device = Device::new();
        device.bytes[10 * BLOCK_SIZE..11 * BLOCK_SIZE].fill(b'A');
        device.bytes[11 * BLOCK_SIZE..12 * BLOCK_SIZE].fill(b'B');
        let extent_digest = digest(&device.bytes[10 * BLOCK_SIZE..12 * BLOCK_SIZE]);
        let record = ExtentRecord::data(object(9), 3, 0, 2, 10, extent_digest).unwrap();
        let map = ExtentMap::<1>::build(header(), object(9), 3, (2 * BLOCK_SIZE) as u64, &[record])
            .unwrap();
        let state = FileState::new(object(9), 3, (2 * BLOCK_SIZE) as u64, map).unwrap();
        let mut authorities = StorageAuthorityTable::<2>::new();
        let handle = authorities
            .insert(
                object(9),
                StorageObjectKind::File,
                StorageRights::READ,
                principal(),
            )
            .unwrap();
        let mut scratch = [0; BLOCK_SIZE];
        let mut volume = BlockVolume::new(header(), 1, device, &mut scratch).unwrap();
        let mut output = [0; 8];
        assert_eq!(
            state
                .read(
                    &authorities,
                    handle,
                    principal(),
                    (BLOCK_SIZE - 4) as u64,
                    &mut output,
                    &mut volume,
                )
                .unwrap(),
            8
        );
        assert_eq!(&output, b"AAAABBBB");
        assert_eq!(volume.device().reads, 4);

        let mut corrupted = volume.into_device();
        corrupted.corrupt_reads = true;
        let mut scratch = [0; BLOCK_SIZE];
        let mut volume = BlockVolume::new(header(), 1, corrupted, &mut scratch).unwrap();
        output.fill(0xcc);
        assert!(
            state
                .read(
                    &authorities,
                    handle,
                    principal(),
                    0,
                    &mut output,
                    &mut volume,
                )
                .is_err()
        );
        assert_eq!(output, [0; 8]);
    }

    #[test]
    fn file_write_session_reconstructs_verifies_flushes_and_rejects_replay() {
        let mut device = Device::new();
        device.bytes[10 * BLOCK_SIZE..11 * BLOCK_SIZE].fill(b'A');
        device.bytes[11 * BLOCK_SIZE..12 * BLOCK_SIZE].fill(b'B');
        let old_digest = digest(&device.bytes[10 * BLOCK_SIZE..12 * BLOCK_SIZE]);
        let old_record = ExtentRecord::data(object(9), 3, 0, 2, 10, old_digest).unwrap();
        let old_map = ExtentMap::<1>::build(
            header(),
            object(9),
            3,
            (2 * BLOCK_SIZE) as u64,
            &[old_record],
        )
        .unwrap();
        let state = FileState::new(object(9), 3, (2 * BLOCK_SIZE) as u64, old_map).unwrap();

        let mut expected = [0; 2 * BLOCK_SIZE];
        expected[..BLOCK_SIZE].fill(b'A');
        expected[BLOCK_SIZE..].fill(b'B');
        expected[BLOCK_SIZE - 2..BLOCK_SIZE + 2].copy_from_slice(b"WXYZ");
        let next_record = ExtentRecord::data(object(9), 4, 0, 2, 20, digest(&expected)).unwrap();
        let next_map = ExtentMap::<1>::build(
            header(),
            object(9),
            4,
            expected.len() as u64,
            &[next_record],
        )
        .unwrap();
        let metadata = FileMetadata::new(
            header(),
            object(9),
            4,
            expected.len() as u64,
            1,
            pointer(24, 1),
            digest(&expected),
        )
        .unwrap();
        let mut authorities = StorageAuthorityTable::<2>::new();
        let handle = authorities
            .insert(
                object(9),
                StorageObjectKind::File,
                StorageRights::WRITE,
                principal(),
            )
            .unwrap();
        let mut volume_scratch = [0; BLOCK_SIZE];
        let mut work_scratch = [0; BLOCK_SIZE];
        let mut volume = BlockVolume::new(header(), 1, device, &mut volume_scratch).unwrap();
        let mut session =
            BlockFileSession::<_, 1, 1>::new(&mut volume, &state, &mut work_scratch).unwrap();
        state
            .prepare_write(
                &authorities,
                handle,
                principal(),
                (BLOCK_SIZE - 2) as u64,
                b"WXYZ",
                expected.len() as u64,
                next_map,
                metadata,
                pointer(23, 1),
                &[pointer(10, 2)],
                &mut session,
            )
            .unwrap();
        assert_eq!(session.staged_count(), 1);
        assert!(session.is_flushed());
        assert_eq!(
            FileWriteBackend::flush_new_file_data(
                &mut session,
                object(9),
                4,
                expected.len() as u64,
                digest(&expected),
            ),
            Err(BlockVolumeError::InvalidState)
        );
        drop(session);
        assert_eq!(
            &volume.device().bytes[20 * BLOCK_SIZE..22 * BLOCK_SIZE],
            &expected
        );
        assert_eq!(volume.device().flushes, 1);
    }

    #[test]
    fn file_write_session_rejects_active_range_reuse_before_writing() {
        let mut device = Device::new();
        device.bytes[10 * BLOCK_SIZE..11 * BLOCK_SIZE].fill(b'A');
        let old_record = ExtentRecord::data(
            object(9),
            3,
            0,
            1,
            10,
            digest(&device.bytes[10 * BLOCK_SIZE..11 * BLOCK_SIZE]),
        )
        .unwrap();
        let old_map =
            ExtentMap::<1>::build(header(), object(9), 3, BLOCK_SIZE as u64, &[old_record])
                .unwrap();
        let state = FileState::new(object(9), 3, BLOCK_SIZE as u64, old_map).unwrap();
        let next = ExtentRecord::data(object(9), 4, 0, 1, 10, [0; 32]).unwrap();
        let mut volume_scratch = [0; BLOCK_SIZE];
        let mut work_scratch = [0; BLOCK_SIZE];
        let mut volume = BlockVolume::new(header(), 1, device, &mut volume_scratch).unwrap();
        let writes = volume.device().writes;
        let mut session =
            BlockFileSession::<_, 1, 1>::new(&mut volume, &state, &mut work_scratch).unwrap();
        assert_eq!(
            FileWriteBackend::stage_new_extent(
                &mut session,
                object(9),
                3,
                BLOCK_SIZE as u64,
                next,
                BLOCK_SIZE as u64,
                0,
                b"x",
            ),
            Err(BlockVolumeError::InvalidRange)
        );
        drop(session);
        assert_eq!(volume.device().writes, writes);
    }

    #[test]
    fn file_write_session_rejects_reserved_and_successor_overlap() {
        let mut device = Device::new();
        device.bytes[10 * BLOCK_SIZE..11 * BLOCK_SIZE].fill(b'A');
        device.bytes[11 * BLOCK_SIZE..12 * BLOCK_SIZE].fill(b'B');
        let old = ExtentRecord::data(
            object(9),
            3,
            0,
            2,
            10,
            digest(&device.bytes[10 * BLOCK_SIZE..12 * BLOCK_SIZE]),
        )
        .unwrap();
        let old_map =
            ExtentMap::<1>::build(header(), object(9), 3, (2 * BLOCK_SIZE) as u64, &[old]).unwrap();
        let state = FileState::new(object(9), 3, (2 * BLOCK_SIZE) as u64, old_map).unwrap();
        let reserved = ExtentRecord::data(object(9), 4, 0, 1, 1, [0; 32]).unwrap();
        let first = ExtentRecord::data(
            object(9),
            4,
            0,
            1,
            20,
            digest(&device.bytes[10 * BLOCK_SIZE..11 * BLOCK_SIZE]),
        )
        .unwrap();
        let overlapping = ExtentRecord::data(
            object(9),
            4,
            1,
            1,
            20,
            digest(&device.bytes[11 * BLOCK_SIZE..12 * BLOCK_SIZE]),
        )
        .unwrap();
        let mut volume_scratch = [0; BLOCK_SIZE];
        let mut work_scratch = [0; BLOCK_SIZE];
        let mut volume = BlockVolume::new(header(), 1, device, &mut volume_scratch).unwrap();
        let mut session =
            BlockFileSession::<_, 1, 2>::new(&mut volume, &state, &mut work_scratch).unwrap();
        assert_eq!(
            FileWriteBackend::stage_new_extent(
                &mut session,
                object(9),
                3,
                (2 * BLOCK_SIZE) as u64,
                reserved,
                (2 * BLOCK_SIZE) as u64,
                0,
                &[],
            ),
            Err(BlockVolumeError::InvalidRange)
        );
        FileWriteBackend::stage_new_extent(
            &mut session,
            object(9),
            3,
            (2 * BLOCK_SIZE) as u64,
            first,
            (2 * BLOCK_SIZE) as u64,
            0,
            &[],
        )
        .unwrap();
        assert_eq!(
            FileWriteBackend::stage_new_extent(
                &mut session,
                object(9),
                3,
                (2 * BLOCK_SIZE) as u64,
                overlapping,
                (2 * BLOCK_SIZE) as u64,
                0,
                &[],
            ),
            Err(BlockVolumeError::InvalidRange)
        );
    }
}
