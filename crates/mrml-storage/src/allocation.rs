use mrml_crypto::Sha3_256;

use crate::{
    CowMetadataImage, ExtentKind, ExtentRecord, MetadataPointer, StorageObjectId, TransactionError,
    TransactionParticipant, TransactionReceipt, VolumeHeader, VolumeId,
};

pub const ALLOCATION_RECORD_BYTES: usize = 112;
pub const ALLOCATION_IMAGE_HEADER_BYTES: usize = 96;
pub const MAX_ALLOCATION_BLOCKS: u32 = 1 << 20;

const ALLOCATION_MAGIC: [u8; 8] = *b"MRALC001";
const ALLOCATION_VERSION: u16 = 1;
const DIGEST_OFFSET: usize = 80;
const IMAGE_MAGIC: [u8; 8] = *b"MRALI001";
const IMAGE_DIGEST_OFFSET: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AllocationKind {
    FileData = 1,
    ObjectMetadata = 2,
    AllocationMetadata = 3,
    DirectoryEntries = 4,
    FileExtents = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationRecord {
    owner: StorageObjectId,
    owner_generation: u64,
    block: u64,
    block_count: u32,
    kind: AllocationKind,
}

impl AllocationRecord {
    pub fn new(
        owner: StorageObjectId,
        owner_generation: u64,
        block: u64,
        block_count: u32,
        kind: AllocationKind,
    ) -> Result<Self, AllocationError> {
        if owner_generation == 0
            || block_count == 0
            || block_count > MAX_ALLOCATION_BLOCKS
            || block.checked_add(u64::from(block_count)).is_none()
        {
            return Err(AllocationError::InvalidRecord);
        }
        Ok(Self {
            owner,
            owner_generation,
            block,
            block_count,
            kind,
        })
    }

    pub const fn owner(self) -> StorageObjectId {
        self.owner
    }

    pub const fn owner_generation(self) -> u64 {
        self.owner_generation
    }

    pub const fn block(self) -> u64 {
        self.block
    }

    pub const fn block_count(self) -> u32 {
        self.block_count
    }

    pub const fn kind(self) -> AllocationKind {
        self.kind
    }

    pub fn encode(self, output: &mut [u8; ALLOCATION_RECORD_BYTES]) {
        *output = [0; ALLOCATION_RECORD_BYTES];
        output[..8].copy_from_slice(&ALLOCATION_MAGIC);
        put_u16(output, 8, ALLOCATION_VERSION);
        put_u16(output, 10, ALLOCATION_RECORD_BYTES as u16);
        output[12] = self.kind as u8;
        output[16..32].copy_from_slice(&self.owner.volume().bytes());
        put_u64(output, 32, self.owner.local());
        put_u64(output, 40, self.owner_generation);
        put_u64(output, 48, self.block);
        put_u32(output, 56, self.block_count);
        let digest = record_digest(output);
        output[DIGEST_OFFSET..].copy_from_slice(&digest);
    }

    pub fn decode(input: &[u8], volume: VolumeId) -> Result<Self, AllocationError> {
        if input.len() != ALLOCATION_RECORD_BYTES {
            return Err(AllocationError::Truncated);
        }
        if input[..8] != ALLOCATION_MAGIC
            || get_u16(input, 10)? != ALLOCATION_RECORD_BYTES as u16
            || input[13..16].iter().any(|byte| *byte != 0)
            || input[60..DIGEST_OFFSET].iter().any(|byte| *byte != 0)
        {
            return Err(AllocationError::NonCanonical);
        }
        if get_u16(input, 8)? != ALLOCATION_VERSION {
            return Err(AllocationError::UnsupportedVersion);
        }
        if input[DIGEST_OFFSET..] != record_digest(input) {
            return Err(AllocationError::Corrupt);
        }
        let mut encoded_volume = [0; 16];
        encoded_volume.copy_from_slice(&input[16..32]);
        if VolumeId::new(encoded_volume).map_err(|_| AllocationError::InvalidRecord)? != volume {
            return Err(AllocationError::WrongVolume);
        }
        let kind = match input[12] {
            1 => AllocationKind::FileData,
            2 => AllocationKind::ObjectMetadata,
            3 => AllocationKind::AllocationMetadata,
            4 => AllocationKind::DirectoryEntries,
            5 => AllocationKind::FileExtents,
            _ => return Err(AllocationError::InvalidRecord),
        };
        Self::new(
            StorageObjectId::new(volume, get_u64(input, 32)?)
                .map_err(|_| AllocationError::InvalidRecord)?,
            get_u64(input, 40)?,
            get_u64(input, 48)?,
            get_u32(input, 56)?,
            kind,
        )
    }
}

pub struct AllocationIndex<const N: usize> {
    records: [Option<AllocationRecord>; N],
    count: usize,
}

impl<const N: usize> AllocationIndex<N> {
    pub fn build(
        header: VolumeHeader,
        records: &[AllocationRecord],
    ) -> Result<Self, AllocationError> {
        if records.len() > N {
            return Err(AllocationError::Capacity);
        }
        let mut stored = [None; N];
        for (slot, record) in stored.iter_mut().zip(records.iter().copied()) {
            *slot = Some(record);
        }
        Self::from_stored(header, stored, records.len())
    }

    fn from_stored(
        header: VolumeHeader,
        stored: [Option<AllocationRecord>; N],
        count: usize,
    ) -> Result<Self, AllocationError> {
        if count > N || stored[..count].iter().any(Option::is_none) {
            return Err(AllocationError::Capacity);
        }
        for index in 0..count {
            let record = stored[index].ok_or(AllocationError::Capacity)?;
            let end = record
                .block
                .checked_add(u64::from(record.block_count))
                .ok_or(AllocationError::Arithmetic)?;
            if record.owner.volume() != header.volume()
                || end > header.block_count()
                || contains(record, 0)
                || contains(record, header.primary_superblock())
                || contains(record, header.secondary_superblock())
            {
                return Err(AllocationError::InvalidRecord);
            }
            if index != 0
                && stored[index - 1].ok_or(AllocationError::Capacity)?.block >= record.block
            {
                return Err(AllocationError::Unordered);
            }
            if stored[..index]
                .iter()
                .flatten()
                .copied()
                .any(|prior| overlaps(prior, record))
            {
                return Err(AllocationError::Overlap);
            }
        }
        Ok(Self {
            records: stored,
            count,
        })
    }

    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub const fn record(&self, index: usize) -> Option<AllocationRecord> {
        if index < self.count {
            self.records[index]
        } else {
            None
        }
    }

    pub fn owns_extent(&self, extent: ExtentRecord) -> bool {
        if extent.kind() != ExtentKind::Data {
            return false;
        }
        let Some(block) = extent.physical_block() else {
            return false;
        };
        self.contains_exact(
            extent.file(),
            extent.metadata_generation(),
            block,
            extent.block_count(),
            AllocationKind::FileData,
        )
    }

    pub fn owns_metadata(
        &self,
        owner: StorageObjectId,
        owner_generation: u64,
        pointer: MetadataPointer,
    ) -> bool {
        self.contains_exact(
            owner,
            owner_generation,
            pointer.block(),
            pointer.blocks(),
            AllocationKind::ObjectMetadata,
        )
    }

    pub fn owns_allocation_image(
        &self,
        owner: StorageObjectId,
        publication_generation: u64,
        pointer: MetadataPointer,
    ) -> bool {
        self.contains_exact(
            owner,
            publication_generation,
            pointer.block(),
            pointer.blocks(),
            AllocationKind::AllocationMetadata,
        )
    }

    pub fn owns_directory_entries(
        &self,
        owner: StorageObjectId,
        owner_generation: u64,
        pointer: MetadataPointer,
    ) -> bool {
        self.contains_exact(
            owner,
            owner_generation,
            pointer.block(),
            pointer.blocks(),
            AllocationKind::DirectoryEntries,
        )
    }

    pub fn owns_file_extents(
        &self,
        owner: StorageObjectId,
        owner_generation: u64,
        pointer: MetadataPointer,
    ) -> bool {
        self.contains_exact(
            owner,
            owner_generation,
            pointer.block(),
            pointer.blocks(),
            AllocationKind::FileExtents,
        )
    }

    pub fn object_metadata(
        &self,
        owner: StorageObjectId,
        owner_generation: u64,
    ) -> Option<MetadataPointer> {
        self.object_metadata_record(owner, owner_generation)
            .map(|(pointer, _)| pointer)
    }

    pub(crate) fn object_metadata_record(
        &self,
        owner: StorageObjectId,
        owner_generation: u64,
    ) -> Option<(MetadataPointer, usize)> {
        let mut found = None;
        for (index, record) in self.records[..self.count]
            .iter()
            .flatten()
            .copied()
            .enumerate()
        {
            if record.owner == owner
                && record.owner_generation == owner_generation
                && record.kind == AllocationKind::ObjectMetadata
            {
                if found.is_some() {
                    return None;
                }
                found = MetadataPointer::new(record.block, record.block_count)
                    .ok()
                    .map(|pointer| (pointer, index));
            }
        }
        found
    }

    pub(crate) fn exact_record_index(
        &self,
        owner: StorageObjectId,
        owner_generation: u64,
        pointer: MetadataPointer,
        kind: AllocationKind,
    ) -> Option<usize> {
        self.exact_range_index(
            owner,
            owner_generation,
            pointer.block(),
            pointer.blocks(),
            kind,
        )
    }

    pub(crate) fn exact_range_index(
        &self,
        owner: StorageObjectId,
        owner_generation: u64,
        block: u64,
        block_count: u32,
        kind: AllocationKind,
    ) -> Option<usize> {
        self.records[..self.count].iter().position(|record| {
            record.is_some_and(|record| {
                record.owner == owner
                    && record.owner_generation == owner_generation
                    && record.block == block
                    && record.block_count == block_count
                    && record.kind == kind
            })
        })
    }

    fn contains_exact(
        &self,
        owner: StorageObjectId,
        owner_generation: u64,
        block: u64,
        block_count: u32,
        kind: AllocationKind,
    ) -> bool {
        self.records[..self.count].iter().flatten().any(|record| {
            record.owner == owner
                && record.owner_generation == owner_generation
                && record.block == block
                && record.block_count == block_count
                && record.kind == kind
        })
    }
}

pub struct AllocationImage<const N: usize> {
    volume: VolumeId,
    generation: u64,
    pointer: MetadataPointer,
    encoded_len: usize,
    index: AllocationIndex<N>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocationChange {
    Allocate(AllocationRecord),
    Free(AllocationRecord),
}

pub struct PreparedAllocationUpdate<const N: usize> {
    old_generation: u64,
    successor: AllocationImage<N>,
    metadata: CowMetadataImage,
}

impl<const N: usize> PreparedAllocationUpdate<N> {
    pub const fn generation(&self) -> u64 {
        self.successor.generation
    }

    pub const fn pointer(&self) -> MetadataPointer {
        self.successor.pointer
    }

    pub const fn metadata_image(&self) -> CowMetadataImage {
        self.metadata
    }

    pub(crate) fn owns_image(
        &self,
        owner: StorageObjectId,
        owner_generation: u64,
        pointer: MetadataPointer,
        kind: AllocationKind,
    ) -> bool {
        self.successor
            .index
            .exact_record_index(owner, owner_generation, pointer, kind)
            .is_some()
    }

    pub(crate) fn transaction_participant(
        &self,
    ) -> Result<TransactionParticipant, TransactionError> {
        TransactionParticipant::allocation(
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
    ) -> Result<AllocationImage<N>, TransactionError> {
        receipt.consume(self.transaction_participant()?)?;
        Ok(self.successor)
    }
}

impl<const N: usize> AllocationImage<N> {
    pub fn build(
        header: VolumeHeader,
        generation: u64,
        pointer: MetadataPointer,
        records: &[AllocationRecord],
    ) -> Result<Self, AllocationError> {
        if generation == 0 || !pointer_fits(header, pointer) {
            return Err(AllocationError::InvalidImage);
        }
        let image_bytes = image_bytes(header, pointer)?;
        let records_bytes = records
            .len()
            .checked_mul(ALLOCATION_RECORD_BYTES)
            .and_then(|bytes| bytes.checked_add(ALLOCATION_IMAGE_HEADER_BYTES))
            .ok_or(AllocationError::Arithmetic)?;
        if records_bytes > image_bytes {
            return Err(AllocationError::Capacity);
        }
        Ok(Self {
            volume: header.volume(),
            generation,
            pointer,
            encoded_len: image_bytes,
            index: AllocationIndex::build(header, records)?,
        })
    }

    pub fn decode(
        header: VolumeHeader,
        generation: u64,
        pointer: MetadataPointer,
        input: &[u8],
    ) -> Result<Self, AllocationError> {
        if generation == 0
            || !pointer_fits(header, pointer)
            || input.len() != image_bytes(header, pointer)?
        {
            return Err(AllocationError::InvalidImage);
        }
        if input[..8] != IMAGE_MAGIC
            || get_u16(input, 8)? != ALLOCATION_VERSION
            || get_u16(input, 10)? != ALLOCATION_IMAGE_HEADER_BYTES as u16
            || get_u16(input, 12)? != ALLOCATION_RECORD_BYTES as u16
            || input[14..16].iter().any(|byte| *byte != 0)
            || input[44..IMAGE_DIGEST_OFFSET].iter().any(|byte| *byte != 0)
        {
            return Err(AllocationError::NonCanonical);
        }
        let mut encoded_volume = [0; 16];
        encoded_volume.copy_from_slice(&input[16..32]);
        if VolumeId::new(encoded_volume).map_err(|_| AllocationError::InvalidImage)?
            != header.volume()
        {
            return Err(AllocationError::WrongVolume);
        }
        if get_u64(input, 32)? != generation {
            return Err(AllocationError::InvalidImage);
        }
        if input[IMAGE_DIGEST_OFFSET..ALLOCATION_IMAGE_HEADER_BYTES] != image_digest(input) {
            return Err(AllocationError::Corrupt);
        }
        let count = usize::try_from(get_u32(input, 40)?).map_err(|_| AllocationError::Capacity)?;
        if count > N {
            return Err(AllocationError::Capacity);
        }
        let used = count
            .checked_mul(ALLOCATION_RECORD_BYTES)
            .and_then(|bytes| bytes.checked_add(ALLOCATION_IMAGE_HEADER_BYTES))
            .ok_or(AllocationError::Arithmetic)?;
        if used > input.len() || input[used..].iter().any(|byte| *byte != 0) {
            return Err(AllocationError::NonCanonical);
        }
        let mut records = [None; N];
        for (index, slot) in records[..count].iter_mut().enumerate() {
            let start = ALLOCATION_IMAGE_HEADER_BYTES + index * ALLOCATION_RECORD_BYTES;
            *slot = Some(AllocationRecord::decode(
                &input[start..start + ALLOCATION_RECORD_BYTES],
                header.volume(),
            )?);
        }
        Ok(Self {
            volume: header.volume(),
            generation,
            pointer,
            encoded_len: input.len(),
            index: AllocationIndex::from_stored(header, records, count)?,
        })
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn pointer(&self) -> MetadataPointer {
        self.pointer
    }

    pub const fn index(&self) -> &AllocationIndex<N> {
        &self.index
    }

    pub fn is_self_owned_by(&self, root: StorageObjectId) -> bool {
        self.index
            .owns_allocation_image(root, self.generation, self.pointer)
    }

    pub fn successor(
        &self,
        header: VolumeHeader,
        root: StorageObjectId,
        next_pointer: MetadataPointer,
        changes: &[AllocationChange],
    ) -> Result<Self, AllocationError> {
        if header.volume() != self.volume || root.volume() != self.volume || changes.len() > N {
            return Err(AllocationError::InvalidImage);
        }
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(AllocationError::GenerationExhausted)?;
        let active_self = self
            .index
            .exact_record_index(
                root,
                self.generation,
                self.pointer,
                AllocationKind::AllocationMetadata,
            )
            .ok_or(AllocationError::InvalidImage)?;
        let mut removed = [false; N];
        let mut additions = [None; N];
        let mut addition_count = 0;
        for change in changes.iter().copied() {
            match change {
                AllocationChange::Free(record) => {
                    let index = self.index.records[..self.index.count]
                        .iter()
                        .position(|candidate| *candidate == Some(record))
                        .ok_or(AllocationError::NotFound)?;
                    if index == active_self || removed[index] {
                        return Err(AllocationError::DuplicateChange);
                    }
                    removed[index] = true;
                }
                AllocationChange::Allocate(record) => {
                    if record.owner.volume() != self.volume
                        || self.index.records[..self.index.count]
                            .iter()
                            .flatten()
                            .copied()
                            .any(|active| overlaps(active, record))
                        || additions[..addition_count]
                            .iter()
                            .flatten()
                            .copied()
                            .any(|prior| overlaps(prior, record))
                    {
                        return Err(AllocationError::ReusesLiveRange);
                    }
                    additions[addition_count] = Some(record);
                    addition_count += 1;
                }
            }
        }
        let next_self = AllocationRecord::new(
            root,
            next_generation,
            next_pointer.block(),
            next_pointer.blocks(),
            AllocationKind::AllocationMetadata,
        )?;
        if self.index.records[..self.index.count]
            .iter()
            .flatten()
            .copied()
            .any(|active| overlaps(active, next_self))
            || additions[..addition_count]
                .iter()
                .flatten()
                .copied()
                .any(|addition| overlaps(addition, next_self))
        {
            return Err(AllocationError::ReusesLiveRange);
        }

        let removed_count = removed[..self.index.count]
            .iter()
            .filter(|removed| **removed)
            .count();
        let retained = self.index.count - removed_count - 1;
        let next_count = retained
            .checked_add(addition_count)
            .and_then(|count| count.checked_add(1))
            .ok_or(AllocationError::Capacity)?;
        if next_count > N {
            return Err(AllocationError::Capacity);
        }
        let mut records = [None; N];
        let mut count = 0;
        for (index, (record, removed)) in self.index.records[..self.index.count]
            .iter()
            .zip(removed[..self.index.count].iter())
            .enumerate()
        {
            let record = record.ok_or(AllocationError::InvalidImage)?;
            if index != active_self && !*removed {
                insert_sorted(&mut records, &mut count, record)?;
            }
        }
        for record in additions[..addition_count].iter().flatten().copied() {
            insert_sorted(&mut records, &mut count, record)?;
        }
        insert_sorted(&mut records, &mut count, next_self)?;
        let encoded_len = image_bytes(header, next_pointer)?;
        let used = count
            .checked_mul(ALLOCATION_RECORD_BYTES)
            .and_then(|bytes| bytes.checked_add(ALLOCATION_IMAGE_HEADER_BYTES))
            .ok_or(AllocationError::Arithmetic)?;
        if used > encoded_len {
            return Err(AllocationError::Capacity);
        }
        Ok(Self {
            volume: self.volume,
            generation: next_generation,
            pointer: next_pointer,
            encoded_len,
            index: AllocationIndex::from_stored(header, records, count)?,
        })
    }

    pub fn prepare_successor<B: AllocationWriteBackend>(
        &self,
        header: VolumeHeader,
        root: StorageObjectId,
        next_pointer: MetadataPointer,
        changes: &[AllocationChange],
        encoded: &mut [u8],
        backend: &mut B,
    ) -> Result<PreparedAllocationUpdate<N>, AllocationUpdateError<B::Error>> {
        let successor = self
            .successor(header, root, next_pointer, changes)
            .map_err(AllocationUpdateError::Planning)?;
        successor
            .encode(encoded)
            .map_err(AllocationUpdateError::Planning)?;
        let mut digest = Sha3_256::new();
        digest.update(encoded);
        let metadata = CowMetadataImage::new(next_pointer, digest.finalize());
        backend
            .stage_allocation_image(metadata, encoded)
            .map_err(AllocationUpdateError::Backend)?;
        backend
            .flush_allocation_image()
            .map_err(AllocationUpdateError::Backend)?;
        Ok(PreparedAllocationUpdate {
            old_generation: self.generation,
            successor,
            metadata,
        })
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<(), AllocationError> {
        if output.len() != self.encoded_len {
            return Err(AllocationError::Truncated);
        }
        output.fill(0);
        output[..8].copy_from_slice(&IMAGE_MAGIC);
        put_u16(output, 8, ALLOCATION_VERSION);
        put_u16(output, 10, ALLOCATION_IMAGE_HEADER_BYTES as u16);
        put_u16(output, 12, ALLOCATION_RECORD_BYTES as u16);
        output[16..32].copy_from_slice(&self.volume.bytes());
        put_u64(output, 32, self.generation);
        put_u32(output, 40, self.index.len() as u32);
        for index in 0..self.index.len() {
            let start = ALLOCATION_IMAGE_HEADER_BYTES + index * ALLOCATION_RECORD_BYTES;
            let end = start + ALLOCATION_RECORD_BYTES;
            if end > output.len() {
                return Err(AllocationError::Truncated);
            }
            let encoded: &mut [u8; ALLOCATION_RECORD_BYTES] = (&mut output[start..end])
                .try_into()
                .map_err(|_| AllocationError::Truncated)?;
            self.index
                .record(index)
                .ok_or(AllocationError::Capacity)?
                .encode(encoded);
        }
        let digest = image_digest(output);
        output[IMAGE_DIGEST_OFFSET..ALLOCATION_IMAGE_HEADER_BYTES].copy_from_slice(&digest);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocationError {
    Truncated,
    UnsupportedVersion,
    NonCanonical,
    Corrupt,
    WrongVolume,
    InvalidRecord,
    Capacity,
    Unordered,
    Overlap,
    Arithmetic,
    InvalidImage,
    GenerationExhausted,
    NotFound,
    DuplicateChange,
    ReusesLiveRange,
}

/// Persistence boundary for a complete unreachable allocation successor image.
///
/// # Safety
///
/// Implementations must write the complete supplied bytes to the exact range in
/// `image`, verify those bytes against its digest, keep the range unreachable
/// from the active root, and make the entire image durable before
/// `flush_allocation_image` succeeds. They must not redirect, shorten, merge, or
/// acknowledge a stale or partially written image.
pub unsafe trait AllocationWriteBackend {
    type Error;

    fn stage_allocation_image(
        &mut self,
        image: CowMetadataImage,
        encoded: &[u8],
    ) -> Result<(), Self::Error>;

    fn flush_allocation_image(&mut self) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocationUpdateError<E> {
    Planning(AllocationError),
    Backend(E),
}

fn contains(record: AllocationRecord, block: u64) -> bool {
    block >= record.block && block < record.block + u64::from(record.block_count)
}

fn overlaps(left: AllocationRecord, right: AllocationRecord) -> bool {
    left.block < right.block + u64::from(right.block_count)
        && right.block < left.block + u64::from(left.block_count)
}

fn insert_sorted<const N: usize>(
    records: &mut [Option<AllocationRecord>; N],
    count: &mut usize,
    record: AllocationRecord,
) -> Result<(), AllocationError> {
    if *count == N {
        return Err(AllocationError::Capacity);
    }
    let index = records[..*count]
        .iter()
        .flatten()
        .position(|current| current.block > record.block)
        .unwrap_or(*count);
    for slot in (index..*count).rev() {
        records[slot + 1] = records[slot];
    }
    records[index] = Some(record);
    *count += 1;
    Ok(())
}

fn record_digest(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(&input[..DIGEST_OFFSET]);
    hasher.finalize()
}

fn image_digest(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(&input[..IMAGE_DIGEST_OFFSET]);
    hasher.update(&[0; 32]);
    hasher.update(&input[ALLOCATION_IMAGE_HEADER_BYTES..]);
    hasher.finalize()
}

fn image_bytes(header: VolumeHeader, pointer: MetadataPointer) -> Result<usize, AllocationError> {
    usize::try_from(
        u64::from(header.block_size())
            .checked_mul(u64::from(pointer.blocks()))
            .ok_or(AllocationError::Arithmetic)?,
    )
    .map_err(|_| AllocationError::Arithmetic)
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

fn pointer_contains(pointer: MetadataPointer, block: u64) -> bool {
    block >= pointer.block() && block < pointer.block() + u64::from(pointer.blocks())
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

fn get_u16(input: &[u8], offset: usize) -> Result<u16, AllocationError> {
    input
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(AllocationError::Truncated)
}

fn get_u32(input: &[u8], offset: usize) -> Result<u32, AllocationError> {
    input
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(AllocationError::Truncated)
}

fn get_u64(input: &[u8], offset: usize) -> Result<u64, AllocationError> {
    input
        .get(offset..offset + 8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(AllocationError::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CowMetadataWrite, CowPublicationBackend, CowPublicationPlan, StorageTransaction,
        StorageTransactionId, Superblock,
    };

    fn volume() -> VolumeId {
        VolumeId::new([8; 16]).unwrap()
    }

    fn object(local: u64) -> StorageObjectId {
        StorageObjectId::new(volume(), local).unwrap()
    }

    fn header() -> VolumeHeader {
        VolumeHeader::new(volume(), 4096, 100, 1, 2).unwrap()
    }

    #[test]
    fn canonical_record_round_trip_rejects_hidden_and_digest_corruption() {
        let record = AllocationRecord::new(object(7), 4, 20, 3, AllocationKind::FileData).unwrap();
        let mut encoded = [0; ALLOCATION_RECORD_BYTES];
        record.encode(&mut encoded);
        assert_eq!(AllocationRecord::decode(&encoded, volume()), Ok(record));

        encoded[60] = 1;
        assert_eq!(
            AllocationRecord::decode(&encoded, volume()),
            Err(AllocationError::NonCanonical)
        );
        record.encode(&mut encoded);
        encoded[48] ^= 1;
        assert_eq!(
            AllocationRecord::decode(&encoded, volume()),
            Err(AllocationError::Corrupt)
        );
    }

    #[test]
    fn index_rejects_reserved_cross_file_overlap_and_capacity() {
        let first = AllocationRecord::new(object(7), 4, 20, 3, AllocationKind::FileData).unwrap();
        let overlap = AllocationRecord::new(object(8), 2, 22, 2, AllocationKind::FileData).unwrap();
        assert!(matches!(
            AllocationIndex::<2>::build(header(), &[first, overlap]),
            Err(AllocationError::Overlap)
        ));
        let reserved =
            AllocationRecord::new(object(7), 4, 1, 1, AllocationKind::ObjectMetadata).unwrap();
        assert!(matches!(
            AllocationIndex::<1>::build(header(), &[reserved]),
            Err(AllocationError::InvalidRecord)
        ));
        assert!(matches!(
            AllocationIndex::<0>::build(header(), &[first]),
            Err(AllocationError::Capacity)
        ));
        let later =
            AllocationRecord::new(object(7), 4, 30, 1, AllocationKind::ObjectMetadata).unwrap();
        assert!(matches!(
            AllocationIndex::<2>::build(header(), &[later, first]),
            Err(AllocationError::Unordered)
        ));
    }

    #[test]
    fn ownership_requires_exact_object_generation_range_and_kind() {
        let data = AllocationRecord::new(object(7), 4, 20, 3, AllocationKind::FileData).unwrap();
        let metadata =
            AllocationRecord::new(object(7), 4, 30, 1, AllocationKind::ObjectMetadata).unwrap();
        let index = AllocationIndex::<2>::build(header(), &[data, metadata]).unwrap();
        let extent = ExtentRecord::data(object(7), 4, 0, 3, 20, [1; 32]).unwrap();
        assert!(index.owns_extent(extent));
        assert!(!index.owns_extent(ExtentRecord::data(object(7), 5, 0, 3, 20, [1; 32]).unwrap()));
        assert!(index.owns_metadata(object(7), 4, MetadataPointer::new(30, 1).unwrap()));
        assert_eq!(
            index.object_metadata(object(7), 4),
            Some(MetadataPointer::new(30, 1).unwrap())
        );
        assert!(!index.owns_metadata(object(7), 4, MetadataPointer::new(30, 2).unwrap()));
    }

    #[test]
    fn allocation_image_round_trip_binds_complete_zero_padded_generation() {
        let pointer = MetadataPointer::new(10, 1).unwrap();
        let records = [
            AllocationRecord::new(object(1), 5, 10, 1, AllocationKind::AllocationMetadata).unwrap(),
            AllocationRecord::new(object(7), 4, 20, 3, AllocationKind::FileData).unwrap(),
        ];
        let image = AllocationImage::<2>::build(header(), 5, pointer, &records).unwrap();
        let mut encoded = [0; 4096];
        image.encode(&mut encoded).unwrap();
        let decoded = AllocationImage::<2>::decode(header(), 5, pointer, &encoded).unwrap();
        assert_eq!(decoded.generation(), 5);
        assert_eq!(decoded.pointer(), pointer);
        assert_eq!(decoded.index().len(), 2);
        assert!(decoded.is_self_owned_by(object(1)));
        assert!(!decoded.is_self_owned_by(object(7)));
        assert!(
            decoded
                .index()
                .owns_extent(ExtentRecord::data(object(7), 4, 0, 3, 20, [1; 32]).unwrap())
        );

        assert!(matches!(
            AllocationImage::<2>::decode(header(), 4, pointer, &encoded),
            Err(AllocationError::InvalidImage)
        ));
        encoded[4095] = 1;
        let digest = image_digest(&encoded);
        encoded[IMAGE_DIGEST_OFFSET..ALLOCATION_IMAGE_HEADER_BYTES].copy_from_slice(&digest);
        assert!(matches!(
            AllocationImage::<2>::decode(header(), 5, pointer, &encoded),
            Err(AllocationError::NonCanonical)
        ));
    }

    #[test]
    fn successor_frees_without_reusing_live_ranges_and_rotates_its_image() {
        let root_metadata =
            AllocationRecord::new(object(1), 2, 10, 1, AllocationKind::ObjectMetadata).unwrap();
        let active_self =
            AllocationRecord::new(object(1), 5, 20, 1, AllocationKind::AllocationMetadata).unwrap();
        let old_data =
            AllocationRecord::new(object(7), 3, 30, 1, AllocationKind::FileData).unwrap();
        let active = AllocationImage::<4>::build(
            header(),
            5,
            MetadataPointer::new(20, 1).unwrap(),
            &[root_metadata, active_self, old_data],
        )
        .unwrap();
        let new_data =
            AllocationRecord::new(object(7), 4, 40, 1, AllocationKind::FileData).unwrap();
        let successor = active
            .successor(
                header(),
                object(1),
                MetadataPointer::new(50, 1).unwrap(),
                &[
                    AllocationChange::Free(old_data),
                    AllocationChange::Allocate(new_data),
                ],
            )
            .unwrap();
        assert_eq!(successor.generation(), 6);
        assert!(successor.is_self_owned_by(object(1)));
        assert!(
            successor
                .index()
                .owns_extent(ExtentRecord::data(object(7), 4, 0, 1, 40, [1; 32]).unwrap())
        );
        assert!(
            !successor
                .index()
                .owns_extent(ExtentRecord::data(object(7), 3, 0, 1, 30, [1; 32]).unwrap())
        );
        assert!(
            active
                .index()
                .owns_extent(ExtentRecord::data(object(7), 3, 0, 1, 30, [1; 32]).unwrap())
        );

        let reused = AllocationRecord::new(object(8), 1, 30, 1, AllocationKind::FileData).unwrap();
        assert!(matches!(
            active.successor(
                header(),
                object(1),
                MetadataPointer::new(50, 1).unwrap(),
                &[
                    AllocationChange::Free(old_data),
                    AllocationChange::Allocate(reused),
                ],
            ),
            Err(AllocationError::ReusesLiveRange)
        ));

        let mut encoded = [0; 4096];
        successor.encode(&mut encoded).unwrap();
        let decoded = AllocationImage::<4>::decode(
            header(),
            6,
            MetadataPointer::new(50, 1).unwrap(),
            &encoded,
        )
        .unwrap();
        assert_eq!(decoded.index().len(), 3);
    }

    struct WriteBackend {
        staged: usize,
        flushed: bool,
    }

    unsafe impl AllocationWriteBackend for WriteBackend {
        type Error = ();

        fn stage_allocation_image(
            &mut self,
            image: CowMetadataImage,
            encoded: &[u8],
        ) -> Result<(), Self::Error> {
            let mut digest = Sha3_256::new();
            digest.update(encoded);
            if image.digest() != digest.finalize() {
                return Err(());
            }
            self.staged += 1;
            Ok(())
        }

        fn flush_allocation_image(&mut self) -> Result<(), Self::Error> {
            self.flushed = true;
            Ok(())
        }
    }

    struct PublishBackend {
        verified: usize,
        replaced: usize,
    }

    unsafe impl CowPublicationBackend for PublishBackend {
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
    fn staged_allocation_successor_commits_only_from_transaction_receipt() {
        let root_metadata =
            AllocationRecord::new(object(1), 2, 10, 1, AllocationKind::ObjectMetadata).unwrap();
        let active_self =
            AllocationRecord::new(object(1), 5, 20, 1, AllocationKind::AllocationMetadata).unwrap();
        let active = AllocationImage::<3>::build(
            header(),
            5,
            MetadataPointer::new(20, 1).unwrap(),
            &[root_metadata, active_self],
        )
        .unwrap();
        let mut encoded = [0; 4096];
        let mut writer = WriteBackend {
            staged: 0,
            flushed: false,
        };
        let prepared = active
            .prepare_successor(
                header(),
                object(1),
                MetadataPointer::new(50, 1).unwrap(),
                &[],
                &mut encoded,
                &mut writer,
            )
            .unwrap();
        assert_eq!((writer.staged, writer.flushed), (1, true));
        assert_eq!(prepared.generation(), 6);

        let mut transaction = StorageTransaction::<1, 1>::new(
            StorageTransactionId::new(20).unwrap(),
            prepared.generation(),
        )
        .unwrap();
        transaction.admit_allocation(&prepared).unwrap();
        let active_superblock = Superblock::new(
            header(),
            5,
            4,
            object(1),
            MetadataPointer::new(10, 1).unwrap(),
            MetadataPointer::new(20, 1).unwrap(),
        )
        .unwrap();
        let root = CowMetadataWrite::new(MetadataPointer::new(60, 1).unwrap(), 6, [7; 32]).unwrap();
        let allocation = prepared.metadata_image().bind(6).unwrap();
        let plan = CowPublicationPlan::<2>::build(
            header(),
            1,
            active_superblock,
            object(1),
            root.pointer(),
            allocation.pointer(),
            &[root, allocation],
            &[
                MetadataPointer::new(10, 1).unwrap(),
                MetadataPointer::new(20, 1).unwrap(),
            ],
        )
        .unwrap();
        let mut publisher = PublishBackend {
            verified: 0,
            replaced: 0,
        };
        let mut receipt = transaction.publish(&plan, &mut publisher).unwrap();
        let committed = prepared.commit_transaction(&mut receipt).unwrap();
        assert_eq!(committed.generation(), 6);
        assert_eq!(receipt.remaining(), 0);
        assert_eq!((publisher.verified, publisher.replaced), (2, 1));
    }
}
