use mrml_crypto::Sha3_256;

use crate::{ExtentKind, ExtentRecord, MetadataPointer, StorageObjectId, VolumeHeader, VolumeId};

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
}

fn contains(record: AllocationRecord, block: u64) -> bool {
    block >= record.block && block < record.block + u64::from(record.block_count)
}

fn overlaps(left: AllocationRecord, right: AllocationRecord) -> bool {
    left.block < right.block + u64::from(right.block_count)
        && right.block < left.block + u64::from(left.block_count)
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
}
