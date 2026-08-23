use mrml_crypto::Sha3_256;

use crate::{ExtentKind, ExtentRecord, MetadataPointer, StorageObjectId, VolumeHeader, VolumeId};

pub const ALLOCATION_RECORD_BYTES: usize = 112;
pub const MAX_ALLOCATION_BLOCKS: u32 = 1 << 20;

const ALLOCATION_MAGIC: [u8; 8] = *b"MRALC001";
const ALLOCATION_VERSION: u16 = 1;
const DIGEST_OFFSET: usize = 80;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AllocationKind {
    FileData = 1,
    ObjectMetadata = 2,
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
        for (index, record) in records.iter().copied().enumerate() {
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
            if index != 0 && records[index - 1].block >= record.block {
                return Err(AllocationError::Unordered);
            }
            if records[..index]
                .iter()
                .copied()
                .any(|prior| overlaps(prior, record))
            {
                return Err(AllocationError::Overlap);
            }
            stored[index] = Some(record);
        }
        Ok(Self {
            records: stored,
            count: records.len(),
        })
    }

    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
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
}
