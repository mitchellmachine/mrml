use mrml_crypto::Sha3_256;

use crate::{StorageObjectId, VolumeHeader, VolumeId};

pub const EXTENT_RECORD_BYTES: usize = 144;
pub const EXTENT_IMAGE_HEADER_BYTES: usize = 96;
pub const MAX_EXTENT_BLOCKS: u32 = 1 << 20;

const EXTENT_MAGIC: [u8; 8] = *b"MREXT001";
const EXTENT_VERSION: u16 = 1;
const DIGEST_OFFSET: usize = 112;
const IMAGE_MAGIC: [u8; 8] = *b"MREXI001";
const IMAGE_DIGEST_OFFSET: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExtentKind {
    Data = 1,
    Hole = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtentRecord {
    file: StorageObjectId,
    metadata_generation: u64,
    logical_block: u64,
    block_count: u32,
    physical_block: u64,
    kind: ExtentKind,
    content_digest: [u8; 32],
}

impl ExtentRecord {
    pub fn data(
        file: StorageObjectId,
        metadata_generation: u64,
        logical_block: u64,
        block_count: u32,
        physical_block: u64,
        content_digest: [u8; 32],
    ) -> Result<Self, ExtentError> {
        Self::new(
            file,
            metadata_generation,
            logical_block,
            block_count,
            physical_block,
            ExtentKind::Data,
            content_digest,
        )
    }

    pub fn hole(
        file: StorageObjectId,
        metadata_generation: u64,
        logical_block: u64,
        block_count: u32,
    ) -> Result<Self, ExtentError> {
        Self::new(
            file,
            metadata_generation,
            logical_block,
            block_count,
            0,
            ExtentKind::Hole,
            [0; 32],
        )
    }

    fn new(
        file: StorageObjectId,
        metadata_generation: u64,
        logical_block: u64,
        block_count: u32,
        physical_block: u64,
        kind: ExtentKind,
        content_digest: [u8; 32],
    ) -> Result<Self, ExtentError> {
        if metadata_generation == 0
            || block_count == 0
            || block_count > MAX_EXTENT_BLOCKS
            || logical_block.checked_add(u64::from(block_count)).is_none()
            || (kind == ExtentKind::Data
                && physical_block.checked_add(u64::from(block_count)).is_none())
            || (kind == ExtentKind::Hole && (physical_block != 0 || content_digest != [0; 32]))
        {
            return Err(ExtentError::InvalidRecord);
        }
        Ok(Self {
            file,
            metadata_generation,
            logical_block,
            block_count,
            physical_block,
            kind,
            content_digest,
        })
    }

    pub const fn kind(self) -> ExtentKind {
        self.kind
    }

    pub const fn logical_block(self) -> u64 {
        self.logical_block
    }

    pub const fn block_count(self) -> u32 {
        self.block_count
    }

    pub const fn file(self) -> StorageObjectId {
        self.file
    }

    pub const fn metadata_generation(self) -> u64 {
        self.metadata_generation
    }

    pub const fn physical_block(self) -> Option<u64> {
        match self.kind {
            ExtentKind::Data => Some(self.physical_block),
            ExtentKind::Hole => None,
        }
    }

    pub const fn content_digest(self) -> [u8; 32] {
        self.content_digest
    }

    pub fn encode(self, output: &mut [u8; EXTENT_RECORD_BYTES]) {
        *output = [0; EXTENT_RECORD_BYTES];
        output[..8].copy_from_slice(&EXTENT_MAGIC);
        put_u16(output, 8, EXTENT_VERSION);
        put_u16(output, 10, EXTENT_RECORD_BYTES as u16);
        output[12] = self.kind as u8;
        output[16..32].copy_from_slice(&self.file.volume().bytes());
        put_u64(output, 32, self.file.local());
        put_u64(output, 40, self.metadata_generation);
        put_u64(output, 48, self.logical_block);
        put_u32(output, 56, self.block_count);
        put_u64(output, 64, self.physical_block);
        output[72..104].copy_from_slice(&self.content_digest);
        let digest = record_digest(output);
        output[DIGEST_OFFSET..].copy_from_slice(&digest);
    }

    pub fn decode(input: &[u8], volume: VolumeId) -> Result<Self, ExtentError> {
        if input.len() != EXTENT_RECORD_BYTES {
            return Err(ExtentError::Truncated);
        }
        if input[..8] != EXTENT_MAGIC
            || get_u16(input, 10)? != EXTENT_RECORD_BYTES as u16
            || input[13..16].iter().any(|byte| *byte != 0)
            || input[60..64].iter().any(|byte| *byte != 0)
            || input[104..112].iter().any(|byte| *byte != 0)
        {
            return Err(ExtentError::NonCanonical);
        }
        if get_u16(input, 8)? != EXTENT_VERSION {
            return Err(ExtentError::UnsupportedVersion);
        }
        if input[DIGEST_OFFSET..] != record_digest(input) {
            return Err(ExtentError::Corrupt);
        }
        if read_volume(input, 16)? != volume {
            return Err(ExtentError::WrongVolume);
        }
        let file = StorageObjectId::new(volume, get_u64(input, 32)?)
            .map_err(|_| ExtentError::InvalidRecord)?;
        let kind = match input[12] {
            1 => ExtentKind::Data,
            2 => ExtentKind::Hole,
            _ => return Err(ExtentError::InvalidRecord),
        };
        let mut content_digest = [0; 32];
        content_digest.copy_from_slice(&input[72..104]);
        Self::new(
            file,
            get_u64(input, 40)?,
            get_u64(input, 48)?,
            get_u32(input, 56)?,
            get_u64(input, 64)?,
            kind,
            content_digest,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtentLocation {
    Data {
        physical_block: u64,
        available_blocks: u32,
        content_digest: [u8; 32],
    },
    Hole {
        available_blocks: u32,
    },
}

pub struct ExtentMap<const N: usize> {
    records: [Option<ExtentRecord>; N],
    count: usize,
    file: StorageObjectId,
    metadata_generation: u64,
    file_length: u64,
    block_size: u32,
    logical_blocks: u64,
}

impl<const N: usize> ExtentMap<N> {
    pub fn build(
        header: VolumeHeader,
        file: StorageObjectId,
        metadata_generation: u64,
        file_length: u64,
        records: &[ExtentRecord],
    ) -> Result<Self, ExtentError> {
        let mut stored = [None; N];
        if records.len() > N {
            return Err(ExtentError::InvalidMap);
        }
        for (slot, record) in stored.iter_mut().zip(records.iter().copied()) {
            *slot = Some(record);
        }
        Self::from_stored(
            header,
            file,
            metadata_generation,
            file_length,
            stored,
            records.len(),
        )
    }

    fn from_stored(
        header: VolumeHeader,
        file: StorageObjectId,
        metadata_generation: u64,
        file_length: u64,
        stored: [Option<ExtentRecord>; N],
        count: usize,
    ) -> Result<Self, ExtentError> {
        if file.volume() != header.volume()
            || metadata_generation == 0
            || count > N
            || stored[..count].iter().any(Option::is_none)
        {
            return Err(ExtentError::InvalidMap);
        }
        let block_size = u64::from(header.block_size());
        let volume_bytes = header
            .block_count()
            .checked_mul(block_size)
            .ok_or(ExtentError::Arithmetic)?;
        if file_length > volume_bytes {
            return Err(ExtentError::InvalidMap);
        }
        let logical_blocks =
            file_length / block_size + u64::from(!file_length.is_multiple_of(block_size));
        if (logical_blocks == 0) != (count == 0) {
            return Err(ExtentError::IncompleteCoverage);
        }

        let mut next_logical = 0_u64;
        for index in 0..count {
            let record = stored[index].ok_or(ExtentError::InvalidMap)?;
            if record.file != file
                || record.metadata_generation != metadata_generation
                || record.logical_block != next_logical
            {
                return Err(ExtentError::InvalidMap);
            }
            let end = record
                .logical_block
                .checked_add(u64::from(record.block_count))
                .ok_or(ExtentError::Arithmetic)?;
            if end > logical_blocks {
                return Err(ExtentError::IncompleteCoverage);
            }
            if record.kind == ExtentKind::Data {
                let physical_end = record
                    .physical_block
                    .checked_add(u64::from(record.block_count))
                    .ok_or(ExtentError::Arithmetic)?;
                if record.physical_block == 0
                    || physical_end > header.block_count()
                    || contains_block(record, header.primary_superblock())
                    || contains_block(record, header.secondary_superblock())
                {
                    return Err(ExtentError::PhysicalRange);
                }
                for prior in stored[..index].iter().flatten().copied() {
                    if prior.kind == ExtentKind::Data && physical_ranges_overlap(prior, record) {
                        return Err(ExtentError::PhysicalOverlap);
                    }
                }
            }
            next_logical = end;
        }
        if next_logical != logical_blocks {
            return Err(ExtentError::IncompleteCoverage);
        }
        Ok(Self {
            records: stored,
            count,
            file,
            metadata_generation,
            file_length,
            block_size: header.block_size(),
            logical_blocks,
        })
    }

    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub const fn logical_blocks(&self) -> u64 {
        self.logical_blocks
    }

    pub const fn file(&self) -> StorageObjectId {
        self.file
    }

    pub const fn metadata_generation(&self) -> u64 {
        self.metadata_generation
    }

    pub const fn file_length(&self) -> u64 {
        self.file_length
    }

    pub const fn block_size(&self) -> u32 {
        self.block_size
    }

    pub fn record(&self, index: usize) -> Option<ExtentRecord> {
        self.records.get(index).copied().flatten()
    }

    pub fn record_for(&self, logical_block: u64) -> Result<ExtentRecord, ExtentError> {
        if logical_block >= self.logical_blocks {
            return Err(ExtentError::OutOfRange);
        }
        self.records[..self.count]
            .iter()
            .flatten()
            .copied()
            .find(|record| {
                logical_block >= record.logical_block
                    && logical_block < record.logical_block + u64::from(record.block_count)
            })
            .ok_or(ExtentError::IncompleteCoverage)
    }

    pub fn locate(&self, logical_block: u64) -> Result<ExtentLocation, ExtentError> {
        let record = self.record_for(logical_block)?;
        let end = record.logical_block + u64::from(record.block_count);
        let offset = logical_block - record.logical_block;
        let available = u32::try_from(end - logical_block).map_err(|_| ExtentError::Arithmetic)?;
        Ok(match record.kind {
            ExtentKind::Data => ExtentLocation::Data {
                physical_block: record.physical_block + offset,
                available_blocks: available,
                content_digest: record.content_digest,
            },
            ExtentKind::Hole => ExtentLocation::Hole {
                available_blocks: available,
            },
        })
    }
}

pub struct ExtentImage<const N: usize> {
    volume: VolumeId,
    pointer: crate::MetadataPointer,
    encoded_len: usize,
    map: ExtentMap<N>,
}

impl<const N: usize> ExtentImage<N> {
    pub fn build(
        header: VolumeHeader,
        file: StorageObjectId,
        metadata_generation: u64,
        file_length: u64,
        pointer: crate::MetadataPointer,
        records: &[ExtentRecord],
    ) -> Result<Self, ExtentError> {
        if !pointer_fits(header, pointer) {
            return Err(ExtentError::InvalidImage);
        }
        let encoded_len = image_bytes(header, pointer)?;
        let used = records
            .len()
            .checked_mul(EXTENT_RECORD_BYTES)
            .and_then(|bytes| bytes.checked_add(EXTENT_IMAGE_HEADER_BYTES))
            .ok_or(ExtentError::Arithmetic)?;
        if used > encoded_len {
            return Err(ExtentError::InvalidImage);
        }
        Ok(Self {
            volume: header.volume(),
            pointer,
            encoded_len,
            map: ExtentMap::build(header, file, metadata_generation, file_length, records)?,
        })
    }

    pub fn decode(
        header: VolumeHeader,
        file: StorageObjectId,
        metadata_generation: u64,
        file_length: u64,
        pointer: crate::MetadataPointer,
        input: &[u8],
    ) -> Result<Self, ExtentError> {
        if !pointer_fits(header, pointer) || input.len() != image_bytes(header, pointer)? {
            return Err(ExtentError::InvalidImage);
        }
        if input[..8] != IMAGE_MAGIC
            || get_u16(input, 10)? != EXTENT_IMAGE_HEADER_BYTES as u16
            || get_u16(input, 12)? != EXTENT_RECORD_BYTES as u16
            || input[14..16].iter().any(|byte| *byte != 0)
            || input[60..IMAGE_DIGEST_OFFSET].iter().any(|byte| *byte != 0)
        {
            return Err(ExtentError::NonCanonical);
        }
        if get_u16(input, 8)? != EXTENT_VERSION {
            return Err(ExtentError::UnsupportedVersion);
        }
        if read_volume(input, 16)? != header.volume() {
            return Err(ExtentError::WrongVolume);
        }
        if get_u64(input, 32)? != file.local()
            || get_u64(input, 40)? != metadata_generation
            || get_u64(input, 48)? != file_length
        {
            return Err(ExtentError::InvalidImage);
        }
        if input[IMAGE_DIGEST_OFFSET..EXTENT_IMAGE_HEADER_BYTES] != image_digest(input) {
            return Err(ExtentError::Corrupt);
        }
        let count = usize::try_from(get_u32(input, 56)?).map_err(|_| ExtentError::InvalidImage)?;
        if count > N {
            return Err(ExtentError::InvalidImage);
        }
        let used = count
            .checked_mul(EXTENT_RECORD_BYTES)
            .and_then(|bytes| bytes.checked_add(EXTENT_IMAGE_HEADER_BYTES))
            .ok_or(ExtentError::Arithmetic)?;
        if used > input.len() || input[used..].iter().any(|byte| *byte != 0) {
            return Err(ExtentError::NonCanonical);
        }
        let mut records = [None; N];
        for (index, slot) in records[..count].iter_mut().enumerate() {
            let start = EXTENT_IMAGE_HEADER_BYTES + index * EXTENT_RECORD_BYTES;
            *slot = Some(ExtentRecord::decode(
                &input[start..start + EXTENT_RECORD_BYTES],
                header.volume(),
            )?);
        }
        Ok(Self {
            volume: header.volume(),
            pointer,
            encoded_len: input.len(),
            map: ExtentMap::from_stored(
                header,
                file,
                metadata_generation,
                file_length,
                records,
                count,
            )?,
        })
    }

    pub const fn pointer(&self) -> crate::MetadataPointer {
        self.pointer
    }

    pub const fn map(&self) -> &ExtentMap<N> {
        &self.map
    }

    pub(crate) fn into_map(self) -> ExtentMap<N> {
        self.map
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<(), ExtentError> {
        if output.len() != self.encoded_len {
            return Err(ExtentError::Truncated);
        }
        output.fill(0);
        output[..8].copy_from_slice(&IMAGE_MAGIC);
        put_u16(output, 8, EXTENT_VERSION);
        put_u16(output, 10, EXTENT_IMAGE_HEADER_BYTES as u16);
        put_u16(output, 12, EXTENT_RECORD_BYTES as u16);
        output[16..32].copy_from_slice(&self.volume.bytes());
        put_u64(output, 32, self.map.file().local());
        put_u64(output, 40, self.map.metadata_generation());
        put_u64(output, 48, self.map.file_length());
        put_u32(output, 56, self.map.len() as u32);
        for index in 0..self.map.len() {
            let start = EXTENT_IMAGE_HEADER_BYTES + index * EXTENT_RECORD_BYTES;
            let end = start + EXTENT_RECORD_BYTES;
            let encoded: &mut [u8; EXTENT_RECORD_BYTES] = (&mut output[start..end])
                .try_into()
                .map_err(|_| ExtentError::Truncated)?;
            self.map
                .record(index)
                .ok_or(ExtentError::InvalidMap)?
                .encode(encoded);
        }
        let digest = image_digest(output);
        output[IMAGE_DIGEST_OFFSET..EXTENT_IMAGE_HEADER_BYTES].copy_from_slice(&digest);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtentError {
    Truncated,
    UnsupportedVersion,
    NonCanonical,
    Corrupt,
    WrongVolume,
    InvalidRecord,
    InvalidMap,
    IncompleteCoverage,
    PhysicalRange,
    PhysicalOverlap,
    OutOfRange,
    Arithmetic,
    InvalidImage,
}

fn contains_block(record: ExtentRecord, block: u64) -> bool {
    block >= record.physical_block && block < record.physical_block + u64::from(record.block_count)
}

fn physical_ranges_overlap(left: ExtentRecord, right: ExtentRecord) -> bool {
    left.physical_block < right.physical_block + u64::from(right.block_count)
        && right.physical_block < left.physical_block + u64::from(left.block_count)
}

fn record_digest(input: &[u8]) -> [u8; 32] {
    let mut digest = Sha3_256::new();
    digest.update(&input[..DIGEST_OFFSET]);
    digest.update(&[0; 32]);
    digest.finalize()
}

fn image_digest(input: &[u8]) -> [u8; 32] {
    let mut digest = Sha3_256::new();
    digest.update(&input[..IMAGE_DIGEST_OFFSET]);
    digest.update(&[0; 32]);
    digest.update(&input[EXTENT_IMAGE_HEADER_BYTES..]);
    digest.finalize()
}

fn image_bytes(
    header: VolumeHeader,
    pointer: crate::MetadataPointer,
) -> Result<usize, ExtentError> {
    usize::try_from(
        u64::from(header.block_size())
            .checked_mul(u64::from(pointer.blocks()))
            .ok_or(ExtentError::Arithmetic)?,
    )
    .map_err(|_| ExtentError::Arithmetic)
}

fn pointer_fits(header: VolumeHeader, pointer: crate::MetadataPointer) -> bool {
    pointer
        .block()
        .checked_add(u64::from(pointer.blocks()))
        .is_some_and(|end| end <= header.block_count())
        && !pointer_contains(pointer, 0)
        && !pointer_contains(pointer, header.primary_superblock())
        && !pointer_contains(pointer, header.secondary_superblock())
}

fn pointer_contains(pointer: crate::MetadataPointer, block: u64) -> bool {
    block >= pointer.block() && block < pointer.block() + u64::from(pointer.blocks())
}

fn read_volume(input: &[u8], offset: usize) -> Result<VolumeId, ExtentError> {
    let mut bytes = [0; 16];
    bytes.copy_from_slice(
        input
            .get(offset..offset + 16)
            .ok_or(ExtentError::Truncated)?,
    );
    VolumeId::new(bytes).map_err(|_| ExtentError::InvalidRecord)
}

fn get_u16(input: &[u8], offset: usize) -> Result<u16, ExtentError> {
    Ok(u16::from_le_bytes(
        input
            .get(offset..offset + 2)
            .ok_or(ExtentError::Truncated)?
            .try_into()
            .map_err(|_| ExtentError::Truncated)?,
    ))
}

fn get_u32(input: &[u8], offset: usize) -> Result<u32, ExtentError> {
    Ok(u32::from_le_bytes(
        input
            .get(offset..offset + 4)
            .ok_or(ExtentError::Truncated)?
            .try_into()
            .map_err(|_| ExtentError::Truncated)?,
    ))
}

fn get_u64(input: &[u8], offset: usize) -> Result<u64, ExtentError> {
    Ok(u64::from_le_bytes(
        input
            .get(offset..offset + 8)
            .ok_or(ExtentError::Truncated)?
            .try_into()
            .map_err(|_| ExtentError::Truncated)?,
    ))
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

    fn volume() -> VolumeId {
        VolumeId::new([7; 16]).unwrap()
    }

    fn file(local: u64) -> StorageObjectId {
        StorageObjectId::new(volume(), local).unwrap()
    }

    fn header() -> VolumeHeader {
        VolumeHeader::new(volume(), 4096, 1000, 1, 2).unwrap()
    }

    #[test]
    fn extent_record_round_trip_rejects_corruption_and_reserved_kinds() {
        let record = ExtentRecord::data(file(3), 4, 0, 2, 10, [9; 32]).unwrap();
        let mut bytes = [0; EXTENT_RECORD_BYTES];
        record.encode(&mut bytes);
        assert_eq!(ExtentRecord::decode(&bytes, volume()), Ok(record));
        bytes[48] ^= 1;
        assert_eq!(
            ExtentRecord::decode(&bytes, volume()),
            Err(ExtentError::Corrupt)
        );
        record.encode(&mut bytes);
        assert_eq!(
            ExtentRecord::decode(&bytes, VolumeId::new([8; 16]).unwrap()),
            Err(ExtentError::WrongVolume)
        );
        bytes[13] = 1;
        let digest = record_digest(&bytes);
        bytes[DIGEST_OFFSET..].copy_from_slice(&digest);
        assert_eq!(
            ExtentRecord::decode(&bytes, volume()),
            Err(ExtentError::NonCanonical)
        );
        record.encode(&mut bytes);
        bytes[12] = 3;
        let digest = record_digest(&bytes);
        bytes[DIGEST_OFFSET..].copy_from_slice(&digest);
        assert_eq!(
            ExtentRecord::decode(&bytes, volume()),
            Err(ExtentError::InvalidRecord)
        );
        let hole = ExtentRecord::hole(file(3), 4, 0, 1).unwrap();
        hole.encode(&mut bytes);
        put_u64(&mut bytes, 64, 5);
        let digest = record_digest(&bytes);
        bytes[DIGEST_OFFSET..].copy_from_slice(&digest);
        assert_eq!(
            ExtentRecord::decode(&bytes, volume()),
            Err(ExtentError::InvalidRecord)
        );
        assert!(ExtentRecord::data(file(3), 4, 0, 2, u64::MAX, [9; 32]).is_err());
    }

    #[test]
    fn map_locates_data_and_explicit_holes() {
        let records = [
            ExtentRecord::data(file(3), 1, 0, 2, 10, [1; 32]).unwrap(),
            ExtentRecord::hole(file(3), 1, 2, 1).unwrap(),
            ExtentRecord::data(file(3), 1, 3, 1, 20, [2; 32]).unwrap(),
        ];
        let map = ExtentMap::<4>::build(header(), file(3), 1, 4 * 4096, &records).unwrap();
        assert_eq!(map.logical_blocks(), 4);
        assert_eq!(
            map.locate(1),
            Ok(ExtentLocation::Data {
                physical_block: 11,
                available_blocks: 1,
                content_digest: [1; 32],
            })
        );
        assert_eq!(
            map.locate(2),
            Ok(ExtentLocation::Hole {
                available_blocks: 1
            })
        );
        assert_eq!(map.locate(4), Err(ExtentError::OutOfRange));
    }

    #[test]
    fn map_requires_exact_ordered_coverage_and_identity() {
        let gap = [ExtentRecord::data(file(3), 1, 1, 1, 10, [1; 32]).unwrap()];
        assert_eq!(
            ExtentMap::<2>::build(header(), file(3), 1, 4096, &gap).map(|_| ()),
            Err(ExtentError::InvalidMap)
        );
        let wrong_file = [ExtentRecord::data(file(4), 1, 0, 1, 10, [1; 32]).unwrap()];
        assert_eq!(
            ExtentMap::<2>::build(header(), file(3), 1, 4096, &wrong_file).map(|_| ()),
            Err(ExtentError::InvalidMap)
        );
        assert!(ExtentMap::<0>::build(header(), file(3), 1, 0, &[]).is_ok());
    }

    #[test]
    fn map_rejects_physical_overlap_and_reserved_superblocks() {
        let overlap = [
            ExtentRecord::data(file(3), 1, 0, 2, 10, [1; 32]).unwrap(),
            ExtentRecord::data(file(3), 1, 2, 2, 11, [2; 32]).unwrap(),
        ];
        assert_eq!(
            ExtentMap::<2>::build(header(), file(3), 1, 4 * 4096, &overlap).map(|_| ()),
            Err(ExtentError::PhysicalOverlap)
        );
        let reserved = [ExtentRecord::data(file(3), 1, 0, 1, 2, [1; 32]).unwrap()];
        assert_eq!(
            ExtentMap::<1>::build(header(), file(3), 1, 4096, &reserved).map(|_| ()),
            Err(ExtentError::PhysicalRange)
        );
        let header_block = [ExtentRecord::data(file(3), 1, 0, 1, 0, [1; 32]).unwrap()];
        assert_eq!(
            ExtentMap::<1>::build(header(), file(3), 1, 4096, &header_block).map(|_| ()),
            Err(ExtentError::PhysicalRange)
        );
    }

    #[test]
    fn map_rejects_capacity_overflow_and_partial_tail_overcoverage() {
        let records = [
            ExtentRecord::data(file(3), 1, 0, 1, 10, [1; 32]).unwrap(),
            ExtentRecord::hole(file(3), 1, 1, 1).unwrap(),
        ];
        assert_eq!(
            ExtentMap::<1>::build(header(), file(3), 1, 8192, &records).map(|_| ()),
            Err(ExtentError::InvalidMap)
        );
        assert_eq!(
            ExtentMap::<2>::build(header(), file(3), 1, 1, &records).map(|_| ()),
            Err(ExtentError::IncompleteCoverage)
        );
        assert_eq!(
            ExtentMap::<2>::build(header(), file(3), 1, u64::MAX, &records).map(|_| ()),
            Err(ExtentError::InvalidMap)
        );
    }

    #[test]
    fn extent_image_round_trip_binds_file_generation_length_and_padding() {
        let pointer = crate::MetadataPointer::new(30, 1).unwrap();
        let records = [
            ExtentRecord::data(file(3), 4, 0, 1, 20, [1; 32]).unwrap(),
            ExtentRecord::hole(file(3), 4, 1, 1).unwrap(),
        ];
        let image = ExtentImage::<2>::build(header(), file(3), 4, 8192, pointer, &records).unwrap();
        let mut encoded = [0; 4096];
        image.encode(&mut encoded).unwrap();
        let decoded =
            ExtentImage::<2>::decode(header(), file(3), 4, 8192, pointer, &encoded).unwrap();
        assert_eq!(decoded.pointer(), pointer);
        assert_eq!(decoded.map().len(), 2);
        assert_eq!(
            decoded.map().locate(1),
            Ok(ExtentLocation::Hole {
                available_blocks: 1
            })
        );
        assert!(matches!(
            ExtentImage::<2>::decode(header(), file(3), 5, 8192, pointer, &encoded),
            Err(ExtentError::InvalidImage)
        ));

        encoded[4095] = 1;
        let digest = image_digest(&encoded);
        encoded[IMAGE_DIGEST_OFFSET..EXTENT_IMAGE_HEADER_BYTES].copy_from_slice(&digest);
        assert!(matches!(
            ExtentImage::<2>::decode(header(), file(3), 4, 8192, pointer, &encoded),
            Err(ExtentError::NonCanonical)
        ));
    }
}
