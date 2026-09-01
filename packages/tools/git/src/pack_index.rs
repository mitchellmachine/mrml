//! Git pack index v2 parsing and construction with repository-wide hash width.

use mrml_runtime::Vector;

use crate::{ObjectFormat, ObjectId};

const MAGIC: [u8; 4] = [0xff, b't', b'O', b'c'];
const VERSION: u32 = 2;
pub const DEFAULT_MAX_PACK_INDEX_OBJECTS: u32 = 10_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackIndexError {
    InputTooLarge,
    Truncated,
    UnsupportedVersion,
    InvalidFanout,
    InvalidObjectId,
    DuplicateObjectId,
    InvalidOffset,
    ChecksumMismatch,
    TrailingData,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackIndexEntry {
    pub id: ObjectId,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackIndex {
    format: ObjectFormat,
    entries: Vector<PackIndexEntry>,
    pack_checksum: ObjectId,
}

impl PackIndex {
    pub const fn format(&self) -> ObjectFormat {
        self.format
    }

    pub fn entries(&self) -> &[PackIndexEntry] {
        &self.entries
    }

    pub const fn pack_checksum(&self) -> ObjectId {
        self.pack_checksum
    }

    pub fn find(&self, id: ObjectId) -> Option<&PackIndexEntry> {
        if id.format() != self.format {
            return None;
        }
        self.entries
            .binary_search_by(|entry| entry.id.as_bytes().cmp(id.as_bytes()))
            .ok()
            .map(|index| &self.entries[index])
    }
}

pub fn build_pack_index_v2(
    format: ObjectFormat,
    entries: &[PackIndexEntry],
    pack_checksum: ObjectId,
) -> Result<Vector<u8>, PackIndexError> {
    if pack_checksum.format() != format || pack_checksum.is_zero() {
        return Err(PackIndexError::InvalidObjectId);
    }
    let count = u32::try_from(entries.len()).map_err(|_| PackIndexError::InputTooLarge)?;
    let mut sorted =
        Vector::with_capacity(entries.len()).map_err(|_| PackIndexError::InputTooLarge)?;
    sorted
        .try_extend_from_slice(entries)
        .map_err(|_| PackIndexError::InputTooLarge)?;
    sort_entries(&mut sorted);
    validate_entries(format, &sorted)?;

    let large_count = sorted
        .iter()
        .filter(|entry| entry.offset >= 0x8000_0000)
        .count();
    if large_count > 0x7fff_ffff {
        return Err(PackIndexError::InvalidOffset);
    }
    let capacity = 8usize
        .checked_add(256 * 4)
        .and_then(|value| value.checked_add(entries.len().checked_mul(format.hash_len())?))
        .and_then(|value| value.checked_add(entries.len().checked_mul(8)?))
        .and_then(|value| value.checked_add(large_count.checked_mul(8)?))
        .and_then(|value| value.checked_add(format.hash_len().checked_mul(2)?))
        .ok_or(PackIndexError::InputTooLarge)?;
    let mut output = Vector::with_capacity(capacity).map_err(|_| PackIndexError::InputTooLarge)?;
    append(&mut output, &MAGIC)?;
    append(&mut output, &VERSION.to_be_bytes())?;
    let mut fanout = [0u32; 256];
    for entry in &sorted {
        let first = usize::from(entry.id.as_bytes()[0]);
        fanout[first] = fanout[first]
            .checked_add(1)
            .ok_or(PackIndexError::InputTooLarge)?;
    }
    let mut cumulative = 0u32;
    for value in fanout {
        cumulative = cumulative
            .checked_add(value)
            .ok_or(PackIndexError::InputTooLarge)?;
        append(&mut output, &cumulative.to_be_bytes())?;
    }
    if cumulative != count {
        return Err(PackIndexError::InvalidFanout);
    }
    for entry in &sorted {
        append(&mut output, entry.id.as_bytes())?;
    }
    for entry in &sorted {
        append(&mut output, &entry.crc32.to_be_bytes())?;
    }
    let mut next_large = 0u32;
    for entry in &sorted {
        if entry.offset < 0x8000_0000 {
            append(&mut output, &(entry.offset as u32).to_be_bytes())?;
        } else {
            append(&mut output, &(0x8000_0000 | next_large).to_be_bytes())?;
            next_large += 1;
        }
    }
    for entry in &sorted {
        if entry.offset >= 0x8000_0000 {
            append(&mut output, &entry.offset.to_be_bytes())?;
        }
    }
    append(&mut output, pack_checksum.as_bytes())?;
    let checksum = format.hash_bytes(&output);
    append(&mut output, checksum.as_bytes())?;
    Ok(output)
}

pub fn parse_pack_index_v2(
    format: ObjectFormat,
    input: &[u8],
    max_objects: u32,
) -> Result<PackIndex, PackIndexError> {
    if max_objects == 0 {
        return Err(PackIndexError::InputTooLarge);
    }
    let hash_len = format.hash_len();
    let minimum = 8 + 256 * 4 + hash_len * 2;
    if input.len() < minimum {
        return Err(PackIndexError::Truncated);
    }
    if input[..4] != MAGIC {
        return Err(PackIndexError::UnsupportedVersion);
    }
    if u32::from_be_bytes(input[4..8].try_into().unwrap()) != VERSION {
        return Err(PackIndexError::UnsupportedVersion);
    }
    let mut fanout = [0u32; 256];
    let mut previous = 0u32;
    for (index, value) in fanout.iter_mut().enumerate() {
        let start = 8 + index * 4;
        *value = u32::from_be_bytes(input[start..start + 4].try_into().unwrap());
        if *value < previous {
            return Err(PackIndexError::InvalidFanout);
        }
        previous = *value;
    }
    let count = fanout[255];
    if count > max_objects {
        return Err(PackIndexError::InputTooLarge);
    }
    let count = count as usize;
    let names_start: usize = 8 + 256 * 4;
    let names_end = names_start
        .checked_add(
            count
                .checked_mul(hash_len)
                .ok_or(PackIndexError::InputTooLarge)?,
        )
        .ok_or(PackIndexError::InputTooLarge)?;
    let crc_end = names_end
        .checked_add(count.checked_mul(4).ok_or(PackIndexError::InputTooLarge)?)
        .ok_or(PackIndexError::InputTooLarge)?;
    let offsets_end = crc_end
        .checked_add(count.checked_mul(4).ok_or(PackIndexError::InputTooLarge)?)
        .ok_or(PackIndexError::InputTooLarge)?;
    let fixed_tail = hash_len
        .checked_mul(2)
        .ok_or(PackIndexError::InputTooLarge)?;
    if offsets_end
        .checked_add(fixed_tail)
        .ok_or(PackIndexError::InputTooLarge)?
        > input.len()
    {
        return Err(PackIndexError::Truncated);
    }
    let mut large_count = 0usize;
    for index in 0..count {
        let start = crc_end + index * 4;
        let value = u32::from_be_bytes(input[start..start + 4].try_into().unwrap());
        if value & 0x8000_0000 != 0 {
            large_count = large_count.max((value & 0x7fff_ffff) as usize + 1);
        }
    }
    let large_end = offsets_end
        .checked_add(
            large_count
                .checked_mul(8)
                .ok_or(PackIndexError::InputTooLarge)?,
        )
        .ok_or(PackIndexError::InputTooLarge)?;
    let expected_end = large_end
        .checked_add(fixed_tail)
        .ok_or(PackIndexError::InputTooLarge)?;
    if expected_end > input.len() {
        return Err(PackIndexError::Truncated);
    }
    if expected_end != input.len() {
        return Err(PackIndexError::TrailingData);
    }
    let stored_index_checksum = &input[input.len() - hash_len..];
    let actual_index_checksum = format.hash_bytes(&input[..input.len() - hash_len]);
    if actual_index_checksum.as_bytes() != stored_index_checksum {
        return Err(PackIndexError::ChecksumMismatch);
    }
    let pack_checksum_start = input.len() - hash_len * 2;
    let pack_checksum = ObjectId::from_bytes(
        format,
        &input[pack_checksum_start..pack_checksum_start + hash_len],
    )
    .ok_or(PackIndexError::InvalidObjectId)?;
    if pack_checksum.is_zero() {
        return Err(PackIndexError::InvalidObjectId);
    }

    let mut entries = Vector::with_capacity(count).map_err(|_| PackIndexError::InputTooLarge)?;
    let mut used_large =
        Vector::with_capacity(large_count).map_err(|_| PackIndexError::InputTooLarge)?;
    for _ in 0..large_count {
        used_large.push(false);
    }
    for index in 0..count {
        let name_start = names_start + index * hash_len;
        let id = ObjectId::from_bytes(format, &input[name_start..name_start + hash_len])
            .ok_or(PackIndexError::InvalidObjectId)?;
        let crc_start = names_end + index * 4;
        let crc32 = u32::from_be_bytes(input[crc_start..crc_start + 4].try_into().unwrap());
        let offset_start = crc_end + index * 4;
        let offset32 =
            u32::from_be_bytes(input[offset_start..offset_start + 4].try_into().unwrap());
        let offset = if offset32 & 0x8000_0000 == 0 {
            u64::from(offset32)
        } else {
            let large_index = (offset32 & 0x7fff_ffff) as usize;
            if large_index >= large_count {
                return Err(PackIndexError::InvalidOffset);
            }
            if used_large[large_index] {
                return Err(PackIndexError::InvalidOffset);
            }
            used_large[large_index] = true;
            let start = offsets_end + large_index * 8;
            let large = u64::from_be_bytes(input[start..start + 8].try_into().unwrap());
            if large < 0x8000_0000 {
                return Err(PackIndexError::InvalidOffset);
            }
            large
        };
        entries.push(PackIndexEntry { id, crc32, offset });
    }
    validate_entries(format, &entries)?;
    if used_large.iter().any(|used| !used) {
        return Err(PackIndexError::InvalidOffset);
    }
    for (byte, window) in fanout.iter().copied().enumerate() {
        let expected = entries
            .iter()
            .take_while(|entry| usize::from(entry.id.as_bytes()[0]) <= byte)
            .count() as u32;
        if window != expected {
            return Err(PackIndexError::InvalidFanout);
        }
    }
    Ok(PackIndex {
        format,
        entries,
        pack_checksum,
    })
}

fn validate_entries(
    format: ObjectFormat,
    entries: &[PackIndexEntry],
) -> Result<(), PackIndexError> {
    for (index, entry) in entries.iter().enumerate() {
        if entry.id.format() != format || entry.id.is_zero() {
            return Err(PackIndexError::InvalidObjectId);
        }
        if index != 0 {
            match entries[index - 1].id.as_bytes().cmp(entry.id.as_bytes()) {
                core::cmp::Ordering::Less => {}
                core::cmp::Ordering::Equal => return Err(PackIndexError::DuplicateObjectId),
                core::cmp::Ordering::Greater => return Err(PackIndexError::InvalidObjectId),
            }
        }
    }
    Ok(())
}

fn sort_entries(entries: &mut [PackIndexEntry]) {
    if entries.len() < 2 {
        return;
    }
    for root in (0..entries.len() / 2).rev() {
        sift_down(entries, root, entries.len());
    }
    for end in (1..entries.len()).rev() {
        entries.swap(0, end);
        sift_down(entries, 0, end);
    }
}

fn sift_down(entries: &mut [PackIndexEntry], mut root: usize, end: usize) {
    loop {
        let left = root * 2 + 1;
        if left >= end {
            return;
        }
        let right = left + 1;
        let child = if right < end && entries[left].id.as_bytes() < entries[right].id.as_bytes() {
            right
        } else {
            left
        };
        if entries[root].id.as_bytes() >= entries[child].id.as_bytes() {
            return;
        }
        entries.swap(root, child);
        root = child;
    }
}

fn append(output: &mut Vector<u8>, bytes: &[u8]) -> Result<(), PackIndexError> {
    output
        .try_extend_from_slice(bytes)
        .map_err(|_| PackIndexError::InputTooLarge)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(format: ObjectFormat, first: u8, last: u8) -> ObjectId {
        let mut bytes = [0u8; 32];
        bytes[0] = first;
        bytes[format.hash_len() - 1] = last;
        ObjectId::from_bytes(format, &bytes[..format.hash_len()]).unwrap()
    }

    #[test]
    fn v2_round_trips_both_hash_widths_and_large_offsets() {
        for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
            let pack_checksum = oid(format, 0xaa, 1);
            let encoded = build_pack_index_v2(
                format,
                &[
                    PackIndexEntry {
                        id: oid(format, 0xfe, 2),
                        crc32: 7,
                        offset: 0x1_0000_0000,
                    },
                    PackIndexEntry {
                        id: oid(format, 1, 3),
                        crc32: 9,
                        offset: 12,
                    },
                ],
                pack_checksum,
            )
            .unwrap();
            let parsed = parse_pack_index_v2(format, &encoded, 2).unwrap();
            assert_eq!(parsed.pack_checksum(), pack_checksum);
            assert_eq!(parsed.entries()[0].offset, 12);
            assert_eq!(parsed.entries()[1].offset, 0x1_0000_0000);
            assert_eq!(parsed.find(oid(format, 0xfe, 2)).unwrap().crc32, 7);
        }
    }

    #[test]
    fn tampering_trailing_data_duplicates_and_limits_fail_closed() {
        let format = ObjectFormat::Sha256;
        let entry = PackIndexEntry {
            id: oid(format, 1, 1),
            crc32: 3,
            offset: 44,
        };
        let encoded = build_pack_index_v2(format, &[entry], oid(format, 2, 2)).unwrap();
        let mut tampered = encoded.clone();
        tampered[8 + 256 * 4] ^= 1;
        assert_eq!(
            parse_pack_index_v2(format, &tampered, 1),
            Err(PackIndexError::ChecksumMismatch)
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            parse_pack_index_v2(format, &trailing, 1),
            Err(PackIndexError::TrailingData)
        );
        assert_eq!(
            parse_pack_index_v2(format, &encoded, 0),
            Err(PackIndexError::InputTooLarge)
        );
        assert_eq!(
            build_pack_index_v2(format, &[entry, entry], oid(format, 2, 2)),
            Err(PackIndexError::DuplicateObjectId)
        );
    }
}
