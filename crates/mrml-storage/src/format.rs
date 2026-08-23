use mrml_crypto::Sha3_256;

use crate::{StorageObjectId, StorageObjectKind, VolumeId};

pub const VOLUME_HEADER_BYTES: usize = 96;
pub const SUPERBLOCK_BYTES: usize = 128;
pub const DIRECTORY_METADATA_BYTES: usize = 128;
pub const FILE_METADATA_BYTES: usize = 160;
pub const DIRECTORY_ENTRY_BYTES: usize = 336;
pub const MAX_STORAGE_NAME_BYTES: usize = 255;
pub const MAX_METADATA_BLOCKS: u32 = 1024;

const FORMAT_VERSION: u16 = 1;
const DIGEST_BYTES: usize = 32;
const VOLUME_MAGIC: [u8; 8] = *b"MRVOL001";
const SUPERBLOCK_MAGIC: [u8; 8] = *b"MRSUP001";
const DIRECTORY_MAGIC: [u8; 8] = *b"MRDIR001";
const FILE_MAGIC: [u8; 8] = *b"MRFIL001";
const ENTRY_MAGIC: [u8; 8] = *b"MRENT001";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageName {
    length: u8,
    bytes: [u8; MAX_STORAGE_NAME_BYTES],
}

impl StorageName {
    pub fn new(value: &str) -> Result<Self, MetadataError> {
        let bytes = value.as_bytes();
        if bytes.is_empty()
            || bytes.len() > MAX_STORAGE_NAME_BYTES
            || matches!(value, "." | "..")
            || bytes.iter().any(|byte| matches!(*byte, 0 | b'/'))
        {
            return Err(MetadataError::InvalidName);
        }
        let mut stored = [0; MAX_STORAGE_NAME_BYTES];
        stored[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            length: bytes.len() as u8,
            bytes: stored,
        })
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..usize::from(self.length)])
            .expect("StorageName is constructed from UTF-8")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    name: StorageName,
    object: StorageObjectId,
    kind: StorageObjectKind,
    metadata_generation: u64,
}

impl DirectoryEntry {
    pub fn new(
        name: StorageName,
        object: StorageObjectId,
        kind: StorageObjectKind,
        metadata_generation: u64,
    ) -> Result<Self, MetadataError> {
        if kind == StorageObjectKind::Volume || metadata_generation == 0 {
            return Err(MetadataError::InvalidDirectoryEntry);
        }
        Ok(Self {
            name,
            object,
            kind,
            metadata_generation,
        })
    }

    pub const fn object(self) -> StorageObjectId {
        self.object
    }

    pub const fn name(self) -> StorageName {
        self.name
    }

    pub const fn kind(self) -> StorageObjectKind {
        self.kind
    }

    pub const fn metadata_generation(self) -> u64 {
        self.metadata_generation
    }

    pub fn encode(self, output: &mut [u8; DIRECTORY_ENTRY_BYTES]) {
        *output = [0; DIRECTORY_ENTRY_BYTES];
        output[..8].copy_from_slice(&ENTRY_MAGIC);
        put_u16(output, 8, FORMAT_VERSION);
        put_u16(output, 10, DIRECTORY_ENTRY_BYTES as u16);
        put_u16(output, 12, u16::from(self.name.length));
        output[14] = self.kind as u8;
        output[16..32].copy_from_slice(&self.object.volume().bytes());
        put_u64(output, 32, self.object.local());
        put_u64(output, 40, self.metadata_generation);
        output[48..48 + usize::from(self.name.length)]
            .copy_from_slice(self.name.as_str().as_bytes());
        write_digest(output, 304);
    }

    pub fn decode(input: &[u8], volume: VolumeId) -> Result<Self, MetadataError> {
        check_record(input, DIRECTORY_ENTRY_BYTES, &ENTRY_MAGIC, 304)?;
        let length = usize::from(get_u16(input, 12)?);
        if input[15] != 0
            || length == 0
            || length > MAX_STORAGE_NAME_BYTES
            || input[48 + length..304].iter().any(|byte| *byte != 0)
        {
            return Err(MetadataError::NonCanonical);
        }
        if read_volume(input, 16)? != volume {
            return Err(MetadataError::WrongVolume);
        }
        let name = core::str::from_utf8(&input[48..48 + length])
            .map_err(|_| MetadataError::InvalidName)
            .and_then(StorageName::new)?;
        let kind = match input[14] {
            2 => StorageObjectKind::Directory,
            3 => StorageObjectKind::File,
            _ => return Err(MetadataError::InvalidDirectoryEntry),
        };
        Self::new(
            name,
            StorageObjectId::new(volume, get_u64(input, 32)?)
                .map_err(|_| MetadataError::InvalidObject)?,
            kind,
            get_u64(input, 40)?,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataPointer {
    block: u64,
    blocks: u32,
}

impl MetadataPointer {
    pub const fn new(block: u64, blocks: u32) -> Result<Self, MetadataError> {
        if blocks == 0 || blocks > MAX_METADATA_BLOCKS || block.checked_add(blocks as u64).is_none()
        {
            return Err(MetadataError::InvalidPointer);
        }
        Ok(Self { block, blocks })
    }

    pub const fn block(self) -> u64 {
        self.block
    }

    pub const fn blocks(self) -> u32 {
        self.blocks
    }

    const fn within(self, block_count: u64) -> bool {
        match self.block.checked_add(self.blocks as u64) {
            Some(end) => end <= block_count,
            None => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VolumeHeader {
    volume: VolumeId,
    block_size: u32,
    block_count: u64,
    primary_superblock: u64,
    secondary_superblock: u64,
}

impl VolumeHeader {
    pub const fn new(
        volume: VolumeId,
        block_size: u32,
        block_count: u64,
        primary_superblock: u64,
        secondary_superblock: u64,
    ) -> Result<Self, MetadataError> {
        if block_size < 4096
            || block_size > 65_536
            || !block_size.is_power_of_two()
            || block_count < 4
            || primary_superblock >= block_count
            || secondary_superblock >= block_count
            || primary_superblock == secondary_superblock
        {
            return Err(MetadataError::InvalidVolume);
        }
        Ok(Self {
            volume,
            block_size,
            block_count,
            primary_superblock,
            secondary_superblock,
        })
    }

    pub const fn volume(self) -> VolumeId {
        self.volume
    }

    pub const fn block_size(self) -> u32 {
        self.block_size
    }

    pub const fn block_count(self) -> u64 {
        self.block_count
    }

    pub const fn primary_superblock(self) -> u64 {
        self.primary_superblock
    }

    pub const fn secondary_superblock(self) -> u64 {
        self.secondary_superblock
    }

    pub fn encode(self, output: &mut [u8; VOLUME_HEADER_BYTES]) {
        *output = [0; VOLUME_HEADER_BYTES];
        output[..8].copy_from_slice(&VOLUME_MAGIC);
        put_u16(output, 8, FORMAT_VERSION);
        put_u16(output, 10, VOLUME_HEADER_BYTES as u16);
        put_u32(output, 12, self.block_size);
        output[16..32].copy_from_slice(&self.volume.bytes());
        put_u64(output, 32, self.block_count);
        put_u64(output, 40, self.primary_superblock);
        put_u64(output, 48, self.secondary_superblock);
        write_digest(output, 64);
    }

    pub fn decode(input: &[u8]) -> Result<Self, MetadataError> {
        check_record(input, VOLUME_HEADER_BYTES, &VOLUME_MAGIC, 64)?;
        if input[56..64].iter().any(|byte| *byte != 0) {
            return Err(MetadataError::NonCanonical);
        }
        let mut volume = [0; 16];
        volume.copy_from_slice(&input[16..32]);
        Self::new(
            VolumeId::new(volume).map_err(|_| MetadataError::InvalidVolume)?,
            get_u32(input, 12)?,
            get_u64(input, 32)?,
            get_u64(input, 40)?,
            get_u64(input, 48)?,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Superblock {
    volume: VolumeId,
    generation: u64,
    previous_generation: u64,
    root: StorageObjectId,
    root_metadata: MetadataPointer,
    allocation_metadata: MetadataPointer,
}

impl Superblock {
    pub fn new(
        header: VolumeHeader,
        generation: u64,
        previous_generation: u64,
        root: StorageObjectId,
        root_metadata: MetadataPointer,
        allocation_metadata: MetadataPointer,
    ) -> Result<Self, MetadataError> {
        if generation == 0
            || previous_generation != generation - 1
            || root.volume() != header.volume
            || !root_metadata.within(header.block_count)
            || !allocation_metadata.within(header.block_count)
        {
            return Err(MetadataError::InvalidSuperblock);
        }
        Ok(Self {
            volume: header.volume,
            generation,
            previous_generation,
            root,
            root_metadata,
            allocation_metadata,
        })
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn volume(self) -> VolumeId {
        self.volume
    }

    pub const fn root(self) -> StorageObjectId {
        self.root
    }

    pub const fn root_metadata(self) -> MetadataPointer {
        self.root_metadata
    }

    pub const fn allocation_metadata(self) -> MetadataPointer {
        self.allocation_metadata
    }

    pub fn encode(self, output: &mut [u8; SUPERBLOCK_BYTES]) {
        *output = [0; SUPERBLOCK_BYTES];
        output[..8].copy_from_slice(&SUPERBLOCK_MAGIC);
        put_u16(output, 8, FORMAT_VERSION);
        put_u16(output, 10, SUPERBLOCK_BYTES as u16);
        output[16..32].copy_from_slice(&self.volume.bytes());
        put_u64(output, 32, self.generation);
        put_u64(output, 40, self.previous_generation);
        put_u64(output, 48, self.root.local());
        put_pointer(output, 56, self.root_metadata);
        put_pointer(output, 72, self.allocation_metadata);
        write_digest(output, 96);
    }

    pub fn decode(input: &[u8], header: VolumeHeader) -> Result<Self, MetadataError> {
        check_record(input, SUPERBLOCK_BYTES, &SUPERBLOCK_MAGIC, 96)?;
        if input[12..16].iter().any(|byte| *byte != 0)
            || input[68..72].iter().any(|byte| *byte != 0)
            || input[84..96].iter().any(|byte| *byte != 0)
        {
            return Err(MetadataError::NonCanonical);
        }
        let volume = read_volume(input, 16)?;
        if volume != header.volume {
            return Err(MetadataError::WrongVolume);
        }
        Self::new(
            header,
            get_u64(input, 32)?,
            get_u64(input, 40)?,
            StorageObjectId::new(volume, get_u64(input, 48)?)
                .map_err(|_| MetadataError::InvalidObject)?,
            get_pointer(input, 56)?,
            get_pointer(input, 72)?,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryMetadata {
    object: StorageObjectId,
    generation: u64,
    parent: Option<StorageObjectId>,
    entry_count: u32,
    entries: MetadataPointer,
}

impl DirectoryMetadata {
    pub fn new(
        header: VolumeHeader,
        object: StorageObjectId,
        generation: u64,
        parent: Option<StorageObjectId>,
        entry_count: u32,
        entries: MetadataPointer,
    ) -> Result<Self, MetadataError> {
        if object.volume() != header.volume
            || parent.is_some_and(|parent| parent.volume() != header.volume || parent == object)
            || generation == 0
            || !entries.within(header.block_count)
        {
            return Err(MetadataError::InvalidDirectory);
        }
        Ok(Self {
            object,
            generation,
            parent,
            entry_count,
            entries,
        })
    }

    pub const fn object(self) -> StorageObjectId {
        self.object
    }

    pub fn encode(self, output: &mut [u8; DIRECTORY_METADATA_BYTES]) {
        *output = [0; DIRECTORY_METADATA_BYTES];
        output[..8].copy_from_slice(&DIRECTORY_MAGIC);
        put_u16(output, 8, FORMAT_VERSION);
        put_u16(output, 10, DIRECTORY_METADATA_BYTES as u16);
        output[16..32].copy_from_slice(&self.object.volume().bytes());
        put_u64(output, 32, self.object.local());
        put_u64(output, 40, self.generation);
        put_u64(
            output,
            48,
            self.parent.map(StorageObjectId::local).unwrap_or(0),
        );
        put_u32(output, 56, self.entry_count);
        put_pointer(output, 64, self.entries);
        write_digest(output, 96);
    }

    pub fn decode(input: &[u8], header: VolumeHeader) -> Result<Self, MetadataError> {
        check_record(input, DIRECTORY_METADATA_BYTES, &DIRECTORY_MAGIC, 96)?;
        if input[12..16].iter().any(|byte| *byte != 0)
            || input[60..64].iter().any(|byte| *byte != 0)
            || input[76..96].iter().any(|byte| *byte != 0)
        {
            return Err(MetadataError::NonCanonical);
        }
        let volume = read_volume(input, 16)?;
        let object = StorageObjectId::new(volume, get_u64(input, 32)?)
            .map_err(|_| MetadataError::InvalidObject)?;
        let parent = match get_u64(input, 48)? {
            0 => None,
            local => Some(
                StorageObjectId::new(volume, local).map_err(|_| MetadataError::InvalidObject)?,
            ),
        };
        Self::new(
            header,
            object,
            get_u64(input, 40)?,
            parent,
            get_u32(input, 56)?,
            get_pointer(input, 64)?,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileMetadata {
    object: StorageObjectId,
    generation: u64,
    length: u64,
    extent_count: u32,
    extents: MetadataPointer,
    content_digest: [u8; DIGEST_BYTES],
}

impl FileMetadata {
    pub fn new(
        header: VolumeHeader,
        object: StorageObjectId,
        generation: u64,
        length: u64,
        extent_count: u32,
        extents: MetadataPointer,
        content_digest: [u8; DIGEST_BYTES],
    ) -> Result<Self, MetadataError> {
        if object.volume() != header.volume
            || generation == 0
            || !extents.within(header.block_count)
            || (length == 0 && extent_count != 0)
            || (length != 0 && extent_count == 0)
        {
            return Err(MetadataError::InvalidFile);
        }
        Ok(Self {
            object,
            generation,
            length,
            extent_count,
            extents,
            content_digest,
        })
    }

    pub const fn object(self) -> StorageObjectId {
        self.object
    }

    pub fn encode(self, output: &mut [u8; FILE_METADATA_BYTES]) {
        *output = [0; FILE_METADATA_BYTES];
        output[..8].copy_from_slice(&FILE_MAGIC);
        put_u16(output, 8, FORMAT_VERSION);
        put_u16(output, 10, FILE_METADATA_BYTES as u16);
        output[16..32].copy_from_slice(&self.object.volume().bytes());
        put_u64(output, 32, self.object.local());
        put_u64(output, 40, self.generation);
        put_u64(output, 48, self.length);
        put_u32(output, 56, self.extent_count);
        put_pointer(output, 64, self.extents);
        output[80..112].copy_from_slice(&self.content_digest);
        write_digest(output, 128);
    }

    pub fn decode(input: &[u8], header: VolumeHeader) -> Result<Self, MetadataError> {
        check_record(input, FILE_METADATA_BYTES, &FILE_MAGIC, 128)?;
        if input[12..16].iter().any(|byte| *byte != 0)
            || input[60..64].iter().any(|byte| *byte != 0)
            || input[76..80].iter().any(|byte| *byte != 0)
            || input[112..128].iter().any(|byte| *byte != 0)
        {
            return Err(MetadataError::NonCanonical);
        }
        let volume = read_volume(input, 16)?;
        let mut content_digest = [0; DIGEST_BYTES];
        content_digest.copy_from_slice(&input[80..112]);
        Self::new(
            header,
            StorageObjectId::new(volume, get_u64(input, 32)?)
                .map_err(|_| MetadataError::InvalidObject)?,
            get_u64(input, 40)?,
            get_u64(input, 48)?,
            get_u32(input, 56)?,
            get_pointer(input, 64)?,
            content_digest,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataError {
    Truncated,
    UnsupportedVersion,
    NonCanonical,
    Corrupt,
    InvalidVolume,
    WrongVolume,
    InvalidObject,
    InvalidName,
    InvalidDirectoryEntry,
    InvalidPointer,
    InvalidSuperblock,
    InvalidDirectory,
    InvalidFile,
}

fn check_record(
    input: &[u8],
    length: usize,
    magic: &[u8; 8],
    digest_offset: usize,
) -> Result<(), MetadataError> {
    if input.len() != length {
        return Err(MetadataError::Truncated);
    }
    if input[..8] != *magic || usize::from(get_u16(input, 10)?) != length {
        return Err(MetadataError::NonCanonical);
    }
    if get_u16(input, 8)? != FORMAT_VERSION {
        return Err(MetadataError::UnsupportedVersion);
    }
    let mut expected = [0; DIGEST_BYTES];
    expected.copy_from_slice(&input[digest_offset..digest_offset + DIGEST_BYTES]);
    if record_digest(input, digest_offset) != expected {
        return Err(MetadataError::Corrupt);
    }
    Ok(())
}

fn write_digest(output: &mut [u8], offset: usize) {
    let digest = record_digest(output, offset);
    output[offset..offset + DIGEST_BYTES].copy_from_slice(&digest);
}

fn record_digest(input: &[u8], offset: usize) -> [u8; DIGEST_BYTES] {
    let mut digest = Sha3_256::new();
    digest.update(&input[..offset]);
    digest.update(&[0; DIGEST_BYTES]);
    digest.update(&input[offset + DIGEST_BYTES..]);
    digest.finalize()
}

fn read_volume(input: &[u8], offset: usize) -> Result<VolumeId, MetadataError> {
    let mut bytes = [0; 16];
    bytes.copy_from_slice(
        input
            .get(offset..offset + 16)
            .ok_or(MetadataError::Truncated)?,
    );
    VolumeId::new(bytes).map_err(|_| MetadataError::InvalidVolume)
}

fn put_pointer(output: &mut [u8], offset: usize, pointer: MetadataPointer) {
    put_u64(output, offset, pointer.block);
    put_u32(output, offset + 8, pointer.blocks);
}

fn get_pointer(input: &[u8], offset: usize) -> Result<MetadataPointer, MetadataError> {
    MetadataPointer::new(get_u64(input, offset)?, get_u32(input, offset + 8)?)
}

fn get_u16(input: &[u8], offset: usize) -> Result<u16, MetadataError> {
    Ok(u16::from_le_bytes(
        input
            .get(offset..offset + 2)
            .ok_or(MetadataError::Truncated)?
            .try_into()
            .map_err(|_| MetadataError::Truncated)?,
    ))
}

fn get_u32(input: &[u8], offset: usize) -> Result<u32, MetadataError> {
    Ok(u32::from_le_bytes(
        input
            .get(offset..offset + 4)
            .ok_or(MetadataError::Truncated)?
            .try_into()
            .map_err(|_| MetadataError::Truncated)?,
    ))
}

fn get_u64(input: &[u8], offset: usize) -> Result<u64, MetadataError> {
    Ok(u64::from_le_bytes(
        input
            .get(offset..offset + 8)
            .ok_or(MetadataError::Truncated)?
            .try_into()
            .map_err(|_| MetadataError::Truncated)?,
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

    fn volume(byte: u8) -> VolumeId {
        VolumeId::new([byte; 16]).unwrap()
    }

    fn header() -> VolumeHeader {
        VolumeHeader::new(volume(1), 4096, 10_000, 1, 2).unwrap()
    }

    fn object(local: u64) -> StorageObjectId {
        StorageObjectId::new(volume(1), local).unwrap()
    }

    #[test]
    fn volume_header_round_trip_rejects_corruption_and_invalid_geometry() {
        let header = header();
        let mut bytes = [0; VOLUME_HEADER_BYTES];
        header.encode(&mut bytes);
        assert_eq!(VolumeHeader::decode(&bytes), Ok(header));
        bytes[32] ^= 1;
        assert_eq!(VolumeHeader::decode(&bytes), Err(MetadataError::Corrupt));
        assert!(VolumeHeader::new(volume(1), 3000, 10_000, 1, 2).is_err());
        assert!(VolumeHeader::new(volume(1), 4096, 4, 1, 1).is_err());
    }

    #[test]
    fn superblock_binds_generation_volume_root_and_metadata_pointers() {
        let header = header();
        let superblock = Superblock::new(
            header,
            2,
            1,
            object(1),
            MetadataPointer::new(10, 2).unwrap(),
            MetadataPointer::new(20, 3).unwrap(),
        )
        .unwrap();
        let mut bytes = [0; SUPERBLOCK_BYTES];
        superblock.encode(&mut bytes);
        assert_eq!(Superblock::decode(&bytes, header), Ok(superblock));
        assert_eq!(
            Superblock::decode(
                &bytes,
                VolumeHeader::new(volume(2), 4096, 10_000, 1, 2).unwrap(),
            ),
            Err(MetadataError::WrongVolume)
        );
        assert!(
            Superblock::new(
                header,
                1,
                1,
                object(1),
                MetadataPointer::new(10, 2).unwrap(),
                MetadataPointer::new(20, 3).unwrap(),
            )
            .is_err()
        );
        assert!(
            Superblock::new(
                header,
                3,
                1,
                object(1),
                MetadataPointer::new(10, 2).unwrap(),
                MetadataPointer::new(20, 3).unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn directory_entry_is_canonical_data_not_authority() {
        let entry = DirectoryEntry::new(
            StorageName::new("project.mrml").unwrap(),
            object(11),
            StorageObjectKind::File,
            7,
        )
        .unwrap();
        let mut bytes = [0; DIRECTORY_ENTRY_BYTES];
        entry.encode(&mut bytes);
        assert_eq!(DirectoryEntry::decode(&bytes, volume(1)), Ok(entry));
        assert_eq!(
            DirectoryEntry::decode(&bytes, volume(2)),
            Err(MetadataError::WrongVolume)
        );
        for invalid in ["", ".", "..", "a/b", "a\0b"] {
            assert_eq!(StorageName::new(invalid), Err(MetadataError::InvalidName));
        }
        bytes[303] = 1;
        write_digest(&mut bytes, 304);
        assert_eq!(
            DirectoryEntry::decode(&bytes, volume(1)),
            Err(MetadataError::NonCanonical)
        );
    }

    #[test]
    fn directory_metadata_preserves_identity_across_parent_changes() {
        let header = header();
        let first = DirectoryMetadata::new(
            header,
            object(7),
            1,
            Some(object(2)),
            3,
            MetadataPointer::new(30, 1).unwrap(),
        )
        .unwrap();
        let renamed = DirectoryMetadata::new(
            header,
            object(7),
            2,
            Some(object(4)),
            3,
            MetadataPointer::new(31, 1).unwrap(),
        )
        .unwrap();
        assert_eq!(first.object(), renamed.object());
        let mut bytes = [0; DIRECTORY_METADATA_BYTES];
        renamed.encode(&mut bytes);
        assert_eq!(DirectoryMetadata::decode(&bytes, header), Ok(renamed));
        assert!(
            DirectoryMetadata::new(
                header,
                object(7),
                1,
                Some(object(7)),
                0,
                MetadataPointer::new(1, 1).unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn file_metadata_binds_length_extent_count_and_content_digest() {
        let header = header();
        let file = FileMetadata::new(
            header,
            object(9),
            3,
            8192,
            2,
            MetadataPointer::new(40, 1).unwrap(),
            [5; 32],
        )
        .unwrap();
        let mut bytes = [0; FILE_METADATA_BYTES];
        file.encode(&mut bytes);
        assert_eq!(FileMetadata::decode(&bytes, header), Ok(file));
        assert!(
            FileMetadata::new(
                header,
                object(9),
                1,
                1,
                0,
                MetadataPointer::new(40, 1).unwrap(),
                [0; 32],
            )
            .is_err()
        );
    }

    #[test]
    fn hidden_reserved_bytes_fail_even_with_recomputed_digest() {
        let directory = DirectoryMetadata::new(
            header(),
            object(3),
            1,
            None,
            0,
            MetadataPointer::new(50, 1).unwrap(),
        )
        .unwrap();
        let mut bytes = [0; DIRECTORY_METADATA_BYTES];
        directory.encode(&mut bytes);
        bytes[60] = 1;
        write_digest(&mut bytes, 96);
        assert_eq!(
            DirectoryMetadata::decode(&bytes, header()),
            Err(MetadataError::NonCanonical)
        );
    }
}
