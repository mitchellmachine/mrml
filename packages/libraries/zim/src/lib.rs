#![no_std]
#![cfg(any(windows, unix))]

use core::fmt;
use mrml_interface_zstd_v3::{
    decode_decompress_response, encode_decompress_request, BorrowedReadView, BorrowedWriteView,
    DecompressError, ZstdTransport,
};
use mrml_runtime::{File, Text, Vector};

pub const ZIM_MAGIC: u32 = 0x044d_495a;
const HEADER_BYTES: usize = 80;
const CHECKSUM_BYTES: u64 = 16;
const MAX_ARCHIVE_BYTES: u64 = 1 << 40;
const MAX_ENTRIES: u32 = 16 * 1024 * 1024;
const MAX_CLUSTERS: u32 = 1024 * 1024;
const MAX_MIME_TYPES: usize = 65_536;
const MAX_STRING_BYTES: usize = 1024 * 1024;
const MAX_MIME_BYTES: usize = 64 * 1024 * 1024;
const MAX_CLUSTER_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Error {
    File(mrml_runtime::FileError),
    InvalidMagic(u32),
    UnsupportedVersion(u16, u16),
    InvalidOffset,
    InvalidDirectoryEntry,
    InvalidCluster,
    UnsupportedCompression(u8),
    Decompression,
    InvalidUtf8,
    Allocation,
    BudgetExceeded,
}

impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(error) => error.fmt(output),
            Self::InvalidMagic(magic) => write!(output, "invalid ZIM magic 0x{magic:08x}"),
            Self::UnsupportedVersion(major, minor) => {
                write!(output, "unsupported ZIM version {major}.{minor}")
            }
            Self::InvalidOffset => output.write_str("invalid ZIM offset table"),
            Self::InvalidDirectoryEntry => output.write_str("invalid ZIM directory entry"),
            Self::InvalidCluster => output.write_str("invalid ZIM cluster"),
            Self::UnsupportedCompression(kind) => {
                write!(output, "unsupported ZIM cluster compression {kind}")
            }
            Self::Decompression => output.write_str("failed to decompress ZIM cluster"),
            Self::InvalidUtf8 => output.write_str("ZIM text is not valid UTF-8"),
            Self::Allocation => output.write_str("not enough memory for ZIM data"),
            Self::BudgetExceeded => output.write_str("ZIM parser budget exceeded"),
        }
    }
}

impl core::error::Error for Error {}
impl From<mrml_runtime::FileError> for Error {
    fn from(error: mrml_runtime::FileError) -> Self {
        Self::File(error)
    }
}
pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Header {
    pub major_version: u16,
    pub minor_version: u16,
    pub uuid: [u8; 16],
    pub entry_count: u32,
    pub cluster_count: u32,
    pub url_pointer_position: u64,
    pub title_pointer_position: u64,
    pub cluster_pointer_position: u64,
    pub mime_list_position: u64,
    pub main_page: u32,
    pub layout_page: u32,
    pub checksum_position: u64,
}

impl Header {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_BYTES {
            return Err(Error::InvalidOffset);
        }
        let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        if magic != ZIM_MAGIC {
            return Err(Error::InvalidMagic(magic));
        }
        let major_version = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
        let minor_version = u16::from_le_bytes(bytes[6..8].try_into().unwrap());
        if major_version != 6 {
            return Err(Error::UnsupportedVersion(major_version, minor_version));
        }
        Ok(Self {
            major_version,
            minor_version,
            uuid: bytes[8..24].try_into().unwrap(),
            entry_count: le_u32(bytes, 24),
            cluster_count: le_u32(bytes, 28),
            url_pointer_position: le_u64(bytes, 32),
            title_pointer_position: le_u64(bytes, 40),
            cluster_pointer_position: le_u64(bytes, 48),
            mime_list_position: le_u64(bytes, 56),
            main_page: le_u32(bytes, 64),
            layout_page: le_u32(bytes, 68),
            checksum_position: le_u64(bytes, 72),
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum EntryLocation {
    Redirect(u32),
    Blob { cluster: u32, blob: u32 },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DirectoryEntry {
    pub mime_type: u16,
    pub namespace: u8,
    pub revision: u32,
    pub path: Text,
    pub title: Text,
    pub location: EntryLocation,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Compression {
    None,
    Zstd,
    Unknown(u8),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ClusterInfo {
    pub offset: u64,
    pub compressed_bytes: u64,
    pub compression: Compression,
    pub extended_offsets: bool,
}

pub struct Archive {
    file: File,
    header: Header,
    cluster_offsets: Vector<u64>,
    mime_types: Vector<Text>,
    decoded_clusters: Vector<DecodedCluster>,
    cluster_cache_capacity: usize,
}

struct DecodedCluster {
    index: u32,
    extended_offsets: bool,
    bytes: Vector<u8>,
}

impl Archive {
    pub fn open(path: &str) -> Result<Self> {
        let mut file = File::open(path)?;
        let mut bytes = [0; HEADER_BYTES];
        file.read_exact(&mut bytes)?;
        let header = Header::parse(&bytes)?;
        let length = file.len()?;
        validate_layout(&header, length)?;
        file.seek(header.mime_list_position)?;
        let mut mime_types = Vector::new();
        let mut mime_bytes = 0usize;
        loop {
            if mime_types.len() == MAX_MIME_TYPES {
                return Err(Error::BudgetExceeded);
            }
            let mime = read_zero_text(&mut file, header.checksum_position)?;
            if mime.is_empty() {
                break;
            }
            mime_bytes = mime_bytes
                .checked_add(mime.len())
                .filter(|bytes| *bytes <= MAX_MIME_BYTES)
                .ok_or(Error::BudgetExceeded)?;
            mime_types.try_push(mime).map_err(|_| Error::Allocation)?;
        }
        let mime_end = file.position();
        file.seek(header.cluster_pointer_position)?;
        let cluster_count =
            usize::try_from(header.cluster_count).map_err(|_| Error::InvalidOffset)?;
        let capacity = cluster_count.checked_add(1).ok_or(Error::InvalidOffset)?;
        let mut cluster_offsets =
            Vector::with_capacity(capacity).map_err(|_| Error::InvalidOffset)?;
        for _ in 0..header.cluster_count {
            cluster_offsets
                .try_push(read_u64(&mut file)?)
                .map_err(|_| Error::Allocation)?;
        }
        cluster_offsets
            .try_push(header.checksum_position)
            .map_err(|_| Error::Allocation)?;
        let data_floor = table_end(header.url_pointer_position, header.entry_count, 8)?
            .max(table_end(
                header.title_pointer_position,
                header.entry_count,
                4,
            )?)
            .max(table_end(
                header.cluster_pointer_position,
                header.cluster_count,
                8,
            )?)
            .max(mime_end);
        if cluster_offsets
            .first()
            .is_some_and(|offset| *offset < data_floor)
            || cluster_offsets.windows(2).any(|pair| {
                pair[0] >= pair[1]
                    || pair[1] > header.checksum_position
                    || pair[1] - pair[0] > MAX_CLUSTER_BYTES
            })
        {
            return Err(Error::InvalidOffset);
        }
        Ok(Self {
            file,
            header,
            cluster_offsets,
            mime_types,
            decoded_clusters: Vector::new(),
            cluster_cache_capacity: 1,
        })
    }

    pub fn set_cluster_cache_capacity(&mut self, capacity: usize) {
        self.cluster_cache_capacity = capacity.max(1);
        while self.decoded_clusters.len() > self.cluster_cache_capacity {
            self.decoded_clusters.remove(0);
        }
    }

    pub fn header(&self) -> &Header {
        &self.header
    }
    pub fn mime_types(&self) -> &[Text] {
        &self.mime_types
    }
    pub fn mime_type(&self, index: u16) -> Option<&str> {
        self.mime_types.get(index as usize).map(Text::as_str)
    }

    pub fn cluster_info(&mut self, cluster: u32) -> Result<ClusterInfo> {
        let offset = *self
            .cluster_offsets
            .get(cluster as usize)
            .ok_or(Error::InvalidOffset)?;
        let end = *self
            .cluster_offsets
            .get(cluster as usize + 1)
            .ok_or(Error::InvalidOffset)?;
        self.file.seek(offset)?;
        let descriptor = read_u8(&mut self.file)?;
        let compression = match descriptor & 0x0f {
            0 | 1 => Compression::None,
            5 => Compression::Zstd,
            value => Compression::Unknown(value),
        };
        Ok(ClusterInfo {
            offset,
            compressed_bytes: end.checked_sub(offset).ok_or(Error::InvalidCluster)?,
            compression,
            extended_offsets: descriptor & 0x10 != 0,
        })
    }

    /// Copies the cluster payload exactly as stored, excluding its descriptor.
    /// This allows the native Zstandard decoder to consume clusters without
    /// loading the complete archive or relying on temporary files.
    pub fn read_cluster_payload(&mut self, cluster: u32) -> Result<Vector<u8>> {
        let info = self.cluster_info(cluster)?;
        let length = usize::try_from(
            info.compressed_bytes
                .checked_sub(1)
                .ok_or(Error::InvalidCluster)?,
        )
        .map_err(|_| Error::InvalidCluster)?;
        let mut output = Vector::with_capacity(length).map_err(|_| Error::Allocation)?;
        output.resize(length, 0);
        self.file.read_exact(&mut output)?;
        Ok(output)
    }

    pub fn entry(&mut self, index: u32) -> Result<DirectoryEntry> {
        if index >= self.header.entry_count {
            return Err(Error::InvalidOffset);
        }
        self.file.seek(checked_table_item(
            self.header.url_pointer_position,
            index,
            8,
        )?)?;
        let offset = read_u64(&mut self.file)?;
        if offset < HEADER_BYTES as u64 || offset >= self.header.checksum_position {
            return Err(Error::InvalidDirectoryEntry);
        }
        if offset
            .checked_add(12)
            .is_none_or(|end| end > self.header.checksum_position)
        {
            return Err(Error::InvalidDirectoryEntry);
        }
        self.file.seek(offset)?;
        let mime_type = read_u16(&mut self.file)?;
        let parameter_len = read_u8(&mut self.file)? as usize;
        let namespace = read_u8(&mut self.file)?;
        let revision = read_u32(&mut self.file)?;
        let location = if mime_type == u16::MAX {
            EntryLocation::Redirect(read_u32(&mut self.file)?)
        } else {
            if offset
                .checked_add(16)
                .is_none_or(|end| end > self.header.checksum_position)
            {
                return Err(Error::InvalidDirectoryEntry);
            }
            EntryLocation::Blob {
                cluster: read_u32(&mut self.file)?,
                blob: read_u32(&mut self.file)?,
            }
        };
        let path = read_zero_text(&mut self.file, self.header.checksum_position)?;
        let title = read_zero_text(&mut self.file, self.header.checksum_position)?;
        let position = self.file.position();
        let parameter_end = position
            .checked_add(u64::try_from(parameter_len).map_err(|_| Error::InvalidOffset)?)
            .ok_or(Error::InvalidOffset)?;
        if parameter_end > self.header.checksum_position {
            return Err(Error::InvalidDirectoryEntry);
        }
        self.file.seek(parameter_end)?;
        match &location {
            EntryLocation::Redirect(target) if *target >= self.header.entry_count => {
                return Err(Error::InvalidDirectoryEntry);
            }
            EntryLocation::Blob { cluster, .. } if *cluster >= self.header.cluster_count => {
                return Err(Error::InvalidDirectoryEntry);
            }
            _ => {}
        }
        Ok(DirectoryEntry {
            mime_type,
            namespace,
            revision,
            path,
            title,
            location,
        })
    }

    /// Reads a blob from an uncompressed cluster. Compressed clusters are
    /// reported explicitly so a decompressor can be layered without changing
    /// directory parsing or dataset streaming APIs.
    pub fn read_blob(&mut self, cluster: u32, blob: u32) -> Result<Vector<u8>> {
        let start = *self
            .cluster_offsets
            .get(cluster as usize)
            .ok_or(Error::InvalidOffset)?;
        let end = *self
            .cluster_offsets
            .get(cluster as usize + 1)
            .ok_or(Error::InvalidOffset)?;
        self.file.seek(start)?;
        let descriptor = read_u8(&mut self.file)?;
        let compression = descriptor & 0x0f;
        if compression != 0 && compression != 1 {
            return Err(Error::UnsupportedCompression(compression));
        }
        let wide = descriptor & 0x10 != 0;
        let length = usize::try_from(
            end.checked_sub(start)
                .and_then(|length| length.checked_sub(1))
                .ok_or(Error::InvalidCluster)?,
        )
        .map_err(|_| Error::InvalidCluster)?;
        let mut bytes = Vector::with_capacity(length).map_err(|_| Error::Allocation)?;
        bytes.resize(length, 0);
        self.file.read_exact(&mut bytes)?;
        blob_from_cluster(&bytes, wide, blob)
    }

    pub fn read_blob_with<T: ZstdTransport>(
        &mut self,
        cluster: u32,
        blob: u32,
        transport: &mut T,
    ) -> Result<Vector<u8>> {
        let info = self.cluster_info(cluster)?;
        if let Some(cached) = self
            .decoded_clusters
            .iter()
            .find(|cached| cached.index == cluster)
        {
            return blob_from_cluster(&cached.bytes, cached.extended_offsets, blob);
        }
        {
            let payload = self.read_cluster_payload(cluster)?;
            let bytes = match info.compression {
                Compression::None => payload,
                Compression::Zstd => decode_zstd(transport, &payload)?,
                Compression::Unknown(kind) => return Err(Error::UnsupportedCompression(kind)),
            };
            if self.decoded_clusters.len() == self.cluster_cache_capacity {
                self.decoded_clusters.remove(0);
            }
            self.decoded_clusters.push(DecodedCluster {
                index: cluster,
                extended_offsets: info.extended_offsets,
                bytes,
            });
        }
        let cached = self.decoded_clusters.last().ok_or(Error::InvalidCluster)?;
        blob_from_cluster(&cached.bytes, cached.extended_offsets, blob)
    }
}

fn decode_zstd<T: ZstdTransport>(transport: &mut T, compressed: &[u8]) -> Result<Vector<u8>> {
    const MAX_OUTPUT: usize = 512 * 1024 * 1024;
    let initial = compressed
        .len()
        .checked_mul(4)
        .unwrap_or(MAX_OUTPUT)
        .clamp(4096, MAX_OUTPUT);
    let mut output_capacity = initial;
    loop {
        let total = compressed
            .len()
            .checked_add(output_capacity)
            .ok_or(Error::Allocation)?;
        let mut memory = Vector::with_capacity(total).map_err(|_| Error::Allocation)?;
        memory.resize(total, 0);
        memory[..compressed.len()].copy_from_slice(compressed);
        let input = BorrowedReadView::within(0, compressed.len() as u64, total as u64)
            .ok_or(Error::Decompression)?;
        let output = BorrowedWriteView::within(
            compressed.len() as u64,
            output_capacity as u64,
            total as u64,
        )
        .ok_or(Error::Decompression)?;
        let request = encode_decompress_request(input, output).map_err(|_| Error::Decompression)?;
        let response = transport
            .call(&request, &mut memory)
            .map_err(|_| Error::Decompression)?;
        match decode_decompress_response(&response).map_err(|_| Error::Decompression)? {
            Ok(written) => {
                let written = usize::try_from(written).map_err(|_| Error::Decompression)?;
                if written > output_capacity {
                    return Err(Error::Decompression);
                }
                let start = compressed.len();
                let mut decoded = Vector::with_capacity(written).map_err(|_| Error::Allocation)?;
                decoded
                    .try_extend_from_slice(&memory[start..start + written])
                    .map_err(|_| Error::Allocation)?;
                return Ok(decoded);
            }
            Err((DecompressError::OutputTooSmall, required)) => {
                let required = usize::try_from(required).map_err(|_| Error::Decompression)?;
                if required <= output_capacity || required > MAX_OUTPUT {
                    return Err(Error::Decompression);
                }
                output_capacity = required;
            }
            Err((DecompressError::InvalidFrame, _)) => return Err(Error::Decompression),
        }
    }
}

fn blob_from_cluster(bytes: &[u8], wide: bool, blob: u32) -> Result<Vector<u8>> {
    let width: usize = if wide { 8 } else { 4 };
    if bytes.len() < width {
        return Err(Error::InvalidCluster);
    }
    let first = if wide {
        u64::from_le_bytes(bytes[..8].try_into().unwrap())
    } else {
        u32::from_le_bytes(bytes[..4].try_into().unwrap()) as u64
    };
    let width: u64 = if wide { 8 } else { 4 };
    if first < width || first % width != 0 {
        return Err(Error::InvalidCluster);
    }
    if first > bytes.len() as u64 {
        return Err(Error::InvalidCluster);
    }
    let count = usize::try_from(first / width)
        .map_err(|_| Error::InvalidCluster)?
        .checked_sub(1)
        .ok_or(Error::InvalidCluster)?;
    let blob = usize::try_from(blob).map_err(|_| Error::InvalidCluster)?;
    if blob >= count {
        return Err(Error::InvalidCluster);
    }
    let width = usize::try_from(width).map_err(|_| Error::InvalidCluster)?;
    let offset = blob.checked_mul(width).ok_or(Error::InvalidCluster)?;
    let blob_start = read_offset(bytes, offset, wide)?;
    let blob_end = read_offset(
        bytes,
        offset.checked_add(width).ok_or(Error::InvalidCluster)?,
        wide,
    )?;
    if blob_start > blob_end || blob_end > bytes.len() as u64 {
        return Err(Error::InvalidCluster);
    }
    let length = usize::try_from(blob_end - blob_start).map_err(|_| Error::InvalidCluster)?;
    let mut output = Vector::with_capacity(length).map_err(|_| Error::InvalidCluster)?;
    output
        .try_extend_from_slice(&bytes[blob_start as usize..blob_end as usize])
        .map_err(|_| Error::Allocation)?;
    Ok(output)
}

fn read_offset(bytes: &[u8], offset: usize, wide: bool) -> Result<u64> {
    if wide {
        bytes
            .get(offset..offset.checked_add(8).ok_or(Error::InvalidCluster)?)
            .map(|value| u64::from_le_bytes(value.try_into().unwrap()))
            .ok_or(Error::InvalidCluster)
    } else {
        bytes
            .get(offset..offset.checked_add(4).ok_or(Error::InvalidCluster)?)
            .map(|value| u32::from_le_bytes(value.try_into().unwrap()) as u64)
            .ok_or(Error::InvalidCluster)
    }
}

fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn le_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn read_u8(file: &mut File) -> Result<u8> {
    let mut b = [0];
    file.read_exact(&mut b)?;
    Ok(b[0])
}
fn read_u16(file: &mut File) -> Result<u16> {
    let mut b = [0; 2];
    file.read_exact(&mut b)?;
    Ok(u16::from_le_bytes(b))
}
fn read_u32(file: &mut File) -> Result<u32> {
    let mut b = [0; 4];
    file.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}
fn read_u64(file: &mut File) -> Result<u64> {
    let mut b = [0; 8];
    file.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}
fn read_zero_text(file: &mut File, end: u64) -> Result<Text> {
    let mut bytes = Vector::new();
    loop {
        if file.position() >= end {
            return Err(Error::InvalidOffset);
        }
        let byte = read_u8(file)?;
        if byte == 0 {
            break;
        }
        if bytes.len() == MAX_STRING_BYTES {
            return Err(Error::BudgetExceeded);
        }
        bytes.try_push(byte).map_err(|_| Error::Allocation)?;
    }
    core::str::from_utf8(&bytes)
        .map(Text::from)
        .map_err(|_| Error::InvalidUtf8)
}

fn checked_range(start: u64, count: u32, width: u64, end: u64) -> Result<()> {
    let range_end = table_end(start, count, width)?;
    if start < HEADER_BYTES as u64 || range_end > end {
        return Err(Error::InvalidOffset);
    }
    Ok(())
}

fn table_end(start: u64, count: u32, width: u64) -> Result<u64> {
    start
        .checked_add(
            u64::from(count)
                .checked_mul(width)
                .ok_or(Error::InvalidOffset)?,
        )
        .ok_or(Error::InvalidOffset)
}

fn checked_table_item(start: u64, index: u32, width: u64) -> Result<u64> {
    start
        .checked_add(
            u64::from(index)
                .checked_mul(width)
                .ok_or(Error::InvalidOffset)?,
        )
        .ok_or(Error::InvalidOffset)
}

fn validate_layout(header: &Header, length: u64) -> Result<()> {
    if length > MAX_ARCHIVE_BYTES
        || header.entry_count > MAX_ENTRIES
        || header.cluster_count > MAX_CLUSTERS
    {
        return Err(Error::BudgetExceeded);
    }
    if header
        .checksum_position
        .checked_add(CHECKSUM_BYTES)
        .is_none_or(|end| end != length)
        || header.mime_list_position < HEADER_BYTES as u64
        || header.mime_list_position >= header.checksum_position
    {
        return Err(Error::InvalidOffset);
    }
    checked_range(
        header.url_pointer_position,
        header.entry_count,
        8,
        header.checksum_position,
    )?;
    checked_range(
        header.title_pointer_position,
        header.entry_count,
        4,
        header.checksum_position,
    )?;
    checked_range(
        header.cluster_pointer_position,
        header.cluster_count,
        8,
        header.checksum_position,
    )?;
    for page in [header.main_page, header.layout_page] {
        if page != u32::MAX && page >= header.entry_count {
            return Err(Error::InvalidOffset);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn archive_path(label: &str) -> Text {
        mrml_runtime::join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-zim-{label}-{}.zim", mrml_runtime::process_id()),
        )
    }

    fn write_header(bytes: &mut [u8], header: &Header) {
        bytes[0..4].copy_from_slice(&ZIM_MAGIC.to_le_bytes());
        bytes[4..6].copy_from_slice(&header.major_version.to_le_bytes());
        bytes[6..8].copy_from_slice(&header.minor_version.to_le_bytes());
        bytes[8..24].copy_from_slice(&header.uuid);
        bytes[24..28].copy_from_slice(&header.entry_count.to_le_bytes());
        bytes[28..32].copy_from_slice(&header.cluster_count.to_le_bytes());
        bytes[32..40].copy_from_slice(&header.url_pointer_position.to_le_bytes());
        bytes[40..48].copy_from_slice(&header.title_pointer_position.to_le_bytes());
        bytes[48..56].copy_from_slice(&header.cluster_pointer_position.to_le_bytes());
        bytes[56..64].copy_from_slice(&header.mime_list_position.to_le_bytes());
        bytes[64..68].copy_from_slice(&header.main_page.to_le_bytes());
        bytes[68..72].copy_from_slice(&header.layout_page.to_le_bytes());
        bytes[72..80].copy_from_slice(&header.checksum_position.to_le_bytes());
    }

    fn open_bytes(label: &str, bytes: &[u8]) -> Result<()> {
        let path = archive_path(label);
        if mrml_runtime::path_exists(&path) {
            mrml_runtime::remove_file(&path).unwrap();
        }
        mrml_runtime::write_file(&path, bytes).unwrap();
        let result = Archive::open(&path).map(drop);
        mrml_runtime::remove_file(&path).unwrap();
        result
    }

    fn valid_header() -> Header {
        Header {
            major_version: 6,
            minor_version: 1,
            uuid: [0; 16],
            entry_count: 1,
            cluster_count: 1,
            url_pointer_position: 80,
            title_pointer_position: 88,
            cluster_pointer_position: 92,
            mime_list_position: 100,
            main_page: 0,
            layout_page: u32::MAX,
            checksum_position: 128,
        }
    }

    #[test]
    fn parses_version_six_header() {
        let mut bytes = [0u8; 80];
        bytes[0..4].copy_from_slice(&ZIM_MAGIC.to_le_bytes());
        bytes[4..6].copy_from_slice(&6u16.to_le_bytes());
        bytes[6..8].copy_from_slice(&1u16.to_le_bytes());
        bytes[24..28].copy_from_slice(&7u32.to_le_bytes());
        bytes[28..32].copy_from_slice(&3u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&4096u64.to_le_bytes());
        let header = Header::parse(&bytes).unwrap();
        assert_eq!(header.entry_count, 7);
        assert_eq!(header.cluster_count, 3);
        assert_eq!(header.checksum_position, 4096);
    }

    #[test]
    fn rejects_other_files_and_versions() {
        assert!(matches!(
            Header::parse(&[0; 80]),
            Err(Error::InvalidMagic(0))
        ));
        let mut bytes = [0u8; 80];
        bytes[0..4].copy_from_slice(&ZIM_MAGIC.to_le_bytes());
        bytes[4..6].copy_from_slice(&5u16.to_le_bytes());
        assert!(matches!(
            Header::parse(&bytes),
            Err(Error::UnsupportedVersion(5, 0))
        ));
    }

    #[test]
    fn rejects_unbounded_counts_and_out_of_range_tables() {
        let mut header = valid_header();
        assert_eq!(validate_layout(&header, 144), Ok(()));

        header.entry_count = MAX_ENTRIES + 1;
        assert_eq!(validate_layout(&header, 144), Err(Error::BudgetExceeded));
        header = valid_header();
        header.cluster_count = MAX_CLUSTERS + 1;
        assert_eq!(validate_layout(&header, 144), Err(Error::BudgetExceeded));
        header = valid_header();
        header.url_pointer_position = u64::MAX - 3;
        assert_eq!(validate_layout(&header, 144), Err(Error::InvalidOffset));
        header = valid_header();
        header.checksum_position = 129;
        assert_eq!(validate_layout(&header, 144), Err(Error::InvalidOffset));
        header = valid_header();
        header.main_page = 1;
        assert_eq!(validate_layout(&header, 144), Err(Error::InvalidOffset));
    }

    #[test]
    fn rejects_unterminated_mime_lists_bad_cluster_offsets_and_checksum_extent() {
        let mut header = valid_header();
        header.entry_count = 0;
        header.cluster_count = 0;
        header.url_pointer_position = 80;
        header.title_pointer_position = 80;
        header.cluster_pointer_position = 80;
        header.mime_list_position = 80;
        header.main_page = u32::MAX;
        let mut bytes = [0u8; 144];
        write_header(&mut bytes, &header);
        assert!(open_bytes("valid-empty", &bytes).is_ok());

        header.checksum_position = 84;
        let mut unterminated = [0u8; 100];
        write_header(&mut unterminated, &header);
        unterminated[80..84].copy_from_slice(b"text");
        assert!(matches!(
            open_bytes("unterminated-mime", &unterminated),
            Err(Error::InvalidOffset)
        ));

        header = valid_header();
        let mut short_checksum = [0u8; 143];
        write_header(&mut short_checksum, &header);
        assert!(matches!(
            open_bytes("short-checksum", &short_checksum),
            Err(Error::InvalidOffset)
        ));

        header.entry_count = 0;
        header.cluster_count = 2;
        header.url_pointer_position = 80;
        header.title_pointer_position = 80;
        header.cluster_pointer_position = 80;
        header.mime_list_position = 96;
        header.main_page = u32::MAX;
        let mut duplicate_clusters = [0u8; 144];
        write_header(&mut duplicate_clusters, &header);
        duplicate_clusters[80..88].copy_from_slice(&112u64.to_le_bytes());
        duplicate_clusters[88..96].copy_from_slice(&112u64.to_le_bytes());
        assert!(matches!(
            open_bytes("duplicate-clusters", &duplicate_clusters),
            Err(Error::InvalidOffset)
        ));
    }

    #[test]
    fn opens_external_archive_when_configured() {
        let Some(path) = mrml_runtime::environment_variable("MRML_TEST_ZIM") else {
            return;
        };
        let mut archive = Archive::open(&path).expect("open configured ZIM archive");
        assert!(archive.header().entry_count > 0);
        assert!(archive.header().cluster_count > 0);
        assert!(archive.mime_types().iter().any(|mime| mime == "text/html"));
        assert!(matches!(
            archive.cluster_info(0).unwrap().compression,
            Compression::Zstd
        ));
        let payload = archive.read_cluster_payload(0).unwrap();
        assert_eq!(payload.get(..4), Some(&[0x28, 0xb5, 0x2f, 0xfd][..]));
        let entry = archive.entry(0).expect("read first directory entry");
        assert!(!entry.path.is_empty());
    }

    #[test]
    fn extracts_blob_from_decoded_cluster() {
        let mut cluster = Vector::new();
        cluster
            .try_extend_from_slice(&[12, 0, 0, 0, 15, 0, 0, 0, 19, 0, 0, 0])
            .unwrap();
        cluster.try_extend_from_slice(b"onefour").unwrap();
        let first = blob_from_cluster(&cluster, false, 0).unwrap();
        let second = blob_from_cluster(&cluster, false, 1).unwrap();
        assert_eq!(&*first, b"one");
        assert_eq!(&*second, b"four");
        assert!(matches!(
            blob_from_cluster(&cluster, false, 2),
            Err(Error::InvalidCluster)
        ));

        let mut outside = cluster.clone();
        outside[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            blob_from_cluster(&outside, false, 0),
            Err(Error::InvalidCluster)
        );
        let mut reversed = cluster.clone();
        reversed[4..8].copy_from_slice(&18u32.to_le_bytes());
        reversed[8..12].copy_from_slice(&17u32.to_le_bytes());
        assert_eq!(
            blob_from_cluster(&reversed, false, 1),
            Err(Error::InvalidCluster)
        );
    }
}
