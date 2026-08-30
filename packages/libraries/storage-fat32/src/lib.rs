#![no_std]

//! Bounded FAT32 interoperability provider for ESP/install/recovery media.
//!
//! Native MRML storage does not inherit FAT authority or namespace semantics.

mod service_loop;
mod mount_service_loop;
mod userspace_syscall_adapter;

use mrml_interface_storage_block_provider_v1::{
    decode_read_response as decode_block_read_response,
    encode_read_request as encode_block_read_request, BlockProviderReadTransport,
    BorrowedWriteView as BlockBorrowedWriteView, OpaqueHandle as BlockOpaqueHandle,
    ProtocolError as BlockProtocolError, ReadError as BlockReadError,
};
use mrml_interface_storage_filesystem_v2::{
    decode_mount_request, decode_probe_request, encode_mount_response, encode_probe_response,
    FilesystemMountTransport, FilesystemTransport, MountError, MountResponse, OpaqueHandle,
    ProbeError, ProtocolError, MOUNT_REQUEST_BYTES, MOUNT_RESPONSE_BYTES, PROBE_REQUEST_BYTES,
    PROBE_RESPONSE_BYTES,
};

pub use service_loop::{
    Fat32ServiceLoop, Fat32ServiceLoopError, Fat32ServiceSyscalls, ReceivedFat32Envelope,
};
pub use mount_service_loop::{
    Fat32MountServiceLoop, Fat32MountServiceLoopError, Fat32MountServiceSyscalls,
    ReceivedFat32MountEnvelope,
};
pub use userspace_syscall_adapter::{
    Fat32MountUserspaceSyscalls, Fat32RawSyscall, Fat32SyscallFrame,
    Fat32UserspaceSyscallError, Fat32UserspaceSyscalls,
};

pub const FAT32_BOOT_SECTOR_BYTES: usize = 512;
pub const FAT32_MINIMUM_CLUSTERS: u32 = 65_525;
pub const FAT32_MAXIMUM_CLUSTERS: u32 = 0x0fff_fff4;

pub struct Fat32Provider;

impl FilesystemTransport for Fat32Provider {
    fn probe(
        &mut self,
        request: &[u8; PROBE_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; PROBE_RESPONSE_BYTES], ProtocolError> {
        let request = decode_probe_request(request, memory.len() as u64)?;
        if request.header.length() < FAT32_BOOT_SECTOR_BYTES as u64 {
            return Ok(encode_probe_response(Err(ProbeError::InvalidRequest)));
        }
        let start =
            usize::try_from(request.header.offset()).map_err(|_| ProtocolError::InvalidRequest)?;
        let end = start
            .checked_add(FAT32_BOOT_SECTOR_BYTES)
            .ok_or(ProtocolError::InvalidRequest)?;
        let mut sector = [0; FAT32_BOOT_SECTOR_BYTES];
        sector.copy_from_slice(
            memory
                .get(start..end)
                .ok_or(ProtocolError::InvalidRequest)?,
        );
        let result = parse_fat32_boot_sector(&sector)
            .map(|_| 100)
            .map_err(|_| ProbeError::UnsupportedFilesystem);
        sector.fill(0);
        Ok(encode_probe_response(result))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fat32Geometry {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub fat_count: u8,
    pub sectors_per_fat: u32,
    pub mirroring_enabled: bool,
    pub active_fat: u8,
    pub total_sectors: u32,
    pub data_start_sector: u32,
    pub data_sectors: u32,
    pub cluster_count: u32,
    pub root_cluster: u32,
    pub fs_info_sector: Option<u16>,
    pub backup_boot_sector: Option<u16>,
    pub volume_id: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fat32MountError {
    AlreadyMounted,
    Capacity,
    GenerationExhausted,
    CompletionExhausted,
    StaleMount,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fat32Unmounted {
    pub serial: u64,
    pub root: OpaqueHandle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Fat32Mount {
    volume: OpaqueHandle,
    generation: u64,
    root: OpaqueHandle,
    geometry: Fat32Geometry,
}

pub struct Fat32MountTable<const N: usize> {
    mounts: [Option<Fat32Mount>; N],
    next_mount_generation: Option<u64>,
    next_root_generation: Option<u32>,
    next_completion_serial: Option<u64>,
}

impl<const N: usize> Fat32MountTable<N> {
    pub const fn new() -> Self {
        Self {
            mounts: [None; N],
            next_mount_generation: Some(1),
            next_root_generation: Some(1),
            next_completion_serial: Some(1),
        }
    }

    pub fn mount(
        &mut self,
        volume: OpaqueHandle,
        geometry: Fat32Geometry,
    ) -> Result<MountResponse, Fat32MountError> {
        if self
            .mounts
            .iter()
            .flatten()
            .any(|mount| mount.volume == volume)
        {
            return Err(Fat32MountError::AlreadyMounted);
        }
        let slot = self
            .mounts
            .iter()
            .position(Option::is_none)
            .ok_or(Fat32MountError::Capacity)?;
        let generation = self
            .next_mount_generation
            .ok_or(Fat32MountError::GenerationExhausted)?;
        let root_generation = self
            .next_root_generation
            .ok_or(Fat32MountError::GenerationExhausted)?;
        let root_index = u32::try_from(slot).map_err(|_| Fat32MountError::Capacity)?;
        let root = OpaqueHandle::new(root_index, root_generation)
            .ok_or(Fat32MountError::GenerationExhausted)?;
        self.next_mount_generation = generation.checked_add(1);
        self.next_root_generation = root_generation.checked_add(1);
        self.mounts[slot] = Some(Fat32Mount {
            volume,
            generation,
            root,
            geometry,
        });
        Ok(MountResponse { generation, root })
    }

    pub fn geometry(
        &self,
        volume: OpaqueHandle,
        generation: u64,
        root: OpaqueHandle,
    ) -> Result<Fat32Geometry, Fat32MountError> {
        self.mounts
            .iter()
            .flatten()
            .find(|mount| {
                mount.volume == volume && mount.generation == generation && mount.root == root
            })
            .map(|mount| mount.geometry)
            .ok_or(Fat32MountError::StaleMount)
    }

    pub fn unmount(
        &mut self,
        volume: OpaqueHandle,
        generation: u64,
    ) -> Result<Fat32Unmounted, Fat32MountError> {
        let slot = self
            .mounts
            .iter()
            .position(|mount| {
                mount.is_some_and(|mount| {
                    mount.volume == volume && mount.generation == generation
                })
            })
            .ok_or(Fat32MountError::StaleMount)?;
        let serial = self
            .next_completion_serial
            .ok_or(Fat32MountError::CompletionExhausted)?;
        let root = self.mounts[slot]
            .take()
            .ok_or(Fat32MountError::StaleMount)?
            .root;
        self.next_completion_serial = serial.checked_add(1);
        Ok(Fat32Unmounted { serial, root })
    }

    #[cfg(test)]
    const fn with_next_generations(mount: u64, root: u32, completion: u64) -> Self {
        Self {
            mounts: [None; N],
            next_mount_generation: Some(mount),
            next_root_generation: Some(root),
            next_completion_serial: Some(completion),
        }
    }
}

impl<const N: usize> Default for Fat32MountTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Trusted exact-volume source for FAT32 mount admission.
///
/// # Safety
///
/// An implementation must read sector zero only from the block volume identified
/// by the exact opaque handle supplied to `read_boot_sector`. Success must fill
/// the complete destination from that same live volume generation.
pub unsafe trait Fat32MountBackend {
    type Error;

    fn read_boot_sector(
        &mut self,
        volume: OpaqueHandle,
        output: &mut [u8; FAT32_BOOT_SECTOR_BYTES],
    ) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fat32BlockBinding {
    volume: OpaqueHandle,
    session: BlockOpaqueHandle,
    logical_block_bytes: u32,
}

impl Fat32BlockBinding {
    /// Creates a cross-service binding after the runtime has proven that the
    /// block session is the exact storage backing for `volume`.
    ///
    /// # Safety
    ///
    /// The caller must hold the authoritative runtime association between these
    /// two live generations. Matching numeric fields, names, or media labels is
    /// insufficient.
    pub unsafe fn new(
        volume: OpaqueHandle,
        session: BlockOpaqueHandle,
        logical_block_bytes: u32,
    ) -> Option<Self> {
        if logical_block_bytes < FAT32_BOOT_SECTOR_BYTES as u32
            || logical_block_bytes > 65_536
            || !logical_block_bytes.is_power_of_two()
        {
            return None;
        }
        Some(Self {
            volume,
            session,
            logical_block_bytes,
        })
    }

    pub const fn volume(self) -> OpaqueHandle {
        self.volume
    }

    pub const fn session(self) -> BlockOpaqueHandle {
        self.session
    }

    pub const fn logical_block_bytes(self) -> u32 {
        self.logical_block_bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fat32BlockMountError {
    VolumeMismatch,
    InvalidScratch,
    Protocol(BlockProtocolError),
    Read(BlockReadError),
    ShortRead,
}

pub struct Fat32BlockMountBackend<'a, T> {
    binding: Fat32BlockBinding,
    transport: T,
    scratch: &'a mut [u8],
}

impl<'a, T> Fat32BlockMountBackend<'a, T> {
    pub fn new(
        binding: Fat32BlockBinding,
        transport: T,
        scratch: &'a mut [u8],
    ) -> Result<Self, Fat32BlockMountError> {
        if scratch.len() != binding.logical_block_bytes as usize {
            scratch.fill(0);
            return Err(Fat32BlockMountError::InvalidScratch);
        }
        scratch.fill(0);
        Ok(Self {
            binding,
            transport,
            scratch,
        })
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

unsafe impl<T: BlockProviderReadTransport> Fat32MountBackend for Fat32BlockMountBackend<'_, T> {
    type Error = Fat32BlockMountError;

    fn read_boot_sector(
        &mut self,
        volume: OpaqueHandle,
        output: &mut [u8; FAT32_BOOT_SECTOR_BYTES],
    ) -> Result<(), Self::Error> {
        output.fill(0);
        if volume != self.binding.volume {
            return Err(Fat32BlockMountError::VolumeMismatch);
        }
        self.scratch.fill(0);
        let result = (|| {
            let view = BlockBorrowedWriteView::within(
                0,
                u64::from(self.binding.logical_block_bytes),
                u64::from(self.binding.logical_block_bytes),
            )
            .ok_or(Fat32BlockMountError::InvalidScratch)?;
            let request = encode_block_read_request(self.binding.session, 0, 1, view)
                .map_err(Fat32BlockMountError::Protocol)?;
            let response = self
                .transport
                .read(&request, self.scratch)
                .map_err(Fat32BlockMountError::Protocol)?;
            let transferred =
                decode_block_read_response(&response, u64::from(self.binding.logical_block_bytes))
                    .map_err(Fat32BlockMountError::Protocol)?
                    .map_err(Fat32BlockMountError::Read)?;
            if transferred != u64::from(self.binding.logical_block_bytes) {
                return Err(Fat32BlockMountError::ShortRead);
            }
            output.copy_from_slice(&self.scratch[..FAT32_BOOT_SECTOR_BYTES]);
            Ok(())
        })();
        self.scratch.fill(0);
        if result.is_err() {
            output.fill(0);
        }
        result
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fat32MountAdmissionError<E> {
    Backend(E),
    InvalidFilesystem(Fat32Error),
    Lifecycle(Fat32MountError),
}

pub struct Fat32MountedProvider<B, const N: usize> {
    backend: B,
    mounts: Fat32MountTable<N>,
}

impl<B, const N: usize> Fat32MountedProvider<B, N> {
    pub const fn new(backend: B) -> Self {
        Self {
            backend,
            mounts: Fat32MountTable::new(),
        }
    }

    pub fn into_backend(self) -> B {
        self.backend
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    pub fn geometry(
        &self,
        volume: OpaqueHandle,
        generation: u64,
        root: OpaqueHandle,
    ) -> Result<Fat32Geometry, Fat32MountError> {
        self.mounts.geometry(volume, generation, root)
    }

    pub fn unmount(
        &mut self,
        volume: OpaqueHandle,
        generation: u64,
    ) -> Result<Fat32Unmounted, Fat32MountError> {
        self.mounts.unmount(volume, generation)
    }
}

impl<B: Fat32MountBackend, const N: usize> Fat32MountedProvider<B, N> {
    pub fn mount(
        &mut self,
        volume: OpaqueHandle,
    ) -> Result<MountResponse, Fat32MountAdmissionError<B::Error>> {
        let mut sector = [0; FAT32_BOOT_SECTOR_BYTES];
        if let Err(error) = self.backend.read_boot_sector(volume, &mut sector) {
            sector.fill(0);
            return Err(Fat32MountAdmissionError::Backend(error));
        }
        let parsed = parse_fat32_boot_sector(&sector);
        sector.fill(0);
        let geometry = parsed.map_err(Fat32MountAdmissionError::InvalidFilesystem)?;
        self.mounts
            .mount(volume, geometry)
            .map_err(Fat32MountAdmissionError::Lifecycle)
    }
}

impl<T: BlockProviderReadTransport, const N: usize> FilesystemMountTransport
    for Fat32MountedProvider<Fat32BlockMountBackend<'_, T>, N>
{
    fn mount(
        &mut self,
        request: &[u8; MOUNT_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; MOUNT_RESPONSE_BYTES], ProtocolError> {
        let request = decode_mount_request(request, memory.len() as u64)?;
        if request.options.length() != 0 {
            return Ok(encode_mount_response(Err(MountError::InvalidRequest)));
        }
        let result = Fat32MountedProvider::mount(self, request.volume).map_err(|error| match error {
            Fat32MountAdmissionError::Backend(Fat32BlockMountError::VolumeMismatch)
            | Fat32MountAdmissionError::Backend(Fat32BlockMountError::Read(
                BlockReadError::StaleObject,
            )) => MountError::StaleObject,
            Fat32MountAdmissionError::Backend(_)
            | Fat32MountAdmissionError::InvalidFilesystem(_)
            | Fat32MountAdmissionError::Lifecycle(Fat32MountError::Capacity)
            | Fat32MountAdmissionError::Lifecycle(Fat32MountError::GenerationExhausted)
            | Fat32MountAdmissionError::Lifecycle(Fat32MountError::CompletionExhausted) => {
                MountError::InconsistentFilesystem
            }
            Fat32MountAdmissionError::Lifecycle(Fat32MountError::AlreadyMounted)
            | Fat32MountAdmissionError::Lifecycle(Fat32MountError::StaleMount) => {
                MountError::InvalidRequest
            }
        });
        Ok(encode_mount_response(result))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fat32FsInfo {
    pub free_cluster_count: Option<u32>,
    pub next_free_cluster: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fat32Error {
    InvalidJump,
    InvalidSignature,
    InvalidSectorSize,
    InvalidClusterSize,
    InvalidReservedArea,
    InvalidFatCount,
    InvalidFatSelection,
    NotFat32,
    UnsupportedVersion,
    InvalidExtent,
    InvalidRootCluster,
    FatTooSmall,
    MissingFsInfo,
    WrongFsInfoSector,
    InvalidFsInfoSignature,
    InvalidFsInfoHint,
    FatRead,
    MirroredFatMismatch,
    FreeClusterInChain,
    ReservedClusterInChain,
    BadCluster,
    ClusterCycle,
    ChainCapacity,
    InvalidDirectoryExtent,
    DirectoryCapacity,
    InvalidLongNameSequence,
    InvalidLongNameEncoding,
    InvalidDirectoryEntry,
    DirectoryAlreadyEnded,
    InvalidLookupName,
    LookupNotFound,
    AmbiguousLookup,
    InvalidFileEntry,
    InvalidFileRange,
    InvalidFileChain,
    InvalidReadBuffers,
    FileRead,
}

pub trait Fat32EntryReader {
    fn read_entry(&mut self, fat_index: u8, cluster: u32) -> Result<u32, ()>;
}

pub trait Fat32ClusterReader {
    fn read_cluster(&mut self, cluster: u32, destination: &mut [u8]) -> Result<(), ()>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fat32ClusterChain<const N: usize> {
    clusters: [u32; N],
    length: usize,
}

impl<const N: usize> Fat32ClusterChain<N> {
    pub fn clusters(&self) -> &[u32] {
        &self.clusters[..self.length]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fat32ShortDirectoryEntry {
    pub short_name: [u8; 11],
    pub long_name: Option<Fat32LongName>,
    pub attributes: u8,
    pub first_cluster: u32,
    pub file_size: u32,
}

impl Fat32ShortDirectoryEntry {
    const EMPTY: Self = Self {
        short_name: [0; 11],
        long_name: None,
        attributes: 0,
        first_cluster: 0,
        file_size: 0,
    };

    pub fn is_directory(&self) -> bool {
        self.attributes & 0x10 != 0
    }

    pub fn is_volume_label(&self) -> bool {
        self.attributes & 0x08 != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fat32LongName {
    utf16: [u16; 255],
    length: u8,
}

impl Fat32LongName {
    pub fn utf16(&self) -> &[u16] {
        &self.utf16[..usize::from(self.length)]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingLongName {
    utf16: [u16; 260],
    slots: u8,
    next_ordinal: u8,
    checksum: u8,
    active: bool,
}

impl PendingLongName {
    const EMPTY: Self = Self {
        utf16: [0; 260],
        slots: 0,
        next_ordinal: 0,
        checksum: 0,
        active: false,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fat32DirectoryBatch<const N: usize> {
    entries: [Fat32ShortDirectoryEntry; N],
    length: usize,
    pub end_of_directory: bool,
    pending_long_name: PendingLongName,
}

impl<const N: usize> Fat32DirectoryBatch<N> {
    pub const fn new() -> Self {
        Self {
            entries: [Fat32ShortDirectoryEntry::EMPTY; N],
            length: 0,
            end_of_directory: false,
            pending_long_name: PendingLongName::EMPTY,
        }
    }

    pub fn entries(&self) -> &[Fat32ShortDirectoryEntry] {
        &self.entries[..self.length]
    }
}

impl<const N: usize> Default for Fat32DirectoryBatch<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolves one bounded directory name to parsed FAT metadata. The returned
/// entry is data, not open authority. ASCII comparison follows FAT's
/// case-insensitive convention; non-ASCII UTF-16 units must match exactly until
/// a complete code-page/upcase policy is admitted.
pub fn lookup_fat32_directory_entry<const N: usize>(
    directory: &Fat32DirectoryBatch<N>,
    name: &[u16],
) -> Result<Fat32ShortDirectoryEntry, Fat32Error> {
    if name.is_empty() || name.len() > 255 || !valid_long_name(name) {
        return Err(Fat32Error::InvalidLookupName);
    }
    let mut matched = None;
    for entry in directory.entries() {
        if entry.is_volume_label() {
            continue;
        }
        let long_match = entry
            .long_name
            .map(|long_name| fat_name_eq(long_name.utf16(), name))
            .unwrap_or(false);
        if !long_match && !short_name_matches(&entry.short_name, name) {
            continue;
        }
        if matched.is_some() {
            return Err(Fat32Error::AmbiguousLookup);
        }
        matched = Some(*entry);
    }
    matched.ok_or(Fat32Error::LookupNotFound)
}

fn fat_name_eq(left: &[u16], right: &[u16]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(&left, &right)| ascii_fold(left) == ascii_fold(right))
}

const fn ascii_fold(unit: u16) -> u16 {
    if unit >= b'a' as u16 && unit <= b'z' as u16 {
        unit - (b'a' - b'A') as u16
    } else {
        unit
    }
}

fn short_name_matches(short_name: &[u8; 11], query: &[u16]) -> bool {
    let base_length = short_name[..8]
        .iter()
        .position(|&byte| byte == b' ')
        .unwrap_or(8);
    let extension_length = short_name[8..]
        .iter()
        .position(|&byte| byte == b' ')
        .unwrap_or(3);
    let expected_length = base_length
        + if extension_length == 0 {
            0
        } else {
            1 + extension_length
        };
    if query.len() != expected_length {
        return false;
    }
    for (index, &byte) in short_name[..base_length].iter().enumerate() {
        if ascii_fold(u16::from(byte)) != ascii_fold(query[index]) {
            return false;
        }
    }
    if extension_length == 0 {
        return true;
    }
    if query[base_length] != u16::from(b'.') {
        return false;
    }
    short_name[8..8 + extension_length]
        .iter()
        .zip(&query[base_length + 1..])
        .all(|(&byte, &unit)| ascii_fold(u16::from(byte)) == ascii_fold(unit))
}

pub fn parse_fat32_boot_sector(
    sector: &[u8; FAT32_BOOT_SECTOR_BYTES],
) -> Result<Fat32Geometry, Fat32Error> {
    if !matches!(sector[0], 0xe9) && !(sector[0] == 0xeb && sector[2] == 0x90) {
        return Err(Fat32Error::InvalidJump);
    }
    if sector[510..512] != [0x55, 0xaa] {
        return Err(Fat32Error::InvalidSignature);
    }
    let bytes_per_sector = read_u16(sector, 11);
    if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096) {
        return Err(Fat32Error::InvalidSectorSize);
    }
    let sectors_per_cluster = sector[13];
    let cluster_bytes = u32::from(bytes_per_sector)
        .checked_mul(u32::from(sectors_per_cluster))
        .ok_or(Fat32Error::InvalidClusterSize)?;
    if sectors_per_cluster == 0
        || !sectors_per_cluster.is_power_of_two()
        || sectors_per_cluster > 128
        || cluster_bytes > 32 * 1024
    {
        return Err(Fat32Error::InvalidClusterSize);
    }
    let reserved_sectors = read_u16(sector, 14);
    if reserved_sectors == 0 {
        return Err(Fat32Error::InvalidReservedArea);
    }
    let fat_count = sector[16];
    if !(1..=2).contains(&fat_count) {
        return Err(Fat32Error::InvalidFatCount);
    }
    if read_u16(sector, 17) != 0 || read_u16(sector, 19) != 0 || read_u16(sector, 22) != 0 {
        return Err(Fat32Error::NotFat32);
    }
    let total_sectors = read_u32(sector, 32);
    let sectors_per_fat = read_u32(sector, 36);
    if total_sectors == 0 || sectors_per_fat == 0 {
        return Err(Fat32Error::NotFat32);
    }
    if read_u16(sector, 42) != 0 {
        return Err(Fat32Error::UnsupportedVersion);
    }
    let extended_flags = read_u16(sector, 40);
    if extended_flags & !0x008f != 0 {
        return Err(Fat32Error::InvalidFatSelection);
    }
    let mirroring_enabled = extended_flags & 0x0080 == 0;
    let selected = (extended_flags & 0x000f) as u8;
    let active_fat = if mirroring_enabled {
        if selected != 0 {
            return Err(Fat32Error::InvalidFatSelection);
        }
        0
    } else if selected < fat_count {
        selected
    } else {
        return Err(Fat32Error::InvalidFatSelection);
    };
    let root_cluster = read_u32(sector, 44);
    if !(2..=FAT32_MAXIMUM_CLUSTERS + 1).contains(&root_cluster) {
        return Err(Fat32Error::InvalidRootCluster);
    }
    let fs_info = optional_reserved_sector(read_u16(sector, 48), reserved_sectors)?;
    let backup_boot = optional_reserved_sector(read_u16(sector, 50), reserved_sectors)?;
    if fs_info.is_some() && fs_info == backup_boot {
        return Err(Fat32Error::InvalidReservedArea);
    }
    let all_fat_sectors = u32::from(fat_count)
        .checked_mul(sectors_per_fat)
        .ok_or(Fat32Error::InvalidExtent)?;
    let data_start_sector = u32::from(reserved_sectors)
        .checked_add(all_fat_sectors)
        .ok_or(Fat32Error::InvalidExtent)?;
    let data_sectors = total_sectors
        .checked_sub(data_start_sector)
        .ok_or(Fat32Error::InvalidExtent)?;
    let cluster_count = data_sectors / u32::from(sectors_per_cluster);
    if !(FAT32_MINIMUM_CLUSTERS..=FAT32_MAXIMUM_CLUSTERS).contains(&cluster_count) {
        return Err(Fat32Error::NotFat32);
    }
    if root_cluster
        >= cluster_count
            .checked_add(2)
            .ok_or(Fat32Error::InvalidExtent)?
    {
        return Err(Fat32Error::InvalidRootCluster);
    }
    let fat_entries = u64::from(sectors_per_fat)
        .checked_mul(u64::from(bytes_per_sector))
        .ok_or(Fat32Error::InvalidExtent)?
        / 4;
    if fat_entries < u64::from(cluster_count) + 2 {
        return Err(Fat32Error::FatTooSmall);
    }
    Ok(Fat32Geometry {
        bytes_per_sector,
        sectors_per_cluster,
        reserved_sectors,
        fat_count,
        sectors_per_fat,
        mirroring_enabled,
        active_fat,
        total_sectors,
        data_start_sector,
        data_sectors,
        cluster_count,
        root_cluster,
        fs_info_sector: fs_info,
        backup_boot_sector: backup_boot,
        volume_id: read_u32(sector, 67),
    })
}

pub fn read_fat32_cluster_chain<const N: usize, R: Fat32EntryReader>(
    geometry: Fat32Geometry,
    first_cluster: u32,
    reader: &mut R,
) -> Result<Fat32ClusterChain<N>, Fat32Error> {
    let last_cluster = geometry
        .cluster_count
        .checked_add(1)
        .ok_or(Fat32Error::InvalidExtent)?;
    if N == 0 || !(2..=last_cluster).contains(&first_cluster) {
        return Err(Fat32Error::InvalidRootCluster);
    }
    let mut clusters = [0; N];
    let mut length = 0;
    let mut current = first_cluster;
    loop {
        if clusters[..length].contains(&current) {
            return Err(Fat32Error::ClusterCycle);
        }
        if length == N {
            return Err(Fat32Error::ChainCapacity);
        }
        clusters[length] = current;
        length += 1;
        let entry = read_selected_entry(geometry, current, reader)? & 0x0fff_ffff;
        match entry {
            0 => return Err(Fat32Error::FreeClusterInChain),
            1 | 0x0fff_fff0..=0x0fff_fff6 => return Err(Fat32Error::ReservedClusterInChain),
            0x0fff_fff7 => return Err(Fat32Error::BadCluster),
            0x0fff_fff8..=0x0fff_ffff => return Ok(Fat32ClusterChain { clusters, length }),
            next if (2..=last_cluster).contains(&next) => current = next,
            _ => return Err(Fat32Error::ReservedClusterInChain),
        }
    }
}

pub fn read_fat32_file_range<const N: usize, R: Fat32ClusterReader>(
    geometry: Fat32Geometry,
    entry: Fat32ShortDirectoryEntry,
    chain: Option<&Fat32ClusterChain<N>>,
    offset: u32,
    output: &mut [u8],
    staging: &mut [u8],
    cluster_scratch: &mut [u8],
    reader: &mut R,
) -> Result<(), Fat32Error> {
    staging.fill(0);
    cluster_scratch.fill(0);
    let cluster_bytes = usize::from(geometry.bytes_per_sector)
        .checked_mul(usize::from(geometry.sectors_per_cluster))
        .ok_or(Fat32Error::InvalidReadBuffers)?;
    if entry.is_directory()
        || entry.is_volume_label()
        || cluster_bytes == 0
        || staging.len() != output.len()
        || cluster_scratch.len() != cluster_bytes
    {
        return Err(if entry.is_directory() || entry.is_volume_label() {
            Fat32Error::InvalidFileEntry
        } else {
            Fat32Error::InvalidReadBuffers
        });
    }

    let end = u64::from(offset)
        .checked_add(u64::try_from(output.len()).map_err(|_| Fat32Error::InvalidFileRange)?)
        .ok_or(Fat32Error::InvalidFileRange)?;
    if end > u64::from(entry.file_size) {
        return Err(Fat32Error::InvalidFileRange);
    }
    if entry.file_size == 0 {
        if entry.first_cluster != 0 || chain.is_some() || offset != 0 {
            return Err(Fat32Error::InvalidFileEntry);
        }
        return Ok(());
    }

    let chain = chain.ok_or(Fat32Error::InvalidFileChain)?;
    let expected_clusters =
        (u64::from(entry.file_size) + cluster_bytes as u64 - 1) / cluster_bytes as u64;
    if chain.length == 0
        || entry.first_cluster != chain.clusters[0]
        || u64::try_from(chain.length).map_err(|_| Fat32Error::InvalidFileChain)?
            != expected_clusters
    {
        return Err(Fat32Error::InvalidFileChain);
    }
    if output.is_empty() {
        return Ok(());
    }

    let result = read_fat32_file_range_into_staging(
        chain,
        offset as usize,
        staging,
        cluster_scratch,
        reader,
    );
    if let Err(error) = result {
        staging.fill(0);
        cluster_scratch.fill(0);
        return Err(error);
    }
    output.copy_from_slice(staging);
    staging.fill(0);
    cluster_scratch.fill(0);
    Ok(())
}

fn read_fat32_file_range_into_staging<const N: usize, R: Fat32ClusterReader>(
    chain: &Fat32ClusterChain<N>,
    offset: usize,
    staging: &mut [u8],
    cluster_scratch: &mut [u8],
    reader: &mut R,
) -> Result<(), Fat32Error> {
    let cluster_bytes = cluster_scratch.len();
    let mut cluster_index = offset / cluster_bytes;
    let mut within_cluster = offset % cluster_bytes;
    let mut copied = 0;
    while copied < staging.len() {
        let cluster = *chain
            .clusters
            .get(cluster_index)
            .ok_or(Fat32Error::InvalidFileChain)?;
        reader
            .read_cluster(cluster, cluster_scratch)
            .map_err(|()| Fat32Error::FileRead)?;
        let available = cluster_bytes - within_cluster;
        let take = core::cmp::min(available, staging.len() - copied);
        staging[copied..copied + take]
            .copy_from_slice(&cluster_scratch[within_cluster..within_cluster + take]);
        copied += take;
        cluster_index += 1;
        within_cluster = 0;
    }
    Ok(())
}

pub fn parse_fat32_short_directory<const N: usize>(
    geometry: Fat32Geometry,
    bytes: &[u8],
) -> Result<Fat32DirectoryBatch<N>, Fat32Error> {
    let mut directory = Fat32DirectoryBatch::new();
    append_fat32_short_directory(geometry, &mut directory, bytes)?;
    Ok(directory)
}

pub fn append_fat32_short_directory<const N: usize>(
    geometry: Fat32Geometry,
    directory: &mut Fat32DirectoryBatch<N>,
    bytes: &[u8],
) -> Result<(), Fat32Error> {
    let mut candidate = *directory;
    append_fat32_short_directory_inner(geometry, &mut candidate, bytes)?;
    *directory = candidate;
    Ok(())
}

fn append_fat32_short_directory_inner<const N: usize>(
    geometry: Fat32Geometry,
    directory: &mut Fat32DirectoryBatch<N>,
    bytes: &[u8],
) -> Result<(), Fat32Error> {
    if directory.end_of_directory {
        return Err(Fat32Error::DirectoryAlreadyEnded);
    }
    let cluster_bytes = usize::from(geometry.bytes_per_sector)
        .checked_mul(usize::from(geometry.sectors_per_cluster))
        .ok_or(Fat32Error::InvalidDirectoryExtent)?;
    if bytes.is_empty() || bytes.len() > cluster_bytes || bytes.len() % 32 != 0 {
        return Err(Fat32Error::InvalidDirectoryExtent);
    }
    if N == 0 {
        return Err(Fat32Error::DirectoryCapacity);
    }

    let last_cluster = geometry
        .cluster_count
        .checked_add(1)
        .ok_or(Fat32Error::InvalidExtent)?;
    for raw in bytes.chunks_exact(32) {
        if raw[0] == 0 {
            if directory.pending_long_name.active {
                return Err(Fat32Error::InvalidLongNameSequence);
            }
            directory.end_of_directory = true;
            return Ok(());
        }
        if raw[0] == 0xe5 {
            directory.pending_long_name = PendingLongName::EMPTY;
            continue;
        }
        let attributes = raw[11];
        if attributes == 0x0f {
            append_long_name_slot(&mut directory.pending_long_name, raw)?;
            continue;
        }
        if attributes & 0xc0 != 0
            || attributes & 0x18 == 0x18
            || raw[12] & !0x18 != 0
            || raw[13] > 199
        {
            return Err(Fat32Error::InvalidDirectoryEntry);
        }
        let mut short_name = [0; 11];
        short_name.copy_from_slice(&raw[..11]);
        let long_name = finish_long_name(&directory.pending_long_name, &short_name)?;
        directory.pending_long_name = PendingLongName::EMPTY;
        if short_name[0] == 0x05 {
            short_name[0] = 0xe5;
        }
        if !valid_short_component(&short_name[..8], false)
            || !valid_short_component(&short_name[8..], true)
        {
            return Err(Fat32Error::InvalidDirectoryEntry);
        }
        let first_cluster = u32::from(read_u16(raw, 26)) | (u32::from(read_u16(raw, 20)) << 16);
        let file_size = read_u32(raw, 28);
        let volume_label = attributes & 0x08 != 0;
        let is_directory = attributes & 0x10 != 0;
        if volume_label && long_name.is_some() {
            return Err(Fat32Error::InvalidLongNameSequence);
        }
        let valid_cluster = if volume_label {
            first_cluster == 0 && file_size == 0
        } else if is_directory {
            (2..=last_cluster).contains(&first_cluster) && file_size == 0
        } else {
            (first_cluster == 0 && file_size == 0) || (2..=last_cluster).contains(&first_cluster)
        };
        if !valid_cluster {
            return Err(Fat32Error::InvalidDirectoryEntry);
        }
        if directory.length == N {
            return Err(Fat32Error::DirectoryCapacity);
        }
        directory.entries[directory.length] = Fat32ShortDirectoryEntry {
            short_name,
            long_name,
            attributes,
            first_cluster,
            file_size,
        };
        directory.length += 1;
    }
    Ok(())
}

fn append_long_name_slot(pending: &mut PendingLongName, raw: &[u8]) -> Result<(), Fat32Error> {
    let sequence = raw[0];
    let ordinal = sequence & 0x1f;
    let last = sequence & 0x40 != 0;
    if sequence & 0xa0 != 0
        || !(1..=20).contains(&ordinal)
        || raw[12] != 0
        || read_u16(raw, 26) != 0
    {
        return Err(Fat32Error::InvalidLongNameSequence);
    }
    if last {
        if pending.active {
            return Err(Fat32Error::InvalidLongNameSequence);
        }
        *pending = PendingLongName {
            slots: ordinal,
            next_ordinal: ordinal,
            checksum: raw[13],
            ..PendingLongName::EMPTY
        };
        pending.active = true;
    } else if !pending.active || pending.next_ordinal != ordinal || pending.checksum != raw[13] {
        return Err(Fat32Error::InvalidLongNameSequence);
    }

    let offset = usize::from(ordinal - 1) * 13;
    let positions = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
    for (index, position) in positions.into_iter().enumerate() {
        pending.utf16[offset + index] = read_u16(raw, position);
    }
    pending.next_ordinal = ordinal - 1;
    Ok(())
}

fn finish_long_name(
    pending: &PendingLongName,
    short_name: &[u8; 11],
) -> Result<Option<Fat32LongName>, Fat32Error> {
    if !pending.active {
        return Ok(None);
    }
    if pending.next_ordinal != 0 || pending.checksum != short_name_checksum(short_name) {
        return Err(Fat32Error::InvalidLongNameSequence);
    }
    let available = usize::from(pending.slots) * 13;
    let mut length = available;
    for index in 0..available {
        match pending.utf16[index] {
            0 => {
                length = index;
                if pending.utf16[index + 1..available]
                    .iter()
                    .any(|&unit| unit != 0xffff)
                {
                    return Err(Fat32Error::InvalidLongNameEncoding);
                }
                break;
            }
            0xffff => return Err(Fat32Error::InvalidLongNameEncoding),
            _ => {}
        }
    }
    if length == 0 || length > 255 || !valid_long_name(&pending.utf16[..length]) {
        return Err(Fat32Error::InvalidLongNameEncoding);
    }
    let mut utf16 = [0; 255];
    utf16[..length].copy_from_slice(&pending.utf16[..length]);
    Ok(Some(Fat32LongName {
        utf16,
        length: length as u8,
    }))
}

fn valid_long_name(units: &[u16]) -> bool {
    if matches!(units.last().copied(), Some(0x20 | 0x2e))
        || units == [0x2e]
        || units == [0x2e, 0x2e]
    {
        return false;
    }
    let mut index = 0;
    while index < units.len() {
        let unit = units[index];
        if unit < 0x20
            || matches!(
                unit,
                0x22 | 0x2a | 0x2f | 0x3a | 0x3c | 0x3e | 0x3f | 0x5c | 0x7c
            )
        {
            return false;
        }
        if (0xd800..=0xdbff).contains(&unit) {
            if index + 1 == units.len() || !(0xdc00..=0xdfff).contains(&units[index + 1]) {
                return false;
            }
            index += 2;
        } else if (0xdc00..=0xdfff).contains(&unit) {
            return false;
        } else {
            index += 1;
        }
    }
    true
}

fn short_name_checksum(short_name: &[u8; 11]) -> u8 {
    short_name.iter().fold(0_u8, |checksum, &byte| {
        checksum.rotate_right(1).wrapping_add(byte)
    })
}

fn valid_short_component(component: &[u8], allow_empty: bool) -> bool {
    let mut padding = false;
    for &byte in component {
        if byte == b' ' {
            padding = true;
        } else if padding
            || byte < 0x20
            || matches!(
                byte,
                b'"' | b'*'
                    | b'+'
                    | b','
                    | b'.'
                    | b'/'
                    | b':'
                    | b';'
                    | b'<'
                    | b'='
                    | b'>'
                    | b'?'
                    | b'['
                    | b'\\'
                    | b']'
                    | b'|'
            )
        {
            return false;
        }
    }
    allow_empty || component.first().copied() != Some(b' ')
}

fn read_selected_entry<R: Fat32EntryReader>(
    geometry: Fat32Geometry,
    cluster: u32,
    reader: &mut R,
) -> Result<u32, Fat32Error> {
    let first = reader
        .read_entry(geometry.active_fat, cluster)
        .map_err(|()| Fat32Error::FatRead)?
        & 0x0fff_ffff;
    if geometry.mirroring_enabled {
        for fat in 1..geometry.fat_count {
            let other = reader
                .read_entry(fat, cluster)
                .map_err(|()| Fat32Error::FatRead)?
                & 0x0fff_ffff;
            if other != first {
                return Err(Fat32Error::MirroredFatMismatch);
            }
        }
    }
    Ok(first)
}

pub fn parse_fat32_fs_info(
    geometry: Fat32Geometry,
    sector_index: u16,
    sector: &[u8; FAT32_BOOT_SECTOR_BYTES],
) -> Result<Fat32FsInfo, Fat32Error> {
    let expected = geometry.fs_info_sector.ok_or(Fat32Error::MissingFsInfo)?;
    if sector_index != expected {
        return Err(Fat32Error::WrongFsInfoSector);
    }
    if read_u32(sector, 0) != 0x4161_5252
        || read_u32(sector, 484) != 0x6141_7272
        || read_u32(sector, 508) != 0xaa55_0000
    {
        return Err(Fat32Error::InvalidFsInfoSignature);
    }
    let free = read_u32(sector, 488);
    let next = read_u32(sector, 492);
    let free_cluster_count = if free == u32::MAX {
        None
    } else if free <= geometry.cluster_count {
        Some(free)
    } else {
        return Err(Fat32Error::InvalidFsInfoHint);
    };
    let last_cluster = geometry
        .cluster_count
        .checked_add(1)
        .ok_or(Fat32Error::InvalidExtent)?;
    let next_free_cluster = if next == u32::MAX {
        None
    } else if (2..=last_cluster).contains(&next) {
        Some(next)
    } else {
        return Err(Fat32Error::InvalidFsInfoHint);
    };
    Ok(Fat32FsInfo {
        free_cluster_count,
        next_free_cluster,
    })
}

fn optional_reserved_sector(value: u16, reserved: u16) -> Result<Option<u16>, Fat32Error> {
    if value == 0 || value == u16::MAX {
        return Ok(None);
    }
    if value >= reserved {
        return Err(Fat32Error::InvalidReservedArea);
    }
    Ok(Some(value))
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn boot_sector() -> [u8; FAT32_BOOT_SECTOR_BYTES] {
        let mut sector = [0; FAT32_BOOT_SECTOR_BYTES];
        sector[0..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        sector[11..13].copy_from_slice(&512_u16.to_le_bytes());
        sector[13] = 8;
        sector[14..16].copy_from_slice(&32_u16.to_le_bytes());
        sector[16] = 2;
        sector[32..36].copy_from_slice(&1_048_576_u32.to_le_bytes());
        sector[36..40].copy_from_slice(&1024_u32.to_le_bytes());
        sector[44..48].copy_from_slice(&2_u32.to_le_bytes());
        sector[48..50].copy_from_slice(&1_u16.to_le_bytes());
        sector[50..52].copy_from_slice(&6_u16.to_le_bytes());
        sector[67..71].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
        sector[510..512].copy_from_slice(&[0x55, 0xaa]);
        sector
    }

    fn fs_info() -> [u8; FAT32_BOOT_SECTOR_BYTES] {
        let mut sector = [0; FAT32_BOOT_SECTOR_BYTES];
        sector[0..4].copy_from_slice(&0x4161_5252_u32.to_le_bytes());
        sector[484..488].copy_from_slice(&0x6141_7272_u32.to_le_bytes());
        sector[488..492].copy_from_slice(&1000_u32.to_le_bytes());
        sector[492..496].copy_from_slice(&3_u32.to_le_bytes());
        sector[508..512].copy_from_slice(&0xaa55_0000_u32.to_le_bytes());
        sector
    }

    fn short_entry(name: &[u8; 11], attributes: u8, cluster: u32, size: u32) -> [u8; 32] {
        let mut entry = [0; 32];
        entry[..11].copy_from_slice(name);
        entry[11] = attributes;
        entry[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
        entry[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
        entry[28..32].copy_from_slice(&size.to_le_bytes());
        entry
    }

    fn long_entry(ordinal: u8, last: bool, checksum: u8, units: &[u16]) -> [u8; 32] {
        let mut entry = [0xff; 32];
        entry[0] = ordinal | if last { 0x40 } else { 0 };
        entry[11] = 0x0f;
        entry[12] = 0;
        entry[13] = checksum;
        entry[26..28].copy_from_slice(&0_u16.to_le_bytes());
        let positions = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
        for (index, position) in positions.into_iter().enumerate() {
            let unit = units
                .get(index)
                .copied()
                .unwrap_or(if index == units.len() { 0 } else { 0xffff });
            entry[position..position + 2].copy_from_slice(&unit.to_le_bytes());
        }
        entry
    }

    fn ascii_utf16<const N: usize>(bytes: &[u8; N]) -> [u16; N] {
        let mut units = [0; N];
        for (unit, &byte) in units.iter_mut().zip(bytes) {
            *unit = u16::from(byte);
        }
        units
    }

    #[test]
    fn parses_exact_bounded_fat32_geometry() {
        let geometry = parse_fat32_boot_sector(&boot_sector()).unwrap();
        assert_eq!(geometry.bytes_per_sector, 512);
        assert_eq!(geometry.data_start_sector, 2080);
        assert_eq!(geometry.cluster_count, 130_812);
        assert_eq!(geometry.root_cluster, 2);
        assert_eq!(geometry.fs_info_sector, Some(1));
        assert_eq!(geometry.backup_boot_sector, Some(6));
        assert_eq!(geometry.volume_id, 0x1234_5678);
    }

    #[test]
    fn mount_table_issues_exact_root_identity_and_invalidates_it_on_unmount() {
        let geometry = parse_fat32_boot_sector(&boot_sector()).unwrap();
        let volume = OpaqueHandle::new(4, 7).unwrap();
        let other = OpaqueHandle::new(5, 7).unwrap();
        let mut mounts = Fat32MountTable::<1>::new();
        let first = mounts.mount(volume, geometry).unwrap();
        assert_eq!(first.generation, 1);
        assert_eq!(first.root, OpaqueHandle::new(0, 1).unwrap());
        assert_eq!(
            mounts.geometry(volume, first.generation, first.root),
            Ok(geometry)
        );
        assert_eq!(
            mounts.mount(volume, geometry),
            Err(Fat32MountError::AlreadyMounted)
        );
        assert_eq!(
            mounts.mount(other, geometry),
            Err(Fat32MountError::Capacity)
        );
        assert_eq!(
            mounts.geometry(volume, first.generation + 1, first.root),
            Err(Fat32MountError::StaleMount)
        );
        assert_eq!(
            mounts.unmount(volume, first.generation),
            Ok(Fat32Unmounted {
                serial: 1,
                root: first.root,
            })
        );
        assert_eq!(
            mounts.unmount(volume, first.generation),
            Err(Fat32MountError::StaleMount)
        );
        assert_eq!(
            mounts.geometry(volume, first.generation, first.root),
            Err(Fat32MountError::StaleMount)
        );
        let second = mounts.mount(volume, geometry).unwrap();
        assert_eq!(second.generation, 2);
        assert_eq!(second.root, OpaqueHandle::new(0, 2).unwrap());
        assert_ne!(first, second);
    }

    #[test]
    fn mount_generation_exhaustion_never_reuses_lifecycle_or_root_identity() {
        let geometry = parse_fat32_boot_sector(&boot_sector()).unwrap();
        let volume = OpaqueHandle::new(4, 7).unwrap();
        let mut mounts =
            Fat32MountTable::<1>::with_next_generations(u64::MAX, u32::MAX, u64::MAX);
        let final_mount = mounts.mount(volume, geometry).unwrap();
        assert_eq!(final_mount.generation, u64::MAX);
        assert_eq!(final_mount.root.generation(), u32::MAX);
        assert_eq!(
            mounts.unmount(volume, final_mount.generation),
            Ok(Fat32Unmounted {
                serial: u64::MAX,
                root: final_mount.root,
            })
        );
        assert_eq!(
            mounts.mount(volume, geometry),
            Err(Fat32MountError::GenerationExhausted)
        );
    }

    #[test]
    fn unmount_completion_exhaustion_preserves_the_exact_live_mount() {
        let geometry = parse_fat32_boot_sector(&boot_sector()).unwrap();
        let volume = OpaqueHandle::new(4, 7).unwrap();
        let mut mounts = Fat32MountTable::<1>::with_next_generations(1, 1, u64::MAX);
        let first = mounts.mount(volume, geometry).unwrap();
        assert_eq!(
            mounts.unmount(volume, first.generation),
            Ok(Fat32Unmounted {
                serial: u64::MAX,
                root: first.root,
            })
        );
        let second = mounts.mount(volume, geometry).unwrap();
        assert_eq!(
            mounts.unmount(volume, second.generation),
            Err(Fat32MountError::CompletionExhausted)
        );
        assert_eq!(
            mounts.geometry(volume, second.generation, second.root),
            Ok(geometry)
        );
    }

    struct MountBackend {
        sector: [u8; FAT32_BOOT_SECTOR_BYTES],
        fail: bool,
        requested: Option<OpaqueHandle>,
        destination_was_zero: bool,
    }

    unsafe impl Fat32MountBackend for MountBackend {
        type Error = u8;

        fn read_boot_sector(
            &mut self,
            volume: OpaqueHandle,
            output: &mut [u8; FAT32_BOOT_SECTOR_BYTES],
        ) -> Result<(), Self::Error> {
            self.requested = Some(volume);
            self.destination_was_zero = output.iter().all(|byte| *byte == 0);
            if self.fail {
                output.fill(0xaa);
                return Err(9);
            }
            *output = self.sector;
            Ok(())
        }
    }

    struct BlockReadTransport {
        session: BlockOpaqueHandle,
        response: Result<u64, BlockReadError>,
        calls: u8,
    }

    impl BlockProviderReadTransport for BlockReadTransport {
        fn read(
            &mut self,
            request: &[u8; mrml_interface_storage_block_provider_v1::READ_REQUEST_BYTES],
            memory: &mut [u8],
        ) -> Result<
            [u8; mrml_interface_storage_block_provider_v1::READ_RESPONSE_BYTES],
            BlockProtocolError,
        > {
            use mrml_interface_storage_block_provider_v1::{
                decode_read_request, encode_read_response,
            };

            let decoded = decode_read_request(request, memory.len() as u64)?;
            assert_eq!(decoded.session, self.session);
            assert_eq!(decoded.lba, 0);
            assert_eq!(decoded.sector_count, 1);
            assert_eq!(decoded.output.offset(), 0);
            assert_eq!(decoded.output.length(), memory.len() as u64);
            self.calls = self.calls.checked_add(1).unwrap();
            if self.response.is_ok() {
                memory[..FAT32_BOOT_SECTOR_BYTES].copy_from_slice(&boot_sector());
                memory[FAT32_BOOT_SECTOR_BYTES..].fill(0xcc);
            }
            Ok(encode_read_response(self.response))
        }
    }

    fn block_binding(volume: OpaqueHandle, session: BlockOpaqueHandle) -> Fat32BlockBinding {
        // SAFETY: This test fixture defines `session` as the exact backing session
        // for `volume`; production callers must obtain the association from the runtime.
        unsafe { Fat32BlockBinding::new(volume, session, 4096).unwrap() }
    }

    #[test]
    fn block_mount_backend_reads_one_exact_logical_block_and_erases_scratch() {
        let volume = OpaqueHandle::new(4, 7).unwrap();
        let session = BlockOpaqueHandle::new(9, 11).unwrap();
        let transport = BlockReadTransport {
            session,
            response: Ok(4096),
            calls: 0,
        };
        let mut scratch = [0xaa; 4096];
        let mut output = [0xbb; FAT32_BOOT_SECTOR_BYTES];
        let returned = {
            let mut backend = Fat32BlockMountBackend::new(
                block_binding(volume, session),
                transport,
                &mut scratch,
            )
            .unwrap();
            backend.read_boot_sector(volume, &mut output).unwrap();
            backend.into_transport()
        };
        assert_eq!(returned.calls, 1);
        assert_eq!(output, boot_sector());
        assert_eq!(scratch, [0; 4096]);
    }

    #[test]
    fn block_mount_backend_rejects_volume_mismatch_without_io() {
        let volume = OpaqueHandle::new(4, 7).unwrap();
        let other = OpaqueHandle::new(5, 7).unwrap();
        let session = BlockOpaqueHandle::new(9, 11).unwrap();
        let transport = BlockReadTransport {
            session,
            response: Ok(4096),
            calls: 0,
        };
        let mut scratch = [0xaa; 4096];
        let mut output = [0xbb; FAT32_BOOT_SECTOR_BYTES];
        let returned = {
            let mut backend = Fat32BlockMountBackend::new(
                block_binding(volume, session),
                transport,
                &mut scratch,
            )
            .unwrap();
            assert_eq!(
                backend.read_boot_sector(other, &mut output),
                Err(Fat32BlockMountError::VolumeMismatch)
            );
            backend.into_transport()
        };
        assert_eq!(returned.calls, 0);
        assert_eq!(output, [0; FAT32_BOOT_SECTOR_BYTES]);
        assert_eq!(scratch, [0; 4096]);
    }

    #[test]
    fn block_mount_backend_preserves_typed_error_and_rejects_short_completion() {
        let volume = OpaqueHandle::new(4, 7).unwrap();
        let session = BlockOpaqueHandle::new(9, 11).unwrap();
        for (response, expected) in [
            (
                Err(BlockReadError::StaleObject),
                Fat32BlockMountError::Read(BlockReadError::StaleObject),
            ),
            (Ok(512), Fat32BlockMountError::ShortRead),
        ] {
            let transport = BlockReadTransport {
                session,
                response,
                calls: 0,
            };
            let mut scratch = [0xaa; 4096];
            let mut output = [0xbb; FAT32_BOOT_SECTOR_BYTES];
            {
                let mut backend = Fat32BlockMountBackend::new(
                    block_binding(volume, session),
                    transport,
                    &mut scratch,
                )
                .unwrap();
                assert_eq!(backend.read_boot_sector(volume, &mut output), Err(expected));
            }
            assert_eq!(output, [0; FAT32_BOOT_SECTOR_BYTES]);
            assert_eq!(scratch, [0; 4096]);
        }
    }

    #[test]
    fn block_mount_backend_rejects_and_erases_wrong_scratch_size() {
        let volume = OpaqueHandle::new(4, 7).unwrap();
        let session = BlockOpaqueHandle::new(9, 11).unwrap();
        let transport = BlockReadTransport {
            session,
            response: Ok(4096),
            calls: 0,
        };
        let mut scratch = [0xaa; 512];
        assert!(matches!(
            Fat32BlockMountBackend::new(block_binding(volume, session), transport, &mut scratch),
            Err(Fat32BlockMountError::InvalidScratch)
        ));
        assert_eq!(scratch, [0; 512]);
    }

    #[test]
    fn canonical_mount_transport_publishes_exact_lifecycle_response() {
        use mrml_interface_storage_filesystem_v2::{
            decode_mount_response, encode_mount_request, BorrowedReadView,
        };

        let volume = OpaqueHandle::new(4, 7).unwrap();
        let session = BlockOpaqueHandle::new(9, 11).unwrap();
        let transport = BlockReadTransport {
            session,
            response: Ok(4096),
            calls: 0,
        };
        let mut scratch = [0xaa; 4096];
        let backend =
            Fat32BlockMountBackend::new(block_binding(volume, session), transport, &mut scratch)
                .unwrap();
        let mut provider = Fat32MountedProvider::<_, 1>::new(backend);
        let request = encode_mount_request(
            volume,
            BorrowedReadView::within(0, 0, 0).unwrap(),
        )
        .unwrap();
        let response = FilesystemMountTransport::mount(&mut provider, &request, &mut []).unwrap();
        let mounted = decode_mount_response(&response).unwrap().unwrap();
        assert_eq!(mounted.generation, 1);
        assert_eq!(mounted.root, OpaqueHandle::new(0, 1).unwrap());
        assert_eq!(
            provider.geometry(volume, mounted.generation, mounted.root),
            Ok(parse_fat32_boot_sector(&boot_sector()).unwrap())
        );
    }

    #[test]
    fn canonical_mount_transport_rejects_options_before_block_io() {
        use mrml_interface_storage_filesystem_v2::{
            decode_mount_response, encode_mount_request, BorrowedReadView,
        };

        let volume = OpaqueHandle::new(4, 7).unwrap();
        let session = BlockOpaqueHandle::new(9, 11).unwrap();
        let transport = BlockReadTransport {
            session,
            response: Ok(4096),
            calls: 0,
        };
        let mut scratch = [0xaa; 4096];
        let backend =
            Fat32BlockMountBackend::new(block_binding(volume, session), transport, &mut scratch)
                .unwrap();
        let mut provider = Fat32MountedProvider::<_, 1>::new(backend);
        let request = encode_mount_request(
            volume,
            BorrowedReadView::within(0, 1, 1).unwrap(),
        )
        .unwrap();
        let response = FilesystemMountTransport::mount(&mut provider, &request, &mut [7]).unwrap();
        assert_eq!(
            decode_mount_response(&response),
            Ok(Err(MountError::InvalidRequest))
        );
        assert_eq!(provider.into_backend().into_transport().calls, 0);
    }

    #[test]
    fn canonical_mount_transport_maps_stale_block_session_without_state() {
        use mrml_interface_storage_filesystem_v2::{
            decode_mount_response, encode_mount_request, BorrowedReadView,
        };

        let volume = OpaqueHandle::new(4, 7).unwrap();
        let session = BlockOpaqueHandle::new(9, 11).unwrap();
        let transport = BlockReadTransport {
            session,
            response: Err(BlockReadError::StaleObject),
            calls: 0,
        };
        let mut scratch = [0xaa; 4096];
        let backend =
            Fat32BlockMountBackend::new(block_binding(volume, session), transport, &mut scratch)
                .unwrap();
        let mut provider = Fat32MountedProvider::<_, 1>::new(backend);
        let request = encode_mount_request(
            volume,
            BorrowedReadView::within(0, 0, 0).unwrap(),
        )
        .unwrap();
        let response = FilesystemMountTransport::mount(&mut provider, &request, &mut []).unwrap();
        assert_eq!(
            decode_mount_response(&response),
            Ok(Err(MountError::StaleObject))
        );
        assert_eq!(provider.into_backend().into_transport().calls, 1);
    }

    #[test]
    fn mounted_provider_validates_exact_volume_before_publishing_state() {
        let volume = OpaqueHandle::new(4, 7).unwrap();
        let backend = MountBackend {
            sector: boot_sector(),
            fail: false,
            requested: None,
            destination_was_zero: false,
        };
        let mut provider = Fat32MountedProvider::<_, 1>::new(backend);
        let mounted = provider.mount(volume).unwrap();
        assert_eq!(provider.backend.requested, Some(volume));
        assert!(provider.backend.destination_was_zero);
        assert_eq!(
            provider
                .geometry(volume, mounted.generation, mounted.root)
                .unwrap(),
            parse_fat32_boot_sector(&boot_sector()).unwrap()
        );
    }

    #[test]
    fn backend_and_parse_failures_publish_nothing_and_do_not_consume_generations() {
        let volume = OpaqueHandle::new(4, 7).unwrap();
        let backend = MountBackend {
            sector: [0; FAT32_BOOT_SECTOR_BYTES],
            fail: true,
            requested: None,
            destination_was_zero: false,
        };
        let mut provider = Fat32MountedProvider::<_, 1>::new(backend);
        assert_eq!(
            provider.mount(volume),
            Err(Fat32MountAdmissionError::Backend(9))
        );
        provider.backend_mut().fail = false;
        assert_eq!(
            provider.mount(volume),
            Err(Fat32MountAdmissionError::InvalidFilesystem(
                Fat32Error::InvalidJump
            ))
        );
        provider.backend_mut().sector = boot_sector();
        let mounted = provider.mount(volume).unwrap();
        assert_eq!(mounted.generation, 1);
        assert_eq!(mounted.root.generation(), 1);
    }

    #[test]
    fn provider_probe_uses_canonical_interface_bytes() {
        use mrml_interface_storage_filesystem_v2::{
            decode_probe_response, encode_probe_request, BorrowedReadView, OpaqueHandle,
        };

        let mut memory = [0; 520];
        memory[8..].copy_from_slice(&boot_sector());
        let request = encode_probe_request(
            OpaqueHandle::new(3, 7).unwrap(),
            BorrowedReadView::within(8, 512, 520).unwrap(),
        )
        .unwrap();
        assert_eq!(
            decode_probe_response(&Fat32Provider.probe(&request, &mut memory).unwrap()),
            Ok(Ok(100))
        );
    }

    #[test]
    fn provider_probe_distinguishes_invalid_call_from_unsupported_media() {
        use mrml_interface_storage_filesystem_v2::{
            decode_probe_response, encode_probe_request, BorrowedReadView, OpaqueHandle,
        };

        let volume = OpaqueHandle::new(3, 7).unwrap();
        let short =
            encode_probe_request(volume, BorrowedReadView::within(0, 511, 512).unwrap()).unwrap();
        let mut memory = [0; 512];
        assert_eq!(
            decode_probe_response(&Fat32Provider.probe(&short, &mut memory).unwrap()),
            Ok(Err(ProbeError::InvalidRequest))
        );
        let unsupported =
            encode_probe_request(volume, BorrowedReadView::within(0, 512, 512).unwrap()).unwrap();
        assert_eq!(
            decode_probe_response(&Fat32Provider.probe(&unsupported, &mut memory).unwrap()),
            Ok(Err(ProbeError::UnsupportedFilesystem))
        );
    }

    #[test]
    fn rejects_fat16_shapes_and_undersized_fat() {
        let mut fat16 = boot_sector();
        fat16[17..19].copy_from_slice(&512_u16.to_le_bytes());
        assert_eq!(parse_fat32_boot_sector(&fat16), Err(Fat32Error::NotFat32));

        let mut small = boot_sector();
        small[36..40].copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(
            parse_fat32_boot_sector(&small),
            Err(Fat32Error::FatTooSmall)
        );
    }

    #[test]
    fn rejects_reserved_extent_root_and_arithmetic_boundaries() {
        let mut reserved = boot_sector();
        reserved[48..50].copy_from_slice(&32_u16.to_le_bytes());
        assert_eq!(
            parse_fat32_boot_sector(&reserved),
            Err(Fat32Error::InvalidReservedArea)
        );

        let mut root = boot_sector();
        root[44..48].copy_from_slice(&200_000_u32.to_le_bytes());
        assert_eq!(
            parse_fat32_boot_sector(&root),
            Err(Fat32Error::InvalidRootCluster)
        );

        let mut extent = boot_sector();
        extent[32..36].copy_from_slice(&100_u32.to_le_bytes());
        assert_eq!(
            parse_fat32_boot_sector(&extent),
            Err(Fat32Error::InvalidExtent)
        );
    }

    #[test]
    fn rejects_noncanonical_sector_cluster_and_signature_fields() {
        for mutate in [
            |sector: &mut [u8; 512]| sector[0] = 0,
            |sector: &mut [u8; 512]| sector[11..13].copy_from_slice(&768_u16.to_le_bytes()),
            |sector: &mut [u8; 512]| sector[13] = 3,
            |sector: &mut [u8; 512]| sector[510] = 0,
        ] {
            assert!(
                parse_fat32_boot_sector(&{
                    let mut sector = boot_sector();
                    mutate(&mut sector);
                    sector
                })
                .is_err()
            );
        }
    }

    #[test]
    fn parses_fs_info_only_at_the_boot_bound_reserved_sector() {
        let geometry = parse_fat32_boot_sector(&boot_sector()).unwrap();
        assert_eq!(
            parse_fat32_fs_info(geometry, 1, &fs_info()),
            Ok(Fat32FsInfo {
                free_cluster_count: Some(1000),
                next_free_cluster: Some(3),
            })
        );
        assert_eq!(
            parse_fat32_fs_info(geometry, 2, &fs_info()),
            Err(Fat32Error::WrongFsInfoSector)
        );
    }

    #[test]
    fn accepts_unknown_hints_but_rejects_out_of_range_values() {
        let geometry = parse_fat32_boot_sector(&boot_sector()).unwrap();
        let mut unknown = fs_info();
        unknown[488..496].fill(0xff);
        assert_eq!(
            parse_fat32_fs_info(geometry, 1, &unknown),
            Ok(Fat32FsInfo {
                free_cluster_count: None,
                next_free_cluster: None,
            })
        );
        let mut invalid = fs_info();
        invalid[488..492].copy_from_slice(&(geometry.cluster_count + 1).to_le_bytes());
        assert_eq!(
            parse_fat32_fs_info(geometry, 1, &invalid),
            Err(Fat32Error::InvalidFsInfoHint)
        );
        invalid = fs_info();
        invalid[492..496].copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(
            parse_fat32_fs_info(geometry, 1, &invalid),
            Err(Fat32Error::InvalidFsInfoHint)
        );
    }

    #[test]
    fn rejects_each_fs_info_signature_independently() {
        let geometry = parse_fat32_boot_sector(&boot_sector()).unwrap();
        for offset in [0, 484, 508] {
            let mut sector = fs_info();
            sector[offset] ^= 1;
            assert_eq!(
                parse_fat32_fs_info(geometry, 1, &sector),
                Err(Fat32Error::InvalidFsInfoSignature)
            );
        }
    }

    struct Reader {
        entries: [[u32; 8]; 2],
        reads: [usize; 2],
    }

    impl Fat32EntryReader for Reader {
        fn read_entry(&mut self, fat_index: u8, cluster: u32) -> Result<u32, ()> {
            let fat = usize::from(fat_index);
            let cluster = usize::try_from(cluster).map_err(|_| ())?;
            self.reads[fat] += 1;
            self.entries
                .get(fat)
                .and_then(|entries| entries.get(cluster))
                .copied()
                .ok_or(())
        }
    }

    fn chain_reader() -> Reader {
        let mut entries = [[0; 8]; 2];
        for fat in &mut entries {
            fat[2] = 3;
            fat[3] = 4;
            fat[4] = 0x0fff_ffff;
        }
        Reader {
            entries,
            reads: [0; 2],
        }
    }

    struct ClusterReader {
        fail_cluster: Option<u32>,
        reads: [u8; 8],
    }

    impl Fat32ClusterReader for ClusterReader {
        fn read_cluster(&mut self, cluster: u32, destination: &mut [u8]) -> Result<(), ()> {
            let index = usize::try_from(cluster).map_err(|_| ())?;
            *self.reads.get_mut(index).ok_or(())? += 1;
            if self.fail_cluster == Some(cluster) {
                destination.fill(0xcc);
                return Err(());
            }
            for (offset, byte) in destination.iter_mut().enumerate() {
                *byte = cluster.wrapping_mul(17).wrapping_add(offset as u32) as u8;
            }
            Ok(())
        }
    }

    fn file_entry(first_cluster: u32, file_size: u32) -> Fat32ShortDirectoryEntry {
        Fat32ShortDirectoryEntry {
            short_name: *b"PAYLOAD BIN",
            long_name: None,
            attributes: 0x20,
            first_cluster,
            file_size,
        }
    }

    #[test]
    fn reads_bounded_chain_only_when_mirrored_fats_agree() {
        let geometry = parse_fat32_boot_sector(&boot_sector()).unwrap();
        let mut reader = chain_reader();
        let chain = read_fat32_cluster_chain::<4, _>(geometry, 2, &mut reader).unwrap();
        assert_eq!(chain.clusters(), &[2, 3, 4]);
        assert_eq!(reader.reads, [3, 3]);

        reader = chain_reader();
        reader.entries[1][3] = 5;
        assert_eq!(
            read_fat32_cluster_chain::<4, _>(geometry, 2, &mut reader),
            Err(Fat32Error::MirroredFatMismatch)
        );
    }

    #[test]
    fn validated_active_fat_disables_mirror_reads() {
        let mut sector = boot_sector();
        sector[40..42].copy_from_slice(&0x0081_u16.to_le_bytes());
        let geometry = parse_fat32_boot_sector(&sector).unwrap();
        assert_eq!(
            (geometry.mirroring_enabled, geometry.active_fat),
            (false, 1)
        );
        let mut reader = chain_reader();
        reader.entries[0][2] = 0;
        assert_eq!(
            read_fat32_cluster_chain::<4, _>(geometry, 2, &mut reader)
                .unwrap()
                .clusters(),
            &[2, 3, 4]
        );
        assert_eq!(reader.reads, [0, 3]);
    }

    #[test]
    fn rejects_cycles_bad_free_reserved_and_capacity_exhaustion() {
        let geometry = parse_fat32_boot_sector(&boot_sector()).unwrap();
        for (entry, error) in [
            (0, Fat32Error::FreeClusterInChain),
            (1, Fat32Error::ReservedClusterInChain),
            (0x0fff_fff7, Fat32Error::BadCluster),
        ] {
            let mut reader = chain_reader();
            reader.entries[0][2] = entry;
            reader.entries[1][2] = entry;
            assert_eq!(
                read_fat32_cluster_chain::<4, _>(geometry, 2, &mut reader),
                Err(error)
            );
        }
        let mut reader = chain_reader();
        reader.entries[0][4] = 2;
        reader.entries[1][4] = 2;
        assert_eq!(
            read_fat32_cluster_chain::<4, _>(geometry, 2, &mut reader),
            Err(Fat32Error::ClusterCycle)
        );
        let mut reader = chain_reader();
        assert_eq!(
            read_fat32_cluster_chain::<2, _>(geometry, 2, &mut reader),
            Err(Fat32Error::ChainCapacity)
        );
    }

    #[test]
    fn rejects_reserved_active_fat_selection() {
        for flags in [0x0001_u16, 0x0082, 0x0100] {
            let mut sector = boot_sector();
            sector[40..42].copy_from_slice(&flags.to_le_bytes());
            assert_eq!(
                parse_fat32_boot_sector(&sector),
                Err(Fat32Error::InvalidFatSelection)
            );
        }
    }

    #[test]
    fn parses_bounded_short_file_directory_and_end_marker() {
        let geometry = parse_fat32_boot_sector(&boot_sector()).unwrap();
        let mut bytes = [0; 96];
        bytes[..32].copy_from_slice(&short_entry(b"KERNEL  MRP", 0x20, 5, 4096));
        bytes[32..64].copy_from_slice(&short_entry(b"SYSTEM     ", 0x10, 6, 0));
        let batch = parse_fat32_short_directory::<4>(geometry, &bytes).unwrap();
        assert!(batch.end_of_directory);
        assert_eq!(batch.entries().len(), 2);
        assert_eq!(batch.entries()[0].short_name, *b"KERNEL  MRP");
        assert_eq!(
            (
                batch.entries()[0].first_cluster,
                batch.entries()[0].file_size
            ),
            (5, 4096)
        );
        assert!(batch.entries()[1].is_directory());
    }

    #[test]
    fn lookup_is_bounded_non_authorizing_and_rejects_ambiguous_aliases() {
        let mut long_units = [0; 255];
        let long_name = ascii_utf16(b"Accessible notes.txt");
        long_units[..long_name.len()].copy_from_slice(&long_name);
        let file = Fat32ShortDirectoryEntry {
            short_name: *b"ACCESS~1TXT",
            long_name: Some(Fat32LongName {
                utf16: long_units,
                length: long_name.len() as u8,
            }),
            attributes: 0x20,
            first_cluster: 8,
            file_size: 20,
        };
        let label = Fat32ShortDirectoryEntry {
            short_name: *b"ACCESS~1TXT",
            long_name: None,
            attributes: 0x08,
            first_cluster: 0,
            file_size: 0,
        };
        let mut directory = Fat32DirectoryBatch::<3>::new();
        directory.entries[0] = file;
        directory.entries[1] = label;
        directory.length = 2;

        assert_eq!(
            lookup_fat32_directory_entry(&directory, &ascii_utf16(b"accessible NOTES.txt")),
            Ok(file)
        );
        assert_eq!(
            lookup_fat32_directory_entry(&directory, &ascii_utf16(b"access~1.txt")),
            Ok(file)
        );
        assert_eq!(
            lookup_fat32_directory_entry(&directory, &ascii_utf16(b"missing.txt")),
            Err(Fat32Error::LookupNotFound)
        );
        assert_eq!(
            lookup_fat32_directory_entry(&directory, &ascii_utf16(b"bad/name")),
            Err(Fat32Error::InvalidLookupName)
        );

        directory.entries[2] = file;
        directory.length = 3;
        assert_eq!(
            lookup_fat32_directory_entry(&directory, &ascii_utf16(b"ACCESS~1.TXT")),
            Err(Fat32Error::AmbiguousLookup)
        );
    }

    #[test]
    fn skips_deleted_entries_and_maps_first_byte_escape() {
        let geometry = parse_fat32_boot_sector(&boot_sector()).unwrap();
        let mut bytes = [0; 64];
        bytes[0] = 0xe5;
        bytes[32..].copy_from_slice(&short_entry(
            &[
                0x05, b'I', b'L', b'E', b' ', b' ', b' ', b' ', b'B', b'I', b'N',
            ],
            0x20,
            7,
            1,
        ));
        let batch = parse_fat32_short_directory::<1>(geometry, &bytes).unwrap();
        assert!(!batch.end_of_directory);
        assert_eq!(batch.entries()[0].short_name[0], 0xe5);
    }

    #[test]
    fn parses_checked_long_name_and_rejects_exhausted_output_capacity() {
        let geometry = parse_fat32_boot_sector(&boot_sector()).unwrap();
        let short_name = *b"LONGNA~1MRP";
        let checksum = short_name_checksum(&short_name);
        let mut units = [0xffff; 13];
        for (target, source) in units.iter_mut().zip("Long name.mrp".encode_utf16()) {
            *target = source;
        }
        let mut named = [0; 96];
        named[..32].copy_from_slice(&long_entry(1, true, checksum, &units));
        named[32..64].copy_from_slice(&short_entry(&short_name, 0x20, 5, 1));
        let parsed = parse_fat32_short_directory::<2>(geometry, &named).unwrap();
        assert_eq!(
            parsed.entries()[0].long_name.unwrap().utf16(),
            &ascii_utf16(b"Long name.mrp")
        );
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(&short_entry(b"FIRST   BIN", 0x20, 5, 1));
        bytes[32..].copy_from_slice(&short_entry(b"SECOND  BIN", 0x20, 6, 1));
        assert_eq!(
            parse_fat32_short_directory::<1>(geometry, &bytes),
            Err(Fat32Error::DirectoryCapacity)
        );
    }

    #[test]
    fn rejects_invalid_short_entry_shapes_and_extents() {
        let geometry = parse_fat32_boot_sector(&boot_sector()).unwrap();
        for entry in [
            short_entry(b"BAD     BIN", 0xc0, 5, 1),
            short_entry(b"BAD     BIN", 0x10, 5, 1),
            short_entry(b"BAD     BIN", 0x20, 0, 1),
            short_entry(b"BAD?    BIN", 0x20, 5, 1),
        ] {
            assert_eq!(
                parse_fat32_short_directory::<1>(geometry, &entry),
                Err(Fat32Error::InvalidDirectoryEntry)
            );
        }
        assert_eq!(
            parse_fat32_short_directory::<1>(geometry, &[0; 31]),
            Err(Fat32Error::InvalidDirectoryExtent)
        );
    }

    #[test]
    fn composes_short_directory_across_cluster_extents() {
        let geometry = parse_fat32_boot_sector(&boot_sector()).unwrap();
        let first = short_entry(b"FIRST   BIN", 0x20, 5, 1);
        let mut second = [0; 64];
        second[..32].copy_from_slice(&short_entry(b"SECOND  BIN", 0x20, 6, 2));
        let mut directory = Fat32DirectoryBatch::<3>::new();
        append_fat32_short_directory(geometry, &mut directory, &first).unwrap();
        assert!(!directory.end_of_directory);
        append_fat32_short_directory(geometry, &mut directory, &second).unwrap();
        assert!(directory.end_of_directory);
        assert_eq!(directory.entries().len(), 2);
        assert_eq!(directory.entries()[1].short_name, *b"SECOND  BIN");
    }

    #[test]
    fn rejects_extent_after_directory_end() {
        let geometry = parse_fat32_boot_sector(&boot_sector()).unwrap();
        let mut directory = parse_fat32_short_directory::<1>(geometry, &[0; 32]).unwrap();
        assert_eq!(
            append_fat32_short_directory(geometry, &mut directory, &[0; 32]),
            Err(Fat32Error::DirectoryAlreadyEnded)
        );
    }

    #[test]
    fn failed_extent_append_is_atomic() {
        let geometry = parse_fat32_boot_sector(&boot_sector()).unwrap();
        let mut directory = Fat32DirectoryBatch::<2>::new();
        let first = short_entry(b"FIRST   BIN", 0x20, 5, 1);
        append_fat32_short_directory(geometry, &mut directory, &first).unwrap();
        let before = directory;
        let mut invalid = [0; 64];
        invalid[..32].copy_from_slice(&short_entry(b"SECOND  BIN", 0x20, 6, 2));
        invalid[32..].copy_from_slice(&short_entry(b"BAD?    BIN", 0x20, 7, 3));
        assert_eq!(
            append_fat32_short_directory(geometry, &mut directory, &invalid),
            Err(Fat32Error::InvalidDirectoryEntry)
        );
        assert_eq!(directory, before);
    }

    #[test]
    fn composes_long_name_sequence_across_cluster_extents() {
        let geometry = parse_fat32_boot_sector(&boot_sector()).unwrap();
        let short_name = *b"ACCESS~1TXT";
        let checksum = short_name_checksum(&short_name);
        let name = ascii_utf16(b"Accessible notes.txt");
        let mut first = [0; 32];
        first.copy_from_slice(&long_entry(2, true, checksum, &name[13..]));
        let mut second = [0; 96];
        second[..32].copy_from_slice(&long_entry(1, false, checksum, &name[..13]));
        second[32..64].copy_from_slice(&short_entry(&short_name, 0x20, 8, 20));
        let mut directory = Fat32DirectoryBatch::<2>::new();
        append_fat32_short_directory(geometry, &mut directory, &first).unwrap();
        append_fat32_short_directory(geometry, &mut directory, &second).unwrap();
        assert_eq!(directory.entries()[0].long_name.unwrap().utf16(), &name);
    }

    #[test]
    fn rejects_wrong_long_name_order_checksum_and_reserved_fields_atomically() {
        let geometry = parse_fat32_boot_sector(&boot_sector()).unwrap();
        let short_name = *b"INVALID TXT";
        let checksum = short_name_checksum(&short_name);
        let units = ascii_utf16(b"Invalid sequence");
        let mut directory = Fat32DirectoryBatch::<2>::new();
        let before = directory;
        let wrong_order = long_entry(1, false, checksum, &units[..13]);
        assert_eq!(
            append_fat32_short_directory(geometry, &mut directory, &wrong_order),
            Err(Fat32Error::InvalidLongNameSequence)
        );
        assert_eq!(directory, before);

        let mut wrong_checksum = [0; 64];
        wrong_checksum[..32].copy_from_slice(&long_entry(
            1,
            true,
            checksum.wrapping_add(1),
            &units[..13],
        ));
        wrong_checksum[32..].copy_from_slice(&short_entry(&short_name, 0x20, 5, 1));
        assert_eq!(
            append_fat32_short_directory(geometry, &mut directory, &wrong_checksum),
            Err(Fat32Error::InvalidLongNameSequence)
        );
        assert_eq!(directory, before);

        let mut reserved = long_entry(1, true, checksum, &units[..13]);
        reserved[26] = 1;
        assert_eq!(
            append_fat32_short_directory(geometry, &mut directory, &reserved),
            Err(Fat32Error::InvalidLongNameSequence)
        );
        assert_eq!(directory, before);
    }

    #[test]
    fn rejects_invalid_long_name_encoding_and_checksum() {
        let geometry = parse_fat32_boot_sector(&boot_sector()).unwrap();
        let short_name = *b"INVALID TXT";
        let checksum = short_name_checksum(&short_name);
        for units in [
            [
                0xd800, 0, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
                0xffff, 0xffff,
            ],
            [
                b'B' as u16,
                b'a' as u16,
                b'd' as u16,
                b'/' as u16,
                0,
                0xffff,
                0xffff,
                0xffff,
                0xffff,
                0xffff,
                0xffff,
                0xffff,
                0xffff,
            ],
        ] {
            let mut bytes = [0; 64];
            bytes[..32].copy_from_slice(&long_entry(1, true, checksum, &units));
            bytes[32..].copy_from_slice(&short_entry(&short_name, 0x20, 5, 1));
            assert_eq!(
                parse_fat32_short_directory::<1>(geometry, &bytes),
                Err(Fat32Error::InvalidLongNameEncoding)
            );
        }
        let units = ascii_utf16(b"Checksum");
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(&long_entry(1, true, checksum.wrapping_add(1), &units));
        bytes[32..].copy_from_slice(&short_entry(&short_name, 0x20, 5, 1));
        assert_eq!(
            parse_fat32_short_directory::<1>(geometry, &bytes),
            Err(Fat32Error::InvalidLongNameSequence)
        );
    }

    #[test]
    fn reads_atomic_file_range_across_validated_clusters() {
        let geometry = parse_fat32_boot_sector(&boot_sector()).unwrap();
        let mut fat = chain_reader();
        let chain = read_fat32_cluster_chain::<4, _>(geometry, 2, &mut fat).unwrap();
        let mut reader = ClusterReader {
            fail_cluster: None,
            reads: [0; 8],
        };
        let mut output = [0xaa; 20];
        let mut staging = [0xbb; 20];
        let mut scratch = [0xdd; 4096];
        read_fat32_file_range(
            geometry,
            file_entry(2, 9000),
            Some(&chain),
            4090,
            &mut output,
            &mut staging,
            &mut scratch,
            &mut reader,
        )
        .unwrap();
        for (index, &byte) in output.iter().enumerate() {
            let (cluster, offset) = if index < 6 {
                (2_u32, 4090 + index)
            } else {
                (3_u32, index - 6)
            };
            assert_eq!(
                byte,
                cluster.wrapping_mul(17).wrapping_add(offset as u32) as u8
            );
        }
        assert_eq!(reader.reads, [0, 0, 1, 1, 0, 0, 0, 0]);
        assert_eq!(staging, [0; 20]);
        assert_eq!(scratch, [0; 4096]);
    }

    #[test]
    fn failed_cluster_read_preserves_output_and_clears_temporaries() {
        let geometry = parse_fat32_boot_sector(&boot_sector()).unwrap();
        let mut fat = chain_reader();
        let chain = read_fat32_cluster_chain::<4, _>(geometry, 2, &mut fat).unwrap();
        let mut reader = ClusterReader {
            fail_cluster: Some(3),
            reads: [0; 8],
        };
        let mut output = [0xaa; 20];
        let mut staging = [0xbb; 20];
        let mut scratch = [0xdd; 4096];
        assert_eq!(
            read_fat32_file_range(
                geometry,
                file_entry(2, 9000),
                Some(&chain),
                4090,
                &mut output,
                &mut staging,
                &mut scratch,
                &mut reader,
            ),
            Err(Fat32Error::FileRead)
        );
        assert_eq!(output, [0xaa; 20]);
        assert_eq!(staging, [0; 20]);
        assert_eq!(scratch, [0; 4096]);
    }

    #[test]
    fn rejects_file_range_entry_and_buffer_mismatch_before_io() {
        let geometry = parse_fat32_boot_sector(&boot_sector()).unwrap();
        let mut fat = chain_reader();
        let chain = read_fat32_cluster_chain::<4, _>(geometry, 2, &mut fat).unwrap();
        let mut reader = ClusterReader {
            fail_cluster: None,
            reads: [0; 8],
        };
        let mut output = [0xaa; 2];
        let mut staging = [0xbb; 2];
        let mut scratch = [0xdd; 4096];
        assert_eq!(
            read_fat32_file_range(
                geometry,
                file_entry(2, 9000),
                Some(&chain),
                8999,
                &mut output,
                &mut staging,
                &mut scratch,
                &mut reader,
            ),
            Err(Fat32Error::InvalidFileRange)
        );
        let mut directory = file_entry(2, 9000);
        directory.attributes = 0x10;
        assert_eq!(
            read_fat32_file_range(
                geometry,
                directory,
                Some(&chain),
                0,
                &mut output,
                &mut staging,
                &mut scratch,
                &mut reader,
            ),
            Err(Fat32Error::InvalidFileEntry)
        );
        let mut short_scratch = [0; 512];
        assert_eq!(
            read_fat32_file_range(
                geometry,
                file_entry(2, 9000),
                Some(&chain),
                0,
                &mut output,
                &mut staging,
                &mut short_scratch,
                &mut reader,
            ),
            Err(Fat32Error::InvalidReadBuffers)
        );
        assert_eq!(reader.reads, [0; 8]);
    }

    #[test]
    fn accepts_only_canonical_empty_file_without_a_chain() {
        let geometry = parse_fat32_boot_sector(&boot_sector()).unwrap();
        let mut reader = ClusterReader {
            fail_cluster: None,
            reads: [0; 8],
        };
        let mut output = [];
        let mut staging = [];
        let mut scratch = [0xdd; 4096];
        assert_eq!(
            read_fat32_file_range::<1, _>(
                geometry,
                file_entry(0, 0),
                None,
                0,
                &mut output,
                &mut staging,
                &mut scratch,
                &mut reader,
            ),
            Ok(())
        );
        assert_eq!(scratch, [0; 4096]);
        assert_eq!(reader.reads, [0; 8]);
    }

    #[test]
    fn rejects_file_chain_with_trailing_allocated_clusters() {
        let geometry = parse_fat32_boot_sector(&boot_sector()).unwrap();
        let mut fat = chain_reader();
        let chain = read_fat32_cluster_chain::<4, _>(geometry, 2, &mut fat).unwrap();
        let mut reader = ClusterReader {
            fail_cluster: None,
            reads: [0; 8],
        };
        let mut output = [0; 1];
        let mut staging = [0; 1];
        let mut scratch = [0; 4096];
        assert_eq!(
            read_fat32_file_range(
                geometry,
                file_entry(2, 4096),
                Some(&chain),
                0,
                &mut output,
                &mut staging,
                &mut scratch,
                &mut reader,
            ),
            Err(Fat32Error::InvalidFileChain)
        );
        assert_eq!(reader.reads, [0; 8]);
    }
}
