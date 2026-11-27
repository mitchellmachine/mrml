#![no_std]

pub mod boot_random {
    /// Fills a 32-byte sample with four independently successful RDRAND words.
    /// An unavailable word is retried at most ten times; no partial sample escapes.
    pub fn collect(mut next_word: impl FnMut() -> Option<u64>) -> Option<[u8; 32]> {
        let mut sample = [0; 32];
        for chunk in sample.chunks_exact_mut(8) {
            let word = (0..10).find_map(|_| next_word())?;
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        Some(sample)
    }

    #[cfg(test)]
    mod tests {
        use super::collect;

        #[test]
        fn retries_each_word_without_using_failed_attempts() {
            let mut attempts = 0u64;
            let sample = collect(|| {
                attempts += 1;
                (attempts.is_multiple_of(10)).then_some(attempts)
            })
            .unwrap();
            assert_eq!(attempts, 40);
            for (word, expected) in sample.chunks_exact(8).zip([10u64, 20, 30, 40]) {
                assert_eq!(word, expected.to_le_bytes());
            }
        }

        #[test]
        fn exhausted_retries_discard_the_partial_sample() {
            let mut attempts = 0;
            assert_eq!(
                collect(|| {
                    attempts += 1;
                    (attempts <= 2).then_some(42)
                }),
                None
            );
            assert_eq!(attempts, 12);
        }
    }
}

pub mod tpm;

pub const BOOT_REPORT_BYTES: usize = 16 * 1024;
pub const BOOT_REPORT_MAGIC: &[u8; 16] = b"MRML BOOT LOG V1";

struct ReportText<'a>(&'a mut [u8], usize);

impl core::fmt::Write for ReportText<'_> {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        let end = self.1.checked_add(text.len()).ok_or(core::fmt::Error)?;
        self.0
            .get_mut(self.1..end)
            .ok_or(core::fmt::Error)?
            .copy_from_slice(text.as_bytes());
        self.1 = end;
        Ok(())
    }
}

/// Encodes only operation metadata and selected fields from the firmware map.
/// Never includes raw descriptor padding, mapped contents, or RNG output.
pub fn encode_boot_report(
    output: &mut [u8; BOOT_REPORT_BYTES],
    stage: &'static str,
    failure: Option<Status>,
    map: Result<(&[u8], usize, u32), Status>,
) -> core::fmt::Result {
    use core::fmt::Write;
    const REPORTED_DESCRIPTORS: usize = 192;
    output.fill(b' ');
    output[..BOOT_REPORT_MAGIC.len()].copy_from_slice(BOOT_REPORT_MAGIC);
    let mut out = ReportText(output, BOOT_REPORT_MAGIC.len());
    write!(out, "\r\nStage: {stage}\r\n")?;
    match failure {
        Some(status) => write!(
            out,
            "Result: pre-exit failure (EFI status {status:#018x})\r\n"
        )?,
        None => write!(out, "Result: pre-exit checkpoint; not a boot result\r\n")?,
    }
    match map {
        Ok((bytes, stride, version))
            if stride >= 40
                && !bytes.is_empty()
                && bytes.len() <= MAX_MEMORY_MAP_BYTES
                && bytes.len().is_multiple_of(stride) =>
        {
            let count = bytes.len() / stride;
            write!(
                out,
                "Map: pre-exit snapshot; entries={count} stride={stride} version={version}\r\n"
            )?;
            write!(
                out,
                "Type     PhysicalStart    Pages            Attributes\r\n"
            )?;
            for row in bytes.chunks_exact(stride).take(REPORTED_DESCRIPTORS) {
                let kind = u32::from_le_bytes(row[..4].try_into().unwrap());
                let start = u64::from_le_bytes(row[8..16].try_into().unwrap());
                let pages = u64::from_le_bytes(row[24..32].try_into().unwrap());
                let attrs = u64::from_le_bytes(row[32..40].try_into().unwrap());
                write!(out, "{kind:08x} {start:016x} {pages:016x} {attrs:016x}\r\n")?;
            }
            if count > REPORTED_DESCRIPTORS {
                write!(
                    out,
                    "Map truncated: showing first {REPORTED_DESCRIPTORS} entries\r\n"
                )?;
            }
        }
        Ok(_) => write!(out, "Map unavailable: invalid returned geometry\r\n")?,
        Err(status) => write!(out, "Map unavailable: EFI status {status:#018x}\r\n")?,
    }
    write!(out, "END MRML BOOT LOG\r\n")
}

use core::ffi::c_void;
use mrml_storage::{
    BlockDeviceDescriptor, BlockDeviceId, BlockVolume, BlockVolumeError,
    CanonicalUefiBlockDevicePathError, CanonicalUefiSataBlockRoute,
    MAX_CANONICAL_UEFI_BLOCK_DEVICE_PATH_BYTES, PlatformBlockDeviceDescriptor,
    PlatformBlockDeviceIdentity, PlatformBlockTransport, RecoveredReachableState, RecoveryError,
    SUPERBLOCK_BYTES, StorageBlockDevice, VOLUME_HEADER_BYTES, VolumeHeader, VolumeId,
    canonical_uefi_block_stable_id, parse_canonical_uefi_sata_block_route, recover_reachable_state,
};

pub type Status = usize;
pub type Handle = *mut c_void;
pub const SUCCESS: Status = 0;
pub const BUFFER_TOO_SMALL: Status = (1usize << (usize::BITS - 1)) | 5;
pub const LOAD_ERROR: Status = (1usize << (usize::BITS - 1)) | 1;
pub const NOT_FOUND: Status = (1usize << (usize::BITS - 1)) | 14;

pub const MAX_BOOT_LOAD_OPTION_UNITS: usize = 128;

/// Authority-free one-boot isolation selection decoded from UEFI LoadOptions.
/// The selected SystemGeneration, signatures, policy floors, and capabilities
/// remain separate admission inputs; this value cannot authorize execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootIsolationSelection {
    ConfiguredDefault,
    TotalMicrovmOnce,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootLoadOptionError {
    TooLong,
    OddByteLength,
    MissingBuffer,
    MisalignedBuffer,
    NonAscii,
    EmbeddedNull,
    NonCanonicalWhitespace,
    UnknownProgram,
    UnknownOption,
}

/// Validates and parses the firmware-owned LoadOptions buffer from a loaded
/// image. No firmware pointer is dereferenced until its byte length, nullness,
/// and `u16` alignment have been checked.
///
/// # Safety
///
/// A non-null `loaded.load_options` must remain readable for exactly
/// `loaded.load_options_size` bytes for the duration of this call.
pub unsafe fn parse_loaded_image_boot_isolation(
    loaded: &LoadedImageProtocol,
) -> Result<BootIsolationSelection, BootLoadOptionError> {
    let byte_length = loaded.load_options_size as usize;
    let maximum_bytes = MAX_BOOT_LOAD_OPTION_UNITS * core::mem::size_of::<u16>();
    if byte_length > maximum_bytes {
        return Err(BootLoadOptionError::TooLong);
    }
    if !byte_length.is_multiple_of(core::mem::size_of::<u16>()) {
        return Err(BootLoadOptionError::OddByteLength);
    }
    if byte_length == 0 {
        return parse_boot_isolation_selection(&[]);
    }
    if loaded.load_options.is_null() {
        return Err(BootLoadOptionError::MissingBuffer);
    }
    if !(loaded.load_options as usize).is_multiple_of(core::mem::align_of::<u16>()) {
        return Err(BootLoadOptionError::MisalignedBuffer);
    }
    let options = unsafe {
        core::slice::from_raw_parts(
            loaded.load_options.cast::<u16>(),
            byte_length / core::mem::size_of::<u16>(),
        )
    };
    parse_boot_isolation_selection(options)
}

/// Parses the same bounded UEFI LoadOptions representation for a firmware boot
/// entry and an EFI Shell launch. The only accepted option is the exact strict
/// one-boot Total MicroVM request. An optional shell program token must name
/// `BOOTX64.EFI`; filenames remain presentation and grant no authority.
pub fn parse_boot_isolation_selection(
    load_options: &[u16],
) -> Result<BootIsolationSelection, BootLoadOptionError> {
    if load_options.len() > MAX_BOOT_LOAD_OPTION_UNITS {
        return Err(BootLoadOptionError::TooLong);
    }

    let input = match load_options.last() {
        Some(0) => &load_options[..load_options.len() - 1],
        _ => load_options,
    };
    if input.contains(&0) {
        return Err(BootLoadOptionError::EmbeddedNull);
    }
    if input.iter().any(|unit| *unit > 0x7f) {
        return Err(BootLoadOptionError::NonAscii);
    }
    if input.is_empty() {
        return Ok(BootIsolationSelection::ConfiguredDefault);
    }
    if input.first() == Some(&u16::from(b' '))
        || input.last() == Some(&u16::from(b' '))
        || input.windows(2).any(|pair| pair == [u16::from(b' '); 2])
        || input.iter().any(|unit| matches!(*unit, 0x09 | 0x0a | 0x0d))
    {
        return Err(BootLoadOptionError::NonCanonicalWhitespace);
    }

    let separator = input.iter().position(|unit| *unit == u16::from(b' '));
    let (program, option) = match separator {
        _ if input.first() == Some(&u16::from(b'-')) => (&[][..], Some(input)),
        Some(index) => (&input[..index], Some(&input[index + 1..])),
        None => (input, None),
    };
    if !program.is_empty() && !uefi_program_is_bootx64(program) {
        return Err(BootLoadOptionError::UnknownProgram);
    }
    match option {
        None => Ok(BootIsolationSelection::ConfiguredDefault),
        Some(option) if ascii_eq(option, b"--isolation=total-microvm") => {
            Ok(BootIsolationSelection::TotalMicrovmOnce)
        }
        Some(_) => Err(BootLoadOptionError::UnknownOption),
    }
}

fn uefi_program_is_bootx64(program: &[u16]) -> bool {
    let basename = program
        .iter()
        .rposition(|unit| matches!(*unit, 0x2f | 0x5c))
        .map_or(program, |index| &program[index + 1..]);
    ascii_eq_ignore_case(basename, b"BOOTX64.EFI")
}

fn ascii_eq(input: &[u16], expected: &[u8]) -> bool {
    input.len() == expected.len()
        && input
            .iter()
            .zip(expected)
            .all(|(actual, expected)| *actual == u16::from(*expected))
}

fn ascii_eq_ignore_case(input: &[u16], expected: &[u8]) -> bool {
    input.len() == expected.len()
        && input.iter().zip(expected).all(|(actual, expected)| {
            u8::try_from(*actual).is_ok_and(|actual| actual.eq_ignore_ascii_case(expected))
        })
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

pub const GOP_GUID: Guid = Guid {
    data1: 0x9042_a9de,
    data2: 0x23dc,
    data3: 0x4a38,
    data4: [0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a],
};
pub const EDID_ACTIVE_GUID: Guid = Guid {
    data1: 0xbd8c_1056,
    data2: 0x9f36,
    data3: 0x44ec,
    data4: [0x92, 0xa8, 0xa6, 0x33, 0x7f, 0x81, 0x79, 0x86],
};
pub const EDID_DISCOVERED_GUID: Guid = Guid {
    data1: 0x1c0c_34f6,
    data2: 0xd380,
    data3: 0x41fa,
    data4: [0xa0, 0x49, 0x8a, 0xd0, 0x6c, 0x1a, 0x66, 0xaa],
};
pub const RNG_GUID: Guid = Guid {
    data1: 0x3152_bca5,
    data2: 0xeade,
    data3: 0x433d,
    data4: [0x86, 0x2e, 0xc0, 0x1c, 0xdc, 0x29, 0x1f, 0x44],
};
pub const LOADED_IMAGE_GUID: Guid = Guid {
    data1: 0x5b1b_31a1,
    data2: 0x9562,
    data3: 0x11d2,
    data4: [0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};
pub const SIMPLE_FILE_SYSTEM_GUID: Guid = Guid {
    data1: 0x964e_5b22,
    data2: 0x6459,
    data3: 0x11d2,
    data4: [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};
pub const FILE_INFO_GUID: Guid = Guid {
    data1: 0x0957_6e92,
    data2: 0x6d3f,
    data3: 0x11d2,
    data4: [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};
pub const TCG2_PROTOCOL_GUID: Guid = Guid {
    data1: 0x607f_766c,
    data2: 0x7455,
    data3: 0x42be,
    data4: [0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f],
};
pub const GLOBAL_VARIABLE_GUID: Guid = Guid {
    data1: 0x8be4_df61,
    data2: 0x93ca,
    data3: 0x11d2,
    data4: [0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c],
};
pub const ACPI_20_TABLE_GUID: Guid = Guid {
    data1: 0x8868_e871,
    data2: 0xe4f1,
    data3: 0x11d3,
    data4: [0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81],
};
pub const ACPI_TABLE_GUID: Guid = Guid {
    data1: 0xeb9d_2d30,
    data2: 0x2d88,
    data3: 0x11d3,
    data4: [0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
};
pub const BLOCK_IO_PROTOCOL_GUID: Guid = Guid {
    data1: 0x964e_5b21,
    data2: 0x6459,
    data3: 0x11d2,
    data4: [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};
pub const DEVICE_PATH_PROTOCOL_GUID: Guid = Guid {
    data1: 0x0957_6e91,
    data2: 0x6d3f,
    data3: 0x11d2,
    data4: [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};

impl Guid {
    pub const fn equals(&self, other: &Self) -> bool {
        self.data1 == other.data1
            && self.data2 == other.data2
            && self.data3 == other.data3
            && self.data4[0] == other.data4[0]
            && self.data4[1] == other.data4[1]
            && self.data4[2] == other.data4[2]
            && self.data4[3] == other.data4[3]
            && self.data4[4] == other.data4[4]
            && self.data4[5] == other.data4[5]
            && self.data4[6] == other.data4[6]
            && self.data4[7] == other.data4[7]
    }
}

#[repr(C)]
pub struct TableHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
    pub reserved: u32,
}

pub type GetMemoryMap = unsafe extern "efiapi" fn(
    *mut usize,
    *mut MemoryDescriptor,
    *mut usize,
    *mut usize,
    *mut u32,
) -> Status;
pub type ExitBootServices = unsafe extern "efiapi" fn(Handle, usize) -> Status;
pub type LocateProtocol =
    unsafe extern "efiapi" fn(*const Guid, *mut c_void, *mut *mut c_void) -> Status;
pub type HandleProtocol =
    unsafe extern "efiapi" fn(Handle, *const Guid, *mut *mut c_void) -> Status;
pub type OpenProtocol =
    unsafe extern "efiapi" fn(Handle, *const Guid, *mut *mut c_void, Handle, Handle, u32) -> Status;
pub type CloseProtocol = unsafe extern "efiapi" fn(Handle, *const Guid, Handle, Handle) -> Status;
pub type FreePool = unsafe extern "efiapi" fn(*mut c_void) -> Status;
pub type LocateHandleBuffer = unsafe extern "efiapi" fn(
    u32,
    *const Guid,
    *mut c_void,
    *mut usize,
    *mut *mut Handle,
) -> Status;
pub type AllocatePages = unsafe extern "efiapi" fn(u32, u32, usize, *mut u64) -> Status;
pub type FreePages = unsafe extern "efiapi" fn(u64, usize) -> Status;
pub type Tcg2HashLogExtendEvent =
    unsafe extern "efiapi" fn(*mut Tcg2Protocol, u64, u64, u64, *mut Tcg2Event) -> Status;
pub type Tcg2SubmitCommand =
    unsafe extern "efiapi" fn(*mut Tcg2Protocol, u32, *mut u8, u32, *mut u8) -> Status;

pub type BlockIoReset = unsafe extern "efiapi" fn(*mut BlockIoProtocol, u8) -> Status;
pub type BlockIoRead =
    unsafe extern "efiapi" fn(*mut BlockIoProtocol, u32, u64, usize, *mut c_void) -> Status;
pub type BlockIoWrite =
    unsafe extern "efiapi" fn(*mut BlockIoProtocol, u32, u64, usize, *const c_void) -> Status;
pub type BlockIoFlush = unsafe extern "efiapi" fn(*mut BlockIoProtocol) -> Status;

#[repr(C)]
pub struct BlockIoMedia {
    pub media_id: u32,
    pub removable_media: u8,
    pub media_present: u8,
    pub logical_partition: u8,
    pub read_only: u8,
    pub write_caching: u8,
    pub block_size: u32,
    pub io_align: u32,
    pub last_block: u64,
    pub lowest_aligned_lba: u64,
    pub logical_blocks_per_physical_block: u32,
    pub optimal_transfer_length_granularity: u32,
}

#[repr(C)]
pub struct BlockIoProtocol {
    pub revision: u64,
    pub media: *mut BlockIoMedia,
    pub reset: BlockIoReset,
    pub read_blocks: BlockIoRead,
    pub write_blocks: BlockIoWrite,
    pub flush_blocks: BlockIoFlush,
}

pub const MAX_UEFI_DEVICE_PATH_BYTES: usize = MAX_CANONICAL_UEFI_BLOCK_DEVICE_PATH_BYTES;
const DEVICE_PATH_END_TYPE: u8 = 0x7f;
const DEVICE_PATH_END_ENTIRE_SUBTYPE: u8 = 0xff;
const DEVICE_PATH_HEADER_BYTES: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UefiBlockDescriptorError {
    MissingImageHandle,
    MissingDeviceHandle,
    OpenBlockIo(Status),
    OpenDevicePath(Status),
    CloseProtocol(Status),
    MissingMedia,
    MediaAbsent,
    NonCanonicalBoolean,
    InvalidAlignment,
    InvalidGeometry,
    DevicePathTooLong,
    TruncatedDevicePath,
    InvalidDevicePathNode,
    UnsupportedDevicePathInstance,
    MissingDevicePathEnd,
    UnsupportedRecoveryGeometry,
    RecoveryRange,
    MediaChanged,
    ReadBlock(Status),
    LocateHandles(Status),
    NoBlockDevices,
    HandleCapacity,
    InvalidHandleBuffer,
    DuplicateHandle,
    FreeHandleBuffer(Status),
    InvalidVolumeHeader,
    VolumeGeometryMismatch,
    SelectedDeviceChanged,
    VolumeHeaderChanged,
    InvalidRecoveryReadBuffer,
    ReadOnlyRecoveryDevice,
}

pub const OPEN_PROTOCOL_GET_PROTOCOL: u32 = 0x0000_0002;
pub const LOCATE_BY_PROTOCOL: u32 = 2;

pub struct UefiBlockHandleSet<const N: usize> {
    handles: [Handle; N],
    count: usize,
}

impl<const N: usize> UefiBlockHandleSet<N> {
    pub fn as_slice(&self) -> &[Handle] {
        &self.handles[..self.count]
    }
}

/// Copies a firmware-allocated Block I/O handle array into a fixed-capacity
/// local set and releases the firmware allocation before returning. Handle
/// values and their enumeration order identify neither devices nor authority.
///
/// # Safety
///
/// `services` must be a live boot-services table. On successful return from
/// `locate_handle_buffer`, firmware must provide `count` readable handles in
/// the returned allocation, which must be releasable through `free_pool`.
pub unsafe fn locate_block_io_handles<const N: usize>(
    services: &BootServices,
) -> Result<UefiBlockHandleSet<N>, UefiBlockDescriptorError> {
    if N == 0 {
        return Err(UefiBlockDescriptorError::HandleCapacity);
    }
    let mut count = 0usize;
    let mut firmware_buffer = core::ptr::null_mut();
    let locate_status = unsafe {
        (services.locate_handle_buffer)(
            LOCATE_BY_PROTOCOL,
            &BLOCK_IO_PROTOCOL_GUID,
            core::ptr::null_mut(),
            &mut count,
            &mut firmware_buffer,
        )
    };
    if locate_status != SUCCESS {
        if !firmware_buffer.is_null() {
            let free_status = unsafe { (services.free_pool)(firmware_buffer.cast()) };
            if free_status != SUCCESS {
                return Err(UefiBlockDescriptorError::FreeHandleBuffer(free_status));
            }
        }
        return Err(UefiBlockDescriptorError::LocateHandles(locate_status));
    }

    let validation = if count == 0 {
        Err(UefiBlockDescriptorError::NoBlockDevices)
    } else if count > N {
        Err(UefiBlockDescriptorError::HandleCapacity)
    } else if firmware_buffer.is_null()
        || !(firmware_buffer as usize).is_multiple_of(core::mem::align_of::<Handle>())
    {
        Err(UefiBlockDescriptorError::InvalidHandleBuffer)
    } else {
        let source = unsafe { core::slice::from_raw_parts(firmware_buffer, count) };
        let mut handles = [core::ptr::null_mut(); N];
        let mut error = None;
        for (index, handle) in source.iter().copied().enumerate() {
            if handle.is_null() {
                error = Some(UefiBlockDescriptorError::InvalidHandleBuffer);
                break;
            }
            if source[..index].contains(&handle) {
                error = Some(UefiBlockDescriptorError::DuplicateHandle);
                break;
            }
            handles[index] = handle;
        }
        match error {
            Some(error) => Err(error),
            None => Ok(UefiBlockHandleSet { handles, count }),
        }
    };
    if !firmware_buffer.is_null() {
        let free_status = unsafe { (services.free_pool)(firmware_buffer.cast()) };
        if free_status != SUCCESS {
            return Err(UefiBlockDescriptorError::FreeHandleBuffer(free_status));
        }
    }
    validation
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UefiBlockMediaSnapshot {
    media_id: u32,
    block_size: u32,
    block_count: u64,
    io_align: u32,
    removable: bool,
    logical_partition: bool,
    read_only: bool,
}

impl UefiBlockMediaSnapshot {
    pub const fn media_id(self) -> u32 {
        self.media_id
    }
    pub const fn block_size(self) -> u32 {
        self.block_size
    }
    pub const fn block_count(self) -> u64 {
        self.block_count
    }
    pub const fn io_align(self) -> u32 {
        self.io_align
    }
    pub const fn removable(self) -> bool {
        self.removable
    }
    pub const fn logical_partition(self) -> bool {
        self.logical_partition
    }
    pub const fn read_only(self) -> bool {
        self.read_only
    }
}

pub const UEFI_RECOVERY_BLOCK_BYTES: usize = 4096;

#[repr(C, align(4096))]
pub struct UefiRecoveryBlock([u8; UEFI_RECOVERY_BLOCK_BYTES]);

impl UefiRecoveryBlock {
    pub const fn new() -> Self {
        Self([0; UEFI_RECOVERY_BLOCK_BYTES])
    }

    pub const fn as_slice(&self) -> &[u8; UEFI_RECOVERY_BLOCK_BYTES] {
        &self.0
    }

    pub fn erase(&mut self) {
        self.0.fill(0);
    }
}

impl Default for UefiRecoveryBlock {
    fn default() -> Self {
        Self::new()
    }
}

/// Copies and validates the volatile media descriptor before any block I/O.
/// The snapshot identifies geometry and one firmware media generation; it
/// grants no read, write, flush, protocol-open, or device-path authority.
///
/// # Safety
///
/// `protocol.media`, when non-null, must point to a readable `BlockIoMedia`
/// that firmware does not mutate for the duration of this call.
pub unsafe fn snapshot_uefi_block_media(
    protocol: &BlockIoProtocol,
) -> Result<UefiBlockMediaSnapshot, UefiBlockDescriptorError> {
    let media = unsafe { protocol.media.as_ref() }.ok_or(UefiBlockDescriptorError::MissingMedia)?;
    for value in [
        media.removable_media,
        media.media_present,
        media.logical_partition,
        media.read_only,
        media.write_caching,
    ] {
        if value > 1 {
            return Err(UefiBlockDescriptorError::NonCanonicalBoolean);
        }
    }
    if media.media_present == 0 {
        return Err(UefiBlockDescriptorError::MediaAbsent);
    }
    if media.io_align > 1 && !media.io_align.is_power_of_two() {
        return Err(UefiBlockDescriptorError::InvalidAlignment);
    }
    let block_count = media
        .last_block
        .checked_add(1)
        .ok_or(UefiBlockDescriptorError::InvalidGeometry)?;
    if block_count == 0 || media.block_size == 0 {
        return Err(UefiBlockDescriptorError::InvalidGeometry);
    }
    Ok(UefiBlockMediaSnapshot {
        media_id: media.media_id,
        block_size: media.block_size,
        block_count,
        io_align: media.io_align,
        removable: media.removable_media == 1,
        logical_partition: media.logical_partition == 1,
        read_only: media.read_only == 1,
    })
}

/// Reads one MRML-native 4 KiB recovery block through an exact still-current
/// firmware media generation. Compatible smaller firmware blocks are grouped
/// in one checked request; no read-modify-write behavior is introduced.
/// Failure or generation change erases the complete output.
///
/// # Safety
///
/// `protocol` and its media record must remain firmware-valid for this call.
/// Its `read_blocks` implementation must follow the UEFI Block I/O contract for
/// the validated media geometry and the aligned output buffer.
pub unsafe fn read_uefi_recovery_block(
    protocol: &mut BlockIoProtocol,
    expected: UefiBlockMediaSnapshot,
    recovery_block: u64,
    output: &mut UefiRecoveryBlock,
) -> Result<(), UefiBlockDescriptorError> {
    output.erase();
    let current = unsafe { snapshot_uefi_block_media(protocol) }?;
    if current != expected {
        return Err(UefiBlockDescriptorError::MediaChanged);
    }
    let firmware_bytes = usize::try_from(expected.block_size)
        .map_err(|_| UefiBlockDescriptorError::UnsupportedRecoveryGeometry)?;
    if !(512..=UEFI_RECOVERY_BLOCK_BYTES).contains(&firmware_bytes)
        || !firmware_bytes.is_power_of_two()
        || !UEFI_RECOVERY_BLOCK_BYTES.is_multiple_of(firmware_bytes)
        || expected.io_align > UEFI_RECOVERY_BLOCK_BYTES as u32
    {
        return Err(UefiBlockDescriptorError::UnsupportedRecoveryGeometry);
    }
    let firmware_blocks = u64::try_from(UEFI_RECOVERY_BLOCK_BYTES / firmware_bytes)
        .map_err(|_| UefiBlockDescriptorError::UnsupportedRecoveryGeometry)?;
    let first = recovery_block
        .checked_mul(firmware_blocks)
        .ok_or(UefiBlockDescriptorError::RecoveryRange)?;
    let end = first
        .checked_add(firmware_blocks)
        .filter(|end| *end <= expected.block_count)
        .ok_or(UefiBlockDescriptorError::RecoveryRange)?;
    let _ = end;
    let address = output.0.as_mut_ptr() as usize;
    if expected.io_align > 1 && !address.is_multiple_of(expected.io_align as usize) {
        return Err(UefiBlockDescriptorError::UnsupportedRecoveryGeometry);
    }
    let status = unsafe {
        (protocol.read_blocks)(
            protocol,
            expected.media_id,
            first,
            UEFI_RECOVERY_BLOCK_BYTES,
            output.0.as_mut_ptr().cast(),
        )
    };
    if status != SUCCESS {
        output.erase();
        return Err(UefiBlockDescriptorError::ReadBlock(status));
    }
    let current = unsafe { snapshot_uefi_block_media(protocol) }?;
    if current != expected {
        output.erase();
        return Err(UefiBlockDescriptorError::MediaChanged);
    }
    Ok(())
}

/// Converts one validated firmware media snapshot and canonical single-instance
/// device path into the storage service's boot-scoped platform descriptor.
/// The path digest identifies only; the caller must separately obtain protocol
/// access and grant a principal-bound block session.
pub fn uefi_platform_block_descriptor(
    id: BlockDeviceId,
    media: UefiBlockMediaSnapshot,
    device_path: &[u8],
) -> Result<PlatformBlockDeviceDescriptor, UefiBlockDescriptorError> {
    validate_single_device_path(device_path)?;
    let block = BlockDeviceDescriptor::new(
        id,
        UEFI_RECOVERY_BLOCK_BYTES as u32,
        uefi_recovery_block_count(media)?,
    )
    .ok_or(UefiBlockDescriptorError::InvalidGeometry)?;
    let stable_id = canonical_uefi_block_stable_id(device_path).map_err(|error| match error {
        CanonicalUefiBlockDevicePathError::TooLong => UefiBlockDescriptorError::DevicePathTooLong,
        CanonicalUefiBlockDevicePathError::Truncated => {
            UefiBlockDescriptorError::TruncatedDevicePath
        }
        CanonicalUefiBlockDevicePathError::MultipleInstances => {
            UefiBlockDescriptorError::UnsupportedDevicePathInstance
        }
        CanonicalUefiBlockDevicePathError::InvalidNode => {
            UefiBlockDescriptorError::InvalidDevicePathNode
        }
        CanonicalUefiBlockDevicePathError::MissingEnd => {
            UefiBlockDescriptorError::MissingDevicePathEnd
        }
    })?;
    let media_generation = u64::from(media.media_id) + 1;
    let identity = PlatformBlockDeviceIdentity::new(
        PlatformBlockTransport::Uefi,
        stable_id,
        1,
        media_generation,
    )
    .ok_or(UefiBlockDescriptorError::InvalidGeometry)?;
    Ok(PlatformBlockDeviceDescriptor::new(block, identity))
}

fn uefi_recovery_block_count(
    media: UefiBlockMediaSnapshot,
) -> Result<u64, UefiBlockDescriptorError> {
    let firmware_bytes = usize::try_from(media.block_size)
        .map_err(|_| UefiBlockDescriptorError::UnsupportedRecoveryGeometry)?;
    if !(512..=UEFI_RECOVERY_BLOCK_BYTES).contains(&firmware_bytes)
        || !firmware_bytes.is_power_of_two()
        || !UEFI_RECOVERY_BLOCK_BYTES.is_multiple_of(firmware_bytes)
        || media.io_align > UEFI_RECOVERY_BLOCK_BYTES as u32
    {
        return Err(UefiBlockDescriptorError::UnsupportedRecoveryGeometry);
    }
    let firmware_blocks = u64::try_from(UEFI_RECOVERY_BLOCK_BYTES / firmware_bytes)
        .map_err(|_| UefiBlockDescriptorError::UnsupportedRecoveryGeometry)?;
    if !media.block_count.is_multiple_of(firmware_blocks) {
        return Err(UefiBlockDescriptorError::UnsupportedRecoveryGeometry);
    }
    let blocks = media.block_count / firmware_blocks;
    if blocks == 0 {
        return Err(UefiBlockDescriptorError::UnsupportedRecoveryGeometry);
    }
    Ok(blocks)
}

/// Opens the exact loaded-image device's Block I/O and Device Path protocols,
/// copies all descriptor input into caller-owned bounded memory, then closes
/// both firmware protocol relationships before returning. The returned value
/// identifies geometry/generation but grants no persistent firmware or block
/// authority.
///
/// # Safety
///
/// `services` must be the live boot-services table for `image`; `loaded` must
/// remain valid; successful protocol opens must return valid protocol pointers;
/// and the returned device-path protocol must remain readable through its end
/// node (bounded by `MAX_UEFI_DEVICE_PATH_BYTES`) until it is closed here.
pub unsafe fn discover_loaded_image_block_descriptor(
    services: &BootServices,
    image: Handle,
    loaded: &LoadedImageProtocol,
    id: BlockDeviceId,
    device_path_scratch: &mut [u8; MAX_UEFI_DEVICE_PATH_BYTES],
) -> Result<PlatformBlockDeviceDescriptor, UefiBlockDescriptorError> {
    if image.is_null() {
        return Err(UefiBlockDescriptorError::MissingImageHandle);
    }
    let device = loaded.device_handle;
    if device.is_null() {
        return Err(UefiBlockDescriptorError::MissingDeviceHandle);
    }
    unsafe {
        with_opened_uefi_block_protocols(services, image, device, |block, path| {
            let media = snapshot_uefi_block_media(block)?;
            let path_length = copy_single_device_path(path, device_path_scratch)?;
            uefi_platform_block_descriptor(id, media, &device_path_scratch[..path_length])
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UefiRecoveryHeaderCandidate {
    handle: Handle,
    descriptor: PlatformBlockDeviceDescriptor,
    media: UefiBlockMediaSnapshot,
    header: VolumeHeader,
    sata_route: Option<CanonicalUefiSataBlockRoute>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UefiRecoveryVolumeScanError {
    Probe(UefiBlockDescriptorError),
    IdentityExhausted,
    CandidateSubstitution,
    DuplicatePlatformIdentity,
    ExpectedVolumeMissing,
    ExpectedVolumeAmbiguous,
}

impl UefiRecoveryHeaderCandidate {
    pub const fn handle(self) -> Handle {
        self.handle
    }

    pub const fn descriptor(self) -> PlatformBlockDeviceDescriptor {
        self.descriptor
    }

    pub const fn media(self) -> UefiBlockMediaSnapshot {
        self.media
    }

    pub const fn header(self) -> VolumeHeader {
        self.header
    }

    pub const fn sata_route(self) -> Option<CanonicalUefiSataBlockRoute> {
        self.sata_route
    }
}

/// Opens one enumerated handle, binds its canonical path and media generation,
/// reads and decodes native block zero, and closes all firmware relationships
/// before publishing the candidate. The ephemeral handle must be reopened and
/// the descriptor revalidated before any later root read.
///
/// # Safety
///
/// The boot-services and protocol-pointer requirements of
/// `discover_loaded_image_block_descriptor` apply to `device`.
pub unsafe fn probe_uefi_recovery_header(
    services: &BootServices,
    image: Handle,
    device: Handle,
    id: BlockDeviceId,
    device_path_scratch: &mut [u8; MAX_UEFI_DEVICE_PATH_BYTES],
    block: &mut UefiRecoveryBlock,
) -> Result<UefiRecoveryHeaderCandidate, UefiBlockDescriptorError> {
    if image.is_null() {
        return Err(UefiBlockDescriptorError::MissingImageHandle);
    }
    if device.is_null() {
        return Err(UefiBlockDescriptorError::MissingDeviceHandle);
    }
    unsafe {
        with_opened_uefi_block_protocols(services, image, device, |protocol, path| {
            let media = snapshot_uefi_block_media(protocol)?;
            let path_length = copy_single_device_path(path, device_path_scratch)?;
            let descriptor =
                uefi_platform_block_descriptor(id, media, &device_path_scratch[..path_length])?;
            let sata_route =
                parse_canonical_uefi_sata_block_route(&device_path_scratch[..path_length]).ok();
            read_uefi_recovery_block(protocol, media, 0, block)?;
            let header = VolumeHeader::decode(&block.as_slice()[..VOLUME_HEADER_BYTES])
                .map_err(|_| UefiBlockDescriptorError::InvalidVolumeHeader)?;
            if header.block_size() != descriptor.block().block_size()
                || header.block_count() != descriptor.block().block_count()
            {
                block.erase();
                return Err(UefiBlockDescriptorError::VolumeGeometryMismatch);
            }
            block.erase();
            Ok(UefiRecoveryHeaderCandidate {
                handle: device,
                descriptor,
                media,
                header,
                sata_route,
            })
        })
    }
}

/// Probes the complete bounded Block I/O set and returns exactly one candidate
/// for `expected_volume`. Firmware enumeration order affects only ephemeral
/// service-local IDs; stable path/media identity and exact volume identity make
/// the selection. Any uncertain probe aborts the scan rather than being hidden
/// as an absent device.
///
/// # Safety
///
/// Every handle in `handles` must retain the firmware validity required by
/// `probe_uefi_recovery_header` for the duration of this call.
pub unsafe fn select_uefi_recovery_volume<const N: usize>(
    services: &BootServices,
    image: Handle,
    handles: &UefiBlockHandleSet<N>,
    expected_volume: VolumeId,
    device_path_scratch: &mut [u8; MAX_UEFI_DEVICE_PATH_BYTES],
    block: &mut UefiRecoveryBlock,
) -> Result<UefiRecoveryHeaderCandidate, UefiRecoveryVolumeScanError> {
    select_uefi_recovery_volume_with(handles, expected_volume, |handle, id| unsafe {
        probe_uefi_recovery_header(services, image, handle, id, device_path_scratch, block)
    })
}

fn select_uefi_recovery_volume_with<const N: usize>(
    handles: &UefiBlockHandleSet<N>,
    expected_volume: VolumeId,
    mut probe: impl FnMut(
        Handle,
        BlockDeviceId,
    ) -> Result<UefiRecoveryHeaderCandidate, UefiBlockDescriptorError>,
) -> Result<UefiRecoveryHeaderCandidate, UefiRecoveryVolumeScanError> {
    let mut identities = [None; N];
    let mut identity_count = 0usize;
    let mut selected = None;
    for (index, handle) in handles.as_slice().iter().copied().enumerate() {
        let id_value = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(UefiRecoveryVolumeScanError::IdentityExhausted)?;
        let id =
            BlockDeviceId::new(id_value).ok_or(UefiRecoveryVolumeScanError::IdentityExhausted)?;
        let candidate = match probe(handle, id) {
            Ok(candidate) => candidate,
            Err(
                UefiBlockDescriptorError::InvalidVolumeHeader
                | UefiBlockDescriptorError::UnsupportedRecoveryGeometry
                | UefiBlockDescriptorError::MediaAbsent,
            ) => continue,
            Err(error) => return Err(UefiRecoveryVolumeScanError::Probe(error)),
        };
        if candidate.handle != handle || candidate.descriptor.block().id() != id {
            return Err(UefiRecoveryVolumeScanError::CandidateSubstitution);
        }
        let identity = candidate.descriptor.identity();
        if identities[..identity_count].contains(&Some(identity)) {
            return Err(UefiRecoveryVolumeScanError::DuplicatePlatformIdentity);
        }
        identities[identity_count] = Some(identity);
        identity_count += 1;
        if candidate.header.volume() == expected_volume {
            if selected.is_some() {
                return Err(UefiRecoveryVolumeScanError::ExpectedVolumeAmbiguous);
            }
            selected = Some(candidate);
        }
    }
    selected.ok_or(UefiRecoveryVolumeScanError::ExpectedVolumeMissing)
}

/// Reopens one selected candidate, exact-revalidates its path/media/geometry and
/// block-zero header, then reads both redundant roots. No root bytes survive an
/// error, including protocol-close uncertainty after otherwise successful I/O.
///
/// # Safety
///
/// The selected handle and boot services must retain the firmware validity
/// required by `probe_uefi_recovery_header` for this complete transaction.
pub unsafe fn read_selected_uefi_recovery_roots(
    services: &BootServices,
    image: Handle,
    selected: UefiRecoveryHeaderCandidate,
    device_path_scratch: &mut [u8; MAX_UEFI_DEVICE_PATH_BYTES],
    primary: &mut UefiRecoveryBlock,
    secondary: &mut UefiRecoveryBlock,
) -> Result<(), UefiBlockDescriptorError> {
    primary.erase();
    secondary.erase();
    let result = unsafe {
        with_opened_uefi_block_protocols(services, image, selected.handle, |protocol, path| {
            let media = snapshot_uefi_block_media(protocol)?;
            if media != selected.media {
                return Err(UefiBlockDescriptorError::SelectedDeviceChanged);
            }
            let path_length = copy_single_device_path(path, device_path_scratch)?;
            let descriptor = uefi_platform_block_descriptor(
                selected.descriptor.block().id(),
                media,
                &device_path_scratch[..path_length],
            )?;
            if descriptor != selected.descriptor {
                return Err(UefiBlockDescriptorError::SelectedDeviceChanged);
            }

            read_uefi_recovery_block(protocol, media, 0, primary)?;
            let header = VolumeHeader::decode(&primary.as_slice()[..VOLUME_HEADER_BYTES])
                .map_err(|_| UefiBlockDescriptorError::VolumeHeaderChanged)?;
            primary.erase();
            if header != selected.header {
                return Err(UefiBlockDescriptorError::VolumeHeaderChanged);
            }
            read_uefi_recovery_block(
                protocol,
                media,
                selected.header.primary_superblock(),
                primary,
            )?;
            if let Err(error) = read_uefi_recovery_block(
                protocol,
                media,
                selected.header.secondary_superblock(),
                secondary,
            ) {
                primary.erase();
                return Err(error);
            }
            Ok(())
        })
    };
    if result.is_err() {
        primary.erase();
        secondary.erase();
    }
    result
}

/// Read-only exact-generation UEFI adapter for the shared native storage stack.
/// It owns aligned private transfer storage; caller output is published only
/// after every requested 4 KiB block completes under the same media snapshot.
pub struct UefiRecoveryStorageDevice<'a> {
    protocol: &'a mut BlockIoProtocol,
    media: UefiBlockMediaSnapshot,
    transfer: UefiRecoveryBlock,
}

impl Drop for UefiRecoveryStorageDevice<'_> {
    fn drop(&mut self) {
        self.transfer.erase();
    }
}

unsafe impl StorageBlockDevice for UefiRecoveryStorageDevice<'_> {
    type Error = UefiBlockDescriptorError;

    fn read_blocks(&mut self, block: u64, output: &mut [u8]) -> Result<(), Self::Error> {
        output.fill(0);
        if output.is_empty() || !output.len().is_multiple_of(UEFI_RECOVERY_BLOCK_BYTES) {
            return Err(UefiBlockDescriptorError::InvalidRecoveryReadBuffer);
        }
        for (index, destination) in output
            .chunks_exact_mut(UEFI_RECOVERY_BLOCK_BYTES)
            .enumerate()
        {
            let logical = block
                .checked_add(
                    u64::try_from(index).map_err(|_| UefiBlockDescriptorError::RecoveryRange)?,
                )
                .ok_or(UefiBlockDescriptorError::RecoveryRange)?;
            if let Err(error) = unsafe {
                read_uefi_recovery_block(self.protocol, self.media, logical, &mut self.transfer)
            } {
                output.fill(0);
                self.transfer.erase();
                return Err(error);
            }
            destination.copy_from_slice(self.transfer.as_slice());
            self.transfer.erase();
        }
        Ok(())
    }

    fn write_blocks(&mut self, _: u64, _: &[u8]) -> Result<(), Self::Error> {
        Err(UefiBlockDescriptorError::ReadOnlyRecoveryDevice)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Err(UefiBlockDescriptorError::ReadOnlyRecoveryDevice)
    }

    fn replace_superblock(
        &mut self,
        _: u64,
        _: &[u8; SUPERBLOCK_BYTES],
    ) -> Result<(), Self::Error> {
        Err(UefiBlockDescriptorError::ReadOnlyRecoveryDevice)
    }
}

/// Reopens and exact-revalidates a selected device, rechecks block zero, and
/// lends a read-only `StorageBlockDevice` to one synchronous operation. The
/// protocol relationship is closed before the operation result can escape.
///
/// # Safety
///
/// The selected handle and boot services must remain firmware-valid for the
/// complete synchronous operation.
pub unsafe fn with_selected_uefi_storage_device<R>(
    services: &BootServices,
    image: Handle,
    selected: UefiRecoveryHeaderCandidate,
    device_path_scratch: &mut [u8; MAX_UEFI_DEVICE_PATH_BYTES],
    operation: impl FnOnce(UefiRecoveryStorageDevice<'_>) -> R,
) -> Result<R, UefiBlockDescriptorError> {
    unsafe {
        with_opened_uefi_block_protocols(services, image, selected.handle, |protocol, path| {
            let media = snapshot_uefi_block_media(protocol)?;
            if media != selected.media {
                return Err(UefiBlockDescriptorError::SelectedDeviceChanged);
            }
            let path_length = copy_single_device_path(path, device_path_scratch)?;
            let descriptor = uefi_platform_block_descriptor(
                selected.descriptor.block().id(),
                media,
                &device_path_scratch[..path_length],
            )?;
            if descriptor != selected.descriptor {
                return Err(UefiBlockDescriptorError::SelectedDeviceChanged);
            }
            let mut transfer = UefiRecoveryBlock::new();
            read_uefi_recovery_block(protocol, media, 0, &mut transfer)?;
            let header = VolumeHeader::decode(&transfer.as_slice()[..VOLUME_HEADER_BYTES])
                .map_err(|_| UefiBlockDescriptorError::VolumeHeaderChanged)?;
            transfer.erase();
            if header != selected.header {
                return Err(UefiBlockDescriptorError::VolumeHeaderChanged);
            }
            let device = UefiRecoveryStorageDevice {
                protocol,
                media,
                transfer,
            };
            Ok(operation(device))
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum UefiReachableRecoveryError {
    Firmware(UefiBlockDescriptorError),
    Volume(BlockVolumeError<UefiBlockDescriptorError>),
    Recovery(RecoveryError<BlockVolumeError<UefiBlockDescriptorError>>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UefiInstalledRecoveryIdentityError {
    VolumeMismatch,
    RootGenerationMismatch,
    Route,
}

/// Authority-free identity retained after one exact installed graph has been
/// recovered. It records what the scoped UEFI control plane proved but grants
/// no firmware protocol, block read, capability, rollback, or launch authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UefiRecoveredInstalledIdentity {
    descriptor: PlatformBlockDeviceDescriptor,
    volume: VolumeId,
    root_block: u64,
    root_generation: u64,
    sata_route: Option<CanonicalUefiSataBlockRoute>,
}

impl UefiRecoveredInstalledIdentity {
    pub const fn descriptor(self) -> PlatformBlockDeviceDescriptor {
        self.descriptor
    }

    pub const fn volume(self) -> VolumeId {
        self.volume
    }

    pub const fn root_block(self) -> u64 {
        self.root_block
    }

    pub const fn root_generation(self) -> u64 {
        self.root_generation
    }

    pub const fn sata_route(self) -> Option<CanonicalUefiSataBlockRoute> {
        self.sata_route
    }

    pub fn sata_handoff_route(
        self,
    ) -> Result<Option<mrml_kernel::InstalledRecoverySataRoute>, UefiInstalledRecoveryIdentityError>
    {
        let Some(route) = self.sata_route else {
            return Ok(None);
        };
        if route.stable_id() != self.descriptor.identity().stable_id() {
            return Err(UefiInstalledRecoveryIdentityError::Route);
        }
        let mut hops = [mrml_kernel::InstalledRecoveryPciHop::default();
            mrml_kernel::MAX_INSTALLED_RECOVERY_PCI_HOPS];
        if route.pci_hops().len() > hops.len() {
            return Err(UefiInstalledRecoveryIdentityError::Route);
        }
        for (output, input) in hops.iter_mut().zip(route.pci_hops()) {
            *output = mrml_kernel::InstalledRecoveryPciHop::new(input.device(), input.function())
                .ok_or(UefiInstalledRecoveryIdentityError::Route)?;
        }
        let media = route
            .media()
            .map(|media| {
                mrml_kernel::InstalledRecoveryHardDriveMedia::new(
                    media.partition_number(),
                    media.partition_start(),
                    media.partition_size(),
                    media.signature(),
                    media.mbr_type(),
                    media.signature_type(),
                )
                .ok_or(UefiInstalledRecoveryIdentityError::Route)
            })
            .transpose()?;
        mrml_kernel::InstalledRecoverySataRoute::new(
            route.root_hid(),
            route.root_uid(),
            &hops[..route.pci_hops().len()],
            route.hba_port(),
            route.port_multiplier_port(),
            route.logical_unit(),
            media,
            route.stable_id(),
        )
        .map(Some)
        .map_err(|_| UefiInstalledRecoveryIdentityError::Route)
    }

    pub fn boot_identity(
        self,
    ) -> Result<
        mrml_kernel::InstalledRecoveryBootIdentity,
        mrml_kernel::InstalledRecoveryBootIdentityError,
    > {
        let identity = self.descriptor.identity();
        let source = match identity.transport() {
            PlatformBlockTransport::Uefi => mrml_kernel::InstalledRecoverySource::Uefi,
            PlatformBlockTransport::Ahci => mrml_kernel::InstalledRecoverySource::Ahci,
            PlatformBlockTransport::Usb => mrml_kernel::InstalledRecoverySource::Usb,
            PlatformBlockTransport::Virtio => mrml_kernel::InstalledRecoverySource::Virtio,
            PlatformBlockTransport::Hosted => mrml_kernel::InstalledRecoverySource::Hosted,
        };
        let block = self.descriptor.block();
        mrml_kernel::InstalledRecoveryBootIdentity::new(
            source,
            identity.stable_id(),
            identity.controller_generation(),
            identity.media_generation(),
            block.block_size(),
            block.block_count(),
            self.volume.bytes(),
            self.root_block,
            self.root_generation,
        )
    }
}

/// Exact-matches a recovered graph with the independently authenticated volume
/// and root generation expected by boot recovery policy. This comparison is
/// non-authorizing and must precede any handoff publication.
pub fn bind_recovered_uefi_installed_identity<const EXTENTS: usize, const OBJECTS: usize>(
    selected: UefiRecoveryHeaderCandidate,
    recovered: &RecoveredReachableState<EXTENTS, OBJECTS>,
    expected_volume: VolumeId,
    expected_root_generation: u64,
) -> Result<UefiRecoveredInstalledIdentity, UefiInstalledRecoveryIdentityError> {
    let root = recovered.selected();
    if selected.header.volume() != expected_volume || root.superblock().volume() != expected_volume
    {
        return Err(UefiInstalledRecoveryIdentityError::VolumeMismatch);
    }
    if expected_root_generation == 0 || root.superblock().generation() != expected_root_generation {
        return Err(UefiInstalledRecoveryIdentityError::RootGenerationMismatch);
    }
    Ok(UefiRecoveredInstalledIdentity {
        descriptor: selected.descriptor,
        volume: expected_volume,
        root_block: root.block(),
        root_generation: expected_root_generation,
        sata_route: selected.sata_route,
    })
}

/// Reopens one exact selected UEFI media generation and validates its complete
/// reachable metadata graph through the shared storage recovery implementation.
/// The firmware protocol remains open across redundant-root selection and every
/// metadata read; no UEFI-specific metadata parser or second recovery policy is
/// introduced. All caller-provided recovery scratch is erased before return.
///
/// A successful graph is discarded if either protocol cannot be closed
/// conclusively, because the exact-generation servicing relationship would then
/// have an uncertain lifetime.
///
/// # Safety
///
/// The selected handle and boot services must remain firmware-valid for the
/// complete synchronous operation. Each scratch block must be distinct.
#[allow(clippy::too_many_arguments)]
pub unsafe fn recover_selected_uefi_reachable_state<
    const ALLOCATIONS: usize,
    const DIRECTORIES: usize,
    const EXTENTS: usize,
    const OBJECTS: usize,
>(
    services: &BootServices,
    image: Handle,
    selected: UefiRecoveryHeaderCandidate,
    device_path_scratch: &mut [u8; MAX_UEFI_DEVICE_PATH_BYTES],
    volume_scratch: &mut [u8; UEFI_RECOVERY_BLOCK_BYTES],
    primary: &mut [u8; UEFI_RECOVERY_BLOCK_BYTES],
    secondary: &mut [u8; UEFI_RECOVERY_BLOCK_BYTES],
    metadata_scratch: &mut [u8],
) -> Result<RecoveredReachableState<EXTENTS, OBJECTS>, UefiReachableRecoveryError> {
    let header = selected.header;
    let operation = unsafe {
        with_selected_uefi_storage_device(
            services,
            image,
            selected,
            device_path_scratch,
            |device| {
                let mut volume =
                    BlockVolume::new(header, header.primary_superblock(), device, volume_scratch)
                        .map_err(UefiReachableRecoveryError::Volume)?;
                volume
                    .read_recovery_superblocks(primary, secondary)
                    .map_err(UefiReachableRecoveryError::Volume)?;
                recover_reachable_state::<_, ALLOCATIONS, DIRECTORIES, EXTENTS, OBJECTS>(
                    header,
                    &primary[..SUPERBLOCK_BYTES],
                    &secondary[..SUPERBLOCK_BYTES],
                    &mut volume,
                    metadata_scratch,
                )
                .map_err(UefiReachableRecoveryError::Recovery)
            },
        )
    };
    volume_scratch.fill(0);
    primary.fill(0);
    secondary.fill(0);
    metadata_scratch.fill(0);
    match operation {
        Ok(result) => result,
        Err(error) => Err(UefiReachableRecoveryError::Firmware(error)),
    }
}

unsafe fn with_opened_uefi_block_protocols<R>(
    services: &BootServices,
    image: Handle,
    device: Handle,
    operation: impl FnOnce(&mut BlockIoProtocol, *const u8) -> Result<R, UefiBlockDescriptorError>,
) -> Result<R, UefiBlockDescriptorError> {
    let mut block_pointer = core::ptr::null_mut();
    let status = unsafe {
        (services.open_protocol)(
            device,
            &BLOCK_IO_PROTOCOL_GUID,
            &mut block_pointer,
            image,
            core::ptr::null_mut(),
            OPEN_PROTOCOL_GET_PROTOCOL,
        )
    };
    if status != SUCCESS {
        return Err(UefiBlockDescriptorError::OpenBlockIo(status));
    }

    let mut path_pointer = core::ptr::null_mut();
    let path_status = unsafe {
        (services.open_protocol)(
            device,
            &DEVICE_PATH_PROTOCOL_GUID,
            &mut path_pointer,
            image,
            core::ptr::null_mut(),
            OPEN_PROTOCOL_GET_PROTOCOL,
        )
    };
    if path_status != SUCCESS {
        let close_status = unsafe {
            (services.close_protocol)(
                device,
                &BLOCK_IO_PROTOCOL_GUID,
                image,
                core::ptr::null_mut(),
            )
        };
        return if close_status == SUCCESS {
            Err(UefiBlockDescriptorError::OpenDevicePath(path_status))
        } else {
            Err(UefiBlockDescriptorError::CloseProtocol(close_status))
        };
    }

    let discovered = match unsafe { block_pointer.cast::<BlockIoProtocol>().as_mut() } {
        Some(block) => operation(block, path_pointer.cast_const().cast::<u8>()),
        None => Err(UefiBlockDescriptorError::MissingMedia),
    };
    let path_close = unsafe {
        (services.close_protocol)(
            device,
            &DEVICE_PATH_PROTOCOL_GUID,
            image,
            core::ptr::null_mut(),
        )
    };
    let block_close = unsafe {
        (services.close_protocol)(
            device,
            &BLOCK_IO_PROTOCOL_GUID,
            image,
            core::ptr::null_mut(),
        )
    };
    if path_close != SUCCESS {
        return Err(UefiBlockDescriptorError::CloseProtocol(path_close));
    }
    if block_close != SUCCESS {
        return Err(UefiBlockDescriptorError::CloseProtocol(block_close));
    }
    discovered
}

unsafe fn copy_single_device_path(
    path: *const u8,
    output: &mut [u8; MAX_UEFI_DEVICE_PATH_BYTES],
) -> Result<usize, UefiBlockDescriptorError> {
    if path.is_null() {
        return Err(UefiBlockDescriptorError::TruncatedDevicePath);
    }
    let mut offset = 0usize;
    loop {
        let header_end = offset
            .checked_add(DEVICE_PATH_HEADER_BYTES)
            .filter(|end| *end <= output.len())
            .ok_or(UefiBlockDescriptorError::DevicePathTooLong)?;
        let header = unsafe { core::slice::from_raw_parts(path.add(offset), 4) };
        let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if length < DEVICE_PATH_HEADER_BYTES {
            return Err(UefiBlockDescriptorError::InvalidDevicePathNode);
        }
        let next = offset
            .checked_add(length)
            .filter(|next| *next <= output.len())
            .ok_or(UefiBlockDescriptorError::DevicePathTooLong)?;
        unsafe {
            core::ptr::copy_nonoverlapping(
                path.add(offset),
                output.as_mut_ptr().add(offset),
                length,
            )
        };
        if header[0] == DEVICE_PATH_END_TYPE {
            if header[1] != DEVICE_PATH_END_ENTIRE_SUBTYPE {
                return Err(UefiBlockDescriptorError::UnsupportedDevicePathInstance);
            }
            if next != header_end || length != DEVICE_PATH_HEADER_BYTES {
                return Err(UefiBlockDescriptorError::InvalidDevicePathNode);
            }
            return Ok(next);
        }
        offset = next;
    }
}

fn validate_single_device_path(path: &[u8]) -> Result<(), UefiBlockDescriptorError> {
    if path.len() > MAX_UEFI_DEVICE_PATH_BYTES {
        return Err(UefiBlockDescriptorError::DevicePathTooLong);
    }
    let mut offset = 0usize;
    while offset < path.len() {
        let header = path
            .get(offset..offset + DEVICE_PATH_HEADER_BYTES)
            .ok_or(UefiBlockDescriptorError::TruncatedDevicePath)?;
        let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if length < DEVICE_PATH_HEADER_BYTES {
            return Err(UefiBlockDescriptorError::InvalidDevicePathNode);
        }
        let next = offset
            .checked_add(length)
            .filter(|next| *next <= path.len())
            .ok_or(UefiBlockDescriptorError::TruncatedDevicePath)?;
        if header[0] == DEVICE_PATH_END_TYPE {
            if header[1] != DEVICE_PATH_END_ENTIRE_SUBTYPE {
                return Err(UefiBlockDescriptorError::UnsupportedDevicePathInstance);
            }
            if length != DEVICE_PATH_HEADER_BYTES || next != path.len() {
                return Err(UefiBlockDescriptorError::InvalidDevicePathNode);
            }
            return Ok(());
        }
        offset = next;
    }
    Err(UefiBlockDescriptorError::MissingDevicePathEnd)
}

#[repr(C)]
pub struct Tcg2Protocol {
    pub get_capability: usize,
    pub get_event_log: usize,
    pub hash_log_extend_event: Tcg2HashLogExtendEvent,
    pub submit_command: Tcg2SubmitCommand,
    pub get_active_pcr_banks: usize,
    pub set_active_pcr_banks: usize,
    pub get_result_of_set_active_pcr_banks: usize,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Tcg2EventHeader {
    pub header_size: u32,
    pub header_version: u16,
    pub pcr_index: u32,
    pub event_type: u32,
}

#[repr(C, packed)]
pub struct Tcg2Event {
    pub size: u32,
    pub header: Tcg2EventHeader,
    pub event: [u8; 32],
}

#[repr(C)]
pub struct BootServices {
    pub header: TableHeader,
    pub raise_tpl: usize,
    pub restore_tpl: usize,
    pub allocate_pages: AllocatePages,
    pub free_pages: FreePages,
    pub get_memory_map: GetMemoryMap,
    pub allocate_pool: usize,
    pub free_pool: FreePool,
    pub create_event: usize,
    pub set_timer: usize,
    pub wait_for_event: usize,
    pub signal_event: usize,
    pub close_event: usize,
    pub check_event: usize,
    pub install_protocol_interface: usize,
    pub reinstall_protocol_interface: usize,
    pub uninstall_protocol_interface: usize,
    pub handle_protocol: HandleProtocol,
    pub reserved: usize,
    pub register_protocol_notify: usize,
    pub locate_handle: usize,
    pub locate_device_path: usize,
    pub install_configuration_table: usize,
    pub load_image: usize,
    pub start_image: usize,
    pub exit: usize,
    pub unload_image: usize,
    pub exit_boot_services: ExitBootServices,
    pub get_next_monotonic_count: usize,
    pub stall: usize,
    pub set_watchdog_timer: usize,
    pub connect_controller: usize,
    pub disconnect_controller: usize,
    pub open_protocol: OpenProtocol,
    pub close_protocol: CloseProtocol,
    pub open_protocol_information: usize,
    pub protocols_per_handle: usize,
    pub locate_handle_buffer: LocateHandleBuffer,
    pub locate_protocol: LocateProtocol,
}

pub type GetVariable =
    unsafe extern "efiapi" fn(*const u16, *const Guid, *mut u32, *mut usize, *mut c_void) -> Status;

#[repr(C)]
pub struct RuntimeServices {
    pub header: TableHeader,
    pub get_time: usize,
    pub set_time: usize,
    pub get_wakeup_time: usize,
    pub set_wakeup_time: usize,
    pub set_virtual_address_map: usize,
    pub convert_pointer: usize,
    pub get_variable: GetVariable,
    pub get_next_variable_name: usize,
    pub set_variable: usize,
}

#[repr(C)]
pub struct LoadedImageProtocol {
    pub revision: u32,
    pub parent_handle: Handle,
    pub system_table: *mut SystemTable,
    pub device_handle: Handle,
    pub file_path: *mut c_void,
    pub reserved: *mut c_void,
    pub load_options_size: u32,
    pub load_options: *mut c_void,
    pub image_base: *mut c_void,
    pub image_size: u64,
    pub image_code_type: u32,
    pub image_data_type: u32,
    pub unload: usize,
}

pub type OpenVolume =
    unsafe extern "efiapi" fn(*mut SimpleFileSystemProtocol, *mut *mut FileProtocol) -> Status;
#[repr(C)]
pub struct SimpleFileSystemProtocol {
    pub revision: u64,
    pub open_volume: OpenVolume,
}
pub type FileOpen = unsafe extern "efiapi" fn(
    *mut FileProtocol,
    *mut *mut FileProtocol,
    *const u16,
    u64,
    u64,
) -> Status;
pub type FileClose = unsafe extern "efiapi" fn(*mut FileProtocol) -> Status;
pub type FileRead = unsafe extern "efiapi" fn(*mut FileProtocol, *mut usize, *mut c_void) -> Status;
pub type FileWrite =
    unsafe extern "efiapi" fn(*mut FileProtocol, *mut usize, *const c_void) -> Status;
pub type FileFlush = unsafe extern "efiapi" fn(*mut FileProtocol) -> Status;
pub type FileSetPosition = unsafe extern "efiapi" fn(*mut FileProtocol, u64) -> Status;
pub type FileGetInfo =
    unsafe extern "efiapi" fn(*mut FileProtocol, *const Guid, *mut usize, *mut c_void) -> Status;
#[repr(C)]
pub struct FileProtocol {
    pub revision: u64,
    pub open: FileOpen,
    pub close: FileClose,
    pub delete: usize,
    pub read: FileRead,
    pub write: Option<FileWrite>,
    pub get_position: usize,
    pub set_position: Option<FileSetPosition>,
    pub get_info: FileGetInfo,
    pub set_info: usize,
    pub flush: Option<FileFlush>,
}

#[repr(C)]
pub struct SystemTable {
    pub header: TableHeader,
    pub firmware_vendor: *mut u16,
    pub firmware_revision: u32,
    pub console_in_handle: Handle,
    pub con_in: *mut c_void,
    pub console_out_handle: Handle,
    pub con_out: *mut c_void,
    pub standard_error_handle: Handle,
    pub std_err: *mut c_void,
    pub runtime_services: *mut RuntimeServices,
    pub boot_services: *mut BootServices,
    pub table_entry_count: usize,
    pub configuration_table: *mut ConfigurationTable,
}

#[repr(C)]
pub struct ConfigurationTable {
    pub vendor_guid: Guid,
    pub vendor_table: *mut c_void,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcpiError {
    Missing,
    TooManyConfigurationTables,
    NullTable,
    BadSignature,
    BadChecksum,
    BadLength,
}

/// Locates ACPI 2.0 preferentially, falling back to ACPI 1.0. The returned
/// physical pointer is admitted only after the complete applicable RSDP
/// checksum validates.
///
/// # Safety
///
/// `system.configuration_table` and each selected `vendor_table` must remain
/// firmware-owned, readable, and valid for their declared lengths throughout
/// this call. The caller must invoke it before those UEFI mappings are revoked.
pub unsafe fn find_acpi_root(system: &SystemTable) -> Result<u64, AcpiError> {
    if system.table_entry_count > 1024 {
        return Err(AcpiError::TooManyConfigurationTables);
    }
    if system.table_entry_count != 0 && system.configuration_table.is_null() {
        return Err(AcpiError::NullTable);
    }
    let entries = unsafe {
        core::slice::from_raw_parts(system.configuration_table, system.table_entry_count)
    };
    for wanted in [&ACPI_20_TABLE_GUID, &ACPI_TABLE_GUID] {
        if let Some(entry) = entries
            .iter()
            .find(|entry| entry.vendor_guid.equals(wanted))
        {
            if entry.vendor_table.is_null() {
                return Err(AcpiError::NullTable);
            }
            let rsdp = entry.vendor_table.cast::<u8>();
            let first = unsafe { core::slice::from_raw_parts(rsdp, 20) };
            if &first[..8] != b"RSD PTR " {
                return Err(AcpiError::BadSignature);
            }
            if checksum(first) != 0 {
                return Err(AcpiError::BadChecksum);
            }
            if wanted.equals(&ACPI_20_TABLE_GUID) {
                let length_bytes = unsafe { core::slice::from_raw_parts(rsdp.add(20), 4) };
                let length = u32::from_le_bytes(length_bytes.try_into().unwrap()) as usize;
                if !(36..=4096).contains(&length) {
                    return Err(AcpiError::BadLength);
                }
                let complete = unsafe { core::slice::from_raw_parts(rsdp, length) };
                if checksum(complete) != 0 {
                    return Err(AcpiError::BadChecksum);
                }
            }
            return Ok(entry.vendor_table as u64);
        }
    }
    Err(AcpiError::Missing)
}

fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte))
}

#[repr(C)]
pub struct MemoryDescriptor {
    pub kind: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub pages: u64,
    pub attributes: u64,
}

pub const MAX_MEMORY_MAP_BYTES: usize = 64 * 1024;
pub const MAX_NORMALIZED_REGIONS: usize = 128;
const MAX_MEMORY_DESCRIPTORS: usize =
    MAX_MEMORY_MAP_BYTES / core::mem::size_of::<MemoryDescriptor>();
const _: () = assert!(MAX_MEMORY_DESCRIPTORS <= u16::MAX as usize);
const PAGE_SIZE: u64 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NormalizedMemoryKind {
    Free = 0,
    Kernel = 1,
    Firmware = 2,
    Mmio = 3,
    Acpi = 4,
    Reserved = 5,
    BootDma = 6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalizedRegion {
    pub start: u64,
    pub pages: u64,
    pub kind: NormalizedMemoryKind,
}

impl NormalizedRegion {
    pub const EMPTY: Self = Self {
        start: 0,
        pages: 0,
        kind: NormalizedMemoryKind::Reserved,
    };

    pub const fn end(self) -> u64 {
        self.start + self.pages * PAGE_SIZE
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalizeError {
    Empty,
    BadDescriptorSize,
    Truncated,
    Unaligned,
    ZeroPages,
    Overflow,
    Overlap,
    TooManyRegions,
    FramebufferConflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootDmaBackingError {
    InvalidExtent,
    MalformedMap,
    MissingLoaderData,
    ConflictingDescriptor,
    OutsideReserved,
    TooManyRegions,
}

/// Tags only the validated loader allocation in a normalized memory map.
/// This must run after framebuffer overlay, so an overlapping MMIO range
/// cannot silently become DMA backing.
pub fn mark_boot_dma_backing(
    output: &mut [NormalizedRegion; MAX_NORMALIZED_REGIONS],
    count: usize,
    start: u64,
    pages: u16,
) -> Result<usize, BootDmaBackingError> {
    if start == 0 || !start.is_multiple_of(PAGE_SIZE) || !(1..=256).contains(&pages) {
        return Err(BootDmaBackingError::InvalidExtent);
    }
    let end = start
        .checked_add(u64::from(pages) * PAGE_SIZE)
        .ok_or(BootDmaBackingError::InvalidExtent)?;
    let regions = output
        .get(..count)
        .ok_or(BootDmaBackingError::TooManyRegions)?;
    let mut previous_end = 0;
    for region in regions {
        if region.kind == NormalizedMemoryKind::BootDma {
            return Err(BootDmaBackingError::ConflictingDescriptor);
        }
        if region.pages == 0
            || region.start < previous_end
            || !region.start.is_multiple_of(PAGE_SIZE)
        {
            return Err(BootDmaBackingError::MalformedMap);
        }
        previous_end = region
            .pages
            .checked_mul(PAGE_SIZE)
            .and_then(|length| region.start.checked_add(length))
            .ok_or(BootDmaBackingError::MalformedMap)?;
    }
    let (index, original) = regions
        .iter()
        .copied()
        .enumerate()
        .find(|(_, r)| {
            r.kind == NormalizedMemoryKind::Reserved && r.start <= start && r.end() >= end
        })
        .ok_or(BootDmaBackingError::OutsideReserved)?;
    let left = usize::from(original.start < start);
    let right = usize::from(end < original.end());
    let new_count = count + left + right;
    if new_count > output.len() {
        return Err(BootDmaBackingError::TooManyRegions);
    }
    output.copy_within(index + 1..count, index + 1 + left + right);
    if left != 0 {
        output[index].pages = (start - original.start) / PAGE_SIZE;
    }
    output[index + left] = NormalizedRegion {
        start,
        pages: u64::from(pages),
        kind: NormalizedMemoryKind::BootDma,
    };
    if right != 0 {
        output[index + left + 1] = NormalizedRegion {
            start: end,
            pages: (original.end() - end) / PAGE_SIZE,
            kind: NormalizedMemoryKind::Reserved,
        };
    }
    Ok(new_count)
}

/// Checks the raw final map before normalization can merge LoaderData with
/// unrelated reserved memory. The caller must supply the exact range it
/// allocated as EfiLoaderData and the validated device/host address limit.
/// Coverage is not proof of allocation ownership, CPU cache policy or DMA
/// isolation. The caller must also exclude aliases (including framebuffer
/// overlaps) and preserve the range as reserved in the kernel handoff.
pub fn verify_boot_dma_backing(
    bytes: &[u8],
    descriptor_size: usize,
    start: u64,
    pages: u16,
    physical_bits: u8,
) -> Result<(), BootDmaBackingError> {
    const LOADER_DATA: u32 = 2;
    const RUNTIME: u64 = 1 << 63;

    if !(1..=256).contains(&pages)
        || !(32..=52).contains(&physical_bits)
        || start == 0
        || !start.is_multiple_of(PAGE_SIZE)
    {
        return Err(BootDmaBackingError::InvalidExtent);
    }
    let end = start
        .checked_add(u64::from(pages) * PAGE_SIZE)
        .filter(|&end| end <= (1u64 << physical_bits))
        .ok_or(BootDmaBackingError::InvalidExtent)?;
    if bytes.is_empty()
        || bytes.len() > MAX_MEMORY_MAP_BYTES
        || descriptor_size < core::mem::size_of::<MemoryDescriptor>()
        || !bytes.len().is_multiple_of(descriptor_size)
    {
        return Err(BootDmaBackingError::MalformedMap);
    }
    let mut found = false;
    for row in bytes.chunks_exact(descriptor_size) {
        let base = u64::from_le_bytes(row[8..16].try_into().unwrap());
        let pages = u64::from_le_bytes(row[24..32].try_into().unwrap());
        let limit = pages
            .checked_mul(PAGE_SIZE)
            .and_then(|length| base.checked_add(length))
            .ok_or(BootDmaBackingError::MalformedMap)?;
        if pages == 0 || !base.is_multiple_of(PAGE_SIZE) {
            return Err(BootDmaBackingError::MalformedMap);
        }
        if limit <= start || end <= base {
            continue;
        }
        let kind = u32::from_le_bytes(row[..4].try_into().unwrap());
        let attributes = u64::from_le_bytes(row[32..40].try_into().unwrap());
        if found || kind != LOADER_DATA || attributes & RUNTIME != 0 || base > start || limit < end
        {
            return Err(BootDmaBackingError::ConflictingDescriptor);
        }
        found = true;
    }
    if found {
        Ok(())
    } else {
        Err(BootDmaBackingError::MissingLoaderData)
    }
}

/// Converts an untrusted variable-stride UEFI map into the fixed MRML memory
/// model. Only conventional memory becomes free; boot-service and loader pages
/// remain reserved until a later kernel phase can prove they are reclaimable.
/// Physical ordering is canonicalized without changing the raw firmware bytes.
pub fn normalize_memory_map(
    bytes: &[u8],
    descriptor_size: usize,
    framebuffer_base: u64,
    framebuffer_bytes: u64,
    output: &mut [NormalizedRegion; MAX_NORMALIZED_REGIONS],
) -> Result<usize, NormalizeError> {
    if bytes.is_empty() {
        return Err(NormalizeError::Empty);
    }
    if descriptor_size < core::mem::size_of::<MemoryDescriptor>() {
        return Err(NormalizeError::BadDescriptorSize);
    }
    if !bytes.len().is_multiple_of(descriptor_size) {
        return Err(NormalizeError::Truncated);
    }
    if !framebuffer_base.is_multiple_of(PAGE_SIZE) || framebuffer_bytes == 0 {
        return Err(NormalizeError::FramebufferConflict);
    }
    let framebuffer_end_unaligned = framebuffer_base
        .checked_add(framebuffer_bytes)
        .ok_or(NormalizeError::Overflow)?;
    let framebuffer_end = framebuffer_end_unaligned
        .checked_add(PAGE_SIZE - 1)
        .map(|end| end & !(PAGE_SIZE - 1))
        .ok_or(NormalizeError::Overflow)?;
    if bytes.len() > MAX_MEMORY_MAP_BYTES {
        return Err(NormalizeError::TooManyRegions);
    }
    let mut order = [0u16; MAX_MEMORY_DESCRIPTORS];
    let order = &mut order[..bytes.len() / descriptor_size];
    for (index, slot) in order.iter_mut().enumerate() {
        *slot = index as u16;
    }
    let descriptor_at = |index: u16| {
        let offset = usize::from(index) * descriptor_size;
        &bytes[offset..offset + descriptor_size]
    };
    order.sort_unstable_by_key(|&index| {
        u64::from_le_bytes(descriptor_at(index)[8..16].try_into().unwrap())
    });
    let mut count = 0usize;
    let mut previous_end = 0u64;
    for &index in order.iter() {
        let descriptor = descriptor_at(index);
        let kind = u32::from_le_bytes(descriptor[..4].try_into().unwrap());
        let start = u64::from_le_bytes(descriptor[8..16].try_into().unwrap());
        let pages = u64::from_le_bytes(descriptor[24..32].try_into().unwrap());
        if start % PAGE_SIZE != 0 {
            return Err(NormalizeError::Unaligned);
        }
        if pages == 0 {
            return Err(NormalizeError::ZeroPages);
        }
        let end = pages
            .checked_mul(PAGE_SIZE)
            .and_then(|length| start.checked_add(length))
            .ok_or(NormalizeError::Overflow)?;
        if start < previous_end {
            return Err(NormalizeError::Overlap);
        }
        previous_end = end;
        let normalized_kind = match kind {
            7 => NormalizedMemoryKind::Free,
            5 | 6 => NormalizedMemoryKind::Firmware,
            9 | 10 => NormalizedMemoryKind::Acpi,
            11 | 12 => NormalizedMemoryKind::Mmio,
            _ => NormalizedMemoryKind::Reserved,
        };
        if count != 0
            && output[count - 1].kind == normalized_kind
            && output[count - 1].end() == start
        {
            output[count - 1].pages = output[count - 1]
                .pages
                .checked_add(pages)
                .ok_or(NormalizeError::Overflow)?;
            continue;
        }
        let slot = output
            .get_mut(count)
            .ok_or(NormalizeError::TooManyRegions)?;
        *slot = NormalizedRegion {
            start,
            pages,
            kind: normalized_kind,
        };
        count += 1;
    }
    overlay_framebuffer(output, count, framebuffer_base, framebuffer_end)
}

fn overlay_framebuffer(
    output: &mut [NormalizedRegion; MAX_NORMALIZED_REGIONS],
    count: usize,
    framebuffer_start: u64,
    framebuffer_end: u64,
) -> Result<usize, NormalizeError> {
    let framebuffer = NormalizedRegion {
        start: framebuffer_start,
        pages: (framebuffer_end - framebuffer_start) / PAGE_SIZE,
        kind: NormalizedMemoryKind::Mmio,
    };
    let mut rebuilt = [NormalizedRegion::EMPTY; MAX_NORMALIZED_REGIONS];
    let mut rebuilt_count = 0usize;
    let mut inserted = false;
    for region in output[..count].iter().copied() {
        if !inserted && framebuffer_end <= region.start {
            push_region(&mut rebuilt, &mut rebuilt_count, framebuffer)?;
            inserted = true;
        }
        let overlaps = region.start < framebuffer_end && region.end() > framebuffer_start;
        if !overlaps {
            push_region(&mut rebuilt, &mut rebuilt_count, region)?;
            continue;
        }
        if inserted || framebuffer_start < region.start || framebuffer_end > region.end() {
            return Err(NormalizeError::FramebufferConflict);
        }
        if region.start < framebuffer_start {
            push_region(
                &mut rebuilt,
                &mut rebuilt_count,
                NormalizedRegion {
                    start: region.start,
                    pages: (framebuffer_start - region.start) / PAGE_SIZE,
                    kind: region.kind,
                },
            )?;
        }
        push_region(&mut rebuilt, &mut rebuilt_count, framebuffer)?;
        if framebuffer_end < region.end() {
            push_region(
                &mut rebuilt,
                &mut rebuilt_count,
                NormalizedRegion {
                    start: framebuffer_end,
                    pages: (region.end() - framebuffer_end) / PAGE_SIZE,
                    kind: region.kind,
                },
            )?;
        }
        inserted = true;
    }
    if !inserted {
        push_region(&mut rebuilt, &mut rebuilt_count, framebuffer)?;
    }
    output[..rebuilt_count].copy_from_slice(&rebuilt[..rebuilt_count]);
    Ok(rebuilt_count)
}

fn push_region(
    output: &mut [NormalizedRegion; MAX_NORMALIZED_REGIONS],
    count: &mut usize,
    region: NormalizedRegion,
) -> Result<(), NormalizeError> {
    if *count != 0
        && output[*count - 1].kind == region.kind
        && output[*count - 1].end() == region.start
    {
        output[*count - 1].pages = output[*count - 1]
            .pages
            .checked_add(region.pages)
            .ok_or(NormalizeError::Overflow)?;
        return Ok(());
    }
    let slot = output
        .get_mut(*count)
        .ok_or(NormalizeError::TooManyRegions)?;
    *slot = region;
    *count += 1;
    Ok(())
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GraphicsOutputModeInformation {
    pub version: u32,
    pub horizontal_resolution: u32,
    pub vertical_resolution: u32,
    pub pixel_format: u32,
    pub pixel_bitmask: [u32; 4],
    pub pixels_per_scan_line: u32,
}

#[repr(C)]
pub struct GraphicsOutputMode {
    pub max_mode: u32,
    pub mode: u32,
    pub info: *mut GraphicsOutputModeInformation,
    pub info_size: usize,
    pub framebuffer_base: u64,
    pub framebuffer_size: usize,
}

#[repr(C)]
pub struct GraphicsOutputProtocol {
    pub query_mode: unsafe extern "efiapi" fn(
        *mut Self,
        u32,
        *mut usize,
        *mut *mut GraphicsOutputModeInformation,
    ) -> Status,
    pub set_mode: unsafe extern "efiapi" fn(*mut Self, u32) -> Status,
    pub blt: usize,
    pub mode: *mut GraphicsOutputMode,
}

#[repr(C)]
pub struct EdidProtocol {
    pub size: u32,
    pub bytes: *const u8,
}

/// Read the preferred detailed timing from a checksummed EDID base block.
/// Extension-only timings fall back to firmware modes rather than being guessed.
pub fn edid_preferred_resolution(base: &[u8; 128]) -> Option<(u32, u32)> {
    if base[..8] != [0, 255, 255, 255, 255, 255, 255, 0]
        || base.iter().copied().fold(0u8, u8::wrapping_add) != 0
        || base[18] != 1
        || base[19] > 4
        || base[24] & 2 == 0
        || base[54..56] == [0, 0]
    {
        return None;
    }
    let width = u32::from(base[56]) | (u32::from(base[58] & 0xf0) << 4);
    let height = u32::from(base[59]) | (u32::from(base[61] & 0xf0) << 4);
    (width != 0 && height != 0).then_some((width, height))
}

/// Rank only linear 32-bit modes understood by the existing handoff renderer.
pub fn framebuffer_mode_rank(
    info: GraphicsOutputModeInformation,
    preferred: Option<(u32, u32)>,
    current: bool,
) -> Option<u8> {
    let size = (info.horizontal_resolution, info.vertical_resolution);
    if info.version != 0
        || !matches!(info.pixel_format, 0 | 1)
        || size.0 == 0
        || size.1 == 0
        || size.0 > 16_384
        || size.1 > 16_384
        || info.pixels_per_scan_line < size.0
        || info.pixels_per_scan_line > 32_768
    {
        return None;
    }
    Some(if Some(size) == preferred {
        0
    } else if size == (1024, 768) {
        1
    } else if current {
        2
    } else {
        3
    })
}

#[cfg(test)]
mod gop_mode_tests {
    use super::*;

    #[test]
    fn preferred_detailed_timing_requires_valid_base_block() {
        let mut edid = [0u8; 128];
        edid[..8].copy_from_slice(&[0, 255, 255, 255, 255, 255, 255, 0]);
        edid[18] = 1;
        edid[19] = 4;
        edid[24] = 2;
        edid[54] = 1;
        edid[56] = 0x80;
        edid[58] = 0x70;
        edid[59] = 0x38;
        edid[61] = 0x40;
        edid[127] = 0u8.wrapping_sub(edid.iter().copied().fold(0u8, u8::wrapping_add));
        assert_eq!(edid_preferred_resolution(&edid), Some((1920, 1080)));
        edid[56] ^= 1;
        assert_eq!(edid_preferred_resolution(&edid), None);
        edid[56] ^= 1;
        edid[54] = 0;
        edid[127] = edid[127].wrapping_add(1);
        assert_eq!(edid_preferred_resolution(&edid), None);
    }

    #[test]
    fn rank_prefers_edid_then_conservative_fallback_and_filters_bad_modes() {
        let mode = |width, height, format, stride| GraphicsOutputModeInformation {
            version: 0,
            horizontal_resolution: width,
            vertical_resolution: height,
            pixel_format: format,
            pixel_bitmask: [0; 4],
            pixels_per_scan_line: stride,
        };
        let preferred = Some((1920, 1080));
        assert_eq!(
            framebuffer_mode_rank(mode(1920, 1080, 1, 1920), preferred, false),
            Some(0)
        );
        assert_eq!(
            framebuffer_mode_rank(mode(1024, 768, 0, 1056), preferred, false),
            Some(1)
        );
        assert_eq!(
            framebuffer_mode_rank(mode(1280, 720, 0, 1280), preferred, true),
            Some(2)
        );
        assert_eq!(
            framebuffer_mode_rank(mode(800, 600, 0, 800), preferred, false),
            Some(3)
        );
        assert_eq!(
            framebuffer_mode_rank(mode(1920, 1080, 3, 1920), preferred, false),
            None
        );
        assert_eq!(
            framebuffer_mode_rank(mode(1024, 768, 0, 800), preferred, false),
            None
        );
    }
}

pub type GetRng =
    unsafe extern "efiapi" fn(*mut RngProtocol, *const Guid, usize, *mut u8) -> Status;

#[repr(C)]
pub struct RngProtocol {
    pub get_info: usize,
    pub get_rng: GetRng,
}

pub const fn status_is_error(status: Status) -> bool {
    status >> (usize::BITS - 1) != 0
}

pub fn parse_root_digest(encoded: &[u8]) -> Option<[u8; 64]> {
    if encoded.len() != 128 {
        return None;
    }
    let mut output = [0u8; 64];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = hex(encoded[index * 2])?
            .checked_mul(16)?
            .checked_add(hex(encoded[index * 2 + 1])?)?;
    }
    (!output.iter().all(|byte| *byte == 0)).then_some(output)
}

pub fn parse_nonzero_version(encoded: &[u8]) -> Option<u64> {
    if encoded.is_empty() || encoded.len() > 20 {
        return None;
    }
    let mut value = 0u64;
    for byte in encoded {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add((byte - b'0') as u64)?;
    }
    (value != 0).then_some(value)
}

pub const SELECTED_BOOT_ARTIFACT_SET_BYTES: usize = 192;
pub const SELECTED_RELEASE_ARTIFACT_SET_BYTES: usize = 512;
pub const SELECTED_RELEASE_MANIFEST_KIND: u16 = 0x100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectedArtifactSetError {
    InvalidIdentity,
}

/// Encodes the exact verified kernel/service pairing extended into the boot
/// PCR. This record is evidence data, not authority or remote attestation.
pub fn encode_selected_boot_artifact_set(
    kernel_version: u64,
    kernel_digest: [u8; 64],
    service_version: u64,
    service_digest: [u8; 64],
) -> Result<[u8; SELECTED_BOOT_ARTIFACT_SET_BYTES], SelectedArtifactSetError> {
    if kernel_version == 0
        || service_version == 0
        || kernel_digest.iter().all(|byte| *byte == 0)
        || service_digest.iter().all(|byte| *byte == 0)
    {
        return Err(SelectedArtifactSetError::InvalidIdentity);
    }
    let mut output = [0; SELECTED_BOOT_ARTIFACT_SET_BYTES];
    output[..16].copy_from_slice(b"MRML-BOOTSET-v1\0");
    output[16..18].copy_from_slice(&(SELECTED_BOOT_ARTIFACT_SET_BYTES as u16).to_le_bytes());
    output[18..20].copy_from_slice(&1u16.to_le_bytes());
    output[20..22].copy_from_slice(&2u16.to_le_bytes());
    encode_artifact_identity(&mut output[32..112], 1, kernel_version, kernel_digest);
    encode_artifact_identity(&mut output[112..192], 3, service_version, service_digest);
    Ok(output)
}

/// Encodes the authenticated release manifest plus all five exact artifacts it
/// authorized. This PCR evidence record carries no authority.
pub fn encode_selected_release_artifact_set(
    release: u64,
    manifest_digest: [u8; 64],
    artifact_digests: [[u8; 64]; 5],
) -> Result<[u8; SELECTED_RELEASE_ARTIFACT_SET_BYTES], SelectedArtifactSetError> {
    if release == 0
        || manifest_digest.iter().all(|byte| *byte == 0)
        || artifact_digests
            .iter()
            .any(|digest| digest.iter().all(|byte| *byte == 0))
    {
        return Err(SelectedArtifactSetError::InvalidIdentity);
    }
    let mut output = [0; SELECTED_RELEASE_ARTIFACT_SET_BYTES];
    output[..16].copy_from_slice(b"MRML-BOOTSET-v3\0");
    output[16..18].copy_from_slice(&(SELECTED_RELEASE_ARTIFACT_SET_BYTES as u16).to_le_bytes());
    output[18..20].copy_from_slice(&3u16.to_le_bytes());
    output[20..22].copy_from_slice(&6u16.to_le_bytes());
    encode_artifact_identity(
        &mut output[32..112],
        SELECTED_RELEASE_MANIFEST_KIND,
        release,
        manifest_digest,
    );
    for (index, digest) in artifact_digests.into_iter().enumerate() {
        let offset = 112 + index * 80;
        encode_artifact_identity(
            &mut output[offset..offset + 80],
            index as u16 + 1,
            release,
            digest,
        );
    }
    Ok(output)
}

fn encode_artifact_identity(output: &mut [u8], kind: u16, version: u64, digest: [u8; 64]) {
    output[..2].copy_from_slice(&kind.to_le_bytes());
    output[8..16].copy_from_slice(&version.to_le_bytes());
    output[16..80].copy_from_slice(&digest);
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};
    use mrml_storage::{
        AllocationImage, AllocationKind, AllocationRecord, DirectoryImage, DirectoryMetadata,
        MetadataPointer, ObjectIdAllocatorImage, StorageObjectId, Superblock,
    };

    static MOCK_FIRMWARE_LOCK: AtomicBool = AtomicBool::new(false);

    struct MockFirmwareGuard;

    impl MockFirmwareGuard {
        fn acquire() -> Self {
            while MOCK_FIRMWARE_LOCK
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            Self
        }
    }

    impl Drop for MockFirmwareGuard {
        fn drop(&mut self) {
            MOCK_FIRMWARE_LOCK.store(false, Ordering::Release);
        }
    }

    static MOCK_BLOCK_PROTOCOL: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
    static MOCK_DEVICE_PATH: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
    static MOCK_CLOSE_STATUS: AtomicUsize = AtomicUsize::new(SUCCESS);
    static MOCK_CLOSE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static RECOVERY_READ_MEDIA: AtomicUsize = AtomicUsize::new(0);
    static RECOVERY_READ_LBA: AtomicUsize = AtomicUsize::new(0);
    static RECOVERY_READ_CALLS: AtomicUsize = AtomicUsize::new(0);
    static RECOVERY_READ_STATUS: AtomicUsize = AtomicUsize::new(SUCCESS);
    static RECOVERY_MUTATE_MEDIA: AtomicPtr<BlockIoMedia> = AtomicPtr::new(core::ptr::null_mut());
    static RECOVERY_READ_SOURCE: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
    static MOCK_HANDLE_BUFFER: AtomicPtr<Handle> = AtomicPtr::new(core::ptr::null_mut());
    static MOCK_HANDLE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static MOCK_LOCATE_STATUS: AtomicUsize = AtomicUsize::new(SUCCESS);
    static MOCK_FREE_STATUS: AtomicUsize = AtomicUsize::new(SUCCESS);
    static MOCK_FREE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static ROOT_HEADER_SOURCE: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
    static ROOT_PRIMARY_SOURCE: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
    static ROOT_SECONDARY_SOURCE: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
    static ROOT_FAIL_LBA: AtomicUsize = AtomicUsize::new(usize::MAX);
    static GRAPH_SOURCE: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
    static GRAPH_SOURCE_BYTES: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "efiapi" fn mock_get_memory_map(
        _: *mut usize,
        _: *mut MemoryDescriptor,
        _: *mut usize,
        _: *mut usize,
        _: *mut u32,
    ) -> Status {
        NOT_FOUND
    }

    unsafe extern "efiapi" fn mock_exit_boot_services(_: Handle, _: usize) -> Status {
        NOT_FOUND
    }

    unsafe extern "efiapi" fn mock_handle_protocol(
        _: Handle,
        _: *const Guid,
        _: *mut *mut c_void,
    ) -> Status {
        NOT_FOUND
    }

    unsafe extern "efiapi" fn mock_allocate_pages(_: u32, _: u32, _: usize, _: *mut u64) -> Status {
        NOT_FOUND
    }

    unsafe extern "efiapi" fn mock_free_pages(_: u64, _: usize) -> Status {
        NOT_FOUND
    }

    unsafe extern "efiapi" fn mock_free_pool(_: *mut c_void) -> Status {
        MOCK_FREE_CALLS.fetch_add(1, Ordering::SeqCst);
        MOCK_FREE_STATUS.load(Ordering::SeqCst)
    }

    unsafe extern "efiapi" fn mock_locate_handle_buffer(
        search: u32,
        protocol: *const Guid,
        search_key: *mut c_void,
        count: *mut usize,
        buffer: *mut *mut Handle,
    ) -> Status {
        if search != LOCATE_BY_PROTOCOL
            || protocol.is_null()
            || !unsafe { &*protocol }.equals(&BLOCK_IO_PROTOCOL_GUID)
            || !search_key.is_null()
            || count.is_null()
            || buffer.is_null()
        {
            return LOAD_ERROR;
        }
        unsafe {
            *count = MOCK_HANDLE_COUNT.load(Ordering::SeqCst);
            *buffer = MOCK_HANDLE_BUFFER.load(Ordering::SeqCst);
        }
        MOCK_LOCATE_STATUS.load(Ordering::SeqCst)
    }

    unsafe extern "efiapi" fn mock_locate_protocol(
        _: *const Guid,
        _: *mut c_void,
        _: *mut *mut c_void,
    ) -> Status {
        NOT_FOUND
    }

    unsafe extern "efiapi" fn mock_open_protocol(
        _: Handle,
        guid: *const Guid,
        interface: *mut *mut c_void,
        _: Handle,
        _: Handle,
        attributes: u32,
    ) -> Status {
        if guid.is_null() || interface.is_null() || attributes != OPEN_PROTOCOL_GET_PROTOCOL {
            return LOAD_ERROR;
        }
        let guid = unsafe { &*guid };
        let pointer = if guid.equals(&BLOCK_IO_PROTOCOL_GUID) {
            MOCK_BLOCK_PROTOCOL.load(Ordering::SeqCst)
        } else if guid.equals(&DEVICE_PATH_PROTOCOL_GUID) {
            MOCK_DEVICE_PATH.load(Ordering::SeqCst)
        } else {
            return NOT_FOUND;
        };
        if pointer.is_null() {
            return NOT_FOUND;
        }
        unsafe { *interface = pointer };
        SUCCESS
    }

    unsafe extern "efiapi" fn mock_close_protocol(
        _: Handle,
        _: *const Guid,
        _: Handle,
        _: Handle,
    ) -> Status {
        MOCK_CLOSE_CALLS.fetch_add(1, Ordering::SeqCst);
        MOCK_CLOSE_STATUS.load(Ordering::SeqCst)
    }

    fn mock_boot_services() -> BootServices {
        BootServices {
            header: TableHeader {
                signature: 0,
                revision: 0,
                header_size: 0,
                crc32: 0,
                reserved: 0,
            },
            raise_tpl: 0,
            restore_tpl: 0,
            allocate_pages: mock_allocate_pages,
            free_pages: mock_free_pages,
            get_memory_map: mock_get_memory_map,
            allocate_pool: 0,
            free_pool: mock_free_pool,
            create_event: 0,
            set_timer: 0,
            wait_for_event: 0,
            signal_event: 0,
            close_event: 0,
            check_event: 0,
            install_protocol_interface: 0,
            reinstall_protocol_interface: 0,
            uninstall_protocol_interface: 0,
            handle_protocol: mock_handle_protocol,
            reserved: 0,
            register_protocol_notify: 0,
            locate_handle: 0,
            locate_device_path: 0,
            install_configuration_table: 0,
            load_image: 0,
            start_image: 0,
            exit: 0,
            unload_image: 0,
            exit_boot_services: mock_exit_boot_services,
            get_next_monotonic_count: 0,
            stall: 0,
            set_watchdog_timer: 0,
            connect_controller: 0,
            disconnect_controller: 0,
            open_protocol: mock_open_protocol,
            close_protocol: mock_close_protocol,
            open_protocol_information: 0,
            protocols_per_handle: 0,
            locate_handle_buffer: mock_locate_handle_buffer,
            locate_protocol: mock_locate_protocol,
        }
    }

    unsafe extern "efiapi" fn block_reset(_: *mut BlockIoProtocol, _: u8) -> Status {
        SUCCESS
    }

    unsafe extern "efiapi" fn block_read(
        _: *mut BlockIoProtocol,
        _: u32,
        _: u64,
        _: usize,
        _: *mut c_void,
    ) -> Status {
        SUCCESS
    }

    unsafe extern "efiapi" fn recovery_block_read(
        _: *mut BlockIoProtocol,
        media_id: u32,
        lba: u64,
        bytes: usize,
        output: *mut c_void,
    ) -> Status {
        RECOVERY_READ_CALLS.fetch_add(1, Ordering::SeqCst);
        if usize::try_from(media_id).ok() != Some(RECOVERY_READ_MEDIA.load(Ordering::SeqCst))
            || usize::try_from(lba).ok() != Some(RECOVERY_READ_LBA.load(Ordering::SeqCst))
            || bytes != UEFI_RECOVERY_BLOCK_BYTES
            || output.is_null()
        {
            return LOAD_ERROR;
        }
        let source = RECOVERY_READ_SOURCE.load(Ordering::SeqCst);
        if source.is_null() {
            unsafe { core::ptr::write_bytes(output.cast::<u8>(), 0x5a, bytes) };
        } else {
            unsafe { core::ptr::copy_nonoverlapping(source, output.cast::<u8>(), bytes) };
        }
        let media = RECOVERY_MUTATE_MEDIA.load(Ordering::SeqCst);
        if let Some(media) = unsafe { media.as_mut() } {
            media.media_id = media.media_id.wrapping_add(1);
        }
        RECOVERY_READ_STATUS.load(Ordering::SeqCst)
    }

    unsafe extern "efiapi" fn recovery_root_read(
        _: *mut BlockIoProtocol,
        media_id: u32,
        lba: u64,
        bytes: usize,
        output: *mut c_void,
    ) -> Status {
        if media_id != 7 || bytes != UEFI_RECOVERY_BLOCK_BYTES || output.is_null() {
            return LOAD_ERROR;
        }
        let source = match lba {
            0 => ROOT_HEADER_SOURCE.load(Ordering::SeqCst),
            8 => ROOT_PRIMARY_SOURCE.load(Ordering::SeqCst),
            16 => ROOT_SECONDARY_SOURCE.load(Ordering::SeqCst),
            _ => return LOAD_ERROR,
        };
        if source.is_null() {
            return LOAD_ERROR;
        }
        unsafe { core::ptr::copy_nonoverlapping(source, output.cast::<u8>(), bytes) };
        if usize::try_from(lba).ok() == Some(ROOT_FAIL_LBA.load(Ordering::SeqCst)) {
            LOAD_ERROR
        } else {
            SUCCESS
        }
    }

    unsafe extern "efiapi" fn recovery_graph_read(
        _: *mut BlockIoProtocol,
        media_id: u32,
        lba: u64,
        bytes: usize,
        output: *mut c_void,
    ) -> Status {
        if media_id != 7 || bytes != UEFI_RECOVERY_BLOCK_BYTES || output.is_null() {
            return LOAD_ERROR;
        }
        let source = GRAPH_SOURCE.load(Ordering::SeqCst);
        let source_bytes = GRAPH_SOURCE_BYTES.load(Ordering::SeqCst);
        let offset = match usize::try_from(lba)
            .ok()
            .and_then(|lba| lba.checked_mul(512))
        {
            Some(offset) => offset,
            None => return LOAD_ERROR,
        };
        let end = match offset.checked_add(bytes) {
            Some(end) => end,
            None => return LOAD_ERROR,
        };
        if source.is_null() || end > source_bytes {
            return LOAD_ERROR;
        }
        unsafe { core::ptr::copy_nonoverlapping(source.add(offset), output.cast::<u8>(), bytes) };
        if usize::try_from(lba).ok() == Some(ROOT_FAIL_LBA.load(Ordering::SeqCst)) {
            LOAD_ERROR
        } else {
            SUCCESS
        }
    }

    unsafe extern "efiapi" fn block_write(
        _: *mut BlockIoProtocol,
        _: u32,
        _: u64,
        _: usize,
        _: *const c_void,
    ) -> Status {
        SUCCESS
    }

    unsafe extern "efiapi" fn block_flush(_: *mut BlockIoProtocol) -> Status {
        SUCCESS
    }

    fn block_protocol(media: &mut BlockIoMedia) -> BlockIoProtocol {
        BlockIoProtocol {
            revision: 0x0001_0000,
            media,
            reset: block_reset,
            read_blocks: block_read,
            write_blocks: block_write,
            flush_blocks: block_flush,
        }
    }

    fn valid_block_media() -> BlockIoMedia {
        BlockIoMedia {
            media_id: 0,
            removable_media: 0,
            media_present: 1,
            logical_partition: 0,
            read_only: 0,
            write_caching: 0,
            block_size: 4096,
            io_align: 1,
            last_block: 31,
            lowest_aligned_lba: 0,
            logical_blocks_per_physical_block: 1,
            optimal_transfer_length_granularity: 1,
        }
    }

    fn scan_candidate(
        handle: Handle,
        id: BlockDeviceId,
        volume: VolumeId,
        path_tag: u8,
    ) -> UefiRecoveryHeaderCandidate {
        let media = UefiBlockMediaSnapshot {
            media_id: u32::from(path_tag),
            block_size: 4096,
            block_count: 8,
            io_align: 4096,
            removable: false,
            logical_partition: true,
            read_only: false,
        };
        let path = [1, 1, 8, 0, path_tag, 0xbb, 0xcc, 0xdd, 0x7f, 0xff, 4, 0];
        UefiRecoveryHeaderCandidate {
            handle,
            descriptor: uefi_platform_block_descriptor(id, media, &path).unwrap(),
            media,
            header: VolumeHeader::new(volume, 4096, 8, 1, 2).unwrap(),
            sata_route: None,
        }
    }

    fn canonical_sata_device_path() -> [u8; 74] {
        let mut path = [0u8; 74];
        path[0..4].copy_from_slice(&[2, 1, 12, 0]);
        path[4..8].copy_from_slice(&0x0a03_41d0u32.to_le_bytes());
        path[8..12].copy_from_slice(&7u32.to_le_bytes());
        path[12..18].copy_from_slice(&[1, 1, 6, 0, 2, 5]);
        path[18..28].copy_from_slice(&[3, 18, 10, 0, 3, 0, 0xff, 0xff, 1, 0]);
        path[28..32].copy_from_slice(&[4, 1, 42, 0]);
        path[32..36].copy_from_slice(&2u32.to_le_bytes());
        path[36..44].copy_from_slice(&2048u64.to_le_bytes());
        path[44..52].copy_from_slice(&4096u64.to_le_bytes());
        path[52..68].copy_from_slice(&[0x5a; 16]);
        path[68] = 2;
        path[69] = 2;
        path[70..74].copy_from_slice(&[0x7f, 0xff, 4, 0]);
        path
    }

    fn utf16_ascii(value: &str) -> [u16; MAX_BOOT_LOAD_OPTION_UNITS] {
        let mut output = [0; MAX_BOOT_LOAD_OPTION_UNITS];
        for (slot, byte) in output.iter_mut().zip(value.bytes()) {
            *slot = u16::from(byte);
        }
        output
    }

    fn loaded_image(load_options: *mut c_void, load_options_size: u32) -> LoadedImageProtocol {
        LoadedImageProtocol {
            revision: 0,
            parent_handle: core::ptr::null_mut(),
            system_table: core::ptr::null_mut(),
            device_handle: core::ptr::null_mut(),
            file_path: core::ptr::null_mut(),
            reserved: core::ptr::null_mut(),
            load_options_size,
            load_options,
            image_base: core::ptr::null_mut(),
            image_size: 0,
            image_code_type: 0,
            image_data_type: 0,
            unload: 0,
        }
    }

    #[test]
    fn boot_isolation_options_share_one_exact_menu_and_shell_policy() {
        assert_eq!(
            parse_boot_isolation_selection(&[]),
            Ok(BootIsolationSelection::ConfiguredDefault)
        );
        assert_eq!(
            parse_boot_isolation_selection(&[0]),
            Ok(BootIsolationSelection::ConfiguredDefault)
        );

        let menu = utf16_ascii("--isolation=total-microvm");
        let menu_length = "--isolation=total-microvm".len();
        assert_eq!(
            parse_boot_isolation_selection(&menu[..menu_length]),
            Ok(BootIsolationSelection::TotalMicrovmOnce)
        );
        assert_eq!(
            parse_boot_isolation_selection(&menu[..=menu_length]),
            Ok(BootIsolationSelection::TotalMicrovmOnce)
        );

        let shell = utf16_ascii("FS0:\\EFI\\MRML\\BOOTX64.EFI --isolation=total-microvm");
        let shell_length = "FS0:\\EFI\\MRML\\BOOTX64.EFI --isolation=total-microvm".len();
        assert_eq!(
            parse_boot_isolation_selection(&shell[..shell_length]),
            Ok(BootIsolationSelection::TotalMicrovmOnce)
        );
        let program = utf16_ascii("bootx64.efi");
        assert_eq!(
            parse_boot_isolation_selection(&program[.."bootx64.efi".len()]),
            Ok(BootIsolationSelection::ConfiguredDefault)
        );
    }

    #[test]
    fn boot_isolation_options_reject_ambiguity_and_unknown_tokens() {
        let unknown = utf16_ascii("--isolation=balanced");
        assert_eq!(
            parse_boot_isolation_selection(&unknown[.."--isolation=balanced".len()]),
            Err(BootLoadOptionError::UnknownOption)
        );
        let extra = utf16_ascii("--isolation=total-microvm extra");
        assert_eq!(
            parse_boot_isolation_selection(&extra[.."--isolation=total-microvm extra".len()]),
            Err(BootLoadOptionError::UnknownOption)
        );
        let wrong_program = utf16_ascii("OTHER.EFI --isolation=total-microvm");
        assert_eq!(
            parse_boot_isolation_selection(
                &wrong_program[.."OTHER.EFI --isolation=total-microvm".len()]
            ),
            Err(BootLoadOptionError::UnknownProgram)
        );
        let spaced = utf16_ascii("BOOTX64.EFI  --isolation=total-microvm");
        assert_eq!(
            parse_boot_isolation_selection(
                &spaced[.."BOOTX64.EFI  --isolation=total-microvm".len()]
            ),
            Err(BootLoadOptionError::NonCanonicalWhitespace)
        );
        assert_eq!(
            parse_boot_isolation_selection(&[b'-' as u16, 0, b'x' as u16]),
            Err(BootLoadOptionError::EmbeddedNull)
        );
        assert_eq!(
            parse_boot_isolation_selection(&[0x80]),
            Err(BootLoadOptionError::NonAscii)
        );
        assert_eq!(
            parse_boot_isolation_selection(&[b'x' as u16; MAX_BOOT_LOAD_OPTION_UNITS + 1]),
            Err(BootLoadOptionError::TooLong)
        );
    }

    #[test]
    fn loaded_image_boot_options_validate_firmware_buffer_before_parsing() {
        let mut options = utf16_ascii("--isolation=total-microvm");
        let byte_length = ("--isolation=total-microvm".len() * 2) as u32;
        let loaded = loaded_image(options.as_mut_ptr().cast(), byte_length);
        assert_eq!(
            unsafe { parse_loaded_image_boot_isolation(&loaded) },
            Ok(BootIsolationSelection::TotalMicrovmOnce)
        );

        let empty = loaded_image(core::ptr::null_mut(), 0);
        assert_eq!(
            unsafe { parse_loaded_image_boot_isolation(&empty) },
            Ok(BootIsolationSelection::ConfiguredDefault)
        );
        let missing = loaded_image(core::ptr::null_mut(), 2);
        assert_eq!(
            unsafe { parse_loaded_image_boot_isolation(&missing) },
            Err(BootLoadOptionError::MissingBuffer)
        );
        let odd = loaded_image(options.as_mut_ptr().cast(), 1);
        assert_eq!(
            unsafe { parse_loaded_image_boot_isolation(&odd) },
            Err(BootLoadOptionError::OddByteLength)
        );
        let misaligned = loaded_image(options.as_mut_ptr().cast::<u8>().wrapping_add(1).cast(), 2);
        assert_eq!(
            unsafe { parse_loaded_image_boot_isolation(&misaligned) },
            Err(BootLoadOptionError::MisalignedBuffer)
        );
        let oversized = loaded_image(
            options.as_mut_ptr().cast(),
            (MAX_BOOT_LOAD_OPTION_UNITS as u32 + 1) * 2,
        );
        assert_eq!(
            unsafe { parse_loaded_image_boot_isolation(&oversized) },
            Err(BootLoadOptionError::TooLong)
        );
    }

    #[test]
    fn abi_layouts_match_x86_64_uefi() {
        assert_eq!(core::mem::size_of::<TableHeader>(), 24);
        assert_eq!(core::mem::size_of::<MemoryDescriptor>(), 40);
        assert_eq!(core::mem::offset_of!(BootServices, get_memory_map), 56);
        assert_eq!(core::mem::offset_of!(BootServices, allocate_pages), 40);
        assert_eq!(core::mem::offset_of!(BootServices, handle_protocol), 152);
        assert_eq!(core::mem::offset_of!(BootServices, exit_boot_services), 232);
        assert_eq!(core::mem::offset_of!(BootServices, locate_protocol), 320);
        assert_eq!(core::mem::offset_of!(SystemTable, boot_services), 96);
        assert_eq!(core::mem::size_of::<Tcg2EventHeader>(), 14);
        assert_eq!(core::mem::offset_of!(Tcg2Event, header), 4);
        assert_eq!(core::mem::offset_of!(Tcg2Event, event), 18);
        assert_eq!(core::mem::size_of::<Tcg2Protocol>(), 56);
        assert_eq!(core::mem::offset_of!(RuntimeServices, get_variable), 72);
        assert_eq!(core::mem::size_of::<RuntimeServices>(), 96);
        assert_eq!(
            core::mem::offset_of!(LoadedImageProtocol, device_handle),
            24
        );
        assert_eq!(core::mem::offset_of!(FileProtocol, read), 32);
        assert_eq!(core::mem::offset_of!(FileProtocol, write), 40);
        assert_eq!(core::mem::offset_of!(FileProtocol, set_position), 56);
        assert_eq!(core::mem::offset_of!(FileProtocol, get_info), 64);
        assert_eq!(core::mem::offset_of!(FileProtocol, flush), 80);
        assert_eq!(core::mem::size_of::<BlockIoMedia>(), 48);
        assert_eq!(core::mem::offset_of!(BlockIoMedia, block_size), 12);
        assert_eq!(core::mem::offset_of!(BlockIoMedia, last_block), 24);
        assert_eq!(core::mem::size_of::<BlockIoProtocol>(), 48);
        assert_eq!(core::mem::offset_of!(BlockIoProtocol, media), 8);
        assert_eq!(core::mem::offset_of!(BlockIoProtocol, read_blocks), 24);
    }

    #[test]
    fn uefi_block_media_snapshot_and_path_produce_exact_platform_generation() {
        let mut media = BlockIoMedia {
            media_id: u32::MAX,
            removable_media: 1,
            media_present: 1,
            logical_partition: 1,
            read_only: 1,
            write_caching: 0,
            block_size: 4096,
            io_align: 4096,
            last_block: 31,
            lowest_aligned_lba: 0,
            logical_blocks_per_physical_block: 1,
            optimal_transfer_length_granularity: 1,
        };
        let protocol = block_protocol(&mut media);
        let snapshot = unsafe { snapshot_uefi_block_media(&protocol) }.unwrap();
        assert_eq!(snapshot.media_id(), u32::MAX);
        assert_eq!(snapshot.block_size(), 4096);
        assert_eq!(snapshot.block_count(), 32);
        assert_eq!(snapshot.io_align(), 4096);
        assert!(snapshot.removable());
        assert!(snapshot.logical_partition());
        assert!(snapshot.read_only());

        let path = [1, 1, 8, 0, 0xaa, 0xbb, 0xcc, 0xdd, 0x7f, 0xff, 4, 0];
        let id = BlockDeviceId::new(7).unwrap();
        let descriptor = uefi_platform_block_descriptor(id, snapshot, &path).unwrap();
        assert_eq!(descriptor.block().id(), id);
        assert_eq!(descriptor.block().block_count(), 32);
        assert_eq!(
            descriptor.identity().transport(),
            PlatformBlockTransport::Uefi
        );
        assert_eq!(descriptor.identity().controller_generation(), 1);
        assert_eq!(
            descriptor.identity().media_generation(),
            u64::from(u32::MAX) + 1
        );

        let changed_path = [1, 1, 8, 0, 0xaa, 0xbb, 0xcc, 0xde, 0x7f, 0xff, 4, 0];
        let changed = uefi_platform_block_descriptor(id, snapshot, &changed_path).unwrap();
        assert_ne!(
            descriptor.identity().stable_id(),
            changed.identity().stable_id()
        );
    }

    #[test]
    fn uefi_block_descriptor_rejects_hostile_media_and_device_paths() {
        let mut absent = valid_block_media();
        absent.media_present = 0;
        let protocol = block_protocol(&mut absent);
        assert_eq!(
            unsafe { snapshot_uefi_block_media(&protocol) },
            Err(UefiBlockDescriptorError::MediaAbsent)
        );
        let mut noncanonical = valid_block_media();
        noncanonical.media_present = 2;
        let protocol = block_protocol(&mut noncanonical);
        assert_eq!(
            unsafe { snapshot_uefi_block_media(&protocol) },
            Err(UefiBlockDescriptorError::NonCanonicalBoolean)
        );
        let mut misaligned = valid_block_media();
        misaligned.io_align = 3;
        let protocol = block_protocol(&mut misaligned);
        assert_eq!(
            unsafe { snapshot_uefi_block_media(&protocol) },
            Err(UefiBlockDescriptorError::InvalidAlignment)
        );
        let mut overflowing = valid_block_media();
        overflowing.last_block = u64::MAX;
        let protocol = block_protocol(&mut overflowing);
        assert_eq!(
            unsafe { snapshot_uefi_block_media(&protocol) },
            Err(UefiBlockDescriptorError::InvalidGeometry)
        );
        let mut valid = valid_block_media();
        let mut protocol = block_protocol(&mut valid);
        protocol.media = core::ptr::null_mut();
        assert_eq!(
            unsafe { snapshot_uefi_block_media(&protocol) },
            Err(UefiBlockDescriptorError::MissingMedia)
        );

        let snapshot = UefiBlockMediaSnapshot {
            media_id: 0,
            block_size: 4096,
            block_count: 32,
            io_align: 1,
            removable: false,
            logical_partition: false,
            read_only: false,
        };
        let id = BlockDeviceId::new(7).unwrap();
        assert_eq!(
            uefi_platform_block_descriptor(id, snapshot, &[1, 1, 3, 0]),
            Err(UefiBlockDescriptorError::InvalidDevicePathNode)
        );
        assert_eq!(
            uefi_platform_block_descriptor(id, snapshot, &[1, 1, 8, 0, 0, 0]),
            Err(UefiBlockDescriptorError::TruncatedDevicePath)
        );
        assert_eq!(
            uefi_platform_block_descriptor(id, snapshot, &[0x7f, 1, 4, 0]),
            Err(UefiBlockDescriptorError::UnsupportedDevicePathInstance)
        );
        assert_eq!(
            uefi_platform_block_descriptor(id, snapshot, &[1, 1, 4, 0]),
            Err(UefiBlockDescriptorError::MissingDevicePathEnd)
        );
    }

    #[test]
    fn loaded_image_protocol_acquisition_closes_every_open_relationship() {
        let _guard = MockFirmwareGuard::acquire();
        let mut media = valid_block_media();
        media.media_id = 9;
        let mut block = block_protocol(&mut media);
        let mut path = [1u8, 1, 8, 0, 0xaa, 0xbb, 0xcc, 0xdd, 0x7f, 0xff, 4, 0];
        MOCK_BLOCK_PROTOCOL.store(
            (&mut block as *mut BlockIoProtocol).cast(),
            Ordering::SeqCst,
        );
        MOCK_DEVICE_PATH.store(path.as_mut_ptr().cast(), Ordering::SeqCst);
        MOCK_CLOSE_STATUS.store(SUCCESS, Ordering::SeqCst);
        MOCK_CLOSE_CALLS.store(0, Ordering::SeqCst);
        let services = mock_boot_services();
        let image = core::ptr::without_provenance_mut::<c_void>(1);
        let device = core::ptr::without_provenance_mut::<c_void>(2);
        let mut loaded = loaded_image(core::ptr::null_mut(), 0);
        loaded.device_handle = device;
        let mut scratch = [0u8; MAX_UEFI_DEVICE_PATH_BYTES];
        let descriptor = unsafe {
            discover_loaded_image_block_descriptor(
                &services,
                image,
                &loaded,
                BlockDeviceId::new(7).unwrap(),
                &mut scratch,
            )
        }
        .unwrap();
        assert_eq!(descriptor.identity().media_generation(), 10);
        assert_eq!(MOCK_CLOSE_CALLS.load(Ordering::SeqCst), 2);

        MOCK_DEVICE_PATH.store(core::ptr::null_mut(), Ordering::SeqCst);
        MOCK_CLOSE_CALLS.store(0, Ordering::SeqCst);
        assert_eq!(
            unsafe {
                discover_loaded_image_block_descriptor(
                    &services,
                    image,
                    &loaded,
                    BlockDeviceId::new(7).unwrap(),
                    &mut scratch,
                )
            },
            Err(UefiBlockDescriptorError::OpenDevicePath(NOT_FOUND))
        );
        assert_eq!(MOCK_CLOSE_CALLS.load(Ordering::SeqCst), 1);

        MOCK_DEVICE_PATH.store(path.as_mut_ptr().cast(), Ordering::SeqCst);
        MOCK_CLOSE_STATUS.store(LOAD_ERROR, Ordering::SeqCst);
        MOCK_CLOSE_CALLS.store(0, Ordering::SeqCst);
        assert_eq!(
            unsafe {
                discover_loaded_image_block_descriptor(
                    &services,
                    image,
                    &loaded,
                    BlockDeviceId::new(7).unwrap(),
                    &mut scratch,
                )
            },
            Err(UefiBlockDescriptorError::CloseProtocol(LOAD_ERROR))
        );
        assert_eq!(MOCK_CLOSE_CALLS.load(Ordering::SeqCst), 2);
        MOCK_CLOSE_STATUS.store(SUCCESS, Ordering::SeqCst);
        MOCK_BLOCK_PROTOCOL.store(core::ptr::null_mut(), Ordering::SeqCst);
        MOCK_DEVICE_PATH.store(core::ptr::null_mut(), Ordering::SeqCst);
    }

    #[test]
    fn recovery_block_read_groups_firmware_blocks_and_erases_uncertain_output() {
        let mut media = valid_block_media();
        media.media_id = 7;
        media.block_size = 512;
        media.last_block = 63;
        let mut protocol = block_protocol(&mut media);
        protocol.read_blocks = recovery_block_read;
        let expected = unsafe { snapshot_uefi_block_media(&protocol) }.unwrap();
        let mut output = UefiRecoveryBlock::new();
        assert!((output.as_slice().as_ptr() as usize).is_multiple_of(4096));

        RECOVERY_READ_MEDIA.store(7, Ordering::SeqCst);
        RECOVERY_READ_LBA.store(16, Ordering::SeqCst);
        RECOVERY_READ_CALLS.store(0, Ordering::SeqCst);
        RECOVERY_READ_STATUS.store(SUCCESS, Ordering::SeqCst);
        RECOVERY_MUTATE_MEDIA.store(core::ptr::null_mut(), Ordering::SeqCst);
        RECOVERY_READ_SOURCE.store(core::ptr::null_mut(), Ordering::SeqCst);
        assert_eq!(
            unsafe { read_uefi_recovery_block(&mut protocol, expected, 2, &mut output) },
            Ok(())
        );
        assert_eq!(RECOVERY_READ_CALLS.load(Ordering::SeqCst), 1);
        assert!(output.as_slice().iter().all(|byte| *byte == 0x5a));

        RECOVERY_READ_STATUS.store(LOAD_ERROR, Ordering::SeqCst);
        assert_eq!(
            unsafe { read_uefi_recovery_block(&mut protocol, expected, 2, &mut output) },
            Err(UefiBlockDescriptorError::ReadBlock(LOAD_ERROR))
        );
        assert!(output.as_slice().iter().all(|byte| *byte == 0));

        RECOVERY_READ_STATUS.store(SUCCESS, Ordering::SeqCst);
        RECOVERY_MUTATE_MEDIA.store(protocol.media, Ordering::SeqCst);
        assert_eq!(
            unsafe { read_uefi_recovery_block(&mut protocol, expected, 2, &mut output) },
            Err(UefiBlockDescriptorError::MediaChanged)
        );
        assert!(output.as_slice().iter().all(|byte| *byte == 0));
        RECOVERY_MUTATE_MEDIA.store(core::ptr::null_mut(), Ordering::SeqCst);

        unsafe { (*protocol.media).media_id = 7 };
        RECOVERY_READ_CALLS.store(0, Ordering::SeqCst);
        assert_eq!(
            unsafe { read_uefi_recovery_block(&mut protocol, expected, 8, &mut output) },
            Err(UefiBlockDescriptorError::RecoveryRange)
        );
        assert_eq!(RECOVERY_READ_CALLS.load(Ordering::SeqCst), 0);

        unsafe { (*protocol.media).block_size = 256 };
        let unsupported = unsafe { snapshot_uefi_block_media(&protocol) }.unwrap();
        assert_eq!(
            unsafe { read_uefi_recovery_block(&mut protocol, unsupported, 0, &mut output) },
            Err(UefiBlockDescriptorError::UnsupportedRecoveryGeometry)
        );
    }

    #[test]
    fn block_handle_enumeration_is_bounded_unique_and_always_releases_firmware_memory() {
        let mut handles = [
            core::ptr::without_provenance_mut::<c_void>(1),
            core::ptr::without_provenance_mut::<c_void>(2),
        ];
        MOCK_HANDLE_BUFFER.store(handles.as_mut_ptr(), Ordering::SeqCst);
        MOCK_HANDLE_COUNT.store(2, Ordering::SeqCst);
        MOCK_LOCATE_STATUS.store(SUCCESS, Ordering::SeqCst);
        MOCK_FREE_STATUS.store(SUCCESS, Ordering::SeqCst);
        MOCK_FREE_CALLS.store(0, Ordering::SeqCst);
        let services = mock_boot_services();
        let set = unsafe { locate_block_io_handles::<4>(&services) }.unwrap();
        assert_eq!(set.as_slice(), handles.as_slice());
        assert_eq!(MOCK_FREE_CALLS.load(Ordering::SeqCst), 1);

        MOCK_FREE_CALLS.store(0, Ordering::SeqCst);
        assert!(matches!(
            unsafe { locate_block_io_handles::<1>(&services) },
            Err(UefiBlockDescriptorError::HandleCapacity)
        ));
        assert_eq!(MOCK_FREE_CALLS.load(Ordering::SeqCst), 1);

        let mut duplicates = [handles[0], handles[0]];
        MOCK_HANDLE_BUFFER.store(duplicates.as_mut_ptr(), Ordering::SeqCst);
        MOCK_FREE_CALLS.store(0, Ordering::SeqCst);
        assert!(matches!(
            unsafe { locate_block_io_handles::<4>(&services) },
            Err(UefiBlockDescriptorError::DuplicateHandle)
        ));
        assert_eq!(MOCK_FREE_CALLS.load(Ordering::SeqCst), 1);

        MOCK_LOCATE_STATUS.store(LOAD_ERROR, Ordering::SeqCst);
        MOCK_FREE_CALLS.store(0, Ordering::SeqCst);
        assert!(matches!(
            unsafe { locate_block_io_handles::<4>(&services) },
            Err(UefiBlockDescriptorError::LocateHandles(LOAD_ERROR))
        ));
        assert_eq!(MOCK_FREE_CALLS.load(Ordering::SeqCst), 1);

        MOCK_LOCATE_STATUS.store(SUCCESS, Ordering::SeqCst);
        MOCK_FREE_STATUS.store(LOAD_ERROR, Ordering::SeqCst);
        MOCK_FREE_CALLS.store(0, Ordering::SeqCst);
        assert!(matches!(
            unsafe { locate_block_io_handles::<4>(&services) },
            Err(UefiBlockDescriptorError::FreeHandleBuffer(LOAD_ERROR))
        ));
        assert_eq!(MOCK_FREE_CALLS.load(Ordering::SeqCst), 1);

        MOCK_HANDLE_BUFFER.store(core::ptr::null_mut(), Ordering::SeqCst);
        MOCK_HANDLE_COUNT.store(0, Ordering::SeqCst);
        MOCK_LOCATE_STATUS.store(SUCCESS, Ordering::SeqCst);
        MOCK_FREE_STATUS.store(SUCCESS, Ordering::SeqCst);
    }

    #[test]
    fn recovery_header_probe_opens_reads_validates_erases_and_closes_atomically() {
        let _guard = MockFirmwareGuard::acquire();
        let mut media = valid_block_media();
        media.media_id = 7;
        media.block_size = 512;
        media.last_block = 63;
        let mut protocol = block_protocol(&mut media);
        protocol.read_blocks = recovery_block_read;
        let mut path = canonical_sata_device_path();
        let volume = VolumeId::new([0x51; 16]).unwrap();
        let header = VolumeHeader::new(volume, 4096, 8, 1, 2).unwrap();
        let mut source = [0u8; UEFI_RECOVERY_BLOCK_BYTES];
        header.encode((&mut source[..VOLUME_HEADER_BYTES]).try_into().unwrap());

        MOCK_BLOCK_PROTOCOL.store(
            (&mut protocol as *mut BlockIoProtocol).cast(),
            Ordering::SeqCst,
        );
        MOCK_DEVICE_PATH.store(path.as_mut_ptr().cast(), Ordering::SeqCst);
        MOCK_CLOSE_STATUS.store(SUCCESS, Ordering::SeqCst);
        MOCK_CLOSE_CALLS.store(0, Ordering::SeqCst);
        RECOVERY_READ_MEDIA.store(7, Ordering::SeqCst);
        RECOVERY_READ_LBA.store(0, Ordering::SeqCst);
        RECOVERY_READ_STATUS.store(SUCCESS, Ordering::SeqCst);
        RECOVERY_MUTATE_MEDIA.store(core::ptr::null_mut(), Ordering::SeqCst);
        RECOVERY_READ_SOURCE.store(source.as_mut_ptr(), Ordering::SeqCst);

        let services = mock_boot_services();
        let image = core::ptr::without_provenance_mut::<c_void>(1);
        let device = core::ptr::without_provenance_mut::<c_void>(2);
        let mut path_scratch = [0u8; MAX_UEFI_DEVICE_PATH_BYTES];
        let mut block = UefiRecoveryBlock::new();
        let candidate = unsafe {
            probe_uefi_recovery_header(
                &services,
                image,
                device,
                BlockDeviceId::new(9).unwrap(),
                &mut path_scratch,
                &mut block,
            )
        }
        .unwrap();
        assert_eq!(candidate.handle(), device);
        assert_eq!(candidate.header(), header);
        assert_eq!(candidate.media().media_id(), 7);
        assert_eq!(candidate.descriptor().block().block_size(), 4096);
        assert_eq!(candidate.descriptor().block().block_count(), 8);
        let route = candidate.sata_route().unwrap();
        assert_eq!(route.root_uid(), 7);
        assert_eq!(route.pci_hops()[0].device(), 5);
        assert_eq!(route.hba_port(), 3);
        let retained = UefiRecoveredInstalledIdentity {
            descriptor: candidate.descriptor(),
            volume,
            root_block: 1,
            root_generation: 2,
            sata_route: candidate.sata_route(),
        };
        let handoff_route = retained.sata_handoff_route().unwrap().unwrap();
        assert_eq!(handoff_route.root_uid(), 7);
        assert_eq!(handoff_route.pci_hops()[0].device(), 5);
        assert_eq!(
            handoff_route.stable_id(),
            candidate.descriptor().identity().stable_id()
        );
        assert!(block.as_slice().iter().all(|byte| *byte == 0));
        assert_eq!(MOCK_CLOSE_CALLS.load(Ordering::SeqCst), 2);

        source[..VOLUME_HEADER_BYTES].fill(0);
        MOCK_CLOSE_CALLS.store(0, Ordering::SeqCst);
        assert!(matches!(
            unsafe {
                probe_uefi_recovery_header(
                    &services,
                    image,
                    device,
                    BlockDeviceId::new(9).unwrap(),
                    &mut path_scratch,
                    &mut block,
                )
            },
            Err(UefiBlockDescriptorError::InvalidVolumeHeader)
        ));
        assert!(block.as_slice().iter().all(|byte| *byte == 0));
        assert_eq!(MOCK_CLOSE_CALLS.load(Ordering::SeqCst), 2);

        RECOVERY_READ_SOURCE.store(core::ptr::null_mut(), Ordering::SeqCst);
        MOCK_BLOCK_PROTOCOL.store(core::ptr::null_mut(), Ordering::SeqCst);
        MOCK_DEVICE_PATH.store(core::ptr::null_mut(), Ordering::SeqCst);
    }

    #[test]
    fn recovery_volume_selection_is_complete_unique_and_order_independent() {
        let first = core::ptr::without_provenance_mut::<c_void>(1);
        let second = core::ptr::without_provenance_mut::<c_void>(2);
        let expected = VolumeId::new([0x51; 16]).unwrap();
        let other = VolumeId::new([0x62; 16]).unwrap();
        let handles = UefiBlockHandleSet {
            handles: [first, second],
            count: 2,
        };
        let selected = select_uefi_recovery_volume_with(&handles, expected, |handle, id| {
            if handle == first {
                Ok(scan_candidate(handle, id, other, 1))
            } else {
                Ok(scan_candidate(handle, id, expected, 2))
            }
        })
        .unwrap();
        assert_eq!(selected.handle(), second);
        let stable_id = selected.descriptor().identity().stable_id();

        let reversed = UefiBlockHandleSet {
            handles: [second, first],
            count: 2,
        };
        let reordered = select_uefi_recovery_volume_with(&reversed, expected, |handle, id| {
            if handle == first {
                Ok(scan_candidate(handle, id, other, 1))
            } else {
                Ok(scan_candidate(handle, id, expected, 2))
            }
        })
        .unwrap();
        assert_eq!(reordered.handle(), second);
        assert_eq!(reordered.descriptor().identity().stable_id(), stable_id);

        assert_eq!(
            select_uefi_recovery_volume_with(&handles, expected, |_, _| {
                Err(UefiBlockDescriptorError::InvalidVolumeHeader)
            }),
            Err(UefiRecoveryVolumeScanError::ExpectedVolumeMissing)
        );
        assert_eq!(
            select_uefi_recovery_volume_with(&handles, expected, |handle, id| {
                Ok(scan_candidate(handle, id, expected, id.get() as u8))
            }),
            Err(UefiRecoveryVolumeScanError::ExpectedVolumeAmbiguous)
        );
        assert_eq!(
            select_uefi_recovery_volume_with(&handles, expected, |handle, id| {
                Ok(scan_candidate(handle, id, other, 7))
            }),
            Err(UefiRecoveryVolumeScanError::DuplicatePlatformIdentity)
        );
        assert_eq!(
            select_uefi_recovery_volume_with(&handles, expected, |_, _| {
                Err(UefiBlockDescriptorError::CloseProtocol(LOAD_ERROR))
            }),
            Err(UefiRecoveryVolumeScanError::Probe(
                UefiBlockDescriptorError::CloseProtocol(LOAD_ERROR)
            ))
        );
        assert_eq!(
            select_uefi_recovery_volume_with(&handles, expected, |handle, id| {
                let wrong_handle = if handle == first { second } else { first };
                Ok(scan_candidate(wrong_handle, id, expected, 9))
            }),
            Err(UefiRecoveryVolumeScanError::CandidateSubstitution)
        );
    }

    #[test]
    fn selected_recovery_roots_require_exact_reopen_header_and_complete_close() {
        let _guard = MockFirmwareGuard::acquire();
        let mut media = valid_block_media();
        media.media_id = 7;
        media.block_size = 512;
        media.last_block = 63;
        let mut protocol = block_protocol(&mut media);
        protocol.read_blocks = recovery_root_read;
        let mut path = [1u8, 1, 8, 0, 0xaa, 0xbb, 0xcc, 0xdd, 0x7f, 0xff, 4, 0];
        let header = VolumeHeader::new(VolumeId::new([0x51; 16]).unwrap(), 4096, 8, 1, 2).unwrap();
        let mut header_source = [0u8; UEFI_RECOVERY_BLOCK_BYTES];
        header.encode(
            (&mut header_source[..VOLUME_HEADER_BYTES])
                .try_into()
                .unwrap(),
        );
        let mut primary_source = [0x31u8; UEFI_RECOVERY_BLOCK_BYTES];
        let mut secondary_source = [0x32u8; UEFI_RECOVERY_BLOCK_BYTES];
        ROOT_HEADER_SOURCE.store(header_source.as_mut_ptr(), Ordering::SeqCst);
        ROOT_PRIMARY_SOURCE.store(primary_source.as_mut_ptr(), Ordering::SeqCst);
        ROOT_SECONDARY_SOURCE.store(secondary_source.as_mut_ptr(), Ordering::SeqCst);
        ROOT_FAIL_LBA.store(usize::MAX, Ordering::SeqCst);
        MOCK_BLOCK_PROTOCOL.store(
            (&mut protocol as *mut BlockIoProtocol).cast(),
            Ordering::SeqCst,
        );
        MOCK_DEVICE_PATH.store(path.as_mut_ptr().cast(), Ordering::SeqCst);
        MOCK_CLOSE_STATUS.store(SUCCESS, Ordering::SeqCst);
        MOCK_CLOSE_CALLS.store(0, Ordering::SeqCst);
        let services = mock_boot_services();
        let image = core::ptr::without_provenance_mut::<c_void>(1);
        let device = core::ptr::without_provenance_mut::<c_void>(2);
        let mut path_scratch = [0u8; MAX_UEFI_DEVICE_PATH_BYTES];
        let mut primary = UefiRecoveryBlock::new();
        let mut secondary = UefiRecoveryBlock::new();
        let selected = unsafe {
            probe_uefi_recovery_header(
                &services,
                image,
                device,
                BlockDeviceId::new(1).unwrap(),
                &mut path_scratch,
                &mut primary,
            )
        }
        .unwrap();

        MOCK_CLOSE_CALLS.store(0, Ordering::SeqCst);
        assert_eq!(
            unsafe {
                read_selected_uefi_recovery_roots(
                    &services,
                    image,
                    selected,
                    &mut path_scratch,
                    &mut primary,
                    &mut secondary,
                )
            },
            Ok(())
        );
        assert_eq!(primary.as_slice(), &primary_source);
        assert_eq!(secondary.as_slice(), &secondary_source);
        assert_eq!(MOCK_CLOSE_CALLS.load(Ordering::SeqCst), 2);

        header_source[..VOLUME_HEADER_BYTES].fill(0);
        assert!(matches!(
            unsafe {
                read_selected_uefi_recovery_roots(
                    &services,
                    image,
                    selected,
                    &mut path_scratch,
                    &mut primary,
                    &mut secondary,
                )
            },
            Err(UefiBlockDescriptorError::VolumeHeaderChanged)
        ));
        assert!(primary.as_slice().iter().all(|byte| *byte == 0));
        assert!(secondary.as_slice().iter().all(|byte| *byte == 0));
        header.encode(
            (&mut header_source[..VOLUME_HEADER_BYTES])
                .try_into()
                .unwrap(),
        );

        let mut changed_path = path;
        changed_path[4] ^= 1;
        MOCK_DEVICE_PATH.store(changed_path.as_mut_ptr().cast(), Ordering::SeqCst);
        assert!(matches!(
            unsafe {
                read_selected_uefi_recovery_roots(
                    &services,
                    image,
                    selected,
                    &mut path_scratch,
                    &mut primary,
                    &mut secondary,
                )
            },
            Err(UefiBlockDescriptorError::SelectedDeviceChanged)
        ));
        MOCK_DEVICE_PATH.store(path.as_mut_ptr().cast(), Ordering::SeqCst);

        ROOT_FAIL_LBA.store(16, Ordering::SeqCst);
        assert!(matches!(
            unsafe {
                read_selected_uefi_recovery_roots(
                    &services,
                    image,
                    selected,
                    &mut path_scratch,
                    &mut primary,
                    &mut secondary,
                )
            },
            Err(UefiBlockDescriptorError::ReadBlock(LOAD_ERROR))
        ));
        assert!(primary.as_slice().iter().all(|byte| *byte == 0));
        assert!(secondary.as_slice().iter().all(|byte| *byte == 0));

        ROOT_FAIL_LBA.store(usize::MAX, Ordering::SeqCst);
        MOCK_CLOSE_STATUS.store(LOAD_ERROR, Ordering::SeqCst);
        assert!(matches!(
            unsafe {
                read_selected_uefi_recovery_roots(
                    &services,
                    image,
                    selected,
                    &mut path_scratch,
                    &mut primary,
                    &mut secondary,
                )
            },
            Err(UefiBlockDescriptorError::CloseProtocol(LOAD_ERROR))
        ));
        assert!(primary.as_slice().iter().all(|byte| *byte == 0));
        assert!(secondary.as_slice().iter().all(|byte| *byte == 0));

        MOCK_CLOSE_STATUS.store(SUCCESS, Ordering::SeqCst);
        MOCK_BLOCK_PROTOCOL.store(core::ptr::null_mut(), Ordering::SeqCst);
        MOCK_DEVICE_PATH.store(core::ptr::null_mut(), Ordering::SeqCst);
        ROOT_HEADER_SOURCE.store(core::ptr::null_mut(), Ordering::SeqCst);
        ROOT_PRIMARY_SOURCE.store(core::ptr::null_mut(), Ordering::SeqCst);
        ROOT_SECONDARY_SOURCE.store(core::ptr::null_mut(), Ordering::SeqCst);
    }

    #[test]
    fn selected_storage_adapter_is_read_only_exact_generation_and_atomic() {
        let _guard = MockFirmwareGuard::acquire();
        let mut media = valid_block_media();
        media.media_id = 7;
        media.block_size = 512;
        media.last_block = 63;
        let mut protocol = block_protocol(&mut media);
        protocol.read_blocks = recovery_root_read;
        let mut path = [1u8, 1, 8, 0, 0xaa, 0xbb, 0xcc, 0xdd, 0x7f, 0xff, 4, 0];
        let header = VolumeHeader::new(VolumeId::new([0x51; 16]).unwrap(), 4096, 8, 1, 2).unwrap();
        let mut header_source = [0u8; UEFI_RECOVERY_BLOCK_BYTES];
        header.encode(
            (&mut header_source[..VOLUME_HEADER_BYTES])
                .try_into()
                .unwrap(),
        );
        let mut primary_source = [0x31u8; UEFI_RECOVERY_BLOCK_BYTES];
        let mut secondary_source = [0x32u8; UEFI_RECOVERY_BLOCK_BYTES];
        ROOT_HEADER_SOURCE.store(header_source.as_mut_ptr(), Ordering::SeqCst);
        ROOT_PRIMARY_SOURCE.store(primary_source.as_mut_ptr(), Ordering::SeqCst);
        ROOT_SECONDARY_SOURCE.store(secondary_source.as_mut_ptr(), Ordering::SeqCst);
        ROOT_FAIL_LBA.store(usize::MAX, Ordering::SeqCst);
        MOCK_BLOCK_PROTOCOL.store(
            (&mut protocol as *mut BlockIoProtocol).cast(),
            Ordering::SeqCst,
        );
        MOCK_DEVICE_PATH.store(path.as_mut_ptr().cast(), Ordering::SeqCst);
        MOCK_CLOSE_STATUS.store(SUCCESS, Ordering::SeqCst);
        let services = mock_boot_services();
        let image = core::ptr::without_provenance_mut::<c_void>(1);
        let handle = core::ptr::without_provenance_mut::<c_void>(2);
        let mut path_scratch = [0u8; MAX_UEFI_DEVICE_PATH_BYTES];
        let mut block = UefiRecoveryBlock::new();
        let selected = unsafe {
            probe_uefi_recovery_header(
                &services,
                image,
                handle,
                BlockDeviceId::new(1).unwrap(),
                &mut path_scratch,
                &mut block,
            )
        }
        .unwrap();

        let (read, output, write, flush, replace) = unsafe {
            with_selected_uefi_storage_device(
                &services,
                image,
                selected,
                &mut path_scratch,
                |mut device| {
                    let mut output = [0u8; UEFI_RECOVERY_BLOCK_BYTES * 2];
                    let read = device.read_blocks(1, &mut output);
                    let write = device.write_blocks(1, &[0; UEFI_RECOVERY_BLOCK_BYTES]);
                    let flush = device.flush();
                    let replace = device.replace_superblock(1, &[0; SUPERBLOCK_BYTES]);
                    (read, output, write, flush, replace)
                },
            )
        }
        .unwrap();
        assert_eq!(read, Ok(()));
        assert_eq!(&output[..UEFI_RECOVERY_BLOCK_BYTES], &primary_source);
        assert_eq!(&output[UEFI_RECOVERY_BLOCK_BYTES..], &secondary_source);
        assert_eq!(write, Err(UefiBlockDescriptorError::ReadOnlyRecoveryDevice));
        assert_eq!(flush, Err(UefiBlockDescriptorError::ReadOnlyRecoveryDevice));
        assert_eq!(
            replace,
            Err(UefiBlockDescriptorError::ReadOnlyRecoveryDevice)
        );

        ROOT_FAIL_LBA.store(16, Ordering::SeqCst);
        let (read, output) = unsafe {
            with_selected_uefi_storage_device(
                &services,
                image,
                selected,
                &mut path_scratch,
                |mut device| {
                    let mut output = [0xa5u8; UEFI_RECOVERY_BLOCK_BYTES * 2];
                    let read = device.read_blocks(1, &mut output);
                    (read, output)
                },
            )
        }
        .unwrap();
        assert_eq!(read, Err(UefiBlockDescriptorError::ReadBlock(LOAD_ERROR)));
        assert!(output.iter().all(|byte| *byte == 0));

        ROOT_FAIL_LBA.store(usize::MAX, Ordering::SeqCst);
        MOCK_CLOSE_STATUS.store(LOAD_ERROR, Ordering::SeqCst);
        assert!(matches!(
            unsafe {
                with_selected_uefi_storage_device(
                    &services,
                    image,
                    selected,
                    &mut path_scratch,
                    |_| 7u8,
                )
            },
            Err(UefiBlockDescriptorError::CloseProtocol(LOAD_ERROR))
        ));

        MOCK_CLOSE_STATUS.store(SUCCESS, Ordering::SeqCst);
        MOCK_BLOCK_PROTOCOL.store(core::ptr::null_mut(), Ordering::SeqCst);
        MOCK_DEVICE_PATH.store(core::ptr::null_mut(), Ordering::SeqCst);
        ROOT_HEADER_SOURCE.store(core::ptr::null_mut(), Ordering::SeqCst);
        ROOT_PRIMARY_SOURCE.store(core::ptr::null_mut(), Ordering::SeqCst);
        ROOT_SECONDARY_SOURCE.store(core::ptr::null_mut(), Ordering::SeqCst);
    }

    #[test]
    fn selected_uefi_device_runs_shared_reachable_graph_recovery_atomically() {
        let _guard = MockFirmwareGuard::acquire();
        const BLOCKS: usize = 7;
        let volume_id = VolumeId::new([0x71; 16]).unwrap();
        let header = VolumeHeader::new(volume_id, 4096, BLOCKS as u64, 1, 2).unwrap();
        let root = StorageObjectId::new(volume_id, 1).unwrap();
        let root_pointer = MetadataPointer::new(3, 1).unwrap();
        let entries_pointer = MetadataPointer::new(4, 1).unwrap();
        let allocation_pointer = MetadataPointer::new(5, 1).unwrap();
        let allocator_pointer = MetadataPointer::new(6, 1).unwrap();
        let candidate =
            Superblock::new(header, 5, 4, root, root_pointer, allocation_pointer).unwrap();

        let mut disk = [0u8; BLOCKS * UEFI_RECOVERY_BLOCK_BYTES];
        header.encode((&mut disk[..VOLUME_HEADER_BYTES]).try_into().unwrap());
        let mut encoded_superblock = [0u8; SUPERBLOCK_BYTES];
        candidate.encode(&mut encoded_superblock);
        disk[UEFI_RECOVERY_BLOCK_BYTES..UEFI_RECOVERY_BLOCK_BYTES + SUPERBLOCK_BYTES]
            .copy_from_slice(&encoded_superblock);
        disk[UEFI_RECOVERY_BLOCK_BYTES * 2..UEFI_RECOVERY_BLOCK_BYTES * 2 + SUPERBLOCK_BYTES]
            .copy_from_slice(&encoded_superblock);
        DirectoryMetadata::new(header, root, 2, None, 0, entries_pointer)
            .unwrap()
            .encode(
                (&mut disk[UEFI_RECOVERY_BLOCK_BYTES * 3
                    ..UEFI_RECOVERY_BLOCK_BYTES * 3 + mrml_storage::DIRECTORY_METADATA_BYTES])
                    .try_into()
                    .unwrap(),
            );
        DirectoryImage::<1>::build(header, root, 2, entries_pointer, &[])
            .unwrap()
            .encode(&mut disk[UEFI_RECOVERY_BLOCK_BYTES * 4..UEFI_RECOVERY_BLOCK_BYTES * 5])
            .unwrap();
        let records = [
            AllocationRecord::new(root, 2, 3, 1, AllocationKind::ObjectMetadata).unwrap(),
            AllocationRecord::new(root, 2, 4, 1, AllocationKind::DirectoryEntries).unwrap(),
            AllocationRecord::new(root, 5, 5, 1, AllocationKind::AllocationMetadata).unwrap(),
            AllocationRecord::new(root, 5, 6, 1, AllocationKind::ObjectIdAllocatorMetadata)
                .unwrap(),
        ];
        AllocationImage::<4>::build(header, 5, allocation_pointer, &records)
            .unwrap()
            .encode(&mut disk[UEFI_RECOVERY_BLOCK_BYTES * 5..UEFI_RECOVERY_BLOCK_BYTES * 6])
            .unwrap();
        ObjectIdAllocatorImage::build(header, 5, Some(2), allocator_pointer)
            .unwrap()
            .encode(&mut disk[UEFI_RECOVERY_BLOCK_BYTES * 6..UEFI_RECOVERY_BLOCK_BYTES * 7])
            .unwrap();

        let mut media = valid_block_media();
        media.media_id = 7;
        media.block_size = 512;
        media.last_block = (BLOCKS * 8 - 1) as u64;
        let mut protocol = block_protocol(&mut media);
        protocol.read_blocks = recovery_graph_read;
        let mut path = [1u8, 1, 8, 0, 0xaa, 0xbb, 0xcc, 0xdd, 0x7f, 0xff, 4, 0];
        GRAPH_SOURCE.store(disk.as_mut_ptr(), Ordering::SeqCst);
        GRAPH_SOURCE_BYTES.store(disk.len(), Ordering::SeqCst);
        ROOT_FAIL_LBA.store(usize::MAX, Ordering::SeqCst);
        MOCK_BLOCK_PROTOCOL.store(
            (&mut protocol as *mut BlockIoProtocol).cast(),
            Ordering::SeqCst,
        );
        MOCK_DEVICE_PATH.store(path.as_mut_ptr().cast(), Ordering::SeqCst);
        MOCK_CLOSE_STATUS.store(SUCCESS, Ordering::SeqCst);
        MOCK_CLOSE_CALLS.store(0, Ordering::SeqCst);
        let services = mock_boot_services();
        let image = core::ptr::without_provenance_mut::<c_void>(1);
        let handle = core::ptr::without_provenance_mut::<c_void>(2);
        let mut path_scratch = [0u8; MAX_UEFI_DEVICE_PATH_BYTES];
        let mut probe = UefiRecoveryBlock::new();
        let selected = unsafe {
            probe_uefi_recovery_header(
                &services,
                image,
                handle,
                BlockDeviceId::new(1).unwrap(),
                &mut path_scratch,
                &mut probe,
            )
        }
        .unwrap();
        MOCK_CLOSE_CALLS.store(0, Ordering::SeqCst);
        let mut volume_scratch = [0xa5; UEFI_RECOVERY_BLOCK_BYTES];
        let mut primary = [0xa5; UEFI_RECOVERY_BLOCK_BYTES];
        let mut secondary = [0xa5; UEFI_RECOVERY_BLOCK_BYTES];
        let mut metadata_scratch = [0xa5; UEFI_RECOVERY_BLOCK_BYTES];

        let recovered = unsafe {
            recover_selected_uefi_reachable_state::<4, 1, 1, 1>(
                &services,
                image,
                selected,
                &mut path_scratch,
                &mut volume_scratch,
                &mut primary,
                &mut secondary,
                &mut metadata_scratch,
            )
        }
        .unwrap();
        assert_eq!(recovered.selected().superblock(), candidate);
        assert_eq!(recovered.file_count(), 0);
        assert!(!recovered.selected().used_fallback());
        let identity =
            bind_recovered_uefi_installed_identity(selected, &recovered, volume_id, 5).unwrap();
        assert_eq!(identity.descriptor(), selected.descriptor());
        assert_eq!(identity.volume(), volume_id);
        assert_eq!(identity.root_block(), 1);
        assert_eq!(identity.root_generation(), 5);
        let boot_identity = identity.boot_identity().unwrap();
        assert_eq!(
            boot_identity.source(),
            mrml_kernel::InstalledRecoverySource::Uefi
        );
        assert_eq!(boot_identity.volume(), volume_id.bytes());
        assert_eq!(boot_identity.root_block(), 1);
        assert_eq!(boot_identity.root_generation(), 5);
        assert_eq!(
            mrml_kernel::InstalledRecoveryBootIdentity::decode(&boot_identity.encode()),
            Ok(boot_identity)
        );
        assert_eq!(
            bind_recovered_uefi_installed_identity(
                selected,
                &recovered,
                VolumeId::new([0x72; 16]).unwrap(),
                5,
            ),
            Err(UefiInstalledRecoveryIdentityError::VolumeMismatch)
        );
        assert_eq!(
            bind_recovered_uefi_installed_identity(selected, &recovered, volume_id, 4),
            Err(UefiInstalledRecoveryIdentityError::RootGenerationMismatch)
        );
        assert_eq!(MOCK_CLOSE_CALLS.load(Ordering::SeqCst), 2);
        assert!(volume_scratch.iter().all(|byte| *byte == 0));
        assert!(primary.iter().all(|byte| *byte == 0));
        assert!(secondary.iter().all(|byte| *byte == 0));
        assert!(metadata_scratch.iter().all(|byte| *byte == 0));

        ROOT_FAIL_LBA.store(40, Ordering::SeqCst);
        assert!(matches!(
            unsafe {
                recover_selected_uefi_reachable_state::<4, 1, 1, 1>(
                    &services,
                    image,
                    selected,
                    &mut path_scratch,
                    &mut volume_scratch,
                    &mut primary,
                    &mut secondary,
                    &mut metadata_scratch,
                )
            },
            Err(UefiReachableRecoveryError::Recovery(
                RecoveryError::Backend(BlockVolumeError::Device(
                    UefiBlockDescriptorError::ReadBlock(LOAD_ERROR)
                ))
            ))
        ));
        assert!(volume_scratch.iter().all(|byte| *byte == 0));
        assert!(primary.iter().all(|byte| *byte == 0));
        assert!(secondary.iter().all(|byte| *byte == 0));
        assert!(metadata_scratch.iter().all(|byte| *byte == 0));

        ROOT_FAIL_LBA.store(usize::MAX, Ordering::SeqCst);
        MOCK_CLOSE_STATUS.store(LOAD_ERROR, Ordering::SeqCst);
        assert!(matches!(
            unsafe {
                recover_selected_uefi_reachable_state::<4, 1, 1, 1>(
                    &services,
                    image,
                    selected,
                    &mut path_scratch,
                    &mut volume_scratch,
                    &mut primary,
                    &mut secondary,
                    &mut metadata_scratch,
                )
            },
            Err(UefiReachableRecoveryError::Firmware(
                UefiBlockDescriptorError::CloseProtocol(LOAD_ERROR)
            ))
        ));
        assert!(volume_scratch.iter().all(|byte| *byte == 0));
        assert!(primary.iter().all(|byte| *byte == 0));
        assert!(secondary.iter().all(|byte| *byte == 0));
        assert!(metadata_scratch.iter().all(|byte| *byte == 0));

        MOCK_CLOSE_STATUS.store(SUCCESS, Ordering::SeqCst);
        GRAPH_SOURCE.store(core::ptr::null_mut(), Ordering::SeqCst);
        GRAPH_SOURCE_BYTES.store(0, Ordering::SeqCst);
        MOCK_BLOCK_PROTOCOL.store(core::ptr::null_mut(), Ordering::SeqCst);
        MOCK_DEVICE_PATH.store(core::ptr::null_mut(), Ordering::SeqCst);
    }

    #[test]
    fn embedded_policy_text_is_exact_and_nonzero() {
        let mut digest = [b'0'; 128];
        digest[127] = b'f';
        assert_eq!(parse_root_digest(&digest).unwrap()[63], 15);
        assert!(parse_root_digest(&digest[..127]).is_none());
        digest[0] = b'g';
        assert!(parse_root_digest(&digest).is_none());
        assert_eq!(
            parse_nonzero_version(b"18446744073709551615"),
            Some(u64::MAX)
        );
        assert!(parse_nonzero_version(b"0").is_none());
        assert!(parse_nonzero_version(b"18446744073709551616").is_none());
    }

    #[test]
    fn selected_boot_artifact_set_is_canonical_and_ordered() {
        let encoded = encode_selected_boot_artifact_set(7, [0x11; 64], 9, [0x22; 64]).unwrap();
        assert_eq!(&encoded[..16], b"MRML-BOOTSET-v1\0");
        assert_eq!(u16::from_le_bytes(encoded[16..18].try_into().unwrap()), 192);
        assert_eq!(u16::from_le_bytes(encoded[18..20].try_into().unwrap()), 1);
        assert_eq!(u16::from_le_bytes(encoded[20..22].try_into().unwrap()), 2);
        assert!(encoded[22..32].iter().all(|byte| *byte == 0));
        assert_eq!(u16::from_le_bytes(encoded[32..34].try_into().unwrap()), 1);
        assert!(encoded[34..40].iter().all(|byte| *byte == 0));
        assert_eq!(u64::from_le_bytes(encoded[40..48].try_into().unwrap()), 7);
        assert_eq!(&encoded[48..112], &[0x11; 64]);
        assert_eq!(u16::from_le_bytes(encoded[112..114].try_into().unwrap()), 3);
        assert!(encoded[114..120].iter().all(|byte| *byte == 0));
        assert_eq!(u64::from_le_bytes(encoded[120..128].try_into().unwrap()), 9);
        assert_eq!(&encoded[128..192], &[0x22; 64]);
    }

    #[test]
    fn selected_boot_artifact_set_rejects_missing_identity() {
        assert_eq!(
            encode_selected_boot_artifact_set(0, [1; 64], 1, [2; 64]),
            Err(SelectedArtifactSetError::InvalidIdentity)
        );
        assert_eq!(
            encode_selected_boot_artifact_set(1, [0; 64], 1, [2; 64]),
            Err(SelectedArtifactSetError::InvalidIdentity)
        );
        assert_eq!(
            encode_selected_boot_artifact_set(1, [1; 64], 0, [2; 64]),
            Err(SelectedArtifactSetError::InvalidIdentity)
        );
        assert_eq!(
            encode_selected_boot_artifact_set(1, [1; 64], 1, [0; 64]),
            Err(SelectedArtifactSetError::InvalidIdentity)
        );
    }

    #[test]
    fn selected_release_set_binds_manifest_and_all_exact_same_release_artifacts() {
        let encoded = encode_selected_release_artifact_set(
            11,
            [0x33; 64],
            [[0x41; 64], [0x42; 64], [0x43; 64], [0x44; 64], [0x45; 64]],
        )
        .unwrap();
        assert_eq!(&encoded[..16], b"MRML-BOOTSET-v3\0");
        assert_eq!(u16::from_le_bytes(encoded[16..18].try_into().unwrap()), 512);
        assert_eq!(u16::from_le_bytes(encoded[18..20].try_into().unwrap()), 3);
        assert_eq!(u16::from_le_bytes(encoded[20..22].try_into().unwrap()), 6);
        for (offset, kind, digest) in core::iter::once((32, SELECTED_RELEASE_MANIFEST_KIND, 0x33))
            .chain((0..5).map(|index| (112 + index * 80, index as u16 + 1, 0x41 + index as u8)))
        {
            assert_eq!(
                u16::from_le_bytes(encoded[offset..offset + 2].try_into().unwrap()),
                kind
            );
            assert!(
                encoded[offset + 2..offset + 8]
                    .iter()
                    .all(|byte| *byte == 0)
            );
            assert_eq!(
                u64::from_le_bytes(encoded[offset + 8..offset + 16].try_into().unwrap()),
                11
            );
            assert_eq!(&encoded[offset + 16..offset + 80], &[digest; 64]);
        }
        assert_eq!(
            encode_selected_release_artifact_set(0, [1; 64], [[2; 64]; 5]),
            Err(SelectedArtifactSetError::InvalidIdentity)
        );
        let mut missing = [[2; 64]; 5];
        missing[3] = [0; 64];
        assert_eq!(
            encode_selected_release_artifact_set(1, [1; 64], missing),
            Err(SelectedArtifactSetError::InvalidIdentity)
        );
    }

    #[test]
    fn acpi_root_requires_both_checksums() {
        let mut rsdp = [0u8; 36];
        rsdp[..8].copy_from_slice(b"RSD PTR ");
        rsdp[15] = 2;
        rsdp[20..24].copy_from_slice(&36u32.to_le_bytes());
        rsdp[8] = 0u8.wrapping_sub(checksum(&rsdp[..20]));
        rsdp[32] = 0u8.wrapping_sub(checksum(&rsdp));
        let mut entry = ConfigurationTable {
            vendor_guid: ACPI_20_TABLE_GUID,
            vendor_table: rsdp.as_mut_ptr().cast(),
        };
        let system = SystemTable {
            header: TableHeader {
                signature: 0,
                revision: 0,
                header_size: 0,
                crc32: 0,
                reserved: 0,
            },
            firmware_vendor: core::ptr::null_mut(),
            firmware_revision: 0,
            console_in_handle: core::ptr::null_mut(),
            con_in: core::ptr::null_mut(),
            console_out_handle: core::ptr::null_mut(),
            con_out: core::ptr::null_mut(),
            standard_error_handle: core::ptr::null_mut(),
            std_err: core::ptr::null_mut(),
            runtime_services: core::ptr::null_mut(),
            boot_services: core::ptr::null_mut(),
            table_entry_count: 1,
            configuration_table: &mut entry,
        };
        assert_eq!(unsafe { find_acpi_root(&system) }, Ok(rsdp.as_ptr() as u64));
        let mut corrupt = rsdp;
        corrupt[35] ^= 1;
        let mut corrupt_entry = ConfigurationTable {
            vendor_guid: ACPI_20_TABLE_GUID,
            vendor_table: corrupt.as_mut_ptr().cast(),
        };
        let corrupt_system = SystemTable {
            configuration_table: &mut corrupt_entry,
            ..system
        };
        assert_eq!(
            unsafe { find_acpi_root(&corrupt_system) },
            Err(AcpiError::BadChecksum)
        );
    }

    fn descriptor(kind: u32, start: u64, pages: u64) -> [u8; 40] {
        let mut bytes = [0u8; 40];
        bytes[..4].copy_from_slice(&kind.to_le_bytes());
        bytes[8..16].copy_from_slice(&start.to_le_bytes());
        bytes[24..32].copy_from_slice(&pages.to_le_bytes());
        bytes
    }

    #[test]
    fn boot_dma_tag_carves_only_reserved_ram_and_preserves_neighbors() {
        let mut regions = [NormalizedRegion::EMPTY; MAX_NORMALIZED_REGIONS];
        regions[0] = NormalizedRegion {
            start: 0x1000,
            pages: 8,
            kind: NormalizedMemoryKind::Reserved,
        };
        regions[1] = NormalizedRegion {
            start: 0x9000,
            pages: 2,
            kind: NormalizedMemoryKind::Mmio,
        };
        assert_eq!(
            mark_boot_dma_backing(&mut regions, 2, 0x8000, 2),
            Err(BootDmaBackingError::OutsideReserved)
        );
        assert_eq!(mark_boot_dma_backing(&mut regions, 2, 0x4000, 2), Ok(4));
        assert_eq!(
            core::array::from_fn(|i| (regions[i].start, regions[i].pages, regions[i].kind)),
            [
                (0x1000, 3, NormalizedMemoryKind::Reserved),
                (0x4000, 2, NormalizedMemoryKind::BootDma),
                (0x6000, 3, NormalizedMemoryKind::Reserved),
                (0x9000, 2, NormalizedMemoryKind::Mmio)
            ]
        );
        assert_eq!(
            mark_boot_dma_backing(&mut regions, 4, 0x1000, 1),
            Err(BootDmaBackingError::ConflictingDescriptor)
        );
    }

    #[test]
    fn final_dma_map_requires_single_uncontested_loader_data_cover() {
        let mut raw = [0xa5; 3 * 48];
        raw[0..40].copy_from_slice(&descriptor(7, 0x1_0000_0000, 4));
        raw[48..88].copy_from_slice(&descriptor(2, 0xffff_c000, 4));
        raw[96..136].copy_from_slice(&descriptor(11, 0x1000, 1));
        let verify = |map: &[u8]| verify_boot_dma_backing(map, 48, 0xffff_e000, 2, 32);

        assert_eq!(verify(&raw), Ok(()));
        assert_eq!(
            verify_boot_dma_backing(&raw, 48, 0xffff_e000, 3, 32),
            Err(BootDmaBackingError::InvalidExtent)
        );
        assert_eq!(verify(&raw[..143]), Err(BootDmaBackingError::MalformedMap));
        assert_eq!(
            verify(&raw[..48]),
            Err(BootDmaBackingError::MissingLoaderData)
        );

        let mut altered = raw;
        altered[96..136].copy_from_slice(&descriptor(2, 0xffff_f000, 1));
        assert_eq!(
            verify(&altered),
            Err(BootDmaBackingError::ConflictingDescriptor)
        );
        altered[96..136].copy_from_slice(&raw[96..136]);
        for row in [
            descriptor(7, 0xffff_c000, 4),
            descriptor(4, 0xffff_c000, 4),
            descriptor(2, 0xffff_c000, 3),
        ] {
            altered[48..88].copy_from_slice(&row);
            assert_eq!(
                verify(&altered),
                Err(BootDmaBackingError::ConflictingDescriptor)
            );
        }
        altered[48..88].copy_from_slice(&raw[48..88]);
        altered[80..88].copy_from_slice(&(1u64 << 63).to_le_bytes());
        assert_eq!(
            verify(&altered),
            Err(BootDmaBackingError::ConflictingDescriptor)
        );
    }

    #[test]
    fn final_dma_map_rejects_bad_range_and_overflowing_descriptors() {
        let raw = descriptor(2, 0x1000, 256);
        for (start, pages, bits) in [
            (0, 1, 32),
            (0x1001, 1, 32),
            (0x1000, 0, 32),
            (0x1000, 257, 32),
            (0x1000, 1, 31),
            (0x1000, 1, 53),
            (u64::MAX - 4095, 1, 52),
        ] {
            assert_eq!(
                verify_boot_dma_backing(&raw, 40, start, pages, bits),
                Err(BootDmaBackingError::InvalidExtent)
            );
        }
        assert_eq!(verify_boot_dma_backing(&raw, 40, 0x1000, 256, 32), Ok(()));
        assert_eq!(
            verify_boot_dma_backing(&descriptor(2, 0x1000, u64::MAX), 40, 0x1000, 1, 32),
            Err(BootDmaBackingError::MalformedMap)
        );
    }

    #[test]
    fn boot_report_bounds_rows_and_omits_descriptor_padding() {
        let mut map = [0; 200 * 48];
        for row in map.chunks_exact_mut(48) {
            row[..40].copy_from_slice(&descriptor(7, 0x1000, 2));
            row[40..].copy_from_slice(b"SECRET!!");
        }
        let mut report = [0xff; BOOT_REPORT_BYTES];
        encode_boot_report(
            &mut report,
            "test stage",
            Some(LOAD_ERROR),
            Ok((&map, 48, 1)),
        )
        .unwrap();
        let text = core::str::from_utf8(&report).unwrap();
        assert!(text.starts_with("MRML BOOT LOG V1\r\nStage: test stage"));
        assert!(text.contains("pre-exit failure"));
        assert!(text.contains("entries=200 stride=48 version=1"));
        assert_eq!(text.matches("00000007 0000000000001000").count(), 192);
        assert!(text.contains("Map truncated"));
        assert!(!text.contains("SECRET"));
        assert!(text.trim_end().ends_with("END MRML BOOT LOG"));
        encode_boot_report(&mut report, "new stage", None, Ok((&map, 0, 1))).unwrap();
        let text = core::str::from_utf8(&report).unwrap();
        assert!(text.contains("invalid returned geometry"));
        assert!(!text.contains("test stage"));
        assert!(!text.contains("00000007"));
    }

    #[test]
    fn sorts_firmware_order_before_merging_and_rejects_overlaps() {
        // Firmware may list high available RAM before low reserved ranges.
        let high = descriptor(7, 0x1_0000_0000, 2);
        let low = descriptor(0, 0, 1);
        let mmio = descriptor(11, 0xa0000, 4);
        let middle = descriptor(7, 0x1000, 2);
        let padded = |descriptors: [[u8; 40]; 4]| {
            let mut bytes = [0xa5; 192];
            for (slot, source) in bytes.chunks_exact_mut(48).zip(descriptors) {
                slot[..40].copy_from_slice(&source);
            }
            bytes
        };
        let mut output = [NormalizedRegion::EMPTY; MAX_NORMALIZED_REGIONS];
        let mut expected = output;
        assert_eq!(
            normalize_memory_map(
                &padded([low, middle, mmio, high]),
                48,
                0xa0000,
                4096,
                &mut expected
            ),
            Ok(4)
        );
        assert_eq!(
            normalize_memory_map(
                &padded([middle, high, low, mmio]),
                48,
                0xa0000,
                4096,
                &mut output
            ),
            Ok(4)
        );
        assert_eq!(output, expected);
        let overlap = descriptor(7, 0, 2);
        assert_eq!(
            normalize_memory_map(
                &padded([middle, high, overlap, mmio]),
                48,
                0xa0000,
                4096,
                &mut output
            ),
            Err(NormalizeError::Overlap)
        );
        assert_eq!(
            normalize_memory_map(
                &padded([middle, high, low, low]),
                48,
                0xa0000,
                4096,
                &mut output
            ),
            Err(NormalizeError::Overlap)
        );
    }

    #[test]
    fn normalizes_merges_and_requires_mmio_framebuffer() {
        let descriptors = [
            descriptor(7, 0x1000, 2),
            descriptor(7, 0x3000, 1),
            descriptor(11, 0xa0000, 4),
        ];
        let mut bytes = [0u8; 120];
        for (index, descriptor) in descriptors.iter().enumerate() {
            bytes[index * 40..index * 40 + 40].copy_from_slice(descriptor);
        }
        let mut output = [NormalizedRegion::EMPTY; MAX_NORMALIZED_REGIONS];
        assert_eq!(
            normalize_memory_map(&bytes, 40, 0xa0000, 4096, &mut output),
            Ok(2)
        );
        assert_eq!(output[0].pages, 3);
        assert_eq!(output[0].kind, NormalizedMemoryKind::Free);
        assert_eq!(output[1].kind, NormalizedMemoryKind::Mmio);

        let mut output = [NormalizedRegion::EMPTY; MAX_NORMALIZED_REGIONS];
        assert_eq!(
            normalize_memory_map(&bytes, 40, 0xb0000, 4096, &mut output),
            Ok(3)
        );
        assert_eq!(output[2].start, 0xb0000);
        assert_eq!(output[2].kind, NormalizedMemoryKind::Mmio);
    }
}
