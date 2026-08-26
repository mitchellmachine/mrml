#![no_std]

pub mod tpm;

use core::ffi::c_void;
use mrml_crypto::Sha3_256;
use mrml_storage::{
    BlockDeviceDescriptor, BlockDeviceId, PlatformBlockDeviceDescriptor,
    PlatformBlockDeviceIdentity, PlatformBlockTransport,
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

pub const MAX_UEFI_DEVICE_PATH_BYTES: usize = 4096;
const DEVICE_PATH_END_TYPE: u8 = 0x7f;
const DEVICE_PATH_END_ENTIRE_SUBTYPE: u8 = 0xff;
const DEVICE_PATH_HEADER_BYTES: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UefiBlockDescriptorError {
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
    let block = BlockDeviceDescriptor::new(id, media.block_size, media.block_count)
        .ok_or(UefiBlockDescriptorError::InvalidGeometry)?;
    let mut hash = Sha3_256::new();
    hash.update(b"MRML-UEFI-BLOCK-ID-v1\0");
    hash.update(device_path);
    let stable_id = hash.finalize();
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
    pub free_pool: usize,
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
    pub open_protocol: usize,
    pub close_protocol: usize,
    pub open_protocol_information: usize,
    pub protocols_per_handle: usize,
    pub locate_handle_buffer: usize,
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
pub type FileGetInfo =
    unsafe extern "efiapi" fn(*mut FileProtocol, *const Guid, *mut usize, *mut c_void) -> Status;
#[repr(C)]
pub struct FileProtocol {
    pub revision: u64,
    pub open: FileOpen,
    pub close: FileClose,
    pub delete: usize,
    pub read: FileRead,
    pub write: usize,
    pub get_position: usize,
    pub set_position: usize,
    pub get_info: FileGetInfo,
    pub set_info: usize,
    pub flush: usize,
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

pub const MAX_NORMALIZED_REGIONS: usize = 128;
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
    Unsorted,
    Overlap,
    TooManyRegions,
    FramebufferConflict,
}

/// Converts an untrusted variable-stride UEFI map into the fixed MRML memory
/// model. Only conventional memory becomes free; boot-service and loader pages
/// remain reserved until a later kernel phase can prove they are reclaimable.
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
    let mut count = 0usize;
    let mut previous_start = 0u64;
    let mut previous_end = 0u64;
    for (index, descriptor) in bytes.chunks_exact(descriptor_size).enumerate() {
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
        if index != 0 && start < previous_start {
            return Err(NormalizeError::Unsorted);
        }
        if index != 0 && start < previous_end {
            return Err(NormalizeError::Overlap);
        }
        previous_start = start;
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
    pub query_mode: usize,
    pub set_mode: usize,
    pub blt: usize,
    pub mode: *mut GraphicsOutputMode,
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
        assert_eq!(core::mem::offset_of!(FileProtocol, get_info), 64);
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
