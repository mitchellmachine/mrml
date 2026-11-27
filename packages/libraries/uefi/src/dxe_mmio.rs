//! Read-only boot-time PI Global Coherency Domain resource classification.

use crate::{ConfigurationTable, Guid, Handle, PAGE_SIZE, Status, SystemTable};

const DXE_GUID: Guid = Guid {
    data1: 0x05ad_34ba,
    data2: 0x6f02,
    data3: 0x4214,
    data4: [0x95, 0x2e, 0x4d, 0xa0, 0x39, 0x8e, 0x2b, 0xb9],
};
const DXE_SIGNATURE: u64 = 0x5652_4553_5f45_5844;
const HEADER_BYTES: usize = 24;
const QUERY_OFFSET: usize = HEADER_BYTES + 4 * 8;
const MIN_TABLE_BYTES: usize = QUERY_OFFSET + 8;
const MAX_TABLE_BYTES: usize = 4096;
const MAX_SEGMENTS: usize = 16;
const TYPE_MMIO: u32 = 3;
const UNCACHEABLE: u64 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct Descriptor {
    base: u64,
    bytes: u64,
    capabilities: u64,
    attributes: u64,
    kind: u32,
    image_handle: Handle,
    device_handle: Handle,
}

type Query = unsafe extern "efiapi" fn(u64, *mut Descriptor) -> Status;

const _: () = {
    assert!(core::mem::size_of::<Descriptor>() == 56);
    assert!(core::mem::offset_of!(Descriptor, image_handle) == 40);
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DxeMmioError {
    Unavailable,
    MalformedTable,
    InvalidRange,
    QueryFailed,
    InvalidDescriptor,
    NotUncacheableMmio,
    Fragmented,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DxeAccess {
    Table,
    Entrypoint,
}

/// Observe positive firmware classification over an exact page range. This is
/// not device ownership, final memory map validation, or permission to map it.
///
/// # Safety
/// Call only while UEFI boot services and DXE services are live. The system
/// configuration entries and selected firmware table must be readable for the
/// declared nonexcessive lengths; the firmware must implement the PI ABI and
/// supply a valid query entrypoint. No returned firmware pointers are retained.
pub unsafe fn inspect_dxe_mmio(
    system: &SystemTable,
    base: u64,
    bytes: u64,
    contains: impl Fn(DxeAccess, usize, usize) -> bool,
) -> Result<(), DxeMmioError> {
    if system.table_entry_count == 0 {
        return Err(DxeMmioError::Unavailable);
    }
    if system.table_entry_count > 1024
        || system.configuration_table.is_null()
        || !system.configuration_table.is_aligned()
    {
        return Err(DxeMmioError::MalformedTable);
    }
    // SAFETY: the caller supplies the live configuration array; its size and
    // alignment were bounded above, and zero entries do not form a slice.
    let entries: &[ConfigurationTable] = unsafe {
        core::slice::from_raw_parts(system.configuration_table, system.table_entry_count)
    };
    let mut matches = entries
        .iter()
        .filter(|entry| entry.vendor_guid.equals(&DXE_GUID));
    let entry = matches.next().ok_or(DxeMmioError::Unavailable)?;
    if matches.next().is_some() || entry.vendor_table.is_null() {
        return Err(DxeMmioError::MalformedTable);
    }
    let ptr = entry.vendor_table.cast::<u8>();
    if !contains(DxeAccess::Table, ptr.addr(), HEADER_BYTES) {
        return Err(DxeMmioError::MalformedTable);
    }
    // SAFETY: caller guarantees the table mapping, and the observed
    // firmware map covers the complete header.
    let header = unsafe { core::slice::from_raw_parts(ptr, HEADER_BYTES) };
    let length = table_length(header)?;
    if !contains(DxeAccess::Table, ptr.addr(), length) {
        return Err(DxeMmioError::MalformedTable);
    }
    // SAFETY: the caller guarantees bounded declared firmware bytes are
    // readable and initialized for the duration of the call.
    let table = unsafe { core::slice::from_raw_parts(ptr, length) };
    let address = query_address(table)?;
    if !contains(DxeAccess::Entrypoint, address, 1) {
        return Err(DxeMmioError::MalformedTable);
    }
    // SAFETY: the validated PI table supplies the nonnull EFIAPI function at
    // this slot; its validity while boot services are live is a caller condition.
    let query: Query = unsafe { core::mem::transmute(address) };
    exact_mmio(base, bytes, |cursor| {
        let mut descriptor = Descriptor {
            base: 0,
            bytes: 0,
            capabilities: 0,
            attributes: 0,
            kind: 0,
            image_handle: core::ptr::null_mut(),
            device_handle: core::ptr::null_mut(),
        };
        // SAFETY: the function and scratch output obey the PI ABI. We never
        // dereference handles published in the resulting descriptor.
        if unsafe { query(cursor, &mut descriptor) } != 0 {
            return Err(DxeMmioError::QueryFailed);
        }
        Ok(descriptor)
    })
}

fn table_length(header: &[u8]) -> Result<usize, DxeMmioError> {
    if header.len() < HEADER_BYTES
        || u64::from_le_bytes(header[..8].try_into().unwrap()) != DXE_SIGNATURE
        || u32::from_le_bytes(header[8..12].try_into().unwrap()) >> 16 == 0
        || header[20..24] != [0; 4]
    {
        return Err(DxeMmioError::MalformedTable);
    }
    let size = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;
    if !(MIN_TABLE_BYTES..=MAX_TABLE_BYTES).contains(&size) {
        return Err(DxeMmioError::MalformedTable);
    }
    Ok(size)
}

fn table_crc(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for (offset, byte) in bytes.iter().enumerate() {
        crc ^= u32::from(if (16..20).contains(&offset) { 0 } else { *byte });
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn query_address(table: &[u8]) -> Result<usize, DxeMmioError> {
    if table_length(table)? != table.len()
        || u32::from_le_bytes(table[16..20].try_into().unwrap()) != table_crc(table)
    {
        return Err(DxeMmioError::MalformedTable);
    }
    let address = usize::from_le_bytes(table[QUERY_OFFSET..MIN_TABLE_BYTES].try_into().unwrap());
    if address == 0 {
        return Err(DxeMmioError::MalformedTable);
    }
    Ok(address)
}

fn exact_mmio(
    base: u64,
    bytes: u64,
    mut query: impl FnMut(u64) -> Result<Descriptor, DxeMmioError>,
) -> Result<(), DxeMmioError> {
    let end = base.checked_add(bytes).ok_or(DxeMmioError::InvalidRange)?;
    if base == 0 || bytes == 0 || base % PAGE_SIZE != 0 || bytes % PAGE_SIZE != 0 {
        return Err(DxeMmioError::InvalidRange);
    }
    let mut cursor = base;
    for index in 0..MAX_SEGMENTS {
        let desc = query(cursor)?;
        let next = desc
            .base
            .checked_add(desc.bytes)
            .ok_or(DxeMmioError::InvalidDescriptor)?;
        if desc.base > cursor || next <= cursor || (index != 0 && desc.base != cursor) {
            return Err(DxeMmioError::InvalidDescriptor);
        }
        if desc.kind != TYPE_MMIO || desc.capabilities & UNCACHEABLE == 0 {
            return Err(DxeMmioError::NotUncacheableMmio);
        }
        if end <= next {
            return Ok(());
        }
        cursor = next;
    }
    Err(DxeMmioError::Fragmented)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mmio(base: u64, bytes: u64) -> Descriptor {
        Descriptor {
            base,
            bytes,
            capabilities: UNCACHEABLE,
            attributes: 0,
            kind: TYPE_MMIO,
            image_handle: core::ptr::null_mut(),
            device_handle: core::ptr::null_mut(),
        }
    }

    #[test]
    fn exact_coverage_uses_adjacent_descriptors_without_allowing_gaps_or_overlap() {
        let classify = |second| {
            exact_mmio(0x2000, 0x2000, |at| {
                Ok(if at == 0x2000 {
                    mmio(0x1000, 0x2000)
                } else {
                    second
                })
            })
        };
        assert_eq!(classify(mmio(0x3000, 0x1000)), Ok(()));
        assert_eq!(
            classify(mmio(0x3001, 0x1000)),
            Err(DxeMmioError::InvalidDescriptor)
        );
        assert_eq!(
            classify(mmio(0x2fff, 0x1001)),
            Err(DxeMmioError::InvalidDescriptor)
        );
        assert_eq!(
            classify(mmio(0x3000, 0)),
            Err(DxeMmioError::InvalidDescriptor)
        );
        assert_eq!(
            classify(mmio(0x3000, u64::MAX)),
            Err(DxeMmioError::InvalidDescriptor)
        );
    }

    #[test]
    fn rejects_reserved_ram_unknown_types_missing_uc_and_excess_fragments() {
        for kind in [0, 1, 2, 4, 5, 6, u32::MAX] {
            assert_eq!(
                exact_mmio(0x2000, PAGE_SIZE, |at| Ok(Descriptor {
                    kind,
                    ..mmio(at, PAGE_SIZE)
                })),
                Err(DxeMmioError::NotUncacheableMmio)
            );
        }
        assert_eq!(
            exact_mmio(0x2000, PAGE_SIZE, |at| Ok(Descriptor {
                capabilities: 0,
                ..mmio(at, PAGE_SIZE)
            })),
            Err(DxeMmioError::NotUncacheableMmio)
        );
        assert_eq!(
            exact_mmio(0x2000, PAGE_SIZE * 17, |at| Ok(mmio(at, PAGE_SIZE))),
            Err(DxeMmioError::Fragmented)
        );
        assert_eq!(
            exact_mmio(0x2001, PAGE_SIZE, |_| panic!(
                "unaligned range reached query"
            )),
            Err(DxeMmioError::InvalidRange)
        );
    }

    #[test]
    fn table_requires_bounded_header_crc_and_nonnull_slot() {
        assert_eq!(table_crc(b"123456789"), 0xcbf4_3926);
        let mut raw = [0; MIN_TABLE_BYTES];
        raw[..8].copy_from_slice(&DXE_SIGNATURE.to_le_bytes());
        raw[8..12].copy_from_slice(&0x10050u32.to_le_bytes());
        raw[12..16].copy_from_slice(&(MIN_TABLE_BYTES as u32).to_le_bytes());
        let crc = table_crc(&raw);
        raw[16..20].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(query_address(&raw), Err(DxeMmioError::MalformedTable));
        raw[QUERY_OFFSET] = 1;
        let crc = table_crc(&raw);
        raw[16..20].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(query_address(&raw), Ok(1));
        assert_eq!(
            query_address(&raw[..MIN_TABLE_BYTES - 1]),
            Err(DxeMmioError::MalformedTable)
        );
        raw[QUERY_OFFSET] = 2;
        assert_eq!(query_address(&raw), Err(DxeMmioError::MalformedTable));
    }
}
