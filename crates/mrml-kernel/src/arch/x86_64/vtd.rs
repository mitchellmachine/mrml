use core::sync::atomic::{Ordering, compiler_fence};

use crate::{GranuleHardwareOutcome, PhysAddr};

use super::DmaIsolation;

const ECAP_OFFSET: usize = 0x10;
const CCMD_OFFSET: usize = 0x28;
const COMMAND_PENDING: u64 = 1 << 63;
const GLOBAL_GRANULARITY: u64 = 1 << 60;
const CCMD_ACTUAL_SHIFT: u32 = 59;
const IOTLB_ACTUAL_SHIFT: u32 = 57;
const ACTUAL_MASK: u64 = 0b11;
const IOTLB_DRAIN_READS: u64 = 1 << 49;
const IOTLB_DRAIN_WRITES: u64 = 1 << 48;
const IOTLB_OFFSET_DELTA: usize = 8;
const VTD_PERMISSION_MASK: u64 = 0b11;
const VTD_LARGE_PAGE: u64 = 1 << 7;
const VTD_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const DMAR_HEADER_BYTES: usize = 48;
const DRHD_HEADER_BYTES: usize = 16;
const DEVICE_SCOPE_HEADER_BYTES: usize = 6;
const MAX_PCI_PATH_DEPTH: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VtdError {
    InvalidRegisterLayout,
    InvalidLeaf,
    Busy,
    InvalidCompletion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmarError {
    Truncated,
    WrongSignature,
    InvalidLength,
    BadChecksum,
    InvalidHostAddressWidth,
    UnitTableFull,
    ScopeTableFull,
    InvalidRegisterBase,
    InvalidScope,
    PathTooDeep,
    AmbiguousUnit,
    MissingUnit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciPathElement {
    pub device: u8,
    pub function: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmarDeviceScope {
    pub scope_type: u8,
    pub enumeration_id: u8,
    pub start_bus: u8,
    pub path: [PciPathElement; MAX_PCI_PATH_DEPTH],
    pub path_len: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmarUnit {
    pub segment: u16,
    pub register_base: PhysAddr,
    pub include_all: bool,
    scope_start: u16,
    scope_len: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmarTopology<const UNITS: usize, const SCOPES: usize> {
    pub host_address_width: u8,
    pub flags: u8,
    units: [Option<DmarUnit>; UNITS],
    scopes: [Option<DmarDeviceScope>; SCOPES],
    unit_count: usize,
    scope_count: usize,
}

impl<const UNITS: usize, const SCOPES: usize> DmarTopology<UNITS, SCOPES> {
    pub fn parse(table: &[u8]) -> Result<Self, DmarError> {
        if table.len() < DMAR_HEADER_BYTES {
            return Err(DmarError::Truncated);
        }
        if &table[..4] != b"DMAR" {
            return Err(DmarError::WrongSignature);
        }
        let length = read_u32(table, 4)? as usize;
        if length != table.len() || length < DMAR_HEADER_BYTES {
            return Err(DmarError::InvalidLength);
        }
        if table.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0 {
            return Err(DmarError::BadChecksum);
        }
        let host_address_width = table[36]
            .checked_add(1)
            .ok_or(DmarError::InvalidHostAddressWidth)?;
        if !(32..=52).contains(&host_address_width) {
            return Err(DmarError::InvalidHostAddressWidth);
        }
        let mut topology = Self {
            host_address_width,
            flags: table[37],
            units: [None; UNITS],
            scopes: [None; SCOPES],
            unit_count: 0,
            scope_count: 0,
        };
        let mut offset = DMAR_HEADER_BYTES;
        while offset < length {
            let header_end = offset.checked_add(4).ok_or(DmarError::InvalidLength)?;
            if header_end > length {
                return Err(DmarError::Truncated);
            }
            let structure_type = read_u16(table, offset)?;
            let structure_len = read_u16(table, offset + 2)? as usize;
            if structure_len < 4 {
                return Err(DmarError::InvalidLength);
            }
            let end = offset
                .checked_add(structure_len)
                .ok_or(DmarError::InvalidLength)?;
            if end > length {
                return Err(DmarError::Truncated);
            }
            if structure_type == 0 {
                topology.parse_drhd(&table[offset..end])?;
            }
            offset = end;
        }
        if topology.unit_count == 0 {
            return Err(DmarError::MissingUnit);
        }
        Ok(topology)
    }

    pub fn units(&self) -> impl Iterator<Item = &DmarUnit> {
        self.units[..self.unit_count].iter().flatten()
    }

    pub fn scopes(&self, unit: &DmarUnit) -> impl Iterator<Item = &DmarDeviceScope> {
        let start = unit.scope_start as usize;
        let end = start + unit.scope_len as usize;
        self.scopes[start..end].iter().flatten()
    }

    fn parse_drhd(&mut self, bytes: &[u8]) -> Result<(), DmarError> {
        if bytes.len() < DRHD_HEADER_BYTES {
            return Err(DmarError::Truncated);
        }
        if self.unit_count == UNITS {
            return Err(DmarError::UnitTableFull);
        }
        let include_all = bytes[4] & 1 != 0;
        if bytes[4] & !1 != 0 || bytes[5] != 0 {
            return Err(DmarError::InvalidLength);
        }
        let segment = read_u16(bytes, 6)?;
        let register = read_u64(bytes, 8)?;
        let register_base = PhysAddr::new(register).map_err(|_| DmarError::InvalidRegisterBase)?;
        if register == 0 || !register.is_multiple_of(4096) {
            return Err(DmarError::InvalidRegisterBase);
        }
        if self.units().any(|unit| {
            unit.register_base == register_base
                || (include_all && unit.include_all && unit.segment == segment)
        }) {
            return Err(DmarError::AmbiguousUnit);
        }
        let scope_start = self.scope_count;
        let mut offset = DRHD_HEADER_BYTES;
        while offset < bytes.len() {
            if offset + 2 > bytes.len() {
                return Err(DmarError::Truncated);
            }
            let scope_len = bytes[offset + 1] as usize;
            if scope_len < DEVICE_SCOPE_HEADER_BYTES + 2 || !scope_len.is_multiple_of(2) {
                return Err(DmarError::InvalidScope);
            }
            let end = offset
                .checked_add(scope_len)
                .ok_or(DmarError::InvalidLength)?;
            if end > bytes.len() {
                return Err(DmarError::Truncated);
            }
            let scope = parse_scope(&bytes[offset..end])?;
            if self.scope_count == SCOPES {
                return Err(DmarError::ScopeTableFull);
            }
            let duplicates_prior_unit = self.units().any(|unit| {
                unit.segment == segment
                    && self
                        .scopes(unit)
                        .any(|existing| same_pci_route(existing, &scope))
            });
            let duplicates_this_unit = self.scopes[scope_start..self.scope_count]
                .iter()
                .flatten()
                .any(|existing| same_pci_route(existing, &scope));
            if duplicates_prior_unit || duplicates_this_unit {
                return Err(DmarError::AmbiguousUnit);
            }
            self.scopes[self.scope_count] = Some(scope);
            self.scope_count += 1;
            offset = end;
        }
        self.units[self.unit_count] = Some(DmarUnit {
            segment,
            register_base,
            include_all,
            scope_start: u16::try_from(scope_start).map_err(|_| DmarError::ScopeTableFull)?,
            scope_len: u16::try_from(self.scope_count - scope_start)
                .map_err(|_| DmarError::ScopeTableFull)?,
        });
        self.unit_count += 1;
        Ok(())
    }
}

fn same_pci_route(left: &DmarDeviceScope, right: &DmarDeviceScope) -> bool {
    left.start_bus == right.start_bus
        && left.path_len == right.path_len
        && left.path[..left.path_len as usize] == right.path[..right.path_len as usize]
}

fn parse_scope(bytes: &[u8]) -> Result<DmarDeviceScope, DmarError> {
    if !(1..=5).contains(&bytes[0]) || bytes[2] != 0 || bytes[3] != 0 {
        return Err(DmarError::InvalidScope);
    }
    let path_len = (bytes.len() - DEVICE_SCOPE_HEADER_BYTES) / 2;
    if path_len == 0 || path_len > MAX_PCI_PATH_DEPTH {
        return Err(if path_len == 0 {
            DmarError::InvalidScope
        } else {
            DmarError::PathTooDeep
        });
    }
    let mut path = [PciPathElement {
        device: 0,
        function: 0,
    }; MAX_PCI_PATH_DEPTH];
    for (index, pair) in bytes[DEVICE_SCOPE_HEADER_BYTES..]
        .as_chunks::<2>()
        .0
        .iter()
        .enumerate()
    {
        if pair[0] > 31 || pair[1] > 7 {
            return Err(DmarError::InvalidScope);
        }
        path[index] = PciPathElement {
            device: pair[0],
            function: pair[1],
        };
    }
    Ok(DmarDeviceScope {
        scope_type: bytes[0],
        enumeration_id: bytes[4],
        start_bus: bytes[5],
        path,
        path_len: path_len as u8,
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, DmarError> {
    let source = bytes.get(offset..offset + 2).ok_or(DmarError::Truncated)?;
    Ok(u16::from_le_bytes([source[0], source[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, DmarError> {
    let source = bytes.get(offset..offset + 4).ok_or(DmarError::Truncated)?;
    Ok(u32::from_le_bytes(source.try_into().unwrap()))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, DmarError> {
    let source = bytes.get(offset..offset + 8).ok_or(DmarError::Truncated)?;
    Ok(u64::from_le_bytes(source.try_into().unwrap()))
}

/// Narrow register boundary for one VT-d remapping hardware unit.
pub trait VtdRegisterIo {
    fn read64(&mut self, offset: usize) -> u64;
    fn write64(&mut self, offset: usize, value: u64);
}

/// Direct volatile MMIO register access for a mapped VT-d register page.
pub struct NativeVtdMmio {
    base: *mut u8,
    bytes: usize,
}

impl NativeVtdMmio {
    /// # Safety
    ///
    /// `base..base + bytes` must be a uniquely controlled, uncached kernel
    /// mapping of one enabled VT-d remapping unit for this object's lifetime.
    pub unsafe fn new(base: *mut u8, bytes: usize) -> Result<Self, VtdError> {
        if base.is_null() || bytes < 0x30 || !(base as usize).is_multiple_of(8) {
            return Err(VtdError::InvalidRegisterLayout);
        }
        Ok(Self { base, bytes })
    }
}

impl VtdRegisterIo for NativeVtdMmio {
    fn read64(&mut self, offset: usize) -> u64 {
        if offset > self.bytes.saturating_sub(8) || !offset.is_multiple_of(8) {
            return u64::MAX;
        }
        // SAFETY: construction establishes the mapped MMIO range; the bounds
        // and alignment checks above constrain this 64-bit register access.
        unsafe { self.base.add(offset).cast::<u64>().read_volatile() }
    }

    fn write64(&mut self, offset: usize, value: u64) {
        if offset > self.bytes.saturating_sub(8) || !offset.is_multiple_of(8) {
            return;
        }
        // SAFETY: same mapped-range invariant as `read64`.
        unsafe { self.base.add(offset).cast::<u64>().write_volatile(value) };
    }
}

/// Register-based global context-cache and IOTLB invalidation.
pub struct VtdInvalidator<R> {
    registers: R,
    iotlb_offset: usize,
    poll_limit: u32,
}

impl<R: VtdRegisterIo> VtdInvalidator<R> {
    pub fn new(mut registers: R, poll_limit: u32) -> Result<Self, VtdError> {
        let ecap = registers.read64(ECAP_OFFSET);
        let invalidation_base = ((ecap >> 8) & 0x3ff) as usize * 16;
        let iotlb_offset = invalidation_base
            .checked_add(IOTLB_OFFSET_DELTA)
            .ok_or(VtdError::InvalidRegisterLayout)?;
        if poll_limit == 0 || invalidation_base == 0 || !iotlb_offset.is_multiple_of(8) {
            return Err(VtdError::InvalidRegisterLayout);
        }
        Ok(Self {
            registers,
            iotlb_offset,
            poll_limit,
        })
    }

    fn wait_clear(&mut self, offset: usize) -> Result<u64, VtdError> {
        let mut remaining = self.poll_limit;
        while remaining != 0 {
            let value = self.registers.read64(offset);
            if value & COMMAND_PENDING == 0 {
                return Ok(value);
            }
            core::hint::spin_loop();
            remaining -= 1;
        }
        Err(VtdError::Busy)
    }

    pub fn ready(&mut self) -> Result<(), VtdError> {
        self.wait_clear(CCMD_OFFSET)?;
        self.wait_clear(self.iotlb_offset)?;
        Ok(())
    }

    pub fn invalidate_global(&mut self) -> Result<(), VtdError> {
        self.registers
            .write64(CCMD_OFFSET, COMMAND_PENDING | GLOBAL_GRANULARITY);
        let context = self.wait_clear(CCMD_OFFSET)?;
        if (context >> CCMD_ACTUAL_SHIFT) & ACTUAL_MASK == 0 {
            return Err(VtdError::InvalidCompletion);
        }

        self.registers.write64(
            self.iotlb_offset,
            COMMAND_PENDING | GLOBAL_GRANULARITY | IOTLB_DRAIN_READS | IOTLB_DRAIN_WRITES,
        );
        let iotlb = self.wait_clear(self.iotlb_offset)?;
        if (iotlb >> IOTLB_ACTUAL_SHIFT) & ACTUAL_MASK == 0 {
            return Err(VtdError::InvalidCompletion);
        }
        Ok(())
    }

    pub fn into_registers(self) -> R {
        self.registers
    }
}

/// One live second-level VT-d leaf coupled to its invalidation unit.
pub struct VtdDmaIsolation<'a, R> {
    physical: PhysAddr,
    leaf: &'a mut u64,
    invalidator: VtdInvalidator<R>,
}

impl<'a, R: VtdRegisterIo> VtdDmaIsolation<'a, R> {
    /// # Safety
    ///
    /// `leaf` must uniquely reference the live 4 KiB VT-d second-level leaf
    /// mapping `physical`, and `invalidator` must control every remapping unit
    /// through which a device can reach that granule.
    pub unsafe fn new(
        physical: PhysAddr,
        leaf: &'a mut u64,
        invalidator: VtdInvalidator<R>,
    ) -> Result<Self, VtdError> {
        if *leaf & VTD_LARGE_PAGE != 0 || *leaf & VTD_ADDRESS_MASK != physical.get() {
            return Err(VtdError::InvalidLeaf);
        }
        Ok(Self {
            physical,
            leaf,
            invalidator,
        })
    }

    pub fn into_parts(self) -> (&'a mut u64, VtdInvalidator<R>) {
        (self.leaf, self.invalidator)
    }
}

impl<R: VtdRegisterIo> DmaIsolation for VtdDmaIsolation<'_, R> {
    fn deny_and_invalidate(&mut self, physical: PhysAddr) -> GranuleHardwareOutcome {
        if physical != self.physical || self.invalidator.ready().is_err() {
            return GranuleHardwareOutcome::Rejected;
        }
        // SAFETY: construction requires the unique live leaf reference.
        unsafe {
            core::ptr::write_volatile(
                self.leaf,
                core::ptr::read_volatile(self.leaf) & !VTD_PERMISSION_MASK,
            )
        };
        compiler_fence(Ordering::SeqCst);
        if self.invalidator.invalidate_global().is_err() {
            GranuleHardwareOutcome::FailStop
        } else {
            GranuleHardwareOutcome::Applied
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Registers {
        values: [u64; 130],
        fail_iotlb: bool,
    }

    impl Registers {
        fn new(fail_iotlb: bool) -> Self {
            let mut values = [0; 130];
            values[ECAP_OFFSET / 8] = 0x20 << 8;
            Self { values, fail_iotlb }
        }
    }

    impl VtdRegisterIo for Registers {
        fn read64(&mut self, offset: usize) -> u64 {
            let value = self.values[offset / 8];
            if value & COMMAND_PENDING == 0 {
                return value;
            }
            if self.fail_iotlb && offset == 0x208 {
                return value;
            }
            let completed = if offset == CCMD_OFFSET {
                (value & !COMMAND_PENDING) | (1 << CCMD_ACTUAL_SHIFT)
            } else {
                (value & !COMMAND_PENDING) | (1 << IOTLB_ACTUAL_SHIFT)
            };
            self.values[offset / 8] = completed;
            completed
        }

        fn write64(&mut self, offset: usize, value: u64) {
            self.values[offset / 8] = value;
        }
    }

    fn finalize_table(table: &mut [u8]) {
        table[9] = 0;
        let sum = table.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
        table[9] = 0u8.wrapping_sub(sum);
    }

    fn dmar() -> [u8; 72] {
        let mut table = [0u8; 72];
        table[..4].copy_from_slice(b"DMAR");
        table[4..8].copy_from_slice(&72u32.to_le_bytes());
        table[36] = 47;
        table[48..50].copy_from_slice(&0u16.to_le_bytes());
        table[50..52].copy_from_slice(&24u16.to_le_bytes());
        table[52] = 1;
        table[54..56].copy_from_slice(&0u16.to_le_bytes());
        table[56..64].copy_from_slice(&0xfed9_0000u64.to_le_bytes());
        table[64..72].copy_from_slice(&[1, 8, 0, 0, 0, 2, 3, 0]);
        finalize_table(&mut table);
        table
    }

    #[test]
    fn parses_checked_drhd_and_complete_pci_path() {
        let topology = DmarTopology::<2, 4>::parse(&dmar()).unwrap();
        assert_eq!(topology.host_address_width, 48);
        let unit = topology.units().next().unwrap();
        assert!(unit.include_all);
        assert_eq!(unit.register_base.get(), 0xfed9_0000);
        let scope = topology.scopes(unit).next().unwrap();
        assert_eq!(scope.start_bus, 2);
        assert_eq!(scope.path_len, 1);
        assert_eq!(
            scope.path[0],
            PciPathElement {
                device: 3,
                function: 0
            }
        );
    }

    #[test]
    fn rejects_corruption_truncation_and_ambiguous_units() {
        let mut corrupt = dmar();
        corrupt[56] ^= 1;
        assert_eq!(
            DmarTopology::<2, 4>::parse(&corrupt),
            Err(DmarError::BadChecksum)
        );
        let mut truncated = dmar();
        truncated[50..52].copy_from_slice(&25u16.to_le_bytes());
        finalize_table(&mut truncated);
        assert_eq!(
            DmarTopology::<2, 4>::parse(&truncated),
            Err(DmarError::Truncated)
        );

        let original = dmar();
        let mut duplicate = [0u8; 96];
        duplicate[..72].copy_from_slice(&original);
        duplicate[4..8].copy_from_slice(&96u32.to_le_bytes());
        duplicate[72..96].copy_from_slice(&original[48..72]);
        finalize_table(&mut duplicate);
        assert_eq!(
            DmarTopology::<2, 4>::parse(&duplicate),
            Err(DmarError::AmbiguousUnit)
        );
    }

    #[test]
    fn deny_clears_dma_permissions_and_completes_both_invalidations() {
        let physical = PhysAddr::new(0x70_0000).unwrap();
        let mut leaf = physical.get() | VTD_PERMISSION_MASK;
        let invalidator = VtdInvalidator::new(Registers::new(false), 4).unwrap();
        let mut dma = unsafe { VtdDmaIsolation::new(physical, &mut leaf, invalidator).unwrap() };
        assert_eq!(
            dma.deny_and_invalidate(physical),
            GranuleHardwareOutcome::Applied
        );
        let (leaf, _) = dma.into_parts();
        assert_eq!(*leaf & VTD_PERMISSION_MASK, 0);
    }

    #[test]
    fn iotlb_timeout_after_leaf_write_is_fail_stop() {
        let physical = PhysAddr::new(0x80_0000).unwrap();
        let mut leaf = physical.get() | VTD_PERMISSION_MASK;
        let invalidator = VtdInvalidator::new(Registers::new(true), 2).unwrap();
        let mut dma = unsafe { VtdDmaIsolation::new(physical, &mut leaf, invalidator).unwrap() };
        assert_eq!(
            dma.deny_and_invalidate(physical),
            GranuleHardwareOutcome::FailStop
        );
    }
}
