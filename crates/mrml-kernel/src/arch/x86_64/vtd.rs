use core::sync::atomic::{Ordering, compiler_fence};

use crate::{DeviceAddress, GranuleHardwareOutcome, PhysAddr};

use super::DmaIsolation;

const ECAP_OFFSET: usize = 0x10;
const CAP_OFFSET: usize = 0x08;
const CCMD_OFFSET: usize = 0x28;
const FSTS_OFFSET: usize = 0x34;
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
const FAULT_STATUS_MASK: u32 = 0xff;
const FAULT_VALID: u64 = 1 << 63;
const DMAR_HEADER_BYTES: usize = 48;
const DRHD_HEADER_BYTES: usize = 16;
const DEVICE_SCOPE_HEADER_BYTES: usize = 6;
const MAX_PCI_PATH_DEPTH: usize = 8;
const MCFG_HEADER_BYTES: usize = 44;
const MCFG_ALLOCATION_BYTES: usize = 16;
const MAX_PHYSICAL_EXCLUSIVE: u64 = 1 << 52;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VtdError {
    InvalidRegisterLayout,
    InvalidLeaf,
    Busy,
    InvalidCompletion,
    InvalidFaultLayout,
    FaultPending,
    FaultChanged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VtdFaultSnapshot {
    pub status: u32,
    pub record_index: u8,
    pub requester_id: u16,
    pub reason: u8,
    pub read: bool,
    pub address: u64,
    record_high: u64,
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
    ConfigReadFailed,
    MissingDevice,
    NotPciBridge,
    InvalidBusRange,
    NoRemappingUnit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McfgError {
    Truncated,
    WrongSignature,
    InvalidLength,
    BadChecksum,
    InvalidReserved,
    InvalidBusRange,
    InvalidAddress,
    AllocationTableFull,
    DuplicateOrOverlapping,
    MissingAllocation,
    SegmentTableFull,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct McfgAllocation {
    pub base: PhysAddr,
    pub segment: u16,
    pub start_bus: u8,
    pub end_bus: u8,
}

impl McfgAllocation {
    pub fn bytes(self) -> usize {
        (usize::from(self.end_bus) - usize::from(self.start_bus) + 1) << 20
    }

    pub fn physical_start(self) -> u64 {
        self.base.get() + (u64::from(self.start_bus) << 20)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct McfgTopology<const ALLOCATIONS: usize> {
    allocations: [Option<McfgAllocation>; ALLOCATIONS],
    count: usize,
}

impl<const ALLOCATIONS: usize> McfgTopology<ALLOCATIONS> {
    pub fn parse(table: &[u8]) -> Result<Self, McfgError> {
        if table.len() < MCFG_HEADER_BYTES {
            return Err(McfgError::Truncated);
        }
        if &table[..4] != b"MCFG" {
            return Err(McfgError::WrongSignature);
        }
        let length = read_mcfg_u32(table, 4)? as usize;
        if length != table.len()
            || !(length - MCFG_HEADER_BYTES).is_multiple_of(MCFG_ALLOCATION_BYTES)
        {
            return Err(McfgError::InvalidLength);
        }
        if table.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0 {
            return Err(McfgError::BadChecksum);
        }
        if table[36..MCFG_HEADER_BYTES].iter().any(|byte| *byte != 0) {
            return Err(McfgError::InvalidReserved);
        }
        let mut topology = Self {
            allocations: [None; ALLOCATIONS],
            count: 0,
        };
        for bytes in table[MCFG_HEADER_BYTES..]
            .as_chunks::<MCFG_ALLOCATION_BYTES>()
            .0
        {
            if topology.count == ALLOCATIONS {
                return Err(McfgError::AllocationTableFull);
            }
            if bytes[12..].iter().any(|byte| *byte != 0) {
                return Err(McfgError::InvalidReserved);
            }
            if bytes[10] > bytes[11] {
                return Err(McfgError::InvalidBusRange);
            }
            let base_value = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            let base = PhysAddr::new(base_value).map_err(|_| McfgError::InvalidAddress)?;
            let buses_from_zero = u64::from(bytes[11]) + 1;
            let bytes_len = buses_from_zero
                .checked_mul(1 << 20)
                .ok_or(McfgError::InvalidAddress)?;
            let end = base_value
                .checked_add(bytes_len)
                .ok_or(McfgError::InvalidAddress)?;
            if base_value == 0
                || !base_value.is_multiple_of(1 << 20)
                || end > MAX_PHYSICAL_EXCLUSIVE
            {
                return Err(McfgError::InvalidAddress);
            }
            let allocation = McfgAllocation {
                base,
                segment: u16::from_le_bytes([bytes[8], bytes[9]]),
                start_bus: bytes[10],
                end_bus: bytes[11],
            };
            if topology.allocations().any(|existing| {
                ranges_overlap(
                    existing.physical_start(),
                    existing.bytes() as u64,
                    allocation.physical_start(),
                    allocation.bytes() as u64,
                ) || (existing.segment == allocation.segment
                    && bus_ranges_overlap(existing, &allocation))
            }) {
                return Err(McfgError::DuplicateOrOverlapping);
            }
            topology.allocations[topology.count] = Some(allocation);
            topology.count += 1;
        }
        if topology.count == 0 {
            return Err(McfgError::MissingAllocation);
        }
        Ok(topology)
    }

    pub fn allocations(&self) -> impl Iterator<Item = &McfgAllocation> {
        self.allocations[..self.count].iter().flatten()
    }
}

fn bus_ranges_overlap(left: &McfgAllocation, right: &McfgAllocation) -> bool {
    left.start_bus <= right.end_bus && right.start_bus <= left.end_bus
}

fn ranges_overlap(left: u64, left_len: u64, right: u64, right_len: u64) -> bool {
    left < right + right_len && right < left + left_len
}

fn read_mcfg_u32(bytes: &[u8], offset: usize) -> Result<u32, McfgError> {
    let source = bytes.get(offset..offset + 4).ok_or(McfgError::Truncated)?;
    Ok(u32::from_le_bytes(source.try_into().unwrap()))
}

pub trait PciConfigSpace {
    fn read_u32(&mut self, address: DeviceAddress, offset: u16) -> Option<u32>;
}

/// One uniquely mapped PCIe ECAM segment window.
pub struct NativeEcamSegment {
    base: *const u8,
    bytes: usize,
    segment: u16,
    start_bus: u8,
    end_bus: u8,
}

impl NativeEcamSegment {
    /// # Safety
    ///
    /// `base..base + bytes` must remain a mapped, uncached ECAM window for the
    /// stated segment and inclusive bus range. Configuration access must be
    /// serialized against removal and firmware ownership changes.
    pub unsafe fn new(
        base: *const u8,
        bytes: usize,
        segment: u16,
        start_bus: u8,
        end_bus: u8,
    ) -> Result<Self, DmarError> {
        let buses = usize::from(end_bus)
            .checked_sub(usize::from(start_bus))
            .and_then(|span| span.checked_add(1))
            .ok_or(DmarError::InvalidBusRange)?;
        let required = buses
            .checked_mul(1 << 20)
            .ok_or(DmarError::InvalidBusRange)?;
        if base.is_null() || !(base as usize).is_multiple_of(4096) || bytes < required {
            return Err(DmarError::InvalidBusRange);
        }
        Ok(Self {
            base,
            bytes,
            segment,
            start_bus,
            end_bus,
        })
    }

    /// # Safety
    ///
    /// `base` must map `allocation.physical_start()` for `allocation.bytes()`
    /// bytes with the same lifetime and serialization guarantees as `new`.
    pub unsafe fn from_allocation(
        base: *const u8,
        bytes: usize,
        allocation: McfgAllocation,
    ) -> Result<Self, DmarError> {
        // SAFETY: forwarded unchanged from this function's contract.
        unsafe {
            Self::new(
                base,
                bytes,
                allocation.segment,
                allocation.start_bus,
                allocation.end_bus,
            )
        }
    }

    fn covers(&self, address: DeviceAddress) -> bool {
        address.segment() == self.segment
            && address.bus() >= self.start_bus
            && address.bus() <= self.end_bus
    }
}

impl PciConfigSpace for NativeEcamSegment {
    fn read_u32(&mut self, address: DeviceAddress, offset: u16) -> Option<u32> {
        if address.segment() != self.segment
            || address.bus() < self.start_bus
            || address.bus() > self.end_bus
            || offset > 4092
            || !offset.is_multiple_of(4)
        {
            return None;
        }
        let relative_bus = usize::from(address.bus() - self.start_bus);
        let location = (relative_bus << 20)
            | (usize::from(address.device()) << 15)
            | (usize::from(address.function()) << 12)
            | usize::from(offset);
        if location > self.bytes.saturating_sub(4) {
            return None;
        }
        // SAFETY: construction establishes the mapped ECAM window and the
        // checked location is naturally aligned within a 4 KiB function.
        Some(unsafe { self.base.add(location).cast::<u32>().read_volatile() })
    }
}

pub struct EcamSegments<const SEGMENTS: usize> {
    windows: [Option<NativeEcamSegment>; SEGMENTS],
    count: usize,
}

impl<const SEGMENTS: usize> EcamSegments<SEGMENTS> {
    pub fn new() -> Self {
        Self {
            windows: core::array::from_fn(|_| None),
            count: 0,
        }
    }

    pub fn push(&mut self, window: NativeEcamSegment) -> Result<(), McfgError> {
        if self.count == SEGMENTS {
            return Err(McfgError::SegmentTableFull);
        }
        if self.windows[..self.count].iter().flatten().any(|existing| {
            existing.segment == window.segment
                && existing.start_bus <= window.end_bus
                && window.start_bus <= existing.end_bus
        }) {
            return Err(McfgError::DuplicateOrOverlapping);
        }
        self.windows[self.count] = Some(window);
        self.count += 1;
        Ok(())
    }
}

impl<const SEGMENTS: usize> Default for EcamSegments<SEGMENTS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const SEGMENTS: usize> PciConfigSpace for EcamSegments<SEGMENTS> {
    fn read_u32(&mut self, address: DeviceAddress, offset: u16) -> Option<u32> {
        self.windows[..self.count]
            .iter_mut()
            .flatten()
            .find(|window| window.covers(address))?
            .read_u32(address, offset)
    }
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

    pub fn resolve_scope<C: PciConfigSpace>(
        &self,
        segment: u16,
        scope: &DmarDeviceScope,
        config: &mut C,
    ) -> Result<DeviceAddress, DmarError> {
        let mut bus = scope.start_bus;
        let path = &scope.path[..scope.path_len as usize];
        for (index, element) in path.iter().enumerate() {
            let address = DeviceAddress::new(segment, bus, element.device, element.function)
                .map_err(|_| DmarError::InvalidScope)?;
            let identity = config
                .read_u32(address, 0)
                .ok_or(DmarError::ConfigReadFailed)?;
            if identity & 0xffff == 0xffff {
                return Err(DmarError::MissingDevice);
            }
            if index + 1 != path.len() {
                let header = config
                    .read_u32(address, 0x0c)
                    .ok_or(DmarError::ConfigReadFailed)?;
                if (header >> 16) as u8 & 0x7f != 1 {
                    return Err(DmarError::NotPciBridge);
                }
                let buses = config
                    .read_u32(address, 0x18)
                    .ok_or(DmarError::ConfigReadFailed)?;
                let primary = buses as u8;
                let secondary = (buses >> 8) as u8;
                let subordinate = (buses >> 16) as u8;
                if primary != bus || secondary == 0 || secondary > subordinate {
                    return Err(DmarError::InvalidBusRange);
                }
                bus = secondary;
            }
        }
        DeviceAddress::new(
            segment,
            bus,
            path.last().ok_or(DmarError::InvalidScope)?.device,
            path.last().ok_or(DmarError::InvalidScope)?.function,
        )
        .map_err(|_| DmarError::InvalidScope)
    }

    /// Selects the unique DRHD covering `requester`. Explicit device scopes
    /// take precedence over a segment's include-all fallback.
    pub fn unit_for_requester<C: PciConfigSpace>(
        &self,
        requester: DeviceAddress,
        config: &mut C,
    ) -> Result<&DmarUnit, DmarError> {
        let mut explicit = None;
        let mut fallback = None;
        for unit in self
            .units()
            .filter(|unit| unit.segment == requester.segment())
        {
            if unit.include_all && fallback.replace(unit).is_some() {
                return Err(DmarError::AmbiguousUnit);
            }
            for scope in self.scopes(unit) {
                if self.resolve_scope(unit.segment, scope, config)? == requester
                    && explicit.replace(unit).is_some()
                {
                    return Err(DmarError::AmbiguousUnit);
                }
            }
        }
        explicit.or(fallback).ok_or(DmarError::NoRemappingUnit)
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
    fn read32(&mut self, offset: usize) -> u32;
    fn write32(&mut self, offset: usize, value: u32);
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
    fn read32(&mut self, offset: usize) -> u32 {
        if offset > self.bytes.saturating_sub(4) || !offset.is_multiple_of(4) {
            return u32::MAX;
        }
        // SAFETY: construction establishes the mapped MMIO range.
        unsafe { self.base.add(offset).cast::<u32>().read_volatile() }
    }

    fn write32(&mut self, offset: usize, value: u32) {
        if offset > self.bytes.saturating_sub(4) || !offset.is_multiple_of(4) {
            return;
        }
        // SAFETY: construction establishes the mapped MMIO range.
        unsafe { self.base.add(offset).cast::<u32>().write_volatile(value) };
    }

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
    fault_offset: usize,
    fault_records: u16,
    poll_limit: u32,
}

impl<R: VtdRegisterIo> VtdInvalidator<R> {
    pub fn new(mut registers: R, poll_limit: u32) -> Result<Self, VtdError> {
        let capability = registers.read64(CAP_OFFSET);
        let ecap = registers.read64(ECAP_OFFSET);
        let invalidation_base = ((ecap >> 8) & 0x3ff) as usize * 16;
        let iotlb_offset = invalidation_base
            .checked_add(IOTLB_OFFSET_DELTA)
            .ok_or(VtdError::InvalidRegisterLayout)?;
        if poll_limit == 0 || invalidation_base == 0 || !iotlb_offset.is_multiple_of(8) {
            return Err(VtdError::InvalidRegisterLayout);
        }
        let fault_offset = (((capability >> 24) & 0x3ff) as usize)
            .checked_mul(16)
            .ok_or(VtdError::InvalidFaultLayout)?;
        let fault_records = (((capability >> 40) & 0xff) as u16) + 1;
        let fault_end = fault_offset
            .checked_add(usize::from(fault_records) * 16)
            .ok_or(VtdError::InvalidFaultLayout)?;
        if fault_offset == 0 || fault_end <= fault_offset {
            return Err(VtdError::InvalidFaultLayout);
        }
        Ok(Self {
            registers,
            iotlb_offset,
            fault_offset,
            fault_records,
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
        self.require_healthy()?;
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
        self.require_healthy()
    }

    pub fn snapshot_fault(&mut self) -> Option<VtdFaultSnapshot> {
        let status = self.registers.read32(FSTS_OFFSET);
        if status & FAULT_STATUS_MASK == 0 {
            return None;
        }
        let index = ((status >> 8) & 0xff) as u8;
        if status & (1 << 1) == 0 || u16::from(index) >= self.fault_records {
            return Some(VtdFaultSnapshot {
                status,
                record_index: index,
                requester_id: 0,
                reason: 0,
                read: false,
                address: 0,
                record_high: 0,
            });
        }
        let offset = self.fault_offset + usize::from(index) * 16;
        let high = self.registers.read64(offset + 8);
        if high & FAULT_VALID == 0 {
            return Some(VtdFaultSnapshot {
                status,
                record_index: index,
                requester_id: 0,
                reason: 0,
                read: false,
                address: 0,
                record_high: 0,
            });
        }
        let low = self.registers.read64(offset);
        if self.registers.read64(offset + 8) != high {
            return Some(VtdFaultSnapshot {
                status,
                record_index: index,
                requester_id: 0,
                reason: 0,
                read: false,
                address: 0,
                record_high: 0,
            });
        }
        Some(VtdFaultSnapshot {
            status,
            record_index: index,
            requester_id: high as u16,
            reason: (high >> 32) as u8,
            read: high & (1 << 62) != 0,
            address: low & VTD_ADDRESS_MASK,
            record_high: high,
        })
    }

    pub fn acknowledge_fault(&mut self, snapshot: VtdFaultSnapshot) -> Result<(), VtdError> {
        if snapshot.record_high != 0 {
            let offset = self.fault_offset + usize::from(snapshot.record_index) * 16 + 8;
            if self.registers.read64(offset) != snapshot.record_high {
                return Err(VtdError::FaultChanged);
            }
            self.registers.write64(offset, FAULT_VALID);
        }
        self.registers.write32(FSTS_OFFSET, snapshot.status & 0xfd);
        Ok(())
    }

    fn require_healthy(&mut self) -> Result<(), VtdError> {
        if self.registers.read32(FSTS_OFFSET) & FAULT_STATUS_MASK == 0 {
            Ok(())
        } else {
            Err(VtdError::FaultPending)
        }
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
        fault_on_iotlb: bool,
        fault_status: u32,
    }

    impl Registers {
        fn new(fail_iotlb: bool) -> Self {
            let mut values = [0; 130];
            values[CAP_OFFSET / 8] = 0x40 << 24;
            values[ECAP_OFFSET / 8] = 0x20 << 8;
            Self {
                values,
                fail_iotlb,
                fault_on_iotlb: false,
                fault_status: 0,
            }
        }
    }

    impl VtdRegisterIo for Registers {
        fn read32(&mut self, offset: usize) -> u32 {
            if offset == FSTS_OFFSET {
                self.fault_status
            } else {
                self.values[offset / 8] as u32
            }
        }

        fn write32(&mut self, offset: usize, value: u32) {
            if offset == FSTS_OFFSET {
                self.fault_status &= !value;
            }
        }

        fn read64(&mut self, offset: usize) -> u64 {
            let value = self.values[offset / 8];
            if !matches!(offset, CCMD_OFFSET | 0x208) || value & COMMAND_PENDING == 0 {
                return value;
            }
            if self.fail_iotlb && offset == 0x208 {
                return value;
            }
            let completed = if offset == CCMD_OFFSET {
                (value & !COMMAND_PENDING) | (1 << CCMD_ACTUAL_SHIFT)
            } else {
                if self.fault_on_iotlb {
                    self.fault_status |= 1 << 6;
                }
                (value & !COMMAND_PENDING) | (1 << IOTLB_ACTUAL_SHIFT)
            };
            self.values[offset / 8] = completed;
            completed
        }

        fn write64(&mut self, offset: usize, value: u64) {
            if offset >= 0x400 && offset % 16 == 8 && value & FAULT_VALID != 0 {
                self.values[offset / 8] &= !FAULT_VALID;
                self.fault_status &= !(1 << 1);
            } else {
                self.values[offset / 8] = value;
            }
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

    fn routing_dmar() -> [u8; 90] {
        let mut table = [0u8; 90];
        table[..4].copy_from_slice(b"DMAR");
        table[4..8].copy_from_slice(&90u32.to_le_bytes());
        table[36] = 47;
        table[48..50].copy_from_slice(&0u16.to_le_bytes());
        table[50..52].copy_from_slice(&26u16.to_le_bytes());
        table[54..56].copy_from_slice(&0u16.to_le_bytes());
        table[56..64].copy_from_slice(&0xfed9_0000u64.to_le_bytes());
        table[64..74].copy_from_slice(&[1, 10, 0, 0, 0, 2, 3, 0, 1, 0]);
        table[74..76].copy_from_slice(&0u16.to_le_bytes());
        table[76..78].copy_from_slice(&16u16.to_le_bytes());
        table[78] = 1;
        table[80..82].copy_from_slice(&0u16.to_le_bytes());
        table[82..90].copy_from_slice(&0xfeda_0000u64.to_le_bytes());
        finalize_table(&mut table);
        table
    }

    fn mcfg() -> [u8; 60] {
        let mut table = [0u8; 60];
        table[..4].copy_from_slice(b"MCFG");
        table[4..8].copy_from_slice(&60u32.to_le_bytes());
        table[44..52].copy_from_slice(&0xe000_0000u64.to_le_bytes());
        table[52..54].copy_from_slice(&0u16.to_le_bytes());
        table[54] = 0x20;
        table[55] = 0x2f;
        finalize_table(&mut table);
        table
    }

    struct Config {
        bridge_header: u32,
    }

    impl PciConfigSpace for Config {
        fn read_u32(&mut self, address: DeviceAddress, offset: u16) -> Option<u32> {
            let bridge = DeviceAddress::new(0, 2, 3, 0).unwrap();
            let endpoint = DeviceAddress::new(0, 5, 1, 0).unwrap();
            match (address, offset) {
                (address, 0) if address == bridge || address == endpoint => Some(0x1234_8086),
                (address, 0x0c) if address == bridge => Some(self.bridge_header),
                (address, 0x18) if address == bridge => Some(2 | (5 << 8) | (5 << 16)),
                _ => None,
            }
        }
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
    fn parses_bounded_mcfg_allocations() {
        let topology = McfgTopology::<2>::parse(&mcfg()).unwrap();
        let allocation = topology.allocations().next().unwrap();
        assert_eq!(allocation.base.get(), 0xe000_0000);
        assert_eq!(allocation.segment, 0);
        assert_eq!(allocation.start_bus, 0x20);
        assert_eq!(allocation.end_bus, 0x2f);
        assert_eq!(allocation.bytes(), 16 << 20);
        assert_eq!(allocation.physical_start(), 0xe200_0000);
    }

    #[test]
    fn rejects_corrupt_and_overlapping_mcfg_allocations() {
        let mut corrupt = mcfg();
        corrupt[44] ^= 1;
        assert_eq!(
            McfgTopology::<2>::parse(&corrupt),
            Err(McfgError::BadChecksum)
        );

        let original = mcfg();
        let mut overlap = [0u8; 76];
        overlap[..60].copy_from_slice(&original);
        overlap[4..8].copy_from_slice(&76u32.to_le_bytes());
        overlap[60..68].copy_from_slice(&0xf000_0000u64.to_le_bytes());
        overlap[68..70].copy_from_slice(&0u16.to_le_bytes());
        overlap[70] = 0x2f;
        overlap[71] = 0x30;
        finalize_table(&mut overlap);
        assert_eq!(
            McfgTopology::<2>::parse(&overlap),
            Err(McfgError::DuplicateOrOverlapping)
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
    fn resolves_bridge_paths_and_prefers_explicit_unit() {
        let topology = DmarTopology::<2, 2>::parse(&routing_dmar()).unwrap();
        let mut config = Config {
            bridge_header: 1 << 16,
        };
        let endpoint = DeviceAddress::new(0, 5, 1, 0).unwrap();
        assert_eq!(
            topology
                .unit_for_requester(endpoint, &mut config)
                .unwrap()
                .register_base
                .get(),
            0xfed9_0000
        );
        let fallback = DeviceAddress::new(0, 7, 2, 0).unwrap();
        assert_eq!(
            topology
                .unit_for_requester(fallback, &mut config)
                .unwrap()
                .register_base
                .get(),
            0xfeda_0000
        );
    }

    #[test]
    fn rejects_firmware_path_through_non_bridge_function() {
        let topology = DmarTopology::<2, 2>::parse(&routing_dmar()).unwrap();
        let unit = topology.units().next().unwrap();
        let scope = topology.scopes(unit).next().unwrap();
        let mut config = Config { bridge_header: 0 };
        assert_eq!(
            topology.resolve_scope(0, scope, &mut config),
            Err(DmarError::NotPciBridge)
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

    #[test]
    fn snapshots_and_explicitly_acknowledges_primary_fault() {
        let mut registers = Registers::new(false);
        registers.fault_status = 1 << 1;
        registers.values[0x400 / 8] = 0x1234_5000;
        registers.values[0x408 / 8] = FAULT_VALID | (1 << 62) | (0x25 << 32) | 0x031a;
        let mut invalidator = VtdInvalidator::new(registers, 4).unwrap();
        assert_eq!(invalidator.ready(), Err(VtdError::FaultPending));
        let snapshot = invalidator.snapshot_fault().unwrap();
        assert_eq!(snapshot.requester_id, 0x031a);
        assert_eq!(snapshot.reason, 0x25);
        assert!(snapshot.read);
        assert_eq!(snapshot.address, 0x1234_5000);
        invalidator.acknowledge_fault(snapshot).unwrap();
        assert_eq!(invalidator.snapshot_fault(), None);
        assert_eq!(invalidator.ready(), Ok(()));
    }

    #[test]
    fn fault_raised_after_dma_leaf_write_is_fail_stop() {
        let physical = PhysAddr::new(0x90_0000).unwrap();
        let mut leaf = physical.get() | VTD_PERMISSION_MASK;
        let mut registers = Registers::new(false);
        registers.fault_on_iotlb = true;
        let invalidator = VtdInvalidator::new(registers, 4).unwrap();
        let mut dma = unsafe { VtdDmaIsolation::new(physical, &mut leaf, invalidator).unwrap() };
        assert_eq!(
            dma.deny_and_invalidate(physical),
            GranuleHardwareOutcome::FailStop
        );
    }
}
