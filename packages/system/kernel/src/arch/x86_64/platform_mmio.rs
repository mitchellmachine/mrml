use crate::{DeviceAddress, MemoryKind, MemoryMap, MemoryRegion, PAGE_SIZE, PhysAddr};

use super::{
    ActivePageTables, DmarTopology, Mapping, McfgTopology, PagePermissions, VirtAddr,
    VtdRegisterLayout, VtdRequesterRoute,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformMmioError {
    ManifestFull,
    InvalidRange,
    Overlap,
    OutsideFirmwareMmio,
    MappingMismatch,
    PageTable,
    CpuProtection,
}

/// A copied observation, not proof of a safe mapping or access authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StableXhciPciHeader {
    pub command: u16,
    pub header_type: u8,
    pub bar0: u32,
    pub bar1: u32,
}

impl StableXhciPciHeader {
    pub const fn bar_base(self) -> u64 {
        ((self.bar1 as u64) << 32) | ((self.bar0 & !15) as u64)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XhciHeaderSampleError {
    Unreadable,
    ChangedFunction,
    InvalidHeader,
    Unstable,
}

/// Read two fixed PCI header samples from a caller-verified read-only page.
/// Status changes are not compared; the command word and full BAR are.
/// Mismatched vendor or class stops before reading the BAR of that sample.
pub fn sample_stable_xhci_pci_header(
    vendor_device: u32,
    class_revision: u32,
    mut read: impl FnMut(u16) -> Option<u32>,
) -> Result<StableXhciPciHeader, XhciHeaderSampleError> {
    use XhciHeaderSampleError::*;
    if matches!(vendor_device as u16, 0 | u16::MAX) || class_revision >> 8 != 0x0c0330 {
        return Err(ChangedFunction);
    }
    let mut word = |offset| read(offset).ok_or(Unreadable);
    let mut sample = || {
        if word(0)? != vendor_device || word(8)? != class_revision {
            return Err(ChangedFunction);
        }
        let command = word(4)? as u16;
        let header_type = (word(0x0c)? >> 16) as u8;
        if command == u16::MAX || command & 2 == 0 || header_type & 0x7f != 0 {
            return Err(InvalidHeader);
        }
        let bar0 = word(0x10)?;
        let bar1 = match bar0 & 7 {
            0 => 0,
            4 => word(0x14)?,
            _ => return Err(InvalidHeader),
        };
        Ok(StableXhciPciHeader { command, header_type, bar0, bar1 })
    };
    let first = sample()?;
    if first != sample()? {
        return Err(Unstable);
    }
    Ok(first)
}

/// Exact expected wire value for the read-only shared Q35 boot. The loader
/// must capture these bytes from UEFI, never synthesize them as evidence.
pub const Q35_SHARED_BOOT_USB_RECORD: &[u8; crate::BOOT_USB_PCI_RECORD_BYTES] =
    b"MRMLXHCI\x01\x00\x28\x00\x00\x41\x00\x00\x36\x1b\x0d\x00\x01\x30\x03\x0c\x00\x00\x20\x81\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00";

/// Exact accepted layouts for the signed, emulator-only q35 fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Q35FixtureTopology {
    Control,
    Isolated,
}

impl Q35FixtureTopology {
    /// Classify ACPI evidence for the model. Neither case grants ownership
    /// or says anything about real hardware.
    pub fn from_dmar(table: &[u8]) -> Option<Self> {
        let dmar = DmarTopology::<1, 64>::parse(table).ok()?;
        let unit = dmar.units().next()?;
        if unit.segment != 0
            || unit.include_all
            || unit.register_base.get() != 0xfed9_0000
            || dmar.reserved_regions().next().is_some()
        {
            return None;
        }
        let matching = |kind, bus, device| {
            dmar.scopes(unit).filter(move |scope| {
                scope.scope_type == kind
                    && scope.enumeration_id == 0
                    && scope.start_bus == bus
                    && scope.path_len == 1
                    && scope.path[0].device == device
                    && scope.path[0].function == 0
            })
        };
        // The model's firmware snapshots this topology before assigning the
        // secondary bus, so the isolated endpoint is covered by type 2, not
        // a separate endpoint scope. Require the whole table, including no
        // extra or unparsed structures, not just a matching entry.
        if table.len() == 80
            && table[8] == 1
            && table[38..48] == [0; 10]
            && table[52..54] == [0; 2]
            && dmar.host_address_width == 48
            && dmar.flags == 0
            && dmar.scopes(unit).count() == 2
            && matching(2, 0x40, 0).count() == 1
            && matching(3, 0xff, 0).count() == 1
        {
            Some(Self::Isolated)
        } else if matching(1, 0, 0x1b).count() == 1 {
            Some(Self::Control)
        } else {
            None
        }
    }
}

/// Exact read-only pages in DRHD / endpoint / bridge / BAR0 order.
/// These are addresses in the signed model fixture, not physical authority.
pub fn q35_fixture_probe_mappings(
    topology: Q35FixtureTopology,
) -> Result<[Option<Mapping>; 4], PlatformMmioError> {
    q35_fixture_mappings(topology, false)
}

/// The sealed shutdown profile changes only the two ECAM leaves. The
/// controller and remapper stay read-only, including in the shutdown case.
pub fn q35_fixture_shutdown_mappings() -> Result<[Option<Mapping>; 4], PlatformMmioError> {
    q35_fixture_mappings(Q35FixtureTopology::Isolated, true)
}

/// Read-only preflight for the three pages needed by the emulator driver.
/// The fourth BAR page is deliberately absent.
pub fn q35_fixture_bar_preflight_mappings() -> Result<[Option<Mapping>; 4], PlatformMmioError> {
    let mut mappings = q35_fixture_probe_mappings(Q35FixtureTopology::Isolated)?;
    let bar = mappings[3].ok_or(PlatformMmioError::InvalidRange)?;
    mappings[3] = Some(
        Mapping::new(
            bar.virtual_start(),
            bar.physical_start(),
            3,
            PagePermissions::KERNEL_MMIO_READ,
        )
        .map_err(|_| PlatformMmioError::MappingMismatch)?,
    );
    Ok(mappings)
}

/// Writable DRHD page only for the separately released, isolated model.
pub fn q35_fixture_activation_mappings() -> Result<[Option<Mapping>; 4], PlatformMmioError> {
    let mut mappings = q35_fixture_shutdown_mappings()?;
    let drhd = mappings[0].ok_or(PlatformMmioError::InvalidRange)?;
    mappings[0] = Some(
        Mapping::new(
            drhd.virtual_start(),
            drhd.physical_start(),
            1,
            PagePermissions::KERNEL_HIGH_MMIO_READ_WRITE,
        )
        .map_err(|_| PlatformMmioError::MappingMismatch)?,
    );
    Ok(mappings)
}

fn q35_fixture_mappings(
    topology: Q35FixtureTopology,
    shutdown: bool,
) -> Result<[Option<Mapping>; 4], PlatformMmioError> {
    let page = |virtual_start, physical, writable| {
        Mapping::new(
            VirtAddr::new(virtual_start).map_err(|_| PlatformMmioError::InvalidRange)?,
            PhysAddr::new(physical).map_err(|_| PlatformMmioError::InvalidRange)?,
            1,
            if writable {
                PagePermissions::KERNEL_HIGH_MMIO_READ_WRITE
            } else {
                PagePermissions::KERNEL_MMIO_READ
            },
        )
        .map_err(|_| PlatformMmioError::InvalidRange)
    };
    let (endpoint, bridge) = match topology {
        Q35FixtureTopology::Control => (0xe00d_8000, None),
        Q35FixtureTopology::Isolated => (
            0xe410_0000,
            Some(page(0xffff_d800_0010_2000, 0xe400_0000, shutdown)?),
        ),
    };
    Ok([
        Some(page(0xffff_d800_0010_0000, 0xfed9_0000, false)?),
        Some(page(0xffff_d800_0010_1000, endpoint, shutdown)?),
        bridge,
        match topology {
            Q35FixtureTopology::Control => None,
            Q35FixtureTopology::Isolated => Some(page(0xffff_d800_0010_3000, 0x8120_0000, false)?),
        },
    ])
}

#[cfg(test)]
mod q35_fixture_tests {
    use super::*;

    fn fixture() -> [u8; 80] {
        let mut table = [0u8; 80];
        table[..4].copy_from_slice(b"DMAR");
        table[4..8].copy_from_slice(&80u32.to_le_bytes());
        table[8] = 1;
        table[36] = 47;
        table[50..52].copy_from_slice(&32u16.to_le_bytes());
        table[56..64].copy_from_slice(&0xfed9_0000u64.to_le_bytes());
        table[64..72].copy_from_slice(&[3, 8, 0, 0, 0, 0xff, 0, 0]);
        table[72..80].copy_from_slice(&[2, 8, 0, 0, 0, 0x40, 0, 0]);
        checksum(&mut table);
        table
    }

    #[test]
    fn q35_dxe_copies_compare_with_independent_acpi_and_final_map() {
        use DxeObservationError::*;
        let dmar = fixture();
        let mut mcfg = [0u8; 60];
        mcfg[..4].copy_from_slice(b"MCFG");
        mcfg[4..8].copy_from_slice(&60u32.to_le_bytes());
        mcfg[44..52].copy_from_slice(&0xe000_0000u64.to_le_bytes());
        mcfg[55] = 255;
        checksum(&mut mcfg);
        let usb = Q35_SHARED_BOOT_USB_RECORD;
        let expected = [(0xe000_0000, 65536), (0xe410_0000, 1), (0xfed9_0000, 1)];
        let mut queries = 0;
        // Synthetic classification for data-only branch coverage.
        let copied = capture_q35_dxe_diagnostic(&dmar, &mcfg, usb, |base, pages| {
            assert_eq!((base.get(), pages), expected[queries]);
            queries += 1;
            true
        }).unwrap();
        assert_eq!(queries, expected.len());
        let region = |base, pages, kind| {
            MemoryRegion::new(PhysAddr::new(base).unwrap(), pages, kind).unwrap()
        };
        let final_map = [region(0x1000, 1, MemoryKind::Free)];
        let map = MemoryMap::new(&final_map).unwrap();
        assert_eq!(check_q35_dxe_diagnostic(&copied, &dmar, &mcfg, usb, &map), Ok(()));
        let incomplete = capture_q35_dxe_diagnostic(&dmar, &mcfg, usb, |base, _| base.get() != 0xe410_0000).unwrap();
        assert_eq!(check_q35_dxe_diagnostic(&incomplete, &dmar, &mcfg, usb, &map), Err(IncompleteDxe));
        let crate::BootDxeDiagnostic::Copied(mut record) = copied else { panic!("expected copied vector") };
        record[48] ^= 1;
        assert_eq!(check_q35_dxe_diagnostic(&crate::BootDxeDiagnostic::Copied(record),
            &dmar, &mcfg, usb, &map), Err(InvalidRecord));
        for (address, kind) in [
            (0xe410_0000, MemoryKind::Free),
            (0xe410_0000, MemoryKind::Mmio),
            (0xfed9_0000, MemoryKind::Reserved),
            (0x8120_0000, MemoryKind::Kernel),
        ] {
            let conflicts = [region(address, 1, kind)];
            let conflict_map = MemoryMap::new(&conflicts).unwrap();
            assert_eq!(check_q35_dxe_diagnostic(&copied, &dmar, &mcfg, usb, &conflict_map), Err(FinalMapConflict));
        }
        let mut wrong_usb = *usb;
        wrong_usb[13] ^= 1;
        assert_eq!(capture_q35_dxe_diagnostic(&dmar, &mcfg, &wrong_usb, |_, _| {
            panic!("wrong requester must refuse before any firmware query")
        }), Err(InvalidLayout));
        let mut changed_mcfg = mcfg;
        changed_mcfg[44..52].copy_from_slice(&0xd000_0000u64.to_le_bytes());
        checksum(&mut changed_mcfg);
        assert_eq!(check_q35_dxe_diagnostic(&copied, &dmar, &changed_mcfg, usb, &map), Err(InvalidLayout));
        let mut changed_dmar = dmar;
        changed_dmar[77] ^= 1;
        checksum(&mut changed_dmar);
        assert_eq!(check_q35_dxe_diagnostic(&copied, &changed_dmar, &mcfg, usb, &map), Err(InvalidLayout));
    }

    #[test]
    fn cold_profile_extends_only_drhd_write_permission() {
        let cold = q35_fixture_activation_mappings().unwrap();
        let shutdown = q35_fixture_shutdown_mappings().unwrap();
        assert_eq!(cold[1..], shutdown[1..]);
        let drhd = cold[0].unwrap();
        assert_eq!(drhd.physical_start(), shutdown[0].unwrap().physical_start());
        assert_eq!(drhd.virtual_start(), shutdown[0].unwrap().virtual_start());
        assert_eq!(drhd.pages(), 1);
        assert_eq!(
            drhd.permissions(),
            PagePermissions::KERNEL_HIGH_MMIO_READ_WRITE
        );
    }

    #[test]
    fn shutdown_profile_cannot_write_the_controller_or_remapper() {
        let read_only = q35_fixture_probe_mappings(Q35FixtureTopology::Isolated).unwrap();
        let shutdown = q35_fixture_shutdown_mappings().unwrap();
        for (index, (before, after)) in read_only.into_iter().zip(shutdown).enumerate() {
            let (before, after) = (before.unwrap(), after.unwrap());
            assert_eq!(before.physical_start(), after.physical_start());
            assert_eq!(before.virtual_start(), after.virtual_start());
            assert_eq!(after.pages(), 1);
            assert_eq!(
                after.permissions(),
                if index == 1 || index == 2 {
                    PagePermissions::KERNEL_HIGH_MMIO_READ_WRITE
                } else {
                    PagePermissions::KERNEL_MMIO_READ
                }
            );
        }
    }

    fn checksum(table: &mut [u8]) {
        table[9] = 0;
        table[9] = 0u8.wrapping_sub(table.iter().copied().fold(0u8, u8::wrapping_add));
    }

    #[test]
    fn isolated_fixture_requires_exact_scope_and_ro_pages() {
        let good = fixture();
        assert_eq!(
            Q35FixtureTopology::from_dmar(&good),
            Some(Q35FixtureTopology::Isolated)
        );
        let pages = q35_fixture_probe_mappings(Q35FixtureTopology::Isolated).unwrap();
        assert_eq!(
            pages.map(|page| page.unwrap().physical_start().get()),
            [0xfed9_0000, 0xe410_0000, 0xe400_0000, 0x8120_0000]
        );
        assert!(
            pages
                .into_iter()
                .flatten()
                .all(|page| page.permissions() == PagePermissions::KERNEL_MMIO_READ)
        );
        for (at, byte) in [
            (36, 38),
            (37, 1),
            (51, 1),
            (52, 1),
            (66, 1),
            (68, 1),
            (72, 1),
            (77, 0x41),
            (78, 1),
            (79, 1),
        ] {
            let mut wrong = good;
            wrong[at] = byte;
            checksum(&mut wrong);
            assert_eq!(Q35FixtureTopology::from_dmar(&wrong), None, "byte {at}");
        }
        let mut opaque = [0u8; 84];
        opaque[..80].copy_from_slice(&good);
        opaque[4..8].copy_from_slice(&84u32.to_le_bytes());
        opaque[80..].copy_from_slice(&[6, 0, 4, 0]);
        checksum(&mut opaque);
        assert_eq!(Q35FixtureTopology::from_dmar(&opaque), None);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformMmioPurpose {
    VtdBootstrap {
        segment: u16,
    },
    PciEcam {
        segment: u16,
        start_bus: u8,
        end_bus: u8,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlatformMmioRequirement {
    physical: PhysAddr,
    pages: u64,
    purpose: PlatformMmioPurpose,
}

impl PlatformMmioRequirement {
    pub const fn physical(self) -> PhysAddr {
        self.physical
    }

    pub const fn pages(self) -> u64 {
        self.pages
    }

    pub const fn bytes(self) -> u64 {
        self.pages * PAGE_SIZE
    }

    pub const fn purpose(self) -> PlatformMmioPurpose {
        self.purpose
    }

    fn end(self) -> u64 {
        self.physical.get() + self.bytes()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct PlatformMmioManifest<const RANGES: usize> {
    requirements: [Option<PlatformMmioRequirement>; RANGES],
    count: usize,
}

impl<const RANGES: usize> PlatformMmioManifest<RANGES> {
    pub fn from_topology<const UNITS: usize, const SCOPES: usize, const ALLOCATIONS: usize>(
        dmar: &DmarTopology<UNITS, SCOPES>,
        mcfg: &McfgTopology<ALLOCATIONS>,
        memory: &[MemoryRegion],
    ) -> Result<Self, PlatformMmioError> {
        let mut manifest = Self {
            requirements: [None; RANGES],
            count: 0,
        };
        for unit in dmar.units() {
            manifest.push(PlatformMmioRequirement {
                physical: unit.register_base,
                pages: 1,
                purpose: PlatformMmioPurpose::VtdBootstrap {
                    segment: unit.segment,
                },
            })?;
        }
        for allocation in mcfg.allocations() {
            let physical = PhysAddr::new(allocation.physical_start())
                .map_err(|_| PlatformMmioError::InvalidRange)?;
            let pages = u64::try_from(allocation.bytes())
                .map_err(|_| PlatformMmioError::InvalidRange)?
                / PAGE_SIZE;
            manifest.push(PlatformMmioRequirement {
                physical,
                pages,
                purpose: PlatformMmioPurpose::PciEcam {
                    segment: allocation.segment,
                    start_bus: allocation.start_bus,
                    end_bus: allocation.end_bus,
                },
            })?;
        }
        for requirement in manifest.iter() {
            if !memory.iter().any(|region| {
                region.kind() == MemoryKind::Mmio
                    && region.start().get() <= requirement.physical.get()
                    && region.end() >= requirement.end()
            }) {
                return Err(PlatformMmioError::OutsideFirmwareMmio);
            }
        }
        Ok(manifest)
    }

    /// Plan a one-page, passive PCI configuration observation. The memory map
    /// must be the normalized map from the current boot; the BAR is the
    /// controller allocation independently captured from firmware. The plan
    /// is not a mapping and never conveys access to ECAM, BARs or DMA.
    pub fn passive_pci_page(
        &self,
        requester: DeviceAddress,
        memory: &MemoryMap<'_>,
        controller_bar: MemoryRegion,
    ) -> Result<PassivePciPage, PassivePciPageError> {
        let mut candidates = self.iter().filter_map(|window| {
            let PlatformMmioPurpose::PciEcam {
                segment,
                start_bus,
                end_bus,
            } = window.purpose
            else {
                return None;
            };
            (segment == requester.segment() && (start_bus..=end_bus).contains(&requester.bus()))
                .then_some((window, start_bus))
        });
        let (window, start_bus) = candidates.next().ok_or(PassivePciPageError::MissingWindow)?;
        if candidates.next().is_some() {
            return Err(PassivePciPageError::Overlap);
        }
        let start = window.physical.get();
        let end = window.end();
        if controller_bar.kind() != MemoryKind::Mmio {
            return Err(PassivePciPageError::InvalidBar);
        }
        if start < controller_bar.end() && controller_bar.start().get() < end {
            return Err(PassivePciPageError::Overlap);
        }
        if !memory.regions().iter().any(|region| {
            region.kind() == MemoryKind::Mmio && region.start().get() <= start && end <= region.end()
        }) {
            return Err(PassivePciPageError::OutsideFirmwareMmio);
        }
        // Manifest physical_start is already adjusted to start_bus. Apply
        // the bus offset relative to that start, not relative to bus zero.
        let offset = (u64::from(requester.bus() - start_bus) << 20)
            | (u64::from(requester.device()) << 15)
            | (u64::from(requester.function()) << 12);
        let physical = start.checked_add(offset).ok_or(PassivePciPageError::InvalidRange)?;
        if !physical
            .checked_add(PAGE_SIZE)
            .is_some_and(|limit| limit <= end)
        {
            return Err(PassivePciPageError::InvalidRange);
        }
        Ok(PassivePciPage {
            requester,
            controller_bar,
            physical: PhysAddr::new(physical).map_err(|_| PassivePciPageError::InvalidRange)?,
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = PlatformMmioRequirement> + '_ {
        self.requirements[..self.count].iter().flatten().copied()
    }

    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    fn push(&mut self, requirement: PlatformMmioRequirement) -> Result<(), PlatformMmioError> {
        if requirement.pages == 0
            || requirement
                .physical
                .get()
                .checked_add(requirement.bytes())
                .is_none()
        {
            return Err(PlatformMmioError::InvalidRange);
        }
        if self.iter().any(|existing| {
            requirement.physical.get() < existing.end()
                && existing.physical.get() < requirement.end()
        }) {
            return Err(PlatformMmioError::Overlap);
        }
        if self.count == RANGES {
            return Err(PlatformMmioError::ManifestFull);
        }
        self.requirements[self.count] = Some(requirement);
        self.count += 1;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DxeObservationError {
    InvalidLayout,
    InconsistentRoute,
    ResourceOverlap,
    IncompleteDxe,
    ChangedLayout,
    FinalMapConflict,
    InvalidRecord,
}

pub use crate::PASSIVE_DXE_RECORD_BYTES;

/// Copied firmware classifications bound to one requester and one exact ACPI
/// layout. This type is diagnostic data, not an MMIO mapping or capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PassiveDxeObservation {
    layout: PassiveDxeLayout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PassiveDxeLayout {
    requester: DeviceAddress,
    remapper: PhysAddr,
    window: MemoryRegion,
    page: MemoryRegion,
    bar: MemoryRegion,
    remappers: [Option<(u16, MemoryRegion)>; 8],
}

impl PassiveDxeLayout {
    fn from_acpi<const U: usize, const S: usize, const A: usize>(
        route: VtdRequesterRoute,
        dmar: &DmarTopology<U, S>,
        mcfg: &McfgTopology<A>,
        bar: MemoryRegion,
    ) -> Result<Self, DxeObservationError> {
        Self::from_coordinates(route.requester(), route.register_base(), dmar, mcfg, bar)
    }

    fn from_coordinates<const U: usize, const S: usize, const A: usize>(
        requester: DeviceAddress,
        remapper: PhysAddr,
        dmar: &DmarTopology<U, S>,
        mcfg: &McfgTopology<A>,
        bar: MemoryRegion,
    ) -> Result<Self, DxeObservationError> {
        use DxeObservationError::*;
        let entry = mcfg.allocations().find(|entry| {
            entry.segment == requester.segment()
                && (entry.start_bus..=entry.end_bus).contains(&requester.bus())
        }).ok_or(InvalidLayout)?;
        let region = |start, pages| {
            let base = PhysAddr::new(start).map_err(|_| InvalidLayout)?;
            MemoryRegion::new(base, pages, MemoryKind::Mmio).map_err(|_| InvalidLayout)
        };
        let start = entry.physical_start();
        let window = region(start, entry.bytes() as u64 / PAGE_SIZE)?;
        let offset = (u64::from(requester.bus() - entry.start_bus) << 20)
            | (u64::from(requester.device()) << 15)
            | (u64::from(requester.function()) << 12);
        let page = region(start.checked_add(offset).ok_or(InvalidLayout)?, 1)?;
        if page.end() > window.end() || bar.kind() != MemoryKind::Mmio || bar.start().get() == 0 {
            return Err(InvalidLayout);
        }
        if mcfg.allocations().any(|allocation| {
            let start = allocation.physical_start();
            bar.start().get() < start + allocation.bytes() as u64 && start < bar.end()
        }) {
            return Err(ResourceOverlap);
        }
        let mut remappers = [None; 8];
        let mut route_found = false;
        for (index, unit) in dmar.units().enumerate() {
            let frame = region(unit.register_base.get(), 1)?;
            if overlaps_region(frame, bar)
                || mcfg.allocations().any(|allocation| {
                    let start = allocation.physical_start();
                    frame.start().get() < start + allocation.bytes() as u64 && start < frame.end()
                })
                || remappers.iter().flatten().any(|&(_, prior)| overlaps_region(prior, frame))
            {
                return Err(ResourceOverlap);
            }
            route_found |= unit.segment == requester.segment()
                && unit.register_base == remapper;
            *remappers.get_mut(index).ok_or(InvalidLayout)? = Some((unit.segment, frame));
        }
        if !route_found {
            return Err(InconsistentRoute);
        }
        Ok(Self { requester, remapper, window, page, bar, remappers })
    }

    fn diagnostic_record(&self) -> [u8; PASSIVE_DXE_RECORD_BYTES] {
        let mut record = [0; PASSIVE_DXE_RECORD_BYTES];
        record[..8].copy_from_slice(b"MRMLDXE\0");
        record[8..10].copy_from_slice(&1u16.to_le_bytes());
        record[10..12].copy_from_slice(&(PASSIVE_DXE_RECORD_BYTES as u16).to_le_bytes());
        record[12] = self.remappers.iter().flatten().count() as u8;
        let requester = self.requester;
        record[16..18].copy_from_slice(&requester.segment().to_le_bytes());
        record[18] = requester.bus();
        record[19] = requester.device();
        record[20] = requester.function();
        for (offset, value) in [
            (24, self.remapper.get()),
            (32, self.window.start().get()),
            (40, self.window.pages()),
            (48, self.page.start().get()),
            (56, self.bar.start().get()),
            (64, self.bar.pages()),
        ] {
            record[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        for (index, &(segment, range)) in self.remappers.iter().flatten().enumerate() {
            let offset = 72 + 16 * index;
            record[offset..offset + 8].copy_from_slice(&range.start().get().to_le_bytes());
            record[offset + 8..offset + 10].copy_from_slice(&segment.to_le_bytes());
        }
        record
    }

    fn check_record(&self, record: &[u8], memory: &MemoryMap<'_>) -> Result<(), DxeObservationError> {
        // No wire address or count is used for a read, a lookup or a loop bound.
        if record != self.diagnostic_record() {
            return Err(DxeObservationError::InvalidRecord);
        }
        self.check_map(memory)
    }

    fn check_map(&self, memory: &MemoryMap<'_>) -> Result<(), DxeObservationError> {
        for range in self.firmware_ranges().chain(core::iter::once(self.bar)) {
            if memory.regions().iter().copied().any(|entry| {
                overlaps_region(entry, range)
                    && (entry.kind() != MemoryKind::Mmio
                        || entry.start().get() > range.start().get()
                        || entry.end() < range.end())
            }) {
                return Err(DxeObservationError::FinalMapConflict);
            }
        }
        Ok(())
    }

    fn firmware_ranges(&self) -> impl Iterator<Item = MemoryRegion> + '_ {
        [self.window, self.page].into_iter()
            .chain(self.remappers.iter().flatten().map(|&(_, range)| range))
    }
}

fn overlaps_region(left: MemoryRegion, right: MemoryRegion) -> bool {
    left.start().get() < right.end() && right.start().get() < left.end()
}

impl PassiveDxeObservation {
    /// Collect positive DXE classifications for each exact range. The caller
    /// is responsible for sourcing them from live trusted firmware. No reader
    /// is called if the ACPI layout already conflicts.
    pub fn capture<const U: usize, const S: usize, const A: usize>(
        route: VtdRequesterRoute,
        dmar: &DmarTopology<U, S>,
        mcfg: &McfgTopology<A>,
        bar: MemoryRegion,
        mut query: impl FnMut(PhysAddr, u64) -> bool,
    ) -> Result<Self, DxeObservationError> {
        let layout = PassiveDxeLayout::from_acpi(route, dmar, mcfg, bar)?;
        if !layout.firmware_ranges().all(|range| query(range.start(), range.pages())) {
            return Err(DxeObservationError::IncompleteDxe);
        }
        Ok(Self { layout })
    }

    /// Serialize only scalar classifications from the successful live capture.
    /// All integers are little-endian; unused slots and reserved bytes are zero.
    /// The record carries no proof of origin and grants no device access.
    pub fn diagnostic_record(self) -> [u8; PASSIVE_DXE_RECORD_BYTES] {
        self.layout.diagnostic_record()
    }

    /// Compare a trusted boot-stage copy against an independently reconstructed
    /// layout and the final normalized map. A match does not authenticate the
    /// copy, prove active cache policy, or authorize touching a device.
    pub fn check_diagnostic_record<const U: usize, const S: usize, const A: usize>(
        record: &[u8],
        route: VtdRequesterRoute,
        dmar: &DmarTopology<U, S>,
        mcfg: &McfgTopology<A>,
        bar: MemoryRegion,
        memory: &MemoryMap<'_>,
    ) -> Result<(), DxeObservationError> {
        if record.len() != PASSIVE_DXE_RECORD_BYTES {
            return Err(DxeObservationError::InvalidRecord);
        }
        let current = PassiveDxeLayout::from_acpi(route, dmar, mcfg, bar)?;
        current.check_record(record, memory)
    }

    /// Compare independently re-derived coordinates and validate that no
    /// region in the final map conflicts. An entirely absent range is not a
    /// conflict, but neither is it evidence of coverage. This method returns
    /// no resource token and does not replace the ordinary MMIO policy.
    pub fn check_final_map<const U: usize, const S: usize, const A: usize>(
        self,
        route: VtdRequesterRoute,
        dmar: &DmarTopology<U, S>,
        mcfg: &McfgTopology<A>,
        bar: MemoryRegion,
        memory: &MemoryMap<'_>,
    ) -> Result<(), DxeObservationError> {
        let current = PassiveDxeLayout::from_acpi(route, dmar, mcfg, bar)?;
        if self.layout != current {
            return Err(DxeObservationError::ChangedLayout);
        }
        current.check_map(memory)
    }
}

// Reconstruct only the known emulated layout. Never fabricate a VtdRequesterRoute
// or consult registers to validate this diagnostic.
fn q35_dxe_layout(
    dmar_bytes: &[u8],
    mcfg_bytes: &[u8],
    usb: &[u8; crate::BOOT_USB_PCI_RECORD_BYTES],
) -> Result<PassiveDxeLayout, DxeObservationError> {
    use DxeObservationError::InvalidLayout;
    if usb != Q35_SHARED_BOOT_USB_RECORD
        || Q35FixtureTopology::from_dmar(dmar_bytes) != Some(Q35FixtureTopology::Isolated)
    {
        return Err(InvalidLayout);
    }
    let dmar = DmarTopology::<1, 64>::parse(dmar_bytes).map_err(|_| InvalidLayout)?;
    let mcfg = McfgTopology::<1>::parse(mcfg_bytes).map_err(|_| InvalidLayout)?;
    let entry = mcfg.allocations().next().ok_or(InvalidLayout)?;
    if entry.segment != 0 || entry.start_bus != 0 || entry.end_bus != 255
        || entry.physical_start() != 0xe000_0000
    {
        return Err(InvalidLayout);
    }
    let requester = DeviceAddress::new(0, 0x41, 0, 0).map_err(|_| InvalidLayout)?;
    let remapper = dmar.units().next().ok_or(InvalidLayout)?.register_base;
    let base = PhysAddr::new(0x8120_0000).map_err(|_| InvalidLayout)?;
    let bar = MemoryRegion::new(base, 4, MemoryKind::Mmio).map_err(|_| InvalidLayout)?;
    PassiveDxeLayout::from_coordinates(requester, remapper, &dmar, &mcfg, bar)
}

/// Data-only classification for the isolated Q35 fixture. The caller must
/// source query results from its live, validated firmware service.
pub fn capture_q35_dxe_diagnostic(
    dmar: &[u8],
    mcfg: &[u8],
    usb: &[u8; crate::BOOT_USB_PCI_RECORD_BYTES],
    mut query: impl FnMut(PhysAddr, u64) -> bool,
) -> Result<crate::BootDxeDiagnostic, DxeObservationError> {
    let layout = q35_dxe_layout(dmar, mcfg, usb)?;
    let complete = layout.firmware_ranges().all(|range| query(range.start(), range.pages()));
    Ok(if complete {
        crate::BootDxeDiagnostic::Copied(layout.diagnostic_record())
    } else {
        crate::BootDxeDiagnostic::Incomplete
    })
}

/// Rebuild the exact fixture using copied boot ACPI data and the receiver's
/// final normalized memory map. Validation supplies no mapping or capability.
pub fn check_q35_dxe_diagnostic(
    diagnostic: &crate::BootDxeDiagnostic,
    dmar: &[u8],
    mcfg: &[u8],
    usb: &[u8; crate::BOOT_USB_PCI_RECORD_BYTES],
    memory: &MemoryMap<'_>,
) -> Result<(), DxeObservationError> {
    let layout = q35_dxe_layout(dmar, mcfg, usb)?;
    let crate::BootDxeDiagnostic::Copied(record) = diagnostic else {
        return Err(DxeObservationError::IncompleteDxe);
    };
    layout.check_record(record, memory)
}

/// A physical-page candidate for a later independently verified kernel-only,
/// uncached, read-only mapping. No pointer or register access is provided.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PassivePciPage {
    requester: DeviceAddress,
    controller_bar: MemoryRegion,
    physical: PhysAddr,
}

impl PassivePciPage {
    pub const fn requester(self) -> DeviceAddress {
        self.requester
    }

    pub const fn physical(self) -> PhysAddr {
        self.physical
    }

    pub const fn observed_controller_bar(self) -> MemoryRegion {
        self.controller_bar
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PassivePciPageError {
    MissingWindow,
    OutsideFirmwareMmio,
    Overlap,
    InvalidRange,
    InvalidBar,
}

#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedPlatformMmio {
    requirement: PlatformMmioRequirement,
    virtual_start: VirtAddr,
    register_extent: Option<u64>,
}

impl VerifiedPlatformMmio {
    pub(super) const fn register_bytes(&self) -> u64 {
        match self.register_extent {
            Some(exact) => exact,
            None => self.requirement.bytes(),
        }
    }

    pub const fn requirement(&self) -> PlatformMmioRequirement {
        self.requirement
    }

    pub const fn virtual_start(&self) -> VirtAddr {
        self.virtual_start
    }

    pub const fn as_mut_ptr(&self) -> *mut u8 {
        self.virtual_start.get() as *mut u8
    }
}

#[cfg(test)]
pub(crate) fn verified_vtd_for_test(
    physical: PhysAddr,
    pages: u64,
    segment: u16,
) -> VerifiedPlatformMmio {
    VerifiedPlatformMmio {
        requirement: PlatformMmioRequirement {
            physical,
            pages,
            purpose: PlatformMmioPurpose::VtdBootstrap { segment },
        },
        virtual_start: VirtAddr::new(0xffff_9000_0000_0000).unwrap(),
        register_extent: None,
    }
}

#[cfg(test)]
pub(crate) fn verified_vtd_mapping_for_test(
    physical: PhysAddr,
    pages: u64,
    segment: u16,
    virtual_start: VirtAddr,
) -> VerifiedPlatformMmio {
    VerifiedPlatformMmio {
        requirement: PlatformMmioRequirement {
            physical,
            pages,
            purpose: PlatformMmioPurpose::VtdBootstrap { segment },
        },
        virtual_start,
        register_extent: None,
    }
}

/// Observes CPU settings required for the BSP-only read-only MMIO probe.
/// It neither configures the CPU nor proves ownership, lack of aliases across
/// multiple roots, or that stale translations have been invalidated.
///
/// # Safety
/// Run at CPL0 on the boot CPU with interrupts disabled; the calling probe
/// must exclude other users of the hierarchy and prevent CPU reconfiguration.
pub unsafe fn check_boot_mmio_cpu_policy() -> Result<(), PlatformMmioError> {
    use core::arch::{asm, x86_64::__cpuid};

    let basic = __cpuid(0);
    let extended = __cpuid(0x8000_0000);
    if basic.eax < 1
        || extended.eax < 0x8000_0001
        || __cpuid(1).edx & ((1 << 16) | (1 << 5)) != (1 << 16) | (1 << 5)
        || __cpuid(0x8000_0001).edx & (1 << 20) == 0
    {
        return Err(PlatformMmioError::CpuProtection);
    }
    let cr0: u64;
    let cr4: u64;
    let pat_low: u32;
    let efer_low: u32;
    // SAFETY: the caller runs at CPL0 on the boot CPU. CPUID above
    // established architectural MSR, PAT and NX support. Reads change no state.
    unsafe {
        asm!(
            "mov {cr0}, cr0",
            "mov {cr4}, cr4",
            cr0 = out(reg) cr0,
            cr4 = out(reg) cr4,
            options(nostack, preserves_flags)
        );
        asm!("rdmsr", in("ecx") 0x277u32, out("eax") pat_low, out("edx") _,
            options(nostack, preserves_flags));
        asm!("rdmsr", in("ecx") 0xc000_0080u32, out("eax") efer_low, out("edx") _,
            options(nostack, preserves_flags));
    }
    validate_boot_mmio_cpu(cr0, cr4, pat_low, efer_low)
}

fn validate_boot_mmio_cpu(
    cr0: u64,
    cr4: u64,
    pat_low: u32,
    efer_low: u32,
) -> Result<(), PlatformMmioError> {
    // Supervisor reads must use the exact RO/NX 4 KiB translations. Require
    // WP, NXE and four-level paging, and architectural UC (not UC-minus).
    // The loader retires firmware's global and tagged translations before
    // changing roots; require PGE and PCIDE to still be off on entry.
    if cr0 & (1 << 16) == 0
        || cr4 & ((1 << 7) | (1 << 12) | (1 << 17)) != 0
        || efer_low & (1 << 11) == 0
        || pat_low >> 24 != 0
    {
        return Err(PlatformMmioError::CpuProtection);
    }
    Ok(())
}

const CACHE_WB: u8 = 6;
const MAX_BOOT_VARIABLE_MTRRS: u8 = 16;
const MTRR_ENABLE: u64 = 1 << 11;

/// Checks the architectural WB subset needed by the boot DMA fixture. This
/// is not a general MTRR interpreter: fixed ranges and mixed-type overlaps
/// are not accepted. It does not establish RAM ownership or device authority.
fn boot_dma_write_back(
    physical: core::ops::Range<u64>,
    physical_bits: u8,
    cr0: u64,
    pat: u64,
    default_type: u64,
    count: u8,
    mut range: impl FnMut(u8) -> (u64, u64),
) -> bool {
    if !(32..=52).contains(&physical_bits)
        || count > MAX_BOOT_VARIABLE_MTRRS
        || cr0 & ((1 << 30) | (1 << 29)) != 0
        || pat as u8 != CACHE_WB
        || default_type & MTRR_ENABLE == 0
        || default_type & !(0xff | (1 << 10) | MTRR_ENABLE) != 0
        || !matches!(default_type as u8, 0 | 1 | 4 | 5 | CACHE_WB)
        || physical.start < 0x10_0000
        || physical.start >= physical.end
        || physical.end > 1 << 32
        || physical.end - physical.start > 16 * PAGE_SIZE
        || (physical.start | physical.end) & (PAGE_SIZE - 1) != 0
    {
        return false;
    }

    let address_mask = ((1u64 << physical_bits) - 1) & !(PAGE_SIZE - 1);
    let mut covered = 0u32;
    for index in 0..count {
        let (base, mask) = range(index);
        if mask & MTRR_ENABLE == 0 {
            continue;
        }
        let address = base & address_mask;
        let size = ((!mask & address_mask) | (PAGE_SIZE - 1)) + 1;
        if base & !(address_mask | 0xff) != 0
            || mask & !(address_mask | MTRR_ENABLE) != 0
            || !size.is_power_of_two()
            || address & (size - 1) != 0
        {
            return false;
        }
        let start = physical.start.max(address);
        let end = physical.end.min(address + size);
        if start >= end {
            continue;
        }
        if base as u8 != CACHE_WB {
            return false;
        }
        for page in (start - physical.start) / PAGE_SIZE..(end - physical.start) / PAGE_SIZE {
            covered |= 1 << page;
        }
    }
    default_type as u8 == CACHE_WB
        || covered == (1 << ((physical.end - physical.start) / PAGE_SIZE)) - 1
}

/// Reads only BSP cache policy for the exact boot allocation.
///
/// # Safety
/// The caller holds the BSP at CPL0 with interrupts disabled, before APs
/// start. It excludes cache-policy changes through subsequent use.
pub(super) unsafe fn check_boot_dma_write_back(physical: core::ops::Range<u64>) -> bool {
    use core::arch::{asm, x86_64::__cpuid};

    const REQUIRED: u32 = (1 << 5) | (1 << 12) | (1 << 16);
    if __cpuid(0).eax < 1
        || __cpuid(1).edx & REQUIRED != REQUIRED
        || __cpuid(0x8000_0000).eax < 0x8000_0008
    {
        return false;
    }
    let width = __cpuid(0x8000_0008).eax as u8;
    let read_msr = |index: u32| {
        let low: u32;
        let high: u32;
        // SAFETY: the caller owns CPL0 and CPUID established MSR/MTRR/PAT
        // support; variable pairs are bounded by IA32_MTRRCAP below.
        unsafe {
            asm!("rdmsr", in("ecx") index, out("eax") low, out("edx") high,
                options(nostack, preserves_flags));
        }
        (u64::from(high) << 32) | u64::from(low)
    };
    let cr0: u64;
    // SAFETY: CPL0 read only; this changes neither the CPU nor table state.
    unsafe { asm!("mov {}, cr0", out(reg) cr0, options(nostack, preserves_flags)) };
    boot_dma_write_back(
        physical,
        width,
        cr0,
        read_msr(0x277),
        read_msr(0x2ff),
        read_msr(0xfe) as u8,
        |index| {
            let base = 0x200 + u32::from(index) * 2;
            (read_msr(base), read_msr(base + 1))
        },
    )
}

/// Verifies an already installed active mapping page by page before issuing a
/// token usable by native MMIO adapters.
pub fn verify_active_platform_mmio(
    active: &ActivePageTables,
    requirement: PlatformMmioRequirement,
    mapping: Mapping,
) -> Result<VerifiedPlatformMmio, PlatformMmioError> {
    if mapping.physical_start() != requirement.physical
        || mapping.pages() != requirement.pages
        || mapping.permissions() != PagePermissions::KERNEL_MMIO_READ_WRITE
    {
        return Err(PlatformMmioError::MappingMismatch);
    }
    for page in 0..requirement.pages {
        let offset = page
            .checked_mul(PAGE_SIZE)
            .ok_or(PlatformMmioError::InvalidRange)?;
        let virtual_address = VirtAddr::new(
            mapping
                .virtual_start()
                .get()
                .checked_add(offset)
                .ok_or(PlatformMmioError::InvalidRange)?,
        )
        .map_err(|_| PlatformMmioError::InvalidRange)?;
        let leaf = active
            .leaf(virtual_address)
            .map_err(|_| PlatformMmioError::PageTable)?
            .ok_or(PlatformMmioError::MappingMismatch)?;
        let expected = requirement
            .physical
            .get()
            .checked_add(offset)
            .ok_or(PlatformMmioError::InvalidRange)?;
        if leaf.physical().get() != expected
            || !leaf.writable()
            || leaf.executable()
            || leaf.user()
            || !leaf.device_pat_index_three()
        {
            return Err(PlatformMmioError::MappingMismatch);
        }
    }
    Ok(VerifiedPlatformMmio {
        requirement,
        virtual_start: mapping.virtual_start(),
        register_extent: None,
    })
}

/// Consume the fixture's verified mapping to bound the native adapter.
///
/// # Safety
/// The caller must hold the current BSP root and exclusive ownership of
/// the exact isolated QEMU subtree and DRHD. Both independent host releases
/// are required, after model inspection and after all scoped BME is off.
pub unsafe fn verify_q35_activation_mmio(
    active: &ActivePageTables,
    dmar: &[u8],
) -> Result<VerifiedPlatformMmio, PlatformMmioError> {
    if Q35FixtureTopology::from_dmar(dmar) != Some(Q35FixtureTopology::Isolated) {
        return Err(PlatformMmioError::MappingMismatch);
    }
    if active.verify_q35_activation_leaves().is_err()
    {
        return Err(PlatformMmioError::PageTable);
    }
    let page = q35_fixture_activation_mappings()?[0].ok_or(PlatformMmioError::InvalidRange)?;
    Ok(VerifiedPlatformMmio {
        requirement: PlatformMmioRequirement {
            physical: page.physical_start(),
            pages: 1,
            purpose: PlatformMmioPurpose::VtdBootstrap { segment: 0 },
        },
        virtual_start: page.virtual_start(),
        register_extent: Some(0x230),
    })
}

/// Replaces a DRHD bootstrap requirement with its complete capability-derived
/// register extent. The result must be mapped and independently PTE-verified.
pub fn extend_vtd_mmio_requirement(
    bootstrap: PlatformMmioRequirement,
    layout: VtdRegisterLayout,
    memory: &[MemoryRegion],
) -> Result<PlatformMmioRequirement, PlatformMmioError> {
    if bootstrap.pages != 1
        || !matches!(bootstrap.purpose, PlatformMmioPurpose::VtdBootstrap { .. })
        || layout.pages() == 0
    {
        return Err(PlatformMmioError::MappingMismatch);
    }
    let extended = PlatformMmioRequirement {
        physical: bootstrap.physical,
        pages: layout.pages(),
        purpose: bootstrap.purpose,
    };
    if !memory.iter().any(|region| {
        region.kind() == MemoryKind::Mmio
            && region.start().get() <= extended.physical.get()
            && region.end() >= extended.end()
    }) {
        return Err(PlatformMmioError::OutsideFirmwareMmio);
    }
    Ok(extended)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dma_cache_policy_requires_complete_wb_coverage_and_no_mixed_overlap() {
        const ADDRESS_MASK: u64 = 0xf_ffff_f000;
        let pair = |base: u64, bytes: u64, ty: u64| {
            (base | ty, (ADDRESS_MASK & !(bytes - 1u64)) | MTRR_ENABLE)
        };
        let pages = 0x201000..0x205000;
        let check = |default_type, pairs: &[(u64, u64)]| {
            boot_dma_write_back(
                pages.clone(),
                36,
                0,
                6,
                MTRR_ENABLE | default_type,
                pairs.len() as u8,
                |i| pairs[usize::from(i)],
            )
        };
        assert!(check(6, &[]));
        assert!(check(0, &[pair(0x200000, 0x200000, 6)]));
        assert!(check(
            0,
            &[pair(0x200000, 0x4000, 6), pair(0x204000, 0x1000, 6)]
        ));
        assert!(!check(0, &[pair(0x200000, 0x4000, 6)]));
        assert!(!check(6, &[pair(0x204000, 0x1000, 0)]));
        assert!(check(6, &[pair(0x205000, 0x1000, 0)]));
        assert!(!check(6, &[(0, ADDRESS_MASK ^ 0x2000 | MTRR_ENABLE)]));
        assert!(!check(6, &[pair(0x201000, 0x2000, 6)]));
        assert!(!check(6, &[(1 << 36, ADDRESS_MASK | MTRR_ENABLE)]));
        assert!(check(6, &[(u64::MAX, 0)]));
    }

    #[test]
    fn dma_cache_policy_rejects_disabled_caching_and_out_of_scope_inputs() {
        let range = 0x100000..0x110000;
        for (cr0, pat, mtrr, width, count) in [
            (1 << 30, 6, MTRR_ENABLE | 6, 36, 0),
            (1 << 29, 6, MTRR_ENABLE | 6, 36, 0),
            (0, 0, MTRR_ENABLE | 6, 36, 0),
            (0, 6, 6, 36, 0),
            (0, 6, MTRR_ENABLE | 2, 36, 0),
            (0, 6, MTRR_ENABLE | 6, 53, 0),
            (0, 6, MTRR_ENABLE | 6, 36, 17),
        ] {
            assert!(!boot_dma_write_back(
                range.clone(),
                width,
                cr0,
                pat,
                mtrr,
                count,
                |_| panic!("invalid policy must not read variable MTRRs")
            ));
        }
        for range in [
            0xff000..0x100000,
            0x100000..0x111000,
            0x100001..0x110000,
            0x100000..0x100000,
            0x1_0000_0000..0x1_0000_1000,
        ] {
            assert!(!boot_dma_write_back(
                range,
                36,
                0,
                6,
                MTRR_ENABLE | 6,
                0,
                |_| unreachable!()
            ));
        }
    }

    #[test]
    fn boot_mmio_cpu_requires_wp_nxe_four_level_and_exact_uc() {
        let wp = 1 << 16;
        let nxe = 1 << 11;
        assert_eq!(validate_boot_mmio_cpu(wp, 0, 0x0007_0406, nxe), Ok(()));
        for (cr0, cr4, pat, efer) in [
            (0, 0, 0, nxe),
            (wp, 1 << 7, 0, nxe),
            (wp, 1 << 12, 0, nxe),
            (wp, 1 << 17, 0, nxe),
            (wp, 0, 0, 0),
            (wp, 0, 0x0700_0000, nxe),
            (wp, 0, 0x0600_0000, nxe),
        ] {
            assert_eq!(
                validate_boot_mmio_cpu(cr0, cr4, pat, efer),
                Err(PlatformMmioError::CpuProtection)
            );
        }
    }

    fn finalize(table: &mut [u8]) {
        table[9] = 0;
        let sum = table.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
        table[9] = 0u8.wrapping_sub(sum);
    }

    fn dmar(register: u64) -> [u8; 64] {
        let mut table = [0u8; 64];
        table[..4].copy_from_slice(b"DMAR");
        table[4..8].copy_from_slice(&64u32.to_le_bytes());
        table[36] = 47;
        table[48..50].copy_from_slice(&0u16.to_le_bytes());
        table[50..52].copy_from_slice(&16u16.to_le_bytes());
        table[52] = 1;
        table[56..64].copy_from_slice(&register.to_le_bytes());
        finalize(&mut table);
        table
    }

    fn mcfg(base: u64) -> [u8; 60] {
        let mut table = [0u8; 60];
        table[..4].copy_from_slice(b"MCFG");
        table[4..8].copy_from_slice(&60u32.to_le_bytes());
        table[44..52].copy_from_slice(&base.to_le_bytes());
        finalize(&mut table);
        table
    }

    #[test]
    fn manifest_requires_firmware_mmio_coverage() {
        let dmar = DmarTopology::<1, 0>::parse(&dmar(0xfed9_0000)).unwrap();
        let mcfg = McfgTopology::<1>::parse(&mcfg(0xe000_0000)).unwrap();
        let memory = [
            MemoryRegion::new(PhysAddr::new(0xe000_0000).unwrap(), 256, MemoryKind::Mmio).unwrap(),
            MemoryRegion::new(PhysAddr::new(0xfed9_0000).unwrap(), 1, MemoryKind::Mmio).unwrap(),
        ];
        let manifest = PlatformMmioManifest::<2>::from_topology(&dmar, &mcfg, &memory).unwrap();
        assert_eq!(manifest.len(), 2);
        assert!(matches!(
            manifest.iter().next().unwrap().purpose(),
            PlatformMmioPurpose::VtdBootstrap { segment: 0 }
        ));

        let wrong_kind = [MemoryRegion::new(
            PhysAddr::new(0xe000_0000).unwrap(),
            256,
            MemoryKind::Reserved,
        )
        .unwrap()];
        assert_eq!(
            PlatformMmioManifest::<2>::from_topology(&dmar, &mcfg, &wrong_kind),
            Err(PlatformMmioError::OutsideFirmwareMmio)
        );
    }

    #[test]
    fn manifest_rejects_cross_purpose_physical_overlap() {
        let dmar = DmarTopology::<1, 0>::parse(&dmar(0xe000_0000)).unwrap();
        let mcfg = McfgTopology::<1>::parse(&mcfg(0xe000_0000)).unwrap();
        let memory =
            [
                MemoryRegion::new(PhysAddr::new(0xe000_0000).unwrap(), 256, MemoryKind::Mmio)
                    .unwrap(),
            ];
        assert_eq!(
            PlatformMmioManifest::<2>::from_topology(&dmar, &mcfg, &memory),
            Err(PlatformMmioError::Overlap)
        );
    }

    #[test]
    fn dxe_observation_rejects_incomplete_evidence_layout_drift_and_final_conflicts() {
        use DxeObservationError::*;
        let requester = DeviceAddress::new(0, 0, 20, 0).unwrap();
        let dmar = DmarTopology::<1, 0>::parse(&dmar(0xfed9_1000)).unwrap();
        let mcfg = McfgTopology::<1>::parse(&mcfg(0xe000_0000)).unwrap();
        let base = |raw| PhysAddr::new(raw).unwrap();
        let region = |raw, pages, kind| MemoryRegion::new(base(raw), pages, kind).unwrap();
        let route = VtdRequesterRoute::for_test(requester, base(0xfed9_1000));
        let bar = region(0xceef_0000, 16, MemoryKind::Mmio);
        let expected = [(0xe000_0000, 256), (0xe00a_0000, 1), (0xfed9_1000, 1)];
        let mut count = 0;
        let observation = PassiveDxeObservation::capture(route, &dmar, &mcfg, bar, |start, pages| {
            assert_eq!((start.get(), pages), expected[count]);
            count += 1;
            true
        }).unwrap();
        assert_eq!(count, expected.len());
        assert_eq!(PassiveDxeObservation::capture(route, &dmar, &mcfg, bar, |start, _| {
            start.get() != 0xe00a_0000
        }), Err(IncompleteDxe));
        let colliding_bar = region(0xfed9_1000, 1, MemoryKind::Mmio);
        assert_eq!(PassiveDxeObservation::capture(route, &dmar, &mcfg, colliding_bar, |_, _| {
            panic!("overlap must reject before first query")
        }), Err(ResourceOverlap));
        let wrong_route = VtdRequesterRoute::for_test(requester, base(0xfed9_0000));
        assert_eq!(PassiveDxeObservation::capture(wrong_route, &dmar, &mcfg, bar, |_, _| {
            panic!("wrong route must reject before first query")
        }), Err(InconsistentRoute));

        let unrelated = region(0x1000, 1, MemoryKind::Free);
        let check = |regions: &[MemoryRegion]| {
            observation.check_final_map(route, &dmar, &mcfg, bar, &MemoryMap::new(regions).unwrap())
        };
        assert_eq!(check(&[unrelated]), Ok(()));
        assert_eq!(check(&[
            bar,
            region(0xe000_0000, 256, MemoryKind::Mmio),
            region(0xfed9_1000, 1, MemoryKind::Mmio),
        ]), Ok(()));
        for conflict in [
            region(0xe00a_0000, 1, MemoryKind::Free),
            region(0xe00a_0000, 1, MemoryKind::Mmio),
            region(0xfed9_1000, 1, MemoryKind::Reserved),
            region(0xceef_0000, 1, MemoryKind::Kernel),
        ] {
            assert_eq!(check(&[unrelated, conflict]), Err(FinalMapConflict));
        }
        let map = MemoryMap::new(core::slice::from_ref(&unrelated)).unwrap();
        let record = observation.diagnostic_record();
        assert_eq!(&record[..13], b"MRMLDXE\0\x01\x00\xc8\x00\x01");
        assert_eq!(&record[16..21], &[0, 0, 0, 20, 0]);
        assert_eq!(&record[72..80], &0xfed9_1000u64.to_le_bytes());
        assert_eq!(&record[82..], &[0; PASSIVE_DXE_RECORD_BYTES - 82]);
        let validate = |bytes: &[u8], memory: &MemoryMap<'_>| {
            PassiveDxeObservation::check_diagnostic_record(bytes, route, &dmar, &mcfg, bar, memory)
        };
        assert_eq!(validate(&record, &map), Ok(()));
        for length in 0..PASSIVE_DXE_RECORD_BYTES {
            assert_eq!(validate(&record[..length], &map), Err(InvalidRecord));
        }
        let mut extended = [0; PASSIVE_DXE_RECORD_BYTES + 1];
        extended[..PASSIVE_DXE_RECORD_BYTES].copy_from_slice(&record);
        assert_eq!(validate(&extended, &map), Err(InvalidRecord));
        for offset in 0..record.len() {
            let mut changed = record;
            changed[offset] ^= 1;
            assert_eq!(validate(&changed, &map), Err(InvalidRecord), "byte {offset}");
        }
        let conflict = region(0xe00a_0000, 1, MemoryKind::Free);
        let conflict_map = MemoryMap::new(core::slice::from_ref(&conflict)).unwrap();
        assert_eq!(validate(&record, &conflict_map), Err(FinalMapConflict));
        let moved_mcfg = McfgTopology::<1>::parse(&self::mcfg(0xe100_0000)).unwrap();
        assert_eq!(observation.check_final_map(route, &dmar, &moved_mcfg, bar, &map), Err(ChangedLayout));
        let sibling = VtdRequesterRoute::for_test(DeviceAddress::new(0, 0, 20, 1).unwrap(), base(0xfed9_1000));
        assert_eq!(observation.check_final_map(sibling, &dmar, &mcfg, bar, &map), Err(ChangedLayout));
        let moved_bar = region(0xcef0_0000, 16, MemoryKind::Mmio);
        assert_eq!(
            observation.check_final_map(route, &dmar, &mcfg, moved_bar, &map),
            Err(ChangedLayout)
        );
    }

    #[test]
    fn passive_pci_plan_bounds_the_exact_function_and_rechecks_the_memory_map() {
        let dmar = DmarTopology::<1, 0>::parse(&dmar(0xfed9_0000)).unwrap();
        let mut table = mcfg(0xe000_0000);
        table[52..54].copy_from_slice(&7u16.to_le_bytes());
        table[54] = 42;
        table[55] = 43;
        finalize(&mut table);
        let mcfg = McfgTopology::<1>::parse(&table).unwrap();
        let region = |address, pages, kind| {
            MemoryRegion::new(PhysAddr::new(address).unwrap(), pages, kind).unwrap()
        };
        let bar = region(0xceef_0000, 16, MemoryKind::Mmio);
        let ecam = region(0xe2a0_0000, 512, MemoryKind::Mmio);
        let memory = [bar, ecam, region(0xfed9_0000, 1, MemoryKind::Mmio)];
        let manifest = PlatformMmioManifest::<2>::from_topology(&dmar, &mcfg, &memory).unwrap();
        let map = MemoryMap::new(&memory).unwrap();
        for (bus, dev, f, physical) in [
            (42, 0, 0, 0xe2a0_0000),
            (42, 20, 0, 0xe2aa_0000),
            (43, 31, 7, 0xe2bf_f000),
        ] {
            let requester = DeviceAddress::new(7, bus, dev, f).unwrap();
            let page = manifest.passive_pci_page(requester, &map, bar).unwrap();
            assert_eq!(page.requester(), requester);
            assert_eq!(page.physical().get(), physical);
        }
        for (segment, bus) in [(0, 42), (7, 41), (7, 44)] {
            let requester = DeviceAddress::new(segment, bus, 20, 0).unwrap();
            assert_eq!(
                manifest.passive_pci_page(requester, &map, bar),
                Err(PassivePciPageError::MissingWindow)
            );
        }
        let requester = DeviceAddress::new(7, 42, 20, 0).unwrap();
        let collision = region(0xe2bf_f000, 1, MemoryKind::Mmio);
        assert_eq!(
            manifest.passive_pci_page(requester, &map, collision),
            Err(PassivePciPageError::Overlap)
        );
        let reserved = region(0xceef_0000, 16, MemoryKind::Reserved);
        assert_eq!(
            manifest.passive_pci_page(requester, &map, reserved),
            Err(PassivePciPageError::InvalidBar)
        );
        let fake_maps = [
            [bar, region(0xe2aa_0000, 1, MemoryKind::Mmio)],
            [bar, region(0xe2a0_0000, 512, MemoryKind::Reserved)],
        ];
        for fake in fake_maps {
            let map = MemoryMap::new(&fake).unwrap();
            assert_eq!(
                manifest.passive_pci_page(requester, &map, bar),
                Err(PassivePciPageError::OutsideFirmwareMmio)
            );
        }
        assert!(MemoryMap::new(&[ecam, collision]).is_err());
    }

    #[test]
    fn capability_extension_requires_complete_mmio_coverage() {
        let dmar = DmarTopology::<1, 0>::parse(&dmar(0xfed9_0000)).unwrap();
        let mcfg = McfgTopology::<1>::parse(&mcfg(0xe000_0000)).unwrap();
        let full_memory = [
            MemoryRegion::new(PhysAddr::new(0xe000_0000).unwrap(), 256, MemoryKind::Mmio).unwrap(),
            MemoryRegion::new(PhysAddr::new(0xfed9_0000).unwrap(), 2, MemoryKind::Mmio).unwrap(),
        ];
        let manifest =
            PlatformMmioManifest::<2>::from_topology(&dmar, &mcfg, &full_memory).unwrap();
        let bootstrap = manifest.iter().next().unwrap();
        let layout = VtdRegisterLayout::from_capabilities(0x100 << 24, 0x20 << 8).unwrap();
        assert_eq!(layout.pages(), 2);
        assert_eq!(
            extend_vtd_mmio_requirement(bootstrap, layout, &full_memory)
                .unwrap()
                .pages(),
            2
        );
        let bootstrap_only =
            [
                MemoryRegion::new(PhysAddr::new(0xfed9_0000).unwrap(), 1, MemoryKind::Mmio)
                    .unwrap(),
            ];
        assert_eq!(
            extend_vtd_mmio_requirement(bootstrap, layout, &bootstrap_only),
            Err(PlatformMmioError::OutsideFirmwareMmio)
        );
    }
}
