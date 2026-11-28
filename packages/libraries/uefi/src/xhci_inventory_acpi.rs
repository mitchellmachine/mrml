use super::{TextOutput, check, line};
use mrml_kernel::arch::x86_64::{
    AcpiError, AcpiMemory, DmarError, DmarTopology, McfgError, McfgTopology, PciConfigSpace,
    DxeObservationError, PassiveDxeObservation, PlatformMmioError, PlatformMmioManifest,
    VtdRequesterRoute, copy_dmar, copy_mcfg,
};
use mrml_kernel::{DeviceAddress, MAX_HANDOFF_DMA_ACPI_TABLE_BYTES, MemoryKind, MemoryMap, MemoryRegion, PhysAddr};
use mrml_uefi::{
    ACPI_20_TABLE_GUID, ACPI_TABLE_GUID, BootServices, MAX_MEMORY_MAP_BYTES, MemoryDescriptor,
    MAX_NORMALIZED_REGIONS, Status, SystemTable,
};

use mrml_uefi::dxe_mmio::{DxeMmioError, dxe_boot_services_contains, inspect_dxe_mmio};

const PAGE: usize = 4096;
const MAP_PAGES: usize = MAX_MEMORY_MAP_BYTES.div_ceil(PAGE);

pub(super) struct Tables {
    mcfg: Result<McfgTopology<8>, TableError<McfgError>>,
    dmar: Result<DmarTopology<8, 64>, TableError<DmarError>>,
    regions: [MemoryRegion; MAX_NORMALIZED_REGIONS],
    region_count: Option<usize>,
    dxe: DxeEvidence,
}

type DxeResult = Result<(), DxeMmioError>;

#[derive(Default)]
struct DxeEvidence {
    requester: Option<DeviceAddress>,
    ecam: Option<DxeResult>,
    page: Option<DxeResult>,
    drhd: [Option<DxeResult>; 8],
}

fn dxe_label(value: Option<DxeResult>) -> &'static str {
    match value {
        Some(Ok(())) => "mmio-uc-capable",
        Some(Err(DxeMmioError::Unavailable)) => "unavailable",
        Some(Err(DxeMmioError::MalformedTable)) => "table-unverified",
        Some(Err(DxeMmioError::NotUncacheableMmio)) => "not-mmio-uc-capable",
        Some(Err(DxeMmioError::QueryFailed)) => "query-failed",
        Some(Err(_)) => "range-unverified",
        None => "not-queried",
    }
}

fn ecam_page(entry: &mrml_kernel::arch::x86_64::McfgAllocation, requester: DeviceAddress) -> Option<u64> {
    if entry.segment != requester.segment()
        || !(entry.start_bus..=entry.end_bus).contains(&requester.bus())
    {
        return None;
    }
    let offset = (u64::from(requester.bus() - entry.start_bus) << 20)
        | (u64::from(requester.device()) << 15)
        | (u64::from(requester.function()) << 12);
    entry.physical_start().checked_add(offset)
}

enum TableError<E> {
    Read(AcpiError),
    Invalid(E),
}

impl<E: core::fmt::Debug> core::fmt::Display for TableError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Read(err) => write!(f, "{err:?}"),
            Self::Invalid(err) => write!(f, "{err:?}"),
        }
    }
}

impl Tables {
    /// Returns only a diagnostic verdict. No physical mapping or raw device
    /// read is performed, even when all reported inputs agree.
    pub(super) fn passive_pci_plan(
        &self,
        requester: DeviceAddress,
        bar_base: u64,
        bar_bytes: u32,
        route: Option<VtdRequesterRoute>,
        mut report: impl FnMut(core::fmt::Arguments<'_>) -> Result<(), Status>,
    ) -> Result<&'static str, Status> {
        let (Ok(mcfg), Ok(dmar), Some(route)) = (&self.mcfg, &self.dmar, route) else {
            return Ok("MCFG or DMAR route unproven");
        };
        if route.requester() != requester {
            return Ok("DMAR route does not match requester");
        }
        let drhd = route.register_base().get();
        let Some(count) = self.region_count else {
            return Ok("firmware map invalid");
        };
        let Ok(map) = MemoryMap::new(&self.regions[..count]) else {
            return Ok("firmware map invalid");
        };
        let length = u64::from(bar_bytes);
        let bar = PhysAddr::new(bar_base).ok().and_then(|base| {
            length.is_multiple_of(PAGE as u64).then_some(length / PAGE as u64)
                .and_then(|pages| MemoryRegion::new(base, pages, MemoryKind::Mmio).ok())
        });
        let Some(bar) = bar else {
            return Ok("BAR extent unproven");
        };
        use mrml_uefi::xhci_inventory::pci_inventory_coverage;
        for entry in mcfg.allocations() {
            let start = entry.physical_start();
            let end = start + entry.bytes() as u64;
            let coverage = pci_inventory_coverage(&map, start, end);
            let segment = entry.segment;
            report(format_args!("xhci map ECAM seg={segment:04x} {start:#x}..{end:#x}: {coverage}"))?;
            if let Some(page) = ecam_page(entry, requester) {
                let page_end = page + PAGE as u64;
                let coverage = pci_inventory_coverage(&map, page, page_end);
                report(format_args!("xhci map PCI page {page:#x}..{page_end:#x}: {coverage}"))?;
                let (window, page) = (dxe_label(self.dxe.ecam), dxe_label(self.dxe.page));
                report(format_args!("xhci DXE ECAM window={window} page={page}"))?;
            }
        }
        for (index, unit) in dmar.units().enumerate() {
            let start = unit.register_base.get();
            let Some(end) = start.checked_add(PAGE as u64) else {
                return Ok("remapper range invalid");
            };
            let coverage = pci_inventory_coverage(&map, start, end);
            let role = if start == drhd { "routed" } else { "other" };
            report(format_args!("xhci map DRHD {role} {start:#x}..{end:#x}: {coverage}"))?;
            let status = dxe_label(self.dxe.drhd[index]);
            report(format_args!("xhci DXE DRHD {role} {start:#x}: {status}"))?;
        }
        let start = bar.start().get();
        let end = bar.end();
        let coverage = pci_inventory_coverage(&map, start, end);
        report(format_args!("xhci map BAR0 {start:#x}..{end:#x}: {coverage} (inventory only)"))?;
        if dmar.units().any(|unit| {
            let start = unit.register_base.get();
            start < bar.end()
                && start.checked_add(PAGE as u64).is_none_or(|end| bar.start().get() < end)
        }) || !dmar.units().any(|unit| unit.register_base.get() == drhd) {
            return Ok("BAR and remapper ranges conflict");
        }
        let observation = PassiveDxeObservation::capture(route, dmar, mcfg, bar, |base, pages| {
            if self.dxe.requester != Some(requester) {
                return false;
            }
            let base = base.get();
            for entry in mcfg.allocations() {
                if let Some(page) = ecam_page(entry, requester) {
                    if base == entry.physical_start() && pages == entry.bytes() as u64 / PAGE as u64 {
                        return self.dxe.ecam == Some(Ok(()));
                    }
                    if base == page && pages == 1 {
                        return self.dxe.page == Some(Ok(()));
                    }
                }
            }
            pages == 1 && dmar.units().zip(self.dxe.drhd.iter()).any(|(unit, result)| {
                unit.register_base.get() == base && *result == Some(Ok(()))
            })
        });
        let diagnostic = match observation {
            Ok(observation) => match PassiveDxeObservation::check_diagnostic_record(
                &observation.diagnostic_record(), route, dmar, mcfg, bar, &map,
            ) {
                Ok(()) => "copy matched pre-exit snapshot only",
                Err(_) => "refused; pre-exit map conflict",
            },
            Err(DxeObservationError::IncompleteDxe) => "refused; incomplete firmware classification",
            Err(_) => "refused; resource layout unverified",
        };
        report(format_args!("xhci DXE copy: {diagnostic}"))?;
        let manifest = match PlatformMmioManifest::<16>::from_topology(dmar, mcfg, map.regions()) {
            Ok(manifest) => manifest,
            Err(PlatformMmioError::Overlap) => return Ok("ACPI resource ranges overlap"),
            Err(PlatformMmioError::OutsideFirmwareMmio) => return Ok("explicit firmware MMIO coverage missing"),
            Err(_) => return Ok("ACPI topology unproven"),
        };
        if manifest.passive_pci_page(requester, &map, bar).is_err() {
            return Ok("exact PCI page or BAR separation unproven");
        }
        Ok("candidate only; no mapping or register access")
    }

    // SAFETY: output is the live firmware console.
    pub(super) unsafe fn report(
        &self,
        output: *mut TextOutput,
        requester: DeviceAddress,
        config: &mut impl PciConfigSpace,
    ) -> Result<(bool, Option<(usize, VtdRequesterRoute)>), Status> {
        // SAFETY: the caller supplies the live console and the read-only tables are local.
        unsafe {
            let covered = match &self.mcfg {
                Ok(mcfg) => {
                    let covered = mcfg.allocations().any(|entry| {
                        entry.segment == requester.segment()
                            && (entry.start_bus..=entry.end_bus).contains(&requester.bus())
                    });
                    line(
                        output,
                        format_args!(
                            "xhci MCFG: valid, entries={}, covered={covered}",
                            mcfg.allocations().count()
                        ),
                    )?;
                    covered
                }
                Err(err) => {
                    line(output, format_args!("xhci MCFG: {err}"))?;
                    false
                }
            };
            let route = match &self.dmar {
                Ok(dmar) => match dmar.route_for_requester(requester, config) {
                    Ok(route) => {
                        let units = dmar.units().count();
                        let base = route.register_base().get();
                        line(
                            output,
                            format_args!("xhci DMAR: valid, units={units}, DRHD={base:#x}"),
                        )?;
                        Some((units, route))
                    }
                    Err(err) => {
                        line(output, format_args!("xhci DMAR: no validated route ({err:?})"))?;
                        None
                    }
                },
                Err(err) => {
                    line(output, format_args!("xhci DMAR: {err}"))?;
                    None
                }
            };
            Ok((covered, route))
        }
    }
}

struct FirmwareMap<'a> {
    bytes: &'a [u8],
    stride: usize,
}

impl AcpiMemory for FirmwareMap<'_> {
    fn read_exact(&mut self, base: u64, output: &mut [u8]) -> bool {
        let Some(end) = base.checked_add(output.len() as u64) else {
            return false;
        };
        if base == 0 || end > isize::MAX as u64 {
            return false;
        }
        let mut admitted = false;
        for descriptor in self.bytes.chunks_exact(self.stride) {
            let kind = u32::from_le_bytes(descriptor[..4].try_into().unwrap());
            let start = u64::from_le_bytes(descriptor[8..16].try_into().unwrap());
            let pages = u64::from_le_bytes(descriptor[24..32].try_into().unwrap());
            let Some(stop) = pages
                .checked_mul(PAGE as u64)
                .and_then(|bytes| start.checked_add(bytes))
            else {
                return false;
            };
            if base < stop && start < end {
                if admitted || !matches!(kind, 9 | 10) || start > base || end > stop {
                    return false;
                }
                admitted = true;
            }
        }
        if !admitted {
            return false;
        }
        // SAFETY: this application remains on UEFI's live x86_64 identity
        // mapping. The current non-overlapping memory map covers the complete
        // range as ACPI Reclaim or ACPI NVS; never read PCI MMIO through it.
        unsafe {
            core::ptr::copy_nonoverlapping(base as *const u8, output.as_mut_ptr(), output.len())
        };
        true
    }
}

// SAFETY: the system and Boot Services tables are live. A successful firmware
// allocation and GetMemoryMap call satisfy their output pointer contracts.
pub(super) unsafe fn read(
    system: &SystemTable,
    services: &BootServices,
    usb_origin: Option<DeviceAddress>,
) -> Result<Tables, &'static str> {
    if !(1..=1024).contains(&system.table_entry_count)
        || system.configuration_table.is_null()
        || !system.configuration_table.is_aligned()
    {
        return Err("no bounded configuration table");
    }
    // SAFETY: UEFI supplied the live aligned configuration-table array and bounded count.
    let entries = unsafe {
        core::slice::from_raw_parts(system.configuration_table, system.table_entry_count)
    };
    let mut root = None;
    for wanted in [ACPI_20_TABLE_GUID, ACPI_TABLE_GUID] {
        let mut matches = entries
            .iter()
            .filter(|entry| entry.vendor_guid.equals(&wanted));
        if let Some(entry) = matches.next() {
            if matches.next().is_some() || entry.vendor_table.is_null() {
                return Err("ambiguous or null ACPI root");
            }
            root = Some(entry.vendor_table as u64);
            break;
        }
    }
    let root = root.ok_or("no ACPI root")?;
    let mut addr = 0;
    // AllocateAnyPages, EfiLoaderData. This is transient RAM, not DMA memory.
    // SAFETY: the live allocator writes the plain physical address to a valid out parameter.
    check(unsafe { (services.allocate_pages)(0, 2, MAP_PAGES, &mut addr) })
        .map_err(|_| "could not allocate memory-map scratch")?;
    // SAFETY: successful allocation provided MAP_PAGES readable and writable scratch pages.
    let result = unsafe { copy_tables(system, services, addr, root, usb_origin) };
    // SAFETY: the firmware owns this allocation and it is no longer borrowed.
    check(unsafe { (services.free_pages)(addr, MAP_PAGES) })
        .map_err(|_| "could not free memory-map scratch")?;
    result
}

// SAFETY: addr points to MAP_PAGES live, firmware-allocated pages.
unsafe fn copy_tables(
    system: &SystemTable,
    services: &BootServices,
    addr: u64,
    root: u64,
    usb_origin: Option<DeviceAddress>,
) -> Result<Tables, &'static str> {
    if addr == 0 || !addr.is_multiple_of(PAGE as u64) {
        return Err("invalid memory-map scratch address");
    }
    let raw = addr as *mut u8;
    let mut size = MAX_MEMORY_MAP_BYTES;
    let (mut key, mut stride, mut version) = (0, 0, 0);
    // SAFETY: the successful allocation covers the complete requested map scratch.
    unsafe { raw.write_bytes(0, MAX_MEMORY_MAP_BYTES) };
    // SAFETY: the allocated aligned map scratch and all scalar out parameters are valid.
    check(unsafe {
        (services.get_memory_map)(&mut size, raw.cast(), &mut key, &mut stride, &mut version)
    })
    .map_err(|_| "memory map unavailable")?;
    if version != 1
        || !(size_of::<MemoryDescriptor>()..=256).contains(&stride)
        || size < stride
        || size > MAX_MEMORY_MAP_BYTES
        || !size.is_multiple_of(stride)
    {
        return Err("invalid memory map");
    }
    let mut memory = FirmwareMap {
        // SAFETY: the successful call returned size initialized bytes within the allocation.
        bytes: unsafe { core::slice::from_raw_parts(raw, size) },
        stride,
    };
    // The shared routines validate the RSDP and uniquely matched table
    // checksums. Reuse scratch; each parsed topology owns its scalar data.
    let mut bytes = [0; MAX_HANDOFF_DMA_ACPI_TABLE_BYTES];
    let mcfg = copy_mcfg(&mut memory, root, &mut bytes)
        .map_err(TableError::Read)
        .and_then(|len| McfgTopology::parse(&bytes[..len]).map_err(TableError::Invalid));
    let dmar = copy_dmar(&mut memory, root, &mut bytes)
        .map_err(TableError::Read)
        .and_then(|len| DmarTopology::parse(&bytes[..len]).map_err(TableError::Invalid));
    let placeholder = MemoryRegion::new(
        PhysAddr::new(0).map_err(|_| "invalid map placeholder")?,
        1,
        MemoryKind::Reserved,
    ).map_err(|_| "invalid map placeholder")?;
    let mut regions = [placeholder; MAX_NORMALIZED_REGIONS];
    let region_count = mrml_uefi::xhci_inventory::normalize_pci_inventory_map(
        memory.bytes, stride, &mut regions,
    );
    let mut dxe = DxeEvidence::default();
    if let (Some(requester), Some(_), Ok(mcfg), Ok(dmar)) =
        (usb_origin, region_count, &mcfg, &dmar)
        && let Some((entry, page)) = mcfg.allocations()
            .find_map(|entry| ecam_page(entry, requester).map(|page| (entry, page)))
    {
        let observe = |base, bytes| {
            // SAFETY: all services and the same bounded memory-map snapshot
            // remain live. The reader validates the DXE table and entrypoint
            // against this snapshot and calls only GetMemorySpaceDescriptor.
            // The addresses being classified are never dereferenced.
            unsafe {
                inspect_dxe_mmio(system, base, bytes, |access, address, bytes| {
                    dxe_boot_services_contains(memory.bytes, stride, access, address, bytes)
                })
            }
        };
        dxe.requester = Some(requester);
        dxe.ecam = Some(observe(entry.physical_start(), entry.bytes() as u64));
        dxe.page = Some(observe(page, PAGE as u64));
        for (slot, unit) in dxe.drhd.iter_mut().zip(dmar.units()) {
            *slot = Some(observe(unit.register_base.get(), PAGE as u64));
        }
    }
    Ok(Tables { mcfg, dmar, regions, region_count, dxe })
}
