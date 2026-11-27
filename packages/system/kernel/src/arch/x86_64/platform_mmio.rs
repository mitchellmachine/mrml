use crate::{MemoryKind, MemoryRegion, PAGE_SIZE, PhysAddr};

use super::{
    ActivePageTables, DmarTopology, Mapping, McfgTopology, PagePermissions, VirtAddr,
    VtdRegisterLayout,
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

#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedPlatformMmio {
    requirement: PlatformMmioRequirement,
    virtual_start: VirtAddr,
}

impl VerifiedPlatformMmio {
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
