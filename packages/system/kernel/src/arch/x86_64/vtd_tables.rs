use crate::{
    DeviceAddress, DomainId, GranuleHardwareOutcome, MonitorError, PAGE_SIZE, PhysAddr,
    ProtectedMonitor,
};
use core::mem::MaybeUninit;

use super::{
    ColdVtdActivationError, CompleteVtdRoutes, DmaIsolation, NativeVtdMmio, PlatformMmioPurpose,
    VerifiedPlatformMmio, VtdDmaIsolation, VtdDmaSet, VtdError, VtdInvalidator, VtdRegisterIo,
    VtdRequesterRoute,
};

const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const ENTRY_FLAGS: u64 = 0x7 | (1 << 8) | (1 << 9) | (1 << 11);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VtdTableError {
    UnsupportedRootMode,
    InvalidRoot,
    MissingRootEntry,
    InvalidRootEntry,
    MissingContextEntry,
    InvalidContextEntry,
    WrongDomain,
    UnsupportedAddressWidth,
    UnsupportedTranslationType,
    FaultReportingDisabled,
    InvalidIntermediate,
    LargePage,
    MissingLeaf,
    AliasedLeaf,
    InvalidAperture,
    InsufficientPermissions,
    OccupiedLeaf,
    OccupiedContext,
    WritebackUnavailable,
    Storage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VtdBindingError {
    UnitSubstitution,
    TableSubstitution,
    InsufficientRegisterMapping,
    Unit(VtdError),
    Table(VtdTableError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VtdTableProvenance {
    register_base: PhysAddr,
    root_table: PhysAddr,
}

impl VtdTableProvenance {
    pub const fn register_base(self) -> PhysAddr {
        self.register_base
    }

    pub const fn root_table(self) -> PhysAddr {
        self.root_table
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VtdSetBindingError {
    Empty,
    DuplicateUnit,
    Unit {
        index: usize,
        error: VtdBindingError,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VtdDomainError {
    TableFull,
    InvalidHardwareDomain,
    DuplicateBinding,
    HardwareDomainCollision,
    MissingBinding,
    Monitor(MonitorError),
}

#[derive(Clone, Copy)]
struct VtdDomainEntry {
    owner: DomainId,
    register_base: PhysAddr,
    hardware_domain: u16,
}

/// Fixed-capacity authority mapping generation-checked monitor domains to the
/// hardware domain number installed in each distinct VT-d unit.
pub struct VtdDomainAuthority<const ENTRIES: usize> {
    entries: [Option<VtdDomainEntry>; ENTRIES],
    count: usize,
}

impl<const ENTRIES: usize> VtdDomainAuthority<ENTRIES> {
    pub const fn new() -> Self {
        Self {
            entries: [None; ENTRIES],
            count: 0,
        }
    }

    pub fn register<const DOMAINS: usize, const GRANULES: usize>(
        &mut self,
        monitor: &ProtectedMonitor<DOMAINS, GRANULES>,
        owner: DomainId,
        register_base: PhysAddr,
        hardware_domain: u16,
    ) -> Result<(), VtdDomainError> {
        monitor
            .domain_state(owner)
            .map_err(VtdDomainError::Monitor)?;
        if hardware_domain == 0 {
            return Err(VtdDomainError::InvalidHardwareDomain);
        }
        if self
            .entries()
            .any(|entry| entry.owner == owner && entry.register_base == register_base)
        {
            return Err(VtdDomainError::DuplicateBinding);
        }
        if self.entries().any(|entry| {
            entry.register_base == register_base && entry.hardware_domain == hardware_domain
        }) {
            return Err(VtdDomainError::HardwareDomainCollision);
        }
        if self.count == ENTRIES {
            return Err(VtdDomainError::TableFull);
        }
        self.entries[self.count] = Some(VtdDomainEntry {
            owner,
            register_base,
            hardware_domain,
        });
        self.count += 1;
        Ok(())
    }

    pub fn authorize<const DOMAINS: usize, const GRANULES: usize, const UNITS: usize>(
        &self,
        monitor: &ProtectedMonitor<DOMAINS, GRANULES>,
        owner: DomainId,
        complete_routes: CompleteVtdRoutes<UNITS>,
    ) -> Result<VtdAuthorizedRoutes<UNITS>, VtdDomainError> {
        monitor
            .domain_state(owner)
            .map_err(VtdDomainError::Monitor)?;
        let routes = complete_routes.into_routes();
        let mut hardware_domains = [0; UNITS];
        for (index, route) in routes.iter().enumerate() {
            hardware_domains[index] = self
                .entries()
                .find(|entry| entry.owner == owner && entry.register_base == route.register_base())
                .ok_or(VtdDomainError::MissingBinding)?
                .hardware_domain;
        }
        Ok(VtdAuthorizedRoutes {
            owner,
            routes,
            hardware_domains,
        })
    }

    fn entries(&self) -> impl Iterator<Item = &VtdDomainEntry> {
        self.entries[..self.count].iter().flatten()
    }
}

impl<const ENTRIES: usize> Default for VtdDomainAuthority<ENTRIES> {
    fn default() -> Self {
        Self::new()
    }
}

/// Opaque, ordered authorization coupling complete live routes to one current
/// monitor-domain generation and each unit's registered hardware-domain ID.
pub struct VtdAuthorizedRoutes<const UNITS: usize> {
    owner: DomainId,
    routes: [VtdRequesterRoute; UNITS],
    hardware_domains: [u16; UNITS],
}

/// Complete VT-d transaction carrying the monitor-domain generation authorized
/// for every hardware-domain context in the set.
pub struct VtdAuthorizedDmaSet<'a, R, const UNITS: usize> {
    owner: DomainId,
    set: VtdDmaSet<'a, R, UNITS>,
}

impl<R: VtdRegisterIo, const UNITS: usize> VtdAuthorizedDmaSet<'_, R, UNITS> {
    pub const fn owner(&self) -> DomainId {
        self.owner
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

impl<R: VtdRegisterIo, const UNITS: usize> DmaIsolation for VtdAuthorizedDmaSet<'_, R, UNITS> {
    fn bound_domain(&self) -> Option<DomainId> {
        Some(self.owner)
    }

    fn deny_and_invalidate(&mut self, physical: PhysAddr) -> GranuleHardwareOutcome {
        self.set.deny_and_invalidate(physical)
    }
}

impl<const UNITS: usize> VtdAuthorizedRoutes<UNITS> {
    pub const fn owner(&self) -> DomainId {
        self.owner
    }

    #[cfg(test)]
    fn for_test(
        owner: DomainId,
        routes: [VtdRequesterRoute; UNITS],
        hardware_domains: [u16; UNITS],
    ) -> Self {
        Self {
            owner,
            routes,
            hardware_domains,
        }
    }

    fn into_parts(self) -> ([VtdRequesterRoute; UNITS], [u16; UNITS]) {
        (self.routes, self.hardware_domains)
    }

    fn routes(&self) -> &[VtdRequesterRoute; UNITS] {
        &self.routes
    }
}

/// A one-shot verified MMIO token coupled to the sole invalidator that may use
/// its remapping-unit register mapping.
pub struct VerifiedVtdUnit<R> {
    verified: VerifiedPlatformMmio,
    invalidator: VtdInvalidator<R>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VtdDmaAperture {
    pub route: VtdRequesterRoute,
    pub hardware_domain: u16,
    pub device_base: u64,
    pub physical_base: PhysAddr,
    pub pages: u16,
}

pub const SINGLE_REQUESTER_VTD_TABLE_PAGES: usize = 6;

const MAX_VTD_WRITEBACK_BYTES: usize = SINGLE_REQUESTER_VTD_TABLE_PAGES * PAGE_SIZE as usize;

fn clflush_line_bytes(ebx: u32, edx: u32) -> Option<usize> {
    let bytes = ((ebx >> 8) & 0xff) as usize * 8;
    (edx & (1 << 19) != 0 && bytes.is_power_of_two() && bytes <= PAGE_SIZE as usize)
        .then_some(bytes)
}

fn local_clflush_line_bytes() -> Option<usize> {
    if core::arch::x86_64::__cpuid(0).eax < 1 {
        return None;
    }
    let info = core::arch::x86_64::__cpuid(1);
    clflush_line_bytes(info.ebx, info.edx)
}

fn visit_writeback_offsets(
    start: usize,
    bytes: usize,
    line: usize,
    mut visit: impl FnMut(usize),
) -> Result<(), VtdTableError> {
    if bytes == 0
        || bytes > MAX_VTD_WRITEBACK_BYTES
        || !line.is_power_of_two()
        || !(8..=PAGE_SIZE as usize).contains(&line)
        || start.checked_add(bytes - 1).is_none()
    {
        return Err(VtdTableError::WritebackUnavailable);
    }
    visit(0);
    let first_boundary = line - (start & (line - 1));
    for offset in (first_boundary..bytes).step_by(line) {
        visit(offset);
    }
    Ok(())
}

/// Publishes stored VT-d entries from exclusive WB RAM to a non-snooping
/// table walker. This does not invalidate IOMMU caches, publish a root pointer,
/// or establish the coherency of device DMA data.
///
/// # Safety
///
/// The caller owns the exact pinned table backing and has independently
/// verified WB mappings with no conflicting aliases. The caller serializes
/// all table writers and ensures the CPU cannot migrate between CPUID and
/// CLFLUSH (or that all eligible CPUs have identical support and geometry).
pub unsafe fn write_back_vtd_table_words(words: &[u64]) -> Result<(), VtdTableError> {
    let line = local_clflush_line_bytes().ok_or(VtdTableError::WritebackUnavailable)?;
    let address = words.as_ptr().cast::<u8>();
    let bytes = core::mem::size_of_val(words);
    // SAFETY: x86-64 guarantees SSE2 and the caller has pinned WB backing.
    // Order the preceding table stores before invalidating cache lines.
    unsafe { core::arch::x86_64::_mm_mfence() };
    visit_writeback_offsets(address.addr(), bytes, line, |offset| {
        // SAFETY: CPUID established CLFLUSH; every operand points inside the
        // provided mapped slice, not an aligned address before the slice.
        unsafe { core::arch::x86_64::_mm_clflush(address.wrapping_add(offset)) };
    })?;
    // SAFETY: x86-64 provides MFENCE; do not publish or invalidate IOMMU
    // caches until all cache-line writebacks have completed.
    unsafe { core::arch::x86_64::_mm_mfence() };
    Ok(())
}

/// Constructs an inactive four-level legacy root/context hierarchy for one
/// exact requester. No DMA leaves are present on return, including in the
/// supplied aperture. All other requesters have absent contexts.
///
/// The caller must place this image in the six contiguous physical pages at
/// `root` before publication and separately establish ownership, coherency,
/// hardware capabilities and safe unit-wide activation. This is an image
/// builder, not permission to replace an active root.
pub fn build_single_requester_legacy_root(
    image: &mut [[u64; 512]; SINGLE_REQUESTER_VTD_TABLE_PAGES],
    root: PhysAddr,
    aperture: VtdDmaAperture,
) -> Result<(), VtdTableError> {
    let bytes = aperture_bytes(aperture.device_base, aperture.physical_base, aperture.pages)?;
    let last = aperture.device_base + bytes - 1;
    if aperture.device_base >> 21 != last >> 21 {
        return Err(VtdTableError::InvalidAperture);
    }
    if aperture.hardware_domain == 0 {
        return Err(VtdTableError::WrongDomain);
    }
    let root_base = checked_table(root.get())?.get();
    let table_end = root_base
        .checked_add(SINGLE_REQUESTER_VTD_TABLE_PAGES as u64 * PAGE_SIZE)
        .filter(|&end| end <= 1 << 52)
        .ok_or(VtdTableError::InvalidRoot)?;
    let physical = aperture.physical_base.get();
    if physical < table_end && root_base < physical + bytes {
        return Err(VtdTableError::InvalidAperture);
    }
    let requester = aperture.route.requester();
    let index = (usize::from(requester.device()) * 8 + usize::from(requester.function())) * 2;
    let table = |page: u64| root_base + page * PAGE_SIZE;
    image.fill([0; 512]);
    image[0][2 * usize::from(requester.bus())] = table(1) | 1;
    image[1][index] = table(2) | 1;
    image[1][index + 1] = (u64::from(aperture.hardware_domain) << 8) | 2;
    for (page, shift) in [(2usize, 39), (3, 30), (4, 21)] {
        let index = ((aperture.device_base >> shift) & 0x1ff) as usize;
        image[page][index] = table(page as u64 + 1) | 3;
    }
    Ok(())
}

/// A newly constructed, synchronized legacy hierarchy, not a DMA grant.
#[must_use]
#[derive(Debug, Eq, PartialEq)]
pub struct PreparedColdVtdRoot {
    root: PhysAddr,
    route: VtdRequesterRoute,
}

impl PreparedColdVtdRoot {
    pub(super) const fn root(&self) -> PhysAddr {
        self.root
    }
    pub(super) const fn register_base(&self) -> PhysAddr {
        self.route.register_base()
    }
}

/// Prepares the exact pinned destination, not a separate image copied later.
///
/// # Safety
///
/// The table slice must be the verified exclusive WB mapping of the six
/// consecutive pages beginning at root. No unit may access them yet. Keep
/// them pinned and unchanged through activation or on uncertain failure.
/// The caller must meet the CPU and alias requirements of the writeback helper.
pub unsafe fn prepare_cold_legacy_vtd_root(
    tables: &mut [[u64; 512]; SINGLE_REQUESTER_VTD_TABLE_PAGES],
    root: PhysAddr,
    aperture: VtdDmaAperture,
) -> Result<PreparedColdVtdRoot, VtdTableError> {
    if local_clflush_line_bytes().is_none() {
        return Err(VtdTableError::WritebackUnavailable);
    }
    build_single_requester_legacy_root(tables, root, aperture)?;
    // SAFETY: the caller established an exact pinned WB mapping and CPU
    // safety. The flushed pages are the ones the remapper will walk.
    unsafe { write_back_vtd_table_words(tables.as_flattened())? };
    Ok(PreparedColdVtdRoot {
        root,
        route: aperture.route,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VtdApertureInstallError {
    Rejected(VtdBindingError),
    RolledBack(VtdBindingError),
    Uncertain(VtdBindingError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VtdApertureRevokeError {
    Rejected(VtdBindingError),
    Uncertain(VtdBindingError),
}

impl VerifiedVtdUnit<NativeVtdMmio> {
    /// Constructs the native register adapter and consumes the mapping proof so
    /// it cannot authorize a second aliasing adapter.
    ///
    /// # Safety
    ///
    /// The verified mapping must be uncached and uniquely owned for the
    /// returned unit's lifetime. Firmware topology and active page tables must
    /// remain stable while it is used.
    pub unsafe fn from_native(
        verified: VerifiedPlatformMmio,
        poll_limit: u32,
    ) -> Result<Self, VtdBindingError> {
        if !matches!(
            verified.requirement().purpose(),
            PlatformMmioPurpose::VtdBootstrap { .. }
        ) {
            return Err(VtdBindingError::UnitSubstitution);
        }
        let bytes = usize::try_from(verified.register_bytes())
            .map_err(|_| VtdBindingError::Unit(VtdError::InvalidRegisterLayout))?;
        // SAFETY: inherited from this function's unique, uncached verified
        // mapping contract. The checked byte count is the verified extent.
        let registers = unsafe { NativeVtdMmio::new(verified.as_mut_ptr(), bytes) }
            .map_err(VtdBindingError::Unit)?;
        let invalidator =
            VtdInvalidator::new(registers, poll_limit).map_err(|error| match error {
                VtdError::InsufficientRegisterAperture => {
                    VtdBindingError::InsufficientRegisterMapping
                }
                other => VtdBindingError::Unit(other),
            })?;
        Ok(Self {
            verified,
            invalidator,
        })
    }
}

impl<R: VtdRegisterIo> VerifiedVtdUnit<R> {
    /// Activate the prepared root only through its verified remapping unit.
    ///
    /// # Safety
    ///
    /// The caller exclusively owns the complete remapper and its scope. All
    /// requesters must stay quiesced with BME off. Keep the prepared RAM
    /// pinned and unchanged through startup, until teardown establishes
    /// safety. This applies on uncertainty as well as success.
    pub unsafe fn activate_cold_legacy_root(
        &mut self,
        prepared: PreparedColdVtdRoot,
    ) -> Result<(), ColdVtdActivationError> {
        let requirement = self.verified.requirement();
        if !matches!(
            requirement.purpose(),
            PlatformMmioPurpose::VtdBootstrap { .. }
        ) || requirement.pages() < self.invalidator.register_pages()
        {
            return Err(ColdVtdActivationError::Rejected(VtdError::ColdUnsupported));
        }
        // SAFETY: this unit owns the verified register region; the caller
        // supplies complete scope ownership and quiescence for this startup.
        unsafe {
            self.invalidator
                .activate_cold_legacy_root(requirement.physical(), prepared)
        }
    }

    /// Bind a non-identity boot mapping to this unit's exact active root.
    ///
    /// # Safety
    /// The exclusive WB slice must cover exactly the six consecutive pinned
    /// physical frames at `root`, already synchronized before activation.
    /// Keep the mapping, cache type and CPU geometry stable; serialize root
    /// changes and all table writers and exclude hardware A/D writes.
    pub unsafe fn borrow_boot_tables<'a>(
        &mut self,
        route: VtdRequesterRoute,
        root: PhysAddr,
        backing: &'a mut [[u64; 512]; SINGLE_REQUESTER_VTD_TABLE_PAGES],
    ) -> Result<BootVtdTables<'a>, VtdBindingError> {
        if !verified_unit_matches_route(&self.verified, route) {
            return Err(VtdBindingError::UnitSubstitution);
        }
        if root.get()
            != self
                .invalidator
                .active_legacy_root()
                .map_err(VtdBindingError::Unit)?
        {
            return Err(VtdBindingError::TableSubstitution);
        }
        local_clflush_line_bytes()
            .ok_or(VtdBindingError::Table(VtdTableError::WritebackUnavailable))?;
        Ok(BootVtdTables {
            provenance: VtdTableProvenance {
                register_base: route.register_base(),
                root_table: root,
            },
            backing,
        })
    }

    /// Samples the active root through this exact unit and creates the exclusive
    /// direct-map view that coherent binding will independently revalidate.
    ///
    /// # Safety
    ///
    /// Every table reachable from the sampled root must be identity mapped,
    /// pinned, supervisor writable, and exclusively owned. Root changes and
    /// concurrent table writers must be serialized until binding completes.
    pub unsafe fn prepare_direct_tables(
        &mut self,
        route: VtdRequesterRoute,
    ) -> Result<DirectVtdTables, VtdBindingError> {
        if !verified_unit_matches_route(&self.verified, route) {
            return Err(VtdBindingError::UnitSubstitution);
        }
        let root = self
            .invalidator
            .active_legacy_root()
            .map_err(VtdBindingError::Unit)?;
        let root_table = PhysAddr::new(root).map_err(|_| VtdBindingError::TableSubstitution)?;
        // SAFETY: inherited from this method's direct-map ownership contract.
        Ok(unsafe {
            DirectVtdTables::assume_exclusive_identity_mapping(route.register_base(), root_table)
        })
    }

    /// Verify that an exact stopped requester has a canonical empty context
    /// on the active coherent legacy root, including a completed cache drain.
    ///
    /// The caller must hold the retained assignment lock, keep the requester
    /// stopped, and independently exclude ATS, requester aliases and firmware
    /// reserved ranges. Do not use a success after releasing that lock or
    /// changing any relevant table, route, or unit state. On uncertainty the
    /// caller must keep the requester stopped and the assignment quarantined.
    /// No table entries or PCI command bits are changed here.
    pub fn verify_routed_dma_denied<M: VtdTableMemory>(
        &mut self,
        memory: &M,
        route: VtdRequesterRoute,
    ) -> Result<(), VtdBindingError> {
        if !verified_unit_matches_route(&self.verified, route) {
            return Err(VtdBindingError::UnitSubstitution);
        }
        let root = self
            .invalidator
            .active_legacy_root()
            .map_err(VtdBindingError::Unit)?;
        let provenance = memory.provenance();
        if provenance.register_base() != route.register_base()
            || provenance.root_table().get() != root
        {
            return Err(VtdBindingError::TableSubstitution);
        }
        let check = || {
            require_empty_legacy_context(memory, root, route.requester())
                .map_err(VtdBindingError::Table)
        };
        check()?;
        // An observed zero is insufficient on noncoherent walks. This path
        // does not publish context/root cache lines, so only admit coherent
        // walks and require the hardware's synchronous read/write drains.
        self.invalidator.ready_for_dma_drain(false).map_err(VtdBindingError::Unit)?;
        self.invalidator.invalidate_global().map_err(VtdBindingError::Unit)?;
        if self.invalidator.active_legacy_root().map_err(VtdBindingError::Unit)? != root {
            return Err(VtdBindingError::TableSubstitution);
        }
        if memory.provenance() != provenance {
            return Err(VtdBindingError::TableSubstitution);
        }
        check()
    }

    /// Checks a bounded, contiguous device-to-physical read/write window in
    /// the exact active legacy domain. This does not install mappings or
    /// establish that the pages, domain, or requester aliases are exclusive.
    /// The provider must hold the assignment lock and keep the checked
    /// translations pinned and synchronized through activation.
    pub fn verify_routed_dma_aperture<M: VtdTableMemory>(
        &mut self,
        memory: &M,
        route: VtdRequesterRoute,
        expected_domain: u16,
        device_base: u64,
        physical_base: PhysAddr,
        pages: u16,
    ) -> Result<(), VtdBindingError> {
        if !verified_unit_matches_route(&self.verified, route) {
            return Err(VtdBindingError::UnitSubstitution);
        }
        let root = self
            .invalidator
            .active_legacy_root()
            .map_err(VtdBindingError::Unit)?;
        let provenance = memory.provenance();
        if provenance.register_base() != route.register_base()
            || provenance.root_table().get() != root
        {
            return Err(VtdBindingError::TableSubstitution);
        }
        let bytes =
            aperture_bytes(device_base, physical_base, pages).map_err(VtdBindingError::Table)?;
        for offset in (0..bytes).step_by(4096) {
            let (_, _, permissions) = find_legacy_leaf(
                memory,
                root,
                route.requester(),
                device_base + offset,
                physical_base.get() + offset,
                expected_domain,
                false,
            )
            .map_err(VtdBindingError::Table)?;
            if permissions != 3 {
                return Err(VtdBindingError::Table(
                    VtdTableError::InsufficientPermissions,
                ));
            }
        }
        Ok(())
    }

    /// Installs a bounded aperture into a caller-owned, existing legacy
    /// hierarchy while the exact requester is stopped with bus mastering off.
    /// The trusted owner must pin the backing, hold the assignment lock, and
    /// independently exclude ATS, aliases, and reserved firmware ranges.
    /// Does not create tables or activate the requester. On Uncertain, retain
    /// the entire original assignment and backing in quarantine.
    pub fn install_routed_dma_aperture<M: VtdTableMemory>(
        &mut self,
        memory: &mut M,
        aperture: VtdDmaAperture,
    ) -> Result<(), VtdApertureInstallError> {
        use VtdApertureInstallError::{Rejected, RolledBack, Uncertain};
        if !verified_unit_matches_route(&self.verified, aperture.route) {
            return Err(Rejected(VtdBindingError::UnitSubstitution));
        }
        let root = self
            .invalidator
            .active_legacy_root()
            .map_err(|e| Rejected(VtdBindingError::Unit(e)))?;
        let provenance = memory.provenance();
        if provenance.register_base() != aperture.route.register_base()
            || provenance.root_table().get() != root
        {
            return Err(Rejected(VtdBindingError::TableSubstitution));
        }
        let bytes = aperture_bytes(aperture.device_base, aperture.physical_base, aperture.pages)
            .map_err(|e| Rejected(VtdBindingError::Table(e)))?;
        let mut slots = [None; 256];
        let count = usize::from(aperture.pages);
        for (i, offset) in (0..bytes).step_by(4096).enumerate() {
            let (table, index, permissions) = walk_legacy_slot(
                memory,
                root,
                aperture.route.requester(),
                aperture.device_base + offset,
                aperture.hardware_domain,
            )
            .map_err(|e| Rejected(VtdBindingError::Table(e)))?;
            if permissions != 3 {
                return Err(Rejected(VtdBindingError::Table(
                    VtdTableError::InsufficientPermissions,
                )));
            }
            if slots[..i].contains(&Some((table, index)))
                || memory
                    .read64(table, index)
                    .map_err(|e| Rejected(VtdBindingError::Table(e)))?
                    != 0
            {
                return Err(Rejected(VtdBindingError::Table(
                    VtdTableError::OccupiedLeaf,
                )));
            }
            slots[i] = Some((table, index));
        }
        let needs_writeback = self
            .invalidator
            .ready_for_dma_drain(memory.supports_explicit_writeback())
            .map_err(|e| Rejected(VtdBindingError::Unit(e)))?;
        let mut written = 0;
        let result = (|| {
            for (i, (table, index)) in slots[..count].iter().copied().flatten().enumerate() {
                let leaf = exclusive_leaf(memory, table, index).map_err(VtdBindingError::Table)?;
                let address = aperture.physical_base.get() + i as u64 * 4096;
                super::vtd::write_dma_leaf(leaf, address | 3);
                written += 1;
                if needs_writeback {
                    memory
                        .write_back_leaf(table, index)
                        .map_err(VtdBindingError::Table)?;
                }
            }
            self.invalidator
                .invalidate_global()
                .map_err(VtdBindingError::Unit)
        })();
        if let Err(error) = result {
            let mut rollback_uncertain = false;
            for (table, index) in slots[..written].iter().copied().flatten() {
                match exclusive_leaf(memory, table, index) {
                    Ok(leaf) => {
                        super::vtd::write_dma_leaf(leaf, 0);
                        if needs_writeback && memory.write_back_leaf(table, index).is_err() {
                            rollback_uncertain = true;
                        }
                    }
                    Err(_) => rollback_uncertain = true,
                }
            }
            // In particular, do not issue another command over a pending
            // command that timed out during the first invalidation attempt.
            if rollback_uncertain
                || self
                    .invalidator
                    .ready()
                    .and_then(|()| self.invalidator.invalidate_global())
                    .is_err()
            {
                return Err(Uncertain(error));
            }
            return Err(RolledBack(error));
        }
        Ok(())
    }

    /// Withdraws exactly this aperture from one legacy VT-d domain after the
    /// requester is stopped and PCI bus mastering is confirmed disabled.
    /// The trusted owner must keep the table view and all backing pinned,
    /// serialize table and root updates, and separately exclude device-side
    /// translation caches (ATS) and requester aliases. This function never
    /// releases memory. Any uncertain result requires quarantine until the
    /// exact same withdrawal and draining invalidation succeed.
    pub fn revoke_routed_dma_aperture<M: VtdTableMemory>(
        &mut self,
        memory: &mut M,
        aperture: VtdDmaAperture,
    ) -> Result<(), VtdApertureRevokeError> {
        use VtdApertureRevokeError::{Rejected, Uncertain};

        if !verified_unit_matches_route(&self.verified, aperture.route) {
            return Err(Rejected(VtdBindingError::UnitSubstitution));
        }
        let root = self
            .invalidator
            .active_legacy_root()
            .map_err(|error| Rejected(VtdBindingError::Unit(error)))?;
        let provenance = memory.provenance();
        if provenance.register_base() != aperture.route.register_base()
            || provenance.root_table().get() != root
        {
            return Err(Rejected(VtdBindingError::TableSubstitution));
        }
        let bytes = aperture_bytes(aperture.device_base, aperture.physical_base, aperture.pages)
            .map_err(|error| Rejected(VtdBindingError::Table(error)))?;

        // Preflight the complete region before changing any entry. Keep the
        // non-present leaf's address so retries prove the same pinned backing.
        let mut slots = [None; 256];
        for (index, offset) in (0..bytes).step_by(4096).enumerate() {
            let (table, entry, _) = find_legacy_leaf(
                memory,
                root,
                aperture.route.requester(),
                aperture.device_base + offset,
                aperture.physical_base.get() + offset,
                aperture.hardware_domain,
                true,
            )
            .map_err(|error| Rejected(VtdBindingError::Table(error)))?;
            slots[index] = Some((table, entry));
        }
        let needs_writeback = self
            .invalidator
            .ready_for_dma_drain(memory.supports_explicit_writeback())
            .map_err(|error| Rejected(VtdBindingError::Unit(error)))?;

        for (table, index) in slots.into_iter().flatten() {
            let leaf = exclusive_leaf(memory, table, index)
                .map_err(|error| Uncertain(VtdBindingError::Table(error)))?;
            super::vtd::clear_dma_leaf_permissions(leaf);
            if needs_writeback {
                memory
                    .write_back_leaf(table, index)
                    .map_err(|error| Uncertain(VtdBindingError::Table(error)))?;
            }
        }
        self.invalidator
            .invalidate_global()
            .map_err(|error| Uncertain(VtdBindingError::Unit(error)))
    }

    #[cfg(test)]
    fn for_test(verified: VerifiedPlatformMmio, invalidator: VtdInvalidator<R>) -> Self {
        Self {
            verified,
            invalidator,
        }
    }

    fn into_parts(self) -> (VerifiedPlatformMmio, VtdInvalidator<R>) {
        (self.verified, self.invalidator)
    }
}

fn require_empty_legacy_context(
    memory: &impl VtdTableMemory,
    root: u64,
    requester: DeviceAddress,
) -> Result<(), VtdTableError> {
    let root = checked_table(root).map_err(|_| VtdTableError::InvalidRoot)?;
    let entry = memory.read128(root, usize::from(requester.bus()))?;
    // Require the exact existing context table. Do not confuse an absent
    // bus table or malformed root with a verified empty requester slot.
    if entry[1] != 0 || entry[0] & !(ADDRESS_MASK | 1) != 0 || entry[0] & 1 == 0 {
        return Err(VtdTableError::InvalidRootEntry);
    }
    let table =
        checked_table(entry[0] & ADDRESS_MASK).map_err(|_| VtdTableError::InvalidRootEntry)?;
    let slot = usize::from(requester.device()) * 8 + usize::from(requester.function());
    if memory.read128(table, slot)? != [0, 0] {
        return Err(VtdTableError::OccupiedContext);
    }
    Ok(())
}

fn verified_unit_matches_route(verified: &VerifiedPlatformMmio, route: VtdRequesterRoute) -> bool {
    let requirement = verified.requirement();
    requirement.physical() == route.register_base()
        && matches!(
            requirement.purpose(),
            PlatformMmioPurpose::VtdBootstrap { segment }
                if segment == route.requester().segment()
        )
}

/// Exclusive access to live legacy VT-d translation tables.
///
/// # Safety
///
/// An implementation must truthfully identify its sole DRHD and sampled active
/// root, read and mutate the exact physical table entries named by each
/// argument, keep every table pinned, serialize against all concurrent table
/// writers, and return a unique leaf reference.
pub unsafe trait VtdTableMemory {
    /// Immutable unit/root identity for this exclusive table view.
    fn provenance(&self) -> VtdTableProvenance;

    /// True only if this backend can publish changes from all reachable WB
    /// table frames to noncoherent walkers, in order, during this assignment.
    fn supports_explicit_writeback(&self) -> bool {
        false
    }

    /// Finish the writeback of the exact modified leaf, with ordering before
    /// device invalidation. The trait's exclusive ownership contract still
    /// holds during this call. Err leaves the update unconfirmed.
    fn write_back_leaf(&mut self, _table: PhysAddr, _index: usize) -> Result<(), VtdTableError> {
        Err(VtdTableError::WritebackUnavailable)
    }
    fn read128(&self, table: PhysAddr, index: usize) -> Result<[u64; 2], VtdTableError>;
    fn read64(&self, table: PhysAddr, index: usize) -> Result<u64, VtdTableError>;
    /// # Safety
    ///
    /// Return the unique live entry designated by `table` and `index`, with
    /// all competing table access serialized.
    unsafe fn leaf_mut(&mut self, table: PhysAddr, index: usize)
    -> Result<&mut u64, VtdTableError>;
}

/// Exclusive bounded view over the exact six WB frames of a prepared
/// boot hierarchy. Physical addresses are translated only within this slice.
pub struct BootVtdTables<'a> {
    provenance: VtdTableProvenance,
    backing: &'a mut [[u64; 512]; SINGLE_REQUESTER_VTD_TABLE_PAGES],
}

impl BootVtdTables<'_> {
    fn page(&self, table: PhysAddr) -> Result<usize, VtdTableError> {
        let offset = table
            .get()
            .checked_sub(self.provenance.root_table.get())
            .filter(|offset| offset.is_multiple_of(PAGE_SIZE))
            .ok_or(VtdTableError::Storage)?;
        let page = offset / PAGE_SIZE;
        if page >= SINGLE_REQUESTER_VTD_TABLE_PAGES as u64 {
            return Err(VtdTableError::Storage);
        }
        Ok(page as usize)
    }
}

// SAFETY: construction binds the active unit and exact pinned frames. The
// unique view returns strictly bounded entries without identity dereferences,
// and writes back only the modified leaf through the same WB mapping.
unsafe impl VtdTableMemory for BootVtdTables<'_> {
    fn provenance(&self) -> VtdTableProvenance {
        self.provenance
    }

    fn supports_explicit_writeback(&self) -> bool {
        true
    }

    fn write_back_leaf(&mut self, table: PhysAddr, index: usize) -> Result<(), VtdTableError> {
        let page = self.page(table)?;
        let leaf = self.backing[page]
            .get(index)
            .ok_or(VtdTableError::Storage)?;
        // SAFETY: the backing contract establishes WB/pins/exclusivity and
        // fixed CPU geometry; this is exactly the just-modified leaf.
        unsafe { write_back_vtd_table_words(core::slice::from_ref(leaf)) }
    }

    fn read128(&self, table: PhysAddr, index: usize) -> Result<[u64; 2], VtdTableError> {
        if index >= 256 {
            return Err(VtdTableError::Storage);
        }
        Ok([
            self.read64(table, index * 2)?,
            self.read64(table, index * 2 + 1)?,
        ])
    }

    fn read64(&self, table: PhysAddr, index: usize) -> Result<u64, VtdTableError> {
        let page = self.page(table)?;
        let leaf = self.backing[page]
            .get(index)
            .ok_or(VtdTableError::Storage)?;
        // SAFETY: the exact entry is pinned with no concurrent writer,
        // including hardware A/D writes, for the lifetime of this view.
        Ok(unsafe { core::ptr::from_ref(leaf).read_volatile() })
    }

    unsafe fn leaf_mut(
        &mut self,
        table: PhysAddr,
        index: usize,
    ) -> Result<&mut u64, VtdTableError> {
        let page = self.page(table)?;
        self.backing[page]
            .get_mut(index)
            .ok_or(VtdTableError::Storage)
    }
}

/// Identity-mapped physical table access for the bare-metal monitor.
pub struct DirectVtdTables {
    provenance: VtdTableProvenance,
    explicit_writeback: bool,
}

impl DirectVtdTables {
    /// # Safety
    ///
    /// All table frames reachable from `root_table` must be identity mapped,
    /// pinned, supervisor writable, and exclusively owned by `register_base`
    /// while this object exists. The supplied root must have been sampled from
    /// that unit after hardware reported the pointer active.
    pub const unsafe fn assume_exclusive_identity_mapping(
        register_base: PhysAddr,
        root_table: PhysAddr,
    ) -> Self {
        Self {
            provenance: VtdTableProvenance {
                register_base,
                root_table,
            },
            explicit_writeback: false,
        }
    }

    /// # Safety
    ///
    /// All reachable table frames are pinned write-back RAM and the exclusive
    /// mapping has no conflicting cache alias. The initial hierarchy must
    /// already have been synchronized before its root was activated. The
    /// modifying CPU must meet the writeback helper's migration contract.
    pub unsafe fn enable_explicit_writeback(&mut self) -> Result<(), VtdTableError> {
        local_clflush_line_bytes().ok_or(VtdTableError::WritebackUnavailable)?;
        self.explicit_writeback = true;
        Ok(())
    }
}

unsafe impl VtdTableMemory for DirectVtdTables {
    fn provenance(&self) -> VtdTableProvenance {
        self.provenance
    }

    fn supports_explicit_writeback(&self) -> bool {
        self.explicit_writeback
    }

    fn write_back_leaf(&mut self, table: PhysAddr, index: usize) -> Result<(), VtdTableError> {
        if !self.explicit_writeback {
            return Err(VtdTableError::WritebackUnavailable);
        }
        let leaf = exclusive_leaf(self, table, index)?;
        // SAFETY: this table view was explicitly opted in under the pinned
        // WB/no-alias contract and owns the exact leaf.
        unsafe { write_back_vtd_table_words(core::slice::from_ref(leaf)) }
    }

    fn read128(&self, table: PhysAddr, index: usize) -> Result<[u64; 2], VtdTableError> {
        if index >= 256 {
            return Err(VtdTableError::Storage);
        }
        let pointer = (table.get() as *const u64).wrapping_add(index * 2);
        // SAFETY: construction establishes identity mapping and exclusive
        // ownership. Volatile reads preserve hardware-visible table state.
        Ok(unsafe { [pointer.read_volatile(), pointer.add(1).read_volatile()] })
    }

    fn read64(&self, table: PhysAddr, index: usize) -> Result<u64, VtdTableError> {
        if index >= 512 {
            return Err(VtdTableError::Storage);
        }
        // SAFETY: same construction invariant as `read128`.
        Ok(unsafe { (table.get() as *const u64).add(index).read_volatile() })
    }

    unsafe fn leaf_mut(
        &mut self,
        table: PhysAddr,
        index: usize,
    ) -> Result<&mut u64, VtdTableError> {
        if index >= 512 {
            return Err(VtdTableError::Storage);
        }
        // SAFETY: the trait and construction contracts require a unique live
        // mapping and serialize all competing table access.
        Ok(unsafe { &mut *(table.get() as *mut u64).add(index) })
    }
}

/// Builds every direct-map table view in authorization order without heap
/// allocation. A failed unit destroys every view already prepared and returns
/// no partially usable array.
///
/// # Safety
///
/// The direct-map ownership and serialization contract of
/// `VerifiedVtdUnit::prepare_direct_tables` must hold for every unit.
pub unsafe fn prepare_direct_vtd_tables<R: VtdRegisterIo, const UNITS: usize>(
    authorized_routes: &VtdAuthorizedRoutes<UNITS>,
    units: &mut [VerifiedVtdUnit<R>; UNITS],
) -> Result<[DirectVtdTables; UNITS], VtdSetBindingError> {
    if UNITS == 0 {
        return Err(VtdSetBindingError::Empty);
    }
    let mut views: [MaybeUninit<DirectVtdTables>; UNITS] = [const { MaybeUninit::uninit() }; UNITS];
    let mut initialized = 0usize;
    for (index, (route, unit)) in authorized_routes
        .routes()
        .iter()
        .copied()
        .zip(units.iter_mut())
        .enumerate()
    {
        // SAFETY: inherited from this function's all-unit contract.
        let view = match unsafe { unit.prepare_direct_tables(route) } {
            Ok(view) => view,
            Err(error) => {
                while initialized != 0 {
                    initialized -= 1;
                    // SAFETY: precisely the prefix below `initialized` was
                    // written, and each element is dropped exactly once.
                    unsafe { views[initialized].assume_init_drop() };
                }
                return Err(VtdSetBindingError::Unit { index, error });
            }
        };
        views[index].write(view);
        initialized += 1;
    }
    // SAFETY: every element was initialized exactly once and the MaybeUninit
    // array does not drop its contents after this move.
    Ok(unsafe { (&raw const views).cast::<[DirectVtdTables; UNITS]>().read() })
}

pub struct VtdIdentityLeaf<'a> {
    physical: PhysAddr,
    domain_id: u16,
    entry: &'a mut u64,
}

impl VtdIdentityLeaf<'_> {
    pub const fn physical(&self) -> PhysAddr {
        self.physical
    }

    pub const fn domain_id(&self) -> u16 {
        self.domain_id
    }
}

impl<'a> VtdIdentityLeaf<'a> {
    /// # Safety
    ///
    /// The caller assumes exclusive responsibility for ordered VT-d cache
    /// invalidation after changing this live entry.
    pub unsafe fn into_live_entry(self) -> &'a mut u64 {
        self.entry
    }
}

pub fn bind_legacy_identity_leaf<'a, M: VtdTableMemory>(
    memory: &'a mut M,
    root_table_address: u64,
    requester: DeviceAddress,
    physical: PhysAddr,
    expected_domain: u16,
) -> Result<VtdIdentityLeaf<'a>, VtdTableError> {
    let (table, index, _) = find_legacy_leaf(
        memory,
        root_table_address,
        requester,
        physical.get(),
        physical.get(),
        expected_domain,
        false,
    )?;
    let entry = exclusive_leaf(memory, table, index)?;
    Ok(VtdIdentityLeaf {
        physical,
        domain_id: expected_domain,
        entry,
    })
}

fn find_legacy_leaf<M: VtdTableMemory>(
    memory: &M,
    root_table_address: u64,
    requester: DeviceAddress,
    device_address: u64,
    backing_address: u64,
    expected_domain: u16,
    allow_denied: bool,
) -> Result<(PhysAddr, usize, u64), VtdTableError> {
    let (table, index, permissions) = walk_legacy_slot(
        memory,
        root_table_address,
        requester,
        device_address,
        expected_domain,
    )?;
    let leaf = memory.read64(table, index)?;
    if leaf & 0x3 == 0 && !allow_denied {
        return Err(VtdTableError::MissingLeaf);
    }
    if leaf & (1 << 7) != 0 {
        return Err(VtdTableError::LargePage);
    }
    if leaf & !(ADDRESS_MASK | ENTRY_FLAGS) != 0 {
        return Err(VtdTableError::InvalidIntermediate);
    }
    if leaf & ADDRESS_MASK != backing_address {
        return Err(VtdTableError::AliasedLeaf);
    }
    Ok((table, index, permissions & leaf & 3))
}

fn walk_legacy_slot<M: VtdTableMemory>(
    memory: &M,
    root_table_address: u64,
    requester: DeviceAddress,
    device_address: u64,
    expected_domain: u16,
) -> Result<(PhysAddr, usize, u64), VtdTableError> {
    if root_table_address & 0xc00 != 0 {
        return Err(VtdTableError::UnsupportedRootMode);
    }
    if root_table_address & !(ADDRESS_MASK | 0xc00) != 0 || root_table_address & 0x3ff != 0 {
        return Err(VtdTableError::InvalidRoot);
    }
    let root =
        checked_table(root_table_address & ADDRESS_MASK).map_err(|_| VtdTableError::InvalidRoot)?;
    let root_entry = memory.read128(root, usize::from(requester.bus()))?;
    if root_entry[0] & 1 == 0 {
        return Err(VtdTableError::MissingRootEntry);
    }
    if root_entry[1] != 0 || root_entry[0] & !(ADDRESS_MASK | 1) != 0 {
        return Err(VtdTableError::InvalidRootEntry);
    }
    let context_table =
        checked_table(root_entry[0] & ADDRESS_MASK).map_err(|_| VtdTableError::InvalidRootEntry)?;
    let context_index = usize::from(requester.device()) * 8 + usize::from(requester.function());
    let context = memory.read128(context_table, context_index)?;
    if context[0] & 1 == 0 {
        return Err(VtdTableError::MissingContextEntry);
    }
    if context[0] & (1 << 1) != 0 {
        return Err(VtdTableError::FaultReportingDisabled);
    }
    if (context[0] >> 2) & 0x3 != 0 {
        return Err(VtdTableError::UnsupportedTranslationType);
    }
    if context[0] & !(ADDRESS_MASK | 0xf) != 0
        || context[1] & !((0x7) | (0xf << 3) | (0xffff << 8)) != 0
    {
        return Err(VtdTableError::InvalidContextEntry);
    }
    if context[1] & 0x7 != 2 {
        return Err(VtdTableError::UnsupportedAddressWidth);
    }
    let domain_id = ((context[1] >> 8) & 0xffff) as u16;
    if domain_id == 0 || domain_id != expected_domain {
        return Err(VtdTableError::WrongDomain);
    }
    let mut table =
        checked_table(context[0] & ADDRESS_MASK).map_err(|_| VtdTableError::InvalidContextEntry)?;
    let mut permissions = 3;
    let shifts = [39u32, 30, 21];
    for shift in shifts {
        let index = ((device_address >> shift) & 0x1ff) as usize;
        let entry = memory.read64(table, index)?;
        if entry & (1 << 7) != 0 {
            return Err(VtdTableError::LargePage);
        }
        if entry & 0x3 == 0 || entry & !(ADDRESS_MASK | ENTRY_FLAGS) != 0 {
            return Err(VtdTableError::InvalidIntermediate);
        }
        permissions &= entry & 3;
        table =
            checked_table(entry & ADDRESS_MASK).map_err(|_| VtdTableError::InvalidIntermediate)?;
    }
    let index = ((device_address >> 12) & 0x1ff) as usize;
    Ok((table, index, permissions))
}

/// Binds a leaf using a requester route produced by checked DMAR and live PCI
/// resolution.
///
/// # Safety
///
/// `root_table_address` must be the RTADDR value read from the verified MMIO
/// unit identified by `route.register_base()`, after translation enable and
/// root-pointer status have been validated for that same unit.
pub unsafe fn bind_routed_legacy_identity_leaf<'a, M: VtdTableMemory>(
    memory: &'a mut M,
    route: VtdRequesterRoute,
    root_table_address: u64,
    physical: PhysAddr,
    expected_domain: u16,
) -> Result<VtdIdentityLeaf<'a>, VtdTableError> {
    bind_legacy_identity_leaf(
        memory,
        root_table_address,
        route.requester(),
        physical,
        expected_domain,
    )
}

/// Constructs one coherent requester leaf plus invalidation adapter.
///
/// # Safety
///
/// `memory` must meet its unsafe table-access contract, and the native mapping
/// consumed by `unit` must remain uniquely owned and stable. The caller must
/// retain exclusive ownership until the resulting adapter is destroyed.
pub unsafe fn bind_routed_dma_isolation<'a, M, R>(
    memory: &'a mut M,
    route: VtdRequesterRoute,
    unit: VerifiedVtdUnit<R>,
    physical: PhysAddr,
    expected_domain: u16,
) -> Result<VtdDmaIsolation<'a, R>, VtdBindingError>
where
    M: VtdTableMemory,
    R: VtdRegisterIo,
{
    let (verified_unit, mut invalidator) = unit.into_parts();
    let requirement = verified_unit.requirement();
    if !verified_unit_matches_route(&verified_unit, route) {
        return Err(VtdBindingError::UnitSubstitution);
    }
    if requirement.pages() < invalidator.register_pages() {
        return Err(VtdBindingError::InsufficientRegisterMapping);
    }
    if !invalidator.table_walks_coherent() {
        return Err(VtdBindingError::Unit(
            VtdError::ApertureInvalidationUnsupported,
        ));
    }
    let root = invalidator
        .active_legacy_root()
        .map_err(VtdBindingError::Unit)?;
    let root_table = PhysAddr::new(root).map_err(|_| VtdBindingError::TableSubstitution)?;
    let provenance = memory.provenance();
    if provenance.register_base() != route.register_base() || provenance.root_table() != root_table
    {
        return Err(VtdBindingError::TableSubstitution);
    }
    // SAFETY: this function's contract binds RTADDR provenance to the exact
    // verified unit represented by both the route and invalidator.
    let leaf =
        unsafe { bind_routed_legacy_identity_leaf(memory, route, root, physical, expected_domain) }
            .map_err(VtdBindingError::Table)?;
    // SAFETY: the returned leaf is unique; invalidation is controlled by the
    // same unit under this function's contract.
    let entry = unsafe { leaf.into_live_entry() };
    // SAFETY: identity and unique-leaf requirements were checked above.
    unsafe { VtdDmaIsolation::new(physical, entry, invalidator) }.map_err(VtdBindingError::Unit)
}

/// Atomically assembles the complete fixed-size set of remapping units for one
/// protected granule.
///
/// # Safety
///
/// Each table-memory element must exclusively control its corresponding unit's
/// pinned translation tables. Every native mapping consumed by `units` must
/// remain uniquely owned and stable. No transition may use the returned set if
/// topology changes without obtaining a new complete-route proof and rebuilding
/// it.
pub unsafe fn bind_routed_dma_set<'a, M, R, const UNITS: usize>(
    memories: &'a mut [M; UNITS],
    authorized_routes: VtdAuthorizedRoutes<UNITS>,
    units: [VerifiedVtdUnit<R>; UNITS],
    physical: PhysAddr,
) -> Result<VtdAuthorizedDmaSet<'a, R, UNITS>, VtdSetBindingError>
where
    M: VtdTableMemory,
    R: VtdRegisterIo,
{
    let owner = authorized_routes.owner();
    let (routes, expected_domains) = authorized_routes.into_parts();
    if UNITS == 0 {
        return Err(VtdSetBindingError::Empty);
    }
    for index in 0..UNITS {
        if routes[..index]
            .iter()
            .any(|route| route.register_base() == routes[index].register_base())
        {
            return Err(VtdSetBindingError::DuplicateUnit);
        }
    }

    let mut set = VtdDmaSet::new(physical);
    for (index, (((memory, route), unit), domain)) in memories
        .iter_mut()
        .zip(routes)
        .zip(units)
        .zip(expected_domains)
        .enumerate()
    {
        // SAFETY: inherited from this function's per-index correspondence and
        // complete-topology contract.
        let isolation = unsafe { bind_routed_dma_isolation(memory, route, unit, physical, domain) }
            .map_err(|error| VtdSetBindingError::Unit { index, error })?;
        // SAFETY: distinct DRHD bases were checked above and every isolation
        // maps the same physical granule by construction.
        unsafe { set.push(isolation) }
            .map_err(VtdBindingError::Unit)
            .map_err(|error| VtdSetBindingError::Unit { index, error })?;
    }
    Ok(VtdAuthorizedDmaSet { owner, set })
}

fn aperture_bytes(
    device_base: u64,
    physical_base: PhysAddr,
    pages: u16,
) -> Result<u64, VtdTableError> {
    let bytes = u64::from(pages) * 4096;
    if !(1..=256).contains(&pages)
        || device_base == 0
        || !device_base.is_multiple_of(4096)
        || device_base
            .checked_add(bytes)
            .is_none_or(|end| end > 1 << 48)
        || physical_base.get() == 0
        || physical_base
            .get()
            .checked_add(bytes)
            .is_none_or(|end| end > 1 << 52)
    {
        Err(VtdTableError::InvalidAperture)
    } else {
        Ok(bytes)
    }
}

fn exclusive_leaf<M: VtdTableMemory>(
    memory: &mut M,
    table: PhysAddr,
    index: usize,
) -> Result<&mut u64, VtdTableError> {
    // SAFETY: called with the exact, preflighted leaf coordinates under
    // the exclusive table borrow required by VtdTableMemory.
    unsafe { memory.leaf_mut(table, index) }
}

fn checked_table(address: u64) -> Result<PhysAddr, VtdTableError> {
    if address == 0 || address & !ADDRESS_MASK != 0 {
        return Err(VtdTableError::Storage);
    }
    PhysAddr::new(address).map_err(|_| VtdTableError::Storage)
}

#[cfg(test)]
mod tests {
    #[test]
    fn boot_table_view_cannot_read_or_modify_outside_six_frames() {
        let root = PhysAddr::new(0x400000).unwrap();
        let mut backing = [[0u64; 512]; SINGLE_REQUESTER_VTD_TABLE_PAGES];
        let mut view = BootVtdTables {
            provenance: VtdTableProvenance {
                register_base: PhysAddr::new(0xfed90000).unwrap(),
                root_table: root,
            },
            backing: &mut backing,
        };
        let last = PhysAddr::new(root.get() + 5 * PAGE_SIZE).unwrap();
        let below = PhysAddr::new(root.get() - PAGE_SIZE).unwrap();
        let past = PhysAddr::new(root.get() + 6 * PAGE_SIZE).unwrap();
        assert_eq!(view.read64(last, 511), Ok(0));
        assert_eq!(view.read128(last, 256), Err(VtdTableError::Storage));
        assert_eq!(view.read64(below, 0), Err(VtdTableError::Storage));
        assert_eq!(view.read64(last, 512), Err(VtdTableError::Storage));
        // SAFETY: the test owns this local backing; there is no live device.
        unsafe {
            assert_eq!(view.leaf_mut(past, 0), Err(VtdTableError::Storage));
            *view.leaf_mut(last, 511).unwrap() = 0x1234;
        }
        assert_eq!(view.read128(last, 255), Ok([0, 0x1234]));
    }

    use super::super::DmaIsolation;
    use super::super::VirtAddr;
    use super::super::platform_mmio::{verified_vtd_for_test, verified_vtd_mapping_for_test};
    use super::*;

    const ROOT: u64 = 0x10_0000;
    const CONTEXT: u64 = 0x11_0000;
    const LEVEL4: u64 = 0x12_0000;
    const LEVEL3: u64 = 0x13_0000;
    const LEVEL2: u64 = 0x14_0000;
    const LEVEL1: u64 = 0x15_0000;

    #[test]
    fn isolated_legacy_root_starts_with_one_context_and_no_dma_leaves() {
        let root = PhysAddr::new(ROOT).unwrap();
        let requester = DeviceAddress::new(0, 2, 3, 1).unwrap();
        let aperture = VtdDmaAperture {
            route: VtdRequesterRoute::for_test(requester, PhysAddr::new(0xfed9_0000).unwrap()),
            hardware_domain: 9,
            device_base: 0x4040_4000,
            physical_base: PhysAddr::new(0x40_0000).unwrap(),
            pages: 16,
        };
        let mut image = [[u64::MAX; 512]; SINGLE_REQUESTER_VTD_TABLE_PAGES];
        build_single_requester_legacy_root(&mut image, root, aperture).unwrap();
        let entries = [
            (0, 4, (ROOT + 0x1000) | 1),
            (1, 50, (ROOT + 0x2000) | 1),
            (1, 51, 0x902),
            (2, 0, (ROOT + 0x3000) | 3),
            (3, 1, (ROOT + 0x4000) | 3),
            (4, 2, (ROOT + 0x5000) | 3),
        ];
        for (page, values) in image.iter().enumerate() {
            for (index, &value) in values.iter().enumerate() {
                assert_eq!(
                    value,
                    entries
                        .iter()
                        .find(|&&(p, i, _)| p == page && i == index)
                        .map_or(0, |&(_, _, v)| v)
                );
            }
        }
        let original = image;
        for bad in [
            VtdDmaAperture {
                device_base: 0x401f_f000,
                ..aperture
            },
            VtdDmaAperture {
                physical_base: PhysAddr::new(ROOT + 0x3000).unwrap(),
                ..aperture
            },
        ] {
            assert_eq!(
                build_single_requester_legacy_root(&mut image, root, bad),
                Err(VtdTableError::InvalidAperture)
            );
            assert_eq!(image, original);
        }
        assert_eq!(
            build_single_requester_legacy_root(
                &mut image,
                PhysAddr::new((1 << 52) - PAGE_SIZE).unwrap(),
                aperture,
            ),
            Err(VtdTableError::InvalidRoot)
        );
        assert_eq!(image, original);
    }

    #[test]
    fn writeback_geometry_validates_cpuid_and_touches_only_slice_lines() {
        assert_eq!(clflush_line_bytes(8 << 8, 1 << 19), Some(64));
        assert_eq!(clflush_line_bytes(8 << 8, 0), None);
        assert_eq!(clflush_line_bytes(3 << 8, 1 << 19), None);
        assert_eq!(clflush_line_bytes(0, 1 << 19), None);
        let mut touched = [usize::MAX; 4];
        let mut count = 0;
        visit_writeback_offsets(0x1038, 80, 64, |offset| {
            touched[count] = offset;
            count += 1;
        })
        .unwrap();
        assert_eq!(count, 3);
        assert_eq!(touched, [0, 8, 72, usize::MAX]);
        for (start, bytes, line) in [
            (0, 0, 64),
            (0, MAX_VTD_WRITEBACK_BYTES + 1, 64),
            (usize::MAX, 2, 64),
            (0, 8, 0),
            (0, 8, 48),
        ] {
            assert_eq!(
                visit_writeback_offsets(start, bytes, line, |_| panic!("unexpected writeback")),
                Err(VtdTableError::WritebackUnavailable)
            );
        }
    }

    struct Tables {
        provenance: VtdTableProvenance,
        root: [u64; 512],
        context: [u64; 512],
        level4: [u64; 512],
        level3: [u64; 512],
        level2: [u64; 512],
        level1: [u64; 512],
        denied_write: Option<usize>,
        explicit_writeback: bool,
        failed_writeback: Option<usize>,
        published: [u64; 2],
    }

    impl Tables {
        fn identity(physical: PhysAddr, domain: u16) -> Self {
            let mut tables = Self {
                provenance: VtdTableProvenance {
                    register_base: PhysAddr::new(0xfed9_0000).unwrap(),
                    root_table: PhysAddr::new(ROOT).unwrap(),
                },
                root: [0; 512],
                context: [0; 512],
                level4: [0; 512],
                level3: [0; 512],
                level2: [0; 512],
                level1: [0; 512],
                denied_write: None,
                explicit_writeback: false,
                failed_writeback: None,
                published: [0; 2],
            };
            tables.root[2 * 2] = CONTEXT | 1;
            let context_index = 3 * 8;
            tables.context[context_index * 2] = LEVEL4 | 1;
            tables.context[context_index * 2 + 1] = 2 | (u64::from(domain) << 8);
            tables.level4[((physical.get() >> 39) & 0x1ff) as usize] = LEVEL3 | 3;
            tables.level3[((physical.get() >> 30) & 0x1ff) as usize] = LEVEL2 | 3;
            tables.level2[((physical.get() >> 21) & 0x1ff) as usize] = LEVEL1 | 3;
            tables.level1[((physical.get() >> 12) & 0x1ff) as usize] = physical.get() | 3;
            tables
        }

        fn for_unit(mut self, register_base: PhysAddr) -> Self {
            self.provenance.register_base = register_base;
            self
        }

        fn for_root(mut self, root_table: PhysAddr) -> Self {
            self.provenance.root_table = root_table;
            self
        }

        fn table(&self, physical: PhysAddr) -> Option<&[u64; 512]> {
            match physical.get() {
                ROOT => Some(&self.root),
                CONTEXT => Some(&self.context),
                LEVEL4 => Some(&self.level4),
                LEVEL3 => Some(&self.level3),
                LEVEL2 => Some(&self.level2),
                LEVEL1 => Some(&self.level1),
                _ => None,
            }
        }
    }

    unsafe impl VtdTableMemory for Tables {
        fn provenance(&self) -> VtdTableProvenance {
            self.provenance
        }

        fn supports_explicit_writeback(&self) -> bool {
            self.explicit_writeback
        }

        fn write_back_leaf(&mut self, table: PhysAddr, index: usize) -> Result<(), VtdTableError> {
            if !self.explicit_writeback
                || self.failed_writeback == Some(index)
                || table.get() != LEVEL1
            {
                return Err(VtdTableError::WritebackUnavailable);
            }
            *self
                .published
                .get_mut(index)
                .ok_or(VtdTableError::WritebackUnavailable)? = self.level1[index];
            Ok(())
        }

        fn read128(&self, table: PhysAddr, index: usize) -> Result<[u64; 2], VtdTableError> {
            let entries = self.table(table).ok_or(VtdTableError::Storage)?;
            let start = index.checked_mul(2).ok_or(VtdTableError::Storage)?;
            Ok([
                *entries.get(start).ok_or(VtdTableError::Storage)?,
                *entries.get(start + 1).ok_or(VtdTableError::Storage)?,
            ])
        }

        fn read64(&self, table: PhysAddr, index: usize) -> Result<u64, VtdTableError> {
            self.table(table)
                .and_then(|entries| entries.get(index))
                .copied()
                .ok_or(VtdTableError::Storage)
        }

        unsafe fn leaf_mut(
            &mut self,
            table: PhysAddr,
            index: usize,
        ) -> Result<&mut u64, VtdTableError> {
            if table.get() != LEVEL1 || self.denied_write == Some(index) {
                return Err(VtdTableError::Storage);
            }
            self.level1.get_mut(index).ok_or(VtdTableError::Storage)
        }
    }

    fn requester() -> DeviceAddress {
        DeviceAddress::new(0, 2, 3, 0).unwrap()
    }

    fn test_owner() -> DomainId {
        ProtectedMonitor::<1, 0>::new().create_domain().unwrap()
    }

    struct UnitRegisters {
        root: u64,
        status: u32,
        context: u64,
        iotlb: u64,
        drain: bool,
        coherent: bool,
        bad_completion_once: bool,
        stuck_iotlb: bool,
        root_after_drain: Option<u64>,
    }

    impl UnitRegisters {
        fn active(root: u64) -> Self {
            Self {
                root,
                status: (1 << 31) | (1 << 30),
                context: 0,
                iotlb: 0,
                drain: true,
                coherent: true,
                bad_completion_once: false,
                stuck_iotlb: false,
                root_after_drain: None,
            }
        }
    }

    impl VtdRegisterIo for UnitRegisters {
        fn register_bytes(&self) -> usize {
            PAGE_SIZE as usize
        }

        fn read32(&mut self, offset: usize) -> u32 {
            match offset {
                0x1c => self.status,
                0x34 => 0,
                _ => 0,
            }
        }

        fn write32(&mut self, _offset: usize, _value: u32) {}

        fn read64(&mut self, offset: usize) -> u64 {
            match offset {
                0x08 => (0x40 << 24) | if self.drain { 3 << 54 } else { 0 },
                0x10 => (0x20 << 8) | u64::from(self.coherent),
                0x20 => self.root,
                0x28 => self.context,
                0x208 => self.iotlb,
                _ => 0,
            }
        }

        fn write64(&mut self, offset: usize, value: u64) {
            match offset {
                0x28 => {
                    assert_eq!((value >> 61) & 3, 1);
                    self.context = (value & !(1 << 63)) | (1 << 59);
                }
                0x208 if self.stuck_iotlb => self.iotlb = value,
                0x208 if core::mem::take(&mut self.bad_completion_once) => self.iotlb = 0,
                0x208 => {
                    self.iotlb = (value & !(1 << 63)) | (1 << 57);
                    if let Some(root) = self.root_after_drain.take() {
                        self.root = root;
                    }
                }
                _ => {}
            }
        }
    }

    fn verified_unit(
        register_base: PhysAddr,
        registers: UnitRegisters,
    ) -> VerifiedVtdUnit<UnitRegisters> {
        VerifiedVtdUnit::for_test(
            verified_vtd_for_test(register_base, 1, requester().segment()),
            VtdInvalidator::new(registers, 4).unwrap(),
        )
    }

    #[repr(align(4096))]
    struct RegisterPage([u64; 512]);

    #[test]
    fn routed_install_rejects_occupied_leaves_and_rolls_back_failed_publication() {
        let device = PhysAddr::new(0x20_0000).unwrap();
        let backing = PhysAddr::new(0x80_0000).unwrap();
        let register = PhysAddr::new(0xfed9_0000).unwrap();
        let aperture = VtdDmaAperture {
            route: VtdRequesterRoute::for_test(requester(), register),
            hardware_domain: 9,
            device_base: device.get(),
            physical_base: backing,
            pages: 2,
        };
        let mut tables = Tables::identity(device, 9);
        tables.level1[0] = 0;
        tables.level1[1] = backing.get(); // Denied-but-retained is not free.
        let mut unit = verified_unit(register, UnitRegisters::active(ROOT));
        assert_eq!(
            unit.install_routed_dma_aperture(&mut tables, aperture),
            Err(VtdApertureInstallError::Rejected(VtdBindingError::Table(
                VtdTableError::OccupiedLeaf
            )))
        );
        assert_eq!(&tables.level1[..2], &[0, backing.get()]);
        tables.level1[1] = 0;
        tables.level1[2] = 0x90_0003;
        tables.denied_write = Some(1);
        assert_eq!(
            unit.install_routed_dma_aperture(&mut tables, aperture),
            Err(VtdApertureInstallError::RolledBack(VtdBindingError::Table(
                VtdTableError::Storage
            )))
        );
        assert_eq!(&tables.level1[..3], &[0, 0, 0x90_0003]);
        tables.denied_write = None;

        let mut failed_completion = UnitRegisters::active(ROOT);
        failed_completion.bad_completion_once = true;
        assert_eq!(
            verified_unit(register, failed_completion)
                .install_routed_dma_aperture(&mut tables, aperture),
            Err(VtdApertureInstallError::RolledBack(VtdBindingError::Unit(
                VtdError::InvalidCompletion
            )))
        );
        assert_eq!(&tables.level1[..3], &[0, 0, 0x90_0003]);

        assert_eq!(
            unit.install_routed_dma_aperture(&mut tables, aperture),
            Ok(())
        );
        assert_eq!(
            unit.verify_routed_dma_aperture(&tables, aperture.route, 9, device.get(), backing, 2),
            Ok(())
        );
        assert_eq!(
            unit.revoke_routed_dma_aperture(&mut tables, aperture),
            Ok(())
        );
        assert_eq!(
            &tables.level1[..3],
            &[backing.get(), backing.get() + 4096, 0x90_0003]
        );

        let mut stuck = UnitRegisters::active(ROOT);
        stuck.stuck_iotlb = true;
        tables.level1[..2].fill(0);
        assert_eq!(
            verified_unit(register, stuck).install_routed_dma_aperture(&mut tables, aperture),
            Err(VtdApertureInstallError::Uncertain(VtdBindingError::Unit(
                VtdError::Busy
            )))
        );
        assert_eq!(&tables.level1[..3], &[0, 0, 0x90_0003]);
    }

    #[test]
    fn noncoherent_aperture_requires_real_writeback_and_quarantines_failed_updates() {
        let device = PhysAddr::new(0x20_0000).unwrap();
        let backing = PhysAddr::new(0x80_0000).unwrap();
        let register = PhysAddr::new(0xfed9_0000).unwrap();
        let aperture = VtdDmaAperture {
            route: VtdRequesterRoute::for_test(requester(), register),
            hardware_domain: 9,
            device_base: device.get(),
            physical_base: backing,
            pages: 2,
        };
        let mut registers = UnitRegisters::active(ROOT);
        registers.coherent = false;
        let mut unit = verified_unit(register, registers);
        let mut tables = Tables::identity(device, 9);
        tables.level1[..2].fill(0);
        assert_eq!(
            unit.install_routed_dma_aperture(&mut tables, aperture),
            Err(VtdApertureInstallError::Rejected(VtdBindingError::Unit(
                VtdError::ApertureInvalidationUnsupported
            )))
        );
        assert_eq!(&tables.level1[..2], &[0, 0]);

        tables.explicit_writeback = true;
        tables.failed_writeback = Some(1);
        assert_eq!(
            unit.install_routed_dma_aperture(&mut tables, aperture),
            Err(VtdApertureInstallError::Uncertain(VtdBindingError::Table(
                VtdTableError::WritebackUnavailable
            )))
        );
        assert_eq!(&tables.level1[..2], &[0, 0]);
        assert_eq!(tables.published, [0, 0]); // first leaf's rollback made it back
        let (_, invalidator) = unit.into_parts();
        let registers = invalidator.into_registers();
        assert_eq!(registers.context, 0); // no invalidation after uncertain rollback

        let mut unit = verified_unit(register, registers);
        tables.failed_writeback = None;
        unit.install_routed_dma_aperture(&mut tables, aperture)
            .unwrap();
        assert_eq!(
            tables.published,
            [backing.get() | 3, (backing.get() + 4096) | 3]
        );

        tables.failed_writeback = Some(1);
        assert_eq!(
            unit.revoke_routed_dma_aperture(&mut tables, aperture),
            Err(VtdApertureRevokeError::Uncertain(VtdBindingError::Table(
                VtdTableError::WritebackUnavailable
            )))
        );
        assert_eq!(
            tables.published,
            [backing.get(), (backing.get() + 4096) | 3]
        );
        tables.failed_writeback = None;
        unit.revoke_routed_dma_aperture(&mut tables, aperture)
            .unwrap();
        assert_eq!(tables.published, [backing.get(), backing.get() + 4096]);
    }

    #[test]
    fn routed_revocation_preflights_the_full_aperture_and_retries_uncertain_flush() {
        let device = PhysAddr::new(0x20_0000).unwrap();
        let backing = PhysAddr::new(0x80_0000).unwrap();
        let register = PhysAddr::new(0xfed9_0000).unwrap();
        let aperture = VtdDmaAperture {
            route: VtdRequesterRoute::for_test(requester(), register),
            hardware_domain: 9,
            device_base: device.get(),
            physical_base: backing,
            pages: 2,
        };
        let mut registers = UnitRegisters::active(ROOT);
        registers.bad_completion_once = true;
        let mut unit = verified_unit(register, registers);
        let mut tables = Tables::identity(device, 9);
        tables.level1[0] = backing.get() | 3;
        tables.level1[1] = (backing.get() + 8192) | 3;
        tables.level1[2] = (backing.get() + 8192) | 3;
        assert_eq!(
            unit.revoke_routed_dma_aperture(&mut tables, aperture),
            Err(VtdApertureRevokeError::Rejected(VtdBindingError::Table(
                VtdTableError::AliasedLeaf
            )))
        );
        assert_eq!(tables.level1[0], backing.get() | 3);
        tables.level1[1] = (backing.get() + 4096) | 3;

        let mut no_drain = UnitRegisters::active(ROOT);
        no_drain.drain = false;
        assert_eq!(
            verified_unit(register, no_drain).revoke_routed_dma_aperture(&mut tables, aperture),
            Err(VtdApertureRevokeError::Rejected(VtdBindingError::Unit(
                VtdError::DrainUnsupported
            )))
        );
        assert_eq!(tables.level1[0], backing.get() | 3);

        assert_eq!(
            unit.revoke_routed_dma_aperture(&mut tables, aperture),
            Err(VtdApertureRevokeError::Uncertain(VtdBindingError::Unit(
                VtdError::InvalidCompletion
            )))
        );
        assert_eq!(
            &tables.level1[..3],
            &[
                backing.get(),
                backing.get() + 4096,
                (backing.get() + 8192) | 3,
            ]
        );
        assert_eq!(
            unit.revoke_routed_dma_aperture(&mut tables, aperture),
            Ok(())
        );
    }

    #[test]
    fn routed_denial_requires_the_exact_empty_context_and_completed_drain() {
        let physical = PhysAddr::new(0x20_0000).unwrap();
        let register = PhysAddr::new(0xfed9_0000).unwrap();
        let route = VtdRequesterRoute::for_test(requester(), register);
        let mut tables = Tables::identity(physical, 9);
        let mut unit = verified_unit(register, UnitRegisters::active(ROOT));
        let occupied = Err(VtdBindingError::Table(VtdTableError::OccupiedContext));
        assert_eq!(unit.verify_routed_dma_denied(&tables, route), occupied);
        let slot = 2 * (3 * 8);
        tables.context[slot + 2] = tables.context[slot];
        tables.context[slot + 3] = tables.context[slot + 1];
        tables.context[slot] = 0;
        assert_eq!(unit.verify_routed_dma_denied(&tables, route), occupied);
        tables.context[slot + 1] = 0;
        assert_eq!(unit.verify_routed_dma_denied(&tables, route), Ok(()));
        let neighbor = VtdRequesterRoute::for_test(DeviceAddress::new(0, 2, 3, 1).unwrap(), register);
        assert_eq!(unit.verify_routed_dma_denied(&tables, neighbor), occupied);

        let mut missing_drain = UnitRegisters::active(ROOT);
        missing_drain.drain = false;
        let mut unit = verified_unit(register, missing_drain);
        assert_eq!(
            unit.verify_routed_dma_denied(&tables, route),
            Err(VtdBindingError::Unit(VtdError::DrainUnsupported))
        );
        let mut failed_drain = UnitRegisters::active(ROOT);
        failed_drain.bad_completion_once = true;
        let mut unit = verified_unit(register, failed_drain);
        assert_eq!(
            unit.verify_routed_dma_denied(&tables, route),
            Err(VtdBindingError::Unit(VtdError::InvalidCompletion))
        );
        assert_eq!(unit.verify_routed_dma_denied(&tables, route), Ok(()));
        let mut switched = UnitRegisters::active(ROOT);
        switched.root_after_drain = Some(ROOT + 4096);
        let mut switched_unit = verified_unit(register, switched);
        assert_eq!(
            switched_unit.verify_routed_dma_denied(&tables, route),
            Err(VtdBindingError::TableSubstitution)
        );
        let new_root = tables.for_root(PhysAddr::new(ROOT + 4096).unwrap());
        assert_eq!(
            unit.verify_routed_dma_denied(&new_root, route),
            Err(VtdBindingError::TableSubstitution)
        );
    }

    #[test]
    fn routed_aperture_checks_every_page_and_effective_permissions() {
        let iova = PhysAddr::new(0x20_0000).unwrap();
        let backing = PhysAddr::new(0x80_0000).unwrap();
        let registers = PhysAddr::new(0xfed9_0000).unwrap();
        let route = VtdRequesterRoute::for_test(requester(), registers);
        let mut unit = verified_unit(registers, UnitRegisters::active(ROOT));
        let mut tables = Tables::identity(iova, 9);

        tables.level1[0] = backing.get() | 3;
        assert_eq!(
            unit.verify_routed_dma_aperture(&tables, route, 9, iova.get(), backing, 2),
            Err(VtdBindingError::Table(VtdTableError::MissingLeaf))
        );
        tables.level1[1] = backing.get() | 3;
        assert_eq!(
            unit.verify_routed_dma_aperture(&tables, route, 9, iova.get(), backing, 2),
            Err(VtdBindingError::Table(VtdTableError::AliasedLeaf))
        );
        tables.level1[1] = (backing.get() + 4096) | 3;
        assert_eq!(
            unit.verify_routed_dma_aperture(&tables, route, 9, iova.get(), backing, 2),
            Ok(())
        );
        tables.level2[1] &= !2;
        assert_eq!(
            unit.verify_routed_dma_aperture(&tables, route, 9, iova.get(), backing, 2),
            Err(VtdBindingError::Table(
                VtdTableError::InsufficientPermissions
            ))
        );
        assert_eq!(
            unit.verify_routed_dma_aperture(&tables, route, 10, iova.get(), backing, 2),
            Err(VtdBindingError::Table(VtdTableError::WrongDomain))
        );
        assert_eq!(
            unit.verify_routed_dma_aperture(&tables, route, 9, (1 << 48) - 4096, backing, 2),
            Err(VtdBindingError::Table(VtdTableError::InvalidAperture))
        );
        let wrong_unit =
            VtdRequesterRoute::for_test(requester(), PhysAddr::new(0xfeda_0000).unwrap());
        assert_eq!(
            unit.verify_routed_dma_aperture(&tables, wrong_unit, 9, iova.get(), backing, 2),
            Err(VtdBindingError::UnitSubstitution)
        );
        let stale_tables = tables.for_root(PhysAddr::new(ROOT + 4096).unwrap());
        assert_eq!(
            unit.verify_routed_dma_aperture(&stale_tables, route, 9, iova.get(), backing, 2),
            Err(VtdBindingError::TableSubstitution)
        );
    }

    #[test]
    fn binds_exact_requester_domain_and_identity_leaf() {
        let physical = PhysAddr::new(0x20_0000).unwrap();
        let mut tables = Tables::identity(physical, 9);
        let binding =
            bind_legacy_identity_leaf(&mut tables, ROOT, requester(), physical, 9).unwrap();
        assert_eq!(binding.physical(), physical);
        assert_eq!(binding.domain_id(), 9);
        let entry = unsafe { binding.into_live_entry() };
        *entry &= !0x3;
        assert_eq!(tables.level1[0] & 0x3, 0);
    }

    #[test]
    fn rejects_wrong_domain_passthrough_and_aliases() {
        let physical = PhysAddr::new(0x20_0000).unwrap();
        let mut wrong_domain = Tables::identity(physical, 9);
        assert!(matches!(
            bind_legacy_identity_leaf(&mut wrong_domain, ROOT, requester(), physical, 10),
            Err(VtdTableError::WrongDomain)
        ));

        let mut passthrough = Tables::identity(physical, 9);
        passthrough.context[(3 * 8) * 2] |= 2 << 2;
        assert!(matches!(
            bind_legacy_identity_leaf(&mut passthrough, ROOT, requester(), physical, 9),
            Err(VtdTableError::UnsupportedTranslationType)
        ));

        let mut alias = Tables::identity(physical, 9);
        alias.level1[0] = 0x21_0000 | 3;
        assert!(matches!(
            bind_legacy_identity_leaf(&mut alias, ROOT, requester(), physical, 9),
            Err(VtdTableError::AliasedLeaf)
        ));
    }

    #[test]
    fn rejects_huge_page_before_leaf_binding() {
        let physical = PhysAddr::new(0x20_0000).unwrap();
        let mut tables = Tables::identity(physical, 9);
        tables.level2[1] |= 1 << 7;
        assert!(matches!(
            bind_legacy_identity_leaf(&mut tables, ROOT, requester(), physical, 9),
            Err(VtdTableError::LargePage)
        ));
    }

    #[test]
    fn coherent_unit_binding_revokes_the_routed_identity_leaf() {
        let physical = PhysAddr::new(0x20_0000).unwrap();
        let register_base = PhysAddr::new(0xfed9_0000).unwrap();
        let route = VtdRequesterRoute::for_test(requester(), register_base);
        let unit = verified_unit(register_base, UnitRegisters::active(ROOT));
        let mut tables = Tables::identity(physical, 9);

        {
            let mut isolation =
                unsafe { bind_routed_dma_isolation(&mut tables, route, unit, physical, 9) }
                    .unwrap();
            assert_eq!(
                isolation.deny_and_invalidate(physical),
                GranuleHardwareOutcome::Applied
            );
        }
        assert_eq!(tables.level1[0] & 0x3, 0);
    }

    #[test]
    fn native_unit_consumes_verified_extent_and_rejects_short_mapping() {
        let physical = PhysAddr::new(0xfed9_0000).unwrap();
        let mut registers = RegisterPage([0; 512]);
        registers.0[0x08 / 8] = 0x40 << 24;
        registers.0[0x10 / 8] = 0x20 << 8;
        let virtual_start = VirtAddr::new(registers.0.as_mut_ptr() as u64).unwrap();
        let verified = verified_vtd_mapping_for_test(physical, 1, 0, virtual_start);
        {
            let unit = unsafe { VerifiedVtdUnit::from_native(verified, 4) }.unwrap();
            let (verified, invalidator) = unit.into_parts();
            assert_eq!(verified.requirement().physical(), physical);
            assert_eq!(invalidator.register_pages(), 1);
        }

        // SAFETY: the aligned test page is still exclusively owned here; use
        // a volatile store to model a hardware-visible capability change.
        unsafe {
            registers
                .0
                .as_mut_ptr()
                .add(0x08 / 8)
                .write_volatile((0x3ff << 24) | (0xff << 40));
        }
        let verified = verified_vtd_mapping_for_test(physical, 1, 0, virtual_start);
        assert!(matches!(
            unsafe { VerifiedVtdUnit::from_native(verified, 4) },
            Err(VtdBindingError::InsufficientRegisterMapping)
        ));
    }

    #[test]
    fn domain_authority_rejects_collisions_missing_units_and_stale_owners() {
        let first_base = PhysAddr::new(0xfed9_0000).unwrap();
        let second_base = PhysAddr::new(0xfeda_0000).unwrap();
        let routes = [
            VtdRequesterRoute::for_test(requester(), first_base),
            VtdRequesterRoute::for_test(requester(), second_base),
        ];
        let mut monitor = ProtectedMonitor::<2, 0>::new();
        let owner = monitor.create_domain().unwrap();
        let other = monitor.create_domain().unwrap();
        let mut authority = VtdDomainAuthority::<2>::new();
        assert_eq!(
            authority.register(&monitor, owner, first_base, 0),
            Err(VtdDomainError::InvalidHardwareDomain)
        );
        authority.register(&monitor, owner, first_base, 9).unwrap();
        assert_eq!(
            authority.register(&monitor, owner, first_base, 10),
            Err(VtdDomainError::DuplicateBinding)
        );
        assert_eq!(
            authority.register(&monitor, other, first_base, 9),
            Err(VtdDomainError::HardwareDomainCollision)
        );
        assert!(matches!(
            authority.authorize(&monitor, owner, CompleteVtdRoutes::for_test(routes),),
            Err(VtdDomainError::MissingBinding)
        ));
        authority
            .register(&monitor, owner, second_base, 10)
            .unwrap();
        let authorized = authority
            .authorize(&monitor, owner, CompleteVtdRoutes::for_test(routes))
            .unwrap();
        assert_eq!(authorized.owner(), owner);
        let (_, hardware_domains) = authorized.into_parts();
        assert_eq!(hardware_domains, [9, 10]);

        monitor.destroy_domain(owner).unwrap();
        assert!(matches!(
            authority.authorize(&monitor, owner, CompleteVtdRoutes::for_test(routes),),
            Err(VtdDomainError::Monitor(MonitorError::StaleDomain))
        ));
    }

    #[test]
    fn prepares_direct_views_in_order_and_rechecks_root_before_walking() {
        let empty_authorized = VtdAuthorizedRoutes::for_test(test_owner(), [], []);
        let mut empty_units: [VerifiedVtdUnit<UnitRegisters>; 0] = [];
        assert!(matches!(
            unsafe { prepare_direct_vtd_tables(&empty_authorized, &mut empty_units) },
            Err(VtdSetBindingError::Empty)
        ));

        let first_base = PhysAddr::new(0xfed9_0000).unwrap();
        let second_base = PhysAddr::new(0xfeda_0000).unwrap();
        let route = VtdRequesterRoute::for_test(requester(), first_base);
        let second_route = VtdRequesterRoute::for_test(requester(), second_base);
        let authorized =
            VtdAuthorizedRoutes::for_test(test_owner(), [route, second_route], [9, 10]);
        let first_root_page = RegisterPage([0; 512]);
        let second_root_page = RegisterPage([0; 512]);
        let first_root = PhysAddr::new(first_root_page.0.as_ptr() as u64).unwrap();
        let second_root = PhysAddr::new(second_root_page.0.as_ptr() as u64).unwrap();
        let mut units = [
            verified_unit(first_base, UnitRegisters::active(first_root.get())),
            verified_unit(second_base, UnitRegisters::active(second_root.get())),
        ];
        let views = unsafe { prepare_direct_vtd_tables(&authorized, &mut units) }.unwrap();
        assert_eq!(views[0].provenance().register_base(), first_base);
        assert_eq!(views[0].provenance().root_table(), first_root);
        assert_eq!(views[1].provenance().register_base(), second_base);
        assert_eq!(views[1].provenance().root_table(), second_root);

        let mut reordered_units = [
            verified_unit(second_base, UnitRegisters::active(second_root.get())),
            verified_unit(first_base, UnitRegisters::active(first_root.get())),
        ];
        assert!(matches!(
            unsafe { prepare_direct_vtd_tables(&authorized, &mut reordered_units) },
            Err(VtdSetBindingError::Unit {
                index: 0,
                error: VtdBindingError::UnitSubstitution
            })
        ));

        let mut inactive = UnitRegisters::active(second_root.get());
        inactive.status &= !(1 << 30);
        let mut partial_units = [
            verified_unit(first_base, UnitRegisters::active(first_root.get())),
            verified_unit(second_base, inactive),
        ];
        assert!(matches!(
            unsafe { prepare_direct_vtd_tables(&authorized, &mut partial_units) },
            Err(VtdSetBindingError::Unit {
                index: 1,
                error: VtdBindingError::Unit(VtdError::RootPointerInactive)
            })
        ));

        let replacement_root_page = RegisterPage([0; 512]);
        let replacement_root = PhysAddr::new(replacement_root_page.0.as_ptr() as u64).unwrap();
        let one_authorized = VtdAuthorizedRoutes::for_test(test_owner(), [route], [9]);
        let mut original_unit = [verified_unit(
            first_base,
            UnitRegisters::active(first_root.get()),
        )];
        let mut stale_view =
            unsafe { prepare_direct_vtd_tables(&one_authorized, &mut original_unit) }.unwrap();
        let replacement_unit = [verified_unit(
            first_base,
            UnitRegisters::active(replacement_root.get()),
        )];
        assert!(matches!(
            unsafe {
                bind_routed_dma_set(
                    &mut stale_view,
                    one_authorized,
                    replacement_unit,
                    PhysAddr::new(0x20_0000).unwrap(),
                )
            },
            Err(VtdSetBindingError::Unit {
                index: 0,
                error: VtdBindingError::TableSubstitution
            })
        ));
    }

    #[test]
    fn coherent_unit_binding_rejects_substitution_and_inactive_root() {
        let physical = PhysAddr::new(0x20_0000).unwrap();
        let register_base = PhysAddr::new(0xfed9_0000).unwrap();
        let route = VtdRequesterRoute::for_test(requester(), register_base);
        let substituted = VerifiedVtdUnit::for_test(
            verified_vtd_for_test(
                PhysAddr::new(0xfeda_0000).unwrap(),
                1,
                requester().segment(),
            ),
            VtdInvalidator::new(UnitRegisters::active(ROOT), 4).unwrap(),
        );
        let mut tables = Tables::identity(physical, 9);
        assert!(matches!(
            unsafe { bind_routed_dma_isolation(&mut tables, route, substituted, physical, 9,) },
            Err(VtdBindingError::UnitSubstitution)
        ));

        let mut inactive = UnitRegisters::active(ROOT);
        inactive.status &= !(1 << 30);
        assert!(matches!(
            unsafe {
                bind_routed_dma_isolation(
                    &mut tables,
                    route,
                    verified_unit(register_base, inactive),
                    physical,
                    9,
                )
            },
            Err(VtdBindingError::Unit(VtdError::RootPointerInactive))
        ));

        let stale_root = PhysAddr::new(ROOT + 0x1000).unwrap();
        let mut stale_tables = Tables::identity(physical, 9).for_root(stale_root);
        assert!(matches!(
            unsafe {
                bind_routed_dma_isolation(
                    &mut stale_tables,
                    route,
                    verified_unit(register_base, UnitRegisters::active(ROOT)),
                    physical,
                    9,
                )
            },
            Err(VtdBindingError::TableSubstitution)
        ));
    }

    #[test]
    fn complete_set_binding_revokes_every_distinct_unit() {
        let physical = PhysAddr::new(0x20_0000).unwrap();
        let first_base = PhysAddr::new(0xfed9_0000).unwrap();
        let second_base = PhysAddr::new(0xfeda_0000).unwrap();
        let routes = [
            VtdRequesterRoute::for_test(requester(), first_base),
            VtdRequesterRoute::for_test(requester(), second_base),
        ];
        let units = [
            verified_unit(first_base, UnitRegisters::active(ROOT)),
            verified_unit(second_base, UnitRegisters::active(ROOT)),
        ];
        let mut tables = [
            Tables::identity(physical, 9).for_unit(first_base),
            Tables::identity(physical, 9).for_unit(second_base),
        ];

        {
            let mut set = unsafe {
                bind_routed_dma_set(
                    &mut tables,
                    VtdAuthorizedRoutes::for_test(test_owner(), routes, [9, 9]),
                    units,
                    physical,
                )
            }
            .unwrap();
            assert_eq!(set.len(), 2);
            assert_eq!(
                set.deny_and_invalidate(physical),
                GranuleHardwareOutcome::Applied
            );
        }
        assert_eq!(tables[0].level1[0] & 0x3, 0);
        assert_eq!(tables[1].level1[0] & 0x3, 0);
    }

    #[test]
    fn complete_set_binding_rejects_empty_duplicate_and_partial_sets() {
        let physical = PhysAddr::new(0x20_0000).unwrap();
        let empty = unsafe {
            bind_routed_dma_set::<Tables, UnitRegisters, 0>(
                &mut [],
                VtdAuthorizedRoutes::for_test(test_owner(), [], []),
                [],
                physical,
            )
        };
        assert!(matches!(empty, Err(VtdSetBindingError::Empty)));

        let register_base = PhysAddr::new(0xfed9_0000).unwrap();
        let route = VtdRequesterRoute::for_test(requester(), register_base);
        let mut duplicate_tables = [Tables::identity(physical, 9), Tables::identity(physical, 9)];
        let duplicate = unsafe {
            bind_routed_dma_set(
                &mut duplicate_tables,
                VtdAuthorizedRoutes::for_test(test_owner(), [route, route], [9, 9]),
                [
                    verified_unit(register_base, UnitRegisters::active(ROOT)),
                    verified_unit(register_base, UnitRegisters::active(ROOT)),
                ],
                physical,
            )
        };
        assert!(matches!(duplicate, Err(VtdSetBindingError::DuplicateUnit)));

        let second_base = PhysAddr::new(0xfeda_0000).unwrap();
        let mut swapped_tables = [
            Tables::identity(physical, 9).for_unit(register_base),
            Tables::identity(physical, 9).for_unit(second_base),
        ];
        let swapped = unsafe {
            bind_routed_dma_set(
                &mut swapped_tables,
                VtdAuthorizedRoutes::for_test(
                    test_owner(),
                    [route, VtdRequesterRoute::for_test(requester(), second_base)],
                    [9, 9],
                ),
                [
                    verified_unit(second_base, UnitRegisters::active(ROOT)),
                    verified_unit(register_base, UnitRegisters::active(ROOT)),
                ],
                physical,
            )
        };
        assert!(matches!(
            swapped,
            Err(VtdSetBindingError::Unit {
                index: 0,
                error: VtdBindingError::UnitSubstitution
            })
        ));
        assert_eq!(swapped_tables[0].level1[0] & 0x3, 0x3);
        assert_eq!(swapped_tables[1].level1[0] & 0x3, 0x3);

        let mut reordered_tables = [
            Tables::identity(physical, 9).for_unit(second_base),
            Tables::identity(physical, 9).for_unit(register_base),
        ];
        let reordered = unsafe {
            bind_routed_dma_set(
                &mut reordered_tables,
                VtdAuthorizedRoutes::for_test(
                    test_owner(),
                    [route, VtdRequesterRoute::for_test(requester(), second_base)],
                    [9, 9],
                ),
                [
                    verified_unit(register_base, UnitRegisters::active(ROOT)),
                    verified_unit(second_base, UnitRegisters::active(ROOT)),
                ],
                physical,
            )
        };
        assert!(matches!(
            reordered,
            Err(VtdSetBindingError::Unit {
                index: 0,
                error: VtdBindingError::TableSubstitution
            })
        ));
        assert_eq!(reordered_tables[0].level1[0] & 0x3, 0x3);
        assert_eq!(reordered_tables[1].level1[0] & 0x3, 0x3);

        let mut partial_tables = [
            Tables::identity(physical, 9).for_unit(register_base),
            Tables::identity(physical, 9).for_unit(second_base),
        ];
        let partial = unsafe {
            bind_routed_dma_set(
                &mut partial_tables,
                VtdAuthorizedRoutes::for_test(
                    test_owner(),
                    [route, VtdRequesterRoute::for_test(requester(), second_base)],
                    [9, 10],
                ),
                [
                    verified_unit(register_base, UnitRegisters::active(ROOT)),
                    verified_unit(second_base, UnitRegisters::active(ROOT)),
                ],
                physical,
            )
        };
        assert!(matches!(
            partial,
            Err(VtdSetBindingError::Unit {
                index: 1,
                error: VtdBindingError::Table(VtdTableError::WrongDomain)
            })
        ));
        assert_eq!(partial_tables[0].level1[0] & 0x3, 0x3);
        assert_eq!(partial_tables[1].level1[0] & 0x3, 0x3);
    }
}
