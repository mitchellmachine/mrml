use crate::{
    DeviceAddress, DomainId, GranuleHardwareOutcome, MonitorError, PhysAddr, ProtectedMonitor,
};

use super::{
    CompleteVtdRoutes, DmaIsolation, NativeVtdMmio, PlatformMmioPurpose, VerifiedPlatformMmio,
    VtdDmaIsolation, VtdDmaSet, VtdError, VtdInvalidator, VtdRegisterIo, VtdRequesterRoute,
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
}

/// A one-shot verified MMIO token coupled to the sole invalidator that may use
/// its remapping-unit register mapping.
pub struct VerifiedVtdUnit<R> {
    verified: VerifiedPlatformMmio,
    invalidator: VtdInvalidator<R>,
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
        let bytes = usize::try_from(verified.requirement().bytes())
            .map_err(|_| VtdBindingError::Unit(VtdError::InvalidRegisterLayout))?;
        // SAFETY: inherited from this function's unique, uncached verified
        // mapping contract. The checked byte count is the verified extent.
        let registers = unsafe { NativeVtdMmio::new(verified.as_mut_ptr(), bytes) }
            .map_err(VtdBindingError::Unit)?;
        let invalidator =
            VtdInvalidator::new(registers, poll_limit).map_err(VtdBindingError::Unit)?;
        if verified.requirement().pages() < invalidator.register_pages() {
            return Err(VtdBindingError::InsufficientRegisterMapping);
        }
        Ok(Self {
            verified,
            invalidator,
        })
    }
}

impl<R: VtdRegisterIo> VerifiedVtdUnit<R> {
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
    fn read128(&self, table: PhysAddr, index: usize) -> Result<[u64; 2], VtdTableError>;
    fn read64(&self, table: PhysAddr, index: usize) -> Result<u64, VtdTableError>;
    /// # Safety
    ///
    /// Return the unique live entry designated by `table` and `index`, with
    /// all competing table access serialized.
    unsafe fn leaf_mut(&mut self, table: PhysAddr, index: usize)
    -> Result<&mut u64, VtdTableError>;
}

/// Identity-mapped physical table access for the bare-metal monitor.
pub struct DirectVtdTables {
    provenance: VtdTableProvenance,
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
        }
    }
}

unsafe impl VtdTableMemory for DirectVtdTables {
    fn provenance(&self) -> VtdTableProvenance {
        self.provenance
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
    let shifts = [39u32, 30, 21];
    for shift in shifts {
        let index = ((physical.get() >> shift) & 0x1ff) as usize;
        let entry = memory.read64(table, index)?;
        if entry & (1 << 7) != 0 {
            return Err(VtdTableError::LargePage);
        }
        if entry & 0x3 == 0 || entry & !(ADDRESS_MASK | ENTRY_FLAGS) != 0 {
            return Err(VtdTableError::InvalidIntermediate);
        }
        table =
            checked_table(entry & ADDRESS_MASK).map_err(|_| VtdTableError::InvalidIntermediate)?;
    }
    let index = ((physical.get() >> 12) & 0x1ff) as usize;
    let leaf = memory.read64(table, index)?;
    if leaf & 0x3 == 0 {
        return Err(VtdTableError::MissingLeaf);
    }
    if leaf & (1 << 7) != 0 {
        return Err(VtdTableError::LargePage);
    }
    if leaf & !(ADDRESS_MASK | ENTRY_FLAGS) != 0 {
        return Err(VtdTableError::InvalidIntermediate);
    }
    if leaf & ADDRESS_MASK != physical.get() {
        return Err(VtdTableError::AliasedLeaf);
    }
    // SAFETY: the unsafe trait contract requires the returned reference to be
    // unique and tied to `memory`'s exclusive borrow.
    let entry = unsafe { memory.leaf_mut(table, index)? };
    Ok(VtdIdentityLeaf {
        physical,
        domain_id,
        entry,
    })
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
    if requirement.physical() != route.register_base()
        || !matches!(
            requirement.purpose(),
            PlatformMmioPurpose::VtdBootstrap { segment }
                if segment == route.requester().segment()
        )
    {
        return Err(VtdBindingError::UnitSubstitution);
    }
    if requirement.pages() < invalidator.register_pages() {
        return Err(VtdBindingError::InsufficientRegisterMapping);
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

fn checked_table(address: u64) -> Result<PhysAddr, VtdTableError> {
    if address == 0 || address & !ADDRESS_MASK != 0 {
        return Err(VtdTableError::Storage);
    }
    PhysAddr::new(address).map_err(|_| VtdTableError::Storage)
}

#[cfg(test)]
mod tests {
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

    struct Tables {
        provenance: VtdTableProvenance,
        root: [u64; 512],
        context: [u64; 512],
        level4: [u64; 512],
        level3: [u64; 512],
        level2: [u64; 512],
        level1: [u64; 512],
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
            if table.get() != LEVEL1 {
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
    }

    impl UnitRegisters {
        fn active(root: u64) -> Self {
            Self {
                root,
                status: (1 << 31) | (1 << 30),
                context: 0,
                iotlb: 0,
            }
        }
    }

    impl VtdRegisterIo for UnitRegisters {
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
                0x08 => 0x40 << 24,
                0x10 => 0x20 << 8,
                0x20 => self.root,
                0x28 => self.context,
                0x208 => self.iotlb,
                _ => 0,
            }
        }

        fn write64(&mut self, offset: usize, value: u64) {
            match offset {
                0x28 => self.context = (value & !(1 << 63)) | (1 << 59),
                0x208 => self.iotlb = (value & !(1 << 63)) | (1 << 57),
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
