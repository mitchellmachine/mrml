use crate::{DeviceAddress, PhysAddr};

use super::{
    PlatformMmioPurpose, VerifiedPlatformMmio, VtdDmaIsolation, VtdDmaSet, VtdError,
    VtdInvalidator, VtdRegisterIo, VtdRequesterRoute,
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
    InsufficientRegisterMapping,
    Unit(VtdError),
    Table(VtdTableError),
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

/// Exclusive access to live legacy VT-d translation tables.
///
/// # Safety
///
/// An implementation must read and mutate the exact physical table entries
/// named by each argument, keep every table pinned, serialize against all
/// concurrent table writers, and return a unique leaf reference.
pub unsafe trait VtdTableMemory {
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
    _private: (),
}

impl DirectVtdTables {
    /// # Safety
    ///
    /// All reachable VT-d table frames must be identity mapped, pinned,
    /// supervisor writable, and exclusively owned while this object exists.
    pub const unsafe fn assume_exclusive_identity_mapping() -> Self {
        Self { _private: () }
    }
}

unsafe impl VtdTableMemory for DirectVtdTables {
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
/// `invalidator` must have been constructed from the exact verified MMIO token
/// supplied here, and `memory` must meet its unsafe table-access contract. The
/// caller must retain exclusive ownership until the resulting adapter is
/// destroyed.
pub unsafe fn bind_routed_dma_isolation<'a, M, R>(
    memory: &'a mut M,
    route: VtdRequesterRoute,
    verified_unit: VerifiedPlatformMmio,
    mut invalidator: VtdInvalidator<R>,
    physical: PhysAddr,
    expected_domain: u16,
) -> Result<VtdDmaIsolation<'a, R>, VtdBindingError>
where
    M: VtdTableMemory,
    R: VtdRegisterIo,
{
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
/// The arrays must contain every distinct remapping unit through which DMA can
/// reach `physical`, as established from checked firmware and live PCI
/// topology. Each invalidator must originate from its corresponding verified
/// MMIO token, and each table-memory element must exclusively control that
/// unit's pinned translation tables. No transition may use the returned set if
/// topology changes without rebuilding it.
pub unsafe fn bind_routed_dma_set<'a, M, R, const UNITS: usize>(
    memories: &'a mut [M; UNITS],
    routes: [VtdRequesterRoute; UNITS],
    verified_units: [VerifiedPlatformMmio; UNITS],
    invalidators: [VtdInvalidator<R>; UNITS],
    physical: PhysAddr,
    expected_domains: [u16; UNITS],
) -> Result<VtdDmaSet<'a, R, UNITS>, VtdSetBindingError>
where
    M: VtdTableMemory,
    R: VtdRegisterIo,
{
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
    for (index, ((((memory, route), verified), invalidator), domain)) in memories
        .iter_mut()
        .zip(routes)
        .zip(verified_units)
        .zip(invalidators)
        .zip(expected_domains)
        .enumerate()
    {
        // SAFETY: inherited from this function's per-index correspondence and
        // complete-topology contract.
        let isolation = unsafe {
            bind_routed_dma_isolation(memory, route, verified, invalidator, physical, domain)
        }
        .map_err(|error| VtdSetBindingError::Unit { index, error })?;
        // SAFETY: distinct DRHD bases were checked above and every isolation
        // maps the same physical granule by construction.
        unsafe { set.push(isolation) }
            .map_err(VtdBindingError::Unit)
            .map_err(|error| VtdSetBindingError::Unit { index, error })?;
    }
    Ok(set)
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
    use super::super::platform_mmio::verified_vtd_for_test;
    use super::*;
    use crate::GranuleHardwareOutcome;

    const ROOT: u64 = 0x10_0000;
    const CONTEXT: u64 = 0x11_0000;
    const LEVEL4: u64 = 0x12_0000;
    const LEVEL3: u64 = 0x13_0000;
    const LEVEL2: u64 = 0x14_0000;
    const LEVEL1: u64 = 0x15_0000;

    struct Tables {
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
        let verified = verified_vtd_for_test(register_base, 1, requester().segment());
        let invalidator = VtdInvalidator::new(UnitRegisters::active(ROOT), 4).unwrap();
        let mut tables = Tables::identity(physical, 9);

        {
            let mut isolation = unsafe {
                bind_routed_dma_isolation(&mut tables, route, verified, invalidator, physical, 9)
            }
            .unwrap();
            assert_eq!(
                isolation.deny_and_invalidate(physical),
                GranuleHardwareOutcome::Applied
            );
        }
        assert_eq!(tables.level1[0] & 0x3, 0);
    }

    #[test]
    fn coherent_unit_binding_rejects_substitution_and_inactive_root() {
        let physical = PhysAddr::new(0x20_0000).unwrap();
        let register_base = PhysAddr::new(0xfed9_0000).unwrap();
        let route = VtdRequesterRoute::for_test(requester(), register_base);
        let substituted = verified_vtd_for_test(
            PhysAddr::new(0xfeda_0000).unwrap(),
            1,
            requester().segment(),
        );
        let mut tables = Tables::identity(physical, 9);
        assert!(matches!(
            unsafe {
                bind_routed_dma_isolation(
                    &mut tables,
                    route,
                    substituted,
                    VtdInvalidator::new(UnitRegisters::active(ROOT), 4).unwrap(),
                    physical,
                    9,
                )
            },
            Err(VtdBindingError::UnitSubstitution)
        ));

        let verified = verified_vtd_for_test(register_base, 1, requester().segment());
        let mut inactive = UnitRegisters::active(ROOT);
        inactive.status &= !(1 << 30);
        assert!(matches!(
            unsafe {
                bind_routed_dma_isolation(
                    &mut tables,
                    route,
                    verified,
                    VtdInvalidator::new(inactive, 4).unwrap(),
                    physical,
                    9,
                )
            },
            Err(VtdBindingError::Unit(VtdError::RootPointerInactive))
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
        let verified = [
            verified_vtd_for_test(first_base, 1, requester().segment()),
            verified_vtd_for_test(second_base, 1, requester().segment()),
        ];
        let invalidators = [
            VtdInvalidator::new(UnitRegisters::active(ROOT), 4).unwrap(),
            VtdInvalidator::new(UnitRegisters::active(ROOT), 4).unwrap(),
        ];
        let mut tables = [Tables::identity(physical, 9), Tables::identity(physical, 9)];

        {
            let mut set = unsafe {
                bind_routed_dma_set(
                    &mut tables,
                    routes,
                    verified,
                    invalidators,
                    physical,
                    [9, 9],
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
            bind_routed_dma_set::<Tables, UnitRegisters, 0>(&mut [], [], [], [], physical, [])
        };
        assert!(matches!(empty, Err(VtdSetBindingError::Empty)));

        let register_base = PhysAddr::new(0xfed9_0000).unwrap();
        let route = VtdRequesterRoute::for_test(requester(), register_base);
        let verified = verified_vtd_for_test(register_base, 1, requester().segment());
        let mut duplicate_tables = [Tables::identity(physical, 9), Tables::identity(physical, 9)];
        let duplicate = unsafe {
            bind_routed_dma_set(
                &mut duplicate_tables,
                [route, route],
                [verified, verified],
                [
                    VtdInvalidator::new(UnitRegisters::active(ROOT), 4).unwrap(),
                    VtdInvalidator::new(UnitRegisters::active(ROOT), 4).unwrap(),
                ],
                physical,
                [9, 9],
            )
        };
        assert!(matches!(duplicate, Err(VtdSetBindingError::DuplicateUnit)));

        let second_base = PhysAddr::new(0xfeda_0000).unwrap();
        let mut partial_tables = [Tables::identity(physical, 9), Tables::identity(physical, 9)];
        let partial = unsafe {
            bind_routed_dma_set(
                &mut partial_tables,
                [route, VtdRequesterRoute::for_test(requester(), second_base)],
                [
                    verified,
                    verified_vtd_for_test(second_base, 1, requester().segment()),
                ],
                [
                    VtdInvalidator::new(UnitRegisters::active(ROOT), 4).unwrap(),
                    VtdInvalidator::new(UnitRegisters::active(ROOT), 4).unwrap(),
                ],
                physical,
                [9, 10],
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
