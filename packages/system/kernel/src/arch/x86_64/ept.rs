use crate::{
    DomainId, GranuleHardware, GranuleHardwareOutcome, GranuleTransition, GranuleTransitionKind,
    PAGE_SIZE, PhysAddr,
};
use core::sync::atomic::{Ordering, compiler_fence};

use super::{EptPointer, VmxInstructions};

const EPT_ACCESS_MASK: u64 = 0b111;
const EPT_LARGE_PAGE: u64 = 1 << 7;
const EPT_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EptAdapterError {
    InvalidLeaf,
    WrongGranule,
    WrongDomain,
}

/// Access bits applied to one 4 KiB EPT leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EptAccess(u64);

impl EptAccess {
    pub const NONE: Self = Self(0);
    pub const READ_WRITE: Self = Self(0b011);

    pub const fn bits(self) -> u64 {
        self.0
    }
}

/// Device isolation used by the EPT transition adapter. The minimal policy
/// denies DMA for every protected granule; device assignment can later refine
/// this behind an equally ordered IOMMU implementation.
pub trait DmaIsolation {
    /// Monitor domain whose device-translation context this adapter controls.
    /// Host-only adapters return `None` and cannot authorize domain transitions.
    fn bound_domain(&self) -> Option<DomainId> {
        None
    }

    /// Revokes DMA access and completes every required IOMMU invalidation.
    /// `Rejected` is only valid when no permissive change may remain pending;
    /// uncertainty after a table write must return `FailStop`.
    fn deny_and_invalidate(&mut self, physical: PhysAddr) -> GranuleHardwareOutcome;
}

pub trait GranuleScrubber {
    fn scrub(&mut self, physical: PhysAddr, bytes: usize) -> bool;
}

/// Volatile zeroization of one pinned, direct-mapped granule.
pub struct VolatileGranuleScrubber<'a> {
    physical: PhysAddr,
    page: &'a mut [u8; PAGE_SIZE as usize],
}

impl<'a> VolatileGranuleScrubber<'a> {
    /// # Safety
    ///
    /// `page` must be the unique writable kernel mapping of `physical` for the
    /// lifetime of this object. DMA and other CPU access must already be
    /// revoked before `scrub` is called.
    pub const unsafe fn new(physical: PhysAddr, page: &'a mut [u8; PAGE_SIZE as usize]) -> Self {
        Self { physical, page }
    }
}

impl GranuleScrubber for VolatileGranuleScrubber<'_> {
    fn scrub(&mut self, physical: PhysAddr, bytes: usize) -> bool {
        if physical != self.physical || bytes != self.page.len() {
            return false;
        }
        for byte in self.page.iter_mut() {
            // SAFETY: construction requires a unique live mapping, and each
            // byte is visited exactly once through that exclusive reference.
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
        true
    }
}

/// Live host and optional domain EPT leaves for one physical granule.
pub struct EptGranuleBinding<'a> {
    physical: PhysAddr,
    host_ept: EptPointer,
    host_leaf: &'a mut u64,
    domain: Option<DomainId>,
    domain_ept: Option<EptPointer>,
    domain_leaf: Option<&'a mut u64>,
}

impl<'a> EptGranuleBinding<'a> {
    /// # Safety
    ///
    /// Each leaf must be the uniquely borrowed, live 4 KiB EPT leaf mapping
    /// `physical` in its stated context. The page-table memory must remain
    /// pinned and write-back cacheable for the lifetime of this binding.
    pub unsafe fn new(
        physical: PhysAddr,
        host_ept: EptPointer,
        host_leaf: &'a mut u64,
        domain: Option<(DomainId, EptPointer, &'a mut u64)>,
    ) -> Result<Self, EptAdapterError> {
        validate_leaf(*host_leaf, physical)?;
        let (domain_id, domain_ept, domain_leaf) = match domain {
            Some((id, ept, leaf)) => {
                validate_leaf(*leaf, physical)?;
                (Some(id), Some(ept), Some(leaf))
            }
            None => (None, None, None),
        };
        Ok(Self {
            physical,
            host_ept,
            host_leaf,
            domain: domain_id,
            domain_ept,
            domain_leaf,
        })
    }
}

/// Revoke-before-grant EPT adapter. DMA is denied and invalidated before any
/// CPU mapping changes. Once a leaf is written, an INVEPT failure is fail-stop
/// because a stale permissive translation can no longer be disproved.
pub struct EptGranuleHardware<'a, I, D, S> {
    binding: EptGranuleBinding<'a>,
    vmx: I,
    dma: D,
    scrubber: S,
}

impl<'a, I, D, S> EptGranuleHardware<'a, I, D, S> {
    pub const fn new(binding: EptGranuleBinding<'a>, vmx: I, dma: D, scrubber: S) -> Self {
        Self {
            binding,
            vmx,
            dma,
            scrubber,
        }
    }

    pub fn into_parts(self) -> (EptGranuleBinding<'a>, I, D, S) {
        (self.binding, self.vmx, self.dma, self.scrubber)
    }
}

unsafe impl<I: VmxInstructions, D: DmaIsolation, S: GranuleScrubber> GranuleHardware
    for EptGranuleHardware<'_, I, D, S>
{
    fn apply_transition(&mut self, transition: GranuleTransition) -> GranuleHardwareOutcome {
        if transition.physical() != self.binding.physical {
            return GranuleHardwareOutcome::Rejected;
        }
        let expected_domain = transition.to_owner().or(transition.from_owner());
        if expected_domain.is_some() && expected_domain != self.binding.domain {
            return GranuleHardwareOutcome::Rejected;
        }
        if expected_domain.is_some() && expected_domain != self.dma.bound_domain() {
            return GranuleHardwareOutcome::Rejected;
        }
        match self.dma.deny_and_invalidate(transition.physical()) {
            GranuleHardwareOutcome::Applied => {}
            outcome => return outcome,
        }

        let (host_access, domain_access, scrub) = match transition.kind() {
            GranuleTransitionKind::Delegate => (EptAccess::NONE, EptAccess::NONE, false),
            GranuleTransitionKind::AssignPrivate | GranuleTransitionKind::MakePrivate => {
                (EptAccess::NONE, EptAccess::READ_WRITE, false)
            }
            GranuleTransitionKind::Share => (EptAccess::READ_WRITE, EptAccess::READ_WRITE, false),
            GranuleTransitionKind::Reclaim => (EptAccess::NONE, EptAccess::NONE, false),
            GranuleTransitionKind::CompleteScrub => (EptAccess::READ_WRITE, EptAccess::NONE, true),
        };
        if scrub
            && !self
                .scrubber
                .scrub(transition.physical(), PAGE_SIZE as usize)
        {
            return GranuleHardwareOutcome::Rejected;
        }

        set_access(self.binding.host_leaf, host_access);
        if self
            .vmx
            .invept_single_context(self.binding.host_ept)
            .is_err()
        {
            return GranuleHardwareOutcome::FailStop;
        }
        if let (Some(ept), Some(leaf)) = (
            self.binding.domain_ept,
            self.binding.domain_leaf.as_deref_mut(),
        ) {
            set_access(leaf, domain_access);
            if self.vmx.invept_single_context(ept).is_err() {
                return GranuleHardwareOutcome::FailStop;
            }
        } else if domain_access != EptAccess::NONE {
            return GranuleHardwareOutcome::FailStop;
        }
        GranuleHardwareOutcome::Applied
    }
}

fn validate_leaf(entry: u64, physical: PhysAddr) -> Result<(), EptAdapterError> {
    if entry & EPT_LARGE_PAGE != 0 || entry & EPT_ADDRESS_MASK != physical.get() {
        return Err(EptAdapterError::InvalidLeaf);
    }
    Ok(())
}

fn set_access(entry: &mut u64, access: EptAccess) {
    *entry = (*entry & !EPT_ACCESS_MASK) | access.bits();
}

const BOOT_EPT_TABLE_LIMIT: usize = 80;
const EPT_WRITE_BACK: u64 = 6 << 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootImageEptError {
    Storage(super::PageTableBuildError),
    TableAlias,
    InvalidTable,
    Capacity,
    OccupiedLeaf,
}

impl From<super::PageTableBuildError> for BootImageEptError {
    fn from(error: super::PageTableBuildError) -> Self {
        Self::Storage(error)
    }
}

/// Build a private four-level EPT offline. This never installs a VMCS field
/// or modifies active EPT. A failure leaves the unpublished arena to its
/// caller for quarantine or teardown.
pub(crate) fn build_boot_image_ept(
    store: &mut impl super::PageTableStore,
    image: core::ops::Range<u64>,
    host_bits: u8,
    regions: impl Iterator<Item = crate::GuestRegion>,
) -> Result<PhysAddr, BootImageEptError> {
    let mut tables = [None; BOOT_EPT_TABLE_LIMIT];
    let end = 1u64 << host_bits;
    let root = allocate_boot_ept_table(store, &image, end, &mut tables)?;
    for region in regions {
        // Read permission is implicit for a validated PE region. No large
        // pages, execute-only leaves, or accessed/dirty tracking.
        let leaf_flags = EPT_WRITE_BACK
            | 1
            | (u64::from(region.is_writable()) << 1)
            | (u64::from(region.is_executable()) << 2);
        for page in 0..region.pages() {
            let offset = page * PAGE_SIZE;
            let guest = region.guest_start() + offset;
            let host = region.host_start().get() + offset;
            let mut table = root;
            for shift in [39, 30, 21] {
                let index = ((guest >> shift) & 0x1ff) as usize;
                let entry = store.read(table, index)?;
                let child = if entry == 0 {
                    let child = allocate_boot_ept_table(store, &image, end, &mut tables)?;
                    store.write(table, index, child.get() | EPT_ACCESS_MASK)?;
                    child
                } else {
                    let child = PhysAddr::new(entry & EPT_ADDRESS_MASK)
                        .map_err(|_| BootImageEptError::InvalidTable)?;
                    if entry != child.get() | EPT_ACCESS_MASK || !tables.contains(&Some(child)) {
                        return Err(BootImageEptError::InvalidTable);
                    }
                    child
                };
                table = child;
            }
            let index = ((guest >> 12) & 0x1ff) as usize;
            if store.read(table, index)? != 0 {
                return Err(BootImageEptError::OccupiedLeaf);
            }
            store.write(table, index, host | leaf_flags)?;
        }
    }
    Ok(root)
}

fn allocate_boot_ept_table(
    store: &mut impl super::PageTableStore,
    image: &core::ops::Range<u64>,
    end: u64,
    tables: &mut [Option<PhysAddr>; BOOT_EPT_TABLE_LIMIT],
) -> Result<PhysAddr, BootImageEptError> {
    let table = store.allocate_zeroed()?;
    if table.get() == 0 || table.get() >= end {
        return Err(BootImageEptError::InvalidTable);
    }
    if image.contains(&table.get()) || tables.contains(&Some(table)) {
        return Err(BootImageEptError::TableAlias);
    }
    for index in 0..512 {
        if store.read(table, index)? != 0 {
            return Err(BootImageEptError::InvalidTable);
        }
    }
    *tables
        .iter_mut()
        .find(|slot| slot.is_none())
        .ok_or(BootImageEptError::Capacity)? = Some(table);
    Ok(table)
}

#[cfg(test)]
mod tests {
    use super::super::VmxInstructionError;
    use super::*;
    use crate::ProtectedMonitor;

    struct BootTables {
        base: u64,
        pages: [[u64; 512]; 6],
        count: usize,
        limit: usize,
        repeat: bool,
    }

    impl BootTables {
        fn new(base: u64) -> Self {
            Self {
                base,
                pages: [[0; 512]; 6],
                count: 0,
                limit: 6,
                repeat: false,
            }
        }
        fn slot(&self, address: PhysAddr) -> usize {
            ((address.get() - self.base) / PAGE_SIZE) as usize
        }
        fn leaf(&self, mut table: PhysAddr, gpa: u64) -> u64 {
            for shift in [39, 30, 21] {
                let entry = self.pages[self.slot(table)][((gpa >> shift) & 511) as usize];
                if entry == 0 {
                    return 0;
                }
                assert_eq!(entry & !EPT_ADDRESS_MASK, 7);
                table = PhysAddr::new(entry & EPT_ADDRESS_MASK).unwrap();
            }
            self.pages[self.slot(table)][((gpa >> 12) & 511) as usize]
        }
    }

    impl super::super::PageTableStore for BootTables {
        fn allocate_zeroed(&mut self) -> Result<PhysAddr, super::super::PageTableBuildError> {
            if self.count == self.limit {
                return Err(super::super::PageTableBuildError::Storage);
            }
            let offset = if self.repeat {
                0
            } else {
                self.count as u64 * PAGE_SIZE
            };
            self.count += 1;
            Ok(PhysAddr::new(self.base + offset).unwrap())
        }

        fn read(
            &self,
            table: PhysAddr,
            index: usize,
        ) -> Result<u64, super::super::PageTableBuildError> {
            Ok(self.pages[self.slot(table)][index])
        }

        fn write(
            &mut self,
            table: PhysAddr,
            index: usize,
            value: u64,
        ) -> Result<(), super::super::PageTableBuildError> {
            let slot = self.slot(table);
            self.pages[slot][index] = value;
            Ok(())
        }
    }

    #[test]
    fn private_boot_ept_preserves_permissions_and_rejects_bad_table_storage() {
        let image = 0x100000..0x104000;
        let gpa = 0x1ff000;
        let region = |offset, w, x| {
            crate::GuestRegion::new(
                gpa + offset,
                PhysAddr::new(image.start + offset).unwrap(),
                1,
                w,
                x,
            )
            .unwrap()
        };
        let mappings = [
            region(0, false, false),
            region(0x2000, false, true),
            region(0x3000, true, false),
        ];
        let build = |tables: &mut BootTables| {
            build_boot_image_ept(tables, image.clone(), 48, mappings.into_iter())
        };
        let mut tables = BootTables::new(0x400000);
        let root = build(&mut tables).unwrap();
        assert_eq!(tables.count, 5);
        for (offset, leaf) in [
            (0, 0x100000 | EPT_WRITE_BACK | 1),
            (0x1000, 0),
            (0x2000, 0x102000 | EPT_WRITE_BACK | 5),
            (0x3000, 0x103000 | EPT_WRITE_BACK | 3),
            (0x4000, 0),
        ] {
            assert_eq!(tables.leaf(root, gpa + offset), leaf);
        }
        assert_eq!(
            build(&mut BootTables::new(0x101000)),
            Err(BootImageEptError::TableAlias)
        );
        assert_eq!(
            build(&mut BootTables::new(1 << 48)),
            Err(BootImageEptError::InvalidTable)
        );
        let mut repeated = BootTables::new(0x400000);
        repeated.repeat = true;
        assert_eq!(build(&mut repeated), Err(BootImageEptError::TableAlias));
        let mut dirty = BootTables::new(0x400000);
        dirty.pages[0][511] = 1;
        assert_eq!(build(&mut dirty), Err(BootImageEptError::InvalidTable));
        let mut short = BootTables::new(0x400000);
        short.limit = 4;
        assert_eq!(
            build(&mut short),
            Err(BootImageEptError::Storage(
                super::super::PageTableBuildError::Storage
            ))
        );
    }

    #[derive(Default)]
    struct TestVmx {
        invalidations: u8,
        fail_at: u8,
    }

    impl VmxInstructions for TestVmx {
        fn vmxon(&mut self, _: PhysAddr) -> Result<(), VmxInstructionError> {
            Ok(())
        }
        fn vmxoff(&mut self) -> Result<(), VmxInstructionError> {
            Ok(())
        }
        fn vmclear(&mut self, _: PhysAddr) -> Result<(), VmxInstructionError> {
            Ok(())
        }
        fn vmptrld(&mut self, _: PhysAddr) -> Result<(), VmxInstructionError> {
            Ok(())
        }
        fn vmlaunch(
            &mut self,
            _: &mut crate::arch::x86_64::VmxGuestRegisters,
        ) -> Result<crate::arch::x86_64::VmxLaunchOutcome, VmxInstructionError> {
            Ok(crate::arch::x86_64::VmxLaunchOutcome::GuestRunning)
        }
        fn vmresume(
            &mut self,
            _: &mut crate::arch::x86_64::VmxGuestRegisters,
        ) -> Result<crate::arch::x86_64::VmxLaunchOutcome, VmxInstructionError> {
            Ok(crate::arch::x86_64::VmxLaunchOutcome::GuestRunning)
        }
        fn vmwrite(
            &mut self,
            _: crate::arch::x86_64::VmcsField,
            _: u64,
        ) -> Result<(), VmxInstructionError> {
            Ok(())
        }
        fn vmread(
            &mut self,
            _: crate::arch::x86_64::VmcsField,
        ) -> Result<u64, VmxInstructionError> {
            Ok(0)
        }
        fn invept_single_context(&mut self, _: EptPointer) -> Result<(), VmxInstructionError> {
            self.invalidations += 1;
            if self.invalidations == self.fail_at {
                Err(VmxInstructionError::Failed)
            } else {
                Ok(())
            }
        }
    }

    #[derive(Default)]
    struct TestDma {
        domain: Option<DomainId>,
        denied: bool,
        invalidated: bool,
        calls: u8,
        outcome: Option<GranuleHardwareOutcome>,
    }
    impl DmaIsolation for TestDma {
        fn bound_domain(&self) -> Option<DomainId> {
            self.domain
        }

        fn deny_and_invalidate(&mut self, _: PhysAddr) -> GranuleHardwareOutcome {
            self.calls += 1;
            self.denied = true;
            self.invalidated = true;
            self.outcome.unwrap_or(GranuleHardwareOutcome::Applied)
        }
    }
    struct TestScrubber(bool);
    impl GranuleScrubber for TestScrubber {
        fn scrub(&mut self, _: PhysAddr, bytes: usize) -> bool {
            bytes == 4096 && self.0
        }
    }

    #[test]
    fn private_assignment_revokes_host_before_granting_domain() {
        let physical = PhysAddr::new(0x20_0000).unwrap();
        let host_ept = EptPointer::new(PhysAddr::new(0x30_0000).unwrap(), false).unwrap();
        let domain_ept = EptPointer::new(PhysAddr::new(0x31_0000).unwrap(), false).unwrap();
        let mut monitor = ProtectedMonitor::<1, 1>::new();
        let domain = monitor.create_domain().unwrap();
        let granule = monitor.register_granule(physical).unwrap();
        let mut host_leaf = physical.get() | EptAccess::READ_WRITE.bits();
        let mut domain_leaf = physical.get();
        let binding = unsafe {
            EptGranuleBinding::new(
                physical,
                host_ept,
                &mut host_leaf,
                Some((domain, domain_ept, &mut domain_leaf)),
            )
            .unwrap()
        };
        let mut hardware = EptGranuleHardware::new(
            binding,
            TestVmx::default(),
            TestDma {
                domain: Some(domain),
                ..TestDma::default()
            },
            TestScrubber(true),
        );
        let delegate = monitor.prepare_delegate(granule).unwrap();
        monitor.execute_transition(delegate, &mut hardware).unwrap();
        let assign = monitor.prepare_assign_private(granule, domain).unwrap();
        monitor.execute_transition(assign, &mut hardware).unwrap();
        let (binding, vmx, dma, _) = hardware.into_parts();
        assert_eq!(*binding.host_leaf & EPT_ACCESS_MASK, 0);
        assert_eq!(
            *binding.domain_leaf.unwrap() & EPT_ACCESS_MASK,
            EptAccess::READ_WRITE.bits()
        );
        assert_eq!(vmx.invalidations, 4);
        assert!(dma.denied && dma.invalidated);
    }

    #[test]
    fn invalidation_failure_after_leaf_write_is_fail_stop() {
        let physical = PhysAddr::new(0x40_0000).unwrap();
        let host_ept = EptPointer::new(PhysAddr::new(0x50_0000).unwrap(), false).unwrap();
        let domain_ept = EptPointer::new(PhysAddr::new(0x51_0000).unwrap(), false).unwrap();
        let mut monitor = ProtectedMonitor::<1, 1>::new();
        let domain = monitor.create_domain().unwrap();
        let granule = monitor.register_granule(physical).unwrap();
        let mut host_leaf = physical.get() | EptAccess::READ_WRITE.bits();
        let mut domain_leaf = physical.get();
        let binding = unsafe {
            EptGranuleBinding::new(
                physical,
                host_ept,
                &mut host_leaf,
                Some((domain, domain_ept, &mut domain_leaf)),
            )
            .unwrap()
        };
        let mut hardware = EptGranuleHardware::new(
            binding,
            TestVmx {
                invalidations: 0,
                fail_at: 4,
            },
            TestDma {
                domain: Some(domain),
                ..TestDma::default()
            },
            TestScrubber(true),
        );
        let delegate = monitor.prepare_delegate(granule).unwrap();
        monitor.execute_transition(delegate, &mut hardware).unwrap();
        let assign = monitor.prepare_assign_private(granule, domain).unwrap();
        assert_eq!(
            monitor.execute_transition(assign, &mut hardware),
            Err(crate::MonitorError::HardwareStateUncertain)
        );
        assert_eq!(
            monitor.granule_state(granule),
            Ok(crate::GranuleState::HardwareUncertain)
        );
    }

    #[test]
    fn mismatched_dma_domain_is_rejected_before_dma_mutation() {
        let physical = PhysAddr::new(0x58_0000).unwrap();
        let host_ept = EptPointer::new(PhysAddr::new(0x59_0000).unwrap(), false).unwrap();
        let domain_ept = EptPointer::new(PhysAddr::new(0x5a_0000).unwrap(), false).unwrap();
        let mut monitor = ProtectedMonitor::<2, 1>::new();
        let domain = monitor.create_domain().unwrap();
        let other = monitor.create_domain().unwrap();
        let granule = monitor.register_granule(physical).unwrap();
        let mut host_leaf = physical.get() | EptAccess::READ_WRITE.bits();
        let mut domain_leaf = physical.get();
        let binding = unsafe {
            EptGranuleBinding::new(
                physical,
                host_ept,
                &mut host_leaf,
                Some((domain, domain_ept, &mut domain_leaf)),
            )
            .unwrap()
        };
        let mut hardware = EptGranuleHardware::new(
            binding,
            TestVmx::default(),
            TestDma {
                domain: Some(other),
                ..TestDma::default()
            },
            TestScrubber(true),
        );
        let delegate = monitor.prepare_delegate(granule).unwrap();
        monitor.execute_transition(delegate, &mut hardware).unwrap();
        let assign = monitor.prepare_assign_private(granule, domain).unwrap();
        assert_eq!(
            monitor.execute_transition(assign, &mut hardware),
            Err(crate::MonitorError::HardwareTransitionFailed)
        );
        let (_, _, dma, _) = hardware.into_parts();
        assert_eq!(dma.calls, 1);
    }

    #[test]
    fn volatile_scrubber_clears_the_complete_bound_page() {
        let physical = PhysAddr::new(0x60_0000).unwrap();
        let mut page = [0xa5; PAGE_SIZE as usize];
        let mut scrubber = unsafe { VolatileGranuleScrubber::new(physical, &mut page) };
        assert!(!scrubber.scrub(PhysAddr::new(0x61_0000).unwrap(), PAGE_SIZE as usize));
        assert!(scrubber.scrub(physical, PAGE_SIZE as usize));
        assert!(page.iter().all(|byte| *byte == 0));
    }
}
