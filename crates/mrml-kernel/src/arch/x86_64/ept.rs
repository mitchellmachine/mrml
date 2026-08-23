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

#[cfg(test)]
mod tests {
    use super::super::VmxInstructionError;
    use super::*;
    use crate::ProtectedMonitor;

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
        fn vmlaunch(&mut self) -> Result<(), VmxInstructionError> {
            Ok(())
        }
        fn vmresume(&mut self) -> Result<(), VmxInstructionError> {
            Ok(())
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
