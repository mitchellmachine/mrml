use core::array;

use crate::{
    IsolationAdmissionTable, IsolationMode, IsolationPlacement, ObjectId, TotalMicrovmClass,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TotalMicrovmInventoryEntry {
    domain: ObjectId,
    class: TotalMicrovmClass,
    must_be_running: bool,
}

impl TotalMicrovmInventoryEntry {
    pub const fn new(
        domain: ObjectId,
        class: TotalMicrovmClass,
        must_be_running: bool,
    ) -> Result<Self, TotalMicrovmRuntimeError> {
        if domain.0 == 0 {
            return Err(TotalMicrovmRuntimeError::InvalidInventory);
        }
        Ok(Self {
            domain,
            class,
            must_be_running,
        })
    }

    pub const fn domain(self) -> ObjectId {
        self.domain
    }

    pub const fn class(self) -> TotalMicrovmClass {
        self.class
    }

    pub const fn must_be_running(self) -> bool {
        self.must_be_running
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TotalMicrovmRuntimeError {
    InvalidInventory,
    InventoryFull,
    DuplicateDomain,
    TotalNotRequested,
    UnclassifiedActiveDomain,
    ClassificationMismatch,
    RequiredDomainMissing,
    RequiredDomainUnavailable,
    EligibleDomainOutsideMicrovm,
    UnsupportedBlockerRunning,
    NativeFallback,
}

pub struct TotalMicrovmInventory<const N: usize> {
    system_generation: u64,
    policy_generation: u64,
    entries: [Option<TotalMicrovmInventoryEntry>; N],
    count: usize,
}

impl<const N: usize> TotalMicrovmInventory<N> {
    pub fn new(
        system_generation: u64,
        policy_generation: u64,
    ) -> Result<Self, TotalMicrovmRuntimeError> {
        if N == 0 || system_generation == 0 || policy_generation == 0 {
            return Err(TotalMicrovmRuntimeError::InvalidInventory);
        }
        Ok(Self {
            system_generation,
            policy_generation,
            entries: array::from_fn(|_| None),
            count: 0,
        })
    }

    pub fn insert(
        &mut self,
        entry: TotalMicrovmInventoryEntry,
    ) -> Result<(), TotalMicrovmRuntimeError> {
        if self.entries[..self.count]
            .iter()
            .flatten()
            .any(|present| present.domain == entry.domain)
        {
            return Err(TotalMicrovmRuntimeError::DuplicateDomain);
        }
        if self.count == N {
            return Err(TotalMicrovmRuntimeError::InventoryFull);
        }
        self.entries[self.count] = Some(entry);
        self.count += 1;
        Ok(())
    }

    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn entries(&self) -> impl Iterator<Item = TotalMicrovmInventoryEntry> + '_ {
        self.entries[..self.count].iter().flatten().copied()
    }

    fn find(&self, domain: ObjectId) -> Option<TotalMicrovmInventoryEntry> {
        self.entries().find(|entry| entry.domain == domain)
    }

    /// Finalizes strict Total mode only from the authoritative admission table
    /// and an exact generation-bound inventory. Names and manifests cannot
    /// satisfy this gate, and failure never creates a native launch path.
    pub fn finalize<const DOMAINS: usize>(
        &self,
        admission: &IsolationAdmissionTable<DOMAINS>,
    ) -> Result<TotalMicrovmRuntimeProof, TotalMicrovmRuntimeError> {
        if admission.mode() != IsolationMode::TotalMicrovm {
            return Err(TotalMicrovmRuntimeError::TotalNotRequested);
        }
        if admission.system_generation() != self.system_generation
            || admission.policy_generation() != self.policy_generation
        {
            return Err(TotalMicrovmRuntimeError::InvalidInventory);
        }

        for running in admission.running() {
            let entry = self
                .find(running.domain())
                .ok_or(TotalMicrovmRuntimeError::UnclassifiedActiveDomain)?;
            if entry.class != running.class() {
                return Err(TotalMicrovmRuntimeError::ClassificationMismatch);
            }
            match running.class() {
                TotalMicrovmClass::MicrovmEligible
                    if running.placement() != IsolationPlacement::Microvm =>
                {
                    return Err(TotalMicrovmRuntimeError::EligibleDomainOutsideMicrovm);
                }
                TotalMicrovmClass::UnsupportedBlocker => {
                    return Err(TotalMicrovmRuntimeError::UnsupportedBlockerRunning);
                }
                _ => {}
            }
        }

        for unavailable in admission.unavailable_domains() {
            let entry = self
                .find(unavailable.domain())
                .ok_or(TotalMicrovmRuntimeError::UnclassifiedActiveDomain)?;
            if entry.class != unavailable.class() {
                return Err(TotalMicrovmRuntimeError::ClassificationMismatch);
            }
            if entry.must_be_running {
                return Err(TotalMicrovmRuntimeError::RequiredDomainUnavailable);
            }
        }

        for entry in self.entries().filter(|entry| entry.must_be_running) {
            if !admission
                .running()
                .any(|running| running.domain() == entry.domain && running.class() == entry.class)
            {
                return Err(TotalMicrovmRuntimeError::RequiredDomainMissing);
            }
        }

        let report = admission.total_microvm_report();
        if report.native_fallback != 0 {
            return Err(TotalMicrovmRuntimeError::NativeFallback);
        }
        if !report.satisfied() {
            return Err(TotalMicrovmRuntimeError::EligibleDomainOutsideMicrovm);
        }
        Ok(TotalMicrovmRuntimeProof {
            system_generation: self.system_generation,
            policy_generation: self.policy_generation,
            classified_domains: self.count,
            running_microvm_eligible: report.running_microvm_eligible,
            running_in_microvm: report.running_in_microvm,
            running_host_substrate: report.running_host_substrate,
            running_boot_only: report.running_boot_only,
            running_recovery_only: report.running_recovery_only,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TotalMicrovmRuntimeProof {
    system_generation: u64,
    policy_generation: u64,
    classified_domains: usize,
    running_microvm_eligible: usize,
    running_in_microvm: usize,
    running_host_substrate: usize,
    running_boot_only: usize,
    running_recovery_only: usize,
}

impl TotalMicrovmRuntimeProof {
    pub const fn system_generation(self) -> u64 {
        self.system_generation
    }

    pub const fn policy_generation(self) -> u64 {
        self.policy_generation
    }

    pub const fn classified_domains(self) -> usize {
        self.classified_domains
    }

    pub const fn running_microvm_eligible(self) -> usize {
        self.running_microvm_eligible
    }

    pub const fn running_in_microvm(self) -> usize {
        self.running_in_microvm
    }

    pub const fn running_host_substrate(self) -> usize {
        self.running_host_substrate
    }

    pub const fn running_boot_only(self) -> usize {
        self.running_boot_only
    }

    pub const fn running_recovery_only(self) -> usize {
        self.running_recovery_only
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        HostSubstrateReason, IsolationLaunchEvidence, IsolationLaunchRequest,
        IsolationUnavailableReason,
    };

    const SYSTEM: u64 = 7;
    const POLICY: u64 = 11;

    fn entry(domain: u64, class: TotalMicrovmClass, required: bool) -> TotalMicrovmInventoryEntry {
        TotalMicrovmInventoryEntry::new(ObjectId(domain), class, required).unwrap()
    }

    fn request(
        domain: u64,
        class: TotalMicrovmClass,
        placement: IsolationPlacement,
    ) -> IsolationLaunchRequest {
        IsolationLaunchRequest::new(ObjectId(domain), SYSTEM, POLICY, class, placement).unwrap()
    }

    fn commit<const N: usize>(
        admission: &mut IsolationAdmissionTable<N>,
        request: IsolationLaunchRequest,
        evidence: IsolationLaunchEvidence,
    ) {
        let prepared = admission.prepare(request).unwrap();
        admission.commit(&prepared, evidence).unwrap();
    }

    #[test]
    fn exact_inventory_finalizes_strict_total_runtime() {
        let mut admission =
            IsolationAdmissionTable::<3>::new(IsolationMode::TotalMicrovm, SYSTEM, POLICY).unwrap();
        commit(
            &mut admission,
            request(
                1,
                TotalMicrovmClass::MicrovmEligible,
                IsolationPlacement::Microvm,
            ),
            IsolationLaunchEvidence::MicrovmReady,
        );
        commit(
            &mut admission,
            request(
                2,
                TotalMicrovmClass::HostSubstrateRequired(HostSubstrateReason::InstantiateMicrovms),
                IsolationPlacement::NativeService,
            ),
            IsolationLaunchEvidence::NativeReady,
        );
        let mut inventory = TotalMicrovmInventory::<3>::new(SYSTEM, POLICY).unwrap();
        inventory
            .insert(entry(1, TotalMicrovmClass::MicrovmEligible, true))
            .unwrap();
        inventory
            .insert(entry(
                2,
                TotalMicrovmClass::HostSubstrateRequired(HostSubstrateReason::InstantiateMicrovms),
                true,
            ))
            .unwrap();
        inventory
            .insert(entry(3, TotalMicrovmClass::RecoveryOnly, false))
            .unwrap();
        let proof = inventory.finalize(&admission).unwrap();
        assert_eq!(proof.classified_domains(), 3);
        assert_eq!(proof.running_microvm_eligible(), 1);
        assert_eq!(proof.running_in_microvm(), 1);
        assert_eq!(proof.running_host_substrate(), 1);
    }

    #[test]
    fn required_missing_and_unavailable_domains_fail_closed() {
        let admission =
            IsolationAdmissionTable::<2>::new(IsolationMode::TotalMicrovm, SYSTEM, POLICY).unwrap();
        let mut inventory = TotalMicrovmInventory::<1>::new(SYSTEM, POLICY).unwrap();
        inventory
            .insert(entry(1, TotalMicrovmClass::MicrovmEligible, true))
            .unwrap();
        assert_eq!(
            inventory.finalize(&admission),
            Err(TotalMicrovmRuntimeError::RequiredDomainMissing)
        );

        let mut admission = admission;
        let prepared = admission
            .prepare(request(
                1,
                TotalMicrovmClass::MicrovmEligible,
                IsolationPlacement::Microvm,
            ))
            .unwrap();
        admission
            .unavailable(prepared, IsolationUnavailableReason::VmmResource)
            .unwrap();
        assert_eq!(
            inventory.finalize(&admission),
            Err(TotalMicrovmRuntimeError::RequiredDomainUnavailable)
        );
    }

    #[test]
    fn unclassified_or_mismatched_active_domains_fail_closed() {
        let mut admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, SYSTEM, POLICY).unwrap();
        commit(
            &mut admission,
            request(1, TotalMicrovmClass::BootOnly, IsolationPlacement::Platform),
            IsolationLaunchEvidence::PlatformReady,
        );
        let empty = TotalMicrovmInventory::<1>::new(SYSTEM, POLICY).unwrap();
        assert_eq!(
            empty.finalize(&admission),
            Err(TotalMicrovmRuntimeError::UnclassifiedActiveDomain)
        );
        let mut wrong = TotalMicrovmInventory::<1>::new(SYSTEM, POLICY).unwrap();
        wrong
            .insert(entry(1, TotalMicrovmClass::RecoveryOnly, true))
            .unwrap();
        assert_eq!(
            wrong.finalize(&admission),
            Err(TotalMicrovmRuntimeError::ClassificationMismatch)
        );
    }

    #[test]
    fn mode_generation_duplicate_and_capacity_errors_are_explicit() {
        let balanced =
            IsolationAdmissionTable::<1>::new(IsolationMode::Balanced, SYSTEM, POLICY).unwrap();
        let mut inventory = TotalMicrovmInventory::<1>::new(SYSTEM, POLICY).unwrap();
        inventory
            .insert(entry(1, TotalMicrovmClass::BootOnly, false))
            .unwrap();
        assert_eq!(
            inventory.finalize(&balanced),
            Err(TotalMicrovmRuntimeError::TotalNotRequested)
        );
        assert_eq!(
            inventory.insert(entry(1, TotalMicrovmClass::BootOnly, false)),
            Err(TotalMicrovmRuntimeError::DuplicateDomain)
        );
        assert_eq!(
            inventory.insert(entry(2, TotalMicrovmClass::BootOnly, false)),
            Err(TotalMicrovmRuntimeError::InventoryFull)
        );
        let total =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, SYSTEM, POLICY).unwrap();
        let stale = TotalMicrovmInventory::<1>::new(SYSTEM, POLICY + 1).unwrap();
        assert_eq!(
            stale.finalize(&total),
            Err(TotalMicrovmRuntimeError::InvalidInventory)
        );
    }
}
