use core::array;

use crate::ObjectId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsolationMode {
    Balanced,
    MoreIsolated,
    TotalMicrovm,
    Custom,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsolationPlacement {
    InProcess,
    NativeProcess,
    NativeService,
    Microvm,
    Platform,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostSubstrateReason {
    InstantiateMicrovms,
    SuperviseMicrovms,
    ProjectCapabilities,
    IsolateDevices,
    BootstrapMicrovms,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TotalMicrovmClass {
    MicrovmEligible,
    HostSubstrateRequired(HostSubstrateReason),
    BootOnly,
    RecoveryOnly,
    UnsupportedBlocker,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsolationLaunchEvidence {
    NativeReady,
    MicrovmReady,
    PlatformReady,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsolationUnavailableReason {
    VirtualizationUnavailable,
    MemoryBudget,
    VcpuBudget,
    VirtualGpu,
    DeviceProjection,
    VmmResource,
    InterfaceTransport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnavailableIsolationDomain {
    domain: ObjectId,
    policy_generation: u64,
    sequence: u64,
    class: TotalMicrovmClass,
    requested_placement: IsolationPlacement,
    reason: IsolationUnavailableReason,
}

impl UnavailableIsolationDomain {
    pub const fn domain(self) -> ObjectId {
        self.domain
    }

    pub const fn reason(self) -> IsolationUnavailableReason {
        self.reason
    }

    pub const fn policy_generation(self) -> u64 {
        self.policy_generation
    }

    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    pub const fn class(self) -> TotalMicrovmClass {
        self.class
    }

    pub const fn requested_placement(self) -> IsolationPlacement {
        self.requested_placement
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsolationLaunchError {
    InvalidPolicyGeneration,
    DuplicateDomain,
    TableFull,
    TotalMicrovmUnsupportedBlocker,
    TotalMicrovmDowngradeAttempt,
    PlacementClassMismatch,
    BackendEvidenceMismatch,
    StaleLaunch,
    GenerationExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IsolationLaunchRequest {
    domain: ObjectId,
    policy_generation: u64,
    class: TotalMicrovmClass,
    placement: IsolationPlacement,
}

impl IsolationLaunchRequest {
    pub const fn new(
        domain: ObjectId,
        policy_generation: u64,
        class: TotalMicrovmClass,
        placement: IsolationPlacement,
    ) -> Result<Self, IsolationLaunchError> {
        if policy_generation == 0 {
            return Err(IsolationLaunchError::InvalidPolicyGeneration);
        }
        Ok(Self {
            domain,
            policy_generation,
            class,
            placement,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct PreparedIsolationLaunch {
    slot: usize,
    slot_generation: u64,
    domain: ObjectId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunningIsolationDomain {
    domain: ObjectId,
    policy_generation: u64,
    class: TotalMicrovmClass,
    placement: IsolationPlacement,
}

impl RunningIsolationDomain {
    pub const fn domain(self) -> ObjectId {
        self.domain
    }

    pub const fn policy_generation(self) -> u64 {
        self.policy_generation
    }

    pub const fn class(self) -> TotalMicrovmClass {
        self.class
    }

    pub const fn placement(self) -> IsolationPlacement {
        self.placement
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LaunchState {
    Prepared,
    Running,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LaunchSlot {
    generation: u64,
    state: LaunchState,
    record: RunningIsolationDomain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TotalMicrovmReport {
    pub mode: IsolationMode,
    pub running_microvm_eligible: usize,
    pub running_in_microvm: usize,
    pub running_eligible_outside_microvm: usize,
    pub running_host_substrate: usize,
    pub running_boot_only: usize,
    pub running_recovery_only: usize,
    pub running_unsupported_blockers: usize,
    pub unavailable_microvm_eligible: usize,
    pub native_fallback: usize,
}

impl TotalMicrovmReport {
    pub fn satisfied(self) -> bool {
        self.mode == IsolationMode::TotalMicrovm
            && self.running_microvm_eligible == self.running_in_microvm
            && self.running_eligible_outside_microvm == 0
            && self.running_unsupported_blockers == 0
            && self.native_fallback == 0
    }
}

/// Kernel-side admission records only caller-selected placement and exact
/// backend readiness. Names and package metadata grant no authority, and this
/// table neither selects providers nor creates VMs or resources.
pub struct IsolationAdmissionTable<const DOMAINS: usize> {
    mode: IsolationMode,
    policy_generation: u64,
    slots: [Option<LaunchSlot>; DOMAINS],
    unavailable: [Option<UnavailableIsolationDomain>; DOMAINS],
    unavailable_head: usize,
    unavailable_count: usize,
    next_slot_generation: u64,
    next_unavailable_sequence: u64,
}

impl<const DOMAINS: usize> IsolationAdmissionTable<DOMAINS> {
    pub fn new(mode: IsolationMode, policy_generation: u64) -> Result<Self, IsolationLaunchError> {
        if policy_generation == 0 {
            return Err(IsolationLaunchError::InvalidPolicyGeneration);
        }
        Ok(Self {
            mode,
            policy_generation,
            slots: array::from_fn(|_| None),
            unavailable: array::from_fn(|_| None),
            unavailable_head: 0,
            unavailable_count: 0,
            next_slot_generation: 1,
            next_unavailable_sequence: 1,
        })
    }

    pub const fn mode(&self) -> IsolationMode {
        self.mode
    }

    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    pub fn prepare(
        &mut self,
        request: IsolationLaunchRequest,
    ) -> Result<PreparedIsolationLaunch, IsolationLaunchError> {
        if request.policy_generation != self.policy_generation {
            return Err(IsolationLaunchError::InvalidPolicyGeneration);
        }
        if self
            .slots
            .iter()
            .flatten()
            .any(|slot| slot.record.domain == request.domain)
        {
            return Err(IsolationLaunchError::DuplicateDomain);
        }
        self.validate_placement(request.class, request.placement)?;
        let slot = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(IsolationLaunchError::TableFull)?;
        let generation = self.next_slot_generation;
        let next_generation = generation
            .checked_add(1)
            .ok_or(IsolationLaunchError::GenerationExhausted)?;
        self.remove_unavailable(request.domain);
        self.next_slot_generation = next_generation;
        self.slots[slot] = Some(LaunchSlot {
            generation,
            state: LaunchState::Prepared,
            record: RunningIsolationDomain {
                domain: request.domain,
                policy_generation: request.policy_generation,
                class: request.class,
                placement: request.placement,
            },
        });
        Ok(PreparedIsolationLaunch {
            slot,
            slot_generation: generation,
            domain: request.domain,
        })
    }

    pub fn commit(
        &mut self,
        prepared: &PreparedIsolationLaunch,
        evidence: IsolationLaunchEvidence,
    ) -> Result<RunningIsolationDomain, IsolationLaunchError> {
        let slot = self.prepared_slot_mut(prepared)?;
        let expected = match slot.record.placement {
            IsolationPlacement::Microvm => IsolationLaunchEvidence::MicrovmReady,
            IsolationPlacement::Platform => IsolationLaunchEvidence::PlatformReady,
            IsolationPlacement::InProcess
            | IsolationPlacement::NativeProcess
            | IsolationPlacement::NativeService => IsolationLaunchEvidence::NativeReady,
        };
        if evidence != expected {
            return Err(IsolationLaunchError::BackendEvidenceMismatch);
        }
        slot.state = LaunchState::Running;
        Ok(slot.record)
    }

    pub fn cancel(
        &mut self,
        prepared: PreparedIsolationLaunch,
    ) -> Result<(), IsolationLaunchError> {
        self.prepared_slot_mut(&prepared)?;
        self.slots[prepared.slot] = None;
        Ok(())
    }

    pub fn unavailable(
        &mut self,
        prepared: PreparedIsolationLaunch,
        reason: IsolationUnavailableReason,
    ) -> Result<UnavailableIsolationDomain, IsolationLaunchError> {
        let record = self.prepared_slot_mut(&prepared)?.record;
        let sequence = self.next_unavailable_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(IsolationLaunchError::GenerationExhausted)?;
        let unavailable = UnavailableIsolationDomain {
            domain: prepared.domain,
            policy_generation: record.policy_generation,
            sequence,
            class: record.class,
            requested_placement: record.placement,
            reason,
        };
        self.record_unavailable(unavailable);
        self.next_unavailable_sequence = next_sequence;
        self.slots[prepared.slot] = None;
        Ok(unavailable)
    }

    pub fn retire(&mut self, domain: ObjectId) -> Result<(), IsolationLaunchError> {
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| {
                slot.as_ref().is_some_and(|slot| {
                    slot.state == LaunchState::Running && slot.record.domain == domain
                })
            })
            .ok_or(IsolationLaunchError::StaleLaunch)?;
        *slot = None;
        Ok(())
    }

    pub fn running(&self) -> impl Iterator<Item = RunningIsolationDomain> + '_ {
        self.slots.iter().filter_map(|slot| {
            slot.filter(|slot| slot.state == LaunchState::Running)
                .map(|slot| slot.record)
        })
    }

    pub fn unavailable_domains(&self) -> impl Iterator<Item = UnavailableIsolationDomain> + '_ {
        (0..self.unavailable_count).filter_map(|offset| {
            let index = (self.unavailable_head + offset) % DOMAINS;
            self.unavailable[index]
        })
    }

    pub fn total_microvm_report(&self) -> TotalMicrovmReport {
        let mut report = TotalMicrovmReport {
            mode: self.mode,
            running_microvm_eligible: 0,
            running_in_microvm: 0,
            running_eligible_outside_microvm: 0,
            running_host_substrate: 0,
            running_boot_only: 0,
            running_recovery_only: 0,
            running_unsupported_blockers: 0,
            unavailable_microvm_eligible: self
                .unavailable_domains()
                .filter(|record| record.class == TotalMicrovmClass::MicrovmEligible)
                .count(),
            native_fallback: 0,
        };
        for record in self.running() {
            match record.class {
                TotalMicrovmClass::MicrovmEligible => {
                    report.running_microvm_eligible += 1;
                    if record.placement == IsolationPlacement::Microvm {
                        report.running_in_microvm += 1;
                    } else {
                        report.running_eligible_outside_microvm += 1;
                        report.native_fallback += 1;
                    }
                }
                TotalMicrovmClass::HostSubstrateRequired(_) => {
                    report.running_host_substrate += 1;
                }
                TotalMicrovmClass::BootOnly => report.running_boot_only += 1,
                TotalMicrovmClass::RecoveryOnly => report.running_recovery_only += 1,
                TotalMicrovmClass::UnsupportedBlocker => {
                    report.running_unsupported_blockers += 1;
                }
            }
        }
        report
    }

    fn record_unavailable(&mut self, record: UnavailableIsolationDomain) {
        self.remove_unavailable(record.domain);
        if self.unavailable_count < DOMAINS {
            let index = (self.unavailable_head + self.unavailable_count) % DOMAINS;
            self.unavailable[index] = Some(record);
            self.unavailable_count += 1;
        } else {
            self.unavailable[self.unavailable_head] = Some(record);
            self.unavailable_head = (self.unavailable_head + 1) % DOMAINS;
        }
    }

    fn remove_unavailable(&mut self, domain: ObjectId) {
        let mut retained = array::from_fn(|_| None);
        let mut retained_count = 0;
        for record in self.unavailable_domains() {
            if record.domain != domain {
                retained[retained_count] = Some(record);
                retained_count += 1;
            }
        }
        self.unavailable = retained;
        self.unavailable_head = 0;
        self.unavailable_count = retained_count;
    }

    fn validate_placement(
        &self,
        class: TotalMicrovmClass,
        placement: IsolationPlacement,
    ) -> Result<(), IsolationLaunchError> {
        if self.mode == IsolationMode::TotalMicrovm {
            return match class {
                TotalMicrovmClass::MicrovmEligible if placement == IsolationPlacement::Microvm => {
                    Ok(())
                }
                TotalMicrovmClass::MicrovmEligible => {
                    Err(IsolationLaunchError::TotalMicrovmDowngradeAttempt)
                }
                TotalMicrovmClass::UnsupportedBlocker => {
                    Err(IsolationLaunchError::TotalMicrovmUnsupportedBlocker)
                }
                TotalMicrovmClass::HostSubstrateRequired(_) => {
                    if matches!(placement, IsolationPlacement::NativeService) {
                        Ok(())
                    } else {
                        Err(IsolationLaunchError::PlacementClassMismatch)
                    }
                }
                TotalMicrovmClass::BootOnly | TotalMicrovmClass::RecoveryOnly => {
                    if placement == IsolationPlacement::Platform {
                        Ok(())
                    } else {
                        Err(IsolationLaunchError::PlacementClassMismatch)
                    }
                }
            };
        }
        match class {
            TotalMicrovmClass::BootOnly | TotalMicrovmClass::RecoveryOnly
                if placement != IsolationPlacement::Platform =>
            {
                Err(IsolationLaunchError::PlacementClassMismatch)
            }
            TotalMicrovmClass::HostSubstrateRequired(_)
                if placement != IsolationPlacement::NativeService =>
            {
                Err(IsolationLaunchError::PlacementClassMismatch)
            }
            TotalMicrovmClass::UnsupportedBlocker if placement == IsolationPlacement::Microvm => {
                Err(IsolationLaunchError::PlacementClassMismatch)
            }
            _ => Ok(()),
        }
    }

    fn prepared_slot_mut(
        &mut self,
        prepared: &PreparedIsolationLaunch,
    ) -> Result<&mut LaunchSlot, IsolationLaunchError> {
        let slot = self
            .slots
            .get_mut(prepared.slot)
            .and_then(Option::as_mut)
            .ok_or(IsolationLaunchError::StaleLaunch)?;
        if slot.generation != prepared.slot_generation
            || slot.state != LaunchState::Prepared
            || slot.record.domain != prepared.domain
        {
            return Err(IsolationLaunchError::StaleLaunch);
        }
        Ok(slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(
        object: u64,
        class: TotalMicrovmClass,
        placement: IsolationPlacement,
    ) -> IsolationLaunchRequest {
        IsolationLaunchRequest::new(ObjectId(object), 7, class, placement).unwrap()
    }

    #[test]
    fn total_mode_admits_only_backend_confirmed_eligible_microvms() {
        let mut table = IsolationAdmissionTable::<2>::new(IsolationMode::TotalMicrovm, 7).unwrap();
        let prepared = table
            .prepare(request(
                1,
                TotalMicrovmClass::MicrovmEligible,
                IsolationPlacement::Microvm,
            ))
            .unwrap();
        assert_eq!(
            table.commit(&prepared, IsolationLaunchEvidence::NativeReady),
            Err(IsolationLaunchError::BackendEvidenceMismatch)
        );
        table
            .commit(&prepared, IsolationLaunchEvidence::MicrovmReady)
            .unwrap();
        let report = table.total_microvm_report();
        assert!(report.satisfied());
        assert_eq!(report.running_microvm_eligible, 1);
        assert_eq!(report.native_fallback, 0);
    }

    #[test]
    fn total_mode_rejects_native_downgrade_and_unsupported_blocker() {
        let mut table = IsolationAdmissionTable::<2>::new(IsolationMode::TotalMicrovm, 7).unwrap();
        assert_eq!(
            table.prepare(request(
                1,
                TotalMicrovmClass::MicrovmEligible,
                IsolationPlacement::NativeService,
            )),
            Err(IsolationLaunchError::TotalMicrovmDowngradeAttempt)
        );
        assert_eq!(
            table.prepare(request(
                2,
                TotalMicrovmClass::UnsupportedBlocker,
                IsolationPlacement::NativeService,
            )),
            Err(IsolationLaunchError::TotalMicrovmUnsupportedBlocker)
        );
        assert_eq!(table.running().count(), 0);
    }

    #[test]
    fn unavailable_microvm_preserves_total_policy_and_exact_reason() {
        let mut table = IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, 7).unwrap();
        let prepared = table
            .prepare(request(
                4,
                TotalMicrovmClass::MicrovmEligible,
                IsolationPlacement::Microvm,
            ))
            .unwrap();
        let unavailable = table
            .unavailable(prepared, IsolationUnavailableReason::MemoryBudget)
            .unwrap();
        assert_eq!(unavailable.domain(), ObjectId(4));
        assert_eq!(
            unavailable.reason(),
            IsolationUnavailableReason::MemoryBudget
        );
        assert_eq!(table.running().count(), 0);
        assert!(table.total_microvm_report().satisfied());
        let retained = table.unavailable_domains().next().unwrap();
        assert_eq!(retained.policy_generation(), 7);
        assert_eq!(retained.sequence(), 1);
        assert_eq!(retained.class(), TotalMicrovmClass::MicrovmEligible);
        assert_eq!(retained.requested_placement(), IsolationPlacement::Microvm);
        assert_eq!(table.total_microvm_report().unavailable_microvm_eligible, 1);
    }

    #[test]
    fn explicit_substrate_reason_is_not_counted_as_fallback() {
        let mut table = IsolationAdmissionTable::<2>::new(IsolationMode::TotalMicrovm, 7).unwrap();
        let prepared = table
            .prepare(request(
                3,
                TotalMicrovmClass::HostSubstrateRequired(HostSubstrateReason::InstantiateMicrovms),
                IsolationPlacement::NativeService,
            ))
            .unwrap();
        table
            .commit(&prepared, IsolationLaunchEvidence::NativeReady)
            .unwrap();
        let report = table.total_microvm_report();
        assert!(report.satisfied());
        assert_eq!(report.running_host_substrate, 1);
        assert_eq!(report.native_fallback, 0);
    }

    #[test]
    fn stale_policy_duplicate_capacity_and_cancel_fail_closed() {
        let mut table = IsolationAdmissionTable::<1>::new(IsolationMode::Balanced, 7).unwrap();
        let stale = IsolationLaunchRequest::new(
            ObjectId(1),
            8,
            TotalMicrovmClass::MicrovmEligible,
            IsolationPlacement::NativeProcess,
        )
        .unwrap();
        assert_eq!(
            table.prepare(stale),
            Err(IsolationLaunchError::InvalidPolicyGeneration)
        );
        let prepared = table
            .prepare(request(
                1,
                TotalMicrovmClass::MicrovmEligible,
                IsolationPlacement::NativeProcess,
            ))
            .unwrap();
        assert_eq!(
            table.prepare(request(
                1,
                TotalMicrovmClass::MicrovmEligible,
                IsolationPlacement::NativeProcess,
            )),
            Err(IsolationLaunchError::DuplicateDomain)
        );
        assert_eq!(
            table.prepare(request(
                2,
                TotalMicrovmClass::MicrovmEligible,
                IsolationPlacement::NativeProcess,
            )),
            Err(IsolationLaunchError::TableFull)
        );
        table.cancel(prepared).unwrap();
        assert_eq!(table.running().count(), 0);
    }

    #[test]
    fn unavailable_ledger_is_bounded_ordered_and_retry_replaces_old_failure() {
        let mut table = IsolationAdmissionTable::<2>::new(IsolationMode::TotalMicrovm, 7).unwrap();
        for (domain, reason) in [
            (1, IsolationUnavailableReason::MemoryBudget),
            (2, IsolationUnavailableReason::VcpuBudget),
            (3, IsolationUnavailableReason::InterfaceTransport),
        ] {
            let prepared = table
                .prepare(request(
                    domain,
                    TotalMicrovmClass::MicrovmEligible,
                    IsolationPlacement::Microvm,
                ))
                .unwrap();
            table.unavailable(prepared, reason).unwrap();
        }
        {
            let mut retained = table.unavailable_domains();
            let first = retained.next().unwrap();
            let second = retained.next().unwrap();
            assert!(retained.next().is_none());
            assert_eq!(first.domain(), ObjectId(2));
            assert_eq!(first.sequence(), 2);
            assert_eq!(second.domain(), ObjectId(3));
            assert_eq!(second.sequence(), 3);
        }

        let retry = table
            .prepare(request(
                2,
                TotalMicrovmClass::MicrovmEligible,
                IsolationPlacement::Microvm,
            ))
            .unwrap();
        {
            let mut retained = table.unavailable_domains();
            assert_eq!(
                retained.next().map(|record| record.domain()),
                Some(ObjectId(3))
            );
            assert!(retained.next().is_none());
        }
        table
            .commit(&retry, IsolationLaunchEvidence::MicrovmReady)
            .unwrap();
        assert!(table.total_microvm_report().satisfied());
    }
}
