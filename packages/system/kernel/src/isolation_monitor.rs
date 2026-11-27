use crate::{
    Capability, CapabilityError, CapabilitySpace, HostSubstrateReason, IsolationAdmissionTable,
    IsolationMode, IsolationUnavailableReason, ObjectId, Rights, TotalMicrovmClass,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TotalMicrovmState {
    NotRequested,
    Satisfied,
    Unsatisfied,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HostSubstrateCounts {
    pub instantiate_microvms: usize,
    pub supervise_microvms: usize,
    pub project_capabilities: usize,
    pub isolate_devices: usize,
    pub bootstrap_microvms: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IsolationUnavailableCounts {
    pub native_process_resource: usize,
    pub native_service_resource: usize,
    pub virtualization_unavailable: usize,
    pub memory_budget: usize,
    pub vcpu_budget: usize,
    pub virtual_gpu: usize,
    pub device_projection: usize,
    pub vmm_resource: usize,
    pub interface_transport: usize,
}

/// Capability-scoped, privacy-bounded projection of the authoritative
/// isolation admission table. The snapshot contains no domain identities and
/// grants no placement, launch, inspection of another object, or remediation
/// authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IsolationStatusSnapshot {
    pub system_generation: u64,
    pub policy_generation: u64,
    pub requested_mode: IsolationMode,
    pub total_state: TotalMicrovmState,
    pub running_microvm_eligible: usize,
    pub running_in_microvm: usize,
    pub running_eligible_outside_microvm: usize,
    pub running_boot_only: usize,
    pub running_recovery_only: usize,
    pub running_unsupported_blockers: usize,
    pub unavailable_microvm_eligible: usize,
    pub native_fallback: usize,
    pub host_substrate: HostSubstrateCounts,
    pub unavailable: IsolationUnavailableCounts,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsolationMonitorError {
    Capability(CapabilityError),
    WrongMonitorObject,
}

/// Reads one aggregate snapshot after exact-object inspection authorization.
/// The capability check is the control plane; constructing the immutable
/// snapshot is a read-only data path over already-authoritative kernel state.
pub fn inspect_isolation_status<const CAPABILITIES: usize, const DOMAINS: usize>(
    capabilities: &CapabilitySpace<CAPABILITIES>,
    inspect: Capability,
    monitor_object: ObjectId,
    admission: &IsolationAdmissionTable<DOMAINS>,
) -> Result<IsolationStatusSnapshot, IsolationMonitorError> {
    let authorized = capabilities
        .authorize(inspect, Rights::INSPECT)
        .map_err(IsolationMonitorError::Capability)?;
    if authorized != monitor_object {
        return Err(IsolationMonitorError::WrongMonitorObject);
    }

    let report = admission.total_microvm_report();
    let total_state = if report.mode != IsolationMode::TotalMicrovm {
        TotalMicrovmState::NotRequested
    } else if report.satisfied() {
        TotalMicrovmState::Satisfied
    } else {
        TotalMicrovmState::Unsatisfied
    };
    let mut host_substrate = HostSubstrateCounts::default();
    for record in admission.running() {
        if let TotalMicrovmClass::HostSubstrateRequired(reason) = record.class() {
            match reason {
                HostSubstrateReason::InstantiateMicrovms => {
                    host_substrate.instantiate_microvms += 1
                }
                HostSubstrateReason::SuperviseMicrovms => host_substrate.supervise_microvms += 1,
                HostSubstrateReason::ProjectCapabilities => {
                    host_substrate.project_capabilities += 1
                }
                HostSubstrateReason::IsolateDevices => host_substrate.isolate_devices += 1,
                HostSubstrateReason::BootstrapMicrovms => host_substrate.bootstrap_microvms += 1,
            }
        }
    }
    let mut unavailable = IsolationUnavailableCounts::default();
    for record in admission.unavailable_domains() {
        match record.reason() {
            IsolationUnavailableReason::NativeProcessResource => {
                unavailable.native_process_resource += 1
            }
            IsolationUnavailableReason::NativeServiceResource => {
                unavailable.native_service_resource += 1
            }
            IsolationUnavailableReason::VirtualizationUnavailable => {
                unavailable.virtualization_unavailable += 1
            }
            IsolationUnavailableReason::MemoryBudget => unavailable.memory_budget += 1,
            IsolationUnavailableReason::VcpuBudget => unavailable.vcpu_budget += 1,
            IsolationUnavailableReason::VirtualGpu => unavailable.virtual_gpu += 1,
            IsolationUnavailableReason::DeviceProjection => unavailable.device_projection += 1,
            IsolationUnavailableReason::VmmResource => unavailable.vmm_resource += 1,
            IsolationUnavailableReason::InterfaceTransport => unavailable.interface_transport += 1,
        }
    }

    Ok(IsolationStatusSnapshot {
        system_generation: admission.system_generation(),
        policy_generation: admission.policy_generation(),
        requested_mode: admission.mode(),
        total_state,
        running_microvm_eligible: report.running_microvm_eligible,
        running_in_microvm: report.running_in_microvm,
        running_eligible_outside_microvm: report.running_eligible_outside_microvm,
        running_boot_only: report.running_boot_only,
        running_recovery_only: report.running_recovery_only,
        running_unsupported_blockers: report.running_unsupported_blockers,
        unavailable_microvm_eligible: report.unavailable_microvm_eligible,
        native_fallback: report.native_fallback,
        host_substrate,
        unavailable,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IsolationLaunchEvidence, IsolationLaunchRequest, IsolationPlacement};

    const MONITOR: ObjectId = ObjectId(0x7100);

    fn request(
        domain: u64,
        class: TotalMicrovmClass,
        placement: IsolationPlacement,
    ) -> IsolationLaunchRequest {
        IsolationLaunchRequest::new(ObjectId(domain), 7, 11, class, placement).unwrap()
    }

    fn commit<const N: usize>(
        table: &mut IsolationAdmissionTable<N>,
        request: IsolationLaunchRequest,
        evidence: IsolationLaunchEvidence,
    ) {
        let prepared = table.prepare(request).unwrap();
        table.commit(&prepared, evidence).unwrap();
    }

    #[test]
    fn inspection_requires_exact_live_monitor_authority() {
        let table = IsolationAdmissionTable::<2>::new(IsolationMode::HostedRegression, 7, 11).unwrap();
        let mut capabilities = CapabilitySpace::<3>::new();
        let read = capabilities.insert(MONITOR, Rights::READ).unwrap();
        let wrong = capabilities
            .insert(ObjectId(0x7200), Rights::INSPECT)
            .unwrap();
        let stale = capabilities.insert(MONITOR, Rights::INSPECT).unwrap();
        capabilities.revoke(stale).unwrap();

        assert_eq!(
            inspect_isolation_status(&capabilities, read, MONITOR, &table),
            Err(IsolationMonitorError::Capability(
                CapabilityError::PermissionDenied
            ))
        );
        assert_eq!(
            inspect_isolation_status(&capabilities, wrong, MONITOR, &table),
            Err(IsolationMonitorError::WrongMonitorObject)
        );
        assert_eq!(
            inspect_isolation_status(&capabilities, stale, MONITOR, &table),
            Err(IsolationMonitorError::Capability(CapabilityError::Invalid))
        );
    }

    #[test]
    fn total_snapshot_reports_exact_aggregate_state_without_domain_ids() {
        let mut table =
            IsolationAdmissionTable::<12>::new(IsolationMode::TotalMicrovm, 7, 11).unwrap();
        commit(
            &mut table,
            request(
                1,
                TotalMicrovmClass::MicrovmEligible,
                IsolationPlacement::Microvm,
            ),
            IsolationLaunchEvidence::MicrovmReady,
        );
        commit(
            &mut table,
            request(
                2,
                TotalMicrovmClass::HostSubstrateRequired(HostSubstrateReason::InstantiateMicrovms),
                IsolationPlacement::NativeService,
            ),
            IsolationLaunchEvidence::NativeReady,
        );
        commit(
            &mut table,
            request(
                3,
                TotalMicrovmClass::HostSubstrateRequired(HostSubstrateReason::ProjectCapabilities),
                IsolationPlacement::NativeService,
            ),
            IsolationLaunchEvidence::NativeReady,
        );
        commit(
            &mut table,
            request(4, TotalMicrovmClass::BootOnly, IsolationPlacement::Platform),
            IsolationLaunchEvidence::PlatformReady,
        );
        let failed = table
            .prepare(request(
                5,
                TotalMicrovmClass::MicrovmEligible,
                IsolationPlacement::Microvm,
            ))
            .unwrap();
        table
            .unavailable(failed, IsolationUnavailableReason::VirtualGpu)
            .unwrap();
        let failed = table
            .prepare(request(
                6,
                TotalMicrovmClass::MicrovmEligible,
                IsolationPlacement::Microvm,
            ))
            .unwrap();
        table
            .unavailable(failed, IsolationUnavailableReason::MemoryBudget)
            .unwrap();

        let mut capabilities = CapabilitySpace::<1>::new();
        let inspect = capabilities.insert(MONITOR, Rights::INSPECT).unwrap();
        let snapshot = inspect_isolation_status(&capabilities, inspect, MONITOR, &table).unwrap();

        assert_eq!(snapshot.system_generation, 7);
        assert_eq!(snapshot.policy_generation, 11);
        assert_eq!(snapshot.requested_mode, IsolationMode::TotalMicrovm);
        assert_eq!(snapshot.total_state, TotalMicrovmState::Satisfied);
        assert_eq!(snapshot.running_microvm_eligible, 1);
        assert_eq!(snapshot.running_in_microvm, 1);
        assert_eq!(snapshot.running_boot_only, 1);
        assert_eq!(snapshot.unavailable_microvm_eligible, 2);
        assert_eq!(snapshot.host_substrate.instantiate_microvms, 1);
        assert_eq!(snapshot.host_substrate.project_capabilities, 1);
        assert_eq!(snapshot.unavailable.virtual_gpu, 1);
        assert_eq!(snapshot.unavailable.memory_budget, 1);
    }

    #[test]
    fn total_state_distinguishes_not_requested_from_satisfied() {
        let balanced = IsolationAdmissionTable::<1>::new(IsolationMode::HostedRegression, 7, 11).unwrap();
        let mut capabilities = CapabilitySpace::<1>::new();
        let inspect = capabilities.insert(MONITOR, Rights::INSPECT).unwrap();
        assert_eq!(
            inspect_isolation_status(&capabilities, inspect, MONITOR, &balanced)
                .unwrap()
                .total_state,
            TotalMicrovmState::NotRequested
        );

        let total = IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, 7, 11).unwrap();
        assert_eq!(
            inspect_isolation_status(&capabilities, inspect, MONITOR, &total)
                .unwrap()
                .total_state,
            TotalMicrovmState::Satisfied
        );
    }

    #[test]
    fn every_substrate_and_unavailable_reason_has_a_distinct_count() {
        let mut table = IsolationAdmissionTable::<20>::new(IsolationMode::HostedRegression, 7, 11).unwrap();
        let substrate = [
            HostSubstrateReason::InstantiateMicrovms,
            HostSubstrateReason::SuperviseMicrovms,
            HostSubstrateReason::ProjectCapabilities,
            HostSubstrateReason::IsolateDevices,
            HostSubstrateReason::BootstrapMicrovms,
        ];
        for (index, reason) in substrate.into_iter().enumerate() {
            commit(
                &mut table,
                request(
                    100 + index as u64,
                    TotalMicrovmClass::HostSubstrateRequired(reason),
                    IsolationPlacement::NativeService,
                ),
                IsolationLaunchEvidence::NativeReady,
            );
        }
        let reasons = [
            IsolationUnavailableReason::NativeProcessResource,
            IsolationUnavailableReason::NativeServiceResource,
            IsolationUnavailableReason::VirtualizationUnavailable,
            IsolationUnavailableReason::MemoryBudget,
            IsolationUnavailableReason::VcpuBudget,
            IsolationUnavailableReason::VirtualGpu,
            IsolationUnavailableReason::DeviceProjection,
            IsolationUnavailableReason::VmmResource,
            IsolationUnavailableReason::InterfaceTransport,
        ];
        for (index, reason) in reasons.into_iter().enumerate() {
            let prepared = table
                .prepare(request(
                    200 + index as u64,
                    TotalMicrovmClass::MicrovmEligible,
                    IsolationPlacement::Microvm,
                ))
                .unwrap();
            table.unavailable(prepared, reason).unwrap();
        }

        let mut capabilities = CapabilitySpace::<1>::new();
        let inspect = capabilities.insert(MONITOR, Rights::INSPECT).unwrap();
        let snapshot = inspect_isolation_status(&capabilities, inspect, MONITOR, &table).unwrap();
        assert_eq!(
            snapshot.host_substrate,
            HostSubstrateCounts {
                instantiate_microvms: 1,
                supervise_microvms: 1,
                project_capabilities: 1,
                isolate_devices: 1,
                bootstrap_microvms: 1,
            }
        );
        assert_eq!(
            snapshot.unavailable,
            IsolationUnavailableCounts {
                native_process_resource: 1,
                native_service_resource: 1,
                virtualization_unavailable: 1,
                memory_budget: 1,
                vcpu_budget: 1,
                virtual_gpu: 1,
                device_projection: 1,
                vmm_resource: 1,
                interface_transport: 1,
            }
        );
    }
}
