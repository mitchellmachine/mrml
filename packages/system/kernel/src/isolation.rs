use core::array;

use crate::{
    ArtifactKind, Capability, CapabilitySpace, CpuBudgetId, CpuBudgetTable, CpuResourceError,
    ObjectId, VcpuReservationId,
};

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
    NativeServiceResource,
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
    system_generation: u64,
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

    pub const fn system_generation(self) -> u64 {
        self.system_generation
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
    InvalidSystemGeneration,
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
pub struct IsolationServiceSpec {
    domain: ObjectId,
    interface: ObjectId,
    interface_generation: u32,
    provider_generation: u64,
    system_generation: u64,
    policy_generation: u64,
    class: TotalMicrovmClass,
    placement: IsolationPlacement,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsolationServiceSpecError {
    InvalidGeneration,
    UnsupportedPlacement,
}

impl IsolationServiceSpec {
    pub const fn new(
        domain: ObjectId,
        interface: ObjectId,
        interface_generation: u32,
        provider_generation: u64,
        system_generation: u64,
        policy_generation: u64,
        class: TotalMicrovmClass,
        placement: IsolationPlacement,
    ) -> Result<Self, IsolationServiceSpecError> {
        if interface_generation == 0
            || provider_generation == 0
            || system_generation == 0
            || policy_generation == 0
        {
            return Err(IsolationServiceSpecError::InvalidGeneration);
        }
        if !matches!(
            placement,
            IsolationPlacement::NativeService | IsolationPlacement::Microvm
        ) {
            return Err(IsolationServiceSpecError::UnsupportedPlacement);
        }
        Ok(Self {
            domain,
            interface,
            interface_generation,
            provider_generation,
            system_generation,
            policy_generation,
            class,
            placement,
        })
    }

    pub const fn domain(self) -> ObjectId {
        self.domain
    }
    pub const fn interface(self) -> ObjectId {
        self.interface
    }
    pub const fn interface_generation(self) -> u32 {
        self.interface_generation
    }
    pub const fn provider_generation(self) -> u64 {
        self.provider_generation
    }
    pub const fn system_generation(self) -> u64 {
        self.system_generation
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

#[derive(Debug, Eq, PartialEq)]
pub struct IsolationBackendFailure<E> {
    reason: IsolationUnavailableReason,
    error: E,
}

impl<E> IsolationBackendFailure<E> {
    pub const fn new(reason: IsolationUnavailableReason, error: E) -> Self {
        Self { reason, error }
    }
    pub const fn reason(&self) -> IsolationUnavailableReason {
        self.reason
    }
    pub const fn error(&self) -> &E {
        &self.error
    }
}

pub trait IsolationServiceBackend {
    type Endpoint;
    type Error;

    fn launch_native_service(
        &mut self,
        spec: IsolationServiceSpec,
    ) -> Result<Self::Endpoint, IsolationBackendFailure<Self::Error>>;

    fn launch_microvm_service(
        &mut self,
        spec: IsolationServiceSpec,
    ) -> Result<Self::Endpoint, IsolationBackendFailure<Self::Error>>;

    fn revoke(&mut self, endpoint: &Self::Endpoint) -> Result<(), Self::Error>;
}

#[derive(Debug, Eq, PartialEq)]
pub enum IsolationServiceRouteError<E, Endpoint> {
    Admission(IsolationLaunchError),
    Backend {
        reason: IsolationUnavailableReason,
        error: E,
    },
    Rollback {
        admission: IsolationLaunchError,
        error: E,
        endpoint: Endpoint,
        prepared: PreparedIsolationServiceRoute,
    },
}

#[derive(Debug, Eq, PartialEq)]
pub struct RoutedIsolationService<E> {
    endpoint: E,
    domain: ObjectId,
    interface: ObjectId,
    interface_generation: u32,
    provider_generation: u64,
    system_generation: u64,
    policy_generation: u64,
    class: TotalMicrovmClass,
    placement: IsolationPlacement,
}

#[derive(Debug, Eq, PartialEq)]
pub struct PreparedIsolationServiceRoute {
    spec: IsolationServiceSpec,
    launch: PreparedIsolationLaunch,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ReservedIsolationVcpus {
    route: PreparedIsolationServiceRoute,
    reservation: VcpuReservationId,
}

impl ReservedIsolationVcpus {
    pub fn into_parts(self) -> (PreparedIsolationServiceRoute, VcpuReservationId) {
        (self.route, self.reservation)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsolationVcpuReservationError {
    Cpu(CpuResourceError),
    Admission(IsolationLaunchError),
}

/// Reserves exact quantitative vCPU authority while retaining the uncommitted
/// isolation route. Resource failure consumes the route into typed
/// unavailability, so callers cannot retry through a weaker placement.
pub fn reserve_isolation_vcpus<
    const DOMAINS: usize,
    const BUDGETS: usize,
    const RESERVATIONS: usize,
    const CAPABILITIES: usize,
>(
    route: PreparedIsolationServiceRoute,
    admission: &mut IsolationAdmissionTable<DOMAINS>,
    budgets: &mut CpuBudgetTable<BUDGETS, RESERVATIONS>,
    budget: CpuBudgetId,
    budget_capability: Capability,
    parallelism: u16,
    capabilities: &CapabilitySpace<CAPABILITIES>,
) -> Result<ReservedIsolationVcpus, IsolationVcpuReservationError> {
    match budgets.reserve_vcpus(
        budget,
        budget_capability,
        route.spec().domain(),
        parallelism,
        capabilities,
    ) {
        Ok(reservation) => Ok(ReservedIsolationVcpus { route, reservation }),
        Err(error) => {
            route
                .unavailable(admission, IsolationUnavailableReason::VcpuBudget)
                .map_err(IsolationVcpuReservationError::Admission)?;
            Err(IsolationVcpuReservationError::Cpu(error))
        }
    }
}

impl PreparedIsolationServiceRoute {
    pub const fn spec(&self) -> IsolationServiceSpec {
        self.spec
    }

    pub fn unavailable<const DOMAINS: usize>(
        self,
        admission: &mut IsolationAdmissionTable<DOMAINS>,
        reason: IsolationUnavailableReason,
    ) -> Result<(), IsolationLaunchError> {
        admission.unavailable(self.launch, reason).map(|_| ())
    }

    pub fn cancel<const DOMAINS: usize>(
        self,
        admission: &mut IsolationAdmissionTable<DOMAINS>,
    ) -> Result<(), IsolationLaunchError> {
        admission.cancel(self.launch)
    }

    pub fn commit<E, const DOMAINS: usize>(
        self,
        admission: &mut IsolationAdmissionTable<DOMAINS>,
        endpoint: E,
    ) -> Result<RoutedIsolationService<E>, (Self, IsolationLaunchError, E)> {
        let evidence = match self.spec.placement {
            IsolationPlacement::NativeService => IsolationLaunchEvidence::NativeReady,
            IsolationPlacement::Microvm => IsolationLaunchEvidence::MicrovmReady,
            _ => unreachable!("IsolationServiceSpec rejected non-service placement"),
        };
        if let Err(error) = admission.commit(&self.launch, evidence) {
            return Err((self, error, endpoint));
        }
        Ok(RoutedIsolationService {
            endpoint,
            domain: self.spec.domain,
            interface: self.spec.interface,
            interface_generation: self.spec.interface_generation,
            provider_generation: self.spec.provider_generation,
            system_generation: self.spec.system_generation,
            policy_generation: self.spec.policy_generation,
            class: self.spec.class,
            placement: self.spec.placement,
        })
    }
}

/// One fail-closed control-plane handoff from exact interface/policy admission
/// to the selected native-service or microVM backend. It owns the
/// still-uncommitted route so attachment failure can be recorded or cancelled
/// without ever publishing a running domain. Control planes establish
/// authority; the resulting data plane may take the shortest safe path only
/// after this transaction commits.
#[derive(Debug, Eq, PartialEq)]
pub struct PreparedComponentServiceLaunch {
    route: PreparedIsolationServiceRoute,
    consumer_artifact: [u8; 64],
    provider_artifact: [u8; 64],
    interface_fingerprint: [u8; 32],
}

impl PreparedComponentServiceLaunch {
    pub fn bind(
        route: PreparedIsolationServiceRoute,
        interface: ObjectId,
        interface_generation: u32,
        provider_generation: u64,
        system_generation: u64,
        interface_fingerprint: [u8; 32],
        consumer_artifact: [u8; 64],
        provider_artifact: [u8; 64],
    ) -> Result<Self, (PreparedIsolationServiceRoute, ComponentServiceLaunchError)> {
        let spec = route.spec();
        let error = if spec.interface() != interface
            || spec.interface_generation() != interface_generation
            || spec.provider_generation() != provider_generation
        {
            Some(ComponentServiceLaunchError::RouteIdentityMismatch)
        } else if spec.system_generation() != system_generation {
            Some(ComponentServiceLaunchError::SystemGenerationMismatch)
        } else if interface_fingerprint == [0; 32] {
            Some(ComponentServiceLaunchError::InvalidInterfaceFingerprint)
        } else if consumer_artifact == [0; 64] || provider_artifact == [0; 64] {
            Some(ComponentServiceLaunchError::InvalidArtifactDigest)
        } else if consumer_artifact == provider_artifact {
            Some(ComponentServiceLaunchError::ArtifactSubstitution)
        } else {
            None
        };
        if let Some(error) = error {
            return Err((route, error));
        }
        Ok(Self {
            route,
            consumer_artifact,
            provider_artifact,
            interface_fingerprint,
        })
    }

    pub const fn spec(&self) -> IsolationServiceSpec {
        self.route.spec()
    }

    pub const fn consumer_artifact(&self) -> &[u8; 64] {
        &self.consumer_artifact
    }

    pub const fn provider_artifact(&self) -> &[u8; 64] {
        &self.provider_artifact
    }

    pub const fn interface_fingerprint(&self) -> &[u8; 32] {
        &self.interface_fingerprint
    }

    /// Verifies the two already authenticated executable records before the
    /// selected backend maps either image. File names, paths, and argument
    /// order never substitute for the exact retained digests.
    pub fn verify_artifacts(
        &self,
        consumer_kind: ArtifactKind,
        consumer_digest: &[u8; 64],
        provider_kind: ArtifactKind,
        provider_digest: &[u8; 64],
    ) -> Result<(), ComponentServiceArtifactError> {
        if consumer_kind != ArtifactKind::ServiceImage
            || provider_kind != ArtifactKind::ServiceImage
        {
            return Err(ComponentServiceArtifactError::InvalidArtifactKind);
        }
        if consumer_digest != &self.consumer_artifact {
            return Err(ComponentServiceArtifactError::ConsumerArtifactMismatch);
        }
        if provider_digest != &self.provider_artifact {
            return Err(ComponentServiceArtifactError::ProviderArtifactMismatch);
        }
        Ok(())
    }

    pub fn into_route(self) -> PreparedIsolationServiceRoute {
        self.route
    }

    /// Consumes an exact component launch that could not be constructed and
    /// records the bounded failure without publishing either artifact or
    /// permitting an alternate placement.
    pub fn unavailable<const DOMAINS: usize>(
        self,
        admission: &mut IsolationAdmissionTable<DOMAINS>,
        reason: IsolationUnavailableReason,
    ) -> Result<(), IsolationLaunchError> {
        self.route.unavailable(admission, reason)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentServiceLaunchError {
    RouteIdentityMismatch,
    SystemGenerationMismatch,
    InvalidInterfaceFingerprint,
    InvalidArtifactDigest,
    ArtifactSubstitution,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentServiceArtifactError {
    InvalidArtifactKind,
    ConsumerArtifactMismatch,
    ProviderArtifactMismatch,
}

#[derive(Debug, Eq, PartialEq)]
pub enum PreparedComponentServiceRouteError<E, Endpoint> {
    Artifact {
        launch: PreparedComponentServiceLaunch,
        error: ComponentServiceArtifactError,
    },
    Route(IsolationServiceRouteError<E, Endpoint>),
}

pub fn prepare_isolation_service_route<const DOMAINS: usize>(
    admission: &mut IsolationAdmissionTable<DOMAINS>,
    spec: IsolationServiceSpec,
) -> Result<PreparedIsolationServiceRoute, IsolationLaunchError> {
    let request = IsolationLaunchRequest::new(
        spec.domain,
        spec.system_generation,
        spec.policy_generation,
        spec.class,
        spec.placement,
    )?;
    admission
        .prepare(request)
        .map(|launch| PreparedIsolationServiceRoute { spec, launch })
}

impl<E> RoutedIsolationService<E> {
    pub const fn endpoint(&self) -> &E {
        &self.endpoint
    }

    pub fn into_endpoint(self) -> E {
        self.endpoint
    }

    /// Replaces only the concrete transport endpoint while preserving the
    /// exact admitted domain, interface, provider, policy, class, and
    /// placement identity. This is used when a placement-specific supervisor
    /// endpoint must be projected into the stable interface data plane.
    pub fn map_endpoint<M>(self, map: impl FnOnce(E) -> M) -> RoutedIsolationService<M> {
        RoutedIsolationService {
            endpoint: map(self.endpoint),
            domain: self.domain,
            interface: self.interface,
            interface_generation: self.interface_generation,
            provider_generation: self.provider_generation,
            system_generation: self.system_generation,
            policy_generation: self.policy_generation,
            class: self.class,
            placement: self.placement,
        }
    }
    pub const fn domain(&self) -> ObjectId {
        self.domain
    }
    pub const fn interface(&self) -> ObjectId {
        self.interface
    }
    pub const fn interface_generation(&self) -> u32 {
        self.interface_generation
    }
    pub const fn provider_generation(&self) -> u64 {
        self.provider_generation
    }
    pub const fn system_generation(&self) -> u64 {
        self.system_generation
    }
    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }
    pub const fn class(&self) -> TotalMicrovmClass {
        self.class
    }
    pub const fn placement(&self) -> IsolationPlacement {
        self.placement
    }
}

pub fn route_isolation_service<B: IsolationServiceBackend, const DOMAINS: usize>(
    admission: &mut IsolationAdmissionTable<DOMAINS>,
    backend: &mut B,
    spec: IsolationServiceSpec,
) -> Result<RoutedIsolationService<B::Endpoint>, IsolationServiceRouteError<B::Error, B::Endpoint>>
{
    let prepared = prepare_isolation_service_route(admission, spec)
        .map_err(IsolationServiceRouteError::Admission)?;
    launch_prepared_isolation_service_route(admission, backend, prepared)
}

/// Launches one already prepared exact service route. Preparation and backend
/// construction remain separate linear stages so package/interface admission
/// can bind immutable artifacts before either placement creates an endpoint.
pub fn launch_prepared_isolation_service_route<B: IsolationServiceBackend, const DOMAINS: usize>(
    admission: &mut IsolationAdmissionTable<DOMAINS>,
    backend: &mut B,
    prepared: PreparedIsolationServiceRoute,
) -> Result<RoutedIsolationService<B::Endpoint>, IsolationServiceRouteError<B::Error, B::Endpoint>>
{
    let spec = prepared.spec();
    let launched = match spec.placement {
        IsolationPlacement::NativeService => backend.launch_native_service(spec),
        IsolationPlacement::Microvm => backend.launch_microvm_service(spec),
        _ => unreachable!("IsolationServiceSpec rejected non-service placement"),
    };
    let endpoint = match launched {
        Ok(endpoint) => endpoint,
        Err(failure) => {
            prepared
                .unavailable(admission, failure.reason)
                .map_err(IsolationServiceRouteError::Admission)?;
            return Err(IsolationServiceRouteError::Backend {
                reason: failure.reason,
                error: failure.error,
            });
        }
    };
    let routed = match prepared.commit(admission, endpoint) {
        Ok(routed) => routed,
        Err((prepared, admission_error, endpoint)) => {
            return match backend.revoke(&endpoint) {
                Ok(()) => {
                    prepared
                        .cancel(admission)
                        .map_err(IsolationServiceRouteError::Admission)?;
                    Err(IsolationServiceRouteError::Admission(admission_error))
                }
                Err(error) => Err(IsolationServiceRouteError::Rollback {
                    admission: admission_error,
                    error,
                    endpoint,
                    prepared,
                }),
            };
        }
    };
    Ok(routed)
}

/// Revalidates the exact authenticated consumer/provider artifacts retained by
/// the control plane before invoking either the native-service or microVM
/// backend. Artifact failure returns the complete uncommitted launch; backend
/// failure follows the normal unavailable/rollback path and never tries the
/// other placement. The returned route is the immutable authority boundary
/// from which a placement adapter can open its direct IPC or shared-queue data
/// plane without repeating resolution or policy selection per message.
#[allow(clippy::too_many_arguments)]
pub fn launch_prepared_component_service<B: IsolationServiceBackend, const DOMAINS: usize>(
    admission: &mut IsolationAdmissionTable<DOMAINS>,
    backend: &mut B,
    launch: PreparedComponentServiceLaunch,
    consumer_kind: ArtifactKind,
    consumer_digest: &[u8; 64],
    provider_kind: ArtifactKind,
    provider_digest: &[u8; 64],
) -> Result<
    RoutedIsolationService<B::Endpoint>,
    PreparedComponentServiceRouteError<B::Error, B::Endpoint>,
> {
    if let Err(error) = launch.verify_artifacts(
        consumer_kind,
        consumer_digest,
        provider_kind,
        provider_digest,
    ) {
        return Err(PreparedComponentServiceRouteError::Artifact { launch, error });
    }
    launch_prepared_isolation_service_route(admission, backend, launch.into_route())
        .map_err(PreparedComponentServiceRouteError::Route)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IsolationLaunchRequest {
    domain: ObjectId,
    system_generation: u64,
    policy_generation: u64,
    class: TotalMicrovmClass,
    placement: IsolationPlacement,
}

impl IsolationLaunchRequest {
    pub const fn new(
        domain: ObjectId,
        system_generation: u64,
        policy_generation: u64,
        class: TotalMicrovmClass,
        placement: IsolationPlacement,
    ) -> Result<Self, IsolationLaunchError> {
        if system_generation == 0 {
            return Err(IsolationLaunchError::InvalidSystemGeneration);
        }
        if policy_generation == 0 {
            return Err(IsolationLaunchError::InvalidPolicyGeneration);
        }
        Ok(Self {
            domain,
            system_generation,
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
    system_generation: u64,
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

    pub const fn system_generation(self) -> u64 {
        self.system_generation
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
    system_generation: u64,
    policy_generation: u64,
    slots: [Option<LaunchSlot>; DOMAINS],
    unavailable: [Option<UnavailableIsolationDomain>; DOMAINS],
    unavailable_head: usize,
    unavailable_count: usize,
    next_slot_generation: u64,
    next_unavailable_sequence: u64,
}

impl<const DOMAINS: usize> IsolationAdmissionTable<DOMAINS> {
    pub fn new(
        mode: IsolationMode,
        system_generation: u64,
        policy_generation: u64,
    ) -> Result<Self, IsolationLaunchError> {
        if system_generation == 0 {
            return Err(IsolationLaunchError::InvalidSystemGeneration);
        }
        if policy_generation == 0 {
            return Err(IsolationLaunchError::InvalidPolicyGeneration);
        }
        Ok(Self {
            mode,
            system_generation,
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

    pub const fn system_generation(&self) -> u64 {
        self.system_generation
    }

    pub fn prepare(
        &mut self,
        request: IsolationLaunchRequest,
    ) -> Result<PreparedIsolationLaunch, IsolationLaunchError> {
        if request.system_generation != self.system_generation {
            return Err(IsolationLaunchError::InvalidSystemGeneration);
        }
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
                system_generation: request.system_generation,
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
            system_generation: record.system_generation,
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

    const SYSTEM_GENERATION: u64 = 108;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum BackendError {
        Unavailable,
        Revoke,
    }

    struct DualBackend {
        native_launches: usize,
        microvm_launches: usize,
        failure: Option<IsolationUnavailableReason>,
        revoke_fails: bool,
    }

    impl IsolationServiceBackend for DualBackend {
        type Endpoint = u64;
        type Error = BackendError;

        fn launch_native_service(
            &mut self,
            spec: IsolationServiceSpec,
        ) -> Result<Self::Endpoint, IsolationBackendFailure<Self::Error>> {
            self.native_launches += 1;
            if let Some(reason) = self.failure {
                Err(IsolationBackendFailure::new(
                    reason,
                    BackendError::Unavailable,
                ))
            } else {
                Ok(0x1000 | spec.provider_generation())
            }
        }

        fn launch_microvm_service(
            &mut self,
            spec: IsolationServiceSpec,
        ) -> Result<Self::Endpoint, IsolationBackendFailure<Self::Error>> {
            self.microvm_launches += 1;
            if let Some(reason) = self.failure {
                Err(IsolationBackendFailure::new(
                    reason,
                    BackendError::Unavailable,
                ))
            } else {
                Ok(0x2000 | spec.provider_generation())
            }
        }

        fn revoke(&mut self, _endpoint: &Self::Endpoint) -> Result<(), Self::Error> {
            if self.revoke_fails {
                Err(BackendError::Revoke)
            } else {
                Ok(())
            }
        }
    }

    fn backend() -> DualBackend {
        DualBackend {
            native_launches: 0,
            microvm_launches: 0,
            failure: None,
            revoke_fails: false,
        }
    }

    fn service_spec(placement: IsolationPlacement) -> IsolationServiceSpec {
        IsolationServiceSpec::new(
            ObjectId(0x43),
            ObjectId(0x434f_4e46_4947),
            1,
            9,
            SYSTEM_GENERATION,
            7,
            TotalMicrovmClass::MicrovmEligible,
            placement,
        )
        .unwrap()
    }

    fn request(
        object: u64,
        class: TotalMicrovmClass,
        placement: IsolationPlacement,
    ) -> IsolationLaunchRequest {
        IsolationLaunchRequest::new(ObjectId(object), SYSTEM_GENERATION, 7, class, placement)
            .unwrap()
    }

    #[test]
    fn total_mode_admits_only_backend_confirmed_eligible_microvms() {
        let mut table =
            IsolationAdmissionTable::<2>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 7)
                .unwrap();
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
        let mut table =
            IsolationAdmissionTable::<2>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 7)
                .unwrap();
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
        let mut table =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 7)
                .unwrap();
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
        assert_eq!(retained.system_generation(), SYSTEM_GENERATION);
        assert_eq!(retained.policy_generation(), 7);
        assert_eq!(retained.sequence(), 1);
        assert_eq!(retained.class(), TotalMicrovmClass::MicrovmEligible);
        assert_eq!(retained.requested_placement(), IsolationPlacement::Microvm);
        assert_eq!(table.total_microvm_report().unavailable_microvm_eligible, 1);
    }

    #[test]
    fn explicit_substrate_reason_is_not_counted_as_fallback() {
        let mut table =
            IsolationAdmissionTable::<2>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 7)
                .unwrap();
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
    fn stale_system_or_policy_generation_and_capacity_fail_closed() {
        let mut table =
            IsolationAdmissionTable::<1>::new(IsolationMode::Balanced, SYSTEM_GENERATION, 7)
                .unwrap();
        let stale_system = IsolationLaunchRequest::new(
            ObjectId(1),
            SYSTEM_GENERATION - 1,
            7,
            TotalMicrovmClass::MicrovmEligible,
            IsolationPlacement::NativeProcess,
        )
        .unwrap();
        assert_eq!(
            table.prepare(stale_system),
            Err(IsolationLaunchError::InvalidSystemGeneration)
        );
        let stale_policy = IsolationLaunchRequest::new(
            ObjectId(1),
            SYSTEM_GENERATION,
            8,
            TotalMicrovmClass::MicrovmEligible,
            IsolationPlacement::NativeProcess,
        )
        .unwrap();
        assert_eq!(
            table.prepare(stale_policy),
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
        let mut table =
            IsolationAdmissionTable::<2>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 7)
                .unwrap();
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

    #[test]
    fn balanced_service_routes_both_placements_under_one_interface_binding() {
        let mut native_table =
            IsolationAdmissionTable::<1>::new(IsolationMode::Balanced, SYSTEM_GENERATION, 7)
                .unwrap();
        let mut native_backend = backend();
        let native = route_isolation_service(
            &mut native_table,
            &mut native_backend,
            service_spec(IsolationPlacement::NativeService),
        )
        .unwrap();
        let mut microvm_table =
            IsolationAdmissionTable::<1>::new(IsolationMode::Balanced, SYSTEM_GENERATION, 7)
                .unwrap();
        let mut microvm_backend = backend();
        let microvm = route_isolation_service(
            &mut microvm_table,
            &mut microvm_backend,
            service_spec(IsolationPlacement::Microvm),
        )
        .unwrap();
        assert_eq!(native.interface(), microvm.interface());
        assert_eq!(
            native.interface_generation(),
            microvm.interface_generation()
        );
        assert_eq!(native.provider_generation(), microvm.provider_generation());
        assert_eq!(native.placement(), IsolationPlacement::NativeService);
        assert_eq!(microvm.placement(), IsolationPlacement::Microvm);
        assert_eq!(
            (
                native_backend.native_launches,
                native_backend.microvm_launches
            ),
            (1, 0)
        );
        assert_eq!(
            (
                microvm_backend.native_launches,
                microvm_backend.microvm_launches
            ),
            (0, 1)
        );
    }

    #[test]
    fn prepared_service_route_spans_construction_without_losing_binding_identity() {
        let mut table =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 7)
                .unwrap();
        let spec = service_spec(IsolationPlacement::Microvm);
        let prepared = prepare_isolation_service_route(&mut table, spec).unwrap();
        assert_eq!(prepared.spec(), spec);
        assert_eq!(table.running().count(), 0);
        let routed = prepared.commit(&mut table, 0x55aa_u64).unwrap();
        assert_eq!(routed.endpoint(), &0x55aa);
        assert_eq!(routed.interface(), spec.interface());
        assert_eq!(routed.interface_generation(), spec.interface_generation());
        assert_eq!(routed.provider_generation(), spec.provider_generation());
        assert_eq!(routed.system_generation(), SYSTEM_GENERATION);
        assert_eq!(routed.placement(), IsolationPlacement::Microvm);
        assert!(table.total_microvm_report().satisfied());
    }

    #[test]
    fn component_launch_retains_exact_two_artifact_route_until_commit() {
        let mut table =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 7)
                .unwrap();
        let spec = service_spec(IsolationPlacement::Microvm);
        let route = prepare_isolation_service_route(&mut table, spec).unwrap();
        let launch = PreparedComponentServiceLaunch::bind(
            route,
            spec.interface(),
            spec.interface_generation(),
            spec.provider_generation(),
            spec.system_generation(),
            [0x3a; 32],
            [0x18; 64],
            [0x2f; 64],
        )
        .unwrap();
        assert_eq!(launch.spec(), spec);
        assert_eq!(launch.interface_fingerprint(), &[0x3a; 32]);
        assert_eq!(launch.consumer_artifact(), &[0x18; 64]);
        assert_eq!(launch.provider_artifact(), &[0x2f; 64]);
        assert_eq!(
            launch.verify_artifacts(
                ArtifactKind::ServiceImage,
                &[0x18; 64],
                ArtifactKind::ServiceImage,
                &[0x2f; 64],
            ),
            Ok(())
        );
        assert_eq!(
            launch.verify_artifacts(
                ArtifactKind::Kernel,
                &[0x18; 64],
                ArtifactKind::ServiceImage,
                &[0x2f; 64],
            ),
            Err(ComponentServiceArtifactError::InvalidArtifactKind)
        );
        assert_eq!(
            launch.verify_artifacts(
                ArtifactKind::ServiceImage,
                &[0x19; 64],
                ArtifactKind::ServiceImage,
                &[0x2f; 64],
            ),
            Err(ComponentServiceArtifactError::ConsumerArtifactMismatch)
        );
        assert_eq!(
            launch.verify_artifacts(
                ArtifactKind::ServiceImage,
                &[0x18; 64],
                ArtifactKind::ServiceImage,
                &[0x30; 64],
            ),
            Err(ComponentServiceArtifactError::ProviderArtifactMismatch)
        );
        assert_eq!(table.running().count(), 0);
        launch.into_route().commit(&mut table, 0x55aa_u64).unwrap();
        assert!(table.total_microvm_report().satisfied());
    }

    #[test]
    fn artifact_bound_component_launch_invokes_only_selected_backend() {
        let mut table =
            IsolationAdmissionTable::<1>::new(IsolationMode::Balanced, SYSTEM_GENERATION, 7)
                .unwrap();
        let spec = service_spec(IsolationPlacement::NativeService);
        let route = prepare_isolation_service_route(&mut table, spec).unwrap();
        let launch = PreparedComponentServiceLaunch::bind(
            route,
            spec.interface(),
            spec.interface_generation(),
            spec.provider_generation(),
            spec.system_generation(),
            [0x3a; 32],
            [0x18; 64],
            [0x2f; 64],
        )
        .unwrap();
        let mut backend = backend();
        let routed = launch_prepared_component_service(
            &mut table,
            &mut backend,
            launch,
            ArtifactKind::ServiceImage,
            &[0x18; 64],
            ArtifactKind::ServiceImage,
            &[0x2f; 64],
        )
        .unwrap();
        assert_eq!(routed.placement(), IsolationPlacement::NativeService);
        assert_eq!((backend.native_launches, backend.microvm_launches), (1, 0));
    }

    #[test]
    fn artifact_mismatch_returns_complete_uncommitted_launch() {
        let mut table =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 7)
                .unwrap();
        let spec = service_spec(IsolationPlacement::Microvm);
        let route = prepare_isolation_service_route(&mut table, spec).unwrap();
        let launch = PreparedComponentServiceLaunch::bind(
            route,
            spec.interface(),
            spec.interface_generation(),
            spec.provider_generation(),
            spec.system_generation(),
            [0x3a; 32],
            [0x18; 64],
            [0x2f; 64],
        )
        .unwrap();
        let mut backend = backend();
        let error = launch_prepared_component_service(
            &mut table,
            &mut backend,
            launch,
            ArtifactKind::ServiceImage,
            &[0x18; 64],
            ArtifactKind::ServiceImage,
            &[0x30; 64],
        )
        .unwrap_err();
        let PreparedComponentServiceRouteError::Artifact { launch, error } = error else {
            panic!("artifact mismatch must precede backend launch");
        };
        assert_eq!(
            error,
            ComponentServiceArtifactError::ProviderArtifactMismatch
        );
        assert_eq!(launch.spec(), spec);
        assert_eq!((backend.native_launches, backend.microvm_launches), (0, 0));
        assert_eq!(table.running().count(), 0);
        launch.into_route().cancel(&mut table).unwrap();
    }

    #[test]
    fn failed_component_construction_records_unavailable_without_native_fallback() {
        let mut table =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 7)
                .unwrap();
        let spec = service_spec(IsolationPlacement::Microvm);
        let route = prepare_isolation_service_route(&mut table, spec).unwrap();
        let launch = PreparedComponentServiceLaunch::bind(
            route,
            spec.interface(),
            spec.interface_generation(),
            spec.provider_generation(),
            spec.system_generation(),
            [0x3a; 32],
            [0x18; 64],
            [0x2f; 64],
        )
        .unwrap();
        launch
            .unavailable(&mut table, IsolationUnavailableReason::VmmResource)
            .unwrap();
        assert_eq!(table.running().count(), 0);
        let unavailable = table.unavailable_domains().next().unwrap();
        assert_eq!(unavailable.domain(), spec.domain());
        assert_eq!(
            unavailable.reason(),
            IsolationUnavailableReason::VmmResource
        );
        let report = table.total_microvm_report();
        assert_eq!(report.running_microvm_eligible, 0);
        assert_eq!(report.native_fallback, 0);
        assert_eq!(report.unavailable_microvm_eligible, 1);
    }

    #[test]
    fn exhausted_vcpu_budget_consumes_total_route_without_native_fallback() {
        let mut admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 7)
                .unwrap();
        let spec = service_spec(IsolationPlacement::Microvm);
        let route = prepare_isolation_service_route(&mut admission, spec).unwrap();
        let mut capabilities = CapabilitySpace::<1>::new();
        let mut budgets = CpuBudgetTable::<1, 1>::new(3).unwrap();
        let budget_spec = crate::CpuBudgetSpec::new(1, 5_000, 10_000, 7, 1).unwrap();
        let (budget, capability) = budgets.create_root(budget_spec, &mut capabilities).unwrap();
        budgets
            .reserve_vcpus(budget, capability, ObjectId(0x99), 1, &capabilities)
            .unwrap();

        assert_eq!(
            reserve_isolation_vcpus(
                route,
                &mut admission,
                &mut budgets,
                budget,
                capability,
                1,
                &capabilities,
            ),
            Err(IsolationVcpuReservationError::Cpu(
                CpuResourceError::ParallelismExhausted
            ))
        );
        let unavailable = admission.unavailable_domains().next().unwrap();
        assert_eq!(unavailable.domain(), spec.domain());
        assert_eq!(unavailable.reason(), IsolationUnavailableReason::VcpuBudget);
        let report = admission.total_microvm_report();
        assert_eq!(report.running_microvm_eligible, 0);
        assert_eq!(report.native_fallback, 0);
        assert_eq!(report.unavailable_microvm_eligible, 1);
    }

    #[test]
    fn component_launch_substitution_returns_uncommitted_route_for_failure_handling() {
        for expected in [
            ComponentServiceLaunchError::RouteIdentityMismatch,
            ComponentServiceLaunchError::SystemGenerationMismatch,
            ComponentServiceLaunchError::InvalidInterfaceFingerprint,
            ComponentServiceLaunchError::InvalidArtifactDigest,
            ComponentServiceLaunchError::ArtifactSubstitution,
        ] {
            let mut table = IsolationAdmissionTable::<1>::new(
                IsolationMode::TotalMicrovm,
                SYSTEM_GENERATION,
                7,
            )
            .unwrap();
            let spec = service_spec(IsolationPlacement::Microvm);
            let route = prepare_isolation_service_route(&mut table, spec).unwrap();
            let (interface, system_generation, fingerprint, consumer, provider) = match expected {
                ComponentServiceLaunchError::RouteIdentityMismatch => (
                    ObjectId(spec.interface().0 + 1),
                    spec.system_generation(),
                    [0x3a; 32],
                    [0x18; 64],
                    [0x2f; 64],
                ),
                ComponentServiceLaunchError::SystemGenerationMismatch => (
                    spec.interface(),
                    spec.system_generation() - 1,
                    [0x3a; 32],
                    [0x18; 64],
                    [0x2f; 64],
                ),
                ComponentServiceLaunchError::InvalidInterfaceFingerprint => (
                    spec.interface(),
                    spec.system_generation(),
                    [0; 32],
                    [0x18; 64],
                    [0x2f; 64],
                ),
                ComponentServiceLaunchError::InvalidArtifactDigest => (
                    spec.interface(),
                    spec.system_generation(),
                    [0x3a; 32],
                    [0; 64],
                    [0x2f; 64],
                ),
                ComponentServiceLaunchError::ArtifactSubstitution => (
                    spec.interface(),
                    spec.system_generation(),
                    [0x3a; 32],
                    [0x2f; 64],
                    [0x2f; 64],
                ),
            };
            let (route, error) = PreparedComponentServiceLaunch::bind(
                route,
                interface,
                spec.interface_generation(),
                spec.provider_generation(),
                system_generation,
                fingerprint,
                consumer,
                provider,
            )
            .unwrap_err();
            assert_eq!(error, expected);
            assert_eq!(table.running().count(), 0);
            route
                .unavailable(&mut table, IsolationUnavailableReason::InterfaceTransport)
                .unwrap();
            assert_eq!(table.running().count(), 0);
            assert_eq!(table.unavailable_domains().count(), 1);
            assert!(table.total_microvm_report().satisfied());
        }
    }

    #[test]
    fn total_service_rejects_native_before_backend_and_never_falls_back() {
        let mut table =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 7)
                .unwrap();
        let mut backend = backend();
        assert_eq!(
            route_isolation_service(
                &mut table,
                &mut backend,
                service_spec(IsolationPlacement::NativeService),
            ),
            Err(IsolationServiceRouteError::Admission(
                IsolationLaunchError::TotalMicrovmDowngradeAttempt
            ))
        );
        assert_eq!((backend.native_launches, backend.microvm_launches), (0, 0));

        backend.failure = Some(IsolationUnavailableReason::InterfaceTransport);
        assert_eq!(
            route_isolation_service(
                &mut table,
                &mut backend,
                service_spec(IsolationPlacement::Microvm),
            ),
            Err(IsolationServiceRouteError::Backend {
                reason: IsolationUnavailableReason::InterfaceTransport,
                error: BackendError::Unavailable,
            })
        );
        assert_eq!((backend.native_launches, backend.microvm_launches), (0, 1));
        assert_eq!(table.running().count(), 0);
        assert_eq!(table.unavailable_domains().count(), 1);
        assert!(table.total_microvm_report().satisfied());
    }

    #[test]
    fn service_spec_rejects_unversioned_or_non_service_routes() {
        assert!(matches!(
            IsolationServiceSpec::new(
                ObjectId(1),
                ObjectId(2),
                0,
                1,
                SYSTEM_GENERATION,
                7,
                TotalMicrovmClass::MicrovmEligible,
                IsolationPlacement::Microvm,
            ),
            Err(IsolationServiceSpecError::InvalidGeneration)
        ));
        assert!(matches!(
            IsolationServiceSpec::new(
                ObjectId(1),
                ObjectId(2),
                1,
                1,
                SYSTEM_GENERATION,
                7,
                TotalMicrovmClass::MicrovmEligible,
                IsolationPlacement::NativeProcess,
            ),
            Err(IsolationServiceSpecError::UnsupportedPlacement)
        ));
    }
}
