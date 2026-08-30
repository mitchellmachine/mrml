use core::array;
use mrml_package_format::{
    ActivatedSystemGeneration, ComponentServiceLaunchHandoff, ComponentServiceLaunchHandoffError,
    ComponentServicePlacement,
};

use crate::{
    ArtifactKind, Capability, CapabilityError, CapabilitySpace, CpuBudgetId, CpuBudgetTable,
    CpuResourceError, MemoryBackingKind, MemoryBackingOperationError, MemoryMappingBackend,
    MemoryMappingId, MemoryMappingOperationError, MemoryMappingPair,
    MemoryMappingPairOperationError, MemoryMappingPairRemovalError, MemoryMappingPairRemovalState,
    MemoryMappingRevocationBackend, MemoryObjectBackingBackend, MemoryObjectId,
    MemoryPhysicalBacking, MemoryPoolId, MemoryPoolTable, MemoryResourceError, ObjectId, PAGE_SIZE,
    Rights, TaskId, TaskRuntime, TaskRuntimeError, VcpuReservationId, arch::x86_64::UserContext,
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
    NativeProcessResource,
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
pub struct IsolationApplicationSpec {
    domain: ObjectId,
    application: ObjectId,
    application_generation: u64,
    application_artifact: [u8; 64],
    system_generation: u64,
    policy_generation: u64,
    placement: IsolationPlacement,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsolationApplicationSpecError {
    InvalidGeneration,
    InvalidArtifactDigest,
    UnsupportedPlacement,
}

impl IsolationApplicationSpec {
    pub fn new(
        domain: ObjectId,
        application: ObjectId,
        application_generation: u64,
        application_artifact: [u8; 64],
        system_generation: u64,
        policy_generation: u64,
        placement: IsolationPlacement,
    ) -> Result<Self, IsolationApplicationSpecError> {
        if application_generation == 0 || system_generation == 0 || policy_generation == 0 {
            return Err(IsolationApplicationSpecError::InvalidGeneration);
        }
        if application_artifact == [0; 64] {
            return Err(IsolationApplicationSpecError::InvalidArtifactDigest);
        }
        if !matches!(
            placement,
            IsolationPlacement::NativeProcess | IsolationPlacement::Microvm
        ) {
            return Err(IsolationApplicationSpecError::UnsupportedPlacement);
        }
        Ok(Self {
            domain,
            application,
            application_generation,
            application_artifact,
            system_generation,
            policy_generation,
            placement,
        })
    }

    pub const fn domain(self) -> ObjectId {
        self.domain
    }
    pub const fn application(self) -> ObjectId {
        self.application
    }
    pub const fn application_generation(self) -> u64 {
        self.application_generation
    }
    pub const fn application_artifact(self) -> [u8; 64] {
        self.application_artifact
    }
    pub const fn system_generation(self) -> u64 {
        self.system_generation
    }
    pub const fn policy_generation(self) -> u64 {
        self.policy_generation
    }
    pub const fn placement(self) -> IsolationPlacement {
        self.placement
    }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentServiceLaunchAttachment {
    domain: ObjectId,
    system_generation: u64,
    policy_generation: u64,
    association_generation: u64,
    launch_data_object: ObjectId,
    launch_data_generation: u64,
    launch_data_bytes: u32,
    launch_data: Capability,
    dependency_endpoint_object: ObjectId,
    dependency_endpoint_generation: u64,
    dependency_endpoint: Capability,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentServiceLaunchAttachmentError {
    InvalidIdentity,
    InvalidGeneration,
    InvalidLength,
    Capability(CapabilityError),
    WrongLaunchDataObject,
    WrongDependencyEndpoint,
}

impl ComponentServiceLaunchAttachment {
    #[allow(clippy::too_many_arguments)]
    pub fn new<const C: usize>(
        spec: IsolationServiceSpec,
        association_generation: u64,
        launch_data_object: ObjectId,
        launch_data_generation: u64,
        launch_data_bytes: u32,
        launch_data: Capability,
        dependency_endpoint_object: ObjectId,
        dependency_endpoint_generation: u64,
        dependency_endpoint: Capability,
        capabilities: &CapabilitySpace<C>,
    ) -> Result<Self, ComponentServiceLaunchAttachmentError> {
        if launch_data_object.0 == 0
            || dependency_endpoint_object.0 == 0
            || launch_data_object == dependency_endpoint_object
        {
            return Err(ComponentServiceLaunchAttachmentError::InvalidIdentity);
        }
        if association_generation == 0
            || launch_data_generation == 0
            || dependency_endpoint_generation == 0
        {
            return Err(ComponentServiceLaunchAttachmentError::InvalidGeneration);
        }
        if launch_data_bytes == 0 || launch_data_bytes > 4096 {
            return Err(ComponentServiceLaunchAttachmentError::InvalidLength);
        }
        let actual_data = capabilities
            .authorize_exact(launch_data, Rights::READ.union(Rights::DELEGATE))
            .map_err(ComponentServiceLaunchAttachmentError::Capability)?;
        if actual_data != launch_data_object {
            return Err(ComponentServiceLaunchAttachmentError::WrongLaunchDataObject);
        }
        let actual_endpoint = capabilities
            .authorize_exact(dependency_endpoint, Rights::SIGNAL.union(Rights::DELEGATE))
            .map_err(ComponentServiceLaunchAttachmentError::Capability)?;
        if actual_endpoint != dependency_endpoint_object {
            return Err(ComponentServiceLaunchAttachmentError::WrongDependencyEndpoint);
        }
        Ok(Self {
            domain: spec.domain(),
            system_generation: spec.system_generation(),
            policy_generation: spec.policy_generation(),
            association_generation,
            launch_data_object,
            launch_data_generation,
            launch_data_bytes,
            launch_data,
            dependency_endpoint_object,
            dependency_endpoint_generation,
            dependency_endpoint,
        })
    }

    pub const fn domain(self) -> ObjectId {
        self.domain
    }
    pub const fn system_generation(self) -> u64 {
        self.system_generation
    }
    pub const fn policy_generation(self) -> u64 {
        self.policy_generation
    }
    pub const fn association_generation(self) -> u64 {
        self.association_generation
    }
    pub const fn launch_data_object(self) -> ObjectId {
        self.launch_data_object
    }
    pub const fn launch_data_generation(self) -> u64 {
        self.launch_data_generation
    }
    pub const fn launch_data_bytes(self) -> u32 {
        self.launch_data_bytes
    }
    pub const fn launch_data(self) -> Capability {
        self.launch_data
    }
    pub const fn dependency_endpoint_object(self) -> ObjectId {
        self.dependency_endpoint_object
    }
    pub const fn dependency_endpoint_generation(self) -> u64 {
        self.dependency_endpoint_generation
    }
    pub const fn dependency_endpoint(self) -> Capability {
        self.dependency_endpoint
    }

    fn matches(self, spec: IsolationServiceSpec) -> bool {
        self.domain == spec.domain()
            && self.system_generation == spec.system_generation()
            && self.policy_generation == spec.policy_generation()
    }
}

/// Direction-scoped shared memory used by a component to receive data from a
/// dependency service.
///
/// The local capability can only read the completed transfer. The distinct
/// transfer capability can only be delegated with write authority to the
/// exact generational provider task. Both capabilities must name the same
/// object, but their separate generations prevent either token from silently
/// acquiring the other's role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentServiceReadTransferAttachment {
    provider_task: TaskId,
    shared_object: ObjectId,
    shared_generation: u64,
    shared_bytes: u32,
    local_read: Capability,
    provider_write: Capability,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentServiceReadTransferAttachmentError {
    InvalidIdentity,
    InvalidGeneration,
    InvalidLength,
    LocalReadCapability(CapabilityError),
    WrongLocalReadObject,
    ProviderWriteCapability(CapabilityError),
    WrongProviderWriteObject,
    CapabilityAlias,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentServiceReadTransferPreparationError {
    InvalidProvider,
    Root(TaskRuntimeError),
    Attachment(ComponentServiceReadTransferAttachmentError),
    Rollback {
        attachment: ComponentServiceReadTransferAttachmentError,
        cleanup: TaskRuntimeError,
    },
}

const COMPONENT_SERVICE_READ_TRANSFER_ROOT_RIGHTS: Rights = Rights::MAP
    .union(Rights::READ)
    .union(Rights::WRITE)
    .union(Rights::PIN)
    .union(Rights::CONTROL)
    .union(Rights::DELEGATE);

/// One charged shared page and its exact construction authority.
///
/// Physical backing and mappings remain absent until a privileged backend
/// consumes this root. The typed memory-object identity keeps accounting and
/// teardown bound to the same table generation as the capability authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentServiceReadTransferMemoryRoot {
    memory_object: MemoryObjectId,
    shared_object: ObjectId,
    root: Capability,
}

impl ComponentServiceReadTransferMemoryRoot {
    pub const fn memory_object(self) -> MemoryObjectId {
        self.memory_object
    }

    pub const fn shared_object(self) -> ObjectId {
        self.shared_object
    }

    pub const fn generation(self) -> u64 {
        self.memory_object.generation() as u64
    }

    pub const fn bytes(self) -> u32 {
        PAGE_SIZE as u32
    }

    pub const fn root(self) -> Capability {
        self.root
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentServiceReadTransferMemoryError {
    Runtime(TaskRuntimeError),
    Memory(MemoryResourceError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentServiceReadTransferBackingError<E> {
    Runtime(TaskRuntimeError),
    Backing(MemoryBackingOperationError<E>),
}

const COMPONENT_SERVICE_READ_TRANSFER_TARGET_RIGHTS: Rights = Rights::MAP.union(Rights::CONTROL);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentServiceReadTransferMappings {
    memory_object: MemoryObjectId,
    shared_object: ObjectId,
    mappings: MemoryMappingPair,
    local_target: ObjectId,
    provider_target: ObjectId,
    local_target_capability: Capability,
    provider_target_capability: Capability,
    local_virtual_page: u64,
    provider_virtual_page: u64,
}

impl ComponentServiceReadTransferMappings {
    pub const fn memory_object(self) -> MemoryObjectId {
        self.memory_object
    }

    pub const fn shared_object(self) -> ObjectId {
        self.shared_object
    }

    pub const fn mappings(self) -> MemoryMappingPair {
        self.mappings
    }

    pub const fn local_target(self) -> ObjectId {
        self.local_target
    }

    pub const fn provider_target(self) -> ObjectId {
        self.provider_target
    }

    pub const fn local_target_capability(self) -> Capability {
        self.local_target_capability
    }

    pub const fn provider_target_capability(self) -> Capability {
        self.provider_target_capability
    }

    pub const fn local_virtual_page(self) -> u64 {
        self.local_virtual_page
    }

    pub const fn provider_virtual_page(self) -> u64 {
        self.provider_virtual_page
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentServiceReadTransferMappingError<F, S> {
    Runtime(TaskRuntimeError),
    Target(CapabilityError),
    TargetAlias,
    Mapping(MemoryMappingPairOperationError<F, S>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentServiceReadTransferLocalMapping {
    memory_object: MemoryObjectId,
    shared_object: ObjectId,
    mapping: MemoryMappingId,
    local_target: ObjectId,
    local_target_capability: Capability,
    local_virtual_page: u64,
}

impl ComponentServiceReadTransferLocalMapping {
    pub const fn memory_object(self) -> MemoryObjectId {
        self.memory_object
    }
    pub const fn shared_object(self) -> ObjectId {
        self.shared_object
    }
    pub const fn mapping(self) -> MemoryMappingId {
        self.mapping
    }
    pub const fn local_target(self) -> ObjectId {
        self.local_target
    }
    pub const fn local_target_capability(self) -> Capability {
        self.local_target_capability
    }
    pub const fn local_virtual_page(self) -> u64 {
        self.local_virtual_page
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentServiceReadTransferLocalMappingError<E> {
    Runtime(TaskRuntimeError),
    Target(CapabilityError),
    Mapping(MemoryMappingOperationError<E>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentServiceReadTransferCopyTaskBinding {
    mapping: ComponentServiceReadTransferLocalMapping,
    local_task: TaskId,
    provider_task: TaskId,
}

impl ComponentServiceReadTransferCopyTaskBinding {
    pub const fn mapping(self) -> ComponentServiceReadTransferLocalMapping {
        self.mapping
    }
    pub const fn local_task(self) -> TaskId {
        self.local_task
    }
    pub const fn provider_task(self) -> TaskId {
        self.provider_task
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentServiceReadTransferTaskBinding {
    mappings: ComponentServiceReadTransferMappings,
    local_task: TaskId,
    provider_task: TaskId,
}

impl ComponentServiceReadTransferTaskBinding {
    pub const fn mappings(self) -> ComponentServiceReadTransferMappings {
        self.mappings
    }

    pub const fn local_task(self) -> TaskId {
        self.local_task
    }

    pub const fn provider_task(self) -> TaskId {
        self.provider_task
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentServiceReadTransferTaskBindingError {
    Runtime(TaskRuntimeError),
    TaskAlias,
}

/// Installs only the consumer's backed read-only mapping. Provider writes use
/// the distinct kernel-mediated copy projection and never request a write-only
/// page-table mapping.
#[allow(clippy::too_many_arguments)]
pub fn install_component_service_read_transfer_local_mapping<
    B: MemoryMappingBackend,
    const POOLS: usize,
    const OBJECTS: usize,
    const MAPPINGS: usize,
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    memory: &mut MemoryPoolTable<POOLS, OBJECTS, MAPPINGS>,
    reservation: ComponentServiceReadTransferMemoryRoot,
    local_target_capability: Capability,
    local_virtual_page: u64,
    backend: &mut B,
    runtime: &TaskRuntime<TASKS, CAPABILITIES>,
    source_task: TaskId,
) -> Result<
    ComponentServiceReadTransferLocalMapping,
    ComponentServiceReadTransferLocalMappingError<B::Error>,
> {
    let capabilities = runtime
        .capabilities(source_task)
        .map_err(ComponentServiceReadTransferLocalMappingError::Runtime)?;
    let local_target = capabilities
        .authorize_exact(
            local_target_capability,
            COMPONENT_SERVICE_READ_TRANSFER_TARGET_RIGHTS,
        )
        .map_err(ComponentServiceReadTransferLocalMappingError::Target)?;
    let mapping = memory
        .install_backed_mapping(
            reservation.memory_object(),
            reservation.root(),
            local_target_capability,
            local_virtual_page,
            0,
            1,
            Rights::READ,
            capabilities,
            backend,
        )
        .map_err(ComponentServiceReadTransferLocalMappingError::Mapping)?;
    Ok(ComponentServiceReadTransferLocalMapping {
        memory_object: reservation.memory_object(),
        shared_object: reservation.shared_object(),
        mapping,
        local_target,
        local_target_capability,
        local_virtual_page,
    })
}

pub fn bind_component_service_read_transfer_copy_tasks<
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    mapping: ComponentServiceReadTransferLocalMapping,
    local_task: TaskId,
    provider_task: TaskId,
    runtime: &TaskRuntime<TASKS, CAPABILITIES>,
) -> Result<ComponentServiceReadTransferCopyTaskBinding, ComponentServiceReadTransferTaskBindingError>
{
    if local_task == provider_task {
        return Err(ComponentServiceReadTransferTaskBindingError::TaskAlias);
    }
    runtime
        .context(local_task)
        .map_err(ComponentServiceReadTransferTaskBindingError::Runtime)?;
    runtime
        .context(provider_task)
        .map_err(ComponentServiceReadTransferTaskBindingError::Runtime)?;
    Ok(ComponentServiceReadTransferCopyTaskBinding {
        mapping,
        local_task,
        provider_task,
    })
}

/// Charges one exact shared page into the source task before backing, mapping,
/// or provider construction can begin.
pub fn reserve_component_service_read_transfer_memory<
    const POOLS: usize,
    const OBJECTS: usize,
    const MAPPINGS: usize,
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    memory: &mut MemoryPoolTable<POOLS, OBJECTS, MAPPINGS>,
    pool: MemoryPoolId,
    pool_capability: Capability,
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    source_task: TaskId,
) -> Result<ComponentServiceReadTransferMemoryRoot, ComponentServiceReadTransferMemoryError> {
    let capabilities = runtime
        .capabilities_mut(source_task)
        .map_err(ComponentServiceReadTransferMemoryError::Runtime)?;
    let (memory_object, root) = memory
        .allocate_object(
            pool,
            pool_capability,
            1,
            MemoryBackingKind::Shared,
            COMPONENT_SERVICE_READ_TRANSFER_ROOT_RIGHTS,
            capabilities,
        )
        .map_err(ComponentServiceReadTransferMemoryError::Memory)?;
    let (shared_object, rights) = capabilities
        .describe(root)
        .map_err(MemoryResourceError::from)
        .map_err(ComponentServiceReadTransferMemoryError::Memory)?;
    debug_assert_eq!(rights, COMPONENT_SERVICE_READ_TRANSFER_ROOT_RIGHTS);
    Ok(ComponentServiceReadTransferMemoryRoot {
        memory_object,
        shared_object,
        root,
    })
}

/// Claims and zeroes the exact one-page physical run for a charged transfer
/// root. Backend failure leaves the memory object unbacked and retryable.
pub fn bind_component_service_read_transfer_backing<
    B: MemoryObjectBackingBackend,
    const POOLS: usize,
    const OBJECTS: usize,
    const MAPPINGS: usize,
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    memory: &mut MemoryPoolTable<POOLS, OBJECTS, MAPPINGS>,
    reservation: ComponentServiceReadTransferMemoryRoot,
    physical: MemoryPhysicalBacking,
    runtime: &TaskRuntime<TASKS, CAPABILITIES>,
    source_task: TaskId,
    backend: &mut B,
) -> Result<(), ComponentServiceReadTransferBackingError<B::Error>> {
    let capabilities = runtime
        .capabilities(source_task)
        .map_err(ComponentServiceReadTransferBackingError::Runtime)?;
    memory
        .bind_physical_backing(
            reservation.memory_object(),
            reservation.root(),
            physical,
            capabilities,
            backend,
        )
        .map_err(ComponentServiceReadTransferBackingError::Backing)
}

/// Installs the charged page read-only into the local target and write-only
/// into the exact provider target as one rollback-aware transaction.
#[allow(clippy::too_many_arguments)]
pub fn install_component_service_read_transfer_mappings<
    F: MemoryMappingBackend,
    S: MemoryMappingBackend,
    const POOLS: usize,
    const OBJECTS: usize,
    const MAPPINGS: usize,
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    memory: &mut MemoryPoolTable<POOLS, OBJECTS, MAPPINGS>,
    reservation: ComponentServiceReadTransferMemoryRoot,
    local_target_capability: Capability,
    local_virtual_page: u64,
    local_backend: &mut F,
    provider_target_capability: Capability,
    provider_virtual_page: u64,
    provider_backend: &mut S,
    runtime: &TaskRuntime<TASKS, CAPABILITIES>,
    source_task: TaskId,
) -> Result<
    ComponentServiceReadTransferMappings,
    ComponentServiceReadTransferMappingError<F::Error, S::Error>,
> {
    let capabilities = runtime
        .capabilities(source_task)
        .map_err(ComponentServiceReadTransferMappingError::Runtime)?;
    let local_target = capabilities
        .authorize_exact(
            local_target_capability,
            COMPONENT_SERVICE_READ_TRANSFER_TARGET_RIGHTS,
        )
        .map_err(ComponentServiceReadTransferMappingError::Target)?;
    let provider_target = capabilities
        .authorize_exact(
            provider_target_capability,
            COMPONENT_SERVICE_READ_TRANSFER_TARGET_RIGHTS,
        )
        .map_err(ComponentServiceReadTransferMappingError::Target)?;
    if local_target == provider_target {
        return Err(ComponentServiceReadTransferMappingError::TargetAlias);
    }
    let mappings = memory
        .install_backed_mapping_pair(
            reservation.memory_object(),
            reservation.root(),
            local_target_capability,
            local_virtual_page,
            Rights::READ,
            local_backend,
            provider_target_capability,
            provider_virtual_page,
            Rights::WRITE,
            provider_backend,
            capabilities,
        )
        .map_err(ComponentServiceReadTransferMappingError::Mapping)?;
    Ok(ComponentServiceReadTransferMappings {
        memory_object: reservation.memory_object(),
        shared_object: reservation.shared_object(),
        mappings,
        local_target,
        provider_target,
        local_target_capability,
        provider_target_capability,
        local_virtual_page,
        provider_virtual_page,
    })
}

/// Associates the two already authorized mapping targets with exact live task
/// generations. Task names identify the consumers; the mapping capabilities
/// checked during installation remain the authority for their address spaces.
pub fn bind_component_service_read_transfer_tasks<const TASKS: usize, const CAPABILITIES: usize>(
    mappings: ComponentServiceReadTransferMappings,
    local_task: TaskId,
    provider_task: TaskId,
    runtime: &TaskRuntime<TASKS, CAPABILITIES>,
) -> Result<ComponentServiceReadTransferTaskBinding, ComponentServiceReadTransferTaskBindingError> {
    if local_task == provider_task {
        return Err(ComponentServiceReadTransferTaskBindingError::TaskAlias);
    }
    runtime
        .context(local_task)
        .map_err(ComponentServiceReadTransferTaskBindingError::Runtime)?;
    runtime
        .context(provider_task)
        .map_err(ComponentServiceReadTransferTaskBindingError::Runtime)?;
    Ok(ComponentServiceReadTransferTaskBinding {
        mappings,
        local_task,
        provider_task,
    })
}

impl ComponentServiceReadTransferAttachment {
    pub fn new<const C: usize>(
        provider_task: TaskId,
        shared_object: ObjectId,
        shared_generation: u64,
        shared_bytes: u32,
        local_read: Capability,
        provider_write: Capability,
        capabilities: &CapabilitySpace<C>,
    ) -> Result<Self, ComponentServiceReadTransferAttachmentError> {
        if shared_object.0 == 0 {
            return Err(ComponentServiceReadTransferAttachmentError::InvalidIdentity);
        }
        if shared_generation == 0 {
            return Err(ComponentServiceReadTransferAttachmentError::InvalidGeneration);
        }
        if shared_bytes == 0 || shared_bytes > 4096 {
            return Err(ComponentServiceReadTransferAttachmentError::InvalidLength);
        }
        if local_read == provider_write {
            return Err(ComponentServiceReadTransferAttachmentError::CapabilityAlias);
        }
        let actual_local = capabilities
            .authorize_exact(
                local_read,
                Rights::MAP.union(Rights::READ).union(Rights::DELEGATE),
            )
            .map_err(ComponentServiceReadTransferAttachmentError::LocalReadCapability)?;
        if actual_local != shared_object {
            return Err(ComponentServiceReadTransferAttachmentError::WrongLocalReadObject);
        }
        let actual_transfer = capabilities
            .authorize_exact(
                provider_write,
                Rights::MAP.union(Rights::WRITE).union(Rights::DELEGATE),
            )
            .map_err(ComponentServiceReadTransferAttachmentError::ProviderWriteCapability)?;
        if actual_transfer != shared_object {
            return Err(ComponentServiceReadTransferAttachmentError::WrongProviderWriteObject);
        }
        Ok(Self {
            provider_task,
            shared_object,
            shared_generation,
            shared_bytes,
            local_read,
            provider_write,
        })
    }

    pub const fn provider_task(self) -> TaskId {
        self.provider_task
    }

    pub const fn shared_object(self) -> ObjectId {
        self.shared_object
    }
    pub const fn shared_generation(self) -> u64 {
        self.shared_generation
    }
    pub const fn shared_bytes(self) -> u32 {
        self.shared_bytes
    }
    pub const fn local_read(self) -> Capability {
        self.local_read
    }
    pub const fn provider_write(self) -> Capability {
        self.provider_write
    }
}

/// Splits one exact shared-memory construction root into the two tracked source
/// handles required by a dependency read path.
pub fn prepare_component_service_read_transfer_attachment<
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    source_task: TaskId,
    provider_task: TaskId,
    shared_object: ObjectId,
    shared_generation: u64,
    shared_bytes: u32,
    shared_root: Capability,
) -> Result<ComponentServiceReadTransferAttachment, ComponentServiceReadTransferPreparationError> {
    if provider_task == source_task {
        return Err(ComponentServiceReadTransferPreparationError::InvalidProvider);
    }
    runtime
        .context(provider_task)
        .map_err(ComponentServiceReadTransferPreparationError::Root)?;
    if shared_object.0 == 0 {
        return Err(ComponentServiceReadTransferPreparationError::Attachment(
            ComponentServiceReadTransferAttachmentError::InvalidIdentity,
        ));
    }
    if shared_generation == 0 {
        return Err(ComponentServiceReadTransferPreparationError::Attachment(
            ComponentServiceReadTransferAttachmentError::InvalidGeneration,
        ));
    }
    if shared_bytes == 0 || shared_bytes > 4096 {
        return Err(ComponentServiceReadTransferPreparationError::Attachment(
            ComponentServiceReadTransferAttachmentError::InvalidLength,
        ));
    }
    runtime
        .authorize_capability_exact(
            source_task,
            shared_root,
            COMPONENT_SERVICE_READ_TRANSFER_ROOT_RIGHTS,
            shared_object,
        )
        .map_err(ComponentServiceReadTransferPreparationError::Root)?;
    let local_rights = Rights::MAP.union(Rights::READ).union(Rights::DELEGATE);
    let provider_rights = Rights::MAP.union(Rights::WRITE).union(Rights::DELEGATE);
    let split = runtime
        .derive_capabilities_for_construction_source(
            source_task,
            &[(shared_root, local_rights), (shared_root, provider_rights)],
        )
        .map_err(ComponentServiceReadTransferPreparationError::Root)?;
    let mut handles = split.capabilities();
    let local_read = handles
        .next()
        .expect("two preflighted local derivations produce two handles");
    let provider_write = handles
        .next()
        .expect("two preflighted local derivations produce two handles");
    debug_assert!(handles.next().is_none());
    match ComponentServiceReadTransferAttachment::new(
        provider_task,
        shared_object,
        shared_generation,
        shared_bytes,
        local_read,
        provider_write,
        runtime
            .capabilities(source_task)
            .expect("successful local derivation preserves the source domain"),
    ) {
        Ok(attachment) => Ok(attachment),
        Err(attachment) => {
            let first = runtime.revoke_capability(source_task, local_read).err();
            let second = runtime.revoke_capability(source_task, provider_write).err();
            match first.or(second) {
                Some(cleanup) => Err(ComponentServiceReadTransferPreparationError::Rollback {
                    attachment,
                    cleanup,
                }),
                None => Err(ComponentServiceReadTransferPreparationError::Attachment(
                    attachment,
                )),
            }
        }
    }
}

/// Native-service entry state built only after the attachment capabilities have
/// been projected into the fresh target capability space.
///
/// Source attachment tokens are deliberately not exposed. Capability tokens
/// are local to one capability space, so a native placement backend must use
/// freshly derived target-space handles from its atomic domain construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeComponentServiceEntry {
    service_endpoint_object: ObjectId,
    supervisor_task_object: ObjectId,
    provider_generation: u64,
    consumer_module_object: ObjectId,
    launch_data_bytes: u32,
    launch_data: Capability,
    dependency_endpoint: Capability,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeComponentServiceEntryError {
    InvalidIdentity,
    AttachmentMismatch,
    LaunchDataCapability(CapabilityError),
    WrongLaunchDataObject,
    DependencyCapability(CapabilityError),
    WrongDependencyEndpoint,
    LaunchRegistersOccupied,
}

impl NativeComponentServiceEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new<const C: usize>(
        spec: IsolationServiceSpec,
        attachment: ComponentServiceLaunchAttachment,
        service_endpoint_object: ObjectId,
        supervisor_task_object: ObjectId,
        consumer_module_object: ObjectId,
        launch_data: Capability,
        dependency_endpoint: Capability,
        target_capabilities: &CapabilitySpace<C>,
    ) -> Result<Self, NativeComponentServiceEntryError> {
        if service_endpoint_object.0 == 0
            || supervisor_task_object.0 == 0
            || consumer_module_object.0 == 0
            || service_endpoint_object == supervisor_task_object
        {
            return Err(NativeComponentServiceEntryError::InvalidIdentity);
        }
        if !attachment.matches(spec) {
            return Err(NativeComponentServiceEntryError::AttachmentMismatch);
        }
        let actual_data = target_capabilities
            .authorize_exact(launch_data, Rights::READ)
            .map_err(NativeComponentServiceEntryError::LaunchDataCapability)?;
        if actual_data != attachment.launch_data_object() {
            return Err(NativeComponentServiceEntryError::WrongLaunchDataObject);
        }
        let actual_dependency = target_capabilities
            .authorize_exact(dependency_endpoint, Rights::SIGNAL)
            .map_err(NativeComponentServiceEntryError::DependencyCapability)?;
        if actual_dependency != attachment.dependency_endpoint_object() {
            return Err(NativeComponentServiceEntryError::WrongDependencyEndpoint);
        }
        Ok(Self {
            service_endpoint_object,
            supervisor_task_object,
            provider_generation: spec.provider_generation(),
            consumer_module_object,
            launch_data_bytes: attachment.launch_data_bytes(),
            launch_data,
            dependency_endpoint,
        })
    }

    pub const fn service_endpoint_object(self) -> ObjectId {
        self.service_endpoint_object
    }

    pub const fn supervisor_task_object(self) -> ObjectId {
        self.supervisor_task_object
    }

    pub const fn provider_generation(self) -> u64 {
        self.provider_generation
    }

    pub const fn consumer_module_object(self) -> ObjectId {
        self.consumer_module_object
    }

    pub const fn launch_data_bytes(self) -> u32 {
        self.launch_data_bytes
    }

    pub const fn launch_data(self) -> Capability {
        self.launch_data
    }

    pub const fn dependency_endpoint(self) -> Capability {
        self.dependency_endpoint
    }

    /// Installs the fixed native-service entry ABI into a fresh user context.
    /// Existing register payloads are rejected rather than overwritten.
    pub fn install(
        self,
        mut context: UserContext,
    ) -> Result<UserContext, (Self, NativeComponentServiceEntryError, UserContext)> {
        if context.r15 != 0
            || context.r14 != 0
            || context.r13 != 0
            || context.r12 != 0
            || context.r11 != 0
            || context.r10 != 0
            || context.rbx != 0
        {
            return Err((
                self,
                NativeComponentServiceEntryError::LaunchRegistersOccupied,
                context,
            ));
        }
        context.r13 = self.service_endpoint_object.0;
        context.r14 = self.supervisor_task_object.0;
        context.r12 = self.provider_generation;
        context.r15 = self.launch_data.token();
        context.rbx = self.dependency_endpoint.token();
        context.r11 = u64::from(self.launch_data_bytes);
        context.r10 = self.consumer_module_object.0;
        Ok(context)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeComponentServiceTask {
    task: TaskId,
    entry: NativeComponentServiceEntry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeComponentServiceReadTransferTask {
    source_task: TaskId,
    task: TaskId,
    entry: NativeComponentServiceEntry,
    local_read: Capability,
    provider_write: Capability,
    source_local_read: Capability,
    source_provider_write: Capability,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeComponentServiceMappedReadTransferTask {
    construction: NativeComponentServiceReadTransferTask,
    memory: ComponentServiceReadTransferMemoryRoot,
    binding: ComponentServiceReadTransferTaskBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeComponentServiceCopyReadTransferTask {
    construction: NativeComponentServiceReadTransferTask,
    memory: ComponentServiceReadTransferMemoryRoot,
    binding: ComponentServiceReadTransferCopyTaskBinding,
    page_table_root: crate::PhysAddr,
}

impl NativeComponentServiceCopyReadTransferTask {
    pub const fn construction(self) -> NativeComponentServiceReadTransferTask {
        self.construction
    }
    pub const fn memory(self) -> ComponentServiceReadTransferMemoryRoot {
        self.memory
    }
    pub const fn binding(self) -> ComponentServiceReadTransferCopyTaskBinding {
        self.binding
    }
    pub const fn page_table_root(self) -> crate::PhysAddr {
        self.page_table_root
    }

    pub fn source_attachment<const TASKS: usize, const CAPABILITIES: usize>(
        self,
        runtime: &TaskRuntime<TASKS, CAPABILITIES>,
    ) -> Result<ComponentServiceReadTransferAttachment, ComponentServiceReadTransferPreparationError>
    {
        let construction = self.construction();
        let capabilities = runtime
            .capabilities(construction.source_task())
            .map_err(ComponentServiceReadTransferPreparationError::Root)?;
        ComponentServiceReadTransferAttachment::new(
            self.binding().provider_task(),
            self.memory().shared_object(),
            self.memory().generation(),
            self.memory().bytes(),
            construction.source_local_read(),
            construction.source_provider_write(),
            capabilities,
        )
        .map_err(ComponentServiceReadTransferPreparationError::Attachment)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeComponentServiceCopyReadTransferTeardown {
    active: NativeComponentServiceCopyReadTransferTask,
    retired_context: Option<UserContext>,
    authority_revoked: bool,
    mapping_removed: bool,
    backing_released: bool,
}

impl NativeComponentServiceCopyReadTransferTeardown {
    pub const fn new(active: NativeComponentServiceCopyReadTransferTask) -> Self {
        Self {
            active,
            retired_context: None,
            authority_revoked: false,
            mapping_removed: false,
            backing_released: false,
        }
    }
    pub const fn from_retirement(
        retirement: NativeComponentServiceCopyReadTransferRetirement,
    ) -> Self {
        Self {
            active: retirement.active,
            retired_context: Some(retirement.context),
            authority_revoked: false,
            mapping_removed: false,
            backing_released: false,
        }
    }
    pub const fn from_retirement_with_mapping_revoked(
        retirement: NativeComponentServiceCopyReadTransferRetirement,
    ) -> Self {
        Self {
            active: retirement.active,
            retired_context: Some(retirement.context),
            authority_revoked: false,
            mapping_removed: true,
            backing_released: false,
        }
    }
    pub const fn active(self) -> NativeComponentServiceCopyReadTransferTask {
        self.active
    }
    pub const fn retired_context(self) -> Option<UserContext> {
        self.retired_context
    }
    pub const fn is_pristine(self) -> bool {
        !self.authority_revoked && !self.mapping_removed && !self.backing_released
    }
    pub const fn authority_revoked(self) -> bool {
        self.authority_revoked
    }
    pub const fn mapping_removed(self) -> bool {
        self.mapping_removed
    }
    pub const fn backing_released(self) -> bool {
        self.backing_released
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeComponentServiceCopyReadTransferRetirement {
    active: NativeComponentServiceCopyReadTransferTask,
    context: UserContext,
}

impl NativeComponentServiceCopyReadTransferRetirement {
    pub const fn active(self) -> NativeComponentServiceCopyReadTransferTask {
        self.active
    }

    pub const fn context(self) -> UserContext {
        self.context
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeComponentServiceCopyReadTransferRetirementError {
    NotCurrent,
    RootMismatch,
    Runtime(TaskRuntimeError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeComponentServiceCopyReadTransferRetirementMappingError<M> {
    Retirement(NativeComponentServiceCopyReadTransferRetirementError),
    Runtime {
        termination: crate::TaskTermination,
        state: NativeComponentServiceCopyReadTransferTeardown,
        error: TaskRuntimeError,
    },
    LocalMapping {
        termination: crate::TaskTermination,
        state: NativeComponentServiceCopyReadTransferTeardown,
        error: MemoryMappingOperationError<M>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeComponentServiceCopyReadTransferActiveRetirementError {
    Retirement(NativeComponentServiceCopyReadTransferRetirementError),
    Runtime(TaskRuntimeError),
    Mapping(MemoryResourceError),
    ActivePageTables(crate::arch::x86_64::PageTableBuildError),
    ActiveRevoker(crate::arch::x86_64::ActiveMappingRevocationError),
    RetirementMapping(
        NativeComponentServiceCopyReadTransferRetirementMappingError<
            crate::arch::x86_64::ActiveMappingRevocationError,
        >,
    ),
}

impl NativeComponentServiceCopyReadTransferActiveRetirementError {
    pub const fn state(&self) -> Option<NativeComponentServiceCopyReadTransferTeardown> {
        match self {
            Self::RetirementMapping(error) => error.state(),
            Self::Retirement(_)
            | Self::Runtime(_)
            | Self::Mapping(_)
            | Self::ActivePageTables(_)
            | Self::ActiveRevoker(_) => None,
        }
    }
}

impl<M> NativeComponentServiceCopyReadTransferRetirementMappingError<M> {
    pub const fn state(&self) -> Option<NativeComponentServiceCopyReadTransferTeardown> {
        match self {
            Self::Retirement(_) => None,
            Self::Runtime { state, .. } | Self::LocalMapping { state, .. } => Some(*state),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeComponentServiceCopyReadTransferTeardownError<M, B> {
    TaskStillLive {
        state: NativeComponentServiceCopyReadTransferTeardown,
        task: TaskId,
    },
    RetirementMissing {
        state: NativeComponentServiceCopyReadTransferTeardown,
        task: TaskId,
    },
    RetirementRootMismatch {
        state: NativeComponentServiceCopyReadTransferTeardown,
        task: TaskId,
    },
    Authority {
        state: NativeComponentServiceCopyReadTransferTeardown,
        error: TaskRuntimeError,
    },
    Runtime {
        state: NativeComponentServiceCopyReadTransferTeardown,
        error: TaskRuntimeError,
    },
    LocalMapping {
        state: NativeComponentServiceCopyReadTransferTeardown,
        error: MemoryMappingOperationError<M>,
    },
    Backing {
        state: NativeComponentServiceCopyReadTransferTeardown,
        error: MemoryBackingOperationError<B>,
    },
    Object {
        state: NativeComponentServiceCopyReadTransferTeardown,
        error: MemoryResourceError,
    },
}

impl<M, B> NativeComponentServiceCopyReadTransferTeardownError<M, B> {
    pub const fn state(&self) -> NativeComponentServiceCopyReadTransferTeardown {
        match self {
            Self::TaskStillLive { state, .. }
            | Self::RetirementMissing { state, .. }
            | Self::RetirementRootMismatch { state, .. }
            | Self::Authority { state, .. }
            | Self::Runtime { state, .. }
            | Self::LocalMapping { state, .. }
            | Self::Backing { state, .. }
            | Self::Object { state, .. } => *state,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeComponentServiceMappedReadTransferTeardown {
    active: NativeComponentServiceMappedReadTransferTask,
    authority_revoked: bool,
    mappings: MemoryMappingPairRemovalState,
    backing_released: bool,
}

impl NativeComponentServiceMappedReadTransferTeardown {
    pub const fn new(active: NativeComponentServiceMappedReadTransferTask) -> Self {
        Self {
            active,
            authority_revoked: false,
            mappings: MemoryMappingPairRemovalState::new(active.binding().mappings().mappings()),
            backing_released: false,
        }
    }

    pub const fn active(self) -> NativeComponentServiceMappedReadTransferTask {
        self.active
    }

    pub const fn authority_revoked(self) -> bool {
        self.authority_revoked
    }

    pub const fn mappings(self) -> MemoryMappingPairRemovalState {
        self.mappings
    }

    pub const fn backing_released(self) -> bool {
        self.backing_released
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeComponentServiceMappedReadTransferTeardownError<F, S, B> {
    TaskStillLive {
        state: NativeComponentServiceMappedReadTransferTeardown,
        task: TaskId,
    },
    Authority {
        state: NativeComponentServiceMappedReadTransferTeardown,
        error: TaskRuntimeError,
    },
    Runtime {
        state: NativeComponentServiceMappedReadTransferTeardown,
        error: TaskRuntimeError,
    },
    ProviderMapping {
        state: NativeComponentServiceMappedReadTransferTeardown,
        error: MemoryMappingOperationError<S>,
    },
    LocalMapping {
        state: NativeComponentServiceMappedReadTransferTeardown,
        error: MemoryMappingOperationError<F>,
    },
    Backing {
        state: NativeComponentServiceMappedReadTransferTeardown,
        error: MemoryBackingOperationError<B>,
    },
    Object {
        state: NativeComponentServiceMappedReadTransferTeardown,
        error: MemoryResourceError,
    },
}

impl<F, S, B> NativeComponentServiceMappedReadTransferTeardownError<F, S, B> {
    pub const fn state(&self) -> NativeComponentServiceMappedReadTransferTeardown {
        match self {
            Self::TaskStillLive { state, .. }
            | Self::Authority { state, .. }
            | Self::Runtime { state, .. }
            | Self::ProviderMapping { state, .. }
            | Self::LocalMapping { state, .. }
            | Self::Backing { state, .. }
            | Self::Object { state, .. } => *state,
        }
    }
}

impl NativeComponentServiceMappedReadTransferTask {
    pub const fn construction(self) -> NativeComponentServiceReadTransferTask {
        self.construction
    }

    pub const fn memory(self) -> ComponentServiceReadTransferMemoryRoot {
        self.memory
    }

    pub const fn binding(self) -> ComponentServiceReadTransferTaskBinding {
        self.binding
    }

    /// Revalidates and reconstructs the source-owned attachment consumed by a
    /// service launch coordinator. Target-task handles are never substituted.
    pub fn source_attachment<const TASKS: usize, const CAPABILITIES: usize>(
        self,
        runtime: &TaskRuntime<TASKS, CAPABILITIES>,
    ) -> Result<ComponentServiceReadTransferAttachment, ComponentServiceReadTransferPreparationError>
    {
        let construction = self.construction();
        let capabilities = runtime
            .capabilities(construction.source_task())
            .map_err(ComponentServiceReadTransferPreparationError::Root)?;
        ComponentServiceReadTransferAttachment::new(
            self.binding().provider_task(),
            self.memory().shared_object(),
            self.memory().generation(),
            self.memory().bytes(),
            construction.source_local_read(),
            construction.source_provider_write(),
            capabilities,
        )
        .map_err(ComponentServiceReadTransferPreparationError::Attachment)
    }
}

impl NativeComponentServiceReadTransferTask {
    pub const fn source_task(self) -> TaskId {
        self.source_task
    }
    pub const fn task(self) -> TaskId {
        self.task
    }
    pub const fn entry(self) -> NativeComponentServiceEntry {
        self.entry
    }
    pub const fn local_read(self) -> Capability {
        self.local_read
    }
    pub const fn provider_write(self) -> Capability {
        self.provider_write
    }
    pub const fn source_local_read(self) -> Capability {
        self.source_local_read
    }
    pub const fn source_provider_write(self) -> Capability {
        self.source_provider_write
    }
}

/// Tears down one mapped transfer in authority, mapping, backing, and object
/// order. The constructed task must already be retired so no schedulable domain
/// can retain a virtual mapping while teardown progresses. Every failure returns
/// the exact progress state for a safe retry.
pub fn teardown_native_component_service_mapped_read_transfer<
    F: MemoryMappingBackend,
    S: MemoryMappingBackend,
    B: MemoryObjectBackingBackend,
    const POOLS: usize,
    const OBJECTS: usize,
    const MAPPINGS: usize,
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    mut state: NativeComponentServiceMappedReadTransferTeardown,
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    memory: &mut MemoryPoolTable<POOLS, OBJECTS, MAPPINGS>,
    local_backend: &mut F,
    provider_backend: &mut S,
    backing_backend: &mut B,
) -> Result<u64, NativeComponentServiceMappedReadTransferTeardownError<F::Error, S::Error, B::Error>>
{
    let construction = state.active().construction();
    match runtime.context(construction.task()) {
        Ok(_) => {
            return Err(
                NativeComponentServiceMappedReadTransferTeardownError::TaskStillLive {
                    state,
                    task: construction.task(),
                },
            );
        }
        Err(TaskRuntimeError::MissingTask) => {}
        Err(error) => {
            return Err(
                NativeComponentServiceMappedReadTransferTeardownError::Runtime { state, error },
            );
        }
    }
    if !state.authority_revoked {
        if let Err(error) = runtime.revoke_capability_pair(
            construction.source_task(),
            construction.source_local_read(),
            construction.source_provider_write(),
        ) {
            return Err(
                NativeComponentServiceMappedReadTransferTeardownError::Authority { state, error },
            );
        }
        state.authority_revoked = true;
    }
    if !state.mappings.complete() {
        let capabilities =
            runtime
                .capabilities(construction.source_task())
                .map_err(|error| {
                    NativeComponentServiceMappedReadTransferTeardownError::Runtime { state, error }
                })?;
        let mapping = state.active().binding().mappings();
        match memory.remove_mapping_pair(
            state.mappings,
            mapping.local_target_capability(),
            local_backend,
            mapping.provider_target_capability(),
            provider_backend,
            capabilities,
        ) {
            Ok(mappings) => state.mappings = mappings,
            Err(MemoryMappingPairRemovalError::Second {
                state: mappings,
                error,
            }) => {
                state.mappings = mappings;
                return Err(
                    NativeComponentServiceMappedReadTransferTeardownError::ProviderMapping {
                        state,
                        error,
                    },
                );
            }
            Err(MemoryMappingPairRemovalError::First {
                state: mappings,
                error,
            }) => {
                state.mappings = mappings;
                return Err(
                    NativeComponentServiceMappedReadTransferTeardownError::LocalMapping {
                        state,
                        error,
                    },
                );
            }
        }
    }
    if !state.backing_released {
        let capabilities =
            runtime
                .capabilities(construction.source_task())
                .map_err(|error| {
                    NativeComponentServiceMappedReadTransferTeardownError::Runtime { state, error }
                })?;
        let root = state.active().memory();
        if let Err(error) = memory.release_physical_backing(
            root.memory_object(),
            root.root(),
            capabilities,
            backing_backend,
        ) {
            return Err(
                NativeComponentServiceMappedReadTransferTeardownError::Backing { state, error },
            );
        }
        state.backing_released = true;
    }
    let root = state.active().memory();
    let capabilities = runtime
        .capabilities_mut(construction.source_task())
        .map_err(
            |error| NativeComponentServiceMappedReadTransferTeardownError::Runtime { state, error },
        )?;
    memory
        .release_object(root.memory_object(), root.root(), capabilities)
        .map_err(
            |error| NativeComponentServiceMappedReadTransferTeardownError::Object { state, error },
        )
}

pub fn retire_current_native_component_service_copy_read_transfer<
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    active: NativeComponentServiceCopyReadTransferTask,
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
) -> Result<
    (
        crate::TaskTermination,
        NativeComponentServiceCopyReadTransferRetirement,
    ),
    NativeComponentServiceCopyReadTransferRetirementError,
> {
    let task = active.construction().task();
    if runtime.current() != Some(task) {
        return Err(NativeComponentServiceCopyReadTransferRetirementError::NotCurrent);
    }
    let context = *runtime
        .context(task)
        .map_err(NativeComponentServiceCopyReadTransferRetirementError::Runtime)?;
    if context.page_table() != active.page_table_root() {
        return Err(NativeComponentServiceCopyReadTransferRetirementError::RootMismatch);
    }
    let (termination, retired_context) = runtime
        .terminate_current_with_context()
        .map_err(NativeComponentServiceCopyReadTransferRetirementError::Runtime)?;
    debug_assert_eq!(termination.task, task);
    debug_assert_eq!(retired_context, context);
    Ok((
        termination,
        NativeComponentServiceCopyReadTransferRetirement {
            active,
            context: retired_context,
        },
    ))
}

/// Retires the current copy-mediated service task and withdraws its exact local
/// mapping before returning control to code that may install the next hardware
/// context. A post-retirement failure retains the typed context and mapping
/// policy record so cleanup can fail closed or retry without reviving the task.
pub fn retire_current_native_component_service_copy_read_transfer_with_mapping_revocation<
    M: MemoryMappingRevocationBackend,
    const POOLS: usize,
    const OBJECTS: usize,
    const MAPPINGS: usize,
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    active: NativeComponentServiceCopyReadTransferTask,
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    memory: &mut MemoryPoolTable<POOLS, OBJECTS, MAPPINGS>,
    mapping_backend: &mut M,
) -> Result<
    (
        crate::TaskTermination,
        NativeComponentServiceCopyReadTransferTeardown,
    ),
    NativeComponentServiceCopyReadTransferRetirementMappingError<M::Error>,
> {
    let (termination, retirement) =
        retire_current_native_component_service_copy_read_transfer(active, runtime)
            .map_err(NativeComponentServiceCopyReadTransferRetirementMappingError::Retirement)?;
    let state = NativeComponentServiceCopyReadTransferTeardown::from_retirement(retirement);
    let construction = active.construction();
    let capabilities = runtime
        .capabilities(construction.source_task())
        .map_err(
            |error| NativeComponentServiceCopyReadTransferRetirementMappingError::Runtime {
                termination,
                state,
                error,
            },
        )?;
    let mapping = active.binding().mapping();
    memory
        .revoke_mapping(
            mapping.mapping(),
            mapping.local_target_capability(),
            capabilities,
            mapping_backend,
        )
        .map_err(|error| {
            NativeComponentServiceCopyReadTransferRetirementMappingError::LocalMapping {
                termination,
                state,
                error,
            }
        })?;
    Ok((
        termination,
        NativeComponentServiceCopyReadTransferTeardown::from_retirement_with_mapping_revoked(
            retirement,
        ),
    ))
}

/// Retires the current native copy-transfer task through its physically active
/// x86-64 page-table root.
///
/// # Safety
///
/// The caller must execute on the CPU currently running `active`, with that
/// task's hierarchy identity-mapped and exclusively owned. Interrupts and all
/// concurrent page-table mutation must remain excluded through this call. The
/// active-table constructor checks IF but cannot establish CPU ownership or
/// restore a caller-managed critical section.
pub unsafe fn retire_current_native_component_service_copy_read_transfer_on_active_x86_64<
    const POOLS: usize,
    const OBJECTS: usize,
    const MAPPINGS: usize,
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    active: NativeComponentServiceCopyReadTransferTask,
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    memory: &mut MemoryPoolTable<POOLS, OBJECTS, MAPPINGS>,
) -> Result<
    (
        crate::TaskTermination,
        NativeComponentServiceCopyReadTransferTeardown,
    ),
    NativeComponentServiceCopyReadTransferActiveRetirementError,
> {
    let construction = active.construction();
    if runtime.current() != Some(construction.task()) {
        return Err(
            NativeComponentServiceCopyReadTransferActiveRetirementError::Retirement(
                NativeComponentServiceCopyReadTransferRetirementError::NotCurrent,
            ),
        );
    }
    let context = runtime
        .context(construction.task())
        .map_err(NativeComponentServiceCopyReadTransferActiveRetirementError::Runtime)?;
    if context.page_table() != active.page_table_root() {
        return Err(
            NativeComponentServiceCopyReadTransferActiveRetirementError::Retirement(
                NativeComponentServiceCopyReadTransferRetirementError::RootMismatch,
            ),
        );
    }
    let capabilities = runtime
        .capabilities(construction.source_task())
        .map_err(NativeComponentServiceCopyReadTransferActiveRetirementError::Runtime)?;
    let mapping = active.binding().mapping();
    let request = memory
        .mapping_revocation_request(
            mapping.mapping(),
            mapping.local_target_capability(),
            capabilities,
        )
        .map_err(NativeComponentServiceCopyReadTransferActiveRetirementError::Mapping)?;
    let mut tables = unsafe { crate::arch::x86_64::ActivePageTables::current() }
        .map_err(NativeComponentServiceCopyReadTransferActiveRetirementError::ActivePageTables)?;
    let mut revoker = unsafe {
        crate::arch::x86_64::ActiveServiceMappingRevoker::from_request(
            &mut tables,
            active.page_table_root(),
            request,
        )
    }
    .map_err(NativeComponentServiceCopyReadTransferActiveRetirementError::ActiveRevoker)?;
    retire_current_native_component_service_copy_read_transfer_with_mapping_revocation(
        active,
        runtime,
        memory,
        &mut revoker,
    )
    .map_err(NativeComponentServiceCopyReadTransferActiveRetirementError::RetirementMapping)
}

pub fn teardown_native_component_service_copy_read_transfer<
    M: MemoryMappingRevocationBackend,
    B: MemoryObjectBackingBackend,
    const POOLS: usize,
    const OBJECTS: usize,
    const MAPPINGS: usize,
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    mut state: NativeComponentServiceCopyReadTransferTeardown,
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    memory: &mut MemoryPoolTable<POOLS, OBJECTS, MAPPINGS>,
    mapping_backend: &mut M,
    backing_backend: &mut B,
) -> Result<u64, NativeComponentServiceCopyReadTransferTeardownError<M::Error, B::Error>> {
    let construction = state.active().construction();
    let retired_context = match state.retired_context() {
        Some(context) => context,
        None => match runtime.context(construction.task()) {
            Ok(_) => {
                return Err(
                    NativeComponentServiceCopyReadTransferTeardownError::TaskStillLive {
                        state,
                        task: construction.task(),
                    },
                );
            }
            Err(TaskRuntimeError::MissingTask) => {
                return Err(
                    NativeComponentServiceCopyReadTransferTeardownError::RetirementMissing {
                        state,
                        task: construction.task(),
                    },
                );
            }
            Err(error) => {
                return Err(
                    NativeComponentServiceCopyReadTransferTeardownError::Runtime { state, error },
                );
            }
        },
    };
    if retired_context.page_table() != state.active().page_table_root() {
        return Err(
            NativeComponentServiceCopyReadTransferTeardownError::RetirementRootMismatch {
                state,
                task: construction.task(),
            },
        );
    }
    if !state.authority_revoked {
        if let Err(error) = runtime.revoke_capability_pair(
            construction.source_task(),
            construction.source_local_read(),
            construction.source_provider_write(),
        ) {
            return Err(
                NativeComponentServiceCopyReadTransferTeardownError::Authority { state, error },
            );
        }
        state.authority_revoked = true;
    }
    if !state.mapping_removed {
        let capabilities = runtime
            .capabilities(construction.source_task())
            .map_err(
                |error| NativeComponentServiceCopyReadTransferTeardownError::Runtime {
                    state,
                    error,
                },
            )?;
        let mapping = state.active().binding().mapping();
        if let Err(error) = memory.revoke_mapping(
            mapping.mapping(),
            mapping.local_target_capability(),
            capabilities,
            mapping_backend,
        ) {
            return Err(
                NativeComponentServiceCopyReadTransferTeardownError::LocalMapping { state, error },
            );
        }
        state.mapping_removed = true;
    }
    if !state.backing_released {
        let capabilities = runtime
            .capabilities(construction.source_task())
            .map_err(
                |error| NativeComponentServiceCopyReadTransferTeardownError::Runtime {
                    state,
                    error,
                },
            )?;
        let root = state.active().memory();
        if let Err(error) = memory.release_physical_backing(
            root.memory_object(),
            root.root(),
            capabilities,
            backing_backend,
        ) {
            return Err(
                NativeComponentServiceCopyReadTransferTeardownError::Backing { state, error },
            );
        }
        state.backing_released = true;
    }
    let root = state.active().memory();
    let capabilities = runtime
        .capabilities_mut(construction.source_task())
        .map_err(
            |error| NativeComponentServiceCopyReadTransferTeardownError::Runtime { state, error },
        )?;
    memory
        .release_object(root.memory_object(), root.root(), capabilities)
        .map_err(
            |error| NativeComponentServiceCopyReadTransferTeardownError::Object { state, error },
        )
}

impl NativeComponentServiceTask {
    pub const fn task(self) -> TaskId {
        self.task
    }

    pub const fn entry(self) -> NativeComponentServiceEntry {
        self.entry
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeComponentServiceTaskError {
    WrongPlacement,
    Runtime(TaskRuntimeError),
    Entry(NativeComponentServiceEntryError),
    Rollback {
        entry: NativeComponentServiceEntryError,
        cleanup: TaskRuntimeError,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeComponentServiceReadTransferRootError {
    Preparation(ComponentServiceReadTransferPreparationError),
    Task(NativeComponentServiceTaskError),
    Rollback {
        task: NativeComponentServiceTaskError,
        cleanup: TaskRuntimeError,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeComponentServiceMappedReadTransferError {
    BindingMismatch,
    Construction(NativeComponentServiceReadTransferRootError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeComponentServiceCopyReadTransferError {
    BindingMismatch,
    Construction(NativeComponentServiceReadTransferRootError),
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_native_component_service_task_from_copy_read_transfer_attachment<
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    source_task: TaskId,
    target_task: TaskId,
    spec: IsolationServiceSpec,
    launch_attachment: ComponentServiceLaunchAttachment,
    transfer: ComponentServiceReadTransferAttachment,
    memory: ComponentServiceReadTransferMemoryRoot,
    binding: ComponentServiceReadTransferCopyTaskBinding,
    page_table_root: crate::PhysAddr,
    service_endpoint_object: ObjectId,
    supervisor_task_object: ObjectId,
    consumer_module_object: ObjectId,
) -> Result<NativeComponentServiceCopyReadTransferTask, NativeComponentServiceCopyReadTransferError>
{
    let mapping = binding.mapping();
    let target_root = runtime
        .context(target_task)
        .map_err(|error| {
            NativeComponentServiceCopyReadTransferError::Construction(
                NativeComponentServiceReadTransferRootError::Task(
                    NativeComponentServiceTaskError::Runtime(error),
                ),
            )
        })?
        .page_table();
    if target_root != page_table_root
        || binding.local_task() != target_task
        || binding.provider_task() != transfer.provider_task()
        || mapping.memory_object() != memory.memory_object()
        || mapping.shared_object() != memory.shared_object()
        || transfer.shared_object() != memory.shared_object()
        || transfer.shared_generation() != memory.generation()
        || transfer.shared_bytes() != memory.bytes()
    {
        return Err(NativeComponentServiceCopyReadTransferError::BindingMismatch);
    }
    let construction = match prepare_native_component_service_task_with_read_transfer(
        runtime,
        source_task,
        target_task,
        spec,
        launch_attachment,
        transfer,
        service_endpoint_object,
        supervisor_task_object,
        consumer_module_object,
    ) {
        Ok(construction) => construction,
        Err(task) => {
            let first = runtime
                .revoke_capability(source_task, transfer.local_read())
                .err();
            let second = runtime
                .revoke_capability(source_task, transfer.provider_write())
                .err();
            let error = match first.or(second) {
                Some(cleanup) => {
                    NativeComponentServiceReadTransferRootError::Rollback { task, cleanup }
                }
                None => NativeComponentServiceReadTransferRootError::Task(task),
            };
            return Err(NativeComponentServiceCopyReadTransferError::Construction(
                error,
            ));
        }
    };
    Ok(NativeComponentServiceCopyReadTransferTask {
        construction,
        memory,
        binding,
        page_table_root,
    })
}

/// Constructs the exact local task from an already prepared source attachment
/// only when that attachment, the live mappings, and the task binding describe
/// the same transfer.
#[allow(clippy::too_many_arguments)]
pub fn prepare_native_component_service_task_from_mapped_read_transfer_attachment<
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    source_task: TaskId,
    target_task: TaskId,
    spec: IsolationServiceSpec,
    launch_attachment: ComponentServiceLaunchAttachment,
    transfer: ComponentServiceReadTransferAttachment,
    memory: ComponentServiceReadTransferMemoryRoot,
    binding: ComponentServiceReadTransferTaskBinding,
    service_endpoint_object: ObjectId,
    supervisor_task_object: ObjectId,
    consumer_module_object: ObjectId,
) -> Result<
    NativeComponentServiceMappedReadTransferTask,
    NativeComponentServiceMappedReadTransferError,
> {
    let mappings = binding.mappings();
    if binding.local_task() != target_task
        || binding.provider_task() != transfer.provider_task()
        || mappings.memory_object() != memory.memory_object()
        || mappings.shared_object() != memory.shared_object()
        || transfer.shared_object() != memory.shared_object()
        || transfer.shared_generation() != memory.generation()
        || transfer.shared_bytes() != memory.bytes()
    {
        return Err(NativeComponentServiceMappedReadTransferError::BindingMismatch);
    }
    let construction = match prepare_native_component_service_task_with_read_transfer(
        runtime,
        source_task,
        target_task,
        spec,
        launch_attachment,
        transfer,
        service_endpoint_object,
        supervisor_task_object,
        consumer_module_object,
    ) {
        Ok(construction) => construction,
        Err(task) => {
            let first = runtime
                .revoke_capability(source_task, transfer.local_read())
                .err();
            let second = runtime
                .revoke_capability(source_task, transfer.provider_write())
                .err();
            let error = match first.or(second) {
                Some(cleanup) => {
                    NativeComponentServiceReadTransferRootError::Rollback { task, cleanup }
                }
                None => NativeComponentServiceReadTransferRootError::Task(task),
            };
            return Err(NativeComponentServiceMappedReadTransferError::Construction(
                error,
            ));
        }
    };
    Ok(NativeComponentServiceMappedReadTransferTask {
        construction,
        memory,
        binding,
    })
}

/// Constructs the exact local task only when the live directional mappings,
/// task association, and charged memory root still describe one transfer.
#[allow(clippy::too_many_arguments)]
pub fn prepare_native_component_service_task_from_mapped_read_transfer<
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    source_task: TaskId,
    target_task: TaskId,
    spec: IsolationServiceSpec,
    launch_attachment: ComponentServiceLaunchAttachment,
    memory: ComponentServiceReadTransferMemoryRoot,
    binding: ComponentServiceReadTransferTaskBinding,
    service_endpoint_object: ObjectId,
    supervisor_task_object: ObjectId,
    consumer_module_object: ObjectId,
) -> Result<
    NativeComponentServiceMappedReadTransferTask,
    NativeComponentServiceMappedReadTransferError,
> {
    let mappings = binding.mappings();
    if binding.local_task() != target_task
        || mappings.memory_object() != memory.memory_object()
        || mappings.shared_object() != memory.shared_object()
    {
        return Err(NativeComponentServiceMappedReadTransferError::BindingMismatch);
    }
    let transfer = prepare_component_service_read_transfer_attachment(
        runtime,
        source_task,
        binding.provider_task(),
        memory.shared_object(),
        memory.generation(),
        memory.bytes(),
        memory.root(),
    )
    .map_err(|error| {
        NativeComponentServiceMappedReadTransferError::Construction(
            NativeComponentServiceReadTransferRootError::Preparation(error),
        )
    })?;
    prepare_native_component_service_task_from_mapped_read_transfer_attachment(
        runtime,
        source_task,
        target_task,
        spec,
        launch_attachment,
        transfer,
        memory,
        binding,
        service_endpoint_object,
        supervisor_task_object,
        consumer_module_object,
    )
}

/// Prepares the direction-scoped source attachment and constructs the native
/// target as one rollback-complete authority transaction. The broad root stays
/// with the caller for mapping/resource cleanup and later transitive revocation.
#[allow(clippy::too_many_arguments)]
pub fn prepare_native_component_service_task_from_read_transfer_root<
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    source_task: TaskId,
    target_task: TaskId,
    spec: IsolationServiceSpec,
    launch_attachment: ComponentServiceLaunchAttachment,
    provider_task: TaskId,
    shared_object: ObjectId,
    shared_generation: u64,
    shared_bytes: u32,
    shared_root: Capability,
    service_endpoint_object: ObjectId,
    supervisor_task_object: ObjectId,
    consumer_module_object: ObjectId,
) -> Result<NativeComponentServiceReadTransferTask, NativeComponentServiceReadTransferRootError> {
    let transfer = prepare_component_service_read_transfer_attachment(
        runtime,
        source_task,
        provider_task,
        shared_object,
        shared_generation,
        shared_bytes,
        shared_root,
    )
    .map_err(NativeComponentServiceReadTransferRootError::Preparation)?;
    match prepare_native_component_service_task_with_read_transfer(
        runtime,
        source_task,
        target_task,
        spec,
        launch_attachment,
        transfer,
        service_endpoint_object,
        supervisor_task_object,
        consumer_module_object,
    ) {
        Ok(task) => Ok(task),
        Err(task) => {
            let first = runtime
                .revoke_capability(source_task, transfer.local_read())
                .err();
            let second = runtime
                .revoke_capability(source_task, transfer.provider_write())
                .err();
            match first.or(second) {
                Some(cleanup) => {
                    Err(NativeComponentServiceReadTransferRootError::Rollback { task, cleanup })
                }
                None => Err(NativeComponentServiceReadTransferRootError::Task(task)),
            }
        }
    }
}

/// Constructs a native component with a receive-only shared-memory path to its
/// dependency. The target keeps local read authority and may delegate only
/// write authority to the provider named by the separately projected endpoint.
#[allow(clippy::too_many_arguments)]
pub fn prepare_native_component_service_task_with_read_transfer<
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    source_task: TaskId,
    target_task: TaskId,
    spec: IsolationServiceSpec,
    attachment: ComponentServiceLaunchAttachment,
    transfer: ComponentServiceReadTransferAttachment,
    service_endpoint_object: ObjectId,
    supervisor_task_object: ObjectId,
    consumer_module_object: ObjectId,
) -> Result<NativeComponentServiceReadTransferTask, NativeComponentServiceTaskError> {
    if spec.placement() != IsolationPlacement::NativeService {
        return Err(NativeComponentServiceTaskError::WrongPlacement);
    }
    if transfer.provider_task() == source_task || transfer.provider_task() == target_task {
        return Err(NativeComponentServiceTaskError::Entry(
            NativeComponentServiceEntryError::InvalidIdentity,
        ));
    }
    runtime
        .context(transfer.provider_task())
        .map_err(NativeComponentServiceTaskError::Runtime)?;
    let context = *runtime
        .context(target_task)
        .map_err(NativeComponentServiceTaskError::Runtime)?;
    if context.rbp != 0
        || context.rsi != 0
        || context.r9 != 0
        || context.r8 != 0
        || context.rdx != 0
    {
        return Err(NativeComponentServiceTaskError::Entry(
            NativeComponentServiceEntryError::LaunchRegistersOccupied,
        ));
    }
    let projection = runtime
        .project_capabilities_for_construction(
            source_task,
            target_task,
            &[
                (attachment.launch_data(), Rights::READ),
                (attachment.dependency_endpoint(), Rights::SIGNAL),
                (transfer.local_read(), Rights::MAP.union(Rights::READ)),
                (
                    transfer.provider_write(),
                    Rights::MAP.union(Rights::WRITE).union(Rights::DELEGATE),
                ),
            ],
        )
        .map_err(NativeComponentServiceTaskError::Runtime)?;
    let mut capabilities = projection.capabilities();
    let projected = [
        capabilities
            .next()
            .expect("four construction projections produce four handles"),
        capabilities
            .next()
            .expect("four construction projections produce four handles"),
        capabilities
            .next()
            .expect("four construction projections produce four handles"),
        capabilities
            .next()
            .expect("four construction projections produce four handles"),
    ];
    debug_assert!(capabilities.next().is_none());
    let [launch_data, dependency_endpoint, local_read, provider_write] = projected;
    let entry = match NativeComponentServiceEntry::new(
        spec,
        attachment,
        service_endpoint_object,
        supervisor_task_object,
        consumer_module_object,
        launch_data,
        dependency_endpoint,
        runtime
            .capabilities(target_task)
            .expect("successful projection preserves the target domain"),
    ) {
        Ok(entry) => entry,
        Err(error) => {
            return rollback_native_read_transfer_projection(
                runtime,
                target_task,
                projected,
                error,
            );
        }
    };
    let mut installed = match entry.install(context) {
        Ok(installed) => installed,
        Err((_, error, _)) => {
            return rollback_native_read_transfer_projection(
                runtime,
                target_task,
                projected,
                error,
            );
        }
    };
    installed.rbp = local_read.token();
    installed.rsi = provider_write.token();
    installed.r9 = transfer.shared_generation();
    installed.r8 = u64::from(transfer.shared_bytes());
    installed.rdx = transfer.provider_task().token();
    *runtime
        .context_mut(target_task)
        .expect("successful projection preserves the target context") = installed;
    Ok(NativeComponentServiceReadTransferTask {
        source_task,
        task: target_task,
        entry,
        local_read,
        provider_write,
        source_local_read: transfer.local_read(),
        source_provider_write: transfer.provider_write(),
    })
}

fn rollback_native_read_transfer_projection<const TASKS: usize, const CAPABILITIES: usize>(
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    target_task: TaskId,
    projected: [Capability; 4],
    entry: NativeComponentServiceEntryError,
) -> Result<NativeComponentServiceReadTransferTask, NativeComponentServiceTaskError> {
    let mut cleanup = None;
    for capability in projected {
        if let Err(error) = runtime.revoke_capability(target_task, capability) {
            cleanup = cleanup.or(Some(error));
        }
    }
    match cleanup {
        Some(cleanup) => Err(NativeComponentServiceTaskError::Rollback { entry, cleanup }),
        None => Err(NativeComponentServiceTaskError::Entry(entry)),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_native_component_service_task<const TASKS: usize, const CAPABILITIES: usize>(
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    source_task: TaskId,
    target_task: TaskId,
    spec: IsolationServiceSpec,
    attachment: ComponentServiceLaunchAttachment,
    service_endpoint_object: ObjectId,
    supervisor_task_object: ObjectId,
    consumer_module_object: ObjectId,
) -> Result<NativeComponentServiceTask, NativeComponentServiceTaskError> {
    if spec.placement() != IsolationPlacement::NativeService {
        return Err(NativeComponentServiceTaskError::WrongPlacement);
    }
    let context = *runtime
        .context(target_task)
        .map_err(NativeComponentServiceTaskError::Runtime)?;
    let projection = runtime
        .project_capabilities_for_construction(
            source_task,
            target_task,
            &[
                (attachment.launch_data(), Rights::READ),
                (attachment.dependency_endpoint(), Rights::SIGNAL),
            ],
        )
        .map_err(NativeComponentServiceTaskError::Runtime)?;
    let mut projected = projection.capabilities();
    let launch_data = projected
        .next()
        .expect("two requested construction projections produce two handles");
    let dependency_endpoint = projected
        .next()
        .expect("two requested construction projections produce two handles");
    debug_assert!(projected.next().is_none());
    let entry = match NativeComponentServiceEntry::new(
        spec,
        attachment,
        service_endpoint_object,
        supervisor_task_object,
        consumer_module_object,
        launch_data,
        dependency_endpoint,
        runtime
            .capabilities(target_task)
            .expect("successful projection preserves the target domain"),
    ) {
        Ok(entry) => entry,
        Err(error) => {
            return rollback_native_projection(
                runtime,
                target_task,
                launch_data,
                dependency_endpoint,
                error,
            );
        }
    };
    let installed = match entry.install(context) {
        Ok(installed) => installed,
        Err((_, error, _)) => {
            return rollback_native_projection(
                runtime,
                target_task,
                launch_data,
                dependency_endpoint,
                error,
            );
        }
    };
    *runtime
        .context_mut(target_task)
        .expect("successful projection preserves the target context") = installed;
    Ok(NativeComponentServiceTask {
        task: target_task,
        entry,
    })
}

fn rollback_native_projection<const TASKS: usize, const CAPABILITIES: usize>(
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    target_task: TaskId,
    launch_data: Capability,
    dependency_endpoint: Capability,
    entry: NativeComponentServiceEntryError,
) -> Result<NativeComponentServiceTask, NativeComponentServiceTaskError> {
    let data_cleanup = runtime.revoke_capability(target_task, launch_data).err();
    let endpoint_cleanup = runtime
        .revoke_capability(target_task, dependency_endpoint)
        .err();
    match data_cleanup.or(endpoint_cleanup) {
        Some(cleanup) => Err(NativeComponentServiceTaskError::Rollback { entry, cleanup }),
        None => Err(NativeComponentServiceTaskError::Entry(entry)),
    }
}

/// Atomic placement boundary for a service whose construction requires one
/// read-only launch-data object and one separately attenuated dependency
/// endpoint.
///
/// Implementations must project both capabilities into the same fresh domain
/// generation and publish no endpoint or ready signal until both projections
/// and service construction succeed. Failure must revoke and erase all partial
/// mappings, capabilities, device state, and domain memory.
pub unsafe trait IsolationAttachedServiceBackend {
    type Endpoint;
    type Error;

    fn launch_native_service_attached(
        &mut self,
        spec: IsolationServiceSpec,
        attachment: ComponentServiceLaunchAttachment,
    ) -> Result<Self::Endpoint, IsolationBackendFailure<Self::Error>>;

    fn launch_microvm_service_attached(
        &mut self,
        spec: IsolationServiceSpec,
        attachment: ComponentServiceLaunchAttachment,
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
    system_generation_digest: Option<[u8; 64]>,
    interface_catalog_digest: Option<[u8; 64]>,
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
    system_generation_digest: [u8; 64],
    interface_catalog_digest: [u8; 64],
    consumer_artifact: [u8; 64],
    provider_artifact: [u8; 64],
    interface_fingerprint: [u8; 32],
}

/// Component launch whose exact retained executable identities have been
/// revalidated. Only this state may release the underlying isolation route to
/// the placement-specific construction path.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedComponentServiceLaunch {
    route: PreparedIsolationServiceRoute,
}

impl PreparedComponentServiceLaunch {
    pub fn bind(
        route: PreparedIsolationServiceRoute,
        interface: ObjectId,
        interface_generation: u32,
        provider_generation: u64,
        system_generation: u64,
        system_generation_digest: [u8; 64],
        interface_catalog_digest: [u8; 64],
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
        } else if system_generation_digest == [0; 64] || interface_catalog_digest == [0; 64] {
            Some(ComponentServiceLaunchError::InvalidGenerationDigest)
        } else if route
            .system_generation_digest
            .is_some_and(|digest| digest != system_generation_digest)
            || route
                .interface_catalog_digest
                .is_some_and(|digest| digest != interface_catalog_digest)
        {
            Some(ComponentServiceLaunchError::GenerationDigestMismatch)
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
            system_generation_digest,
            interface_catalog_digest,
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

    pub const fn system_generation_digest(&self) -> &[u8; 64] {
        &self.system_generation_digest
    }

    pub const fn interface_catalog_digest(&self) -> &[u8; 64] {
        &self.interface_catalog_digest
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

    pub fn verify(
        self,
        consumer_kind: ArtifactKind,
        consumer_digest: &[u8; 64],
        provider_kind: ArtifactKind,
        provider_digest: &[u8; 64],
    ) -> Result<VerifiedComponentServiceLaunch, (Self, ComponentServiceArtifactError)> {
        if let Err(error) = self.verify_artifacts(
            consumer_kind,
            consumer_digest,
            provider_kind,
            provider_digest,
        ) {
            return Err((self, error));
        }
        Ok(VerifiedComponentServiceLaunch { route: self.route })
    }

    pub fn cancel<const DOMAINS: usize>(
        self,
        admission: &mut IsolationAdmissionTable<DOMAINS>,
    ) -> Result<(), IsolationLaunchError> {
        self.route.cancel(admission)
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

impl VerifiedComponentServiceLaunch {
    pub const fn spec(&self) -> IsolationServiceSpec {
        self.route.spec()
    }

    pub fn into_route(self) -> PreparedIsolationServiceRoute {
        self.route
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentServiceLaunchError {
    RouteIdentityMismatch,
    SystemGenerationMismatch,
    InvalidGenerationDigest,
    GenerationDigestMismatch,
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

#[derive(Debug, Eq, PartialEq)]
pub enum ComponentServiceHandoffError {
    Decode(ComponentServiceLaunchHandoffError),
    SystemGenerationDigestMismatch,
    InterfaceCatalogDigestMismatch,
    Spec(IsolationServiceSpecError),
    Admission(IsolationLaunchError),
    Binding {
        route: PreparedIsolationServiceRoute,
        error: ComponentServiceLaunchError,
    },
}

/// Decodes and consumes one canonical generation-bound control-plane handoff.
/// The active system/policy generations are checked by isolation admission
/// before a backend can run; the exact interface fingerprint and authenticated
/// artifact digests then remain owned by the prepared component launch.
pub fn prepare_component_service_handoff<const DOMAINS: usize>(
    admission: &mut IsolationAdmissionTable<DOMAINS>,
    bytes: &[u8],
) -> Result<PreparedComponentServiceLaunch, ComponentServiceHandoffError> {
    let handoff = ComponentServiceLaunchHandoff::decode(bytes)
        .map_err(ComponentServiceHandoffError::Decode)?;
    if admission.system_generation_digest() != Some(handoff.system_generation_digest()) {
        return Err(ComponentServiceHandoffError::SystemGenerationDigestMismatch);
    }
    if admission
        .interface_catalog_digest()
        .is_some_and(|digest| digest != handoff.interface_catalog_digest())
    {
        return Err(ComponentServiceHandoffError::InterfaceCatalogDigestMismatch);
    }
    let placement = match handoff.placement() {
        ComponentServicePlacement::NativeService => IsolationPlacement::NativeService,
        ComponentServicePlacement::Microvm => IsolationPlacement::Microvm,
    };
    let spec = IsolationServiceSpec::new(
        ObjectId(handoff.domain_object()),
        ObjectId(handoff.interface_object()),
        handoff.interface_generation(),
        handoff.provider_generation(),
        handoff.system_generation(),
        handoff.policy_generation(),
        TotalMicrovmClass::MicrovmEligible,
        placement,
    )
    .map_err(ComponentServiceHandoffError::Spec)?;
    let route = prepare_isolation_service_route(admission, spec)
        .map_err(ComponentServiceHandoffError::Admission)?;
    bind_component_service_handoff(route, handoff)
        .map_err(|(route, error)| ComponentServiceHandoffError::Binding { route, error })
}

/// Binds an already resource-reserved isolation route to the same canonical
/// handoff. This keeps CPU/RAM reservation stages linear without reconstructing
/// or weakening the generation/interface transaction.
pub fn bind_component_service_handoff(
    route: PreparedIsolationServiceRoute,
    handoff: ComponentServiceLaunchHandoff,
) -> Result<
    PreparedComponentServiceLaunch,
    (PreparedIsolationServiceRoute, ComponentServiceLaunchError),
> {
    let placement = match handoff.placement() {
        ComponentServicePlacement::NativeService => IsolationPlacement::NativeService,
        ComponentServicePlacement::Microvm => IsolationPlacement::Microvm,
    };
    let expected = match IsolationServiceSpec::new(
        ObjectId(handoff.domain_object()),
        ObjectId(handoff.interface_object()),
        handoff.interface_generation(),
        handoff.provider_generation(),
        handoff.system_generation(),
        handoff.policy_generation(),
        TotalMicrovmClass::MicrovmEligible,
        placement,
    ) {
        Ok(spec) => spec,
        Err(_) => return Err((route, ComponentServiceLaunchError::RouteIdentityMismatch)),
    };
    if route.spec() != expected {
        return Err((route, ComponentServiceLaunchError::RouteIdentityMismatch));
    }
    PreparedComponentServiceLaunch::bind(
        route,
        expected.interface(),
        expected.interface_generation(),
        expected.provider_generation(),
        expected.system_generation(),
        *handoff.system_generation_digest(),
        *handoff.interface_catalog_digest(),
        *handoff.interface_fingerprint(),
        *handoff.consumer_artifact(),
        *handoff.provider_artifact(),
    )
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
    let system_generation_digest = admission.system_generation_digest;
    let interface_catalog_digest = admission.interface_catalog_digest;
    admission
        .prepare(request)
        .map(|launch| PreparedIsolationServiceRoute {
            spec,
            launch,
            system_generation_digest,
            interface_catalog_digest,
        })
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
    let launch = match launch.verify(
        consumer_kind,
        consumer_digest,
        provider_kind,
        provider_digest,
    ) {
        Ok(launch) => launch,
        Err((launch, error)) => {
            return Err(PreparedComponentServiceRouteError::Artifact { launch, error });
        }
    };
    launch_prepared_isolation_service_route(admission, backend, launch.into_route())
        .map_err(PreparedComponentServiceRouteError::Route)
}

#[derive(Debug, Eq, PartialEq)]
pub enum PreparedAttachedComponentServiceRouteError<E, Endpoint> {
    Artifact {
        launch: PreparedComponentServiceLaunch,
        attachment: ComponentServiceLaunchAttachment,
        error: ComponentServiceArtifactError,
    },
    AttachmentMismatch {
        launch: VerifiedComponentServiceLaunch,
        attachment: ComponentServiceLaunchAttachment,
    },
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

#[allow(clippy::too_many_arguments)]
pub fn launch_prepared_component_service_with_attachment<
    B: IsolationAttachedServiceBackend,
    const DOMAINS: usize,
>(
    admission: &mut IsolationAdmissionTable<DOMAINS>,
    backend: &mut B,
    launch: PreparedComponentServiceLaunch,
    attachment: ComponentServiceLaunchAttachment,
    consumer_kind: ArtifactKind,
    consumer_digest: &[u8; 64],
    provider_kind: ArtifactKind,
    provider_digest: &[u8; 64],
) -> Result<
    RoutedIsolationService<B::Endpoint>,
    PreparedAttachedComponentServiceRouteError<B::Error, B::Endpoint>,
> {
    let launch = match launch.verify(
        consumer_kind,
        consumer_digest,
        provider_kind,
        provider_digest,
    ) {
        Ok(launch) => launch,
        Err((launch, error)) => {
            return Err(PreparedAttachedComponentServiceRouteError::Artifact {
                launch,
                attachment,
                error,
            });
        }
    };
    let spec = launch.spec();
    if !attachment.matches(spec) {
        return Err(
            PreparedAttachedComponentServiceRouteError::AttachmentMismatch { launch, attachment },
        );
    }
    let prepared = launch.into_route();
    let launched = match spec.placement() {
        IsolationPlacement::NativeService => {
            backend.launch_native_service_attached(spec, attachment)
        }
        IsolationPlacement::Microvm => backend.launch_microvm_service_attached(spec, attachment),
        _ => unreachable!("IsolationServiceSpec rejected non-service placement"),
    };
    let endpoint = match launched {
        Ok(endpoint) => endpoint,
        Err(failure) => {
            prepared
                .unavailable(admission, failure.reason)
                .map_err(PreparedAttachedComponentServiceRouteError::Admission)?;
            return Err(PreparedAttachedComponentServiceRouteError::Backend {
                reason: failure.reason,
                error: failure.error,
            });
        }
    };
    match prepared.commit(admission, endpoint) {
        Ok(routed) => Ok(routed),
        Err((prepared, admission_error, endpoint)) => match backend.revoke(&endpoint) {
            Ok(()) => {
                prepared
                    .cancel(admission)
                    .map_err(PreparedAttachedComponentServiceRouteError::Admission)?;
                Err(PreparedAttachedComponentServiceRouteError::Admission(
                    admission_error,
                ))
            }
            Err(error) => Err(PreparedAttachedComponentServiceRouteError::Rollback {
                admission: admission_error,
                error,
                endpoint,
                prepared,
            }),
        },
    }
}

pub trait IsolationApplicationBackend {
    type Endpoint;
    type Error;

    fn launch_native_process(
        &mut self,
        spec: IsolationApplicationSpec,
    ) -> Result<Self::Endpoint, IsolationBackendFailure<Self::Error>>;

    fn launch_microvm_application(
        &mut self,
        spec: IsolationApplicationSpec,
    ) -> Result<Self::Endpoint, IsolationBackendFailure<Self::Error>>;

    fn revoke(&mut self, endpoint: &Self::Endpoint) -> Result<(), Self::Error>;
}

#[derive(Debug, Eq, PartialEq)]
pub enum IsolationApplicationRouteError<E, Endpoint> {
    Admission(IsolationLaunchError),
    Backend {
        reason: IsolationUnavailableReason,
        error: E,
    },
    Rollback {
        admission: IsolationLaunchError,
        error: E,
        endpoint: Endpoint,
        prepared: PreparedIsolationApplicationRoute,
    },
}

#[derive(Debug, Eq, PartialEq)]
pub struct PreparedIsolationApplicationRoute {
    spec: IsolationApplicationSpec,
    launch: PreparedIsolationLaunch,
}

impl PreparedIsolationApplicationRoute {
    pub const fn spec(&self) -> IsolationApplicationSpec {
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
    ) -> Result<RoutedIsolationApplication<E>, (Self, IsolationLaunchError, E)> {
        let evidence = match self.spec.placement {
            IsolationPlacement::NativeProcess => IsolationLaunchEvidence::NativeReady,
            IsolationPlacement::Microvm => IsolationLaunchEvidence::MicrovmReady,
            _ => unreachable!("IsolationApplicationSpec rejected non-application placement"),
        };
        if let Err(error) = admission.commit(&self.launch, evidence) {
            return Err((self, error, endpoint));
        }
        Ok(RoutedIsolationApplication {
            endpoint,
            spec: self.spec,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct RoutedIsolationApplication<E> {
    endpoint: E,
    spec: IsolationApplicationSpec,
}

impl<E> RoutedIsolationApplication<E> {
    pub const fn endpoint(&self) -> &E {
        &self.endpoint
    }
    pub fn into_endpoint(self) -> E {
        self.endpoint
    }
    pub const fn spec(&self) -> IsolationApplicationSpec {
        self.spec
    }
}

/// Prepares one immutable application generation for either native-process or
/// microVM execution. Total mode rejects native placement here, before either
/// backend is called; package metadata identifies the application but grants no
/// runtime capability or authority.
pub fn prepare_isolation_application_route<const DOMAINS: usize>(
    admission: &mut IsolationAdmissionTable<DOMAINS>,
    spec: IsolationApplicationSpec,
) -> Result<PreparedIsolationApplicationRoute, IsolationLaunchError> {
    let request = IsolationLaunchRequest::new(
        spec.domain,
        spec.system_generation,
        spec.policy_generation,
        TotalMicrovmClass::MicrovmEligible,
        spec.placement,
    )?;
    admission
        .prepare(request)
        .map(|launch| PreparedIsolationApplicationRoute { spec, launch })
}

pub fn route_isolation_application<B: IsolationApplicationBackend, const DOMAINS: usize>(
    admission: &mut IsolationAdmissionTable<DOMAINS>,
    backend: &mut B,
    spec: IsolationApplicationSpec,
) -> Result<
    RoutedIsolationApplication<B::Endpoint>,
    IsolationApplicationRouteError<B::Error, B::Endpoint>,
> {
    let prepared = prepare_isolation_application_route(admission, spec)
        .map_err(IsolationApplicationRouteError::Admission)?;
    launch_prepared_isolation_application_route(admission, backend, prepared)
}

/// Launches exactly the selected application placement. Backend failure records
/// typed unavailability and never probes or falls back to the other backend.
pub fn launch_prepared_isolation_application_route<
    B: IsolationApplicationBackend,
    const DOMAINS: usize,
>(
    admission: &mut IsolationAdmissionTable<DOMAINS>,
    backend: &mut B,
    prepared: PreparedIsolationApplicationRoute,
) -> Result<
    RoutedIsolationApplication<B::Endpoint>,
    IsolationApplicationRouteError<B::Error, B::Endpoint>,
> {
    let spec = prepared.spec();
    let launched = match spec.placement {
        IsolationPlacement::NativeProcess => backend.launch_native_process(spec),
        IsolationPlacement::Microvm => backend.launch_microvm_application(spec),
        _ => unreachable!("IsolationApplicationSpec rejected non-application placement"),
    };
    let endpoint = match launched {
        Ok(endpoint) => endpoint,
        Err(failure) => {
            prepared
                .unavailable(admission, failure.reason)
                .map_err(IsolationApplicationRouteError::Admission)?;
            return Err(IsolationApplicationRouteError::Backend {
                reason: failure.reason,
                error: failure.error,
            });
        }
    };
    match prepared.commit(admission, endpoint) {
        Ok(routed) => Ok(routed),
        Err((prepared, admission_error, endpoint)) => match backend.revoke(&endpoint) {
            Ok(()) => {
                prepared
                    .cancel(admission)
                    .map_err(IsolationApplicationRouteError::Admission)?;
                Err(IsolationApplicationRouteError::Admission(admission_error))
            }
            Err(error) => Err(IsolationApplicationRouteError::Rollback {
                admission: admission_error,
                error,
                endpoint,
                prepared,
            }),
        },
    }
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
    system_generation_digest: Option<[u8; 64]>,
    interface_catalog_digest: Option<[u8; 64]>,
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
            system_generation_digest: None,
            interface_catalog_digest: None,
            policy_generation,
            slots: array::from_fn(|_| None),
            unavailable: array::from_fn(|_| None),
            unavailable_head: 0,
            unavailable_count: 0,
            next_slot_generation: 1,
            next_unavailable_sequence: 1,
        })
    }

    /// Constructs admission bound to one exact canonical SystemGeneration.
    /// A component handoff is accepted only when its generation number and
    /// digest both match this active control-plane selection.
    pub fn new_generation_bound(
        mode: IsolationMode,
        system_generation: u64,
        system_generation_digest: [u8; 64],
        policy_generation: u64,
    ) -> Result<Self, IsolationLaunchError> {
        if system_generation_digest.iter().all(|byte| *byte == 0) {
            return Err(IsolationLaunchError::InvalidSystemGeneration);
        }
        let mut table = Self::new(mode, system_generation, policy_generation)?;
        table.system_generation_digest = Some(system_generation_digest);
        Ok(table)
    }

    /// Consumes the exact active generation identity published by the
    /// capability-authorized DeploymentService activation transaction.
    pub fn new_activated(
        mode: IsolationMode,
        active: ActivatedSystemGeneration,
        policy_generation: u64,
    ) -> Result<Self, IsolationLaunchError> {
        let mut table = Self::new_generation_bound(
            mode,
            active.generation(),
            *active.generation_digest(),
            policy_generation,
        )?;
        table.interface_catalog_digest = Some(*active.interface_catalog_digest());
        Ok(table)
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

    pub const fn system_generation_digest(&self) -> Option<&[u8; 64]> {
        self.system_generation_digest.as_ref()
    }

    pub const fn interface_catalog_digest(&self) -> Option<&[u8; 64]> {
        self.interface_catalog_digest.as_ref()
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
    use crate::{MemoryBackingBackendRequest, MemoryMappingBackendRequest};

    const SYSTEM_GENERATION: u64 = 108;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum BackendError {
        Unavailable,
        Revoke,
    }

    #[derive(Default)]
    struct TransferBackingBackend {
        claimed: Option<MemoryBackingBackendRequest>,
        fail_claim: bool,
        fail_release: bool,
    }

    // SAFETY: the test backend records only an exact successful claim, leaves
    // failed claims absent, and releases only the same recorded request.
    unsafe impl MemoryObjectBackingBackend for TransferBackingBackend {
        type Error = &'static str;

        fn claim_zeroed(
            &mut self,
            request: MemoryBackingBackendRequest,
        ) -> Result<(), Self::Error> {
            if self.fail_claim {
                return Err("claim");
            }
            if self.claimed.replace(request).is_some() {
                return Err("occupied");
            }
            Ok(())
        }

        fn release_scrubbed(
            &mut self,
            request: MemoryBackingBackendRequest,
        ) -> Result<(), Self::Error> {
            if self.fail_release {
                return Err("release");
            }
            if self.claimed != Some(request) {
                return Err("substitution");
            }
            self.claimed = None;
            Ok(())
        }
    }

    #[derive(Default)]
    struct TransferMappingBackend {
        installed: Option<MemoryMappingBackendRequest>,
        fail_remove: bool,
    }

    // SAFETY: the test backend publishes and removes only the exact request it
    // records, with no aliases or partial state.
    unsafe impl MemoryMappingBackend for TransferMappingBackend {
        type Error = &'static str;

        fn install(&mut self, request: MemoryMappingBackendRequest) -> Result<(), Self::Error> {
            if self.installed.replace(request).is_some() {
                return Err("occupied");
            }
            Ok(())
        }

        fn remove(&mut self, request: MemoryMappingBackendRequest) -> Result<(), Self::Error> {
            if self.fail_remove {
                return Err("remove");
            }
            if self.installed != Some(request) {
                return Err("substitution");
            }
            self.installed = None;
            Ok(())
        }
    }

    struct DualBackend {
        native_launches: usize,
        microvm_launches: usize,
        failure: Option<IsolationUnavailableReason>,
        revoke_fails: bool,
        attachment: Option<ComponentServiceLaunchAttachment>,
    }

    unsafe impl IsolationAttachedServiceBackend for DualBackend {
        type Endpoint = u64;
        type Error = BackendError;

        fn launch_native_service_attached(
            &mut self,
            spec: IsolationServiceSpec,
            attachment: ComponentServiceLaunchAttachment,
        ) -> Result<Self::Endpoint, IsolationBackendFailure<Self::Error>> {
            self.attachment = Some(attachment);
            self.launch_native_service(spec)
        }

        fn launch_microvm_service_attached(
            &mut self,
            spec: IsolationServiceSpec,
            attachment: ComponentServiceLaunchAttachment,
        ) -> Result<Self::Endpoint, IsolationBackendFailure<Self::Error>> {
            self.attachment = Some(attachment);
            self.launch_microvm_service(spec)
        }

        fn revoke(&mut self, endpoint: &Self::Endpoint) -> Result<(), Self::Error> {
            IsolationServiceBackend::revoke(self, endpoint)
        }
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

    impl IsolationApplicationBackend for DualBackend {
        type Endpoint = u64;
        type Error = BackendError;

        fn launch_native_process(
            &mut self,
            spec: IsolationApplicationSpec,
        ) -> Result<Self::Endpoint, IsolationBackendFailure<Self::Error>> {
            self.native_launches += 1;
            if let Some(reason) = self.failure {
                Err(IsolationBackendFailure::new(
                    reason,
                    BackendError::Unavailable,
                ))
            } else {
                Ok(0x3000 | spec.application_generation())
            }
        }

        fn launch_microvm_application(
            &mut self,
            spec: IsolationApplicationSpec,
        ) -> Result<Self::Endpoint, IsolationBackendFailure<Self::Error>> {
            self.microvm_launches += 1;
            if let Some(reason) = self.failure {
                Err(IsolationBackendFailure::new(
                    reason,
                    BackendError::Unavailable,
                ))
            } else {
                Ok(0x4000 | spec.application_generation())
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
            attachment: None,
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

    fn component_launch(
        table: &mut IsolationAdmissionTable<1>,
        spec: IsolationServiceSpec,
    ) -> PreparedComponentServiceLaunch {
        let route = prepare_isolation_service_route(table, spec).unwrap();
        PreparedComponentServiceLaunch::bind(
            route,
            spec.interface(),
            spec.interface_generation(),
            spec.provider_generation(),
            spec.system_generation(),
            [0x51; 64],
            [0x61; 64],
            [0x3a; 32],
            [0x18; 64],
            [0x2f; 64],
        )
        .unwrap()
    }

    fn application_spec(placement: IsolationPlacement) -> IsolationApplicationSpec {
        IsolationApplicationSpec::new(
            ObjectId(0x71),
            ObjectId(0x4d52_4d4c_4150_50),
            12,
            [0xa5; 64],
            SYSTEM_GENERATION,
            7,
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
    fn application_spec_binds_exact_immutable_identity_and_allowed_placements() {
        let spec = application_spec(IsolationPlacement::NativeProcess);
        assert_eq!(spec.domain(), ObjectId(0x71));
        assert_eq!(spec.application(), ObjectId(0x4d52_4d4c_4150_50));
        assert_eq!(spec.application_generation(), 12);
        assert_eq!(spec.application_artifact(), [0xa5; 64]);
        assert_eq!(spec.system_generation(), SYSTEM_GENERATION);
        assert_eq!(spec.policy_generation(), 7);
        assert_eq!(spec.placement(), IsolationPlacement::NativeProcess);
        assert_eq!(
            IsolationApplicationSpec::new(
                ObjectId(1),
                ObjectId(2),
                1,
                [1; 64],
                SYSTEM_GENERATION,
                7,
                IsolationPlacement::NativeService,
            ),
            Err(IsolationApplicationSpecError::UnsupportedPlacement)
        );
        assert_eq!(
            IsolationApplicationSpec::new(
                ObjectId(1),
                ObjectId(2),
                1,
                [0; 64],
                SYSTEM_GENERATION,
                7,
                IsolationPlacement::Microvm,
            ),
            Err(IsolationApplicationSpecError::InvalidArtifactDigest)
        );
    }

    #[test]
    fn balanced_application_routes_exactly_one_selected_backend() {
        let mut native_table =
            IsolationAdmissionTable::<1>::new(IsolationMode::Balanced, SYSTEM_GENERATION, 7)
                .unwrap();
        let mut native_backend = backend();
        let native = route_isolation_application(
            &mut native_table,
            &mut native_backend,
            application_spec(IsolationPlacement::NativeProcess),
        )
        .unwrap();
        assert_eq!(native.spec().placement(), IsolationPlacement::NativeProcess);
        assert_eq!(
            (
                native_backend.native_launches,
                native_backend.microvm_launches
            ),
            (1, 0)
        );

        let mut microvm_table =
            IsolationAdmissionTable::<1>::new(IsolationMode::Balanced, SYSTEM_GENERATION, 7)
                .unwrap();
        let mut microvm_backend = backend();
        let microvm = route_isolation_application(
            &mut microvm_table,
            &mut microvm_backend,
            application_spec(IsolationPlacement::Microvm),
        )
        .unwrap();
        assert_eq!(microvm.spec().application(), native.spec().application());
        assert_eq!(
            microvm.spec().application_generation(),
            native.spec().application_generation()
        );
        assert_eq!(
            microvm.spec().application_artifact(),
            native.spec().application_artifact()
        );
        assert_eq!(microvm.spec().placement(), IsolationPlacement::Microvm);
        assert_eq!(
            (
                microvm_backend.native_launches,
                microvm_backend.microvm_launches
            ),
            (0, 1)
        );
    }

    #[test]
    fn total_application_rejects_native_before_backend_and_never_falls_back() {
        let mut table =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 7)
                .unwrap();
        let mut backend = backend();
        assert_eq!(
            route_isolation_application(
                &mut table,
                &mut backend,
                application_spec(IsolationPlacement::NativeProcess),
            ),
            Err(IsolationApplicationRouteError::Admission(
                IsolationLaunchError::TotalMicrovmDowngradeAttempt
            ))
        );
        assert_eq!((backend.native_launches, backend.microvm_launches), (0, 0));

        backend.failure = Some(IsolationUnavailableReason::VmmResource);
        assert_eq!(
            route_isolation_application(
                &mut table,
                &mut backend,
                application_spec(IsolationPlacement::Microvm),
            ),
            Err(IsolationApplicationRouteError::Backend {
                reason: IsolationUnavailableReason::VmmResource,
                error: BackendError::Unavailable,
            })
        );
        assert_eq!((backend.native_launches, backend.microvm_launches), (0, 1));
        assert_eq!(table.running().count(), 0);
        assert_eq!(
            table.unavailable_domains().next().unwrap().reason(),
            IsolationUnavailableReason::VmmResource
        );
        assert!(table.total_microvm_report().satisfied());
        assert_eq!(table.total_microvm_report().native_fallback, 0);
    }

    #[test]
    fn application_route_rejects_stale_system_and_policy_before_backend() {
        let mut table =
            IsolationAdmissionTable::<1>::new(IsolationMode::Balanced, SYSTEM_GENERATION, 7)
                .unwrap();
        let mut backend = backend();
        let stale_system = IsolationApplicationSpec::new(
            ObjectId(0x71),
            ObjectId(0x72),
            12,
            [0xa5; 64],
            SYSTEM_GENERATION - 1,
            7,
            IsolationPlacement::Microvm,
        )
        .unwrap();
        assert_eq!(
            route_isolation_application(&mut table, &mut backend, stale_system),
            Err(IsolationApplicationRouteError::Admission(
                IsolationLaunchError::InvalidSystemGeneration
            ))
        );
        let stale_policy = IsolationApplicationSpec::new(
            ObjectId(0x71),
            ObjectId(0x72),
            12,
            [0xa5; 64],
            SYSTEM_GENERATION,
            8,
            IsolationPlacement::Microvm,
        )
        .unwrap();
        assert_eq!(
            route_isolation_application(&mut table, &mut backend, stale_policy),
            Err(IsolationApplicationRouteError::Admission(
                IsolationLaunchError::InvalidPolicyGeneration
            ))
        );
        assert_eq!((backend.native_launches, backend.microvm_launches), (0, 0));
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
            [0x51; 64],
            [0x61; 64],
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
        launch
            .verify(
                ArtifactKind::ServiceImage,
                &[0x18; 64],
                ArtifactKind::ServiceImage,
                &[0x2f; 64],
            )
            .unwrap()
            .into_route()
            .commit(&mut table, 0x55aa_u64)
            .unwrap();
        assert!(table.total_microvm_report().satisfied());
    }

    #[test]
    fn attached_component_launch_owns_only_narrow_delegable_source_authority() {
        let mut table =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 7)
                .unwrap();
        let spec = service_spec(IsolationPlacement::Microvm);
        let launch = component_launch(&mut table, spec);
        let mut capabilities = CapabilitySpace::<2>::new();
        let data = capabilities
            .insert(ObjectId(0x80), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let endpoint = capabilities
            .insert(ObjectId(0x81), Rights::SIGNAL.union(Rights::DELEGATE))
            .unwrap();
        let attachment = ComponentServiceLaunchAttachment::new(
            spec,
            12,
            ObjectId(0x80),
            4,
            144,
            data,
            ObjectId(0x81),
            7,
            endpoint,
            &capabilities,
        )
        .unwrap();
        let mut backend = backend();
        let routed = launch_prepared_component_service_with_attachment(
            &mut table,
            &mut backend,
            launch,
            attachment,
            ArtifactKind::ServiceImage,
            &[0x18; 64],
            ArtifactKind::ServiceImage,
            &[0x2f; 64],
        )
        .unwrap();
        assert_eq!(backend.attachment, Some(attachment));
        assert_eq!((backend.native_launches, backend.microvm_launches), (0, 1));
        assert_eq!(routed.domain(), spec.domain());
        assert_eq!(attachment.association_generation(), 12);
        assert_eq!(attachment.launch_data_bytes(), 144);
        assert_eq!(attachment.launch_data(), data);
        assert_eq!(attachment.dependency_endpoint(), endpoint);
        assert!(table.total_microvm_report().satisfied());
    }

    #[test]
    fn native_entry_uses_only_fresh_target_space_attachment_capabilities() {
        let spec = service_spec(IsolationPlacement::NativeService);
        let mut source = CapabilitySpace::<2>::new();
        let source_data = source
            .insert(ObjectId(0x80), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let source_endpoint = source
            .insert(ObjectId(0x81), Rights::SIGNAL.union(Rights::DELEGATE))
            .unwrap();
        let attachment = ComponentServiceLaunchAttachment::new(
            spec,
            12,
            ObjectId(0x80),
            4,
            144,
            source_data,
            ObjectId(0x81),
            7,
            source_endpoint,
            &source,
        )
        .unwrap();
        let mut target = CapabilitySpace::<3>::new();
        let unrelated = target.insert(ObjectId(0x99), Rights::READ).unwrap();
        let target_data = target.insert(ObjectId(0x80), Rights::READ).unwrap();
        let target_endpoint = target.insert(ObjectId(0x81), Rights::SIGNAL).unwrap();
        let entry = NativeComponentServiceEntry::new(
            spec,
            attachment,
            ObjectId(0x90),
            ObjectId(0x91),
            ObjectId(0x92),
            target_data,
            target_endpoint,
            &target,
        )
        .unwrap();
        assert_ne!(entry.launch_data(), unrelated);
        assert_eq!(entry.launch_data(), target_data);
        assert_eq!(entry.dependency_endpoint(), target_endpoint);
        assert_eq!(entry.service_endpoint_object(), ObjectId(0x90));
        assert_eq!(entry.supervisor_task_object(), ObjectId(0x91));
        assert_eq!(entry.consumer_module_object(), ObjectId(0x92));
        assert_eq!(entry.provider_generation(), spec.provider_generation());
        assert_eq!(entry.launch_data_bytes(), 144);
        assert_ne!(entry.launch_data(), source_data);
        assert_ne!(entry.dependency_endpoint(), source_endpoint);
        let context = UserContext::new(
            crate::PhysAddr::new(0x20_0000).unwrap(),
            0x40_0000,
            0x7000_0000,
        )
        .unwrap();
        let installed = entry.install(context).unwrap();
        assert_eq!(installed.r13, 0x90);
        assert_eq!(installed.r14, 0x91);
        assert_eq!(installed.r12, spec.provider_generation());
        assert_eq!(installed.r15, target_data.token());
        assert_eq!(installed.rbx, target_endpoint.token());
        assert_eq!(installed.r11, 144);
        assert_eq!(installed.r10, 0x92);
    }

    #[test]
    fn native_entry_rejects_wrong_target_objects_and_overbroad_rights() {
        let spec = service_spec(IsolationPlacement::NativeService);
        let mut source = CapabilitySpace::<2>::new();
        let source_data = source
            .insert(ObjectId(0x80), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let source_endpoint = source
            .insert(ObjectId(0x81), Rights::SIGNAL.union(Rights::DELEGATE))
            .unwrap();
        let attachment = ComponentServiceLaunchAttachment::new(
            spec,
            12,
            ObjectId(0x80),
            4,
            144,
            source_data,
            ObjectId(0x81),
            7,
            source_endpoint,
            &source,
        )
        .unwrap();
        let mut target = CapabilitySpace::<5>::new();
        let wrong_data = target.insert(ObjectId(0x82), Rights::READ).unwrap();
        let overbroad_data = target
            .insert(ObjectId(0x80), Rights::READ.union(Rights::WRITE))
            .unwrap();
        let endpoint = target.insert(ObjectId(0x81), Rights::SIGNAL).unwrap();
        let wrong_endpoint = target.insert(ObjectId(0x83), Rights::SIGNAL).unwrap();
        let exact_data = target.insert(ObjectId(0x80), Rights::READ).unwrap();
        let create = |data, dependency| {
            NativeComponentServiceEntry::new(
                spec,
                attachment,
                ObjectId(0x90),
                ObjectId(0x91),
                ObjectId(0x92),
                data,
                dependency,
                &target,
            )
        };
        assert_eq!(
            create(wrong_data, endpoint),
            Err(NativeComponentServiceEntryError::WrongLaunchDataObject)
        );
        assert_eq!(
            create(overbroad_data, endpoint),
            Err(NativeComponentServiceEntryError::LaunchDataCapability(
                CapabilityError::PermissionDenied
            ))
        );
        assert_eq!(
            create(exact_data, wrong_endpoint),
            Err(NativeComponentServiceEntryError::WrongDependencyEndpoint)
        );
        let entry = create(exact_data, endpoint).unwrap();
        let mut occupied = UserContext::new(
            crate::PhysAddr::new(0x20_0000).unwrap(),
            0x40_0000,
            0x7000_0000,
        )
        .unwrap();
        occupied.r15 = 1;
        let (_, error, returned) = entry.install(occupied).unwrap_err();
        assert_eq!(
            error,
            NativeComponentServiceEntryError::LaunchRegistersOccupied
        );
        assert_eq!(returned.r15, 1);
    }

    #[test]
    fn native_task_construction_projects_tracks_and_installs_exact_entry() {
        let spec = service_spec(IsolationPlacement::NativeService);
        let mut runtime = TaskRuntime::<2, 4>::new(1_000, 1).unwrap();
        let source = runtime
            .create(
                crate::Priority::NORMAL,
                UserContext::new(
                    crate::PhysAddr::new(0x20_0000).unwrap(),
                    0x40_0000,
                    0x7000_0000,
                )
                .unwrap(),
            )
            .unwrap();
        let target = runtime
            .create(
                crate::Priority::NORMAL,
                UserContext::new(
                    crate::PhysAddr::new(0x30_0000).unwrap(),
                    0x50_0000,
                    0x7100_0000,
                )
                .unwrap(),
            )
            .unwrap();
        let data = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(ObjectId(0x80), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let endpoint = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(ObjectId(0x81), Rights::SIGNAL.union(Rights::DELEGATE))
            .unwrap();
        let attachment = ComponentServiceLaunchAttachment::new(
            spec,
            12,
            ObjectId(0x80),
            4,
            144,
            data,
            ObjectId(0x81),
            7,
            endpoint,
            runtime.capabilities(source).unwrap(),
        )
        .unwrap();
        let prepared = prepare_native_component_service_task(
            &mut runtime,
            source,
            target,
            spec,
            attachment,
            ObjectId(0x90),
            ObjectId(0x91),
            ObjectId(0x92),
        )
        .unwrap();
        assert_eq!(prepared.task(), target);
        let entry = prepared.entry();
        let context = runtime.context(target).unwrap();
        assert_eq!(context.r13, 0x90);
        assert_eq!(context.r14, 0x91);
        assert_eq!(context.r12, spec.provider_generation());
        assert_eq!(context.r15, entry.launch_data().token());
        assert_eq!(context.rbx, entry.dependency_endpoint().token());
        assert_eq!(context.r11, 144);
        assert_eq!(context.r10, 0x92);
        runtime.revoke_capability(source, data).unwrap();
        assert_eq!(
            runtime
                .capabilities(target)
                .unwrap()
                .authorize(entry.launch_data(), Rights::READ,),
            Err(CapabilityError::Invalid)
        );
        assert_eq!(
            runtime
                .capabilities(target)
                .unwrap()
                .authorize_exact(entry.dependency_endpoint(), Rights::SIGNAL,),
            Ok(ObjectId(0x81))
        );
    }

    #[test]
    fn read_transfer_attachment_requires_disjoint_direction_scoped_authority() {
        let mut capabilities = CapabilitySpace::<3>::new();
        let local_read = capabilities
            .insert(
                ObjectId(0xa0),
                Rights::MAP.union(Rights::READ).union(Rights::DELEGATE),
            )
            .unwrap();
        let provider_write = capabilities
            .insert(
                ObjectId(0xa0),
                Rights::MAP.union(Rights::WRITE).union(Rights::DELEGATE),
            )
            .unwrap();
        let wrong_object = capabilities
            .insert(
                ObjectId(0xa1),
                Rights::MAP.union(Rights::WRITE).union(Rights::DELEGATE),
            )
            .unwrap();
        let attachment = ComponentServiceReadTransferAttachment::new(
            TaskId::from_token((3_u64 << 32) | 2),
            ObjectId(0xa0),
            9,
            4096,
            local_read,
            provider_write,
            &capabilities,
        )
        .unwrap();
        assert_eq!(attachment.provider_task().token(), (3_u64 << 32) | 2);
        assert_eq!(attachment.shared_object(), ObjectId(0xa0));
        assert_eq!(attachment.shared_generation(), 9);
        assert_eq!(attachment.shared_bytes(), 4096);
        assert_eq!(attachment.local_read(), local_read);
        assert_eq!(attachment.provider_write(), provider_write);
        assert_eq!(
            ComponentServiceReadTransferAttachment::new(
                TaskId::from_token((3_u64 << 32) | 2),
                ObjectId(0xa0),
                9,
                4096,
                local_read,
                wrong_object,
                &capabilities,
            ),
            Err(ComponentServiceReadTransferAttachmentError::WrongProviderWriteObject)
        );
        assert_eq!(
            ComponentServiceReadTransferAttachment::new(
                TaskId::from_token((3_u64 << 32) | 2),
                ObjectId(0xa0),
                9,
                4096,
                local_read,
                local_read,
                &capabilities,
            ),
            Err(ComponentServiceReadTransferAttachmentError::CapabilityAlias)
        );
    }

    #[test]
    fn read_transfer_memory_reservation_charges_one_exact_shared_page() {
        let mut runtime = TaskRuntime::<3, 8>::new(1_000, 1).unwrap();
        let source = runtime
            .create(
                crate::Priority::NORMAL,
                UserContext::new(
                    crate::PhysAddr::new(0x20_0000).unwrap(),
                    0x40_0000,
                    0x7000_0000,
                )
                .unwrap(),
            )
            .unwrap();
        let local_task = runtime
            .create(
                crate::Priority::NORMAL,
                UserContext::new(
                    crate::PhysAddr::new(0x30_0000).unwrap(),
                    0x50_0000,
                    0x7100_0000,
                )
                .unwrap(),
            )
            .unwrap();
        let provider_task = runtime
            .create(
                crate::Priority::NORMAL,
                UserContext::new(
                    crate::PhysAddr::new(0x40_0000).unwrap(),
                    0x60_0000,
                    0x7200_0000,
                )
                .unwrap(),
            )
            .unwrap();
        let mut memory = MemoryPoolTable::<1, 1, 3>::new(0x2a).unwrap();
        let pool_rights = Rights::ALLOCATE
            .union(Rights::CONTROL)
            .union(Rights::INSPECT);
        let (pool, pool_capability) = memory
            .create_root(
                1,
                3,
                0,
                pool_rights,
                runtime.capabilities_mut(source).unwrap(),
            )
            .unwrap();

        let reservation = reserve_component_service_read_transfer_memory(
            &mut memory,
            pool,
            pool_capability,
            &mut runtime,
            source,
        )
        .unwrap();
        assert_eq!(reservation.generation(), 1);
        assert_eq!(reservation.bytes(), PAGE_SIZE as u32);
        assert_eq!(
            runtime.capabilities(source).unwrap().authorize_exact(
                reservation.root(),
                COMPONENT_SERVICE_READ_TRANSFER_ROOT_RIGHTS,
            ),
            Ok(reservation.shared_object())
        );
        let usage = memory
            .usage(pool, pool_capability, runtime.capabilities(source).unwrap())
            .unwrap();
        assert_eq!(usage.object_pages(), 1);
        assert_eq!(usage.live_objects(), 1);
        assert_eq!(usage.active_mappings(), 0);

        let physical =
            MemoryPhysicalBacking::new(crate::PhysAddr::new(0x40_0000).unwrap(), 1).unwrap();
        let mut backend = TransferBackingBackend {
            fail_claim: true,
            ..TransferBackingBackend::default()
        };
        assert_eq!(
            bind_component_service_read_transfer_backing(
                &mut memory,
                reservation,
                physical,
                &runtime,
                source,
                &mut backend,
            ),
            Err(ComponentServiceReadTransferBackingError::Backing(
                MemoryBackingOperationError::Backend("claim")
            ))
        );
        assert!(backend.claimed.is_none());
        backend.fail_claim = false;
        bind_component_service_read_transfer_backing(
            &mut memory,
            reservation,
            physical,
            &runtime,
            source,
            &mut backend,
        )
        .unwrap();
        assert!(backend.claimed.is_some());
        let local_target = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(
                ObjectId(0x7100),
                COMPONENT_SERVICE_READ_TRANSFER_TARGET_RIGHTS,
            )
            .unwrap();
        let provider_target = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(
                ObjectId(0x7200),
                COMPONENT_SERVICE_READ_TRANSFER_TARGET_RIGHTS,
            )
            .unwrap();
        let mut local_mapping = TransferMappingBackend::default();
        let mut provider_mapping = TransferMappingBackend::default();
        assert_eq!(
            install_component_service_read_transfer_mappings(
                &mut memory,
                reservation,
                local_target,
                0x300,
                &mut local_mapping,
                local_target,
                0x400,
                &mut provider_mapping,
                &runtime,
                source,
            ),
            Err(ComponentServiceReadTransferMappingError::TargetAlias)
        );
        assert!(local_mapping.installed.is_none());
        assert!(provider_mapping.installed.is_none());
        let mappings = install_component_service_read_transfer_mappings(
            &mut memory,
            reservation,
            local_target,
            0x300,
            &mut local_mapping,
            provider_target,
            0x400,
            &mut provider_mapping,
            &runtime,
            source,
        )
        .unwrap();
        assert_eq!(mappings.local_target(), ObjectId(0x7100));
        assert_eq!(mappings.provider_target(), ObjectId(0x7200));
        assert_eq!(mappings.memory_object(), reservation.memory_object());
        assert_eq!(mappings.shared_object(), reservation.shared_object());
        assert_eq!(mappings.local_target_capability(), local_target);
        assert_eq!(mappings.provider_target_capability(), provider_target);
        assert_eq!(mappings.local_virtual_page(), 0x300);
        assert_eq!(mappings.provider_virtual_page(), 0x400);
        assert_eq!(
            bind_component_service_read_transfer_tasks(mappings, local_task, local_task, &runtime,),
            Err(ComponentServiceReadTransferTaskBindingError::TaskAlias)
        );
        let binding = bind_component_service_read_transfer_tasks(
            mappings,
            local_task,
            provider_task,
            &runtime,
        )
        .unwrap();
        assert_eq!(binding.mappings(), mappings);
        assert_eq!(binding.local_task(), local_task);
        assert_eq!(binding.provider_task(), provider_task);
        let mut copy_local_backend = TransferMappingBackend::default();
        let local = install_component_service_read_transfer_local_mapping(
            &mut memory,
            reservation,
            local_target,
            0x500,
            &mut copy_local_backend,
            &runtime,
            source,
        )
        .unwrap();
        assert_eq!(local.memory_object(), reservation.memory_object());
        assert_eq!(local.shared_object(), reservation.shared_object());
        assert_eq!(local.local_target(), ObjectId(0x7100));
        assert_eq!(local.local_target_capability(), local_target);
        assert_eq!(local.local_virtual_page(), 0x500);
        assert_eq!(
            copy_local_backend.installed.unwrap().mapping().access(),
            Rights::READ
        );
        assert_eq!(
            bind_component_service_read_transfer_copy_tasks(
                local, local_task, local_task, &runtime,
            ),
            Err(ComponentServiceReadTransferTaskBindingError::TaskAlias)
        );
        let copy_binding = bind_component_service_read_transfer_copy_tasks(
            local,
            local_task,
            provider_task,
            &runtime,
        )
        .unwrap();
        assert_eq!(copy_binding.mapping(), local);
        assert_eq!(copy_binding.local_task(), local_task);
        assert_eq!(copy_binding.provider_task(), provider_task);
        memory
            .remove_mapping(
                local.mapping(),
                local.local_target_capability(),
                runtime.capabilities(source).unwrap(),
                &mut copy_local_backend,
            )
            .unwrap();
        let spec = service_spec(IsolationPlacement::NativeService);
        let data = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(ObjectId(0x80), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let endpoint = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(ObjectId(0x81), Rights::SIGNAL.union(Rights::DELEGATE))
            .unwrap();
        let launch = ComponentServiceLaunchAttachment::new(
            spec,
            12,
            ObjectId(0x80),
            4,
            144,
            data,
            ObjectId(0x81),
            7,
            endpoint,
            runtime.capabilities(source).unwrap(),
        )
        .unwrap();
        let constructed = prepare_native_component_service_task_from_mapped_read_transfer(
            &mut runtime,
            source,
            local_task,
            spec,
            launch,
            reservation,
            binding,
            ObjectId(0x90),
            ObjectId(0x91),
            ObjectId(0x92),
        )
        .unwrap();
        assert_eq!(constructed.memory(), reservation);
        assert_eq!(constructed.binding(), binding);
        assert_eq!(constructed.construction().task(), local_task);
        let source_attachment = constructed.source_attachment(&runtime).unwrap();
        assert_eq!(source_attachment.provider_task(), provider_task);
        assert_eq!(
            source_attachment.shared_object(),
            reservation.shared_object()
        );
        assert_eq!(
            source_attachment.shared_generation(),
            reservation.generation()
        );
        assert_eq!(source_attachment.shared_bytes(), reservation.bytes());
        assert_eq!(
            source_attachment.local_read(),
            constructed.construction().source_local_read()
        );
        assert_eq!(
            source_attachment.provider_write(),
            constructed.construction().source_provider_write()
        );
        let wrong_generation = ComponentServiceReadTransferAttachment::new(
            provider_task,
            reservation.shared_object(),
            reservation.generation() + 1,
            reservation.bytes(),
            source_attachment.local_read(),
            source_attachment.provider_write(),
            runtime.capabilities(source).unwrap(),
        )
        .unwrap();
        assert_eq!(
            prepare_native_component_service_task_from_mapped_read_transfer_attachment(
                &mut runtime,
                source,
                local_task,
                spec,
                launch,
                wrong_generation,
                reservation,
                binding,
                ObjectId(0x90),
                ObjectId(0x91),
                ObjectId(0x92),
            ),
            Err(NativeComponentServiceMappedReadTransferError::BindingMismatch)
        );
        assert_eq!(
            local_mapping.installed.unwrap().mapping().access(),
            Rights::READ
        );
        assert_eq!(
            provider_mapping.installed.unwrap().mapping().access(),
            Rights::WRITE
        );
        let state = match teardown_native_component_service_mapped_read_transfer(
            NativeComponentServiceMappedReadTransferTeardown::new(constructed),
            &mut runtime,
            &mut memory,
            &mut local_mapping,
            &mut provider_mapping,
            &mut backend,
        ) {
            Err(NativeComponentServiceMappedReadTransferTeardownError::TaskStillLive {
                state,
                task,
            }) => {
                assert_eq!(task, local_task);
                assert_eq!(
                    NativeComponentServiceMappedReadTransferTeardownError::<(), (), ()>::TaskStillLive {
                        state,
                        task,
                    }
                    .state(),
                    state
                );
                state
            }
            other => panic!("unexpected live-task teardown result: {other:?}"),
        };
        runtime.start();
        runtime.yield_current().unwrap();
        assert_eq!(runtime.current(), Some(local_task));
        assert_eq!(runtime.terminate_current().unwrap().task, local_task);
        provider_mapping.fail_remove = true;
        let state = match teardown_native_component_service_mapped_read_transfer(
            state,
            &mut runtime,
            &mut memory,
            &mut local_mapping,
            &mut provider_mapping,
            &mut backend,
        ) {
            Err(NativeComponentServiceMappedReadTransferTeardownError::ProviderMapping {
                state,
                error: MemoryMappingOperationError::Backend("remove"),
            }) => state,
            other => panic!("unexpected provider teardown result: {other:?}"),
        };
        assert!(state.authority_revoked());
        assert_eq!(
            runtime.context(local_task),
            Err(TaskRuntimeError::MissingTask)
        );
        assert_eq!(state.mappings().first(), Some(mappings.mappings().first()));
        assert_eq!(
            state.mappings().second(),
            Some(mappings.mappings().second())
        );
        provider_mapping.fail_remove = false;
        local_mapping.fail_remove = true;
        let state = match teardown_native_component_service_mapped_read_transfer(
            state,
            &mut runtime,
            &mut memory,
            &mut local_mapping,
            &mut provider_mapping,
            &mut backend,
        ) {
            Err(NativeComponentServiceMappedReadTransferTeardownError::LocalMapping {
                state,
                error: MemoryMappingOperationError::Backend("remove"),
            }) => state,
            other => panic!("unexpected local teardown result: {other:?}"),
        };
        assert_eq!(state.mappings().first(), Some(mappings.mappings().first()));
        assert_eq!(state.mappings().second(), None);
        local_mapping.fail_remove = false;
        backend.fail_release = true;
        let state = match teardown_native_component_service_mapped_read_transfer(
            state,
            &mut runtime,
            &mut memory,
            &mut local_mapping,
            &mut provider_mapping,
            &mut backend,
        ) {
            Err(NativeComponentServiceMappedReadTransferTeardownError::Backing {
                state,
                error: MemoryBackingOperationError::Backend("release"),
            }) => state,
            other => panic!("unexpected backing teardown result: {other:?}"),
        };
        assert!(state.mappings().complete());
        assert!(!state.backing_released());
        backend.fail_release = false;
        assert_eq!(
            teardown_native_component_service_mapped_read_transfer(
                state,
                &mut runtime,
                &mut memory,
                &mut local_mapping,
                &mut provider_mapping,
                &mut backend,
            ),
            Ok(1)
        );
        let usage = memory
            .usage(pool, pool_capability, runtime.capabilities(source).unwrap())
            .unwrap();
        assert_eq!(usage.object_pages(), 0);
        assert_eq!(usage.live_objects(), 0);
    }

    #[test]
    fn copy_read_transfer_constructs_and_tears_down_one_mapping() {
        let spec = service_spec(IsolationPlacement::NativeService);
        let mut runtime = TaskRuntime::<3, 8>::new(1_000, 1).unwrap();
        let source = runtime
            .create(
                crate::Priority::NORMAL,
                UserContext::new(
                    crate::PhysAddr::new(0x20_0000).unwrap(),
                    0x40_0000,
                    0x7000_0000,
                )
                .unwrap(),
            )
            .unwrap();
        let target = runtime
            .create(
                crate::Priority::NORMAL,
                UserContext::new(
                    crate::PhysAddr::new(0x30_0000).unwrap(),
                    0x50_0000,
                    0x7100_0000,
                )
                .unwrap(),
            )
            .unwrap();
        let provider = runtime
            .create(
                crate::Priority::NORMAL,
                UserContext::new(
                    crate::PhysAddr::new(0x40_0000).unwrap(),
                    0x60_0000,
                    0x7200_0000,
                )
                .unwrap(),
            )
            .unwrap();
        let mut memory = MemoryPoolTable::<1, 1, 1>::new(0x2b).unwrap();
        let pool_rights = Rights::ALLOCATE
            .union(Rights::CONTROL)
            .union(Rights::INSPECT);
        let (pool, pool_capability) = memory
            .create_root(
                1,
                1,
                0,
                pool_rights,
                runtime.capabilities_mut(source).unwrap(),
            )
            .unwrap();
        let root = reserve_component_service_read_transfer_memory(
            &mut memory,
            pool,
            pool_capability,
            &mut runtime,
            source,
        )
        .unwrap();
        let physical =
            MemoryPhysicalBacking::new(crate::PhysAddr::new(0x50_0000).unwrap(), 1).unwrap();
        let mut backing = TransferBackingBackend::default();
        bind_component_service_read_transfer_backing(
            &mut memory,
            root,
            physical,
            &runtime,
            source,
            &mut backing,
        )
        .unwrap();
        let local_target = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(
                ObjectId(0x7300),
                COMPONENT_SERVICE_READ_TRANSFER_TARGET_RIGHTS,
            )
            .unwrap();
        let mut mapping_backend = TransferMappingBackend::default();
        let mapping = install_component_service_read_transfer_local_mapping(
            &mut memory,
            root,
            local_target,
            0x500,
            &mut mapping_backend,
            &runtime,
            source,
        )
        .unwrap();
        let binding =
            bind_component_service_read_transfer_copy_tasks(mapping, target, provider, &runtime)
                .unwrap();
        let data = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(ObjectId(0x80), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let endpoint = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(ObjectId(0x81), Rights::SIGNAL.union(Rights::DELEGATE))
            .unwrap();
        let launch = ComponentServiceLaunchAttachment::new(
            spec,
            12,
            ObjectId(0x80),
            4,
            144,
            data,
            ObjectId(0x81),
            7,
            endpoint,
            runtime.capabilities(source).unwrap(),
        )
        .unwrap();
        let transfer = prepare_component_service_read_transfer_attachment(
            &mut runtime,
            source,
            provider,
            root.shared_object(),
            root.generation(),
            root.bytes(),
            root.root(),
        )
        .unwrap();
        let active = prepare_native_component_service_task_from_copy_read_transfer_attachment(
            &mut runtime,
            source,
            target,
            spec,
            launch,
            transfer,
            root,
            binding,
            crate::PhysAddr::new(0x30_0000).unwrap(),
            ObjectId(0x90),
            ObjectId(0x91),
            ObjectId(0x92),
        )
        .unwrap();
        assert_eq!(active.binding(), binding);
        assert_eq!(active.page_table_root().get(), 0x30_0000);
        assert_eq!(active.source_attachment(&runtime).unwrap(), transfer);
        assert!(mapping_backend.installed.is_some());
        assert_eq!(
            retire_current_native_component_service_copy_read_transfer(active, &mut runtime),
            Err(NativeComponentServiceCopyReadTransferRetirementError::NotCurrent)
        );
        assert_eq!(
            unsafe {
                retire_current_native_component_service_copy_read_transfer_on_active_x86_64(
                    active,
                    &mut runtime,
                    &mut memory,
                )
            },
            Err(
                NativeComponentServiceCopyReadTransferActiveRetirementError::Retirement(
                    NativeComponentServiceCopyReadTransferRetirementError::NotCurrent
                )
            )
        );
        let state = match teardown_native_component_service_copy_read_transfer(
            NativeComponentServiceCopyReadTransferTeardown::new(active),
            &mut runtime,
            &mut memory,
            &mut mapping_backend,
            &mut backing,
        ) {
            Err(NativeComponentServiceCopyReadTransferTeardownError::TaskStillLive {
                state,
                task,
            }) => {
                assert_eq!(task, target);
                state
            }
            other => panic!("unexpected live copy teardown result: {other:?}"),
        };
        runtime.start();
        runtime.yield_current().unwrap();
        assert_eq!(runtime.current(), Some(target));
        assert!(state.is_pristine());
        let (termination, state) =
            retire_current_native_component_service_copy_read_transfer_with_mapping_revocation(
                state.active(),
                &mut runtime,
                &mut memory,
                &mut mapping_backend,
            )
            .unwrap();
        assert_eq!(termination.task, target);
        assert_eq!(
            state.retired_context().unwrap().page_table(),
            active.page_table_root()
        );
        assert!(!state.authority_revoked());
        assert!(state.mapping_removed());
        mapping_backend.fail_remove = true;
        backing.fail_release = true;
        let state = match teardown_native_component_service_copy_read_transfer(
            state,
            &mut runtime,
            &mut memory,
            &mut mapping_backend,
            &mut backing,
        ) {
            Err(NativeComponentServiceCopyReadTransferTeardownError::Backing {
                state,
                error: MemoryBackingOperationError::Backend("release"),
            }) => state,
            other => panic!("unexpected copy backing teardown result: {other:?}"),
        };
        assert!(state.mapping_removed());
        assert!(!state.backing_released());
        backing.fail_release = false;
        assert_eq!(
            teardown_native_component_service_copy_read_transfer(
                state,
                &mut runtime,
                &mut memory,
                &mut mapping_backend,
                &mut backing,
            ),
            Ok(1)
        );
        let usage = memory
            .usage(pool, pool_capability, runtime.capabilities(source).unwrap())
            .unwrap();
        assert_eq!(
            (
                usage.object_pages(),
                usage.live_objects(),
                usage.active_mappings()
            ),
            (0, 0, 0)
        );
        assert!(matches!(
            teardown_native_component_service_copy_read_transfer(
                NativeComponentServiceCopyReadTransferTeardown::new(active),
                &mut runtime,
                &mut memory,
                &mut mapping_backend,
                &mut backing,
            ),
            Err(
                NativeComponentServiceCopyReadTransferTeardownError::RetirementMissing {
                    task,
                    ..
                }
            ) if task == target
        ));
    }

    #[test]
    fn read_transfer_preparation_splits_one_exact_root_and_tracks_revocation() {
        let mut runtime = TaskRuntime::<2, 3>::new(1_000, 1).unwrap();
        let source = runtime
            .create(
                crate::Priority::NORMAL,
                UserContext::new(
                    crate::PhysAddr::new(0x20_0000).unwrap(),
                    0x40_0000,
                    0x7000_0000,
                )
                .unwrap(),
            )
            .unwrap();
        let provider = runtime
            .create(
                crate::Priority::NORMAL,
                UserContext::new(
                    crate::PhysAddr::new(0x30_0000).unwrap(),
                    0x50_0000,
                    0x7100_0000,
                )
                .unwrap(),
            )
            .unwrap();
        let root_rights = Rights::MAP
            .union(Rights::READ)
            .union(Rights::WRITE)
            .union(Rights::PIN)
            .union(Rights::CONTROL)
            .union(Rights::DELEGATE);
        let root = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(ObjectId(0xa0), root_rights)
            .unwrap();
        let attachment = prepare_component_service_read_transfer_attachment(
            &mut runtime,
            source,
            provider,
            ObjectId(0xa0),
            9,
            4096,
            root,
        )
        .unwrap();
        assert_eq!(attachment.provider_task(), provider);
        assert_eq!(attachment.shared_object(), ObjectId(0xa0));
        runtime.revoke_capability(source, root).unwrap();
        assert_eq!(
            runtime
                .capabilities(source)
                .unwrap()
                .authorize(attachment.local_read(), Rights::READ),
            Err(CapabilityError::Invalid)
        );
        assert_eq!(
            runtime
                .capabilities(source)
                .unwrap()
                .authorize(attachment.provider_write(), Rights::WRITE),
            Err(CapabilityError::Invalid)
        );
    }

    #[test]
    fn native_read_transfer_construction_projects_exact_split_authority() {
        let spec = service_spec(IsolationPlacement::NativeService);
        let mut runtime = TaskRuntime::<3, 4>::new(1_000, 1).unwrap();
        let source = runtime
            .create(
                crate::Priority::NORMAL,
                UserContext::new(
                    crate::PhysAddr::new(0x20_0000).unwrap(),
                    0x40_0000,
                    0x7000_0000,
                )
                .unwrap(),
            )
            .unwrap();
        let target = runtime
            .create(
                crate::Priority::NORMAL,
                UserContext::new(
                    crate::PhysAddr::new(0x30_0000).unwrap(),
                    0x50_0000,
                    0x7100_0000,
                )
                .unwrap(),
            )
            .unwrap();
        let provider = runtime
            .create(
                crate::Priority::NORMAL,
                UserContext::new(
                    crate::PhysAddr::new(0x40_0000).unwrap(),
                    0x60_0000,
                    0x7200_0000,
                )
                .unwrap(),
            )
            .unwrap();
        let source_capabilities = runtime.capabilities_mut(source).unwrap();
        let data = source_capabilities
            .insert(ObjectId(0x80), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let endpoint = source_capabilities
            .insert(ObjectId(0x81), Rights::SIGNAL.union(Rights::DELEGATE))
            .unwrap();
        let local_read = source_capabilities
            .insert(
                ObjectId(0xa0),
                Rights::MAP.union(Rights::READ).union(Rights::DELEGATE),
            )
            .unwrap();
        let provider_write = source_capabilities
            .insert(
                ObjectId(0xa0),
                Rights::MAP.union(Rights::WRITE).union(Rights::DELEGATE),
            )
            .unwrap();
        let attachment = ComponentServiceLaunchAttachment::new(
            spec,
            12,
            ObjectId(0x80),
            4,
            144,
            data,
            ObjectId(0x81),
            7,
            endpoint,
            runtime.capabilities(source).unwrap(),
        )
        .unwrap();
        let transfer = ComponentServiceReadTransferAttachment::new(
            provider,
            ObjectId(0xa0),
            9,
            4096,
            local_read,
            provider_write,
            runtime.capabilities(source).unwrap(),
        )
        .unwrap();
        let stale_provider = ComponentServiceReadTransferAttachment::new(
            TaskId::from_token(provider.token() + (1_u64 << 32)),
            ObjectId(0xa0),
            9,
            4096,
            local_read,
            provider_write,
            runtime.capabilities(source).unwrap(),
        )
        .unwrap();
        assert_eq!(
            prepare_native_component_service_task_with_read_transfer(
                &mut runtime,
                source,
                target,
                spec,
                attachment,
                stale_provider,
                ObjectId(0x90),
                ObjectId(0x91),
                ObjectId(0x92),
            ),
            Err(NativeComponentServiceTaskError::Runtime(
                TaskRuntimeError::MissingTask
            ))
        );
        let prepared = prepare_native_component_service_task_with_read_transfer(
            &mut runtime,
            source,
            target,
            spec,
            attachment,
            transfer,
            ObjectId(0x90),
            ObjectId(0x91),
            ObjectId(0x92),
        )
        .unwrap();
        let context = runtime.context(target).unwrap();
        assert_eq!(context.rbp, prepared.local_read().token());
        assert_eq!(context.rsi, prepared.provider_write().token());
        assert_eq!(context.r9, transfer.shared_generation());
        assert_eq!(context.r8, u64::from(transfer.shared_bytes()));
        assert_eq!(context.rdx, provider.token());
        assert_eq!(prepared.source_local_read(), local_read);
        assert_eq!(prepared.source_provider_write(), provider_write);
        let target_capabilities = runtime.capabilities(target).unwrap();
        assert_eq!(
            target_capabilities
                .authorize_exact(prepared.local_read(), Rights::MAP.union(Rights::READ),),
            Ok(ObjectId(0xa0))
        );
        assert_eq!(
            target_capabilities.authorize_exact(
                prepared.provider_write(),
                Rights::MAP.union(Rights::WRITE).union(Rights::DELEGATE),
            ),
            Ok(ObjectId(0xa0))
        );
        runtime
            .revoke_capability(source, prepared.source_provider_write())
            .unwrap();
        assert_eq!(
            runtime
                .capabilities(target)
                .unwrap()
                .authorize(prepared.provider_write(), Rights::WRITE,),
            Err(CapabilityError::Invalid)
        );
        assert_eq!(
            runtime
                .capabilities(target)
                .unwrap()
                .authorize_exact(prepared.local_read(), Rights::MAP.union(Rights::READ),),
            Ok(ObjectId(0xa0))
        );
    }

    #[test]
    fn rooted_read_transfer_construction_rolls_back_both_domains_on_entry_failure() {
        let spec = service_spec(IsolationPlacement::NativeService);
        let mut runtime = TaskRuntime::<3, 5>::new(1_000, 1).unwrap();
        let source = runtime
            .create(
                crate::Priority::NORMAL,
                UserContext::new(
                    crate::PhysAddr::new(0x20_0000).unwrap(),
                    0x40_0000,
                    0x7000_0000,
                )
                .unwrap(),
            )
            .unwrap();
        let target = runtime
            .create(
                crate::Priority::NORMAL,
                UserContext::new(
                    crate::PhysAddr::new(0x30_0000).unwrap(),
                    0x50_0000,
                    0x7100_0000,
                )
                .unwrap(),
            )
            .unwrap();
        let provider = runtime
            .create(
                crate::Priority::NORMAL,
                UserContext::new(
                    crate::PhysAddr::new(0x40_0000).unwrap(),
                    0x60_0000,
                    0x7200_0000,
                )
                .unwrap(),
            )
            .unwrap();
        let source_capabilities = runtime.capabilities_mut(source).unwrap();
        let data = source_capabilities
            .insert(ObjectId(0x80), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let endpoint = source_capabilities
            .insert(ObjectId(0x81), Rights::SIGNAL.union(Rights::DELEGATE))
            .unwrap();
        let root_rights = Rights::MAP
            .union(Rights::READ)
            .union(Rights::WRITE)
            .union(Rights::PIN)
            .union(Rights::CONTROL)
            .union(Rights::DELEGATE);
        let root = source_capabilities
            .insert(ObjectId(0xa0), root_rights)
            .unwrap();
        let launch = ComponentServiceLaunchAttachment::new(
            spec,
            12,
            ObjectId(0x80),
            4,
            144,
            data,
            ObjectId(0x81),
            7,
            endpoint,
            runtime.capabilities(source).unwrap(),
        )
        .unwrap();
        assert_eq!(
            prepare_native_component_service_task_from_read_transfer_root(
                &mut runtime,
                source,
                target,
                spec,
                launch,
                provider,
                ObjectId(0xa0),
                9,
                4096,
                root,
                ObjectId(0x90),
                ObjectId(0x90),
                ObjectId(0x92),
            ),
            Err(NativeComponentServiceReadTransferRootError::Task(
                NativeComponentServiceTaskError::Entry(
                    NativeComponentServiceEntryError::InvalidIdentity
                )
            ))
        );
        assert_eq!(
            runtime
                .capabilities(source)
                .unwrap()
                .authorize_exact(root, root_rights),
            Ok(ObjectId(0xa0))
        );
        let target_capabilities = runtime.capabilities_mut(target).unwrap();
        for object in 1..=5 {
            assert!(
                target_capabilities
                    .insert(ObjectId(object), Rights::READ)
                    .is_ok()
            );
        }
        let source_capabilities = runtime.capabilities_mut(source).unwrap();
        assert!(
            source_capabilities
                .insert(ObjectId(0xb0), Rights::READ)
                .is_ok()
        );
        assert!(
            source_capabilities
                .insert(ObjectId(0xb1), Rights::WRITE)
                .is_ok()
        );
    }

    #[test]
    fn native_task_construction_rolls_back_projection_before_entry_failure() {
        let spec = service_spec(IsolationPlacement::NativeService);
        let mut runtime = TaskRuntime::<2, 4>::new(1_000, 1).unwrap();
        let source = runtime
            .create(
                crate::Priority::NORMAL,
                UserContext::new(
                    crate::PhysAddr::new(0x20_0000).unwrap(),
                    0x40_0000,
                    0x7000_0000,
                )
                .unwrap(),
            )
            .unwrap();
        let target_context = UserContext::new(
            crate::PhysAddr::new(0x30_0000).unwrap(),
            0x50_0000,
            0x7100_0000,
        )
        .unwrap();
        let target = runtime
            .create(crate::Priority::NORMAL, target_context)
            .unwrap();
        let data = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(ObjectId(0x80), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let endpoint = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(ObjectId(0x81), Rights::SIGNAL.union(Rights::DELEGATE))
            .unwrap();
        let attachment = ComponentServiceLaunchAttachment::new(
            spec,
            12,
            ObjectId(0x80),
            4,
            144,
            data,
            ObjectId(0x81),
            7,
            endpoint,
            runtime.capabilities(source).unwrap(),
        )
        .unwrap();
        assert_eq!(
            prepare_native_component_service_task(
                &mut runtime,
                source,
                target,
                spec,
                attachment,
                ObjectId(0x90),
                ObjectId(0x90),
                ObjectId(0x92),
            ),
            Err(NativeComponentServiceTaskError::Entry(
                NativeComponentServiceEntryError::InvalidIdentity
            ))
        );
        assert_eq!(runtime.context(target).unwrap(), &target_context);
        let target_capabilities = runtime.capabilities_mut(target).unwrap();
        assert!(
            target_capabilities
                .insert(ObjectId(1), Rights::READ)
                .is_ok()
        );
        assert!(
            target_capabilities
                .insert(ObjectId(2), Rights::SIGNAL)
                .is_ok()
        );
    }

    #[test]
    fn attachment_identity_or_rights_substitution_fails_before_backend_launch() {
        let mut table =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 7)
                .unwrap();
        let spec = service_spec(IsolationPlacement::Microvm);
        let launch = component_launch(&mut table, spec);
        let mut capabilities = CapabilitySpace::<2>::new();
        let data = capabilities
            .insert(
                ObjectId(0x80),
                Rights::READ.union(Rights::WRITE).union(Rights::DELEGATE),
            )
            .unwrap();
        let endpoint = capabilities
            .insert(ObjectId(0x81), Rights::SIGNAL.union(Rights::DELEGATE))
            .unwrap();
        assert_eq!(
            ComponentServiceLaunchAttachment::new(
                spec,
                12,
                ObjectId(0x80),
                4,
                144,
                data,
                ObjectId(0x81),
                7,
                endpoint,
                &capabilities,
            ),
            Err(ComponentServiceLaunchAttachmentError::Capability(
                CapabilityError::PermissionDenied
            ))
        );

        let mut capabilities = CapabilitySpace::<2>::new();
        let data = capabilities
            .insert(ObjectId(0x80), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let endpoint = capabilities
            .insert(ObjectId(0x81), Rights::SIGNAL.union(Rights::DELEGATE))
            .unwrap();
        let other = IsolationServiceSpec::new(
            ObjectId(0x44),
            spec.interface(),
            spec.interface_generation(),
            spec.provider_generation(),
            spec.system_generation(),
            spec.policy_generation(),
            spec.class(),
            spec.placement(),
        )
        .unwrap();
        let attachment = ComponentServiceLaunchAttachment::new(
            other,
            12,
            ObjectId(0x80),
            4,
            144,
            data,
            ObjectId(0x81),
            7,
            endpoint,
            &capabilities,
        )
        .unwrap();
        let mut backend = backend();
        let error = launch_prepared_component_service_with_attachment(
            &mut table,
            &mut backend,
            launch,
            attachment,
            ArtifactKind::ServiceImage,
            &[0x18; 64],
            ArtifactKind::ServiceImage,
            &[0x2f; 64],
        )
        .unwrap_err();
        let PreparedAttachedComponentServiceRouteError::AttachmentMismatch { launch, .. } = error
        else {
            panic!("substituted attachment must return the retained launch");
        };
        assert_eq!((backend.native_launches, backend.microvm_launches), (0, 0));
        launch.into_route().cancel(&mut table).unwrap();
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
            [0x51; 64],
            [0x61; 64],
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
    fn canonical_handoff_revalidates_active_generation_before_backend_launch() {
        let handoff = ComponentServiceLaunchHandoff::new(
            SYSTEM_GENERATION,
            7,
            0x43,
            0x434f_4e46_4947,
            1,
            9,
            ComponentServicePlacement::Microvm,
            [0x51; 64],
            [0x61; 64],
            [0x3a; 32],
            [0x18; 64],
            [0x2f; 64],
        )
        .unwrap();
        let active =
            ActivatedSystemGeneration::new(SYSTEM_GENERATION, [0x51; 64], [0x61; 64], 1, 0x500, 1)
                .unwrap();
        let mut table =
            IsolationAdmissionTable::<1>::new_activated(IsolationMode::TotalMicrovm, active, 7)
                .unwrap();
        let launch = prepare_component_service_handoff(&mut table, &handoff.encode()).unwrap();
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
        assert_eq!(routed.system_generation(), SYSTEM_GENERATION);
        assert_eq!(routed.placement(), IsolationPlacement::Microvm);
        assert_eq!((backend.native_launches, backend.microvm_launches), (0, 1));

        let stale = ComponentServiceLaunchHandoff::new(
            SYSTEM_GENERATION - 1,
            7,
            0x44,
            0x434f_4e46_4947,
            1,
            9,
            ComponentServicePlacement::Microvm,
            [0x51; 64],
            [0x61; 64],
            [0x3a; 32],
            [0x18; 64],
            [0x2f; 64],
        )
        .unwrap();
        assert_eq!(
            prepare_component_service_handoff(&mut table, &stale.encode()),
            Err(ComponentServiceHandoffError::Admission(
                IsolationLaunchError::InvalidSystemGeneration
            ))
        );
        assert_eq!((backend.native_launches, backend.microvm_launches), (0, 1));

        let substituted_generation = ComponentServiceLaunchHandoff::new(
            SYSTEM_GENERATION,
            7,
            0x45,
            0x434f_4e46_4947,
            1,
            9,
            ComponentServicePlacement::Microvm,
            [0x52; 64],
            [0x61; 64],
            [0x3a; 32],
            [0x18; 64],
            [0x2f; 64],
        )
        .unwrap();
        assert_eq!(
            prepare_component_service_handoff(&mut table, &substituted_generation.encode()),
            Err(ComponentServiceHandoffError::SystemGenerationDigestMismatch)
        );
        assert_eq!((backend.native_launches, backend.microvm_launches), (0, 1));

        let substituted_catalog = ComponentServiceLaunchHandoff::new(
            SYSTEM_GENERATION,
            7,
            0x46,
            0x434f_4e46_4947,
            1,
            9,
            ComponentServicePlacement::Microvm,
            [0x51; 64],
            [0x62; 64],
            [0x3a; 32],
            [0x18; 64],
            [0x2f; 64],
        )
        .unwrap();
        assert_eq!(
            prepare_component_service_handoff(&mut table, &substituted_catalog.encode()),
            Err(ComponentServiceHandoffError::InterfaceCatalogDigestMismatch)
        );
        assert_eq!((backend.native_launches, backend.microvm_launches), (0, 1));
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
            [0x51; 64],
            [0x61; 64],
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
        launch.cancel(&mut table).unwrap();
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
            [0x51; 64],
            [0x61; 64],
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
            ComponentServiceLaunchError::InvalidGenerationDigest,
            ComponentServiceLaunchError::GenerationDigestMismatch,
            ComponentServiceLaunchError::InvalidInterfaceFingerprint,
            ComponentServiceLaunchError::InvalidArtifactDigest,
            ComponentServiceLaunchError::ArtifactSubstitution,
        ] {
            let mut table = if expected == ComponentServiceLaunchError::GenerationDigestMismatch {
                let active = ActivatedSystemGeneration::new(
                    SYSTEM_GENERATION,
                    [0x51; 64],
                    [0x61; 64],
                    1,
                    0x500,
                    1,
                )
                .unwrap();
                IsolationAdmissionTable::<1>::new_activated(IsolationMode::TotalMicrovm, active, 7)
                    .unwrap()
            } else {
                IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 7)
                    .unwrap()
            };
            let spec = service_spec(IsolationPlacement::Microvm);
            let route = prepare_isolation_service_route(&mut table, spec).unwrap();
            let (
                interface,
                system_generation,
                generation_digest,
                catalog_digest,
                fingerprint,
                consumer,
                provider,
            ) = match expected {
                ComponentServiceLaunchError::RouteIdentityMismatch => (
                    ObjectId(spec.interface().0 + 1),
                    spec.system_generation(),
                    [0x51; 64],
                    [0x61; 64],
                    [0x3a; 32],
                    [0x18; 64],
                    [0x2f; 64],
                ),
                ComponentServiceLaunchError::SystemGenerationMismatch => (
                    spec.interface(),
                    spec.system_generation() - 1,
                    [0x51; 64],
                    [0x61; 64],
                    [0x3a; 32],
                    [0x18; 64],
                    [0x2f; 64],
                ),
                ComponentServiceLaunchError::InvalidGenerationDigest => (
                    spec.interface(),
                    spec.system_generation(),
                    [0; 64],
                    [0x61; 64],
                    [0x3a; 32],
                    [0x18; 64],
                    [0x2f; 64],
                ),
                ComponentServiceLaunchError::GenerationDigestMismatch => (
                    spec.interface(),
                    spec.system_generation(),
                    [0x52; 64],
                    [0x61; 64],
                    [0x3a; 32],
                    [0x18; 64],
                    [0x2f; 64],
                ),
                ComponentServiceLaunchError::InvalidInterfaceFingerprint => (
                    spec.interface(),
                    spec.system_generation(),
                    [0x51; 64],
                    [0x61; 64],
                    [0; 32],
                    [0x18; 64],
                    [0x2f; 64],
                ),
                ComponentServiceLaunchError::InvalidArtifactDigest => (
                    spec.interface(),
                    spec.system_generation(),
                    [0x51; 64],
                    [0x61; 64],
                    [0x3a; 32],
                    [0; 64],
                    [0x2f; 64],
                ),
                ComponentServiceLaunchError::ArtifactSubstitution => (
                    spec.interface(),
                    spec.system_generation(),
                    [0x51; 64],
                    [0x61; 64],
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
                generation_digest,
                catalog_digest,
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
