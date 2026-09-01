use crate::{
    FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES, FilesystemBlockAssociation,
    FilesystemBlockAssociationHandoff,
};
use mrml_interface_storage_filesystem_v3::{FilesystemProviderReady, ProtocolError};
use mrml_kernel::arch::x86_64::TrapDisposition;
use mrml_kernel::{
    Capability, CapabilityError, CapabilitySpace, CleanedSupervisedConstructedService,
    CleanedSupervisedConstructedServiceFault, CleanedSupervisedConstructedServiceViolation,
    ComponentServiceLaunchAttachment, ComponentServiceReadTransferAttachment,
    ComponentServiceReadTransferCopyTaskBinding, ComponentServiceReadTransferMemoryRoot,
    IsolationPlacement, IsolationServiceSpec, MemoryMappingRevocationBackend,
    MemoryObjectBackingBackend, MemoryPoolTable,
    NativeComponentServiceCopyReadTransferActiveRetirementError,
    NativeComponentServiceCopyReadTransferError,
    NativeComponentServiceCopyReadTransferRetirementMappingError,
    NativeComponentServiceCopyReadTransferTask, NativeComponentServiceCopyReadTransferTeardown,
    NativeComponentServiceCopyReadTransferTeardownError, ObjectId, ReceivedMessage, RestartPolicy,
    Rights, ServiceError, ServiceId, ServiceSupervisor, SupervisedConstructedServiceCleanupFailure,
    SupervisedConstructedServiceDispatchFailure, SupervisedConstructedServiceFault,
    SupervisedConstructedServiceFaultCleanupFailure,
    SupervisedConstructedServiceFaultDispatchFailure, SupervisedConstructedServiceRetirement,
    SupervisedConstructedServiceViolation, SupervisedConstructedServiceViolationCleanupFailure,
    SupervisedConstructedServiceViolationDispatchFailure, SupervisedServiceTask, TaskId,
    TaskProtocolViolation, TaskRuntime, TaskRuntimeError, TaskTermination, TaskTerminationDispatch,
    TaskTerminationDispatchError,
    prepare_native_component_service_task_from_copy_read_transfer_attachment,
    resume_native_component_service_copy_read_transfer_mapping_revocation,
    resume_native_component_service_copy_read_transfer_mapping_revocation_on_active_x86_64,
    retire_current_native_component_service_copy_read_transfer_on_active_x86_64,
    retire_current_native_component_service_copy_read_transfer_with_mapping_revocation,
    teardown_native_component_service_copy_read_transfer,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemProviderLaunchReceipt<I> {
    provider_object: ObjectId,
    filesystem_module_object: ObjectId,
    block_endpoint_object: ObjectId,
    association_generation: u64,
    filesystem_provider_generation: u64,
    block_provider_generation: u64,
    system_generation: u64,
    instance: I,
}

impl<I> FilesystemProviderLaunchReceipt<I> {
    pub const fn provider_object(&self) -> ObjectId {
        self.provider_object
    }

    pub const fn filesystem_module_object(&self) -> ObjectId {
        self.filesystem_module_object
    }

    pub const fn block_endpoint_object(&self) -> ObjectId {
        self.block_endpoint_object
    }

    pub const fn association_generation(&self) -> u64 {
        self.association_generation
    }

    pub const fn filesystem_provider_generation(&self) -> u64 {
        self.filesystem_provider_generation
    }

    pub const fn block_provider_generation(&self) -> u64 {
        self.block_provider_generation
    }

    pub const fn system_generation(&self) -> u64 {
        self.system_generation
    }

    pub const fn instance(&self) -> &I {
        &self.instance
    }

    pub fn into_instance(self) -> I {
        self.instance
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilesystemProviderLaunchError<E> {
    Capability(CapabilityError),
    WrongEndpointAuthority,
    WrongTransferAuthority,
    TransferTooSmall,
    Backend(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeFilesystemProviderLaunchSpecError {
    WrongPlacement,
    WrongInterface,
    WrongInterfaceGeneration,
    WrongProviderGeneration,
    WrongSystemGeneration,
    WrongLaunchPolicy,
    WrongAssociationGeneration,
    WrongLaunchDataLength,
    WrongDependencyEndpoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeFilesystemProviderLaunchSpec {
    service: IsolationServiceSpec,
    attachment: ComponentServiceLaunchAttachment,
}

impl NativeFilesystemProviderLaunchSpec {
    pub fn new(
        association: FilesystemBlockAssociation,
        service: IsolationServiceSpec,
        attachment: ComponentServiceLaunchAttachment,
        block_endpoint: Capability,
    ) -> Result<Self, NativeFilesystemProviderLaunchSpecError> {
        if service.placement() != IsolationPlacement::NativeService {
            return Err(NativeFilesystemProviderLaunchSpecError::WrongPlacement);
        }
        if service.interface() != association.filesystem_binding.interface_object {
            return Err(NativeFilesystemProviderLaunchSpecError::WrongInterface);
        }
        if service.interface_generation() != association.filesystem_binding.interface_generation {
            return Err(NativeFilesystemProviderLaunchSpecError::WrongInterfaceGeneration);
        }
        if service.provider_generation() != association.filesystem_binding.provider_generation {
            return Err(NativeFilesystemProviderLaunchSpecError::WrongProviderGeneration);
        }
        if service.system_generation() != association.filesystem_binding.system_generation {
            return Err(NativeFilesystemProviderLaunchSpecError::WrongSystemGeneration);
        }
        if attachment.domain() != service.domain()
            || attachment.system_generation() != service.system_generation()
            || attachment.policy_generation() != service.policy_generation()
        {
            return Err(NativeFilesystemProviderLaunchSpecError::WrongLaunchPolicy);
        }
        if attachment.association_generation() != association.association_generation {
            return Err(NativeFilesystemProviderLaunchSpecError::WrongAssociationGeneration);
        }
        if attachment.launch_data_bytes() as usize != FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES {
            return Err(NativeFilesystemProviderLaunchSpecError::WrongLaunchDataLength);
        }
        if attachment.dependency_endpoint_object() != association.block_binding.endpoint_object
            || attachment.dependency_endpoint() != block_endpoint
        {
            return Err(NativeFilesystemProviderLaunchSpecError::WrongDependencyEndpoint);
        }
        Ok(Self {
            service,
            attachment,
        })
    }

    pub const fn service(self) -> IsolationServiceSpec {
        self.service
    }

    pub const fn attachment(self) -> ComponentServiceLaunchAttachment {
        self.attachment
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeFilesystemProviderLaunchPreflightError {
    Source(TaskRuntimeError),
    Target(TaskRuntimeError),
    WrongSupervisorTask,
    TargetNotConstructionPending,
    Capability(CapabilityError),
    WrongEndpointAuthority,
    WrongTransferAuthority,
    TransferTooSmall,
    WrongPageTableRoot,
    Spec(NativeFilesystemProviderLaunchSpecError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeFilesystemProviderLaunchError {
    Preflight(NativeFilesystemProviderLaunchPreflightError),
    Rollback {
        preflight: NativeFilesystemProviderLaunchPreflightError,
        cleanup: TaskRuntimeError,
    },
    Construction(NativeComponentServiceCopyReadTransferError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeFilesystemProviderInstance {
    Active(NativeComponentServiceCopyReadTransferTask),
    Teardown(NativeComponentServiceCopyReadTransferTeardown),
}

impl NativeFilesystemProviderInstance {
    pub const fn active(self) -> Option<NativeComponentServiceCopyReadTransferTask> {
        match self {
            Self::Active(active) => Some(active),
            Self::Teardown(_) => None,
        }
    }

    pub const fn teardown(self) -> Option<NativeComponentServiceCopyReadTransferTeardown> {
        match self {
            Self::Active(_) => None,
            Self::Teardown(state) => Some(state),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ActiveNativeFilesystemProvider {
    receipt: FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    binding: SupervisedServiceTask,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ReadyNativeFilesystemProvider {
    active: ActiveNativeFilesystemProvider,
    ready_sequence: u64,
}

impl ReadyNativeFilesystemProvider {
    pub const fn service(&self) -> ServiceId {
        self.active.service()
    }

    pub const fn task(&self) -> TaskId {
        self.active.task()
    }

    pub const fn ready_sequence(&self) -> u64 {
        self.ready_sequence
    }

    pub const fn receipt(
        &self,
    ) -> &FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance> {
        self.active.receipt()
    }

    pub fn into_active(self) -> ActiveNativeFilesystemProvider {
        self.active
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeFilesystemProviderReadyError {
    WrongSender,
    TransferredCapabilities,
    Protocol(ProtocolError),
    WrongFilesystemModule,
    WrongFilesystemProviderGeneration,
    WrongBlockProviderGeneration,
    WrongSystemGeneration,
    WrongAssociationGeneration,
    WrongBlockEndpoint,
}

pub struct NativeFilesystemProviderReadyFailure {
    active: ActiveNativeFilesystemProvider,
    received: ReceivedMessage,
    error: NativeFilesystemProviderReadyError,
}

impl core::fmt::Debug for NativeFilesystemProviderReadyFailure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NativeFilesystemProviderReadyFailure")
            .field("active", &self.active)
            .field("sender", &self.received.sender())
            .field("sequence", &self.received.sequence())
            .field("payload_length", &self.received.message().payload().len())
            .field(
                "capability_count",
                &self.received.message().capability_count(),
            )
            .field("error", &self.error)
            .finish()
    }
}

impl NativeFilesystemProviderReadyFailure {
    pub const fn error(&self) -> NativeFilesystemProviderReadyError {
        self.error
    }

    pub fn into_parts(self) -> (ActiveNativeFilesystemProvider, ReceivedMessage) {
        (self.active, self.received)
    }
}

pub fn accept_native_filesystem_provider_ready(
    active: ActiveNativeFilesystemProvider,
    received: ReceivedMessage,
) -> Result<ReadyNativeFilesystemProvider, NativeFilesystemProviderReadyFailure> {
    let result = validate_native_filesystem_provider_ready(
        active.receipt(),
        active.task(),
        received.sender(),
        received.message(),
    );
    match result {
        Ok(()) => Ok(ReadyNativeFilesystemProvider {
            active,
            ready_sequence: received.sequence(),
        }),
        Err(error) => Err(NativeFilesystemProviderReadyFailure {
            active,
            received,
            error,
        }),
    }
}

fn validate_native_filesystem_provider_ready<I>(
    receipt: &FilesystemProviderLaunchReceipt<I>,
    expected_task: TaskId,
    sender: TaskId,
    message: &mrml_kernel::Message,
) -> Result<(), NativeFilesystemProviderReadyError> {
    if sender != expected_task {
        return Err(NativeFilesystemProviderReadyError::WrongSender);
    }
    message
        .authorize_no_capabilities()
        .map_err(|_| NativeFilesystemProviderReadyError::TransferredCapabilities)?;
    let ready = FilesystemProviderReady::decode(message.payload())
        .map_err(NativeFilesystemProviderReadyError::Protocol)?;
    if ready.module_object() != receipt.filesystem_module_object.0 {
        return Err(NativeFilesystemProviderReadyError::WrongFilesystemModule);
    }
    if ready.provider_generation() != receipt.filesystem_provider_generation {
        return Err(NativeFilesystemProviderReadyError::WrongFilesystemProviderGeneration);
    }
    if ready.block_provider_generation() != receipt.block_provider_generation {
        return Err(NativeFilesystemProviderReadyError::WrongBlockProviderGeneration);
    }
    if ready.system_generation() != receipt.system_generation {
        return Err(NativeFilesystemProviderReadyError::WrongSystemGeneration);
    }
    if ready.association_generation() != receipt.association_generation {
        return Err(NativeFilesystemProviderReadyError::WrongAssociationGeneration);
    }
    if ready.block_endpoint_object() != receipt.block_endpoint_object.0 {
        return Err(NativeFilesystemProviderReadyError::WrongBlockEndpoint);
    }
    Ok(())
}

impl ActiveNativeFilesystemProvider {
    pub const fn service(&self) -> ServiceId {
        self.binding.service()
    }

    pub const fn task(&self) -> TaskId {
        self.binding.task()
    }

    pub const fn receipt(
        &self,
    ) -> &FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance> {
        &self.receipt
    }

    pub fn into_receipt(self) -> FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance> {
        self.receipt
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeFilesystemProviderActivationError {
    TeardownProgressed,
    Service(ServiceError),
}

#[derive(Debug, Eq, PartialEq)]
pub struct NativeFilesystemProviderActivationFailure {
    receipt: FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    error: NativeFilesystemProviderActivationError,
}

impl NativeFilesystemProviderActivationFailure {
    pub const fn error(&self) -> NativeFilesystemProviderActivationError {
        self.error
    }

    pub const fn receipt(
        &self,
    ) -> &FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance> {
        &self.receipt
    }

    pub fn into_receipt(self) -> FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance> {
        self.receipt
    }
}

pub fn activate_native_filesystem_provider<
    const TASKS: usize,
    const CAPABILITIES: usize,
    const SERVICES: usize,
>(
    receipt: FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    restart_policy: RestartPolicy,
    supervisor: &mut ServiceSupervisor<SERVICES>,
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
) -> Result<ActiveNativeFilesystemProvider, NativeFilesystemProviderActivationFailure> {
    let Some(active) = receipt.instance.active() else {
        return Err(NativeFilesystemProviderActivationFailure {
            receipt,
            error: NativeFilesystemProviderActivationError::TeardownProgressed,
        });
    };
    let task = active.construction().task();
    // The receipt retains the provider object from the same validated
    // filesystem association that constructed `task`; it is not caller input.
    // SAFETY: the typed construction owner remains inside `receipt` and the
    // kernel validates both the pending task and runtime before publication.
    match unsafe {
        supervisor.register_and_activate_constructed(
            receipt.provider_object,
            task,
            restart_policy,
            runtime,
        )
    } {
        Ok(binding) => Ok(ActiveNativeFilesystemProvider { receipt, binding }),
        Err(error) => Err(NativeFilesystemProviderActivationFailure {
            receipt,
            error: NativeFilesystemProviderActivationError::Service(error),
        }),
    }
}

#[derive(Debug)]
pub struct RetiredNativeFilesystemProvider {
    receipt: FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    retirement: SupervisedConstructedServiceRetirement,
}

impl RetiredNativeFilesystemProvider {
    pub const fn service(&self) -> ServiceId {
        self.retirement.service()
    }

    pub const fn task(&self) -> TaskId {
        self.retirement.task()
    }

    pub const fn receipt(
        &self,
    ) -> &FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance> {
        &self.receipt
    }
}

#[derive(Debug)]
pub struct NativeFilesystemProviderSupervisedRetirementFailure {
    active: ActiveNativeFilesystemProvider,
    error: ServiceError,
}

impl NativeFilesystemProviderSupervisedRetirementFailure {
    pub const fn error(&self) -> ServiceError {
        self.error
    }

    pub fn into_active(self) -> ActiveNativeFilesystemProvider {
        self.active
    }
}

pub fn retire_current_supervised_native_filesystem_provider<
    const TASKS: usize,
    const CAPABILITIES: usize,
    const SERVICES: usize,
>(
    active: ActiveNativeFilesystemProvider,
    supervisor: &mut ServiceSupervisor<SERVICES>,
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
) -> Result<RetiredNativeFilesystemProvider, NativeFilesystemProviderSupervisedRetirementFailure> {
    match supervisor.retire_current_constructed_service(active.binding, runtime) {
        Ok(retirement) => Ok(RetiredNativeFilesystemProvider {
            receipt: active.receipt,
            retirement,
        }),
        Err(error) => Err(NativeFilesystemProviderSupervisedRetirementFailure { active, error }),
    }
}

#[derive(Debug)]
pub struct RetiredNativeFilesystemProviderTeardownFailure<E> {
    retired: RetiredNativeFilesystemProvider,
    error: E,
}

#[derive(Debug)]
pub struct ResourceReleasedRetiredNativeFilesystemProvider {
    receipt: FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    retirement: SupervisedConstructedServiceRetirement,
}

impl ResourceReleasedRetiredNativeFilesystemProvider {
    pub const fn service(&self) -> ServiceId {
        self.retirement.service()
    }

    pub const fn task(&self) -> TaskId {
        self.retirement.task()
    }

    pub const fn receipt(
        &self,
    ) -> &FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance> {
        &self.receipt
    }
}

impl<E> RetiredNativeFilesystemProviderTeardownFailure<E> {
    pub const fn error(&self) -> &E {
        &self.error
    }

    pub fn into_retired(self) -> RetiredNativeFilesystemProvider {
        self.retired
    }
}

pub fn teardown_retired_native_filesystem_provider<B>(
    mut retired: RetiredNativeFilesystemProvider,
    backend: &mut B,
) -> Result<
    ResourceReleasedRetiredNativeFilesystemProvider,
    RetiredNativeFilesystemProviderTeardownFailure<B::TeardownError>,
>
where
    B: FilesystemProviderTeardownBackend<Instance = NativeFilesystemProviderInstance>,
{
    if let NativeFilesystemProviderInstance::Active(active) = retired.receipt.instance {
        debug_assert_eq!(active.construction().task(), retired.retirement.task());
        // SAFETY: `retired.retirement` was minted above by the exact
        // supervisor-bound retirement of this active receipt and remains
        // retained until resource teardown returns.
        retired.receipt.instance = NativeFilesystemProviderInstance::Teardown(unsafe {
            NativeComponentServiceCopyReadTransferTeardown::from_supervised_retirement(
                active,
                retired.retirement.cleanup().context(),
            )
        });
    }
    match backend.teardown(&mut retired.receipt.instance) {
        Ok(()) => Ok(ResourceReleasedRetiredNativeFilesystemProvider {
            receipt: retired.receipt,
            retirement: retired.retirement,
        }),
        Err(error) => Err(RetiredNativeFilesystemProviderTeardownFailure { retired, error }),
    }
}

#[derive(Debug)]
pub struct ResourceReleasedNativeFilesystemProviderRetirementCleanupFailure<E> {
    receipt: FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    failure: SupervisedConstructedServiceCleanupFailure<E>,
}

impl<E> ResourceReleasedNativeFilesystemProviderRetirementCleanupFailure<E> {
    pub fn error(&self) -> &mrml_kernel::ServiceCleanupError<E> {
        self.failure.error()
    }

    pub fn into_released(self) -> ResourceReleasedRetiredNativeFilesystemProvider {
        ResourceReleasedRetiredNativeFilesystemProvider {
            receipt: self.receipt,
            retirement: self.failure.into_retirement(),
        }
    }
}

#[derive(Debug)]
pub struct CleanedRetiredNativeFilesystemProvider {
    receipt: FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    cleaned: CleanedSupervisedConstructedService,
}

impl CleanedRetiredNativeFilesystemProvider {
    pub const fn service(&self) -> ServiceId {
        self.cleaned.service()
    }

    pub const fn task(&self) -> TaskId {
        self.cleaned.task()
    }

    pub const fn receipt(
        &self,
    ) -> &FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance> {
        &self.receipt
    }
}

pub fn complete_resource_released_native_filesystem_provider_retirement_cleanup<
    E: mrml_kernel::ServiceAddressSpaceEraser,
    const SERVICES: usize,
>(
    released: ResourceReleasedRetiredNativeFilesystemProvider,
    supervisor: &mut ServiceSupervisor<SERVICES>,
    eraser: &mut E,
) -> Result<
    CleanedRetiredNativeFilesystemProvider,
    ResourceReleasedNativeFilesystemProviderRetirementCleanupFailure<E::Error>,
> {
    match supervisor.complete_constructed_service_cleanup(released.retirement, eraser) {
        Ok(cleaned) => Ok(CleanedRetiredNativeFilesystemProvider {
            receipt: released.receipt,
            cleaned,
        }),
        Err(failure) => Err(
            ResourceReleasedNativeFilesystemProviderRetirementCleanupFailure {
                receipt: released.receipt,
                failure,
            },
        ),
    }
}

#[derive(Debug)]
pub struct DispatchedRetiredNativeFilesystemProvider {
    receipt: FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    service: ServiceId,
    task: TaskId,
    dispatch: TaskTerminationDispatch,
}

impl DispatchedRetiredNativeFilesystemProvider {
    pub const fn service(&self) -> ServiceId {
        self.service
    }

    pub const fn task(&self) -> TaskId {
        self.task
    }

    pub const fn receipt(
        &self,
    ) -> &FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance> {
        &self.receipt
    }

    pub const fn dispatch(&self) -> &TaskTerminationDispatch {
        &self.dispatch
    }

    pub fn into_parts(
        self,
    ) -> (
        FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
        TaskTerminationDispatch,
    ) {
        (self.receipt, self.dispatch)
    }

    pub fn into_restart_parts(
        self,
    ) -> (
        RestartableStoppedNativeFilesystemProvider,
        TaskTerminationDispatch,
    ) {
        (
            RestartableStoppedNativeFilesystemProvider {
                receipt: self.receipt,
                service: self.service,
                task: self.task,
                cause: NativeFilesystemProviderStopCause::Retirement,
            },
            self.dispatch,
        )
    }
}

#[derive(Debug)]
pub struct RestartableStoppedNativeFilesystemProvider {
    receipt: FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    service: ServiceId,
    task: TaskId,
    cause: NativeFilesystemProviderStopCause,
}

impl RestartableStoppedNativeFilesystemProvider {
    pub const fn service(&self) -> ServiceId {
        self.service
    }

    pub const fn task(&self) -> TaskId {
        self.task
    }

    pub const fn cause(&self) -> NativeFilesystemProviderStopCause {
        self.cause
    }

    pub const fn receipt(
        &self,
    ) -> &FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance> {
        &self.receipt
    }

    pub fn into_receipt(self) -> FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance> {
        self.receipt
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeFilesystemProviderStopCause {
    Retirement,
    Fault(TrapDisposition),
    ProtocolViolation(TaskProtocolViolation),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeFilesystemProviderRestartError {
    CandidateTeardownProgressed,
    WrongProviderObject,
    WrongAssociationGeneration,
    WrongFilesystemProviderGeneration,
    WrongBlockProviderGeneration,
    WrongSystemGeneration,
    Service(ServiceError),
}

fn validate_native_filesystem_provider_restart_association<I, J>(
    retired: &FilesystemProviderLaunchReceipt<I>,
    candidate: &FilesystemProviderLaunchReceipt<J>,
) -> Result<(), NativeFilesystemProviderRestartError> {
    if candidate.provider_object != retired.provider_object {
        return Err(NativeFilesystemProviderRestartError::WrongProviderObject);
    }
    if candidate.association_generation != retired.association_generation {
        return Err(NativeFilesystemProviderRestartError::WrongAssociationGeneration);
    }
    if candidate.filesystem_provider_generation != retired.filesystem_provider_generation {
        return Err(NativeFilesystemProviderRestartError::WrongFilesystemProviderGeneration);
    }
    if candidate.block_provider_generation != retired.block_provider_generation {
        return Err(NativeFilesystemProviderRestartError::WrongBlockProviderGeneration);
    }
    if candidate.system_generation != retired.system_generation {
        return Err(NativeFilesystemProviderRestartError::WrongSystemGeneration);
    }
    Ok(())
}

#[derive(Debug)]
pub struct NativeFilesystemProviderRestartFailure {
    stopped: RestartableStoppedNativeFilesystemProvider,
    candidate: FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    error: NativeFilesystemProviderRestartError,
}

impl NativeFilesystemProviderRestartFailure {
    pub const fn error(&self) -> NativeFilesystemProviderRestartError {
        self.error
    }

    pub fn into_parts(
        self,
    ) -> (
        RestartableStoppedNativeFilesystemProvider,
        FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    ) {
        (self.stopped, self.candidate)
    }
}

#[derive(Debug)]
pub struct RestartedNativeFilesystemProvider {
    stopped: RestartableStoppedNativeFilesystemProvider,
    active: ActiveNativeFilesystemProvider,
}

impl RestartedNativeFilesystemProvider {
    pub const fn stopped(&self) -> &RestartableStoppedNativeFilesystemProvider {
        &self.stopped
    }

    pub const fn active(&self) -> &ActiveNativeFilesystemProvider {
        &self.active
    }

    pub fn into_active(self) -> ActiveNativeFilesystemProvider {
        self.active
    }

    pub fn into_parts(
        self,
    ) -> (
        RestartableStoppedNativeFilesystemProvider,
        ActiveNativeFilesystemProvider,
    ) {
        (self.stopped, self.active)
    }
}

pub fn restart_and_activate_native_filesystem_provider<
    const TASKS: usize,
    const CAPABILITIES: usize,
    const SERVICES: usize,
>(
    stopped: RestartableStoppedNativeFilesystemProvider,
    candidate: FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    supervisor: &mut ServiceSupervisor<SERVICES>,
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    now: u64,
) -> Result<RestartedNativeFilesystemProvider, NativeFilesystemProviderRestartFailure> {
    let result = (|| {
        validate_native_filesystem_provider_restart_association(&stopped.receipt, &candidate)?;
        let active = candidate
            .instance
            .active()
            .ok_or(NativeFilesystemProviderRestartError::CandidateTeardownProgressed)?;
        let task = active.construction().task();
        // SAFETY: `candidate` is the exact typed filesystem construction owner;
        // the equality checks above bind it to the retained retired association,
        // and the kernel revalidates service generation, task state, policy,
        // cleanup, budget, backoff, and scheduler state before publication.
        let binding = unsafe {
            supervisor.restart_and_activate_constructed(
                stopped.service,
                candidate.provider_object,
                task,
                runtime,
                now,
            )
        }
        .map_err(NativeFilesystemProviderRestartError::Service)?;
        Ok(ActiveNativeFilesystemProvider {
            receipt: candidate,
            binding,
        })
    })();
    match result {
        Ok(active) => Ok(RestartedNativeFilesystemProvider { stopped, active }),
        Err(error) => Err(NativeFilesystemProviderRestartFailure {
            stopped,
            candidate,
            error,
        }),
    }
}

#[derive(Debug)]
pub struct CleanedNativeFilesystemProviderRetirementDispatchFailure {
    receipt: FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    failure: SupervisedConstructedServiceDispatchFailure,
}

impl CleanedNativeFilesystemProviderRetirementDispatchFailure {
    pub const fn error(&self) -> TaskTerminationDispatchError {
        self.failure.error()
    }

    pub fn into_cleaned(self) -> CleanedRetiredNativeFilesystemProvider {
        CleanedRetiredNativeFilesystemProvider {
            receipt: self.receipt,
            cleaned: self.failure.into_cleaned(),
        }
    }
}

pub fn dispatch_cleaned_native_filesystem_provider_retirement<
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    cleaned: CleanedRetiredNativeFilesystemProvider,
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
) -> Result<
    DispatchedRetiredNativeFilesystemProvider,
    CleanedNativeFilesystemProviderRetirementDispatchFailure,
> {
    let service = cleaned.service();
    let task = cleaned.task();
    match cleaned.cleaned.dispatch(runtime) {
        Ok(dispatch) => Ok(DispatchedRetiredNativeFilesystemProvider {
            receipt: cleaned.receipt,
            service,
            task,
            dispatch,
        }),
        Err(failure) => Err(CleanedNativeFilesystemProviderRetirementDispatchFailure {
            receipt: cleaned.receipt,
            failure,
        }),
    }
}

#[derive(Debug)]
pub struct FaultedNativeFilesystemProvider {
    receipt: FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    fault: SupervisedConstructedServiceFault,
}

impl FaultedNativeFilesystemProvider {
    pub const fn service(&self) -> ServiceId {
        self.fault.service()
    }

    pub const fn task(&self) -> TaskId {
        self.fault.task()
    }

    pub const fn receipt(
        &self,
    ) -> &FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance> {
        &self.receipt
    }
}

#[derive(Debug)]
pub struct NativeFilesystemProviderSupervisedFaultFailure {
    active: ActiveNativeFilesystemProvider,
    error: ServiceError,
}

impl NativeFilesystemProviderSupervisedFaultFailure {
    pub const fn error(&self) -> ServiceError {
        self.error
    }

    pub fn into_active(self) -> ActiveNativeFilesystemProvider {
        self.active
    }
}

pub fn fault_current_supervised_native_filesystem_provider<
    const TASKS: usize,
    const CAPABILITIES: usize,
    const SERVICES: usize,
>(
    active: ActiveNativeFilesystemProvider,
    supervisor: &mut ServiceSupervisor<SERVICES>,
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    disposition: TrapDisposition,
) -> Result<FaultedNativeFilesystemProvider, NativeFilesystemProviderSupervisedFaultFailure> {
    match supervisor.fault_current_constructed_service(active.binding, runtime, disposition) {
        Ok(fault) => Ok(FaultedNativeFilesystemProvider {
            receipt: active.receipt,
            fault,
        }),
        Err(error) => Err(NativeFilesystemProviderSupervisedFaultFailure { active, error }),
    }
}

#[derive(Debug)]
pub struct FaultedNativeFilesystemProviderTeardownFailure<E> {
    faulted: FaultedNativeFilesystemProvider,
    error: E,
}

#[derive(Debug)]
pub struct ResourceReleasedFaultedNativeFilesystemProvider {
    receipt: FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    fault: SupervisedConstructedServiceFault,
}

impl ResourceReleasedFaultedNativeFilesystemProvider {
    pub const fn service(&self) -> ServiceId {
        self.fault.service()
    }

    pub const fn task(&self) -> TaskId {
        self.fault.task()
    }

    pub const fn receipt(
        &self,
    ) -> &FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance> {
        &self.receipt
    }
}

impl<E> FaultedNativeFilesystemProviderTeardownFailure<E> {
    pub const fn error(&self) -> &E {
        &self.error
    }

    pub fn into_faulted(self) -> FaultedNativeFilesystemProvider {
        self.faulted
    }
}

pub fn teardown_faulted_native_filesystem_provider<B>(
    mut faulted: FaultedNativeFilesystemProvider,
    backend: &mut B,
) -> Result<
    ResourceReleasedFaultedNativeFilesystemProvider,
    FaultedNativeFilesystemProviderTeardownFailure<B::TeardownError>,
>
where
    B: FilesystemProviderTeardownBackend<Instance = NativeFilesystemProviderInstance>,
{
    if let NativeFilesystemProviderInstance::Active(active) = faulted.receipt.instance {
        debug_assert_eq!(active.construction().task(), faulted.fault.task());
        // SAFETY: `faulted.fault` was minted by the exact supervisor-bound
        // fault transition for this active receipt and remains retained.
        faulted.receipt.instance = NativeFilesystemProviderInstance::Teardown(unsafe {
            NativeComponentServiceCopyReadTransferTeardown::from_supervised_retirement(
                active,
                faulted.fault.cleanup().context(),
            )
        });
    }
    match backend.teardown(&mut faulted.receipt.instance) {
        Ok(()) => Ok(ResourceReleasedFaultedNativeFilesystemProvider {
            receipt: faulted.receipt,
            fault: faulted.fault,
        }),
        Err(error) => Err(FaultedNativeFilesystemProviderTeardownFailure { faulted, error }),
    }
}

#[derive(Debug)]
pub struct ResourceReleasedNativeFilesystemProviderFaultCleanupFailure<E> {
    receipt: FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    failure: SupervisedConstructedServiceFaultCleanupFailure<E>,
}

impl<E> ResourceReleasedNativeFilesystemProviderFaultCleanupFailure<E> {
    pub fn error(&self) -> &mrml_kernel::ServiceCleanupError<E> {
        self.failure.error()
    }

    pub fn into_released(self) -> ResourceReleasedFaultedNativeFilesystemProvider {
        ResourceReleasedFaultedNativeFilesystemProvider {
            receipt: self.receipt,
            fault: self.failure.into_fault(),
        }
    }
}

#[derive(Debug)]
pub struct CleanedFaultedNativeFilesystemProvider {
    receipt: FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    cleaned: CleanedSupervisedConstructedServiceFault,
}

impl CleanedFaultedNativeFilesystemProvider {
    pub const fn service(&self) -> ServiceId {
        self.cleaned.service()
    }

    pub const fn task(&self) -> TaskId {
        self.cleaned.task()
    }

    pub const fn receipt(
        &self,
    ) -> &FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance> {
        &self.receipt
    }
}

pub fn complete_resource_released_native_filesystem_provider_fault_cleanup<
    E: mrml_kernel::ServiceAddressSpaceEraser,
    const SERVICES: usize,
>(
    released: ResourceReleasedFaultedNativeFilesystemProvider,
    supervisor: &mut ServiceSupervisor<SERVICES>,
    eraser: &mut E,
) -> Result<
    CleanedFaultedNativeFilesystemProvider,
    ResourceReleasedNativeFilesystemProviderFaultCleanupFailure<E::Error>,
> {
    match supervisor.complete_constructed_service_fault_cleanup(released.fault, eraser) {
        Ok(cleaned) => Ok(CleanedFaultedNativeFilesystemProvider {
            receipt: released.receipt,
            cleaned,
        }),
        Err(failure) => Err(
            ResourceReleasedNativeFilesystemProviderFaultCleanupFailure {
                receipt: released.receipt,
                failure,
            },
        ),
    }
}

#[derive(Debug)]
pub struct DispatchedFaultedNativeFilesystemProvider {
    receipt: FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    service: ServiceId,
    task: TaskId,
    cause: NativeFilesystemProviderStopCause,
    dispatch: TaskTerminationDispatch,
}

impl DispatchedFaultedNativeFilesystemProvider {
    pub const fn service(&self) -> ServiceId {
        self.service
    }

    pub const fn task(&self) -> TaskId {
        self.task
    }

    pub const fn receipt(
        &self,
    ) -> &FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance> {
        &self.receipt
    }

    pub const fn dispatch(&self) -> &TaskTerminationDispatch {
        &self.dispatch
    }

    pub fn into_parts(
        self,
    ) -> (
        FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
        TaskTerminationDispatch,
    ) {
        (self.receipt, self.dispatch)
    }

    pub fn into_restart_parts(
        self,
    ) -> (
        RestartableStoppedNativeFilesystemProvider,
        TaskTerminationDispatch,
    ) {
        (
            RestartableStoppedNativeFilesystemProvider {
                receipt: self.receipt,
                service: self.service,
                task: self.task,
                cause: self.cause,
            },
            self.dispatch,
        )
    }
}

#[derive(Debug)]
pub struct CleanedNativeFilesystemProviderFaultDispatchFailure {
    receipt: FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    failure: SupervisedConstructedServiceFaultDispatchFailure,
}

impl CleanedNativeFilesystemProviderFaultDispatchFailure {
    pub const fn error(&self) -> TaskTerminationDispatchError {
        self.failure.error()
    }

    pub fn into_cleaned(self) -> CleanedFaultedNativeFilesystemProvider {
        CleanedFaultedNativeFilesystemProvider {
            receipt: self.receipt,
            cleaned: self.failure.into_cleaned(),
        }
    }
}

pub fn dispatch_cleaned_native_filesystem_provider_fault<
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    cleaned: CleanedFaultedNativeFilesystemProvider,
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
) -> Result<
    DispatchedFaultedNativeFilesystemProvider,
    CleanedNativeFilesystemProviderFaultDispatchFailure,
> {
    let service = cleaned.service();
    let task = cleaned.task();
    let cause = NativeFilesystemProviderStopCause::Fault(cleaned.cleaned.disposition());
    match cleaned.cleaned.dispatch(runtime) {
        Ok(dispatch) => Ok(DispatchedFaultedNativeFilesystemProvider {
            receipt: cleaned.receipt,
            service,
            task,
            cause,
            dispatch,
        }),
        Err(failure) => Err(CleanedNativeFilesystemProviderFaultDispatchFailure {
            receipt: cleaned.receipt,
            failure,
        }),
    }
}

#[derive(Debug)]
pub struct ViolatingNativeFilesystemProvider {
    receipt: FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    violation: SupervisedConstructedServiceViolation,
}

impl ViolatingNativeFilesystemProvider {
    pub const fn service(&self) -> ServiceId {
        self.violation.service()
    }

    pub const fn task(&self) -> TaskId {
        self.violation.task()
    }

    pub const fn receipt(
        &self,
    ) -> &FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance> {
        &self.receipt
    }
}

#[derive(Debug)]
pub struct NativeFilesystemProviderSupervisedViolationFailure {
    active: ActiveNativeFilesystemProvider,
    error: ServiceError,
}

impl NativeFilesystemProviderSupervisedViolationFailure {
    pub const fn error(&self) -> ServiceError {
        self.error
    }

    pub fn into_active(self) -> ActiveNativeFilesystemProvider {
        self.active
    }
}

pub fn violate_current_supervised_native_filesystem_provider<
    const TASKS: usize,
    const CAPABILITIES: usize,
    const SERVICES: usize,
>(
    active: ActiveNativeFilesystemProvider,
    supervisor: &mut ServiceSupervisor<SERVICES>,
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    violation: TaskProtocolViolation,
) -> Result<ViolatingNativeFilesystemProvider, NativeFilesystemProviderSupervisedViolationFailure> {
    match supervisor.violate_current_constructed_service(active.binding, runtime, violation) {
        Ok(violation) => Ok(ViolatingNativeFilesystemProvider {
            receipt: active.receipt,
            violation,
        }),
        Err(error) => Err(NativeFilesystemProviderSupervisedViolationFailure { active, error }),
    }
}

#[derive(Debug)]
pub struct ViolatingNativeFilesystemProviderTeardownFailure<E> {
    violating: ViolatingNativeFilesystemProvider,
    error: E,
}

#[derive(Debug)]
pub struct ResourceReleasedViolatingNativeFilesystemProvider {
    receipt: FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    violation: SupervisedConstructedServiceViolation,
}

impl ResourceReleasedViolatingNativeFilesystemProvider {
    pub const fn service(&self) -> ServiceId {
        self.violation.service()
    }

    pub const fn task(&self) -> TaskId {
        self.violation.task()
    }

    pub const fn receipt(
        &self,
    ) -> &FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance> {
        &self.receipt
    }
}

impl<E> ViolatingNativeFilesystemProviderTeardownFailure<E> {
    pub const fn error(&self) -> &E {
        &self.error
    }

    pub fn into_violating(self) -> ViolatingNativeFilesystemProvider {
        self.violating
    }
}

pub fn teardown_violating_native_filesystem_provider<B>(
    mut violating: ViolatingNativeFilesystemProvider,
    backend: &mut B,
) -> Result<
    ResourceReleasedViolatingNativeFilesystemProvider,
    ViolatingNativeFilesystemProviderTeardownFailure<B::TeardownError>,
>
where
    B: FilesystemProviderTeardownBackend<Instance = NativeFilesystemProviderInstance>,
{
    if let NativeFilesystemProviderInstance::Active(active) = violating.receipt.instance {
        debug_assert_eq!(active.construction().task(), violating.violation.task());
        // SAFETY: `violating.violation` was minted by the exact
        // supervisor-bound protocol-violation transition for this active
        // receipt and remains retained until resource teardown returns.
        violating.receipt.instance = NativeFilesystemProviderInstance::Teardown(unsafe {
            NativeComponentServiceCopyReadTransferTeardown::from_supervised_retirement(
                active,
                violating.violation.cleanup().context(),
            )
        });
    }
    match backend.teardown(&mut violating.receipt.instance) {
        Ok(()) => Ok(ResourceReleasedViolatingNativeFilesystemProvider {
            receipt: violating.receipt,
            violation: violating.violation,
        }),
        Err(error) => Err(ViolatingNativeFilesystemProviderTeardownFailure { violating, error }),
    }
}

#[derive(Debug)]
pub struct ResourceReleasedNativeFilesystemProviderViolationCleanupFailure<E> {
    receipt: FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    failure: SupervisedConstructedServiceViolationCleanupFailure<E>,
}

impl<E> ResourceReleasedNativeFilesystemProviderViolationCleanupFailure<E> {
    pub fn error(&self) -> &mrml_kernel::ServiceCleanupError<E> {
        self.failure.error()
    }

    pub fn into_released(self) -> ResourceReleasedViolatingNativeFilesystemProvider {
        ResourceReleasedViolatingNativeFilesystemProvider {
            receipt: self.receipt,
            violation: self.failure.into_violation(),
        }
    }
}

#[derive(Debug)]
pub struct CleanedViolatingNativeFilesystemProvider {
    receipt: FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    cleaned: CleanedSupervisedConstructedServiceViolation,
}

impl CleanedViolatingNativeFilesystemProvider {
    pub const fn service(&self) -> ServiceId {
        self.cleaned.service()
    }

    pub const fn task(&self) -> TaskId {
        self.cleaned.task()
    }

    pub const fn receipt(
        &self,
    ) -> &FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance> {
        &self.receipt
    }
}

pub fn complete_resource_released_native_filesystem_provider_violation_cleanup<
    E: mrml_kernel::ServiceAddressSpaceEraser,
    const SERVICES: usize,
>(
    released: ResourceReleasedViolatingNativeFilesystemProvider,
    supervisor: &mut ServiceSupervisor<SERVICES>,
    eraser: &mut E,
) -> Result<
    CleanedViolatingNativeFilesystemProvider,
    ResourceReleasedNativeFilesystemProviderViolationCleanupFailure<E::Error>,
> {
    match supervisor.complete_constructed_service_violation_cleanup(released.violation, eraser) {
        Ok(cleaned) => Ok(CleanedViolatingNativeFilesystemProvider {
            receipt: released.receipt,
            cleaned,
        }),
        Err(failure) => Err(
            ResourceReleasedNativeFilesystemProviderViolationCleanupFailure {
                receipt: released.receipt,
                failure,
            },
        ),
    }
}

#[derive(Debug)]
pub struct DispatchedViolatingNativeFilesystemProvider {
    receipt: FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    service: ServiceId,
    task: TaskId,
    cause: NativeFilesystemProviderStopCause,
    dispatch: TaskTerminationDispatch,
}

impl DispatchedViolatingNativeFilesystemProvider {
    pub const fn service(&self) -> ServiceId {
        self.service
    }

    pub const fn task(&self) -> TaskId {
        self.task
    }

    pub const fn receipt(
        &self,
    ) -> &FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance> {
        &self.receipt
    }

    pub const fn dispatch(&self) -> &TaskTerminationDispatch {
        &self.dispatch
    }

    pub fn into_parts(
        self,
    ) -> (
        FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
        TaskTerminationDispatch,
    ) {
        (self.receipt, self.dispatch)
    }

    pub fn into_restart_parts(
        self,
    ) -> (
        RestartableStoppedNativeFilesystemProvider,
        TaskTerminationDispatch,
    ) {
        (
            RestartableStoppedNativeFilesystemProvider {
                receipt: self.receipt,
                service: self.service,
                task: self.task,
                cause: self.cause,
            },
            self.dispatch,
        )
    }
}

#[derive(Debug)]
pub struct CleanedNativeFilesystemProviderViolationDispatchFailure {
    receipt: FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    failure: SupervisedConstructedServiceViolationDispatchFailure,
}

impl CleanedNativeFilesystemProviderViolationDispatchFailure {
    pub const fn error(&self) -> TaskTerminationDispatchError {
        self.failure.error()
    }

    pub fn into_cleaned(self) -> CleanedViolatingNativeFilesystemProvider {
        CleanedViolatingNativeFilesystemProvider {
            receipt: self.receipt,
            cleaned: self.failure.into_cleaned(),
        }
    }
}

pub fn dispatch_cleaned_native_filesystem_provider_violation<
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    cleaned: CleanedViolatingNativeFilesystemProvider,
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
) -> Result<
    DispatchedViolatingNativeFilesystemProvider,
    CleanedNativeFilesystemProviderViolationDispatchFailure,
> {
    let service = cleaned.service();
    let task = cleaned.task();
    let cause = NativeFilesystemProviderStopCause::ProtocolViolation(cleaned.cleaned.violation());
    match cleaned.cleaned.dispatch(runtime) {
        Ok(dispatch) => Ok(DispatchedViolatingNativeFilesystemProvider {
            receipt: cleaned.receipt,
            service,
            task,
            cause,
            dispatch,
        }),
        Err(failure) => Err(CleanedNativeFilesystemProviderViolationDispatchFailure {
            receipt: cleaned.receipt,
            failure,
        }),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeFilesystemProviderRetirementError<M> {
    TeardownProgressed,
    RetirementMapping(NativeComponentServiceCopyReadTransferRetirementMappingError<M>),
    Dispatch {
        termination: TaskTermination,
        error: TaskTerminationDispatchError,
    },
}

#[derive(Debug, Eq, PartialEq)]
pub struct NativeFilesystemProviderRetirement {
    termination: TaskTermination,
    dispatch: TaskTerminationDispatch,
}

impl NativeFilesystemProviderRetirement {
    pub const fn termination(&self) -> TaskTermination {
        self.termination
    }

    pub const fn dispatch(&self) -> &TaskTerminationDispatch {
        &self.dispatch
    }

    pub fn into_parts(self) -> (TaskTermination, TaskTerminationDispatch) {
        (self.termination, self.dispatch)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeFilesystemProviderActiveRetirementError {
    TeardownProgressed,
    Retirement(NativeComponentServiceCopyReadTransferActiveRetirementError),
    Dispatch {
        termination: TaskTermination,
        error: TaskTerminationDispatchError,
    },
}

pub fn retire_current_native_filesystem_provider<
    M: MemoryMappingRevocationBackend,
    const POOLS: usize,
    const OBJECTS: usize,
    const MAPPINGS: usize,
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    receipt: &mut FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    memory: &mut MemoryPoolTable<POOLS, OBJECTS, MAPPINGS>,
    mapping_backend: &mut M,
) -> Result<NativeFilesystemProviderRetirement, NativeFilesystemProviderRetirementError<M::Error>> {
    if let NativeFilesystemProviderInstance::Teardown(state) = receipt.instance {
        if let Some(termination) = state.retired_termination()
            && state.mapping_removed()
            && !state.dispatch_issued()
            && !state.authority_revoked()
            && !state.backing_released()
        {
            let dispatch = runtime
                .dispatch_after_termination(termination)
                .map_err(|error| NativeFilesystemProviderRetirementError::Dispatch {
                    termination,
                    error,
                })?;
            let Some(state) = state.with_dispatch_issued() else {
                return Err(NativeFilesystemProviderRetirementError::TeardownProgressed);
            };
            receipt.instance = NativeFilesystemProviderInstance::Teardown(state);
            return Ok(NativeFilesystemProviderRetirement {
                termination,
                dispatch,
            });
        }
        if state.retired_termination().is_some()
            && !state.mapping_removed()
            && !state.authority_revoked()
            && !state.backing_released()
        {
            return match resume_native_component_service_copy_read_transfer_mapping_revocation(
                state,
                runtime,
                memory,
                mapping_backend,
            ) {
                Ok((termination, state)) => {
                    receipt.instance = NativeFilesystemProviderInstance::Teardown(state);
                    let dispatch =
                        runtime
                            .dispatch_after_termination(termination)
                            .map_err(|error| NativeFilesystemProviderRetirementError::Dispatch {
                                termination,
                                error,
                            })?;
                    let Some(state) = state.with_dispatch_issued() else {
                        return Err(NativeFilesystemProviderRetirementError::TeardownProgressed);
                    };
                    receipt.instance = NativeFilesystemProviderInstance::Teardown(state);
                    Ok(NativeFilesystemProviderRetirement {
                        termination,
                        dispatch,
                    })
                }
                Err(error) => Err(NativeFilesystemProviderRetirementError::RetirementMapping(
                    error,
                )),
            };
        }
    }
    let active = match receipt.instance {
        NativeFilesystemProviderInstance::Active(active) => active,
        NativeFilesystemProviderInstance::Teardown(state)
            if state.is_pristine() && state.retired_context().is_none() =>
        {
            state.active()
        }
        NativeFilesystemProviderInstance::Teardown(_) => {
            return Err(NativeFilesystemProviderRetirementError::TeardownProgressed);
        }
    };
    match retire_current_native_component_service_copy_read_transfer_with_mapping_revocation(
        active,
        runtime,
        memory,
        mapping_backend,
    ) {
        Ok((termination, state)) => {
            receipt.instance = NativeFilesystemProviderInstance::Teardown(state);
            let dispatch = runtime
                .dispatch_after_termination(termination)
                .map_err(|error| NativeFilesystemProviderRetirementError::Dispatch {
                    termination,
                    error,
                })?;
            let Some(state) = state.with_dispatch_issued() else {
                return Err(NativeFilesystemProviderRetirementError::TeardownProgressed);
            };
            receipt.instance = NativeFilesystemProviderInstance::Teardown(state);
            Ok(NativeFilesystemProviderRetirement {
                termination,
                dispatch,
            })
        }
        Err(error) => {
            if let Some(state) = error.state() {
                receipt.instance = NativeFilesystemProviderInstance::Teardown(state);
            }
            Err(NativeFilesystemProviderRetirementError::RetirementMapping(
                error,
            ))
        }
    }
}

/// Retires the current filesystem provider through its physically active x86-64
/// page-table root and retains exact teardown state in `receipt`.
///
/// # Safety
///
/// The safety contract of
/// [`retire_current_native_component_service_copy_read_transfer_on_active_x86_64`]
/// applies to the provider task and its local mapping.
pub unsafe fn retire_current_native_filesystem_provider_on_active_x86_64<
    const POOLS: usize,
    const OBJECTS: usize,
    const MAPPINGS: usize,
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    receipt: &mut FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    memory: &mut MemoryPoolTable<POOLS, OBJECTS, MAPPINGS>,
) -> Result<NativeFilesystemProviderRetirement, NativeFilesystemProviderActiveRetirementError> {
    if let NativeFilesystemProviderInstance::Teardown(state) = receipt.instance {
        if let Some(termination) = state.retired_termination()
            && state.mapping_removed()
            && !state.dispatch_issued()
            && !state.authority_revoked()
            && !state.backing_released()
        {
            let dispatch = runtime
                .dispatch_after_termination(termination)
                .map_err(
                    |error| NativeFilesystemProviderActiveRetirementError::Dispatch {
                        termination,
                        error,
                    },
                )?;
            let Some(state) = state.with_dispatch_issued() else {
                return Err(NativeFilesystemProviderActiveRetirementError::TeardownProgressed);
            };
            receipt.instance = NativeFilesystemProviderInstance::Teardown(state);
            return Ok(NativeFilesystemProviderRetirement {
                termination,
                dispatch,
            });
        }
        if state.retired_termination().is_some()
            && !state.mapping_removed()
            && !state.authority_revoked()
            && !state.backing_released()
        {
            return match unsafe {
                resume_native_component_service_copy_read_transfer_mapping_revocation_on_active_x86_64(
                    state, runtime, memory,
                )
            } {
                Ok((termination, state)) => {
                    receipt.instance = NativeFilesystemProviderInstance::Teardown(state);
                    let dispatch =
                        runtime
                            .dispatch_after_termination(termination)
                            .map_err(|error| {
                                NativeFilesystemProviderActiveRetirementError::Dispatch {
                                    termination,
                                    error,
                                }
                            })?;
                    let Some(state) = state.with_dispatch_issued() else {
                        return Err(
                            NativeFilesystemProviderActiveRetirementError::TeardownProgressed,
                        );
                    };
                    receipt.instance = NativeFilesystemProviderInstance::Teardown(state);
                    Ok(NativeFilesystemProviderRetirement {
                        termination,
                        dispatch,
                    })
                }
                Err(error) => Err(NativeFilesystemProviderActiveRetirementError::Retirement(
                    error,
                )),
            };
        }
    }
    let active = match receipt.instance {
        NativeFilesystemProviderInstance::Active(active) => active,
        NativeFilesystemProviderInstance::Teardown(state)
            if state.is_pristine() && state.retired_context().is_none() =>
        {
            state.active()
        }
        NativeFilesystemProviderInstance::Teardown(_) => {
            return Err(NativeFilesystemProviderActiveRetirementError::TeardownProgressed);
        }
    };
    match unsafe {
        retire_current_native_component_service_copy_read_transfer_on_active_x86_64(
            active, runtime, memory,
        )
    } {
        Ok((termination, state)) => {
            receipt.instance = NativeFilesystemProviderInstance::Teardown(state);
            let dispatch = runtime
                .dispatch_after_termination(termination)
                .map_err(
                    |error| NativeFilesystemProviderActiveRetirementError::Dispatch {
                        termination,
                        error,
                    },
                )?;
            let Some(state) = state.with_dispatch_issued() else {
                return Err(NativeFilesystemProviderActiveRetirementError::TeardownProgressed);
            };
            receipt.instance = NativeFilesystemProviderInstance::Teardown(state);
            Ok(NativeFilesystemProviderRetirement {
                termination,
                dispatch,
            })
        }
        Err(error) => {
            if let Some(state) = error.state() {
                receipt.instance = NativeFilesystemProviderInstance::Teardown(state);
            }
            Err(NativeFilesystemProviderActiveRetirementError::Retirement(
                error,
            ))
        }
    }
}

fn reject_native_filesystem_provider_preflight<const TASKS: usize, const CAPABILITIES: usize>(
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    source_task: TaskId,
    transfer: ComponentServiceReadTransferAttachment,
    preflight: NativeFilesystemProviderLaunchPreflightError,
) -> NativeFilesystemProviderLaunchError {
    match runtime.revoke_capability_pair(
        source_task,
        transfer.local_read(),
        transfer.provider_write(),
    ) {
        Ok(()) => NativeFilesystemProviderLaunchError::Preflight(preflight),
        Err(cleanup) => NativeFilesystemProviderLaunchError::Rollback { preflight, cleanup },
    }
}

#[allow(clippy::too_many_arguments)]
pub fn launch_native_filesystem_provider<const TASKS: usize, const CAPABILITIES: usize>(
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    source_task: TaskId,
    target_task: TaskId,
    block_endpoint: Capability,
    transfer: ComponentServiceReadTransferAttachment,
    association: FilesystemBlockAssociation,
    service: IsolationServiceSpec,
    launch_attachment: ComponentServiceLaunchAttachment,
    memory: ComponentServiceReadTransferMemoryRoot,
    binding: ComponentServiceReadTransferCopyTaskBinding,
    local_page_table_root: mrml_kernel::PhysAddr,
    supervisor_task_object: ObjectId,
) -> Result<
    FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    NativeFilesystemProviderLaunchError,
> {
    let target_context = match runtime.context(target_task) {
        Ok(context) => context,
        Err(error) => {
            return Err(reject_native_filesystem_provider_preflight(
                runtime,
                source_task,
                transfer,
                NativeFilesystemProviderLaunchPreflightError::Target(error),
            ));
        }
    };
    if supervisor_task_object != ObjectId(source_task.token()) {
        return Err(reject_native_filesystem_provider_preflight(
            runtime,
            source_task,
            transfer,
            NativeFilesystemProviderLaunchPreflightError::WrongSupervisorTask,
        ));
    }
    match runtime.construction_pending(target_task) {
        Ok(true) => {}
        Ok(false) => {
            return Err(reject_native_filesystem_provider_preflight(
                runtime,
                source_task,
                transfer,
                NativeFilesystemProviderLaunchPreflightError::TargetNotConstructionPending,
            ));
        }
        Err(error) => {
            return Err(reject_native_filesystem_provider_preflight(
                runtime,
                source_task,
                transfer,
                NativeFilesystemProviderLaunchPreflightError::Target(error),
            ));
        }
    }
    if target_context.page_table() != local_page_table_root {
        return Err(reject_native_filesystem_provider_preflight(
            runtime,
            source_task,
            transfer,
            NativeFilesystemProviderLaunchPreflightError::WrongPageTableRoot,
        ));
    }
    let preflight = runtime
        .capabilities(source_task)
        .map_err(NativeFilesystemProviderLaunchPreflightError::Source)
        .and_then(|capabilities| {
            let endpoint_object = capabilities
                .authorize_exact(block_endpoint, Rights::SIGNAL.union(Rights::DELEGATE))
                .map_err(NativeFilesystemProviderLaunchPreflightError::Capability)?;
            if endpoint_object != association.block_binding.endpoint_object {
                return Err(NativeFilesystemProviderLaunchPreflightError::WrongEndpointAuthority);
            }
            let local_object = capabilities
                .authorize_exact(
                    transfer.local_read(),
                    Rights::MAP.union(Rights::READ).union(Rights::DELEGATE),
                )
                .map_err(NativeFilesystemProviderLaunchPreflightError::Capability)?;
            let write_object = capabilities
                .authorize_exact(
                    transfer.provider_write(),
                    Rights::MAP.union(Rights::WRITE).union(Rights::DELEGATE),
                )
                .map_err(NativeFilesystemProviderLaunchPreflightError::Capability)?;
            if local_object != transfer.shared_object() || write_object != transfer.shared_object()
            {
                return Err(NativeFilesystemProviderLaunchPreflightError::WrongTransferAuthority);
            }
            if transfer.shared_bytes() < association.logical_block_bytes {
                return Err(NativeFilesystemProviderLaunchPreflightError::TransferTooSmall);
            }
            NativeFilesystemProviderLaunchSpec::new(
                association,
                service,
                launch_attachment,
                block_endpoint,
            )
            .map_err(NativeFilesystemProviderLaunchPreflightError::Spec)
        });
    if let Err(preflight) = preflight {
        return Err(reject_native_filesystem_provider_preflight(
            runtime,
            source_task,
            transfer,
            preflight,
        ));
    }
    let active = prepare_native_component_service_task_from_copy_read_transfer_attachment(
        runtime,
        source_task,
        target_task,
        service,
        launch_attachment,
        transfer,
        memory,
        binding,
        local_page_table_root,
        association.filesystem_binding.endpoint_object,
        supervisor_task_object,
        association.filesystem_binding.module_object,
    )
    .map_err(NativeFilesystemProviderLaunchError::Construction)?;
    Ok(receipt(
        association.filesystem_binding.provider_object,
        association.handoff(),
        NativeFilesystemProviderInstance::Active(active),
    ))
}

pub struct NativeFilesystemProviderTeardownBackend<
    'a,
    F,
    B,
    const POOLS: usize,
    const OBJECTS: usize,
    const MAPPINGS: usize,
    const TASKS: usize,
    const CAPABILITIES: usize,
> {
    runtime: &'a mut TaskRuntime<TASKS, CAPABILITIES>,
    memory: &'a mut MemoryPoolTable<POOLS, OBJECTS, MAPPINGS>,
    local_backend: &'a mut F,
    backing_backend: &'a mut B,
}

impl<
    'a,
    F,
    B,
    const POOLS: usize,
    const OBJECTS: usize,
    const MAPPINGS: usize,
    const TASKS: usize,
    const CAPABILITIES: usize,
> NativeFilesystemProviderTeardownBackend<'a, F, B, POOLS, OBJECTS, MAPPINGS, TASKS, CAPABILITIES>
{
    pub const fn new(
        runtime: &'a mut TaskRuntime<TASKS, CAPABILITIES>,
        memory: &'a mut MemoryPoolTable<POOLS, OBJECTS, MAPPINGS>,
        local_backend: &'a mut F,
        backing_backend: &'a mut B,
    ) -> Self {
        Self {
            runtime,
            memory,
            local_backend,
            backing_backend,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemProviderTeardownError<I, E> {
    receipt: FilesystemProviderLaunchReceipt<I>,
    error: E,
}

impl<I, E> FilesystemProviderTeardownError<I, E> {
    pub const fn receipt(&self) -> &FilesystemProviderLaunchReceipt<I> {
        &self.receipt
    }

    pub const fn error(&self) -> &E {
        &self.error
    }

    pub fn into_parts(self) -> (FilesystemProviderLaunchReceipt<I>, E) {
        (self.receipt, self.error)
    }
}

/// Placement-specific construction boundary for an isolated filesystem
/// provider with one exact block dependency.
///
/// # Safety
///
/// Implementations must create a fresh provider domain, project `handoff` as
/// read-only launch data, attenuate `block_endpoint` to exact SIGNAL, project
/// the attachment's local read and delegable provider-write handles, bind all
/// projections to that same domain generation, and publish no endpoint or ready
/// signal unless every projection and provider construction succeeds. Failure
/// must revoke and erase every partial projection and domain. A successful
/// return must be the exact live instance or cleanup owner for those resources;
/// the caller retains it in the launch receipt until supervised teardown.
pub unsafe trait FilesystemProviderLaunchBackend {
    type Error;
    type Instance;

    fn launch(
        &mut self,
        association: FilesystemBlockAssociation,
        handoff: &[u8; FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES],
        block_endpoint: Capability,
        transfer: ComponentServiceReadTransferAttachment,
    ) -> Result<Self::Instance, Self::Error>;
}

/// Placement-specific teardown boundary for a successfully launched provider.
///
/// # Safety
///
/// Implementations must advance `instance` only after each cleanup stage is
/// confirmed. On failure it must retain the exact live resources and progress
/// needed for a safe retry. Success means the complete provider domain and all
/// projections owned by the instance are retired.
pub unsafe trait FilesystemProviderTeardownBackend {
    type Instance;
    type TeardownError;

    fn teardown(&mut self, instance: &mut Self::Instance) -> Result<(), Self::TeardownError>;
}

pub fn launch_filesystem_provider<B: FilesystemProviderLaunchBackend, const CAPABILITIES: usize>(
    capabilities: &CapabilitySpace<CAPABILITIES>,
    block_endpoint_capability: Capability,
    transfer: ComponentServiceReadTransferAttachment,
    association: FilesystemBlockAssociation,
    backend: &mut B,
) -> Result<FilesystemProviderLaunchReceipt<B::Instance>, FilesystemProviderLaunchError<B::Error>> {
    let endpoint_object = capabilities
        .authorize_exact(
            block_endpoint_capability,
            Rights::SIGNAL.union(Rights::DELEGATE),
        )
        .map_err(FilesystemProviderLaunchError::Capability)?;
    if endpoint_object != association.block_binding.endpoint_object {
        return Err(FilesystemProviderLaunchError::WrongEndpointAuthority);
    }
    let local_object = capabilities
        .authorize_exact(
            transfer.local_read(),
            Rights::MAP.union(Rights::READ).union(Rights::DELEGATE),
        )
        .map_err(FilesystemProviderLaunchError::Capability)?;
    let write_object = capabilities
        .authorize_exact(
            transfer.provider_write(),
            Rights::MAP.union(Rights::WRITE).union(Rights::DELEGATE),
        )
        .map_err(FilesystemProviderLaunchError::Capability)?;
    if local_object != transfer.shared_object() || write_object != transfer.shared_object() {
        return Err(FilesystemProviderLaunchError::WrongTransferAuthority);
    }
    if transfer.shared_bytes() < association.logical_block_bytes {
        return Err(FilesystemProviderLaunchError::TransferTooSmall);
    }
    let handoff = association.handoff();
    let mut encoded = handoff.encode();
    let launched = backend
        .launch(association, &encoded, block_endpoint_capability, transfer)
        .map_err(FilesystemProviderLaunchError::Backend);
    encoded.fill(0);
    Ok(receipt(
        association.filesystem_binding.provider_object,
        handoff,
        launched?,
    ))
}

fn receipt<I>(
    provider_object: ObjectId,
    handoff: FilesystemBlockAssociationHandoff,
    instance: I,
) -> FilesystemProviderLaunchReceipt<I> {
    FilesystemProviderLaunchReceipt {
        provider_object,
        filesystem_module_object: ObjectId(handoff.filesystem_module_object()),
        block_endpoint_object: ObjectId(handoff.block_endpoint_object()),
        association_generation: handoff.association_generation(),
        filesystem_provider_generation: handoff.filesystem_provider_generation(),
        block_provider_generation: handoff.block_provider_generation(),
        system_generation: handoff.system_generation(),
        instance,
    }
}

pub fn teardown_filesystem_provider<B: FilesystemProviderTeardownBackend>(
    mut receipt: FilesystemProviderLaunchReceipt<B::Instance>,
    backend: &mut B,
) -> Result<(), FilesystemProviderTeardownError<B::Instance, B::TeardownError>> {
    match backend.teardown(&mut receipt.instance) {
        Ok(()) => Ok(()),
        Err(error) => Err(FilesystemProviderTeardownError { receipt, error }),
    }
}

// SAFETY: the exact kernel retry state replaces the active instance before any
// backend error is returned. A caller therefore retries from confirmed progress
// and cannot repeat a completed unmap, scrub, or object release.
unsafe impl<
    'a,
    F: MemoryMappingRevocationBackend,
    B: MemoryObjectBackingBackend,
    const POOLS: usize,
    const OBJECTS: usize,
    const MAPPINGS: usize,
    const TASKS: usize,
    const CAPABILITIES: usize,
> FilesystemProviderTeardownBackend
    for NativeFilesystemProviderTeardownBackend<
        'a,
        F,
        B,
        POOLS,
        OBJECTS,
        MAPPINGS,
        TASKS,
        CAPABILITIES,
    >
{
    type Instance = NativeFilesystemProviderInstance;
    type TeardownError = NativeComponentServiceCopyReadTransferTeardownError<F::Error, B::Error>;

    fn teardown(&mut self, instance: &mut Self::Instance) -> Result<(), Self::TeardownError> {
        let state = match *instance {
            NativeFilesystemProviderInstance::Active(active) => {
                NativeComponentServiceCopyReadTransferTeardown::new(active)
            }
            NativeFilesystemProviderInstance::Teardown(state) => state,
        };
        match teardown_native_component_service_copy_read_transfer(
            state,
            self.runtime,
            self.memory,
            self.local_backend,
            self.backing_backend,
        ) {
            Ok(released_pages) => {
                debug_assert_eq!(released_pages, 1);
                Ok(())
            }
            Err(error) => {
                *instance = NativeFilesystemProviderInstance::Teardown(error.state());
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{StorageModuleBinding, StorageModuleClass};
    use mrml_interface_storage_block_provider_v1::OpaqueHandle as BlockOpaqueHandle;
    use mrml_interface_storage_filesystem_v3::OpaqueHandle as FilesystemOpaqueHandle;
    use mrml_kernel::ObjectId;
    use mrml_kernel::arch::x86_64::{
        InactivePageTableMappingBackend, Mapping, PagePermissions, PageTableBuilder,
        PreallocatedPageTableStore, UserContext, VirtAddr,
    };
    use mrml_kernel::{
        IsolationServiceSpec, MemoryBackingBackendRequest, MemoryPhysicalBacking, MemoryPoolTable,
        Priority, ScheduleOutcome, TotalMicrovmClass,
    };

    #[test]
    fn retirement_transfers_exact_termination_with_opaque_dispatch() {
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let exiting = runtime
            .create(
                Priority::NORMAL,
                UserContext::new(
                    mrml_kernel::PhysAddr::new(0x20_0000).unwrap(),
                    0x40_0000,
                    0x7000_0000,
                )
                .unwrap(),
            )
            .unwrap();
        let successor_context = UserContext::new(
            mrml_kernel::PhysAddr::new(0x30_0000).unwrap(),
            0x50_0000,
            0x7100_0000,
        )
        .unwrap();
        let successor = runtime.create(Priority::NORMAL, successor_context).unwrap();
        assert!(matches!(
            runtime.start(),
            ScheduleOutcome::Switch { to, .. } if to == exiting
        ));
        let termination = runtime.terminate_current().unwrap();
        let dispatch = runtime.dispatch_after_termination(termination).unwrap();
        let retirement = NativeFilesystemProviderRetirement {
            termination,
            dispatch,
        };

        let (retained_termination, retained_dispatch) = retirement.into_parts();
        assert_eq!(retained_termination.task(), exiting);
        assert_eq!(
            retained_termination.outcome(),
            ScheduleOutcome::Switch {
                from: Some(exiting),
                to: successor,
            }
        );
        assert_eq!(
            retained_dispatch.user(),
            Some((successor, successor_context))
        );
    }

    #[derive(Default)]
    struct NativeBackingBackend {
        claimed: Option<MemoryBackingBackendRequest>,
    }

    unsafe impl MemoryObjectBackingBackend for NativeBackingBackend {
        type Error = &'static str;

        fn claim_zeroed(
            &mut self,
            request: MemoryBackingBackendRequest,
        ) -> Result<(), Self::Error> {
            if self.claimed.replace(request).is_some() {
                return Err("occupied");
            }
            Ok(())
        }

        fn release_scrubbed(
            &mut self,
            request: MemoryBackingBackendRequest,
        ) -> Result<(), Self::Error> {
            if self.claimed != Some(request) {
                return Err("substitution");
            }
            self.claimed = None;
            Ok(())
        }
    }

    #[repr(C, align(4096))]
    struct PageTableArena([u64; 512 * 5]);

    struct RejectingRevoker;

    // SAFETY: this backend never mutates native mapping state and never reports
    // successful withdrawal.
    unsafe impl MemoryMappingRevocationBackend for RejectingRevoker {
        type Error = &'static str;

        fn revoke(
            &mut self,
            _request: mrml_kernel::MemoryMappingBackendRequest,
        ) -> Result<(), Self::Error> {
            Err("revoke")
        }
    }

    #[derive(Default)]
    struct AddressSpaceEraser {
        erased: Option<TaskId>,
    }

    impl mrml_kernel::ServiceAddressSpaceEraser for AddressSpaceEraser {
        type Error = ();

        fn erase(&mut self, task: TaskId, _: UserContext) -> Result<(), Self::Error> {
            self.erased = Some(task);
            Ok(())
        }
    }

    struct RejectingAddressSpaceEraser;

    impl mrml_kernel::ServiceAddressSpaceEraser for RejectingAddressSpaceEraser {
        type Error = &'static str;

        fn erase(&mut self, _: TaskId, _: UserContext) -> Result<(), Self::Error> {
            Err("erase")
        }
    }

    struct Backend {
        fail: bool,
        fail_teardown: bool,
        calls: usize,
        teardown_calls: usize,
        observed: [u8; FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES],
    }

    unsafe impl FilesystemProviderTeardownBackend for Backend {
        type Instance = u64;
        type TeardownError = ();

        fn teardown(&mut self, instance: &mut Self::Instance) -> Result<(), Self::TeardownError> {
            self.teardown_calls += 1;
            *instance += 1;
            if self.fail_teardown { Err(()) } else { Ok(()) }
        }
    }

    unsafe impl FilesystemProviderLaunchBackend for Backend {
        type Error = ();
        type Instance = u64;

        fn launch(
            &mut self,
            association: FilesystemBlockAssociation,
            handoff: &[u8; FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES],
            block_endpoint: Capability,
            transfer: ComponentServiceReadTransferAttachment,
        ) -> Result<Self::Instance, Self::Error> {
            assert_eq!(association.association_generation, 12);
            assert_ne!(block_endpoint.token(), 0);
            assert_eq!(transfer.shared_bytes(), 4096);
            self.calls += 1;
            self.observed = *handoff;
            if self.fail { Err(()) } else { Ok(0xfeed) }
        }
    }

    fn association() -> FilesystemBlockAssociation {
        FilesystemBlockAssociation {
            filesystem_binding: StorageModuleBinding {
                class: StorageModuleClass::Filesystem,
                module_object: ObjectId(41),
                interface_object: ObjectId(42),
                provider_object: ObjectId(43),
                endpoint_object: ObjectId(44),
                interface_generation: 3,
                provider_generation: 5,
                system_generation: 9,
                binding_generation: 3,
            },
            block_binding: StorageModuleBinding {
                class: StorageModuleClass::BlockProvider,
                module_object: ObjectId(11),
                interface_object: ObjectId(10),
                provider_object: ObjectId(20),
                endpoint_object: ObjectId(21),
                interface_generation: 1,
                provider_generation: 7,
                system_generation: 9,
                binding_generation: 4,
            },
            volume: FilesystemOpaqueHandle::new(2, 6).unwrap(),
            block_session: BlockOpaqueHandle::new(8, 10).unwrap(),
            logical_block_bytes: 4096,
            association_generation: 12,
        }
    }

    fn provider_task() -> mrml_kernel::TaskId {
        let mut runtime = mrml_kernel::TaskRuntime::<1, 1>::new(100, 1).unwrap();
        runtime
            .create(
                mrml_kernel::Priority::NORMAL,
                UserContext::new(
                    mrml_kernel::PhysAddr::new(0x20_0000).unwrap(),
                    0x40_0000,
                    0x7000_0000,
                )
                .unwrap(),
            )
            .unwrap()
    }

    fn transfer_attachment<const C: usize>(
        capabilities: &mut CapabilitySpace<C>,
    ) -> ComponentServiceReadTransferAttachment {
        let local_read = capabilities
            .insert(
                ObjectId(0x80),
                Rights::MAP.union(Rights::READ).union(Rights::DELEGATE),
            )
            .unwrap();
        let provider_write = capabilities
            .insert(
                ObjectId(0x80),
                Rights::MAP.union(Rights::WRITE).union(Rights::DELEGATE),
            )
            .unwrap();
        ComponentServiceReadTransferAttachment::new(
            provider_task(),
            ObjectId(0x80),
            6,
            4096,
            local_read,
            provider_write,
            capabilities,
        )
        .unwrap()
    }

    fn native_launch_spec(
        association_generation: u64,
        launch_data_bytes: u32,
    ) -> (
        CapabilitySpace<2>,
        Capability,
        IsolationServiceSpec,
        ComponentServiceLaunchAttachment,
    ) {
        let association = association();
        let service = IsolationServiceSpec::new(
            association.filesystem_binding.provider_object,
            association.filesystem_binding.interface_object,
            association.filesystem_binding.interface_generation,
            association.filesystem_binding.provider_generation,
            association.filesystem_binding.system_generation,
            2,
            TotalMicrovmClass::MicrovmEligible,
            IsolationPlacement::NativeService,
        )
        .unwrap();
        let mut capabilities = CapabilitySpace::<2>::new();
        let data = capabilities
            .insert(ObjectId(0x90), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let endpoint = capabilities
            .insert(
                association.block_binding.endpoint_object,
                Rights::SIGNAL.union(Rights::DELEGATE),
            )
            .unwrap();
        let attachment = ComponentServiceLaunchAttachment::new(
            service,
            association_generation,
            ObjectId(0x90),
            3,
            launch_data_bytes,
            data,
            association.block_binding.endpoint_object,
            association.block_binding.binding_generation,
            endpoint,
            &capabilities,
        )
        .unwrap();
        (capabilities, endpoint, service, attachment)
    }

    #[test]
    fn exact_endpoint_launches_with_canonical_handoff_and_returns_bound_receipt() {
        let association = association();
        let mut capabilities = CapabilitySpace::<3>::new();
        let endpoint = capabilities
            .insert(
                association.block_binding.endpoint_object,
                Rights::SIGNAL.union(Rights::DELEGATE),
            )
            .unwrap();
        let transfer = transfer_attachment(&mut capabilities);
        let mut backend = Backend {
            fail: false,
            fail_teardown: false,
            calls: 0,
            teardown_calls: 0,
            observed: [0; FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES],
        };
        let receipt = launch_filesystem_provider(
            &capabilities,
            endpoint,
            transfer,
            association,
            &mut backend,
        )
        .unwrap();
        assert_eq!(backend.calls, 1);
        assert_eq!(
            FilesystemBlockAssociationHandoff::decode(&backend.observed),
            Ok(association.handoff())
        );
        assert_eq!(receipt.association_generation(), 12);
        assert_eq!(receipt.filesystem_module_object(), ObjectId(41));
        assert_eq!(receipt.block_endpoint_object(), ObjectId(21));
        assert_eq!(receipt.filesystem_provider_generation(), 5);
        assert_eq!(receipt.block_provider_generation(), 7);
        assert_eq!(receipt.system_generation(), 9);
        assert_eq!(*receipt.instance(), 0xfeed);
        assert_eq!(receipt.into_instance(), 0xfeed);
    }

    #[test]
    fn native_ready_admission_exact_matches_sender_receipt_and_zero_authority() {
        let association = association();
        let receipt = receipt(
            association.filesystem_binding.provider_object,
            association.handoff(),
            0_u8,
        );
        let expected = TaskId::from_token((2_u64 << 32) | 3);
        let ready = FilesystemProviderReady::new(41, 5, 7, 9, 12, 21).unwrap();
        let message = mrml_kernel::Message::new(&ready.encode(), &[]).unwrap();
        assert_eq!(
            validate_native_filesystem_provider_ready(&receipt, expected, expected, &message),
            Ok(())
        );
        assert_eq!(
            validate_native_filesystem_provider_ready(
                &receipt,
                expected,
                TaskId::from_token((3_u64 << 32) | 3),
                &message,
            ),
            Err(NativeFilesystemProviderReadyError::WrongSender)
        );
        let authority = Capability::from_token((4_u64 << 32) | 5);
        let with_authority = mrml_kernel::Message::new(&ready.encode(), &[authority]).unwrap();
        assert_eq!(
            validate_native_filesystem_provider_ready(
                &receipt,
                expected,
                expected,
                &with_authority,
            ),
            Err(NativeFilesystemProviderReadyError::TransferredCapabilities)
        );
        let malformed = mrml_kernel::Message::new(&ready.encode()[..103], &[]).unwrap();
        assert_eq!(
            validate_native_filesystem_provider_ready(&receipt, expected, expected, &malformed),
            Err(NativeFilesystemProviderReadyError::Protocol(
                ProtocolError::InvalidResponse
            ))
        );
        let substitutions = [
            (
                FilesystemProviderReady::new(42, 5, 7, 9, 12, 21).unwrap(),
                NativeFilesystemProviderReadyError::WrongFilesystemModule,
            ),
            (
                FilesystemProviderReady::new(41, 6, 7, 9, 12, 21).unwrap(),
                NativeFilesystemProviderReadyError::WrongFilesystemProviderGeneration,
            ),
            (
                FilesystemProviderReady::new(41, 5, 8, 9, 12, 21).unwrap(),
                NativeFilesystemProviderReadyError::WrongBlockProviderGeneration,
            ),
            (
                FilesystemProviderReady::new(41, 5, 7, 10, 12, 21).unwrap(),
                NativeFilesystemProviderReadyError::WrongSystemGeneration,
            ),
            (
                FilesystemProviderReady::new(41, 5, 7, 9, 13, 21).unwrap(),
                NativeFilesystemProviderReadyError::WrongAssociationGeneration,
            ),
            (
                FilesystemProviderReady::new(41, 5, 7, 9, 12, 22).unwrap(),
                NativeFilesystemProviderReadyError::WrongBlockEndpoint,
            ),
        ];
        for (substituted, expected_error) in substitutions {
            let substituted = mrml_kernel::Message::new(&substituted.encode(), &[]).unwrap();
            assert_eq!(
                validate_native_filesystem_provider_ready(
                    &receipt,
                    expected,
                    expected,
                    &substituted,
                ),
                Err(expected_error)
            );
        }
    }

    #[test]
    fn native_launch_spec_exact_matches_service_handoff_and_endpoint() {
        let association = association();
        let (_capabilities, endpoint, service, attachment) =
            native_launch_spec(association.association_generation, 144);
        let plan =
            NativeFilesystemProviderLaunchSpec::new(association, service, attachment, endpoint)
                .unwrap();
        assert_eq!(plan.service(), service);
        assert_eq!(plan.attachment(), attachment);

        let mut wrong_provider = association;
        wrong_provider.filesystem_binding.provider_generation += 1;
        assert_eq!(
            NativeFilesystemProviderLaunchSpec::new(wrong_provider, service, attachment, endpoint,),
            Err(NativeFilesystemProviderLaunchSpecError::WrongProviderGeneration)
        );
        let (_capabilities, endpoint, service, wrong_association) =
            native_launch_spec(association.association_generation + 1, 144);
        assert_eq!(
            NativeFilesystemProviderLaunchSpec::new(
                association,
                service,
                wrong_association,
                endpoint,
            ),
            Err(NativeFilesystemProviderLaunchSpecError::WrongAssociationGeneration)
        );
        let (_capabilities, endpoint, service, wrong_length) =
            native_launch_spec(association.association_generation, 143);
        assert_eq!(
            NativeFilesystemProviderLaunchSpec::new(association, service, wrong_length, endpoint,),
            Err(NativeFilesystemProviderLaunchSpecError::WrongLaunchDataLength)
        );
    }

    #[test]
    fn restart_association_rejects_every_identity_and_generation_substitution() {
        let association = association();
        let retired = receipt(
            association.filesystem_binding.provider_object,
            association.handoff(),
            1_u8,
        );
        let exact = receipt(
            association.filesystem_binding.provider_object,
            association.handoff(),
            2_u16,
        );
        assert_eq!(
            validate_native_filesystem_provider_restart_association(&retired, &exact),
            Ok(())
        );

        let candidate = |provider_object, candidate: FilesystemBlockAssociation| {
            receipt(provider_object, candidate.handoff(), 3_u32)
        };
        assert_eq!(
            validate_native_filesystem_provider_restart_association(
                &retired,
                &candidate(ObjectId(0xdead), association),
            ),
            Err(NativeFilesystemProviderRestartError::WrongProviderObject)
        );
        let mut substituted = association;
        substituted.association_generation += 1;
        assert_eq!(
            validate_native_filesystem_provider_restart_association(
                &retired,
                &candidate(association.filesystem_binding.provider_object, substituted),
            ),
            Err(NativeFilesystemProviderRestartError::WrongAssociationGeneration)
        );
        substituted = association;
        substituted.filesystem_binding.provider_generation += 1;
        assert_eq!(
            validate_native_filesystem_provider_restart_association(
                &retired,
                &candidate(association.filesystem_binding.provider_object, substituted),
            ),
            Err(NativeFilesystemProviderRestartError::WrongFilesystemProviderGeneration)
        );
        substituted = association;
        substituted.block_binding.provider_generation += 1;
        assert_eq!(
            validate_native_filesystem_provider_restart_association(
                &retired,
                &candidate(association.filesystem_binding.provider_object, substituted),
            ),
            Err(NativeFilesystemProviderRestartError::WrongBlockProviderGeneration)
        );
        substituted = association;
        substituted.filesystem_binding.system_generation += 1;
        assert_eq!(
            validate_native_filesystem_provider_restart_association(
                &retired,
                &candidate(association.filesystem_binding.provider_object, substituted),
            ),
            Err(NativeFilesystemProviderRestartError::WrongSystemGeneration)
        );
    }

    #[test]
    fn native_preflight_rejection_revokes_both_consumed_transfer_roots() {
        let mut runtime = TaskRuntime::<1, 2>::new(100, 1).unwrap();
        let source = runtime
            .create(
                mrml_kernel::Priority::NORMAL,
                UserContext::new(
                    mrml_kernel::PhysAddr::new(0x20_0000).unwrap(),
                    0x40_0000,
                    0x7000_0000,
                )
                .unwrap(),
            )
            .unwrap();
        let local_read = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(
                ObjectId(0xa0),
                Rights::MAP.union(Rights::READ).union(Rights::DELEGATE),
            )
            .unwrap();
        let provider_write = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(
                ObjectId(0xa0),
                Rights::MAP.union(Rights::WRITE).union(Rights::DELEGATE),
            )
            .unwrap();
        let transfer = ComponentServiceReadTransferAttachment::new(
            provider_task(),
            ObjectId(0xa0),
            1,
            4096,
            local_read,
            provider_write,
            runtime.capabilities(source).unwrap(),
        )
        .unwrap();
        assert_eq!(
            reject_native_filesystem_provider_preflight(
                &mut runtime,
                source,
                transfer,
                NativeFilesystemProviderLaunchPreflightError::WrongTransferAuthority,
            ),
            NativeFilesystemProviderLaunchError::Preflight(
                NativeFilesystemProviderLaunchPreflightError::WrongTransferAuthority
            )
        );
        assert_eq!(
            runtime
                .capabilities(source)
                .unwrap()
                .authorize(local_read, Rights::READ),
            Err(CapabilityError::Invalid)
        );
        assert_eq!(
            runtime
                .capabilities(source)
                .unwrap()
                .authorize(provider_write, Rights::WRITE),
            Err(CapabilityError::Invalid)
        );
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum SupervisedFailureKind {
        Retirement,
        RetirementRestart,
        Fault,
        ProtocolViolation,
    }

    fn native_launch_and_teardown_retain_one_exact_copy_task_lifecycle(
        failure_kind: SupervisedFailureKind,
    ) {
        let association = association();
        let mut page_tables = PageTableArena([0; 512 * 5]);
        let page_table_base =
            mrml_kernel::PhysAddr::new(page_tables.0.as_mut_ptr() as u64).unwrap();
        let mut runtime = TaskRuntime::<3, 8>::new(1_000, 1).unwrap();
        let context = |physical, page_table, stack| {
            UserContext::new(
                mrml_kernel::PhysAddr::new(physical).unwrap(),
                page_table,
                stack,
            )
            .unwrap()
        };
        let source = runtime
            .create(
                mrml_kernel::Priority::NORMAL,
                context(0x20_0000, 0x40_0000, 0x7000_0000),
            )
            .unwrap();
        let target = runtime
            .create_for_construction(
                mrml_kernel::Priority::NORMAL,
                context(page_table_base.get(), 0x50_0000, 0x7100_0000),
            )
            .unwrap();
        let provider = runtime
            .create(
                mrml_kernel::Priority::NORMAL,
                context(0x40_0000, 0x60_0000, 0x7200_0000),
            )
            .unwrap();
        let mut memory = MemoryPoolTable::<1, 1, 1>::new(0x2a).unwrap();
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
        let root = mrml_kernel::reserve_component_service_read_transfer_memory(
            &mut memory,
            pool,
            pool_capability,
            &mut runtime,
            source,
        )
        .unwrap();
        let mut backing = NativeBackingBackend::default();
        mrml_kernel::bind_component_service_read_transfer_backing(
            &mut memory,
            root,
            MemoryPhysicalBacking::new(mrml_kernel::PhysAddr::new(0x80_0000).unwrap(), 1).unwrap(),
            &runtime,
            source,
            &mut backing,
        )
        .unwrap();
        let local_target = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(ObjectId(0x7100), Rights::MAP.union(Rights::CONTROL))
            .unwrap();
        // SAFETY: the aligned test arena remains exclusively owned and
        // unreachable by every CPU for the complete adapter lifetime.
        let store = unsafe { PreallocatedPageTableStore::new(page_table_base, 5) }.unwrap();
        let builder = PageTableBuilder::new(store).unwrap();
        // SAFETY: the builder is exclusively owned and never activated.
        let mut local_mapping =
            unsafe { InactivePageTableMappingBackend::new(builder, ObjectId(0x7100)) };
        let mapping = mrml_kernel::install_component_service_read_transfer_local_mapping(
            &mut memory,
            root,
            local_target,
            0x300,
            &mut local_mapping,
            &runtime,
            source,
        )
        .unwrap();
        let binding = mrml_kernel::bind_component_service_read_transfer_copy_tasks(
            mapping, target, provider, &runtime,
        )
        .unwrap();
        let service = IsolationServiceSpec::new(
            association.filesystem_binding.provider_object,
            association.filesystem_binding.interface_object,
            association.filesystem_binding.interface_generation,
            association.filesystem_binding.provider_generation,
            association.filesystem_binding.system_generation,
            2,
            TotalMicrovmClass::MicrovmEligible,
            IsolationPlacement::NativeService,
        )
        .unwrap();
        let launch_data = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(ObjectId(0x90), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let endpoint = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(
                association.block_binding.endpoint_object,
                Rights::SIGNAL.union(Rights::DELEGATE),
            )
            .unwrap();
        let launch_attachment = ComponentServiceLaunchAttachment::new(
            service,
            association.association_generation,
            ObjectId(0x90),
            3,
            FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES as u32,
            launch_data,
            association.block_binding.endpoint_object,
            association.block_binding.binding_generation,
            endpoint,
            runtime.capabilities(source).unwrap(),
        )
        .unwrap();
        let transfer = mrml_kernel::prepare_component_service_read_transfer_attachment(
            &mut runtime,
            source,
            provider,
            root.shared_object(),
            root.generation(),
            root.bytes(),
            root.root(),
        )
        .unwrap();
        let wrong_root =
            mrml_kernel::PhysAddr::new(page_table_base.get() + mrml_kernel::PAGE_SIZE).unwrap();
        assert_eq!(
            launch_native_filesystem_provider(
                &mut runtime,
                source,
                target,
                endpoint,
                transfer,
                association,
                service,
                launch_attachment,
                root,
                binding,
                local_mapping.root(),
                ObjectId(0x91),
            ),
            Err(NativeFilesystemProviderLaunchError::Preflight(
                NativeFilesystemProviderLaunchPreflightError::WrongSupervisorTask
            ))
        );
        let transfer = mrml_kernel::prepare_component_service_read_transfer_attachment(
            &mut runtime,
            source,
            provider,
            root.shared_object(),
            root.generation(),
            root.bytes(),
            root.root(),
        )
        .unwrap();
        assert_eq!(
            launch_native_filesystem_provider(
                &mut runtime,
                source,
                target,
                endpoint,
                transfer,
                association,
                service,
                launch_attachment,
                root,
                binding,
                wrong_root,
                ObjectId(source.token()),
            ),
            Err(NativeFilesystemProviderLaunchError::Preflight(
                NativeFilesystemProviderLaunchPreflightError::WrongPageTableRoot
            ))
        );
        let transfer = mrml_kernel::prepare_component_service_read_transfer_attachment(
            &mut runtime,
            source,
            provider,
            root.shared_object(),
            root.generation(),
            root.bytes(),
            root.root(),
        )
        .unwrap();
        let receipt = launch_native_filesystem_provider(
            &mut runtime,
            source,
            target,
            endpoint,
            transfer,
            association,
            service,
            launch_attachment,
            root,
            binding,
            local_mapping.root(),
            ObjectId(source.token()),
        )
        .unwrap();
        assert_eq!(
            receipt.association_generation(),
            association.association_generation
        );
        assert_eq!(
            receipt.instance().active().unwrap().construction().task(),
            target
        );
        let _blocked_peers = if failure_kind == SupervisedFailureKind::RetirementRestart {
            runtime.start();
            assert_eq!(runtime.current(), Some(source));
            let source_wait = match runtime.receive_or_block_current().unwrap() {
                Err(blocked) => blocked,
                Ok(_) => panic!("empty source inbox must block"),
            };
            assert_eq!(runtime.current(), Some(provider));
            let provider_wait = match runtime.receive_or_block_current().unwrap() {
                Err(blocked) => blocked,
                Ok(_) => panic!("empty provider inbox must block"),
            };
            assert_eq!(runtime.current(), None);
            Some((source_wait, provider_wait))
        } else {
            None
        };
        let mut full_supervisor = ServiceSupervisor::<0>::new();
        let failure = activate_native_filesystem_provider(
            receipt,
            RestartPolicy::ONCE_IMMEDIATE,
            &mut full_supervisor,
            &mut runtime,
        )
        .unwrap_err();
        assert_eq!(
            failure.error(),
            NativeFilesystemProviderActivationError::Service(ServiceError::Full)
        );
        let mut supervisor = ServiceSupervisor::<1>::new();
        let active = activate_native_filesystem_provider(
            failure.into_receipt(),
            RestartPolicy::ONCE_IMMEDIATE,
            &mut supervisor,
            &mut runtime,
        )
        .unwrap();
        assert_eq!(active.task(), target);
        assert_eq!(
            active.receipt().provider_object(),
            association.filesystem_binding.provider_object
        );
        assert_eq!(supervisor.task(active.service()), Ok(Some(target)));
        let active = if failure_kind != SupervisedFailureKind::RetirementRestart {
            let ready_endpoint_object = association.filesystem_binding.endpoint_object;
            let ready_capability = runtime
                .capabilities_mut(target)
                .unwrap()
                .insert(ready_endpoint_object, Rights::SIGNAL)
                .unwrap();
            let ready = FilesystemProviderReady::new(
                association.filesystem_binding.module_object.0,
                association.filesystem_binding.provider_generation,
                association.block_binding.provider_generation,
                association.filesystem_binding.system_generation,
                association.association_generation,
                association.block_binding.endpoint_object.0,
            )
            .unwrap()
            .encode();
            let mut ready_endpoint = mrml_kernel::Endpoint::new(ready_endpoint_object);
            let sequence = runtime
                .deliver_ipc(
                    target,
                    source,
                    &mut ready_endpoint,
                    ready_capability,
                    &ready,
                    &[],
                )
                .unwrap();
            let received = match runtime.receive_control(source).unwrap() {
                mrml_kernel::ControlEvent::Message(received) => received,
                mrml_kernel::ControlEvent::PeerDied(_) => {
                    panic!("ready delivery cannot become peer death")
                }
            };
            let ready = accept_native_filesystem_provider_ready(active, received).unwrap();
            assert_eq!(ready.task(), target);
            assert_eq!(ready.ready_sequence(), sequence);
            ready.into_active()
        } else {
            active
        };
        let service_id = active.service();
        let failure = retire_current_supervised_native_filesystem_provider(
            active,
            &mut supervisor,
            &mut runtime,
        )
        .unwrap_err();
        assert_eq!(failure.error(), ServiceError::TaskMismatch);
        runtime.start();
        runtime.yield_current().unwrap();
        assert_eq!(runtime.current(), Some(target));
        let (dispatch, expected_successor) = match failure_kind {
            SupervisedFailureKind::Retirement | SupervisedFailureKind::RetirementRestart => {
                let retired = retire_current_supervised_native_filesystem_provider(
                    failure.into_active(),
                    &mut supervisor,
                    &mut runtime,
                )
                .unwrap();
                assert_eq!(retired.service(), service_id);
                assert_eq!(retired.task(), target);
                assert!(retired.receipt().instance().active().is_some());
                let successor = runtime.current();
                let successor_context = successor.map(|task| *runtime.context(task).unwrap());
                let mut rejecting = RejectingRevoker;
                let failure = {
                    let mut teardown = NativeFilesystemProviderTeardownBackend::new(
                        &mut runtime,
                        &mut memory,
                        &mut rejecting,
                        &mut backing,
                    );
                    teardown_retired_native_filesystem_provider(retired, &mut teardown).unwrap_err()
                };
                assert!(matches!(
                    failure.error(),
                    NativeComponentServiceCopyReadTransferTeardownError::LocalMapping {
                        error: mrml_kernel::MemoryMappingOperationError::Backend("revoke"),
                        ..
                    }
                ));
                assert!(failure.retired.receipt().instance().teardown().is_some());
                let released = {
                    let mut teardown = NativeFilesystemProviderTeardownBackend::new(
                        &mut runtime,
                        &mut memory,
                        &mut local_mapping,
                        &mut backing,
                    );
                    teardown_retired_native_filesystem_provider(
                        failure.into_retired(),
                        &mut teardown,
                    )
                    .unwrap()
                };
                assert_eq!(released.service(), service_id);
                assert_eq!(released.task(), target);
                assert_eq!(
                    released.receipt().association_generation(),
                    association.association_generation
                );
                let mut rejecting_eraser = RejectingAddressSpaceEraser;
                let failure =
                    complete_resource_released_native_filesystem_provider_retirement_cleanup(
                        released,
                        &mut supervisor,
                        &mut rejecting_eraser,
                    )
                    .unwrap_err();
                assert_eq!(
                    failure.error(),
                    &mrml_kernel::ServiceCleanupError::Eraser("erase")
                );
                let released = failure.into_released();
                assert_eq!(
                    released.receipt().filesystem_provider_generation(),
                    association.filesystem_binding.provider_generation
                );
                let mut eraser = AddressSpaceEraser::default();
                let cleaned =
                    complete_resource_released_native_filesystem_provider_retirement_cleanup(
                        released,
                        &mut supervisor,
                        &mut eraser,
                    )
                    .unwrap();
                assert_eq!(eraser.erased, Some(target));
                assert_eq!(cleaned.service(), service_id);
                assert_eq!(cleaned.task(), target);
                let mut wrong_runtime = TaskRuntime::<1, 1>::new(9_000, 1).unwrap();
                let failure = dispatch_cleaned_native_filesystem_provider_retirement(
                    cleaned,
                    &mut wrong_runtime,
                )
                .unwrap_err();
                assert_eq!(
                    failure.error(),
                    TaskTerminationDispatchError::RetirementRuntimeMismatch
                );
                let cleaned = failure.into_cleaned();
                assert_eq!(
                    cleaned.receipt().system_generation(),
                    association.filesystem_binding.system_generation
                );
                let dispatched =
                    dispatch_cleaned_native_filesystem_provider_retirement(cleaned, &mut runtime)
                        .unwrap();
                assert_eq!(
                    dispatched.receipt().block_provider_generation(),
                    association.block_binding.provider_generation
                );
                assert_eq!(dispatched.service(), service_id);
                assert_eq!(dispatched.task(), target);
                let (restartable, dispatch) = dispatched.into_restart_parts();
                assert_eq!(restartable.service(), service_id);
                assert_eq!(restartable.task(), target);
                assert_eq!(
                    restartable.cause(),
                    NativeFilesystemProviderStopCause::Retirement
                );
                assert_eq!(
                    restartable.receipt().association_generation(),
                    association.association_generation
                );
                if failure_kind == SupervisedFailureKind::RetirementRestart {
                    assert!(dispatch.is_idle());
                    runtime.consume_idle_dispatch(dispatch).unwrap();
                    let mut restart_page_tables = PageTableArena([0; 512 * 5]);
                    let restart_page_table_base =
                        mrml_kernel::PhysAddr::new(restart_page_tables.0.as_mut_ptr() as u64)
                            .unwrap();
                    let replacement = runtime
                        .create_for_construction(
                            mrml_kernel::Priority::NORMAL,
                            context(restart_page_table_base.get(), 0x70_0000, 0x7300_0000),
                        )
                        .unwrap();
                    let restart_root = mrml_kernel::reserve_component_service_read_transfer_memory(
                        &mut memory,
                        pool,
                        pool_capability,
                        &mut runtime,
                        source,
                    )
                    .unwrap();
                    mrml_kernel::bind_component_service_read_transfer_backing(
                        &mut memory,
                        restart_root,
                        MemoryPhysicalBacking::new(
                            mrml_kernel::PhysAddr::new(0x90_0000).unwrap(),
                            1,
                        )
                        .unwrap(),
                        &runtime,
                        source,
                        &mut backing,
                    )
                    .unwrap();
                    let restart_store =
                        unsafe { PreallocatedPageTableStore::new(restart_page_table_base, 5) }
                            .unwrap();
                    let restart_builder = PageTableBuilder::new(restart_store).unwrap();
                    // SAFETY: the second aligned arena is exclusively owned and
                    // remains unreachable by every CPU for this fixture.
                    let mut restart_local_mapping = unsafe {
                        InactivePageTableMappingBackend::new(restart_builder, ObjectId(0x7100))
                    };
                    let restart_mapping =
                        mrml_kernel::install_component_service_read_transfer_local_mapping(
                            &mut memory,
                            restart_root,
                            local_target,
                            0x300,
                            &mut restart_local_mapping,
                            &runtime,
                            source,
                        )
                        .unwrap();
                    let restart_binding =
                        mrml_kernel::bind_component_service_read_transfer_copy_tasks(
                            restart_mapping,
                            replacement,
                            provider,
                            &runtime,
                        )
                        .unwrap();
                    let restart_launch_attachment = ComponentServiceLaunchAttachment::new(
                        service,
                        association.association_generation,
                        ObjectId(0x90),
                        3,
                        FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES as u32,
                        launch_data,
                        association.block_binding.endpoint_object,
                        association.block_binding.binding_generation,
                        endpoint,
                        runtime.capabilities(source).unwrap(),
                    )
                    .unwrap();
                    let restart_transfer =
                        mrml_kernel::prepare_component_service_read_transfer_attachment(
                            &mut runtime,
                            source,
                            provider,
                            restart_root.shared_object(),
                            restart_root.generation(),
                            restart_root.bytes(),
                            restart_root.root(),
                        )
                        .unwrap();
                    let candidate = launch_native_filesystem_provider(
                        &mut runtime,
                        source,
                        replacement,
                        endpoint,
                        restart_transfer,
                        association,
                        service,
                        restart_launch_attachment,
                        restart_root,
                        restart_binding,
                        restart_local_mapping.root(),
                        ObjectId(source.token()),
                    )
                    .unwrap();
                    let restarted = restart_and_activate_native_filesystem_provider(
                        restartable,
                        candidate,
                        &mut supervisor,
                        &mut runtime,
                        0,
                    )
                    .unwrap();
                    assert_eq!(restarted.stopped().service(), service_id);
                    assert_eq!(restarted.stopped().task(), target);
                    assert_eq!(restarted.active().task(), replacement);
                    assert_eq!(
                        restarted.active().service().token(),
                        service_id.token() + (1_u64 << 32)
                    );
                    assert_eq!(
                        supervisor.task(restarted.active().service()),
                        Ok(Some(replacement))
                    );
                    runtime.start();
                    assert_eq!(runtime.current(), Some(replacement));
                    (None, None)
                } else {
                    (Some(dispatch), successor.zip(successor_context))
                }
            }
            SupervisedFailureKind::Fault => {
                let faulted = fault_current_supervised_native_filesystem_provider(
                    failure.into_active(),
                    &mut supervisor,
                    &mut runtime,
                    TrapDisposition::TerminateUser {
                        vector: 14,
                        address: Some(0xfeed_0000),
                    },
                )
                .unwrap();
                assert_eq!(faulted.service(), service_id);
                assert_eq!(faulted.task(), target);
                assert!(faulted.receipt().instance().active().is_some());
                let successor = runtime.current().unwrap();
                let successor_context = *runtime.context(successor).unwrap();
                let mut rejecting = RejectingRevoker;
                let failure = {
                    let mut teardown = NativeFilesystemProviderTeardownBackend::new(
                        &mut runtime,
                        &mut memory,
                        &mut rejecting,
                        &mut backing,
                    );
                    teardown_faulted_native_filesystem_provider(faulted, &mut teardown).unwrap_err()
                };
                assert!(matches!(
                    failure.error(),
                    NativeComponentServiceCopyReadTransferTeardownError::LocalMapping {
                        error: mrml_kernel::MemoryMappingOperationError::Backend("revoke"),
                        ..
                    }
                ));
                assert!(failure.faulted.receipt().instance().teardown().is_some());
                let released = {
                    let mut teardown = NativeFilesystemProviderTeardownBackend::new(
                        &mut runtime,
                        &mut memory,
                        &mut local_mapping,
                        &mut backing,
                    );
                    teardown_faulted_native_filesystem_provider(
                        failure.into_faulted(),
                        &mut teardown,
                    )
                    .unwrap()
                };
                assert_eq!(released.service(), service_id);
                assert_eq!(released.task(), target);
                assert_eq!(
                    released.receipt().association_generation(),
                    association.association_generation
                );
                let mut rejecting_eraser = RejectingAddressSpaceEraser;
                let failure = complete_resource_released_native_filesystem_provider_fault_cleanup(
                    released,
                    &mut supervisor,
                    &mut rejecting_eraser,
                )
                .unwrap_err();
                assert_eq!(
                    failure.error(),
                    &mrml_kernel::ServiceCleanupError::Eraser("erase")
                );
                let released = failure.into_released();
                assert_eq!(
                    released.receipt().filesystem_provider_generation(),
                    association.filesystem_binding.provider_generation
                );
                let mut eraser = AddressSpaceEraser::default();
                let cleaned = complete_resource_released_native_filesystem_provider_fault_cleanup(
                    released,
                    &mut supervisor,
                    &mut eraser,
                )
                .unwrap();
                assert_eq!(eraser.erased, Some(target));
                assert_eq!(cleaned.service(), service_id);
                assert_eq!(cleaned.task(), target);
                let mut wrong_runtime = TaskRuntime::<1, 1>::new(9_000, 1).unwrap();
                let failure =
                    dispatch_cleaned_native_filesystem_provider_fault(cleaned, &mut wrong_runtime)
                        .unwrap_err();
                assert_eq!(
                    failure.error(),
                    TaskTerminationDispatchError::RetirementRuntimeMismatch
                );
                let cleaned = failure.into_cleaned();
                assert_eq!(
                    cleaned.receipt().system_generation(),
                    association.filesystem_binding.system_generation
                );
                let dispatched =
                    dispatch_cleaned_native_filesystem_provider_fault(cleaned, &mut runtime)
                        .unwrap();
                assert_eq!(
                    dispatched.receipt().block_provider_generation(),
                    association.block_binding.provider_generation
                );
                assert_eq!(dispatched.service(), service_id);
                assert_eq!(dispatched.task(), target);
                let (restartable, dispatch) = dispatched.into_restart_parts();
                assert_eq!(restartable.service(), service_id);
                assert_eq!(restartable.task(), target);
                assert_eq!(
                    restartable.cause(),
                    NativeFilesystemProviderStopCause::Fault(TrapDisposition::TerminateUser {
                        vector: 14,
                        address: Some(0xfeed_0000),
                    })
                );
                assert_eq!(
                    restartable.receipt().association_generation(),
                    association.association_generation
                );
                (Some(dispatch), Some((successor, successor_context)))
            }
            SupervisedFailureKind::ProtocolViolation => {
                let violating = violate_current_supervised_native_filesystem_provider(
                    failure.into_active(),
                    &mut supervisor,
                    &mut runtime,
                    TaskProtocolViolation::BufferedReceiveMappingDrift,
                )
                .unwrap();
                assert_eq!(violating.service(), service_id);
                assert_eq!(violating.task(), target);
                assert!(violating.receipt().instance().active().is_some());
                let successor = runtime.current().unwrap();
                let successor_context = *runtime.context(successor).unwrap();
                let mut rejecting = RejectingRevoker;
                let failure = {
                    let mut teardown = NativeFilesystemProviderTeardownBackend::new(
                        &mut runtime,
                        &mut memory,
                        &mut rejecting,
                        &mut backing,
                    );
                    teardown_violating_native_filesystem_provider(violating, &mut teardown)
                        .unwrap_err()
                };
                assert!(matches!(
                    failure.error(),
                    NativeComponentServiceCopyReadTransferTeardownError::LocalMapping {
                        error: mrml_kernel::MemoryMappingOperationError::Backend("revoke"),
                        ..
                    }
                ));
                assert!(failure.violating.receipt().instance().teardown().is_some());
                let released = {
                    let mut teardown = NativeFilesystemProviderTeardownBackend::new(
                        &mut runtime,
                        &mut memory,
                        &mut local_mapping,
                        &mut backing,
                    );
                    teardown_violating_native_filesystem_provider(
                        failure.into_violating(),
                        &mut teardown,
                    )
                    .unwrap()
                };
                assert_eq!(released.service(), service_id);
                assert_eq!(released.task(), target);
                assert_eq!(
                    released.receipt().association_generation(),
                    association.association_generation
                );
                let mut rejecting_eraser = RejectingAddressSpaceEraser;
                let failure =
                    complete_resource_released_native_filesystem_provider_violation_cleanup(
                        released,
                        &mut supervisor,
                        &mut rejecting_eraser,
                    )
                    .unwrap_err();
                assert_eq!(
                    failure.error(),
                    &mrml_kernel::ServiceCleanupError::Eraser("erase")
                );
                let released = failure.into_released();
                assert_eq!(
                    released.receipt().filesystem_provider_generation(),
                    association.filesystem_binding.provider_generation
                );
                let mut eraser = AddressSpaceEraser::default();
                let cleaned =
                    complete_resource_released_native_filesystem_provider_violation_cleanup(
                        released,
                        &mut supervisor,
                        &mut eraser,
                    )
                    .unwrap();
                assert_eq!(eraser.erased, Some(target));
                assert_eq!(cleaned.service(), service_id);
                assert_eq!(cleaned.task(), target);
                assert_eq!(
                    cleaned.receipt().system_generation(),
                    association.filesystem_binding.system_generation
                );
                let mut wrong_runtime = TaskRuntime::<1, 1>::new(9_000, 1).unwrap();
                let failure = dispatch_cleaned_native_filesystem_provider_violation(
                    cleaned,
                    &mut wrong_runtime,
                )
                .unwrap_err();
                assert_eq!(
                    failure.error(),
                    TaskTerminationDispatchError::RetirementRuntimeMismatch
                );
                let cleaned = failure.into_cleaned();
                assert_eq!(
                    cleaned.receipt().association_generation(),
                    association.association_generation
                );
                let dispatched =
                    dispatch_cleaned_native_filesystem_provider_violation(cleaned, &mut runtime)
                        .unwrap();
                assert_eq!(
                    dispatched.receipt().block_provider_generation(),
                    association.block_binding.provider_generation
                );
                assert_eq!(dispatched.service(), service_id);
                assert_eq!(dispatched.task(), target);
                let (restartable, dispatch) = dispatched.into_restart_parts();
                assert_eq!(restartable.service(), service_id);
                assert_eq!(restartable.task(), target);
                assert_eq!(
                    restartable.cause(),
                    NativeFilesystemProviderStopCause::ProtocolViolation(
                        TaskProtocolViolation::BufferedReceiveMappingDrift
                    )
                );
                assert_eq!(
                    restartable.receipt().association_generation(),
                    association.association_generation
                );
                (Some(dispatch), Some((successor, successor_context)))
            }
        };
        if let Some(dispatch) = dispatch {
            assert_eq!(dispatch.user(), expected_successor);
        } else {
            assert_eq!(expected_successor, None);
        }
        let expected = Mapping::new(
            VirtAddr::new(0x300 * mrml_kernel::PAGE_SIZE).unwrap(),
            mrml_kernel::PhysAddr::new(0x80_0000).unwrap(),
            1,
            PagePermissions::USER_READ,
        )
        .unwrap();
        assert_eq!(
            local_mapping
                .into_builder()
                .unwrap()
                .verify_unmapped(expected),
            Ok(())
        );
        let expected_live_pages = if failure_kind == SupervisedFailureKind::RetirementRestart {
            assert!(backing.claimed.is_some());
            1
        } else {
            assert!(backing.claimed.is_none());
            0
        };
        assert_eq!(
            memory
                .usage(pool, pool_capability, runtime.capabilities(source).unwrap())
                .unwrap()
                .object_pages(),
            expected_live_pages
        );
    }

    #[test]
    fn native_retirement_teardown_retains_one_exact_copy_task_lifecycle() {
        native_launch_and_teardown_retain_one_exact_copy_task_lifecycle(
            SupervisedFailureKind::Retirement,
        );
    }

    #[test]
    fn native_retirement_constructs_and_activates_exact_replacement() {
        native_launch_and_teardown_retain_one_exact_copy_task_lifecycle(
            SupervisedFailureKind::RetirementRestart,
        );
    }

    #[test]
    fn native_fault_teardown_retains_one_exact_copy_task_lifecycle() {
        native_launch_and_teardown_retain_one_exact_copy_task_lifecycle(
            SupervisedFailureKind::Fault,
        );
    }

    #[test]
    fn native_violation_teardown_retains_one_exact_copy_task_lifecycle() {
        native_launch_and_teardown_retain_one_exact_copy_task_lifecycle(
            SupervisedFailureKind::ProtocolViolation,
        );
    }

    #[test]
    fn substituted_endpoint_and_backend_failure_never_become_success_receipts() {
        let association = association();
        let mut capabilities = CapabilitySpace::<3>::new();
        let substituted = capabilities
            .insert(ObjectId(22), Rights::SIGNAL.union(Rights::DELEGATE))
            .unwrap();
        let transfer = transfer_attachment(&mut capabilities);
        let mut backend = Backend {
            fail: false,
            fail_teardown: false,
            calls: 0,
            teardown_calls: 0,
            observed: [0; FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES],
        };
        assert_eq!(
            launch_filesystem_provider(
                &capabilities,
                substituted,
                transfer,
                association,
                &mut backend,
            ),
            Err(FilesystemProviderLaunchError::WrongEndpointAuthority)
        );
        assert_eq!(backend.calls, 0);

        let mut oversized = association;
        oversized.logical_block_bytes = 8192;
        let mut capabilities = CapabilitySpace::<3>::new();
        let endpoint = capabilities
            .insert(
                oversized.block_binding.endpoint_object,
                Rights::SIGNAL.union(Rights::DELEGATE),
            )
            .unwrap();
        let transfer = transfer_attachment(&mut capabilities);
        assert_eq!(
            launch_filesystem_provider(&capabilities, endpoint, transfer, oversized, &mut backend,),
            Err(FilesystemProviderLaunchError::TransferTooSmall)
        );
        assert_eq!(backend.calls, 0);

        let mut capabilities = CapabilitySpace::<3>::new();
        let endpoint = capabilities
            .insert(
                association.block_binding.endpoint_object,
                Rights::SIGNAL.union(Rights::DELEGATE),
            )
            .unwrap();
        let transfer = transfer_attachment(&mut capabilities);
        backend.fail = true;
        assert_eq!(
            launch_filesystem_provider(
                &capabilities,
                endpoint,
                transfer,
                association,
                &mut backend,
            ),
            Err(FilesystemProviderLaunchError::Backend(()))
        );
        assert_eq!(backend.calls, 1);
    }

    #[test]
    fn teardown_failure_returns_exact_progressed_receipt_for_retry() {
        let mut backend = Backend {
            fail: false,
            fail_teardown: true,
            calls: 0,
            teardown_calls: 0,
            observed: [0; FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES],
        };
        let association = association();
        let receipt = receipt(
            association.filesystem_binding.provider_object,
            association.handoff(),
            40,
        );
        let failure = teardown_filesystem_provider(receipt, &mut backend).unwrap_err();
        assert_eq!(backend.teardown_calls, 1);
        assert_eq!(*failure.receipt().instance(), 41);
        assert_eq!(failure.receipt().association_generation(), 12);
        assert_eq!(failure.error(), &());
        let (receipt, ()) = failure.into_parts();
        backend.fail_teardown = false;
        assert_eq!(teardown_filesystem_provider(receipt, &mut backend), Ok(()));
        assert_eq!(backend.teardown_calls, 2);
    }
}
