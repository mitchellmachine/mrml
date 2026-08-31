//! Device quiescence gate before AHCI service mapping withdrawal.

use crate::{
    ActiveAhciPort, AhciAbarMapping, AhciAbarRemovalBackend, AhciCleanupFailure,
    AhciCommandBackendTeardown, AhciCommandMemoryIo, AhciDataBufferIo, AhciDataDmaRegion,
    AhciEngineFailure, AhciPortDmaBackend, AhciRegisterIo, AhciServiceCpuMappingBackend,
    AhciServiceMappingRemovalError, AhciServiceMappingTeardown, BoundAhciServiceLaunch,
    InstalledAhciPortDma, reclaim_stopped_ahci_port_dma, remove_ahci_service_mappings,
    revoke_ahci_port_dma, stop_ahci_port_engine,
};
use mrml_kernel::arch::x86_64::PageTableStore;
use mrml_kernel::{
    Capability, CapabilitySpace, NativeDeviceServiceTask, ServiceAddressSpaceEraser,
    ServiceCleanupError, ServiceCleanupTicket, ServiceId, ServiceSupervisor,
    SupervisedNativeDeviceServiceDispatch, SupervisedNativeDeviceServiceFreeze,
    SupervisedNativeDeviceServiceRetirement, SupervisedNativeDeviceServiceRetirementError,
    SyscallRequest, TaskId, TaskRuntime, TaskTerminationDispatch, TaskTerminationDispatchError,
};

#[derive(Debug, Eq, PartialEq)]
pub enum PendingAhciServiceDeviceTeardown {
    DataSanitization {
        dma: InstalledAhciPortDma,
        mappings: AhciServiceMappingTeardown,
    },
    DmaWithdrawal {
        dma: InstalledAhciPortDma,
        mappings: AhciServiceMappingTeardown,
    },
}

impl PendingAhciServiceDeviceTeardown {
    pub fn mapping_withdrawal_pending(&self) -> bool {
        matches!(self, Self::DmaWithdrawal { .. })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct QuiescedAhciServiceMappings {
    mappings: AhciServiceMappingTeardown,
}

impl QuiescedAhciServiceMappings {
    pub fn complete(&self) -> bool {
        self.mappings.complete()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum AhciServiceDeviceQuiesceError {
    MappingMismatch {
        port: ActiveAhciPort,
        mappings: AhciServiceMappingTeardown,
    },
    Engine {
        failure: AhciEngineFailure,
        mappings: AhciServiceMappingTeardown,
    },
    Cleanup {
        failure: AhciCleanupFailure,
        mappings: AhciServiceMappingTeardown,
    },
    Pending(PendingAhciServiceDeviceTeardown),
}

pub struct AhciCommandBackendQuiesceError<R, M, D> {
    failure: AhciServiceDeviceQuiesceError,
    data_region: AhciDataDmaRegion,
    registers: R,
    command_memory: M,
    data_io: D,
}

impl<R, M, D> AhciCommandBackendQuiesceError<R, M, D> {
    pub const fn failure(&self) -> &AhciServiceDeviceQuiesceError {
        &self.failure
    }
}

pub struct QuiescedAhciCommandBackend<R, M, D> {
    mappings: QuiescedAhciServiceMappings,
    data_region: AhciDataDmaRegion,
    registers: R,
    command_memory: M,
    data_io: D,
}

impl<R, M, D> QuiescedAhciCommandBackend<R, M, D> {
    pub const fn mappings(&self) -> &QuiescedAhciServiceMappings {
        &self.mappings
    }

    pub const fn data_region(&self) -> AhciDataDmaRegion {
        self.data_region
    }

    pub fn into_parts(self) -> (QuiescedAhciServiceMappings, AhciDataDmaRegion, R, M, D) {
        (
            self.mappings,
            self.data_region,
            self.registers,
            self.command_memory,
            self.data_io,
        )
    }
}

pub fn quiesce_ahci_command_backend<
    R: AhciRegisterIo,
    M: AhciCommandMemoryIo,
    D: AhciDataBufferIo,
    B: AhciPortDmaBackend,
>(
    backend: AhciCommandBackendTeardown<R, M, D>,
    mappings: AhciServiceMappingTeardown,
    dma_backend: &mut B,
) -> Result<QuiescedAhciCommandBackend<R, M, D>, AhciCommandBackendQuiesceError<R, M, D>> {
    let (mapping, port, data_region, mut registers, mut command_memory, mut data_io) =
        backend.into_parts();
    match quiesce_ahci_service_device(
        mapping,
        port,
        mappings,
        data_region,
        &mut registers,
        &mut command_memory,
        &mut data_io,
        dma_backend,
    ) {
        Ok(mappings) => Ok(QuiescedAhciCommandBackend {
            mappings,
            data_region,
            registers,
            command_memory,
            data_io,
        }),
        Err(failure) => Err(AhciCommandBackendQuiesceError {
            failure,
            data_region,
            registers,
            command_memory,
            data_io,
        }),
    }
}

pub fn resume_ahci_command_backend_teardown<D: AhciDataBufferIo, B: AhciPortDmaBackend, R, M>(
    error: AhciCommandBackendQuiesceError<R, M, D>,
    dma_backend: &mut B,
) -> Result<QuiescedAhciCommandBackend<R, M, D>, AhciCommandBackendQuiesceError<R, M, D>> {
    let AhciCommandBackendQuiesceError {
        failure,
        data_region,
        registers,
        command_memory,
        mut data_io,
    } = error;
    let AhciServiceDeviceQuiesceError::Pending(pending) = failure else {
        return Err(AhciCommandBackendQuiesceError {
            failure,
            data_region,
            registers,
            command_memory,
            data_io,
        });
    };
    match resume_ahci_service_device_teardown(pending, data_region, &mut data_io, dma_backend) {
        Ok(mappings) => Ok(QuiescedAhciCommandBackend {
            mappings,
            data_region,
            registers,
            command_memory,
            data_io,
        }),
        Err(pending) => Err(AhciCommandBackendQuiesceError {
            failure: AhciServiceDeviceQuiesceError::Pending(pending),
            data_region,
            registers,
            command_memory,
            data_io,
        }),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciServiceTaskBindingError {
    MappingMismatch,
    PortMismatch,
    DataRegionMismatch,
}

/// Frozen service lifecycle after device/data/DMA quiescence and destruction
/// of every borrowed register, command-memory, and data-buffer view.
pub struct QuiescedAhciServiceTask {
    frozen: SupervisedNativeDeviceServiceFreeze<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
    launch: BoundAhciServiceLaunch,
    mappings: QuiescedAhciServiceMappings,
}

impl QuiescedAhciServiceTask {
    pub const fn task(&self) -> mrml_kernel::TaskId {
        self.frozen.task()
    }

    pub const fn launch(&self) -> BoundAhciServiceLaunch {
        self.launch
    }

    pub const fn service(&self) -> ServiceId {
        self.frozen.service()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciServiceTeardownLeaseBindingError {
    NativeTaskMismatch,
    LaunchMismatch,
}

/// One-shot manager authority retained for exactly one activated AHCI service.
/// Identity accessors support exact matching but do not themselves authorize
/// device reclamation.
///
/// # Safety
///
/// An implementation must be minted from the controller manager's exclusive
/// assignment authority for exactly `native_task()` and `launch()`, including
/// the native task's opaque runtime identity. Both identity accessors must be
/// stable and side-effect-free for the lease's lifetime. The lease must remain
/// non-duplicated while the service runs. Dropping it before successful
/// acquisition must be inert and fail-stopped: no hardware access, unmapping,
/// DMA revocation, assignment release/reissue, task resume, or dispatch.
/// `reacquire` consumes that authority and may return success exactly once,
/// atomically transferring the sole register, active-port, command-memory, and
/// data-buffer teardown owners with no aliases.
/// It runs only after the exact task is frozen and must not resume or dispatch
/// it. On failure it must perform no acquisition mutation and return the same
/// lease. `Error` must be diagnostic-only: it may retain no partial owner or
/// alias and its destructor must have no lifecycle, mapping, DMA, or hardware
/// effect. Returned view owners remain valid until successful quiescence drops
/// them; their destructors may only release views and must not touch hardware,
/// unmap, revoke DMA, or retain aliases.
pub unsafe trait AhciServiceTeardownLease: Sized {
    type Registers;
    type CommandMemory;
    type DataIo;
    type Error;

    fn native_task(&self) -> NativeDeviceServiceTask<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>;

    fn launch(&self) -> BoundAhciServiceLaunch;

    /// Transfers teardown mechanism after the exact bound task is frozen.
    ///
    /// # Safety
    ///
    /// The caller must hold the matching consuming
    /// [`FrozenAhciServiceExit`] and must not permit the task to resume or any
    /// other issuer to access the controller during this call.
    unsafe fn reacquire(
        self,
    ) -> Result<
        AhciCommandBackendTeardown<Self::Registers, Self::CommandMemory, Self::DataIo>,
        (Self::Error, Self),
    >;
}

/// Manager-owned stop handoff created before any AHCI teardown state is
/// reacquired. The exact service task is frozen and cannot run, while the
/// one-shot controller-manager lease and all mapping owners remain retained.
pub struct FrozenAhciServiceExit<L> {
    frozen: SupervisedNativeDeviceServiceFreeze<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
    launch: BoundAhciServiceLaunch,
    mappings: AhciServiceMappingTeardown,
    lease: L,
}

impl<L> FrozenAhciServiceExit<L> {
    pub const fn service(&self) -> ServiceId {
        self.frozen.service()
    }

    pub const fn task(&self) -> TaskId {
        self.frozen.task()
    }

    pub const fn launch(&self) -> BoundAhciServiceLaunch {
        self.launch
    }
}

pub enum AhciServiceExitFreezeError<L> {
    LeaseBinding {
        error: AhciServiceTeardownLeaseBindingError,
        active: crate::ActiveAhciNativeServiceTask,
        lease: L,
    },
    Lifecycle {
        error: SupervisedNativeDeviceServiceRetirementError,
        active: crate::ActiveAhciNativeServiceTask,
        lease: L,
    },
}

/// Exact manager lease paired with the execution-frozen concrete page-table
/// and mapping-set owner. Neither component can be substituted independently.
pub struct FrozenKernelAhciServiceExit<
    'resources,
    S: PageTableStore,
    L,
    const P: usize,
    const O: usize,
    const M: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
> {
    frozen: crate::FrozenKernelAhciMappingSetOwner<
        'resources,
        S,
        P,
        O,
        M,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
    lease: L,
}

impl<
    'resources,
    S: PageTableStore,
    L,
    const P: usize,
    const O: usize,
    const M: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
> FrozenKernelAhciServiceExit<'resources, S, L, P, O, M, TASKS, TASK_CAPABILITIES, AUTHORITIES>
{
    pub const fn service(&self) -> ServiceId {
        self.frozen.service()
    }
    pub const fn task(&self) -> TaskId {
        self.frozen.task()
    }
    pub const fn root(&self) -> mrml_kernel::PhysAddr {
        self.frozen.root()
    }
    pub const fn lease(&self) -> &L {
        &self.lease
    }
}

pub enum KernelAhciServiceExitFreezeError<
    'resources,
    S: PageTableStore,
    L,
    const P: usize,
    const O: usize,
    const M: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
> {
    LeaseBinding {
        error: AhciServiceTeardownLeaseBindingError,
        active: crate::ActiveKernelAhciMappingSetOwner<
            'resources,
            S,
            P,
            O,
            M,
            TASKS,
            TASK_CAPABILITIES,
            AUTHORITIES,
        >,
        lease: L,
    },
    Lifecycle {
        failure: crate::KernelAhciMappingSetFreezeFailure<
            'resources,
            S,
            P,
            O,
            M,
            TASKS,
            TASK_CAPABILITIES,
            AUTHORITIES,
        >,
        lease: L,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelAhciServiceExitRequest(());

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelAhciServiceExitRequestError {
    request: SyscallRequest,
}

impl KernelAhciServiceExitRequestError {
    pub const fn request(self) -> SyscallRequest {
        self.request
    }
}

impl KernelAhciServiceExitRequest {
    /// Admits only the canonical decoded operation-3 request. This token is
    /// descriptive and carries no task, service, mapping, or device authority.
    pub const fn admit(request: SyscallRequest) -> Result<Self, KernelAhciServiceExitRequestError> {
        if matches!(request, SyscallRequest::Exit) {
            Ok(Self(()))
        } else {
            Err(KernelAhciServiceExitRequestError { request })
        }
    }
}

impl<
    'resources,
    S: PageTableStore,
    L,
    const P: usize,
    const O: usize,
    const M: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
>
    KernelAhciServiceExitFreezeError<
        'resources,
        S,
        L,
        P,
        O,
        M,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >
{
    pub fn into_parts(
        self,
    ) -> (
        crate::ActiveKernelAhciMappingSetOwner<
            'resources,
            S,
            P,
            O,
            M,
            TASKS,
            TASK_CAPABILITIES,
            AUTHORITIES,
        >,
        L,
    ) {
        match self {
            Self::LeaseBinding { active, lease, .. } => (active, lease),
            Self::Lifecycle { failure, lease } => (failure.into_active(), lease),
        }
    }
}

/// Binds the controller manager's one-use teardown authority before freezing
/// the concrete active task. Every failure returns both unchanged owners.
pub fn begin_active_kernel_ahci_service_exit<
    'resources,
    S: PageTableStore,
    L: AhciServiceTeardownLease,
    const P: usize,
    const O: usize,
    const M: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
    const SERVICES: usize,
>(
    active: crate::ActiveKernelAhciMappingSetOwner<
        'resources,
        S,
        P,
        O,
        M,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
    lease: L,
    supervisor: &ServiceSupervisor<SERVICES>,
    runtime: &mut TaskRuntime<TASKS, TASK_CAPABILITIES>,
) -> Result<
    FrozenKernelAhciServiceExit<'resources, S, L, P, O, M, TASKS, TASK_CAPABILITIES, AUTHORITIES>,
    KernelAhciServiceExitFreezeError<
        'resources,
        S,
        L,
        P,
        O,
        M,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
> {
    let binding_error = if lease.native_task() != active.native_task() {
        Some(AhciServiceTeardownLeaseBindingError::NativeTaskMismatch)
    } else if lease.launch() != active.launch() {
        Some(AhciServiceTeardownLeaseBindingError::LaunchMismatch)
    } else {
        None
    };
    if let Some(error) = binding_error {
        return Err(KernelAhciServiceExitFreezeError::LeaseBinding {
            error,
            active,
            lease,
        });
    }
    match active.freeze_current(supervisor, runtime) {
        Ok(frozen) => Ok(FrozenKernelAhciServiceExit { frozen, lease }),
        Err(failure) => Err(KernelAhciServiceExitFreezeError::Lifecycle { failure, lease }),
    }
}

/// Routes one already decoded operation-3 request into the exact concrete
/// freeze-first manager handoff. The request token identifies the requested
/// transition but grants nothing; the consuming active owner and matched lease
/// remain the only teardown authority.
pub fn route_active_kernel_ahci_service_exit<
    'resources,
    S: PageTableStore,
    L: AhciServiceTeardownLease,
    const P: usize,
    const O: usize,
    const M: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
    const SERVICES: usize,
>(
    _request: KernelAhciServiceExitRequest,
    active: crate::ActiveKernelAhciMappingSetOwner<
        'resources,
        S,
        P,
        O,
        M,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
    lease: L,
    supervisor: &ServiceSupervisor<SERVICES>,
    runtime: &mut TaskRuntime<TASKS, TASK_CAPABILITIES>,
) -> Result<
    FrozenKernelAhciServiceExit<'resources, S, L, P, O, M, TASKS, TASK_CAPABILITIES, AUTHORITIES>,
    KernelAhciServiceExitFreezeError<
        'resources,
        S,
        L,
        P,
        O,
        M,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
> {
    begin_active_kernel_ahci_service_exit(active, lease, supervisor, runtime)
}

impl<L> AhciServiceExitFreezeError<L> {
    pub const fn binding_error(&self) -> Option<AhciServiceTeardownLeaseBindingError> {
        match self {
            Self::LeaseBinding { error, .. } => Some(*error),
            Self::Lifecycle { .. } => None,
        }
    }

    pub const fn lifecycle_error(&self) -> Option<SupervisedNativeDeviceServiceRetirementError> {
        match self {
            Self::LeaseBinding { .. } => None,
            Self::Lifecycle { error, .. } => Some(*error),
        }
    }

    pub fn into_parts(self) -> (crate::ActiveAhciNativeServiceTask, L) {
        match self {
            Self::LeaseBinding { active, lease, .. } | Self::Lifecycle { active, lease, .. } => {
                (active, lease)
            }
        }
    }
}

/// Consumes the exact active AHCI owner when its current userspace task asks to
/// stop. This transition performs no MMIO, command-memory, data-buffer, or DMA
/// operation. Holding the typed active owner is the manager's authority; an
/// untrusted operation number, status value, or service identifier is not.
pub fn begin_active_ahci_service_exit<
    L: AhciServiceTeardownLease,
    const TASKS: usize,
    const CAPABILITIES: usize,
    const SERVICES: usize,
>(
    active: crate::ActiveAhciNativeServiceTask,
    lease: L,
    supervisor: &ServiceSupervisor<SERVICES>,
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
) -> Result<FrozenAhciServiceExit<L>, AhciServiceExitFreezeError<L>> {
    let native = active.mapped().prepared().task();
    let launch = active.mapped().prepared().launch();
    let binding_error = if lease.native_task() != native {
        Some(AhciServiceTeardownLeaseBindingError::NativeTaskMismatch)
    } else if lease.launch() != launch {
        Some(AhciServiceTeardownLeaseBindingError::LaunchMismatch)
    } else {
        None
    };
    if let Some(error) = binding_error {
        return Err(AhciServiceExitFreezeError::LeaseBinding {
            error,
            active,
            lease,
        });
    }
    let frozen =
        match supervisor.freeze_current_native_device_service(active.binding(), native, runtime) {
            Ok(frozen) => frozen,
            Err(error) => {
                return Err(AhciServiceExitFreezeError::Lifecycle {
                    error,
                    active,
                    lease,
                });
            }
        };
    let (binding, mapped) = active.into_parts();
    let (prepared, mappings) = mapped.into_parts();
    debug_assert_eq!(binding.service(), frozen.service());
    Ok(FrozenAhciServiceExit {
        frozen,
        launch: prepared.launch(),
        mappings,
        lease,
    })
}

pub struct ReacquiredAhciServiceTeardown<R, M, D> {
    frozen: SupervisedNativeDeviceServiceFreeze<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
    launch: BoundAhciServiceLaunch,
    mappings: AhciServiceMappingTeardown,
    backend: AhciCommandBackendTeardown<R, M, D>,
}

impl<R, M, D> ReacquiredAhciServiceTeardown<R, M, D> {
    pub const fn service(&self) -> ServiceId {
        self.frozen.service()
    }

    pub const fn task(&self) -> TaskId {
        self.frozen.task()
    }
}

pub struct QuarantinedAhciServiceTeardown<R, M, D> {
    frozen: SupervisedNativeDeviceServiceFreeze<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
    launch: BoundAhciServiceLaunch,
    mappings: AhciServiceMappingTeardown,
    backend: AhciCommandBackendTeardown<R, M, D>,
}

impl<R, M, D> QuarantinedAhciServiceTeardown<R, M, D> {
    pub const fn service(&self) -> ServiceId {
        self.frozen.service()
    }

    pub const fn task(&self) -> TaskId {
        self.frozen.task()
    }

    pub const fn launch(&self) -> BoundAhciServiceLaunch {
        self.launch
    }

    pub fn retained_mappings_complete(&self) -> bool {
        self.mappings.complete()
    }

    pub const fn acquired_mapping(&self) -> AhciAbarMapping {
        self.backend.mapping()
    }
}

pub enum AhciServiceTeardownReacquisitionError<L, E, R, M, D> {
    Lease {
        error: E,
        frozen: FrozenAhciServiceExit<L>,
    },
    Binding {
        error: AhciServiceTaskBindingError,
        quarantine: QuarantinedAhciServiceTeardown<R, M, D>,
    },
}

/// Concrete-root teardown owner after the controller manager transfers its
/// one-use register, command-memory, and data-buffer views. The frozen page
/// table and every memory-resource mapping owner remain indivisible here.
pub struct ReacquiredKernelAhciServiceTeardown<
    'resources,
    S: PageTableStore,
    R,
    M,
    D,
    const P: usize,
    const O: usize,
    const MM: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
> {
    frozen: crate::FrozenKernelAhciMappingSetOwner<
        'resources,
        S,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
    backend: AhciCommandBackendTeardown<R, M, D>,
}

impl<
    'resources,
    S: PageTableStore,
    R,
    M,
    D,
    const P: usize,
    const O: usize,
    const MM: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
>
    ReacquiredKernelAhciServiceTeardown<
        'resources,
        S,
        R,
        M,
        D,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >
{
    pub const fn service(&self) -> ServiceId {
        self.frozen.service()
    }

    pub const fn task(&self) -> TaskId {
        self.frozen.task()
    }

    pub const fn root(&self) -> mrml_kernel::PhysAddr {
        self.frozen.root()
    }
}

pub struct QuarantinedKernelAhciServiceTeardown<
    'resources,
    S: PageTableStore,
    R,
    M,
    D,
    const P: usize,
    const O: usize,
    const MM: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
> {
    frozen: crate::FrozenKernelAhciMappingSetOwner<
        'resources,
        S,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
    backend: AhciCommandBackendTeardown<R, M, D>,
}

impl<
    'resources,
    S: PageTableStore,
    R,
    M,
    D,
    const P: usize,
    const O: usize,
    const MM: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
>
    QuarantinedKernelAhciServiceTeardown<
        'resources,
        S,
        R,
        M,
        D,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >
{
    pub const fn service(&self) -> ServiceId {
        self.frozen.service()
    }

    pub const fn task(&self) -> TaskId {
        self.frozen.task()
    }

    pub const fn root(&self) -> mrml_kernel::PhysAddr {
        self.frozen.root()
    }

    pub const fn acquired_mapping(&self) -> AhciAbarMapping {
        self.backend.mapping()
    }
}

pub enum KernelAhciServiceTeardownReacquisitionError<
    'resources,
    S: PageTableStore,
    L: AhciServiceTeardownLease,
    const P: usize,
    const O: usize,
    const MM: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
> {
    Lease {
        error: L::Error,
        frozen: FrozenKernelAhciServiceExit<
            'resources,
            S,
            L,
            P,
            O,
            MM,
            TASKS,
            TASK_CAPABILITIES,
            AUTHORITIES,
        >,
    },
    Binding {
        error: AhciServiceTaskBindingError,
        quarantine: QuarantinedKernelAhciServiceTeardown<
            'resources,
            S,
            L::Registers,
            L::CommandMemory,
            L::DataIo,
            P,
            O,
            MM,
            TASKS,
            TASK_CAPABILITIES,
            AUTHORITIES,
        >,
    },
}

impl<
    'resources,
    S: PageTableStore,
    L: AhciServiceTeardownLease,
    const P: usize,
    const O: usize,
    const MM: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
>
    KernelAhciServiceTeardownReacquisitionError<
        'resources,
        S,
        L,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >
{
    pub const fn lease_error(&self) -> Option<&L::Error> {
        match self {
            Self::Lease { error, .. } => Some(error),
            Self::Binding { .. } => None,
        }
    }

    pub const fn binding_error(&self) -> Option<AhciServiceTaskBindingError> {
        match self {
            Self::Lease { .. } => None,
            Self::Binding { error, .. } => Some(*error),
        }
    }

    pub fn into_retry(
        self,
    ) -> Result<
        (
            L::Error,
            FrozenKernelAhciServiceExit<
                'resources,
                S,
                L,
                P,
                O,
                MM,
                TASKS,
                TASK_CAPABILITIES,
                AUTHORITIES,
            >,
        ),
        Self,
    > {
        match self {
            Self::Lease { error, frozen } => Ok((error, frozen)),
            other => Err(other),
        }
    }

    pub fn into_quarantine(
        self,
    ) -> Result<
        QuarantinedKernelAhciServiceTeardown<
            'resources,
            S,
            L::Registers,
            L::CommandMemory,
            L::DataIo,
            P,
            O,
            MM,
            TASKS,
            TASK_CAPABILITIES,
            AUTHORITIES,
        >,
        Self,
    > {
        match self {
            Self::Binding { quarantine, .. } => Ok(quarantine),
            other => Err(other),
        }
    }
}

/// Transfers the trusted teardown views only after the concrete kernel mapping
/// set is execution-frozen, then independently exact-matches every returned
/// device identity before any MMIO or DMA transition.
pub fn reacquire_frozen_kernel_ahci_service_teardown<
    'resources,
    S: PageTableStore,
    L: AhciServiceTeardownLease,
    const P: usize,
    const O: usize,
    const MM: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
>(
    exit: FrozenKernelAhciServiceExit<
        'resources,
        S,
        L,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
) -> Result<
    ReacquiredKernelAhciServiceTeardown<
        'resources,
        S,
        L::Registers,
        L::CommandMemory,
        L::DataIo,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
    KernelAhciServiceTeardownReacquisitionError<
        'resources,
        S,
        L,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
> {
    let FrozenKernelAhciServiceExit { frozen, lease } = exit;
    // SAFETY: begin_active_kernel_ahci_service_exit matched this consuming
    // lease to the exact opaque native-task identity and launch before it
    // created the retained freeze. No safe API can resume that task here.
    let backend = match unsafe { lease.reacquire() } {
        Ok(backend) => backend,
        Err((error, lease)) => {
            return Err(KernelAhciServiceTeardownReacquisitionError::Lease {
                error,
                frozen: FrozenKernelAhciServiceExit { frozen, lease },
            });
        }
    };
    let spec = frozen.launch().spec();
    let binding = if frozen.abar_mapping() != Some(backend.mapping())
        || backend.mapping() != spec.mapping()
    {
        Some(AhciServiceTaskBindingError::MappingMismatch)
    } else if backend.port() != &ActiveAhciPort::from_layout(spec.layout()) {
        Some(AhciServiceTaskBindingError::PortMismatch)
    } else if backend.data_region() != spec.data() {
        Some(AhciServiceTaskBindingError::DataRegionMismatch)
    } else {
        None
    };
    if let Some(error) = binding {
        return Err(KernelAhciServiceTeardownReacquisitionError::Binding {
            error,
            quarantine: QuarantinedKernelAhciServiceTeardown { frozen, backend },
        });
    }
    Ok(ReacquiredKernelAhciServiceTeardown { frozen, backend })
}

#[derive(Debug, Eq, PartialEq)]
pub enum KernelAhciServiceDeviceQuiesceFailure {
    MappingMismatch { port: ActiveAhciPort },
    Engine(AhciEngineFailure),
    Cleanup(AhciCleanupFailure),
    DataSanitization(InstalledAhciPortDma),
    DmaWithdrawal(InstalledAhciPortDma),
}

pub struct FrozenKernelAhciServiceQuiesceError<
    'resources,
    S: PageTableStore,
    R,
    M,
    D,
    const P: usize,
    const O: usize,
    const MM: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
> {
    frozen: crate::FrozenKernelAhciMappingSetOwner<
        'resources,
        S,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
    failure: KernelAhciServiceDeviceQuiesceFailure,
    data_region: AhciDataDmaRegion,
    registers: R,
    command_memory: M,
    data_io: D,
}

impl<
    'resources,
    S: PageTableStore,
    R,
    M,
    D,
    const P: usize,
    const O: usize,
    const MM: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
>
    FrozenKernelAhciServiceQuiesceError<
        'resources,
        S,
        R,
        M,
        D,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >
{
    pub const fn failure(&self) -> &KernelAhciServiceDeviceQuiesceFailure {
        &self.failure
    }

    pub const fn root(&self) -> mrml_kernel::PhysAddr {
        self.frozen.root()
    }
}

/// Concrete kernel owner after device/data/DMA quiescence and destruction of
/// every borrowed service-address-space view. Page-table and memory-resource
/// ownership remains retained for the following retirement/withdrawal gate.
pub struct QuiescedKernelAhciServiceTask<
    'resources,
    S: PageTableStore,
    const P: usize,
    const O: usize,
    const MM: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
> {
    frozen: crate::FrozenKernelAhciMappingSetOwner<
        'resources,
        S,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
}

impl<
    'resources,
    S: PageTableStore,
    const P: usize,
    const O: usize,
    const MM: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
> QuiescedKernelAhciServiceTask<'resources, S, P, O, MM, TASKS, TASK_CAPABILITIES, AUTHORITIES>
{
    pub const fn service(&self) -> ServiceId {
        self.frozen.service()
    }

    pub const fn task(&self) -> TaskId {
        self.frozen.task()
    }

    pub const fn root(&self) -> mrml_kernel::PhysAddr {
        self.frozen.root()
    }
}

pub fn quiesce_reacquired_kernel_ahci_service<
    'resources,
    S: PageTableStore,
    R: AhciRegisterIo,
    M: AhciCommandMemoryIo,
    D: AhciDataBufferIo,
    B: AhciPortDmaBackend,
    const P: usize,
    const O: usize,
    const MM: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
>(
    owner: ReacquiredKernelAhciServiceTeardown<
        'resources,
        S,
        R,
        M,
        D,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
    dma_backend: &mut B,
) -> Result<
    QuiescedKernelAhciServiceTask<'resources, S, P, O, MM, TASKS, TASK_CAPABILITIES, AUTHORITIES>,
    FrozenKernelAhciServiceQuiesceError<
        'resources,
        S,
        R,
        M,
        D,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
> {
    let ReacquiredKernelAhciServiceTeardown { frozen, backend } = owner;
    let (mapping, port, data_region, mut registers, mut command_memory, mut data_io) =
        backend.into_parts();
    if frozen.abar_mapping() != Some(mapping) {
        return Err(FrozenKernelAhciServiceQuiesceError {
            frozen,
            failure: KernelAhciServiceDeviceQuiesceFailure::MappingMismatch { port },
            data_region,
            registers,
            command_memory,
            data_io,
        });
    }
    let stopped = match stop_ahci_port_engine(mapping, port, &mut registers) {
        Ok(stopped) => stopped,
        Err(failure) => {
            return Err(FrozenKernelAhciServiceQuiesceError {
                frozen,
                failure: KernelAhciServiceDeviceQuiesceFailure::Engine(failure),
                data_region,
                registers,
                command_memory,
                data_io,
            });
        }
    };
    let dma = match reclaim_stopped_ahci_port_dma(
        mapping,
        stopped,
        &mut registers,
        &mut command_memory,
    ) {
        Ok(dma) => dma,
        Err(failure) => {
            return Err(FrozenKernelAhciServiceQuiesceError {
                frozen,
                failure: KernelAhciServiceDeviceQuiesceFailure::Cleanup(failure),
                data_region,
                registers,
                command_memory,
                data_io,
            });
        }
    };
    if data_io.sanitize(data_region).is_err() {
        return Err(FrozenKernelAhciServiceQuiesceError {
            frozen,
            failure: KernelAhciServiceDeviceQuiesceFailure::DataSanitization(dma),
            data_region,
            registers,
            command_memory,
            data_io,
        });
    }
    if let Err(error) = revoke_ahci_port_dma(dma, dma_backend) {
        return Err(FrozenKernelAhciServiceQuiesceError {
            frozen,
            failure: KernelAhciServiceDeviceQuiesceFailure::DmaWithdrawal(error.into_owner()),
            data_region,
            registers,
            command_memory,
            data_io,
        });
    }
    drop(data_io);
    drop(command_memory);
    drop(registers);
    Ok(QuiescedKernelAhciServiceTask { frozen })
}

pub fn resume_frozen_kernel_ahci_service_quiescence<
    'resources,
    S: PageTableStore,
    R,
    M,
    D: AhciDataBufferIo,
    B: AhciPortDmaBackend,
    const P: usize,
    const O: usize,
    const MM: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
>(
    error: FrozenKernelAhciServiceQuiesceError<
        'resources,
        S,
        R,
        M,
        D,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
    dma_backend: &mut B,
) -> Result<
    QuiescedKernelAhciServiceTask<'resources, S, P, O, MM, TASKS, TASK_CAPABILITIES, AUTHORITIES>,
    FrozenKernelAhciServiceQuiesceError<
        'resources,
        S,
        R,
        M,
        D,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
> {
    let FrozenKernelAhciServiceQuiesceError {
        frozen,
        failure,
        data_region,
        registers,
        command_memory,
        mut data_io,
    } = error;
    let dma = match failure {
        KernelAhciServiceDeviceQuiesceFailure::DataSanitization(dma) => {
            if data_io.sanitize(data_region).is_err() {
                return Err(FrozenKernelAhciServiceQuiesceError {
                    frozen,
                    failure: KernelAhciServiceDeviceQuiesceFailure::DataSanitization(dma),
                    data_region,
                    registers,
                    command_memory,
                    data_io,
                });
            }
            dma
        }
        KernelAhciServiceDeviceQuiesceFailure::DmaWithdrawal(dma) => dma,
        failure => {
            return Err(FrozenKernelAhciServiceQuiesceError {
                frozen,
                failure,
                data_region,
                registers,
                command_memory,
                data_io,
            });
        }
    };
    if let Err(error) = revoke_ahci_port_dma(dma, dma_backend) {
        return Err(FrozenKernelAhciServiceQuiesceError {
            frozen,
            failure: KernelAhciServiceDeviceQuiesceFailure::DmaWithdrawal(error.into_owner()),
            data_region,
            registers,
            command_memory,
            data_io,
        });
    }
    drop(data_io);
    drop(command_memory);
    drop(registers);
    Ok(QuiescedKernelAhciServiceTask { frozen })
}

pub struct RetiredKernelAhciServiceTask<
    'resources,
    S: PageTableStore,
    const P: usize,
    const O: usize,
    const MM: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
> {
    owner: crate::KernelAhciPreactivationMappingSetOwner<
        'resources,
        S,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
    retirement: SupervisedNativeDeviceServiceRetirement<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
}

impl<
    'resources,
    S: PageTableStore,
    const P: usize,
    const O: usize,
    const MM: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
> RetiredKernelAhciServiceTask<'resources, S, P, O, MM, TASKS, TASK_CAPABILITIES, AUTHORITIES>
{
    pub const fn service(&self) -> ServiceId {
        self.retirement.service()
    }

    pub const fn task(&self) -> TaskId {
        self.owner.task()
    }

    pub const fn root(&self) -> mrml_kernel::PhysAddr {
        self.owner.root()
    }
}

pub struct KernelAhciServiceTaskRetirementError<
    'resources,
    S: PageTableStore,
    const P: usize,
    const O: usize,
    const MM: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
> {
    error: SupervisedNativeDeviceServiceRetirementError,
    owner: QuiescedKernelAhciServiceTask<
        'resources,
        S,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
}

impl<
    'resources,
    S: PageTableStore,
    const P: usize,
    const O: usize,
    const MM: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
>
    KernelAhciServiceTaskRetirementError<
        'resources,
        S,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >
{
    pub const fn error(&self) -> SupervisedNativeDeviceServiceRetirementError {
        self.error
    }

    pub fn into_owner(
        self,
    ) -> QuiescedKernelAhciServiceTask<'resources, S, P, O, MM, TASKS, TASK_CAPABILITIES, AUTHORITIES>
    {
        self.owner
    }
}

/// Retires the exact frozen concrete service only after all device views are
/// gone and DMA has been withdrawn. The page-table/resource owner remains
/// paired with the supervisor retirement and successor dispatch stays blocked.
///
/// # Safety
///
/// The backends which created `owner` must truthfully have enforced device
/// quiescence, data sanitization, and DMA withdrawal.
pub unsafe fn retire_quiesced_kernel_ahci_service_task<
    'resources,
    S: PageTableStore,
    const P: usize,
    const O: usize,
    const MM: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
    const SERVICES: usize,
>(
    owner: QuiescedKernelAhciServiceTask<
        'resources,
        S,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
    supervisor: &mut ServiceSupervisor<SERVICES>,
    runtime: &mut TaskRuntime<TASKS, TASK_CAPABILITIES>,
) -> Result<
    RetiredKernelAhciServiceTask<'resources, S, P, O, MM, TASKS, TASK_CAPABILITIES, AUTHORITIES>,
    KernelAhciServiceTaskRetirementError<
        'resources,
        S,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
> {
    let QuiescedKernelAhciServiceTask { frozen } = owner;
    let (mapping_owner, lifecycle) = frozen.into_parts();
    // SAFETY: the caller supplies the device/DMA truthfulness proof while the
    // consuming lifecycle token proves the exact task remains frozen.
    match unsafe { supervisor.retire_frozen_native_device_service(lifecycle, runtime) } {
        Ok(retirement) => Ok(RetiredKernelAhciServiceTask {
            owner: mapping_owner,
            retirement,
        }),
        Err(error) => {
            let retirement_error = error.error();
            Err(KernelAhciServiceTaskRetirementError {
                error: retirement_error,
                owner: QuiescedKernelAhciServiceTask {
                    frozen: crate::FrozenKernelAhciMappingSetOwner::from_parts(
                        mapping_owner,
                        error.into_frozen(),
                    ),
                },
            })
        }
    }
}

pub struct RetiredKernelAhciServiceMappingsRemoved<
    'resources,
    S: PageTableStore,
    const P: usize,
    const O: usize,
    const MM: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
> {
    owner: crate::KernelAhciPreactivationMappingSetOwner<
        'resources,
        S,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
    retirement: SupervisedNativeDeviceServiceRetirement<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
}

impl<
    'resources,
    S: PageTableStore,
    const P: usize,
    const O: usize,
    const MM: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
>
    RetiredKernelAhciServiceMappingsRemoved<
        'resources,
        S,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >
{
    pub const fn service(&self) -> ServiceId {
        self.retirement.service()
    }

    pub const fn task(&self) -> TaskId {
        self.owner.task()
    }

    pub const fn root(&self) -> mrml_kernel::PhysAddr {
        self.owner.root()
    }

    pub fn mappings_complete(&self) -> bool {
        self.owner.abar_mapping().is_none() && self.owner.cpu_mappings().complete()
    }
}

pub struct KernelAhciRetiredMappingRemovalError<
    'resources,
    S: PageTableStore,
    const P: usize,
    const O: usize,
    const MM: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
> {
    failure: crate::KernelAhciPreactivationMappingSetRollbackFailure<
        'resources,
        S,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
    retirement: SupervisedNativeDeviceServiceRetirement<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
}

impl<
    'resources,
    S: PageTableStore,
    const P: usize,
    const O: usize,
    const MM: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
>
    KernelAhciRetiredMappingRemovalError<
        'resources,
        S,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >
{
    pub const fn error(&self) -> crate::KernelAhciPreactivationMappingSetError {
        self.failure.error()
    }

    pub fn into_owner(
        self,
    ) -> RetiredKernelAhciServiceTask<'resources, S, P, O, MM, TASKS, TASK_CAPABILITIES, AUTHORITIES>
    {
        RetiredKernelAhciServiceTask {
            owner: self.failure.into_owner(),
            retirement: self.retirement,
        }
    }
}

/// Removes the four CPU/DMA leaves and then the ABAR from the exact retired
/// hierarchy. Success retains the empty concrete root through later cleanup.
///
/// # Safety
///
/// The concrete backend must truthfully remove each mapping and complete every
/// required SMP translation invalidation. Successor dispatch must remain
/// withheld through subsequent address-space cleanup.
pub unsafe fn remove_retired_kernel_ahci_service_mappings<
    'resources,
    S: PageTableStore,
    const P: usize,
    const O: usize,
    const MM: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
>(
    retired: RetiredKernelAhciServiceTask<
        'resources,
        S,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
) -> Result<
    RetiredKernelAhciServiceMappingsRemoved<
        'resources,
        S,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
    KernelAhciRetiredMappingRemovalError<
        'resources,
        S,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
> {
    let RetiredKernelAhciServiceTask { owner, retirement } = retired;
    // SAFETY: this function preserves the caller's quiescence, invalidation,
    // and dispatch-withholding proof in the paired retirement owner.
    match unsafe { owner.withdraw_retired_mappings() } {
        Ok(owner) => Ok(RetiredKernelAhciServiceMappingsRemoved { owner, retirement }),
        Err(failure) => Err(KernelAhciRetiredMappingRemovalError {
            failure,
            retirement,
        }),
    }
}

pub struct RetiredKernelAhciServiceCleanupComplete {
    retirement: SupervisedNativeDeviceServiceRetirement<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
    launch: BoundAhciServiceLaunch,
}

impl RetiredKernelAhciServiceCleanupComplete {
    pub const fn service(&self) -> ServiceId {
        self.retirement.service()
    }
}

pub struct KernelAhciRetiredServiceCleanupError<
    'resources,
    S: PageTableStore,
    E,
    const P: usize,
    const O: usize,
    const MM: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
> {
    error: ServiceCleanupError<E>,
    owner: RetiredKernelAhciServiceMappingsRemoved<
        'resources,
        S,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
}

impl<
    'resources,
    S: PageTableStore,
    E,
    const P: usize,
    const O: usize,
    const MM: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
>
    KernelAhciRetiredServiceCleanupError<
        'resources,
        S,
        E,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >
{
    pub const fn error(&self) -> &ServiceCleanupError<E> {
        &self.error
    }

    pub fn into_owner(
        self,
    ) -> RetiredKernelAhciServiceMappingsRemoved<
        'resources,
        S,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    > {
        self.owner
    }
}

/// Erases the exact retired address space while its empty concrete root and
/// memory-resource owner remain retained, then releases that owner only after
/// the supervisor accepts the same cleanup ticket.
///
/// # Safety
///
/// The mapping backend which produced `owner` must truthfully have withdrawn
/// every leaf and required translation. `eraser` success must mean the retired
/// address space can no longer be entered or addressed. Dispatch must remain
/// withheld until this operation succeeds.
pub unsafe fn complete_retired_kernel_ahci_service_cleanup<
    'resources,
    S: PageTableStore,
    E: ServiceAddressSpaceEraser,
    const P: usize,
    const O: usize,
    const MM: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
    const SERVICES: usize,
>(
    owner: RetiredKernelAhciServiceMappingsRemoved<
        'resources,
        S,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
    supervisor: &mut ServiceSupervisor<SERVICES>,
    eraser: &mut E,
) -> Result<
    RetiredKernelAhciServiceCleanupComplete,
    KernelAhciRetiredServiceCleanupError<
        'resources,
        S,
        E::Error,
        P,
        O,
        MM,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
> {
    let RetiredKernelAhciServiceMappingsRemoved {
        owner: mapping_owner,
        retirement,
    } = owner;
    // SAFETY: the caller supplies the exact mapping-withdrawal and erasure
    // truthfulness proof while the retained owner prevents premature release.
    match unsafe {
        supervisor.complete_supervised_native_device_service_cleanup(&retirement, eraser)
    } {
        Ok(()) => {
            let launch = mapping_owner.prepared().launch();
            // SAFETY: cleanup above succeeded for this retirement while all
            // concrete mappings were already removed by the only constructor.
            let _prepared = unsafe { mapping_owner.release_after_retired_cleanup() };
            Ok(RetiredKernelAhciServiceCleanupComplete { retirement, launch })
        }
        Err(error) => Err(KernelAhciRetiredServiceCleanupError {
            error,
            owner: RetiredKernelAhciServiceMappingsRemoved {
                owner: mapping_owner,
                retirement,
            },
        }),
    }
}

pub struct KernelAhciServiceDispatchError {
    error: TaskTerminationDispatchError,
    owner: RetiredKernelAhciServiceCleanupComplete,
}

impl KernelAhciServiceDispatchError {
    pub const fn error(&self) -> TaskTerminationDispatchError {
        self.error
    }

    pub fn into_owner(self) -> RetiredKernelAhciServiceCleanupComplete {
        self.owner
    }
}

pub fn dispatch_retired_kernel_ahci_service_task<
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
>(
    owner: RetiredKernelAhciServiceCleanupComplete,
    runtime: &mut TaskRuntime<TASKS, TASK_CAPABILITIES>,
) -> Result<DispatchedAhciServiceTask, KernelAhciServiceDispatchError> {
    let RetiredKernelAhciServiceCleanupComplete { retirement, launch } = owner;
    match retirement.dispatch(runtime) {
        Ok(retirement) => Ok(DispatchedAhciServiceTask { retirement, launch }),
        Err(error) => {
            let dispatch_error = error.error();
            Err(KernelAhciServiceDispatchError {
                error: dispatch_error,
                owner: RetiredKernelAhciServiceCleanupComplete {
                    retirement: error.into_retirement(),
                    launch,
                },
            })
        }
    }
}

impl<L, E, R, M, D> AhciServiceTeardownReacquisitionError<L, E, R, M, D> {
    pub const fn lease_error(&self) -> Option<&E> {
        match self {
            Self::Lease { error, .. } => Some(error),
            Self::Binding { .. } => None,
        }
    }

    pub const fn binding_error(&self) -> Option<AhciServiceTaskBindingError> {
        match self {
            Self::Lease { .. } => None,
            Self::Binding { error, .. } => Some(*error),
        }
    }

    pub fn into_retry(self) -> Result<(E, FrozenAhciServiceExit<L>), Self> {
        match self {
            Self::Lease { error, frozen } => Ok((error, frozen)),
            other => Err(other),
        }
    }

    pub fn into_quarantine(self) -> Result<QuarantinedAhciServiceTeardown<R, M, D>, Self> {
        match self {
            Self::Binding { quarantine, .. } => Ok(quarantine),
            other => Err(other),
        }
    }
}

/// Reacquires trusted teardown mechanism only after the exact task is frozen,
/// then independently exact-matches the lease result to retained launch
/// state before any device quiescence begins.
///
/// The unsafe implementation of [`AhciServiceTeardownLease`] supplies the sole
/// authority-transfer proof. This safe wrapper consumes it only after the
/// exact runtime-bound native task has been frozen. Successful quiescence later
/// destroys all borrowed views before retirement or mapping withdrawal.
pub fn reacquire_frozen_ahci_service_teardown<L: AhciServiceTeardownLease>(
    frozen: FrozenAhciServiceExit<L>,
) -> Result<
    ReacquiredAhciServiceTeardown<L::Registers, L::CommandMemory, L::DataIo>,
    AhciServiceTeardownReacquisitionError<L, L::Error, L::Registers, L::CommandMemory, L::DataIo>,
> {
    let FrozenAhciServiceExit {
        frozen: lifecycle,
        launch,
        mappings,
        lease,
    } = frozen;
    // SAFETY: the consuming owner contains the exact freeze whose native task
    // and launch were matched to this lease before that freeze was created.
    // No safe API exposes the frozen task for resume or controller issue.
    let backend = match unsafe { lease.reacquire() } {
        Ok(backend) => backend,
        Err((error, lease)) => {
            return Err(AhciServiceTeardownReacquisitionError::Lease {
                error,
                frozen: FrozenAhciServiceExit {
                    frozen: lifecycle,
                    launch,
                    mappings,
                    lease,
                },
            });
        }
    };
    let spec = launch.spec();
    let binding = if backend.mapping() != spec.mapping() {
        Some(AhciServiceTaskBindingError::MappingMismatch)
    } else if backend.port() != &ActiveAhciPort::from_layout(spec.layout()) {
        Some(AhciServiceTaskBindingError::PortMismatch)
    } else if backend.data_region() != spec.data() {
        Some(AhciServiceTaskBindingError::DataRegionMismatch)
    } else {
        None
    };
    if let Some(error) = binding {
        return Err(AhciServiceTeardownReacquisitionError::Binding {
            error,
            quarantine: QuarantinedAhciServiceTeardown {
                frozen: lifecycle,
                launch,
                mappings,
                backend,
            },
        });
    }
    Ok(ReacquiredAhciServiceTeardown {
        frozen: lifecycle,
        launch,
        mappings,
        backend,
    })
}

pub struct FrozenAhciServiceQuiesceError<R, M, D> {
    frozen: SupervisedNativeDeviceServiceFreeze<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
    launch: BoundAhciServiceLaunch,
    error: AhciCommandBackendQuiesceError<R, M, D>,
}

impl<R, M, D> FrozenAhciServiceQuiesceError<R, M, D> {
    pub const fn device_error(&self) -> &AhciServiceDeviceQuiesceError {
        self.error.failure()
    }
}

pub fn quiesce_reacquired_ahci_service<
    R: AhciRegisterIo,
    M: AhciCommandMemoryIo,
    D: AhciDataBufferIo,
    B: AhciPortDmaBackend,
>(
    owner: ReacquiredAhciServiceTeardown<R, M, D>,
    dma_backend: &mut B,
) -> Result<QuiescedAhciServiceTask, FrozenAhciServiceQuiesceError<R, M, D>> {
    let ReacquiredAhciServiceTeardown {
        frozen,
        launch,
        mappings,
        backend,
    } = owner;
    match quiesce_ahci_command_backend(backend, mappings, dma_backend) {
        Ok(backend) => Ok(quiesced_service_task(frozen, launch, backend)),
        Err(error) => Err(FrozenAhciServiceQuiesceError {
            frozen,
            launch,
            error,
        }),
    }
}

pub fn resume_frozen_ahci_service_quiescence<R, M, D: AhciDataBufferIo, B: AhciPortDmaBackend>(
    error: FrozenAhciServiceQuiesceError<R, M, D>,
    dma_backend: &mut B,
) -> Result<QuiescedAhciServiceTask, FrozenAhciServiceQuiesceError<R, M, D>> {
    let FrozenAhciServiceQuiesceError {
        frozen,
        launch,
        error,
    } = error;
    match resume_ahci_command_backend_teardown(error, dma_backend) {
        Ok(backend) => Ok(quiesced_service_task(frozen, launch, backend)),
        Err(error) => Err(FrozenAhciServiceQuiesceError {
            frozen,
            launch,
            error,
        }),
    }
}

fn quiesced_service_task<R, M, D>(
    frozen: SupervisedNativeDeviceServiceFreeze<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
    launch: BoundAhciServiceLaunch,
    backend: QuiescedAhciCommandBackend<R, M, D>,
) -> QuiescedAhciServiceTask {
    let (mappings, _, registers, command_memory, data_io) = backend.into_parts();
    // These owners may borrow the service's CPU mappings. Destroy every view
    // while the frozen address space and mappings are still live; the returned
    // lifecycle token deliberately contains no generic backend value.
    drop(data_io);
    drop(command_memory);
    drop(registers);
    QuiescedAhciServiceTask {
        frozen,
        launch,
        mappings,
    }
}

pub struct RetiredAhciServiceTask {
    retirement: SupervisedNativeDeviceServiceRetirement<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
    launch: BoundAhciServiceLaunch,
    mappings: QuiescedAhciServiceMappings,
}

impl RetiredAhciServiceTask {
    pub const fn service(&self) -> ServiceId {
        self.retirement.service()
    }
}

pub struct AhciServiceTaskRetirementError {
    error: SupervisedNativeDeviceServiceRetirementError,
    owner: QuiescedAhciServiceTask,
}

impl AhciServiceTaskRetirementError {
    pub const fn error(&self) -> SupervisedNativeDeviceServiceRetirementError {
        self.error
    }

    pub fn into_owner(self) -> QuiescedAhciServiceTask {
        self.owner
    }
}

/// Retires an execution-frozen AHCI service after trusted device quiescence.
///
/// # Safety
///
/// The caller must establish that the backends which produced `owner`
/// truthfully enforced engine stop, command completion or fail-closed
/// cancellation, data sanitization, and DMA withdrawal. All borrowed backend
/// views have already been destroyed. The returned owner must continue through
/// typed mapping removal and exact supervisor cleanup before successor dispatch.
pub unsafe fn retire_quiesced_ahci_service_task<
    const TASKS: usize,
    const CAPABILITIES: usize,
    const SERVICES: usize,
>(
    owner: QuiescedAhciServiceTask,
    supervisor: &mut ServiceSupervisor<SERVICES>,
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
) -> Result<RetiredAhciServiceTask, AhciServiceTaskRetirementError> {
    let QuiescedAhciServiceTask {
        frozen,
        launch,
        mappings,
    } = owner;
    // SAFETY: the caller supplies the trusted-backend proof documented above;
    // the consuming owner proves that this path ran those backend operations.
    // The composite kernel path withholds successor dispatch for mapping cleanup.
    match unsafe { supervisor.retire_frozen_native_device_service(frozen, runtime) } {
        Ok(retirement) => Ok(RetiredAhciServiceTask {
            retirement,
            launch,
            mappings,
        }),
        Err(error) => {
            let retirement_error = error.error();
            Err(AhciServiceTaskRetirementError {
                error: retirement_error,
                owner: QuiescedAhciServiceTask {
                    frozen: error.into_frozen(),
                    launch,
                    mappings,
                },
            })
        }
    }
}

pub struct RetiredAhciServiceMappingsRemoved {
    retirement: SupervisedNativeDeviceServiceRetirement<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
    launch: BoundAhciServiceLaunch,
}

pub struct AhciRetiredMappingRemovalError<E> {
    error: AhciServiceMappingRemovalError<E>,
    retirement: SupervisedNativeDeviceServiceRetirement<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
    launch: BoundAhciServiceLaunch,
}

impl<E> AhciRetiredMappingRemovalError<E> {
    pub const fn error(&self) -> &AhciServiceMappingRemovalError<E> {
        &self.error
    }

    pub fn into_owner(self) -> RetiredAhciServiceTask {
        RetiredAhciServiceTask {
            retirement: self.retirement,
            launch: self.launch,
            mappings: QuiescedAhciServiceMappings {
                mappings: self.error.into_retained(),
            },
        }
    }
}

/// Withdraws every retained CPU and ABAR mapping before service cleanup.
///
/// # Safety
///
/// The caller must establish that successful results from `abar_backend` and
/// `cpu_backend` mean the exact mappings are no longer live. The returned
/// owner must remain retained through exact supervisor cleanup before dispatch.
pub unsafe fn remove_retired_ahci_service_mappings<
    A: AhciAbarRemovalBackend,
    B: AhciServiceCpuMappingBackend,
    const C: usize,
>(
    owner: RetiredAhciServiceTask,
    abar_control_capability: Capability,
    capabilities: &CapabilitySpace<C>,
    abar_backend: &mut A,
    cpu_backend: &mut B,
) -> Result<RetiredAhciServiceMappingsRemoved, AhciRetiredMappingRemovalError<B::Error>> {
    let RetiredAhciServiceTask {
        retirement,
        launch,
        mappings,
    } = owner;
    match remove_quiesced_ahci_service_mappings(
        mappings,
        abar_control_capability,
        capabilities,
        abar_backend,
        cpu_backend,
    ) {
        Ok(state) => {
            debug_assert!(state.complete());
            Ok(RetiredAhciServiceMappingsRemoved { retirement, launch })
        }
        Err(error) => Err(AhciRetiredMappingRemovalError {
            error,
            retirement,
            launch,
        }),
    }
}

pub struct RetiredAhciServiceCleanupComplete {
    retirement: SupervisedNativeDeviceServiceRetirement<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
    launch: BoundAhciServiceLaunch,
}

pub struct AhciRetiredServiceCleanupError<E> {
    error: ServiceCleanupError<E>,
    owner: RetiredAhciServiceMappingsRemoved,
}

impl<E> AhciRetiredServiceCleanupError<E> {
    pub const fn error(&self) -> &ServiceCleanupError<E> {
        &self.error
    }

    pub fn into_owner(self) -> RetiredAhciServiceMappingsRemoved {
        self.owner
    }
}

/// Erases the exact retired service address space after mapping withdrawal.
///
/// # Safety
///
/// The caller must establish that the mapping-removal backends which produced
/// `owner` truthfully withdrew every mapping and that an `Ok` result from
/// `eraser` means the retired address space can no longer be entered or
/// addressed. Dispatch must remain withheld until this call succeeds.
pub unsafe fn complete_retired_ahci_service_cleanup<
    E: ServiceAddressSpaceEraser,
    const SERVICES: usize,
>(
    owner: RetiredAhciServiceMappingsRemoved,
    supervisor: &mut ServiceSupervisor<SERVICES>,
    eraser: &mut E,
) -> Result<RetiredAhciServiceCleanupComplete, AhciRetiredServiceCleanupError<E::Error>> {
    let RetiredAhciServiceMappingsRemoved { retirement, launch } = owner;
    // SAFETY: the caller supplies the backend-success and address-erasure proof;
    // the typed owner binds completed mapping steps to the exact retirement.
    match unsafe {
        supervisor.complete_supervised_native_device_service_cleanup(&retirement, eraser)
    } {
        Ok(()) => Ok(RetiredAhciServiceCleanupComplete { retirement, launch }),
        Err(error) => Err(AhciRetiredServiceCleanupError {
            error,
            owner: RetiredAhciServiceMappingsRemoved { retirement, launch },
        }),
    }
}

pub struct DispatchedAhciServiceTask {
    retirement: SupervisedNativeDeviceServiceDispatch<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
    launch: BoundAhciServiceLaunch,
}

impl DispatchedAhciServiceTask {
    pub const fn dispatch(&self) -> &TaskTerminationDispatch {
        self.retirement.dispatch()
    }

    pub const fn service(&self) -> ServiceId {
        self.retirement.service()
    }

    pub const fn cleanup(&self) -> ServiceCleanupTicket {
        self.retirement.cleanup()
    }

    pub fn into_parts(
        self,
    ) -> (
        SupervisedNativeDeviceServiceDispatch<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
        BoundAhciServiceLaunch,
    ) {
        (self.retirement, self.launch)
    }
}

pub struct AhciServiceDispatchError {
    error: TaskTerminationDispatchError,
    owner: RetiredAhciServiceCleanupComplete,
}

impl AhciServiceDispatchError {
    pub const fn error(&self) -> TaskTerminationDispatchError {
        self.error
    }

    pub fn into_owner(self) -> RetiredAhciServiceCleanupComplete {
        self.owner
    }
}

pub fn dispatch_retired_ahci_service_task<const TASKS: usize, const CAPABILITIES: usize>(
    owner: RetiredAhciServiceCleanupComplete,
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
) -> Result<DispatchedAhciServiceTask, AhciServiceDispatchError> {
    let RetiredAhciServiceCleanupComplete { retirement, launch } = owner;
    match retirement.dispatch(runtime) {
        Ok(retirement) => Ok(DispatchedAhciServiceTask { retirement, launch }),
        Err(error) => {
            let dispatch_error = error.error();
            Err(AhciServiceDispatchError {
                error: dispatch_error,
                owner: RetiredAhciServiceCleanupComplete {
                    retirement: error.into_retirement(),
                    launch,
                },
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn quiesce_ahci_service_device<
    R: AhciRegisterIo,
    M: AhciCommandMemoryIo,
    D: AhciDataBufferIo,
    B: AhciPortDmaBackend,
>(
    mapping: AhciAbarMapping,
    port: ActiveAhciPort,
    mappings: AhciServiceMappingTeardown,
    data_region: AhciDataDmaRegion,
    registers: &mut R,
    command_memory: &mut M,
    data: &mut D,
    dma_backend: &mut B,
) -> Result<QuiescedAhciServiceMappings, AhciServiceDeviceQuiesceError> {
    if mappings.abar().map(|abar| abar.mapping()) != Some(mapping) {
        return Err(AhciServiceDeviceQuiesceError::MappingMismatch { port, mappings });
    }
    let stopped = match stop_ahci_port_engine(mapping, port, registers) {
        Ok(stopped) => stopped,
        Err(failure) => {
            return Err(AhciServiceDeviceQuiesceError::Engine { failure, mappings });
        }
    };
    let dma = match reclaim_stopped_ahci_port_dma(mapping, stopped, registers, command_memory) {
        Ok(dma) => dma,
        Err(failure) => {
            return Err(AhciServiceDeviceQuiesceError::Cleanup { failure, mappings });
        }
    };
    if data.sanitize(data_region).is_err() {
        return Err(AhciServiceDeviceQuiesceError::Pending(
            PendingAhciServiceDeviceTeardown::DataSanitization { dma, mappings },
        ));
    }
    withdraw_dma(dma, mappings, dma_backend).map_err(AhciServiceDeviceQuiesceError::Pending)
}

pub fn resume_ahci_service_device_teardown<D: AhciDataBufferIo, B: AhciPortDmaBackend>(
    pending: PendingAhciServiceDeviceTeardown,
    data_region: AhciDataDmaRegion,
    data: &mut D,
    dma_backend: &mut B,
) -> Result<QuiescedAhciServiceMappings, PendingAhciServiceDeviceTeardown> {
    let (dma, mappings) = match pending {
        PendingAhciServiceDeviceTeardown::DataSanitization { dma, mappings } => {
            if data.sanitize(data_region).is_err() {
                return Err(PendingAhciServiceDeviceTeardown::DataSanitization { dma, mappings });
            }
            (dma, mappings)
        }
        PendingAhciServiceDeviceTeardown::DmaWithdrawal { dma, mappings } => (dma, mappings),
    };
    withdraw_dma(dma, mappings, dma_backend)
}

fn withdraw_dma<B: AhciPortDmaBackend>(
    dma: InstalledAhciPortDma,
    mappings: AhciServiceMappingTeardown,
    backend: &mut B,
) -> Result<QuiescedAhciServiceMappings, PendingAhciServiceDeviceTeardown> {
    match revoke_ahci_port_dma(dma, backend) {
        Ok(()) => Ok(QuiescedAhciServiceMappings { mappings }),
        Err(error) => Err(PendingAhciServiceDeviceTeardown::DmaWithdrawal {
            dma: error.into_owner(),
            mappings,
        }),
    }
}

pub fn remove_quiesced_ahci_service_mappings<
    A: AhciAbarRemovalBackend,
    D: AhciServiceCpuMappingBackend,
    const C: usize,
>(
    quiesced: QuiescedAhciServiceMappings,
    abar_control_capability: Capability,
    capabilities: &CapabilitySpace<C>,
    abar_backend: &mut A,
    cpu_backend: &mut D,
) -> Result<AhciServiceMappingTeardown, AhciServiceMappingRemovalError<D::Error>> {
    remove_ahci_service_mappings(
        quiesced.mappings,
        abar_control_capability,
        capabilities,
        abar_backend,
        cpu_backend,
    )
}
