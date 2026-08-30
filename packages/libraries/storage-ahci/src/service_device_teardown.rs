//! Device quiescence gate before AHCI service mapping withdrawal.

use crate::{
    reclaim_stopped_ahci_port_dma, remove_ahci_service_mappings, revoke_ahci_port_dma,
    stop_ahci_port_engine, ActiveAhciPort, AhciAbarMapping, AhciAbarRemovalBackend,
    AhciCleanupFailure, AhciCommandBackendTeardown, AhciCommandMemoryIo, AhciDataBufferIo,
    AhciDataDmaRegion, AhciEngineFailure, AhciPortDmaBackend, AhciRegisterIo,
    AhciServiceCpuMappingBackend, AhciServiceMappingRemovalError,
    AhciServiceMappingTeardown, BoundAhciServiceLaunch, InstalledAhciPortDma,
};
use mrml_kernel::{
    Capability, CapabilitySpace, ServiceAddressSpaceEraser, ServiceCleanupError,
    ServiceCleanupTicket, ServiceId, ServiceSupervisor,
    SupervisedNativeDeviceServiceDispatch, SupervisedNativeDeviceServiceFreeze,
    SupervisedNativeDeviceServiceRetirement, SupervisedNativeDeviceServiceRetirementError,
    TaskRuntime, TaskTerminationDispatch, TaskTerminationDispatchError,
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
    match resume_ahci_service_device_teardown(
        pending,
        data_region,
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

pub struct QuiescedAhciServiceTask<R, M, D> {
    frozen: SupervisedNativeDeviceServiceFreeze<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
    launch: BoundAhciServiceLaunch,
    backend: QuiescedAhciCommandBackend<R, M, D>,
}

impl<R, M, D> QuiescedAhciServiceTask<R, M, D> {
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

pub enum ActiveAhciServiceQuiesceError<R, M, D> {
    Binding {
        error: AhciServiceTaskBindingError,
        active: crate::ActiveAhciNativeServiceTask,
        backend: AhciCommandBackendTeardown<R, M, D>,
    },
    Device {
        frozen: SupervisedNativeDeviceServiceFreeze<{
            crate::AHCI_SERVICE_AUTHORITY_COUNT
        }>,
        launch: BoundAhciServiceLaunch,
        error: AhciCommandBackendQuiesceError<R, M, D>,
    },
    Lifecycle {
        error: SupervisedNativeDeviceServiceRetirementError,
        active: crate::ActiveAhciNativeServiceTask,
        backend: AhciCommandBackendTeardown<R, M, D>,
    },
}

impl<R, M, D> ActiveAhciServiceQuiesceError<R, M, D> {
    pub const fn binding_error(&self) -> Option<AhciServiceTaskBindingError> {
        match self {
            Self::Binding { error, .. } => Some(*error),
            Self::Device { .. } | Self::Lifecycle { .. } => None,
        }
    }

    pub const fn lifecycle_error(
        &self,
    ) -> Option<SupervisedNativeDeviceServiceRetirementError> {
        match self {
            Self::Lifecycle { error, .. } => Some(*error),
            Self::Binding { .. } | Self::Device { .. } => None,
        }
    }

    pub const fn device_error(&self) -> Option<&AhciServiceDeviceQuiesceError> {
        match self {
            Self::Binding { .. } => None,
            Self::Device { error, .. } => Some(error.failure()),
            Self::Lifecycle { .. } => None,
        }
    }

    pub fn into_binding_parts(
        self,
    ) -> Result<
        (
            AhciServiceTaskBindingError,
            crate::ActiveAhciNativeServiceTask,
            AhciCommandBackendTeardown<R, M, D>,
        ),
        Self,
    > {
        match self {
            Self::Binding {
                error,
                active,
                backend,
            } => Ok((error, active, backend)),
            other => Err(other),
        }
    }

    pub fn into_lifecycle_parts(
        self,
    ) -> Result<
        (
            SupervisedNativeDeviceServiceRetirementError,
            crate::ActiveAhciNativeServiceTask,
            AhciCommandBackendTeardown<R, M, D>,
        ),
        Self,
    > {
        match self {
            Self::Lifecycle {
                error,
                active,
                backend,
            } => Ok((error, active, backend)),
            other => Err(other),
        }
    }
}

pub fn quiesce_active_ahci_service_task<
    R: AhciRegisterIo,
    M: AhciCommandMemoryIo,
    D: AhciDataBufferIo,
    B: AhciPortDmaBackend,
    const TASKS: usize,
    const CAPABILITIES: usize,
    const SERVICES: usize,
>(
    active: crate::ActiveAhciNativeServiceTask,
    backend: AhciCommandBackendTeardown<R, M, D>,
    dma_backend: &mut B,
    supervisor: &ServiceSupervisor<SERVICES>,
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
) -> Result<QuiescedAhciServiceTask<R, M, D>, ActiveAhciServiceQuiesceError<R, M, D>> {
    let spec = active.mapped().prepared().launch().spec();
    let failure = if backend.mapping() != spec.mapping() {
        Some(AhciServiceTaskBindingError::MappingMismatch)
    } else if backend.port() != &ActiveAhciPort::from_layout(spec.layout()) {
        Some(AhciServiceTaskBindingError::PortMismatch)
    } else if backend.data_region() != spec.data() {
        Some(AhciServiceTaskBindingError::DataRegionMismatch)
    } else {
        None
    };
    if let Some(error) = failure {
        return Err(ActiveAhciServiceQuiesceError::Binding {
            error,
            active,
            backend,
        });
    }

    let native = active.mapped().prepared().task();
    let frozen = match supervisor.freeze_current_native_device_service(
        active.binding(),
        native,
        runtime,
    ) {
        Ok(frozen) => frozen,
        Err(error) => {
            return Err(ActiveAhciServiceQuiesceError::Lifecycle {
                error,
                active,
                backend,
            });
        }
    };
    let (binding, mapped) = active.into_parts();
    let (prepared, mappings) = mapped.into_parts();
    debug_assert_eq!(binding.service(), frozen.service());
    let launch = prepared.launch();
    match quiesce_ahci_command_backend(backend, mappings, dma_backend) {
        Ok(backend) => Ok(quiesced_service_task(frozen, launch, backend)),
        Err(error) => Err(ActiveAhciServiceQuiesceError::Device {
            frozen,
            launch,
            error,
        }),
    }
}

pub fn resume_active_ahci_service_task_quiescence<
    R,
    M,
    D: AhciDataBufferIo,
    B: AhciPortDmaBackend,
>(
    error: ActiveAhciServiceQuiesceError<R, M, D>,
    dma_backend: &mut B,
) -> Result<QuiescedAhciServiceTask<R, M, D>, ActiveAhciServiceQuiesceError<R, M, D>> {
    let ActiveAhciServiceQuiesceError::Device {
        frozen,
        launch,
        error,
    } = error
    else {
        return Err(error);
    };
    match resume_ahci_command_backend_teardown(error, dma_backend) {
        Ok(backend) => Ok(quiesced_service_task(frozen, launch, backend)),
        Err(error) => Err(ActiveAhciServiceQuiesceError::Device {
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
) -> QuiescedAhciServiceTask<R, M, D> {
    QuiescedAhciServiceTask {
        frozen,
        launch,
        backend,
    }
}

pub struct RetiredAhciServiceTask<R, M, D> {
    retirement: SupervisedNativeDeviceServiceRetirement<{
        crate::AHCI_SERVICE_AUTHORITY_COUNT
    }>,
    launch: BoundAhciServiceLaunch,
    backend: QuiescedAhciCommandBackend<R, M, D>,
}

impl<R, M, D> RetiredAhciServiceTask<R, M, D> {
    pub const fn service(&self) -> ServiceId {
        self.retirement.service()
    }
}

pub struct AhciServiceTaskRetirementError<R, M, D> {
    error: SupervisedNativeDeviceServiceRetirementError,
    owner: QuiescedAhciServiceTask<R, M, D>,
}

impl<R, M, D> AhciServiceTaskRetirementError<R, M, D> {
    pub const fn error(&self) -> SupervisedNativeDeviceServiceRetirementError {
        self.error
    }

    pub fn into_owner(self) -> QuiescedAhciServiceTask<R, M, D> {
        self.owner
    }
}

/// Retires an execution-frozen AHCI service after trusted device quiescence.
///
/// # Safety
///
/// The caller must establish that the supplied command and DMA backend
/// implementations truthfully enforce engine stop, command completion or
/// fail-closed cancellation, data sanitization, and DMA withdrawal. The
/// returned owner must continue through typed mapping removal and exact
/// supervisor cleanup before successor dispatch.
pub unsafe fn retire_quiesced_ahci_service_task<
    R,
    M,
    D,
    const TASKS: usize,
    const CAPABILITIES: usize,
    const SERVICES: usize,
>(
    owner: QuiescedAhciServiceTask<R, M, D>,
    supervisor: &mut ServiceSupervisor<SERVICES>,
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
) -> Result<RetiredAhciServiceTask<R, M, D>, AhciServiceTaskRetirementError<R, M, D>> {
    let QuiescedAhciServiceTask {
        frozen,
        launch,
        backend,
    } = owner;
    // SAFETY: the caller supplies the trusted-backend proof documented above;
    // the consuming owner proves that this path ran those backend operations.
    // The composite kernel path withholds successor dispatch for mapping cleanup.
    match unsafe { supervisor.retire_frozen_native_device_service(frozen, runtime) } {
        Ok(retirement) => Ok(RetiredAhciServiceTask {
            retirement,
            launch,
            backend,
        }),
        Err(error) => {
            let retirement_error = error.error();
            Err(AhciServiceTaskRetirementError {
                error: retirement_error,
                owner: QuiescedAhciServiceTask {
                    frozen: error.into_frozen(),
                    launch,
                    backend,
                },
            })
        }
    }
}

pub struct RetiredAhciServiceMappingsRemoved<R, M, D> {
    retirement: SupervisedNativeDeviceServiceRetirement<{
        crate::AHCI_SERVICE_AUTHORITY_COUNT
    }>,
    launch: BoundAhciServiceLaunch,
    registers: R,
    command_memory: M,
    data_io: D,
}

pub struct AhciRetiredMappingRemovalError<E, R, M, D> {
    error: AhciServiceMappingRemovalError<E>,
    retirement: SupervisedNativeDeviceServiceRetirement<{
        crate::AHCI_SERVICE_AUTHORITY_COUNT
    }>,
    launch: BoundAhciServiceLaunch,
    data_region: AhciDataDmaRegion,
    registers: R,
    command_memory: M,
    data_io: D,
}

impl<E, R, M, D> AhciRetiredMappingRemovalError<E, R, M, D> {
    pub const fn error(&self) -> &AhciServiceMappingRemovalError<E> {
        &self.error
    }

    pub fn into_owner(self) -> RetiredAhciServiceTask<R, M, D> {
        RetiredAhciServiceTask {
            retirement: self.retirement,
            launch: self.launch,
            backend: QuiescedAhciCommandBackend {
                mappings: QuiescedAhciServiceMappings {
                    mappings: self.error.into_retained(),
                },
                data_region: self.data_region,
                registers: self.registers,
                command_memory: self.command_memory,
                data_io: self.data_io,
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
    R,
    M,
    D,
    const C: usize,
>(
    owner: RetiredAhciServiceTask<R, M, D>,
    abar_control_capability: Capability,
    capabilities: &CapabilitySpace<C>,
    abar_backend: &mut A,
    cpu_backend: &mut B,
) -> Result<
    RetiredAhciServiceMappingsRemoved<R, M, D>,
    AhciRetiredMappingRemovalError<B::Error, R, M, D>,
> {
    let RetiredAhciServiceTask {
        retirement,
        launch,
        backend,
    } = owner;
    let (mappings, data_region, registers, command_memory, data_io) = backend.into_parts();
    match remove_quiesced_ahci_service_mappings(
        mappings,
        abar_control_capability,
        capabilities,
        abar_backend,
        cpu_backend,
    ) {
        Ok(state) => {
            debug_assert!(state.complete());
            Ok(RetiredAhciServiceMappingsRemoved {
                retirement,
                launch,
                registers,
                command_memory,
                data_io,
            })
        }
        Err(error) => {
            Err(AhciRetiredMappingRemovalError {
                error,
                retirement,
                launch,
                data_region,
                registers,
                command_memory,
                data_io,
            })
        }
    }
}

pub struct RetiredAhciServiceCleanupComplete<R, M, D> {
    retirement: SupervisedNativeDeviceServiceRetirement<{
        crate::AHCI_SERVICE_AUTHORITY_COUNT
    }>,
    launch: BoundAhciServiceLaunch,
    registers: R,
    command_memory: M,
    data_io: D,
}

pub struct AhciRetiredServiceCleanupError<E, R, M, D> {
    error: ServiceCleanupError<E>,
    owner: RetiredAhciServiceMappingsRemoved<R, M, D>,
}

impl<E, R, M, D> AhciRetiredServiceCleanupError<E, R, M, D> {
    pub const fn error(&self) -> &ServiceCleanupError<E> {
        &self.error
    }

    pub fn into_owner(self) -> RetiredAhciServiceMappingsRemoved<R, M, D> {
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
    R,
    M,
    D,
    const SERVICES: usize,
>(
    owner: RetiredAhciServiceMappingsRemoved<R, M, D>,
    supervisor: &mut ServiceSupervisor<SERVICES>,
    eraser: &mut E,
) -> Result<RetiredAhciServiceCleanupComplete<R, M, D>, AhciRetiredServiceCleanupError<E::Error, R, M, D>>
{
    let RetiredAhciServiceMappingsRemoved {
        retirement,
        launch,
        registers,
        command_memory,
        data_io,
    } = owner;
    // SAFETY: the caller supplies the backend-success and address-erasure proof;
    // the typed owner binds completed mapping steps to the exact retirement.
    match unsafe {
        supervisor.complete_supervised_native_device_service_cleanup(&retirement, eraser)
    } {
        Ok(()) => Ok(RetiredAhciServiceCleanupComplete {
            retirement,
            launch,
            registers,
            command_memory,
            data_io,
        }),
        Err(error) => Err(AhciRetiredServiceCleanupError {
            error,
            owner: RetiredAhciServiceMappingsRemoved {
                retirement,
                launch,
                registers,
                command_memory,
                data_io,
            },
        }),
    }
}

pub struct DispatchedAhciServiceTask<R, M, D> {
    retirement: SupervisedNativeDeviceServiceDispatch<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
    launch: BoundAhciServiceLaunch,
    registers: R,
    command_memory: M,
    data_io: D,
}

impl<R, M, D> DispatchedAhciServiceTask<R, M, D> {
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
        R,
        M,
        D,
    ) {
        (
            self.retirement,
            self.launch,
            self.registers,
            self.command_memory,
            self.data_io,
        )
    }
}

pub struct AhciServiceDispatchError<R, M, D> {
    error: TaskTerminationDispatchError,
    owner: RetiredAhciServiceCleanupComplete<R, M, D>,
}

impl<R, M, D> AhciServiceDispatchError<R, M, D> {
    pub const fn error(&self) -> TaskTerminationDispatchError {
        self.error
    }

    pub fn into_owner(self) -> RetiredAhciServiceCleanupComplete<R, M, D> {
        self.owner
    }
}

pub fn dispatch_retired_ahci_service_task<
    R,
    M,
    D,
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    owner: RetiredAhciServiceCleanupComplete<R, M, D>,
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
) -> Result<DispatchedAhciServiceTask<R, M, D>, AhciServiceDispatchError<R, M, D>> {
    let RetiredAhciServiceCleanupComplete {
        retirement,
        launch,
        registers,
        command_memory,
        data_io,
    } = owner;
    match retirement.dispatch(runtime) {
        Ok(retirement) => Ok(DispatchedAhciServiceTask {
            retirement,
            launch,
            registers,
            command_memory,
            data_io,
        }),
        Err(error) => {
            let dispatch_error = error.error();
            Err(AhciServiceDispatchError {
                error: dispatch_error,
                owner: RetiredAhciServiceCleanupComplete {
                    retirement: error.into_retirement(),
                    launch,
                    registers,
                    command_memory,
                    data_io,
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
        return Err(AhciServiceDeviceQuiesceError::MappingMismatch {
            port,
            mappings,
        });
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
    withdraw_dma(dma, mappings, dma_backend)
        .map_err(AhciServiceDeviceQuiesceError::Pending)
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
                return Err(PendingAhciServiceDeviceTeardown::DataSanitization {
                    dma,
                    mappings,
                });
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
