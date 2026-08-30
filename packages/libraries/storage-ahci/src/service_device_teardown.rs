//! Device quiescence gate before AHCI service mapping withdrawal.

use crate::{
    reclaim_stopped_ahci_port_dma, remove_ahci_service_mappings, revoke_ahci_port_dma,
    stop_ahci_port_engine, ActiveAhciPort, AhciAbarMapping, AhciAbarRemovalBackend,
    AhciCleanupFailure, AhciCommandBackendTeardown, AhciCommandMemoryIo, AhciDataBufferIo,
    AhciDataDmaRegion, AhciEngineFailure, AhciPortDmaBackend, AhciRegisterIo,
    AhciServiceCpuMappingBackend, AhciServiceLaunchRecord, AhciServiceMappingRemovalError,
    AhciServiceMappingTeardown, BoundAhciServiceLaunch, InstalledAhciPortDma,
};
use mrml_kernel::{
    retire_current_native_device_service_task, Capability, CapabilitySpace,
    NativeDeviceServiceRetirement, NativeDeviceServiceRetirementError, NativeDeviceServiceTask,
    TaskRuntime,
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
    pub const fn mappings(&self) -> AhciServiceMappingTeardown {
        match self {
            Self::DataSanitization { mappings, .. }
            | Self::DmaWithdrawal { mappings, .. } => *mappings,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuiescedAhciServiceMappings {
    mappings: AhciServiceMappingTeardown,
}

impl QuiescedAhciServiceMappings {
    pub const fn mappings(self) -> AhciServiceMappingTeardown {
        self.mappings
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
    pub const fn mappings(&self) -> QuiescedAhciServiceMappings {
        self.mappings
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
    InvalidBoundLaunch,
    TaskAttachmentMismatch,
    ProviderGenerationMismatch,
    MappingMismatch,
    CpuMappingsMismatch,
    DataRegionMismatch,
}

pub struct QuiescedAhciServiceTask<R, M, D> {
    task: NativeDeviceServiceTask<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
    launch: BoundAhciServiceLaunch,
    backend: QuiescedAhciCommandBackend<R, M, D>,
}

impl<R, M, D> QuiescedAhciServiceTask<R, M, D> {
    pub const fn task(
        &self,
    ) -> NativeDeviceServiceTask<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }> {
        self.task
    }

    pub const fn launch(&self) -> BoundAhciServiceLaunch {
        self.launch
    }
}

pub fn bind_quiesced_ahci_service_task<R, M, D>(
    task: NativeDeviceServiceTask<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
    launch: BoundAhciServiceLaunch,
    backend: QuiescedAhciCommandBackend<R, M, D>,
) -> Result<
    QuiescedAhciServiceTask<R, M, D>,
    (
        AhciServiceTaskBindingError,
        NativeDeviceServiceTask<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
        BoundAhciServiceLaunch,
        QuiescedAhciCommandBackend<R, M, D>,
    ),
> {
    let spec = launch.spec();
    let entry = task.entry();
    let failure = if entry.attachment() != spec.attachment() {
        Some(AhciServiceTaskBindingError::TaskAttachmentMismatch)
    } else if entry.provider_generation() != spec.service().provider_generation() {
        Some(AhciServiceTaskBindingError::ProviderGenerationMismatch)
    } else if backend.mappings().mappings().abar().map(|abar| abar.mapping())
        != Some(spec.mapping())
    {
        Some(AhciServiceTaskBindingError::MappingMismatch)
    } else if backend.data_region() != spec.data() {
        Some(AhciServiceTaskBindingError::DataRegionMismatch)
    } else {
        let record = AhciServiceLaunchRecord::new(
            spec.service().system_generation(),
            spec.service().provider_generation(),
            spec.attachment().attachment_generation(),
            spec.device(),
            spec.mapping(),
            spec.layout(),
            spec.data(),
            launch.cpu_mappings(),
        );
        match record {
            Ok(record) => {
                let cpu = backend.mappings().mappings().cpu();
                (!cpu.fully_installed()
                    || cpu.requests() != crate::service_cpu_mapping::mapping_requests(record))
                    .then_some(AhciServiceTaskBindingError::CpuMappingsMismatch)
            }
            Err(_) => Some(AhciServiceTaskBindingError::InvalidBoundLaunch),
        }
    };
    if let Some(error) = failure {
        return Err((error, task, launch, backend));
    }
    Ok(QuiescedAhciServiceTask {
        task,
        launch,
        backend,
    })
}

pub struct RetiredAhciServiceTask<R, M, D> {
    retirement: NativeDeviceServiceRetirement<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
    launch: BoundAhciServiceLaunch,
    backend: QuiescedAhciCommandBackend<R, M, D>,
}

impl<R, M, D> RetiredAhciServiceTask<R, M, D> {
    pub const fn retirement(
        &self,
    ) -> NativeDeviceServiceRetirement<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }> {
        self.retirement
    }

    pub fn into_parts(
        self,
    ) -> (
        NativeDeviceServiceRetirement<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
        BoundAhciServiceLaunch,
        QuiescedAhciCommandBackend<R, M, D>,
    ) {
        (self.retirement, self.launch, self.backend)
    }
}

pub struct AhciServiceTaskRetirementError<R, M, D> {
    error: NativeDeviceServiceRetirementError,
    owner: QuiescedAhciServiceTask<R, M, D>,
}

impl<R, M, D> AhciServiceTaskRetirementError<R, M, D> {
    pub const fn error(&self) -> NativeDeviceServiceRetirementError {
        self.error
    }

    pub fn into_owner(self) -> QuiescedAhciServiceTask<R, M, D> {
        self.owner
    }
}

pub fn retire_quiesced_ahci_service_task<
    R,
    M,
    D,
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    owner: QuiescedAhciServiceTask<R, M, D>,
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
) -> Result<RetiredAhciServiceTask<R, M, D>, AhciServiceTaskRetirementError<R, M, D>> {
    let QuiescedAhciServiceTask {
        task,
        launch,
        backend,
    } = owner;
    match retire_current_native_device_service_task(task, runtime) {
        Ok((_, retirement)) => Ok(RetiredAhciServiceTask {
            retirement,
            launch,
            backend,
        }),
        Err(error) => Err(AhciServiceTaskRetirementError {
            error,
            owner: QuiescedAhciServiceTask {
                task,
                launch,
                backend,
            },
        }),
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
    let stopped = stop_ahci_port_engine(mapping, port, registers).map_err(|failure| {
        AhciServiceDeviceQuiesceError::Engine { failure, mappings }
    })?;
    let dma = reclaim_stopped_ahci_port_dma(mapping, stopped, registers, command_memory)
        .map_err(|failure| AhciServiceDeviceQuiesceError::Cleanup { failure, mappings })?;
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
