//! Device quiescence gate before AHCI service mapping withdrawal.

use crate::{
    reclaim_stopped_ahci_port_dma, remove_ahci_service_mappings, revoke_ahci_port_dma,
    stop_ahci_port_engine, ActiveAhciPort, AhciAbarMapping, AhciAbarRemovalBackend,
    AhciCleanupFailure, AhciCommandMemoryIo, AhciDataBufferIo, AhciDataDmaRegion,
    AhciEngineFailure, AhciPortDmaBackend, AhciRegisterIo,
    AhciServiceCpuMappingBackend, AhciServiceMappingRemovalError, AhciServiceMappingTeardown,
    InstalledAhciPortDma,
};
use mrml_kernel::{Capability, CapabilitySpace};

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
