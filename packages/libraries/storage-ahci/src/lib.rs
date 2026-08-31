#![no_std]

//! Isolated AHCI block-provider implementation for MRML storage.
//!
//! This library contains device mechanism only. The storage service retains
//! object identity, filesystem, transaction, and authority policy.

#[cfg(target_arch = "x86_64")]
mod active_mapping_verification;
mod ahci_cleanup;
mod ahci_command;
mod ahci_command_execute;
mod ahci_command_memory;
mod ahci_command_recycle;
mod ahci_controller;
mod ahci_discovery;
mod ahci_dma;
mod ahci_engine;
mod ahci_flush;
mod ahci_mapping;
mod ahci_port;
mod ahci_port_program;
mod ahci_reset;
mod block_io_adapter;
mod command_block_backend;
mod control_service_loop;
mod data_service_loop;
mod dispatch_service;
mod kernel_abar_page_table;
mod kernel_preactivation_mapping_set;
mod kernel_service_cpu_mapping;
mod mapped_command_memory;
mod mapped_data_buffer;
mod native_mapped_memory;
#[cfg(target_arch = "x86_64")]
mod native_pci_bar_probe;
mod native_port_reconstruction;
mod native_service_state;
mod platform_io;
mod service_bootstrap;
mod service_cpu_mapping;
mod service_device_teardown;
mod service_launch;
mod service_launch_record;
mod service_loop;
mod service_mapping_lifecycle;
mod userspace_syscall_adapter;
#[cfg(target_arch = "x86_64")]
mod x86_coherent_data_sync;
#[cfg(target_arch = "x86_64")]
mod x86_teardown_reacquisition;

use mrml_interface_storage_block_provider_v1::{
    BlockProviderDevice, BlockProviderTransport, ENUMERATE_REQUEST_BYTES, ENUMERATE_RESPONSE_BYTES,
    EnumerateError, ProtocolError, decode_enumerate_request, encode_block_device_catalog,
    encode_enumerate_response,
};

#[cfg(target_arch = "x86_64")]
pub use active_mapping_verification::{
    ActiveAhciMappingVerificationError, verify_active_x86_ahci_mappings,
    verify_current_x86_ahci_mappings,
};
pub use ahci_cleanup::{AhciCleanupError, AhciCleanupFailure, reclaim_stopped_ahci_port_dma};
pub use ahci_command::{
    AHCI_MAX_TRANSFER_BYTES, AhciAtaCommand, AhciCommandBuildError, AhciCommandBuildFailure,
    AhciDataDmaRegion, PreparedAhciCommand, prepare_ahci_dma_command,
};
pub use ahci_command_execute::{
    AHCI_COMMAND_COMPLETION_POLL_LIMIT, AhciCommandCompletion, AhciCommandExecuteError,
    AhciCommandExecuteFailure, execute_ahci_dma_command,
};
pub use ahci_command_memory::{
    AhciCommandMemoryError, AhciCommandMemoryFailure, AhciCommandMemoryIo,
    InitializedAhciCommandMemory, initialize_ahci_command_memory,
};
pub use ahci_command_recycle::{
    AhciCommandRecycleError, AhciCommandRecycleFailure, RecycledAhciCommand,
    recycle_ahci_command_slot,
};
pub use ahci_controller::{
    AHCI_CAP_OFFSET, AHCI_GHC_OFFSET, AHCI_PI_OFFSET, AHCI_RESET_POLL_LIMIT, AHCI_VERSION_OFFSET,
    AhciControllerError, AhciControllerSnapshot, AhciRegisterIo, NativeAhciRegisterIo,
    reset_ahci_controller,
};
pub use ahci_discovery::{
    AHCI_ABAR_MINIMUM_BYTES, AHCI_PCI_CLASS, AHCI_PCI_PROGRAMMING_INTERFACE, AHCI_PCI_SUBCLASS,
    AhciAbarDescriptor, AhciAbarSizeProbe, AhciAbarSizeProbeError, AhciDiscoveryError,
    AhciPciBarProbeError, AhciPciBarProbeFailure, AhciPciBarProbeIo, AhciPciFunctionSnapshot,
    ExclusiveAhciPciFunction, PciFunctionLocation, ProbedAhciPciFunction,
};
pub use ahci_dma::{
    AHCI_COMMAND_LIST_ALIGNMENT, AHCI_COMMAND_LIST_BYTES, AHCI_COMMAND_TABLE_ALIGNMENT,
    AHCI_COMMAND_TABLE_BYTES_PER_SLOT, AHCI_RECEIVED_FIS_ALIGNMENT, AHCI_RECEIVED_FIS_BYTES,
    AhciDmaRegion, AhciPortDmaBackend, AhciPortDmaError, AhciPortDmaLayout, AhciPortDmaRequest,
    AhciPortDmaRevocationError, InstalledAhciPortDma, prepare_ahci_port_dma, revoke_ahci_port_dma,
};
pub use ahci_engine::{
    AHCI_ENGINE_STOP_POLL_LIMIT, ActiveAhciPort, AhciEngineError, AhciEngineFailure,
    StoppedAhciPort, start_ahci_port_engine, stop_ahci_port_engine,
};
pub use ahci_flush::{
    AHCI_FLUSH_COMPLETION_POLL_LIMIT, AhciFlushError, AhciFlushFailure, flush_ahci_cache,
};
pub use ahci_mapping::{
    AHCI_ABAR_PAGE_PERMISSIONS, AHCI_MMIO_PAGE_BYTES, AhciAbarMapping, AhciAbarMappingBackend,
    AhciAbarMappingError, AhciAbarRemovalBackend, AhciAbarRemovalError, InstalledAhciAbarMapping,
    install_ahci_service_abar, map_ahci_abar, remove_ahci_service_abar,
};
pub use ahci_port::{
    AHCI_ATAPI_SIGNATURE, AHCI_ENCLOSURE_MANAGEMENT_SIGNATURE, AHCI_MAX_PORTS,
    AHCI_PORT_BASE_OFFSET, AHCI_PORT_COMMAND_ISSUE_OFFSET, AHCI_PORT_COMMAND_OFFSET,
    AHCI_PORT_INTERRUPT_ENABLE_OFFSET, AHCI_PORT_MULTIPLIER_SIGNATURE,
    AHCI_PORT_SATA_ACTIVE_OFFSET, AHCI_PORT_SATA_STATUS_OFFSET, AHCI_PORT_SIGNATURE_OFFSET,
    AHCI_PORT_STRIDE_BYTES, AHCI_SATA_SIGNATURE, AhciPortDeviceKind, AhciPortDiscoveryError,
    AhciPortError, AhciPortLinkSpeed, AhciPortLinkState, AhciPortPowerState, AhciPortSnapshot,
    AhciPortSnapshotSet, discover_ahci_ports,
};
pub use ahci_port_program::{
    AhciPortProgramError, AhciPortProgramFailure, ProgrammedAhciPortDma,
    program_ahci_port_dma_bases,
};
pub use ahci_reset::{
    AHCI_RESET_LINK_POLL_LIMIT, AhciPortResetError, AhciPortResetFailure, AhciResetIo,
    reset_ahci_sata_port,
};
pub use block_io_adapter::{
    AhciBlockControlAdapter, AhciBlockControlBackend, AhciBlockControlError, AhciBlockIoAdapter,
    AhciBlockIoBackend, AhciBlockIoError,
};
pub use command_block_backend::{
    AhciCommandBackendTeardown, AhciCommandBlockBackend, AhciDataBufferIo,
    AhciDataCapabilityAuthorizer, QuarantinedAhciCommandBackend,
};
pub use control_service_loop::{
    AhciControlServiceLoop, AhciControlServiceLoopError, AhciControlServiceSyscalls,
    ReceivedAhciControlEnvelope,
};
pub use data_service_loop::{
    AhciDataServiceLoopError, AhciDataServiceSyscalls, AhciReadWriteServiceLoop,
    ReceivedAhciDataEnvelope,
};
pub use dispatch_service::{
    AHCI_DISPATCH_REQUEST_BYTES, AhciDispatchService, AhciDispatchServiceError,
    AhciDispatchSyscalls, ReceivedAhciDispatchEnvelope,
};
pub use kernel_abar_page_table::{
    KernelAhciAbarPreactivationError, KernelAhciAbarPreactivationOwner,
    KernelAhciAbarRollbackFailure,
};
pub use kernel_preactivation_mapping_set::{
    ActiveKernelAhciMappingSetOwner, FrozenKernelAhciMappingSetOwner,
    KernelAhciMappingSetActivationError, KernelAhciMappingSetActivationFailure,
    KernelAhciMappingSetFreezeFailure, KernelAhciPreactivationMappingSetError,
    KernelAhciPreactivationMappingSetInstallFailure, KernelAhciPreactivationMappingSetInstallState,
    KernelAhciPreactivationMappingSetOwner, KernelAhciPreactivationMappingSetQuarantineError,
    KernelAhciPreactivationMappingSetQuarantineFailure,
    KernelAhciPreactivationMappingSetRollbackFailure, KernelAhciQuarantinedMappingSetOwner,
};
pub use kernel_service_cpu_mapping::{
    KernelAhciServiceCpuMappingAdapter, KernelAhciServiceCpuMappingAdapterError,
    KernelAhciServiceCpuMappingOperationError,
};
pub use mapped_command_memory::AhciMappedCommandMemory;
pub use mapped_data_buffer::{AhciDataBufferSync, AhciMappedDataBuffer};
pub use native_mapped_memory::{AhciNativeMappedMemory, AhciNativeMappedMemoryError};
#[cfg(target_arch = "x86_64")]
pub use native_pci_bar_probe::{
    NativeAhciPciAdmissionFailure, NativeAhciPciBarProbe, NativeAhciPciBarProbeError,
};
pub use native_port_reconstruction::{
    AhciNativePortReconstructionError, reconstruct_bound_ahci_port, reconstruct_installed_ahci_port,
};
pub use native_service_state::{
    AHCI_DISPATCH_SCRATCH_BYTES, AhciNativeServiceBuffers, AhciNativeServiceExitDisposition,
    AhciNativeServiceExitReady, AhciNativeServicePreparationError, AhciNativeServiceState,
    AhciNativeServiceStateError, AhciNativeServiceStopOwner,
    bootstrap_and_prepare_installed_ahci_service, prepare_installed_ahci_service_state,
};
#[cfg(target_arch = "x86_64")]
pub use native_service_state::{
    bootstrap_and_prepare_native_x86_coherent_ahci_service,
    bootstrap_and_prepare_x86_coherent_ahci_service,
    prepare_bootstrapped_native_x86_coherent_ahci_service,
};
pub use platform_io::{AhciMonotonicDelay, AhciPlatformIo};
pub use service_bootstrap::{
    AhciReplyBinding, AhciServiceBootstrapError, AhciServiceEntryRegisters,
    bootstrap_installed_ahci_entry, bootstrap_installed_ahci_service,
};
pub use service_cpu_mapping::{
    AHCI_SERVICE_CPU_MAPPING_RIGHTS, AhciInstalledCpuMappings, AhciServiceCpuMappingBackend,
    AhciServiceCpuMappingError, AhciServiceCpuMappingRemovalError, AhciServiceCpuMappingRequest,
    install_ahci_service_cpu_mappings, remove_ahci_service_cpu_mappings,
};
pub use service_device_teardown::{
    AhciCommandBackendQuiesceError, AhciRetiredMappingRemovalError, AhciRetiredServiceCleanupError,
    AhciServiceDeviceQuiesceError, AhciServiceDispatchError, AhciServiceExitFreezeError,
    AhciServiceTaskBindingError, AhciServiceTaskRetirementError, AhciServiceTeardownLease,
    AhciServiceTeardownLeaseBindingError, AhciServiceTeardownReacquisitionError,
    DispatchedAhciServiceTask, FrozenAhciServiceExit, FrozenAhciServiceQuiesceError,
    FrozenKernelAhciServiceExit, FrozenKernelAhciServiceQuiesceError,
    KernelAhciManagerTeardownLease, KernelAhciRetiredMappingRemovalError,
    KernelAhciRetiredServiceCleanupError, KernelAhciServiceCleanupCompleted,
    KernelAhciServiceDeviceQuiesceFailure, KernelAhciServiceDispatchError,
    KernelAhciServiceDispatched, KernelAhciServiceExitDispatchError,
    KernelAhciServiceExitFreezeError, KernelAhciServiceExitManager,
    KernelAhciServiceExitManagerDispatchError, KernelAhciServiceExitRequest,
    KernelAhciServiceExitRequestError, KernelAhciServiceExitRouted, KernelAhciServiceExitSlot,
    KernelAhciServiceExitSlotInstallError, KernelAhciServiceExitSlotPopulationError,
    KernelAhciServiceExitSlotPopulationFailure, KernelAhciServiceExitSlotRouteError,
    KernelAhciServiceManagerCleanupError, KernelAhciServiceManagerDispatchCompletionError,
    KernelAhciServiceManagerMappingRemovalError, KernelAhciServiceManagerQuiesceError,
    KernelAhciServiceManagerReacquisitionError, KernelAhciServiceManagerRetirementError,
    KernelAhciServiceMappingsRemoved, KernelAhciServiceQuiesced, KernelAhciServiceReacquired,
    KernelAhciServiceRetired, KernelAhciServiceTaskRetirementError,
    KernelAhciServiceTeardownManager, KernelAhciServiceTeardownReacquisitionError,
    KernelAhciTeardownReacquisitionBackend, PendingAhciServiceDeviceTeardown,
    QuarantinedAhciServiceTeardown, QuarantinedKernelAhciServiceTeardown,
    QuiescedAhciCommandBackend, QuiescedAhciServiceMappings, QuiescedAhciServiceTask,
    QuiescedKernelAhciServiceTask, ReacquiredAhciServiceTeardown,
    ReacquiredKernelAhciServiceTeardown, RetiredAhciServiceCleanupComplete,
    RetiredAhciServiceMappingsRemoved, RetiredAhciServiceTask,
    RetiredKernelAhciServiceCleanupComplete, RetiredKernelAhciServiceMappingsRemoved,
    RetiredKernelAhciServiceTask, begin_active_ahci_service_exit,
    begin_active_kernel_ahci_service_exit, complete_retired_ahci_service_cleanup,
    complete_retired_kernel_ahci_service_cleanup, dispatch_retired_ahci_service_task,
    dispatch_retired_kernel_ahci_service_task, quiesce_ahci_command_backend,
    quiesce_ahci_service_device, quiesce_reacquired_ahci_service,
    quiesce_reacquired_kernel_ahci_service, reacquire_frozen_ahci_service_teardown,
    reacquire_frozen_kernel_ahci_service_teardown, remove_quiesced_ahci_service_mappings,
    remove_retired_ahci_service_mappings, remove_retired_kernel_ahci_service_mappings,
    resume_ahci_command_backend_teardown, resume_ahci_service_device_teardown,
    resume_frozen_ahci_service_quiescence, resume_frozen_kernel_ahci_service_quiescence,
    retire_quiesced_ahci_service_task, retire_quiesced_kernel_ahci_service_task,
    route_active_kernel_ahci_service_exit,
};
pub use service_launch::{
    AHCI_COMMAND_LIST_AUTHORITY_INDEX, AHCI_COMMAND_TABLES_AUTHORITY_INDEX,
    AHCI_DEVICE_AUTHORITY_INDEX, AHCI_DEVICE_READ_DATA_AUTHORITY_INDEX,
    AHCI_DEVICE_WRITE_DATA_AUTHORITY_INDEX, AHCI_RECEIVED_FIS_AUTHORITY_INDEX,
    AHCI_SERVICE_AUTHORITY_COUNT, AHCI_SERVICE_LAUNCH_BYTES, AhciServiceLaunchSpec,
    AhciServiceLaunchSpecError,
};
pub use service_launch_record::{
    AhciNativeServiceTaskPreparationFailure, AhciServiceCpuMapping, AhciServiceLaunchRecord,
    AhciServiceLaunchRecordError, BoundAhciServiceLaunch, InstalledAhciServiceLaunch,
    PreparedAhciNativeServiceTask, prepare_bound_ahci_native_service_task,
};
pub use service_loop::{
    AhciEnumerationServiceLoop, AhciServiceLoopError, AhciServiceSyscalls, ReceivedAhciEnvelope,
};
pub use service_mapping_lifecycle::{
    ActiveAhciNativeServiceTask, AhciServiceActivationError, AhciServiceActivationFailure,
    AhciServiceMappingInstallError, AhciServiceMappingRemovalError, AhciServiceMappingTeardown,
    MappedAhciNativeServiceTask, PreparedAhciServiceMappingError,
    PreparedAhciServiceMappingFailure, activate_mapped_ahci_service_task,
    install_ahci_service_mappings, install_prepared_ahci_service_mappings,
    remove_ahci_service_mappings,
};
#[cfg(target_arch = "x86_64")]
pub use userspace_syscall_adapter::NativeAhciRawSyscall;
pub use userspace_syscall_adapter::{
    AhciInstalledDataAuthorizer, AhciRawSyscall, AhciSyscallFrame, AhciUserspaceSyscallError,
    AhciUserspaceSyscalls,
};
#[cfg(target_arch = "x86_64")]
pub use x86_coherent_data_sync::AhciX86CoherentDataSync;
#[cfg(target_arch = "x86_64")]
pub use x86_teardown_reacquisition::{
    AhciX86ActiveMappingVerifier, AhciX86TeardownReacquisition, AhciX86TeardownReacquisitionError,
    CurrentAhciX86ActiveMappingVerifier, X86AhciServiceExitSlot,
    X86AhciServiceManagerActivationFailure, activate_and_install_x86_ahci_service_exit_slot,
    activate_and_populate_x86_ahci_service_exit_slot, install_x86_ahci_service_exit_slot,
};

pub struct AhciBlockProvider<'a> {
    devices: &'a [BlockProviderDevice],
}

impl<'a> AhciBlockProvider<'a> {
    pub const fn new(devices: &'a [BlockProviderDevice]) -> Self {
        Self { devices }
    }
}

impl BlockProviderTransport for AhciBlockProvider<'_> {
    fn enumerate(
        &mut self,
        request: &[u8; ENUMERATE_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; ENUMERATE_RESPONSE_BYTES], ProtocolError> {
        let request = decode_enumerate_request(request, memory.len() as u64)?;
        let result = encode_block_device_catalog(self.devices, request.output, memory)
            .map_err(|_| EnumerateError::InvalidRequest);
        Ok(encode_enumerate_response(result))
    }
}

#[cfg(test)]
mod provider_tests {
    use super::*;
    use mrml_interface_storage_block_provider_v1::{
        BLOCK_DEVICE_FLAG_FLUSH, BorrowedWriteView, OpaqueHandle, decode_enumerate_response,
        encode_enumerate_request,
    };

    #[test]
    fn provider_enumerates_exact_generation_bound_catalog() {
        let devices = [BlockProviderDevice {
            session: OpaqueHandle::new(4, 8).unwrap(),
            logical_block_bytes: 512,
            flags: BLOCK_DEVICE_FLAG_FLUSH,
            logical_block_count: 65_536,
            media_generation: 12,
        }];
        let mut provider = AhciBlockProvider::new(&devices);
        let output = BorrowedWriteView::within(16, 48, 64).unwrap();
        let request = encode_enumerate_request(output).unwrap();
        let mut memory = [0xa5; 64];
        let response = provider.enumerate(&request, &mut memory).unwrap();
        assert_eq!(decode_enumerate_response(&response, 48), Ok(Ok(48)));
        assert_eq!(&memory[16..24], b"MRMLBLK\0");
        assert_eq!(u32::from_le_bytes(memory[32..36].try_into().unwrap()), 4);
        assert_eq!(u32::from_le_bytes(memory[36..40].try_into().unwrap()), 8);
        assert_eq!(u64::from_le_bytes(memory[56..64].try_into().unwrap()), 12);
    }
}
