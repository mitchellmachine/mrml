#![no_std]

//! Isolated AHCI block-provider implementation for MRML storage.
//!
//! This library contains device mechanism only. The storage service retains
//! object identity, filesystem, transaction, and authority policy.

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
mod mapped_command_memory;
mod mapped_data_buffer;
mod service_launch;
mod service_launch_record;
mod service_loop;
mod userspace_syscall_adapter;

use mrml_interface_storage_block_provider_v1::{
    decode_enumerate_request, encode_block_device_catalog, encode_enumerate_response,
    BlockProviderDevice, BlockProviderTransport, EnumerateError, ProtocolError,
    ENUMERATE_REQUEST_BYTES, ENUMERATE_RESPONSE_BYTES,
};

pub use ahci_cleanup::{reclaim_stopped_ahci_port_dma, AhciCleanupError, AhciCleanupFailure};
pub use ahci_command::{
    prepare_ahci_dma_command, AhciAtaCommand, AhciCommandBuildError, AhciCommandBuildFailure,
    AhciDataDmaRegion, PreparedAhciCommand,
};
pub use ahci_command_execute::{
    execute_ahci_dma_command, AhciCommandCompletion, AhciCommandExecuteError,
    AhciCommandExecuteFailure, AHCI_COMMAND_COMPLETION_POLL_LIMIT,
};
pub use ahci_command_memory::{
    initialize_ahci_command_memory, AhciCommandMemoryError, AhciCommandMemoryFailure,
    AhciCommandMemoryIo, InitializedAhciCommandMemory,
};
pub use ahci_command_recycle::{
    recycle_ahci_command_slot, AhciCommandRecycleError, AhciCommandRecycleFailure,
    RecycledAhciCommand,
};
pub use ahci_controller::{
    reset_ahci_controller, AhciControllerError, AhciControllerSnapshot, AhciRegisterIo,
    NativeAhciRegisterIo, AHCI_CAP_OFFSET, AHCI_GHC_OFFSET, AHCI_PI_OFFSET, AHCI_RESET_POLL_LIMIT,
    AHCI_VERSION_OFFSET,
};
pub use ahci_discovery::{
    AhciAbarDescriptor, AhciDiscoveryError, AhciPciFunctionSnapshot, PciFunctionLocation,
    AHCI_ABAR_MINIMUM_BYTES, AHCI_PCI_CLASS, AHCI_PCI_PROGRAMMING_INTERFACE, AHCI_PCI_SUBCLASS,
};
pub use ahci_dma::{
    prepare_ahci_port_dma, revoke_ahci_port_dma, AhciDmaRegion, AhciPortDmaBackend,
    AhciPortDmaError, AhciPortDmaLayout, AhciPortDmaRequest, AhciPortDmaRevocationError,
    InstalledAhciPortDma, AHCI_COMMAND_LIST_ALIGNMENT, AHCI_COMMAND_LIST_BYTES,
    AHCI_COMMAND_TABLE_ALIGNMENT, AHCI_COMMAND_TABLE_BYTES_PER_SLOT, AHCI_RECEIVED_FIS_ALIGNMENT,
    AHCI_RECEIVED_FIS_BYTES,
};
pub use ahci_engine::{
    start_ahci_port_engine, stop_ahci_port_engine, ActiveAhciPort, AhciEngineError,
    AhciEngineFailure, StoppedAhciPort, AHCI_ENGINE_STOP_POLL_LIMIT,
};
pub use ahci_flush::{
    flush_ahci_cache, AhciFlushError, AhciFlushFailure, AHCI_FLUSH_COMPLETION_POLL_LIMIT,
};
pub use ahci_mapping::{
    map_ahci_abar, AhciAbarMapping, AhciAbarMappingBackend, AhciAbarMappingError,
    AHCI_MMIO_PAGE_BYTES,
};
pub use ahci_port::{
    discover_ahci_ports, AhciPortDeviceKind, AhciPortDiscoveryError, AhciPortError,
    AhciPortLinkSpeed, AhciPortLinkState, AhciPortPowerState, AhciPortSnapshot,
    AhciPortSnapshotSet, AHCI_ATAPI_SIGNATURE, AHCI_ENCLOSURE_MANAGEMENT_SIGNATURE, AHCI_MAX_PORTS,
    AHCI_PORT_BASE_OFFSET, AHCI_PORT_COMMAND_ISSUE_OFFSET, AHCI_PORT_COMMAND_OFFSET,
    AHCI_PORT_INTERRUPT_ENABLE_OFFSET, AHCI_PORT_MULTIPLIER_SIGNATURE,
    AHCI_PORT_SATA_ACTIVE_OFFSET, AHCI_PORT_SATA_STATUS_OFFSET, AHCI_PORT_SIGNATURE_OFFSET,
    AHCI_PORT_STRIDE_BYTES, AHCI_SATA_SIGNATURE,
};
pub use ahci_port_program::{
    program_ahci_port_dma_bases, AhciPortProgramError, AhciPortProgramFailure,
    ProgrammedAhciPortDma,
};
pub use ahci_reset::{
    reset_ahci_sata_port, AhciPortResetError, AhciPortResetFailure, AhciResetIo,
    AHCI_RESET_LINK_POLL_LIMIT,
};
pub use block_io_adapter::{
    AhciBlockControlAdapter, AhciBlockControlBackend, AhciBlockControlError, AhciBlockIoAdapter,
    AhciBlockIoBackend, AhciBlockIoError,
};
pub use command_block_backend::{AhciCommandBlockBackend, AhciDataBufferIo};
pub use control_service_loop::{
    AhciControlServiceLoop, AhciControlServiceLoopError, AhciControlServiceSyscalls,
    ReceivedAhciControlEnvelope,
};
pub use data_service_loop::{
    AhciDataServiceLoopError, AhciDataServiceSyscalls, AhciReadWriteServiceLoop,
    ReceivedAhciDataEnvelope,
};
pub use dispatch_service::{
    AhciDispatchService, AhciDispatchServiceError, AhciDispatchSyscalls,
    ReceivedAhciDispatchEnvelope, AHCI_DISPATCH_REQUEST_BYTES,
};
pub use mapped_command_memory::AhciMappedCommandMemory;
pub use mapped_data_buffer::{AhciDataBufferSync, AhciMappedDataBuffer};
pub use service_launch::{
    AHCI_COMMAND_LIST_AUTHORITY_INDEX, AHCI_COMMAND_TABLES_AUTHORITY_INDEX,
    AHCI_DEVICE_AUTHORITY_INDEX, AHCI_DEVICE_READ_DATA_AUTHORITY_INDEX,
    AHCI_DEVICE_WRITE_DATA_AUTHORITY_INDEX, AHCI_RECEIVED_FIS_AUTHORITY_INDEX,
    AHCI_SERVICE_AUTHORITY_COUNT, AHCI_SERVICE_LAUNCH_BYTES, AhciServiceLaunchSpec,
    AhciServiceLaunchSpecError,
};
pub use service_launch_record::{
    AhciServiceCpuMapping, AhciServiceLaunchRecord, AhciServiceLaunchRecordError,
    BoundAhciServiceLaunch,
};
pub use service_loop::{
    AhciEnumerationServiceLoop, AhciServiceLoopError, AhciServiceSyscalls, ReceivedAhciEnvelope,
};
pub use userspace_syscall_adapter::{
    AhciRawSyscall, AhciSyscallFrame, AhciUserspaceSyscallError, AhciUserspaceSyscalls,
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
        decode_enumerate_response, encode_enumerate_request, BorrowedWriteView, OpaqueHandle,
        BLOCK_DEVICE_FLAG_FLUSH,
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
