#![no_std]

//! Isolated NVMe block-provider mechanisms for MRML storage.
//!
//! The storage service retains object identity, filesystem, transaction, and
//! authority policy. This package never treats PCI identity as authority.

mod nvme_admin_command;
mod nvme_controller;
mod nvme_discovery;
mod nvme_identify;
mod nvme_io_command;
mod nvme_io_queue_dma;
mod nvme_io_queue_program;
mod nvme_mapping;
mod nvme_namespace;
mod nvme_prp;
mod nvme_queue_dma;
mod nvme_queue_program;
mod nvme_shutdown;
mod service_loop;
mod userspace_syscall_adapter;

use mrml_interface_storage_block_provider_v1::{
    decode_enumerate_request, encode_block_device_catalog, encode_enumerate_response,
    BlockProviderDevice, BlockProviderTransport, EnumerateError, ProtocolError,
    ENUMERATE_REQUEST_BYTES, ENUMERATE_RESPONSE_BYTES,
};

pub use nvme_admin_command::{
    execute_nvme_identify_controller, execute_nvme_identify_namespace,
    negotiate_nvme_io_queue_count, NvmeAdminCommandError, NvmeAdminCommandFailure,
    NvmeAdminCommandMemoryIo, NvmeAdminCommandStatus, NvmeIdentifyControllerRequest,
    NvmeIdentifyNamespaceRequest, NvmeIoQueueGrant, NVME_IDENTIFY_BYTES, NVME_IO_QUEUE_COUNT_LIMIT,
};
pub use nvme_controller::{
    disable_nvme_controller, NvmeControllerError, NvmeControllerFailure, NvmeControllerRegisterIo,
    NvmeControllerSnapshot, NVME_CAP_OFFSET, NVME_CC_OFFSET, NVME_CSTS_OFFSET, NVME_VERSION_OFFSET,
};
pub use nvme_discovery::{
    NvmeControllerBarDescriptor, NvmeDiscoveryError, NvmePciFunctionSnapshot, PciFunctionLocation,
    NVME_CONTROLLER_BAR_MINIMUM_BYTES, NVME_PCI_CLASS, NVME_PCI_PROGRAMMING_INTERFACE,
    NVME_PCI_SUBCLASS,
};
pub use nvme_identify::{
    parse_nvme_controller_identity, NvmeControllerIdentity, NvmeIdentifyError,
    NVME_BLOCK_INTERFACE_MAX_TRANSFER_BYTES, NVME_NAMESPACE_LIMIT,
};
pub use nvme_io_command::{
    execute_nvme_io, CompletedNvmeIo, NvmeIoCommandError, NvmeIoCommandFailure,
    NvmeIoCommandMemoryIo, NvmeIoOperation, NvmeIoRequest,
};
pub use nvme_io_queue_dma::{
    prepare_nvme_io_queue_dma, NvmeIoQueueDmaBackend, NvmeIoQueueDmaError, NvmeIoQueueDmaFailure,
    NvmeIoQueueDmaLayout, NvmeIoQueueDmaRequest, PreparedNvmeIoQueueDma, NVME_IO_QUEUE_DEPTH_LIMIT,
};
pub use nvme_io_queue_program::{
    create_nvme_io_queue_pair, delete_nvme_io_queue_pair, ActiveNvmeIoQueues,
    NvmeIoQueueCreateError, NvmeIoQueueCreateFailure, NvmeIoQueueDeleteError,
    NvmeIoQueueDeleteFailure,
};
pub use nvme_mapping::{
    map_nvme_controller_bar, unmap_nvme_controller_bar, NvmeControllerBarMapping,
    NvmeControllerBarMappingBackend, NvmeControllerBarMappingError, NvmeControllerBarUnmapError,
    NVME_MMIO_PAGE_BYTES,
};
pub use nvme_namespace::{
    parse_nvme_namespace_identity, NvmeNamespaceIdentity, NvmeNamespaceParseError,
    NVME_MAX_LBA_FORMATS,
};
pub use nvme_prp::{
    prepare_nvme_prps, NvmePrpError, NvmePrpFailure, NvmePrpMemoryIo, NvmePrpRequest,
    NvmeTransferDirection, PreparedNvmePrps, NVME_MAX_PRP_TRANSFER_BYTES, NVME_PRP_LIST_BYTES,
};
pub use nvme_queue_dma::{
    prepare_nvme_admin_queue_dma, revoke_nvme_admin_queue_dma, InstalledNvmeAdminQueueDma,
    NvmeAdminQueueDmaBackend, NvmeAdminQueueDmaError, NvmeAdminQueueDmaLayout,
    NvmeAdminQueueDmaRequest, NvmeAdminQueueDmaRevocationError, NvmeDmaRegion,
    NVME_ADMIN_COMPLETION_BYTES, NVME_ADMIN_QUEUE_DEPTH_LIMIT, NVME_ADMIN_SUBMISSION_BYTES,
    NVME_QUEUE_PAGE_BYTES,
};
pub use nvme_queue_program::{
    disable_nvme_admin_queues, enable_nvme_admin_queues, ActiveNvmeAdminQueues,
    NvmeAdminQueueRegisterIo, NvmeQueueDisableError, NvmeQueueDisableFailure,
    NvmeQueueProgramError, NvmeQueueProgramFailure, NVME_ACQ_OFFSET, NVME_AQA_OFFSET,
    NVME_ASQ_OFFSET,
};
pub use nvme_shutdown::{
    shutdown_nvme_provider, NvmeShutdownError, NvmeShutdownFailure, NvmeShutdownReceipt,
};
pub use service_loop::{
    NvmeEnumerationServiceLoop, NvmeServiceLoopError, NvmeServiceSyscalls, ReceivedNvmeEnvelope,
};
pub use userspace_syscall_adapter::{
    NvmeRawSyscall, NvmeSyscallFrame, NvmeUserspaceSyscallError, NvmeUserspaceSyscalls,
};

pub struct NvmeBlockProvider<'a> {
    devices: &'a [BlockProviderDevice],
}

impl<'a> NvmeBlockProvider<'a> {
    pub const fn new(devices: &'a [BlockProviderDevice]) -> Self {
        Self { devices }
    }
}

impl BlockProviderTransport for NvmeBlockProvider<'_> {
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
        BLOCK_DEVICE_FLAG_FLUSH, BLOCK_DEVICE_FLAG_RESET,
    };

    #[test]
    fn provider_enumerates_exact_namespace_and_media_generations() {
        let devices = [BlockProviderDevice {
            session: OpaqueHandle::new(6, 14).unwrap(),
            logical_block_bytes: 4096,
            flags: BLOCK_DEVICE_FLAG_FLUSH | BLOCK_DEVICE_FLAG_RESET,
            logical_block_count: 262_144,
            media_generation: 21,
        }];
        let mut provider = NvmeBlockProvider::new(&devices);
        let output = BorrowedWriteView::within(16, 48, 64).unwrap();
        let request = encode_enumerate_request(output).unwrap();
        let mut memory = [0xa5; 64];
        let response = provider.enumerate(&request, &mut memory).unwrap();
        assert_eq!(decode_enumerate_response(&response, 48), Ok(Ok(48)));
        assert_eq!(&memory[16..24], b"MRMLBLK\0");
        assert_eq!(u32::from_le_bytes(memory[32..36].try_into().unwrap()), 6);
        assert_eq!(u32::from_le_bytes(memory[36..40].try_into().unwrap()), 14);
        assert_eq!(u64::from_le_bytes(memory[56..64].try_into().unwrap()), 21);
    }
}
