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
