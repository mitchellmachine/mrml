#![no_std]

//! Isolated NVMe block-provider mechanisms for MRML storage.
//!
//! The storage service retains object identity, filesystem, transaction, and
//! authority policy. This package never treats PCI identity as authority.

mod nvme_controller;
mod nvme_discovery;
mod nvme_mapping;

pub use nvme_controller::{
    disable_nvme_controller, NvmeControllerError, NvmeControllerFailure, NvmeControllerRegisterIo,
    NvmeControllerSnapshot, NVME_CAP_OFFSET, NVME_CC_OFFSET, NVME_CSTS_OFFSET, NVME_VERSION_OFFSET,
};
pub use nvme_discovery::{
    NvmeControllerBarDescriptor, NvmeDiscoveryError, NvmePciFunctionSnapshot, PciFunctionLocation,
    NVME_CONTROLLER_BAR_MINIMUM_BYTES, NVME_PCI_CLASS, NVME_PCI_PROGRAMMING_INTERFACE,
    NVME_PCI_SUBCLASS,
};
pub use nvme_mapping::{
    map_nvme_controller_bar, NvmeControllerBarMapping, NvmeControllerBarMappingBackend,
    NvmeControllerBarMappingError, NVME_MMIO_PAGE_BYTES,
};
