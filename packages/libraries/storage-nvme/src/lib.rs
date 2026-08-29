#![no_std]

//! Isolated NVMe block-provider mechanisms for MRML storage.
//!
//! The storage service retains object identity, filesystem, transaction, and
//! authority policy. This package never treats PCI identity as authority.

mod nvme_discovery;

pub use nvme_discovery::{
    NvmeControllerBarDescriptor, NvmeDiscoveryError, NvmePciFunctionSnapshot, PciFunctionLocation,
    NVME_CONTROLLER_BAR_MINIMUM_BYTES, NVME_PCI_CLASS, NVME_PCI_PROGRAMMING_INTERFACE,
    NVME_PCI_SUBCLASS,
};
