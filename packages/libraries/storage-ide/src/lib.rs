#![no_std]

//! Isolated legacy IDE block-provider mechanisms for MRML storage.
//!
//! Legacy compatibility is opt-in. PCI identity and fixed port numbers never
//! authorize I/O; the storage service retains authority and policy.

mod ide_discovery;

pub use ide_discovery::{
    IdeChannelDescriptor, IdeChannelMode, IdeControllerDescriptor, IdeDiscoveryError,
    IdePciFunctionSnapshot, PciFunctionLocation, IDE_PCI_CLASS, IDE_PCI_SUBCLASS,
};
