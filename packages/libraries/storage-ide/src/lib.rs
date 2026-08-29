#![no_std]

//! Isolated legacy IDE block-provider mechanisms for MRML storage.
//!
//! Legacy compatibility is opt-in. PCI identity and fixed port numbers never
//! authorize I/O; the storage service retains authority and policy.

mod ide_discovery;
mod ide_identify;
mod ide_pio;
mod ide_ports;

pub use ide_discovery::{
    IdeChannelDescriptor, IdeChannelMode, IdeControllerDescriptor, IdeDiscoveryError,
    IdePciFunctionSnapshot, PciFunctionLocation, IDE_PCI_CLASS, IDE_PCI_SUBCLASS,
};
pub use ide_identify::{
    identify_ide_device, IdeDevice, IdeDeviceIdentity, IdeIdentifyError, IdeIdentifyFailure,
    IdePortIo,
};
pub use ide_pio::{
    execute_ide_pio, CompletedIdePio, IdePioBuffer, IdePioError, IdePioFailure, IdePioIo,
    IdePioOperation, IdePioRequest,
};
pub use ide_ports::{
    prepare_ide_channel_ports, IdeChannel, IdeChannelPortGrant, IdePortGrantBackend,
    IdePortGrantError, IdePortGrantRequest, IdePortRange,
};
