#![no_std]

//! Isolated legacy IDE block-provider mechanisms for MRML storage.
//!
//! Legacy compatibility is opt-in. PCI identity and fixed port numbers never
//! authorize I/O; the storage service retains authority and policy.

mod ide_discovery;
mod ide_dma;
mod ide_dma_command;
mod ide_identify;
mod ide_pio;
mod ide_ports;
mod ide_reset;

pub use ide_discovery::{
    IdeChannelDescriptor, IdeChannelMode, IdeControllerDescriptor, IdeDiscoveryError,
    IdePciFunctionSnapshot, PciFunctionLocation, IDE_PCI_CLASS, IDE_PCI_SUBCLASS,
};
pub use ide_dma::{
    prepare_ide_dma, revoke_ide_dma, IdeDmaBackend, IdeDmaDirection, IdeDmaError, IdeDmaFailure,
    IdeDmaLayout, IdeDmaMemoryIo, IdeDmaRegion, IdeDmaRequest, IdeDmaRevocationError,
    PreparedIdeDma, IDE_PRD_ENTRY_LIMIT, IDE_PRD_TABLE_BYTES,
};
pub use ide_dma_command::{
    execute_ide_dma, CompletedIdeDma, IdeDmaCommandError, IdeDmaCommandFailure, IdeDmaCommandIo,
    IdeDmaCommandRequest, IdeDmaOperation,
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
    prepare_ide_channel_ports, revoke_ide_channel_ports, IdeChannel, IdeChannelPortGrant,
    IdePortGrantBackend, IdePortGrantError, IdePortGrantRequest, IdePortRange,
    IdePortRevocationError,
};
pub use ide_reset::{reset_ide_channel, IdeResetError, IdeResetFailure};
