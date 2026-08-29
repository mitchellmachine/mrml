#![no_std]

//! Isolated AHCI block-provider implementation for MRML storage.
//!
//! This library contains device mechanism only. The storage service retains
//! object identity, filesystem, transaction, and authority policy.

mod ahci_cleanup;
mod ahci_command_memory;
mod ahci_controller;
mod ahci_discovery;
mod ahci_dma;
mod ahci_engine;
mod ahci_mapping;
mod ahci_port;
mod ahci_port_program;

pub use ahci_cleanup::{AhciCleanupError, AhciCleanupFailure, reclaim_stopped_ahci_port_dma};
pub use ahci_command_memory::{
    AhciCommandMemoryError, AhciCommandMemoryFailure, AhciCommandMemoryIo,
    InitializedAhciCommandMemory, initialize_ahci_command_memory,
};
pub use ahci_controller::{
    AHCI_CAP_OFFSET, AHCI_GHC_OFFSET, AHCI_PI_OFFSET, AHCI_RESET_POLL_LIMIT, AHCI_VERSION_OFFSET,
    AhciControllerError, AhciControllerSnapshot, AhciRegisterIo, NativeAhciRegisterIo,
    reset_ahci_controller,
};
pub use ahci_discovery::{
    AHCI_ABAR_MINIMUM_BYTES, AHCI_PCI_CLASS, AHCI_PCI_PROGRAMMING_INTERFACE, AHCI_PCI_SUBCLASS,
    AhciAbarDescriptor, AhciDiscoveryError, AhciPciFunctionSnapshot, PciFunctionLocation,
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
pub use ahci_mapping::{
    AHCI_MMIO_PAGE_BYTES, AhciAbarMapping, AhciAbarMappingBackend, AhciAbarMappingError,
    map_ahci_abar,
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
