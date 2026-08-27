#![no_std]

mod abi;
#[cfg(target_os = "windows")]
mod native;
mod protected_broker;

pub use abi::{GuestRange, MapPermissions, WHP_EXIT_CONTEXT_BYTES, WhpError, decode_exit_context};
#[cfg(target_os = "windows")]
pub use native::{
    FirmwareProbeLayout, PreparedWhpFirmware, PreparedWhpGuest, PreparedWhpPeerPage,
    WhpLaunchLayout, WhpPageWalk, WhpPeerPageError, WhpPeerPagePrepareFailure, WhpServiceEraser,
    WhpSystem,
};
pub use protected_broker::{BrokerError, BrokerTicket, UntrustedLaunchBroker};
