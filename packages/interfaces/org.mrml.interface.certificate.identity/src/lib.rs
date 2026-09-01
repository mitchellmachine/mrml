#![no_std]
//! Capability-scoped exact TLS identity publication; descriptors identify but do not authorize.
#[path = "../1.rs"] mod generated;
pub use generated::*;
pub const HEALTH_HEALTHY:u32=1;
pub const HEALTH_WARNING:u32=2;
pub const HEALTH_CRITICAL:u32=3;
pub const HEALTH_EXPIRED:u32=4;
