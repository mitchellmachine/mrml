#![no_std]
//! Owner-authorized certificate lifecycle administration; the route capability authorizes.
#[path = "../1.rs"] mod generated;
pub use generated::*;
pub const BACKUP_CREATE:u32=1;
pub const BACKUP_VERIFY:u32=2;
pub const RESTORE_VERIFY_ONLY:u32=3;
pub const RESTORE_COMMIT:u32=4;
