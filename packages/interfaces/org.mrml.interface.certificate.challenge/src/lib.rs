#![no_std]
//! Exact generation-bound HTTP-01, TLS-ALPN-01, and DNS-01 publication lifecycle.
#[path = "../1.rs"] mod generated;
pub use generated::*;
pub const CHALLENGE_HTTP01:u32=1;
pub const CHALLENGE_TLS_ALPN01:u32=2;
pub const CHALLENGE_DNS01:u32=3;
