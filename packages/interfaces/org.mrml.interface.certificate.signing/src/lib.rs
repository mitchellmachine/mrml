#![no_std]
//! Generation-bound, use-only certificate signing. The route capability authorizes;
//! identity and key fields only bind the selected route and never grant authority.
#[path = "../1.rs"] mod generated;
pub use generated::*;
pub const PURPOSE_ACME_ACCOUNT_JWS:u32=1;
pub const PURPOSE_PKCS10:u32=2;
pub const PURPOSE_TLS13_CERTIFICATE_VERIFY:u32=3;
pub const PURPOSE_TLS_ALPN01_CERTIFICATE:u32=4;
