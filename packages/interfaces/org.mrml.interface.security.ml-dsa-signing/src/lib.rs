#![no_std]

//! Capability-bound ML-DSA-65 signing-use interface.
//!
//! The provider owns randomness and key custody. The caller supplies a
//! canonical Git object payload and receives only a raw signature. Routes are
//! exact-key and workspace scoped; names and public-key digests do not grant
//! authority. An implementation may back the route with an expiring
//! `UnlockedSigningKeyCache`, but passphrases never cross this protocol and are
//! never cached.

#[path = "../1.rs"]
mod generated;

pub use generated::*;

pub const ML_DSA_65_PUBLIC_KEY_BYTES: u64 = 1952;
pub const ML_DSA_65_SIGNATURE_BYTES: u64 = 3309;
pub const MAX_SIGNING_INPUT_BYTES: u64 = 16 * 1024 * 1024;
