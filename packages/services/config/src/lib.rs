#![no_std]

//! Fixed-capacity policy/configuration service foundation.
//!
//! Setting identifiers select records; they never authorize access. Every
//! read and transaction update repeats exact capability checks against the
//! schema-bound object. Transactions preflight all schema, authority, revision,
//! capacity, and sequence conditions before the first mutation.
//! Control planes establish authority; data planes should take the shortest
//! safe path. Persisted policy is therefore typed control-plane input only: it
//! neither grants capabilities nor becomes an invocation-path data transport.

include!("config/implementation.rs");
include!("config/tests.rs");
