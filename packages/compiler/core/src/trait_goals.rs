//! Bounded canonical trait-goal foundations.
//!
//! It provides stable, allocation-free identities, first-occurrence
//! canonicalization, exact concrete-header selection, and bounded response
//! substitutions without confusing inference variables, placeholders, or
//! concrete types.

include!("trait_goals/implementation.rs");
include!("trait_goals/tests.rs");
