// This module is split by compiler phase to keep every auditable source file below
// the repository source-size ceiling while preserving one private codegen namespace.
include!("codegen/api_and_assembly.rs");
include!("codegen/runtime_analysis.rs");
include!("codegen/runtime_emitter.rs");
include!("codegen/tests.rs");
