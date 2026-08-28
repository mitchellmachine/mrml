# MRML ABI v1

Status: **PARTIALLY IMPLEMENTED**

MRML ABI v1 is the first versioned MRML-owned function interface. It is a
language-level interface whose native lowering is target-specific; it is not the
Rust ABI and is not inferred from `extern "C"`.

## Shared-source facade

Source selects this ABI with the exact attribute:

```rust
#[mrml_abi::export(version = 1)]
pub fn sum_bytes(input: &[u8]) -> u64 {
    input.iter().map(|byte| u64::from(*byte)).sum()
}
```

The source does not contain a literal `extern "mrml-v1"`, so the same function
body can be used by MRML and a pinned upstream-rustc differential harness. The
upstream build must provide the pinned, repository-controlled `mrml_abi` facade;
absence or identity mismatch is a comparison failure, not permission to discard
the attribute.

The MRML parser accepts only `mrml_abi::export`, requires exactly
`version = 1`, and records the central `FunctionAbi::MrmlV1` identity. The
function must currently be an ordinary public Rust-syntax function. The facade
implies a stable unmangled export name. Duplicate attributes, unknown fields or
versions, private functions, const functions, naked functions, and combination
with an explicit native ABI fail closed.

Unknown future versions are never interpreted as version 1.

## Signature validation

The central, allocation-free v1 classifier currently admits these logical
source types:

- fixed-width `u8` through `u128` and `i8` through `i128` integers;
- `bool` and `char`;
- const and mutable raw pointers to those scalar types;
- shared and mutable references to those scalar types;
- shared and mutable slices of those scalar types; and
- shared and mutable `str` references.

An omitted return type is the v1 unit type. `usize` and `isize` fail with a
distinct platform-sized-integer reason. Undefined aggregates, floats, aliases,
user types, nested pointers, and every other unclassified spelling fail closed
as unsupported. Validation reports whether failure belongs to the function,
an exact parameter index, or the return type. This logical classification does
not itself define a machine representation.

## Current implementation boundary

The central identity, bounded facade parser, and initial signature classifier
are implemented at this checkpoint. Deterministic type layout,
ownership/borrowing rules beyond ordinary language checking, System V and
Windows lowering, link compatibility, and external execution evidence remain
required before an attributed function can be emitted. Code generation
therefore continues to reject `MrmlV1` rather than silently routing it through
the C ABI.

In particular, logical acceptance of slices, strings, or references does not
yet define their representation. Arrays, tuples, aggregates, and indirect
returns are not admitted. This checkpoint also does not establish that existing
`extern "C"` tests with Rust-specific types are C-compatible; those boundaries
require a separate fail-closed validation and test migration.
