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

## Initial x86-64 value representation

The central layout model defines the same in-memory v1 value representation for
the x86-64 System V and Windows targets. Fixed-width integers use their stated
width and natural alignment. `bool` is one byte and `char` is a four-byte
Unicode scalar value. Raw pointers and references are one eight-byte pointer.
Slices and strings are 16-byte, eight-byte-aligned records with an eight-byte
data pointer at offset zero and an unsigned 64-bit element or UTF-8 byte length
at offset eight. Unit has size zero and alignment one. Integer representation is
little-endian on these x86-64 targets.

Valid v1 `bool` values are zero and one; valid v1 `char` values are Unicode
scalar values. References are non-null and aligned for their pointee, while raw
pointers may be null. A zero-length slice or string may use a non-dereferenceable
aligned data pointer, but its pointer field is still present. These validity
requirements are contract rules; this checkpoint does not yet claim that every
call boundary dynamically validates them.

This representation is distinct from parameter and return classification under
either native calling convention. The later lowering must explicitly describe
registers, stack slots, indirect values, and caller/callee obligations for each
target rather than inheriting Rust or C aggregate rules.

## Current implementation boundary

The central identity, bounded facade parser, initial signature classifier, and
x86-64 in-memory value layout are implemented at this checkpoint.
Ownership/borrowing rules beyond ordinary language checking, System V and
Windows parameter/return lowering, link compatibility, and external execution
evidence remain required before an attributed function can be emitted. Code
generation therefore continues to reject `MrmlV1` rather than silently routing
it through the C ABI.

Arrays, tuples, user aggregates, and indirect returns are not admitted. This
checkpoint also does not establish that existing
`extern "C"` tests with Rust-specific types are C-compatible; those boundaries
require a separate fail-closed validation and test migration.
