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

## Current implementation boundary

Only the central identity and bounded facade parser are implemented at this
checkpoint. MRML ABI v1 signature validation, deterministic type layout,
ownership/borrowing rules, System V and Windows lowering, link compatibility,
and external execution evidence remain required before an attributed function
can be emitted. Code generation therefore continues to reject `MrmlV1` rather
than silently routing it through the C ABI.

In particular, this checkpoint does not define the representation of slices,
strings, references, arrays, tuples, aggregates, or indirect returns. It also
does not establish that existing `extern "C"` tests with Rust-specific types are
C-compatible; those boundaries require a separate fail-closed validation and
test migration.
