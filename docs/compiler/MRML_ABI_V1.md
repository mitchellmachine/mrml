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
ABI identity, validation, layout, and lowering are built into `mrml-rustc`. An
upstream build instead provides the pinned, repository-controlled, modular
`mrml_abi` facade adapter; official rustc can therefore compile the shared
source without learning the custom ABI. Absence or identity mismatch is a
comparison failure, not permission to discard the attribute. The adapter does
not define or authorize MRML-v1 semantics.

The compiler oracle support contains that bounded facade as an identity
attribute macro. The semantic execution gate builds it with the exact dated
rustc, builds executables containing the same attributed functions fed to MRML,
executes both artifacts, and compares their returned observations. Windows uses
the pinned toolchain's own `rust-lld` and runtime library rather than an unpinned
system linker. Current evidence covers one-word scalar calls and two-word slice
parameters, including register/stack crossings and independent data-pointer,
length, and byte-content observations. It is not yet general differential or
cross-language ABI evidence.

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

## Initial x86-64 call classification

V1 decomposes each admitted parameter into zero, one, or two ordered eight-byte
words. A two-word value is the low-address word followed by the high-address
word; for slices and strings this is the data pointer followed by the unsigned
64-bit length. Words consume target argument locations in source order and may
straddle the final argument register and the first stack slot.

On x86-64 System V, the first six words use `rdi`, `rsi`, `rdx`, `rcx`, `r8`,
and `r9`; later words start at callee-entry `[rsp + 8]`. On x86-64 Windows, the
first four words use `rcx`, `rdx`, `r8`, and `r9`; later words start after the
return address and required 32-byte home area at callee-entry `[rsp + 40]`.
Each later word advances by eight bytes. Callers preserve each platform's
ordinary stack-alignment and Windows home-area obligations.

Zero-word unit returns use no register. One-word returns use `rax`. Two-word
returns use `rax` for the low or first word and `rdx` for the high or second
word. Sub-eight-byte unsigned integers, `bool`, `char`, pointers, and references
are zero-extended in their word; signed integers are sign-extended. Unused bits
are therefore deterministic. This is an MRML v1 convention, not a claim that
native C or Rust aggregate classification uses these rules.

## Current implementation boundary

The central identity, bounded facade parser, initial signature classifier,
x86-64 in-memory value layout, and abstract call-location planner are
implemented. Machine-code emission now admits one-word parameters and returns
after validating the signature and target plan: fixed-width integers through 64
bits, `bool`, `char`, scalar raw pointers, scalar references, and unit returns.
It also admits two-word shared or mutable slice and string parameters and
returns. The emitter uses the planned target register or stack order for every
parameter word, returns borrowed views directly in `rax` and `rdx` on both
targets, and does not relabel the function as C ABI.

Unsupported zero-word parameters and `u128` or `i128` parameters and returns
fail with a distinct typed codegen reason at the exact type span. Ownership and
borrowing rules beyond ordinary language checking, other multiword machine-code
lowering, link compatibility, and external execution evidence remain required.
The typed runtime stack model reserves two ordered words for `u128` and `i128`
values as a prerequisite for that lowering; this internal representation does
not by itself admit those types at the public call boundary.

The admitted subset has controlled native execution evidence on the Windows and
Linux test hosts: the public pipeline emits the host object, the test harness
independently extracts its executable image, applies any bounded read-only
relocations, changes the mapping from writable to executable, and calls facade
scalar and slice functions through the host's matching word convention. Exact
dated-rustc observations cover the same attributed sources, including a slice
whose pointer and length straddle the register/stack boundary on each target
and a returned slice captured directly from `rax` and `rdx`. This is not linker,
dynamic-loader, cross-language, or physical-hardware evidence.

Arrays, tuples, user aggregates, and indirect returns are not admitted. This
checkpoint also does not establish that existing
`extern "C"` tests with Rust-specific types are C-compatible; those boundaries
require a separate fail-closed validation and test migration.
