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

Unsupported zero-word parameters fail with a distinct typed codegen reason at
the exact type span. Two-word `u128` and `i128` parameters are admitted for
direct Rust `as` narrowing to supported one-word integer types and for returning
that same parameter unchanged in `rax` and `rdx`. Direct `as` widening from any
fixed-width one-word integer to `u128` or `i128` normalizes the low word at the
source width, then zero-extends unsigned sources or sign-extends signed sources.
Direct casts between `u128` and `i128` preserve both parameter words unchanged.
Direct unary bitwise inversion of a two-word integer inverts both words.
Direct `i128` negation uses carry-aware two-word lowering and traps on `i128::MIN`
when ordinary overflow checks are enabled.
Typed `&`, `|`, and `^` expressions evaluate left-to-right and combine both words
independently for matching wide integer types.
Matching-type `u128` and `i128` addition evaluates left-to-right, propagates the
low-word carry into the high word, and uses unsigned-carry or signed-overflow
branches respectively when ordinary overflow checks are enabled.
Matching-type subtraction likewise propagates low-word borrow into the high word
and selects unsigned-borrow or signed-overflow trapping by declared type.
Equality and inequality compare both words after left-to-right evaluation and
normalize the combined word differences to a boolean that may enter the supported
one-word integer cast/return path.
Closed positive and negative two-word integer literals are range-checked against
the declared return type and materialized directly into the two return words.
Other wide casts, expressions, locals, operations, calls, and returns remain
unavailable and fail closed.
Ownership and borrowing rules beyond ordinary language checking, other
multiword machine-code lowering, link compatibility, and external execution
evidence remain required.
The typed runtime stack model reserves two ordered words for `u128` and `i128`
values, and its logical integer-layout metadata preserves their exact signed or
unsigned 128-bit bounds. The existing one-word instruction emitter rejects that
logical layout instead of narrowing it. These internal representations do not
by themselves admit the types at the public call boundary.
Range-endpoint analysis also uses the logical layout, so positive and negative
128-bit literal magnitudes are checked exactly even while machine emission
remains unavailable.
Saved-parameter and relative parameter-offset accounting use the same complete
runtime type classifier, so a two-word integer reserves both stack words and
cannot overlap a following parameter. Direct narrowing reads the low word after
recording the ordinary parameter-place access; both words still enter through
the target call plan in source order.

The admitted subset has controlled native execution evidence on the Windows and
Linux test hosts: the public pipeline emits the host object, the test harness
independently extracts its executable image, applies any bounded read-only
relocations, changes the mapping from writable to executable, and calls facade
scalar and slice functions through the host's matching word convention. Exact
dated-rustc observations cover the same attributed sources, including a slice
whose pointer and length straddle the register/stack boundary on each target
and a returned slice captured directly from `rax` and `rdx`. Wide-parameter
evidence passes independent `u128` and `i128` low/high words through four target
argument registers and compares nested narrowing with the pinned rustc facade.
It also captures `rax` and `rdx` independently for a nontrivial `u128` identity
round trip and for unsigned, signed, narrow, and cross-signed widening at zero,
extrema, and all-ones. Same-width `u128`/`i128` casts are compared at both words.
Unsigned and signed unary bitwise inversion is likewise compared at both words.
Non-overflowing signed negation results are compared at both words, while exact
machine-code checks cover the shared overflow trap.
Wide bitwise operations are compared at both words across zero, extrema,
all-ones, and mixed-bit inputs.
Non-overflowing unsigned and signed addition is compared across both words;
machine-code tests require the shared overflow trap.
Non-overflowing unsigned and signed subtraction is compared across both words,
including low-word borrow cases.
Unsigned equality and signed inequality are compared with the pinned oracle at
equal values and values differing in either word.
Exact `u128::MAX`, `i128::MAX`, and `i128::MIN` literal
words are also compared with the same oracle. This is not linker, dynamic-loader,
cross-language, or physical-hardware evidence.

Arrays, tuples, user aggregates, and indirect returns are not admitted. This
checkpoint also does not establish that existing
`extern "C"` tests with Rust-specific types are C-compatible; those boundaries
require a separate fail-closed validation and test migration.
