# MRML Rust oracle generation 0002

## Identity

- rustup toolchain: `nightly-2026-08-24`
- rustc version: `rustc 1.100.0-nightly`
- full commit: `fb6531d550e0075b9eb9a51464f404805eec87d9`
- source/build date: `2026-08-23`
- MRML verification date: `2026-08-25`
- verified host: `x86_64-pc-windows-gnullvm`
- LLVM version: `23.1.0`
- edition/default behavior: MRML probes use Rust 2024 syntax where applicable;
  individual mapped upstream tests retain their own declared/default edition.

This exact dated nightly is the repository's default upstream build toolchain
and current behavioral oracle. ORACLE-0001 remains an immutable prior generation.
Neither record promises compatibility with every behavior of its compiler.

## Relevant feature state

- Polonius: no complete Polonius compatibility claim is established; the MRML
  corpus covers only its independently implemented and documented borrowing
  subset.
- trait solver: no complete next-generation trait-solver compatibility claim is
  established.
- unstable features: only features exercised by independently authored MRML
  source and probes are adopted; the nightly as a whole is not an MRML contract.
- unsupported borrowing, trait, provenance, unsafe, ABI, assembly, const, or
  metadata behavior continues to fail closed as documented.

## Delta from ORACLE-0001

ORACLE-0001 used rustc commit
`f7d782a3be46d6bb4b9792fe69a61db389ba1769` from 2026-08-19. Generation 0002
advances the default to the nightly distributed on 2026-08-24. The existing
MRML compiler corpus passed unchanged on the verified Windows gnullvm host; no
corpus-visible semantic or diagnostic delta was observed. This is bounded
evidence, not a claim that the upstream compilers are globally equivalent.

## Conformance result

All 767 `mrml-rustc` and `mrml-rustc-driver` tests passed on Windows gnullvm.
Clippy with warnings denied also passed. A previous Arch Linux release build of
the same rustc commit crashed in LLVM `PromotePass`; Linux is therefore recorded
as a toolchain regression/blocker, not passing oracle evidence. The default pin
does not convert that failure into a cross-host support claim.

Generation 0002 is accepted as the current build/oracle for the documented
subset on the verified host. Future generations must preserve both prior
records, rerun the corpus, classify observed deltas, and retain independently
authored regression probes.

## Naked-assembly option follow-up

On 2026-08-26, an independently authored Rust 2024 probe against this exact
oracle compiled `naked_asm!("ud2")`, `options(raw)`, and
`options(att_syntax)` with `rustc --edition 2024 --emit metadata`. A separate
probe invocation rejected `noreturn`, `nomem`, `nostack`, `preserves_flags`,
and `pure` as options that cannot be used with `naked_asm!`. MRML admits `raw`
and implements a distinct bounded AT&T operand grammar when `att_syntax` is
selected; unsupported options fail closed. These are
black-box syntax/validation observations, not copied upstream source or tests,
and do not establish general inline-assembly compatibility.

## Component-interface follow-up

On 2026-08-25, the canonical native MRML action added and passed one independently
authored component-interface probe on Windows gnullvm and Arch Linux. Pinned
upstream rustc executed the explicit Zstd ABI-3 generation/operation/size
identity check, while `mrml-rustc` emitted nonempty COFF and ELF objects for the
same bounded scalar projection. The full core action passed 420 library, one
component-interface, 10 conformance, and 335 nightly-replacement tests on each
host. This does not revise the earlier Linux release-build regression, claim
full binding-source compatibility, compare object semantics byte-for-byte, or
make Rust/C ABI part of the stable MRML interface.

## Inline-assembly validation follow-up

On 2026-08-26, independently authored Rust 2024 metadata-only probes against
the exact `nightly-2026-08-24-x86_64-pc-windows-gnullvm` oracle compiled a
fixed `asm!("nop")` template with `nomem`, `nostack`, and `preserves_flags`; a
named `inout(reg)` operand referenced from the template; and explicit
`in("rax")` plus `lateout("rax")` operands. A separate probe invocation rejected
`pure` without `nomem` or `readonly` and without an output, rejected combined
`readonly` and `nomem`, and rejected `rsp` as an explicit operand register.
These are black-box syntax and validation observations from original probes,
not copied upstream source or tests. They establish neither general inline-
assembly compatibility nor permission to omit MRML's independent bounded
register, option, template, clobber, control-flow, and safety validation.

An additional independently authored metadata-only probe on the same date and
exact commit compiled output-bearing named `inout(reg)` forms with
`options(pure, nomem)`, `options(pure, readonly)`, and standalone
`options(readonly)`. Separate invocations rejected `pure` without `nomem` or
`readonly`, rejected `pure, nomem` on an input-only form because it had no
output, and rejected `pure, nomem, readonly` because `nomem` and `readonly` are
mutually exclusive. Temporary probe sources and metadata were removed after
recording the black-box outcomes.

A further independently authored metadata-only probe against the same exact
commit compiled a two-operand named template with one `inout(reg)` and one
`in(reg)` operand and compiled `asm!("nop", clobber_abi("C"))`. Separate
invocations rejected a duplicate named operand, an unknown `clobber_abi`, and a
generic register-class output combined with `clobber_abi("C")`, which requires
explicit output registers. Temporary probe sources and metadata were removed.

An independently authored Rust 2024 metadata-only probe on 2026-08-26 against
the same `nightly-2026-08-24-x86_64-pc-windows-gnullvm` toolchain and exact
`fb6531d550e0075b9eb9a51464f404805eec87d9` commit compiled a named
`inout(reg)` operand whose place was the second `u64` field of a mutable tuple.
This establishes only the black-box acceptance of that projected operand shape;
it does not establish general place, register-allocation, or assembly semantics.
Temporary probe source and metadata were removed after recording the outcome.

A subsequent independently authored metadata-only probe against that same
toolchain and commit compiled a named `inout(reg)` whose `u64` input was distinct
from its output place, with the output written to the second `u64` field of a
mutable tuple. This records only exact black-box acceptance of split projected
output syntax and does not establish general projected-place or assembly
semantics. Temporary probe source and metadata were removed.

Another independently authored Rust 2024 metadata-only probe against the same
exact toolchain and commit compiled three explicit RAX forms whose output was
`values[1]` for a mutable `[u64; 2]`: `lateout`, same-place `inout`, and a
distinct-input `inout`. This is exact black-box acceptance evidence for those
constant array-element output shapes only, not for dynamic indexing, general
places, register allocation, or assembly semantics. Temporary source and
metadata were removed.

An independently authored Rust 2024 metadata-only probe against this exact
toolchain and commit accepted a mutable-reference forwarding callee whose local
alias was directly reassigned through `&mut *alias`, plus a caller that reused the
owner after the returned child's last use. A separate invocation rejected a
competing mutable owner borrow while that child remained live with E0499. This is
black-box evidence for that exact straight-line reassigned-alias shape, not
general interprocedural dataflow or region inference. Temporary sources and
metadata were removed.

An independently authored Rust 2024 metadata-only probe against this exact
toolchain and commit accepted a mutable-reference forwarding callee whose local
alias was reassigned through `&mut *alias` in both exhaustive conditional
branches, plus a caller that reused the owner after the returned child's last
use. A separate invocation rejected a competing mutable owner borrow while that
child remained live with E0499. This is black-box evidence for that exact equal-
origin conditional reassignment shape, not general branch dataflow, alias
analysis, or region inference. Temporary sources and metadata were removed.

An independently authored Rust 2024 metadata-only probe against this exact
toolchain and commit accepted a mutable-reference forwarding callee whose local
alias was repeatedly reassigned through `&mut *alias` in a `while` body, plus a
caller that reused the owner after the returned child's last use. A separate
invocation rejected a competing mutable owner borrow while that child remained
live with E0499. This is black-box evidence for that exact stable-origin loop
shape, not general loop dataflow, alias analysis, or region inference. Temporary
sources and metadata were removed.

An independently authored Rust 2024 metadata-only probe against this exact
toolchain and commit accepted a mutable-reference forwarding callee that created
an `&mut` alias inside each conditional branch and assigned that branch-local
alias into the returned outer local. The caller could reuse the owner after the
returned child's last use. A separate invocation rejected a competing mutable
owner borrow while that child remained live with E0499. This is black-box
evidence for that exact branch-local alias shape, not arbitrary branch dataflow,
nested projections, or region inference. Temporary sources and metadata were
removed.

An independently authored Rust 2024 metadata-only probe against this exact
toolchain and commit accepted a mutable-reference forwarding callee with a
branch-local alias returned early from one conditional arm and a parameter-
backed alias returned from the tail. The caller could reuse the owner after the
returned child's last use. A separate invocation rejected a competing mutable
owner borrow while that child remained live with E0499. This is black-box
evidence for that exact branch-local early-return shape, not general control-flow
or region inference. Temporary sources and metadata were removed.

An independently authored Rust 2024 metadata-only probe against this exact
toolchain and commit accepted a mutable-reference forwarding callee whose
`while` body created an iteration-local `&mut` alias and assigned it into the
returned outer local. The caller could reuse the owner after the returned
child's last use. A separate invocation rejected a competing mutable owner
borrow while that child remained live with E0499. This is black-box evidence for
that exact loop-local alias shape, not general loop fixed-point, path-sensitive,
or region analysis. Temporary sources and metadata were removed.

An independently authored Rust 2024 metadata-only probe against this exact
toolchain and commit accepted a mutable-reference forwarding callee whose loop
contained a conditional arm that created a local `&mut` alias and returned it,
an `else` return of the parameter, and a zero-iteration parameter tail. The
caller could reuse the owner after the returned child's last use. A separate
invocation rejected a competing mutable owner borrow while that child remained
live with E0499. This is black-box evidence for that exact loop-arm local-return
shape, not general loop dataflow or region inference. Temporary sources and
metadata were removed.

An independently authored Rust 2024 metadata-only probe against this exact
toolchain and commit accepted a mutable-reference forwarding callee whose nested
loop declared a local `&mut` alias and conditionally returned it. The caller
could reuse the owner after the returned child's last use. A separate invocation
rejected a competing mutable owner borrow while that child remained live with
E0499. This is black-box evidence for that exact nested-loop local-return shape,
not a general nested-loop fixed point, path-sensitive analysis, or region
inference. Temporary sources and metadata were removed.

An independently authored Rust 2024 metadata-only probe against this exact
toolchain and commit accepted a mutable scalar reference returned from index
zero of a mutable two-element array-reference parameter. The caller could reuse
that indexed place after the returned child's last use. A separate invocation
rejected a competing mutable borrow of the same indexed place while the child
remained live with E0499. This is black-box evidence for that exact indexed
array-reference shape, not general aggregate or index-sensitive alias analysis.
Temporary sources and metadata were removed.

Projected local-alias probes against the same oracle accepted an array-element
alias, a slice-subslice alias, and owner access after the returned alias's last
use. A live competing array-element borrow was rejected with E0499. MRML's
standalone callee-origin proof additionally rejects an explicit alias annotation
that differs from the declared return type.

A follow-up reassignment probe accepted replacing one `&mut u16` alias with
another indexed `&mut u16` and rejected assigning `&mut u16` into an explicitly
typed `&mut [u16]` alias, then returning it as `&mut u16`, with two E0308
diagnostics. MRML retains the explicit compatibility bit so its standalone
origin proof rejects the same transfer without relying on later codegen.

The inferred form produced the same result: replacing an inferred indexed
`&mut u16` alias with another indexed scalar reference was accepted, while an
inferred `&mut [u16]` alias assigned an indexed `&mut u16` and returned as that
scalar reference was rejected with two E0308 diagnostics.

Bounded local-type-state probes accepted returning an inferred alias that began
at local `u16` storage and was then replaced by an indexed parameter reference,
both directly and after both arms of an `if` replaced it. A separate probe
rejected initializing an explicitly scalar mutable-reference alias from a
mutable subslice with E0308.

A projected mutable-to-shared return probe accepted a callee local declared as
`&mut u16` and returned as `&u16`, plus caller mutation after the result's last
use. The corresponding live caller mutation was rejected with E0503.

The fat-reference variant accepted a mutable subslice passed through mutable
and shared slice locals and returned as `&[u16]`, followed by mutation after its
last indexed use. Mutating the same owner before that indexed use was rejected
with two E0503 diagnostics.

Assignment-direction probes accepted replacing a shared alias with an indexed
mutable reference and rejected assigning a shared reference into a mutable
alias with E0308. MRML performs that check inside callee-origin transfer.

An independently authored Rust 2024 metadata-only probe against this exact
toolchain and commit separately accepted a mutable scalar reference returned
from index zero of a mutable slice-reference parameter, followed by owner reuse
after the child's last use. A separate invocation rejected a live mutable borrow
of the same indexed slice place with E0499 and E0503. This is direct black-box
slice evidence rather than an inference from the fixed-array probe; it does not
establish subslice or disjoint-index alias analysis. Temporary sources and
metadata were removed.

Independent Rust 2024 metadata-only probes against this exact toolchain and
commit accepted mutable slice references returned from `[1..]` of both a mutable
two-element array-reference parameter and a mutable slice-reference parameter,
followed by owner access after the returned subslice's last use. Separate
invocations rejected a live mutable borrow of element one with E0499 in both
cases and E0503 additionally for the slice. This is black-box evidence for those
exact subslice shapes, not general range-disjointness or region inference.
Temporary sources and metadata were removed.

An independently authored Rust 2024 metadata-only probe against the same exact
toolchain and commit compiled three explicit RAX forms whose output place was
`*target` for `target: &mut u64`: `lateout`, same-place `inout`, and a distinct-
input `inout`. This records black-box acceptance of those exact mutable-
reference dereference shapes only; it does not establish general pointer,
memory-effect, place, register-allocation, or assembly semantics. Temporary
source and metadata were removed.

An independently authored Rust 2024 metadata-only probe against the same exact
toolchain and commit compiled `values[index]` output places for a mutable
`[u64; 2]` and runtime `usize` parameter in explicit RAX `lateout`, same-place
`inout`, and distinct-input `inout` forms. This establishes black-box acceptance
of those exact dynamic-index shapes only, not evaluation order for effectful
index expressions, general place semantics, register allocation, memory effects,
or general assembly. Temporary source and metadata were removed.

A follow-up independently authored Rust 2024 metadata-only probe against that
same exact toolchain and commit compiled explicit RAX `lateout`, same-place
`inout`, and distinct-input `inout` outputs indexed respectively by `index % 2`,
`(index + 1) % 2`, and `index`. This records black-box acceptance of those exact
expression-indexed output shapes only; it does not establish general expression,
evaluation-order, place, register-allocation, memory-effect, or assembly
semantics. Temporary source and metadata were removed.

An independently authored Rust 2024 metadata-only probe against that same exact
toolchain and commit compiled `asm!("cmp rcx, rcx", in("rcx") value,
options(nomem, nostack))`. This records black-box acceptance of that exact
explicit-RCX input form only; it does not establish other registers, allocation,
effects, or general assembly semantics. Temporary source and metadata were
removed.

An independently authored Rust 2024 metadata-only probe against that same exact
toolchain and commit compiled fixed RDX `in("rdx")`, stored and discarded
`lateout("rdx")`, same-place `inout("rdx")`, and distinct-input
`inout("rdx")` forms. This records black-box acceptance of those five exact
fixed-template forms only; it does not establish other registers, general
allocation, effects, or general assembly semantics. Temporary source and
metadata were removed.

A later independently authored Rust 2024 metadata-only probe against that same
exact toolchain and commit compiled explicit input forms for RSI, RDI, and R8
through R15. A focused follow-up compiled low-register and R15 inputs plus
stored/discarded R15 outputs and same-place/distinct-input R15 inout. A separate
probe invocation rejected RBX because LLVM reserves it, RSP because it is the
stack pointer, and RBP because it is the frame pointer. This is black-box
admission evidence for those exact registers and forms only, not general
register allocation or assembly semantics. Temporary sources and metadata were
removed.

Another independently authored Rust 2024 metadata-only probe against that same
exact toolchain and commit compiled explicit RAX `lateout`, same-place `inout`,
and distinct-input output forms whose destinations indexed a `&mut [u64; 2]`
parameter with a runtime `usize` expression. This records black-box acceptance
of those exact mutable fixed-array-reference output shapes only; it does not
establish general nested-place, borrowing, evaluation-order, register-allocation,
memory-effect, or assembly semantics. Temporary source and metadata were
removed.

An independently authored Rust 2024 metadata-only probe against that same exact
toolchain and commit compiled `asm!("mov rax, 7", lateout("rax") _)`. This
records black-box acceptance of that exact discarded explicit-output form only;
it does not establish other clobbers, register allocation, effects, or general
assembly semantics. Temporary source and metadata were removed.

Another independently authored Rust 2024 metadata-only probe against that same
exact toolchain and commit compiled `asm!("mov rcx, 7", lateout("rcx") value)`
and the corresponding discarded `_` output. This records black-box acceptance
of those exact RCX output forms only; it does not establish other registers,
register allocation, effects, or general assembly semantics. Temporary source
and metadata were removed.

A subsequent independently authored Rust 2024 metadata-only probe against that
same exact toolchain and commit compiled explicit RAX `lateout`, same-place
`inout`, and distinct-input output forms whose destinations indexed a mutable
`[u64]` slice parameter with `index % 2` or `index`. This records black-box
acceptance of those exact mutable-slice output shapes only; it does not establish
general unsized-place, borrowing, evaluation-order, register-allocation, memory-
effect, or assembly semantics. Temporary source and metadata were removed.

An independently authored Rust 2024 metadata-only probe against that same exact
toolchain and commit compiled `asm!("inc rcx", inout("rcx") value)` and
`asm!("inc rcx", inout("rcx") input => output)`. This records black-box
acceptance of those exact same-place and split explicit-RCX inout forms only; it
does not establish other registers, allocation, effects, or general assembly
semantics. Temporary source and metadata were removed.
