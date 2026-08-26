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

An independently authored Rust 2024 metadata-only probe on 2026-08-26 against
this exact toolchain and commit rejected mutation through a mutable-reference
parameter after a shared-reference local was assigned from that parameter and
used later, reporting E0506. A conditional shared reference selecting either of
two exact mutable tuple fields rejected direct mutation of the first owner with
E0503. Moving the shared child's last use before the direct parameter mutation
compiled successfully. These are black-box observations for those exact
straight-line and conditional shapes, not evidence of general region behavior.
Temporary probe sources and metadata were removed.

Another independently authored Rust 2024 metadata-only probe against this exact
toolchain and commit formed two successive mutable local reborrows from an
incoming mutable-reference parameter and then a shared grandchild. Directly
mutating the incoming owner while that grandchild was used later failed with
E0503; moving the grandchild's last use before the mutation compiled. This is
black-box evidence for that exact three-level chain, not general region
inference. Temporary probe sources and metadata were removed.

An independently authored Rust 2024 metadata-only probe against this exact
toolchain and commit initialized a mutable parent from one parameter, optionally
reassigned it from a second parameter, and then formed a shared child. Separate
invocations rejected direct mutation of the initializer owner and replacement
owner with E0503 while the child was used later. A control that used the child
before mutating both owners compiled. This is exact black-box evidence for the
bounded conditional join, not general path-sensitive regions. Temporary probe
sources and metadata were removed.

An independently authored Rust 2024 metadata-only probe against this exact
toolchain and commit initialized a mutable parent before a `while`, optionally
reassigned it from a second parameter immediately before `break`, and formed a
shared child after the loop. Separate invocations rejected direct mutation of
the pre-loop and loop-assigned owners with E0503 while the child was used later.
A control used the child before mutating both owners and compiled. This is exact
black-box evidence for the bounded single-exit loop shape, not a general loop
fixed point. Temporary probe sources and metadata were removed.

An independently authored Rust 2024 metadata-only probe against this exact
toolchain and commit passed a mutable-reference parameter through a direct
identity function and through a conditional function whose two returns were the
same parameter. Each returned mutable reference was reborrowed into a shared
child. Direct mutation of the original parameter while the child was used later
failed with E0503 in both cases; moving the child's last use before mutation
compiled. This is exact black-box evidence for those two call shapes, not
general interprocedural regions. Temporary probe sources and metadata were
removed.

An independently authored Rust 2024 metadata-only probe against this exact
toolchain and commit returned a shared child of a mutable reference obtained
from both a direct identity function and a conditional same-parameter function.
Both parameter-backed caller returns compiled. Equivalent callers that passed a
local into each function and returned its shared child failed with E0515. This
is exact black-box outlives evidence for those call shapes, not general
interprocedural lifetime inference. Temporary probe sources and metadata were
removed.

A follow-up independently authored Rust 2024 metadata-only probe against this
exact toolchain and commit returned the shared child of an exhaustive projected
callee result through an explicit return and a conditional early-return plus
tail-return join. Parameter-backed forms compiled. Matching local-backed forms
failed with E0515 at the explicit and conditional return sites. The oracle-only
callee retained the explicit `'a: 'b` relationship required by tuple-field
replacement. This is evidence for those exact sites, not general
interprocedural lifetime inference. Temporary sources and metadata were removed.

Another independently authored Rust 2024 metadata-only probe against this exact
toolchain and commit returned that projected callee result's shared child from
direct and conditional sites inside `loop` blocks. Both parameter-backed forms
compiled. Matching loop-local forms failed with E0515 at their return sites.
The oracle-only callee retained the explicit `'a: 'b` relationship required by
tuple-field replacement. This is evidence for those exact loop-return shapes,
not a general loop or region fixed point. Temporary sources and metadata were
removed.

A nested-loop follow-up against this exact toolchain and commit compiled an
exhaustive inner return of the projected callee result's shared child when the
second argument was parameter-backed. The matching inner-loop-local argument
failed with E0515 at the conditional return. The oracle-only callee retained
the explicit `'a: 'b` relationship required by tuple-field replacement. This
is evidence for that exact nested terminal shape, not a general loop or region
fixed point. Temporary sources and metadata were removed.

A follow-up invocation compiled the same projected call inside a nonterminal
nested-loop path. On the path that did not return, both mutable-reference
arguments were available for the next iteration through Rust's implicit call-
argument reborrows. This is exact evidence for direct reference places passed to
those reference-typed parameters, not general call coercion or region inference.
Temporary source and metadata were removed.

A separate invocation kept the projected result live and attempted a competing
mutable borrow of the non-origin first argument. This exact toolchain rejected
the second borrow with E0499 because the first argument's call reborrow remained
live through the later result use. Together these probes distinguish returned-
pointer origin from the lifetime of every reference argument loan. Temporary
source and metadata were removed.

Another independently authored invocation passed function-local storage as the
non-origin first argument and a parameter as the returned-origin second
argument, then attempted to return a shared child of the result. This exact
toolchain rejected the return with E0515 because the first argument's loan still
referenced local storage. This is exact evidence that result pointer ancestry
does not erase non-origin argument lifetime constraints. Temporary source and
metadata were removed.

The complementary invocation copied the result pointee, ended the result's last
use, and then mutated the non-origin local. This exact toolchain compiled the
case, confirming non-lexical release rather than permanent consumption of the
local argument. Temporary source and metadata were removed.

An independently authored conditional-argument pair passed the same mutable
parameter from both `if` arms to an identity callee. This exact toolchain
accepted mutation after copying the result pointee and rejected a competing
mutable borrow before the result's later use with E0499. This is exact evidence
for expected-reference reborrows across that conditional join, not general call
coercion or region inference. Temporary sources and metadata were removed.

A distinct-owner follow-up selected the first or second mutable parameter in
the two conditional argument arms. This exact toolchain rejected direct access
to either possible owner before a later result use with E0503, then compiled a
separate case that copied the result and mutated both owners afterward. This is
exact evidence for the joined loan set and its last-use release, not general
path-sensitive regions. Temporary sources and metadata were removed.

An independently authored escape pair returned a shared child of an identity
call whose argument conditionally selected two parameters or selected a
parameter and function-local storage. This exact toolchain compiled the all-
parameter case and rejected the mixed local case with E0515. This is exact
evidence for the bounded conditional call-result origin join, not general
interprocedural region inference. Temporary sources and metadata were removed.

An independently authored scalar `shared_identity(&u16) -> &u16` probe kept the
returned shared reference live across a competing mutable owner borrow. This
exact toolchain rejected the borrow with E0502. A companion copied the pointee
before mutating the owner and compiled successfully. This is exact shared-call
loan-liveness evidence, not general call or region inference. Temporary sources
and metadata were removed.

An independently authored Rust 2024 metadata-only probe against this exact
toolchain and commit returned call-derived shared children through an explicit
return and through a conditional early-return plus tail-return path. Both
parameter-backed forms compiled. Equivalent local-backed forms failed with
E0515 at the explicit and conditional return sites. This is exact black-box
evidence for those return shapes, not general region inference. Temporary probe
sources and metadata were removed.

An independently authored Rust 2024 metadata-only probe against this exact
toolchain and commit returned call-derived shared children from direct and
conditional sites inside `loop` blocks. Both parameter-backed forms compiled.
Equivalent loop-local forms failed with E0515. This is exact black-box evidence
for those loop-return shapes, not a general loop or region fixed point.
Temporary probe sources and metadata were removed.

An independently authored Rust 2024 metadata-only probe against this exact
toolchain and commit defined straight-line and exhaustive conditional callees
that initialized a one-element mutable-reference tuple from a first parameter,
replaced its field with a second parameter, and returned that field. Shared
children of both call results compiled when the second argument was parameter-
backed. Equivalent calls supplied with function-local storage failed with E0515
at the shared-child return. The explicit `'a: 'b` relationship needed by the
tuple replacement was part of the oracle-only function signatures. This is
black-box evidence for these exact projected call-return shapes, not general
interprocedural lifetime inference. Temporary probe sources and metadata were
removed.

## Straight-line tuple-field callee-origin follow-up

On 2026-08-26, an independently authored Rust 2024 metadata-only probe against
this exact toolchain and commit accepted a mutable-reference callee that
initialized a one-element tuple field from one parameter, replaced that field
with a second parameter, returned the field, and allowed the second owner to be
reborrowed after the returned child's last use. A separate invocation rejected
a competing mutable borrow of the second owner while that child remained live
with E0499. The oracle rejected with E0515 a superficially similar callee whose
field was initialized from local storage before parameter replacement. MRML
therefore admits only the exact parameter-backed straight-line replacement and
continues to reject the local-backed divergence. Temporary probe sources and
metadata were removed. This is black-box evidence for that bounded shape, not
general aggregate dataflow, conditional joins, loops, or region inference.

An additional independently authored Rust 2024 metadata-only probe against the
same exact toolchain and commit accepted exhaustive conditional arms that each
replaced a one-element mutable-reference tuple field from a first parameter to
the same second parameter. The caller could reborrow the second owner after the
returned child's last use. A separate invocation rejected a competing mutable
borrow of that owner while the child remained live with E0499. Temporary probe
sources and metadata were removed. This records only the exact equal-origin
conditional replacement, not general aggregate dataflow or region inference.

A further independently authored Rust 2024 metadata-only probe against the same
exact toolchain and commit accepted a tuple field replaced from a first mutable-
reference parameter to a second before a `while`, then identity-reborrowed from
that field in the loop body. The caller could reborrow the second owner after
the returned child's last use. A separate invocation rejected a competing
mutable borrow while that child remained live with E0499. Temporary probe
sources and metadata were removed. This records only that stable zero/one-
iteration origin shape, not a general loop fixed point or region inference.

Another independently authored Rust 2024 metadata-only probe against the same
exact toolchain and commit accepted direct return of a one-element tuple field
initialized from a mutable-reference parameter. It also accepted initializing
that field from the parameter before a `while`, identity-reborrowing the field
in the loop, and reborrowing the owner after the returned child's last use. A
separate invocation rejected a competing mutable owner borrow while the direct
returned child remained live with E0499. Temporary sources and metadata were
removed. This records only exact tuple-literal parameter origins, not general
aggregate initialization, loop fixed points, or region inference.

A subsequent independently authored Rust 2024 metadata-only probe against the
same exact toolchain and commit accepted a two-field mutable-reference tuple
whose second element selected the same second parameter in both conditional
arms, then returned that second field. The caller could reuse the second owner
after the returned child's last use. A separate invocation rejected a competing
mutable borrow while the child remained live with E0499. Temporary sources and
metadata were removed. This is exact equal-origin conditional initializer
evidence, not arbitrary aggregate or path-sensitive origin inference.

Another independently authored Rust 2024 metadata-only probe against the same
exact toolchain and commit accepted consuming a parameter-initialized tuple
field into an explicitly typed mutable-reference local before return. It also
accepted the corresponding moved alias from an equal-origin conditional second
field and allowed owner reuse after the returned child's last use. A separate
invocation rejected a live competing mutable owner borrow with E0499. Temporary
sources and metadata were removed. This is exact one-move projected-origin
evidence, not general aggregate moves, aliases, or region inference.

A further independently authored Rust 2024 metadata-only probe against the same
exact toolchain and commit accepted two successive consuming mutable-reference
locals after a parameter-initialized tuple field. It also accepted one consuming
local after exhaustive equal-origin field assignment and after a stable loop
field self-reborrow, and permitted owner reuse after the returned child's last
use. A separate invocation rejected a competing owner borrow while the two-move
chain result remained live with E0499. Temporary sources and metadata were
removed. This is bounded move-chain evidence, not general alias or region
inference.

Another independently authored Rust 2024 metadata-only probe against the same
exact toolchain and commit accepted creating a one-field mutable-reference tuple
inside each exhaustive conditional arm and assigning that field into an outer
alias before return. A separate invocation rejected a live competing borrow of
the shared parameter owner with E0499. A third probe rejected with E0515 a later
local-backed tuple return after those branch-local slots ended. Temporary sources
and metadata were removed. This is exact scoped-origin evidence, not general
lexical-region or alias inference.

Another independently authored Rust 2024 metadata-only probe against the same
exact toolchain and commit accepted creating an iteration-local one-field tuple
from an identity reborrow of an outer mutable-reference alias and assigning that
field back into the alias in a `while`. The caller could reuse the owner after
the returned child's last use. Separate invocations rejected a live competing
owner borrow with E0499 and a loop-local tuple borrowing function-local storage
with E0515. Temporary sources and metadata were removed. This is one stable
zero/one-iteration origin join, not general loop or region inference.

Another independently authored Rust 2024 metadata-only probe against the same
exact toolchain and commit accepted creating a one-field mutable-reference tuple
from a branch-local alias reborrow inside a `while` conditional block, assigning
the field back into that alias, and immediately returning it. The caller could
reuse the owner after the returned child's last use. Separate invocations
rejected a live competing owner borrow with E0499 and a branch tuple borrowing
function-local storage with E0515. Temporary sources and metadata were removed.
This is exact projected assignment before a loop-branch return, not general loop
dataflow, alias, or region inference.

A further independently authored Rust 2024 metadata-only probe against the same
exact toolchain and commit accepted the same alias-reborrow tuple-field transfer
inside a nested loop before a conditional return, and accepted owner reuse after
the returned child's last use. Separate invocations rejected a live competing
owner borrow with E0499 and a function-local backing store with E0515. Temporary
sources and metadata were removed. This is nested projected-return evidence, not
nested fixed-point, alias, or region inference.

Another independently authored Rust 2024 metadata-only probe against the same
exact toolchain and commit assigned one of two explicit mutable-reference tuple
field reborrows into an existing mutable-reference local. Separate invocations
rejected mutation of the first and second possible owners while the selected
child remained live with E0499. A passing invocation for each owner accepted
reuse after the child's last use. Temporary sources and metadata were removed.
This is conditional exact projected-loan evidence, not general path-sensitive
alias or region inference.

A follow-up independently authored Rust 2024 metadata-only probe against the
same exact toolchain and commit overwrote a mutable-reference tuple field before
moving a child from it. The oracle rejected use of the original field owner with
E0503 and a live competing borrow of the replacement owner with E0499. Separate
passing functions used the child first and then reused each owner. Temporary
sources and metadata were removed. This is exact multi-generation tuple-field
evidence, not general aggregate history or region inference.

Another independently authored Rust 2024 metadata-only probe against the same
exact toolchain and commit created a mutable grandchild reborrow through a child
moved from an exact tuple field. The oracle rejected a competing mutable borrow
of the ultimate parameter owner with E0499 while the grandchild remained live,
and accepted owner reuse after the grandchild's last use. Temporary sources and
metadata were removed. This is bounded projected ancestry evidence, not general
region inference.

Another independently authored Rust 2024 metadata-only probe against the same
exact toolchain and commit passed an exact tuple-field mutable reborrow through
an identity function and assigned the result into an existing mutable-reference
local. The oracle rejected a competing mutable borrow of the ultimate owner with
E0499 while the assigned child remained live, and accepted owner reuse after its
last use. Temporary sources and metadata were removed. This is exact projected
call-result ancestry evidence, not general call-summary or region inference.

A follow-up independently authored Rust 2024 metadata-only probe against the
same exact toolchain and commit passed a conditional choice between two mutable-
reference tuple fields through the identity call before assigning its result.
The oracle rejected live use of the first and second possible owners with E0503
and accepted reuse of each after the assigned child's last use. Temporary
sources and metadata were removed. This is bounded conditional projected-call
evidence, not general path-sensitive interprocedural region inference.

Another independently authored Rust 2024 metadata-only probe against the same
exact toolchain and commit passed an exact mutable-reference tuple field to a
shared `read` function while a mutable child reborrowed from that field remained
live. The oracle rejected the overlapping call with E0502 and accepted the call
after the child's last use. Temporary sources and metadata were removed. This is
projected call-scoped invalidation evidence, not general interprocedural regions.

A complementary independently authored Rust 2024 metadata-only probe against
the same exact toolchain and commit passed an exact mutable-reference tuple field
to a mutable `touch` function while a shared child of that field remained live.
The oracle rejected the overlapping call with E0502 and accepted it after the
shared child's last use. Temporary sources and metadata were removed. This is
exact projected mutable-call invalidation evidence, not general regions.

Another independently authored Rust 2024 metadata-only probe against the same
exact toolchain and commit assigned mutable-reference tuple fields into explicit
shared-reference locals, both directly and through a conditional field choice.
The oracle rejected direct use of the exact owner and each conditional owner
with E0503 while the shared child remained live, and accepted owner reuse after
the child's last use. Temporary sources and metadata were removed. This is exact
mutable-to-shared projected-coercion evidence, not general region inference.

Another independently authored Rust 2024 metadata-only probe against the same
exact toolchain and commit accepted assigning a parameter-backed tuple field
into an existing mutable-reference local and returning that local. The same
probe accepted an inferred alias initially moved from a local-backed tuple field,
then replaced by a parameter reference before return. The caller could reuse the
projected owner after the returned child's last use. A separate invocation
rejected a live competing owner borrow with E0499. Temporary sources and metadata
were removed. This is exact typed projected-assignment evidence, not general
assignment, alias, or region inference.

Another independently authored Rust 2024 metadata-only probe against the same
exact toolchain and commit accepted assigning the same parameter-backed tuple
field into a root mutable-reference alias in both exhaustive conditional arms.
It also accepted initializing that alias from an identity reborrow of the field
and repeating the same assignment in a `while`, then permitted owner reuse after
the returned child's last use. A separate invocation rejected a live competing
projected-owner borrow with E0499. Temporary sources and metadata were removed.
This is exact equal-origin control-flow evidence, not general alias or region
inference.

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
