# MRML Rust compiler direction

This document records the durable architectural direction for `mrml-rustc`.
Implementation status remains grounded in current source, tests, and native
evidence; this roadmap does not promote planned work to implemented work.
The concise, commit-addressed recovery state is maintained in
[`compiler/CHECKPOINT.md`](compiler/CHECKPOINT.md); update it after every pushed
compiler milestone.

## Identity and compatibility objective

`mrml-rustc` is an original MRML Rust compiler implementation targeting
contemporary and forward-looking Rust semantics, with MRML-specific security
and systems integration. It is not a Rust-inspired replacement language and it
does not claim complete Rust compatibility.

Rust 2024 is the language floor and an historical architectural baseline, not
the destination. Prefer a modern or future successor semantic over obsolete
edition behavior, historical unsoundness, compiler quirks, or implementation
accidents unless current MRML source or a required conformance dependency needs
the legacy behavior. Do not deliberately diverge from modern Rust merely to be
different. Rust 2015, 2018, and 2021 compatibility, every historical nightly,
diagnostic wording, rustc query/MIR internals, LLVM accidents, ordinary Rust ABI,
and unstable symbol mangling are not standing compatibility obligations.

Observable language semantics are the compatibility target. Stable MRML/native
boundaries remain explicit and versioned. Supporting modern Rust syntax does not
make rustc's unstable native ABI the MRML application ABI.

“Forward-looking” describes the semantic and roadmap direction; it is not an
instruction to replace the workspace manifest with Cargo's experimental
`edition = "future"` value. Keep the workspace on edition 2024 until a newer
named edition is intentionally adopted with a pinned toolchain, complete
workspace migration, and recorded oracle delta. An experimental edition that
requires per-package Cargo feature opt-ins is not a usable clean-install
baseline.

## Reproducible future-Rust oracles

The bootstrap and upgrade chain is:

```text
exact dated rustc nightly
        -> black-box semantic observation
        -> independently authored MRML conformance probe
        -> MRML-owned implementation
        -> differential native verification
```

An installed current nightly is never an oracle merely because it is available.
Each oracle generation records the rustc version, full commit, date, edition and
default behavior, Polonius state, trait-solver state, relevant unstable feature
state, MRML-relevant semantic deltas, and conformance outcome under
`docs/compiler/oracles/`. The initial record is
[ORACLE-0001](compiler/oracles/ORACLE-0001.md).

An oracle is a reproducible observation point, not a permanent compatibility
ceiling. To advance it:

1. retain all previous records and pin the candidate nightly exactly;
2. run the existing MRML corpus against both the previous and candidate oracle;
3. classify every difference as intended Rust evolution, bug fix, new feature,
   diagnostic-only change, temporary nightly regression, or unknown;
4. change MRML semantics only deliberately and preserve regression probes for
   accepted changes; and
5. record exact Windows and Linux outcomes without copying upstream compiler
   source or test bodies.

## Feature classification

Every considered upstream or MRML extension has one classification:

- **STABLE** — a normal contemporary compatibility target.
- **NIGHTLY-LIKELY-FUTURE** — actively evaluate and implement when useful and
  semantically mature.
- **EXPERIMENTAL** — observe and probe; do not adopt by default.
- **LEGACY** — implement only for a concrete MRML or conformance dependency.
- **MRML-SPECIFIC** — an independently specified platform/compiler security or
  systems extension.

Experimental syntax is not promoted because it appears in one nightly. Observe,
write a black-box probe when valuable, document the semantics, wait for direction
and stability, and implement only with a recorded justification. Type Alias Impl
Trait and Return Type Notation are **NIGHTLY-LIKELY-FUTURE** research targets;
future implicit default bounds and unsettled implementation/mutability
restrictions remain **EXPERIMENTAL** until their direction is clear. Individual
trait/type-system soundness fixes become **STABLE** compatibility targets once
settled or **NIGHTLY-LIKELY-FUTURE** earlier when their security value and oracle
stability justify adoption. Features with unclear dependencies or no MRML use
are **DEFERRED** roadmap items even when they remain visible as upstream
research.

## Post-Rust-2024 gap analysis

The following classifications describe the current compiler, not the upstream
language as a whole.

| Area | MRML status | Current evidence and important gap |
| --- | --- | --- |
| Rust 2024 semantic changes | **PARTIAL** | The workspace uses edition 2024; the parser accepts required unsafe attributes such as `#[unsafe(no_mangle)]` and a bounded unsafe-function/raw-pointer subset. General edition migration rules, unsafe extern/item rules, temporary lifetime changes, and complete 2024 pattern ergonomics are not implemented. |
| Let chains | **NOT IMPLEMENTED** | Boolean short-circuit expressions exist, but `if let`/`while let` chains and their pattern scopes do not. |
| Async closures | **NOT IMPLEMENTED** | There is no async/await, generator, future, or async-closure lowering. |
| Modern borrowing / Polonius | **NOT IMPLEMENTED** | References, reborrows, mutable pointee operations, and bounded mutability checks exist, but there is no ownership, move, loan, region, outlives, or control-flow borrow analysis. |
| Next-generation trait solving | **NOT IMPLEMENTED** | Method-like built-ins are recognized directly; there is no general trait declaration/implementation model, goal solver, canonicalization, projection, coherence, ambiguity, or cycle handling. |
| Naked functions / `naked_asm!` | **NOT IMPLEMENTED** | High-priority **STABLE** systems-language target. No implementation may insert an ordinary prologue or epilogue into a naked function. |
| Modern inline assembly | **NOT IMPLEMENTED** | No `asm!`, register/operand validation, options, clobber model, or architecture-specific assembly lowering exists. |
| Pointer/provenance APIs | **PARTIAL** | Raw-pointer casts, `addr`, `with_addr`, `expose_provenance`, integer-address reconstruction, offsets, comparisons, alignment, copying, writes, references, and metadata operations have bounded tests. The current scalar machine representation cannot establish a complete provenance/alias model and must not equate equal integer addresses with interchangeable provenance. |
| Modern const features | **PARTIAL** | Bounded deterministic scalar evaluation supports typed constants, const functions, conditionals, loops, locals, assignments, arrays, and many integer operations. General aggregate evaluation, ownership, traits, const safety, statics/layout queries, and contemporary const-trait behavior remain absent. |
| Modern integer APIs | **IMPLEMENTED** for a broad bounded subset | Checked, strict, wrapping, saturating, mixed-sign, endian, bit, logarithm, square-root, midpoint, next-multiple/power, and newer nightly bit-manipulation APIs have original tests and native evidence. This does not imply complete library compatibility. |
| Never-type improvements | **PARTIAL** | Structurally diverging inlined helpers and bounded never-to-supported-result coercion exist. General `!` inference, never parameters, public never ABI, and arbitrary divergence analysis do not. |
| Modern patterns and match | **PARTIAL** | Bounded scalar constant/range/wildcard patterns and limited matches exist. Destructuring, match ergonomics, guards and ownership-sensitive patterns are incomplete. |
| Modern unsafe rules | **PARTIAL** | Unsafe functions gate a bounded unchecked integer/raw-pointer subset and unsupported operations fail closed. General unsafe blocks, unsafe traits/impls, extern rules, assembly, provenance, and complete `unsafe_op_in_unsafe_fn` semantics are absent. |
| Modern `no_std` systems features | **PARTIAL** | Dependency-free native code generation covers integers, control flow, arrays, bounded scalar tuples, references, slices, raw pointers, COFF/ELF64, UEFI checks, and NVPTX checks. Assembly, naked entry points, atomics, SIMD, full ABI/layout, relocations, linking, and package compilation remain missing. |

Already implemented post-2024 or forward-looking work should be preserved rather
than reimplemented: unsafe attributes, broad modern integer APIs, modern raw
pointer address/provenance-facing APIs, bounded never coercion, and fixed-capacity
`no_std` compilation. Their documented limits remain binding.

## Ownership and Polonius-direction roadmap

The current borrowed-source AST and fixed-capacity expression arenas are useful
front ends, but the compiler is not yet architecturally ready for sound
Polonius-style checking. References currently lower directly to scalar/fat
runtime representations without an explicit ownership/place/loan IR. Build the
analysis incrementally:

1. define explicit place identities and projections independent of parser text;
2. add initialization and move-path analysis;
3. track shared loans;
4. track mutable loans and invalidation;
5. represent lexical and control-flow loan facts in a bounded CFG;
6. implement reborrow semantics;
7. add flow-sensitive region/outlives reasoning;
8. add independently authored Polonius-compatible accepted/rejected probes;
9. improve bounded diagnostics and source explanations; and
10. optimize fixed-capacity analysis memory and time only after semantics hold.

Study flow-sensitive loan reasoning, region/outlives relationships, borrow
invalidation, reborrowing, mutable aliasing, and control-flow-sensitive lifetime
behavior. Do not copy rustc internals or freeze temporary Polonius Alpha
implementation accidents as MRML language semantics.

The prerequisite refactor is a bounded typed body representation with stable
local/place IDs, projection lists, explicit reads/writes/moves/borrows, and basic
blocks/edges. Assignment targets now retain a source-independent base binding
plus one explicit direct, dereference, index, or numeric tuple-field projection;
index source and spans are captured once, and ambiguous non-numeric tuple
assignment projections fail closed. Runtime typing/emission still rediscovers
type information recursively. Runtime locals now receive checked monotonic IDs
that are not recycled after scope cleanup. Their name, type, mutability, and ID
remain in a fixed 256-entry fact table after the active stack slot is released.
Assignment writes resolve once to a typed local-ID/parameter base plus the
parsed projection before emission and append an ordered fact to a separate
fixed 256-entry table. Runtime identifier loads append `Read` facts to that
same table, including specialized tuple, array, range, and address paths that
bypass the scalar loader; constants do not acquire local/parameter identities.
Facts store up to four source-independent `Dereference`, `Index`, `TupleField`,
or `Subslice` projections. Assignment projections are translated once rather
than retained as parser objects; specialized local tuple-field, element-index,
and local-array range reads retain their actual projection. Validation walks
the list against the type produced by each preceding projection and rejects
holes, invalid type transitions, out-of-range fields, and capacity overflow.
The resolved place also classifies access intent as `Write` or
`ReadModifyWrite`; every supported direct, tuple-field, fixed-array,
reference-array, slice, and dereference assignment family uses that fact to
decide whether the previous value is read. Final emission validates contiguous
local identities, referenced local/parameter types, projection/type shape,
binding mutability, and the absence of holes in the ordered access facts.
Capacity exhaustion and inconsistent internal facts fail explicitly.

Local and access facts now live in a standalone fixed-capacity
`RuntimeBodyFacts` object borrowed by the x86 emitter rather than in its machine-
code state. Before the prologue is emitted, a bounded analysis pass types the
supported leading straight-line local-declaration prefix and assigns each named
binding its stable ID, mutability, type, and translated declaration span. The
pass mirrors the emitter's complete supported declaration order: pre-loop top-
level statements, each parsed loop, then post-loop top-level statements. Within
a loop it retains direct loop locals, copies the active loop environment for
nested-loop and conditional-arm actions, and restores the outer environment for
the next loop. The fact-ID sequence remains monotonic across every discarded
scope, so same-named locals retain distinct identities and later declarations
cannot inherit a scoped ID.
The same traversal now resolves every non-wildcard assignment target represented
by those body forms into a separate fixed 256-entry expectation table containing
stable base identity, projection list, base type, access class, and source span.
Emission consumes each matching expectation at the assignment site while still
appending reads and writes to the existing true emission-order access ledger.
This separation prevents precomputed writes from being reordered ahead of RHS
reads. Missing, reordered, malformed, immutable, or identity-drifted expectations
fail as `InvalidRuntimePlaceFacts`.
Assignment RHS expressions whose root is a discoverable identifier, dereference,
index, tuple field, subslice, transparent wrapper, or sequence tail also reserve
a separate fixed 256-entry read-expectation table. The pass resolves the root
base against the exact active scope and retains its projection list and span.
Emission consumes each expectation through the ordinary identifier-read recorder,
so projected specialized paths and direct identifiers share the identity check.
For scalar assignment RHS expressions, the pass now recursively visits casts,
type ascriptions, unary wrappers, returns/break values, sequences, binary
operands, and conditional condition/arms in the emitter's exact source order.
A discovered projected place reserves one read without separately reserving its
identifier base. Address-taking follows its specialized lowering rather than
inventing a pointee read. Typed index dispatch now mirrors the distinct lowering
shapes: reference indexes reserve the base and runtime index; constant local-
array indexes reserve one projected element read; runtime local-array indexes
reserve every materialized element read before the runtime index. Method/call
and aggregate families remain outside this slice.
The same bounded visitor now runs for scalar local initializers before the new
binding enters the active environment. Sequential and scoped shadowing therefore
records reads against the previous binding identity; the replacement binding
receives its monotonic ID only after initializer emission. Aggregate and fat-
reference initializers retain their specialized emission-time materialization.
Emission must consume every preassigned declaration exactly once. Inlined helper
parameters and later scoped locals append to a checked dynamic tail and cannot
steal a preassigned source identity; mismatches fail as
`InvalidRuntimePlaceFacts`.

The table still covers current runtime emission, including expanded inlined
helper bodies; it is ephemeral compiler state rather than serialized IR.
Expression identifiers still resolve by name before their stable fact is
recorded. A bounded source-independent discovery pass can now peel identifier,
dereference, index, tuple-field, subslice, transparent wrapper, and sequence-tail
syntax into an ordered read-place projection chain. A fifth projection and a
64-level discovery nesting overflow fail explicitly. Direct scalar dereference
emission consumes that discovery and records one projected read instead of an
empty base read. Specialized direct aggregate paths reuse the same recorder.
The discovery is not yet universally consumed by nested emission paths. The
prepass now enumerates every declaration and assignment-target form represented
by the supported runtime body and loop parsers, plus root-place and supported
nested scalar reads of assignment RHS expressions and scalar initializer reads.
It does not yet preanalyze compound array-base materialization, aggregate/fat-
reference initializers, method/call, expression-statement, condition/control,
tail, or other body reads or replace name lookup across the whole body. Expanded
inlined-helper locals still append dynamically. There is not
yet a complete typed body table, move path, borrow, loan, or CFG. This runtime
place foundation is therefore an incremental prerequisite, not a claim of
ownership checking.

Complexity assessment for the bounded runtime fact tables:

```text
Complexity impact: LOW
TCB impact: NONE
New parser boundary: NO
New authority model: NO
New persistent state: NO
External dependency: NO
Failure isolated: YES
Existing-object reuse: HIGH
```

## Modern trait-solver roadmap

The current architecture is not yet suitable for a general modern trait solver.
Built-in operations are matched directly and there is no persistent type/trait
environment or obligation representation. Before adding broad generic syntax,
introduce bounded interned type identities, substitutions, binders, predicates,
and source-independent item identities. Then build an MRML-owned solver around:

1. explicit goals and responses;
2. canonicalization and inference variables;
3. where-clause elaboration;
4. associated-type normalization and projection;
5. higher-ranked reasoning where required;
6. coherence and overlap checks;
7. ambiguity as a first-class outcome;
8. bounded recursive goals; and
9. explicit cycle handling and diagnostics.

Do not design around limitations of rustc's legacy solver or mimic rustc query
internals. The target is intended modern Rust semantics through an independent,
bounded implementation.

## Systems-language and security priorities

Post-2024 systems work should investigate, in dependency order, naked functions
and `naked_asm!`, modern inline assembly, Polonius-direction borrowing, modern
trait solving, new safe integer and const capabilities, strict provenance APIs,
`no_std` improvements, and new ABI/system-programming facilities. Do not repeat
features already supported correctly.

Naked functions are a high-priority **STABLE** target for context switches,
interrupt/trap entry, boot transitions, VMM entry/exit glue, and architecture
stubs. Their implementation requires explicit architecture parsing, operand and
register validation, exact body restrictions, direct instruction/object
emission, and tests proving that no normal prologue/epilogue is inserted. It
must not rely on unspecified backend behavior.

Language capability and application admission are separate. These planned
security profiles are profiles of one Rust language, not different languages:

- **MRML Application Profile:** safe Rust only; unsafe and native unsafe FFI
  prohibited; JIT prohibited; stable MRML service/application ABI; compiler-
  derived security metadata required.
- **MRML System Profile:** audited unsafe, raw pointers, assembly, hardware
  intrinsics, and stable system boundaries allowed where required; security
  metadata required.
- **MRML Compiler/Kernel Profile:** maximum required architecture functionality,
  explicit unsafe boundaries, and the strongest audit requirements.

Preserve the existing unsafe/raw-pointer implementation. Profiles eventually
classify and validate compilation units; they do not delete systems Rust from
the compiler to enforce ordinary application policy.

Compiler-emitted metadata is a long-term **MRML-SPECIFIC** milestone. Candidate
derived fields include `memory_safe_profile`, `unsafe_used`,
`unsafe_region_count`, `native_ffi_used`, `inline_assembly_used`,
`naked_functions_used`, `JIT_required`, `CET_compatible`, `IBT_compatible`,
`shadow_stack_compatible`, target ABI, compiler version, and language profile.
Source files cannot self-assert these properties. The compiler/toolchain derives
or validates them, the loader verifies them, and hardware claims remain absent
until code generation, metadata, loader enforcement, and hardware enforcement
all exist.

Retain the MRML-specific convergence direction:

```text
MRML service source
    -> mrml-rustc under a memory-safe profile
    -> MRML object/executable plus compiler-derived metadata
    -> loader validation
    -> capability namespace assignment
    -> service execution
```

CET, IBT, and shadow-stack work may advance independently of upstream rustc when
technically sound, but compatibility never substitutes for verified executable
properties and hardware enforcement.

## Const and pointer direction

Const evaluation remains bounded and deterministic. Prioritize layouts, kernel
configuration, security metadata, static tables, protocol/device descriptions,
and capability declarations. If an existing capacity is insufficient, redesign
and document the bound; do not silently add unrestricted compile-time execution
or global allocation.

Pointer work tracks modern provenance semantics around addresses, provenance
exposure/reconstruction, casts, offsets, reference creation, reborrowing, and
aliasing. The eventual place/loan model must connect provenance-bearing values
to allocation and capability identities where appropriate. Address equality
alone never proves provenance interchangeability.

## Roadmap selection

Score candidate work by MRML usefulness, modern Rust relevance, security
relevance, dependency unlocks, implementation complexity, oracle stability, and
testability. Prefer high-value dependency unlocks rather than a superficial
upstream test-pass percentage. The major sequence is:

1. preserve and stabilize supported semantics;
2. establish the explicit typed ownership/place/CFG representation;
3. build toward Polonius-style borrowing;
4. build modern trait-solver foundations;
5. fill post-2024 systems-language gaps;
6. add naked functions and architecture-level functionality when prerequisites
   are ready;
7. expand modern const, type, and pattern support required by MRML;
8. enforce application/system/compiler security profiles;
9. emit compiler-derived executable security metadata; and
10. progressively advance the exact future-Rust oracle.

The highest-value next major implementation task is the bounded typed
ownership/place/CFG representation. Smaller parser, type, aggregate, control-
flow, and diagnostic prerequisites may continue when they directly prepare that
representation. Arbitrary old-edition parsing, obsolete compiler quirks,
historical diagnostic compatibility, unstable symbol compatibility, and obscure
legacy cases with no MRML dependency are deprioritized.

The OS/platform and compiler remain two concurrent lanes. Neither waits for the
other to become complete; they converge progressively as real MRML components
become compilable under verified profiles.

## Non-negotiable implementation rules

- Preserve `no_std`, no global `alloc`, dependency-free core compilation,
  caller-selected fixed capacities, bounded recursion/diagnostics, checked
  offsets, explicit target layouts, deterministic memory use, and capacity
  failures.
- Unsupported borrowing, provenance, traits, ABI, const, control-flow, unsafe,
  assembly, and metadata behavior fails explicitly. Never emit guessed
  semantics.
- Preserve existing working functionality, original conformance probes,
  COFF/ELF64 code generation, Windows GNU/LLVM and Arch verification, UEFI and
  NVPTX checks, and pinned-nightly evidence unless a concrete correctness issue
  requires a deliberate change.
- Every new semantic feature follows black-box observation, independently
  authored MRML probe, MRML-owned implementation, and differential verification.
- Never copy upstream compiler implementation source or upstream test bodies to
  inflate coverage.
