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
| Modern borrowing / Polonius | **PARTIAL** | References, explicit and expected-type implicit direct mutable-reborrow ancestry and parent suspension, mutable pointee operations, bounded ownership/place/effect facts, fixed-point definite-initialization, and direct shared/mutable-loan conflict checks across the supported statement/loop CFG exist. Conditional expressions retain bounded program points and canonical nested/sequential edges. General shared-child access classification, indirect loan identity, regions/outlives reasoning, and complete Polonius-compatible analysis remain unimplemented. |
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
The body facts now also contain a fixed 1,360-entry move-path table and 512-entry
initialization-site table. Every supported parameter and named local receives
one dense root path; supported owned tuples immediately add one precisely typed
child path per numbered field. The derived path capacity covers all 256 retained
locals and 16 supported ABI parameters at maximum tuple width. Parameter entry
and successful local-declaration completion are recorded as distinct
initialization origins
with matching type and source span. Final validation requires exact root and
initialization counts, dense IDs, complete local/parameter coverage, empty root
projections, and exact child ordering, parent, base, field projection, and type.
Corruption, missing paired facts, or capacity exhaustion fails closed. These
root sites are structural
prerequisites: arrays remain root-only because the current summary `Index`
projection does not identify a disjoint element. A separate fixed 768-entry
effect ledger now records only contextually proven effects: direct identifier
initialization of a mutable-reference binding is a `Move` on the source root,
and direct root or precise tuple-field assignments become `Write` or
`ReadModifyWrite` after RHS planning. Assignment reads resolving to an exact
root or tuple-field path of a proven `Copy` type transactionally add a `Copy`
effect; an exhausted effect table cannot leave a read without its paired effect.
Validation rejects incompatible types, projected moves in this direct-only
slice, invalid paths, holes, corrupt counts, malformed spans, and capacity
overflow. Exact non-`Copy` roots passed to resolved non-`Copy` parameters or
returned from supported source expressions now record `Move`; transparent
wrappers, sequence tails, and conditional branches preserve that context while
prefixes and conditions retain ordinary value evaluation. Unsupported or
implicit-coercion call/return shapes, dereferences, summary indexes, other
non-`Copy` reads, and indirect borrow shapes remain unclassified rather than
guessed. Direct shared
and mutable borrows of exact roots, including reborrows through a direct
reference root, now record distinct `SharedBorrow` or `MutableBorrow` effects;
an allocation-free derived view can associate the latest matching same-origin
borrow effect with the initialized reference local, giving it a stable loan ID
equal to that initialization's dense index plus the borrower, borrowed path,
kind, and issuance-effect index. This direct issuance identity adds no fact
arena and does not yet claim completeness, loan lifetime, liveness, conflict
enforcement, invalidation, or NLL semantics. The facts do not claim that
unreachable or divergent declarations execute.
A derived fixed 1,280-event ownership order now spans the maximum 512
initializations and 768 effects. Event IDs are assigned at insertion time, so
RHS effects precede the successful initialization of their destination local.
Validation requires the initialization and effect tables to merge into one
dense monotonic sequence without holes, duplicates, inversions, or corrupt
counts. For functions with a complete supported control-flow graph, a fixed
1,360-path state map now consumes this
order and rejects a copy, move, borrow, or read-modify-write of an uninitialized
exact path as `RuntimeUseAfterMove`. Moves clear roots and tuple descendants;
exact writes restore state and child writes recompute tuple-root completeness.
Each event now also retains insertion-time origin: parameter
entry, an exact bounded top-level statement index, a verified final tail, or an
explicit emission-expansion marker for dynamically appended inline-helper
facts. Validation rejects unassigned, out-of-body, or otherwise incompatible
origins. Conditional returns now distinguish indexed condition evaluation,
true-return values, and the final else value. Conditional assignments distinguish
indexed conditions and every indexed branch/else action. A fixed parser-shaped
statement table validates exact branch counts, else presence, and action counts;
forged or mismatched program points fail closed. Complete supported CFGs now
derive a control point for every non-expansion origin without adding a per-event
table: parameter entry, exact top-level or conditional blocks, true/false return
edges for conditional return values, sourced conditional action blocks including
disconnected post-return suffixes, reachable tail-return edges, or an explicit
`Unreachable` point for syntactically retained tails after all-path termination.
Final validation rejects origins whose required block or edge cannot be found.
Loop events retain exact header, operation, conditional-arm/action/terminal,
direct-return, nested-loop-header/action, and ordered nested-control origins.
These map to exact sourced blocks or return edges. Bounded parser operation
counts and exact CFG-source matching reject forged operation, arm, action, and
control coordinates instead of assigning an enclosing block.
For complete supported statement/loop CFGs, definite initializedness now uses
a bounded fixed point over exact block and edge events. Two fixed 64-block by
22-word bitset matrices cover all 1,360 move paths; predecessor states meet by
intersection, edge transfers precede joins, and convergence is limited to
`block_count * move_path_count + 1`. Reads are validated only after convergence.
This accepts mutually exclusive early-return moves while rejecting a use after
a move on any continuing join path or loop-exit path. Each expression event now
also retains a fixed-width nested branch path: conditions remain on the parent,
then/else arms append zero/one, and nested arms extend the path up to the parser's
64-level bound. Validation rejects malformed encodings and path state leaking
between expressions. A fixed 1,280-entry table gives every visited conditional
a dense occurrence ID plus its enclosing ownership location, span, parent ID,
and parent path. Events retain the active ID, so sequential conditionals with
the same branch bits and nested conditionals are not conflated. A derived fixed
6,400-entry program-point table now gives each visited expression location a
root and each conditional occurrence explicit condition, then, else, and join
points. Branch traversal records its actual exit: a direct arm exits from its
arm point, while a nested arm exits from the nested join. A sequential
conditional enters from the preceding join. Capacity is preflighted before any
conditional fact mutates, and validation rejects holes, non-dense IDs, wrong
kinds or locations, malformed occurrence references, missing exits, forged
event points, and capacity exhaustion. A second derived fixed 6,400-entry table
records exactly five edges per occurrence: entry to condition, condition to
both arms, and both actual branch exits to the join. Nested joins therefore feed
their enclosing join, while sequential conditionals enter from the preceding
join. Construction preflights the complete edge budget, and validation rejects
holes, count mismatches, substitution, reordering, invalid endpoints, or edges
that disagree with the occurrence facts. Every point's ownership location must
also resolve to an existing statement/loop block, edge, or explicit unreachable
point. The initializedness fixed point does not consume this expression
subgraph as linear control flow. Instead, supported same-location expression
graphs require one root and sink and an exact program point for every event.
A bounded structured traversal processes straight-line edges iteratively,
recurses only through the parser's 64-level conditional nesting bound, meets
then/else states by intersection at each join, and composes the sink state with
the enclosing statement or loop control point. The global 6,400-point capacity
does not allocate a per-point state matrix. Unsupported cross-location or
incomplete expression graphs fail closed as `RuntimeExpressionUnsupported`.
Original accepted/rejected probes preserve initializedness when neither arm
moves a reference and reject its later use when exactly one arm moves it.
Assignment RHS expressions whose root is a discoverable identifier, dereference,
index, tuple field, subslice, transparent wrapper, or sequence tail also reserve
a separate fixed 256-entry read-expectation table. The pass resolves the root
base against the exact active scope and retains its projection list and span.
Emission consumes each expectation through the ordinary identifier-read recorder,
so projected specialized paths and direct identifiers share the identity check.
The typed assignment RHS selects value or move context before traversal. An
exact non-`Copy` root therefore records `Move` before the destination `Write`,
while exact proven-`Copy` paths retain `Copy`; explicit address-taking still
records its borrow effect. Projected non-`Copy` reads, dereferences, summary
indexes, and tuple materialization remain unclassified rather than being
guessed as moves.
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
receives its monotonic ID only after initializer emission. Aggregate initializers
retain their specialized emission-time materialization, except that direct array
literals, single-evaluation array repeats, and tuple
literals now preanalyze their scalar operands in the same order as stack
materialization. Direct identifier-backed array and tuple copies also reserve
the emitter's exact per-element `Index` or numbered `TupleField` projections.
Conditional tuple initializers with direct tuple-literal branches reserve the
condition once followed by both branches' source-ordered scalar operands.
Conditional array initializers with direct array-literal branches instead mirror
the emitter's per-element traversal: condition, then element, else element for
each materialized index.
Sequence-wrapped direct tuple literals plan the prefix once before all tuple
operands, while sequence-wrapped direct array literals plan the prefix before
each element, matching their distinct materializers.
Fat-reference initializers now recursively reserve supported non-call forms:
identifiers, conditional branches, transparent return/break/inline-const
wrappers, sequence prefixes and tails, and range-derived slice/string values.
Range-derived slice and string
initializers reserve their runtime start and end reads before the base read;
local-array bases retain the exact `Subslice` projection. The recursion is
bounded to 64 levels. Call-derived fat-reference initializers also use the same
visitor when every argument is a one-slot scalar, another supported fat
reference, a direct identifier-backed array or tuple, an array literal or
single-evaluation repeat, a direct conditional array with literal branches, a
an array accepted by the bounded recursive element planner, or a supported
literal/conditional/wrapped tuple. The array planner covers identifiers,
contextual defaults, literals, repeats, integer-to-byte arrays, direct and
wrapped array-producing calls, conditionals, transparent return/break/inline-
const wrappers, and nested sequences in the emitter's per-index order. Tuple-
producing calls and their supported whole-value wrappers are planned once.
Prefix expressions and call arguments are reserved left-to-right before
inlined-helper emission; identifier-backed arrays reserve one `Index` read per
element and tuples reserve numbered `TupleField` reads. Direct conditional
arrays repeat condition/then-element/else-element for every index. Supported
sequence-wrapped arrays additionally repeat the prefix before every materialized
element; identifier tails then retain one exact `Index` read per element, while
default tails correctly add no element-place read. Conditions and nested branch
prefixes are likewise repeated for each index. Direct root repeats preserve
their distinct single-evaluation rule. Direct array-producing calls are planned
once, while calls reached through per-element wrappers are planned once per
materialized index. Unsupported aggregate-leaf call arguments remain
emission-time work because their specialized materializers need separate
traversal facts.
Supported direct identifier, range-derived, and recursively conditional fat-
reference explicit returns and final tails now use the same bounded read
preanalysis. Their conditions, runtime endpoints, and bases retain exact source
and emission order on both native ABIs.
The visitor also runs for every supported scalar expression statement at the
top level, in conditional arms, in direct and nested loop actions, and after
loops. Each statement is parsed once and its reads are reserved against the
exact scoped environment in the same order used by emission.
Supported scalar control reads now include top-level conditional-return and
conditional-assignment conditions, conditional and explicit return values,
while-loop heads, direct conditional break/continue/return controls,
conditional loop block/arm conditions and branch-local return values, and the
final scalar tail. Nested-loop blocks mirror the emitter's entry-condition,
action-boundary, and control-order traversal exactly, including interleaved
unconditional returns, conditional breaks, conditional returns, and conditional
continues before each following action. Aggregate/fat values retain specialized
emission-time materialization instead of being misclassified as one scalar read.
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
nested scalar reads of assignment RHS expressions, scalar initializer reads,
supported scalar expression-statement reads, and the supported scalar
condition/control/return/tail paths above.
Supported compound fixed-array index bases now reuse the bounded whole-array
planner before the index read. Non-call fat-reference returns now share bounded
return/break/inline-const, sequence, and conditional recursion between emission
and read preanalysis. Direct and wrapped call-derived fat-reference returns now
validate and preanalyze supported call arguments, then transport the inline
pointer/length result through the explicit System V or Windows return path. It
does not yet preanalyze unsupported compound
array-base materialization, other wrapped or non-literal conditional aggregate
values, wrapped/non-literal conditional-array
and otherwise unsupported aggregate-argument call-derived fat-reference
initializers, method/call families beyond the bounded initializer slice,
unsupported
aggregate returns/tails, or other body reads, or replace name lookup
across the whole body. Expanded
inlined-helper locals still append dynamically. There is not
yet a complete typed body table, array-element paths, complete effect coverage,
move-state enforcement, borrow, or loan model. An initial
fixed-capacity CFG fact table records stable basic-block IDs, exact top-level
statement ranges, reachability, and true/false/unconditional edges to blocks or
function return for straight-line, conditional-return, explicit-return, and tail
flow. Chained conditional returns carry explicit synthetic-branch provenance:
exhaustive chains terminate on the final false edge, while
non-exhaustive chains route it to a top-level continuation block. Conditional
action blocks now carry distinct condition, branch-action, else-action, and join
blocks, including final-return termination and unreachable top-level successors.
Top-level `while` and unconditional loops now add explicit header, operation-
range, exit, return, and backedge facts for ordered simple and conditional
break/continue/return controls. Conditional loop blocks additionally represent
primary, `else if`, and final `else` condition/action provenance, joins, and
arm-specific terminals, including structurally proven exhaustive termination.
Nested loop blocks now carry dedicated entry headers and ordered action/control
provenance, including parser-resolved inner and outer break/continue targets,
conditional returns, entry-condition exits, and divergent backedges without
replaying preceding outer-body operations. The parser's immediately-breaking
nested unit-loop form stays within the enclosing operation range, matching its
existing no-op emitter semantics. Operations after unconditional direct,
conditional-block, or nested-loop terminals now begin disconnected unreachable
blocks; syntactic exits in those suffixes do not make the enclosing continuation
reachable. Conditional-assignment actions after a return likewise occupy
bounded, separately sourced, disconnected unreachable blocks with no incoming
edge; their return or join edge cannot make the enclosing continuation
reachable. This closes the known CFG-suffix gap for runtime forms admitted by
the supported parser. This runtime place/CFG
foundation is therefore an incremental prerequisite, not a claim of ownership
checking.

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

The current bounded ownership foundation derives direct loan identities from
existing borrow and initialization facts. It records dereference and projection
uses only for reference locals with a derived direct loan. Across reachable
paths in the validated bounded CFG, live shared loans reject later exact-place
mutable borrows, while live mutable loans reject later copies, moves, borrows,
writes, or read-modify-writes of the exact borrowed path. This is direct-loan
liveness and invalidation, not indirect alias tracking, implicit reborrows,
regions, reborrow completion, or a complete borrow checker.

Explicit direct mutable reborrows additionally derive their parent loan and
bounded ultimate owner path. A mutable parent is suspended when it is used
before a later child use, restored after the child’s last reachable use, and
owner-path conflicts are checked through the ancestry chain. Shared-to-shared
reborrows preserve compatible shared parent reads. An explicitly typed expected
reference binding from a direct reference identifier creates the corresponding
implicit reborrow, while an inferred mutable-reference binding remains a move.
This does not yet classify every shared-child mutation or general coercion site.
Assignments through a direct mutable-reference borrower now distinguish loan
mutation from compatible loan reads. While a shared child is live, mutation
through its mutable parent is rejected but reads through that parent remain
compatible; mutation after the child's last reachable use is accepted. For an
unconditional top-level explicit-borrow assignment to a mutable
reference binding, the destination write is a new bounded loan generation.
Uses resolve to the latest generation, while a child created before replacement
remains tied to the old generation. Conditional statement reference
replacements now use bounded reaching definitions: a generation remains active
when a bypass path reaches the use and is killed when every reaching path
crosses a replacement. Conflict-to-use queries preserve the same path
correlation instead of combining mutually exclusive events. A child reborrow
issued where multiple parent generations reach recursively preserves every
possible ultimate owner path and applies parent suspension to each active
mutable generation. Direct reference assignments in loop operations,
conditional loop actions, and nested loop actions now use the same bounded
reaching-definition analysis. A possible zero-iteration path retains the
pre-loop generation, while replacement crossed before every exit kills it;
repeated dynamic issuances at one static assignment are represented
conservatively by that assignment's bounded generation identity. A conditional
reference expression used as a direct local initializer or direct assignment
now retains each final branch borrow as an alternative origin sharing the
destination generation event. Nested alternatives remain distinct, sibling
origins do not conflict merely because their fact IDs are ordered, and
sequence-prefix temporaries are excluded from the destination origins.
When that direct destination has an explicit reference type, final conditional
identifier values use the expected shared or mutable reference context and
therefore become reborrows rather than consuming moves. Conditions and sequence
prefixes remain ordinary value evaluation and do not become destination origins.
Direct projected reference places, including numeric tuple fields, now receive
the same expected-reference treatment at explicit typed local initialization and
direct assignment sites. Inferred projected reference bindings remain consuming
moves, preserving partial-move initializedness.
Direct and conditional place arguments passed to a shared or mutable reference
parameter now use that expected reference context when the call result cannot
carry a reference. This models a call-scoped reborrow, rejects conflicts with a
live child, and restores the parent after the call. Calls returning references
remain conservatively move-classified until their result loan can be linked to
the originating argument without shortening its lifetime.
Statement-free reference-returning callees whose direct, transparent-wrapper,
sequence-tail, or conditional result paths all resolve to the same compatible
reference parameter now supply that argument as the destination reference's
bounded loan origin. The relation works for direct local initialization and
direct assignment generations, suspends the argument while the returned child
is live, and restores it afterward. Callees with statements, ambiguous result
parameters, unsupported result expressions, or locally derived references remain
conservative rather than receiving a guessed origin.
The same proof now merges top-level explicit returns, conditional returns,
bounded else-if return chains, exhaustive else values, and a continuing tail.
Every retained result must resolve to the same compatible parameter. Any local,
assignment, expression statement, loop, missing value, parse failure, or differing
origin makes the call result conservative.
Non-direct conditional destinations and indirect reference-value moves remain
unclassified loan origins.
A plain assignment of a direct reference identifier into an existing typed
reference binding now uses the destination type as coercion context and records
a shared or mutable implicit reborrow before the destination write. For mutable
references this preserves parent suspension until the reassigned child’s last
use and restores the parent afterward. Projected, compound, conditional-RHS,
and call-derived assignments retain their existing classifications.

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

The highest-value next major implementation task is validated local/loop
call-result origins followed by return coercion-site reborrowing before region
reasoning.
Smaller parser, type, aggregate, control-flow, and diagnostic prerequisites may
continue when they directly prepare that analysis. Arbitrary old-edition
parsing, obsolete compiler quirks, historical diagnostic compatibility,
unstable symbol compatibility, and obscure legacy cases with no MRML dependency
are deprioritized.

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
