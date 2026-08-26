# MRML Rust compiler direction

Production build-tool transition is governed by
[build/BUILD_SYSTEM.md](build/BUILD_SYSTEM.md). Until an exact artifact profile
satisfies its readiness gate, production artifacts use pinned upstream Rust.
Experimental `mrml-rustc` is explicit, never silently falls back, and does not
alter this document's compiler-core priorities.

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
`docs/compiler/oracles/`. Preserve the initial
[ORACLE-0001](compiler/oracles/ORACLE-0001.md); the current default build and
behavioral reference is [ORACLE-0002](compiler/oracles/ORACLE-0002.md).

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
| Modern borrowing / Polonius | **PARTIAL** | References, explicit and expected-type implicit reborrow ancestry, return coercion-site reborrows, mutable pointee operations, bounded ownership/place/effect facts, fixed-point definite-initialization, direct shared/mutable-loan conflicts, and bounded intermediate-ancestor invalidation across the supported statement/loop CFG exist. Conditional expressions retain bounded program points and canonical nested/sequential edges. General indirect loan identity, regions/outlives reasoning, and complete Polonius-compatible analysis remain unimplemented. |
| Next-generation trait solving | **PARTIAL** | Method-like built-ins remain recognized directly. Allocation-free goals distinguish concrete types, universe-aware inference variables, explicit bounded universal/existential binders, and rigid placeholders. Exact existential goals recover universe-aware substitutions from exact implementation selection. Flat generic and where-clause existential selection use a bounded symbolic unifier to retain concrete constraints and inference equality classes; one fixed root state recursively composes exact, generic, clause, and projection-equality premises. A 64-entry clause database and 16-frame solver separately prove concrete or skolemized implemented-trait premises. Exact and generic associated values normalize bounded projections after implementation proof; generic values may recursively project through a separate 16-frame visited stack. Bounded existential conjunctions compose implemented-trait and projection-equality predicates in one inference state, deferring and retrying ambiguous predicates after other predicates refine that state. Projection-aware existential and concrete proof evaluate projection premises on clauses and generic implementations, including nested projection proof, while legacy environment-free proof entry points fail closed. Rigid proof checks concrete and placeholder-bearing projection predicates, preserves placeholder identity through generic associated values and nested projections, and recursively proves the selected implementation's trait/projection premises under the existing proof and projection bounds. A 64-node acyclic term arena represents projection-bearing goals under both existential and universal top-level binders; universal instantiation creates a fresh placeholder universe before rigid normalization and proof. Universally bound projection-equality predicates and bounded mixed implemented/projection conjunctions use the same premise-aware rigid normalizer and exact placeholder comparison. Fixed nested universal prefixes advance one universe per binder level, retain level-local placeholder identities, and bound both levels and total parameters. A bounded branch forest assigns independent prefixes disjoint universe segments while globally capping branches, predicates, and binder levels. A fixed 64-trait classification enables opt-in coinductive success only when every goal in a repeated rigid cycle is classified coinductive; rigid projection premises remain mandatory before that cycle may succeed, including within nested universal branch forests. In existential proof, the current substitution is reapplied to every cycle goal and coinduction requires every variable to be resolved to a rigid term. An unresolved classified cycle can be deferred within the existing eight-predicate scheduler while a projection equality refines the state, but returns `Cycle` if no sibling makes progress. Ordinary, mixed, and projection-normalization cycles remain explicit. A coherent 64-entry generic-implementation table rejects flat-head overlap, selects one stable implementation for concrete or rigid queries, and recursively proves instantiated premises while preserving placeholder universes. Symmetric admission checks reject exact/generic overlap in either insertion order. The canonical parser accepts bounded traits with positional type parameters, supertraits, associated types, and up to eight declaration `where` requirements over flat implemented-trait or projection-equality predicates; unconditional exact facts; concrete and generic conditional implementations with up to eight implemented-trait or projection-equality premises; concrete projection obligations; flat generic heads whose parameters occur as complete self or argument positions; and projection-valued generic or exact associated types with flat self/argument positions. Declaration requirements substitute `Self`, complete declaration parameters, and concrete nominal types into every exact, generic, or conditional implementation clause; projection requirements resolve stable associated-type identity and substitute their expected type through the same bounded path. Conditional concrete heads, requirement-bearing exact heads, and exact projection-valued implementations lower as zero-parameter clauses and share exact/generic coherence, recursive projection-aware proof, and generic associated-value normalization. Direct supertraits with `Self`, complete child-parameter, or concrete nominal arguments lower as deduplicated inherited premises on generic and conditional implementations; exact child facts instantiate the same indexed arguments while validating generic or conditional parents through the projection-aware proof environment. Distinct instantiations of one parent trait remain separate required goals, while an exact duplicate requirement is rejected. Arbitrary nested parameter constructors, inference in source signatures, parameter defaults/bounds, lifetime/const parameters, compound supertrait arguments, associated defaults/bounds/generics, general projection types, methods, negative/unsafe/default implementations, inferred operation obligations, higher-ranked or `?Sized` supertraits, specialization, general answer composition, and candidate backtracking remain absent. |
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
Conditional-loop terminal returns in both the primary and else arm now use
return-context preanalysis and the existing exact terminal return edge. This
rejects a loop-local identity-call result while preserving a parameter-backed
result. It does not classify ordinary terminal actions or `break` as returns,
and it does not claim general lifetime solving. Nested-loop unconditional and
conditional return values likewise use return-context preanalysis and their
existing shape-validated ordered control location. Only return controls carry a
`NestedLoopControlValue`; conditions, `break`, `continue`, and ordinary actions
remain outside the exact return-value classification. Local-backed identity-call
results are rejected and parameter-backed controls are preserved.
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
paths in the validated bounded CFG, live shared loans reject later exact-owner
moves, mutable borrows, writes, or read-modify-writes, while live mutable loans
reject later copies, moves, borrows, writes, or read-modify-writes of the exact
borrowed path. Mutation-through-reference, shared or mutable call reborrows, and
moves of a local reference ancestor additionally inspect bounded intermediate
ancestry. Projected reference paths walk the validated move-path parent chain,
so a containing tuple move overlaps its borrowed field without conflating a
sibling field or a generation-replacing destination write. This is bounded loan
liveness and invalidation, not unrestricted alias tracking, regions, reborrow
completion, or a complete borrow checker.

Inferred direct mutable-reference moves now propagate a single direct loan
origin into the destination local instead of discarding it. Event-decreasing,
fixed-capacity lookup supports chained moves and selects the source binding's
latest direct initialization or assignment generation. The consumed source
still participates in initializedness, while conflicts and last-use restoration
follow the moved destination. For one immediate precise root move, conditional
expression-origin loans now derive one destination fact per existing branch
borrow effect. The facts retain distinct borrowed paths and share only the
destination generation, so a later conflict with either possible owner is
preserved without inventing a conflict with unrelated owners. A source-
generation replacement blocks derivation. The same bounded relation now retains
one fact per origin and move depth through direct root-move chains. Its checked
`initialization_count * effect_count` enumeration and depth-qualified loan IDs
preserve intermediate generations instead of collapsing to the terminal
binding; every hop rechecks precise move/init shape and intervening replacement.
One direct move from a reference-typed field of a directly initialized tuple now
retains the field's exact loan origin. The bounded correlation requires one
validated numeric tuple-field projection, the exact expected borrow-effect count
and order, compatible mutability, and no intervening root or field write. It
refuses ambiguous or malformed shapes rather than guessing. After that field
origin enters a direct local, the existing bounded event-decreasing move lookup
preserves it through later direct root-move chains and selects the latest
assignment generation rather than reviving the field's old owner. The same
correlation may now cross another directly initialized tuple-field source later
in the chain before continuing through direct root moves. Every projected hop
retains the one-step numeric-field, exact effect count/order, matching
mutability, and no-unclassified-replacement requirements. A later move from a
directly reassigned tuple reference field now selects the exact assignment borrow
generation before considering its initialization origin, preserving the new
owner's ancestry without reviving it from older storage. Nested projections,
general aggregate provenance, and general alias/region propagation remain
unimplemented.

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

Future GPU compiler work follows [gpu/GPU_ARCHITECTURE.md](gpu/GPU_ARCHITECTURE.md)
only after the current CPU typed-place/CFG/ownership dependency gates. It adds a
safe typed kernel subset, explicit address spaces, High/Machine IR, and metadata
admission without displacing the Polonius-direction critical path.
GPU High IR is evolving compiler/library state, not an early frozen public ABI;
Machine IR remains low-level semantic SSA/address-space/subgroup/matrix/barrier
state, not ordinary-source vendor packets. Stable object ABI, evolving
algorithms, and final vendor emission remain distinct.

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

Return coercion-site reborrowing and bounded direct/intermediate reborrow
invalidation are implemented for the documented subset. The first explicit
outlives slice now rejects a supported returned reference unless its active,
event-decreasing ancestry reaches parameter-backed storage. It covers exact
tail, explicit, conditional, and supported loop return-value locations; preserves
latest-generation replacement, cyclic reborrow ancestry, moved parameters, and
exact tuple-field initialization/reassignment origins. Direct shared-reference
copies now retain the same bounded ancestry through successive local bindings;
mutable references remain move-only. Local storage, mismatched mutability, and
unclassified ancestry fail closed. Conditional action-block returns now retain
an exact terminal ownership location and CFG return edge, including direct or
locally stored identity-call results. Reference-typed return `Copy`/`Move`
effects are validated without classifying ordinary value effects as reference
returns. This is not named-lifetime inference, general regions, or complete
Polonius outlives reasoning. The highest-value next major
implementation task is extending this relation across the remaining exact return
and indirect-alias forms, including nested projections and non-tuple aggregate
provenance, without collapsing generation or CFG path distinctions.
Existing loop-result origin proofs do not imply branch-local or loop-local
mutation dataflow or general regions.
Conditional reference reassignment into an exact tuple field now records every
supported branch owner together with the field's replaced initialization owner.
When that field is moved and reborrowed, bounded loan ancestry rejects mutation
of any still-live possible owner and releases the branch owners after the
descendant's last use. The same bounded ancestry retains both replaced owners
across two successive exact field writes. This is exact one-field conditional
and repeated-generation provenance, not path-
sensitive branch selection, nested projections, general aggregate provenance,
or complete Polonius semantics.
Exact returned tuple fields now require every retained origin of their latest
conditional reference-assignment generation to outlive the function. A mixed
parameter/local generation therefore fails closed even when another branch is
parameter-backed, while a generation whose branches all trace to the input is
accepted. This remains one-step tuple-field provenance, not general aggregate
escape analysis or named lifetime inference.
Conditional reference origins created inside an initial tuple value receive the
same all-origins return proof. The bounded grouping follows the exact reference-
field ordinal, distinguishes reference copies/moves from fresh shared or mutable
borrows, and does not let a local-backed sibling field poison a parameter-backed
returned field. Nested conditional groups and nested tuple types remain outside
this implemented slice.
Nested conditional leaves within that field are normalized through their bounded
parent chain to the outer conditional generation. This preserves separation from
later tuple fields while requiring every nested leaf origin to pass the same
outlives proof. Arbitrary expression-origin partitioning remains unimplemented.
At a returned exact tuple field, every CFG-reaching assignment generation and
the original field generation must outlive the function. Mutually exclusive
branch writes are both retained, as are sequential historical owners, matching
modern Rust's projected-field return behavior. Reference-value copy/move RHS
origins and fresh borrow RHS origins are classified separately and boundedly.
Loop-carried projected generations apply the same rule, but only when the write
is reachable from function entry and can reach the exact returned field. This
retains local-backed generations from zero-or-more-iteration loops while
excluding disconnected post-`break` suffix writes.
The same exact-origin set survives a projected field move into a reference local
before return. Direct initialization, conditional initialization, branch-local
assignments, and disconnected loop suffixes therefore retain the same outlives
result through the additional local generation.
Projected mutable tuple-field origins also survive an identity call at the
return boundary and through one stored call result. A local-backed conditional
origin fails outlives validation while all parameter-backed origins remain
accepted, reusing the same call-argument and projected-origin facts.

The first modern trait-solver foundation is an explicit bounded implemented-
goal representation. Stable trait/type/inference/placeholder identities remain
distinct; canonicalization replaces inference identities with first-occurrence
bound variables, makes alpha-equivalent goals equal, preserves placeholders,
and fails on argument or variable capacity overflow. The next slices add only
exact concrete impl headers and bounded answers: duplicate identities and
overlapping heads fail, one matching header returns its exact implementation
and fixed canonical-variable substitution, multiple matching inference answers
remain ambiguous, and no matching header returns no solution. Per-candidate
fixed bindings preserve equality when a canonical variable occurs more than
once. Canonicalization can also retain the first-occurrence inference identities
so a unique response maps its fixed bindings back to the caller without
allocation; incomplete or mismatched responses fail closed. This is not generic
unification or a complete solver and cannot authorize trait syntax.

The predicate-conjunction foundation groups up to eight implemented-trait goals
and canonicalizes them in one shared first-occurrence variable universe. A
variable reused by separate predicates therefore receives one bound-variable
identity, while predicate and aggregate variable overflow fail explicitly. It
does not elaborate or solve where clauses, introduce binders, or compose
answers.

The first binder slice represents a where clause as one bound consequence and
up to eight bound premises over eight explicitly indexed generic parameters.
Construction rejects out-of-scope parameters and excess capacity; concrete
instantiation requires exact arity and consistently replaces each parameter in
the consequence and premises. Generic parameters remain distinct from inference
variables and rigid placeholders. This is not elaboration, selection, or source
syntax.

Single-clause elaboration structurally matches a fully concrete implemented-
trait consequence against the bound consequence, infers fixed generic arguments,
and instantiates the clause when every parameter is constrained. Repeated
parameters require equal concrete types; mismatches return no solution,
unconstrained parameters remain ambiguous, and inference-bearing or placeholder
queries fail closed. There is no clause database, candidate combination,
recursion, or cycle handling.

The first clause database stores 64 stable identified clauses. Duplicate IDs and
structurally identical clauses fail at insertion. Distinct clauses that may
overlap remain representable, but a concrete query with multiple unique matches
or any unconstrained matching candidate is ambiguous; exactly one match returns
its clause identity and instantiated premises. This deliberately does not solve
those premises or recurse.

Concrete proof composition first accepts an exact implementation fact, then
recursively proves every premise of one unique clause. A fixed 16-goal stack
bounds work and detects repeated goals, including a cycle that closes at the
depth boundary. Missing premises, ambiguous candidates, cycles, and acyclic
depth overflow remain distinct results. This does not recurse over inference-
bearing goals, cache answers, normalize projections, or implement coinduction.

The first projection-normalization slice registers up to 64 exact associated-
type values under stable `(implementation, associated type)` identities. Values
must reference an implementation already present in the exact header database;
stale references, duplicate keys, and overflow fail. Normalization selects the
implementation through the existing canonical query and returns the exact value
or preserves ambiguity/no solution. Values cannot yet mention generic parameters
or other projections.

Generic projection normalization adds a separate fixed 64-value table keyed by
stable generic-implementation and associated-type identities. Values may be a
concrete type or one bound implementation parameter. Selection retains the
implementation's fixed substitution, recursively proves its instantiated
premises, and only then substitutes the associated value. Stale implementation
IDs, duplicate keys, unbound parameters, and overflow fail explicitly; missing
premises produce no solution, while cycles, overflow, and unchecked selection
collisions remain ambiguous at the projection boundary. Nested projections,
projection goals inside premises, and source associated-type syntax remain
unsupported.

A unified concrete projection entry point now selects across exact and generic
implementation families before reading either value table. Exact facts return
their registered values directly; generic candidates must pass recursive premise
proof before substitution. An absent implementation or value returns no
solution, and any unchecked cross-family collision remains ambiguous. The entry
point is the common boundary used by the bounded nested normalization below; it
does not provide general answer composition.

Bounded nested projection templates allow a generic associated value to name a
second concrete projection over the same implementation binder. The selected
substitution instantiates the nested goal, which may cross into either exact or
generic implementations. A separate 16-frame stack tracks exact `(goal,
associated type)` identities; repeated projections return cycle and acyclic
depth exhaustion returns overflow. Invalid bound parameters fail during value
admission. This supports recursive value normalization, not projection-bearing
type arguments, projection premises, inference projections, or coinduction.

The higher-ranked prerequisite gives every rigid placeholder an explicit 16-bit
universe plus a stable placeholder identity. A bound clause can instantiate its
parameters as distinct rigid placeholders in a caller-selected fresh universe;
canonicalization preserves those identities, different universes do not alias,
and universe advancement overflow fails. No general universe relation,
higher-ranked search, or `for<...>` source syntax exists yet.

Inference-variable identity now includes its creation universe while preserving
the root-universe `new(id)` constructor. Canonicalization treats identical
numeric IDs from different universes as distinct. A checked assignment permits
concrete values and same-or-older-universe inference variables/placeholders, but
rejects any value from a newer universe with an explicit leak error. This is a
bounded leak-check primitive, not higher-ranked candidate matching or complete
unification.

Rigid proof composition applies the same 16-frame visited-goal discipline to
concrete/placeholder goals. Exact concrete facts may terminate a branch;
otherwise one unique rigid clause is elaborated and every rigid premise is
proved recursively. Ambiguity, missing premises, cycles, and overflow remain
distinct, and inference-bearing entry goals fail. This is not mixed
inference/skolem unification, coinduction, or complete higher-ranked Rust
reasoning.

The first generic coherence slice admits 64 identified bound implementations.
An exact fixed 16-node equality unifier tests whether two flat heads have any
common instantiation across their separate binders. It propagates concrete
constraints through parameter unions, so repeated-parameter heads are disjoint
from unequal concrete tuples but overlap equal ones. Duplicate IDs, satisfiable
head overlap, and capacity overflow fail. Premises do not waive a head conflict,
and specialization is not implemented.

Concrete generic selection elaborates each admitted implementation head against
the query. Coherence guarantees at most one fully constrained candidate; a
unique result carries its stable implementation identity and instantiated
premises. No matching head returns no solution, while a parameter used only in
premises remains ambiguous. Inference-bearing queries fail at this concrete
boundary.

Concrete generic proof composes that selection with the existing 16-frame
visited-goal solver. Every instantiated premise must recursively resolve through
an exact implementation, another generic implementation, or a bounded where
clause. Missing premises, ambiguity, cycles, and overflow remain distinct.
Symmetric bounded admission checks reject overlap between exact headers and
generic heads in either insertion order, including repeated-parameter equality
constraints. The solver still treats a pre-existing unchecked collision as
ambiguous for defense in depth. This is not inference-bearing generic proof,
premise-aware coherence, specialization, or source-level trait solving.

Rigid generic selection applies the same coherent implementation table to goals
containing concrete types and rigid placeholders. Selected answers retain each
placeholder's exact identity and universe, repeated parameters require exact
term equality, and instantiated generic premises recurse through the existing
16-frame proof stack. Missing premises, ambiguity, cycles, and overflow remain
distinct, while inference-bearing entry goals fail. This is bounded skolemized
generic proof, not mixed inference/skolem unification, binder introduction,
coinduction, or complete higher-ranked reasoning.

Universal implemented-trait goals introduce an explicit binder over up to eight
parameters. Solving advances from a caller-supplied parent universe, instantiates
distinct rigid placeholders in that checked fresh universe, and sends the
skolemized goal through rigid generic proof. Invalid bound indices and universe
exhaustion fail explicitly; unconstrained implementation parameters preserve
ambiguity. This is one bounded universal-goal introduction rule, not nested
binders, leak-aware answer inversion, or `for<...>` source integration.

Standalone existential implemented-trait goals bind up to eight parameters as
universe-aware inference variables. Exact implementation selection canonicalizes
their first occurrences and restores a unique answer as substitutions keyed to
the original variable identities. Repeated parameters enforce equality; zero,
one, and multiple matching exact headers remain no-solution, unique, and
ambiguous. This does not yet search generic implementations, prove inferred
premises, compose projections, or invert answers across a universal binder.

Flat generic existential selection unifies a canonical inference-bearing query
with one coherent generic implementation head using a fixed 16-node constraint
graph. Concrete constraints become concrete answers; unbound equality classes
map every related query variable to their oldest universe-safe representative.
The same symbolic terms instantiate the selected implementation premises.
Parameters absent from the head remain ambiguous, rigid placeholders are
rejected, and no candidate returns no solution. Instantiated inferred premises
are not yet recursively proved, and this is not nested type unification,
projection unification, or a general answer-composition engine.

Recursive inferred proof retains one fixed constraint state for the root
existential variables. Before each obligation it applies current equality and
concrete constraints, selects across exact and generic implementations, merges
the resulting answer, and proves generic premises in order through a 16-frame
visited stack. Exact premises can refine symbolic roots to concrete types;
generic chains propagate those refinements. Contradictory premises return no
solution, while ambiguity, cycles, and overflow remain distinct. Premises may
not introduce unrelated variables. Inference-aware where-clause elaboration,
projection constraints, backtracking, caching, and coinduction remain absent.

Inference-aware where-clause elaboration applies the same symbolic matcher to
the bounded clause database. It returns a stable clause identity, instantiated
premises, and a universe-checked substitution; multiple matches or a
head-unconstrained parameter remain ambiguous. Recursive inferred proof consults
clauses only after exact and generic implementations return no solution, merges
their constraints into the same root state, and composes clause, generic, and
exact premise chains under the same visited stack. Clause cycles and acyclic
overflow remain distinct. This does not add environment layering, implied
bounds, negative reasoning, projection predicates, or backtracking.

Standalone existential projection equality binds one projection goal and one
expected type term over the existing eight-parameter universe. It proves the
projection's trait obligation in the root inference state, reselects the exact
or generic implementation, instantiates its associated value, and unifies that
concrete or symbolic value with the expected term. Generic associated values
may recursively project through the existing fixed 16-frame projection stack;
cycles and acyclic depth exhaustion remain distinct. Exact input/output
refinement, generic parameter equality, premise-constrained selection,
mismatch, ambiguity, cycle, and overflow have focused tests. This is not a
general projection-bearing type grammar, a projection premise language,
predicate conjunction composition, backtracking, or source associated-type
syntax.

Bounded existential predicate conjunctions contain up to eight implemented-
trait or projection-equality predicates over one shared root inference state.
An ambiguous predicate rolls back its tentative constraints and is retried
after other predicates refine the state; a complete pass without a proven
predicate returns ambiguity. Contradictions, cycles, and overflow retain their
distinct fail-closed results, while an empty conjunction preserves each bound
variable as its own symbolic representative. This is bounded goal scheduling,
not backtracking: predicates are not branched, projection equalities are not yet
admitted as where-clause premises, and general projection-bearing type terms,
source syntax, caching, and coinduction remain absent.

Where clauses and generic implementations now admit projection-equality
premises alongside implemented-trait premises under one combined eight-entry
capacity. Construction validates every bound projection goal and expected term;
concrete, rigid, and existential instantiation preserve the exact associated-
type identity and substituted terms. Existing proof APIs lacking associated-
value environments return no solution rather than treating one as proven.
Projection-aware existential proof evaluates these premises through the exact
and generic associated-value environment described below; concrete and rigid
proof remain fail-closed.

Projection-aware existential proof schedules instantiated implemented-trait and
projection-equality premises in one shared root constraint state. Ambiguous
attempts roll back and retry after another premise refines the state;
contradictions remain no solution. Projection normalization recursively invokes
the same aware proof for projection-bearing generic implementations, with a
separate 16-transition premise/normalization nesting bound in addition to the
existing proof and projection stacks. Direct refinement, deferred mixed
premises, generic projection premises, nested proof, and adversarial recursive
overflow have focused tests. This is not backtracking, concrete or rigid
projection-premise proof, general projection-bearing type terms, or source
syntax.

Projection-bearing trait type terms use a fixed 64-node arena. Leaf nodes retain
concrete, inference, or placeholder terms; projection nodes retain an associated-
type identity and a trait goal whose self and arguments reference earlier arena
nodes. Backward-only references make the graph acyclic at admission, identical
nodes intern to one stable identity, invalid references and capacity overflow
fail explicitly, and recursive normalization is independently limited to 16
term frames. Normalization evaluates projections in self or argument position
through the projection-aware environment and returns both the final flat term
and recovered inference substitution. Nested argument projections, inference
refinement, invalid forward references, arena overflow, and normalization depth
overflow have focused tests. Whole projection-bearing goals normalize every
self/argument term in one shared state before exact, generic, and clause
selection plus projection-aware premise proof. A parallel bound-term arena
retains indexed generic parameters and instantiates them as distinct inference
variables in a caller-selected universe before using the same normalization and
proof path. Binder admission validates every parameter index and remaps interned
identities after instantiation. This does not add higher-ranked term binders,
projection terms to clause heads or premise type positions, or source
associated-type syntax.

Projection-bearing logical clause heads use a separate fixed 64-entry
identified database. Direct concrete or parameter leaf positions first bind
every clause parameter in the root inference state; the complete head is then
instantiated and normalized through the existing projection-aware environment
before it is unified with the query. Stable clause identities are retained,
duplicate identities and clauses fail explicitly, multiple matching clauses
remain ambiguous, and a parameter that occurs only beneath a projection fails
closed as ambiguous instead of being guessed. Focused tests cover projection
normalization that determines an existential substitution, a normalized
mismatch, and the unconstrained-parameter boundary. Each head may also retain
up to eight flat implemented-trait premises; the selected substitution
instantiates them and the existing projection-aware recursive proof must
discharge them before the candidate succeeds. Missing premises and premise
capacity have focused tests. An opt-in existential solver threads the same
projection-clause database, inference state, and 16-frame proof stack through
nested implemented-trait premises. Unique nested selection commits one copied
candidate state; multiple candidates remain ambiguous, cycles and depth
overflow remain explicit, and callers that do not supply the database retain
their previous closed behavior. This is bounded logical head elaboration with
flat premises only. A separate 64-entry projection-bearing generic-
implementation admission table establishes the first coherence gate. Different
trait/arity or an unequal concrete leaf proves heads disjoint; parameters,
projections, and every other unresolved relationship conservatively mean
potential overlap. Admission rejects duplicate identities, peer overlap, and
potential collisions with exact or flat-generic heads, while permitting heads
separated by an explicit concrete leaf. Premises never waive overlap.
Direct leaf positions across the complete head now feed the existing fixed
equality unifier, so repeated parameters, parameter unions, and concrete
constraints can prove disjointness even when other positions contain opaque
projections. The same repeated-parameter constraints apply against exact and
flat-generic heads. Projection nodes themselves never prove disjointness.
Existential selection copies the root constraint state per admitted candidate,
normalizes the complete head through the associated-value environment, proves
flat premises, and returns the stable generic implementation identity plus the
recovered substitution. Missing premises reject the candidate; ambiguity,
cycles, and overflow remain explicit. An opt-in general solver threads this
table through nested implemented-trait premises alongside projection-bearing
logical clauses. Admitted implementations are tried before logical clauses,
one successful copied state is committed, and the shared 16-frame stack reports
cycles and depth overflow. Legacy entry points remain closed. Projection-
bearing clauses and implementations may also retain bounded implemented-trait
premises whose self and argument positions reference the same validated term
arena as the head. Selection instantiates and normalizes those premises in the
shared root state before proof. One bounded mixed scheduler attempts flat and
term-bearing predicates in the same pass, rolls back ambiguous attempts, and
retries pending predicates after any sibling refines the state. Refinement works
in either direction, while a pass with no proof progress returns ambiguity.
This is fixed-capacity conjunction scheduling, not candidate backtracking.
Complete projection-
equation coherence, higher-ranked term binders,
backtracking, caching,
coinduction, and source associated-type syntax remain unsupported.

Rigid clause elaboration accepts goals containing only concrete types and rigid
placeholders. Bound parameters may match either term, repeated parameters require
exact equality, and instantiated premises retain the same placeholder universe
and identity. The 64-clause database preserves its unique/ambiguous/no-solution
classification for rigid queries; inference-bearing inputs fail explicitly.
This is bounded skolem matching, not recursive higher-ranked proof or general
unification.

```text
Complexity impact: LOW
TCB impact: LOW
New parser boundary: NO
New authority model: NO
New persistent state: NO
External dependency: NO
Failure isolated: YES
Existing-object reuse: HIGH
```
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
