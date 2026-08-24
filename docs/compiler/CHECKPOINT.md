# mrml-rustc durable checkpoint

This file is the short recovery record for the independent compiler lane. It
does not replace `docs/COMPILER.md`, the oracle records, or the detailed
evidence ledger in `crates/mrml-rustc/README.md`. If chat history or a local
worktree is lost, recover this checkpoint first and verify every claim against
the named commit and current source.

## Recoverable baseline

- Branch: `main`
- Compiler checkpoint commit: `6812ef8`
  (`compiler: invalidate call reborrow ancestors`)
- Remote state when recorded: `origin/main` is still at `2cfe524`. The named
  compiler checkpoint is committed locally after independently committed VMM
  and kernel work; pushing the combined mainline history awaits explicit owner
  approval after the repository safety review declined the mixed-scope push.
- Preceding compiler commits: `5c53eb9` (`compiler: track mutable tuple field
  moves`), `480a198` (`compiler: identify constant array
  elements`), `40a035c` (`compiler: analyze initializedness
  through expressions`), `daf9fb9` (`compiler: connect conditional
  expression flow`), `cbc6cc5` (`compiler: map conditional expression
  program points`), `7003640` (`compiler: identify conditional
  expression occurrences`), `8ddd42f` (`compiler: refine conditional event
  origins`), `df01b9b` (`compiler: retain ownership event
  origins`), `40d7544` (`compiler: reject linear use after
  move`), `1e0dc42` (`compiler: order ownership events`),
  `724f40b` (`compiler: classify call and return
  moves`), `3b8599e` (`compiler: distinguish borrow place
  effects`), `97b275d` (`compiler: classify exact Copy
  effects`), `147e15a` (`compiler: classify direct move and
  write effects`), `fbb7c27` (`compiler: project tuple move paths`), `1139f96`
  (`compiler: establish initialized move path roots`), `4879955` (`Preanalyze
  runtime assignment accesses`), `996ac72` (`Preanalyze runtime loop
  declarations`), `e393097`
  (`Preanalyze sequential runtime declarations`), `8b4a529`
  (`Preanalyze conditional branch local identities`),
  `acd1d64` (`Preanalyze bounded runtime body facts`), `486fc87`
  (`Discover bounded runtime read places`), `aac7798`
  (`Bound runtime place projection facts`), `308c781`
  (`Record stable runtime identifier reads`), and `099b11c` (`Retain bounded
  runtime place facts`).
- Oracle: `docs/compiler/oracles/ORACLE-0001.md`, rustc
  `1.100.0-nightly`, full commit
  `f7d782a3be46d6bb4b9792fe69a61db389ba1769`, dated 2026-08-19.
- Language direction: Rust 2024 is the edition floor. Contemporary and future
  Rust semantics are the target; obsolete editions, historical unsoundness,
  rustc internals, diagnostic wording, and unstable Rust ABI details are not
  standing compatibility requirements.

Do not replace the exact oracle with the newest installed nightly. A future
oracle upgrade receives a new immutable record and differential classification
against all prior accepted probes. Keep Cargo on edition 2024 until a newer
named edition can be adopted through a pinned, workspace-wide migration.

## Implemented ownership/place foundation

At the checkpoint commit, the runtime emitter has these bounded mechanisms:

- structured assignment bases with direct, dereference, index, or numeric
  tuple-field parser projections;
- checked monotonic `RuntimeLocalId` values that are not reused after scope
  cleanup;
- fixed tables of 256 retained local facts and 256 ordered place-access facts;
- stable local or parameter identity, type, span, and `Read`, `Write`, or
  `ReadModifyWrite` access intent;
- source-independent projection lists of at most four `Dereference`, summary
  `Index`, exact `ArrayElement`, `TupleField`, or `Subslice` steps. Direct
  owned-array reads and assignments refine an in-bounds compile-time index to
  its exact element number; runtime indexes, reference/slice indexes, compound
  bases, and internal aggregate materialization remain conservative summaries;
- projection/type validation, hole detection, tuple-field and exact-array-
  element bound checks, and explicit capacity failures; and
- read facts for direct identifiers plus the specialized local tuple-field,
  array-element, range, and address paths that bypass the scalar loader;
- bounded syntax discovery for identifier, dereference, index, tuple-field,
  subslice, transparent-wrapper, and sequence-tail read places; and
- direct scalar dereference emission that records one projected read without a
  duplicate empty base read;
- a standalone fixed-capacity body-fact object outside the x86 machine-code
  state; and
- a fixed 1,360-entry move-path table and 512-entry initialization-site table
  with one dense root path for every supported parameter and named local.
  Supported owned tuple roots immediately expand into one precisely numbered,
  typed child path per field. Tuple elements now retain bounded scalar values,
  thin scalar references, or scalar raw pointers; fat references, arrays, and
  nested tuples remain excluded. The derived capacity preserves all 256 retained
  locals and 16 supported ABI parameters at maximum tuple width. Parameter-entry
  and successful-local-declaration initialization origins retain their exact type
  and source span. Final validation requires deterministic parameter-then-local
  ordering, exact path/initialization pairing, matching local or parameter
  identity and type, exact root/child ordering, parent, tuple-field projection,
  valid spans, and complete coverage. Missing pairs, corrupt roots or children,
  cross-root parents, and capacity exhaustion fail closed before native output
  is accepted; and
- a fixed 768-entry place-effect ledger tied to validated move-path IDs. Direct
  identifier initialization of a mutable-reference binding records a `Move` on
  the source root. Direct root and precise tuple-field assignments record
  `Write` or `ReadModifyWrite` after their RHS read planning. Assignment reads
  derive their effect context from the typed RHS: an exact root of proven
  non-`Copy` type records `Move` before the destination write, while an exact
  root or tuple field of proven `Copy` type records `Copy`. An inferred exact
  mutable-reference tuple-field binding records a `Move`; moving it twice or
  consuming the incomplete tuple fails initializedness, while sibling fields
  remain independently usable and an exact field write restores completeness.
  Capacity failure cannot retain the read without its effect. Summary indexes,
  dereferences, other projected non-`Copy` reads, and tuple materialization
  remain unclassified.
  Direct shared and mutable borrows of an exact root, plus shared
  or mutable reborrows through a direct reference root, record `SharedBorrow` or
  `MutableBorrow` instead of being mislabeled as copies or moves. Reference
  indexing and summary projections remain unclassified. A zero-arena-growth
  derived view associates the latest matching same-origin borrow effect with a
  reference-local initialization and exposes a stable identity (the dense
  initialization index), borrower, borrowed move path, borrow kind, and issue-
  effect index. Shared-reference dereference and projection reads additionally
  record `LoanUse` on the borrower root. For a complete supported CFG, an exact
  mutable borrow after direct shared-loan issuance is rejected when the shared
  borrower is used later along a reachable bounded-CFG path. Direct mutable
  loans use the same traversal: a later exact-path copy, move, shared/mutable
  borrow, write, or read-modify-write is rejected when the mutable borrower is
  subsequently used. Loan uses are recorded only for locals with a derived
  direct loan, and final validation rejects a forged loan use on an unrelated
  reference. The fixed-capacity traversal covers entry, blocks, edges, returns,
  and genuine cycles without treating mutually unreachable points as ordered.
  This is bounded direct-loan liveness and invalidation evidence, not indirect
  alias tracking, regions, or complete NLL enforcement.
  Explicit direct mutable reborrows derive their parent loan and ultimate owner
  path with an initialization-count traversal bound. A parent use before a
  later child use reports a conflict, a parent use after the child’s last use is
  accepted, and owner-path conflicts follow the ancestry root. Shared-to-shared
  reborrows retain compatible shared parent reads. Mutation through a direct
  mutable-reference parent is separately classified from a loan read, so a
  live shared child blocks the former but preserves the latter until its last
  reachable use. An unconditional top-level explicit-borrow assignment to a
  mutable reference binding creates a new loan generation from the existing
  bounded write event. Uses select the latest generation, while children issued
  before replacement retain the old identity. Conditional statement
  replacements use a fixed 193-point reaching-definition traversal: bypass
  paths retain the old generation, exhaustive replacement kills it, and
  conflict-to-use queries do not combine mutually exclusive paths. A child
  issued with multiple reaching parent generations recursively preserves each
  possible ultimate owner and applies suspension to each mutable parent, with
  traversal bounded by the combined initialization/effect count. Direct
  assignments in loop operations, conditional loop actions, and nested loop
  actions now participate in the same reaching-definition analysis. A loop
  that can execute zero times retains the pre-loop generation; an unconditional
  replacement crossed before every exit kills it. Repeated dynamic issuances
  from one static assignment conservatively share that bounded generation
  identity. Conditional reference expressions used as a direct local
  initializer or direct assignment now retain one bounded loan origin per
  possible final branch value while sharing the destination initialization or
  write as their generation event. Nested alternatives are preserved;
  mutually exclusive sibling origins are not treated as sequential conflicts,
  and sequence-prefix temporaries are not promoted into destination origins.
  Moved reference values and non-direct conditional destinations are not
  indirect loan origins. This is not general coercion-site reborrowing.
  A plain direct reference identifier assigned into an existing typed reference
  binding uses the destination reference type as coercion context and records a
  shared or mutable reborrow before the destination write. Mutable parent
  suspension and last-use restoration then apply to the reassigned child.
  Projected, compound, conditional-RHS, and call-derived assignments remain
  outside this coercion-site classification.
  A direct identifier initializing an explicitly typed expected reference now
  records the corresponding shared or mutable implicit reborrow. The same
  identifier in an inferred mutable-reference binding remains a move, preserving
  use-after-move enforcement. Other coercion sites remain unclassified.
  Supported call
  arguments are classified from the resolved parameter type: exact non-`Copy`
  roots record `Move`, while explicit borrow syntax retains its borrow effect.
  Supported non-`Copy` returned source expressions propagate the same move
  context through transparent wrappers, sequence tails, and conditional
  branches. Sequence prefixes, conditions, indexes, arithmetic operands, and
  aggregate elements keep ordinary value context. Moves of `Copy` types,
  unsupported projected moves, read-modify-write on non-`Copy` paths, invalid
  IDs, holes, malformed
  spans, corrupt counts, incompatible `Copy` effects, and capacity exhaustion
  fail closed; and
- a derived fixed bound of 1,280 ownership events spanning all 512 possible
  initialization facts and 768 possible place effects. Each fact receives a
  dense monotonic event ID when it is appended, preserving parameter entry,
  RHS effects, successful local initialization, assignment effects, and return
  effects in their actual preanalysis order. Final validation merges the two
  append-only tables and requires exactly `0..event_count` with no holes,
  duplicates, inversions, or uncounted entries. Event-capacity failure occurs
  before mutating a path, initialization, read, effect, or counter. Event IDs
  remain independent of CFG numbering; their source origins can now be mapped
  on demand without enlarging every event fact; and
- insertion-time provenance on every initialization and effect. Parameter roots
  record `ParameterEntry`; preanalyzed body events record an exact bounded
  `TopLevelStatement(index)` or verified `Tail`; dynamically appended inlined-
  helper facts record `EmissionExpansion` and are explicitly excluded from
  source-order claims. Validation rejects unassigned origins, parameter-origin
  misuse, statement indexes outside the parsed body, tail origins on bodies
  without a tail, and invalid local-initialization origins; and
- a fixed-width conditional-expression branch path on every initialization and
  effect. The parent path owns condition evaluation; then/else traversal appends
  a zero/one bit, nested branches extend the path, and traversal restores the
  parent before post-join events. The existing parser/expression nesting bound
  limits paths to 64 branches. Final validation rejects excessive depth, set
  bits outside the declared depth, parameter facts outside the root path, and a
  leaked non-root traversal state. A fixed 1,280-entry conditional-occurrence
  table now assigns dense IDs and retains each conditional's enclosing ownership
  location, source span, parent occurrence, and parent path. Events retain the
  active occurrence ID, distinguishing nested and sequential conditionals that
  would otherwise share identical branch bits. Validation requires dense IDs,
  parent-before-child order, exact location agreement, a valid parent path, and
  an existing event occurrence; forged IDs, malformed parents, holes, and
  capacity exhaustion fail closed. A derived fixed 6,400-entry expression
  program-point table now assigns a root to each visited ownership location and
  condition, then, else, and join points to every conditional occurrence.
  Branches record exact exits, including nested joins; sequential conditionals
  enter from the prior join. Conditional construction preflights all required
  capacity before mutation. Validation rejects table holes, non-dense IDs,
  wrong point kinds or locations, missing/malformed exits, forged occurrence
  references, forged event points, and exhaustion. A second derived fixed
  6,400-entry table records exactly five canonical edges per occurrence: entry
  to condition, condition to both arms, and each actual branch exit to join.
  This composes nested joins into enclosing joins and sequences a later
  conditional from the prior join. Construction preflights the complete edge
  budget. Validation rejects holes, count mismatches, edge substitution or
  reordering, invalid endpoints, and disagreement with occurrence facts. Every
  expression point's ownership location must resolve to an existing
  statement/loop block, edge, or explicit unreachable point. Supported
  same-location expression graphs now require one root and sink and an exact
  point for every initialization/effect event. A structured bounded traversal
  follows straight-line points iteratively, descends only through the 64-level
  conditional nesting bound, intersects both arm states at each join, and feeds
  the sink state into the enclosing statement/loop control point. It uses no
  global per-point state matrix. Cross-location, incomplete, cyclic, duplicate,
  or otherwise unsupported shapes fail closed rather than disabling analysis;
  and
- parser-shape-validated conditional program points. Conditional-return events
  distinguish each branch condition from its true-return value and final else
  value. Conditional-assignment events distinguish each branch condition and
  every indexed branch/else action. Plain explicit returns have their own
  origin. A fixed 32-entry statement-shape table retains exact conditional
  branch counts, else presence, and the parser-bounded four action counts per
  branch plus else. Forged branch/action indexes, mismatched origin kinds, holes,
  and out-of-body statements fail validation. For complete supported CFGs,
  parameter entries map to function entry, top-level and conditional conditions
  map to exact blocks, conditional return values map to exact true/false return
  edges, and conditional branch/else actions map to their sourced blocks,
  including disconnected post-return suffixes. Reachable tails map to their
  unconditional return edge; syntactically retained tails after all-path
  termination map to an explicit `Unreachable` point rather than a fabricated
  block. Loop events now retain exact loop-header, operation, conditional-arm,
  action, return-value, nested-loop-header, nested-action, and ordered nested-
  control origins. Their control points resolve to the exact sourced CFG block
  or return edge. The parser-shape table retains each loop's bounded operation
  count, while CFG-source matching validates exact operation, arm, action, and
  control coordinates. Final place-fact validation requires every non-expansion
  origin to resolve. Missing or forged loop/action/control provenance fails
  closed. This mapping is derived from the bounded 64-block/128-edge CFG and
  adds no per-event table; and
- bounded fixed-point initializedness enforcement across every reachable block
  and edge of a complete supported statement/loop CFG, composed with the
  supported conditional-expression subgraphs described above. Two fixed
  64-block by 22-word bitset matrices retain definite input/output state for
  all 1,360 move paths. Incoming paths use intersection, entry participates as
  an explicit predecessor, and exact edge events transfer before successor
  joins. Convergence is bounded by `block_count * move_path_count + 1`; missing
  predecessors, malformed dense block IDs, corrupt facts, or non-convergence
  fail closed. Preconditions are checked only against the converged states, so
  transient iteration state cannot create a false use-after-move report.
  Parameter/local initialization marks roots and tuple children initialized;
  exact moves clear roots and descendants; copies, moves, shared/mutable borrows,
  and read-modify-write require prior initialization; exact writes restore paths,
  and child writes recompute tuple-root completeness. A second straight-line
  move reports `RuntimeUseAfterMove`. Early-return edges remain path-specific,
  while a move on one continuing conditional arm or before a loop exit poisons
  the joined path. Conditional expression nodes still disable enforcement
  because their arm events do not yet have distinct control points, closing the
  observed mutually-exclusive-tail false positive; and
- pre-emission typing and stable identity assignment for every declaration form
  represented by the supported runtime body and loop parsers, mirroring pre-loop,
  loop, nested-loop, conditional-arm, and post-loop emission order with exact
  scoped-environment restoration and consumption validation; and
- a separate fixed 256-entry expectation table that pre-resolves every supported
  non-wildcard assignment target to stable identity, projections, type, access
  class, and span without disturbing the emitted read/write ledger's true order;
  and
- a separate fixed 256-entry expectation table for assignment RHS expressions
  whose root is a discoverable place, resolved against the exact active scope
  and consumed through the ordinary identifier-read path; and
- bounded recursive assignment-RHS traversal for casts, ascriptions, unary
  wrappers, return/break values, sequences, binary operands, and conditional
  condition/arms in exact emission order, with one fact per discovered place;
  and
- typed index dispatch that distinguishes reference-base reads, one constant
  local-array element read, and every runtime local-array materialization read
  before its runtime index; and
- scalar local-initializer read planning before binding activation, preserving
  previous-binding identity across sequential and scoped shadowing, including
  source-ordered scalar operands of direct array literals, single-evaluation
  array repeats, and tuple literals, plus exact per-element projections for
  direct identifier-backed array and tuple copies and single-condition planning
  for conditional tuple initializers with direct literal branches, plus exact
  repeated-condition per-element planning for direct conditional array literals;
  plus exact prefix-once tuple and prefix-per-element array planning for direct
  sequence-wrapped literals; plus direct, direct-identifier conditional, and
  sequence-prefix/direct-identifier-tail fat-reference initializer reads; plus
  runtime range-endpoint reads followed by exact slice/string base reads, with
  a `Subslice` projection for local-array bases; recursive 64-level-bounded
  conditional, transparent return/break/inline-const, and sequence composition
  of those non-call fat-reference forms; plus direct, range-derived, and
  recursively conditional fat-reference explicit-return and final-tail reads;
  plus sequence-prefix and left-to-right argument reads for call-derived fat-
  reference initializers whose arguments are one-slot scalars, supported fat
  references, direct identifier-backed arrays and tuples, array literals or
  single-evaluation repeats, direct conditional arrays with literal branches,
  arrays accepted by a 64-level-bounded recursive per-element planner, including
  identifiers, contextual defaults, literals, repeats, integer-to-byte arrays,
  direct and wrapped array-producing calls, conditionals, transparent return/
  break/inline-const wrappers, and nested sequences, plus tuple-producing calls
  and bounded tuple value/field planners that mirror whole-value condition,
  sequence, inline-const, literal, identifier, and call lowering as well as
  per-field return, loop-break, ascription, and nested-sequence lowering,
  with one `Index` read per identifier-array element and numbered `TupleField`
  reads for identifier tuples, and with a sequence-array prefix repeated before
  every materialized element and nested branch prefix, exact `Index` reads
  retained for identifier tails, no invented element-place reads for contextual
  defaults, direct root repeats kept on their single-evaluation path, and scalar
  integer bases repeated once per emitted byte, direct array calls planned once,
  wrapped array calls planned once per materialized element, direct or
  whole-value-wrapped tuple calls planned once per tuple, and tuple calls below
  a per-field wrapper planned once per materialized field;
  and
- scalar expression-statement read planning across top-level bodies,
  conditional arms, direct loop actions, nested loop actions, and post-loop
  statements in the emitter's exact scoped order; and
- scalar read planning for top-level branch conditions and returns, while-loop
  heads, direct conditional loop controls, conditional loop blocks/arms and
  branch-local returns, explicit scalar returns, final scalar tails, and
  interleaved nested-loop controls in exact action-boundary/control order.
  Direct aggregate-producing calls used as supported explicit return operands
  or final tails now reserve their recursively validated arguments in call
  order. Complete direct fixed-array literals reserve their elements once in
  source order, and exact-count direct array repeats reserve their operand once;
  direct array identifiers reserve one indexed read per materialized element.
  Fixed-array materialization now preserves Rust single-evaluation semantics
  across returns, locals, discarded values, assignments, and call arguments.
  Sequence prefixes and conditions execute once per aggregate, selected
  branches and wrapped array-producing calls materialize once, and integer
  byte-conversion bases are saved once before byte extraction. Complete literal
  elements remain evaluated once in source order, identifiers retain indexed
  read evidence, and direct repeats retain their single operand evaluation.
  Aggregate admission is syntax-based, so unsupported packed aggregates cannot
  fall through the scalar planner. Supported tuple-value explicit returns and
  final tails now use the bounded whole-value tuple planner: sequence prefixes
  and conditions are reserved once, literal fields remain in source order,
  identifier copies retain numbered `TupleField` projections, and tuple-producing
  call arguments remain left-to-right. Public tuple transport remains
  unsupported; this evidence work does not invent an unstable Rust tuple ABI.
  Supported compound fixed-array index bases now reuse the same bounded whole-
  array planner before the index read, covering literal, conditional, wrapped,
  identifier, repeat, integer-byte, and array-producing-call materializers
  without guessing unsupported shapes.
  Non-call fat-reference returns now accept the emitter's bounded return/break/
  inline-const wrappers, sequence prefixes, and both conditional forms. Their
  read preanalysis mirrors the same recursion and source order. Direct and
  wrapped call-derived fat returns now validate their bounded call arguments,
  preserve left-to-right evidence, retain the System V register pair, and use
  checked hidden-pointer transport for the Windows return buffer.
  Other aggregate return/tail shapes remain outside preanalysis.
- initial fixed-capacity basic-block and control-flow-edge facts for supported
  top-level straight-line statements, simple and chained conditional returns,
  conditional action blocks, explicit returns, and final-tail return flow.
  Blocks carry stable IDs, exact top-level statement ranges, reachability, and
  explicit top-level, condition, branch-action, or else-action provenance;
  edges target another block or function return and distinguish true, false,
  and unconditional flow. Exhaustive `else if` return chains end in a false
  return edge, while non-exhaustive chains route the final false edge through an
  explicit top-level continuation block. Conditional action branches similarly
  route through explicit action and join blocks, and all-path final returns mark
  later top-level blocks unreachable. The tables are capped at 64 blocks and
  128 edges with explicit capacity errors.
  Initial top-level loop facts additionally represent `while` true/false
  headers, unconditional-loop entries, exact contiguous operation ranges,
  backedges, and ordered simple or conditional break/continue/return targets.
  Conditional loop blocks now add separately sourced condition and action
  blocks for primary, `else if`, and final `else` arms, with explicit joins and
  break/continue/return targets. Exhaustive all-terminal chains are detected
  structurally; malformed arm ranges/order and later unreachable operations
  fail closed. Nested loop blocks now use dedicated headers plus ordered action
  and control blocks; parser-resolved inner and outer break/continue targets,
  conditional returns, nested entry-condition exits, and divergent backedges
  are represented without replaying preceding outer operations. Duplicate,
  missing, or out-of-range control-order metadata fails closed. The parser's
  dedicated immediately-breaking `NestedUnitLoop` form remains inside the
  enclosing contiguous operation range, matching its existing no-op emitter
  semantics. Direct, conditional-block, and nested-loop operations after an
  unconditional terminal now begin disconnected unreachable blocks. Syntactic
  exits in those blocks do not make an enclosing continuation reachable.
  Conditional-assignment actions after a return now receive the same explicit
  treatment: bounded, separately sourced suffix blocks are disconnected and
  unreachable, have no incoming edge, and preserve their own return or join
  edge without making an enclosing continuation reachable. This closes the
  known CFG-suffix gap for runtime forms admitted by the supported parser.

The compiler core remains `no_std`, forbids unsafe code, uses no global
allocator, emits COFF and ELF64 for the documented subset, and fails closed on
unsupported semantics.

This is an initial typed body-fact slice, not a complete typed body IR and not a
borrow checker. Unsupported aggregate-leaf call arguments, other aggregate-
argument and call-derived fat-reference initializers, unsupported compound array
bases, method/call families, unsupported tuple-value shapes, and other body reads
remain emission-time facts.
Names are still
resolved during
emission, expanded inlined-helper declarations append dynamically, and read-
place discovery is not yet body-wide. Parser locals do not yet carry these IDs.
Array-element move paths and remaining indirect move/borrow classification,
unsupported expression/control-flow forms, complete loans, indirect alias
invalidation, unsupported coercion sites, regions,
Polonius-style analysis, and a general trait solver are unimplemented. The root
initialization sites do not claim that unreachable or divergent declarations
execute.

## Next compiler work

Continue the dependency chain instead of filling arbitrary historical Rust
compatibility gaps:

1. supported owned arrays currently contain only `Copy` scalar elements, and
   modern Rust rejects indexed moves from non-`Copy` arrays. Do not add array
   move paths until a supported legal operation such as bounded destructuring
   requires them, and never turn summary runtime indexes into exact paths;
2. extend indirect alias invalidation and full reborrow semantics beyond the
   direct shared-loan conflict set and bounded multi-level mutable-ancestor
   suspension, then stage flow-sensitive outlives reasoning with independent accepted/rejected
   probes.

Return coercion sites now apply the declared shared or mutable reference context
to direct, projected, and conditional reference places in explicit returns,
conditional returns, supported loop returns, conditional action returns, and the
tail. Explicitly typed reference locals therefore reborrow at the function
boundary; inferred non-`Copy` bindings remain consuming moves. Unsupported
indirect shapes retain conservative move classification.

Modern trait solving, naked functions/`naked_asm!`, inline assembly, security
profiles, and compiler-derived executable metadata remain important later
milestones. Do not attempt the complete borrow checker or trait solver in one
patch, and do not discard the existing compiler implementation.

## Clean-install toolchains

Windows uses GNU/LLVM (`x86_64-pc-windows-gnullvm`), not MSVC. With rustup
already installed, install the pinned nightly and target components required by
the repository before testing. The exact dated oracle toolchain must remain
available for black-box oracle work; the workspace `rust-toolchain.toml` also
requires `rustfmt`, `clippy`, `rust-src`, `nvptx64-nvidia-cuda`, and
`x86_64-unknown-uefi`.

On Arch Linux, install the native build prerequisites required by the linker and
use rustup's `nightly-x86_64-unknown-linux-gnu` toolchain with the same declared
components and targets. Do not infer successful cross-host verification from a
Windows-only run.

## Last complete verification

The checkpoint source passed 746 tests on each host: 408
library tests, 10 conformance tests, 326 replacement tests, and 2 driver tests.
Warnings-denied Clippy also passed on both hosts. The commands were:

```powershell
$env:RUSTFLAGS='-C link-arg=/stack:16777216'
cargo +nightly-2026-08-20-x86_64-pc-windows-gnullvm test -p mrml-rustc -p mrml-rustc-driver --target x86_64-pc-windows-gnullvm --offline
cargo +nightly-2026-08-20-x86_64-pc-windows-gnullvm clippy -p mrml-rustc -p mrml-rustc-driver --target x86_64-pc-windows-gnullvm --all-targets --no-deps --offline -- -D warnings
```

```sh
cd /mnt/c/Users/Mitch/Documents/mrml
cargo +nightly-2026-08-20-x86_64-unknown-linux-gnu test -p mrml-rustc -p mrml-rustc-driver --target x86_64-unknown-linux-gnu --release --offline
cargo +nightly-2026-08-20-x86_64-unknown-linux-gnu clippy -p mrml-rustc -p mrml-rustc-driver --target x86_64-unknown-linux-gnu --release --all-targets --no-deps --offline -- -D warnings
```

The separately installed 2026-08-23 Arch nightly at commit
`fb6531d550e0075b9eb9a51464f404805eec87d9` crashed in LLVM `PromotePass` while
building the release test binary. That compiler-host failure is recorded but is
not passing evidence and does not replace the pinned oracle generation.

The hygiene scan must remain empty:

```sh
rg -n "(^|[^A-Za-z])(std|alloc)::|unsafe\s*\{" crates/mrml-rustc/src crates/mrml-rustc-driver/src
```

Format only the compiler packages, preserve unrelated worktree changes, stage
overlapping documentation hunks interactively, fetch before pushing, never
force-push, and update this checkpoint after every pushed compiler milestone.
