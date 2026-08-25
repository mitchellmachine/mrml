# mrml-rustc durable checkpoint

This file is the short recovery record for the independent compiler lane. It
does not replace `docs/COMPILER.md`, the oracle records, or the detailed
evidence ledger in `packages/compiler/core/README.md`. If chat history or a local
worktree is lost, recover this checkpoint first and verify every claim against
the named commit and current source.

## Recoverable baseline

- Branch: `main`
- Compiler checkpoint commit: `0350249c`
  (`build: move compiler driver`)
- Remote state when recorded: `origin/main` includes the behavior-preserving
  compiler core/driver relocation to `packages/compiler/core` and `packages/compiler/driver`,
  exact recovery/review path updates, and Windows verification. The driver push
  from `3ed363de` to `0350249c` was a verified fast-forward; no compiler or
  driver semantics changed.
- Preceding compiler commits: `9a950ae9` (`build: move compiler core`),
  `885ba7b7` (`compiler: validate nested loop
  returns`), `5c53eb9` (`compiler: track mutable tuple field
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
- Current build/oracle: `docs/compiler/oracles/ORACLE-0002.md`, rustc
  `1.100.0-nightly`, full commit
  `fb6531d550e0075b9eb9a51464f404805eec87d9`, dated 2026-08-23 and
  distributed as `nightly-2026-08-24`. Preserve ORACLE-0001 as the prior
  generation.
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
  alias tracking, regions, or complete NLL enforcement. Moving an intermediate
  local reference ancestor is also checked against live shared or mutable child
  loans. Projected reference paths use their bounded move-path parent chain, so
  moving the containing tuple conflicts while sibling-field moves remain
  disjoint. Malformed or cyclic parent chains fail closed. Bounded last-use
  reachability restores the move after the child dies, and replacing a reference
  binding retains the existing generation semantics. A direct mutable-reference
  value moved into an inferred local now carries its single direct loan origin
  through bounded, event-decreasing one-hop or chained moves. The lookup selects
  the source's latest direct initialization or assignment generation, so an old
  owner is not revived after reassignment. One immediate precise root move of a
  conditional expression-generation now derives one destination loan per
  existing branch-origin effect. The derived category is bounded by the place-
  effect capacity, retains each origin independently, and refuses derivation
  across a source-generation replacement. The same derivation now enumerates
  every origin at every move depth up to the actual bounded initialization
  count. Checked `initialization_count * effect_count` work and depth-qualified
  loan IDs preserve intermediate generations and reject missing or replaced
  hops without collapsing the chain to its terminal binding.
  A direct move from one reference-typed field of a directly initialized tuple
  now retains that field's exact shared or mutable loan origin. Correlation is
  limited to a validated one-step numeric tuple-field path whose tuple
  initialization contains exactly the expected number and order of borrow
  effects. An intervening root/field write, mismatched mutability, malformed
  path, or ambiguous effect shape refuses derivation. Sibling owners remain
  disjoint and bounded last-use reachability still restores owner access.
  Once the projected field origin enters a direct local, the existing bounded,
  event-decreasing root-move traversal preserves it through later two- and
  three-hop move chains. Latest-generation selection prevents an intervening
  reassignment from reviving the tuple field's old owner. A later directly
  initialized tuple may now consume that local and expose its reference field as
  another projected source: the same exact tuple-value correlation is followed
  before the remaining direct move chain continues. Each projected hop still
  requires one numeric field, exact reference-value count/order and mutability,
  and no unclassified intervening root or field replacement. A direct tuple-
  field reference reassignment is classified separately: a later move now uses
  that latest exact borrow generation rather than losing the reassigned owner's
  ancestry. Nested projections and general aggregate provenance remain
  unimplemented.
  A separate bounded return-outlives pass now runs for declared reference-return
  functions with complete CFG facts. Exact tail, explicit, conditional, and
  supported loop return-value effects trace reference ancestry through the active
  generation at each successively earlier issuance event. Parameter roots
  outlive the function; direct or projected local storage, missing ancestry,
  mismatched reference mutability, malformed facts, ambiguous provenance, and
  bound exhaustion fail closed with `RuntimeReferenceOutlivesFunction` or the
  existing invalid-fact error. The relation preserves direct parameter returns,
  explicit reborrows, moved mutable parameters, latest-generation replacement,
  cyclic reborrow generations, exact tuple-field initialization or reassignment
  origins, and one- or multi-hop direct shared-reference copies. Copy ancestry
  requires the exact immediately preceding local-initialization effect with
  matching expression identity and reference mutability; mutable references
  still require a move. Ambiguous nested-loop control coordinates, general
  regions, named lifetime relationships, and complete Polonius outlives
  reasoning remain unimplemented.
  Return expressions inside conditional action blocks now have a distinct,
  shape-validated ownership location mapped to the action block's exact
  unconditional return edge. This lets the outlives pass reject direct and
  locally stored identity-call results backed by local storage while preserving
  equivalent parameter-backed calls. Exact reference-typed `Copy` and `Move`
  return effects are checked alongside borrow effects; non-reference value
  effects and ordinary conditional actions remain outside this gate.
  Primary and else-arm `ConditionalLoopTerminal::Return` expressions now use
  return-context preanalysis and their existing shape-validated terminal
  location maps to the exact unconditional CFG return edge. The outlives pass
  rejects an identity-call result backed by loop-local storage while preserving
  the equivalent parameter-backed return. Ordinary loop actions and `break`
  terminals are not promoted into this gate; general lifetime relationships
  remain separate future work.
  Nested-loop unconditional and conditional return values now also use return-
  context preanalysis. Their existing shape-validated action index and ordered
  control coordinate maps to an exact CFG return edge, and only nested controls
  that carry a return value use `NestedLoopControlValue`. Local-backed identity
  results are rejected while parameter-backed equivalents are preserved.
  Nested conditional conditions, `break`, `continue`, ordinary actions, and
  general region relationships remain outside this bounded gate.
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
   direct shared-loan conflict set, bounded multi-level mutable-ancestor
   suspension, and bounded repeated direct tuple-field sources, then stage
   flow-sensitive outlives reasoning with independent accepted/rejected probes.

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
`x86_64-unknown-none` and `x86_64-unknown-uefi`.

On Arch Linux, install the native build prerequisites required by the linker and
use rustup's `nightly-2026-08-24-x86_64-unknown-linux-gnu` toolchain with the same
declared components and targets. Do not infer successful cross-host verification
from a Windows-only run.

## Current oracle verification

The conditional projected-reassignment milestone preserves bounded ancestry for
both owners of a supported conditional reference RHS and for the tuple field's
replaced initialization owner. ORACLE-0002 rejects live-child mutation of each
possible owner with E0503, accepts unrelated mutation, and accepts both branch-
owner mutations after the child's last use. The MRML native frontend passed 420
library tests, one component-interface probe, 10 conformance tests, and 335
replacement tests on Windows gnullvm and native Arch Linux WSL: 766 compiler
tests per host. The unchanged driver and warnings-denied Clippy were not
re-executed for this milestone.
The same exact oracle and cross-host suites also verify two successive field
reassignments: all three owners remain protected while the moved descendant is
live, unrelated mutation is accepted, and all owners are released after its
last use.

The projected conditional-return outlives milestone checks every retained
origin of the latest exact tuple-field assignment. ORACLE-0002 rejects a return
whose conditional generation may reference local storage with E0515 and accepts
direct projected parameter storage plus a conditional generation whose branches
both trace to that parameter. The Windows gnullvm and native Arch Linux WSL
frontend suites each pass the same 766 compiler tests. Formatting and the
`no_std`/no-allocation/unsafe hygiene scan pass. The current Manifest V2
workspace has no Cargo package named `mrml-rustc`, so the obsolete direct Cargo
Clippy command was rejected before compilation; warnings-denied Clippy is not
claimed for this milestone.

The conditional tuple-initialization return milestone applies the same proof to
origins created while the tuple root is initialized. ORACLE-0002 rejects a
returned field whose branch may borrow local storage and accepts both parameter-
backed branches. Two-reference-field controls prove that a local-backed sibling
does not affect the selected returned field in either field position. Windows
gnullvm and native Arch Linux WSL each pass the same 766 compiler tests.

Nested conditional tuple-field origins now normalize each leaf's bounded
conditional-parent chain to its outer generation. ORACLE-0002 rejects a
three-leaf generation with one local-backed leaf and accepts the equivalent
all-parameter generation. Both host suites remain green at 766 compiler tests.

The branch-reaching projected-return milestone checks the original tuple-field
generation plus every assignment generation that can reach the return. The
oracle rejects a local-backed write in either branch, an old local-backed
initialization even after replacement, and a final sequential local-backed
write; it accepts branch and sequential controls whose generations are all
parameter-backed. Both host suites remain green at 766 compiler tests.

The loop-carried projected-return milestone retains reachable local-backed field
writes across a zero-or-more-iteration loop, including a local generation later
replaced in the same iteration. It accepts the parameter-backed equivalent and
an unreachable write after unconditional `break`. The latter requires both
entry-to-generation and generation-to-return CFG reachability, not event order
alone. Both host suites remain green at 766 compiler tests.

Moved projected-return evidence now covers direct and conditional tuple-field
initializations plus mutually exclusive field assignments before the field is
moved into a local and returned. Local-backed reachable origins fail with the
bounded outlives diagnostic, all-parameter origins pass, and a disconnected
post-`break` local write remains excluded. Both hosts pass 766 compiler tests.

Projected identity-call return evidence covers a conditional mutable-reference
tuple field returned directly through the call and through one stored call
result. ORACLE-0002 and MRML reject the mixed local/parameter origin set and
accept the all-parameter set. Both hosts pass 766 compiler tests.

The first trait-goal foundation adds fixed-capacity implemented goals and
first-occurrence canonicalization without source syntax or selection. Concrete
types, inference variables, placeholders, and canonical bound variables are
distinct; alpha-equivalent goals canonicalize equally; argument and variable
overflow fail explicitly. Windows gnullvm and native Arch Linux WSL each pass
425 library tests, one component-interface probe, 10 conformance tests, and 335
replacement tests: 771 compiler tests per host. The unchanged driver was not
re-executed.

The exact trait-impl selection milestone adds a fixed 64-header database.
Duplicate implementation IDs and overlapping exact heads fail; rigid concrete
queries return one exact implementation or no solution; inference-bearing
matches remain ambiguous without manufacturing substitutions; repeated
canonical variables must bind to equal concrete types. Windows gnullvm and
native Arch Linux WSL each pass 431 library tests, one component-interface
probe, 10 conformance tests, and 335 replacement tests: 777 compiler tests per
host. Generic impls, where-clauses, projections, cycles, and source integration
remain unsupported.

The bounded trait-answer milestone represents the exact per-candidate bindings
instead of discarding them. One matching concrete header now returns its stable
implementation identity and an eight-slot canonical-variable substitution;
multiple matching inference answers remain ambiguous, mismatches return no
solution, and repeated variables still require equal concrete types. Windows
gnullvm and native Arch Linux WSL each pass 432 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 778 compiler
tests per host. Generic impls, where-clauses, projections, recursive goals,
answer composition, and source integration remain unsupported.

The bounded response-substitution milestone retains the original inference-
variable identities alongside the canonical goal and maps a unique answer back
to those identities in first-occurrence order. Missing bindings or mismatched
response arity fail closed, and lookup remains fixed-capacity and allocation-
free. Windows gnullvm and native Arch Linux WSL each pass 433 library tests, one
component-interface probe, 10 conformance tests, and 335 replacement tests: 779
compiler tests per host. This does not add generic unification, nested answer
composition, where-clauses, projections, recursive goals, or source integration.

The bounded predicate-conjunction milestone stores up to eight implemented-
trait predicates and canonicalizes the entire conjunction in one shared eight-
variable universe. Reused inference identities remain equal across predicate
boundaries; predicate-count and cross-predicate variable overflow fail
explicitly. Windows gnullvm and native Arch Linux WSL each pass 436 library
tests, one component-interface probe, 10 conformance tests, and 335 replacement
tests: 782 compiler tests per host. This is representation and canonicalization,
not where-clause elaboration, binders, generic impls, recursive solving, or
answer composition. `mrml build mrml-rustc`, formatting, the core hygiene scan,
manifest validation, `doctor`, and `audit` pass. The documented Cargo Clippy
selector was rejected before compilation because `mrml-rustc` is no longer a
Cargo package, so this checkpoint claims no new Clippy evidence.

The bounded where-clause binder milestone represents one consequence and up to
eight premises over eight indexed generic parameters. Construction rejects
unbound parameters and excess parameter capacity; concrete instantiation
requires exact arity and substitutes repeated parameters consistently through
the entire clause. Windows gnullvm and native Arch Linux WSL each pass 438
library tests, one component-interface probe, 10 conformance tests, and 335
replacement tests: 784 compiler tests per host. This does not elaborate clauses,
select generic impls, introduce source syntax, normalize projections, or recurse.

The single-clause elaboration milestone matches a fully concrete query against
one bound consequence, infers its fixed generic arguments, and instantiates the
premises only when every parameter is constrained. Repeated parameters require
equal concrete types; mismatch is no solution, unconstrained parameters are
ambiguous, and nonconcrete queries fail closed. Windows gnullvm and native Arch
Linux WSL each pass 439 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 785 compiler tests per host. No
clause database, multi-candidate combination, recursion, or cycle handling exists.

The identified clause-database milestone stores up to 64 bounded where clauses.
Duplicate stable IDs and structurally identical clauses fail; distinct
potentially overlapping clauses are retained, while queries with multiple
matching candidates or an unconstrained candidate return ambiguity. One unique
candidate returns its stable clause ID and instantiated premises. Windows
gnullvm and native Arch Linux WSL each pass 443 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 789 compiler
tests per host. Premises are not recursively solved and cycles are not entered.

The bounded recursive-proof milestone composes exact concrete implementation
facts with the premises of one unique clause through a fixed 16-goal stack. It
returns distinct proven, no-solution, ambiguous, cycle, and overflow outcomes;
cycle detection precedes the boundary overflow classification. Windows gnullvm
and native Arch Linux WSL each pass 447 library tests, one component-interface
probe, 10 conformance tests, and 335 replacement tests: 793 compiler tests per
host. Inference-bearing recursion, caching, coinduction, projections, and source
integration remain unsupported.

The exact associated-type normalization milestone adds a fixed 64-value table
keyed by stable implementation and associated-type IDs. Insertion rejects stale
implementation references, duplicate keys, and overflow. Normalization reuses
canonical implementation selection and preserves unique, ambiguous, and no-
solution outcomes. Windows gnullvm and native Arch Linux WSL each pass 450
library tests, one component-interface probe, 10 conformance tests, and 335
replacement tests: 796 compiler tests per host. Generic associated values,
nested projections, source syntax, and recursive normalization remain absent.

The rigid-placeholder universe milestone distinguishes a placeholder's stable ID
from its explicit 16-bit universe. Bound clauses instantiate each parameter as a
distinct rigid placeholder in a caller-selected universe; canonicalization
preserves universe identity, separate universes remain unequal, and advancing
past the universe ceiling fails explicitly. Windows gnullvm and native Arch
Linux WSL each pass 452 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 798 compiler tests per host. Leak
checking, higher-ranked matching, universe relations, and `for<...>` syntax are
not implemented.

The inference-universe leak-check milestone includes creation universe in every
inference-variable identity while retaining `new(id)` for root variables.
Canonicalization distinguishes equal numeric IDs created in different
universes. Checked assignments reject newer-universe placeholders and inference
variables while accepting concrete and same-or-older-universe values. Windows
gnullvm and native Arch Linux WSL each pass 454 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 800 compiler
tests per host. This is not higher-ranked candidate matching, general
unification, or source `for<...>` support.

The rigid clause-matching milestone elaborates bound consequences against goals
containing concrete types and skolem placeholders. Repeated parameters require
exact placeholder identity, instantiated premises retain the matched universe,
and the fixed clause database preserves unique, ambiguous, and no-solution
outcomes. Inference-bearing rigid queries fail explicitly. Windows gnullvm and
native Arch Linux WSL each pass 456 library tests, one component-interface
probe, 10 conformance tests, and 335 replacement tests: 802 compiler tests per
host. Recursive rigid proof, general unification, and source `for<...>` remain
unsupported.

The flat generic-head coherence milestone adds a fixed 64-entry identified
implementation table. A fixed 16-node equality unifier decides exact overlap for
the current concrete/parameter head language across both binders, including
repeated-parameter constraints and conflicting concrete assignments. Duplicate
IDs, satisfiable overlap, and overflow fail. Windows gnullvm and native Arch
Linux WSL each pass 461 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 807 compiler tests per host.
Premise satisfiability, cross-family coherence, specialization, and source impl
syntax remain unsupported.

The coherent generic-selection milestone matches concrete queries against the
admitted generic implementation table. One fully constrained head returns its
stable implementation ID and instantiated premises; no head returns no solution,
and a parameter absent from the head remains ambiguous. Inference-bearing
queries fail explicitly. Windows gnullvm and native Arch Linux WSL each pass 463
library tests, one component-interface probe, 10 conformance tests, and 335
replacement tests: 809 compiler tests per host. Recursive generic-implementation
proof, specialization, and source impl syntax remain unsupported.

The recursive generic-proof milestone composes concrete generic selection with
the existing 16-frame proof stack. Instantiated premises may resolve through
exact facts, further generic implementations, or bounded where clauses; missing
premises, ambiguity, cycles, and overflow remain distinct. A simultaneous exact
and generic match fails closed as ambiguity until cross-family admission is
coherent. Windows gnullvm and native Arch Linux WSL each pass 466 library tests,
one component-interface probe, 10 conformance tests, and 335 replacement tests:
812 compiler tests per host. Inference-bearing generic proof, specialization,
cross-family coherence, and source impl syntax remain unsupported.

The cross-family coherence milestone adds symmetric bounded admission paths for
exact and generic implementations. Either insertion order rejects a concrete
header that instantiates a generic head, including repeated-parameter equality;
disjoint heads remain admissible. Runtime selection retains defensive ambiguity
for databases constructed through older unchecked paths. Windows gnullvm and
native Arch Linux WSL each pass 468 library tests, one component-interface
probe, 10 conformance tests, and 335 replacement tests: 814 compiler tests per
host. Premise-aware coherence, specialization, and source impl syntax remain
unsupported.

The generic associated-type normalization milestone adds a separate fixed
64-value table keyed by stable generic-implementation and associated-type IDs.
A value may be concrete or refer to one bound implementation parameter. The
normalizer retains the selected implementation substitution and requires its
recursive premises to prove before producing a value. Missing premises and
values return no solution; unchecked collisions, proof cycles, and proof
overflow remain ambiguous. Stale IDs, duplicate keys, and unbound parameters
fail explicitly. Windows gnullvm and native Arch Linux WSL each pass 471 library
tests, one component-interface probe, 10 conformance tests, and 335 replacement
tests: 817 compiler tests per host. Nested projection terms, premise projection
goals, specialization, and source associated-type syntax remain unsupported.

The unified concrete-projection milestone selects coherently across the exact
and generic implementation families before consulting their separate bounded
value tables. Exact facts return exact values; generic values retain recursive
premise proof and parameter substitution. Absent implementations or values
return no solution, while unchecked family collisions fail closed as ambiguity.
Windows gnullvm and native Arch Linux WSL each pass 473 library tests, one
component-interface probe, 10 conformance tests, and 335 replacement tests: 819
compiler tests per host. Nested projections, projection answer composition,
specialization, and source associated-type syntax remain unsupported.

The bounded nested-projection milestone lets a generic associated value contain
a projection template over its implementation binder. Selection substitutes the
template and recursively normalizes through either implementation family. A
separate 16-frame visited stack reports exact projection cycles and acyclic
overflow distinctly; invalid template parameters fail at admission. Windows
gnullvm and native Arch Linux WSL each pass 476 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 822 compiler
tests per host. Projection-bearing type arguments and premises, inference
projections, coinduction, specialization, and source syntax remain unsupported.

The rigid generic-selection and proof milestone generalizes retained generic
substitutions to concrete-or-placeholder terms. Rigid selection preserves exact
placeholder identities and universes, rejects repeated-parameter mismatches, and
recursively proves instantiated generic or rigid-clause premises through the
existing 16-frame stack. Missing premises, ambiguity, cycles, and overflow remain
distinct; inference-bearing inputs fail explicitly. Windows gnullvm and native
Arch Linux WSL each pass 480 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 826 compiler tests per host. Mixed
inference/skolem unification, binder introduction, coinduction, specialization,
and source higher-ranked syntax remain unsupported.

The universal trait-goal milestone adds an explicit binder over at most eight
implemented-trait parameters. It advances a caller-relative universe, creates a
distinct rigid placeholder for each parameter, and proves the instantiated goal
through rigid generic solving. Invalid indices and universe exhaustion fail;
unconstrained implementation parameters remain ambiguous. Windows gnullvm and
native Arch Linux WSL each pass 483 library tests, one component-interface probe,
10 conformance tests, and 335 replacement tests: 829 compiler tests per host.
Nested binders, leak-aware answer inversion, mixed generic inference, and
`for<...>` source syntax remain unsupported.

The exact existential trait-goal milestone binds at most eight parameters as
inference variables in a caller-selected universe. Canonical exact selection
restores unique answers as substitutions keyed to those original identities;
repeated parameters enforce equality, and ambiguity/no solution remain explicit.
Invalid binder indices fail at construction. Windows gnullvm and native Arch
Linux WSL each pass 486 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 832 compiler tests per host.
Generic inference candidates, inferred premise proof, projection composition,
universal answer inversion, and source existential syntax remain unsupported.

The symbolic generic-existential milestone matches canonical inference-bearing
queries against coherent flat generic heads with a fixed 16-node constraint
graph. Concrete constraints produce concrete bindings; unresolved equality
classes map to their oldest universe-safe query representative, and selected
premises retain those symbolic terms. Head-unconstrained implementation
parameters remain ambiguous; rigid inputs fail explicitly. Windows gnullvm and
native Arch Linux WSL each pass 489 library tests, one component-interface probe,
10 conformance tests, and 335 replacement tests: 835 compiler tests per host.
Recursive inferred-premise proof, nested/projection unification, cross-family
answer composition, and source existential syntax remain unsupported.

The recursive inferred-proof milestone keeps one fixed union/concrete state for
the root existential variables. Each exact or generic implementation answer
refines that state before generic premises recurse through the existing 16-frame
stack. Exact premises can resolve symbolic variables, generic chains propagate
the result, contradictory premises return no solution, and cross-family
ambiguity, cycles, and overflow remain distinct. Unrelated premise variables
fail explicitly. Windows gnullvm and native Arch Linux WSL each pass 493 library
tests, one component-interface probe, 10 conformance tests, and 335 replacement
tests: 839 compiler tests per host. Inference-aware where clauses, projection
constraints, backtracking, caching, coinduction, and source syntax remain
unsupported.

The inferred where-clause milestone applies the existing flat symbolic matcher
to the bounded clause database and returns stable clause identity, instantiated
premises, and a universe-checked substitution. The recursive solver consults a
clause only after exact and generic candidates return no solution and composes
clause/generic/exact chains in the same root constraint state. Multiple clauses,
cycles, and acyclic overflow remain distinct. Windows gnullvm and native Arch
Linux WSL each pass 498 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 844 compiler tests per host.
Environment layering, implied bounds, negative reasoning, projection predicates,
backtracking, caching, coinduction, and source syntax remain unsupported.

The bounded rigid-proof milestone recursively composes concrete and skolemized
placeholder premises through the existing 16-goal stack. Exact concrete facts
can terminate branches; otherwise one unique rigid clause is elaborated.
Ambiguity, no solution, cycles, and overflow remain distinct, and inference-
bearing entry goals fail explicitly. Windows gnullvm and native Arch Linux WSL
each pass 458 library tests, one component-interface probe, 10 conformance
tests, and 335 replacement tests: 804 compiler tests per host. Mixed
inference/skolem unification, coinduction, and source higher-ranked syntax remain
unsupported.

At compiler path checkpoint `9a950ae9`, the Windows gnullvm core suite passed
765 tests: 420 library tests, 10 conformance tests, and 335 replacement tests.
Core formatting, warnings-denied Clippy, the no-`std`/no-`alloc`/unsafe hygiene
scan, `mrml doctor`, `mrml audit`, and `mrml build mrml-rustc` passed.
The driver was not re-executed by this path-only checkpoint, and no new Linux
evidence is claimed.

At driver path checkpoint `0350249c`, the Windows gnullvm driver suite passed
2 tests; driver formatting, warnings-denied Clippy, and the combined core/driver
hygiene scan passed. `mrml doctor` and `mrml audit` passed. Direct
`mrml build mrml-rustc-driver` selected MSVC and failed because `link.exe`
was unavailable. No new Linux evidence is claimed.

On 2026-08-25, ORACLE-0002 passed 767 tests on Windows gnullvm: 420 library
tests, 10 conformance tests, 335 replacement tests, and 2 driver tests.
Warnings-denied Clippy also passed. The current commands are:

```powershell
$env:RUSTFLAGS='-C link-arg=/stack:16777216'
cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm test -p mrml-rustc -p mrml-rustc-driver
cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm clippy -p mrml-rustc -p mrml-rustc-driver --all-targets --no-deps -- -D warnings
```

```sh
cd /mnt/c/Users/Mitch/Documents/mrml
cargo +nightly-2026-08-24-x86_64-unknown-linux-gnu test -p mrml-rustc -p mrml-rustc-driver --release --offline
cargo +nightly-2026-08-24-x86_64-unknown-linux-gnu clippy -p mrml-rustc -p mrml-rustc-driver --all-targets --release --offline --no-deps -- -D warnings
```

The Arch Linux toolchain at the same commit crashed in LLVM `PromotePass` while
building the release test binary. That compiler-host failure is recorded as an
ORACLE-0002 regression/blocker, not passing evidence. The previous ORACLE-0001
generation retains the last complete Windows/Linux evidence.

The hygiene scan must remain empty:

```sh
rg -n "(^|[^A-Za-z])(std|alloc)::|unsafe\s*\{" packages/compiler/core/src packages/compiler/driver/src
```

Format only the compiler packages, preserve unrelated worktree changes, stage
overlapping documentation hunks interactively, fetch before pushing, never
force-push, and update this checkpoint after every pushed compiler milestone.
