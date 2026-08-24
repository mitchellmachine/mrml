# mrml-rustc durable checkpoint

This file is the short recovery record for the independent compiler lane. It
does not replace `docs/COMPILER.md`, the oracle records, or the detailed
evidence ledger in `crates/mrml-rustc/README.md`. If chat history or a local
worktree is lost, recover this checkpoint first and verify every claim against
the named commit and current source.

## Recoverable baseline

- Branch: `main`
- Compiler checkpoint commit: `df01b9b`
  (`compiler: retain ownership event origins`)
- Remote state when recorded: the named compiler checkpoint is pushed to
  `origin/main`; this recovery-document commit follows it.
- Preceding compiler commits: `40d7544` (`compiler: reject linear use after
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
- source-independent projection lists of at most four `Dereference`, `Index`,
  `TupleField`, or `Subslice` steps;
- projection/type validation, hole detection, tuple-bound checks, and explicit
  capacity failures; and
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
  typed child path per field; the derived capacity preserves all 256 retained
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
  that resolve to an exact root or tuple-field move path of a proven `Copy`
  type transactionally record `Copy`; capacity failure cannot retain the read
  without its effect. Summary indexes, dereferences, and non-`Copy` reads remain
  unclassified. Direct shared and mutable borrows of an exact root, plus shared
  or mutable reborrows through a direct reference root, record `SharedBorrow` or
  `MutableBorrow` instead of being mislabeled as copies or moves. Reference
  indexing and summary projections remain unclassified. Supported call
  arguments are classified from the resolved parameter type: exact non-`Copy`
  roots record `Move`, while explicit borrow syntax retains its borrow effect.
  Supported non-`Copy` returned source expressions propagate the same move
  context through transparent wrappers, sequence tails, and conditional
  branches. Sequence prefixes, conditions, indexes, arithmetic operands, and
  aggregate elements keep ordinary value context. Moves of `Copy` types,
  projected moves in this direct-only
  slice, read-modify-write on non-`Copy` paths, invalid IDs, holes, malformed
  spans, corrupt counts, incompatible `Copy` effects, and capacity exhaustion
  fail closed; and
- a derived fixed bound of 1,280 ownership events spanning all 512 possible
  initialization facts and 768 possible place effects. Each fact receives a
  dense monotonic event ID when it is appended, preserving parameter entry,
  RHS effects, successful local initialization, assignment effects, and return
  effects in their actual preanalysis order. Final validation merges the two
  append-only tables and requires exactly `0..event_count` with no holes,
  duplicates, inversions, or uncounted entries. Event-capacity failure occurs
  before mutating a path, initialization, read, effect, or counter. These event
  IDs do not yet claim CFG-block membership; and
- insertion-time provenance on every initialization and effect. Parameter roots
  record `ParameterEntry`; preanalyzed body events record an exact bounded
  `TopLevelStatement(index)` or verified `Tail`; dynamically appended inlined-
  helper facts record `EmissionExpansion` and are explicitly excluded from
  source-order claims. Validation rejects unassigned origins, parameter-origin
  misuse, statement indexes outside the parsed body, tail origins on bodies
  without a tail, and invalid local-initialization origins. Conditional branch,
  edge, nested-action, and loop-operation provenance is not yet refined beyond
  its containing top-level statement; and
- bounded initializedness enforcement for functions proven to have exactly one
  reachable top-level basic block and an expression stream with no conditional
  path split. A fixed 1,360-path state map consumes the dense event order.
  Parameter/local initialization marks roots and tuple children initialized;
  exact moves clear roots and descendants; copies, moves, shared/mutable borrows,
  and read-modify-write require prior initialization; exact writes restore paths,
  and child writes recompute tuple-root completeness. A second straight-line
  move reports `RuntimeUseAfterMove`. Conditional expression nodes disable this
  enforcement even when the structural CFG has one block, closing the observed
  mutually-exclusive-tail false positive. Multi-block and multi-path functions
  remain unenforced until events carry explicit block provenance; and
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
Array-element move paths, remaining indirect move/borrow classification,
general CFG initializedness and use-after-move enforcement, unsupported
parser/control-flow forms, borrows, loans, regions,
Polonius-style analysis, and a general trait solver are unimplemented. The root
initialization sites do not claim that unreachable or divergent declarations
execute.

## Next compiler work

Continue the dependency chain instead of filling arbitrary historical Rust
compatibility gaps:

1. refine statement provenance into conditional block/edge, nested-action, and
   loop-operation origins, then map events to the existing CFG;
2. compute fixed-point initializedness across CFG edges and precise tuple paths;
3. extend contextual effects for implicit coercions and remaining indirect
   call/return shapes without treating ambiguous pointee reads as moves;
4. add array-element paths only after place facts retain exact constant element
   identity rather than the current summary `Index` projection;
5. then stage shared loans, mutable loans/invalidation, full reborrow semantics,
   and flow-sensitive outlives reasoning with independent accepted/rejected
   probes.

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

The checkpoint source passed 683 tests on each host: 376
library tests, 10 conformance tests, 295 replacement tests, and 2 driver tests.
Warnings-denied Clippy also passed on both hosts. The commands were:

```powershell
$env:RUSTFLAGS='-C link-arg=/stack:16777216'
cargo +nightly-x86_64-pc-windows-gnullvm test -p mrml-rustc -p mrml-rustc-driver --target x86_64-pc-windows-gnullvm --offline
cargo +nightly-x86_64-pc-windows-gnullvm clippy -p mrml-rustc -p mrml-rustc-driver --target x86_64-pc-windows-gnullvm --all-targets --no-deps --offline -- -D warnings
```

```sh
cd /mnt/c/Users/Mitch/Documents/mrml
cargo +nightly-x86_64-unknown-linux-gnu test -p mrml-rustc -p mrml-rustc-driver --target x86_64-unknown-linux-gnu --release --offline
cargo +nightly-x86_64-unknown-linux-gnu clippy -p mrml-rustc -p mrml-rustc-driver --target x86_64-unknown-linux-gnu --release --all-targets --no-deps --offline -- -D warnings
```

The hygiene scan must remain empty:

```sh
rg -n "(^|[^A-Za-z])(std|alloc)::|unsafe\s*\{" crates/mrml-rustc/src crates/mrml-rustc-driver/src
```

Format only the compiler packages, preserve unrelated worktree changes, stage
overlapping documentation hunks interactively, fetch before pushing, never
force-push, and update this checkpoint after every pushed compiler milestone.
