# mrml-rustc durable checkpoint

This file is the short recovery record for the independent compiler lane. It
does not replace `docs/COMPILER.md`, the oracle records, or the detailed
evidence ledger in `packages/compiler/core/README.md`. If chat history or a local
worktree is lost, recover this checkpoint first and verify every claim against
the named commit and current source.

## Recoverable baseline

- Branch: `main`
- Compiler checkpoint commit: `00888d66`
  (`compiler: link bounded ordered object lists`)
- Remote state when recorded: `origin/main` includes the bounded MRML-owned
  static-link core, exact MRML COFF and ELF64 ingestion, deterministic
  import-free PE32+/ELF64 executable serialization, explicit compiler-driver
  selection, identical-input gnullvm rust-lld comparison, and ordered linking
  of one through 32 object inputs. The original compiler core/driver relocation
  remains at `0350249c`.
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

## Latest bounded linker milestone

Commits `5169d8ed` through `00888d66` establish the MRML-owned linker lane. The
no-std core resolves one symbol per input across at most 32 inputs and 256
checked PC-relative relocations, with typed named-code and local-read-only-data
targets. It decodes the exact bounded COFF and ELF64 subsets emitted by
`mrml-rustc`, and serializes deterministic fixed-address import-free PE32+ and
ELF64 executables with page-separated permissions. Explicit `--emit pe`,
`--emit elf-executable`, `--link-coff`, and `--link-elf` selections never fall
back to a system linker.

Commit `00888d66` separates object-data and relocation-arena lifetimes and lets
the driver retain one through 32 ordered decoded objects without raw pointers
or self-references. A Windows release-driver probe linked two independently
compiled objects and returned 42. On the same host, an eight-object, 744-byte
controlled workload ran 50 times after five warmups: MRML median 10.677 ms,
pinned `nightly-2026-08-24` gnullvm rust-lld median 27.524 ms, with matching
1,024-byte outputs and exit status 42. This is a 2.58x result for that small
import-free workload only, not a general superiority claim. The single-object
controlled result was 10.196 ms versus 26.870 ms. Arch WSL separately executed
the generated bounded ELF64 image and returned 42; the ordinary MRML Linux test
target remained unavailable, so this is hosted evidence only.

Archives, PE imports/exports/exception/base-relocation/debug metadata, ELF
dynamic metadata/interpreter/PIE/sections, section GC, ICF, parallel execution,
and public `mrml` build-frontend selection remain unimplemented. Upstream rustc
and its pinned linker remain the production path until the profile-specific
gate in `docs/build/BUILD_SYSTEM.md` passes.

Patent review: **NOT_TRIGGERED** for these conventional bounded linker,
serializer, command-routing, and benchmark increments; see
`docs/patents/REVIEW_LOG.md`.

## Latest bounded C-string byte-view milestone

Commit `975b7041` introduces distinct cooked/raw C-string tokens and expressions
and threads them exhaustively through constant, IR, semantic, analysis, and
emission consumers with `UnsupportedCStringLiteral` as the fail-closed boundary.
Commit `d06a8fe9` admits only exact `.as_ptr()`: bounded decoding rejects an
interior NUL before object-data mutation, appends one terminator, and emits a
checked ELF64/COFF relocation with type `*const i8`. Exact ORACLE-0002 probes
accepted cooked/raw C strings and rejected an interior NUL on Windows and Arch.
Both hosts passed 656 library, 1 component-interface, 10 conformance, 351
replacement, and 6 semantic-execution tests: 1,024 per host. General `&CStr`
transport and methods remain unsupported.

Commit `76f299f5` adds distinct `CStrToBytes` expressions for exact literal
`.to_bytes()` and `.to_bytes_with_nul()` calls. Only the typed fat-slice return
path admits them: it reuses the checked read-only relocation, returns length
excluding or including the single terminator respectively, and retains
defensive scalar-emitter and IR rejection. ELF64 and COFF object tests verify
the exact `hello\0` bytes and encoded lengths 5 and 6; an interior-NUL input
still fails before object emission. The exact ORACLE-0002 Arch executable
returned `b"hello"` and `b"hello\0"`. Windows and Arch each passed 657 library,
1 component-interface, 10 conformance, 351 replacement, and 6
semantic-execution tests: 1,025 per host.

Commit `0c517e09` uses one canonical checked decoder/view-length helper for
direct byte-slice returns and exact literal `.len()`/`.is_empty()` observation.
A typed tail classifier routes otherwise constant-looking functions through
native lowering, while preserving empty-tail functions. The relocation-free
scalar results execute in the semantic loader: `hello` reports 5 or 6 and an
empty literal reports empty only when the terminator is excluded. The exact
ORACLE-0002 Arch executable agrees. Windows and Arch each passed 657 library,
1 component-interface, 10 conformance, 351 replacement, and 7
semantic-execution tests: 1,026 per host. General `&CStr` transport, locals,
arguments, and conditionals remain unsupported.

Commit `8a172ed2` extends the test-only semantic loader from relocation-free
`.text` to MRML's exact internal read-only object contract. It accepts only COFF
`IMAGE_REL_AMD64_REL32` references from `.text` to `.rdata` and ELF64
`R_X86_64_PC32` entries from `.rela.text` to `.rodata`, then applies checked
in-range displacements inside one bounded allocation. A conditional cooked/raw
C-string byte-view probe executes from both object formats and verifies exact
contents, length, ordering, and terminator inclusion. Exact ORACLE-0002 Arch
execution agrees. Windows and Arch each passed 657 library, 1
component-interface, 10 conformance, 351 replacement, and 8 semantic-execution
tests: 1,027 per host. External relocation linking and a production loader are
not claimed.

Patent review: **NOT_TRIGGERED**; see `docs/patents/REVIEW_LOG.md`.

### Preceding bounded explicit-static reference milestone

Commit `d0983d5e` recognizes exact `&'static` spelling for the existing bounded
reference targets. Static string literals and explicitly static parameters can
supply explicit-static returns; an ordinary borrowed parameter cannot be
narrowed and fails as `UnsupportedLifetimeRelation`. The original no-input
elision control remains distinct. Exact ORACLE-0002 metadata probes accepted
the literal/static-input forms and rejected `&str -> &'static str` on Windows
and Arch. Both hosts passed 653 library, 1 component-interface, 10 conformance,
351 replacement, and 6 semantic-execution tests: 1,021 per host. Named and
higher-ranked lifetimes, general subtyping, and regions remain unsupported.

Follow-up commit `a5384c57` proves the same classification for cooked/raw
`&'static [u8]` literals and explicitly static thin `&u32`, including a
fail-closed ordinary-`&u32` narrowing control, in both object formats.

Patent review: **NOT_TRIGGERED**; see `docs/patents/REVIEW_LOG.md`.

### Preceding exhaustive nested-control lowering milestone

Commit `183038f0` validates every supported nested conditional alternative,
rejects incomplete CFG construction, and requires a `ValidatedRuntimeBody`
before emission. Native relocation-free COFF/ELF execution probes distinguish
omitted, duplicated, reordered, or mistargeted actions and controls and cover
reference mutations, initializedness, and fixed-register assembly. Both hosts
passed 1,021 compiler tests. General CFGs, relocating runtime loading, isolated
trap capture, and complete regions remain unsupported.

Patent review: **NOT_TRIGGERED**; see `docs/patents/REVIEW_LOG.md`.

### Preceding bounded byte character-literal milestone

Commit `c21a70fc` gives byte characters distinct lexical/expression identity
and a concrete `u8` runtime type. ASCII, conventional byte escapes, and the full
`\x00` through `\xFF` range reach both native object formats; Unicode escapes,
direct non-ASCII input, and malformed cardinality fail closed. The exact
ORACLE-0002 nightly accepted ASCII, `b'\xFF'`, and escaped-newline controls.
Windows and native Arch Linux WSL each passed 652 library tests, 1 component
probe, 10 conformance tests, and 351 replacement tests: 1,014 compiler tests per
host. Patent review: **NOT_TRIGGERED**; see `docs/patents/REVIEW_LOG.md`.

### Preceding bounded byte string-literal milestone

Commit `a2d1b000` gives cooked and raw byte strings distinct lexical and
expression identity and immutable `&[u8]` runtime types. It decodes cooked
`\x00` through `\xFF`, rejects Unicode escapes and direct non-ASCII bytes,
preserves ASCII raw content, and reuses the bounded read-only-data relocation
path for ELF64 and COFF. Exact object tests retain `41 FF 0A` and the raw
11-byte payload; byte/string mixing fails closed. The exact ORACLE-0002 nightly
accepted the independently authored cooked and raw controls. Windows and native
Arch Linux WSL each passed 652 library tests, 1 component probe, 10 conformance
tests, and 350 replacement tests: 1,013 compiler tests per host. Byte literals,
suffixes, C strings, general static data, and general lifetime inference remain
outside this checkpoint.

Patent review: **NOT_TRIGGERED**; see `docs/patents/REVIEW_LOG.md`.

### Preceding zero-input return-lifetime elision milestone

Commit `481281c7` rejects an elided reference return when no supported reference
parameter can supply its output lifetime. The exact ORACLE-0002 nightly rejected
the independently authored `fn(u8) -> &str` form with E0106; MRML now reports
`UnsupportedLifetimeElision` before ELF64 or COFF emission. One-reference-input
controls remain accepted. Windows and native Arch Linux WSL each passed 650
library tests, 1 component probe, 10 conformance tests, and 349 replacement
tests: 1,010 compiler tests per host. Multiple-input elision, named and
`'static` lifetimes, higher-ranked lifetimes, and general regions remain outside
this bounded checkpoint.

### Preceding thirty-two-relocation object milestone

Commit `78a7f771` raises both the runtime read-only relocation arena and shared
x86-64 object validator from eight to 32 entries. A modern-Rust-compatible
parameter-backed return with nine distinct static arms reaches both ELF64 and
COFF; the existing thirty-third-entry object control remains fail-closed. The
exact ORACLE-0002 nightly accepted the independently authored source. Windows
and native Arch Linux WSL each passed 650 library tests, 1 component probe, 10
conformance tests, and 349 replacement tests: 1,010 compiler tests per host.
This remains a fixed bound, not dynamic allocation or complete linker support.

### Preceding bounded decoded string-literal pooling milestone

Commit `85bdd637` decodes each cooked or raw string into a fixed 1,024-byte
scratch buffer before mutating object data, then deterministically reuses the
first existing identical runtime byte sequence. Each use retains its own
checked relocation. A 640-byte cooked/raw pair proves the second value can fit
only through reuse in both ELF64 and COFF. Windows and native Arch Linux WSL
each passed 650 library tests, 1 component probe, 10 conformance tests, and 349
replacement tests: 1,010 compiler tests per host. This does not guarantee
literal address identity, merge general constants, enlarge fixed capacities,
or add general static data.

### Preceding bounded raw string-literal milestone

Commit `be6da69d` recognizes Rust raw strings with at most 255 delimiter hashes,
requires an exact closing delimiter, and copies the interior bytes verbatim
through the existing bounded read-only data path. Embedded backslashes and
non-closing quote/hash sequences have exact lexer and COFF object coverage;
unterminated strings and excess delimiter hashes fail closed. The exact
ORACLE-0002 nightly accepted the independently authored direct conditional
return. Windows and native Arch Linux WSL each passed 650 library tests, 1
component probe, 10 conformance tests, and 349 replacement tests: 1,010 compiler
tests per host. Byte/raw-byte/C strings, pooling, larger capacities, and general
static data remain outside the claim.

### Preceding direct conditional string-return milestone

Commit `5eeefa10` aligns return-specific fat-reference preanalysis and ABI
emission with the existing bounded literal value path. A tail `if` may select a
parameter-backed `&str` or a cooked static literal; the literal arm creates no
place-read fact and uses the checked read-only bytes and internal relocation.
The exact ORACLE-0002 nightly accepted the independently authored direct form.
Windows and native Arch Linux WSL each passed 649 library tests, 1 component
probe, 10 conformance tests, and 349 replacement tests: 1,009 compiler tests per
host. Raw/byte/C strings, pooling, larger capacities, general static data, and
general lifetime inference remain outside the claim.

### Preceding cooked string-escape decoding milestone

Commit `ba637ea5` decodes ordinary cooked string literal escapes into their
runtime UTF-8 bytes under the existing 1,024-byte bound. It covers simple
escapes, ASCII `\\xNN`, Unicode `\\u{...}` scalar validation, and line
continuations. Exact object tests cover newline, ASCII hex, and a four-byte
Unicode scalar; unknown escapes, non-ASCII hex bytes, surrogates, malformed
forms, capacity overflow, and excess relocations fail closed. The exact
ORACLE-0002 nightly accepts the escaped conditional companion. Windows and
native Arch Linux WSL each passed 649 library tests, 1 component probe, 10
conformance tests, and 349 replacement tests: 1,009 compiler tests per host.

### Preceding runtime string-literal object milestone

Commit `52b1a941` splits bare code from a bounded relocatable runtime result,
copies simple unescaped UTF-8 string literal bytes into the proven internal
read-only-data contract, and emits a typed RIP-relative address plus exact byte
length. The object pipeline consumes those bytes for ELF64 `.rodata` and COFF
`.rdata`; the bare `MachineCode` API continues to reject data-bearing output.
The exact ORACLE-0002 nightly accepts both the plain and escaped independently
authored conditional forms; MRML accepts the plain form and rejects escapes
pending exact decoding. Windows and native Arch Linux WSL each passed 649
library tests, 1 component probe, 10 conformance tests, and 349 replacement
tests: 1,009 compiler tests per host. This preceding increment supported only
unescaped literals; commit `ba637ea5` adds bounded cooked escape decoding.

### Preceding bounded read-only object-data milestone

Commit `93b3a998` adds typed, bounded internal read-only-data relocations to the
ELF64 and COFF emitters. ELF uses `.rodata`, a local section symbol, and checked
RELA addends; COFF uses `.rdata`, a static internal symbol, and checked REL32
in-place addends. Structural tests cover two code/data offsets, exact section
bytes and flags, symbol targeting, and out-of-range rejection. Windows and
native Arch Linux WSL each passed 648 library tests, 1 component probe, 10
conformance tests, and 349 replacement tests: 1,008 compiler tests per host.
Ordinary code generation does not consume the contract yet, so runtime string
literals remain fail-closed.

### Preceding conditional string-reference initialization milestone

Commit `801455c9` verifies exhaustive conditional first assignment of a shared
`&str` local from parameter-backed values through the existing branch-aware
two-word transport, CFG initializedness join, and return-outlives relation. The
exact ORACLE-0002 nightly accepts the independently authored form. Windows and
native Arch Linux WSL each passed 647 library tests, 1 component probe, 10
conformance tests, and 349 replacement tests: 1,007 compiler tests per host.
Static string literals, distinct-origin fat references, slices, mutable `str`,
and general fat-pointer semantics remain fail-closed or unclaimed.

### Preceding direct string-reference initialization milestone

Commit `1a177dea` makes uninitialized-local emission allocate the exact bounded
slot count and admits direct shared `&str` delayed initialization through the
existing fat-value store and outlives relation. ORACLE-0002 accepts the direct
parameter-backed return and rejects a missing arm with E0381. Windows and native
Arch Linux WSL each passed 647 library tests, 1 component probe, 10 conformance
tests, and 349 replacement tests: 1,007 compiler tests per host. Conditional
fat-reference assignment beyond the parameter-backed `&str` case, slices,
mutable `str`, and general fat-pointer semantics remain fail-closed.

### Preceding conditional thin-reference initialization milestone

Commit `7847c11f` proves that exhaustive conditional first writes retain every
thin-reference assignment origin through the existing CFG and outlives joins.
ORACLE-0002 accepts parameter-backed shared and mutable cases, rejects a mixed
local origin with E0515, and rejects a missing arm with E0381. Windows and native
Arch Linux WSL each passed 647 library tests, 1 component probe, 10 conformance
tests, and 348 replacement tests: 1,006 compiler tests per host. This is focused
conformance evidence for the mechanism established by the preceding compiler
commits; no new unchecked origin path was added.

### Preceding thin-reference delayed-initialization milestone

Commit `beb37de7` parses exact uninitialized scalar `&T`/`&mut T` declarations,
retains their direct assignment reborrow generation, and includes an immutable
uninitialized reference's first write in bounded return-outlives analysis.
ORACLE-0002 accepts parameter-backed shared and mutable returns and rejects a
local-backed return with E0515. Windows and native Arch Linux WSL each passed
647 library tests, 1 component probe, 10 conformance tests, and 347 replacement
tests: 1,005 compiler tests per host. Fat references, aggregates, and named
lifetime inference remain fail-closed.

### Preceding thin raw-pointer delayed-initialization milestone

Commit `0a5f2cc6` parses exact uninitialized `*const T`/`*mut T` declarations
and admits their direct or exhaustive conditional first writes through the
existing initializedness path. It tracks writes without manufacturing pointer
provenance. ORACLE-0002 accepts the independent exhaustive `*const u8` probe.
Windows and native Arch Linux WSL each passed 647 library tests, 1 component
probe, 10 conformance tests, and 346 replacement tests: 1,004 compiler tests per
host. References, fat pointers, aggregates, and loop-carried initialization
remain fail-closed.

### Preceding primitive scalar delayed-initialization milestone

Commit `1cfcc246` widens direct and bounded conditional delayed initialization
from `u64` to every concrete primitive integer width plus `bool` and `char`.
Preanalysis and emission share one admission predicate; raw pointers,
references, and aggregates remain rejected. ORACLE-0002 accepts independent
`i8`, `bool`, and `char` exhaustive probes. Windows and native Arch Linux WSL
each passed 647 library tests, 1 component probe, 10 conformance tests, and 345
replacement tests: 1,003 compiler tests per host.

### Preceding conditional delayed-initialization milestone

Commit `d032d92c` lets different arms of the same bounded conditional each
perform the mutually exclusive first write to an immutable uninitialized `u64`.
The existing CFG intersection admits the post-join read only when every
reachable arm initializes the path. ORACLE-0002 accepts the exhaustive pair and
rejects the missing-else form with E0381. Windows and native Arch Linux WSL each
passed 647 library tests, 1 component probe, 10 conformance tests, and 344
replacement tests: 1,002 compiler tests per host. Nested/general joins,
loop-carried initialization, projected first writes, and other types remain
fail-closed.

### Preceding direct delayed-initialization milestone

Commit `b02037df` lets direct ordinary `=` perform the first write to an
explicitly uninitialized `u64` local. Immutable locals admit exactly that first
root write and reject a repeated write. ORACLE-0002 accepts the direct
initialization and rejects the repeated immutable assignment with E0384.
Windows and native Arch Linux WSL each passed 647 library tests, 1 component
probe, 10 conformance tests, and 343 replacement tests: 1,001 compiler tests per
host. Conditional joins, projected first writes, and other uninitialized types
remain fail-closed.

### Preceding assembly-output definite-initialization milestone

Commit `21e1d328` represents explicit uninitialized `u64` locals without an
initialization event and lets an exact returning syscall output perform their
first write. Reads before that write fail, and immutable locals reject later
writes. ORACLE-0002 accepts the split-output probe and rejects the direct read
with E0381. Windows and native Arch Linux WSL each passed 647 library tests, 1
component probe, 10 conformance tests, and 342 replacement tests: 1,000 compiler
tests per host.

### Preceding terminal halt-loop milestone

Commit `9a312d4e` lowers the exact first-party terminal x86-64 `cli`, `2:`,
`hlt`, `jmp 2b` assembly sequence with all permutations of its required
`noreturn`, `nomem`, and `nostack` options. ORACLE-0002 accepts the comparison
probe. Windows and native Arch Linux WSL each passed 646 library tests, 1
component probe, 10 conformance tests, and 342 replacement tests: 999 compiler
tests per host. This is object encoding, not privileged-instruction execution.

### Preceding returning syscall milestone

Commit `9797cabb` adds returning seven-register `int 0x80` forms with RAX
`inlateout`, ordered input/`inlateout` operands, mutable named-local or discarded
outputs, exact `nostack`, source-ordered read/write facts, and preservation of
all seven results before stores. ORACLE-0002 accepts the mixed comparison probe.
Windows and native Arch Linux WSL each passed 646 library tests, 1 component
probe, 10 conformance tests, and 341 replacement tests: 998 compiler tests per
host. General output places and other syscall forms remain unsupported.

### Preceding terminal syscall milestone

Commit `3602f172` extends the terminal path with exact x86-64
`asm!("int 0x80", ...)` containing seven ordered `u64` inputs in RAX, RDI,
RSI, RDX, R10, R8, and R9 and exact `noreturn, nostack` options. The bounded
parser, read preanalysis, left-to-right evaluation, register loads, and `CD 80`
emission are covered for ELF64 and COFF. ORACLE-0002 accepts the comparison
probe. Windows and native Arch Linux WSL each passed 646 library tests, 1
component probe, 10 conformance tests, and 340 replacement tests: 997 compiler
tests per host. Returning/inout syscall forms remain the next assembly gate.

### Preceding terminal INT3 milestone

Commit `01c14e8a` adds a typed terminal property to final top-level expression
statements and lowers exact unsafe x86-64
`asm!("int3", options(noreturn, nostack))` in either option order. It emits
`CC`, omits the ordinary return sequence, and admits direct `!` returns and
never-to-value coercion. Nonterminal/conditional forms fail closed until the
compiler models unreachable suffixes. ORACLE-0002 accepts the terminal forms
and also accepts a following suffix with an unreachable-code warning; that
last behavior is a classified conservative MRML delta. Windows and native Arch
Linux WSL each passed 646 library tests, 1 component probe, 10 conformance
tests, and 339 replacement tests: 996 compiler tests per host.

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

The direct callee-local reassignment milestone carries one compatible reference-
parameter origin through straight-line plain assignment to a mutable reference
local. The fixed local state is newest-first and generation-ordered; immutable,
projected, compound, local-backed, conditional, or unclassified assignments
make the proof conservative. The exact dated oracle accepted the reassigned
alias and post-last-use control and rejected a live competing mutable borrow with
E0499. Windows gnullvm and native Arch Linux WSL each pass 639 library tests, one
component-interface probe, 10 conformance tests, and 335 replacement tests: 985
compiler tests per host. General interprocedural dataflow and regions remain
unsupported.

Direct unconditional returns now resolve from the current loop local/projected
state and terminate that modeled iteration. Disconnected suffix operations no
longer manufacture a backedge; for a condition-headed loop only the incoming
zero-iteration state can continue after the loop. ORACLE-0002 accepts a stable
same-origin return with an unreachable suffix and rejects local-backed storage
with E0515. Windows and Arch each pass 643 library tests, one component-interface
probe, 10 conformance tests, and 335 replacement tests: 989 compiler tests per
host. Mixed break/continue exit-state joining remains unsupported.

Direct break exits now retain the current outer local/projected origin state.
Condition-headed loops intersect that exit with the incoming zero-iteration
path; unconditional loops use the exact break state, and loop-scoped locals are
discarded. ORACLE-0002 accepts the unconditional parameter overwrite and rejects
the corresponding `while` with E0515 because zero iterations retain local
storage. Windows and Arch each pass 643 library tests, one component-interface
probe, 10 conformance tests, and 335 replacement tests: 989 compiler tests per
host. Conditional break/continue joins remain unsupported.

Conditional break paths now accumulate separately from the continuing/backedge
state. Multiple breaks intersect; condition-headed loops also join their
natural and zero-iteration exit, while unconditional loops expose only break
outcomes. ORACLE-0002 accepts a parameter-backed break with a local-backed
non-break path and rejects the reversed local-backed break with E0515. Windows
and Arch each pass 643 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 989 compiler tests per host.
Conditional continue and branch-block break transfer remain unsupported.

Direct continue now ends the current syntactic operation suffix and preserves
the current origin state as the sole backedge outcome. ORACLE-0002 accepts the
stable parameter-backed conditional return before that continue and reports a
later local assignment as unreachable. Windows and Arch each pass 643 library
tests, one component-interface probe, 10 conformance tests, and 335 replacement
tests: 989 compiler tests per host. Conditional continue remains unsupported.

Conditional continue paths now accumulate independently from their false-path
suffix, then intersect with direct-continue and normal-fallthrough backedges.
The joined state feeds the existing condition-headed natural exit. ORACLE-0002
accepts stable parameter-backed outcomes and rejects a local-backed fallthrough
backedge reaching a `while` tail with E0515. Windows and Arch each pass 643
library tests, one component-interface probe, 10 conformance tests, and 335
replacement tests: 989 compiler tests per host. Conditional-block terminal
continue remains unsupported.

Conditional action-block terminal break and continue arms now feed the bounded
loop-exit and backedge accumulators respectively. Terminal arms do not join the
state that reaches later operations; nonterminal arms and an implicit missing
else remain fallthrough outcomes. ORACLE-0002 accepts parameter-backed terminal
break/continue arms and rejects a local-backed break arm with E0515. Windows and
Arch each pass 643 library tests, one component-interface probe, 10 conformance
tests, and 335 replacement tests: 989 compiler tests per host. Nested-loop state
transfer and general fixed points remain incomplete.

Nested-loop return/stability analysis now accepts an explicit incoming local,
projected, type, mutability, and compatibility state. The same implementation is
used both at function-level loop state and after outer-loop declarations,
assignments, and branch joins. Proven-stable nested edges preserve that outer
state. ORACLE-0002 accepts an outer same-origin reassignment before a nested
conditional return and rejects a local-backed reassignment with E0515. Windows
and Arch each pass 643 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 989 compiler tests per host.
General nested-loop exit-state transfer and fixed points remain incomplete.

Nested inner-break paths now accumulate exact outer-visible local/projected
origins and return the joined exit state to subsequent outer-loop operations.
Condition-headed inner loops include their zero-iteration state. Inner continue
and normal backedges remain stability-checked. ORACLE-0002 accepts a parameter
overwrite before an inner break and rejects local-backed and zero-iteration/
local outcomes with E0515. Windows and Arch each pass 643 library tests, one
component-interface probe, 10 conformance tests, and 335 replacement tests: 989
compiler tests per host. General nested fixed points remain incomplete.

Labeled nested controls now export separate outer-break and outer-continue
origin states. The enclosing loop routes those outcomes into its existing exit
and backedge accumulators, while only an inner-loop exit permits subsequent
outer operations to execute. Earlier unconditional controls suppress later
ordered outcomes. ORACLE-0002 accepts the parameter-backed labeled break and
condition-headed labeled continue probes and rejects the equivalent local-
backed escapes with E0515. Windows and Arch each pass 643 library tests, one
component-interface probe, 10 conformance tests, and 335 replacement tests: 989
compiler tests per host. General nested-loop fixed points remain incomplete.

Conditional labeled-control coverage now combines an outer-target break or
continue with a separately reachable inner exit. Focused cases prove that the
outer destination and inner fallthrough states remain independently joined;
local-backed alternatives fail closed. ORACLE-0002 accepts both parameter-
backed mixed paths and rejects both local-backed variants with E0515. Windows
and Arch each pass 643 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 989 compiler tests per host.
General nested-loop fixed points remain incomplete.

Nested normal-backedge analysis now admits one bounded normalization step. The
candidate produced by the complete action sequence must be idempotent on an
exact second replay, and every recorded return/break/continue prefix must retain
identical outer-visible origins from the initial and candidate headers. The
pinned oracle accepts a parameter overwrite before every conditional exit and
rejects the same exit placed before normalization with E0515. Windows and Arch
each pass 643 library tests, one component-interface probe, 10 conformance
tests, and 335 replacement tests: 989 compiler tests per host. Multi-step,
branching, and general nested-loop fixed points remain incomplete.

Conditional inner-continue backedges now reuse the same bounded normalization
proof instead of requiring equality with the original header. The complete
transfer remains exactly idempotent, and every stored control prefix must agree
between initial and normalized headers. ORACLE-0002 accepts a parameter
overwrite before both continue and break controls and rejects controls that can
observe the earlier local-backed state with E0515. Windows and Arch each pass
643 library tests, one component-interface probe, 10 conformance tests, and 335
replacement tests: 989 compiler tests per host. Unconditional normalized
continues and general fixed points remain incomplete.

Unconditional inner continues now normalize only their exact reachable action
prefix. The prefix candidate must be idempotent on replay, and every stored
control at or before that action index must retain identical origins; operations
after the unconditional continue are excluded. ORACLE-0002 accepts a parameter
overwrite before a conditional return and continue, reports the retained suffix
as unreachable, and rejects a return before normalization with E0515. Windows
and Arch each pass 643 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 989 compiler tests per host.
Multi-backedge fixed-point iteration remains incomplete.

Conditional inner backedges now use a bounded joined header. The initial state,
every conditional inner-continue prefix, and normal fallthrough are intersected;
one replay from that header must reproduce the same local/projected origins.
Break, return, and outer-continue prefixes must remain equal between the initial
and converged headers. ORACLE-0002 accepts parameter and local-backed continue
edges when every exit first restores the parameter, and rejects an early local-
backed break with E0515. Windows and Arch each pass 643 library tests, one
component-interface probe, 10 conformance tests, and 335 replacement tests: 989
compiler tests per host. Unconditional mixed-backedge and broader iterative
fixed points remain incomplete.

The bounded joined-header proof now recognizes the earliest unconditional
nested-loop terminal. Conditional inner continues before that source-order
boundary feed the header; normal fallthrough is excluded, the terminal prefix
must agree between initial and converged headers, and later operations remain
unreachable. ORACLE-0002 accepts differing conditional backedges followed by a
parameter-normalized unconditional break and rejects an earlier local-backed
break with E0515. Windows and Arch each pass 643 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 989 compiler
tests per host. Nested branching transfers and broader iterative fixed points
remain incomplete.

An unconditional inner-continue terminal now contributes its exact prefix as
another backedge rather than an exit. It joins initial entry and every earlier
conditional inner continue, must reproduce the same header on replay, and keeps
its suffix unreachable; only returns and other exits require header-invariant
prefixes. ORACLE-0002 accepts mixed parameter/local backedges after a parameter-
backed return prefix and rejects the same return before normalization with
E0515. Windows and Arch each pass 643 library tests, one component-interface
probe, 10 conformance tests, and 335 replacement tests: 989 compiler tests per
host. Nested branching transfers and broader iterative fixed points remain
incomplete.

The modeled nested-loop origin header now iterates its monotone meet to a fixed
point. Direct origins and retained projected facts may only disappear, so the
loop is bounded by `local_count + projected_origin_count + 1`; exceeding that
bound fails closed. Exit prefixes are checked only after convergence. A focused
two-alias chain requires multiple transfers before a local origin reaches the
header, then restores the parameter before every exit. ORACLE-0002 accepts that
case and rejects the early-exit ordering with E0499. Windows and Arch each pass
643 library tests, one component-interface probe, 10 conformance tests, and 335
replacement tests: 989 compiler tests per host. This completes iterative header
convergence for the currently modeled flat nested-loop actions and controls;
nested branch-action representation and general region inference remain
incomplete.

The nested branch-action representation now has a bounded parser-level record.
It preserves a branch condition, up to four scoped local/assignment/expression
actions, a target-aware terminal, and exact ordering relative to surrounding
nested-loop actions and controls. One explicit `else` arm can now retain the
same bounded actions and terminal. The CFG models that successor with a distinct
else-action block, false edge, and independent terminal target; ownership
locations distinguish else actions and return values. Native and constant
execution were initially rejected. Constant evaluation now selects exactly one
arm, executes its scoped actions, and routes its terminal under the existing
bounded loop evaluator. Direct and helper-inlined x86-64 emission now lowers
scalar else arms. Exact parameter-backed reference returns are also admitted;
branch-local returned origins fail closed. The
single-arm CFG assigns separate condition and
scoped-action blocks, routes false fallthrough and target-aware true terminals,
and maps condition/action/return ownership locations back to those control
points. Branch-return origin transfer applies the exact scoped action prefix:
parameter-backed reborrows are admitted and local-backed returns fail closed.
Branch breaks transfer the exact scoped state to inner/outer exits, as do outer
continues. Inner continues feed their scoped state into the existing monotone
bounded header convergence, and subsequent exits must match the converged
header. Constant semantics are implemented: taken actions use a
scoped resolver checkpoint and target-aware break, continue, and return reuse
the existing bounded loop evaluator. Direct and inline native x86-64 lowering
mirrors those actions, scoped cleanup, and terminals for scalar-only primary and
else arms. Primary and else native reference-return branches are admitted only
after the exact function-return outlives proof; a branch-local else return is
rejected. Reference break/continue branches use the bounded destination/backedge
transfer above. ELF64 and COFF probes cover separate return, continue, and break
prefixes, direct and helper-inlined scalar else returns, and a parameter-backed
mutable-reference else return. Windows and
Arch each pass 645 library
tests, one component-interface probe, 10 conformance tests, and 336 replacement
tests: 992 compiler tests per host.

The nested branch alternative record now distinguishes an unconditional
`else` from one explicit `else if` by retaining an optional condition and exact
span. Parsing remains bounded to one alternative arm and four scoped actions.
Constant evaluation lazily tests the alternative only after a false primary,
executes only the selected scoped actions, and preserves fallthrough when both
conditions are false. CFG construction now gives the alternative condition a
distinct sourced block, routes primary false into it, routes alternative true
into scoped actions, and retains alternative false as fallthrough. Ownership
preanalysis records and maps the alternative-condition reads separately from
its actions and terminal. Direct and helper-inlined x86-64 emission now lazily
tests the alternative condition after primary false, routes true through the
existing scoped actions and terminal, and preserves false fallthrough. ELF64
and COFF probes cover both native paths. The parser now retains up to four
ordered alternatives, including an optional final `else`, and constant
evaluation lazily selects only the first matching arm. CFG and ownership now
give every alternative condition, action block, and return value an exact arm
index and route false edges through the ordered chain; an unconditional final
arm is exhaustive. Direct and helper-inlined x86-64 emission now lowers all
bounded alternatives in source order, with ELF64 and COFF probes for both
paths. Direct and helper-inlined mutable-reference chain probes retain the
parameter origin across every indexed arm, and a later local-backed arm fails
the exact return-outlives proof. The exact dated oracle
accepts an independently authored Rust 2024 four-outcome chain. Windows and Arch each continue
to pass 645 library tests, one component-interface probe, 10 conformance tests,
and 336 replacement tests: 992 compiler tests per host.

The conditional callee-local reassignment milestone evaluates supported direct
assignments from a copy of the incoming fixed local-origin state for every
conditional outcome, then joins each local independently. A missing `else`
contributes the unchanged fallthrough state. Equal parameter origins remain
exact; differing origins make only the affected local unknown. Unsupported
branch actions and assignment shapes remain conservative. ORACLE-0002 accepted
equal-origin branches and post-last-use owner reuse and rejected a live
competing mutable owner borrow with E0499. The Windows gnullvm canonical suite
passes 639 library tests, one component-interface probe, 10 conformance tests,
and 335 replacement tests: 985 compiler tests. The Arch Linux WSL rerun did not
reach compiler execution because concurrent `org.mrml.library.uefi` isolation
metadata failed build-graph validation; that run is recorded as blocked, not
passing evidence. General interprocedural CFG, alias, and region analysis remain
unsupported.

The branch-local callee-origin milestone copies the fixed name/origin/mutability
state for each conditional action block. Supported local reference declarations
may feed later direct assignments in that branch; newest-first shadowing remains
scoped, and branch-local entries are discarded before joining the pre-existing
locals. Local-backed aliases make the affected result unknown, while returns,
expressions, projected or compound writes, and unsupported actions fail closed.
ORACLE-0002 accepted same-origin branch-local aliases and post-last-use owner
reuse and rejected a live competing mutable owner borrow with E0499. Windows
gnullvm and native Arch Linux WSL each pass 639 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 985 compiler
tests per host. Arbitrary branch dataflow, nested projections, and general
regions remain unsupported.

The branch-local return-origin milestone resolves a terminal explicit return
using aliases accumulated earlier in that conditional action block. Its exact
parameter origin joins the other callee exits, and the terminal path is excluded
from the conditional fallthrough-state join. Local-backed, nonterminal,
malformed, and unsupported returns fail conservative. ORACLE-0002 accepted the
branch-local early return, its parameter-backed tail, and post-last-use owner
reuse, and rejected a live competing mutable owner borrow with E0499. Windows
gnullvm and native Arch Linux WSL each pass 639 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 985 compiler
tests per host. General control-flow and region inference remain unsupported.

The loop callee-local reassignment milestone applies one bounded transfer when a
`while` body contains only supported direct assignments, then joins it with the
incoming zero-iteration state. Same-origin reborrows remain exact; a changed
origin becomes unknown. Mixed control, return, local, expression, nested-loop,
or unsupported assignment operations remain conservative. ORACLE-0002 accepted
the same-origin loop and post-last-use owner reuse and rejected a live competing
mutable owner borrow with E0499. Windows gnullvm and native Arch Linux WSL each
pass 639 library tests, one component-interface probe, 10 conformance tests, and
335 replacement tests: 985 compiler tests per host. General loop fixed-point,
path-sensitive, alias, and region analysis remain unsupported.

The loop-local callee-origin milestone permits bounded local reference
declarations in that assignment-only transfer. Per-iteration name/origin/
mutability entries are discarded before joining only the pre-loop locals with
the zero-iteration state. Same-parameter origins remain exact; local-backed or
changed origins become unknown, and mixed controls remain conservative.
ORACLE-0002 accepted the loop-local alias and post-last-use owner reuse and
rejected a live competing mutable owner borrow with E0499. Windows gnullvm and
native Arch Linux WSL each pass 639 library tests, one component-interface
probe, 10 conformance tests, and 335 replacement tests: 985 compiler tests per
host. One concurrent Arch invocation exited during replacement execution
without a stable failing summary; the immediate full rerun passed 985. General
loop fixed-point, path-sensitive, and region analysis remain unsupported.

The conditional-loop arm-local return milestone gives each supported loop
`if`/`else if`/`else` arm an independent fixed-capacity local alias state before
a terminal return. Its exact parameter origin joins other function exits;
local-backed returns fail closed. Assignments and expressions inside these arms
remain conservative because loop-carried fallthrough effects are not modeled.
ORACLE-0002 accepted the loop-arm local alias and post-last-use owner reuse and
rejected a live competing mutable owner borrow with E0499. Windows gnullvm and
native Arch Linux WSL each pass 639 library tests, one component-interface
probe, 10 conformance tests, and 335 replacement tests: 985 compiler tests per
host. General loop dataflow, nested projections, and regions remain unsupported.

The nested-loop local return milestone applies one fixed local-only alias state
to the supported unconditional and conditional returns of a parsed nested loop
block. Exact parameter origins merge with other function exits; local-backed
returns, assignments, and expressions fail conservative. ORACLE-0002 accepted
the nested-loop local alias and post-last-use owner reuse and rejected a live
competing mutable owner borrow with E0499. Windows gnullvm and native Arch Linux
WSL each pass 639 library tests, one component-interface probe, 10 conformance
tests, and 335 replacement tests: 985 compiler tests per host. General nested-
loop fixed-point, path-sensitive, and region analysis remain unsupported.

The indexed aggregate call-origin milestone accepts a scalar-reference return
from an exact indexed place rooted at a compatible array-reference or slice-
reference parameter. Element type and mutability must match, and the projection
is exactly `Index` with at most one preceding explicit `Dereference`. The caller
retains the whole parameter origin. Identity, mismatched, shared-to-mutable,
deeper, and unrelated projections fail closed. ORACLE-0002 accepted the indexed
array-element return and post-last-use reuse and rejected a live competitor with
E0499. Windows gnullvm and native Arch Linux WSL each pass 640 library tests,
one component-interface probe, 10 conformance tests, and 335 replacement tests:
986 compiler tests per host. General aggregate and index-sensitive alias
analysis remain unsupported.

The slice-reference half now has direct evidence through a distinct mutable-
slice target and caller rather than inference from the array case. ORACLE-0002
accepted post-last-use indexed slice reuse and rejected a live indexed competitor
with E0499 and E0503. Both canonical hosts retain 640 library tests, one
component-interface probe, 10 conformance tests, and 335 replacement tests: 986
compiler tests per host. Subslice and disjoint-index alias analysis remain
unsupported.

The subslice call-origin milestone retains a compatible array/slice-reference
parameter origin through exact `Subslice` into a slice-reference result. Element
type and mutability must match and at most one explicit dereference may precede
the subslice. Caller preanalysis now classifies an unprojected unclassified read
of a loan-backed fat-reference local as `LoanUse`, preserving liveness when the
returned subslice is indexed. ORACLE-0002 accepted array and slice post-last-use
restoration, rejected both live competitors with E0499, and additionally emitted
E0503 for the slice. Windows gnullvm and native Arch Linux WSL each pass 640
library tests, one component-interface probe, 10 conformance tests, and 335
replacement tests: 986 compiler tests per host. General subslice disjointness,
deeper projections, and regions remain unsupported.

The projected-alias hardening milestone carries exact array-element and slice-
subslice parameter origins through one direct local alias. Explicit alias types
must equal the call target's return type before origin retention; inferred
aliases reuse the already compatible initializer result. Live competing caller
borrows fail, post-last-use owner access succeeds, and mismatched explicit alias
types fail the standalone interprocedural proof closed. Both canonical hosts
pass 986 compiler tests.

Alias return compatibility is now retained alongside every modeled local's
name, origin, and mutability. Plain reassignment consults that state, preventing
an explicitly incompatible mutable local from acquiring a return origin after
initialization. Straight-line and both-arm conditional controls fail closed;
the exact oracle accepts a compatible scalar-reference reassignment and rejects
the slice/scalar mismatch with E0308. Both canonical hosts pass 986 compiler
tests.

The bounded callee-local type-state milestone adds one fixed type slot per
modeled local and derives reference types through the canonical projection
walker. It supports address-of, exact index/subslice, identifiers, transparent
wrappers, sequence tails, and equal conditional results. A local-backed inferred
scalar alias may now be replaced on every modeled path by a compatible indexed
parameter reference and retain that parameter origin. Mismatched annotations or
ascriptions fail closed. ORACLE-0002 accepted direct and conditional local-
backed replacement and rejected a slice initializer annotated as scalar with
E0308. Both canonical hosts pass 986 compiler tests.

The mutable-to-shared projected-return milestone applies the canonical
directional reference compatibility relation to callee-local annotations and
return state. Direct loan derivation accepts a mutable borrow effect for a
shared destination but records the resulting loan as shared. A live caller
mutation conflicts, post-last-use mutation succeeds, and ORACLE-0002 rejects
the live indexed-array case with E0503. Both hosts pass 986 tests.

Shared fat-slice evidence covers a mutable slice subslice flowing through a
mutable local and then a shared local before return. Caller indexing retains
loan liveness: a live mutation conflicts and post-last-use mutation succeeds.
ORACLE-0002 rejects the live case with two E0503 diagnostics. Both hosts pass
986 compiler tests.

Alias assignment transfer now checks the inferred RHS reference type against
the retained local type before changing its origin. Mutable-to-shared remains
accepted; shared-to-mutable fails the standalone callee proof closed rather
than exploiting a compatible shared function return. ORACLE-0002 accepts the
former and rejects the latter with E0308. Both hosts pass 986 tests.

The projected-callee-origin foundation adds a fixed-capacity table keyed by
stable local index plus a validated nonempty projection. Entries retain final
projected type, parameter origin, and checked monotonic generation. Exact
replacement updates one key; branch intersection keeps only identical typed
origins and preserves the maximum generation. Invalid/empty projections and
capacity overflow fail closed. The first transfer integration now accepts one
exact straight-line numeric tuple-field assignment on a mutable local. The RHS
must match the projected field type; assignment replaces or clears the field
generation, and return inference consults the exact projected state. Existing
dereference/subslice local-origin behavior is unchanged.
ORACLE-0002 accepts a field initialized from one mutable-reference parameter and
replaced by a second, accepts owner reuse after the returned child's last use,
and rejects a live competing borrow of the second owner with E0499. It rejects
local-backed field initialization followed by parameter replacement with E0515,
and MRML likewise does not claim that shape. Windows and Arch each pass 641
library, 1 component, 10 conformance, and 335 replacement tests: 987 per host.

The conditional projected-origin integration forks the fixed projected state
for each arm and intersects fallthrough outcomes. Equal typed tuple-field
origins survive; unequal origins and a non-exhaustive path retaining the incoming
generation become unknown. Return-only arms remain exit evidence rather than
post-conditional state. ORACLE-0002 accepts exhaustive replacement from a first
mutable-reference parameter to a second, accepts second-owner reuse after the
returned child's last use, and rejects a live competitor with E0499. Windows
and Arch remain at 987 tests per host. Projected loop writes require the
separately bounded stable-loop rule below.

The stable projected-loop slice starts only from field evidence established
before the loop. It admits an identity reborrow of that same tuple field in one
modeled iteration, normalizes only the trailing identity dereference for origin
lookup, and intersects iteration state with the zero-iteration incoming state.
Changed or unavailable origins disappear. ORACLE-0002 accepts the exact pre-loop
replacement and loop self-reborrow, accepts second-owner reuse after last use,
and rejects a live competitor with E0499. Windows and Arch remain at 987 tests
per host; this is not general loop fixed-point or region inference.

Exact typed tuple-literal locals now seed projected origins at declaration.
Reference elements must match both their declared field type and the callee
return type, and only parameter-backed elements record evidence. Scalar and
local-backed fields remain non-origin state; invalid shapes and capacity
exhaustion fail closed. Top-level, conditional-action, conditional-loop, and
loop-body local paths share this transfer. ORACLE-0002 accepts direct initialized
field return and a loop identity-reborrow from that field, accepts owner reuse
after last use, and rejects a live competing borrow with E0499. Windows and Arch
remain at 987 tests per host.

Root-alias conditional and stable-loop joins now accept an exact typed projected
tuple-field RHS. Equal-origin exhaustive branches retain the field owner; a
missing branch with a different incoming alias becomes unknown. The loop joins a
projected self-reborrow with the zero-iteration projected incoming alias and
rejects a differing incoming origin. ORACLE-0002 accepts both equal-origin forms,
accepts restoration after last use, and rejects a live projected-owner competitor
with E0499. Windows and Arch remain at 987 tests per host.

Branch-local tuple initialization now feeds exact field origins into an outer
root alias in conditional action blocks. Before fallthrough joins, projected
state retains only entries whose local index predates the branch; scoped entries
cannot survive and collide with later slot reuse. ORACLE-0002 accepts equal-
origin branch-local assignment, rejects a live competitor with E0499, and rejects
return of a later local-backed tuple with E0515. A focused state test proves
prefix retention, and Windows/Arch remain at 987 tests per host.

The loop-local projected-origin slice creates an iteration-local tuple from an
outer alias identity reborrow, assigns its field back into the alias, and joins
that one-iteration origin with the zero-iteration incoming state. A local-backed
iteration clears the result; loop-local projected entries cannot survive the
incoming-state intersection. ORACLE-0002 accepts the stable form, rejects a live
competitor with E0499, and rejects local-backed escape with E0515. Windows and
Arch remain at 987 tests per host.

The projected loop-branch return slice permits a conditional loop arm to create
an exact typed tuple from a mutable-reference alias reborrow, assign that field
back into the alias, and immediately return it. The bounded action walker admits
only tuple-field assignment RHS places; other loop-arm assignments and
expressions remain conservative. ORACLE-0002 accepted the parameter-backed form
and post-last-use owner reuse, rejected a live competing owner borrow with
E0499, and rejected a local-backed field return with E0515. Windows and Arch
each pass 987 compiler tests. General loop dataflow and regions remain
unsupported.

Nested-loop projected-return evidence now applies the same bounded tuple-field
assignment action before a conditional return. ORACLE-0002 accepted the
parameter-backed reborrow and post-last-use restoration and rejected live
competition with E0499 and local-backed escape with E0515. Windows and Arch each
pass 987 compiler tests. This adds evidence, not nested fixed-point analysis.

Conditional projected-loan ancestry now follows an exact tuple field through
its recorded initializer and reassignment generations instead of stopping at
the projected path. A conditional assignment selecting either of two mutable-
reference fields therefore retains both possible owners: live mutation of each
owner fails, while both are restored after the child's last use. ORACLE-0002
accepted both restoration controls and rejected both competitors with E0499.
Windows and Arch each pass 987 compiler tests. Unknown projections and general
path-sensitive regions remain unsupported.

Projected ancestry across an overwritten tuple field retains every exact field
generation rather than selecting only the latest. ORACLE-0002 rejected use of
the initializer owner with E0503 and the replacement owner with E0499 while a
moved child remained live, then accepted both owners after last use. Windows and
Arch each pass 987 compiler tests. The traversal is fixed-capacity and does not
infer unknown aggregate generations.

Projected grandchild coverage proves that a mutable reborrow through a child
moved from an exact tuple field recursively reaches the field's parameter owner.
ORACLE-0002 rejected a live owner competitor with E0499 and accepted owner reuse
after the grandchild's last use. Windows and Arch each pass 987 compiler tests.
General indirect regions remain unsupported.

Projected call-assignment coverage proves that an exact identity-call result
assigned into an existing mutable-reference local retains ancestry when its
returned argument is a tuple field. ORACLE-0002 rejected a live ultimate-owner
competitor with E0499 and accepted restoration after the assigned child's last
use. Windows and Arch each pass 987 compiler tests. This does not generalize
unknown call summaries or projected arguments.

Conditional projected call-result coverage carries both exact tuple-field
owners through an identity call and assignment into an existing local.
ORACLE-0002 rejected live use of either owner with E0503 and accepted restoration
of each after the assigned child's last use. Windows and Arch each pass 987
compiler tests. General call summaries and path-sensitive regions remain
unsupported.

Projected shared-call invalidation now covers a shared call through an exact
tuple-field parent while a mutable child of that field is live. ORACLE-0002
rejected the overlap with E0502 and accepted the call after the child's last
use. Windows and Arch each pass 987 compiler tests. Unknown call summaries and
general regions remain unsupported.

Projected mutable-call invalidation covers a mutable call through an exact
tuple-field parent while a shared child of that field remains live. ORACLE-0002
rejected the overlap with E0502 and accepted the call after the child's last
use. Windows and Arch each pass 987 compiler tests. This complements the shared-
call case without claiming general projected call summaries or regions.

Mutable-to-shared projected assignment coverage now includes one exact tuple
field and a conditional choice between two fields. Each explicit shared-
reference destination retains all possible owners; focused MRML tests reject
live competing mutable reborrows and accept restoration after last use.
ORACLE-0002 rejected direct live-owner use with E0503 and accepted the same
restoration controls. Windows and Arch each pass 987 compiler tests.

Direct dereference writes through mutable-reference parameters now produce
loan-mutation effects as well as equivalent writes through proven local
reference loans. Focused coverage rejects mutation after direct shared
assignment, exact tuple-field assignment, and either arm of a conditional
tuple-field assignment while the child remains live; last-use controls remain
accepted. ORACLE-0002 rejected the direct form with E0506 and the conditional
projected form with E0503, and accepted the direct last-use control. Windows and
Arch each pass 987 compiler tests.

Nested parameter-owner invalidation now has focused coverage through a mutable
parent, mutable child, and shared grandchild. A direct incoming-owner write is
rejected while the grandchild remains live and accepted after its last use.
ORACLE-0002 reports E0503 for the live case and accepts the control. Windows and
Arch each pass 987 compiler tests; general indirect regions remain unsupported.

A shared child created after an optional mutable-parent reassignment now has
direct mutation coverage for both reaching owner generations. Each live-owner
write is rejected and both owners are writable after the child's last use.
ORACLE-0002 reports E0503 for both conflicts and accepts the combined control.
Windows and Arch each pass 987 compiler tests; this remains a bounded CFG join.

A single-exit loop-carried mutable-parent generation now has direct mutation
coverage for both its pre-loop and assigned-before-break owners. Both conflicts
fail while the post-loop shared child remains live, and both owners are restored
after its last use. ORACLE-0002 reports E0503 for each conflict and accepts the
combined control. Windows and Arch each pass 987 compiler tests.

Call-derived mutable references now have focused shared-child invalidation
coverage for the exact identity and conditional same-parameter summaries. A
direct owner write fails while the child is live and succeeds after its last
use. ORACLE-0002 reports E0503 for both call shapes and accepts both controls.
Windows and Arch each pass 987 compiler tests; general call summaries remain
unsupported.

Shared children of exact identity and conditional same-parameter mutable call
results now have return-outlives coverage. Parameter-backed children return;
equivalent local-backed children fail with the bounded outlives diagnostic.
ORACLE-0002 accepts both parameter cases and rejects both local escapes with
E0515. Windows and Arch each pass 642 library tests, one component-interface
probe, 10 conformance tests, and 335 replacement tests: 988 tests per host.

Explicit and conditional return sites now preserve the same call-derived shared-
child outlives result as the tail. Parameter-backed identity and conditional
same-parameter children return successfully; equivalent local-backed sites fail
closed. ORACLE-0002 accepts both parameter cases and rejects both local escapes
with E0515. Windows and Arch remain at 988 compiler tests per host.

Loop-contained direct and conditional returns now preserve call-derived shared-
child origins. Both parameter-backed forms pass, while matching loop-local
escapes fail closed. ORACLE-0002 accepts the parameter cases and rejects the
local cases with E0515. Windows and Arch remain at 988 compiler tests per host;
general loop fixed points remain unsupported.

Shared children of projected callee returns now preserve a proven second-
parameter origin through straight-line and exhaustive conditional tuple-field
replacement summaries. Parameter-backed calls pass; substituting a caller-local
second argument fails closed. ORACLE-0002 accepts the two parameter cases and
rejects both local escapes with E0515. Windows and Arch each pass 642 library
tests, one component-interface probe, 10 conformance tests, and 335 replacement
tests: 988 compiler tests per host. General interprocedural lifetime inference
remains unsupported.

Explicit and conditional return sites now retain the projected callee summary's
shared-child origin. Parameter-backed cases pass and matching local-backed cases
fail closed; ORACLE-0002 reports E0515 at both local return sites. Windows and
Arch remain at 988 compiler tests per host. General interprocedural lifetime
inference remains unsupported.

Loop CFG loan reachability now blocks the current borrower generation point and
does not attribute an earlier static use reached after event-order wrap to the
prior dynamic generation. A shared-call result used after owner mutation still
fails with `RuntimeBorrowConflict`/E0506; copying the pointee first permits owner
mutation and the next iteration. Windows and Arch remain at 989 compiler tests.
This is a bounded generation rule, not a general loop-region fixed point.

Mutable-reference identity calls now exercise the same loop-generation boundary.
A later same-iteration result use rejects owner mutation with
`RuntimeBorrowConflict`, matching ORACLE-0002 E0503; copy-before-mutation permits
the backedge. Windows and Arch remain at 989 compiler tests per host.

Conditional shared-reference call origins now exercise both possible owners at
the same loop-generation boundary. Mutation of either candidate before the
result's later same-iteration use fails with `RuntimeBorrowConflict`, matching
ORACLE-0002 E0506; copy-before-mutation permits both owner writes and the
backedge. Windows and Arch remain at 989 compiler tests per host.

Nested `while` control flow now exercises the conditional shared-reference
generation boundary at the inner backedge. Same-iteration owner mutation before
the later result use fails with `RuntimeBorrowConflict`, matching ORACLE-0002
E0506; copying first permits both owner writes across the nested loop structure.
Windows and Arch remain at 989 compiler tests per host. This is nested bounded
CFG evidence, not a general loop-region fixed point.

The callee-origin engine now applies one bounded transfer to each nonterminal
conditional arm inside a supported `while`, joins only its fallthrough states
(including the implicit unchanged path when no final `else` exists), and then
intersects that result with the zero-iteration input. Existing reference aliases
may receive direct assignments on fallthrough or terminal-return arms, and a
terminal return resolves the post-assignment state. Break/continue arms, nested-
loop transfers, expressions, and unstable origins remain conservative. ORACLE-
0002 accepts the stable same-origin reborrow and rejects a local-backed arm with
E0515. Windows and Arch remain at 989 compiler tests per host.

Nested-loop return-origin transfer now uses each return control's validated
action index and source order. Each reachable return replays only its preceding
bounded action prefix from the incoming state; an earlier unconditional nested
control makes later returns unreachable. Direct alias assignments in that exact
prefix are supported, while local-backed or inconsistent reachable exits remain
fail-closed. ORACLE-0002 accepts the ordered parameter-backed case and rejects
an earlier local-backed conditional return with E0515. Windows and Arch each
pass 643 library tests, one component-interface probe, 10 conformance tests, and
335 replacement tests: 989 compiler tests per host. General nested-loop fixed
points, path-sensitive regions, and complete Polonius reasoning remain
unsupported.

Nested-loop callee summaries now require every modeled inner backedge and
break/continue state edge to preserve the incoming outer local and projected
origins. Prefix transfer uses the same exact action indices as return transfer;
local declarations are discarded, and origin generations do not create false
instability. ORACLE-0002 accepts a temporary local alias restored to the
parameter before the backedge and rejects the unrestored local-backed cycle
with E0515. Windows and Arch each pass 643 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 989 compiler
tests per host. This is bounded stable-backedge proof, not general nested-loop
fixed-point or region inference.

Direct conditional returns now participate in the loop local-origin transfer
after supported declarations and assignments. Their taken edge merges the
current exact parameter origin into the function result, while their untaken
edge continues with the unchanged current state toward later operations and the
backedge/zero-iteration intersection. ORACLE-0002 accepts the stable same-origin
reborrow and rejects a local-backed replacement with E0515. Windows and Arch
each pass 643 library tests, one component-interface probe, 10 conformance
tests, and 335 replacement tests: 989 compiler tests per host. Unconditional
return, mixed break/continue transfer, and general fixed points remain
unsupported.

Mixed conditional loop arms now partition exit and backedge evidence: supported
terminal returns merge directly into the function result, while only nonterminal
arms join the one-iteration state before its zero-iteration intersection. Direct
alias assignment in a terminal arm is applied before resolving that return;
local-backed replacements fail closed. Break, continue, expressions, and nested-
loop transfer remain conservative. ORACLE-0002 accepts a parameter-backed
return/stable-fallthrough pair and terminal same-origin reassignment, and rejects
immediate or loop-carried local-backed returns with E0515. Windows and Arch
remain at 989 compiler tests per host.

Direct and conditional return sites inside supported `loop` blocks now retain
the projected callee summary's shared-child origin. Parameter-backed second
arguments pass and matching loop-local second arguments fail closed. ORACLE-0002
accepts both parameter cases and rejects both local escapes with E0515. Windows
and Arch each pass 642 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 988 compiler tests per host.
General loop and region fixed points remain unsupported.

Nested supported `loop` returns now retain projected callee-summary shared-child
origins. Every direct place passed to a reference-typed parameter receives its
implicit reborrow effect. Every reference argument loan remains live with a
reference result, while only the proven origin supplies its pointer ancestry.
The formerly conservative nonterminal inner backedge now matches ORACLE-0002
and passes after the result dies; a competing borrow of a non-origin argument
while the result is live fails with `RuntimeBorrowConflict`, matching E0499. An
inner-loop-local origin still fails with E0515. Windows and Arch each pass 642
library tests, one component-interface probe, 10 conformance tests, and 335
replacement tests: 988 tests per host. General loop fixed points are unsupported.

A focused non-origin-local case proves that returned-pointer ancestry and call-
argument loan lifetime remain distinct: the result origin resolves to the
parameter-backed second argument, but a local first-argument loan still prevents
escape. MRML fails with `RuntimeReferenceOutlivesFunction`, matching ORACLE-0002
E0515. Both hosts remain at 988 compiler tests.

The complementary last-use case copies through the result, then mutates the
non-origin local successfully after its tied loan dies. ORACLE-0002 accepts the
same non-lexical release. Windows and Arch remain at 988 compiler tests.

Conditional same-place call arguments now have focused joined-reborrow evidence.
Both arms borrow under the expected mutable-reference parameter type; a live
result rejects a competing owner borrow with `RuntimeBorrowConflict`/E0499, and
post-last-use mutation succeeds. Both hosts remain at 988 compiler tests.

Distinct-owner conditional arguments retain both possible loans at the join.
A live result blocks competing access to either owner with
`RuntimeBorrowConflict`, matching ORACLE-0002 E0503; after the result's last use,
both owners can be mutated. Windows and Arch remain at 988 compiler tests.

Conditional call-result escape joins now have direct evidence: two parameter-
backed arms may return a shared child, while a parameter/local pair fails with
`RuntimeReferenceOutlivesFunction`, matching ORACLE-0002 E0515. Both hosts
remain at 988 compiler tests; general region inference remains unsupported.

A bounded scalar `shared_identity(&u16) -> &u16` call target now covers shared-
reference parameter/result liveness. A live result rejects owner mutation with
`RuntimeBorrowConflict`, matching ORACLE-0002 E0502; after copying the pointee,
owner mutation succeeds. Windows and Arch remain at 988 compiler tests.

Scalar shared-call escape analysis now has a focused unit: a parameter-backed
`shared_identity` result returns successfully, while a local-backed result fails
with `RuntimeReferenceOutlivesFunction`, matching ORACLE-0002 E0515. Windows and
Arch each pass 643 library tests, one component-interface probe, 10 conformance
tests, and 335 replacement tests: 989 compiler tests per host.

Conditional shared-reference call arguments now retain both possible owner loans
at their join. A live result rejects mutation of either owner with
`RuntimeBorrowConflict`, matching ORACLE-0002 E0506; after last use, both owners
are mutable. Windows and Arch remain at 989 compiler tests per host.

Conditional shared-call escape joins accept two parameter-backed arms and reject
a parameter/local origin set with `RuntimeReferenceOutlivesFunction`, matching
ORACLE-0002 E0515. Both hosts remain at 989 compiler tests; general shared-region
inference remains unsupported.

Multi-field tuple literals retain a separate projected origin per field. A
conditional reference element seeds its field only when both arms prove the
same parameter; unequal first/second origins fail closed. Focused caller tests
retain the second owner's loan, reject a live competitor, and accept restoration
after last use. ORACLE-0002 accepts the exact equal-origin conditional element
and rejects the competitor with E0499. Both hosts remain at 987 tests.

One consuming move from an initialized tuple field into an explicitly typed
reference local now retains the field's parameter origin through return. The
same transfer covers an equal-origin conditional field. Non-tuple or unavailable
local types make the projected-initializer hook a no-op rather than aborting an
already valid alias proof; malformed tuple initialization remains conservative.
ORACLE-0002 accepts both moved-alias forms, accepts owner restoration after last
use, and rejects a live competitor with E0499. Windows and Arch remain at 987
tests per host.

The projected-origin move-chain evidence now covers two successive consuming
reference locals plus one post-join move after exhaustive equal-origin field
assignment and stable loop field reborrow. The retained parameter origin crosses
each local generation without replacing the preceding projected or control-flow
proof. ORACLE-0002 accepts the chain, conditional, and loop forms, accepts owner
restoration after last use, and rejects the live chain competitor with E0499.
Windows and Arch remain at 987 tests per host.

Numeric tuple fields now participate in bounded reference RHS type inference.
Assignment from a compatible field into an existing root reference alias carries
the field's parameter origin; a local-backed field clears it. The established
inferred local-backed alias replacement remains accepted because type eligibility
is not incorrectly equated with initializer origin. ORACLE-0002 accepts the
projected and inferred replacement forms, accepts restoration after last use,
and rejects the live projected-owner competitor with E0499. Windows and Arch
remain at 987 tests per host.

Inferred locals now become reassignment-origin eligible only when their
initializer already proved a compatible parameter origin. This preserves valid
indexed scalar alias replacement while preventing an inferred slice alias from
acquiring a scalar return origin through direct or both-arm conditional
assignment. ORACLE-0002 accepts the compatible replacement and rejects the
inferred mismatch with two E0308 diagnostics. Both hosts pass 986 tests.

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

The inferred projection-equality milestone binds a bounded projection and
expected term in one root inference universe. It proves exact, generic, and
where-clause premises before instantiating the selected associated value, then
merges concrete or symbolic results into the existing fixed constraint state.
Nested generic projection templates reuse the 16-frame cycle/overflow guard.
Windows gnullvm and native Arch Linux WSL each pass 503 library tests, one
component-interface probe, 10 conformance tests, and 335 replacement tests: 849
compiler tests per host. Projection-bearing type terms and premises, predicate
conjunction composition, backtracking, caching, coinduction, and source syntax
remain unsupported.

The mixed inferred-predicate milestone admits up to eight implemented-trait or
projection-equality predicates under one existential binder and one fixed root
constraint state. Ambiguous predicates roll back tentative refinement and are
retried after another predicate proves; a no-progress pass remains ambiguous.
Cross-predicate contradictions, projection cycles, empty conjunctions, and
capacity limits have focused tests. Windows gnullvm and native Arch Linux WSL
each pass 507 library tests, one component-interface probe, 10 conformance
tests, and 335 replacement tests: 853 compiler tests per host. Projection
equalities in where-clause premises, general projection-bearing type terms,
backtracking, caching, coinduction, and source syntax remain unsupported.

The projection-premise representation milestone extends bounded where clauses
and generic implementations with projection equality under the existing shared
eight-predicate capacity. Concrete, rigid, and existential instantiation retain
the projection goal, associated-type identity, and expected term. Proof entry
points without associated-value environments reject such premises as no
solution. Windows gnullvm and native Arch Linux WSL each pass 509 library tests,
one component-interface probe, 10 conformance tests, and 335 replacement tests:
855 compiler tests per host. Projection-aware recursive premise proof, general
projection-bearing type terms, backtracking, caching, coinduction, and source
syntax remain unsupported.

The projection-aware inferred-proof milestone evaluates instantiated projection
premises on bounded clauses and generic implementations in the same root state
as implemented-trait premises. Ambiguous attempts roll back and retry after
other premise refinement; nested projection normalization recursively uses the
same aware environment. A separate 16-transition nesting budget bounds
projection-to-proof recursion. Windows gnullvm and native Arch Linux WSL each
pass 513 library tests, one component-interface probe, 10 conformance tests,
and 335 replacement tests: 859 compiler tests per host. Concrete/rigid
projection-premise proof, general projection-bearing type terms, backtracking,
caching, coinduction, and source syntax remain unsupported.

The projection-bearing term milestone interns up to 64 leaf or projection nodes
in an acyclic backward-referenced arena. Projection trait self/argument positions
may reference earlier terms, and 16-frame normalization uses the projection-
aware environment while retaining root inference substitutions. Windows gnullvm
and native Arch Linux WSL each pass 518 library tests, one component-interface
probe, 10 conformance tests, and 335 replacement tests: 864 compiler tests per
host. Whole term-bearing goal selection, projection terms in binders,
concrete/rigid projection-premise proof, backtracking, caching, coinduction, and
source syntax remain unsupported.

The projection-bearing goal milestone normalizes every self and argument term
through one shared inference state, then sends the resulting flat goal through
exact/generic/clause selection and projection-aware premise proof. Windows
gnullvm and native Arch Linux WSL each pass 519 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 865 compiler
tests per host. Projection terms in binders, clause heads, and premise type
positions, concrete/rigid projection-premise proof, backtracking, caching,
coinduction, and source syntax remain unsupported.

The concrete projection-premise entry point validates a fully concrete goal and
reuses the same fixed projection-aware constraint state, proof stack, associated-
value environment, and mixed predicate scheduler as existential proof. Matching
associated values prove while mismatches remain no solution; legacy environment-
free concrete proof continues to fail closed. Windows gnullvm and native Arch
Linux WSL each pass 531 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 877 compiler tests per host. Rigid
projection-premise proof remains unsupported.

The rigid concrete-projection milestone threads an optional associated-value
environment through the existing rigid generic/clause recursion. A skolemized
outer goal can prove fully concrete projection predicates under the same fixed
16-frame proof and projection limits; mismatches preserve no solution, and the
environment-free entry point remains fail closed. Projection goals or expected
values containing placeholders are rejected rather than treated as concrete.
Windows gnullvm and native Arch Linux WSL each pass 532 library tests, one
component-interface probe, 10 conformance tests, and 335 replacement tests: 878
compiler tests per host. General rigid projection normalization remains
unsupported.

The symbolic rigid-projection milestone selects premise-free generic associated
values with rigid heads, substitutes exact placeholder identities into parameter
results, and recursively normalizes nested projections through the existing
16-frame visited stack. Focused tests prove placeholder identity and report a
self-projection cycle distinctly. Implementations whose associated values depend
on trait or projection premises still fail closed in this rigid normalization
path. Windows gnullvm and native Arch Linux WSL each pass 534 library tests, one
component-interface probe, 10 conformance tests, and 335 replacement tests: 880
compiler tests per host.

The universal projection-term binder milestone mirrors the bounded existential
term arena but instantiates every bound parameter as a fresh placeholder in the
successor universe. Rigid term normalization preserves those identities through
nested associated projections before the existing rigid solver proves the flat
goal. Focused evidence covers a parameter-valued associated projection and
universe-index overflow. Windows gnullvm and native Arch Linux WSL each pass 538
library tests, one component-interface probe, 10 conformance tests, and 335
replacement tests: 884 compiler tests per host. Nested and mixed higher-ranked
term binders remain unsupported.

The universal projection-equality milestone binds a projection and expected term
to fresh placeholders in the successor universe, runs premise-aware rigid
normalization, and requires exact symbolic identity. It preserves ambiguity, no
solution, cycle, overflow, and universe-index overflow as distinct outcomes.
Windows gnullvm and native Arch Linux WSL each pass 539 library tests, one
component-interface probe, 10 conformance tests, and 335 replacement tests: 885
compiler tests per host. Nested/mixed higher-ranked predicates and source syntax
remain unsupported.

The mixed universal-predicate milestone admits up to eight implemented-trait or
projection-equality predicates under one top-level universal binder. Every
predicate shares the same fresh placeholder universe and is proven through the
premise-aware rigid environment without inference refinement. Focused tests
cover mixed success, exact symbolic contradiction, an empty conjunction,
capacity rejection, recursive cycles, and universe overflow. Windows gnullvm and
native Arch Linux WSL each pass 540 library tests, one component-interface probe,
10 conformance tests, and 335 replacement tests: 886 compiler tests per host.
Nested higher-ranked binders and source syntax remain unsupported.

The nested universal-prefix milestone admits a fixed sequence of binder levels
before a terminal mixed predicate conjunction. Each level advances the universe
and restarts level-local placeholder identities, while globally indexed bound
parameters preserve exact scope across levels. Binder levels and total parameters
are bounded by the existing generic capacity; adding a binder after predicates
fails closed. Focused tests cover same-local-ID/different-universe identity,
cross-universe mismatch, valid nested proof, total-scope and universe overflow,
closed-prefix admission, and recursive cycles. Windows gnullvm and native Arch
Linux WSL each pass 541 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 887 compiler tests per host.
Branching scopes and binders nested inside predicate terms remain unsupported.

The universal branch-forest milestone combines up to eight independent nested
prefixes. Branches receive consecutive non-overlapping universe segments, while
the forest globally caps eight predicates and 16 binder levels so branching
cannot amplify the solver beyond existing fixed work. Focused tests cover mixed
branch success, a missing later branch, later-segment universe overflow,
predicate, binder, and branch capacity, and recursive cycles. Windows gnullvm
and native Arch Linux WSL each pass 542 library tests, one component-interface
probe, 10 conformance tests, and 335 replacement tests: 888 compiler tests per
host.
Binders nested inside predicate terms and source syntax remain unsupported.

The rigid coinduction milestone adds an explicit fixed classification of at most
64 coinductive trait identities. A repeated rigid proof path succeeds only when
every goal from the cycle entry onward is classified; unclassified and mixed
inductive/coinductive cycles retain the existing `Cycle` result. Duplicate and
capacity admission fail explicitly. Windows gnullvm and native Arch Linux WSL
each pass 543 library tests, one component-interface probe, 10 conformance tests,
and 335 replacement tests: 889 compiler tests per host. Projection-premise,
inference, and source-level coinduction remain unsupported at this milestone.

The coinductive projection-premise milestone threads the same explicit trait
classification through rigid proof with an associated-value environment. Every
projection equality is still normalized and compared before a classified trait
cycle can succeed. Missing values remain `NoSolution`, unclassified paths remain
`Cycle`, and projection-normalization cycles are not treated as coinductive.
Windows gnullvm and native Arch Linux WSL each pass 544 library tests, one
component-interface probe, 10 conformance tests, and 335 replacement tests: 890
compiler tests per host. Inference and source-level coinduction remain
unsupported.

The universal coinduction-composition milestone applies the explicit
classification to implemented-trait predicates inside nested universal branch
forests. Each branch still receives its disjoint universe segment, projection
equalities still normalize rigidly, and only the repeated classified trait cycle
changes from `Cycle` to `Proven`. The existing mixed branch test covers an
ordinary implemented predicate, a rigid projection equality, and a later
coinductive cycle. Windows gnullvm and native Arch Linux WSL each pass 544
library tests, one component-interface probe, 10 conformance tests, and 335
replacement tests: 890 compiler tests per host. Inference and source integration
remain unsupported.

The resolved-inference coinduction milestone reapplies the current substitution
to every stored goal before classifying a repeated existential proof path. A
cycle succeeds only when all cycle goals are inference-free and all trait
identities are explicitly coinductive. A preceding exact sibling obligation can
therefore resolve a variable and preserve that concrete answer, while an
otherwise identical unresolved self-cycle remains `Cycle`. Windows gnullvm and
native Arch Linux WSL each pass 545 library tests, one component-interface probe,
10 conformance tests, and 335 replacement tests: 891 compiler tests per host.
Backtracking over unresolved coinductive answers and source integration remain
unsupported.

The projection-resolved coinduction milestone threads classification through the
existential associated-value environment. An unresolved implemented-trait cycle
is deferred only while another bounded predicate may refine the state; a rigid
projection equality can then bind the query variable and the retried classified
cycle preserves that answer. Missing associated values remain `NoSolution`, and
a pass with no refinement remains `Cycle`. Windows gnullvm and native Arch Linux
WSL each pass 546 library tests, one component-interface probe, 10 conformance
tests, and 335 replacement tests: 892 compiler tests per host. General candidate
backtracking and source integration remain unsupported.

The source marker-trait milestone integrates the first trait syntax with the
canonical allocation-free module parser. It accepts bounded empty marker
declarations, preserves visibility and source spans, and lowers declarations in
source order into a separate fixed 64-entry table of stable solver `TraitId`
identities. Duplicate trait names, cross-kind duplicate definitions, and table
overflow fail explicitly. Unsupported generic parameters, supertraits,
associated items, methods, implementations, and trait-bearing types remain
closed. Windows gnullvm and native Arch Linux WSL each pass 551 library tests,
one component-interface probe, 10 conformance tests, and 335 replacement tests:
897 compiler tests per host.

The exact source-implementation milestone accepts empty `impl Trait for Type {}`
items in the canonical parser and lowers them into the existing exact solver
database. Declared traits resolve to their stable IDs; supported nominal paths
intern in a separate 64-entry source-order type table. Existing solver admission
rejects overlapping heads. Unknown traits, unsupported self types, nonempty
bodies, malformed forms, and capacity overflow fail with focused diagnostics.
Generic, negative, unsafe, and default implementations, trait arguments,
associated items, and source-level obligations remain unsupported. Windows
gnullvm and native Arch Linux WSL each pass 555 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 901 compiler
tests per host.

The concrete source-obligation milestone parses up to eight function-level
`where Type: Trait` predicates and proves every predicate in the module before
code generation. Predicate type paths share the source identity table with
implementation self types; declared trait names resolve to stable IDs and the
existing exact solver selects the implementation. Missing implementations,
unknown traits, duplicate predicates, unsupported bound/type forms, and
capacity exhaustion fail with focused source spans. Generic binders, inferred
operation obligations, trait arguments, associated items, and dispatch remain
unsupported. Windows gnullvm and native Arch Linux WSL each pass 560 library
tests, one component-interface probe, 10 conformance tests, and 335 replacement
tests: 906 compiler tests per host.

The bounded source-supertrait milestone parses up to eight marker supertraits,
resolves forward declaration names in a second pass, and validates the fixed
64-node graph as acyclic. Unknown and duplicate edges fail explicitly. After
all exact source implementation headers are admitted, each implementation must
prove every direct and transitive supertrait for the same stable type identity;
item order cannot bypass the check and missing ancestors fail before code
generation. Generic supertraits, associated items, `?Sized`, higher-ranked
bounds, and generic implementations remain unsupported. Windows gnullvm and
native Arch Linux WSL each pass 564 library tests, one component-interface
probe, 10 conformance tests, and 335 replacement tests: 910 compiler tests per
host.

The exact source-associated-type milestone parses up to eight `type Name;`
declarations per trait and requires exactly one `type Name = Type;` value in
each exact source implementation. Stable source-order identities feed the
existing bounded associated-value database and exact projection normalizer.
Missing, unknown, duplicate, and capacity-exhausted declarations or values fail
closed. Defaults, bounds, generics, methods, and source projection syntax remain
unsupported. Windows gnullvm and native Arch Linux WSL each pass 569 library
tests, one component-interface probe, 10 conformance tests, and 335 replacement
tests: 915 compiler tests per host.

The concrete source-projection milestone parses bounded function predicates of
the form `where <Type as Trait>::Item = Expected`, resolves all four stable
source identities, and queries the existing exact projection normalizer before
code generation. Unknown identities, absent or ambiguous implementations,
mismatched values, duplicate predicates, and capacity exhaustion fail closed.
Generic projections, projection types outside where-equalities, and associated
constraints on generic binders remain unsupported. Windows gnullvm and native
Arch Linux WSL each pass 572 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 918 compiler tests per host.

The concrete source-trait-argument milestone parses up to eight positional type
parameters per trait and concrete arguments on exact implementations,
implemented-trait predicates, and projection equalities. Argument-bearing exact
headers select independently and retain their own associated values. Duplicate
parameter names, wrong arity, unsupported argument types, overlap, unknown
types, and capacity exhaustion fail closed. Generic implementations, inference,
defaults, bounds, lifetimes, and const parameters remain unsupported. Windows
gnullvm and native Arch Linux WSL each pass 575 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 921 compiler
tests per host.

The flat generic source-implementation milestone admits up to eight implementation
type parameters constrained by complete self or trait-argument head positions.
Concrete obligations reuse the exact-plus-generic proof path, while parameter
and concrete associated values reuse generic projection normalization.
Exact/generic and generic/generic overlap, duplicate or unconstrained
parameters, wrong arity, missing values, generic supertraits, and compound
parameter positions fail closed. Generic where-premises, nested constructors,
bounds, source inference, specialization, and methods remain unsupported.
Windows gnullvm and native Arch Linux WSL each pass 578 library tests, one
component-interface probe, 10 conformance tests, and 335 replacement tests: 924
compiler tests per host.

The generic source-premise milestone parses up to eight implemented-trait
predicates after each flat generic implementation head. Premises use complete
parameter or concrete nominal self/argument positions, resolve stable trait
identity and arity, reject duplicates, and lower onto the existing bounded
generic clause. Concrete proof and generic associated-value normalization
recursively discharge them through the existing 16-frame solver. Missing
premises fail before code generation. Projection-equality premises, exact-
implementation premises, nested parameter constructors, and bounds remain
unsupported. Windows gnullvm and native Arch Linux WSL each pass 581 library
tests, one component-interface probe, 10 conformance tests, and 335 replacement
tests: 927 compiler tests per host.

The generic source projection-premise milestone parses equalities such as
`where <T as Parent<T>>::Output = u8` after flat generic implementation heads.
It resolves projected trait arguments, associated identity, and expected bound
type, stores the equality on the existing generic clause, and proves selected
implementations through the existing projection-aware environment before code
generation. Unknown, duplicate, mismatched, cyclic, and over-depth premises fail
closed. Nested projections and compound generic constructors remain
unsupported. Windows gnullvm and native Arch Linux WSL each pass 583 library
tests, one component-interface probe, 10 conformance tests, and 335 replacement
tests: 929 compiler tests per host.

The premise-bearing exact source-implementation milestone represents a concrete
implementation with `where` predicates as a zero-parameter bounded clause, not
an unconditional exact fact. This reuses generic clause coherence, recursive
implemented/projection premise proof, and generic associated-value normalization
while retaining a fully concrete head. Missing premises make the implementation
unavailable; an unconditional fact with the same head is rejected as overlap.
Conditional implementations of traits with source supertraits remain
unsupported. Windows gnullvm and native Arch Linux WSL each pass 586 library
tests, one component-interface probe, 10 conformance tests, and 335 replacement
tests: 932 compiler tests per host.

The projection-valued generic associated-type milestone parses values such as
`type Output = <T as Parent<T>>::Output`, resolves the projected trait,
arguments, and associated identity, and lowers them into the existing bounded
generic projection representation. Concrete obligations recursively prove the
projected implementation through the existing 16-frame normalizer. Missing
implementations fail closed; malformed projections, unknown identities, wrong
arity, and unsupported compound positions are rejected. Windows gnullvm and
native Arch Linux WSL
each pass 589 library tests, one component-interface probe, 10 conformance
tests, and 335 replacement tests: 935 compiler tests per host.

The exact projection-valued associated-type milestone represents an
unconditional concrete implementation containing a projection value as a
zero-parameter bounded clause. Existing exact/generic coherence is preserved,
and recursive implementation proof plus projection normalization are shared
with the generic source form. A missing projected implementation remains
unavailable before code generation. Windows gnullvm and native Arch Linux WSL
each pass 590 library tests, one component-interface probe, 10 conformance
tests, and 335 replacement tests: 936 compiler tests per host.

The inherited source-supertrait milestone lowers every direct marker
supertrait of a generic, conditional concrete, or projection-valued
implementation as a deduplicated bounded premise over the same self type. A
selected child implementation is unavailable unless each declared parent can
be proved, while an equivalent explicit premise is retained only once.
Parameterized supertrait paths remain unsupported and fail on arity. Windows
gnullvm and native Arch Linux WSL each pass 592 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 938 compiler
tests per host.

The exact-child generic-parent milestone validates supertraits of unconditional
exact child facts through the same projection-aware exact-plus-generic proof
environment used by source obligations. Generic and conditional parent
implementations are accepted only when every instantiated premise proves;
unavailable parents still fail closed before child admission. Windows gnullvm
and native Arch Linux WSL each pass 593 library tests, one component-interface
probe, 10 conformance tests, and 335 replacement tests: 939 compiler tests per
host.

The parameterized source-supertrait milestone admits paths such as
`trait Child<T>: Parent<T>` when every parent argument is a complete child
declaration parameter. Stable parent identity and arity resolve during
declaration admission; parameter indexes instantiate from exact, generic, or
conditional implementation heads and propagate through transitive parents.
Concrete and compound parent argument positions remain fail-closed. Windows
gnullvm and native Arch Linux WSL each pass 596 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 942 compiler
tests per host.

The concrete source-supertrait argument milestone represents each parent
argument as either a child declaration parameter index or a complete concrete
nominal type. Concrete identities intern in the bounded source type table and
instantiate through generic, exact, and transitive proof; mismatched parent
facts remain unavailable. Adjacent nested/enclosing `>>` closes now reach
semantic admission, where compound terms continue to fail closed. Windows
gnullvm and native Arch Linux WSL each pass 597 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 943 compiler
tests per host.

The source-supertrait `Self` milestone represents `Self` as an explicit parent-
argument identity rather than a nominal source type. Bound implementations
substitute their self term into inherited premises, while exact and transitive
validation substitute the concrete implementation self identity. Missing
matching parents remain unavailable before code generation. Windows gnullvm
and native Arch Linux WSL each pass 598 library tests, one component-interface
probe, 10 conformance tests, and 335 replacement tests: 944 compiler tests per
host.

The distinct source-supertrait instantiation milestone compares duplicate
requirements by parent identity and semantic bounded arguments. Distinct
requirements such as `Parent<u8> + Parent<u16>` remain separate through exact
validation and inherited-premise proof, and every instantiation must resolve;
an exact repeated requirement still fails admission. Windows gnullvm and native
Arch Linux WSL each pass 599 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 945 compiler tests per host.

The trait-declaration requirement milestone parses and admits up to eight flat
implemented-trait predicates after a declaration `where` keyword. `Self`, a
complete declaration parameter, and concrete nominal types substitute through
generic, conditional, and exact implementation clauses; prerequisites must
prove before the declared trait is available. Unknown traits, wrong arity,
duplicates, and compound terms fail closed during declaration admission.
Projection-equality declaration requirements resolve stable associated-type
identity during admission, substitute flat self/argument/expected terms through
each implementation head, and reuse the projection-aware premise solver;
unknown associated types fail closed. Windows gnullvm and native Arch Linux WSL
each pass 604 library tests, one component-interface probe, 10 conformance
tests, and 335 replacement tests: 950 compiler tests per host.

The trait-parameter-bound milestone parses `+`-separated implemented-trait
bounds on declaration type parameters and desugars them into the same bounded
requirement array used by an explicit declaration `where` clause. Both forms
share capacity, duplicate admission, substitution, and proof. Defaults,
lifetime/const parameters, `?Sized`, associated constraints, and compound type
terms remain fail-closed. Windows gnullvm and native Arch Linux WSL each pass
607 library tests, one component-interface probe, 10 conformance tests, and 335
replacement tests: 953 compiler tests per host.

The implementation-parameter-bound milestone parses `+`-separated implemented-
trait bounds on implementation type parameters and desugars them into the same
bounded premises as the explicit implementation `where` clause. Capacity,
duplicate rejection, substitution, recursive proof, and projection-aware
normalization are shared. Defaults, lifetime/const parameters, `?Sized`,
associated constraints, and compound type terms remain fail-closed. Windows
gnullvm and native Arch Linux WSL each pass 610 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 956 compiler
tests per host.

The associated-type-default milestone parses flat declaration defaults and
substitutes `Self`, a complete declaration parameter, or a concrete nominal
type through each exact or generic implementation head when no explicit value
is present. Explicit values override defaults. Projection-valued defaults with
flat `Self`/parameter/concrete projection positions resolve after the forward
identity phase and reuse bounded generic normalization; missing projected
implementations remain unavailable, while compound defaults remain fail-
closed. Windows gnullvm and native Arch Linux WSL each pass 617 library tests,
one component-interface probe, 10 conformance tests, and 335 replacement tests:
963 compiler tests per host.

The forward associated-identity milestone registers every bounded associated
identity after trait identities but before supertrait and declaration-
requirement validation. Projection requirements can consequently reference a
later trait declaration without source-order dependence, while missing
identities remain explicit errors. Windows gnullvm and native Arch Linux WSL
each pass 615 library tests, one component-interface probe, 10 conformance
tests, and 335 replacement tests: 961 compiler tests per host.

The inline associated-binding milestone parses bounds such as
`T: Iterator<Item = T>` or `T: Convert<u8, Output = T>` on declaration or implementation type parameters and
desugars them into the existing implemented-trait plus projection-equality
predicates. Both predicates share capacity, identity admission, duplicate
rejection, substitution, and projection-aware proof with explicit `where`
clauses. Positional arguments are preserved on both generated predicates so a
mixed list retains one semantic trait instantiation. Equivalent explicit
declaration and implementation `where` predicates use the same parser and
desugaring. Supertrait bindings retain positional arguments on the parent edge
and lower associated equalities into `Self` declaration requirements. Windows
gnullvm and native Arch Linux WSL each pass 627 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 973 compiler
tests per host.

The trailing trait-default milestone parses defaults such as
`trait Convert<Input = u8, Output = Input>` and materializes omitted arguments in exact and
generic implementation heads, supertraits, declaration/implementation
premises, projection values/defaults, and function obligations. Defaults must
form a trailing run of complete concrete nominal types, `Self`, or references
to an earlier trait type parameter. Forward/self-referential type-parameter,
lifetime/const, and compound defaults fail closed. `Self` and earlier-parameter
defaults copy already materialized typed terms without introducing inference. Windows gnullvm and
native Arch Linux WSL each pass 630 library tests, one component-interface
probe, 10 conformance tests, and 335 replacement tests: 976 compiler tests per
host.

Default-equivalent predicate admission compares recursively materialized
argument tuples: an omitted default chain and the same explicitly written types are one semantic
requirement and duplicate declaration/implementation premises are rejected.

The restricted naked-function milestone parses repeated unsafe attributes and
admits `#[unsafe(naked)]` only on unsafe, zero-parameter C-ABI functions with no
where predicates and a unit or never return. Its bounded `naked_asm!` body
accepts at most eight x86-64 instructions from `nop`, `ret`, `int3`, `ud2`,
`cli`, `sti`, `hlt`, `swapgs`, and `iretq`, validated 64-bit GPR `push`/`pop`
and register-indirect `jmp`, and register-to-register `mov`. A quote-aware
bounded scanner preserves operand commas without accepting escapes. A checked
decimal/hexadecimal parser admits signed `push` immediates only when their
sign-extended x86-64 encoding preserves the requested `i32` value, and admits
full-width signed-or-unsigned `mov r64, imm64`; malformed, overflowing, and
noncanonical separators fail.
Base-register memory operands admit 64-bit `mov` loads/stores,
memory-indirect `jmp`, and `lgdt`, `lidt`, and `invlpg`, including the required
SIB or zero displacement for `rsp`/`r12` and `rbp`/`r13`. The typed address
admits an optional base GPR, one optional index GPR at scale 1/2/4/8, and a
checked signed `i32` displacement. Base-less numeric and index-only addresses
emit the conventional SIB no-base disp32 form; the encoder otherwise selects
canonical no-displacement, disp8, or disp32 forms and rejects `rsp` as an index. It requires an
explicit terminating instruction and emits those exact bytes without ordinary function lowering.
The bounded two-pass layout recognizes numeric local definitions `2:` through
`9:` and direction-checked `jmp 2f`/`2b` references, rejects duplicate, missing,
or wrong-direction labels, and emits a checked rel32 displacement without an
object relocation.
The exact dated oracle accepts `raw` and `att_syntax` for `naked_asm!` while
rejecting inline-only options. The restricted MRML encoder admits either marker
alone or together. Its distinct AT&T grammar parses `%` registers, `$`
immediates, source-first moves, `disp(base,index,scale)` addresses including an
omitted base, and indirect `*` jumps for the supported instruction set;
cross-syntax inputs fail closed.
The object layer now has a typed fixed-capacity relocation collection. It checks
each four-byte patch range and undefined symbol, distinguishes branch from data,
and emits up to eight source-ordered ELF64 `.rela.text` records with
`R_X86_64_PLT32` or `R_X86_64_PC32` and addend `-4`, or corresponding COFF
`IMAGE_REL_AMD64_REL32` records. Repeated symbols retain exact source order and
relocation-free objects remain unchanged. The naked compiler returns validated
direct `jmp symbol` and RIP-relative symbolic memory operands as code plus typed
external-relocation records. Intel `[rip + symbol]` and AT&T `symbol(%rip)` work
across the supported loads, stores, indirect jumps, and system-memory forms.
Ordinary `MachineCode` compilation rejects unresolved output; only the
source-to-object pipeline consumes them immediately. A ninth unresolved
reference and invalid symbol identifiers fail closed in both syntax modes.
Focused tests compare the complete machine-code slice to prove that no prologue
or epilogue is inserted and reject unsupported safety, ABI, signature,
instruction, register, immediate, label, relocation, and fallthrough cases.
Symbol addends, additional relocation families, additional architectures, and
general inline assembly remain fail-closed.
Windows gnullvm and native Arch Linux WSL each pass 638 library tests,
one component-interface probe, 10 conformance tests, and 335 replacement tests:
984 compiler tests per host.

The first validated inline-assembly milestone operates inside ordinary x86-64
function lowering rather than the naked-function path. An unsafe function may
use a statement-position fixed `asm!("nop")` template with no operands and may
spell the exact-oracle-observed `nomem`, `nostack`, and `preserves_flags`
options once each. Exact byte comparison proves that one `nop` is inserted
while the existing prologue, return lowering, and epilogue remain unchanged.
Safe functions, operands, unknown templates, and duplicate, empty, or
unsupported options fail closed. Register allocation, register operands,
clobbers, memory effects beyond this fixed no-op, symbols, labels, control flow,
additional instructions/architectures, and general inline assembly remain
unimplemented. Windows gnullvm and native Arch Linux WSL each pass 639 library
tests, one component-interface probe, 10 conformance tests, and 335 replacement
tests: 985 compiler tests per host.

The next bounded inline-assembly increment adds one explicit typed input form:
`asm!("cmp rax, rax", in("rax") value)` accepts only a checked `u64`
expression, evaluates it through ordinary lowering into RAX, records its reads
in the ownership preanalysis, and emits the published 64-bit register compare.
Unique `nomem` and `nostack` options remain available, while
`preserves_flags` fails closed because this instruction modifies flags. Safe
functions, missing inputs, wrong types, other registers/templates, and invalid
options remain rejected. Windows gnullvm and native Arch Linux WSL each pass
639 library tests, one component-interface probe, 10 conformance tests, and
335 replacement tests: 985 compiler tests per host. Output/inout operands,
register classes, allocation, clobbers, arbitrary effects, and general inline
assembly remain unimplemented.

The explicit-output increment admits the single oracle-compatible form
`asm!("mov rax, 7", lateout("rax") value)` for a mutable `u64` local. The
bounded validator resolves the destination as an exact local identity, records
a write in ownership preanalysis and emission, emits the published immediate
move, and stores RAX into the destination's checked stack slot. `nomem`,
`nostack`, and `preserves_flags` are accepted uniquely because this fixed move
preserves flags. Immutable locals, parameters, unknown names, wrong types,
other registers/templates, and malformed operands fail closed. Windows gnullvm
and native Arch Linux WSL each pass 639 library tests, one component-interface
probe, 10 conformance tests, and 335 replacement tests: 985 compiler tests per
host. Inout operands, register classes/allocation, output projections,
clobbers, arbitrary effects, and general inline assembly remain unimplemented.

The explicit-inout increment admits
`asm!("inc rax", inout("rax") value)` for a mutable `u64` local. It records one
typed read-modify-write ownership effect, loads the exact checked stack slot,
emits the published 64-bit increment, and writes RAX back to that same slot.
Unique `nomem` and `nostack` options are accepted; `preserves_flags` is rejected
because the fixed increment modifies flags. Immutable locals, parameters, wrong
types, other registers/templates, and malformed operands fail closed. Windows
gnullvm and native Arch Linux WSL each pass 639 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 985 compiler
tests per host. Register classes/allocation, separate input/output expressions,
output projections, clobbers, arbitrary effects, and general inline assembly
remain unimplemented.

The distinct-inout increment additionally accepts
`asm!("inc rax", inout("rax") input => output)` where `input` is any supported
typed `u64` expression and `output` is a mutable `u64` local. Ownership
preanalysis records expression reads before a separate destination write rather
than conflating the two places into read-modify-write. Emission evaluates the
input once into RAX, applies the fixed increment, and stores only to the checked
output slot. Empty or repeated arrows, wrong input/output types, immutable or
parameter outputs, unsupported registers, and invalid options fail closed.
Windows gnullvm and native Arch Linux WSL each pass 639 library tests, one
component-interface probe, 10 conformance tests, and 335 replacement tests: 985
compiler tests per host. Register classes/allocation, projections, clobbers,
arbitrary effects, and general inline assembly remain unimplemented.

The first register-class increment implements the exact ORACLE-0002 shape
`asm!("inc {value}", value = inout(reg) ...)`. A bounded named-template parser
requires one identifier placeholder and the same declaration name, accepts the
existing same-place or distinct-place `u64` inout operands, and deterministically
allocates the sole class operand to RAX. It then uses the already verified
ownership and increment/writeback paths. Positional, missing, mismatched, or
repeated placeholders; other classes; additional operands; and invalid options
fail closed. Windows gnullvm and native Arch Linux WSL each pass 639 library
tests, one component-interface probe, 10 conformance tests, and 335 replacement
tests: 985 compiler tests per host. Multi-operand allocation, other classes,
projections, clobbers, arbitrary effects, and general inline assembly remain
unimplemented.

Exact ORACLE-0002 follow-up probes establish and the bounded option validator
implements output-bearing `pure+nomem`, `pure+readonly`, and standalone
`readonly`. `pure` requires an output and one of the two memory declarations;
`nomem` and `readonly` are mutually exclusive. Existing duplicate-option,
template-specific `preserves_flags`, and unsupported-option rejection remains
in force. Windows gnullvm and native Arch Linux WSL each pass 639 library tests,
one component-interface probe, 10 conformance tests, and 335 replacement tests:
985 compiler tests per host. This is declarative validation for fixed templates,
not evidence of actual assembly memory accesses, optimizer integration, general
clobbers/effects, or general inline assembly.

The two-register-class increment implements the exact oracle-proven named
`add {left}, {right}` template with a mutable `u64 inout(reg)` left local and a
typed `u64 in(reg)` right expression. Allocation is deterministic and non-
aliasing: the left value is preserved on the evaluation stack, the right lowers
once and moves to RCX, the left restores to RAX, and `add rax, rcx` writes back
only to the left slot. Ownership facts record right-expression reads and a left
read-modify-write effect. Invalid names, types, mutability, surplus operands,
classes, templates, and effects fail closed. Both canonical hosts pass 985
compiler tests. Three-or-more operands and general allocation remain absent.

The typed clobber increment admits the exact oracle-proven
`asm!("nop", clobber_abi("C"))` case. Ordinary statement lowering retains all
language values in checked stack storage across this boundary, so the fixed
no-op has no hidden register-resident value to preserve. Unknown ABI names,
generic outputs combined with a clobber ABI, additional declarations, and
non-no-op clobber templates fail closed. Both canonical hosts pass 985 compiler
tests. Other ABI clobber sets, explicit clobber outputs, and general clobber
integration remain absent.

Explicit RAX `lateout`, same-place `inout`, and a distinct `inout` output now
accept one exact numeric field of a mutable tuple local when that field is
`u64`. The compiler retains the tuple local as the public place identity,
records the selected `TupleField` projection in the typed write or read-modify-
write fact, validates bounds and element type before emission, and uses checked
stack-slot arithmetic for load and writeback. The distinct input remains an
ordinary typed expression and is evaluated exactly once before increment and
projected writeback. Immutable tuples, out-of-range fields, and non-`u64` fields
fail closed. Windows gnullvm and native Arch Linux WSL each pass 639 library
tests, one component-interface probe, 10 conformance tests, and 335 replacement
tests: 985 compiler tests per host. Nested, indexed, and dereferenced places
remain absent.

The constant indexed-output increment extends those three explicit RAX forms to
one compile-time numeric element of a mutable `[u64; N]`. Admission checks exact
array type, `u64` element type, mutability, and bounds before recording an
`ArrayElement` ownership projection; emission selects the checked stack slot for
load or writeback. The exact dated oracle accepted independently authored
`lateout`, same-place `inout`, and split `inout` probes with `values[1]` output
places. Windows gnullvm and native Arch Linux WSL each continue to pass 985
compiler tests. Dynamic indexes, nested aggregates, dereference outputs, and
general place lowering remain absent.

The static inline-output place consolidation replaces the separate scalar,
tuple, and array preanalysis/emission paths with one typed record carrying the
resolved local, bounded projection sequence, and checked stack offset. A common
preanalysis boundary records the write or read-modify-write fact and any exact
move-path effect; a common emission boundary verifies fact order and resolves
the destination slot. This removed 561 duplicated lines while preserving the
same fail-closed syntax and behavior. Both canonical hosts pass the same 985
compiler tests. This is a structural dependency for dynamic-index and
dereference places, not a claim that either is implemented.

The indirect inline-output milestone adds an explicit pointer-backed storage
kind to that typed place. Exact `*name` output syntax resolves either a local or
parameter whose base type is `&mut u64` or `*mut u64`, records the base identity
plus `Dereference` projection, and emits an indirect load/writeback for RAX
`lateout`, same-place `inout`, and distinct `inout`. Shared/immutable references,
const raw pointers, other pointee types, malformed names, and unknown bases fail
closed before emission. The exact dated oracle accepted all three independently
authored mutable-reference shapes. Windows gnullvm and native Arch Linux WSL
each pass 985 compiler tests. Dynamic indexes, nested projections, general
memory operands/effects, and general assembly remain absent.

The dynamic indexed-output milestone accepts `values[index]` when `values` is a
mutable `[u64; N]` local and `index` is an exact local or parameter of type
`usize`. Preanalysis records the index read and an `Index` output projection.
Emission evaluates the identifier once, traps when it is not less than `N`,
saves the checked value across the fixed RAX operation, and reuses the existing
bounded array-element load/store selector. Explicit `lateout`, same-place
`inout`, and distinct `inout` are covered. The exact dated oracle accepted all
three original forms. Windows gnullvm and native Arch Linux WSL each pass 985
compiler tests. General index expressions, nested projections, reference-array
index outputs, and general assembly remain absent.

The expression-indexed output milestone generalizes that dynamic place to any
`usize` expression supported by the bounded runtime expression engine. The
normal type checker and read preanalysis now validate the parsed index, and the
normal emitter evaluates it exactly once before the existing bounds check and
saved-index load/writeback path. Focused coverage includes remainder and grouped
addition expressions plus fail-closed non-`usize` indexes. The exact dated
oracle accepted original Rust 2024 `lateout`, same-place `inout`, and distinct-
input `inout` probes using those expression places. Windows gnullvm and native
Arch Linux WSL each pass 639 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 985 compiler tests per host.
Expressions outside the existing bounded subset, nested projections, reference-
array index outputs, and general assembly remain absent.

The indexed reference-output milestone extends that expression-indexed place to
mutable `[u64; N]` references held in parameters or locals. The typed place
records ordered `Dereference` and `Index` projections, resolves the pointer slot
before emission, and reuses the existing checked reference-array address/load/
store helpers after evaluating the index once. Parameter slots include all live
local stack slots; this also corrects explicit scalar dereference outputs when a
parameter pointee is written while locals are live. Focused tests cover RAX
`lateout`, same-place `inout`, distinct-input `inout`, local-reference storage,
and fail-closed shared/non-`u64` references. The exact dated oracle accepted all
three parameter-reference forms. Windows gnullvm and native Arch Linux WSL each
pass 639 library tests, one component-interface probe, 10 conformance tests, and
335 replacement tests: 985 compiler tests per host. Deeper nested projections,
slice outputs, general memory effects, and general assembly remain absent.

The indexed slice-output milestone extends the same typed destination to mutable
`[u64]` slice references in parameters or locals. Resolved storage keeps the fat
reference's pointer and runtime-length slots separate. Emission evaluates the
index once, preserves it on the evaluation stack, compares it unsigned against
the stored length, and then reuses the scaled reference load/store path. Slice
ownership follows the existing direct `Index` projection rather than inventing
an invalid dereferenced-unsized move path. Focused tests cover RAX `lateout`,
same-place `inout`, distinct-input `inout`, local slice storage, and fail-closed
shared/non-`u64` slices. The exact dated oracle accepted all three parameter-
slice forms. Windows gnullvm and native Arch Linux WSL each pass 639 library
tests, one component-interface probe, 10 conformance tests, and 335 replacement
tests: 985 compiler tests per host. Deeper nested places, other element types,
general memory effects, and general assembly remain absent.

The discarded explicit-output milestone accepts exact `lateout("rax") _` on the
fixed `mov rax, 7` template. It preserves the register-write declaration and
machine instruction while deliberately creating no destination place, write
fact, or writeback. The exact dated oracle accepted the independently authored
Rust 2024 form. Windows gnullvm and native Arch Linux WSL each pass 639 library
tests, one component-interface probe, 10 conformance tests, and 335 replacement
tests: 985 compiler tests per host. Other explicit clobbers, additional registers,
general effects, and general assembly remain absent.

The explicit RCX-output milestone generalizes the fixed output representation
to carry RAX or RCX identity. Exact `mov rcx, 7` plus `lateout("rcx")` reuses the
existing typed destination, ownership, bounds, and writeback path; a non-
discarded RCX value is transferred to the common writeback register only after
the declared instruction, while `_` produces no place effect or transfer. The
exact dated oracle accepted both independently authored Rust 2024 forms. Windows
gnullvm and native Arch Linux WSL each pass 639 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 985 compiler
tests per host. Other explicit registers, generic allocation, and general
assembly remain absent.

The explicit RCX-inout milestone generalizes the fixed inout representation to
carry the same RAX-or-RCX identity as fixed outputs. Exact `inc rcx` with
`inout("rcx")` accepts same-place and distinct-input `u64` destinations through
the existing typed place, ownership, bounds, and writeback machinery. The input
enters RCX before the declared instruction and returns to the common writeback
register afterward. Mismatched template and explicit-register pairs fail
closed. The exact dated oracle accepted both independently authored Rust 2024
forms. Windows gnullvm and native Arch Linux WSL each pass 639 library tests,
one component-interface probe, 10 conformance tests, and 335 replacement tests:
985 compiler tests per host. Other explicit registers, generic allocation, and
general assembly remain absent.

The explicit RCX-input milestone generalizes the fixed compare input to carry
RAX-or-RCX identity. Exact `cmp rcx, rcx` with `in("rcx")` uses the existing
checked `u64` expression and read-effect path, transfers the value to RCX, and
rejects mismatched template/register pairs. The exact dated oracle accepted the
independently authored Rust 2024 form. Windows gnullvm and native Arch Linux WSL
each pass 639 library tests, one component-interface probe, 10 conformance tests,
and 335 replacement tests: 985 compiler tests per host. Other explicit registers
and general assembly remain absent.

The fixed explicit-RDX milestone extends the shared typed register identity
across exact `cmp rdx, rdx` input, `mov rdx, 7` stored/discarded output, and
`inc rdx` same-place/distinct-input inout. It reuses the existing checked `u64`
expression, typed destination, ownership, bounds, and writeback machinery;
mismatched template/register pairs fail closed. The exact dated oracle accepted
all five independently authored Rust 2024 forms. Windows gnullvm and native Arch
Linux WSL each pass 639 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 985 compiler tests per host. Other
explicit registers, generic allocation, and general assembly remain absent.

The fixed explicit-GPR milestone replaces the three-register enum and manual
template branches with one bounded register code shared by parsing and checked
REX/ModRM encoding. Exact `cmp reg, reg` input, `mov reg, 7` stored/discarded
output, and `inc reg` same-place/distinct-input inout admit RAX, RCX, RDX, RSI,
RDI, and R8 through R15. Exact oracle probes accepted low and extended forms and
all R15 output/inout shapes; independent rejection probes rejected RBX, RSP, and
RBP, which MRML also rejects. Windows gnullvm and native Arch Linux WSL each pass
639 library tests, one component-interface probe, 10 conformance tests, and 335
replacement tests: 985 compiler tests per host. Arbitrary templates, register
classes/general allocation, and general assembly remain absent.

The premise-bearing rigid-normalization milestone proves the selected generic
implementation's instantiated trait and projection predicates before exposing
its associated value. It shares the caller's 16-frame rigid proof stack and
retains the separate 16-frame projection visited stack, so recursive premise
cycles and deep proof chains report `Cycle` and `Overflow` rather than escaping
the bounds. Focused tests cover satisfied and missing prerequisites, recursive
cycles, and proof-depth overflow. Windows gnullvm and native Arch Linux WSL each
pass 537 library tests, one component-interface probe, 10 conformance tests, and
335 replacement tests: 883 compiler tests per host.

The projection-bearing logical clause-head milestone stores up to 64 identified
bound heads separately from flat clauses. Every parameter must be constrained
by a direct leaf position before the instantiated head is normalized through
the shared projection environment and unified with the existential query;
parameters found only below projections fail closed as ambiguous. Windows
gnullvm and native Arch Linux WSL each pass 522 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 868 compiler
tests per host. Each clause may retain up to eight flat implemented-trait
premises, instantiated from the selected head substitution and discharged by
the existing depth- and cycle-bounded projection-aware proof. The recursive
integration milestone adds an opt-in existential entry point that threads the
database, copied candidate constraint states, and shared proof stack through
nested premises. Windows gnullvm and native Arch Linux WSL each pass 525 library
tests, one component-interface probe, 10 conformance tests, and 335 replacement
tests: 871 compiler tests per host. Nested success, ambiguity, cycle, and depth
overflow have focused tests. The projection-bearing generic-implementation
admission milestone adds a separate 64-entry table. It proves disjointness only
from trait/arity mismatch or an unequal direct concrete leaf and rejects every
projection or parameter relationship it cannot decide, including collisions
with exact and flat-generic heads. Windows gnullvm and native Arch Linux WSL
each pass 526 library tests, one component-interface probe, 10 conformance
tests, and 335 replacement tests: 872 compiler tests per host. Existential
selection now normalizes one admitted head in a copied root state, proves its
flat premises, and returns the stable implementation identity and inferred
substitution. Windows gnullvm and native Arch Linux WSL each pass 527 library
tests, one component-interface probe, 10 conformance tests, and 335 replacement
tests: 873 compiler tests per host. The recursive integration entry point
threads the admitted implementation table through nested premises before
logical-clause fallback, using the same copied root state and 16-frame proof
stack. Windows gnullvm and native Arch Linux WSL each pass 528 library tests,
one component-interface probe, 10 conformance tests, and 335 replacement tests:
874 compiler tests per host. Nested proof, cycles, and depth overflow have
focused tests. Projection-bearing implemented-trait premises now reuse each
head's validated term arena, instantiate in the selected substitution, and
normalize in the shared root state before flat recursive proof. Both hosts pass
the same 874 compiler tests, including a projected premise and its missing flat
dependency. The dependency-ordered premise milestone proves flat predicates
first and then normalizes term-bearing predicates in the refined root state.
Windows gnullvm and native Arch Linux WSL each pass 529 library tests, one
component-interface probe, 10 conformance tests, and 335 replacement tests: 875
compiler tests per host. A two-candidate projection becomes unique only after a
flat premise constrains its parameter. The mixed projected-premise scheduler
now retries both flat and term-bearing predicates after any sibling proves,
with per-attempt state rollback and explicit no-progress ambiguity. Windows
gnullvm and native Arch Linux WSL each pass 530 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 876 compiler
tests per host. Focused tests cover refinement in both directions. The direct-leaf coherence refinement
feeds every non-projection head position into the fixed equality unifier, so
repeated parameters can prove a projection-bearing head disjoint from peer,
exact, and flat-generic heads with conflicting concrete tuples. Both hosts pass
the same 875 compiler tests; projection nodes remain opaque and never prove
disjointness. Complete projection-equation coherence,
higher-ranked term binders, backtracking, caching, coinduction, and source
syntax remain unsupported.

The existential projection-term binder milestone mirrors the 64-node runtime
arena with bound concrete/parameter leaves, validates parameter scope, remaps
deduplicated identities during instantiation, and creates universe-aware root
inference variables before projection-bearing goal proof. Windows gnullvm and
native Arch Linux WSL each pass 520 library tests, one component-interface
probe, 10 conformance tests, and 335 replacement tests: 866 compiler tests per
host. Higher-ranked term binders, projection terms in clause heads and premise
type positions, concrete/rigid projection-premise proof, backtracking, caching,
coinduction, and source syntax remain unsupported.
