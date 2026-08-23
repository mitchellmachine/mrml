# mrml-rustc durable checkpoint

This file is the short recovery record for the independent compiler lane. It
does not replace `docs/COMPILER.md`, the oracle records, or the detailed
evidence ledger in `crates/mrml-rustc/README.md`. If chat history or a local
worktree is lost, recover this checkpoint first and verify every claim against
the named commit and current source.

## Recoverable baseline

- Branch: `main`
- Compiler checkpoint commit: `4879955d3813a37764a89a5cdd3956564adc0030`
  (`Preanalyze runtime assignment accesses`)
- Remote state when recorded: the named compiler checkpoint was pushed in the
  `origin/main` history; this recovery-document commit follows it.
- Preceding compiler commits: `996ac72` (`Preanalyze runtime loop declarations`),
  `e393097` (`Preanalyze sequential runtime declarations`), `8b4a529`
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
- pre-emission typing and stable identity assignment for every declaration form
  represented by the supported runtime body and loop parsers, mirroring pre-loop,
  loop, nested-loop, conditional-arm, and post-loop emission order with exact
  scoped-environment restoration and consumption validation; and
- a separate fixed 256-entry expectation table that pre-resolves every supported
  non-wildcard assignment target to stable identity, projections, type, access
  class, and span without disturbing the emitted read/write ledger's true order.

The compiler core remains `no_std`, forbids unsafe code, uses no global
allocator, emits COFF and ELF64 for the documented subset, and fails closed on
unsupported semantics.

This is an initial typed body-fact slice, not a complete typed body IR and not a
borrow checker. Expression reads are not yet preanalyzed. Names are still
resolved during emission, expanded inlined-helper declarations append
dynamically, and read-place discovery
is not yet run body-wide or consumed by every nested emission family. Parser
locals do not yet carry these IDs. Initialization/move paths, body basic blocks
and edges, borrows, loans, regions, Polonius-style analysis, and a general trait
solver are unimplemented.

## Next compiler work

Continue the dependency chain instead of filling arbitrary historical Rust
compatibility gaps:

1. make the standalone table preanalyze bounded read-place discovery across
   supported body expressions rather than rediscovering names during emission;
2. add explicit basic blocks and control-flow edges;
3. add initialization and move-path facts;
4. then stage shared loans, mutable loans/invalidation, reborrows, and
   flow-sensitive outlives reasoning with independent accepted/rejected probes.

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

The checkpoint source passed 572 tests on each host: 316
library tests, 10 conformance tests, 244 replacement tests, and 2 driver tests.
Warnings-denied Clippy also passed on both hosts. The commands were:

```powershell
$env:RUSTFLAGS='-C link-arg=/stack:16777216'
cargo +nightly-x86_64-pc-windows-gnullvm test -p mrml-rustc -p mrml-rustc-driver --target x86_64-pc-windows-gnullvm --offline
cargo +nightly-x86_64-pc-windows-gnullvm clippy -p mrml-rustc -p mrml-rustc-driver --target x86_64-pc-windows-gnullvm --all-targets --no-deps --offline -- -D warnings
```

```sh
cd /mnt/c/Users/Mitch/Documents/mrml
cargo +nightly-x86_64-unknown-linux-gnu test -p mrml-rustc -p mrml-rustc-driver --release --offline
cargo +nightly-x86_64-unknown-linux-gnu clippy -p mrml-rustc -p mrml-rustc-driver --release --all-targets --no-deps --offline -- -D warnings
```

The hygiene scan must remain empty:

```sh
rg -n "(^|[^A-Za-z])(std|alloc)::|unsafe\s*\{" crates/mrml-rustc/src crates/mrml-rustc-driver/src
```

Format only the compiler packages, preserve unrelated worktree changes, stage
overlapping documentation hunks interactively, fetch before pushing, never
force-push, and update this checkpoint after every pushed compiler milestone.
