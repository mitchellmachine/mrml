# mrml-rustc durable checkpoint

This file is the short recovery record for the independent compiler lane. It
does not replace `docs/COMPILER.md`, the oracle records, or the detailed
evidence ledger in `crates/mrml-rustc/README.md`. If chat history or a local
worktree is lost, recover this checkpoint first and verify every claim against
the named commit and current source.

## Recoverable baseline

- Branch: `main`
- Compiler checkpoint commit: `486fc87ae2fa4ff345abb90037f25a3684a31660`
  (`Discover bounded runtime read places`)
- Remote state when recorded: the named compiler checkpoint was pushed in the
  `origin/main` history; this recovery-document commit follows it.
- Preceding compiler commits: `aac7798` (`Bound runtime place projection
  facts`), `308c781` (`Record stable runtime identifier reads`), and `099b11c`
  (`Retain bounded runtime place facts`).
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
  duplicate empty base read.

The compiler core remains `no_std`, forbids unsafe code, uses no global
allocator, emits COFF and ELF64 for the documented subset, and fails closed on
unsupported semantics.

This is emission-side prerequisite state, not a typed body IR and not a borrow
checker. Names are still resolved during emission. Read-place discovery is not
yet run body-wide or consumed by every nested emission family. Parser and
semantic locals do not yet have stable IDs. Initialization/move paths, body
basic blocks and edges, borrows, loans, regions, Polonius-style analysis, and a
general trait solver are unimplemented.

## Next compiler work

Continue the dependency chain instead of filling arbitrary historical Rust
compatibility gaps:

1. move stable local/place/access identities out of emission into a bounded
   typed body-wide representation;
2. make that table consume bounded read-place discovery across supported body
   expressions rather than rediscovering names during emission;
3. add explicit basic blocks and control-flow edges;
4. add initialization and move-path facts;
5. then stage shared loans, mutable loans/invalidation, reborrows, and
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

The checkpoint source passed 565 tests on each host: 312 library tests, 10
conformance tests, 241 replacement tests, and 2 driver tests. Warnings-denied
Clippy also passed on both hosts. The commands were:

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
