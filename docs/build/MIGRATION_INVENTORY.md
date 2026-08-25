# Universal build migration inventory

**Status: PARTIALLY IMPLEMENTED.** The authoritative machine-readable inventory
is [`../../MRML.workspace`](../../MRML.workspace). All 42 current components are
classified and live in semantic `apps/`, `compiler/`, `packages/`, `services/`,
`system/`, `tests/`, or `tools/` homes; no tracked component remains under generic
`crates/`. The native resolver validates all 118 declared dependency edges
without Cargo metadata. Cargo remains a compilation bridge, so no claim is made
that direct-rustc migration or Cargo bridge removal is complete.

## Implemented first gate

- dependency-free Rust `tools/mrml`, bootstrapped with pinned Cargo/rustc;
- versioned native component inventory with distinct identity, path, Cargo bridge,
  class, target families, default selection, dependencies, features, outputs,
  and per-component input policies;
- Windows/Linux host recognition and MRML/Windows/Linux/UEFI/CUDA target families;
- structured list, doctor, build, test, target/toolchain failure, and planned-
  command results;
- bounded native graph resolution and `mrml audit` verification of component
  identities, local dependencies, features, outputs, build scripts, procedural
  macros, and direct source-input sites; see
  [BRIDGE_INVENTORY.md](BRIDGE_INVENTORY.md);
- explicit dependency-free `mrml-math`, `mrml-windows`, and `mrml-linux` native
  rustc build/test actions with validated crate names/types/sources,
  deterministic artifact paths, pinned target flags, exact dated rustup tool
  resolution independent of the caller's default, and no Cargo fallback;

The direct-action platform increment was checked on 2026-08-25 with exact dated
toolchains:

- Windows GNU/LLVM: direct `mrml-math` build/test — PASS, 1 test;
- Windows GNU/LLVM: direct `mrml-windows` build/test — PASS, 15 tests;
- Arch Linux WSL2 (`6.18.33.2-microsoft-standard-WSL2`): native `doctor` and
  `audit` — PASS, 42 components and 118 dependency edges;
- Arch Linux WSL2: direct `mrml-math` build/test — PASS, 1 test;
- Arch Linux WSL2: direct `mrml-linux` build/test — PASS, 4 tests.
- Windows GNU/LLVM: dependency-first direct `mrml-runtime` build/test with only
  the Windows platform extern — PASS, 38 tests;
- Arch Linux WSL2: dependency-first direct `mrml-runtime` build/test with only
  the Linux platform extern — PASS, 37 tests.
- Windows GNU/LLVM: direct build/test of the eight-component featureless runtime
  consumer layer — PASS, 31 tests;
- Arch Linux WSL2: the same eight-component direct build/test layer — PASS,
  31 tests.
- Windows GNU/LLVM: direct `mrml-rustc` library, inline harness, conformance
  target, and nightly-replacement target — PASS, 420 + 10 + 335 tests;
- Arch Linux WSL2: the same direct multi-output compiler-core action — PASS,
  420 + 10 + 335 tests. The declared 32 MiB stack is applied before exec; an
  earlier ELF-metadata-only attempt failed 29 stack-heavy tests and is not
  counted as parity evidence.
- Windows GNU/LLVM: direct `mrml-opus` build, 179 inline tests, and three example
  links — PASS;
- Arch Linux WSL2: the same Opus action — PASS after installing the explicit
  distribution `opus` test dependency. The initial `-lopus` absence failed
  closed and is not counted as parity evidence.

This is hosted WSL2 evidence. No KVM, bare-metal Linux, or physical hardware was
exercised by this increment.
- stage1 `mrml` selection, `mrml-rustc-driver`, current-host WHP/KVM selection,
  x86-64 UEFI routing, and lazy CUDA/PTX routing;
- duplicate `mrml-opus` root workspace member removed.
- dependency-free `mrml-math` moved to its semantic library home with all three
  consumer paths and the native graph updated; its Cargo bridge remains.
- `mrml-percent-encoding` moved with its runtime dependency and sole tools
  consumer updated; its malformed-input tests and Cargo bridge remain.
- `mrml-tokenizer` moved with its runtime dependency and sole trainer consumer
  updated; its UTF-8 round-trip/training tests and Cargo bridge remain.
- `mrml-zstd` moved with its runtime dependency, Wikipedia consumer, and patent
  source reference updated; its eight decoder tests and Cargo bridge remain.
- `mrml-zim` moved with its runtime dependency and Wikipedia consumer updated;
  its four archive/parser tests and Cargo bridge remain.
- `mrml-json` moved with its runtime dependency and six consumers updated; its
  four parser/writer tests and Cargo bridge remain.
- `mrml-wikipedia` moved after ZIM/Zstandard, with sibling semantic paths and its
  trainer consumer updated; its six extraction/filter tests and bridge remain.
- `mrml-opus` moved with its math dependency converted to a sibling semantic
  path; its codec implementation, examples, native-link declaration, and Cargo
  bridge remain unchanged.
- `mrml-windows` moved with all six consumer paths updated; its allocation-free
  Windows primitives, native-link declarations, and Cargo bridge remain
  unchanged.
- `mrml-linux` moved with all five consumer paths updated; its allocation-free
  Linux/Unix primitives, native-link declaration, and Cargo bridge remain
  unchanged. Linux execution evidence remains outstanding.
- `mrml-runtime` moved after both platform leaves, with its two dependency
  paths and all thirty-one inbound Cargo paths updated across thirty manifests;
  its runtime implementation, direct-input policy, and Cargo bridge remain
  unchanged.
- `mrml-crypto` moved after runtime, with its runtime edge and all fourteen
  inbound Cargo paths updated; its algorithms, feature behavior, review status,
  and Cargo bridge remain unchanged.
- `mrml-tls` moved after crypto/runtime, with both dependency paths and its two
  inbound Cargo paths updated; its protocol implementation, review status, and
  Cargo bridge remain unchanged.
- `mrml-http` moved after TLS/runtime, with both dependency paths and its two
  inbound Cargo paths updated; its HTTP/HTTPS implementation and Cargo bridge
  remain unchanged.
- `mrml-ssh` moved after crypto/runtime, with both dependency paths and its Git
  consumer path updated; its SSH/signing implementation and Cargo bridge remain
  unchanged.
- `mrml-error` moved after JSON/runtime, with both dependency paths and all
  eleven inbound Cargo paths updated; its error schema and Cargo bridge remain
  unchanged.
- `mrml-terminal-style` moved after its platform/runtime dependencies, with all
  three dependency paths and five inbound Cargo paths updated; its terminal
  behavior and Cargo bridge remain unchanged.
- `mrml-av1` moved after its platform/runtime dependencies, with all three
  dependency paths updated; its codec implementation, conformance evidence,
  feature behavior, review status, and Cargo bridge remain unchanged.
- dependency-free `mrml-rustc` moved to `compiler/core`, with its driver,
  recovery, oracle, checkpoint, hygiene-command, and patent-review paths
  updated; compiler semantics and its Cargo bridge remain unchanged.
- `mrml-rustc-driver` moved to `compiler/driver` after its core, error, and
  runtime dependencies; its three dependency paths, recovery/checkpoint paths,
  command behavior, and Cargo bridge remain unchanged.
- `mrml-git` moved to `tools/git` after error/runtime/SSH/terminal-style;
  its dependency paths already resolve to semantic packages, while library/bin
  behavior, compile-environment policy, and Cargo bridge remain unchanged.
- `mrml-tools` moved to `tools/host` after all eight dependencies, with all
  four inbound Cargo paths updated; its feature behavior, 26 external-command
  sites, compile-environment policy, and Cargo bridge remain unchanged.

The runtime move was checked on a Windows host:

- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm fmt -p mrml-runtime -- --check`
  — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm test -p mrml-runtime`
  — PASS, 38 tests;
- `.\target\debug\mrml.exe doctor` and `.\target\debug\mrml.exe audit`
  — PASS;
- `.\target\debug\mrml.exe build mrml-runtime` — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm clippy -p mrml-runtime --all-targets --no-deps -- -D warnings`
  — FAIL, six existing lints in unchanged runtime source and tests.

No Linux host or runtime execution was exercised by this move.

The cryptography move was checked on a Windows host:

- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm fmt -p mrml-crypto -- --check`
  — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm test -p mrml-crypto`
  — PASS, 27 tests;
- `.\target\debug\mrml.exe doctor`, `.\target\debug\mrml.exe audit`, and
  `.\target\debug\mrml.exe build mrml-crypto` — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm clippy -p mrml-crypto --all-targets --no-deps -- -D warnings`
  — FAIL, five existing lints in unchanged cryptography source.

No Linux host or runtime execution was exercised by this move.

The later native cryptography action was checked with the exact dated
2026-08-24 toolchains on Windows and Arch Linux WSL2. Its resolved effective
default set selects `runtime`, activating the exact optional runtime extern.
`mrml doctor`, `mrml audit`, `mrml build mrml-crypto`, and all 27 direct tests
passed on both hosts. This did not exercise external ACVP vector directories,
physical hardware, or establish independent cryptographic validation.

The TLS move was checked on a Windows host:

- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm fmt -p mrml-tls -- --check`
  — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm test -p mrml-tls`
  — PASS, 11 tests;
- `.\target\debug\mrml.exe doctor`, `.\target\debug\mrml.exe audit`, and
  `.\target\debug\mrml.exe build mrml-tls` — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm clippy -p mrml-tls --all-targets --no-deps -- -D warnings`
  — FAIL, seven existing lints in unchanged TLS source.

No Linux host or runtime execution was exercised by this move.

The later native TLS action was checked with the exact dated 2026-08-24
toolchains on Windows and Arch Linux WSL2. `mrml doctor`, `mrml audit`,
`mrml build mrml-tls`, and all 11 direct tests passed on both hosts. The
environment-selected live peer, external certificate fixtures, KVM, bare metal,
and independent protocol validation were not exercised.

The HTTP move was checked on a Windows host:

- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm fmt -p mrml-http -- --check`
  — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm test -p mrml-http`
  — PASS, 3 tests;
- `.\target\debug\mrml.exe doctor`, `.\target\debug\mrml.exe audit`, and
  `.\target\debug\mrml.exe build mrml-http` — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm clippy -p mrml-http --all-targets --no-deps -- -D warnings`
  — FAIL, one existing lint in unchanged HTTP source.

No Linux host or runtime execution was exercised by this move.

The later native HTTP action was checked with the exact dated 2026-08-24
toolchains on Windows and Arch Linux WSL2. `mrml doctor`, `mrml audit`,
`mrml build mrml-http`, and all three direct tests passed on both hosts. The
environment-selected live URL/range probes, KVM, bare metal, and external
network interoperability were not exercised.

The SSH move was checked on a Windows host:

- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm fmt -p mrml-ssh -- --check`
  — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm test -p mrml-ssh`
  — PASS, 23 tests;
- `.\target\debug\mrml.exe doctor`, `.\target\debug\mrml.exe audit`, and
  `.\target\debug\mrml.exe build mrml-ssh` — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm clippy -p mrml-ssh --all-targets --no-deps -- -D warnings`
  — FAIL, six existing lints in unchanged SSH source.

No Linux host or runtime execution was exercised by this move.

The later native SSH action was checked with the exact dated 2026-08-24
toolchains on Windows and Arch Linux WSL2. `mrml doctor`, `mrml audit`,
`mrml build mrml-ssh`, and all 23 direct tests passed on both hosts, including
loopback transport. No live remote, real external host key, external signing,
KVM, bare metal, or physical hardware was exercised.

The error-library move was checked on a Windows host:

- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm fmt -p mrml-error -- --check`,
  `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm clippy -p mrml-error --all-targets --no-deps -- -D warnings`,
  `.\target\debug\mrml.exe doctor`, and `.\target\debug\mrml.exe audit`
  — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm test -p mrml-error`
  — PASS, 1 test;
- `.\target\debug\mrml.exe build mrml-error` — PASS.

No Linux host or runtime execution was exercised by this move.

The terminal-style move was checked on a Windows host:

- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm fmt -p mrml-terminal-style -- --check`,
  `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm clippy -p mrml-terminal-style --all-targets --no-deps -- -D warnings`,
  `.\target\debug\mrml.exe doctor`, and `.\target\debug\mrml.exe audit`
  — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm test -p mrml-terminal-style`
  — PASS, 3 tests;
- `.\target\debug\mrml.exe build mrml-terminal-style` — PASS.

No Linux host or runtime execution was exercised by this move.

The AV1 move was checked on a Windows host:

- `.\target\debug\mrml.exe doctor`, `.\target\debug\mrml.exe audit`, and
  `.\target\debug\mrml.exe build mrml-av1` — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm test -p mrml-av1 --lib`
  — FAIL, 257 passed and 18 failed; sixteen failures reported stack overflow and
  two reported existing assertion/arithmetic failures;
- the same test with `RUST_MIN_STACK=33554432` — FAIL with the same 257/18
  result;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm fmt -p mrml-av1 -- --check`
  — FAIL on existing formatting differences;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm clippy -p mrml-av1 --all-targets --no-deps -- -D warnings`
  — FAIL, four existing lints in unchanged AV1 source.

No Linux host, NVIDIA feature path, conformance corpus, or physical decoder was
exercised by this move.

The later native-action increment was checked on Windows and Arch Linux WSL2
with the exact dated 2026-08-24 toolchains. On both hosts, `mrml doctor`,
`mrml audit`, and `mrml build mrml-av1` passed, including native compilation of
the declared `decode_ivf` example. The empty feature set left both optional
`nvidia` platform externs inactive and retained the unconditional runtime edge.
With a declared 32 MiB executable stack, `mrml test mrml-av1` reached 273 passed
and 2 failed on each host; those are the same pointer-identity assertion and
restoration arithmetic failure already present in the pinned Cargo baseline.
This establishes build-system parity only. No NVIDIA path, corpus, KVM, bare
metal, physical decoder, or complete AV1 interoperability was exercised.

The compiler-core move was checked on a Windows host with
`RUSTFLAGS=-C link-arg=/stack:16777216`:

- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm fmt -p mrml-rustc -- --check`
  and `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm clippy -p mrml-rustc --all-targets --no-deps -- -D warnings`
  — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm test -p mrml-rustc`
  — PASS, 765 tests (420 library, 10 conformance, 335 replacement);
- `.\target\debug\mrml.exe doctor`, `.\target\debug\mrml.exe audit`, and
  `.\target\debug\mrml.exe build mrml-rustc` — PASS;
- `rg -n "(^|[^A-Za-z])(std|alloc)::|unsafe\\s*\\{" compiler/core/src`
  — PASS with no matches.

No Linux compiler-core execution was exercised by this move; the existing
oracle records retain their exact historical Linux evidence and limitations.

The compiler-driver move was checked on a Windows host with
`RUSTFLAGS=-C link-arg=/stack:16777216`:

- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm fmt -p mrml-rustc-driver -- --check`,
  `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm clippy -p mrml-rustc-driver --all-targets --no-deps -- -D warnings`,
  `.\target\debug\mrml.exe doctor`, and `.\target\debug\mrml.exe audit`
  — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm test -p mrml-rustc-driver`
  — PASS, 2 tests;
- `rg -n "(^|[^A-Za-z])(std|alloc)::|unsafe\\s*\\{" compiler/core/src compiler/driver/src`
  — PASS with no matches;
- `.\target\debug\mrml.exe build mrml-rustc-driver` — FAIL because the
  selected MSVC target could not find `link.exe`.

No Linux compiler-driver execution was exercised by this move.

The later bin-only native action was checked with the exact dated 2026-08-24
toolchains on Windows and Arch Linux WSL2. The action declares no primary rlib,
binds the exact `mrml-rustc` binary source/output, and consumes native compiler-
core, error, and runtime artifacts. Native build and both inline tests passed on
each host, eliminating the earlier MSVC `link.exe` bridge failure. No emitted
object was executed, no oracle delta was measured, and no KVM, bare metal, or
physical hardware was exercised.

The target-feature prerequisite was then checked from both Windows and Arch
Linux WSL2 with the exact dated 2026-08-24 toolchains. The loader requires every
featureful action target to appear in exactly one feature set. Direct
`mrml build mrml-crypto --target native` passed on both hosts, selecting no
features and no runtime extern for `x86_64-unknown-none`; the host `runtime`
profile continued to pass all 27 tests. No target code was executed and no
bare-metal or physical-hardware claim follows.

The Git-tool move was checked on a Windows host:

- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm fmt -p mrml-git -- --check`,
  `.\target\debug\mrml.exe doctor`, and `.\target\debug\mrml.exe audit`
  — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm test -p mrml-git`
  — PASS, 52 tests;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm clippy -p mrml-git --all-targets --no-deps -- -D warnings`
  — FAIL, 15 existing lint instances in unchanged Git-tool source/tests;
- `.\target\debug\mrml.exe build mrml-git` — FAIL because the selected MSVC
  target could not find `link.exe`.

No Linux Git-tool execution or live remote operation was exercised by this
move.

The later native Git action was checked with the exact dated 2026-08-24
toolchains on Windows and Arch Linux WSL2. Its exact library and `mrml-git`
binary outputs build directly; `CARGO_PKG_VERSION=0.0.1` is an explicit action
input rather than inherited Cargo ambience. `mrml test mrml-git` passed 51
library tests plus the binary's one inline test on each host. `mrml doctor` and
`mrml audit` passed with 48 external-command sites. No live remote, external
host key/signing operation, KVM, bare metal, or physical hardware was exercised.

The host-tool move was checked on a Windows host:

- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm fmt -p mrml-tools -- --check`,
  `.\target\debug\mrml.exe doctor`, `.\target\debug\mrml.exe audit`, and
  `.\target\debug\mrml.exe build mrml-tools` — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm test -p mrml-tools`
  — FAIL, 31 passed and the installed-Edge integration test failed because
  DevTools was not exposed on its assigned port;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm clippy -p mrml-tools --all-targets --no-deps -- -D warnings`
  — FAIL, 19 existing lints in unchanged host-tool source.

No Linux host-tool execution, live remote web service, physical desktop/audio
route, or accessibility hardware was exercised by this move.

The later native host-tool action was checked with the exact dated 2026-08-24
toolchains. It records the resolved `runtime` set, repository-relative
`CARGO_MANIFEST_DIR=tools/host`, six universal externs, and one host platform
extern. Arch Linux WSL2 passed all 32 tests. Windows reproduced the Cargo
baseline at 31 passed and one installed-Edge DevTools-port failure. `mrml doctor`,
`mrml audit`, and native build passed on both hosts. No live remote web service,
physical browser, desktop/audio route, accessibility hardware, KVM, or bare
metal was established by this evidence.

The kernel move from `crates/mrml-kernel` to `system/kernel` was checked on a
Windows host without changing kernel source behavior:

- `cargo metadata --no-deps --format-version 1`,
  `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm fmt -p mrml-kernel -- --check`,
  `.\target\debug\mrml.exe doctor`, and `.\target\debug\mrml.exe audit`
  — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm test -p mrml-kernel`
  — FAIL, 472 passed and 2 existing stack-heavy tests overflowed the default
  Windows test-harness stack;
- the same test with `RUST_MIN_STACK=33554432` — FAIL with the same 472/2
  result because those tests execute on the harness main thread;
- the same test with `RUSTFLAGS=-C link-arg=/stack:67108864` — PASS, 474 tests;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm clippy -p mrml-kernel --all-targets --no-deps -- -D warnings`
  — FAIL on one existing `drop_non_drop` lint in unchanged kernel test code;
- `.\target\debug\mrml.exe build mrml-kernel` — FAIL closed with
  `NoMatchingComponents { target: WINDOWS }` because the kernel is declared
  only for the `MRML_NATIVE` target, not the Windows host target;
- `git grep -n 'crates/mrml-kernel/' -- ':!docs/build/MIGRATION_INVENTORY.md'`
  — PASS with no stale exact kernel-package path matches.

No Linux, KVM, WHP, nested-virtualization, UEFI, Secure Boot, TPM, IOMMU,
bare-metal, or physical-hardware execution was exercised by this path-only move.

The later native kernel action was checked from Windows and Arch Linux WSL2
with the exact dated 2026-08-24 toolchains. Each host directly cross-built the
kernel and empty-feature crypto dependency for `x86_64-unknown-none`, then used
a fresh host dependency graph and the explicitly declared 64 MiB test stack.
All 474 host tests passed on each host. `mrml doctor` and `mrml audit` passed.
The target rlib was not executed; no KVM, WHP, nested virtualization, UEFI,
Secure Boot, TPM, IOMMU, bare metal, or physical hardware was verified.

The bootloader move from `crates/mrml-kernel-image` to `system/bootloader` was
checked on a Windows host without changing bootloader source behavior:

- `cargo metadata --no-deps --format-version 1`,
  `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm fmt -p mrml-kernel-image -- --check`,
  `.\target\debug\mrml.exe doctor`, and `.\target\debug\mrml.exe audit`
  — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm check -p mrml-kernel-image --target x86_64-unknown-uefi --no-default-features --features kernel-image`
  — PASS;
- the corresponding `clippy` command with `--no-deps -- -D warnings` — PASS;
- `.\target\debug\mrml.exe build mrml-kernel-image` — FAIL closed with
  `NoMatchingComponents { target: WINDOWS }` because the bootloader is declared
  only for the `UEFI` target;
- `git grep -n 'crates/mrml-kernel-image/' -- ':!docs/build/MIGRATION_INVENTORY.md'`
  — PASS with no stale exact bootloader-package path matches.

No UEFI runtime, Secure Boot, TPM, bare-metal, or physical-hardware execution
was exercised by this path-only move.

The signed service-image move from `crates/mrml-service-image` to
`system/service-image` was checked on a Windows host without changing service
source behavior:

- `cargo metadata --no-deps --format-version 1`,
  `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm fmt -p mrml-service-image -- --check`,
  `.\target\debug\mrml.exe doctor`, and `.\target\debug\mrml.exe audit`
  — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm check -p mrml-service-image --target x86_64-unknown-uefi`
  and the corresponding strict `clippy` command with `--no-deps -- -D warnings`
  — PASS;
- `.\target\debug\mrml.exe build mrml-service-image` — FAIL closed with
  `NoMatchingComponents { target: WINDOWS }` because the service image is
  declared only for the `MRML_NATIVE` target;
- `git grep -n 'crates/mrml-service-image/' -- ':!docs/build/MIGRATION_INVENTORY.md'`
  — PASS with no stale exact service-image path matches.

The UEFI target compilation above is compile-time evidence only. No signed
service runtime, WHP/KVM, UEFI firmware, bare-metal, or physical-hardware
execution was exercised by this path-only move.

The configuration-service move from `crates/mrml-config` to `services/config`
was checked on a Windows host without changing service source behavior:

- `cargo metadata --no-deps --format-version 1`,
  `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm fmt -p mrml-config -- --check`,
  `.\target\debug\mrml.exe doctor`, and `.\target\debug\mrml.exe audit`
  — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm test -p mrml-config`
  — PASS, 31 tests;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm clippy -p mrml-config --all-targets --no-deps -- -D warnings`
  — FAIL on one existing `drop_non_drop` lint in unchanged configuration test
  code;
- `.\target\debug\mrml.exe build mrml-config` — PASS;
- `git grep -n 'crates/mrml-config/' -- ':!docs/build/MIGRATION_INVENTORY.md'`
  — PASS with no stale exact configuration-package path matches.

No Linux host/runtime, signed service, WHP/KVM, bare-metal, or physical-hardware
execution was exercised by this path-only move.

The storage-service move from `crates/mrml-storage` to `services/storage` was
checked on a Windows host without changing storage source behavior:

- `cargo metadata --no-deps --format-version 1`,
  `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm fmt -p mrml-storage -- --check`,
  `.\target\debug\mrml.exe doctor`, and `.\target\debug\mrml.exe audit`
  — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm test -p mrml-storage`
  — FAIL, 118 passed and 3 existing stack-heavy tests overflowed the default
  Windows test-harness stack;
- the same test with `RUSTFLAGS=-C link-arg=/stack:67108864` — PASS, 121 tests;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm clippy -p mrml-storage --all-targets --no-deps -- -D warnings`
  — FAIL on four existing `drop_non_drop` lints in unchanged storage test code;
- `.\target\debug\mrml.exe build mrml-storage` — PASS;
- `git grep -n 'crates/mrml-storage/' -- ':!docs/build/MIGRATION_INVENTORY.md'`
  — PASS with no stale exact storage-package path matches.

No Linux host/runtime, live block device, signed service, WHP/KVM, bare-metal,
or physical-storage execution was exercised by this path-only move.

The shared UEFI-library move from `crates/mrml-uefi` to
`packages/libraries/uefi` was checked on a Windows host without changing source
behavior:

- `cargo metadata --no-deps --format-version 1`,
  `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm fmt -p mrml-uefi -- --check`,
  `.\target\debug\mrml.exe doctor`, and `.\target\debug\mrml.exe audit`
  — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm test -p mrml-uefi --lib`
  — PASS, 24 tests;
- UEFI-target `check` and strict `clippy` for `mrml-uefi` with the `uefi-image`
  feature — PASS;
- `.\target\debug\mrml.exe build mrml-uefi` — PASS;
- `git grep -n 'crates/mrml-uefi/' -- ':!docs/build/MIGRATION_INVENTORY.md'`
  — PASS with no stale exact UEFI-library path matches.

No Linux host/runtime, UEFI firmware, Secure Boot, TPM, bare-metal, or physical-
hardware execution was exercised by this path-only move.

The kernel benchmark/test-harness move from `crates/mrml-kernel-bench` to
`tests/kernel-bench` was checked on a Windows host without changing harness
source behavior:

- `cargo metadata --no-deps --format-version 1`, formatting, strict Clippy,
  `.\target\debug\mrml.exe doctor`, and `.\target\debug\mrml.exe audit`
  — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm test -p mrml-kernel-bench`
  — PASS with 14 manual performance gates ignored and no measured tests run;
- `.\target\debug\mrml.exe build mrml-kernel-bench` — PASS;
- `git grep -n 'crates/mrml-kernel-bench/' -- ':!docs/build/MIGRATION_INVENTORY.md'`
  — PASS with no stale exact benchmark-package path matches.

No Linux host/runtime, release-mode performance gate, affinity-pinned physical
core, bare-metal, or physical-hardware execution was exercised by this move.

The signing-tool move from `crates/mrml-sign` to `tools/sign` was checked on a
Windows host without changing signing source behavior:

- `cargo metadata --no-deps --format-version 1`, formatting, strict Clippy,
  `.\target\debug\mrml.exe doctor`, and `.\target\debug\mrml.exe audit`
  — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm test -p mrml-sign`
  — PASS, 8 tests;
- `.\target\debug\mrml.exe build mrml-sign` — FAIL because the frontend's
  selected MSVC target could not find `link.exe` on this host;
- `git grep -n 'crates/mrml-sign/' -- ':!docs/build/MIGRATION_INVENTORY.md'`
  — PASS with no stale exact signing-tool path matches.

No Linux host/runtime, live signing key, Secure Boot enrollment, firmware,
bare-metal, or physical-hardware execution was exercised by this path-only move.

The KVM-library move from `crates/mrml-kvm` to `system/vmm/kvm` was checked on a
Windows host without changing VMM source behavior:

- `cargo metadata --no-deps --format-version 1`, formatting, strict Clippy,
  `.\target\debug\mrml.exe doctor`, and `.\target\debug\mrml.exe audit`
  — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm test -p mrml-kvm`
  — PASS, 7 portable ABI tests;
- `.\target\debug\mrml.exe build mrml-kvm` — FAIL closed with
  `NoMatchingComponents { target: WINDOWS }` because KVM is Linux-only;
- `rustup target list --installed` showed no Linux target, so Linux cross-check
  compilation was unavailable in this host toolchain;
- `git grep -n 'crates/mrml-kvm/' -- ':!docs/build/MIGRATION_INVENTORY.md'`
  — PASS with no stale exact KVM-library path matches.

No Linux host/runtime, `/dev/kvm`, nested virtualization, VM launch, or physical-
hardware execution was exercised by this path-only move.

The WHP-library move from `crates/mrml-whp` to `system/vmm/whp` was checked on a
Windows host without changing VMM source behavior:

- `cargo metadata --no-deps --format-version 1`, formatting, strict Clippy,
  `.\target\debug\mrml.exe doctor`, and `.\target\debug\mrml.exe audit`
  — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm test -p mrml-whp`
  — PASS, 22 tests with 1 manual live-mapping performance gate ignored;
- `.\target\debug\mrml.exe build mrml-whp` — PASS;
- `git grep -n 'crates/mrml-whp/' -- ':!docs/build/MIGRATION_INVENTORY.md'`
  — PASS with no stale exact WHP-library path matches.

Several focused tests are conditional on hypervisor availability; a passing
test process does not by itself prove those conditional operations ran. No
nested-virtualization, physical-hardware, VTL1, TPM, IOMMU, or remote-attestation
evidence was established by this path-only move.

The KVM-runner move from `crates/mrml-kvm-run` to `tools/vmm/kvm-run` was checked
on a Windows host without changing launcher source behavior:

- workspace metadata, formatting, strict Clippy, `mrml doctor`, and `mrml audit`
  — PASS;
- `cargo +nightly-2026-08-24-x86_64-pc-windows-gnullvm test -p mrml-kvm-run`
  — PASS, 5 portable handoff/policy tests;
- `.\target\debug\mrml.exe build mrml-kvm-run` — FAIL closed with
  `NoMatchingComponents { target: WINDOWS }` because this runner is Linux-only;
- stale exact `crates/mrml-kvm-run/` path scan — PASS.

No Linux host/runtime, CUDA, `/dev/kvm`, VM launch, nested virtualization, or
physical-hardware execution was exercised by this path-only move.

The WHP-runner move from `crates/mrml-whp-run` to `tools/vmm/whp-run` was checked
on a Windows host without changing launcher source behavior:

- workspace metadata, formatting, no-default-feature strict Clippy,
  `mrml doctor`, and `mrml audit` — PASS;
- pinned-nightly tests both with `--no-default-features` and with default CUDA
  enabled — PASS, 7 tests in each configuration; the default build compiled
  Rust CUDA PTX but did not execute it;
- `.\target\debug\mrml.exe build mrml-whp-run` — FAIL because the selected MSVC
  target could not find `link.exe` on this host;
- stale exact `crates/mrml-whp-run/` path scan — PASS.

No GPU execution, VM launch, nested virtualization, physical hardware, VTL1,
TPM, IOMMU, or remote-attestation evidence was established by this move.

The tensor/GPU-package move from `crates/mrml-tensor` to `packages/gpu/tensor`
was checked on a Windows host without changing tensor, CUDA, or build-script
source behavior:

- workspace metadata, formatting, `mrml doctor`, and `mrml audit` — PASS; the
  audit retained exactly one build script, one included file, and one external
  command for this package;
- pinned-nightly `cargo test -p mrml-tensor --lib` — PASS, 14 tests;
- strict all-target Clippy — FAIL on 38 existing warning/lint sites in unchanged
  tensor source and tests;
- `.\target\debug\mrml.exe build mrml-tensor` — FAIL while compiling the
  `no_std` build script for the selected MSVC target because its prebuilt core
  uses unwinding;
- stale exact `crates/mrml-tensor/` path scan — PASS.

No Linux runtime, CUDA execution, native GPU, WHP/KVM launch, or physical-
hardware evidence was established by this path-only move.

Patent review: `TRIGGERED` remains in force for the existing tensor/GPU
mechanisms; see [`../patents/REVIEW_LOG.md`](../patents/REVIEW_LOG.md). The
relocation itself introduced no new mechanism.

The model-library move from `crates/mrml-model` to `packages/libraries/model`
was checked on a Windows host without changing model source behavior:

- workspace metadata, formatting, strict package Clippy, `mrml doctor`, and
  `mrml audit` — PASS;
- pinned-nightly `cargo test -p mrml-model` — PASS, 7 tests; the unchanged
  tensor dependency emitted its existing warnings;
- `.\target\debug\mrml.exe build mrml-model` — FAIL at the relocated tensor
  dependency's already-recorded MSVC/no_std build-script unwind limitation;
- stale exact `crates/mrml-model/` path scan — PASS.

No Linux runtime, model corpus, CUDA/GPU execution, or physical-hardware
evidence was established by this path-only move.

The agent-library move from `crates/mrml-agent` to `packages/libraries/agent`
was checked on a Windows host without changing agent source behavior:

- workspace metadata, formatting, `mrml doctor`, and `mrml audit` — PASS;
- pinned-nightly `cargo test -p mrml-agent` — PASS, 20 tests; conditional live
  query test success does not prove that a remote query occurred;
- strict all-target Clippy — FAIL on 17 existing lint sites in unchanged agent
  source/tests;
- `.\target\debug\mrml.exe build mrml-agent` — FAIL at the relocated tensor
  dependency's already-recorded MSVC/no_std build-script unwind limitation;
- stale exact `crates/mrml-agent/` path scan — PASS.

No Linux runtime, live remote model service, CUDA/GPU execution, desktop tools,
or physical-hardware evidence was established by this path-only move.

The CLI move from `crates/mrml-cli` to `apps/cli` was checked on a Windows host
without changing application source behavior:

- workspace metadata, formatting, `mrml doctor`, and `mrml audit` — PASS;
- pinned-nightly no-default-feature tests — PASS with zero tests defined;
- no-default-feature strict all-target Clippy — FAIL on four existing lint sites
  in unchanged CLI source/test compilation;
- `.\target\debug\mrml.exe build mrml-cli` — FAIL at tensor's already-recorded
  MSVC/no_std build-script unwind limitation;
- stale exact `crates/mrml-cli/` path scan — PASS.

No Linux runtime, interactive CLI, remote model download, CUDA/GPU execution,
or physical-hardware evidence was established by this path-only move.

The machine-application move from `crates/mrml-machine` to `apps/machine` was
checked on a Windows host without changing application source behavior:

- workspace metadata, formatting, `mrml doctor`, and `mrml audit` — PASS;
- pinned-nightly no-default-feature tests — PASS, 4 protocol/parser tests;
- no-default-feature strict all-target Clippy — FAIL on 18 existing dead-code
  sites in unchanged test compilation;
- `.\target\debug\mrml.exe build mrml-machine` — FAIL at tensor's already-
  recorded MSVC/no_std build-script unwind limitation;
- stale exact `crates/mrml-machine/` path scan — PASS.

No Linux runtime, live machine session, remote model service, CUDA/GPU execution,
or physical-hardware evidence was established by this path-only move.

The server move from `crates/mrml-server` to `apps/server` was checked on a
Windows host without changing application source behavior:

- workspace metadata, formatting, `mrml doctor`, and `mrml audit` — PASS;
- pinned-nightly no-default-feature tests — PASS, 4 library tests plus an empty
  binary test target, including a controlled native-TCP test;
- no-default-feature strict all-target Clippy — FAIL on one existing dead-code
  lint in unchanged binary test compilation;
- `.\target\debug\mrml.exe build mrml-server` — FAIL at tensor's already-
  recorded MSVC/no_std build-script unwind limitation;
- stale exact `crates/mrml-server/` path scan — PASS.

No Linux runtime, externally exposed server, remote traffic, CUDA/GPU execution,
or physical-hardware evidence was established by this path-only move.

The trainer-tool move from `crates/mrml-trainer` to `tools/trainer` was checked
on a Windows host without changing trainer source behavior:

- workspace metadata, formatting, `mrml doctor`, and `mrml audit` — PASS;
- pinned-nightly tests — PASS, 4 training/export tests;
- strict all-target Clippy — FAIL on 8 existing dead-code sites in unchanged
  test compilation;
- `.\target\debug\mrml.exe build mrml-trainer` — FAIL at tensor's already-
  recorded MSVC/no_std build-script unwind limitation;
- stale exact `crates/mrml-trainer/` path scan — PASS.

No Linux runtime, production corpus, long-running training, CUDA/GPU execution,
or physical-hardware evidence was established by this path-only move.

`package`, `release`, `image`, and `publish` deliberately fail as `PLANNED`.
Linux, KVM, cross-host equivalence, physical UEFI/GPU, and release functionality
were not exercised by the Windows implementation environment.

## Current semantic classes

| Class | Current components/direction |
| --- | --- |
| `BOOTSTRAP_ONLY` | `tools/mrml`; Cargo stage zero, then self-build graph |
| `COMPILER` | `mrml-rustc` at `compiler/core`; driver at `compiler/driver` |
| `MRML_NATIVE` | kernel, service image, configuration, storage |
| `UEFI` | kernel-image bootloader artifact; `mrml-uefi` is shared support |
| `HOST_WINDOWS_LINUX` | Git at `tools/git`, host tools at `tools/host`; CLI/server/sign/trainer and VMM launchers remain transitional |
| `GPU` | tensor/CUDA compatibility path; native GPU remains separate |
| `TEST` | kernel benchmark |
| `SHARED` | reusable crypto/runtime/protocol/media/model/platform libraries |

The exact 42 entries live in `MRML.workspace`; this table must not become a
second inventory.

## Cargo-removal blockers

- Every component still has Cargo dependency metadata, but no tracked component
  remains beneath generic `crates/`. The root Cargo workspace still contains
  every component so the bridge resolves today's exact graph.
- `packages/gpu/tensor/build.rs` invokes rustc for CUDA PTX and is the one current
  build script. It must become an explicit structured build action.
- Dependency, feature, output, and source-input facts are persisted and fail
  closed on Cargo metadata or lexical-audit drift. Lexical discovery still
  cannot prove that arbitrary macro expansion introduces no additional input.
- Native graph construction now provides dependency-first ordering, cycle
  diagnostics, and target-scoped exact extern artifacts for migrated library
  nodes. Native integration-test outputs and bounded test-process stacks are
  explicit, native example outputs are checked and compiled, and exact feature
  sets can gate optional target-specific externs. Exact binary outputs, binary
  test harnesses, compile-time environment values, and bin-only actions are
  explicit. Twenty-six
  components now have native actions. Direct-rustc expansion still needs
  lock/digest validation and the remaining non-library actions before
  Cargo can be removed behind the remaining nodes.
- Moving all paths requires updating Cargo dependencies, docs, scripts, fixtures,
  and CI together and verifying both Windows/WHP and Linux/KVM. The present task
  intentionally establishes the graph before that high-churn move.

Named provider feature profiles close a host-projection gap in that resolver.
An extern may select a validated nondefault provider profile; the selected
profile participates in recursive-build identity and the rlib filename. The
kernel now binds crypto's empty `core` profile for `MRML_NATIVE`, Windows, and
Linux instead of acquiring crypto's host-default `runtime` feature during host
tests. Verification with the exact dated toolchains passed `mrml`'s 11 unit
tests and clippy, `mrml doctor`, `mrml audit`, the native kernel cross-build,
and all 474 kernel host tests on Windows gnullvm and Arch Linux WSL2. The
separate `libmrml_crypto__core.rlib` artifact was observed; this remains hosted
and cross-build evidence only.

The next bounded action adds explicit host-build projections without widening a
provider's public target declaration. Kernel permits Windows/Linux projection;
storage binds that artifact and crypto's empty `core` profile. With both exact
dated toolchains, `mrml` unit tests, clippy, doctor, and audit pass; storage
cross-builds for `x86_64-unknown-none` and its 64 MiB host harness passes all 121
tests on Windows gnullvm and Arch Linux WSL2. Twenty-four components are native
and 18 remain transitional. This is not physical-device or durability evidence.

Configuration is the next dependency-ordered native action. It declares only
crypto's empty `core` profile, kernel, and storage, matching its Cargo graph.
Both exact dated host toolchains pass doctor/audit, cross-build the library for
`x86_64-unknown-none`, and run all 31 projected host tests. Twenty-five
components are native and 17 remain transitional; no signed service or target
runtime was exercised.

Service-image requires a different compiler ABI from the default semantic
family: it is an MRML native service payload stored as PE, so its exact target is
`x86_64-unknown-uefi`. The resolver now validates that sole nondefault pairing,
propagates it through the complete dependency graph, and isolates the artifact
directory by triple. Both exact dated host toolchains pass the frontend tests,
clippy, doctor, and audit and emit PE32+ EFI applications in debug and release
profiles. Repeated builds are byte-stable within each host; Windows and Linux
hashes differ, so cross-host reproducibility remains unproved. Twenty-six
components are native and 16 remain transitional. No UEFI or signed-service
runtime was exercised.

## Next safe migration order

1. Move the next dependency-light leaf into `packages/libraries/`, update every
   reference, and prove Cargo-bridge and `mrml` builds agree.
2. Expand by semantic groups: shared libraries, services, system, host tools;
   keep compiler and bootstrap roots distinct.
3. Prove Windows WHP and Linux KVM matrices, then remove generic `crates/` only
   after repository-wide stale-path search returns none.
4. Add direct-rustc nodes using the implemented native resolver, leaving Cargo
   required only for clean-source stage-zero `mrml` bootstrap.

Patent review: `TRIGGERED` for the native dependency-resolver increment under the
existing package/cache/resolver review in
[`../patents/REVIEW_LOG.md`](../patents/REVIEW_LOG.md).
