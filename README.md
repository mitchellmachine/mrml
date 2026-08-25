# MRML

MRML—the **Mitchell Renouf Machine Learning Library**—is an AI-led,
human-directed experimental computing stack, implemented from first principles
in dependency-free Rust and validated incrementally across UEFI, KVM, Hyper-V,
Windows, and Linux.

The project began as a native local-LLM runtime and is growing into a sovereign
software stack: inference, media codecs, development tools, cryptography,
network protocols, virtualization, verified boot, and an x86_64 microkernel are
implemented inside this repository. The objective is not merely to replace
individual libraries. It is to minimize trusted dependencies from source code
and signed builds through boot, isolated execution, and accelerated inference.

MRML is dedicated to the public domain under CC0. It is experimental research,
not a production-secure operating system, a complete Rust compiler, or a
drop-in replacement for mature codec and inference ecosystems.

## Project scope

The planned canonical package, Store, immutable system-generation, image,
servicing, installer, and typed-administration architecture is defined in
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). It is not currently implemented.

The planned modern x86-64 support floor, Intel/AMD microcode policy,
heterogeneous scheduling, CPU budgets, power, sensors, and thermal safety are
defined in [docs/platform/CPU_PLATFORM.md](docs/platform/CPU_PLATFORM.md). The
reference CPUs are targets, not current physical-hardware support claims.

| Area | Repository-owned implementation | Current maturity |
| --- | --- | --- |
| Local inference | GGUF loading, tokenizer, Gemma-family execution, CPU kernels, Rust-to-PTX CUDA kernels, KV cache, sampling, CLI, JSONL automation, and HTTPS/SSE service | Functional but narrower and less tuned than established runtimes |
| Microkernel | PE32+ x86_64 kernel, UEFI handoff, page tables, GDT/IDT/TSS, CPL3 tasks, APIC timer, preemption, capabilities, IPC, fault retirement, SMP, and service lifecycle | Booting research kernel with signed QEMU, KVM, and WHP probes; not production ready |
| Virtualization | Common VM policy plus native KVM and Hyper-V/WHP launchers, signed launch manifests, isolated guest memory, interrupt handling, and authenticated queues | Development and benchmark harnesses; a compromised host remains authoritative |
| Mediated GPU | Authenticated rings, signed kernels, capabilities, quotas, watchdogs, reset, CPU fallback, fail-stop EPT/VT-d, checked DMAR/MCFG, complete-route proofs, one-shot MMIO ownership, generation-checked domain authority, root-race-checked direct tables, and fail-closed all-unit assembly | Register and benchmark plumbing exist; physical execution and hardware IOMMU validation, plus near-native in-VM CUDA, remain unfinished |
| Rust compiler | Original forward-looking Rust lexer, parser, semantic analysis, constant evaluation, code generation, and source-to-object driver for a documented subset | Experimental contemporary/future-Rust subset, not a complete `rustc` replacement |
| Git | Original repository, index, object, pack, ref, diff, checkout, commit, SSH transport, and signing functionality | Useful native client with documented unsupported Git features |
| AV1 | Original parser, transform, prediction, reconstruction, and encoder/decoder work | Active conformance work; do not claim complete AV1 interoperability yet |
| Opus | Original range coding, SILK/CELT primitives, packet handling, and encoder/decoder work | Active implementation and conformance work; not yet a production codec claim |
| Networking and security | Original HTTP, TLS, SSH, JSON, cryptography, signing, artifact admission, and rollback-policy components | Security-sensitive experimental code requiring independent audit |
| Data and training | ZIM, Zstandard, Wikipedia streaming, tokenizer training, compact transformer training, and GGUF export | Research pipeline; trainer is not yet a fully trained competitive LLM system |

Detailed microkernel architecture, trust boundaries, probe evidence, and
remaining milestones live in [docs/MICROKERNEL.md](docs/MICROKERNEL.md). Keeping
that detail outside this README makes the project overview readable while
retaining the evidence needed for engineering work.

The durable OS direction is split by purpose: [architecture](docs/ARCHITECTURE.md),
[security boundaries](docs/SECURITY.md), [dependency-ordered roadmap](docs/ROADMAP.md),
[application platform](docs/APPLICATION_PLATFORM.md),
[accessibility architecture](docs/ACCESSIBILITY.md), [project values](VALUES.md), and
[context-loss recovery](docs/RECOVERY.md). The
[Engineering Constitution](docs/ENGINEERING_CONSTITUTION.md) is normative for
complexity, authority, dependencies, compatibility, and major design changes;
[history and prior art](docs/HISTORY_AND_PRIOR_ART.md) records predecessors and
carefully bounded comparison claims;
[EULOGY.md](EULOGY.md) records historical inspiration without defining
architecture. `docs/MICROKERNEL.md` remains the
detailed implementation and evidence ledger. Architecture goals in those files
are not completion claims.

## Design principles

- Own the critical implementation and keep the trusted dependency surface
  small.
- Put security first, measured performance second, and convenience third.
- Use narrow, auditable modules and explicit bounded storage at trust
  boundaries.
- Treat every parser, artifact, model, device, network peer, tool, and host
  input as untrusted.
- Enforce W^X, least privilege, capability-mediated access, generational
  identities, authenticated artifacts, and fail-closed state transitions.
- Measure claims on both Windows and Linux and distinguish controlled probes
  from production guarantees.
- State unsupported behavior and incomplete conformance explicitly.

All repository libraries and applications use `#![no_std]` and repository-owned
allocation and platform layers rather than importing Rust's `std` or global
`alloc` crates. Cargo's external test harness still supplies a host runtime for
`#[test]`; this does not mean model execution avoids all dynamic memory.

## Mandatory contribution rules

These rules apply equally to human and LLM/agent contributors. A change that
violates any rule must not be merged.

- Submit only original work that the contributor has the right to dedicate
  under CC0. Do not copy, translate, transcribe, or adapt third-party code or
  generated material with incompatible or uncertain provenance.
- All implementation code, build logic, tests, examples, benchmarks, and
  utilities must be Rust. Documentation, manifests, lockfiles, licenses, and
  required data formats may use their appropriate formats.
- Code may depend only on `core` and original crates in this workspace. Do not
  use `std`, `alloc`, crates.io packages, Git dependencies, or other sysroot
  crates.
- Keep code modular, cohesive, and easy to audit wherever that does not
  conflict with security or measured performance. Document non-obvious trust
  boundaries and invariants.
- Build and test every change on Windows and Linux. Windows supports only
  Rust's MinGW-based `x86_64-pc-windows-gnullvm` toolchain; do not require
  MSVC, Visual Studio, the Windows SDK, or a separate LLVM installation.
- Review unsafe code, FFI, integer and buffer arithmetic, parsers, filesystem
  and process operations, network input, concurrency, and failure paths. Add
  adversarial and regression tests appropriate to the change.
- When a workspace formatter changes otherwise unrelated tracked Rust files,
  preserve those mechanical changes in a separate formatting-only commit so
  the functional change remains independently reviewable.
- Reject and rework security or measured performance regressions. Never waive
  a regression merely to make a feature pass.
- Record Windows and Linux test commands, security checks, and relevant
  benchmarks. Never claim a property or platform was verified when it was not.
- Compiler and codec work must clearly identify its supported subset and pass
  independent differential, conformance, malformed-input, and interoperability
  testing before broader compatibility is claimed.
- Apply the worldwide patent-awareness rules in
  [docs/patents](docs/patents/README.md) to substantial patent-sensitive
  mechanisms. Prefer verified expired, public-domain, clearly non-overlapping,
  or appropriately royalty-free designs. CC0 addresses copyright and does not
  establish freedom to operate under third-party patents.

## Trust model

The threat model assumes a hosted Windows or Linux OS and its VMM process may
be compromised. KVM and WHP are therefore development, compatibility, and
performance environments—not security boundaries against their hosts. A host
can inspect or alter guest RAM, CPU state, clocks, virtual devices, entropy,
keys, and GPU results regardless of in-guest authentication.

Bare-metal MRML currently trusts the CPU and microcode, chipset and memory
controller, RAM, selected hardware attestation root, firmware that establishes
the machine, and authenticated MRML loader/kernel/policy code. Devices, device
firmware, DMA, networks, models, tools, and external data are untrusted.
Compromised UEFI, SMM, platform security processors, hardware, or physical
access remain outside the enforceable boundary until a separately verified
dynamic root of trust and hardware reinitialization path exists.

MRML does not currently claim production verified boot, rollback resistance,
confidential computing, physical GPU isolation, side-channel resistance, or
formal noninterference. Those require hardware validation, TPM-backed monotonic
state, IOMMU/reset testing, reproducible release infrastructure, formal work,
and independent security review.

Protected execution is reported as an explicit backend and bounded claim set,
never inferred from a VMM name. Ordinary WHP/KVM is unprotected; the planned
Windows VBS authority protects only against VTL0 and still trusts Hyper-V and
the secure kernel; the bare-metal path uses an MRML VMX-root monitor. The
consumer-PC design does not depend on server confidential-computing extensions.
Admission policy requires the exact backend as well as claims, measurement,
security version, nonce, sequence, and debug state. A valid receipt from another
mode cannot satisfy a weaker overlapping claim set or consume replay state.
VBS request admission also compares the request's policy measurement with a
verifier-owned SHA3-512 commitment to the exact backend, claims, debug rule,
security version, and image measurement. Merely MAC-binding a broker-selected
policy identifier is not approval, and the enforced policy must reproduce that
same commitment before replay state advances.
Raw and receipt-authenticated admissions are distinct public types. The latter
carries the exact request digest and independently approved policy identity;
only it can evaluate secret release, and then only for non-debug execution with
measured sealed-key claims.
It also exposes `AuthenticatedProtectionMode`, whose `VbsVtl1`,
`BareMetalVmxRoot`, or `Unprotected` value can be obtained only after receipt
authentication and exact policy admission. Raw self-asserted reports expose no
equivalent verified-mode conversion.
The VBS authority also refuses receipt issuance unless Windows 11 24H2 reports
safe TPM-provisioned attested keys with boot, kernel, and hypervisor debugging
never enabled. The production enclave image contains no fixed receipt key: its
authority instance generates a random key in VTL1, seals it to exact enclave
code with debug unsealing forbidden, and an independent verifier instance
unseals it. VTL0 transports only the bounded opaque blob. This local key custody
does not constitute remote attestation.
The authority can emit a bounded Windows-signed local VBS report binding a fresh
verifier nonce to a domain-separated digest of the exact canonical launch
request and policy. Only another VBS enclave on the same machine can use
Microsoft's verification API, so the ordinary host transports
this report without treating it as verified evidence.
An allocation-free parser validates the complete signed-statement layout and can
compare exact code/signer identities, debug state, and security-version floors,
but its type remains explicitly unverified until a separate verifier enclave
authenticates the same report bytes through Windows.
Every enclave entry obtains its own runtime address interval and rejects context,
input, or output ranges that overlap or wrap into VTL1 before invoking explicit
boundary-copy APIs.
The Windows probe loads separate authority and verifier VBS instances. The
verifier creates a one-use enclave-random challenge, retains the complete
expected request binding inside VTL1, validates Windows' report signature, and
requires the authority identity and security versions to match its own signed
image. Receipt and attestation gates are retained independently inside VTL1 and
must match the exact request before a one-use sealed workload secret can be
unsealed and consumed there. Only an HMAC result leaves the enclave; every
VTL0-visible success value remains diagnostic and cannot itself authorize
secret release.
The live probe routes each canonical request and its opaque authority receipt
through the same generational `UntrustedLaunchBroker` used by the WHP control
plane. Its atomic paired take prevents honest host code from accidentally
combining different exchanges, and consumed or cancelled slots are wiped before
reuse. The broker never holds a receipt key, authenticates a claim, or releases
a secret. A compromised VTL0 host can still inspect, alter, suppress, or replay
broker memory; exact request, policy, sequence, receipt, and attestation checks
inside VTL1 are what reject those attempts. Broker wiping is residual-state
hygiene, not a confidentiality guarantee against the host.
Reports are policy inputs, not attestation, until authenticated by the
corresponding hardware-backed launch authority. See `docs/MICROKERNEL.md` for
the layered design.
The bare-metal monitor derives a nonzero receipt key internally exactly once
before any domain or granule exists, mixing an opaque full-signed-chain boot
capability with fresh post-entry CPU `RDSEED` entropy. Callers cannot inject or
retrieve that key. It issues the same canonical authenticated receipt format
directly from live ownership state. This launch-local key is not TPM sealing,
persistent identity, or remote attestation. After a measured domain owns at
least one private granule and no shared granules, the monitor can also derive a
domain-generation- and measurement-bound workload key from independent
`RDSEED` entropy. Only an exact authenticated non-debug receipt carrying the
implemented sealed-key claim can consume its sequence once and obtain a
challenge-bound HMAC result; neither key leaves VMX root. This is launch-local
key custody, not persistent hardware sealing or evidence of physical execution.

## Kernel state

The current x86_64 kernel has demonstrated:

- signed PE32+ loading through the repository-owned UEFI loader;
- bounded and normalized firmware handoff validation;
- private page tables with W^X and supervisor/user separation;
- GDT, 256-entry IDT, TSS, guarded privilege stacks, and double-fault IST;
- CPL3 entry, exact hardware trap-frame validation, and `IRETQ` restoration;
- local-APIC timer preemption across independent CR3 roots;
- capability spaces, bounded IPC, generational tasks, and lifecycle control;
- user-fault retirement with domain and capability revocation;
- resumption of a surviving CPL3 task after another task faults;
- multiprocessor startup, per-CPU state, IPIs, migration, and load balancing;
- controlled signed nested-KVM execution of VMX-root entry, a minimal non-root
  guest, an exact EPT-denied monitor-private-page read exit, and VMXOFF teardown;
- signed execution probes under QEMU/UEFI, nested Linux KVM, and Windows WHP.

The kernel remains experimental. Storage, network, tool, inference, and GPU
service VMs; physical-hardware coverage; production rollback storage; complete
IOMMU containment; architecture ports; formal verification; and external audit
remain unfinished.

## Workspace layout

- `mrml-kernel`, `mrml-kernel-image`, `mrml-uefi`, `mrml-service-image`:
  microkernel, boot, and isolated-service execution.
- `mrml-config`: fixed-capacity typed configuration state and versioned
  configuration/supervision service protocols.
- `mrml-storage`: capability-native stable storage identities, attenuated
  authority lineage, canonical versioned metadata records, and bounded extent
  mapping with fail-closed copy-on-write publication planning and
  capability-authorized bounded directory and verified COW file I/O, including
  explicit fixed-capacity multi-file publication transactions and redundant-root
  recovery selection, backed by canonical cross-object allocation ownership.
- `mrml-kvm`, `mrml-kvm-run`, `mrml-whp`, `mrml-whp-run`: Linux and Windows
  virtualization backends and signed probes.
- `mrml-runtime`, `mrml-tensor`, `mrml-model`, `mrml-tokenizer`: inference and
  portable execution.
- `mrml-cli`, `mrml-machine`, `mrml-server`, `mrml-agent`, `mrml-tools`:
  interactive, automated, server, and agent interfaces.
- `mrml-rustc`, `mrml-rustc-driver`: original Rust language subset and object
  compiler. Its future-Rust compatibility, analysis, profile, and oracle policy
  is in [COMPILER.md](docs/COMPILER.md).
- `mrml-git`, `mrml-ssh`: repository management, transport, and signing.
- `mrml-av1`, `mrml-opus`: native video and audio codec work.
- `mrml-http`, `mrml-tls`, `mrml-crypto`, `mrml-sign`: native protocol,
  cryptographic, and signed-artifact layers.
- `mrml-zim`, `mrml-zstd`, `mrml-wikipedia`, `mrml-trainer`: dataset ingestion
  and research training.
- `mrml-windows`, `mrml-linux`: minimal native platform interfaces.

## Build and run

The planned first-party `mrml` build/package frontend and mandatory pinned-
upstream-rustc bootstrap policy are specified in
[docs/build/BUILD_SYSTEM.md](docs/build/BUILD_SYSTEM.md). Bootstrap once with the
repository-pinned Windows/Linux Rust toolchain:

```text
cargo build -p mrml
```

Then use `mrml doctor`, `mrml audit`, `mrml build`, `mrml test`, and target/
component selectors for migrated repository work. `doctor` verifies the native
dependency graph without Cargo metadata; `audit` inventories native declarations
and unusual build inputs. Cargo remains an internal locked compilation bridge
during this incremental migration; package/release/image commands are not
implemented yet.

`mrml-math`, `mrml-windows`, and `mrml-linux` are the first native compiler
nodes: their build and test actions invoke the pinned upstream rustc directly
and are reported as `builder=native-rustc`. Other components remain visibly
`builder=cargo-transition` until their exact
extern, feature, target, and build-action declarations migrate.

`mrml-runtime` is the first dependent native node. Its Windows and Linux externs
are target-scoped; `mrml` builds the active platform leaf first and supplies its
exact rlib path directly to rustc.

The featureless percent-encoding, tokenizer, Zstandard, ZIM, JSON, Wikipedia,
error, and terminal-style libraries have also migrated to dependency-first
native rustc actions. Together with the platform/runtime nodes, they form the
twelve-node native library layer.

The `mrml-rustc` core is also native, including both integration-test targets
and an explicit bounded test stack. Thirteen components are now native and 29
remain transitional.

`mrml-opus` adds exact native example compilation: all 179 library tests and its
three declared example binaries pass on Windows and Arch Linux WSL2. Fourteen
components are native and 28 remain transitional.

`mrml-av1` adds exact empty-default feature selection and feature-gated platform
externs. Its library and `decode_ivf` example build natively on Windows and Arch
Linux WSL2. A declared 32 MiB executable stack removes sixteen harness-only
overflows; both native hosts reproduce the Cargo baseline's two remaining AV1
source-test failures at 273 passed and 2 failed. Fifteen components are native
and 27 remain transitional; this is build parity, not AV1 conformance evidence.

`mrml-crypto` records the resolved default feature set as `runtime`, activates
only that optional native extern, and passes all 27 direct tests on Windows and
Arch Linux WSL2. Sixteen components are native and 26 remain transitional.

`mrml-tls` now builds after those exact crypto/runtime artifacts and passes all
11 direct tests on both hosts. No live peer, external certificate fixture, or
independent protocol validation was implied. Seventeen components are native
and 25 remain transitional.

`mrml-http` directly consumes the native runtime/TLS artifacts and passes all
three tests on both hosts. Live URL/range paths were not configured, so this is
not network-interoperability evidence. Eighteen components are native and 24
remain transitional.

`mrml-ssh` directly consumes native crypto/runtime artifacts and passes all 23
tests on both hosts, including loopback transport. No live remote or external
signing operation was exercised. Nineteen components are native and 23 remain
transitional.

Native actions now cover exact library-plus-binary outputs and explicit
compile-time environment values. `mrml-git` builds both outputs and passes 51
library tests plus its binary test on Windows and Arch Linux WSL2. No live
remote operation was exercised. Twenty components are native and 22 remain
transitional.

`mrml-tools` now records its resolved `runtime` feature, stable manifest path,
six universal externs, and one host-selected platform extern. Linux passes all
32 direct tests; Windows reproduces the Cargo baseline at 31 passed and one
installed-Edge DevTools failure. Twenty-one components are native and 21 remain
transitional; no physical browser or accessibility hardware coverage is claimed.

Bin-only actions now omit a fabricated primary library while retaining exact
binary output and test declarations. `mrml-rustc-driver` builds the real
`mrml-rustc` executable and passes both driver tests on Windows and Arch Linux
WSL2. Twenty-two components are native and 20 remain transitional.

Feature sets are target-specific: every featureful native action covers each
declared target exactly once. `mrml-crypto` selects `runtime` for Windows/Linux
host tests but selects no features or runtime extern for its `MRML_NATIVE`
`x86_64-unknown-none` rlib. Both hosts cross-build that profile successfully.

Named provider profiles keep a dependency's nondefault feature resolution
distinct from its ordinary target default, including in cache keys and artifact
names. `mrml-kernel` binds `mrml-crypto`'s empty `core` profile for both its
`x86_64-unknown-none` build and separately declared 64 MiB host harness, rather
than silently acquiring the host-default `runtime` feature. Windows and Arch
Linux WSL2 cross-build the kernel and pass all 474 host tests. Twenty-three
components are native and 19 remain transitional; no target execution or
physical-hardware verification is implied.

Explicit host-build projections allow a target-only dependency to be rebuilt
for an approved host without widening the component's public target families.
`mrml-storage` now directly binds crypto's empty `core` profile and the kernel,
cross-builds for `x86_64-unknown-none`, and passes all 121 tests in its declared
64 MiB host harness on Windows and Arch Linux WSL2. Twenty-four components are
native and 18 remain transitional; this is cross-build and hosted-test evidence,
not native-storage or physical-device execution.

`mrml-config` now directly consumes the native crypto-core, kernel, and storage
artifacts. Windows and Arch Linux WSL2 cross-build it for
`x86_64-unknown-none` and pass all 31 tests in its approved host projection.
Twenty-five components are native and 17 remain transitional; no signed service
runtime, target execution, or physical-hardware verification is implied.

Native actions may declare an allowlisted compiler-target variant distinct from
their semantic target family. The variant propagates through the complete rlib
graph and has a separate artifact directory, preventing ABI/cache collisions.
`mrml-service-image` uses this to remain `MRML_NATIVE` while producing its
`x86_64-unknown-uefi` PE32+ EFI application. Debug and release builds pass on
Windows and Arch Linux WSL2 and repeat deterministically per host; cross-host
hashes differ and are not claimed reproducible. Twenty-six components are native
and 16 remain transitional. No UEFI runtime or signed-service execution occurred.

`mrml-kernel-bench` now compiles directly against native kernel and runtime
artifacts on both hosts. Its harness discovers 14 Windows and 13 Linux tests;
all remain deliberately ignored manual performance gates, so this verifies
compilation and ignore policy but records no benchmark result. Twenty-seven
components are native and 15 remain transitional.

Non-host dependency projections and absent compile-environment inputs are now
explicit and fail closed. `mrml-kernel-image` selects only `kernel-image`,
rebuilds kernel and crypto-core for `x86_64-unknown-uefi`, and emits a PE32+ EFI
application on Windows and Arch Linux WSL2. Poisoning all four inherited
`MRML_*` option variables leaves each host's artifact hash unchanged. Twenty-
eight components are native and 14 remain transitional; no firmware or hardware
execution is implied.

Binary outputs can now be gated by exact target family and selected feature.
`mrml-uefi` builds its library on hosts but emits `mrml-loader.efi` only for
UEFI with `uefi-image`; exact UEFI selectors are no longer overwritten by the
default kernel-image choice. Both hosts emit a PE32+ EFI loader and pass all 24
host-projected library/TPM simulation tests. A Windows poisoned-environment
probe confirms all 21 absent inputs leave the loader hash unchanged. Twenty-nine
components are native and 13 remain transitional; no TPM, firmware, or physical
hardware ran.

Feature-profile identity now reaches rustc metadata as well as filenames and
cache keys, allowing one graph to contain crypto-core through kernel and
host-default crypto directly without crate ambiguity. `mrml-sign` uses that
mixed graph, builds on both hosts, and passes all eight temporary-file tests.
Thirty components are native and 12 remain transitional. No live signing key,
Secure Boot enrollment, firmware, or hardware was used.

Extern edges can now be test-only: KVM's direct crypto-core dev dependency is
absent from its production extern set while remaining available to its harness
(crypto-core is still transitively required by kernel). `mrml-kvm` builds on
Arch Linux WSL2 and passes 18 tests with one manual mapping-performance test
ignored. `/dev/kvm` was usable, so conditional API and signed-guest probes ran.
Thirty-one components are native and 11 remain transitional; this is nested WSL2
KVM evidence, not bare-metal or physical-hardware verification.

MRML uses Rust 2024 and the exact `nightly-2026-08-24` build toolchain pinned in
`rust-toolchain.toml`. It is also the current `mrml-rustc` behavioral reference
recorded as [ORACLE-0002](docs/compiler/oracles/ORACLE-0002.md); a floating
installed nightly is never oracle evidence.

Windows requires the self-contained GNU/LLVM toolchain:

```powershell
winget install Rustlang.Rustup
rustup toolchain install nightly-2026-08-24-x86_64-pc-windows-gnullvm --profile minimal `
  --component rust-src --component rustfmt --component clippy `
  --component rust-mingw --target nvptx64-nvidia-cuda `
  --target x86_64-unknown-uefi --target x86_64-unknown-none
rustup default nightly-2026-08-24-x86_64-pc-windows-gnullvm
rustc -vV
```

Linux uses its native GNU host with the same Rust components and targets. CUDA
builds use Rust PTX plus the NVIDIA driver API and do not require the CUDA
Toolkit or `libcudart`.

```powershell
# CPU inference
cargo run --release -p mrml-cli --no-default-features -- `
  --model C:\path\to\model.gguf --prompt "Hello"

# CUDA inference
cargo run --release -p mrml-cli --features cuda -- `
  --model C:\path\to\model.gguf --ctx-size 8192 --prompt "Hello"

# Native Git client
cargo run --release -p mrml-git -- status

# Compile a supported Rust source subset to an object
cargo run --release -p mrml-rustc-driver --bin mrml-rustc -- `
  --emit coff --function answer input.rs -o answer.obj
```

Run a binary with `--help` for its supported interface. Do not infer complete
compatibility from familiar command names.

## Verification

The minimum repository gates are:

```powershell
cargo test --workspace --release --no-default-features
cargo clippy --workspace --all-targets --release --no-default-features -- `
  -D warnings
```

Run feature- and hardware-specific suites for CUDA, KVM, WHP, UEFI, codecs,
network protocols, and the compiler whenever those areas change. Performance
results must identify the exact artifact, backend, hardware, configuration,
warm-up policy, measurement boundary, and variation across runs. Codec and
compiler compatibility require independent conformance/differential evidence,
not only self-round-trip tests.

## Context for ChatGPT and Codex sessions

This section exists specifically to prevent a new AI session from overstating
the repository or undoing its invariants.

1. Read `AGENTS.md`, this README, the architecture, security, application
   platform, roadmap, recovery, and
   [microkernel evidence](docs/MICROKERNEL.md) documents before changing kernel,
   VMM, signing, GPU, application, browser, GUI, or trust-boundary code.
2. Treat the mandatory contribution rules above as hard acceptance gates.
3. Inspect the current worktree before editing. Preserve unrelated staged,
   unstaged, and untracked user work; stage only the intended change.
4. Do not describe a controlled probe as production functionality. Report the
   exact backend and observed evidence.
5. Never describe the Rust compiler as complete `rustc`, AV1/Opus as fully
   conforming, hosted virtualization as secure against its host, or the kernel
   as production ready until independent evidence supports those claims.
6. Update this overview when project scope changes. Put detailed experimental
   traces, threat analysis, and milestone evidence in the relevant document
   under `docs/`, not in an ever-growing README status narrative.
7. Commit and push only after proportional Windows and Linux testing and an
   explicit review of security and performance impact.
8. For compiler work, read [COMPILER.md](docs/COMPILER.md), preserve the prior
   oracle records, and use the [current oracle](docs/compiler/oracles/ORACLE-0002.md).
   Rust 2024 is the
   floor; prioritize modern/future semantics and do not infer old-edition,
   stable-Rust, every-nightly, or unstable-Rust-ABI compatibility.

## License

MRML is dedicated to the public domain under [CC0 1.0 Universal](LICENSE)
(`CC0-1.0`). Anyone may use, study, modify, share, and redistribute it for any
purpose, including commercially. Where public-domain dedication is not legally
possible, CC0 provides its broad license and waiver fallback.
