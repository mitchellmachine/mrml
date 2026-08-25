# MRML bootstrap build and packaging toolchain

**Status: PARTIALLY IMPLEMENTED.** `packages/tools/mrml` now parses the versioned root
`MRML.workspace`, emits typed list/doctor/audit/build/test results, resolves and
validates the complete declared dependency graph natively, inventories unusual
build inputs, directly invokes pinned upstream rustc for all 42 actions, selects current-
host WHP/KVM VMM adapters, builds an
x86-64 UEFI artifact, recognizes the CUDA target with explicit architecture and
toolchain checks, and rejects unimplemented package/release/image/publish
commands. All tracked components have semantic homes outside generic `crates/`.
Package/release/image builders, sandboxing, and publication remain planned. See
[MIGRATION_INVENTORY.md](MIGRATION_INVENTORY.md).

> Until `mrml-rustc` satisfies the defined production-readiness gate, the MRML
> build tool MUST use upstream Rust tooling for production MRML artifacts.

> Cargo is used only to bootstrap the first-party `mrml` build tool. Once
> `mrml` exists, every normal repository component is built through `mrml`.

## Tool and stage boundaries

The planned first-party `mrml` frontend provides coherent build, test, package,
sign, release, image, install, EFI-export, media, publish, and verify operations.
Syntax is provisional. Cargo-like ergonomics means one manifest, simple commands,
explicit targets/profiles, lockfiles, reproducible inputs, workspaces, and
consistent metadata—not crates.io assumptions, unrestricted scripts, arbitrary
host execution, ambient filesystem/network access, or compatibility quirks.

Terminology is exact. A **Compiler** translates source; **Build Tool** orchestrates
inputs and tools; **Linker/Object Writer** emits formats; **Artifact** is a build
output; **Package** binds artifacts/resources/metadata; **Signature** authenticates
an exact digest; **SystemRelease** is a coherent exact package graph; and
**SystemImage** is its deployable container. Do not call every stage “build.”

Build, package, sign, release, and image remain separate. Packaging existing
artifacts is supported. Unsigned development packages stay visibly unsigned.
Ordinary build workers never require production signing keys: digest/manifests
cross an offline or isolated signing boundary. Manifests never contain raw private
key paths. Publisher, Store-metadata, release, and OS-root key roles remain
separate.

```text
source -> mrml build -> pinned upstream rustc -> linked artifact
  -> ABI/security/build metadata -> mrml package -> exact package digest
  -> isolated mrml sign -> PackageStore / mrml release
  -> mrml image -> SystemImage / installation media
```

Cargo is stage zero and is not a second public build frontend. Clean checkout
uses pinned Cargo/rustc only for `cargo build --locked -p mrml`, after which all
normal component build/test commands use `mrml`. The internal Cargo bridge has
been removed and missing native actions fail workspace loading. Removing rustc
or LLVM remains an evidence-driven migration, never an OS-progress prerequisite. Compiler,
object, package, release, and image responsibilities may later be libraries or
tools; avoid premature process/tool proliferation.

Native artifacts are isolated under `target/mrml-native/`. This deliberately
does not use `target/mrml/`, because Cargo's Unix stage-zero executable occupies
the path `target/mrml`; sharing that name makes a clean Linux bootstrap unable
to create its native artifact directory.

## Compiler modes and readiness

Compiler selection is explicit: `UpstreamRustc`, `MrmlRustcExperimental`, or
`MrmlRustcProduction`. Initially production defaults to a pinned upstream
rustc/Cargo. Experimental `mrml-rustc` remains concurrent for differential,
oracle, conformance, probe, and explicit development builds. Production mode is
unavailable until the exact artifact-profile gate passes.

There is no silent fallback. A requested `mrml-rustc` build fails explicitly on
unsupported semantics instead of rebuilding with rustc. Every artifact/package
records compiler identity/version/mode, target, profile, flags, relevant backend/
linker, and build-tool version. Compiler identity is provenance, not authority;
signature, admission, capability, release, and generation checks still apply.
Policy may temporarily admit honestly labeled mixed-compiler generations.

An `mrml-rustc` profile becomes production-eligible only after sufficient Rust
coverage and explicit unsupported diagnostics; correct ownership/move/borrow,
trait/generic, typed CFG/body, target ABI, object/executable, and metadata behavior;
cross-platform differential testing against exact dated upstream oracles;
warnings-denied suites, substantial fuzzing, and no known silent miscompile in
scope; representative real-component/runtime evidence; repeatable builds; and
performance measurement. Full crates.io compatibility is not required.

Application, system-service, driver, kernel, VMM, UEFI, GPU-kernel, library, and
tool profiles promote independently. Promotion records the gate, runs corpus and
real workloads, compares ABI/behavior/performance, enables selected components,
retains upstream-built rollback, and monitors miscompilation. Prefer isolated
libraries/services/apps before drivers, VMM, bootloader, and kernel as evidence
allows. Self-hosting is evidence, not correctness proof. A compare-compilers mode
may compare acceptance, behavior, ABI/object/package metadata, boot result, and
intentional divergence without changing production output.

Production upstream tools are exactly pinned: rustc/Cargo version, target,
LLVM/backend, linker/object tools, and flags. Prefer stable when sufficient;
otherwise pin one exact dated nightly. Never auto-upgrade release toolchains.
Upstream rustc does not make its native/unsafe toolchain memory-safe.

## Manifest, lockfile, profiles, and isolation

`MRML.workspace` v3 is the authoritative repository component inventory and
target/profile graph. During migration its `cargo-package` field bridges exact upstream
dependency compilation; Cargo package identity is not MRML identity. Every
existing component is classified `MRML_NATIVE`, `HOST_WINDOWS_LINUX`, `COMPILER`,
`UEFI`, `GPU`, `TEST`, `SHARED`, or `BOOTSTRAP_ONLY`. The generic `crates/`
layout has been eliminated for tracked components after `mrml` graph/path parity
was verified. The first eighteen library components, `mrml-math`,
`mrml-percent-encoding`, `mrml-tokenizer`, `mrml-zstd`, `mrml-zim`, `mrml-json`,
`mrml-wikipedia`, `mrml-opus`, `mrml-windows`, `mrml-linux`, and
`mrml-runtime`, `mrml-crypto`, `mrml-tls`, `mrml-http`, `mrml-ssh`,
`mrml-error`, `mrml-terminal-style`, and `mrml-av1`, now live under
`packages/libraries/`; further semantic component homes belong under
`packages/`, with the
bootstrap tool under `packages/tools/mrml` and compiler tooling under a clear compiler
location. Do not create empty speculative directories.

The dependency-free `mrml-rustc` core lives at `packages/compiler/core`, and its
separate driver lives at `packages/compiler/driver`.
`mrml-git` now lives at `packages/tools/git`; its host-tool classification and Cargo
bridge remain unchanged.
`mrml-tools` now lives at `packages/tools/host`; its input-policy counts, feature
behavior, and Cargo bridge remain unchanged.

The first explicit `rust-action` nodes are the dependency-free `mrml-math`,
`mrml-windows`, and `mrml-linux` libraries; each binds its crate name, `lib`
type, and repository-relative source root. Native build emits a deterministic
rlib and native test compiles and executes the inline test harness directly
through the pinned rustc. Windows execution covers math and the Windows platform
leaf; Arch Linux WSL2 execution covers math and the Linux platform leaf. This is
hosted WSL2 evidence, not bare-metal Linux or KVM evidence. Action paths and crate
names are validated before invocation;
the frontend resolves the exact dated Windows GNU/LLVM or Linux GNU toolchain
through rustup rather than inheriting the caller's active default. There is no
Cargo fallback: all nodes now have exact actions, and workspace loading fails if
any action is missing.

`mrml-runtime` is the first dependent native node. Its action declares the
package identity, Rust crate name, and target family for each platform extern:
only `mrml_windows` is built/wired on Windows and only `mrml_linux` on Linux.
The native planner recursively compiles declared extern providers first, rejects
missing native actions and target mismatches, and passes exact deterministic rlib
paths through `--extern`. Windows passed 38 runtime tests and Arch Linux WSL2
passed 37; the one-test difference is the Windows-only argument parser.

The next featureless layer is also native: `mrml-percent-encoding`,
`mrml-tokenizer`, `mrml-zstd`, `mrml-zim`, `mrml-json`, `mrml-wikipedia`,
`mrml-error`, and `mrml-terminal-style`. Rustc receives the single bounded
target/profile artifact directory as its transitive dependency search path and
each direct extern remains bound to an exact rlib. Both Windows GNU/LLVM and
Arch Linux WSL2 passed all 31 inline tests across this layer.

Native actions can now declare integration-test targets, whether each target
requires the component's own rlib, and a bounded test-process stack. The loader
fails when declared `:test` outputs and native test actions differ. This migrated
the dependency-free `mrml-rustc` core without omitting either integration suite:
Windows and Arch Linux WSL2 each pass 420 inline tests, 10 conformance tests, and
335 nightly-replacement tests. Linux applies the declared stack with `setrlimit`
before exec so panic-abort child tests inherit it; Windows records the same stack
in linker metadata.

Native actions also declare example source/output pairs. Test mode compiles each
example as its real binary crate and fails if example declarations drift from
the component's `:example` outputs. `mrml-opus` uses this path for
`inspect_range`, `opus_range_diff`, and `rfc8251_audit`; both hosts pass 179
inline tests and link all three examples. Native-library requirements such as
the differential example's system `libopus` remain explicit host prerequisites,
not silently skipped outputs.

Each native Rust action with declared component features must bind an exact
feature set, including an explicitly empty set. Rustc receives selected feature
cfgs plus the complete allowed feature universe, and optional externs are active
only when both their target family and feature gate match. `mrml-av1` exercises
this with an empty default set: `mrml-runtime` is active, while the `nvidia`
Windows/Linux externs are not. Its library and declared example build on both
hosts; a 32 MiB executable-stack policy leaves the same two source failures as
the pinned Cargo baseline rather than sixteen additional stack failures.

An extern may also declare a bounded consumer-profile-to-provider-profile
mapping. Both names and every overlapping target are validated before planning;
an undeclared consumer profile retains the extern's explicit base provider
profile. The selected provider profile remains part of recursive build identity
and the exact artifact name, preventing feature-forwarded dependencies from
aliasing their default artifacts.

Generated PTX is evaluated at the native component where it is declared, even
when that component is reached recursively through a provider profile. The PTX
declaration includes a validated default GPU architecture; an explicit
`--gpu-arch` overrides it for the complete build graph. This removes hidden
ordering on an earlier top-level CUDA build while keeping `OUT_DIR`, feature,
source, output, target, and architecture inputs exact.

`mrml-crypto` exercises the enabled side of the same rule. Its action records
the resolved effective default set as `runtime`, which activates exactly the
optional runtime extern; both supported hosts pass all 27 inline tests directly.

`mrml-tls` is the next featureless consumer and binds exact crypto/runtime rlibs.
Both hosts pass its 11 inline tests directly; absent environment-selected live
peers and certificate fixtures remain absent evidence, not silently claimed
coverage.

An action may explicitly declare no primary library. Such a component must have
no `:lib` output, cannot satisfy another action's extern edge, and still requires
exact binary output/source/self-binding records. This migrates the bin-only
compiler driver: both hosts build `mrml-rustc` and pass its two inline tests.

Feature selection is per target, exhaustive, and non-overlapping. The loader
rejects an uncovered or multiply covered target. Native library compilation now
supports the pinned `x86_64-unknown-none` target; the crypto action demonstrates
an empty `MRML_NATIVE` feature set with no runtime extern while preserving the
host `runtime` profile.

Cross-target test execution is never implicit. An action may enumerate approved
Windows/Linux host-test families; test mode first builds the requested target,
then creates a fresh host dependency graph and runs only the host harness. The
kernel uses this path with a 64 MiB stack: both hosts cross-build the native rlib
and pass 474 host tests. This is not target execution evidence.

`mrml-http` is the next featureless consumer and binds exact runtime/TLS rlibs.
Both hosts pass its three inline tests directly; absent live URL/range inputs
remain absent network evidence.

`mrml-ssh` directly binds exact crypto/runtime rlibs. Both hosts pass its 23
inline tests, including loopback transport; live remotes and external signing
remain outside this evidence.

Native binary records bind the public output name separately from the Rust crate
name, source, and optional self-library extern. Build mode emits the real binary;
test mode also compiles and runs that binary source as a test harness. Explicit
compile-time environment records replace Cargo-provided ambient values.
`mrml-git` exercises the complete path: both hosts build its library and binary,
then pass 51 library tests and one binary test.

`mrml-tools` combines exact feature, compile-environment, universal-extern, and
target-extern records. Linux passes 32 direct tests; Windows reproduces the
existing installed-Edge DevTools failure after 31 passes. Neither result alone
establishes physical browser, desktop/audio-route, or accessibility-hardware
coverage.

Rust crate identity, MRML package identity, and stable MRML interface identity
are distinct. The runtime component model is specified in
[../packages/COMPONENT_INTERFACES.md](../packages/COMPONENT_INTERFACES.md).
`mrml` must resolve compile-time crate edges separately from `STATIC`,
`DYNAMIC_INTERFACE`, `SERVICE_INTERFACE`, and `BUILD_ONLY` package edges. Cargo's
graph never becomes the permanent runtime resolver.

`mrml doctor` now validates the native graph without invoking Cargo: component
and bridge-package identities are unique, targets and outputs are bounded,
every declared local dependency resolves, and self-dependencies and cycles fail
with structured diagnostics. `mrml audit` emits dependencies, features,
outputs, custom builds, proc macros, native links, compile-time
environment reads, included files, and external-command sites. The bounded
parser validates native dependency/feature/output declarations. The lexical scan
validates per-component input policies and fails closed on count drift. A policy
change still requires human review because equal counts do not establish equal
commands, paths, libraries, or environment semantics. See
[BRIDGE_INVENTORY.md](BRIDGE_INVENTORY.md).

A canonical manifest (filename provisional) binds package identity/version/class,
profile/compiler mode, target slices, capability requests, dependencies/interfaces,
and resources. It grants no authority. An exact lockfile binds dependency identity,
version, digest, source, and relevant compiler/tool inputs; system graphs are
especially strict.

For versioned components, manifests additionally distinguish provided and
required interface identities/major generations, dependency form, and update
policy. Runtime locks record the exact provider package generation and digest
selected for each `InterfaceBinding`. The first canonical schema generator is
implemented as `mrml interface generate-rust SCHEMA OUTPUT`. It bounds input at
64 KiB, exclusively creates output, accepts only the explicit version-1 policy
profile, computes a SHA3-256 fingerprint, and emits deterministic pointer-free
Rust types. The Zstd ABI-3 schema and checked-in generated output are the first
golden fixture. Native call lowering, conformance execution, ABI diffs, and
`mrml-rustc` emission remain **PLANNED**; neither Rust's native ABI nor a package
name is the stable interface.

Profiles define compiler restrictions, ABI, unsafe/FFI policy, format, metadata,
signing, and admission:

- application: safe native Rust, stable MRML service ABI, capability requests;
- system service: broader interfaces but isolated and explicitly capable;
- driver: unsafe, assembly, MMIO, DMA, hardware ABI, and firmware inventory;
- kernel: strict unsafe, assembly, naked, architecture, privileged instruction, and boot-ABI metadata;
- VMM: virtualization operations, guest parsers/devices, unsafe and assembly;
- UEFI bootloader: bounded PE/COFF EFI output and boot metadata;
- GPU kernel, library, and tool: class-specific feature/admission rules.

Build profiles never grant runtime privilege. Long term, arbitrary Cargo
`build.rs` execution yields to declarative metadata, explicit generators, and
capability-constrained reproducible helpers. Bootstrap build-script authority is
documented host risk. Planned sandboxes receive neither the whole filesystem,
credentials, network, SSH keys, nor signing keys by default; this is not current
implementation.

Release dependencies remain small, audited, pinned, and recorded by source,
version, checksum, license, and relevant unsafe/FFI. Cargo dependencies are
acceptable during bootstrap under lockfiles; convenience never justifies large
early-boot/TCB graphs.

## UEFI and package construction

```text
source -> mrml build --profile uefi-bootloader --target x86_64-uefi
  -> pinned upstream rustc/linker -> PE/COFF BOOTX64.EFI
  -> mrml package -> org.mrml.system.bootloader package
  -> EFI/x86_64/BOOTX64.EFI + META manifest/digests/security metadata/signatures
```

Future AArch64 emits `BOOTAA64.EFI`. `.efi` is the firmware-consumable artifact;
the signed package is distribution. UEFI understands neither packages nor Cargo.
EFI export/inspection remains straightforward and separate from signing.

One logical package may combine common resources with requested x86_64, AArch64,
and RISC-V64 slices. Developers build one local architecture; releases build all
supported slices. Identity stays stable. Wrong, missing, stale, or unauthorized
slices fail. `mrml package --artifact BOOTX64.EFI` supports upstream-built input.

Package output is a typed object containing ID, version/class, slices, digest,
capability requests, compiler provenance, path, and signature state. Package,
release, and image verification return structured format/digest/signature/slice/
compiler/dependency/capability/graph results before boot. Store, installer,
recovery, and tools share canonical parsers where possible. The reduced boot-safe
parser is differential-tested against userspace semantics.

Kernel/VMM tests exact-match slice digests, reject wrong architecture/stale
generation, prove exact combination binding, and admit only authorized slices.
UEFI testing builds, packages/extracts, and boots `BOOTX64.EFI` under QEMU with an
expected signed probe before any exact physical-hardware claim.

## Releases, images, install, and publication

`mrml release` consumes exact packages/digests, compatibility policy, and metadata
and emits a candidate signed or unsigned release manifest. `mrml image` combines
it with content-addressed packages, boot/recovery, profile, and optional content
into the canonical Zstd image without needless duplication. Media tooling follows
[DEPLOYMENT.md](../DEPLOYMENT.md).

Local development remains build -> package -> visible owner/developer admission
-> supervised exact component replacement where allowed, never untracked system-
directory copying. Dev/release profiles distinguish iteration from locked,
deterministic, warnings/security-clean output without local substitutions.

`mrml publish` verifies completeness, uploads to configured neutral transport,
checks the remote digest, and publishes signed metadata only after artifact
availability. GitHub Pages/Releases may transport initial catalog/artifacts but
are not trust. Publishing does not hold OS-root keys. Native shell and future GUI
call the same service libraries and receive typed objects rather than scraping CLI
text.

## Reproducibility and supply chain

Release inputs record source revision, lockfile, compiler, target, profile,
environment inputs, linker, and tool version. Package ID/version, build ID, and
content digest remain distinct. Claim reproducibility only after independent clean
rebuilds match canonical digests; Windows/Linux byte identity is a separate
measured claim, while first-milestone semantic metadata must agree.

Collect only supported compiler/build security metadata. Initially source/build
analysis inventories unsafe Rust, FFI, assembly, naked functions, privileged
intrinsics, MMIO/DMA, and firmware. Do not invent guarantees upstream rustc does
not provide. Mature `mrml-rustc` may later reduce the TCB and emit stronger MRML
metadata; those benefits are future claims.

Production packages plan a machine-readable SBOM with component/dependency
versions, digests, source provenance, and licenses, plus authenticated provenance
binding source, builder/tool, compiler, lock, and artifact digest. Patent/license
markers are reports, not automated legal conclusions. Do not claim supply-chain
provenance before implementation.

Build semantics are equivalent on Windows and Linux despite host-specific tools
beneath `mrml`. Cross-compilation is normal. Manifests never encode shell-specific
PowerShell-versus-Bash behavior as package meaning.

## Results, tests, and roadmap

Supported hosts are Windows and Linux. Explicit target families are MRML native,
Windows, Linux, UEFI, and CUDA; future native GPU, AArch64, and RISC-V64 do not
become current support claims. Host and target are distinct. Target definitions
select ABI, object format, linker/runtime assumptions, profiles, and adapters;
Windows excludes KVM and selects WHP, Linux excludes WHP and selects KVM. CUDA
is lazy compatibility/oracle tooling, never the native MRML GPU architecture or
runtime authority.

`mrml build` returns typed `BuildResult` package ID, profile, target, compiler,
artifacts, warnings, and test status. `mrml test` orchestrates unit, integration,
backend, VM, architecture, and profile tests without assuming native host
execution. Human text is a view. Shell concepts such as `Build-Package`,
`Get-BuildResult`, `New-SystemRelease`, and `Export-SystemImage` share APIs.

Bootstrap order is implemented tool and inventory; locked Cargo/rustc bridge;
semantic source moves and path updates; profiles/targets; EFI/VMM/compiler graph;
CUDA scaffold; package command; then
export; package construction/verification; isolated signing; release/image;
publication and typed shell results; sandbox/SBOM/provenance/cross-host evidence;
experimental `mrml-rustc`; per-profile promotion; then reduction of external
tools where justified.

The first Windows/Linux milestone parses one manifest, builds one `no_std` test
artifact and `BOOTX64.EFI` with pinned upstream tools, packages/verifies both with
exact metadata/digests, constructs a simple release, and preserves identical
semantic metadata. It does not require `mrml-rustc`. Later milestones boot the
extracted EFI package under QEMU, compare compilers without promotion, rebuild
twice cleanly, and identify nondeterministic inputs.

This lane must not derail the OS foundation or redirect `mrml-rustc` from typed
place/CFG/ownership/borrowing compiler priorities.

Stage zero is pinned Cargo/rustc -> `mrml`. Normal build is `mrml` -> upstream
rustc initially -> selected MRML/Windows/Linux/UEFI/CUDA graph. Future build is
`mrml` -> profile-approved `mrml-rustc` -> native MRML/GPU targets. Official
releases use `mrml` even while its private bridge invokes Cargo. Do not maintain
meaningfully divergent Cargo and `mrml` release instructions.

Digital-rights review: owner builds/keys remain viable; no official Store or
compiler is mandatory; metadata does not authorize; first-party tools have no
hidden privilege. Hostile-security review: treat manifests, locks, dependencies,
scripts, compilers, artifacts, packages, provenance, parsers, and transports as
hostile; remove ambient credentials/keys/network, differential-test parsers, and
make fallback or authority amplification impossible to hide.

Patent review: `TRIGGERED` — package/release/image construction, content identity,
provenance, parser reuse/differential validation, and publication compositions
require mechanism-specific worldwide review before implementation. See
[`../patents/REVIEW_LOG.md`](../patents/REVIEW_LOG.md).
