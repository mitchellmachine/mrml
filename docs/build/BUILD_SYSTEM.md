# MRML bootstrap build and packaging toolchain

**Status: PARTIALLY IMPLEMENTED.** `tools/mrml` now parses the versioned root
`MRML.workspace`, emits typed list/doctor/audit/build/test results, verifies the
Cargo bridge graph and inventories unusual build inputs, uses a locked Cargo/
upstream-rustc bridge, selects current-host WHP/KVM VMM adapters, builds an
x86-64 UEFI artifact, recognizes the CUDA target with explicit architecture and
toolchain checks, and rejects unimplemented package/release/image/publish
commands. Component moves, native dependency resolution, direct rustc, Linux
execution evidence, package/release/image builders, sandboxing, and publication
remain planned. See [MIGRATION_INVENTORY.md](MIGRATION_INVENTORY.md).

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
source -> mrml build -> pinned upstream rustc/Cargo initially -> linked artifact
  -> ABI/security/build metadata -> mrml package -> exact package digest
  -> isolated mrml sign -> PackageStore / mrml release
  -> mrml image -> SystemImage / installation media
```

Cargo is stage-zero plus a private transitional bridge invoked by `mrml`; it is
not a second public build frontend. Clean checkout uses pinned Cargo/rustc only
for `cargo build -p mrml`, after which normal build/test commands use `mrml` for
kernel, VMM, bootloader, services, drivers, apps, libraries, compiler, tests,
host tools, CUDA, packages, releases, and images as each graph node migrates.
Removing the internal Cargo bridge, rustc, or LLVM is an evidence-driven
migration, never an OS-progress prerequisite. Compiler,
object, package, release, and image responsibilities may later be libraries or
tools; avoid premature process/tool proliferation.

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

`MRML.workspace` v2 is the authoritative repository component inventory and
target/profile graph. During migration its `cargo-package` field bridges exact upstream
dependency compilation; Cargo package identity is not MRML identity. Every
existing component is classified `MRML_NATIVE`, `HOST_WINDOWS_LINUX`, `COMPILER`,
`UEFI`, `GPU`, `TEST`, `SHARED`, or `BOOTSTRAP_ONLY`. The generic `crates/`
layout remains transitional and moves only after `mrml` graph/path parity is
verified; new semantic component homes belong under `packages/`, with the
bootstrap tool under `tools/mrml` and compiler tooling under a clear compiler
location. Do not create empty speculative directories.

`mrml doctor` fails unless locked Cargo metadata has exact one-to-one package
and manifest-path coverage with that inventory and every local Cargo dependency
maps to a declared component. `mrml audit` emits dependencies, features,
targets/outputs, custom builds, proc macros, native links, compile-time
environment reads, included files, and external-command sites. The bounded
parser validates native dependency/feature/output declarations. Lexically found
input sites are migration evidence, not yet per-component input policy; those
policy declarations remain the next gate. See
[BRIDGE_INVENTORY.md](BRIDGE_INVENTORY.md).

A canonical manifest (filename provisional) binds package identity/version/class,
profile/compiler mode, target slices, capability requests, dependencies/interfaces,
and resources. It grants no authority. An exact lockfile binds dependency identity,
version, digest, source, and relevant compiler/tool inputs; system graphs are
especially strict.

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
