# MRML operating-system roadmap

This roadmap is dependency ordered. It describes intended work, not completion
claims. Status is determined from source, tests, and the evidence ledger in
[MICROKERNEL.md](MICROKERNEL.md), using the vocabulary in
[ARCHITECTURE.md](ARCHITECTURE.md).

## Work-in-progress limit

Maintain one foundational OS task plus, optionally, one independently scoped
compiler task. Never run two giant cross-cutting OS milestones simultaneously.
Each OS task advances one current dependency gate to a coherent tested endpoint
before the next OS subsystem begins. Compiler work may run alongside it only
when implementation, tests, review, commits, and performance/security evidence
remain independently attributable.

## Current priority

Three new persistent deltas are documented before implementation:

- [packages/ARTIFACT_EXTENSIONS.md](packages/ARTIFACT_EXTENSIONS.md) defines
  `.mrp`, `.mrs`, `.mrz`, `.mri`, and `.mrsig` as non-authoritative filename
  conventions. Package/release default output, the first `.mri`, and package
  filename-independence tests are now **IMPLEMENTED**. The bounded exact
  three-package boot release is available as `mrml release create|verify`;
  general Store release composition, `.mrz`, and `.mrsig` tooling remain
  **PLANNED**.
- [ISOLATION_PLACEMENT.md](ISOLATION_PLACEMENT.md) defines adaptive placement,
  mandatory floors, semantic interface compatibility across admitted forms,
  persistent owner policy, and a strict one-boot total-microVM request. Typed
  Manifest V2 validation and explicit current application/service native
  policies are **IMPLEMENTED**. The
  resolver handles defaults, owner selection, total-mode promotion, and visible
  unsupported exceptions, and the workspace/lock retains each validated policy;
  the kernel additionally records bounded generational launch admission and
  retains typed unavailable attempts while rejecting Total-mode native
  downgrades or active blockers. A bounded routing prerequisite now dispatches
  a caller-selected service placement to distinct native-service or microVM
  backend entries while preserving exact interface and provider generations.
  The configuration package now admits both forms and supplies a concrete
  configuration-specific adapter with focused fail-closed tests. The native
  form now uses a real accounted `TaskRuntime`/`ServiceSupervisor` launch and
  exact retryable address-space cleanup. The VMM form now has a backend-neutral
  owner that retains one prepared guest behind an exact generational endpoint
  until confirmed teardown, including retry after teardown uncertainty. Both
  KVM and WHP hosted probes now place their transaction-committed guest in
  that owner, gate execution access on the exact endpoint, and explicitly retire
  it on the successful terminal path. Their builds and focused tests pass. Fresh
  one-time-signed identical artifacts completed the full hosted service probe on
  both backends with one eligible domain, one microVM domain, and zero native
  fallback. Component guest construction, exact binding, and atomic pair
  attachment failures now consume the prepared route as typed `VMM_RESOURCE`
  unavailability on both runners instead of attempting native execution; a
  focused kernel test proves zero fallback. This is hosted controlled-probe evidence, not required-system Total
  readiness. The canonical Zstd provider/ZIM consumer now use the isolated-
  service form, and a bounded hosted adapter carries the exact ABI-3 request
  through `TaskRuntime` plus one attenuated shared-buffer capability under
  distinct VM/task bindings on Windows and Arch Linux. This is not a launched
  service or VMM invocation. A complete representative dual-placement service,
  Settings/shell projection of owner policy, VM construction, resource
  projection, resolver-to-launch binding, concrete service syscalls, and WHP/KVM
  runtime transport remain **PLANNED**. A bounded userspace receive/reply loop
  and hosted `TaskRuntime` adapter now prove the full authenticated round trip,
  including sender binding, separate reply authority, and revocation-before-
  reply ordering.
  The configuration service now provides a bounded typed persistence
  prerequisite for component placement preference and system isolation-mode
  selection, using exact setting/root capabilities and its authenticated
  checkpoint recovery path. A revision-bound application plan reauthorizes the
  system and component reads after loading, rejects intervening configuration
  commits, and produces the typed kernel mode, component request, and admission
  policy generation. The representative service path now also checks an exact
  runtime projection of authenticated package preference, floor, ceiling, and
  supported forms before producing a generational `IsolationServiceSpec`;
  unsupported Total or below-floor requests fail without fallback. It does not
  yet provide the general package resolver or grant placement. One composed
  configuration-service route now repeats live policy authorization, checks the
  kernel admission mode/generation and exact interface/provider identity, and
  invokes only the admitted backend. Stale policy or admission mismatch reaches
  neither launcher. Broad cross-placement interface transport remains planned.
  The WHP and KVM hosted service probes now create and capability-authorize the
  same typed component/system policy records, apply exact service package bounds
  and verified provider generation, and reserve that prepared route before
  constructing the guest. Fresh same-artifact runs on both backends again report
  one eligible microVM domain and zero native fallback. Their in-memory policy
  setup is controlled-probe evidence, not stable recovery or boot policy.
  The existing hosted KVM/WHP configuration-service probes are wired to this
  admission record, but do not yet constitute native-versus-microVM resolution.
  A one-use typed service transaction now preserves exact binding identity from
  pre-construction admission through endpoint commit and teardown-safe rollback.
  Both hosted configuration probes use it around real guest construction and
  pass build/unit gates and the fresh signed lifecycle probe completed on both
  hosted backends. The build tool now also
  composes one exact `SystemGeneration`, isolated-service `InterfaceBinding`,
  and already resolved placement into a generation-bound handoff while rejecting
  stale IDs, package substitution, in-process targets, and Total-mode exceptions.
  This remains host policy evidence and does not yet launch or transport the
  representative service.
- [storage/STORAGE_AND_OPTICAL.md](storage/STORAGE_AND_OPTICAL.md) defines the
  disk/image, GPT/FAT, UDF/ISO, MMC, AHCI/USB optical, burning, and virtual-
  optical dependency order. New optical mechanisms are **PLANNED**.

With the small package-extension/tooling gate complete, keep adaptive isolation
and storage/optical as separate sequential foundational OS tasks under
the work-in-progress limit; do not combine them into one functional commit.

Adaptive-isolation milestones remain separate: policy/object schema; one
dual-placement service; one dual-placement GUI app; monitor visibility;
resource/device projection; Settings/shell policy; strict Total runtime;
bootloader selector; EFI Shell selector; required-system Total readiness;
broad application compatibility; and physical/performance evidence. A menu
entry, policy type, UI, or one guest cannot promote Total mode. Successful
tested Total requires every running `MICROVM_ELIGIBLE` domain in a microVM, no
active required `UNSUPPORTED_BLOCKER`, zero native fallback, and every host/
boot/recovery exception explicitly enumerated and justified.

The deployment lane is defined in [DEPLOYMENT.md](DEPLOYMENT.md) and must not
displace the current foundational gate. Later work proceeds as separate bounded
milestones: package/boot-safe formats; release/generation state; Store/catalog;
A/B loader; images and servicing; typed read-only administration; destructive
storage transactions; text installer; unattended deployment; GUI projection.
Its first end-to-end acceptance target is the same signed image and text installer
creating and independently booting generation 1 on supported KVM and WHP. Physical
UEFI/NVMe/power-cut work is a later, separately evidenced gate.

**PARTIALLY IMPLEMENTED boot-image prerequisite:** one canonical signed package-
derived GPT/FAT image completed its exact authenticated 20-byte trace through
QEMU/EDK2 with TCG and WHPX on Windows and QEMU/KVM under Arch Linux/WSL2 on
2026-08-25. The bounded gate accepts only explicit `tcg`, `whpx`, or `kvm`
accelerators and reports the selected backend. Native MRML WHP/KVM runners now
execute bounded controlled firmware stubs from the architectural reset vector
and produced matching decoded I/O proof on both backends. WHP enforces RX
firmware and RW/NX low RAM at its GPA boundary; KVM's memory-slot API enforces
guest-read-only firmware but cannot encode NX. They still launch verified package payloads directly
rather than executing OVMF, but their
release-bound boot form now authenticates the identical `SYSTEM.RELEASE` and
exact kernel-package version/digest carried by that image. Fresh WHP and nested-
KVM runs reached the authenticated marker from that shared pair. Both runners
now delegate the package trust-root, identity, version, release-binding, payload-
selection, and payload-bound decision to one `no_std` package-format admission
function. Their focused verification mode decoded the same 2,232,432-byte
kernel payload before optimized live runs reached the expected halt. Native-runner
OVMF/device/boot-media integration and physical UEFI evidence remain **PLANNED**.

The independently serviced component lane is **PLANNED** in
[packages/COMPONENT_INTERFACES.md](packages/COMPONENT_INTERFACES.md) and follows,
without blocking earlier foundations: canonical package identity;
`SystemGeneration`; package resolver; loader and stable MRML ABI primitives; and
quantitative memory accounting. Then add the interface schema, typed
provides/requires metadata, exact resolver, immutable in-process loader,
generation-safe binding, Zstd ABI-3 provider, ZIM migration, Store servicing,
retention/GC and inspection, optional service form, and cross-compiler evidence.
Do not convert kernel dependencies or every Rust crate, and do not claim any of
these steps implemented before code and focused tests exist.

**PARTIALLY IMPLEMENTED prerequisite:** the native build tool validates
canonical MRML package identities separately from Cargo package and Rust crate
identity and constructs a bounded immutable `SystemGeneration` record with exact
package versions and artifact digests. Windows and Arch Linux tests cover exact
lookup and fail-closed malformed, zero, duplicate, noncanonical, empty, and
over-capacity inputs. Runtime provider resolution, admission, activation,
persistence, rollback, and the end-to-end component-interface lane remain
**PLANNED**; bounded prerequisite increments are recorded below.

The prerequisite now includes bounded exact package resolution from canonical
identity/version/digest requirements to identical immutable candidates and
bounded transitive closure from canonical exact roots. Closure preserves exact
cycles, emits canonical package order, and rejects conflicting, missing,
ambiguous, noncanonical, self-dependent, or over-limit graphs. It has no version
ranges, optimization, backtracking, network/catalog lookup, provider
substitution or admission policy. The resulting exact package records now have
a canonical bounded version-2 codec that rejects truncation, trailing bytes,
reserved fields, malformed identities, and noncanonical order. Activation,
authenticated crash-safe persistence, and broader package/component lifecycle
remain **PLANNED**.

Stable ABI groundwork now includes canonical interface identity/generation,
bounded borrowed-view validation, opaque generational handles, and a fixed
little-endian call-header codec. The bounded schema/generator prerequisite is
also **PARTIALLY IMPLEMENTED**: version-1 schemas have deterministic SHA3-256
fingerprints and pointer-free Rust bindings, with the canonical Zstd ABI-3
fixture reproducing byte-for-byte on Windows and Arch Linux. Native call
lowering, compiler-emitted conformance metadata, ABI diffs, runtime loading, and
native provider execution remain **PLANNED**. The hosted Zstd ABI-3 byte-call
adapter now exercises exact generated descriptors on Windows and Arch Linux.
Separate package-owned `org.mrml.zstd` provider and `org.mrml.zim` consumer
artifacts also build for the MRML-native target. Separately signed artifacts
now complete one exact-generation hosted microVM call and supervised cleanup on
WHP and nested KVM; this remains controlled hosted evidence rather than native-
service, host-resistant, physical, or general resolver evidence.
A backend-neutral control-plane admission now binds those two immutable load
plans to the exact generation/interface placement and rejects either package
generation mismatch before backend launch. WHP/KVM attachment and execution
remain **PLANNED**.
The kernel-side prepared launch handoff now carries the same two digests plus
the exact interface fingerprint/generation and provider generation while
retaining the uncommitted fail-closed isolation route. Backend verification of
those digests and two-image builder attachment are **PARTIALLY IMPLEMENTED** in
both WHP and KVM adapters: mismatch precedes mapping and a second-image failure
cannot publish the consumed builder. Package-artifact execution is **PARTIALLY
IMPLEMENTED** for that one signed ZIM/Zstd hosted probe.

Loader groundwork now validates exact immutable package image geometry and W^X
section plans, including an executable entry point, without parsing, relocating,
mapping, patching, resolving symbols, or binding a provider. Runtime loading and
all binding/lifetime behavior remain **PLANNED**.

Kernel memory-accounting groundwork now charges one immutable component code
object once to an existing `MemoryPool` and permits separately authorized,
bounded read/execute mapping reservations for multiple consumers. The object
capability contains no write right, live mappings block reclamation, and package
metadata cannot substitute for pool or target capabilities. Physical backing,
population/sealing, native mapping, private-state charges, and runtime provider
binding remain **PLANNED**. The focused hosted component profile now also
charges its fixed-capacity task runtime and supervisor to one exact memory pool
and proves both commitments return after supervised cleanup; executable/private
pages and device projections remain unaccounted in that path. A separate kernel
guest-RAM reservation prerequisite now charges an
exact non-executable `Guest` `MemoryObject` under a pool capability, rejects
overcommit or metadata-only allocation, and requires proven native teardown
before release. The signed component profile now consumes exact backend-
specific base, consumer/provider, and shared/resource phases before WHP/KVM
native allocation, requires complete consumption before admission, and returns
the object after confirmed guest teardown. Fresh WHP and nested-KVM probes pass.
The vCPU prerequisite is now **PARTIALLY IMPLEMENTED** in the kernel: a
fixed-capacity generational CPU budget binds parallelism, runtime/period,
priority ceiling, and affinity to capability authority and issues exact
domain-bound reservations without amplification. The signed component path now
reserves one vCPU before WHP/KVM construction, retains it through guest lifetime,
and reclaims it after teardown. Exhaustion consumes the Total route into typed
unavailability with zero fallback. Each runner also pre-reserves a separate
page-rounded anonymous object for its exact MRML-owned prepared guest structure,
retains that charge through teardown, and requires the pool to return to zero.
The focused shared data and resource pages are no longer hidden in aggregate
guest RAM: each has a distinct one-page shared object and exact guest mapping
reservation, with a two-slot ceiling and native-teardown-first reclamation on
WHP and KVM. This deliberately excludes opaque host-hypervisor allocations.
Scheduler enforcement, executable/private-page integration, and broader
device-specific projection accounting are the current gates.

Typed provider-resolution groundwork now matches canonical `REQUIRES` and
`PROVIDES` edges only inside an immutable `SystemGeneration`. Interface name,
major generation, and schema fingerprint must all be byte-identical; resolved
records retain exact consumer/provider package versions and artifact digests.
Manifest V2 and `mrml.lock` also retain the exact in-process versus isolated-
service form; consumer/provider form mismatch fails closed. Bootloader and
recovery packages reject ordinary dynamic interface requirements regardless of
form.
ABI-4 cannot satisfy ABI-3, ambiguity fails instead of choosing a preferred
provider, and no path or filename participates. Live generation-safe binding,
policy preference, activation, and loading remain **PLANNED**.

Generation-safe binding identity is now **PARTIALLY IMPLEMENTED** in the build
tool model. Fixed-capacity generational slots retain exact resolved
consumer/provider package records and a generation-tagged in-process executable
or isolated-service endpoint. Existing entries cannot be retargeted during an
update, and released slot identities cannot address replacements. Runtime
capability authorization, executable admission/mapping, call dispatch,
reference accounting, and process integration remain **PLANNED**.

The canonical `org.mrml.zstd` provider and `org.mrml.zim` consumer migration are
**PARTIALLY IMPLEMENTED** as hosted code and focused tests. ZIM depends on the
separate ABI-3 binding package, declares the isolated-service form, and no
longer names a provider crate or path. Zstd declares native-service or microVM
placement and supplies a bounded service-side kernel IPC/shared-buffer adapter.
The existing Wikipedia composition root still directly supplies the provider
in its host build. A standalone `org.mrml.zstd` x86-64 UEFI service artifact now
builds through `mrml` on Windows and Arch Linux with exact launch-register and
syscall-frame bindings. Its allocation-free one-page target floor handles
raw/RLE frames and rejects entropy-coded blocks. This proves target build and
format plus one separately signed hosted execution with the ZIM consumer on WHP
and nested KVM. It does not prove general resolver-to-launch dispatch,
update-without-consumer-rebuild, native-service placement, or physical
isolation.

Servicing retention and inspection are **PARTIALLY IMPLEMENTED** as a bounded
build-tool model. Exact live bindings and retained system generations, rollback
roots, snapshots, exports, and disabled package-GC policy independently block
reclamation. Prohibited providers are denied for new bindings without erasing
retained content. No package deletion, persistent root discovery, update
transaction, or running-system integration is implemented.

The isolated-service form is **PARTIALLY IMPLEMENTED** as both the existing
hosted endpoint adapter and one service-side kernel composition around the
identical ABI-3 byte descriptors. The latter exercises a real `TaskRuntime`
inbox and one attenuated read/write shared-buffer capability, with exact
VM/task projection, private erased scratch, and bounded output. Windows and
Arch Linux host suites pass. A bounded userspace loop also receives one exact
request/capability, sends one exact response through a launch-bound runtime
trait, releases the leaf, and erases all buffers. A hosted `TaskRuntime` adapter
exercises a complete request/reply round trip,
rejects an unexpected sender, uses separate reply authority, and withholds the
reply unless received-leaf revocation succeeds. Its construction now consumes a
committed route retaining domain, interface/provider/policy generations,
Total-mode class, and placement, and rejects disagreement with the expected
resolver/policy binding. A canonical MRML-target provider binary and concrete
x86-64 trap now run with the separately signed ZIM consumer in the focused WHP
and nested-KVM microVM probe. Its fixed task runtime and supervisor are RAM-pool
accounted and reclaimed after cleanup. General resolver dispatch,
native-service parity, guest RAM/vCPU/device accounting, and physical isolation
remain unproved. The host-tested register adapter maps the loop to exact
operations 5, 7/8, 12, and 4 and proves capability release precedes response
visibility.

Cross-compiler evidence is **PARTIALLY IMPLEMENTED** for one narrow descriptor
identity projection. On both Windows gnullvm and Arch Linux, the canonical MRML
test action passed the 420 compiler-core tests, one component-interface test,
10 general conformance tests, and 335 nightly-replacement tests. The new test
executes the upstream-rustc reference and requires `mrml-rustc` to emit both
COFF and ELF objects. It does not establish full generated-binding support,
native MRML call lowering, object equivalence, or stable Rust/C component ABI.

Within existing boot/deployment phases, add typed UEFI objects, verified installer
entry creation, shell boot administration, owner/compatibility/dbx policy, then
physical firmware tests per
[UEFI_BOOT_MANAGEMENT.md](platform/UEFI_BOOT_MANAGEMENT.md). Within existing
service/device phases, add typed Ethernet, Wi-Fi, Bluetooth, persistent secret-
referencing profiles, shell operations, semantic Network & Devices, installer/
recovery reuse, and power integration per
[NETWORK_ADMINISTRATION.md](network/NETWORK_ADMINISTRATION.md). These are not new
mega-phases and do not displace the current gate.

The modern x86-64 platform lane is defined in
[platform/CPU_PLATFORM.md](platform/CPU_PLATFORM.md). Do not begin its broad
implementation ahead of the current foundational dependency gate. When reached,
split it into discovery/support-floor, vendor microcode and post-update security
state, scheduler constraints/CPU budgets, power/telemetry/thermal safety, system
monitor, and physical-device milestones rather than one cross-cutting patch.

**PARTIALLY IMPLEMENTED:** the kernel has bounded IPC, blocking receive/wakeup,
two-message inbox backpressure, attenuated capability transfer with rollback,
generational revocation, bounded exact-generation IPC delegation tracking,
transitive descendant revocation, shared-memory bindings, mapping revocation,
fault retirement, service cleanup/restart policy, and signed two-service probes.
Kernel-owned receive envelopes now retain exact sender and endpoint sequence,
and bounded explicitly linked peers receive typed fault/exit results with
scheduler wakeup. Cross-CPU peer migration remains fail-closed until ownership
transfer for those relations is implemented.
The host-resource table now supports capability-authorized multi-party sharing
of one exact host extent across distinct VM mappings. Each added endpoint
independently proves mapping authority and liveness, cannot amplify the source
access, and must remain NX. Per-endpoint revocation reports when the final
reference is gone without exposing the opaque host handle to a guest.
Backend-neutral revocation now removes the exact KVM memory slot or every WHP
GPA submapping before retiring the common mapping identity. Any uncertain
native teardown poisons subsequent vCPU execution. Live Linux KVM and Windows
WHP probes now also exercise stopped-task leaf revocation for a common service
page while the peer mapping and backing remain live.
Service retirement now preflights restart timing and publishes an exact one-use
cleanup ticket. Restart remains blocked until the corresponding KVM/WHP eraser
proves the retired task and page-table root and completes exact-artifact
reprovisioning; failed erasure is retryable and ticket replay is rejected.
Shared endpoints may now bind an exact task generation in addition to their VM
and mapping identities. Cleanup invalidates each failed task's native mapping
before retiring its common mapping and binding, preserves peer endpoints, and
requires successful final host-resource retirement before restart. Completed
obligations survive retry across host-resource or address-space erasure failure.
The supervisor now exposes one bounded recovery operation that retires the
faulted task, publishes typed peer death, completes the caller-supplied
task-resource/address-space eraser, and creates a fresh service/task generation
from an independently validated context before returning the surviving peer's
scheduling outcome. Cleanup failure retains the exact ticket for retry; restart
rejection leaves a clean stopped service that can be authorized and retried
separately. Freshly signed WHP and KVM runs now exercise cleanup-ticket-gated
per-slot address-space reprovisioning across clean exit, fault, restart, and
restart-budget exhaustion. The general task-owned shared-binding/opaque
host-resource composition remains simulation-tested; the signed service path
now exercises its concrete one-page hosted realization on both backends.
Those signed paths now also establish an exact-generation control-peer relation
in each generation. Clean sender exit publishes a typed `Exited` result; the
kernel verifies its retired task identity and the queued message envelope's
sender and endpoint sequence before receiver continuation.

The next coherent milestone is an end-to-end service substrate: two isolated
CPL3 services communicate through a multi-client blocking control channel and a
revocable shared-page bulk channel; one service is deliberately crashed; the
kernel revokes its capabilities, mappings, IPC and shared state; peers receive a
typed death result; the supervisor performs one bounded clean restart; and the
unrelated service continues. Exercise equivalent signed paths under WHP and KVM
and add adversarial unit tests. This milestone must not claim host-resistant
confidentiality.

The signed two-service path now covers the blocking control channel, exact
sender/sequence envelopes, typed clean peer death, a revocable task-owned
shared page, cleanup-gated fault retirement, and bounded restart on both hosted
backends. The replacement generation now leaves its sender blocked and live
while the receiver faults; retirement publishes and validates the exact typed
fault result before returning any peer continuation. This closes the signed
two-service Phase 1 substrate gate. The next dependency-ordered OS milestone is
the Phase 2 policy/configuration service and its supervision protocol.

## Concurrent compiler lane

The separate build-tool lane follows [build/BUILD_SYSTEM.md](build/BUILD_SYSTEM.md):
manifest, pinned upstream orchestration, profiles, EFI export, packaging/signing,
release/image/publication, provenance, experimental `mrml-rustc`, then per-profile
promotion. It cannot redirect this compiler lane or the foundational OS gate.

**PARTIALLY IMPLEMENTED:** stage-zero `packages/tools/mrml`, root and package-local
`mrml.toml` manifests, structured native build/test dispatch, native dependency resolution, current-host VMM
selection, UEFI routing, and CUDA target validation now exist. All tracked
components have semantic homes outside generic `crates/`. Follow
[build/MIGRATION_INVENTORY.md](build/MIGRATION_INVENTORY.md): make compiler inputs
and actions exact, replace compilation with direct rustc, prove Windows/Linux
parity, then confine Cargo to clean-source bootstrap. Package/release/image/
publication remain planned.

The native-resolver audit increment is now implemented: `mrml doctor` validates
all 45 components and their declared edges without invoking Cargo metadata, and
`mrml audit` emits dependencies, features, outputs, build scripts, proc macros,
and bounded source-input sites. Missing dependencies, invalid targets, empty
outputs, self-dependencies, and cycles fail closed. Dependency, feature, output,
and per-component input-policy facts are native version-3 declarations that fail
on graph or lexical-audit drift. The first
semantic leaf move is complete: dependency-free `mrml-math` now resides under
`packages/libraries/math`; its explicit build/test action now invokes pinned
rustc directly with no Cargo fallback. The dependency-free Windows and Linux
platform leaves now have the same exact action; Windows GNU/LLVM and Arch Linux
WSL2 build/test evidence exists, without implying KVM, bare-metal, or physical-
hardware verification. The next leaf,
`mrml-percent-encoding`, now resides under `packages/libraries/percent-encoding`
with its runtime edge and Cargo bridge retained. Continue one dependency-light
leaf at a time before group moves; `mrml-tokenizer` is now the third migrated
leaf with its trainer edge retained. See
[build/BRIDGE_INVENTORY.md](build/BRIDGE_INVENTORY.md).

`mrml-runtime` is now the first dependent direct-rustc node: the native planner
builds and wires only the target-active platform extern. Windows passed 38 tests
and Arch Linux WSL2 passed 37 without Cargo compilation for those nodes.

The next eight featureless runtime consumers are now direct-rustc nodes as well;
Windows and Arch Linux WSL2 each passed 31 tests across that layer. Twelve of 42
components now have native actions, with the other 30 explicitly transitional.

The compiler core is the first multi-output native node: its inline harness and
both integration targets run directly with an explicit bounded test stack.
Windows and Arch Linux WSL2 each pass 765 compiler-core tests. Thirteen of 42
components are native; 29 remain transitional.

Native example outputs are now exact. `mrml-opus` passes 179 tests and links all
three declared examples on both hosts, bringing the native count to 14 of 42.

Native feature sets and optional extern gates are now exact for `mrml-av1`.
The empty default set omits its `nvidia` platform extern while retaining the
runtime edge; both Windows and Arch Linux WSL2 build the library and declared
example directly. With its declared 32 MiB test stack, each host reproduces the
Cargo baseline at 273 passing and two existing source-test failures. Fifteen of
42 components are native; 27 remain transitional.

`mrml-crypto` is the first nonempty native feature-set consumer. Its resolved
default set selects `runtime`, activating the already-native runtime extern;
Windows and Arch Linux WSL2 each pass all 27 direct tests. Sixteen of 42
components are native; 26 remain transitional.

`mrml-tls` now consumes the exact native crypto/runtime artifacts. Windows and
Arch Linux WSL2 each pass all 11 direct tests; environment-selected live-peer
and external-fixture paths were not exercised. Seventeen of 42 components are
native; 25 remain transitional.

`mrml-http` now consumes exact native runtime/TLS artifacts. Windows and Arch
Linux WSL2 each pass all three direct tests; environment-selected live URL and
range probes were not exercised. Eighteen of 42 components are native; 24
remain transitional.

`mrml-ssh` now consumes exact native crypto/runtime artifacts. Windows and Arch
Linux WSL2 each pass all 23 direct tests, including loopback transport; no live
remote or external signing operation was exercised. Nineteen of 42 components
are native; 23 remain transitional.

Exact native binary outputs and compile-time environment records are now
implemented. `mrml-git` builds its library and executable on both hosts, then
passes 51 library tests plus one binary test. No live remote operation was
exercised. Twenty of 42 components are native; 22 remain transitional.

`mrml-tools` now has an exact resolved `runtime` feature set, stable manifest
path input, six universal externs, and one target-selected platform extern.
Arch Linux WSL2 passes 32 direct tests; Windows matches its Cargo baseline at
31 passed and one installed-Edge DevTools failure. Twenty-one of 42 components
are native; 21 remain transitional.

Bin-only native actions now declare the absence of a primary library, require
exact binary outputs, and cannot satisfy an extern edge. The compiler driver
builds `mrml-rustc` and passes both tests on Windows and Arch Linux WSL2.
Twenty-two of 42 components are native; 20 remain transitional.

Native feature profiles now cover every component target exactly once.
`mrml-crypto` keeps `runtime` for Windows/Linux and selects the empty set for
`MRML_NATIVE`; both hosts cross-build the latter as an `x86_64-unknown-none`
rlib without a runtime extern. This is cross-build evidence, not execution.

Named provider profiles now resolve, cache, and name nondefault dependency
artifacts independently. The kernel binds crypto's empty `core` profile on
`MRML_NATIVE` and in its host harness, so host verification cannot silently
activate crypto's default `runtime` feature. Both hosts cross-build its
`x86_64-unknown-none` rlib, then independently compile and run the explicitly
declared 64 MiB host harness with 474 passing tests. Twenty-three of 42
components are native; 19 remain transitional. This does not establish target,
bare-metal, virtualization, or physical-hardware execution.

The kernel now declares Windows/Linux as exact host-build projections without
adding them to its public `MRML_NATIVE` target set. Storage uses that projection
to bind native kernel mechanics plus crypto's empty `core` profile. Both hosts
cross-build `mrml-storage` for `x86_64-unknown-none` and pass its declared 64 MiB
host harness with 121 tests. Twenty-four of 42 components are native; 18 remain
transitional. No physical storage, target execution, or durability evidence is
claimed by this build migration.

Configuration now has an exact native action over crypto's empty `core` profile,
kernel, and storage. Both hosts cross-build it for `x86_64-unknown-none` and run
all 31 tests through the declared host projection. Twenty-five of 42 components
are native; 17 remain transitional. This does not establish signed-service,
target-runtime, or physical-hardware execution.

Compiler-target variants are now explicit, allowlisted, dependency-transitive,
and artifact-separated from the semantic target's default triple. The service
image remains in `MRML_NATIVE` policy while its complete graph compiles for
`x86_64-unknown-uefi`; both hosts emit a PE32+ EFI application in debug and
release modes. Repeated same-host hashes are stable, but Windows/Linux hashes
differ, so cross-host reproducibility is not established. Twenty-six of 42
components are native; 16 remain transitional. No UEFI or service runtime ran.

The kernel benchmark harness now has a native action over the host-projected
kernel and runtime. Windows discovers 14 tests and Linux 13; all are explicitly
ignored manual performance gates, and none ran. This is compile/registration
evidence only, not benchmark or physical-core evidence. Twenty-seven of 42
components are native; 15 remain transitional.

Non-host projected builds now require an explicit provider declaration, and
compile-environment inputs distinguish fixed values from enforced absence.
Kernel-image selects exactly `kernel-image`, projects kernel/crypto-core to UEFI,
and emits a PE32+ EFI application on both hosts. Deliberately inherited values
for all four optional `MRML_*` inputs are removed and do not change the resulting
same-host hash. Twenty-eight of 42 components are native; 14 remain transitional.
No UEFI firmware, Secure Boot, TPM, bare-metal, or hardware execution occurred.

Native binary actions now bind exact target and feature gates, and an explicit
UEFI selector is preserved instead of being replaced by the default kernel
image. `mrml-uefi` builds its library on hosts, emits the loader only for UEFI
with `uefi-image`, and passes 24 projected tests on each host. Both hosts emit a
PE32+ EFI application; a Windows poisoned-environment probe leaves the hash
unchanged across all 21 absent inputs. Twenty-nine of 42 components are native;
13 remain transitional. Tests use simulated TPM transports, not TPM hardware.

Native profile identity now includes a stable rustc metadata discriminator, not
only the artifact filename and build key. This permits the signing tool's direct
host-default crypto dependency to coexist with kernel's crypto-core dependency.
`mrml-sign` builds and passes eight temporary-file tests on both hosts. Thirty of
42 components are native; 12 remain transitional. No live key, enrollment,
firmware, or hardware signing operation occurred.

Native extern scope now distinguishes production from test-only direct edges.
KVM's direct crypto-core dev edge is active only in its harness, while kernel's
transitive production crypto-core edge remains. On Arch Linux WSL2, `/dev/kvm`
was usable and 18 tests passed, including conditional API and signed-guest
probes; one manual live-mapping performance gate remained ignored. Thirty-one of
42 components are native; 11 remain transitional. This is nested KVM evidence,
not bare-metal, IOMMU, TPM, or physical-hardware evidence.

WHP now has the corresponding native Windows action with production kernel and
runtime externs and a test-only crypto-core dev edge. Native and Cargo baselines
each pass 22 tests with one manual performance gate ignored. A separate run of
that gate completed 10,000 WHP map/revoke iterations, directly establishing WHP
API and hosted-hypervisor mapping execution on this Windows host. The exact Linux
toolchain passes the declaration frontend tests, Clippy, doctor, and audit but
does not build or run this Windows-only component. Thirty-two of 42 components
are native; 10 remain transitional. This is not VTL1, TPM, IOMMU, bare-metal, or
physical-hardware evidence.

Tensor now replaces its Cargo-only custom build execution with a declared PTX
sub-action. It validates the required GPU architecture, invokes the pinned
nvptx rustc with fixed arguments, supplies the exact generated `OUT_DIR`, keeps
CUDA host artifacts separate by ABI triple, and accounts for every test,
example, and benchmark output. Windows gnullvm and Arch Linux WSL2 each match
Cargo's 43-test CUDA baseline, run the focused CUDA prefill probe, and emit the
same `sm_120` PTX hash. Thirty-three of 42 components are native; nine remain
transitional. This is controlled CUDA driver/device evidence, not proof of
physical GPU topology, passthrough isolation, or native MRML GPU execution.

The model library's default `runtime` profile now directly consumes native JSON,
runtime, and tensor artifacts. Both exact host toolchains build it and match the
Cargo baseline at seven passing tests. Thirty-four of 42 components are native;
eight remain transitional. No production model, remote service, CUDA profile,
or inference workload was exercised.

Compile-time environment declarations now include a bounded source-use count.
Agent binds one exact `CARGO_PKG_VERSION=0.0.1` value to its two audited reads,
then its default `runtime` profile directly consumes the eight native providers.
Both exact hosts build it and match Cargo at 20 passing tests. Thirty-five of 42
components are native; seven remain transitional. No configured live Hugging
Face query, remote inference, model workload, or CUDA agent profile ran.

The trainer is now a native bin-only action with exact math, runtime, tensor,
tokenizer, and Wikipedia providers. Both exact hosts build it and match Cargo
at four passing tests. Thirty-six of 42 components are native; six remain
transitional. Only bounded generated test data ran; this is not production
corpus, sustained training, CUDA, or physical-hardware evidence.

The WHP runner now has an exact Windows bin-only action matching the bridge's
deliberate `--no-default-features` build. Native and Cargo suites both pass its
seven tests. Thirty-seven of 42 components are native; five remain
transitional. The declared CUDA edge remains inactive, and no VM, VBS/VTL1,
IOMMU, or physical-hardware execution occurred.

CLI and machine now preserve their default `auto` chain through named agent,
model, and tensor profiles. Recursive native compilation generates the declared
`sm_120` PTX input at tensor instead of depending on Cargo or a prior build.
Windows and Linux match Cargo at zero CLI tests and four machine tests, with an
identical PTX hash. Thirty-nine of 42 components are native; three remain
transitional. No CUDA device, inference, live provider, or production workload
ran.

Server now compiles its library and self-linked binary natively while binding
one `auto` model artifact on both its direct edge and the edge through agent.
Windows and Linux match Cargo at four library tests and a zero-test binary
harness. Forty of 42 components are native; two remain transitional. No live
listener, TLS endpoint, remote model, CUDA device, or production traffic ran.

The KVM runner now compiles natively on Linux with its exact core-crypto,
kernel/KVM, runtime, and tensor `cuda` providers. Arch Linux WSL2 matches Cargo
at eight tests. Forty-one of 42 components are native; only the `mrml`
clean-source bootstrap remains transitional. No VM, bare-metal, IOMMU, GPU, or
physical-hardware execution occurred.

The native build graph is complete: `mrml` now self-builds/tests through its own
bin-only action, workspace loading rejects any missing native action, and the
internal Cargo transition branch is removed. Locked clean-source bootstrap plus
doctor/audit, native self-build, and 12 self-tests passes on both exact hosts.
All 42 components are native. Cargo remains only stage zero; package, release,
image, install, and publication milestones remain independently incomplete.

`mrml-zstd` is the fourth migrated leaf; its Wikipedia edge and patent-review
source path now resolve to `packages/libraries/zstd` without changing codec
behavior.

`mrml-zim` is the fifth migrated leaf; its Wikipedia edge now resolves to
`packages/libraries/zim` without changing archive semantics.

`mrml-json` is the sixth migrated leaf; its six consumer edges now resolve to
`packages/libraries/json` without changing parser/writer semantics.

`mrml-wikipedia` is the seventh migrated library component; its ZIM/Zstandard
edges are now sibling semantic-package references and its trainer edge remains.

`mrml-opus` is the eighth migrated library component; its math edge is now a
sibling semantic-package reference without changing codec behavior.

`mrml-windows` is the ninth migrated library component; its six consumers now
resolve to the semantic package without changing Windows primitive behavior.

`mrml-linux` is the tenth migrated library component; its five consumers now
resolve to the semantic package without changing Linux/Unix primitive behavior.
This Windows-host move does not establish Linux execution evidence.

`mrml-runtime` is the eleventh migrated library component; its Windows/Linux
edges are now sibling semantic-package references and all thirty-one inbound
Cargo paths across thirty manifests resolve to the semantic runtime home without
changing runtime behavior.

`mrml-crypto` is the twelfth migrated library component; its runtime edge is a
sibling semantic-package reference and all fourteen inbound Cargo paths resolve
to the semantic cryptography home without changing algorithms or policy.

`mrml-tls` is the thirteenth migrated library component; its crypto/runtime
edges are sibling semantic-package references and both consumers resolve to its
semantic home without changing protocol behavior.

`mrml-http` is the fourteenth migrated library component; its TLS/runtime
edges are sibling semantic-package references and both consumers resolve to its
semantic home without changing HTTP/HTTPS behavior.

`mrml-ssh` is the fifteenth migrated library component; its crypto/runtime
edges are sibling semantic-package references and its Git consumer resolves to
the semantic SSH home without changing protocol or signing behavior.

`mrml-error` is the sixteenth migrated library component; its JSON/runtime
edges are sibling semantic-package references and all eleven consumers resolve
to its semantic home without changing error behavior.

`mrml-terminal-style` is the seventeenth migrated library component; its
platform/runtime edges are sibling semantic-package references and all five
consumers resolve to its semantic home without changing terminal behavior.

`mrml-av1` is the eighteenth migrated library component; its platform/runtime
edges are sibling semantic-package references without changing codec,
conformance, or feature behavior.

The compiler lane has moved dependency-free `mrml-rustc` to
`packages/compiler/core`; its driver edge and durable recovery/oracle/review references
now resolve there without changing compiler semantics.

The compiler driver now resides at `packages/compiler/driver`; its core/error/runtime
edges resolve to semantic homes without changing command behavior.

`mrml-git` now resides at `packages/tools/git`; all four dependency edges already
resolve to semantic packages without changing Git or SSH behavior.

`mrml-tools` now resides at `packages/tools/host`; all eight dependency edges resolve
to semantic packages and all four consumers resolve to the host-tool home
without changing input policy or tool behavior.

The independently scoped compiler lane follows
[COMPILER.md](COMPILER.md), not an arbitrary historical-rustc coverage target.
Rust 2024 is the floor. Preserve and stabilize the existing bounded semantics,
then prioritize:

1. an explicit typed ownership/place/control-flow representation;
2. move, shared-loan, mutable-loan, reborrow, and flow-sensitive outlives
   analysis toward modern Polonius semantics;
3. bounded modern trait-goal, canonicalization, where-clause, normalization,
   coherence, ambiguity, recursion, and cycle foundations;
4. post-2024 systems gaps, especially naked functions/`naked_asm!`, validated
   inline assembly, strict provenance, modern const behavior, and `no_std`/ABI
   facilities needed by MRML;
5. Application, System, and Compiler/Kernel admission profiles;
6. compiler-derived executable security metadata and loader validation; and
7. reproducible advancement through exact recorded future-Rust oracles.

The highest-value next major compiler milestone is the bounded typed
ownership/place/CFG representation needed by both sound borrow checking and
future dataflow analyses. Smaller aggregate, pattern, control-flow, and
diagnostic prerequisites remain appropriate when they directly unlock that
model. Old-edition parsing, historical unsoundness, rustc diagnostic wording,
unstable symbol/ABI quirks, and legacy cases with no current MRML dependency are
deprioritized.

Compiler candidates are ranked by MRML usefulness, modern Rust relevance,
security relevance, dependency unlocks, implementation complexity, oracle
stability, and testability—not superficial upstream test counts. The compiler
and OS lanes progress concurrently and converge when real MRML services compile
under validated profiles; neither waits for the other to become complete.

## Phase 1 — Kernel and service foundation

1. Complete multi-client blocking send/receive and scheduler sleep/wakeup.
2. Define bounded queues, backpressure, cancellation/timeout policy, and typed
   peer-death behavior.
3. Complete atomic capability transfer/derivation with non-amplification tests.
4. Complete transitive revocation accounting for IPC and descendants.
   **IMPLEMENTED:** successful transfers commit bounded exact-generation
   delegation edges; explicit source or intermediate revocation and task death
   revoke the complete descendant set before another task can run. Capacity is
   preflighted, denied transfers roll back both handles and edges, and domains
   with live delegation relations cannot migrate.
5. Add shared-page/ring setup with explicit ownership and access attenuation.
   **IMPLEMENTED** for the bounded one-page service substrate: KVM and WHP map
   one common frame through independent exact user read/write leaves, revoke
   only the retired task's leaf while preserving its peer, and re-arm leaves
   only after fresh task generations exist. General multi-page ring protocol,
   backpressure, and application-facing setup remain later work.
6. Pair mapping revocation with native KVM/WHP invalidation before vCPU resume.
   **IMPLEMENTED** in code, focused tests, and signed hosted probes. The vCPU is
   stopped for exact-leaf removal; the next service transition reloads CR3
   before peer continuation, and stale retired roots are never resumed.
7. Integrate fault cleanup, peer notification, erasure, and bounded restart.
   **IMPLEMENTED** in kernel mechanism and focused simulation tests: typed peer
   notification, task-domain revocation, native-first task-owned shared-resource
   cleanup, final host-handle retirement, exact erasure gating, and bounded
   restart are coupled through one supervised recovery operation. Cleanup and
   restart failures retain retryable fail-closed state. Signed KVM and WHP runs
   exercise exact per-slot address-space cleanup before restart plus
   exact-generation control-peer reconstruction, typed clean-death delivery,
   per-task shared-leaf revocation, surviving-peer access, and fresh-generation
   re-arm. The broader opaque host-resource composition remains outstanding
   live evidence rather than a missing kernel mechanism.
8. Benchmark one-way, round-trip, cross-core, wakeup, transfer, revocation, and
   shared-memory setup costs.
   **IMPLEMENTED:** release microbenchmarks cover backend-neutral
   one-way and round-trip IPC policy, blocked wakeup, capability transfer and
   revocation, shared-binding setup, and cross-runtime domain handoff. Windows
   evidence now includes a topology-validated affinity-pinned distinct-core
   mailbox round trip and live WHP map/revoke lifecycle; an Arch Linux/WSL2
   `/dev/kvm` run covers the matching KVM allocation/map/revoke lifecycle.

Security gate: no stale identity, capability, mapping, queue entry, or shared
page remains usable after death/revocation; partial operations cannot duplicate
authority; unrelated domains continue.

## Phase 2 — Minimal userspace system

Add quantitative `MemoryPool`/`MemoryObject` accounting and bounded delegation,
then IPC/cache charge foundations, as specified in
[memory/MEMORY_RESOURCE_MODEL.md](memory/MEMORY_RESOURCE_MODEL.md). Preserve the
current storage/service critical path; VMM guest-pool accounting follows its
memory dependencies, while resize, NUMA, huge pages, swap/compression, and QoS
remain later work. This does not displace VirtualGPU or compiler ownership/CFG.

**PARTIALLY IMPLEMENTED memory-resource prerequisite:** the kernel policy core
now represents fixed-capacity generational `MemoryPool` and `MemoryObject`
identities. Root creation and child delegation bound page commitments, mapping
reservations, child counts, and rights; exact allocation limits fail locally;
content-free usage inspection is independent from control; release and
recursive pool revocation stale object and descendant-pool identities. This is
accounting rather than frame allocation. Fixed-capacity mapping reservations
now consume the pool's quantitative mapping budget under separate source-object
and target-address-space capabilities, enforce W^X/bounds/non-overlap, and block
object or pool retirement until real mapping teardown and invalidation are
proven. A backend-neutral transaction publishes a reservation only after exact
installation succeeds and retains it across removal failure until exact teardown
and invalidation succeed. Deterministic protocol tests cover both boundaries;
no x86 page-table or KVM/WHP adapter is integrated yet. Physical mapping,
sharing, DMA, resize/COW, cache charging, VMM guest projection,
userspace policy, and hardware evidence remain pending before this prerequisite
is complete. The first physical-backing lifecycle is **PARTIALLY IMPLEMENTED**:
an exact object-sized run may be published only after a privileged backend
confirms exclusive zeroed ownership, and remains live until confirmed mapping/
DMA revocation, invalidation, full scrub, and safe release. Exact `CONTROL|PIN`,
physical overlap rejection, separate `INSPECT`, and fail-closed object/pool
retirement are enforced. Only a deterministic protocol backend is tested; no
reusable frame allocator or physical machine is claimed. Backed mapping
composition now rejects unbacked objects before backend invocation, derives the exact
physical subrange from the validated object-page range, binds that range into
both install and retryable removal, and prevents backing release until mapping
retirement. Accounting-only mappings remain available for simulation; an x86
active-page-table or KVM/WHP adapter is still pending. An exclusively owned inactive
x86-64 hierarchy can now serve as the concrete backed-mapping adapter: it binds
one exact target, rejects access that x86 leaves would broaden, maps exact
physical leaves transactionally, restores a mapping after retryable removal
failure, and permanently quarantines uncertain cleanup. Active hierarchy
publication, TLB/SMP invalidation, boot adoption, and KVM/WHP adapters remain
pending. The first page-table charge
foundation is **PARTIALLY IMPLEMENTED**: an opt-in wrapper commits
the complete validated preallocated arena capacity before exposing a usable
store, and unsafe release requires the caller to prove every table unreachable
and required invalidation complete. Existing boot construction is not migrated.
The first IPC/task-metadata charge foundation is now **PARTIALLY IMPLEMENTED**:
an accounted runtime reserves its complete fixed scheduler, task/capability,
delegation-table, and two-slot-per-task inline-inbox footprint from one exact
pool before publication. Exhaustion leaves the pool unchanged, and consuming
release returns the commitment; failed release returns the still-accounted
runtime. Existing boot/runtime construction is not yet migrated to this path.
The first userspace-policy charge foundation is **PARTIALLY IMPLEMENTED**:
fresh, empty, and checkpoint-recovered `ConfigurationService` construction may
commit the complete concrete settings/audit footprint to one exact pool before
publication. Validation or exhaustion leaves usage unchanged; consuming release
returns the commitment. The signed service image and reboot path do not use it.
The separate fixed lifecycle owner is now **PARTIALLY IMPLEMENTED** with an
opt-in accounted `ServiceSupervisor`: its complete service/task, restart-policy,
budget, generation, and cleanup-ticket capacity is committed before
registration. Release is unsafe until no task, cleanup, prepared plan, peer,
recovery path, or external policy depends on it. An opt-in aggregate substrate
now commits the task runtime, supervisor, and configuration service atomically;
live composition remains pending.

1. Implement the policy/configuration service and service supervision protocol.
   **PARTIALLY IMPLEMENTED:** `mrml-config` provides a no-allocation typed
   schema, exact-object capability checks for reads and every transaction
   update, optimistic revision binding, atomic bounded commits, monotonic audit
   sequencing with explicit overwrite gaps, and strict version-1
   configuration/supervision request and response codecs. The opt-in
   `AccountedConfigurationService` charges its complete fixed settings and audit
   capacity before fresh or checkpoint-recovered publication; live image and
   reboot integration remain pending. `AccountedServiceSupervisor` separately
   charges the complete fixed lifecycle/restart/cleanup table before use.
   `AccountedPolicyServiceSubstrate` instead supports one exact aggregate charge
   after scheduler and schema validation; exact-limit admission succeeds and a
   one-page shortage leaves usage unchanged. Live image construction remains
   unaccounted. Kernel service-state
   introspection now requires exact READ authority rather than a service token.
   Syscall operation 9 now exposes only that authorized state query to CPL3: it
   accepts an opaque generational service token plus an exact task-local READ
   capability, rejects nonzero reserved registers, and returns only a detail-
   free Running/Exited/Faulted code. Canonical 48-byte query requests now cross
   the real buffered IPC path with one sender-derived READ capability, and the
   userspace service invokes operation 9 before returning a canonical 48-byte
   detail-free response. Fresh signed KVM and WHP probes repeat that exchange in
   both generations.
   The restart wire record can no longer carry a clock value; bytes 40--47 are
   canonical zero and dispatch receives time only from trusted kernel state.
   Syscall operation 10 decodes only an exact generational capability and
   service token, rejects every other register, and returns only a replacement
   generation or detail-free denial. The live image always denies it until an
   exact trusted reprovision plan exists. Split-phase restart planning now
   authorizes CONTROL and snapshots trusted priority/context/time without
   mutation, then revalidates generation, object, cleanup, backoff, budget, and
   one-use state after the reprovisioning boundary before task creation.
   Both hosted backends admit a third independently rooted verified service
   image for a management client. Its image, stack, and page tables use
   disjoint checked physical ranges, while the common shared page and per-service
   resource remain deliberately confined to slots 0 and 1. Signed KVM and WHP
   regression runs verify construction. The focused restart-request image now
   creates that task without shared or resource mappings. After the old sender
   is retired and cleaned, the manager transfers exactly CONTROL in a canonical
   restart envelope. Trusted kernel code supplies the fixed launch context,
   stages host shared-leaf re-arm, commits only after revalidation, provisions a
   fresh generation, and returns a detail-free response that the manager checks.
   Fresh signed KVM and WHP probes exercise this path. They stop before the new
   task executes; the separate ordinary service probe remains the evidence for
   replacement re-entry. The separate recovered-policy foundation described
   below is not exercised by these probes; live persistent-policy restoration
   and physical-hardware execution remain pending.
   Message dispatch now takes authority only from kernel-derived receiver-space
   capabilities, rejects missing/extra/payload-forged authority, and composes
   authorized restart with existing cleanup, backoff, limit, and trusted fresh-
   context gates. Buffered syscall operations canonically bind payload and
   capability-descriptor addresses/counts, and
   mapping policy validates every complete user leaf and access direction before
   invoking a copy backend. Signed WHP and KVM probes now execute real
   `mrml-config` schema admission and commit dispatch in CPL3. Each signed
   generation begins with the trusted configuration-root identity and no
   settings. The client sends a canonical bounded schema record and delegates
   only attenuated root CONTROL; exact kernel authorization precedes admission,
   and schemas freeze after the first commit. A separate one-update request has
   zero payload authority and independently delegates fresh root CONTROL and
   setting WRITE before atomically committing revision 1. The supervised
   replacement repeats admission and commit from fresh volatile state. The same
   proof retains bounded lifecycle cleanup and covers two simultaneously blocked
   buffered receivers. A canonical bounded checkpoint codec now preserves all
   admitted schemas, values, per-setting/global revisions, and the retained
   chronological audit window. Export requires root READ; recovery requires
   root CONTROL and a caller-supplied expected SHA3-256 digest, and rejects
   corruption, hidden data, stale digests, capacity mismatch, and inconsistent
   revision/audit state. The digest is not self-authentication. The codec is now
   bound to one exact capability-native stable file successor: export requires
   configuration-root READ, staging requires file WRITE and RESIZE, and the
   object, successor generation, length, content digest, extent metadata, and
   publication participant must all agree. Staged data becomes active only
   after the existing COW transaction publishes and an exact one-use receipt is
   consumed. Recovery requires file READ plus configuration-root CONTROL and an
   exact authenticated-recovery-selected file generation; corruption and I/O
   uncertainty fail rather than searching an older generation. This is focused
   in-memory simulation evidence. A signed CPL3 KVM/WHP probe now composes the
   checkpoint with the isolated MRML-native block service, publishes by exact
   COW receipt, recovers file generation 2, and reloads the service-bound
   policy. A nonvolatile device, reboot restoration, physical power-loss
   evidence, live stable-storage policy restoration, and
   reboot-time capability reconstruction remain pending, so this item is not
   complete. A
   canonical persistent restart-policy record now binds one service object to a
   finite restart budget and bounded exponential backoff. Loading it from fresh
   or recovered configuration rechecks the exact setting READ capability,
   rejects unset, malformed, noncanonical, or wrong-service data, and retains
   both configuration and setting revisions. Application rechecks the exact
   live capability, record, service binding, and both revisions immediately
   before supervisor mutation, so revocation or configuration drift invalidates
   the cached value. Only trusted code holding mutable supervisor state can
   apply the result; the record carries no authority and
   every restart still requires exact service CONTROL. Focused tests prove
   checkpoint restoration, stale-capability denial, service substitution
   rejection, backoff, and budget enforcement. Dynamic policy replacement is
   now implemented in host-side unit/simulation code. Application explicitly
   rechecks setting READ and exact value/global/setting revisions, while the
   supervisor independently requires exact service CONTROL. Each successful
   replacement advances a bounded policy generation and stales prepared restart
   plans without resetting consumed budget or shortening an existing deadline;
   generation exhaustion changes nothing. The versioned CPL3 protocol now
   requires exactly two ordered IPC-derived capabilities: setting READ followed
   by service CONTROL. The service re-reads the canonical service-bound record,
   uses a trusted service-object mapping, and invokes operation 11 separately.
   Fresh identical signed artifacts completed this path and the subsequent
   authorized restart on KVM and WHP. A reusable exact-block composition now
   stages the checkpoint through `BlockFileSession` over `BlockVolume`, including
   when its device is selected by a principal-bound MRML block-service session.
   Deterministic integration publishes by one-use COW receipt, recovers the
   exact selected file generation, reloads the service-bound policy, rejects a
   derived read-only block session before writes, and proves parent revocation
   stales its descendants. Identical signed KVM/WHP artifacts now exercise that
   exact composition through 18 bounded CPL3 block requests and complete both
   task/resource lifecycles. The backend remains volatile; reboot-time
   restoration and capability reconstruction remain pending, so
   this item remains partial.
   The next protocol dependency is now implemented at the kernel ABI boundary:
   operation 11 accepts only an opaque service generation, one task-local
   capability, bounded restart count/backoff scalars, and a zero reserved
   register. Decode constructs a valid `RestartPolicy` before dispatch; the
   service path independently requires exact CONTROL for the live supervisor
   object and returns a detail-free result. It accepts no setting identity,
   service-object claim, pointer, context, priority, executable, time, or
   persistence claim. The versioned userspace supervision request, trusted
   service-object mapping, and signed CPL3 KVM/WHP execution are now implemented
   as described above.
2. Define native filesystem object identities and attenuated directory/file
   rights, then the volume/superblock and directory/file metadata formats.
   **IMPLEMENTED:** `mrml-storage` supplies stable nonzero volume/object IDs,
   kind-specific rights without a universal administrator right,
   principal-bound generational handles, attenuated cross-principal derivation,
   and transitive descendant revocation. Version-1 fixed records cover volume
   geometry, an exact predecessor-linked superblock generation, directory and
   file metadata, and canonical bounded UTF-8 directory entries. SHA3-256
   self-checks detect covered corruption only; they provide neither authority,
   authenticity, atomic persistence, nor rollback resistance. Windows and
   Linux unit tests exercise malformed records, wrong volumes, stable identity
   across rename, rights confusion, stale handles, and descendant revocation.
   Prepared file and directory primary-metadata COW digests cover the fixed
   record followed by canonical zeros through the exact block-aligned pointer
   extent; undersized ranges and hidden nonzero tails fail closed.
3. Implement extent mapping, checksummed COW metadata, directory operations,
   file reads/writes, explicit transactions, and crash recovery in that order.
   **PARTIALLY IMPLEMENTED:** canonical extent records bind an exact file and
   metadata generation to a bounded logical range, either a physical data range
   with a content digest or an explicit hole. A fixed-capacity map requires
   ordered gap-free coverage of the rounded file length, bounds data ranges to
   the volume, excludes the volume header and both superblocks, rejects
   intra-file physical overlap, and returns bounded logical lookup results.
   Reserved future kinds are rejected rather than treated as compression,
   encryption, or sharing. The COW publication planner then requires an exact
   successor generation, inactive superblock target, nonoverlapping new ranges,
   active-range preservation, staged-image digest verification, metadata flush,
   atomic superblock replacement, and final flush in that order. Prepublication
   failure is clean rejection; replacement or later failure is fail-stop.
   Concrete block-backend integration, allocation ownership across files, a
   complete COW tree, and every later operation in this item remain pending.
   Directory lookup/enumeration/create/rename/remove and atomic cross-directory
   file moves are now implemented over fixed-capacity state. Every operation
   requires the exact directory object and operation-specific right; create
   allocates a service-owned stable ID and returns object-bound authority, while
   rename/move preserve identity and open capabilities. All failure-prone checks
   precede mutation. Cross-directory directory moves now require a bounded
   ancestry proof loaded through one immutable selected-generation backend. The
   proof binds the exact destination generation, reaches the selected root, and
   rejects the moved directory anywhere in that chain, repeated ancestors,
   broken links, stale state, backend failure, and capacity exhaustion. It also
   requires the moved directory's exact generation and current source-parent
   link. The proof retains the exact bounded source and destination paths to the
   root, including their independently checked starting generations.
   A fixed-capacity closure planner now merges both paths with the moved object,
   deduplicates shared ancestors, rejects insufficient output capacity, and
   orders children before parents with the root last. A duplicate ancestor at
   inconsistent depths or generations fails closed. Every closure entry binds
   the exact canonical generation loaded by the proof, preventing stale
   ancestor substitution. A bounded immutable-state backend now loads every
   exact predecessor and constructs the complete successor closure. It changes
   the moved directory's parent, compacts source removal, inserts the moved
   successor generation at the destination, advances every affected directory
   exactly once, and rewrites exact child-generation links through shared
   ancestors to the root. Complete-plan staging now preflights all metadata and
   entry ranges for volume bounds, exact entry-image size, and pairwise
   disjointness before writing; it stages every successor child-before-parent
   and can admit every prepared directory and image to one new transaction. A
   focused publication helper now requires the allocation successor to own each
   exact new directory range with the correct object, generation, and kind,
   includes all directory and allocation participants/images in one COW plan,
   and atomically consumes the directory receipt set before exposing successors.
   This remains in-memory simulation: concrete block integration, power-loss
   evidence, and full recovery validation are pending. A canonical COW
   object-ID allocator image now persists its volume, generation, exact next ID
   or exhaustion, pointer, digest, and zero padding. Reservation leaves active
   state unchanged, stages and flushes one successor, participates as a distinct
   volume transaction resource, and activates once from an exact receipt.
   The prepared allocator successor now requires an exact allocation record
   with a distinct allocator-metadata purpose, root lifetime anchor, allocator
   generation, and pointer range. This record is accounting, not authority.
   Reachable recovery now requires exactly one canonical root-anchored allocator
   image at the selected generation and rejects missing, duplicate, stale,
   corrupt, substituted, or reachable-ID-reusing state. Authenticated rollback
   resistance and physical durability remain pending, so directory operations
   are not yet proven crash-safe. An inactive
   authority-slot reservation now closes the create activation race: it consumes
   bounded capacity without authorizing access, rejects guessed handles,
   activates once, and advances its generation when canceled. Prepared-create
   orchestration is implemented as described below. Canonical initial child staging now supports
   both admitted kinds: an empty file has generation-1 file metadata plus an
   empty extent image, while an empty directory has generation-1 directory
   metadata plus an empty entry image and exact parent. Disjoint layouts are
   checked before I/O and each child participates as an explicit typed
   `0 -> 1` creation. A general bounded mutation proof now binds the exact
   target-to-root path. Create successor construction reloads all predecessors,
   inserts the child at the target, advances every directory once, and
   propagates exact child generations to the root. The complete directory
   closure now passes the same preflight/staging path as moves and is admitted
   child-before-parent to one bounded directory transaction. Receipt handling
   can now atomically preflight and consume the variable directory closure with
   fixed create participants, rejecting missing or cross-group duplicates
   without partial consumption. The bounded prepared-create coordinator now
   binds the exact allocated ID, child kind, inactive authority reservation,
   directory closure, initial child images, allocator successor, and allocation
   successor. It admits all four resource classes to one transaction, requires
   exact purpose-specific allocation ownership, builds one COW-root plan, and
   exposes successors plus the new handle only after atomic receipt consumption
   and authority activation. Empty-file and empty-directory creates are covered
   end to end in the in-memory model. Directory child metadata retains its exact
   parent; the coordinator requires it to equal the unique inserting directory
   successor and preserves it in committed state. A deterministic create
   durability simulation materializes and verifies all staged bytes, fails at
   every publication event, and runs complete reachable recovery. Only the old
   graph or fully valid new graph is selected, and authority activates only from
   a successful exact receipt. When fail-stop recovery selects the durable new
   graph, the in-memory model cancels the stale reservation and can reopen the
   child only from an exact surviving parent handle with the separate
   `OPEN_CHILD` right. The name remains non-authorizing, requested rights must
   match the child kind, and the new handle is a revocable descendant. Reboot-
   time capability reconstruction, a block service/device implementation, and
   physical power-loss evidence remain pending. A bounded exact-block metadata
   adapter now supplies canonical padded staging, complete digest readback,
   ordered flushes, inactive-superblock-only atomic replacement, fail-stop
   session poisoning, and exact immutable recovery reads. This is a tested
   service-boundary adapter, not physical-device durability evidence. Exact-
   block file reads now verify a complete extent before copying any requested
   subrange. A bounded write session reconstructs every successor data block
   from the exact verified predecessor plus holes and patch bytes, independently
   rejects reserved, active, and overlapping physical ranges, verifies complete
   staged extents and the complete logical-file digest, and flushes once before
   metadata publication. A fixed-capacity block-service core now registers
   non-authorizing device identities and grants principal-bound generational
   sessions with separately attenuable read, write, flush, and atomic-
   replacement rights. Derived sessions preserve device identity and can only
   reduce rights; parent revocation is transitive; device removal retires all
   sessions; and malformed, unauthorized, stale, or wrong-owner requests fail
   before the backend. A scoped client runs the exact-block volume adapter
   through this service. A canonical v1 control codec now provides fixed bounded
   requests/responses with no wire principal or raw address. Read/write requires
   one separately transferred buffer capability; atomic replacement alone
   carries its fixed record inline. Dispatch binds the authenticated sender,
   exact buffer shape, and strictly increasing request ID to the current session
   generation; replay fails before the backend, while uncertain mutation
   failures poison that generation. Each decoded operation now declares whether
   the service reads, writes, or uses no bulk buffer. Kernel IPC can validate
   zero capabilities or exactly one live receiver capability with the exact
   required nonzero rights; over-privileged, insufficient, missing, multiple,
   stale, and revoked transfers fail before object identity is returned. The
   same gate now resolves one exact shared binding and revalidates object,
   VM/task, mapping generation, access mode, host range, writability, and
   non-executable state before returning only an opaque host resource handle.
   Generic bounded reads and writes repeat those checks at every use, reject
   empty/overflowing ranges and read-only writes before backend access, expose
   no address, and preserve backend errors. The storage-service transport now
   composes decoded kernel messages, exact selected bindings, bounded erased
   scratch, replay/poison admission, and the block dispatcher outside the
   privileged kernel. It admits before touching bulk bytes, so denied, replayed,
   poisoned, revoked, malformed, or wrongly shaped requests reach no block I/O.
   A bounded service-side loop now receives one exact 320-byte request and zero
   or one transferred capability, performs replay/session admission before any
   shared-buffer or device I/O, invokes only capability-selected shared-buffer
   operations, dispatches the device request, sends one canonical response, and
   erases request, capability, scratch, and response storage on every return.
   Copy uncertainty consumes the admitted request ID, so retry cannot duplicate
   a mutation. Its unsafe syscall contract forbids manufacturing sender identity,
   capability tokens, mappings, or reply peers. The UEFI service image compiles
   a concrete adapter for receive/send operations 5/4 and shared-buffer
   operations 7/8 with launch-bound endpoint and reply task. A focused signed
   KVM/WHP probe now instantiates the loop as a separately provisioned hosted
   service task against a volatile one-page in-image backend. A hosted or
   physical device backend plus physical durability evidence remain pending.
   The syscall decoder now admits capability-selected shared-buffer reads and
   writes with implicit exact access modes, nonempty transfers capped at 1 MiB,
   checked shared offsets, complete canonical user ranges, and zero reserved
   registers. A generic executor now composes the current task capability space,
   exact selected binding, direction-validated user copy, opaque resource I/O,
   and fully erased caller scratch. It revalidates immediately before resource
   use and preserves user/resource backend errors. The kernel-image composition
   returns no handle or address. The x86-64 active-page copy adapter now walks
   every live user leaf under the expected current CR3, issues one exact task/
   range/direction ticket, consumes it once, and cancels it on later executor
   failure. A fixed-capacity opaque-resource table now owns monotonically issued
   handles, rejects live aliases and stale handles, bounds I/O before backend
   access, and integrates with final-reference retirement. Its direct-memory
   adapter is confined to an unsafe supervisor boundary. Cleanup now accepts a
   minimal native-mapping revoker instead of requiring full VMM authority. The
   active x86-64 service adapter removes only an exact expected CR3/mapping and
   invalidates local translations, enabling task retirement to precede reuse.
   KVM and WHP now accept kernel-side removal only after a complete read-only
   absent-leaf verification, then mark precisely that service slot eligible for
   re-arm; live leaves, invalid slots, and repeated observation fail closed.
   Backend-neutral policy is preserved: KVM and WHP now expose matching
   per-service resource-page lifecycles distinct from the common two-party
   diagnostic page. Admission rejects common-page or sibling virtual/physical
   aliases, maps only one service root, and zeroes backing before generation
   re-arm. KVM/WHP runners attach the distinct receiver page and couple host
   observation, zeroed restore, and final revocation to the existing service
   lifecycle. The kernel image now provisions separate exact receiver-only read
   and read/write capabilities plus binding/resource state, executes bounded
   shared-buffer syscalls through validated
   active user copy, and retires the exact active leaf, binding, and final opaque
   handle before host re-arm. Fresh one-time signed KVM and WHP probes check
   zero-before-use and write/read behavior in both generations plus absent-leaf
   observation and zeroed re-arm. These are hosted controlled probes, not host-
   resistant isolation or physical-hardware evidence.
   Service-side binding selection is implemented: the exact transferred
   capability and kernel-known VM/task identity must select exactly one live
   binding of the required access, while missing, ambiguous, and stale
   candidates fail before backend use and request bytes supply no binding ID.
   Bounded file reads are now implemented. Exact file `READ` authority is
   checked before range details, immutable file state must match its extent-map
   object/generation/length, sparse holes return zeroes, and every physical data
   extent is completely SHA3-256-verified by the backend before its requested
   subrange is copied. Reads are capped at 1 MiB and erase partial output after
   any backend verification failure. Bounded file writes are now implemented as
   COW preparation plus publication. Exact `WRITE` and conditional `RESIZE`
   authority precede all state disclosure; the patch is capped at 1 MiB; the
   complete successor map and canonical `FileMetadata` must bind the same object,
   exact next generation, length, and extent count; and new data ranges cannot
   overlap active data or protected metadata. The backend stages and flushes
   complete digest-verified new extents before returning an unpublished state.
   That state commits only through a COW plan containing the internally derived
   exact full-range zero-padded file-metadata and canonical zero-padded
   extent-list digests, while the
   backend verifies the complete logical-file content digest before flush.
   Explicit fixed-capacity multi-file transactions are now implemented. Each
   admitted prepared write retains its exact object predecessor/successor while
   its derived metadata images are bound to one independent volume-publication
   generation. Duplicate objects or metadata ranges, capacity overflow, missing
   plan writes, empty transactions, and wrong publication generations fail
   before backend I/O. One COW root transition produces a receipt whose exact
   participants can each activate once. Directory/allocator participation,
   concrete block/allocation integration, and crash recovery remain pending.
   The bounded redundant-root recovery selector is now implemented: both exact
   superblock records are decoded and passed to a complete-graph validation
   contract; two usable candidates must be identical at one generation or
   adjacent generations, and only the newer is selected. A single usable
   candidate is explicitly reported as fallback. Proven-invalid candidates may
   be bypassed, but indeterminate backend failures abort instead of silently
   rolling back. The exact-block adapter exists, but a concrete block
   service/device, power-loss harness, repair, and
   authenticated anti-rollback state remain pending, so
   crash recovery is still only partially implemented.
   Canonical checksummed allocation records and their fixed-capacity global
   ownership index are now implemented as the next validator prerequisite.
   Records bind one exact object generation, range, and data/metadata kind; the
   index requires physical ordering, volume bounds, reserved-block exclusion,
   and cross-object nonoverlap. Exact extent and metadata ownership queries do
   not accept containment, wrong generations, or kind substitution. A canonical
   block-aligned allocation image now binds its exact volume and publication
   generation, fixed record width/count, complete-image SHA3-256 digest, and
   zero-filled unused capacity. Decoding rebuilds all ownership invariants.
   Concrete block persistence and allocation/free mutation remain pending.
   Allocation-image ranges now use a distinct ownership kind and can be checked
   against the selected root and publication generation. Canonical block-aligned
   extent-list images now bind file identity, object generation, logical length,
   record geometry, complete-image SHA3-256, and zero padding; decoding rebuilds
   the exact-coverage extent map. These remove serialized-list ambiguity for the
   bounded reachable-tree traversal below.
   Bounded reachable-tree traversal is now implemented over an immutable-
   generation metadata-read contract. Canonical directory-entry images bind the
   owning directory/generation and rebuild duplicate namespace checks. Recovery
   walks the root and every directory/file child, validates exact parent and
   generation links, checks purpose-specific metadata ownership, reconstructs
   extent maps, requires exact ownership for every data extent, rejects repeated
   object references and capacity overflow, and finally rejects any allocation
   record not claimed by the reachable graph. The volume-scoped object-ID
   allocator is now part of that mandatory graph: exactly one root-owned,
   candidate-generation, purpose-specific record must decode canonically, and
   a concrete next ID must exceed every reachable local object ID; exhausted
   state remains valid and non-allocating. The backend remains an emulated
   immutable image; physical block integration, interrupted-write/power-loss
   evidence, repair, and authenticated anti-rollback remain pending.
   The selector and traversal now compose into one recovery entry point. A
   typed variant preserves each candidate's validated file states separately
   until root selection and exposes only the selected graph's exact file
   objects, generations, lengths, and extent maps. Focused simulation verifies
   selected-file lookup and absence without treating this integrity result as
   authority or anti-rollback authentication. New stable-authority recovery
   entry points require the selected file and reject a selected volume/root
   generation that differs from the unsafe owner-approved admission before any
   read or proof consumption. Reconstructed authority retains that authenticated
   root provenance. The selected configuration validator derives its file
   generation from a second reachable selection and compares that selection's
   volume/root against the temporary authenticated authority before any file
   read. Lower-level mechanism APIs retain explicit trusted-caller contracts;
   the typed selected path closes the in-memory root/file substitution gate. A
   controlled
   interrupted-publication simulation presents a checksum-valid
   newer superblock whose allocation image remains bound to the prior generation:
   complete validation proves the newer candidate invalid and explicitly falls
   back to the adjacent valid root. A separate injected read failure during the
   newer validation aborts recovery rather than being treated as corruption or
   permission to roll back. This is deterministic in-memory fault injection,
   not physical power-loss or device durability evidence.
   A separate deterministic durability model now splits volatile and durable
   metadata/superblock state and crashes after every publication operation.
   Verification or metadata-flush failures recover the old generation. Atomic
   replacement and final-flush failures exercise both permitted device outcomes:
   either the old root or the new root whose metadata was already durable.
   Successful final flush always recovers the new root, and no partial metadata
   generation is selectable. Physical-device cache, torn-write, and power-cut
   testing remain pending.
   Bounded allocation/free successor planning is now implemented. It verifies
   the active allocation image's exact self-ownership, advances exactly one
   publication generation, automatically retires the prior allocation-image
   claim, rotates to a disjoint new image, applies exact frees and additions,
   sorts the complete successor index, and rebuilds every invariant. An added
   range cannot overlap any active allocation even when that allocation is freed
   in the same unpublished successor, preventing pre-commit reuse. The canonical
   successor image is now encoded into caller-bounded storage,
   hashed over its complete bytes, staged and durably flushed through a narrow
   unsafe backend contract, and returned only as a prepared update. Transactions
   model volume-allocation state as a resource distinct from directory/file
   objects, require the exact derived image in the publication plan, and return
   the successor only after its one-use receipt is consumed. Directory
   successors now encode and stage the exact canonical directory metadata and
   entry-list images, flush both through one narrow durability contract, bind
   both ranges to a directory transaction participant, and expose the immutable
   next object generation only after its one-use publication receipt is
   consumed. Persistent object-ID allocation, inactive authority reservation,
   complete in-memory prepared-create coupling, and deterministic interrupted-
   create publication recovery and surviving-parent post-fail-stop child
   reconciliation are implemented in memory. A canonical bounded durable-grant
   checkpoint foundation now reconstructs fresh storage handles only from an
   exact externally authenticated volume, selected root generation, monotonic
   epoch, nonzero handle-generation high-water mark, and complete checkpoint
   digest. It serializes no bearer handle,
   rejects hidden bytes, capacity mismatch, forward/cyclic lineage, object/kind
   substitution, and rights amplification, and atomically advances its volatile
   replay/generation guards only after the complete fresh table is built. The
   table exposes the next generation strictly above every slot for the
   following authenticated checkpoint, preventing stale pre-reboot token
   collision. The grant policy is explicit rather than an automatic snapshot
   of transient capabilities.
   The checkpoint is now staged as the complete content of an exact capability-
   authorized stable-file successor. File WRITE/RESIZE precedes encoding,
   metadata binds object, next generation, length, content digest, and extents,
   and activation requires the matching COW transaction's one-use receipt.
   Recovery reads only the exact file generation selected by authenticated
   reachable recovery through separate bootstrap READ authority, preserves I/O
   uncertainty, and erases policy bytes after parsing. A one-use proof issuer
   now accepts only canonical bytes matching an exact unsafe owner-approved
   admission across digest, volume, selected root, epoch, and handle generation;
   no other safe API can construct the proof. The recovery guard likewise
   requires an unsafe authenticated rollback-state token instead of caller-
   chosen counters. Stable recovery issues only after successful authorized
   I/O, so pre-acceptance I/O failure remains retryable, while duplicate issue
   fails closed. A canonical 64-byte accepted-state record and backend-neutral
   authenticated monotonic-store contract now bind the accepted epoch,
   handle-generation pair, exact volume, and selected root generation. Genesis
   is explicitly unbound; after first acceptance, cross-volume substitution and
   root regression fail closed. Integrated stable recovery releases no rebuilt
   authority table unless compare-and-store matches the entire prior canonical
   record before replacement; corrupt state, stale conflicts, and backend
   uncertainty fail closed.
   A backend-neutral two-slot authenticated journal now implements that store
   contract over an unsafe exact backend. Each 112-byte slot binds its journal
   sequence and complete 64-byte state with SHA3-256. The authenticated
   monotonic counter selects one parity slot and is the sole publication point:
   the inactive successor must be durably written and verified before one exact
   serialized counter advance. Tests inject every protocol boundary, including
   a committed-but-uncertain increment, and never search or silently select an
   older slot. Firmware integration, owner provisioning/recovery, and physical
   power-cut validation remain pending, so Phase 6 item 1 is not
   complete.
   Its UEFI provisioning-admission prerequisite is now implemented: one bounded
   parser recomputes SHA-256 TPM Names over complete NV public areas and admits
   only three distinct owner-configured indices with a shared exact nonzero
   policy digest, an exact 8-byte counter, two exact 112-byte ordinary slots,
   policy-only read/write/no-DA attributes, and full-slot writes. Hostile tests
   reject aliases, shortened or substituted policy, extra authority, wrong type
   or size, and forged Names. The verified layout now feeds a concrete
   `RecoveryJournalBackend`: bounded policy-session `NV_Read`, full-slot
   `NV_Write`, and `NV_Increment` commands consume fresh one-use authorization
   from an unsafe provider bound to exact Name, policy digest, and operation.
   Exact response framing is enforced, writes are read-verified, and increments
   recheck predecessor and successor. The pre-existing rollback helper's command
   code was corrected from `NV_Write` to the actual `NV_Increment`. A concrete
   provider now starts a fresh unsalted, unbound SHA-256 policy session from
   explicit nonzero caller entropy, executes one exact owner-configured
   `PolicyPCR` recipe, and permits only the requested next NV operation. The
   safe composition path admits the complete layout before constructing this
   provider; authorization must match one exact admitted index/Name/policy
   tuple, and both command handle fields must repeat that index. Hostile tests
   reject Name, index, authorization-handle, and NV-index substitution before
   the target NV command reaches the backend. Immediate nonce reuse fails
   closed, and mismatch or policy
   failure triggers
   best-effort cleanup. Ambiguous NV transport failure now also clears the
   pending authorization and best-effort flushes the satisfied TPM session
   while returning the original error. A safe constructor now composes this
   provider, the
   admitted layout, the TPM backend, and the authenticated journal; an end-to-
   end hosted test loads and atomically replaces journal state while rejecting
   layout-policy substitution. The loader now accepts an optional exact all-or-
   none development configuration for the three indices and PolicyPCR recipe,
   composes the real TCG2 transport with one firmware-RNG call per session, and
   authenticates the selected journal record before `ExitBootServices`.
   Partial configuration, malformed state, or firmware uncertainty aborts;
   temporary state is erased. Canonical epoch, handle generation, optional
   volume, and root generation now cross a separately flagged 40-byte handoff
   record and are revalidated by early-kernel decoding before any memory region
   is emitted. Tests prove this metadata can exist while artifact rollback
   evidence remains false. It creates no recovery token, capability, or
   authority table. Actual owner-policy provisioning/recovery, native UEFI-
   target linkage/execution, signed booted storage-service invocation, and
   physical testing remain pending. An isolated operation-13 adapter now decodes one exact
   capability and canonical output address, validates the current task's fixed
   writable range through a one-use directional ticket before revocation,
   erases kernel scratch, and makes post-revocation copy uncertainty terminal.
   The kernel-image service dispatcher now routes that operation before generic
   decoding, binds the active CR3 and current task, and creates the exact
   metadata-only capability/delivery only for the initial service generation
   when metadata is present. UEFI-target compile/lint and focused unit evidence
   exist; no signed invocation or native boot evidence exists. A storage-side
   one-use wrapper now binds the handed metadata to the
   independently authenticated state store: one exact load and one exact
   compare-and-store are permitted, with replay, field substitution, malformed
   state, or store uncertainty releasing nothing and erasing output. The full
   configuration recovery simulation uses this binding before owner-approved
   checkpoint proof, capability-authorized I/O, dependent validation, monotonic
   commit, and service registration release results. A kernel delivery object
   now additionally requires one exact task generation, object, and exact non-
   delegable `READ` capability, revokes before copy, and consumes metadata after
   success. Wrong-service, wrong-object, overbroad/stale capability, replay, and
   replacement-task tests expose no data. The full configuration simulation
   traverses this delivery object before authenticated-store binding.
   The signed block-service launch ABI now supplies the exact token as its
   seventh SysV argument; CPL3 operation 13 returns one canonical fixed record,
   which the service verifies and erases. Windows gnullvm passed 451 kernel, 5
   KVM-runner, and 7 WHP-runner release tests; scoped strict Clippy and both
   focused UEFI image checks passed. Fresh independently signed controlled WHP
   and KVM probes reached exact service cleanup after this invocation. These
   are unit, ABI-compilation, and hosted controlled-probe evidence, not native
   UEFI, TPM, persistence, reboot, rollback-resistance, or physical evidence.
   The signed service now applies `BootRecoveryAdmission` to the delivered
   record and a separately constructed controlled test record before
   readiness. It requires exact equality, proves replay rejection with zero
   output, and erases both copies. Fresh signed WHP/KVM probes passed this path;
   both platforms also passed all 116 storage tests. The controlled provider
   now also participates in the full dependent transaction in the configuration
   client: exact owner-approved checkpoint proof reconstructs one private
   attenuated file capability, configuration and restart policy are validated,
   and only the fixed epoch 8→9, handle generation 2→3, root generation 1→2
   successor releases results. Fresh signed WHP/KVM probes and 27 configuration
   tests on Windows and Linux passed. This proves hosted orchestration and exact
   volatile compare-and-store behavior only; a conforming authenticated,
   power-loss-atomic backend and physical evidence remain pending.
   Recorded verification on 2026-08-24: Windows gnullvm and Arch Linux/WSL2
   each pass all 447 kernel tests, all 20 `mrml-uefi` library tests, all 116
   storage tests, and all 27 configuration tests. Strict
   Windows Clippy and a hosted gnullvm loader check pass with `uefi-image`
   enabled; strict Linux crate-local Clippy also passes. The direct UEFI crypto
   dependency now disables its unused host-runtime default feature, so the
   optimized `x86_64-unknown-uefi` loader links successfully and strict target
   Clippy passes. Dependency inspection confirms `mrml-runtime` is absent from
   the firmware graph. A fresh QEMU/OVMF nested-KVM boot with pinned,
   independently signed artifacts produced `a1 a2 a3 a4 a5 a6 a7 a8 b1 b2 b3
   d0 d1 d2 d3 d4 df`, covering loader execution through kernel entry and the
   existing VMX-root probe. Building that ordinary signed service also exposed
   and fixed its feature-specific shared-buffer parameter names and confined
   recovery-only imports to the block-service feature. Recovery configuration
   was absent because no software TPM was available. This is controlled native
   UEFI execution, not provisioned TPM, recovery-journal execution, reboot,
   Secure Boot, bare-metal, or physical evidence.
   A generic consumed validation transaction now keeps that rebuilt table
   private while a dependent recovery validator uses one exact reconstructed
   file handle. The configuration adapter recovers only the selected file
   generation, rechecks configuration-root CONTROL and setting READ, binds the
   exact expected service policy, erases scratch, and releases neither result
   until compare-and-store succeeds. Validation failure does not consume the
   accepted monotonic state. This is unit/simulation composition rather than a
   live reboot path.
   Service registration now has an exact non-mutating slot/generation plan and
   consumed commit. Dependent validation can prepare that plan while authority
   remains private; after monotonic compare-and-store, a committed-authority
   wrapper and matching epoch are required to publish configuration, authority,
   and the running supervised service together. Stale-slot commit fails without
   mutation. A deterministic exact-block/block-service test covers this typed
   in-memory boot sequence, but no real reboot or persistent backend is claimed.
   A conforming TPM NV or equivalent power-loss-atomic backend remains pending.
   The platform owner-policy authenticator/UI and boot orchestration remain pending, so
   reboot-time capability reconstruction is still partial. A hosted/physical
   device backend and physical
   power-loss evidence remain pending. A focused signed KVM/WHP controlled
   probe now instantiates the bounded block-service loop in an isolated CPL3
   process against a volatile one-page in-image backend. A separate client has
   only delegable shared-buffer authority and verifies both responses, while
   the service verifies the written and returned bytes;
   the client and service then retire through the supervised cleanup path. The
   launchers require ordered client erasure, exact peer-death delivery, service
   mapping/resource erasure, and terminal proof that both slots have no task or
   pending cleanup. This does not establish device durability or physical
   isolation. The bounded block-service core and exact-block
   metadata publication/recovery and file-data adapters are implemented as
   described above.
4. Add snapshot objects and capability enforcement, then system-generation and
   authenticated update integration.
5. Add compatibility filesystem readers and optional advanced storage features
   only after measured need; they do not define native semantics.
6. Implement a network service returning bounded connection capabilities.
7. Add firewall/network-policy as defense in depth outside the kernel.
8. Add tool and local-inference services over control and bulk IPC.
9. Establish bounded structured audit foundations with explicit event purpose,
   retention, access, erasure/redaction, and content-minimization rules.

Security gate: services start with explicit least authority; paths, ports,
names, identity, and signatures do not grant ambient access; raw packet/device
access is separately privileged; service failure is contained. Filesystem names
and IDs never authorize, rename preserves object identity, transactions are
all-or-nothing, covered corruption is detected, inconsistent recovery fails
safely, and snapshots require authority without implying anti-rollback.

### Phase 2 virtual-device and service progression

The canonical cross-device plan and acceptance scenarios are in
[PARAVIRTUAL_DEVICES.md](PARAVIRTUAL_DEVICES.md). Dependency order is: common
lifecycle/transport; complete the MRML-native block transport; PCI attachment;
VirtIO-blk compatibility and QEMU differential testing; capability-native share
protocol; deterministic hostfs; VMM hostfs; optional VirtIO-fs compatibility;
virtual accessibility bus; Braille, switch/alternative-input, and deterministic
speech/audio emulators; networking; broader input/graphics/audio; then physical
USB accessibility adapters. Phase 2 may build accessibility virtual hardware and
test harnesses, but connection to semantic accessibility waits for the Phase 3
Semantic Scene Graph and capability prerequisites.

The existing serial/console bring-up path remains available. Establish common
queue, lifecycle/reset, interrupt, PCI-transport separation, and differential
harnesses before broad device coverage. Compatibility emulation appears only
where required, and every applicable device behaves consistently under KVM and
WHP.

**PARTIALLY IMPLEMENTED:** the first MRML-specific virtual-block device core
defines canonical fixed requests/completions, disjoint bounded shared rings,
read/write plus negotiated flush, monotonic request IDs, bounded GPA/length
validation, generational in-flight tickets, explicit lifecycle transitions,
and reset/removal invalidation. The backend-neutral VMM copy bridge returns no
request until it publishes consumption and permanently poisons on uncertain
guest-memory I/O. A backend-neutral executor copies reads and writes through
erased bounded private scratch, issues flush only after admission, returns a
detail-free device error for a backend-guaranteed clean rejection, and fails the
device plus bridge after uncertain mutation. A complete one-request transaction
now preflights admission and completion-ring
capacity before consumption, distinguishes idle and backpressure, rejects a
consumed malformed request before backend access, executes once, and publishes
the bound completion. If completion publication becomes uncertain after possible
mutation, the device and bridge fail rather than retry. A production block
backend, QEMU comparison, and fuzzing remain pending. The bounded signed
PCI-MMIO write/read/flush/acknowledgement probe described below is complete.
This is not VirtIO-compatible. Completion publication now latches one coalesced
notification. Delivery uses the device-configured vector through the existing
allowlisted, exact-`SIGNAL`-capability VM interrupt boundary and acknowledges
the latch only after confirmed backend injection. Denial and uncertain
injection retain it; reset, removal, and failure invalidate it. This composition
is simulation-tested shared policy, not a concrete KVM/WHP device attachment.
An optimized 10,000-iteration in-process regression baseline measures the full
mock transaction-through-acknowledgement policy composition on Windows gnullvm
and Arch Linux/WSL2; it is not storage, hypervisor, or hardware-interrupt
latency evidence.
The MRML-specific block doorbell is now an exact 32-bit write-only scalar tuple
over the common deny-by-default I/O dispatcher. It rechecks port, width,
direction, and value before queue access and processes at most one request per
accepted disposition. The port and value carry no backend or interrupt
authority. A backend-neutral one-exit runner now composes backend execution,
exit accounting, common I/O dispatch, exact doorbell handling, one queue
transaction, and capability-authorized notification delivery. It delivers an
already pending notification before another vCPU entry and fails the VM on any
runner-stage error. Both prepared native guest types satisfy its memory
contract. Controlled signed KVM and WHP images now execute eight bounded write/
read cycles over a two-slot queue. Every cycle fills both slots before
retirement, drains both protected completions in order, reuses both slots for
reads, and compares two complete pages with distinct per-cycle patterns. Signed
read-only descriptor data supports exact interrupt entry and return. This is
live-verified on both hosted backends. The guest still lacks a general interrupt
framework and unbounded progress.
The same common runners now require a separately provisioned live block
capability for one exact backend object and reauthorize `READ`, `WRITE`, or
`FLUSH` for each matching operation. Focused tests prove attenuation,
wrong-object selection, and revocation fail before backend I/O, while backend
rejection-versus-uncertainty semantics remain unchanged. Fresh signed KVM and
WHP controlled probes exercised the common capability-selected path. A checked
backend start/count now translates guest-relative blocks, rejects empty,
overflowing, malformed, or cross-boundary regions before I/O, and must equal
the device's advertised block count before vCPU entry. Nonzero translation is
simulation-tested; hosted probes exercise a full two-block region. A production
backend and physical-device evidence remain pending, so the complete MRML-native
block gate remains partial.
Prepared KVM and WHP guests now implement the common virtual-block memory
contract and transactionally attach the validated request/completion ranges.
Native request memory is guest-writable, while completion memory rejects the
ordinary guest-write path and remains writable by the isolated device path.
Dedicated kernel-block launch builders now install the same directionality in
the initial guest page tables: request ranges are identity-mapped RW/NX and
completion ranges R/NX. Controlled live tests cover both backends, including
overlap rejection and KVM native-slot undercapacity. The signed probe now
exercises these mappings as the bounded write/read producer-consumer pair
through the common runners.

The backend-neutral completion bridge now owns its monotonic consumer position
instead of trusting a guest write into the read-only completion page. An exact
32-bit write/value acknowledgement at port `0x4d43` retires one published
completion only after confirmed interrupt delivery and updates the protected
header through the device path. Every scalar is rechecked before state or
memory access; empty, premature, wrong-queue, terminal, or uncertain accepted
acknowledgements fail closed. Signed KVM/WHP images now contain the matching
consumer and exercise 32 protected acknowledgements across repeated two-slot
reuse, with live controlled evidence on both backends.

The next reusable-driver prerequisite is now a canonical 128-byte active-device
configuration record. It is explicitly MRML-specific and binds generation,
geometry, supported/negotiated features, exact queue layout, vector, ports,
transfer bound, and wire sizes with zero reserved bytes. Only a fully active
device can produce it. A decoded copy must reconstruct the queue exactly and
match the current live device; reset makes the old generation stale. The record
carries no authority. A typed page binding now additionally requires one
page-aligned, queue-disjoint GPA and the exact configuration/queue pair. The KVM
and WHP block launch builders publish the fully zeroed page through their
host/device-only paths and identity-map it read-only/NX. Signed guests on both
KVM and WHP now discover this record in live controlled probes. PCI or another
transport remains pending.

The first reusable guest-driver state is now implemented as allocation-free
backend-neutral policy. Fresh discovery requires the canonical configuration
plus four exact zero queue counters. Nonzero reconstruction now requires a
canonical 192-byte live resume record containing the complete configuration,
four queue watermarks, and separate last-admitted and last-published request-ID
anchors. The active device and unpoisoned bridge capture it only from a stable
queue; uncertain reads poison the bridge. Reconstruction accepts exactly the
configured physical request slots, revalidates every outstanding canonical
request and geometry, requires strict ID order and both history anchors, and
rebuilds pending ownership without republishing or retrying work. The record is
data, not authority. Request preparation
is non-mutating, exact publication tickets fill at most the configured queue
capacity, and completion acceptance binds the next published counter and slot,
generation, request ID, status, and expected byte count before returning an
acknowledgement. Completion preparation changes no state, allowing the exact
protected acknowledgement to be published before a fresh ticket commits
retirement. Stale ticket replay cannot free capacity. Slots cannot be reused
before exact in-order retirement, and reset/removal invalidates every
outstanding descendant. Geometry, buffer
arithmetic, flush features, replay, stale tickets, terminal reset/removal, and
exhaustion fail closed. Reset rediscovery now records the exact terminal cause,
accepts only a canonical exact-successor generation with four zero queue
counters, and leaves all state unchanged on rejection. Removal and request-ID
exhaustion cannot be rediscovered. One-time-signed compiled KVM and WHP images
now discover and execute this common driver across eight bounded cycles. Each
cycle publishes two disjoint writes before either completion retires, drains
both in order, and reuses both slots for corresponding reads against a volatile
two-page backend. The exact probe budget covers 32 requests and their 32
protected acknowledgements; counters advance beyond queue capacity while the
two physical slots repeatedly wrap. Live presentation of the resume record is
now implemented with KVM/WHP parity: one typed page must bind the exact
configuration page and queue, remain disjoint from every launch range, is
initialized and republished as a complete zero-padded canonical image through
the device path, and is guest-read-only/NX. The host now selects the recovery
cut immediately after common processing has consumed requests 13 and 14 and
published their protected completions but before another guest entry. The
guest contains no checkpoint port, and the launchers contain no checkpoint I/O
permission or exit. The host requires producer/consumed/published watermarks 14
and consumer watermark 12, then publishes nonzero state while execution remains
stopped. The replacement guest reconstructs two pending ownership records from
the complete page plus both request slots, retires the already-published completions in order,
and continues through operation 32. Canonical capture/publication now requires
an explicit device `Suspended` state in addition to the stopped vCPU. Suspension
admits no device in-flight slot or pending interrupt, and the device resumes
only after publication and all state checks succeed. Fresh signed KVM execution
covers this checkpoint. WHP source parity is present, but this increment has no
new WHP build or execution evidence because the available Windows shell lacked
its linker. KVM now has controlled native VM-replacement evidence: the runner
never resumes the stopped VM, prepares a new VM from the same verified
executable and canonical handoff, copies canonical request, completion, and
resume pages while the device remains suspended, requires fresh zeroed payload
memory, then resumes the retained device only after complete restoration. Each
queue page contains only its two required counters and two live slots; all
other bytes are zero. The fresh kernel
entry accepts only all-zero launch state or the exact `14/14/14/12` checkpoint
and matching ID anchors before reconstructing. The device, bridge, volatile
backend, and common policy VM identity are retained, so this is orderly
execution replacement, not crash recovery. The WHP runner now has the same
consuming partition replacement and canonical three-page restoration source path;
native Windows `check --tests` and strict Clippy pass with CUDA excluded. A
linked/live WHP replacement run remains pending because the available shell
lacks `link.exe`. Both runners now consume ownership of the old VM and destroy
it immediately after the bounded snapshot, before replacement preparation.
Failure therefore cannot fall back to old execution and leaves the retained
device suspended. Fresh signed KVM execution covers this stronger ordering;
WHP remains compile/lint-only. Both runners now delegate canonical capture and
restoration to one allocation-free common-kernel restart image. It validates
the published page against the suspended device/bridge state, copies only live
request/history and unretired completion slots, rejects mismatched completion
identity/status/length, and preflights zero queue extents plus the exact fresh
configuration-bound resume page before any restoration write. Directional
slot/counter publication and poison-on-uncertainty are common rather than
launcher policy. Restoration consumes the non-clonable image once and
volatile-erases its encoded queue/resume storage on every return; the exact
capture type cannot call restoration. Both hosted runners first consume and
destroy the old native VM, then cross one documented unsafe boundary that
converts the image into a distinct linear lost-execution witness. Only that
type is accepted by restoration; it is not authenticated evidence or resume
authority. The exact
policy budget is reduced to 64 common block exits. This is deterministic
host-forced execution loss, not asynchronous/unplanned crash capture.
Asynchronous crash orchestration, backend-in-flight recovery, and unbounded
progress remain pending. The MRML-native PCI-MMIO probe now consumes and
destroys its old VM after five fully retired operations, restores the canonical
idle queue/resume image into a fresh MMIO-trap guest while the retained device
and attachment remain suspended, and resumes only after exact reconstruction.
Transport substitution is rejected before restoration. This is orderly
replacement, not asynchronous crash recovery.

Both scalar transport directions now cross one common backend-neutral
transaction runner. Each invocation delivers any pending completion interrupt
before entry, accounts exactly one native exit, accepts only the canonical
doorbell or protected acknowledgement tuple, performs its exact queue
transition, and delivers a newly latched interrupt before returning. Every
other exit or stage failure fails the VM. KVM and WHP launchers no longer
choose separate doorbell and acknowledgement runner functions. The caller
still supplies an exact finite exit budget and invokes one transaction at a
time; a general scheduler-integrated loop remains pending.

The transport-separation prerequisite is explicit: each virtual-block device
owns one transport identity, and the canonical configuration, guest queue
publisher, protected acknowledgement path, device handlers, and common host
runner all derive their mechanics from that same binding. Implemented
identities are deliberately named `MrmlSpecificScalarIo` and
`MrmlSpecificPciMmio`; their record encodings remain canonical and carry no
authority. The PCI-MMIO slice covers one test-only function, exact BAR
assignment/memory enable, and a bounded two-write/two-read/one-flush queue cycle
with protected acknowledgement. It does not implement production native
interrupt routing, MSI/MSI-X, DMA, VirtIO compatibility, or a QEMU differential harness.
Those gates remain before broader virtual-device coverage.
The KVM and WHP launchers now also derive their complete two-rule VM I/O
allowlist transactionally from that exact transport binding and construct the
device with the same value. Admission no longer repeats independent global
port constants. Exact scalar writes are admitted; reads, wrong widths, and
unrelated ports remain denied. This closes scalar admission-policy separation,
not the pending PCI or QEMU gates.

The first unattached PCI configuration-state core is now implemented. It
models one exact 64-byte Type-0 header with caller-supplied identity data and
one bounded 32-bit non-prefetchable memory BAR. It implements aligned 1/2/4-
byte reads, exact all-ones BAR size probing, masked BAR assignment, and
transactional writes to only the command register or BAR. Bus mastering and
all unsupported command bits are rejected without mutation; BAR assignment is
data and does not map host memory. Memory decode now requires an assigned BAR,
relocation is rejected while decode is active, and reset advances an exact
generation before clearing command, BAR, and probe state. Old MMIO-window views
then fail as stale; generation exhaustion preserves the live state. This is
local unattached reset coupling only, not native mapping or interrupt cleanup.
This is not yet a PCI-presented block device or a compatibility claim. Assigned
MRML vendor/device IDs, capabilities, MSI/MSI-X, additional BARs, VMM
configuration-space routing, attached revoke-before-reset composition, guest-
driver discovery, and QEMU differential testing remain dependency gates.
A backend-neutral fixed-capacity router now covers the policy half of
configuration-space routing. It validates exact segment/BDF locations, rejects
non-reset attachment state, duplicates, and absent functions, routes bounded
reads/writes to one function, uses generational host-side attachment IDs for
reset/removal, forbids detach while memory decode is active, and preserves live
state on capacity or generation exhaustion. This does not decode KVM/WHP exits,
define an ECAM or legacy
configuration transport, assign MRML identity, attach block, map a BAR, or
authorize interrupts/DMA. Those integrations remain the next gates.
The canonical shared Configuration Mechanism #1 transport contract is now also
implemented. It owns the `0xCF8` selector, derives the complete eight-rule
`0xCF8`/`0xCFC` scalar-I/O policy, validates reserved bits and exact byte/word/
dword data-port geometry, decodes segment-zero BDF/register state, and composes
present accesses with the router. Disabled or absent reads return only the
appropriate all-ones width and writes are ignored. KVM/WHP runner integration,
guest register completion, one test-only attached block function, and bounded
trapped BAR block notifications are now implemented. Production identity,
native PCI interrupt routing, MSI/MSI-X, DMA, and QEMU comparison remain
pending.
A common one-transaction PCI runner now composes the existing VM exit budget and
deny-by-default dispatcher with Mechanism #1 and the router. Read outcomes cross
a narrow backend completion contract carrying exact vCPU, port, width, and
bounded value; writes never invoke it. Transport failure, completion uncertainty,
or any other exit fails the VM before another entry. Mock-backend tests cover
present and absent reads plus failure. Both native implementations now satisfy
that contract. KVM completely re-decodes the mapped run page, requires exact
vCPU/port/width/count/data-offset identity, and writes only the selected bytes.
WHP retains the exact per-vCPU port/width/instruction-length tuple and installs
the architectural-width RAX result with a checked next RIP in one register-set
operation. Both deny duplicate or mismatched completion and block vCPU re-entry
while a read remains pending. A freshly signed controlled kernel first composed
the common runner with both native backends for an absent BDF and exact all-ones
completion. It now discovers one exact test-only block attachment at BDF
`00:04.0`, reading fixed vendor/device and mass-storage-class dwords before proof
continuation on KVM and WHP. The same signed probe now assigns and enables one
exact BAR, publishes two writes, retires their protected completions, reuses
both slots for reads, retires those completions, submits one explicitly
negotiated flush, retires its zero-length completion, and verifies both payload
pages on both backends. Production native PCI interrupt routing, MSI/MSI-X, DMA,
production identity, durable block I/O, and QEMU comparison remain pending.
Attached reset/removal ordering is now enforced at the router boundary.
`VirtualPciFunctionRevoker` is an unsafe exact-generation contract whose success
must retire every native mapping, interrupt, DMA binding, queue, cached decision,
device state, and derived handle. Router reset and detach preflight identity,
generation capacity, decode state, and assigned MMIO-window state before
invoking it, including residual window identity after decode is disabled;
revocation failure preserves configuration, while success precedes reset or
removal mutation. Focused tests cover exact cleanup identity, stale-window
invalidation, quarantine-preserving reset/detach failures, independent success,
and no cleanup call after preflight failure. Controlled KVM/WHP destroyed-VM
revokers now retire the exact native execution container, preflight the complete
cleanup record and both capabilities, revoke backend and interrupt authority,
reset the block attachment, and then allow PCI generation advance with BAR/
decode clear. The controlled KVM/WHP path exact-matches, removes, and verifies
absence of its non-global first-level BAR trap leaf while the sole vCPU is
stopped. It publishes a no-reentry quarantine before mutation,
rejects pending emulation, a changed root, PCID, or a multi-vCPU backend,
rewrites the exact CR3 through KVM/WHP, and reads it back before permitting
later entry. Failure leaves the quarantine permanent. Controlled signed probes
cover successful withdrawal on both backends. A fresh one-use-signed artifact
emits a second exact port/width/value proof after that withdrawal; KVM and WHP
both resume the same guest and return the marker before cleanup.
SMP/asynchronous shootdown, hotplug, and production native revokers remain
pending.
Memory-decode command writes are now transactionally coupled to native BAR
state. `VirtualPciMemoryMapper` is an unsafe exact-generation boundary: enable
must map the complete assigned window before the command bit publishes, while
disable must make that exact mapping unusable before the bit clears. Rejected or
uncertain native results preserve configuration; uncertainty requires VM
quarantine/failure. Default router/transport/common-runner entry points use a
deny mapper, and the explicit mapper-aware runner is required for a present
function. Tests cover exact mapping/unmapping identity, deny-by-default enable,
failure preservation, independent successful transitions, mapper-free BAR
assignment, and common-runner VM failure on mapping rejection. A backend-aware
variant now passes the same stopped backend that produced the configuration
exit into the exact mapper without aliasing. The controlled KVM/WHP adapters
begin with the BAR leaf absent, install and verify it plus reload/read back CR3
before decode publishes, reconstruct it for replacement, and coherently
withdraw it before decode clears. Wrong-leaf and replay attempts fail, and the
signed guest proves traffic plus post-withdrawal continuation on both backends.
This completes the sole-vCPU install/withdraw mapper prerequisite;
SMP/asynchronous shootdown and production reset/remove revokers remain pending.
The first authorized concrete-function policy slice now binds one routed PCI
generation to an active MRML-native block generation, exact queue/vector, and
capability-selected backend region. A block-specific mapper records only a
confirmed exact BAR window; reset/removal composes external resource cleanup
before both block and PCI lifecycle mutation. Focused hostile tests cover stale
generations, class/geometry substitution, poisoned queues, mapping rejection and
uncertainty, cleanup failure, reset, and detach. This is host-side unit/
simulation policy. Signed guest-visible identity/class discovery, guest BAR
assignment, memory-decode enable, five trapped MMIO block notifications,
protected MMIO acknowledgements, exact native write retirement, and complete
payload comparison now pass on KVM and WHP. The fifth request is an explicitly
negotiated, independently `FLUSH`-authorized backend flush. Production native
PCI interrupt routing, MSI/MSI-X, DMA, durable block I/O, QEMU comparison, and a production
PCI identity remain pending, so the broader PCI attachment/transport gate is
still partial.
The `BLOCK` reset acceptance slice now has host-side simulation and controlled
KVM/WHP execution for a reset
with one published-but-unacknowledged completion and one request still in
flight. Reactivation requires a fresh queue bridge and attachment at block and
PCI generation 2; across the combined simulation and hosted evidence, the old
MMIO acknowledgement, BAR window, attachment, completion ticket, and
generation-1 request all fail before successor mutation,
and a fresh generation-2 request remains admissible. The controlled hosted
probe stages the two pending ownership classes in native guest memory after the
signed workload, destroys that VM/partition, revokes the old block and interrupt
capabilities, performs the exact common reset, rejects both stale identities,
and issues fresh successor capabilities before admission. Resumable dynamic
native unmapping/hotplug, durable backend recovery, and QEMU differential evidence
remain pending, so this does not complete `BLOCK` acceptance.
Legacy completion notification now also revalidates the exact live router
generation, BAR, memory-decode, and interrupt-disable state. The first signed
completion is retained while masked, the guest explicitly unmasks the same
function, and the next common entry performs the existing independently
capability-authorized injection. This remains test-only legacy delivery, not a
production native interrupt adapter.

The common driver now has an unsafe backend-neutral guest queue-transport
boundary. It derives every header and slot address from the canonical
configuration, publishes a complete request before its producer, and rings only
the exact configured doorbell after publication. It acquires the completion
watermark before copying the exact next consumer slot and uses the exact
protected acknowledgement tuple to publish only that one consumer before
committing retirement. A watermark ahead of the consumer does not skip entries.
A reported transport failure guarantees no counter or notification became
visible and leaves driver state unchanged; stale tickets fail before transport
access. The unsafe contract requires exact non-redirected access,
release/acquire ordering, exact port/value tuples, and unchanged counters on
error. A concrete x86_64 identity-mapped implementation now uses exact volatile
copies, aligned volatile counters, release/acquire fences, exact 32-bit port
output, and fail-stop acknowledgement observation. Its controlled port model is
unit/simulation evidence. Live signed compiled KVM and WHP probes now execute the
privileged native `OUT` path, shared host runner, exact capability-authorized
interrupt, protected acknowledgement, and complete two-page write/read comparison.
This does not verify native boot, durability, PCI, or physical hardware.

Networking proceeds from capability-bound network objects and a basic native
service to packet buffers/rings, a basic backend path, firewall integration,
then a VirtIO-net-compatible device and QEMU comparison. Multiqueue, offloads,
and tuning follow baseline correctness and measurement.

Audio proceeds from capability-bound device/playback/capture/session objects and
an explicit timing/format model to userspace mixing, basic output, capture,
trusted capture indication, trusted accessibility speech output, local trusted
speech capture/control, then VirtIO-sound or an MRML virtual-audio device
connected to the host service. Application playback/capture, accessibility
speech, VM audio, and notifications retain separate capabilities and privacy
boundaries. Latency/jitter measurement precedes advanced routing and
multi-device work.

USB proceeds from device/interface/endpoint capabilities and a host-controller
abstraction through enumeration and bounded descriptor parsing, then HID and
storage classes, refreshable Braille and accessibility HID protocols, other
classes as needed, per-interface delegation, VM
passthrough lifecycle, and physical IOMMU/DMA validation. Legacy controller
emulation comes only with a demonstrated compatibility need.

Security gate: device creation grants no implicit backend authority; descriptors
and guest memory are bounded and directional; stale queue state dies on reset;
host policy cannot be bypassed by a guest; capture and playback, composite USB
interfaces, ordinary input and secure attention, and paravirtualization versus
passthrough remain distinct authorities.

## Phase 3 — Safe applications and trusted GUI foundation

The GPU dependency lane is canonical in
[gpu/GPU_ARCHITECTURE.md](gpu/GPU_ARCHITECTURE.md): native semantic/object and
capability specification; safe command/IR and GPU-0 reference transfer;
VirtualGPU control, accounting, timelines, compute, rendering/presentation,
reset, fuzzing, and conformance; Linux oracle tooling; then physical Blackwell
transfer/compute/matrix/desktop/VirtualGPU host and later advanced features, AMD,
Intel, optimized libraries, and compatibility expansion. VirtualGPU is GPU
priority 1 and Blackwell is priority 2; compositor/application prerequisites
remain in their existing order. API simplicity precedes feature growth: stable
objects stay separate from evolving AI/compiler IR; Safe, Advanced, and Raw
profiles remain distinct; VirtualGPU compactness/fuzzability tests portable
additions; Blackwell-driven expansion requires portable justification and
performance evidence.

Before trusted consent UI, establish the application-facing foundation:

1. Specify bounded versioned service protocols and a safe SDK without freezing
   Rust's internal ABI or creating a general public C/C++ ABI.
2. Define transitive memory-safe application admission and dependency/FFI rules.
3. Project the same capability-preserving API into application microVMs.
4. Define logical display coordinates and output identities for fractional
   per-monitor HiDPI.
5. Define capability-bound graphics objects, keeping surfaces, buffers, render
   devices, display outputs, command queues, and fences distinct.
6. Implement the trusted compositor boundary, non-spoofable domain identity,
   surface commit protocol, and backend-neutral compositor/display interface.
7. Implement software composition, GOP presentation, and damage tracking in
   that order.
8. Add bounded asynchronous fence semantics.
9. Define the VGPU resource protocol and shared command/completion transport,
   then implement accelerated VGPU rendering.
10. Support live GOP-to-accelerated takeover and accelerated-failure-to-GOP
   recovery; native physical GPU backends come later.
11. Implement a bounded, generational semantic scene graph with authorized
   incremental subscriptions and resynchronization.
12. Add deterministic focus order and keyboard semantic actions, then a bounded
    accessibility semantic API with uniform secret redaction.
    Keep that documented API available to third-party assistive tools under the
    same capability and admission rules.
13. Add basic trusted local speech output and a Braille representation/backend;
    simulated evidence does not establish physical-device compatibility.
14. Add Braille input/routing and local deterministic speech input/control over
    semantic actions, preserving distinct microphone and device authorities.
15. Benchmark scene updates, input-to-action latency, composition, damage,
    synchronization, scaling, takeover, and recovery.

The graphics device may add VirtIO-GPU compatibility for guest display and 3D
interoperability, with QEMU differential tests. It must preserve the existing
MRML-specific CUDA compute protocol as a separate capability surface carrying
signed kernel admission, authenticated queues, quotas, watchdog/reset, and CPU
fallback. Display compatibility must not regress CUDA capability or performance.

Security gate: ordinary native apps cannot introduce unsafe native code or
ambient authority; VM transport cannot widen capabilities; applications cannot
spoof trusted surfaces; stale semantic identities/deltas cannot target reused
objects; surface/buffer ownership cannot become scanout or cross-process access;
backend changes preserve validation; semantic inspection and raw input remain
separate authority; trusted prompts have nonvisual semantics; accessibility
cannot bypass secret redaction or grant universal observation/input authority.

## Phase 4 — Browser and AI application control

The canonical dependency order and acceptance gates are in
[BROWSER_SEMANTICS.md](BROWSER_SEMANTICS.md): Semantic Scene Graph; browser tree;
focus/keyboard; Braille/speech; trusted chrome; bounded text-only AI; no-JIT
JavaScript and dynamic semantics; browser-only no-JIT WebAssembly and semantic
bridge; scoped media/multimodal inspection; monitor-off and blind-user testing;
then semantic ABI stabilization. Earlier script execution never establishes
accessibility completeness.

1. Build the browser as isolated services with no JIT and strict W^X.
2. Keep WebAssembly inside the browser boundary and mediate every sensitive API
   per origin and capability.
3. Expose a sanitized semantic document tree with deliberate bounded actions.
4. Project that same tree to browser accessibility and keyboard operation.
5. Represent visual web/media content as lazy capability-controlled objects
   carrying captions, transcripts, audio descriptions, chapters, language, and
   timing where available.
6. Add authenticated application-VM semantic projection, then bounded bridges
   from compatibility-guest accessibility APIs; guest content cannot assert
   trusted host identity.
7. Add cohort-normalized fingerprint surfaces and regression testing against
   independent fingerprinting suites.
8. Add local/remote AI disclosure controls, incremental graph transport, and
   explicit visual-inspection requests.
9. Restrict remote AI to capability-scoped semantic views and preserve useful
   operation with no AI, local AI, or interchangeable remote providers.
10. Add browser anti-tracking tests and an owner-controlled, selective-
    attestation policy that avoids stable ordinary-service device identifiers.

Security gate: web content cannot reach native admission, arbitrary JavaScript
control, browser memory/debug authority, raw devices, or W+X execution; AI does
not receive secrets, screenshots, media, HID injection, or global GUI control
without the exact capability. Fingerprint claims require empirical evidence.

Accessibility verification proceeds alongside Phases 3 and 4 rather than after
the GUI is complete. Add semantic completeness, focus ordering, keyboard-only,
Braille/speech representation, redaction, trusted-prompt, VM/browser projection,
HiDPI/backend-independence, and capability tests. Dogfood core workflows without
pointer or framebuffer inspection. Add physical Braille and alternative-device
tests when hardware is available and label simulation separately. Extend
accessible semantics into boot errors, rollback, login, recovery, and repair as
early as service/hardware prerequisites permit without claiming unfinished
early-boot support.

### Accessibility dependency lane

Within and across Phases 3 and 4, preserve this dependency order:

1. prove Semantic Scene Graph correctness and incremental synchronization;
2. add deterministic focus and keyboard semantic actions;
3. define a bounded accessibility semantic API with shared redaction;
4. add automated semantic completeness, action, and parity tests;
5. add trusted local speech output;
6. add the transport-neutral 40-cell-baseline Braille line presentation;
7. add bounded interoperable physical Braille transport;
8. add Braille routing and input through semantic actions;
9. operate trusted prompts through Braille and speech;
10. integrate browser structured accessibility;
11. pass a basic monitor-off desktop workflow;
12. add authenticated VM and compatibility accessibility bridges;
13. add deterministic local speech control before optional AI interpretation;
14. add Deaf/hard-of-hearing semantic system-event parity;
15. refine cognitive, motor, and low-vision behavior;
16. conduct practical usability testing with disabled users across multiple
    interaction modes;
17. pass the full supported monitor-off core suite;
18. only then consider accessibility ABI stabilization.

User testing cannot be deferred until after ABI freeze. CI grows to cover
semantic completeness, focus, keyboard-only operation, shared redaction,
trusted prompts, AI/accessibility parity, Braille lines/routing, speech,
VM/browser projection, HiDPI, and rendering-backend independence. Track focus-
to-Braille/speech, Braille/speech-input-to-action, and delta-propagation latency.
Physical hardware and disabled-user evidence remain distinct from simulation.

## Phase 5 — Authority, consent, and observation

The unified system-monitor lane is **PLANNED** and follows
[monitor/SYSTEM_MONITOR.md](monitor/SYSTEM_MONITOR.md). It depends on the
relevant lifecycle, capability, accounting, package/component, and event sources.
Progress through bounded gates: core snapshots; sequenced events and restart/
resync; generation/executable integrity; GPU/network/storage/device/DMA/power/
thermal views; platform/recovery evidence; separately authorized response;
accessible GUI and structured shell; then scoped participating-application
integrity after privacy, hostile-security, digital-rights, and patent review.
Do not combine these gates into one cross-cutting implementation patch.

After the core capability/service substrate and trusted compositor exist:

1. Add bounded capability provenance tracking and delegation audit events.
2. Add an access-controlled capability introspection/explanation API.
3. Implement trusted file-picker capability delegation.
4. Add the structured system-monitor authority and security-exception view.
5. Add common time/lifecycle-bounded capability expiration.
6. Define `SecretObject` and independent use/export rights.
7. Add non-extractable credential operations and trusted export consent.
8. Make local/remote AI sessions visible, expiring security principals.
9. Add structured diagnostic objects with observation-only capabilities.
10. Add exact-target, independently attenuated debugging rights.
11. Add disposable application/VM domains and trusted identity indicators.
12. Add bounded object provenance/history.
13. Preserve data-origin/taint labels through service and AI boundaries.
14. Integrate provenance with prompt-injection-resistant AI context/tool policy.
15. Add device ownership/delegation visualization and transition audit.
16. Add deterministic system-generation metadata.
17. Integrate crash/restart policy with persistent-state restoration.
18. Add retention-aware disclosure policy separating observation, retention,
    export, correlation, and training/secondary use.
19. Add anti-dark-pattern consent behavior and realistic prompt-frequency tests.
20. Add owner-visible AI-session disclosure and audit-privacy controls.

In parallel, implement the capability-native authority broker with narrow scope,
duration, and one-shot grants; the trusted userspace consent agent with anti-
spoof transaction binding; protected audit storage; and a non-omnipotent
security monitor with separate observation/remediation capabilities. Do not
attempt the entire list as one change.

Security gate: identity is not authority; temporary grants expire/revoke on all
specified paths; applications cannot forge consent or privileged events; the
monitor cannot exceed its explicit capabilities. Names, object IDs, and data do
not create authority; introspection leaks no secrets; `USE` never implies secret
`EXPORT`; debug stays target-scoped; AI remains non-root; disposable domains
retain no undeclared persistent authority.

Trusted consent depends on the Phase 3 compositor boundary. The authority broker
and non-UI policy core may be developed earlier, but no application-rendered UI
can count as trusted consent.

## Phase 6 — Persistent security state and boot

1. Implement a TPM NV or equivalent authenticated, monotonic, power-loss-atomic
   release-state backend.
   **PARTIALLY IMPLEMENTED:** release `BootstrapState` compare-and-store now
   requires the complete authenticated 152-byte predecessor rather than only its
   minimum-release scalar. A dedicated backend-neutral two-slot journal uses
   200-byte records containing an independent magic, exact sequence, complete
   state, and SHA3-256 digest. It writes the inactive successor before one exact
   monotonic counter advance and reloads the selected result. Deterministic
   tests cover same-floor root substitution, write and pre-commit failure,
   committed-but-uncertain advance, corruption, read failure, and exhaustion.
   Windows gnullvm passes all 5 focused journal tests and strict kernel/storage
   Clippy; Arch Linux/WSL2 passes all 452 kernel and 121 storage tests; the
   optimized native UEFI loader links. The Windows full storage run passes 118
   tests while three known large tests overflow the Windows test-process stack.
   The state now also authenticates the installed manifest digest, so repeat
   boots can recover the exact committed artifact authority without replaying a
   one-time root transition. A distinct UEFI TPM layout/transport adapter now
   admits one exact counter and two exact 200-byte full-write slots by complete
   public area and recomputed Name. It reuses the one-use exact-operation
   owner-policy session mechanism,
   read-verifies writes, checks exact counter succession, and provides an
   explicit cross-journal index-alias rejection gate. Arch Linux/WSL2 passes all
   24 UEFI library tests, including hostile exact-size/alias admission and a
   composed 200-byte publication simulation. This is not TPM provisioning,
   reboot, physical power-loss, or rollback-resistance evidence.
   The native UEFI submission wrapper is now bounded at 256 bytes rather than
   the previous 128-byte limit, so it can represent the 147-byte recovery and
   235-byte release full-slot write commands.
2. Bind measured boot to the exact coherent signed artifact set.
   **PARTIALLY IMPLEMENTED:** after independently extending the authenticated
   kernel and service payloads into PCR 11, the UEFI loader now extends one
   canonical 192-byte selected-boot-set record. It binds a fixed kernel-then-
   service order, explicit kinds, nonzero signed versions, verified SHA3-512
   digests, exact length, and zero reserved bytes. The measured-boot handoff bit
   is set only when all three extensions succeed; focused tests reject missing
   identity and verify every canonical field. The legacy record now correctly
   labels service kind 3 rather than VM kind 2. With a complete compiled
   release-journal configuration, the loader instead extends a canonical
   512-byte version-3 record binding a distinct manifest identity plus kernel,
   VM, service, CUDA, and launch-policy identities at one authenticated release.
   Configured boot requires all five bounded signed bundles, admits every kind
   through one exact `VerifiedRelease`, independently extends every payload,
   and refuses journal publication while any kind is missing or invalid.
   Temporary VM/CUDA/policy firmware pages are zeroed and freed after
   measurement. The policy payload must now be a strict canonical build receipt
   whose kernel and service identities exactly match the already authenticated
   payloads before publication. The signed receipt authenticates declared
   source, lockfile, loader, configuration, and tool identities as generation
   evidence, but boot does not independently reconstruct those inputs or prove
   which compiler/runtime binaries executed. No TPM-backed execution or
   remote-attestation evidence is claimed. The implemented `VerifiedRelease`
   foundation now also
   withholds its per-kind minimum-version roots and exposes exact-release
   artifact/executable admission instead: requested kind and signed artifact
   version must equal the authenticated manifest release before signature or PE
   interpretation can succeed. Focused tests reject substitution from both an
   older and a newer release. The UEFI loader now distinguishes an already
   installed manifest receipt from a new signed transition, admits both
   executables through the resulting `VerifiedRelease`, and publishes a new
   transition after both signatures and PE formats pass but before PCR 11
   extension, keeping the journal read/write PCR recipe coherent. Later boot
   preparation failure can retry through the installed receipt. Required mode
   rejects absent configuration; optional mode retains the legacy independent-
   root path. A distinct canonical handoff flag records which path was used;
   kernel production policy now requires coherent-release evidence alongside
   Secure Boot, measured boot, and rollback protection, while development
   policy may accept legacy admission. The admitted authenticated monotonic
   release journal now supplies rollback
   evidence directly; the standalone version counter remains an optional
   compatibility source rather than a second mandatory authority.
   A typed pending-release transaction now records all five exact admissions
   and refuses publication when any kind is missing. A deterministic composed
   test covers progressive omission, publication conflict and retry, successful
   transition, installed-manifest reconstruction, and repeat boot without a
   second counter write. Coherent-set boot admission remains partial because
   independent configuration/compiler/runtime verification and physical
   reboot/power-loss behavior are not yet integrated. Verification on
   2026-08-24 passed all
   5 artifact tests, all 5 release-journal tests, all 24 UEFI library tests,
   strict kernel/storage/UEFI
   library Clippy on Windows and Arch Linux/WSL2, strict native UEFI-target
   loader Clippy on Windows, all 456 kernel and 121 storage tests on Arch
   Linux/WSL2, and an optimized native UEFI loader build. A preceding 451-test
   Windows full run
   passed 450 tests; the known deep delegation-capacity test again overflowed
   the Windows test-process stack independently of this artifact code. As the
   next manifest-admission
   prerequisite, construction now requires the next manifest root and all five
   artifact roots to be pairwise distinct; authenticated transition also
   rejects any reuse of the current manifest-signing root in those six roles.
   Adversarial tests cover next/artifact, artifact/artifact, and current/
   artifact collisions. This enforces in-repository Lamport key separation but
   cannot prove external one-time-key backup destruction or human key custody.
3. Add rollback, stale-update, corruption, interrupted-write, and recovery tests.
   **PARTIALLY IMPLEMENTED:** deterministic kernel/storage/TPM simulations cover
   manifest replay and adjacent-release substitution, same-floor root conflict,
   corrupt and stale slots, failed inactive writes, pre-commit failure,
   committed-but-uncertain counter advance, read failure, sequence exhaustion,
   incomplete boot-artifact admission, publication conflict and retry, installed-
   manifest reconstruction, and repeat boot without republishing. These are unit
   and simulation results; provisioned-TPM reboot, torn-write, power-cut, and
   accessible owner-recovery exercises remain pending.
4. Establish reproducible builds, independently controlled release keys,
   Secure Boot integration, recovery, and key rotation.
   **PARTIALLY IMPLEMENTED:** signer outputs now use native exclusive creation,
   never overwrite an existing path, and best-effort remove a partial new file
   after a write error. A one-time private key is removed before its signature
   or bundle is published, and key generation writes the public half before the
   private half. Native runtime tests cover nonreplacement. This fail-closed
   host-filesystem ordering does not establish reproducible builds, independent
   custody, durable key erasure, atomic multi-file publication, Secure Boot
   enrollment, recovery, rotation, or physical evidence.
   A canonical build-receipt command now binds a declared compiler/Cargo
   version, target/profile, canonical source archive, dependency lockfile,
   unsigned kernel/service/loader, and selected configuration by exact length
   and SHA3-512 digest; a second command requires strict canonical parsing and
   byte equality. Tests cover deterministic path-independent encoding,
   noncanonical rejection, and changed-artifact disagreement. No independently
   controlled second build has yet been performed, so this remains comparison
   infrastructure rather than independent reproducible-build evidence.
   The UEFI target now fixes the PE timestamp at zero and omits the otherwise
   nondeterministic embedded PE debug identity. A controlled same-host build of
   exact commit `6976f8f` in two separate source and target roots, using only
   committed build configuration, produced matching canonical receipts for the
   unsigned kernel, service, and loader with an empty selected test
   configuration. This is repeat-build evidence for one exact toolchain and
   host, not independent-builder, cross-host, or complete configured-release
   reproducibility evidence.
5. Bind inspectable system-generation metadata to the exact kernel, compositor,
   services, configuration root, and compiler/runtime artifacts.
   **PARTIALLY IMPLEMENTED:** the signed policy artifact is now a canonical
   build receipt, and configured boot checks its exact kernel and service
   identities against authenticated payloads before monotonic publication. It
   also authenticates source archive, lockfile, loader, selected configuration,
   and declared compiler/Cargo identities for inspection. There is no
   compositor yet, and boot does not independently verify the recorded source,
   lockfile, loader, configuration bytes, or actual compiler/runtime binaries.
   Verification on 2026-08-24 passed all 456 kernel tests, all 6 signer tests,
   all 24 UEFI library tests, strict scoped Clippy, and an optimized native UEFI
   loader build. These are hosted code/test results, not firmware or physical
   TPM evidence.
6. Implement owner-selectable trust-root enrollment, replacement, owner-build and
   development authorization, compromised-key revocation, and accessible recovery.
   **PARTIALLY IMPLEMENTED as provisioning input only:** the release tool can
   exclusively create a canonical genesis bootstrap state from any explicitly
   supplied owner public key and nonzero minimum release. It embeds no vendor
   fallback. Structural inspection exposes only the public root digest,
   rollback floor, and optional installed-manifest digest and explicitly labels
   authentication as unverified. Safe construction rejects zero root/floor;
   focused tests cover exact key/floor binding, substitution, wrong key length,
   and zero floor. This does not authenticate owner consent, provision TPM NV,
   replace or revoke a live root, authorize development mode, or deliver
   accessible recovery. Verification on 2026-08-24 passed all 456 kernel, 121
   storage, 8 signer, and 24 UEFI library tests plus strict scoped Clippy and an
   optimized native UEFI loader build.
7. Add scoped remote-attestation capabilities with verifier/claim/lifetime
   binding and privacy-limited identities.
8. Verify authenticated update and recovery cannot silently replace owner trust
   policy while preserving rollback resistance.

Security gate: older signed vulnerable releases cannot be admitted after a
committed advance; loss/corruption fails safely and has a documented recovery
path. No rollback-resistance claim precedes physical testing.
Generation identity is not called deterministic until both artifacts and
configuration are reproducible.

## Phase 7 — Bare-metal hardware isolation

1. Run VMX-root entry, non-root launch, EPT ownership, exits, and teardown on a
   supported physical machine.
2. Activate VT-d/IOMMU from validated firmware topology and test every remapping
   unit relevant to assigned devices.
3. Test DMA grant/revoke, invalidation completion, device reset, quarantine,
   fault handling, and ownership transitions using real hardware.
4. Integrate internal monitor receipt/workload-key custody with live domains.

Security gate: monitor authority fails closed and retains its keys; CPU and DMA
translations agree before grant/resume; uncertain invalidation/reset never
returns a device or granule to use. Nested KVM and QEMU do not satisfy this gate.

## Phase 8 — Hardening and expansion

Continuously fuzz parsers, IPC, shared-memory metadata, capability abuse, and
corruption paths. Stress SMP races, mapping/revocation races, interrupts,
crashes, exhaustion, network adversaries, and power loss. Perform unsafe/FFI
review, application dependency/admission tests, browser fingerprint regressions,
semantic-graph desynchronization and spoofing tests, side-channel analysis,
formal specification of critical capability and noninterference properties,
reproducible release review, and external audit. Investigate CET/IBT only as
defense in depth for relevant trusted native boundaries; do not claim or depend
on enforcement until implemented and exercised. Only then consider broad
drivers, production claims, AArch64, and RISC-V64.

Before architectural maturity, perform independent hostile-security and digital-
rights reviews, accessibility user testing, and adversarial AI testing. Include
acceptance scenarios for prompt-injected credential export, compromised-service
non-amplification and anti-persistence, malicious publisher requests to disable
accessibility/inspection, overbroad remote attestation, equivalent first-party
and third-party authorization, and deliberately authorized owner-built boot.
Expected results are denial outside delegated authority, complete cleanup,
continued peer operation, ordinary redaction without publisher veto, scoped
privacy-preserving claims only under owner policy, no first-party bypass, and no
hidden vendor veto. Agent adversaries supplement rather than replace external
human audit.

Guest-device fuzzing prioritizes VirtIO descriptors and indirect/cyclic chains,
virtual-network packets, audio control, USB descriptors, PCI configuration,
VGPU/CUDA commands, block requests, interrupt delivery, and lifecycle/reset
transitions using malformed, truncated, oversized, repeated, and stale inputs.
Differential tests run the same guest workload against QEMU and MRML and explain
every guest-visible difference; matching QEMU is not itself a security proof.

Every milestone requires proportional Windows gnullvm and Linux testing,
backend-specific signed probes where applicable, exact commands/results, and
before/after performance measurements. Unsupported environments must be listed,
not implied.
