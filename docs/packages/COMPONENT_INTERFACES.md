# MRML versioned component interfaces

**Status: PLANNED.** This document defines package metadata, resolution,
loading, lifetime, and evidence requirements. Bounded identity, schema,
load-plan, and memory-accounting prerequisites are partially implemented as
recorded below; runtime resolution, dynamic loading, independently serviced
providers, and ZIM integration are not implemented.

**PARTIALLY IMPLEMENTED prerequisite:** `packages/tools/mrml` now defines
compiler-independent canonical interface identity/generation validation, bounded
borrowed views, opaque generational handles, and one fixed little-endian call
header codec. The first bounded schema/generator increment now parses the exact
version-1 `mrml-call-v1` format, rejects noncanonical or unbounded definitions,
computes a SHA3-256 ABI fingerprint, and deterministically emits pointer-free
safe Rust request/error types. The canonical Zstd ABI-3 schema and generated
binding live under `packages/interfaces/org.mrml.interface.compression.zstd/`.
This does not implement native call lowering, executable mapping, a provider,
consumer migration, or runtime interface resolution.

**PARTIALLY IMPLEMENTED loader prerequisite:** the build tool now admits an
immutable exact-package load plan made only of bounded, page-aligned,
nonoverlapping sections. It rejects writable-executable mappings, nonexecutable
entry points, overflow, overlap, and image escape. This is validation evidence,
not a runtime loader: it performs no parsing, relocation, symbol lookup,
executable mapping, interface binding, or in-place patching.

**PARTIALLY IMPLEMENTED memory-accounting prerequisite:** the kernel now wraps
the existing `MemoryPoolTable` rather than defining component-local resource
authority. One shared immutable-code `MemoryObject` is charged once, carries no
write authority, and can have multiple separately target-authorized RX mapping
reservations. Live mappings prevent object reclamation. This is policy and
accounting evidence only: no physical backing, code population/sealing, native
page-table installation, provider binding, private-state charge, or runtime
loader is implemented.

**PARTIALLY IMPLEMENTED resolution prerequisite:** the build tool now represents
typed exact `REQUIRES` and `PROVIDES` edges and resolves them only within one
immutable `SystemGeneration`. A match requires identical interface name, major
generation, and 256-bit schema fingerprint; the result retains exact consumer
and provider package versions and artifact digests plus the in-process/service
form. Missing, ambiguous, out-of-generation, reordered, ABI-generation, and
fingerprint substitution fail closed. This produces dependency data only, not a
live `InterfaceBinding`, load authority, capability, or provider selection
preference.

The canonical deployment and generation model remains
[DEPLOYMENT.md](../DEPLOYMENT.md); build orchestration remains
[BUILD_SYSTEM.md](../build/BUILD_SYSTEM.md). This document adds only the
dynamic-component/interface delta to those architectures.

> Functionality historically embedded in a Rust binary may instead be supplied
> by an independently signed and serviced MRML component through an explicit,
> versioned interface.

## Identity and terminology

Package identity and interface identity are distinct:

```text
package:    org.mrml.zstd
interface:  org.mrml.interface.compression.zstd@3
```

A package may provide several interfaces and require several interfaces. A
package name is never itself the stable ABI. Package version, package
generation, interface generation, and exact content digest remain separate.
Names identify; capabilities authorize.

The layers are also distinct:

- a **Rust crate** is a source/compiler dependency unit;
- an **MRML package** is a signed deployable component unit;
- an **MRML interface** is a stable semantic and binary contract;
- a **provider** implements an interface; a **consumer** requires one;
- an **InterfaceBinding** binds one consumer to one exact admitted provider
  generation for a defined lifetime.

One package may contain several implementation-private crates, one crate may
implement several interfaces, and several owner-authorized packages may
implement one interface. First-party preference is policy, not hidden authority.

Package manifests and dependency graphs distinguish at least `STATIC` (linked
into an artifact), `DYNAMIC_INTERFACE` (in-process versioned binding),
`SERVICE_INTERFACE` (typed IPC to an isolated provider), and `BUILD_ONLY`.
Package, interface, service, build, and hardware requirements are typed edges,
not interchangeable strings. Exact encoding and names are provisional.

## Canonical independent-servicing example

```text
org.mrml.zim version 8
  requires org.mrml.interface.compression.zstd@3

org.mrml.zstd version 14
  provides org.mrml.interface.compression.zstd@3
```

The generation resolver may bind ZIM 8 to Zstd 14 without embedding Zstd in
ZIM. If Store servicing admits Zstd 15 with the same interface generation, it
may construct:

```text
SystemGeneration 104: ZIM 8 -> Zstd 14 (compression.zstd@3)
SystemGeneration 105: ZIM 8 -> Zstd 15 (compression.zstd@3)
```

ZIM is not rebuilt. User-facing update and support views state that its provider
changed while ZIM did not. If Zstd 16 supplies only interface generation 4,
the resolver must not bind it to ZIM 8's generation-3 requirement. It may retain
an admitted ABI-3 provider, update ZIM, admit both major generations, or reject
the candidate. It never guesses compatibility.

Multiple major interface generations and multiple provider packages may coexist
when resources and owner policy permit. Selection uses interface identity,
interface generation, package provenance, architecture/profile, admission
evidence, update policy, and the applicable `SystemGeneration` or
`ApplicationGeneration`; it never searches arbitrary paths for the first
matching DLL, SO, filename, or global symbol.

## Interface specification and evolution

Canonical interface definitions live in one shared, versioned schema location.
The schema language version is separate from the interface generation. An
interface definition describes identity and major generation; calling
convention; operation identities; types and external layouts; bounded optional
features; memory ownership and borrowed-view lifetime; opaque generational
handles; typed errors; concurrency and failure behavior; initialization and
finalization; and capability transfer, attenuation, and object lifetime.

The resolver primarily requires machine-checkable ABI compatibility. API/source
compatibility is related but distinct. Incompatible change creates a new major
interface generation; an existing generation is never silently redefined.
Simple explicit major generations are preferred to semantic-version inference
or unbounded per-operation negotiation.

The interface ABI is MRML-defined, bounded, and language-neutral enough for
future safe-language bindings; this does not mean adopting the C ABI. Rust's
native compiler ABI, layouts, symbol quirks, unwinding, allocator conventions,
or generics are not component contracts. Upstream-rustc and mrml-rustc artifacts
may interoperate only when both conform to the same exact MRML ABI. Compiler
provenance is evidence metadata, not a new interface identity.

Canonical schemas should generate checked provider/consumer bindings and ABI
fingerprints. Safe Rust types are exposed where semantics permit; unavoidable
unsafe mechanics remain in a tiny generated/runtime boundary. Cross-component
pointers are bounded borrowed views with call-scoped or explicit lifetimes, or
opaque generational objects with explicit ownership operations. Raw allocator
ownership, Rust references, trait objects, unwinding, and thread-local layout do
not cross an interface accidentally. Component-local symbols remain private;
there is no global interposition namespace.

Interfaces have conformance/golden fixtures and ABI-diff reports. Fuzzing covers
schemas, descriptors, lengths, enum values, layouts, stale handles, generation
confusion, and negotiation. Parser-heavy providers are fuzzed independently.
Cross-compiler and cross-architecture tests use canonical values and malformed
inputs without treating equal source APIs as ABI proof.

The implemented schema version 1 deliberately accepts only one explicit policy
profile: `mrml-call-v1`, parallel calls, fail-closed behavior, no implicit
initialization/finalization, and no capability transfer. Operations and typed
errors have nonzero, canonically ordered numeric identities. Arguments are
fixed-width scalars, direction-distinct bounded borrowed views, or opaque
generational handles. Any future ownership, capability-transfer, async,
streaming, callback, allocator, or exception policy requires a new reviewed
schema-language version rather than an ignored extension.

## Component forms and isolation decision

Two primary forms are planned:

- **in-process component:** immutable executable pages mapped into an admitted
  caller for sufficiently trusted, memory-safe, performance-sensitive code;
- **service component:** typed IPC to an isolated, supervised provider with its
  own projected capabilities and resource pool.

Where it stays simple, a semantic interface may support either location. This is
not mandatory. For each candidate, review performance benefit, fault impact,
memory-safety evidence, parser attack surface, IPC cost, and update frequency.
An in-process fault can terminate or corrupt the caller; a service fault follows
service revocation/restart policy. Speed alone does not justify sharing an
address space.

Good candidates tend to have many consumers, meaningful size, frequent security
updates, a stable narrow boundary, shared-memory benefit, and mature fuzzing.
Tiny helpers, unstable compiler internals, monomorphized/generic abstractions,
and boundaries without stable semantics remain static. Dynamic servicing can
reduce inlining and whole-program optimization, so critical conversions measure
call/load overhead, throughput, startup, RAM/storage sharing, code-cache effects,
and update benefit. An admitted in-process binding targets ordinary function-
call-level overhead: resolution happens at bind time, not through a kernel or
global capability lookup on every call.

Potential later providers include Zstd, Unicode data, font shaping, image
codecs, math/runtime functions, TLS, HTTP, and cryptography. Each receives its
own review. Crypto/TLS may require release binding, stronger key/rollback policy,
and audit rather than inheriting compression's servicing policy. Fundamental
language/code-generation primitives do not become one giant Store component.

## Admission, loading, and capability rules

The generation resolver, not an application filesystem search, selects an exact
provider:

```text
download -> authenticate -> validate ABI/evidence/policy
  -> resolve typed requirements -> construct candidate generation
  -> admit/activate under component update policy
```

Candidate resolution is deterministic and fail closed. It checks the complete
relevant graph before activation and records exact bindings in the generation
lock. Package signing authenticates provenance; it does not prove ABI
conformance, memory safety, semantic correctness, performance, or audit. Track
those evidence dimensions separately.

An `InterfaceBinding` contains the consumer, interface and major generation,
exact provider package generation/digest, compatible target/profile, entry table
or service endpoint, and binding generation/lifetime. It is produced only after
admission. Stale bindings never resolve through reused slots to newer code.
Eager binding is preferred initially; bounded lazy binding may exist only if it
preserves deterministic admission and failure semantics.

The loader validates the admitted binding and exact immutable executable object,
performs checked relocations into private writable construction state, seals
code/constant pages executable/read-only, applies ASLR where compatible, and
publishes no partially initialized binding. It rejects unknown relocation forms,
overflow, out-of-range targets, writable executable pages, unexpected exports,
ABI mismatch, wrong architecture/profile, and stale generations. Arbitrary
load-time constructors are forbidden; bounded initialization receives only
explicit interface state. Position independence, control-flow integrity, and
direct/fixed-stub optimization must preserve exact-generation semantics.
Provider-specific optimization assumptions must appear as explicit metadata;
secret devirtualization cannot erase provider compatibility.

Loading grants no ambient authority. Package/interface metadata requests or
describes and never grants capabilities. An in-process provider operates inside
the caller's already established domain and ABI safety model. An isolated service
receives its own explicitly projected capabilities. Ordinary compression should
need bounded input/output memory, CPU, and RAM—not filesystem, network,
credentials, GPU, or disk-administration authority. Binding, interface
inspection, provider administration, package install, and capability transfer
are separate rights.

## Immutability, lifetime, and accounting

Dynamic does not mean mutable. Once admitted, code and read-only data are exact
immutable generational objects. Updates never patch executable pages beneath a
running process and preserve W^X.

Existing consumers may retain Zstd generation 14 while new consumers bind
generation 15. Long-lived contexts remain bound to their creation provider and
cannot migrate unless the interface defines an explicit, authenticated state
export/import operation. A prohibited vulnerable generation receives no new
bindings; policy reports affected processes and may request or force bounded
restart. Retained prohibited content can remain quarantined for forensic use
without becoming normally executable.

An old provider generation is reclaimable only when it has no live process,
service, or binding references; no retained `SystemGeneration`,
`ApplicationGeneration`, rollback root, export, or snapshot pin; and package
store GC policy permits reclamation. Revoked signing keys stop new admission and
trigger policy reevaluation, not blind deletion of owner state.

Immutable executable pages may share one physical `MemoryObject` across domains,
while each mapping has exact rights/generation and each process has private
state. Accounting distinguishes physical backing, per-domain mappings, private
state, relocation/metadata, and service pools. The physical charge is assigned
once under explicit system/cache policy; mapping/table and private charges stay
with each consumer; fanout and mappings are bounded so sharing cannot amplify
resource authority. Shared backing does not exempt any page from `MemoryPool`
accounting, pinning limits, revocation, cleanup, or W^X. Cross-domain writable
executable sharing is forbidden.

## Store, generations, snapshots, and policy

Component update policy metadata conceptually supports:

- `INDEPENDENT`: compatible provider versions may be serviced independently;
- `SYSTEM_RELEASE_BOUND`: a coherent `SystemRelease` selects the exact provider;
- `BOOT_BOUND`: early-boot admission selects the exact implementation;
- `SECURITY_PINNED`: stronger security/rollback/review policy applies.

Names are provisional and a component may be more constrained by profile.
Ordinary userspace `org.mrml.zstd` is the first planned `INDEPENDENT` example.
Bootloader/recovery Zstd can remain statically embedded or `BOOT_BOUND`. Coupled
providers form an explicit update group rather than pretending independence.

The Store understands `PROVIDES`, `REQUIRES`, interface generation, dependency
form, and update policy. Its preview shows affected dependents, compatibility,
provider substitutions, restarts/reboots, retention, rollback, security impact,
and download/storage cost. A Store update constructs a candidate graph; it does
not overwrite a shared library. Official-provider preference and alternative
providers are visible owner policy.

`SystemRelease` signing validates every release-bound requirement. A
`SystemGeneration` records system-bound exact bindings; an
`ApplicationGeneration` records independently selected application bindings;
service instances also retain exact service generations. System and application
activation is atomic at the relevant graph boundary. Support reports, crash
dumps, task views, profiling, snapshots, and exact exports preserve provider
package generation/digest, interface generation, and binding generation—not just
the main application version. Debug symbols remain separately authorized.

Exact restore reproduces the recorded graph subject to current security policy;
`COMPATIBLE_CURRENT` may resolve admitted compatible providers. Prohibited old
code requires an explicitly isolated forensic mode rather than normal execution.
Offline image servicing reruns dependency resolution. A self-contained install/
recovery image includes the provider closure needed offline; a later thin image
declares external repositories without making base recovery network-dependent.
Dependency graphs and versions are locally inspectable but not transmitted as
telemetry without separate authority.

Future typed administration may expose `Get-PackageDependency`,
`Get-InterfaceProvider`, `Get-InterfaceConsumer`, dependency impact previews,
and interface migration/ABI-diff tests. Inspection never grants load, install,
provider-control, debug, or content-read authority.

## Boot, kernel, VMM, and recovery constraints

The UEFI loader, early kernel, and recovery-critical path remain bootable without
the normal userspace component resolver. The bootloader understands only its
bounded boot-safe package profile and never solves the desktop graph. It may
embed a minimal Zstd decoder even while userspace independently services Zstd.
Recovery may understand a deliberately larger bounded subset, but its essential
package/image codecs remain pinned or static and self-contained so a broken or
malicious provider update cannot make recovery unreadable.

This model does not automatically turn kernel dependencies into ordinary
dynamic libraries. Kernel componentization needs a separate TCB/security review.
The VMM may consume a serviced interface only when host/native target rules,
explicit ABI compatibility, release/update policy, and TCB review permit it; a
low-trust update cannot silently change the VMM TCB.

## Build and compiler integration

The public `mrml` build/package frontend resolves Rust compile-time crates and
MRML runtime interfaces as separate graphs. Cargo remains a transitional private
bridge and its dependency model never becomes the runtime package model.
Canonical package manifests carry typed provides/requires, interface generation,
dependency form, update class, target/profile, and evidence metadata; lockfiles
record exact selected provider generations and digests.

The semantic `packages/` hierarchy organizes deployable packages. Private crates
may live below a package, for example `packages/libraries/zstd/crates/`, without
recreating a repository-wide generic crate dumping ground. Static embedding is
allowed for boot/recovery, security-pinned builds, or measured specialization.
Rust generic code is not mechanically converted into a dynamic component.

Eventually `mrml` generates bindings, validates schemas/fingerprints, resolves
providers, produces ABI diffs, and emits exact runtime locks. `mrml-rustc`
eventually validates MRML ABI metadata directly, rejects unsupported layouts or
unsafe transfers, and emits the same contract as pinned upstream rustc. Neither
compiler silently falls back or changes interface identity.

## Initial milestones and acceptance

After package identity, generation construction, package resolution, loader
foundations, stable ABI primitives, and quantitative memory accounting, proceed:

1. versioned canonical interface schema and generated safe bindings
   (**PARTIALLY IMPLEMENTED** for schema version 1 and the Zstd ABI-3 fixture);
2. typed provides/requires metadata and exact candidate resolution
   (**PARTIALLY IMPLEMENTED** as bounded in-generation exact resolution);
3. immutable in-process loader and generation-safe `InterfaceBinding`;
4. `org.mrml.zstd` providing `compression.zstd@3`;
5. `org.mrml.zim` consuming that interface without provider path knowledge;
6. Store update N to N+1 while old/new ZIM processes retain exact bindings;
7. lifetime/rollback/snapshot-aware GC and dependency inspection;
8. ABI-4 coexistence/rejection and vulnerable-provider quarantine/retirement;
9. cross-compiler, performance, fuzzing, and optional service-provider evidence;
10. selective migration of further high-value components.

The end-to-end Zstd gate proves equal corpus decoding by old and new providers,
no ZIM rebuild, old-generation retention while referenced, later safe GC, ABI-4
non-substitution, and prohibited-generation denial for new bindings. Performance
compares static and dynamic compression/decompression throughput, load/startup,
call overhead, physical/mapped RAM, code-cache behavior, and update size. The
dynamic form targets negligible steady-state overhead; results, not ideology,
decide static/dynamic placement.

Before maturity, prove no path/filename binding or symbol interposition,
generation-safe references, incompatible-ABI rejection, W^X and immutable
updates, complete accounting, no metadata authority grant, safe retention/GC,
policy-controlled substitution, recovery independence, and fail-closed stale
contexts/handles. Test unit/simulation, hosted, nested-virtualization, and
physical evidence as distinct categories; documentation is none of them.

## Non-goals

MRML dynamic components are not ELF `LD_LIBRARY_PATH`, Windows DLL search,
arbitrary global symbols, unrestricted plugins, live code patching, every Rust
crate converted to a DLL, or a replacement for service isolation. They are
typed interface bindings to exact immutable admitted provider generations,
independently serviceable where evidence and policy justify it, capability-aware,
package/provenance-aware, and compatible with shared immutable code pages.

Engineering Constitution complexity score for the future subsystem: complexity
impact `HIGH`, TCB impact `HIGH` for the in-process loader and `LOWER/ISOLATED`
for service providers, new parser `YES`, new authority model `NO`, new persistent
state `YES`, external dependency `NO`, failure isolated `PARTLY`, and existing-
object reuse `YES` through packages, generations, capabilities, `MemoryPool`,
`MemoryObject`, services, and deployment transactions. The design passes the
digital-rights review only if owner-authorized providers remain viable,
first-party preference is policy, metadata never grants authority, local graphs
do not create telemetry, recovery remains owner-controlled, and no DRM authority
is introduced. Hostile-security review treats every schema, manifest, provider,
binding, relocation, handle, generation, length, capability transfer, update,
retention root, and cleanup result as adversarial.

Patent review: `TRIGGERED` — package/interface resolution, executable loading,
generated ABI bindings, update/retention composition, and shared-page accounting
require mechanism-specific worldwide review before implementation. Record that
review in [patents/REVIEW_LOG.md](../patents/REVIEW_LOG.md); this design does not
establish patent clearance and agent review does not replace human dual review.
