# Patent review log

## 2026-08-23 — initial worldwide repository landscape

### Implemented areas inventoried

Microkernel, capabilities/IPC, scheduling, memory/address spaces, boot/UEFI/TPM,
VMX/EPT/VT-d, KVM, WHP/VBS, mediated GPU/authenticated queues, CUDA/PTX, tensor
inference, GGUF loading, quantization, speculative decoding, training,
Rust-subset compilation, TLS/SSH/HTTP, cryptography, Git/ZIM, Zstandard/FSE,
AV1, and Opus. Roadmap-only systems were not treated as implemented.

### Priority mechanisms

| Priority | Mechanism | MRML source | Initial result |
| --- | --- | --- | --- |
| Highest | AV1 coding tools, restoration, prediction, transforms, entropy, film grain | `crates/mrml-av1/src/` | AOMedia patent terms require exact license review; third-party assertions remain possible. |
| Highest | Opus SILK/CELT, PVQ, range coding, stereo/pitch tools | `crates/mrml-opus/src/` | RFC 6716 records multiple IETF IPR disclosures; terms and worldwide family members need claims review. |
| High | GPU mediation, authenticated rings, reset, EPT/VT-d, CUDA | `crates/mrml-kernel/src/virtual_gpu.rs`, `arch/x86_64/{ept,vtd,vtd_tables}.rs`, `crates/mrml-{kvm,whp}/`, `crates/mrml-tensor/src/cuda.rs` | Distinctive hardware-facing composition; no candidate verified. |
| High | Quantized inference, planning, KV cache, speculative decoding | `crates/mrml-tensor/src/{quant,ops,execution_plan,kv_cache,speculative}.rs` | Must distinguish standard formats from MRML scheduling/layout. |
| High | Zstandard FSE/Huffman/sequences | `crates/mrml-zstd/src/` | Compression and upstream grant review required. |
| High | Hybrid X25519/ML-KEM TLS and AEAD | `crates/mrml-tls/`, `crates/mrml-crypto/` | Standards/IPR and exact protocol-version review required. |
| Medium-high | Protected receipts, sealed-key gates, VMX-root custody | `crates/mrml-kernel/src/protected_*.rs`, `crates/mrml-whp/src/protected_broker.rs` | Unusual composed state machine; search confidence low. |
| Medium | Rust-subset lowering/object generation | `crates/mrml-rustc/src/` | Review distinctive optimizations only, not ordinary compiler structure. |

### Discovery performed

- Reviewed WIPO territoriality/PCT guidance, PATENTSCOPE, the Patent Register
  Portal, and worldwide family/legal-status workflow.
- Reviewed AOMedia's public AV1 patent-license statements as a licensing lead,
  not a clearance conclusion.
- Reviewed RFC 6716 and its recorded IETF IPR disclosures as standards-risk
  signals, not proof that a claim is essential or reads on MRML.
- Established Tier 1 deep-review jurisdictions and worldwide family discovery.

### Result and limitations

Verified active rights: **none**. Verified pending candidates: **none**.
Verified relevant expired rights: **none**. This means no candidate completed
the required claim-by-claim, family, license, and territorial-status workflow
during this preliminary pass; it does not mean no relevant right exists.

Global and per-area search confidence is **LOW**. Technical overlap and legal
status confidence remain unassessed. Multilingual claims, prosecution,
ownership, national phases, validations, fees, term changes, continuations,
divisionals, oppositions, litigation, and commercial-country facts were not
exhaustively reviewed. Professional review is most warranted for AV1, Opus,
GPU/CUDA mediation, quantization/speculative inference, and Zstandard before
commercial or production release.

Patent review: `TRIGGERED` — persistent worldwide policy and initial landscape.

## 2026-08-23 — fixed-array reference helper signatures

MRML source: `crates/mrml-rustc/src/{expression,codegen,pipeline}.rs`.

The compiler now carries existing fixed-array element, count, and mutability
information through its bounded descriptor for inlined safe Rust-ABI helper
calls. The change reuses ordinary type compatibility, reference representation,
index lowering, and inline-frame cleanup already present in MRML; it adds no
distinctive optimization, memory layout, calling convention, or algorithm.

Patent review: `NOT_TRIGGERED` — ordinary compiler type propagation and inline
lowering within the review log's existing Rust-subset compiler category.

## 2026-08-23 — slice and string reference helper signatures

MRML source: `crates/mrml-rustc/src/{expression,codegen,pipeline}.rs`.

The compiler now carries existing slice element, string, and mutability
information through bounded descriptors for inlined safe Rust-ABI helper calls.
It transports the existing two-word pointer/length representation through
arguments, locals, normal and early returns, and direct indexing. The change
uses ordinary type compatibility, bounds checks, register/stack movement, and
inline-frame cleanup; it adds no distinctive optimization, public calling
convention, memory layout, or algorithm.

Patent review: `NOT_TRIGGERED` — ordinary compiler type propagation, multiword
value transport, and inline lowering within the existing Rust-subset compiler
category.

## 2026-08-23 — value-producing loop helper tails

MRML source: `crates/mrml-rustc/src/{parser,codegen,pipeline}.rs`.

The helper-body parser now preserves a tail value-producing loop when the
existing bounded expression parser accepts the complete remainder. Existing
scalar and reference result emitters then lower its conditional break choices
before ordinary inline-frame cleanup. Statement loops and unsupported loop
graphs retain their separate fail-closed path. The change adds no distinctive
optimization, calling convention, memory layout, or algorithm.

Patent review: `NOT_TRIGGERED` — ordinary compiler parsing, control-flow
lowering, and inline-frame cleanup within the existing Rust-subset compiler
category.

## 2026-08-23 — by-value fixed-array helper signatures

MRML source: `crates/mrml-rustc/src/{expression,codegen,pipeline}.rs`.

The compiler now carries existing fixed-array element and count information
through bounded descriptors for inlined safe Rust-ABI helper calls. Arguments
reuse the established array materialization and local packing paths. Returns
move existing element slots across inline-frame cleanup without defining a new
public ABI. The change adds no distinctive optimization, memory layout, or
algorithm.

Patent review: `NOT_TRIGGERED` — ordinary compiler type propagation, fixed-array
value transport, and inline-frame cleanup within the existing Rust-subset
compiler category.

## 2026-08-23 — native guest-mapping revocation ordering

MRML source: `crates/mrml-kernel/src/vm.rs`,
`crates/mrml-kvm/src/{abi,native.rs,native/launch.rs}`, and
`crates/mrml-whp/src/{abi,native.rs,native/launch.rs}`.

The VMM adapters now remove exact second-level guest mappings before the common
mapping identity is retired and prevent vCPU execution after uncertain native
teardown. The implementation uses ordinary lifecycle ordering and the existing
documented KVM memory-slot and WHP GPA unmapping interfaces. It adds no novel
algorithm, device protocol, codec, cryptographic construction, or optimization.

Patent review: `NOT_TRIGGERED` — conventional capability/mapping lifecycle
enforcement over existing hypervisor APIs.

## 2026-08-23 — cleanup-gated service restart

MRML source: `crates/mrml-kernel/src/{task_runtime,service_lifecycle}.rs` and
`crates/mrml-{kvm,whp}/src/native/launch.rs`.

Service retirement now preflights restart timing, retains an exact one-use
cleanup ticket, and permits restart only after the existing backend-specific
service memory reset succeeds for the bound task and page-table root. This uses
ordinary lifecycle state, identity comparison, retry handling, memory clearing,
and existing PE reprovisioning; it adds no novel algorithm, device protocol,
codec, cryptographic construction, or optimization.

Patent review: `NOT_TRIGGERED` — conventional fail-closed lifecycle and
zeroization gating over existing service reset mechanisms.

## 2026-08-23 — task-owned shared-resource cleanup

MRML source: `crates/mrml-kernel/src/shared_memory.rs`.

Shared mappings may now bind an exact task generation. Service cleanup removes
each native mapping before its policy identity and binding, retains peer
endpoints, destroys the opaque host resource only at the final reference, and
retains completed obligations across retry. This is ordinary reference-counted
resource lifetime, generational identity checking, and fail-closed teardown
ordering; it adds no novel algorithm, device protocol, codec, cryptographic
construction, or optimization.

Patent review: `NOT_TRIGGERED` — conventional capability-bound resource
lifecycle and cleanup composition.

## 2026-08-23 — Phase 1 service-policy microbenchmarks

MRML source: `crates/mrml-kernel-bench/src/lib.rs`.

The host-only release harness now times existing IPC, scheduler wakeup,
capability transfer/revocation, shared-binding, and cross-runtime domain-handoff
operations using fixed iteration counts and optimization barriers. It introduces
no new runtime mechanism, algorithm, protocol, or optimization.

Patent review: `NOT_TRIGGERED` — ordinary measurement of existing kernel policy
operations.

## 2026-08-23 — pinned cross-core and live WHP mapping benchmarks

MRML source: `crates/mrml-kernel-bench/src/lib.rs`,
`crates/mrml-whp/src/native.rs`, and `crates/mrml-kvm/src/native.rs`.

The host-only harness parses documented Windows processor topology, pins two
threads to distinct reported cores, and measures the existing ownership
mailbox. WHP and KVM ignored tests measure their existing allocation, GPA map,
unmap, and release lifecycles. These are ordinary measurement and affinity
controls and introduce no new scheduler, mapping algorithm, protocol, or
optimization.

Patent review: `NOT_TRIGGERED` — ordinary measurement of existing kernel and
hypervisor operations.

## 2026-08-23 — transitive IPC capability revocation

MRML source: `crates/mrml-kernel/src/task_runtime.rs`.

IPC transfers now record bounded parent/child relations between exact
generational capability handles. Explicit revocation and task retirement walk
those relations to invalidate descendants, while transactional capacity checks
and rollback prevent partial graph publication. This is ordinary capability
lifecycle accounting and graph traversal; it adds no novel algorithm, device
protocol, codec, cryptographic construction, or optimization.

Patent review: `NOT_TRIGGERED` — conventional bounded delegation tracking and
lifecycle revocation.

## 2026-08-23 — supervised fault cleanup and restart composition

MRML source: `crates/mrml-kernel/src/{service_lifecycle,shared_memory}.rs`.

Service recovery now sequences existing task retirement, peer notification,
native shared-mapping revocation, resource/address-space erasure, and bounded
fresh-generation restart through one synchronous operation with retryable
failure states. This is ordinary lifecycle orchestration and error-state
composition; it adds no novel algorithm, device protocol, codec, cryptographic
construction, or optimization.

Patent review: `NOT_TRIGGERED` — conventional fail-closed service lifecycle
composition.

## 2026-08-23 — hosted cleanup-ticket service reset handshake

MRML source: `crates/mrml-kernel-image/src/main.rs` and
`crates/mrml-{kvm,whp}-run/src/main.rs`.

The signed hosted probe now pauses on an exact service-slot cleanup request,
uses the existing authenticated reprovisioning operation, verifies erased state,
and resumes cleanup-ticket completion before fresh-generation restart. This is
ordinary synchronous test-harness coordination and lifecycle ordering; it adds
no novel algorithm, device protocol, codec, cryptographic construction, or
optimization.

Patent review: `NOT_TRIGGERED` — conventional hosted reset orchestration and
verification.

## 2026-08-23 — signed typed service peer-death proof

MRML source: `crates/mrml-kernel-image/src/main.rs` and
`crates/mrml-{kvm,whp}-run/src/main.rs`.

The signed hosted service path now checks an existing typed clean peer-death
event and exact sender/sequence envelope before receiver continuation, then
reconstructs the same capability-authorized relation for fresh task
generations. This is ordinary lifecycle notification, generational identity
checking, and controlled-probe staging; it adds no novel algorithm, device
protocol, codec, cryptographic construction, or optimization.

Patent review: `NOT_TRIGGERED` — conventional typed lifecycle notification and
test-harness verification.

## 2026-08-23 — diverging Rust helper signatures

MRML source: `crates/mrml-rustc/src/{expression,codegen,pipeline}.rs`.

Safe inlined Rust helpers may declare the never return type when their existing
bounded body representation proves an unconditional diverging loop. Call-site
typing applies ordinary bottom-type coercion and reuses the existing loop
backedge and inline-frame bookkeeping; no new control-flow algorithm, ABI,
protocol, cryptographic construction, or optimization is introduced.

Patent review: `NOT_TRIGGERED` — conventional never-type propagation over
existing bounded compiler control flow.

## 2026-08-23 — bounded heterogeneous scalar tuples

MRML source:
`crates/mrml-rustc/src/{expression,ir,semantics,codegen,pipeline}.rs`.

The compiler now represents up to four heterogeneous built-in scalar tuple
elements in fixed arrays, materializes them in existing checked stack slots,
and applies ordinary numbered projection and inline helper frame cleanup. This
is conventional parser, type propagation, aggregate copying, and stack-value
transport; it introduces no novel ABI, algorithm, protocol, cryptographic
construction, or optimization.

Patent review: `NOT_TRIGGERED` — ordinary bounded compiler aggregate handling.

## 2026-08-23 — signed task-owned shared-page lifecycle

MRML source: `crates/mrml-{kvm,whp}/src/native/{launch.rs,rs}`,
`crates/mrml-{kvm,whp}-run/src/main.rs`, and
`crates/mrml-{kernel,service}-image/src/main.rs`.

The hosted service probe maps one common frame through independent page-table
leaves, removes the retired task's exact leaf, preserves the peer leaf, and
re-arms the mapping for a fresh generation. This is conventional page-table
mapping, exact-match unmapping, lifecycle ordering, and controlled-probe
verification; it introduces no novel algorithm, device protocol, codec,
cryptographic construction, or optimization.

Patent review: `NOT_TRIGGERED` — conventional shared-memory mapping and
lifecycle revocation.

## 2026-08-23 — signed surviving-peer fault notification

MRML source: `crates/mrml-kernel/src/task_runtime.rs`,
`crates/mrml-kernel-image/src/main.rs`, `crates/mrml-service-image/src/main.rs`,
and `crates/mrml-{kvm,whp}-run/src/main.rs`.

Retirement now publishes an existing typed death event and wakes blocked peers
before the scheduler chooses a continuation. The signed probe keeps one peer
blocked through the other peer's deliberate fault and checks the exact reason
and identity after cleanup. This is ordinary scheduler ordering, lifecycle
notification, and controlled test staging; it introduces no novel algorithm,
protocol, cryptographic construction, or optimization.

Patent review: `NOT_TRIGGERED` — conventional scheduler wakeup and typed
lifecycle verification.

## 2026-08-23 — typed configuration and supervision protocol foundation

MRML source: `crates/mrml-config/src/lib.rs` and
`crates/mrml-kernel/src/{capability,service_lifecycle}.rs`.

The service foundation applies fixed schemas, ordinary optimistic transaction
revision checks, exact capability authorization, a bounded overwrite-detecting
audit ring, and canonical fixed-record request/response parsing. Supervision
messages carry opaque generational handles whose authority is independently
checked. These are conventional database, capability, and protocol-validation
techniques; they introduce no novel algorithm, device protocol, codec,
cryptographic construction, or optimization.

Patent review: `NOT_TRIGGERED` — conventional transactional configuration and
service-control message handling.

## 2026-08-23 — IPC-derived configuration and supervision dispatch

MRML source: `crates/mrml-config/src/lib.rs` and
`crates/mrml-kernel/src/ipc.rs`.

Configuration and supervision dispatch now separates payload data from
authority by resolving operations from the receiver-space capabilities that
ordinary kernel IPC derives in message order. It rejects mismatched envelopes
and composes existing configuration transactions and service restart checks.
This is conventional capability-message dispatch and lifecycle orchestration;
it introduces no novel algorithm, ABI, protocol, cryptographic construction,
or optimization.

Patent review: `NOT_TRIGGERED` — conventional capability-envelope validation
and service dispatch.

## 2026-08-23 — bounded CPL3 buffer validation foundation

MRML source: `crates/mrml-kernel/src/{syscall,capability}.rs` and
`crates/mrml-kernel/src/arch/x86_64/{address_space,page_table,service_space}.rs`.

The kernel now decodes bounded buffer descriptors, validates canonical
capability-transfer records, resolves complete ranges against user mappings,
and checks each active user page before directional copy. These are conventional
syscall marshalling, page-table walking, bounds checking, and capability
attenuation techniques; they introduce no novel algorithm, ABI optimization,
device protocol, codec, or cryptographic construction.

Patent review: `NOT_TRIGGERED` — conventional bounded user-copy validation and
syscall descriptor parsing.

## 2026-08-23 — lazy tuple-valued compiler control flow

MRML source: `crates/mrml-rustc/src/codegen.rs`.

Tuple-valued conditionals and bounded value-producing loops now select one
existing branch and materialize its fixed stack slots once. This reuses
conventional branch lowering, aggregate copying, and loop-break representation;
it introduces no novel algorithm, ABI, protocol, cryptographic construction,
or optimization.

Patent review: `NOT_TRIGGERED` — ordinary aggregate control-flow lowering.

## 2026-08-23 — ordered tuple expression sequencing

MRML source: `crates/mrml-rustc/src/codegen.rs`.

Tuple materialization and field projection now evaluate an existing scalar
statement prefix once before consuming the tuple tail. This reuses conventional
expression sequencing and aggregate projection; it introduces no novel
algorithm, ABI, protocol, cryptographic construction, or optimization.

Patent review: `NOT_TRIGGERED` — ordinary expression sequencing.

## 2026-08-23 — bounded mutable tuple places

MRML source: `crates/mrml-rustc/src/parser.rs` and
`crates/mrml-rustc/src/codegen.rs`.

Numeric fields of mutable bounded scalar-tuple locals can now be assigned in
their existing fixed stack slots. This reuses conventional place parsing,
scalar compound assignment, and aggregate layout; it introduces no novel
algorithm, ABI, protocol, cryptographic construction, or optimization.

Verification used independent 398-byte COFF and 792-byte ELF64 objects across
Windows and Arch Linux callers.

Patent review: `NOT_TRIGGERED` — ordinary aggregate-place assignment.

## 2026-08-23 — structured bounded assignment places

MRML source: `crates/mrml-rustc/src/parser.rs` and
`crates/mrml-rustc/src/codegen.rs`.

Assignment targets now retain a base binding and an explicit bounded direct,
dereference, index, or numeric tuple-field projection instead of repeatedly
splitting the original target text. This is conventional compiler parsing and
place representation; it introduces no novel algorithm, ABI, protocol,
cryptographic construction, or optimization.

Patent review: `NOT_TRIGGERED` — ordinary compiler place representation.

## 2026-08-23 — monotonic runtime local identities

MRML source: `crates/mrml-rustc/src/codegen.rs`.

Runtime locals receive checked monotonic identities that remain distinct when
scope cleanup permits a fixed storage index to be reused. Assignment lowering
resolves a conventional typed base/projection record once and validates the
identity before a local store. This is ordinary compiler symbol/place handling;
it introduces no novel algorithm, ABI, protocol, cryptographic construction, or
optimization.

Patent review: `NOT_TRIGGERED` — ordinary compiler local/place identity.

## 2026-08-23 — explicit runtime place access intent

MRML source: `crates/mrml-rustc/src/codegen.rs`.

Resolved assignment places now distinguish a plain write from a
read-modify-write, and existing assignment emitters consume that classification
when deciding whether to load the previous value. This is conventional compiler
use/definition and place-access representation; it introduces no novel
algorithm, ABI, protocol, cryptographic construction, or optimization.

Patent review: `NOT_TRIGGERED` — ordinary compiler access classification.

## 2026-08-23 — signed buffered CPL3 service IPC

MRML source: `crates/mrml-kernel-image/src/main.rs`,
`crates/mrml-service-image/src/main.rs`,
`crates/mrml-kernel/src/arch/x86_64/context.rs`, and hosted launchers.

The signed service probe now performs bounded user-buffer validation, ordinary
capability-message delivery, blocked-receiver wakeup, address-space switching,
and directional copies. Hosted launchers provide supervisor-only page-table
self-mappings for the existing active walker. These are conventional syscall
marshalling, page-table access, scheduling, and IPC techniques; they introduce
no novel algorithm, ABI optimization, device protocol, codec, or cryptographic
construction.

Patent review: `NOT_TRIGGERED` — conventional bounded IPC and context switching.

## 2026-08-23 — bounded runtime body fact tables

MRML source: `crates/mrml-rustc/src/codegen.rs`.

Runtime emission now retains fixed-capacity monotonic local facts across stack-
slot reuse and source-ordered assignment-place access facts through final
invariant validation. This is conventional compiler symbol, type,
use/definition, and place bookkeeping; it introduces no novel algorithm, ABI,
protocol, cryptographic construction, or optimization.

Patent review: `NOT_TRIGGERED` — ordinary bounded compiler fact tables and
validation within the existing Rust-subset compiler category.

## 2026-08-23 — stable runtime identifier-read facts

MRML source: `crates/mrml-rustc/src/codegen.rs`.

Runtime identifier loads now append conventional read facts to the existing
bounded local/place table, reusing stable local or parameter identity across
ordinary scalar and specialized aggregate/address emission paths. This adds no
novel algorithm, ABI, protocol, cryptographic construction, or optimization.

Patent review: `NOT_TRIGGERED` — ordinary compiler use/definition bookkeeping
within the existing Rust-subset compiler category.

## 2026-08-23 — bounded source-independent place projections

MRML source: `crates/mrml-rustc/src/codegen.rs`.

Runtime place facts now retain a four-step fixed-capacity list of conventional
dereference, index, tuple-field, or subslice projections and validate each step
against the preceding type. Assignment facts and specialized local aggregate
reads reuse this representation. This adds no novel algorithm, ABI, protocol,
cryptographic construction, or optimization.

Patent review: `NOT_TRIGGERED` — ordinary bounded compiler place representation
and type validation within the existing Rust-subset compiler category.

## 2026-08-23 — bounded runtime read-place discovery

MRML source: `crates/mrml-rustc/src/codegen.rs`.

Runtime read syntax now peels conventional identifier, dereference, index,
tuple-field, subslice, and transparent expression forms into the existing
fixed-capacity place-projection representation. Direct scalar dereference
emission uses that result to avoid an empty duplicate base-read fact. This adds
no novel algorithm, ABI, protocol, cryptographic construction, or optimization.

Patent review: `NOT_TRIGGERED` — ordinary bounded compiler place/use discovery
within the existing Rust-subset compiler category.

## 2026-08-23 — standalone typed runtime body facts

MRML source: `crates/mrml-rustc/src/codegen.rs`.

Local and place-access facts now occupy a conventional fixed-capacity object
separate from machine-code buffers. A bounded pre-emission pass assigns types,
source spans, and monotonic identities to a supported straight-line declaration
prefix, while later expansion facts use a checked tail. This adds no novel
algorithm, ABI, protocol, cryptographic construction, or optimization.

Patent review: `NOT_TRIGGERED` — ordinary compiler symbol-table ownership,
preanalysis, and invariant checking within the existing Rust-subset compiler
category.

## 2026-08-23 — signed CPL3 configuration read dispatch

MRML source: `crates/mrml-config`, `crates/mrml-kernel`, the signed kernel and
service images, and the WHP/KVM hosted launch paths.

The signed service now decodes a conventional fixed-record configuration read,
asks the kernel to validate an opaque capability against exact rights and object
identity, and returns a fixed response through bounded IPC. Task-keyed blocked
receives, supervisor metadata mappings, verified-PE entry publication, and
lifecycle revocation reuse conventional syscall, capability, scheduling, page-
table, and hosted-launch techniques. This introduces no novel algorithm, ABI
optimization, device protocol, codec, or cryptographic construction.

Patent review: `NOT_TRIGGERED` — conventional capability RPC and hosted launch
integration.

## 2026-08-23 — signed CPL3 configuration commit dispatch

MRML source: `crates/mrml-config`, the signed kernel and service images, and the
WHP/KVM hosted launch paths.

The signed client encodes a conventional fixed-record one-update transaction,
transfers separate root and setting capabilities through the existing bounded
IPC mechanism, and the service performs ordinary exact-object authorization and
optimistic revision validation before an atomic in-memory update. The hosted
lifecycle proof repeats the operation after restoring a fresh volatile image.
This introduces no novel algorithm, ABI optimization, device protocol, codec,
or cryptographic construction.

Patent review: `NOT_TRIGGERED` — conventional capability RPC and bounded
transaction integration.

## 2026-08-23 — signed CPL3 configuration schema admission

MRML source: `crates/mrml-config`, the signed service image, and the WHP/KVM
hosted probe sequencing.

The service decodes a conventional fixed schema record for Boolean, bounded
integer, or bounded bytes values, checks ordinary duplicate/capacity/freeze
conditions, and requires exact root-control authorization before insertion into
a fixed array. The signed proof performs this ordinary RPC before the existing
commit RPC in each volatile service generation. This introduces no novel
algorithm, ABI optimization, device protocol, codec, or cryptographic
construction.

Patent review: `NOT_TRIGGERED` — conventional schema validation and capability
RPC integration.

## 2026-08-23 — bounded configuration checkpoint codec

MRML source: `crates/mrml-config`.

Configuration state is serialized into conventional fixed headers and records,
hashed with SHA3-256, and decoded into fresh fixed-capacity state only after
ordinary capability, length, uniqueness, constraint, revision, and sequence
checks. A separately supplied expected digest distinguishes the recovery input
from a self-checksummed record. This introduces no novel algorithm, storage
layout optimization, cryptographic construction, or recovery technique.

Patent review: `NOT_TRIGGERED` — conventional canonical serialization, hashing,
and defensive recovery validation.

## 2026-08-23 — scoped conditional compiler fact identities

MRML source: `crates/mrml-rustc`.

The bounded compiler prepass uses conventional lexical-scope copies and a
monotonic local-identity counter while visiting mutually exclusive conditional
branches in source emission order. This is ordinary compiler symbol-table and
definition bookkeeping and introduces no novel analysis algorithm, parser,
object format, ABI optimization, or persistent representation.

Patent review: `NOT_TRIGGERED` — ordinary compiler scope and definition
bookkeeping.

## 2026-08-23 — bounded assignment access expectations

MRML source: `crates/mrml-rustc`.

The compiler records conventional pre-resolved assignment use/definition facts
in a fixed-capacity table and compares them with assignment sites during its
existing emission traversal. A separate emitted-access ledger preserves actual
read/write order. This introduces no novel analysis algorithm, parser, object
format, ABI optimization, or persistent representation.

Patent review: `NOT_TRIGGERED` — ordinary compiler use/definition bookkeeping
and defensive invariant checking.

## 2026-08-23 — assignment root-place read expectations

MRML source: `crates/mrml-rustc`.

The compiler applies its existing bounded place-syntax discovery to assignment
RHS roots, resolves conventional symbol-table identities, and compares fixed-
capacity read expectations with the ordinary emission recorder. This introduces
no novel analysis algorithm, parser, object format, ABI optimization, or
persistent representation.

Patent review: `NOT_TRIGGERED` — ordinary compiler use bookkeeping and defensive
invariant checking.

## 2026-08-23 — bounded loop-scope compiler declaration facts

MRML source: `crates/mrml-rustc`.

The compiler mirrors its existing bounded emission traversal to perform
conventional symbol-table preanalysis across loop, nested-loop, conditional-arm,
and post-loop lexical scopes. It copies fixed-capacity environments at scope
boundaries and retains monotonically assigned definition identities. This
introduces no novel analysis algorithm, parser, object format, ABI optimization,
or persistent representation.

Patent review: `NOT_TRIGGERED` — ordinary compiler scope and definition
bookkeeping.

## 2026-08-23 — sequential top-level compiler declaration facts

MRML source: `crates/mrml-rustc`.

The compiler continues conventional bounded symbol-table preanalysis across
ordinary top-level statements and repeated lexical conditional scopes until its
existing loop boundary. It retains monotonic definition identities and copies
outer lexical environments for branches. This introduces no novel analysis
algorithm, parser, object format, ABI optimization, or persistent representation.

Patent review: `NOT_TRIGGERED` — ordinary compiler scope and definition
bookkeeping.

## 2026-08-23 — capability-native storage identity and metadata foundation

MRML source: `crates/mrml-storage`.

The userspace storage foundation uses conventional nonzero stable identifiers,
fixed-capacity generational capability tables, attenuated delegation with
parent-lineage revocation, and fixed versioned metadata records protected by a
SHA3-256 corruption checksum. Directory entries use bounded UTF-8 names and
object references; superblocks use ordinary monotonically chained generations.
This adds no novel filesystem algorithm, storage optimization, cryptographic
construction, on-disk tree, compression scheme, or recovery technique.

Patent review: `NOT_TRIGGERED` — conventional capability bookkeeping and
defensive fixed-record filesystem metadata.

## 2026-08-23 — bounded native extent mapping

MRML source: `crates/mrml-storage/src/extent.rs`.

The storage service uses conventional fixed extent records, explicit sparse
holes, ordered logical coverage, linear bounded lookup, physical range checks,
and SHA3-256 corruption digests. It reserves unknown record kinds without
implementing compression, encryption, sharing, deduplication, allocation, or a
novel on-disk tree. This adds no novel filesystem algorithm, storage
optimization, cryptographic construction, or recovery technique.

Patent review: `NOT_TRIGGERED` — conventional extent validation and sparse-file
mapping.

## 2026-08-23 — checksummed COW metadata publication planning

MRML source: `crates/mrml-storage/src/cow.rs`.

The storage service uses conventional copy-on-write ordering: validate and
checksum new unreachable metadata, flush it, atomically replace an inactive
redundant superblock, and flush again. It distinguishes clean failures before
root replacement from uncertain failures afterward. This adds no novel
filesystem tree, allocation algorithm, storage optimization, cryptographic
construction, or recovery technique.

Patent review: `NOT_TRIGGERED` — conventional checksummed copy-on-write metadata
publication ordering.

## 2026-08-23 — capability-authorized bounded directory operations

MRML source: `crates/mrml-storage/src/directory.rs` and the storage authority
and metadata modules.

The service uses conventional fixed-capacity directory tables, monotonic object
identifiers, per-operation capability checks, preflight-before-mutation updates,
stable-identity rename, namespace unlink, and cross-directory file movement.
Cross-directory directory movement is deliberately rejected without ancestry
proof. This adds no novel filesystem tree, lookup algorithm, namespace
optimization, cryptographic construction, or recovery technique.

Patent review: `NOT_TRIGGERED` — conventional capability-checked directory
bookkeeping.

## 2026-08-23 — bounded verified native file reads

MRML source: `crates/mrml-storage/src/file.rs` and the extent/authority modules.

The service uses conventional capability-checked range reads, linear extent
resolution, sparse-hole zero filling, SHA3-256 data verification, bounded
buffers, and partial-output erasure on verification failure. This adds no novel
filesystem tree, caching strategy, read optimization, cryptographic
construction, device protocol, or recovery technique.

Patent review: `NOT_TRIGGERED` — conventional checksummed extent reads.

## 2026-08-23 — bounded COW native file writes

MRML source: `crates/mrml-storage/src/file.rs` and the extent/COW/metadata
modules.

The service uses conventional capability-checked range writes, complete
successor extent maps, copy-on-write physical separation, checksum verification,
whole-file and canonical extent-list hashing, data-before-metadata flush
ordering, and inactive-superblock publication. This adds no novel filesystem
tree, allocation algorithm, write optimization,
cryptographic construction, device protocol, or recovery technique.

Patent review: `NOT_TRIGGERED` — conventional checksummed copy-on-write file
updates.

## 2026-08-23 — bounded multi-file COW transactions

MRML source: `crates/mrml-storage/src/transaction.rs` and the file/COW modules.

The service uses conventional fixed-capacity transaction admission, duplicate
participant/range rejection, one copy-on-write root publication, and one-use
in-memory participant receipts. Object metadata generations remain distinct
from the volume publication generation. This adds no novel commit protocol,
filesystem tree, allocation algorithm, cryptographic construction, device
protocol, or recovery technique.

Patent review: `NOT_TRIGGERED` — conventional bounded transaction batching.

## 2026-08-23 — redundant COW root recovery selection

MRML source: `crates/mrml-storage/src/recovery.rs` and the canonical superblock
format.

The service uses conventional redundant checksummed superblocks, complete-tree
validation callbacks, generation comparison, corruption fallback, and
fail-closed rejection of inconsistent or indeterminate state. This adds no
novel recovery algorithm, filesystem tree, repair method, cryptographic
construction, device protocol, or anti-rollback technique.

Patent review: `NOT_TRIGGERED` — conventional redundant-root selection.

## 2026-08-23 — canonical allocation ownership index

MRML source: `crates/mrml-storage/src/allocation.rs`.

The service uses conventional checksummed allocation records, physical ordering,
reserved-range exclusion, global overlap rejection, and exact owner/generation/
kind lookups. This adds no novel allocator, free-space structure, filesystem
tree, recovery method, cryptographic construction, or storage optimization.

Patent review: `NOT_TRIGGERED` — conventional allocation ownership bookkeeping.

## 2026-08-23 — canonical allocation metadata image

MRML source: `crates/mrml-storage/src/allocation.rs`.

The service uses a conventional versioned image header, fixed-width allocation
records, whole-image SHA3-256 corruption detection, zero padding, and bounded
decode that reconstructs the allocation index. This adds no novel persistent
format, allocator, recovery method, cryptographic construction, or storage
optimization.

Patent review: `NOT_TRIGGERED` — conventional checksummed allocation metadata.

## 2026-08-23 — canonical extent metadata images

MRML source: `crates/mrml-storage/src/extent.rs` and allocation ownership types.

The service uses a conventional versioned extent-list header, fixed-width
checksummed records, whole-image SHA3-256 corruption detection, zero padding,
and reconstruction of bounded extent-map invariants. Allocation metadata uses a
separate conventional ownership tag. This adds no novel extent structure,
allocator, recovery method, cryptographic construction, or storage optimization.

Patent review: `NOT_TRIGGERED` — conventional checksummed extent-list metadata.

## 2026-08-23 — bounded reachable storage validation

MRML source: `crates/mrml-storage/src/recovery.rs`, `directory.rs`, and the
allocation/extent metadata modules.

The service uses conventional fixed-capacity graph traversal, versioned
checksummed directory-entry images, parent/generation consistency checks, exact
allocation ownership, duplicate-reference rejection, and orphan-allocation
rejection. This adds no novel filesystem graph, recovery algorithm, allocator,
cryptographic construction, or storage optimization.

Patent review: `NOT_TRIGGERED` — conventional filesystem consistency traversal.

## 2026-08-23 — integrated redundant-root recovery simulation

MRML source: `crates/mrml-storage/src/recovery.rs`.

The service composes conventional redundant-root selection with bounded
filesystem consistency validation, deterministic fault injection, and a
volatile/durable cut-point model of metadata flush, root replacement, and final
flush. It falls back from proven-invalid unpublished metadata, aborts on
indeterminate I/O, and admits only old or fully metadata-durable new state after
uncertain publication. This adds no novel recovery algorithm, persistence
protocol, fault-injection method, cryptographic construction, or storage
optimization.

Patent review: `NOT_TRIGGERED` — conventional recovery fault simulation.

## 2026-08-23 — bounded allocation successor planning

MRML source: `crates/mrml-storage/src/allocation.rs`.

The service uses conventional copy-on-write allocation-table reconstruction,
exact free/allocate changes, sorted records, active-range exclusion, generation
advancement, and allocation-image rotation. This adds no novel allocator,
free-space structure, transaction protocol, recovery algorithm, cryptographic
construction, or storage optimization.

Patent review: `NOT_TRIGGERED` — conventional COW allocation bookkeeping.

## 2026-08-23 — staged transactional allocation images

MRML source: `crates/mrml-storage/src/allocation.rs` and `transaction.rs`.

The service uses conventional complete-image staging, SHA3-256 corruption
detection, durable flush ordering, typed transaction participants, exact COW
plan membership, and one-use commit receipts. This adds no novel allocator,
transaction protocol, persistence technique, cryptographic construction, or
storage optimization.

Patent review: `NOT_TRIGGERED` — conventional transactional metadata staging.

## 2026-08-23 — bounded assignment-expression read traversal

MRML source: `crates/mrml-rustc/src/codegen.rs`.

The compiler performs a conventional bounded recursive syntax traversal in the
same operand order as code emission and stores resolved reads in fixed-capacity
fact tables. This adds no novel parsing, ownership, borrowing, optimization,
code-generation, or compiler-analysis technique.

Patent review: `NOT_TRIGGERED` — conventional compiler fact collection.

## 2026-08-23 — typed assignment-index read planning

MRML source: `crates/mrml-rustc/src/codegen.rs`.

The compiler uses conventional expression typing and constant evaluation to
select the same fixed-capacity read-fact order as its existing reference and
array-index lowering paths. This adds no novel type system, array
representation, bounds check, optimization, or compiler-analysis technique.

Patent review: `NOT_TRIGGERED` — conventional type-directed compiler traversal.

## 2026-08-23 — staged transactional directory images

MRML source: `crates/mrml-storage/src/directory.rs` and `transaction.rs`.

The service uses conventional canonical directory metadata and entry-list
encoding, SHA3-256 corruption detection, copy-on-write staging, durable flush
ordering, exact transaction membership, and one-use publication receipts. This
adds no novel namespace structure, transaction protocol, persistence technique,
cryptographic construction, or storage optimization.

Patent review: `NOT_TRIGGERED` — conventional transactional directory metadata
staging.

## 2026-08-23 — bounded directory ancestry proof

MRML source: `crates/mrml-storage/src/directory.rs`.

The service performs a conventional fixed-capacity parent-chain walk over one
immutable filesystem generation, binds the moved directory's exact generation
and source parent, retains bounded source and destination ancestor paths with
each node's exact canonical generation, and merges them into a conventional
deduplicated child-before-parent worklist. Duplicate objects must agree on both
generation and depth. It
rejects cycles, repeated objects, stale state, broken
links, backend uncertainty, and capacity exhaustion before a directory move.
It then uses conventional immutable predecessor loading, fixed-capacity arrays,
entry removal/insertion, and bottom-up generation replacement to construct the
complete in-memory successor worklist through the root.
It preflights conventional disjoint COW output ranges, stages canonical images
in dependency order, and admits their typed participants to one bounded
transaction. Conventional allocation-record membership checks, COW-plan
construction, and atomic one-use receipt consumption bind and activate the
complete simulated update.
This adds no novel namespace structure, graph algorithm,
transaction protocol, cryptographic construction, or storage optimization.

Patent review: `NOT_TRIGGERED` — conventional bounded filesystem ancestry
validation.

## 2026-08-23 — transactional stable object-ID allocator image

MRML source: `crates/mrml-storage/src/object_id_allocator.rs` and
`transaction.rs`.

The service uses a conventional monotonic integer allocator, canonical
checksummed COW image, disjoint successor staging, typed transaction resource,
one-use activation receipt, and inactive generational authority-slot
reservation. This adds no novel identity-allocation,
persistence, transaction, cryptographic, or storage technique.

Patent review: `NOT_TRIGGERED` — conventional persistent monotonic allocator
metadata.

## 2026-08-23 — exact allocator-metadata allocation ownership

MRML source: `crates/mrml-storage/src/allocation.rs` and
`object_id_allocator.rs`.

The service uses a conventional purpose tag and exact owner, generation, and
range comparison to require that a staged object-ID allocator image is present
in the prepared allocation index. The root object is only a conventional
lifetime-accounting anchor and does not authorize access. This adds no novel
allocation, identity, capability, persistence, or cryptographic technique.

Patent review: `NOT_TRIGGERED` — conventional exact allocation bookkeeping.

## 2026-08-23 — grouped create receipt consumption

MRML source: `crates/mrml-storage/src/transaction.rs`.

The transaction receipt conventionally preflights two bounded participant
groups for presence and duplicates before clearing the complete set. This adds
no novel transaction, capability, filesystem, or persistence technique.

Patent review: `NOT_TRIGGERED` — conventional atomic receipt bookkeeping.

## 2026-08-23 — complete prepared storage create assembly

MRML source: `crates/mrml-storage/src/create.rs` and its existing directory,
file, allocation, allocator, authority, COW, and transaction primitives.

The service conventionally groups a staged parent-directory closure, empty
child metadata, monotonic object-ID successor, allocation-index successor, and
inactive capability-table slot into one copy-on-write transaction. It checks
exact identity, type, generation, range, purpose, and receipt membership before
exposing state or activating the handle. This adds no novel filesystem-create,
allocation, capability, transaction, or persistence technique.

Patent review: `NOT_TRIGGERED` — conventional transactional create assembly.

## 2026-08-23 — reachable object-ID allocator recovery validation

MRML source: `crates/mrml-storage/src/recovery.rs` and the canonical allocator
and allocation formats.

The recovery validator conventionally requires one purpose-tagged allocator
allocation, decodes its canonical generation-bound image, and compares a
concrete next integer with the maximum reachable object integer to prevent
reuse. Missing, duplicate, corrupt, stale, or substituted state is rejected;
exhaustion remains valid. This adds no novel recovery, allocation, identity,
transaction, or cryptographic technique.

Patent review: `NOT_TRIGGERED` — conventional allocator recovery validation.

## 2026-08-23 — exact directory-create parent binding

MRML source: `crates/mrml-storage/src/directory.rs` and `create.rs`.

The service conventionally retains the parent encoded in new directory
metadata, compares it with the unique parent successor containing the new
generation-1 namespace entry, and returns that parent with committed state.
This adds no novel directory, namespace, capability, transaction, or persistence
technique.

Patent review: `NOT_TRIGGERED` — conventional directory parent validation.

## 2026-08-23 — full-range primary-metadata COW digests

MRML source: `crates/mrml-storage/src/cow.rs`, `file.rs`, and `directory.rs`.

The service conventionally hashes a fixed metadata record followed by zero
padding through its exact block-aligned storage range. This makes the staged
digest cover the same canonical bytes recovery reads. This adds no novel
encoding, hashing, filesystem, transaction, or persistence technique.

Patent review: `NOT_TRIGGERED` — conventional zero-padded image hashing.

## 2026-08-23 — interrupted create publication recovery simulation

MRML source: `crates/mrml-storage/src/create.rs` using the existing COW and
reachable-recovery primitives.

The test model conventionally separates staged metadata and redundant
superblocks, injects failure at each publication operation, models the two
permitted atomic-replacement persistence outcomes, and validates either the old
or complete new filesystem graph. Capability activation still requires a
successful receipt. This adds no novel crash-recovery, filesystem, transaction,
capability, or persistence technique.

Patent review: `NOT_TRIGGERED` — conventional cut-point recovery simulation.

## 2026-08-23 — recovered child capability derivation

MRML source: `crates/mrml-storage/src/authority.rs`, `directory.rs`, and
`create.rs`.

The service conventionally requires an explicit parent-directory right before
opening a named recovered child, validates kind-specific requested rights, and
records the child handle as a generational descendant for transitive
revocation. Transactional create reservations retain and revalidate the same
parent lineage. This adds no novel capability, namespace, recovery, or
revocation technique.

Patent review: `NOT_TRIGGERED` — conventional capability derivation and
revocation lineage.

## 2026-08-23 — exact-block metadata adapter

MRML source: `crates/mrml-storage/src/block.rs`.

The service conventionally adapts canonical metadata images to exact block
writes, verifies SHA3-256 by complete readback, orders flushes before and after
atomic inactive-superblock replacement, supplies exact recovery reads, and
poisons a session after uncertain replacement durability. This adds no novel
block protocol, filesystem, persistence, hashing, recovery, or fail-stop
technique.

Patent review: `NOT_TRIGGERED` — conventional checked block-I/O adaptation.

## 2026-08-23 — exact-block file-data adapter

MRML source: `crates/mrml-storage/src/block.rs` and the crate-private
`FileState` extent-map accessor in `crates/mrml-storage/src/file.rs`.

The service conventionally verifies a complete extent before a subrange read,
reconstructs copy-on-write successor blocks from verified predecessor data,
holes, and patch bytes, verifies complete staged extents by readback, checks the
complete logical-file digest, and flushes once. This adds no novel filesystem,
copy-on-write, block-I/O, hashing, reconstruction, or persistence technique.

Patent review: `NOT_TRIGGERED` — conventional verified file-data adaptation.

## 2026-08-23 — capability-bound block-service core

MRML source: `crates/mrml-storage/src/block_service.rs`.

The service conventionally registers device descriptors, authorizes exact block
operations with principal-bound generational handles and attenuable rights,
revokes derived sessions transitively, validates aligned bounded transfers, and
adapts calls to a device backend. This adds no novel capability, block-service,
device protocol, revocation, transport, or persistence technique.

Patent review: `NOT_TRIGGERED` — conventional capability-controlled block
service dispatch.

## 2026-08-23 — versioned block-service control codec

MRML source: `crates/mrml-storage/src/block_protocol.rs`.

The service conventionally encodes fixed-size versioned request/response
records, uses separately authorized buffers for bulk I/O, correlates requests
with monotonic per-session identifiers, rejects replay, and fail-stops a session
after uncertain mutating I/O. This adds no novel IPC, serialization, block,
capability-transfer, replay-protection, or fail-stop technique.

Patent review: `NOT_TRIGGERED` — conventional bounded control protocol.

## 2026-08-23 — exact received-buffer capability shape

MRML source: `crates/mrml-kernel/src/{capability,ipc}.rs` and
`crates/mrml-storage/src/block_protocol.rs`.

The kernel conventionally requires zero capabilities or one live transferred
capability with an exact rights set before returning its object identity, while
the service protocol labels whether the service reads, writes, or uses no bulk
buffer. This adds no novel IPC, capability, shared-memory, block-service, or
authorization technique.

Patent review: `NOT_TRIGGERED` — conventional exact capability authorization.

## 2026-08-23 — received capability to shared-binding resolution

MRML source: `crates/mrml-kernel/src/{ipc,shared_memory}.rs`.

The kernel conventionally composes exact receiver-capability authorization with
an exact live shared-memory binding check and returns an opaque resource handle
only after object, endpoint, access, mapping generation, and range agreement.
This adds no novel IPC, capability, shared-memory, mapping, or resource-handle
technique.

Patent review: `NOT_TRIGGERED` — conventional authorized mapping resolution.

## 2026-08-23 — canonical empty child creation images

MRML source: `crates/mrml-storage/src/file.rs`, `directory.rs`, and
`transaction.rs`.

The service conventionally encodes and stages empty generation-1 file/extent
or directory/entry image pairs and labels their typed transaction participant
as object creation. It uses a conventional bounded parent-chain walk and
bottom-up directory-entry generation replacement to construct the affected
ancestor successors, then applies the existing conventional disjoint COW
staging and typed transaction admission. This adds no novel filesystem object, empty-file,
transaction, persistence, or encoding technique.

Patent review: `NOT_TRIGGERED` — conventional initial filesystem-object
metadata.

## 2026-08-23 — scalar initializer and expression-statement read planning

MRML source: `crates/mrml-rustc/src/codegen.rs`.

The compiler applies its existing bounded recursive expression visitor before
binding activation and across supported scoped expression statements, retaining
stable local identities and emitter order in fixed-capacity fact tables. This
adds no novel parsing, ownership, borrowing, optimization, code-generation, or
compiler-analysis technique.

Patent review: `NOT_TRIGGERED` — conventional bounded compiler fact collection
and source-order traversal.

## 2026-08-23 — authorized opaque shared-buffer I/O

MRML source: `crates/mrml-kernel/src/{ipc,shared_memory}.rs`.

The kernel conventionally repeats exact receiver-capability and live
shared-binding validation before a bounded read or write through an opaque
resource handle. Checked ranges, read-only enforcement, and explicit backend
errors add no novel IPC, capability, mapping, or buffer-I/O technique.

Patent review: `NOT_TRIGGERED` — conventional authorized bounded I/O.

## 2026-08-23 — authenticated shared-binding selection

MRML source: `crates/mrml-kernel/src/{ipc,shared_memory}.rs`.

The kernel conventionally selects exactly one bounded table entry by an
already-authorized object plus kernel-known VM/task identity and access mode,
then applies its existing live-binding checks before opaque-handle I/O. Missing
or duplicate matches are rejected. This adds no novel capability, lookup,
mapping, or resource-selection technique.

Patent review: `NOT_TRIGGERED` — conventional bounded authorized lookup.

## 2026-08-23 — capability-bound block transport composition

MRML source: `crates/mrml-storage/src/{block_protocol,kernel_transport}.rs`
and `crates/mrml-kernel/src/ipc.rs`.

The storage service conventionally separates replay/poison admission from
execution, copies exact capability-authorized buffer ranges through bounded
caller scratch, erases scratch after use, and dispatches an existing versioned
block protocol. This adds no novel IPC, capability, admission, block-I/O, or
buffer-copy technique.

Patent review: `NOT_TRIGGERED` — conventional authorized service dispatch.

## 2026-08-23 — capability-selected shared-buffer syscall ABI

MRML source: `crates/mrml-kernel/src/syscall.rs` and
`crates/mrml-kernel-image/src/main.rs`.

The kernel conventionally decodes opaque capability, offset, userspace address,
and bounded length fields for read/write copy operations, rejects noncanonical
or overflowing ranges, and leaves unsupported execution fail-closed. This adds
no novel syscall, capability, shared-memory, or bounded-copy technique.

Patent review: `NOT_TRIGGERED` — conventional bounded syscall validation.

## 2026-08-23 — shared-buffer syscall execution composition

MRML source: `crates/mrml-kernel/src/shared_buffer_syscall.rs` and
`task_runtime.rs`.

The kernel conventionally combines task-local capability lookup, live binding
resolution, direction-validated userspace copies, opaque-handle resource I/O,
and erased bounded scratch. This adds no novel syscall, capability, user-copy,
shared-memory, or buffer-erasure technique.

Patent review: `NOT_TRIGGERED` — conventional authorized copy composition.

## 2026-08-23 — active-page shared-buffer user copy

MRML source: `crates/mrml-kernel/src/arch/x86_64/active_user_copy.rs` and
`shared_buffer_syscall.rs`.

The x86-64 adapter conventionally binds an active page-table range validation
to one exact task/address/length/direction copy, consumes or cancels that ticket,
and performs a bounded direct copy while address-space mutation is excluded.
This adds no novel page-table, syscall, ticket, or user-copy technique.

Patent review: `NOT_TRIGGERED` — conventional validated active-memory copy.

## 2026-08-23 — bounded opaque host-resource table

MRML source: `crates/mrml-kernel/src/host_resource.rs`.

The kernel conventionally assigns monotonic opaque handles to fixed-capacity
resource entries, rejects live aliases and stale handles, checks transfer bounds
before an internal backend copy, and removes entries through an existing
retirement hook. Raw supervisor addresses remain behind an explicit unsafe
adapter. This adds no novel handle-table, bounds-checking, revocation, or memory-
copy technique.

Patent review: `NOT_TRIGGERED` — conventional bounded resource indirection.

## 2026-08-23 — active service mapping revocation adapter

MRML source: `crates/mrml-kernel/src/{vm,shared_memory}.rs` and
`crates/mrml-kernel/src/arch/x86_64/page_table.rs`.

Shared cleanup conventionally consumes a narrow native mapping-removal
interface. The x86-64 service adapter binds one active root and exact mapping,
preflights the complete old leaf identity and permissions, clears the leaves,
and invalidates local translations. This adds no novel page-table, revocation,
capability, or service-lifecycle technique.

Patent review: `NOT_TRIGGERED` — conventional exact mapping teardown.

## 2026-08-23 — hosted observation of kernel-side leaf retirement

MRML source: `crates/mrml-kernel/src/arch/x86_64/page_table.rs` and
`crates/mrml-{kvm,whp}/src/native/launch.rs`.

KVM and WHP conventionally verify that every leaf in one recorded service
mapping is absent before updating host live/re-arm bookkeeping after kernel-side
retirement. This adds no novel page-table, revocation, synchronization, or
service-lifecycle technique.

Patent review: `NOT_TRIGGERED` — conventional absent-mapping verification.

## 2026-08-24 — per-service hosted resource-page lifecycle

MRML source: `crates/mrml-{kvm,whp}/src/native/launch.rs` and
`crates/mrml-{kvm,whp}-run/src/main.rs`.

KVM and WHP conventionally install a separately backed page into one selected
service root, reject address aliases with other recorded pages, track revoke and
restore state, and erase backing before re-arm. This adds no novel page-table,
memory-sharing, lifecycle, or zeroization technique. The hosted runners
conventionally schedule those transitions around receiver cleanup/restart.

Patent review: `NOT_TRIGGERED` — conventional isolated page lifecycle.

## 2026-08-24 — kernel-image service-resource composition

MRML source: `crates/mrml-kernel-image/src/main.rs`,
`crates/mrml-service-image/src/main.rs`, and
`crates/mrml-{kvm,whp}-run/src/main.rs`.

The kernel conventionally provisions a task-local attenuated capability, binds
one non-executable page to an opaque resource, dispatches bounded validated
copies, and composes exact active-leaf, binding, and final-handle retirement
before host observation and zeroed generation re-arm. The service source
conventionally checks zero-before-use and bounded write/read behavior. This adds
no novel capability, syscall, page-table, zeroization, or lifecycle technique.

Patent review: `NOT_TRIGGERED` — conventional authorized resource lifecycle.

## 2026-08-24 — exact service-resource operation capabilities

MRML source: `crates/mrml-kernel/src/shared_memory.rs`,
`crates/mrml-kernel-image/src/main.rs`, and
`crates/mrml-service-image/src/main.rs`.

The hosted service conventionally uses separate exact read and read/write
capabilities for one non-executable bound page. Binding selection allows only a
requested access that the established endpoint already permits, while message
authorization still requires the exact per-operation capability shape. This
adds no novel capability-attenuation, shared-memory, or syscall technique.

Patent review: `NOT_TRIGGERED` — conventional least-authority separation.
