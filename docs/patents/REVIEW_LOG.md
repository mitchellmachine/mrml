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
