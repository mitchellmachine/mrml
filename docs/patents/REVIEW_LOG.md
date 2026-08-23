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

## 2026-08-23 — diverging Rust helper signatures

MRML source: `crates/mrml-rustc/src/{expression,codegen,pipeline}.rs`.

Safe inlined Rust helpers may declare the never return type when their existing
bounded body representation proves an unconditional diverging loop. Call-site
typing applies ordinary bottom-type coercion and reuses the existing loop
backedge and inline-frame bookkeeping; no new control-flow algorithm, ABI,
protocol, cryptographic construction, or optimization is introduced.

Patent review: `NOT_TRIGGERED` — conventional never-type propagation over
existing bounded compiler control flow.
