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
