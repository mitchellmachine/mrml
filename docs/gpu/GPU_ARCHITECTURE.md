# MRML native GPU architecture

**Status: PLANNED.** Existing mediated CUDA/VGPU mechanisms remain experimental
and do not implement this complete API. VirtualGPU is GPU priority 1; native
NVIDIA Blackwell is priority 2; AMD and Intel follow; broader Vulkan/WebGPU/CUDA
compatibility follows the native object/security foundation.

MRML has a native capability-oriented GPU API. Vulkan, CUDA, Direct3D, OpenCL,
ROCm, WebGPU, and vendor driver APIs do not define MRML authority.

```text
applications / compositor / compute / media
  -> MRML GPU API
  -> capability objects
  -> validated semantic IR
  +-> VirtualGPU
  +-> native AMD / NVIDIA / Intel backends
```

> Possessing access to a device does not imply possessing every function or
> every resource of that device.

> Native MRML GPU software must not require CUDA.

## Authority and objects

`GpuDomain` is the normal capability-derived authority unit. Independently
attenuable rights include graphics, transfer, compute, matrix, ray tracing,
decode, encode, video process, present, peer memory, RDMA export, self/device
profiling, and advanced placement. Limits separately bound device/shared memory,
queues, execution budget, priority, media sessions, resident work, and peers.
Unknown rights fail closed.

Conceptual children are `GpuAddressSpace`, `MemoryPool`, typed `Buffer`, `Image`,
`Tensor`, typed queues, shader/compute modules, pipelines, `CommandGraph`,
`Timeline`, surfaces/presentation, media sessions, and peer/fabric links. Names
are not frozen ABI. Generational identity and capability lineage are normative.

Rendering does not grant compute, encoding, profiling, screen capture, other-
window reads, raw display, or trusted-surface reads. Decode does not grant encode
or capture. `Surface.RENDER`, `Display.PRESENT`, and `Surface.READ_CONTENT` are
distinct; the compositor owns final presentation.

Domain revocation invalidates mappings, queues, children, submissions, peers,
DMA/IOMMU state, media/profiling sessions, and stale guest handles before reuse.
Device loss advances exact generation; applications receive typed loss and
recreate resources. One crash and one compromise remain contained.

## Safe application and kernel model

Ordinary applications use typed generational objects, not physical addresses,
vendor packets, arbitrary MMIO, `void*`, or unsafe native code. Raw instructions,
addresses, and vendor streams require a privileged audited profile.

The planned `mrml-rustc` GPU-safe subset models bounds, ownership, immutable
sharing, exclusive mutation, atomics, synchronization, workgroup memory, and
explicit private/workgroup/device/constant/host-visible/peer address spaces.
Cross-space conversion is explicit. Data races do not become accepted undefined
behavior in the ordinary safe profile; unsupported proofs fail closed. Do not
claim memory safety before compiler/runtime enforcement exists.

Compiler-generated module metadata declares features, address spaces, subgroup,
shared-memory bound, writes, atomics, matrix/ray/device-address/media use. Runtime
admission proves requirements are a subset of device features and `GpuDomain`
authority; applications do not self-certify.

The compiler lane proceeds only after current CPU typed-place/CFG/ownership work:
GPU-safe subset, address spaces, launch model, typed GPU High IR, GPU Machine IR,
VirtualGPU/reference backend, Blackwell, then AMD/Intel specialization. GPU work
must not derail the present CPU ownership/Polonius dependency path.

## Execution, memory, and synchronization

Reusable validated `CommandGraph` is preferred for copy, render, compute, matrix,
reduction, media, and dependencies. Backends may precompile and repeat graphs,
eliminate barriers, overlap engines, and place work topologically. Applications
do not reproduce vendor barrier machinery.

Monotonic timelines are the principal inter-queue primitive; binary events may be
derived. Memory requests describe properties such as device-local, host-visible,
coherent, shared, transient, persistent, graph-local, and preferred device plus
typed usage. Vendor heap/tiling/compression choices remain backend policy unless
advanced-placement authority is present.

Every domain has a separate revocable GPU VA space. VA, host/device mappings,
pinned/shared memory, and peer mappings are bounded and generational. GPU compute
never implies arbitrary physical DMA. IOMMU mappings derive from domain memory
authority and complete invalidation before protected reuse.

First-class tensors carry type, shape, strides, layout, quantization, sparsity,
backing, and placement. The portable High IR covers scalar/vector/subgroup/
workgroup/matrix operations, reductions, async copies, barriers, atomics, tensor
layouts, and address spaces; Machine IR specializes for vendors. No vendor ISA is
portable IR.

Portable subgroups are not hard-coded to warp 32. Backends advertise widths and
lane/subgroup/workgroup/optional cluster/grid/device-group scopes. The model
supports async transfers, prefetch, staging/double buffering, typed workgroup
memory, atomics, matrix formats, and specialization without reducing hardware to
the lowest common denominator.

## Graphics, media, scheduling, and fabric

Optional features include classic and mesh/task graphics, indirect/GPU-generated
work, ray objects, sampling/compression, and hardware presentation. Baseline
desktop support does not require ray tracing. Decode, encode, and video process
remain distinct media engines and capabilities.

Zero-copy presentation delegates a bounded presentation view of an owned image
to the compositor without transferring readback or scanout authority. AI visual/
media inspection remains separately capability-controlled and accessibility
semantics remain independent of framebuffer authority.

Budgets cover time, queues, priority, preemptibility, memory, and latency class so
AI compute cannot freeze the compositor. `PROFILE_SELF` differs from potentially
cross-domain-leaking `PROFILE_DEVICE`.

Multi-GPU uses explicit topology/fabric and peer capabilities; GPU A compute does
not imply GPU B memory. RDMA requires the buffer, RDMA-export, and NIC-queue
capabilities together plus IOMMU enforcement. Vendor/device-generation feature
namespaces may optimize but never widen authority.

## Progressive backend profiles

- GPU-0 TRANSFER: admit, memory, map/unmap, copy/fill, timeline, reset.
- GPU-1 DESKTOP: images, sampling, rendering/blending, compositor presentation.
- GPU-2 COMPUTE: general compute, workgroup memory, atomics, subgroups, indirect.
- GPU-3 MATRIX: native tensor/matrix formats and memory optimization.
- GPU-4 ADVANCED GRAPHICS: mesh/task, ray tracing, acceleration structures.
- GPU-5 MEDIA: decode, encode, processing.
- GPU-6 FABRIC: peer memory, topology, RDMA/direct integration.

A backend can accelerate the desktop before advanced AI/media/ray/fabric work.
Feature discovery is typed structured data, not an uncontrolled extension-string
authority channel.

## Security, recovery, and evidence

Fuzz object tables, ranges/shapes, graphs/cycles, bindings, timelines, pipeline/
module/IR/tensor/media metadata, topology, budgets, rights, stale generations,
overflow, exhaustion, and native packet construction. Driver services receive
only exact MMIO, interrupt, IOMMU/DMA, firmware, reset, and PCI capabilities.
Unsafe register/DMA wrappers remain tiny, explicit, audited, and separate from
policy. Vendor-signed firmware establishes policy origin/integrity, not
correctness, and remains an explicit TCB component.

GPU failure falls back to software/GOP, preserves semantic/Braille/speech control,
resets/restarts the service, rebuilds compositor resources, and returns to
acceleration only when safe.

Evidence records exact environment, model, firmware/GSP, backend/compiler,
commands, outcomes, unsupported features, performance, reset, and isolation.
Distinguish `HOSTED`, `VIRTUALGPU`, and `NATIVE PHYSICAL` plus the repository's
goal/implemented/tested/measured/audited/proven vocabulary. Virtual evidence is
not physical DMA/IOMMU proof. Kernel launch does not establish CUDA replacement;
distinguish API, native kernels, optimized libraries, measured parity, and
ecosystem competitiveness.

Patent review: `TRIGGERED` — the planned GPU API, IR, VirtualGPU, native drivers,
media/fabric, and compatibility mechanisms require targeted worldwide review
before implementation. See [`../patents/REVIEW_LOG.md`](../patents/REVIEW_LOG.md).
