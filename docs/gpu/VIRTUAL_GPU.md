# MRML VirtualGPU

**Status: PLANNED. Priority: GPU #1.** Existing mediated GPU/CUDA queues remain
compatible work but are not this complete native object transport.

VirtualGPU projects a host-owned `GpuDomain` through the common native object
model. It never exposes host pointers, handles, VAs, packets, or wider authority.
Blackwell work must not delay this semantic/transport gate.

> A GPU abstraction that cannot be represented cleanly and securely across the
> VirtualGPU boundary requires additional scrutiny before becoming part of the
> portable MRML API.

The VirtIO-like, transport-independent protocol follows
[`../PARAVIRTUAL_DEVICES.md`](../PARAVIRTUAL_DEVICES.md). Bounded CONTROL,
SUBMISSION, COMPLETION, and EVENT queues and shared generational object tables
carry create/destroy buffer/image/tensor/pipeline/graph, map/unmap, submit, wait-
timeline, loss/reset, and presentation operations. Batch semantic graphs rather
than trapping for each low-level operation. The wire carries compact object and
resource metadata, immutable/versioned module, pipeline, and graph references,
submissions, timelines, presentation, and media requests—not repeated state,
packets, host handles, or addresses. Creation/authority projection remains
understandable, submission auditable, and messages independently fuzzable. A
giant hardware-specific wire protocol triggers abstraction redesign.

Guest requests, IDs, offsets, graphs, shader metadata, timelines, tensor shapes,
and claimed features are hostile. Host policy projects exact rights and budgets;
the guest cannot manufacture encode, device profiling, peer memory, VRAM, time,
or any unknown right. Reset/hotplug advances generation and invalidates objects,
mappings, submissions, timelines, and descendants. Uncertain mutation or
completion fails closed and is never blindly replayed.

KVM and WHP use identical common policy. Hosted/reference backends may initially
implement GPU-0 transfer, compute, rendering, timelines, accounting, and reset;
later physical backends use the same protocol. VirtIO-GPU display compatibility
may coexist but does not replace the MRML API or signed-kernel CUDA channel.

The first completion gate runs under both KVM and WHP: negotiate a bounded
domain; create/destroy buffers and an image; transfer; basic compute and render;
timeline synchronization; reusable graph; authorized presentation; enforced
VRAM/time limits; malformed rejection; reset/loss; stale-handle denial; and proof
that guest authority cannot exceed host projection. Run the same semantic suite
through a hosted/reference backend. This gate precedes native Blackwell.

Patent review: `TRIGGERED`; see
[`../patents/REVIEW_LOG.md`](../patents/REVIEW_LOG.md).
