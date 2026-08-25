# MRML capability-bound memory resources

**Status: PLANNED**, except for existing generational address-space mappings,
shared-page bindings, lifecycle cleanup, and revocation mechanisms documented in
the implementation ledger. This document does not claim quantitative pool
accounting is implemented.

> The ability to execute does not imply an unlimited right to consume memory.

> RAM is an explicitly budgeted, accountable resource.

> Resource consumption is authority.

> Resource authority may be delegated only by attenuation, never amplification.

## Separate objects and authority

```text
SystemMemory
  -> MemoryPool                 quantitative allocation authority
     -> MemoryObject            owned generational pages/granules
        +-> Mapping             projection into an address space
        +-> SharedView/Binding  deliberate peer delegation
        +-> DMA mapping         separate device + IOMMU authority
```

Exact names are not frozen ABI. Budget, ownership, virtual reservation, mapping,
sharing, pinning, content access, and DMA are distinct. A virtual address, object
name, task identity, or mapping address is not authority.

`MemoryPool` carries a maximum commitment, current usage, mapping bound, child-
delegation allowance, placement policy, lifetime/generation, and separately
attenuable allocation, derivation, sharing, mapping, pinning, and usage-
inspection rights. A task receives an explicit pool/derived allocator,
preallocated objects, or no additional allocation authority—never a hidden
unlimited global allocator.

The amount is part of authority. Child-pool commitments/delegations follow a
defined accounting model whose total cannot exceed the parent. Derivation may
narrow bytes/pages, placement, mapping, pinning, sharing, and lifetime. Parent
revocation invalidates/reclaims descendants according to explicit lifetime
semantics. Lowering a limit below commitment requires explicit pressure/reclaim/
termination behavior and never silent corruption.

`MemoryObject` binds exact size/extent, backing kind, generation, lifetime,
sharing state, ancestry/charge, and optional placement. Identity is independent
of VA. A mapping separately binds target address space, range, generation, and
attenuated read/write/execute/delegate/fixed-address rights while preserving W^X.

Address-range reservation is virtual structure; commitment charges pool RAM;
mapping associates an object with a reservation. Lazy backing reserves maximum
authorized commitment before it can affect peers. Native semantics do not assume
hidden overcommit. Any future explicit overcommit documents failures and cannot
promise backing that disappears unpredictably.

## Sharing, COW, lifecycle, and erasure

Shared memory deliberately maps the same object or derived view with per-peer
rights. Revoking one peer removes only that view while other valid authority
survives unless the object itself is revoked. This preserves existing exact-
generation shared-page revocation.

COW initially shares backing, but a private write charges the writer's pool; if
budget is unavailable it fails under defined semantics rather than charging an
unrelated domain. Pools, objects, mappings, views, guest mappings, and derived
bindings are generational so reuse cannot revive stale handles.

Task/domain/VM death accounts for owned objects, mappings, views, child pools,
pinned pages, DMA/IOMMU mappings, and guest mappings. Cleanup completes or
retains an explicit fail-closed/quarantined state before protected reuse.
Sensitive memory may require separately specified zeroization; reclamation is
not itself proof of secure erasure, especially on unverified hardware paths.

## Exhaustion and system accounting

Pool exhaustion is local: one application hitting 512 MiB receives deterministic
denial without consuming another domain's authority. Trusted policy may reserve
RAM for kernel, memory manager, supervisor, storage/network cleanup, compositor
fallback, and accessible recovery UI; that reserve is not ambient application
authority. Pressure events (`LOW`, `HIGH`, `LIMIT_REACHED` conceptually) grant no
additional RAM and allow voluntary release.

Filesystem/executable caches, network/GPU staging, service caches, IPC buffers/
queues, capability/task/mapping metadata, page tables, and VM metadata all consume
accounted bounded memory. Reclaimable cache is still inspectable resource use.
Sparse VA or cheap requests cannot force unbounded privileged page-table/kernel
growth. Charge policy avoids denial-of-service amplification.

Future in-process components may share one immutable executable `MemoryObject`
physically across consumers, as specified in
[../packages/COMPONENT_INTERFACES.md](../packages/COMPONENT_INTERFACES.md).
Accounting charges physical backing once under explicit system/cache policy and
charges every consumer for bounded mapping metadata and private component state.
Mapping fanout is bounded. Sharing never hides RAM, creates allocation authority,
permits writable executable code, or lets a stale mapping select newer code.

**PARTIALLY IMPLEMENTED foundation:** `account_component_executable` charges one
shared `MemoryObject` to an already authorized pool and issues an object
capability without `WRITE`. `reserve_component_executable_mapping` records one
complete RX projection under a separate target-address-space capability; the
existing mapping limit bounds fanout and live reservations block reclamation.
The current helper records accounting/policy only. Physical backing,
population/sealing, native installation, per-consumer private-state accounting,
and runtime generation binding remain **PLANNED**.

Pinning is separate scarce authority because it limits reclamation and may enable
device visibility. Object ownership never implies DMA. DMA requires the exact
object plus device/DMA authority and a valid IOMMU mapping; invalidation completes
before reuse.

Future swap/compression preserves per-domain accounting, confidentiality,
authenticated/encrypted untrusted persistence where required, and bounded
latency/failure semantics. Swap does not promise unlimited RAM. Cross-domain
deduplication is disabled by default pending side-channel analysis.

## Placement and performance

Adaptive execution placement is specified in
[../ISOLATION_PLACEMENT.md](../ISOLATION_PLACEMENT.md). Requested and effective
placement carry explicit process/service/VM, page-table, queue, and shared-code
charges; total-microVM policy cannot hide commitment or cross limits silently.

Default policy selects NUMA placement, migration, tiering, and huge pages while
preserving object identity. Advanced authority may request node/device locality,
interleave, latency class, or large-page preference, subject to policy. Physical
page identity is not ordinary ABI.

Measure allocation/free/reclaim/map latency, pool-accounting overhead, sharing,
revocation, and VM provisioning. Optimize from evidence rather than weakening
accounting.

## VMM and guest memory

A VM receives a bounded host-derived guest-memory pool and mapping limit. Guest
physical addresses are data, not host authority, and the guest cannot inflate
host commitment beyond projection. Shared host/guest pages derive from exact host
objects, rights, lifetime, and revocation.

Ballooning/hot-resize explicitly changes delegated quantity. Increase requires
new host authority; decrease requires cooperation or defined forced reclamation,
mapping invalidation, and cleanup before reuse. It is not bookkeeping-only.

## GPU/system alignment

System `MemoryPool -> MemoryObject -> Mapping` and GPU `GpuDomain/MemoryPool ->
Buffer/Image/Tensor -> GPU VA Mapping` use analogous bounded allocation,
derivation, generation, mapping, accounting, and revocation principles without
requiring identical implementations. Unified physical memory retains separate
CPU mapping, GPU-domain mapping, pool charge, and residency/migration authority.
See [GPU_ARCHITECTURE.md](../gpu/GPU_ARCHITECTURE.md).

## Introspection and broader resources

The [unified system monitor](../monitor/SYSTEM_MONITOR.md) projects these
accounted objects and shared-page costs without acquiring mapping, content,
debug, or budget authority. This integration remains **PLANNED**.

Authorized monitors may inspect pool limit, committed/shared/pinned quantities,
descendant pools, and pressure without reading memory contents. Observation,
content read, limit increase, modification, and termination are separate
capabilities. AI may see “browser uses 3.8/4 GiB” without browser memory.

RAM is one resource-specific capability family alongside CPU, VRAM/GPU time,
storage quota, network capacity, device sessions, and IPC capacity. Common
attenuation/accounting/revocation principles do not require one omnipotent
`ResourceCapability` or administrator.

Illustrative browser-VM envelope: four bounded vCPUs; 4 GiB RAM pool; graphics +
decode with 512 MiB VRAM and bounded GPU time; 10 GiB storage quota; and exact
network-connection capabilities. This is not frozen policy.

## Security and acceptance gate

- allocation cannot exceed explicit pool authority;
- child pools cannot amplify quantity;
- VA reservations do not hide physical commitment;
- mappings cannot outlive object/address-space generations;
- stale pools, objects, mappings, and shared bindings fail closed;
- revoking one shared peer preserves unrelated valid peers;
- pinning and DMA require separate rights;
- guest RAM cannot exceed host projection;
- uncertain cleanup blocks protected reuse;
- exhaustion remains local where reserves/policy permit;
- usage inspection reveals no content.

Tests cover exact limit and one-page-over denial, child attenuation/amplification,
parent revocation, stale handles, COW exhaustion, sparse-page-table and IPC
exhaustion, pinning, guest inflation, death cleanup, peer survival, cleanup-before-
reuse, and introspection accuracy. Adversarial tests stress tiny/huge allocation,
churn, sparse mappings, COW, sharing fanout, VM cycles, pinned/DMA state, and
cleanup failure while verifying exact accounting.

## Dependency placement

Phase 1 retains exact ownership, generations, mappings, shared memory, cleanup,
and revocation. Phase 2 adds pools, objects, quantitative delegation, and IPC/
cache accounting without preempting current storage/service gates. VMM work adds
bounded guest pools; dynamic resize follows. GPU work aligns VRAM concepts.
NUMA, huge pages, swap/compression, QoS, and side-channel review are later. This
does not preempt VirtualGPU or the compiler ownership/CFG/Polonius lane.

Patent review: `NOT_TRIGGERED` — this documentation specifies conventional
quantitative resource accounting, allocation/mapping separation, and capability
attenuation without implementing a new mechanism. See
[`../patents/REVIEW_LOG.md`](../patents/REVIEW_LOG.md).
