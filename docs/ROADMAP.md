# MRML operating-system roadmap

This roadmap is dependency ordered. It describes intended work, not completion
claims. Status is determined from source, tests, and the evidence ledger in
[MICROKERNEL.md](MICROKERNEL.md), using the vocabulary in
[ARCHITECTURE.md](ARCHITECTURE.md).

## Current priority

**PARTIALLY IMPLEMENTED:** the kernel has bounded IPC, blocking receive/wakeup,
two-message inbox backpressure, attenuated capability transfer with rollback,
generational revocation, shared-memory bindings, mapping revocation, fault
retirement, service cleanup/restart policy, and signed two-service probes.

The next coherent milestone is an end-to-end service substrate: two isolated
CPL3 services communicate through a multi-client blocking control channel and a
revocable shared-page bulk channel; one service is deliberately crashed; the
kernel revokes its capabilities, mappings, IPC and shared state; peers receive a
typed death result; the supervisor performs one bounded clean restart; and the
unrelated service continues. Exercise equivalent signed paths under WHP and KVM
and add adversarial unit tests. This milestone must not claim host-resistant
confidentiality.

## Phase 1 — Kernel and service foundation

1. Complete multi-client blocking send/receive and scheduler sleep/wakeup.
2. Define bounded queues, backpressure, cancellation/timeout policy, and typed
   peer-death behavior.
3. Complete atomic capability transfer/derivation with non-amplification tests.
4. Complete transitive revocation accounting for IPC and descendants.
5. Add shared-page/ring setup with explicit ownership and access attenuation.
6. Pair mapping revocation with native KVM/WHP invalidation before vCPU resume.
7. Integrate fault cleanup, peer notification, erasure, and bounded restart.
8. Benchmark one-way, round-trip, cross-core, wakeup, transfer, revocation, and
   shared-memory setup costs.

Security gate: no stale identity, capability, mapping, queue entry, or shared
page remains usable after death/revocation; partial operations cannot duplicate
authority; unrelated domains continue.

## Phase 2 — Minimal userspace system

1. Implement the policy/configuration service and service supervision protocol.
2. Implement a storage service and authenticated bounded block protocol.
3. Implement a network service returning bounded connection capabilities.
4. Add firewall/network-policy as defense in depth outside the kernel.
5. Add tool and local-inference services over control and bulk IPC.

Security gate: services start with explicit least authority; paths, ports,
names, identity, and signatures do not grant ambient access; raw packet/device
access is separately privileged; service failure is contained.

## Phase 3 — Authority, consent, and observation

1. Implement a capability-native authority broker with narrow scope, duration,
   and one-shot grants.
2. Implement a trusted userspace consent agent with anti-spoof transaction
   binding; keep UI outside the kernel.
3. Add typed structured security events and protected audit storage.
4. Add a non-omnipotent security monitor with separate observation and narrow
   remediation capabilities.

Security gate: identity is not authority; temporary grants expire/revoke on all
specified paths; applications cannot forge consent or privileged events; the
monitor cannot exceed its explicit capabilities.

## Phase 4 — Persistent security state and boot

1. Implement a TPM NV or equivalent authenticated, monotonic, power-loss-atomic
   release-state backend.
2. Bind measured boot to the exact coherent signed artifact set.
3. Add rollback, stale-update, corruption, interrupted-write, and recovery tests.
4. Establish reproducible builds, independently controlled release keys,
   Secure Boot integration, recovery, and key rotation.

Security gate: older signed vulnerable releases cannot be admitted after a
committed advance; loss/corruption fails safely and has a documented recovery
path. No rollback-resistance claim precedes physical testing.

## Phase 5 — Bare-metal hardware isolation

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

## Phase 6 — Hardening and expansion

Continuously fuzz parsers, IPC, shared-memory metadata, capability abuse, and
corruption paths. Stress SMP races, mapping/revocation races, interrupts,
crashes, exhaustion, network adversaries, and power loss. Perform unsafe/FFI
review, side-channel analysis, formal specification of critical capability and
noninterference properties, reproducible release review, and external audit.
Only then consider broad drivers, production claims, AArch64, and RISC-V64.

Every milestone requires proportional Windows gnullvm and Linux testing,
backend-specific signed probes where applicable, exact commands/results, and
before/after performance measurements. Unsupported environments must be listed,
not implied.
