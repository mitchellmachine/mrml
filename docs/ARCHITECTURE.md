# MRML operating-system architecture

This is the durable architectural overview. Detailed implementation history and
probe evidence remain in [MICROKERNEL.md](MICROKERNEL.md); security boundaries
are normative in [SECURITY.md](SECURITY.md); dependency order is in
[ROADMAP.md](ROADMAP.md); the application contract is in
[APPLICATION_PLATFORM.md](APPLICATION_PLATFORM.md); context-loss recovery is in
[RECOVERY.md](RECOVERY.md).

## Status vocabulary

- **IMPLEMENTED**: repository code and focused tests exist. This does not imply
  production readiness, physical-hardware validation, or independent review.
- **PARTIALLY IMPLEMENTED**: useful pieces exist but the named end-to-end
  property or integration is incomplete.
- **EXPERIMENTAL**: executable research or controlled probe whose environment
  and evidence are narrower than a production claim.
- **PLANNED**: intended architecture with no complete implementation.
- **ASPIRATIONAL**: long-term direction whose feasibility or exact design is
  not yet established.

## Identity and direction

MRML is the **Mitchell Renouf Machine Learning Library**. It began as local
machine-learning and inference work and is evolving into a broader experimental
computing stack, including an operating system built from first principles.
The OS direction is experimental, security-oriented, capability-based,
microkernel-oriented, Rust-first, local-first, dependency-minimized, designed
for user sovereignty, and intended to make local AI a first-class system
capability. MRML is not currently a production operating system.

## Current architecture

**IMPLEMENTED:** an experimental x86_64 PE32+ microkernel, original UEFI loader,
bounded firmware handoff and allocator, W^X page tables, GDT/IDT/TSS, guarded
privilege stacks, CPL3 domains, APIC timer preemption, SMP startup, IPIs,
scheduling and migration, fixed-capacity generational capabilities and tasks,
bounded IPC, fault retirement, service restart policy, guest-memory policy, and
native KVM and Windows WHP launch backends. Signed controlled probes exercise
subsets of these mechanisms. See the evidence ledger in MICROKERNEL.md.

**PARTIALLY IMPLEMENTED:** blocking receive and scheduler wakeup, bounded
backpressure, attenuated capability transfer, shared-memory bindings, mapping
revocation, peer fault cleanup, multi-core balancing, protected-execution
admission, VMX-root monitoring, VT-d table/control machinery, mediated GPU, boot
admission, measured-boot plumbing, and monotonic release-state abstractions.
These pieces do not yet form a complete production service substrate or
hardware-validated security boundary.

**EXPERIMENTAL:** signed QEMU/UEFI, nested KVM, and WHP runs; Windows VBS enclave
authority/verifier work; nested-KVM VMX-root/EPT probes; CUDA mediation and VMM
benchmarks. Backend-specific evidence is not evidence for another backend.

**PLANNED:** practical storage, network, firewall, configuration, authority-
broker, trusted-consent, security-monitor, audit-event, tool, inference, driver,
and GPU services; a safe native application SDK and versioned protocols;
application microVM projection; trusted compositor and semantic GUI; a no-JIT
browser; production shared-memory queues; TPM-backed rollback state; complete
physical VT-d/device-reset validation; recovery and release key rotation.

**ASPIRATIONAL:** a production-secure sovereign local-AI OS, broad device
support, machine-checked noninterference, independently audited security, and
additional architectures.

## The microkernel boundary

The microkernel contains only mechanisms that fundamentally require privileged
execution: address-space isolation, scheduling, IPC primitives, capability
enforcement and transfer/revocation primitives, interrupt routing, fundamental
memory ownership, minimal hardware isolation, and mechanisms needed to prevent
userspace policy bypass. Ordinary policy must not migrate into the kernel merely
because it is security-sensitive.

Storage, networking, firewall/network policy, system configuration, authority
brokering, trusted consent UI, security monitoring, service supervision policy,
ordinary drivers where feasible, and AI policy belong in isolated userspace
services. A service failure should revoke its authority and resources, notify
affected peers, permit bounded restart, and leave unrelated services and the
kernel running.

## Authority model

MRML avoids ambient authority. A path, PID, port, service name, object ID,
device name, signature, publisher, hash, or user identity does not itself grant
access. Authentication answers who an entity is; a capability answers what it
may do. Human-facing names may guide policy, but enforcement should resolve
them to capabilities for stable objects.

Capabilities are narrow, explicitly transferred, and generational. Derivation
may preserve or reduce rights but cannot increase them. Launch by a privileged
user does not imply universal authority. Revocation is not complete until all
relevant descendants and derived state—handles, mappings, shared memory, IPC,
DMA, devices, network/firewall state, cached decisions, and temporary grants—
are unusable or quarantined.

The durable object-model rule is: **everything meaningful is an object, and
authority to an object is represented by capabilities**. An object is a
resource with identity and lifetime; a capability grants specific operations on
it; a name or path discovers it but does not authorize it. This applies to
storage and graphics resources. It does not require turning meaningless private
implementation details into public objects.

## Native storage direction

**PLANNED:** MRML will have a capability-aware native filesystem. The EFI System
Partition and UEFI Simple File System remain appropriate FAT32 interoperability
for boot. ext4, NTFS, and other formats may later be compatibility/import
services, but FAT32, legacy formats, POSIX permissions, and a universal global
namespace do not define native MRML storage or security semantics.

Paths locate objects; capabilities authorize them. Namespace traversal resolves
a stable `DirectoryObject`, `FileObject`, `SnapshotObject`, `VolumeObject`, or
`NamespaceObject`, then access requires explicit rights. Renaming an object does
not change its identity, and knowing or guessing its ID grants nothing. Open
handles remain bound to objects rather than mutable paths. Processes receive
specific roots and objects—such as app-private data, a selected project, or an
update target—rather than seeing a universal namespace filtered by deny rules.
Compatibility layers may emulate conventional paths.

Conceptual directory rights include `LOOKUP`, `ENUMERATE`, `CREATE_FILE`,
`CREATE_DIRECTORY`, `RENAME_CHILD`, and `REMOVE_CHILD`; file rights include
`READ`, `WRITE`, `RESIZE`, `MAP`, `READ_METADATA`, and `WRITE_METADATA`. These
are not frozen ABI names. There is no universal `ADMIN` right, and derivation
never increases authority.

The intentionally small native filesystem v1 targets stable object IDs,
directories/files, extent allocation, checksummed copy-on-write metadata,
atomic transactions, snapshots, crash consistency/recovery, and capability
enforcement. User data is checksummed by default if measurements make it
practical. Compression, encryption, deduplication, replication, remote storage,
complex quotas, and advanced caching are optional later work, not v1 blockers.

Critical metadata is not mutated in place: modified tree nodes/extents form a
new generation followed by an atomic root/superblock transition. Redundant or
rotating roots should be evaluated for recovery. Extent records may reserve
future `HOLE`, `COMPRESSED`, `ENCRYPTED`, or `SHARED` semantics without
implementing them prematurely. Explicit transactions make grouped writes,
renames, and metadata changes externally all-or-nothing.

Snapshots are capability-controlled objects with a generation, filesystem
root, optional parent, and metadata. They support authenticated system-
generation recovery, but checksums are not executable signatures and snapshots
are not malicious-downgrade protection. That claim still requires authenticated
persistent anti-rollback state.

## IPC and shared data

The control path is kernel-mediated, bounded IPC for small messages,
synchronization, request/reply, and capability transfer. Its target semantics
include blocking send/receive, scheduler sleep/wakeup, backpressure, multiple
clients, peer-death notification, cancellation/timeouts where justified, and
predictable cleanup. Some receive/wakeup, bounded inbox, sequencing, and
capability-transfer behavior is implemented; a complete multi-client service
protocol is not.

The bulk path uses revocable shared pages or rings for storage, network, GPU,
and inference data. Large payloads should not be copied through the kernel.
Avoid allocation, global locks, policy engines, scanning, and unnecessary copies
on hot paths. Measure syscall, IPC, wakeup, lookup, transfer, revocation,
mapping, interrupt-to-userspace, and later service throughput.

## VMM backends

```text
backend-independent MRML VM policy and exit handling
    +-- native WHP/WHPX backend (Windows)
    +-- native KVM backend (Linux)
```

Both backends are implemented development and compatibility environments and
must be preserved. Backend-specific lifecycle, memory mapping, registers, and
exit decoding remain behind their adapters. Shared semantics belong in common
kernel/VMM policy. Hosted WHP and KVM do not protect a guest from their host.

## Planned system services

The capability-native authority broker will evaluate narrow requests and may
deny, allow, request trusted user consent, grant once, grant until process exit,
or grant for a duration. Consent UI remains outside the kernel and must be
difficult for untrusted applications to spoof. Temporary grants are revoked on
exit, expiry, policy change, or explicit action.

The configuration service is planned as typed, schema-validated,
transactional, capability-controlled, versioned, auditable, exportable, and
recoverable—not a clone of the Windows Registry. Secrets remain separate.

Networking is planned around explicit authority and bounded connection objects,
not ambient sockets. Raw packet and device access require separate capabilities.
Firewall policy remains a service and provides defense in depth; a firewall
allow rule never creates network authority.

The planned security monitor consumes structured, non-secret events and holds
only explicit observation/remediation capabilities. It is not an omnipotent
antivirus process. Stable event classes should cover authority decisions,
capability revocation, process/service lifecycle, artifact admission, networking,
and policy changes with monotonic sequencing and trustworthy time only when
available.

Local AI is eventually exposed as a capability such as
`ai.inference:<model/resource>`. AI agents receive the same least-authority
discipline as all software: **AI-native does not mean AI-privileged**.

The application platform does not inherit POSIX/C as its foundational ABI.
Ordinary native applications are intended to be admitted as memory-safe code
using a safe SDK over stable service protocols. Unsafe/legacy applications live
behind explicit VM compatibility boundaries. The trusted compositor, semantic
scene graph, HiDPI coordinate model, browser rules, and AI interaction boundary
are specified in [APPLICATION_PLATFORM.md](APPLICATION_PLATFORM.md). None is
currently implemented as an MRML OS application platform.
