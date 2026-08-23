# MRML operating-system architecture

This is the durable architectural overview. Detailed implementation history and
probe evidence remain in [MICROKERNEL.md](MICROKERNEL.md); security boundaries
are normative in [SECURITY.md](SECURITY.md); dependency order is in
[ROADMAP.md](ROADMAP.md); the application contract is in
[APPLICATION_PLATFORM.md](APPLICATION_PLATFORM.md); context-loss recovery is in
[RECOVERY.md](RECOVERY.md); compiler direction is in
[COMPILER.md](COMPILER.md). The normative cross-cutting engineering and
complexity rules are in
[ENGINEERING_CONSTITUTION.md](ENGINEERING_CONSTITUTION.md); historical
inspiration in [EULOGY.md](../EULOGY.md) is not architecture policy.

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
backpressure, attenuated capability transfer with bounded transitive IPC-handle
revocation, multi-party shared-memory bindings, mapping revocation, peer fault
cleanup with cleanup-gated fresh-generation restart, multi-core balancing,
protected-execution admission, VMX-root
monitoring, VT-d table/control machinery, mediated GPU, boot admission,
measured-boot plumbing, and monotonic release-state abstractions. IPC-handle
descendants are covered in `TaskRuntime`; the broader derived-state revocation
requirement still includes mappings, shared memory, DMA, devices, cached
decisions, and service-specific state. These pieces do not yet form a complete
production service substrate or hardware-validated security boundary.

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

## Rust compiler architecture

`mrml-rustc` is an original MRML Rust compiler targeting contemporary and
forward-looking Rust semantics. Rust 2024 is its floor, not its final target.
Compatibility means deliberately reproduced observable language semantics, not
every historical edition or nightly, old unsoundness, rustc/LLVM internals,
diagnostic text, unstable Rust ABI, or symbol accidents. It remains recognizably
Rust and must not diverge merely to create an MRML-specific language.

**IMPLEMENTED:** a fixed-capacity, dependency-free, `no_std`, no-global-`alloc`
compiler core; bounded parsing, semantic and const-evaluation subsets;
deterministic x86-64 COFF/ELF64 emission; substantial modern integer and raw-
pointer operations; and original Windows/Arch differential probes against an
exact stage-zero nightly.

**PARTIALLY IMPLEMENTED:** typed places and mutations, references/reborrowing,
modern pointer/provenance-facing APIs, patterns/matches, never coercion, unsafe
operations, aggregates, control flow, and modern const behavior. These bounded
features are not an ownership checker, provenance model, general type system,
stable Rust ABI, or application security proof.

**PLANNED:** an explicit typed ownership/place/CFG representation; staged
Polonius-direction flow-sensitive loan/outlives checking; an independent modern
trait-goal solver; naked functions and validated assembly; application/system/
compiler profiles; compiler-derived security metadata; loader validation; and
progressive exact future-Rust oracle generations.

Unsupported semantics fail closed. Language support for unsafe systems work is
separate from the stricter admission profile planned for ordinary native
applications. The detailed feature matrix, prerequisites, priority policy, and
oracle procedure are normative in [COMPILER.md](COMPILER.md).

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
files, directories, processes, threads, services, windows, surfaces, VMs,
devices, connections, audio streams, configuration, credentials, AI sessions,
debugging, media, snapshots, and security state. **Names identify. Capabilities
authorize.** This does not require turning meaningless private implementation
details into public objects.

### Capability namespace and provenance

**PLANNED:** a launcher/policy assembles each application's initial capability
namespace. Entries such as GUI, app-data, playback, network-connect, or AI
inference refer to already authorized objects; globally discoverable service
names never confer privilege. Optional services may be discovered without
granting access.

Capabilities will carry bounded, access-controlled provenance sufficient to
explain their parent/delegator, rights attenuation, target object, lifetime,
expiration, transfer, and revocation. Introspection answers “why does this have
access?” using the real delegation graph—for example, user selection through a
trusted picker produced a file READ capability—not a cosmetic ACL explanation.
It must not reveal object contents, secret values, unrelated principals, or an
unbounded history.

Where practical, authority has a common lifecycle: delegate, derive, restrict,
revoke, expire, and inspect provenance. Subsystems retain specific rights.
Lifetime policies may bind to one operation, process/window/VM lifetime, device
removal, logout, an explicit deadline, or revocation. The common mechanism—not
subsystem-specific timers—must invalidate derived state.

### Secrets, debugging, and diagnostics

**PLANNED:** `SecretObject` represents passwords, API/OAuth tokens, keys,
sessions, and recovery material. A secret capability normally permits bounded
`USE`, `AUTHENTICATE`, or `SIGN` without plaintext disclosure. `ROTATE`,
`DELETE`, and especially `EXPORT` are separate rights; export generally needs
stronger policy or trusted consent. Protocols that require plaintext exposure
must document the limitation. Remote AI receives no export authority by
default.

Debugging is object-scoped authority, not universal ptrace/root. Independent
rights may read registers/memory, break, single-step, write state, inject a
signal, or terminate one exact process. Diagnostics likewise expose structured
fault objects and events—subsystem, target, operation, error, severity, and
recoverability—through observation capabilities that do not imply kernel memory
or mutation access.

### Disposable domains and restart

**PLANNED:** “Open Isolated” launches unknown downloads, documents, media,
browsers, or suspicious applications in a temporary process/VM domain with
minimal capability namespace and trusted compositor identity. Closing it
revokes authority, destroys the domain, discards temporary storage, and erases
sensitive memory where practical. Persistent storage or networking is absent
unless explicitly delegated.

Userspace services should be crash/restart oriented where suitable: detect
failure, revoke all service authority, destroy transient state, launch a clean
generation, and restore only explicit persistent configuration. Services whose
domain requires richer recovery need not be forced into this model.

### Object and data provenance

**PLANNED:** bounded, privacy-conscious, access-controlled object history may
record creator/modifier/downloader, network origin, URL, source application or
domain, signature/admission state, timestamps when trustworthy, and relevant
capability transfers. Integrity-protected system provenance remains distinct
from application-supplied metadata.

Lightweight data labels such as trusted user instruction, system policy, local
trusted content, untrusted file/web/email/remote content, and AI-generated
content survive important serialization and AI-context boundaries. **Data
cannot grant authority.** Imperative text from an untrusted source remains data;
tool execution is still capability constrained. Provenance informs decisions
and prompt-injection defense but never replaces authorization.

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

### VMM device model

The shared VMM will expose a small explicit device family, preferring
paravirtualization over broad legacy emulation. **IMPLEMENTED:** backend-neutral
VM lifecycle, bounded guest memory, exit decoding, interrupt injection policy,
allowlisted scalar I/O, and MRML hypercalls. **PARTIALLY IMPLEMENTED:** the
MRML-specific mediated GPU has authenticated bounded command/completion and
resource queues plus reset/watchdog behavior, but is not a VirtIO GPU or general
display device. **PLANNED:** guest console, block, network, input, graphics, and
sound devices; PCI transport; and any required compatibility emulation. No
VirtIO-compatible MRML device currently exists.

Each device is explicitly classified as **VirtIO-compatible**,
**VirtIO-inspired**, **MRML-specific**, or **legacy-emulated**, with supported
features, queue formats, reset semantics, backend coverage, QEMU comparison,
known differences, and fuzzing status recorded before compatibility claims.
Actual VirtIO specifications govern devices advertised as compatible. Stronger
capability semantics use an MRML-specific protocol instead of distorting
VirtIO. Guest-visible behavior stays common across KVM and WHP/WHPX; transport,
PCI configuration, device core logic, and backend interrupt injection remain
separate layers.

QEMU is the primary interoperability and differential-test oracle for applicable
devices, not the security specification. Equivalent guest workloads should
compare feature negotiation, descriptor and queue behavior, completion,
interrupts, reset/removal, errors, and boundary cases. Agreement with QEMU alone
does not prove specification compliance or security.

Selected UART, simple HID/PS2, PCI configuration, timer, framebuffer, or storage
emulation may support firmware, bring-up, testing, and legacy compatibility.
Normal MRML guests use paravirtualized devices. Large legacy-hardware emulation
does not become a foundational dependency without a concrete requirement.

Every device has explicit `create -> negotiate -> activate -> operate -> reset
-> suspend/resume (when supported) -> remove -> destroy` transitions. Reset
invalidates every descriptor and queue generation. Shared rings are preferred
for block, network, audio, graphics, storage, and high-rate input, avoiding a VM
exit per small operation while validating all guest metadata. Descriptor chains
are bounded for length, cycles, indirect entries, arithmetic, GPA range,
direction, alignment, queue size, and live device generation. Guests never
supply trusted host pointers.

Virtual devices are security boundaries. Long term, device implementations
should be isolated components/services with only the capabilities required for
their backend rather than one omnipotent VMM process. Device notifications use
a common abstraction over legacy injection where required, MSI/MSI-X-style
virtual interrupts, and event notifications.

The future display/3D device may implement applicable VirtIO-GPU interfaces,
but it must coexist with the existing MRML-specific CUDA compute path. VirtIO-
GPU does not silently become the CUDA ABI. Signed kernel-bundle admission,
authenticated queues, buffer capabilities, quotas, watchdog/reset, and CPU
fallback remain available through a separate MRML compute protocol wherever
VirtIO cannot express them. A VM may receive display and CUDA-compute devices
under distinct capabilities and lifecycle state.

### Network, audio, USB, and input services

**PLANNED:** networking remains a userspace service for native applications,
which request bounded connection objects instead of raw packets. A VM receives
a VirtIO-net-compatible or MRML virtual NIC only with explicit authority such as
none, isolated, outbound-only, specifically routed, bridged, or raw access.
Guest NIC programming cannot bypass host firewall/policy. Baseline bounded
TX/RX, deliberate feature/ring selection, validation, interrupts, and reset
precede multiqueue and offloads.

Audio is a userspace service exposing capability-bound `AudioDevice`,
`PlaybackStream`, `CaptureStream`, `AudioRoute`, and `AudioSession` objects.
Playback and microphone capture are independent; capture is explicitly granted,
revocable, audited, policy-scoped, and shown through compositor-owned trusted
UI. VMs use a VirtIO-sound-compatible or MRML device connected to the service,
not physical hardware unless separately granted passthrough authority.
Application playback/capture, VM audio, system notifications, trusted
accessibility speech output, and trusted accessibility speech input are distinct
routes and authorities. Applications cannot capture trusted screen-reader audio
by default. Local recognition and deterministic semantic commands remain
possible without remote AI; remote speech processing is separately disclosed.

USB is managed by userspace controller/class services where practical.
Applications receive narrow class or interface objects rather than raw USB
transactions. Composite-device interfaces are independently grantable—for
example, webcam video without its microphone. VM passthrough revokes conflicting
host access first and makes reset, cleanup, DMA isolation, and reattachment
explicit. Dedicated paravirtualized input, storage, network, and audio devices
are preferred over emulating a USB controller merely to expose those functions.

Refreshable Braille displays, adaptive keyboards, switch controls, alternative
pointing devices, and other accessibility HID interfaces are explicit device
use cases. Prefer interoperable protocols and narrow interface delegation to
trusted accessibility/input services rather than raw USB.

Trusted input services route keyboard, pointer, touch, pen, and gamepad events
only to authorized native surfaces or selected VMs, optionally through
VirtIO-input or an MRML device. A focused VM receives ordinary routed events,
not global HID. Secure-attention sequences terminate in the trusted host and
cannot be intercepted by applications or guests.
Braille input and accessibility-device events use the same focus, isolation,
secure-attention, and capability rules. A focused application or VM never gains
global accessibility input. See [ACCESSIBILITY.md](ACCESSIBILITY.md).

## Planned system services

The capability-native authority broker will evaluate narrow requests and may
deny, allow, request trusted user consent, grant once, grant until process exit,
or grant for a duration. Consent UI remains outside the kernel and must be
difficult for untrusted applications to spoof. Temporary grants are revoked on
exit, expiry, policy change, or explicit action.

**PARTIALLY IMPLEMENTED:** the configuration-service foundation is typed,
schema-validated, transactional, capability-controlled, versioned, and
bounded-auditable. Kernel-message dispatch resolves authority only from exact
receiver-space capabilities derived by IPC; payload authority fields are
canonical zero placeholders, and extra, missing, or payload-forged authority
fails closed. The supervision adapter composes query and restart with existing
exact-object, cleanup, backoff, restart-limit, and trusted-context gates. Names,
numeric setting IDs, and service handles never authorize. A bounded CPL3
request-buffer ABI now decodes fixed payload/capability-buffer descriptors and
validates every active user leaf before a directional copy. The signed service
probe now executes real `mrml-config` read and atomic commit dispatch under both
WHP and KVM. Commit payload authority remains zero: the sender independently
attenuates configuration-root CONTROL and setting WRITE, and the receiver asks
the kernel to validate both derived opaque handles against exact generation,
rights, and objects through a detail-free syscall before revision 1 is applied.
The canonical 112-byte response returns over the same bounded IPC path. The
supervised replacement repeats the transaction from fresh volatile service
state, without claiming persistence across cleanup. Two simultaneous blocked
buffered receives retain independent bounded state. Service page-table
frames and a host-published signed-image entry page are supervisor-only mapped
so active-root validation and recovery remain available without granting CPL3
access. Signed schema admission, persistent export/import, and storage-backed
recovery remain planned. It is not a clone of the Windows
Registry, and secrets remain separate.

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
