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
inspiration in [EULOGY.md](../EULOGY.md) is not architecture policy. Relevant
predecessors and deliberately bounded comparison claims are recorded in
[HISTORY_AND_PRIOR_ART.md](HISTORY_AND_PRIOR_ART.md).

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

Values must resolve into mechanisms and tests, not remain slogans:

```text
Power is revocable
  -> derived authority must be removable
  -> generational capability graph plus mapping/IPC/device cleanup
  -> revoke a parent and prove descendant handles and mappings fail

Intelligence does not imply authority
  -> AI is an ordinary capability principal
  -> scoped AI-session capabilities and SemanticView
  -> injected content requests SecretObject.EXPORT and receives DENIED

Owner controls the machine
  -> owner-selected trust roots without rollback bypass
  -> boot, update, recovery, and scoped-attestation key policy
  -> an explicitly authorized owner-built generation boots and reports that policy
```

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

**PARTIALLY IMPLEMENTED:** MRML is building a capability-aware native
filesystem. The `mrml-storage` userspace-service foundation defines nonzero
volume/object identities, principal-bound generational handles with attenuated
derivation and transitive descendant revocation, and canonical checksummed
volume, superblock, directory, directory-entry, and file metadata records.
Prepared file and directory primary-metadata COW images hash the fixed canonical
record followed by zeros through the exact block-aligned pointer extent; hidden
tail bytes and an extent shorter than the record therefore cannot share the
published digest. Unsafe staging backends must write and verify that complete
canonical padded range.
It also validates fixed extent records into exact logical coverage containing
data or explicit holes, rejects intra-file physical overlap and reserved volume
blocks, and provides bounded logical-to-physical lookup. A COW publication plan
requires exact next-generation nonoverlapping metadata ranges outside the
protected active generation, verifies staged-image digests, flushes them before
atomically replacing only the inactive superblock, and treats any failure at or
after replacement as fail-stop. A bounded block-volume adapter now implements
metadata staging, complete-image readback verification, durable-flush calls,
inactive-superblock replacement, and immutable recovery reads over an unsafe
exact-block device boundary. It permanently poisons a session after uncertain
replacement durability. Exact-block file reads now hash each complete physical
extent before copying a requested subrange. A bounded one-use file-write session
binds one exact predecessor, reconstructs successor blocks from verified old
data, holes, and the caller patch, rejects active/reserved/overlapping ranges,
verifies each complete staged extent by readback and the complete logical-file
digest, then flushes data before metadata publication. A fixed-capacity in-process block-service core now
registers non-authorizing device identities and issues principal-bound
generational sessions with independently attenuable `READ`, `WRITE`, `FLUSH`,
and `REPLACE_SUPERBLOCK` rights. Every operation reauthorizes before validating
or disclosing ranges; revocation is transitive, device removal retires every
session, and a scoped client connects the service to the exact-block adapter.
The canonical v1 control protocol now uses fixed 320-byte requests and 32-byte
responses, carries no principal or raw address, requires exactly one separately
transferred buffer capability for reads/writes, and inlines only the bounded
superblock record for atomic replacement. A bounded dispatcher authenticates
the IPC-derived principal, binds the exact buffer length, rejects noncanonical
records and replayed per-generation request IDs, and fail-stops a session after
an uncertain mutating backend result. Block requests now expose their exact
service-side buffer access shape. The kernel IPC receiver can require zero
transferred capabilities or exactly one live capability with an exact nonzero
rights set; it rejects missing, multiple, attenuated-too-far, over-privileged,
stale, or revoked transfers before returning object identity. Existing shared-
memory resolution is now composed into the same receiver gate: the exact
binding, object, VM/task, mapping generation, access mode, host range,
writability, and non-executable state must agree before only the opaque host
resource handle is returned. Generic bounded buffer reads and writes now repeat
that complete authorization at every use, reject empty or overflowing ranges,
deny writes through read-only bindings, and preserve backend uncertainty while
passing no raw address across the interface. Service-side selection now derives
the unique binding from the exact transferred capability plus kernel-known
VM/task identity; absent, ambiguous, or stale candidates fail before I/O, and
request bytes cannot nominate a binding. There is not yet an isolated service
process, block-specific syscall/receive loop, or physical device
implementation, persistent allocation/free engine, complete COW tree, or
concrete native block I/O. The syscall decoder admits bounded capability-
selected shared-buffer copy operations without binding IDs or shared addresses.
A generic executor binds those requests to the current task capability space,
kernel-known VM/task identity, exact live binding, direction-validated user-copy
backend, opaque resource backend, and erased bounded scratch. The kernel-image
service path composes that executor with active user copy and opaque resource
state. A fixed-capacity kernel-
owned opaque-resource table now issues monotonically increasing nonzero handles,
rejects live aliases, independently bounds transfers, retires stale handles
through the existing cleanup hook, and preserves backend uncertainty. Its
supervisor-memory adapter keeps raw addresses behind an unsafe boundary. The x86-64
active-page user-copy adapter is implemented: it binds validation to expected
CR3 and task plus exact address, length, and direction in a one-use ticket;
executor failure cancels an unconsumed ticket. Shared cleanup now depends only
on a narrow native-mapping revoker rather than full VMM authority. An active
x86-64 service adapter exact-matches CR3, virtual and physical extent, and old
permissions before removing all leaves and invalidating their local TLB entries.
KVM and WHP can now observe that kernel-side retirement only by verifying the
complete expected leaf range is absent before changing their live/re-arm
bookkeeping; they do not attempt a second unmap. This is the revocation
kernel-image resource composition. Each backend now also carries a
separate per-service resource slot: attachment targets exactly one service root,
rejects virtual or physical overlap with the common page or sibling resources,
and has independent revoke, observed-revoke, and restore state. Restore erases
the complete backing page before reinstalling the leaf. These APIs are compile-
tested. Both hosted runners prepare a distinct receiver-only page. The kernel-
image service path now gives only that receiver separate exact non-delegable
read and read/write resource capabilities, resolves bounded shared-buffer
syscalls through kernel-owned VM,
binding, and opaque-resource state, and composes receiver cleanup with exact
active-leaf removal, binding retirement, and final handle retirement. The host
accepts cleanup only by observing the absent leaf before zeroed restore; sender
cleanup remains resource-free. Fresh one-time signed KVM and WHP probes check
zero-before-use and bounded write/read behavior in both generations, kernel-
side leaf/binding/handle retirement, host absent-leaf observation, zeroed re-
arm, and final retirement. This is hosted controlled-probe evidence, not host-
resistant or physical-hardware evidence. Bounded
in-memory directory state now requires exact
per-operation directory authority for lookup, enumeration, creation, rename,
cross-directory file moves, and removal. Creation returns a capability bound to
a service-allocated stable object identity; namespace removal does not revoke
existing object capabilities, and rename preserves identity. Cross-directory
directory moves now require a bounded proof that walks canonical directory
metadata from the exact destination generation to the selected root, rejecting
the moved object, repeated ancestors, stale destination state, broken parent
links, backend uncertainty, and capacity exhaustion. The proof now also loads
the moved directory's exact generation and requires its current parent to be the
source directory. The opaque proof retains both bounded source-to-root and
destination-to-root object/generation paths. A fixed-capacity planner merges
those paths with the moved directory, removes shared ancestors, rejects a
shared object with inconsistent generation or depth, and orders the affected
closure child-before-parent with the root last. An immutable-state backend now
loads every exact predecessor in that closure and constructs bounded canonical
successors: the moved directory changes parent, source removal is compacted,
destination insertion points at the moved successor, each affected directory
advances once, and exact child-generation links propagate through deduplicated
shared ancestors to the root. This is non-authorizing construction only;
the complete plan now preflights distinct bounded metadata/entry layouts before
any write, stages every unreachable canonical successor child-before-parent,
and can build one directory-only transaction containing every participant and
image. The publication helper now additionally requires one allocation
successor to own every exact directory metadata/entry range with the matching
object, successor generation, and allocation kind; it binds that allocation
participant and image plus every directory participant and image into one
transaction and one COW-root plan. Successful publication returns a one-use
receipt whose directory participants are consumed atomically before their
successors are exposed. Concrete block integration, power-loss evidence, and
crash-safe creation remain pending. A canonical volume-scoped object-ID
allocator image now binds its nonzero generation, exact next stable ID or
exhausted state, COW pointer, full-image checksum, and zero padding. Reservation
stages an unreachable successor without changing the active allocator, admits
one distinct allocator transaction resource, and exposes the allocated ID and
successor only after its one-use receipt. Its successor must now be present in
the prepared allocation successor under a distinct allocator-metadata purpose,
bound to the exact root lifetime anchor, allocator generation, and pointer
range; this accounting anchor grants no authority. Reachable recovery now
requires exactly one such root-anchored record, decodes the exact canonical
allocator image at the candidate generation, and rejects a concrete next ID
that could reuse any reachable object ID. Missing, duplicate, corrupt, stale,
wrong-purpose, wrong-owner, and wrong-range state invalidates the candidate;
canonical exhaustion remains valid and strictly non-allocating. Authenticated
anti-rollback and physical durability evidence remain pending. The storage
authority table now supports opaque inactive insertion reservations: reserved
slots consume capacity but cannot authorize, guessed handles are rejected,
activation succeeds once, and cancellation retires the slot generation before
reuse. The prepared-create coordinator now validates that exact reservation
before consuming any receipt and activates it only after the complete receipt
set is consumed; prepublication cancellation retires it.
Canonical empty-file and empty-directory initialization is now staged without
making either child reachable. Both bind generation 1, exact stable identity,
disjoint metadata ranges, canonical zero-padded empty subordinate images, and
complete-image digests; the directory additionally binds its parent. Each is an
explicit typed `0 -> 1` creation participant rather than an ordinary update.
Parent-directory, allocation, ID-allocator, child, and authority-reservation
are now assembled by one bounded prepared-create coordinator. A general one-directory mutation proof now walks
the exact target generation to the selected root through the immutable backend.
For create it reloads every predecessor, inserts the generation-1 child only in
the target successor, advances every affected directory once, and rewrites each
parent entry bottom-up through the root. Staging and publication of this create
closure now reuse the same whole-plan layout preflight as directory moves:
every metadata/entry range is valid, exactly sized, and pairwise disjoint before
the first write; all successors stage child-before-parent and enter one bounded
directory transaction. The coordinator requires exact ownership for every
directory, child, and allocator image; admits the closure, typed child,
object-ID allocator, and allocation successor to one transaction; builds one
COW-root publication; and atomically consumes all participants before exposing
successor states or activating authority. Focused empty-file and empty-directory
creates exercise both admitted child kinds. Directory preparation retains its
exact parent, the coordinator requires that parent to be the unique directory
successor containing the generation-1 child entry, and the committed child state
preserves it. A deterministic durability simulation now materializes the exact
six staged create images, verifies their complete digests, crashes at every COW
publication event, and runs the full reachable validator. It selects only the
complete old or complete new graph. Authority remains inactive unless a
successful publication returns the exact receipt. After a fail-stop whose
superblock became durable, the in-memory model cancels the stale inactive
reservation and permits a fresh child handle only through the exact surviving
parent-directory handle carrying the distinct `OPEN_CHILD` right. The name
identifies the recovered child but does not authorize it; requested rights must
be valid for the recovered kind, and the fresh handle retains parent lineage so
revocation is transitive. `LOOKUP` alone cannot manufacture authority. Reboot-
time capability checkpoint/reconstruction, block service/device integration, and
physical power-loss evidence remain pending.
Capability-authorized file reads split an arbitrary bounded range across exact
extent records, synthesize sparse holes as zeroes, and require a backend to
verify the complete physical extent digest before copying any data subrange.
The buffer is erased if later verification fails. Bounded writes require exact
`WRITE` and, when length changes, `RESIZE`; accept only a complete successor extent map
and canonical file metadata for the next generation; reject reuse of active
data or protected metadata blocks; stage and durably flush the complete new
extent images; then return an unpublished state that can commit only through a
matching COW metadata plan containing internally derived digests for both the
canonical file record plus its complete zero tail and the zero-padded
extent-list image. The backend also
verifies the complete logical-file digest before flush. The backend and
allocation persistence remain simulated. A canonical fixed-capacity allocation
index binds each data or metadata range to one exact object generation, requires
physical ordering, and rejects overlap across all owners plus volume-header and
superblock use. Explicit fixed-capacity transactions admit
multiple prepared file successors, bind their independently advancing object
generations to one later volume-publication generation, require every derived
metadata image in one COW plan, and issue one-use participant receipts only
after root publication succeeds. Redundant-root recovery decodes both exact
superblock images, requires complete reachable-metadata validation through a
fail-closed backend contract, selects only identical or adjacent valid
generations, and permits fallback only when the other candidate is proven
invalid. The allocation index provides the ownership proof needed by that
validator and exact-block adapter but is not yet loaded from or published to a
real block service/device.
The allocation index now has a canonical block-aligned image whose header binds
the volume, publication generation, record width/count, complete-image digest,
and zero padding; decoding reconstructs and revalidates the index rather than
trusting serialized ownership. It is still not connected to a block backend.
Allocation-image ownership is a distinct kind bound to the selected root and
publication generation rather than being confused with ordinary object
metadata. Extent lists likewise have a canonical block-aligned image binding
file identity, object generation, logical length, fixed record geometry,
complete-image digest, and zero padding; decoding rebuilds exact coverage and
physical-range invariants.
Directory-entry lists now have the same canonical image treatment and rebuild
duplicate-name/object invariants. A fixed-capacity reachable-tree validator
loads the selected allocation image through one immutable-generation backend,
requires exact self-ownership, walks root and child directory/file metadata,
checks parent and generation links, decodes entry and extent images, binds every
data range to exact allocation ownership, and rejects every orphan allocation.
Repeated object references and capacity overflow fail closed. The root selector
and reachable validator are exposed as one bounded recovery entry
point. Simulation rejects a checksum-valid newer superblock whose referenced
allocation generation was not published and explicitly falls back to the fully
validated adjacent root; an indeterminate read of the newer candidate aborts
instead of becoming rollback. Publication is also exercised with separate
volatile and durable simulated
state at every COW persistence boundary. Pre-replacement crashes retain the old
root; the uncertain replacement/final-flush window admits either old or fully
metadata-durable new state; completed flush selects the new root. No partial
metadata generation is selectable. This remains a deterministic model, not
physical power-loss evidence. Allocation updates now build a complete
next-generation image rather than mutating live ownership. Frees affect only
that successor, additions are sorted
into its canonical index, its own metadata allocation rotates to the exact next
publication generation, and neither a retained nor same-successor-freed active
range may be reused before root publication. Allocation updates can now stage
that complete encoded allocation image
through a narrow unsafe durability contract. The service derives SHA3-256 over
the exact staged bytes and admits a distinct volume-allocation resource to the
multi-object transaction; it cannot collide with the root directory object's
participant identity. The successor becomes visible only after its exact image
is present in the COW plan and its one-use receipt is consumed. Directory
successors now stage exact canonical directory and entry images, bind both
images to a directory transaction participant, and expose the new immutable
state only after its one-use publication receipt is consumed. The exact-block
metadata and file-data adapters plus the bounded block-service core are
implemented. A bounded no-allocation service loop now composes exact IPC receive,
capability-shape validation, replay admission, capability-selected shared-buffer
syscalls, device dispatch, response send, and unconditional transport-buffer
erasure. Its syscall adapter is an unsafe authority boundary: principal,
capability transfer, mapping selection, endpoint, and reply task must come only
from authenticated kernel/launch state. The UEFI image compiles the concrete
x86-64 operations 4/5/7/8 adapter, but the loop is not yet instantiated as an
isolated hosted service process; physical
device backend, snapshots, physical power-loss testing, and persistent anti-rollback state
remain unimplemented. The EFI
System Partition and UEFI Simple File System remain appropriate FAT32 interoperability
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
service-state syscall now exposes only the adapter's query mechanism: an exact
task-local READ capability authorizes one opaque generational service token,
reserved registers must be zero, and the result is limited to Running, Exited,
or Faulted. The canonical query envelope now crosses buffered IPC with exactly
one sender-derived READ capability; the userspace service rejects missing,
extra, or payload-forged authority, invokes the syscall, and returns only a
fixed detail-free response. Restart request bytes contain no time, launch
address, stack, or priority. Operation 10 admits only capability plus service
identity and remains detail-free denied unless trusted code stages a matching
reprovision plan. Planning and commit are split around that boundary: commit
rechecks the exact service generation, object, completed cleanup, policy budget,
backoff, and plan freshness before creating a task. KVM and WHP can now construct
a third independently rooted verified service image for the eventual management
client. Its image, stack, and page tables are disjoint, and it receives neither
the two-service shared page nor the receiver-only resource mapping. In the
focused restart-request image, an independent task enters that root, blocks,
then sends one canonical restart request after old-generation cleanup. It
transfers exact CONTROL; the receiver cannot supply launch context or time.
Trusted kernel code stages the host shared-leaf re-arm, commits the one-use plan,
provisions the fresh task and least required capabilities, and returns a fixed
response verified by the manager. Signed KVM and WHP probes cover that exchange
but stop before replacement execution; ordinary service-probe runs separately
cover fresh-generation re-entry. This remains hosted controlled-probe evidence,
not persistent policy, host-resistant isolation, or physical-hardware evidence.
The bounded CPL3 request-
buffer ABI decodes fixed payload/capability-
buffer descriptors and validates every active user leaf before a directional
copy. The signed service
probe now executes real `mrml-config` schema admission and atomic commit
dispatch under both WHP and KVM. Each generation begins with a trusted root
identity and no settings. A canonical admission request identifies a bounded
typed schema but delegates only root CONTROL; object IDs remain names. Schema
mutation freezes after commit. A separate commit keeps payload authority zero,
independently attenuates fresh configuration-root CONTROL and setting WRITE,
and applies revision 1 only after both derived opaque handles pass exact kernel
validation. The canonical 112-byte responses return over the same bounded IPC
path. The supervised replacement repeats admission and commit from fresh
volatile service state, without claiming persistence across cleanup. Two
simultaneous blocked buffered receives retain independent bounded state. Service page-table
frames and a host-published signed-image entry page are supervisor-only mapped
so active-root validation and recovery remain available without granting CPL3
access. A canonical bounded checkpoint now preserves schemas, values, global
and per-setting revisions, and the retained chronological audit window. Export
requires exact root READ; recovery into fresh state requires exact root CONTROL,
canonical invariants, and a caller-supplied expected SHA3-256 digest matching
the embedded digest. The checkpoint is now staged as the complete content of an
exact stable-file successor under independently checked configuration-root READ
and file WRITE/RESIZE authority. Object identity, generation, length, content
digest, extents, and metadata are bound before staging; activation requires the
existing atomic COW publication and exact one-use transaction receipt. Recovery
accepts only an exact authenticated-recovery-selected file generation under
file READ plus configuration-root CONTROL and never treats I/O uncertainty as
permission to fall back. This remains simulated service-library integration,
not live block-device persistence, physical power-loss evidence, or reboot-time
capability reconstruction. It is not a clone of the Windows Registry, and
secrets remain separate.

A canonical persistent restart-policy value now connects recovered
configuration to trusted service registration without turning data into
authority. The fixed record binds one service object, a nonzero finite restart
budget, and bounded base/maximum backoff; version, length, and all reserved bytes
are canonical. Loading rechecks exact READ authority for the schema-bound
setting, requires the record's service to match the trusted expected object, and
retains configuration and setting revisions. Applying it revalidates the live
capability, exact value, service binding, and both revisions immediately before
requiring mutable trusted supervisor access; revocation or configuration drift
invalidates the bound value. Later restart remains independently gated by
exact service CONTROL, cleanup, trusted time/context, backoff, and budget.
Revoking configuration READ prevents future loads and use of an unapplied bound
value but does not pretend to erase policy already installed into a live trusted
supervisor. Dynamic replacement and reboot-time
capability/policy orchestration remain pending.

Networking is planned around explicit authority and bounded connection objects,
not ambient sockets. Raw packet and device access require separate capabilities.
Firewall policy remains a service and provides defense in depth; a firewall
allow rule never creates network authority.

Connection authority should expose the application, destination/scope, protocol,
and lifetime as meaningful objects without treating DNS names as authority.
Specific connection capability is preferred to raw networking, and network-
service compromise must not imply kernel compromise. User-owned state should
have documented export or migration paths where practical; secrets require an
independent export capability and trusted consent.

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
