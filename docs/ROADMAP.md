# MRML operating-system roadmap

This roadmap is dependency ordered. It describes intended work, not completion
claims. Status is determined from source, tests, and the evidence ledger in
[MICROKERNEL.md](MICROKERNEL.md), using the vocabulary in
[ARCHITECTURE.md](ARCHITECTURE.md).

## Work-in-progress limit

Maintain one foundational OS task plus, optionally, one independently scoped
compiler task. Never run two giant cross-cutting OS milestones simultaneously.
Each OS task advances one current dependency gate to a coherent tested endpoint
before the next OS subsystem begins. Compiler work may run alongside it only
when implementation, tests, review, commits, and performance/security evidence
remain independently attributable.

## Current priority

**PARTIALLY IMPLEMENTED:** the kernel has bounded IPC, blocking receive/wakeup,
two-message inbox backpressure, attenuated capability transfer with rollback,
generational revocation, bounded exact-generation IPC delegation tracking,
transitive descendant revocation, shared-memory bindings, mapping revocation,
fault retirement, service cleanup/restart policy, and signed two-service probes.
Kernel-owned receive envelopes now retain exact sender and endpoint sequence,
and bounded explicitly linked peers receive typed fault/exit results with
scheduler wakeup. Cross-CPU peer migration remains fail-closed until ownership
transfer for those relations is implemented.
The host-resource table now supports capability-authorized multi-party sharing
of one exact host extent across distinct VM mappings. Each added endpoint
independently proves mapping authority and liveness, cannot amplify the source
access, and must remain NX. Per-endpoint revocation reports when the final
reference is gone without exposing the opaque host handle to a guest.
Backend-neutral revocation now removes the exact KVM memory slot or every WHP
GPA submapping before retiring the common mapping identity. Any uncertain
native teardown poisons subsequent vCPU execution. Live Linux KVM and Windows
WHP probes now also exercise stopped-task leaf revocation for a common service
page while the peer mapping and backing remain live.
Service retirement now preflights restart timing and publishes an exact one-use
cleanup ticket. Restart remains blocked until the corresponding KVM/WHP eraser
proves the retired task and page-table root and completes exact-artifact
reprovisioning; failed erasure is retryable and ticket replay is rejected.
Shared endpoints may now bind an exact task generation in addition to their VM
and mapping identities. Cleanup invalidates each failed task's native mapping
before retiring its common mapping and binding, preserves peer endpoints, and
requires successful final host-resource retirement before restart. Completed
obligations survive retry across host-resource or address-space erasure failure.
The supervisor now exposes one bounded recovery operation that retires the
faulted task, publishes typed peer death, completes the caller-supplied
task-resource/address-space eraser, and creates a fresh service/task generation
from an independently validated context before returning the surviving peer's
scheduling outcome. Cleanup failure retains the exact ticket for retry; restart
rejection leaves a clean stopped service that can be authorized and retried
separately. Freshly signed WHP and KVM runs now exercise cleanup-ticket-gated
per-slot address-space reprovisioning across clean exit, fault, restart, and
restart-budget exhaustion. The general task-owned shared-binding/opaque
host-resource composition remains simulation-tested; the signed service path
now exercises its concrete one-page hosted realization on both backends.
Those signed paths now also establish an exact-generation control-peer relation
in each generation. Clean sender exit publishes a typed `Exited` result; the
kernel verifies its retired task identity and the queued message envelope's
sender and endpoint sequence before receiver continuation.

The next coherent milestone is an end-to-end service substrate: two isolated
CPL3 services communicate through a multi-client blocking control channel and a
revocable shared-page bulk channel; one service is deliberately crashed; the
kernel revokes its capabilities, mappings, IPC and shared state; peers receive a
typed death result; the supervisor performs one bounded clean restart; and the
unrelated service continues. Exercise equivalent signed paths under WHP and KVM
and add adversarial unit tests. This milestone must not claim host-resistant
confidentiality.

The signed two-service path now covers the blocking control channel, exact
sender/sequence envelopes, typed clean peer death, a revocable task-owned
shared page, cleanup-gated fault retirement, and bounded restart on both hosted
backends. The replacement generation now leaves its sender blocked and live
while the receiver faults; retirement publishes and validates the exact typed
fault result before returning any peer continuation. This closes the signed
two-service Phase 1 substrate gate. The next dependency-ordered OS milestone is
the Phase 2 policy/configuration service and its supervision protocol.

## Concurrent compiler lane

The independently scoped compiler lane follows
[COMPILER.md](COMPILER.md), not an arbitrary historical-rustc coverage target.
Rust 2024 is the floor. Preserve and stabilize the existing bounded semantics,
then prioritize:

1. an explicit typed ownership/place/control-flow representation;
2. move, shared-loan, mutable-loan, reborrow, and flow-sensitive outlives
   analysis toward modern Polonius semantics;
3. bounded modern trait-goal, canonicalization, where-clause, normalization,
   coherence, ambiguity, recursion, and cycle foundations;
4. post-2024 systems gaps, especially naked functions/`naked_asm!`, validated
   inline assembly, strict provenance, modern const behavior, and `no_std`/ABI
   facilities needed by MRML;
5. Application, System, and Compiler/Kernel admission profiles;
6. compiler-derived executable security metadata and loader validation; and
7. reproducible advancement through exact recorded future-Rust oracles.

The highest-value next major compiler milestone is the bounded typed
ownership/place/CFG representation needed by both sound borrow checking and
future dataflow analyses. Smaller aggregate, pattern, control-flow, and
diagnostic prerequisites remain appropriate when they directly unlock that
model. Old-edition parsing, historical unsoundness, rustc diagnostic wording,
unstable symbol/ABI quirks, and legacy cases with no current MRML dependency are
deprioritized.

Compiler candidates are ranked by MRML usefulness, modern Rust relevance,
security relevance, dependency unlocks, implementation complexity, oracle
stability, and testability—not superficial upstream test counts. The compiler
and OS lanes progress concurrently and converge when real MRML services compile
under validated profiles; neither waits for the other to become complete.

## Phase 1 — Kernel and service foundation

1. Complete multi-client blocking send/receive and scheduler sleep/wakeup.
2. Define bounded queues, backpressure, cancellation/timeout policy, and typed
   peer-death behavior.
3. Complete atomic capability transfer/derivation with non-amplification tests.
4. Complete transitive revocation accounting for IPC and descendants.
   **IMPLEMENTED:** successful transfers commit bounded exact-generation
   delegation edges; explicit source or intermediate revocation and task death
   revoke the complete descendant set before another task can run. Capacity is
   preflighted, denied transfers roll back both handles and edges, and domains
   with live delegation relations cannot migrate.
5. Add shared-page/ring setup with explicit ownership and access attenuation.
   **IMPLEMENTED** for the bounded one-page service substrate: KVM and WHP map
   one common frame through independent exact user read/write leaves, revoke
   only the retired task's leaf while preserving its peer, and re-arm leaves
   only after fresh task generations exist. General multi-page ring protocol,
   backpressure, and application-facing setup remain later work.
6. Pair mapping revocation with native KVM/WHP invalidation before vCPU resume.
   **IMPLEMENTED** in code, focused tests, and signed hosted probes. The vCPU is
   stopped for exact-leaf removal; the next service transition reloads CR3
   before peer continuation, and stale retired roots are never resumed.
7. Integrate fault cleanup, peer notification, erasure, and bounded restart.
   **IMPLEMENTED** in kernel mechanism and focused simulation tests: typed peer
   notification, task-domain revocation, native-first task-owned shared-resource
   cleanup, final host-handle retirement, exact erasure gating, and bounded
   restart are coupled through one supervised recovery operation. Cleanup and
   restart failures retain retryable fail-closed state. Signed KVM and WHP runs
   exercise exact per-slot address-space cleanup before restart plus
   exact-generation control-peer reconstruction, typed clean-death delivery,
   per-task shared-leaf revocation, surviving-peer access, and fresh-generation
   re-arm. The broader opaque host-resource composition remains outstanding
   live evidence rather than a missing kernel mechanism.
8. Benchmark one-way, round-trip, cross-core, wakeup, transfer, revocation, and
   shared-memory setup costs.
   **IMPLEMENTED:** release microbenchmarks cover backend-neutral
   one-way and round-trip IPC policy, blocked wakeup, capability transfer and
   revocation, shared-binding setup, and cross-runtime domain handoff. Windows
   evidence now includes a topology-validated affinity-pinned distinct-core
   mailbox round trip and live WHP map/revoke lifecycle; an Arch Linux/WSL2
   `/dev/kvm` run covers the matching KVM allocation/map/revoke lifecycle.

Security gate: no stale identity, capability, mapping, queue entry, or shared
page remains usable after death/revocation; partial operations cannot duplicate
authority; unrelated domains continue.

## Phase 2 — Minimal userspace system

1. Implement the policy/configuration service and service supervision protocol.
   **PARTIALLY IMPLEMENTED:** `mrml-config` provides a no-allocation typed
   schema, exact-object capability checks for reads and every transaction
   update, optimistic revision binding, atomic bounded commits, monotonic audit
   sequencing with explicit overwrite gaps, and strict version-1
   configuration/supervision request and response codecs. Kernel service-state
   introspection now requires exact READ authority rather than a service token.
   Message dispatch now takes authority only from kernel-derived receiver-space
   capabilities, rejects missing/extra/payload-forged authority, and composes
   authorized restart with existing cleanup, backoff, limit, and trusted fresh-
   context gates. Buffered syscall operations canonically bind payload and
   capability-descriptor addresses/counts, and
   mapping policy validates every complete user leaf and access direction before
   invoking a copy backend. Signed WHP and KVM probes now execute real
   `mrml-config` schema admission and commit dispatch in CPL3. Each signed
   generation begins with the trusted configuration-root identity and no
   settings. The client sends a canonical bounded schema record and delegates
   only attenuated root CONTROL; exact kernel authorization precedes admission,
   and schemas freeze after the first commit. A separate one-update request has
   zero payload authority and independently delegates fresh root CONTROL and
   setting WRITE before atomically committing revision 1. The supervised
   replacement repeats admission and commit from fresh volatile state. The same
   proof retains bounded lifecycle cleanup and covers two simultaneously blocked
   buffered receivers. A canonical bounded checkpoint codec now preserves all
   admitted schemas, values, per-setting/global revisions, and the retained
   chronological audit window. Export requires root READ; recovery requires
   root CONTROL and a caller-supplied expected SHA3-256 digest, and rejects
   corruption, hidden data, stale digests, capacity mismatch, and inconsistent
   revision/audit state. The digest is not self-authentication. The next gate is
   binding this codec to capability-native stable storage objects and an
   authenticated atomic commit/recovery protocol before this item is complete.
2. Define native filesystem object identities and attenuated directory/file
   rights, then the volume/superblock and directory/file metadata formats.
   **IMPLEMENTED:** `mrml-storage` supplies stable nonzero volume/object IDs,
   kind-specific rights without a universal administrator right,
   principal-bound generational handles, attenuated cross-principal derivation,
   and transitive descendant revocation. Version-1 fixed records cover volume
   geometry, an exact predecessor-linked superblock generation, directory and
   file metadata, and canonical bounded UTF-8 directory entries. SHA3-256
   self-checks detect covered corruption only; they provide neither authority,
   authenticity, atomic persistence, nor rollback resistance. Windows and
   Linux unit tests exercise malformed records, wrong volumes, stable identity
   across rename, rights confusion, stale handles, and descendant revocation.
3. Implement extent mapping, checksummed COW metadata, directory operations,
   file reads/writes, explicit transactions, and crash recovery in that order.
   **PARTIALLY IMPLEMENTED:** canonical extent records bind an exact file and
   metadata generation to a bounded logical range, either a physical data range
   with a content digest or an explicit hole. A fixed-capacity map requires
   ordered gap-free coverage of the rounded file length, bounds data ranges to
   the volume, excludes the volume header and both superblocks, rejects
   intra-file physical overlap, and returns bounded logical lookup results.
   Reserved future kinds are rejected rather than treated as compression,
   encryption, or sharing. The COW publication planner then requires an exact
   successor generation, inactive superblock target, nonoverlapping new ranges,
   active-range preservation, staged-image digest verification, metadata flush,
   atomic superblock replacement, and final flush in that order. Prepublication
   failure is clean rejection; replacement or later failure is fail-stop.
   Concrete block-backend integration, allocation ownership across files, a
   complete COW tree, and every later operation in this item remain pending.
   Directory lookup/enumeration/create/rename/remove and atomic cross-directory
   file moves are now implemented over fixed-capacity state. Every operation
   requires the exact directory object and operation-specific right; create
   allocates a service-owned stable ID and returns object-bound authority, while
   rename/move preserve identity and open capabilities. All failure-prone checks
   precede mutation. Cross-directory directory moves remain rejected pending a
   bounded ancestry proof, and allocator persistence awaits transactions, so
   directory operations are not yet complete or crash-safe.
   Bounded file reads are now implemented. Exact file `READ` authority is
   checked before range details, immutable file state must match its extent-map
   object/generation/length, sparse holes return zeroes, and every physical data
   extent is completely SHA3-256-verified by the backend before its requested
   subrange is copied. Reads are capped at 1 MiB and erase partial output after
   any backend verification failure. Bounded file writes are now implemented as
   COW preparation plus publication. Exact `WRITE` and conditional `RESIZE`
   authority precede all state disclosure; the patch is capped at 1 MiB; the
   complete successor map and canonical `FileMetadata` must bind the same object,
   exact next generation, length, and extent count; and new data ranges cannot
   overlap active data or protected metadata. The backend stages and flushes
   complete digest-verified new extents before returning an unpublished state.
   That state commits only through a COW plan containing the internally derived
   exact file-metadata and canonical zero-padded extent-list digests, while the
   backend verifies the complete logical-file content digest before flush.
   Explicit fixed-capacity multi-file transactions are now implemented. Each
   admitted prepared write retains its exact object predecessor/successor while
   its derived metadata images are bound to one independent volume-publication
   generation. Duplicate objects or metadata ranges, capacity overflow, missing
   plan writes, empty transactions, and wrong publication generations fail
   before backend I/O. One COW root transition produces a receipt whose exact
   participants can each activate once. Directory/allocator participation,
   concrete block/allocation integration, and crash recovery remain pending.
   The bounded redundant-root recovery selector is now implemented: both exact
   superblock records are decoded and passed to a complete-graph validation
   contract; two usable candidates must be identical at one generation or
   adjacent generations, and only the newer is selected. A single usable
   candidate is explicitly reported as fallback. Proven-invalid candidates may
   be bypassed, but indeterminate backend failures abort instead of silently
   rolling back. A concrete reachable-tree validator, block backend, power-loss
   harness, repair, and authenticated anti-rollback state remain pending, so
   crash recovery is still only partially implemented.
4. Add snapshot objects and capability enforcement, then system-generation and
   authenticated update integration.
5. Add compatibility filesystem readers and optional advanced storage features
   only after measured need; they do not define native semantics.
6. Implement a network service returning bounded connection capabilities.
7. Add firewall/network-policy as defense in depth outside the kernel.
8. Add tool and local-inference services over control and bulk IPC.

Security gate: services start with explicit least authority; paths, ports,
names, identity, and signatures do not grant ambient access; raw packet/device
access is separately privileged; service failure is contained. Filesystem names
and IDs never authorize, rename preserves object identity, transactions are
all-or-nothing, covered corruption is detected, inconsistent recovery fails
safely, and snapshots require authority without implying anti-rollback.

### Phase 2 virtual-device and service progression

The VMM device family proceeds in this order: serial/console, block, network,
input, graphics, audio, additional MRML-specific transports, then compatibility
emulation only as required. Establish common queue, lifecycle/reset, interrupt,
PCI-transport separation, and QEMU differential harnesses before broad device
coverage. Every applicable device must behave consistently under KVM and WHP.

Networking proceeds from capability-bound network objects and a basic native
service to packet buffers/rings, a basic backend path, firewall integration,
then a VirtIO-net-compatible device and QEMU comparison. Multiqueue, offloads,
and tuning follow baseline correctness and measurement.

Audio proceeds from capability-bound device/playback/capture/session objects and
an explicit timing/format model to userspace mixing, basic output, capture,
trusted capture indication, trusted accessibility speech output, local trusted
speech capture/control, then VirtIO-sound or an MRML virtual-audio device
connected to the host service. Application playback/capture, accessibility
speech, VM audio, and notifications retain separate capabilities and privacy
boundaries. Latency/jitter measurement precedes advanced routing and
multi-device work.

USB proceeds from device/interface/endpoint capabilities and a host-controller
abstraction through enumeration and bounded descriptor parsing, then HID and
storage classes, refreshable Braille and accessibility HID protocols, other
classes as needed, per-interface delegation, VM
passthrough lifecycle, and physical IOMMU/DMA validation. Legacy controller
emulation comes only with a demonstrated compatibility need.

Security gate: device creation grants no implicit backend authority; descriptors
and guest memory are bounded and directional; stale queue state dies on reset;
host policy cannot be bypassed by a guest; capture and playback, composite USB
interfaces, ordinary input and secure attention, and paravirtualization versus
passthrough remain distinct authorities.

## Phase 3 — Safe applications and trusted GUI foundation

Before trusted consent UI, establish the application-facing foundation:

1. Specify bounded versioned service protocols and a safe SDK without freezing
   Rust's internal ABI or creating a general public C/C++ ABI.
2. Define transitive memory-safe application admission and dependency/FFI rules.
3. Project the same capability-preserving API into application microVMs.
4. Define logical display coordinates and output identities for fractional
   per-monitor HiDPI.
5. Define capability-bound graphics objects, keeping surfaces, buffers, render
   devices, display outputs, command queues, and fences distinct.
6. Implement the trusted compositor boundary, non-spoofable domain identity,
   surface commit protocol, and backend-neutral compositor/display interface.
7. Implement software composition, GOP presentation, and damage tracking in
   that order.
8. Add bounded asynchronous fence semantics.
9. Define the VGPU resource protocol and shared command/completion transport,
   then implement accelerated VGPU rendering.
10. Support live GOP-to-accelerated takeover and accelerated-failure-to-GOP
   recovery; native physical GPU backends come later.
11. Implement a bounded, generational semantic scene graph with authorized
   incremental subscriptions and resynchronization.
12. Add deterministic focus order and keyboard semantic actions, then a bounded
    accessibility semantic API with uniform secret redaction.
13. Add basic trusted local speech output and a Braille representation/backend;
    simulated evidence does not establish physical-device compatibility.
14. Add Braille input/routing and local deterministic speech input/control over
    semantic actions, preserving distinct microphone and device authorities.
15. Benchmark scene updates, input-to-action latency, composition, damage,
    synchronization, scaling, takeover, and recovery.

The graphics device may add VirtIO-GPU compatibility for guest display and 3D
interoperability, with QEMU differential tests. It must preserve the existing
MRML-specific CUDA compute protocol as a separate capability surface carrying
signed kernel admission, authenticated queues, quotas, watchdog/reset, and CPU
fallback. Display compatibility must not regress CUDA capability or performance.

Security gate: ordinary native apps cannot introduce unsafe native code or
ambient authority; VM transport cannot widen capabilities; applications cannot
spoof trusted surfaces; stale semantic identities/deltas cannot target reused
objects; surface/buffer ownership cannot become scanout or cross-process access;
backend changes preserve validation; semantic inspection and raw input remain
separate authority; trusted prompts have nonvisual semantics; accessibility
cannot bypass secret redaction or grant universal observation/input authority.

## Phase 4 — Browser and AI application control

1. Build the browser as isolated services with no JIT and strict W^X.
2. Keep WebAssembly inside the browser boundary and mediate every sensitive API
   per origin and capability.
3. Expose a sanitized semantic document tree with deliberate bounded actions.
4. Project that same tree to browser accessibility and keyboard operation.
5. Represent visual web/media content as lazy capability-controlled objects
   carrying captions, transcripts, audio descriptions, chapters, language, and
   timing where available.
6. Add authenticated application-VM semantic projection, then bounded bridges
   from compatibility-guest accessibility APIs; guest content cannot assert
   trusted host identity.
7. Add cohort-normalized fingerprint surfaces and regression testing against
   independent fingerprinting suites.
8. Add local/remote AI disclosure controls, incremental graph transport, and
   explicit visual-inspection requests.

Security gate: web content cannot reach native admission, arbitrary JavaScript
control, browser memory/debug authority, raw devices, or W+X execution; AI does
not receive secrets, screenshots, media, HID injection, or global GUI control
without the exact capability. Fingerprint claims require empirical evidence.

Accessibility verification proceeds alongside Phases 3 and 4 rather than after
the GUI is complete. Add semantic completeness, focus ordering, keyboard-only,
Braille/speech representation, redaction, trusted-prompt, VM/browser projection,
HiDPI/backend-independence, and capability tests. Dogfood core workflows without
pointer or framebuffer inspection. Add physical Braille and alternative-device
tests when hardware is available and label simulation separately. Extend
accessible semantics into boot errors, rollback, login, recovery, and repair as
early as service/hardware prerequisites permit without claiming unfinished
early-boot support.

### Accessibility dependency lane

Within and across Phases 3 and 4, preserve this dependency order:

1. prove Semantic Scene Graph correctness and incremental synchronization;
2. add deterministic focus and keyboard semantic actions;
3. define a bounded accessibility semantic API with shared redaction;
4. add automated semantic completeness, action, and parity tests;
5. add trusted local speech output;
6. add the transport-neutral 40-cell-baseline Braille line presentation;
7. add bounded interoperable physical Braille transport;
8. add Braille routing and input through semantic actions;
9. operate trusted prompts through Braille and speech;
10. integrate browser structured accessibility;
11. pass a basic monitor-off desktop workflow;
12. add authenticated VM and compatibility accessibility bridges;
13. add deterministic local speech control before optional AI interpretation;
14. add Deaf/hard-of-hearing semantic system-event parity;
15. refine cognitive, motor, and low-vision behavior;
16. conduct practical usability testing with disabled users across multiple
    interaction modes;
17. pass the full supported monitor-off core suite;
18. only then consider accessibility ABI stabilization.

User testing cannot be deferred until after ABI freeze. CI grows to cover
semantic completeness, focus, keyboard-only operation, shared redaction,
trusted prompts, AI/accessibility parity, Braille lines/routing, speech,
VM/browser projection, HiDPI, and rendering-backend independence. Track focus-
to-Braille/speech, Braille/speech-input-to-action, and delta-propagation latency.
Physical hardware and disabled-user evidence remain distinct from simulation.

## Phase 5 — Authority, consent, and observation

After the core capability/service substrate and trusted compositor exist:

1. Add bounded capability provenance tracking and delegation audit events.
2. Add an access-controlled capability introspection/explanation API.
3. Implement trusted file-picker capability delegation.
4. Add the structured system-monitor authority and security-exception view.
5. Add common time/lifecycle-bounded capability expiration.
6. Define `SecretObject` and independent use/export rights.
7. Add non-extractable credential operations and trusted export consent.
8. Make local/remote AI sessions visible, expiring security principals.
9. Add structured diagnostic objects with observation-only capabilities.
10. Add exact-target, independently attenuated debugging rights.
11. Add disposable application/VM domains and trusted identity indicators.
12. Add bounded object provenance/history.
13. Preserve data-origin/taint labels through service and AI boundaries.
14. Integrate provenance with prompt-injection-resistant AI context/tool policy.
15. Add device ownership/delegation visualization and transition audit.
16. Add deterministic system-generation metadata.
17. Integrate crash/restart policy with persistent-state restoration.

In parallel, implement the capability-native authority broker with narrow scope,
duration, and one-shot grants; the trusted userspace consent agent with anti-
spoof transaction binding; protected audit storage; and a non-omnipotent
security monitor with separate observation/remediation capabilities. Do not
attempt the entire list as one change.

Security gate: identity is not authority; temporary grants expire/revoke on all
specified paths; applications cannot forge consent or privileged events; the
monitor cannot exceed its explicit capabilities. Names, object IDs, and data do
not create authority; introspection leaks no secrets; `USE` never implies secret
`EXPORT`; debug stays target-scoped; AI remains non-root; disposable domains
retain no undeclared persistent authority.

Trusted consent depends on the Phase 3 compositor boundary. The authority broker
and non-UI policy core may be developed earlier, but no application-rendered UI
can count as trusted consent.

## Phase 6 — Persistent security state and boot

1. Implement a TPM NV or equivalent authenticated, monotonic, power-loss-atomic
   release-state backend.
2. Bind measured boot to the exact coherent signed artifact set.
3. Add rollback, stale-update, corruption, interrupted-write, and recovery tests.
4. Establish reproducible builds, independently controlled release keys,
   Secure Boot integration, recovery, and key rotation.
5. Bind inspectable system-generation metadata to the exact kernel, compositor,
   services, configuration root, and compiler/runtime artifacts.

Security gate: older signed vulnerable releases cannot be admitted after a
committed advance; loss/corruption fails safely and has a documented recovery
path. No rollback-resistance claim precedes physical testing.
Generation identity is not called deterministic until both artifacts and
configuration are reproducible.

## Phase 7 — Bare-metal hardware isolation

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

## Phase 8 — Hardening and expansion

Continuously fuzz parsers, IPC, shared-memory metadata, capability abuse, and
corruption paths. Stress SMP races, mapping/revocation races, interrupts,
crashes, exhaustion, network adversaries, and power loss. Perform unsafe/FFI
review, application dependency/admission tests, browser fingerprint regressions,
semantic-graph desynchronization and spoofing tests, side-channel analysis,
formal specification of critical capability and noninterference properties,
reproducible release review, and external audit. Investigate CET/IBT only as
defense in depth for relevant trusted native boundaries; do not claim or depend
on enforcement until implemented and exercised. Only then consider broad
drivers, production claims, AArch64, and RISC-V64.

Guest-device fuzzing prioritizes VirtIO descriptors and indirect/cyclic chains,
virtual-network packets, audio control, USB descriptors, PCI configuration,
VGPU/CUDA commands, block requests, interrupt delivery, and lifecycle/reset
transitions using malformed, truncated, oversized, repeated, and stale inputs.
Differential tests run the same guest workload against QEMU and MRML and explain
every guest-visible difference; matching QEMU is not itself a security proof.

Every milestone requires proportional Windows gnullvm and Linux testing,
backend-specific signed probes where applicable, exact commands/results, and
before/after performance measurements. Unsupported environments must be listed,
not implied.
