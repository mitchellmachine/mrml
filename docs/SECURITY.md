# MRML operating-system security model

This document states security boundaries and non-claims. Implementation details
and dated evidence are in [MICROKERNEL.md](MICROKERNEL.md).

## MRML security principles

1. No ambient authority.
2. Identity is not authority: names identify; capabilities authorize.
3. Power should be explicit, limited, inspectable, and revocable.
4. Memory safety is the default for ordinary native applications.
5. Minimize the trusted computing base.
6. One compromise should remain one compromise; one crash should remain one
   crash.
7. Transient compromise must not imply persistence.
8. Secrets can be usable without being extractable.
9. Intelligence does not imply authority; AI is never root.
10. Accessibility cannot bypass security, and security cannot arbitrarily
    disable accessibility.
11. Security enforces the owner's policy.
12. Remote attestation is owner-controlled and privacy-scoped.
13. Publisher metadata does not create authority.
14. First-party software gets no hidden privilege.
15. Data collection, metadata exposure, and retention are minimized.
16. Compatibility does not receive ambient privilege.
17. Claims require evidence.
18. Hardware-dependent claims require real-hardware evidence.
19. Secure defaults must not dispossess the machine owner.
20. Security mechanisms must not become general-purpose DRM against the owner.

These principles apply to applications, services, administrators, VMs, devices,
first- and third-party software, accessibility software, and local or remote AI.

## Trust boundaries

CPU age, generation, or marketing identity does not establish vulnerability
status. Final mitigation policy derives from exact identity, capabilities, and
resulting microcode state after an approved vendor-specific update attempt;
unknown security-sensitive state fails conservatively. Power profiles cannot
silently disable required mitigations. See
[platform/CPU_PLATFORM.md](platform/CPU_PLATFORM.md).

Hosted WHP/KVM is for development, compatibility, and measurement. A compromised
host controls guest RAM, CPU state, clocks, devices, entropy, keys, and results;
therefore it is not a security boundary against that host.

The experimental Windows VBS design targets only the documented VTL0 adversary
and trusts Hyper-V, the secure kernel, VTL1, Microsoft platform verification,
and the stated hardware/firmware base. It is local protected execution, not
remote attestation. Raw reports are unverified bytes and never authenticated
evidence. Only the verifier-enclave path may authenticate the same report bytes.

The intended bare-metal boundary places authority and receipt-key custody in an
MRML VMX-root monitor. The current nested-KVM VMX/EPT execution is a controlled
probe, not physical bare-metal proof. Bare metal still trusts CPU/microcode,
chipset, memory controller, RAM, the selected hardware root, firmware that
establishes the machine, and authenticated loader/kernel/policy. Compromised
UEFI, SMM, platform processors, hardware, and physical attacks are outside the
present enforceable boundary.

Devices, device firmware, DMA, networks, models, tools, external data, binary
formats, service messages, and host inputs are untrusted.

## Admission, receipts, and secrets

Versioned component admission follows
[packages/COMPONENT_INTERFACES.md](packages/COMPONENT_INTERFACES.md): signatures
authenticate provider provenance but do not prove ABI conformance, memory safety,
semantic correctness, or authorization. Metadata grants no capability. Bindings
select exact immutable generations, incompatible major ABIs fail closed,
executable pages are never patched in place, and prohibited generations receive
no new bindings. In-process providers share caller fault impact; service
providers remain isolated and explicitly capable.

Raw and receipt-authenticated admissions remain distinct types. An authenticated
receipt binds the exact canonical request digest, independently expected policy,
backend/mode, claims, image measurement, security version, nonce, sequence, and
debug state. Authentication from one mode cannot satisfy another mode. Invalid,
stale, mismatched, cancelled, or replayed requests fail without incorrectly
advancing replay state.

Secret release requires all of the following: an authenticated receipt, exact
request and policy binding, the exact allowed backend, non-debug execution,
proper one-use sequence/replay handling, and the documented measured sealed-key
claim. A raw report, host-visible marker, broker success, or self-asserted claim
can never release a secret.

The VBS broker is untrusted transport and holds no receipt key. Production VBS
keys are intended to be generated and sealed within VTL1 to exact non-debug
code. The bare-metal monitor derives its receipt key internally once after
entry; callers cannot inject or retrieve it. Bare-metal domain workload keys
remain internal to VMX root. These mechanisms are launch-local and do not by
themselves provide persistent identity, TPM sealing, physical-execution proof,
or remote attestation.

## Capability and isolation invariants

The planned adaptive placement policy is specified in
[ISOLATION_PLACEMENT.md](ISOLATION_PLACEMENT.md). Placement metadata never grants
authority, mandatory floors fail closed, and microVM capabilities are separately
projected and revocable.

Memory allocation is quantitative authority distinct from mapping and content
access. The security/acceptance gate is canonical in
[memory/MEMORY_RESOURCE_MODEL.md](memory/MEMORY_RESOURCE_MODEL.md).

- Object identity is not authority; names and data are not authority.
- Identity and provenance may select policy but do not grant authority.
- Capability derivation cannot increase authority.
- Object and task identities are nonzero, bounded, and generational; stale
  identities cannot regain access after slot reuse.
- Capability slot generation zero is invalid. Revocation advances generations
  with checked arithmetic; a slot at the terminal generation is cleared and
  permanently retired, and allocation reports explicit exhaustion rather than
  wrapping to generation one. This kernel mechanism and focused adversarial
  tests are **IMPLEMENTED**; it does not establish production assurance.
- Revocation precedes reuse and covers all derived state in the operation's
  boundary. Uncertain device/DMA teardown quarantines or fails closed.
- Boundary copies validate complete ranges, overlap, wrapping, alignment,
  length, reserved fields, and exact encodings before mutation.
- Buffered IPC completion retains a typed exact-capacity witness through the
  final trap-frame or saved-context publication; loose result scalars cannot
  replace the checked pending receive bounds.
- Buffered send descriptors and receive-token outputs use distinct element
  widths and complete checked user ranges; validating only their starting
  address is insufficient.
- Buffered payload input and output likewise require complete non-wrapping user
  ranges at syscall decode, before page-table walking or copying.
- Buffered payload and capability regions must be disjoint; exact adjacency is
  valid, but overlap fails before parsing or output mutation.
- Hosted service-probe buffered IPC copies use task-bound, directional,
  single-use active-user-copy tickets; pending capacity validation does not
  substitute for exact-length validation at resumed output-copy time.
- Capability-buffer byte lengths are checked once and retained through overlap
  validation and hosted token encoding rather than recomputed unchecked.
- A pending buffered receive is bound to its admitted page-table root as well as
  its generational task; completion under a substituted root fails closed.
- Resumed buffered completion takes its pending record before consuming the
  message, so duplicate or re-entrant completion cannot replay the same slot.
- Pending-record lookup requires a unique generational-task match and fails
  closed on duplicate internal state.
- The hosted service runtime and pending-receive table share one named
  three-task capacity; task capability spaces use a separate named nine-slot
  capacity rather than duplicated numeric configuration.
- Service-image receive adapters reject kernel-returned payload or capability
  counts beyond their exact supplied slices before exposing the result.
- Service-image capability-transfer descriptors have explicit ABI alignment;
  malformed width, count, alignment, or payload bounds fail before the trap.
- Configuration and supervision service-image dispatch releases each received
  leaf before response visibility; cleanup failure suppresses the response.
- Capability-release syscall denial covers invalid task-local handles only;
  unexpected runtime or delegation-integrity failure is fail-stop.
- Restart-policy replacement denial covers unknown service or unauthorized
  capability only; generation exhaustion and impossible lifecycle errors halt.
- Service query maps only lookup/authorization failure to absence. Split-phase
  restart maps documented policy drift or capacity exhaustion to denial, while
  terminal identity, generation, policy, or runtime errors fail-stop.
- Capability authorization maps only task-local IPC/capability errors to
  denial; missing task state or unexpected runtime errors fail-stop.
- Malformed service syscall arguments return a generic error with scrubbed
  result registers. Invalid privilege/return-frame state remains fail-stop
  pending safe task-scoped retirement rather than an unsafe `iret`.
- Boot-recovery operation 13 preserves the same distinction through an explicit
  `InvalidReturn` decoder result instead of conflating it with bad arguments.
- Service sends return scrubbed failure only for a kernel-classified precommit
  denial or malformed descriptor; scheduler and integrity failures fail-stop.
- Buffered-send payload, descriptor, decoded-handle, and requested-rights
  staging is erased at bounded last-use points on success and denial.
- The MRML-native ZIM consumer applies the same exact-capacity rule at its
  buffered-receive boundary and uses explicitly aligned exact-width storage for
  its outgoing capability descriptor.
- Writable and executable mappings are mutually exclusive.
- Authority, replay state, ownership, mappings, and lifecycle transitions are
  explicit and commit only after validation; partial failure rolls back or
  leaves a fail-closed state.
- One service fault must not confer authority on another service or require an
  unrelated kernel/system failure.
- Temporary capabilities must actually expire and revoke every derived path;
  disposable domains must not silently retain persistent authority.
- Secret `USE` does not imply `EXPORT`; remote AI receives no secret material or
  export right by default.
- Debug authority is exact-target and rights-scoped, never implicitly global.
- AI control is not user/root authority, and provenance labels never replace
  capability enforcement.
- Storage and optical inspection, health, content, write, erase, burn, eject,
  and delegation rights remain separate and exact-generation as defined in
  [storage/STORAGE_AND_OPTICAL.md](storage/STORAGE_AND_OPTICAL.md).

Compromise cleanup generalizes the Phase 1 lifecycle rules: revoke task/service
capabilities and descendants; remove native mappings; invalidate IPC, queues,
shared state, cached decisions, and exact generations; destroy stale credentials
and tokens; clean or quarantine device/DMA assignments; erase sensitive transient
state; and restart only from independently validated state. Half-complete cleanup
fails closed. Successful code execution in one component cannot create durable
authority unless the principal separately holds the narrow persistent-object
capability for startup, service replacement, configuration, executable trust,
credentials, boot state, or firmware.

Dynamic supervision-policy replacement treats cached configuration as data,
not authority. Application requires an explicitly supplied live READ
capability for the exact schema-bound setting and rechecks its value plus global
and setting revisions immediately before mutation. The supervisor separately
requires exact CONTROL for the service object. A bounded policy generation
invalidates restart plans prepared before a change; generation exhaustion is
non-mutating. Replacement preserves consumed restart count and an already-
computed eligibility deadline, so rewriting policy cannot manufacture retries
or shorten pending backoff.

The policy-replacement syscall is pointer-free and separately bounded. Its
service token identifies a live supervisor slot but supplies no object
authority. The kernel decodes a finite valid restart policy, rejects every
reserved or overflowing scalar, and then authorizes exact CONTROL in the
calling task's capability space against the supervisor's live service object.
Completion exposes one success bit and no object, generation, rights, policy,
budget, timing, or denial detail. It accepts no configuration-setting claim.
The userspace protocol keeps a trusted service-object mapping, revalidates the
canonical record through an IPC-derived exact setting READ capability, and
requires a second ordered IPC-derived exact service CONTROL capability before
invoking this mechanism. Missing, extra, reordered, stale, or payload-forged
authority fails closed.

Configuration checkpoint storage can now use the exact-block volume through a
principal-bound MRML block-service session. Configuration-root READ, stable-file
WRITE/RESIZE, block-session operation rights, exact object/generation/extents,
complete digests, publication generation, and one-use receipt remain distinct
checks. Device identity and checkpoint bytes authorize none of them. A derived
read-only block session fails before backend mutation, and revoking its parent
stales the complete session lineage. Fresh identical signed artifacts now run
this composition in isolated CPL3 tasks under hosted KVM and WHP. Operation-
specific local shared-buffer handles remain separate from transfer authority,
and received leaf capabilities are released after every request. The backend
is volatile kernel-owned memory, so this is controlled hosted evidence, not
reboot, durability, power-loss, host-resistance, or rollback-resistance
evidence.

Reboot-recovery composition now validates dependent configuration and its exact
service-bound restart policy while reconstructed storage authority remains
private to one consumed transaction. The authenticated monotonic store advances
only after that validation succeeds, and neither authority nor policy is
released if validation, storage I/O, conflict detection, or compare-and-store
is uncertain. The validator is an explicit unsafe side-effect-free boundary;
checkpoint bytes, reconstructed handles, object identities, digests, and policy
records remain non-authorizing data outside the exact capability checks.
Service registration is split around that boundary: immutable planning binds an
exact vacant supervisor slot/generation, service object, task, and validated
restart policy; consumed commit rechecks the slot only after authenticated state
has advanced. A distinct committed-authority type prevents safe code from
releasing a recovered service from pre-commit reconstruction. Epoch mismatch,
slot reuse, capacity loss, or registration failure drops the recovery result.

## Persistent state and boot

Firmware mutation and Secure Boot policy follow
[platform/UEFI_BOOT_MANAGEMENT.md](platform/UEFI_BOOT_MANAGEMENT.md): typed
generational transactions, re-read verification, owner-controlled keys,
SecretObject use/export separation, versioned Windows/Option-ROM compatibility,
monotonic revocations, dual-boot preservation, and physical evidence gates.

Package/update/deployment security follows [DEPLOYMENT.md](DEPLOYMENT.md): UEFI
authentication and MRML release authentication are separate; GitHub is transport,
not trust; individually valid packages do not form a release automatically;
catalog and generation rollback/freeze protection is mandatory; imaging cannot
export non-exportable secrets; and disk destruction requires authorization bound
to the exact revalidated transaction.

Signed images alone do not prevent rollback. TPM-backed or equivalent
authenticated, monotonic, power-loss-atomic storage; measured boot; exact
artifact-set admission; corruption handling; recovery; and key rotation remain
required. Development signing is not production Secure Boot.

The legacy loader path extends a canonical selected-set record after separate
authenticated kernel and service payload events. Manifest-configured boot now
requires bounded kernel, VM, service, CUDA, and launch-policy bundles, admits
each through the exact same `VerifiedRelease`, and publishes no root transition
while any kind is absent or invalid. It separately extends every authenticated
payload and a canonical 512-byte version-3 set record containing a distinct
manifest identity plus all five ordered artifact identities. Zero identities
fail before measurement, and the measured-boot flag requires every extension.
The additional firmware buffers are zeroed and returned before memory-map
handoff. This is code and hosted-test evidence, not firmware/TPM execution,
owner trust-root persistence, remote attestation, or direct measurement and
independent verification of configuration and compiler/runtime artifacts;
Phase 6 remains partial.
The configured policy artifact is now required to decode as the canonical
release build receipt before a new journal transition can publish. Its kernel
and service identities must match the exact authenticated payload lengths and
SHA3-512 digests, and all six recorded digests must be nonzero. This binds the
remaining recorded source, lockfile, loader, configuration, and tool
declarations into signed generation evidence, but does not independently
verify those input bytes at boot or prove truthful compiler/runtime identity.
Receipt contents remain data, grant no authority, and cannot widen any
manifest capability or owner trust decision.
At the release-manifest boundary, callers can no longer extract a per-kind
minimum-version trust root and accidentally admit a later artifact into an
earlier verified release. `VerifiedRelease` now authenticates only the exact
manifest release and exact requested kind; executable payload parsing follows
that check. Tests reject both older-manifest/newer-artifact and newer-manifest/
older-artifact substitution plus kind substitution. This is unit-tested
admission machinery, not UEFI manifest integration or durable release commit.
Manifest admission also rejects every root-role collision: the next manifest
root and five artifact roots must be pairwise distinct, and none may equal the
current authenticated manifest-signing root. This prevents one Lamport key from
being authorized for a second statement or a different artifact role. The
check is local key-lifecycle enforcement, not proof that external backups were
destroyed or independently controlled.
Release-state compare-and-store now binds all 152 authenticated predecessor
bytes, closing same-floor current-root and installed-manifest substitution. A separate 200-byte
two-slot journal writes and verifies the inactive successor before advancing
its authenticated monotonic counter, then reloads the selected state. Corrupt
slots, stale predecessors, failed writes, pre-commit failures, uncertain
committed advances, read failure, and sequence exhaustion fail closed in
deterministic tests. Its unsafe backend still requires fixed owner-provisioned
objects and real power-loss-atomic behavior. The UEFI adapter now admits a
separate counter and two exact 200-byte full-write objects by complete public
area and recomputed Name, consumes fresh exact-operation policy sessions,
read-verifies writes, checks exact counter succession, and rejects index alias
with the recovery journal when both layouts are checked together. Deterministic
tests exercise these properties; no provisioning, reboot, physical power-loss,
or rollback-resistance evidence exists.
The authenticated state includes the exact installed-manifest digest, allowing
later boots to reconstruct the committed release authority without replaying
the consumed one-time transition. The firmware submission boundary is bounded
at 256 command bytes, large enough for the 235-byte release write without
permitting unbounded input.

When configured, the UEFI loader derives both kernel and service authority from
one authenticated release. An installed-manifest digest permits repeat boot
without reusing the consumed transition key; a different manifest must verify
as a new transition under the current root. Publication occurs only after both
signed containers and PE images pass exact-release admission, and before PCR 11
extension so the journal's read/write PCR policy remains coherent. Complete
release and recovery layouts must be index-disjoint. Required mode rejects an
absent or partial release configuration; optional development mode still uses
the legacy independent embedded roots.
The typed pending-release transaction makes incomplete publication fail closed:
neither manifest authentication alone nor one valid executable can advance the
journal. A state conflict retains the pending transition for a serialized retry;
repeat admission of the installed manifest performs no counter write. Exact
predecessor and successor bytes are erased when the transaction is consumed or
dropped.
The handoff represents manifest admission with its own canonical flag rather
than inferring it from version or PCR success. Production `BootPolicy` rejects
the legacy path even if Secure Boot, measurement, and a rollback counter are
present; development policy may opt into it. This loader evidence does not
manufacture authority for missing manifest artifacts and is not attestation.
An admitted monotonic release journal satisfies loader rollback evidence without
also requiring the legacy standalone counter. This avoids treating two counters
as one authority while retaining compatibility; physical resistance remains
unverified.

The UEFI TPM parser can now validate the exact public identity of a planned
owner-policy recovery layout: one monotonic counter and two full-write ordinary
slots under a shared nonzero policy digest, with every SHA-256 TPM Name
recomputed from its complete public area. This prevents numeric-index, type,
size, attribute, policy, and returned-Name substitution during admission. It
now feeds bounded TPM NV read/write/increment commands. Each operation consumes
a fresh one-use authorization from an unsafe owner-policy provider bound to the
exact Name, shared policy digest, and operation; safe code cannot construct that
session. Full slot writes are read-verified and counter advancement rechecks the
exact predecessor and successor. A concrete provider starts a fresh unsalted,
unbound SHA-256 policy session using explicit nonzero caller entropy, executes
one exact configured `PolicyPCR` recipe, and accepts only the requested next NV
operation. The concrete provider exists only after admission of the three exact
index/Name/policy tuples, and the next command must repeat the admitted index in
both handle fields along with the exact operation and session handle. Zero or
immediately reused caller nonces fail closed. Operation
mismatch, policy failure, and a malformed nonce following
a valid returned session handle trigger best-effort cleanup. The TPM still
enforces the admitted NV index's exact policy digest; the provider does not
derive authority from PCR data or expose remote attestation. The provider does
not provision the owner policy, authenticate an owner UI, establish transport
confidentiality, prove firmware integration, or establish physical durability,
so this remains protocol evidence rather than rollback-resistance evidence.
The safe journal constructor first admits all three exact NV public identities
on the raw transport, then constructs the provider from that sealed admission;
mismatched layout policy never yields a usable store.
The UEFI loader's optional development integration requires all six exact
configuration fields together, obtains every session nonce from a separate
firmware RNG call, and authenticates only the counter-selected slot before
`ExitBootServices`. Partial configuration and all TPM/RNG uncertainty fail
closed; temporary recovery bytes are erased. This admission is not owner
provisioning, authority reconstruction, artifact rollback evidence, remote
attestation, native UEFI execution evidence, or physical durability evidence.
The recovery-enabled loader now links as an optimized native
`x86_64-unknown-uefi` image. Its direct crypto dependency disables the unused
host-runtime default feature, and dependency inspection confirms filesystem,
network, process, and other `mrml-runtime` host facilities are absent from the
firmware graph. This reduces ambient code and capability surface but is linkage
evidence only, not physical TPM evidence. A fresh QEMU/OVMF nested-KVM boot of
pinned, independently signed kernel and service artifacts subsequently reached
the exact trace `a1 a2 a3 a4 a5 a6 a7 a8 b1 b2 b3 d0 d1 d2 d3 d4 df`. This
proves controlled loader and kernel execution, but recovery configuration was
absent because no software TPM was available. It is not recovery-journal,
Secure Boot, bare-metal, physical TPM, power-loss, or rollback-resistance
evidence.
Canonical recovery metadata crosses the loader/kernel boundary only in its own
optional fixed-size handoff record. Both encoder and decoder require nonzero
epoch and handle generation, zero reserved bytes, and an all-or-none nonzero
volume/root pair. Its flag is independent of rollback-protected boot evidence,
and the decoded value is explicitly data: it cannot authorize storage recovery
or manufacture a capability.
Storage recovery can now consume that data only by wrapping the independently
authenticated state store for one transaction. The authenticated load must
match all handed fields, and compare-and-store must reuse the exact loaded
record. Duplicate load, duplicate commit, handoff/store substitution, malformed
state, and backend uncertainty fail closed and erase exposed state bytes. This
binding does not bypass owner-approved checkpoint proof, exact capability-
authorized file selection, attenuation checks, dependent validation, or the
monotonic publication gate.
Kernel delivery is independently bound to one exact live task generation, one
object, and an exact non-delegable `READ` capability. The capability and tracked
descendants are revoked before the fixed metadata record is copied; successful
copy consumes the record. Wrong task/object, excess rights, stale generation,
replay, and service replacement return zero bytes. This is a narrow mechanism,
not an ambient recovery-state query or kernel-owned storage policy.
The isolated syscall adapter accepts only the opaque capability, one canonical
output address, and zero reserved registers. It validates the complete exact
current-task writable range before revocation, consumes one directional copy
ticket, erases kernel scratch on every return, and treats a copy failure after
revocation as terminal delivery uncertainty rather than retry permission. This
is unit-tested mechanism, not live boot-path or physical evidence.
The kernel-image service path now routes that operation before generic syscall
decoding, rechecks the complete user return state and active address-space root,
and constructs the metadata-only capability/delivery for one exact initial task
generation only when the handoff contains recovery metadata. This launch-policy
capability authorizes only the one-use metadata copy; the metadata itself still
cannot authorize storage recovery. The image and service compile for the UEFI
target. Fresh independently signed WHP and KVM controlled probes passed a fixed
recovery record through the handoff, initial-generation capability, launch ABI,
operation-13 dispatcher, active user-copy adapter, and service-side decoder
before exact lifecycle cleanup completed. The public test record grants no new
storage authority. Hosted WHP/KVM remain controlled by their hosts; this is not
native UEFI, TPM, persistence, reboot, rollback-resistance, Secure Boot, or
physical evidence.
The signed service now additionally binds the decoded handoff record through
`BootRecoveryAdmission` to a separately constructed controlled test record
before it becomes ready. It requires one successful exact load followed by a
rejected, zero-output replay, then erases all copies. The client receives the
metadata only as data and independently binds it before the existing dependent
authority-recovery transaction. Owner-approved checkpoint proof, temporary
attenuated capability reconstruction, configuration and policy validation, and
an exact epoch/generation/root successor all precede release. Mismatch,
malformed bytes, replay, stale expected state, or successor substitution halts
without releasing recovered authority or configuration. The controlled provider
is volatile test code, not authenticated hardware or durability evidence.

**PLANNED:** owner policy selects boot trust roots and authorizes each measured
system generation. Recommended project keys are defaults, not a hidden vendor
veto. Owner key enrollment/replacement, owner-built and narrowly scoped
development authorization, compromised-key revocation, accessible recovery,
authenticated rollback-resistant updates, and explicit security-state reporting
must coexist. Update infrastructure may not silently replace trust policy,
delete owner-authorized software, or disable owner builds.

Remote attestation is a capability delegated by the owner to a specific verifier
for specific claims and lifetime. Prefer selective claims and per-verifier or
ephemeral pseudonyms over a stable device identity or complete software
fingerprint. Websites and applications receive no universal exact-machine
attestation by default. Attestation cannot silently become DRM or tracking.

Release infrastructure inventories exact compiler/tool versions, dependencies,
unsafe/FFI/assembly boundaries, and signed artifacts; supports reproducible builds
and independent source-to-artifact verification where practical; and documents
key rotation and compromise recovery. A valid signature establishes identity and
integrity under a trust policy, not software safety.

**PARTIALLY IMPLEMENTED:** release-signer outputs use native exclusive creation
and do not replace existing paths. Signing consumes the one-time private key
before output publication, preferring a safely aborted release over publishing
while reusable key material remains. This is a local tooling invariant, not
evidence of independent custody, durable deletion, reproducibility, rotation,
recovery, Secure Boot enrollment, or production security.

**IMPLEMENTED as owner-selectable provisioning input:** `mrml-sign
bootstrap-state` derives the initial manifest-root digest from an exact
caller-selected public key, requires a nonzero rollback floor, validates the
canonical state, and exclusively creates the output. No project/vendor key is
implicit. `inspect-bootstrap-state` performs structural parsing only and emits
`authentication=not-verified`; it cannot turn a file into authenticated state.
These commands handle no private key and grant no boot authority. They do not
prove owner consent, provision TPM NV, replace or revoke a live root, authorize
development mode, or provide accessible recovery.

**IMPLEMENTED as bounded comparison infrastructure:** canonical build receipts
omit ambient host identity and paths while binding declared tool versions,
target/profile, a canonical source archive, dependency lockfile, unsigned boot
artifacts, and selected configuration by length and SHA3-512. Strict parsing
and byte-exact comparison detect changed recorded inputs or outputs. The receipt
is untrusted evidence until independently produced and reviewed; it grants no
authority and cannot prove that a builder was clean or its declarations honest.
The UEFI linker policy fixes the non-authoritative PE timestamp and omits the
nondeterministic embedded debug identity from signed boot artifacts. Separate
debug evidence remains possible. A same-host, separate-root controlled build of
exact commit `6976f8f`, using committed configuration and an empty selected test
configuration, matched the unsigned kernel/service/loader receipts. No
independent-builder, cross-host, or complete configured-release result has been
recorded.
The same strict parser is shared by the signer and kernel/loader boundary. It
rejects overlong input, alternate field order, noncanonical numbers or hex,
carriage returns, missing final newline, extensions, wrong target/profile,
zero identities, and authenticated kernel/service substitution before release
publication.

Do not claim verified boot, rollback resistance, DMA isolation, device reset,
confidential computing, side-channel resistance, formal noninterference,
physical hardware validation, or production security until the corresponding
implementation, adversarial testing, physical evidence where relevant,
reproducibility, and independent review exist.

## Security events and monitoring

The canonical **PLANNED** state, event, integrity, privacy, resynchronization,
and response boundaries are in
[monitor/SYSTEM_MONITOR.md](monitor/SYSTEM_MONITOR.md). It extends this observer;
it does not introduce a parallel security or integrity authority.

Planned privileged audit events use stable typed classes, monotonic sequences,
actor/target/object identities, decisions, and reason codes. Time is included
only when trustworthy. Events must avoid secrets and cannot be forgeable or
erasable by ordinary services. Monitoring and remediation remain separate,
narrow capabilities; high-impact remediation requires policy authorization or
trusted consent.

Security-sensitive delegation will use structured events such as capability
grant/derive/transfer/revoke/expire/deny, secret use/export request, debug grant,
device assignment, and AI session start/revoke. Records identify only necessary
principals and objects and never secret contents. Introspection and “why access?”
queries are themselves authorized and privacy bounded.

Audit is not surveillance. Each event class must define purpose, retention bound,
read/erase authority, redaction, and any justified prohibition on erasure.
Metadata is preferred to content; MRML does not create a permanent record of
every file read, page visited, keystroke, or AI prompt without a separate narrow
purpose. Logs are structured, bounded, capability-controlled, and secret-free.
Crash reports default to local structured diagnostics; remote submission follows
inspectable owner policy and strips unnecessary memory, names, credentials,
semantic content, and identifiers.

Structured diagnostics separate observation from mutation: permission to inspect
a fault object does not grant kernel memory, debug, or repair authority. Security
UI consumes trusted capability/lifecycle state, not application-provided claims.

For AI prompt-injection defense, content provenance survives browser/document/
email/media/source/remote-service ingestion into model context. Untrusted text
cannot become a trusted instruction merely by wording itself imperatively, and
model output cannot exceed the tool capabilities held by the AI session.

The safest unnecessary data is data never collected. Authority to observe does
not imply authority to retain, correlate, repurpose, train on, redistribute, or
disclose. `OBSERVE`, `RETAIN`, `EXPORT`, `CORRELATE`, and
`TRAIN/SECONDARY_USE` are distinct policy concepts where relevant. The kernel can
enforce local capabilities and disclosure boundaries; provider behavior after
remote disclosure is a separately stated provider/policy expectation, never an
unverifiable kernel privacy claim.

Consent surfaces show requester, object, rights, purpose where available,
duration, off-device disclosure, delegation, and revocability, with deny,
one-shot, session, and narrow persistent choices where appropriate. Safe
defaults, attenuation, grouping, and contextual delegation limit prompt volume;
prompt frequency and denial behavior are tested because habituation is a
security failure.

Core operation requires no telemetry. Any future telemetry has a separately
defined purpose, exact inspectable fields, minimal identifiers, bounded retention,
and genuinely optional owner policy where feasible; diagnostics is not blanket
collection authority.

## Exploit mitigation and evidence

NX/W^X, page-table write/execute separation, CET, IBT, shadow stacks, IOMMU/DMA
isolation, and architecture-appropriate memory tagging are defense in depth, not
substitutes for least authority and isolation. Claim them only at the cumulative
scope actually reached: `IMPLEMENTED`, `TESTED`, `MEASURED` where applicable,
and exercised on real hardware where hardware behavior is material. Virtualized
or nested evidence cannot establish physical IOMMU, DMA, VT-d, VMX, device-reset,
Secure Boot, TPM monotonic-state, CET, or IBT behavior.

Continuously fuzz IPC and capability transfer, shared-memory protocols,
executable/filesystem metadata, packets, VirtIO and USB descriptors, audio
control, VGPU input, browser parsers, semantic updates, and accessibility bridges.
Include stale, malformed, truncated, oversized, cyclic, duplicate, and generation-
confused inputs; normal tests alone do not harden a parser.

## Application and GUI boundary

Browser semantic state is capability-bound, origin/generation validated, and
redacted before accessibility/AI fan-out according to
[BROWSER_SEMANTICS.md](BROWSER_SEMANTICS.md). No AI-only DOM/control path exists;
media inspection, semantic inspection/interaction, and raw input remain separate.

The native application model is memory-safe by default. A safe-language label
alone is insufficient: ordinary application admission must eventually exclude
unsafe code, native FFI, and memory-unsafe dependencies unless the application
is moved behind an explicitly stronger compatibility boundary. The experimental
MRML compiler does not yet establish this admission property. Rust's unstable
native ABI and a public C/C++ ABI are not stable application authority surfaces.

Legacy and memory-unsafe applications belong in compatibility VMs. Application
microVM projection must preserve exact capability identity, rights,
generations, revocation, and protocol validation across the transport. Hosted
WHP/KVM still does not protect such a VM from its host.

Strict Total MicroVM semantics are canonical in
[ISOLATION_PLACEMENT.md](ISOLATION_PLACEMENT.md). Failure to satisfy a stronger
requested boundary must not silently weaken it: an eligible component whose
microVM or required resource/device projection cannot be created is unavailable,
not launched natively. Every host-substrate exception is explicitly classified
and justified. A microVM limits compromise propagation but grants no file,
network, GPU, device, secret, IPC, or resource authority; capabilities remain
authoritative. Total mode changes the TCB's shape and does not eliminate trust in
the microkernel, VMM, device isolation, narrow brokers, or bootstrap path.

The planned compositor owns trusted identity indicators, secure prompts, focus,
input routing, capture policy, and final composition. Application pixels cannot
draw or obscure the trusted portion of those surfaces. Semantic inspection,
semantic interaction, media inspection, clipboard/capture, and global HID
injection are distinct authorities.

Trusted prompts and recovery/login decisions must eventually expose equivalent
meaningful visual, keyboard, Braille, speech, and appropriate accessibility-
device semantics. Security identity cannot depend on color, sound, icon,
animation, position, or pixels alone. One redaction policy protects secrets
across visual rendering, speech, Braille, automation, and AI; accessibility
software receives no implicit secret or universal observation authority.

WebAssembly remains inside the browser sandbox and cannot bypass application
admission. The browser is no-JIT and W^X by design. Browser-level access to a
device is not delegated to an origin without separate authorization. The
sanitized semantic document tree, not arbitrary browser internals or JavaScript
execution, is the normal AI boundary. Remote AI receives no UI, media, secret,
or browsing state without explicit disclosure authority.

## Filesystem and graphics invariants

Filesystem names and object IDs never authorize. Rename preserves stable object
identity, and open capabilities remain bound to the object rather than its
current path. Derivation only decreases rights; snapshot access requires its own
authority. Recovery fails safely on inconsistent metadata, and checksummed
metadata corruption must be detected wherever coverage applies. Filesystem
checksums establish committed-data integrity, not publisher trust, executable
admission, or rollback protection.

An application that owns a surface does not own the physical display. A surface
does not imply scanout authority, and one graphics buffer does not imply access
to another. VGPU guests never receive host pointers. Trusted decorations and
security indicators remain compositor-owned through GOP and accelerated modes.
Backend takeover or fallback repeats capability validation and cannot weaken the
GUI trust boundary. Semantic AI/accessibility state remains distinct from
untrusted pixels. Fence identities, values, ownership, overflow, and reuse are
bounded and generational.

## Virtual-device invariants

GPU authority, memory/DMA, profiling, media, presentation, peer/RDMA, reset, and
driver-TCB rules are canonical in
[gpu/GPU_ARCHITECTURE.md](gpu/GPU_ARCHITECTURE.md). A GPU is not an exception to
capability attenuation, generational revocation, or physical-evidence rules.

The complete reusable queue, lifecycle, restart, block, host-share, accessibility,
hotplug, parity, fuzzing, and evidence rules are in
[PARAVIRTUAL_DEVICES.md](PARAVIRTUAL_DEVICES.md). They preserve the existing
MRML-native block device; no current mechanism is called VirtIO-compatible until
that transport exists and passes its scoped differential tests.

Virtual NIC or device presence never grants host network, raw device, USB,
audio, microphone, HID, bridge, passthrough, or DMA authority. Host firewall and
network policy remain outside guest control. Capture and playback are separate;
microphone capture is explicit, revocable, audited, and indicated by trusted
compositor UI. Composite USB interfaces are authorized independently. Exclusive
passthrough revokes conflicting host ownership before assignment and requires
completed reset, DMA isolation, cleanup, and reattachment transitions.
Trusted accessibility speech capture, application capture, VM capture, and AI
capture are separate authorities. Trusted accessibility speech output is not an
application-capturable playback stream by default. Braille and accessibility
HID services receive narrow interface/input-route capabilities, not raw global
USB or HID authority.

All queue descriptors, feature bits, lengths, addresses, chains, indirect
tables, indices, and device states are adversarial. Validation precedes host
access; reset/removal invalidates stale generations; guests never receive host
pointers. Unknown or uncertain lifecycle, interrupt, DMA, or cleanup state fails
closed. A virtual-device parser flaw should be contained by narrow component
capabilities rather than imply authority over the entire host. Secure attention
and global input remain outside every ordinary guest.

The MRML-native block runner now reauthorizes one live exact-object capability
with the operation-specific `READ`, `WRITE`, or `FLUSH` right before backend
access. Block numbers, lengths, queue records, transport identity, and the
separate interrupt capability cannot select that object. Wrong-object,
attenuated, stale, or revoked authority performs no backend I/O. A nonempty,
nonoverflowing backend start/count now binds guest-relative block translation;
cross-boundary and malformed transfers fail before backend access, and exposed
count must match advertised device geometry before vCPU entry. No production or
physical block backend is claimed.

PCI identity and configuration data never authorize mappings, interrupts, DMA,
or device use. Configuration offsets, widths, command bits, BAR probes, BAR
sizes, and BAR addresses are hostile. Unsupported or partial state transitions
fail without mutation. Bus mastering remains unavailable until an exact device
has separately authorized, revocable DMA/IOMMU state with complete reset and
cleanup. A BAR assignment alone never maps host memory. Memory decode requires
an assigned BAR, and configuration reset invalidates exact generational routing
views. For an attached device, native mapping and interrupt cleanup must complete
before configuration reset commits; uncertainty quarantines or fails closed
rather than treating cleared configuration bytes as completed revocation.
The router exposes reset and detach only through an unsafe revoker contract
whose success covers the exact attachment and function generation plus every
derived mapping, interrupt, DMA binding, queue, cached decision, device state,
and handle. Configuration and generation preflight occurs before cleanup;
cleanup failure preserves configuration and cannot report lifecycle success.
An assigned generational BAR window remains part of cleanup identity even after
memory decode is disabled; clearing the command bit cannot hide residual native
state from reset or detach cleanup.
Memory-decode enable requires confirmed native mapping of the exact attachment,
function generation, assigned address, and size before the command bit changes.
Disable requires confirmed unmapping before the bit clears. A rejected operation
means no native mutation; uncertain includes partial or unprovable state. Both
preserve configuration, and uncertainty requires quarantine/fail-stop. Default
configuration routing denies decode transitions unless an explicitly authorized
unsafe mapper is supplied. BAR assignment alone still creates no mapping.
Configuration routing additionally requires one exact bounded BDF match.
Attachment requires reset, unassigned, non-probing state. Duplicate
registrations, absent functions, table exhaustion, stale attachment generations,
and removal while memory decode is enabled fail before mutation.
A BDF or attachment ID identifies state but is never a capability; only the
trusted VMM policy boundary may attach, reset, route writes, or detach functions.
Legacy PCI configuration transport admits only the exact allowlisted address and
data-port width/direction tuples. Selector reserved bits, data-port alignment,
dword crossing, BDF, and register arithmetic are validated before router access.
Disabled or absent selections disclose only a width-sized all-ones value and
cannot mutate a function. Transport selection remains routing data, not device
or backend authority.
PCI scalar-input completion must match the exact still-pending vCPU, port, and
width before another entry. A backend may not report success after partial
register or native run-state mutation. Completion failure, transport rejection,
or an unexpected exit fails the VM rather than resuming ambiguous state.
For KVM, completion revalidates the complete `KVM_EXIT_IO` input record and
kernel-provided data offset before mutating only the exact selected bytes. The
vCPU retains one pending tuple and refuses another `KVM_RUN` until exact
completion succeeds; mismatch or duplicate completion fails closed.
For WHP, each vCPU retains one pending port, width, and decoded instruction
length. Completion requires the exact tuple, preserves the unaffected RAX bits
for byte and word inputs, applies x86 zero-extension for a dword input, checks
the next RIP for overflow and canonicality, and submits RAX and RIP together.
The tuple remains pending after any register-read, validation, or register-set
failure, so re-entry and stale or duplicate completion fail closed.
The native configuration probe originally selected only a deliberately
unattached BDF and required the architectural all-ones result. It now uses the
same bounded path to read two dwords from one deliberately test-only attached
block-class function, assigns its one BAR, enables memory decode through an
exact mapper, and completes a bounded two-write/two-read/one-flush queue cycle.
The flush feature must match in the guest-visible configuration and host device,
the request carries no payload or host selector, and backend execution
independently requires the exact object's `FLUSH` right. The fixed
identity, BDF, BAR, and request data remain non-authorizing; the backend object,
operation rights, mapping, and legacy interrupt delivery remain separately
capability checked. This assigns no production identity, MSI/MSI-X, DMA, or
durable backend authority.
Legacy completion injection additionally requires the exact current routed
function generation and BAR window with memory decode enabled. PCI interrupt-
disable retains the pending completion latch and performs no injection; a later
exact unmask permits the ordinary separately capability-authorized delivery.
The common block/PCI attachment now exact-matches PCI and block generations,
queue layout, interrupt vector, backend object/range, and confirmed BAR-mapping
state. Its unsafe cleanup contract covers every mapping, interrupt, DMA binding,
queue, backend-capability descendant, cached decision, device state, and handle
before block and PCI reset/removal commit. Clean rejection preserves state;
uncertain native mutation requires VM quarantine. The cleanup contract remains
unit/simulation tested. The KVM/WHP probes exercise only a narrow preinstalled
trap-window mapper and bounded volatile block I/O; they do not prove production
mapping revocation, native PCI interrupt routing, durability, or physical-device
cleanup.

Orderly PCI-MMIO VM replacement retains the exact routed attachment and backend
authority; neither is reconstructed from guest data. The device and bridge must
be suspended with all five operations fully retired before capture. The old VM
is destroyed before a linear lost-execution witness can restore only the exact
transport-bound canonical queue/resume image into fresh queue pages. Stale,
noncanonical, or scalar-transport substitution fails before restoration, and
resume occurs only after complete validation.

Final controlled cleanup succeeds only after the replacement native VM or
partition is destroyed, so no runnable translation, trapped BAR leaf, pending
native exit, or interrupt injection context survives. The revoker exact-matches
the cleanup record and preflights both exact capabilities before revoking block
and interrupt authority. Common block reset and attachment invalidation precede
PCI generation advance and BAR/decode clearing. This does not claim live TLB-
safe dynamic unmapping; that path remains fail-closed and unavailable.

Reset-with-pending simulation now composes a published unacknowledged
completion, latched notification, and separate in-flight request. Reset
invalidates the old attachment and ticket and advances both device identities;
reactivation creates a fresh bridge and attachment. The old BAR acknowledgement
is rejected by attachment validation before it can touch successor device or
queue state, and stale ticket/request generations are independently rejected.
This proves bounded common-state isolation only, not native TLB invalidation,
hosted pending-I/O reset, durable recovery, or device cleanup.

A VirtIO-GPU-compatible presentation device does not replace or implicitly
authorize MRML's CUDA compute channel. Display, presentation, and CUDA compute
are distinct capabilities. The MRML-specific compute path retains exact signed
kernel admission, authenticated request/completion binding, bounds, quotas,
reset/watchdog behavior, and fallback requirements.
