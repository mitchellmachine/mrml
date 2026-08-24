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

- Object identity is not authority; names and data are not authority.
- Identity and provenance may select policy but do not grant authority.
- Capability derivation cannot increase authority.
- Object and task identities are nonzero, bounded, and generational; stale
  identities cannot regain access after slot reuse.
- Revocation precedes reuse and covers all derived state in the operation's
  boundary. Uncertain device/DMA teardown quarantines or fails closed.
- Boundary copies validate complete ranges, overlap, wrapping, alignment,
  length, reserved fields, and exact encodings before mutation.
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

Compromise cleanup generalizes the Phase 1 lifecycle rules: revoke task/service
capabilities and descendants; remove native mappings; invalidate IPC, queues,
shared state, cached decisions, and exact generations; destroy stale credentials
and tokens; clean or quarantine device/DMA assignments; erase sensitive transient
state; and restart only from independently validated state. Half-complete cleanup
fails closed. Successful code execution in one component cannot create durable
authority unless the principal separately holds the narrow persistent-object
capability for startup, service replacement, configuration, executable trust,
credentials, boot state, or firmware.

## Persistent state and boot

Signed images alone do not prevent rollback. TPM-backed or equivalent
authenticated, monotonic, power-loss-atomic storage; measured boot; exact
artifact-set admission; corruption handling; recovery; and key rotation remain
required. Development signing is not production Secure Boot.

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

Do not claim verified boot, rollback resistance, DMA isolation, device reset,
confidential computing, side-channel resistance, formal noninterference,
physical hardware validation, or production security until the corresponding
implementation, adversarial testing, physical evidence where relevant,
reproducibility, and independent review exist.

## Security events and monitoring

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

A VirtIO-GPU-compatible presentation device does not replace or implicitly
authorize MRML's CUDA compute channel. Display, presentation, and CUDA compute
are distinct capabilities. The MRML-specific compute path retains exact signed
kernel admission, authenticated request/completion binding, bounds, quotas,
reset/watchdog behavior, and fallback requirements.
