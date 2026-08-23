# MRML operating-system security model

This document states security boundaries and non-claims. Implementation details
and dated evidence are in [MICROKERNEL.md](MICROKERNEL.md).

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

## Persistent state and boot

Signed images alone do not prevent rollback. TPM-backed or equivalent
authenticated, monotonic, power-loss-atomic storage; measured boot; exact
artifact-set admission; corruption handling; recovery; and key rotation remain
required. Development signing is not production Secure Boot.

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
