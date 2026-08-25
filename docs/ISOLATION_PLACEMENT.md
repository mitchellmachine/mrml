# MRML adaptive isolation placement

Status: **PARTIALLY IMPLEMENTED**. Manifest V2 now parses a typed placement
policy, rejects unknown fields/tokens, contradictory bounds, duplicates, and
cross-class placements, and requires a reason for fixed platform policy. Every
current package without an explicit table receives a conservative singleton
default. All current application and service manifests explicitly record their
native singleton policy. The typed resolver applies package defaults, owner
selection, and total-microVM requests without crossing supported forms or bounds;
unsupported total-mode promotion is an explicit exception. MicroVM launch,
persistent settings, boot overrides, and location-independent runtime transport
remain **PLANNED**.

## One policy, several placements

Every eligible application or service has one explicit placement policy. MRML
extends its existing process, service, capability, and VMM architecture; it does
not add a second sandbox system.

The conceptual placements are:

- `IN_PROCESS`: admitted safe code in an explicitly compatible consumer;
- `NATIVE_PROCESS`: a distinct native userspace process/domain;
- `NATIVE_SERVICE`: a supervised native service domain;
- `MICROVM`: a supervised VMM guest using projected capabilities and stable
  MRML interfaces;
- `PLATFORM`: a fixed kernel, loader, recovery, or pre-VMM component which is
  outside user-selectable placement.

The exact wire enum is frozen only with its schema and tests. Kernel and UEFI
loader placement is fixed. Ordinary applications may support native process or
microVM placement; services may support native service or microVM placement.
An independently serviced safe provider may support in-process, service, and/or
microVM forms only when its interface declares those forms.

## Preference, floor, and ceiling

Package metadata separately records the default/preferred placement, minimum
required isolation, supported placements, and—where needed—a maximum allowed
placement. Ordering is policy-specific, not a claim that every placement is a
strict security superset in every threat model.

Owner policy may strengthen placement. It may weaken a preference only within
the package/interface supported set and never below a mandatory security floor.
Weakening a mandatory minimum requires an explicit owner-authorized expert or
development policy, visible consequences, and must remain forbidden for
non-overridable TCB constraints. Publisher identity or metadata describes the
floor but does not itself grant authority.

Canonical Manifest V2 uses one bounded `[isolation]` table with explicit
tokens, conceptually:

```toml
[isolation]
default = "native-process"
minimum = "native-process"
supported = ["native-process", "microvm"]
```

A pre-VMM component instead uses `default = "platform"`, a singleton supported
set, and a bounded reason. Manifest admission rejects unknown placements,
contradictory bounds, duplicate values, unsupported defaults, and a microVM
requirement on a component that cannot run in a guest. Metadata never grants
capabilities.

## Interface location independence

Consumers bind a stable typed MRML interface and exact provider generation, not
a DLL/SO name, filesystem path, process ID, VM ID, or placement. The resolver
selects an admitted provider form compatible with the interface, package,
system generation, host capability, and effective placement policy. In-process,
native-service IPC, and microVM transport are distinct adapters behind the same
semantic interface; transport details cannot change authority or invent an
AI-only/accessibility-only control path.

Moving a provider preserves exact immutable generation binding, protocol
semantics, capability attenuation, revocation, W^X, memory/resource accounting,
and supported accessibility meaning. A placement change is a supervised
replacement, never in-place executable patching. Existing consumers retain
their bound generation until orderly rebind/restart. Rust's native ABI is not
the stable cross-placement ABI.

## Defaults and owner policy

MRML supplies conservative package defaults. Risky unsafe or compatibility
components may require microVM placement; ordinary memory-safe applications may
default to native processes; boot-critical code remains platform-fixed. The
owner may set per-package, per-service, class, profile, and global preferences,
subject to mandatory floors and resource feasibility.

`Total MicroVM Isolation` is a best-effort maximum-isolation policy over every
eligible component, not a promise that the kernel, loader, VMM, early recovery,
or every boot-critical codec runs in a microVM. Components without an admitted
microVM form remain at their fixed or minimum-safe placement and are reported
explicitly. Resource exhaustion fails closed or presents an owner-visible
degraded-placement decision according to policy; it never silently violates a
minimum.

The settings application and object shell project the same typed policy service.
They show requested versus effective placement, immutable constraints, expected
CPU/RAM/device overhead, restart/reboot requirements, and security consequences.
They never edit package files directly or scrape command output. First-party UI
has no hidden authority. Changes are transactional, generation-bound, auditable,
recoverable, and accessible through keyboard, Braille, speech, and trusted
nonvisual prompts.

## One-boot override

The MRML bootloader will offer a one-boot `Total MicroVM Isolation` choice and
accept the equivalent explicit argument when launched from a UEFI/EFI Shell.
The option is bounded, exact-token, nonpersistent by default, recorded in the
authenticated boot handoff, and consumed by the early policy service. Unknown,
duplicated, malformed, or conflicting arguments fail closed. EFI shell
compatibility does not turn arbitrary command-line data into authority.

The boot menu must explain that startup may be slower and RAM consumption
higher, remain operable without a monitor where supported, and preserve owner-
controlled recovery. A one-boot request cannot bypass Secure Boot, package,
generation, capability, or mandatory placement policy.

## Security, resources, and monitoring

A microVM is isolated from sibling guests by the VMM and projected capabilities,
but hosted KVM/WHP is not a boundary against its host. Device, network, storage,
GPU, accessibility, semantic inspection, debug, and monitoring authority remain
separately projected and revocable. Secure attention terminates in the trusted
host. Placement never implies ambient host access.

Each placement has explicit CPU scheduling, committed/resident/shared memory,
page-table, IPC/queue, device, and teardown accounting. Shared executable pages
remain represented by `MemoryPool` and `MemoryObject`; microVM duplication or
sharing is not hidden. The monitor exposes requested/effective placement,
policy source, provider generation, VM/domain identity, resource cost, restart
state, and evidence scope without leaking unrelated content or secrets.

## Implementation order and acceptance

Implementation proceeds as bounded milestones. The typed placement model,
validation, initial Manifest V2 metadata, and effective request resolver are
implemented. Next are the resource plan;
native/interface transport invariants; microVM launch adapter; persistent policy
service; shell/settings/monitor projections; boot-handoff override; recovery and
adversarial tests. Do not start GUI polish before the typed backend exists.

Acceptance includes contradictory-manifest rejection, floor enforcement,
owner strengthening, authorized preference weakening, exact-generation
interface behavior across supported forms, revocation and restart, resource
exhaustion, stale policy/generation rejection, boot-token parsing, recovery, and
WHP/KVM parity. `Total MicroVM Isolation` remains **PLANNED** until an actual
booted generation proves all eligible placements and reports every exception.

Patent review: **TRIGGERED**. Adaptive placement selection, transparent
interface transport, whole-system isolation policy, and boot-time policy
composition require targeted worldwide claim review before implementation. See
[the patent review log](patents/REVIEW_LOG.md); this is technical screening, not
legal advice or a clearance conclusion.
