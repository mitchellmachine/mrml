# MRML adaptive isolation placement

Status: **PARTIALLY IMPLEMENTED**. Manifest V2 parses a typed placement policy,
rejects unknown fields/tokens, contradictory bounds, duplicates, and cross-class
placements, and requires a reason for fixed platform policy. Current application
and service manifests explicitly record policy; the configuration service is the
first package admitting both native-service and microVM forms. The bounded
resolver applies package defaults, owner requests, and total-mode requests; an
unsupported total promotion is reported as an exception and launches nothing.
The workspace model retains each validated policy and `mrml.lock` records its
default, floor, ceiling, and supported set. The kernel now has a fixed-capacity
launch-admission mechanism that records an exact policy generation, Total-mode
eligibility class, requested placement, and matching backend-ready evidence. It
rejects eligible native placement and active unsupported blockers in Total mode,
and reports typed resource or transport unavailability without native fallback.
Unavailable attempts are retained in a bounded ordered kernel ledger with exact
policy generation, attempt sequence, class, requested placement, and reason;
an explicit retry removes the prior failure only after a new launch slot is
successfully reserved. The Total report counts unavailable eligible domains
separately from running domains and native fallback.
It does not select providers, create a VM, allocate resources, persist policy,
or implement boot/runtime transport. Those mechanisms remain **PLANNED**.
The existing signed configuration-service probes on both hosted VMM runners now
prepare that exact Total-mode record before guest construction, commit it only
after the backend has produced the requested microVM container, and emit a
structured zero-fallback report only after the complete service probe succeeds.
This is launch-admission integration, not completion of a dual-placement runtime
or proof that the required system satisfies Total mode.

The kernel also has a bounded caller-selected routing prerequisite for service
placements. One typed service specification binds the domain, interface and
exact interface/provider/policy generations to either `NATIVE_SERVICE` or
`MICROVM`; the router invokes only that backend entry and commits only matching
readiness evidence. Total mode rejects a native-service request before backend
launch, and microVM failure is retained as unavailable without native fallback.
The configuration service now supplies the first concrete adapter over those
two backend entries, and its manifest admits both forms while retaining native
service as the default and floor. Focused tests prove that either form preserves
one interface/provider binding and that microVM failure never invokes its native
launcher. This routing composition still does not automatically select a
provider or placement, carry a general interface invocation, persist policy, or
provide transparent cross-placement transport. A fully resolved representative
dual-placement service remains **PLANNED**.

The native configuration form now has its first real supervised launcher. It
preflights one vacant supervisor slot before creating a task, publishes the task
and `ServiceId` as one kernel-owned transition, and returns a binding-preserving
endpoint only after the dedicated runtime starts it. Revocation retires the task
and consumes its exact cleanup ticket only after address-space erasure. Erasure
uncertainty retains the endpoint and ticket for exact retry. The microVM launcher
now has a backend-neutral owner around one actual prepared guest: successful
construction publishes only an opaque generational endpoint bound to the exact
domain, interface, provider, and policy generations; confirmed destruction
retires it; uncertain destruction retains the guest and endpoint for exact
retry. Forged or stale endpoint tokens never reach backend teardown. Concrete
KVM and WHP hosted configuration probes now transfer their transaction-
committed prepared guest into this owner, use the retained guest through its
exact endpoint, and explicitly retire the lifecycle on the successful terminal
path. Unrelated launch modes cannot consume a configuration-owned guest. Both
runner builds and focused unit suites pass with this identical ownership shape.
The dual-placement milestone remains **PARTIALLY IMPLEMENTED** rather than
complete because general resolution and cross-placement transport remain
planned.
An admitted-guest transfer factory now accepts one backend-constructed guest
only when the complete `IsolationServiceSpec` matches, consumes it once, and
permits trusted mutable guest access only through the matching generational
endpoint. This is the explicit bridge the existing KVM/WHP construction
transactions use; it grants no new guest authority.

The kernel routing API now also exposes a one-use prepared service transaction
for VMM launchers whose construction spans multiple backend operations. The
transaction reserves admission before construction and retains the exact
domain, interface, interface generation, provider generation, policy generation,
class, and placement until matching endpoint commit. Construction failure can
consume it into the typed unavailable ledger; commit failure returns both the
transaction and endpoint so native teardown precedes admission cancellation.
Both KVM and WHP configuration-service probes now use this transaction around
their real guest and projected-service construction. The prepared transaction
exists before either backend creates the guest and binds provider generation to
the verified service artifact version; only the fully attached guest is
committed as the endpoint, after which execution receives it back unchanged.
The committed guest now remains inside the common configuration lifecycle until
explicit terminal retirement. Both runners build and their focused host tests
pass. Newly built one-time-signed kernel and service artifacts completed the
full hosted service probe on both backends on 2026-08-25. WHP and nested KVM
each reported one eligible domain, one domain in a microVM, and zero native
fallback after explicit lifecycle retirement. WHP reported `verify=18258us`,
`prepare=6937us`, `execute=3530us`, `total=53537us`; KVM reported
`verify=22013us`, `prepare=2758us`, `execute=1578us`, `total=109945us`.
The identical package, signed kernel, signed service, and public keys were used
for both. This is hosted controlled-probe evidence—not host-resistant isolation,
bare metal, physical hardware, broad application compatibility, or required-
system Total readiness.

The exact frontend/build and execution commands were:

```text
mrml build org.mrml.system.bootloader --target uefi-x86_64 --release --feature-profile service_probe
mrml build org.mrml.system.service-image --target native --release
mrml build org.mrml.tool.sign --target windows --release
mrml-sign keygen target/total-microvm-current/kernel.private target/total-microvm-current/kernel.public
mrml-sign keygen target/total-microvm-current/service.private target/total-microvm-current/service.public
mrml-sign keygen target/total-microvm-current/package.private target/total-microvm-current/package.public
mrml-sign sign-bundle kernel 1 target/total-microvm-current/kernel.efi target/total-microvm-current/kernel.private target/total-microvm-current/kernel.signed
mrml-sign sign-bundle service 1 target/total-microvm-current/service.efi target/total-microvm-current/service.private target/total-microvm-current/service.signed
mrml package create org.mrml.system.kernel kernel 1 x86_64 kernel target/total-microvm-current/kernel.signed target/total-microvm-current/kernel.mrp --private-key target/total-microvm-current/package.private
mrml-whp-run.exe target/total-microvm-current/kernel.mrp target/total-microvm-current/package.public target/total-microvm-current/kernel.public 1 service-probe target/total-microvm-current/service.signed target/total-microvm-current/service.public 1
wsl.exe -d archlinux -- ./target/mrml-native/linux/release/mrml-kvm-run target/total-microvm-current/kernel.mrp target/total-microvm-current/package.public target/total-microvm-current/kernel.public 1 service-probe target/total-microvm-current/service.signed target/total-microvm-current/service.public 1
```

The build tool now has a bounded composition prerequisite between exact package
resolution and kernel launch routing. A `GenerationBoundServicePlacement`
rechecks that an isolated-service `InterfaceBinding` retains the exact consumer
and provider records in one immutable `SystemGeneration`, then binds its
generational endpoint to an already resolved native-service or microVM
placement. Stale bindings, package-generation substitution, in-process targets,
and Total-mode exceptions fail closed. This does not select the provider or
placement, grant capabilities, create either runtime, or carry interface
traffic, so the representative dual-placement service remains **PLANNED**.

> Control planes establish authority; data planes should take the shortest safe
> path.

For adaptive placement, the configuration service, resolver, capability policy,
and VMM admission form the control plane. They select and authorize an exact
provider generation, placement, projected capabilities, queues, resource
budgets, and revocation path. Once admitted, ordinary interface traffic uses
the shortest safe transport supported by that binding—an in-process call,
native IPC, or a bounded shared microVM queue—without repeating policy lookup
for every message. Data-plane bytes cannot grant capabilities, change placement,
substitute providers, or widen the admitted binding.

```text
CONTROL PLANE
App -> request interface capability -> policy/resolver -> service or VMM broker
    -> bind exact provider generation + placement + queues -> done

DATA PLANE
App domain == admitted IPC/shared queue ==> bound provider -> backend/hardware
```

## One policy, several placements

MRML extends its existing process, service, capability, package-generation, and
VMM architecture; it does not add a second sandbox system. `IsolationPlacement`
conceptually contains:

- `IN_PROCESS`: admitted code in an explicitly compatible consumer domain;
- `NATIVE_PROCESS`: a distinct native userspace process/domain;
- `NATIVE_SERVICE`: a supervised native service domain;
- `MICROVM`: a supervised VMM guest using projected capabilities and typed MRML
  interfaces;
- `PLATFORM`: fixed kernel, loader, or pre-VMM execution outside selectable
  userspace placement.

Kernel and UEFI-loader placement is fixed. Applications may support native
process and/or microVM placement; services may support native service and/or
microVM placement. An independently serviced provider may support in-process,
service, and/or microVM forms only when its package and interface admit them.
Some interfaces legitimately support only one form. There is no universal
location-independence promise.

## Preference, floor, supported forms, and policy

Package metadata separately records default/preferred placement, minimum
required isolation, supported placements, and, where needed, a maximum. Owner
policy may strengthen placement and may select a weaker preference only within
the admitted supported set and never below the mandatory floor. A package whose
minimum is `MICROVM` cannot be weakened by ordinary Settings. Publisher identity
or metadata describes policy input but neither grants authority nor lets a
malicious package demand ambient in-process authority.

Canonical Manifest V2 uses one bounded table:

```toml
[isolation]
default = "native-process"
minimum = "native-process"
supported = ["native-process", "microvm"]
```

A fixed pre-VMM component uses `platform`, a singleton supported set, and a
bounded reason. Admission rejects unknown placements, contradictory bounds,
duplicates, unsupported defaults, and impossible requirements. Placement and
authority are orthogonal: metadata never grants capabilities.

Defaults consider untrusted-input exposure, parser complexity, network/device
exposure, authority breadth, unsafe/FFI and third-party surfaces, persistence,
fault impact, performance, RAM, and startup cost. Memory safety is important but
not decisive; a memory-safe browser renderer remains a strong microVM candidate
because it processes adversarial content and has a large attack surface.
Third-party identity alone neither requires a microVM nor grants native placement.

The planned `IsolationMode` values are `BALANCED`, `MORE_ISOLATED`,
`TOTAL_MICROVM`, and `CUSTOM` (wire spellings remain provisional). Balanced uses
risk-based defaults and may make a visible policy-permitted fallback within the
supported set and mandatory floor. More Isolated forces additional admitted
components into microVMs but does not claim Total completeness. Custom applies
explicit owner choices above mandatory floors. Choosing native placement where
permitted does not disable address-space isolation, capabilities, resource
limits, memory protection, or explicit device/network/file authority.

Conceptual precedence is: non-overridable platform/security constraint, strict
boot/session overlay, owner component override, system/project default, package
recommendation. A Total overlay therefore supersedes a stale `FORCE_NATIVE`
preference for that boot when microVM placement is supported.

## Semantic interface compatibility across placements

Consumers bind a stable typed MRML interface and exact immutable provider
generation, not a DLL/SO name, path, PID, VM ID, or placement. The resolver
selects an admitted form compatible with interface, package, generation,
hardware, and effective policy. Where multiple forms exist, in-process calls,
native-service IPC, and microVM VirtIO/shared-IPC are transport adapters behind
the same semantic contract.

Placement may legitimately change latency, startup time, failure boundaries,
resource accounting, shared-memory behavior, timeouts, and debugging. This is
semantic compatibility where supported, not identical transport or performance.
Interfaces define observable failure, cancellation, and bounded backpressure as
needed. Shared memory is explicit, range/right/lifetime bounded, revocable, and
generation-safe; executable sharing is immutable and preserves W^X.

Moving a provider preserves exact generation binding, protocol semantics,
capability attenuation, revocation, accounting, and supported accessibility
meaning. It is a supervised replacement, never in-place executable patching.
Existing consumers retain their generation until orderly rebind/restart. Rust's
native ABI is not the stable cross-placement ABI.

## Strict Total MicroVM semantics

`TOTAL_MICROVM` is a strict one-boot or persistent policy overlay. Every running
`MICROVM_ELIGIBLE` userspace execution domain MUST execute within an admitted
microVM boundary. If its microVM, resources, projection, or required transport
cannot be created, that component is unavailable. It MUST NOT automatically run
as `IN_PROCESS`, `NATIVE_PROCESS`, or `NATIVE_SERVICE`.

```text
TOTAL_MICROVM + MICROVM_ELIGIBLE
  -> microVM starts       -> run in MICROVM
  -> microVM cannot start -> component unavailable

NEVER: failed microVM -> native or in-process fallback
```

Total mode may sacrifice availability to preserve the requested boundary.
Failure of an optional launch need not shut down the machine; a boot- or
session-critical failure may block the session or enter explicitly labeled
diagnostic/recovery handling. Changing to Balanced, changing a later-boot policy,
or overriding a floor is an explicit authorized owner action, never an automatic
recovery decision.

Every component has one explainable Total-mode eligibility class:

- `MICROVM_ELIGIBLE`: the execution domain supports the standard microVM runtime
  and MUST use it whenever running in Total mode;
- `HOST_SUBSTRATE_REQUIRED`: it must remain outside guests to instantiate,
  supervise, broker, or secure microVM execution, with a specific reason;
- `BOOT_ONLY`: it executes before the normal microVM substrate exists;
- `RECOVERY_ONLY`: it belongs to the independently repairable recovery
  environment and follows recovery policy;
- `UNSUPPORTED_BLOCKER`: ordinary userspace should be eligible, but the current
  implementation lacks an admitted microVM path.

Unsupported does not mean unsafe or untrusted. An unfinished Settings app or
service is an `UNSUPPORTED_BLOCKER`, not host substrate. Performance alone is
not a substrate reason. Every `HOST_SUBSTRATE_REQUIRED` classification is
reviewed as the architecture evolves. The substrate SHOULD be minimized,
memory-safe where practical, capability-limited, fuzzed, and inspectable.

Total mode stops at the minimal host substrate; it does not recursively place
the VMM inside another VMM. Its TCB still includes the relevant microkernel,
virtualization core, IOMMU/device isolation, minimum capability/resource/device
brokers, and microVM bootstrap path. Shared brokers are explicit common-mode
dependencies and expose narrow typed interfaces rather than ambient proxies.
A microVM boundary limits compromise propagation; it does not define or grant
authority.

In-process libraries admitted inside a guest remain inside that guest boundary.
Total does not mean one VM per crate, library, function, process, or thread. A
browser microVM may contain its exact in-process Zstd and Unicode providers; a
shared service may run in its own microVM. Approved multi-component guest groups
are explicit and inspectable. Each guest graph is exact and generational, with
private writable state and bounded RAM, vCPU, GPU, IPC, and device projections.

Balanced and Total differ explicitly:

```text
Balanced browser renderer:
  preferred MICROVM; minimum NATIVE_PROCESS
  microVM unavailable -> policy MAY visibly permit NATIVE_PROCESS

Total browser renderer:
  MICROVM_ELIGIBLE
  microVM unavailable -> DO NOT LAUNCH
```

Package updates that change defaults, floors, supported forms, or microVM
transport are re-evaluated before generation activation. A required unsupported
component blocks Total readiness; an installed but unused optional blocker need
not prevent a current session, but it cannot launch natively under the Total
label. Provider substitution still requires exact interface compatibility,
admission, security policy, and generation binding.

## Settings, boot, recovery, and accessibility

The configuration service now implements the first bounded typed persistent
records for component preference and system Balanced, More Isolated, Total, or
Custom selection. Exact
setting READ/WRITE plus configuration-root CONTROL capabilities remain required;
records survive the authenticated checkpoint path, reject scope confusion and
noncanonical bytes, and grant no runtime authority. A revision-bound application
plan now repeats both exact setting READ checks immediately before translating
the records into the kernel `IsolationMode`, component placement request, and
admission-table policy generation. Capability revocation or any intervening
configuration commit invalidates the plan. A service-specific admission step
then checks an authenticated package projection of preferred, minimum, maximum,
and supported native-service/microVM forms. It produces an exact generational
`IsolationServiceSpec`; unsupported strict Total requests and owner requests
below the mandatory floor fail without alternate placement. This is **PARTIALLY
IMPLEMENTED** control-plane application. The configuration service now composes
that sequence into one route which revalidates policy, bounds, kernel mode and
policy generation, and exact interface/provider generations before calling only
the selected native-service or microVM backend. Stale policy and mismatched
admission tables reach neither launcher. This is not a general package-policy
resolver, Settings, shell, broad interface transport, or Total-mode completion.

The planned Settings application and object shell project that one typed policy
service. They distinguish configured default, requested boot mode, effective
state, and policy generation; show floors, supported forms, blockers, overhead,
and restart/reboot requirements; and allow Default, stronger microVM placement,
or an explicit native selection only where the floor permits. Changes are
transactional, auditable, recoverable, capability-controlled, and semantically
available through keyboard, Braille, speech, automation, and authorized AI.
Configuration expresses desired policy; it does not prove current placement.

Focused Windows and Arch Linux runs each pass all 40 configuration-service
tests, including typed persistence, exact capability enforcement, canonical
decoding, scope separation, authenticated checkpoint recovery, reauthorization,
stale-plan rejection, native-class substitution denial, package-bound floor and
supported-form checks, no-fallback Total rejection, policy-generation handoff,
stale route rejection, and proof that control-plane mismatches call no backend.
These are unit tests on hosted build targets, not boot, VMM, or physical-
hardware evidence.

The planned boot menu is `MRML`, `MRML — Total MicroVM Isolation`, `MRML
Recovery`, and an independently discovered `Windows Boot Manager` where
applicable. The Total entry selects the same admitted `SystemGeneration` plus a
strict one-boot overlay, not a separate unsigned build. The same signed loader
accepts `BOOTX64.EFI --isolation=total-microvm` from a UEFI/EFI Shell and produces
the same typed policy object rather than a second implementation. Parsing is
bounded, exact-token, and fail closed; the selector contains no secrets.

The one-boot request expires after that boot and cannot bypass Secure Boot,
package signatures, `SystemRelease` admission, anti-rollback, capabilities, or
mandatory floors. Selection proves only requested mode; runtime evidence proves
satisfaction. Virtualization or resource failure MUST NOT silently convert the
boot to Balanced. The owner may explicitly retry, boot Balanced once, or enter
Recovery. Recovery remains a separate small audited environment and can repair
policy or VMM/runtime generations without depending on successful Total mode.

## Resources, devices, security, and monitoring

RAM, vCPU, `VirtualGPU`, VirtIO, device-projection, or VMM exhaustion in Total
mode makes the affected component unavailable and reports the exact shortage.
Power/thermal policy MAY throttle or stop workloads but MUST NOT weaken their
placement. Network, file-portal, GPU, accessibility-bridge, or other projection
failure never justifies native fallback. Balanced may use an explicit policy-
permitted alternative within the mandatory floor.

Every microVM receives only explicitly projected files, network, GPU, input,
audio, devices, secrets, IPC, and resources. VirtualGPU/brokered devices are the
normal path, not broad raw-device fallback. Capabilities remain separately
attenuated and revocable. Hosted WHP/KVM cannot protect a guest from its host;
QEMU, hosted WHP/KVM, nested virtualization, and physical Intel/AMD evidence are
distinct. MicroVM isolation does not eliminate shared-hardware side channels or
common-mode VMM, broker, scheduler, GPU, or device failures.

The planned monitor is authoritative for actual runtime state rather than
configuration files. It reports requested mode, effective status, eligibility,
placement and policy generation, substrate reasons, active/required blockers,
unavailable domains, resource costs, and native-fallback count. Findings include
`MICROVM_REQUIRED_BUT_UNAVAILABLE` and `TOTAL_MICROVM_DOWNGRADE_ATTEMPT`; neither
triggers a native launch. Conceptual successful evidence is:

```text
requested_mode = TOTAL_MICROVM
effective_status = SATISFIED
running_microvm_eligible = N
running_in_microvm = N
unsupported_blocker_required = 0
native_fallback = 0
```

Installed-but-idle applications do not count as running domains. Every running
`HOST_SUBSTRATE_REQUIRED`, `BOOT_ONLY`, and `RECOVERY_ONLY` exception is
enumerated and justified. A request with an eligible native execution or active
required blocker is `TOTAL_MICROVM_NOT_SATISFIED`, even if selected by the boot
menu, Settings, EFI Shell, or an intentional developer override. Monitor and
shell expose typed structured state without revealing unrelated content or
secrets.

## Implementation order and acceptance

Documentation is not implementation evidence. Implement bounded milestones:

1. policy/object schema, validation, workspace retention, lock output, and
   bounded kernel launch admission/reporting (**PARTIALLY IMPLEMENTED**);
2. one representative dual-placement service;
3. one representative dual-placement GUI application;
4. monitor placement visibility;
5. resource and device projections;
6. persistent Settings and shell policy;
7. strict Total runtime enforcement;
8. bootloader and EFI Shell selectors;
9. required-system Total readiness and broader application compatibility;
10. recovery, adversarial, performance, and physical-hardware evidence.

Acceptance includes contradictory-manifest rejection, floor enforcement,
owner strengthening, authorized Balanced weakening, exact-generation interface
behavior across supported forms, revocation/restart, resource exhaustion,
stale-policy rejection, boot-token parsing, recovery, and backend parity. Total
MicroVM remains **PLANNED** until a tested configuration proves every running
eligible domain is in a microVM, zero active required blockers, zero native
fallback, and an enumerated justified host/boot/recovery substrate.

## Total MicroVM invariants

1. Every running `MICROVM_ELIGIBLE` domain MUST execute within an admitted
   microVM boundary.
2. Failure to create that boundary MUST NOT cause automatic native fallback.
3. Required non-microVM components MUST have explicit classification and
   architectural justification; unsupported userspace cannot masquerade as host
   substrate.
4. Resource pressure MAY reduce availability but MUST NOT silently weaken
   placement.
5. Capabilities remain the authority mechanism regardless of placement.
6. Requested Total mode is satisfied only when effective runtime state meets
   these invariants.

Patent review: **TRIGGERED**. Adaptive placement selection, interface transport,
whole-system isolation policy, and boot-time policy composition require targeted
worldwide claim review before implementation. See
[the patent review log](patents/REVIEW_LOG.md); this is technical screening, not
legal advice or a clearance conclusion.
