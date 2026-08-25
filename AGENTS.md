# MRML contributor and recovery instructions

These instructions apply to the entire repository. The Git repository is the
durable source of truth; chat history, agent memory, local notes, and benchmark
claims outside the repository are not authoritative.

Before changing kernel, VMM, boot, signing, protected-execution, capability,
IPC, device, or security code, read completely:

1. `README.md`
2. `VALUES.md`
3. `docs/ENGINEERING_CONSTITUTION.md`
4. `docs/ARCHITECTURE.md`
5. `docs/SECURITY.md`
6. `docs/APPLICATION_PLATFORM.md`
7. `docs/ACCESSIBILITY.md`
8. `docs/ROADMAP.md`
9. `docs/RECOVERY.md`
10. `docs/MICROKERNEL.md`

Treat `docs/ENGINEERING_CONSTITUTION.md` as normative before introducing major
architecture. Apply its lightweight complexity score to major subsystem
proposals, not routine work. If a proposal conflicts, identify the conflict and
propose an explicit amendment rather than bypassing the rule. `EULOGY.md` is
historical inspiration only and never overrides MRML's security architecture.

Owner sovereignty is a hard architectural constraint. Security authenticates
and enforces owner-selected policy; it must not create superior permanent vendor,
publisher, provider, or verifier authority. Preserve owner-controlled trust roots,
rollback resistance, accessible recovery, owner-build authorization, and scoped
privacy-limited attestation together. Publisher policy, signatures, manifests,
licenses, EULAs, remote statements, and first-party status identify or describe;
they do not authorize. Do not build general-purpose DRM against the owner.

Accessibility is foundational. A core interface is incomplete when essential
operations depend on one sensory/physical mode despite practical semantic
alternatives. Reuse the Semantic Scene Graph for visual, keyboard, Braille,
speech, accessibility-device, automation, testing, and AI projections; do not
create divergent authority or semantic systems. Preserve local accessibility,
secret redaction, trusted nonvisual prompts, and separate semantic inspection,
interaction, microphone, audio-route, HID/input-route, and raw-device rights.
Never claim Braille/hardware or early-boot support beyond exact evidence.

If text-only AI receives task-essential semantic state, supported human
accessibility interfaces must receive equivalent meaning unless a documented
technical/security reason prevents it. Equivalent meaning is not identical
format or authority. Treat Braille as semantic I/O, not framebuffer text; the
40-cell baseline is a design target, not a device restriction. Preserve trusted-
prompt Braille/speech operation, monitor-off acceptance, shared AI/accessibility
redaction, physical-hardware evidence labels, disabled-user testing before ABI
freeze, and provider-independent keyboard/Braille/basic speech operation.

Treat the README contribution, testing, provenance, dependency, formatting,
and claims rules as hard acceptance gates. Inspect `git status`, recent
relevant history, source, and tests before editing. Preserve unrelated staged,
unstaged, and untracked work; stage only the intended files. If `rustfmt`
changes unrelated tracked Rust files, commit those mechanical changes in a
separate formatting-only commit.

Use the status vocabulary in `docs/ARCHITECTURE.md`: **IMPLEMENTED** means the
code and focused tests exist, not that it is production-ready or physically
verified. Never silently promote **PARTIALLY IMPLEMENTED**, **EXPERIMENTAL**,
**PLANNED**, or **ASPIRATIONAL** work.

Architectural invariants:

- keep the privileged microkernel small and mechanism-focused;
- put storage, networking, firewall policy, configuration, consent UI,
  monitoring, supervision policy, ordinary drivers, and AI policy in isolated
  services wherever practical;
- identity and provenance inform policy but never replace capabilities;
- derived capabilities can only preserve or reduce authority;
- revocation must cover derived handles, mappings, IPC, shared memory, DMA,
  device state, cached decisions, and descendants where applicable;
- keep shared VMM policy backend-neutral and preserve both WHP and KVM;
- hosted WHP/KVM is never a security boundary against its host;
- raw reports are never authenticated evidence; VBS claims cover only the
  documented VTL0 threat model and are not remote attestation;
- secret release requires authenticated receipts, exact request/policy
  binding, non-debug execution, replay protection, and the documented sealed-
  key claims;
- bare-metal receipt keys remain internal to VMX root and all authority
  transitions fail closed;
- all parsers, arithmetic, identities, generations, boundary copies,
  capabilities, and state transitions remain bounded and adversarially tested.
- ordinary native applications are memory-safe by admission policy and do not
  gain a general-purpose C/C++ ABI; stable contracts are versioned service
  protocols rather than Rust's internal ABI;
- WebAssembly remains browser content, the browser remains no-JIT/W^X, and
  neither web content nor browser possession silently delegates hardware
  authority;
- follow `docs/BROWSER_SEMANTICS.md`: blind users and text-only AI receive the
  same sanitized generational semantic truth under consumer-specific capability
  scopes; no AI-only DOM/control interface, hidden JIT, automatic media export,
  or accessibility-fingerprint disclosure is permitted;
- the compositor owns trusted display surfaces, semantic GUI state is primary
  for accessibility and automation, and raw input or visual access remains a
  separately privileged fallback.
- every meaningful public resource has identity and lifetime, while a
  capability—not a name, path, or guessed object ID—carries authority; do not
  expose meaningless internal details as objects merely for uniformity;
- native storage uses capability-bound stable objects and is not founded on
  FAT32, ext4, NTFS, POSIX permissions, or a universal global namespace;
- follow `docs/DEPLOYMENT.md`: applications, kernel, VMM, bootloader, drivers,
  services, modules, and recovery use one package family; exact coherent releases
  instantiate immutable generations; UEFI remains conventional; GitHub is only
  transport; manifests request rather than grant; Store download is not admission;
  image/backup/secret export remain distinct; servicing constructs generations;
  and installation/storage destruction requires an exact preview-bound capability;
  all shell/text/GUI/recovery/unattended/AI frontends use one `DeploymentService`;
  shell and recovery are not root; automatic partitioning exact-matches target and
  source media; GC retains every current/candidate/known-good/pinned root; runtime
  microcode evidence is distinct from packaged payload; and operational rollback
  never bypasses committed security anti-rollback policy;
- follow `docs/memory/MEMORY_RESOURCE_MODEL.md`: RAM allocation is explicit
  quantitative authority; pools cannot amplify; objects, mappings, sharing,
  pinning, content access, DMA, and guest projection remain separate;
- follow `docs/platform/CPU_PLATFORM.md`: the initial modern x86-64 references
  are i9-13900K and Ryzen 9 7950X3D, not permanent product allowlists; discover
  exact identity/topology, use distinct Intel/AMD microcode backends, re-evaluate
  vulnerabilities after update, never equate age with safety, expose scheduler
  security constraints, attenuate CPU budgets, and keep power/telemetry/control
  authorities separate; do not claim physical support without exact evidence;
- applications submit capability-bound surfaces/buffers to the trusted
  compositor and never render directly to GOP, VGPU, native GPU, or scanout;
  surfaces, buffers, render devices, display outputs, fences, rendering, and
  presentation remain distinct abstractions.
- keep a small backend-neutral paravirtualized VMM device family; use actual
  VirtIO specifications only where compatibility is intended and label every
  device VirtIO-compatible, VirtIO-inspired, MRML-specific, or legacy-emulated;
- follow `docs/PARAVIRTUAL_DEVICES.md` for common device lifecycle, queues,
  restart, hotplug, capability-selected backends, KVM/WHP parity, accessibility
  emulation, block, host-share, QEMU differential testing, fuzzing, and evidence;
  VirtIO transport and device identity never authorize host objects;
- preserve MRML's signed-kernel CUDA compute mediation alongside any future
  VirtIO-GPU display path; do not distort VirtIO-GPU or remove stronger MRML
  capability, authentication, queue, and CUDA semantics to claim compatibility;
- follow `docs/gpu/GPU_ARCHITECTURE.md`: MRML's native capability/object model is
  not Vulkan/CUDA/WebGPU; VirtualGPU is GPU priority 1, Blackwell priority 2,
  AMD/Intel later; safe kernels, exact generations, bounded resources, DMA/IOMMU
  revocation, and hosted/virtual/native-physical evidence separation are hard
  gates; Linux traces are oracle evidence, never trusted production replay;
- do not recreate Vulkan in the native API: prefer inference, keep tensors first-
  class while AI algorithms remain evolving libraries/IR, separate Safe/
  Advanced/Raw profiles, forbid universal `unsafe_gpu`, require measured escape
  hatches, and keep Blackwell details backend-local;
- treat every guest descriptor, queue, feature, interrupt, reset, removal, and
  device-state transition as hostile; reset invalidates stale queue state, and
  no guest-provided pointer, length, or host address is trusted;
- virtual NIC, audio capture/playback, USB interface, HID routing, passthrough,
  and raw-device authorities remain explicit and independently revocable;
  secure attention terminates in the trusted host environment.
- apply “names identify; capabilities authorize” consistently to every
  meaningful public object, including services, processes, VMs, devices,
  connections, credentials, AI sessions, diagnostics, and security state;
- data is never authority: provenance-labeled web, email, document, media,
  source, model, or remote content cannot manufacture instructions or tool
  capabilities, and provenance never replaces a capability check;
- secret use and secret export are separate rights; AI and applications should
  receive constrained non-extractable operations rather than plaintext wherever
  protocols permit;
- introspection, diagnostics, monitoring, and debugging are independently
  capability-controlled and reveal neither unrelated object state nor secrets;
  debug authority over one process is never system-wide authority;
- lifecycle/time-bounded authority must actually expire and revoke all derived
  state; disposable domains retain no storage, network, device, or secret
  authority unless explicitly granted.
- first-party software has no hidden privilege; documented interfaces remain
  available to equivalent third-party applications and assistive tools unless a
  narrow TCB reason is explicitly recorded;
- minimize data, metadata, retention, correlation, secondary use, and remote
  disclosure; observation does not imply any of those authorities;
- remote AI receives capability-scoped semantic views, not the whole desktop,
  and no AI provider is a root of trust for ordinary operation;
- compatibility adapts through isolated projected capabilities and never gains
  ambient host authority merely because legacy software expects it;
- major mechanisms pass both the Engineering Constitution's digital-rights and
  hostile-security reviews, including independent adversarial review where
  security-significant; agent review never replaces external human audit.

Implement OS work in the dependency order in `docs/ROADMAP.md`. Determine the
next milestone from current code, tests, documentation, TODOs, and Git history,
not from an old summary. Record exact test commands and outcomes. Distinguish
unit tests, simulation, hosted controlled probes, nested virtualization, and
physical-hardware evidence. Never claim Linux, Windows, VTL1, TPM, IOMMU,
Secure Boot, bare metal, or physical hardware was verified unless that exact
environment was exercised.

Work scheduling is deliberately bounded: keep at most one foundational OS task
and one independently scoped compiler task active at a time. Never combine two
large cross-cutting OS subsystems in one task, branch, or functional commit.
Finish and verify the current OS dependency gate before starting another. The
compiler task may proceed alongside it only when changes, tests, and review
remain separable and shared-file edits do not couple the milestones.

Compiler direction is durable in `docs/COMPILER.md`. `mrml-rustc` targets
contemporary and forward-looking Rust semantics with Rust 2024 as its floor; it
does not carry a standing obligation to support Rust 2015/2018/2021, every
historical nightly, obsolete unsoundness, diagnostic wording, rustc internals,
or unstable Rust ABI/symbol quirks. Do not deliberately diverge from modern Rust
or turn it into an unrelated Rust-inspired language. Prefer modern successor
semantics unless current MRML source or a required conformance dependency needs
legacy behavior.

Every Rust oracle must be an exact dated rustc version and full commit recorded
under `docs/compiler/oracles/`; an installed latest nightly is not a reproducible
oracle. Preserve previous generations, classify every upgrade delta, and use
black-box observations plus independently authored MRML probes. Do not copy
upstream compiler implementation source or upstream test bodies.

Prioritize an explicit typed ownership/place/control-flow representation,
Polonius-direction flow-sensitive borrowing, modern trait-goal solving, modern
pointer provenance, bounded const evaluation, naked functions/assembly, and
compiler-derived security profiles/metadata. Do not implement Polonius or a
trait solver as one giant patch. Language capability and application admission
are separate: preserve audited systems Rust while the planned Application
Profile forbids unsafe code and native unsafe FFI. Unsupported borrowing,
traits, provenance, unsafe, ABI, assembly, const, or metadata semantics must
continue to fail closed.

Build-tool direction is durable in `docs/build/BUILD_SYSTEM.md`. Until an exact
profile readiness gate passes, production artifacts use pinned upstream
rustc/Cargo. Compiler selection/provenance is explicit and never silently falls
back. Standard `.efi` output precedes bootloader packaging; build, package, sign,
release, image, install, and publish remain distinct; ordinary builders hold no
production signing keys; build metadata/profile/first-party identity grants no
runtime capability; and tooling must not derail compiler-core work.

Patent review is technical risk screening, not legal adjudication. For each
substantial new mechanism, report `Patent review: NOT_TRIGGERED` or
`Patent review: TRIGGERED` with the reason and a link to
`docs/patents/REVIEW_LOG.md`. Prefer mechanisms whose relevant patents are
verified expired, public-domain, or covered by an applicable royalty-free
grant. Verify the grant's claims, versions, territories, beneficiaries,
reciprocity, defensive-suspension, termination and downstream-distribution
conditions; "open source," a standard, CC0, independent creation, or an AI
origin does not establish patent clearance. If a suitable grant or clearly
non-overlapping implementation cannot be established, pause that mechanism for
targeted review or use a documented design-around rather than guessing.

Search claim limitations and actual MRML mechanisms, not titles or branding.
Discover families worldwide, but verify claims and status independently in the
authoritative national or regional register for every material right; a PCT
publication is not a worldwide patent. Persist public findings under
`docs/patents/`. Never copy patent implementation prose into code or state that
MRML is patent-free or infringes a patent solely from automated analysis.
