# MRML contributor and recovery instructions

These instructions apply to the entire repository. The Git repository is the
durable source of truth; chat history, agent memory, local notes, and benchmark
claims outside the repository are not authoritative.

Before changing kernel, VMM, boot, signing, protected-execution, capability,
IPC, device, or security code, read completely:

1. `README.md`
2. `docs/ENGINEERING_CONSTITUTION.md`
3. `docs/ARCHITECTURE.md`
4. `docs/SECURITY.md`
5. `docs/APPLICATION_PLATFORM.md`
6. `docs/ROADMAP.md`
7. `docs/RECOVERY.md`
8. `docs/MICROKERNEL.md`

Treat `docs/ENGINEERING_CONSTITUTION.md` as normative before introducing major
architecture. Apply its lightweight complexity score to major subsystem
proposals, not routine work. If a proposal conflicts, identify the conflict and
propose an explicit amendment rather than bypassing the rule. `EULOGY.md` is
historical inspiration only and never overrides MRML's security architecture.

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
- the compositor owns trusted display surfaces, semantic GUI state is primary
  for accessibility and automation, and raw input or visual access remains a
  separately privileged fallback.
- every meaningful public resource has identity and lifetime, while a
  capability—not a name, path, or guessed object ID—carries authority; do not
  expose meaningless internal details as objects merely for uniformity;
- native storage uses capability-bound stable objects and is not founded on
  FAT32, ext4, NTFS, POSIX permissions, or a universal global namespace;
- applications submit capability-bound surfaces/buffers to the trusted
  compositor and never render directly to GOP, VGPU, native GPU, or scanout;
  surfaces, buffers, render devices, display outputs, fences, rendering, and
  presentation remain distinct abstractions.
- keep a small backend-neutral paravirtualized VMM device family; use actual
  VirtIO specifications only where compatibility is intended and label every
  device VirtIO-compatible, VirtIO-inspired, MRML-specific, or legacy-emulated;
- preserve MRML's signed-kernel CUDA compute mediation alongside any future
  VirtIO-GPU display path; do not distort VirtIO-GPU or remove stronger MRML
  capability, authentication, queue, and CUDA semantics to claim compatibility;
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
