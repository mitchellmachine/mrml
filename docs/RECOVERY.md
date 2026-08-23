# Recovering MRML project direction

Use this procedure when prior conversations, agent memory, local notes, signing
artifacts, or development context are unavailable. Git is authoritative.

Read `docs/ENGINEERING_CONSTITUTION.md` before proposing major architecture. It
is normative project policy. `EULOGY.md` records Terry A. Davis and TempleOS as
historical inspiration for whole-system understandability, but it does not
override MRML's security architecture. Preserve MRML's independent technical
identity, memory safety, capabilities, isolation, userspace services, VM
compartments, and modern hardware protection.

Read `VALUES.md` and `docs/ACCESSIBILITY.md` before GUI, compositor, semantic
graph, input/HID, USB, audio, browser, AI-control, trusted-prompt, boot, or
recovery work. Accessibility is a platform property built on the shared semantic
object system, not a later visual add-on. Preserve local/offline operation,
uniform secret redaction, separate inspect/interact/microphone/device authority,
and the roadmap order from semantic graph through keyboard actions, speech,
Braille, VM/browser projection, and alternative devices. Do not claim physical
Braille or early-boot accessibility from simulation or plans.

Patent research is also durable repository state. Before repeating a search,
read `docs/patents/README.md`, its status registers, and `REVIEW_LOG.md`.
Resume from recorded mechanisms, claims, families, jurisdictions, official
registers, dates, license conditions, and confidence. Never promote a discovery
record to an active-right candidate without territorial status verification,
or convert an incomplete search or royalty-free label into a clearance claim.

## 1. Establish repository state

Run read-only inspection first:

```text
git status --short --branch
git log --oneline --decorate -20
git diff --stat
git diff --cached --stat
rg --files
```

Treat every existing staged, unstaged, and untracked file as user-owned until
proved otherwise. Do not reset, clean, discard, or fold unrelated formatting
into a functional commit.

## 2. Reconstruct intent

Read `AGENTS.md`, `README.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`,
`docs/APPLICATION_PLATFORM.md`, `docs/COMPILER.md`, this file,
`docs/ROADMAP.md`, and `docs/MICROKERNEL.md` completely. Then inspect recent
history for the affected
subsystem. README gives repository-wide rules; ARCHITECTURE gives stable
direction; SECURITY gives normative boundaries; APPLICATION_PLATFORM gives the
native/VM/browser/GUI/AI contract; COMPILER gives the future-Rust compatibility,
analysis, profile, and oracle direction; ROADMAP gives dependency order;
MICROKERNEL is the detailed dated evidence ledger. Source and tests decide
whether a stated item actually exists.

If documents disagree, prefer in this order for factual implementation status:

1. current source plus tests and executable evidence;
2. newer relevant commits and their diffs;
3. dated MICROKERNEL evidence;
4. ROADMAP status;
5. overview prose.

Never reinterpret a design goal as implemented. Record unresolved uncertainty
explicitly and downgrade the status rather than guessing.

## 3. Inspect the implementation map

- Kernel mechanisms: `crates/mrml-kernel/src/`
- x86_64 CPU, memory, SMP, VMX, EPT, VT-d: `crates/mrml-kernel/src/arch/x86_64/`
- Boot image and loader: `crates/mrml-kernel-image/`, `crates/mrml-uefi/`
- CPL3 service image: `crates/mrml-service-image/`
- Shared VM policy: `vm.rs`, `vm_dispatch.rs`, `vm_interrupt.rs`
- Linux KVM: `crates/mrml-kvm/`, `crates/mrml-kvm-run/`
- Windows WHP: `crates/mrml-whp/`, `crates/mrml-whp-run/`
- VBS and protected execution: search for `Vbs`, `Vtl1`, `ProtectionMode`,
  `AuthenticatedAdmission`, `receipt`, and `sealed` across the workspace.
- Capabilities/IPC/lifecycle: `capability.rs`, `ipc.rs`, `shared_memory.rs`,
  `scheduler.rs`, `task_runtime.rs`, `service_lifecycle.rs`.
- Compiler: `crates/mrml-rustc/`, `crates/mrml-rustc-driver/`; never infer a
  complete compiler or application ABI from supported subset code generation.
  Read `docs/COMPILER.md` and every record under `docs/compiler/oracles/` before
  selecting compiler work. Recover the future-Rust direction, not an assumed
  obligation to reproduce old editions or arbitrary historical rustc behavior.
- Host browser automation: `crates/mrml-tools/src/browser.rs` and `web.rs`; this
  is not an MRML browser engine, compositor, or OS application implementation.
- Application/GUI/browser OS work: search the whole tree; absence is meaningful
  and planned documentation must not be promoted to implementation status.
- Native filesystem: no implementation currently exists. UEFI Simple File
  System use is boot interoperability, and `mrml-runtime` file APIs wrap host
  files; neither establishes native MRML storage semantics.
- Graphics: `framebuffer.rs`, UEFI GOP handoff, and signed framebuffer probes are
  bring-up/diagnostic mechanisms. `virtual_gpu.rs` is experimental mediated GPU
  machinery. None is a compositor, surface protocol, display backend, fence
  model, or accelerated desktop implementation.
- VMM device inventory: inspect `vm.rs`, `vm_dispatch.rs`, `vm_interrupt.rs`,
  `virtual_gpu.rs`, and both native backends. Currently the common lifecycle,
  guest-memory, exit, I/O-policy, hypercall, and interrupt mechanisms are
  implemented; the MRML-specific mediated GPU queues are partial. No MRML
  VirtIO, PCI device transport, UART device, block, NIC, input, sound, USB, or
  general display device is implemented. QEMU VirtIO devices appearing in boot
  commands are external test infrastructure, not MRML VMM implementations.

For every future device, recover and update its classification, exact feature
bits, queue/ring encoding, lifecycle/reset rules, interrupt model, QEMU
differential status, KVM/WHP status, incompatibilities, fuzzing, and hardware
evidence. Critical device semantics must live in durable documentation, not
only source comments or old probe logs. A future VirtIO-GPU display device must
remain separate from and coexist with the MRML-specific signed-kernel CUDA
compute protocol.
- Authority transparency and security UX are planned, not implemented. Search
  `capability.rs`, `ipc.rs`, `task_runtime.rs`, `service_lifecycle.rs`, protected
  execution, and artifact state for foundations. Current code has generational
  capabilities, attenuation, transfer rollback, revocation on domain death,
  restart policy, typed errors, and narrow protected-secret-use examples; it
  does not have general provenance/introspection, expiration, a file picker,
  disposable domains, `SecretObject`, credential broker, visible AI principals,
  diagnostic objects, scoped debugger, provenance labels, or security UI.

Recover the intended model from ARCHITECTURE, SECURITY, APPLICATION_PLATFORM,
and ROADMAP: launcher-built capability namespaces; bounded delegation graphs and
“why access?” explanations; real live revocation; non-extractable secrets;
lifecycle expiration; capability-scoped diagnostics/debugging; structured data
provenance and prompt-injection defense; deterministic system generations; and
crash/restart restoration. Never infer implementation from conceptual event or
right names.

Use `rg` to locate definitions, callers, tests, TODOs, probe modes, and feature
gates. Inspect manifests and the pinned toolchain before assuming build targets.

For compiler recovery, verify the exact oracle version, full commit, date,
edition/default behavior, Polonius state, trait-solver state, relevant unstable
features, semantic deltas, and corpus result from its generation record. Never
substitute whichever nightly is installed. If advancing the oracle, retain the
old record, run both generations, classify every delta, change semantics only
deliberately, and retain original regression probes.

Read `docs/compiler/CHECKPOINT.md` for the concise commit-addressed compiler
state, exact last complete Windows/Arch gates, known analysis boundary, and next
dependency milestone. Treat it as a recovery index, verify it against source,
and update it after every pushed compiler milestone.

Current typed-place recovery boundary: parsed assignments store their base
binding separately from an explicit dereference, index, or numeric tuple-field
projection. Do not regress this to target-string splitting in semantics or
code generation. Index text is trimmed once with its exact body-relative span;
non-numeric tuple assignment fields fail with `ExpectedAssignmentTarget` only
after an assignment operator is recognized, so ordinary method-call expressions
remain parseable. The next dependency is a stable bounded typed body
representation with general projection lists and CFG edges;
move/loan/region claims remain unimplemented.

Runtime assignment lowering has the first stable-identity slice. Every emitted
local and inlined-helper parameter receives a checked monotonic `RuntimeLocalId`;
scope cleanup clears active stack entries without rewinding that ID sequence.
Each non-wildcard assignment resolves once to a typed `RuntimePlace` containing
either the exact local ID and current storage index or a parameter index, plus
the parsed projection, effective mutability, and explicit `Write` or
`ReadModifyWrite` access. All runtime assignment families consume this access
classification instead of independently inferring old-value reads from the
operator. Resolution validates the ID again before a local store. Do not
confuse the storage index with identity or reintroduce separate name/access
inference in assignment families.

The runtime emitter retains up to 256 local facts and 256 ordered runtime place-
access facts. Local facts preserve ID, name, type, and mutability after scope
cleanup releases the active stack entry; assignment facts preserve stable
local/parameter identity, parsed projection, type, access intent, and source
span. Direct runtime identifier loads and the specialized tuple, array, range,
and address paths append `Read` facts with the same stable base identities;
constants do not enter this table. `finish` rejects holes, recycled/mismatched
IDs, invalid projection/type combinations, immutable binding stores, and
missing or mismatched parameters.
Each fact now owns a source-independent list of at most four `Dereference`,
`Index`, `TupleField`, or `Subslice` projections. Assignment parser projections
translate once into this list; specialized local tuple-field, array-element,
and local-array range reads retain their corresponding projection. Validation
walks the list through the base type and rejects holes, invalid transitions,
out-of-range fields, and overflow. The exact projection-capacity error is
`TooManyRuntimePlaceProjections`.
The tables are bounded ephemeral compiler state and include expanded inlined
helper bodies; they are not serialized IR or a claim of whole-program analysis.
The exact capacity errors are `TooManyRuntimeLocalFacts` and
`TooManyRuntimePlaceAccessFacts`; invariant failure is
`InvalidRuntimePlaceFacts`.

Read facts still resolve names during emission; general nested read-place
discovery and dereference-read projection are not centralized, and address-
taking is not yet classified as a borrow. Parser-level IDs, initialization and
move paths, CFG analysis, borrows, loans, and regions are still absent. The next
compiler milestone is to turn this emission-side foundation into the bounded
typed body-wide local/place/access table, then add CFG and initialization/move
facts.

Forward-looking compiler policy does not make Cargo's experimental
`edition = "future"` a clean-install default. The recoverable baseline remains
edition 2024 until a pinned toolchain and complete per-package migration are
committed together. A root-only switch leaves current Cargo unable to parse the
workspace because inheriting packages require their own unstable-edition opt-in.

## 4. Select the next work

Compare the current source and tests with the first incomplete security gate in
ROADMAP. Choose the smallest coherent end-to-end milestone that advances that
gate and can be tested in the available environments. Preserve backend-neutral
policy and both WHP/KVM adapters. Do not skip service-foundation dependencies to
implement attractive high-level policy prematurely.

For the independent compiler lane, compare current source and tests with the
dependency order in `docs/COMPILER.md`. Prefer the typed ownership/place/CFG,
Polonius-direction borrowing, modern trait solver, post-2024 systems features,
profiles, and security-metadata path over historical compatibility work. Treat
Rust 2024 as a floor, keep unsupported semantics fail-closed, and never attempt
the complete borrow checker or trait solver in one patch.

Restore the project work-in-progress limit after context loss: select exactly
one foundational OS milestone. At most one separately scoped compiler milestone
may accompany it. If two OS-wide efforts appear active, preserve both worktrees
but choose one dependency gate to finish; do not merge them into a giant task or
commit. Shared-file coupling means the purported compiler task is not independent
and must wait or be split.

## 5. Verify and report

Use the README's exact Windows gnullvm requirements. Run focused tests first,
then the strongest relevant platform-independent and platform-specific suites.
Record exact commands, toolchain, backend, artifact versions, configuration,
outcomes, and benchmark boundaries. Label evidence as unit test, simulated,
QEMU TCG, hosted WHP, hosted/nested KVM, VTL1, or physical hardware.

Do not recreate missing private signing keys or hardware evidence by assertion.
Generate development-only keys only when the documented workflow permits it,
and never confuse them with production keys. If an environment is unavailable,
state that it was not tested.

Update documentation only when implementation, architecture, evidence, or
limitations materially change. Keep mechanical formatter output in a separate
commit. Before committing, inspect the staged diff and confirm unrelated work
is absent. Push only the intended branch after required tests pass.
