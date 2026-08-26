# Recovering MRML project direction

Use this procedure when prior conversations, agent memory, local notes, signing
artifacts, or development context are unavailable. Git is authoritative.

Read `docs/ENGINEERING_CONSTITUTION.md` before proposing major architecture. It
is normative project policy. `EULOGY.md` records Terry A. Davis and TempleOS as
historical inspiration for whole-system understandability, but it does not
override MRML's security architecture. Preserve MRML's independent technical
identity, memory safety, capabilities, isolation, userspace services, VM
compartments, and modern hardware protection.

Owner sovereignty is a hard constraint: security authenticates owner-selected
policy and does not establish permanent vendor, publisher, provider, or verifier
authority. Preserve owner-controlled trust roots, rollback resistance, scoped
remote attestation, accessible recovery, and owner-build authorization together.
Publisher policy, signatures, licenses, manifests, and first-party status never
authorize by themselves; DRM against the owner is not an MRML security goal.

Minimize data, metadata, and retention. Remote AI receives only scoped semantic
views and no provider is a root of trust for ordinary operation. Preserve third-
party assistive tooling and documented interoperable/export interfaces under the
same capabilities as equivalent first-party software. Every major security
review must examine both technical compromise and digital-rights consequences,
and every evidence claim remains limited to the environment actually exercised.

Read `VALUES.md` and `docs/ACCESSIBILITY.md` before GUI, compositor, semantic
graph, input/HID, USB, audio, browser, AI-control, trusted-prompt, boot, or
recovery work. Accessibility is a platform property built on the shared semantic
object system, not a later visual add-on. Preserve local/offline operation,
uniform secret redaction, separate inspect/interact/microphone/device authority,
and the roadmap order from semantic graph through keyboard actions, speech,
Braille, VM/browser projection, and alternative devices. Do not claim physical
Braille or early-boot accessibility from simulation or plans.

Maintain semantic-access parity: if text-only AI receives task-essential GUI
meaning, supported accessibility interfaces receive equivalent meaning unless a
documented reason prevents it; formatting and capabilities may differ. Braille
is semantic input/output, with a 40-cell device only as an initial usability
target. Trusted prompts must work through Braille/speech, and core operation
must progress toward the explicitly `DESIGNED`, currently unpassed monitor-off
suite. Read `docs/accessibility/BRAILLE_INTERFACE.md` and
`docs/accessibility/MONITOR_OFF_ACCEPTANCE.md`. Do not freeze an accessibility
ABI before practical disabled-user feedback or claim hardware compatibility
without physical tests.

Memory recovery must read `docs/memory/MEMORY_RESOURCE_MODEL.md`: allocation is
quantitative `MemoryPool` authority; `MemoryObject`, mapping, sharing, pinning,
content access, and DMA remain separate; child pools cannot amplify; guest RAM
is host-bounded; introspection reveals no content; RAM and VRAM are analogous but
distinct. Do not assume ambient allocation or preempt current dependency gates.

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

- UEFI boot entry/order/next and Secure Boot owner/compatibility/revocation
  direction: `docs/platform/UEFI_BOOT_MANAGEMENT.md`. Preserve Windows entries,
  normal Option ROM trust, SecretObject key rules, re-read verification, and exact
  physical-evidence labels.
- Ethernet/Wi-Fi/Bluetooth shell/GUI/service direction:
  `docs/network/NETWORK_ADMINISTRATION.md`. Preserve configuration/connection/raw
  authority separation, secret non-exportability, one shared semantic API, offline
  install/recovery, and crash containment. These features remain planned absent
  exact code and focused evidence.

- Build/package orchestration: `docs/build/BUILD_SYSTEM.md`. Recover the planned
  `mrml` frontend and `docs/build/MIGRATION_INVENTORY.md`; Cargo bootstraps it and
  remains a private bridge, while normal component commands use `mrml`. Recover
  explicit Windows/Linux hosts, MRML/Windows/Linux/UEFI/CUDA targets, VMM and
  compiler graph integration, semantic `packages/` migration, explicit blockers,
  pinned upstream production compilation, explicit compiler modes
  without fallback, profile-specific promotion, EFI export then bootloader
  packaging, distinct build/package/sign/release/image stages, isolated keys, and
  typed results. Do not claim the partial frontend implements its planned
  package, release, image, publish, sandbox, or native resolver stages.

- Package, Store, release/generation, bootloader distribution, system image,
  servicing, shell, disk administration, installer, and deployment direction:
  `docs/DEPLOYMENT.md`. Treat it as planned unless exact implementation and
  evidence exist. Recover one immutable package/`SystemGeneration` model; never
  invent separate update, offline-service, recovery, image, or snapshot paths.
  Preserve automatic/custom GPT safety, one `DeploymentService` for every
  frontend, scoped recovery/shell authority, content-store reachability GC,
  candidate health/known-good rollback, typed progress/errors, offline install,
  owner-built/third-party sources, and exact transaction-bound disk operations.

- Dynamic components are **PLANNED** in
  `docs/packages/COMPONENT_INTERFACES.md`. Rust crates are not automatically
  packages; packages are not interfaces. `org.mrml.zstd` is the canonical first
  independently serviced provider and `org.mrml.zim` consumes
  `org.mrml.interface.compression.zstd@3`. Compatible provider updates do not
  rebuild ZIM; running consumers retain exact old provider generations; mapped
  executable pages are never patched; old providers remain until live bindings,
  retained/rollback generations, snapshots, and GC permit reclamation. In-
  process and service providers remain distinct, there is no DLL/SO path-search
  model, metadata grants no capability, substitution is explicit policy, package
  and ABI generations differ, boot/recovery codecs may remain pinned/static, and
  `mrml-rustc` will eventually validate the same explicit ABI as upstream rustc.

- Kernel mechanisms: `packages/system/kernel/src/`
- x86_64 CPU, memory, SMP, VMX, EPT, VT-d: `packages/system/kernel/src/arch/x86_64/`
- CPU support floor, Intel/AMD microcode, post-update vulnerability state,
  heterogeneous scheduling, CPU budgets, power, telemetry, thermal safety,
  monitor, and hardware milestones: `docs/platform/CPU_PLATFORM.md`. These are
  planned unless exact code and focused evidence establish otherwise; CPU age
  never substitutes for affectedness evaluation.
  A runtime slice precharged before vCPU entry is linear transient authority.
  Recovery must never infer that an unresolved in-flight slice was unused or
  refund it from reconstructed data. Retain its full charge and fail the domain
  closed unless the exact live accounting instance can reconcile the matching
  slice; reservation release and period rollover remain blocked meanwhile.
  A multi-vCPU reservation retains one fixed in-flight slot per vCPU, but every
  slot charges one shared allowance. Recovery must reconcile each exact vCPU,
  logical-CPU, priority, start, and charge tuple independently; it must never
  merge sibling slots, transfer a refund, or clear the reservation merely
  because one sibling returned. Any unresolved bit retains its charge and keeps
  release and rollover blocked.
  Hosted SMP adds one native runner and deadline worker per live vCPU. Recovery
  must never treat one runner's exit, elapsed measurement, affinity restoration,
  priority restoration, or cancellation retirement as evidence for its sibling.
  Both exact runner states must retire and both slices must reconcile before VM
  teardown or reservation release. A missing result retains that slice's full
  precharge and fails the domain closed; persisted thread handles, cancellation
  pointers, and native scheduling snapshots are never reconstructed.
  A hosted deadline worker is also linear transient state: VM teardown, run-page
  unmapping, VP deletion, and accounting reconciliation must wait until the
  exact worker has retired. Recovery must never reconstruct a cancellation
  pointer, signal target, or partition handle from persisted data.
  Hosted runner affinity is likewise transient linear state. Reconciliation,
  teardown, and control-plane completion require proof that the exact prior
  affinity was restored after both vCPU and deadline-worker retirement. Never
  persist or reconstruct a native thread handle or prior CPU set; uncertain
  restoration fails the domain closed and requires host-process recovery.
  Native host-priority state follows the same rule. Recovery may retain the
  authorized MRML class but must never persist or reconstruct a native thread
  handle, Windows priority value, or Linux scheduler policy/parameter pair.
  Control-plane completion requires verified restoration after affinity, vCPU,
  and deadline-worker retirement; uncertainty requires host-process recovery.
- Boot image and loader: `packages/system/bootloader/`, `packages/libraries/uefi/`
- CPL3 service image: `packages/system/service-image/`
- Shared VM policy: `vm.rs`, `vm_dispatch.rs`, `vm_interrupt.rs`
- Linux KVM: `packages/system/vmm/kvm/`, `packages/tools/vmm/kvm-run/`
- Windows WHP: `packages/system/vmm/whp/`, `packages/tools/vmm/whp-run/`
- VBS and protected execution: search for `Vbs`, `Vtl1`, `ProtectionMode`,
  `AuthenticatedAdmission`, `receipt`, and `sealed` across the workspace.
- Capabilities/IPC/lifecycle: `capability.rs`, `ipc.rs`, `shared_memory.rs`,
  `scheduler.rs`, `task_runtime.rs`, `service_lifecycle.rs`.
- Compiler: `packages/compiler/core/`, `packages/compiler/driver/`; never infer a
  complete compiler or application ABI from supported subset code generation.
  Read `docs/COMPILER.md` and every record under `docs/compiler/oracles/` before
  selecting compiler work. Recover the future-Rust direction, not an assumed
  obligation to reproduce old editions or arbitrary historical rustc behavior.
- Host browser automation: `packages/tools/host/src/browser.rs` and `web.rs`; this
  is not an MRML browser engine, compositor, or OS application implementation.
- Future browser work must read `docs/BROWSER_SEMANTICS.md`: blind humans,
  Braille, speech, keyboard, and text-only AI share one sanitized generational
  tree; there is no AI-only DOM/control path; JavaScript/Wasm remain no-JIT/W^X;
  media is separately authorized; and monitor-off/blind-user evidence precedes
  ABI stabilization.
- Application/GUI/browser OS work: search the whole tree; absence is meaningful
  and planned documentation must not be promoted to implementation status.
- Native filesystem: `packages/services/storage` contains the first userspace-service
  foundation: stable volume/object identities, attenuated generational
  authority with descendant revocation, and canonical checksummed v1 volume,
  superblock, directory-entry, directory, file, and extent metadata. Its bounded
  extent map checks exact logical coverage, physical volume bounds, reserved
  blocks, and intra-file overlap. Its COW planner verifies staged next-generation
  metadata and orders durable metadata before atomic inactive-superblock
  replacement, with fail-stop handling once replacement may have begun. A
  bounded block-volume adapter now performs exact metadata writes, digest
  readback, flush ordering, inactive-superblock replacement, and immutable
  recovery reads over an unsafe block-device contract; uncertain superblock
  durability permanently poisons that adapter session. Exact-block file reads
  verify complete extents before copying, while a bounded file-write session
  reconstructs successor blocks from an exact verified predecessor, verifies
  complete extent and logical-file digests, and flushes before metadata
  publication. A bounded in-process block-service core now supplies principal-
  bound generational sessions, independent attenuable operation rights,
  transitive revocation, device-removal cleanup, checked transfers, and a scoped
  exact-block client. Its canonical v1 control records are fixed-size, carry no
  raw pointer or principal, bind read/write to one separately authorized buffer,
  reject replay per session generation, and poison uncertain mutating sessions.
  The operation exposes its exact service-side buffer access shape, and kernel
  IPC now accepts zero transferred capabilities or exactly one live receiver
  capability with the exact nonzero rights required for that shape. Existing
  shared-memory binding resolution is now composed into that gate and rechecks
  the exact object, VM/task, mapping generation, access, host range, writability,
  and non-executable state before returning only the opaque host resource
  handle. Generic buffer I/O repeats the exact capability and binding checks on
  every use, checks nonempty bounded ranges and write access before calling an
  opaque-handle backend, and preserves backend uncertainty. Selection derives
  one live binding from exact receiver authority and kernel-known VM/task
  identity; missing or ambiguous selection fails before I/O and no request
  field supplies a binding ID. The storage-service transport now performs
  capability/binding validation and replay/poison admission before copying bulk
  bytes, dispatches through bounded caller-owned scratch, and erases scratch on
  every return path. A bounded service-side loop now composes exact receive,
  replay/session admission, capability-selected shared-buffer syscalls, device
  dispatch, canonical response, and unconditional request/capability/scratch/
  response erasure. Admission precedes all bulk and device I/O; copy uncertainty
  consumes the request ID and therefore cannot be retried as a duplicate
  mutation. The UEFI image compiles the concrete operations 4/5/7/8 syscall
  adapter, but no isolated hosted service task invokes it yet. No concrete hosted
  or physical device backend, persistent allocation/free engine,
  complete COW tree, snapshot, or physical crash evidence exists yet.
  The kernel syscall ABI can decode bounded capability-selected shared-buffer
  reads and writes, and a generic executor composes exact task authority, live
  binding selection, validated directional user copy, opaque resource I/O, and
  erased scratch. The x86-64 active-page copy adapter validates the expected CR3
  and every touched user leaf, then permits exactly one matching task/range/
  direction copy; failure cancels any unused ticket. A fixed-capacity opaque-
  resource table now issues fresh monotonic handles, bounds every operation,
  rejects live aliases and stale handles, and retires through the existing
  cleanup path while preserving backend failures. Its address-backed adapter is
  an unsafe supervisor-only boundary. Shared cleanup now uses a minimal native-
  mapping revoker; its active x86-64 service implementation requires exact CR3,
  virtual/physical extent, and permissions before all-or-nothing leaf removal
  and local TLB invalidation. KVM/WHP host bookkeeping can observe that removal
  only after verifying the whole expected leaf range is absent; only then may
  that exact slot be re-armed. Matching KVM/WHP per-service resource slots are
  isolated from the common page and sibling slots and erase their backing page
  before restore. Both hosted runners now schedule receiver-only attachment,
  kernel-side absent-leaf observation, zeroed restore, and final revocation.
  The kernel image binds separate exact receiver-only read and read/write
  capabilities to one live mapping and opaque resource, dispatches bounded
  shared-buffer copies through active user-
  memory validation, and retires mapping, binding, and handle before re-arm.
  Fresh one-time signed KVM and WHP runs verify zero state before each generation
  writes and reads its value, kernel-side retirement before host observation,
  zeroed re-arm, and final retirement. This is hosted controlled-probe evidence,
  not crash, physical-hardware, or host-resistant evidence.
  The kernel image also exposes service-state query operation 9: one exact
  task-local READ capability authorizes one opaque generational service token,
  reserved registers must be zero, and success reveals only Running, Exited, or
  Faulted. A canonical query now crosses buffered IPC with one derived READ
  capability; the userspace service rejects authority in payload bytes or the
  wrong capability count before invoking the syscall and returns a fixed
  detail-free response. Fresh signed KVM and WHP runs exercised that exchange in
  both generations. It neither mutates lifecycle state nor persists policy.
  Restart request bytes now reserve their former time field as canonical zero,
  and syscall operation 10 admits only capability and opaque service identity.
  The kernel image denies that operation until a trusted reprovision plan is
  staged. Restart planning is non-mutating and commit revalidates the exact
  generation, object, cleanup completion, backoff, budget, and one-use plan
  after the host boundary.
  KVM and WHP can additionally construct a third verified service slot with an
  independent page-table root, image, and stack. The shared and resource pages
  remain limited to their original slots. The focused restart-request image
  creates an independent management task there. After old-sender cleanup it
  sends a canonical envelope with exact transferred CONTROL; trusted kernel
  code stages shared-leaf re-arm, commits the revalidated plan, provisions a
  fresh generation, and returns a detail-free response verified in CPL3. Fresh
  signed KVM and WHP runs exercise this exchange. They stop before replacement
  execution; separate ordinary service-probe runs retain the re-entry evidence.
  These are hosted controlled probes, not live persistent-policy restoration,
  host-resistant isolation, crash evidence, or physical-hardware evidence.
  Fixed-capacity directory state supports capability-authorized lookup,
  enumeration, create, rename, remove, and cross-directory file moves. Its
  object-ID allocator is now canonical, COW-persistent, transaction-bound, and
  part of mandatory reachable recovery validation. Cross-directory directory moves require a
  bounded immutable-generation ancestry proof that reaches the selected root
  without encountering the moved object and binds the moved generation's current
  source parent. It retains both bounded source-to-root and destination-to-root
  paths with each ancestor's exact canonical generation; a bounded planner
  merges and deduplicates their affected object/generation pairs in
  child-before-parent order and rejects inconsistent shared ancestors. An
  immutable-state backend constructs exact next-generation states for that
  complete closure and propagates child generations through every affected
  ancestor to the root. Complete-plan staging preflights disjoint output ranges,
  durably stages every unreachable directory image, and admits the complete
  directory set to a fresh transaction. The focused simulation also verifies
  that one allocation successor owns every exact new directory range, binds all
  directory/allocation images into one COW plan, publishes once, and consumes
  the complete directory receipt set atomically before exposing successors.
  Concrete block integration and power-loss evidence remain pending.
  Capability-authorized
  bounded file reads resolve the exact extent generation, synthesize holes, and require full-extent digest
  verification before copying a physical-data subrange. Bounded writes stage a
  complete disjoint successor image, flush it, and remain unpublished until a
  matching canonical full-range zero-padded file-metadata digest and zero-padded extent-list digest are
  included in the COW root plan; the complete logical-file digest is verified
  before data flush. Fixed-capacity transactions group multiple prepared file
  successors under one independently generated COW root publication and return
  one-use activation receipts. Directory successors now stage canonical object
  metadata and entry-list images and activate only through a directory
  transaction receipt. A canonical volume-scoped object-ID allocator image now
  stages a generation-bound successor and activates a reserved stable ID only
  through its distinct one-use transaction participant. A prepared allocation
  successor can now prove exact ownership of the allocator image using a
  distinct purpose, root lifetime anchor, allocator generation, and pointer;
  the anchor is not authority. Reachable recovery now requires exactly one such
  record and canonical allocator image at the candidate generation, rejecting
  removal, duplication, corruption, stale state, substitution, and a concrete
  next ID that could reuse a reachable object. Exhaustion remains valid and
  non-allocating. Concrete block I/O is not yet implemented. Inactive child-authority reservations consume capacity
  without authorizing access and either activate once or retire their generation
  on cancellation, preventing a durable create from racing an unrelated handle
  insertion once orchestration is added. Initial empty files and directories
  now stage canonical unreachable metadata
  and empty subordinate images as typed generation-1 creation participants;
  a bounded exact-generation mutation path constructs the parent-to-root
  directory successor closure and propagates child generations bottom-up.
  The closure's disjoint canonical images are staged child-before-parent and
  admitted to one directory transaction. A bounded coordinator now combines
  that closure with the exact initial child, persistent ID reservation,
  purpose-owned allocation successor, and inactive authority reservation in
  one COW publication and one atomic receipt activation. Focused in-memory
  evidence covers both empty-file and empty-directory creates. The directory
  child's retained canonical parent must equal the unique directory successor
  containing its generation-1 entry and remains available after commit.
  A deterministic durability backend now materializes those six exact staged
  images, verifies their complete digests, fails at every COW publication event,
  and invokes full reachable recovery. Pre-replacement failures select the old
  graph; uncertain replacement/final flush permits only the complete old or
  complete new graph; success selects new. Authority stays inactive without a
  successful receipt. If fail-stop recovery selects the durable new graph, the
  in-memory model cancels the stale inactive reservation and requires an exact
  surviving parent-directory capability carrying `OPEN_CHILD` to derive a
  fresh, kind-valid child handle. The name identifies but does not authorize;
  `LOOKUP` alone is insufficient, and parent revocation transitively invalidates
  the reopened child. A canonical bounded durable-grant checkpoint can now
  reconstruct a separate fresh storage-authority table from an exact externally
  authenticated volume/root-generation/digest tuple, a newer recovery epoch,
  and a strictly newer handle-generation high-water mark.
  It records stable object policy and attenuated parent lineage, never bearer
  handles; rejects hidden bytes, capacity mismatch, cycles/forward parents,
  substitution, amplification, corruption, and replay; and advances the
  volatile epoch/generation guards only after complete reconstruction. Fresh
  slots start at that high-water mark and expose the next value above every
  issued generation, preventing stale pre-reboot token collision. The canonical
  checkpoint can now be staged as a complete capability-authorized stable-file
  successor and activated only through its exact one-use COW transaction
  receipt. Recovery requires separate bootstrap file READ authority and the
  exact file generation already selected by authenticated reachable recovery;
  it never searches older generations, preserves I/O errors, and erases policy
  bytes after parsing. A one-use issuer now matches canonical bytes to an exact
  unsafe owner-approved admission before constructing the otherwise
  unforgeable recovery proof. The replay guard can be initialized only from an
  unsafe authenticated rollback-state token. Stable recovery issues after a
  successful authorized read, so I/O failure does not consume admission;
  duplicate issue fails closed. A canonical 64-byte accepted-state record now
  binds the epoch, handle-generation pair, exact volume, and selected root
  generation behind an authenticated monotonic-store contract. Genesis is
  explicitly unbound; after first acceptance, cross-volume substitution and
  root regression fail closed. Compare-and-store matches the entire prior
  canonical record before replacement. Integrated recovery releases no fresh
  authority table unless that exact transition commits; corruption, conflict,
  and backend uncertainty fail closed. A backend-neutral authenticated journal
  now provides one conforming protocol
  shape for the state store. Two fixed 112-byte slots each bind journal
  sequence, complete recovery state, and SHA3-256 digest. The authenticated
  monotonic counter selects exactly one parity slot; recovery never searches
  the older slot. Replacement writes and durably verifies the inactive slot,
  then advances the counter exactly once as the sole publication point.
  Deterministic tests cover write failure, failure before counter commit,
  committed-but-uncertain advance, corrupt/stale slots, conflict, read
  uncertainty, and exhaustion. The unsafe backend contract—not this simulation—
  must provide policy-authorized exact slots and a power-loss-atomic counter.
  UEFI-side TPM public-area admission now validates the prerequisite layout:
  three distinct owner-configured indices, SHA-256 Names recomputed from each
  complete public area, one exact 8-byte counter, two exact 112-byte ordinary
  slots, one shared nonzero 32-byte authorization policy, policy-only read/write,
  no-DA, and full-slot writes. Alias, type, size, policy, Name, and attribute
  substitution fail closed. A TPM recovery backend now uses that admitted
  layout for bounded exact `NV_Read`, full-slot `NV_Write`, and `NV_Increment`.
  Each operation consumes a fresh one-use session from an unsafe owner-policy
  provider bound to the exact TPM Name, shared policy digest, and operation.
  Response parameters and authorization framing are exact; writes are read-
  verified and increments recheck predecessor and successor. Hosted tests reject
  forged session handles, malformed response authorization, readback mismatch,
  and stale expected counters. A concrete provider now creates a fresh SHA-256
  policy session from explicit nonzero caller entropy, executes the exact
  configured `PolicyPCR` selection/digest, binds it to one requested next NV
  operation, and is constructed only after the exact three-object layout is
  admitted. It rejects Name/index substitution before session creation and
  verifies both NV command handle fields, the operation, and the session handle
  at one-use consumption. It rejects immediate nonce reuse and best-effort
  flushes mismatched or failed sessions. An ambiguous NV-command transport
  failure now clears the
  local pending authorization and best-effort flushes the TPM handle while
  preserving the original error; focused Windows gnullvm and Arch Linux/WSL2
  tests exercise this fail-closed boundary. A safe constructor composes this
  provider, admitted NV
  layout, TPM backend, and authenticated journal; policy/layout substitution
  fails before journal use. An optional all-or-none UEFI development
  configuration now binds the exact indices and policy recipe to TCG2 and a
  fresh firmware-RNG call per session, then authenticates the counter-selected
  slot before boot-services exit. Partial configuration and any backend
  uncertainty fail boot; temporary state is erased. The optimized native
  `x86_64-unknown-uefi` loader now links this path after disabling the unused
  host-runtime default feature on its direct crypto dependency; dependency
  inspection confirms `mrml-runtime` is absent from the firmware graph. This
  path was then executed under QEMU/OVMF nested KVM with fresh pinned,
  independently signed kernel and service artifacts. The exact trace `a1 a2 a3
  a4 a5 a6 a7 a8 b1 b2 b3 d0 d1 d2 d3 d4 df` proves loader execution,
  artifact admission, handoff/page-table construction, kernel entry, and the
  existing VMX-root lifecycle. No recovery variables were embedded because the
  environment has no software TPM, so this does not provision indices or
  policy, execute the recovery journal, or provide physical evidence.
  The host release tool now constructs a canonical genesis release bootstrap
  state from an exact owner-selected public key and nonzero rollback floor and
  can inspect its public fields with an explicit `authentication=not-verified`
  result. This supplies bounded provisioning data without an implicit vendor
  root. It is not owner-consent evidence, TPM enrollment, live key replacement,
  compromised-key revocation, development authorization, or accessible
  recovery, and the ordinary output file carries no boot authority.
  The canonical epoch, handle generation, optional volume, and root generation
  now cross into early kernel decoding through a separately flagged 40-byte
  handoff record. Exact length, reserved bytes, nonzero generations, and the
  volume/root pair are revalidated before region emission. This remains typed
  metadata, independent of artifact rollback evidence; it does not construct a
  recovery token, capability, or authority table. No complete durable TPM
  backend is claimed. A consumed storage-service wrapper now binds this metadata
  to one exact transaction on the independently authenticated state store: one
  load must match every field, and one compare-and-store must reuse the exact
  loaded bytes. Replay, mismatch, malformed state, or backend error erases
  output and cannot release authority. A full configuration recovery simulation
  proves this wrapper composes with owner-approved checkpoint proof,
  capability-authorized checkpoint I/O, dependent validation, monotonic commit,
  and final service registration. This remains hosted deterministic composition,
  not delivery to a live booted storage service. A kernel mechanism now binds
  delivery to one exact service task generation, object, and exact non-
  delegable `READ` capability; it revokes before copying and consumes the
  metadata. Wrong-service, wrong-object, overbroad/stale capability, replay, and
  replacement-task tests fail closed with zero output. The deterministic full
  path now also has an isolated operation-13 syscall adapter. It decodes one
  opaque capability and canonical output address with zero reserved registers,
  validates an exact current-task writable range through the existing one-use
  directional copy contract, performs revoke-before-copy delivery, and erases
  fixed scratch on every return. Pre-delivery validation failure remains
  retryable; copy uncertainty after revocation is terminal. This is focused unit
  evidence, not live booted service, UEFI, TPM hardware, or durability evidence.
  The kernel-image service dispatcher now recognizes operation 13 before the
  generic decoder, revalidates the complete user return frame and active CR3,
  and initializes the exact metadata-only capability/delivery for the initial
  service task generation only when handoff metadata exists. The token is
  launch state, not storage authority. The block-service launch ABI supplies
  that token as a seventh SysV argument. The signed CPL3 service invokes
  operation 13, verifies the exact fixed metadata record, and erases its copy.
  Windows gnullvm passed 451 kernel, 5 KVM-runner, and 7 WHP-runner release
  tests; strict scoped Clippy and both focused UEFI-target image checks passed.
  Fresh independently signed WHP and KVM controlled probes reached the exact
  lifecycle-cleanup gate. This is hosted invocation evidence, not native UEFI,
  authenticated TPM, persistence, reboot, rollback-resistance, Secure Boot, or
  physical evidence. The deterministic recovery test also traverses delivery
  before the authenticated-store wrapper; live composition with that store in
  a booted service now reaches the one-use equality boundary: before readiness,
  the signed service binds the delivered record to a separately constructed
  controlled record, requires one exact load, requires a replay to
  fail with zero output, and erases both copies. Fresh signed WHP and KVM probes
  passed, and Windows gnullvm plus Linux/WSL2 each passed all 116 storage tests.
  The configuration client receives only the typed data, independently rebinds
  it, proves an exact owner-approved authority checkpoint, privately rebuilds
  one attenuated file capability, validates configuration and restart policy,
  and releases them only after the controlled record accepts the exact epoch
  8→9, handle generation 2→3, and root generation 1→2 successor. Both platforms
  passed all 27 configuration tests. The provider remains volatile controlled
  test code, not authenticated hardware, durable storage, power-loss atomicity,
  or physical monotonic-write evidence.
  Dependent
  recovery can run before that commit: one consumed transaction keeps the
  rebuilt table private while a narrowly unsafe side-effect-free validator
  reads the exact selected configuration file,
  reconstructs canonical configuration, and binds its exact service restart
  policy. Only after all validation succeeds does compare-and-store advance and
  release both results. Validation failure leaves accepted state unchanged;
  store failure drops both results; configuration scratch is erased on every
  validator return.
  Reachable-root recovery now also has a typed result that retains only the
  exact file states validated under the selected candidate, keeping primary and
  secondary snapshots separate through selection. This is checksummed
  reachability/integrity evidence only. Selected stable-authority recovery
  entry points now require that file selection, compare its selected
  volume/root generation with the owner-approved admission before reading, and
  retain the authenticated root provenance with reconstructed authority.
  A selected configuration validator also derives its generation from its file
  selection and compares that selection's volume/root with temporary
  authenticated authority before reading. Lower-level recovery remains
  available as mechanism with its documented trusted-caller obligation; boot
  recovery must use the selected variants. This closes the typed in-memory
  root/file substitution gate, but does not provide reboot, TPM, nonvolatile,
  or physical power-loss evidence.
  Service registration can now be planned against one exact vacant supervisor
  slot and generation during dependent validation without mutation. After the
  monotonic store advances, only the committed recovered-authority wrapper and
  matching epoch can consume that plan into a released configuration, authority
  table, and running service. Slot reuse, capacity loss, or epoch mismatch fails
  closed and releases no recovered system. This is deterministic in-memory boot
  composition rather than reboot evidence. A conforming TPM NV or equivalent
  power-loss-atomic
  backend, platform owner-policy authentication/UI, and boot orchestration
  remain pending, so
  reboot-time capability reconstruction and concrete block durability remain
  partial.
  Configuration checkpoints can now participate in this same exact stable-file
  publication protocol. Preparation binds configuration-root READ and file
  WRITE/RESIZE to the exact object, successor generation, length, digest,
  extents, metadata, and transaction participant; no active state changes until
  its one-use publication receipt is consumed. Recovery requires file READ,
  configuration-root CONTROL, and the exact nonzero file generation already
  selected by authenticated reachable recovery. It does not search older
  generations, and I/O uncertainty is never converted into fallback. Current
  coverage is deterministic in-memory simulation, not physical power-loss or a
  live block-service result.
  A recovered configuration can now yield one canonical service-bound restart
  policy only through the exact live setting READ capability. Applying a bound
  result repeats that capability check and requires the exact value and both
  source revisions to remain unchanged. The record carries
  a finite budget and bounded backoff but no capability, launch context, time,
  priority, or automatic restart right. Trusted registration retains the source
  configuration and setting revisions, while every later restart still passes
  the ordinary CONTROL, cleanup, backoff, budget, and fresh-context checks.
  Wrong-service substitution, stale capability, malformed state, and unset
  policy fail closed. Host-side dynamic replacement now requires the bound value
  to be reloaded with an explicitly supplied live setting READ capability and
  independently requires exact service CONTROL. Recover the supervisor's policy
  generation with its lifecycle state: a successful change advances it and
  invalidates older prepared restart plans, while consumed restart budget and
  an existing eligibility deadline survive. Exhaustion preserves the prior
  policy. Signed CPL3 replacement now re-reads the canonical record through an
  IPC-derived setting READ capability, checks a trusted service-object mapping,
  and invokes the kernel through a separate IPC-derived service CONTROL
  capability. Identical signed artifacts completed under hosted KVM and WHP.
  Live persistent restoration and reboot-time capability reconstruction remain
  unimplemented.
  A reusable exact-block composition now stages the configuration checkpoint
  through `BlockFileSession` over `BlockVolume`, including a principal-bound
  capability-selected MRML block-service device. Deterministic integration
  publishes with one exact COW receipt, recovers only the selected file
  generation, and reloads the service-bound policy. Read-only attenuation and
  transitive block-session revocation fail before writes. Identical signed KVM
  and WHP artifacts now execute the same publication and exact-generation
  recovery through the isolated CPL3 block service. The backend remains
  volatile; reboot restoration, power-loss, and physical-device evidence are
  still absent.
  A pointer-free kernel syscall foundation now admits bounded replacement
  mechanics only after exact service CONTROL authorization. Recover its ABI as
  operation 11 with service token, capability, finite restart count, base and
  maximum backoff, and a mandatory zero reserved register. It returns no policy
  or denial detail. This is not the userspace configuration protocol: service
  tokens do not reveal object identity, so the supervision service recovers its
  trusted service-object mapping rather than inferring it from a token.
  Redundant-root
  selection decodes both canonical superblocks, requires complete candidate
  validation, accepts only identical or adjacent usable generations, and marks
  single-candidate fallback. Validator uncertainty aborts rather than becoming
  rollback. The complete reachable-tree validator can now consume exact reads
  through the block-volume adapter, but tests still use simulated storage; a
  focused signed KVM/WHP probes now instantiate the isolated block-service loop
  against a volatile 16-block in-image backend and verify 18 canonical requests
  through stable-policy publication and recovery. The probes also retire the client and service in order, require the
  exact peer-death event, complete both cleanup tickets, tear down the service
  shared mapping/resource, and accept success only after both service slots are
  exited with no task or pending cleanup. This is not a real hosted or physical
  device backend, physical
  power-loss evidence,
  repair, and authenticated anti-rollback state do not yet exist. A
  separate MRML-specific virtual-block foundation now supplies canonical
  fixed requests/completions, disjoint bounded queue layouts, explicit device
  lifecycle, generation-invalidating reset/removal, and backend-neutral exact
  read/write/flush execution through erased bounded scratch. Clean mutation
  rejection remains distinguishable from uncertainty; uncertainty fails the
  device and poisons its bridge. A one-request processor preflights admission
  and completion capacity before consuming, then admits, executes once, and
  publishes the exact completion; post-mutation publication uncertainty fails
  closed. Published completions latch one coalesced notification that crosses
  the existing capability-authorized, allowlisted VM interrupt boundary and is
  cleared only after confirmed injection. Denied or uncertain delivery remains
  pending; terminal device lifecycle invalidates it. It is unit-tested shared
  policy only. An exact MRML-specific 32-bit write/value doorbell over the
  common I/O disposition processes at most one request and rejects every scalar
  mismatch before queue/backend access. A backend-neutral one-exit runner now
  composes backend execution, exit accounting, common I/O dispatch, the exact
  doorbell, one queue transaction, and capability-authorized interruption;
  pending delivery precedes another vCPU entry and any stage error fails the VM.
  No production hosted/physical backend or durability evidence exists yet. A
  freshly one-time-signed compiled KVM and WHP images now exercise the common
  guest driver against volatile two-page backends; this is controlled hosted
  evidence, not recovery or persistence evidence.
  The common runners now wrap those volatile backends in one exact-object live
  capability projection and independently require `READ`, `WRITE`, or `FLUSH`
  for the corresponding operation. Wrong-object, attenuated, stale, and revoked
  authority reaches no backend. Fresh matching signed KVM and WHP probes cover
  this path. The projection now also binds a checked backend start/count,
  translates guest-relative blocks, rejects cross-boundary access before I/O,
  and requires exact advertised geometry before vCPU entry. Nonzero translation
  is simulation-tested; the hosted probes use the full volatile two-block
  region. Production block I/O, physical durability, and hardware evidence
  remain absent.
  Prepared KVM and WHP guests attach the same validated request and guest-read-
  only completion ranges transactionally; ordinary completion writes fail while
  the device-memory path can publish. Dedicated initial-launch builders also
  identity-map request pages RW/NX and completion pages R/NX in guest page
  tables, rejecting aliases and KVM native-slot undercapacity before launch.
  Earlier controlled signed probes wrote one fixed payload and completed one
  request through the common runner on each backend. This is hosted controlled-
  probe evidence, not a production device backend, durability result, or
  physical-device result. A
  protected completion acknowledgement now lets the bridge retire exactly one
  published completion through the device-only write path after confirmed
  notification delivery; the guest-read-only mapping is preserved. The signed
  probes first reused one retired slot for a bounded write/read pair, validating
  and acknowledging both protected records on KVM and WHP. A
  canonical pointer-free active-device configuration record now captures exact
  virtual-block mechanics and must be revalidated against the live generation;
  it is not authority. Typed queue-bound page presentation is now implemented
  by both hosted launch builders: the page is disjoint, completely zero-padded,
  and guest-read-only/NX. Both KVM and WHP have live controlled-probe evidence.
  Signed-guest discovery now has live KVM and WHP evidence; PCI presentation
  remains pending. A
  backend-neutral allocation-free initial guest-driver state now discovers only
  a canonical configuration with a completely fresh idle queue, uses two-phase
  exact publication tickets, fills only the configured-capacity in-flight
  window, and binds ordered completion acceptance to the exact
  counter/slot/generation/request/status/length. A slot is reusable only after
  exact retirement. Completion preparation is non-mutating so the caller can
  publish the protected acknowledgement before committing the fresh ticket;
  replay cannot retire another slot. A terminal completion invalidates all
  outstanding descendants only on commit. An accepted
  reset records its terminal cause and can rediscover only the exact canonical
  successor generation with four zero counters; rejection changes nothing,
  while removal and sequence exhaustion remain permanent. Fresh signed KVM and
  WHP images now repeat eight two-entry windows with disjoint writes, drain each
  in order, and reuse both slots for reads. The 32 requests and 32 protected
  acknowledgements exercise repeated counter and slot wrap against volatile
  storage only. A canonical data-only resume record now binds the complete
  active configuration, all four queue watermarks, and separate last-admitted
  and last-published request IDs. A live unpoisoned bridge captures it against
  the exact active device and poisons on uncertain memory reads. Allocation-free
  guest reconstruction validates exact slot count and placement, canonical
  request encodings and geometry, counter bounds, generation, strict ID order,
  and both history anchors before rebuilding pending ownership. Idle nonzero
  state advances beyond the last published ID. This is unit/simulation policy,
  not crash or recovery evidence. A distinct canonical resume page is now
  configuration- and queue-bound, completely zero-padded, mapped read-only/NX
  to KVM and WHP guests, and writable only through the device path. The common
  bridge recaptures live state before publication and poisons on uncertain
  writes. The host now cuts execution after common processing has consumed
  requests 13 and 14 and published their protected completions, but before
  another vCPU entry can retire either. There is no guest checkpoint port,
  checkpoint exit, or corresponding I/O permission. The host requires
  producer/consumed/published watermarks 14, consumer watermark 12, and both
  history anchors 14 before it
  publishes the exact nonzero page while execution is stopped. The guest
  discards its local driver state, reconstructs two pending ownership records
  from the complete page and physical request slots, retires the two already-
  published completions in order, and continues through operation 32. Fresh
  capture now requires both a stopped vCPU and the device's explicit
  `Suspended` state; suspension rejects device in-flight slots and pending
  interrupts, while resume occurs only after exact publication and validation.
  Signed KVM execution covers this bounded live reinitialization. WHP source
  parity and current compile/lint evidence are present, but no linked or live
  WHP replacement evidence exists. This is not crash recovery. A controlled
  KVM path now leaves the device, bridge, volatile
  backend, and common policy VM identity live while destroying the stopped
  native VM. It prepares a fresh VM from the same verified executable and
  canonical handoff, restores canonical request, completion, and resume pages
  while the device stays suspended, requires fresh zeroed replacement payload
  memory, and enters the kernel from
  its beginning. That entry accepts only all-zero launch state or the exact
  `14/14/14/12` recovery watermarks plus matching ID anchors. This is orderly
  hosted execution replacement. The WHP runner now implements the same
  consuming partition replacement and restores the same three pages through
  their ordinary versus protected device-write paths. Native Windows
  `check --tests` and strict Clippy pass with CUDA excluded, but no linked or
  live WHP replacement evidence exists because `link.exe` is unavailable.
  Both runners now own and destroy the old VM immediately after the exact three-
  page snapshot, before preparing a replacement. No failure path can fall back
  to old execution; preparation or restoration failure leaves the retained
  device suspended. Fresh signed KVM execution covers this ordering, while WHP
  remains compile/lint-only.
  Restart-image capture and restoration are now one backend-neutral,
  allocation-free kernel mechanism. Capture revalidates the complete published
  resume page, retains only reconstruction/history request slots and unretired
  completions, and binds each completion to its canonical request. Restoration
  performs all freshness checks before mutation: queue extents must be zero and
  the resume page must equal the exact configuration-bound fresh record. Slots
  precede counters, protected bytes use the device boundary, and memory
  uncertainty poisons the bridge without resuming the device.
  Restoration consumes the non-clonable restart image once and volatile-erases
  encoded request, completion, and resume storage on all return paths. The VM
  capture type cannot be restored directly. After consuming and destroying the
  exact native VM, each runner crosses a documented unsafe boundary to obtain a
  distinct linear lost-execution witness; restoration accepts only that type.
  It is type state, not authenticated evidence or lifecycle authority. The VM
  budget contains exactly 64 common block exits. This proves deterministic
  host-forced execution loss only; asynchronous/unplanned crash orchestration,
  backend-in-flight recovery, and unbounded progress remain pending. The same
  consuming image now covers an idle MRML-native PCI-MMIO replacement cut. A common
  unsafe guest queue-transport boundary now derives
  exact queue addresses, orders request-slot publication before its producer and
  the exact doorbell, acquires the completion watermark before the next consumer
  slot, and uses the exact protected acknowledgement tuple before local
  retirement. Ahead watermarks cannot skip slots; a reported transport failure
  guarantees no counter or notification became visible and changes no driver
  state, while stale tickets cause no transport access. Its exact
  access/order/tuple/error guarantees are part of the unsafe contract. The
  common path has a concrete x86_64 identity-mapped implementation with
  volatile exact copies, ordered counters, exact port output, and fail-stop
  acknowledgement observation. Controlled-port unit/simulation and signed
  native KVM/WHP execution evidence now exist. The canonical fixed-capacity
  allocation index now supplies exact object-generation
  ownership for physically ordered file-data and object-metadata ranges and
  rejects cross-object overlap and reserved blocks. Its canonical block-aligned
  image binds volume, publication generation, record geometry, full-image
  digest, and zero padding, and decode rebuilds the index. It is traversed by
  the immutable in-memory recovery backend and the generic exact-block adapter,
  but not yet a real hosted or physical block-device backend. Allocation
  image ownership is now distinct and exactly root/publication-generation bound.
  Canonical extent-list images bind file identity, object generation, logical
  length, record geometry, full-image digest, and zero padding, then rebuild
  exact extent coverage during decode. Canonical directory-entry images bind the
  owner/generation and rebuild duplicate checks. File and directory primary
  metadata now use the same complete-range publication rule: the fixed record is
  followed by zeros through its exact pointer extent before hashing. Recovery's
  zero-tail requirement is therefore covered by the COW digest instead of an
  unhashed backend convention. A fixed-capacity validator now
  walks the root directory and every referenced directory/file through one
  immutable-generation read contract, validates parent/generation links and
  purpose-specific metadata/data ownership, and rejects duplicate objects,
  capacity exhaustion, ambiguity, missing ownership, or orphan allocations. The
  integrated recovery entry point falls back from a checksum-valid newer root
  only when its mismatched/unpublished metadata is definitively invalid; an
  injected validation I/O error aborts instead of becoming rollback. The backend
  remains simulated. A volatile/durable cut-point model crashes after every COW
  publication operation: pre-replacement failures recover the old root;
  uncertain replacement/flush failures allow only old or fully metadata-durable
  new state; successful flush recovers new state. Physical power-loss behavior
  is not verified. Allocation/free changes now form an exact next-generation
  image: the active image remains unchanged, its self-allocation rotates, and
  no active range—including one freed by that successor—may be reused before
  publication. Exact encoded successor bytes are now staged, durably flushed,
  digest-bound into a distinct allocation transaction resource, and exposed only
  after a one-use publication receipt. Focused directory-move transaction
  integration is simulated; the isolated block-service transport is exercised
  only by the focused volatile-backend probes, while real device integration
  remains pending. UEFI
  Simple File System use is boot interoperability,
  and `mrml-runtime` file APIs wrap host files; neither establishes native MRML
  storage semantics.
- Graphics: `framebuffer.rs`, UEFI GOP handoff, and signed framebuffer probes are
  bring-up/diagnostic mechanisms. `virtual_gpu.rs` is experimental mediated GPU
  machinery. None is a compositor, surface protocol, display backend, fence
  model, or accelerated desktop implementation.
- GPU recovery starts with `docs/gpu/GPU_ARCHITECTURE.md`, `VIRTUAL_GPU.md`, and
  `DRIVER_BRINGUP.md`. MRML owns the native capability/object model; VirtualGPU
  is priority 1, Blackwell priority 2, and AMD/Intel later. Linux/vendor drivers
  are oracle evidence, not native proof or replay architecture. CUDA/Vulkan/
  WebGPU are compatibility/frontends, GPU generations and DMA revocation are
  mandatory, and GPU compiler work cannot derail the CPU ownership/CFG lane.
  Do not recreate Vulkan: infer machinery where safe, keep tensors first-class
  but AI algorithms outside stable device ABI, preserve Safe/Advanced/Raw
  profiles without universal `unsafe_gpu`, measure escape hatches, and never let
  Blackwell define the portable API.
- VMM device inventory: inspect `vm.rs`, `vm_dispatch.rs`, `vm_interrupt.rs`,
  `virtual_block.rs`, `virtual_gpu.rs`, and both native backends. Currently the common lifecycle,
  guest-memory, exit, I/O-policy, hypercall, and interrupt mechanisms are
  implemented; the MRML-specific mediated GPU queues and virtual-block
  queue/lifecycle/execution policy are partial. The test-only MRML-specific PCI-
  MMIO slice now completes two volatile writes and reads with protected
  acknowledgement on KVM and WHP. No MRML VirtIO, production PCI device,
  durable attached block backend, UART device, NIC, input, sound, USB, or
  general display device is implemented. QEMU VirtIO devices appearing in boot
  commands are external test infrastructure, not MRML VMM implementations.

Before extending that inventory, read
`docs/PARAVIRTUAL_DEVICES.md`. Preserve the MRML-native block transport and its
generation, negotiated-flush, protected-completion, exact-acknowledgement,
suspension, canonical-restart, poison-on-uncertainty, and bounded-runner
evidence. VirtIO and QEMU are
compatibility/testing layers, not authority. Host shares use exact capability
roots rather than raw paths, and accessibility emulators remain distinct from
physical-device and user evidence.
The current host-side PCI/block composition binds exact routed-function and
active-block generations, queue/vector state, capability-selected backend range,
confirmed BAR mapping, and revoke-before-reset/removal cleanup. Signed hosted KVM
and WHP probes discover a test-only attached identity/class through
Configuration Mechanism #1, assign and enable its BAR, and complete one bounded
two-write/two-read/one-flush queue cycle with protected MMIO acknowledgement.
The guest-visible configuration and host device must both negotiate flush, and
backend execution still requires independent `FLUSH` authority. Do not
recover that narrow result as production BAR lifecycle/revocation, durable
block I/O, native PCI interrupts, MSI/MSI-X, DMA, VirtIO, physical evidence, or
an assigned production PCI identity.
The test-only legacy completion path now reads the exact current router state:
interrupt-disable retains a pending completion without injection, and explicit
unmask of the same function generation permits the separately capability-
authorized vector. Recover this only as bounded hosted KVM/WHP evidence, not a
production PCI interrupt implementation.
The PCI-MMIO probe now also performs one orderly consuming VM replacement only
after all five requests and protected completions are retired. It destroys the
old native VM, retains the exact suspended device/bridge/attachment/backend,
restores the canonical idle queue and resume pages into a fresh MMIO-trap guest,
and resumes only after exact nonzero reconstruction. A scalar-transport
substitution is rejected before restoration. Recover this as orderly hosted
replacement evidence only, not crash capture, pending-I/O recovery, durable
backend recovery, reset, hotplug, or physical evidence.
After final replacement proof, the controlled runners destroy the remaining
native execution container and then perform exact revoke-before-reset cleanup.
Backend and interrupt capabilities are preflighted and revoked before the block
attachment resets and PCI generation advances with BAR/decode cleared. Recover
this only as destroyed-VM cleanup evidence; in-place BAR unmapping, hotplug,
durable backend recovery, and production native cleanup remain pending.
Host-side simulation separately covers reset while one completion is published
but unacknowledged and another request remains in flight. Recovery of the
successor requires new block and PCI generations, a fresh bridge, and a fresh
attachment. Never recover the prior BAR acknowledgement, ticket, request,
attachment, or bridge into that successor. This is unit/simulation evidence,
not hosted pending-I/O reset, live unmap/hotplug, durable recovery, QEMU, or
physical evidence.

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

The standalone `RuntimeBodyFacts` object retains up to 256 local facts and 256
ordered runtime place-access facts and is borrowed by the x86 emitter. Local
facts preserve ID, name, type, mutability, and an optional translated declaration
span after scope cleanup releases the active stack entry; assignment facts
preserve stable
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
Before prologue emission, a bounded pass types and preassigns identities for all
declaration forms represented by the supported runtime body and loop parsers. It
mirrors pre-loop, loop, nested-loop, conditional-arm, and post-loop emission
order. Direct loop locals remain active inside that loop; nested and conditional
actions copy the current environment, and each later loop restores the outer
environment without rewinding the fact-ID sequence. The emitter must consume each
preassigned declaration once. Helper parameters and later scoped locals
append to the dynamic fact tail and cannot inherit those reserved IDs. The table
is bounded ephemeral compiler state and includes expanded inlined helper bodies;
it is not serialized IR or a claim of whole-program analysis.
That traversal also stores up to 256 pre-resolved non-wildcard assignment
expectations with stable identity, projections, type, access class, and span.
Emission consumes exact expectations while retaining its separate true-order
read/write ledger; this avoids reordering precomputed writes ahead of RHS reads.
Missing, reordered, malformed, or identity-drifted expectations fail closed.
Assignment RHS expressions whose root is a discoverable place reserve another
fixed 256-entry read-expectation table. The root is resolved against the active
scope and consumed through the ordinary identifier-read recorder. Supported
scalar compound RHS expressions recursively visit casts, ascriptions, unary
wrappers, return/break values, sequences, binary operands, and conditional
condition/arms in exact emission order. Typed nested indexes distinguish
reference-base reads, constant local-array element reads, and runtime local-
array element materialization before the runtime index. Compound array bases and
method/call and aggregate families remain emission-time facts. Supported scalar
expression statements at top level, in conditional arms, in direct and nested
loop actions, and after loops now use the same bounded read visitor in exact
scoped emission order. Conditions/control values, scalar tails, and other body
reads remain outside preanalysis.
The exact capacity errors are `TooManyRuntimeLocalFacts` and
`TooManyRuntimePlaceAccessFacts`; invariant failure is
`InvalidRuntimePlaceFacts`.

Read facts still resolve names during emission. Bounded read-place discovery now
peels identifier, dereference, index, tuple-field, subslice, transparent wrapper,
and sequence-tail syntax into base-to-leaf projection order. It rejects a fifth
projection and 64-level nesting. Direct scalar dereference emission records one
projected read rather than an empty duplicate base read; specialized direct
aggregate paths use the same recorder. Discovery is not yet run body-wide or
consumed by every nested emission family, and address-taking is not yet
classified as a borrow. Compound array-base, method/call, aggregate,
condition/control, scalar-tail, and other body reads are not yet preanalyzed,
and parser-level IDs,
initialization and move paths, CFG
analysis, borrows, loans, and regions are still absent. The next compiler
milestone is supported condition/control and scalar-tail reads before CFG and
initialization/move facts.

Forward-looking compiler policy does not make Cargo's experimental
`edition = "future"` a clean-install default. The recoverable baseline remains
edition 2024 until a pinned toolchain and complete per-package migration are
committed together. A root-only switch leaves current Cargo unable to parse the
workspace because inheriting packages require their own unstable-edition opt-in.

## 4. Select the next work

Recover the three new persistent deltas from
[packages/ARTIFACT_EXTENSIONS.md](packages/ARTIFACT_EXTENSIONS.md),
[ISOLATION_PLACEMENT.md](ISOLATION_PLACEMENT.md), and
[storage/STORAGE_AND_OPTICAL.md](storage/STORAGE_AND_OPTICAL.md). Complete their
documentation first, then keep adaptive isolation and storage/optical as
sequential foundational OS milestones. Preserve every **PLANNED** physical, UDF,
optical, and total-microVM claim until exact implementation and evidence exist.
Total MicroVM is strict: a failed eligible microVM launch makes that component
unavailable and never silently boots or launches it natively. Recovery remains a
separate small audited environment so it can repair persistent isolation policy,
the VMM, and guest-runtime generations even when Total mode cannot start. A
repeated failed persistent Total request may offer an explicit Balanced-once or
Recovery choice, but must not mutate persistent policy automatically; authorized
recovery policy changes are recorded where audit support exists.

Application-launch recovery must retain the exact runtime domain, application
object, immutable application generation and artifact digest, active system
generation, and applied policy generation. The kernel application route accepts
only `NATIVE_PROCESS` or `MICROVM`; in Total mode a native request is rejected
before backend construction and a failed microVM launch is retained as
unavailable without probing the native backend. These are hosted unit-tested
control-plane invariants, not evidence of a GUI application or WHP/KVM
application execution.

The first native-process lifecycle adapter uses a dedicated caller-owned task
runtime. Cleanup removes the complete task context/capability domain before
erasing its exact address space; erasure uncertainty retains the immutable
application endpoint and retired context for explicit retry. Recovery must not
recreate that endpoint, reuse its task identity, or report cleanup complete
until erasure succeeds. Current tests use an unaccounted hosted runtime and do
not prove application-image, GUI, physical, WHP, or KVM execution.

The backend-neutral application microVM owner retains an admitted guest behind
an endpoint that includes a separate launch generation and the complete
immutable application route. Recovered or replacement code must not recreate
that endpoint from scalar fields, transfer a second guest through a consumed
factory, or drop a guest after uncertain teardown. Exact teardown retry is
required. Current coverage uses mock guests and is not WHP/KVM execution
evidence.

Application recovery must preserve the distinction between the fixed five-root
early-boot release and independently admitted application artifacts. The kernel
recognizes bounded executable `ApplicationImage` bytes, but a recovered
`VerifiedRelease` cannot manufacture an application trust root: that request
fails with `MissingTrustRoot`. Recovery must reacquire the exact independently
selected application root and signed artifact through the eventual package and
generation admission path. This is unit-tested artifact-boundary evidence, not
an implemented application loader or recovered application execution path.

The focused recovery oracle now includes the two-vCPU component profiles
`whp_component_service_smp_probe` and `kvm_component_service_smp_probe`. Each
must use fresh signed kernel/package artifacts, the exact signed ZIM/Zstd
consumer/provider generations and signed general SystemRelease, and the
`component-service-smp-probe` runner mode. Acceptance requires both SMP proofs,
the complete ABI-3 component exchange and cleanup, release of exactly two vCPUs,
and (where structured output is emitted) `native_fallback=0`. WHP evidence on
2026-08-26 measured 6,089/3,984 microseconds; nested KVM measured 4,415/4,086
microseconds. Both reported one eligible microVM, one running microVM, and zero
native fallback. This is hosted controlled evidence only.

For system-monitor work, recover the single canonical observer from
[monitor/SYSTEM_MONITOR.md](monitor/SYSTEM_MONITOR.md). Its caches are
disposable: after restart, reconstruct scoped snapshots from authoritative
services, expose sequence gaps and incomplete sources, and never infer
completeness or execute remediation from stale state.

For component-launch recovery, canonical `MRMLSG2` generation bytes and
canonical bounded `MRMLIC1` interface-catalog bytes are required inputs to the
shared runtime resolver. A recovered `ActivatedSystemGeneration` identity alone
is insufficient: its two digests and generation must exactly match both
validated records before an in-generation consumer/provider can produce a
kernel/VMM handoff. Recovery must retain the selected generation and catalog
bytes together; it must never reconstruct a provider from a
filename, path search, current-latest package, or a declaration outside that
generation. The version-2 activation checkpoint and authenticated recovery
state retain both digests. Persistent hardware-backed storage and complete
Manifest V2 catalog delivery remain planned.

The focused WHP/KVM recovery-to-admission path now also requires the general
signed `SystemRelease` bytes and an explicit caller-selected public root before
staging the recovered generation. It compares the admitted generation/catalog
digests with the locally verified component artifacts before kernel admission;
recovery cannot replace the signed pair with raw records. Fresh WHP and nested-
KVM component probes consumed the identical signed release after both runners
emitted byte-identical records. This is hosted controlled-probe evidence, not
persistent Store media or TPM/NVRAM trust-root recovery.

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
