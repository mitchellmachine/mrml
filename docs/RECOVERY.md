# Recovering MRML project direction

Use this procedure when prior conversations, agent memory, local notes, signing
artifacts, or development context are unavailable. Git is authoritative.

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

Read `AGENTS.md`, `README.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, this
file, `docs/ROADMAP.md`, and `docs/MICROKERNEL.md` completely. Then inspect recent
history for the affected subsystem. README gives repository-wide rules;
ARCHITECTURE gives stable direction; SECURITY gives normative boundaries;
ROADMAP gives dependency order; MICROKERNEL is the detailed dated evidence
ledger. Source and tests decide whether a stated item actually exists.

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

Use `rg` to locate definitions, callers, tests, TODOs, probe modes, and feature
gates. Inspect manifests and the pinned toolchain before assuming build targets.

## 4. Select the next work

Compare the current source and tests with the first incomplete security gate in
ROADMAP. Choose the smallest coherent end-to-end milestone that advances that
gate and can be tested in the available environments. Preserve backend-neutral
policy and both WHP/KVM adapters. Do not skip service-foundation dependencies to
implement attractive high-level policy prematurely.

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
