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

Read `AGENTS.md`, `README.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`,
`docs/APPLICATION_PLATFORM.md`, this file, `docs/ROADMAP.md`, and
`docs/MICROKERNEL.md` completely. Then inspect recent history for the affected
subsystem. README gives repository-wide rules; ARCHITECTURE gives stable
direction; SECURITY gives normative boundaries; APPLICATION_PLATFORM gives the
native/VM/browser/GUI/AI contract; ROADMAP gives dependency order; MICROKERNEL
is the detailed dated evidence ledger. Source and tests decide whether a stated
item actually exists.

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
