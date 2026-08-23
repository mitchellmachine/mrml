# MRML contributor and recovery instructions

These instructions apply to the entire repository. The Git repository is the
durable source of truth; chat history, agent memory, local notes, and benchmark
claims outside the repository are not authoritative.

Before changing kernel, VMM, boot, signing, protected-execution, capability,
IPC, device, or security code, read completely:

1. `README.md`
2. `docs/ARCHITECTURE.md`
3. `docs/SECURITY.md`
4. `docs/ROADMAP.md`
5. `docs/RECOVERY.md`
6. `docs/MICROKERNEL.md`

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

Implement OS work in the dependency order in `docs/ROADMAP.md`. Determine the
next milestone from current code, tests, documentation, TODOs, and Git history,
not from an old summary. Record exact test commands and outcomes. Distinguish
unit tests, simulation, hosted controlled probes, nested virtualization, and
physical-hardware evidence. Never claim Linux, Windows, VTL1, TPM, IOMMU,
Secure Boot, bare metal, or physical hardware was verified unless that exact
environment was exercised.
