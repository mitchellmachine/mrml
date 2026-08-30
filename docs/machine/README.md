# MRML technical-document index

This directory is the entry point for machine-oriented and detailed engineering
material. The files indexed here retain their established canonical paths so
existing references, review history, and tooling continue to work. Moving a
document into this directory is not required for it to be classified as a
technical document.

The concise project `README.md` and the guides under `docs/human/` are intended
for people approaching the project. This index is intended for maintainers,
review tools, and automated agents that need the complete architecture,
evidence, policy, or historical record.

## Authority and interpretation

Document location does not determine authority. Apply this order when records
overlap:

1. [`ENGINEERING_CONSTITUTION.md`](../ENGINEERING_CONSTITUTION.md) is normative
   for major architectural decisions.
2. The canonical architecture and policy document for a subsystem defines its
   current constraints.
3. Generated status and inventory files describe the checked workspace; they do
   not create policy.
4. Oracle, probe, review, and historical records report bounded evidence. They
   do not establish broader support or completion claims.
5. [`PROJECT_TECHNICAL_REFERENCE.txt`](PROJECT_TECHNICAL_REFERENCE.txt) is a
   retained overview snapshot. Current canonical documents take precedence.

Status terms such as **IMPLEMENTED**, **PARTIALLY IMPLEMENTED**,
**EXPERIMENTAL**, **PLANNED**, and **ASPIRATIONAL** have the meanings defined in
[`ARCHITECTURE.md`](../ARCHITECTURE.md). Evidence applies only to the exact
environment and operation recorded.

## Normative project-wide documents

- [Engineering Constitution](../ENGINEERING_CONSTITUTION.md)
- [Operating-system architecture](../ARCHITECTURE.md)
- [Operating-system security model](../SECURITY.md)
- [Application-platform architecture](../APPLICATION_PLATFORM.md)
- [Accessibility architecture](../ACCESSIBILITY.md)
- [Operating-system roadmap](../ROADMAP.md)
- [Project-direction recovery](../RECOVERY.md)

## Subsystem architecture and policy

- [Accessible browser semantics](../BROWSER_SEMANTICS.md)
- [Rust compiler direction](../COMPILER.md)
- [Deployment, installation, and system administration](../DEPLOYMENT.md)
- [Adaptive isolation placement](../ISOLATION_PLACEMENT.md)
- [Microkernel design and evidence](../MICROKERNEL.md)
- [Paravirtual-device architecture](../PARAVIRTUAL_DEVICES.md)
- [Braille interface design](../accessibility/BRAILLE_INTERFACE.md)
- [Monitor-off accessibility acceptance](../accessibility/MONITOR_OFF_ACCEPTANCE.md)
- [Bootstrap build and packaging toolchain](../build/BUILD_SYSTEM.md)
- [MRML linker](../compiler/LINKER.md)
- [MRML ABI v1](../compiler/MRML_ABI_V1.md)
- [GPU driver bring-up](../gpu/DRIVER_BRINGUP.md)
- [Native GPU architecture](../gpu/GPU_ARCHITECTURE.md)
- [VirtualGPU](../gpu/VIRTUAL_GPU.md)
- [Capability-bound memory resources](../memory/MEMORY_RESOURCE_MODEL.md)
- [Unified system monitor](../monitor/SYSTEM_MONITOR.md)
- [Network and Bluetooth administration](../network/NETWORK_ADMINISTRATION.md)
- [Artifact extensions and content identity](../packages/ARTIFACT_EXTENSIONS.md)
- [Versioned component interfaces](../packages/COMPONENT_INTERFACES.md)
- [CPU platform, scheduling, power, and thermal architecture](../platform/CPU_PLATFORM.md)
- [UEFI boot and Secure Boot administration](../platform/UEFI_BOOT_MANAGEMENT.md)
- [Storage tooling, disk images, and optical media](../storage/STORAGE_AND_OPTICAL.md)

## Generated status and inventories

These files are maintained by repository tooling. Do not hand-edit generated
content unless the generating workflow explicitly requires it.

- [Generated workspace status](../STATUS.md)
- [Generated unsafe-boundary inventory](../UNSAFE_INVENTORY.md)
- [Cargo bridge inventory](../build/BRIDGE_INVENTORY.md)
- [Universal build migration inventory](../build/MIGRATION_INVENTORY.md)
- [Compiler durable checkpoint](../compiler/CHECKPOINT.md)

## Reproducible oracle and probe evidence

- [`docs/compiler/oracles/`](../compiler/oracles/) records exact dated Rust
  oracle generations and their provenance.
- [`docs/compiler/probes/`](../compiler/probes/) contains independently authored
  compiler and linker probes plus their launch scripts.
- [`docs/compiler/linker/`](../compiler/linker/) contains platform-specific
  linker measurement scripts.

Probe source and scripts are evidence fixtures, not user setup instructions.
Their presence does not mean that every host platform is currently available or
verified.

## Patent-awareness records

Patent material is technical risk screening, not legal advice or an
infringement determination.

- [Patent-awareness policy and index](../patents/README.md)
- [Review log](../patents/REVIEW_LOG.md)
- [Potentially relevant active rights](../patents/ACTIVE.md)
- [Potentially relevant pending applications](../patents/PENDING.md)
- [Expired, lapsed, abandoned, or cancelled rights](../patents/EXPIRED.md)
- [FAT long-file-name technical screen](../patents/FAT_LFN_SCOPE_2026-08-29.md)
- [Historical source-path migration record](../patents/PATH_MIGRATION.md)

## Historical and retained context

- [Detailed project overview snapshot](PROJECT_TECHNICAL_REFERENCE.txt)
- [Patent-review source-path migration history](../patents/PATH_MIGRATION.md)

Historical documents are retained for provenance. They must not be used to
promote an old test result into current platform support.
