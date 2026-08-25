# MRML packages, deployment, installation, and system administration

**Status: PLANNED.** Existing signed-container parsing, UEFI loading, measured-
boot plumbing, release/recovery journals, rollback policy, native storage
objects, and configuration generations retain the exact implementation statuses
and evidence recorded elsewhere. This document does not claim a package manager,
Store, `SystemImage`, installer, deployment service, shell, or physical-disk
workflow is implemented.

> Installation, updating, offline servicing, recovery, system imaging, and
> system snapshots are different operations over the same immutable package and
> SystemGeneration model, not independent mechanisms.

## Canonical package family

One signed MRML package-container family uses artifact classes and admission
profiles for applications, libraries, drivers, system modules, kernel, VMM,
bootloader distribution, and recovery components. The exact extension and
binary layout remain provisional. Stable reverse-DNS identifiers include
`org.mrml.system.kernel`, `.bootloader`, `.vmm`, and `.recovery`;
`org.mrml.service.network`, `.wifi`, and `.bluetooth`;
`org.mrml.driver.nvme` and `.gpu.nvidia.blackwell`; and
`org.mrml.app.terminal` and `.store`. These illustrate identity, not ownership.

`package_id`, publisher key ID, version, architecture/profile, and content digest
remain separate. Publisher changes do not rename the logical package by default.
Names identify; capabilities authorize. A manifest requests authority and never
grants it.

Canonical metadata binds package ID/class/version, architecture slices, exact
digests, publisher identity/key, dependencies and required interfaces, requested
capabilities, hardware/features, minimum compatible ABI, admission/security
profile, and compiler/security metadata where applicable. Multi-architecture
packages may carry `META/`, shared `RESOURCES/`, and payloads for `x86_64`,
`aarch64`, and `riscv64`; this does not promote architectures beyond the current
roadmap. Large releases may use architecture-specific split artifacts under one
logical release.

Zstandard is the preferred package/image compression family. Canonical bounded
profiles support deterministic hashing, signing, reproducibility, and content
addressing where practical. No final representation is claimed before a format
specification, independent parser review, and adversarial tests.

## Releases and generations

A signed `SystemRelease` is an exact mutually admitted and tested package graph.
Individually valid bootloader, kernel, VMM, service, driver, and application
packages do not automatically compose a valid release. Changing the VMM or any
other bound artifact produces a different release graph even if the kernel is
unchanged.

A `SystemGeneration` is a locally admitted instantiation of the immutable release
graph plus an exact configuration generation, owner trust policy, and required
boot/security state. Useful lifecycle states include `Downloaded`, `Staged`,
`Candidate`, `Current`, `KnownGood`, `Failed`, and `Retired`; names are not frozen
ABI. Transitions are authenticated, monotonic, crash/power-loss safe, and
inspectable. Failed candidates never silently replace the last known-good path.

Kernel, VMM, bootloader, recovery, services, and drivers use the same package
family with class-specific admission. A filename such as `kernel.bin` is not
sufficient identity. Architecture-specific kernel/VMM images and metadata are
selected only after exact release, profile, digest, and feature validation.

## Conventional UEFI bootstrap

> UEFI loads one conventional EFI application; that application is MRML's
> package-aware secure loader.

Ordinary conforming UEFI loads architecture-specific PE/COFF (`BOOTX64.EFI`,
`BOOTAA64.EFI`, or equivalent) from the EFI System Partition. It need not parse
MRML packages. The verified updater extracts the applicable EFI payload from the
bootloader package and stages it safely on the ESP. The loader then selects a
generation, validates bounded canonical manifests/signatures/digests, selects
architecture, decompresses boot-safe payloads, measures relevant artifacts,
constructs launch state, and loads the kernel, VMM, and required early objects.
It does not browse repositories, solve arbitrary dependencies, discover
publishers, run the Store, or perform general installation.

The initial boot-safe Zstd profile has a bounded maximum window and artifact
size, known output size, no external dictionary, and strict malformed-stream
rejection. Userspace may later support broader profiles without enlarging the
early parser.

The ESP converges on active and alternate/known-good EFI loaders, necessary
recovery material, and a small signed generation locator. The native system
volume owns the content-addressed store, release manifests, generation metadata,
and recovery generations. Bring-up may temporarily place more on FAT32; FAT32 is
not the permanent package database.

Bootloader update uses A/B, previous/current, or equivalent staging: verify and
write inactive state, flush and read-back verify, select a candidate, boot it,
and only then mark it known good. Every interruption retains a defined recovery
path and never destroys the final known-good loader first.

UEFI Secure Boot authenticates an owner-authorized EFI loader; MRML separately
authenticates the exact `SystemRelease` and package digests. Owner-controlled
trust roots, development authorization, rollback resistance, and accessible
recovery coexist. A project/vendor key is not permanent machine ownership.
Separate offline root delegations cover system releases, Store metadata/key
sets, system-module policy, and publisher trust. One online Store compromise
must not become Secure Boot or release-signing authority.

## Store and transport

The initial catalog may use GitHub Pages and package artifacts may use GitHub
Releases, but GitHub is transport, not the root of trust. Signed catalog records
bind identity, version, size, digest, architecture, publisher/signature, and one
or more neutral sources such as mirrors, local media, local/enterprise stores,
or GitHub. Artifact identity survives transport changes.

Catalog epochs/generations, accepted-state persistence, appropriate expiry or
freshness, exact digests, key rotation, and revocation resist rollback and
freeze. Old valid signatures do not make vulnerable metadata current.
Applications, system components, drivers, developer tools, accessibility,
language/localization, models, and updates are presentation categories, never
authority.

The Store may authenticate and download kernel, VMM, bootloader, services,
drivers, modules, or applications, but only a generation builder performs
admission and constructs a candidate. Download does not grant kernel, MMIO, DMA,
filesystem, network, device, or other capability.

## System images, export, and servicing

A signed, content-addressed, Zstd-compressed, multi-architecture `SystemImage`
is streamable where practical and independently verifiable for installation,
recovery, offline servicing, and archival export. Its provisional structure has
`META/` image/signature/profile metadata, `RELEASES/` exact manifests,
`PACKAGES/` content-addressed objects, `BOOT/` required boot/recovery material,
and `OPTIONAL/` drivers, applications, languages, and profiles. Identical content
is not duplicated. Builders measure whether to retain independently compressed
packages or repack canonical payload groups; they do not blindly nest Zstd while
preserving package/content verification.

Exporting a generation preserves exact package identities/digests and relevant
configuration/trust metadata. A system image is a deployable OS, not a personal
backup: it excludes arbitrary documents, browser history, personal data,
credentials, and non-exportable secrets by default. `USE` remains distinct from
`EXPORT`. Transferable secret backup requires explicit export authority,
trusted consent/policy, encryption, and destination semantics; hardware-bound
secrets may require reprovisioning.

A first-party deployment/servicing service modifies the running machine only by
building a candidate generation and modifies offline images/staged generations
through the same immutable operations. It never patches arbitrary live system
files in place. Recovery selects verified known-good generations or performs
the same offline service operations under recovery-specific authority.

## Typed administration and terminal

The native shell takes object pipelines, discoverable commands, structured
errors, inspectable properties, and explicit destructive operations from
PowerShell 7 without promising syntax compatibility, Windows object models,
ambient administrator authority, or stringly compatibility. Commands return
typed `DiskObject`, `PartitionObject`, `VolumeObject`, `SystemImageObject`,
`SystemGenerationObject`, `PackageObject`, `CapabilityObject`, `ServiceObject`,
`GpuObject`, `CpuObject`, `TemperatureSensorObject`, and `PowerProfileObject`
where appropriate. Text is presentation, not universal administration IPC.

Provisional verbs include `Get/Test/Mount/Dismount/Install/Export-SystemImage`,
`Get/Set-Next-SystemGeneration`, `Get/Add/Remove/Update-SystemPackage`,
`Update-System`, and disk/partition/volume commands. Pipelines carry semantic
objects with identity and generation, while every action independently checks
exact capabilities.

The first-party terminal accelerates glyph rasterization/cache, scrolling,
selection, composition, HiDPI, and suitable animation through the GPU when
available, with software/GOP fallback. Canonical terminal state is semantic
text, not pixels. Braille, speech, AI, search, selection, and copy use the same
redacted semantic state. The terminal is neither root nor ambient authority and
its scrollback and rendering resources are bounded.

## Disk, partition, and boot administration

Native administration enumerates disks, inspects tables, initializes GPT,
creates/deletes partitions, identifies ESPs, creates MRML system/data/recovery
partitions, formats supported filesystems, inspects volumes, stages boot state,
and verifies layout. MBR/legacy BIOS is not a native priority. NVMe controller,
namespace, queue, health, and content authorities remain separate from layout
administration.

Conceptual rights `READ_LAYOUT`, `MODIFY_PARTITION_TABLE`, `FORMAT`, `ERASE`,
`INSTALL_BOOT`, and `MOUNT/ATTACH` are independently attenuated and revocable.
Metadata observation does not authorize destruction or content. Bounded DMA,
IOMMU, reset/recovery, and native-storage invariants remain unchanged.

Before destructive work, a canonical preview identifies the exact disk by
stable hardware evidence, expected prior layout/generation, every delete/create/
format/boot/deploy operation, and an explicit data-loss result. Trusted
authorization binds this exact transaction and expires; generic “allow
installer” authority is insufficient. Revalidation before commit rejects device
replacement, changed layout, stale plan, ambiguity, or partial cleanup.

## InstallPlan and installers

A declarative `InstallPlan` contains target disk, layout, architecture, profile,
exact `SystemRelease`, package selections, boot configuration, owner trust
policy, network bootstrap policy, accessibility defaults, and recovery
configuration. It is intent/data and grants no destructive authority.

```text
InstallPlan -> Validate -> Preview -> trusted exact authorization
            -> Execute -> Verify -> Candidate -> KnownGood after boot proof
```

Downloaded plans cannot trigger installation. Unattended/declarative deployment
uses the same validation and exact pre-provisioned authority; noninteractive does
not mean ambient. Secrets and credentials arrive through separate scoped
provisioning, not embedded casually in plans or images.

The first complete installer is text based, keyboard operable, minimal,
recovery-friendly, and understandable, with strong automatic defaults and
optional advanced choices. Its short path is welcome -> language/accessibility
-> disk -> automatic/custom layout -> profile -> owner/trust setup -> exact
destructive review -> install -> verify -> reboot. It does not wait for the GUI.
A later GUI installer is a Semantic Scene Graph projection over the same
`InstallPlan`, preview, authorization, execution, and verification service—not a
second installer architecture. Essential text and GUI flows support trusted
visual, keyboard, Braille, and speech operation as capability and evidence mature.

## Verification, recovery, and review

Dependency order is: specify/fuzz canonical package and boot-safe compression;
release graph and generation state machine; content store and catalog rollback;
bootloader A/B; image/export/offline servicing; typed read-only shell objects;
exact destructive transaction service; text installer; unattended deployment;
then GUI projection. Do not skip storage durability, owner-trust, accessibility,
or rollback gates for Store presentation.

Tests cover canonical encoding/digests, architecture selection, decompression
bounds, invalid graphs, publisher/admission separation, catalog replay/freeze,
generation power loss, A/B interruption, image streaming/deduplication, secret
non-exportability, online/offline equivalence, typed pipeline identity, capability
attenuation, stale disk/layout substitution, transaction preview binding,
installer recovery, accessibility, and known-good boot proof. Label simulation,
hosted VMM, UEFI, provisioned Secure Boot/TPM, physical disk, NVMe, reboot, and
power-cut evidence exactly.

Digital-rights review: owner trust roots and export/migration remain practical;
the Store cannot create publisher DRM; imaging excludes personal data and secrets
by default; unattended install cannot erase without exact authority; installer
and recovery semantics remain accessible. Hostile-security review: treat package,
catalog, compression, manifest, image, plan, filesystem, firmware, partition,
device identity, and recovery inputs as hostile; prevent dependency/capability
amplification, rollback, parser exhaustion, stale-device substitution, partial
commit, and last-known-good destruction.

Patent review: `TRIGGERED` — package/image containers, content-addressed
deployment, snapshot/export, offline servicing, Store update, A/B boot,
transactional install, and object-shell compositions require mechanism-specific
worldwide review before implementation. See
[`patents/REVIEW_LOG.md`](patents/REVIEW_LOG.md).
