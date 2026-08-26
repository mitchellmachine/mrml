# MRML storage tooling, disk images, and optical media

Status: **DESIGN GOAL / PLANNED** except where this document cites an existing
implementation and focused evidence. Existing capability-bound native storage,
virtual block queues, package-derived GPT/FAT boot media, and deployment
transactions are foundations; UDF, optical burning, ATAPI, USB optical, VirtIO
optical, and real-drive passthrough are not thereby implemented.

## Typed administration and authority

First-party tooling and the object shell share typed services for `Disk`,
`BlockDevice`, `PartitionTable`, `Partition`, `Volume`, `Filesystem`,
`DiskImage`, `OpticalDrive`, `OpticalMedia`, and `OpticalImage`. Every physical
or virtual device and inserted medium has stable object identity plus a
generation. `/dev/sda`, `Disk 1`, `D:`, paths, labels, and enumeration numbers
identify presentation only and never authorize.

Visibility is separate from destructive authority. Capabilities distinguish at
least disk read, health read, disk write/erase, partition read/modify,
filesystem format/check, disk-image create/write, and optical read/burn/erase/
eject. A destructive preview binds the exact device/media generation, operation,
ranges, image digest, and consequences before owner authorization. Reuse of an
enumeration number or media replacement invalidates old authority.

Platform/native block descriptors enter the isolated `BlockService` through an
atomic fixed-capacity registration set. The service preflights set-internal
duplicates, collisions with every live registered identity, and complete slot
capacity before publishing any descriptor. Registration records identity and
geometry only; an explicit principal-bound session grant is still required for
every read, write, flush, or superblock operation. Hardware discovery backends
must use this control-plane boundary rather than granting authority from PCI,
AHCI, VirtIO, firmware, path, or enumeration metadata.

Initial session publication for a registered set is atomic as well.
`BlockSessionGrant` records an explicit device, principal, and attenuated rights
decision; `grant_sessions_atomic` validates every device and rights mask plus
complete session capacity before publishing any handle. A late unknown device,
invalid right, or exhausted table therefore leaves no partial I/O authority.

The registration boundary now **PARTIALLY IMPLEMENTS** stable platform/media
provenance. `PlatformBlockDeviceIdentity` records an opaque nonzero stable
identifier, transport class, and exact nonzero controller and media generations
beside the service-local descriptor. `BlockDeviceId` remains a local registry
identity and never substitutes for that provenance or grants authority. A
replacement media generation cannot coexist under the same live stable
controller identity: removal first revokes every old session, after which the
new generation may be registered. Installed-recovery enumeration accepts only
sessions backed by this platform descriptor and rejects legacy registration
before block I/O. The current hosted source supplies synthetic provenance;
native UEFI/AHCI/USB/VirtIO identity derivation and physical media evidence
remain **PLANNED**.

The first UEFI source primitive is now **PARTIALLY IMPLEMENTED** in the shared
firmware library. ABI-checked `EFI_BLOCK_IO_PROTOCOL`/media layouts are copied
into a bounded snapshot only after canonical Boolean, media-presence, alignment,
block-count, and overflow validation. A maximum-4096-byte, single-instance UEFI
device path is structurally validated through its exact end node and hashed with
an MRML domain separator into the opaque boot-scoped stable identifier;
firmware `MediaId` maps injectively to a nonzero media generation. This creates
non-authorizing descriptor input only. The loaded-image source now opens the
exact device handle's Block I/O and Device Path protocols with UEFI
`GET_PROTOCOL`, copies all inputs into caller-owned bounded memory, and closes
both relationships before returning. Failure to open the second protocol cleans
up the first; both closes are attempted and any close failure rejects discovery.
Actual loader integration, reads, multi-device enumeration, persistence across
boots, and physical firmware evidence remain **PLANNED**.

An exact 4 KiB recovery-read bridge is now **PARTIALLY IMPLEMENTED** for
compatible 512/1024/2048/4096-byte UEFI media. It uses a 4096-aligned private
buffer, checked logical-to-firmware LBA multiplication and range bounds, and one
firmware request covering exactly the constituent blocks. The complete media
snapshot is revalidated before and after the read. Backend failure or post-read
media replacement erases all output; incompatible block size/alignment fails
before firmware access. This is host-mocked and cross-build evidence, not a
running loader, durable storage, OVMF, or physical-device result.

Bounded UEFI Block I/O handle enumeration is now **PARTIALLY IMPLEMENTED**.
`LocateHandleBuffer(ByProtocol)` output is treated as firmware-owned hostile
storage: count, fixed caller capacity, alignment, null handles, and duplicates
are checked before publication; the array is copied locally and `FreePool` is
required on every allocated result, including locate failure. Free uncertainty
rejects the operation. Handle values and firmware order remain ephemeral
presentation and never form stable identity or authority. Per-handle descriptor
opening, block-zero volume matching, and real-loader execution remain next.

One per-handle recovery-header transaction is now **PARTIALLY IMPLEMENTED**.
It opens Block I/O and Device Path together, snapshots media, converts compatible
firmware geometry into exact native 4 KiB geometry, reads block zero, decodes the
canonical `VolumeHeader`, exact-matches its size/count to the converted
descriptor, erases scratch, and closes both protocols before publishing a
candidate. Invalid headers and close uncertainty publish nothing. Windows and
Arch Linux each pass 33 UEFI-library tests and cross-build the target; this is
mocked protocol evidence, not a real installed-volume scan.

Complete-set expected-volume selection is now **PARTIALLY IMPLEMENTED** above
that probe. Every bounded handle is considered; unsupported/non-MRML media may
be skipped, while protocol, read, replacement, or close uncertainty aborts the
scan. Candidate handle/local-ID substitution, duplicate stable platform
identity, zero expected matches, and multiple expected matches fail distinctly.
Reversing firmware enumeration order selects the same stable identity. Windows
and Arch Linux each pass 34 UEFI-library tests and cross-build the target; real
loader invocation and root reads remain **PLANNED**.

Selected-device redundant-root reopening is now **PARTIALLY IMPLEMENTED**. The
ephemeral handle is reopened, its complete path/media/native geometry descriptor
is exact-matched, and block zero must reproduce the selected canonical header
before primary and secondary roots are read. Neither root buffer survives a
header/path/media mismatch, failure of the second read, or failure to close
either protocol after successful I/O. Windows and Arch Linux each pass 35 UEFI-
library tests and cross-build the target. Root graph validation and real-loader
ownership transfer remain **PLANNED**.

A read-only exact-generation `StorageBlockDevice` adapter is now **PARTIALLY
IMPLEMENTED** for the selected UEFI handle. It is lent only inside one reopened,
path/media/header-revalidated protocol lifetime, uses private aligned transfer
storage, and publishes a multi-block read only if every constituent 4 KiB block
succeeds. A late failure zeroes the complete caller destination. Write, flush,
and superblock replacement are always denied, and close uncertainty discards the
operation result. Windows and Arch Linux each pass 36 UEFI-library tests and
cross-build the target. The reachable-graph validator has not yet been composed
through this adapter.

Complete reachable-graph validation through that exact UEFI generation is now
**PARTIALLY IMPLEMENTED**. One operation keeps the selected Block I/O and device-
path protocols open while the shared `BlockVolume` reads both redundant roots
and the existing storage validator traverses allocation, object-ID, directory,
and file metadata. No UEFI-specific filesystem parser or recovery selector is
introduced. Scratch is erased on every outcome, and close uncertainty discards
an otherwise valid recovered graph. Windows and Arch Linux each pass 37 UEFI-
library tests and cross-build the target. Real-loader invocation and transfer of
the recovered installed owner into early boot remain **PLANNED**.

The real UEFI loader now **PARTIALLY IMPLEMENTS** installed-graph admission
before `ExitBootServices`. When the authenticated recovery journal names a
volume/root, the loader enumerates at most 32 Block I/O handles, selects exactly
one matching volume, validates its complete graph through the scoped adapter,
and exact-matches the recovered root generation with the journal. The boot
validator is explicitly bounded to 256 allocation records, 64 directories, 64
extents per file, 64 objects, and 64 KiB metadata scratch; exceeding a bound
fails boot rather than weakening validation. The UEFI target cross-builds on
Windows and Arch Linux. This is compile evidence, not firmware execution, physical-media
evidence, or transfer of device identity into the kernel.

The exact installed selection now converts into a canonical 104-byte,
non-authorizing boot identity and is retained through `ExitBootServices` to
handoff construction. It carries source class, opaque stable ID,
controller/media generations, 4 KiB-native geometry, volume, and selected root;
firmware handles, local device IDs, sessions, pointers, and capabilities are
absent. Windows kernel tests pass 561, UEFI tests pass 37, and the UEFI target
cross-builds. The canonical kernel handoff does not yet include the record, and
cross-transport native-device correlation remains **PLANNED**.

The canonical kernel handoff now includes the record under a distinct flag and
requires exact volume/root-generation equality with its authenticated recovery
metadata. The encoder shifts the existing SMP/MADT tail only after validating
capacity, and the decoder rejects malformed identity or inconsistent tail
length before publishing regions. The real loader uses this path. Windows
kernel tests pass 561, UEFI tests pass 37, and the UEFI target cross-builds.
Native AHCI/USB identity correlation and live `BlockService` reacquisition
remain **PLANNED**.

The service half of live reacquisition is now **PARTIALLY IMPLEMENTED**. One
bounded supervisor operation exact-matches the handed source, stable identifier,
controller/media generations, and geometry against a unique registered platform
descriptor before granting a principal-bound read-only session. Identity is
still data rather than authority; write remains denied and all block reads use
the ordinary session checks. Windows and Arch Linux storage suites pass 125
tests. Native transport enumeration, the proof that its derived identity
corresponds to the firmware source, configuration-service composition, and
physical-media execution remain **PLANNED**.

Configuration-service composition is now **PARTIALLY IMPLEMENTED** through the
same boundary. It reads and validates block zero via the reacquired session,
then exact-matches the handoff volume, geometry, and selected primary/secondary
root before creating the installed selection consumed by graph recovery. Any
failure revokes the new session before return. Configuration passes 49 tests on
Windows and Arch Linux; WHP/KVM runner parity remains 11/12. Native driver
correlation, complete graph/Total-owner composition, and physical media remain
**PLANNED**.

Complete graph/Total-owner composition is now **PARTIALLY IMPLEMENTED** in the
controlled hosted path. Recovery-only handoffs carry the installed identity;
the recovery source refuses absence, reacquires its exact read session, validates
the selected root and reachable graph, and retains the installed selection
through Total admission. Windows and Arch Linux pass 561 kernel and 49
configuration tests; WHP/KVM runner parity passes 11/12. Native transport
enumeration/correlation, durable storage, OVMF, and physical media remain
**PLANNED**.

The transport-neutral correlation control plane is now **PARTIALLY
IMPLEMENTED**. `NativeBlockCorrelationVerifier` is an unsafe trusted-driver
contract: success must prove that an independently discovered physical route
and medium are the exact firmware-selected device, and may not be implemented
by copying IDs or matching presentation paths/names/order. `BlockService`
preflights native transport, geometry, capacity, local/native identity, and
existing boot correlations, calls the verifier, then atomically stores the
native descriptor plus exact boot correlation without granting I/O. Storage
passes 126 tests on Windows and Arch Linux. AHCI, USB, and native VirtIO
verifiers and hardware execution remain **PLANNED**.

The `mrml` frontend may expose structured `disk`, `filesystem`, `optical`, and
`media` operations. The PowerShell-inspired shell projects the same backend as
typed `Get-*`, `Test-*`, `Initialize-*`, `New-*`, `Format-*`, `Write-*`, and
`Mount-*` operations; it never scrapes CLI text. GUI `Disks & Media`, installer,
recovery, accessibility, automation, and AI consume the same capability-scoped
objects, progress, diagnostics, and redaction.

## Disk checking and images

Checking has distinct result types for block-device health, partition-table
validation, filesystem validation, and media readability. Inspection never
silently repairs. GPT checking covers protective MBR, primary and backup
headers/tables, CRCs, range/alignment, overlap, identifiers, and primary/backup
agreement. Repair requires a separately previewed transaction and a valid source
of reconstruction.

Formatting and checking use shared `FilesystemFormatter` and
`FilesystemChecker` contracts. Initial implementations match real filesystem
support: FAT32 must cover ESP/install/recovery use; native filesystem support is
integrated only as it becomes implemented; detection never implies repair.

Raw images are exact byte-addressable block images with bounded logical size,
sector assumptions, and block count. Host sparse creation is preferred where
supported and records logical size, allocated size, sector size, and format.
Creation rejects zero/overflowing/misaligned sizes, output collisions, unsupported
block counts, and known insufficient capacity. Partitioned image creation reuses
the deployment transaction: create GPT, ESP and MRML partitions, format, deploy
an authenticated `.mrz`/`SystemRelease` package graph, flush, reread, and verify.
Writing an image to a physical disk is never modeled as an authorized blind copy.

## Optical object and common MMC layer

Optical media is not an ordinary random-write disk. `OpticalDrive` reports
transport, vendor/model/firmware, discovered profiles and speeds, tray/current
media state, and actual read/write/rewrite capabilities. `OpticalMedia` records
its own generation, profile (CD/DVD/BD ROM/R/RW/RE as supported), capacity,
writability, finalization/session state, and detected filesystem.

One common bounded optical/MMC service owns profile discovery, readiness,
capacity, reads, eject/load, write/erase, synchronization, finalization, sense
mapping, timeout policy, and progress. Initial native transports are only
AHCI/SATA ATAPI and applicable USB Mass Storage SCSI/MMC. AHCI and USB provide
transport; neither duplicates Blu-ray policy. IDE/PATA, FireWire, general SCSI
HBA, and other transports remain out of scope.

Errors are semantic—no media, media changed/read-only/not blank/full, drive not
ready, unsupported media/command, sense error, device removed, write/power-
calibration/finalization/verification failure—while bounded lower-level sense
diagnostics remain available to authorized inspection. Long burns use operation-
specific timeouts and shared semantic progress: preparing, writing sectors/
percent, finalizing, verifying, and complete.

## UDF and optical images

MRML will independently implement a deterministic bounded UDF writer, reader,
and checker for the highest revision actually demonstrated interoperable across
the supported Windows 11 environment, supported Linux environment, and MRML.
UDF 2.60 is a candidate, not a selected or implemented claim. The evidence must
cover Unicode, empty/deep trees, normalized timestamps, malformed extents, and a
file larger than 4 GiB. External implementations are behavioral oracles, not
source to copy.

`.iso` denotes an interoperable logical optical image and may contain ISO 9660,
UDF, or a hybrid profile. ISO 9660 and optional Joliet remain separate from UDF.
UEFI optical media includes the required El Torito/catalog boot structures,
`BOOTX64.EFI`, authenticated `SystemRelease`, `.mrp` packages, and optionally a
complete `.mrz` image. Firmware does not merely scan an arbitrary optical tree
as if it were an ESP. Image validation covers descriptors/extents, boot catalog,
release/package graph, digest, capacity, and media profile before burn.

## Burning and physical semantics

An `OpticalImageBuilder` produces a deterministic sector stream consumed by one
`OpticalWriter`; direct `.mrz` burn reuses that path. Initial implementation may
materialize the `.iso`, while the API permits future bounded streaming once
layout and digest are known.

`BurnTransaction` binds exact drive and media generations, image identity,
speed, finalization, and verification policies. It inspects, previews, requires
`OPTICAL_BURN`, writes, synchronizes drive cache, finalizes as requested, and
rereads sectors/content digests. Drive success without readback is not verified.
`OPTICAL_ERASE` is separate. Write-once CD-R/DVD-R/BD-R consumption is explicit
and irreversible; rewritable media uses profile-specific erase/format. Cancel
may leave an incomplete or consumed medium and is never represented as rollback.

Data BD-ROM, BD-R, and BD-RE are the target. Audio-CD mastering, complex mixed
mode/multitrack work, movie-region management, AACS/BD+ circumvention, and
commercial DRM bypass are non-goals. Drive firmware is inspection metadata;
flashing is out of scope.

## Virtual optical device and host backends

The VMM presents a narrow MRML-specific experimental VirtIO optical protocol
unless an exact standard device proves sufficient. It supports bounded semantic
read, media/profile query, eject/load, write/burn, synchronization, events, and
structured errors—not arbitrary host SCSI passthrough. Any expert raw path has a
separate capability and restricted opcode policy and is never default.

The guest driver joins the same MMC service used by AHCI/ATAPI and USB. Windows
and Linux host backends may exclusively delegate one exact drive generation to
WHP or KVM. Delegation grants no sibling SATA/USB device, HBA control, host
filesystem, or host path. Revocation yields device removal; inserted/replaced
media increments generation. Host and guest cannot burn concurrently.

For firmware boot, the smallest maintainable bootstrap is preferred: expose a
standard firmware-visible ATAPI/SCSI optical device until MRML boots, then move
runtime operation to VirtIO. A custom OVMF fork is not assumed. No boot claim is
made until actual guest firmware reads the physical or synthetic optical path.

## Monitoring, recovery, and evidence

Resource accounting attributes image construction, read/burn buffers, I/O, CPU,
and service/domain ownership without exposing file content. Low-power policy may
defer background verification or spin down idle drives but cannot interrupt an
active burn. Monitoring reports supported drive/media state, activity, burn
progress/errors, delegation, and temperature only when measured. Security events
cover media insert/remove, burn start/completion/failure, erase, VM delegation,
and revocation.

Installer and offline recovery may read verified `.mrz` and `.mrp` content from
USB, optical, or virtual optical media through the same package architecture.
Recovery media creation/burn remains subject to exact capabilities and evidence.

Implementation order is: typed disk/image APIs; raw/sparse images; GPT/FAT32;
UDF writer; UDF reader/checker; ISO/El Torito; host optical read; MMC; AHCI/ATAPI;
USB optical; physical writer; synthetic VirtIO device and guest driver; Windows
and Linux real-drive backends; real-drive passthrough; GUI projection.

Synthetic tests do not prove physical hardware. UDF is not mature before bounds,
fuzzing, >4 GiB, Unicode, Windows/Linux/MRML interoperability, and physical media
evidence. Physical read/burn, BD-R/BD-RE, AHCI, USB, real-drive WHP/KVM, and boot
claims require exact recorded hardware, firmware, media, host, speed, and result.
Destructive fuzzing against user drives is forbidden.

Patent review: **TRIGGERED** for UDF/optical layout, MMC/burning, virtual optical
protocols, and deployment mechanisms. Standards and implementations require
targeted worldwide family/status and royalty-free-grant review before code is
introduced. See [the patent review log](../patents/REVIEW_LOG.md); no clearance
or infringement conclusion is stated.
