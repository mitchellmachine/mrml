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

`ExactNativeBlockCorrelationVerifier` is now **PARTIALLY IMPLEMENTED** as the
safe default for a driver that independently reconstructs the firmware-stable
route. It exact-matches stable ID and controller/media generations and prevents
an already-native AHCI/USB/VirtIO source from changing transport. UEFI may map
only into those supported native transports. This check and capability issuance
form the control plane; subsequent reads use the shortest safe existing block
data path under the exact issued session. Storage passes 127 tests on Windows
and Arch Linux. No native route parser, controller enumerator, or physical
device has been implemented or exercised by this increment.

The boot/native stable-ID algorithm is now **PARTIALLY IMPLEMENTED** as one
shared storage contract rather than duplicated firmware knowledge.
`canonical_uefi_block_stable_id` bounds and structurally validates one canonical
single-instance UEFI device path before applying the existing domain-separated
SHA3-256 digest; the UEFI library calls it directly. Truncation, malformed node
lengths, multiple instances, missing termination, and trailing bytes fail closed.
This enables a future native driver to compare
an independently reconstructed route using exactly the boot algorithm, but it
does not reconstruct that route or grant device authority. Storage passes 128
tests and UEFI 37 tests on Windows and Arch Linux; UEFI cross-builds on both.

The supported SATA route now has a **PARTIALLY IMPLEMENTED** typed extraction
design-around. `parse_canonical_uefi_sata_block_route` accepts only ACPI root,
one to eight valid PCI nodes, SATA target, optional valid hard-drive media node,
and end-entire. It retains the exact full-path stable digest and compares native
root/PCI/SATA/partition fields directly; native code need not reconstruct UEFI
binary path bytes. The typed route is data, not registration or I/O authority.
Storage passes 129 tests on Windows and Arch Linux; UEFI remains 37 tests and
cross-builds on both. Canonical typed handoff is described below; native AHCI
enumeration remains **PLANNED**.

The typed-handoff prerequisite is now **PARTIALLY IMPLEMENTED** as a canonical
128-byte kernel record. It binds the route version, ACPI root, one through eight
PCI hops, SATA target, optional partition identity, and exact stable ID while
requiring all reserved and unused bytes to be zero. The UEFI boundary translates
its retained route only when the full stable ID still equals the recovered block
descriptor. This authority-free record avoids native reconstruction of firmware
bytes. Kernel passes 563 tests and UEFI 37 tests on Windows and Arch Linux, with
UEFI cross-builds on both. Handoff carriage is described below; independently
enumerated native correlation remains **PLANNED**.

Canonical carriage of the typed route through `BootHandoff` is now **PARTIALLY
IMPLEMENTED**. A distinct presence flag places the fixed 128-byte route after
the installed identity and before SMP/MADT bytes. The adjacent identity must be
UEFI-sourced and carry the same exact stable ID; route-only input, substitution,
malformed length, and noncanonical route bytes fail closed before publication.
The real loader retains and emits both records before leaving firmware. Kernel
passes 563 tests and UEFI 37 tests on Windows and Arch Linux, UEFI cross-builds
on both, and WHP/KVM runners pass 11/12. Native enumeration and correlation
remain **PLANNED**; no AHCI, USB, VirtIO, OVMF, or physical-device evidence is
claimed.

The native side of this equality boundary is now **PARTIALLY IMPLEMENTED** as
`NativeSataBlockRoute` and `SataNativeBlockCorrelationVerifier`. A trusted
driver supplies bounded ACPI/PCI/SATA/optional-partition fields with no copied
stable ID or authority. The verifier exact-matches every field against the
handed route and separately requires the boot stable ID, AHCI transport,
controller/media generations, and geometry before existing atomic registration.
The first native AHCI discovery boundary is also **PARTIALLY IMPLEMENTED**: an
immutable PCI-enumerator snapshot must carry the exact mass-storage/SATA/AHCI
class tuple, a live nonzero configuration generation, a type-zero function, and
a bounded non-prefetchable 32-bit ABAR with valid power-of-two size and
alignment. Its result is identity and geometry, never mapping or I/O authority.
Storage passes 135 tests on Windows. Native PCI enumeration, ABAR mapping, AHCI
register/DMA/interrupt mechanics, reacquisition, Arch Linux parity, and physical
evidence remain **PLANNED**.

The first ABAR authority boundary is now **PARTIALLY IMPLEMENTED** without
claiming controller access. After the typed PCI snapshot validates the function
and BAR geometry, `map_ahci_abar` requires one live capability carrying
`MAP | READ | WRITE` for the expected device object, nonzero configuration and
mapping generations, and an aligned non-wrapping virtual range. Its backend
contract permits only a supervisor read/write, non-executable mapping of that
exact range and binds revocation to both generations. Missing rights, stale
handles, object substitution, malformed ranges, and backend refusal fail before
publication. Storage passes 138 tests on Windows and Arch Linux. No ABAR
register was accessed; HBA reset, port enumeration, DMA, interrupts, ATA/ATAPI,
NCQ, native PCI enumeration, and physical evidence remain **PLANNED**.

The global-register initialization gate is now **PARTIALLY IMPLEMENTED** for
the bounded Canadian software-driver scope. `NativeAhciRegisterIo` admits only
aligned volatile 32-bit accesses inside one already-authorized exact-generation
ABAR mapping. `reset_ahci_controller` disables global interrupts, enables AHCI
mode, requests the standard HBA reset, waits for a fixed maximum poll count,
reasserts AHCI mode with interrupts still disabled, and publishes a controller
snapshot only after validating version, capability-derived port/command-slot
bounds, and the implemented-port bitmap. Timeout, access uncertainty, malformed
mapping state, unavailable AHCI mode, invalid version, no ports, or a port bit
outside the advertised bound publishes nothing. Storage passes 143 tests on
Windows and Arch Linux for this global-register boundary.

The next port/signature boundary is **PARTIALLY IMPLEMENTED IN SOURCE** as a
read-only atomic scan. `discover_ahci_ports` requires the exact retained object,
configuration generation, and mapping generation; stabilizes the controller's
capability/version/implemented-port state before and after discovery; reads no
unimplemented port; and compares two complete bounded observations before
publishing indexed snapshots. Per-port interrupts, command/FIS engines, SATA
active bits, and command-issue bits must all be inactive. Link detection, speed,
power state, and SATA/ATAPI/enclosure-management/port-multiplier signatures are
classified; a stable unknown signature remains descriptive and cannot qualify
for installed recovery. Thirteen static hostile-model tests cover stale
mapping/controller state, offset bounds, unimplemented ports, read uncertainty,
state substitution, controller substitution, active engines/commands, malformed
link state, and unavailable signatures. The focused Windows gnullvm storage
suite passes 156 tests, including the thirteen tests for this boundary. Linux
execution was not available in this workspace, so no Linux pass count is
claimed for the increment. No physical HBA, link, DMA, interrupt delivery,
ATA/ATAPI command, NCQ, media, OVMF, or installed-device reacquisition evidence
is claimed.

Port base programming is now **PARTIALLY IMPLEMENTED IN SOURCE** without engine
activation. Exact mapping generations and a quiescent port are required before
writing all four 32-bit halves of the command-list and received-FIS physical
bases, followed by exact read-back. Preflight uncertainty returns the untouched
DMA owner. Once any write occurs, later write/read/substitution uncertainty
produces a quarantined owner that cannot use ordinary DMA removal. Storage
passes 166 tests on Windows and Arch Linux.
No command header/table content, PRDT, engine start, interrupt, ATA/ATAPI, NCQ,
IOMMU hardware, OVMF, or physical device was exercised.

The extracted AHCI provider now **PARTIALLY IMPLEMENTS** construction of one
non-NCQ ATA `READ DMA EXT` or `WRITE DMA EXT` command without issuing it. One
idle advertised slot receives a checked 48-bit LBA, nonzero exact 512-byte sector
count, at most 1 MiB contiguous data extent, five-DWORD host-to-device FIS, and
one PRDT entry. Device-read requires data-buffer `WRITE`; device-write requires
`READ`, with separate `PIN | MAP`. Control DMA overlap, stale/wrong authority,
dirty headers/tables, active/issued slots, overflow, and partial mutation fail
closed. Every written header/FIS/PRDT DWORD is read-verified; post-write
uncertainty quarantines the active layout. The AHCI library passes 55 tests on
Windows and Arch Linux. `CI` issue, completion/error handling, data verification,
interrupts, NCQ, hardware, and physical evidence remain **PLANNED**.

The command-memory gate is now **PARTIALLY IMPLEMENTED IN SOURCE**. The driver
checks every word in the exact command-list, received-FIS, and per-slot command-
table extents is zero before writing anything. It then gives every advertised
header its exact distinct 64-bit table base and read-verifies all values. A
dirty/unreadable preflight returns the untouched programmed owner; uncertainty
after a write quarantines the layout. Storage passes 169 tests on Windows and
Arch Linux. No PRDT,
data buffer, command issue, engine start, interrupt, ATA/ATAPI, NCQ, IOMMU
hardware, OVMF, or physical device was exercised.

The port-engine activation gate is now **PARTIALLY IMPLEMENTED IN SOURCE**.
Only the initialized command-memory typestate may enter it. The transition
exact-matches controller generations, requires an idle task file and no active
or issued command, keeps interrupts disabled, enables FIS receive before command
processing, and read-verifies each write. Failure before mutation returns the
owner; later uncertainty quarantines the layout. Storage passes 172 tests on
Windows and Arch Linux. No command is built or issued, and no PRDT, data transfer, interrupt,
engine stop/removal, ATA/ATAPI, NCQ, IOMMU hardware, OVMF, or physical device was
exercised.

The inverse engine-stop lifecycle is **PARTIALLY IMPLEMENTED IN SOURCE**. It
clears command processing before FIS receive and bounds both hardware-quiescence
waits to 1024 reads. Exact read-back is required, and all uncertainty retains a
quarantined DMA layout. Storage passes 174 tests on Windows and Arch Linux. Register-base clearing,
DMA sanitization/reclamation, command issue, and data transfer remain unimplemented.

The stopped-port reclamation gate is now **PARTIALLY IMPLEMENTED IN SOURCE**.
It exact-matches generations and quiescence, clears and verifies all DMA base
registers, then zeroes and verifies exactly the retained command-list,
received-FIS, and command-table extents. Only complete success recreates the
installed owner accepted by exact backend revocation; every failure quarantines
the layout. Storage passes 177 tests on Windows and Arch Linux. No command, transfer, interrupt,
IOMMU hardware, OVMF, or physical device was exercised.

The following DMA-memory ownership boundary is **PARTIALLY IMPLEMENTED IN
SOURCE**. One safe transaction binds a quiescent discovered SATA port and exact
controller generations to explicit controller `CONTROL` plus separate
`PIN | MAP | READ | WRITE` capabilities for command-list, received-FIS, and
command-table memory objects. It derives the table extent from the validated
controller slot count and rejects zero generations, wrong objects, missing
rights, malformed size/alignment, wrapping ranges, physical overlap, memory-
object aliasing, or backend refusal before publishing a layout. The backend
must atomically pin, verify zeroed state, and install exactly the complete
layout, leaving no device mapping on failure. The installed layout is retained
by a non-copyable owner. Exact teardown consumes it only after the backend
confirms removal and all required device/IOMMU invalidation; uncertainty returns
the same owner for retry, while completed removal cannot be replayed. Storage
passes 163 tests on Windows and Arch Linux. No port register is written and no
IOMMU, engine, interrupt, ATA/ATAPI, NCQ, block-I/O, OVMF, or physical evidence
is claimed.

The configuration service now **PARTIALLY IMPLEMENTS** an atomic
correlate/register/reacquire operation for this route. It admits the descriptor
only through the typed verifier, creates the existing principal-bound read-only
session, validates block zero and the selected root, and returns the installed
owner. Route mismatch leaves no registration or session and causes no block I/O;
later validation failure revokes the session and removes the new device before
return. Configuration passes 50 tests on Windows and Arch Linux; WHP/KVM
regression runners pass 11/12 without native SATA evidence. Real driver
discovery and installed-kernel consumption remain **PLANNED**.

Configuration now **PARTIALLY IMPLEMENTS** decoded-handoff-only recovery for
the pair. A recovery-only canonical encoder retains the adjacent identity and
typed route without unrelated service/SMP payloads. The consumer extracts both
from one validated `BootHandoff`; missing identity or route fails before
registration, session issuance, or block I/O, and detached replacement boot data
is not accepted. Kernel passes 563 tests and configuration 51 tests on Windows
and Arch Linux. Native descriptor discovery and installed Total consumption
remain **PLANNED**.

The recovered-system Total boundary now **PARTIALLY IMPLEMENTS** consumption of
that installed owner. Before release construction it rechecks the selection's
stable platform identity, controller/media generations, geometry, volume, and
root against the decoded handoff; a UEFI source also requires the adjacent SATA
route. Missing or substituted state cannot run the release builder. Successful
admission retains the exact live selection beside the sole release-derived
Total table through final proof. Configuration passes 51 tests on Windows and
Arch Linux; WHP/KVM 11/12 remain regression rather than native-storage evidence.

The `mrml` frontend may expose structured `disk`, `filesystem`, `optical`, and
`media` operations. The PowerShell-inspired shell projects the same backend as
typed `Get-*`, `Test-*`, `Initialize-*`, `New-*`, `Format-*`, `Write-*`, and
`Mount-*` operations; it never scrapes CLI text. GUI `Disks & Media`, installer,
recovery, accessibility, automation, and AI consume the same capability-scoped
objects, progress, diagnostics, and redaction.

The NVMe provider is **PARTIALLY IMPLEMENTED** at its first authority-free
discovery gate. It validates the PCI-SIG mass-storage/NVM/NVMe class tuple,
type-zero function identity, nonzero configuration generation, and a bounded,
aligned, non-prefetchable 64-bit controller BAR from an immutable platform-
enumerator snapshot. A separately authorized exact controller capability now
prepares a generation-bound, supervisor-only read/write NX mapping through a
backend that may reject without publication; missing, excess, stale, or
substituted authority and invalid ranges fail before the backend. A bounded
controller gate validates `CAP`/`VS`, checked queue, page, doorbell-stride, and
timeout limits, requires the NVM command set, clears `CC.EN`, and waits for
`CSTS.RDY` to clear with a fixed-delay bounded poll. Fatal state, timeout, and
register uncertainty publish no snapshot. The initial admin-queue ownership gate
then requires exact controller-control and separate pin/map/read/write memory
capabilities, a supported 4 KiB controller page, at least two queue entries, two
distinct aligned zero-verified pages, and one nonzero DMA generation. Installation
is atomic; revocation retains exclusive ownership until device and IOMMU removal
is confirmed. The queue-programming gate consumes that exclusive owner only
while `CC.EN` and `CSTS.RDY` are clear, writes and verifies bounded `AQA`, `ASQ`,
and `ACQ`, enables the baseline 64-byte submission/16-byte completion entry
sizes, and publishes active queues only after bounded ready polling. Any write,
readback, fatal-state, or timeout uncertainty quarantines the DMA layout. The
first admin-command path admits only Identify Controller: it exact-authorizes a
distinct zeroed 4 KiB DMA result page, writes and verifies all 16 command
dwords before the submission doorbell, bounds phase-tagged completion polling,
validates command ID, queue ID/head and status, and acknowledges the completion
head. Pre-mutation failures return the active queue owner; uncertainty after
mutation quarantines it; an explicit controller error advances and returns the
reusable queue with decoded status. Hostile Identify Controller data is now
parsed into fixed-capacity printable serial/model/firmware labels, exact
controller generations, bounded namespace count, checked/capped maximum
transfer size, and optional-command/cache feature facts. Labels and feature
bits remain non-authorizing data. Native PCI enumeration, concrete MMIO
installation, DMA/IOMMU revocation, interrupts, reset, service IPC,
runtime provider publication, and physical-device evidence remain
**PLANNED**. The same semantic command engine now admits one nonzero Identify
Namespace request without exposing raw admin authority. Its hostile result is
generation-bound to the controller identity and validates namespace ID/count,
size/capacity/utilization ordering, at most 16 baseline LBA formats, active
format, absence of unsupported metadata, 512-byte through 64-KiB logical blocks,
checked total size, transfer-block bounds, GUID/EUI labels, and thin-provisioning
facts before producing a non-authorizing namespace identity. The shared bounded
admin executor now also negotiates one through 64 I/O submission/completion
queues with the standard Number of Queues feature, exact controller-control
authority, verified command publication, and hostile result bounds; it rejects
zero, excess requests, excess grants, and authority substitution without
inventing queue availability. One negotiated queue-pair DMA gate now retains
the live admin queue owner while exact controller-control and separate
pin/map/read/write capabilities authorize two distinct zero-verified 4 KiB
pages. Queue ID must be nonzero and within both grants, depth is bounded to two
through 64 entries, admin/I/O regions may not overlap, and backend rejection
returns the complete grant for retry. Queue creation now consumes that owner,
creates and verifies the completion queue before its associated submission
queue, and publishes active cursors only after both commands complete. A
rejected completion queue removes the DMA layout; a rejected submission queue
first deletes the already-created completion queue and then removes DMA. Any
uncertain command, cleanup, or device/IOMMU removal quarantines both admin and
I/O layouts. Capability-bound PRP preparation now covers the block interface's
complete 512-byte through 1 MiB range: each data mapping is page-rounded and
exactly authorized for device-read versus device-write direction, device-write
buffers are zero-verified, one/two-page requests use direct PRPs, and larger
requests build and verify at most 255 entries in a distinct zeroed 4 KiB list.
Missing/excess lists, overlaps, stale or excessive rights, and malformed extents
fail before mutation; partial list mutation quarantines the request. The active
I/O queue now accepts only generation-bound namespace read, write, and flush
requests through exact namespace capabilities. Read/write ranges and transfer
geometry are checked against the parsed namespace identity and the 1 MiB
interface bound; PRPs must match the device transfer direction and may not
overlap queue memory. The provider writes and verifies every command dword,
rings queue-specific submission/completion doorbells, validates phase, command
ID, queue ID/head, and advances bounded cursors. Explicit device rejection
returns live cleanup ownership, while malformed or uncertain completion state
quarantines admin, I/O, and data ownership. Provider teardown now deletes the
submission queue
before its dependent completion queue, then releases the exact IOMMU/DMA layout
only after both device deletions complete. Any command rejection, uncertainty,
or DMA-removal failure retains both layouts as quarantined ownership. Active
admin-queue teardown now clears `CC.EN`, bounds readiness-clear polling, and
reconstructs the exclusive admin-DMA owner only after `CSTS.RDY` is zero.
Register uncertainty, fatal status, or timeout retains the exact layout for
quarantine. The exact supervisor-only BAR mapping can now be removed only after
the backend confirms mapping and TLB invalidation; failure returns the complete
generation-bound mapping for quarantine/retry. Full provider shutdown binds all
three generations before mutation, deletes the I/O submission and completion
queues, removes their DMA layout, disables the controller, removes the admin
DMA layout, and finally unmaps the BAR. An initial identity mismatch returns all
live owners untouched; any later failure reports the exact completed phase and
retains the remaining layouts as quarantined ownership. The NVMe library now
publishes caller-supplied namespace sessions and media generations through the
same canonical block-provider catalog as AHCI, without exposing admin-command
authority. Its isolated enumeration loop uses one transferred shared-memory
leaf, bounded local scratch, validated copy-back, release on every post-receive
path, reply-after-release ordering, and complete transient-buffer wiping. Its
concrete userspace adapter validates immutable reply bindings and emits exact
receive, shared-write, release, and send register frames. Sixty-seven focused
tests pass on Windows and Arch Linux. The class tuple
is cross-checked against the
[PCI-SIG DEVICE_INTERFACE_REPORT ECN](https://pcisig.com/PCIExpress/ECN/Base/AddClasstoDEVICE_INTERFACE_REPORT);
later register and queue work will use the current
[NVM Express specifications](https://nvmexpress.org/specifications/) as its
interoperability reference.

The opt-in classic IDE disk provider is **PARTIALLY IMPLEMENTED** at the same
authority-free discovery level. It validates an exact PCI mass-storage/IDE
function and configuration generation, rejects reserved programming-interface
bits, distinguishes compatibility and native primary/secondary channels, uses
the architectural fixed compatibility ports without trusting ignored BARs, and
validates native command/control and optional bus-master I/O BARs within the
x86 port space. An exact read/write port capability can now install one
generation-bound channel grant containing only its eight command ports, one
control port, and optional channel-specific eight-byte bus-master window.
Excess rights, substituted objects, invalid generations/ranges, overlaps, and
backend rejection fail before publication. Media generations, interrupts,
service IPC, runtime publication, and
physical-device evidence remain
**PLANNED**. The IDENTIFY gate now selects master/slave devices, performs four
alternate-status settling reads, clears the task-file address registers, issues
ATA IDENTIFY, and bounds busy polling to one second. It reads exactly 256 words
only after DRQ and parses printable fixed-capacity labels, LBA28/LBA48 capacity,
512-byte through 64-KiB power-of-two logical blocks, transfer bounds, DMA, and
flush facts into a generation-bound identity. Absent devices remain retryable;
timeouts, device faults, missing DRQ, and partial data transfers quarantine the
port grant. Eleven focused tests pass on Windows and Arch Linux.
The semantic PIO path now exact-authorizes device read, write, and flush
separately and exact-authorizes transfer buffers for only the CPU access
direction required. It validates identity generations, block ranges, LBA28/LBA48
addressability, exact buffer size, and the 1 MiB interface bound before port
mutation. It programs the conventional task file, bounds every per-block DRQ
transition and final completion, transfers exact logical-block word counts, and
quarantines port and buffer ownership after any partial or uncertain command.
Fourteen focused tests pass on Windows and Arch Linux.
Restart teardown now masks channel interrupts, asserts/deasserts ATA software
reset, performs four settling reads, and bounds the return to idle before the
exact port projection may be removed. Reset or removal uncertainty retains the
grant for quarantine/retry rather than making replacement authority available.
Seventeen focused tests pass on Windows and Arch Linux.
Bus-master DMA ownership now exact-authorizes separately pinned data and PRD
memory with direction-specific data rights and a nonzero DMA generation. It
supports the complete 1 MiB interface bound below the classic 32-bit DMA ceiling,
splits transfers at every 64-KiB boundary into at most 32 conventional PRDs,
zero-verifies the 4-KiB table, writes and verifies every entry and terminal bit,
and rejects overlap or substitution. Backend rejection is untouched; partial
PRD mutation and uncertain IOMMU removal retain quarantined ownership. Twenty
focused tests pass on Windows and Arch Linux.
Bus-master execution now exact-authorizes the selected device operation, binds
the identity and DMA generations to the same channel, verifies transfer size
and direction, stops the engine before programming, clears stale status, writes
and reads back the PRDT address, programs LBA28/LBA48 task files, and starts the
engine with the exact device-to-memory direction bit. Completion polling is
bounded, requires the interrupt indication, checks bus-master and ATA errors,
then stops and verifies the engine before returning live DMA cleanup ownership.
Any post-mutation error, missing interrupt, or timeout quarantines the channel
and DMA layout. The IDE library now publishes caller-supplied device sessions
and media generations through the canonical block-provider catalog without
granting raw port or DMA authority to the storage service. Twenty-four focused
tests pass on Windows and Arch Linux.

## Disk checking and images

## Dynamically serviced storage modules

Storage transport and filesystem implementations are dynamically resolved
library packages behind stable MRML interfaces rather than statically fused
policy code or path-searched DLL/SO plugins. `mrml-storage` remains the authority,
object, transaction, and policy service. An AHCI library provides
`org.mrml.interface.storage.block-provider`; a FAT32 library provides
`org.mrml.interface.storage.filesystem`. Both initially use the
`isolated-service` form so MMIO/DMA faults and hostile-filesystem parser faults
do not share the storage service address space. “Load into the service” means
bind an exact admitted provider endpoint into its module registry, not map
mutable code with ambient service authority.

NVMe and legacy IDE are additional isolated block-provider implementations,
not new storage authority models. They reuse the same block-provider interface,
module registry, package admission, generation replacement, and supervisor
boundary. The storage service explicitly declares `multiplicity = "many"` for
that dynamic interface; the workspace lock therefore records AHCI, NVMe, and
IDE as three distinct exact provider edges in canonical package order. NVMe and
IDE now publish the same generation-1 fingerprint and isolated-service form as
AHCI. Requirements without this explicit multiplicity remain exactly-one and
fail on ambiguity. PCI enumeration order never selects release membership or
grants device authority.

The generation-1 block-provider interface now **PARTIALLY IMPLEMENTS** its
canonical isolated-service transport at the enumeration gate. The call frame
binds the ABI magic and schema, exact interface fingerprint and generation,
operation number, and fixed request/response sizes. The transport routes through
one opaque endpoint generation and validates the borrowed catalog range before
IPC; response decoding rejects reserved bytes, unknown status values, and byte
counts beyond both the caller's output and the 64-KiB interface limit. The
canonical catalog header and fixed-size records carry only opaque session
generations, checked block geometry, explicit feature facts, and media
generations. Encoding validates every record and zeroes the exact output extent
before publication. The AHCI library implements enumeration over that catalog
without receiving storage-service authority. Four focused interface tests and
55 AHCI-library tests pass on Windows and Arch Linux. AHCI, NVMe, and IDE now
each implement this same enumeration contract independently. Provider-side
isolated IPC is now **PARTIALLY IMPLEMENTED** for AHCI and NVMe enumeration.
Each service loop accepts one exact transferred shared-memory leaf, rebuilds the catalog in
bounded local scratch, copies back only the validated response extent, releases
the leaf on success or failure, replies only after release, and wipes request,
token, scratch, and response buffers. The AHCI and NVMe concrete userspace adapters validate
immutable reply bindings and emits the exact receive, shared-write, release, and
send register frames. Malformed envelopes fail before copy-back.
The read
transport is now canonical: it binds exact endpoint and session generations,
LBA and nonzero sector count, one caller-bounded writable view, fixed framing,
reserved bytes, and operation-specific status. Responses must report a nonzero
byte count within both that view and the 1-MiB interface limit. Six focused
interface tests pass on Windows and Arch Linux; provider-side read adapters
remain **PLANNED**. Write framing independently binds the same identities and
geometry to an immutable borrowed input view, preserves `ReadOnly` as distinct
from permission/media/I/O failures, and bounds nonzero completion bytes to the
view and 1-MiB limit. Eight focused interface tests pass on both hosts;
provider-side write adapters remain **PLANNED**. Flush and reset now use separate
buffer-free calls through the exact endpoint: flush accepts only a nonzero
durability serial, while reset accepts only a nonzero successor generation and
preserves cleanup-incomplete failure separately. Cross-operation frames fail
closed. Ten focused interface tests pass on Windows and Arch Linux. Provider-side
control adapters remain **PLANNED**.

The NVMe/legacy-IDE expansion has the following architectural score. Work stays
sequential by provider and each parser/register/queue gate is independently
bounded and tested.

- Complexity impact: **HIGH**
- TCB impact: **NONE**
- New parser boundary: **YES**
- New authority model: **NO**
- New persistent state: **NO**
- External dependency: **NO**
- Failure isolated: **YES**
- Existing-object reuse: **HIGH**

The owner may select or replace an admitted compatible provider without vendor
preference or rebooting the kernel. PCI class, manifest identity, signatures,
and device names only identify candidates. Exact capabilities separately
authorize configuration access, MMIO or I/O ports, DMA, interrupts, controller,
namespace/media objects, and reset. Hostile configuration/register/queue data,
integer overflow, stale generations, DMA after revocation, and uncertain reset
all fail closed; uncertainty quarantines the provider and its device state.

Generation resolution validates the complete candidate graph before activation.
Updating a provider stages immutable package/interface bytes, drains new calls,
revokes the old provider's sessions, DMA, mappings, IPC, and derived handles,
destroys and erases its domain, launches and health-checks a fresh generation,
then atomically publishes a new binding. Existing handles become stale. Failure
leaves the module unavailable and never falls back to an incompatible provider.
The kernel and unrelated services continue running, so a compatible module or
storage-service update requires no reboot. Boot-bound recovery components may
remain static until the userspace resolver is available.

The generation-1 block-provider interface bounds enumeration records and 1 MiB
reads/writes and keeps read, write, flush, and reset distinct. The generation-1
filesystem interface separates probe, mount/unmount, lookup, read/write/create,
flush, check, and format. Opaque handles identify exact generations;
capabilities transferred by the runtime authorize access. Names, signatures,
PCI classes, and manifests do not authorize.

- Complexity impact: **MEDIUM**
- TCB impact: **NONE**
- New parser boundary: **YES**
- New authority model: **NO**
- New persistent state: **NO**
- External dependency: **NO**
- Failure isolated: **YES**
- Existing-object reuse: **HIGH**

The two schemas and generated safe types are **PARTIALLY IMPLEMENTED**. The block
interface passes ten focused tests and the filesystem interface's canonical probe
codec and exact-generation isolated transport pass three on Windows and Arch
Linux. The fixed-capacity module registry is also **PARTIALLY IMPLEMENTED**. It
binds stable module-slot control, interface inspection, provider control, and
endpoint signal authorities separately; exact-matches all generations; permits
three independently replaceable AHCI, NVMe, and IDE block-provider slots to
coexist; cleanup-gates
replacement; and publishes only after fresh launch and health-check. Cleanup
uncertainty quarantines only the affected slot, while failed launch leaves that
slot unavailable until explicit retry and never falls back. Storage passes
181 tests on Windows and Arch Linux before extraction. The AHCI mechanism is now
preserved in the separate `org.mrml.library.storage.ahci` package, which declares
the exact generation-1 block-provider interface and isolated-service placement;
the policy/storage crate no longer compiles AHCI modules. Windows and Arch Linux
each pass 55 AHCI-library tests. The storage service now passes 137 tests with a
hosted cleanup-gated FAT32 generation replacement that invalidates the old
endpoint, health-checks the candidate through canonical probe bytes, and leaves
the modeled kernel epoch unchanged. The AHCI library now has a canonical catalog
enumeration endpoint, capability-cleanup-gated service loop, and raw userspace
syscall adapter; installed supervisor execution remains **PLANNED**.

The FAT32 provider package is now **PARTIALLY IMPLEMENTED** as
`org.mrml.library.storage.fat32`. It advertises the exact generation-1 filesystem
interface as an isolated service, and `mrml-storage` requires that dynamic
binding separately from the block provider. Its initial read-only boot-sector
parser validates FAT32 geometry, checked extents/FAT capacity, root-cluster and
reserved-sector bounds, and volume identity. The provider also exact-binds the
declared FSInfo sector, validates all three signatures, accepts unknown free/
next hints, and bounds known hints to the parsed cluster domain; hints remain
data and never allocation authority. FAT-chain traversal validates active versus
mirrored selection, requires exact masked mirror agreement, bounds output to
caller-fixed capacity, and rejects cycles, free, reserved, bad, or out-of-domain
clusters. A fixed-capacity short-directory parser now validates 8.3 entries,
deleted records, attributes, output bounds, file sizes, and first-cluster domains
while failing closed on malformed records. Atomic fixed-capacity composition now
joins validated cluster extents and rejects any extent after an end marker. The
read-only LFN path bounds and validates ordinals, reserved fields, short-name
checksums, termination, UTF-16 structure, and cross-cluster sequences; decoded
names remain non-authorizing labels. Bounded read-only file ranges require an
exact validated chain, stage all requested bytes before publication, preserve
caller output on failure, and wipe temporary buffers. The FAT32 provider now
consumes the canonical probe bytes and distinguishes malformed calls from
unsupported media. Its authenticated receive/read/release/reply loop and concrete
register-level syscall adapter erase transient buffers on every path; the
`mrml-fat32-service.efi` entry sends a generation-bound ready message and then
serves calls until fail-stop or supervised replacement. Thirty-three tests pass
on Windows and Arch Linux, and the MRML-native release binary builds on Windows
as a 5,120-byte x86-64 PE32+ EFI application with entrypoint `0x1c60`. Storage
passes 137 tests on both hosts. This does not implement mount, lookup/open policy,
check/repair, format, writes, installed-kernel launch, or physical interoperability
evidence.

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
transport; neither duplicates Blu-ray policy. The optional isolated IDE/PATA
disk provider described above does not add IDE/ATAPI to the optical stack;
IDE/ATAPI optical, FireWire, general SCSI HBA, and other transports remain out
of scope.

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
