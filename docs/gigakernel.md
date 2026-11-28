# MRML Gigakernel design

The Gigakernel is the privileged core of MRML OS. It is designed to launch
ordinary applications and services only in admitted, supervised microVMs.
If isolation or a required resource is unavailable, the workload does not
start. There is no native fallback inside MRML OS. The Windows and Linux
host tools are separate programs, not an alternate execution mode.

## Hardware discovery and driver supervision

The hardware supervisor is a service, not part of the privileged kernel.
It consumes a complete, generation-tagged PCI inventory from a trusted
platform provider. For each xHCI controller it requests a separate driver
microVM, keyed by PCI segment, bus, device, function, and controller
incarnation. USB peripherals remain beneath their controller's driver;
drivers are not shared across controllers. A failed driver launch has no
native fallback. Removal or replacement stops routing and retires that
controller's VM before reusing its address. Unrelated controllers stay put.

An opt-in QEMU fixture enumerates two real emulated xHCI functions and
checks that each produces one distinct launch request. A second scan
retains both. It records requests and does not launch driver guests.
A separate admission adapter now matches each request against an
independently supplied controller binding and live control capability,
rejects descriptor or incarnation changes, and prepares only a distinct
Total MicroVM route in the existing kernel table. It grants no device
mapping and starts no guest. The QEMU test verifies both requests prepare
separate domains against a fixed test catalog. A separate hosted KVM lifecycle fixture uses synthetic controller
snapshots and the same admission adapter to run two distinct signed,
device-free diagnostic guests. It verifies that retiring one withdraws
its route without stopping the other, and that a failed constructor
publishes no running guest. This is not an xHCI driver guest or a combined
QEMU-to-KVM device test. Production inventory transport and
the platform adapter that binds each launch to independently admitted
controller, interrupt, and DMA capabilities are not wired yet. Inventory
data itself never grants those capabilities.

## Input driver services

Input decoding is split into five microVM-only service components: PS/2
keyboard, PS/2 mouse, USB keyboard, USB mouse, and USB tablet. A shared
i8042 broker must own the PS/2 ports and route keyboard and auxiliary
bytes separately. The broker's tested routing core separates command
replies from input, bounds work and queues, and quarantines an affected
stream after loss until the owner re-establishes its input boundary. It
contains no production port reads. The opt-in Linux QEMU test runs a
private emulator and verifies that its actual i8042 output reaches
only the corresponding keyboard or mouse decoder. Neither decoder
runs in a guest in that test. Each USB controller keeps its own driver microVM and
will route just the admitted HID interface reports to the input service.
Input services do not receive raw I/O ports, controller mappings, or DMA
access. This keeps a USB mouse and keyboard separate even if they share
one controller or are part of one composite device.

The PS/2 cores cover scan set 2 and standard three-byte mouse packets.
USB keyboard and mouse cover HID boot protocol; the tablet covers the
bounded QEMU-style absolute pointer profile, not pen pressure or touch.
The decoder cores have host test coverage. Live controller transports,
guest entry points, and routing into the Semantic Scene Graph are not yet
wired. Device reports cannot directly interact with a trusted prompt;
the existing [accessibility and authority rules](ACCESSIBILITY.md) apply.

## Boot display and compositor service

UEFI GOP mode selection stays in the loader: GOP is a firmware boot
protocol, not a runtime display service. After boot, the compositor
microVM renders into private memory. A trusted output owner must authorize
presentation separately; the guest receives no physical framebuffer
address, firmware interface, or raw device mapping. The compositor has no
direct native-paint entry point.

The signed hosted compositor probe already proves a private raster capture.
Hosted projection tests now take a captured frame from a live admitted
route and copy it into a bounded output, including different source and
output strides and RGB/BGR ordering. The copy preserves pixels outside
its rectangle and refuses retired routes, unauthorized or replaced outputs,
and incompatible geometry. Normal boot still does not launch a compositor
or present its frame on real hardware. See [the reported fixture scope](ISOLATION_PLACEMENT.md).

## How the Gigakernel compares

Gigakernel, named after Gigachad, is MRML's name for its experimental
virtualization-based kernel design. It shares the small privileged core and
capability principles of conventional small-core systems. The
[Hyperkernel research project](https://syslab.cs.washington.edu/papers/nelson-hyperkernel.pdf)
also used hardware virtualization, but focused on formal verification of a
bounded kernel interface. MRML's defining choice is mandatory microVM
placement for ordinary workloads. Whether this warrants a distinct kernel
classification remains open. The name makes no claim of priority, formal
verification, or production readiness.

## Isolation boundary

- The privileged core supplies launch, memory, communication, and resource
  enforcement. Policy, filesystems, and ordinary drivers belong in isolated
  services where the required mechanisms exist.
- Cross-VM links require explicit, scoped, revocable capabilities. An
  executable signature establishes provenance; it does not grant access to
  another guest, memory, or devices.
- Stop new work before retiring a guest or device lease. Verify that mappings
  and device access are withdrawn before reusing pages. Quarantine uncertain
  resources rather than returning them to the allocator.
- Firmware, the loader, the virtualization substrate, and the fixed recovery
  mechanisms are part of boot or recovery, not a second workload mode.

See [Architecture](ARCHITECTURE.md), [Security](SECURITY.md),
[Isolation placement](ISOLATION_PLACEMENT.md), and
[Application platform](APPLICATION_PLATFORM.md) for the normative design.

### Core to verify

Keep only the mechanisms that must enforce isolation in the normal
Gigakernel. Everything else should justify its place as either a bounded
boot/recovery component or a separately admitted microVM.

| Keep in the privileged core | Run outside it |
| --- | --- |
| Validate the authenticated handoff and bind the first supervisor to owner policy. | The authenticated loader handles firmware and release assembly. The supervisor service chooses what to run after bootstrap; the kernel checks the authority for each request. |
| Own CPU and guest entry/exit, physical frame ownership, second-stage mappings, IOMMU containment and interrupt delivery. | An inventory service interprets platform discovery, and individual driver microVMs own protocol and device policy. Hardware access is scoped to the assigned device. |
| Enforce capability derivation, bounded communication, scheduling and safe retirement. | Service management decides when to launch, restart or stop guests. Filesystems, network and firewall policy, input decoding, the compositor, accessibility and user interfaces stay in services. |

For eventual formal verification, start with the actual normal release
profile, not every source file in the kernel library. Record reachable
privileged code and dependencies by commit and build profile, including
assembly and unsafe Rust; executable section size is a trend, not a proof
or a complete trusted-code inventory. Specify and check frame ownership,
mapping and permission invariants, capability non-amplification, and safe
revocation at the small kernel interfaces. Track boot-chain, toolchain,
CPU and IOMMU assumptions separately. Moving code out is only a security
improvement if it loses ambient privilege and cannot bypass those
interfaces. This is a verification plan, not a verification claim.

## What has been verified

| Area | Evidence | Limit |
| --- | --- | --- |
| Boot and VMX | Authenticated QEMU/OVMF boot reaches the kernel. Chromebook diagnostics exercised VMX guest entry and the kernel PE entry probe. | Diagnostic guest entry is not a normal installed-system boot. |
| Hosted microVMs | Signed hosted fixtures exercise supervised launch, communication, and retirement. The storage read fixture uses a scoped shared page and checks withdrawal. | Check the [platform results](PLATFORM_TESTS.md) for exact backend and fixture coverage. |
| USB write in a guest | A signed guest updates the three expected bytes in a preallocated `PROBE.TXT` through emulated xHCI on USB 2 and USB 3. It flushes, reads back, and retires; the host checks the entire disk image. | This is an exact fixture, not a general FAT32 writer or a physical USB write. |
| Chromebook USB | A read-only EFI diagnostic measured 34 scratchpad pages at 4 KiB each and confirmed that firmware still owns the controller shared with the boot stick. Software-model tests exercise buffered startup, cleanup retry, and refusal when the handoff prerequisites change. | No firmware ownership transfer, physical DMA activation, or physical write was tested. |

The recorded x86-64 release baseline at `a9ca7377` had 35,133 virtual
bytes in the kernel PE's executable section, excluding the loader and
virtualization backends. This is a dated build measurement, not the size of
the trusted computing base. Remeasure when normal boot starts admitted
service microVMs.

## Current work

The kernel PE has a separate `normal_boot` build profile. It uses the same
bounded loader-handoff decoder as the bring-up builds, checks the release
boot policy on the bootstrap CPU, and then parks without launching anything.
It validates the memory map without materializing the unused region array
or constructing the bring-up context. It still rejects an installed UEFI
recovery identity without its matching route.
This profile rejects diagnostic features at compile time. The existing
default and opt-in probe builds are unchanged in purpose; they are not
alternate operating modes. Selecting `normal_boot` builds a kernel PE, not a
complete boot image or a working installed system. In the November 28, 2026
Windows-hosted x86-64 release build with release floor 1, removing the unused
context reduced executable bytes from 34,253 at `d14abc95` to 32,669. The
whole PE went from 46,592 to 44,032 bytes; writable data stayed at 8,192
virtual bytes. The next cut excluded the QEMU-only USB PCI and copied DXE
record decoders from normal boot, including its observation profile. Both
reject those handoff flags, while bring-up builds still understand them.
Normal boot still validates DMAR and MCFG when present and uses the same
release, supervisor-selection and recovery checks. The same release build
measured 31,197 executable bytes and a 42,496-byte PE after the cut;
writable data was unchanged. These are bootstrap sizes, not full-runtime
or trusted-code measurements.

The separate `normal_boot_observed` fixture uses the same policy entry and
emits fixed, non-authoritative QEMU trace records for invalid configuration,
policy rejection, or policy acceptance. The shipping profile has no such
trace output. `mrml usb test-normal-boot-policy OVMF_CODE OVMF_VARS QEMU`
uses a disposable MRML-signed image, records the exact kernel digest and
embedded release floor, and checks that unenrolled OVMF is rejected by the
kernel. The command does not enroll firmware keys or provision a TPM.

On 2026-11-28, a separate QEMU 11.1.3 q35/TCG experiment at `7816741e`
used SMM-protected OVMF 4 MiB Secure Boot firmware, private copies of its
variable store, and a disposable certificate to sign the EFI loader. The
inner MRML packages were unchanged. With enrolled OVMF, the unsigned loader
produced no MRML trace during the 18-second observation. The signed loader
reached the kernel's normal-boot policy in both controls:

| QEMU configuration | Final kernel trace record | What the run establishes |
| --- | --- | --- |
| Enrolled OVMF, signed loader, no TPM | `MRML:BOOT:POLICY:MEASUREMENT` (49 trace bytes) | The Secure Boot gate passed; the measurement gate did not. |
| Same signed image and enrollment, fresh emulated TPM 2.0 | `MRML:BOOT:POLICY:ROLLBACK` (46 trace bytes) | Secure Boot and the measurement gate passed; authenticated rollback state was absent. |

An empty emulated TPM is not an owner-provisioned release journal. A separate
offline provisioning test used `mrml-sign prepare-release-genesis-slot` to
encode the 200-byte slot for the counter value read from a fresh software
TPM. The counter was 1, so slot 1 was selected. The software TPM returned
the exact bytes under a PolicyPCR session and rejected a password-only read.
That offline test used the emulator's reset PCR state.

On 2026-11-28, an integrated fixture built from `e82c1c92` bound the
release journal to the SHA-256 PCR 7 measurements observed with the enrolled
OVMF firmware. It used the authenticated package loader, required Secure
Boot, TPM measurement, rollback protection, and a coherent manifest, and
supplied five separately signed boot artifacts and the matching build receipt.
On first boot, the TPM trace showed one NV slot write and one counter advance
from the provisioned sequence of 1. The Gigakernel emitted the exact
`MRML:BOOT:POLICY:ACCEPTED` record. A cold reboot of the same image with the
committed TPM state produced the identical 46-byte trace with no slot write
or counter increment. Removing `CUDA.SIGNED` from a copy and starting from
the provisioned state stopped in the loader after reading the journal and
did not write or advance it. That control produced no kernel policy record.

The fixture image's SHA-256 was
`774a532322a9d2684ea457dddc7eb950000f23d1abae7b7a1d39bf8fbb46a143`.
The VM image was the existing zstd probe PE; the CUDA bytes were inert fixture
data. Neither was executed. This establishes kernel policy acceptance and
journal persistence in QEMU only. The kernel still parks without launching a
supervisor. No physical firmware, TPM, USB drive, or service microVM was
exercised.

For the next launch boundary, `BootServiceImage` checks the retained service
envelope against the accepted release number, loader-recorded payload
measurement, and exact single-image PE32+ layout. It returns the checked PE
source, not the loader's legacy native page tables or a launch capability.
The observation profile reports this as a separate `MRML:BOOT:SERVICE:CHECKED`
record, or reports missing or rejected input, and continues to park. A fresh
signed QEMU fixture with the same four required policy gates produced
`MRML:BOOT:POLICY:ACCEPTED` followed by `MRML:BOOT:SERVICE:CHECKED`.
This checks the retained FAT32 service payload; it does not reauthenticate
the release signature, name a supervisor, or start a guest.

The envelope identity and bounds now have their own type, independent of
the loader's native image, stack and page-table addresses. The envelope
checker validates length, kind, release, measured digest and PE32+ source.
The legacy handoff still checks the source against its native layout
descriptor. The `package_boot_normal` loader profile instead emits a
version-3 handoff with an 80-byte envelope descriptor. It retains the
original signed file in a supervisor-only, read-only, non-executable
mapping, without allocating or mapping a native service image, stack or
page tables. This avoids the old one-slot stack and table allocations
(320 KiB) plus the materialized service image. The checked handoff
preserves recovery metadata independently and requires the envelope range
to be wholly reserved. It can carry the same owner-selected supervisor
record when the production policy gates pass. Legacy loader and probe
profiles keep their existing format. This is a boot handoff, not guest
entry or evidence of runtime service isolation.
The envelope-type refactor measured 30,541 executable bytes and a 41,984-byte
PE. Reading both the old and new formats during the transition adds code:
the version-3-capable Windows-hosted release measures 31,853 executable bytes
and a 43,520-byte PE, with 8,192 virtual bytes of writable data. This is
separate from the loader's avoided allocations.

The next boundary now has a tested owner selection record for exactly one
release manifest and one measured service image. Its fixed 152-byte format
starts with the supervisor role tag, followed by the little-endian release
number and two SHA3-512 digests. The record cannot authorize itself: the
caller must supply its SHA3-512 pin from independently authenticated owner
policy and the manifest identity from coherent release admission. A publisher
signature, build receipt, or generic service kind is not a substitute.

Once selected, the image can be staged from the checked PE bytes into a
separate, exact-size non-executable buffer. This stage returns a guest virtual
entry address and the PE region permission plan; it does not adopt loader
mappings, allocate guest frames, install EPT, or enter VMX. Hosted tests cover
missing owner selection, a different manifest or release, a different service
digest, invalid destination sizes, zeroed padding, and non-writable executable
pages.

An owner building and enrolling the UEFI loader can now opt in by setting
`MRML_BOOT_SUPERVISOR_PIN_HEX` to the 128 hexadecimal characters of the
selection record's SHA3-512 digest. The loader reconstructs the record from
the authenticated release and verified service; the boot volume cannot supply
the pin. This option requires Secure Boot and the coherent signed release and
TPM journal path. A malformed or mismatched pin stops boot before journal
publication. For this opt-in path, complete PCR 11 measurements, including the
owner selection, must succeed before the journal advances. Use a journal
authorization policy not invalidated by the PCR 11 extensions, such as the
PCR 7 fixture policy. Leaving the pin unset preserves the existing boot check
and does not select a supervisor.

In enrolled OVMF with a copy of the already-committed software TPM journal,
the matching loader reached `POLICY:ACCEPTED` and `SERVICE:CHECKED` after
seven PCR 11 extensions. The mismatched loader reached the selection check
but failed before any PCR 11 extension or kernel policy acceptance. Neither
cold boot issued a journal write or counter increment. This compares the
loader checks against the same existing signed artifacts; it does not test a
fresh journal transition, a physical TPM, or supervisor execution.

The loader now appends the measured selection to a bounded version-2 handoff.
Version 1 remains valid and carries no selection. Version 2 is rejected if
any production boot-evidence flag is absent, the retained service or release
does not match, or the trailer digest is inconsistent. The digest detects
corruption; it is not a second signature or an independent trust root. The
kernel relies on the authenticated loader, then checks the retained PE bytes
before accepting the selection for further work. The observation profile
distinguishes a checked and a missing selection. There is still no guest
allocation, mapping, entry, or native fallback.

Enrolled QEMU verified this handoff end to end at source commit
`0349376ed32be9da2ca0d26ec050a50b3fdf630e`. Two loaders signed by the same
disposable enrolled certificate used the same freshly signed release and
separate copies of its initial software TPM journal. The matching pin
produced `POLICY:ACCEPTED`, `SERVICE:CHECKED`, then `SUPERVISOR:CHECKED`.
Seven PCR 11 extensions preceded one journal write and one counter increment.
The unpinned control accepted the release and checked the same service, but
reported `SUPERVISOR:MISSING`; its six PCR 11 extensions did not include the
selection. The matching image then cold-booted with the committed journal:
the same 101-byte trace returned, with seven PCR 11 extensions and no journal
write or counter increment. Its image SHA-256 was
`cf34b28aedc378848aaa71af291bccc255d08b17be3e38b8918ab5d3c4c3fc52`.
This verifies selection and journal behavior, not execution: the selected
FAT32 PE was a fixture, and neither boot entered a service microVM.

The next guest-memory step now has a hosted-tested reservation and layout
builder. It consumes page-aligned free RAM from the boot allocator, rejects
the null page and out-of-width addresses, and keeps host-physical,
guest-physical, and PE virtual addresses separate. Only the PE headers
and sections appear in the proposed guest map: headers are read-only and
non-executable, code is not writable, and gaps are left unmapped. The PE
can be initialized through an exact-size non-executable view of the reserved
range. Normal boot does not yet provide that view or install these mappings,
so this is not EPT, guest allocation on hardware, or guest-entry evidence.

The supervisor reservation can now build a private, inactive four-level EPT
for the image. The builder accepts only fresh, zeroed tables outside the
image reservation and installs exact read-only, read/execute, or read/write
4 KiB leaves. Unmapped PE gaps remain absent. Hosted tests inspect the
actual table entries and reject reused, dirty, out-of-width, or exhausted
table storage. No VMCS receives this root. Guest linear page tables, stack,
concrete physical backing setup, and execution remain separate work.

The supervisor bootstrap can reserve distinct physical backing for a guarded
stack and guest page tables. Its inactive linear address space starts from an
empty guest CR3, maps only the PE regions and the writable, non-executable
stack, and leaves the guard unmapped. Hosted tests walk the resulting entries,
confirm that they point to guest physical addresses rather than host frames,
and verify that the stack and unused table pages are zeroed. The image-only
EPT is not yet combined with the table and stack backing, and no launch path
installs either hierarchy.

1. Connect authenticated recovery to the first admitted supervisor microVM
   on the normal boot path. Verify launch and clean retirement of one real
   service before moving supervision policy out of the kernel.
2. Qualify USB controller handoff with firmware I/O closed and DMA blocked
   across the transition. Verify scratchpad retirement and controller
   isolation before running a physical read or a single authorized write
   to a separate expendable test device.
3. Keep x86-64 the first bring-up target. ARM64 and macOS host support are
   planned; do not infer readiness from portable code or an emulator result.

See [UEFI and Chromebook evidence](platform/UEFI_BOOT_MANAGEMENT.md#read-only-xhci-inventory-before-native-bring-up),
[Storage and USB](storage/STORAGE_AND_OPTICAL.md), [Recovery](RECOVERY.md),
and the [roadmap](ROADMAP.md#current-priority) for implementation detail and
current gates.

## Historical evidence

The [full dated engineering ledger](https://github.com/mitchellmachine/mrml/blob/0d898ca0cb8efe215c23413d6928ed85232e6531/docs/GIGAKERNEL.md)
is preserved at the last revision before this rewrite. Use it for prior
probe commands, exact traces, and earlier measurements. A dated result is
evidence for its test configuration, not a claim about today's build.
