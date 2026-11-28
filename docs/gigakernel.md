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
bounded loader-handoff validation as the bring-up builds, checks the release
boot policy on the bootstrap CPU, and then parks without launching anything.
This profile rejects diagnostic features at compile time. The existing
default and opt-in probe builds are unchanged in purpose; they are not
alternate operating modes. Selecting `normal_boot` builds a kernel PE, not a
complete boot image or a working installed system. In the Windows-hosted
x86-64 release build, the PE's executable section was 26,765 virtual bytes
and its writable data section was 8,192 virtual bytes. The diagnostic build
still owns its secondary-CPU descriptor arena. These are section sizes for
this bootstrap, not a full-runtime or trusted-code-base measurement.

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
That test used the emulator's reset PCR state, not a firmware-measured
production policy. The next integrated fixture must bind the journal to the
expected firmware measurements and boot a matching coherent release. Policy
acceptance and actual supervisor guest entry remain separate checkpoints.
No physical firmware, TPM, USB drive, or service microVM was exercised.

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
