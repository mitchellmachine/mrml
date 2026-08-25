# MRML UEFI boot and Secure Boot administration

**Status: PLANNED.** Existing bounded UEFI loading, signed-container checks,
measured-boot plumbing, release/recovery journals, and owner-policy abstractions
retain their recorded status. No current claim is made for firmware NVRAM writes,
boot-entry creation, owner-key enrollment, compatibility-trust preservation,
dbx update, dual boot, or physical-firmware behavior.

## Typed firmware objects and authority

Firmware administration exposes typed `UefiVariable`, `UefiBootEntry`,
`UefiBootOrder`, `UefiBootNext`, `SecureBootDatabase`, `UefiBootTransaction`, and
`SecureBootTransaction` objects rather than requiring efivar blob parsing. A boot
entry carries numeric identity, description, active/attribute state, device,
partition, device path, file path, optional data, and generation. Description is
presentation, never security identity. `BootTarget` remains deployment intent;
the UEFI entry is resulting firmware state.

The PowerShell-inspired shell may conceptually get/create/set/remove entries,
get/set order, get/set/clear next boot, and inspect variables. Exact verbs are not
ABI. Rights remain separate: `UEFI_VARIABLE_READ`, `UEFI_BOOT_CREATE`,
`UEFI_BOOT_MODIFY`, `UEFI_BOOT_DELETE`, `UEFI_BOOT_ORDER_MODIFY`,
`UEFI_BOOT_NEXT_MODIFY`, `SECURE_BOOT_DATABASE_READ`, and
`SECURE_BOOT_DATABASE_MODIFY`. Inspection grants no mutation. Arbitrary/raw
authenticated-variable writes require a separate expert/system capability.

Returned objects are generational. Before mutation, the platform service re-reads
and exact-matches firmware identity/content/generation. Stale entry/order/next or
variable state fails without blind modification. A transaction follows construct
-> validate -> preview -> trusted exact authorization -> apply -> re-read ->
verify. `NVRAM_FULL`, `WRITE_PROTECTED`, `AUTHENTICATION_REQUIRED`,
`FIRMWARE_REJECTED`, `WRITE_UNCERTAIN`, and `ENTRY_NOT_PERSISTED` remain distinct
typed outcomes; successful `SetVariable` alone is not proof.

Conceptual object-shell use remains structured:

```text
Get-UefiBootEntry | Where Description == "MRML"
Set-UefiBootNext $windowsEntry
New-UefiBootEntry -Description "MRML Recovery" -BootTarget $recovery
```

## Installer, paths, and dual boot

After selecting/creating the ESP, writing and flushing the exact MRML loader, and
verifying its bytes/signature, installation creates its own `MRML` firmware entry,
then re-reads and verifies the expected partition/path before claiming success.
The installed x86-64 path is `\EFI\MRML\BOOTX64.EFI`; future architectures select
their corresponding EFI executable through `BootTarget`, not x86 hard-coding.

Unrelated entries and EFI directories are preserved. In particular, a detected
Windows Boot Manager remains an independent firmware entry and Windows stays
directly bootable without the MRML loader. Structured detection reports its entry,
EFI path/ESP, Secure Boot state, trust configuration, and preservation
compatibility where safely knowable. Automatic layout preserves Windows
partitions; any deletion/resizing is explicit in the exact destructive preview.

Putting MRML first in `BootOrder` is owner policy. Preview shows current and
proposed complete order and permits retaining the existing default. `BootNext`
is separately controlled for one-time recovery, candidate, Windows, or test boot
and never implies permanent order change. A boot transaction can create MRML,
preserve Windows, propose order, and leave fallback state unchanged.

The conventional fallback `\EFI\BOOT\BOOTX64.EFI` may be installed only under
policy that proves ownership/non-conflict and previews backup/recovery or exact
replacement. A shared ESP's existing fallback is never casually overwritten.
Normal MRML installation stays under `\EFI\MRML\`.

## Owner Secure Boot and compatibility policy

The typed shell/platform service may inspect state, keys/databases, create/import
owner keys, export recovery material, add/remove trust, test/apply policy, update
revocations, and sign/test EFI images. Private keys are `SecretObject`s: ordinary
operations receive `SIGN`/`USE`, not `EXPORT`, and raw key bytes do not enter the
shell or normal GUI. Explicit encrypted recovery export requires separate export
authority and never places plaintext private keys on the ESP.

User-facing policy modes are conceptually:

- **Recommended / MRML + Windows compatibility:** owner MRML trust, supported
  Windows boot, Microsoft UEFI/Option ROM compatibility, and accepted revocations;
- **MRML only:** owner MRML OS trust without required Windows boot trust, while
  retaining Option ROM and other detected platform compatibility trust;
- **Preserve existing:** retain firmware databases and safely add MRML trust;
- **Expert custom:** exact anchors with strong validation, warning, and recovery.

Microsoft Windows boot, general UEFI compatibility, Option ROM UEFI compatibility,
and revocation sets are separate, authenticated, versioned policy data with
source, generation, digest, and accepted state. Literal certificate names are not
architecture. Compatibility keys authorize applicable EFI images at firmware
only; they grant Microsoft no MRML package, capability, owner-root, or generation
authority. MRML normally boots through owner/project signing, not Microsoft.

> Normal MRML Secure Boot enrollment must preserve or install the current
> supported Microsoft Option ROM UEFI trust required for platform hardware
> compatibility.

Removing Windows boot trust is not removing hardware initialization trust.
Complete Option ROM trust removal is Expert Custom only: preview the exact anchor,
warn that GPU/storage/network/Thunderbolt/PCIe initialization may fail, report
detected dependencies without claiming completeness, require trusted owner
authorization/physical presence as policy demands, and preserve a recovery path.

A Secure Boot transaction previews current/proposed/removed PK, KEK, db, dbx,
owner/MRML and compatibility anchors, and revocation generations. It exact-binds
authorization, applies, then re-reads and verifies every database. Normal policy
keeps current accepted dbx revocations; dual boot never means trusting revoked
components. Authenticated Microsoft revocation updates arrive through platform-
security/system-update policy with rollback/freeze resistance. Rolling back a
`SystemGeneration` does not silently downgrade firmware trust/revocation state.

The eventual Boot & Platform Security GUI uses the same objects to show Secure
Boot/owner trust, key fingerprints/purpose/role/status, compatibility and Option
ROM status, dbx, entries, order/next, and loader slots. It never displays private
key bytes. Secure attention, owner authentication, and physical presence apply to
high-risk actions; application-rendered prompts are not trusted consent.

## Audit, recovery, and evidence

Bounded audits record entry create/delete, order/next change, trust add/remove,
dbx update, and owner-key change by identities/digests, never secrets. Recovery
can repair typed boot state and owner policy only with narrow capabilities.

OVMF tests cover create/read/delete, Windows preservation, order/next, stale
denial, full/rejected/uncertain NVRAM, duplicate descriptions, corrupt variables,
and interruption. Secure Boot tests cover owner enrollment, MRML signature,
Windows independence, compatibility/Option ROM presence, dbx update, invalid/
revoked denial, rollback, partial write, and key recovery. Fuzz bounded LoadOption,
device-path, variable, certificate-list, and transaction codecs.

OVMF/QEMU is not physical proof. Reliable support records exact motherboard and
firmware results. Hardware-safe enrollment additionally proves GPU display,
NVMe/storage, relevant network and other boot-critical Option ROM devices still
initialize. The installer acceptance gate verifies loader bytes, creates/re-reads
the entry, preserves synthetic Windows, and reboots via it in a VM; then a
separate physical gate proves Secure Boot, compatibility, revocation, Windows,
devices, and recovery.

Patent review: `TRIGGERED` — typed firmware transactions, A/B/deployment binding,
trust-set composition, rollback handling, and Secure Boot management require
mechanism-specific worldwide review before implementation. See
[`../patents/REVIEW_LOG.md`](../patents/REVIEW_LOG.md).
