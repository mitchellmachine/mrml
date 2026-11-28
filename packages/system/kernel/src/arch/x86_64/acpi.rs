const RSDP_V1_BYTES: usize = 20;
const RSDP_V2_BYTES: usize = 36;
const SDT_HEADER_BYTES: usize = 36;
const MAX_RSDP_BYTES: usize = 4 * 1024;
const MAX_SDT_BYTES: usize = 1024 * 1024;
const MAX_PHYSICAL_EXCLUSIVE: u64 = 1u64 << 52;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcpiError {
    InvalidAddress,
    ReadFailed,
    BadRsdpSignature,
    UnsupportedRevision,
    InvalidLength,
    BadChecksum,
    WrongRootSignature,
    MissingRoot,
    MalformedRoot,
    MissingMadt,
    DuplicateMadt,
    MadtTooLarge,
    MissingDmar,
    DuplicateDmar,
    DmarTooLarge,
    MissingFadt,
    DuplicateFadt,
    FadtTooLarge,
    MissingMcfg,
    DuplicateMcfg,
    McfgTooLarge,
    MissingQ35FixtureMarker,
    DuplicateQ35FixtureMarker,
    InvalidQ35FixtureMarker,
}

/// Read-only access to firmware-owned physical bytes. Implementations must
/// either fill the complete output slice or return `false` without exposing a
/// partial read to the caller.
pub trait AcpiMemory {
    fn read_exact(&mut self, physical: u64, output: &mut [u8]) -> bool;
}

/// Finds and copies the unique MADT reachable from a validated RSDP. Every
/// firmware structure is checksummed before its contents are trusted. The
/// caller owns the bounded destination and can revoke firmware mappings after
/// this function returns.
pub fn copy_madt<M: AcpiMemory>(
    memory: &mut M,
    rsdp_physical: u64,
    output: &mut [u8],
) -> Result<usize, AcpiError> {
    copy_unique_sdt(
        memory,
        rsdp_physical,
        output,
        *b"APIC",
        AcpiError::MissingMadt,
        AcpiError::DuplicateMadt,
        AcpiError::MadtTooLarge,
    )
}

/// Finds and copies the unique DMA Remapping Reporting table reachable from a
/// validated RSDP. No firmware mapping needs to remain trusted after return.
pub fn copy_dmar<M: AcpiMemory>(
    memory: &mut M,
    rsdp_physical: u64,
    output: &mut [u8],
) -> Result<usize, AcpiError> {
    copy_unique_sdt(
        memory,
        rsdp_physical,
        output,
        *b"DMAR",
        AcpiError::MissingDmar,
        AcpiError::DuplicateDmar,
        AcpiError::DmarTooLarge,
    )
}

/// Finds and copies the unique PCI Express MCFG reachable from a validated
/// RSDP into caller-owned bounded memory.
pub fn copy_mcfg<M: AcpiMemory>(
    memory: &mut M,
    rsdp_physical: u64,
    output: &mut [u8],
) -> Result<usize, AcpiError> {
    copy_unique_sdt(
        memory,
        rsdp_physical,
        output,
        *b"MCFG",
        AcpiError::MissingMcfg,
        AcpiError::DuplicateMcfg,
        AcpiError::McfgTooLarge,
    )
}

/// A firmware inventory observation, not proof of a working keyboard,
/// exclusive port ownership, or authority to touch the controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum I8042Inventory {
    Advertised,
    NotAdvertised,
}

/// Inspect the unique, checksummed FADT reachable from the firmware root.
/// Legacy FADTs without a boot-architecture field fail closed.
pub fn i8042_inventory<M: AcpiMemory>(
    memory: &mut M,
    rsdp_physical: u64,
) -> Result<I8042Inventory, AcpiError> {
    let mut fadt = [0; 512];
    let len = copy_unique_sdt(
        memory,
        rsdp_physical,
        &mut fadt,
        *b"FACP",
        AcpiError::MissingFadt,
        AcpiError::DuplicateFadt,
        AcpiError::FadtTooLarge,
    )?;
    if fadt[8] < 3 {
        return Err(AcpiError::UnsupportedRevision);
    }
    if len < 116 {
        return Err(AcpiError::InvalidLength);
    }
    // ACPI §5.2.9: IAPC_BOOT_ARCH is at 109, bit 1 denotes 8042.
    // Do not qualify a legacy I/O path on hardware-reduced firmware.
    let hardware_reduced = read_u32(&fadt, 112) & (1 << 20) != 0;
    let flag = u16::from_le_bytes([fadt[109], fadt[110]]) & 2 != 0;
    Ok(if flag && !hardware_reduced {
        I8042Inventory::Advertised
    } else {
        I8042Inventory::NotAdvertised
    })
}

/// Test-only transport observation; this table is not platform MMIO authority.
pub fn q35_fixture_marker<M: AcpiMemory>(
    memory: &mut M,
    rsdp_physical: u64,
) -> Result<[u8; SDT_HEADER_BYTES], AcpiError> {
    let mut marker = [0; SDT_HEADER_BYTES];
    if copy_unique_sdt(
        memory,
        rsdp_physical,
        &mut marker,
        *b"MQ35",
        AcpiError::MissingQ35FixtureMarker,
        AcpiError::DuplicateQ35FixtureMarker,
        AcpiError::InvalidQ35FixtureMarker,
    )? != SDT_HEADER_BYTES
        || marker[8] != 1
        || &marker[10..32] != b"MRMLQ3MMIOTEST\x01\x00\x00\x00MRML"
        || !matches!(marker[32], 1..=4 | 8 | 9)
        || marker[33..] != [0; 3]
    {
        return Err(AcpiError::InvalidQ35FixtureMarker);
    }
    Ok(marker)
}

fn copy_unique_sdt<M: AcpiMemory>(
    memory: &mut M,
    rsdp_physical: u64,
    output: &mut [u8],
    wanted_signature: [u8; 4],
    missing: AcpiError,
    duplicate: AcpiError,
    too_large: AcpiError,
) -> Result<usize, AcpiError> {
    let mut rsdp = [0u8; RSDP_V2_BYTES];
    read(memory, rsdp_physical, &mut rsdp[..RSDP_V1_BYTES])?;
    if &rsdp[..8] != b"RSD PTR " {
        return Err(AcpiError::BadRsdpSignature);
    }
    if checksum(&rsdp[..RSDP_V1_BYTES]) != 0 {
        return Err(AcpiError::BadChecksum);
    }

    let revision = rsdp[15];
    let (root, entry_bytes, signature) = if revision == 0 {
        (u64::from(read_u32(&rsdp, 16)), 4usize, *b"RSDT")
    } else if revision >= 2 {
        read(
            memory,
            rsdp_physical + RSDP_V1_BYTES as u64,
            &mut rsdp[20..],
        )?;
        let length = read_u32(&rsdp, 20) as usize;
        if !(RSDP_V2_BYTES..=MAX_RSDP_BYTES).contains(&length) {
            return Err(AcpiError::InvalidLength);
        }
        if physical_checksum(memory, rsdp_physical, length)? != 0 {
            return Err(AcpiError::BadChecksum);
        }
        let xsdt = read_u64(&rsdp, 24);
        if xsdt != 0 {
            (xsdt, 8usize, *b"XSDT")
        } else {
            (u64::from(read_u32(&rsdp, 16)), 4usize, *b"RSDT")
        }
    } else {
        return Err(AcpiError::UnsupportedRevision);
    };
    if root == 0 {
        return Err(AcpiError::MissingRoot);
    }

    let root_length = validated_sdt(memory, root, signature)?;
    let payload = root_length - SDT_HEADER_BYTES;
    if !payload.is_multiple_of(entry_bytes) {
        return Err(AcpiError::MalformedRoot);
    }

    let mut found = None;
    let mut pointer = [0u8; 8];
    for index in 0..payload / entry_bytes {
        let offset = SDT_HEADER_BYTES
            .checked_add(
                index
                    .checked_mul(entry_bytes)
                    .ok_or(AcpiError::InvalidLength)?,
            )
            .ok_or(AcpiError::InvalidLength)?;
        read(memory, root + offset as u64, &mut pointer[..entry_bytes])?;
        let table = if entry_bytes == 8 {
            read_u64(&pointer, 0)
        } else {
            u64::from(read_u32(&pointer, 0))
        };
        if table == 0 {
            return Err(AcpiError::InvalidAddress);
        }
        let mut header = [0u8; SDT_HEADER_BYTES];
        read(memory, table, &mut header)?;
        if header[..4] != wanted_signature {
            continue;
        }
        if found.is_some() {
            return Err(duplicate);
        }
        let length = validated_header_and_checksum(memory, table, &header)?;
        if length > output.len() {
            return Err(too_large);
        }
        read(memory, table, &mut output[..length])?;
        if output[..4] != wanted_signature
            || read_u32(output, 4) as usize != length
            || checksum(&output[..length]) != 0
        {
            return Err(AcpiError::BadChecksum);
        }
        found = Some(length);
    }
    // Detect ordinary concurrent firmware mutation of the root during the
    // walk. The copied MADT is independently revalidated above and is the only
    // table retained after this point.
    if physical_checksum(memory, root, root_length)? != 0 {
        return Err(AcpiError::BadChecksum);
    }
    found.ok_or(missing)
}

fn validated_sdt<M: AcpiMemory>(
    memory: &mut M,
    physical: u64,
    signature: [u8; 4],
) -> Result<usize, AcpiError> {
    let mut header = [0u8; SDT_HEADER_BYTES];
    read(memory, physical, &mut header)?;
    if header[..4] != signature {
        return Err(AcpiError::WrongRootSignature);
    }
    validated_header_and_checksum(memory, physical, &header)
}

fn validated_header_and_checksum<M: AcpiMemory>(
    memory: &mut M,
    physical: u64,
    header: &[u8; SDT_HEADER_BYTES],
) -> Result<usize, AcpiError> {
    let length = read_u32(header, 4) as usize;
    if !(SDT_HEADER_BYTES..=MAX_SDT_BYTES).contains(&length) {
        return Err(AcpiError::InvalidLength);
    }
    checked_range(physical, length)?;
    if physical_checksum(memory, physical, length)? != 0 {
        return Err(AcpiError::BadChecksum);
    }
    Ok(length)
}

fn physical_checksum<M: AcpiMemory>(
    memory: &mut M,
    physical: u64,
    length: usize,
) -> Result<u8, AcpiError> {
    checked_range(physical, length)?;
    let mut block = [0u8; 64];
    let mut sum = 0u8;
    let mut offset = 0usize;
    while offset < length {
        let take = core::cmp::min(block.len(), length - offset);
        read(memory, physical + offset as u64, &mut block[..take])?;
        for byte in &block[..take] {
            sum = sum.wrapping_add(*byte);
        }
        offset += take;
    }
    Ok(sum)
}

fn read<M: AcpiMemory>(memory: &mut M, physical: u64, output: &mut [u8]) -> Result<(), AcpiError> {
    checked_range(physical, output.len())?;
    if memory.read_exact(physical, output) {
        Ok(())
    } else {
        Err(AcpiError::ReadFailed)
    }
}

fn checked_range(physical: u64, length: usize) -> Result<(), AcpiError> {
    let end = physical
        .checked_add(length as u64)
        .ok_or(AcpiError::InvalidAddress)?;
    if physical == 0 || end > MAX_PHYSICAL_EXCLUSIVE {
        return Err(AcpiError::InvalidAddress);
    }
    Ok(())
}

fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Memory([u8; 4096]);

    impl AcpiMemory for Memory {
        fn read_exact(&mut self, physical: u64, output: &mut [u8]) -> bool {
            let Ok(start) = usize::try_from(physical) else {
                return false;
            };
            let Some(end) = start.checked_add(output.len()) else {
                return false;
            };
            let Some(source) = self.0.get(start..end) else {
                return false;
            };
            output.copy_from_slice(source);
            true
        }
    }

    fn finalize(bytes: &mut [u8], checksum_offset: usize) {
        bytes[checksum_offset] = 0;
        bytes[checksum_offset] = 0u8.wrapping_sub(checksum(bytes));
    }

    fn memory() -> Memory {
        let mut memory = Memory([0; 4096]);
        let rsdp = &mut memory.0[0x100..0x124];
        rsdp[..8].copy_from_slice(b"RSD PTR ");
        rsdp[15] = 2;
        rsdp[20..24].copy_from_slice(&36u32.to_le_bytes());
        rsdp[24..32].copy_from_slice(&0x200u64.to_le_bytes());
        finalize(&mut rsdp[..20], 8);
        finalize(rsdp, 32);

        let xsdt = &mut memory.0[0x200..0x22c];
        xsdt[..4].copy_from_slice(b"XSDT");
        xsdt[4..8].copy_from_slice(&44u32.to_le_bytes());
        xsdt[36..44].copy_from_slice(&0x300u64.to_le_bytes());
        finalize(xsdt, 9);

        let madt = &mut memory.0[0x300..0x334];
        madt[..4].copy_from_slice(b"APIC");
        madt[4..8].copy_from_slice(&52u32.to_le_bytes());
        madt[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
        madt[44..52].copy_from_slice(&[0, 8, 0, 1, 1, 0, 0, 0]);
        finalize(madt, 9);
        memory
    }

    fn with_fadt(revision: u8, declared: usize, flags: u16, reduced: bool) -> Memory {
        let mut image = memory();
        image.0[0x204..0x208].copy_from_slice(&52u32.to_le_bytes());
        image.0[0x22c..0x234].copy_from_slice(&0x380u64.to_le_bytes());
        finalize(&mut image.0[0x200..0x234], 9);
        let fadt = &mut image.0[0x380..0x380 + 512];
        fadt[..4].copy_from_slice(b"FACP");
        fadt[4..8].copy_from_slice(&(declared as u32).to_le_bytes());
        fadt[8] = revision;
        fadt[109..111].copy_from_slice(&flags.to_le_bytes());
        fadt[112..116].copy_from_slice(&(u32::from(reduced) << 20).to_le_bytes());
        finalize(&mut fadt[..declared], 9);
        image
    }

    #[test]
    fn i8042_requires_explicit_non_reduced_firmware_advertisement() {
        for (flags, reduced, result) in [
            (0, false, I8042Inventory::NotAdvertised),
            (1, false, I8042Inventory::NotAdvertised),
            (2, false, I8042Inventory::Advertised),
            (2, true, I8042Inventory::NotAdvertised),
        ] {
            assert_eq!(
                i8042_inventory(&mut with_fadt(6, 276, flags, reduced), 0x100),
                Ok(result)
            );
        }
    }

    #[test]
    fn i8042_rejects_missing_old_short_corrupt_and_duplicate_fadt() {
        assert_eq!(
            i8042_inventory(&mut memory(), 0x100),
            Err(AcpiError::MissingFadt)
        );
        assert_eq!(
            i8042_inventory(&mut with_fadt(1, 116, 2, false), 0x100),
            Err(AcpiError::UnsupportedRevision)
        );
        assert_eq!(
            i8042_inventory(&mut with_fadt(6, 110, 2, false), 0x100),
            Err(AcpiError::InvalidLength)
        );
        let mut corrupt = with_fadt(6, 276, 2, false);
        corrupt.0[0x380 + 109] ^= 2;
        assert_eq!(
            i8042_inventory(&mut corrupt, 0x100),
            Err(AcpiError::BadChecksum)
        );
        let mut duplicate = with_fadt(6, 276, 2, false);
        duplicate.0[0x224..0x22c].copy_from_slice(&0x380u64.to_le_bytes());
        finalize(&mut duplicate.0[0x200..0x234], 9);
        assert_eq!(
            i8042_inventory(&mut duplicate, 0x100),
            Err(AcpiError::DuplicateFadt)
        );
    }

    #[test]
    fn copies_unique_madt_through_checked_xsdt() {
        let mut memory = memory();
        let mut output = [0u8; 64];
        assert_eq!(copy_madt(&mut memory, 0x100, &mut output), Ok(52));
        assert_eq!(&output[..4], b"APIC");
        assert_eq!(
            super::super::X86CpuTopology::parse_madt(&output[..52])
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn rejects_corrupt_root_and_undersized_destination() {
        let mut corrupt = memory();
        corrupt.0[0x210] ^= 1;
        assert_eq!(
            copy_madt(&mut corrupt, 0x100, &mut [0; 64]),
            Err(AcpiError::BadChecksum)
        );
        assert_eq!(
            copy_madt(&mut memory(), 0x100, &mut [0; 51]),
            Err(AcpiError::MadtTooLarge)
        );
    }

    #[test]
    fn rejects_duplicate_madt_and_bad_rsdp() {
        let mut duplicate = memory();
        duplicate.0[0x204..0x208].copy_from_slice(&52u32.to_le_bytes());
        duplicate.0[0x22c..0x234].copy_from_slice(&0x300u64.to_le_bytes());
        finalize(&mut duplicate.0[0x200..0x234], 9);
        assert_eq!(
            copy_madt(&mut duplicate, 0x100, &mut [0; 64]),
            Err(AcpiError::DuplicateMadt)
        );
        let mut bad_rsdp = memory();
        bad_rsdp.0[0x100] = b'X';
        assert_eq!(
            copy_madt(&mut bad_rsdp, 0x100, &mut [0; 64]),
            Err(AcpiError::BadRsdpSignature)
        );
    }

    #[test]
    fn copies_unique_dmar_through_the_same_validated_root() {
        let mut memory = memory();
        memory.0[0x200 + 4..0x200 + 8].copy_from_slice(&52u32.to_le_bytes());
        memory.0[0x22c..0x234].copy_from_slice(&0x380u64.to_le_bytes());
        finalize(&mut memory.0[0x200..0x234], 9);
        let dmar = &mut memory.0[0x380..0x3b0];
        dmar[..4].copy_from_slice(b"DMAR");
        dmar[4..8].copy_from_slice(&48u32.to_le_bytes());
        dmar[36] = 47;
        finalize(dmar, 9);
        let mut output = [0u8; 64];
        assert_eq!(copy_dmar(&mut memory, 0x100, &mut output), Ok(48));
        assert_eq!(&output[..4], b"DMAR");
    }

    #[test]
    fn copies_unique_mcfg_through_the_same_validated_root() {
        let mut memory = memory();
        memory.0[0x200 + 4..0x200 + 8].copy_from_slice(&52u32.to_le_bytes());
        memory.0[0x22c..0x234].copy_from_slice(&0x400u64.to_le_bytes());
        finalize(&mut memory.0[0x200..0x234], 9);
        let mcfg = &mut memory.0[0x400..0x43c];
        mcfg[..4].copy_from_slice(b"MCFG");
        mcfg[4..8].copy_from_slice(&60u32.to_le_bytes());
        mcfg[44..52].copy_from_slice(&0xe000_0000u64.to_le_bytes());
        mcfg[54] = 0;
        mcfg[55] = 0;
        finalize(mcfg, 9);
        let mut output = [0u8; 64];
        assert_eq!(copy_mcfg(&mut memory, 0x100, &mut output), Ok(60));
        assert_eq!(&output[..4], b"MCFG");
    }

    #[test]
    fn fixture_marker_is_unique_exact_and_checksummed() {
        let mut memory = memory();
        assert_eq!(
            q35_fixture_marker(&mut memory, 0x100),
            Err(AcpiError::MissingQ35FixtureMarker)
        );
        memory.0[0x204..0x208].copy_from_slice(&52u32.to_le_bytes());
        memory.0[0x22c..0x234].copy_from_slice(&0x380u64.to_le_bytes());
        finalize(&mut memory.0[0x200..0x234], 9);
        let marker = &mut memory.0[0x380..0x3a4];
        marker[..4].copy_from_slice(b"MQ35");
        marker[4..8].copy_from_slice(&36u32.to_le_bytes());
        marker[8] = 1;
        marker[10..].copy_from_slice(b"MRMLQ3MMIOTEST\x01\x00\x00\x00MRML\x01\x00\x00\x00");
        finalize(marker, 9);
        assert!(q35_fixture_marker(&mut memory, 0x100).is_ok());
        memory.0[0x3a0] = 2;
        finalize(&mut memory.0[0x380..0x3a4], 9);
        assert_eq!(q35_fixture_marker(&mut memory, 0x100).unwrap()[32], 2);
        memory.0[0x3a0] = 3;
        finalize(&mut memory.0[0x380..0x3a4], 9);
        assert_eq!(q35_fixture_marker(&mut memory, 0x100).unwrap()[32], 3);
        memory.0[0x3a0] = 4;
        finalize(&mut memory.0[0x380..0x3a4], 9);
        assert_eq!(q35_fixture_marker(&mut memory, 0x100).unwrap()[32], 4);
        memory.0[0x3a0] = 8;
        finalize(&mut memory.0[0x380..0x3a4], 9);
        assert_eq!(q35_fixture_marker(&mut memory, 0x100).unwrap()[32], 8);
        memory.0[0x3a0] = 9;
        finalize(&mut memory.0[0x380..0x3a4], 9);
        assert_eq!(q35_fixture_marker(&mut memory, 0x100).unwrap()[32], 9);
        for profile in [5, 6, 7, 10] {
            memory.0[0x3a0] = profile;
            finalize(&mut memory.0[0x380..0x3a4], 9);
            assert_eq!(
                q35_fixture_marker(&mut memory, 0x100),
                Err(AcpiError::InvalidQ35FixtureMarker)
            );
        }
        memory.0[0x3a0] = 1;
        finalize(&mut memory.0[0x380..0x3a4], 9);
        memory.0[0x389] ^= 1;
        assert_eq!(
            q35_fixture_marker(&mut memory, 0x100),
            Err(AcpiError::BadChecksum)
        );
        memory.0[0x388] = 2;
        finalize(&mut memory.0[0x380..0x3a4], 9);
        assert_eq!(
            q35_fixture_marker(&mut memory, 0x100),
            Err(AcpiError::InvalidQ35FixtureMarker)
        );
        memory.0[0x388] = 1;
        finalize(&mut memory.0[0x380..0x3a4], 9);
        memory.0[0x204..0x208].copy_from_slice(&60u32.to_le_bytes());
        memory.0[0x234..0x23c].copy_from_slice(&0x380u64.to_le_bytes());
        finalize(&mut memory.0[0x200..0x23c], 9);
        assert_eq!(
            q35_fixture_marker(&mut memory, 0x100),
            Err(AcpiError::DuplicateQ35FixtureMarker)
        );
    }
}
