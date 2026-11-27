/// UEFI PCI I/O supplies a single QWord Address Space descriptor for BAR0
/// followed by the ACPI End Tag. Other resource encodings are not accepted.
pub const BAR_RESOURCE_BYTES: usize = 48;
pub const BAR_RESOURCE_HEADER: [u8; 3] = [0x8a, 43, 0];

/// Validate an untranslated, enabled memory BAR without sizing it with writes.
/// The returned length only bounds reads through the firmware protocol.
pub fn inspect_bar0(
    command: u16,
    header: u8,
    lo: u32,
    hi: u32,
    resource: &[u8],
) -> Option<(u64, u32)> {
    if command & 2 == 0
        || header & 0x7f != 0
        || lo & 1 != 0
        || resource.len() != BAR_RESOURCE_BYTES
        || resource[..3] != BAR_RESOURCE_HEADER
        || resource[3] != 0
        || resource[46] != 0x79
        || (resource[47] != 0 && resource.iter().copied().fold(0u8, u8::wrapping_add) != 0)
    {
        return None;
    }
    let word = |offset| {
        // All offsets are constants within the validated 48-byte descriptor.
        u64::from_le_bytes(resource[offset..offset + 8].try_into().unwrap())
    };
    let (width, base) = match lo & 6 {
        0 => (32, u64::from(lo & !15)),
        4 => (64, (u64::from(hi) << 32) | u64::from(lo & !15)),
        _ => return None,
    };
    let length = word(38);
    let end = base.checked_add(length)?;
    if word(6) != width
        || word(14) != base
        || word(30) != 0
        || base == 0
        || length < 0x20
        || !length.is_power_of_two()
        || !base.is_multiple_of(length)
        || (width == 32 && end > 1u64 << 32)
    {
        return None;
    }
    Some((base, u32::try_from(length).ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(base: u64, length: u64, width: u64) -> [u8; BAR_RESOURCE_BYTES] {
        let mut bytes = [0; BAR_RESOURCE_BYTES];
        bytes[..3].copy_from_slice(&BAR_RESOURCE_HEADER);
        bytes[6..14].copy_from_slice(&width.to_le_bytes());
        bytes[14..22].copy_from_slice(&base.to_le_bytes());
        bytes[38..46].copy_from_slice(&length.to_le_bytes());
        bytes[46] = 0x79;
        bytes
    }

    #[test]
    fn admits_only_the_matching_enabled_memory_bar() {
        let bytes = descriptor(0x1_8120_0000, 0x4000, 64);
        assert_eq!(
            inspect_bar0(2, 0x80, 0x8120_0004, 1, &bytes),
            Some((0x1_8120_0000, 0x4000))
        );
        assert_eq!(inspect_bar0(0, 0, 0x8120_0004, 1, &bytes), None);
        assert_eq!(inspect_bar0(2, 1, 0x8120_0004, 1, &bytes), None);
        assert_eq!(inspect_bar0(2, 0, 0x8120_0005, 1, &bytes), None);
        assert_eq!(inspect_bar0(2, 0, 0x8120_0004, 0, &bytes), None);
        assert_eq!(inspect_bar0(2, 0, 0x8120_0004, 1, &bytes[..47]), None);
        let bytes = descriptor(0x8120_0000, 0x4000, 32);
        assert_eq!(
            inspect_bar0(2, 0, 0x8120_0000, 0xffff_ffff, &bytes),
            Some((0x8120_0000, 0x4000))
        );
    }

    #[test]
    fn rejects_translation_non_memory_bad_trailer_and_unsafe_spans() {
        let probe = |bytes: &[u8]| inspect_bar0(2, 0, 0x8120_0000, 0, bytes);
        for index in [0, 1, 3, 6, 14, 30, 46, 47] {
            let mut bytes = descriptor(0x8120_0000, 0x4000, 32);
            bytes[index] ^= 1;
            assert_eq!(probe(&bytes), None, "index {index}");
        }
        for length in [0, 16, 0x4800, 0x400000, 1 << 33] {
            assert_eq!(probe(&descriptor(0x8120_0000, length, 32)), None);
        }
    }
}
