#[path = "xhci_boot_observation.rs"]
pub mod boot_observation;

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

/// Read xHCI DMA geometry without taking ownership of the controller.
pub fn inspect_dma_geometry<E>(
    bar_bytes: u32,
    mut read: impl FnMut(u32) -> Result<u32, E>,
) -> Option<(u16, u16)> {
    // xHCI 1.2 sections 5.3.1, 5.3.4 and 5.4.3.
    if bar_bytes < 0x20 {
        return None;
    }
    let cap_length = read(0).ok()? & 0xff;
    if cap_length < 0x20 || cap_length % 4 != 0 || cap_length + 12 > bar_bytes {
        return None;
    }
    let structural = read(8).ok()?;
    let page_mask = read(cap_length + 8).ok()?;
    if structural == u32::MAX || page_mask == 0 || page_mask > u32::from(u16::MAX) {
        return None;
    }
    let count = ((structural >> 21) & 31) << 5 | ((structural >> 27) & 31);
    Some((count as u16, page_mask as u16))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceTransport {
    Usb,
    SataOrNvme,
}

/// Classify only an actual node boundary after the firmware PCI path prefix.
/// Unknown transports never imply the boot media is safely separate.
pub fn source_transport(path: &[u8], remaining: usize) -> Option<SourceTransport> {
    super::validate_single_device_path(path).ok()?;
    let mut offset = 0;
    let mut transport = None;
    let mut media_seen = false;
    while offset < path.len() {
        let node = path.get(offset..offset + 4)?;
        let len = u16::from_le_bytes([node[2], node[3]]) as usize;
        if offset == remaining && (offset == 0 || transport.is_some()) {
            return None;
        }
        if offset >= remaining {
            match (node[0], node[1], len) {
                (3, 5, 6)
                    if !media_seen && matches!(transport, None | Some(SourceTransport::Usb)) =>
                {
                    transport = Some(SourceTransport::Usb);
                }
                (3, 0x12, 10) | (3, 0x17, 16) if offset == remaining => {
                    transport = Some(SourceTransport::SataOrNvme);
                }
                (4, 1, 42) if transport.is_some() && !media_seen => media_seen = true,
                (0x7f, 0xff, 4) => return transport,
                _ => return None,
            }
        } else if offset + len > remaining {
            return None;
        }
        offset += len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_split_scratchpad_count_and_page_mask_including_non_4k() {
        for (bits, pages, count) in [(0, 1, 0), ((1 << 21) | (2 << 27), 0x10, 34)] {
            let mut offsets = [0; 3];
            let mut reads = 0;
            let report = inspect_dma_geometry(0x80, |offset| {
                offsets[reads] = offset;
                reads += 1;
                match offset {
                    0 => Ok(0x0110_0040),
                    8 => Ok(bits),
                    0x48 => Ok(pages),
                    _ => Err(()),
                }
            });
            assert_eq!(report, Some((count, pages as u16)));
            assert_eq!(reads, 3);
            assert_eq!(offsets, [0, 8, 0x48]);
        }
    }

    #[test]
    fn rejects_invalid_offsets_and_does_not_read_past_the_bar() {
        for (bytes, cap, expected_reads) in [(0, 0x20, 0), (32, 0, 1), (64, 0x21, 1), (64, 0x38, 1)]
        {
            let mut reads = 0;
            assert_eq!(
                inspect_dma_geometry(bytes, |offset| {
                    reads += 1;
                    assert_eq!(offset, 0);
                    Ok::<_, ()>(cap)
                }),
                None
            );
            assert_eq!(reads, expected_reads);
        }
        for pages in [Ok(0), Ok(0x1_0001), Ok(u32::MAX), Err(())] {
            assert_eq!(
                inspect_dma_geometry(0x2c, |offset| match offset {
                    0 => Ok(0x20),
                    8 => Ok(0),
                    0x28 => pages,
                    _ => panic!("unexpected offset"),
                }),
                None
            );
        }
    }

    #[test]
    fn classifies_only_bounded_unambiguous_source_suffixes() {
        const PCI: [u8; 6] = [1, 1, 6, 0, 0, 5];
        const USB: [u8; 6] = [3, 5, 6, 0, 1, 0];
        const SATA: [u8; 10] = [3, 0x12, 10, 0, 0, 0, 0, 0, 0, 0];
        const END: [u8; 4] = [0x7f, 0xff, 4, 0];
        let usb = [&PCI[..], &USB[..], &USB[..], &END[..]].concat();
        let sata = [&PCI[..], &SATA[..], &END[..]].concat();
        let ambiguous = [&PCI[..], &USB[..], &PCI[..], &END[..]].concat();
        assert_eq!(source_transport(&usb, 6), Some(SourceTransport::Usb));
        assert_eq!(
            source_transport(&sata, 6),
            Some(SourceTransport::SataOrNvme)
        );
        assert_eq!(source_transport(&ambiguous, 6), None);
        assert_eq!(source_transport(&usb, 1), None);
        assert_eq!(source_transport(&usb, 0), None);
        assert_eq!(source_transport(&usb[..12], 6), None);
    }

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
