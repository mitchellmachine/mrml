use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Inject {
    None,
    BadWriteTag,
    ShortWrite,
    FlushFailed,
    ReadbackMismatch,
    PhaseError,
    Residue,
}

struct EmulatedDisk {
    sector: [u8; SECTOR_BYTES],
    stage: u8,
    tag: [u8; 4],
    opcode: u8,
    commands: [u8; 8],
    count: usize,
    inject: Inject,
    capacity: [u8; 8],
}

impl EmulatedDisk {
    fn new() -> Self {
        Self {
            sector: [0; SECTOR_BYTES],
            stage: 0,
            tag: [0; 4],
            opcode: 0,
            commands: [0; 8],
            count: 0,
            inject: Inject::None,
            capacity: [0, 0, 0, 15, 0, 0, 2, 0],
        }
    }
}

impl BulkTransport for EmulatedDisk {
    type Error = ();

    fn bulk_out(&mut self, bytes: &[u8]) -> Result<usize, Self::Error> {
        if self.stage == 1 {
            assert_eq!(self.opcode, 0x2a);
            self.sector.copy_from_slice(bytes);
            self.stage = 2;
            return Ok(if self.inject == Inject::ShortWrite {
                511
            } else {
                bytes.len()
            });
        }
        assert_eq!(self.stage, 0);
        assert_eq!(bytes.len(), CBW_BYTES);
        assert_eq!(&bytes[..4], b"USBC");
        assert_eq!(bytes[13], 0);
        assert_eq!(bytes[14], 10);
        assert_eq!(&bytes[25..], &[0; 6]);
        self.tag.copy_from_slice(&bytes[4..8]);
        assert_eq!(u32::from_le_bytes(self.tag), self.count as u32 + 1);
        self.opcode = bytes[15];
        self.commands[self.count] = self.opcode;
        self.count += 1;
        let length = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        match self.opcode {
            0x25 => {
                assert_eq!((length, bytes[12]), (8, 0x80));
                assert_eq!(&bytes[16..25], &[0; 9]);
            }
            0x28 | 0x2a => {
                assert_eq!(
                    (length, bytes[12]),
                    (512, if self.opcode == 0x28 { 0x80 } else { 0 })
                );
                assert_eq!(&bytes[17..21], &3u32.to_be_bytes());
                assert_eq!(&bytes[22..24], &[0, 1]);
            }
            0x35 => {
                assert_eq!((length, bytes[12]), (0, 0));
                assert_eq!(&bytes[16..25], &[0; 9]);
            }
            _ => panic!("unexpected command"),
        }
        self.stage = if length == 0 { 2 } else { 1 };
        Ok(bytes.len())
    }

    fn bulk_in(&mut self, bytes: &mut [u8]) -> Result<usize, Self::Error> {
        if self.stage == 1 {
            match self.opcode {
                0x25 => bytes.copy_from_slice(&self.capacity),
                0x28 => {
                    bytes.copy_from_slice(&self.sector);
                    if self.inject == Inject::ReadbackMismatch {
                        bytes[0] ^= 1;
                    }
                }
                _ => panic!("unexpected data-in command"),
            }
            self.stage = 2;
            return Ok(bytes.len());
        }
        assert_eq!(self.stage, 2);
        assert_eq!(bytes.len(), CSW_BYTES);
        bytes[..4].copy_from_slice(b"USBS");
        bytes[4..8].copy_from_slice(&self.tag);
        bytes[8..].fill(0);
        match (self.opcode, self.inject) {
            (0x2a, Inject::BadWriteTag) => bytes[4] ^= 1,
            (0x35, Inject::FlushFailed) => bytes[12] = 1,
            (0x2a, Inject::PhaseError) => bytes[12] = 2,
            (0x28, Inject::Residue) => bytes[8] = 1,
            _ => {}
        }
        self.stage = 0;
        Ok(bytes.len())
    }
}

#[test]
fn writes_syncs_and_verifies_exact_sector() {
    let mut disk = UsbDisk::probe(EmulatedDisk::new()).unwrap();
    assert_eq!(disk.sectors(), 16);
    assert_eq!(
        disk.write_sector_verified(16, &[4; SECTOR_BYTES]),
        Err(Error::OutOfRange)
    );
    disk.write_sector_verified(3, &[0x5a; SECTOR_BYTES])
        .unwrap();
    assert_eq!(
        &disk.endpoint.commands[..disk.endpoint.count],
        &[0x25, 0x2a, 0x35, 0x28]
    );
    assert_eq!(disk.endpoint.sector, [0x5a; SECTOR_BYTES]);
}

#[test]
fn failures_stop_the_session_without_reissuing_a_write() {
    for (inject, expected, count) in [
        (Inject::BadWriteTag, Error::InvalidStatus, 2),
        (Inject::ShortWrite, Error::ShortTransfer, 2),
        (Inject::PhaseError, Error::PhaseError, 2),
        (Inject::FlushFailed, Error::CommandFailed, 3),
        (Inject::ReadbackMismatch, Error::ReadbackMismatch, 4),
        (Inject::Residue, Error::InvalidStatus, 4),
    ] {
        let mut endpoint = EmulatedDisk::new();
        endpoint.inject = inject;
        let mut disk = UsbDisk::probe(endpoint).unwrap();
        assert_eq!(
            disk.write_sector_verified(3, &[1; SECTOR_BYTES]),
            Err(expected)
        );
        assert_eq!(disk.endpoint.count, count);
        assert_eq!(
            disk.write_sector_verified(3, &[1; SECTOR_BYTES]),
            Err(Error::Faulted)
        );
        assert_eq!(disk.endpoint.count, count);
    }
}

#[test]
fn a_failed_read_never_publishes_unconfirmed_bytes() {
    let mut endpoint = EmulatedDisk::new();
    endpoint.inject = Inject::Residue;
    let mut disk = UsbDisk::probe(endpoint).unwrap();
    let mut output = [9; SECTOR_BYTES];
    assert_eq!(disk.read_sector(3, &mut output), Err(Error::InvalidStatus));
    assert_eq!(output, [9; SECTOR_BYTES]);
}

#[test]
fn rejects_saturated_capacity_and_non_512_byte_media() {
    let mut e = EmulatedDisk::new();
    e.capacity[..4].fill(0xff);
    assert!(matches!(UsbDisk::probe(e), Err(Error::UnsupportedCapacity)));
    let mut e = EmulatedDisk::new();
    e.capacity[4..].copy_from_slice(&4096u32.to_be_bytes());
    assert!(matches!(UsbDisk::probe(e), Err(Error::UnsupportedCapacity)));
}

#[test]
fn descriptors_select_only_an_unambiguous_bulk_only_interface() {
    let mut config = [
        9, 2, 32, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 2, 8, 6, 0x50, 0, 7, 5, 0x81, 2, 0, 2, 0, 7, 5,
        0x02, 2, 0, 2, 0,
    ];
    assert_eq!(
        find_bulk_interface(&config),
        Ok(BulkInterface {
            configuration: 1,
            interface: 0,
            bulk_in: 0x81,
            bulk_out: 2,
            packet_in: 512,
            packet_out: 512,
            burst_in: None,
            burst_out: None,
        })
    );
    assert_eq!(
        find_bulk_interface(&config[..31]),
        Err(DescriptorError::Malformed)
    );
    config[27] = 0x82;
    assert_eq!(
        find_bulk_interface(&config),
        Err(DescriptorError::Ambiguous)
    );
    config[16] = 0x62;
    assert_eq!(
        find_bulk_interface(&config),
        Err(DescriptorError::Unsupported)
    );
}

#[test]
fn superspeed_companions_bind_to_their_exact_endpoints() {
    let mut config = [
        9, 2, 44, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 2, 8, 6, 0x50, 0, 7, 5, 0x81, 2, 0, 4, 0, 6,
        48, 15, 0, 0, 0, 7, 5, 0x02, 2, 0, 4, 0, 6, 48, 3, 0, 0, 0,
    ];
    let parsed = find_bulk_interface(&config).unwrap();
    assert_eq!((parsed.packet_in, parsed.packet_out), (1024, 1024));
    assert_eq!((parsed.burst_in, parsed.burst_out), (Some(15), Some(3)));
    config[28] = 1; // Streams are not part of this BOT profile.
    assert_eq!(
        find_bulk_interface(&config),
        Err(DescriptorError::Unsupported)
    );
    config[28] = 0;
    config[40] = 16;
    assert_eq!(
        find_bulk_interface(&config),
        Err(DescriptorError::Unsupported)
    );
}

/// Exercise the canonical protocol through the existing BOT implementation.
#[test]
fn usb_provider_enumerates_read_only_and_reads_exact_subrange() {
    use crate::block_provider::UsbReadProvider;
    use mrml_interface_storage_block_provider_v1::{
        BLOCK_DEVICE_FLAG_READ_ONLY, BlockProviderReadTransport, BlockProviderTransport,
        BorrowedWriteView, OpaqueHandle, decode_enumerate_response, decode_read_response,
        encode_enumerate_request, encode_read_request,
    };

    let mut transport = EmulatedDisk::new();
    transport.sector.fill(0x4f);
    let session = OpaqueHandle::new(4, 8).unwrap();
    let mut provider =
        UsbReadProvider::new(UsbDisk::probe(transport).unwrap(), session, 11).unwrap();
    let range = BorrowedWriteView::within(7, 48, 64).unwrap();
    let mut catalog = [0xa5; 64];
    let request = encode_enumerate_request(range).unwrap();
    let response = provider.enumerate(&request, &mut catalog).unwrap();
    assert_eq!(decode_enumerate_response(&response, 48), Ok(Ok(48)));
    assert_eq!(&catalog[7..15], b"MRMLBLK\0");
    assert_eq!(&catalog[31..35], &512u32.to_le_bytes());
    assert_eq!(&catalog[35..39], &BLOCK_DEVICE_FLAG_READ_ONLY.to_le_bytes());
    assert_eq!(&catalog[39..47], &16u64.to_le_bytes());
    assert_eq!(&catalog[47..55], &11u64.to_le_bytes());
    assert_eq!(&catalog[..7], &[0xa5; 7]);
    assert_eq!(&catalog[55..], &[0xa5; 9]);

    let output = BorrowedWriteView::within(9, 512, 528).unwrap();
    let mut memory = [0xa5; 528];
    let request = encode_read_request(session, 3, 1, output).unwrap();
    let response = provider.read(&request, &mut memory).unwrap();
    assert_eq!(decode_read_response(&response, 512), Ok(Ok(512)));
    assert_eq!(&memory[..9], &[0xa5; 9]);
    assert_eq!(&memory[9..521], &[0x4f; 512]);
    assert_eq!(&memory[521..], &[0xa5; 7]);
    assert_eq!(&provider.into_disk().endpoint.commands[..2], &[0x25, 0x28]);
}

#[test]
fn usb_provider_rejects_stale_and_invalid_reads_before_device_access() {
    use crate::block_provider::UsbReadProvider;
    use mrml_interface_storage_block_provider_v1::{
        BlockProviderReadTransport, BorrowedWriteView, OpaqueHandle, ReadError,
        decode_read_response, encode_read_request,
    };

    let session = OpaqueHandle::new(4, 8).unwrap();
    let older = OpaqueHandle::new(4, 7).unwrap();
    let mut provider =
        UsbReadProvider::new(UsbDisk::probe(EmulatedDisk::new()).unwrap(), session, 11).unwrap();
    let output = BorrowedWriteView::within(9, 512, 528).unwrap();
    let mut memory = [0xa5; 528];
    for (session, lba, count, view, error) in [
        (older, 3, 1, output, ReadError::StaleObject),
        (session, 16, 1, output, ReadError::InvalidRequest),
        (session, 3, 2, output, ReadError::InvalidRequest),
        (
            session,
            3,
            1,
            BorrowedWriteView::within(9, 511, 528).unwrap(),
            ReadError::InvalidRequest,
        ),
    ] {
        let request = encode_read_request(session, lba, count, view).unwrap();
        let response = provider.read(&request, &mut memory).unwrap();
        assert_eq!(decode_read_response(&response, 512), Ok(Err(error)));
        assert_eq!(memory, [0xa5; 528]);
    }
    provider.invalidate_session();
    let request = encode_read_request(session, 3, 1, output).unwrap();
    let response = provider.read(&request, &mut memory).unwrap();
    assert_eq!(
        decode_read_response(&response, 512),
        Ok(Err(ReadError::StaleObject))
    );
    assert_eq!(memory, [0xa5; 528]);
    assert_eq!(provider.into_disk().endpoint.count, 1);
}

#[test]
fn usb_provider_does_not_publish_failed_data_or_retry_faulted_session() {
    use crate::block_provider::UsbReadProvider;
    use mrml_interface_storage_block_provider_v1::{
        BlockProviderReadTransport, BorrowedWriteView, OpaqueHandle, ReadError,
        decode_read_response, encode_read_request,
    };

    let mut transport = EmulatedDisk::new();
    transport.inject = Inject::Residue;
    transport.sector.fill(0x4f);
    let session = OpaqueHandle::new(4, 8).unwrap();
    let mut provider =
        UsbReadProvider::new(UsbDisk::probe(transport).unwrap(), session, 11).unwrap();
    let output = BorrowedWriteView::within(0, 512, 512).unwrap();
    let request = encode_read_request(session, 3, 1, output).unwrap();
    let mut memory = [0xa5; 512];
    for error in [ReadError::IoFailure, ReadError::StaleObject] {
        let response = provider.read(&request, &mut memory).unwrap();
        assert_eq!(decode_read_response(&response, 512), Ok(Err(error)));
        assert_eq!(memory, [0xa5; 512]);
    }
    assert_eq!(provider.into_disk().endpoint.count, 2);
}
