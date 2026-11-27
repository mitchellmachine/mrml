#![no_std]
//! Test-only synthetic USB medium for the freestanding guest diagnostic.

use mrml_storage_fat32::VerifiedSectorDevice;
use mrml_storage_fat32::provisioned_probe::{
    PROBE_DATA_SECTOR, PROBE_PARTITION_SECTORS, ProvisionedProbe, probe_metadata_sector,
};
pub use mrml_storage_usb::UsbDisk;
pub use mrml_storage_usb::{
    BulkTransport,
    xhci::{
        BulkDma, Controller, DeviceDma, DmaAssignment, DmaLayout, PciActivation, Platform,
        RevocablePlatform, inspect_legacy_ownership,
        pci::{PciController, PciLocation, PciSnapshot},
    },
};
use mrml_storage_usb::{Error as UsbError, SECTOR_BYTES};

const START: u32 = 32;
const SERIAL: u32 = 42;
pub const FILE: u32 = START + PROBE_DATA_SECTOR;

pub fn fixture_sectors() -> u64 {
    u64::from(START + PROBE_PARTITION_SECTORS)
}

struct Disk {
    command: Option<(u8, u32, [u8; 4], bool)>,
    sector: [u8; SECTOR_BYTES],
    writes: u8,
    flushed: bool,
}

impl BulkTransport for Disk {
    type Error = ();

    fn bulk_out(&mut self, bytes: &[u8]) -> Result<usize, ()> {
        match self.command {
            None if bytes.len() == 31 && &bytes[..4] == b"USBC" => {
                let operation = bytes[15];
                let lba = u32::from_be_bytes(bytes[17..21].try_into().unwrap());
                let tag = bytes[4..8].try_into().unwrap();
                if !matches!(operation, 0x25 | 0x28 | 0x2a | 0x35) {
                    return Err(());
                }
                self.command = Some((operation, lba, tag, operation == 0x35));
            }
            Some((0x2a, FILE, tag, false)) if bytes.len() == SECTOR_BYTES && self.writes == 0 => {
                self.sector.copy_from_slice(bytes);
                self.writes = 1;
                self.flushed = false;
                self.command = Some((0x2a, FILE, tag, true));
            }
            _ => return Err(()),
        }
        Ok(bytes.len())
    }

    fn bulk_in(&mut self, bytes: &mut [u8]) -> Result<usize, ()> {
        let (operation, lba, tag, status) = self.command.ok_or(())?;
        bytes.fill(0);
        match (operation, status, bytes.len()) {
            (_, true, 13) => {
                bytes[..4].copy_from_slice(b"USBS");
                bytes[4..8].copy_from_slice(&tag);
                self.command = None;
                if operation == 0x35 {
                    self.flushed = true;
                }
                return Ok(bytes.len());
            }
            (0x25, false, 8) => {
                bytes[..4].copy_from_slice(&(START + PROBE_PARTITION_SECTORS - 1).to_be_bytes());
                bytes[4..].copy_from_slice(&(SECTOR_BYTES as u32).to_be_bytes());
            }
            (0x28, false, SECTOR_BYTES) if lba == FILE && (self.writes == 0 || self.flushed) => {
                bytes.copy_from_slice(&self.sector);
            }
            (0x28, false, SECTOR_BYTES) if lba != FILE => {
                bytes.copy_from_slice(
                    &probe_metadata_sector(START, SERIAL, lba.checked_sub(START).ok_or(())?)
                        .ok_or(())?,
                );
            }
            _ => return Err(()),
        }
        self.command = Some((operation, lba, tag, true));
        Ok(bytes.len())
    }
}

struct Partition<T: BulkTransport>(UsbDisk<T>);

impl<T: BulkTransport> VerifiedSectorDevice for Partition<T> {
    type Error = UsbError<T::Error>;

    fn read_sector(
        &mut self,
        sector: u32,
        output: &mut [u8; SECTOR_BYTES],
    ) -> Result<(), Self::Error> {
        if sector >= PROBE_PARTITION_SECTORS {
            return Err(UsbError::OutOfRange);
        }
        self.0.read_sector(u64::from(START + sector), output)
    }

    fn write_sector_verified(
        &mut self,
        sector: u32,
        input: &[u8; SECTOR_BYTES],
    ) -> Result<(), Self::Error> {
        if sector != PROBE_DATA_SECTOR {
            return Err(UsbError::OutOfRange);
        }
        self.0
            .write_sector_verified(u64::from(START + sector), input)
    }
}

pub fn exercise() -> bool {
    let mut original = [0xa5; SECTOR_BYTES];
    original[..3].copy_from_slice(b"old");
    exercise_transport(Disk {
        command: None,
        sector: original,
        writes: 0,
        flushed: false,
    })
}

pub fn exercise_transport<T: BulkTransport>(transport: T) -> bool {
    let Ok(disk) = UsbDisk::probe(transport) else {
        return false;
    };
    let mut partition = Partition(disk);
    let Ok(mut probe) =
        ProvisionedProbe::verify(&mut partition, START, PROBE_PARTITION_SECTORS, SERIAL)
    else {
        return false;
    };
    if probe.update(b"old", b"new").is_err() {
        return false;
    }
    let mut observed = [0; SECTOR_BYTES];
    partition
        .read_sector(PROBE_DATA_SECTOR, &mut observed)
        .is_ok()
        && observed[..3] == *b"new"
        && observed[3..].iter().all(|&value| value == 0xa5)
}
