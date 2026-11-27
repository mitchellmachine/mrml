//! Deliberately narrow write target for an owner-provisioned diagnostic partition.
//! This is not a general FAT32 writer or an authorization mechanism.

use super::{
    FAT32_BOOT_SECTOR_BYTES as SECTOR, FAT32_MINIMUM_CLUSTERS, Fat32ClusterChain, Fat32Geometry,
    Fat32ShortDirectoryEntry, FixedFileWriteError, VerifiedSectorDevice, overwrite_fixed_file,
    parse_fat32_boot_sector, parse_fat32_short_directory,
};

const RESERVED: u32 = 32;
const FAT_SECTORS: u32 = 520;
const ROOT_SECTOR: u32 = RESERVED + 2 * FAT_SECTORS;
pub const PROBE_DATA_SECTOR: u32 = ROOT_SECTOR + 1;
pub const PROBE_PARTITION_SECTORS: u32 = ROOT_SECTOR + FAT32_MINIMUM_CLUSTERS;
pub const PROBE_NAME: [u8; 11] = *b"PROBE   TXT";

/// Deterministic metadata for the dedicated, single-file probe partition.
/// The caller is responsible for creating/selecting the partition and owning
/// it exclusively. The serial is a provisioning check, not a credential.
pub fn probe_metadata_sector(
    partition_start: u32,
    serial: u32,
    sector: u32,
) -> Option<[u8; SECTOR]> {
    let mut bytes = [0; SECTOR];
    match sector {
        0 => {
            bytes[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
            bytes[3..11].copy_from_slice(b"MRMLTEST");
            bytes[11..13].copy_from_slice(&(SECTOR as u16).to_le_bytes());
            bytes[13] = 1;
            bytes[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
            bytes[16] = 2;
            bytes[21] = 0xf8;
            bytes[28..32].copy_from_slice(&partition_start.to_le_bytes());
            bytes[32..36].copy_from_slice(&PROBE_PARTITION_SECTORS.to_le_bytes());
            bytes[36..40].copy_from_slice(&FAT_SECTORS.to_le_bytes());
            bytes[44..48].copy_from_slice(&2u32.to_le_bytes());
            bytes[48..52].fill(0xff); // No FSInfo or backup boot sector.
            bytes[64] = 0x80;
            bytes[66] = 0x29;
            bytes[67..71].copy_from_slice(&serial.to_le_bytes());
            bytes[71..82].copy_from_slice(b"NO NAME    ");
            bytes[82..90].copy_from_slice(b"FAT32   ");
            bytes[510..].copy_from_slice(&[0x55, 0xaa]);
        }
        n if n == RESERVED || n == RESERVED + FAT_SECTORS => {
            for (slot, entry) in bytes.chunks_exact_mut(4).zip([
                0x0fff_fff8u32,
                0x0fff_ffff,
                0x0fff_ffff,
                0x0fff_ffff,
            ]) {
                slot.copy_from_slice(&entry.to_le_bytes());
            }
        }
        ROOT_SECTOR => {
            bytes[..11].copy_from_slice(&PROBE_NAME);
            bytes[11] = 0x20;
            bytes[26..28].copy_from_slice(&3u16.to_le_bytes());
            bytes[28..32].copy_from_slice(&3u32.to_le_bytes());
        }
        n if n < ROOT_SECTOR => {}
        _ => return None,
    }
    Some(bytes)
}

#[derive(Debug, Eq, PartialEq)]
pub enum ProbeError<E> {
    InvalidFixture,
    MetadataMismatch(u32),
    Read(E),
    Unavailable,
    Update(FixedFileWriteError<E>),
}

/// Scoped to one exclusive partition view and exact provisioned layout.
/// The backend must bind all I/O to the same retained media generation and
/// enforce partition/device write authority. Matching bytes alone grant none.
pub struct ProvisionedProbe<'a, D> {
    device: &'a mut D,
    geometry: Fat32Geometry,
    entry: Fat32ShortDirectoryEntry,
    available: bool,
}

impl<'a, D: VerifiedSectorDevice> ProvisionedProbe<'a, D> {
    pub fn verify(
        device: &'a mut D,
        partition_start: u32,
        partition_sectors: u32,
        serial: u32,
    ) -> Result<Self, ProbeError<D::Error>> {
        if serial == 0
            || partition_start == 0
            || partition_start.checked_add(partition_sectors).is_none()
            || partition_sectors != PROBE_PARTITION_SECTORS
        {
            return Err(ProbeError::InvalidFixture);
        }
        let mut current = [0; SECTOR];
        for sector in 0..=ROOT_SECTOR {
            device
                .read_sector(sector, &mut current)
                .map_err(ProbeError::Read)?;
            let expected = probe_metadata_sector(partition_start, serial, sector)
                .ok_or(ProbeError::InvalidFixture)?;
            if current != expected {
                return Err(ProbeError::MetadataMismatch(sector));
            }
        }
        // The complete layout matched: both FATs have only root/data EOCs,
        // and the one-sector root contains just the one file, without aliases.
        let geometry = parse_fat32_boot_sector(
            &probe_metadata_sector(partition_start, serial, 0).ok_or(ProbeError::InvalidFixture)?,
        )
        .map_err(|_| ProbeError::InvalidFixture)?;
        let directory = parse_fat32_short_directory::<1>(geometry, &current)
            .map_err(|_| ProbeError::InvalidFixture)?;
        let [entry] = directory.entries() else {
            return Err(ProbeError::InvalidFixture);
        };
        Ok(Self {
            device,
            geometry,
            entry: *entry,
            available: true,
        })
    }

    /// Updates only PROBE.TXT's three bytes. Success includes synchronized
    /// sector readback through the backend; an I/O failure closes the view.
    pub fn update(
        &mut self,
        before: &[u8; 3],
        after: &[u8; 3],
    ) -> Result<(), ProbeError<D::Error>> {
        if !self.available {
            return Err(ProbeError::Unavailable);
        }
        let chain = Fat32ClusterChain {
            clusters: [3],
            length: 1,
        };
        let result = overwrite_fixed_file(
            self.device,
            self.geometry,
            self.entry,
            &chain,
            before,
            after,
        );
        if matches!(
            result,
            Err(FixedFileWriteError::Read(_) | FixedFileWriteError::WriteUncertain(_))
        ) {
            self.available = false;
        }
        result.map_err(ProbeError::Update)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Disk {
        broken_metadata: Option<(u32, usize)>,
        data: [u8; SECTOR],
        writes: u32,
        fail_write: bool,
    }

    impl Disk {
        fn new() -> Self {
            let mut data = [0xa5; SECTOR];
            data[..3].copy_from_slice(b"old");
            Self {
                broken_metadata: None,
                data,
                writes: 0,
                fail_write: false,
            }
        }
    }

    impl VerifiedSectorDevice for Disk {
        type Error = ();
        fn read_sector(&mut self, sector: u32, output: &mut [u8; SECTOR]) -> Result<(), ()> {
            *output = if sector == PROBE_DATA_SECTOR {
                self.data
            } else {
                probe_metadata_sector(32, 42, sector).ok_or(())?
            };
            if let Some((changed, byte)) = self.broken_metadata {
                if changed == sector {
                    output[byte] ^= 1;
                }
            }
            Ok(())
        }

        fn write_sector_verified(&mut self, sector: u32, input: &[u8; SECTOR]) -> Result<(), ()> {
            assert_eq!(sector, PROBE_DATA_SECTOR);
            self.writes += 1;
            self.data = *input;
            if self.fail_write { Err(()) } else { Ok(()) }
        }
    }

    #[test]
    fn requires_exact_media_layout_before_opening_write_view() {
        let mut disk = Disk::new();
        assert!(matches!(
            ProvisionedProbe::verify(&mut disk, 32, PROBE_PARTITION_SECTORS, 43),
            Err(ProbeError::MetadataMismatch(0))
        ));
        assert!(matches!(
            ProvisionedProbe::verify(&mut disk, 32, PROBE_PARTITION_SECTORS - 1, 42),
            Err(ProbeError::InvalidFixture)
        ));
        for (sector, byte) in [
            (0, 11),
            (RESERVED + 3, 511),
            (ROOT_SECTOR - 1, 63),
            (ROOT_SECTOR, 32),
        ] {
            disk.broken_metadata = Some((sector, byte));
            assert!(matches!(
                ProvisionedProbe::verify(&mut disk, 32, PROBE_PARTITION_SECTORS, 42),
                Err(ProbeError::MetadataMismatch(n)) if n == sector
            ));
        }
        assert_eq!(disk.writes, 0);
    }

    #[test]
    fn stale_input_is_not_written_and_uncertain_write_never_retries() {
        let mut disk = Disk::new();
        disk.fail_write = true;
        let mut probe =
            ProvisionedProbe::verify(&mut disk, 32, PROBE_PARTITION_SECTORS, 42).unwrap();
        assert_eq!(
            probe.update(b"bad", b"new"),
            Err(ProbeError::Update(FixedFileWriteError::StaleContents))
        );
        assert_eq!(
            probe.update(b"old", b"new"),
            Err(ProbeError::Update(FixedFileWriteError::WriteUncertain(())))
        );
        assert_eq!(probe.update(b"new", b"old"), Err(ProbeError::Unavailable));
        assert_eq!(disk.writes, 1);
        assert_eq!(&disk.data[..3], b"new");
        assert_eq!(&disk.data[3..], &[0xa5; SECTOR - 3]);
    }
}
