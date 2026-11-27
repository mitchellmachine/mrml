//! Exact, non-growing data update for one preallocated diagnostic file.
//! No FAT, directory, allocation, file-size or volume metadata is modified.

use super::{
    FAT32_BOOT_SECTOR_BYTES as SECTOR, Fat32ClusterChain, Fat32Geometry, Fat32ShortDirectoryEntry,
};

/// Sector numbers are relative to one explicitly selected, exclusive partition.
/// Success must mean the same sector was written, flushed and read back exactly,
/// on the same medium generation. A write error may already have changed media.
pub trait VerifiedSectorDevice {
    type Error;
    fn read_sector(&mut self, sector: u32, output: &mut [u8; SECTOR]) -> Result<(), Self::Error>;
    fn write_sector_verified(
        &mut self,
        sector: u32,
        input: &[u8; SECTOR],
    ) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixedFileWriteError<E> {
    Unsupported,
    InvalidExtent,
    StaleContents,
    Read(E),
    WriteUncertain(E),
}

/// Overwrites only an existing, single-sector regular file without resizing.
/// The caller owns the selected partition, and must establish a fresh matching
/// directory entry and chain with no cluster aliasing before calling. This is
/// a diagnostic building block, not a general write API for untrusted volumes.
pub fn overwrite_fixed_file<const N: usize, D: VerifiedSectorDevice>(
    device: &mut D,
    geometry: Fat32Geometry,
    entry: Fat32ShortDirectoryEntry,
    chain: &Fat32ClusterChain<N>,
    before: &[u8],
    after: &[u8],
) -> Result<(), FixedFileWriteError<D::Error>> {
    if geometry.bytes_per_sector as usize != SECTOR
        || geometry.sectors_per_cluster != 1
        || entry.attributes & 0x1f != 0
        || entry.attributes & !0x20 != 0
        || before.is_empty()
        || before.len() != after.len()
        || before.len() > SECTOR
        || before.len() as u32 != entry.file_size
    {
        return Err(FixedFileWriteError::Unsupported);
    }
    let [cluster] = chain.clusters() else {
        return Err(FixedFileWriteError::InvalidExtent);
    };
    if *cluster != entry.first_cluster
        || *cluster == geometry.root_cluster
        || *cluster < 2
        || *cluster - 2 >= geometry.cluster_count
    {
        return Err(FixedFileWriteError::InvalidExtent);
    }
    let sector = geometry
        .data_start_sector
        .checked_add(*cluster - 2)
        .filter(|&value| value < geometry.total_sectors)
        .ok_or(FixedFileWriteError::InvalidExtent)?;
    let mut current = [0; SECTOR];
    device
        .read_sector(sector, &mut current)
        .map_err(FixedFileWriteError::Read)?;
    if &current[..before.len()] != before {
        return Err(FixedFileWriteError::StaleContents);
    }
    current[..after.len()].copy_from_slice(after);
    device
        .write_sector_verified(sector, &current)
        .map_err(FixedFileWriteError::WriteUncertain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse_fat32_boot_sector, tests::boot_sector};

    struct Disk {
        sector: [u8; SECTOR],
        expected_address: u32,
        writes: u32,
    }

    impl VerifiedSectorDevice for Disk {
        type Error = ();
        fn read_sector(&mut self, sector: u32, output: &mut [u8; SECTOR]) -> Result<(), ()> {
            assert_eq!(sector, self.expected_address);
            *output = self.sector;
            Ok(())
        }
        fn write_sector_verified(&mut self, sector: u32, input: &[u8; SECTOR]) -> Result<(), ()> {
            assert_eq!(sector, self.expected_address);
            self.writes += 1;
            self.sector = *input;
            Ok(())
        }
    }

    #[test]
    fn fixed_data_write_refuses_stale_contents_and_preserves_slack() {
        let mut geometry = parse_fat32_boot_sector(&boot_sector()).unwrap();
        geometry.sectors_per_cluster = 1;
        let mut entry = Fat32ShortDirectoryEntry {
            short_name: *b"PROBE   TXT",
            long_name: None,
            attributes: 0x20,
            first_cluster: 3,
            file_size: 3,
        };
        let chain = Fat32ClusterChain {
            clusters: [3],
            length: 1,
        };
        let mut disk = Disk {
            sector: [0xa5; SECTOR],
            expected_address: geometry.data_start_sector + 1,
            writes: 0,
        };
        disk.sector[..3].copy_from_slice(b"old");
        assert_eq!(
            overwrite_fixed_file(&mut disk, geometry, entry, &chain, b"bad", b"new"),
            Err(FixedFileWriteError::StaleContents)
        );
        assert_eq!(
            overwrite_fixed_file(&mut disk, geometry, entry, &chain, b"old", b"more"),
            Err(FixedFileWriteError::Unsupported)
        );
        entry.attributes |= 1;
        assert_eq!(
            overwrite_fixed_file(&mut disk, geometry, entry, &chain, b"old", b"new"),
            Err(FixedFileWriteError::Unsupported)
        );
        assert_eq!(disk.writes, 0);
        entry.attributes = 0x20;
        overwrite_fixed_file(&mut disk, geometry, entry, &chain, b"old", b"new").unwrap();
        assert_eq!(disk.writes, 1);
        assert_eq!(&disk.sector[..3], b"new");
        assert_eq!(&disk.sector[3..], &[0xa5; SECTOR - 3]);
    }
}
