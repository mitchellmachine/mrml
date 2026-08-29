#![no_std]

//! Bounded FAT32 interoperability provider for ESP/install/recovery media.
//!
//! Native MRML storage does not inherit FAT authority or namespace semantics.

pub const FAT32_BOOT_SECTOR_BYTES: usize = 512;
pub const FAT32_MINIMUM_CLUSTERS: u32 = 65_525;
pub const FAT32_MAXIMUM_CLUSTERS: u32 = 0x0fff_fff4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fat32Geometry {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub fat_count: u8,
    pub sectors_per_fat: u32,
    pub total_sectors: u32,
    pub data_start_sector: u32,
    pub data_sectors: u32,
    pub cluster_count: u32,
    pub root_cluster: u32,
    pub fs_info_sector: Option<u16>,
    pub backup_boot_sector: Option<u16>,
    pub volume_id: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fat32Error {
    InvalidJump,
    InvalidSignature,
    InvalidSectorSize,
    InvalidClusterSize,
    InvalidReservedArea,
    InvalidFatCount,
    NotFat32,
    UnsupportedVersion,
    InvalidExtent,
    InvalidRootCluster,
    FatTooSmall,
}

pub fn parse_fat32_boot_sector(
    sector: &[u8; FAT32_BOOT_SECTOR_BYTES],
) -> Result<Fat32Geometry, Fat32Error> {
    if !matches!(sector[0], 0xe9) && !(sector[0] == 0xeb && sector[2] == 0x90) {
        return Err(Fat32Error::InvalidJump);
    }
    if sector[510..512] != [0x55, 0xaa] {
        return Err(Fat32Error::InvalidSignature);
    }
    let bytes_per_sector = read_u16(sector, 11);
    if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096) {
        return Err(Fat32Error::InvalidSectorSize);
    }
    let sectors_per_cluster = sector[13];
    let cluster_bytes = u32::from(bytes_per_sector)
        .checked_mul(u32::from(sectors_per_cluster))
        .ok_or(Fat32Error::InvalidClusterSize)?;
    if sectors_per_cluster == 0
        || !sectors_per_cluster.is_power_of_two()
        || sectors_per_cluster > 128
        || cluster_bytes > 32 * 1024
    {
        return Err(Fat32Error::InvalidClusterSize);
    }
    let reserved_sectors = read_u16(sector, 14);
    if reserved_sectors == 0 {
        return Err(Fat32Error::InvalidReservedArea);
    }
    let fat_count = sector[16];
    if !(1..=2).contains(&fat_count) {
        return Err(Fat32Error::InvalidFatCount);
    }
    if read_u16(sector, 17) != 0 || read_u16(sector, 19) != 0 || read_u16(sector, 22) != 0 {
        return Err(Fat32Error::NotFat32);
    }
    let total_sectors = read_u32(sector, 32);
    let sectors_per_fat = read_u32(sector, 36);
    if total_sectors == 0 || sectors_per_fat == 0 {
        return Err(Fat32Error::NotFat32);
    }
    if read_u16(sector, 42) != 0 {
        return Err(Fat32Error::UnsupportedVersion);
    }
    let root_cluster = read_u32(sector, 44);
    if !(2..=FAT32_MAXIMUM_CLUSTERS + 1).contains(&root_cluster) {
        return Err(Fat32Error::InvalidRootCluster);
    }
    let fs_info = optional_reserved_sector(read_u16(sector, 48), reserved_sectors)?;
    let backup_boot = optional_reserved_sector(read_u16(sector, 50), reserved_sectors)?;
    if fs_info.is_some() && fs_info == backup_boot {
        return Err(Fat32Error::InvalidReservedArea);
    }
    let all_fat_sectors = u32::from(fat_count)
        .checked_mul(sectors_per_fat)
        .ok_or(Fat32Error::InvalidExtent)?;
    let data_start_sector = u32::from(reserved_sectors)
        .checked_add(all_fat_sectors)
        .ok_or(Fat32Error::InvalidExtent)?;
    let data_sectors = total_sectors
        .checked_sub(data_start_sector)
        .ok_or(Fat32Error::InvalidExtent)?;
    let cluster_count = data_sectors / u32::from(sectors_per_cluster);
    if !(FAT32_MINIMUM_CLUSTERS..=FAT32_MAXIMUM_CLUSTERS).contains(&cluster_count) {
        return Err(Fat32Error::NotFat32);
    }
    if root_cluster
        >= cluster_count
            .checked_add(2)
            .ok_or(Fat32Error::InvalidExtent)?
    {
        return Err(Fat32Error::InvalidRootCluster);
    }
    let fat_entries = u64::from(sectors_per_fat)
        .checked_mul(u64::from(bytes_per_sector))
        .ok_or(Fat32Error::InvalidExtent)?
        / 4;
    if fat_entries < u64::from(cluster_count) + 2 {
        return Err(Fat32Error::FatTooSmall);
    }
    Ok(Fat32Geometry {
        bytes_per_sector,
        sectors_per_cluster,
        reserved_sectors,
        fat_count,
        sectors_per_fat,
        total_sectors,
        data_start_sector,
        data_sectors,
        cluster_count,
        root_cluster,
        fs_info_sector: fs_info,
        backup_boot_sector: backup_boot,
        volume_id: read_u32(sector, 67),
    })
}

fn optional_reserved_sector(value: u16, reserved: u16) -> Result<Option<u16>, Fat32Error> {
    if value == 0 || value == u16::MAX {
        return Ok(None);
    }
    if value >= reserved {
        return Err(Fat32Error::InvalidReservedArea);
    }
    Ok(Some(value))
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boot_sector() -> [u8; FAT32_BOOT_SECTOR_BYTES] {
        let mut sector = [0; FAT32_BOOT_SECTOR_BYTES];
        sector[0..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        sector[11..13].copy_from_slice(&512_u16.to_le_bytes());
        sector[13] = 8;
        sector[14..16].copy_from_slice(&32_u16.to_le_bytes());
        sector[16] = 2;
        sector[32..36].copy_from_slice(&1_048_576_u32.to_le_bytes());
        sector[36..40].copy_from_slice(&1024_u32.to_le_bytes());
        sector[44..48].copy_from_slice(&2_u32.to_le_bytes());
        sector[48..50].copy_from_slice(&1_u16.to_le_bytes());
        sector[50..52].copy_from_slice(&6_u16.to_le_bytes());
        sector[67..71].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
        sector[510..512].copy_from_slice(&[0x55, 0xaa]);
        sector
    }

    #[test]
    fn parses_exact_bounded_fat32_geometry() {
        let geometry = parse_fat32_boot_sector(&boot_sector()).unwrap();
        assert_eq!(geometry.bytes_per_sector, 512);
        assert_eq!(geometry.data_start_sector, 2080);
        assert_eq!(geometry.cluster_count, 130_812);
        assert_eq!(geometry.root_cluster, 2);
        assert_eq!(geometry.fs_info_sector, Some(1));
        assert_eq!(geometry.backup_boot_sector, Some(6));
        assert_eq!(geometry.volume_id, 0x1234_5678);
    }

    #[test]
    fn rejects_fat16_shapes_and_undersized_fat() {
        let mut fat16 = boot_sector();
        fat16[17..19].copy_from_slice(&512_u16.to_le_bytes());
        assert_eq!(parse_fat32_boot_sector(&fat16), Err(Fat32Error::NotFat32));

        let mut small = boot_sector();
        small[36..40].copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(
            parse_fat32_boot_sector(&small),
            Err(Fat32Error::FatTooSmall)
        );
    }

    #[test]
    fn rejects_reserved_extent_root_and_arithmetic_boundaries() {
        let mut reserved = boot_sector();
        reserved[48..50].copy_from_slice(&32_u16.to_le_bytes());
        assert_eq!(
            parse_fat32_boot_sector(&reserved),
            Err(Fat32Error::InvalidReservedArea)
        );

        let mut root = boot_sector();
        root[44..48].copy_from_slice(&200_000_u32.to_le_bytes());
        assert_eq!(
            parse_fat32_boot_sector(&root),
            Err(Fat32Error::InvalidRootCluster)
        );

        let mut extent = boot_sector();
        extent[32..36].copy_from_slice(&100_u32.to_le_bytes());
        assert_eq!(
            parse_fat32_boot_sector(&extent),
            Err(Fat32Error::InvalidExtent)
        );
    }

    #[test]
    fn rejects_noncanonical_sector_cluster_and_signature_fields() {
        for mutate in [
            |sector: &mut [u8; 512]| sector[0] = 0,
            |sector: &mut [u8; 512]| sector[11..13].copy_from_slice(&768_u16.to_le_bytes()),
            |sector: &mut [u8; 512]| sector[13] = 3,
            |sector: &mut [u8; 512]| sector[510] = 0,
        ] {
            assert!(
                parse_fat32_boot_sector(&{
                    let mut sector = boot_sector();
                    mutate(&mut sector);
                    sector
                })
                .is_err()
            );
        }
    }
}
