#![no_std]

//! Service-facing USB block provider contract. Hosted tests do not launch an
//! installed controller-bound guest or grant access to physical devices.

pub use mrml_storage_usb::{SECTOR_BYTES, UsbDisk, block_provider::UsbReadProvider};

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use mrml_usb_fat32_qtest::{FIXTURE_DATA_SECTOR, with_emulated_service_partition};

    #[test]
    #[ignore = "requires a private QEMU USB fixture"]
    fn usb_storage_service_reads_and_persists_the_scoped_sector() {
        for super_speed in [false, true] {
            with_emulated_service_partition(super_speed, &mut |partition| {
                // The fixture grants one data sector. Treat it as opaque
                // block data here: FAT metadata and file policy belong to FAT32.
                let mut before = [0; SECTOR_BYTES];
                partition
                    .read_sector(FIXTURE_DATA_SECTOR, &mut before)
                    .unwrap();
                assert_eq!(&before[..3], b"old");
                assert_eq!(&before[3..], &[0xa5; SECTOR_BYTES - 3]);
                let mut expected = before;
                expected[..3].copy_from_slice(b"new");
                partition
                    .write_sector_verified(FIXTURE_DATA_SECTOR, &expected)
                    .unwrap();
                let mut after = [0; SECTOR_BYTES];
                partition
                    .read_sector(FIXTURE_DATA_SECTOR, &mut after)
                    .unwrap();
                assert_eq!(after, expected);
            });
        }
    }
}
