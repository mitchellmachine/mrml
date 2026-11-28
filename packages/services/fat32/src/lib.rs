#![no_std]

//! Service-facing FAT32 contract. The existing signed guest remains in the
//! storage-fat32 package; this is not an additional installed guest.

pub use mrml_storage_fat32::{
    FixedFileWriteError, VerifiedSectorDevice,
    provisioned_probe::{ProbeError, ProvisionedProbe},
};

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use mrml_storage_fat32::provisioned_probe::PROBE_PARTITION_SECTORS;
    use mrml_usb_fat32_qtest::{
        FIXTURE_PARTITION_START, FIXTURE_VOLUME_SERIAL, with_emulated_service_partition,
    };

    impl<D: VerifiedSectorDevice + ?Sized> VerifiedSectorDevice for BorrowedPartition<'_, D> {
        type Error = D::Error;

        fn read_sector(&mut self, sector: u32, output: &mut [u8; 512]) -> Result<(), Self::Error> {
            self.0.read_sector(sector, output)
        }

        fn write_sector_verified(
            &mut self,
            sector: u32,
            input: &[u8; 512],
        ) -> Result<(), Self::Error> {
            self.0.write_sector_verified(sector, input)
        }
    }

    struct BorrowedPartition<'a, D: ?Sized>(&'a mut D);

    #[test]
    #[ignore = "requires a private QEMU USB fixture"]
    fn fat32_service_rejects_stale_contents_and_updates_only_the_fixed_file() {
        for super_speed in [false, true] {
            with_emulated_service_partition(super_speed, &mut |partition| {
                let mut device = BorrowedPartition(partition);
                let mut probe = ProvisionedProbe::verify(
                    &mut device,
                    FIXTURE_PARTITION_START,
                    PROBE_PARTITION_SECTORS,
                    FIXTURE_VOLUME_SERIAL,
                )
                .unwrap();
                assert!(matches!(
                    probe.update(b"bad", b"new"),
                    Err(ProbeError::Update(FixedFileWriteError::StaleContents))
                ));
                // Cross multiple bulk and event ring wraps; the fixture
                // independently compares the entire persisted disk.
                let mut previous = *b"old";
                for byte in b'A'..=b'K' {
                    let next = [byte; 3];
                    probe.update(&previous, &next).unwrap();
                    previous = next;
                }
                probe.update(&previous, b"new").unwrap();
            });
        }
    }
}
