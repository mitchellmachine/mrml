//! Exact-layout access to already-mapped AHCI command memory.
//!
//! This adapter owns no allocation, mapping, pinning, or cache authority. Its
//! caller must retain those lifetimes; the adapter only prevents a command
//! path from addressing bytes outside the three admitted DMA regions.

use crate::{
    AHCI_COMMAND_LIST_BYTES, AHCI_COMMAND_TABLE_BYTES_PER_SLOT, AHCI_RECEIVED_FIS_BYTES,
    AhciCommandMemoryIo, AhciDmaRegion, AhciPortDmaLayout,
};

pub struct AhciMappedCommandMemory<'a> {
    command_list: Region<'a>,
    received_fis: Region<'a>,
    command_tables: Region<'a>,
}

struct Region<'a> {
    descriptor: AhciDmaRegion,
    bytes: &'a mut [u8],
}

impl<'a> AhciMappedCommandMemory<'a> {
    /// Binds three existing CPU mappings to one exact admitted DMA layout.
    ///
    /// Mapping, pinning, cache synchronization, IOMMU installation, and
    /// revocation remain the caller's separately authorized responsibility.
    pub fn new(
        layout: AhciPortDmaLayout,
        command_list: &'a mut [u8],
        received_fis: &'a mut [u8],
        command_tables: &'a mut [u8],
    ) -> Option<Self> {
        let descriptors = [
            layout.command_list,
            layout.received_fis,
            layout.command_tables,
        ];
        let expected_table_bytes =
            u64::from(layout.command_slot_count).checked_mul(AHCI_COMMAND_TABLE_BYTES_PER_SLOT)?;
        if layout.device_object.0 == 0
            || layout.configuration_generation == 0
            || layout.mapping_generation == 0
            || layout.dma_generation == 0
            || layout.port >= 32
            || layout.command_slot_count == 0
            || layout.command_slot_count > 32
            || descriptors[0].bytes != AHCI_COMMAND_LIST_BYTES
            || descriptors[1].bytes != AHCI_RECEIVED_FIS_BYTES
            || descriptors[2].bytes != expected_table_bytes
            || !valid_region(descriptors[0], command_list.len())
            || !valid_region(descriptors[1], received_fis.len())
            || !valid_region(descriptors[2], command_tables.len())
            || descriptors[0].memory_object == descriptors[1].memory_object
            || descriptors[0].memory_object == descriptors[2].memory_object
            || descriptors[1].memory_object == descriptors[2].memory_object
            || overlaps(descriptors[0], descriptors[1])
            || overlaps(descriptors[0], descriptors[2])
            || overlaps(descriptors[1], descriptors[2])
        {
            return None;
        }
        Some(Self {
            command_list: Region {
                descriptor: descriptors[0],
                bytes: command_list,
            },
            received_fis: Region {
                descriptor: descriptors[1],
                bytes: received_fis,
            },
            command_tables: Region {
                descriptor: descriptors[2],
                bytes: command_tables,
            },
        })
    }

    pub fn into_mappings(self) -> (&'a mut [u8], &'a mut [u8], &'a mut [u8]) {
        (
            self.command_list.bytes,
            self.received_fis.bytes,
            self.command_tables.bytes,
        )
    }

    fn region(&mut self, requested: AhciDmaRegion) -> Option<&mut Region<'a>> {
        if self.command_list.descriptor == requested {
            Some(&mut self.command_list)
        } else if self.received_fis.descriptor == requested {
            Some(&mut self.received_fis)
        } else if self.command_tables.descriptor == requested {
            Some(&mut self.command_tables)
        } else {
            None
        }
    }
}

impl AhciCommandMemoryIo for AhciMappedCommandMemory<'_> {
    fn read_u32(&mut self, region: AhciDmaRegion, offset: u64) -> Result<u32, ()> {
        let bytes = word(self.region(region).ok_or(())?.bytes, offset)?;
        Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| ())?))
    }

    fn write_u32(&mut self, region: AhciDmaRegion, offset: u64, value: u32) -> Result<(), ()> {
        word_mut(self.region(region).ok_or(())?.bytes, offset)?
            .copy_from_slice(&value.to_le_bytes());
        Ok(())
    }
}

fn valid_region(region: AhciDmaRegion, mapping_bytes: usize) -> bool {
    region.memory_object.0 != 0
        && region.allocation_generation != 0
        && region.bytes != 0
        && usize::try_from(region.bytes).ok() == Some(mapping_bytes)
        && region.physical_base.checked_add(region.bytes).is_some()
}

fn overlaps(left: AhciDmaRegion, right: AhciDmaRegion) -> bool {
    let Some(left_end) = left.physical_base.checked_add(left.bytes) else {
        return true;
    };
    let Some(right_end) = right.physical_base.checked_add(right.bytes) else {
        return true;
    };
    left.physical_base < right_end && right.physical_base < left_end
}

fn word(bytes: &[u8], offset: u64) -> Result<&[u8], ()> {
    let offset = usize::try_from(offset).map_err(|_| ())?;
    if offset % 4 != 0 {
        return Err(());
    }
    bytes
        .get(offset..offset.checked_add(4).ok_or(())?)
        .ok_or(())
}

fn word_mut(bytes: &mut [u8], offset: u64) -> Result<&mut [u8], ()> {
    let offset = usize::try_from(offset).map_err(|_| ())?;
    if offset % 4 != 0 {
        return Err(());
    }
    bytes
        .get_mut(offset..offset.checked_add(4).ok_or(())?)
        .ok_or(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProgrammedAhciPortDma, initialize_ahci_command_memory};
    use mrml_kernel::ObjectId;

    fn region(object: u64, physical_base: u64, bytes: u64) -> AhciDmaRegion {
        AhciDmaRegion {
            memory_object: ObjectId(object),
            allocation_generation: object + 10,
            physical_base,
            bytes,
        }
    }

    fn layout() -> AhciPortDmaLayout {
        AhciPortDmaLayout {
            device_object: ObjectId(1),
            configuration_generation: 2,
            mapping_generation: 3,
            port: 0,
            command_slot_count: 2,
            command_list: region(4, 0x1000, 1024),
            received_fis: region(5, 0x2000, 256),
            command_tables: region(6, 0x3000, 512),
            dma_generation: 7,
        }
    }

    #[test]
    fn exact_regions_are_independently_addressable_and_recoverable() {
        let layout = layout();
        let mut command_list = [0; 1024];
        let mut received_fis = [0; 256];
        let mut command_tables = [0; 512];
        let mut memory = AhciMappedCommandMemory::new(
            layout,
            &mut command_list,
            &mut received_fis,
            &mut command_tables,
        )
        .unwrap();
        memory
            .write_u32(layout.command_list, 8, 0x1122_3344)
            .unwrap();
        memory
            .write_u32(layout.received_fis, 4, 0x5566_7788)
            .unwrap();
        memory
            .write_u32(layout.command_tables, 508, 0x99aa_bbcc)
            .unwrap();
        assert_eq!(memory.read_u32(layout.command_list, 8), Ok(0x1122_3344));
        assert_eq!(memory.read_u32(layout.received_fis, 4), Ok(0x5566_7788));
        assert_eq!(memory.read_u32(layout.command_tables, 508), Ok(0x99aa_bbcc));
        let (command_list, received_fis, command_tables) = memory.into_mappings();
        assert_eq!(&command_list[8..12], &0x1122_3344_u32.to_le_bytes());
        assert_eq!(&received_fis[4..8], &0x5566_7788_u32.to_le_bytes());
        assert_eq!(&command_tables[508..], &0x99aa_bbcc_u32.to_le_bytes());
    }

    #[test]
    fn command_initialization_programs_exact_table_bases_through_mapped_regions() {
        let layout = layout();
        let mut command_list = [0; 1024];
        let mut received_fis = [0; 256];
        let mut command_tables = [0; 512];
        let mut memory = AhciMappedCommandMemory::new(
            layout,
            &mut command_list,
            &mut received_fis,
            &mut command_tables,
        )
        .unwrap();
        let initialized =
            initialize_ahci_command_memory(ProgrammedAhciPortDma::from_layout(layout), &mut memory)
                .unwrap();
        assert_eq!(initialized.layout(), layout);
        let (command_list, _, _) = memory.into_mappings();
        assert_eq!(
            &command_list[8..16],
            &layout.command_tables.physical_base.to_le_bytes()
        );
        assert_eq!(
            &command_list[40..48],
            &(layout.command_tables.physical_base + AHCI_COMMAND_TABLE_BYTES_PER_SLOT)
                .to_le_bytes()
        );
    }

    #[test]
    fn descriptor_substitution_and_invalid_word_ranges_fail_closed() {
        let layout = layout();
        let mut command_list = [0; 1024];
        let mut received_fis = [0; 256];
        let mut command_tables = [0; 512];
        let mut memory = AhciMappedCommandMemory::new(
            layout,
            &mut command_list,
            &mut received_fis,
            &mut command_tables,
        )
        .unwrap();
        let substituted = AhciDmaRegion {
            allocation_generation: layout.command_list.allocation_generation + 1,
            ..layout.command_list
        };
        assert_eq!(memory.read_u32(substituted, 0), Err(()));
        assert_eq!(memory.write_u32(layout.command_list, 1, 1), Err(()));
        assert_eq!(memory.read_u32(layout.command_list, 1021), Err(()));
        assert_eq!(memory.read_u32(layout.command_list, u64::MAX), Err(()));
    }

    #[test]
    fn malformed_layout_or_mapping_lengths_publish_no_adapter() {
        let mut command_list = [0; 1024];
        let mut received_fis = [0; 256];
        let mut command_tables = [0; 512];
        assert!(
            AhciMappedCommandMemory::new(
                layout(),
                &mut command_list[..1020],
                &mut received_fis,
                &mut command_tables,
            )
            .is_none()
        );
        let mut aliased = layout();
        aliased.received_fis.memory_object = aliased.command_list.memory_object;
        assert!(
            AhciMappedCommandMemory::new(
                aliased,
                &mut command_list,
                &mut received_fis,
                &mut command_tables,
            )
            .is_none()
        );
    }
}
