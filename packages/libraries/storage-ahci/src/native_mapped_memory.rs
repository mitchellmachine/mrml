//! Native service views over the four preinstalled AHCI CPU mappings.

use crate::{
    AhciMappedCommandMemory, AhciMappedDataBuffer, BoundAhciServiceLaunch,
    InstalledAhciServiceLaunch,
    service_cpu_mapping::{bound_mapping_requests, mapping_requests},
};

const PAGE_BYTES: u64 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciNativeMappedMemoryError {
    InvalidVirtualMapping,
    AdapterMismatch,
}

pub struct AhciNativeMappedMemory<'a, S> {
    command_memory: AhciMappedCommandMemory<'a>,
    data: AhciMappedDataBuffer<'a, S>,
}

impl<'a, S> AhciNativeMappedMemory<'a, S> {
    /// Binds the exact CPU mappings installed for one native AHCI service.
    ///
    /// # Safety
    ///
    /// Each launch virtual range must currently map the exact named memory
    /// object/generation as writable, non-executable, exclusively borrowed
    /// storage for `'a`. Those mappings and their DMA/IOMMU ownership must
    /// remain live until the returned owner is consumed.
    pub unsafe fn from_installed_launch(
        launch: InstalledAhciServiceLaunch,
        sync: S,
    ) -> Result<Self, AhciNativeMappedMemoryError> {
        let record = launch.record();
        unsafe {
            Self::from_requests(
                record.layout(),
                record.data(),
                mapping_requests(record),
                sync,
            )
        }
    }

    /// Reconstructs the same four views from the manager-held bound launch
    /// after the exact service task is frozen and its active leaves are
    /// independently revalidated.
    ///
    /// # Safety
    ///
    /// The caller must hold the matching frozen service owner. Every bound
    /// virtual range must still map its exact physical object generation as
    /// writable, non-executable, exclusive storage in the active root, and no
    /// service or competing manager access may occur until this owner is
    /// consumed.
    pub unsafe fn from_bound_launch(
        launch: BoundAhciServiceLaunch,
        sync: S,
    ) -> Result<Self, AhciNativeMappedMemoryError> {
        let spec = launch.spec();
        unsafe {
            Self::from_requests(
                spec.layout(),
                spec.data(),
                bound_mapping_requests(launch),
                sync,
            )
        }
    }

    unsafe fn from_requests(
        layout: crate::AhciPortDmaLayout,
        data_region: crate::AhciDataDmaRegion,
        requests: [crate::AhciServiceCpuMappingRequest; 4],
        sync: S,
    ) -> Result<Self, AhciNativeMappedMemoryError> {
        for request in requests {
            if request.virtual_base() == 0
                || request.virtual_base() % PAGE_BYTES != 0
                || request.exposed_bytes() == 0
                || request.exposed_bytes() > request.mapped_bytes()
                || request
                    .virtual_base()
                    .checked_add(request.mapped_bytes())
                    .is_none()
                || usize::try_from(request.virtual_base()).is_err()
                || usize::try_from(request.exposed_bytes())
                    .ok()
                    .is_none_or(|bytes| bytes > isize::MAX as usize)
            {
                return Err(AhciNativeMappedMemoryError::InvalidVirtualMapping);
            }
        }
        for left in 0..requests.len() {
            for right in left + 1..requests.len() {
                let left_end = requests[left].virtual_base() + requests[left].mapped_bytes();
                let right_end = requests[right].virtual_base() + requests[right].mapped_bytes();
                if requests[left].virtual_base() < right_end
                    && requests[right].virtual_base() < left_end
                {
                    return Err(AhciNativeMappedMemoryError::InvalidVirtualMapping);
                }
            }
        }
        let view = |index: usize| -> Result<&'a mut [u8], AhciNativeMappedMemoryError> {
            let base = usize::try_from(requests[index].virtual_base())
                .map_err(|_| AhciNativeMappedMemoryError::InvalidVirtualMapping)?;
            let bytes = usize::try_from(requests[index].exposed_bytes())
                .map_err(|_| AhciNativeMappedMemoryError::InvalidVirtualMapping)?;
            Ok(unsafe { core::slice::from_raw_parts_mut(base as *mut u8, bytes) })
        };
        let command_list = view(0)?;
        let received_fis = view(1)?;
        let command_tables = view(2)?;
        let data_bytes = view(3)?;
        let command_memory =
            AhciMappedCommandMemory::new(layout, command_list, received_fis, command_tables)
                .ok_or(AhciNativeMappedMemoryError::AdapterMismatch)?;
        let data = AhciMappedDataBuffer::new(data_region, data_bytes, sync)
            .ok_or(AhciNativeMappedMemoryError::AdapterMismatch)?;
        Ok(Self {
            command_memory,
            data,
        })
    }

    pub fn into_parts(self) -> (AhciMappedCommandMemory<'a>, AhciMappedDataBuffer<'a, S>) {
        (self.command_memory, self.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AhciAbarMapping, AhciCommandMemoryIo, AhciDataBufferSync, AhciDataDmaRegion, AhciDmaRegion,
        AhciPortDmaLayout, AhciServiceCpuMapping, AhciServiceLaunchRecord,
    };
    use mrml_interface_storage_block_provider_v1::{
        BLOCK_DEVICE_FLAG_FLUSH, BLOCK_DEVICE_FLAG_RESET, BlockProviderDevice, OpaqueHandle,
    };
    use mrml_kernel::{Capability, ObjectId};

    #[repr(align(4096))]
    struct Page([u8; 4096]);

    struct Sync;
    impl AhciDataBufferSync for Sync {
        fn prepare_device_write(&mut self, _: AhciDataDmaRegion) -> Result<(), ()> {
            Ok(())
        }
        fn prepare_device_read(&mut self, _: AhciDataDmaRegion) -> Result<(), ()> {
            Ok(())
        }
        fn complete_device_write(&mut self, _: AhciDataDmaRegion) -> Result<(), ()> {
            Ok(())
        }
        fn complete_device_read(&mut self, _: AhciDataDmaRegion) -> Result<(), ()> {
            Ok(())
        }
        fn publish_sanitized(&mut self, _: AhciDataDmaRegion) -> Result<(), ()> {
            Ok(())
        }
    }

    fn region(object: u64, physical_base: u64, bytes: u64) -> AhciDmaRegion {
        AhciDmaRegion {
            memory_object: ObjectId(object),
            allocation_generation: object + 10,
            physical_base,
            bytes,
        }
    }

    #[test]
    fn exact_native_views_are_bounded_to_the_four_launch_mappings() {
        let pages = [
            Page([0; 4096]),
            Page([0; 4096]),
            Page([0; 4096]),
            Page([0; 4096]),
        ];
        let bases = pages.each_ref().map(|page| page.0.as_ptr() as u64);
        let layout = AhciPortDmaLayout {
            device_object: ObjectId(10),
            configuration_generation: 11,
            mapping_generation: 12,
            port: 2,
            command_slot_count: 4,
            command_list: region(20, 0x30_0000, 1024),
            received_fis: region(21, 0x31_0000, 256),
            command_tables: region(22, 0x32_0000, 1024),
            dma_generation: 13,
        };
        let record = AhciServiceLaunchRecord::new(
            4,
            3,
            8,
            BlockProviderDevice {
                session: OpaqueHandle::new(1, 2).unwrap(),
                logical_block_bytes: 512,
                flags: BLOCK_DEVICE_FLAG_FLUSH | BLOCK_DEVICE_FLAG_RESET,
                logical_block_count: 100,
                media_generation: 7,
            },
            crate::AhciAbarDescriptor {
                location: crate::PciFunctionLocation::new(0, 0, 31, 2).unwrap(),
                configuration_generation: 11,
                vendor_id: 0x8086,
                device_id: 0x7a62,
                physical_base: 0x10_0000,
                bytes: 0x2000,
            },
            AhciAbarMapping {
                device_object: ObjectId(10),
                configuration_generation: 11,
                mapping_generation: 12,
                physical_base: 0x10_0000,
                virtual_base: 0x20_0000,
                bytes: 0x2000,
            },
            layout,
            AhciDataDmaRegion {
                memory_object: ObjectId(23),
                allocation_generation: 33,
                physical_base: 0x40_0000,
                bytes: 4096,
            },
            core::array::from_fn(|index| {
                AhciServiceCpuMapping::new(index as u64 + 1, bases[index]).unwrap()
            }),
        )
        .unwrap();
        let authorities =
            core::array::from_fn(|index| Capability::from_token(((index as u64 + 20) << 32) | 1));
        let launch = unsafe {
            InstalledAhciServiceLaunch::from_installed_projection(&record.encode(), 3, authorities)
        }
        .unwrap();
        let mapped =
            unsafe { AhciNativeMappedMemory::from_installed_launch(launch, Sync) }.unwrap();
        let (mut command, data) = mapped.into_parts();
        command
            .write_u32(layout.command_list, 1020, 0x1122_3344)
            .unwrap();
        let (command_list, _, _) = command.into_mappings();
        assert_eq!(&command_list[1020..], &0x1122_3344_u32.to_le_bytes());
        let (data, _) = data.into_clean_parts().ok().unwrap();
        assert_eq!(data.len(), 4096);
    }
}
