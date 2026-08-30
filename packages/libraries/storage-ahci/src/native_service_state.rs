//! Exact assembly of installed AHCI mechanism state for service dispatch.

use crate::{
    ActiveAhciPort, AhciCommandBlockBackend, AhciDataCapabilityAuthorizer, AhciMappedCommandMemory,
    AhciMappedDataBuffer, InstalledAhciServiceLaunch,
};
use mrml_interface_storage_block_provider_v1::BlockProviderDevice;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciNativeServiceStateError {
    BackendBinding,
}

/// Launch-bound catalog and command backend owned by one native AHCI service.
pub struct AhciNativeServiceState<'a, 'm, A, R, S> {
    device: BlockProviderDevice,
    backend: AhciCommandBlockBackend<
        'a,
        A,
        R,
        AhciMappedCommandMemory<'m>,
        AhciMappedDataBuffer<'m, S>,
    >,
}

impl<'a, 'm, A: AhciDataCapabilityAuthorizer, R, S>
    AhciNativeServiceState<'a, 'm, A, R, S>
{
    /// Assembles only state named by the installed launch projection.
    pub fn new(
        capabilities: &'a mut A,
        launch: InstalledAhciServiceLaunch,
        owner: ActiveAhciPort,
        registers: R,
        command_memory: AhciMappedCommandMemory<'m>,
        data_io: AhciMappedDataBuffer<'m, S>,
    ) -> Result<Self, AhciNativeServiceStateError> {
        let record = launch.record();
        let device = record.device();
        let backend = AhciCommandBlockBackend::new(
            capabilities,
            device.session,
            device.media_generation,
            launch.device_write_data(),
            launch.device_read_data(),
            record.data(),
            record.mapping(),
            owner,
            registers,
            command_memory,
            data_io,
        )
        .ok_or(AhciNativeServiceStateError::BackendBinding)?;
        Ok(Self { device, backend })
    }

    pub const fn device(&self) -> BlockProviderDevice {
        self.device
    }

    pub fn into_parts(
        self,
    ) -> (
        BlockProviderDevice,
        AhciCommandBlockBackend<
            'a,
            A,
            R,
            AhciMappedCommandMemory<'m>,
            AhciMappedDataBuffer<'m, S>,
        >,
    ) {
        (self.device, self.backend)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        reconstruct_installed_ahci_port, AhciAbarMapping, AhciDataBufferSync,
        AhciDataDmaRegion, AhciDmaRegion, AhciMappedDataBuffer, AhciPortDmaLayout,
        AhciRegisterIo, AhciServiceCpuMapping, AhciServiceLaunchRecord,
    };
    use mrml_interface_storage_block_provider_v1::{
        OpaqueHandle, BLOCK_DEVICE_FLAG_FLUSH, BLOCK_DEVICE_FLAG_RESET,
    };
    use mrml_kernel::{Capability, CapabilityError, ObjectId, Rights};

    struct Registers;
    impl AhciRegisterIo for Registers {
        fn read_u32(&mut self, offset: u32) -> Result<u32, ()> {
            Ok(if offset == 0x118 { 0x11 } else { 0 })
        }
        fn write_u32(&mut self, _: u32, _: u32) -> Result<(), ()> {
            Ok(())
        }
    }

    struct Authorizer {
        object: ObjectId,
        calls: usize,
        reject: bool,
    }
    impl AhciDataCapabilityAuthorizer for Authorizer {
        fn authorize_exact(
            &mut self,
            _: Capability,
            _: Rights,
        ) -> Result<ObjectId, CapabilityError> {
            self.calls += 1;
            if self.reject {
                Err(CapabilityError::PermissionDenied)
            } else {
                Ok(self.object)
            }
        }
    }

    struct Sync;
    impl AhciDataBufferSync for Sync {
        fn prepare_device_write(&mut self, _: AhciDataDmaRegion) -> Result<(), ()> { Ok(()) }
        fn prepare_device_read(&mut self, _: AhciDataDmaRegion) -> Result<(), ()> { Ok(()) }
        fn complete_device_write(&mut self, _: AhciDataDmaRegion) -> Result<(), ()> { Ok(()) }
        fn complete_device_read(&mut self, _: AhciDataDmaRegion) -> Result<(), ()> { Ok(()) }
        fn publish_sanitized(&mut self, _: AhciDataDmaRegion) -> Result<(), ()> { Ok(()) }
    }

    fn region(object: u64, physical: u64, bytes: u64) -> AhciDmaRegion {
        AhciDmaRegion {
            memory_object: ObjectId(object),
            allocation_generation: object + 10,
            physical_base: physical,
            bytes,
        }
    }

    fn launch() -> InstalledAhciServiceLaunch {
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
            AhciAbarMapping {
                device_object: ObjectId(10),
                configuration_generation: 11,
                mapping_generation: 12,
                physical_base: 0x10_0000,
                virtual_base: 0x20_0000,
                bytes: 0x2000,
            },
            AhciPortDmaLayout {
                device_object: ObjectId(10),
                configuration_generation: 11,
                mapping_generation: 12,
                port: 0,
                command_slot_count: 1,
                command_list: region(20, 0x30_0000, 1024),
                received_fis: region(21, 0x31_0000, 256),
                command_tables: region(22, 0x32_0000, 256),
                dma_generation: 13,
            },
            AhciDataDmaRegion {
                memory_object: ObjectId(23),
                allocation_generation: 33,
                physical_base: 0x40_0000,
                bytes: 4096,
            },
            [
                AhciServiceCpuMapping::new(1, 0x30_0000).unwrap(),
                AhciServiceCpuMapping::new(2, 0x31_0000).unwrap(),
                AhciServiceCpuMapping::new(3, 0x32_0000).unwrap(),
                AhciServiceCpuMapping::new(4, 0x40_0000).unwrap(),
            ],
        )
        .unwrap();
        let authorities = core::array::from_fn(|index| {
            Capability::from_token(((index as u64 + 20) << 32) | 1)
        });
        unsafe {
            InstalledAhciServiceLaunch::from_installed_projection(&record.encode(), 3, authorities)
        }
        .unwrap()
    }

    fn memory<'a>(
        launch: InstalledAhciServiceLaunch,
        command_list: &'a mut [u8; 1024],
        received_fis: &'a mut [u8; 256],
        command_tables: &'a mut [u8; 256],
        data: &'a mut [u8; 4096],
    ) -> (AhciMappedCommandMemory<'a>, AhciMappedDataBuffer<'a, Sync>) {
        let record = launch.record();
        (
            AhciMappedCommandMemory::new(
                record.layout(),
                command_list,
                received_fis,
                command_tables,
            )
            .unwrap(),
            AhciMappedDataBuffer::new(record.data(), data, Sync).unwrap(),
        )
    }

    #[test]
    fn exact_installed_state_assembles_catalog_and_backend_once() {
        let installed = launch();
        let mut registers = Registers;
        let owner = reconstruct_installed_ahci_port(installed, &mut registers).unwrap();
        let mut command_list = [0; 1024];
        let mut received_fis = [0; 256];
        let mut command_tables = [0; 256];
        let mut data = [0; 4096];
        let (command_memory, data_io) = memory(
            installed,
            &mut command_list,
            &mut received_fis,
            &mut command_tables,
            &mut data,
        );
        let mut authorizer = Authorizer { object: ObjectId(23), calls: 0, reject: false };
        let state = AhciNativeServiceState::new(
            &mut authorizer,
            installed,
            owner,
            Registers,
            command_memory,
            data_io,
        )
        .unwrap();
        assert_eq!(state.device(), installed.record().device());
        let (_, backend) = state.into_parts();
        assert!(backend.is_available());
        drop(backend);
        assert_eq!(authorizer.calls, 2);
    }

    #[test]
    fn authorization_denial_publishes_no_service_state() {
        let installed = launch();
        let mut registers = Registers;
        let owner = reconstruct_installed_ahci_port(installed, &mut registers).unwrap();
        let mut command_list = [0; 1024];
        let mut received_fis = [0; 256];
        let mut command_tables = [0; 256];
        let mut data = [0; 4096];
        let (command_memory, data_io) = memory(
            installed,
            &mut command_list,
            &mut received_fis,
            &mut command_tables,
            &mut data,
        );
        let mut authorizer = Authorizer { object: ObjectId(23), calls: 0, reject: true };
        let result = AhciNativeServiceState::new(
                &mut authorizer,
                installed,
                owner,
                Registers,
                command_memory,
                data_io,
            );
        assert!(matches!(result, Err(AhciNativeServiceStateError::BackendBinding)));
        assert_eq!(authorizer.calls, 1);
    }
}
