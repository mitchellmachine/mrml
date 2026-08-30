//! Exact assembly of installed AHCI mechanism state for service dispatch.

use crate::{
    ActiveAhciPort, AhciCommandBlockBackend, AhciDataBufferSync, AhciDataCapabilityAuthorizer,
    AhciDispatchService, AhciDispatchServiceError, AhciDispatchSyscalls, AhciMappedCommandMemory,
    AhciMappedDataBuffer, AhciNativeMappedMemory, AhciNativeMappedMemoryError,
    AhciNativePortReconstructionError, AhciRegisterIo, AhciResetIo, InstalledAhciServiceLaunch,
    AHCI_DISPATCH_REQUEST_BYTES, reconstruct_installed_ahci_port,
};
use mrml_interface_storage_block_provider_v1::BlockProviderDevice;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciNativeServiceStateError {
    BackendBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciNativeServicePreparationError {
    MappedMemory(AhciNativeMappedMemoryError),
    ActivePort(AhciNativePortReconstructionError),
    ServiceState(AhciNativeServiceStateError),
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

/// Constructs all installed mechanism state needed by the bounded dispatcher.
///
/// # Safety
///
/// The launch's four virtual mappings must satisfy
/// [`AhciNativeMappedMemory::from_installed_launch`]. `registers` must be the
/// exclusive, launch-bound ABAR view and remain valid for the returned state's
/// lifetime. On failure no service state is published; the supervisor owns
/// process termination and installed-resource cleanup.
pub unsafe fn prepare_installed_ahci_service_state<'a, 'm, A, R, S>(
    capabilities: &'a mut A,
    launch: InstalledAhciServiceLaunch,
    mut registers: R,
    sync: S,
) -> Result<AhciNativeServiceState<'a, 'm, A, R, S>, AhciNativeServicePreparationError>
where
    A: AhciDataCapabilityAuthorizer,
    R: AhciRegisterIo,
{
    let mapped = unsafe { AhciNativeMappedMemory::from_installed_launch(launch, sync) }
        .map_err(AhciNativeServicePreparationError::MappedMemory)?;
    let owner = reconstruct_installed_ahci_port(launch, &mut registers)
        .map_err(AhciNativeServicePreparationError::ActivePort)?;
    let (command_memory, data_io) = mapped.into_parts();
    AhciNativeServiceState::new(
        capabilities,
        launch,
        owner,
        registers,
        command_memory,
        data_io,
    )
    .map_err(AhciNativeServicePreparationError::ServiceState)
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

impl<
        A: AhciDataCapabilityAuthorizer,
        R: AhciRegisterIo + AhciResetIo,
        S: AhciDataBufferSync,
    > AhciNativeServiceState<'_, '_, A, R, S>
{
    /// Serves exactly one authenticated envelope and retains the backend owner.
    pub fn serve_one<D: AhciDispatchSyscalls>(
        &mut self,
        syscalls: &mut D,
        request: &mut [u8; AHCI_DISPATCH_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
        scratch: &mut [u8],
    ) -> Result<(), AhciDispatchServiceError<D::Error>> {
        AhciDispatchService::new(core::slice::from_ref(&self.device), &mut self.backend)
            .serve_one(syscalls, request, capability_tokens, scratch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        reconstruct_installed_ahci_port, AhciAbarMapping, AhciDataDmaRegion, AhciDmaRegion,
        AhciMappedDataBuffer, AhciPortDmaLayout, AhciServiceCpuMapping, AhciServiceLaunchRecord,
        ReceivedAhciDispatchEnvelope,
    };
    use mrml_interface_storage_block_provider_v1::{
        OpaqueHandle, BLOCK_DEVICE_FLAG_FLUSH, BLOCK_DEVICE_FLAG_RESET,
    };
    use mrml_kernel::{Capability, CapabilityError, ObjectId, Rights};

    #[repr(align(4096))]
    struct Page([u8; 4096]);

    struct Registers;
    impl AhciRegisterIo for Registers {
        fn read_u32(&mut self, offset: u32) -> Result<u32, ()> {
            Ok(if offset == 0x118 { 0x11 } else { 0 })
        }
        fn write_u32(&mut self, _: u32, _: u32) -> Result<(), ()> {
            Ok(())
        }
    }
    impl AhciResetIo for Registers {
        fn delay_microseconds(&mut self, _: u32) -> Result<(), ()> {
            Ok(())
        }
    }

    struct BusyRegisters;
    impl AhciRegisterIo for BusyRegisters {
        fn read_u32(&mut self, offset: u32) -> Result<u32, ()> {
            Ok(if offset == 0x118 { 0x10 } else { 0 })
        }
        fn write_u32(&mut self, _: u32, _: u32) -> Result<(), ()> {
            panic!("preparation must not write a non-idle port")
        }
    }

    struct InvalidEnvelope;
    unsafe impl AhciDispatchSyscalls for InvalidEnvelope {
        type Error = ();

        fn receive(
            &mut self,
            _: &mut [u8; AHCI_DISPATCH_REQUEST_BYTES],
            _: &mut [u64; 1],
        ) -> Result<ReceivedAhciDispatchEnvelope, Self::Error> {
            Ok(ReceivedAhciDispatchEnvelope {
                payload_length: AHCI_DISPATCH_REQUEST_BYTES + 1,
                capability_count: 0,
            })
        }

        fn read_shared(
            &mut self,
            _: Capability,
            _: u64,
            _: &mut [u8],
        ) -> Result<(), Self::Error> {
            panic!("invalid envelope must not read shared memory")
        }

        fn write_shared(
            &mut self,
            _: Capability,
            _: u64,
            _: &[u8],
        ) -> Result<(), Self::Error> {
            panic!("invalid envelope must not write shared memory")
        }

        fn release_received(&mut self, _: Capability) -> Result<(), Self::Error> {
            panic!("invalid envelope must not release a capability")
        }

        fn send_response(
            &mut self,
            _: &[u8; mrml_interface_storage_block_provider_v1::READ_RESPONSE_BYTES],
        ) -> Result<(), Self::Error> {
            panic!("invalid envelope must not send a response")
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

    fn launch_with_mappings(bases: [u64; 4]) -> InstalledAhciServiceLaunch {
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
                AhciServiceCpuMapping::new(1, bases[0]).unwrap(),
                AhciServiceCpuMapping::new(2, bases[1]).unwrap(),
                AhciServiceCpuMapping::new(3, bases[2]).unwrap(),
                AhciServiceCpuMapping::new(4, bases[3]).unwrap(),
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

    fn launch() -> InstalledAhciServiceLaunch {
        launch_with_mappings([0x30_0000, 0x31_0000, 0x32_0000, 0x40_0000])
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

    #[test]
    fn assembled_state_bounds_one_dispatch_and_retains_backend_owner() {
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
        let mut authorizer = Authorizer {
            object: ObjectId(23),
            calls: 0,
            reject: false,
        };
        let mut state = AhciNativeServiceState::new(
            &mut authorizer,
            installed,
            owner,
            Registers,
            command_memory,
            data_io,
        )
        .unwrap();
        let mut request = [0xa5; AHCI_DISPATCH_REQUEST_BYTES];
        let mut tokens = [u64::MAX];
        let mut scratch = [0xcc; 512];
        assert_eq!(
            state.serve_one(
                &mut InvalidEnvelope,
                &mut request,
                &mut tokens,
                &mut scratch,
            ),
            Err(AhciDispatchServiceError::InvalidEnvelope)
        );
        assert_eq!(request, [0; AHCI_DISPATCH_REQUEST_BYTES]);
        assert_eq!(tokens, [0]);
        assert_eq!(scratch, [0; 512]);
        let (_, backend) = state.into_parts();
        assert!(backend.is_available());
    }

    #[test]
    fn installed_preparation_publishes_only_complete_service_state() {
        let mut pages = [Page([0; 4096]), Page([0; 4096]), Page([0; 4096]), Page([0; 4096])];
        let bases = pages.each_mut().map(|page| page.0.as_mut_ptr() as u64);
        let installed = launch_with_mappings(bases);
        let mut authorizer = Authorizer {
            object: ObjectId(23),
            calls: 0,
            reject: false,
        };
        let state = unsafe {
            prepare_installed_ahci_service_state(
                &mut authorizer,
                installed,
                Registers,
                Sync,
            )
        }
        .unwrap();
        assert_eq!(state.device(), installed.record().device());
        let (_, backend) = state.into_parts();
        assert!(backend.is_available());
        drop(backend);
        assert_eq!(authorizer.calls, 2);

        let mut denied_authorizer = Authorizer {
            object: ObjectId(23),
            calls: 0,
            reject: false,
        };
        let result = unsafe {
            prepare_installed_ahci_service_state(
                &mut denied_authorizer,
                installed,
                BusyRegisters,
                Sync,
            )
        };
        assert!(matches!(
            result,
            Err(AhciNativeServicePreparationError::ActivePort(
                AhciNativePortReconstructionError::PortNotIdle
            ))
        ));
        assert_eq!(denied_authorizer.calls, 0);
    }
}
