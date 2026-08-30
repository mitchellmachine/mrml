//! Exact assembly of installed AHCI mechanism state for service dispatch.

use crate::{
    ActiveAhciPort, AhciCommandBlockBackend, AhciDataBufferSync, AhciDataCapabilityAuthorizer,
    AhciDispatchService, AhciDispatchServiceError, AhciDispatchSyscalls, AhciMappedCommandMemory,
    AhciMappedDataBuffer, AhciNativeMappedMemory, AhciNativeMappedMemoryError,
    AhciNativePortReconstructionError, AhciRawSyscall, AhciRegisterIo, AhciResetIo,
    AhciServiceBootstrapError, AhciServiceEntryRegisters, AhciUserspaceSyscalls,
    InstalledAhciServiceLaunch, AHCI_DISPATCH_REQUEST_BYTES, AHCI_SERVICE_LAUNCH_BYTES,
    bootstrap_installed_ahci_entry, reconstruct_installed_ahci_port,
};
use mrml_interface_storage_block_provider_v1::BlockProviderDevice;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciNativeServiceStateError {
    BackendBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciNativeServicePreparationError {
    Bootstrap(AhciServiceBootstrapError),
    CoherenceAdmission,
    RegisterMapping,
    MappedMemory(AhciNativeMappedMemoryError),
    ActivePort(AhciNativePortReconstructionError),
    ServiceState(AhciNativeServiceStateError),
}

/// Authenticates and prepares a service whose exact x86-64 DMA mapping has
/// already been proven hardware coherent by the platform owner.
///
/// # Safety
///
/// In addition to [`bootstrap_and_prepare_installed_ahci_service`], the caller
/// must satisfy [`crate::AhciX86CoherentDataSync::new`] for the launch data
/// extent. `register_factory` must construct only the exact launch-bound ABAR
/// view it receives and retain exclusive device assignment. This function does
/// not create either form of platform evidence.
#[cfg(target_arch = "x86_64")]
pub unsafe fn bootstrap_and_prepare_x86_coherent_ahci_service<'a, 'm, A, B, R, F>(
    syscalls: &mut AhciUserspaceSyscalls<B>,
    entry: AhciServiceEntryRegisters,
    launch_scratch: &mut [u8; AHCI_SERVICE_LAUNCH_BYTES],
    capabilities: &'a mut A,
    register_factory: F,
) -> Result<
    AhciNativeServiceState<'a, 'm, A, R, crate::AhciX86CoherentDataSync>,
    AhciNativeServicePreparationError,
>
where
    A: AhciDataCapabilityAuthorizer,
    B: AhciRawSyscall,
    R: AhciRegisterIo,
    F: FnOnce(crate::AhciAbarMapping) -> Option<R>,
{
    let launch = bootstrap_installed_ahci_entry(syscalls, entry, launch_scratch)
        .map_err(AhciNativeServicePreparationError::Bootstrap)?;
    let registers = register_factory(launch.record().mapping())
        .ok_or(AhciNativeServicePreparationError::RegisterMapping)?;
    let sync = unsafe { crate::AhciX86CoherentDataSync::new(launch.record().data()) }
        .ok_or(AhciNativeServicePreparationError::CoherenceAdmission)?;
    unsafe { prepare_installed_ahci_service_state(capabilities, launch, registers, sync) }
}

/// Prepares the concrete native x86-64 register path with an injected clock.
///
/// # Safety
///
/// The safety requirements of
/// [`bootstrap_and_prepare_x86_coherent_ahci_service`] apply. The decoded ABAR
/// virtual range must be a live exclusive volatile mapping. `delay` must use a
/// platform-owned monotonic source and satisfy [`crate::AhciMonotonicDelay`].
#[cfg(target_arch = "x86_64")]
pub unsafe fn bootstrap_and_prepare_native_x86_coherent_ahci_service<'a, 'm, A, B, D>(
    syscalls: &mut AhciUserspaceSyscalls<B>,
    entry: AhciServiceEntryRegisters,
    launch_scratch: &mut [u8; AHCI_SERVICE_LAUNCH_BYTES],
    capabilities: &'a mut A,
    delay: D,
) -> Result<
    AhciNativeServiceState<
        'a,
        'm,
        A,
        crate::AhciPlatformIo<crate::NativeAhciRegisterIo, D>,
        crate::AhciX86CoherentDataSync,
    >,
    AhciNativeServicePreparationError,
>
where
    A: AhciDataCapabilityAuthorizer,
    B: AhciRawSyscall,
    D: crate::AhciMonotonicDelay,
{
    let launch = bootstrap_installed_ahci_entry(syscalls, entry, launch_scratch)
        .map_err(AhciNativeServicePreparationError::Bootstrap)?;
    unsafe {
        prepare_bootstrapped_native_x86_coherent_ahci_service(
            capabilities,
            launch,
            delay,
        )
    }
}

/// Prepares one already-authenticated launch after its authorizer is bound.
///
/// This separation lets native entry code bootstrap the launch, construct an
/// [`crate::AhciInstalledDataAuthorizer`] from its exact roles and data object,
/// and then borrow that authorizer for the complete service-state lifetime.
///
/// # Safety
///
/// The launch must be the result of the current entry's authenticated bootstrap.
/// Its ABAR and CPU mappings must remain live and exclusive, its data extent
/// must be platform-proven coherent, and `delay` must satisfy
/// [`crate::AhciMonotonicDelay`].
#[cfg(target_arch = "x86_64")]
pub unsafe fn prepare_bootstrapped_native_x86_coherent_ahci_service<'a, 'm, A, D>(
    capabilities: &'a mut A,
    launch: InstalledAhciServiceLaunch,
    delay: D,
) -> Result<
    AhciNativeServiceState<
        'a,
        'm,
        A,
        crate::AhciPlatformIo<crate::NativeAhciRegisterIo, D>,
        crate::AhciX86CoherentDataSync,
    >,
    AhciNativeServicePreparationError,
>
where
    A: AhciDataCapabilityAuthorizer,
    D: crate::AhciMonotonicDelay,
{
    let registers = unsafe {
        crate::AhciPlatformIo::from_installed_mapping(launch.record().mapping(), delay)
    }
    .ok_or(AhciNativeServicePreparationError::RegisterMapping)?;
    let sync = unsafe { crate::AhciX86CoherentDataSync::new(launch.record().data()) }
        .ok_or(AhciNativeServicePreparationError::CoherenceAdmission)?;
    unsafe { prepare_installed_ahci_service_state(capabilities, launch, registers, sync) }
}

/// Authenticates the native entry projection, wipes its copied bytes, and then
/// prepares the complete installed service state.
///
/// # Safety
///
/// `entry` must come from [`AhciServiceEntryRegisters::from_installed_registers`]
/// at the kernel-installed entry point. The mapping and ABAR requirements of
/// [`prepare_installed_ahci_service_state`] also apply.
pub unsafe fn bootstrap_and_prepare_installed_ahci_service<'a, 'm, A, B, R, S>(
    syscalls: &mut AhciUserspaceSyscalls<B>,
    entry: AhciServiceEntryRegisters,
    launch_scratch: &mut [u8; AHCI_SERVICE_LAUNCH_BYTES],
    capabilities: &'a mut A,
    registers: R,
    sync: S,
) -> Result<AhciNativeServiceState<'a, 'm, A, R, S>, AhciNativeServicePreparationError>
where
    A: AhciDataCapabilityAuthorizer,
    B: AhciRawSyscall,
    R: AhciRegisterIo,
{
    let launch = bootstrap_installed_ahci_entry(syscalls, entry, launch_scratch)
        .map_err(AhciNativeServicePreparationError::Bootstrap)?;
    unsafe { prepare_installed_ahci_service_state(capabilities, launch, registers, sync) }
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

    #[derive(Default)]
    struct Delay;
    impl crate::AhciMonotonicDelay for Delay {
        fn delay_at_least_microseconds(&mut self, _: u32) -> Result<(), ()> {
            Ok(())
        }
    }

    struct BootRaw {
        bytes: [u8; AHCI_SERVICE_LAUNCH_BYTES],
        calls: usize,
    }

    struct AuthorizeRaw {
        frames: [Option<crate::AhciSyscallFrame>; 2],
        statuses: [u64; 2],
        calls: usize,
    }
    unsafe impl AhciRawSyscall for AuthorizeRaw {
        unsafe fn invoke(&mut self, frame: &mut crate::AhciSyscallFrame) {
            self.frames[self.calls] = Some(*frame);
            frame.rax = self.statuses[self.calls];
            self.calls += 1;
        }
    }
    unsafe impl AhciRawSyscall for BootRaw {
        unsafe fn invoke(&mut self, frame: &mut crate::AhciSyscallFrame) {
            self.calls += 1;
            assert_eq!(frame.rax, 7);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.bytes.as_ptr(),
                    frame.rdx as *mut u8,
                    self.bytes.len(),
                )
            };
            frame.rax = 0;
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

    fn launch_with_ranges(
        bases: [u64; 4],
        abar_virtual_base: u64,
    ) -> InstalledAhciServiceLaunch {
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
                virtual_base: abar_virtual_base,
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

    fn launch_with_mappings(bases: [u64; 4]) -> InstalledAhciServiceLaunch {
        launch_with_ranges(bases, 0x20_0000)
    }

    fn launch() -> InstalledAhciServiceLaunch {
        launch_with_mappings([0x30_0000, 0x31_0000, 0x32_0000, 0x40_0000])
    }

    fn entry(installed: InstalledAhciServiceLaunch) -> AhciServiceEntryRegisters {
        unsafe {
            AhciServiceEntryRegisters::from_installed_registers(
                1,
                2,
                3,
                (10 << 32) | 1,
                AHCI_SERVICE_LAUNCH_BYTES as u64,
                9,
                installed.device().token(),
                installed.command_list().token(),
                installed.received_fis().token(),
                installed.command_tables().token(),
                installed.device_write_data().token(),
                installed.device_read_data().token(),
            )
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

    #[test]
    fn authenticated_entry_wipes_launch_copy_before_state_publication() {
        let mut pages = [Page([0; 4096]), Page([0; 4096]), Page([0; 4096]), Page([0; 4096])];
        let bases = pages.each_mut().map(|page| page.0.as_mut_ptr() as u64);
        let installed = launch_with_mappings(bases);
        let entry = entry(installed);
        let mut syscalls = AhciUserspaceSyscalls::new(
            BootRaw {
                bytes: installed.record().encode(),
                calls: 0,
            },
            1,
            2,
        )
        .unwrap();
        let mut launch_scratch = [0xa5; AHCI_SERVICE_LAUNCH_BYTES];
        let mut authorizer = Authorizer {
            object: ObjectId(23),
            calls: 0,
            reject: false,
        };
        let state = unsafe {
            bootstrap_and_prepare_installed_ahci_service(
                &mut syscalls,
                entry,
                &mut launch_scratch,
                &mut authorizer,
                Registers,
                Sync,
            )
        }
        .unwrap();
        assert_eq!(launch_scratch, [0; AHCI_SERVICE_LAUNCH_BYTES]);
        assert_eq!(state.device(), installed.record().device());
        drop(state);
        assert_eq!(authorizer.calls, 2);
        assert_eq!(syscalls.into_raw().calls, 1);
    }

    #[test]
    fn coherent_entry_selects_visibility_adapter_at_single_unsafe_boundary() {
        let mut pages = [Page([0; 4096]), Page([0; 4096]), Page([0; 4096]), Page([0; 4096])];
        let bases = pages.each_mut().map(|page| page.0.as_mut_ptr() as u64);
        let installed = launch_with_mappings(bases);
        let mut syscalls = AhciUserspaceSyscalls::new(
            BootRaw {
                bytes: installed.record().encode(),
                calls: 0,
            },
            1,
            2,
        )
        .unwrap();
        let mut launch_scratch = [0xa5; AHCI_SERVICE_LAUNCH_BYTES];
        let mut authorizer = Authorizer {
            object: ObjectId(23),
            calls: 0,
            reject: false,
        };
        let state = unsafe {
            bootstrap_and_prepare_x86_coherent_ahci_service(
                &mut syscalls,
                entry(installed),
                &mut launch_scratch,
                &mut authorizer,
                |mapping| (mapping == installed.record().mapping()).then_some(Registers),
            )
        }
        .unwrap();
        assert_eq!(launch_scratch, [0; AHCI_SERVICE_LAUNCH_BYTES]);
        assert_eq!(state.device(), installed.record().device());
        drop(state);
        assert_eq!(authorizer.calls, 2);
        assert_eq!(syscalls.into_raw().calls, 1);

        let mut rejected_syscalls = AhciUserspaceSyscalls::new(
            BootRaw {
                bytes: installed.record().encode(),
                calls: 0,
            },
            1,
            2,
        )
        .unwrap();
        let mut rejected_scratch = [0xa5; AHCI_SERVICE_LAUNCH_BYTES];
        let mut rejected_authorizer = Authorizer {
            object: ObjectId(23),
            calls: 0,
            reject: false,
        };
        let rejected = unsafe {
            bootstrap_and_prepare_x86_coherent_ahci_service(
                &mut rejected_syscalls,
                entry(installed),
                &mut rejected_scratch,
                &mut rejected_authorizer,
                |_| None::<Registers>,
            )
        };
        assert!(matches!(
            rejected,
            Err(AhciNativeServicePreparationError::RegisterMapping)
        ));
        assert_eq!(rejected_scratch, [0; AHCI_SERVICE_LAUNCH_BYTES]);
        assert_eq!(rejected_authorizer.calls, 0);
        assert_eq!(rejected_syscalls.into_raw().calls, 1);
    }

    #[test]
    fn native_entry_constructs_volatile_abar_only_from_decoded_mapping() {
        let mut pages = [Page([0; 4096]), Page([0; 4096]), Page([0; 4096]), Page([0; 4096])];
        let bases = pages.each_mut().map(|page| page.0.as_mut_ptr() as u64);
        let mut abar = [Page([0; 4096]), Page([0; 4096])];
        abar[0].0[0x118..0x11c].copy_from_slice(&0x11_u32.to_ne_bytes());
        let installed = launch_with_ranges(bases, abar[0].0.as_mut_ptr() as u64);
        let mut syscalls = AhciUserspaceSyscalls::new(
            BootRaw {
                bytes: installed.record().encode(),
                calls: 0,
            },
            1,
            2,
        )
        .unwrap();
        let mut launch_scratch = [0xa5; AHCI_SERVICE_LAUNCH_BYTES];
        let mut authorizer = Authorizer {
            object: ObjectId(23),
            calls: 0,
            reject: false,
        };
        let state = unsafe {
            bootstrap_and_prepare_native_x86_coherent_ahci_service(
                &mut syscalls,
                entry(installed),
                &mut launch_scratch,
                &mut authorizer,
                Delay,
            )
        }
        .unwrap();
        assert_eq!(launch_scratch, [0; AHCI_SERVICE_LAUNCH_BYTES]);
        assert_eq!(state.device(), installed.record().device());
        drop(state);
        assert_eq!(authorizer.calls, 2);
        assert_eq!(syscalls.into_raw().calls, 1);
    }

    #[test]
    fn bootstrapped_launch_can_bind_authorizer_before_native_state_borrow() {
        let mut pages = [Page([0; 4096]), Page([0; 4096]), Page([0; 4096]), Page([0; 4096])];
        let bases = pages.each_mut().map(|page| page.0.as_mut_ptr() as u64);
        let mut abar = [Page([0; 4096]), Page([0; 4096])];
        abar[0].0[0x118..0x11c].copy_from_slice(&0x11_u32.to_ne_bytes());
        let expected = launch_with_ranges(bases, abar[0].0.as_mut_ptr() as u64);
        let mut bootstrap_syscalls = AhciUserspaceSyscalls::new(
            BootRaw {
                bytes: expected.record().encode(),
                calls: 0,
            },
            1,
            2,
        )
        .unwrap();
        let mut launch_scratch = [0xa5; AHCI_SERVICE_LAUNCH_BYTES];
        let launch = bootstrap_installed_ahci_entry(
            &mut bootstrap_syscalls,
            entry(expected),
            &mut launch_scratch,
        )
        .unwrap();
        let mut authorizer = crate::AhciInstalledDataAuthorizer::from_installed_launch(
            AuthorizeRaw {
                frames: [None; 2],
                statuses: [0; 2],
                calls: 0,
            },
            launch,
        );
        let state = unsafe {
            prepare_bootstrapped_native_x86_coherent_ahci_service(
                &mut authorizer,
                launch,
                Delay,
            )
        }
        .unwrap();
        assert_eq!(launch_scratch, [0; AHCI_SERVICE_LAUNCH_BYTES]);
        assert_eq!(state.device(), expected.record().device());
        drop(state);
        assert_eq!(authorizer.into_raw().calls, 2);
        assert_eq!(bootstrap_syscalls.into_raw().calls, 1);
    }
}
