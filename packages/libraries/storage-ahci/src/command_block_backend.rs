//! Reusable single-port AHCI command backend for canonical block I/O.
//!
//! The backend owns the active-port typestate and an exact pre-authorized data
//! DMA extent. It composes buffer synchronization, command preparation,
//! bounded execution, slot recycling, and data sanitization without exposing
//! those mechanisms to the storage service.

use crate::{
    ActiveAhciPort, AhciAbarMapping, AhciAtaCommand, AhciBlockControlBackend,
    AhciBlockControlError, AhciBlockIoBackend, AhciBlockIoError, AhciCommandBuildFailure,
    AhciCommandMemoryIo, AhciDataDmaRegion, AhciFlushFailure, AhciRegisterIo, AhciResetIo,
    execute_ahci_dma_command, flush_ahci_cache, prepare_ahci_dma_command,
    recycle_ahci_command_slot, reset_ahci_sata_port,
};
use mrml_interface_storage_block_provider_v1::BlockProviderDevice;
use mrml_kernel::{Capability, CapabilityError, CapabilitySpace, ObjectId, Rights};

/// Exact userspace-facing authorization needed by the AHCI data path.
pub trait AhciDataCapabilityAuthorizer {
    fn authorize_exact(
        &mut self,
        capability: Capability,
        rights: Rights,
    ) -> Result<ObjectId, CapabilityError>;
}

impl<const N: usize> AhciDataCapabilityAuthorizer for CapabilitySpace<N> {
    fn authorize_exact(
        &mut self,
        capability: Capability,
        rights: Rights,
    ) -> Result<ObjectId, CapabilityError> {
        CapabilitySpace::authorize_exact(self, capability, rights)
    }
}

pub trait AhciDataBufferIo {
    /// Zeroes the exact range and makes it device-writable.
    fn prepare_read(&mut self, region: AhciDataDmaRegion) -> Result<(), ()>;
    /// Copies exact input and makes it device-readable.
    fn prepare_write(&mut self, region: AhciDataDmaRegion, input: &[u8]) -> Result<(), ()>;
    /// Makes device writes CPU-visible and copies exactly the completed range.
    fn complete_read(&mut self, region: AhciDataDmaRegion, output: &mut [u8]) -> Result<(), ()>;
    /// Completes CPU-side synchronization after a device read of the range.
    fn complete_write(&mut self, region: AhciDataDmaRegion) -> Result<(), ()>;
    /// Zeroes the range and completes all CPU/device synchronization for reuse.
    fn sanitize(&mut self, region: AhciDataDmaRegion) -> Result<(), ()>;
}

pub struct AhciCommandBlockBackend<'a, A, R, M, D> {
    capabilities: &'a mut A,
    session: mrml_interface_storage_block_provider_v1::OpaqueHandle,
    media_generation: u64,
    read_data_capability: Capability,
    write_data_capability: Capability,
    data_region: AhciDataDmaRegion,
    mapping: AhciAbarMapping,
    owner: Option<ActiveAhciPort>,
    registers: R,
    memory: M,
    data_io: D,
    durability_serial: u64,
}

/// Exact live mechanism state handed to the service teardown path.
pub struct AhciCommandBackendTeardown<R, M, D> {
    mapping: AhciAbarMapping,
    port: ActiveAhciPort,
    data_region: AhciDataDmaRegion,
    registers: R,
    command_memory: M,
    data_io: D,
}

impl<R, M, D> AhciCommandBackendTeardown<R, M, D> {
    pub const fn mapping(&self) -> AhciAbarMapping {
        self.mapping
    }

    pub(crate) const fn port(&self) -> &ActiveAhciPort {
        &self.port
    }

    pub const fn data_region(&self) -> AhciDataDmaRegion {
        self.data_region
    }

    pub(crate) fn into_parts(
        self,
    ) -> (AhciAbarMapping, ActiveAhciPort, AhciDataDmaRegion, R, M, D) {
        (
            self.mapping,
            self.port,
            self.data_region,
            self.registers,
            self.command_memory,
            self.data_io,
        )
    }
}

/// State retained when a fail-stopped backend has lost its active-port owner.
pub struct QuarantinedAhciCommandBackend<R, M, D> {
    mapping: AhciAbarMapping,
    data_region: AhciDataDmaRegion,
    registers: R,
    command_memory: M,
    data_io: D,
}

impl<R, M, D> QuarantinedAhciCommandBackend<R, M, D> {
    pub const fn mapping(&self) -> AhciAbarMapping {
        self.mapping
    }

    pub const fn data_region(&self) -> AhciDataDmaRegion {
        self.data_region
    }

    pub fn into_parts(self) -> (AhciAbarMapping, AhciDataDmaRegion, R, M, D) {
        (
            self.mapping,
            self.data_region,
            self.registers,
            self.command_memory,
            self.data_io,
        )
    }
}

impl<'a, A: AhciDataCapabilityAuthorizer, R, M, D> AhciCommandBlockBackend<'a, A, R, M, D> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        capabilities: &'a mut A,
        session: mrml_interface_storage_block_provider_v1::OpaqueHandle,
        media_generation: u64,
        read_data_capability: Capability,
        write_data_capability: Capability,
        data_region: AhciDataDmaRegion,
        mapping: AhciAbarMapping,
        owner: ActiveAhciPort,
        registers: R,
        memory: M,
        data_io: D,
    ) -> Option<Self> {
        let read_rights = Rights::PIN.union(Rights::MAP).union(Rights::WRITE);
        let write_rights = Rights::PIN.union(Rights::MAP).union(Rights::READ);
        if media_generation == 0
            || data_region.bytes == 0
            || data_region.bytes > 1024 * 1024
            || capabilities
                .authorize_exact(read_data_capability, read_rights)
                .ok()
                != Some(data_region.memory_object)
            || owner.layout().device_object != mapping.device_object
            || owner.layout().configuration_generation != mapping.configuration_generation
            || owner.layout().mapping_generation != mapping.mapping_generation
            || capabilities
                .authorize_exact(write_data_capability, write_rights)
                .ok()
                != Some(data_region.memory_object)
        {
            return None;
        }
        Some(Self {
            capabilities,
            session,
            media_generation,
            read_data_capability,
            write_data_capability,
            data_region,
            mapping,
            owner: Some(owner),
            registers,
            memory,
            data_io,
            durability_serial: 0,
        })
    }

    pub const fn is_available(&self) -> bool {
        self.owner.is_some()
    }

    pub fn into_teardown(
        self,
    ) -> Result<AhciCommandBackendTeardown<R, M, D>, QuarantinedAhciCommandBackend<R, M, D>> {
        let Self {
            mapping,
            owner,
            data_region,
            registers,
            memory,
            data_io,
            ..
        } = self;
        match owner {
            Some(port) => Ok(AhciCommandBackendTeardown {
                mapping,
                port,
                data_region,
                registers,
                command_memory: memory,
                data_io,
            }),
            None => Err(QuarantinedAhciCommandBackend {
                mapping,
                data_region,
                registers,
                command_memory: memory,
                data_io,
            }),
        }
    }
}

impl<A: AhciDataCapabilityAuthorizer, R: AhciResetIo, M: AhciCommandMemoryIo, D: AhciDataBufferIo>
    AhciBlockControlBackend for AhciCommandBlockBackend<'_, A, R, M, D>
{
    fn flush(&mut self, device: BlockProviderDevice) -> Result<u64, AhciBlockControlError> {
        if device.session != self.session || device.media_generation != self.media_generation {
            return Err(AhciBlockControlError::IoFailure);
        }
        let owner = self.owner.take().ok_or(AhciBlockControlError::IoFailure)?;
        match flush_ahci_cache(owner, &mut self.registers, &mut self.memory) {
            Ok(owner) => self.owner = Some(owner),
            Err(AhciFlushFailure::Untouched { owner, .. }) => {
                self.owner = Some(owner);
                return Err(AhciBlockControlError::IoFailure);
            }
            Err(AhciFlushFailure::Quarantined { .. }) => {
                return Err(AhciBlockControlError::IoFailure);
            }
        }
        self.durability_serial = self.durability_serial.checked_add(1).ok_or_else(|| {
            self.owner = None;
            AhciBlockControlError::IoFailure
        })?;
        Ok(self.durability_serial)
    }

    fn reset(&mut self, device: BlockProviderDevice) -> Result<u64, AhciBlockControlError> {
        if device.session != self.session || device.media_generation != self.media_generation {
            return Err(AhciBlockControlError::CleanupIncomplete);
        }
        let successor = self
            .media_generation
            .checked_add(1)
            .ok_or(AhciBlockControlError::CleanupIncomplete)?;
        if self.data_io.sanitize(self.data_region).is_err() {
            self.owner = None;
            return Err(AhciBlockControlError::CleanupIncomplete);
        }
        let owner = self
            .owner
            .take()
            .ok_or(AhciBlockControlError::CleanupIncomplete)?;
        let owner =
            reset_ahci_sata_port(self.mapping, owner, &mut self.registers, &mut self.memory)
                .map_err(|_| AhciBlockControlError::CleanupIncomplete)?;
        self.owner = Some(owner);
        self.media_generation = successor;
        Ok(successor)
    }
}

impl<
    A: AhciDataCapabilityAuthorizer,
    R: AhciRegisterIo,
    M: AhciCommandMemoryIo,
    D: AhciDataBufferIo,
> AhciBlockIoBackend for AhciCommandBlockBackend<'_, A, R, M, D>
{
    fn read(
        &mut self,
        device: BlockProviderDevice,
        lba: u64,
        sector_count: u32,
        output: &mut [u8],
    ) -> Result<(), AhciBlockIoError> {
        self.execute(
            device,
            lba,
            sector_count,
            AhciAtaCommand::ReadDmaExt,
            None,
            Some(output),
        )
    }

    fn write(
        &mut self,
        device: BlockProviderDevice,
        lba: u64,
        sector_count: u32,
        input: &[u8],
    ) -> Result<(), AhciBlockIoError> {
        self.execute(
            device,
            lba,
            sector_count,
            AhciAtaCommand::WriteDmaExt,
            Some(input),
            None,
        )
    }
}

impl<
    A: AhciDataCapabilityAuthorizer,
    R: AhciRegisterIo,
    M: AhciCommandMemoryIo,
    D: AhciDataBufferIo,
> AhciCommandBlockBackend<'_, A, R, M, D>
{
    fn execute(
        &mut self,
        device: BlockProviderDevice,
        lba: u64,
        sector_count: u32,
        operation: AhciAtaCommand,
        input: Option<&[u8]>,
        output: Option<&mut [u8]>,
    ) -> Result<(), AhciBlockIoError> {
        if device.session != self.session || device.media_generation != self.media_generation {
            return Err(AhciBlockIoError::MediaChanged);
        }
        if device.logical_block_bytes != 512 || sector_count == 0 {
            return Err(AhciBlockIoError::IoFailure);
        }
        let bytes = u64::from(sector_count)
            .checked_mul(512)
            .ok_or(AhciBlockIoError::IoFailure)?;
        if bytes > self.data_region.bytes
            || usize::try_from(bytes).ok()
                != input
                    .map(<[u8]>::len)
                    .or_else(|| output.as_ref().map(|slice| slice.len()))
        {
            return Err(AhciBlockIoError::IoFailure);
        }
        let sector_count = u16::try_from(sector_count).map_err(|_| AhciBlockIoError::IoFailure)?;
        let region = AhciDataDmaRegion {
            bytes,
            ..self.data_region
        };
        match operation {
            AhciAtaCommand::ReadDmaExt => self.data_io.prepare_read(region),
            AhciAtaCommand::WriteDmaExt => self.data_io.prepare_write(region, input.unwrap_or(&[])),
        }
        .map_err(|()| self.fail_stop())?;

        let owner = self.owner.take().ok_or(AhciBlockIoError::IoFailure)?;
        let data_capability = match operation {
            AhciAtaCommand::ReadDmaExt => self.read_data_capability,
            AhciAtaCommand::WriteDmaExt => self.write_data_capability,
        };
        let prepared = match prepare_ahci_dma_command(
            self.capabilities,
            owner,
            data_capability,
            region,
            operation,
            0,
            lba,
            sector_count,
            &mut self.registers,
            &mut self.memory,
        ) {
            Ok(prepared) => prepared,
            Err(failure) => {
                if let AhciCommandBuildFailure::Untouched { owner, .. } = failure {
                    self.owner = Some(owner);
                }
                if self.data_io.sanitize(region).is_err() {
                    self.owner = None;
                }
                return Err(AhciBlockIoError::IoFailure);
            }
        };
        let completion =
            match execute_ahci_dma_command(prepared, &mut self.registers, &mut self.memory) {
                Ok(completion) => completion,
                Err(_) => {
                    let _ = self.data_io.sanitize(region);
                    return Err(AhciBlockIoError::IoFailure);
                }
            };
        let recycled = match recycle_ahci_command_slot(completion, &mut self.memory) {
            Ok(recycled) => recycled,
            Err(_) => {
                let _ = self.data_io.sanitize(region);
                return Err(AhciBlockIoError::IoFailure);
            }
        };
        let (owner, _) = recycled.into_parts();
        self.owner = Some(owner);

        let completed = match operation {
            AhciAtaCommand::ReadDmaExt => self.data_io.complete_read(region, output.unwrap()),
            AhciAtaCommand::WriteDmaExt => self.data_io.complete_write(region),
        };
        if completed.is_err() || self.data_io.sanitize(region).is_err() {
            self.owner = None;
            return Err(AhciBlockIoError::IoFailure);
        }
        Ok(())
    }

    fn fail_stop(&mut self) -> AhciBlockIoError {
        self.owner = None;
        AhciBlockIoError::IoFailure
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AhciDmaRegion, AhciPortDmaLayout};
    use core::cell::Cell;
    use mrml_interface_storage_block_provider_v1::OpaqueHandle;
    use mrml_kernel::{ObjectId, Rights};

    struct Registers {
        words: [u32; 16],
        issued_reads: u32,
    }

    impl Registers {
        fn ready() -> Self {
            let mut words = [0; 16];
            words[0x18 / 4] = (1 << 0) | (1 << 4);
            words[0x24 / 4] = crate::AHCI_SATA_SIGNATURE;
            words[0x28 / 4] = 3 | (2 << 4) | (1 << 8);
            Self {
                words,
                issued_reads: 0,
            }
        }
    }

    impl AhciRegisterIo for Registers {
        fn read_u32(&mut self, offset: u32) -> Result<u32, ()> {
            let register = offset.checked_sub(0x100).ok_or(())?;
            if register == 0x38 && self.words[0x38 / 4] != 0 {
                self.issued_reads += 1;
                if self.issued_reads % 2 == 0 {
                    self.words[0x38 / 4] = 0;
                }
            }
            self.words.get(register as usize / 4).copied().ok_or(())
        }
        fn write_u32(&mut self, offset: u32, value: u32) -> Result<(), ()> {
            let register = offset.checked_sub(0x100).ok_or(())?;
            *self.words.get_mut(register as usize / 4).ok_or(())? = value;
            Ok(())
        }
    }
    impl AhciResetIo for Registers {
        fn delay_microseconds(&mut self, microseconds: u32) -> Result<(), ()> {
            (microseconds >= 1_000).then_some(()).ok_or(())
        }
    }

    struct Memory {
        list: [u32; 256],
        fis: [u32; 64],
        tables: [u32; 64],
        prdbc_reads: usize,
    }

    impl Memory {
        fn initialized() -> Self {
            let mut list = [0; 256];
            list[2] = 0x3000;
            Self {
                list,
                fis: [0; 64],
                tables: [0; 64],
                prdbc_reads: 0,
            }
        }
    }

    impl AhciCommandMemoryIo for Memory {
        fn read_u32(&mut self, region: AhciDmaRegion, offset: u64) -> Result<u32, ()> {
            if region.memory_object == ObjectId(20) && offset == 4 {
                let value = if self.list[0] & (1 << 16) != 0 && self.prdbc_reads % 4 == 2 {
                    512
                } else {
                    self.list[1]
                };
                self.prdbc_reads += 1;
                return Ok(value);
            }
            let index = usize::try_from(offset / 4).map_err(|_| ())?;
            match region.memory_object {
                ObjectId(20) => self.list.get(index).copied().ok_or(()),
                ObjectId(21) => self.fis.get(index).copied().ok_or(()),
                ObjectId(22) => self.tables.get(index).copied().ok_or(()),
                _ => Err(()),
            }
        }
        fn write_u32(&mut self, region: AhciDmaRegion, offset: u64, value: u32) -> Result<(), ()> {
            let index = usize::try_from(offset / 4).map_err(|_| ())?;
            match region.memory_object {
                ObjectId(20) => *self.list.get_mut(index).ok_or(())? = value,
                ObjectId(21) => *self.fis.get_mut(index).ok_or(())? = value,
                ObjectId(22) => *self.tables.get_mut(index).ok_or(())? = value,
                _ => return Err(()),
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct DataIo {
        staged_writes: usize,
        completed_reads: usize,
        sanitizes: usize,
        reject_sanitize: bool,
    }

    impl AhciDataBufferIo for DataIo {
        fn prepare_read(&mut self, _: AhciDataDmaRegion) -> Result<(), ()> {
            Ok(())
        }
        fn prepare_write(&mut self, _: AhciDataDmaRegion, input: &[u8]) -> Result<(), ()> {
            if input != [0xa5; 512] {
                return Err(());
            }
            self.staged_writes += 1;
            Ok(())
        }
        fn complete_read(&mut self, _: AhciDataDmaRegion, output: &mut [u8]) -> Result<(), ()> {
            output.fill(0x5a);
            self.completed_reads += 1;
            Ok(())
        }
        fn complete_write(&mut self, _: AhciDataDmaRegion) -> Result<(), ()> {
            Ok(())
        }
        fn sanitize(&mut self, _: AhciDataDmaRegion) -> Result<(), ()> {
            self.sanitizes += 1;
            if self.reject_sanitize {
                Err(())
            } else {
                Ok(())
            }
        }
    }

    fn layout() -> AhciPortDmaLayout {
        AhciPortDmaLayout {
            device_object: ObjectId(10),
            configuration_generation: 7,
            mapping_generation: 9,
            port: 0,
            command_slot_count: 1,
            command_list: AhciDmaRegion {
                memory_object: ObjectId(20),
                allocation_generation: 1,
                physical_base: 0x1000,
                bytes: 1024,
            },
            received_fis: AhciDmaRegion {
                memory_object: ObjectId(21),
                allocation_generation: 2,
                physical_base: 0x2000,
                bytes: 256,
            },
            command_tables: AhciDmaRegion {
                memory_object: ObjectId(22),
                allocation_generation: 3,
                physical_base: 0x3000,
                bytes: 256,
            },
            dma_generation: 11,
        }
    }

    fn device(session: OpaqueHandle, media_generation: u64) -> BlockProviderDevice {
        BlockProviderDevice {
            session,
            logical_block_bytes: 512,
            flags: 0,
            logical_block_count: 100,
            media_generation,
        }
    }

    fn mapping() -> AhciAbarMapping {
        AhciAbarMapping {
            device_object: ObjectId(10),
            configuration_generation: 7,
            mapping_generation: 9,
            physical_base: 0xf000_0000,
            virtual_base: 0xffff_9000_0000_0000,
            bytes: 0x2000,
        }
    }

    struct Authorizer {
        calls: Cell<usize>,
        object: ObjectId,
    }

    impl AhciDataCapabilityAuthorizer for Authorizer {
        fn authorize_exact(
            &mut self,
            capability: Capability,
            rights: Rights,
        ) -> Result<ObjectId, CapabilityError> {
            let expected = if capability == Capability::from_token(1) {
                Rights::PIN.union(Rights::MAP).union(Rights::WRITE)
            } else if capability == Capability::from_token(2) {
                Rights::PIN.union(Rights::MAP).union(Rights::READ)
            } else {
                return Err(CapabilityError::Invalid);
            };
            if rights != expected {
                return Err(CapabilityError::PermissionDenied);
            }
            self.calls.set(self.calls.get() + 1);
            Ok(self.object)
        }
    }

    #[test]
    fn injected_authorizer_exact_matches_both_directional_data_rights() {
        let data = AhciDataDmaRegion {
            memory_object: ObjectId(40),
            allocation_generation: 5,
            physical_base: 0x8000,
            bytes: 512,
        };
        let mut authorizer = Authorizer {
            calls: Cell::new(0),
            object: ObjectId(40),
        };
        assert!(
            AhciCommandBlockBackend::new(
                &mut authorizer,
                OpaqueHandle::new(4, 7).unwrap(),
                12,
                Capability::from_token(1),
                Capability::from_token(2),
                data,
                mapping(),
                ActiveAhciPort::from_layout(layout()),
                Registers::ready(),
                Memory::initialized(),
                DataIo::default(),
            )
            .is_some()
        );
        assert_eq!(authorizer.calls.get(), 2);

        let mut substituted = Authorizer {
            calls: Cell::new(0),
            object: ObjectId(41),
        };
        assert!(
            AhciCommandBlockBackend::new(
                &mut substituted,
                OpaqueHandle::new(4, 7).unwrap(),
                12,
                Capability::from_token(1),
                Capability::from_token(2),
                data,
                mapping(),
                ActiveAhciPort::from_layout(layout()),
                Registers::ready(),
                Memory::initialized(),
                DataIo::default(),
            )
            .is_none()
        );
        assert_eq!(substituted.calls.get(), 1);
    }

    #[test]
    fn repeated_read_and_write_traverse_complete_owned_lifecycle() {
        let mut capabilities = CapabilitySpace::<2>::new();
        let read_capability = capabilities
            .insert(
                ObjectId(40),
                Rights::PIN.union(Rights::MAP).union(Rights::WRITE),
            )
            .unwrap();
        let write_capability = capabilities
            .insert(
                ObjectId(40),
                Rights::PIN.union(Rights::MAP).union(Rights::READ),
            )
            .unwrap();
        let session = OpaqueHandle::new(4, 7).unwrap();
        let data = AhciDataDmaRegion {
            memory_object: ObjectId(40),
            allocation_generation: 5,
            physical_base: 0x8000,
            bytes: 512,
        };
        let mut backend = AhciCommandBlockBackend::new(
            &mut capabilities,
            session,
            12,
            read_capability,
            write_capability,
            data,
            mapping(),
            ActiveAhciPort::from_layout(layout()),
            Registers::ready(),
            Memory::initialized(),
            DataIo::default(),
        )
        .unwrap();
        let mut output = [0; 512];
        backend
            .read(device(session, 12), 3, 1, &mut output)
            .unwrap();
        assert_eq!(output, [0x5a; 512]);
        backend
            .write(device(session, 12), 4, 1, &[0xa5; 512])
            .unwrap();
        assert_eq!(backend.flush(device(session, 12)), Ok(1));
        assert_eq!(backend.flush(device(session, 12)), Ok(2));
        assert_eq!(backend.reset(device(session, 12)), Ok(13));
        assert_eq!(
            backend.read(device(session, 12), 0, 1, &mut [0; 512]),
            Err(AhciBlockIoError::MediaChanged)
        );
        assert!(backend.is_available());
        let teardown = match backend.into_teardown() {
            Ok(teardown) => teardown,
            Err(_) => panic!("healthy backend must retain its teardown owner"),
        };
        let (_, _, _, _, _, data_io) = teardown.into_parts();
        assert_eq!(
            (
                data_io.completed_reads,
                data_io.staged_writes,
                data_io.sanitizes
            ),
            (1, 1, 3)
        );
    }

    #[test]
    fn stale_media_preserves_owner_but_uncertain_sanitization_fail_stops() {
        let mut capabilities = CapabilitySpace::<2>::new();
        let read_capability = capabilities
            .insert(
                ObjectId(40),
                Rights::PIN.union(Rights::MAP).union(Rights::WRITE),
            )
            .unwrap();
        let write_capability = capabilities
            .insert(
                ObjectId(40),
                Rights::PIN.union(Rights::MAP).union(Rights::READ),
            )
            .unwrap();
        let session = OpaqueHandle::new(4, 7).unwrap();
        let data = AhciDataDmaRegion {
            memory_object: ObjectId(40),
            allocation_generation: 5,
            physical_base: 0x8000,
            bytes: 512,
        };
        let mut backend = AhciCommandBlockBackend::new(
            &mut capabilities,
            session,
            12,
            read_capability,
            write_capability,
            data,
            mapping(),
            ActiveAhciPort::from_layout(layout()),
            Registers::ready(),
            Memory::initialized(),
            DataIo {
                reject_sanitize: true,
                ..DataIo::default()
            },
        )
        .unwrap();
        assert_eq!(
            backend.read(device(session, 13), 0, 1, &mut [0; 512]),
            Err(AhciBlockIoError::MediaChanged)
        );
        assert!(backend.is_available());
        assert_eq!(
            backend.read(device(session, 12), 0, 1, &mut [0; 512]),
            Err(AhciBlockIoError::IoFailure)
        );
        assert!(!backend.is_available());
        let quarantine = match backend.into_teardown() {
            Ok(_) => panic!("fail-stopped backend must not yield an active port"),
            Err(quarantine) => quarantine,
        };
        assert_eq!(quarantine.mapping(), mapping());
        assert_eq!(quarantine.data_region(), data);
        let (_, _, _, _, data_io) = quarantine.into_parts();
        assert_eq!(data_io.sanitizes, 1);
    }
}
