//! Canonical non-authorizing launch record for the installed AHCI service.

use crate::{
    service_launch::validate_ahci_service_state, AhciAbarMapping, AhciDataDmaRegion, AhciDmaRegion, AhciPortDmaLayout,
    AhciServiceLaunchSpec, AhciServiceLaunchSpecError, AHCI_SERVICE_AUTHORITY_COUNT,
    AHCI_COMMAND_LIST_AUTHORITY_INDEX, AHCI_COMMAND_TABLES_AUTHORITY_INDEX,
    AHCI_DEVICE_AUTHORITY_INDEX, AHCI_DEVICE_READ_DATA_AUTHORITY_INDEX,
    AHCI_DEVICE_WRITE_DATA_AUTHORITY_INDEX, AHCI_RECEIVED_FIS_AUTHORITY_INDEX,
    AHCI_SERVICE_LAUNCH_BYTES,
};
use mrml_interface_storage_block_provider_v1::{BlockProviderDevice, OpaqueHandle};
use mrml_kernel::{
    prepare_native_device_service_task, Capability, DeviceServiceLaunchAttachment,
    IsolationServiceSpec, NativeDeviceServiceTask, NativeDeviceServiceTaskError, ObjectId,
    TaskId, TaskRuntime,
};

const MAGIC: [u8; 8] = *b"MRMLAHC1";
const VERSION: u16 = 1;
const HEADER_BYTES: u16 = 32;
const PAGE_BYTES: u64 = 4096;
const USER_CANONICAL_END: u64 = 0x0000_8000_0000_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AhciServiceCpuMapping {
    mapping_generation: u64,
    virtual_base: u64,
}

impl AhciServiceCpuMapping {
    pub const fn new(mapping_generation: u64, virtual_base: u64) -> Option<Self> {
        if mapping_generation == 0
            || virtual_base == 0
            || virtual_base % PAGE_BYTES != 0
            || virtual_base >= USER_CANONICAL_END
        {
            return None;
        }
        Some(Self {
            mapping_generation,
            virtual_base,
        })
    }

    pub const fn mapping_generation(self) -> u64 {
        self.mapping_generation
    }

    pub const fn virtual_base(self) -> u64 {
        self.virtual_base
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AhciServiceLaunchRecord {
    system_generation: u64,
    provider_generation: u64,
    attachment_generation: u64,
    device: BlockProviderDevice,
    mapping: AhciAbarMapping,
    layout: AhciPortDmaLayout,
    data: AhciDataDmaRegion,
    cpu_mappings: [AhciServiceCpuMapping; 4],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciServiceLaunchRecordError {
    InvalidLength,
    InvalidHeader,
    NonzeroReserved,
    InvalidGeneration,
    InvalidHandle,
    InvalidCpuMapping,
    OverlappingCpuMappings,
    BindingMismatch,
    InvalidInstalledCapability,
    DuplicateInstalledCapability,
    Launch(AhciServiceLaunchSpecError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundAhciServiceLaunch {
    spec: AhciServiceLaunchSpec,
    cpu_mappings: [AhciServiceCpuMapping; 4],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstalledAhciServiceLaunch {
    record: AhciServiceLaunchRecord,
    authorities: [Capability; AHCI_SERVICE_AUTHORITY_COUNT],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedAhciNativeServiceTask {
    task: NativeDeviceServiceTask<AHCI_SERVICE_AUTHORITY_COUNT>,
    launch: BoundAhciServiceLaunch,
}

impl PreparedAhciNativeServiceTask {
    pub const fn task(self) -> NativeDeviceServiceTask<AHCI_SERVICE_AUTHORITY_COUNT> {
        self.task
    }

    pub const fn launch(self) -> BoundAhciServiceLaunch {
        self.launch
    }

    pub const fn into_parts(
        self,
    ) -> (
        NativeDeviceServiceTask<AHCI_SERVICE_AUTHORITY_COUNT>,
        BoundAhciServiceLaunch,
    ) {
        (self.task, self.launch)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AhciNativeServiceTaskPreparationFailure {
    error: NativeDeviceServiceTaskError,
    launch: BoundAhciServiceLaunch,
}

impl AhciNativeServiceTaskPreparationFailure {
    pub const fn error(self) -> NativeDeviceServiceTaskError {
        self.error
    }

    pub const fn launch(self) -> BoundAhciServiceLaunch {
        self.launch
    }
}

/// Projects one already-bound AHCI launch into a fresh native service task.
///
/// The bound launch remains paired with the prepared task for later mapping,
/// dispatch, and teardown checks. Kernel construction owns atomic capability
/// attenuation and rollback; failure returns the unchanged launch for retry.
#[allow(clippy::too_many_arguments)]
pub fn prepare_bound_ahci_native_service_task<
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    source_task: TaskId,
    target_task: TaskId,
    launch: BoundAhciServiceLaunch,
    service_endpoint_object: ObjectId,
    supervisor_task_object: ObjectId,
    service_module_object: ObjectId,
) -> Result<PreparedAhciNativeServiceTask, AhciNativeServiceTaskPreparationFailure> {
    let spec = launch.spec();
    match prepare_native_device_service_task(
        runtime,
        source_task,
        target_task,
        spec.service(),
        spec.attachment(),
        service_endpoint_object,
        supervisor_task_object,
        service_module_object,
    ) {
        Ok(task) => Ok(PreparedAhciNativeServiceTask { task, launch }),
        Err(error) => Err(AhciNativeServiceTaskPreparationFailure { error, launch }),
    }
}

impl BoundAhciServiceLaunch {
    pub const fn spec(self) -> AhciServiceLaunchSpec {
        self.spec
    }

    pub const fn cpu_mappings(self) -> [AhciServiceCpuMapping; 4] {
        self.cpu_mappings
    }
}

impl InstalledAhciServiceLaunch {
    /// Binds copied launch bytes to the fixed authority-token order installed
    /// by `NativeDeviceServiceEntry`.
    ///
    /// # Safety
    ///
    /// The caller must be the native entry path constructed by the kernel for
    /// this exact AHCI domain. `bytes` must have been copied through its
    /// read-only launch-data capability, `provider_generation` must be the entry
    /// register value, and `authorities` must be the six separately projected
    /// entry capabilities in canonical register order. Record bytes carry no
    /// authority and cannot substitute any of these capabilities.
    pub unsafe fn from_installed_projection(
        bytes: &[u8],
        provider_generation: u64,
        authorities: [Capability; AHCI_SERVICE_AUTHORITY_COUNT],
    ) -> Result<Self, AhciServiceLaunchRecordError> {
        let record = AhciServiceLaunchRecord::decode(bytes)?;
        if provider_generation == 0 || record.provider_generation() != provider_generation {
            return Err(AhciServiceLaunchRecordError::BindingMismatch);
        }
        for (index, capability) in authorities.iter().enumerate() {
            let token = capability.token();
            if token == 0 || token >> 32 == 0 {
                return Err(AhciServiceLaunchRecordError::InvalidInstalledCapability);
            }
            if authorities[..index].contains(capability) {
                return Err(AhciServiceLaunchRecordError::DuplicateInstalledCapability);
            }
        }
        Ok(Self {
            record,
            authorities,
        })
    }

    pub const fn record(self) -> AhciServiceLaunchRecord {
        self.record
    }

    pub const fn device(self) -> Capability {
        self.authorities[AHCI_DEVICE_AUTHORITY_INDEX]
    }

    pub const fn command_list(self) -> Capability {
        self.authorities[AHCI_COMMAND_LIST_AUTHORITY_INDEX]
    }

    pub const fn received_fis(self) -> Capability {
        self.authorities[AHCI_RECEIVED_FIS_AUTHORITY_INDEX]
    }

    pub const fn command_tables(self) -> Capability {
        self.authorities[AHCI_COMMAND_TABLES_AUTHORITY_INDEX]
    }

    pub const fn device_write_data(self) -> Capability {
        self.authorities[AHCI_DEVICE_WRITE_DATA_AUTHORITY_INDEX]
    }

    pub const fn device_read_data(self) -> Capability {
        self.authorities[AHCI_DEVICE_READ_DATA_AUTHORITY_INDEX]
    }
}

impl AhciServiceLaunchRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        system_generation: u64,
        provider_generation: u64,
        attachment_generation: u64,
        device: BlockProviderDevice,
        mapping: AhciAbarMapping,
        layout: AhciPortDmaLayout,
        data: AhciDataDmaRegion,
        cpu_mappings: [AhciServiceCpuMapping; 4],
    ) -> Result<Self, AhciServiceLaunchRecordError> {
        if system_generation == 0 || provider_generation == 0 || attachment_generation == 0 {
            return Err(AhciServiceLaunchRecordError::InvalidGeneration);
        }
        validate_ahci_service_state(device, mapping, layout, data)
            .map_err(AhciServiceLaunchRecordError::Launch)?;
        validate_cpu_mappings(mapping, layout, data, cpu_mappings)?;
        Ok(Self {
            system_generation,
            provider_generation,
            attachment_generation,
            device,
            mapping,
            layout,
            data,
            cpu_mappings,
        })
    }

    pub const fn system_generation(self) -> u64 {
        self.system_generation
    }

    pub const fn provider_generation(self) -> u64 {
        self.provider_generation
    }

    pub const fn attachment_generation(self) -> u64 {
        self.attachment_generation
    }

    pub const fn device(self) -> BlockProviderDevice {
        self.device
    }

    pub const fn mapping(self) -> AhciAbarMapping {
        self.mapping
    }

    pub const fn layout(self) -> AhciPortDmaLayout {
        self.layout
    }

    pub const fn data(self) -> AhciDataDmaRegion {
        self.data
    }

    pub const fn cpu_mappings(self) -> [AhciServiceCpuMapping; 4] {
        self.cpu_mappings
    }

    pub fn bind(
        self,
        service: IsolationServiceSpec,
        attachment: DeviceServiceLaunchAttachment<AHCI_SERVICE_AUTHORITY_COUNT>,
    ) -> Result<BoundAhciServiceLaunch, AhciServiceLaunchRecordError> {
        if self.system_generation != service.system_generation()
            || self.provider_generation != service.provider_generation()
            || self.attachment_generation != attachment.attachment_generation()
            || attachment.launch_data_bytes() as usize != AHCI_SERVICE_LAUNCH_BYTES
        {
            return Err(AhciServiceLaunchRecordError::BindingMismatch);
        }
        let spec = AhciServiceLaunchSpec::new(
            service,
            attachment,
            self.device,
            self.mapping,
            self.layout,
            self.data,
        )
        .map_err(AhciServiceLaunchRecordError::Launch)?;
        Ok(BoundAhciServiceLaunch {
            spec,
            cpu_mappings: self.cpu_mappings,
        })
    }

    pub fn encode(self) -> [u8; AHCI_SERVICE_LAUNCH_BYTES] {
        let mut output = [0; AHCI_SERVICE_LAUNCH_BYTES];
        output[..8].copy_from_slice(&MAGIC);
        put_u16(&mut output, 8, VERSION);
        put_u16(&mut output, 10, HEADER_BYTES);
        put_u32(&mut output, 12, AHCI_SERVICE_LAUNCH_BYTES as u32);
        put_u64(&mut output, 32, self.system_generation);
        put_u64(&mut output, 40, self.provider_generation);
        put_u64(&mut output, 48, self.attachment_generation);
        put_u32(&mut output, 64, self.device.session.index());
        put_u32(&mut output, 68, self.device.session.generation());
        put_u32(&mut output, 72, self.device.logical_block_bytes);
        put_u32(&mut output, 76, self.device.flags);
        put_u64(&mut output, 80, self.device.logical_block_count);
        put_u64(&mut output, 88, self.device.media_generation);
        put_mapping(&mut output, 96, self.mapping);
        put_u64(&mut output, 144, self.layout.device_object.0);
        put_u64(&mut output, 152, self.layout.configuration_generation);
        put_u64(&mut output, 160, self.layout.mapping_generation);
        output[168] = self.layout.port;
        output[169] = self.layout.command_slot_count;
        put_u64(&mut output, 176, self.layout.dma_generation);
        put_region(&mut output, 184, self.layout.command_list);
        put_region(&mut output, 216, self.layout.received_fis);
        put_region(&mut output, 248, self.layout.command_tables);
        put_data_region(&mut output, 280, self.data);
        for (index, mapping) in self.cpu_mappings.into_iter().enumerate() {
            let offset = 312 + index * 16;
            put_u64(&mut output, offset, mapping.mapping_generation);
            put_u64(&mut output, offset + 8, mapping.virtual_base);
        }
        output
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AhciServiceLaunchRecordError> {
        if bytes.len() != AHCI_SERVICE_LAUNCH_BYTES {
            return Err(AhciServiceLaunchRecordError::InvalidLength);
        }
        if bytes[..8] != MAGIC
            || read_u16(bytes, 8) != VERSION
            || read_u16(bytes, 10) != HEADER_BYTES
            || read_u32(bytes, 12) != AHCI_SERVICE_LAUNCH_BYTES as u32
        {
            return Err(AhciServiceLaunchRecordError::InvalidHeader);
        }
        if bytes[16..32].iter().any(|byte| *byte != 0)
            || bytes[56..64].iter().any(|byte| *byte != 0)
            || bytes[170..176].iter().any(|byte| *byte != 0)
            || bytes[376..384].iter().any(|byte| *byte != 0)
        {
            return Err(AhciServiceLaunchRecordError::NonzeroReserved);
        }
        let session = OpaqueHandle::new(read_u32(bytes, 64), read_u32(bytes, 68))
            .ok_or(AhciServiceLaunchRecordError::InvalidHandle)?;
        let device = BlockProviderDevice {
            session,
            logical_block_bytes: read_u32(bytes, 72),
            flags: read_u32(bytes, 76),
            logical_block_count: read_u64(bytes, 80),
            media_generation: read_u64(bytes, 88),
        };
        let mapping = read_mapping(bytes, 96);
        let layout = AhciPortDmaLayout {
            device_object: ObjectId(read_u64(bytes, 144)),
            configuration_generation: read_u64(bytes, 152),
            mapping_generation: read_u64(bytes, 160),
            port: bytes[168],
            command_slot_count: bytes[169],
            command_list: read_region(bytes, 184),
            received_fis: read_region(bytes, 216),
            command_tables: read_region(bytes, 248),
            dma_generation: read_u64(bytes, 176),
        };
        let data = read_data_region(bytes, 280);
        let mut cpu_mappings = [AhciServiceCpuMapping {
            mapping_generation: 0,
            virtual_base: 0,
        }; 4];
        for (index, mapping) in cpu_mappings.iter_mut().enumerate() {
            let offset = 312 + index * 16;
            *mapping = AhciServiceCpuMapping::new(
                read_u64(bytes, offset),
                read_u64(bytes, offset + 8),
            )
            .ok_or(AhciServiceLaunchRecordError::InvalidCpuMapping)?;
        }
        Self::new(
            read_u64(bytes, 32),
            read_u64(bytes, 40),
            read_u64(bytes, 48),
            device,
            mapping,
            layout,
            data,
            cpu_mappings,
        )
    }
}

fn validate_cpu_mappings(
    abar: AhciAbarMapping,
    layout: AhciPortDmaLayout,
    data: AhciDataDmaRegion,
    mappings: [AhciServiceCpuMapping; 4],
) -> Result<(), AhciServiceLaunchRecordError> {
    let bytes = [
        layout.command_list.bytes,
        layout.received_fis.bytes,
        layout.command_tables.bytes,
        data.bytes,
    ];
    let mut ranges = [(0_u64, 0_u64); 4];
    for (index, mapping) in mappings.into_iter().enumerate() {
        if mapping.mapping_generation == 0
            || mapping.virtual_base == 0
            || mapping.virtual_base % PAGE_BYTES != 0
            || mapping.virtual_base >= USER_CANONICAL_END
        {
            return Err(AhciServiceLaunchRecordError::InvalidCpuMapping);
        }
        let pages = bytes[index]
            .checked_add(PAGE_BYTES - 1)
            .ok_or(AhciServiceLaunchRecordError::InvalidCpuMapping)?
            / PAGE_BYTES;
        let mapped_bytes = pages
            .checked_mul(PAGE_BYTES)
            .ok_or(AhciServiceLaunchRecordError::InvalidCpuMapping)?;
        let end = mapping
            .virtual_base
            .checked_add(mapped_bytes)
            .filter(|end| *end <= USER_CANONICAL_END)
            .ok_or(AhciServiceLaunchRecordError::InvalidCpuMapping)?;
        ranges[index] = (mapping.virtual_base, end);
        let abar_end = abar
            .virtual_base
            .checked_add(abar.bytes)
            .ok_or(AhciServiceLaunchRecordError::InvalidCpuMapping)?;
        if mapping.virtual_base < abar_end && abar.virtual_base < end {
            return Err(AhciServiceLaunchRecordError::OverlappingCpuMappings);
        }
    }
    for left in 0..ranges.len() {
        for right in left + 1..ranges.len() {
            if ranges[left].0 < ranges[right].1 && ranges[right].0 < ranges[left].1 {
                return Err(AhciServiceLaunchRecordError::OverlappingCpuMappings);
            }
        }
    }
    Ok(())
}

fn put_mapping(output: &mut [u8], offset: usize, mapping: AhciAbarMapping) {
    put_u64(output, offset, mapping.device_object.0);
    put_u64(output, offset + 8, mapping.configuration_generation);
    put_u64(output, offset + 16, mapping.mapping_generation);
    put_u64(output, offset + 24, mapping.physical_base);
    put_u64(output, offset + 32, mapping.virtual_base);
    put_u64(output, offset + 40, mapping.bytes);
}

fn read_mapping(bytes: &[u8], offset: usize) -> AhciAbarMapping {
    AhciAbarMapping {
        device_object: ObjectId(read_u64(bytes, offset)),
        configuration_generation: read_u64(bytes, offset + 8),
        mapping_generation: read_u64(bytes, offset + 16),
        physical_base: read_u64(bytes, offset + 24),
        virtual_base: read_u64(bytes, offset + 32),
        bytes: read_u64(bytes, offset + 40),
    }
}

fn put_region(output: &mut [u8], offset: usize, region: AhciDmaRegion) {
    put_u64(output, offset, region.memory_object.0);
    put_u64(output, offset + 8, region.allocation_generation);
    put_u64(output, offset + 16, region.physical_base);
    put_u64(output, offset + 24, region.bytes);
}

fn read_region(bytes: &[u8], offset: usize) -> AhciDmaRegion {
    AhciDmaRegion {
        memory_object: ObjectId(read_u64(bytes, offset)),
        allocation_generation: read_u64(bytes, offset + 8),
        physical_base: read_u64(bytes, offset + 16),
        bytes: read_u64(bytes, offset + 24),
    }
}

fn put_data_region(output: &mut [u8], offset: usize, region: AhciDataDmaRegion) {
    put_u64(output, offset, region.memory_object.0);
    put_u64(output, offset + 8, region.allocation_generation);
    put_u64(output, offset + 16, region.physical_base);
    put_u64(output, offset + 24, region.bytes);
}

fn read_data_region(bytes: &[u8], offset: usize) -> AhciDataDmaRegion {
    AhciDataDmaRegion {
        memory_object: ObjectId(read_u64(bytes, offset)),
        allocation_generation: read_u64(bytes, offset + 8),
        physical_base: read_u64(bytes, offset + 16),
        bytes: read_u64(bytes, offset + 24),
    }
}

fn put_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("fixed range"))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("fixed range"))
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("fixed range"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_interface_storage_block_provider_v1::{
        BLOCK_DEVICE_FLAG_FLUSH, BLOCK_DEVICE_FLAG_RESET,
    };
    use mrml_kernel::{
        arch::x86_64::UserContext, CapabilitySpace, IsolationPlacement,
        NativeDeviceServiceEntryError, PhysAddr, Priority, Rights, TotalMicrovmClass,
    };

    fn service() -> IsolationServiceSpec {
        IsolationServiceSpec::new(
            ObjectId(1),
            ObjectId(2),
            1,
            3,
            4,
            5,
            TotalMicrovmClass::MicrovmEligible,
            IsolationPlacement::NativeService,
        )
        .unwrap()
    }

    fn region(object: u64, physical_base: u64, bytes: u64) -> AhciDmaRegion {
        AhciDmaRegion {
            memory_object: ObjectId(object),
            allocation_generation: object + 10,
            physical_base,
            bytes,
        }
    }

    fn record() -> AhciServiceLaunchRecord {
        AhciServiceLaunchRecord::new(
            4,
            3,
            8,
            BlockProviderDevice {
                session: OpaqueHandle::new(1, 2).unwrap(),
                logical_block_bytes: 512,
                flags: BLOCK_DEVICE_FLAG_FLUSH | BLOCK_DEVICE_FLAG_RESET,
                logical_block_count: 1_000,
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
                port: 2,
                command_slot_count: 4,
                command_list: region(20, 0x30_0000, 1024),
                received_fis: region(21, 0x31_0000, 256),
                command_tables: region(22, 0x32_0000, 1024),
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
        .unwrap()
    }

    fn attachment() -> DeviceServiceLaunchAttachment<AHCI_SERVICE_AUTHORITY_COUNT> {
        let record = record();
        let mut capabilities = CapabilitySpace::<7>::new();
        let launch = capabilities
            .insert(ObjectId(30), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let roles = [
            (record.mapping.device_object, Rights::CONTROL),
            (
                record.layout.command_list.memory_object,
                Rights::MAP.union(Rights::READ).union(Rights::WRITE),
            ),
            (
                record.layout.received_fis.memory_object,
                Rights::MAP.union(Rights::READ).union(Rights::WRITE),
            ),
            (
                record.layout.command_tables.memory_object,
                Rights::MAP.union(Rights::READ).union(Rights::WRITE),
            ),
            (
                record.data.memory_object,
                Rights::PIN.union(Rights::MAP).union(Rights::WRITE),
            ),
            (
                record.data.memory_object,
                Rights::PIN.union(Rights::MAP).union(Rights::READ),
            ),
        ];
        let authorities = core::array::from_fn(|index| {
            let source = capabilities
                .insert(roles[index].0, roles[index].1.union(Rights::DELEGATE))
                .unwrap();
            (roles[index].0, source, roles[index].1)
        });
        DeviceServiceLaunchAttachment::new(
            service(),
            8,
            ObjectId(30),
            9,
            AHCI_SERVICE_LAUNCH_BYTES as u32,
            launch,
            authorities,
            &capabilities,
        )
        .unwrap()
    }

    fn runtime_launch(
        occupied_entry: bool,
    ) -> (
        TaskRuntime<2, 8>,
        TaskId,
        TaskId,
        BoundAhciServiceLaunch,
    ) {
        let mut runtime = TaskRuntime::<2, 8>::new(1_000, 1).unwrap();
        let source = runtime
            .create(
                Priority::NORMAL,
                UserContext::new(PhysAddr::new(0x50_0000).unwrap(), 0x40_0000, 0x7000_0000)
                    .unwrap(),
            )
            .unwrap();
        let target = runtime
            .create(
                Priority::NORMAL,
                UserContext::new(PhysAddr::new(0x60_0000).unwrap(), 0x40_0000, 0x7000_0000)
                    .unwrap(),
            )
            .unwrap();
        if occupied_entry {
            runtime.context_mut(target).unwrap().r13 = 1;
        }
        let launch_data = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(ObjectId(30), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let record = record();
        let roles = [
            (record.mapping.device_object, Rights::CONTROL),
            (
                record.layout.command_list.memory_object,
                Rights::MAP.union(Rights::READ).union(Rights::WRITE),
            ),
            (
                record.layout.received_fis.memory_object,
                Rights::MAP.union(Rights::READ).union(Rights::WRITE),
            ),
            (
                record.layout.command_tables.memory_object,
                Rights::MAP.union(Rights::READ).union(Rights::WRITE),
            ),
            (
                record.data.memory_object,
                Rights::PIN.union(Rights::MAP).union(Rights::WRITE),
            ),
            (
                record.data.memory_object,
                Rights::PIN.union(Rights::MAP).union(Rights::READ),
            ),
        ];
        let mut handles = [Capability::from_token(0); AHCI_SERVICE_AUTHORITY_COUNT];
        for (index, (object, rights)) in roles.into_iter().enumerate() {
            handles[index] = runtime
                .capabilities_mut(source)
                .unwrap()
                .insert(object, rights.union(Rights::DELEGATE))
                .unwrap();
        }
        let authorities = core::array::from_fn(|index| {
            let (object, rights) = roles[index];
            (object, handles[index], rights)
        });
        let attachment = DeviceServiceLaunchAttachment::new(
            service(),
            8,
            ObjectId(30),
            9,
            AHCI_SERVICE_LAUNCH_BYTES as u32,
            launch_data,
            authorities,
            runtime.capabilities(source).unwrap(),
        )
        .unwrap();
        let bound = record.bind(service(), attachment).unwrap();
        (runtime, source, target, bound)
    }

    #[test]
    fn bound_launch_prepares_exact_native_task_and_preserves_pairing() {
        let (mut runtime, source, target, launch) = runtime_launch(false);
        let prepared = prepare_bound_ahci_native_service_task(
            &mut runtime,
            source,
            target,
            launch,
            ObjectId(40),
            ObjectId(41),
            ObjectId(42),
        )
        .unwrap();
        assert_eq!(prepared.launch(), launch);
        assert_eq!(prepared.task().task(), target);
        assert_eq!(prepared.task().source_task(), source);
        assert_eq!(prepared.task().entry().attachment(), launch.spec().attachment());
        assert_eq!(prepared.task().entry().provider_generation(), 3);
    }

    #[test]
    fn task_preparation_failure_rolls_back_and_returns_unchanged_launch() {
        let (mut runtime, source, target, launch) = runtime_launch(true);
        let original_context = *runtime.context(target).unwrap();
        let failure = prepare_bound_ahci_native_service_task(
            &mut runtime,
            source,
            target,
            launch,
            ObjectId(40),
            ObjectId(41),
            ObjectId(42),
        )
        .unwrap_err();
        assert_eq!(failure.launch(), launch);
        assert_eq!(
            failure.error(),
            NativeDeviceServiceTaskError::Entry(
                NativeDeviceServiceEntryError::LaunchRegistersOccupied
            )
        );
        assert_eq!(*runtime.context(target).unwrap(), original_context);
    }

    #[test]
    fn canonical_record_round_trips_and_binds_separate_authority() {
        let record = record();
        let bytes = record.encode();
        assert!(bytes[16..32].iter().all(|byte| *byte == 0));
        assert!(bytes[56..64].iter().all(|byte| *byte == 0));
        assert!(bytes[170..176].iter().all(|byte| *byte == 0));
        assert!(bytes[376..384].iter().all(|byte| *byte == 0));
        let decoded = AhciServiceLaunchRecord::decode(&bytes).unwrap();
        assert_eq!(decoded, record);
        let bound = decoded.bind(service(), attachment()).unwrap();
        assert_eq!(bound.spec().device(), record.device());
        assert_eq!(bound.cpu_mappings(), record.cpu_mappings());
    }

    #[test]
    fn header_length_reserved_and_handle_corruption_fail_closed() {
        assert_eq!(
            AhciServiceLaunchRecord::decode(&record().encode()[..383]),
            Err(AhciServiceLaunchRecordError::InvalidLength)
        );
        for offset in [0, 8, 10, 12] {
            let mut bytes = record().encode();
            bytes[offset] ^= 1;
            assert_eq!(
                AhciServiceLaunchRecord::decode(&bytes),
                Err(AhciServiceLaunchRecordError::InvalidHeader)
            );
        }
        for offset in [16, 56, 170, 376] {
            let mut bytes = record().encode();
            bytes[offset] = 1;
            assert_eq!(
                AhciServiceLaunchRecord::decode(&bytes),
                Err(AhciServiceLaunchRecordError::NonzeroReserved)
            );
        }
        let mut bytes = record().encode();
        bytes[68..72].fill(0);
        assert_eq!(
            AhciServiceLaunchRecord::decode(&bytes),
            Err(AhciServiceLaunchRecordError::InvalidHandle)
        );
    }

    #[test]
    fn cpu_mapping_overlap_and_generation_substitution_never_bind() {
        let mut mappings = record().cpu_mappings();
        mappings[1] = mappings[0];
        assert_eq!(
            AhciServiceLaunchRecord::new(
                4,
                3,
                8,
                record().device(),
                record().mapping(),
                record().layout(),
                record().data(),
                mappings,
            ),
            Err(AhciServiceLaunchRecordError::OverlappingCpuMappings)
        );
        let mut bytes = record().encode();
        put_u64(&mut bytes, 48, 9);
        assert_eq!(
            AhciServiceLaunchRecord::decode(&bytes)
                .unwrap()
                .bind(service(), attachment()),
            Err(AhciServiceLaunchRecordError::BindingMismatch)
        );
    }

    #[test]
    fn installed_projection_preserves_fixed_authority_order() {
        let authorities = core::array::from_fn(|index| {
            Capability::from_token(((index as u64 + 1) << 32) | (index as u64 + 1))
        });
        let installed = unsafe {
            InstalledAhciServiceLaunch::from_installed_projection(
                &record().encode(),
                3,
                authorities,
            )
        }
        .unwrap();
        assert_eq!(installed.record(), record());
        assert_eq!(installed.device(), authorities[0]);
        assert_eq!(installed.command_list(), authorities[1]);
        assert_eq!(installed.received_fis(), authorities[2]);
        assert_eq!(installed.command_tables(), authorities[3]);
        assert_eq!(installed.device_write_data(), authorities[4]);
        assert_eq!(installed.device_read_data(), authorities[5]);

        assert_eq!(
            unsafe {
                InstalledAhciServiceLaunch::from_installed_projection(
                    &record().encode(),
                    4,
                    authorities,
                )
            },
            Err(AhciServiceLaunchRecordError::BindingMismatch)
        );
    }

    #[test]
    fn installed_projection_rejects_invalid_or_aliased_tokens() {
        let mut authorities = core::array::from_fn(|index| {
            Capability::from_token(((index as u64 + 1) << 32) | (index as u64 + 1))
        });
        authorities[2] = Capability::from_token(2);
        assert_eq!(
            unsafe {
                InstalledAhciServiceLaunch::from_installed_projection(
                    &record().encode(),
                    3,
                    authorities,
                )
            },
            Err(AhciServiceLaunchRecordError::InvalidInstalledCapability)
        );

        authorities[2] = authorities[1];
        assert_eq!(
            unsafe {
                InstalledAhciServiceLaunch::from_installed_projection(
                    &record().encode(),
                    3,
                    authorities,
                )
            },
            Err(AhciServiceLaunchRecordError::DuplicateInstalledCapability)
        );
    }
}
