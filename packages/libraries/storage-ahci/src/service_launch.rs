//! Typed AHCI binding for the generic native device-service attachment.
//!
//! This is a pre-encoding boundary. It exact-matches six capability roles to
//! already-validated AHCI identity and DMA state, but it neither decodes launch
//! bytes nor reconstructs an active hardware owner.

use crate::{
    AhciAbarMapping, AhciDataDmaRegion, AhciDmaRegion, AhciPortDmaLayout, AHCI_ABAR_MINIMUM_BYTES,
    AHCI_COMMAND_LIST_BYTES, AHCI_COMMAND_TABLE_BYTES_PER_SLOT, AHCI_MAX_TRANSFER_BYTES,
    AHCI_MMIO_PAGE_BYTES, AHCI_RECEIVED_FIS_BYTES,
};
use mrml_interface_storage_block_provider_v1::{
    BlockProviderDevice, BLOCK_DEVICE_FLAG_FLUSH, BLOCK_DEVICE_FLAG_READ_ONLY,
    BLOCK_DEVICE_FLAG_RESET,
};
use mrml_kernel::{DeviceServiceLaunchAttachment, IsolationServiceSpec, Rights};

pub const AHCI_DEVICE_AUTHORITY_INDEX: usize = 0;
pub const AHCI_COMMAND_LIST_AUTHORITY_INDEX: usize = 1;
pub const AHCI_RECEIVED_FIS_AUTHORITY_INDEX: usize = 2;
pub const AHCI_COMMAND_TABLES_AUTHORITY_INDEX: usize = 3;
pub const AHCI_DEVICE_WRITE_DATA_AUTHORITY_INDEX: usize = 4;
pub const AHCI_DEVICE_READ_DATA_AUTHORITY_INDEX: usize = 5;
pub const AHCI_SERVICE_AUTHORITY_COUNT: usize = 6;
pub const AHCI_SERVICE_LAUNCH_BYTES: usize = 384;

const COMMAND_MEMORY_RIGHTS: Rights = Rights::MAP.union(Rights::READ).union(Rights::WRITE);
const DEVICE_WRITE_DATA_RIGHTS: Rights = Rights::PIN.union(Rights::MAP).union(Rights::WRITE);
const DEVICE_READ_DATA_RIGHTS: Rights = Rights::PIN.union(Rights::MAP).union(Rights::READ);
const KNOWN_DEVICE_FLAGS: u32 =
    BLOCK_DEVICE_FLAG_READ_ONLY | BLOCK_DEVICE_FLAG_FLUSH | BLOCK_DEVICE_FLAG_RESET;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciServiceLaunchSpecError {
    AttachmentMismatch,
    InvalidDevice,
    InvalidMapping,
    InvalidLayout,
    LayoutMismatch,
    InvalidDataRegion,
    OverlappingDma,
    WrongAuthorityRole(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AhciServiceLaunchSpec {
    service: IsolationServiceSpec,
    attachment: DeviceServiceLaunchAttachment<AHCI_SERVICE_AUTHORITY_COUNT>,
    device: BlockProviderDevice,
    mapping: AhciAbarMapping,
    layout: AhciPortDmaLayout,
    data: AhciDataDmaRegion,
}

impl AhciServiceLaunchSpec {
    pub fn new(
        service: IsolationServiceSpec,
        attachment: DeviceServiceLaunchAttachment<AHCI_SERVICE_AUTHORITY_COUNT>,
        device: BlockProviderDevice,
        mapping: AhciAbarMapping,
        layout: AhciPortDmaLayout,
        data: AhciDataDmaRegion,
    ) -> Result<Self, AhciServiceLaunchSpecError> {
        if !attachment.matches_spec(service) {
            return Err(AhciServiceLaunchSpecError::AttachmentMismatch);
        }
        if attachment.launch_data_bytes() as usize != AHCI_SERVICE_LAUNCH_BYTES {
            return Err(AhciServiceLaunchSpecError::AttachmentMismatch);
        }
        validate_ahci_service_state(device, mapping, layout, data)?;
        let authorities = attachment.authorities();
        for (index, object, rights) in [
            (
                AHCI_DEVICE_AUTHORITY_INDEX,
                mapping.device_object,
                Rights::CONTROL,
            ),
            (
                AHCI_COMMAND_LIST_AUTHORITY_INDEX,
                layout.command_list.memory_object,
                COMMAND_MEMORY_RIGHTS,
            ),
            (
                AHCI_RECEIVED_FIS_AUTHORITY_INDEX,
                layout.received_fis.memory_object,
                COMMAND_MEMORY_RIGHTS,
            ),
            (
                AHCI_COMMAND_TABLES_AUTHORITY_INDEX,
                layout.command_tables.memory_object,
                COMMAND_MEMORY_RIGHTS,
            ),
            (
                AHCI_DEVICE_WRITE_DATA_AUTHORITY_INDEX,
                data.memory_object,
                DEVICE_WRITE_DATA_RIGHTS,
            ),
            (
                AHCI_DEVICE_READ_DATA_AUTHORITY_INDEX,
                data.memory_object,
                DEVICE_READ_DATA_RIGHTS,
            ),
        ] {
            if authorities[index].object() != object || authorities[index].target_rights() != rights
            {
                return Err(AhciServiceLaunchSpecError::WrongAuthorityRole(index));
            }
        }
        Ok(Self {
            service,
            attachment,
            device,
            mapping,
            layout,
            data,
        })
    }

    pub const fn service(self) -> IsolationServiceSpec {
        self.service
    }

    pub const fn attachment(self) -> DeviceServiceLaunchAttachment<AHCI_SERVICE_AUTHORITY_COUNT> {
        self.attachment
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
}

pub(crate) fn validate_ahci_service_state(
    device: BlockProviderDevice,
    mapping: AhciAbarMapping,
    layout: AhciPortDmaLayout,
    data: AhciDataDmaRegion,
) -> Result<(), AhciServiceLaunchSpecError> {
    if device.logical_block_bytes != 512
        || device.logical_block_count == 0
        || device.media_generation == 0
        || device.flags & !KNOWN_DEVICE_FLAGS != 0
        || device.flags & (BLOCK_DEVICE_FLAG_FLUSH | BLOCK_DEVICE_FLAG_RESET)
            != BLOCK_DEVICE_FLAG_FLUSH | BLOCK_DEVICE_FLAG_RESET
    {
        return Err(AhciServiceLaunchSpecError::InvalidDevice);
    }
    if mapping.device_object.0 == 0
        || mapping.configuration_generation == 0
        || mapping.mapping_generation == 0
        || mapping.physical_base == 0
        || mapping.virtual_base == 0
        || mapping.bytes < AHCI_ABAR_MINIMUM_BYTES
        || mapping.physical_base % AHCI_MMIO_PAGE_BYTES != 0
        || mapping.virtual_base % AHCI_MMIO_PAGE_BYTES != 0
        || mapping.bytes % AHCI_MMIO_PAGE_BYTES != 0
        || mapping.physical_base.checked_add(mapping.bytes).is_none()
        || mapping.virtual_base.checked_add(mapping.bytes).is_none()
    {
        return Err(AhciServiceLaunchSpecError::InvalidMapping);
    }
    let table_bytes = u64::from(layout.command_slot_count)
        .checked_mul(AHCI_COMMAND_TABLE_BYTES_PER_SLOT)
        .ok_or(AhciServiceLaunchSpecError::InvalidLayout)?;
    if layout.device_object.0 == 0
        || layout.configuration_generation == 0
        || layout.mapping_generation == 0
        || layout.dma_generation == 0
        || layout.port >= 32
        || layout.command_slot_count == 0
        || layout.command_slot_count > 32
        || !valid_dma_region(layout.command_list, AHCI_COMMAND_LIST_BYTES)
        || !valid_dma_region(layout.received_fis, AHCI_RECEIVED_FIS_BYTES)
        || !valid_dma_region(layout.command_tables, table_bytes)
    {
        return Err(AhciServiceLaunchSpecError::InvalidLayout);
    }
    if layout.device_object != mapping.device_object
        || layout.configuration_generation != mapping.configuration_generation
        || layout.mapping_generation != mapping.mapping_generation
    {
        return Err(AhciServiceLaunchSpecError::LayoutMismatch);
    }
    if data.memory_object.0 == 0
        || data.allocation_generation == 0
        || data.physical_base == 0
        || data.bytes == 0
        || data.bytes > AHCI_MAX_TRANSFER_BYTES
        || data.bytes % 512 != 0
        || data.physical_base.checked_add(data.bytes).is_none()
    {
        return Err(AhciServiceLaunchSpecError::InvalidDataRegion);
    }
    let control = [
        layout.command_list,
        layout.received_fis,
        layout.command_tables,
    ];
    if control[0].memory_object == control[1].memory_object
        || control[0].memory_object == control[2].memory_object
        || control[1].memory_object == control[2].memory_object
        || overlaps(control[0], control[1])
        || overlaps(control[0], control[2])
        || overlaps(control[1], control[2])
        || control.iter().any(|region| {
            region.memory_object == data.memory_object || overlaps_data(data, *region)
        })
        || control
            .iter()
            .any(|region| overlaps_mapping(*region, mapping))
        || overlaps_data_mapping(data, mapping)
    {
        return Err(AhciServiceLaunchSpecError::OverlappingDma);
    }
    Ok(())
}

fn valid_dma_region(region: AhciDmaRegion, expected_bytes: u64) -> bool {
    region.memory_object.0 != 0
        && region.allocation_generation != 0
        && region.physical_base != 0
        && region.bytes == expected_bytes
        && region.physical_base.checked_add(region.bytes).is_some()
}

fn overlaps(left: AhciDmaRegion, right: AhciDmaRegion) -> bool {
    left.physical_base < right.physical_base + right.bytes
        && right.physical_base < left.physical_base + left.bytes
}

fn overlaps_data(data: AhciDataDmaRegion, control: AhciDmaRegion) -> bool {
    data.physical_base < control.physical_base + control.bytes
        && control.physical_base < data.physical_base + data.bytes
}

fn overlaps_mapping(region: AhciDmaRegion, mapping: AhciAbarMapping) -> bool {
    region.physical_base < mapping.physical_base + mapping.bytes
        && mapping.physical_base < region.physical_base + region.bytes
}

fn overlaps_data_mapping(data: AhciDataDmaRegion, mapping: AhciAbarMapping) -> bool {
    data.physical_base < mapping.physical_base + mapping.bytes
        && mapping.physical_base < data.physical_base + data.bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_interface_storage_block_provider_v1::OpaqueHandle;
    use mrml_kernel::{
        Capability, CapabilitySpace, IsolationPlacement, ObjectId, TotalMicrovmClass,
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

    fn mapping() -> AhciAbarMapping {
        AhciAbarMapping {
            device_object: ObjectId(10),
            configuration_generation: 11,
            mapping_generation: 12,
            physical_base: 0x10_0000,
            virtual_base: 0x20_0000,
            bytes: 0x2000,
        }
    }

    fn layout() -> AhciPortDmaLayout {
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
        }
    }

    fn data() -> AhciDataDmaRegion {
        AhciDataDmaRegion {
            memory_object: ObjectId(23),
            allocation_generation: 33,
            physical_base: 0x40_0000,
            bytes: 4096,
        }
    }

    fn device() -> BlockProviderDevice {
        BlockProviderDevice {
            session: OpaqueHandle::new(1, 2).unwrap(),
            logical_block_bytes: 512,
            flags: BLOCK_DEVICE_FLAG_FLUSH | BLOCK_DEVICE_FLAG_RESET,
            logical_block_count: 1_000,
            media_generation: 7,
        }
    }

    fn attachment() -> DeviceServiceLaunchAttachment<AHCI_SERVICE_AUTHORITY_COUNT> {
        let mut capabilities = CapabilitySpace::<7>::new();
        let launch = capabilities
            .insert(ObjectId(30), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let mut handles = [Capability::from_token(0); AHCI_SERVICE_AUTHORITY_COUNT];
        let roles = [
            (ObjectId(10), Rights::CONTROL),
            (ObjectId(20), COMMAND_MEMORY_RIGHTS),
            (ObjectId(21), COMMAND_MEMORY_RIGHTS),
            (ObjectId(22), COMMAND_MEMORY_RIGHTS),
            (ObjectId(23), DEVICE_WRITE_DATA_RIGHTS),
            (ObjectId(23), DEVICE_READ_DATA_RIGHTS),
        ];
        let authorities = core::array::from_fn(|index| {
            handles[index] = capabilities
                .insert(roles[index].0, roles[index].1.union(Rights::DELEGATE))
                .unwrap();
            (roles[index].0, handles[index], roles[index].1)
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

    #[test]
    fn exact_six_roles_bind_one_typed_ahci_launch_spec() {
        let spec = AhciServiceLaunchSpec::new(
            service(),
            attachment(),
            device(),
            mapping(),
            layout(),
            data(),
        )
        .unwrap();
        assert_eq!(spec.device(), device());
        assert_eq!(spec.mapping(), mapping());
        assert_eq!(spec.layout(), layout());
        assert_eq!(spec.data(), data());
    }

    #[test]
    fn identity_geometry_and_dma_substitution_fail_before_binding() {
        let create = |device, mapping, layout, data| {
            AhciServiceLaunchSpec::new(service(), attachment(), device, mapping, layout, data)
        };
        assert_eq!(
            create(
                BlockProviderDevice {
                    logical_block_bytes: 4096,
                    ..device()
                },
                mapping(),
                layout(),
                data(),
            ),
            Err(AhciServiceLaunchSpecError::InvalidDevice)
        );
        assert_eq!(
            create(
                device(),
                AhciAbarMapping {
                    virtual_base: 1,
                    ..mapping()
                },
                layout(),
                data(),
            ),
            Err(AhciServiceLaunchSpecError::InvalidMapping)
        );
        assert_eq!(
            create(
                device(),
                mapping(),
                AhciPortDmaLayout {
                    mapping_generation: 13,
                    ..layout()
                },
                data(),
            ),
            Err(AhciServiceLaunchSpecError::LayoutMismatch)
        );
        assert_eq!(
            create(
                device(),
                mapping(),
                layout(),
                AhciDataDmaRegion {
                    physical_base: layout().command_list.physical_base,
                    ..data()
                },
            ),
            Err(AhciServiceLaunchSpecError::OverlappingDma)
        );
        assert_eq!(
            create(
                device(),
                mapping(),
                layout(),
                AhciDataDmaRegion {
                    physical_base: mapping().physical_base,
                    ..data()
                },
            ),
            Err(AhciServiceLaunchSpecError::OverlappingDma)
        );
    }

    #[test]
    fn swapped_or_widened_authority_roles_are_rejected_exactly() {
        let mut capabilities = CapabilitySpace::<7>::new();
        let launch = capabilities
            .insert(ObjectId(30), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let roles = [
            (ObjectId(10), Rights::CONTROL),
            (ObjectId(21), COMMAND_MEMORY_RIGHTS),
            (ObjectId(20), COMMAND_MEMORY_RIGHTS),
            (ObjectId(22), COMMAND_MEMORY_RIGHTS),
            (ObjectId(23), DEVICE_READ_DATA_RIGHTS),
            (ObjectId(23), DEVICE_WRITE_DATA_RIGHTS),
        ];
        let authorities = core::array::from_fn(|index| {
            let handle = capabilities
                .insert(roles[index].0, roles[index].1.union(Rights::DELEGATE))
                .unwrap();
            (roles[index].0, handle, roles[index].1)
        });
        let attachment = DeviceServiceLaunchAttachment::new(
            service(),
            8,
            ObjectId(30),
            9,
            AHCI_SERVICE_LAUNCH_BYTES as u32,
            launch,
            authorities,
            &capabilities,
        )
        .unwrap();
        assert_eq!(
            AhciServiceLaunchSpec::new(
                service(),
                attachment,
                device(),
                mapping(),
                layout(),
                data(),
            ),
            Err(AhciServiceLaunchSpecError::WrongAuthorityRole(1))
        );
    }
}
