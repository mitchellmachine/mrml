//! Capability-bound preparation of one AHCI port's DMA memory layout.
//!
//! This layer validates already allocated, pinned, zeroed physical memory and
//! delegates one complete layout atomically. It does not program port
//! registers, start engines, enable interrupts, or issue ATA commands.

use crate::{AhciControllerSnapshot, AhciPortDeviceKind, AhciPortLinkState, AhciPortSnapshot};
use mrml_kernel::{Capability, CapabilityError, CapabilitySpace, ObjectId, Rights};

pub const AHCI_COMMAND_LIST_BYTES: u64 = 1024;
pub const AHCI_COMMAND_LIST_ALIGNMENT: u64 = 1024;
pub const AHCI_RECEIVED_FIS_BYTES: u64 = 256;
pub const AHCI_RECEIVED_FIS_ALIGNMENT: u64 = 256;
pub const AHCI_COMMAND_TABLE_BYTES_PER_SLOT: u64 = 256;
pub const AHCI_COMMAND_TABLE_ALIGNMENT: u64 = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AhciDmaRegion {
    pub memory_object: ObjectId,
    pub allocation_generation: u64,
    pub physical_base: u64,
    pub bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AhciPortDmaRequest {
    pub device_capability: Capability,
    pub command_list_capability: Capability,
    pub received_fis_capability: Capability,
    pub command_tables_capability: Capability,
    pub command_list: AhciDmaRegion,
    pub received_fis: AhciDmaRegion,
    pub command_tables: AhciDmaRegion,
    pub dma_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AhciPortDmaLayout {
    pub device_object: ObjectId,
    pub configuration_generation: u64,
    pub mapping_generation: u64,
    pub port: u8,
    pub command_slot_count: u8,
    pub command_list: AhciDmaRegion,
    pub received_fis: AhciDmaRegion,
    pub command_tables: AhciDmaRegion,
    pub dma_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciPortDmaError {
    DeviceCapability(CapabilityError),
    MemoryCapability(CapabilityError),
    WrongDeviceObject,
    WrongMemoryObject,
    ControllerPortMismatch,
    PortUnavailable,
    InvalidGeneration,
    InvalidRegion,
    OverlappingRegions,
    BackendRejected,
}

pub trait AhciPortDmaBackend {
    /// Atomically pins, zero-verifies, and installs exactly these device DMA
    /// mappings. Failure must leave no mapping or retained device access.
    fn install_zeroed_layout(&mut self, layout: AhciPortDmaLayout) -> Result<(), ()>;
}

pub fn prepare_ahci_port_dma<const N: usize, B: AhciPortDmaBackend>(
    capabilities: &CapabilitySpace<N>,
    controller: AhciControllerSnapshot,
    port: AhciPortSnapshot,
    request: AhciPortDmaRequest,
    backend: &mut B,
) -> Result<AhciPortDmaLayout, AhciPortDmaError> {
    let device = capabilities
        .authorize_exact(request.device_capability, Rights::CONTROL)
        .map_err(AhciPortDmaError::DeviceCapability)?;
    if device != controller.device_object {
        return Err(AhciPortDmaError::WrongDeviceObject);
    }
    if port.device_object != controller.device_object
        || port.configuration_generation != controller.configuration_generation
        || port.mapping_generation != controller.mapping_generation
        || port.port >= controller.port_count
        || controller.implemented_ports & (1_u32 << u32::from(port.port)) == 0
    {
        return Err(AhciPortDmaError::ControllerPortMismatch);
    }
    if !matches!(port.link_state, AhciPortLinkState::Established(_))
        || port.device_kind != Some(AhciPortDeviceKind::Sata)
    {
        return Err(AhciPortDmaError::PortUnavailable);
    }
    if request.dma_generation == 0 {
        return Err(AhciPortDmaError::InvalidGeneration);
    }

    let memory_rights = Rights::PIN
        .union(Rights::MAP)
        .union(Rights::READ)
        .union(Rights::WRITE);
    authorize_region(
        capabilities,
        request.command_list_capability,
        request.command_list,
        memory_rights,
    )?;
    authorize_region(
        capabilities,
        request.received_fis_capability,
        request.received_fis,
        memory_rights,
    )?;
    authorize_region(
        capabilities,
        request.command_tables_capability,
        request.command_tables,
        memory_rights,
    )?;

    let table_bytes = u64::from(controller.command_slot_count)
        .checked_mul(AHCI_COMMAND_TABLE_BYTES_PER_SLOT)
        .ok_or(AhciPortDmaError::InvalidRegion)?;
    validate_region(
        request.command_list,
        AHCI_COMMAND_LIST_BYTES,
        AHCI_COMMAND_LIST_ALIGNMENT,
    )?;
    validate_region(
        request.received_fis,
        AHCI_RECEIVED_FIS_BYTES,
        AHCI_RECEIVED_FIS_ALIGNMENT,
    )?;
    validate_region(
        request.command_tables,
        table_bytes,
        AHCI_COMMAND_TABLE_ALIGNMENT,
    )?;
    if request.command_list.memory_object == request.received_fis.memory_object
        || request.command_list.memory_object == request.command_tables.memory_object
        || request.received_fis.memory_object == request.command_tables.memory_object
        || overlaps(request.command_list, request.received_fis)
        || overlaps(request.command_list, request.command_tables)
        || overlaps(request.received_fis, request.command_tables)
    {
        return Err(AhciPortDmaError::OverlappingRegions);
    }

    let layout = AhciPortDmaLayout {
        device_object: controller.device_object,
        configuration_generation: controller.configuration_generation,
        mapping_generation: controller.mapping_generation,
        port: port.port,
        command_slot_count: controller.command_slot_count,
        command_list: request.command_list,
        received_fis: request.received_fis,
        command_tables: request.command_tables,
        dma_generation: request.dma_generation,
    };
    backend
        .install_zeroed_layout(layout)
        .map_err(|_| AhciPortDmaError::BackendRejected)?;
    Ok(layout)
}

fn authorize_region<const N: usize>(
    capabilities: &CapabilitySpace<N>,
    capability: Capability,
    region: AhciDmaRegion,
    rights: Rights,
) -> Result<(), AhciPortDmaError> {
    let object = capabilities
        .authorize_exact(capability, rights)
        .map_err(AhciPortDmaError::MemoryCapability)?;
    if object != region.memory_object {
        return Err(AhciPortDmaError::WrongMemoryObject);
    }
    Ok(())
}

fn validate_region(
    region: AhciDmaRegion,
    exact_bytes: u64,
    alignment: u64,
) -> Result<(), AhciPortDmaError> {
    if region.allocation_generation == 0
        || region.physical_base == 0
        || region.physical_base % alignment != 0
        || region.bytes != exact_bytes
        || region.physical_base.checked_add(region.bytes).is_none()
    {
        return Err(AhciPortDmaError::InvalidRegion);
    }
    Ok(())
}

fn overlaps(left: AhciDmaRegion, right: AhciDmaRegion) -> bool {
    let left_end = left.physical_base + left.bytes;
    let right_end = right.physical_base + right.bytes;
    left.physical_base < right_end && right.physical_base < left_end
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AhciPortLinkSpeed, AhciPortPowerState};

    #[derive(Default)]
    struct Backend {
        installed: Option<AhciPortDmaLayout>,
        reject: bool,
    }

    impl AhciPortDmaBackend for Backend {
        fn install_zeroed_layout(&mut self, layout: AhciPortDmaLayout) -> Result<(), ()> {
            if self.reject {
                return Err(());
            }
            self.installed = Some(layout);
            Ok(())
        }
    }

    fn fixture() -> (
        CapabilitySpace<4>,
        AhciControllerSnapshot,
        AhciPortSnapshot,
        AhciPortDmaRequest,
    ) {
        let device = ObjectId(10);
        let memory = [ObjectId(20), ObjectId(21), ObjectId(22)];
        let memory_rights = Rights::PIN
            .union(Rights::MAP)
            .union(Rights::READ)
            .union(Rights::WRITE);
        let mut capabilities = CapabilitySpace::new();
        let device_capability = capabilities.insert(device, Rights::CONTROL).unwrap();
        let command_list_capability = capabilities.insert(memory[0], memory_rights).unwrap();
        let received_fis_capability = capabilities.insert(memory[1], memory_rights).unwrap();
        let command_tables_capability = capabilities.insert(memory[2], memory_rights).unwrap();
        let controller = AhciControllerSnapshot {
            device_object: device,
            configuration_generation: 7,
            mapping_generation: 9,
            version: 0x0001_0301,
            capabilities: 3 | (3 << 8),
            implemented_ports: 1,
            port_count: 4,
            command_slot_count: 4,
            native_command_queuing: false,
        };
        let port = AhciPortSnapshot {
            device_object: device,
            configuration_generation: 7,
            mapping_generation: 9,
            port: 0,
            sata_status: 0x123,
            link_state: AhciPortLinkState::Established(AhciPortPowerState::Active),
            link_speed: Some(AhciPortLinkSpeed::Generation2),
            device_kind: Some(AhciPortDeviceKind::Sata),
            signature: Some(crate::AHCI_SATA_SIGNATURE),
        };
        let request = AhciPortDmaRequest {
            device_capability,
            command_list_capability,
            received_fis_capability,
            command_tables_capability,
            command_list: AhciDmaRegion {
                memory_object: memory[0],
                allocation_generation: 1,
                physical_base: 0x1000,
                bytes: AHCI_COMMAND_LIST_BYTES,
            },
            received_fis: AhciDmaRegion {
                memory_object: memory[1],
                allocation_generation: 2,
                physical_base: 0x2000,
                bytes: AHCI_RECEIVED_FIS_BYTES,
            },
            command_tables: AhciDmaRegion {
                memory_object: memory[2],
                allocation_generation: 3,
                physical_base: 0x3000,
                bytes: 4 * AHCI_COMMAND_TABLE_BYTES_PER_SLOT,
            },
            dma_generation: 11,
        };
        (capabilities, controller, port, request)
    }

    #[test]
    fn installs_one_exact_capability_bound_layout() {
        let (capabilities, controller, port, request) = fixture();
        let mut backend = Backend::default();
        let layout =
            prepare_ahci_port_dma(&capabilities, controller, port, request, &mut backend).unwrap();
        assert_eq!(layout.command_slot_count, 4);
        assert_eq!(layout.command_tables.bytes, 1024);
        assert_eq!(backend.installed, Some(layout));
    }

    #[test]
    fn rejects_stale_or_unavailable_port_before_backend() {
        let (capabilities, controller, mut port, request) = fixture();
        port.mapping_generation += 1;
        let mut backend = Backend::default();
        assert_eq!(
            prepare_ahci_port_dma(&capabilities, controller, port, request, &mut backend),
            Err(AhciPortDmaError::ControllerPortMismatch)
        );
        let (capabilities, controller, mut port, request) = fixture();
        port.device_kind = Some(AhciPortDeviceKind::Atapi);
        assert_eq!(
            prepare_ahci_port_dma(&capabilities, controller, port, request, &mut backend),
            Err(AhciPortDmaError::PortUnavailable)
        );
        assert!(backend.installed.is_none());
    }

    #[test]
    fn rejects_authority_generation_geometry_and_aliasing() {
        let (mut capabilities, controller, port, request) = fixture();
        capabilities
            .revoke(request.command_list_capability)
            .unwrap();
        let mut backend = Backend::default();
        assert!(matches!(
            prepare_ahci_port_dma(&capabilities, controller, port, request, &mut backend),
            Err(AhciPortDmaError::MemoryCapability(_))
        ));

        let (capabilities, controller, port, mut request) = fixture();
        request.received_fis.allocation_generation = 0;
        assert_eq!(
            prepare_ahci_port_dma(&capabilities, controller, port, request, &mut backend),
            Err(AhciPortDmaError::InvalidRegion)
        );

        let (capabilities, controller, port, mut request) = fixture();
        request.received_fis.physical_base = request.command_list.physical_base;
        assert_eq!(
            prepare_ahci_port_dma(&capabilities, controller, port, request, &mut backend),
            Err(AhciPortDmaError::OverlappingRegions)
        );
        assert!(backend.installed.is_none());
    }

    #[test]
    fn rejects_substitution_zero_dma_generation_and_malformed_extents() {
        let (capabilities, controller, port, mut request) = fixture();
        request.command_list.memory_object = request.received_fis.memory_object;
        let mut backend = Backend::default();
        assert_eq!(
            prepare_ahci_port_dma(&capabilities, controller, port, request, &mut backend),
            Err(AhciPortDmaError::WrongMemoryObject)
        );

        let (capabilities, controller, port, mut request) = fixture();
        request.dma_generation = 0;
        assert_eq!(
            prepare_ahci_port_dma(&capabilities, controller, port, request, &mut backend),
            Err(AhciPortDmaError::InvalidGeneration)
        );

        for mutate in [
            |request: &mut AhciPortDmaRequest| request.command_list.physical_base += 1,
            |request: &mut AhciPortDmaRequest| request.received_fis.bytes -= 1,
            |request: &mut AhciPortDmaRequest| request.command_tables.bytes -= 1,
            |request: &mut AhciPortDmaRequest| {
                request.command_tables.physical_base = u64::MAX - 127
            },
        ] {
            let (capabilities, controller, port, mut request) = fixture();
            mutate(&mut request);
            assert_eq!(
                prepare_ahci_port_dma(&capabilities, controller, port, request, &mut backend),
                Err(AhciPortDmaError::InvalidRegion)
            );
        }
        assert!(backend.installed.is_none());
    }

    #[test]
    fn backend_failure_publishes_no_layout() {
        let (capabilities, controller, port, request) = fixture();
        let mut backend = Backend {
            installed: None,
            reject: true,
        };
        assert_eq!(
            prepare_ahci_port_dma(&capabilities, controller, port, request, &mut backend),
            Err(AhciPortDmaError::BackendRejected)
        );
        assert!(backend.installed.is_none());
    }
}
