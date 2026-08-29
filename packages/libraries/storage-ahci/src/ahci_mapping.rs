//! Capability-bound preparation of one validated AHCI ABAR mapping.
//!
//! This module does not access controller registers. The platform mapper remains
//! responsible for installing a supervisor-only, read/write, non-executable MMIO
//! mapping and for invalidating it when either generation is retired.

use crate::AhciAbarDescriptor;
use mrml_kernel::{Capability, CapabilityError, CapabilitySpace, ObjectId, Rights};

pub const AHCI_MMIO_PAGE_BYTES: u64 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AhciAbarMapping {
    pub device_object: ObjectId,
    pub configuration_generation: u64,
    pub mapping_generation: u64,
    pub physical_base: u64,
    pub virtual_base: u64,
    pub bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciAbarMappingError {
    Capability(CapabilityError),
    WrongDeviceObject,
    InvalidMappingGeneration,
    InvalidVirtualRange,
    BackendRejected,
}

pub trait AhciAbarMappingBackend {
    /// Installs an NX MMIO mapping for exactly this prepared range.
    ///
    /// The backend must not broaden the range or make it user-accessible. It
    /// must bind revocation to both generations retained in `mapping`.
    fn map_read_write_nx(&mut self, mapping: AhciAbarMapping) -> Result<(), ()>;
}

pub fn map_ahci_abar<const N: usize, B: AhciAbarMappingBackend>(
    capabilities: &CapabilitySpace<N>,
    capability: Capability,
    device_object: ObjectId,
    descriptor: AhciAbarDescriptor,
    virtual_base: u64,
    mapping_generation: u64,
    backend: &mut B,
) -> Result<AhciAbarMapping, AhciAbarMappingError> {
    let required = Rights::MAP.union(Rights::READ).union(Rights::WRITE);
    let authorized = capabilities
        .authorize_exact(capability, required)
        .map_err(AhciAbarMappingError::Capability)?;
    if authorized != device_object {
        return Err(AhciAbarMappingError::WrongDeviceObject);
    }
    if mapping_generation == 0 {
        return Err(AhciAbarMappingError::InvalidMappingGeneration);
    }
    if virtual_base == 0
        || virtual_base % AHCI_MMIO_PAGE_BYTES != 0
        || descriptor.physical_base % AHCI_MMIO_PAGE_BYTES != 0
        || descriptor.bytes % AHCI_MMIO_PAGE_BYTES != 0
        || virtual_base.checked_add(descriptor.bytes).is_none()
    {
        return Err(AhciAbarMappingError::InvalidVirtualRange);
    }

    let mapping = AhciAbarMapping {
        device_object,
        configuration_generation: descriptor.configuration_generation,
        mapping_generation,
        physical_base: descriptor.physical_base,
        virtual_base,
        bytes: descriptor.bytes,
    };
    backend
        .map_read_write_nx(mapping)
        .map_err(|_| AhciAbarMappingError::BackendRejected)?;
    Ok(mapping)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AhciPciFunctionSnapshot, PciFunctionLocation};

    #[derive(Default)]
    struct RecordingBackend {
        mapping: Option<AhciAbarMapping>,
        reject: bool,
    }

    impl AhciAbarMappingBackend for RecordingBackend {
        fn map_read_write_nx(&mut self, mapping: AhciAbarMapping) -> Result<(), ()> {
            if self.reject {
                return Err(());
            }
            self.mapping = Some(mapping);
            Ok(())
        }
    }

    fn descriptor() -> AhciAbarDescriptor {
        AhciAbarDescriptor::validate(AhciPciFunctionSnapshot {
            location: PciFunctionLocation::new(0, 0, 31, 2).unwrap(),
            configuration_generation: 7,
            vendor_id: 0x8086,
            device_id: 0x7a62,
            header_type: 0,
            class: 0x01,
            subclass: 0x06,
            programming_interface: 0x01,
            abar: 0xf7f0_0000,
            abar_bytes: 0x2000,
        })
        .unwrap()
    }

    fn authority(rights: Rights) -> (CapabilitySpace<2>, Capability, ObjectId) {
        let object = ObjectId(41);
        let mut capabilities = CapabilitySpace::new();
        let capability = capabilities.insert(object, rights).unwrap();
        (capabilities, capability, object)
    }

    #[test]
    fn maps_only_the_exact_descriptor_as_read_write_nx() {
        let rights = Rights::MAP.union(Rights::READ).union(Rights::WRITE);
        let (capabilities, capability, object) = authority(rights);
        let mut backend = RecordingBackend::default();
        let mapping = map_ahci_abar(
            &capabilities,
            capability,
            object,
            descriptor(),
            0xffff_9000_0000_0000,
            9,
            &mut backend,
        )
        .unwrap();
        assert_eq!(backend.mapping, Some(mapping));
        assert_eq!(mapping.configuration_generation, 7);
        assert_eq!(mapping.mapping_generation, 9);
        assert_eq!(mapping.bytes, 0x2000);
    }

    #[test]
    fn rejects_missing_rights_stale_handles_and_object_substitution() {
        for rights in [
            Rights::MAP.union(Rights::READ),
            Rights::MAP.union(Rights::WRITE),
            Rights::READ.union(Rights::WRITE),
        ] {
            let (capabilities, capability, object) = authority(rights);
            assert_eq!(
                map_ahci_abar(
                    &capabilities,
                    capability,
                    object,
                    descriptor(),
                    0x8000_0000,
                    1,
                    &mut RecordingBackend::default(),
                ),
                Err(AhciAbarMappingError::Capability(
                    CapabilityError::PermissionDenied
                ))
            );
        }

        let excessive = Rights::MAP
            .union(Rights::READ)
            .union(Rights::WRITE)
            .union(Rights::EXECUTE);
        let (capabilities, capability, object) = authority(excessive);
        assert_eq!(
            map_ahci_abar(
                &capabilities,
                capability,
                object,
                descriptor(),
                0x8000_0000,
                1,
                &mut RecordingBackend::default(),
            ),
            Err(AhciAbarMappingError::Capability(
                CapabilityError::PermissionDenied
            ))
        );

        let rights = Rights::MAP.union(Rights::READ).union(Rights::WRITE);
        let (mut capabilities, stale, object) = authority(rights);
        capabilities.revoke(stale).unwrap();
        assert_eq!(
            map_ahci_abar(
                &capabilities,
                stale,
                object,
                descriptor(),
                0x8000_0000,
                1,
                &mut RecordingBackend::default(),
            ),
            Err(AhciAbarMappingError::Capability(CapabilityError::Invalid))
        );

        let (capabilities, capability, _) = authority(rights);
        assert_eq!(
            map_ahci_abar(
                &capabilities,
                capability,
                ObjectId(42),
                descriptor(),
                0x8000_0000,
                1,
                &mut RecordingBackend::default(),
            ),
            Err(AhciAbarMappingError::WrongDeviceObject)
        );
    }

    #[test]
    fn rejects_invalid_ranges_generations_and_backend_failure() {
        let rights = Rights::MAP.union(Rights::READ).union(Rights::WRITE);
        let (capabilities, capability, object) = authority(rights);
        for (virtual_base, generation, expected) in [
            (0, 1, AhciAbarMappingError::InvalidVirtualRange),
            (0x8000_0001, 1, AhciAbarMappingError::InvalidVirtualRange),
            (
                u64::MAX - 0xfff,
                1,
                AhciAbarMappingError::InvalidVirtualRange,
            ),
            (
                0x8000_0000,
                0,
                AhciAbarMappingError::InvalidMappingGeneration,
            ),
        ] {
            assert_eq!(
                map_ahci_abar(
                    &capabilities,
                    capability,
                    object,
                    descriptor(),
                    virtual_base,
                    generation,
                    &mut RecordingBackend::default(),
                ),
                Err(expected)
            );
        }
        let mut backend = RecordingBackend {
            mapping: None,
            reject: true,
        };
        assert_eq!(
            map_ahci_abar(
                &capabilities,
                capability,
                object,
                descriptor(),
                0x8000_0000,
                1,
                &mut backend,
            ),
            Err(AhciAbarMappingError::BackendRejected)
        );
    }
}
