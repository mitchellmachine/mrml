//! Capability-bound preparation of one validated NVMe controller BAR mapping.
//!
//! The backend must install a supervisor-only, read/write, non-executable MMIO
//! mapping and bind its revocation to both retained generations. This module
//! does not access controller registers.

use crate::NvmeControllerBarDescriptor;
use mrml_kernel::{Capability, CapabilityError, CapabilitySpace, ObjectId, Rights};

pub const NVME_MMIO_PAGE_BYTES: u64 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvmeControllerBarMapping {
    pub controller_object: ObjectId,
    pub configuration_generation: u64,
    pub mapping_generation: u64,
    pub physical_base: u64,
    pub virtual_base: u64,
    pub bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NvmeControllerBarMappingError {
    Capability(CapabilityError),
    WrongControllerObject,
    InvalidMappingGeneration,
    InvalidVirtualRange,
    BackendRejected,
}

pub trait NvmeControllerBarMappingBackend {
    fn map_read_write_nx(&mut self, mapping: NvmeControllerBarMapping) -> Result<(), ()>;
    /// Removes the exact supervisor mapping and completes TLB invalidation.
    fn unmap_read_write_nx(&mut self, mapping: NvmeControllerBarMapping) -> Result<(), ()>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvmeControllerBarUnmapError {
    pub mapping: NvmeControllerBarMapping,
}

pub fn map_nvme_controller_bar<const N: usize, B: NvmeControllerBarMappingBackend>(
    capabilities: &CapabilitySpace<N>,
    capability: Capability,
    controller_object: ObjectId,
    descriptor: NvmeControllerBarDescriptor,
    virtual_base: u64,
    mapping_generation: u64,
    backend: &mut B,
) -> Result<NvmeControllerBarMapping, NvmeControllerBarMappingError> {
    let required = Rights::MAP.union(Rights::READ).union(Rights::WRITE);
    let authorized = capabilities
        .authorize_exact(capability, required)
        .map_err(NvmeControllerBarMappingError::Capability)?;
    if authorized != controller_object {
        return Err(NvmeControllerBarMappingError::WrongControllerObject);
    }
    if mapping_generation == 0 {
        return Err(NvmeControllerBarMappingError::InvalidMappingGeneration);
    }
    if virtual_base == 0
        || virtual_base % NVME_MMIO_PAGE_BYTES != 0
        || descriptor.physical_base % NVME_MMIO_PAGE_BYTES != 0
        || descriptor.bytes % NVME_MMIO_PAGE_BYTES != 0
        || virtual_base.checked_add(descriptor.bytes).is_none()
    {
        return Err(NvmeControllerBarMappingError::InvalidVirtualRange);
    }

    let mapping = NvmeControllerBarMapping {
        controller_object,
        configuration_generation: descriptor.configuration_generation,
        mapping_generation,
        physical_base: descriptor.physical_base,
        virtual_base,
        bytes: descriptor.bytes,
    };
    backend
        .map_read_write_nx(mapping)
        .map_err(|_| NvmeControllerBarMappingError::BackendRejected)?;
    Ok(mapping)
}

pub fn unmap_nvme_controller_bar<B: NvmeControllerBarMappingBackend>(
    mapping: NvmeControllerBarMapping,
    backend: &mut B,
) -> Result<(), NvmeControllerBarUnmapError> {
    backend
        .unmap_read_write_nx(mapping)
        .map_err(|_| NvmeControllerBarUnmapError { mapping })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        NvmePciFunctionSnapshot, PciFunctionLocation, NVME_PCI_CLASS,
        NVME_PCI_PROGRAMMING_INTERFACE, NVME_PCI_SUBCLASS,
    };

    #[derive(Default)]
    struct RecordingBackend {
        mapping: Option<NvmeControllerBarMapping>,
        reject: bool,
    }

    impl NvmeControllerBarMappingBackend for RecordingBackend {
        fn map_read_write_nx(&mut self, mapping: NvmeControllerBarMapping) -> Result<(), ()> {
            if self.reject {
                return Err(());
            }
            self.mapping = Some(mapping);
            Ok(())
        }
        fn unmap_read_write_nx(&mut self, mapping: NvmeControllerBarMapping) -> Result<(), ()> {
            if self.reject || self.mapping != Some(mapping) {
                return Err(());
            }
            self.mapping = None;
            Ok(())
        }
    }

    fn descriptor() -> NvmeControllerBarDescriptor {
        NvmeControllerBarDescriptor::validate(NvmePciFunctionSnapshot {
            location: PciFunctionLocation::new(0, 4, 0, 0).unwrap(),
            configuration_generation: 11,
            vendor_id: 0x144d,
            device_id: 0xa80b,
            header_type: 0,
            class: NVME_PCI_CLASS,
            subclass: NVME_PCI_SUBCLASS,
            programming_interface: NVME_PCI_PROGRAMMING_INTERFACE,
            controller_bar_low: 0x8000_0004,
            controller_bar_high: 1,
            controller_bar_bytes: 0x4000,
        })
        .unwrap()
    }

    fn authority(rights: Rights) -> (CapabilitySpace<2>, Capability, ObjectId) {
        let object = ObjectId(71);
        let mut capabilities = CapabilitySpace::new();
        let capability = capabilities.insert(object, rights).unwrap();
        (capabilities, capability, object)
    }

    #[test]
    fn maps_only_the_exact_controller_range_as_read_write_nx() {
        let rights = Rights::MAP.union(Rights::READ).union(Rights::WRITE);
        let (capabilities, capability, object) = authority(rights);
        let mut backend = RecordingBackend::default();
        let mapping = map_nvme_controller_bar(
            &capabilities,
            capability,
            object,
            descriptor(),
            0xffff_a000_0000_0000,
            9,
            &mut backend,
        )
        .unwrap();
        assert_eq!(backend.mapping, Some(mapping));
        assert_eq!(mapping.configuration_generation, 11);
        assert_eq!(mapping.mapping_generation, 9);
        assert_eq!(mapping.bytes, 0x4000);
    }

    #[test]
    fn rejects_missing_excess_stale_or_substituted_authority() {
        for rights in [
            Rights::MAP.union(Rights::READ),
            Rights::MAP.union(Rights::WRITE),
            Rights::READ.union(Rights::WRITE),
            Rights::MAP
                .union(Rights::READ)
                .union(Rights::WRITE)
                .union(Rights::EXECUTE),
        ] {
            let (capabilities, capability, object) = authority(rights);
            assert!(matches!(
                map_nvme_controller_bar(
                    &capabilities,
                    capability,
                    object,
                    descriptor(),
                    0x8000_0000,
                    1,
                    &mut RecordingBackend::default(),
                ),
                Err(NvmeControllerBarMappingError::Capability(_))
            ));
        }
        let rights = Rights::MAP.union(Rights::READ).union(Rights::WRITE);
        let (mut capabilities, stale, object) = authority(rights);
        capabilities.revoke(stale).unwrap();
        assert!(matches!(
            map_nvme_controller_bar(
                &capabilities,
                stale,
                object,
                descriptor(),
                0x8000_0000,
                1,
                &mut RecordingBackend::default(),
            ),
            Err(NvmeControllerBarMappingError::Capability(_))
        ));
        let (capabilities, capability, _) = authority(rights);
        assert_eq!(
            map_nvme_controller_bar(
                &capabilities,
                capability,
                ObjectId(72),
                descriptor(),
                0x8000_0000,
                1,
                &mut RecordingBackend::default(),
            ),
            Err(NvmeControllerBarMappingError::WrongControllerObject)
        );
    }

    #[test]
    fn rejects_invalid_range_generation_and_backend_failure() {
        let rights = Rights::MAP.union(Rights::READ).union(Rights::WRITE);
        let (capabilities, capability, object) = authority(rights);
        for (virtual_base, generation, expected) in [
            (0, 1, NvmeControllerBarMappingError::InvalidVirtualRange),
            (
                0x8000_0001,
                1,
                NvmeControllerBarMappingError::InvalidVirtualRange,
            ),
            (
                u64::MAX - 0xfff,
                1,
                NvmeControllerBarMappingError::InvalidVirtualRange,
            ),
            (
                0x8000_0000,
                0,
                NvmeControllerBarMappingError::InvalidMappingGeneration,
            ),
        ] {
            assert_eq!(
                map_nvme_controller_bar(
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
            map_nvme_controller_bar(
                &capabilities,
                capability,
                object,
                descriptor(),
                0x8000_0000,
                1,
                &mut backend,
            ),
            Err(NvmeControllerBarMappingError::BackendRejected)
        );
    }

    #[test]
    fn unmap_retains_exact_mapping_until_backend_confirms_invalidation() {
        let rights = Rights::MAP.union(Rights::READ).union(Rights::WRITE);
        let (capabilities, capability, object) = authority(rights);
        let mut backend = RecordingBackend::default();
        let mapping = map_nvme_controller_bar(
            &capabilities,
            capability,
            object,
            descriptor(),
            0x8000_0000,
            1,
            &mut backend,
        )
        .unwrap();
        backend.reject = true;
        assert_eq!(
            unmap_nvme_controller_bar(mapping, &mut backend),
            Err(NvmeControllerBarUnmapError { mapping })
        );
        backend.reject = false;
        assert_eq!(unmap_nvme_controller_bar(mapping, &mut backend), Ok(()));
        assert_eq!(backend.mapping, None);
    }
}
