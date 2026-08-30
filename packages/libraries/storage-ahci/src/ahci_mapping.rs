//! Capability-bound preparation of one validated AHCI ABAR mapping.
//!
//! This module does not access controller registers. The platform mapper remains
//! responsible for installing the range only in the exact isolated driver task,
//! user-accessible there, read/write, non-executable, and with the x86 device-PAT
//! selector. It must independently prove that PAT index 3 is UC, exclude
//! cacheable aliases, and invalidate the mapping when either generation retires.
//! No ordinary application or other task may receive the mapping.

use crate::{AHCI_ABAR_MINIMUM_BYTES, AhciAbarDescriptor};
use mrml_kernel::arch::x86_64::PagePermissions;
use mrml_kernel::{Capability, CapabilityError, CapabilitySpace, ObjectId, Rights};

pub const AHCI_MMIO_PAGE_BYTES: u64 = 4096;
pub const AHCI_ABAR_PAGE_PERMISSIONS: PagePermissions = PagePermissions::USER_MMIO_READ_WRITE;

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
    InvalidDescriptor,
    InvalidMappingGeneration,
    InvalidVirtualRange,
    BackendRejected,
}

fn descriptor_is_well_formed(descriptor: AhciAbarDescriptor) -> bool {
    let Some(physical_end) = descriptor.physical_base.checked_add(descriptor.bytes) else {
        return false;
    };
    descriptor.location.device <= 31
        && descriptor.location.function <= 7
        && descriptor.configuration_generation != 0
        && descriptor.vendor_id != 0
        && descriptor.vendor_id != u16::MAX
        && descriptor.physical_base != 0
        && descriptor.physical_base <= u64::from(u32::MAX)
        && descriptor.bytes >= AHCI_ABAR_MINIMUM_BYTES
        && descriptor.bytes.is_power_of_two()
        && descriptor.physical_base & (descriptor.bytes - 1) == 0
        && physical_end <= 1u64 << 32
}

/// Privileged installation boundary for one isolated AHCI driver address space.
///
/// # Safety
///
/// The backend value must be bound to the exact target task/address-space root.
/// A successful call must install only [`AHCI_ABAR_PAGE_PERMISSIONS`] for the
/// exact range, with PAT index 3 proved UC and no cacheable alias. It must not
/// expose the range to another task or ordinary application.
pub unsafe trait AhciAbarMappingBackend {
    /// Installs an exact task-local MMIO mapping using
    /// [`AHCI_ABAR_PAGE_PERMISSIONS`].
    ///
    /// The backend must already be bound to the isolated driver address space;
    /// it must not broaden the range, install the leaf in any other task, or
    /// create a cacheable alias. It must establish that x86 PAT index 3 is UC
    /// and bind revocation to both generations retained in `mapping`.
    fn map_read_write_nx(&mut self, mapping: AhciAbarMapping) -> Result<(), ()>;
}

/// Privileged withdrawal boundary for one exact installed ABAR mapping.
///
/// # Safety
///
/// Success must mean that every CPU translation for the exact task-bound range
/// is absent and no consumer can access it. Failure must retain the mapping or
/// fail-stop every possible consumer.
pub unsafe trait AhciAbarRemovalBackend {
    /// Success confirms that the mapping and required translation-cache state
    /// are absent. Failure retains the mapping or fail-stops every consumer.
    fn unmap_read_write_nx(&mut self, mapping: AhciAbarMapping) -> Result<(), ()>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstalledAhciAbarMapping {
    mapping: AhciAbarMapping,
}

impl InstalledAhciAbarMapping {
    pub const fn mapping(self) -> AhciAbarMapping {
        self.mapping
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciAbarRemovalError {
    Capability {
        error: CapabilityError,
        retained: InstalledAhciAbarMapping,
    },
    WrongDeviceObject {
        retained: InstalledAhciAbarMapping,
    },
    BackendRejected {
        retained: InstalledAhciAbarMapping,
    },
}

impl AhciAbarRemovalError {
    pub const fn retained(self) -> InstalledAhciAbarMapping {
        match self {
            Self::Capability { retained, .. }
            | Self::WrongDeviceObject { retained }
            | Self::BackendRejected { retained } => retained,
        }
    }
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
    if !descriptor_is_well_formed(descriptor) {
        return Err(AhciAbarMappingError::InvalidDescriptor);
    }
    let virtual_end = virtual_base
        .checked_add(descriptor.bytes)
        .ok_or(AhciAbarMappingError::InvalidVirtualRange)?;
    if virtual_base == 0
        || virtual_base % AHCI_MMIO_PAGE_BYTES != 0
        || descriptor.physical_base % AHCI_MMIO_PAGE_BYTES != 0
        || descriptor.bytes % AHCI_MMIO_PAGE_BYTES != 0
        || virtual_end > 1 << 47
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

pub fn install_ahci_service_abar<const N: usize, B: AhciAbarMappingBackend>(
    capabilities: &CapabilitySpace<N>,
    capability: Capability,
    device_object: ObjectId,
    descriptor: AhciAbarDescriptor,
    virtual_base: u64,
    mapping_generation: u64,
    backend: &mut B,
) -> Result<InstalledAhciAbarMapping, AhciAbarMappingError> {
    map_ahci_abar(
        capabilities,
        capability,
        device_object,
        descriptor,
        virtual_base,
        mapping_generation,
        backend,
    )
    .map(|mapping| InstalledAhciAbarMapping { mapping })
}

pub fn remove_ahci_service_abar<const N: usize, B: AhciAbarRemovalBackend>(
    installed: InstalledAhciAbarMapping,
    capabilities: &CapabilitySpace<N>,
    control: Capability,
    backend: &mut B,
) -> Result<AhciAbarMapping, AhciAbarRemovalError> {
    let object = capabilities
        .authorize_exact(control, Rights::CONTROL)
        .map_err(|error| AhciAbarRemovalError::Capability {
            error,
            retained: installed,
        })?;
    if object != installed.mapping.device_object {
        return Err(AhciAbarRemovalError::WrongDeviceObject {
            retained: installed,
        });
    }
    backend
        .unmap_read_write_nx(installed.mapping)
        .map_err(|_| AhciAbarRemovalError::BackendRejected {
            retained: installed,
        })?;
    Ok(installed.mapping)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AhciPciFunctionSnapshot, PciFunctionLocation};

    #[derive(Default)]
    struct RecordingBackend {
        mapping: Option<AhciAbarMapping>,
        reject: bool,
        reject_unmap: bool,
    }

    unsafe impl AhciAbarMappingBackend for RecordingBackend {
        fn map_read_write_nx(&mut self, mapping: AhciAbarMapping) -> Result<(), ()> {
            if self.reject {
                return Err(());
            }
            self.mapping = Some(mapping);
            Ok(())
        }
    }

    unsafe impl AhciAbarRemovalBackend for RecordingBackend {
        fn unmap_read_write_nx(&mut self, mapping: AhciAbarMapping) -> Result<(), ()> {
            if self.reject_unmap || self.mapping != Some(mapping) {
                return Err(());
            }
            self.mapping = None;
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
    fn maps_only_validated_descriptor_geometry_as_read_write_nx() {
        let rights = Rights::MAP.union(Rights::READ).union(Rights::WRITE);
        let (capabilities, capability, object) = authority(rights);
        let mut backend = RecordingBackend::default();
        let mapping = map_ahci_abar(
            &capabilities,
            capability,
            object,
            descriptor(),
            0x20_0000,
            9,
            &mut backend,
        )
        .unwrap();
        assert_eq!(backend.mapping, Some(mapping));
        assert_eq!(mapping.configuration_generation, 7);
        assert_eq!(mapping.mapping_generation, 9);
        assert_eq!(mapping.bytes, 0x2000);
        assert_eq!(
            AHCI_ABAR_PAGE_PERMISSIONS,
            PagePermissions::USER_MMIO_READ_WRITE
        );
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
                (1 << 47) - 0x1000,
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

        let valid = descriptor();
        for invalid in [
            AhciAbarDescriptor {
                configuration_generation: 0,
                ..valid
            },
            AhciAbarDescriptor {
                physical_base: 0,
                ..valid
            },
            AhciAbarDescriptor { bytes: 0, ..valid },
            AhciAbarDescriptor {
                bytes: 0x1000,
                ..valid
            },
            AhciAbarDescriptor {
                bytes: 0x3000,
                ..valid
            },
            AhciAbarDescriptor {
                physical_base: 0x1_0000_0000,
                ..valid
            },
            AhciAbarDescriptor {
                location: PciFunctionLocation {
                    device: 32,
                    ..valid.location
                },
                ..valid
            },
        ] {
            let mut backend = RecordingBackend::default();
            assert_eq!(
                map_ahci_abar(
                    &capabilities,
                    capability,
                    object,
                    invalid,
                    0x8000_0000,
                    1,
                    &mut backend,
                ),
                Err(AhciAbarMappingError::InvalidDescriptor)
            );
            assert_eq!(backend.mapping, None);
        }

        let mut backend = RecordingBackend {
            mapping: None,
            reject: true,
            reject_unmap: false,
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

    #[test]
    fn installed_mapping_requires_exact_control_and_retains_uncertain_cleanup() {
        let map_rights = Rights::MAP.union(Rights::READ).union(Rights::WRITE);
        let (mut capabilities, mapping_capability, object) = authority(map_rights);
        let control = capabilities.insert(object, Rights::CONTROL).unwrap();
        let mut backend = RecordingBackend::default();
        let installed = install_ahci_service_abar(
            &capabilities,
            mapping_capability,
            object,
            descriptor(),
            0x8000_0000,
            9,
            &mut backend,
        )
        .unwrap();
        backend.reject_unmap = true;
        let error =
            remove_ahci_service_abar(installed, &capabilities, control, &mut backend).unwrap_err();
        let AhciAbarRemovalError::BackendRejected { retained } = error else {
            panic!("expected retained ABAR mapping");
        };
        assert_eq!(backend.mapping, Some(retained.mapping()));
        backend.reject_unmap = false;
        assert_eq!(
            remove_ahci_service_abar(retained, &capabilities, control, &mut backend),
            Ok(installed.mapping())
        );
        assert_eq!(backend.mapping, None);
    }

    #[test]
    fn wrong_control_object_never_reaches_unmap_backend() {
        let map_rights = Rights::MAP.union(Rights::READ).union(Rights::WRITE);
        let (mut capabilities, mapping_capability, object) = authority(map_rights);
        let wrong = capabilities.insert(ObjectId(42), Rights::CONTROL).unwrap();
        let mut backend = RecordingBackend::default();
        let installed = install_ahci_service_abar(
            &capabilities,
            mapping_capability,
            object,
            descriptor(),
            0x8000_0000,
            9,
            &mut backend,
        )
        .unwrap();
        assert!(matches!(
            remove_ahci_service_abar(installed, &capabilities, wrong, &mut backend),
            Err(AhciAbarRemovalError::WrongDeviceObject { .. })
        ));
        assert_eq!(backend.mapping, Some(installed.mapping()));
    }
}
