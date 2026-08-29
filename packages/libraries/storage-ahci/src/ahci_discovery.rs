//! Authority-free validation of an enumerated AHCI PCI function.
//!
//! The platform PCI enumerator remains responsible for configuration-space
//! access and BAR sizing. This module accepts its immutable snapshot and emits
//! identity/geometry only; mapping or accessing the ABAR requires separate
//! capabilities and a later driver layer.

pub const AHCI_PCI_CLASS: u8 = 0x01;
pub const AHCI_PCI_SUBCLASS: u8 = 0x06;
pub const AHCI_PCI_PROGRAMMING_INTERFACE: u8 = 0x01;
pub const AHCI_ABAR_MINIMUM_BYTES: u64 = 0x1100;

const PCI_BAR_IO_SPACE: u32 = 1;
const PCI_MEMORY_BAR_TYPE_MASK: u32 = 0b110;
const PCI_MEMORY_BAR_32_BIT: u32 = 0;
const PCI_MEMORY_BAR_PREFETCHABLE: u32 = 0b1000;
const PCI_MEMORY_BAR_ADDRESS_MASK: u32 = 0xffff_fff0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciFunctionLocation {
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciFunctionLocation {
    pub const fn new(segment: u16, bus: u8, device: u8, function: u8) -> Option<Self> {
        if device > 31 || function > 7 {
            return None;
        }
        Some(Self {
            segment,
            bus,
            device,
            function,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AhciPciFunctionSnapshot {
    pub location: PciFunctionLocation,
    pub configuration_generation: u64,
    pub vendor_id: u16,
    pub device_id: u16,
    pub header_type: u8,
    pub class: u8,
    pub subclass: u8,
    pub programming_interface: u8,
    /// BAR5 as read before the enumerator's bounded size probe.
    pub abar: u32,
    /// Restored BAR5 size established by the enumerator's bounded size probe.
    pub abar_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AhciAbarDescriptor {
    pub location: PciFunctionLocation,
    pub configuration_generation: u64,
    pub vendor_id: u16,
    pub device_id: u16,
    pub physical_base: u64,
    pub bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciDiscoveryError {
    AbsentFunction,
    InvalidGeneration,
    UnsupportedHeader,
    NotAhci,
    IoBar,
    UnsupportedMemoryBar,
    PrefetchableBar,
    MissingAbar,
    InvalidAbarSize,
    MisalignedAbar,
}

impl AhciAbarDescriptor {
    pub fn validate(snapshot: AhciPciFunctionSnapshot) -> Result<Self, AhciDiscoveryError> {
        if snapshot.vendor_id == 0 || snapshot.vendor_id == u16::MAX {
            return Err(AhciDiscoveryError::AbsentFunction);
        }
        if snapshot.configuration_generation == 0 {
            return Err(AhciDiscoveryError::InvalidGeneration);
        }
        if snapshot.header_type & 0x7f != 0 {
            return Err(AhciDiscoveryError::UnsupportedHeader);
        }
        if (
            snapshot.class,
            snapshot.subclass,
            snapshot.programming_interface,
        ) != (
            AHCI_PCI_CLASS,
            AHCI_PCI_SUBCLASS,
            AHCI_PCI_PROGRAMMING_INTERFACE,
        ) {
            return Err(AhciDiscoveryError::NotAhci);
        }
        if snapshot.abar & PCI_BAR_IO_SPACE != 0 {
            return Err(AhciDiscoveryError::IoBar);
        }
        if snapshot.abar & PCI_MEMORY_BAR_TYPE_MASK != PCI_MEMORY_BAR_32_BIT {
            return Err(AhciDiscoveryError::UnsupportedMemoryBar);
        }
        if snapshot.abar & PCI_MEMORY_BAR_PREFETCHABLE != 0 {
            return Err(AhciDiscoveryError::PrefetchableBar);
        }

        let physical_base = u64::from(snapshot.abar & PCI_MEMORY_BAR_ADDRESS_MASK);
        if physical_base == 0 {
            return Err(AhciDiscoveryError::MissingAbar);
        }
        if snapshot.abar_bytes < AHCI_ABAR_MINIMUM_BYTES || !snapshot.abar_bytes.is_power_of_two() {
            return Err(AhciDiscoveryError::InvalidAbarSize);
        }
        if physical_base & (snapshot.abar_bytes - 1) != 0 {
            return Err(AhciDiscoveryError::MisalignedAbar);
        }

        Ok(Self {
            location: snapshot.location,
            configuration_generation: snapshot.configuration_generation,
            vendor_id: snapshot.vendor_id,
            device_id: snapshot.device_id,
            physical_base,
            bytes: snapshot.abar_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> AhciPciFunctionSnapshot {
        AhciPciFunctionSnapshot {
            location: PciFunctionLocation::new(0, 0, 31, 2).unwrap(),
            configuration_generation: 7,
            vendor_id: 0x8086,
            device_id: 0x7a62,
            header_type: 0,
            class: AHCI_PCI_CLASS,
            subclass: AHCI_PCI_SUBCLASS,
            programming_interface: AHCI_PCI_PROGRAMMING_INTERFACE,
            abar: 0xf7f0_0000,
            abar_bytes: 0x2000,
        }
    }

    #[test]
    fn accepts_exact_conventional_ahci_function() {
        let descriptor = AhciAbarDescriptor::validate(snapshot()).unwrap();
        assert_eq!(descriptor.physical_base, 0xf7f0_0000);
        assert_eq!(descriptor.bytes, 0x2000);
        assert_eq!(descriptor.configuration_generation, 7);
    }

    #[test]
    fn rejects_other_mass_storage_interfaces() {
        for (class, subclass, interface) in [
            (0x01, 0x06, 0x00),
            (0x01, 0x08, 0x02),
            (0x01, 0x04, 0x00),
            (0x02, 0x00, 0x00),
        ] {
            let mut candidate = snapshot();
            candidate.class = class;
            candidate.subclass = subclass;
            candidate.programming_interface = interface;
            assert_eq!(
                AhciAbarDescriptor::validate(candidate),
                Err(AhciDiscoveryError::NotAhci)
            );
        }
    }

    #[test]
    fn rejects_absent_stale_or_non_type_zero_functions() {
        let mut candidate = snapshot();
        candidate.vendor_id = u16::MAX;
        assert_eq!(
            AhciAbarDescriptor::validate(candidate),
            Err(AhciDiscoveryError::AbsentFunction)
        );
        candidate = snapshot();
        candidate.configuration_generation = 0;
        assert_eq!(
            AhciAbarDescriptor::validate(candidate),
            Err(AhciDiscoveryError::InvalidGeneration)
        );
        candidate = snapshot();
        candidate.header_type = 1;
        assert_eq!(
            AhciAbarDescriptor::validate(candidate),
            Err(AhciDiscoveryError::UnsupportedHeader)
        );
    }

    #[test]
    fn rejects_unsafe_or_ambiguous_abar_geometry() {
        for (abar, bytes, error) in [
            (0xf7f0_0001, 0x2000, AhciDiscoveryError::IoBar),
            (
                0xf7f0_0004,
                0x2000,
                AhciDiscoveryError::UnsupportedMemoryBar,
            ),
            (0xf7f0_0008, 0x2000, AhciDiscoveryError::PrefetchableBar),
            (0, 0x2000, AhciDiscoveryError::MissingAbar),
            (0xf7f0_0000, 0x1000, AhciDiscoveryError::InvalidAbarSize),
            (0xf7f0_0000, 0x3000, AhciDiscoveryError::InvalidAbarSize),
            (0xf7f0_1000, 0x2000, AhciDiscoveryError::MisalignedAbar),
        ] {
            let mut candidate = snapshot();
            candidate.abar = abar;
            candidate.abar_bytes = bytes;
            assert_eq!(AhciAbarDescriptor::validate(candidate), Err(error));
        }
    }

    #[test]
    fn location_rejects_out_of_range_requester_fields() {
        assert!(PciFunctionLocation::new(0, 0, 31, 7).is_some());
        assert!(PciFunctionLocation::new(0, 0, 32, 0).is_none());
        assert!(PciFunctionLocation::new(0, 0, 0, 8).is_none());
    }
}
