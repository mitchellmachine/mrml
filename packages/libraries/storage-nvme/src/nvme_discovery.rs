//! Authority-free validation of an enumerated NVMe PCI function.
//!
//! The platform PCI enumerator owns configuration-space access and destructive
//! BAR sizing. This module accepts an immutable, generation-bound snapshot and
//! emits identity and geometry only. Mapping or accessing controller registers
//! requires separate capabilities and later driver gates.

pub const NVME_PCI_CLASS: u8 = 0x01;
pub const NVME_PCI_SUBCLASS: u8 = 0x08;
pub const NVME_PCI_PROGRAMMING_INTERFACE: u8 = 0x02;
pub const NVME_CONTROLLER_BAR_MINIMUM_BYTES: u64 = 0x4000;

const PCI_BAR_IO_SPACE: u32 = 1;
const PCI_MEMORY_BAR_TYPE_MASK: u32 = 0b110;
const PCI_MEMORY_BAR_64_BIT: u32 = 0b100;
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
pub struct NvmePciFunctionSnapshot {
    pub location: PciFunctionLocation,
    pub configuration_generation: u64,
    pub vendor_id: u16,
    pub device_id: u16,
    pub header_type: u8,
    pub class: u8,
    pub subclass: u8,
    pub programming_interface: u8,
    /// BAR0 and BAR1 as restored after the enumerator's bounded size probe.
    pub controller_bar_low: u32,
    pub controller_bar_high: u32,
    pub controller_bar_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvmeControllerBarDescriptor {
    pub location: PciFunctionLocation,
    pub configuration_generation: u64,
    pub vendor_id: u16,
    pub device_id: u16,
    pub physical_base: u64,
    pub bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NvmeDiscoveryError {
    AbsentFunction,
    InvalidGeneration,
    UnsupportedHeader,
    NotNvme,
    IoBar,
    UnsupportedMemoryBar,
    PrefetchableBar,
    MissingControllerBar,
    InvalidControllerBarSize,
    MisalignedControllerBar,
    ControllerBarRangeOverflow,
}

impl NvmeControllerBarDescriptor {
    pub fn validate(snapshot: NvmePciFunctionSnapshot) -> Result<Self, NvmeDiscoveryError> {
        if snapshot.vendor_id == 0 || snapshot.vendor_id == u16::MAX {
            return Err(NvmeDiscoveryError::AbsentFunction);
        }
        if snapshot.configuration_generation == 0 {
            return Err(NvmeDiscoveryError::InvalidGeneration);
        }
        if snapshot.header_type & 0x7f != 0 {
            return Err(NvmeDiscoveryError::UnsupportedHeader);
        }
        if (
            snapshot.class,
            snapshot.subclass,
            snapshot.programming_interface,
        ) != (
            NVME_PCI_CLASS,
            NVME_PCI_SUBCLASS,
            NVME_PCI_PROGRAMMING_INTERFACE,
        ) {
            return Err(NvmeDiscoveryError::NotNvme);
        }
        if snapshot.controller_bar_low & PCI_BAR_IO_SPACE != 0 {
            return Err(NvmeDiscoveryError::IoBar);
        }
        if snapshot.controller_bar_low & PCI_MEMORY_BAR_TYPE_MASK != PCI_MEMORY_BAR_64_BIT {
            return Err(NvmeDiscoveryError::UnsupportedMemoryBar);
        }
        if snapshot.controller_bar_low & PCI_MEMORY_BAR_PREFETCHABLE != 0 {
            return Err(NvmeDiscoveryError::PrefetchableBar);
        }

        let physical_base = (u64::from(snapshot.controller_bar_high) << 32)
            | u64::from(snapshot.controller_bar_low & PCI_MEMORY_BAR_ADDRESS_MASK);
        if physical_base == 0 {
            return Err(NvmeDiscoveryError::MissingControllerBar);
        }
        if snapshot.controller_bar_bytes < NVME_CONTROLLER_BAR_MINIMUM_BYTES
            || !snapshot.controller_bar_bytes.is_power_of_two()
        {
            return Err(NvmeDiscoveryError::InvalidControllerBarSize);
        }
        if physical_base & (snapshot.controller_bar_bytes - 1) != 0 {
            return Err(NvmeDiscoveryError::MisalignedControllerBar);
        }
        if physical_base
            .checked_add(snapshot.controller_bar_bytes)
            .is_none()
        {
            return Err(NvmeDiscoveryError::ControllerBarRangeOverflow);
        }

        Ok(Self {
            location: snapshot.location,
            configuration_generation: snapshot.configuration_generation,
            vendor_id: snapshot.vendor_id,
            device_id: snapshot.device_id,
            physical_base,
            bytes: snapshot.controller_bar_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> NvmePciFunctionSnapshot {
        NvmePciFunctionSnapshot {
            location: PciFunctionLocation::new(0, 4, 0, 0).unwrap(),
            configuration_generation: 11,
            vendor_id: 0x144d,
            device_id: 0xa80b,
            header_type: 0,
            class: NVME_PCI_CLASS,
            subclass: NVME_PCI_SUBCLASS,
            programming_interface: NVME_PCI_PROGRAMMING_INTERFACE,
            controller_bar_low: 0x8000_0004,
            controller_bar_high: 0x0000_0001,
            controller_bar_bytes: 0x4000,
        }
    }

    #[test]
    fn accepts_exact_conventional_nvme_function_and_64_bit_bar() {
        let descriptor = NvmeControllerBarDescriptor::validate(snapshot()).unwrap();
        assert_eq!(descriptor.physical_base, 0x0000_0001_8000_0000);
        assert_eq!(descriptor.bytes, 0x4000);
        assert_eq!(descriptor.configuration_generation, 11);
    }

    #[test]
    fn rejects_other_storage_interfaces() {
        for (class, subclass, interface) in [
            (0x01, 0x08, 0x01),
            (0x01, 0x06, 0x01),
            (0x01, 0x01, 0x8a),
            (0x02, 0x00, 0x00),
        ] {
            let mut candidate = snapshot();
            candidate.class = class;
            candidate.subclass = subclass;
            candidate.programming_interface = interface;
            assert_eq!(
                NvmeControllerBarDescriptor::validate(candidate),
                Err(NvmeDiscoveryError::NotNvme)
            );
        }
    }

    #[test]
    fn rejects_absent_stale_or_non_type_zero_functions() {
        let mut candidate = snapshot();
        candidate.vendor_id = u16::MAX;
        assert_eq!(
            NvmeControllerBarDescriptor::validate(candidate),
            Err(NvmeDiscoveryError::AbsentFunction)
        );
        candidate = snapshot();
        candidate.configuration_generation = 0;
        assert_eq!(
            NvmeControllerBarDescriptor::validate(candidate),
            Err(NvmeDiscoveryError::InvalidGeneration)
        );
        candidate = snapshot();
        candidate.header_type = 1;
        assert_eq!(
            NvmeControllerBarDescriptor::validate(candidate),
            Err(NvmeDiscoveryError::UnsupportedHeader)
        );
    }

    #[test]
    fn rejects_unsafe_or_ambiguous_controller_bar_geometry() {
        for (low, high, bytes, error) in [
            (0x8000_0005, 1, 0x4000, NvmeDiscoveryError::IoBar),
            (
                0x8000_0000,
                1,
                0x4000,
                NvmeDiscoveryError::UnsupportedMemoryBar,
            ),
            (0x8000_000c, 1, 0x4000, NvmeDiscoveryError::PrefetchableBar),
            (
                0x0000_0004,
                0,
                0x4000,
                NvmeDiscoveryError::MissingControllerBar,
            ),
            (
                0x8000_0004,
                1,
                0x2000,
                NvmeDiscoveryError::InvalidControllerBarSize,
            ),
            (
                0x8000_0004,
                1,
                0x6000,
                NvmeDiscoveryError::InvalidControllerBarSize,
            ),
            (
                0x8000_4004,
                1,
                0x8000,
                NvmeDiscoveryError::MisalignedControllerBar,
            ),
        ] {
            let mut candidate = snapshot();
            candidate.controller_bar_low = low;
            candidate.controller_bar_high = high;
            candidate.controller_bar_bytes = bytes;
            assert_eq!(NvmeControllerBarDescriptor::validate(candidate), Err(error));
        }
    }

    #[test]
    fn rejects_controller_bar_range_overflow() {
        let mut candidate = snapshot();
        candidate.controller_bar_low = 0xffff_c004;
        candidate.controller_bar_high = u32::MAX;
        assert_eq!(
            NvmeControllerBarDescriptor::validate(candidate),
            Err(NvmeDiscoveryError::ControllerBarRangeOverflow)
        );
    }

    #[test]
    fn location_rejects_out_of_range_requester_fields() {
        assert!(PciFunctionLocation::new(0, 255, 31, 7).is_some());
        assert!(PciFunctionLocation::new(0, 0, 32, 0).is_none());
        assert!(PciFunctionLocation::new(0, 0, 0, 8).is_none());
    }
}
