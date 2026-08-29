//! Authority-free validation of a PCI IDE controller snapshot.

pub const IDE_PCI_CLASS: u8 = 0x01;
pub const IDE_PCI_SUBCLASS: u8 = 0x01;

const PRIMARY_NATIVE: u8 = 1 << 0;
const PRIMARY_SWITCHABLE: u8 = 1 << 1;
const SECONDARY_NATIVE: u8 = 1 << 2;
const SECONDARY_SWITCHABLE: u8 = 1 << 3;
const BUS_MASTER: u8 = 1 << 7;
const RESERVED_PROGRAMMING_INTERFACE_BITS: u8 = 0x70;
const IO_BAR: u32 = 1;
const IO_BAR_ADDRESS_MASK: u32 = 0xffff_fffc;

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
pub struct IdePciFunctionSnapshot {
    pub location: PciFunctionLocation,
    pub configuration_generation: u64,
    pub vendor_id: u16,
    pub device_id: u16,
    pub header_type: u8,
    pub class: u8,
    pub subclass: u8,
    pub programming_interface: u8,
    pub bars: [u32; 5],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdeChannelMode {
    Compatibility,
    Native,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdeChannelDescriptor {
    pub mode: IdeChannelMode,
    pub switchable: bool,
    pub command_base: u16,
    pub control_base: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdeControllerDescriptor {
    pub location: PciFunctionLocation,
    pub configuration_generation: u64,
    pub vendor_id: u16,
    pub device_id: u16,
    pub primary: IdeChannelDescriptor,
    pub secondary: IdeChannelDescriptor,
    pub bus_master_base: Option<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdeDiscoveryError {
    AbsentFunction,
    InvalidGeneration,
    UnsupportedHeader,
    NotIde,
    ReservedProgrammingInterface,
    MissingNativeCommandBar,
    MissingNativeControlBar,
    MissingBusMasterBar,
    NotIoBar,
    PortOutOfRange,
    MisalignedCommandBar,
    MisalignedBusMasterBar,
}

impl IdeControllerDescriptor {
    pub fn validate(snapshot: IdePciFunctionSnapshot) -> Result<Self, IdeDiscoveryError> {
        if snapshot.vendor_id == 0 || snapshot.vendor_id == u16::MAX {
            return Err(IdeDiscoveryError::AbsentFunction);
        }
        if snapshot.configuration_generation == 0 {
            return Err(IdeDiscoveryError::InvalidGeneration);
        }
        if snapshot.header_type & 0x7f != 0 {
            return Err(IdeDiscoveryError::UnsupportedHeader);
        }
        if (snapshot.class, snapshot.subclass) != (IDE_PCI_CLASS, IDE_PCI_SUBCLASS) {
            return Err(IdeDiscoveryError::NotIde);
        }
        if snapshot.programming_interface & RESERVED_PROGRAMMING_INTERFACE_BITS != 0 {
            return Err(IdeDiscoveryError::ReservedProgrammingInterface);
        }

        let primary = channel(
            snapshot.programming_interface & PRIMARY_NATIVE != 0,
            snapshot.programming_interface & PRIMARY_SWITCHABLE != 0,
            snapshot.bars[0],
            snapshot.bars[1],
            0x1f0,
            0x3f6,
        )?;
        let secondary = channel(
            snapshot.programming_interface & SECONDARY_NATIVE != 0,
            snapshot.programming_interface & SECONDARY_SWITCHABLE != 0,
            snapshot.bars[2],
            snapshot.bars[3],
            0x170,
            0x376,
        )?;
        let bus_master_base = if snapshot.programming_interface & BUS_MASTER != 0 {
            let base = io_base(snapshot.bars[4], IdeDiscoveryError::MissingBusMasterBar)?;
            if base & 0x0f != 0 {
                return Err(IdeDiscoveryError::MisalignedBusMasterBar);
            }
            Some(base)
        } else {
            None
        };

        Ok(Self {
            location: snapshot.location,
            configuration_generation: snapshot.configuration_generation,
            vendor_id: snapshot.vendor_id,
            device_id: snapshot.device_id,
            primary,
            secondary,
            bus_master_base,
        })
    }
}

fn channel(
    native: bool,
    switchable: bool,
    command_bar: u32,
    control_bar: u32,
    compatibility_command: u16,
    compatibility_control: u16,
) -> Result<IdeChannelDescriptor, IdeDiscoveryError> {
    if !native {
        return Ok(IdeChannelDescriptor {
            mode: IdeChannelMode::Compatibility,
            switchable,
            command_base: compatibility_command,
            control_base: compatibility_control,
        });
    }
    let command_base = io_base(command_bar, IdeDiscoveryError::MissingNativeCommandBar)?;
    let control_base = io_base(control_bar, IdeDiscoveryError::MissingNativeControlBar)?;
    if command_base & 7 != 0 {
        return Err(IdeDiscoveryError::MisalignedCommandBar);
    }
    Ok(IdeChannelDescriptor {
        mode: IdeChannelMode::Native,
        switchable,
        command_base,
        control_base: control_base
            .checked_add(2)
            .ok_or(IdeDiscoveryError::PortOutOfRange)?,
    })
}

fn io_base(bar: u32, missing: IdeDiscoveryError) -> Result<u16, IdeDiscoveryError> {
    if bar == 0 {
        return Err(missing);
    }
    if bar & IO_BAR == 0 {
        return Err(IdeDiscoveryError::NotIoBar);
    }
    u16::try_from(bar & IO_BAR_ADDRESS_MASK).map_err(|_| IdeDiscoveryError::PortOutOfRange)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> IdePciFunctionSnapshot {
        IdePciFunctionSnapshot {
            location: PciFunctionLocation::new(0, 0, 31, 1).unwrap(),
            configuration_generation: 4,
            vendor_id: 0x8086,
            device_id: 0x7010,
            header_type: 0,
            class: IDE_PCI_CLASS,
            subclass: IDE_PCI_SUBCLASS,
            programming_interface: 0,
            bars: [0; 5],
        }
    }

    #[test]
    fn compatibility_mode_uses_fixed_legacy_ports_without_trusting_bars() {
        let mut candidate = snapshot();
        candidate.programming_interface = PRIMARY_SWITCHABLE | SECONDARY_SWITCHABLE;
        candidate.bars = [u32::MAX; 5];
        let descriptor = IdeControllerDescriptor::validate(candidate).unwrap();
        assert_eq!(descriptor.primary.command_base, 0x1f0);
        assert_eq!(descriptor.primary.control_base, 0x3f6);
        assert_eq!(descriptor.secondary.command_base, 0x170);
        assert_eq!(descriptor.secondary.control_base, 0x376);
        assert_eq!(descriptor.bus_master_base, None);
    }

    #[test]
    fn native_mode_validates_io_bars_and_control_register_offset() {
        let mut candidate = snapshot();
        candidate.programming_interface = PRIMARY_NATIVE | SECONDARY_NATIVE | BUS_MASTER;
        candidate.bars = [0x2001, 0x2101, 0x2201, 0x2301, 0x2401];
        let descriptor = IdeControllerDescriptor::validate(candidate).unwrap();
        assert_eq!(descriptor.primary.command_base, 0x2000);
        assert_eq!(descriptor.primary.control_base, 0x2102);
        assert_eq!(descriptor.secondary.command_base, 0x2200);
        assert_eq!(descriptor.secondary.control_base, 0x2302);
        assert_eq!(descriptor.bus_master_base, Some(0x2400));
    }

    #[test]
    fn rejects_absent_stale_wrong_class_reserved_or_bridge_functions() {
        let cases = [
            (
                u16::MAX,
                1,
                0,
                IDE_PCI_CLASS,
                IDE_PCI_SUBCLASS,
                0,
                IdeDiscoveryError::AbsentFunction,
            ),
            (
                1,
                0,
                0,
                IDE_PCI_CLASS,
                IDE_PCI_SUBCLASS,
                0,
                IdeDiscoveryError::InvalidGeneration,
            ),
            (
                1,
                1,
                1,
                IDE_PCI_CLASS,
                IDE_PCI_SUBCLASS,
                0,
                IdeDiscoveryError::UnsupportedHeader,
            ),
            (1, 1, 0, 2, 0, 0, IdeDiscoveryError::NotIde),
            (
                1,
                1,
                0,
                IDE_PCI_CLASS,
                IDE_PCI_SUBCLASS,
                0x10,
                IdeDiscoveryError::ReservedProgrammingInterface,
            ),
        ];
        for (vendor, generation, header, class, subclass, interface, error) in cases {
            let mut candidate = snapshot();
            candidate.vendor_id = vendor;
            candidate.configuration_generation = generation;
            candidate.header_type = header;
            candidate.class = class;
            candidate.subclass = subclass;
            candidate.programming_interface = interface;
            assert_eq!(IdeControllerDescriptor::validate(candidate), Err(error));
        }
    }

    #[test]
    fn rejects_missing_memory_or_misaligned_native_bars() {
        for (bars, interface, error) in [
            (
                [0, 0x2101, 0, 0, 0],
                PRIMARY_NATIVE,
                IdeDiscoveryError::MissingNativeCommandBar,
            ),
            (
                [0x2001, 0, 0, 0, 0],
                PRIMARY_NATIVE,
                IdeDiscoveryError::MissingNativeControlBar,
            ),
            (
                [0x2000, 0x2101, 0, 0, 0],
                PRIMARY_NATIVE,
                IdeDiscoveryError::NotIoBar,
            ),
            (
                [0x2005, 0x2101, 0, 0, 0],
                PRIMARY_NATIVE,
                IdeDiscoveryError::MisalignedCommandBar,
            ),
            (
                [0, 0, 0, 0, 0],
                BUS_MASTER,
                IdeDiscoveryError::MissingBusMasterBar,
            ),
            (
                [0, 0, 0, 0, 0x2405],
                BUS_MASTER,
                IdeDiscoveryError::MisalignedBusMasterBar,
            ),
        ] {
            let mut candidate = snapshot();
            candidate.bars = bars;
            candidate.programming_interface = interface;
            assert_eq!(IdeControllerDescriptor::validate(candidate), Err(error));
        }
    }

    #[test]
    fn rejects_ports_outside_x86_io_space() {
        let mut candidate = snapshot();
        candidate.programming_interface = PRIMARY_NATIVE;
        candidate.bars = [0x1_0001, 0x2101, 0, 0, 0];
        assert_eq!(
            IdeControllerDescriptor::validate(candidate),
            Err(IdeDiscoveryError::PortOutOfRange)
        );
    }

    #[test]
    fn location_rejects_out_of_range_requester_fields() {
        assert!(PciFunctionLocation::new(0, 255, 31, 7).is_some());
        assert!(PciFunctionLocation::new(0, 0, 32, 0).is_none());
        assert!(PciFunctionLocation::new(0, 0, 0, 8).is_none());
    }
}
