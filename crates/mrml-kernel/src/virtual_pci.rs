//! Backend-neutral PCI Type-0 configuration-state foundation.
//!
//! This module does not assign MRML a PCI identity and does not attach a PCI
//! function to a guest. It bounds the configuration mechanics needed before a
//! concrete VMM transport can do so. Configuration values are routing data;
//! native mappings, interrupts, DMA, and device authority remain separate.

pub const PCI_TYPE0_CONFIGURATION_BYTES: usize = 64;
pub const PCI_COMMAND_MEMORY_SPACE: u16 = 1 << 1;
pub const PCI_COMMAND_INTERRUPT_DISABLE: u16 = 1 << 10;
const PCI_COMMAND_SUPPORTED: u16 = PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_INTERRUPT_DISABLE;
const PCI_BAR_MEMORY_ADDRESS_MASK: u32 = 0xffff_fff0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualPciError {
    InvalidIdentity,
    InvalidBar,
    InvalidAccess,
    ReadOnly,
    UnsupportedCommand,
}

/// Externally assigned PCI identity and class data. Construction validates
/// representation only; it does not prove registration, ownership, or device
/// authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualPciIdentity {
    vendor: u16,
    device: u16,
    revision: u8,
    programming_interface: u8,
    subclass: u8,
    class: u8,
    subsystem_vendor: u16,
    subsystem: u16,
}

impl VirtualPciIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vendor: u16,
        device: u16,
        revision: u8,
        programming_interface: u8,
        subclass: u8,
        class: u8,
        subsystem_vendor: u16,
        subsystem: u16,
    ) -> Result<Self, VirtualPciError> {
        if matches!(vendor, 0 | u16::MAX) || class == u8::MAX {
            return Err(VirtualPciError::InvalidIdentity);
        }
        Ok(Self {
            vendor,
            device,
            revision,
            programming_interface,
            subclass,
            class,
            subsystem_vendor,
            subsystem,
        })
    }

    pub const fn vendor(self) -> u16 {
        self.vendor
    }

    pub const fn device(self) -> u16 {
        self.device
    }

    pub const fn class(self) -> u8 {
        self.class
    }
}

/// One 32-bit, non-prefetchable memory BAR. The address is guest-selected
/// routing data; accepting it never creates a host mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualPciMemoryBar {
    size: u32,
    address: u32,
    probing: bool,
}

impl VirtualPciMemoryBar {
    pub fn new(size: u32) -> Result<Self, VirtualPciError> {
        if size < 16 || !size.is_power_of_two() {
            return Err(VirtualPciError::InvalidBar);
        }
        Ok(Self {
            size,
            address: 0,
            probing: false,
        })
    }

    pub const fn size(self) -> u32 {
        self.size
    }

    pub const fn address(self) -> u32 {
        self.address
    }

    const fn value(self) -> u32 {
        if self.probing {
            !(self.size - 1) & PCI_BAR_MEMORY_ADDRESS_MASK
        } else {
            self.address
        }
    }

    fn write(&mut self, value: u32) -> VirtualPciWriteOutcome {
        if value == u32::MAX {
            self.probing = true;
            return VirtualPciWriteOutcome::BarProbe;
        }
        self.probing = false;
        self.address = value & !(self.size - 1) & PCI_BAR_MEMORY_ADDRESS_MASK;
        VirtualPciWriteOutcome::BarAddress(self.address)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualPciWriteOutcome {
    Command(u16),
    BarProbe,
    BarAddress(u32),
}

/// Minimal conventional Type-0 header state. It intentionally has no
/// capability list, MSI/MSI-X, bus mastering, expansion ROM, legacy interrupt
/// pin, or additional BARs.
pub struct VirtualPciType0Function {
    identity: VirtualPciIdentity,
    command: u16,
    bar0: VirtualPciMemoryBar,
}

impl VirtualPciType0Function {
    pub const fn new(identity: VirtualPciIdentity, bar0: VirtualPciMemoryBar) -> Self {
        Self {
            identity,
            command: 0,
            bar0,
        }
    }

    pub const fn identity(&self) -> VirtualPciIdentity {
        self.identity
    }

    pub const fn command(&self) -> u16 {
        self.command
    }

    pub const fn bar0(&self) -> VirtualPciMemoryBar {
        self.bar0
    }

    pub fn encode(&self, output: &mut [u8; PCI_TYPE0_CONFIGURATION_BYTES]) {
        output.fill(0);
        output[0..2].copy_from_slice(&self.identity.vendor.to_le_bytes());
        output[2..4].copy_from_slice(&self.identity.device.to_le_bytes());
        output[4..6].copy_from_slice(&self.command.to_le_bytes());
        output[8] = self.identity.revision;
        output[9] = self.identity.programming_interface;
        output[10] = self.identity.subclass;
        output[11] = self.identity.class;
        output[14] = 0;
        output[16..20].copy_from_slice(&self.bar0.value().to_le_bytes());
        output[44..46].copy_from_slice(&self.identity.subsystem_vendor.to_le_bytes());
        output[46..48].copy_from_slice(&self.identity.subsystem.to_le_bytes());
    }

    pub fn read(&self, offset: u16, size: u8) -> Result<u32, VirtualPciError> {
        let range = access_range(offset, size)?;
        let mut encoded = [0; PCI_TYPE0_CONFIGURATION_BYTES];
        self.encode(&mut encoded);
        let mut value = [0; 4];
        value[..range.len()].copy_from_slice(&encoded[range]);
        Ok(u32::from_le_bytes(value))
    }

    /// Applies one exact writable-field access transactionally. Unsupported
    /// command bits and all read-only/header-crossing writes fail without
    /// mutating command or BAR state.
    pub fn write(
        &mut self,
        offset: u16,
        size: u8,
        value: u32,
    ) -> Result<VirtualPciWriteOutcome, VirtualPciError> {
        let _ = access_range(offset, size)?;
        match (offset, size) {
            (4, 2) => {
                let command = value as u16;
                if command & !PCI_COMMAND_SUPPORTED != 0 {
                    return Err(VirtualPciError::UnsupportedCommand);
                }
                self.command = command;
                Ok(VirtualPciWriteOutcome::Command(command))
            }
            (16, 4) => Ok(self.bar0.write(value)),
            _ => Err(VirtualPciError::ReadOnly),
        }
    }
}

fn access_range(offset: u16, size: u8) -> Result<core::ops::Range<usize>, VirtualPciError> {
    if !matches!(size, 1 | 2 | 4) || !offset.is_multiple_of(u16::from(size)) {
        return Err(VirtualPciError::InvalidAccess);
    }
    let start = usize::from(offset);
    let end = start
        .checked_add(usize::from(size))
        .filter(|end| *end <= PCI_TYPE0_CONFIGURATION_BYTES)
        .ok_or(VirtualPciError::InvalidAccess)?;
    Ok(start..end)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> VirtualPciIdentity {
        VirtualPciIdentity::new(0x1234, 0x5678, 1, 2, 0x80, 1, 0x1234, 0x5679).unwrap()
    }

    #[test]
    fn identity_rejects_absent_vendor_and_reserved_class_only() {
        for vendor in [0, u16::MAX] {
            assert_eq!(
                VirtualPciIdentity::new(vendor, 1, 0, 0, 0, 1, 1, 1),
                Err(VirtualPciError::InvalidIdentity)
            );
        }
        assert_eq!(
            VirtualPciIdentity::new(1, 1, 0, 0, 0, u8::MAX, 1, 1),
            Err(VirtualPciError::InvalidIdentity)
        );
        assert!(VirtualPciIdentity::new(1, 0, 0, 0, 0, 1, 0, 0).is_ok());
    }

    #[test]
    fn type0_header_is_exact_and_zero_fills_unimplemented_fields() {
        let function =
            VirtualPciType0Function::new(identity(), VirtualPciMemoryBar::new(4096).unwrap());
        let mut encoded = [0xa5; PCI_TYPE0_CONFIGURATION_BYTES];
        function.encode(&mut encoded);
        assert_eq!(&encoded[0..4], &[0x34, 0x12, 0x78, 0x56]);
        assert_eq!(&encoded[8..12], &[1, 2, 0x80, 1]);
        assert_eq!(encoded[14], 0);
        assert_eq!(&encoded[16..20], &[0; 4]);
        assert_eq!(&encoded[44..48], &[0x34, 0x12, 0x79, 0x56]);
        for range in [6..8, 12..14, 15..16, 20..44, 48..64] {
            assert!(encoded[range].iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn bar_probe_reports_exact_mask_without_becoming_an_address() {
        let mut function =
            VirtualPciType0Function::new(identity(), VirtualPciMemoryBar::new(4096).unwrap());
        assert_eq!(
            function.write(16, 4, u32::MAX),
            Ok(VirtualPciWriteOutcome::BarProbe)
        );
        assert_eq!(function.read(16, 4), Ok(0xffff_f000));
        assert_eq!(function.bar0().address(), 0);
        assert_eq!(
            function.write(16, 4, 0x1234_5fff),
            Ok(VirtualPciWriteOutcome::BarAddress(0x1234_5000))
        );
        assert_eq!(function.read(16, 4), Ok(0x1234_5000));
    }

    #[test]
    fn command_denies_bus_mastering_and_is_transactional() {
        let mut function =
            VirtualPciType0Function::new(identity(), VirtualPciMemoryBar::new(4096).unwrap());
        assert_eq!(
            function.write(
                4,
                2,
                u32::from(PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_INTERRUPT_DISABLE)
            ),
            Ok(VirtualPciWriteOutcome::Command(
                PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_INTERRUPT_DISABLE
            ))
        );
        assert_eq!(
            function.write(4, 2, 1 << 2),
            Err(VirtualPciError::UnsupportedCommand)
        );
        assert_eq!(
            function.command(),
            PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_INTERRUPT_DISABLE
        );
    }

    #[test]
    fn malformed_and_read_only_writes_preserve_all_state() {
        let mut function =
            VirtualPciType0Function::new(identity(), VirtualPciMemoryBar::new(4096).unwrap());
        assert_eq!(
            function.write(17, 4, 0),
            Err(VirtualPciError::InvalidAccess)
        );
        assert_eq!(function.write(0, 4, 0), Err(VirtualPciError::ReadOnly));
        assert_eq!(function.write(16, 2, 0), Err(VirtualPciError::ReadOnly));
        assert_eq!(function.command(), 0);
        assert_eq!(function.bar0().address(), 0);
        assert_eq!(function.read(63, 2), Err(VirtualPciError::InvalidAccess));
    }

    #[test]
    fn bar_geometry_is_bounded() {
        for size in [0, 8, 24] {
            assert_eq!(
                VirtualPciMemoryBar::new(size),
                Err(VirtualPciError::InvalidBar)
            );
        }
        assert_eq!(VirtualPciMemoryBar::new(16).unwrap().size(), 16);
        assert_eq!(VirtualPciMemoryBar::new(1 << 31).unwrap().size(), 1 << 31);
    }
}
