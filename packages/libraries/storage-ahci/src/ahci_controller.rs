//! Bounded initialization of one capability-mapped conventional AHCI HBA.
//!
//! This layer touches only the global host registers. It enables AHCI mode,
//! requests the standard HBA reset, waits for bounded completion, and validates
//! the immutable capability/version/implemented-port snapshot before
//! publication. Port engines, DMA, commands, interrupts, ATA/ATAPI, and NCQ are
//! later layers.

use crate::{AhciAbarMapping, AHCI_ABAR_MINIMUM_BYTES};

pub const AHCI_CAP_OFFSET: u32 = 0x00;
pub const AHCI_GHC_OFFSET: u32 = 0x04;
pub const AHCI_PI_OFFSET: u32 = 0x0c;
pub const AHCI_VERSION_OFFSET: u32 = 0x10;
pub const AHCI_RESET_POLL_LIMIT: u32 = 1_000_000;

pub(crate) const GHC_HBA_RESET: u32 = 1 << 0;
pub(crate) const GHC_INTERRUPT_ENABLE: u32 = 1 << 1;
pub(crate) const GHC_AHCI_ENABLE: u32 = 1 << 31;
const CAP_PORT_COUNT_MASK: u32 = 0x1f;
const CAP_COMMAND_SLOT_COUNT_MASK: u32 = 0x1f << 8;
const CAP_COMMAND_SLOT_COUNT_SHIFT: u32 = 8;
const CAP_NATIVE_COMMAND_QUEUING: u32 = 1 << 30;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AhciControllerSnapshot {
    pub device_object: mrml_kernel::ObjectId,
    pub configuration_generation: u64,
    pub mapping_generation: u64,
    pub version: u32,
    pub capabilities: u32,
    pub implemented_ports: u32,
    pub port_count: u8,
    pub command_slot_count: u8,
    pub native_command_queuing: bool,
}

impl AhciControllerSnapshot {
    pub(crate) fn matches_mapping(self, mapping: AhciAbarMapping) -> bool {
        self.device_object == mapping.device_object
            && self.configuration_generation == mapping.configuration_generation
            && self.mapping_generation == mapping.mapping_generation
    }

    pub(crate) fn is_structurally_valid(self) -> bool {
        self.configuration_generation != 0
            && self.mapping_generation != 0
            && self.matches_registers(self.capabilities, self.version, self.implemented_ports)
    }

    pub(crate) fn matches_registers(
        self,
        capabilities: u32,
        version: u32,
        implemented_ports: u32,
    ) -> bool {
        if version == 0 || version == u32::MAX || implemented_ports == 0 {
            return false;
        }
        let port_count = ((capabilities & CAP_PORT_COUNT_MASK) + 1) as u8;
        let valid_port_mask = if port_count == 32 {
            u32::MAX
        } else {
            (1_u32 << port_count) - 1
        };
        let command_slot_count = (((capabilities & CAP_COMMAND_SLOT_COUNT_MASK)
            >> CAP_COMMAND_SLOT_COUNT_SHIFT)
            + 1) as u8;
        self.capabilities == capabilities
            && self.version == version
            && self.implemented_ports == implemented_ports
            && self.port_count == port_count
            && implemented_ports & !valid_port_mask == 0
            && self.command_slot_count == command_slot_count
            && self.native_command_queuing == (capabilities & CAP_NATIVE_COMMAND_QUEUING != 0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciControllerError {
    InvalidMapping,
    RegisterRead,
    RegisterWrite,
    ResetTimeout,
    AhciModeUnavailable,
    InvalidVersion,
    NoImplementedPorts,
    ImplementedPortOutsideCapability,
}

/// Register access to the exact mapped ABAR retained by the caller.
///
/// Implementations must use volatile 32-bit accesses, reject offsets outside
/// the mapping, and preserve the mapping's generation-bound revocation.
pub trait AhciRegisterIo {
    fn read_u32(&mut self, offset: u32) -> Result<u32, ()>;
    fn write_u32(&mut self, offset: u32, value: u32) -> Result<(), ()>;
}

/// Volatile access to one already-authorized supervisor ABAR mapping.
///
/// # Safety
///
/// The creator must keep the exact mapping live and exclusively assigned to
/// this driver for the complete value lifetime. Revocation must stop all users
/// before unmapping the range. Construction does not itself grant authority.
pub struct NativeAhciRegisterIo {
    base: *mut u8,
    bytes: usize,
}

impl NativeAhciRegisterIo {
    pub unsafe fn new(mapping: AhciAbarMapping) -> Option<Self> {
        let base = usize::try_from(mapping.virtual_base).ok()?;
        let bytes = usize::try_from(mapping.bytes).ok()?;
        if base == 0
            || base % core::mem::align_of::<u32>() != 0
            || bytes < AHCI_ABAR_MINIMUM_BYTES as usize
            || base.checked_add(bytes).is_none()
        {
            return None;
        }
        Some(Self {
            base: base as *mut u8,
            bytes,
        })
    }

    fn register(&self, offset: u32) -> Option<*mut u32> {
        let offset = usize::try_from(offset).ok()?;
        if offset % core::mem::align_of::<u32>() != 0
            || offset.checked_add(core::mem::size_of::<u32>())? > self.bytes
        {
            return None;
        }
        // Pointer arithmetic stays inside the exact validated mapping.
        Some(unsafe { self.base.add(offset).cast::<u32>() })
    }
}

impl AhciRegisterIo for NativeAhciRegisterIo {
    fn read_u32(&mut self, offset: u32) -> Result<u32, ()> {
        let register = self.register(offset).ok_or(())?;
        // SAFETY: construction and `register` establish the mapped aligned
        // range; the owner retains its exclusive generation for this lifetime.
        Ok(unsafe { register.read_volatile() })
    }

    fn write_u32(&mut self, offset: u32, value: u32) -> Result<(), ()> {
        let register = self.register(offset).ok_or(())?;
        // SAFETY: same mapping and lifetime requirements as `read_u32`.
        unsafe { register.write_volatile(value) };
        Ok(())
    }
}

pub fn reset_ahci_controller<R: AhciRegisterIo>(
    mapping: AhciAbarMapping,
    registers: &mut R,
) -> Result<AhciControllerSnapshot, AhciControllerError> {
    if mapping.configuration_generation == 0
        || mapping.mapping_generation == 0
        || mapping.virtual_base == 0
        || mapping.bytes < AHCI_ABAR_MINIMUM_BYTES
        || mapping.virtual_base.checked_add(mapping.bytes).is_none()
    {
        return Err(AhciControllerError::InvalidMapping);
    }

    let initial_ghc = registers
        .read_u32(AHCI_GHC_OFFSET)
        .map_err(|_| AhciControllerError::RegisterRead)?;
    let reset = (initial_ghc | GHC_AHCI_ENABLE | GHC_HBA_RESET) & !GHC_INTERRUPT_ENABLE;
    registers
        .write_u32(AHCI_GHC_OFFSET, reset)
        .map_err(|_| AhciControllerError::RegisterWrite)?;

    let mut completed_ghc = None;
    for _ in 0..AHCI_RESET_POLL_LIMIT {
        let ghc = registers
            .read_u32(AHCI_GHC_OFFSET)
            .map_err(|_| AhciControllerError::RegisterRead)?;
        if ghc & GHC_HBA_RESET == 0 {
            completed_ghc = Some(ghc);
            break;
        }
    }
    let completed_ghc = completed_ghc.ok_or(AhciControllerError::ResetTimeout)?;
    let enabled_ghc = (completed_ghc | GHC_AHCI_ENABLE) & !GHC_INTERRUPT_ENABLE;
    registers
        .write_u32(AHCI_GHC_OFFSET, enabled_ghc)
        .map_err(|_| AhciControllerError::RegisterWrite)?;
    let verified_ghc = registers
        .read_u32(AHCI_GHC_OFFSET)
        .map_err(|_| AhciControllerError::RegisterRead)?;
    if verified_ghc & GHC_AHCI_ENABLE == 0 || verified_ghc & GHC_INTERRUPT_ENABLE != 0 {
        return Err(AhciControllerError::AhciModeUnavailable);
    }

    let capabilities = registers
        .read_u32(AHCI_CAP_OFFSET)
        .map_err(|_| AhciControllerError::RegisterRead)?;
    let version = registers
        .read_u32(AHCI_VERSION_OFFSET)
        .map_err(|_| AhciControllerError::RegisterRead)?;
    let implemented_ports = registers
        .read_u32(AHCI_PI_OFFSET)
        .map_err(|_| AhciControllerError::RegisterRead)?;
    if version == 0 || version == u32::MAX {
        return Err(AhciControllerError::InvalidVersion);
    }
    if implemented_ports == 0 {
        return Err(AhciControllerError::NoImplementedPorts);
    }

    let port_count = ((capabilities & CAP_PORT_COUNT_MASK) + 1) as u8;
    let valid_port_mask = if port_count == 32 {
        u32::MAX
    } else {
        (1_u32 << port_count) - 1
    };
    if implemented_ports & !valid_port_mask != 0 {
        return Err(AhciControllerError::ImplementedPortOutsideCapability);
    }
    let command_slot_count =
        (((capabilities & CAP_COMMAND_SLOT_COUNT_MASK) >> CAP_COMMAND_SLOT_COUNT_SHIFT) + 1) as u8;

    Ok(AhciControllerSnapshot {
        device_object: mapping.device_object,
        configuration_generation: mapping.configuration_generation,
        mapping_generation: mapping.mapping_generation,
        version,
        capabilities,
        implemented_ports,
        port_count,
        command_slot_count,
        native_command_queuing: capabilities & CAP_NATIVE_COMMAND_QUEUING != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_kernel::ObjectId;

    struct Registers {
        capabilities: u32,
        version: u32,
        implemented_ports: u32,
        ghc: u32,
        reset_reads_remaining: u32,
        reject_read: Option<u32>,
        reject_write: bool,
        drop_ahci_enable_after_reset: bool,
        writes: [Option<(u32, u32)>; 2],
        write_count: usize,
    }

    impl Registers {
        fn valid() -> Self {
            Self {
                capabilities: 3 | (31 << 8) | CAP_NATIVE_COMMAND_QUEUING,
                version: 0x0001_0301,
                implemented_ports: 0b1011,
                ghc: GHC_INTERRUPT_ENABLE,
                reset_reads_remaining: 2,
                reject_read: None,
                reject_write: false,
                drop_ahci_enable_after_reset: false,
                writes: [None; 2],
                write_count: 0,
            }
        }
    }

    impl AhciRegisterIo for Registers {
        fn read_u32(&mut self, offset: u32) -> Result<u32, ()> {
            if self.reject_read == Some(offset) {
                return Err(());
            }
            match offset {
                AHCI_CAP_OFFSET => Ok(self.capabilities),
                AHCI_GHC_OFFSET => {
                    if self.ghc & GHC_HBA_RESET != 0 && self.reset_reads_remaining > 0 {
                        self.reset_reads_remaining -= 1;
                        if self.reset_reads_remaining == 0 {
                            self.ghc &= !GHC_HBA_RESET;
                        }
                    }
                    if self.drop_ahci_enable_after_reset && self.write_count == 2 {
                        Ok(self.ghc & !GHC_AHCI_ENABLE)
                    } else {
                        Ok(self.ghc)
                    }
                }
                AHCI_PI_OFFSET => Ok(self.implemented_ports),
                AHCI_VERSION_OFFSET => Ok(self.version),
                _ => Err(()),
            }
        }

        fn write_u32(&mut self, offset: u32, value: u32) -> Result<(), ()> {
            if self.reject_write || offset != AHCI_GHC_OFFSET || self.write_count >= 2 {
                return Err(());
            }
            self.writes[self.write_count] = Some((offset, value));
            self.write_count += 1;
            self.ghc = value;
            Ok(())
        }
    }

    fn mapping() -> AhciAbarMapping {
        AhciAbarMapping {
            device_object: ObjectId(41),
            configuration_generation: 7,
            mapping_generation: 9,
            physical_base: 0xf7f0_0000,
            virtual_base: 0xffff_9000_0000_0000,
            bytes: 0x2000,
        }
    }

    #[test]
    fn resets_with_interrupts_disabled_and_publishes_bounded_capabilities() {
        let mut registers = Registers::valid();
        let snapshot = reset_ahci_controller(mapping(), &mut registers).unwrap();
        assert_eq!(snapshot.device_object, ObjectId(41));
        assert_eq!(snapshot.port_count, 4);
        assert_eq!(snapshot.command_slot_count, 32);
        assert_eq!(snapshot.implemented_ports, 0b1011);
        assert!(snapshot.native_command_queuing);
        assert_eq!(registers.write_count, 2);
        assert_eq!(
            registers.writes[0].unwrap().1 & GHC_HBA_RESET,
            GHC_HBA_RESET
        );
        assert_eq!(registers.writes[0].unwrap().1 & GHC_INTERRUPT_ENABLE, 0);
        assert_eq!(
            registers.writes[1].unwrap().1 & GHC_AHCI_ENABLE,
            GHC_AHCI_ENABLE
        );
        assert_eq!(registers.writes[1].unwrap().1 & GHC_INTERRUPT_ENABLE, 0);
    }

    #[test]
    fn rejects_mapping_register_and_reset_failures_without_snapshot() {
        let mut invalid = mapping();
        invalid.mapping_generation = 0;
        assert_eq!(
            reset_ahci_controller(invalid, &mut Registers::valid()),
            Err(AhciControllerError::InvalidMapping)
        );

        let mut read_failure = Registers::valid();
        read_failure.reject_read = Some(AHCI_GHC_OFFSET);
        assert_eq!(
            reset_ahci_controller(mapping(), &mut read_failure),
            Err(AhciControllerError::RegisterRead)
        );

        let mut write_failure = Registers::valid();
        write_failure.reject_write = true;
        assert_eq!(
            reset_ahci_controller(mapping(), &mut write_failure),
            Err(AhciControllerError::RegisterWrite)
        );

        let mut timeout = Registers::valid();
        timeout.reset_reads_remaining = AHCI_RESET_POLL_LIMIT + 1;
        assert_eq!(
            reset_ahci_controller(mapping(), &mut timeout),
            Err(AhciControllerError::ResetTimeout)
        );
    }

    #[test]
    fn rejects_unusable_post_reset_controller_state() {
        let mut unavailable = Registers::valid();
        unavailable.drop_ahci_enable_after_reset = true;
        assert_eq!(
            reset_ahci_controller(mapping(), &mut unavailable),
            Err(AhciControllerError::AhciModeUnavailable)
        );

        let mut invalid_version = Registers::valid();
        invalid_version.version = 0;
        assert_eq!(
            reset_ahci_controller(mapping(), &mut invalid_version),
            Err(AhciControllerError::InvalidVersion)
        );

        let mut no_ports = Registers::valid();
        no_ports.implemented_ports = 0;
        assert_eq!(
            reset_ahci_controller(mapping(), &mut no_ports),
            Err(AhciControllerError::NoImplementedPorts)
        );

        let mut excess_port = Registers::valid();
        excess_port.capabilities = 1;
        excess_port.implemented_ports = 0b100;
        assert_eq!(
            reset_ahci_controller(mapping(), &mut excess_port),
            Err(AhciControllerError::ImplementedPortOutsideCapability)
        );
    }

    #[test]
    fn native_register_window_rejects_invalid_mapping_without_access() {
        let mut invalid = mapping();
        invalid.virtual_base = 0;
        assert!(unsafe { NativeAhciRegisterIo::new(invalid) }.is_none());

        invalid = mapping();
        invalid.virtual_base += 1;
        assert!(unsafe { NativeAhciRegisterIo::new(invalid) }.is_none());

        invalid = mapping();
        invalid.bytes = 0x1000;
        assert!(unsafe { NativeAhciRegisterIo::new(invalid) }.is_none());
    }
}
