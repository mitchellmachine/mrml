//! Read-only discovery of bounded conventional AHCI port state.
//!
//! This layer consumes one exact generation-bound controller snapshot and its
//! retained ABAR mapping. It samples only implemented ports, requires the HBA
//! and every observed port to remain quiescent, and publishes descriptive link
//! and signature state only when complete observations agree. It performs no
//! MMIO writes, DMA, command submission, interrupt handling, ATA/ATAPI
//! protocol, NCQ operation, or block I/O.

use crate::ahci_controller::{
    AhciControllerSnapshot, AhciRegisterIo, AHCI_CAP_OFFSET, AHCI_GHC_OFFSET, AHCI_PI_OFFSET,
    AHCI_VERSION_OFFSET, GHC_AHCI_ENABLE, GHC_HBA_RESET, GHC_INTERRUPT_ENABLE,
};
use crate::ahci_discovery::AHCI_ABAR_MINIMUM_BYTES;
use crate::ahci_mapping::{AhciAbarMapping, AHCI_MMIO_PAGE_BYTES};
use mrml_kernel::ObjectId;

pub const AHCI_MAX_PORTS: usize = 32;
pub const AHCI_PORT_BASE_OFFSET: u32 = 0x100;
pub const AHCI_PORT_STRIDE_BYTES: u32 = 0x80;
pub const AHCI_PORT_INTERRUPT_ENABLE_OFFSET: u32 = 0x14;
pub const AHCI_PORT_COMMAND_OFFSET: u32 = 0x18;
pub const AHCI_PORT_SIGNATURE_OFFSET: u32 = 0x24;
pub const AHCI_PORT_SATA_STATUS_OFFSET: u32 = 0x28;
pub const AHCI_PORT_SATA_ACTIVE_OFFSET: u32 = 0x34;
pub const AHCI_PORT_COMMAND_ISSUE_OFFSET: u32 = 0x38;

pub const AHCI_SATA_SIGNATURE: u32 = 0x0000_0101;
pub const AHCI_ATAPI_SIGNATURE: u32 = 0xeb14_0101;
pub const AHCI_ENCLOSURE_MANAGEMENT_SIGNATURE: u32 = 0xc33c_0101;
pub const AHCI_PORT_MULTIPLIER_SIGNATURE: u32 = 0x9669_0101;

const AHCI_PORT_REGISTER_BYTES: u64 = core::mem::size_of::<u32>() as u64;
const AHCI_PORT_REGISTER_LIMIT: u32 = AHCI_PORT_STRIDE_BYTES - core::mem::size_of::<u32>() as u32;
const PORT_COMMAND_START: u32 = 1 << 0;
const PORT_COMMAND_LIST_OVERRIDE: u32 = 1 << 3;
const PORT_FIS_RECEIVE_ENABLE: u32 = 1 << 4;
const PORT_FIS_RECEIVE_RUNNING: u32 = 1 << 14;
const PORT_COMMAND_LIST_RUNNING: u32 = 1 << 15;
const PORT_TRANSIENT_COMMAND_MASK: u32 = PORT_COMMAND_START
    | PORT_COMMAND_LIST_OVERRIDE
    | PORT_FIS_RECEIVE_ENABLE
    | PORT_FIS_RECEIVE_RUNNING
    | PORT_COMMAND_LIST_RUNNING;
const SATA_STATUS_DETECTION_MASK: u32 = 0x0f;
const SATA_STATUS_SPEED_MASK: u32 = 0x0f << 4;
const SATA_STATUS_SPEED_SHIFT: u32 = 4;
const SATA_STATUS_POWER_MASK: u32 = 0x0f << 8;
const SATA_STATUS_POWER_SHIFT: u32 = 8;
const SATA_STATUS_DEFINED_MASK: u32 =
    SATA_STATUS_DETECTION_MASK | SATA_STATUS_SPEED_MASK | SATA_STATUS_POWER_MASK;
const RELEVANT_GLOBAL_HOST_CONTROL_MASK: u32 =
    GHC_AHCI_ENABLE | GHC_HBA_RESET | GHC_INTERRUPT_ENABLE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciPortPowerState {
    Active,
    Partial,
    Slumber,
    DeviceSleep,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciPortLinkSpeed {
    Generation1,
    Generation2,
    Generation3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciPortLinkState {
    NoDevice,
    PresentWithoutCommunication,
    Established(AhciPortPowerState),
    Offline,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciPortDeviceKind {
    Sata,
    Atapi,
    EnclosureManagement,
    PortMultiplier,
    Unknown,
}

/// Descriptive state for one implemented AHCI port.
///
/// The object and generation fields bind this observation to the exact mapped
/// controller state. They identify the observation but grant no authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AhciPortSnapshot {
    pub device_object: ObjectId,
    pub configuration_generation: u64,
    pub mapping_generation: u64,
    pub port: u8,
    pub sata_status: u32,
    pub link_state: AhciPortLinkState,
    pub link_speed: Option<AhciPortLinkSpeed>,
    pub device_kind: Option<AhciPortDeviceKind>,
    pub signature: Option<u32>,
}

impl AhciPortSnapshot {
    pub const fn has_device(&self) -> bool {
        self.device_kind.is_some()
    }

    pub const fn is_installed_recovery_candidate(&self) -> bool {
        matches!(self.link_state, AhciPortLinkState::Established(_))
            && matches!(self.device_kind, Some(AhciPortDeviceKind::Sata))
    }
}

/// Atomic fixed-capacity result for all implemented ports in one controller
/// generation. No partial result is returned when any port is uncertain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AhciPortSnapshotSet {
    controller: AhciControllerSnapshot,
    ports: [Option<AhciPortSnapshot>; AHCI_MAX_PORTS],
    count: u8,
}

impl AhciPortSnapshotSet {
    pub const fn controller(&self) -> AhciControllerSnapshot {
        self.controller
    }

    pub const fn len(&self) -> usize {
        self.count as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn device_count(&self) -> usize {
        let mut count = 0;
        for snapshot in self.ports.iter().flatten() {
            if snapshot.has_device() {
                count += 1;
            }
        }
        count
    }

    pub fn installed_recovery_candidate_count(&self) -> usize {
        let mut count = 0;
        for snapshot in self.ports.iter().flatten() {
            if snapshot.is_installed_recovery_candidate() {
                count += 1;
            }
        }
        count
    }

    pub fn port(&self, port: u8) -> Option<AhciPortSnapshot> {
        self.ports.get(usize::from(port)).copied().flatten()
    }

    pub const fn ports(&self) -> &[Option<AhciPortSnapshot>; AHCI_MAX_PORTS] {
        &self.ports
    }

    pub const fn into_ports(self) -> [Option<AhciPortSnapshot>; AHCI_MAX_PORTS] {
        self.ports
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciPortError {
    RegisterOutsideMapping,
    RegisterRead,
    StateChanged,
    InterruptsEnabled,
    EngineActive,
    CommandsActive,
    InvalidLinkState(u32),
    SignatureUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciPortDiscoveryError {
    InvalidMapping,
    ControllerSnapshotMismatch,
    ControllerRegisterRead,
    ControllerUnavailable,
    ControllerChanged,
    Port { port: u8, error: AhciPortError },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ControllerObservation {
    capabilities: u32,
    global_host_control: u32,
    implemented_ports: u32,
    version: u32,
}

impl ControllerObservation {
    const fn available(self) -> bool {
        self.global_host_control == GHC_AHCI_ENABLE
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PortObservation {
    interrupt_enable: u32,
    command: u32,
    signature: u32,
    sata_status: u32,
    sata_active: u32,
    command_issue: u32,
}

/// Discovers all ports named by one validated controller snapshot.
///
/// The operation is read-only and atomic: any stale generation, controller
/// change, register uncertainty, non-quiescent port, malformed link state, or
/// unavailable attached-device signature returns an error without a snapshot
/// set. An otherwise stable unrecognized signature remains descriptive
/// `Unknown` state and is never an installed-recovery candidate.
pub fn discover_ahci_ports<R: AhciRegisterIo>(
    mapping: AhciAbarMapping,
    controller: AhciControllerSnapshot,
    registers: &mut R,
) -> Result<AhciPortSnapshotSet, AhciPortDiscoveryError> {
    if !valid_mapping(mapping) {
        return Err(AhciPortDiscoveryError::InvalidMapping);
    }
    if !controller.matches_mapping(mapping) || !controller.is_structurally_valid() {
        return Err(AhciPortDiscoveryError::ControllerSnapshotMismatch);
    }

    let before = read_stable_controller_observation(registers)?;
    if !before.available() {
        return Err(AhciPortDiscoveryError::ControllerUnavailable);
    }
    if !controller.matches_registers(
        before.capabilities,
        before.version,
        before.implemented_ports,
    ) {
        return Err(AhciPortDiscoveryError::ControllerSnapshotMismatch);
    }

    let first = read_all_port_observations(mapping, controller, registers)?;
    let second = read_all_port_observations(mapping, controller, registers)?;
    let mut ports = [None; AHCI_MAX_PORTS];
    let mut count = 0_u8;
    for port in 0_u8..controller.port_count {
        let port_mask = 1_u32 << u32::from(port);
        if controller.implemented_ports & port_mask == 0 {
            continue;
        }
        let first =
            first[usize::from(port)].ok_or(AhciPortDiscoveryError::ControllerSnapshotMismatch)?;
        let second =
            second[usize::from(port)].ok_or(AhciPortDiscoveryError::ControllerSnapshotMismatch)?;
        let snapshot = validate_port_observation(controller, port, first, second)
            .map_err(|error| AhciPortDiscoveryError::Port { port, error })?;
        ports[usize::from(port)] = Some(snapshot);
        count = count
            .checked_add(1)
            .ok_or(AhciPortDiscoveryError::ControllerSnapshotMismatch)?;
    }

    let after = read_stable_controller_observation(registers)?;
    if after != before
        || !after.available()
        || !controller.matches_registers(after.capabilities, after.version, after.implemented_ports)
    {
        return Err(AhciPortDiscoveryError::ControllerChanged);
    }

    Ok(AhciPortSnapshotSet {
        controller,
        ports,
        count,
    })
}

fn valid_mapping(mapping: AhciAbarMapping) -> bool {
    mapping.configuration_generation != 0
        && mapping.mapping_generation != 0
        && mapping.physical_base != 0
        && mapping.physical_base % AHCI_MMIO_PAGE_BYTES == 0
        && mapping.virtual_base != 0
        && mapping.virtual_base % AHCI_MMIO_PAGE_BYTES == 0
        && mapping.bytes >= AHCI_ABAR_MINIMUM_BYTES
        && mapping.bytes.is_power_of_two()
        && mapping.bytes % AHCI_MMIO_PAGE_BYTES == 0
        && mapping.physical_base & (mapping.bytes - 1) == 0
        && mapping.physical_base.checked_add(mapping.bytes).is_some()
        && mapping.virtual_base.checked_add(mapping.bytes).is_some()
}

fn read_stable_controller_observation<R: AhciRegisterIo>(
    registers: &mut R,
) -> Result<ControllerObservation, AhciPortDiscoveryError> {
    let first = read_controller_observation(registers)?;
    let second = read_controller_observation(registers)?;
    if first != second {
        return Err(AhciPortDiscoveryError::ControllerChanged);
    }
    Ok(first)
}

fn read_controller_observation<R: AhciRegisterIo>(
    registers: &mut R,
) -> Result<ControllerObservation, AhciPortDiscoveryError> {
    Ok(ControllerObservation {
        capabilities: registers
            .read_u32(AHCI_CAP_OFFSET)
            .map_err(|_| AhciPortDiscoveryError::ControllerRegisterRead)?,
        global_host_control: registers
            .read_u32(AHCI_GHC_OFFSET)
            .map_err(|_| AhciPortDiscoveryError::ControllerRegisterRead)?
            & RELEVANT_GLOBAL_HOST_CONTROL_MASK,
        implemented_ports: registers
            .read_u32(AHCI_PI_OFFSET)
            .map_err(|_| AhciPortDiscoveryError::ControllerRegisterRead)?,
        version: registers
            .read_u32(AHCI_VERSION_OFFSET)
            .map_err(|_| AhciPortDiscoveryError::ControllerRegisterRead)?,
    })
}

fn read_all_port_observations<R: AhciRegisterIo>(
    mapping: AhciAbarMapping,
    controller: AhciControllerSnapshot,
    registers: &mut R,
) -> Result<[Option<PortObservation>; AHCI_MAX_PORTS], AhciPortDiscoveryError> {
    let mut observations = [None; AHCI_MAX_PORTS];
    for port in 0_u8..controller.port_count {
        let port_mask = 1_u32 << u32::from(port);
        if controller.implemented_ports & port_mask == 0 {
            continue;
        }
        observations[usize::from(port)] = Some(
            read_port_observation(mapping, port, registers)
                .map_err(|error| AhciPortDiscoveryError::Port { port, error })?,
        );
    }
    Ok(observations)
}

fn read_port_observation<R: AhciRegisterIo>(
    mapping: AhciAbarMapping,
    port: u8,
    registers: &mut R,
) -> Result<PortObservation, AhciPortError> {
    Ok(PortObservation {
        interrupt_enable: read_port_register(
            mapping,
            port,
            AHCI_PORT_INTERRUPT_ENABLE_OFFSET,
            registers,
        )?,
        command: read_port_register(mapping, port, AHCI_PORT_COMMAND_OFFSET, registers)?,
        signature: read_port_register(mapping, port, AHCI_PORT_SIGNATURE_OFFSET, registers)?,
        sata_status: read_port_register(mapping, port, AHCI_PORT_SATA_STATUS_OFFSET, registers)?,
        sata_active: read_port_register(mapping, port, AHCI_PORT_SATA_ACTIVE_OFFSET, registers)?,
        command_issue: read_port_register(
            mapping,
            port,
            AHCI_PORT_COMMAND_ISSUE_OFFSET,
            registers,
        )?,
    })
}

fn read_port_register<R: AhciRegisterIo>(
    mapping: AhciAbarMapping,
    port: u8,
    register: u32,
    registers: &mut R,
) -> Result<u32, AhciPortError> {
    let offset = port_register_offset(mapping, port, register)?;
    registers
        .read_u32(offset)
        .map_err(|_| AhciPortError::RegisterRead)
}

fn port_register_offset(
    mapping: AhciAbarMapping,
    port: u8,
    register: u32,
) -> Result<u32, AhciPortError> {
    if usize::from(port) >= AHCI_MAX_PORTS
        || register % core::mem::align_of::<u32>() as u32 != 0
        || register > AHCI_PORT_REGISTER_LIMIT
    {
        return Err(AhciPortError::RegisterOutsideMapping);
    }
    let offset = u32::from(port)
        .checked_mul(AHCI_PORT_STRIDE_BYTES)
        .and_then(|value| AHCI_PORT_BASE_OFFSET.checked_add(value))
        .and_then(|value| value.checked_add(register))
        .ok_or(AhciPortError::RegisterOutsideMapping)?;
    let end = u64::from(offset)
        .checked_add(AHCI_PORT_REGISTER_BYTES)
        .ok_or(AhciPortError::RegisterOutsideMapping)?;
    if end > mapping.bytes {
        return Err(AhciPortError::RegisterOutsideMapping);
    }
    Ok(offset)
}

fn validate_port_observation(
    controller: AhciControllerSnapshot,
    port: u8,
    first: PortObservation,
    second: PortObservation,
) -> Result<AhciPortSnapshot, AhciPortError> {
    if first != second {
        return Err(AhciPortError::StateChanged);
    }
    if first.interrupt_enable != 0 {
        return Err(AhciPortError::InterruptsEnabled);
    }
    if first.command & PORT_TRANSIENT_COMMAND_MASK != 0 {
        return Err(AhciPortError::EngineActive);
    }
    if first.sata_active != 0 || first.command_issue != 0 {
        return Err(AhciPortError::CommandsActive);
    }

    let (link_state, link_speed, device_kind, signature) =
        classify_link_and_signature(first.sata_status, first.signature)?;
    Ok(AhciPortSnapshot {
        device_object: controller.device_object,
        configuration_generation: controller.configuration_generation,
        mapping_generation: controller.mapping_generation,
        port,
        sata_status: first.sata_status,
        link_state,
        link_speed,
        device_kind,
        signature,
    })
}

fn classify_link_and_signature(
    sata_status: u32,
    signature: u32,
) -> Result<
    (
        AhciPortLinkState,
        Option<AhciPortLinkSpeed>,
        Option<AhciPortDeviceKind>,
        Option<u32>,
    ),
    AhciPortError,
> {
    if sata_status & !SATA_STATUS_DEFINED_MASK != 0 {
        return Err(AhciPortError::InvalidLinkState(sata_status));
    }
    let detection = sata_status & SATA_STATUS_DETECTION_MASK;
    let speed = (sata_status & SATA_STATUS_SPEED_MASK) >> SATA_STATUS_SPEED_SHIFT;
    let power = (sata_status & SATA_STATUS_POWER_MASK) >> SATA_STATUS_POWER_SHIFT;
    match detection {
        0 if speed == 0 && power == 0 => Ok((AhciPortLinkState::NoDevice, None, None, None)),
        1 if speed == 0 && power == 0 => Ok((
            AhciPortLinkState::PresentWithoutCommunication,
            None,
            None,
            None,
        )),
        3 => {
            let link_speed = match speed {
                1 => AhciPortLinkSpeed::Generation1,
                2 => AhciPortLinkSpeed::Generation2,
                3 => AhciPortLinkSpeed::Generation3,
                _ => return Err(AhciPortError::InvalidLinkState(sata_status)),
            };
            let power_state = match power {
                1 => AhciPortPowerState::Active,
                2 => AhciPortPowerState::Partial,
                6 => AhciPortPowerState::Slumber,
                8 => AhciPortPowerState::DeviceSleep,
                _ => return Err(AhciPortError::InvalidLinkState(sata_status)),
            };
            // HBA reset leaves FIS receive disabled, but AHCI requires the
            // initial device-to-host signature FIS to update PxSIG anyway.
            if signature == u32::MAX {
                return Err(AhciPortError::SignatureUnavailable);
            }
            let device_kind = match signature {
                AHCI_SATA_SIGNATURE => AhciPortDeviceKind::Sata,
                AHCI_ATAPI_SIGNATURE => AhciPortDeviceKind::Atapi,
                AHCI_ENCLOSURE_MANAGEMENT_SIGNATURE => AhciPortDeviceKind::EnclosureManagement,
                AHCI_PORT_MULTIPLIER_SIGNATURE => AhciPortDeviceKind::PortMultiplier,
                _ => AhciPortDeviceKind::Unknown,
            };
            Ok((
                AhciPortLinkState::Established(power_state),
                Some(link_speed),
                Some(device_kind),
                Some(signature),
            ))
        }
        4 if speed == 0 && power == 0 => Ok((AhciPortLinkState::Offline, None, None, None)),
        _ => Err(AhciPortError::InvalidLinkState(sata_status)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACTIVE_LINK: u32 = 3 | (3 << SATA_STATUS_SPEED_SHIFT) | (1 << SATA_STATUS_POWER_SHIFT);
    const PORT_OBSERVATION_READS: u8 = 6;

    #[derive(Clone, Copy)]
    struct PortRegisters {
        interrupt_enable: u32,
        command: u32,
        signature: u32,
        sata_status: u32,
        sata_active: u32,
        command_issue: u32,
    }

    impl PortRegisters {
        const fn sata() -> Self {
            Self {
                interrupt_enable: 0,
                command: 0,
                signature: AHCI_SATA_SIGNATURE,
                sata_status: ACTIVE_LINK,
                sata_active: 0,
                command_issue: 0,
            }
        }

        fn read(self, register: u32) -> Result<u32, ()> {
            match register {
                AHCI_PORT_INTERRUPT_ENABLE_OFFSET => Ok(self.interrupt_enable),
                AHCI_PORT_COMMAND_OFFSET => Ok(self.command),
                AHCI_PORT_SIGNATURE_OFFSET => Ok(self.signature),
                AHCI_PORT_SATA_STATUS_OFFSET => Ok(self.sata_status),
                AHCI_PORT_SATA_ACTIVE_OFFSET => Ok(self.sata_active),
                AHCI_PORT_COMMAND_ISSUE_OFFSET => Ok(self.command_issue),
                _ => Err(()),
            }
        }

        fn write_for_test(&mut self, register: u32, value: u32) {
            match register {
                AHCI_PORT_INTERRUPT_ENABLE_OFFSET => self.interrupt_enable = value,
                AHCI_PORT_COMMAND_OFFSET => self.command = value,
                AHCI_PORT_SIGNATURE_OFFSET => self.signature = value,
                AHCI_PORT_SATA_STATUS_OFFSET => self.sata_status = value,
                AHCI_PORT_SATA_ACTIVE_OFFSET => self.sata_active = value,
                AHCI_PORT_COMMAND_ISSUE_OFFSET => self.command_issue = value,
                _ => panic!("unexpected test register"),
            }
        }
    }

    #[derive(Clone, Copy)]
    struct Mutation {
        port: u8,
        register: u32,
        value: u32,
    }

    struct Registers {
        capabilities: u32,
        global_host_control: u32,
        implemented_ports: u32,
        version: u32,
        ports: [PortRegisters; AHCI_MAX_PORTS],
        port_read_counts: [u8; AHCI_MAX_PORTS],
        port_read_mask: u32,
        total_reads: usize,
        write_count: usize,
        reject_offset: Option<u32>,
        mutation: Option<Mutation>,
        version_change_on_read: Option<u8>,
        version_read_count: u8,
        change_version_after_ports: bool,
    }

    impl Registers {
        fn new(implemented_ports: u32, port_count: u8) -> Self {
            let capabilities = u32::from(port_count - 1) | (31 << 8) | (1 << 30);
            Self {
                capabilities,
                global_host_control: GHC_AHCI_ENABLE,
                implemented_ports,
                version: 0x0001_0301,
                ports: [PortRegisters::sata(); AHCI_MAX_PORTS],
                port_read_counts: [0; AHCI_MAX_PORTS],
                port_read_mask: 0,
                total_reads: 0,
                write_count: 0,
                reject_offset: None,
                mutation: None,
                version_change_on_read: None,
                version_read_count: 0,
                change_version_after_ports: false,
            }
        }

        fn controller(&self, mapping: AhciAbarMapping) -> AhciControllerSnapshot {
            AhciControllerSnapshot {
                device_object: mapping.device_object,
                configuration_generation: mapping.configuration_generation,
                mapping_generation: mapping.mapping_generation,
                version: self.version,
                capabilities: self.capabilities,
                implemented_ports: self.implemented_ports,
                port_count: ((self.capabilities & 0x1f) + 1) as u8,
                command_slot_count: (((self.capabilities >> 8) & 0x1f) + 1) as u8,
                native_command_queuing: self.capabilities & (1 << 30) != 0,
            }
        }

        fn decode_port_offset(offset: u32) -> Option<(u8, u32)> {
            let relative = offset.checked_sub(AHCI_PORT_BASE_OFFSET)?;
            let port = relative / AHCI_PORT_STRIDE_BYTES;
            let register = relative % AHCI_PORT_STRIDE_BYTES;
            (port < AHCI_MAX_PORTS as u32).then_some((port as u8, register))
        }
    }

    impl AhciRegisterIo for Registers {
        fn read_u32(&mut self, offset: u32) -> Result<u32, ()> {
            self.total_reads += 1;
            if self.reject_offset == Some(offset) {
                return Err(());
            }
            match offset {
                AHCI_CAP_OFFSET => return Ok(self.capabilities),
                AHCI_GHC_OFFSET => return Ok(self.global_host_control),
                AHCI_PI_OFFSET => return Ok(self.implemented_ports),
                AHCI_VERSION_OFFSET => {
                    self.version_read_count = self.version_read_count.checked_add(1).ok_or(())?;
                    if self.change_version_after_ports && self.port_read_mask != 0 {
                        return Ok(self.version ^ 1);
                    }
                    if self.version_change_on_read == Some(self.version_read_count) {
                        return Ok(self.version ^ 1);
                    }
                    return Ok(self.version);
                }
                _ => {}
            }

            let (port, register) = Self::decode_port_offset(offset).ok_or(())?;
            let port_index = usize::from(port);
            let port_mask = 1_u32 << u32::from(port);
            if self.implemented_ports & port_mask == 0 {
                return Err(());
            }
            self.port_read_mask |= port_mask;
            let value = self.ports[port_index].read(register)?;
            self.port_read_counts[port_index] =
                self.port_read_counts[port_index].checked_add(1).ok_or(())?;
            if self.port_read_counts[port_index] == PORT_OBSERVATION_READS {
                if let Some(mutation) = self.mutation {
                    if mutation.port == port {
                        self.ports[port_index].write_for_test(mutation.register, mutation.value);
                        self.mutation = None;
                    }
                }
            }
            Ok(value)
        }

        fn write_u32(&mut self, _offset: u32, _value: u32) -> Result<(), ()> {
            self.write_count += 1;
            Err(())
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

    fn discover(registers: &mut Registers) -> Result<AhciPortSnapshotSet, AhciPortDiscoveryError> {
        let mapping = mapping();
        discover_ahci_ports(mapping, registers.controller(mapping), registers)
    }

    fn port_offset(port: u8, register: u32) -> u32 {
        AHCI_PORT_BASE_OFFSET + u32::from(port) * AHCI_PORT_STRIDE_BYTES + register
    }

    #[test]
    fn classifies_conventional_and_unknown_signatures_and_preserves_generations() {
        let mut registers = Registers::new(0b1_1111, 5);
        registers.ports[0].signature = AHCI_SATA_SIGNATURE;
        registers.ports[0].sata_status =
            3 | (1 << SATA_STATUS_SPEED_SHIFT) | (1 << SATA_STATUS_POWER_SHIFT);
        registers.ports[1].signature = AHCI_ATAPI_SIGNATURE;
        registers.ports[1].sata_status =
            3 | (2 << SATA_STATUS_SPEED_SHIFT) | (2 << SATA_STATUS_POWER_SHIFT);
        registers.ports[2].signature = AHCI_ENCLOSURE_MANAGEMENT_SIGNATURE;
        registers.ports[2].sata_status =
            3 | (3 << SATA_STATUS_SPEED_SHIFT) | (6 << SATA_STATUS_POWER_SHIFT);
        registers.ports[3].signature = AHCI_PORT_MULTIPLIER_SIGNATURE;
        registers.ports[3].sata_status =
            3 | (3 << SATA_STATUS_SPEED_SHIFT) | (8 << SATA_STATUS_POWER_SHIFT);
        registers.ports[4].signature = 0x1234_5678;
        registers.ports[4].sata_status =
            3 | (2 << SATA_STATUS_SPEED_SHIFT) | (1 << SATA_STATUS_POWER_SHIFT);

        let snapshots = discover(&mut registers).unwrap();
        assert_eq!(snapshots.len(), 5);
        assert_eq!(snapshots.device_count(), 5);
        assert_eq!(snapshots.installed_recovery_candidate_count(), 1);
        assert_eq!(snapshots.controller().mapping_generation, 9);
        let expected = [
            (
                AhciPortDeviceKind::Sata,
                AhciPortPowerState::Active,
                AhciPortLinkSpeed::Generation1,
            ),
            (
                AhciPortDeviceKind::Atapi,
                AhciPortPowerState::Partial,
                AhciPortLinkSpeed::Generation2,
            ),
            (
                AhciPortDeviceKind::EnclosureManagement,
                AhciPortPowerState::Slumber,
                AhciPortLinkSpeed::Generation3,
            ),
            (
                AhciPortDeviceKind::PortMultiplier,
                AhciPortPowerState::DeviceSleep,
                AhciPortLinkSpeed::Generation3,
            ),
            (
                AhciPortDeviceKind::Unknown,
                AhciPortPowerState::Active,
                AhciPortLinkSpeed::Generation2,
            ),
        ];
        for (port, (device_kind, power_state, link_speed)) in expected.into_iter().enumerate() {
            let snapshot = snapshots.port(port as u8).unwrap();
            assert_eq!(snapshot.device_object, ObjectId(41));
            assert_eq!(snapshot.configuration_generation, 7);
            assert_eq!(snapshot.mapping_generation, 9);
            assert_eq!(snapshot.device_kind, Some(device_kind));
            assert_eq!(
                snapshot.link_state,
                AhciPortLinkState::Established(power_state)
            );
            assert_eq!(snapshot.link_speed, Some(link_speed));
            assert_eq!(snapshot.is_installed_recovery_candidate(), port == 0);
        }
        assert_eq!(snapshots.port(4).unwrap().signature, Some(0x1234_5678));
        assert_eq!(registers.write_count, 0);
    }

    #[test]
    fn retains_empty_transient_and_offline_implemented_ports_without_devices() {
        let mut registers = Registers::new(0b1101, 4);
        registers.ports[0].sata_status = 0;
        registers.ports[0].signature = AHCI_SATA_SIGNATURE;
        registers.ports[2].sata_status = 1;
        registers.ports[2].signature = AHCI_ATAPI_SIGNATURE;
        registers.ports[3].sata_status = 4;
        registers.ports[3].signature = AHCI_PORT_MULTIPLIER_SIGNATURE;

        let snapshots = discover(&mut registers).unwrap();
        assert_eq!(snapshots.len(), 3);
        assert_eq!(snapshots.device_count(), 0);
        assert_eq!(snapshots.installed_recovery_candidate_count(), 0);
        assert_eq!(
            snapshots.port(0).unwrap().link_state,
            AhciPortLinkState::NoDevice
        );
        assert_eq!(
            snapshots.port(2).unwrap().link_state,
            AhciPortLinkState::PresentWithoutCommunication
        );
        assert_eq!(
            snapshots.port(3).unwrap().link_state,
            AhciPortLinkState::Offline
        );
        assert!(snapshots.port(1).is_none());
        for port in [0, 2, 3] {
            let snapshot = snapshots.port(port).unwrap();
            assert!(!snapshot.has_device());
            assert_eq!(snapshot.link_speed, None);
            assert_eq!(snapshot.signature, None);
            assert!(!snapshot.is_installed_recovery_candidate());
        }
    }

    #[test]
    fn reads_only_implemented_ports_and_never_writes_registers() {
        let implemented_ports = (1 << 1) | (1 << 31);
        let mut registers = Registers::new(implemented_ports, 32);
        let snapshots = discover(&mut registers).unwrap();
        assert_eq!(snapshots.len(), 2);
        assert_eq!(registers.port_read_mask, implemented_ports);
        assert_eq!(registers.port_read_counts[1], 2 * PORT_OBSERVATION_READS);
        assert_eq!(registers.port_read_counts[31], 2 * PORT_OBSERVATION_READS);
        assert_eq!(snapshots.ports()[1].unwrap().port, 1);
        assert_eq!(snapshots.ports()[31].unwrap().port, 31);
        assert_eq!(registers.write_count, 0);
    }

    #[test]
    fn rejects_invalid_or_mismatched_generations_before_register_access() {
        let mapping = mapping();
        let mut registers = Registers::new(1, 1);
        let controller = registers.controller(mapping);

        for invalid_mapping in [
            AhciAbarMapping {
                mapping_generation: 0,
                ..mapping
            },
            AhciAbarMapping {
                physical_base: 0,
                ..mapping
            },
            AhciAbarMapping {
                virtual_base: mapping.virtual_base + 1,
                ..mapping
            },
            AhciAbarMapping {
                bytes: AHCI_ABAR_MINIMUM_BYTES,
                ..mapping
            },
        ] {
            assert_eq!(
                discover_ahci_ports(invalid_mapping, controller, &mut registers),
                Err(AhciPortDiscoveryError::InvalidMapping)
            );
        }
        assert_eq!(registers.total_reads, 0);

        let stale_mapping = AhciAbarMapping {
            mapping_generation: mapping.mapping_generation + 1,
            ..mapping
        };
        assert_eq!(
            discover_ahci_ports(stale_mapping, controller, &mut registers),
            Err(AhciPortDiscoveryError::ControllerSnapshotMismatch)
        );
        assert_eq!(registers.total_reads, 0);

        let mut inconsistent = controller;
        inconsistent.command_slot_count -= 1;
        assert_eq!(
            discover_ahci_ports(mapping, inconsistent, &mut registers),
            Err(AhciPortDiscoveryError::ControllerSnapshotMismatch)
        );
        assert_eq!(registers.total_reads, 0);

        let mut excess_port = controller;
        excess_port.implemented_ports |= 1 << 1;
        assert_eq!(
            discover_ahci_ports(mapping, excess_port, &mut registers),
            Err(AhciPortDiscoveryError::ControllerSnapshotMismatch)
        );
        assert_eq!(registers.total_reads, 0);
    }

    #[test]
    fn bounds_every_port_register_to_the_exact_mapping() {
        let mut exact = mapping();
        exact.bytes = AHCI_ABAR_MINIMUM_BYTES;
        assert_eq!(
            port_register_offset(exact, 31, AHCI_PORT_COMMAND_ISSUE_OFFSET),
            Ok(0x10b8)
        );
        assert_eq!(
            port_register_offset(exact, 32, AHCI_PORT_COMMAND_ISSUE_OFFSET),
            Err(AhciPortError::RegisterOutsideMapping)
        );
        assert_eq!(
            port_register_offset(exact, 0, AHCI_PORT_STRIDE_BYTES),
            Err(AhciPortError::RegisterOutsideMapping)
        );
        assert_eq!(
            port_register_offset(exact, 0, AHCI_PORT_SIGNATURE_OFFSET + 1),
            Err(AhciPortError::RegisterOutsideMapping)
        );
        exact.bytes = 0x10b8;
        assert_eq!(
            port_register_offset(exact, 31, AHCI_PORT_COMMAND_ISSUE_OFFSET),
            Err(AhciPortError::RegisterOutsideMapping)
        );
    }

    #[test]
    fn register_uncertainty_aborts_without_partial_publication() {
        let mut global_registers = Registers::new(1, 1);
        global_registers.reject_offset = Some(AHCI_CAP_OFFSET);
        assert_eq!(
            discover(&mut global_registers),
            Err(AhciPortDiscoveryError::ControllerRegisterRead)
        );
        assert_eq!(global_registers.port_read_mask, 0);
        assert_eq!(global_registers.write_count, 0);

        let mut port_registers = Registers::new(0b11, 2);
        port_registers.reject_offset = Some(port_offset(1, AHCI_PORT_SIGNATURE_OFFSET));
        assert_eq!(
            discover(&mut port_registers),
            Err(AhciPortDiscoveryError::Port {
                port: 1,
                error: AhciPortError::RegisterRead,
            })
        );
        assert_eq!(port_registers.write_count, 0);
    }

    #[test]
    fn changing_port_state_between_complete_samples_is_rejected() {
        for mutation in [
            Mutation {
                port: 0,
                register: AHCI_PORT_SATA_STATUS_OFFSET,
                value: 0,
            },
            Mutation {
                port: 0,
                register: AHCI_PORT_SIGNATURE_OFFSET,
                value: AHCI_ATAPI_SIGNATURE,
            },
        ] {
            let mut registers = Registers::new(0b11, 2);
            registers.mutation = Some(mutation);
            assert_eq!(
                discover(&mut registers),
                Err(AhciPortDiscoveryError::Port {
                    port: 0,
                    error: AhciPortError::StateChanged,
                })
            );
            assert_eq!(registers.port_read_counts[0], 2 * PORT_OBSERVATION_READS);
            assert_eq!(registers.port_read_counts[1], 2 * PORT_OBSERVATION_READS);
            assert_eq!(registers.write_count, 0);
        }
    }

    #[test]
    fn unstable_controller_observation_never_reaches_a_port() {
        let mut registers = Registers::new(1, 1);
        registers.version_change_on_read = Some(2);
        assert_eq!(
            discover(&mut registers),
            Err(AhciPortDiscoveryError::ControllerChanged)
        );
        assert_eq!(registers.port_read_mask, 0);
        assert_eq!(registers.write_count, 0);
    }

    #[test]
    fn controller_change_after_port_sampling_aborts_the_atomic_result() {
        let mut registers = Registers::new(1, 1);
        registers.change_version_after_ports = true;
        assert_eq!(
            discover(&mut registers),
            Err(AhciPortDiscoveryError::ControllerChanged)
        );
        assert_eq!(registers.write_count, 0);
    }

    #[test]
    fn unavailable_or_substituted_controller_never_reaches_a_port() {
        for global_host_control in [
            0,
            GHC_AHCI_ENABLE | GHC_INTERRUPT_ENABLE,
            GHC_AHCI_ENABLE | GHC_HBA_RESET,
        ] {
            let mut registers = Registers::new(1, 1);
            registers.global_host_control = global_host_control;
            assert_eq!(
                discover(&mut registers),
                Err(AhciPortDiscoveryError::ControllerUnavailable)
            );
            assert_eq!(registers.port_read_mask, 0);
        }

        let mapping = mapping();
        let mut registers = Registers::new(1, 1);
        let controller = registers.controller(mapping);
        registers.version ^= 1;
        assert_eq!(
            discover_ahci_ports(mapping, controller, &mut registers),
            Err(AhciPortDiscoveryError::ControllerSnapshotMismatch)
        );
        assert_eq!(registers.port_read_mask, 0);
    }

    #[test]
    fn enabled_interrupts_engines_or_commands_are_rejected() {
        let cases = [
            (
                AHCI_PORT_INTERRUPT_ENABLE_OFFSET,
                1,
                AhciPortError::InterruptsEnabled,
            ),
            (
                AHCI_PORT_COMMAND_OFFSET,
                PORT_COMMAND_START,
                AhciPortError::EngineActive,
            ),
            (
                AHCI_PORT_COMMAND_OFFSET,
                PORT_COMMAND_LIST_OVERRIDE,
                AhciPortError::EngineActive,
            ),
            (
                AHCI_PORT_COMMAND_OFFSET,
                PORT_FIS_RECEIVE_ENABLE,
                AhciPortError::EngineActive,
            ),
            (
                AHCI_PORT_COMMAND_OFFSET,
                PORT_FIS_RECEIVE_RUNNING,
                AhciPortError::EngineActive,
            ),
            (
                AHCI_PORT_COMMAND_OFFSET,
                PORT_COMMAND_LIST_RUNNING,
                AhciPortError::EngineActive,
            ),
            (
                AHCI_PORT_SATA_ACTIVE_OFFSET,
                1,
                AhciPortError::CommandsActive,
            ),
            (
                AHCI_PORT_COMMAND_ISSUE_OFFSET,
                1,
                AhciPortError::CommandsActive,
            ),
        ];
        for (register, value, error) in cases {
            let mut registers = Registers::new(1, 1);
            registers.ports[0].write_for_test(register, value);
            assert_eq!(
                discover(&mut registers),
                Err(AhciPortDiscoveryError::Port { port: 0, error })
            );
            assert_eq!(registers.write_count, 0);
        }
    }

    #[test]
    fn malformed_detection_speed_or_power_state_is_rejected() {
        let invalid_statuses = [
            1 << SATA_STATUS_SPEED_SHIFT,
            1 | (1 << SATA_STATUS_POWER_SHIFT),
            3 | (1 << SATA_STATUS_POWER_SHIFT),
            3 | (4 << SATA_STATUS_SPEED_SHIFT) | (1 << SATA_STATUS_POWER_SHIFT),
            3 | (1 << SATA_STATUS_SPEED_SHIFT) | (3 << SATA_STATUS_POWER_SHIFT),
            4 | (1 << SATA_STATUS_SPEED_SHIFT),
            2,
            1 << 12,
        ];
        for sata_status in invalid_statuses {
            let mut registers = Registers::new(1, 1);
            registers.ports[0].sata_status = sata_status;
            assert_eq!(
                discover(&mut registers),
                Err(AhciPortDiscoveryError::Port {
                    port: 0,
                    error: AhciPortError::InvalidLinkState(sata_status),
                })
            );
        }
    }

    #[test]
    fn unavailable_established_device_signature_is_rejected() {
        let mut registers = Registers::new(1, 1);
        registers.ports[0].signature = u32::MAX;
        assert_eq!(
            discover(&mut registers),
            Err(AhciPortDiscoveryError::Port {
                port: 0,
                error: AhciPortError::SignatureUnavailable,
            })
        );
    }
}
