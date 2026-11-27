//! Bounded, polled xHCI bring-up over an exclusively assigned MMIO/DMA backend.
//! This controller session does not grant PCI or DMA access to its caller.

mod activation;
mod bulk;
mod ecam_lease;
pub use activation::{DmaAssignment, PciActivation, VtdActivation};
pub use ecam_lease::{EcamLeaseError, EcamPciLease, NativePciBacking};
mod lifecycle;
mod managed_vtd;
mod native_owner;
pub use managed_vtd::{ManagedVtd, ManagedVtdError, VtdPciPlatform};
pub use native_owner::{NativePciBinding, NativePciLease, NativePciOwner, NativePciOwnerError};
pub mod pci;
pub use bulk::{BulkDma, BulkPipe};
pub use lifecycle::{Halted, RevocablePlatform, RevocationFailure, StartFailure, StopFailure};

const RUN: u32 = 1;
const RESET: u32 = 2;
const HALTED: u32 = 1;
const FATAL: u32 = (1 << 2) | (1 << 12);
const NOT_READY: u32 = 1 << 11;
const TRB_BYTES: u64 = 16;
const RING_BYTES: u64 = 16 * TRB_BYTES;
const ENABLE_SLOT: u32 = 9;
const ADDRESS_DEVICE: u32 = 11;
const COMMAND_NOOP: u32 = 23;
const PORT_RESET: u32 = 1 << 4;
const PORT_RESET_CHANGE: u32 = 1 << 21;
const PORT_CONNECT_CHANGE: u32 = 1 << 17;
const PORT_POWER: u32 = 1 << 9;
const HIGH_SPEED_ID: u8 = 3;
const SUPER_SPEED_ID: u8 = 4;
const COMMAND_COMPLETION: u32 = 33;
const PORT_STATUS_CHANGE: u32 = 34;

/// Owns the controller assignment and the DMA mappings for its entire life.
/// MMIO accesses must be ordered and restricted to the assigned BAR. DMA access
/// must be coherent and confined to the reserved device aperture. The backend
/// must quarantine live or uncertain assignments if dropped, and must not
/// release or reuse mappings until hardware access has been revoked.
pub trait Platform {
    type Error;
    fn read32(&mut self, byte_offset: u32) -> Result<u32, Self::Error>;
    fn write32(&mut self, byte_offset: u32, value: u32) -> Result<(), Self::Error>;
    fn dma_write(&mut self, device_address: u64, bytes: &[u8]) -> Result<(), Self::Error>;
    fn dma_read(&mut self, device_address: u64, bytes: &mut [u8]) -> Result<(), Self::Error>;
    /// Orders DMA initialization before publishing ownership or ringing a doorbell.
    fn publish_dma(&mut self) -> Result<(), Self::Error>;
    /// Orders device-written event data after observing the event cycle bit.
    fn acquire_dma(&mut self) -> Result<(), Self::Error>;
    fn wait_tick(&mut self) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error<E> {
    Platform(E),
    InvalidBar,
    Unsupported,
    FirmwareOwned,
    InvalidDma,
    Pci(pci::PciError),
    Vtd(mrml_kernel::arch::x86_64::VtdBindingError),
    Timeout,
    ControllerFault,
    UnexpectedEvent,
    CommandFailed(u8),
    InvalidPort,
    QueueExhausted,
    Faulted,
}

/// Four disjoint, DMA-mapped buffers belonging to this controller generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmaLayout {
    pub device_contexts: u64,
    pub command_ring: u64,
    pub event_segments: u64,
    pub event_ring: u64,
}

#[derive(Clone, Copy)]
struct Registers {
    operational: u32,
    runtime: u32,
    doorbell: u32,
    ports: u8,
    address64: bool,
    context_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortStatus {
    pub connected: bool,
    pub enabled: bool,
    pub powered: bool,
    pub speed_id: u8,
}

/// Caller-owned context and EP0 ring in the same isolated DMA aperture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceDma {
    pub input_context: u64,
    pub output_context: u64,
    pub control_ring: u64,
    pub control_buffer: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressedDevice {
    pub port: u8,
    pub address: u8,
}

/// Takes exclusive ownership of the backend even if initialization fails.
/// Currently admits one slot, one interrupter, 4 KiB page support, and no
/// scratchpads. Addressing admits one direct high-speed or SuperSpeed device.
pub struct Controller<P: Platform> {
    platform: P,
    registers: Registers,
    dma: DmaLayout,
    commands: u8,
    events: u8,
    event_cycle: bool,
    control: Option<(DeviceDma, u8, u8)>,
    faulted: bool,
    bulk_configured: bool,
    assignment: Option<DmaAssignment>,
}

impl<P: Platform> Controller<P> {
    /// For non-PCI or externally activated backends with DMA already isolated.
    /// For native PCI startup use start_pci to gate bus mastering.
    pub fn start(
        platform: P,
        bar_bytes: u32,
        dma: DmaLayout,
        ticks: u32,
    ) -> Result<Self, StartFailure<P>> {
        Self::start_inner(platform, bar_bytes, None, dma, ticks, |_| Ok(()))
    }

    fn start_inner(
        mut platform: P,
        bar_bytes: u32,
        assignment: Option<DmaAssignment>,
        dma: DmaLayout,
        ticks: u32,
        activate: impl FnOnce(&mut P) -> Result<(), Error<P::Error>>,
    ) -> Result<Self, StartFailure<P>> {
        let registers = match discover(&mut platform, bar_bytes).and_then(|registers| {
            validate_dma::<P::Error>(dma, registers.address64, assignment).map(|()| registers)
        }) {
            Ok(registers) => registers,
            Err(error) => return Err(StartFailure::Untouched { error, platform }),
        };
        let mut this = Self {
            platform,
            registers,
            dma,
            commands: 0,
            events: 0,
            event_cycle: true,
            control: None,
            faulted: false,
            bulk_configured: false,
            assignment,
        };
        match this.initialize(ticks, activate) {
            Ok(()) => Ok(this),
            Err(error) => Err(StartFailure::Programming(StopFailure::new(error, this))),
        }
    }

    fn initialize(
        &mut self,
        ticks: u32,
        activate: impl FnOnce(&mut P) -> Result<(), Error<P::Error>>,
    ) -> Result<(), Error<P::Error>> {
        let op = self.registers.operational;
        let rt = self.registers.runtime + 0x20;
        self.wait(op + 4, NOT_READY, 0, ticks)?;
        // Never carry forward firmware's interrupt or command action bits.
        self.write(op, 0)?;
        self.wait(op + 4, HALTED, HALTED, ticks)?;
        self.write(op, RESET)?;
        self.wait(op, RESET, 0, ticks)?;
        self.wait(op + 4, NOT_READY, 0, ticks)?;
        if self.read(op + 8)? & 1 == 0 {
            return Err(Error::Unsupported);
        }
        for (address, len) in [
            (self.dma.device_contexts, 16),
            (self.dma.command_ring, RING_BYTES as usize),
            (self.dma.event_ring, RING_BYTES as usize),
        ] {
            self.platform
                .dma_write(address, &[0; RING_BYTES as usize][..len])
                .map_err(Error::Platform)?;
        }
        let mut segment = [0; 16];
        segment[..8].copy_from_slice(&self.dma.event_ring.to_le_bytes());
        segment[8..12].copy_from_slice(&16u32.to_le_bytes());
        self.platform
            .dma_write(self.dma.event_segments, &segment)
            .map_err(Error::Platform)?;
        self.platform.publish_dma().map_err(Error::Platform)?;
        self.wait(op + 4, HALTED, HALTED, ticks)?;
        // Some controllers fetch the event ring segment table when its
        // registers are programmed. Enable only after reset and isolated
        // queue memory publication, but before installing those pointers.
        activate(&mut self.platform)?;
        self.write64(op + 0x30, self.dma.device_contexts)?;
        self.write64(op + 0x18, self.dma.command_ring | 1)?;
        self.write(op + 0x38, 1)?;
        self.write(rt, 1)?; // Clear pending, leave interrupts disabled.
        self.write(rt + 8, 1)?;
        self.write64(rt + 0x18, self.dma.event_ring)?;
        self.write64(rt + 0x10, self.dma.event_segments)?;
        self.write(op, RUN)?;
        self.wait(op + 4, HALTED, 0, ticks)
    }

    pub fn port_status(&mut self, port: u8) -> Result<PortStatus, Error<P::Error>> {
        if self.faulted {
            return Err(Error::Faulted);
        }
        if port == 0 || port > self.registers.ports {
            return Err(Error::InvalidPort);
        }
        let value = self.read(self.registers.operational + 0x400 + u32::from(port - 1) * 0x10)?;
        Ok(PortStatus {
            connected: value & 1 != 0,
            enabled: value & 2 != 0,
            powered: value & (1 << 9) != 0,
            speed_id: ((value >> 10) & 0xf) as u8,
        })
    }

    /// Admits one direct high-speed or enabled SuperSpeed port, then issues
    /// SET_ADDRESS through xHCI. A failed hardware sequence faults the session.
    pub fn address_device(
        &mut self,
        port: u8,
        dma: DeviceDma,
        ticks: u32,
    ) -> Result<AddressedDevice, Error<P::Error>> {
        let status = self.port_status(port)?;
        if self.control.is_some()
            || !status.connected
            || !status.powered
            || !matches!(status.speed_id, HIGH_SPEED_ID | SUPER_SPEED_ID)
            || (status.speed_id == SUPER_SPEED_ID && !status.enabled)
        {
            return Err(Error::InvalidPort);
        }
        if self.commands > 13 {
            return Err(Error::QueueExhausted);
        }
        let stride = self.registers.context_bytes;
        validate_ranges::<P::Error>(
            &[
                (self.dma.device_contexts, 16),
                (self.dma.command_ring, RING_BYTES),
                (self.dma.event_segments, 16),
                (self.dma.event_ring, RING_BYTES),
                (dma.input_context, 33 * stride as u64),
                (dma.output_context, 32 * stride as u64),
                (dma.control_ring, RING_BYTES),
                (dma.control_buffer, 256),
            ],
            self.registers.address64,
            self.assignment,
        )?;
        self.faulted = true;
        let result = self.address_device_inner(port, status.speed_id, dma, ticks);
        if result.is_ok() {
            self.faulted = false;
            self.control = Some((dma, port, 0));
        }
        result
    }

    fn address_device_inner(
        &mut self,
        port: u8,
        speed: u8,
        dma: DeviceDma,
        ticks: u32,
    ) -> Result<AddressedDevice, Error<P::Error>> {
        let portsc = self.registers.operational + 0x400 + u32::from(port - 1) * 0x10;
        // Do not echo PORTSC's write-one-to-clear bits or the port-disable bit.
        // Acknowledge a stale reset-change before starting this reset.
        self.write(portsc, PORT_POWER | PORT_RESET_CHANGE | PORT_CONNECT_CHANGE)?;
        if speed == HIGH_SPEED_ID {
            self.write(portsc, PORT_POWER | PORT_RESET)?;
            self.wait(
                portsc,
                PORT_RESET | PORT_RESET_CHANGE,
                PORT_RESET_CHANGE,
                ticks,
            )?;
        }
        let status = self.read(portsc)?;
        if status & (3 | PORT_CONNECT_CHANGE) != 3 || ((status >> 10) & 0xf) as u8 != speed {
            return Err(Error::InvalidPort);
        }
        self.write(portsc, PORT_POWER | PORT_RESET_CHANGE)?;

        let stride = self.registers.context_bytes;
        let mut input = [0; 33 * 64];
        input[4..8].copy_from_slice(&3u32.to_le_bytes()); // add slot and EP0
        let slot = &mut input[stride..2 * stride];
        slot[..4].copy_from_slice(&((1u32 << 27) | (u32::from(speed) << 20)).to_le_bytes());
        slot[4..8].copy_from_slice(&(u32::from(port) << 16).to_le_bytes());
        let control = &mut input[2 * stride..3 * stride];
        control[4..8].copy_from_slice(
            &((u32::from(if speed == SUPER_SPEED_ID { 512u16 } else { 64 }) << 16)
                | (4 << 3)
                | (3 << 1))
                .to_le_bytes(),
        );
        control[8..16].copy_from_slice(&(dma.control_ring | 1).to_le_bytes());
        control[16..20].copy_from_slice(&8u32.to_le_bytes());
        // An empty EP0 ring is reserved solely for this slot.
        let zeros = [0; 32 * 64];
        self.platform
            .dma_write(dma.input_context, &input[..33 * stride])
            .map_err(Error::Platform)?;
        self.platform
            .dma_write(dma.output_context, &zeros[..32 * stride])
            .map_err(Error::Platform)?;
        self.platform
            .dma_write(dma.control_ring, &zeros[..RING_BYTES as usize])
            .map_err(Error::Platform)?;
        let slot = self.issue_command(0, ENABLE_SLOT << 10, ticks)?;
        if slot != 1 {
            return Err(Error::UnexpectedEvent);
        }
        self.platform
            .dma_write(
                self.dma.device_contexts + 8,
                &dma.output_context.to_le_bytes(),
            )
            .map_err(Error::Platform)?;
        let completed =
            self.issue_command(dma.input_context, (ADDRESS_DEVICE << 10) | (1 << 24), ticks)?;
        if completed != slot {
            return Err(Error::UnexpectedEvent);
        }
        let mut assigned = [0; 4];
        self.platform
            .dma_read(dma.output_context + 12, &mut assigned)
            .map_err(Error::Platform)?;
        let assigned = u32::from_le_bytes(assigned);
        let address = (assigned & 0xff) as u8;
        if assigned >> 27 != 2 || !(1..=127).contains(&address) {
            return Err(Error::UnexpectedEvent);
        }
        Ok(AddressedDevice { port, address })
    }

    /// Reads one USB device or configuration descriptor from addressed EP0.
    /// Only full successful transfers are published; no automatic retry.
    pub fn read_descriptor(
        &mut self,
        kind: u8,
        index: u8,
        output: &mut [u8],
        ticks: u32,
    ) -> Result<(), Error<P::Error>> {
        if self.faulted {
            return Err(Error::Faulted);
        }
        let (dma, port, position) = self.control.ok_or(Error::InvalidPort)?;
        if !matches!((kind, index, output.len()), (1, 0, 18) | (2, _, 9..=256)) {
            return Err(Error::Unsupported);
        }
        if position > 12 {
            return Err(Error::QueueExhausted);
        }
        self.faulted = true;
        self.require_same_connection(port)?;
        let length = output.len() as u16;
        let [low, high] = length.to_le_bytes();
        let setup = u64::from_le_bytes([0x80, 6, index, kind, 0, 0, low, high]);
        let address = dma.control_ring + u64::from(position) * TRB_BYTES;
        // Stage the tail first; the setup cycle bit is the publication point.
        self.write_trb(address + 32, 0, 0, (4 << 10) | (1 << 5) | 1)?;
        self.write_trb(
            address + 16,
            dma.control_buffer,
            u32::from(length),
            (3 << 10) | (1 << 16) | (1 << 2) | 1,
        )?;
        self.write_trb(address, setup, 8, (2 << 10) | (3 << 16) | (1 << 6) | 1)?;
        self.platform.publish_dma().map_err(Error::Platform)?;
        self.write(self.registers.doorbell + 4, 1)?;
        for _ in 0..ticks {
            let Some((control, fields)) = self.next_event()? else {
                self.platform.wait_tick().map_err(Error::Platform)?;
                continue;
            };
            match (control >> 10) & 0x3f {
                PORT_STATUS_CHANGE => continue,
                32 if u64::from_le_bytes(fields[..8].try_into().unwrap()) == address + 32
                    && control >> 24 == 1
                    && (control >> 16) & 0x1f == 1 =>
                {
                    if fields[11] != 1 || fields[8..11] != [0; 3] {
                        return Err(Error::CommandFailed(fields[11]));
                    }
                    let mut staged = [0; 256];
                    self.platform
                        .dma_read(dma.control_buffer, &mut staged[..output.len()])
                        .map_err(Error::Platform)?;
                    if staged[1] != kind || staged[0] != if kind == 1 { 18 } else { 9 } {
                        return Err(Error::UnexpectedEvent);
                    }
                    self.require_same_connection(port)?;
                    output.copy_from_slice(&staged[..output.len()]);
                    self.control = Some((dma, port, position + 3));
                    self.faulted = false;
                    return Ok(());
                }
                _ => return Err(Error::UnexpectedEvent),
            }
        }
        Err(Error::Timeout)
    }

    fn require_same_connection(&mut self, port: u8) -> Result<(), Error<P::Error>> {
        let register = self.registers.operational + 0x400 + u32::from(port - 1) * 0x10;
        if self.read(register)? & (3 | PORT_CONNECT_CHANGE) != 3 {
            return Err(Error::InvalidPort);
        }
        Ok(())
    }

    fn write_trb(
        &mut self,
        address: u64,
        parameter: u64,
        length: u32,
        control: u32,
    ) -> Result<(), Error<P::Error>> {
        let mut fields = [0; 12];
        fields[..8].copy_from_slice(&parameter.to_le_bytes());
        fields[8..].copy_from_slice(&length.to_le_bytes());
        self.platform
            .dma_write(address, &fields)
            .map_err(Error::Platform)?;
        self.platform.publish_dma().map_err(Error::Platform)?;
        self.platform
            .dma_write(address + 12, &control.to_le_bytes())
            .map_err(Error::Platform)
    }

    /// Proves command/event DMA round-trip without addressing any USB device.
    pub fn no_op(&mut self, ticks: u32) -> Result<(), Error<P::Error>> {
        if self.faulted {
            return Err(Error::Faulted);
        }
        if self.commands >= 15 {
            return Err(Error::QueueExhausted);
        }
        self.faulted = true;
        let slot = self.issue_command(0, COMMAND_NOOP << 10, ticks)?;
        if slot != 0 {
            return Err(Error::UnexpectedEvent);
        }
        self.faulted = false;
        Ok(())
    }

    fn issue_command(
        &mut self,
        parameter: u64,
        control: u32,
        ticks: u32,
    ) -> Result<u8, Error<P::Error>> {
        // One empty sentinel remains; no wrap through an uninitialized entry.
        if self.commands >= 15 {
            return Err(Error::QueueExhausted);
        }
        let target = self.dma.command_ring + u64::from(self.commands) * TRB_BYTES;
        let mut fields = [0; 12];
        fields[..8].copy_from_slice(&parameter.to_le_bytes());
        self.platform
            .dma_write(target, &fields)
            .map_err(Error::Platform)?;
        self.platform.publish_dma().map_err(Error::Platform)?;
        self.platform
            .dma_write(target + 12, &(control | 1).to_le_bytes())
            .map_err(Error::Platform)?;
        self.platform.publish_dma().map_err(Error::Platform)?;
        self.write(self.registers.doorbell, 0)?;
        let slot = self.complete(target, ticks)?;
        self.commands += 1;
        Ok(slot)
    }

    fn complete(&mut self, target: u64, ticks: u32) -> Result<u8, Error<P::Error>> {
        for _ in 0..ticks {
            let Some((control, fields)) = self.next_event()? else {
                self.platform.wait_tick().map_err(Error::Platform)?;
                continue;
            };
            match (control >> 10) & 0x3f {
                PORT_STATUS_CHANGE => continue,
                COMMAND_COMPLETION
                    if u64::from_le_bytes(fields[..8].try_into().unwrap()) == target =>
                {
                    return if fields[11] == 1 {
                        Ok((control >> 24) as u8)
                    } else {
                        Err(Error::CommandFailed(fields[11]))
                    };
                }
                _ => return Err(Error::UnexpectedEvent),
            }
        }
        Err(Error::Timeout)
    }

    fn next_event(&mut self) -> Result<Option<(u32, [u8; 12])>, Error<P::Error>> {
        self.check_status()?;
        let event = self.dma.event_ring + u64::from(self.events) * TRB_BYTES;
        let mut control = [0; 4];
        self.platform
            .dma_read(event + 12, &mut control)
            .map_err(Error::Platform)?;
        let control = u32::from_le_bytes(control);
        if (control & 1 != 0) != self.event_cycle {
            return Ok(None);
        }
        self.platform.acquire_dma().map_err(Error::Platform)?;
        let mut fields = [0; 12];
        self.platform
            .dma_read(event, &mut fields)
            .map_err(Error::Platform)?;
        self.events += 1;
        if self.events == 16 {
            self.events = 0;
            self.event_cycle = !self.event_cycle;
        }
        self.write64(
            self.registers.runtime + 0x38,
            (self.dma.event_ring + u64::from(self.events) * TRB_BYTES) | 8,
        )?;
        Ok(Some((control, fields)))
    }

    /// Consumes the session. Only a confirmed halt permits the next step,
    /// withdrawing the backend's assignment and mappings.
    pub fn stop(mut self, ticks: u32) -> Result<Halted<P>, StopFailure<P>> {
        match self.confirm_halt(ticks) {
            Ok(()) => Ok(Halted::new(self.platform)),
            Err(error) => Err(StopFailure::new(error, self)),
        }
    }

    fn confirm_halt(&mut self, ticks: u32) -> Result<(), Error<P::Error>> {
        let op = self.registers.operational;
        self.wait(op + 4, NOT_READY, 0, ticks)?;
        self.wait(op, RESET, 0, ticks)?;
        self.write(op, 0)?;
        self.wait(op + 4, HALTED, HALTED, ticks)?;
        if self.read(op)? & (RUN | RESET) != 0 {
            return Err(Error::ControllerFault);
        }
        Ok(())
    }

    fn read(&mut self, offset: u32) -> Result<u32, Error<P::Error>> {
        self.platform.read32(offset).map_err(Error::Platform)
    }
    fn write(&mut self, offset: u32, value: u32) -> Result<(), Error<P::Error>> {
        self.platform
            .write32(offset, value)
            .map_err(Error::Platform)
    }
    fn write64(&mut self, offset: u32, value: u64) -> Result<(), Error<P::Error>> {
        self.write(offset, value as u32)?;
        self.write(offset + 4, (value >> 32) as u32)
    }
    fn check_status(&mut self) -> Result<(), Error<P::Error>> {
        if self.read(self.registers.operational + 4)? & FATAL != 0 {
            return Err(Error::ControllerFault);
        }
        Ok(())
    }
    fn wait(
        &mut self,
        offset: u32,
        mask: u32,
        expected: u32,
        ticks: u32,
    ) -> Result<(), Error<P::Error>> {
        for _ in 0..ticks {
            self.check_status()?;
            if self.read(offset)? & mask == expected {
                return Ok(());
            }
            self.platform.wait_tick().map_err(Error::Platform)?;
        }
        Err(Error::Timeout)
    }
}

fn discover<P: Platform>(platform: &mut P, bar_bytes: u32) -> Result<Registers, Error<P::Error>> {
    if bar_bytes < 0x20 {
        return Err(Error::InvalidBar);
    }
    let mut read = |offset| platform.read32(offset).map_err(Error::Platform);
    let hdr = read(0)?;
    let op = hdr & 0xff;
    if op < 0x20 || op & 3 != 0 || !(0x100..=0x1ff).contains(&(hdr >> 16)) {
        return Err(Error::Unsupported);
    }
    let hcs1 = read(4)?;
    let hcs2 = read(8)?;
    let hcc1 = read(0x10)?;
    let ports = (hcs1 >> 24) as u8;
    if hcs1 & 0xff == 0 || hcs1 & 0x7ff00 == 0 || ports == 0 || hcs2 & 0xffe0_0000 != 0 {
        return Err(Error::Unsupported);
    }
    let doorbell = read(0x14)? & !3;
    let runtime = read(0x18)? & !31;
    let ranges = [
        (0, op + 0x400 + 0x10 * u32::from(ports)),
        (doorbell, 8),
        (runtime, 0x40),
    ];
    for (i, &(start, size)) in ranges.iter().enumerate() {
        let end = start
            .checked_add(size)
            .filter(|&v| v <= bar_bytes)
            .ok_or(Error::InvalidBar)?;
        if ranges[..i]
            .iter()
            .any(|&(base, length)| start < base + length && end > base)
        {
            return Err(Error::InvalidBar);
        }
    }
    let mut ext = (hcc1 >> 16) * 4;
    for _ in 0..64 {
        if ext == 0 {
            return Ok(Registers {
                operational: op,
                runtime,
                doorbell,
                ports,
                address64: hcc1 & 1 != 0,
                context_bytes: if hcc1 & 4 != 0 { 64 } else { 32 },
            });
        }
        if ext < 0x20 || ext.checked_add(4).is_none_or(|end| end > bar_bytes) {
            return Err(Error::InvalidBar);
        }
        let header = read(ext)?;
        if header & 0xff == 1 && header & (1 << 16) != 0 {
            return Err(Error::FirmwareOwned);
        }
        let next = ((header >> 8) & 0xff) * 4;
        ext = if next == 0 {
            0
        } else {
            ext.checked_add(next).ok_or(Error::InvalidBar)?
        };
    }
    Err(Error::InvalidBar)
}

fn validate_dma<E>(
    dma: DmaLayout,
    address64: bool,
    assignment: Option<DmaAssignment>,
) -> Result<(), Error<E>> {
    let ranges = [
        (dma.device_contexts, 16),
        (dma.command_ring, RING_BYTES),
        (dma.event_segments, 16),
        (dma.event_ring, RING_BYTES),
    ];
    validate_ranges(&ranges, address64, assignment)
}

fn validate_ranges<E>(
    ranges: &[(u64, u64)],
    address64: bool,
    assignment: Option<DmaAssignment>,
) -> Result<(), Error<E>> {
    for (i, &(base, size)) in ranges.iter().enumerate() {
        let end = base.checked_add(size).ok_or(Error::InvalidDma)?;
        if base == 0
            || base & 63 != 0
            || (base >> 16 != (end - 1) >> 16)
            || (!address64 && end > 1u64 << 32)
            || assignment.is_some_and(|mapping| !mapping.contains(base, size))
            || ranges[..i]
                .iter()
                .any(|&(other, len)| base < other + len && end > other)
        {
            return Err(Error::InvalidDma);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
