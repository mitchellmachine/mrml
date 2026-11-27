//! Bounded, polled xHCI bring-up over an exclusively assigned MMIO/DMA backend.
//! This controller session does not grant PCI or DMA access to its caller.

const RUN: u32 = 1;
const RESET: u32 = 2;
const HALTED: u32 = 1;
const FATAL: u32 = (1 << 2) | (1 << 12);
const NOT_READY: u32 = 1 << 11;
const TRB_BYTES: u64 = 16;
const RING_BYTES: u64 = 16 * TRB_BYTES;
const COMMAND_NOOP: u32 = 23;
const COMMAND_COMPLETION: u32 = 33;
const PORT_STATUS_CHANGE: u32 = 34;

/// Owns the controller assignment and the DMA mappings for its entire life.
/// MMIO accesses must be ordered and restricted to the assigned BAR. DMA access
/// must be coherent and confined to the reserved device aperture. The backend
/// must not release or reuse mappings after an error until it proves the
/// controller is quiescent, or quarantines it behind DMA isolation.
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortStatus {
    pub connected: bool,
    pub enabled: bool,
    pub powered: bool,
    pub speed_id: u8,
}

/// Takes exclusive ownership of the backend even if initialization fails.
/// Currently admits one slot, one interrupter, 4 KiB page support, and no
/// scratchpads. No device-facing transfer ring is armed in this profile.
pub struct Controller<P: Platform> {
    platform: P,
    registers: Registers,
    dma: DmaLayout,
    commands: u8,
    events: u8,
    event_cycle: bool,
    faulted: bool,
}

impl<P: Platform> Controller<P> {
    pub fn start(
        mut platform: P,
        bar_bytes: u32,
        dma: DmaLayout,
        ticks: u32,
    ) -> Result<Self, Error<P::Error>> {
        let registers = discover(&mut platform, bar_bytes)?;
        validate_dma::<P::Error>(dma, registers.address64)?;
        let mut this = Self {
            platform,
            registers,
            dma,
            commands: 0,
            events: 0,
            event_cycle: true,
            faulted: false,
        };
        this.initialize(ticks)?;
        Ok(this)
    }

    fn initialize(&mut self, ticks: u32) -> Result<(), Error<P::Error>> {
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

    /// Proves command/event DMA round-trip without addressing any USB device.
    pub fn no_op(&mut self, ticks: u32) -> Result<(), Error<P::Error>> {
        if self.faulted {
            return Err(Error::Faulted);
        }
        // Do not allow the producer to reach nor wrap past the end of the
        // command segment. One empty sentinel must remain after the last TRB.
        if self.commands >= 15 {
            return Err(Error::QueueExhausted);
        }
        self.faulted = true;
        let target = self.dma.command_ring + u64::from(self.commands) * TRB_BYTES;
        // A fresh slot already has a zero cycle bit. Publish dwords 0–2 before
        // making the final control dword visible to an already-running xHC.
        self.platform
            .dma_write(target, &[0; 12])
            .map_err(Error::Platform)?;
        self.platform.publish_dma().map_err(Error::Platform)?;
        self.platform
            .dma_write(target + 12, &((COMMAND_NOOP << 10) | 1).to_le_bytes())
            .map_err(Error::Platform)?;
        self.platform.publish_dma().map_err(Error::Platform)?;
        self.write(self.registers.doorbell, 0)?;
        let result = self.complete(target, ticks);
        if result.is_ok() {
            self.commands += 1;
            self.faulted = false;
        }
        result
    }

    fn complete(&mut self, target: u64, ticks: u32) -> Result<(), Error<P::Error>> {
        for _ in 0..ticks {
            self.check_status()?;
            let event = self.dma.event_ring + u64::from(self.events) * TRB_BYTES;
            let mut control = [0; 4];
            self.platform
                .dma_read(event + 12, &mut control)
                .map_err(Error::Platform)?;
            let control = u32::from_le_bytes(control);
            if (control & 1 != 0) != self.event_cycle {
                self.platform.wait_tick().map_err(Error::Platform)?;
                continue;
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
            match (control >> 10) & 0x3f {
                PORT_STATUS_CHANGE => continue,
                COMMAND_COMPLETION
                    if u64::from_le_bytes(fields[..8].try_into().unwrap()) == target =>
                {
                    return if fields[11] == 1 {
                        Ok(())
                    } else {
                        Err(Error::CommandFailed(fields[11]))
                    };
                }
                _ => return Err(Error::UnexpectedEvent),
            }
        }
        Err(Error::Timeout)
    }

    /// Puts the controller back in the halted state. The platform still owns
    /// mappings and must handle teardown even when this method fails.
    pub fn halt(&mut self, ticks: u32) -> Result<(), Error<P::Error>> {
        self.faulted = true;
        let op = self.registers.operational;
        self.write(op, 0)?;
        self.wait(op + 4, HALTED, HALTED, ticks)
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
        (doorbell, 4),
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

fn validate_dma<E>(dma: DmaLayout, address64: bool) -> Result<(), Error<E>> {
    let ranges = [
        (dma.device_contexts, 16),
        (dma.command_ring, RING_BYTES),
        (dma.event_segments, 16),
        (dma.event_ring, RING_BYTES),
    ];
    for (i, &(base, size)) in ranges.iter().enumerate() {
        let end = base.checked_add(size).ok_or(Error::InvalidDma)?;
        if base == 0
            || base & 63 != 0
            || (base >> 16 != (end - 1) >> 16)
            || (!address64 && end > 1u64 << 32)
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
