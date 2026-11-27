//! Polled USB 2 and SuperSpeed bulk IN/OUT, with exact completion.
use super::*;
use crate::{BulkTransport, SECTOR_BYTES, find_bulk_interface};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BulkDma {
    pub input_ring: u64,
    pub output_ring: u64,
    pub buffer: u64,
}

const LINK_INDEX: u8 = 15;

#[derive(Clone, Copy)]
struct Cursor {
    index: u8,
    cycle: bool,
}

impl Cursor {
    const INITIAL: Self = Self {
        index: 0,
        cycle: true,
    };

    fn advance(&mut self) {
        self.index += 1;
        if self.index == LINK_INDEX {
            self.index = 0;
            self.cycle = !self.cycle;
        }
    }
}

/// Borrows the controller exclusively, with at most one outstanding transfer.
pub struct BulkPipe<'a, P: Platform> {
    controller: &'a mut Controller<P>,
    dma: BulkDma,
    endpoint: [u8; 2],
    enqueue: [Cursor; 2],
    port: u8,
    ticks: u32,
}

impl<P: Platform> Controller<P> {
    /// Configures the exact descriptor-selected BOT pair on the addressed slot.
    /// The configuration bytes must have come from this connection's EP0.
    pub fn configure_bulk<'a>(
        &'a mut self,
        configuration: &[u8],
        dma: BulkDma,
        ticks: u32,
    ) -> Result<BulkPipe<'a, P>, Error<P::Error>> {
        if self.faulted {
            return Err(Error::Faulted);
        }
        let (dev, port, ep0) = self.control.ok_or(Error::InvalidPort)?;
        if self.bulk_configured || ep0 > 13 || self.commands >= 15 {
            return Err(Error::QueueExhausted);
        }
        let interface = find_bulk_interface(configuration).map_err(|_| Error::Unsupported)?;
        let speed = self.port_status(port)?.speed_id;
        let (packet, bursts) = match (
            speed,
            interface.packet_in,
            interface.packet_out,
            interface.burst_in,
            interface.burst_out,
        ) {
            (HIGH_SPEED_ID, 512, 512, None, None) => (512u32, [0, 0]),
            (SUPER_SPEED_ID, 1024, 1024, Some(input), Some(output)) => (1024, [input, output]),
            _ => return Err(Error::Unsupported),
        };
        if configuration[4] != 1 {
            return Err(Error::Unsupported);
        }
        let endpoint = [
            (interface.bulk_in & 15) * 2 + 1,
            (interface.bulk_out & 15) * 2,
        ];
        let stride = self.registers.context_bytes;
        validate_ranges::<P::Error>(
            &[
                (self.dma.device_contexts, 16),
                (self.dma.command_ring, RING_BYTES),
                (self.dma.event_segments, 16),
                (self.dma.event_ring, RING_BYTES),
                (dev.input_context, 33 * stride as u64),
                (dev.output_context, 32 * stride as u64),
                (dev.control_ring, RING_BYTES),
                (dev.control_buffer, 256),
                (dma.input_ring, RING_BYTES),
                (dma.output_ring, RING_BYTES),
                (dma.buffer, SECTOR_BYTES as u64),
            ],
            self.registers.address64,
        )?;
        self.faulted = true;
        self.require_same_connection(port)?;
        let mut input = [0; 33 * 64];
        let flags = 1u32 | (1 << endpoint[0]) | (1 << endpoint[1]);
        input[4..8].copy_from_slice(&flags.to_le_bytes());
        let slot = &mut input[stride..2 * stride];
        self.platform
            .dma_read(dev.output_context, &mut slot[..12])
            .map_err(Error::Platform)?;
        let value = u32::from_le_bytes(slot[..4].try_into().unwrap());
        let entries = u32::from(endpoint[0].max(endpoint[1]));
        slot[..4].copy_from_slice(&((value & 0x07ff_ffff) | (entries << 27)).to_le_bytes());
        for (direction, &dci) in endpoint.iter().enumerate() {
            let ring = [dma.input_ring, dma.output_ring][direction];
            self.platform
                .dma_write(ring, &[0; RING_BYTES as usize])
                .map_err(Error::Platform)?;
            let start = (usize::from(dci) + 1) * stride;
            let ep = &mut input[start..start + stride];
            let kind = [6u32, 2][direction];
            ep[4..8].copy_from_slice(
                &((packet << 16) | (u32::from(bursts[direction]) << 8) | (kind << 3) | (3 << 1))
                    .to_le_bytes(),
            );
            ep[8..16].copy_from_slice(&(ring | 1).to_le_bytes());
            ep[16..20].copy_from_slice(&512u32.to_le_bytes());
        }
        self.platform
            .dma_write(dev.input_context, &input[..33 * stride])
            .map_err(Error::Platform)?;
        if self.issue_command(dev.input_context, (12 << 10) | (1 << 24), ticks)? != 1 {
            return Err(Error::UnexpectedEvent);
        }

        let trb = dev.control_ring + u64::from(ep0) * TRB_BYTES;
        let setup = u64::from_le_bytes([0, 9, interface.configuration, 0, 0, 0, 0, 0]);
        // No-data control request: status stage is IN.
        self.write_trb(trb + 16, 0, 0, (4 << 10) | (1 << 16) | (1 << 5) | 1)?;
        self.write_trb(trb, setup, 8, (2 << 10) | (1 << 6) | 1)?;
        self.platform.publish_dma().map_err(Error::Platform)?;
        self.write(self.registers.doorbell + 4, 1)?;
        self.complete_transfer(trb + 16, 1, ticks)?;
        self.require_same_connection(port)?;
        self.control = Some((dev, port, ep0 + 2));
        self.bulk_configured = true;
        self.faulted = false;
        Ok(BulkPipe {
            controller: self,
            dma,
            endpoint,
            enqueue: [Cursor::INITIAL; 2],
            port,
            ticks,
        })
    }

    fn complete_transfer(
        &mut self,
        target: u64,
        dci: u8,
        ticks: u32,
    ) -> Result<(), Error<P::Error>> {
        for _ in 0..ticks {
            let Some((control, fields)) = self.next_event()? else {
                self.platform.wait_tick().map_err(Error::Platform)?;
                continue;
            };
            match (control >> 10) & 0x3f {
                PORT_STATUS_CHANGE => continue,
                32 if u64::from_le_bytes(fields[..8].try_into().unwrap()) == target
                    && control >> 24 == 1
                    && (control >> 16) & 31 == u32::from(dci)
                    && control & 4 == 0 =>
                {
                    return if fields[11] != 1 {
                        Err(Error::CommandFailed(fields[11]))
                    } else if fields[8..11] != [0; 3] {
                        Err(Error::UnexpectedEvent)
                    } else {
                        Ok(())
                    };
                }
                _ => return Err(Error::UnexpectedEvent),
            }
        }
        Err(Error::Timeout)
    }
}

enum Direction<'a> {
    In(&'a mut [u8]),
    Out(&'a [u8]),
}

impl<P: Platform> BulkPipe<'_, P> {
    fn transfer(&mut self, data: Direction<'_>) -> Result<usize, Error<P::Error>> {
        let c = &mut self.controller;
        if c.faulted {
            return Err(Error::Faulted);
        }
        let (direction, len) = match &data {
            Direction::In(bytes) => (0, bytes.len()),
            Direction::Out(bytes) => (1, bytes.len()),
        };
        if !(1..=SECTOR_BYTES).contains(&len) {
            return Err(Error::Unsupported);
        }
        c.faulted = true;
        c.require_same_connection(self.port)?;
        if let Direction::Out(bytes) = &data {
            c.platform
                .dma_write(self.dma.buffer, bytes)
                .map_err(Error::Platform)?;
        }
        let ring = [self.dma.input_ring, self.dma.output_ring][direction];
        let head = self.enqueue[direction];
        let cycle = u32::from(head.cycle);
        let trb = ring + u64::from(head.index) * TRB_BYTES;
        // The final Normal TRB is still software-owned. Publish the Link
        // before that Normal TRB hands control to the controller. Entry zero
        // retains the old cycle until the next transfer is actually issued.
        if head.index + 1 == LINK_INDEX {
            c.write_trb(trb + TRB_BYTES, ring, 0, (6 << 10) | (1 << 1) | cycle)?;
        }
        let dci = self.endpoint[direction];
        c.write_trb(
            trb,
            self.dma.buffer,
            len as u32,
            (1 << 10) | (1 << 5) | (1 << 2) | cycle,
        )?;
        c.platform.publish_dma().map_err(Error::Platform)?;
        c.write(c.registers.doorbell + 4, u32::from(dci))?;
        c.complete_transfer(trb, dci, self.ticks)?;
        let mut staged = [0; SECTOR_BYTES];
        if direction == 0 {
            c.platform
                .dma_read(self.dma.buffer, &mut staged[..len])
                .map_err(Error::Platform)?;
        }
        c.require_same_connection(self.port)?;
        if let Direction::In(bytes) = data {
            bytes.copy_from_slice(&staged[..len]);
        }
        self.enqueue[direction].advance();
        c.faulted = false;
        Ok(len)
    }
}

impl<P: Platform> BulkTransport for BulkPipe<'_, P> {
    type Error = Error<P::Error>;
    fn bulk_out(&mut self, bytes: &[u8]) -> Result<usize, Self::Error> {
        self.transfer(Direction::Out(bytes))
    }
    fn bulk_in(&mut self, bytes: &mut [u8]) -> Result<usize, Self::Error> {
        self.transfer(Direction::In(bytes))
    }
}
