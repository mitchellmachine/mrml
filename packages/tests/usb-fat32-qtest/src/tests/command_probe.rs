//! Emulator-only broker for one no-op command. It never lends raw PCI access.
use super::{DMA, PciActivation, PciSnapshot, Platform};

pub trait CommandIo: Platform<Error = ()> {
    fn snapshot(&mut self) -> Result<PciSnapshot, ()>;
    fn activate(&mut self, before: u16) -> Result<(), ()>;
    fn revoke(&mut self) -> Result<(), ()>;
}

struct Command<'a, P> {
    platform: &'a mut P,
    assignment: super::DmaAssignment,
    operational: u32,
    runtime: u32,
    doorbell: u32,
    published: bool,
    activated: bool,
    doorbell_sent: bool,
    revoked: bool,
}

impl<P: PciActivation> Platform for Command<'_, P> {
    type Error = ();

    fn read32(&mut self, offset: u32) -> Result<u32, ()> {
        if self.revoked {
            return Err(());
        }
        self.platform.read32(offset).map_err(|_| ())
    }

    fn write32(&mut self, offset: u32, value: u32) -> Result<(), ()> {
        let op = self.operational;
        let rt = self.runtime;
        let event = DMA.event_ring as u32;
        let allowed = if offset == op {
            matches!(value, 0 | 2) && !self.activated || matches!(value, 0 | 1) && self.activated
        } else if !self.activated {
            false
        } else if offset == self.doorbell {
            value == 0 && !self.doorbell_sent
        } else {
            match offset {
                x if x == op + 0x30 => value == DMA.device_contexts as u32,
                x if x == op + 0x18 => value == DMA.command_ring as u32 | 1,
                x if x == op + 0x38 || x == rt || x == rt + 8 => value == 1,
                x if x == rt + 0x10 => value == DMA.event_segments as u32,
                x if x == rt + 0x18 => {
                    value == event
                        || ((event + 16)..(event + 256)).contains(&(value & !15)) && value & 15 == 8
                }
                x if [op + 0x34, op + 0x1c, rt + 0x14, rt + 0x1c].contains(&x) => value == 0,
                _ => false,
            }
        };
        if self.revoked || !allowed {
            return Err(());
        }
        if offset == self.doorbell {
            self.doorbell_sent = true;
        }
        self.platform.write32(offset, value).map_err(|_| ())
    }

    fn dma_write(&mut self, address: u64, bytes: &[u8]) -> Result<(), ()> {
        let mut segment = [0; 16];
        segment[..8].copy_from_slice(&DMA.event_ring.to_le_bytes());
        segment[8..12].copy_from_slice(&16u32.to_le_bytes());
        let allowed = if self.activated {
            !self.doorbell_sent
                && ((address == DMA.command_ring && bytes == [0; 12])
                    || (address == DMA.command_ring + 12
                        && bytes == (23u32 << 10 | 1).to_le_bytes()))
        } else {
            (address == DMA.event_segments && bytes == segment)
                || [
                    DMA.device_contexts,
                    DMA.command_ring,
                    DMA.event_segments,
                    DMA.event_ring,
                ]
                .into_iter()
                .zip([16, 256, 16, 256])
                .any(|(base, size)| {
                    address == base && bytes.len() == size && bytes.iter().all(|&b| b == 0)
                })
        };
        if self.revoked || !allowed {
            return Err(());
        }
        self.platform.dma_write(address, bytes).map_err(|_| ())
    }

    fn dma_read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), ()> {
        if self.revoked
            || !self.doorbell_sent
            || !matches!(bytes.len(), 4 | 12)
            || address < DMA.event_ring
            || address
                .checked_add(bytes.len() as u64)
                .is_none_or(|end| end > DMA.event_ring + 256)
        {
            return Err(());
        }
        self.platform.dma_read(address, bytes).map_err(|_| ())
    }

    fn publish_dma(&mut self) -> Result<(), ()> {
        if self.revoked {
            return Err(());
        }
        self.platform.publish_dma().map_err(|_| ())?;
        self.published = true;
        Ok(())
    }

    fn acquire_dma(&mut self) -> Result<(), ()> {
        if self.revoked || !self.doorbell_sent {
            return Err(());
        }
        self.platform.acquire_dma().map_err(|_| ())
    }

    fn wait_tick(&mut self) -> Result<(), ()> {
        if self.revoked {
            return Err(());
        }
        self.platform.wait_tick().map_err(|_| ())
    }
}

impl<P: PciActivation> CommandIo for Command<'_, P> {
    fn snapshot(&mut self) -> Result<PciSnapshot, ()> {
        if self.revoked {
            return Err(());
        }
        let (snapshot, live) = self.platform.activation_state().map_err(|_| ())?;
        (live == self.assignment).then_some(snapshot).ok_or(())
    }

    fn activate(&mut self, before: u16) -> Result<(), ()> {
        if self.revoked
            || self.activated
            || !self.published
            || self.snapshot()?.command != before
            || before & 6 != 2
        {
            return Err(());
        }
        self.platform
            .enable_bus_master(self.assignment, before)
            .map_err(|_| ())?;
        self.activated = true;
        Ok(())
    }

    fn revoke(&mut self) -> Result<(), ()> {
        if self.revoked
            || !self.doorbell_sent
            || self.platform.read32(self.operational).map_err(|_| ())? & 3 != 0
            || self.platform.read32(self.operational + 4).map_err(|_| ())? & 1 == 0
        {
            return Err(());
        }
        self.platform.revoke_after_halt().map_err(|_| ())?;
        self.revoked = true;
        Ok(())
    }
}

pub(super) fn run<P: PciActivation>(platform: &mut P, probe: &mut dyn FnMut(&mut dyn CommandIo))
where
    P::Error: core::fmt::Debug,
{
    let (before, assignment) = platform.activation_state().unwrap();
    assert_eq!(before.command & 6, 2);
    let operational = platform.read32(0).unwrap() & 0xff;
    let runtime = (platform.read32(0x18).unwrap() & !31) + 0x20;
    let doorbell = platform.read32(0x14).unwrap() & !3;
    let mut broker = Command {
        platform,
        assignment,
        operational,
        runtime,
        doorbell,
        published: false,
        activated: false,
        doorbell_sent: false,
        revoked: false,
    };
    assert!(broker.activate(before.command).is_err());
    assert!(broker.write32(doorbell, 0).is_err());
    probe(&mut broker);
    assert!(broker.activated && broker.doorbell_sent && broker.revoked);
    assert!(broker.read32(0).is_err());
    assert!(broker.activate(before.command).is_err());
    let (after, same) = platform.activation_state().unwrap();
    assert_eq!(same, assignment);
    assert_eq!(after.command & 6, 0);
    let mut events = [0; 256];
    platform.dma_read(DMA.event_ring, &mut events).unwrap();
    assert_eq!(
        events
            .chunks_exact(16)
            .filter(|entry| {
                let control = u32::from_le_bytes(entry[12..16].try_into().unwrap());
                control & 1 != 0
                    && (control >> 10) & 63 == 33
                    && entry[11] == 1
                    && entry[12..16][3] == 0
                    && entry[..8] == DMA.command_ring.to_le_bytes()
            })
            .count(),
        1
    );
    for address in [
        DMA.device_contexts,
        DMA.command_ring,
        DMA.event_segments,
        DMA.event_ring,
    ] {
        platform.dma_write(address, &[0; 256]).unwrap();
        platform.dma_read(address, &mut events).unwrap();
        assert_eq!(events, [0; 256]);
    }
}
