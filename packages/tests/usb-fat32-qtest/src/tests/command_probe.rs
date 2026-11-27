//! Emulator-only broker for one no-op and optional single-device enumeration.
use super::{DMA, PciActivation, PciSnapshot, Platform};

pub trait CommandIo: Platform<Error = ()> {
    fn snapshot(&mut self) -> Result<PciSnapshot, ()>;
    fn activate(&mut self, before: u16) -> Result<(), ()>;
    fn revoke(&mut self) -> Result<(), ()>;
}

const INPUT: u64 = 0x10_1000;
const OUTPUT: u64 = 0x10_2000;
const EP0: u64 = 0x10_3000;
const BUFFER: u64 = 0x10_4000;

#[derive(Clone, Copy)]
struct Enumeration {
    portsc: u32,
    port: u8,
    speed: u32,
    stride: usize,
}

impl Enumeration {
    fn context_write(self, address: u64, bytes: &[u8]) -> bool {
        if address == INPUT && bytes.len() == 33 * self.stride {
            let mut expected = [0; 33 * 64];
            expected[4..8].copy_from_slice(&3u32.to_le_bytes());
            let slot = self.stride;
            expected[slot..slot + 4]
                .copy_from_slice(&((1 << 27) | (self.speed << 20)).to_le_bytes());
            expected[slot + 4..slot + 8]
                .copy_from_slice(&(u32::from(self.port) << 16).to_le_bytes());
            let ep = 2 * slot;
            let max_packet = if self.speed == 4 { 512u32 } else { 64 };
            expected[ep + 4..ep + 8]
                .copy_from_slice(&((max_packet << 16) | (4 << 3) | (3 << 1)).to_le_bytes());
            expected[ep + 8..ep + 16].copy_from_slice(&(EP0 | 1).to_le_bytes());
            expected[ep + 16..ep + 20].copy_from_slice(&8u32.to_le_bytes());
            return bytes == &expected[..bytes.len()];
        }
        ((address == OUTPUT && bytes.len() == 32 * self.stride)
            || (address == EP0 && bytes.len() == 256))
            && bytes.iter().all(|&byte| byte == 0)
    }
}

fn trb_fields(parameter: u64, length: u32) -> [u8; 12] {
    let mut bytes = [0; 12];
    bytes[..8].copy_from_slice(&parameter.to_le_bytes());
    bytes[8..].copy_from_slice(&length.to_le_bytes());
    bytes
}

fn descriptor_write(address: u64, bytes: &[u8]) -> bool {
    let setup = u64::from_le_bytes([0x80, 6, 0, 1, 0, 0, 18, 0]);
    let stages = [
        (EP0, setup, 8, (2u32 << 10) | (3 << 16) | (1 << 6) | 1),
        (
            EP0 + 16,
            BUFFER,
            18,
            (3u32 << 10) | (1 << 16) | (1 << 2) | 1,
        ),
        (EP0 + 32, 0, 0, (4u32 << 10) | (1 << 5) | 1),
    ];
    stages
        .into_iter()
        .any(|(base, parameter, length, control)| {
            (address == base && bytes == trb_fields(parameter, length))
                || (address == base + 12 && bytes == control.to_le_bytes())
        })
}

fn verify_descriptor<P: Platform>(events: &[u8], platform: &mut P)
where
    P::Error: core::fmt::Debug,
{
    let check = |kind, pointer, slot, endpoint| {
        assert_eq!(
            events
                .chunks_exact(16)
                .filter(|entry| {
                    let control = u32::from_le_bytes(entry[12..16].try_into().unwrap());
                    control & 1 != 0
                        && (control >> 10) & 63 == kind
                        && (control >> 16) & 31 == endpoint
                        && control >> 24 == slot
                        && entry[11] == 1
                        && entry[..8] == u64::to_le_bytes(pointer)
                })
                .count(),
            1
        );
    };
    check(33, DMA.command_ring + 16, 1, 0);
    check(33, DMA.command_ring + 32, 1, 0);
    check(32, EP0 + 32, 1, 1);
    let mut descriptor = [0; 18];
    platform.dma_read(BUFFER, &mut descriptor).unwrap();
    assert_eq!(&descriptor[..2], &[18, 1]);
    for (address, length) in [
        (INPUT, 33 * 64),
        (OUTPUT, 32 * 64),
        (EP0, 256),
        (BUFFER, 18),
    ] {
        let mut bytes = vec![1; length];
        platform.dma_write(address, &vec![0; length]).unwrap();
        platform.dma_read(address, &mut bytes).unwrap();
        assert!(bytes.iter().all(|&byte| byte == 0));
    }
}

struct Command<'a, P> {
    platform: &'a mut P,
    assignment: super::DmaAssignment,
    operational: u32,
    runtime: u32,
    doorbell: u32,
    published: bool,
    activated: bool,
    command_count: u8,
    descriptor_sent: bool,
    enumeration: Option<Enumeration>,
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
            value == 0 && self.command_count < if self.enumeration.is_some() { 3 } else { 1 }
        } else if offset == self.doorbell + 4 {
            value == 1
                && self.enumeration.is_some()
                && self.command_count == 3
                && !self.descriptor_sent
        } else if self.enumeration.is_some_and(|e| offset == e.portsc) {
            [0x220200, 0x210, 0x200200].contains(&value)
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
            self.command_count += 1;
        } else if offset == self.doorbell + 4 {
            self.descriptor_sent = true;
        }
        self.platform.write32(offset, value).map_err(|_| ())
    }

    fn dma_write(&mut self, address: u64, bytes: &[u8]) -> Result<(), ()> {
        let mut segment = [0; 16];
        segment[..8].copy_from_slice(&DMA.event_ring.to_le_bytes());
        segment[8..12].copy_from_slice(&16u32.to_le_bytes());
        let allowed = if self.activated {
            let word = |parameter: u64| trb_fields(parameter, 0);
            let fields = |index, parameter, command: u32| {
                let target = DMA.command_ring + u64::from(index) * 16;
                (address == target && bytes == word(parameter))
                    || (address == target + 12 && bytes == (command | 1).to_le_bytes())
            };
            match self.command_count {
                0 => fields(0u8, 0, 23 << 10),
                1 if self.enumeration.is_some() => {
                    fields(1u8, 0, 9 << 10)
                        || self.enumeration.unwrap().context_write(address, bytes)
                }
                2 if self.enumeration.is_some() => {
                    fields(2u8, INPUT, (11 << 10) | (1 << 24))
                        || (address == DMA.device_contexts + 8 && bytes == OUTPUT.to_le_bytes())
                }
                3 if self.enumeration.is_some() && !self.descriptor_sent => {
                    descriptor_write(address, bytes)
                }
                _ => false,
            }
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
        let event = matches!(bytes.len(), 4 | 12)
            && address >= DMA.event_ring
            && address
                .checked_add(bytes.len() as u64)
                .is_some_and(|end| end <= DMA.event_ring + 256);
        let enumeration = self.enumeration.is_some()
            && ((self.command_count == 3 && address == OUTPUT + 12 && bytes.len() == 4)
                || (self.descriptor_sent && address == BUFFER && bytes.len() == 18));
        if self.revoked || self.command_count == 0 || !(event || enumeration) {
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
        if self.revoked || self.command_count == 0 {
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
            || self.command_count == 0
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

pub(super) fn run<P: PciActivation>(
    platform: &mut P,
    probe: &mut dyn FnMut(&mut dyn CommandIo),
    enumerate: bool,
) where
    P::Error: core::fmt::Debug,
{
    let (before, assignment) = platform.activation_state().unwrap();
    assert_eq!(before.command & 6, 2);
    let operational = platform.read32(0).unwrap() & 0xff;
    let runtime = (platform.read32(0x18).unwrap() & !31) + 0x20;
    let doorbell = platform.read32(0x14).unwrap() & !3;
    let enumeration = enumerate.then(|| {
        let ports = (platform.read32(4).unwrap() >> 24) as u8;
        let stride = if platform.read32(0x10).unwrap() & 4 != 0 {
            64
        } else {
            32
        };
        (1..=ports)
            .find_map(|port| {
                let portsc = operational + 0x400 + u32::from(port - 1) * 0x10;
                let status = platform.read32(portsc).unwrap();
                let speed = (status >> 10) & 15;
                (status & 1 != 0 && matches!(speed, 3 | 4)).then_some(Enumeration {
                    portsc,
                    port,
                    speed,
                    stride,
                })
            })
            .expect("one disposable USB fixture is connected")
    });
    let mut broker = Command {
        platform,
        assignment,
        operational,
        runtime,
        doorbell,
        published: false,
        activated: false,
        command_count: 0,
        descriptor_sent: false,
        enumeration,
        revoked: false,
    };
    assert!(broker.activate(before.command).is_err());
    assert!(broker.write32(doorbell, 0).is_err());
    probe(&mut broker);
    assert!(broker.activated && broker.revoked);
    assert_eq!(broker.command_count, if enumerate { 3 } else { 1 });
    assert_eq!(broker.descriptor_sent, enumerate);
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
    if enumerate {
        verify_descriptor(&events, platform);
    }
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
