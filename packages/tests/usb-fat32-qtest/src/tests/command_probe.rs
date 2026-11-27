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
const BULK_IN: u64 = 0x10_5000;
const BULK_OUT: u64 = 0x10_6000;
const BULK_BUFFER: u64 = 0x10_7000;
mod read_only;
use read_only::ReadOnly;

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

fn descriptor_write(address: u64, bytes: &[u8], base: u64, kind: u8, len: u16) -> bool {
    let [lo, hi] = len.to_le_bytes();
    let setup = u64::from_le_bytes([0x80, 6, 0, kind, 0, 0, lo, hi]);
    let stages = [
        (base, setup, 8, (2u32 << 10) | (3 << 16) | (1 << 6) | 1),
        (
            base + 16,
            BUFFER,
            u32::from(len),
            (3u32 << 10) | (1 << 16) | (1 << 2) | 1,
        ),
        (base + 32, 0, 0, (4u32 << 10) | (1 << 5) | 1),
    ];
    stages
        .into_iter()
        .any(|(base, parameter, length, control)| {
            (address == base && bytes == trb_fields(parameter, length))
                || (address == base + 12 && bytes == control.to_le_bytes())
        })
}

fn verify_descriptor<P: Platform>(events: &[u8], platform: &mut P, level: u8, configuration: &[u8])
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
    if level >= 2 {
        check(32, EP0 + 80, 1, 1);
        check(32, EP0 + 128, 1, 1);
        check(33, DMA.command_ring + 48, 1, 0);
        check(32, EP0 + 160, 1, 1);
        let mut observed = vec![0; configuration.len()];
        platform.dma_read(BUFFER, &mut observed).unwrap();
        assert_eq!(observed, configuration);
        assert!(mrml_storage_usb::find_bulk_interface(&observed).is_ok());
        for address in [BULK_IN, BULK_OUT] {
            let mut ring = [1; 256];
            platform.dma_read(address, &mut ring).unwrap();
            if level == 2 {
                assert_eq!(ring, [0; 256]);
            }
        }
    } else {
        let mut descriptor = [0; 18];
        platform.dma_read(BUFFER, &mut descriptor).unwrap();
        assert_eq!(&descriptor[..2], &[18, 1]);
    }
    for (address, length) in [
        (INPUT, 33 * 64),
        (OUTPUT, 32 * 64),
        (EP0, 256),
        (BUFFER, 256),
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
    control_count: u8,
    level: u8,
    config_len: usize,
    configuration: [u8; 256],
    bulk: ReadOnly,
    enumeration: Option<Enumeration>,
    revoked: bool,
}

impl<P: PciActivation> Command<'_, P> {
    fn commands(&self) -> u8 {
        match self.level {
            0 => 1,
            1 => 3,
            _ => 4,
        }
    }

    fn bulk_context(&mut self, address: u64, bytes: &[u8]) -> bool {
        let Some(e) = self.enumeration else {
            return false;
        };
        if address != INPUT || bytes.len() != 33 * e.stride {
            return false;
        }
        let Ok(interface) =
            mrml_storage_usb::find_bulk_interface(&self.configuration[..self.config_len])
        else {
            return false;
        };
        let endpoints = [
            (interface.bulk_in & 15) * 2 + 1,
            (interface.bulk_out & 15) * 2,
        ];
        let mut expected = [0; 33 * 64];
        let flags = 1u32 | (1 << endpoints[0]) | (1 << endpoints[1]);
        expected[4..8].copy_from_slice(&flags.to_le_bytes());
        let slot = e.stride;
        if self
            .platform
            .dma_read(OUTPUT, &mut expected[slot..slot + 12])
            .is_err()
        {
            return false;
        }
        let context = u32::from_le_bytes(expected[slot..slot + 4].try_into().unwrap());
        let entries = u32::from(endpoints[0].max(endpoints[1]));
        expected[slot..slot + 4]
            .copy_from_slice(&((context & 0x07ff_ffff) | (entries << 27)).to_le_bytes());
        for (dci, packet, burst, kind, ring) in [
            (
                endpoints[0],
                interface.packet_in,
                interface.burst_in,
                6,
                BULK_IN,
            ),
            (
                endpoints[1],
                interface.packet_out,
                interface.burst_out,
                2,
                BULK_OUT,
            ),
        ] {
            let offset = (usize::from(dci) + 1) * e.stride;
            let control =
                (u32::from(packet) << 16) | (u32::from(burst.unwrap_or(0)) << 8) | (kind << 3) | 6;
            expected[offset + 4..offset + 8].copy_from_slice(&control.to_le_bytes());
            expected[offset + 8..offset + 16].copy_from_slice(&(ring | 1).to_le_bytes());
            expected[offset + 16..offset + 20].copy_from_slice(&512u32.to_le_bytes());
        }
        bytes == &expected[..bytes.len()]
    }

    fn control_write(&mut self, address: u64, bytes: &[u8]) -> bool {
        match (self.control_count, self.command_count, self.level) {
            (0, 3, 1..=4) => descriptor_write(address, bytes, EP0, 1, 18),
            (1, 3, 2..=4) => descriptor_write(address, bytes, EP0 + 48, 2, 9),
            (2, 3, 2..=4) if self.config_len != 0 => {
                descriptor_write(address, bytes, EP0 + 96, 2, self.config_len as u16)
            }
            (3, 4, 2..=4) => {
                let Ok(interface) =
                    mrml_storage_usb::find_bulk_interface(&self.configuration[..self.config_len])
                else {
                    return false;
                };
                let setup = u64::from_le_bytes([0, 9, interface.configuration, 0, 0, 0, 0, 0]);
                [
                    (EP0 + 144, setup, 8, (2u32 << 10) | (1 << 6) | 1),
                    (EP0 + 160, 0, 0, (4u32 << 10) | (1 << 16) | (1 << 5) | 1),
                ]
                .into_iter()
                .any(|(base, parameter, len, control)| {
                    (address == base && bytes == trb_fields(parameter, len))
                        || (address == base + 12 && bytes == control.to_le_bytes())
                })
            }
            _ => false,
        }
    }
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
        let bulk_doorbell =
            offset == self.doorbell + 4 && self.level >= 3 && self.control_count == 4;
        let allowed = if bulk_doorbell {
            self.bulk
                .dci(&self.configuration[..self.config_len])
                .is_some_and(|dci| u32::from(dci) == value)
                && self.bulk.staged()
        } else if offset == op {
            matches!(value, 0 | 2) && !self.activated || matches!(value, 0 | 1) && self.activated
        } else if !self.activated {
            false
        } else if offset == self.doorbell {
            value == 0
                && self.command_count < self.commands()
                && (self.command_count != 3 || self.control_count == 3)
        } else if offset == self.doorbell + 4 {
            value == 1
                && matches!(
                    (self.control_count, self.command_count, self.level),
                    (0, 3, 1..=4) | (1 | 2, 3, 2..=4) | (3, 4, 2..=4)
                )
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
                        || (self.level >= 3 && value == event | 8)
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
        } else if bulk_doorbell {
            self.bulk.ring();
        } else if offset == self.doorbell + 4 {
            self.control_count += 1;
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
                3 if self.level >= 2 && self.control_count == 3 => {
                    fields(3u8, INPUT, (12 << 10) | (1 << 24))
                        || ([BULK_IN, BULK_OUT].contains(&address) && bytes == [0; 256])
                        || self.bulk_context(address, bytes)
                }
                4 if self.level >= 3 && self.control_count == 4 => {
                    if !self.bulk.started() {
                        let mut events = [0; 256];
                        self.platform
                            .dma_read(DMA.event_ring, &mut events)
                            .map_err(|_| ())?;
                        self.bulk.start(events);
                    }
                    self.bulk.allow_write(address, bytes)
                }
                3 | 4 => self.control_write(address, bytes),
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
                || (self.level >= 2
                    && self.control_count == 3
                    && address == OUTPUT
                    && bytes.len() == 12)
                || (address == BUFFER
                    && match self.control_count {
                        1 => bytes.len() == 18,
                        2 => bytes.len() == 9,
                        3 => self.config_len != 0 && bytes.len() == self.config_len,
                        _ => false,
                    }));
        let bulk_read =
            self.level >= 3 && address == BULK_BUFFER && self.bulk.in_length() == Some(bytes.len());
        if self.revoked || self.command_count == 0 || !(event || enumeration || bulk_read) {
            return Err(());
        }
        self.platform.dma_read(address, bytes).map_err(|_| ())?;
        if bulk_read {
            self.bulk.receive(bytes)?;
        }
        if self.level >= 2 && address == BUFFER {
            if self.control_count == 2 {
                let len = usize::from(u16::from_le_bytes([bytes[2], bytes[3]]));
                if bytes[..2] != [9, 2] || !(9..=256).contains(&len) {
                    return Err(());
                }
                self.config_len = len;
            } else if self.control_count == 3 {
                mrml_storage_usb::find_bulk_interface(bytes).map_err(|_| ())?;
                self.configuration[..bytes.len()].copy_from_slice(bytes);
            }
        }
        Ok(())
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
    level: u8,
) where
    P::Error: core::fmt::Debug,
{
    let (before, assignment) = platform.activation_state().unwrap();
    assert_eq!(before.command & 6, 2);
    let operational = platform.read32(0).unwrap() & 0xff;
    let runtime = (platform.read32(0x18).unwrap() & !31) + 0x20;
    let doorbell = platform.read32(0x14).unwrap() & !3;
    let enumeration = (level != 0).then(|| {
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
        control_count: 0,
        level,
        config_len: 0,
        configuration: [0; 256],
        bulk: ReadOnly::new(level == 4),
        enumeration,
        revoked: false,
    };
    assert!(broker.activate(before.command).is_err());
    assert!(broker.write32(doorbell, 0).is_err());
    probe(&mut broker);
    assert!(broker.activated && broker.revoked);
    assert_eq!(broker.command_count, broker.commands());
    assert_eq!(broker.control_count, [0, 1, 4, 4, 4][usize::from(level)]);
    assert!(broker.read32(0).is_err());
    assert!(broker.activate(before.command).is_err());
    let configuration = broker.configuration[..broker.config_len].to_vec();
    let pre_bulk_events = broker.bulk.events;
    assert!(level < 3 || broker.bulk.complete());
    let (after, same) = platform.activation_state().unwrap();
    assert_eq!(same, assignment);
    assert_eq!(after.command & 6, 0);
    let mut events = [0; 256];
    if let Some(saved) = pre_bulk_events {
        events = saved;
    } else {
        platform.dma_read(DMA.event_ring, &mut events).unwrap();
    }
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
    if level != 0 {
        verify_descriptor(&events, platform, level, &configuration);
    }
    if level >= 3 {
        let mut data = [0; 512];
        for (address, length) in [(BULK_IN, 256), (BULK_OUT, 256), (BULK_BUFFER, 512)] {
            platform.dma_write(address, &[0; 512][..length]).unwrap();
            platform.dma_read(address, &mut data[..length]).unwrap();
            assert_eq!(data[..length], [0; 512][..length]);
        }
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
