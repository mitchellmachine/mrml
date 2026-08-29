//! Bounded ATA device selection and IDENTIFY parsing for one granted channel.

use crate::IdeChannelPortGrant;

const ATA_IDENTIFY: u8 = 0xec;
const STATUS_ERROR: u8 = 1;
const STATUS_DATA_REQUEST: u8 = 1 << 3;
const STATUS_DEVICE_FAULT: u8 = 1 << 5;
const STATUS_BUSY: u8 = 1 << 7;
const POLL_LIMIT: u32 = 2000;
const IDENTIFY_WORDS: usize = 256;
const MAX_TRANSFER_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdeDevice {
    Master,
    Slave,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdeDeviceIdentity {
    pub controller_generation: u64,
    pub port_grant_generation: u64,
    pub device: IdeDevice,
    pub identity_generation: u64,
    pub serial: [u8; 20],
    pub firmware: [u8; 8],
    pub model: [u8; 40],
    pub block_count: u64,
    pub logical_block_bytes: u32,
    pub maximum_transfer_blocks: u32,
    pub lba48: bool,
    pub dma_supported: bool,
    pub flush_supported: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdeIdentifyError {
    InvalidGeneration,
    PortRead,
    PortWrite,
    NoDevice,
    DeviceError,
    DeviceFault,
    Timeout,
    MissingDataRequest,
    InvalidIdentity,
    UnsupportedBlockSize,
    CapacityOverflow,
}

#[derive(Debug, Eq, PartialEq)]
pub enum IdeIdentifyFailure {
    Untouched {
        grant: IdeChannelPortGrant,
        error: IdeIdentifyError,
    },
    Quarantined {
        grant: IdeChannelPortGrant,
        error: IdeIdentifyError,
    },
}

pub trait IdePortIo {
    fn read_u8(&mut self, port: u16) -> Result<u8, ()>;
    fn read_u16(&mut self, port: u16) -> Result<u16, ()>;
    fn write_u8(&mut self, port: u16, value: u8) -> Result<(), ()>;
    fn delay_500_micros(&mut self);
}

pub fn identify_ide_device<I: IdePortIo>(
    grant: IdeChannelPortGrant,
    device: IdeDevice,
    identity_generation: u64,
    io: &mut I,
) -> Result<IdeDeviceIdentity, IdeIdentifyFailure> {
    if identity_generation == 0 || grant.controller_generation == 0 || grant.grant_generation == 0 {
        return Err(untouched(grant, IdeIdentifyError::InvalidGeneration));
    }
    let base = grant.command.base;
    let selected = match device {
        IdeDevice::Master => 0xa0,
        IdeDevice::Slave => 0xb0,
    };
    io.write_u8(base + 6, selected)
        .map_err(|_| untouched(grant, IdeIdentifyError::PortWrite))?;
    for _ in 0..4 {
        io.read_u8(grant.control.base)
            .map_err(|_| quarantined(grant, IdeIdentifyError::PortRead))?;
    }
    for port in [base + 2, base + 3, base + 4, base + 5] {
        io.write_u8(port, 0)
            .map_err(|_| quarantined(grant, IdeIdentifyError::PortWrite))?;
    }
    io.write_u8(base + 7, ATA_IDENTIFY)
        .map_err(|_| quarantined(grant, IdeIdentifyError::PortWrite))?;
    let initial = io
        .read_u8(base + 7)
        .map_err(|_| quarantined(grant, IdeIdentifyError::PortRead))?;
    if initial == 0 {
        return Err(untouched(grant, IdeIdentifyError::NoDevice));
    }
    let mut status = initial;
    for _ in 0..POLL_LIMIT {
        if status & STATUS_BUSY == 0 {
            break;
        }
        io.delay_500_micros();
        status = io
            .read_u8(base + 7)
            .map_err(|_| quarantined(grant, IdeIdentifyError::PortRead))?;
    }
    if status & STATUS_BUSY != 0 {
        return Err(quarantined(grant, IdeIdentifyError::Timeout));
    }
    if status & STATUS_DEVICE_FAULT != 0 {
        return Err(quarantined(grant, IdeIdentifyError::DeviceFault));
    }
    if status & STATUS_ERROR != 0 {
        return Err(untouched(grant, IdeIdentifyError::DeviceError));
    }
    if status & STATUS_DATA_REQUEST == 0 {
        return Err(quarantined(grant, IdeIdentifyError::MissingDataRequest));
    }
    let mut words = [0_u16; IDENTIFY_WORDS];
    for word in &mut words {
        *word = io
            .read_u16(base)
            .map_err(|_| quarantined(grant, IdeIdentifyError::PortRead))?;
    }
    parse_identity(grant, device, identity_generation, words)
}

fn parse_identity(
    grant: IdeChannelPortGrant,
    device: IdeDevice,
    identity_generation: u64,
    words: [u16; IDENTIFY_WORDS],
) -> Result<IdeDeviceIdentity, IdeIdentifyFailure> {
    if words[0] & 0x8000 != 0 || words[49] & (1 << 9) == 0 {
        return Err(untouched(grant, IdeIdentifyError::InvalidIdentity));
    }
    let lba48 = words[83] & (1 << 10) != 0;
    let block_count = if lba48 {
        u64::from(words[100])
            | (u64::from(words[101]) << 16)
            | (u64::from(words[102]) << 32)
            | (u64::from(words[103]) << 48)
    } else {
        u64::from(words[60]) | (u64::from(words[61]) << 16)
    };
    if block_count == 0 {
        return Err(untouched(grant, IdeIdentifyError::InvalidIdentity));
    }
    let logical_block_bytes = if words[106] & 0xc000 == 0x4000 && words[106] & (1 << 12) != 0 {
        let words_per_block = u32::from(words[117]) | (u32::from(words[118]) << 16);
        words_per_block
            .checked_mul(2)
            .ok_or_else(|| untouched(grant, IdeIdentifyError::CapacityOverflow))?
    } else {
        512
    };
    if !(512..=65536).contains(&logical_block_bytes) || !logical_block_bytes.is_power_of_two() {
        return Err(untouched(grant, IdeIdentifyError::UnsupportedBlockSize));
    }
    block_count
        .checked_mul(u64::from(logical_block_bytes))
        .ok_or_else(|| untouched(grant, IdeIdentifyError::CapacityOverflow))?;
    let serial = text::<20>(&words[10..20])
        .ok_or_else(|| untouched(grant, IdeIdentifyError::InvalidIdentity))?;
    let firmware = text::<8>(&words[23..27])
        .ok_or_else(|| untouched(grant, IdeIdentifyError::InvalidIdentity))?;
    let model = text::<40>(&words[27..47])
        .ok_or_else(|| untouched(grant, IdeIdentifyError::InvalidIdentity))?;
    Ok(IdeDeviceIdentity {
        controller_generation: grant.controller_generation,
        port_grant_generation: grant.grant_generation,
        device,
        identity_generation,
        serial,
        firmware,
        model,
        block_count,
        logical_block_bytes,
        maximum_transfer_blocks: u32::try_from(MAX_TRANSFER_BYTES / u64::from(logical_block_bytes))
            .unwrap(),
        lba48,
        dma_supported: words[49] & (1 << 8) != 0,
        flush_supported: words[83] & (1 << 12) != 0,
    })
}

fn text<const N: usize>(words: &[u16]) -> Option<[u8; N]> {
    if words.len() * 2 != N {
        return None;
    }
    let mut output = [b' '; N];
    for (index, word) in words.iter().enumerate() {
        output[index * 2] = (word >> 8) as u8;
        output[index * 2 + 1] = *word as u8;
    }
    let end = output
        .iter()
        .rposition(|byte| *byte != b' ')
        .map_or(0, |index| index + 1);
    if end == 0
        || output[..end]
            .iter()
            .any(|byte| !(0x20..=0x7e).contains(byte))
    {
        return None;
    }
    Some(output)
}

const fn untouched(grant: IdeChannelPortGrant, error: IdeIdentifyError) -> IdeIdentifyFailure {
    IdeIdentifyFailure::Untouched { grant, error }
}
const fn quarantined(grant: IdeChannelPortGrant, error: IdeIdentifyError) -> IdeIdentifyFailure {
    IdeIdentifyFailure::Quarantined { grant, error }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IdeChannel, IdePortRange};
    use mrml_kernel::ObjectId;

    struct Ports {
        statuses: [u8; 3],
        status_index: usize,
        words: [u16; IDENTIFY_WORDS],
        word_index: usize,
        writes: [Option<(u16, u8)>; 6],
        write_index: usize,
        alt_reads: usize,
        delays: u32,
        fail_word: Option<usize>,
    }

    impl IdePortIo for Ports {
        fn read_u8(&mut self, port: u16) -> Result<u8, ()> {
            if port == 0x3f6 {
                self.alt_reads += 1;
                return Ok(0);
            }
            if port != 0x1f7 {
                return Err(());
            }
            let value = self.statuses[self.status_index.min(2)];
            self.status_index += 1;
            Ok(value)
        }
        fn read_u16(&mut self, port: u16) -> Result<u16, ()> {
            if port != 0x1f0 || self.fail_word == Some(self.word_index) {
                return Err(());
            }
            let value = self.words[self.word_index];
            self.word_index += 1;
            Ok(value)
        }
        fn write_u8(&mut self, port: u16, value: u8) -> Result<(), ()> {
            *self.writes.get_mut(self.write_index).ok_or(())? = Some((port, value));
            self.write_index += 1;
            Ok(())
        }
        fn delay_500_micros(&mut self) {
            self.delays += 1;
        }
    }

    fn grant() -> IdeChannelPortGrant {
        IdeChannelPortGrant {
            controller_generation: 4,
            grant_generation: 7,
            port_object: ObjectId(9),
            channel: IdeChannel::Primary,
            command: IdePortRange {
                base: 0x1f0,
                bytes: 8,
            },
            control: IdePortRange {
                base: 0x3f6,
                bytes: 1,
            },
            bus_master: Some(IdePortRange {
                base: 0x2400,
                bytes: 8,
            }),
        }
    }

    fn encode(words: &mut [u16], text: &[u8]) {
        for (word, pair) in words.iter_mut().zip(text.chunks_exact(2)) {
            *word = u16::from(pair[0]) << 8 | u16::from(pair[1]);
        }
    }

    fn ports() -> Ports {
        let mut words = [0_u16; IDENTIFY_WORDS];
        words[49] = (1 << 9) | (1 << 8);
        words[83] = (1 << 10) | (1 << 12);
        words[100] = 0x5678;
        words[101] = 0x1234;
        encode(&mut words[10..20], b"SERIAL-0001         ");
        encode(&mut words[23..27], b"FW1     ");
        encode(
            &mut words[27..47],
            b"MRML CLASSIC IDE DEVICE                 ",
        );
        Ports {
            statuses: [STATUS_BUSY, STATUS_DATA_REQUEST, STATUS_DATA_REQUEST],
            status_index: 0,
            words,
            word_index: 0,
            writes: [None; 6],
            write_index: 0,
            alt_reads: 0,
            delays: 0,
            fail_word: None,
        }
    }

    #[test]
    fn selects_waits_reads_and_parses_lba48_identity() {
        let mut io = ports();
        let identity = identify_ide_device(grant(), IdeDevice::Slave, 11, &mut io).unwrap();
        assert_eq!(io.writes[0], Some((0x1f6, 0xb0)));
        assert_eq!(io.writes[5], Some((0x1f7, ATA_IDENTIFY)));
        assert_eq!(io.alt_reads, 4);
        assert_eq!(io.delays, 1);
        assert_eq!(io.word_index, 256);
        assert_eq!(identity.block_count, 0x1234_5678);
        assert_eq!(identity.logical_block_bytes, 512);
        assert_eq!(identity.maximum_transfer_blocks, 2048);
        assert!(identity.lba48 && identity.dma_supported && identity.flush_supported);
    }

    #[test]
    fn no_device_is_recoverable_but_timeout_or_partial_data_is_quarantined() {
        let mut io = ports();
        io.statuses = [0; 3];
        assert!(matches!(
            identify_ide_device(grant(), IdeDevice::Master, 1, &mut io),
            Err(IdeIdentifyFailure::Untouched {
                error: IdeIdentifyError::NoDevice,
                ..
            })
        ));
        let mut io = ports();
        io.statuses = [STATUS_BUSY; 3];
        assert!(matches!(
            identify_ide_device(grant(), IdeDevice::Master, 1, &mut io),
            Err(IdeIdentifyFailure::Quarantined {
                error: IdeIdentifyError::Timeout,
                ..
            })
        ));
        let mut io = ports();
        io.fail_word = Some(10);
        assert!(matches!(
            identify_ide_device(grant(), IdeDevice::Master, 1, &mut io),
            Err(IdeIdentifyFailure::Quarantined {
                error: IdeIdentifyError::PortRead,
                ..
            })
        ));
    }

    #[test]
    fn hostile_identity_capacity_and_block_geometry_fail_closed() {
        let mut io = ports();
        io.words[49] = 0;
        assert!(matches!(
            identify_ide_device(grant(), IdeDevice::Master, 1, &mut io),
            Err(IdeIdentifyFailure::Untouched {
                error: IdeIdentifyError::InvalidIdentity,
                ..
            })
        ));
        let mut io = ports();
        io.words[106] = 0x5000;
        io.words[117] = 3;
        assert!(matches!(
            identify_ide_device(grant(), IdeDevice::Master, 1, &mut io),
            Err(IdeIdentifyFailure::Untouched {
                error: IdeIdentifyError::UnsupportedBlockSize,
                ..
            })
        ));
    }
}
