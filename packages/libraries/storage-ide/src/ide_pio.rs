//! Capability-bound bounded ATA PIO read, write, and flush execution.

use crate::{IdeChannelPortGrant, IdeDevice, IdeDeviceIdentity, IdePortIo};
use mrml_kernel::{Capability, CapabilityError, CapabilitySpace, ObjectId, Rights};

const READ_SECTORS: u8 = 0x20;
const READ_SECTORS_EXT: u8 = 0x24;
const WRITE_SECTORS: u8 = 0x30;
const WRITE_SECTORS_EXT: u8 = 0x34;
const CACHE_FLUSH: u8 = 0xe7;
const CACHE_FLUSH_EXT: u8 = 0xea;
const STATUS_ERROR: u8 = 1;
const STATUS_DATA_REQUEST: u8 = 1 << 3;
const STATUS_DEVICE_FAULT: u8 = 1 << 5;
const STATUS_BUSY: u8 = 1 << 7;
const POLL_LIMIT: u32 = 2000;
const MAX_TRANSFER_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdePioOperation {
    Read,
    Write,
    Flush,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdePioBuffer {
    pub capability: Capability,
    pub memory_object: ObjectId,
    pub allocation_generation: u64,
    pub bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdePioRequest {
    pub device_capability: Capability,
    pub device_object: ObjectId,
    pub identity: IdeDeviceIdentity,
    pub operation: IdePioOperation,
    pub starting_lba: u64,
    pub block_count: u32,
    pub buffer: Option<IdePioBuffer>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletedIdePio {
    pub grant: IdeChannelPortGrant,
    pub request: IdePioRequest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdePioError {
    DeviceCapability(CapabilityError),
    BufferCapability(CapabilityError),
    WrongDeviceObject,
    WrongBufferObject,
    StaleIdentity,
    InvalidBlockRange,
    InvalidBuffer,
    UnsupportedAddress,
    UnsupportedFlush,
    PortRead,
    PortWrite,
    BufferRead,
    BufferWrite,
    DeviceError,
    DeviceFault,
    Timeout,
    MissingDataRequest,
}

#[derive(Debug, Eq, PartialEq)]
pub enum IdePioFailure {
    Untouched {
        grant: IdeChannelPortGrant,
        request: IdePioRequest,
        error: IdePioError,
    },
    Quarantined {
        grant: IdeChannelPortGrant,
        request: IdePioRequest,
        error: IdePioError,
    },
}

pub trait IdePioIo: IdePortIo {
    fn read_buffer_u16(&mut self, buffer: IdePioBuffer, offset: u64) -> Result<u16, ()>;
    fn write_buffer_u16(&mut self, buffer: IdePioBuffer, offset: u64, value: u16)
        -> Result<(), ()>;
    fn write_data_u16(&mut self, port: u16, value: u16) -> Result<(), ()>;
}

pub fn execute_ide_pio<const N: usize, I: IdePioIo>(
    capabilities: &CapabilitySpace<N>,
    grant: IdeChannelPortGrant,
    request: IdePioRequest,
    io: &mut I,
) -> Result<CompletedIdePio, IdePioFailure> {
    validate(capabilities, grant, request).map_err(|error| untouched(grant, request, error))?;
    let base = grant.command.base;
    let lba48 = request.identity.lba48;
    program_task_file(base, request, lba48, io)
        .map_err(|error| quarantined(grant, request, error))?;
    let command = match (request.operation, lba48) {
        (IdePioOperation::Read, false) => READ_SECTORS,
        (IdePioOperation::Read, true) => READ_SECTORS_EXT,
        (IdePioOperation::Write, false) => WRITE_SECTORS,
        (IdePioOperation::Write, true) => WRITE_SECTORS_EXT,
        (IdePioOperation::Flush, false) => CACHE_FLUSH,
        (IdePioOperation::Flush, true) => CACHE_FLUSH_EXT,
    };
    io.write_u8(base + 7, command)
        .map_err(|_| quarantined(grant, request, IdePioError::PortWrite))?;
    if request.operation == IdePioOperation::Flush {
        poll(base, false, io).map_err(|error| quarantined(grant, request, error))?;
    } else {
        let buffer = request.buffer.unwrap();
        let words_per_block = u64::from(request.identity.logical_block_bytes / 2);
        for block in 0..u64::from(request.block_count) {
            poll(base, true, io).map_err(|error| quarantined(grant, request, error))?;
            for word in 0..words_per_block {
                let offset = (block * words_per_block + word) * 2;
                match request.operation {
                    IdePioOperation::Read => {
                        let value = io
                            .read_u16(base)
                            .map_err(|_| quarantined(grant, request, IdePioError::PortRead))?;
                        io.write_buffer_u16(buffer, offset, value)
                            .map_err(|_| quarantined(grant, request, IdePioError::BufferWrite))?;
                    }
                    IdePioOperation::Write => {
                        let value = io
                            .read_buffer_u16(buffer, offset)
                            .map_err(|_| quarantined(grant, request, IdePioError::BufferRead))?;
                        io.write_data_u16(base, value)
                            .map_err(|_| quarantined(grant, request, IdePioError::PortWrite))?;
                    }
                    IdePioOperation::Flush => unreachable!(),
                }
            }
        }
        poll(base, false, io).map_err(|error| quarantined(grant, request, error))?;
    }
    Ok(CompletedIdePio { grant, request })
}

fn validate<const N: usize>(
    capabilities: &CapabilitySpace<N>,
    grant: IdeChannelPortGrant,
    request: IdePioRequest,
) -> Result<(), IdePioError> {
    let device_rights = match request.operation {
        IdePioOperation::Read => Rights::READ,
        IdePioOperation::Write => Rights::WRITE,
        IdePioOperation::Flush => Rights::FLUSH,
    };
    let object = capabilities
        .authorize_exact(request.device_capability, device_rights)
        .map_err(IdePioError::DeviceCapability)?;
    if object != request.device_object {
        return Err(IdePioError::WrongDeviceObject);
    }
    if request.identity.controller_generation != grant.controller_generation
        || request.identity.port_grant_generation != grant.grant_generation
        || request.identity.identity_generation == 0
    {
        return Err(IdePioError::StaleIdentity);
    }
    if request.operation == IdePioOperation::Flush {
        if !request.identity.flush_supported {
            return Err(IdePioError::UnsupportedFlush);
        }
        if request.starting_lba != 0 || request.block_count != 0 || request.buffer.is_some() {
            return Err(IdePioError::InvalidBuffer);
        }
        return Ok(());
    }
    if request.block_count == 0
        || request
            .starting_lba
            .checked_add(u64::from(request.block_count))
            .is_none_or(|end| end > request.identity.block_count)
    {
        return Err(IdePioError::InvalidBlockRange);
    }
    if !request.identity.lba48
        && (request.starting_lba > 0x0fff_ffff
            || request.block_count > 256
            || request.starting_lba + u64::from(request.block_count) > 0x1000_0000)
    {
        return Err(IdePioError::UnsupportedAddress);
    }
    let bytes = u64::from(request.block_count)
        .checked_mul(u64::from(request.identity.logical_block_bytes))
        .ok_or(IdePioError::InvalidBuffer)?;
    if bytes == 0 || bytes > MAX_TRANSFER_BYTES {
        return Err(IdePioError::InvalidBuffer);
    }
    let buffer = request.buffer.ok_or(IdePioError::InvalidBuffer)?;
    if buffer.allocation_generation == 0 || buffer.bytes != bytes {
        return Err(IdePioError::InvalidBuffer);
    }
    let rights = match request.operation {
        IdePioOperation::Read => Rights::WRITE,
        IdePioOperation::Write => Rights::READ,
        IdePioOperation::Flush => unreachable!(),
    };
    let object = capabilities
        .authorize_exact(buffer.capability, rights)
        .map_err(IdePioError::BufferCapability)?;
    if object != buffer.memory_object {
        return Err(IdePioError::WrongBufferObject);
    }
    Ok(())
}

fn program_task_file<I: IdePioIo>(
    base: u16,
    request: IdePioRequest,
    lba48: bool,
    io: &mut I,
) -> Result<(), IdePioError> {
    let slave = request.identity.device == IdeDevice::Slave;
    let drive = if slave { 0xf0 } else { 0xe0 };
    let drive = if lba48 {
        drive
    } else {
        drive | ((request.starting_lba >> 24) as u8 & 0x0f)
    };
    io.write_u8(base + 6, drive)
        .map_err(|_| IdePioError::PortWrite)?;
    let count = request.block_count;
    if lba48 {
        for (port, value) in [
            (1, 0),
            (2, (count >> 8) as u8),
            (3, (request.starting_lba >> 24) as u8),
            (4, (request.starting_lba >> 32) as u8),
            (5, (request.starting_lba >> 40) as u8),
            (1, 0),
            (2, count as u8),
            (3, request.starting_lba as u8),
            (4, (request.starting_lba >> 8) as u8),
            (5, (request.starting_lba >> 16) as u8),
        ] {
            io.write_u8(base + port, value)
                .map_err(|_| IdePioError::PortWrite)?;
        }
    } else {
        for (port, value) in [
            (1, 0),
            (2, count as u8),
            (3, request.starting_lba as u8),
            (4, (request.starting_lba >> 8) as u8),
            (5, (request.starting_lba >> 16) as u8),
        ] {
            io.write_u8(base + port, value)
                .map_err(|_| IdePioError::PortWrite)?;
        }
    }
    Ok(())
}

fn poll<I: IdePioIo>(base: u16, require_drq: bool, io: &mut I) -> Result<(), IdePioError> {
    for _ in 0..POLL_LIMIT {
        let status = io.read_u8(base + 7).map_err(|_| IdePioError::PortRead)?;
        if status & STATUS_BUSY != 0 {
            io.delay_500_micros();
            continue;
        }
        if status & STATUS_DEVICE_FAULT != 0 {
            return Err(IdePioError::DeviceFault);
        }
        if status & STATUS_ERROR != 0 {
            return Err(IdePioError::DeviceError);
        }
        if require_drq && status & STATUS_DATA_REQUEST == 0 {
            return Err(IdePioError::MissingDataRequest);
        }
        return Ok(());
    }
    Err(IdePioError::Timeout)
}

const fn untouched(
    grant: IdeChannelPortGrant,
    request: IdePioRequest,
    error: IdePioError,
) -> IdePioFailure {
    IdePioFailure::Untouched {
        grant,
        request,
        error,
    }
}
const fn quarantined(
    grant: IdeChannelPortGrant,
    request: IdePioRequest,
    error: IdePioError,
) -> IdePioFailure {
    IdePioFailure::Quarantined {
        grant,
        request,
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IdeChannel, IdePortRange};

    struct Io {
        status: u8,
        task_writes: [Option<(u16, u8)>; 16],
        task_count: usize,
        device_words: [u16; 512],
        buffer_words: [u16; 512],
        reads: usize,
        writes: usize,
        fail_after: Option<usize>,
    }
    impl IdePortIo for Io {
        fn read_u8(&mut self, port: u16) -> Result<u8, ()> {
            if port == 0x1f7 {
                Ok(self.status)
            } else {
                Err(())
            }
        }
        fn read_u16(&mut self, port: u16) -> Result<u16, ()> {
            if port != 0x1f0 || self.fail_after == Some(self.reads) {
                return Err(());
            }
            let value = self.device_words[self.reads];
            self.reads += 1;
            Ok(value)
        }
        fn write_u8(&mut self, port: u16, value: u8) -> Result<(), ()> {
            *self.task_writes.get_mut(self.task_count).ok_or(())? = Some((port, value));
            self.task_count += 1;
            Ok(())
        }
        fn delay_500_micros(&mut self) {}
    }
    impl IdePioIo for Io {
        fn read_buffer_u16(&mut self, _: IdePioBuffer, offset: u64) -> Result<u16, ()> {
            self.buffer_words
                .get(offset as usize / 2)
                .copied()
                .ok_or(())
        }
        fn write_buffer_u16(&mut self, _: IdePioBuffer, offset: u64, value: u16) -> Result<(), ()> {
            *self.buffer_words.get_mut(offset as usize / 2).ok_or(())? = value;
            Ok(())
        }
        fn write_data_u16(&mut self, port: u16, value: u16) -> Result<(), ()> {
            if port != 0x1f0 {
                return Err(());
            }
            *self.device_words.get_mut(self.writes).ok_or(())? = value;
            self.writes += 1;
            Ok(())
        }
    }
    fn io(status: u8) -> Io {
        Io {
            status,
            task_writes: [None; 16],
            task_count: 0,
            device_words: core::array::from_fn(|i| i as u16),
            buffer_words: [0; 512],
            reads: 0,
            writes: 0,
            fail_after: None,
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
            bus_master: None,
        }
    }
    fn identity() -> IdeDeviceIdentity {
        IdeDeviceIdentity {
            controller_generation: 4,
            port_grant_generation: 7,
            device: IdeDevice::Master,
            identity_generation: 11,
            serial: [b' '; 20],
            firmware: [b' '; 8],
            model: [b' '; 40],
            block_count: 1_000_000_000,
            logical_block_bytes: 512,
            maximum_transfer_blocks: 2048,
            lba48: true,
            dma_supported: true,
            flush_supported: true,
        }
    }

    fn make_request(operation: IdePioOperation, rights: Rights) -> (CapabilitySpace<2>, IdePioRequest) {
        let mut caps = CapabilitySpace::new();
        let device_capability = caps.insert(ObjectId(20), rights).unwrap();
        let buffer = if operation == IdePioOperation::Flush {
            None
        } else {
            let buffer_rights = if operation == IdePioOperation::Read {
                Rights::WRITE
            } else {
                Rights::READ
            };
            let capability = caps.insert(ObjectId(21), buffer_rights).unwrap();
            Some(IdePioBuffer {
                capability,
                memory_object: ObjectId(21),
                allocation_generation: 3,
                bytes: 1024,
            })
        };
        (
            caps,
            IdePioRequest {
                device_capability,
                device_object: ObjectId(20),
                identity: identity(),
                operation,
                starting_lba: if operation == IdePioOperation::Flush {
                    0
                } else {
                    0x1234_5678
                },
                block_count: if operation == IdePioOperation::Flush {
                    0
                } else {
                    2
                },
                buffer,
            },
        )
    }

    #[test]
    fn reads_two_lba48_blocks_through_exact_writable_buffer() {
        let (caps, request) = make_request(IdePioOperation::Read, Rights::READ);
        let mut ports = io(STATUS_DATA_REQUEST);
        execute_ide_pio(&caps, grant(), request, &mut ports).unwrap();
        assert_eq!(ports.task_writes[0], Some((0x1f6, 0xe0)));
        assert_eq!(ports.task_writes[2], Some((0x1f2, 0)));
        assert_eq!(ports.task_writes[7], Some((0x1f2, 2)));
        assert_eq!(ports.task_writes[11], Some((0x1f7, READ_SECTORS_EXT)));
        assert_eq!(ports.reads, 512);
        assert_eq!(ports.buffer_words[511], 511);
    }

    #[test]
    fn writes_blocks_and_flushes_with_separate_device_rights() {
        let (caps, request) = make_request(IdePioOperation::Write, Rights::WRITE);
        let mut ports = io(STATUS_DATA_REQUEST);
        ports.buffer_words = core::array::from_fn(|i| (1000 + i) as u16);
        execute_ide_pio(&caps, grant(), request, &mut ports).unwrap();
        assert_eq!(ports.task_writes[11], Some((0x1f7, WRITE_SECTORS_EXT)));
        assert_eq!(ports.writes, 512);
        assert_eq!(ports.device_words[511], 1511);
        let (caps, request) = make_request(IdePioOperation::Flush, Rights::FLUSH);
        let mut ports = io(0);
        execute_ide_pio(&caps, grant(), request, &mut ports).unwrap();
        assert_eq!(ports.task_writes[11], Some((0x1f7, CACHE_FLUSH_EXT)));
    }

    #[test]
    fn rights_ranges_buffers_and_partial_transfers_fail_closed() {
        let (caps, mut request) = make_request(IdePioOperation::Read, Rights::READ);
        request.starting_lba = request.identity.block_count;
        assert!(matches!(
            execute_ide_pio(&caps, grant(), request, &mut io(STATUS_DATA_REQUEST)),
            Err(IdePioFailure::Untouched {
                error: IdePioError::InvalidBlockRange,
                ..
            })
        ));
        let (caps, mut request) = make_request(IdePioOperation::Read, Rights::READ);
        request.buffer.as_mut().unwrap().bytes = 512;
        assert!(matches!(
            execute_ide_pio(&caps, grant(), request, &mut io(STATUS_DATA_REQUEST)),
            Err(IdePioFailure::Untouched {
                error: IdePioError::InvalidBuffer,
                ..
            })
        ));
        let (caps, request) = make_request(IdePioOperation::Read, Rights::READ);
        let mut ports = io(STATUS_DATA_REQUEST);
        ports.fail_after = Some(10);
        assert!(matches!(
            execute_ide_pio(&caps, grant(), request, &mut ports),
            Err(IdePioFailure::Quarantined {
                error: IdePioError::PortRead,
                ..
            })
        ));
    }
}
