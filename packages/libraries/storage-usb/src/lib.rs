#![no_std]

//! Single-LUN USB Mass Storage Bulk-Only Transport for 512-byte disks.
//! Controller discovery, DMA, endpoint recovery and device ownership belong
//! below this layer. A session never retries an uncertain write.

pub mod xhci;

pub const SECTOR_BYTES: usize = 512;
const CBW_BYTES: usize = 31;
const CSW_BYTES: usize = 13;
const CBW_SIGNATURE: [u8; 4] = *b"USBC";
const CSW_SIGNATURE: [u8; 4] = *b"USBS";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BulkInterface {
    pub configuration: u8,
    pub interface: u8,
    pub bulk_in: u8,
    pub bulk_out: u8,
    pub packet_in: u16,
    pub packet_out: u16,
    pub burst_in: Option<u8>,
    pub burst_out: Option<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorError {
    Malformed,
    Unsupported,
    Ambiguous,
}

/// Selects exactly one default-alternate SCSI transparent/BOT interface.
/// This identifies endpoints; it does not configure or grant device access.
pub fn find_bulk_interface(bytes: &[u8]) -> Result<BulkInterface, DescriptorError> {
    if !(9..=4096).contains(&bytes.len())
        || bytes[..2] != [9, 2]
        || usize::from(u16::from_le_bytes([bytes[2], bytes[3]])) != bytes.len()
        || bytes[5] == 0
    {
        return Err(DescriptorError::Malformed);
    }
    let mut remaining = &bytes[9..];
    let mut interface = None;
    let mut endpoints = [0; 2];
    let mut packets = [0; 2];
    let mut bursts = [None; 2];
    let mut previous_endpoint = None;
    let mut selected = None;
    loop {
        let next = if remaining.is_empty() {
            None
        } else {
            if remaining.len() < 2 || remaining[0] < 2 {
                return Err(DescriptorError::Malformed);
            }
            let length = usize::from(remaining[0]);
            let (descriptor, rest) = remaining
                .split_at_checked(length)
                .ok_or(DescriptorError::Malformed)?;
            remaining = rest;
            Some(descriptor)
        };
        if next.is_none_or(|descriptor| descriptor[1] == 4) {
            if let Some(number) = interface.take() {
                if endpoints.contains(&0) {
                    return Err(DescriptorError::Malformed);
                }
                if selected.is_some() {
                    return Err(DescriptorError::Ambiguous);
                }
                selected = Some(BulkInterface {
                    configuration: bytes[5],
                    interface: number,
                    bulk_in: endpoints[0],
                    bulk_out: endpoints[1],
                    packet_in: packets[0],
                    packet_out: packets[1],
                    burst_in: bursts[0],
                    burst_out: bursts[1],
                });
            }
            endpoints = [0; 2];
            packets = [0; 2];
            bursts = [None; 2];
        }
        let Some(descriptor) = next else { break };
        let companion_direction = previous_endpoint.take();
        match descriptor[1] {
            2 => return Err(DescriptorError::Malformed),
            4 => {
                if descriptor.len() < 9 {
                    return Err(DescriptorError::Malformed);
                }
                if descriptor[3] == 0 && descriptor[5..8] == [8, 6, 0x50] {
                    if descriptor[4] != 2 {
                        return Err(DescriptorError::Unsupported);
                    }
                    interface = Some(descriptor[2]);
                }
            }
            5 if interface.is_some() => {
                if descriptor.len() < 7 {
                    return Err(DescriptorError::Malformed);
                }
                let address = descriptor[2];
                let packet = u16::from_le_bytes([descriptor[4], descriptor[5]]);
                if descriptor[3] != 2
                    || address & 0x70 != 0
                    || address & 0x0f == 0
                    || !matches!(packet, 8 | 16 | 32 | 64 | 512 | 1024)
                {
                    return Err(DescriptorError::Unsupported);
                }
                let direction = usize::from(address & 0x80 == 0);
                let endpoint = &mut endpoints[direction];
                if *endpoint != 0 {
                    return Err(DescriptorError::Ambiguous);
                }
                *endpoint = address;
                packets[direction] = packet;
                previous_endpoint = Some(direction);
            }
            48 if interface.is_some() => {
                let direction = companion_direction.ok_or(DescriptorError::Malformed)?;
                if descriptor.len() != 6 || descriptor[2] > 15 || descriptor[3..6] != [0; 3] {
                    return Err(DescriptorError::Unsupported);
                }
                bursts[direction] = Some(descriptor[2]);
            }
            _ => {}
        }
    }
    selected.ok_or(DescriptorError::Unsupported)
}

/// A configured, exclusively held BOT interface pinned to one device generation.
/// Each operation must complete or time out before returning, and must reject
/// stale/removed device generations. A caller must reset and re-admit hardware
/// separately before creating a new session after an uncertain transaction.
pub trait BulkTransport {
    type Error;

    fn bulk_out(&mut self, bytes: &[u8]) -> Result<usize, Self::Error>;
    fn bulk_in(&mut self, bytes: &mut [u8]) -> Result<usize, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error<E> {
    Transport(E),
    ShortTransfer,
    InvalidStatus,
    CommandFailed,
    PhaseError,
    UnsupportedCapacity,
    OutOfRange,
    ReadbackMismatch,
    Faulted,
}

enum Data<'a> {
    None,
    In(&'a mut [u8]),
    Out(&'a [u8]),
}

/// A bounded transport session. One sector per read or write; LUN zero only.
pub struct UsbDisk<T: BulkTransport> {
    endpoint: T,
    next_tag: u32,
    sectors: u64,
    faulted: bool,
}

impl<T: BulkTransport> UsbDisk<T> {
    /// Reads capacity and rejects disks requiring READ CAPACITY(16) or a
    /// different logical sector size. The controller must already have
    /// admitted interface class/subclass/protocol and both bulk endpoints.
    pub fn probe(endpoint: T) -> Result<Self, Error<T::Error>> {
        let mut disk = Self {
            endpoint,
            next_tag: 1,
            sectors: 0,
            faulted: false,
        };
        let mut capacity = [0; 8];
        const READ_CAPACITY: [u8; 10] = [0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        match disk.command(READ_CAPACITY, Data::In(&mut capacity)) {
            Ok(()) => {}
            Err(Error::CommandFailed) => {
                // An exact CSW reported a SCSI failure during read-only probe.
                // Clear only a reset/power-on unit attention, never a write
                // failure or a transport ambiguity. One sense and one retry.
                disk.faulted = false;
                let mut sense = [0; 18];
                disk.command([3, 0, 0, 0, 18, 0, 0, 0, 0, 0], Data::In(&mut sense))?;
                if !matches!(sense[0] & 0x7f, 0x70 | 0x71)
                    || sense[2] & 0x0f != 6
                    || sense[7] < 6
                    || sense[12] != 0x29
                {
                    return Err(Error::CommandFailed);
                }
                disk.command(READ_CAPACITY, Data::In(&mut capacity))?;
            }
            Err(error) => return Err(error),
        }
        let last = u32::from_be_bytes(capacity[..4].try_into().unwrap());
        let block_size = u32::from_be_bytes(capacity[4..].try_into().unwrap());
        if last == u32::MAX || block_size != SECTOR_BYTES as u32 {
            return Err(Error::UnsupportedCapacity);
        }
        disk.sectors = u64::from(last) + 1;
        Ok(disk)
    }

    pub const fn sectors(&self) -> u64 {
        self.sectors
    }

    pub fn read_sector(
        &mut self,
        sector: u64,
        output: &mut [u8; SECTOR_BYTES],
    ) -> Result<(), Error<T::Error>> {
        let lba = self.lba(sector)?;
        let mut staged = [0; SECTOR_BYTES];
        self.command(block_cdb(0x28, lba), Data::In(&mut staged))?;
        *output = staged;
        Ok(())
    }

    /// Writes one authorized sector, synchronizes cache, then rereads it.
    /// On error the medium may already have changed; do not replay blindly.
    /// Partition and filesystem authorization remain with the caller.
    pub fn write_sector_verified(
        &mut self,
        sector: u64,
        input: &[u8; SECTOR_BYTES],
    ) -> Result<(), Error<T::Error>> {
        let lba = self.lba(sector)?;
        self.command(block_cdb(0x2a, lba), Data::Out(input))?;
        // IMMED is clear. A successful completion reports synchronization
        // before the independent READ(10), not just acceptance of WRITE(10).
        self.command([0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0], Data::None)?;
        let mut observed = [0; SECTOR_BYTES];
        self.read_sector(sector, &mut observed)?;
        if &observed != input {
            self.faulted = true;
            return Err(Error::ReadbackMismatch);
        }
        Ok(())
    }

    fn lba(&self, sector: u64) -> Result<u32, Error<T::Error>> {
        if self.faulted {
            return Err(Error::Faulted);
        }
        if sector >= self.sectors {
            return Err(Error::OutOfRange);
        }
        u32::try_from(sector).map_err(|_| Error::OutOfRange)
    }

    fn command(&mut self, cdb: [u8; 10], data: Data<'_>) -> Result<(), Error<T::Error>> {
        if self.faulted {
            return Err(Error::Faulted);
        }
        self.faulted = true;
        let tag = self.next_tag;
        self.next_tag = self.next_tag.checked_add(1).ok_or(Error::Faulted)?;
        let (length, flags) = match &data {
            Data::None => (0, 0),
            Data::In(bytes) => (bytes.len(), 0x80),
            Data::Out(bytes) => (bytes.len(), 0),
        };
        let mut cbw = [0; CBW_BYTES];
        cbw[..4].copy_from_slice(&CBW_SIGNATURE);
        cbw[4..8].copy_from_slice(&tag.to_le_bytes());
        cbw[8..12].copy_from_slice(&(length as u32).to_le_bytes());
        cbw[12] = flags;
        cbw[14] = if cdb[0] == 3 { 6 } else { 10 };
        cbw[15..25].copy_from_slice(&cdb);
        exact(self.endpoint.bulk_out(&cbw), CBW_BYTES)?;
        match data {
            Data::None => {}
            Data::In(bytes) => exact(self.endpoint.bulk_in(bytes), length)?,
            Data::Out(bytes) => exact(self.endpoint.bulk_out(bytes), length)?,
        }
        let mut csw = [0; CSW_BYTES];
        exact(self.endpoint.bulk_in(&mut csw), CSW_BYTES)?;
        if csw[..4] != CSW_SIGNATURE || csw[4..8] != tag.to_le_bytes() {
            return Err(Error::InvalidStatus);
        }
        match csw[12] {
            0 if csw[8..12] == [0; 4] => {}
            1 if u32::from_le_bytes(csw[8..12].try_into().unwrap()) <= length as u32 => {
                return Err(Error::CommandFailed);
            }
            2 => return Err(Error::PhaseError),
            _ => return Err(Error::InvalidStatus),
        }
        self.faulted = false;
        Ok(())
    }
}

fn exact<E>(result: Result<usize, E>, expected: usize) -> Result<(), Error<E>> {
    if result.map_err(Error::Transport)? != expected {
        return Err(Error::ShortTransfer);
    }
    Ok(())
}

fn block_cdb(opcode: u8, lba: u32) -> [u8; 10] {
    let mut cdb = [0; 10];
    cdb[0] = opcode;
    cdb[2..6].copy_from_slice(&lba.to_be_bytes());
    cdb[8] = 1;
    cdb
}

#[cfg(test)]
mod tests;
