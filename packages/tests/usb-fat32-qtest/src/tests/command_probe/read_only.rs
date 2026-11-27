//! Test-only bulk allowance for the exact disposable sector and marker.
use super::super::{FILE_SECTOR, START, TOTAL};
use super::{BULK_BUFFER, BULK_IN, BULK_OUT, trb_fields};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    Capacity,
    CapacityData,
    CapacityStatus,
    Sense,
    SenseData,
    SenseStatus,
    Retry,
    RetryData,
    RetryStatus,
    Read,
    Sector,
    ReadStatus,
    Write,
    WriteData,
    WriteStatus,
    Flush,
    FlushStatus,
    ReadBack,
    ReadBackData,
    ReadBackStatus,
    Done,
}

pub(super) struct ReadOnly {
    pub(super) events: Option<[u8; 256]>,
    step: Step,
    out: u8,
    tag: u8,
    allow_update: bool,
    input: u8,
    buffer_ready: bool,
    fields_ready: bool,
    control_ready: bool,
    in_flight: bool,
    capacity_valid: bool,
}

impl ReadOnly {
    pub(super) fn new(allow_update: bool) -> Self {
        Self {
            events: None,
            step: Step::Capacity,
            out: 0,
            tag: 0,
            allow_update,
            input: 0,
            buffer_ready: false,
            fields_ready: false,
            control_ready: false,
            in_flight: false,
            capacity_valid: false,
        }
    }

    pub(super) fn started(&self) -> bool {
        self.events.is_some()
    }
    pub(super) fn start(&mut self, capture: [u8; 256]) {
        self.events = Some(capture);
    }
    pub(super) fn complete(&self) -> bool {
        self.step == Step::Done && !self.in_flight
    }

    fn output(&self) -> bool {
        matches!(
            self.step,
            Step::Capacity
                | Step::Sense
                | Step::Retry
                | Step::Read
                | Step::Write
                | Step::WriteData
                | Step::Flush
                | Step::ReadBack
        )
    }

    fn length(&self) -> Option<usize> {
        match self.step {
            Step::Capacity
            | Step::Sense
            | Step::Retry
            | Step::Read
            | Step::Write
            | Step::Flush
            | Step::ReadBack => Some(31),
            Step::CapacityData | Step::RetryData => Some(8),
            Step::SenseData => Some(18),
            Step::Sector | Step::WriteData | Step::ReadBackData => Some(512),
            Step::CapacityStatus
            | Step::SenseStatus
            | Step::RetryStatus
            | Step::ReadStatus
            | Step::WriteStatus
            | Step::FlushStatus
            | Step::ReadBackStatus => Some(13),
            Step::Done => None,
        }
    }

    pub(super) fn in_length(&self) -> Option<usize> {
        if !self.in_flight || self.output() {
            return None;
        }
        self.length()
    }

    pub(super) fn dci(&self, configuration: &[u8]) -> Option<u8> {
        self.length()?;
        let interface = mrml_storage_usb::find_bulk_interface(configuration).ok()?;
        Some(if self.output() {
            (interface.bulk_out & 15) * 2
        } else {
            (interface.bulk_in & 15) * 2 + 1
        })
    }

    fn cbw(&self) -> [u8; 31] {
        let mut bytes = [0; 31];
        bytes[..4].copy_from_slice(b"USBC");
        bytes[4..8].copy_from_slice(&(u32::from(self.tag) + 1).to_le_bytes());
        let (opcode, length, cdb_size) = match self.step {
            Step::Sense => (3, 18u32, 6),
            Step::Read | Step::ReadBack => (0x28, 512, 10),
            Step::Write => (0x2a, 512, 10),
            Step::Flush => (0x35, 0, 10),
            _ => (0x25, 8, 10),
        };
        bytes[8..12].copy_from_slice(&length.to_le_bytes());
        bytes[12] = if matches!(self.step, Step::Write | Step::Flush) {
            0
        } else {
            0x80
        };
        bytes[14] = cdb_size;
        bytes[15] = opcode;
        if self.step == Step::Sense {
            bytes[19] = 18;
        }
        if matches!(self.step, Step::Read | Step::Write | Step::ReadBack) {
            bytes[17..21].copy_from_slice(&(FILE_SECTOR as u32).to_be_bytes());
            bytes[23] = 1;
        }
        bytes
    }

    pub(super) fn allow_write(&mut self, address: u64, bytes: &[u8]) -> bool {
        let Some(len) = self.length() else {
            return false;
        };
        if self.in_flight {
            return false;
        }
        let output = self.output();
        let payload_matches = if self.step == Step::WriteData {
            bytes.len() == 512 && &bytes[..3] == b"new" && bytes[3..].iter().all(|&b| b == 0xa5)
        } else {
            bytes == self.cbw()
        };
        if output && !self.buffer_ready && address == BULK_BUFFER && payload_matches {
            self.buffer_ready = true;
            return true;
        }
        let (ring, index) = if output {
            (BULK_OUT, self.out)
        } else {
            (BULK_IN, self.input)
        };
        let trb = ring + u64::from(index) * 16;
        if (!output || self.buffer_ready)
            && !self.fields_ready
            && address == trb
            && bytes == trb_fields(BULK_BUFFER, len as u32)
        {
            self.fields_ready = true;
            return true;
        }
        if self.fields_ready
            && !self.control_ready
            && address == trb + 12
            && bytes == ((1u32 << 10) | (1 << 5) | (1 << 2) | 1).to_le_bytes()
        {
            self.control_ready = true;
            return true;
        }
        false
    }

    pub(super) fn staged(&self) -> bool {
        !self.in_flight && self.control_ready && (!self.output() || self.buffer_ready)
    }

    pub(super) fn ring(&mut self) {
        self.buffer_ready = false;
        self.fields_ready = false;
        self.control_ready = false;
        if self.output() {
            self.out += 1;
            if self.step != Step::WriteData {
                self.tag += 1;
            }
            self.step = match self.step {
                Step::Capacity => Step::CapacityData,
                Step::Sense => Step::SenseData,
                Step::Retry => Step::RetryData,
                Step::Read => Step::Sector,
                Step::Write => Step::WriteData,
                Step::WriteData => Step::WriteStatus,
                Step::Flush => Step::FlushStatus,
                Step::ReadBack => Step::ReadBackData,
                _ => unreachable!(),
            };
        } else {
            self.input += 1;
            self.in_flight = true;
        }
    }

    pub(super) fn receive(&mut self, bytes: &[u8]) -> Result<(), ()> {
        if self.in_length() != Some(bytes.len()) {
            return Err(());
        }
        let csw = |residue: u32, status| {
            &bytes[..4] == b"USBS"
                && bytes[4..8] == u32::from(self.tag).to_le_bytes()
                && bytes[8..12] == residue.to_le_bytes()
                && bytes[12] == status
        };
        self.step = match self.step {
            Step::CapacityData | Step::RetryData => {
                self.capacity_valid = bytes[..4] == ((START + TOTAL - 1) as u32).to_be_bytes()
                    && bytes[4..] == 512u32.to_be_bytes();
                if self.step == Step::CapacityData {
                    Step::CapacityStatus
                } else {
                    Step::RetryStatus
                }
            }
            Step::CapacityStatus if csw(8, 1) => Step::Sense,
            Step::CapacityStatus | Step::RetryStatus if csw(0, 0) && self.capacity_valid => {
                Step::Read
            }
            Step::SenseData
                if matches!(bytes[0] & 0x7f, 0x70 | 0x71)
                    && bytes[2] & 15 == 6
                    && bytes[7] >= 6
                    && bytes[12] == 0x29 =>
            {
                Step::SenseStatus
            }
            Step::SenseStatus if csw(0, 0) => Step::Retry,
            Step::Sector
                if &bytes[..3] == b"old" && bytes[3..].iter().all(|&byte| byte == 0xa5) =>
            {
                Step::ReadStatus
            }
            Step::ReadStatus if csw(0, 0) => {
                if self.allow_update {
                    Step::Write
                } else {
                    Step::Done
                }
            }
            Step::WriteStatus if csw(0, 0) => Step::Flush,
            Step::FlushStatus if csw(0, 0) => Step::ReadBack,
            Step::ReadBackData
                if &bytes[..3] == b"new" && bytes[3..].iter().all(|&b| b == 0xa5) =>
            {
                Step::ReadBackStatus
            }
            Step::ReadBackStatus if csw(0, 0) => Step::Done,
            _ => return Err(()),
        };
        self.in_flight = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_expected_read_commands_and_buffers_can_be_staged() {
        let mut broker = ReadOnly::new(false);
        let mut request = broker.cbw();
        request[15] = 0x2a;
        assert!(!broker.allow_write(BULK_BUFFER, &request));
        assert!(!broker.staged());
        let capacity = broker.cbw();
        assert!(!broker.allow_write(BULK_BUFFER + 512, &capacity));
        assert!(broker.allow_write(BULK_BUFFER, &capacity));
        assert!(!broker.allow_write(BULK_OUT, &trb_fields(BULK_BUFFER + 512, 31)));
        assert!(broker.allow_write(BULK_OUT, &trb_fields(BULK_BUFFER, 31)));
        assert!(!broker.staged());
    }

    #[test]
    fn identical_capacity_with_wrong_status_tag_does_not_progress() {
        let mut broker = ReadOnly::new(false);
        broker.step = Step::CapacityStatus;
        broker.tag = 1;
        broker.in_flight = true;
        broker.capacity_valid = true;
        let mut csw = [0; 13];
        csw[..4].copy_from_slice(b"USBS");
        csw[4] = 2;
        assert_eq!(broker.receive(&csw), Err(()));
        assert!(broker.step == Step::CapacityStatus);
    }
}

#[cfg(test)]
#[test]
fn update_requires_exact_lba_marker_and_successful_flush() {
    let mut broker = ReadOnly::new(true);
    broker.step = Step::Write;
    let mut wrong_lba = broker.cbw();
    wrong_lba[20] ^= 1;
    assert!(!broker.allow_write(BULK_BUFFER, &wrong_lba));
    broker.step = Step::WriteData;
    let mut marker = [0xa5; 512];
    marker[..3].copy_from_slice(b"new");
    marker[30] ^= 1;
    assert!(!broker.allow_write(BULK_BUFFER, &marker));
    marker[30] ^= 1;
    assert!(broker.allow_write(BULK_BUFFER, &marker));
    broker.step = Step::FlushStatus;
    broker.tag = 6;
    broker.in_flight = true;
    let mut csw = [0; 13];
    csw[..4].copy_from_slice(b"USBS");
    csw[4] = 6;
    csw[12] = 1;
    assert_eq!(broker.receive(&csw), Err(()));
    assert!(!broker.complete());
}
