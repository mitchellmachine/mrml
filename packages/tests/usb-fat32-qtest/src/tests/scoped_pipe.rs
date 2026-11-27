use super::{FILE_SECTOR, START};
use mrml_storage_usb::BulkTransport;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Command,
    Read(usize, [u8; 4], u8, u32),
    Write([u8; 4]),
    Status([u8; 4], u8, u32),
    Fault,
}

/// Test-only endpoint for a freshly owned and verified disposable QEMU image.
/// It cannot forward raw commands to any host device or make a second write.
pub(super) struct ScopedProbePipe<T> {
    pipe: T,
    phase: Phase,
    sent_write: bool,
    flushed: bool,
    read_back: bool,
}

impl<T> ScopedProbePipe<T> {
    pub(super) fn new(pipe: T) -> Self {
        Self {
            pipe,
            phase: Phase::Command,
            sent_write: false,
            flushed: false,
            read_back: false,
        }
    }

    pub(super) fn completed(&self) -> bool {
        self.phase == Phase::Command && self.sent_write && self.flushed && self.read_back
    }

    fn command(&self, bytes: &[u8]) -> Option<Phase> {
        if bytes.len() != 31 || &bytes[..4] != b"USBC" || bytes[13] != 0 || bytes[25..] != [0; 6] {
            return None;
        }
        let tag = bytes[4..8].try_into().ok()?;
        let size = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
        let op = bytes[15];
        let lba = u32::from_be_bytes(bytes[17..21].try_into().ok()?);
        let block = bytes[16] == 0 && bytes[21..25] == [0, 0, 1, 0];
        let data_lba = FILE_SECTOR as u32;
        let read_lba = lba >= START as u32 && lba <= data_lba;
        match (op, bytes[12], bytes[14], size) {
            (0x25, 0x80, 10, 8) if bytes[16..25] == [0; 9] && !self.sent_write => {
                Some(Phase::Read(8, tag, op, 0))
            }
            (3, 0x80, 6, 18)
                if bytes[16..25] == [0, 0, 0, 18, 0, 0, 0, 0, 0] && !self.sent_write =>
            {
                Some(Phase::Read(18, tag, op, 0))
            }
            (0x28, 0x80, 10, 512) if block && read_lba && (!self.sent_write || self.flushed) => {
                Some(Phase::Read(512, tag, op, lba))
            }
            (0x2a, 0, 10, 512) if block && lba == data_lba && !self.sent_write => {
                Some(Phase::Write(tag))
            }
            (0x35, 0, 10, 0) if bytes[16..25] == [0; 9] && self.sent_write && !self.flushed => {
                Some(Phase::Status(tag, op, 0))
            }
            _ => None,
        }
    }
}

impl<T: BulkTransport> BulkTransport for ScopedProbePipe<T> {
    type Error = ();

    fn bulk_out(&mut self, bytes: &[u8]) -> Result<usize, ()> {
        let phase = core::mem::replace(&mut self.phase, Phase::Fault);
        let next = match phase {
            Phase::Command => self.command(bytes).ok_or(())?,
            Phase::Write(tag)
                if bytes.len() == 512
                    && &bytes[..3] == b"new"
                    && bytes[3..].iter().all(|&byte| byte == 0xa5) =>
            {
                self.sent_write = true;
                Phase::Status(tag, 0x2a, FILE_SECTOR as u32)
            }
            _ => return Err(()),
        };
        let length = self.pipe.bulk_out(bytes).map_err(|_| ())?;
        if length != bytes.len() {
            return Err(());
        }
        self.phase = next;
        Ok(length)
    }

    fn bulk_in(&mut self, bytes: &mut [u8]) -> Result<usize, ()> {
        let phase = core::mem::replace(&mut self.phase, Phase::Fault);
        let expected = match phase {
            Phase::Read(size, _, _, _) => size,
            Phase::Status(_, _, _) => 13,
            _ => return Err(()),
        };
        if bytes.len() != expected || self.pipe.bulk_in(bytes).map_err(|_| ())? != expected {
            return Err(());
        }
        self.phase = match phase {
            Phase::Read(_, tag, op, lba) => Phase::Status(tag, op, lba),
            Phase::Status(tag, op, lba) => {
                if &bytes[..4] != b"USBS"
                    || bytes[4..8] != tag
                    || !(bytes[8..13] == [0; 5] || (op == 0x25 && bytes[12] == 1))
                {
                    return Err(());
                }
                self.flushed |= op == 0x35;
                self.read_back |= op == 0x28 && lba == FILE_SECTOR as u32 && self.flushed;
                Phase::Command
            }
            _ => return Err(()),
        };
        Ok(expected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Fake(usize);
    impl BulkTransport for Fake {
        type Error = ();

        fn bulk_out(&mut self, bytes: &[u8]) -> Result<usize, ()> {
            self.0 += 1;
            Ok(bytes.len())
        }

        fn bulk_in(&mut self, _: &mut [u8]) -> Result<usize, ()> {
            self.0 += 1;
            Err(())
        }
    }

    fn write_at(lba: u32) -> [u8; 31] {
        let mut bytes = [0; 31];
        bytes[..4].copy_from_slice(b"USBC");
        bytes[8..12].copy_from_slice(&512u32.to_le_bytes());
        bytes[14..16].copy_from_slice(&[10, 0x2a]);
        bytes[17..21].copy_from_slice(&lba.to_be_bytes());
        bytes[23] = 1;
        bytes
    }

    #[test]
    fn wrong_sector_closes_pipe_before_forwarding() {
        let mut scoped = ScopedProbePipe::new(Fake::default());
        assert_eq!(scoped.bulk_out(&write_at(FILE_SECTOR as u32 - 1)), Err(()));
        assert_eq!(scoped.bulk_out(&write_at(FILE_SECTOR as u32)), Err(()));
        assert_eq!(scoped.pipe.0, 0);
        assert!(!scoped.completed());
    }

    #[test]
    fn wrong_data_is_not_forwarded_and_cannot_be_retried() {
        let mut scoped = ScopedProbePipe::new(Fake::default());
        assert_eq!(scoped.bulk_out(&write_at(FILE_SECTOR as u32)), Ok(31));
        assert_eq!(scoped.bulk_out(&[0; 512]), Err(()));
        let mut correct = [0xa5; 512];
        correct[..3].copy_from_slice(b"new");
        assert_eq!(scoped.bulk_out(&correct), Err(()));
        assert_eq!(scoped.pipe.0, 1);
        assert!(!scoped.completed());
    }
}
