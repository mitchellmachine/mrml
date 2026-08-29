//! Bounded ATA software reset before IDE provider replacement.

use crate::{IdeChannelPortGrant, IdePortIo};

const DEVICE_CONTROL_INTERRUPT_DISABLE: u8 = 1 << 1;
const DEVICE_CONTROL_SOFTWARE_RESET: u8 = 1 << 2;
const STATUS_ERROR: u8 = 1;
const STATUS_DEVICE_FAULT: u8 = 1 << 5;
const STATUS_BUSY: u8 = 1 << 7;
const POLL_LIMIT: u32 = 2000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdeResetError {
    PortRead,
    PortWrite,
    DeviceError,
    DeviceFault,
    Timeout,
}

#[derive(Debug, Eq, PartialEq)]
pub struct IdeResetFailure {
    pub grant: IdeChannelPortGrant,
    pub error: IdeResetError,
}

/// Masks channel interrupts, asserts/deasserts SRST, performs the required
/// settling reads, and returns ownership only after the channel is idle.
pub fn reset_ide_channel<I: IdePortIo>(
    grant: IdeChannelPortGrant,
    io: &mut I,
) -> Result<IdeChannelPortGrant, IdeResetFailure> {
    let control = grant.control.base;
    io.write_u8(
        control,
        DEVICE_CONTROL_INTERRUPT_DISABLE | DEVICE_CONTROL_SOFTWARE_RESET,
    )
    .map_err(|_| failure(grant, IdeResetError::PortWrite))?;
    io.delay_500_micros();
    io.write_u8(control, DEVICE_CONTROL_INTERRUPT_DISABLE)
        .map_err(|_| failure(grant, IdeResetError::PortWrite))?;
    for _ in 0..4 {
        io.read_u8(control)
            .map_err(|_| failure(grant, IdeResetError::PortRead))?;
    }
    for _ in 0..POLL_LIMIT {
        let status = io
            .read_u8(grant.command.base + 7)
            .map_err(|_| failure(grant, IdeResetError::PortRead))?;
        if status & STATUS_BUSY != 0 {
            io.delay_500_micros();
            continue;
        }
        if status & STATUS_DEVICE_FAULT != 0 {
            return Err(failure(grant, IdeResetError::DeviceFault));
        }
        if status & STATUS_ERROR != 0 {
            return Err(failure(grant, IdeResetError::DeviceError));
        }
        return Ok(grant);
    }
    Err(failure(grant, IdeResetError::Timeout))
}

const fn failure(grant: IdeChannelPortGrant, error: IdeResetError) -> IdeResetFailure {
    IdeResetFailure { grant, error }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IdeChannel, IdePortRange};
    use mrml_kernel::ObjectId;

    struct Io {
        statuses: [u8; 3],
        index: usize,
        writes: [Option<(u16, u8)>; 2],
        delays: u32,
        alt_reads: usize,
        reject_write: bool,
    }
    impl IdePortIo for Io {
        fn read_u8(&mut self, port: u16) -> Result<u8, ()> {
            if port == 0x3f6 {
                self.alt_reads += 1;
                return Ok(0);
            }
            let value = self.statuses[self.index.min(2)];
            self.index += 1;
            Ok(value)
        }
        fn read_u16(&mut self, _: u16) -> Result<u16, ()> {
            Err(())
        }
        fn write_u8(&mut self, port: u16, value: u8) -> Result<(), ()> {
            if self.reject_write {
                return Err(());
            }
            let index = usize::from(self.writes[0].is_some());
            self.writes[index] = Some((port, value));
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
            bus_master: None,
        }
    }
    fn io() -> Io {
        Io {
            statuses: [STATUS_BUSY, 0, 0],
            index: 0,
            writes: [None; 2],
            delays: 0,
            alt_reads: 0,
            reject_write: false,
        }
    }

    #[test]
    fn masks_interrupts_resets_settles_and_waits_for_idle() {
        let mut ports = io();
        assert_eq!(reset_ide_channel(grant(), &mut ports), Ok(grant()));
        assert_eq!(ports.writes, [Some((0x3f6, 6)), Some((0x3f6, 2))]);
        assert_eq!(ports.alt_reads, 4);
        assert_eq!(ports.delays, 2);
    }
    #[test]
    fn write_fault_status_or_timeout_retains_quarantined_grant() {
        let mut ports = io();
        ports.reject_write = true;
        assert_eq!(
            reset_ide_channel(grant(), &mut ports).unwrap_err().error,
            IdeResetError::PortWrite
        );
        let mut ports = io();
        ports.statuses = [STATUS_DEVICE_FAULT; 3];
        assert_eq!(
            reset_ide_channel(grant(), &mut ports).unwrap_err().error,
            IdeResetError::DeviceFault
        );
        let mut ports = io();
        ports.statuses = [STATUS_BUSY; 3];
        assert_eq!(
            reset_ide_channel(grant(), &mut ports).unwrap_err().error,
            IdeResetError::Timeout
        );
    }
}
