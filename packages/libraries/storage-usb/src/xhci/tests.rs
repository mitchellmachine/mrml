use super::*;

const DMA: DmaLayout = DmaLayout {
    device_contexts: 0x10_0000,
    command_ring: 0x10_0100,
    event_segments: 0x10_0200,
    event_ring: 0x10_0300,
};
const OP: u32 = 0x40;
const RT: u32 = 0x1000;
const DB: u32 = 0x2000;

struct Fake {
    regs: [u32; 0x2400 / 4],
    dma: [u8; 1024],
    completion: bool,
    corrupt_event: bool,
    bell: u64,
}

impl Fake {
    fn new() -> Self {
        let mut fake = Self {
            regs: [0; 0x2400 / 4],
            dma: [0xff; 1024],
            completion: true,
            corrupt_event: false,
            bell: 0,
        };
        fake.regs[0] = 0x0110_0040;
        fake.regs[1] = 0x0200_0108;
        fake.regs[4] = 1;
        fake.regs[5] = DB;
        fake.regs[6] = RT;
        fake.regs[(OP as usize + 4) / 4] = HALTED;
        fake.regs[(OP as usize + 8) / 4] = 1;
        fake.regs[(OP as usize + 0x400) / 4] = (3 << 10) | (1 << 9) | 1;
        fake
    }
}

impl Platform for Fake {
    type Error = ();
    fn read32(&mut self, offset: u32) -> Result<u32, ()> {
        Ok(self.regs[offset as usize / 4])
    }
    fn write32(&mut self, offset: u32, value: u32) -> Result<(), ()> {
        self.regs[offset as usize / 4] = value;
        if offset == OP {
            self.regs[(OP as usize + 4) / 4] = if value == RUN { 0 } else { HALTED };
            self.regs[OP as usize / 4] = if value == RESET { 0 } else { value };
        }
        if offset == DB && self.completion {
            assert_eq!(
                self.regs[(OP as usize + 0x30) / 4],
                DMA.device_contexts as u32
            );
            assert_eq!(
                self.regs[(RT as usize + 0x30) / 4],
                DMA.event_segments as u32
            );
            let target = DMA.command_ring + self.bell * TRB_BYTES;
            let mut command = [0; 16];
            self.dma_read(target, &mut command)?;
            assert_eq!(&command[..12], &[0; 12]);
            assert_eq!(
                u32::from_le_bytes(command[12..].try_into().unwrap()),
                (COMMAND_NOOP << 10) | 1
            );
            let mut done = [0; 16];
            done[..8].copy_from_slice(&(target + u64::from(self.corrupt_event) * 16).to_le_bytes());
            done[11] = 1;
            done[12..].copy_from_slice(&((COMMAND_COMPLETION << 10) | 1).to_le_bytes());
            self.dma_write(DMA.event_ring + self.bell * TRB_BYTES, &done)?;
            self.bell += 1;
        }
        Ok(())
    }
    fn dma_write(&mut self, address: u64, bytes: &[u8]) -> Result<(), ()> {
        let offset = (address - DMA.device_contexts) as usize;
        self.dma[offset..][..bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
    fn dma_read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), ()> {
        let offset = (address - DMA.device_contexts) as usize;
        bytes.copy_from_slice(&self.dma[offset..][..bytes.len()]);
        Ok(())
    }
    fn publish_dma(&mut self) -> Result<(), ()> {
        Ok(())
    }
    fn acquire_dma(&mut self) -> Result<(), ()> {
        Ok(())
    }
    fn wait_tick(&mut self) -> Result<(), ()> {
        Ok(())
    }
}

#[test]
fn programs_rings_and_requires_exact_command_completion() {
    let mut controller = Controller::start(Fake::new(), 0x2400, DMA, 10).unwrap();
    assert_eq!(
        controller.port_status(1),
        Ok(PortStatus {
            connected: true,
            powered: true,
            enabled: false,
            speed_id: 3
        })
    );
    assert_eq!(controller.port_status(3), Err(Error::InvalidPort));
    for _ in 0..15 {
        controller.no_op(5).unwrap();
    }
    assert_eq!(controller.no_op(5), Err(Error::QueueExhausted));
    controller.halt(5).unwrap();
    assert_eq!(controller.no_op(5), Err(Error::Faulted));
}

#[test]
fn rejects_invalid_resources_or_unreleased_firmware() {
    let bad_dma = DmaLayout {
        event_ring: DMA.command_ring,
        ..DMA
    };
    assert!(matches!(
        Controller::start(Fake::new(), 0x2400, bad_dma, 10),
        Err(Error::InvalidDma)
    ));
    assert!(matches!(
        Controller::start(Fake::new(), 0x1800, DMA, 10),
        Err(Error::InvalidBar)
    ));
    let mut fake = Fake::new();
    fake.regs[4] |= (0x900 / 4) << 16;
    fake.regs[0x900 / 4] = 1 | (1 << 16);
    assert!(matches!(
        Controller::start(fake, 0x2400, DMA, 10),
        Err(Error::FirmwareOwned)
    ));
    assert!(matches!(
        Controller::start(Fake::new(), 0x2400, DMA, 0),
        Err(Error::Timeout)
    ));
}

#[test]
fn a_timeout_or_wrong_command_pointer_faults_the_session() {
    for (inject, expected) in [(false, Error::Timeout), (true, Error::UnexpectedEvent)] {
        let mut fake = Fake::new();
        fake.completion = inject;
        fake.corrupt_event = inject;
        let mut controller = Controller::start(fake, 0x2400, DMA, 10).unwrap();
        assert_eq!(controller.no_op(3), Err(expected));
        assert_eq!(controller.no_op(3), Err(Error::Faulted));
        controller.halt(5).unwrap();
    }
}

#[cfg(unix)]
mod qemu;
