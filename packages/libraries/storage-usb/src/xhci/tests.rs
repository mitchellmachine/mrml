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
    fail_run: bool,
    ignore_stop_once: bool,
    fail_revoke_once: bool,
    activation_fault: u8,
    activation_reads: u8,
}

impl Fake {
    fn new() -> Self {
        let mut fake = Self {
            regs: [0; 0x2400 / 4],
            dma: [0xff; 1024],
            completion: true,
            corrupt_event: false,
            bell: 0,
            fail_run: false,
            ignore_stop_once: false,
            fail_revoke_once: false,
            activation_fault: 0,
            activation_reads: 0,
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
        if offset == OP && value == 0 && self.ignore_stop_once {
            self.ignore_stop_once = false;
            return Ok(());
        }
        self.regs[offset as usize / 4] = value;
        if offset == OP {
            self.regs[(OP as usize + 4) / 4] = if value == RUN { 0 } else { HALTED };
            self.regs[OP as usize / 4] = if value == RESET { 0 } else { value };
        }
        if offset == OP && value == RUN && self.fail_run {
            return Err(());
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

impl RevocablePlatform for Fake {
    fn revoke_after_halt(&mut self) -> Result<(), ()> {
        assert_eq!(self.regs[OP as usize / 4], 0);
        assert_ne!(self.regs[(OP as usize + 4) / 4] & HALTED, 0);
        if core::mem::take(&mut self.fail_revoke_once) {
            return Err(());
        }
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
    controller.stop(5).unwrap().revoke().unwrap();
}

#[test]
fn rejects_invalid_resources_or_unreleased_firmware() {
    let bad_dma = DmaLayout {
        event_ring: DMA.command_ring,
        ..DMA
    };
    assert!(matches!(
        Controller::start(Fake::new(), 0x2400, bad_dma, 10),
        Err(StartFailure::Untouched {
            error: Error::InvalidDma,
            ..
        })
    ));
    assert!(matches!(
        Controller::start(Fake::new(), 0x1800, DMA, 10),
        Err(StartFailure::Untouched {
            error: Error::InvalidBar,
            ..
        })
    ));
    let mut fake = Fake::new();
    fake.regs[4] |= (0x900 / 4) << 16;
    fake.regs[0x900 / 4] = 1 | (1 << 16);
    assert!(matches!(
        Controller::start(fake, 0x2400, DMA, 10),
        Err(StartFailure::Untouched {
            error: Error::FirmwareOwned,
            ..
        })
    ));
    let Err(StartFailure::Programming(pending)) = Controller::start(Fake::new(), 0x2400, DMA, 0)
    else {
        panic!("expected a retryable startup failure");
    };
    assert_eq!(pending.error(), &Error::Timeout);
    pending.retry(5).unwrap().revoke().unwrap();
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
        controller.stop(5).unwrap().revoke().unwrap();
    }
}

#[test]
fn failed_start_keeps_ownership_after_the_run_write() {
    let mut fake = Fake::new();
    fake.fail_run = true;
    let Err(StartFailure::Programming(pending)) = Controller::start(fake, 0x2400, DMA, 5) else {
        panic!("expected ownership of the partially programmed controller");
    };
    assert_eq!(pending.error(), &Error::Platform(()));
    pending.retry(5).unwrap().revoke().unwrap();
}

#[test]
fn halt_timeout_and_revocation_failure_allow_only_their_own_retry() {
    let mut controller = Controller::start(Fake::new(), 0x2400, DMA, 5).unwrap();
    controller.platform.ignore_stop_once = true;
    controller.platform.fail_revoke_once = true;
    let Err(pending) = controller.stop(5) else {
        panic!("must not release a running device");
    };
    assert_eq!(pending.error(), &Error::Timeout);
    let halted = pending.retry(5).unwrap();
    let failed = halted.revoke().unwrap_err();
    assert_eq!(failed.error(), &());
    failed.retry().unwrap();
}

fn activation_snapshot() -> pci::PciSnapshot {
    pci::PciSnapshot {
        location: pci::PciLocation {
            segment: 0,
            bus: 0,
            device: 3,
            function: 0,
        },
        configuration_generation: 1,
        vendor_device: 0x000d_1b36,
        class_revision: 0x0c03_3000,
        header_type: 0,
        command: 2,
        bar0: 0xfeb0_0004,
        bar1: 0,
        bar0_bytes: 0x4000,
    }
}

fn activation_assignment() -> DmaAssignment {
    DmaAssignment {
        controller: pci::PciController::discover(activation_snapshot()).unwrap(),
        mapping_generation: 1,
        device_base: DMA.device_contexts,
        bytes: 4096,
    }
}

impl PciActivation for Fake {
    fn activation_state(&mut self) -> Result<(pci::PciSnapshot, DmaAssignment), ()> {
        self.activation_reads += 1;
        let mut mapping = activation_assignment();
        if self.activation_fault == 1 && self.activation_reads == 2 {
            mapping.mapping_generation += 1;
        }
        // Neither activation error may reach the actual run write. This
        // emulates the command remaining unchanged after a reported success.
        Ok((activation_snapshot(), mapping))
    }

    fn enable_bus_master(&mut self, expected: DmaAssignment, before: u16) -> Result<(), ()> {
        assert_eq!(
            self.activation_fault, 2,
            "must not arm a changed assignment"
        );
        assert_eq!(expected, activation_assignment());
        assert_eq!(before, 2);
        assert_eq!(self.regs[OP as usize / 4], 0);
        assert_eq!(self.regs[(OP as usize + 0x30) / 4], 0);
        Ok(())
    }
}

#[test]
fn mapping_drift_or_missing_pci_readback_prevents_run_and_retains_cleanup() {
    for (fault, expected) in [
        (1, Error::InvalidDma),
        (2, Error::Pci(pci::PciError::CommandMismatch)),
    ] {
        let mut fake = Fake::new();
        fake.activation_fault = fault;
        fake.fail_run = true;
        let Err(StartFailure::Programming(pending)) =
            Controller::start_pci(fake, activation_assignment(), DMA, 5)
        else {
            panic!("activation must not start the controller");
        };
        assert_eq!(pending.error(), &expected);
        pending.retry(5).unwrap().revoke().unwrap();
    }
}
