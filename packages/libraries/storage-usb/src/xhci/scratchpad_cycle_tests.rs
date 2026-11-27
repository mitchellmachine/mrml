use super::*;

const PAGE: usize = 4096;
const PREFIX: u64 = PAGE as u64;
const PAGES: usize = 35;
const TABLE: u64 = DMA.device_contexts + PREFIX;

struct ScratchFake<'a> {
    inner: Fake,
    backing: &'a mut [u8; PAGE * PAGES],
    assignment: DmaAssignment,
    published: bool,
    armed: bool,
    deny_cleanup_once: bool,
}

impl Platform for ScratchFake<'_> {
    type Error = ();

    fn read32(&mut self, offset: u32) -> Result<u32, ()> {
        self.inner.read32(offset)
    }

    fn write32(&mut self, offset: u32, value: u32) -> Result<(), ()> {
        if offset == OP && value == RUN {
            assert!(self.published && self.armed);
        }
        self.inner.write32(offset, value)
    }

    fn dma_write(&mut self, address: u64, bytes: &[u8]) -> Result<(), ()> {
        if address >= TABLE {
            assert!(!self.published && !self.armed);
            let offset = usize::try_from(address - TABLE).unwrap();
            self.backing[offset..][..bytes.len()].copy_from_slice(bytes);
            Ok(())
        } else {
            self.inner.dma_write(address, bytes)
        }
    }

    fn dma_read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), ()> {
        self.inner.dma_read(address, bytes)
    }

    fn publish_dma(&mut self) -> Result<(), ()> {
        assert_eq!(self.armed, self.published);
        self.published = true;
        Ok(())
    }

    fn acquire_dma(&mut self) -> Result<(), ()> {
        Ok(())
    }

    fn wait_tick(&mut self) -> Result<(), ()> {
        Ok(())
    }
}

impl PciActivation for ScratchFake<'_> {
    fn activation_state(&mut self) -> Result<(pci::PciSnapshot, DmaAssignment), ()> {
        let mut snapshot = activation_snapshot();
        if self.armed {
            snapshot.command |= 4;
        }
        Ok((snapshot, self.assignment))
    }

    fn enable_bus_master(&mut self, expected: DmaAssignment, before: u16) -> Result<(), ()> {
        assert_eq!(expected, self.assignment);
        assert_eq!(before, 2);
        assert!(self.published && !self.armed);
        assert_eq!(&self.inner.dma[..8], &TABLE.to_le_bytes());
        assert_eq!(self.inner.regs[(OP as usize + 0x30) / 4], 0);
        for (index, entry) in self.backing[..34 * 8].chunks_exact(8).enumerate() {
            assert_eq!(entry, &(TABLE + (index as u64 + 1) * PREFIX).to_le_bytes());
        }
        assert!(self.backing[34 * 8..].iter().all(|&byte| byte == 0));
        self.armed = true;
        Ok(())
    }
}

impl RevocablePlatform for ScratchFake<'_> {
    fn revoke_after_halt(&mut self) -> Result<(), ()> {
        self.inner.revoke_after_halt()?;
        self.armed = false;
        if core::mem::take(&mut self.deny_cleanup_once) {
            return Err(());
        }
        self.backing.fill(0);
        Ok(())
    }
}

fn fixture(backing: &mut [u8; PAGE * PAGES]) -> (ScratchFake<'_>, ScratchpadPlan) {
    let assignment = DmaAssignment {
        bytes: PREFIX * (PAGES as u64 + 1),
        ..activation_assignment()
    };
    let plan = ScratchpadPlan::plan(assignment, PREFIX, 34, 1, false).unwrap();
    let mut inner = Fake::new();
    inner.regs[2] = (1 << 21) | (2 << 27);
    (
        ScratchFake {
            inner,
            backing,
            assignment,
            published: false,
            armed: false,
            deny_cleanup_once: true,
        },
        plan,
    )
}

#[test]
fn exact_scratchpads_are_published_before_activation_and_scrubbed_after_retry() {
    let mut backing = [0xa5; PAGE * PAGES];
    let (platform, plan) = fixture(&mut backing);
    let assignment = platform.assignment;
    let mut controller = Controller::start_checked_pci_with_scratchpads(
        platform,
        assignment,
        DMA,
        Some(plan),
        5,
        || Ok(()),
    )
    .unwrap();
    assert_eq!(controller.assignment.unwrap().bytes, PREFIX);
    controller.no_op(5).unwrap();
    let mut retire = ControllerRetirement::new(controller);
    assert_eq!(
        retire.withdraw(5),
        Err(ControllerRetirementPending::Revocation)
    );
    assert_eq!(retire.withdraw(5), Ok(()));
    drop(retire);
    assert!(backing.iter().all(|&byte| byte == 0));
}

#[test]
fn bad_scratchpad_geometry_or_queue_overlap_prevents_any_programming() {
    for case in 0..3 {
        let mut backing = [0xa5; PAGE * PAGES];
        let (mut platform, plan) = fixture(&mut backing);
        let assignment = platform.assignment;
        let dma = if case == 2 {
            DmaLayout {
                event_ring: TABLE,
                ..DMA
            }
        } else {
            DMA
        };
        if case == 1 {
            platform.inner.regs[2] = 1 << 27;
        }
        let Err(StartFailure::Untouched { error, platform }) =
            Controller::start_checked_pci_with_scratchpads(
                platform,
                assignment,
                dma,
                (case != 0).then_some(plan),
                5,
                || Ok(()),
            )
        else {
            panic!("must reject before programming")
        };
        assert_eq!(
            error,
            if case == 0 {
                Error::Unsupported
            } else {
                Error::InvalidDma
            }
        );
        assert!(!platform.published && !platform.armed);
        assert_eq!(platform.inner.mmio_writes, 0);
        assert!(platform.backing.iter().all(|&byte| byte == 0xa5));
    }
}
