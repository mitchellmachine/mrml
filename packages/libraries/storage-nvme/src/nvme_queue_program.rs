//! Bounded programming and activation of the initial NVMe admin queues.

use crate::{
    InstalledNvmeAdminQueueDma, NvmeAdminQueueDmaLayout, NVME_CC_OFFSET, NVME_CSTS_OFFSET,
};

pub const NVME_AQA_OFFSET: u64 = 0x24;
pub const NVME_ASQ_OFFSET: u64 = 0x28;
pub const NVME_ACQ_OFFSET: u64 = 0x30;

const CC_ENABLE: u32 = 1;
const CC_IO_SUBMISSION_ENTRY_SIZE: u32 = 6 << 16;
const CC_IO_COMPLETION_ENTRY_SIZE: u32 = 4 << 20;
const CSTS_READY: u32 = 1;
const CSTS_FATAL: u32 = 1 << 1;
const POLLS_PER_500_MS: u32 = 1000;

#[derive(Debug, Eq, PartialEq)]
pub struct ActiveNvmeAdminQueues {
    layout: NvmeAdminQueueDmaLayout,
}

impl ActiveNvmeAdminQueues {
    pub const fn layout(&self) -> NvmeAdminQueueDmaLayout {
        self.layout
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NvmeQueueProgramError {
    ControllerNotDisabled,
    InvalidLayout,
    RegisterRead,
    RegisterWrite,
    VerificationFailed,
    FatalStatus,
    EnableTimeout,
}

#[derive(Debug, Eq, PartialEq)]
pub enum NvmeQueueProgramFailure {
    Untouched {
        owner: InstalledNvmeAdminQueueDma,
        error: NvmeQueueProgramError,
    },
    Quarantined {
        layout: NvmeAdminQueueDmaLayout,
        error: NvmeQueueProgramError,
    },
}

impl NvmeQueueProgramFailure {
    pub const fn error(&self) -> NvmeQueueProgramError {
        match self {
            Self::Untouched { error, .. } | Self::Quarantined { error, .. } => *error,
        }
    }

    pub fn into_untouched_owner(self) -> Option<InstalledNvmeAdminQueueDma> {
        match self {
            Self::Untouched { owner, .. } => Some(owner),
            Self::Quarantined { .. } => None,
        }
    }
}

pub trait NvmeAdminQueueRegisterIo {
    fn read_u32(&mut self, offset: u64) -> Result<u32, ()>;
    fn read_u64(&mut self, offset: u64) -> Result<u64, ()>;
    fn write_u32(&mut self, offset: u64, value: u32) -> Result<(), ()>;
    fn write_u64(&mut self, offset: u64, value: u64) -> Result<(), ()>;
    fn delay_500_micros(&mut self);
}

pub fn enable_nvme_admin_queues<I: NvmeAdminQueueRegisterIo>(
    owner: InstalledNvmeAdminQueueDma,
    io: &mut I,
) -> Result<ActiveNvmeAdminQueues, NvmeQueueProgramFailure> {
    let layout = owner.layout();
    if layout.queue_depth < 2
        || layout.queue_depth > 4096
        || layout.timeout_500ms_units == 0
        || layout.submission.bytes != 4096
        || layout.completion.bytes != 4096
        || layout.submission.physical_base & 0xfff != 0
        || layout.completion.physical_base & 0xfff != 0
    {
        return Err(NvmeQueueProgramFailure::Untouched {
            owner,
            error: NvmeQueueProgramError::InvalidLayout,
        });
    }
    let cc = match io.read_u32(NVME_CC_OFFSET) {
        Ok(value) => value,
        Err(()) => {
            return Err(NvmeQueueProgramFailure::Untouched {
                owner,
                error: NvmeQueueProgramError::RegisterRead,
            });
        }
    };
    let status = match io.read_u32(NVME_CSTS_OFFSET) {
        Ok(value) => value,
        Err(()) => {
            return Err(NvmeQueueProgramFailure::Untouched {
                owner,
                error: NvmeQueueProgramError::RegisterRead,
            });
        }
    };
    if cc & CC_ENABLE != 0 || status & CSTS_READY != 0 {
        return Err(NvmeQueueProgramFailure::Untouched {
            owner,
            error: NvmeQueueProgramError::ControllerNotDisabled,
        });
    }

    let zero_based = u32::from(layout.queue_depth - 1);
    let aqa = zero_based | (zero_based << 16);
    let layout = owner.into_layout();
    if io.write_u32(NVME_AQA_OFFSET, aqa).is_err()
        || io
            .write_u64(NVME_ASQ_OFFSET, layout.submission.physical_base)
            .is_err()
        || io
            .write_u64(NVME_ACQ_OFFSET, layout.completion.physical_base)
            .is_err()
    {
        return Err(quarantined(layout, NvmeQueueProgramError::RegisterWrite));
    }
    if io.read_u32(NVME_AQA_OFFSET) != Ok(aqa)
        || io.read_u64(NVME_ASQ_OFFSET) != Ok(layout.submission.physical_base)
        || io.read_u64(NVME_ACQ_OFFSET) != Ok(layout.completion.physical_base)
    {
        return Err(quarantined(
            layout,
            NvmeQueueProgramError::VerificationFailed,
        ));
    }

    let enabled = CC_IO_SUBMISSION_ENTRY_SIZE | CC_IO_COMPLETION_ENTRY_SIZE | CC_ENABLE;
    if io.write_u32(NVME_CC_OFFSET, enabled).is_err() {
        return Err(quarantined(layout, NvmeQueueProgramError::RegisterWrite));
    }
    let polls = u32::from(layout.timeout_500ms_units) * POLLS_PER_500_MS;
    for _ in 0..polls {
        let status = match io.read_u32(NVME_CSTS_OFFSET) {
            Ok(status) => status,
            Err(()) => return Err(quarantined(layout, NvmeQueueProgramError::RegisterRead)),
        };
        if status & CSTS_FATAL != 0 {
            return Err(quarantined(layout, NvmeQueueProgramError::FatalStatus));
        }
        if status & CSTS_READY != 0 {
            return Ok(ActiveNvmeAdminQueues { layout });
        }
        io.delay_500_micros();
    }
    Err(quarantined(layout, NvmeQueueProgramError::EnableTimeout))
}

const fn quarantined(
    layout: NvmeAdminQueueDmaLayout,
    error: NvmeQueueProgramError,
) -> NvmeQueueProgramFailure {
    NvmeQueueProgramFailure::Quarantined { layout, error }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NvmeDmaRegion;
    use mrml_kernel::ObjectId;

    struct Registers {
        cc: u32,
        status: [u32; 3],
        status_reads: usize,
        aqa: u32,
        asq: u64,
        acq: u64,
        writes: usize,
        reject_write: Option<usize>,
        corrupt_readback: bool,
        delays: u32,
    }

    impl NvmeAdminQueueRegisterIo for Registers {
        fn read_u32(&mut self, offset: u64) -> Result<u32, ()> {
            match offset {
                NVME_CC_OFFSET => Ok(self.cc),
                NVME_CSTS_OFFSET => {
                    let value = self.status[self.status_reads.min(2)];
                    self.status_reads += 1;
                    Ok(value)
                }
                NVME_AQA_OFFSET => Ok(if self.corrupt_readback {
                    self.aqa ^ 1
                } else {
                    self.aqa
                }),
                _ => Err(()),
            }
        }
        fn read_u64(&mut self, offset: u64) -> Result<u64, ()> {
            match offset {
                NVME_ASQ_OFFSET => Ok(self.asq),
                NVME_ACQ_OFFSET => Ok(self.acq),
                _ => Err(()),
            }
        }
        fn write_u32(&mut self, offset: u64, value: u32) -> Result<(), ()> {
            if self.reject_write == Some(self.writes) {
                return Err(());
            }
            self.writes += 1;
            match offset {
                NVME_AQA_OFFSET => self.aqa = value,
                NVME_CC_OFFSET => self.cc = value,
                _ => return Err(()),
            }
            Ok(())
        }
        fn write_u64(&mut self, offset: u64, value: u64) -> Result<(), ()> {
            if self.reject_write == Some(self.writes) {
                return Err(());
            }
            self.writes += 1;
            match offset {
                NVME_ASQ_OFFSET => self.asq = value,
                NVME_ACQ_OFFSET => self.acq = value,
                _ => return Err(()),
            }
            Ok(())
        }
        fn delay_500_micros(&mut self) {
            self.delays += 1;
        }
    }

    fn owner() -> InstalledNvmeAdminQueueDma {
        InstalledNvmeAdminQueueDma::from_layout(NvmeAdminQueueDmaLayout {
            controller_object: ObjectId(71),
            configuration_generation: 11,
            mapping_generation: 9,
            queue_depth: 64,
            timeout_500ms_units: 1,
            submission: NvmeDmaRegion {
                memory_object: ObjectId(80),
                allocation_generation: 3,
                physical_base: 0x1000,
                bytes: 4096,
            },
            completion: NvmeDmaRegion {
                memory_object: ObjectId(81),
                allocation_generation: 4,
                physical_base: 0x2000,
                bytes: 4096,
            },
            dma_generation: 12,
        })
    }

    fn registers() -> Registers {
        Registers {
            cc: 0,
            status: [0, 0, CSTS_READY],
            status_reads: 0,
            aqa: 0,
            asq: 0,
            acq: 0,
            writes: 0,
            reject_write: None,
            corrupt_readback: false,
            delays: 0,
        }
    }

    #[test]
    fn programs_verifies_enables_and_waits_for_ready() {
        let mut io = registers();
        let active = enable_nvme_admin_queues(owner(), &mut io).unwrap();
        assert_eq!(active.layout().queue_depth, 64);
        assert_eq!(io.aqa, 63 | (63 << 16));
        assert_eq!(io.asq, 0x1000);
        assert_eq!(io.acq, 0x2000);
        assert_eq!(
            io.cc,
            CC_IO_SUBMISSION_ENTRY_SIZE | CC_IO_COMPLETION_ENTRY_SIZE | 1
        );
        assert_eq!(io.delays, 1);
    }

    #[test]
    fn enabled_or_ready_controller_leaves_owner_untouched() {
        for (cc, status) in [(1, 0), (0, 1)] {
            let mut io = registers();
            io.cc = cc;
            io.status = [status; 3];
            let failure = enable_nvme_admin_queues(owner(), &mut io).unwrap_err();
            assert_eq!(
                failure.error(),
                NvmeQueueProgramError::ControllerNotDisabled
            );
            assert!(failure.into_untouched_owner().is_some());
            assert_eq!(io.writes, 0);
        }
    }

    #[test]
    fn write_or_readback_failure_quarantines_programmed_dma() {
        let mut rejected = registers();
        rejected.reject_write = Some(1);
        let failure = enable_nvme_admin_queues(owner(), &mut rejected).unwrap_err();
        assert_eq!(failure.error(), NvmeQueueProgramError::RegisterWrite);
        assert!(failure.into_untouched_owner().is_none());
        let mut corrupt = registers();
        corrupt.corrupt_readback = true;
        assert_eq!(
            enable_nvme_admin_queues(owner(), &mut corrupt)
                .unwrap_err()
                .error(),
            NvmeQueueProgramError::VerificationFailed
        );
    }

    #[test]
    fn fatal_or_timeout_never_publishes_active_queues() {
        let mut fatal = registers();
        fatal.status = [0, CSTS_FATAL, CSTS_FATAL];
        assert_eq!(
            enable_nvme_admin_queues(owner(), &mut fatal)
                .unwrap_err()
                .error(),
            NvmeQueueProgramError::FatalStatus
        );
        let mut timeout = registers();
        timeout.status = [0; 3];
        assert_eq!(
            enable_nvme_admin_queues(owner(), &mut timeout)
                .unwrap_err()
                .error(),
            NvmeQueueProgramError::EnableTimeout
        );
        assert_eq!(timeout.delays, 1000);
    }
}
