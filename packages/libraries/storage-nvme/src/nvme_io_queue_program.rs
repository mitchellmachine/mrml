//! Ordered creation and cleanup of one NVMe I/O queue pair.

use crate::nvme_admin_command::execute_prepared_admin;
use crate::{
    ActiveNvmeAdminQueues, NvmeAdminCommandError, NvmeAdminCommandFailure,
    NvmeAdminCommandMemoryIo, NvmeAdminCommandStatus, NvmeAdminQueueDmaLayout,
    NvmeIoQueueDmaBackend, NvmeIoQueueDmaLayout, PreparedNvmeIoQueueDma,
};

const CREATE_IO_SUBMISSION_QUEUE_OPCODE: u32 = 0x01;
const CREATE_IO_COMPLETION_QUEUE_OPCODE: u32 = 0x05;
const DELETE_IO_COMPLETION_QUEUE_OPCODE: u32 = 0x04;
const PHYSICALLY_CONTIGUOUS: u32 = 1;

#[derive(Debug, Eq, PartialEq)]
pub struct ActiveNvmeIoQueues {
    admin_queues: ActiveNvmeAdminQueues,
    layout: NvmeIoQueueDmaLayout,
    submission_tail: u16,
    completion_head: u16,
    completion_phase: bool,
    next_command_id: u16,
}

impl ActiveNvmeIoQueues {
    pub const fn admin_queues(&self) -> &ActiveNvmeAdminQueues {
        &self.admin_queues
    }

    pub const fn layout(&self) -> NvmeIoQueueDmaLayout {
        self.layout
    }

    #[cfg(test)]
    pub(crate) const fn state(&self) -> (u16, u16, bool, u16) {
        (
            self.submission_tail,
            self.completion_head,
            self.completion_phase,
            self.next_command_id,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NvmeIoQueueCreateError {
    Admin(NvmeAdminCommandError),
    Rejected(NvmeAdminCommandStatus),
    DmaRemoval,
}

#[derive(Debug, Eq, PartialEq)]
pub enum NvmeIoQueueCreateFailure {
    Recovered {
        admin_queues: ActiveNvmeAdminQueues,
        error: NvmeIoQueueCreateError,
    },
    Quarantined {
        admin_layout: NvmeAdminQueueDmaLayout,
        io_layout: NvmeIoQueueDmaLayout,
        error: NvmeIoQueueCreateError,
    },
}

pub fn create_nvme_io_queue_pair<I: NvmeAdminCommandMemoryIo, B: NvmeIoQueueDmaBackend>(
    prepared: PreparedNvmeIoQueueDma,
    io: &mut I,
    dma: &mut B,
) -> Result<ActiveNvmeIoQueues, NvmeIoQueueCreateFailure> {
    let (admin_queues, layout) = prepared.into_parts();
    let completion_command = create_completion_command(layout);
    let completion = match execute_prepared_admin(admin_queues, completion_command, io) {
        Ok(completion) => completion,
        Err(failure) => return recover_without_created_queue(failure, layout, dma),
    };

    let submission_command = create_submission_command(layout);
    let submission = match execute_prepared_admin(completion.queues, submission_command, io) {
        Ok(submission) => submission,
        Err(failure) => return cleanup_created_completion_queue(failure, layout, io, dma),
    };
    Ok(ActiveNvmeIoQueues {
        admin_queues: submission.queues,
        layout,
        submission_tail: 0,
        completion_head: 0,
        completion_phase: true,
        next_command_id: 1,
    })
}

fn create_completion_command(layout: NvmeIoQueueDmaLayout) -> [u32; 16] {
    let mut command = [0; 16];
    command[0] = CREATE_IO_COMPLETION_QUEUE_OPCODE;
    command[6] = layout.completion.physical_base as u32;
    command[7] = (layout.completion.physical_base >> 32) as u32;
    command[10] = u32::from(layout.queue_id) | (u32::from(layout.queue_depth - 1) << 16);
    command[11] = PHYSICALLY_CONTIGUOUS;
    command
}

fn create_submission_command(layout: NvmeIoQueueDmaLayout) -> [u32; 16] {
    let mut command = [0; 16];
    command[0] = CREATE_IO_SUBMISSION_QUEUE_OPCODE;
    command[6] = layout.submission.physical_base as u32;
    command[7] = (layout.submission.physical_base >> 32) as u32;
    command[10] = u32::from(layout.queue_id) | (u32::from(layout.queue_depth - 1) << 16);
    command[11] = PHYSICALLY_CONTIGUOUS | (u32::from(layout.queue_id) << 16);
    command
}

fn delete_completion_command(queue_id: u16) -> [u32; 16] {
    let mut command = [0; 16];
    command[0] = DELETE_IO_COMPLETION_QUEUE_OPCODE;
    command[10] = u32::from(queue_id);
    command
}

fn recover_without_created_queue<B: NvmeIoQueueDmaBackend>(
    failure: NvmeAdminCommandFailure,
    layout: NvmeIoQueueDmaLayout,
    dma: &mut B,
) -> Result<ActiveNvmeIoQueues, NvmeIoQueueCreateFailure> {
    match recoverable_admin_failure(failure) {
        Ok((admin_queues, error)) => {
            if dma.remove_layout(layout).is_err() {
                return Err(quarantined(
                    admin_queues.layout(),
                    layout,
                    NvmeIoQueueCreateError::DmaRemoval,
                ));
            }
            Err(NvmeIoQueueCreateFailure::Recovered {
                admin_queues,
                error,
            })
        }
        Err((admin_layout, error)) => Err(quarantined(admin_layout, layout, error)),
    }
}

fn cleanup_created_completion_queue<I: NvmeAdminCommandMemoryIo, B: NvmeIoQueueDmaBackend>(
    failure: NvmeAdminCommandFailure,
    layout: NvmeIoQueueDmaLayout,
    io: &mut I,
    dma: &mut B,
) -> Result<ActiveNvmeIoQueues, NvmeIoQueueCreateFailure> {
    let (admin_queues, original_error) = match recoverable_admin_failure(failure) {
        Ok(recoverable) => recoverable,
        Err((admin_layout, error)) => return Err(quarantined(admin_layout, layout, error)),
    };
    let deleted = match execute_prepared_admin(
        admin_queues,
        delete_completion_command(layout.queue_id),
        io,
    ) {
        Ok(deleted) => deleted,
        Err(failure) => {
            let (admin_layout, error) = admin_failure_for_quarantine(failure);
            return Err(quarantined(admin_layout, layout, error));
        }
    };
    if dma.remove_layout(layout).is_err() {
        return Err(quarantined(
            deleted.queues.layout(),
            layout,
            NvmeIoQueueCreateError::DmaRemoval,
        ));
    }
    Err(NvmeIoQueueCreateFailure::Recovered {
        admin_queues: deleted.queues,
        error: original_error,
    })
}

fn recoverable_admin_failure(
    failure: NvmeAdminCommandFailure,
) -> Result<
    (ActiveNvmeAdminQueues, NvmeIoQueueCreateError),
    (NvmeAdminQueueDmaLayout, NvmeIoQueueCreateError),
> {
    match failure {
        NvmeAdminCommandFailure::Untouched { queues, error }
        | NvmeAdminCommandFailure::InvalidResult { queues, error } => {
            Ok((queues, NvmeIoQueueCreateError::Admin(error)))
        }
        NvmeAdminCommandFailure::Rejected { queues, status } => {
            Ok((queues, NvmeIoQueueCreateError::Rejected(status)))
        }
        NvmeAdminCommandFailure::Quarantined { layout, error } => {
            Err((layout, NvmeIoQueueCreateError::Admin(error)))
        }
    }
}

fn admin_failure_for_quarantine(
    failure: NvmeAdminCommandFailure,
) -> (NvmeAdminQueueDmaLayout, NvmeIoQueueCreateError) {
    match failure {
        NvmeAdminCommandFailure::Untouched { queues, error }
        | NvmeAdminCommandFailure::InvalidResult { queues, error } => {
            (queues.layout(), NvmeIoQueueCreateError::Admin(error))
        }
        NvmeAdminCommandFailure::Rejected { queues, status } => {
            (queues.layout(), NvmeIoQueueCreateError::Rejected(status))
        }
        NvmeAdminCommandFailure::Quarantined { layout, error } => {
            (layout, NvmeIoQueueCreateError::Admin(error))
        }
    }
}

const fn quarantined(
    admin_layout: NvmeAdminQueueDmaLayout,
    io_layout: NvmeIoQueueDmaLayout,
    error: NvmeIoQueueCreateError,
) -> NvmeIoQueueCreateFailure {
    NvmeIoQueueCreateFailure::Quarantined {
        admin_layout,
        io_layout,
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        prepare_nvme_io_queue_dma, ActiveNvmeAdminQueues, NvmeAdminQueueDmaLayout, NvmeDmaRegion,
        NvmeIoQueueDmaRequest, NvmeIoQueueGrant,
    };
    use mrml_kernel::{CapabilitySpace, ObjectId, Rights};

    #[derive(Default)]
    struct Dma {
        installed: Option<NvmeIoQueueDmaLayout>,
        reject_remove: bool,
    }

    impl NvmeIoQueueDmaBackend for Dma {
        fn install_zeroed_layout(&mut self, layout: NvmeIoQueueDmaLayout) -> Result<(), ()> {
            self.installed = Some(layout);
            Ok(())
        }
        fn remove_layout(&mut self, layout: NvmeIoQueueDmaLayout) -> Result<(), ()> {
            if self.reject_remove || self.installed != Some(layout) {
                return Err(());
            }
            self.installed = None;
            Ok(())
        }
    }

    struct AdminMemory {
        submission: [u32; 1024],
        completion: [u32; 1024],
        submission_doorbells: usize,
        completion_doorbells: usize,
        reject_command: Option<usize>,
        fail_doorbell: Option<usize>,
        total_doorbells: usize,
    }

    impl Default for AdminMemory {
        fn default() -> Self {
            Self {
                submission: [0; 1024],
                completion: [0; 1024],
                submission_doorbells: 0,
                completion_doorbells: 0,
                reject_command: None,
                fail_doorbell: None,
                total_doorbells: 0,
            }
        }
    }

    impl NvmeAdminCommandMemoryIo for AdminMemory {
        fn read_u32(&mut self, region: crate::NvmeDmaRegion, offset: u64) -> Result<u32, ()> {
            let index = usize::try_from(offset / 4).map_err(|_| ())?;
            match region.memory_object.0 {
                80 => self.submission.get(index).copied().ok_or(()),
                81 => self.completion.get(index).copied().ok_or(()),
                _ => Err(()),
            }
        }
        fn write_u32(
            &mut self,
            region: crate::NvmeDmaRegion,
            offset: u64,
            value: u32,
        ) -> Result<(), ()> {
            if region.memory_object != ObjectId(80) {
                return Err(());
            }
            let index = usize::try_from(offset / 4).map_err(|_| ())?;
            *self.submission.get_mut(index).ok_or(())? = value;
            Ok(())
        }
        fn ring_doorbell(&mut self, offset: u64, _: u32) -> Result<(), ()> {
            if self.fail_doorbell == Some(self.total_doorbells) {
                return Err(());
            }
            self.total_doorbells += 1;
            match offset {
                0x1000 => {
                    let command = self.submission_doorbells;
                    let cid = (self.submission[command * 16] >> 16) & 0xffff;
                    let completion = command * 4;
                    self.completion[completion + 2] = 0;
                    self.completion[completion + 3] = cid
                        | (1 << 16)
                        | if self.reject_command == Some(command) {
                            1 << 17
                        } else {
                            0
                        };
                    self.submission_doorbells += 1;
                }
                0x1004 => self.completion_doorbells += 1,
                _ => return Err(()),
            }
            Ok(())
        }
        fn delay_500_micros(&mut self) {}
    }

    fn make_prepared(dma: &mut Dma) -> PreparedNvmeIoQueueDma {
        let rights = Rights::PIN
            .union(Rights::MAP)
            .union(Rights::READ)
            .union(Rights::WRITE);
        let mut capabilities = CapabilitySpace::<3>::new();
        let controller_capability = capabilities.insert(ObjectId(71), Rights::CONTROL).unwrap();
        let submission_capability = capabilities.insert(ObjectId(90), rights).unwrap();
        let completion_capability = capabilities.insert(ObjectId(91), rights).unwrap();
        let admin = NvmeAdminQueueDmaLayout {
            controller_object: ObjectId(71),
            configuration_generation: 11,
            mapping_generation: 9,
            queue_depth: 64,
            timeout_500ms_units: 1,
            doorbell_stride_bytes: 4,
            submission: NvmeDmaRegion {
                memory_object: ObjectId(80),
                allocation_generation: 1,
                physical_base: 0x1000,
                bytes: 4096,
            },
            completion: NvmeDmaRegion {
                memory_object: ObjectId(81),
                allocation_generation: 2,
                physical_base: 0x2000,
                bytes: 4096,
            },
            dma_generation: 3,
        };
        let grant = NvmeIoQueueGrant {
            queues: ActiveNvmeAdminQueues::from_state(admin),
            submission_queues: 1,
            completion_queues: 1,
        };
        let request = NvmeIoQueueDmaRequest {
            controller_capability,
            submission_capability,
            completion_capability,
            queue_id: 1,
            queue_depth: 64,
            submission: NvmeDmaRegion {
                memory_object: ObjectId(90),
                allocation_generation: 4,
                physical_base: 0x3000,
                bytes: 4096,
            },
            completion: NvmeDmaRegion {
                memory_object: ObjectId(91),
                allocation_generation: 5,
                physical_base: 0x4000,
                bytes: 4096,
            },
            dma_generation: 6,
        };
        prepare_nvme_io_queue_dma(&capabilities, grant, request, dma).unwrap()
    }

    #[test]
    fn creates_completion_before_submission_and_publishes_active_pair() {
        let mut dma = Dma::default();
        let prepared = make_prepared(&mut dma);
        let mut memory = AdminMemory::default();
        let active = create_nvme_io_queue_pair(prepared, &mut memory, &mut dma).unwrap();
        assert_eq!(
            memory.submission[0] & 0xff,
            CREATE_IO_COMPLETION_QUEUE_OPCODE
        );
        assert_eq!(
            memory.submission[16] & 0xff,
            CREATE_IO_SUBMISSION_QUEUE_OPCODE
        );
        assert_eq!(active.layout().queue_id, 1);
        assert_eq!(active.state(), (0, 0, true, 1));
        assert_eq!(memory.submission_doorbells, 2);
        assert!(dma.installed.is_some());
    }

    #[test]
    fn rejected_completion_queue_removes_dma_and_recovers_admin_queue() {
        let mut dma = Dma::default();
        let prepared = make_prepared(&mut dma);
        let mut memory = AdminMemory {
            reject_command: Some(0),
            ..AdminMemory::default()
        };
        let failure = create_nvme_io_queue_pair(prepared, &mut memory, &mut dma).unwrap_err();
        assert!(matches!(
            failure,
            NvmeIoQueueCreateFailure::Recovered { .. }
        ));
        assert_eq!(memory.submission_doorbells, 1);
        assert_eq!(dma.installed, None);
    }

    #[test]
    fn rejected_submission_queue_deletes_completion_before_dma_removal() {
        let mut dma = Dma::default();
        let prepared = make_prepared(&mut dma);
        let mut memory = AdminMemory {
            reject_command: Some(1),
            ..AdminMemory::default()
        };
        let failure = create_nvme_io_queue_pair(prepared, &mut memory, &mut dma).unwrap_err();
        assert!(matches!(
            failure,
            NvmeIoQueueCreateFailure::Recovered { .. }
        ));
        assert_eq!(
            memory.submission[32] & 0xff,
            DELETE_IO_COMPLETION_QUEUE_OPCODE
        );
        assert_eq!(memory.submission_doorbells, 3);
        assert_eq!(dma.installed, None);
    }

    #[test]
    fn uncertain_publication_or_dma_removal_quarantines_both_layouts() {
        let mut dma = Dma::default();
        let prepared = make_prepared(&mut dma);
        let mut memory = AdminMemory {
            fail_doorbell: Some(0),
            ..AdminMemory::default()
        };
        assert!(matches!(
            create_nvme_io_queue_pair(prepared, &mut memory, &mut dma),
            Err(NvmeIoQueueCreateFailure::Quarantined { .. })
        ));
        let mut dma = Dma {
            installed: None,
            reject_remove: false,
        };
        let prepared = make_prepared(&mut dma);
        dma.reject_remove = true;
        let mut memory = AdminMemory {
            reject_command: Some(0),
            ..AdminMemory::default()
        };
        assert!(matches!(
            create_nvme_io_queue_pair(prepared, &mut memory, &mut dma),
            Err(NvmeIoQueueCreateFailure::Quarantined {
                error: NvmeIoQueueCreateError::DmaRemoval,
                ..
            })
        ));
    }
}
