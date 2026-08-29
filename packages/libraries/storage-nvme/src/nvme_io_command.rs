//! Semantic single-outstanding NVMe namespace read, write, and flush execution.

use crate::{
    ActiveNvmeIoQueues, NvmeAdminCommandStatus, NvmeAdminQueueDmaLayout, NvmeDmaRegion,
    NvmeIoQueueDmaLayout, NvmeNamespaceIdentity, NvmeTransferDirection, PreparedNvmePrps,
};
use mrml_kernel::{Capability, CapabilityError, CapabilitySpace, ObjectId, Rights};

const FLUSH_OPCODE: u32 = 0x00;
const WRITE_OPCODE: u32 = 0x01;
const READ_OPCODE: u32 = 0x02;
const SUBMISSION_ENTRY_BYTES: u64 = 64;
const COMPLETION_ENTRY_BYTES: u64 = 16;
const DOORBELL_BASE: u64 = 0x1000;
const POLLS_PER_500_MS: u32 = 1000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NvmeIoOperation {
    Read,
    Write,
    Flush,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvmeIoRequest {
    pub namespace_capability: Capability,
    pub namespace_object: ObjectId,
    pub namespace: NvmeNamespaceIdentity,
    pub operation: NvmeIoOperation,
    pub starting_lba: u64,
    pub block_count: u32,
    pub prps: Option<PreparedNvmePrps>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct CompletedNvmeIo {
    pub queues: ActiveNvmeIoQueues,
    pub prps: Option<PreparedNvmePrps>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NvmeIoCommandError {
    NamespaceCapability(CapabilityError),
    WrongNamespaceObject,
    NamespaceGenerationMismatch,
    InvalidBlockRange,
    MissingPrps,
    UnexpectedPrps,
    WrongPrpDirection,
    TransferMismatch,
    DmaOverlapsQueues,
    InvalidQueueState,
    MemoryRead,
    MemoryWrite,
    VerificationFailed,
    DoorbellWrite,
    CompletionTimeout,
    MalformedCompletion,
}

#[derive(Debug, Eq, PartialEq)]
pub enum NvmeIoCommandFailure {
    Untouched {
        queues: ActiveNvmeIoQueues,
        request: NvmeIoRequest,
        error: NvmeIoCommandError,
    },
    Rejected {
        queues: ActiveNvmeIoQueues,
        request: NvmeIoRequest,
        status: NvmeAdminCommandStatus,
    },
    Quarantined {
        admin_layout: NvmeAdminQueueDmaLayout,
        io_layout: NvmeIoQueueDmaLayout,
        request: NvmeIoRequest,
        error: NvmeIoCommandError,
    },
}

pub trait NvmeIoCommandMemoryIo {
    /// Reads completion/queue memory with device-to-CPU acquire ordering.
    fn read_u32(&mut self, region: NvmeDmaRegion, offset: u64) -> Result<u32, ()>;
    fn write_u32(&mut self, region: NvmeDmaRegion, offset: u64, value: u32) -> Result<(), ()>;
    /// Publishes preceding queue-memory writes before the MMIO doorbell.
    fn ring_doorbell(&mut self, offset: u64, value: u32) -> Result<(), ()>;
    fn delay_500_micros(&mut self);
}

pub fn execute_nvme_io<const N: usize, I: NvmeIoCommandMemoryIo>(
    capabilities: &CapabilitySpace<N>,
    queues: ActiveNvmeIoQueues,
    request: NvmeIoRequest,
    io: &mut I,
) -> Result<CompletedNvmeIo, NvmeIoCommandFailure> {
    let required = match request.operation {
        NvmeIoOperation::Read => Rights::READ,
        NvmeIoOperation::Write | NvmeIoOperation::Flush => Rights::WRITE,
    };
    let authorized = match capabilities.authorize_exact(request.namespace_capability, required) {
        Ok(object) => object,
        Err(error) => {
            return Err(untouched(
                queues,
                request,
                NvmeIoCommandError::NamespaceCapability(error),
            ))
        }
    };
    if authorized != request.namespace_object {
        return Err(untouched(
            queues,
            request,
            NvmeIoCommandError::WrongNamespaceObject,
        ));
    }
    let layout = queues.layout();
    if request.namespace.configuration_generation != layout.configuration_generation
        || request.namespace.mapping_generation != layout.mapping_generation
        || request.namespace.namespace_id == 0
    {
        return Err(untouched(
            queues,
            request,
            NvmeIoCommandError::NamespaceGenerationMismatch,
        ));
    }

    let mut command = [0_u32; 16];
    command[1] = request.namespace.namespace_id;
    match request.operation {
        NvmeIoOperation::Flush => {
            if request.starting_lba != 0 || request.block_count != 0 {
                return Err(untouched(
                    queues,
                    request,
                    NvmeIoCommandError::InvalidBlockRange,
                ));
            }
            if request.prps.is_some() {
                return Err(untouched(
                    queues,
                    request,
                    NvmeIoCommandError::UnexpectedPrps,
                ));
            }
            command[0] = FLUSH_OPCODE;
        }
        NvmeIoOperation::Read | NvmeIoOperation::Write => {
            if let Err(error) = validate_block_range(&request) {
                return Err(untouched(queues, request, error));
            }
            let prps = match request.prps {
                Some(prps) => prps,
                None => return Err(untouched(queues, request, NvmeIoCommandError::MissingPrps)),
            };
            let expected_direction = if request.operation == NvmeIoOperation::Read {
                NvmeTransferDirection::DeviceWrites
            } else {
                NvmeTransferDirection::DeviceReads
            };
            if prps.request().direction != expected_direction {
                return Err(untouched(
                    queues,
                    request,
                    NvmeIoCommandError::WrongPrpDirection,
                ));
            }
            let transfer_bytes = match u64::from(request.block_count)
                .checked_mul(u64::from(request.namespace.logical_block_bytes))
            {
                Some(bytes) => bytes,
                None => {
                    return Err(untouched(
                        queues,
                        request,
                        NvmeIoCommandError::TransferMismatch,
                    ));
                }
            };
            if prps.request().transfer_bytes != transfer_bytes {
                return Err(untouched(
                    queues,
                    request,
                    NvmeIoCommandError::TransferMismatch,
                ));
            }
            if prps_overlap_queues(prps, queues.admin_queues().layout(), layout) {
                return Err(untouched(
                    queues,
                    request,
                    NvmeIoCommandError::DmaOverlapsQueues,
                ));
            }
            command[0] = if request.operation == NvmeIoOperation::Read {
                READ_OPCODE
            } else {
                WRITE_OPCODE
            };
            command[6] = prps.prp1 as u32;
            command[7] = (prps.prp1 >> 32) as u32;
            command[8] = prps.prp2 as u32;
            command[9] = (prps.prp2 >> 32) as u32;
            command[10] = request.starting_lba as u32;
            command[11] = (request.starting_lba >> 32) as u32;
            command[12] = request.block_count - 1;
        }
    }
    execute_prepared_io(queues, request, command, io)
}

fn validate_block_range(request: &NvmeIoRequest) -> Result<(), NvmeIoCommandError> {
    if request.block_count == 0
        || request.block_count > request.namespace.maximum_transfer_blocks
        || request.starting_lba >= request.namespace.block_count
        || request
            .starting_lba
            .checked_add(u64::from(request.block_count))
            .is_none_or(|end| end > request.namespace.block_count)
    {
        return Err(NvmeIoCommandError::InvalidBlockRange);
    }
    Ok(())
}

fn execute_prepared_io<I: NvmeIoCommandMemoryIo>(
    queues: ActiveNvmeIoQueues,
    request: NvmeIoRequest,
    mut command: [u32; 16],
    io: &mut I,
) -> Result<CompletedNvmeIo, NvmeIoCommandFailure> {
    let layout = queues.layout();
    let admin_layout = queues.admin_queues().layout();
    let (tail, head, phase, command_id) = queues.state();
    if tail >= layout.queue_depth || head >= layout.queue_depth || command_id == 0 {
        return Err(untouched(
            queues,
            request,
            NvmeIoCommandError::InvalidQueueState,
        ));
    }
    command[0] |= u32::from(command_id) << 16;
    let submission_offset = u64::from(tail) * SUBMISSION_ENTRY_BYTES;
    let completion_offset = u64::from(head) * COMPLETION_ENTRY_BYTES;
    for (index, value) in command.into_iter().enumerate() {
        if io
            .write_u32(
                layout.submission,
                submission_offset + index as u64 * 4,
                value,
            )
            .is_err()
        {
            return Err(quarantined(
                admin_layout,
                layout,
                request,
                NvmeIoCommandError::MemoryWrite,
            ));
        }
    }
    for (index, expected) in command.into_iter().enumerate() {
        if io.read_u32(layout.submission, submission_offset + index as u64 * 4) != Ok(expected) {
            return Err(quarantined(
                admin_layout,
                layout,
                request,
                NvmeIoCommandError::VerificationFailed,
            ));
        }
    }
    let next_tail = if tail + 1 == layout.queue_depth {
        0
    } else {
        tail + 1
    };
    let submission_doorbell =
        DOORBELL_BASE + u64::from(2 * layout.queue_id) * u64::from(layout.doorbell_stride_bytes);
    if io
        .ring_doorbell(submission_doorbell, u32::from(next_tail))
        .is_err()
    {
        return Err(quarantined(
            admin_layout,
            layout,
            request,
            NvmeIoCommandError::DoorbellWrite,
        ));
    }
    let polls = u32::from(layout.timeout_500ms_units) * POLLS_PER_500_MS;
    let mut completion = None;
    for _ in 0..polls {
        let dword3 = match io.read_u32(layout.completion, completion_offset + 12) {
            Ok(value) => value,
            Err(()) => {
                return Err(quarantined(
                    admin_layout,
                    layout,
                    request,
                    NvmeIoCommandError::MemoryRead,
                ));
            }
        };
        if (dword3 & (1 << 16) != 0) == phase {
            completion = Some(dword3);
            break;
        }
        io.delay_500_micros();
    }
    let completion = match completion {
        Some(value) => value,
        None => {
            return Err(quarantined(
                admin_layout,
                layout,
                request,
                NvmeIoCommandError::CompletionTimeout,
            ))
        }
    };
    let queue = match io.read_u32(layout.completion, completion_offset + 8) {
        Ok(value) => value,
        Err(()) => {
            return Err(quarantined(
                admin_layout,
                layout,
                request,
                NvmeIoCommandError::MemoryRead,
            ));
        }
    };
    if u16::try_from(completion & 0xffff).unwrap() != command_id
        || queue >> 16 != u32::from(layout.queue_id)
        || queue & 0xffff >= u32::from(layout.queue_depth)
    {
        return Err(quarantined(
            admin_layout,
            layout,
            request,
            NvmeIoCommandError::MalformedCompletion,
        ));
    }
    let queues = queues.advance();
    let (_, next_head, _, _) = queues.state();
    let completion_doorbell = DOORBELL_BASE
        + u64::from(2 * layout.queue_id + 1) * u64::from(layout.doorbell_stride_bytes);
    if io
        .ring_doorbell(completion_doorbell, u32::from(next_head))
        .is_err()
    {
        return Err(quarantined(
            admin_layout,
            layout,
            request,
            NvmeIoCommandError::DoorbellWrite,
        ));
    }
    let status = NvmeAdminCommandStatus {
        status_code: ((completion >> 17) & 0xff) as u8,
        status_code_type: ((completion >> 25) & 0x7) as u8,
        command_retry_delay: ((completion >> 28) & 0x3) as u8,
        more: completion & (1 << 30) != 0,
        do_not_retry: completion & (1 << 31) != 0,
    };
    if status.status_code != 0 || status.status_code_type != 0 {
        return Err(NvmeIoCommandFailure::Rejected {
            queues,
            request,
            status,
        });
    }
    Ok(CompletedNvmeIo {
        queues,
        prps: request.prps,
    })
}

fn prps_overlap_queues(
    prps: PreparedNvmePrps,
    admin: NvmeAdminQueueDmaLayout,
    io: NvmeIoQueueDmaLayout,
) -> bool {
    let request = prps.request();
    [
        admin.submission,
        admin.completion,
        io.submission,
        io.completion,
    ]
    .into_iter()
    .any(|queue| {
        overlaps(request.data, queue) || request.prp_list.is_some_and(|list| overlaps(list, queue))
    })
}

fn overlaps(left: NvmeDmaRegion, right: NvmeDmaRegion) -> bool {
    left.physical_base < right.physical_base + right.bytes
        && right.physical_base < left.physical_base + left.bytes
}

const fn untouched(
    queues: ActiveNvmeIoQueues,
    request: NvmeIoRequest,
    error: NvmeIoCommandError,
) -> NvmeIoCommandFailure {
    NvmeIoCommandFailure::Untouched {
        queues,
        request,
        error,
    }
}

const fn quarantined(
    admin_layout: NvmeAdminQueueDmaLayout,
    io_layout: NvmeIoQueueDmaLayout,
    request: NvmeIoRequest,
    error: NvmeIoCommandError,
) -> NvmeIoCommandFailure {
    NvmeIoCommandFailure::Quarantined {
        admin_layout,
        io_layout,
        request,
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{prepare_nvme_prps, ActiveNvmeAdminQueues, NvmePrpMemoryIo, NvmePrpRequest};

    struct PrpMemory {
        data: [u64; 131072],
        list: [u64; 512],
    }

    impl Default for PrpMemory {
        fn default() -> Self {
            Self {
                data: [0; 131072],
                list: [0; 512],
            }
        }
    }

    impl NvmePrpMemoryIo for PrpMemory {
        fn read_u64(&mut self, region: NvmeDmaRegion, offset: u64) -> Result<u64, ()> {
            let index = usize::try_from(offset / 8).map_err(|_| ())?;
            match region.memory_object.0 {
                100 => self.data.get(index).copied().ok_or(()),
                101 => self.list.get(index).copied().ok_or(()),
                _ => Err(()),
            }
        }
        fn write_u64(&mut self, region: NvmeDmaRegion, offset: u64, value: u64) -> Result<(), ()> {
            if region.memory_object != ObjectId(101) {
                return Err(());
            }
            let index = usize::try_from(offset / 8).map_err(|_| ())?;
            *self.list.get_mut(index).ok_or(())? = value;
            Ok(())
        }
    }

    struct QueueMemory {
        submission: [u32; 1024],
        completion: [u32; 1024],
        doorbells: [Option<(u64, u32)>; 2],
        doorbell_count: usize,
        status: u32,
        malformed_queue: bool,
        delays: u32,
    }

    impl Default for QueueMemory {
        fn default() -> Self {
            Self {
                submission: [0; 1024],
                completion: [0; 1024],
                doorbells: [None; 2],
                doorbell_count: 0,
                status: 0,
                malformed_queue: false,
                delays: 0,
            }
        }
    }

    impl NvmeIoCommandMemoryIo for QueueMemory {
        fn read_u32(&mut self, region: NvmeDmaRegion, offset: u64) -> Result<u32, ()> {
            let index = usize::try_from(offset / 4).map_err(|_| ())?;
            match region.memory_object.0 {
                90 => self.submission.get(index).copied().ok_or(()),
                91 => self.completion.get(index).copied().ok_or(()),
                _ => Err(()),
            }
        }
        fn write_u32(&mut self, region: NvmeDmaRegion, offset: u64, value: u32) -> Result<(), ()> {
            if region.memory_object != ObjectId(90) {
                return Err(());
            }
            let index = usize::try_from(offset / 4).map_err(|_| ())?;
            *self.submission.get_mut(index).ok_or(())? = value;
            Ok(())
        }
        fn ring_doorbell(&mut self, offset: u64, value: u32) -> Result<(), ()> {
            *self.doorbells.get_mut(self.doorbell_count).ok_or(())? = Some((offset, value));
            self.doorbell_count += 1;
            if offset == 0x1008 {
                let cid = (self.submission[0] >> 16) & 0xffff;
                self.completion[2] = if self.malformed_queue {
                    2 << 16
                } else {
                    1 << 16
                };
                self.completion[3] = cid | (1 << 16) | self.status;
            }
            Ok(())
        }
        fn delay_500_micros(&mut self) {
            self.delays += 1;
        }
    }

    fn admin_layout() -> NvmeAdminQueueDmaLayout {
        NvmeAdminQueueDmaLayout {
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
        }
    }

    fn io_layout() -> NvmeIoQueueDmaLayout {
        NvmeIoQueueDmaLayout {
            controller_object: ObjectId(71),
            configuration_generation: 11,
            mapping_generation: 9,
            queue_id: 1,
            queue_depth: 64,
            timeout_500ms_units: 1,
            doorbell_stride_bytes: 4,
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
        }
    }

    fn queues() -> ActiveNvmeIoQueues {
        ActiveNvmeIoQueues::from_state(
            ActiveNvmeAdminQueues::from_state(admin_layout()),
            io_layout(),
        )
    }

    fn namespace() -> NvmeNamespaceIdentity {
        NvmeNamespaceIdentity {
            configuration_generation: 11,
            mapping_generation: 9,
            namespace_id: 2,
            block_count: 1_000_000,
            capacity_blocks: 900_000,
            utilized_blocks: 400_000,
            logical_block_bytes: 4096,
            maximum_transfer_blocks: 256,
            thin_provisioning: true,
            relative_performance: 0,
            namespace_guid: [0; 16],
            ieee_extended_unique_identifier: [0; 8],
        }
    }

    fn read_fixture(blocks: u32) -> (CapabilitySpace<3>, NvmeIoRequest, PrpMemory) {
        let mut capabilities = CapabilitySpace::new();
        let namespace_capability = capabilities.insert(ObjectId(110), Rights::READ).unwrap();
        let data_rights = Rights::PIN
            .union(Rights::MAP)
            .union(Rights::READ)
            .union(Rights::WRITE);
        let data_capability = capabilities.insert(ObjectId(100), data_rights).unwrap();
        let bytes = u64::from(blocks) * 4096;
        let needs_list = bytes > 8192;
        let list_rights = Rights::PIN
            .union(Rights::MAP)
            .union(Rights::READ)
            .union(Rights::WRITE);
        let prp_list_capability =
            needs_list.then(|| capabilities.insert(ObjectId(101), list_rights).unwrap());
        let request = NvmePrpRequest {
            data_capability,
            prp_list_capability,
            data: NvmeDmaRegion {
                memory_object: ObjectId(100),
                allocation_generation: 7,
                physical_base: 0x10_0000,
                bytes,
            },
            prp_list: needs_list.then_some(NvmeDmaRegion {
                memory_object: ObjectId(101),
                allocation_generation: 8,
                physical_base: 0x20_0000,
                bytes: 4096,
            }),
            transfer_bytes: bytes,
            direction: NvmeTransferDirection::DeviceWrites,
        };
        let mut memory = PrpMemory::default();
        let prps = prepare_nvme_prps(&capabilities, request, &mut memory).unwrap();
        (
            capabilities,
            NvmeIoRequest {
                namespace_capability,
                namespace_object: ObjectId(110),
                namespace: namespace(),
                operation: NvmeIoOperation::Read,
                starting_lba: 40,
                block_count: blocks,
                prps: Some(prps),
            },
            memory,
        )
    }

    #[test]
    fn executes_full_one_mib_read_with_exact_namespace_and_prps() {
        let (capabilities, request, _) = read_fixture(256);
        let mut memory = QueueMemory::default();
        let completed = execute_nvme_io(&capabilities, queues(), request, &mut memory).unwrap();
        assert_eq!(memory.submission[0], READ_OPCODE | (1 << 16));
        assert_eq!(memory.submission[1], 2);
        assert_eq!(memory.submission[6], 0x10_0000);
        assert_eq!(memory.submission[8], 0x20_0000);
        assert_eq!(memory.submission[10], 40);
        assert_eq!(memory.submission[12], 255);
        assert_eq!(memory.doorbells, [Some((0x1008, 1)), Some((0x100c, 1))]);
        assert_eq!(completed.queues.state(), (1, 1, true, 2));
        assert!(completed.prps.is_some());
    }

    #[test]
    fn executes_write_with_device_read_prps_and_write_authority() {
        let mut capabilities = CapabilitySpace::<3>::new();
        let namespace_capability = capabilities.insert(ObjectId(110), Rights::WRITE).unwrap();
        let data_capability = capabilities
            .insert(
                ObjectId(100),
                Rights::PIN.union(Rights::MAP).union(Rights::READ),
            )
            .unwrap();
        let prp_request = NvmePrpRequest {
            data_capability,
            prp_list_capability: None,
            data: NvmeDmaRegion {
                memory_object: ObjectId(100),
                allocation_generation: 7,
                physical_base: 0x10_0000,
                bytes: 4096,
            },
            prp_list: None,
            transfer_bytes: 4096,
            direction: NvmeTransferDirection::DeviceReads,
        };
        let prepared =
            prepare_nvme_prps(&capabilities, prp_request, &mut PrpMemory::default()).unwrap();
        let request = NvmeIoRequest {
            namespace_capability,
            namespace_object: ObjectId(110),
            namespace: namespace(),
            operation: NvmeIoOperation::Write,
            starting_lba: 80,
            block_count: 1,
            prps: Some(prepared),
        };
        let mut memory = QueueMemory::default();
        let completed = execute_nvme_io(&capabilities, queues(), request, &mut memory).unwrap();
        assert_eq!(memory.submission[0], WRITE_OPCODE | (1 << 16));
        assert_eq!(memory.submission[10], 80);
        assert_eq!(memory.submission[12], 0);
        assert!(completed.prps.is_some());
    }

    #[test]
    fn executes_flush_without_data_or_lba_range() {
        let mut capabilities = CapabilitySpace::<1>::new();
        let namespace_capability = capabilities.insert(ObjectId(110), Rights::WRITE).unwrap();
        let request = NvmeIoRequest {
            namespace_capability,
            namespace_object: ObjectId(110),
            namespace: namespace(),
            operation: NvmeIoOperation::Flush,
            starting_lba: 0,
            block_count: 0,
            prps: None,
        };
        let mut memory = QueueMemory::default();
        assert!(execute_nvme_io(&capabilities, queues(), request, &mut memory).is_ok());
        assert_eq!(memory.submission[0], 1 << 16);
        assert!(memory.submission[1..16]
            .iter()
            .enumerate()
            .all(|(index, value)| index == 0 || *value == 0));
    }

    #[test]
    fn wrong_rights_range_or_prp_direction_fails_before_queue_mutation() {
        let (capabilities, mut request, _) = read_fixture(1);
        request.starting_lba = request.namespace.block_count;
        let mut memory = QueueMemory::default();
        assert!(matches!(
            execute_nvme_io(&capabilities, queues(), request, &mut memory),
            Err(NvmeIoCommandFailure::Untouched {
                error: NvmeIoCommandError::InvalidBlockRange,
                ..
            })
        ));
        assert_eq!(memory.doorbell_count, 0);
        let (capabilities, mut request, _) = read_fixture(1);
        request.prps = Some(
            request
                .prps
                .unwrap()
                .with_direction_for_test(NvmeTransferDirection::DeviceReads),
        );
        assert!(matches!(
            execute_nvme_io(
                &capabilities,
                queues(),
                request,
                &mut QueueMemory::default()
            ),
            Err(NvmeIoCommandFailure::Untouched {
                error: NvmeIoCommandError::WrongPrpDirection,
                ..
            })
        ));
    }

    #[test]
    fn explicit_device_rejection_advances_queue_but_retains_request_for_cleanup() {
        let (capabilities, request, _) = read_fixture(1);
        let mut memory = QueueMemory {
            status: 1 << 17,
            ..QueueMemory::default()
        };
        match execute_nvme_io(&capabilities, queues(), request, &mut memory).unwrap_err() {
            NvmeIoCommandFailure::Rejected {
                queues,
                request,
                status,
            } => {
                assert_eq!(queues.state(), (1, 1, true, 2));
                assert_eq!(request.operation, NvmeIoOperation::Read);
                assert_eq!(status.status_code, 1);
            }
            _ => panic!("expected explicit rejection"),
        }
    }

    #[test]
    fn malformed_completion_quarantines_admin_io_and_data_ownership() {
        let (capabilities, request, _) = read_fixture(1);
        let mut memory = QueueMemory {
            malformed_queue: true,
            ..QueueMemory::default()
        };
        assert!(matches!(
            execute_nvme_io(&capabilities, queues(), request, &mut memory),
            Err(NvmeIoCommandFailure::Quarantined {
                error: NvmeIoCommandError::MalformedCompletion,
                ..
            })
        ));
    }
}
