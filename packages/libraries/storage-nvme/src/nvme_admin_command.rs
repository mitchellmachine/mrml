//! Single-outstanding-command NVMe admin queue execution.
//!
//! The initial engine deliberately permits only Identify Controller and
//! Identify Namespace. Broader
//! admin opcodes require separate semantic APIs instead of a universal raw
//! command escape hatch.

use crate::{ActiveNvmeAdminQueues, NvmeAdminQueueDmaLayout, NvmeDmaRegion};
use mrml_kernel::{Capability, CapabilityError, CapabilitySpace, Rights};

pub const NVME_IDENTIFY_BYTES: u64 = 4096;
const IDENTIFY_OPCODE: u32 = 0x06;
const IDENTIFY_CONTROLLER_CNS: u32 = 0x01;
const IDENTIFY_NAMESPACE_CNS: u32 = 0x00;
const SET_FEATURES_OPCODE: u32 = 0x09;
const NUMBER_OF_QUEUES_FEATURE: u32 = 0x07;
pub const NVME_IO_QUEUE_COUNT_LIMIT: u16 = 64;
const ADMIN_SUBMISSION_ENTRY_BYTES: u64 = 64;
const ADMIN_COMPLETION_ENTRY_BYTES: u64 = 16;
const ADMIN_DOORBELL_BASE: u64 = 0x1000;
const POLLS_PER_500_MS: u32 = 1000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvmeIdentifyControllerRequest {
    pub controller_capability: Capability,
    pub data_capability: Capability,
    pub data: NvmeDmaRegion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvmeIdentifyNamespaceRequest {
    pub controller_capability: Capability,
    pub data_capability: Capability,
    pub data: NvmeDmaRegion,
    pub namespace_id: u32,
}

#[derive(Debug, Eq, PartialEq)]
pub struct NvmeIoQueueGrant {
    pub queues: ActiveNvmeAdminQueues,
    pub submission_queues: u16,
    pub completion_queues: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvmeAdminCommandStatus {
    pub status_code: u8,
    pub status_code_type: u8,
    pub command_retry_delay: u8,
    pub more: bool,
    pub do_not_retry: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NvmeAdminCommandError {
    ControllerCapability(CapabilityError),
    DataCapability(CapabilityError),
    WrongControllerObject,
    WrongDataObject,
    InvalidDataRegion,
    DataOverlapsQueue,
    DataNotZero,
    InvalidNamespace,
    InvalidQueueRequest,
    InvalidQueueGrant,
    InvalidQueueState,
    MemoryRead,
    MemoryWrite,
    VerificationFailed,
    DoorbellWrite,
    CompletionTimeout,
    MalformedCompletion,
}

#[derive(Debug, Eq, PartialEq)]
pub enum NvmeAdminCommandFailure {
    Untouched {
        queues: ActiveNvmeAdminQueues,
        error: NvmeAdminCommandError,
    },
    Rejected {
        queues: ActiveNvmeAdminQueues,
        status: NvmeAdminCommandStatus,
    },
    InvalidResult {
        queues: ActiveNvmeAdminQueues,
        error: NvmeAdminCommandError,
    },
    Quarantined {
        layout: NvmeAdminQueueDmaLayout,
        error: NvmeAdminCommandError,
    },
}

impl NvmeAdminCommandFailure {
    pub const fn error(&self) -> Option<NvmeAdminCommandError> {
        match self {
            Self::Untouched { error, .. }
            | Self::InvalidResult { error, .. }
            | Self::Quarantined { error, .. } => Some(*error),
            Self::Rejected { .. } => None,
        }
    }
}

pub fn negotiate_nvme_io_queue_count<const N: usize, I: NvmeAdminCommandMemoryIo>(
    capabilities: &CapabilitySpace<N>,
    queues: ActiveNvmeAdminQueues,
    controller_capability: Capability,
    requested: u16,
    io: &mut I,
) -> Result<NvmeIoQueueGrant, NvmeAdminCommandFailure> {
    if requested == 0 || requested > NVME_IO_QUEUE_COUNT_LIMIT {
        return Err(untouched(
            queues,
            NvmeAdminCommandError::InvalidQueueRequest,
        ));
    }
    let controller = match capabilities.authorize_exact(controller_capability, Rights::CONTROL) {
        Ok(object) => object,
        Err(error) => {
            return Err(untouched(
                queues,
                NvmeAdminCommandError::ControllerCapability(error),
            ));
        }
    };
    if controller != queues.layout().controller_object {
        return Err(untouched(
            queues,
            NvmeAdminCommandError::WrongControllerObject,
        ));
    }
    let zero_based = u32::from(requested - 1);
    let mut command = [0_u32; 16];
    command[0] = SET_FEATURES_OPCODE;
    command[10] = NUMBER_OF_QUEUES_FEATURE;
    command[11] = zero_based | (zero_based << 16);
    let completion = execute_prepared_admin(queues, command, io)?;
    let submission_queues = (completion.result & 0xffff) + 1;
    let completion_queues = (completion.result >> 16) + 1;
    if submission_queues > u32::from(requested)
        || completion_queues > u32::from(requested)
        || submission_queues > u32::from(u16::MAX)
        || completion_queues > u32::from(u16::MAX)
    {
        return Err(NvmeAdminCommandFailure::InvalidResult {
            queues: completion.queues,
            error: NvmeAdminCommandError::InvalidQueueGrant,
        });
    }
    Ok(NvmeIoQueueGrant {
        queues: completion.queues,
        submission_queues: u16::try_from(submission_queues).unwrap(),
        completion_queues: u16::try_from(completion_queues).unwrap(),
    })
}

pub trait NvmeAdminCommandMemoryIo {
    /// Reads queue/DMA memory with device-to-CPU acquire ordering.
    fn read_u32(&mut self, region: NvmeDmaRegion, offset: u64) -> Result<u32, ()>;
    fn write_u32(&mut self, region: NvmeDmaRegion, offset: u64, value: u32) -> Result<(), ()>;
    /// Publishes preceding queue-memory writes before the MMIO doorbell.
    fn ring_doorbell(&mut self, offset: u64, value: u32) -> Result<(), ()>;
    fn delay_500_micros(&mut self);
}

pub fn execute_nvme_identify_controller<const N: usize, I: NvmeAdminCommandMemoryIo>(
    capabilities: &CapabilitySpace<N>,
    queues: ActiveNvmeAdminQueues,
    request: NvmeIdentifyControllerRequest,
    io: &mut I,
) -> Result<ActiveNvmeAdminQueues, NvmeAdminCommandFailure> {
    execute_nvme_identify(
        capabilities,
        queues,
        request.controller_capability,
        request.data_capability,
        request.data,
        0,
        IDENTIFY_CONTROLLER_CNS,
        io,
    )
}

pub fn execute_nvme_identify_namespace<const N: usize, I: NvmeAdminCommandMemoryIo>(
    capabilities: &CapabilitySpace<N>,
    queues: ActiveNvmeAdminQueues,
    request: NvmeIdentifyNamespaceRequest,
    io: &mut I,
) -> Result<ActiveNvmeAdminQueues, NvmeAdminCommandFailure> {
    execute_nvme_identify(
        capabilities,
        queues,
        request.controller_capability,
        request.data_capability,
        request.data,
        request.namespace_id,
        IDENTIFY_NAMESPACE_CNS,
        io,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_nvme_identify<const N: usize, I: NvmeAdminCommandMemoryIo>(
    capabilities: &CapabilitySpace<N>,
    queues: ActiveNvmeAdminQueues,
    controller_capability: Capability,
    data_capability: Capability,
    data: NvmeDmaRegion,
    namespace_id: u32,
    cns: u32,
    io: &mut I,
) -> Result<ActiveNvmeAdminQueues, NvmeAdminCommandFailure> {
    let layout = queues.layout();
    if (cns == IDENTIFY_NAMESPACE_CNS && namespace_id == 0)
        || (cns == IDENTIFY_CONTROLLER_CNS && namespace_id != 0)
    {
        return Err(untouched(queues, NvmeAdminCommandError::InvalidNamespace));
    }
    let controller = match capabilities.authorize_exact(controller_capability, Rights::CONTROL) {
        Ok(object) => object,
        Err(error) => {
            return Err(untouched(
                queues,
                NvmeAdminCommandError::ControllerCapability(error),
            ))
        }
    };
    if controller != layout.controller_object {
        return Err(untouched(
            queues,
            NvmeAdminCommandError::WrongControllerObject,
        ));
    }
    let data_rights = Rights::PIN
        .union(Rights::MAP)
        .union(Rights::READ)
        .union(Rights::WRITE);
    let memory = match capabilities.authorize_exact(data_capability, data_rights) {
        Ok(object) => object,
        Err(error) => {
            return Err(untouched(
                queues,
                NvmeAdminCommandError::DataCapability(error),
            ))
        }
    };
    if memory != data.memory_object {
        return Err(untouched(queues, NvmeAdminCommandError::WrongDataObject));
    }
    if data.allocation_generation == 0
        || data.physical_base == 0
        || data.physical_base & 0xfff != 0
        || data.bytes != NVME_IDENTIFY_BYTES
        || data.physical_base.checked_add(data.bytes).is_none()
    {
        return Err(untouched(queues, NvmeAdminCommandError::InvalidDataRegion));
    }
    if overlaps(data, layout.submission) || overlaps(data, layout.completion) {
        return Err(untouched(queues, NvmeAdminCommandError::DataOverlapsQueue));
    }
    let mut data_offset = 0;
    while data_offset < data.bytes {
        match io.read_u32(data, data_offset) {
            Ok(0) => {}
            Ok(_) => return Err(untouched(queues, NvmeAdminCommandError::DataNotZero)),
            Err(()) => return Err(untouched(queues, NvmeAdminCommandError::MemoryRead)),
        }
        data_offset += 4;
    }

    let mut command = [0_u32; 16];
    command[0] = IDENTIFY_OPCODE;
    command[1] = namespace_id;
    command[6] = data.physical_base as u32;
    command[7] = (data.physical_base >> 32) as u32;
    command[10] = cns;
    execute_prepared_admin(queues, command, io).map(|completion| completion.queues)
}

struct CompletedAdminCommand {
    queues: ActiveNvmeAdminQueues,
    result: u32,
}

fn execute_prepared_admin<I: NvmeAdminCommandMemoryIo>(
    queues: ActiveNvmeAdminQueues,
    mut command: [u32; 16],
    io: &mut I,
) -> Result<CompletedAdminCommand, NvmeAdminCommandFailure> {
    let layout = queues.layout();
    let (tail, head, phase, command_id) = queues.state();
    if tail >= layout.queue_depth
        || head >= layout.queue_depth
        || command_id == 0
        || command[0] & 0xffff_0000 != 0
        || !matches!(
            layout.doorbell_stride_bytes,
            4 | 8
                | 16
                | 32
                | 64
                | 128
                | 256
                | 512
                | 1024
                | 2048
                | 4096
                | 8192
                | 16384
                | 32768
                | 65536
                | 131072
        )
    {
        return Err(untouched(queues, NvmeAdminCommandError::InvalidQueueState));
    }
    command[0] |= u32::from(command_id) << 16;
    let submission_offset = u64::from(tail) * ADMIN_SUBMISSION_ENTRY_BYTES;
    let completion_offset = u64::from(head) * ADMIN_COMPLETION_ENTRY_BYTES;

    for (index, value) in command.into_iter().enumerate() {
        let offset = submission_offset + u64::try_from(index).unwrap() * 4;
        if io.write_u32(layout.submission, offset, value).is_err() {
            return Err(quarantined(layout, NvmeAdminCommandError::MemoryWrite));
        }
    }
    for (index, expected) in command.into_iter().enumerate() {
        let offset = submission_offset + u64::try_from(index).unwrap() * 4;
        if io.read_u32(layout.submission, offset) != Ok(expected) {
            return Err(quarantined(
                layout,
                NvmeAdminCommandError::VerificationFailed,
            ));
        }
    }

    let next_tail = if tail + 1 == layout.queue_depth {
        0
    } else {
        tail + 1
    };
    if io
        .ring_doorbell(ADMIN_DOORBELL_BASE, u32::from(next_tail))
        .is_err()
    {
        return Err(quarantined(layout, NvmeAdminCommandError::DoorbellWrite));
    }
    let polls = u32::from(layout.timeout_500ms_units) * POLLS_PER_500_MS;
    let mut observed_completion = None;
    for _ in 0..polls {
        let dword3 = match io.read_u32(layout.completion, completion_offset + 12) {
            Ok(value) => value,
            Err(()) => return Err(quarantined(layout, NvmeAdminCommandError::MemoryRead)),
        };
        if (dword3 & (1 << 16) != 0) == phase {
            observed_completion = Some(dword3);
            break;
        }
        io.delay_500_micros();
    }
    let completion = observed_completion
        .ok_or_else(|| quarantined(layout, NvmeAdminCommandError::CompletionTimeout))?;

    let completion_result = match io.read_u32(layout.completion, completion_offset) {
        Ok(value) => value,
        Err(()) => return Err(quarantined(layout, NvmeAdminCommandError::MemoryRead)),
    };
    let completion_command_id = u16::try_from(completion & 0xffff).unwrap();
    let queue = match io.read_u32(layout.completion, completion_offset + 8) {
        Ok(value) => value,
        Err(()) => return Err(quarantined(layout, NvmeAdminCommandError::MemoryRead)),
    };
    if completion_command_id != command_id
        || queue >> 16 != 0
        || queue & 0xffff >= u32::from(layout.queue_depth)
    {
        return Err(quarantined(
            layout,
            NvmeAdminCommandError::MalformedCompletion,
        ));
    }
    let queues = queues.advance();
    let (_, next_head, _, _) = queues.state();
    let completion_doorbell = ADMIN_DOORBELL_BASE + u64::from(layout.doorbell_stride_bytes);
    if io
        .ring_doorbell(completion_doorbell, u32::from(next_head))
        .is_err()
    {
        return Err(quarantined(layout, NvmeAdminCommandError::DoorbellWrite));
    }
    let status = NvmeAdminCommandStatus {
        status_code: u8::try_from((completion >> 17) & 0xff).unwrap(),
        status_code_type: u8::try_from((completion >> 25) & 0x7).unwrap(),
        command_retry_delay: u8::try_from((completion >> 28) & 0x3).unwrap(),
        more: completion & (1 << 30) != 0,
        do_not_retry: completion & (1 << 31) != 0,
    };
    if status.status_code != 0 || status.status_code_type != 0 {
        return Err(NvmeAdminCommandFailure::Rejected { queues, status });
    }
    Ok(CompletedAdminCommand {
        queues,
        result: completion_result,
    })
}

fn overlaps(left: NvmeDmaRegion, right: NvmeDmaRegion) -> bool {
    left.physical_base < right.physical_base + right.bytes
        && right.physical_base < left.physical_base + left.bytes
}

const fn untouched(
    queues: ActiveNvmeAdminQueues,
    error: NvmeAdminCommandError,
) -> NvmeAdminCommandFailure {
    NvmeAdminCommandFailure::Untouched { queues, error }
}

const fn quarantined(
    layout: NvmeAdminQueueDmaLayout,
    error: NvmeAdminCommandError,
) -> NvmeAdminCommandFailure {
    NvmeAdminCommandFailure::Quarantined { layout, error }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_kernel::ObjectId;

    struct Memory {
        submission: [u32; 1024],
        completion: [u32; 1024],
        data: [u32; 1024],
        doorbells: [Option<(u64, u32)>; 2],
        doorbell_count: usize,
        completion_delay_reads: u32,
        completion_reads: u32,
        completion_status: u32,
        malformed_command_id: bool,
        fail_write_at: Option<usize>,
        writes: usize,
        delays: u32,
    }

    impl Default for Memory {
        fn default() -> Self {
            Self {
                submission: [0; 1024],
                completion: [0; 1024],
                data: [0; 1024],
                doorbells: [None; 2],
                doorbell_count: 0,
                completion_delay_reads: 0,
                completion_reads: 0,
                completion_status: 0,
                malformed_command_id: false,
                fail_write_at: None,
                writes: 0,
                delays: 0,
            }
        }
    }

    impl NvmeAdminCommandMemoryIo for Memory {
        fn read_u32(&mut self, region: NvmeDmaRegion, offset: u64) -> Result<u32, ()> {
            let index = usize::try_from(offset / 4).map_err(|_| ())?;
            match region.memory_object.0 {
                80 => self.submission.get(index).copied().ok_or(()),
                81 => {
                    if offset == 12 && self.doorbell_count != 0 {
                        self.completion_reads += 1;
                        if self.completion_reads > self.completion_delay_reads {
                            let cid = if self.malformed_command_id { 2 } else { 1 };
                            return Ok(cid | (1 << 16) | self.completion_status);
                        }
                    }
                    self.completion.get(index).copied().ok_or(())
                }
                82 => self.data.get(index).copied().ok_or(()),
                _ => Err(()),
            }
        }

        fn write_u32(&mut self, region: NvmeDmaRegion, offset: u64, value: u32) -> Result<(), ()> {
            if self.fail_write_at == Some(self.writes) {
                return Err(());
            }
            self.writes += 1;
            if region.memory_object != ObjectId(80) {
                return Err(());
            }
            let index = usize::try_from(offset / 4).map_err(|_| ())?;
            *self.submission.get_mut(index).ok_or(())? = value;
            Ok(())
        }

        fn ring_doorbell(&mut self, offset: u64, value: u32) -> Result<(), ()> {
            let slot = self.doorbells.get_mut(self.doorbell_count).ok_or(())?;
            *slot = Some((offset, value));
            self.doorbell_count += 1;
            Ok(())
        }

        fn delay_500_micros(&mut self) {
            self.delays += 1;
        }
    }

    fn layout() -> NvmeAdminQueueDmaLayout {
        NvmeAdminQueueDmaLayout {
            controller_object: ObjectId(71),
            configuration_generation: 11,
            mapping_generation: 9,
            queue_depth: 64,
            timeout_500ms_units: 1,
            doorbell_stride_bytes: 4,
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
        }
    }

    fn fixture() -> (
        CapabilitySpace<3>,
        ActiveNvmeAdminQueues,
        NvmeIdentifyControllerRequest,
    ) {
        let rights = Rights::PIN
            .union(Rights::MAP)
            .union(Rights::READ)
            .union(Rights::WRITE);
        let mut capabilities = CapabilitySpace::new();
        let controller_capability = capabilities.insert(ObjectId(71), Rights::CONTROL).unwrap();
        let data_capability = capabilities.insert(ObjectId(82), rights).unwrap();
        let request = NvmeIdentifyControllerRequest {
            controller_capability,
            data_capability,
            data: NvmeDmaRegion {
                memory_object: ObjectId(82),
                allocation_generation: 5,
                physical_base: 0x3000,
                bytes: 4096,
            },
        };
        (
            capabilities,
            ActiveNvmeAdminQueues::from_state(layout()),
            request,
        )
    }

    #[test]
    fn identifies_controller_with_verified_command_and_phase_completion() {
        let (capabilities, queues, request) = fixture();
        let mut memory = Memory {
            completion_delay_reads: 2,
            ..Memory::default()
        };
        let queues =
            execute_nvme_identify_controller(&capabilities, queues, request, &mut memory).unwrap();
        assert_eq!(memory.submission[0], IDENTIFY_OPCODE | (1 << 16));
        assert_eq!(memory.submission[6], 0x3000);
        assert_eq!(memory.submission[7], 0);
        assert_eq!(memory.submission[10], IDENTIFY_CONTROLLER_CNS);
        assert_eq!(memory.doorbells, [Some((0x1000, 1)), Some((0x1004, 1))]);
        assert_eq!(memory.delays, 2);
        assert_eq!(queues.state(), (1, 1, true, 2));
    }

    #[test]
    fn identifies_one_nonzero_namespace_without_raw_admin_authority() {
        let (capabilities, queues, request) = fixture();
        let request = NvmeIdentifyNamespaceRequest {
            controller_capability: request.controller_capability,
            data_capability: request.data_capability,
            data: request.data,
            namespace_id: 7,
        };
        let mut memory = Memory::default();
        let queues =
            execute_nvme_identify_namespace(&capabilities, queues, request, &mut memory).unwrap();
        assert_eq!(memory.submission[0], IDENTIFY_OPCODE | (1 << 16));
        assert_eq!(memory.submission[1], 7);
        assert_eq!(memory.submission[10], IDENTIFY_NAMESPACE_CNS);
        assert_eq!(queues.state(), (1, 1, true, 2));
    }

    #[test]
    fn zero_namespace_fails_before_memory_or_doorbells() {
        let (capabilities, queues, request) = fixture();
        let request = NvmeIdentifyNamespaceRequest {
            controller_capability: request.controller_capability,
            data_capability: request.data_capability,
            data: request.data,
            namespace_id: 0,
        };
        let mut memory = Memory::default();
        assert_eq!(
            execute_nvme_identify_namespace(&capabilities, queues, request, &mut memory)
                .unwrap_err()
                .error(),
            Some(NvmeAdminCommandError::InvalidNamespace)
        );
        assert_eq!(memory.writes, 0);
        assert_eq!(memory.doorbell_count, 0);
    }

    #[test]
    fn negotiates_bounded_io_queue_counts_through_shared_admin_executor() {
        let (capabilities, queues, request) = fixture();
        let mut memory = Memory::default();
        memory.completion[0] = 1;
        let grant = negotiate_nvme_io_queue_count(
            &capabilities,
            queues,
            request.controller_capability,
            4,
            &mut memory,
        )
        .unwrap();
        assert_eq!(grant.submission_queues, 2);
        assert_eq!(grant.completion_queues, 1);
        assert_eq!(grant.queues.state(), (1, 1, true, 2));
        assert_eq!(memory.submission[0], SET_FEATURES_OPCODE | (1 << 16));
        assert_eq!(memory.submission[10], NUMBER_OF_QUEUES_FEATURE);
        assert_eq!(memory.submission[11], 3 | (3 << 16));
    }

    #[test]
    fn invalid_queue_request_or_excess_controller_grant_fails_closed() {
        for requested in [0, NVME_IO_QUEUE_COUNT_LIMIT + 1] {
            let (capabilities, queues, request) = fixture();
            let mut memory = Memory::default();
            assert_eq!(
                negotiate_nvme_io_queue_count(
                    &capabilities,
                    queues,
                    request.controller_capability,
                    requested,
                    &mut memory,
                )
                .unwrap_err()
                .error(),
                Some(NvmeAdminCommandError::InvalidQueueRequest)
            );
            assert_eq!(memory.writes, 0);
        }
        let (capabilities, queues, request) = fixture();
        let mut memory = Memory::default();
        memory.completion[0] = 4 | (4 << 16);
        let failure = negotiate_nvme_io_queue_count(
            &capabilities,
            queues,
            request.controller_capability,
            4,
            &mut memory,
        )
        .unwrap_err();
        assert!(matches!(
            failure,
            NvmeAdminCommandFailure::InvalidResult {
                error: NvmeAdminCommandError::InvalidQueueGrant,
                ..
            }
        ));
    }

    #[test]
    fn authority_geometry_overlap_and_nonzero_data_fail_before_mutation() {
        let (capabilities, queues, mut request) = fixture();
        request.data.physical_base = 0x1000;
        let mut memory = Memory::default();
        assert_eq!(
            execute_nvme_identify_controller(&capabilities, queues, request, &mut memory)
                .unwrap_err()
                .error(),
            Some(NvmeAdminCommandError::DataOverlapsQueue)
        );
        let (capabilities, queues, request) = fixture();
        memory.data[9] = 1;
        assert_eq!(
            execute_nvme_identify_controller(&capabilities, queues, request, &mut memory)
                .unwrap_err()
                .error(),
            Some(NvmeAdminCommandError::DataNotZero)
        );
        assert_eq!(memory.writes, 0);
        assert_eq!(memory.doorbell_count, 0);
    }

    #[test]
    fn memory_mutation_or_malformed_completion_quarantines_layout() {
        let (capabilities, queues, request) = fixture();
        let mut memory = Memory {
            fail_write_at: Some(3),
            ..Memory::default()
        };
        assert!(matches!(
            execute_nvme_identify_controller(&capabilities, queues, request, &mut memory),
            Err(NvmeAdminCommandFailure::Quarantined {
                error: NvmeAdminCommandError::MemoryWrite,
                ..
            })
        ));
        let (capabilities, queues, request) = fixture();
        let mut memory = Memory {
            malformed_command_id: true,
            ..Memory::default()
        };
        assert!(matches!(
            execute_nvme_identify_controller(&capabilities, queues, request, &mut memory),
            Err(NvmeAdminCommandFailure::Quarantined {
                error: NvmeAdminCommandError::MalformedCompletion,
                ..
            })
        ));
    }

    #[test]
    fn device_status_is_returned_with_advanced_reusable_queues() {
        let (capabilities, queues, request) = fixture();
        let mut memory = Memory {
            completion_status: (2 << 17) | (1 << 25) | (1 << 31),
            ..Memory::default()
        };
        let failure = execute_nvme_identify_controller(&capabilities, queues, request, &mut memory)
            .unwrap_err();
        match failure {
            NvmeAdminCommandFailure::Rejected { queues, status } => {
                assert_eq!(queues.state(), (1, 1, true, 2));
                assert_eq!(status.status_code, 2);
                assert_eq!(status.status_code_type, 1);
                assert!(status.do_not_retry);
            }
            _ => panic!("expected explicit controller rejection"),
        }
    }
}
