use crate::{PAGE_SIZE, VmBackend};

pub const VIRTUAL_BLOCK_REQUEST_BYTES: usize = 64;
pub const VIRTUAL_BLOCK_COMPLETION_BYTES: usize = 32;
pub const MAX_VIRTUAL_BLOCK_QUEUE_SLOTS: usize = 64;
pub const MAX_VIRTUAL_BLOCK_TRANSFER_BYTES: u32 = 1024 * 1024;
pub const VIRTUAL_BLOCK_FEATURE_FLUSH: u64 = 1 << 0;
const REQUEST_MAGIC: [u8; 4] = *b"MRBQ";
const COMPLETION_MAGIC: [u8; 4] = *b"MRBC";
const VERSION: u8 = 1;
const QUEUE_HEADER_BYTES: u64 = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualBlockError {
    InvalidGeometry,
    InvalidFeatures,
    InvalidState,
    InvalidQueue,
    InvalidInterrupt,
    MalformedRequest,
    UnsupportedOperation,
    StaleGeneration,
    Replay,
    InvalidRange,
    InvalidBuffer,
    QueueFull,
    QueueEmpty,
    StaleTicket,
    InvalidCompletion,
    SequenceExhausted,
    RangeOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum VirtualBlockOperation {
    Read = 1,
    Write = 2,
    Flush = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualBlockRequest {
    generation: u32,
    request_id: u64,
    operation: VirtualBlockOperation,
    block: u64,
    block_count: u32,
    buffer_address: u64,
    buffer_length: u32,
}

impl VirtualBlockRequest {
    pub fn read(
        generation: u32,
        request_id: u64,
        block: u64,
        block_count: u32,
        buffer_address: u64,
        buffer_length: u32,
    ) -> Self {
        Self {
            generation,
            request_id,
            operation: VirtualBlockOperation::Read,
            block,
            block_count,
            buffer_address,
            buffer_length,
        }
    }

    pub fn write(
        generation: u32,
        request_id: u64,
        block: u64,
        block_count: u32,
        buffer_address: u64,
        buffer_length: u32,
    ) -> Self {
        Self {
            operation: VirtualBlockOperation::Write,
            ..Self::read(
                generation,
                request_id,
                block,
                block_count,
                buffer_address,
                buffer_length,
            )
        }
    }

    pub fn flush(generation: u32, request_id: u64) -> Self {
        Self {
            generation,
            request_id,
            operation: VirtualBlockOperation::Flush,
            block: 0,
            block_count: 0,
            buffer_address: 0,
            buffer_length: 0,
        }
    }

    pub const fn generation(self) -> u32 {
        self.generation
    }

    pub const fn request_id(self) -> u64 {
        self.request_id
    }

    pub const fn operation(self) -> VirtualBlockOperation {
        self.operation
    }

    pub const fn block(self) -> u64 {
        self.block
    }

    pub const fn block_count(self) -> u32 {
        self.block_count
    }

    pub const fn buffer_address(self) -> u64 {
        self.buffer_address
    }

    pub const fn buffer_length(self) -> u32 {
        self.buffer_length
    }

    pub fn encode(self, output: &mut [u8; VIRTUAL_BLOCK_REQUEST_BYTES]) {
        output.fill(0);
        output[..4].copy_from_slice(&REQUEST_MAGIC);
        output[4] = VERSION;
        output[5] = self.operation as u8;
        output[8..12].copy_from_slice(&self.generation.to_le_bytes());
        output[16..24].copy_from_slice(&self.request_id.to_le_bytes());
        output[24..32].copy_from_slice(&self.block.to_le_bytes());
        output[32..36].copy_from_slice(&self.block_count.to_le_bytes());
        output[40..48].copy_from_slice(&self.buffer_address.to_le_bytes());
        output[48..52].copy_from_slice(&self.buffer_length.to_le_bytes());
    }

    pub fn decode(input: &[u8]) -> Result<Self, VirtualBlockError> {
        if input.len() != VIRTUAL_BLOCK_REQUEST_BYTES
            || input[..4] != REQUEST_MAGIC
            || input[4] != VERSION
            || input[6..8].iter().any(|byte| *byte != 0)
            || input[12..16].iter().any(|byte| *byte != 0)
            || input[36..40].iter().any(|byte| *byte != 0)
            || input[52..].iter().any(|byte| *byte != 0)
        {
            return Err(VirtualBlockError::MalformedRequest);
        }
        let operation = match input[5] {
            1 => VirtualBlockOperation::Read,
            2 => VirtualBlockOperation::Write,
            3 => VirtualBlockOperation::Flush,
            _ => return Err(VirtualBlockError::UnsupportedOperation),
        };
        let generation = u32::from_le_bytes(input[8..12].try_into().unwrap());
        let request_id = u64::from_le_bytes(input[16..24].try_into().unwrap());
        if generation == 0 || request_id == 0 {
            return Err(VirtualBlockError::MalformedRequest);
        }
        Ok(Self {
            generation,
            request_id,
            operation,
            block: u64::from_le_bytes(input[24..32].try_into().unwrap()),
            block_count: u32::from_le_bytes(input[32..36].try_into().unwrap()),
            buffer_address: u64::from_le_bytes(input[40..48].try_into().unwrap()),
            buffer_length: u32::from_le_bytes(input[48..52].try_into().unwrap()),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum VirtualBlockCompletionStatus {
    Ok = 0,
    DeviceError = 1,
    Reset = 2,
    Removed = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualBlockCompletion {
    generation: u32,
    request_id: u64,
    status: VirtualBlockCompletionStatus,
    transferred: u32,
}

impl VirtualBlockCompletion {
    pub const fn generation(self) -> u32 {
        self.generation
    }

    pub const fn request_id(self) -> u64 {
        self.request_id
    }

    pub const fn status(self) -> VirtualBlockCompletionStatus {
        self.status
    }

    pub const fn transferred(self) -> u32 {
        self.transferred
    }

    pub fn encode(self, output: &mut [u8; VIRTUAL_BLOCK_COMPLETION_BYTES]) {
        output.fill(0);
        output[..4].copy_from_slice(&COMPLETION_MAGIC);
        output[4] = VERSION;
        output[5] = self.status as u8;
        output[8..12].copy_from_slice(&self.generation.to_le_bytes());
        output[16..24].copy_from_slice(&self.request_id.to_le_bytes());
        output[24..28].copy_from_slice(&self.transferred.to_le_bytes());
    }

    pub fn decode(input: &[u8]) -> Result<Self, VirtualBlockError> {
        if input.len() != VIRTUAL_BLOCK_COMPLETION_BYTES
            || input[..4] != COMPLETION_MAGIC
            || input[4] != VERSION
            || input[6..8].iter().any(|byte| *byte != 0)
            || input[12..16].iter().any(|byte| *byte != 0)
            || input[28..].iter().any(|byte| *byte != 0)
        {
            return Err(VirtualBlockError::InvalidCompletion);
        }
        let status = match input[5] {
            0 => VirtualBlockCompletionStatus::Ok,
            1 => VirtualBlockCompletionStatus::DeviceError,
            2 => VirtualBlockCompletionStatus::Reset,
            3 => VirtualBlockCompletionStatus::Removed,
            _ => return Err(VirtualBlockError::InvalidCompletion),
        };
        let transferred = u32::from_le_bytes(input[24..28].try_into().unwrap());
        if status != VirtualBlockCompletionStatus::Ok && transferred != 0 {
            return Err(VirtualBlockError::InvalidCompletion);
        }
        Ok(Self {
            generation: u32::from_le_bytes(input[8..12].try_into().unwrap()),
            request_id: u64::from_le_bytes(input[16..24].try_into().unwrap()),
            status,
            transferred,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualBlockQueueLayout {
    request_base: u64,
    completion_base: u64,
    pages_per_queue: u64,
    slots: u16,
}

impl VirtualBlockQueueLayout {
    pub fn new(
        request_base: u64,
        completion_base: u64,
        slots: usize,
    ) -> Result<Self, VirtualBlockError> {
        if slots == 0
            || slots > MAX_VIRTUAL_BLOCK_QUEUE_SLOTS
            || request_base == 0
            || completion_base == 0
            || !request_base.is_multiple_of(PAGE_SIZE)
            || !completion_base.is_multiple_of(PAGE_SIZE)
        {
            return Err(VirtualBlockError::InvalidQueue);
        }
        let request_bytes = queue_bytes(slots, VIRTUAL_BLOCK_REQUEST_BYTES)?;
        let completion_bytes = queue_bytes(slots, VIRTUAL_BLOCK_COMPLETION_BYTES)?;
        let bytes = request_bytes.max(completion_bytes);
        let pages_per_queue = bytes
            .checked_add(PAGE_SIZE - 1)
            .ok_or(VirtualBlockError::RangeOverflow)?
            / PAGE_SIZE;
        let length = pages_per_queue
            .checked_mul(PAGE_SIZE)
            .ok_or(VirtualBlockError::RangeOverflow)?;
        let request_end = request_base
            .checked_add(length)
            .ok_or(VirtualBlockError::RangeOverflow)?;
        let completion_end = completion_base
            .checked_add(length)
            .ok_or(VirtualBlockError::RangeOverflow)?;
        if request_base < completion_end && completion_base < request_end {
            return Err(VirtualBlockError::InvalidQueue);
        }
        Ok(Self {
            request_base,
            completion_base,
            pages_per_queue,
            slots: slots as u16,
        })
    }

    pub const fn request_base(self) -> u64 {
        self.request_base
    }

    pub const fn completion_base(self) -> u64 {
        self.completion_base
    }

    pub const fn pages_per_queue(self) -> u64 {
        self.pages_per_queue
    }

    pub const fn slots(self) -> u16 {
        self.slots
    }
}

fn queue_bytes(slots: usize, slot_bytes: usize) -> Result<u64, VirtualBlockError> {
    (slots as u64)
        .checked_mul(slot_bytes as u64)
        .and_then(|bytes| bytes.checked_add(QUEUE_HEADER_BYTES))
        .ok_or(VirtualBlockError::RangeOverflow)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualBlockDeviceState {
    Created,
    Negotiated,
    Active,
    Suspended,
    Failed,
    Removed,
    Destroyed,
}

#[derive(Clone, Copy)]
struct InFlight {
    slot_generation: u32,
    device_generation: u32,
    request_id: u64,
    operation: VirtualBlockOperation,
    transfer_bytes: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualBlockTicket {
    slot: u16,
    slot_generation: u32,
    device_generation: u32,
    request_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmittedVirtualBlockRequest {
    request: VirtualBlockRequest,
    ticket: VirtualBlockTicket,
}

impl AdmittedVirtualBlockRequest {
    pub const fn request(self) -> VirtualBlockRequest {
        self.request
    }

    pub const fn ticket(self) -> VirtualBlockTicket {
        self.ticket
    }
}

pub struct VirtualBlockDevice<const N: usize> {
    block_size: u32,
    block_count: u64,
    supported_features: u64,
    negotiated_features: u64,
    generation: u32,
    state: VirtualBlockDeviceState,
    queue: Option<VirtualBlockQueueLayout>,
    interrupt_vector: Option<u8>,
    last_request_id: u64,
    slots: [Option<InFlight>; N],
    slot_generations: [u32; N],
}

impl<const N: usize> VirtualBlockDevice<N> {
    pub fn new(
        block_size: u32,
        block_count: u64,
        supported_features: u64,
    ) -> Result<Self, VirtualBlockError> {
        if N == 0
            || N > MAX_VIRTUAL_BLOCK_QUEUE_SLOTS
            || !(4096..=65_536).contains(&block_size)
            || !block_size.is_power_of_two()
            || block_count == 0
            || supported_features & !VIRTUAL_BLOCK_FEATURE_FLUSH != 0
        {
            return Err(VirtualBlockError::InvalidGeometry);
        }
        Ok(Self {
            block_size,
            block_count,
            supported_features,
            negotiated_features: 0,
            generation: 1,
            state: VirtualBlockDeviceState::Created,
            queue: None,
            interrupt_vector: None,
            last_request_id: 0,
            slots: [None; N],
            slot_generations: [0; N],
        })
    }

    pub const fn state(&self) -> VirtualBlockDeviceState {
        self.state
    }

    pub const fn generation(&self) -> u32 {
        self.generation
    }

    pub const fn negotiated_features(&self) -> u64 {
        self.negotiated_features
    }

    pub const fn block_size(&self) -> u32 {
        self.block_size
    }

    pub const fn block_count(&self) -> u64 {
        self.block_count
    }

    pub const fn queue(&self) -> Option<VirtualBlockQueueLayout> {
        self.queue
    }

    pub const fn interrupt_vector(&self) -> Option<u8> {
        self.interrupt_vector
    }

    pub fn admission_ready(&self) -> Result<bool, VirtualBlockError> {
        if self.state != VirtualBlockDeviceState::Active {
            return Err(VirtualBlockError::InvalidState);
        }
        if self
            .slots
            .iter()
            .zip(self.slot_generations)
            .any(|(entry, generation)| entry.is_none() && generation != u32::MAX)
        {
            return Ok(true);
        }
        if self.slots.iter().any(Option::is_none) {
            return Err(VirtualBlockError::SequenceExhausted);
        }
        Ok(false)
    }

    pub fn negotiate(&mut self, requested: u64) -> Result<u64, VirtualBlockError> {
        if !matches!(
            self.state,
            VirtualBlockDeviceState::Created | VirtualBlockDeviceState::Negotiated
        ) {
            return Err(VirtualBlockError::InvalidState);
        }
        if requested & !self.supported_features != 0 {
            return Err(VirtualBlockError::InvalidFeatures);
        }
        self.negotiated_features = requested;
        self.state = VirtualBlockDeviceState::Negotiated;
        Ok(requested)
    }

    pub fn activate(
        &mut self,
        queue: VirtualBlockQueueLayout,
        interrupt_vector: u8,
    ) -> Result<(), VirtualBlockError> {
        if self.state != VirtualBlockDeviceState::Negotiated {
            return Err(VirtualBlockError::InvalidState);
        }
        if usize::from(queue.slots()) != N {
            return Err(VirtualBlockError::InvalidQueue);
        }
        if !(32..=254).contains(&interrupt_vector) {
            return Err(VirtualBlockError::InvalidInterrupt);
        }
        self.queue = Some(queue);
        self.interrupt_vector = Some(interrupt_vector);
        self.state = VirtualBlockDeviceState::Active;
        Ok(())
    }

    pub fn suspend(&mut self) -> Result<(), VirtualBlockError> {
        if self.state != VirtualBlockDeviceState::Active || self.slots.iter().any(Option::is_some) {
            return Err(VirtualBlockError::InvalidState);
        }
        self.state = VirtualBlockDeviceState::Suspended;
        Ok(())
    }

    pub fn resume(&mut self) -> Result<(), VirtualBlockError> {
        if self.state != VirtualBlockDeviceState::Suspended {
            return Err(VirtualBlockError::InvalidState);
        }
        self.state = VirtualBlockDeviceState::Active;
        Ok(())
    }

    pub fn fail(&mut self) -> Result<usize, VirtualBlockError> {
        if !matches!(
            self.state,
            VirtualBlockDeviceState::Active | VirtualBlockDeviceState::Suspended
        ) {
            return Err(VirtualBlockError::InvalidState);
        }
        if let Err(error) = self.preflight_invalidation() {
            self.state = VirtualBlockDeviceState::Failed;
            return Err(error);
        }
        let invalidated = self.invalidate_inflight();
        self.state = VirtualBlockDeviceState::Failed;
        Ok(invalidated)
    }

    pub fn reset(&mut self) -> Result<usize, VirtualBlockError> {
        if !matches!(
            self.state,
            VirtualBlockDeviceState::Active
                | VirtualBlockDeviceState::Suspended
                | VirtualBlockDeviceState::Failed
        ) {
            return Err(VirtualBlockError::InvalidState);
        }
        self.preflight_invalidation()?;
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(VirtualBlockError::SequenceExhausted)?;
        let invalidated = self.invalidate_inflight();
        self.generation = next_generation;
        self.queue = None;
        self.interrupt_vector = None;
        self.negotiated_features = 0;
        self.last_request_id = 0;
        self.state = VirtualBlockDeviceState::Created;
        Ok(invalidated)
    }

    pub fn remove(&mut self) -> Result<usize, VirtualBlockError> {
        if matches!(
            self.state,
            VirtualBlockDeviceState::Removed | VirtualBlockDeviceState::Destroyed
        ) {
            return Err(VirtualBlockError::InvalidState);
        }
        self.preflight_invalidation()?;
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(VirtualBlockError::SequenceExhausted)?;
        let invalidated = self.invalidate_inflight();
        self.generation = next_generation;
        self.queue = None;
        self.interrupt_vector = None;
        self.negotiated_features = 0;
        self.state = VirtualBlockDeviceState::Removed;
        Ok(invalidated)
    }

    pub fn destroy(&mut self) -> Result<(), VirtualBlockError> {
        if self.state != VirtualBlockDeviceState::Removed {
            return Err(VirtualBlockError::InvalidState);
        }
        self.state = VirtualBlockDeviceState::Destroyed;
        Ok(())
    }

    pub fn admit(
        &mut self,
        encoded: &[u8],
    ) -> Result<AdmittedVirtualBlockRequest, VirtualBlockError> {
        if self.state != VirtualBlockDeviceState::Active {
            return Err(VirtualBlockError::InvalidState);
        }
        let request = VirtualBlockRequest::decode(encoded)?;
        self.validate_request(request)?;
        let slot = self
            .slots
            .iter()
            .zip(self.slot_generations)
            .enumerate()
            .find(|(_, (entry, generation))| entry.is_none() && *generation != u32::MAX)
            .map(|(slot, _)| slot);
        let slot = match slot {
            Some(slot) => slot,
            None if self.slots.iter().any(Option::is_none) => {
                return Err(VirtualBlockError::SequenceExhausted);
            }
            None => return Err(VirtualBlockError::QueueFull),
        };
        let slot_generation = self.slot_generations[slot]
            .checked_add(1)
            .ok_or(VirtualBlockError::SequenceExhausted)?;
        self.slot_generations[slot] = slot_generation;
        let transfer_bytes = request.buffer_length;
        self.slots[slot] = Some(InFlight {
            slot_generation,
            device_generation: self.generation,
            request_id: request.request_id,
            operation: request.operation,
            transfer_bytes,
        });
        self.last_request_id = request.request_id;
        Ok(AdmittedVirtualBlockRequest {
            request,
            ticket: VirtualBlockTicket {
                slot: slot as u16,
                slot_generation,
                device_generation: self.generation,
                request_id: request.request_id,
            },
        })
    }

    pub fn complete(
        &mut self,
        ticket: VirtualBlockTicket,
        status: VirtualBlockCompletionStatus,
        transferred: u32,
    ) -> Result<VirtualBlockCompletion, VirtualBlockError> {
        if self.state != VirtualBlockDeviceState::Active {
            return Err(VirtualBlockError::InvalidState);
        }
        let (index, entry) = self.inflight(ticket)?;
        let expected = if entry.operation == VirtualBlockOperation::Flush {
            0
        } else {
            entry.transfer_bytes
        };
        if (status == VirtualBlockCompletionStatus::Ok && transferred != expected)
            || (status != VirtualBlockCompletionStatus::Ok && transferred != 0)
            || matches!(
                status,
                VirtualBlockCompletionStatus::Reset | VirtualBlockCompletionStatus::Removed
            )
        {
            return Err(VirtualBlockError::InvalidCompletion);
        }
        self.slots[index] = None;
        Ok(VirtualBlockCompletion {
            generation: self.generation,
            request_id: entry.request_id,
            status,
            transferred,
        })
    }

    fn inflight(&self, ticket: VirtualBlockTicket) -> Result<(usize, InFlight), VirtualBlockError> {
        let index = usize::from(ticket.slot);
        let entry = self
            .slots
            .get(index)
            .copied()
            .flatten()
            .ok_or(VirtualBlockError::StaleTicket)?;
        if entry.slot_generation != ticket.slot_generation
            || entry.device_generation != ticket.device_generation
            || entry.request_id != ticket.request_id
            || ticket.device_generation != self.generation
        {
            return Err(VirtualBlockError::StaleTicket);
        }
        Ok((index, entry))
    }

    fn validate_request(&self, request: VirtualBlockRequest) -> Result<(), VirtualBlockError> {
        if request.generation != self.generation {
            return Err(VirtualBlockError::StaleGeneration);
        }
        if request.request_id == 0 || request.request_id <= self.last_request_id {
            return Err(VirtualBlockError::Replay);
        }
        match request.operation {
            VirtualBlockOperation::Flush => {
                if self.negotiated_features & VIRTUAL_BLOCK_FEATURE_FLUSH == 0 {
                    return Err(VirtualBlockError::InvalidFeatures);
                }
                if request.block != 0
                    || request.block_count != 0
                    || request.buffer_address != 0
                    || request.buffer_length != 0
                {
                    return Err(VirtualBlockError::MalformedRequest);
                }
            }
            VirtualBlockOperation::Read | VirtualBlockOperation::Write => {
                if request.block_count == 0 {
                    return Err(VirtualBlockError::InvalidRange);
                }
                let end = request
                    .block
                    .checked_add(u64::from(request.block_count))
                    .ok_or(VirtualBlockError::InvalidRange)?;
                if end > self.block_count {
                    return Err(VirtualBlockError::InvalidRange);
                }
                let expected = self
                    .block_size
                    .checked_mul(request.block_count)
                    .ok_or(VirtualBlockError::InvalidBuffer)?;
                if expected > MAX_VIRTUAL_BLOCK_TRANSFER_BYTES
                    || request.buffer_length != expected
                    || request.buffer_address == 0
                    || !request.buffer_address.is_multiple_of(8)
                    || request
                        .buffer_address
                        .checked_add(u64::from(expected))
                        .is_none()
                {
                    return Err(VirtualBlockError::InvalidBuffer);
                }
            }
        }
        Ok(())
    }

    fn preflight_invalidation(&self) -> Result<(), VirtualBlockError> {
        if self
            .slots
            .iter()
            .zip(self.slot_generations)
            .any(|(entry, generation)| entry.is_some() && generation == u32::MAX)
        {
            return Err(VirtualBlockError::SequenceExhausted);
        }
        Ok(())
    }

    fn invalidate_inflight(&mut self) -> usize {
        let count = self.slots.iter().filter(|entry| entry.is_some()).count();
        for (entry, generation) in self.slots.iter_mut().zip(&mut self.slot_generations) {
            if entry.take().is_some() {
                *generation += 1;
            }
        }
        count
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum VirtualBlockQueueError<E> {
    Protocol(VirtualBlockError),
    Backend(E),
    Poisoned,
}

#[derive(Debug, Eq, PartialEq)]
pub enum VirtualBlockMutationError<E> {
    Rejected(E),
    Uncertain(E),
}

/// Exact block operations behind one separately provisioned virtual device.
///
/// # Safety
///
/// A successful operation must transfer the complete supplied buffer at the
/// exact block without redirection or shortening. `Rejected` means no durable
/// or externally visible mutation occurred. Any write or flush failure for
/// which that statement cannot be guaranteed must be returned as `Uncertain`.
pub unsafe trait VirtualBlockBackend {
    type Error;

    fn read_blocks(&mut self, block: u64, output: &mut [u8]) -> Result<(), Self::Error>;
    fn write_blocks(
        &mut self,
        block: u64,
        input: &[u8],
    ) -> Result<(), VirtualBlockMutationError<Self::Error>>;
    fn flush(&mut self) -> Result<(), VirtualBlockMutationError<Self::Error>>;
}

#[derive(Debug, Eq, PartialEq)]
pub enum VirtualBlockExecutionOutcome<E> {
    Completed(VirtualBlockCompletion),
    BackendRejected {
        completion: VirtualBlockCompletion,
        error: E,
    },
}

impl<E> VirtualBlockExecutionOutcome<E> {
    pub const fn completion(&self) -> VirtualBlockCompletion {
        match self {
            Self::Completed(completion) | Self::BackendRejected { completion, .. } => *completion,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum VirtualBlockExecutionError<M, D> {
    Protocol(VirtualBlockError),
    GuestMemory {
        error: VirtualBlockQueueError<M>,
        invalidated: Result<usize, VirtualBlockError>,
    },
    BackendUncertain {
        error: D,
        invalidated: Result<usize, VirtualBlockError>,
    },
}

pub type VirtualBlockExecutionResult<M, D> =
    Result<VirtualBlockExecutionOutcome<D>, VirtualBlockExecutionError<M, D>>;

#[derive(Debug, Eq, PartialEq)]
pub enum VirtualBlockProcessOutcome<E> {
    Idle,
    Backpressured,
    Rejected(VirtualBlockError),
    Completed(VirtualBlockExecutionOutcome<E>),
}

#[derive(Debug, Eq, PartialEq)]
pub enum VirtualBlockProcessError<M, D> {
    Queue {
        error: VirtualBlockQueueError<M>,
        invalidated: Result<usize, VirtualBlockError>,
    },
    Execution(VirtualBlockExecutionError<M, D>),
}

pub type VirtualBlockProcessResult<M, D> =
    Result<VirtualBlockProcessOutcome<D>, VirtualBlockProcessError<M, D>>;

/// VMM memory authority for the MRML-specific block transport. Request pages
/// are guest-writable; completion slots and read-result payloads are writable
/// only by this device path.
pub trait VirtualBlockVmmMemory: VmBackend {
    fn write_virtual_block(&mut self, guest_address: u64, input: &[u8]) -> Result<(), Self::Error>;
}

/// Copy boundary for disjoint request and completion rings. Any VMM memory
/// uncertainty permanently poisons the bridge; reset requires a fresh bridge
/// and a newly activated device generation.
pub struct VirtualBlockQueueBridge<const N: usize> {
    layout: VirtualBlockQueueLayout,
    request_consumed: u64,
    completion_published: u64,
    poisoned: bool,
}

impl<const N: usize> VirtualBlockQueueBridge<N> {
    pub fn new(layout: VirtualBlockQueueLayout) -> Result<Self, VirtualBlockError> {
        if usize::from(layout.slots()) != N {
            return Err(VirtualBlockError::InvalidQueue);
        }
        Ok(Self {
            layout,
            request_consumed: 0,
            completion_published: 0,
            poisoned: false,
        })
    }

    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub const fn layout(&self) -> VirtualBlockQueueLayout {
        self.layout
    }

    pub fn read_payload<B: VirtualBlockVmmMemory>(
        &mut self,
        backend: &B,
        guest_address: u64,
        output: &mut [u8],
    ) -> Result<(), VirtualBlockQueueError<B::Error>> {
        self.require_live()?;
        self.read(backend, guest_address, output)
    }

    pub fn write_payload<B: VirtualBlockVmmMemory>(
        &mut self,
        backend: &mut B,
        guest_address: u64,
        input: &[u8],
    ) -> Result<(), VirtualBlockQueueError<B::Error>> {
        self.require_live()?;
        self.write(backend, guest_address, input)
    }

    pub fn completion_ready<B: VirtualBlockVmmMemory>(
        &mut self,
        backend: &B,
    ) -> Result<bool, VirtualBlockQueueError<B::Error>> {
        self.require_live()?;
        let consumed = self.read_counter(backend, self.layout.completion_base + 64)?;
        if consumed > self.completion_published || self.completion_published - consumed > N as u64 {
            return Err(VirtualBlockQueueError::Protocol(
                VirtualBlockError::InvalidQueue,
            ));
        }
        Ok(self.completion_published - consumed < N as u64)
    }

    pub fn consume_request<B: VirtualBlockVmmMemory>(
        &mut self,
        backend: &mut B,
        output: &mut [u8; VIRTUAL_BLOCK_REQUEST_BYTES],
    ) -> Result<(), VirtualBlockQueueError<B::Error>> {
        output.fill(0);
        self.require_live()?;
        let published = self.read_counter(backend, self.layout.request_base)?;
        if published < self.request_consumed || published - self.request_consumed > N as u64 {
            return Err(VirtualBlockQueueError::Protocol(
                VirtualBlockError::InvalidQueue,
            ));
        }
        if published == self.request_consumed {
            return Err(VirtualBlockQueueError::Protocol(
                VirtualBlockError::QueueEmpty,
            ));
        }
        let position =
            self.request_consumed
                .checked_add(1)
                .ok_or(VirtualBlockQueueError::Protocol(
                    VirtualBlockError::SequenceExhausted,
                ))?;
        let address = slot_address(
            self.layout.request_base,
            position,
            N,
            VIRTUAL_BLOCK_REQUEST_BYTES,
        )
        .map_err(VirtualBlockQueueError::Protocol)?;
        let mut copied = [0; VIRTUAL_BLOCK_REQUEST_BYTES];
        self.read(backend, address, &mut copied)?;
        self.write_counter(backend, self.layout.request_base + 64, position)?;
        self.request_consumed = position;
        output.copy_from_slice(&copied);
        Ok(())
    }

    pub fn publish_completion<B: VirtualBlockVmmMemory>(
        &mut self,
        backend: &mut B,
        completion: VirtualBlockCompletion,
    ) -> Result<(), VirtualBlockQueueError<B::Error>> {
        self.require_live()?;
        let consumed = self.read_counter(backend, self.layout.completion_base + 64)?;
        if consumed > self.completion_published {
            return Err(VirtualBlockQueueError::Protocol(
                VirtualBlockError::InvalidQueue,
            ));
        }
        if self.completion_published - consumed >= N as u64 {
            return Err(VirtualBlockQueueError::Protocol(
                VirtualBlockError::QueueFull,
            ));
        }
        let position =
            self.completion_published
                .checked_add(1)
                .ok_or(VirtualBlockQueueError::Protocol(
                    VirtualBlockError::SequenceExhausted,
                ))?;
        let address = slot_address(
            self.layout.completion_base,
            position,
            N,
            VIRTUAL_BLOCK_COMPLETION_BYTES,
        )
        .map_err(VirtualBlockQueueError::Protocol)?;
        let mut encoded = [0; VIRTUAL_BLOCK_COMPLETION_BYTES];
        completion.encode(&mut encoded);
        self.write(backend, address, &encoded)?;
        self.write_counter(backend, self.layout.completion_base, position)?;
        self.completion_published = position;
        Ok(())
    }

    fn require_live<E>(&self) -> Result<(), VirtualBlockQueueError<E>> {
        if self.poisoned {
            Err(VirtualBlockQueueError::Poisoned)
        } else {
            Ok(())
        }
    }

    fn fail_stop(&mut self) {
        self.poisoned = true;
    }

    fn read_counter<B: VmBackend>(
        &mut self,
        backend: &B,
        address: u64,
    ) -> Result<u64, VirtualBlockQueueError<B::Error>> {
        let mut encoded = [0; 8];
        self.read(backend, address, &mut encoded)?;
        Ok(u64::from_le_bytes(encoded))
    }

    fn write_counter<B: VirtualBlockVmmMemory>(
        &mut self,
        backend: &mut B,
        address: u64,
        value: u64,
    ) -> Result<(), VirtualBlockQueueError<B::Error>> {
        self.write(backend, address, &value.to_le_bytes())
    }

    fn read<B: VmBackend>(
        &mut self,
        backend: &B,
        address: u64,
        output: &mut [u8],
    ) -> Result<(), VirtualBlockQueueError<B::Error>> {
        backend.read_guest(address, output).map_err(|error| {
            self.poisoned = true;
            VirtualBlockQueueError::Backend(error)
        })
    }

    fn write<B: VirtualBlockVmmMemory>(
        &mut self,
        backend: &mut B,
        address: u64,
        input: &[u8],
    ) -> Result<(), VirtualBlockQueueError<B::Error>> {
        backend
            .write_virtual_block(address, input)
            .map_err(|error| {
                self.poisoned = true;
                VirtualBlockQueueError::Backend(error)
            })
    }
}

/// Executes one already admitted request through private bounded scratch.
/// Queue consumption and completion publication remain separate so transports
/// can preserve their own ordering and interrupt semantics.
pub fn execute_virtual_block_request<const N: usize, M, D>(
    device: &mut VirtualBlockDevice<N>,
    bridge: &mut VirtualBlockQueueBridge<N>,
    memory: &mut M,
    backend: &mut D,
    admitted: AdmittedVirtualBlockRequest,
    scratch: &mut [u8],
) -> VirtualBlockExecutionResult<M::Error, D::Error>
where
    M: VirtualBlockVmmMemory,
    D: VirtualBlockBackend,
{
    let request = admitted.request();
    scratch.fill(0);
    if device.state() != VirtualBlockDeviceState::Active || bridge.is_poisoned() {
        return Err(VirtualBlockExecutionError::Protocol(
            VirtualBlockError::InvalidState,
        ));
    }
    if device.queue() != Some(bridge.layout()) {
        return Err(VirtualBlockExecutionError::Protocol(
            VirtualBlockError::InvalidQueue,
        ));
    }
    let (_, inflight) = device
        .inflight(admitted.ticket())
        .map_err(VirtualBlockExecutionError::Protocol)?;
    if inflight.operation != request.operation()
        || inflight.transfer_bytes != request.buffer_length()
        || inflight.device_generation != request.generation()
        || inflight.request_id != request.request_id()
    {
        return Err(VirtualBlockExecutionError::Protocol(
            VirtualBlockError::StaleTicket,
        ));
    }
    let transfer_bytes = usize::try_from(request.buffer_length())
        .map_err(|_| VirtualBlockExecutionError::Protocol(VirtualBlockError::InvalidBuffer))?;
    if scratch.len() < transfer_bytes {
        return Err(VirtualBlockExecutionError::Protocol(
            VirtualBlockError::InvalidBuffer,
        ));
    }
    let work = &mut scratch[..transfer_bytes];

    let rejection = match request.operation() {
        VirtualBlockOperation::Read => match backend.read_blocks(request.block(), work) {
            Ok(()) => match bridge.write_payload(memory, request.buffer_address(), work) {
                Ok(()) => None,
                Err(error) => {
                    work.fill(0);
                    return Err(VirtualBlockExecutionError::GuestMemory {
                        error,
                        invalidated: device.fail(),
                    });
                }
            },
            Err(error) => Some(error),
        },
        VirtualBlockOperation::Write => {
            if let Err(error) = bridge.read_payload(memory, request.buffer_address(), work) {
                work.fill(0);
                return Err(VirtualBlockExecutionError::GuestMemory {
                    error,
                    invalidated: device.fail(),
                });
            }
            match backend.write_blocks(request.block(), work) {
                Ok(()) => None,
                Err(VirtualBlockMutationError::Rejected(error)) => Some(error),
                Err(VirtualBlockMutationError::Uncertain(error)) => {
                    work.fill(0);
                    bridge.fail_stop();
                    return Err(VirtualBlockExecutionError::BackendUncertain {
                        error,
                        invalidated: device.fail(),
                    });
                }
            }
        }
        VirtualBlockOperation::Flush => match backend.flush() {
            Ok(()) => None,
            Err(VirtualBlockMutationError::Rejected(error)) => Some(error),
            Err(VirtualBlockMutationError::Uncertain(error)) => {
                bridge.fail_stop();
                return Err(VirtualBlockExecutionError::BackendUncertain {
                    error,
                    invalidated: device.fail(),
                });
            }
        },
    };

    work.fill(0);
    let status = if rejection.is_some() {
        VirtualBlockCompletionStatus::DeviceError
    } else {
        VirtualBlockCompletionStatus::Ok
    };
    let transferred = if status == VirtualBlockCompletionStatus::Ok {
        request.buffer_length()
    } else {
        0
    };
    let completion = match device.complete(admitted.ticket(), status, transferred) {
        Ok(completion) => completion,
        Err(error) => {
            bridge.fail_stop();
            let _ = device.fail();
            return Err(VirtualBlockExecutionError::Protocol(error));
        }
    };
    Ok(match rejection {
        Some(error) => VirtualBlockExecutionOutcome::BackendRejected { completion, error },
        None => VirtualBlockExecutionOutcome::Completed(completion),
    })
}

/// Processes at most one request as a complete queue transaction. Completion
/// capacity and device admission are checked before the request is consumed.
/// Interrupt delivery remains a separate capability-authorized operation.
pub fn process_virtual_block_request<const N: usize, M, D>(
    device: &mut VirtualBlockDevice<N>,
    bridge: &mut VirtualBlockQueueBridge<N>,
    memory: &mut M,
    backend: &mut D,
    scratch: &mut [u8],
) -> VirtualBlockProcessResult<M::Error, D::Error>
where
    M: VirtualBlockVmmMemory,
    D: VirtualBlockBackend,
{
    scratch.fill(0);
    match device.admission_ready() {
        Ok(true) => {}
        Ok(false) => return Ok(VirtualBlockProcessOutcome::Backpressured),
        Err(error) => {
            bridge.fail_stop();
            return Err(VirtualBlockProcessError::Queue {
                error: VirtualBlockQueueError::Protocol(error),
                invalidated: device.fail(),
            });
        }
    }
    match bridge.completion_ready(memory) {
        Ok(true) => {}
        Ok(false) => return Ok(VirtualBlockProcessOutcome::Backpressured),
        Err(error) => {
            bridge.fail_stop();
            return Err(VirtualBlockProcessError::Queue {
                error,
                invalidated: device.fail(),
            });
        }
    }

    let mut encoded = [0; VIRTUAL_BLOCK_REQUEST_BYTES];
    match bridge.consume_request(memory, &mut encoded) {
        Ok(()) => {}
        Err(VirtualBlockQueueError::Protocol(VirtualBlockError::QueueEmpty)) => {
            return Ok(VirtualBlockProcessOutcome::Idle);
        }
        Err(error) => {
            bridge.fail_stop();
            return Err(VirtualBlockProcessError::Queue {
                error,
                invalidated: device.fail(),
            });
        }
    }
    let admitted = match device.admit(&encoded) {
        Ok(admitted) => admitted,
        Err(error) => {
            encoded.fill(0);
            return Ok(VirtualBlockProcessOutcome::Rejected(error));
        }
    };
    encoded.fill(0);
    let execution =
        match execute_virtual_block_request(device, bridge, memory, backend, admitted, scratch) {
            Ok(execution) => execution,
            Err(error) => {
                bridge.fail_stop();
                let _ = device.fail();
                return Err(VirtualBlockProcessError::Execution(error));
            }
        };
    if let Err(error) = bridge.publish_completion(memory, execution.completion()) {
        bridge.fail_stop();
        return Err(VirtualBlockProcessError::Queue {
            error,
            invalidated: device.fail(),
        });
    }
    Ok(VirtualBlockProcessOutcome::Completed(execution))
}

fn slot_address(
    base: u64,
    position: u64,
    slots: usize,
    slot_bytes: usize,
) -> Result<u64, VirtualBlockError> {
    if position == 0 || slots == 0 {
        return Err(VirtualBlockError::InvalidQueue);
    }
    let slot = (position - 1) % slots as u64;
    base.checked_add(QUEUE_HEADER_BYTES)
        .and_then(|address| address.checked_add(slot * slot_bytes as u64))
        .ok_or(VirtualBlockError::RangeOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VmExit;

    fn layout<const N: usize>() -> VirtualBlockQueueLayout {
        VirtualBlockQueueLayout::new(0x1000, 0x3000, N).unwrap()
    }

    fn active<const N: usize>() -> VirtualBlockDevice<N> {
        let mut device = VirtualBlockDevice::new(4096, 64, VIRTUAL_BLOCK_FEATURE_FLUSH).unwrap();
        device.negotiate(VIRTUAL_BLOCK_FEATURE_FLUSH).unwrap();
        device.activate(layout::<N>(), 48).unwrap();
        device
    }

    fn encoded(request: VirtualBlockRequest) -> [u8; VIRTUAL_BLOCK_REQUEST_BYTES] {
        let mut output = [0; VIRTUAL_BLOCK_REQUEST_BYTES];
        request.encode(&mut output);
        output
    }

    #[test]
    fn canonical_requests_reject_hidden_unknown_and_invalid_ranges() {
        let request = VirtualBlockRequest::write(1, 1, 63, 1, 0x8000, 4096);
        let mut bytes = encoded(request);
        assert_eq!(VirtualBlockRequest::decode(&bytes), Ok(request));
        bytes[63] = 1;
        assert_eq!(
            VirtualBlockRequest::decode(&bytes),
            Err(VirtualBlockError::MalformedRequest)
        );
        bytes = encoded(request);
        bytes[5] = 0xff;
        assert_eq!(
            VirtualBlockRequest::decode(&bytes),
            Err(VirtualBlockError::UnsupportedOperation)
        );
        bytes = encoded(request);
        bytes[8..12].fill(0);
        assert_eq!(
            VirtualBlockRequest::decode(&bytes),
            Err(VirtualBlockError::MalformedRequest)
        );

        let mut device = active::<2>();
        assert_eq!(
            device.admit(&encoded(VirtualBlockRequest::read(
                1, 1, 64, 1, 0x8000, 4096
            ))),
            Err(VirtualBlockError::InvalidRange)
        );
        assert_eq!(
            device.admit(&encoded(VirtualBlockRequest::read(1, 1, 0, 1, 3, 4096))),
            Err(VirtualBlockError::InvalidBuffer)
        );
        assert_eq!(
            device.admit(&encoded(VirtualBlockRequest::flush(2, 1))),
            Err(VirtualBlockError::StaleGeneration)
        );
    }

    #[test]
    fn lifecycle_negotiation_reset_and_removal_invalidate_stale_work() {
        let mut device =
            VirtualBlockDevice::<2>::new(4096, 64, VIRTUAL_BLOCK_FEATURE_FLUSH).unwrap();
        assert_eq!(device.state(), VirtualBlockDeviceState::Created);
        assert_eq!(device.negotiate(2), Err(VirtualBlockError::InvalidFeatures));
        device.negotiate(VIRTUAL_BLOCK_FEATURE_FLUSH).unwrap();
        assert_eq!(
            device.activate(layout::<2>(), 31),
            Err(VirtualBlockError::InvalidInterrupt)
        );
        device.activate(layout::<2>(), 48).unwrap();
        let admitted = device
            .admit(&encoded(VirtualBlockRequest::read(
                1, 1, 0, 1, 0x8000, 4096,
            )))
            .unwrap();
        assert_eq!(device.suspend(), Err(VirtualBlockError::InvalidState));
        assert_eq!(device.reset(), Ok(1));
        assert_eq!(
            (device.state(), device.generation()),
            (VirtualBlockDeviceState::Created, 2)
        );
        assert_eq!(
            device.complete(admitted.ticket(), VirtualBlockCompletionStatus::Ok, 4096),
            Err(VirtualBlockError::InvalidState)
        );
        device.negotiate(0).unwrap();
        device.activate(layout::<2>(), 49).unwrap();
        assert_eq!(
            device.admit(&encoded(VirtualBlockRequest::read(
                1, 2, 0, 1, 0x8000, 4096
            ))),
            Err(VirtualBlockError::StaleGeneration)
        );
        assert_eq!(device.remove(), Ok(0));
        assert_eq!(device.state(), VirtualBlockDeviceState::Removed);
        device.destroy().unwrap();
        assert_eq!(device.state(), VirtualBlockDeviceState::Destroyed);
    }

    #[test]
    fn reset_exhaustion_preserves_live_state_and_inflight_ticket() {
        let mut device = active::<1>();
        let admitted = device
            .admit(&encoded(VirtualBlockRequest::read(
                1, 1, 0, 1, 0x8000, 4096,
            )))
            .unwrap();
        device.slot_generations[0] = u32::MAX;
        assert_eq!(device.reset(), Err(VirtualBlockError::SequenceExhausted));
        assert_eq!(device.state(), VirtualBlockDeviceState::Active);
        assert_eq!(
            device
                .complete(admitted.ticket(), VirtualBlockCompletionStatus::Ok, 4096,)
                .map(|completion| completion.request_id()),
            Ok(1)
        );
    }

    #[test]
    fn fail_exhaustion_is_terminal_instead_of_returning_to_active_use() {
        let mut device = active::<1>();
        let admitted = device
            .admit(&encoded(VirtualBlockRequest::read(
                1, 1, 0, 1, 0x8000, 4096,
            )))
            .unwrap();
        device.slot_generations[0] = u32::MAX;
        assert_eq!(device.fail(), Err(VirtualBlockError::SequenceExhausted));
        assert_eq!(device.state(), VirtualBlockDeviceState::Failed);
        assert_eq!(
            device.complete(admitted.ticket(), VirtualBlockCompletionStatus::Ok, 4096),
            Err(VirtualBlockError::InvalidState)
        );
        assert_eq!(
            device.admit(&encoded(VirtualBlockRequest::read(
                1, 2, 1, 1, 0x9000, 4096,
            ))),
            Err(VirtualBlockError::InvalidState)
        );
    }

    #[test]
    fn admission_is_monotonic_bounded_and_completion_is_ticket_bound() {
        let mut device = active::<1>();
        let first = device
            .admit(&encoded(VirtualBlockRequest::read(
                1, 7, 0, 1, 0x8000, 4096,
            )))
            .unwrap();
        assert_eq!(
            device.admit(&encoded(VirtualBlockRequest::write(
                1, 8, 1, 1, 0x9000, 4096
            ))),
            Err(VirtualBlockError::QueueFull)
        );
        let mut forged = first.ticket();
        forged.request_id = 8;
        assert_eq!(
            device.complete(forged, VirtualBlockCompletionStatus::Ok, 4096),
            Err(VirtualBlockError::StaleTicket)
        );
        let completion = device
            .complete(first.ticket(), VirtualBlockCompletionStatus::Ok, 4096)
            .unwrap();
        assert_eq!(
            (completion.request_id(), completion.transferred()),
            (7, 4096)
        );
        assert_eq!(
            device.admit(&encoded(VirtualBlockRequest::read(
                1, 7, 0, 1, 0x8000, 4096
            ))),
            Err(VirtualBlockError::Replay)
        );
    }

    #[test]
    fn admission_skips_exhausted_empty_slots_and_reports_terminal_exhaustion() {
        let mut device = active::<2>();
        device.slot_generations[0] = u32::MAX;
        let admitted = device
            .admit(&encoded(VirtualBlockRequest::read(
                1, 1, 0, 1, 0x8000, 4096,
            )))
            .unwrap();
        assert_eq!(admitted.ticket().slot, 1);
        device
            .complete(admitted.ticket(), VirtualBlockCompletionStatus::Ok, 4096)
            .unwrap();
        device.slot_generations[1] = u32::MAX;
        assert_eq!(
            device.admission_ready(),
            Err(VirtualBlockError::SequenceExhausted)
        );
        assert_eq!(
            device.admit(&encoded(VirtualBlockRequest::read(
                1, 2, 1, 1, 0x9000, 4096,
            ))),
            Err(VirtualBlockError::SequenceExhausted)
        );
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MockError {
        Bounds,
        Injected,
    }

    struct MockVmm {
        bytes: [u8; 0x5000],
        fail_read: bool,
        fail_write: bool,
        fail_write_address: Option<u64>,
    }

    impl MockVmm {
        fn new() -> Self {
            Self {
                bytes: [0; 0x5000],
                fail_read: false,
                fail_write: false,
                fail_write_address: None,
            }
        }
    }

    impl VmBackend for MockVmm {
        type Error = MockError;

        fn run(&mut self, _: u32) -> Result<VmExit, Self::Error> {
            unreachable!()
        }

        fn read_guest(&self, address: u64, output: &mut [u8]) -> Result<(), Self::Error> {
            if self.fail_read {
                return Err(MockError::Injected);
            }
            let start = usize::try_from(address).map_err(|_| MockError::Bounds)?;
            let end = start.checked_add(output.len()).ok_or(MockError::Bounds)?;
            output.copy_from_slice(self.bytes.get(start..end).ok_or(MockError::Bounds)?);
            Ok(())
        }

        fn write_guest(&mut self, address: u64, input: &[u8]) -> Result<(), Self::Error> {
            self.write_virtual_block(address, input)
        }

        fn inject_interrupt(&mut self, _: u32, _: u8) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl VirtualBlockVmmMemory for MockVmm {
        fn write_virtual_block(&mut self, address: u64, input: &[u8]) -> Result<(), Self::Error> {
            if self.fail_write || self.fail_write_address == Some(address) {
                return Err(MockError::Injected);
            }
            let start = usize::try_from(address).map_err(|_| MockError::Bounds)?;
            let end = start.checked_add(input.len()).ok_or(MockError::Bounds)?;
            self.bytes
                .get_mut(start..end)
                .ok_or(MockError::Bounds)?
                .copy_from_slice(input);
            Ok(())
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MockMutation {
        Complete,
        Reject,
        Uncertain,
    }

    struct MockBlock {
        bytes: [u8; 0x4000],
        mutation: MockMutation,
        reads: usize,
        writes: usize,
        flushes: usize,
    }

    impl MockBlock {
        fn new() -> Self {
            Self {
                bytes: [0; 0x4000],
                mutation: MockMutation::Complete,
                reads: 0,
                writes: 0,
                flushes: 0,
            }
        }

        fn range(&self, block: u64, bytes: usize) -> Result<core::ops::Range<usize>, MockError> {
            let start = usize::try_from(block)
                .ok()
                .and_then(|block| block.checked_mul(4096))
                .ok_or(MockError::Bounds)?;
            let end = start.checked_add(bytes).ok_or(MockError::Bounds)?;
            self.bytes.get(start..end).ok_or(MockError::Bounds)?;
            Ok(start..end)
        }
    }

    unsafe impl VirtualBlockBackend for MockBlock {
        type Error = MockError;

        fn read_blocks(&mut self, block: u64, output: &mut [u8]) -> Result<(), Self::Error> {
            let range = self.range(block, output.len())?;
            self.reads += 1;
            output.copy_from_slice(&self.bytes[range]);
            Ok(())
        }

        fn write_blocks(
            &mut self,
            block: u64,
            input: &[u8],
        ) -> Result<(), VirtualBlockMutationError<Self::Error>> {
            let range = self
                .range(block, input.len())
                .map_err(VirtualBlockMutationError::Rejected)?;
            self.writes += 1;
            match self.mutation {
                MockMutation::Complete => {
                    self.bytes[range].copy_from_slice(input);
                    Ok(())
                }
                MockMutation::Reject => {
                    Err(VirtualBlockMutationError::Rejected(MockError::Injected))
                }
                MockMutation::Uncertain => {
                    self.bytes[range.start] = input[0];
                    Err(VirtualBlockMutationError::Uncertain(MockError::Injected))
                }
            }
        }

        fn flush(&mut self) -> Result<(), VirtualBlockMutationError<Self::Error>> {
            self.flushes += 1;
            match self.mutation {
                MockMutation::Complete => Ok(()),
                MockMutation::Reject => {
                    Err(VirtualBlockMutationError::Rejected(MockError::Injected))
                }
                MockMutation::Uncertain => {
                    Err(VirtualBlockMutationError::Uncertain(MockError::Injected))
                }
            }
        }
    }

    #[test]
    fn executor_copies_reads_and_writes_privately_and_flushes() {
        let mut device = active::<2>();
        let mut bridge = VirtualBlockQueueBridge::<2>::new(layout::<2>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        backend.bytes[4096..8192].fill(0x5a);

        let read = device
            .admit(&encoded(VirtualBlockRequest::read(
                1, 1, 1, 1, 0x4000, 4096,
            )))
            .unwrap();
        let outcome = execute_virtual_block_request(
            &mut device,
            &mut bridge,
            &mut vmm,
            &mut backend,
            read,
            &mut scratch,
        )
        .unwrap();
        assert!(matches!(
            outcome,
            VirtualBlockExecutionOutcome::Completed(_)
        ));
        assert!(vmm.bytes[0x4000..0x5000].iter().all(|byte| *byte == 0x5a));
        assert!(scratch.iter().all(|byte| *byte == 0));

        vmm.bytes[0x4000..0x5000].fill(0x3c);
        let write = device
            .admit(&encoded(VirtualBlockRequest::write(
                1, 2, 2, 1, 0x4000, 4096,
            )))
            .unwrap();
        execute_virtual_block_request(
            &mut device,
            &mut bridge,
            &mut vmm,
            &mut backend,
            write,
            &mut scratch,
        )
        .unwrap();
        assert!(backend.bytes[8192..12_288].iter().all(|byte| *byte == 0x3c));
        assert!(scratch.iter().all(|byte| *byte == 0));
        assert_eq!(
            execute_virtual_block_request(
                &mut device,
                &mut bridge,
                &mut vmm,
                &mut backend,
                write,
                &mut scratch,
            ),
            Err(VirtualBlockExecutionError::Protocol(
                VirtualBlockError::StaleTicket
            ))
        );
        assert_eq!(backend.writes, 1);

        let flush = device
            .admit(&encoded(VirtualBlockRequest::flush(1, 3)))
            .unwrap();
        execute_virtual_block_request(
            &mut device,
            &mut bridge,
            &mut vmm,
            &mut backend,
            flush,
            &mut scratch,
        )
        .unwrap();
        assert_eq!((backend.reads, backend.writes, backend.flushes), (1, 1, 1));
        assert_eq!(device.state(), VirtualBlockDeviceState::Active);
    }

    #[test]
    fn executor_distinguishes_clean_rejection_from_uncertain_mutation() {
        let mut device = active::<2>();
        let mut bridge = VirtualBlockQueueBridge::<2>::new(layout::<2>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        vmm.bytes[0x4000..0x5000].fill(0x7b);

        backend.mutation = MockMutation::Reject;
        let rejected = device
            .admit(&encoded(VirtualBlockRequest::write(
                1, 1, 0, 1, 0x4000, 4096,
            )))
            .unwrap();
        assert_eq!(
            execute_virtual_block_request(
                &mut device,
                &mut bridge,
                &mut vmm,
                &mut backend,
                rejected,
                &mut scratch,
            ),
            Ok(VirtualBlockExecutionOutcome::BackendRejected {
                completion: VirtualBlockCompletion {
                    generation: 1,
                    request_id: 1,
                    status: VirtualBlockCompletionStatus::DeviceError,
                    transferred: 0,
                },
                error: MockError::Injected,
            })
        );
        assert_eq!(device.state(), VirtualBlockDeviceState::Active);
        assert!(!bridge.is_poisoned());

        backend.mutation = MockMutation::Uncertain;
        let uncertain = device
            .admit(&encoded(VirtualBlockRequest::write(
                1, 2, 1, 1, 0x4000, 4096,
            )))
            .unwrap();
        assert_eq!(
            execute_virtual_block_request(
                &mut device,
                &mut bridge,
                &mut vmm,
                &mut backend,
                uncertain,
                &mut scratch,
            ),
            Err(VirtualBlockExecutionError::BackendUncertain {
                error: MockError::Injected,
                invalidated: Ok(1),
            })
        );
        assert_eq!(device.state(), VirtualBlockDeviceState::Failed);
        assert!(bridge.is_poisoned());
        assert!(scratch.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn executor_guest_memory_uncertainty_precedes_backend_mutation() {
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        let admitted = device
            .admit(&encoded(VirtualBlockRequest::write(
                1, 1, 0, 1, 0x4000, 4096,
            )))
            .unwrap();
        vmm.fail_read = true;
        assert_eq!(
            execute_virtual_block_request(
                &mut device,
                &mut bridge,
                &mut vmm,
                &mut backend,
                admitted,
                &mut scratch,
            ),
            Err(VirtualBlockExecutionError::GuestMemory {
                error: VirtualBlockQueueError::Backend(MockError::Injected),
                invalidated: Ok(1),
            })
        );
        assert_eq!(backend.writes, 0);
        assert_eq!(device.state(), VirtualBlockDeviceState::Failed);
        assert!(bridge.is_poisoned());
        assert!(scratch.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn executor_rejects_wrong_queue_and_scratch_before_backend_access() {
        let mut device = active::<1>();
        let wrong_layout = VirtualBlockQueueLayout::new(0x5000, 0x7000, 1).unwrap();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(wrong_layout).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let admitted = device
            .admit(&encoded(VirtualBlockRequest::read(
                1, 1, 0, 1, 0x4000, 4096,
            )))
            .unwrap();
        let mut scratch = [0xa5; 4096];
        assert_eq!(
            execute_virtual_block_request(
                &mut device,
                &mut bridge,
                &mut vmm,
                &mut backend,
                admitted,
                &mut scratch,
            ),
            Err(VirtualBlockExecutionError::Protocol(
                VirtualBlockError::InvalidQueue
            ))
        );
        assert!(scratch.iter().all(|byte| *byte == 0));
        assert_eq!((backend.reads, backend.writes, backend.flushes), (0, 0, 0));

        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut short_scratch = [0xa5; 4095];
        assert_eq!(
            execute_virtual_block_request(
                &mut device,
                &mut bridge,
                &mut vmm,
                &mut backend,
                admitted,
                &mut short_scratch,
            ),
            Err(VirtualBlockExecutionError::Protocol(
                VirtualBlockError::InvalidBuffer
            ))
        );
        assert!(short_scratch.iter().all(|byte| *byte == 0));
        assert_eq!((backend.reads, backend.writes, backend.flushes), (0, 0, 0));
    }

    #[test]
    fn processor_completes_one_exact_queue_transaction_then_idles() {
        let mut device = active::<2>();
        let mut bridge = VirtualBlockQueueBridge::<2>::new(layout::<2>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        let request = encoded(VirtualBlockRequest::write(1, 1, 2, 1, 0x4000, 4096));
        vmm.bytes[0x4000..0x5000].fill(0x6d);
        vmm.write_guest(0x1000 + QUEUE_HEADER_BYTES, &request)
            .unwrap();
        vmm.write_guest(0x1000, &1u64.to_le_bytes()).unwrap();

        let outcome = process_virtual_block_request(
            &mut device,
            &mut bridge,
            &mut vmm,
            &mut backend,
            &mut scratch,
        )
        .unwrap();
        assert!(matches!(
            outcome,
            VirtualBlockProcessOutcome::Completed(VirtualBlockExecutionOutcome::Completed(_))
        ));
        assert!(backend.bytes[8192..12_288].iter().all(|byte| *byte == 0x6d));
        assert!(scratch.iter().all(|byte| *byte == 0));
        let mut counter = [0; 8];
        vmm.read_guest(0x1040, &mut counter).unwrap();
        assert_eq!(u64::from_le_bytes(counter), 1);
        vmm.read_guest(0x3000, &mut counter).unwrap();
        assert_eq!(u64::from_le_bytes(counter), 1);
        let mut completion = [0; VIRTUAL_BLOCK_COMPLETION_BYTES];
        vmm.read_guest(0x3000 + QUEUE_HEADER_BYTES, &mut completion)
            .unwrap();
        assert_eq!(
            VirtualBlockCompletion::decode(&completion)
                .map(|completion| (completion.request_id(), completion.transferred())),
            Ok((1, 4096))
        );
        assert_eq!(
            process_virtual_block_request(
                &mut device,
                &mut bridge,
                &mut vmm,
                &mut backend,
                &mut scratch,
            ),
            Ok(VirtualBlockProcessOutcome::Idle)
        );
        assert_eq!(backend.writes, 1);
    }

    #[test]
    fn processor_backpressure_precedes_request_consumption() {
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        bridge.completion_published = 1;
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        let request = encoded(VirtualBlockRequest::write(1, 1, 0, 1, 0x4000, 4096));
        vmm.write_guest(0x1000 + QUEUE_HEADER_BYTES, &request)
            .unwrap();
        vmm.write_guest(0x1000, &1u64.to_le_bytes()).unwrap();

        assert_eq!(
            process_virtual_block_request(
                &mut device,
                &mut bridge,
                &mut vmm,
                &mut backend,
                &mut scratch,
            ),
            Ok(VirtualBlockProcessOutcome::Backpressured)
        );
        let mut consumed = [0; 8];
        vmm.read_guest(0x1040, &mut consumed).unwrap();
        assert_eq!(u64::from_le_bytes(consumed), 0);
        assert_eq!((backend.reads, backend.writes, backend.flushes), (0, 0, 0));
        assert_eq!(device.state(), VirtualBlockDeviceState::Active);
        assert!(!bridge.is_poisoned());
    }

    #[test]
    fn processor_consumes_malformed_request_without_backend_access() {
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        let mut request = encoded(VirtualBlockRequest::write(1, 1, 0, 1, 0x4000, 4096));
        request[63] = 1;
        vmm.write_guest(0x1000 + QUEUE_HEADER_BYTES, &request)
            .unwrap();
        vmm.write_guest(0x1000, &1u64.to_le_bytes()).unwrap();

        assert_eq!(
            process_virtual_block_request(
                &mut device,
                &mut bridge,
                &mut vmm,
                &mut backend,
                &mut scratch,
            ),
            Ok(VirtualBlockProcessOutcome::Rejected(
                VirtualBlockError::MalformedRequest
            ))
        );
        assert_eq!((backend.reads, backend.writes, backend.flushes), (0, 0, 0));
        assert_eq!(device.state(), VirtualBlockDeviceState::Active);
        assert!(!bridge.is_poisoned());
        let mut consumed = [0; 8];
        vmm.read_guest(0x1040, &mut consumed).unwrap();
        assert_eq!(u64::from_le_bytes(consumed), 1);
    }

    #[test]
    fn processor_completion_uncertainty_fails_after_one_mutation() {
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        let request = encoded(VirtualBlockRequest::write(1, 1, 0, 1, 0x4000, 4096));
        vmm.bytes[0x4000..0x5000].fill(0x4e);
        vmm.write_guest(0x1000 + QUEUE_HEADER_BYTES, &request)
            .unwrap();
        vmm.write_guest(0x1000, &1u64.to_le_bytes()).unwrap();
        vmm.fail_write_address = Some(0x3000 + QUEUE_HEADER_BYTES);

        assert_eq!(
            process_virtual_block_request(
                &mut device,
                &mut bridge,
                &mut vmm,
                &mut backend,
                &mut scratch,
            ),
            Err(VirtualBlockProcessError::Queue {
                error: VirtualBlockQueueError::Backend(MockError::Injected),
                invalidated: Ok(0),
            })
        );
        assert_eq!(backend.writes, 1);
        assert!(backend.bytes[..4096].iter().all(|byte| *byte == 0x4e));
        assert_eq!(device.state(), VirtualBlockDeviceState::Failed);
        assert!(bridge.is_poisoned());
        assert!(scratch.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn processor_insufficient_scratch_fails_after_admission_before_backend() {
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4095];
        let request = encoded(VirtualBlockRequest::write(1, 1, 0, 1, 0x4000, 4096));
        vmm.write_guest(0x1000 + QUEUE_HEADER_BYTES, &request)
            .unwrap();
        vmm.write_guest(0x1000, &1u64.to_le_bytes()).unwrap();

        assert_eq!(
            process_virtual_block_request(
                &mut device,
                &mut bridge,
                &mut vmm,
                &mut backend,
                &mut scratch,
            ),
            Err(VirtualBlockProcessError::Execution(
                VirtualBlockExecutionError::Protocol(VirtualBlockError::InvalidBuffer)
            ))
        );
        assert_eq!((backend.reads, backend.writes, backend.flushes), (0, 0, 0));
        assert_eq!(device.state(), VirtualBlockDeviceState::Failed);
        assert!(bridge.is_poisoned());
        assert!(scratch.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn queue_bridge_copies_disjoint_slots_and_poison_is_permanent() {
        const N: usize = 2;
        let layout = layout::<N>();
        let mut bridge = VirtualBlockQueueBridge::<N>::new(layout).unwrap();
        let mut vmm = MockVmm::new();
        let request = encoded(VirtualBlockRequest::read(1, 1, 0, 1, 0x4000, 4096));
        let request_slot = 0x1000 + QUEUE_HEADER_BYTES;
        vmm.write_guest(request_slot, &request).unwrap();
        vmm.write_guest(0x1000, &1u64.to_le_bytes()).unwrap();
        let mut copied = [0; VIRTUAL_BLOCK_REQUEST_BYTES];
        bridge.consume_request(&mut vmm, &mut copied).unwrap();
        assert_eq!(copied, request);
        let mut consumed = [0; 8];
        vmm.read_guest(0x1040, &mut consumed).unwrap();
        assert_eq!(u64::from_le_bytes(consumed), 1);

        let mut device = active::<N>();
        let admitted = device.admit(&copied).unwrap();
        let completion = device
            .complete(admitted.ticket(), VirtualBlockCompletionStatus::Ok, 4096)
            .unwrap();
        bridge.publish_completion(&mut vmm, completion).unwrap();
        let mut encoded_completion = [0; VIRTUAL_BLOCK_COMPLETION_BYTES];
        vmm.read_guest(0x3000 + QUEUE_HEADER_BYTES, &mut encoded_completion)
            .unwrap();
        assert_eq!(
            VirtualBlockCompletion::decode(&encoded_completion),
            Ok(completion)
        );

        vmm.fail_read = true;
        assert_eq!(
            bridge.consume_request(&mut vmm, &mut copied),
            Err(VirtualBlockQueueError::Backend(MockError::Injected))
        );
        assert!(bridge.is_poisoned());
        vmm.fail_read = false;
        assert_eq!(
            bridge.publish_completion(&mut vmm, completion),
            Err(VirtualBlockQueueError::Poisoned)
        );
    }

    #[test]
    fn failed_consumed_publication_returns_no_request_and_poisons_bridge() {
        let layout = layout::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout).unwrap();
        let mut vmm = MockVmm::new();
        let request = encoded(VirtualBlockRequest::flush(1, 1));
        vmm.write_guest(0x1000 + QUEUE_HEADER_BYTES, &request)
            .unwrap();
        vmm.write_guest(0x1000, &1u64.to_le_bytes()).unwrap();
        vmm.fail_write = true;
        let mut output = [0xa5; VIRTUAL_BLOCK_REQUEST_BYTES];
        assert_eq!(
            bridge.consume_request(&mut vmm, &mut output),
            Err(VirtualBlockQueueError::Backend(MockError::Injected))
        );
        assert!(output.iter().all(|byte| *byte == 0));
        assert!(bridge.is_poisoned());
    }

    #[test]
    fn hostile_ring_indices_fail_before_slot_or_completion_access() {
        let layout = layout::<2>();
        let mut bridge = VirtualBlockQueueBridge::<2>::new(layout).unwrap();
        let mut vmm = MockVmm::new();
        vmm.write_guest(0x1000, &3u64.to_le_bytes()).unwrap();
        let mut output = [0xa5; VIRTUAL_BLOCK_REQUEST_BYTES];
        assert_eq!(
            bridge.consume_request(&mut vmm, &mut output),
            Err(VirtualBlockQueueError::Protocol(
                VirtualBlockError::InvalidQueue
            ))
        );
        assert!(output.iter().all(|byte| *byte == 0));

        vmm.write_guest(0x3040, &1u64.to_le_bytes()).unwrap();
        let completion = VirtualBlockCompletion {
            generation: 1,
            request_id: 1,
            status: VirtualBlockCompletionStatus::Ok,
            transferred: 4096,
        };
        assert_eq!(
            bridge.publish_completion(&mut vmm, completion),
            Err(VirtualBlockQueueError::Protocol(
                VirtualBlockError::InvalidQueue
            ))
        );
        let completion_slot = 0x3000 + QUEUE_HEADER_BYTES;
        assert!(
            vmm.bytes[completion_slot as usize
                ..completion_slot as usize + VIRTUAL_BLOCK_COMPLETION_BYTES]
                .iter()
                .all(|byte| *byte == 0)
        );
    }

    #[test]
    fn queue_layout_rejects_aliases_capacity_and_overflow() {
        assert_eq!(
            VirtualBlockQueueLayout::new(0x1000, 0x1000, 1),
            Err(VirtualBlockError::InvalidQueue)
        );
        assert_eq!(
            VirtualBlockQueueLayout::new(0x1001, 0x3000, 1),
            Err(VirtualBlockError::InvalidQueue)
        );
        assert_eq!(
            VirtualBlockQueueLayout::new(0x1000, 0x3000, 0),
            Err(VirtualBlockError::InvalidQueue)
        );
        assert_eq!(
            VirtualBlockQueueLayout::new(u64::MAX - PAGE_SIZE + 1, 0x3000, 1),
            Err(VirtualBlockError::RangeOverflow)
        );
    }
}
