use crate::{
    Capability, CapabilityError, CapabilitySpace, ExitDisposition, GuestMemory, HypercallRouter,
    InterruptPolicy, IoDirection, IoPortPolicy, IoPortRule, MmioWriteCompleter, ObjectId,
    PAGE_SIZE, PCI_COMMAND_INTERRUPT_DISABLE, PCI_COMMAND_MEMORY_SPACE, Rights,
    VirtualBlockInterruptError, VirtualPciAttachedFunction, VirtualPciAttachedResources,
    VirtualPciConfigurationRouter, VirtualPciFunctionRevoker, VirtualPciMemoryMapper,
    VirtualPciMmioWindow, VirtualPciNativeResourceError, VmBackend, VmError, VmId, VmRunError,
    VmTable, inject_virtual_block_interrupt, run_vm_once, run_vm_once_for_mmio,
};

pub const VIRTUAL_BLOCK_REQUEST_BYTES: usize = 64;
pub const VIRTUAL_BLOCK_COMPLETION_BYTES: usize = 32;
pub const VIRTUAL_BLOCK_CONFIGURATION_BYTES: usize = 128;
pub const VIRTUAL_BLOCK_RESUME_STATE_BYTES: usize = 192;
pub const MAX_VIRTUAL_BLOCK_QUEUE_SLOTS: usize = 64;
pub const MAX_VIRTUAL_BLOCK_TRANSFER_BYTES: u32 = 1024 * 1024;
pub const VIRTUAL_BLOCK_FEATURE_FLUSH: u64 = 1 << 0;
pub const VIRTUAL_BLOCK_DOORBELL_PORT: u16 = 0x4d42;
pub const VIRTUAL_BLOCK_DOORBELL_VALUE: u32 = 1;
pub const VIRTUAL_BLOCK_COMPLETION_ACK_PORT: u16 = 0x4d43;
pub const VIRTUAL_BLOCK_COMPLETION_ACK_VALUE: u32 = 1;
pub const VIRTUAL_BLOCK_MMIO_DOORBELL_OFFSET: u32 = 0;
pub const VIRTUAL_BLOCK_MMIO_COMPLETION_ACK_OFFSET: u32 = 4;
const REQUEST_MAGIC: [u8; 4] = *b"MRBQ";
const COMPLETION_MAGIC: [u8; 4] = *b"MRBC";
const CONFIGURATION_MAGIC: [u8; 4] = *b"MRBD";
const RESUME_STATE_MAGIC: [u8; 4] = *b"MRBR";
const MRML_SPECIFIC_DEVICE_CLASS: u8 = 1;
const VERSION: u8 = 1;
const QUEUE_HEADER_BYTES: u64 = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualBlockError {
    InvalidGeometry,
    InvalidConfiguration,
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

/// Transport identity for an MRML virtual-block configuration. Transport data
/// selects mechanics only and never grants queue, interrupt, backend, or port
/// authority. Both variants retain the MRML-native queue protocol; PCI-MMIO
/// changes only the notification mechanics and is not VirtIO compatibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualBlockTransport {
    MrmlSpecificScalarIo,
    MrmlSpecificPciMmio,
}

impl VirtualBlockTransport {
    /// Builds the complete deny-by-default VM I/O policy for this transport.
    /// Construction is transactional: no partially populated policy escapes if
    /// either rule is invalid or aliases the other.
    pub fn io_policy(self) -> Result<IoPortPolicy<2>, VmError> {
        let mut policy = IoPortPolicy::deny_all();
        if let Some(port) = self.doorbell_port() {
            policy.allow(IoPortRule::new(port, 4, IoDirection::Write)?)?;
        }
        if let Some(port) = self.completion_acknowledgement_port() {
            policy.allow(IoPortRule::new(port, 4, IoDirection::Write)?)?;
        }
        Ok(policy)
    }

    pub const fn doorbell_port(self) -> Option<u16> {
        match self {
            Self::MrmlSpecificScalarIo => Some(VIRTUAL_BLOCK_DOORBELL_PORT),
            Self::MrmlSpecificPciMmio => None,
        }
    }

    pub const fn doorbell_value(self) -> u32 {
        match self {
            Self::MrmlSpecificScalarIo => VIRTUAL_BLOCK_DOORBELL_VALUE,
            Self::MrmlSpecificPciMmio => VIRTUAL_BLOCK_DOORBELL_VALUE,
        }
    }

    pub const fn completion_acknowledgement_port(self) -> Option<u16> {
        match self {
            Self::MrmlSpecificScalarIo => Some(VIRTUAL_BLOCK_COMPLETION_ACK_PORT),
            Self::MrmlSpecificPciMmio => None,
        }
    }

    pub const fn completion_acknowledgement_value(self) -> u32 {
        match self {
            Self::MrmlSpecificScalarIo => VIRTUAL_BLOCK_COMPLETION_ACK_VALUE,
            Self::MrmlSpecificPciMmio => VIRTUAL_BLOCK_COMPLETION_ACK_VALUE,
        }
    }

    pub const fn doorbell_mmio_offset(self) -> Option<u32> {
        match self {
            Self::MrmlSpecificScalarIo => None,
            Self::MrmlSpecificPciMmio => Some(VIRTUAL_BLOCK_MMIO_DOORBELL_OFFSET),
        }
    }

    pub const fn completion_acknowledgement_mmio_offset(self) -> Option<u32> {
        match self {
            Self::MrmlSpecificScalarIo => None,
            Self::MrmlSpecificPciMmio => Some(VIRTUAL_BLOCK_MMIO_COMPLETION_ACK_OFFSET),
        }
    }

    pub const fn doorbell_notification(self) -> VirtualBlockGuestNotification {
        match self {
            Self::MrmlSpecificScalarIo => VirtualBlockGuestNotification::ScalarIo {
                port: VIRTUAL_BLOCK_DOORBELL_PORT,
                value: VIRTUAL_BLOCK_DOORBELL_VALUE,
            },
            Self::MrmlSpecificPciMmio => VirtualBlockGuestNotification::PciMmio {
                offset: VIRTUAL_BLOCK_MMIO_DOORBELL_OFFSET,
                value: VIRTUAL_BLOCK_DOORBELL_VALUE,
            },
        }
    }

    pub const fn completion_acknowledgement_notification(self) -> VirtualBlockGuestNotification {
        match self {
            Self::MrmlSpecificScalarIo => VirtualBlockGuestNotification::ScalarIo {
                port: VIRTUAL_BLOCK_COMPLETION_ACK_PORT,
                value: VIRTUAL_BLOCK_COMPLETION_ACK_VALUE,
            },
            Self::MrmlSpecificPciMmio => VirtualBlockGuestNotification::PciMmio {
                offset: VIRTUAL_BLOCK_MMIO_COMPLETION_ACK_OFFSET,
                value: VIRTUAL_BLOCK_COMPLETION_ACK_VALUE,
            },
        }
    }
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

/// Canonical pointer-free discovery data for one active MRML-specific block
/// device. This record carries no device, mapping, backend, or interrupt
/// authority. A decoded copy must be revalidated against the live device before
/// use because reset and reconfiguration make old snapshots stale.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualBlockConfiguration {
    generation: u32,
    block_size: u32,
    block_count: u64,
    supported_features: u64,
    negotiated_features: u64,
    queue: VirtualBlockQueueLayout,
    interrupt_vector: u8,
    transport: VirtualBlockTransport,
}

impl VirtualBlockConfiguration {
    pub const fn generation(self) -> u32 {
        self.generation
    }

    pub const fn block_size(self) -> u32 {
        self.block_size
    }

    pub const fn block_count(self) -> u64 {
        self.block_count
    }

    pub const fn supported_features(self) -> u64 {
        self.supported_features
    }

    pub const fn negotiated_features(self) -> u64 {
        self.negotiated_features
    }

    pub const fn queue(self) -> VirtualBlockQueueLayout {
        self.queue
    }

    pub const fn interrupt_vector(self) -> u8 {
        self.interrupt_vector
    }

    pub const fn transport(self) -> VirtualBlockTransport {
        self.transport
    }

    pub fn encode(self, output: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]) {
        output.fill(0);
        output[..4].copy_from_slice(&CONFIGURATION_MAGIC);
        output[4] = VERSION;
        output[5] = MRML_SPECIFIC_DEVICE_CLASS;
        output[8..12].copy_from_slice(&self.generation.to_le_bytes());
        output[12..16].copy_from_slice(&self.block_size.to_le_bytes());
        output[16..24].copy_from_slice(&self.block_count.to_le_bytes());
        output[24..32].copy_from_slice(&self.supported_features.to_le_bytes());
        output[32..40].copy_from_slice(&self.negotiated_features.to_le_bytes());
        output[40..48].copy_from_slice(&self.queue.request_base().to_le_bytes());
        output[48..56].copy_from_slice(&self.queue.completion_base().to_le_bytes());
        output[56..64].copy_from_slice(&self.queue.pages_per_queue().to_le_bytes());
        output[64..66].copy_from_slice(&self.queue.slots().to_le_bytes());
        output[66] = self.interrupt_vector;
        match self.transport {
            VirtualBlockTransport::MrmlSpecificScalarIo => {
                output[67] = 0;
                output[68..70].copy_from_slice(&VIRTUAL_BLOCK_DOORBELL_PORT.to_le_bytes());
                output[70..72].copy_from_slice(&VIRTUAL_BLOCK_COMPLETION_ACK_PORT.to_le_bytes());
            }
            VirtualBlockTransport::MrmlSpecificPciMmio => {
                output[67] = 1;
                output[68..70]
                    .copy_from_slice(&(VIRTUAL_BLOCK_MMIO_DOORBELL_OFFSET as u16).to_le_bytes());
                output[70..72].copy_from_slice(
                    &(VIRTUAL_BLOCK_MMIO_COMPLETION_ACK_OFFSET as u16).to_le_bytes(),
                );
            }
        }
        output[72..76].copy_from_slice(&MAX_VIRTUAL_BLOCK_TRANSFER_BYTES.to_le_bytes());
        output[76..78].copy_from_slice(&(VIRTUAL_BLOCK_REQUEST_BYTES as u16).to_le_bytes());
        output[78..80].copy_from_slice(&(VIRTUAL_BLOCK_COMPLETION_BYTES as u16).to_le_bytes());
    }

    pub fn decode(input: &[u8]) -> Result<Self, VirtualBlockError> {
        if input.len() != VIRTUAL_BLOCK_CONFIGURATION_BYTES
            || input[..4] != CONFIGURATION_MAGIC
            || input[4] != VERSION
            || input[5] != MRML_SPECIFIC_DEVICE_CLASS
            || input[6..8].iter().any(|byte| *byte != 0)
            || input[80..].iter().any(|byte| *byte != 0)
            || u32::from_le_bytes(input[72..76].try_into().unwrap())
                != MAX_VIRTUAL_BLOCK_TRANSFER_BYTES
            || u16::from_le_bytes(input[76..78].try_into().unwrap())
                != VIRTUAL_BLOCK_REQUEST_BYTES as u16
            || u16::from_le_bytes(input[78..80].try_into().unwrap())
                != VIRTUAL_BLOCK_COMPLETION_BYTES as u16
        {
            return Err(VirtualBlockError::InvalidConfiguration);
        }
        let transport = match input[67] {
            0 if u16::from_le_bytes(input[68..70].try_into().unwrap())
                == VIRTUAL_BLOCK_DOORBELL_PORT
                && u16::from_le_bytes(input[70..72].try_into().unwrap())
                    == VIRTUAL_BLOCK_COMPLETION_ACK_PORT =>
            {
                VirtualBlockTransport::MrmlSpecificScalarIo
            }
            1 if u16::from_le_bytes(input[68..70].try_into().unwrap())
                == VIRTUAL_BLOCK_MMIO_DOORBELL_OFFSET as u16
                && u16::from_le_bytes(input[70..72].try_into().unwrap())
                    == VIRTUAL_BLOCK_MMIO_COMPLETION_ACK_OFFSET as u16 =>
            {
                VirtualBlockTransport::MrmlSpecificPciMmio
            }
            _ => return Err(VirtualBlockError::InvalidConfiguration),
        };
        let generation = u32::from_le_bytes(input[8..12].try_into().unwrap());
        let block_size = u32::from_le_bytes(input[12..16].try_into().unwrap());
        let block_count = u64::from_le_bytes(input[16..24].try_into().unwrap());
        let supported_features = u64::from_le_bytes(input[24..32].try_into().unwrap());
        let negotiated_features = u64::from_le_bytes(input[32..40].try_into().unwrap());
        let pages_per_queue = u64::from_le_bytes(input[56..64].try_into().unwrap());
        let slots = usize::from(u16::from_le_bytes(input[64..66].try_into().unwrap()));
        let interrupt_vector = input[66];
        if generation == 0
            || !(4096..=65_536).contains(&block_size)
            || !block_size.is_power_of_two()
            || block_count == 0
            || supported_features & !VIRTUAL_BLOCK_FEATURE_FLUSH != 0
            || negotiated_features & !supported_features != 0
            || !(32..=254).contains(&interrupt_vector)
        {
            return Err(VirtualBlockError::InvalidConfiguration);
        }
        let queue = VirtualBlockQueueLayout::new(
            u64::from_le_bytes(input[40..48].try_into().unwrap()),
            u64::from_le_bytes(input[48..56].try_into().unwrap()),
            slots,
        )
        .map_err(|_| VirtualBlockError::InvalidConfiguration)?;
        if queue.pages_per_queue() != pages_per_queue {
            return Err(VirtualBlockError::InvalidConfiguration);
        }
        Ok(Self {
            generation,
            block_size,
            block_count,
            supported_features,
            negotiated_features,
            queue,
            interrupt_vector,
            transport,
        })
    }
}

/// One page-aligned guest presentation of canonical configuration data. The
/// page carries no authority and must be mapped read-only by a concrete VMM.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualBlockConfigurationPage {
    base: u64,
    configuration: VirtualBlockConfiguration,
}

impl VirtualBlockConfigurationPage {
    pub fn new(
        base: u64,
        configuration: VirtualBlockConfiguration,
    ) -> Result<Self, VirtualBlockError> {
        let end = base
            .checked_add(PAGE_SIZE)
            .ok_or(VirtualBlockError::InvalidConfiguration)?;
        if base == 0 || !base.is_multiple_of(PAGE_SIZE) {
            return Err(VirtualBlockError::InvalidConfiguration);
        }
        let queue = configuration.queue();
        let queue_bytes = queue
            .pages_per_queue()
            .checked_mul(PAGE_SIZE)
            .ok_or(VirtualBlockError::InvalidConfiguration)?;
        for queue_base in [queue.request_base(), queue.completion_base()] {
            let queue_end = queue_base
                .checked_add(queue_bytes)
                .ok_or(VirtualBlockError::InvalidConfiguration)?;
            if base < queue_end && queue_base < end {
                return Err(VirtualBlockError::InvalidConfiguration);
            }
        }
        Ok(Self {
            base,
            configuration,
        })
    }

    pub const fn base(self) -> u64 {
        self.base
    }

    pub const fn configuration(self) -> VirtualBlockConfiguration {
        self.configuration
    }

    pub fn encode_page(self, output: &mut [u8; PAGE_SIZE as usize]) {
        output.fill(0);
        let record = <&mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]>::try_from(
            &mut output[..VIRTUAL_BLOCK_CONFIGURATION_BYTES],
        )
        .unwrap();
        self.configuration.encode(record);
    }
}

/// Canonical data-only snapshot needed to reconstruct this guest driver's
/// nonzero queue history. It carries no capability and is useful only while it
/// exactly matches the quiesced active device, bridge, and request ring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualBlockResumeState {
    configuration: VirtualBlockConfiguration,
    request_producer: u64,
    request_consumed: u64,
    completion_published: u64,
    completion_consumer: u64,
    last_admitted_request_id: u64,
    last_published_request_id: u64,
}

/// One page-aligned, guest-read-only presentation of canonical resume state.
/// The page is device-writable only through the virtual-block VMM boundary and
/// carries no authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualBlockResumePage {
    base: u64,
    configuration_base: u64,
    state: VirtualBlockResumeState,
}

/// Canonical, allocation-free data needed to reconstruct one suspended
/// virtual-block guest. The image carries no capability, backend handle, or
/// permission to resume the device. Unused physical slots are zero so stale
/// queue history is not retained across replacement.
pub struct VirtualBlockRestartImage {
    resume_base: u64,
    configuration_base: u64,
    state: VirtualBlockResumeState,
    request_slots: [[u8; VIRTUAL_BLOCK_REQUEST_BYTES]; MAX_VIRTUAL_BLOCK_QUEUE_SLOTS],
    completion_slots: [[u8; VIRTUAL_BLOCK_COMPLETION_BYTES]; MAX_VIRTUAL_BLOCK_QUEUE_SLOTS],
    encoded_resume_page: [u8; PAGE_SIZE as usize],
}

impl VirtualBlockRestartImage {
    pub const fn state(&self) -> VirtualBlockResumeState {
        self.state
    }

    /// Confirms that the native execution context captured by this image has
    /// been irreversibly destroyed and makes the image eligible for one
    /// replacement restoration.
    ///
    /// # Safety
    ///
    /// The caller must have consumed and destroyed the exact native VM whose
    /// guest memory produced this image. No runnable old execution context may
    /// remain, and no retained memory object may be used to resume that context
    /// or seed another replacement. The exact device and bridge must remain
    /// suspended and unchanged. This transition does not itself grant device-
    /// resume authority.
    pub unsafe fn confirm_execution_loss(self) -> VirtualBlockLostExecution {
        VirtualBlockLostExecution { image: self }
    }
}

/// Linear type-state witness that the caller crossed the unsafe native
/// execution-loss boundary. It is not authenticated evidence, carries only
/// data, and is consumed by the single restoration attempt.
pub struct VirtualBlockLostExecution {
    image: VirtualBlockRestartImage,
}

impl Drop for VirtualBlockRestartImage {
    fn drop(&mut self) {
        for byte in self
            .request_slots
            .iter_mut()
            .flatten()
            .chain(self.completion_slots.iter_mut().flatten())
            .chain(self.encoded_resume_page.iter_mut())
        {
            // SAFETY: `byte` is a unique reference into image-owned storage.
            // Volatile erasure prevents ordinary dead-store removal.
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
    }
}

impl VirtualBlockResumePage {
    pub fn fresh(
        base: u64,
        configuration_page: VirtualBlockConfigurationPage,
    ) -> Result<Self, VirtualBlockError> {
        Self::new(
            base,
            configuration_page,
            VirtualBlockResumeState {
                configuration: configuration_page.configuration(),
                request_producer: 0,
                request_consumed: 0,
                completion_published: 0,
                completion_consumer: 0,
                last_admitted_request_id: 0,
                last_published_request_id: 0,
            },
        )
    }

    pub fn new(
        base: u64,
        configuration_page: VirtualBlockConfigurationPage,
        state: VirtualBlockResumeState,
    ) -> Result<Self, VirtualBlockError> {
        let end = base
            .checked_add(PAGE_SIZE)
            .ok_or(VirtualBlockError::InvalidConfiguration)?;
        let configuration_end = configuration_page
            .base()
            .checked_add(PAGE_SIZE)
            .ok_or(VirtualBlockError::InvalidConfiguration)?;
        let queue = state.configuration().queue();
        let queue_bytes = queue
            .pages_per_queue()
            .checked_mul(PAGE_SIZE)
            .ok_or(VirtualBlockError::InvalidConfiguration)?;
        let request_end = queue
            .request_base()
            .checked_add(queue_bytes)
            .ok_or(VirtualBlockError::InvalidConfiguration)?;
        let completion_end = queue
            .completion_base()
            .checked_add(queue_bytes)
            .ok_or(VirtualBlockError::InvalidConfiguration)?;
        if base == 0
            || !base.is_multiple_of(PAGE_SIZE)
            || state.configuration() != configuration_page.configuration()
            || ranges_overlap(base, end, configuration_page.base(), configuration_end)
            || ranges_overlap(base, end, queue.request_base(), request_end)
            || ranges_overlap(base, end, queue.completion_base(), completion_end)
        {
            return Err(VirtualBlockError::InvalidConfiguration);
        }
        Ok(Self {
            base,
            configuration_base: configuration_page.base(),
            state,
        })
    }

    pub const fn base(self) -> u64 {
        self.base
    }

    pub const fn state(self) -> VirtualBlockResumeState {
        self.state
    }

    pub const fn configuration_base(self) -> u64 {
        self.configuration_base
    }

    pub fn encode_page(self, output: &mut [u8; PAGE_SIZE as usize]) {
        output.fill(0);
        self.state.encode(
            (&mut output[..VIRTUAL_BLOCK_RESUME_STATE_BYTES])
                .try_into()
                .unwrap(),
        );
    }

    /// Decodes only a complete canonical page. Hidden tail data is rejected so
    /// a guest cannot reconstruct from bytes that differ from the published
    /// device image.
    pub fn decode_page(input: &[u8]) -> Result<VirtualBlockResumeState, VirtualBlockError> {
        if input.len() != PAGE_SIZE as usize
            || input[VIRTUAL_BLOCK_RESUME_STATE_BYTES..]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(VirtualBlockError::InvalidConfiguration);
        }
        VirtualBlockResumeState::decode(&input[..VIRTUAL_BLOCK_RESUME_STATE_BYTES])
    }
}

impl VirtualBlockResumeState {
    pub const fn configuration(self) -> VirtualBlockConfiguration {
        self.configuration
    }

    pub const fn request_producer(self) -> u64 {
        self.request_producer
    }

    pub const fn request_consumed(self) -> u64 {
        self.request_consumed
    }

    pub const fn completion_published(self) -> u64 {
        self.completion_published
    }

    pub const fn completion_consumer(self) -> u64 {
        self.completion_consumer
    }

    pub const fn last_admitted_request_id(self) -> u64 {
        self.last_admitted_request_id
    }

    pub const fn last_published_request_id(self) -> u64 {
        self.last_published_request_id
    }

    pub fn encode(self, output: &mut [u8; VIRTUAL_BLOCK_RESUME_STATE_BYTES]) {
        output.fill(0);
        self.configuration.encode(
            (&mut output[..VIRTUAL_BLOCK_CONFIGURATION_BYTES])
                .try_into()
                .unwrap(),
        );
        output[128..132].copy_from_slice(&RESUME_STATE_MAGIC);
        output[132] = VERSION;
        output[136..144].copy_from_slice(&self.request_producer.to_le_bytes());
        output[144..152].copy_from_slice(&self.request_consumed.to_le_bytes());
        output[152..160].copy_from_slice(&self.completion_published.to_le_bytes());
        output[160..168].copy_from_slice(&self.completion_consumer.to_le_bytes());
        output[168..176].copy_from_slice(&self.last_admitted_request_id.to_le_bytes());
        output[176..184].copy_from_slice(&self.last_published_request_id.to_le_bytes());
    }

    pub fn decode(input: &[u8]) -> Result<Self, VirtualBlockError> {
        if input.len() != VIRTUAL_BLOCK_RESUME_STATE_BYTES
            || input[128..132] != RESUME_STATE_MAGIC
            || input[132] != VERSION
            || input[133..136].iter().any(|byte| *byte != 0)
            || input[184..].iter().any(|byte| *byte != 0)
        {
            return Err(VirtualBlockError::InvalidConfiguration);
        }
        let configuration =
            VirtualBlockConfiguration::decode(&input[..VIRTUAL_BLOCK_CONFIGURATION_BYTES])?;
        let state = Self {
            configuration,
            request_producer: u64::from_le_bytes(input[136..144].try_into().unwrap()),
            request_consumed: u64::from_le_bytes(input[144..152].try_into().unwrap()),
            completion_published: u64::from_le_bytes(input[152..160].try_into().unwrap()),
            completion_consumer: u64::from_le_bytes(input[160..168].try_into().unwrap()),
            last_admitted_request_id: u64::from_le_bytes(input[168..176].try_into().unwrap()),
            last_published_request_id: u64::from_le_bytes(input[176..184].try_into().unwrap()),
        };
        state.validate()?;
        Ok(state)
    }

    fn validate(self) -> Result<(), VirtualBlockError> {
        let capacity = u64::from(self.configuration.queue().slots());
        if self.completion_consumer > self.completion_published
            || self.completion_published != self.request_consumed
            || self.request_consumed > self.request_producer
            || self.request_producer - self.completion_consumer > capacity
            || self.request_producer - self.request_consumed > capacity
            || (self.request_consumed == 0) != (self.last_admitted_request_id == 0)
            || (self.request_producer == 0) != (self.last_published_request_id == 0)
            || self.last_admitted_request_id > self.last_published_request_id
        {
            return Err(VirtualBlockError::InvalidQueue);
        }
        Ok(())
    }
}

/// A prepared single-request publication. Encoding the request and publishing
/// the returned producer counter must complete before this ticket is committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualBlockGuestSubmission {
    request: VirtualBlockRequest,
    producer: u64,
    slot: u16,
    expected_transferred: u32,
}

impl VirtualBlockGuestSubmission {
    pub const fn request(self) -> VirtualBlockRequest {
        self.request
    }

    pub const fn producer(self) -> u64 {
        self.producer
    }

    pub const fn slot(self) -> u16 {
        self.slot
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualBlockGuestCompletion {
    status: VirtualBlockCompletionStatus,
    transferred: u32,
    acknowledgement: u64,
}

/// A non-mutating proof that one exact completion may be acknowledged. The
/// protected acknowledgement must be published before this ticket is committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualBlockGuestCompletionTicket {
    completion: VirtualBlockCompletion,
    completion_published: u64,
    acknowledgement: u64,
    pending: VirtualBlockGuestSubmission,
    slot: u16,
}

impl VirtualBlockGuestCompletionTicket {
    pub const fn status(self) -> VirtualBlockCompletionStatus {
        self.completion.status()
    }

    pub const fn transferred(self) -> u32 {
        self.completion.transferred()
    }

    pub const fn acknowledgement(self) -> u64 {
        self.acknowledgement
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualBlockGuestTerminalReason {
    Reset,
    Removed,
    SequenceExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualBlockGuestQueueTransportError<E> {
    Protocol(VirtualBlockError),
    Transport(E),
}

/// Non-authorizing notification route derived from one canonical block
/// transport. The concrete guest adapter must already hold the separately
/// established scalar-I/O privilege or live PCI BAR mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualBlockGuestNotification {
    ScalarIo { port: u16, value: u32 },
    PciMmio { offset: u32, value: u32 },
}

/// Exact guest-side memory and notification operations for the MRML-specific
/// block queues.
///
/// # Safety
///
/// Implementations must access exactly the supplied addresses and lengths and
/// use exactly the supplied notification route and value.
/// `publish_request_and_notify`
/// must make the complete slot visible before release-publishing the producer,
/// notify only after that publication, and leave the producer unchanged without
/// notifying on error.
/// `read_completion` must acquire the published counter before copying the
/// corresponding complete slot. `acknowledge_completion` must use the protected
/// acknowledgement transport to release-publish the exact consumer at the
/// supplied address and leave it unchanged on error. No operation may redirect
/// or shorten a copy, substitute a transport tuple, or report an error after a
/// producer or consumer publication might have become visible.
pub unsafe trait VirtualBlockGuestQueueTransport {
    type Error;

    fn publish_request_and_notify(
        &mut self,
        request_address: u64,
        request: &[u8; VIRTUAL_BLOCK_REQUEST_BYTES],
        producer_address: u64,
        producer: u64,
        notification: VirtualBlockGuestNotification,
    ) -> Result<(), Self::Error>;

    fn read_completion(
        &mut self,
        published_address: u64,
        completion_address: u64,
        published: &mut u64,
        completion: &mut [u8; VIRTUAL_BLOCK_COMPLETION_BYTES],
    ) -> Result<(), Self::Error>;

    fn acknowledge_completion(
        &mut self,
        consumer_address: u64,
        consumer: u64,
        notification: VirtualBlockGuestNotification,
    ) -> Result<(), Self::Error>;
}

impl VirtualBlockGuestCompletion {
    pub const fn status(self) -> VirtualBlockCompletionStatus {
        self.status
    }

    pub const fn transferred(self) -> u32 {
        self.transferred
    }

    pub const fn acknowledgement(self) -> u64 {
        self.acknowledgement
    }
}

/// Allocation-free initial guest-driver state discovered from canonical device
/// data and an idle queue snapshot. The state carries no backend authority and
/// supports one exact configured-capacity window so ownership and replay are
/// explicit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VirtualBlockGuestDriver {
    configuration: VirtualBlockConfiguration,
    next_request_id: u64,
    request_ids_exhausted: bool,
    request_producer: u64,
    completion_consumer: u64,
    pending: [Option<VirtualBlockGuestSubmission>; MAX_VIRTUAL_BLOCK_QUEUE_SLOTS],
    pending_count: u16,
    terminal: Option<VirtualBlockGuestTerminalReason>,
}

impl VirtualBlockGuestDriver {
    pub fn discover(
        encoded_configuration: &[u8],
        request_producer: u64,
        request_consumed: u64,
        completion_published: u64,
        completion_consumer: u64,
    ) -> Result<Self, VirtualBlockError> {
        let configuration = Self::decode_fresh(
            encoded_configuration,
            request_producer,
            request_consumed,
            completion_published,
            completion_consumer,
        )?;
        Ok(Self {
            configuration,
            next_request_id: 1,
            request_ids_exhausted: false,
            request_producer,
            completion_consumer,
            pending: [None; MAX_VIRTUAL_BLOCK_QUEUE_SLOTS],
            pending_count: 0,
            terminal: None,
        })
    }

    /// Reconstructs bounded pending ownership from a canonical quiesced device
    /// snapshot and the exact physical request slots. The snapshot is data, not
    /// authority; its provider must separately ensure it still matches the live
    /// capability-bound device and bridge before allowing I/O to resume.
    pub fn reconstruct(
        encoded_state: &[u8],
        encoded_requests: &[[u8; VIRTUAL_BLOCK_REQUEST_BYTES]],
    ) -> Result<Self, VirtualBlockError> {
        let state = VirtualBlockResumeState::decode(encoded_state)?;
        let configuration = state.configuration();
        let slots = usize::from(configuration.queue().slots());
        if encoded_requests.len() != slots {
            return Err(VirtualBlockError::InvalidQueue);
        }

        let mut pending = [None; MAX_VIRTUAL_BLOCK_QUEUE_SLOTS];
        let pending_count = u16::try_from(state.request_producer() - state.completion_consumer())
            .map_err(|_| VirtualBlockError::InvalidQueue)?;
        let mut last_request_id = if state.request_consumed() == state.completion_consumer() {
            state.last_admitted_request_id()
        } else {
            0
        };
        if pending_count != 0 {
            let first = state
                .completion_consumer()
                .checked_add(1)
                .ok_or(VirtualBlockError::SequenceExhausted)?;
            for position in first..=state.request_producer() {
                let slot = ((position - 1) % slots as u64) as usize;
                let request = VirtualBlockRequest::decode(&encoded_requests[slot])?;
                let expected_transferred =
                    Self::validate_reconstructed_request(configuration, request)?;
                if request.request_id() <= last_request_id {
                    return Err(VirtualBlockError::Replay);
                }
                if position == state.request_consumed()
                    && request.request_id() != state.last_admitted_request_id()
                {
                    return Err(VirtualBlockError::InvalidQueue);
                }
                last_request_id = request.request_id();
                pending[slot] = Some(VirtualBlockGuestSubmission {
                    request,
                    producer: position,
                    slot: slot as u16,
                    expected_transferred,
                });
            }
        }
        if state.request_producer() == state.completion_consumer() && state.request_producer() != 0
        {
            let slot = ((state.request_producer() - 1) % slots as u64) as usize;
            let latest = VirtualBlockRequest::decode(&encoded_requests[slot])?;
            Self::validate_reconstructed_request(configuration, latest)?;
            last_request_id = latest.request_id();
        }
        if last_request_id != state.last_published_request_id() {
            return Err(VirtualBlockError::InvalidQueue);
        }
        let (next_request_id, request_ids_exhausted) = match last_request_id.checked_add(1) {
            Some(next) => (next, false),
            None => (u64::MAX, true),
        };
        let terminal = if request_ids_exhausted && pending_count == 0 {
            Some(VirtualBlockGuestTerminalReason::SequenceExhausted)
        } else {
            None
        };
        Ok(Self {
            configuration,
            next_request_id,
            request_ids_exhausted,
            request_producer: state.request_producer(),
            completion_consumer: state.completion_consumer(),
            pending,
            pending_count,
            terminal,
        })
    }

    /// Reconstructs from the complete zero-padded page presented by the device.
    /// The caller must still establish a stopped execution boundary and bind
    /// the page and request snapshot to the live capability-authorized device.
    pub fn reconstruct_from_page(
        encoded_page: &[u8],
        encoded_requests: &[[u8; VIRTUAL_BLOCK_REQUEST_BYTES]],
    ) -> Result<Self, VirtualBlockError> {
        let state = VirtualBlockResumePage::decode_page(encoded_page)?;
        let mut encoded_state = [0; VIRTUAL_BLOCK_RESUME_STATE_BYTES];
        state.encode(&mut encoded_state);
        Self::reconstruct(&encoded_state, encoded_requests)
    }

    /// Selects fresh discovery or nonzero reconstruction only after binding a
    /// complete canonical resume page to the separately presented
    /// configuration and all four live queue counters. The page remains data;
    /// callers must independently hold device and mapping authority.
    #[allow(clippy::too_many_arguments)]
    pub fn resume_from_page(
        encoded_configuration: &[u8],
        encoded_page: &[u8],
        encoded_requests: &[[u8; VIRTUAL_BLOCK_REQUEST_BYTES]],
        request_producer: u64,
        request_consumed: u64,
        completion_published: u64,
        completion_consumer: u64,
    ) -> Result<Self, VirtualBlockError> {
        let configuration = VirtualBlockConfiguration::decode(encoded_configuration)?;
        let state = VirtualBlockResumePage::decode_page(encoded_page)?;
        if encoded_requests.len() != usize::from(configuration.queue().slots())
            || state.configuration() != configuration
            || state.request_producer() != request_producer
            || state.request_consumed() != request_consumed
            || state.completion_published() != completion_published
            || state.completion_consumer() != completion_consumer
        {
            return Err(VirtualBlockError::InvalidQueue);
        }
        if request_producer == 0
            && request_consumed == 0
            && completion_published == 0
            && completion_consumer == 0
        {
            Self::discover(
                encoded_configuration,
                request_producer,
                request_consumed,
                completion_published,
                completion_consumer,
            )
        } else {
            Self::reconstruct_from_page(encoded_page, encoded_requests)
        }
    }

    /// Reinitializes state only after an exact reset completion and only from
    /// the canonical successor generation with completely fresh queue state.
    /// Removal and sequence exhaustion are permanently terminal.
    pub fn rediscover_after_reset(
        &mut self,
        encoded_configuration: &[u8],
        request_producer: u64,
        request_consumed: u64,
        completion_published: u64,
        completion_consumer: u64,
    ) -> Result<(), VirtualBlockError> {
        if self.terminal != Some(VirtualBlockGuestTerminalReason::Reset) {
            return Err(VirtualBlockError::InvalidState);
        }
        let expected_generation = self
            .configuration
            .generation()
            .checked_add(1)
            .ok_or(VirtualBlockError::SequenceExhausted)?;
        let configuration = Self::decode_fresh(
            encoded_configuration,
            request_producer,
            request_consumed,
            completion_published,
            completion_consumer,
        )?;
        if configuration.generation() != expected_generation {
            return Err(VirtualBlockError::StaleGeneration);
        }
        *self = Self {
            configuration,
            next_request_id: 1,
            request_ids_exhausted: false,
            request_producer: 0,
            completion_consumer: 0,
            pending: [None; MAX_VIRTUAL_BLOCK_QUEUE_SLOTS],
            pending_count: 0,
            terminal: None,
        };
        Ok(())
    }

    pub const fn configuration(&self) -> VirtualBlockConfiguration {
        self.configuration
    }

    pub const fn request_producer(&self) -> u64 {
        self.request_producer
    }

    pub const fn completion_consumer(&self) -> u64 {
        self.completion_consumer
    }

    pub const fn has_pending(&self) -> bool {
        self.pending_count != 0
    }

    pub const fn pending_count(&self) -> u16 {
        self.pending_count
    }

    pub const fn is_terminal(&self) -> bool {
        self.terminal.is_some()
    }

    pub const fn terminal_reason(&self) -> Option<VirtualBlockGuestTerminalReason> {
        self.terminal
    }

    pub fn prepare_read(
        &self,
        block: u64,
        block_count: u32,
        buffer_address: u64,
        buffer_length: u32,
    ) -> Result<VirtualBlockGuestSubmission, VirtualBlockError> {
        self.prepare_data(
            VirtualBlockOperation::Read,
            block,
            block_count,
            buffer_address,
            buffer_length,
        )
    }

    pub fn prepare_write(
        &self,
        block: u64,
        block_count: u32,
        buffer_address: u64,
        buffer_length: u32,
    ) -> Result<VirtualBlockGuestSubmission, VirtualBlockError> {
        self.prepare_data(
            VirtualBlockOperation::Write,
            block,
            block_count,
            buffer_address,
            buffer_length,
        )
    }

    pub fn prepare_flush(&self) -> Result<VirtualBlockGuestSubmission, VirtualBlockError> {
        self.prepare_ready()?;
        if self.configuration.negotiated_features() & VIRTUAL_BLOCK_FEATURE_FLUSH == 0 {
            return Err(VirtualBlockError::InvalidFeatures);
        }
        self.submission(
            VirtualBlockRequest::flush(self.configuration.generation(), self.next_request_id),
            0,
        )
    }

    pub fn commit_submission(
        &mut self,
        submission: VirtualBlockGuestSubmission,
    ) -> Result<(), VirtualBlockError> {
        let (slot, pending_count) = self.validate_submission(submission)?;
        self.finish_submission(submission, slot, pending_count);
        Ok(())
    }

    pub fn publish_submission<M: VirtualBlockGuestQueueTransport>(
        &mut self,
        transport: &mut M,
        submission: VirtualBlockGuestSubmission,
    ) -> Result<(), VirtualBlockGuestQueueTransportError<M::Error>> {
        let (slot, pending_count) = self
            .validate_submission(submission)
            .map_err(VirtualBlockGuestQueueTransportError::Protocol)?;
        let configuration = self.configuration;
        let request_address = slot_address(
            configuration.queue().request_base(),
            submission.producer,
            usize::from(configuration.queue().slots()),
            VIRTUAL_BLOCK_REQUEST_BYTES,
        )
        .map_err(VirtualBlockGuestQueueTransportError::Protocol)?;
        if slot != usize::from(submission.slot) {
            return Err(VirtualBlockGuestQueueTransportError::Protocol(
                VirtualBlockError::StaleTicket,
            ));
        }
        let mut encoded = [0; VIRTUAL_BLOCK_REQUEST_BYTES];
        submission.request.encode(&mut encoded);
        transport
            .publish_request_and_notify(
                request_address,
                &encoded,
                configuration.queue().request_base(),
                submission.producer,
                configuration.transport().doorbell_notification(),
            )
            .map_err(VirtualBlockGuestQueueTransportError::Transport)?;
        self.finish_submission(submission, slot, pending_count);
        Ok(())
    }

    fn validate_submission(
        &self,
        submission: VirtualBlockGuestSubmission,
    ) -> Result<(usize, u16), VirtualBlockError> {
        self.prepare_ready()?;
        let expected_producer = self
            .request_producer
            .checked_add(1)
            .ok_or(VirtualBlockError::SequenceExhausted)?;
        if submission.request.generation() != self.configuration.generation()
            || submission.request.request_id() != self.next_request_id
            || submission.producer != expected_producer
            || submission.slot
                != (self.request_producer % u64::from(self.configuration.queue().slots())) as u16
        {
            return Err(VirtualBlockError::StaleTicket);
        }
        let slot = usize::from(submission.slot);
        if self.pending[slot].is_some() {
            return Err(VirtualBlockError::InvalidState);
        }
        let pending_count = self
            .pending_count
            .checked_add(1)
            .ok_or(VirtualBlockError::SequenceExhausted)?;
        Ok((slot, pending_count))
    }

    fn finish_submission(
        &mut self,
        submission: VirtualBlockGuestSubmission,
        slot: usize,
        pending_count: u16,
    ) {
        self.request_producer = submission.producer;
        self.pending[slot] = Some(submission);
        self.pending_count = pending_count;
        match self.next_request_id.checked_add(1) {
            Some(next) => self.next_request_id = next,
            None => self.request_ids_exhausted = true,
        }
    }

    pub fn accept_completion(
        &mut self,
        published: u64,
        encoded_completion: &[u8],
    ) -> Result<VirtualBlockGuestCompletion, VirtualBlockError> {
        let ticket = self.prepare_completion(published, encoded_completion)?;
        self.commit_completion(ticket)
    }

    pub fn prepare_completion(
        &self,
        published: u64,
        encoded_completion: &[u8],
    ) -> Result<VirtualBlockGuestCompletionTicket, VirtualBlockError> {
        let completion = VirtualBlockCompletion::decode(encoded_completion)?;
        let (slot, pending) = self.validate_completion(published, completion)?;
        let acknowledgement = self
            .completion_consumer
            .checked_add(1)
            .ok_or(VirtualBlockError::SequenceExhausted)?;
        Ok(VirtualBlockGuestCompletionTicket {
            completion,
            completion_published: published,
            acknowledgement,
            pending,
            slot: slot as u16,
        })
    }

    pub fn prepare_completion_from_transport<M: VirtualBlockGuestQueueTransport>(
        &self,
        transport: &mut M,
    ) -> Result<VirtualBlockGuestCompletionTicket, VirtualBlockGuestQueueTransportError<M::Error>>
    {
        let position = self.completion_consumer.checked_add(1).ok_or(
            VirtualBlockGuestQueueTransportError::Protocol(VirtualBlockError::SequenceExhausted),
        )?;
        let configuration = self.configuration;
        let completion_address = slot_address(
            configuration.queue().completion_base(),
            position,
            usize::from(configuration.queue().slots()),
            VIRTUAL_BLOCK_COMPLETION_BYTES,
        )
        .map_err(VirtualBlockGuestQueueTransportError::Protocol)?;
        let mut published = 0;
        let mut encoded = [0; VIRTUAL_BLOCK_COMPLETION_BYTES];
        transport
            .read_completion(
                configuration.queue().completion_base(),
                completion_address,
                &mut published,
                &mut encoded,
            )
            .map_err(VirtualBlockGuestQueueTransportError::Transport)?;
        self.prepare_completion(published, &encoded)
            .map_err(VirtualBlockGuestQueueTransportError::Protocol)
    }

    pub fn commit_completion(
        &mut self,
        ticket: VirtualBlockGuestCompletionTicket,
    ) -> Result<VirtualBlockGuestCompletion, VirtualBlockError> {
        let (slot, pending) = self
            .validate_completion(ticket.completion_published, ticket.completion)
            .map_err(|_| VirtualBlockError::StaleTicket)?;
        let acknowledgement = self
            .completion_consumer
            .checked_add(1)
            .ok_or(VirtualBlockError::SequenceExhausted)?;
        if slot != usize::from(ticket.slot)
            || pending != ticket.pending
            || ticket.acknowledgement != acknowledgement
        {
            return Err(VirtualBlockError::StaleTicket);
        }
        let pending_count = self
            .pending_count
            .checked_sub(1)
            .ok_or(VirtualBlockError::InvalidState)?;
        Ok(self.finish_completion(slot, pending_count, acknowledgement, ticket.completion))
    }

    pub fn acknowledge_completion_with_transport<M: VirtualBlockGuestQueueTransport>(
        &mut self,
        transport: &mut M,
        ticket: VirtualBlockGuestCompletionTicket,
    ) -> Result<VirtualBlockGuestCompletion, VirtualBlockGuestQueueTransportError<M::Error>> {
        let (slot, pending) = self
            .validate_completion(ticket.completion_published, ticket.completion)
            .map_err(|_| {
                VirtualBlockGuestQueueTransportError::Protocol(VirtualBlockError::StaleTicket)
            })?;
        let acknowledgement = self.completion_consumer.checked_add(1).ok_or(
            VirtualBlockGuestQueueTransportError::Protocol(VirtualBlockError::SequenceExhausted),
        )?;
        if slot != usize::from(ticket.slot)
            || pending != ticket.pending
            || ticket.acknowledgement != acknowledgement
        {
            return Err(VirtualBlockGuestQueueTransportError::Protocol(
                VirtualBlockError::StaleTicket,
            ));
        }
        let pending_count = self.pending_count.checked_sub(1).ok_or(
            VirtualBlockGuestQueueTransportError::Protocol(VirtualBlockError::InvalidState),
        )?;
        let consumer_address = self
            .configuration
            .queue()
            .completion_base()
            .checked_add(64)
            .ok_or(VirtualBlockGuestQueueTransportError::Protocol(
                VirtualBlockError::RangeOverflow,
            ))?;
        transport
            .acknowledge_completion(
                consumer_address,
                acknowledgement,
                self.configuration
                    .transport()
                    .completion_acknowledgement_notification(),
            )
            .map_err(VirtualBlockGuestQueueTransportError::Transport)?;
        Ok(self.finish_completion(slot, pending_count, acknowledgement, ticket.completion))
    }

    fn validate_completion(
        &self,
        published: u64,
        completion: VirtualBlockCompletion,
    ) -> Result<(usize, VirtualBlockGuestSubmission), VirtualBlockError> {
        let expected_published = self
            .completion_consumer
            .checked_add(1)
            .ok_or(VirtualBlockError::SequenceExhausted)?;
        let slot =
            (self.completion_consumer % u64::from(self.configuration.queue().slots())) as usize;
        let pending = self.pending[slot].ok_or(VirtualBlockError::InvalidState)?;
        if published < expected_published
            || published > self.request_producer
            || completion.generation() != self.configuration.generation()
            || completion.request_id() != pending.request.request_id()
            || (completion.status() == VirtualBlockCompletionStatus::Ok
                && completion.transferred() != pending.expected_transferred)
        {
            return Err(VirtualBlockError::InvalidCompletion);
        }
        Ok((slot, pending))
    }

    fn finish_completion(
        &mut self,
        slot: usize,
        pending_count: u16,
        published: u64,
        completion: VirtualBlockCompletion,
    ) -> VirtualBlockGuestCompletion {
        self.completion_consumer = published;
        self.pending[slot] = None;
        self.pending_count = pending_count;
        self.terminal = if self.request_ids_exhausted
            && (self.pending_count == 0
                || matches!(
                    completion.status(),
                    VirtualBlockCompletionStatus::Reset | VirtualBlockCompletionStatus::Removed
                )) {
            Some(VirtualBlockGuestTerminalReason::SequenceExhausted)
        } else {
            match completion.status() {
                VirtualBlockCompletionStatus::Reset => Some(VirtualBlockGuestTerminalReason::Reset),
                VirtualBlockCompletionStatus::Removed => {
                    Some(VirtualBlockGuestTerminalReason::Removed)
                }
                _ => None,
            }
        };
        if self.terminal.is_some() {
            self.pending.fill(None);
            self.pending_count = 0;
        }
        VirtualBlockGuestCompletion {
            status: completion.status(),
            transferred: completion.transferred(),
            acknowledgement: published,
        }
    }

    fn prepare_ready(&self) -> Result<(), VirtualBlockError> {
        if self.terminal.is_some() {
            return Err(VirtualBlockError::InvalidState);
        }
        if self.request_ids_exhausted {
            return Err(VirtualBlockError::SequenceExhausted);
        }
        if self.completion_consumer > self.request_producer {
            return Err(VirtualBlockError::InvalidState);
        }
        if self.request_producer - self.completion_consumer
            >= u64::from(self.configuration.queue().slots())
        {
            return Err(VirtualBlockError::QueueFull);
        }
        Ok(())
    }

    fn prepare_data(
        &self,
        operation: VirtualBlockOperation,
        block: u64,
        block_count: u32,
        buffer_address: u64,
        buffer_length: u32,
    ) -> Result<VirtualBlockGuestSubmission, VirtualBlockError> {
        self.prepare_ready()?;
        if block_count == 0 || buffer_address == 0 {
            return Err(VirtualBlockError::InvalidBuffer);
        }
        let block_end = block
            .checked_add(u64::from(block_count))
            .ok_or(VirtualBlockError::InvalidRange)?;
        if block_end > self.configuration.block_count() {
            return Err(VirtualBlockError::InvalidRange);
        }
        let expected = self
            .configuration
            .block_size()
            .checked_mul(block_count)
            .ok_or(VirtualBlockError::InvalidBuffer)?;
        if expected != buffer_length || expected > MAX_VIRTUAL_BLOCK_TRANSFER_BYTES {
            return Err(VirtualBlockError::InvalidBuffer);
        }
        buffer_address
            .checked_add(u64::from(buffer_length))
            .ok_or(VirtualBlockError::InvalidBuffer)?;
        let request = match operation {
            VirtualBlockOperation::Read => VirtualBlockRequest::read,
            VirtualBlockOperation::Write => VirtualBlockRequest::write,
            VirtualBlockOperation::Flush => return Err(VirtualBlockError::InvalidState),
        }(
            self.configuration.generation(),
            self.next_request_id,
            block,
            block_count,
            buffer_address,
            buffer_length,
        );
        self.submission(request, expected)
    }

    fn validate_reconstructed_request(
        configuration: VirtualBlockConfiguration,
        request: VirtualBlockRequest,
    ) -> Result<u32, VirtualBlockError> {
        if request.generation() != configuration.generation() {
            return Err(VirtualBlockError::StaleGeneration);
        }
        match request.operation() {
            VirtualBlockOperation::Flush => {
                if configuration.negotiated_features() & VIRTUAL_BLOCK_FEATURE_FLUSH == 0 {
                    return Err(VirtualBlockError::InvalidFeatures);
                }
                if request.block() != 0
                    || request.block_count() != 0
                    || request.buffer_address() != 0
                    || request.buffer_length() != 0
                {
                    return Err(VirtualBlockError::MalformedRequest);
                }
                Ok(0)
            }
            VirtualBlockOperation::Read | VirtualBlockOperation::Write => {
                if request.block_count() == 0 || request.buffer_address() == 0 {
                    return Err(VirtualBlockError::InvalidBuffer);
                }
                let block_end = request
                    .block()
                    .checked_add(u64::from(request.block_count()))
                    .ok_or(VirtualBlockError::InvalidRange)?;
                if block_end > configuration.block_count() {
                    return Err(VirtualBlockError::InvalidRange);
                }
                let expected = configuration
                    .block_size()
                    .checked_mul(request.block_count())
                    .ok_or(VirtualBlockError::InvalidBuffer)?;
                if expected != request.buffer_length()
                    || expected > MAX_VIRTUAL_BLOCK_TRANSFER_BYTES
                {
                    return Err(VirtualBlockError::InvalidBuffer);
                }
                request
                    .buffer_address()
                    .checked_add(u64::from(request.buffer_length()))
                    .ok_or(VirtualBlockError::InvalidBuffer)?;
                Ok(expected)
            }
        }
    }

    fn submission(
        &self,
        request: VirtualBlockRequest,
        expected_transferred: u32,
    ) -> Result<VirtualBlockGuestSubmission, VirtualBlockError> {
        let producer = self
            .request_producer
            .checked_add(1)
            .ok_or(VirtualBlockError::SequenceExhausted)?;
        Ok(VirtualBlockGuestSubmission {
            request,
            producer,
            slot: (self.request_producer % u64::from(self.configuration.queue().slots())) as u16,
            expected_transferred,
        })
    }

    fn decode_fresh(
        encoded_configuration: &[u8],
        request_producer: u64,
        request_consumed: u64,
        completion_published: u64,
        completion_consumer: u64,
    ) -> Result<VirtualBlockConfiguration, VirtualBlockError> {
        let configuration = VirtualBlockConfiguration::decode(encoded_configuration)?;
        if request_producer != 0
            || request_consumed != 0
            || completion_published != 0
            || completion_consumer != 0
        {
            return Err(VirtualBlockError::InvalidQueue);
        }
        Ok(configuration)
    }
}

fn queue_bytes(slots: usize, slot_bytes: usize) -> Result<u64, VirtualBlockError> {
    (slots as u64)
        .checked_mul(slot_bytes as u64)
        .and_then(|bytes| bytes.checked_add(QUEUE_HEADER_BYTES))
        .ok_or(VirtualBlockError::RangeOverflow)
}

const fn ranges_overlap(
    first_start: u64,
    first_end: u64,
    second_start: u64,
    second_end: u64,
) -> bool {
    first_start < second_end && second_start < first_end
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
    transport: VirtualBlockTransport,
    negotiated_features: u64,
    generation: u32,
    state: VirtualBlockDeviceState,
    queue: Option<VirtualBlockQueueLayout>,
    interrupt_vector: Option<u8>,
    completion_interrupt_pending: bool,
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
        Self::new_with_transport(
            block_size,
            block_count,
            supported_features,
            VirtualBlockTransport::MrmlSpecificScalarIo,
        )
    }

    pub fn new_with_transport(
        block_size: u32,
        block_count: u64,
        supported_features: u64,
        transport: VirtualBlockTransport,
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
            transport,
            negotiated_features: 0,
            generation: 1,
            state: VirtualBlockDeviceState::Created,
            queue: None,
            interrupt_vector: None,
            completion_interrupt_pending: false,
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

    pub const fn supported_features(&self) -> u64 {
        self.supported_features
    }

    pub const fn transport(&self) -> VirtualBlockTransport {
        self.transport
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

    pub fn configuration(&self) -> Result<VirtualBlockConfiguration, VirtualBlockError> {
        self.configuration_in(VirtualBlockDeviceState::Active)
    }

    /// Returns the exact mechanics of a successfully quiesced device. This
    /// record is data rather than authority; callers must retain the separate
    /// lifecycle authority needed to resume the device.
    pub fn suspended_configuration(&self) -> Result<VirtualBlockConfiguration, VirtualBlockError> {
        self.configuration_in(VirtualBlockDeviceState::Suspended)
    }

    fn configuration_in(
        &self,
        expected_state: VirtualBlockDeviceState,
    ) -> Result<VirtualBlockConfiguration, VirtualBlockError> {
        if self.state != expected_state {
            return Err(VirtualBlockError::InvalidState);
        }
        Ok(VirtualBlockConfiguration {
            generation: self.generation,
            block_size: self.block_size,
            block_count: self.block_count,
            supported_features: self.supported_features,
            negotiated_features: self.negotiated_features,
            queue: self.queue.ok_or(VirtualBlockError::InvalidState)?,
            interrupt_vector: self
                .interrupt_vector
                .ok_or(VirtualBlockError::InvalidState)?,
            transport: self.transport,
        })
    }

    pub fn validate_configuration(
        &self,
        configuration: VirtualBlockConfiguration,
    ) -> Result<(), VirtualBlockError> {
        if configuration.generation() != self.generation {
            return Err(VirtualBlockError::StaleGeneration);
        }
        if configuration != self.configuration()? {
            return Err(VirtualBlockError::InvalidConfiguration);
        }
        Ok(())
    }

    /// Returns the configured vector only while a published completion still
    /// requires notification. Reading this latch carries no injection
    /// authority; the VMM must separately authorize delivery.
    pub const fn pending_interrupt_vector(&self) -> Option<u8> {
        if self.completion_interrupt_pending {
            self.interrupt_vector
        } else {
            None
        }
    }

    /// Clears one coalesced completion notification only after the exact
    /// configured vector has been delivered successfully.
    pub fn acknowledge_interrupt(&mut self, vector: u8) -> Result<(), VirtualBlockError> {
        if self.state != VirtualBlockDeviceState::Active
            || !self.completion_interrupt_pending
            || self.interrupt_vector != Some(vector)
        {
            return Err(VirtualBlockError::InvalidInterrupt);
        }
        self.completion_interrupt_pending = false;
        Ok(())
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
        if self.state != VirtualBlockDeviceState::Active
            || self.slots.iter().any(Option::is_some)
            || self.completion_interrupt_pending
        {
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
            self.completion_interrupt_pending = false;
            self.state = VirtualBlockDeviceState::Failed;
            return Err(error);
        }
        let invalidated = self.invalidate_inflight();
        self.completion_interrupt_pending = false;
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
        self.completion_interrupt_pending = false;
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
        self.completion_interrupt_pending = false;
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

    pub(crate) fn latch_completion_interrupt(&mut self) -> Result<(), VirtualBlockError> {
        if self.state != VirtualBlockDeviceState::Active || self.interrupt_vector.is_none() {
            return Err(VirtualBlockError::InvalidInterrupt);
        }
        self.completion_interrupt_pending = true;
        Ok(())
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
pub enum VirtualBlockCapabilityError<E> {
    Capability(CapabilityError),
    ObjectMismatch,
    InvalidRange,
    Backend(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualBlockAuthorityError {
    InvalidRange,
    GeometryMismatch,
}

/// Trusted-policy selection of one exact block object and one exposed region.
/// This descriptor is data, not authority: every operation still requires the
/// live capability. Guest block zero maps to `backend_first_block`; guest
/// requests cannot address outside `exposed_block_count`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualBlockBackendAuthority {
    capability: Capability,
    object: ObjectId,
    backend_first_block: u64,
    exposed_block_count: u64,
}

impl VirtualBlockBackendAuthority {
    pub fn new(
        capability: Capability,
        object: ObjectId,
        backend_first_block: u64,
        exposed_block_count: u64,
    ) -> Result<Self, VirtualBlockAuthorityError> {
        if exposed_block_count == 0
            || backend_first_block
                .checked_add(exposed_block_count)
                .is_none()
        {
            return Err(VirtualBlockAuthorityError::InvalidRange);
        }
        Ok(Self {
            capability,
            object,
            backend_first_block,
            exposed_block_count,
        })
    }

    pub const fn capability(self) -> Capability {
        self.capability
    }

    pub const fn object(self) -> ObjectId {
        self.object
    }

    pub const fn backend_first_block(self) -> u64 {
        self.backend_first_block
    }

    pub const fn exposed_block_count(self) -> u64 {
        self.exposed_block_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualBlockPciAttachmentState {
    Attached,
    Reset,
    Removed,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualBlockPciError {
    InvalidPciClass,
    InvalidState,
    StalePciGeneration,
    StaleBlockGeneration,
    GeometryMismatch,
}

/// Exact common and native authority that must be retired for one PCI-presented
/// MRML-native block generation. This record identifies cleanup; it grants no
/// cleanup or backend authority by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualBlockPciCleanupRecord {
    pci: VirtualPciAttachedResources,
    block_generation: u32,
    queue: VirtualBlockQueueLayout,
    interrupt_vector: u8,
    backend: VirtualBlockBackendAuthority,
    mapped_window: Option<VirtualPciMmioWindow>,
}

impl VirtualBlockPciCleanupRecord {
    pub const fn pci(self) -> VirtualPciAttachedResources {
        self.pci
    }

    pub const fn block_generation(self) -> u32 {
        self.block_generation
    }

    pub const fn queue(self) -> VirtualBlockQueueLayout {
        self.queue
    }

    pub const fn interrupt_vector(self) -> u8 {
        self.interrupt_vector
    }

    pub const fn backend(self) -> VirtualBlockBackendAuthority {
        self.backend
    }

    pub const fn mapped_window(self) -> Option<VirtualPciMmioWindow> {
        self.mapped_window
    }
}

/// Cleanup boundary below the common block lifecycle.
///
/// # Safety
///
/// Success must make every native mapping, interrupt route, DMA binding,
/// backend-capability descendant, cached decision, queue mapping, and derived
/// handle identified by `record` unusable. Execution must remain stopped across
/// this call and the following common device reset/removal. Partial or uncertain
/// cleanup must return an error and quarantine the VM.
pub unsafe trait VirtualBlockPciResourceRevoker {
    type Error;

    fn revoke_block_resources(
        &mut self,
        record: VirtualBlockPciCleanupRecord,
    ) -> Result<(), Self::Error>;
}

/// Exact relationship between one routed PCI function generation and one
/// active MRML-native block generation. PCI identity and BDF remain data; the
/// separately held block and cleanup capabilities carry authority.
pub struct VirtualBlockPciAttachment {
    pci: VirtualPciAttachedResources,
    block_generation: u32,
    queue: VirtualBlockQueueLayout,
    interrupt_vector: u8,
    backend: VirtualBlockBackendAuthority,
    mapped_window: Option<VirtualPciMmioWindow>,
    state: VirtualBlockPciAttachmentState,
    invalidated_requests: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VirtualBlockPciInterruptState {
    Enabled,
    Masked,
}

impl VirtualBlockPciAttachment {
    pub fn new<const N: usize>(
        pci: VirtualPciAttachedFunction,
        device: &VirtualBlockDevice<N>,
        bridge: &VirtualBlockQueueBridge<N>,
        backend: VirtualBlockBackendAuthority,
    ) -> Result<Self, VirtualBlockPciError> {
        if pci.identity().class() != 1
            || pci.identity().subclass() != 0x80
            || pci.identity().programming_interface() != 0
        {
            return Err(VirtualBlockPciError::InvalidPciClass);
        }
        if pci.resources().mmio_window().is_some()
            || device.state() != VirtualBlockDeviceState::Active
            || bridge.is_poisoned()
        {
            return Err(VirtualBlockPciError::InvalidState);
        }
        let queue = device.queue().ok_or(VirtualBlockPciError::InvalidState)?;
        if queue != bridge.layout() {
            return Err(VirtualBlockPciError::InvalidState);
        }
        let interrupt_vector = device
            .interrupt_vector()
            .ok_or(VirtualBlockPciError::InvalidState)?;
        if backend.exposed_block_count() != device.block_count() {
            return Err(VirtualBlockPciError::GeometryMismatch);
        }
        Ok(Self {
            pci: pci.resources(),
            block_generation: device.generation(),
            queue,
            interrupt_vector,
            backend,
            mapped_window: None,
            state: VirtualBlockPciAttachmentState::Attached,
            invalidated_requests: 0,
        })
    }

    pub const fn state(&self) -> VirtualBlockPciAttachmentState {
        self.state
    }

    pub const fn pci(&self) -> VirtualPciAttachedResources {
        self.pci
    }

    pub const fn block_generation(&self) -> u32 {
        self.block_generation
    }

    pub const fn backend(&self) -> VirtualBlockBackendAuthority {
        self.backend
    }

    pub const fn invalidated_requests(&self) -> usize {
        self.invalidated_requests
    }

    pub const fn mapped_window(&self) -> Option<VirtualPciMmioWindow> {
        self.mapped_window
    }

    /// Revalidates the complete live relationship before an MMIO operation.
    /// The returned window remains routing data; native completion and block
    /// backend authority are still exercised through separate capabilities.
    pub fn validate_mmio_window<const N: usize>(
        &self,
        device: &VirtualBlockDevice<N>,
        bridge: &VirtualBlockQueueBridge<N>,
    ) -> Result<VirtualPciMmioWindow, VirtualBlockPciError> {
        if self.state != VirtualBlockPciAttachmentState::Attached
            || device.transport() != VirtualBlockTransport::MrmlSpecificPciMmio
            || device.state() != VirtualBlockDeviceState::Active
            || device.generation() != self.block_generation
            || device.queue() != Some(self.queue)
            || bridge.layout() != self.queue
            || bridge.is_poisoned()
            || device.interrupt_vector() != Some(self.interrupt_vector)
            || self.backend.exposed_block_count() != device.block_count()
        {
            return Err(VirtualBlockPciError::InvalidState);
        }
        self.mapped_window.ok_or(VirtualBlockPciError::InvalidState)
    }

    /// Revalidates the exact live PCI generation and command state before
    /// legacy completion delivery. PCI state remains routing data; the
    /// separately checked interrupt capability is still the authority.
    fn validate_interrupt_state<const N: usize>(
        &self,
        pci: VirtualPciAttachedResources,
        device: &VirtualBlockDevice<N>,
        bridge: &VirtualBlockQueueBridge<N>,
    ) -> Result<VirtualBlockPciInterruptState, VirtualBlockPciError> {
        let window = self.validate_mmio_window(device, bridge)?;
        if pci.attachment() != self.pci.attachment()
            || pci.location() != self.pci.location()
            || pci.function_generation() != self.pci.function_generation()
            || pci.mmio_window() != Some(window)
            || pci.command() & PCI_COMMAND_MEMORY_SPACE == 0
        {
            return Err(VirtualBlockPciError::StalePciGeneration);
        }
        Ok(if pci.command() & PCI_COMMAND_INTERRUPT_DISABLE == 0 {
            VirtualBlockPciInterruptState::Enabled
        } else {
            VirtualBlockPciInterruptState::Masked
        })
    }

    fn cleanup_record<const N: usize>(
        &self,
        pci: VirtualPciAttachedResources,
        device: &VirtualBlockDevice<N>,
    ) -> Result<VirtualBlockPciCleanupRecord, VirtualBlockPciError> {
        if self.state != VirtualBlockPciAttachmentState::Attached {
            return Err(VirtualBlockPciError::InvalidState);
        }
        if pci.attachment() != self.pci.attachment()
            || pci.location() != self.pci.location()
            || pci.function_generation() != self.pci.function_generation()
        {
            return Err(VirtualBlockPciError::StalePciGeneration);
        }
        if device.generation() != self.block_generation {
            return Err(VirtualBlockPciError::StaleBlockGeneration);
        }
        if device.queue() != Some(self.queue)
            || device.interrupt_vector() != Some(self.interrupt_vector)
            || self.backend.exposed_block_count() != device.block_count()
        {
            return Err(VirtualBlockPciError::InvalidState);
        }
        if self.mapped_window.is_some() && self.mapped_window != pci.mmio_window() {
            return Err(VirtualBlockPciError::InvalidState);
        }
        Ok(VirtualBlockPciCleanupRecord {
            pci,
            block_generation: self.block_generation,
            queue: self.queue,
            interrupt_vector: self.interrupt_vector,
            backend: self.backend,
            mapped_window: self.mapped_window,
        })
    }

    fn window_record<const N: usize>(
        &self,
        pci: VirtualPciAttachedResources,
        device: &VirtualBlockDevice<N>,
        mapping: bool,
    ) -> Result<VirtualBlockPciCleanupRecord, VirtualBlockPciError> {
        let record = self.cleanup_record(pci, device)?;
        let window = pci
            .mmio_window()
            .ok_or(VirtualBlockPciError::InvalidState)?;
        if (mapping && self.mapped_window.is_some())
            || (!mapping && self.mapped_window != Some(window))
        {
            return Err(VirtualBlockPciError::InvalidState);
        }
        Ok(record)
    }
}

/// Native BAR mapping below the exact block/PCI attachment.
///
/// # Safety
///
/// Success from map must establish only the exact window in `record`; success
/// from unmap must make it unusable. Partial or uncertain state must return
/// `Uncertain` and the VM must not resume.
pub unsafe trait VirtualBlockPciWindowBackend {
    fn map_block_window(
        &mut self,
        record: VirtualBlockPciCleanupRecord,
    ) -> Result<(), VirtualPciNativeResourceError>;

    fn unmap_block_window(
        &mut self,
        record: VirtualBlockPciCleanupRecord,
    ) -> Result<(), VirtualPciNativeResourceError>;
}

/// Native BAR mapping below an exact block/PCI attachment that mutates the
/// same stopped VMM backend whose configuration exit is being retired.
///
/// # Safety
///
/// Success must establish or withdraw only the exact window in `record` and
/// leave `guest` translation state coherent. Uncertainty must be reported as
/// `Uncertain` and must leave the guest unable to resume.
pub unsafe trait VirtualBlockPciGuestWindowBackend<B> {
    fn map_block_window(
        &mut self,
        guest: &mut B,
        record: VirtualBlockPciCleanupRecord,
    ) -> Result<(), VirtualPciNativeResourceError>;

    fn unmap_block_window(
        &mut self,
        guest: &mut B,
        record: VirtualBlockPciCleanupRecord,
    ) -> Result<(), VirtualPciNativeResourceError>;
}

pub struct VirtualBlockPciMemoryMapper<'a, M, const N: usize> {
    attachment: &'a mut VirtualBlockPciAttachment,
    device: &'a VirtualBlockDevice<N>,
    backend: &'a mut M,
}

pub struct VirtualBlockPciGuestMemoryMapper<'a, M, const N: usize> {
    attachment: &'a mut VirtualBlockPciAttachment,
    device: &'a VirtualBlockDevice<N>,
    backend: &'a mut M,
}

impl<'a, M, const N: usize> VirtualBlockPciGuestMemoryMapper<'a, M, N> {
    pub fn new(
        attachment: &'a mut VirtualBlockPciAttachment,
        device: &'a VirtualBlockDevice<N>,
        backend: &'a mut M,
    ) -> Self {
        Self {
            attachment,
            device,
            backend,
        }
    }
}

unsafe impl<B, M: VirtualBlockPciGuestWindowBackend<B>, const N: usize>
    crate::VirtualPciBackendMemoryMapper<B> for VirtualBlockPciGuestMemoryMapper<'_, M, N>
{
    fn map_window(
        &mut self,
        guest: &mut B,
        pci: VirtualPciAttachedResources,
    ) -> Result<(), VirtualPciNativeResourceError> {
        let record = self
            .attachment
            .window_record(pci, self.device, true)
            .map_err(|_| VirtualPciNativeResourceError::Rejected)?;
        self.backend.map_block_window(guest, record)?;
        self.attachment.mapped_window = pci.mmio_window();
        Ok(())
    }

    fn unmap_window(
        &mut self,
        guest: &mut B,
        pci: VirtualPciAttachedResources,
    ) -> Result<(), VirtualPciNativeResourceError> {
        let record = self
            .attachment
            .window_record(pci, self.device, false)
            .map_err(|_| VirtualPciNativeResourceError::Rejected)?;
        self.backend.unmap_block_window(guest, record)?;
        self.attachment.mapped_window = None;
        Ok(())
    }
}

impl<'a, M, const N: usize> VirtualBlockPciMemoryMapper<'a, M, N> {
    pub fn new(
        attachment: &'a mut VirtualBlockPciAttachment,
        device: &'a VirtualBlockDevice<N>,
        backend: &'a mut M,
    ) -> Self {
        Self {
            attachment,
            device,
            backend,
        }
    }
}

unsafe impl<M: VirtualBlockPciWindowBackend, const N: usize> VirtualPciMemoryMapper
    for VirtualBlockPciMemoryMapper<'_, M, N>
{
    fn map_window(
        &mut self,
        pci: VirtualPciAttachedResources,
    ) -> Result<(), VirtualPciNativeResourceError> {
        let record = self
            .attachment
            .window_record(pci, self.device, true)
            .map_err(|_| VirtualPciNativeResourceError::Rejected)?;
        self.backend.map_block_window(record)?;
        self.attachment.mapped_window = pci.mmio_window();
        Ok(())
    }

    fn unmap_window(
        &mut self,
        pci: VirtualPciAttachedResources,
    ) -> Result<(), VirtualPciNativeResourceError> {
        let record = self
            .attachment
            .window_record(pci, self.device, false)
            .map_err(|_| VirtualPciNativeResourceError::Rejected)?;
        self.backend.unmap_block_window(record)?;
        self.attachment.mapped_window = None;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualBlockPciCleanupMode {
    Reset,
    Remove,
}

#[derive(Debug, Eq, PartialEq)]
pub enum VirtualBlockPciCleanupError<E> {
    Attachment(VirtualBlockPciError),
    Resource(E),
    Device(VirtualBlockError),
}

/// One-use synchronous composition supplied to the PCI router's existing
/// revoke-before-reset/removal boundary.
pub struct VirtualBlockPciFunctionRevoker<'a, R, const N: usize> {
    attachment: &'a mut VirtualBlockPciAttachment,
    device: &'a mut VirtualBlockDevice<N>,
    resources: &'a mut R,
    mode: VirtualBlockPciCleanupMode,
}

impl<'a, R, const N: usize> VirtualBlockPciFunctionRevoker<'a, R, N> {
    pub fn new(
        attachment: &'a mut VirtualBlockPciAttachment,
        device: &'a mut VirtualBlockDevice<N>,
        resources: &'a mut R,
        mode: VirtualBlockPciCleanupMode,
    ) -> Self {
        Self {
            attachment,
            device,
            resources,
            mode,
        }
    }
}

unsafe impl<R: VirtualBlockPciResourceRevoker, const N: usize> VirtualPciFunctionRevoker
    for VirtualBlockPciFunctionRevoker<'_, R, N>
{
    type Error = VirtualBlockPciCleanupError<R::Error>;

    fn revoke_function(&mut self, pci: VirtualPciAttachedResources) -> Result<(), Self::Error> {
        let record = self
            .attachment
            .cleanup_record(pci, self.device)
            .map_err(VirtualBlockPciCleanupError::Attachment)?;
        self.resources
            .revoke_block_resources(record)
            .map_err(VirtualBlockPciCleanupError::Resource)?;
        let invalidated = match self.mode {
            VirtualBlockPciCleanupMode::Reset => self.device.reset(),
            VirtualBlockPciCleanupMode::Remove => self.device.remove(),
        };
        match invalidated {
            Ok(invalidated) => {
                self.attachment.invalidated_requests = invalidated;
                self.attachment.state = match self.mode {
                    VirtualBlockPciCleanupMode::Reset => VirtualBlockPciAttachmentState::Reset,
                    VirtualBlockPciCleanupMode::Remove => VirtualBlockPciAttachmentState::Removed,
                };
                Ok(())
            }
            Err(error) => {
                self.attachment.state = VirtualBlockPciAttachmentState::Failed;
                Err(VirtualBlockPciCleanupError::Device(error))
            }
        }
    }
}

/// Revalidates one exact backend capability for every block operation.
/// Possession of this adapter, its object ID, or the underlying backend is not
/// authority; the live capability and operation-specific right are checked on
/// every call. The common runners recreate the adapter for each transaction, so
/// revocation and attenuation before the next transaction take effect.
pub struct CapabilitySelectedVirtualBlockBackend<'a, D, const C: usize> {
    backend: &'a mut D,
    capabilities: &'a CapabilitySpace<C>,
    authority: VirtualBlockBackendAuthority,
    block_size: u32,
}

impl<'a, D, const C: usize> CapabilitySelectedVirtualBlockBackend<'a, D, C> {
    pub fn new(
        backend: &'a mut D,
        capabilities: &'a CapabilitySpace<C>,
        authority: VirtualBlockBackendAuthority,
        block_size: u32,
    ) -> Self {
        Self {
            backend,
            capabilities,
            authority,
            block_size,
        }
    }

    fn authorize(&self, right: Rights) -> Result<(), VirtualBlockCapabilityError<D::Error>>
    where
        D: VirtualBlockBackend,
    {
        let object = self
            .capabilities
            .authorize(self.authority.capability, right)
            .map_err(VirtualBlockCapabilityError::Capability)?;
        if object != self.authority.object {
            return Err(VirtualBlockCapabilityError::ObjectMismatch);
        }
        Ok(())
    }

    fn translate(
        &self,
        right: Rights,
        block: u64,
        bytes: usize,
    ) -> Result<u64, VirtualBlockCapabilityError<D::Error>>
    where
        D: VirtualBlockBackend,
    {
        self.authorize(right)?;
        let block_size = usize::try_from(self.block_size)
            .ok()
            .filter(|block_size| *block_size != 0)
            .ok_or(VirtualBlockCapabilityError::InvalidRange)?;
        if bytes == 0 || !bytes.is_multiple_of(block_size) {
            return Err(VirtualBlockCapabilityError::InvalidRange);
        }
        let count = u64::try_from(bytes / block_size)
            .map_err(|_| VirtualBlockCapabilityError::InvalidRange)?;
        let end = block
            .checked_add(count)
            .ok_or(VirtualBlockCapabilityError::InvalidRange)?;
        if end > self.authority.exposed_block_count {
            return Err(VirtualBlockCapabilityError::InvalidRange);
        }
        self.authority
            .backend_first_block
            .checked_add(block)
            .ok_or(VirtualBlockCapabilityError::InvalidRange)
    }
}

unsafe impl<D: VirtualBlockBackend, const C: usize> VirtualBlockBackend
    for CapabilitySelectedVirtualBlockBackend<'_, D, C>
{
    type Error = VirtualBlockCapabilityError<D::Error>;

    fn read_blocks(&mut self, block: u64, output: &mut [u8]) -> Result<(), Self::Error> {
        let block = self.translate(Rights::READ, block, output.len())?;
        self.backend
            .read_blocks(block, output)
            .map_err(VirtualBlockCapabilityError::Backend)
    }

    fn write_blocks(
        &mut self,
        block: u64,
        input: &[u8],
    ) -> Result<(), VirtualBlockMutationError<Self::Error>> {
        let block = self
            .translate(Rights::WRITE, block, input.len())
            .map_err(VirtualBlockMutationError::Rejected)?;
        self.backend
            .write_blocks(block, input)
            .map_err(|error| match error {
                VirtualBlockMutationError::Rejected(error) => {
                    VirtualBlockMutationError::Rejected(VirtualBlockCapabilityError::Backend(error))
                }
                VirtualBlockMutationError::Uncertain(error) => {
                    VirtualBlockMutationError::Uncertain(VirtualBlockCapabilityError::Backend(
                        error,
                    ))
                }
            })
    }

    fn flush(&mut self) -> Result<(), VirtualBlockMutationError<Self::Error>> {
        self.authorize(Rights::FLUSH)
            .map_err(VirtualBlockMutationError::Rejected)?;
        self.backend.flush().map_err(|error| match error {
            VirtualBlockMutationError::Rejected(error) => {
                VirtualBlockMutationError::Rejected(VirtualBlockCapabilityError::Backend(error))
            }
            VirtualBlockMutationError::Uncertain(error) => {
                VirtualBlockMutationError::Uncertain(VirtualBlockCapabilityError::Backend(error))
            }
        })
    }
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

#[derive(Debug, Eq, PartialEq)]
pub enum VirtualBlockDoorbellError<M, D> {
    InvalidExit,
    Process(VirtualBlockProcessError<M, D>),
}

pub type VirtualBlockDoorbellResult<M, D> =
    Result<VirtualBlockProcessOutcome<D>, VirtualBlockDoorbellError<M, D>>;

#[derive(Debug, Eq, PartialEq)]
pub enum VirtualBlockCompletionAckError<M> {
    InvalidExit,
    Queue {
        error: VirtualBlockQueueError<M>,
        invalidated: Result<usize, VirtualBlockError>,
    },
}

pub type VirtualBlockCompletionAckResult<M> = Result<u64, VirtualBlockCompletionAckError<M>>;

#[derive(Debug, Eq, PartialEq)]
pub enum VirtualBlockCompletionAckRunError<M> {
    Exit(VmRunError<M>),
    Acknowledgement(VirtualBlockCompletionAckError<M>),
}

pub type VirtualBlockCompletionAckRunResult<M> = Result<u64, VirtualBlockCompletionAckRunError<M>>;

#[derive(Debug, Eq, PartialEq)]
pub enum VirtualBlockRunError<M, D> {
    Authority(VirtualBlockAuthorityError),
    Exit(VmRunError<M>),
    Doorbell(VirtualBlockDoorbellError<M, D>),
    Interrupt(VirtualBlockInterruptError<M>),
}

pub type VirtualBlockRunResult<M, D> =
    Result<VirtualBlockProcessOutcome<D>, VirtualBlockRunError<M, D>>;

#[derive(Debug, Eq, PartialEq)]
pub enum VirtualBlockTransactionOutcome<E> {
    Doorbell(VirtualBlockProcessOutcome<E>),
    CompletionAcknowledged(u64),
}

#[derive(Debug, Eq, PartialEq)]
pub enum VirtualBlockTransactionRunError<M, D> {
    Authority(VirtualBlockAuthorityError),
    Exit(VmRunError<M>),
    InvalidExit,
    Doorbell(VirtualBlockDoorbellError<M, D>),
    Acknowledgement(VirtualBlockCompletionAckError<M>),
    Interrupt(VirtualBlockInterruptError<M>),
    Completion(M),
}

pub type VirtualBlockTransactionRunResult<M, D> =
    Result<VirtualBlockTransactionOutcome<D>, VirtualBlockTransactionRunError<M, D>>;

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
    completion_consumed: u64,
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
            completion_consumed: 0,
            poisoned: false,
        })
    }

    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub const fn layout(&self) -> VirtualBlockQueueLayout {
        self.layout
    }

    /// Captures canonical data only for an explicitly suspended device/bridge
    /// pair. Suspension proves that no device request or notification is live;
    /// a stopped vCPU alone is insufficient. A backend read failure poisons the
    /// bridge, and the returned record carries no authority to resume or access
    /// the device.
    pub fn resume_state<B: VirtualBlockVmmMemory>(
        &mut self,
        backend: &B,
        device: &VirtualBlockDevice<N>,
    ) -> Result<VirtualBlockResumeState, VirtualBlockQueueError<B::Error>> {
        self.require_live()?;
        let configuration = device
            .suspended_configuration()
            .map_err(VirtualBlockQueueError::Protocol)?;
        if configuration.queue() != self.layout {
            return Err(VirtualBlockQueueError::Protocol(
                VirtualBlockError::InvalidConfiguration,
            ));
        }
        let request_producer = self.read_counter(backend, self.layout.request_base)?;
        let last_published_request_id = if request_producer == 0 {
            0
        } else {
            let address = slot_address(
                self.layout.request_base,
                request_producer,
                N,
                VIRTUAL_BLOCK_REQUEST_BYTES,
            )
            .map_err(VirtualBlockQueueError::Protocol)?;
            let mut encoded = [0; VIRTUAL_BLOCK_REQUEST_BYTES];
            self.read(backend, address, &mut encoded)?;
            VirtualBlockRequest::decode(&encoded)
                .map_err(VirtualBlockQueueError::Protocol)?
                .request_id()
        };
        let state = VirtualBlockResumeState {
            configuration,
            request_producer,
            request_consumed: self.request_consumed,
            completion_published: self.completion_published,
            completion_consumer: self.completion_consumed,
            last_admitted_request_id: device.last_request_id,
            last_published_request_id,
        };
        state.validate().map_err(VirtualBlockQueueError::Protocol)?;
        Ok(state)
    }

    /// Captures and publishes one exact canonical page through the isolated
    /// device-write path. Capture or publication uncertainty poisons the
    /// bridge; the page remains data and grants no resume authority.
    pub fn publish_resume_page<B: VirtualBlockVmmMemory>(
        &mut self,
        backend: &mut B,
        device: &VirtualBlockDevice<N>,
        page: VirtualBlockResumePage,
    ) -> Result<VirtualBlockResumePage, VirtualBlockQueueError<B::Error>> {
        let state = self.resume_state(backend, device)?;
        let page = VirtualBlockResumePage::new(
            page.base(),
            VirtualBlockConfigurationPage::new(page.configuration_base(), state.configuration())
                .map_err(VirtualBlockQueueError::Protocol)?,
            state,
        )
        .map_err(VirtualBlockQueueError::Protocol)?;
        let mut encoded = [0; PAGE_SIZE as usize];
        page.encode_page(&mut encoded);
        self.write(backend, page.base(), &encoded)?;
        Ok(page)
    }

    /// Captures and validates the minimal canonical restart image for an exact
    /// suspended device/bridge pair. Backend uncertainty poisons the bridge;
    /// protocol rejection grants no recovery or resume authority.
    pub fn capture_restart_image<B: VirtualBlockVmmMemory>(
        &mut self,
        backend: &B,
        device: &VirtualBlockDevice<N>,
        page: VirtualBlockResumePage,
    ) -> Result<VirtualBlockRestartImage, VirtualBlockQueueError<B::Error>> {
        let state = self.resume_state(backend, device)?;
        if page.state() != state || page.state().configuration().queue() != self.layout {
            return Err(VirtualBlockQueueError::Protocol(
                VirtualBlockError::InvalidConfiguration,
            ));
        }
        let mut encoded_resume_page = [0; PAGE_SIZE as usize];
        self.read(backend, page.base(), &mut encoded_resume_page)?;
        let decoded = VirtualBlockResumePage::decode_page(&encoded_resume_page)
            .map_err(VirtualBlockQueueError::Protocol)?;
        if decoded != state {
            return Err(VirtualBlockQueueError::Protocol(
                VirtualBlockError::InvalidConfiguration,
            ));
        }

        let mut request_slots = [[0; VIRTUAL_BLOCK_REQUEST_BYTES]; MAX_VIRTUAL_BLOCK_QUEUE_SLOTS];
        let request_first = if state.request_producer() == 0 {
            None
        } else if state.request_producer() == state.completion_consumer() {
            Some(state.request_producer())
        } else {
            Some(state.completion_consumer().checked_add(1).ok_or(
                VirtualBlockQueueError::Protocol(VirtualBlockError::SequenceExhausted),
            )?)
        };
        if let Some(first) = request_first {
            for position in first..=state.request_producer() {
                let slot = slot_index(position, N).map_err(VirtualBlockQueueError::Protocol)?;
                let address = slot_address(
                    self.layout.request_base(),
                    position,
                    N,
                    VIRTUAL_BLOCK_REQUEST_BYTES,
                )
                .map_err(VirtualBlockQueueError::Protocol)?;
                self.read(backend, address, &mut request_slots[slot])?;
            }
        }
        let mut encoded_state = [0; VIRTUAL_BLOCK_RESUME_STATE_BYTES];
        state.encode(&mut encoded_state);
        VirtualBlockGuestDriver::reconstruct(&encoded_state, &request_slots[..N])
            .map_err(VirtualBlockQueueError::Protocol)?;

        let mut completion_slots =
            [[0; VIRTUAL_BLOCK_COMPLETION_BYTES]; MAX_VIRTUAL_BLOCK_QUEUE_SLOTS];
        if state.completion_published() != state.completion_consumer() {
            let first = state.completion_consumer().checked_add(1).ok_or(
                VirtualBlockQueueError::Protocol(VirtualBlockError::SequenceExhausted),
            )?;
            for position in first..=state.completion_published() {
                let slot = slot_index(position, N).map_err(VirtualBlockQueueError::Protocol)?;
                let address = slot_address(
                    self.layout.completion_base(),
                    position,
                    N,
                    VIRTUAL_BLOCK_COMPLETION_BYTES,
                )
                .map_err(VirtualBlockQueueError::Protocol)?;
                self.read(backend, address, &mut completion_slots[slot])?;
                let completion = VirtualBlockCompletion::decode(&completion_slots[slot])
                    .map_err(VirtualBlockQueueError::Protocol)?;
                let request = VirtualBlockRequest::decode(&request_slots[slot])
                    .map_err(VirtualBlockQueueError::Protocol)?;
                let expected = if request.operation() == VirtualBlockOperation::Flush {
                    0
                } else {
                    request.buffer_length()
                };
                if completion.generation() != state.configuration().generation()
                    || completion.request_id() != request.request_id()
                    || matches!(
                        completion.status(),
                        VirtualBlockCompletionStatus::Reset | VirtualBlockCompletionStatus::Removed
                    )
                    || (completion.status() == VirtualBlockCompletionStatus::Ok
                        && completion.transferred() != expected)
                {
                    return Err(VirtualBlockQueueError::Protocol(
                        VirtualBlockError::InvalidCompletion,
                    ));
                }
            }
        }
        Ok(VirtualBlockRestartImage {
            resume_base: page.base(),
            configuration_base: page.configuration_base(),
            state,
            request_slots,
            completion_slots,
            encoded_resume_page,
        })
    }

    /// Restores a validated image into completely fresh queue/resume memory.
    /// Request bytes use the ordinary host boundary; completion and resume
    /// bytes use only the device boundary. Any read or write uncertainty
    /// poisons the bridge and leaves the suspended device without resume.
    pub fn restore_restart_image<B: VirtualBlockVmmMemory>(
        &mut self,
        backend: &mut B,
        device: &VirtualBlockDevice<N>,
        lost: VirtualBlockLostExecution,
    ) -> Result<(), VirtualBlockQueueError<B::Error>> {
        let image = &lost.image;
        self.require_live()?;
        let configuration = device
            .suspended_configuration()
            .map_err(VirtualBlockQueueError::Protocol)?;
        let state = image.state;
        if configuration != state.configuration()
            || configuration.queue() != self.layout
            || self.request_consumed != state.request_consumed()
            || self.completion_published != state.completion_published()
            || self.completion_consumed != state.completion_consumer()
        {
            return Err(VirtualBlockQueueError::Protocol(
                VirtualBlockError::InvalidConfiguration,
            ));
        }

        let mut fresh = [0; PAGE_SIZE as usize];
        for base in [self.layout.request_base(), self.layout.completion_base()] {
            for page_index in 0..self.layout.pages_per_queue() {
                let address = base
                    .checked_add(page_index.checked_mul(PAGE_SIZE).ok_or(
                        VirtualBlockQueueError::Protocol(VirtualBlockError::RangeOverflow),
                    )?)
                    .ok_or(VirtualBlockQueueError::Protocol(
                        VirtualBlockError::RangeOverflow,
                    ))?;
                self.read(backend, address, &mut fresh)?;
                if fresh.iter().any(|byte| *byte != 0) {
                    return Err(VirtualBlockQueueError::Protocol(
                        VirtualBlockError::InvalidQueue,
                    ));
                }
            }
        }
        self.read(backend, image.resume_base, &mut fresh)?;
        let configuration_page =
            VirtualBlockConfigurationPage::new(image.configuration_base, configuration)
                .map_err(VirtualBlockQueueError::Protocol)?;
        let fresh_resume = VirtualBlockResumePage::fresh(image.resume_base, configuration_page)
            .map_err(VirtualBlockQueueError::Protocol)?;
        let mut expected_fresh = [0; PAGE_SIZE as usize];
        fresh_resume.encode_page(&mut expected_fresh);
        if fresh != expected_fresh {
            return Err(VirtualBlockQueueError::Protocol(
                VirtualBlockError::InvalidConfiguration,
            ));
        }

        let request_first = if state.request_producer() == 0 {
            None
        } else if state.request_producer() == state.completion_consumer() {
            Some(state.request_producer())
        } else {
            Some(state.completion_consumer().checked_add(1).ok_or(
                VirtualBlockQueueError::Protocol(VirtualBlockError::SequenceExhausted),
            )?)
        };
        if let Some(first) = request_first {
            for position in first..=state.request_producer() {
                let slot = slot_index(position, N).map_err(VirtualBlockQueueError::Protocol)?;
                let address = slot_address(
                    self.layout.request_base(),
                    position,
                    N,
                    VIRTUAL_BLOCK_REQUEST_BYTES,
                )
                .map_err(VirtualBlockQueueError::Protocol)?;
                backend
                    .write_guest(address, &image.request_slots[slot])
                    .map_err(|error| {
                        self.poisoned = true;
                        VirtualBlockQueueError::Backend(error)
                    })?;
            }
        }
        backend
            .write_guest(
                self.layout.request_base() + 64,
                &state.request_consumed().to_le_bytes(),
            )
            .and_then(|()| {
                backend.write_guest(
                    self.layout.request_base(),
                    &state.request_producer().to_le_bytes(),
                )
            })
            .map_err(|error| {
                self.poisoned = true;
                VirtualBlockQueueError::Backend(error)
            })?;

        if state.completion_published() != state.completion_consumer() {
            let first = state.completion_consumer().checked_add(1).ok_or(
                VirtualBlockQueueError::Protocol(VirtualBlockError::SequenceExhausted),
            )?;
            for position in first..=state.completion_published() {
                let slot = slot_index(position, N).map_err(VirtualBlockQueueError::Protocol)?;
                let address = slot_address(
                    self.layout.completion_base(),
                    position,
                    N,
                    VIRTUAL_BLOCK_COMPLETION_BYTES,
                )
                .map_err(VirtualBlockQueueError::Protocol)?;
                self.write(backend, address, &image.completion_slots[slot])?;
            }
        }
        self.write_counter(
            backend,
            self.layout.completion_base() + 64,
            state.completion_consumer(),
        )?;
        self.write_counter(
            backend,
            self.layout.completion_base(),
            state.completion_published(),
        )?;
        self.write(backend, image.resume_base, &image.encoded_resume_page)
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
        _backend: &B,
    ) -> Result<bool, VirtualBlockQueueError<B::Error>> {
        self.require_live()?;
        if self.completion_consumed > self.completion_published
            || self.completion_published - self.completion_consumed > N as u64
        {
            return Err(VirtualBlockQueueError::Protocol(
                VirtualBlockError::InvalidQueue,
            ));
        }
        Ok(self.completion_published - self.completion_consumed < N as u64)
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
        if self.completion_consumed > self.completion_published {
            return Err(VirtualBlockQueueError::Protocol(
                VirtualBlockError::InvalidQueue,
            ));
        }
        if self.completion_published - self.completion_consumed >= N as u64 {
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

    fn acknowledge_completion<B: VirtualBlockVmmMemory>(
        &mut self,
        backend: &mut B,
    ) -> Result<u64, VirtualBlockQueueError<B::Error>> {
        self.require_live()?;
        if self.completion_consumed >= self.completion_published {
            return Err(VirtualBlockQueueError::Protocol(
                VirtualBlockError::QueueEmpty,
            ));
        }
        let consumed =
            self.completion_consumed
                .checked_add(1)
                .ok_or(VirtualBlockQueueError::Protocol(
                    VirtualBlockError::SequenceExhausted,
                ))?;
        self.write_counter(backend, self.layout.completion_base + 64, consumed)?;
        self.completion_consumed = consumed;
        Ok(consumed)
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
    if let Err(error) = device.latch_completion_interrupt() {
        bridge.fail_stop();
        return Err(VirtualBlockProcessError::Queue {
            error: VirtualBlockQueueError::Protocol(error),
            invalidated: device.fail(),
        });
    }
    Ok(VirtualBlockProcessOutcome::Completed(execution))
}

/// Processes at most one request for an exact MRML virtual-block doorbell.
/// The disposition must first have crossed the common deny-by-default VM exit
/// dispatcher. Port, width, direction, and value are rechecked here before any
/// queue, payload, scratch, or block-backend access. Interrupt delivery remains
/// a separate capability-authorized operation after a published completion.
pub fn process_virtual_block_doorbell<const N: usize, M, D>(
    disposition: ExitDisposition,
    device: &mut VirtualBlockDevice<N>,
    bridge: &mut VirtualBlockQueueBridge<N>,
    memory: &mut M,
    backend: &mut D,
    scratch: &mut [u8],
) -> VirtualBlockDoorbellResult<M::Error, D::Error>
where
    M: VirtualBlockVmmMemory,
    D: VirtualBlockBackend,
{
    let transport = device.transport();
    let Some(doorbell_port) = transport.doorbell_port() else {
        return Err(VirtualBlockDoorbellError::InvalidExit);
    };
    if disposition
        != (ExitDisposition::Io {
            port: doorbell_port,
            size: 4,
            write: true,
            value: transport.doorbell_value(),
        })
    {
        return Err(VirtualBlockDoorbellError::InvalidExit);
    }
    process_virtual_block_request(device, bridge, memory, backend, scratch)
        .map_err(VirtualBlockDoorbellError::Process)
}

fn exact_mmio_register(
    window: VirtualPciMmioWindow,
    offset: u32,
) -> Result<u64, VirtualBlockPciError> {
    let end = offset
        .checked_add(4)
        .ok_or(VirtualBlockPciError::InvalidState)?;
    if end > window.size() {
        return Err(VirtualBlockPciError::InvalidState);
    }
    u64::from(window.address())
        .checked_add(u64::from(offset))
        .ok_or(VirtualBlockPciError::InvalidState)
}

/// Processes one write-only MRML-native PCI-MMIO doorbell after exact live
/// PCI/block/mapping revalidation. No BAR address or device identity grants
/// backend authority; those remain separately capability-selected.
pub fn process_virtual_block_mmio_doorbell<const N: usize, M, D>(
    disposition: ExitDisposition,
    attachment: &VirtualBlockPciAttachment,
    device: &mut VirtualBlockDevice<N>,
    bridge: &mut VirtualBlockQueueBridge<N>,
    memory: &mut M,
    backend: &mut D,
    scratch: &mut [u8],
) -> VirtualBlockDoorbellResult<M::Error, D::Error>
where
    M: VirtualBlockVmmMemory,
    D: VirtualBlockBackend,
{
    let window = attachment
        .validate_mmio_window(device, bridge)
        .map_err(|_| VirtualBlockDoorbellError::InvalidExit)?;
    let address = exact_mmio_register(window, VIRTUAL_BLOCK_MMIO_DOORBELL_OFFSET)
        .map_err(|_| VirtualBlockDoorbellError::InvalidExit)?;
    if disposition
        != (ExitDisposition::Mmio {
            guest_address: address,
            size: 4,
            write: true,
            value: u64::from(VIRTUAL_BLOCK_DOORBELL_VALUE),
        })
    {
        return Err(VirtualBlockDoorbellError::InvalidExit);
    }
    process_virtual_block_request(device, bridge, memory, backend, scratch)
        .map_err(VirtualBlockDoorbellError::Process)
}

/// Acknowledges exactly one already-published completion while keeping the
/// completion ring guest-read-only. The scalar tuple is routing data only; the
/// bridge owns the monotonic consumer position and performs the protected
/// header write. Acknowledgement is accepted only after notification delivery.
pub fn process_virtual_block_completion_ack<const N: usize, M>(
    disposition: ExitDisposition,
    device: &mut VirtualBlockDevice<N>,
    bridge: &mut VirtualBlockQueueBridge<N>,
    memory: &mut M,
) -> VirtualBlockCompletionAckResult<M::Error>
where
    M: VirtualBlockVmmMemory,
{
    let transport = device.transport();
    let Some(acknowledgement_port) = transport.completion_acknowledgement_port() else {
        return Err(VirtualBlockCompletionAckError::InvalidExit);
    };
    if disposition
        != (ExitDisposition::Io {
            port: acknowledgement_port,
            size: 4,
            write: true,
            value: transport.completion_acknowledgement_value(),
        })
    {
        return Err(VirtualBlockCompletionAckError::InvalidExit);
    }
    if device.state() != VirtualBlockDeviceState::Active
        || device.queue() != Some(bridge.layout())
        || device.pending_interrupt_vector().is_some()
    {
        bridge.fail_stop();
        return Err(VirtualBlockCompletionAckError::Queue {
            error: VirtualBlockQueueError::Protocol(VirtualBlockError::InvalidState),
            invalidated: device.fail(),
        });
    }
    bridge.acknowledge_completion(memory).map_err(|error| {
        bridge.fail_stop();
        VirtualBlockCompletionAckError::Queue {
            error,
            invalidated: device.fail(),
        }
    })
}

/// Retires one protected completion through the separately mapped PCI-MMIO
/// acknowledgement register. The exact generational mapping is revalidated
/// before the common monotonic completion consumer is advanced.
pub fn process_virtual_block_mmio_completion_ack<const N: usize, M>(
    disposition: ExitDisposition,
    attachment: &VirtualBlockPciAttachment,
    device: &mut VirtualBlockDevice<N>,
    bridge: &mut VirtualBlockQueueBridge<N>,
    memory: &mut M,
) -> VirtualBlockCompletionAckResult<M::Error>
where
    M: VirtualBlockVmmMemory,
{
    let window = attachment
        .validate_mmio_window(device, bridge)
        .map_err(|_| VirtualBlockCompletionAckError::InvalidExit)?;
    let address = exact_mmio_register(window, VIRTUAL_BLOCK_MMIO_COMPLETION_ACK_OFFSET)
        .map_err(|_| VirtualBlockCompletionAckError::InvalidExit)?;
    if disposition
        != (ExitDisposition::Mmio {
            guest_address: address,
            size: 4,
            write: true,
            value: u64::from(VIRTUAL_BLOCK_COMPLETION_ACK_VALUE),
        })
    {
        return Err(VirtualBlockCompletionAckError::InvalidExit);
    }
    if device.pending_interrupt_vector().is_some() {
        bridge.fail_stop();
        return Err(VirtualBlockCompletionAckError::Queue {
            error: VirtualBlockQueueError::Protocol(VirtualBlockError::InvalidState),
            invalidated: device.fail(),
        });
    }
    bridge.acknowledge_completion(memory).map_err(|error| {
        bridge.fail_stop();
        VirtualBlockCompletionAckError::Queue {
            error,
            invalidated: device.fail(),
        }
    })
}

/// Runs one vCPU to an exact virtual-block doorbell, processes at most one
/// request, and delivers completion notification through the ordinary VM
/// interrupt authority. Pending notification is delivered before vCPU entry.
/// Any stage error fails the VM so uncertain native or device state cannot be
/// resumed through this composition.
#[allow(clippy::too_many_arguments)]
pub fn run_virtual_block_doorbell_once<
    M,
    D,
    const N: usize,
    const V: usize,
    const C: usize,
    const G: usize,
    const I: usize,
>(
    memory: &mut M,
    block_backend: &mut D,
    block_authority: VirtualBlockBackendAuthority,
    vcpu: u32,
    vms: &mut VmTable<V>,
    vm: VmId,
    router: &mut HypercallRouter,
    capabilities: &CapabilitySpace<C>,
    guest_memory: &GuestMemory<G>,
    io_policy: &IoPortPolicy<I>,
    interrupt_policy: &InterruptPolicy,
    interrupt_capability: Capability,
    interrupt_object: ObjectId,
    device: &mut VirtualBlockDevice<N>,
    bridge: &mut VirtualBlockQueueBridge<N>,
    scratch: &mut [u8],
) -> VirtualBlockRunResult<M::Error, VirtualBlockCapabilityError<D::Error>>
where
    M: VirtualBlockVmmMemory,
    D: VirtualBlockBackend,
{
    if block_authority.exposed_block_count() != device.block_count() {
        let _ = vms.fail(vm);
        return Err(VirtualBlockRunError::Authority(
            VirtualBlockAuthorityError::GeometryMismatch,
        ));
    }
    if device.pending_interrupt_vector().is_some() {
        inject_virtual_block_interrupt(
            device,
            memory,
            vms,
            vm,
            vcpu,
            interrupt_policy,
            capabilities,
            interrupt_capability,
            interrupt_object,
        )
        .map_err(|error| {
            let _ = vms.fail(vm);
            VirtualBlockRunError::Interrupt(error)
        })?;
    }

    let disposition = run_vm_once(
        memory,
        vcpu,
        vms,
        vm,
        router,
        capabilities,
        guest_memory,
        io_policy,
    )
    .map_err(VirtualBlockRunError::Exit)?;
    let mut selected_backend = CapabilitySelectedVirtualBlockBackend::new(
        block_backend,
        capabilities,
        block_authority,
        device.block_size(),
    );
    let outcome = process_virtual_block_doorbell(
        disposition,
        device,
        bridge,
        memory,
        &mut selected_backend,
        scratch,
    )
    .map_err(|error| {
        let _ = vms.fail(vm);
        VirtualBlockRunError::Doorbell(error)
    })?;

    if matches!(outcome, VirtualBlockProcessOutcome::Completed(_)) {
        inject_virtual_block_interrupt(
            device,
            memory,
            vms,
            vm,
            vcpu,
            interrupt_policy,
            capabilities,
            interrupt_capability,
            interrupt_object,
        )
        .map_err(|error| {
            let _ = vms.fail(vm);
            VirtualBlockRunError::Interrupt(error)
        })?;
    }
    Ok(outcome)
}

/// Runs one vCPU to one completion acknowledgement and composes native exit
/// accounting, deny-by-default I/O dispatch, and the protected completion
/// consumer transition. Any exit or acknowledgement error fails the VM so an
/// uncertain native position cannot be resumed through this composition.
#[allow(clippy::too_many_arguments)]
pub fn run_virtual_block_completion_ack_once<
    M,
    const N: usize,
    const V: usize,
    const C: usize,
    const G: usize,
    const I: usize,
>(
    memory: &mut M,
    vcpu: u32,
    vms: &mut VmTable<V>,
    vm: VmId,
    router: &mut HypercallRouter,
    capabilities: &CapabilitySpace<C>,
    guest_memory: &GuestMemory<G>,
    io_policy: &IoPortPolicy<I>,
    device: &mut VirtualBlockDevice<N>,
    bridge: &mut VirtualBlockQueueBridge<N>,
) -> VirtualBlockCompletionAckRunResult<M::Error>
where
    M: VirtualBlockVmmMemory,
{
    let disposition = run_vm_once(
        memory,
        vcpu,
        vms,
        vm,
        router,
        capabilities,
        guest_memory,
        io_policy,
    )
    .map_err(VirtualBlockCompletionAckRunError::Exit)?;
    process_virtual_block_completion_ack(disposition, device, bridge, memory).map_err(|error| {
        let _ = vms.fail(vm);
        VirtualBlockCompletionAckRunError::Acknowledgement(error)
    })
}

/// Runs one vCPU for exactly one MRML-specific virtual-block transport
/// transaction. Only the configured doorbell and protected completion
/// acknowledgement tuples are accepted. Pending completion notification is
/// delivered before vCPU entry, and a newly published completion is notified
/// before returning. Every other exit or stage failure fails the VM, preserving
/// the caller's explicit exit budget and preventing ambiguous native state from
/// being resumed.
#[allow(clippy::too_many_arguments)]
pub fn run_virtual_block_transaction_once<
    M,
    D,
    const N: usize,
    const V: usize,
    const C: usize,
    const G: usize,
    const I: usize,
>(
    memory: &mut M,
    block_backend: &mut D,
    block_authority: VirtualBlockBackendAuthority,
    vcpu: u32,
    vms: &mut VmTable<V>,
    vm: VmId,
    router: &mut HypercallRouter,
    capabilities: &CapabilitySpace<C>,
    guest_memory: &GuestMemory<G>,
    io_policy: &IoPortPolicy<I>,
    interrupt_policy: &InterruptPolicy,
    interrupt_capability: Capability,
    interrupt_object: ObjectId,
    device: &mut VirtualBlockDevice<N>,
    bridge: &mut VirtualBlockQueueBridge<N>,
    scratch: &mut [u8],
) -> VirtualBlockTransactionRunResult<M::Error, VirtualBlockCapabilityError<D::Error>>
where
    M: VirtualBlockVmmMemory,
    D: VirtualBlockBackend,
{
    if block_authority.exposed_block_count() != device.block_count() {
        let _ = vms.fail(vm);
        return Err(VirtualBlockTransactionRunError::Authority(
            VirtualBlockAuthorityError::GeometryMismatch,
        ));
    }
    if device.pending_interrupt_vector().is_some() {
        inject_virtual_block_interrupt(
            device,
            memory,
            vms,
            vm,
            vcpu,
            interrupt_policy,
            capabilities,
            interrupt_capability,
            interrupt_object,
        )
        .map_err(|error| {
            let _ = vms.fail(vm);
            VirtualBlockTransactionRunError::Interrupt(error)
        })?;
    }

    let disposition = run_vm_once(
        memory,
        vcpu,
        vms,
        vm,
        router,
        capabilities,
        guest_memory,
        io_policy,
    )
    .map_err(VirtualBlockTransactionRunError::Exit)?;
    let transport = device.transport();
    let doorbell_port = transport.doorbell_port();

    if disposition
        == (ExitDisposition::Io {
            port: doorbell_port.unwrap_or(0),
            size: 4,
            write: true,
            value: transport.doorbell_value(),
        })
    {
        let mut selected_backend = CapabilitySelectedVirtualBlockBackend::new(
            block_backend,
            capabilities,
            block_authority,
            device.block_size(),
        );
        let outcome = process_virtual_block_doorbell(
            disposition,
            device,
            bridge,
            memory,
            &mut selected_backend,
            scratch,
        )
        .map_err(|error| {
            let _ = vms.fail(vm);
            VirtualBlockTransactionRunError::Doorbell(error)
        })?;
        if matches!(outcome, VirtualBlockProcessOutcome::Completed(_)) {
            inject_virtual_block_interrupt(
                device,
                memory,
                vms,
                vm,
                vcpu,
                interrupt_policy,
                capabilities,
                interrupt_capability,
                interrupt_object,
            )
            .map_err(|error| {
                let _ = vms.fail(vm);
                VirtualBlockTransactionRunError::Interrupt(error)
            })?;
        }
        return Ok(VirtualBlockTransactionOutcome::Doorbell(outcome));
    }

    let acknowledgement_port = transport.completion_acknowledgement_port();
    if disposition
        == (ExitDisposition::Io {
            port: acknowledgement_port.unwrap_or(0),
            size: 4,
            write: true,
            value: transport.completion_acknowledgement_value(),
        })
    {
        return process_virtual_block_completion_ack(disposition, device, bridge, memory)
            .map(VirtualBlockTransactionOutcome::CompletionAcknowledged)
            .map_err(|error| {
                let _ = vms.fail(vm);
                VirtualBlockTransactionRunError::Acknowledgement(error)
            });
    }

    let _ = vms.fail(vm);
    Err(VirtualBlockTransactionRunError::InvalidExit)
}

/// Runs one exact MRML-native PCI-MMIO block notification transaction. The
/// live generational BAR mapping and block attachment are revalidated before
/// queue access, and the native write exit is retired only after successful
/// device processing. Any mismatch or completion uncertainty fail-stops the
/// VM and prevents native re-entry.
#[allow(clippy::too_many_arguments)]
pub fn run_virtual_block_mmio_transaction_once<
    M,
    D,
    const N: usize,
    const V: usize,
    const C: usize,
    const G: usize,
    const I: usize,
>(
    memory: &mut M,
    block_backend: &mut D,
    block_authority: VirtualBlockBackendAuthority,
    vcpu: u32,
    vms: &mut VmTable<V>,
    vm: VmId,
    router: &mut HypercallRouter,
    capabilities: &CapabilitySpace<C>,
    guest_memory: &GuestMemory<G>,
    io_policy: &IoPortPolicy<I>,
    interrupt_policy: &InterruptPolicy,
    interrupt_capability: Capability,
    interrupt_object: ObjectId,
    pci_router: &VirtualPciConfigurationRouter,
    attachment: &VirtualBlockPciAttachment,
    device: &mut VirtualBlockDevice<N>,
    bridge: &mut VirtualBlockQueueBridge<N>,
    scratch: &mut [u8],
) -> VirtualBlockTransactionRunResult<M::Error, VirtualBlockCapabilityError<D::Error>>
where
    M: VirtualBlockVmmMemory + MmioWriteCompleter,
    D: VirtualBlockBackend,
{
    let interrupt_state = pci_router
        .describe_attachment(attachment.pci().attachment())
        .map_err(|_| ())
        .and_then(|pci| {
            attachment
                .validate_interrupt_state(pci.resources(), device, bridge)
                .map_err(|_| ())
        });
    if block_authority != attachment.backend()
        || block_authority.exposed_block_count() != device.block_count()
        || interrupt_state.is_err()
    {
        let _ = vms.fail(vm);
        return Err(VirtualBlockTransactionRunError::Authority(
            VirtualBlockAuthorityError::GeometryMismatch,
        ));
    }
    if device.pending_interrupt_vector().is_some()
        && interrupt_state == Ok(VirtualBlockPciInterruptState::Enabled)
    {
        inject_virtual_block_interrupt(
            device,
            memory,
            vms,
            vm,
            vcpu,
            interrupt_policy,
            capabilities,
            interrupt_capability,
            interrupt_object,
        )
        .map_err(|error| {
            let _ = vms.fail(vm);
            VirtualBlockTransactionRunError::Interrupt(error)
        })?;
    }

    let disposition = run_vm_once_for_mmio(
        memory,
        vcpu,
        vms,
        vm,
        router,
        capabilities,
        guest_memory,
        io_policy,
    )
    .map_err(VirtualBlockTransactionRunError::Exit)?;
    let ExitDisposition::Mmio {
        guest_address,
        size,
        write: true,
        value,
    } = disposition
    else {
        let _ = vms.fail(vm);
        return Err(VirtualBlockTransactionRunError::InvalidExit);
    };

    let window = attachment
        .validate_mmio_window(device, bridge)
        .map_err(|_| {
            let _ = vms.fail(vm);
            VirtualBlockTransactionRunError::InvalidExit
        })?;
    let doorbell_address = exact_mmio_register(window, VIRTUAL_BLOCK_MMIO_DOORBELL_OFFSET)
        .map_err(|_| VirtualBlockTransactionRunError::InvalidExit)?;
    let acknowledgement_address =
        exact_mmio_register(window, VIRTUAL_BLOCK_MMIO_COMPLETION_ACK_OFFSET)
            .map_err(|_| VirtualBlockTransactionRunError::InvalidExit)?;

    let outcome = if guest_address == doorbell_address
        && size == 4
        && value == u64::from(VIRTUAL_BLOCK_DOORBELL_VALUE)
    {
        let mut selected_backend = CapabilitySelectedVirtualBlockBackend::new(
            block_backend,
            capabilities,
            block_authority,
            device.block_size(),
        );
        let processed = process_virtual_block_mmio_doorbell(
            disposition,
            attachment,
            device,
            bridge,
            memory,
            &mut selected_backend,
            scratch,
        )
        .map_err(|error| {
            let _ = vms.fail(vm);
            VirtualBlockTransactionRunError::Doorbell(error)
        })?;
        VirtualBlockTransactionOutcome::Doorbell(processed)
    } else if guest_address == acknowledgement_address
        && size == 4
        && value == u64::from(VIRTUAL_BLOCK_COMPLETION_ACK_VALUE)
    {
        let consumed = process_virtual_block_mmio_completion_ack(
            disposition,
            attachment,
            device,
            bridge,
            memory,
        )
        .map_err(|error| {
            let _ = vms.fail(vm);
            VirtualBlockTransactionRunError::Acknowledgement(error)
        })?;
        VirtualBlockTransactionOutcome::CompletionAcknowledged(consumed)
    } else {
        let _ = vms.fail(vm);
        return Err(VirtualBlockTransactionRunError::InvalidExit);
    };

    memory
        .complete_mmio_write(vcpu, guest_address, size, value)
        .map_err(|error| {
            bridge.fail_stop();
            let _ = device.fail();
            let _ = vms.fail(vm);
            VirtualBlockTransactionRunError::Completion(error)
        })?;
    if matches!(
        &outcome,
        VirtualBlockTransactionOutcome::Doorbell(VirtualBlockProcessOutcome::Completed(_))
    ) && interrupt_state == Ok(VirtualBlockPciInterruptState::Enabled)
    {
        inject_virtual_block_interrupt(
            device,
            memory,
            vms,
            vm,
            vcpu,
            interrupt_policy,
            capabilities,
            interrupt_capability,
            interrupt_object,
        )
        .map_err(|error| {
            let _ = vms.fail(vm);
            VirtualBlockTransactionRunError::Interrupt(error)
        })?;
    }
    Ok(outcome)
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

fn slot_index(position: u64, slots: usize) -> Result<usize, VirtualBlockError> {
    if position == 0 || slots == 0 || slots > MAX_VIRTUAL_BLOCK_QUEUE_SLOTS {
        return Err(VirtualBlockError::InvalidQueue);
    }
    Ok(((position - 1) % slots as u64) as usize)
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

    fn active_mmio<const N: usize>() -> VirtualBlockDevice<N> {
        let mut device = VirtualBlockDevice::new_with_transport(
            4096,
            64,
            VIRTUAL_BLOCK_FEATURE_FLUSH,
            VirtualBlockTransport::MrmlSpecificPciMmio,
        )
        .unwrap();
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
    fn active_configuration_round_trips_exact_mechanics_without_authority() {
        let device = active::<2>();
        let configuration = device.configuration().unwrap();
        assert_eq!(configuration.generation(), 1);
        assert_eq!(configuration.block_size(), 4096);
        assert_eq!(configuration.block_count(), 64);
        assert_eq!(
            configuration.supported_features(),
            VIRTUAL_BLOCK_FEATURE_FLUSH
        );
        assert_eq!(
            configuration.negotiated_features(),
            VIRTUAL_BLOCK_FEATURE_FLUSH
        );
        assert_eq!(configuration.queue(), layout::<2>());
        assert_eq!(configuration.interrupt_vector(), 48);
        assert_eq!(
            configuration.transport(),
            VirtualBlockTransport::MrmlSpecificScalarIo
        );
        assert_eq!(
            configuration.transport().doorbell_port(),
            Some(VIRTUAL_BLOCK_DOORBELL_PORT)
        );
        assert_eq!(
            configuration.transport().completion_acknowledgement_port(),
            Some(VIRTUAL_BLOCK_COMPLETION_ACK_PORT)
        );
        let transport_policy = configuration.transport().io_policy().unwrap();
        assert!(transport_policy.permits(VIRTUAL_BLOCK_DOORBELL_PORT, 4, true));
        assert!(transport_policy.permits(VIRTUAL_BLOCK_COMPLETION_ACK_PORT, 4, true));
        assert!(!transport_policy.permits(VIRTUAL_BLOCK_DOORBELL_PORT, 4, false));
        assert!(!transport_policy.permits(VIRTUAL_BLOCK_DOORBELL_PORT, 2, true));
        assert!(!transport_policy.permits(VIRTUAL_BLOCK_DOORBELL_PORT + 2, 4, true));

        let mut encoded = [0xa5; VIRTUAL_BLOCK_CONFIGURATION_BYTES];
        configuration.encode(&mut encoded);
        assert_eq!(
            VirtualBlockConfiguration::decode(&encoded),
            Ok(configuration)
        );
        assert!(encoded[80..].iter().all(|byte| *byte == 0));
        assert_eq!(device.validate_configuration(configuration), Ok(()));
    }

    #[test]
    fn pci_mmio_configuration_is_canonical_and_grants_no_scalar_ports() {
        let configuration = active_mmio::<2>().configuration().unwrap();
        assert_eq!(
            configuration.transport(),
            VirtualBlockTransport::MrmlSpecificPciMmio
        );
        assert_eq!(configuration.transport().doorbell_port(), None);
        assert_eq!(
            configuration.transport().completion_acknowledgement_port(),
            None
        );
        assert_eq!(
            configuration.transport().doorbell_mmio_offset(),
            Some(VIRTUAL_BLOCK_MMIO_DOORBELL_OFFSET)
        );
        assert_eq!(
            configuration
                .transport()
                .completion_acknowledgement_mmio_offset(),
            Some(VIRTUAL_BLOCK_MMIO_COMPLETION_ACK_OFFSET)
        );
        let policy = configuration.transport().io_policy().unwrap();
        assert!(!policy.permits(VIRTUAL_BLOCK_DOORBELL_PORT, 4, true));
        assert!(!policy.permits(VIRTUAL_BLOCK_COMPLETION_ACK_PORT, 4, true));

        let mut encoded = [0xa5; VIRTUAL_BLOCK_CONFIGURATION_BYTES];
        configuration.encode(&mut encoded);
        assert_eq!(encoded[67], 1);
        assert_eq!(
            u16::from_le_bytes(encoded[68..70].try_into().unwrap()),
            VIRTUAL_BLOCK_MMIO_DOORBELL_OFFSET as u16
        );
        assert_eq!(
            u16::from_le_bytes(encoded[70..72].try_into().unwrap()),
            VIRTUAL_BLOCK_MMIO_COMPLETION_ACK_OFFSET as u16
        );
        assert_eq!(
            VirtualBlockConfiguration::decode(&encoded),
            Ok(configuration)
        );

        encoded[67] = 2;
        assert_eq!(
            VirtualBlockConfiguration::decode(&encoded),
            Err(VirtualBlockError::InvalidConfiguration)
        );
    }

    #[test]
    fn configuration_decode_rejects_every_noncanonical_boundary_class() {
        let configuration = active::<2>().configuration().unwrap();
        let mut canonical = [0; VIRTUAL_BLOCK_CONFIGURATION_BYTES];
        configuration.encode(&mut canonical);
        assert_eq!(
            VirtualBlockConfiguration::decode(&canonical[..127]),
            Err(VirtualBlockError::InvalidConfiguration)
        );

        let mutations: [fn(&mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]); 21] = [
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[0] ^= 1,
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[4] += 1,
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[5] += 1,
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[6] = 1,
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[8..12].fill(0),
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[12..16].fill(0),
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[16..24].fill(0),
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[24..32].fill(2),
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[24..32].fill(0),
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[40] |= 1,
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| {
                let request_base: [u8; 8] = bytes[40..48].try_into().unwrap();
                bytes[48..56].copy_from_slice(&request_base);
            },
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[56..64].fill(0),
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[64..66].fill(0),
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[66] = 31,
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[67] = 1,
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[68] ^= 1,
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[70] ^= 1,
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[72] ^= 1,
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[76] ^= 1,
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[78] ^= 1,
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[127] = 1,
        ];
        for mutate in mutations {
            let mut corrupted = canonical;
            mutate(&mut corrupted);
            assert_eq!(
                VirtualBlockConfiguration::decode(&corrupted),
                Err(VirtualBlockError::InvalidConfiguration)
            );
        }
    }

    #[test]
    fn configuration_requires_exact_live_binding_and_reset_stales_snapshot() {
        let mut device = active::<1>();
        let configuration = device.configuration().unwrap();
        let mut encoded = [0; VIRTUAL_BLOCK_CONFIGURATION_BYTES];
        configuration.encode(&mut encoded);
        encoded[32..40].fill(0);
        let altered = VirtualBlockConfiguration::decode(&encoded).unwrap();
        assert_eq!(
            device.validate_configuration(altered),
            Err(VirtualBlockError::InvalidConfiguration)
        );
        assert_eq!(device.suspend(), Ok(()));
        assert_eq!(
            device.validate_configuration(configuration),
            Err(VirtualBlockError::InvalidState)
        );
        device.resume().unwrap();
        device.reset().unwrap();
        assert_eq!(
            device.validate_configuration(configuration),
            Err(VirtualBlockError::StaleGeneration)
        );
    }

    #[test]
    fn configuration_page_is_exact_zero_padded_and_queue_disjoint() {
        let configuration = active::<1>().configuration().unwrap();
        let page = VirtualBlockConfigurationPage::new(0x30_0000, configuration).unwrap();
        assert_eq!(page.base(), 0x30_0000);
        assert_eq!(page.configuration(), configuration);
        let mut encoded = [0xa5; PAGE_SIZE as usize];
        page.encode_page(&mut encoded);
        assert_eq!(
            VirtualBlockConfiguration::decode(&encoded[..VIRTUAL_BLOCK_CONFIGURATION_BYTES]),
            Ok(configuration)
        );
        assert!(
            encoded[VIRTUAL_BLOCK_CONFIGURATION_BYTES..]
                .iter()
                .all(|byte| *byte == 0)
        );
        for invalid in [
            0,
            0x30_0001,
            configuration.queue().request_base(),
            configuration.queue().completion_base(),
            !(PAGE_SIZE - 1),
        ] {
            assert_eq!(
                VirtualBlockConfigurationPage::new(invalid, configuration),
                Err(VirtualBlockError::InvalidConfiguration)
            );
        }
    }

    #[test]
    fn resume_page_is_exact_zero_padded_and_disjoint_from_configuration_and_queues() {
        let configuration = active::<1>().configuration().unwrap();
        let configuration_page =
            VirtualBlockConfigurationPage::new(0x30_0000, configuration).unwrap();
        let page = VirtualBlockResumePage::fresh(0x31_0000, configuration_page).unwrap();
        assert_eq!(page.base(), 0x31_0000);
        assert_eq!(page.configuration_base(), configuration_page.base());
        assert_eq!(page.state().configuration(), configuration);
        let mut encoded = [0xa5; PAGE_SIZE as usize];
        page.encode_page(&mut encoded);
        assert_eq!(
            VirtualBlockResumeState::decode(&encoded[..VIRTUAL_BLOCK_RESUME_STATE_BYTES]),
            Ok(page.state())
        );
        assert!(
            encoded[VIRTUAL_BLOCK_RESUME_STATE_BYTES..]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(
            VirtualBlockResumePage::decode_page(&encoded),
            Ok(page.state())
        );
        encoded[VIRTUAL_BLOCK_RESUME_STATE_BYTES] = 1;
        assert_eq!(
            VirtualBlockResumePage::decode_page(&encoded),
            Err(VirtualBlockError::InvalidConfiguration)
        );
        assert_eq!(
            VirtualBlockResumePage::decode_page(&encoded[..PAGE_SIZE as usize - 1]),
            Err(VirtualBlockError::InvalidConfiguration)
        );

        for invalid in [
            0,
            0x31_0001,
            configuration_page.base(),
            configuration.queue().request_base(),
            configuration.queue().completion_base(),
            !(PAGE_SIZE - 1),
        ] {
            assert_eq!(
                VirtualBlockResumePage::fresh(invalid, configuration_page),
                Err(VirtualBlockError::InvalidConfiguration)
            );
        }
    }

    fn discovered_driver<const N: usize>(
        device: &VirtualBlockDevice<N>,
    ) -> VirtualBlockGuestDriver {
        let mut encoded = [0; VIRTUAL_BLOCK_CONFIGURATION_BYTES];
        device.configuration().unwrap().encode(&mut encoded);
        VirtualBlockGuestDriver::discover(&encoded, 0, 0, 0, 0).unwrap()
    }

    fn completion_bytes(
        generation: u32,
        request_id: u64,
        status: VirtualBlockCompletionStatus,
        transferred: u32,
    ) -> [u8; VIRTUAL_BLOCK_COMPLETION_BYTES] {
        let mut encoded = [0; VIRTUAL_BLOCK_COMPLETION_BYTES];
        VirtualBlockCompletion {
            generation,
            request_id,
            status,
            transferred,
        }
        .encode(&mut encoded);
        encoded
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum GuestQueueTransportError {
        Injected,
    }

    struct MockGuestQueueTransport {
        published_request: Option<(
            u64,
            [u8; VIRTUAL_BLOCK_REQUEST_BYTES],
            u64,
            u64,
            VirtualBlockGuestNotification,
        )>,
        completion_published: u64,
        completion: [u8; VIRTUAL_BLOCK_COMPLETION_BYTES],
        completion_read: Option<(u64, u64)>,
        acknowledgement: Option<(u64, u64, VirtualBlockGuestNotification)>,
        fail_publish: bool,
        fail_read: bool,
        fail_acknowledge: bool,
    }

    impl MockGuestQueueTransport {
        fn new() -> Self {
            Self {
                published_request: None,
                completion_published: 0,
                completion: [0; VIRTUAL_BLOCK_COMPLETION_BYTES],
                completion_read: None,
                acknowledgement: None,
                fail_publish: false,
                fail_read: false,
                fail_acknowledge: false,
            }
        }
    }

    unsafe impl VirtualBlockGuestQueueTransport for MockGuestQueueTransport {
        type Error = GuestQueueTransportError;

        fn publish_request_and_notify(
            &mut self,
            request_address: u64,
            request: &[u8; VIRTUAL_BLOCK_REQUEST_BYTES],
            producer_address: u64,
            producer: u64,
            notification: VirtualBlockGuestNotification,
        ) -> Result<(), Self::Error> {
            if self.fail_publish {
                return Err(GuestQueueTransportError::Injected);
            }
            self.published_request = Some((
                request_address,
                *request,
                producer_address,
                producer,
                notification,
            ));
            Ok(())
        }

        fn read_completion(
            &mut self,
            published_address: u64,
            completion_address: u64,
            published: &mut u64,
            completion: &mut [u8; VIRTUAL_BLOCK_COMPLETION_BYTES],
        ) -> Result<(), Self::Error> {
            if self.fail_read {
                return Err(GuestQueueTransportError::Injected);
            }
            self.completion_read = Some((published_address, completion_address));
            *published = self.completion_published;
            completion.copy_from_slice(&self.completion);
            Ok(())
        }

        fn acknowledge_completion(
            &mut self,
            consumer_address: u64,
            consumer: u64,
            notification: VirtualBlockGuestNotification,
        ) -> Result<(), Self::Error> {
            if self.fail_acknowledge {
                return Err(GuestQueueTransportError::Injected);
            }
            self.acknowledgement = Some((consumer_address, consumer, notification));
            Ok(())
        }
    }

    #[test]
    fn guest_driver_discovery_requires_one_exact_idle_queue_snapshot() {
        let configuration = active::<2>().configuration().unwrap();
        let mut encoded = [0; VIRTUAL_BLOCK_CONFIGURATION_BYTES];
        configuration.encode(&mut encoded);
        let driver = VirtualBlockGuestDriver::discover(&encoded, 0, 0, 0, 0).unwrap();
        assert_eq!(driver.configuration(), configuration);
        assert_eq!(driver.request_producer(), 0);
        assert_eq!(driver.completion_consumer(), 0);
        assert!(!driver.has_pending());
        assert!(!driver.is_terminal());

        for counters in [(1, 0, 0, 0), (1, 1, 0, 0), (1, 1, 1, 0), (1, 1, 1, 1)] {
            assert_eq!(
                VirtualBlockGuestDriver::discover(
                    &encoded, counters.0, counters.1, counters.2, counters.3,
                ),
                Err(VirtualBlockError::InvalidQueue)
            );
        }
        encoded[0] ^= 1;
        assert_eq!(
            VirtualBlockGuestDriver::discover(&encoded, 0, 0, 0, 0),
            Err(VirtualBlockError::InvalidConfiguration)
        );
    }

    #[test]
    fn guest_driver_reconstructs_exact_nonzero_pending_history() {
        let configuration = active::<2>().configuration().unwrap();
        let state = VirtualBlockResumeState {
            configuration,
            request_producer: 5,
            request_consumed: 4,
            completion_published: 4,
            completion_consumer: 3,
            last_admitted_request_id: 40,
            last_published_request_id: 50,
        };
        let mut encoded_state = [0; VIRTUAL_BLOCK_RESUME_STATE_BYTES];
        state.encode(&mut encoded_state);
        assert_eq!(VirtualBlockResumeState::decode(&encoded_state), Ok(state));

        let mut requests = [[0; VIRTUAL_BLOCK_REQUEST_BYTES]; 2];
        VirtualBlockRequest::read(1, 40, 0, 1, 0x80_0000, 4096).encode(&mut requests[1]);
        VirtualBlockRequest::write(1, 50, 1, 1, 0x81_0000, 4096).encode(&mut requests[0]);
        let mut driver = VirtualBlockGuestDriver::reconstruct(&encoded_state, &requests).unwrap();
        let configuration_page =
            VirtualBlockConfigurationPage::new(0x30_0000, configuration).unwrap();
        let page = VirtualBlockResumePage::new(0x31_0000, configuration_page, state).unwrap();
        let mut encoded_page = [0; PAGE_SIZE as usize];
        page.encode_page(&mut encoded_page);
        assert_eq!(
            VirtualBlockGuestDriver::reconstruct_from_page(&encoded_page, &requests),
            Ok(driver.clone())
        );
        let mut encoded_configuration = [0; VIRTUAL_BLOCK_CONFIGURATION_BYTES];
        configuration.encode(&mut encoded_configuration);
        assert_eq!(
            VirtualBlockGuestDriver::resume_from_page(
                &encoded_configuration,
                &encoded_page,
                &requests,
                5,
                4,
                4,
                3,
            ),
            Ok(driver.clone())
        );
        for counters in [(6, 4, 4, 3), (5, 5, 4, 3), (5, 4, 5, 3), (5, 4, 4, 4)] {
            assert_eq!(
                VirtualBlockGuestDriver::resume_from_page(
                    &encoded_configuration,
                    &encoded_page,
                    &requests,
                    counters.0,
                    counters.1,
                    counters.2,
                    counters.3,
                ),
                Err(VirtualBlockError::InvalidQueue)
            );
        }
        encoded_configuration[16] ^= 1;
        assert!(
            VirtualBlockGuestDriver::resume_from_page(
                &encoded_configuration,
                &encoded_page,
                &requests,
                5,
                4,
                4,
                3,
            )
            .is_err()
        );
        assert_eq!(driver.configuration(), configuration);
        assert_eq!(driver.request_producer(), 5);
        assert_eq!(driver.completion_consumer(), 3);
        assert_eq!(driver.pending_count(), 2);
        assert_eq!(
            driver.prepare_read(0, 1, 0x90_0000, 4096),
            Err(VirtualBlockError::QueueFull)
        );

        let completion = completion_bytes(1, 40, VirtualBlockCompletionStatus::Ok, 4096);
        driver.accept_completion(4, &completion).unwrap();
        let next = driver.prepare_read(0, 1, 0x90_0000, 4096).unwrap();
        assert_eq!(next.producer(), 6);
        assert_eq!(next.slot(), 1);
        assert_eq!(next.request().request_id(), 51);
    }

    #[test]
    fn guest_driver_reconstructs_nonzero_idle_history_without_reusing_ids() {
        let configuration = active::<2>().configuration().unwrap();
        let state = VirtualBlockResumeState {
            configuration,
            request_producer: 5,
            request_consumed: 5,
            completion_published: 5,
            completion_consumer: 5,
            last_admitted_request_id: 50,
            last_published_request_id: 50,
        };
        let mut encoded_state = [0; VIRTUAL_BLOCK_RESUME_STATE_BYTES];
        state.encode(&mut encoded_state);
        let mut requests = [[0; VIRTUAL_BLOCK_REQUEST_BYTES]; 2];
        VirtualBlockRequest::write(1, 50, 1, 1, 0x81_0000, 4096).encode(&mut requests[0]);
        let driver = VirtualBlockGuestDriver::reconstruct(&encoded_state, &requests).unwrap();
        assert!(!driver.has_pending());
        let next = driver.prepare_read(0, 1, 0x90_0000, 4096).unwrap();
        assert_eq!(next.request().request_id(), 51);
        assert_eq!(next.producer(), 6);

        let configuration_page =
            VirtualBlockConfigurationPage::new(0x30_0000, configuration).unwrap();
        let page = VirtualBlockResumePage::new(0x31_0000, configuration_page, state).unwrap();
        let mut encoded_page = [0; PAGE_SIZE as usize];
        page.encode_page(&mut encoded_page);
        let reconstructed =
            VirtualBlockGuestDriver::reconstruct_from_page(&encoded_page, &requests).unwrap();
        assert_eq!(reconstructed, driver);

        let exhausted = VirtualBlockResumeState {
            request_producer: u64::MAX,
            request_consumed: u64::MAX,
            completion_published: u64::MAX,
            completion_consumer: u64::MAX,
            last_admitted_request_id: u64::MAX,
            last_published_request_id: u64::MAX,
            ..state
        };
        exhausted.encode(&mut encoded_state);
        VirtualBlockRequest::read(1, u64::MAX, 0, 1, 0x80_0000, 4096).encode(&mut requests[0]);
        let exhausted_driver =
            VirtualBlockGuestDriver::reconstruct(&encoded_state, &requests).unwrap();
        assert_eq!(
            exhausted_driver.terminal_reason(),
            Some(VirtualBlockGuestTerminalReason::SequenceExhausted)
        );
    }

    #[test]
    fn guest_driver_reconstruction_rejects_counter_slot_and_history_substitution() {
        let configuration = active::<2>().configuration().unwrap();
        let canonical = VirtualBlockResumeState {
            configuration,
            request_producer: 5,
            request_consumed: 4,
            completion_published: 4,
            completion_consumer: 3,
            last_admitted_request_id: 40,
            last_published_request_id: 50,
        };
        let mut requests = [[0; VIRTUAL_BLOCK_REQUEST_BYTES]; 2];
        VirtualBlockRequest::read(1, 40, 0, 1, 0x80_0000, 4096).encode(&mut requests[1]);
        VirtualBlockRequest::write(1, 50, 1, 1, 0x81_0000, 4096).encode(&mut requests[0]);

        for invalid in [
            VirtualBlockResumeState {
                completion_published: 3,
                ..canonical
            },
            VirtualBlockResumeState {
                completion_consumer: 2,
                ..canonical
            },
            VirtualBlockResumeState {
                last_admitted_request_id: 41,
                ..canonical
            },
            VirtualBlockResumeState {
                last_published_request_id: 49,
                ..canonical
            },
        ] {
            let mut encoded = [0; VIRTUAL_BLOCK_RESUME_STATE_BYTES];
            invalid.encode(&mut encoded);
            assert!(VirtualBlockGuestDriver::reconstruct(&encoded, &requests).is_err());
        }

        let mut encoded = [0; VIRTUAL_BLOCK_RESUME_STATE_BYTES];
        canonical.encode(&mut encoded);
        assert_eq!(
            VirtualBlockGuestDriver::reconstruct(&encoded, &requests[..1]),
            Err(VirtualBlockError::InvalidQueue)
        );
        let mut replay = requests;
        VirtualBlockRequest::write(1, 40, 1, 1, 0x81_0000, 4096).encode(&mut replay[0]);
        assert_eq!(
            VirtualBlockGuestDriver::reconstruct(&encoded, &replay),
            Err(VirtualBlockError::Replay)
        );
        let mut stale = requests;
        VirtualBlockRequest::write(2, 50, 1, 1, 0x81_0000, 4096).encode(&mut stale[0]);
        assert_eq!(
            VirtualBlockGuestDriver::reconstruct(&encoded, &stale),
            Err(VirtualBlockError::StaleGeneration)
        );
        let mut hidden = encoded;
        hidden[191] = 1;
        assert_eq!(
            VirtualBlockGuestDriver::reconstruct(&hidden, &requests),
            Err(VirtualBlockError::InvalidConfiguration)
        );
    }

    #[test]
    fn guest_driver_submission_and_completion_are_exact_two_phase_state() {
        let device = active::<2>();
        let mut driver = discovered_driver(&device);
        let first = driver.prepare_write(0, 1, 0x80_0000, 4096).unwrap();
        assert_eq!(first.producer(), 1);
        assert_eq!(first.slot(), 0);
        assert_eq!(first.request().generation(), 1);
        assert_eq!(first.request().request_id(), 1);
        assert_eq!(driver.request_producer(), 0);
        assert!(!driver.has_pending());
        let mut request = [0; VIRTUAL_BLOCK_REQUEST_BYTES];
        first.request().encode(&mut request);
        assert_eq!(VirtualBlockRequest::decode(&request), Ok(first.request()));

        driver.commit_submission(first).unwrap();
        assert_eq!(driver.request_producer(), 1);
        assert!(driver.has_pending());
        assert_eq!(driver.pending_count(), 1);
        let second = driver.prepare_read(0, 1, 0x80_0000, 4096).unwrap();
        assert_eq!(second.producer(), 2);
        assert_eq!(second.slot(), 1);
        assert_eq!(second.request().request_id(), 2);
        driver.commit_submission(second).unwrap();
        assert_eq!(driver.pending_count(), 2);
        assert_eq!(
            driver.prepare_read(0, 1, 0x80_0000, 4096),
            Err(VirtualBlockError::QueueFull)
        );
        assert_eq!(
            driver.commit_submission(first),
            Err(VirtualBlockError::QueueFull)
        );

        let second_completion = completion_bytes(1, 2, VirtualBlockCompletionStatus::Ok, 4096);
        assert_eq!(
            driver.accept_completion(1, &second_completion),
            Err(VirtualBlockError::InvalidCompletion)
        );
        assert!(driver.has_pending());
        assert_eq!(driver.pending_count(), 2);
        assert_eq!(driver.completion_consumer(), 0);
        let completed = completion_bytes(1, 1, VirtualBlockCompletionStatus::Ok, 4096);
        assert_eq!(
            driver.accept_completion(0, &completed),
            Err(VirtualBlockError::InvalidCompletion)
        );
        let completion_ticket = driver.prepare_completion(1, &completed).unwrap();
        assert_eq!(completion_ticket.status(), VirtualBlockCompletionStatus::Ok);
        assert_eq!(completion_ticket.transferred(), 4096);
        assert_eq!(completion_ticket.acknowledgement(), 1);
        assert_eq!(driver.completion_consumer(), 0);
        assert_eq!(driver.pending_count(), 2);
        let outcome = driver.commit_completion(completion_ticket).unwrap();
        assert_eq!(outcome.status(), VirtualBlockCompletionStatus::Ok);
        assert_eq!(outcome.transferred(), 4096);
        assert_eq!(outcome.acknowledgement(), 1);
        assert!(driver.has_pending());
        assert_eq!(driver.pending_count(), 1);
        assert_eq!(
            driver.commit_completion(completion_ticket),
            Err(VirtualBlockError::StaleTicket)
        );
        assert_eq!(driver.pending_count(), 1);

        let third = driver.prepare_read(0, 1, 0x80_0000, 4096).unwrap();
        assert_eq!(third.producer(), 3);
        assert_eq!(third.slot(), 0);
        assert_eq!(third.request().request_id(), 3);
        assert_eq!(
            driver.commit_submission(first),
            Err(VirtualBlockError::StaleTicket)
        );
        driver.commit_submission(third).unwrap();
        assert_eq!(driver.pending_count(), 2);
        driver.accept_completion(2, &second_completion).unwrap();
        let third_completion = completion_bytes(1, 3, VirtualBlockCompletionStatus::Ok, 4096);
        driver.accept_completion(3, &third_completion).unwrap();
        assert!(!driver.has_pending());

        let fourth = driver.prepare_write(0, 1, 0x80_0000, 4096).unwrap();
        driver.commit_submission(fourth).unwrap();
        let fifth = driver.prepare_read(0, 1, 0x80_0000, 4096).unwrap();
        driver.commit_submission(fifth).unwrap();
        assert_eq!(driver.pending_count(), 2);
        let reset = completion_bytes(1, 4, VirtualBlockCompletionStatus::Reset, 0);
        let reset_ticket = driver.prepare_completion(4, &reset).unwrap();
        assert_eq!(driver.pending_count(), 2);
        assert_eq!(driver.terminal_reason(), None);
        driver.commit_completion(reset_ticket).unwrap();
        assert_eq!(
            driver.terminal_reason(),
            Some(VirtualBlockGuestTerminalReason::Reset)
        );
        assert_eq!(driver.pending_count(), 0);
        let invalidated = completion_bytes(1, 5, VirtualBlockCompletionStatus::Ok, 4096);
        assert_eq!(
            driver.accept_completion(5, &invalidated),
            Err(VirtualBlockError::InvalidState)
        );
    }

    #[test]
    fn guest_driver_queue_transport_is_exact_and_transactional() {
        let device = active::<2>();
        let mut driver = discovered_driver(&device);
        let submission = driver.prepare_write(0, 1, 0x80_0000, 4096).unwrap();
        let mut transport = MockGuestQueueTransport::new();

        transport.fail_publish = true;
        assert_eq!(
            driver.publish_submission(&mut transport, submission),
            Err(VirtualBlockGuestQueueTransportError::Transport(
                GuestQueueTransportError::Injected
            ))
        );
        assert_eq!(driver.request_producer(), 0);
        assert_eq!(driver.pending_count(), 0);
        assert_eq!(transport.published_request, None);
        transport.fail_publish = false;
        driver
            .publish_submission(&mut transport, submission)
            .unwrap();
        let (request_address, encoded_request, producer_address, producer, notification) =
            transport.published_request.unwrap();
        assert_eq!(
            request_address,
            layout::<2>().request_base() + QUEUE_HEADER_BYTES
        );
        assert_eq!(producer_address, layout::<2>().request_base());
        assert_eq!(producer, 1);
        assert_eq!(
            notification,
            VirtualBlockGuestNotification::ScalarIo {
                port: VIRTUAL_BLOCK_DOORBELL_PORT,
                value: VIRTUAL_BLOCK_DOORBELL_VALUE,
            }
        );
        assert_eq!(
            VirtualBlockRequest::decode(&encoded_request),
            Ok(submission.request())
        );
        assert_eq!(driver.request_producer(), 1);
        assert_eq!(driver.pending_count(), 1);

        let second = driver.prepare_read(1, 1, 0x81_0000, 4096).unwrap();
        driver.publish_submission(&mut transport, second).unwrap();
        assert_eq!(driver.request_producer(), 2);
        assert_eq!(driver.pending_count(), 2);

        transport.completion_published = 2;
        transport.completion = completion_bytes(1, 1, VirtualBlockCompletionStatus::Ok, 4096);
        transport.fail_read = true;
        assert_eq!(
            driver.prepare_completion_from_transport(&mut transport),
            Err(VirtualBlockGuestQueueTransportError::Transport(
                GuestQueueTransportError::Injected
            ))
        );
        assert_eq!(driver.completion_consumer(), 0);
        assert_eq!(driver.pending_count(), 2);
        transport.fail_read = false;
        let ticket = driver
            .prepare_completion_from_transport(&mut transport)
            .unwrap();
        assert_eq!(
            transport.completion_read,
            Some((
                layout::<2>().completion_base(),
                layout::<2>().completion_base() + QUEUE_HEADER_BYTES,
            ))
        );
        assert_eq!(ticket.acknowledgement(), 1);
        assert_eq!(driver.completion_consumer(), 0);

        transport.fail_acknowledge = true;
        assert_eq!(
            driver.acknowledge_completion_with_transport(&mut transport, ticket),
            Err(VirtualBlockGuestQueueTransportError::Transport(
                GuestQueueTransportError::Injected
            ))
        );
        assert_eq!(driver.completion_consumer(), 0);
        assert_eq!(driver.pending_count(), 2);
        transport.fail_acknowledge = false;
        let outcome = driver
            .acknowledge_completion_with_transport(&mut transport, ticket)
            .unwrap();
        assert_eq!(outcome.status(), VirtualBlockCompletionStatus::Ok);
        assert_eq!(
            transport.acknowledgement,
            Some((
                layout::<2>().completion_base() + 64,
                1,
                VirtualBlockGuestNotification::ScalarIo {
                    port: VIRTUAL_BLOCK_COMPLETION_ACK_PORT,
                    value: VIRTUAL_BLOCK_COMPLETION_ACK_VALUE,
                },
            ))
        );
        assert_eq!(driver.completion_consumer(), 1);
        assert_eq!(driver.pending_count(), 1);

        transport.acknowledgement = None;
        assert_eq!(
            driver.acknowledge_completion_with_transport(&mut transport, ticket),
            Err(VirtualBlockGuestQueueTransportError::Protocol(
                VirtualBlockError::StaleTicket
            ))
        );
        assert_eq!(transport.acknowledgement, None);
    }

    #[test]
    fn guest_driver_maximum_window_is_bounded_and_drains_in_order() {
        let device = active::<MAX_VIRTUAL_BLOCK_QUEUE_SLOTS>();
        let mut driver = discovered_driver(&device);
        for index in 0..MAX_VIRTUAL_BLOCK_QUEUE_SLOTS {
            let submission = driver
                .prepare_read(index as u64, 1, 0x80_0000 + (index as u64 * 4096), 4096)
                .unwrap();
            assert_eq!(submission.slot(), index as u16);
            assert_eq!(submission.request().request_id(), index as u64 + 1);
            driver.commit_submission(submission).unwrap();
        }
        assert_eq!(driver.pending_count(), MAX_VIRTUAL_BLOCK_QUEUE_SLOTS as u16);
        assert_eq!(
            driver.prepare_read(0, 1, 0x90_0000, 4096),
            Err(VirtualBlockError::QueueFull)
        );

        for position in 1..=MAX_VIRTUAL_BLOCK_QUEUE_SLOTS as u64 {
            let completion = completion_bytes(1, position, VirtualBlockCompletionStatus::Ok, 4096);
            driver.accept_completion(position, &completion).unwrap();
            assert_eq!(
                driver.pending_count(),
                (MAX_VIRTUAL_BLOCK_QUEUE_SLOTS as u64 - position) as u16
            );
        }
        assert!(!driver.has_pending());
    }

    #[test]
    fn guest_driver_bounds_features_errors_and_terminal_completions() {
        let mut no_flush =
            VirtualBlockDevice::<1>::new(4096, 2, VIRTUAL_BLOCK_FEATURE_FLUSH).unwrap();
        no_flush.negotiate(0).unwrap();
        no_flush.activate(layout::<1>(), 48).unwrap();
        let mut driver = discovered_driver(&no_flush);
        assert_eq!(
            driver.prepare_flush(),
            Err(VirtualBlockError::InvalidFeatures)
        );
        for result in [
            driver.prepare_read(0, 0, 0x80_0000, 0),
            driver.prepare_read(2, 1, 0x80_0000, 4096),
            driver.prepare_read(0, 1, 0, 4096),
            driver.prepare_read(0, 1, u64::MAX - 1024, 4096),
            driver.prepare_read(0, 1, 0x80_0000, 2048),
        ] {
            assert!(matches!(
                result,
                Err(VirtualBlockError::InvalidRange | VirtualBlockError::InvalidBuffer)
            ));
        }
        let submission = driver.prepare_write(0, 1, 0x80_0000, 4096).unwrap();
        driver.commit_submission(submission).unwrap();
        let reset = completion_bytes(1, 1, VirtualBlockCompletionStatus::Reset, 0);
        let outcome = driver.accept_completion(1, &reset).unwrap();
        assert_eq!(outcome.status(), VirtualBlockCompletionStatus::Reset);
        assert!(driver.is_terminal());
        assert_eq!(
            driver.terminal_reason(),
            Some(VirtualBlockGuestTerminalReason::Reset)
        );
        assert_eq!(
            driver.prepare_write(0, 1, 0x80_0000, 4096),
            Err(VirtualBlockError::InvalidState)
        );

        let reset_state = driver.clone();
        let mut stale_configuration = [0; VIRTUAL_BLOCK_CONFIGURATION_BYTES];
        no_flush
            .configuration()
            .unwrap()
            .encode(&mut stale_configuration);
        assert_eq!(
            driver.rediscover_after_reset(&stale_configuration, 0, 0, 0, 0),
            Err(VirtualBlockError::StaleGeneration)
        );
        assert_eq!(driver, reset_state);

        no_flush.reset().unwrap();
        no_flush.negotiate(0).unwrap();
        no_flush.activate(layout::<1>(), 49).unwrap();
        let replacement = no_flush.configuration().unwrap();
        let mut encoded_replacement = [0; VIRTUAL_BLOCK_CONFIGURATION_BYTES];
        replacement.encode(&mut encoded_replacement);
        let mut skipped_generation = encoded_replacement;
        skipped_generation[8..12].copy_from_slice(&3_u32.to_le_bytes());
        assert_eq!(
            driver.rediscover_after_reset(&skipped_generation, 0, 0, 0, 0),
            Err(VirtualBlockError::StaleGeneration)
        );
        assert_eq!(driver, reset_state);
        for counters in [(1, 0, 0, 0), (0, 1, 0, 0), (0, 0, 1, 0), (0, 0, 0, 1)] {
            assert_eq!(
                driver.rediscover_after_reset(
                    &encoded_replacement,
                    counters.0,
                    counters.1,
                    counters.2,
                    counters.3,
                ),
                Err(VirtualBlockError::InvalidQueue)
            );
            assert_eq!(driver, reset_state);
        }
        let mut corrupt = encoded_replacement;
        corrupt[127] = 1;
        assert_eq!(
            driver.rediscover_after_reset(&corrupt, 0, 0, 0, 0),
            Err(VirtualBlockError::InvalidConfiguration)
        );
        assert_eq!(driver, reset_state);
        driver
            .rediscover_after_reset(&encoded_replacement, 0, 0, 0, 0)
            .unwrap();
        assert_eq!(driver.configuration(), replacement);
        assert_eq!(driver.terminal_reason(), None);
        let rediscovered = driver.prepare_write(0, 1, 0x80_0000, 4096).unwrap();
        assert_eq!(rediscovered.request().generation(), 2);
        assert_eq!(rediscovered.request().request_id(), 1);
        assert_eq!(rediscovered.producer(), 1);

        let configuration = no_flush.configuration().unwrap();
        let mut exhausted = VirtualBlockGuestDriver {
            configuration,
            next_request_id: u64::MAX,
            request_ids_exhausted: false,
            request_producer: u64::MAX - 1,
            completion_consumer: u64::MAX - 1,
            pending: [None; MAX_VIRTUAL_BLOCK_QUEUE_SLOTS],
            pending_count: 0,
            terminal: None,
        };
        let last = exhausted.prepare_write(0, 1, 0x80_0000, 4096).unwrap();
        assert_eq!(last.request().request_id(), u64::MAX);
        assert_eq!(last.producer(), u64::MAX);
        exhausted.commit_submission(last).unwrap();
        assert_eq!(
            exhausted.prepare_write(0, 1, 0x80_0000, 4096),
            Err(VirtualBlockError::SequenceExhausted)
        );
        let completed = completion_bytes(
            configuration.generation(),
            u64::MAX,
            VirtualBlockCompletionStatus::Ok,
            4096,
        );
        exhausted.accept_completion(u64::MAX, &completed).unwrap();
        assert!(exhausted.is_terminal());
        assert_eq!(
            exhausted.terminal_reason(),
            Some(VirtualBlockGuestTerminalReason::SequenceExhausted)
        );
        assert_eq!(
            exhausted.rediscover_after_reset(&encoded_replacement, 0, 0, 0, 0),
            Err(VirtualBlockError::InvalidState)
        );

        let mut removed = discovered_driver(&no_flush);
        let request = removed.prepare_read(0, 1, 0x80_0000, 4096).unwrap();
        removed.commit_submission(request).unwrap();
        let completion = completion_bytes(2, 1, VirtualBlockCompletionStatus::Removed, 0);
        removed.accept_completion(1, &completion).unwrap();
        assert_eq!(
            removed.terminal_reason(),
            Some(VirtualBlockGuestTerminalReason::Removed)
        );
        assert_eq!(
            removed.rediscover_after_reset(&encoded_replacement, 0, 0, 0, 0),
            Err(VirtualBlockError::InvalidState)
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
    fn completion_notification_coalesces_and_terminal_lifecycle_clears_it() {
        let mut device = active::<1>();
        device.latch_completion_interrupt().unwrap();
        device.latch_completion_interrupt().unwrap();
        assert_eq!(device.pending_interrupt_vector(), Some(48));
        assert_eq!(device.suspend(), Err(VirtualBlockError::InvalidState));
        assert_eq!(device.reset(), Ok(0));
        assert_eq!(device.pending_interrupt_vector(), None);

        device.negotiate(0).unwrap();
        device.activate(layout::<1>(), 49).unwrap();
        device.latch_completion_interrupt().unwrap();
        assert_eq!(device.fail(), Ok(0));
        assert_eq!(device.pending_interrupt_vector(), None);
        assert_eq!(
            device.acknowledge_interrupt(49),
            Err(VirtualBlockError::InvalidInterrupt)
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
        next_exit: Option<VmExit>,
        injected: Option<(u32, u8)>,
        fail_inject: bool,
        completed_mmio: Option<(u32, u64, u8, u64)>,
        fail_mmio_completion: bool,
    }

    impl MockVmm {
        fn new() -> Self {
            Self {
                bytes: [0; 0x5000],
                fail_read: false,
                fail_write: false,
                fail_write_address: None,
                next_exit: None,
                injected: None,
                fail_inject: false,
                completed_mmio: None,
                fail_mmio_completion: false,
            }
        }
    }

    impl VmBackend for MockVmm {
        type Error = MockError;

        fn run(&mut self, _: u32) -> Result<VmExit, Self::Error> {
            self.next_exit.take().ok_or(MockError::Injected)
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

        fn inject_interrupt(&mut self, vcpu: u32, vector: u8) -> Result<(), Self::Error> {
            if self.fail_inject {
                return Err(MockError::Injected);
            }
            self.injected = Some((vcpu, vector));
            Ok(())
        }
    }

    impl MmioWriteCompleter for MockVmm {
        fn complete_mmio_write(
            &mut self,
            vcpu: u32,
            guest_address: u64,
            size: u8,
            value: u64,
        ) -> Result<(), Self::Error> {
            if self.fail_mmio_completion || self.completed_mmio.is_some() {
                return Err(MockError::Injected);
            }
            self.completed_mmio = Some((vcpu, guest_address, size, value));
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

    #[test]
    fn live_bridge_resume_state_binds_device_history_and_poison_on_uncertainty() {
        let mut device = active::<2>();
        let queue = layout::<2>();
        let mut bridge = VirtualBlockQueueBridge::<2>::new(queue).unwrap();
        let first = VirtualBlockRequest::read(1, 10, 0, 1, 0x4000, 4096);
        let second = VirtualBlockRequest::write(1, 20, 1, 1, 0x4000, 4096);
        let first_admitted = device.admit(&encoded(first)).unwrap();
        let second_admitted = device.admit(&encoded(second)).unwrap();
        device
            .complete(
                first_admitted.ticket(),
                VirtualBlockCompletionStatus::Ok,
                4096,
            )
            .unwrap();
        device
            .complete(
                second_admitted.ticket(),
                VirtualBlockCompletionStatus::Ok,
                4096,
            )
            .unwrap();
        bridge.request_consumed = 2;
        bridge.completion_published = 2;
        bridge.completion_consumed = 1;

        let mut vmm = MockVmm::new();
        vmm.bytes[queue.request_base() as usize..queue.request_base() as usize + 8]
            .copy_from_slice(&2_u64.to_le_bytes());
        let first_address = queue.request_base() as usize + QUEUE_HEADER_BYTES as usize;
        vmm.bytes[first_address..first_address + VIRTUAL_BLOCK_REQUEST_BYTES]
            .copy_from_slice(&encoded(first));
        let second_address = first_address + VIRTUAL_BLOCK_REQUEST_BYTES;
        vmm.bytes[second_address..second_address + VIRTUAL_BLOCK_REQUEST_BYTES]
            .copy_from_slice(&encoded(second));

        assert_eq!(
            bridge.resume_state(&vmm, &device),
            Err(VirtualBlockQueueError::Protocol(
                VirtualBlockError::InvalidState
            ))
        );
        let active_configuration = device.configuration().unwrap();
        device.suspend().unwrap();
        let state = bridge.resume_state(&vmm, &device).unwrap();
        assert_eq!(state.configuration(), active_configuration);
        assert_eq!(state.request_producer(), 2);
        assert_eq!(state.request_consumed(), 2);
        assert_eq!(state.completion_published(), 2);
        assert_eq!(state.completion_consumer(), 1);
        assert_eq!(state.last_admitted_request_id(), 20);
        assert_eq!(state.last_published_request_id(), 20);

        let mut encoded_state = [0; VIRTUAL_BLOCK_RESUME_STATE_BYTES];
        state.encode(&mut encoded_state);
        let requests = [encoded(first), encoded(second)];
        let driver = VirtualBlockGuestDriver::reconstruct(&encoded_state, &requests).unwrap();
        assert_eq!(driver.pending_count(), 1);
        assert_eq!(driver.completion_consumer(), 1);

        let configuration_page =
            VirtualBlockConfigurationPage::new(0x5000, active_configuration).unwrap();
        let resume_page = VirtualBlockResumePage::fresh(0x4000, configuration_page).unwrap();
        let published = bridge
            .publish_resume_page(&mut vmm, &device, resume_page)
            .unwrap();
        assert_eq!(published.state(), state);
        assert_eq!(
            VirtualBlockResumeState::decode(
                &vmm.bytes[0x4000..0x4000 + VIRTUAL_BLOCK_RESUME_STATE_BYTES]
            ),
            Ok(state)
        );
        assert!(
            vmm.bytes[0x4000 + VIRTUAL_BLOCK_RESUME_STATE_BYTES..0x5000]
                .iter()
                .all(|byte| *byte == 0)
        );
        vmm.fail_write_address = Some(resume_page.base());
        assert_eq!(
            bridge.publish_resume_page(&mut vmm, &device, resume_page),
            Err(VirtualBlockQueueError::Backend(MockError::Injected))
        );
        assert!(bridge.is_poisoned());

        let mut uncertain_bridge = VirtualBlockQueueBridge::<2>::new(queue).unwrap();
        let mut uncertain_vmm = MockVmm::new();
        uncertain_vmm.fail_read = true;
        assert_eq!(
            uncertain_bridge.resume_state(&uncertain_vmm, &device),
            Err(VirtualBlockQueueError::Backend(MockError::Injected))
        );
        assert!(uncertain_bridge.is_poisoned());
    }

    #[test]
    fn restart_image_is_bounded_one_use_and_restores_only_fresh_memory() {
        assert!(core::mem::needs_drop::<VirtualBlockRestartImage>());
        assert!(core::mem::size_of::<VirtualBlockRestartImage>() <= 16 * 1024);
        assert!(core::mem::needs_drop::<VirtualBlockLostExecution>());
        assert!(core::mem::size_of::<VirtualBlockLostExecution>() <= 16 * 1024);
        let mut device = active::<4>();
        let queue = layout::<4>();
        let mut bridge = VirtualBlockQueueBridge::<4>::new(queue).unwrap();
        let first = VirtualBlockRequest::write(1, 10, 0, 1, 0x4000, 4096);
        let second = VirtualBlockRequest::write(1, 20, 1, 1, 0x5000, 4096);
        let first_admitted = device.admit(&encoded(first)).unwrap();
        let second_admitted = device.admit(&encoded(second)).unwrap();
        let first_completion = device
            .complete(
                first_admitted.ticket(),
                VirtualBlockCompletionStatus::Ok,
                4096,
            )
            .unwrap();
        let second_completion = device
            .complete(
                second_admitted.ticket(),
                VirtualBlockCompletionStatus::Ok,
                4096,
            )
            .unwrap();
        bridge.request_consumed = 2;
        bridge.completion_published = 2;

        let mut source = MockVmm::new();
        source.bytes[queue.request_base() as usize..queue.request_base() as usize + 8]
            .copy_from_slice(&2_u64.to_le_bytes());
        source.bytes[queue.request_base() as usize + 64..queue.request_base() as usize + 72]
            .copy_from_slice(&2_u64.to_le_bytes());
        for (position, request) in [(1, first), (2, second)] {
            let address = slot_address(
                queue.request_base(),
                position,
                4,
                VIRTUAL_BLOCK_REQUEST_BYTES,
            )
            .unwrap() as usize;
            source.bytes[address..address + VIRTUAL_BLOCK_REQUEST_BYTES]
                .copy_from_slice(&encoded(request));
        }
        source.bytes[queue.request_base() as usize + 0x800] = 0xa5;
        source.bytes[queue.completion_base() as usize..queue.completion_base() as usize + 8]
            .copy_from_slice(&2_u64.to_le_bytes());
        for (position, completion) in [(1, first_completion), (2, second_completion)] {
            let address = slot_address(
                queue.completion_base(),
                position,
                4,
                VIRTUAL_BLOCK_COMPLETION_BYTES,
            )
            .unwrap() as usize;
            completion.encode(
                (&mut source.bytes[address..address + VIRTUAL_BLOCK_COMPLETION_BYTES])
                    .try_into()
                    .unwrap(),
            );
        }
        source.bytes[queue.completion_base() as usize + 0x800] = 0x5a;

        let configuration = device.configuration().unwrap();
        let configuration_page = VirtualBlockConfigurationPage::new(0x5000, configuration).unwrap();
        let resume_page = VirtualBlockResumePage::fresh(0x4000, configuration_page).unwrap();
        device.suspend().unwrap();
        let published = bridge
            .publish_resume_page(&mut source, &device, resume_page)
            .unwrap();
        let nonfresh_image = bridge
            .capture_restart_image(&source, &device, published)
            .unwrap();
        assert_eq!(nonfresh_image.state(), published.state());
        assert!(
            nonfresh_image.request_slots[2..]
                .iter()
                .flatten()
                .all(|byte| *byte == 0)
        );
        assert!(
            nonfresh_image.completion_slots[2..]
                .iter()
                .flatten()
                .all(|byte| *byte == 0)
        );
        let mut encoded_fresh_resume = [0; PAGE_SIZE as usize];
        resume_page.encode_page(&mut encoded_fresh_resume);

        let mut nonfresh = MockVmm::new();
        nonfresh.bytes[queue.request_base() as usize + 1] = 1;
        // SAFETY: this mock has no runnable native execution context.
        let nonfresh_loss = unsafe { nonfresh_image.confirm_execution_loss() };
        assert_eq!(
            bridge.restore_restart_image(&mut nonfresh, &device, nonfresh_loss),
            Err(VirtualBlockQueueError::Protocol(
                VirtualBlockError::InvalidQueue
            ))
        );
        assert_eq!(
            &nonfresh.bytes[queue.completion_base() as usize..queue.completion_base() as usize + 8],
            &[0; 8]
        );

        let image = bridge
            .capture_restart_image(&source, &device, published)
            .unwrap();
        let mut replacement = MockVmm::new();
        replacement.bytes[0x4000..0x5000].copy_from_slice(&encoded_fresh_resume);
        // SAFETY: this mock has no runnable native execution context.
        let lost = unsafe { image.confirm_execution_loss() };
        bridge
            .restore_restart_image(&mut replacement, &device, lost)
            .unwrap();
        assert_eq!(
            &replacement.bytes[queue.request_base() as usize..queue.request_base() as usize + 8],
            &2_u64.to_le_bytes()
        );
        assert_eq!(
            &replacement.bytes
                [queue.completion_base() as usize..queue.completion_base() as usize + 8],
            &2_u64.to_le_bytes()
        );
        assert_eq!(
            &replacement.bytes[0x4000..0x5000],
            &source.bytes[0x4000..0x5000]
        );
        assert_eq!(replacement.bytes[queue.request_base() as usize + 0x800], 0);
        assert_eq!(
            replacement.bytes[queue.completion_base() as usize + 0x800],
            0
        );

        let second_completion_address = slot_address(
            queue.completion_base(),
            2,
            4,
            VIRTUAL_BLOCK_COMPLETION_BYTES,
        )
        .unwrap() as usize;
        source.bytes[second_completion_address + 16] ^= 1;
        assert!(matches!(
            bridge.capture_restart_image(&source, &device, published),
            Err(VirtualBlockQueueError::Protocol(
                VirtualBlockError::InvalidCompletion
            ))
        ));

        source.bytes[second_completion_address + 16] ^= 1;
        let uncertain_image = bridge
            .capture_restart_image(&source, &device, published)
            .unwrap();
        let mut uncertain = MockVmm::new();
        uncertain.bytes[0x4000..0x5000].copy_from_slice(&encoded_fresh_resume);
        uncertain.fail_write_address =
            Some(slot_address(queue.request_base(), 1, 4, VIRTUAL_BLOCK_REQUEST_BYTES).unwrap());
        // SAFETY: this mock has no runnable native execution context.
        let uncertain_loss = unsafe { uncertain_image.confirm_execution_loss() };
        assert_eq!(
            bridge.restore_restart_image(&mut uncertain, &device, uncertain_loss),
            Err(VirtualBlockQueueError::Backend(MockError::Injected))
        );
        assert!(bridge.is_poisoned());
    }

    #[test]
    fn restart_image_rejects_transport_substitution_before_restoration() {
        let queue = layout::<2>();
        let mut pci = VirtualBlockDevice::<2>::new_with_transport(
            4096,
            64,
            VIRTUAL_BLOCK_FEATURE_FLUSH,
            VirtualBlockTransport::MrmlSpecificPciMmio,
        )
        .unwrap();
        pci.negotiate(VIRTUAL_BLOCK_FEATURE_FLUSH).unwrap();
        pci.activate(queue, 48).unwrap();
        let mut bridge = VirtualBlockQueueBridge::<2>::new(queue).unwrap();
        let mut source = MockVmm::new();
        let pci_configuration = pci.configuration().unwrap();
        let pci_page = VirtualBlockConfigurationPage::new(0x5000, pci_configuration).unwrap();
        let resume_page = VirtualBlockResumePage::fresh(0x4000, pci_page).unwrap();
        pci.suspend().unwrap();
        let published = bridge
            .publish_resume_page(&mut source, &pci, resume_page)
            .unwrap();
        let image = bridge
            .capture_restart_image(&source, &pci, published)
            .unwrap();

        let mut scalar = VirtualBlockDevice::<2>::new_with_transport(
            4096,
            64,
            VIRTUAL_BLOCK_FEATURE_FLUSH,
            VirtualBlockTransport::MrmlSpecificScalarIo,
        )
        .unwrap();
        scalar.negotiate(VIRTUAL_BLOCK_FEATURE_FLUSH).unwrap();
        scalar.activate(queue, 48).unwrap();
        let scalar_configuration = scalar.configuration().unwrap();
        scalar.suspend().unwrap();
        let scalar_page = VirtualBlockConfigurationPage::new(0x5000, scalar_configuration).unwrap();
        let scalar_resume = VirtualBlockResumePage::fresh(0x4000, scalar_page).unwrap();
        let mut encoded_scalar_resume = [0; PAGE_SIZE as usize];
        scalar_resume.encode_page(&mut encoded_scalar_resume);
        let mut replacement = MockVmm::new();
        replacement.bytes[0x4000..0x5000].copy_from_slice(&encoded_scalar_resume);
        // SAFETY: this mock has no runnable native execution context.
        let lost = unsafe { image.confirm_execution_loss() };
        assert_eq!(
            bridge.restore_restart_image(&mut replacement, &scalar, lost),
            Err(VirtualBlockQueueError::Protocol(
                VirtualBlockError::InvalidConfiguration
            ))
        );
        assert_eq!(
            &replacement.bytes
                [queue.request_base() as usize..queue.request_base() as usize + PAGE_SIZE as usize],
            &[0; PAGE_SIZE as usize]
        );
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
    fn capability_selected_backend_enforces_independent_operation_rights() {
        let object = ObjectId(0x300);

        let mut read_space = CapabilitySpace::<1>::new();
        let read_capability = read_space.insert(object, crate::Rights::READ).unwrap();
        let mut read_backend = MockBlock::new();
        read_backend.bytes[..4096].fill(0x5a);
        let mut output = [0; 4096];
        let mut selected = CapabilitySelectedVirtualBlockBackend::new(
            &mut read_backend,
            &read_space,
            VirtualBlockBackendAuthority::new(read_capability, object, 0, 4).unwrap(),
            4096,
        );
        assert_eq!(selected.read_blocks(0, &mut output), Ok(()));
        assert!(output.iter().all(|byte| *byte == 0x5a));
        assert!(matches!(
            selected.write_blocks(0, &[0x65; 4096]),
            Err(VirtualBlockMutationError::Rejected(
                VirtualBlockCapabilityError::Capability(CapabilityError::PermissionDenied)
            ))
        ));
        assert!(matches!(
            selected.flush(),
            Err(VirtualBlockMutationError::Rejected(
                VirtualBlockCapabilityError::Capability(CapabilityError::PermissionDenied)
            ))
        ));
        assert_eq!(
            (
                read_backend.reads,
                read_backend.writes,
                read_backend.flushes
            ),
            (1, 0, 0)
        );

        let mut write_space = CapabilitySpace::<1>::new();
        let write_capability = write_space.insert(object, crate::Rights::WRITE).unwrap();
        let mut write_backend = MockBlock::new();
        let mut selected = CapabilitySelectedVirtualBlockBackend::new(
            &mut write_backend,
            &write_space,
            VirtualBlockBackendAuthority::new(write_capability, object, 0, 4).unwrap(),
            4096,
        );
        assert!(matches!(
            selected.read_blocks(0, &mut output),
            Err(VirtualBlockCapabilityError::Capability(
                CapabilityError::PermissionDenied
            ))
        ));
        assert_eq!(selected.write_blocks(0, &[0x65; 4096]), Ok(()));
        assert!(matches!(
            selected.flush(),
            Err(VirtualBlockMutationError::Rejected(
                VirtualBlockCapabilityError::Capability(CapabilityError::PermissionDenied)
            ))
        ));
        assert_eq!(
            (
                write_backend.reads,
                write_backend.writes,
                write_backend.flushes
            ),
            (0, 1, 0)
        );

        let mut flush_space = CapabilitySpace::<1>::new();
        let flush_capability = flush_space.insert(object, crate::Rights::FLUSH).unwrap();
        let mut flush_backend = MockBlock::new();
        let mut selected = CapabilitySelectedVirtualBlockBackend::new(
            &mut flush_backend,
            &flush_space,
            VirtualBlockBackendAuthority::new(flush_capability, object, 0, 4).unwrap(),
            4096,
        );
        assert!(matches!(
            selected.read_blocks(0, &mut output),
            Err(VirtualBlockCapabilityError::Capability(
                CapabilityError::PermissionDenied
            ))
        ));
        assert!(matches!(
            selected.write_blocks(0, &[0x65; 4096]),
            Err(VirtualBlockMutationError::Rejected(
                VirtualBlockCapabilityError::Capability(CapabilityError::PermissionDenied)
            ))
        ));
        assert_eq!(selected.flush(), Ok(()));
        assert_eq!(
            (
                flush_backend.reads,
                flush_backend.writes,
                flush_backend.flushes
            ),
            (0, 0, 1)
        );
    }

    #[test]
    fn capability_selected_backend_rejects_wrong_object_and_revoked_handle_before_io() {
        let object = ObjectId(0x300);
        let other = ObjectId(0x301);
        let mut output = [0xa5; 4096];

        let mut wrong_space = CapabilitySpace::<1>::new();
        let wrong_capability = wrong_space.insert(other, crate::Rights::READ).unwrap();
        let mut wrong_backend = MockBlock::new();
        let mut selected = CapabilitySelectedVirtualBlockBackend::new(
            &mut wrong_backend,
            &wrong_space,
            VirtualBlockBackendAuthority::new(wrong_capability, object, 0, 4).unwrap(),
            4096,
        );
        assert_eq!(
            selected.read_blocks(0, &mut output),
            Err(VirtualBlockCapabilityError::ObjectMismatch)
        );
        assert_eq!(wrong_backend.reads, 0);
        assert!(output.iter().all(|byte| *byte == 0xa5));

        let mut revoked_space = CapabilitySpace::<1>::new();
        let revoked_capability = revoked_space.insert(object, crate::Rights::READ).unwrap();
        revoked_space.revoke(revoked_capability).unwrap();
        let mut revoked_backend = MockBlock::new();
        let mut selected = CapabilitySelectedVirtualBlockBackend::new(
            &mut revoked_backend,
            &revoked_space,
            VirtualBlockBackendAuthority::new(revoked_capability, object, 0, 4).unwrap(),
            4096,
        );
        assert_eq!(
            selected.read_blocks(0, &mut output),
            Err(VirtualBlockCapabilityError::Capability(
                CapabilityError::Invalid
            ))
        );
        assert_eq!(revoked_backend.reads, 0);
        assert!(output.iter().all(|byte| *byte == 0xa5));
    }

    #[test]
    fn block_authority_rejects_empty_and_overflowing_backend_regions() {
        let mut capabilities = CapabilitySpace::<1>::new();
        let capability = capabilities
            .insert(ObjectId(0x300), crate::Rights::READ)
            .unwrap();
        assert_eq!(
            VirtualBlockBackendAuthority::new(capability, ObjectId(0x300), 0, 0),
            Err(VirtualBlockAuthorityError::InvalidRange)
        );
        assert_eq!(
            VirtualBlockBackendAuthority::new(capability, ObjectId(0x300), u64::MAX, 1),
            Err(VirtualBlockAuthorityError::InvalidRange)
        );
    }

    #[test]
    fn capability_selected_backend_translates_and_bounds_the_exposed_region() {
        let object = ObjectId(0x300);
        let mut capabilities = CapabilitySpace::<1>::new();
        let capability = capabilities
            .insert(object, crate::Rights::READ.union(crate::Rights::WRITE))
            .unwrap();
        let authority = VirtualBlockBackendAuthority::new(capability, object, 1, 2).unwrap();
        assert_eq!(authority.capability(), capability);
        assert_eq!(authority.object(), object);
        assert_eq!(authority.backend_first_block(), 1);
        assert_eq!(authority.exposed_block_count(), 2);

        let mut backend = MockBlock::new();
        backend.bytes[2 * 4096..3 * 4096].fill(0x5a);
        let mut selected = CapabilitySelectedVirtualBlockBackend::new(
            &mut backend,
            &capabilities,
            authority,
            4096,
        );
        assert_eq!(selected.write_blocks(0, &[0x65; 4096]), Ok(()));
        let mut output = [0; 4096];
        assert_eq!(selected.read_blocks(1, &mut output), Ok(()));
        assert!(output.iter().all(|byte| *byte == 0x5a));
        assert!(matches!(
            selected.read_blocks(2, &mut output),
            Err(VirtualBlockCapabilityError::InvalidRange)
        ));
        let mut oversized = [0xa5; 8192];
        assert!(matches!(
            selected.read_blocks(1, &mut oversized),
            Err(VirtualBlockCapabilityError::InvalidRange)
        ));
        assert!(matches!(
            selected.write_blocks(0, &[0x11; 4095]),
            Err(VirtualBlockMutationError::Rejected(
                VirtualBlockCapabilityError::InvalidRange
            ))
        ));
        assert_eq!((backend.reads, backend.writes), (1, 1));
        assert!(backend.bytes[..4096].iter().all(|byte| *byte == 0));
        assert!(backend.bytes[4096..8192].iter().all(|byte| *byte == 0x65));
        assert!(backend.bytes[8192..12288].iter().all(|byte| *byte == 0x5a));
        assert!(backend.bytes[12288..].iter().all(|byte| *byte == 0));
    }

    struct RecordingBlockPciRevoker {
        fail: bool,
        last: Option<VirtualBlockPciCleanupRecord>,
    }

    unsafe impl VirtualBlockPciResourceRevoker for RecordingBlockPciRevoker {
        type Error = MockError;

        fn revoke_block_resources(
            &mut self,
            record: VirtualBlockPciCleanupRecord,
        ) -> Result<(), Self::Error> {
            self.last = Some(record);
            if self.fail {
                Err(MockError::Injected)
            } else {
                Ok(())
            }
        }
    }

    struct RecordingBlockPciWindowBackend {
        map_result: Result<(), VirtualPciNativeResourceError>,
        unmap_result: Result<(), VirtualPciNativeResourceError>,
        maps: usize,
        unmaps: usize,
        last: Option<VirtualBlockPciCleanupRecord>,
    }

    unsafe impl VirtualBlockPciWindowBackend for RecordingBlockPciWindowBackend {
        fn map_block_window(
            &mut self,
            record: VirtualBlockPciCleanupRecord,
        ) -> Result<(), VirtualPciNativeResourceError> {
            self.maps += 1;
            self.last = Some(record);
            self.map_result
        }

        fn unmap_block_window(
            &mut self,
            record: VirtualBlockPciCleanupRecord,
        ) -> Result<(), VirtualPciNativeResourceError> {
            self.unmaps += 1;
            self.last = Some(record);
            self.unmap_result
        }
    }

    fn block_pci_function(class: u8) -> crate::VirtualPciType0Function {
        let identity =
            crate::VirtualPciIdentity::new(0x1234, 0x5678, 1, 0, 0x80, class, 0x1234, 0x5678)
                .unwrap();
        crate::VirtualPciType0Function::new(
            identity,
            crate::VirtualPciMemoryBar::new(4096).unwrap(),
        )
    }

    fn block_pci_function_with_subclass(subclass: u8) -> crate::VirtualPciType0Function {
        let identity =
            crate::VirtualPciIdentity::new(0x1234, 0x5678, 1, 0, subclass, 1, 0x1234, 0x5678)
                .unwrap();
        crate::VirtualPciType0Function::new(
            identity,
            crate::VirtualPciMemoryBar::new(4096).unwrap(),
        )
    }

    #[test]
    fn pci_block_attachment_binds_exact_generations_and_resets_after_cleanup() {
        let location = crate::VirtualPciLocation::new(0, 0, 4, 0).unwrap();
        let mut router = crate::VirtualPciConfigurationRouter::new();
        let pci_id = router.attach(location, block_pci_function(1)).unwrap();
        let description = router.describe_attachment(pci_id).unwrap();
        let mut device = active::<1>();
        let bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut capabilities = CapabilitySpace::<1>::new();
        let block_capability = capabilities
            .insert(
                ObjectId(0x300),
                crate::Rights::READ
                    .union(crate::Rights::WRITE)
                    .union(crate::Rights::FLUSH),
            )
            .unwrap();
        let authority =
            VirtualBlockBackendAuthority::new(block_capability, ObjectId(0x300), 8, 64).unwrap();
        let mut attachment =
            VirtualBlockPciAttachment::new(description, &device, &bridge, authority).unwrap();
        assert_eq!(attachment.state(), VirtualBlockPciAttachmentState::Attached);
        assert_eq!(attachment.pci(), description.resources());
        assert_eq!(attachment.block_generation(), 1);
        assert_eq!(attachment.backend(), authority);

        device
            .admit(&encoded(VirtualBlockRequest::read(
                1, 1, 0, 1, 0x4000, 4096,
            )))
            .unwrap();
        router.write(location, 16, 4, 0x20_0000).unwrap();
        let mut resource_revoker = RecordingBlockPciRevoker {
            fail: false,
            last: None,
        };
        {
            let mut revoker = VirtualBlockPciFunctionRevoker::new(
                &mut attachment,
                &mut device,
                &mut resource_revoker,
                VirtualBlockPciCleanupMode::Reset,
            );
            assert_eq!(router.reset_with_revoker(pci_id, &mut revoker), Ok(2));
        }

        assert_eq!(attachment.state(), VirtualBlockPciAttachmentState::Reset);
        assert_eq!(attachment.invalidated_requests(), 1);
        assert_eq!(device.state(), VirtualBlockDeviceState::Created);
        assert_eq!(device.generation(), 2);
        let cleaned = resource_revoker.last.unwrap();
        assert_eq!(cleaned.pci().attachment(), pci_id);
        assert_eq!(cleaned.pci().location(), location);
        assert_eq!(cleaned.pci().function_generation(), 1);
        assert_eq!(cleaned.pci().mmio_window().unwrap().address(), 0x20_0000);
        assert_eq!(cleaned.block_generation(), 1);
        assert_eq!(cleaned.queue(), layout::<1>());
        assert_eq!(cleaned.interrupt_vector(), 48);
        assert_eq!(cleaned.backend(), authority);
        assert_eq!(
            router
                .describe_attachment(pci_id)
                .unwrap()
                .resources()
                .function_generation(),
            2
        );
    }

    #[test]
    fn pci_block_reset_with_pending_state_rejects_every_stale_successor_action() {
        let location = crate::VirtualPciLocation::new(0, 0, 4, 0).unwrap();
        let mut router = crate::VirtualPciConfigurationRouter::new();
        let pci_id = router.attach(location, block_pci_function(1)).unwrap();
        let mut device = active_mmio::<2>();
        let mut old_bridge = VirtualBlockQueueBridge::<2>::new(layout::<2>()).unwrap();
        let mut capabilities = CapabilitySpace::<1>::new();
        let capability = capabilities
            .insert(
                ObjectId(0x30a),
                crate::Rights::READ
                    .union(crate::Rights::WRITE)
                    .union(crate::Rights::FLUSH),
            )
            .unwrap();
        let authority =
            VirtualBlockBackendAuthority::new(capability, ObjectId(0x30a), 0, 64).unwrap();
        let mut old_attachment = VirtualBlockPciAttachment::new(
            router.describe_attachment(pci_id).unwrap(),
            &device,
            &old_bridge,
            authority,
        )
        .unwrap();
        router.write(location, 16, 4, 0x20_0000).unwrap();
        let old_window = router
            .describe_attachment(pci_id)
            .unwrap()
            .resources()
            .mmio_window()
            .unwrap();
        let mut window_backend = RecordingBlockPciWindowBackend {
            map_result: Ok(()),
            unmap_result: Ok(()),
            maps: 0,
            unmaps: 0,
            last: None,
        };
        {
            let mut mapper =
                VirtualBlockPciMemoryMapper::new(&mut old_attachment, &device, &mut window_backend);
            router
                .write_with_mapper(
                    location,
                    4,
                    2,
                    crate::PCI_COMMAND_MEMORY_SPACE as u32,
                    &mut mapper,
                )
                .unwrap();
        }

        let completed_request = VirtualBlockRequest::write(1, 1, 0, 1, 0x4000, 4096);
        let pending_request = VirtualBlockRequest::read(1, 2, 1, 1, 0x5000, 4096);
        let completed = device.admit(&encoded(completed_request)).unwrap();
        let pending = device.admit(&encoded(pending_request)).unwrap();
        let stale_completion = device
            .complete(completed.ticket(), VirtualBlockCompletionStatus::Ok, 4096)
            .unwrap();
        let mut old_memory = MockVmm::new();
        old_bridge
            .publish_completion(&mut old_memory, stale_completion)
            .unwrap();
        device.latch_completion_interrupt().unwrap();

        let mut resource_revoker = RecordingBlockPciRevoker {
            fail: false,
            last: None,
        };
        {
            let mut revoker = VirtualBlockPciFunctionRevoker::new(
                &mut old_attachment,
                &mut device,
                &mut resource_revoker,
                VirtualBlockPciCleanupMode::Reset,
            );
            assert_eq!(router.reset_with_revoker(pci_id, &mut revoker), Ok(2));
        }
        assert_eq!(old_attachment.invalidated_requests(), 1);
        assert_eq!(
            old_attachment.state(),
            VirtualBlockPciAttachmentState::Reset
        );
        assert_eq!(device.pending_interrupt_vector(), None);

        device.negotiate(VIRTUAL_BLOCK_FEATURE_FLUSH).unwrap();
        device.activate(layout::<2>(), 48).unwrap();
        let successor_bridge = VirtualBlockQueueBridge::<2>::new(layout::<2>()).unwrap();
        let successor_attachment = VirtualBlockPciAttachment::new(
            router.describe_attachment(pci_id).unwrap(),
            &device,
            &successor_bridge,
            authority,
        )
        .unwrap();
        assert_eq!(successor_attachment.block_generation(), 2);
        assert_eq!(successor_attachment.pci().function_generation(), 2);

        let stale_ack = ExitDisposition::Mmio {
            guest_address: u64::from(old_window.address())
                + u64::from(VIRTUAL_BLOCK_MMIO_COMPLETION_ACK_OFFSET),
            size: 4,
            write: true,
            value: u64::from(VIRTUAL_BLOCK_COMPLETION_ACK_VALUE),
        };
        assert_eq!(
            process_virtual_block_mmio_completion_ack(
                stale_ack,
                &old_attachment,
                &mut device,
                &mut old_bridge,
                &mut old_memory,
            ),
            Err(VirtualBlockCompletionAckError::InvalidExit)
        );
        assert_eq!(device.state(), VirtualBlockDeviceState::Active);
        assert!(!successor_bridge.is_poisoned());
        assert_eq!(
            device.complete(pending.ticket(), VirtualBlockCompletionStatus::Ok, 4096),
            Err(VirtualBlockError::StaleTicket)
        );
        assert_eq!(
            device.admit(&encoded(pending_request)),
            Err(VirtualBlockError::StaleGeneration)
        );
        assert!(
            device
                .admit(&encoded(VirtualBlockRequest::read(
                    2, 3, 0, 1, 0x6000, 4096,
                )))
                .is_ok()
        );
    }

    #[test]
    fn pci_block_detach_removes_device_only_after_exact_resource_cleanup() {
        let location = crate::VirtualPciLocation::new(0, 0, 5, 0).unwrap();
        let mut router = crate::VirtualPciConfigurationRouter::new();
        let pci_id = router.attach(location, block_pci_function(1)).unwrap();
        let mut device = active::<1>();
        let bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut capabilities = CapabilitySpace::<1>::new();
        let capability = capabilities
            .insert(ObjectId(0x301), crate::Rights::READ)
            .unwrap();
        let authority =
            VirtualBlockBackendAuthority::new(capability, ObjectId(0x301), 0, 64).unwrap();
        let mut attachment = VirtualBlockPciAttachment::new(
            router.describe_attachment(pci_id).unwrap(),
            &device,
            &bridge,
            authority,
        )
        .unwrap();
        let mut resource_revoker = RecordingBlockPciRevoker {
            fail: false,
            last: None,
        };
        {
            let mut revoker = VirtualBlockPciFunctionRevoker::new(
                &mut attachment,
                &mut device,
                &mut resource_revoker,
                VirtualBlockPciCleanupMode::Remove,
            );
            let detached = router.detach_with_revoker(pci_id, &mut revoker).unwrap();
            assert_eq!(detached.identity().class(), 1);
        }
        assert_eq!(attachment.state(), VirtualBlockPciAttachmentState::Removed);
        assert_eq!(device.state(), VirtualBlockDeviceState::Removed);
        assert_eq!(device.generation(), 2);
        assert_eq!(
            router.describe_attachment(pci_id),
            Err(crate::VirtualPciError::StaleAttachment)
        );
        assert_eq!(resource_revoker.last.unwrap().backend(), authority);
    }

    #[test]
    fn pci_block_cleanup_failure_and_stale_state_preserve_pci_configuration() {
        let location = crate::VirtualPciLocation::new(0, 0, 6, 0).unwrap();
        let mut router = crate::VirtualPciConfigurationRouter::new();
        let pci_id = router.attach(location, block_pci_function(1)).unwrap();
        let mut device = active::<1>();
        let bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut capabilities = CapabilitySpace::<1>::new();
        let capability = capabilities
            .insert(ObjectId(0x302), crate::Rights::READ)
            .unwrap();
        let authority =
            VirtualBlockBackendAuthority::new(capability, ObjectId(0x302), 0, 64).unwrap();
        let description = router.describe_attachment(pci_id).unwrap();
        let mut attachment =
            VirtualBlockPciAttachment::new(description, &device, &bridge, authority).unwrap();
        let mut resource_revoker = RecordingBlockPciRevoker {
            fail: true,
            last: None,
        };
        {
            let mut revoker = VirtualBlockPciFunctionRevoker::new(
                &mut attachment,
                &mut device,
                &mut resource_revoker,
                VirtualBlockPciCleanupMode::Reset,
            );
            assert_eq!(
                router.reset_with_revoker(pci_id, &mut revoker),
                Err(crate::VirtualPciResetError::Revocation(
                    VirtualBlockPciCleanupError::Resource(MockError::Injected)
                ))
            );
        }
        assert_eq!(attachment.state(), VirtualBlockPciAttachmentState::Attached);
        assert_eq!(device.state(), VirtualBlockDeviceState::Active);
        assert_eq!(device.generation(), 1);
        assert_eq!(router.describe_attachment(pci_id), Ok(description));

        device.reset().unwrap();
        resource_revoker.fail = false;
        let mut revoker = VirtualBlockPciFunctionRevoker::new(
            &mut attachment,
            &mut device,
            &mut resource_revoker,
            VirtualBlockPciCleanupMode::Reset,
        );
        assert_eq!(
            router.reset_with_revoker(pci_id, &mut revoker),
            Err(crate::VirtualPciResetError::Revocation(
                VirtualBlockPciCleanupError::Attachment(VirtualBlockPciError::StaleBlockGeneration)
            ))
        );
        assert_eq!(router.describe_attachment(pci_id), Ok(description));
    }

    #[test]
    fn pci_block_attachment_rejects_identity_state_and_geometry_substitution() {
        let location = crate::VirtualPciLocation::new(0, 0, 7, 0).unwrap();
        let mut router = crate::VirtualPciConfigurationRouter::new();
        let non_block_id = router.attach(location, block_pci_function(2)).unwrap();
        let device = active::<1>();
        let mut poisoned_bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        poisoned_bridge.fail_stop();
        let clean_bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut capabilities = CapabilitySpace::<1>::new();
        let capability = capabilities
            .insert(ObjectId(0x303), crate::Rights::READ)
            .unwrap();
        let exact = VirtualBlockBackendAuthority::new(capability, ObjectId(0x303), 0, 64).unwrap();
        assert_eq!(
            VirtualBlockPciAttachment::new(
                router.describe_attachment(non_block_id).unwrap(),
                &device,
                &clean_bridge,
                exact,
            )
            .map(|_| ()),
            Err(VirtualBlockPciError::InvalidPciClass)
        );
        let mut subclass_router = crate::VirtualPciConfigurationRouter::new();
        let subclass_id = subclass_router
            .attach(location, block_pci_function_with_subclass(0x01))
            .unwrap();
        assert_eq!(
            VirtualBlockPciAttachment::new(
                subclass_router.describe_attachment(subclass_id).unwrap(),
                &device,
                &clean_bridge,
                exact,
            )
            .map(|_| ()),
            Err(VirtualBlockPciError::InvalidPciClass)
        );

        let mut block_router = crate::VirtualPciConfigurationRouter::new();
        let block_id = block_router
            .attach(location, block_pci_function(1))
            .unwrap();
        let description = block_router.describe_attachment(block_id).unwrap();
        assert_eq!(
            VirtualBlockPciAttachment::new(description, &device, &poisoned_bridge, exact)
                .map(|_| ()),
            Err(VirtualBlockPciError::InvalidState)
        );
        let narrow = VirtualBlockBackendAuthority::new(capability, ObjectId(0x303), 0, 63).unwrap();
        assert_eq!(
            VirtualBlockPciAttachment::new(description, &device, &clean_bridge, narrow).map(|_| ()),
            Err(VirtualBlockPciError::GeometryMismatch)
        );
    }

    #[test]
    fn pci_block_bar_mapping_tracks_only_the_exact_attachment_window() {
        let location = crate::VirtualPciLocation::new(0, 0, 4, 0).unwrap();
        let mut router = crate::VirtualPciConfigurationRouter::new();
        let pci_id = router.attach(location, block_pci_function(1)).unwrap();
        let mut device = active::<1>();
        let bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut capabilities = CapabilitySpace::<1>::new();
        let capability = capabilities
            .insert(ObjectId(0x304), crate::Rights::READ)
            .unwrap();
        let authority =
            VirtualBlockBackendAuthority::new(capability, ObjectId(0x304), 8, 64).unwrap();
        let mut attachment = VirtualBlockPciAttachment::new(
            router.describe_attachment(pci_id).unwrap(),
            &device,
            &bridge,
            authority,
        )
        .unwrap();
        router.write(location, 16, 4, 0x20_0000).unwrap();
        let expected_window = router
            .describe_attachment(pci_id)
            .unwrap()
            .resources()
            .mmio_window()
            .unwrap();
        let mut backend = RecordingBlockPciWindowBackend {
            map_result: Ok(()),
            unmap_result: Ok(()),
            maps: 0,
            unmaps: 0,
            last: None,
        };

        {
            let mut mapper =
                VirtualBlockPciMemoryMapper::new(&mut attachment, &device, &mut backend);
            router
                .write_with_mapper(
                    location,
                    4,
                    2,
                    crate::PCI_COMMAND_MEMORY_SPACE as u32,
                    &mut mapper,
                )
                .unwrap();
        }
        assert_eq!(attachment.mapped_window(), Some(expected_window));
        assert_eq!(backend.maps, 1);
        let mapped = backend.last.unwrap();
        assert_eq!(mapped.pci().attachment(), pci_id);
        assert_eq!(mapped.pci().mmio_window(), Some(expected_window));
        assert_eq!(mapped.mapped_window(), None);
        assert_eq!(mapped.backend(), authority);

        {
            let mut mapper =
                VirtualBlockPciMemoryMapper::new(&mut attachment, &device, &mut backend);
            router
                .write_with_mapper(location, 4, 2, 0, &mut mapper)
                .unwrap();
        }
        assert_eq!(attachment.mapped_window(), None);
        assert_eq!(backend.unmaps, 1);
        let unmapped = backend.last.unwrap();
        assert_eq!(unmapped.pci().mmio_window(), Some(expected_window));
        assert_eq!(unmapped.mapped_window(), Some(expected_window));

        {
            let mut mapper =
                VirtualBlockPciMemoryMapper::new(&mut attachment, &device, &mut backend);
            router
                .write_with_mapper(
                    location,
                    4,
                    2,
                    crate::PCI_COMMAND_MEMORY_SPACE as u32,
                    &mut mapper,
                )
                .unwrap();
        }
        let mut resources = RecordingBlockPciRevoker {
            fail: false,
            last: None,
        };
        {
            let mut revoker = VirtualBlockPciFunctionRevoker::new(
                &mut attachment,
                &mut device,
                &mut resources,
                VirtualBlockPciCleanupMode::Reset,
            );
            assert_eq!(router.reset_with_revoker(pci_id, &mut revoker), Ok(2));
        }
        assert_eq!(
            resources.last.unwrap().mapped_window(),
            Some(expected_window)
        );
    }

    #[test]
    fn pci_mmio_doorbell_requires_exact_live_mapping_and_tuple() {
        let location = crate::VirtualPciLocation::new(0, 0, 4, 0).unwrap();
        let mut router = crate::VirtualPciConfigurationRouter::new();
        let pci_id = router.attach(location, block_pci_function(1)).unwrap();
        let mut device = active_mmio::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut capabilities = CapabilitySpace::<1>::new();
        let capability = capabilities
            .insert(
                ObjectId(0x30a),
                crate::Rights::READ.union(crate::Rights::WRITE),
            )
            .unwrap();
        let authority =
            VirtualBlockBackendAuthority::new(capability, ObjectId(0x30a), 0, 64).unwrap();
        let mut attachment = VirtualBlockPciAttachment::new(
            router.describe_attachment(pci_id).unwrap(),
            &device,
            &bridge,
            authority,
        )
        .unwrap();
        router.write(location, 16, 4, 0x20_0000).unwrap();
        let mut window_backend = RecordingBlockPciWindowBackend {
            map_result: Ok(()),
            unmap_result: Ok(()),
            maps: 0,
            unmaps: 0,
            last: None,
        };
        {
            let mut mapper =
                VirtualBlockPciMemoryMapper::new(&mut attachment, &device, &mut window_backend);
            router
                .write_with_mapper(
                    location,
                    4,
                    2,
                    crate::PCI_COMMAND_MEMORY_SPACE as u32,
                    &mut mapper,
                )
                .unwrap();
        }
        router
            .write(
                location,
                4,
                2,
                u32::from(PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_INTERRUPT_DISABLE),
            )
            .unwrap();
        let masked = router.describe_attachment(pci_id).unwrap().resources();
        assert_eq!(
            attachment.validate_interrupt_state(masked, &device, &bridge),
            Ok(VirtualBlockPciInterruptState::Masked)
        );
        router
            .write(location, 4, 2, u32::from(PCI_COMMAND_MEMORY_SPACE))
            .unwrap();
        let unmasked = router.describe_attachment(pci_id).unwrap().resources();
        assert_eq!(
            attachment.validate_interrupt_state(unmasked, &device, &bridge),
            Ok(VirtualBlockPciInterruptState::Enabled)
        );

        let exact = ExitDisposition::Mmio {
            guest_address: 0x20_0000,
            size: 4,
            write: true,
            value: u64::from(VIRTUAL_BLOCK_DOORBELL_VALUE),
        };
        let mut memory = MockVmm::new();
        let mut block = MockBlock::new();
        let mut scratch = [0; 4096];
        assert_eq!(
            process_virtual_block_mmio_doorbell(
                exact,
                &attachment,
                &mut device,
                &mut bridge,
                &mut memory,
                &mut block,
                &mut scratch,
            ),
            Ok(VirtualBlockProcessOutcome::Idle)
        );

        for hostile in [
            ExitDisposition::Mmio {
                guest_address: 0x20_0004,
                size: 4,
                write: true,
                value: 1,
            },
            ExitDisposition::Mmio {
                guest_address: 0x20_0000,
                size: 2,
                write: true,
                value: 1,
            },
            ExitDisposition::Mmio {
                guest_address: 0x20_0000,
                size: 4,
                write: true,
                value: 2,
            },
            ExitDisposition::Mmio {
                guest_address: 0x20_0000,
                size: 4,
                write: false,
                value: 1,
            },
        ] {
            assert_eq!(
                process_virtual_block_mmio_doorbell(
                    hostile,
                    &attachment,
                    &mut device,
                    &mut bridge,
                    &mut memory,
                    &mut block,
                    &mut scratch,
                ),
                Err(VirtualBlockDoorbellError::InvalidExit)
            );
        }

        {
            let mut mapper =
                VirtualBlockPciMemoryMapper::new(&mut attachment, &device, &mut window_backend);
            router
                .write_with_mapper(location, 4, 2, 0, &mut mapper)
                .unwrap();
        }
        assert_eq!(
            process_virtual_block_mmio_doorbell(
                exact,
                &attachment,
                &mut device,
                &mut bridge,
                &mut memory,
                &mut block,
                &mut scratch,
            ),
            Err(VirtualBlockDoorbellError::InvalidExit)
        );
        assert_eq!((block.reads, block.writes, block.flushes), (0, 0, 0));
    }

    #[test]
    fn pci_block_bar_mapping_failures_preserve_configuration_and_attachment_state() {
        for error in [
            VirtualPciNativeResourceError::Rejected,
            VirtualPciNativeResourceError::Uncertain,
        ] {
            let location = crate::VirtualPciLocation::new(0, 0, 4, 0).unwrap();
            let mut router = crate::VirtualPciConfigurationRouter::new();
            let pci_id = router.attach(location, block_pci_function(1)).unwrap();
            let device = active::<1>();
            let bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
            let mut capabilities = CapabilitySpace::<1>::new();
            let capability = capabilities
                .insert(ObjectId(0x305), crate::Rights::READ)
                .unwrap();
            let authority =
                VirtualBlockBackendAuthority::new(capability, ObjectId(0x305), 0, 64).unwrap();
            let mut attachment = VirtualBlockPciAttachment::new(
                router.describe_attachment(pci_id).unwrap(),
                &device,
                &bridge,
                authority,
            )
            .unwrap();
            router.write(location, 16, 4, 0x20_0000).unwrap();
            let before = router.read(location, 4, 2).unwrap();
            let mut backend = RecordingBlockPciWindowBackend {
                map_result: Err(error),
                unmap_result: Ok(()),
                maps: 0,
                unmaps: 0,
                last: None,
            };
            let result = {
                let mut mapper =
                    VirtualBlockPciMemoryMapper::new(&mut attachment, &device, &mut backend);
                router.write_with_mapper(
                    location,
                    4,
                    2,
                    crate::PCI_COMMAND_MEMORY_SPACE as u32,
                    &mut mapper,
                )
            };
            let expected = match error {
                VirtualPciNativeResourceError::Rejected => {
                    crate::VirtualPciError::NativeResourceRejected
                }
                VirtualPciNativeResourceError::Uncertain => {
                    crate::VirtualPciError::NativeResourceUncertain
                }
            };
            assert_eq!(result, Err(expected));
            assert_eq!(router.read(location, 4, 2), Ok(before));
            assert_eq!(attachment.mapped_window(), None);
            assert_eq!(backend.maps, 1);
        }
    }

    #[test]
    fn pci_block_bar_unmap_failure_preserves_decode_and_mapping_state() {
        let location = crate::VirtualPciLocation::new(0, 0, 4, 0).unwrap();
        let mut router = crate::VirtualPciConfigurationRouter::new();
        let pci_id = router.attach(location, block_pci_function(1)).unwrap();
        let device = active::<1>();
        let bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut capabilities = CapabilitySpace::<1>::new();
        let capability = capabilities
            .insert(ObjectId(0x306), crate::Rights::READ)
            .unwrap();
        let authority =
            VirtualBlockBackendAuthority::new(capability, ObjectId(0x306), 0, 64).unwrap();
        let mut attachment = VirtualBlockPciAttachment::new(
            router.describe_attachment(pci_id).unwrap(),
            &device,
            &bridge,
            authority,
        )
        .unwrap();
        router.write(location, 16, 4, 0x20_0000).unwrap();
        let mut backend = RecordingBlockPciWindowBackend {
            map_result: Ok(()),
            unmap_result: Err(VirtualPciNativeResourceError::Uncertain),
            maps: 0,
            unmaps: 0,
            last: None,
        };
        {
            let mut mapper =
                VirtualBlockPciMemoryMapper::new(&mut attachment, &device, &mut backend);
            router
                .write_with_mapper(
                    location,
                    4,
                    2,
                    crate::PCI_COMMAND_MEMORY_SPACE as u32,
                    &mut mapper,
                )
                .unwrap();
        }
        let mapped = attachment.mapped_window();
        let command = router.read(location, 4, 2).unwrap();
        let result = {
            let mut mapper =
                VirtualBlockPciMemoryMapper::new(&mut attachment, &device, &mut backend);
            router.write_with_mapper(location, 4, 2, 0, &mut mapper)
        };
        assert_eq!(result, Err(crate::VirtualPciError::NativeResourceUncertain));
        assert_eq!(router.read(location, 4, 2), Ok(command));
        assert_eq!(attachment.mapped_window(), mapped);
        assert_eq!(backend.unmaps, 1);
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
        assert_eq!(device.pending_interrupt_vector(), Some(48));
        assert_eq!(device.suspend(), Err(VirtualBlockError::InvalidState));
        assert_eq!(
            device.acknowledge_interrupt(49),
            Err(VirtualBlockError::InvalidInterrupt)
        );
        assert_eq!(device.pending_interrupt_vector(), Some(48));
        device.acknowledge_interrupt(48).unwrap();
        assert_eq!(device.pending_interrupt_vector(), None);
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
    fn doorbell_rejects_every_scalar_mismatch_before_queue_or_backend_access() {
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        let request = encoded(VirtualBlockRequest::write(1, 1, 0, 1, 0x4000, 4096));
        vmm.bytes[0x4000..0x5000].fill(0x73);
        vmm.write_guest(0x1000 + QUEUE_HEADER_BYTES, &request)
            .unwrap();
        vmm.write_guest(0x1000, &1u64.to_le_bytes()).unwrap();

        let invalid = [
            ExitDisposition::Io {
                port: VIRTUAL_BLOCK_DOORBELL_PORT + 1,
                size: 4,
                write: true,
                value: VIRTUAL_BLOCK_DOORBELL_VALUE,
            },
            ExitDisposition::Io {
                port: VIRTUAL_BLOCK_DOORBELL_PORT,
                size: 2,
                write: true,
                value: VIRTUAL_BLOCK_DOORBELL_VALUE,
            },
            ExitDisposition::Io {
                port: VIRTUAL_BLOCK_DOORBELL_PORT,
                size: 4,
                write: false,
                value: VIRTUAL_BLOCK_DOORBELL_VALUE,
            },
            ExitDisposition::Io {
                port: VIRTUAL_BLOCK_DOORBELL_PORT,
                size: 4,
                write: true,
                value: VIRTUAL_BLOCK_DOORBELL_VALUE + 1,
            },
            ExitDisposition::Resume,
        ];
        for disposition in invalid {
            assert_eq!(
                process_virtual_block_doorbell(
                    disposition,
                    &mut device,
                    &mut bridge,
                    &mut vmm,
                    &mut backend,
                    &mut scratch,
                ),
                Err(VirtualBlockDoorbellError::InvalidExit)
            );
        }
        let mut consumed = [0; 8];
        vmm.read_guest(0x1040, &mut consumed).unwrap();
        assert_eq!(u64::from_le_bytes(consumed), 0);
        assert_eq!((backend.reads, backend.writes, backend.flushes), (0, 0, 0));
        assert!(scratch.iter().all(|byte| *byte == 0xa5));
        assert_eq!(device.pending_interrupt_vector(), None);
    }

    #[test]
    fn exact_doorbell_processes_at_most_one_request_and_latches_notification() {
        let mut device = active::<2>();
        let mut bridge = VirtualBlockQueueBridge::<2>::new(layout::<2>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        for (slot, request_id) in [1u64, 2].into_iter().enumerate() {
            let request = encoded(VirtualBlockRequest::write(
                1,
                request_id,
                request_id - 1,
                1,
                0x4000,
                4096,
            ));
            vmm.write_guest(
                0x1000 + QUEUE_HEADER_BYTES + (slot * VIRTUAL_BLOCK_REQUEST_BYTES) as u64,
                &request,
            )
            .unwrap();
        }
        vmm.bytes[0x4000..0x5000].fill(0x41);
        vmm.write_guest(0x1000, &2u64.to_le_bytes()).unwrap();
        let doorbell = ExitDisposition::Io {
            port: VIRTUAL_BLOCK_DOORBELL_PORT,
            size: 4,
            write: true,
            value: VIRTUAL_BLOCK_DOORBELL_VALUE,
        };

        assert!(matches!(
            process_virtual_block_doorbell(
                doorbell,
                &mut device,
                &mut bridge,
                &mut vmm,
                &mut backend,
                &mut scratch,
            ),
            Ok(VirtualBlockProcessOutcome::Completed(_))
        ));
        assert_eq!(backend.writes, 1);
        assert_eq!(device.pending_interrupt_vector(), Some(48));
        let mut consumed = [0; 8];
        vmm.read_guest(0x1040, &mut consumed).unwrap();
        assert_eq!(u64::from_le_bytes(consumed), 1);

        assert!(matches!(
            process_virtual_block_doorbell(
                doorbell,
                &mut device,
                &mut bridge,
                &mut vmm,
                &mut backend,
                &mut scratch,
            ),
            Ok(VirtualBlockProcessOutcome::Completed(_))
        ));
        assert_eq!(backend.writes, 2);
        vmm.read_guest(0x1040, &mut consumed).unwrap();
        assert_eq!(u64::from_le_bytes(consumed), 2);
    }

    fn runner_vm() -> (VmTable<1>, VmId) {
        let mut vms = VmTable::new();
        let vm = vms.create(8).unwrap();
        vms.mark_loaded(vm).unwrap();
        vms.start(vm).unwrap();
        (vms, vm)
    }

    fn block_io_policy() -> IoPortPolicy<1> {
        let mut policy = IoPortPolicy::deny_all();
        policy
            .allow(
                crate::IoPortRule::new(VIRTUAL_BLOCK_DOORBELL_PORT, 4, crate::IoDirection::Write)
                    .unwrap(),
            )
            .unwrap();
        policy
    }

    fn block_ack_io_policy() -> IoPortPolicy<1> {
        let mut policy = IoPortPolicy::deny_all();
        policy
            .allow(
                crate::IoPortRule::new(
                    VIRTUAL_BLOCK_COMPLETION_ACK_PORT,
                    4,
                    crate::IoDirection::Write,
                )
                .unwrap(),
            )
            .unwrap();
        policy
    }

    fn block_transaction_io_policy() -> IoPortPolicy<2> {
        let mut policy = IoPortPolicy::deny_all();
        for port in [
            VIRTUAL_BLOCK_DOORBELL_PORT,
            VIRTUAL_BLOCK_COMPLETION_ACK_PORT,
        ] {
            policy
                .allow(crate::IoPortRule::new(port, 4, crate::IoDirection::Write).unwrap())
                .unwrap();
        }
        policy
    }

    fn mapped_mmio_attachment(
        device: &VirtualBlockDevice<1>,
        bridge: &VirtualBlockQueueBridge<1>,
        authority: VirtualBlockBackendAuthority,
    ) -> (VirtualBlockPciAttachment, VirtualPciConfigurationRouter) {
        let location = crate::VirtualPciLocation::new(0, 0, 4, 0).unwrap();
        let mut router = crate::VirtualPciConfigurationRouter::new();
        let pci_id = router.attach(location, block_pci_function(1)).unwrap();
        let mut attachment = VirtualBlockPciAttachment::new(
            router.describe_attachment(pci_id).unwrap(),
            device,
            bridge,
            authority,
        )
        .unwrap();
        router.write(location, 16, 4, 0x20_0000).unwrap();
        let mut backend = RecordingBlockPciWindowBackend {
            map_result: Ok(()),
            unmap_result: Ok(()),
            maps: 0,
            unmaps: 0,
            last: None,
        };
        {
            let mut mapper =
                VirtualBlockPciMemoryMapper::new(&mut attachment, device, &mut backend);
            router
                .write_with_mapper(
                    location,
                    4,
                    2,
                    crate::PCI_COMMAND_MEMORY_SPACE as u32,
                    &mut mapper,
                )
                .unwrap();
        }
        assert_eq!(backend.maps, 1);
        (attachment, router)
    }

    #[test]
    fn mmio_transaction_runner_retires_only_the_consumed_exact_write() {
        let interrupt_object = ObjectId(0x320);
        let block_object = ObjectId(0x321);
        let mut capabilities = CapabilitySpace::<2>::new();
        let block_capability = capabilities
            .insert(
                block_object,
                crate::Rights::READ
                    .union(crate::Rights::WRITE)
                    .union(crate::Rights::FLUSH),
            )
            .unwrap();
        let interrupt_capability = capabilities
            .insert(interrupt_object, crate::Rights::SIGNAL)
            .unwrap();
        let authority =
            VirtualBlockBackendAuthority::new(block_capability, block_object, 0, 64).unwrap();
        let mut interrupts = InterruptPolicy::deny_all();
        interrupts.allow(48).unwrap();
        let (mut vms, vm) = runner_vm();
        let mut router = HypercallRouter::new(ObjectId(0x322), ObjectId(0x323), ObjectId(0x324));
        let guest_memory = GuestMemory::<0>::new();
        let io = IoPortPolicy::<0>::deny_all();
        let mut device = active_mmio::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let (attachment, pci_router) = mapped_mmio_attachment(&device, &bridge, authority);
        let mut vmm = MockVmm::new();
        vmm.next_exit = Some(VmExit::Mmio {
            guest_address: 0x20_0000,
            size: 4,
            write: true,
            value: 1,
        });
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];

        assert_eq!(
            run_virtual_block_mmio_transaction_once(
                &mut vmm,
                &mut backend,
                authority,
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &interrupts,
                interrupt_capability,
                interrupt_object,
                &pci_router,
                &attachment,
                &mut device,
                &mut bridge,
                &mut scratch,
            ),
            Ok(VirtualBlockTransactionOutcome::Doorbell(
                VirtualBlockProcessOutcome::Idle
            ))
        );
        assert_eq!(vmm.completed_mmio, Some((0, 0x20_0000, 4, 1)));
        assert_eq!(vms.state(vm), Ok(crate::VmState::Running));
        assert_eq!((backend.reads, backend.writes, backend.flushes), (0, 0, 0));
    }

    #[test]
    fn mmio_transaction_runner_completes_request_and_protected_acknowledgement() {
        let interrupt_object = ObjectId(0x325);
        let block_object = ObjectId(0x326);
        let mut capabilities = CapabilitySpace::<2>::new();
        let block_capability = capabilities
            .insert(block_object, crate::Rights::WRITE)
            .unwrap();
        let interrupt_capability = capabilities
            .insert(interrupt_object, crate::Rights::SIGNAL)
            .unwrap();
        let authority =
            VirtualBlockBackendAuthority::new(block_capability, block_object, 0, 64).unwrap();
        let mut interrupts = InterruptPolicy::deny_all();
        interrupts.allow(48).unwrap();
        let (mut vms, vm) = runner_vm();
        let mut router = HypercallRouter::new(ObjectId(0x327), ObjectId(0x328), ObjectId(0x329));
        let guest_memory = GuestMemory::<0>::new();
        let io = IoPortPolicy::<0>::deny_all();
        let mut device = active_mmio::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let (attachment, pci_router) = mapped_mmio_attachment(&device, &bridge, authority);
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0; 4096];
        let request = encoded(VirtualBlockRequest::write(1, 1, 0, 1, 0x4000, 4096));
        vmm.bytes[0x4000..0x5000].fill(0x6b);
        vmm.write_guest(0x1000 + QUEUE_HEADER_BYTES, &request)
            .unwrap();
        vmm.write_guest(0x1000, &1u64.to_le_bytes()).unwrap();
        vmm.next_exit = Some(VmExit::Mmio {
            guest_address: 0x20_0000,
            size: 4,
            write: true,
            value: 1,
        });

        assert!(matches!(
            run_virtual_block_mmio_transaction_once(
                &mut vmm,
                &mut backend,
                authority,
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &interrupts,
                interrupt_capability,
                interrupt_object,
                &pci_router,
                &attachment,
                &mut device,
                &mut bridge,
                &mut scratch,
            ),
            Ok(VirtualBlockTransactionOutcome::Doorbell(
                VirtualBlockProcessOutcome::Completed(_)
            ))
        ));
        assert_eq!(vmm.injected, Some((0, 48)));
        assert_eq!(backend.writes, 1);

        // Model the native backend having consumed its exact pending tuple.
        vmm.completed_mmio = None;
        vmm.next_exit = Some(VmExit::Mmio {
            guest_address: 0x20_0004,
            size: 4,
            write: true,
            value: 1,
        });
        assert_eq!(
            run_virtual_block_mmio_transaction_once(
                &mut vmm,
                &mut backend,
                authority,
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &interrupts,
                interrupt_capability,
                interrupt_object,
                &pci_router,
                &attachment,
                &mut device,
                &mut bridge,
                &mut scratch,
            ),
            Ok(VirtualBlockTransactionOutcome::CompletionAcknowledged(1))
        );
        assert_eq!(bridge.completion_consumed, 1);
        assert_eq!(vms.state(vm), Ok(crate::VmState::Running));
    }

    #[test]
    fn mmio_completion_uncertainty_fail_stops_the_vm() {
        let interrupt_object = ObjectId(0x330);
        let block_object = ObjectId(0x331);
        let mut capabilities = CapabilitySpace::<2>::new();
        let block_capability = capabilities
            .insert(block_object, crate::Rights::READ)
            .unwrap();
        let interrupt_capability = capabilities
            .insert(interrupt_object, crate::Rights::SIGNAL)
            .unwrap();
        let authority =
            VirtualBlockBackendAuthority::new(block_capability, block_object, 0, 64).unwrap();
        let mut interrupts = InterruptPolicy::deny_all();
        interrupts.allow(48).unwrap();
        let (mut vms, vm) = runner_vm();
        let mut router = HypercallRouter::new(ObjectId(0x332), ObjectId(0x333), ObjectId(0x334));
        let guest_memory = GuestMemory::<0>::new();
        let io = IoPortPolicy::<0>::deny_all();
        let mut device = active_mmio::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let (attachment, pci_router) = mapped_mmio_attachment(&device, &bridge, authority);
        let mut vmm = MockVmm::new();
        vmm.fail_mmio_completion = true;
        vmm.next_exit = Some(VmExit::Mmio {
            guest_address: 0x20_0000,
            size: 4,
            write: true,
            value: 1,
        });
        let mut backend = MockBlock::new();
        let mut scratch = [0; 4096];

        assert_eq!(
            run_virtual_block_mmio_transaction_once(
                &mut vmm,
                &mut backend,
                authority,
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &interrupts,
                interrupt_capability,
                interrupt_object,
                &pci_router,
                &attachment,
                &mut device,
                &mut bridge,
                &mut scratch,
            ),
            Err(VirtualBlockTransactionRunError::Completion(
                MockError::Injected
            ))
        );
        assert_eq!(vms.state(vm), Ok(crate::VmState::Failed));
        assert_eq!(vmm.completed_mmio, None);
        assert!(bridge.is_poisoned());
        assert_eq!(device.state(), VirtualBlockDeviceState::Failed);
    }

    #[test]
    fn shared_ack_runner_accounts_exact_exit_and_updates_protected_counter() {
        let (mut vms, vm) = runner_vm();
        let mut router = HypercallRouter::new(ObjectId(76), ObjectId(77), ObjectId(78));
        let capabilities = CapabilitySpace::<0>::new();
        let guest_memory = GuestMemory::<0>::new();
        let io = block_ack_io_policy();
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        published_completion(&mut device, &mut bridge, &mut vmm);
        vmm.next_exit = Some(VmExit::Io {
            port: VIRTUAL_BLOCK_COMPLETION_ACK_PORT,
            size: 4,
            write: true,
            value: VIRTUAL_BLOCK_COMPLETION_ACK_VALUE,
        });

        assert_eq!(
            run_virtual_block_completion_ack_once(
                &mut vmm,
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &mut device,
                &mut bridge,
            ),
            Ok(1)
        );
        assert_eq!(vms.state(vm), Ok(crate::VmState::Running));
        let mut consumed = [0; 8];
        vmm.read_guest(0x3000 + 64, &mut consumed).unwrap();
        assert_eq!(u64::from_le_bytes(consumed), 1);
    }

    #[test]
    fn shared_ack_runner_fails_vm_on_dispatched_scalar_mismatch() {
        let (mut vms, vm) = runner_vm();
        let mut router = HypercallRouter::new(ObjectId(72), ObjectId(73), ObjectId(74));
        let capabilities = CapabilitySpace::<0>::new();
        let guest_memory = GuestMemory::<0>::new();
        let io = block_ack_io_policy();
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        published_completion(&mut device, &mut bridge, &mut vmm);
        vmm.next_exit = Some(VmExit::Io {
            port: VIRTUAL_BLOCK_COMPLETION_ACK_PORT,
            size: 4,
            write: true,
            value: VIRTUAL_BLOCK_COMPLETION_ACK_VALUE + 1,
        });

        assert_eq!(
            run_virtual_block_completion_ack_once(
                &mut vmm,
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &mut device,
                &mut bridge,
            ),
            Err(VirtualBlockCompletionAckRunError::Acknowledgement(
                VirtualBlockCompletionAckError::InvalidExit
            ))
        );
        assert_eq!(vms.state(vm), Ok(crate::VmState::Failed));
        assert_eq!(device.state(), VirtualBlockDeviceState::Active);
        assert!(!bridge.is_poisoned());
        assert_eq!(bridge.completion_consumed, 0);
    }

    #[test]
    fn shared_runners_reuse_one_slot_for_bounded_write_then_read() {
        let interrupt_object = ObjectId(68);
        let block_object = ObjectId(0x300);
        let mut capabilities = CapabilitySpace::<2>::new();
        let block_capability = capabilities
            .insert(
                block_object,
                crate::Rights::READ
                    .union(crate::Rights::WRITE)
                    .union(crate::Rights::FLUSH),
            )
            .unwrap();
        let interrupt_capability = capabilities
            .insert(interrupt_object, crate::Rights::SIGNAL)
            .unwrap();
        let mut interrupts = InterruptPolicy::deny_all();
        interrupts.allow(48).unwrap();
        let (mut vms, vm) = runner_vm();
        let mut router = HypercallRouter::new(ObjectId(69), ObjectId(70), ObjectId(71));
        let guest_memory = GuestMemory::<0>::new();
        let io = block_transaction_io_policy();
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];

        for (sequence, request) in [
            VirtualBlockRequest::write(1, 1, 0, 1, 0x4000, 4096),
            VirtualBlockRequest::read(1, 2, 0, 1, 0x4000, 4096),
        ]
        .into_iter()
        .enumerate()
        {
            let sequence = sequence as u64 + 1;
            if sequence == 1 {
                vmm.bytes[0x4000..0x5000].fill(0x65);
            } else {
                vmm.bytes[0x4000..0x5000].fill(0);
            }
            vmm.write_guest(0x1000 + QUEUE_HEADER_BYTES, &encoded(request))
                .unwrap();
            vmm.write_guest(0x1000, &sequence.to_le_bytes()).unwrap();
            vmm.next_exit = Some(VmExit::Io {
                port: VIRTUAL_BLOCK_DOORBELL_PORT,
                size: 4,
                write: true,
                value: VIRTUAL_BLOCK_DOORBELL_VALUE,
            });
            assert!(matches!(
                run_virtual_block_doorbell_once(
                    &mut vmm,
                    &mut backend,
                    VirtualBlockBackendAuthority::new(block_capability, block_object, 0, 64)
                        .unwrap(),
                    0,
                    &mut vms,
                    vm,
                    &mut router,
                    &capabilities,
                    &guest_memory,
                    &io,
                    &interrupts,
                    interrupt_capability,
                    interrupt_object,
                    &mut device,
                    &mut bridge,
                    &mut scratch,
                ),
                Ok(VirtualBlockProcessOutcome::Completed(_))
            ));
            vmm.next_exit = Some(VmExit::Io {
                port: VIRTUAL_BLOCK_COMPLETION_ACK_PORT,
                size: 4,
                write: true,
                value: VIRTUAL_BLOCK_COMPLETION_ACK_VALUE,
            });
            assert_eq!(
                run_virtual_block_completion_ack_once(
                    &mut vmm,
                    0,
                    &mut vms,
                    vm,
                    &mut router,
                    &capabilities,
                    &guest_memory,
                    &io,
                    &mut device,
                    &mut bridge,
                ),
                Ok(sequence)
            );
        }

        assert_eq!((backend.writes, backend.reads), (1, 1));
        assert!(vmm.bytes[0x4000..0x5000].iter().all(|byte| *byte == 0x65));
        assert_eq!(bridge.request_consumed, 2);
        assert_eq!(bridge.completion_published, 2);
        assert_eq!(bridge.completion_consumed, 2);
        assert_eq!(vms.state(vm), Ok(crate::VmState::Running));
    }

    #[test]
    fn transaction_runner_dispatches_doorbell_then_protected_acknowledgement() {
        let interrupt_object = ObjectId(96);
        let block_object = ObjectId(0x300);
        let mut capabilities = CapabilitySpace::<2>::new();
        let block_capability = capabilities
            .insert(
                block_object,
                crate::Rights::READ
                    .union(crate::Rights::WRITE)
                    .union(crate::Rights::FLUSH),
            )
            .unwrap();
        let interrupt_capability = capabilities
            .insert(interrupt_object, crate::Rights::SIGNAL)
            .unwrap();
        let mut interrupts = InterruptPolicy::deny_all();
        interrupts.allow(48).unwrap();
        let (mut vms, vm) = runner_vm();
        let mut router = HypercallRouter::new(ObjectId(97), ObjectId(98), ObjectId(99));
        let guest_memory = GuestMemory::<0>::new();
        let io = block_transaction_io_policy();
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        let request = encoded(VirtualBlockRequest::write(1, 1, 0, 1, 0x4000, 4096));
        vmm.bytes[0x4000..0x5000].fill(0x65);
        vmm.write_guest(0x1000 + QUEUE_HEADER_BYTES, &request)
            .unwrap();
        vmm.write_guest(0x1000, &1u64.to_le_bytes()).unwrap();
        vmm.next_exit = Some(VmExit::Io {
            port: VIRTUAL_BLOCK_DOORBELL_PORT,
            size: 4,
            write: true,
            value: VIRTUAL_BLOCK_DOORBELL_VALUE,
        });

        assert!(matches!(
            run_virtual_block_transaction_once(
                &mut vmm,
                &mut backend,
                VirtualBlockBackendAuthority::new(block_capability, block_object, 0, 64).unwrap(),
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &interrupts,
                interrupt_capability,
                interrupt_object,
                &mut device,
                &mut bridge,
                &mut scratch,
            ),
            Ok(VirtualBlockTransactionOutcome::Doorbell(
                VirtualBlockProcessOutcome::Completed(_)
            ))
        ));
        assert_eq!(vmm.injected, Some((0, 48)));

        vmm.next_exit = Some(VmExit::Io {
            port: VIRTUAL_BLOCK_COMPLETION_ACK_PORT,
            size: 4,
            write: true,
            value: VIRTUAL_BLOCK_COMPLETION_ACK_VALUE,
        });
        assert_eq!(
            run_virtual_block_transaction_once(
                &mut vmm,
                &mut backend,
                VirtualBlockBackendAuthority::new(block_capability, block_object, 0, 64).unwrap(),
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &interrupts,
                interrupt_capability,
                interrupt_object,
                &mut device,
                &mut bridge,
                &mut scratch,
            ),
            Ok(VirtualBlockTransactionOutcome::CompletionAcknowledged(1))
        );
        assert_eq!(vms.state(vm), Ok(crate::VmState::Running));
        assert_eq!((backend.reads, backend.writes, backend.flushes), (0, 1, 0));
        assert_eq!(bridge.completion_consumed, 1);
    }

    #[test]
    fn transaction_runner_fails_vm_on_non_transport_exit() {
        let interrupt_object = ObjectId(100);
        let block_object = ObjectId(0x300);
        let mut capabilities = CapabilitySpace::<2>::new();
        let block_capability = capabilities
            .insert(
                block_object,
                crate::Rights::READ
                    .union(crate::Rights::WRITE)
                    .union(crate::Rights::FLUSH),
            )
            .unwrap();
        let interrupt_capability = capabilities
            .insert(interrupt_object, crate::Rights::SIGNAL)
            .unwrap();
        let mut interrupts = InterruptPolicy::deny_all();
        interrupts.allow(48).unwrap();
        let (mut vms, vm) = runner_vm();
        let mut router = HypercallRouter::new(ObjectId(101), ObjectId(102), ObjectId(103));
        let guest_memory = GuestMemory::<0>::new();
        let io = block_transaction_io_policy();
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        vmm.next_exit = Some(VmExit::Halted);

        assert_eq!(
            run_virtual_block_transaction_once(
                &mut vmm,
                &mut backend,
                VirtualBlockBackendAuthority::new(block_capability, block_object, 0, 64).unwrap(),
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &interrupts,
                interrupt_capability,
                interrupt_object,
                &mut device,
                &mut bridge,
                &mut scratch,
            ),
            Err(VirtualBlockTransactionRunError::InvalidExit)
        );
        assert_eq!(vms.state(vm), Ok(crate::VmState::Failed));
        assert_eq!((backend.reads, backend.writes, backend.flushes), (0, 0, 0));
        assert!(scratch.iter().all(|byte| *byte == 0xa5));
        assert_eq!(bridge.request_consumed, 0);
        assert_eq!(bridge.completion_consumed, 0);
    }

    #[test]
    fn transaction_runner_rejects_backend_region_geometry_before_vcpu_entry() {
        let block_object = ObjectId(0x300);
        let interrupt_object = ObjectId(0x310);
        let mut capabilities = CapabilitySpace::<2>::new();
        let block_capability = capabilities
            .insert(
                block_object,
                crate::Rights::READ
                    .union(crate::Rights::WRITE)
                    .union(crate::Rights::FLUSH),
            )
            .unwrap();
        let interrupt_capability = capabilities
            .insert(interrupt_object, crate::Rights::SIGNAL)
            .unwrap();
        let mut interrupts = InterruptPolicy::deny_all();
        interrupts.allow(48).unwrap();
        let (mut vms, vm) = runner_vm();
        let mut router = HypercallRouter::new(ObjectId(0x311), ObjectId(0x312), ObjectId(0x313));
        let guest_memory = GuestMemory::<0>::new();
        let io = block_transaction_io_policy();
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        let expected_exit = VmExit::Halted;
        vmm.next_exit = Some(expected_exit);
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];

        assert_eq!(
            run_virtual_block_transaction_once(
                &mut vmm,
                &mut backend,
                VirtualBlockBackendAuthority::new(block_capability, block_object, 1, 63).unwrap(),
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &interrupts,
                interrupt_capability,
                interrupt_object,
                &mut device,
                &mut bridge,
                &mut scratch,
            ),
            Err(VirtualBlockTransactionRunError::Authority(
                VirtualBlockAuthorityError::GeometryMismatch
            ))
        );
        assert_eq!(vmm.next_exit, Some(expected_exit));
        assert_eq!(vms.state(vm), Ok(crate::VmState::Failed));
        assert_eq!((backend.reads, backend.writes, backend.flushes), (0, 0, 0));
        assert_eq!(bridge.request_consumed, 0);
        assert!(scratch.iter().all(|byte| *byte == 0xa5));
    }

    #[test]
    fn shared_runner_completes_exact_doorbell_and_authorized_interrupt() {
        let interrupt_object = ObjectId(80);
        let block_object = ObjectId(0x300);
        let mut capabilities = CapabilitySpace::<2>::new();
        let block_capability = capabilities
            .insert(
                block_object,
                crate::Rights::READ
                    .union(crate::Rights::WRITE)
                    .union(crate::Rights::FLUSH),
            )
            .unwrap();
        let interrupt_capability = capabilities
            .insert(interrupt_object, crate::Rights::SIGNAL)
            .unwrap();
        let mut interrupts = InterruptPolicy::deny_all();
        interrupts.allow(48).unwrap();
        let (mut vms, vm) = runner_vm();
        let mut router = HypercallRouter::new(ObjectId(81), ObjectId(82), ObjectId(83));
        let guest_memory = GuestMemory::<0>::new();
        let io = block_io_policy();
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        let request = encoded(VirtualBlockRequest::write(1, 1, 0, 1, 0x4000, 4096));
        vmm.bytes[0x4000..0x5000].fill(0x65);
        vmm.write_guest(0x1000 + QUEUE_HEADER_BYTES, &request)
            .unwrap();
        vmm.write_guest(0x1000, &1u64.to_le_bytes()).unwrap();
        vmm.next_exit = Some(VmExit::Io {
            port: VIRTUAL_BLOCK_DOORBELL_PORT,
            size: 4,
            write: true,
            value: VIRTUAL_BLOCK_DOORBELL_VALUE,
        });

        assert!(matches!(
            run_virtual_block_doorbell_once(
                &mut vmm,
                &mut backend,
                VirtualBlockBackendAuthority::new(block_capability, block_object, 0, 64).unwrap(),
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &interrupts,
                interrupt_capability,
                interrupt_object,
                &mut device,
                &mut bridge,
                &mut scratch,
            ),
            Ok(VirtualBlockProcessOutcome::Completed(_))
        ));
        assert_eq!(vms.state(vm), Ok(crate::VmState::Running));
        assert_eq!(backend.writes, 1);
        assert_eq!(vmm.injected, Some((0, 48)));
        assert_eq!(device.pending_interrupt_vector(), None);
    }

    #[test]
    fn shared_runner_rejects_bad_doorbell_and_fails_vm_before_queue_access() {
        let interrupt_object = ObjectId(84);
        let block_object = ObjectId(0x300);
        let mut capabilities = CapabilitySpace::<2>::new();
        let block_capability = capabilities
            .insert(
                block_object,
                crate::Rights::READ
                    .union(crate::Rights::WRITE)
                    .union(crate::Rights::FLUSH),
            )
            .unwrap();
        let interrupt_capability = capabilities
            .insert(interrupt_object, crate::Rights::SIGNAL)
            .unwrap();
        let mut interrupts = InterruptPolicy::deny_all();
        interrupts.allow(48).unwrap();
        let (mut vms, vm) = runner_vm();
        let mut router = HypercallRouter::new(ObjectId(85), ObjectId(86), ObjectId(87));
        let guest_memory = GuestMemory::<0>::new();
        let io = block_io_policy();
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        vmm.next_exit = Some(VmExit::Io {
            port: VIRTUAL_BLOCK_DOORBELL_PORT,
            size: 4,
            write: true,
            value: VIRTUAL_BLOCK_DOORBELL_VALUE + 1,
        });

        assert_eq!(
            run_virtual_block_doorbell_once(
                &mut vmm,
                &mut backend,
                VirtualBlockBackendAuthority::new(block_capability, block_object, 0, 64).unwrap(),
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &interrupts,
                interrupt_capability,
                interrupt_object,
                &mut device,
                &mut bridge,
                &mut scratch,
            ),
            Err(VirtualBlockRunError::Doorbell(
                VirtualBlockDoorbellError::InvalidExit
            ))
        );
        assert_eq!(vms.state(vm), Ok(crate::VmState::Failed));
        assert_eq!((backend.reads, backend.writes, backend.flushes), (0, 0, 0));
        assert!(scratch.iter().all(|byte| *byte == 0xa5));
    }

    #[test]
    fn shared_runner_injection_failure_retains_completion_and_fails_vm() {
        let interrupt_object = ObjectId(88);
        let block_object = ObjectId(0x300);
        let mut capabilities = CapabilitySpace::<2>::new();
        let block_capability = capabilities
            .insert(
                block_object,
                crate::Rights::READ
                    .union(crate::Rights::WRITE)
                    .union(crate::Rights::FLUSH),
            )
            .unwrap();
        let interrupt_capability = capabilities
            .insert(interrupt_object, crate::Rights::SIGNAL)
            .unwrap();
        let mut interrupts = InterruptPolicy::deny_all();
        interrupts.allow(48).unwrap();
        let (mut vms, vm) = runner_vm();
        let mut router = HypercallRouter::new(ObjectId(89), ObjectId(90), ObjectId(91));
        let guest_memory = GuestMemory::<0>::new();
        let io = block_io_policy();
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        let request = encoded(VirtualBlockRequest::write(1, 1, 0, 1, 0x4000, 4096));
        vmm.write_guest(0x1000 + QUEUE_HEADER_BYTES, &request)
            .unwrap();
        vmm.write_guest(0x1000, &1u64.to_le_bytes()).unwrap();
        vmm.next_exit = Some(VmExit::Io {
            port: VIRTUAL_BLOCK_DOORBELL_PORT,
            size: 4,
            write: true,
            value: VIRTUAL_BLOCK_DOORBELL_VALUE,
        });
        vmm.fail_inject = true;

        assert_eq!(
            run_virtual_block_doorbell_once(
                &mut vmm,
                &mut backend,
                VirtualBlockBackendAuthority::new(block_capability, block_object, 0, 64).unwrap(),
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &interrupts,
                interrupt_capability,
                interrupt_object,
                &mut device,
                &mut bridge,
                &mut scratch,
            ),
            Err(VirtualBlockRunError::Interrupt(
                VirtualBlockInterruptError::Injection(VmRunError::Backend(MockError::Injected))
            ))
        );
        assert_eq!(vms.state(vm), Ok(crate::VmState::Failed));
        assert_eq!(backend.writes, 1);
        assert_eq!(device.pending_interrupt_vector(), Some(48));
    }

    #[test]
    fn shared_runner_delivers_pending_notification_before_vcpu_entry() {
        let interrupt_object = ObjectId(92);
        let block_object = ObjectId(0x300);
        let mut capabilities = CapabilitySpace::<2>::new();
        let block_capability = capabilities
            .insert(
                block_object,
                crate::Rights::READ
                    .union(crate::Rights::WRITE)
                    .union(crate::Rights::FLUSH),
            )
            .unwrap();
        let interrupt_capability = capabilities
            .insert(interrupt_object, crate::Rights::SIGNAL)
            .unwrap();
        let mut interrupts = InterruptPolicy::deny_all();
        interrupts.allow(48).unwrap();
        let (mut vms, vm) = runner_vm();
        let mut router = HypercallRouter::new(ObjectId(93), ObjectId(94), ObjectId(95));
        let guest_memory = GuestMemory::<0>::new();
        let io = block_io_policy();
        let mut device = active::<1>();
        device.latch_completion_interrupt().unwrap();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        let expected_exit = VmExit::Io {
            port: VIRTUAL_BLOCK_DOORBELL_PORT,
            size: 4,
            write: true,
            value: VIRTUAL_BLOCK_DOORBELL_VALUE,
        };
        vmm.next_exit = Some(expected_exit);
        vmm.fail_inject = true;
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];

        assert!(matches!(
            run_virtual_block_doorbell_once(
                &mut vmm,
                &mut backend,
                VirtualBlockBackendAuthority::new(block_capability, block_object, 0, 64).unwrap(),
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &interrupts,
                interrupt_capability,
                interrupt_object,
                &mut device,
                &mut bridge,
                &mut scratch,
            ),
            Err(VirtualBlockRunError::Interrupt(_))
        ));
        assert_eq!(vmm.next_exit, Some(expected_exit));
        assert_eq!(vms.state(vm), Ok(crate::VmState::Failed));
        assert_eq!(device.pending_interrupt_vector(), Some(48));
        assert_eq!((backend.reads, backend.writes, backend.flushes), (0, 0, 0));
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
        bridge.publish_completion(&mut vmm, completion).unwrap();
        assert_eq!(bridge.completion_consumed, 0);
        assert_eq!(bridge.completion_published, 1);
        let completion_slot = 0x3000 + QUEUE_HEADER_BYTES;
        assert_eq!(
            VirtualBlockCompletion::decode(
                &vmm.bytes[completion_slot as usize
                    ..completion_slot as usize + VIRTUAL_BLOCK_COMPLETION_BYTES]
            ),
            Ok(completion)
        );
    }

    fn exact_completion_ack() -> ExitDisposition {
        ExitDisposition::Io {
            port: VIRTUAL_BLOCK_COMPLETION_ACK_PORT,
            size: 4,
            write: true,
            value: VIRTUAL_BLOCK_COMPLETION_ACK_VALUE,
        }
    }

    fn published_completion<const N: usize>(
        device: &mut VirtualBlockDevice<N>,
        bridge: &mut VirtualBlockQueueBridge<N>,
        vmm: &mut MockVmm,
    ) -> VirtualBlockCompletion {
        let request = VirtualBlockRequest::flush(device.generation(), 1);
        let mut encoded = [0; VIRTUAL_BLOCK_REQUEST_BYTES];
        request.encode(&mut encoded);
        let admitted = device.admit(&encoded).unwrap();
        let completion = device
            .complete(admitted.ticket(), VirtualBlockCompletionStatus::Ok, 0)
            .unwrap();
        bridge.publish_completion(vmm, completion).unwrap();
        completion
    }

    #[test]
    fn completion_ack_advances_one_protected_counter_and_restores_capacity() {
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        published_completion(&mut device, &mut bridge, &mut vmm);
        assert_eq!(bridge.completion_ready(&vmm), Ok(false));

        assert_eq!(
            process_virtual_block_completion_ack(
                exact_completion_ack(),
                &mut device,
                &mut bridge,
                &mut vmm,
            ),
            Ok(1)
        );
        assert_eq!(bridge.completion_consumed, 1);
        assert_eq!(bridge.completion_ready(&vmm), Ok(true));
        let mut consumed = [0; 8];
        vmm.read_guest(0x3000 + 64, &mut consumed).unwrap();
        assert_eq!(u64::from_le_bytes(consumed), 1);
    }

    #[test]
    fn completion_ack_rechecks_every_scalar_before_state_or_memory_access() {
        for disposition in [
            ExitDisposition::Io {
                port: VIRTUAL_BLOCK_COMPLETION_ACK_PORT + 1,
                size: 4,
                write: true,
                value: VIRTUAL_BLOCK_COMPLETION_ACK_VALUE,
            },
            ExitDisposition::Io {
                port: VIRTUAL_BLOCK_COMPLETION_ACK_PORT,
                size: 2,
                write: true,
                value: VIRTUAL_BLOCK_COMPLETION_ACK_VALUE,
            },
            ExitDisposition::Io {
                port: VIRTUAL_BLOCK_COMPLETION_ACK_PORT,
                size: 4,
                write: false,
                value: VIRTUAL_BLOCK_COMPLETION_ACK_VALUE,
            },
            ExitDisposition::Io {
                port: VIRTUAL_BLOCK_COMPLETION_ACK_PORT,
                size: 4,
                write: true,
                value: VIRTUAL_BLOCK_COMPLETION_ACK_VALUE + 1,
            },
            ExitDisposition::Stopped,
        ] {
            let mut device = active::<1>();
            let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
            let mut vmm = MockVmm::new();
            published_completion(&mut device, &mut bridge, &mut vmm);
            vmm.fail_write = true;
            assert_eq!(
                process_virtual_block_completion_ack(
                    disposition,
                    &mut device,
                    &mut bridge,
                    &mut vmm,
                ),
                Err(VirtualBlockCompletionAckError::InvalidExit)
            );
            assert_eq!(device.state(), VirtualBlockDeviceState::Active);
            assert!(!bridge.is_poisoned());
            assert_eq!(bridge.completion_consumed, 0);
        }
    }

    #[test]
    fn premature_or_uncertain_completion_ack_fails_closed() {
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        published_completion(&mut device, &mut bridge, &mut vmm);
        device.latch_completion_interrupt().unwrap();
        assert!(matches!(
            process_virtual_block_completion_ack(
                exact_completion_ack(),
                &mut device,
                &mut bridge,
                &mut vmm,
            ),
            Err(VirtualBlockCompletionAckError::Queue {
                error: VirtualBlockQueueError::Protocol(VirtualBlockError::InvalidState),
                ..
            })
        ));
        assert_eq!(device.state(), VirtualBlockDeviceState::Failed);
        assert!(bridge.is_poisoned());

        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        published_completion(&mut device, &mut bridge, &mut vmm);
        vmm.fail_write = true;
        assert!(matches!(
            process_virtual_block_completion_ack(
                exact_completion_ack(),
                &mut device,
                &mut bridge,
                &mut vmm,
            ),
            Err(VirtualBlockCompletionAckError::Queue {
                error: VirtualBlockQueueError::Backend(MockError::Injected),
                ..
            })
        ));
        assert_eq!(device.state(), VirtualBlockDeviceState::Failed);
        assert!(bridge.is_poisoned());
        assert_eq!(bridge.completion_consumed, 0);
    }

    #[test]
    fn empty_completion_ack_fails_device_and_bridge_closed() {
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        assert!(matches!(
            process_virtual_block_completion_ack(
                exact_completion_ack(),
                &mut device,
                &mut bridge,
                &mut vmm,
            ),
            Err(VirtualBlockCompletionAckError::Queue {
                error: VirtualBlockQueueError::Protocol(VirtualBlockError::QueueEmpty),
                ..
            })
        ));
        assert_eq!(device.state(), VirtualBlockDeviceState::Failed);
        assert!(bridge.is_poisoned());
        assert_eq!(bridge.completion_consumed, 0);
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
