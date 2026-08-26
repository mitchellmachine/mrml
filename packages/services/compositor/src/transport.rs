use core::array;
use mrml_interface_gui_surface_v1 as abi;
use mrml_kernel::{
    Capability, ControlEvent, Endpoint, GraphicsProtocolError, SurfaceDataPlaneBinding, TaskId,
    TaskRuntime, TaskRuntimeError, admit_surface_interface_commit,
};

use crate::GraphicsObjectRegistry;

pub const SURFACE_CALL_BYTES: usize = abi::COMMIT_REQUEST_BYTES + abi::SURFACE_STATE_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SurfaceCallFrame {
    bytes: [u8; SURFACE_CALL_BYTES],
}

impl SurfaceCallFrame {
    const EMPTY: Self = Self {
        bytes: [0; SURFACE_CALL_BYTES],
    };

    pub const fn bytes(&self) -> &[u8; SURFACE_CALL_BYTES] {
        &self.bytes
    }
}

pub fn encode_surface_call(
    surface: abi::OpaqueHandle,
    output: abi::OpaqueHandle,
    buffer: abi::OpaqueHandle,
    state: abi::SurfaceState,
) -> Result<SurfaceCallFrame, abi::SurfaceProtocolError> {
    let state_bytes = abi::encode_surface_state(state)?;
    let view = abi::BorrowedReadView::within(
        0,
        abi::SURFACE_STATE_BYTES as u64,
        abi::SURFACE_STATE_BYTES as u64,
    )
    .ok_or(abi::SurfaceProtocolError::InvalidView)?;
    let request = abi::encode_commit_request(surface, output, buffer, view)?;
    let mut bytes = [0; SURFACE_CALL_BYTES];
    bytes[..abi::COMMIT_REQUEST_BYTES].copy_from_slice(&request);
    bytes[abi::COMMIT_REQUEST_BYTES..].copy_from_slice(&state_bytes);
    Ok(SurfaceCallFrame { bytes })
}

pub fn decode_surface_call(
    payload: &[u8],
) -> Result<(abi::CommitEnvelope, abi::SurfaceState), abi::SurfaceProtocolError> {
    if payload.len() != SURFACE_CALL_BYTES {
        return Err(abi::SurfaceProtocolError::InvalidView);
    }
    let request: [u8; abi::COMMIT_REQUEST_BYTES] = payload[..abi::COMMIT_REQUEST_BYTES]
        .try_into()
        .map_err(|_| abi::SurfaceProtocolError::InvalidHeader)?;
    let state_bytes: [u8; abi::SURFACE_STATE_BYTES] = payload[abi::COMMIT_REQUEST_BYTES..]
        .try_into()
        .map_err(|_| abi::SurfaceProtocolError::InvalidState)?;
    let envelope = abi::decode_commit_request(&request, abi::SURFACE_STATE_BYTES as u64)?;
    if envelope.state.offset() != 0 || envelope.state.length() != abi::SURFACE_STATE_BYTES as u64 {
        return Err(abi::SurfaceProtocolError::InvalidView);
    }
    let state = abi::decode_surface_state(&state_bytes)?;
    Ok((envelope, state))
}

#[derive(Debug, Eq, PartialEq)]
pub enum SurfaceNativeTransportError {
    Runtime(TaskRuntimeError),
    PeerDied,
    UnexpectedSender,
    CapabilityShape,
    Protocol(abi::SurfaceProtocolError),
    Admission(GraphicsProtocolError),
}

fn send_response<const TASKS: usize, const CAPS: usize>(
    runtime: &mut TaskRuntime<TASKS, CAPS>,
    service: TaskId,
    caller: TaskId,
    reply_endpoint: &mut Endpoint,
    reply_capability: Capability,
    response: [u8; abi::COMMIT_RESPONSE_BYTES],
) -> Result<(), SurfaceNativeTransportError> {
    runtime
        .deliver_ipc(
            service,
            caller,
            reply_endpoint,
            reply_capability,
            &response,
            &[],
        )
        .map(|_| ())
        .map_err(SurfaceNativeTransportError::Runtime)
}

fn commit_error_for_graphics(error: GraphicsProtocolError) -> abi::CommitError {
    match error {
        GraphicsProtocolError::InvalidCapability => abi::CommitError::PermissionDenied,
        GraphicsProtocolError::InvalidIdentity
        | GraphicsProtocolError::InvalidGeneration
        | GraphicsProtocolError::WrongObject => abi::CommitError::StaleObject,
        GraphicsProtocolError::InvalidGeometry
        | GraphicsProtocolError::InvalidScale
        | GraphicsProtocolError::InvalidBuffer
        | GraphicsProtocolError::InvalidDamage
        | GraphicsProtocolError::InterfaceRejected => abi::CommitError::InvalidRequest,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn serve_native_surface_once<const TASKS: usize, const CAPS: usize, const OBJECTS: usize>(
    runtime: &mut TaskRuntime<TASKS, CAPS>,
    caller: TaskId,
    service: TaskId,
    reply_endpoint: &mut Endpoint,
    reply_capability: Capability,
    registry: &mut GraphicsObjectRegistry<OBJECTS>,
) -> Result<SurfaceDataPlaneBinding, SurfaceNativeTransportError> {
    let received = match runtime
        .receive_control(service)
        .map_err(SurfaceNativeTransportError::Runtime)?
    {
        ControlEvent::Message(message) => message,
        ControlEvent::PeerDied(_) => return Err(SurfaceNativeTransportError::PeerDied),
    };
    if received.sender() != caller {
        return Err(SurfaceNativeTransportError::UnexpectedSender);
    }
    let message = received.into_message();
    message
        .authorize_no_capabilities()
        .map_err(|_| SurfaceNativeTransportError::CapabilityShape)?;
    let (envelope, state) = match decode_surface_call(message.payload()) {
        Ok(decoded) => decoded,
        Err(error) => {
            send_response(
                runtime,
                service,
                caller,
                reply_endpoint,
                reply_capability,
                abi::encode_commit_response(Err(abi::CommitError::InvalidRequest)),
            )?;
            return Err(SurfaceNativeTransportError::Protocol(error));
        }
    };
    let admitted = match admit_surface_interface_commit(
        runtime
            .capabilities(service)
            .map_err(SurfaceNativeTransportError::Runtime)?,
        registry,
        envelope,
        state,
    ) {
        Ok(admitted) => admitted,
        Err(error) => {
            let response_error = commit_error_for_graphics(error);
            send_response(
                runtime,
                service,
                caller,
                reply_endpoint,
                reply_capability,
                abi::encode_commit_response(Err(response_error)),
            )?;
            return Err(SurfaceNativeTransportError::Admission(error));
        }
    };
    let binding = admitted.into_data_plane();
    send_response(
        runtime,
        service,
        caller,
        reply_endpoint,
        reply_capability,
        abi::encode_commit_response(Ok(binding.serial())),
    )?;
    Ok(binding)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SurfaceMicrovmTicket {
    queue_generation: u64,
    sequence: u64,
}

impl SurfaceMicrovmTicket {
    pub const fn queue_generation(self) -> u64 {
        self.queue_generation
    }

    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SurfaceMicrovmQueueError {
    InvalidGeneration,
    InvalidCapacity,
    Full,
    Empty,
    StaleTicket,
    OutOfOrder,
    SequenceExhausted,
    CompletionOccupied,
    InvalidResponse,
}

#[derive(Clone, Copy)]
struct RequestSlot {
    sequence: u64,
    frame: SurfaceCallFrame,
    ready: bool,
    inflight: bool,
}

impl RequestSlot {
    const EMPTY: Self = Self {
        sequence: 0,
        frame: SurfaceCallFrame::EMPTY,
        ready: false,
        inflight: false,
    };
}

#[derive(Clone, Copy)]
struct CompletionSlot {
    sequence: u64,
    response: [u8; abi::COMMIT_RESPONSE_BYTES],
    ready: bool,
}

impl CompletionSlot {
    const EMPTY: Self = Self {
        sequence: 0,
        response: [0; abi::COMMIT_RESPONSE_BYTES],
        ready: false,
    };
}

/// Backend-neutral fixed queue used by the application-microVM projection.
///
/// The control plane establishes authority in the capability space and object
/// registry before this shortest-safe-path data plane is serviced. Queue bytes
/// are exactly the native `SurfaceCallFrame`; queue identity, tickets, and
/// lifecycle carry no graphics authority.
pub struct SurfaceMicrovmQueue<const N: usize> {
    generation: u64,
    requests: [RequestSlot; N],
    completions: [CompletionSlot; N],
    next_submit: u64,
    next_receive: u64,
    next_complete: u64,
    next_collect: u64,
}

impl<const N: usize> SurfaceMicrovmQueue<N> {
    pub fn new(generation: u64) -> Result<Self, SurfaceMicrovmQueueError> {
        if generation == 0 {
            return Err(SurfaceMicrovmQueueError::InvalidGeneration);
        }
        if N == 0 || N > 64 {
            return Err(SurfaceMicrovmQueueError::InvalidCapacity);
        }
        Ok(Self {
            generation,
            requests: array::from_fn(|_| RequestSlot::EMPTY),
            completions: array::from_fn(|_| CompletionSlot::EMPTY),
            next_submit: 1,
            next_receive: 1,
            next_complete: 1,
            next_collect: 1,
        })
    }

    pub fn guest_submit(
        &mut self,
        frame: SurfaceCallFrame,
    ) -> Result<SurfaceMicrovmTicket, SurfaceMicrovmQueueError> {
        let sequence = self.next_submit;
        let next = sequence
            .checked_add(1)
            .ok_or(SurfaceMicrovmQueueError::SequenceExhausted)?;
        let index = ((sequence - 1) % N as u64) as usize;
        let slot = &mut self.requests[index];
        if slot.ready || slot.inflight || self.completions[index].ready {
            return Err(SurfaceMicrovmQueueError::Full);
        }
        slot.sequence = sequence;
        slot.frame = frame;
        slot.ready = true;
        self.next_submit = next;
        Ok(SurfaceMicrovmTicket {
            queue_generation: self.generation,
            sequence,
        })
    }

    pub fn host_receive(
        &mut self,
    ) -> Result<(SurfaceMicrovmTicket, SurfaceCallFrame), SurfaceMicrovmQueueError> {
        let sequence = self.next_receive;
        let next = sequence
            .checked_add(1)
            .ok_or(SurfaceMicrovmQueueError::SequenceExhausted)?;
        let index = ((sequence - 1) % N as u64) as usize;
        let slot = &mut self.requests[index];
        if !slot.ready {
            return Err(SurfaceMicrovmQueueError::Empty);
        }
        if slot.sequence != sequence || slot.inflight {
            return Err(SurfaceMicrovmQueueError::OutOfOrder);
        }
        slot.ready = false;
        slot.inflight = true;
        self.next_receive = next;
        Ok((
            SurfaceMicrovmTicket {
                queue_generation: self.generation,
                sequence,
            },
            slot.frame,
        ))
    }

    pub fn host_complete(
        &mut self,
        ticket: SurfaceMicrovmTicket,
        response: [u8; abi::COMMIT_RESPONSE_BYTES],
    ) -> Result<(), SurfaceMicrovmQueueError> {
        self.validate_ticket(ticket)?;
        if ticket.sequence != self.next_complete {
            return Err(SurfaceMicrovmQueueError::OutOfOrder);
        }
        let next = ticket
            .sequence
            .checked_add(1)
            .ok_or(SurfaceMicrovmQueueError::SequenceExhausted)?;
        let index = ((ticket.sequence - 1) % N as u64) as usize;
        let request = &mut self.requests[index];
        if !request.inflight || request.sequence != ticket.sequence {
            return Err(SurfaceMicrovmQueueError::StaleTicket);
        }
        let completion = &mut self.completions[index];
        if completion.ready {
            return Err(SurfaceMicrovmQueueError::CompletionOccupied);
        }
        let _decoded = abi::decode_commit_response(&response)
            .map_err(|_| SurfaceMicrovmQueueError::InvalidResponse)?;
        completion.sequence = ticket.sequence;
        completion.response = response;
        completion.ready = true;
        request.inflight = false;
        request.sequence = 0;
        request.frame = SurfaceCallFrame::EMPTY;
        self.next_complete = next;
        Ok(())
    }

    pub fn guest_collect(
        &mut self,
    ) -> Result<(SurfaceMicrovmTicket, [u8; abi::COMMIT_RESPONSE_BYTES]), SurfaceMicrovmQueueError>
    {
        let sequence = self.next_collect;
        let next = sequence
            .checked_add(1)
            .ok_or(SurfaceMicrovmQueueError::SequenceExhausted)?;
        let index = ((sequence - 1) % N as u64) as usize;
        let slot = &mut self.completions[index];
        if !slot.ready {
            return Err(SurfaceMicrovmQueueError::Empty);
        }
        if slot.sequence != sequence {
            return Err(SurfaceMicrovmQueueError::OutOfOrder);
        }
        slot.ready = false;
        let response = slot.response;
        slot.sequence = 0;
        slot.response = [0; abi::COMMIT_RESPONSE_BYTES];
        self.next_collect = next;
        Ok((
            SurfaceMicrovmTicket {
                queue_generation: self.generation,
                sequence,
            },
            response,
        ))
    }

    pub fn reset(&mut self, generation: u64) -> Result<(), SurfaceMicrovmQueueError> {
        if generation <= self.generation {
            return Err(SurfaceMicrovmQueueError::InvalidGeneration);
        }
        *self = Self::new(generation)?;
        Ok(())
    }

    fn validate_ticket(
        &self,
        ticket: SurfaceMicrovmTicket,
    ) -> Result<(), SurfaceMicrovmQueueError> {
        if ticket.queue_generation != self.generation || ticket.sequence == 0 {
            return Err(SurfaceMicrovmQueueError::StaleTicket);
        }
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum SurfaceMicrovmServiceError {
    Queue(SurfaceMicrovmQueueError),
    Protocol(abi::SurfaceProtocolError),
    Admission(GraphicsProtocolError),
}

pub fn serve_microvm_surface_once<
    const SLOTS: usize,
    const CAPABILITIES: usize,
    const OBJECTS: usize,
>(
    queue: &mut SurfaceMicrovmQueue<SLOTS>,
    capabilities: &mrml_kernel::CapabilitySpace<CAPABILITIES>,
    registry: &mut GraphicsObjectRegistry<OBJECTS>,
) -> Result<SurfaceDataPlaneBinding, SurfaceMicrovmServiceError> {
    let (ticket, frame) = queue
        .host_receive()
        .map_err(SurfaceMicrovmServiceError::Queue)?;
    let (envelope, state) = match decode_surface_call(frame.bytes()) {
        Ok(decoded) => decoded,
        Err(error) => {
            queue
                .host_complete(
                    ticket,
                    abi::encode_commit_response(Err(abi::CommitError::InvalidRequest)),
                )
                .map_err(SurfaceMicrovmServiceError::Queue)?;
            return Err(SurfaceMicrovmServiceError::Protocol(error));
        }
    };
    let admitted = match admit_surface_interface_commit(capabilities, registry, envelope, state) {
        Ok(admitted) => admitted,
        Err(error) => {
            queue
                .host_complete(
                    ticket,
                    abi::encode_commit_response(Err(commit_error_for_graphics(error))),
                )
                .map_err(SurfaceMicrovmServiceError::Queue)?;
            return Err(SurfaceMicrovmServiceError::Admission(error));
        }
    };
    let binding = admitted.into_data_plane();
    queue
        .host_complete(ticket, abi::encode_commit_response(Ok(binding.serial())))
        .map_err(SurfaceMicrovmServiceError::Queue)?;
    Ok(binding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GraphicsRegistryGeneration, RegisteredGraphicsObject};
    use mrml_interface_gui_surface_v1::{LogicalRect, SurfaceFormat, SurfaceState};
    use mrml_kernel::arch::x86_64::UserContext;
    use mrml_kernel::{
        CapabilitySpace, DisplayOutputIdentity, GraphicsBufferDescriptor, GraphicsFormat, ObjectId,
        PhysAddr, PhysicalExtent, Priority, Rights, SurfaceIdentity,
    };

    fn state(serial: u64) -> SurfaceState {
        SurfaceState {
            logical_bounds: LogicalRect {
                x: 0,
                y: 0,
                width: 800,
                height: 600,
            },
            scale_numerator: 1,
            scale_denominator: 1,
            buffer_width: 800,
            buffer_height: 600,
            buffer_stride: 3200,
            buffer_byte_length: 1_920_000,
            format: SurfaceFormat::Bgra8Srgb,
            serial,
            damage_count: 0,
            damage: [LogicalRect {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            }; abi::MAX_DAMAGE_RECTS],
        }
    }

    fn context(root: u64, entry: u64, stack: u64) -> UserContext {
        UserContext::new(PhysAddr::new(root).unwrap(), entry, stack).unwrap()
    }

    #[test]
    fn native_task_runtime_carries_the_exact_frame_without_capability_transfer() {
        let mut runtime = TaskRuntime::<2, 8>::new(1_000, 1).unwrap();
        let caller = runtime
            .create(Priority::NORMAL, context(0x1000, 0x2000, 0x3000))
            .unwrap();
        let service = runtime
            .create(Priority::NORMAL, context(0x4000, 0x5000, 0x6000))
            .unwrap();
        let request_object = ObjectId(100);
        let reply_object = ObjectId(101);
        let request_capability = runtime
            .capabilities_mut(caller)
            .unwrap()
            .insert(request_object, Rights::SIGNAL)
            .unwrap();
        let reply_capability = runtime
            .capabilities_mut(service)
            .unwrap()
            .insert(reply_object, Rights::SIGNAL)
            .unwrap();
        let surface = SurfaceIdentity::new(ObjectId(10), 5).unwrap();
        let output = DisplayOutputIdentity::new(ObjectId(20), 6).unwrap();
        let buffer = GraphicsBufferDescriptor::new(
            ObjectId(30),
            7,
            PhysicalExtent::new(800, 600).unwrap(),
            3200,
            1_920_000,
            GraphicsFormat::Bgra8Srgb,
        )
        .unwrap();
        let surface_capability = runtime
            .capabilities_mut(service)
            .unwrap()
            .insert(ObjectId(10), Rights::CONTROL)
            .unwrap();
        let output_capability = runtime
            .capabilities_mut(service)
            .unwrap()
            .insert(ObjectId(20), Rights::INSPECT)
            .unwrap();
        let buffer_capability = runtime
            .capabilities_mut(service)
            .unwrap()
            .insert(ObjectId(30), Rights::READ)
            .unwrap();
        let mut registry =
            GraphicsObjectRegistry::<3>::new(GraphicsRegistryGeneration::new(1).unwrap());
        let surface_handle = registry
            .register(RegisteredGraphicsObject::Surface {
                capability: surface_capability,
                identity: surface,
            })
            .unwrap();
        let output_handle = registry
            .register(RegisteredGraphicsObject::Output {
                capability: output_capability,
                identity: output,
            })
            .unwrap();
        let buffer_handle = registry
            .register(RegisteredGraphicsObject::Buffer {
                capability: buffer_capability,
                descriptor: buffer,
            })
            .unwrap();
        let frame =
            encode_surface_call(surface_handle, output_handle, buffer_handle, state(9)).unwrap();
        let mut request_endpoint = Endpoint::new(request_object);
        runtime
            .deliver_ipc(
                caller,
                service,
                &mut request_endpoint,
                request_capability,
                frame.bytes(),
                &[],
            )
            .unwrap();
        let mut reply_endpoint = Endpoint::new(reply_object);
        let binding = serve_native_surface_once(
            &mut runtime,
            caller,
            service,
            &mut reply_endpoint,
            reply_capability,
            &mut registry,
        )
        .unwrap();
        assert_eq!(binding.serial(), 9);
        assert_eq!(
            binding.revalidate(runtime.capabilities(service).unwrap()),
            Ok(())
        );
        let response = match runtime.receive_control(caller).unwrap() {
            ControlEvent::Message(message) => {
                assert_eq!(message.sender(), service);
                message.into_message()
            }
            ControlEvent::PeerDied(_) => panic!("unexpected peer death"),
        };
        response.authorize_no_capabilities().unwrap();
        let response: &[u8; abi::COMMIT_RESPONSE_BYTES] = response.payload().try_into().unwrap();
        assert_eq!(abi::decode_commit_response(response), Ok(Ok(9)));
    }

    #[test]
    fn microvm_queue_preserves_exact_native_frame_and_reset_stales_tickets() {
        let surface = abi::OpaqueHandle::new(1, 1).unwrap();
        let output = abi::OpaqueHandle::new(2, 1).unwrap();
        let buffer = abi::OpaqueHandle::new(3, 1).unwrap();
        let frame = encode_surface_call(surface, output, buffer, state(7)).unwrap();
        let mut queue = SurfaceMicrovmQueue::<2>::new(4).unwrap();
        let submitted = queue.guest_submit(frame).unwrap();
        let (received, exact) = queue.host_receive().unwrap();
        assert_eq!(submitted, received);
        assert_eq!(exact, frame);
        let response = abi::encode_commit_response(Ok(7));
        queue.host_complete(received, response).unwrap();
        let (completed, exact_response) = queue.guest_collect().unwrap();
        assert_eq!(completed, submitted);
        assert_eq!(abi::decode_commit_response(&exact_response), Ok(Ok(7)));

        let stale = queue.guest_submit(frame).unwrap();
        queue.reset(5).unwrap();
        assert_eq!(
            queue.host_complete(stale, response),
            Err(SurfaceMicrovmQueueError::StaleTicket)
        );
    }

    #[test]
    fn microvm_queue_reaches_the_same_registry_and_kernel_admission() {
        let mut capabilities = CapabilitySpace::<3>::new();
        let surface = SurfaceIdentity::new(ObjectId(10), 5).unwrap();
        let output = DisplayOutputIdentity::new(ObjectId(20), 6).unwrap();
        let buffer = GraphicsBufferDescriptor::new(
            ObjectId(30),
            7,
            PhysicalExtent::new(800, 600).unwrap(),
            3200,
            1_920_000,
            GraphicsFormat::Bgra8Srgb,
        )
        .unwrap();
        let surface_capability = capabilities.insert(ObjectId(10), Rights::CONTROL).unwrap();
        let output_capability = capabilities.insert(ObjectId(20), Rights::INSPECT).unwrap();
        let buffer_capability = capabilities.insert(ObjectId(30), Rights::READ).unwrap();
        let mut registry =
            GraphicsObjectRegistry::<3>::new(GraphicsRegistryGeneration::new(2).unwrap());
        let surface_handle = registry
            .register(RegisteredGraphicsObject::Surface {
                capability: surface_capability,
                identity: surface,
            })
            .unwrap();
        let output_handle = registry
            .register(RegisteredGraphicsObject::Output {
                capability: output_capability,
                identity: output,
            })
            .unwrap();
        let buffer_handle = registry
            .register(RegisteredGraphicsObject::Buffer {
                capability: buffer_capability,
                descriptor: buffer,
            })
            .unwrap();
        let frame =
            encode_surface_call(surface_handle, output_handle, buffer_handle, state(11)).unwrap();
        let mut queue = SurfaceMicrovmQueue::<2>::new(8).unwrap();
        let submitted = queue.guest_submit(frame).unwrap();
        let binding = serve_microvm_surface_once(&mut queue, &capabilities, &mut registry).unwrap();
        assert_eq!(binding.serial(), 11);
        assert_eq!(binding.surface(), surface);
        assert_eq!(binding.output(), output);
        assert_eq!(binding.buffer(), buffer);
        assert_eq!(binding.revalidate(&capabilities), Ok(()));
        let (completed, response) = queue.guest_collect().unwrap();
        assert_eq!(completed, submitted);
        assert_eq!(abi::decode_commit_response(&response), Ok(Ok(11)));
    }
}
