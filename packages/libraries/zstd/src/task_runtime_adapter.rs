use crate::{ReceivedZstdEnvelope, ZstdServiceSyscalls};
use mrml_interface_zstd_v3::{
    DECOMPRESS_REQUEST_BYTES, DECOMPRESS_RESPONSE_BYTES, INTERFACE_GENERATION,
};
use mrml_kernel::arch::x86_64::UserContext;
use mrml_kernel::{
    Capability, CapabilityError, ControlEvent, Endpoint, GuestMemory, IpcSharedBufferBackend,
    IpcSharedBufferIoError, IsolationBackendFailure, IsolationPlacement, IsolationServiceBackend,
    IsolationServiceSpec, IsolationUnavailableReason, ObjectId, Priority, ReceivedMessage, Rights,
    RoutedIsolationService, ServiceAddressSpaceEraser, ServiceCleanupError, ServiceError,
    ServiceId, ServiceState, ServiceSupervisor, SharedMemoryBindings, TaskId, TaskRuntime,
    TaskRuntimeError, TaskTerminationDispatch, TotalMicrovmClass, VmId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZstdServiceBindingError {
    InvalidGeneration,
    InvalidEndpoint,
    AdmissionMismatch,
}

/// Exact resolver and policy result expected by the caller. Names identify the
/// interface elsewhere; this object binds its capability-selected object and
/// immutable generations without granting authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZstdResolvedServiceBinding {
    interface: ObjectId,
    provider_generation: u64,
    system_generation: u64,
    policy_generation: u64,
}

impl ZstdResolvedServiceBinding {
    pub const fn new(
        interface: ObjectId,
        provider_generation: u64,
        system_generation: u64,
        policy_generation: u64,
    ) -> Result<Self, ZstdServiceBindingError> {
        if provider_generation == 0 || system_generation == 0 || policy_generation == 0 {
            return Err(ZstdServiceBindingError::InvalidGeneration);
        }
        Ok(Self {
            interface,
            provider_generation,
            system_generation,
            policy_generation,
        })
    }
}

/// Runtime identities and reply authority created by the isolation backend.
/// The endpoint becomes usable only after its route is committed.
pub struct ZstdTaskRuntimeEndpoint {
    caller: TaskId,
    provider: TaskId,
    vm: VmId,
    reply_endpoint: Endpoint,
    reply_capability: Capability,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZstdNativeServiceEndpoint {
    service: ServiceId,
    task: TaskId,
    domain: ObjectId,
    interface: ObjectId,
    provider_generation: u64,
    system_generation: u64,
    policy_generation: u64,
}

impl ZstdNativeServiceEndpoint {
    pub const fn service(self) -> ServiceId {
        self.service
    }

    pub const fn task(self) -> TaskId {
        self.task
    }

    pub const fn domain(self) -> ObjectId {
        self.domain
    }

    pub const fn interface(self) -> ObjectId {
        self.interface
    }

    pub const fn provider_generation(self) -> u64 {
        self.provider_generation
    }

    pub const fn system_generation(self) -> u64 {
        self.system_generation
    }

    pub const fn policy_generation(self) -> u64 {
        self.policy_generation
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ZstdNativeServiceError<E> {
    Binding(ZstdServiceBindingError),
    AlreadyRunning,
    RetirementDispatchPending,
    WrongEndpoint,
    Runtime(TaskRuntimeError),
    Capability(CapabilityError),
    Service(ServiceError),
    Cleanup(ServiceCleanupError<E>),
}

/// Placement backend for one exact supervised native Zstd provider. Launch
/// creates a real task/service lifecycle domain; opening the stable ABI data
/// plane is a separate, capability-creating step. A failed data-plane open
/// therefore leaves an exact endpoint that can still be revoked and cleaned.
pub struct ZstdNativeServiceBackend<
    'a,
    E,
    const TASKS: usize,
    const CAPS: usize,
    const SERVICES: usize,
> {
    runtime: &'a mut TaskRuntime<TASKS, CAPS>,
    supervisor: &'a mut ServiceSupervisor<SERVICES>,
    eraser: &'a mut E,
    expected: ZstdResolvedServiceBinding,
    caller: TaskId,
    vm: VmId,
    reply_object: ObjectId,
    priority: Priority,
    context: UserContext,
    active: Option<ZstdNativeServiceEndpoint>,
    retirement_dispatch: Option<TaskTerminationDispatch>,
}

impl<'a, E, const TASKS: usize, const CAPS: usize, const SERVICES: usize>
    ZstdNativeServiceBackend<'a, E, TASKS, CAPS, SERVICES>
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runtime: &'a mut TaskRuntime<TASKS, CAPS>,
        supervisor: &'a mut ServiceSupervisor<SERVICES>,
        eraser: &'a mut E,
        expected: ZstdResolvedServiceBinding,
        caller: TaskId,
        vm: VmId,
        reply_object: ObjectId,
        priority: Priority,
        context: UserContext,
    ) -> Result<Self, ZstdNativeServiceError<E::Error>>
    where
        E: ServiceAddressSpaceEraser,
    {
        let caller_context = runtime
            .context(caller)
            .map_err(ZstdNativeServiceError::Runtime)?;
        if reply_object.0 == 0 || caller_context.page_table() == context.page_table() {
            return Err(ZstdNativeServiceError::Binding(
                ZstdServiceBindingError::InvalidEndpoint,
            ));
        }
        Ok(Self {
            runtime,
            supervisor,
            eraser,
            expected,
            caller,
            vm,
            reply_object,
            priority,
            context,
            active: None,
            retirement_dispatch: None,
        })
    }

    pub const fn active(&self) -> Option<ZstdNativeServiceEndpoint> {
        self.active
    }

    pub fn pending_retirement_dispatch(&self) -> Option<&TaskTerminationDispatch> {
        self.retirement_dispatch.as_ref()
    }

    pub fn take_retirement_dispatch(&mut self) -> Option<TaskTerminationDispatch> {
        self.retirement_dispatch.take()
    }

    pub fn runtime_mut(&mut self) -> &mut TaskRuntime<TASKS, CAPS> {
        self.runtime
    }

    pub fn open_data_plane(
        &mut self,
        routed: RoutedIsolationService<ZstdNativeServiceEndpoint>,
    ) -> Result<
        RoutedIsolationService<ZstdTaskRuntimeEndpoint>,
        (
            RoutedIsolationService<ZstdNativeServiceEndpoint>,
            ZstdNativeServiceError<E::Error>,
        ),
    >
    where
        E: ServiceAddressSpaceEraser,
    {
        // The committed route is the control-plane proof. This projection
        // creates only the direct IPC endpoint used for steady-state traffic;
        // it cannot re-resolve a provider, change placement, or widen rights.
        let endpoint = *routed.endpoint();
        if self.active != Some(endpoint) {
            return Err((routed, ZstdNativeServiceError::WrongEndpoint));
        }
        let space = match self.runtime.capabilities_mut(endpoint.task) {
            Ok(space) => space,
            Err(error) => return Err((routed, ZstdNativeServiceError::Runtime(error))),
        };
        let reply_capability = match space.insert(self.reply_object, Rights::SIGNAL) {
            Ok(capability) => capability,
            Err(error) => return Err((routed, ZstdNativeServiceError::Capability(error))),
        };
        let transport = match ZstdTaskRuntimeEndpoint::new(
            self.caller,
            endpoint.task,
            self.vm,
            Endpoint::new(self.reply_object),
            reply_capability,
        ) {
            Ok(transport) => transport,
            Err(error) => return Err((routed, ZstdNativeServiceError::Binding(error))),
        };
        Ok(routed.map_endpoint(|_| transport))
    }
}

impl<
        E: ServiceAddressSpaceEraser,
        const TASKS: usize,
        const CAPS: usize,
        const SERVICES: usize,
    > IsolationServiceBackend for ZstdNativeServiceBackend<'_, E, TASKS, CAPS, SERVICES>
{
    type Endpoint = ZstdNativeServiceEndpoint;
    type Error = ZstdNativeServiceError<E::Error>;

    fn launch_native_service(
        &mut self,
        spec: IsolationServiceSpec,
    ) -> Result<Self::Endpoint, IsolationBackendFailure<Self::Error>> {
        if self.active.is_some() {
            return Err(IsolationBackendFailure::new(
                IsolationUnavailableReason::NativeServiceResource,
                ZstdNativeServiceError::AlreadyRunning,
            ));
        }
        if self.retirement_dispatch.is_some() {
            return Err(IsolationBackendFailure::new(
                IsolationUnavailableReason::NativeServiceResource,
                ZstdNativeServiceError::RetirementDispatchPending,
            ));
        }
        if spec.interface() != self.expected.interface
            || spec.interface_generation() != INTERFACE_GENERATION
            || spec.provider_generation() != self.expected.provider_generation
            || spec.system_generation() != self.expected.system_generation
            || spec.policy_generation() != self.expected.policy_generation
            || spec.class() != TotalMicrovmClass::MicrovmEligible
            || spec.placement() != IsolationPlacement::NativeService
        {
            return Err(IsolationBackendFailure::new(
                IsolationUnavailableReason::InterfaceTransport,
                ZstdNativeServiceError::Binding(ZstdServiceBindingError::AdmissionMismatch),
            ));
        }
        let (service, task) = self
            .supervisor
            .launch(spec.domain(), self.runtime, self.priority, self.context)
            .map_err(|error| {
                IsolationBackendFailure::new(
                    IsolationUnavailableReason::NativeServiceResource,
                    ZstdNativeServiceError::Service(error),
                )
            })?;
        let endpoint = ZstdNativeServiceEndpoint {
            service,
            task,
            domain: spec.domain(),
            interface: spec.interface(),
            provider_generation: spec.provider_generation(),
            system_generation: spec.system_generation(),
            policy_generation: spec.policy_generation(),
        };
        self.active = Some(endpoint);
        Ok(endpoint)
    }

    fn launch_microvm_service(
        &mut self,
        _spec: IsolationServiceSpec,
    ) -> Result<Self::Endpoint, IsolationBackendFailure<Self::Error>> {
        Err(IsolationBackendFailure::new(
            IsolationUnavailableReason::VmmResource,
            ZstdNativeServiceError::Binding(ZstdServiceBindingError::AdmissionMismatch),
        ))
    }

    fn revoke(&mut self, endpoint: &Self::Endpoint) -> Result<(), Self::Error> {
        if self.active != Some(*endpoint) {
            return Err(ZstdNativeServiceError::WrongEndpoint);
        }
        let cleanup = match self
            .supervisor
            .state(endpoint.service)
            .map_err(ZstdNativeServiceError::Service)?
        {
            ServiceState::Running => {
                let retirement = self
                    .supervisor
                    .exit_current(self.runtime)
                    .map_err(ZstdNativeServiceError::Service)?;
                self.retirement_dispatch = Some(retirement.dispatch);
                retirement.cleanup
            }
            ServiceState::Exited | ServiceState::Faulted => self
                .supervisor
                .pending_cleanup(endpoint.service)
                .map_err(ZstdNativeServiceError::Service)?
                .ok_or(ZstdNativeServiceError::WrongEndpoint)?,
        };
        if cleanup.task() != endpoint.task {
            return Err(ZstdNativeServiceError::WrongEndpoint);
        }
        self.supervisor
            .complete_cleanup(cleanup, self.eraser)
            .map_err(ZstdNativeServiceError::Cleanup)?;
        self.active = None;
        Ok(())
    }
}

impl ZstdTaskRuntimeEndpoint {
    pub fn new(
        caller: TaskId,
        provider: TaskId,
        vm: VmId,
        reply_endpoint: Endpoint,
        reply_capability: Capability,
    ) -> Result<Self, ZstdServiceBindingError> {
        if caller == provider {
            return Err(ZstdServiceBindingError::InvalidEndpoint);
        }
        Ok(Self {
            caller,
            provider,
            vm,
            reply_endpoint,
            reply_capability,
        })
    }
}

/// A committed route whose immutable identity matches the resolver and policy
/// result. A mismatch returns the complete live route so its endpoint can be
/// revoked through the normal isolation lifecycle.
pub struct ZstdAdmittedTaskRuntimeEndpoint {
    routed: RoutedIsolationService<ZstdTaskRuntimeEndpoint>,
}

impl ZstdAdmittedTaskRuntimeEndpoint {
    pub fn bind(
        routed: RoutedIsolationService<ZstdTaskRuntimeEndpoint>,
        expected: ZstdResolvedServiceBinding,
    ) -> Result<
        Self,
        (
            RoutedIsolationService<ZstdTaskRuntimeEndpoint>,
            ZstdServiceBindingError,
        ),
    > {
        if routed.interface() != expected.interface
            || routed.interface_generation() != INTERFACE_GENERATION
            || routed.provider_generation() != expected.provider_generation
            || routed.system_generation() != expected.system_generation
            || routed.policy_generation() != expected.policy_generation
            || routed.class() != TotalMicrovmClass::MicrovmEligible
            || !matches!(
                routed.placement(),
                IsolationPlacement::NativeService | IsolationPlacement::Microvm
            )
        {
            return Err((routed, ZstdServiceBindingError::AdmissionMismatch));
        }
        Ok(Self { routed })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZstdTaskRuntimeAdapterError<E> {
    Runtime(TaskRuntimeError),
    Buffer(IpcSharedBufferIoError<E>),
    PeerDied,
    UnexpectedSender,
    InvalidEnvelope,
    MissingRequest,
    CapabilityMismatch,
}

/// Hosted composition proof for the exact runtime operations a native service
/// or microVM adapter must perform. Caller, provider, VM, and reply authority
/// are immutable launch-time state.
pub struct ZstdTaskRuntimeAdapter<
    'a,
    const TASKS: usize,
    const CAPS: usize,
    const MAPPINGS: usize,
    const BINDINGS: usize,
    B: IpcSharedBufferBackend,
> {
    runtime: &'a mut TaskRuntime<TASKS, CAPS>,
    caller: TaskId,
    provider: TaskId,
    vm: VmId,
    reply_endpoint: Endpoint,
    reply_capability: Capability,
    bindings: &'a SharedMemoryBindings<BINDINGS>,
    memory: &'a GuestMemory<MAPPINGS>,
    backend: &'a mut B,
    domain: ObjectId,
    provider_generation: u64,
    system_generation: u64,
    policy_generation: u64,
    placement: IsolationPlacement,
    received: Option<ReceivedMessage>,
    reply_ready: bool,
}

impl<
        'a,
        const TASKS: usize,
        const CAPS: usize,
        const MAPPINGS: usize,
        const BINDINGS: usize,
        B: IpcSharedBufferBackend,
    > ZstdTaskRuntimeAdapter<'a, TASKS, CAPS, MAPPINGS, BINDINGS, B>
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runtime: &'a mut TaskRuntime<TASKS, CAPS>,
        admitted: ZstdAdmittedTaskRuntimeEndpoint,
        bindings: &'a SharedMemoryBindings<BINDINGS>,
        memory: &'a GuestMemory<MAPPINGS>,
        backend: &'a mut B,
    ) -> Self {
        let routed = admitted.routed;
        let domain = routed.domain();
        let provider_generation = routed.provider_generation();
        let system_generation = routed.system_generation();
        let policy_generation = routed.policy_generation();
        let placement = routed.placement();
        let endpoint = routed.into_endpoint();
        Self {
            runtime,
            caller: endpoint.caller,
            provider: endpoint.provider,
            vm: endpoint.vm,
            reply_endpoint: endpoint.reply_endpoint,
            reply_capability: endpoint.reply_capability,
            bindings,
            memory,
            backend,
            domain,
            provider_generation,
            system_generation,
            policy_generation,
            placement,
            received: None,
            reply_ready: false,
        }
    }

    pub const fn domain(&self) -> ObjectId {
        self.domain
    }

    pub const fn provider_generation(&self) -> u64 {
        self.provider_generation
    }

    pub const fn system_generation(&self) -> u64 {
        self.system_generation
    }

    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    pub const fn placement(&self) -> IsolationPlacement {
        self.placement
    }

    fn reject_received(
        &mut self,
        received: ReceivedMessage,
        error: ZstdTaskRuntimeAdapterError<B::Error>,
    ) -> Result<ReceivedZstdEnvelope, ZstdTaskRuntimeAdapterError<B::Error>> {
        for capability in received.message().capabilities() {
            self.runtime
                .revoke_capability(self.provider, capability)
                .map_err(ZstdTaskRuntimeAdapterError::Runtime)?;
        }
        Err(error)
    }
}

unsafe impl<
        const TASKS: usize,
        const CAPS: usize,
        const MAPPINGS: usize,
        const BINDINGS: usize,
        B: IpcSharedBufferBackend,
    > ZstdServiceSyscalls for ZstdTaskRuntimeAdapter<'_, TASKS, CAPS, MAPPINGS, BINDINGS, B>
{
    type Error = ZstdTaskRuntimeAdapterError<B::Error>;

    fn receive(
        &mut self,
        request: &mut [u8; DECOMPRESS_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
    ) -> Result<ReceivedZstdEnvelope, Self::Error> {
        if self.received.is_some() {
            return Err(ZstdTaskRuntimeAdapterError::InvalidEnvelope);
        }
        let received = match self
            .runtime
            .receive_control(self.provider)
            .map_err(ZstdTaskRuntimeAdapterError::Runtime)?
        {
            ControlEvent::Message(message) => message,
            ControlEvent::PeerDied(_) => return Err(ZstdTaskRuntimeAdapterError::PeerDied),
        };
        if received.sender() != self.caller {
            return self.reject_received(received, ZstdTaskRuntimeAdapterError::UnexpectedSender);
        }
        let message = received.message();
        if message.payload().len() != DECOMPRESS_REQUEST_BYTES || message.capability_count() != 1 {
            return self.reject_received(received, ZstdTaskRuntimeAdapterError::InvalidEnvelope);
        }
        let capability = message
            .capabilities()
            .next()
            .ok_or(ZstdTaskRuntimeAdapterError::InvalidEnvelope)?;
        request.copy_from_slice(message.payload());
        capability_tokens[0] = capability.token();
        self.received = Some(received);
        self.reply_ready = false;
        Ok(ReceivedZstdEnvelope {
            payload_length: DECOMPRESS_REQUEST_BYTES,
            capability_count: 1,
        })
    }

    fn read_shared(
        &mut self,
        capability: Capability,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        let Self {
            runtime,
            provider,
            vm,
            bindings,
            memory,
            backend,
            received,
            ..
        } = self;
        let message = received
            .as_ref()
            .map(ReceivedMessage::message)
            .ok_or(ZstdTaskRuntimeAdapterError::MissingRequest)?;
        if message.capabilities().next() != Some(capability) {
            return Err(ZstdTaskRuntimeAdapterError::CapabilityMismatch);
        }
        let rights = Rights::MAP.union(Rights::READ).union(Rights::WRITE);
        message
            .read_selected_shared_buffer(
                runtime
                    .capabilities_mut(*provider)
                    .map_err(ZstdTaskRuntimeAdapterError::Runtime)?,
                rights,
                bindings,
                memory,
                *vm,
                *provider,
                offset,
                output,
                *backend,
            )
            .map_err(ZstdTaskRuntimeAdapterError::Buffer)
    }

    fn write_shared(
        &mut self,
        capability: Capability,
        offset: u64,
        input: &[u8],
    ) -> Result<(), Self::Error> {
        let Self {
            runtime,
            provider,
            vm,
            bindings,
            memory,
            backend,
            received,
            ..
        } = self;
        let message = received
            .as_ref()
            .map(ReceivedMessage::message)
            .ok_or(ZstdTaskRuntimeAdapterError::MissingRequest)?;
        if message.capabilities().next() != Some(capability) {
            return Err(ZstdTaskRuntimeAdapterError::CapabilityMismatch);
        }
        let rights = Rights::MAP.union(Rights::READ).union(Rights::WRITE);
        message
            .write_selected_shared_buffer(
                runtime
                    .capabilities_mut(*provider)
                    .map_err(ZstdTaskRuntimeAdapterError::Runtime)?,
                rights,
                bindings,
                memory,
                *vm,
                *provider,
                offset,
                input,
                *backend,
            )
            .map_err(ZstdTaskRuntimeAdapterError::Buffer)
    }

    fn send_response(
        &mut self,
        response: &[u8; DECOMPRESS_RESPONSE_BYTES],
    ) -> Result<(), Self::Error> {
        if !self.reply_ready {
            return Err(ZstdTaskRuntimeAdapterError::UnexpectedSender);
        }
        self.runtime
            .deliver_ipc(
                self.provider,
                self.caller,
                &mut self.reply_endpoint,
                self.reply_capability,
                response,
                &[],
            )
            .map_err(ZstdTaskRuntimeAdapterError::Runtime)?;
        self.reply_ready = false;
        Ok(())
    }

    fn release_received(&mut self, capability: Capability) -> Result<(), Self::Error> {
        let received = self
            .received
            .as_ref()
            .ok_or(ZstdTaskRuntimeAdapterError::MissingRequest)?;
        if received.message().capabilities().next() != Some(capability) {
            return Err(ZstdTaskRuntimeAdapterError::CapabilityMismatch);
        }
        self.runtime
            .revoke_capability(self.provider, capability)
            .map_err(ZstdTaskRuntimeAdapterError::Runtime)?;
        self.received = None;
        self.reply_ready = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ZstdServiceLoop, ZstdServiceLoopError};
    use mrml_interface_zstd_v3::{
        decode_decompress_response, encode_decompress_request, BorrowedReadView, BorrowedWriteView,
    };
    use mrml_kernel::arch::x86_64::UserContext;
    use mrml_kernel::{
        launch_prepared_component_service, prepare_isolation_service_route,
        route_isolation_service, ArtifactKind, GuestRegion, HostResourceHandle,
        IsolationAdmissionTable, IsolationMode, IsolationServiceSpec, PhysAddr,
        PreparedComponentServiceLaunch, Priority, SharedAccess, SharedEndpoint, VmTable,
    };

    const PAGE_BYTES: usize = 4096;
    const SYSTEM_GENERATION: u64 = 108;
    const FRAME: [u8; 10] = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 5, 0x2b, 0, 0, b'x'];

    struct BufferBackend {
        handle: HostResourceHandle,
        bytes: [u8; PAGE_BYTES],
    }

    #[derive(Default)]
    struct NativeEraser {
        erased: Option<(TaskId, UserContext)>,
        attempts: usize,
        fail_first: bool,
    }

    impl ServiceAddressSpaceEraser for NativeEraser {
        type Error = ();

        fn erase(&mut self, task: TaskId, context: UserContext) -> Result<(), Self::Error> {
            self.attempts += 1;
            if self.fail_first && self.attempts == 1 {
                return Err(());
            }
            self.erased = Some((task, context));
            Ok(())
        }
    }

    unsafe impl IpcSharedBufferBackend for BufferBackend {
        type Error = ();

        fn read(
            &mut self,
            handle: HostResourceHandle,
            offset: u64,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            if handle != self.handle {
                return Err(());
            }
            let start = usize::try_from(offset).map_err(|_| ())?;
            output.copy_from_slice(self.bytes.get(start..start + output.len()).ok_or(())?);
            Ok(())
        }

        fn write(
            &mut self,
            handle: HostResourceHandle,
            offset: u64,
            input: &[u8],
        ) -> Result<(), Self::Error> {
            if handle != self.handle {
                return Err(());
            }
            let start = usize::try_from(offset).map_err(|_| ())?;
            self.bytes
                .get_mut(start..start + input.len())
                .ok_or(())?
                .copy_from_slice(input);
            Ok(())
        }
    }

    fn context(root: u64, entry: u64, stack: u64) -> UserContext {
        UserContext::new(PhysAddr::new(root).unwrap(), entry, stack).unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn admitted_endpoint(
        caller: TaskId,
        provider: TaskId,
        vm: VmId,
        reply_object: ObjectId,
        reply_capability: Capability,
        interface: ObjectId,
        interface_generation: u32,
        provider_generation: u64,
        policy_generation: u64,
        placement: IsolationPlacement,
    ) -> RoutedIsolationService<ZstdTaskRuntimeEndpoint> {
        let endpoint = ZstdTaskRuntimeEndpoint::new(
            caller,
            provider,
            vm,
            Endpoint::new(reply_object),
            reply_capability,
        )
        .unwrap();
        let spec = IsolationServiceSpec::new(
            ObjectId(0x500),
            interface,
            interface_generation,
            provider_generation,
            SYSTEM_GENERATION,
            policy_generation,
            TotalMicrovmClass::MicrovmEligible,
            placement,
        )
        .unwrap();
        let mut admission = IsolationAdmissionTable::<1>::new(
            IsolationMode::Balanced,
            SYSTEM_GENERATION,
            policy_generation,
        )
        .unwrap();
        prepare_isolation_service_route(&mut admission, spec)
            .unwrap()
            .commit(&mut admission, endpoint)
            .map_err(|(_, error, _)| error)
            .unwrap()
    }

    fn service_spec(
        interface: ObjectId,
        provider_generation: u64,
        policy_generation: u64,
        placement: IsolationPlacement,
    ) -> IsolationServiceSpec {
        IsolationServiceSpec::new(
            ObjectId(0x500),
            interface,
            INTERFACE_GENERATION,
            provider_generation,
            SYSTEM_GENERATION,
            policy_generation,
            TotalMicrovmClass::MicrovmEligible,
            placement,
        )
        .unwrap()
    }

    #[test]
    fn supervised_native_service_runs_exact_abi_call_and_cleans_address_space() {
        let mut runtime = TaskRuntime::<2, 4>::new(1_000, 1).unwrap();
        let caller = runtime
            .create(
                Priority::NORMAL,
                context(0x20_0000, 0x40_0000, 0x0000_7000_0000_0000),
            )
            .unwrap();
        let provider_context = context(0x30_0000, 0x50_0000, 0x0000_7000_0000_1000);
        let vm = VmTable::<1>::new().create(0x404).unwrap();
        let interface = ObjectId(0x406);
        let expected =
            ZstdResolvedServiceBinding::new(interface, 11, SYSTEM_GENERATION, 7).unwrap();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let mut eraser = NativeEraser::default();
        let mut native = ZstdNativeServiceBackend::new(
            &mut runtime,
            &mut supervisor,
            &mut eraser,
            expected,
            caller,
            vm,
            ObjectId(0x402),
            Priority::NORMAL,
            provider_context,
        )
        .unwrap();
        let mut admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::Balanced, SYSTEM_GENERATION, 7)
                .unwrap();
        let spec = service_spec(interface, 11, 7, IsolationPlacement::NativeService);
        let route = prepare_isolation_service_route(&mut admission, spec).unwrap();
        let launch = PreparedComponentServiceLaunch::bind(
            route,
            interface,
            INTERFACE_GENERATION,
            11,
            SYSTEM_GENERATION,
            [0x51; 64],
            [0x61; 64],
            [0x3a; 32],
            [0x18; 64],
            [0x2f; 64],
        )
        .unwrap();
        let routed = launch_prepared_component_service(
            &mut admission,
            &mut native,
            launch,
            ArtifactKind::ServiceImage,
            &[0x18; 64],
            ArtifactKind::ServiceImage,
            &[0x2f; 64],
        )
        .unwrap();
        let native_endpoint = *routed.endpoint();
        assert_eq!(native_endpoint.interface(), interface);
        assert_eq!(native_endpoint.provider_generation(), 11);
        assert_eq!(native_endpoint.system_generation(), SYSTEM_GENERATION);
        assert_eq!(routed.system_generation(), SYSTEM_GENERATION);
        let routed = native.open_data_plane(routed).unwrap();
        let provider = native_endpoint.task();

        let request_object = ObjectId(0x401);
        let request_capability = native
            .runtime_mut()
            .capabilities_mut(caller)
            .unwrap()
            .insert(request_object, Rights::SIGNAL)
            .unwrap();
        let rights = Rights::MAP.union(Rights::READ).union(Rights::WRITE);
        let buffer_root = native
            .runtime_mut()
            .capabilities_mut(caller)
            .unwrap()
            .insert(ObjectId(0x403), rights.union(Rights::DELEGATE))
            .unwrap();
        let mut memory = GuestMemory::<1>::new();
        let mapping = memory
            .map(GuestRegion::new(0x4000, PhysAddr::new(0x8000).unwrap(), 1, true, false).unwrap())
            .unwrap();
        let handle = HostResourceHandle::new(0x405).unwrap();
        let mut bindings = SharedMemoryBindings::<1>::new();
        bindings
            .bind(
                native.runtime_mut().capabilities_mut(caller).unwrap(),
                buffer_root,
                &memory,
                SharedEndpoint::for_task(vm, provider, mapping, SharedAccess::ReadWrite),
                handle,
            )
            .unwrap();
        let request = encode_decompress_request(
            BorrowedReadView::within(0, FRAME.len() as u64, PAGE_BYTES as u64).unwrap(),
            BorrowedWriteView::within(64, 32, PAGE_BYTES as u64).unwrap(),
        )
        .unwrap();
        let mut request_channel = Endpoint::new(request_object);
        native
            .runtime_mut()
            .deliver_ipc(
                caller,
                provider,
                &mut request_channel,
                request_capability,
                &request,
                &[(buffer_root, rights)],
            )
            .unwrap();
        assert!(matches!(
            native.runtime_mut().start(),
            mrml_kernel::ScheduleOutcome::Switch { from: None, to } if to == caller
        ));
        assert!(matches!(
            native.runtime_mut().yield_current().unwrap(),
            mrml_kernel::ScheduleOutcome::Switch { from: Some(from), to }
                if from == caller && to == provider
        ));

        let admitted = ZstdAdmittedTaskRuntimeEndpoint::bind(routed, expected)
            .map_err(|(_, error)| error)
            .unwrap();
        let mut buffer_backend = BufferBackend {
            handle,
            bytes: [0xa5; PAGE_BYTES],
        };
        buffer_backend.bytes[..FRAME.len()].copy_from_slice(&FRAME);
        let mut request_buffer = [0xcc; DECOMPRESS_REQUEST_BYTES];
        let mut capability_tokens = [u64::MAX; 1];
        let mut scratch = [0xcc; 128];
        let mut response_buffer = [0xcc; DECOMPRESS_RESPONSE_BYTES];
        ZstdServiceLoop::new()
            .serve_one(
                &mut ZstdTaskRuntimeAdapter::new(
                    native.runtime_mut(),
                    admitted,
                    &bindings,
                    &memory,
                    &mut buffer_backend,
                ),
                &mut request_buffer,
                &mut capability_tokens,
                &mut scratch,
                &mut response_buffer,
            )
            .unwrap();
        let ControlEvent::Message(reply) = native.runtime_mut().receive_control(caller).unwrap()
        else {
            panic!("expected reply");
        };
        assert_eq!(reply.sender(), provider);
        assert_eq!(&buffer_backend.bytes[64..69], b"xxxxx");
        native.revoke(&native_endpoint).unwrap();
        assert_eq!(native.active(), None);
        assert!(matches!(
            native.launch_native_service(service_spec(
                interface,
                11,
                7,
                IsolationPlacement::NativeService,
            )),
            Err(failure)
                if failure.error() == &ZstdNativeServiceError::RetirementDispatchPending
        ));
        let dispatch = native.take_retirement_dispatch().unwrap();
        assert_eq!(
            dispatch.user(),
            Some((caller, context(0x20_0000, 0x40_0000, 0x0000_7000_0000_0000)))
        );
        drop(native);
        assert_eq!(eraser.erased, Some((provider, provider_context)));
        assert_eq!(
            supervisor.state(native_endpoint.service()),
            Ok(ServiceState::Exited)
        );
        assert_eq!(
            supervisor.pending_cleanup(native_endpoint.service()),
            Ok(None)
        );
        assert_eq!(
            runtime.context(provider),
            Err(TaskRuntimeError::MissingTask)
        );
    }

    #[test]
    fn total_mode_rejects_native_zstd_before_supervisor_launch() {
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let caller = runtime
            .create(
                Priority::NORMAL,
                context(0x20_0000, 0x40_0000, 0x0000_7000_0000_0000),
            )
            .unwrap();
        let vm = VmTable::<1>::new().create(0x404).unwrap();
        let interface = ObjectId(0x406);
        let expected =
            ZstdResolvedServiceBinding::new(interface, 11, SYSTEM_GENERATION, 7).unwrap();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let mut eraser = NativeEraser::default();
        let mut native = ZstdNativeServiceBackend::new(
            &mut runtime,
            &mut supervisor,
            &mut eraser,
            expected,
            caller,
            vm,
            ObjectId(0x402),
            Priority::NORMAL,
            context(0x30_0000, 0x50_0000, 0x0000_7000_0000_1000),
        )
        .unwrap();
        let mut admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 7)
                .unwrap();
        assert!(matches!(
            route_isolation_service(
                &mut admission,
                &mut native,
                service_spec(interface, 11, 7, IsolationPlacement::NativeService),
            ),
            Err(mrml_kernel::IsolationServiceRouteError::Admission(
                mrml_kernel::IsolationLaunchError::TotalMicrovmDowngradeAttempt
            ))
        ));
        assert_eq!(native.active(), None);
        assert_eq!(admission.total_microvm_report().native_fallback, 0);
        drop(native);
        assert_eq!(runtime.load().occupied(), 1);
    }

    #[test]
    fn native_service_requires_distinct_address_space_and_reply_object() {
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let caller_context = context(0x20_0000, 0x40_0000, 0x0000_7000_0000_0000);
        let caller = runtime.create(Priority::NORMAL, caller_context).unwrap();
        let vm = VmTable::<1>::new().create(0x404).unwrap();
        let expected =
            ZstdResolvedServiceBinding::new(ObjectId(0x406), 11, SYSTEM_GENERATION, 7).unwrap();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let mut eraser = NativeEraser::default();
        assert!(matches!(
            ZstdNativeServiceBackend::new(
                &mut runtime,
                &mut supervisor,
                &mut eraser,
                expected,
                caller,
                vm,
                ObjectId(0),
                Priority::NORMAL,
                context(0x30_0000, 0x50_0000, 0x0000_7000_0000_1000),
            ),
            Err(ZstdNativeServiceError::Binding(
                ZstdServiceBindingError::InvalidEndpoint
            ))
        ));
        assert!(matches!(
            ZstdNativeServiceBackend::new(
                &mut runtime,
                &mut supervisor,
                &mut eraser,
                expected,
                caller,
                vm,
                ObjectId(0x402),
                Priority::NORMAL,
                caller_context,
            ),
            Err(ZstdNativeServiceError::Binding(
                ZstdServiceBindingError::InvalidEndpoint
            ))
        ));
        assert_eq!(runtime.load().occupied(), 1);
    }

    #[test]
    fn native_cleanup_uncertainty_retains_exact_endpoint_for_retry() {
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let caller = runtime
            .create(
                Priority::NORMAL,
                context(0x20_0000, 0x40_0000, 0x0000_7000_0000_0000),
            )
            .unwrap();
        let provider_context = context(0x30_0000, 0x50_0000, 0x0000_7000_0000_1000);
        let vm = VmTable::<1>::new().create(0x404).unwrap();
        let interface = ObjectId(0x406);
        let expected =
            ZstdResolvedServiceBinding::new(interface, 11, SYSTEM_GENERATION, 7).unwrap();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let mut eraser = NativeEraser {
            fail_first: true,
            ..NativeEraser::default()
        };
        let mut native = ZstdNativeServiceBackend::new(
            &mut runtime,
            &mut supervisor,
            &mut eraser,
            expected,
            caller,
            vm,
            ObjectId(0x402),
            Priority::NORMAL,
            provider_context,
        )
        .unwrap();
        let mut admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::Balanced, SYSTEM_GENERATION, 7)
                .unwrap();
        let routed = route_isolation_service(
            &mut admission,
            &mut native,
            service_spec(interface, 11, 7, IsolationPlacement::NativeService),
        )
        .unwrap();
        let endpoint = *routed.endpoint();
        let _transport = native.open_data_plane(routed).unwrap();
        let _ = native.runtime_mut().start();
        let _ = native.runtime_mut().yield_current().unwrap();
        assert_eq!(
            native.revoke(&endpoint),
            Err(ZstdNativeServiceError::Cleanup(
                ServiceCleanupError::Eraser(())
            ))
        );
        assert_eq!(native.active(), Some(endpoint));
        assert_eq!(
            native
                .pending_retirement_dispatch()
                .and_then(|dispatch| dispatch.user())
                .map(|(task, _)| task),
            Some(caller)
        );
        native.revoke(&endpoint).unwrap();
        assert_eq!(native.active(), None);
        let dispatch = native.take_retirement_dispatch().unwrap();
        assert_eq!(dispatch.user().map(|(task, _)| task), Some(caller));
        drop(native);
        assert_eq!(eraser.attempts, 2);
        assert_eq!(eraser.erased, Some((endpoint.task(), provider_context)));
        assert_eq!(supervisor.pending_cleanup(endpoint.service()), Ok(None));
    }

    #[test]
    fn full_task_runtime_call_replies_to_authenticated_caller_and_revokes_leaf() {
        let mut runtime = TaskRuntime::<2, 4>::new(1_000, 1).unwrap();
        let caller = runtime
            .create(
                Priority::NORMAL,
                context(0x20_0000, 0x40_0000, 0x0000_7000_0000_0000),
            )
            .unwrap();
        let provider = runtime
            .create(
                Priority::NORMAL,
                context(0x30_0000, 0x50_0000, 0x0000_7000_0000_1000),
            )
            .unwrap();
        let request_object = ObjectId(0x401);
        let request_capability = runtime
            .capabilities_mut(caller)
            .unwrap()
            .insert(request_object, Rights::SIGNAL)
            .unwrap();
        let reply_object = ObjectId(0x402);
        let reply_capability = runtime
            .capabilities_mut(provider)
            .unwrap()
            .insert(reply_object, Rights::SIGNAL)
            .unwrap();
        let rights = Rights::MAP.union(Rights::READ).union(Rights::WRITE);
        let buffer_root = runtime
            .capabilities_mut(caller)
            .unwrap()
            .insert(ObjectId(0x403), rights.union(Rights::DELEGATE))
            .unwrap();
        let vm = VmTable::<1>::new().create(0x404).unwrap();
        let mut memory = GuestMemory::<1>::new();
        let mapping = memory
            .map(GuestRegion::new(0x4000, PhysAddr::new(0x8000).unwrap(), 1, true, false).unwrap())
            .unwrap();
        let handle = HostResourceHandle::new(0x405).unwrap();
        let mut bindings = SharedMemoryBindings::<1>::new();
        bindings
            .bind(
                runtime.capabilities_mut(caller).unwrap(),
                buffer_root,
                &memory,
                SharedEndpoint::for_task(vm, provider, mapping, SharedAccess::ReadWrite),
                handle,
            )
            .unwrap();
        let request = encode_decompress_request(
            BorrowedReadView::within(0, FRAME.len() as u64, PAGE_BYTES as u64).unwrap(),
            BorrowedWriteView::within(64, 32, PAGE_BYTES as u64).unwrap(),
        )
        .unwrap();
        let mut request_channel = Endpoint::new(request_object);
        runtime
            .deliver_ipc(
                caller,
                provider,
                &mut request_channel,
                request_capability,
                &request,
                &[(buffer_root, rights)],
            )
            .unwrap();

        let mut backend = BufferBackend {
            handle,
            bytes: [0xa5; PAGE_BYTES],
        };
        backend.bytes[..FRAME.len()].copy_from_slice(&FRAME);
        let interface = ObjectId(0x406);
        let routed = admitted_endpoint(
            caller,
            provider,
            vm,
            reply_object,
            reply_capability,
            interface,
            INTERFACE_GENERATION,
            11,
            7,
            IsolationPlacement::Microvm,
        );
        let expected =
            ZstdResolvedServiceBinding::new(interface, 11, SYSTEM_GENERATION, 7).unwrap();
        let admitted = ZstdAdmittedTaskRuntimeEndpoint::bind(routed, expected)
            .map_err(|(_, error)| error)
            .unwrap();
        let mut request_buffer = [0xcc; DECOMPRESS_REQUEST_BYTES];
        let mut capability_tokens = [u64::MAX; 1];
        let mut scratch = [0xcc; 128];
        let mut response_buffer = [0xcc; DECOMPRESS_RESPONSE_BYTES];
        let mut adapter =
            ZstdTaskRuntimeAdapter::new(&mut runtime, admitted, &bindings, &memory, &mut backend);
        assert_eq!(adapter.domain(), ObjectId(0x500));
        assert_eq!(adapter.provider_generation(), 11);
        assert_eq!(adapter.system_generation(), SYSTEM_GENERATION);
        assert_eq!(adapter.policy_generation(), 7);
        assert_eq!(adapter.placement(), IsolationPlacement::Microvm);
        ZstdServiceLoop::new()
            .serve_one(
                &mut adapter,
                &mut request_buffer,
                &mut capability_tokens,
                &mut scratch,
                &mut response_buffer,
            )
            .unwrap();

        let ControlEvent::Message(reply) = runtime.receive_control(caller).unwrap() else {
            panic!("expected reply");
        };
        assert_eq!(reply.sender(), provider);
        assert_eq!(reply.sequence(), 1);
        assert_eq!(reply.message().capability_count(), 0);
        let response: &[u8; DECOMPRESS_RESPONSE_BYTES] =
            reply.message().payload().try_into().unwrap();
        assert_eq!(decode_decompress_response(response), Ok(Ok(5)));
        assert_eq!(&backend.bytes[64..69], b"xxxxx");
        assert_eq!(request_buffer, [0; DECOMPRESS_REQUEST_BYTES]);
        assert_eq!(capability_tokens, [0]);
        assert_eq!(scratch, [0; 128]);
        assert_eq!(response_buffer, [0; DECOMPRESS_RESPONSE_BYTES]);
    }

    #[test]
    fn adapter_requires_the_exact_committed_resolver_and_policy_binding() {
        assert_eq!(
            ZstdResolvedServiceBinding::new(ObjectId(1), 0, SYSTEM_GENERATION, 1),
            Err(ZstdServiceBindingError::InvalidGeneration)
        );
        assert_eq!(
            ZstdResolvedServiceBinding::new(ObjectId(1), 1, SYSTEM_GENERATION, 0),
            Err(ZstdServiceBindingError::InvalidGeneration)
        );
        assert_eq!(
            ZstdResolvedServiceBinding::new(ObjectId(1), 1, 0, 1),
            Err(ZstdServiceBindingError::InvalidGeneration)
        );

        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let caller = runtime
            .create(
                Priority::NORMAL,
                context(0x20_0000, 0x40_0000, 0x0000_7000_0000_0000),
            )
            .unwrap();
        let provider = runtime
            .create(
                Priority::NORMAL,
                context(0x30_0000, 0x50_0000, 0x0000_7000_0000_1000),
            )
            .unwrap();
        let reply_object = ObjectId(0x421);
        let reply_capability = runtime
            .capabilities_mut(provider)
            .unwrap()
            .insert(reply_object, Rights::SIGNAL)
            .unwrap();
        let vm = VmTable::<1>::new().create(0x422).unwrap();
        let interface = ObjectId(0x423);
        let routed = admitted_endpoint(
            caller,
            provider,
            vm,
            reply_object,
            reply_capability,
            interface,
            INTERFACE_GENERATION,
            17,
            5,
            IsolationPlacement::NativeService,
        );
        let (returned, error) = ZstdAdmittedTaskRuntimeEndpoint::bind(
            routed,
            ZstdResolvedServiceBinding::new(interface, 18, SYSTEM_GENERATION, 5).unwrap(),
        )
        .err()
        .expect("mismatched provider generation must be rejected");
        assert_eq!(error, ZstdServiceBindingError::AdmissionMismatch);
        assert_eq!(returned.provider_generation(), 17);
        assert_eq!(returned.system_generation(), SYSTEM_GENERATION);
        assert_eq!(returned.policy_generation(), 5);
        assert_eq!(returned.placement(), IsolationPlacement::NativeService);
        let (returned, error) = ZstdAdmittedTaskRuntimeEndpoint::bind(
            returned,
            ZstdResolvedServiceBinding::new(interface, 17, SYSTEM_GENERATION - 1, 5).unwrap(),
        )
        .err()
        .expect("stale system generation must be rejected");
        assert_eq!(error, ZstdServiceBindingError::AdmissionMismatch);
        assert_eq!(returned.system_generation(), SYSTEM_GENERATION);
    }

    #[test]
    fn unexpected_sender_is_rejected_and_transferred_leaf_is_revoked() {
        let mut runtime = TaskRuntime::<3, 3>::new(1_000, 1).unwrap();
        let caller = runtime
            .create(
                Priority::NORMAL,
                context(0x20_0000, 0x40_0000, 0x0000_7000_0000_0000),
            )
            .unwrap();
        let provider = runtime
            .create(
                Priority::NORMAL,
                context(0x30_0000, 0x50_0000, 0x0000_7000_0000_1000),
            )
            .unwrap();
        let attacker = runtime
            .create(
                Priority::NORMAL,
                context(0x40_0000, 0x60_0000, 0x0000_7000_0000_2000),
            )
            .unwrap();
        let request_object = ObjectId(0x411);
        let request_capability = runtime
            .capabilities_mut(attacker)
            .unwrap()
            .insert(request_object, Rights::SIGNAL)
            .unwrap();
        let delegated = runtime
            .capabilities_mut(attacker)
            .unwrap()
            .insert(ObjectId(0x412), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let mut request_channel = Endpoint::new(request_object);
        runtime
            .deliver_ipc(
                attacker,
                provider,
                &mut request_channel,
                request_capability,
                &[0; DECOMPRESS_REQUEST_BYTES],
                &[(delegated, Rights::READ)],
            )
            .unwrap();
        let reply_object = ObjectId(0x413);
        let reply_capability = runtime
            .capabilities_mut(provider)
            .unwrap()
            .insert(reply_object, Rights::SIGNAL)
            .unwrap();
        let vm = VmTable::<1>::new().create(0x414).unwrap();
        let memory = GuestMemory::<1>::new();
        let bindings = SharedMemoryBindings::<1>::new();
        let handle = HostResourceHandle::new(0x415).unwrap();
        let mut backend = BufferBackend {
            handle,
            bytes: [0; PAGE_BYTES],
        };
        let interface = ObjectId(0x418);
        let routed = admitted_endpoint(
            caller,
            provider,
            vm,
            reply_object,
            reply_capability,
            interface,
            INTERFACE_GENERATION,
            13,
            9,
            IsolationPlacement::NativeService,
        );
        let mut request_buffer = [0xcc; DECOMPRESS_REQUEST_BYTES];
        let mut capability_tokens = [u64::MAX; 1];
        let mut scratch = [0xcc; 128];
        let mut response_buffer = [0xcc; DECOMPRESS_RESPONSE_BYTES];
        let admitted = ZstdAdmittedTaskRuntimeEndpoint::bind(
            routed,
            ZstdResolvedServiceBinding::new(interface, 13, SYSTEM_GENERATION, 9).unwrap(),
        )
        .map_err(|(_, error)| error)
        .unwrap();
        assert_eq!(
            ZstdServiceLoop::new().serve_one(
                &mut ZstdTaskRuntimeAdapter::new(
                    &mut runtime,
                    admitted,
                    &bindings,
                    &memory,
                    &mut backend,
                ),
                &mut request_buffer,
                &mut capability_tokens,
                &mut scratch,
                &mut response_buffer,
            ),
            Err(ZstdServiceLoopError::Syscall(
                ZstdTaskRuntimeAdapterError::UnexpectedSender
            ))
        );
        assert_eq!(request_buffer, [0; DECOMPRESS_REQUEST_BYTES]);
        assert_eq!(capability_tokens, [0]);
        assert_eq!(scratch, [0; 128]);
        assert_eq!(response_buffer, [0; DECOMPRESS_RESPONSE_BYTES]);
        let provider_space = runtime.capabilities_mut(provider).unwrap();
        assert!(provider_space.insert(ObjectId(0x416), Rights::READ).is_ok());
        assert!(provider_space.insert(ObjectId(0x417), Rights::READ).is_ok());
    }
}
