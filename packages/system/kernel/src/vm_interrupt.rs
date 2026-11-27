use crate::{
    Capability, CapabilitySpace, MicrovmInterfaceQueueIdentity,
    MicrovmInterfaceRequestNotification, MicrovmInterfaceResponseNotification, MicrovmPeerPageIdentity,
    MicrovmPeerPageRetirement,
    ObjectId, Rights,
    VirtualBlockDevice, VirtualBlockError, VmBackend, VmError, VmId, VmRunError, VmState, VmTable,
};

const FIRST_EXTERNAL_VECTOR: u8 = 32;
const LAST_EXTERNAL_VECTOR: u8 = 254;

/// Explicit allowlist for externally injected interrupt vectors. CPU exception
/// vectors and the spurious-vector sentinel are never injectable through this
/// interface.
pub struct InterruptPolicy {
    words: [u64; 4],
}

impl InterruptPolicy {
    pub const fn deny_all() -> Self {
        Self { words: [0; 4] }
    }

    pub fn allow(&mut self, vector: u8) -> Result<(), VmError> {
        if !(FIRST_EXTERNAL_VECTOR..=LAST_EXTERNAL_VECTOR).contains(&vector) {
            return Err(VmError::InterruptDenied);
        }
        self.words[vector as usize / 64] |= 1u64 << (vector as usize % 64);
        Ok(())
    }

    pub fn deny(&mut self, vector: u8) {
        self.words[vector as usize / 64] &= !(1u64 << (vector as usize % 64));
    }

    pub fn permits(&self, vector: u8) -> bool {
        (FIRST_EXTERNAL_VECTOR..=LAST_EXTERNAL_VECTOR).contains(&vector)
            && self.words[vector as usize / 64] & (1u64 << (vector as usize % 64)) != 0
    }
}

impl Default for InterruptPolicy {
    fn default() -> Self {
        Self::deny_all()
    }
}

/// Delivers an interrupt only when the caller owns SIGNAL authority for the
/// VM's interrupt object and the vector is explicitly allowlisted.
// Capability, object, vector, and VM identity remain separate so every
// authorization input is visible at the call site.
#[allow(clippy::too_many_arguments)]
pub fn inject_vm_interrupt<B: VmBackend, const V: usize, const C: usize>(
    backend: &mut B,
    vms: &mut VmTable<V>,
    vm: VmId,
    vcpu: u32,
    vector: u8,
    policy: &InterruptPolicy,
    capabilities: &CapabilitySpace<C>,
    capability: Capability,
    interrupt_object: ObjectId,
) -> Result<(), VmRunError<B::Error>> {
    if vms.state(vm).map_err(VmRunError::Policy)? != VmState::Running {
        return Err(VmRunError::Policy(VmError::InvalidVmState));
    }
    if !policy.permits(vector) {
        return Err(VmRunError::Policy(VmError::InterruptDenied));
    }
    let object = capabilities
        .authorize(capability, Rights::SIGNAL)
        .map_err(|error| VmRunError::Policy(VmError::Capability(error)))?;
    if object != interrupt_object {
        return Err(VmRunError::Policy(VmError::WrongObject));
    }
    if let Err(error) = backend.inject_interrupt(vcpu, vector) {
        let _ = vms.fail(vm);
        return Err(VmRunError::Backend(error));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualBlockInterruptError<E> {
    Device(VirtualBlockError),
    Injection(VmRunError<E>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MicrovmInterfaceInterruptError<E> {
    AlreadyPending,
    Retired,
    WrongRetirement,
    InvalidNotification,
    SequenceExhausted,
    Injection(VmRunError<E>),
}

struct MicrovmInterfaceInterruptRoute<N> {
    identity: MicrovmInterfaceQueueIdentity,
    projection: MicrovmPeerPageIdentity,
    vm: VmId,
    vcpu: u32,
    vector: u8,
    interrupt_object: ObjectId,
    pending: Option<N>,
    delivered_sequence: u64,
    retired: bool,
}

pub struct MicrovmInterfaceRequestInterrupt {
    route: MicrovmInterfaceInterruptRoute<MicrovmInterfaceRequestNotification>,
}

pub struct MicrovmInterfaceResponseInterrupt {
    route: MicrovmInterfaceInterruptRoute<MicrovmInterfaceResponseNotification>,
}

macro_rules! interface_interrupt_route {
    ($name:ident, $notification:ty) => {
        impl $name {
            pub const fn new(
                identity: MicrovmInterfaceQueueIdentity,
                projection: MicrovmPeerPageIdentity,
                vm: VmId,
                vcpu: u32,
                vector: u8,
                interrupt_object: ObjectId,
            ) -> Self {
                Self {
                    route: MicrovmInterfaceInterruptRoute {
                        identity,
                        projection,
                        vm,
                        vcpu,
                        vector,
                        interrupt_object,
                        pending: None,
                        delivered_sequence: 0,
                        retired: false,
                    },
                }
            }

            pub fn publish(
                &mut self,
                notification: $notification,
            ) -> Result<(), MicrovmInterfaceInterruptError<core::convert::Infallible>> {
                if self.route.retired {
                    return Err(MicrovmInterfaceInterruptError::Retired);
                }
                if self.route.pending.is_some() {
                    return Err(MicrovmInterfaceInterruptError::AlreadyPending);
                }
                let expected = self
                    .route
                    .delivered_sequence
                    .checked_add(1)
                    .ok_or(MicrovmInterfaceInterruptError::SequenceExhausted)?;
                if notification.identity() != self.route.identity
                    || notification.projection() != self.route.projection
                    || notification.sequence() != expected
                {
                    return Err(MicrovmInterfaceInterruptError::InvalidNotification);
                }
                self.route.pending = Some(notification);
                Ok(())
            }

            /// Permanently closes the route once the exact shared page is
            /// retired. Returns whether a queued notification was discarded.
            /// Does not cancel an interrupt already delivered to a vCPU.
            pub fn retire(
                &mut self,
                receipt: &MicrovmPeerPageRetirement,
            ) -> Result<bool, MicrovmInterfaceInterruptError<core::convert::Infallible>> {
                if receipt.identity() != self.route.projection {
                    return Err(MicrovmInterfaceInterruptError::WrongRetirement);
                }
                if self.route.retired {
                    return Err(MicrovmInterfaceInterruptError::Retired);
                }
                self.route.retired = true;
                Ok(self.route.pending.take().is_some())
            }

            pub const fn pending(&self) -> Option<$notification> {
                self.route.pending
            }
        }
    };
}

interface_interrupt_route!(
    MicrovmInterfaceRequestInterrupt,
    MicrovmInterfaceRequestNotification
);
interface_interrupt_route!(
    MicrovmInterfaceResponseInterrupt,
    MicrovmInterfaceResponseNotification
);

fn deliver_interface_interrupt<B: VmBackend, N: Copy, const V: usize, const C: usize>(
    route: &mut MicrovmInterfaceInterruptRoute<N>,
    sequence: impl FnOnce(N) -> u64,
    backend: &mut B,
    vms: &mut VmTable<V>,
    policy: &InterruptPolicy,
    capabilities: &CapabilitySpace<C>,
    capability: Capability,
) -> Result<Option<N>, MicrovmInterfaceInterruptError<B::Error>> {
    if route.retired {
        return Err(MicrovmInterfaceInterruptError::Retired);
    }
    let Some(notification) = route.pending else {
        return Ok(None);
    };
    inject_vm_interrupt(
        backend,
        vms,
        route.vm,
        route.vcpu,
        route.vector,
        policy,
        capabilities,
        capability,
        route.interrupt_object,
    )
    .map_err(MicrovmInterfaceInterruptError::Injection)?;
    route.pending = None;
    route.delivered_sequence = sequence(notification);
    Ok(Some(notification))
}

pub fn deliver_microvm_interface_request_interrupt<B: VmBackend, const V: usize, const C: usize>(
    route: &mut MicrovmInterfaceRequestInterrupt,
    backend: &mut B,
    vms: &mut VmTable<V>,
    policy: &InterruptPolicy,
    capabilities: &CapabilitySpace<C>,
    capability: Capability,
) -> Result<Option<MicrovmInterfaceRequestNotification>, MicrovmInterfaceInterruptError<B::Error>> {
    deliver_interface_interrupt(
        &mut route.route,
        MicrovmInterfaceRequestNotification::sequence,
        backend,
        vms,
        policy,
        capabilities,
        capability,
    )
}

pub fn deliver_microvm_interface_response_interrupt<
    B: VmBackend,
    const V: usize,
    const C: usize,
>(
    route: &mut MicrovmInterfaceResponseInterrupt,
    backend: &mut B,
    vms: &mut VmTable<V>,
    policy: &InterruptPolicy,
    capabilities: &CapabilitySpace<C>,
    capability: Capability,
) -> Result<Option<MicrovmInterfaceResponseNotification>, MicrovmInterfaceInterruptError<B::Error>>
{
    deliver_interface_interrupt(
        &mut route.route,
        MicrovmInterfaceResponseNotification::sequence,
        backend,
        vms,
        policy,
        capabilities,
        capability,
    )
}

/// Delivers one coalesced virtual-block completion notification through the
/// ordinary capability-authorized VM interrupt boundary. Denied or uncertain
/// injection leaves the device latch pending; only confirmed delivery clears
/// it. The device supplies its configured vector, so callers cannot substitute
/// a different interrupt while retaining the same device state.
#[allow(clippy::too_many_arguments)]
pub fn inject_virtual_block_interrupt<
    B: VmBackend,
    const N: usize,
    const V: usize,
    const C: usize,
>(
    device: &mut VirtualBlockDevice<N>,
    backend: &mut B,
    vms: &mut VmTable<V>,
    vm: VmId,
    vcpu: u32,
    policy: &InterruptPolicy,
    capabilities: &CapabilitySpace<C>,
    capability: Capability,
    interrupt_object: ObjectId,
) -> Result<bool, VirtualBlockInterruptError<B::Error>> {
    let Some(vector) = device.pending_interrupt_vector() else {
        return Ok(false);
    };
    inject_vm_interrupt(
        backend,
        vms,
        vm,
        vcpu,
        vector,
        policy,
        capabilities,
        capability,
        interrupt_object,
    )
    .map_err(VirtualBlockInterruptError::Injection)?;
    device
        .acknowledge_interrupt(vector)
        .map_err(VirtualBlockInterruptError::Device)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        MemoryPoolTable, MicrovmInterfaceQueuePair, VirtualBlockQueueLayout, VmExit,
        reserve_microvm_peer_page_projection,
    };

    struct Backend {
        injected: Option<(u32, u8)>,
        fail: bool,
    }

    impl VmBackend for Backend {
        type Error = ();
        fn run(&mut self, _vcpu: u32) -> Result<VmExit, Self::Error> {
            Err(())
        }
        fn read_guest(&self, _address: u64, _output: &mut [u8]) -> Result<(), Self::Error> {
            Err(())
        }
        fn write_guest(&mut self, _address: u64, _input: &[u8]) -> Result<(), Self::Error> {
            Err(())
        }
        fn inject_interrupt(&mut self, vcpu: u32, vector: u8) -> Result<(), Self::Error> {
            if self.fail {
                return Err(());
            }
            self.injected = Some((vcpu, vector));
            Ok(())
        }
    }

    fn running_vm() -> (VmTable<1>, VmId) {
        let mut table = VmTable::new();
        let id = table.create(4).unwrap();
        table.mark_loaded(id).unwrap();
        table.start(id).unwrap();
        (table, id)
    }

    fn pending_block_device() -> VirtualBlockDevice<1> {
        let mut device = VirtualBlockDevice::new(4096, 64, 0).unwrap();
        device.negotiate(0).unwrap();
        device
            .activate(VirtualBlockQueueLayout::new(0x1000, 0x3000, 1).unwrap(), 48)
            .unwrap();
        device.latch_completion_interrupt().unwrap();
        device
    }

    fn interface_notifications(
        capabilities: &mut CapabilitySpace<12>,
    ) -> (
        MicrovmInterfaceQueueIdentity,
        MicrovmInterfaceRequestNotification,
        MicrovmInterfaceResponseNotification,
    ) {
        let identity = MicrovmInterfaceQueueIdentity::new([0x5a; 32], 3, 14, 9, 7, 11).unwrap();
        let target_rights = Rights::MAP.union(Rights::INSPECT).union(Rights::CONTROL);
        let pool_rights = Rights::ALLOCATE
            .union(Rights::CONTROL)
            .union(Rights::INSPECT);
        let mut memory = MemoryPoolTable::<1, 1, 2>::new(0x981).unwrap();
        let (pool, pool_capability) = memory
            .create_root(1, 2, 0, pool_rights, capabilities)
            .unwrap();
        let first = capabilities.insert(ObjectId(0x982), target_rights).unwrap();
        let second = capabilities.insert(ObjectId(0x983), target_rights).unwrap();
        let (projection, _) = reserve_microvm_peer_page_projection(
            &mut memory,
            pool,
            pool_capability,
            first,
            second,
            0x700,
            0x800,
            capabilities,
        )
        .unwrap();
        let (consumer, mut provider) =
            MicrovmInterfaceQueuePair::bind(identity, &projection, first, second, capabilities)
                .unwrap()
                .split();
        let mut page = [0; crate::PAGE_SIZE as usize];
        consumer
            .initialize(&mut page, &projection, capabilities)
            .unwrap();
        let request = consumer
            .submit(&mut page, &projection, capabilities, 1, b"request")
            .unwrap();
        let mut scratch = [0; 8];
        provider
            .receive_request(&page, &projection, capabilities, request, &mut scratch)
            .unwrap();
        let response = provider
            .respond(&mut page, &projection, capabilities, 1, 1, b"response")
            .unwrap();
        (identity, request, response)
    }

    #[test]
    fn interface_notifications_are_exact_monotonic_and_clear_only_after_delivery() {
        let interrupt_object = ObjectId(0x991);
        let wrong_object = ObjectId(0x992);
        let mut capabilities = CapabilitySpace::<12>::new();
        let signal = capabilities
            .insert(interrupt_object, Rights::SIGNAL)
            .unwrap();
        let wrong = capabilities.insert(wrong_object, Rights::SIGNAL).unwrap();
        let (identity, request, response) = interface_notifications(&mut capabilities);
        let (mut vms, vm) = running_vm();
        let mut policy = InterruptPolicy::deny_all();
        policy.allow(64).unwrap();
        policy.allow(65).unwrap();
        let mut backend = Backend {
            injected: None,
            fail: false,
        };
        let other_identity =
            MicrovmInterfaceQueueIdentity::new([0x6b; 32], 3, 14, 9, 7, 11).unwrap();
        let mut wrong_identity_route =
            MicrovmInterfaceRequestInterrupt::new(other_identity, request.projection(), vm, 1, 64, interrupt_object);
        assert_eq!(
            wrong_identity_route.publish(request),
            Err(MicrovmInterfaceInterruptError::InvalidNotification)
        );
        let mut request_route =
            MicrovmInterfaceRequestInterrupt::new(identity, request.projection(), vm, 1, 64, interrupt_object);
        request_route.publish(request).unwrap();
        assert_eq!(
            request_route.publish(request),
            Err(MicrovmInterfaceInterruptError::AlreadyPending)
        );
        assert!(matches!(
            deliver_microvm_interface_request_interrupt(
                &mut request_route,
                &mut backend,
                &mut vms,
                &policy,
                &capabilities,
                wrong,
            ),
            Err(MicrovmInterfaceInterruptError::Injection(
                VmRunError::Policy(VmError::WrongObject)
            ))
        ));
        assert_eq!(request_route.pending(), Some(request));
        assert_eq!(
            deliver_microvm_interface_request_interrupt(
                &mut request_route,
                &mut backend,
                &mut vms,
                &policy,
                &capabilities,
                signal,
            ),
            Ok(Some(request))
        );
        assert_eq!(backend.injected, Some((1, 64)));
        assert_eq!(request_route.pending(), None);
        assert_eq!(
            request_route.publish(request),
            Err(MicrovmInterfaceInterruptError::InvalidNotification)
        );

        backend.injected = None;
        let mut response_route =
            MicrovmInterfaceResponseInterrupt::new(identity, response.projection(), vm, 2, 65, interrupt_object);
        response_route.publish(response).unwrap();
        assert_eq!(
            deliver_microvm_interface_response_interrupt(
                &mut response_route,
                &mut backend,
                &mut vms,
                &policy,
                &capabilities,
                signal,
            ),
            Ok(Some(response))
        );
        assert_eq!(backend.injected, Some((2, 65)));
        assert_eq!(response_route.pending(), None);

        let mut denied_route =
            MicrovmInterfaceResponseInterrupt::new(identity, response.projection(), vm, 2, 66, interrupt_object);
        denied_route.publish(response).unwrap();
        assert!(matches!(
            deliver_microvm_interface_response_interrupt(
                &mut denied_route,
                &mut backend,
                &mut vms,
                &policy,
                &capabilities,
                signal,
            ),
            Err(MicrovmInterfaceInterruptError::Injection(
                VmRunError::Policy(VmError::InterruptDenied)
            ))
        ));
        assert_eq!(denied_route.pending(), Some(response));
    }

    #[test]
    fn uncertain_interface_notification_delivery_fails_vm_and_retains_pending_token() {
        let interrupt_object = ObjectId(0x995);
        let mut capabilities = CapabilitySpace::<12>::new();
        let signal = capabilities
            .insert(interrupt_object, Rights::SIGNAL)
            .unwrap();
        let (identity, request, _) = interface_notifications(&mut capabilities);
        let (mut vms, vm) = running_vm();
        let mut policy = InterruptPolicy::deny_all();
        policy.allow(64).unwrap();
        let mut backend = Backend {
            injected: None,
            fail: true,
        };
        let mut route =
            MicrovmInterfaceRequestInterrupt::new(identity, request.projection(), vm, 0, 64, interrupt_object);
        route.publish(request).unwrap();
        assert_eq!(
            deliver_microvm_interface_request_interrupt(
                &mut route,
                &mut backend,
                &mut vms,
                &policy,
                &capabilities,
                signal,
            ),
            Err(MicrovmInterfaceInterruptError::Injection(
                VmRunError::Backend(())
            ))
        );
        assert_eq!(vms.state(vm), Ok(VmState::Failed));
        assert_eq!(route.pending(), Some(request));
    }

    #[test]
    fn exception_and_spurious_vectors_cannot_be_allowed() {
        let mut policy = InterruptPolicy::deny_all();
        assert_eq!(policy.allow(31), Err(VmError::InterruptDenied));
        assert_eq!(policy.allow(255), Err(VmError::InterruptDenied));
        policy.allow(32).unwrap();
        policy.allow(254).unwrap();
        assert!(policy.permits(32));
        policy.deny(32);
        assert!(!policy.permits(32));
    }

    #[test]
    fn injection_requires_vector_and_exact_capability_object() {
        let object = ObjectId(7);
        let wrong = ObjectId(8);
        let mut capabilities = CapabilitySpace::<2>::new();
        let right_cap = capabilities.insert(object, Rights::SIGNAL).unwrap();
        let wrong_cap = capabilities.insert(wrong, Rights::SIGNAL).unwrap();
        let mut policy = InterruptPolicy::deny_all();
        policy.allow(48).unwrap();
        let (mut vms, id) = running_vm();
        let mut backend = Backend {
            injected: None,
            fail: false,
        };
        assert_eq!(
            inject_vm_interrupt(
                &mut backend,
                &mut vms,
                id,
                2,
                49,
                &policy,
                &capabilities,
                right_cap,
                object
            ),
            Err(VmRunError::Policy(VmError::InterruptDenied))
        );
        assert_eq!(
            inject_vm_interrupt(
                &mut backend,
                &mut vms,
                id,
                2,
                48,
                &policy,
                &capabilities,
                wrong_cap,
                object
            ),
            Err(VmRunError::Policy(VmError::WrongObject))
        );
        inject_vm_interrupt(
            &mut backend,
            &mut vms,
            id,
            2,
            48,
            &policy,
            &capabilities,
            right_cap,
            object,
        )
        .unwrap();
        assert_eq!(backend.injected, Some((2, 48)));
    }

    #[test]
    fn uncertain_backend_injection_fails_vm() {
        let object = ObjectId(7);
        let mut capabilities = CapabilitySpace::<1>::new();
        let cap = capabilities.insert(object, Rights::SIGNAL).unwrap();
        let mut policy = InterruptPolicy::deny_all();
        policy.allow(48).unwrap();
        let (mut vms, id) = running_vm();
        let mut backend = Backend {
            injected: None,
            fail: true,
        };
        assert_eq!(
            inject_vm_interrupt(
                &mut backend,
                &mut vms,
                id,
                0,
                48,
                &policy,
                &capabilities,
                cap,
                object
            ),
            Err(VmRunError::Backend(()))
        );
        assert_eq!(vms.state(id), Ok(VmState::Failed));
    }

    #[test]
    fn virtual_block_notification_requires_exact_authority_and_acks_after_delivery() {
        let object = ObjectId(9);
        let wrong = ObjectId(10);
        let mut capabilities = CapabilitySpace::<2>::new();
        let right_cap = capabilities.insert(object, Rights::SIGNAL).unwrap();
        let wrong_cap = capabilities.insert(wrong, Rights::SIGNAL).unwrap();
        let mut policy = InterruptPolicy::deny_all();
        policy.allow(48).unwrap();
        let (mut vms, id) = running_vm();
        let mut backend = Backend {
            injected: None,
            fail: false,
        };
        let mut device = pending_block_device();

        assert_eq!(
            inject_virtual_block_interrupt(
                &mut device,
                &mut backend,
                &mut vms,
                id,
                3,
                &policy,
                &capabilities,
                wrong_cap,
                object,
            ),
            Err(VirtualBlockInterruptError::Injection(VmRunError::Policy(
                VmError::WrongObject
            )))
        );
        assert_eq!(device.pending_interrupt_vector(), Some(48));
        assert_eq!(backend.injected, None);

        assert_eq!(
            inject_virtual_block_interrupt(
                &mut device,
                &mut backend,
                &mut vms,
                id,
                3,
                &policy,
                &capabilities,
                right_cap,
                object,
            ),
            Ok(true)
        );
        assert_eq!(backend.injected, Some((3, 48)));
        assert_eq!(device.pending_interrupt_vector(), None);
        backend.injected = None;
        assert_eq!(
            inject_virtual_block_interrupt(
                &mut device,
                &mut backend,
                &mut vms,
                id,
                3,
                &policy,
                &capabilities,
                right_cap,
                object,
            ),
            Ok(false)
        );
        assert_eq!(backend.injected, None);
    }

    #[test]
    fn failed_virtual_block_injection_keeps_notification_pending_and_fails_vm() {
        let object = ObjectId(11);
        let mut capabilities = CapabilitySpace::<1>::new();
        let capability = capabilities.insert(object, Rights::SIGNAL).unwrap();
        let mut policy = InterruptPolicy::deny_all();
        policy.allow(48).unwrap();
        let (mut vms, id) = running_vm();
        let mut backend = Backend {
            injected: None,
            fail: true,
        };
        let mut device = pending_block_device();

        assert_eq!(
            inject_virtual_block_interrupt(
                &mut device,
                &mut backend,
                &mut vms,
                id,
                0,
                &policy,
                &capabilities,
                capability,
                object,
            ),
            Err(VirtualBlockInterruptError::Injection(VmRunError::Backend(
                ()
            )))
        );
        assert_eq!(vms.state(id), Ok(VmState::Failed));
        assert_eq!(device.pending_interrupt_vector(), Some(48));
    }
}
