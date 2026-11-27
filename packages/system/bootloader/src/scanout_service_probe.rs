//! Hosted-only signed compositor diagnostic. No display hardware access.
use super::*;

const ENDPOINT: ObjectId = ObjectId(0x5c01);
const FRAME: ObjectId = ObjectId(0x5c02);
const FRAME_BYTES: usize = 16 * 1024;
const READY: [u8; 16] = *b"MRMLSCN1\x00\x40\x00\x00\x00\x00\x00\x00";
type Runtime = TaskRuntime<SERVICE_TASK_CAPACITY, SERVICE_CAPABILITY_CAPACITY>;

struct Probe {
    provider: mrml_kernel::TaskId,
    caller: mrml_kernel::TaskId,
    grant: Capability,
    endpoint: Endpoint,
    denied: bool,
    copied: bool,
    released: bool,
    acknowledged: bool,
}

static mut PROBE: Option<Probe> = None;
static mut FRAME_BYTES_STORE: [u8; FRAME_BYTES] = [0; FRAME_BYTES];

pub(super) unsafe fn start() -> ! {
    // SAFETY: the hosted runner initialized this reserved mailbox before
    // entering the authenticated, single-BSP diagnostic kernel profile.
    let (entry, mode) = unsafe {
        (
            hosted_service_entry(),
            core::ptr::read_volatile((SERVICE_SHARED_PHYSICAL + 24) as *const u8),
        )
    };
    let denied = match mode {
        1 => false,
        2 => true,
        _ => halt(),
    };
    let context = |root| {
        UserContext::new(
            PhysAddr::new(root).unwrap_or_else(|_| halt()),
            entry,
            SERVICE_STACK_TOP,
        )
        .unwrap_or_else(|_| halt())
    };
    let mut runtime = Runtime::new(1_000, 1).unwrap_or_else(|_| halt());
    let provider = runtime
        .create(Priority::RESPONSIVE, context(SERVICE_ROOT))
        .unwrap_or_else(|_| halt());
    let caller = runtime
        .create_for_construction(Priority::NORMAL, context(SERVICE_B_ROOT))
        .unwrap_or_else(|_| halt());
    let caps = runtime
        .capabilities_mut(provider)
        .unwrap_or_else(|_| halt());
    let grant = caps
        .insert(FRAME, if denied { Rights::READ } else { Rights::WRITE })
        .unwrap_or_else(|_| halt());
    let signal = caps
        .insert(ENDPOINT, Rights::SIGNAL)
        .unwrap_or_else(|_| halt());
    let caller_context = runtime.context_mut(provider).unwrap_or_else(|_| halt());
    caller_context.r12 = grant.token();
    caller_context.r13 = signal.token();
    caller_context.r14 = caller.token();
    if !matches!(runtime.start(), ScheduleOutcome::Switch { from: None, to } if to == provider) {
        halt();
    }
    // SAFETY: the BSP is the sole owner, and the runtime has not entered CPL3.
    unsafe {
        core::ptr::addr_of_mut!(PROBE).write(Some(Probe {
            provider,
            caller,
            grant,
            endpoint: Endpoint::new(ENDPOINT),
            denied,
            copied: false,
            released: false,
            acknowledged: false,
        }));
        let pointer = core::ptr::addr_of_mut!(SERVICE_RUNTIME);
        pointer.write(Some(runtime));
        enter_service_task((*pointer).as_mut().unwrap_or_else(|| halt()), provider);
    }
}

pub(super) unsafe fn dispatch(
    runtime: &mut Runtime,
    current: mrml_kernel::TaskId,
    root: PhysAddr,
    request: SyscallRequest,
    frame: &mut UserCallFrame,
) {
    // SAFETY: hosted single-BSP fixture; no other owner touches this probe.
    let (state, bytes) = unsafe {
        (
            (*core::ptr::addr_of_mut!(PROBE)).as_mut().unwrap_or_else(|| halt()),
            &mut *core::ptr::addr_of_mut!(FRAME_BYTES_STORE),
        )
    };
    if current != state.provider {
        halt();
    }
    match request {
        SyscallRequest::WriteSharedBuffer {
            capability,
            offset,
            input_address,
            length,
        } if capability == state.grant
            && offset == 0
            && length as usize == FRAME_BYTES
            && !state.copied
            && !state.released
            && runtime
                .authorize_capability_exact(current, capability, Rights::WRITE, FRAME)
                .is_ok() =>
        {
            // SAFETY: the active root and complete user-readable range are
            // independently checked by the existing guarded copy routine.
            if unsafe { try_copy_from_active_user(root, current, input_address, bytes) }
            {
                state.copied = true;
                frame.complete(0);
                return;
            }
        }
        SyscallRequest::ReleaseCapability { capability }
            if capability == state.grant
                && !state.released
                && runtime.revoke_capability(current, capability).is_ok() =>
        {
            state.released = true;
            frame.complete(0);
            return;
        }
        SyscallRequest::SendBuffer {
            endpoint,
            receiver,
            payload_address,
            payload_length,
            capability_count,
            ..
        } if state.copied
            && state.released
            && !state.acknowledged
            && receiver == state.caller
            && capability_count == 0
            && payload_length as usize == READY.len() =>
        {
            let mut ready = [0; READY.len()];
            // SAFETY: use the same active-user checked copy as the data path.
            if unsafe { try_copy_from_active_user(root, current, payload_address, &mut ready) }
                && ready == READY
                && runtime
                    .authorize_capability_exact(current, endpoint, Rights::SIGNAL, ENDPOINT)
                    .is_ok()
                && runtime
                    .deliver_ipc(
                        current,
                        receiver,
                        &mut state.endpoint,
                        endpoint,
                        &ready,
                        &[],
                    )
                    .is_ok()
            {
                let message = runtime
                    .receive_ipc_envelope_bounded(receiver, READY.len(), 0)
                    .unwrap_or_else(|_| halt());
                if message.sender() != current
                    || message.message().payload() != READY
                    || message.message().authorize_no_capabilities().is_err()
                {
                    halt();
                }
                state.acknowledged = true;
                frame.complete(0);
                return;
            }
        }
        SyscallRequest::Exit if state.released => {
            if state.denied
                && !state.copied
                && !state.acknowledged
                && bytes.iter().all(|&byte| byte == 0)
            {
                emit(SERVICE_PROBE_PORT, 0x5c02);
            } else if !state.denied && state.copied && state.acknowledged {
                emit(SERVICE_PROBE_PORT, 0x5c01);
                for word in bytes.chunks_exact(4) {
                    emit(
                        SERVICE_FRAME_PORT,
                        u32::from_le_bytes(word.try_into().unwrap_or_else(|_| halt())),
                    );
                }
                bytes.fill(0);
                emit(SERVICE_PROBE_PORT, 0x5c03);
            }
            halt();
        }
        _ => {}
    }
    frame.complete_error();
}

fn emit(port: u16, value: u32) {
    // SAFETY: diagnostic kernel only, and this caller uses only its reserved
    // hosted proof ports, not firmware, graphics MMIO or any physical device.
    unsafe { asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack)) };
}
