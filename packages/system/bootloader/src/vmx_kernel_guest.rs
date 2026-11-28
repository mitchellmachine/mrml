//! Opt-in signed L2 Gigakernel, Zstd, and desktop diagnostics. No installed devices.
use core::{arch::asm, cell::UnsafeCell};

use mrml_kernel::arch::x86_64::{
    ActivePageTables, EptPointer, MinimalVmcsLaunch, NativeVmx, PRIVILEGE_STACK_ARENA_PAGES,
    PrivilegeStackLayout, VirtAddr, VmxControlPolicy, VmxController, VmxHostState,
    VmxLongModeGuest,
};
use mrml_kernel::{ArtifactKind, PhysAddr, SignedArtifact, TrustRoot};

#[cfg(not(feature = "vmx-desktop-monitor"))]
use mrml_kernel::{
    CapabilitySpace, FramebufferInfo, MemoryKind, MemoryPoolTable, MemoryRegion,
    MicrovmInterfaceQueueIdentity, MicrovmInterfaceQueuePair, ObjectId, PixelFormat, Rights,
    encode_handoff, reserve_microvm_peer_page_projection,
};

#[cfg(not(feature = "vmx-desktop-monitor"))]
use super::vmx_zstd_call::{CALL_GPA, REPLY, REQUEST};
#[cfg(not(feature = "vmx-desktop-monitor"))]
use mrml_interface_zstd_v3::{INTERFACE_FINGERPRINT, INTERFACE_GENERATION, OP_DECOMPRESS};

const PAGE: usize = 4096;
const KERNEL_ROOT: &str = env!("MRML_VMX_KERNEL_ROOT");
const SERVICE_ROOT: &str = env!("MRML_VMX_SERVICE_ROOT");
const GROUPS: usize = 5;
const PAGES: usize = GROUPS * 512;
const EPT_TABLES: usize = 3 + GROUPS;
const VMCS: usize = EPT_TABLES;
const ARENA_PAGES: usize = VMCS + 1 + PAGES;
const RAM: usize = (VMCS + 1) * PAGE;
const HIGH: u64 = 0xffff_8000_0000_0000;
const IMAGE: usize = 0x20_0000;
const TRAMPOLINE: usize = 0x10_000;
const HANDOFF: usize = 0x11_000;
const GDT: usize = 0x12_000;
#[cfg(not(feature = "vmx-desktop-monitor"))]
const ACPI: usize = 0x13_000;
const FRAMEBUFFER: usize = 0x14_000;
const STACK: usize = 0x40_000;
const _: () = assert!(STACK + PRIVILEGE_STACK_ARENA_PAGES as usize * PAGE <= IMAGE);

#[repr(C, align(4096))]
struct Arena(UnsafeCell<[u8; ARENA_PAGES * PAGE]>);

// SAFETY: exclusive BSP preparation before VMX entry; no AP or device access.
unsafe impl Sync for Arena {}
static ARENA: Arena = Arena(UnsafeCell::new([0; ARENA_PAGES * PAGE]));
static SERVICE_ARENA: Arena = Arena(UnsafeCell::new([0; ARENA_PAGES * PAGE]));

#[derive(Clone, Copy)]
enum Payload {
    #[cfg(not(feature = "vmx-desktop-monitor"))]
    Kernel([u8; 32]),
    Service,
}

struct GuestPlatform {
    revision: u32,
    controls: VmxControlPolicy,
    host: VmxHostState,
    guest_cr0: u64,
    guest_cr4: u64,
}

pub(super) struct PreparedGuest {
    vmcs: PhysAddr,
    ept: EptPointer,
    launch: MinimalVmcsLaunch,
    image_end: u64,
    artifact_version: u64,
}

pub(super) struct ServiceLaunch {
    guest: PreparedGuest,
}

impl ServiceLaunch {
    fn exchange<const REQUEST_BYTES: usize, const REPLY_BYTES: usize>(
        self,
        controller: &mut VmxController<NativeVmx>,
        controls: VmxControlPolicy,
        ticks: u32,
        request: [u8; REQUEST_BYTES],
    ) -> Option<[u8; REPLY_BYTES]> {
        Self::write_request(request)?;
        self.guest.start(controller, controls, ticks)?;
        terminal(controller, 0xe8)?;
        Self::read_reply()
    }

    fn write_request<const REQUEST_BYTES: usize>(request: [u8; REQUEST_BYTES]) -> Option<()> {
        if REQUEST_BYTES > PAGE {
            return None;
        }
        // SAFETY: only the BSP calls this with the service vCPU stopped,
        // before its first launch or while its exact continuation is parked.
        // This is the fixed RO guest request page; only the monitor writes it.
        unsafe {
            SERVICE_ARENA
                .0
                .get()
                .cast::<u8>()
                .add(RAM + HANDOFF)
                .cast::<[u8; REQUEST_BYTES]>()
                .write_volatile(request);
        }
        Some(())
    }

    fn read_reply<const REPLY_BYTES: usize>() -> Option<[u8; REPLY_BYTES]> {
        if REPLY_BYTES > PAGE {
            return None;
        }
        // SAFETY: the exact service vCPU is stopped. Copy only its fixed,
        // bounded response, not guest-controlled memory locations or sizes.
        Some(unsafe {
            SERVICE_ARENA
                .0
                .get()
                .cast::<u8>()
                .add(RAM + FRAMEBUFFER)
                .cast::<[u8; REPLY_BYTES]>()
                .read_volatile()
        })
    }
}

#[cfg(feature = "vmx-desktop-monitor")]
#[inline(never)]
pub(super) fn run_desktop_probe(
    service: ServiceLaunch,
    controller: &mut VmxController<NativeVmx>,
    controls: VmxControlPolicy,
    ticks: u32,
    framebuffer: mrml_kernel::FramebufferInfo,
) -> Option<PhysAddr> {
    use mrml_boot_frame::{BOOT_REPLY_BYTES, FRAME_BYTES, HEIGHT, WIDTH, decode_boot_reply};
    #[cfg(not(feature = "vmx-desktop-qemu-keyboard"))]
    use mrml_boot_frame::BootScene;
    use mrml_kernel::{
        CapabilitySpace, DisplayOutputIdentity, FramebufferLayout, IsolationAdmissionTable,
        IsolationMode, IsolationPlacement, IsolationServiceSpec, ObjectId, PixelFormat, Rights,
        TotalMicrovmClass, prepare_isolation_service_route,
    };

    // One boot-local policy, one output, and one admitted device-free guest.
    // The provider generation is the exact signed artifact's version.
    let vmcs = service.guest.vmcs;
    let mut admission = IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, 1, 1).ok()?;
    let spec = IsolationServiceSpec::new(
        ObjectId(vmcs.get()), ObjectId(0xd02), 1, service.guest.artifact_version,
        1, 1, TotalMicrovmClass::MicrovmEligible, IsolationPlacement::Microvm,
    ).ok()?;
    let route = prepare_isolation_service_route(&mut admission, spec).ok()?.commit(&mut admission, ()).ok()?;
    let mut frame = [0; FRAME_BYTES];
    let source = FramebufferLayout::new(
        FRAME_BYTES as u64, WIDTH as u32, HEIGHT as u32, WIDTH as u32,
        PixelFormat::BlueGreenRedReserved,
    ).ok()?;
    let identity = DisplayOutputIdentity::new(ObjectId(0xd30), 1).ok()?;
    let mut caps = CapabilitySpace::<1>::new();
    let control = caps.insert(identity.object(), Rights::CONTROL).ok()?;
    let mut present = |reply: &[u8; BOOT_REPLY_BYTES]| -> Option<()> {
        decode_boot_reply(reply, &mut frame).ok()?;
        // The only capture is an immutable view of the bounded host copy
        // from the fixed reply page of this exact parked desktop guest.
        super::with_diagnostic_framebuffer(framebuffer, |output| {
            mrml_compositor::publish_total_guest_scanout(
                &admission, &route, spec, &caps, control, identity, identity,
                source, framebuffer.layout(), mrml_compositor::BootProjection::FitCentered,
                |_| Some(frame.as_slice()), output,
            )
        }).ok()
    };
    #[cfg(feature = "vmx-desktop-qemu-keyboard")]
    let result = live_desktop(service, controller, controls, ticks, &mut present);
    #[cfg(not(feature = "vmx-desktop-qemu-keyboard"))]
    let result = (|| {
        let reply: [u8; BOOT_REPLY_BYTES] = if cfg!(feature = "vmx-desktop-persistent-probe") {
            persistent_desktop(service, controller, controls, ticks)?
        } else {
            let scene = if cfg!(feature = "vmx-desktop-input-probe") {
                BootScene::Enter
            } else {
                BootScene::Idle
            };
            service.exchange(controller, controls, ticks, scene.request())?
        };
        present(&reply)
    })();
    admission.retire(route.domain()).ok()?;
    caps.revoke(control).ok()?;
    result?;
    // The caller retires this VMCS after restoring the separately parked
    // timer guest. The desktop is already stopped and cannot be reloaded.
    Some(vmcs)
}

#[cfg(feature = "vmx-desktop-qemu-keyboard")]
#[inline(never)]
fn live_desktop(
    service: ServiceLaunch,
    controller: &mut VmxController<NativeVmx>,
    controls: VmxControlPolicy,
    ticks: u32,
    present: &mut impl FnMut(&[u8; mrml_boot_frame::BOOT_REPLY_BYTES]) -> Option<()>,
) -> Option<()> {
    use mrml_boot_frame::{BOOT_REPLY_BYTES, BootScene, MAX_LIVE_KEYS};
    let guest = service.guest;
    let mut keyboard = super::vmx_qemu_keyboard::QemuKeyboard::probe()?;
    ServiceLaunch::write_request(BootScene::LiveBegin.request())?;
    guest.start(controller, controls, ticks)?;
    let bounds = HIGH + IMAGE as u64..guest.image_end;
    let park = |controller: &mut VmxController<NativeVmx>| {
        controller.park_boot_call_probe(bounds.clone()).ok()
    };
    let resume = |controller: &mut VmxController<NativeVmx>, scene: BootScene| -> Option<()> {
        ServiceLaunch::write_request(scene.request())?;
        controller.reload_boot_probe_guest(guest.vmcs, guest.ept).ok()?;
        controller.arm_boot_probe_timer(controls, ticks).ok()?;
        controller.resume().ok()
    };
    park(controller)?;
    let mut last: [u8; BOOT_REPLY_BYTES] = ServiceLaunch::read_reply()?;
    present(&last)?;
    super::vmx_probe::trace(0xca);

    let enter = keyboard.await_key(BootScene::Enter)?;
    super::vmx_probe::trace(0xcd);
    resume(controller, enter)?;
    park(controller)?;
    last = ServiceLaunch::read_reply()?;
    present(&last)?;
    super::vmx_probe::trace(0xcb);

    for _ in 0..MAX_LIVE_KEYS {
        let Some(scene @ BootScene::Letter(_)) = keyboard.await_text() else {
            break;
        };
        resume(controller, scene)?;
        park(controller)?;
        let next = ServiceLaunch::read_reply()?;
        if last == next {
            return None;
        }
        present(&next)?;
        last = next;
        super::vmx_probe::trace(0xce);
    }
    resume(controller, BootScene::End)?;
    terminal(controller, 0xe8)?;
    let end: [u8; BOOT_REPLY_BYTES] = ServiceLaunch::read_reply()?;
    if end != last {
        return None;
    }
    super::vmx_probe::trace(0xcf);
    Some(())
}

#[cfg(all(feature = "vmx-desktop-monitor", not(feature = "vmx-desktop-qemu-keyboard")))]
#[inline(never)]
fn persistent_desktop(
    service: ServiceLaunch,
    controller: &mut VmxController<NativeVmx>,
    controls: VmxControlPolicy,
    ticks: u32,
) -> Option<[u8; mrml_boot_frame::BOOT_REPLY_BYTES]> {
    use mrml_boot_frame::{BOOT_REPLY_BYTES, BootScene, validate_boot_reply};
    let guest = service.guest;
    ServiceLaunch::write_request(BootScene::Begin.request())?;
    guest.start(controller, controls, ticks)?;
    let bounds = HIGH + IMAGE as u64..guest.image_end;
    controller.park_boot_call_probe(bounds.clone()).ok()?;
    let idle: [u8; BOOT_REPLY_BYTES] = ServiceLaunch::read_reply()?;
    validate_boot_reply(&idle).ok()?;
    super::vmx_probe::trace(0xca);

    let mut resume = |scene: BootScene| -> Option<()> {
        ServiceLaunch::write_request(scene.request())?;
        controller.reload_boot_probe_guest(guest.vmcs, guest.ept).ok()?;
        controller.arm_boot_probe_timer(controls, ticks).ok()?;
        controller.resume().ok()
    };
    // The same VMCS, EPT and guest stack are kept across both yields.
    let enter = BootScene::Enter;
    resume(enter)?;
    controller.park_boot_call_probe(bounds).ok()?;
    let entered: [u8; BOOT_REPLY_BYTES] = ServiceLaunch::read_reply()?;
    validate_boot_reply(&entered).ok()?;
    if entered == idle {
        return None;
    }
    super::vmx_probe::trace(0xcb);
    let text = BootScene::TextA;
    ServiceLaunch::write_request(text.request())?;
    controller.reload_boot_probe_guest(guest.vmcs, guest.ept).ok()?;
    controller.arm_boot_probe_timer(controls, ticks).ok()?;
    controller.resume().ok()?;
    terminal(controller, 0xe8)?;
    let typed = ServiceLaunch::read_reply()?;
    (typed != entered).then_some(typed)
}

fn terminal(controller: &mut VmxController<NativeVmx>, port: u16) -> Option<()> {
    let exit = controller.record_vm_exit_snapshot().ok()?;
    (exit.reason() == 30 && exit.qualification() == (u64::from(port) << 16) | (1 << 6))
        .then_some(())
}

/// Route one call through the existing generation-bound capability queue.
/// The queue is monitor-local: only bounded copies enter either stopped VM.
#[cfg(not(feature = "vmx-desktop-monitor"))]
pub(super) fn run_service_call(
    caller: PreparedGuest,
    service: ServiceLaunch,
    controller: &mut VmxController<NativeVmx>,
    controls: VmxControlPolicy,
    ticks: u32,
) -> Option<()> {
    let mut caps = CapabilitySpace::<8>::new();
    let mut memory = MemoryPoolTable::<1, 1, 2>::new(0x900).ok()?;
    let (pool, pool_capability) = memory
        .create_root(
            1,
            2,
            0,
            Rights::ALLOCATE
                .union(Rights::CONTROL)
                .union(Rights::INSPECT),
            &mut caps,
        )
        .ok()?;
    let rights = Rights::MAP.union(Rights::INSPECT).union(Rights::CONTROL);
    let first = caps.insert(ObjectId(caller.vmcs.get()), rights).ok()?;
    let second = caps
        .insert(ObjectId(service.guest.vmcs.get()), rights)
        .ok()?;
    let foreign = caps.insert(ObjectId(0x901), rights).ok()?;
    let (projection, _) = reserve_microvm_peer_page_projection(
        &mut memory,
        pool,
        pool_capability,
        first,
        second,
        0x700,
        0x800,
        &mut caps,
    )
    .ok()?;
    // This diagnostic has one policy and one binding. Its provider and
    // caller generations are the versions of the verified signed artifacts.
    let identity = MicrovmInterfaceQueueIdentity::new(
        INTERFACE_FINGERPRINT,
        INTERFACE_GENERATION,
        service.guest.artifact_version,
        caller.artifact_version,
        1,
        1,
    )
    .ok()?;
    if MicrovmInterfaceQueuePair::bind(identity, &projection, foreign, second, &caps).is_ok() {
        return None;
    }
    let (mut client, mut provider) =
        MicrovmInterfaceQueuePair::bind(identity, &projection, first, second, &caps)
            .ok()?
            .split();
    let mut queue = [0; PAGE];
    client.initialize(&mut queue, &projection, &caps).ok()?;

    caller.start(controller, controls, ticks)?;
    controller
        .park_boot_call_probe(HIGH + IMAGE as u64..caller.image_end)
        .ok()?;
    let caller_page = ARENA.0.get().cast::<u8>().wrapping_add(RAM + CALL_GPA);
    // SAFETY: the measured caller is parked and the address is its fixed
    // RW/NX mailbox, not a pointer selected by the guest.
    let request = unsafe { caller_page.cast::<[u8; REQUEST]>().read_volatile() };
    let submitted = client
        .submit(&mut queue, &projection, &caps, OP_DECOMPRESS, &request)
        .ok()?;
    let mut payload = [0; REQUEST];
    let (sequence, operation, length) = provider
        .receive_request(&queue, &projection, &caps, submitted, &mut payload)
        .ok()?;
    if sequence != 1 || operation != OP_DECOMPRESS || length != REQUEST {
        return None;
    }
    let reply: [u8; REPLY] = service.exchange(controller, controls, ticks, payload)?;
    let notification = provider
        .respond(&mut queue, &projection, &caps, sequence, operation, &reply)
        .ok()?;
    let mut received = [0; REPLY];
    if client
        .consume_response(&mut queue, &projection, &caps, notification, &mut received)
        .ok()?
        != (OP_DECOMPRESS, REPLY)
        || client
            .consume_response(&mut queue, &projection, &caps, notification, &mut received)
            .is_ok()
    {
        return None;
    }
    caps.revoke(first).ok()?;
    if client
        .submit(&mut queue, &projection, &caps, OP_DECOMPRESS, &request)
        .is_ok()
    {
        return None;
    }
    // SAFETY: caller remains parked; this writes only its private mailbox
    // after authenticated completion, dropping the old request bytes.
    unsafe {
        let mut cleared = [0; REQUEST];
        cleared[..REPLY].copy_from_slice(&received);
        caller_page.cast::<[u8; REQUEST]>().write_volatile(cleared);
    }
    super::vmx_probe::trace(0xc6);
    controller
        .reload_boot_probe_guest(caller.vmcs, caller.ept)
        .ok()?;
    controller.arm_boot_probe_timer(controls, ticks).ok()?;
    controller.resume().ok()?;
    terminal(controller, 0xe7)
}

impl PreparedGuest {
    fn start(
        &self,
        controller: &mut VmxController<NativeVmx>,
        controls: VmxControlPolicy,
        ticks: u32,
    ) -> Option<()> {
        controller.clear_vmcs(self.vmcs).ok()?;
        controller.load_vmcs(self.vmcs, self.ept).ok()?;
        controller.program_minimal_vmcs(&self.launch).ok()?;
        controller.arm_boot_probe_timer(controls, ticks).ok()?;
        let mut original_cw = 0u16;
        // SAFETY: this diagnostic reaches here only after earlier isolated
        // entries validated x87 on the same BSP. The output word is aligned.
        unsafe {
            asm!("fnstcw [{}]", in(reg) &mut original_cw, options(nostack, preserves_flags));
        }
        let probe_cw = (original_cw & !0x0c00) | 0x0800;
        // SAFETY: both operands are live aligned words; `probe_cw` retains
        // all non-rounding bits from the CPU's own valid control word.
        unsafe { asm!("fldcw [{}]", in(reg) &probe_cw, options(nostack, preserves_flags)) };
        let launched = controller.launch();
        let mut observed_cw = 0u16;
        // SAFETY: synchronous VM entry returned to the same BSP, which
        // retains its host CR0/CR4 prerequisites. Restore the original word.
        unsafe {
            asm!("fnstcw [{}]", "fldcw [{}]", in(reg) &mut observed_cw, in(reg) &original_cw,
                options(nostack, preserves_flags));
        }
        launched.ok()?;
        (observed_cw == probe_cw).then_some(())
    }
}

fn root_digest(hex: &str) -> Option<[u8; 64]> {
    if hex.len() != 128 || !hex.is_ascii() {
        return None;
    }
    let mut out = [0; 64];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(not(feature = "vmx-desktop-monitor"))]
pub(super) fn prepare(
    revision: u32,
    controls: VmxControlPolicy,
    host: VmxHostState,
    guest_cr0: u64,
    guest_cr4: u64,
    entropy: [u8; 32],
) -> Option<PreparedGuest> {
    prepare_payload(
        GuestPlatform {
            revision,
            controls,
            host,
            guest_cr0,
            guest_cr4,
        },
        Payload::Kernel(entropy),
        include_bytes!(env!("MRML_VMX_KERNEL_BUNDLE")),
        root_digest(KERNEL_ROOT)?,
        root_digest(SERVICE_ROOT)?,
    )
}

pub(super) fn prepare_service(
    revision: u32,
    controls: VmxControlPolicy,
    host: VmxHostState,
    guest_cr0: u64,
    guest_cr4: u64,
) -> Option<ServiceLaunch> {
    let guest = prepare_payload(
        GuestPlatform {
            revision,
            controls,
            host,
            guest_cr0,
            guest_cr4,
        },
        Payload::Service,
        include_bytes!(env!("MRML_VMX_SERVICE_BUNDLE")),
        root_digest(SERVICE_ROOT)?,
        root_digest(KERNEL_ROOT)?,
    )?;
    Some(ServiceLaunch { guest })
}

fn prepare_payload(
    platform: GuestPlatform,
    payload: Payload,
    bundle: &[u8],
    root: [u8; 64],
    other_root: [u8; 64],
) -> Option<PreparedGuest> {
    let GuestPlatform {
        revision,
        controls,
        host,
        guest_cr0,
        guest_cr4,
    } = platform;
    if root == other_root {
        return None;
    }
    let kind = match payload {
        #[cfg(not(feature = "vmx-desktop-monitor"))]
        Payload::Kernel(_) => ArtifactKind::Kernel,
        Payload::Service => ArtifactKind::ServiceImage,
    };
    let signed = SignedArtifact::decode(bundle).ok()?;
    if signed
        .verify_executable(&TrustRoot::new(kind, other_root, 1), kind)
        .is_ok()
    {
        return None;
    }
    let executable = signed
        .verify_executable(&TrustRoot::new(kind, root, 1), kind)
        .ok()?;
    let pe = executable.image();
    let end = IMAGE.checked_add(pe.image_size() as usize)?;
    if end > PAGES * PAGE {
        return None;
    }
    let backing = match payload {
        #[cfg(not(feature = "vmx-desktop-monitor"))]
        Payload::Kernel(_) => &ARENA,
        Payload::Service => &SERVICE_ARENA,
    };
    // SAFETY: the UEFI loader installed this BSP's validated four-level tables.
    let active = unsafe { ActivePageTables::current() }.ok()?;
    let mut frames = [0u64; ARENA_PAGES];
    let base = backing.0.get() as u64;
    for (index, frame) in frames.iter_mut().enumerate() {
        let leaf = active
            .leaf(VirtAddr::new(base.checked_add((index * PAGE) as u64)?).ok()?)
            .ok()??;
        if !leaf.writable()
            || leaf.user()
            || leaf.device_pat_index_three()
            || leaf.physical().get() == 0
        {
            return None;
        }
        *frame = leaf.physical().get();
    }
    let mut sorted = frames;
    sorted.sort_unstable();
    if sorted.windows(2).any(|w| w[0] == w[1]) {
        return None;
    }
    if matches!(payload, Payload::Service) {
        let kernel_base = ARENA.0.get() as u64;
        for index in 0..ARENA_PAGES {
            let leaf = active
                .leaf(VirtAddr::new(kernel_base + (index * PAGE) as u64).ok()?)
                .ok()??;
            if sorted.binary_search(&leaf.physical().get()).is_ok() {
                return None;
            }
        }
    }
    // SAFETY: every host frame is validated and the service and kernel
    // arenas cannot alias. The BSP's exclusive borrow ends before VM entry.
    let arena = unsafe { &mut *backing.0.get() };
    arena.fill(0);
    let entry = pe
        .materialize_at(&mut arena[RAM + IMAGE..RAM + end], HIGH + IMAGE as u64)
        .ok()?;
    let stacks =
        PrivilegeStackLayout::new(HIGH + STACK as u64, PRIVILEGE_STACK_ARENA_PAGES).ok()?;
    let stack_top = stacks.early_top().ok()?.checked_add(8)?;
    let (rdx, r8, r9) = match payload {
        #[cfg(not(feature = "vmx-desktop-monitor"))]
        Payload::Kernel(entropy) => {
            let regions = [
                MemoryRegion::new(PhysAddr::new(FRAMEBUFFER as u64).ok()?, 1, MemoryKind::Mmio)
                    .ok()?,
                MemoryRegion::new(
                    PhysAddr::new(STACK as u64).ok()?,
                    PRIVILEGE_STACK_ARENA_PAGES,
                    MemoryKind::Kernel,
                )
                .ok()?,
                MemoryRegion::new(
                    PhysAddr::new(IMAGE as u64).ok()?,
                    (pe.image_size() as u64).div_ceil(PAGE as u64),
                    MemoryKind::Kernel,
                )
                .ok()?,
            ];
            let framebuffer = FramebufferInfo::new(
                FRAMEBUFFER as u64,
                PAGE as u64,
                16,
                16,
                16,
                PixelFormat::BlueGreenRedReserved,
            )
            .ok()?;
            let handoff_len = encode_handoff(
                executable.artifact().version(),
                entropy,
                *executable.artifact().digest(),
                true,
                false,
                false,
                ACPI as u64,
                framebuffer,
                &regions,
                &mut arena[RAM + HANDOFF..RAM + HANDOFF + PAGE],
            )
            .ok()?;
            (
                handoff_len as u64,
                stacks.entry_top().ok()?,
                stacks.double_fault_top().ok()?,
            )
        }
        Payload::Service => (HIGH + FRAMEBUFFER as u64, 0, 0),
    };
    // Win64 ABI: RCX is the RO request/handoff, RDX is the RW service
    // reply or handoff length, and R8/R9 are kernel-only IST tops.
    // Caller RSP is 16-byte aligned. Reserve home space before CALL.
    let mut pc = RAM + TRAMPOLINE;
    for (opcode, value) in [
        ([0x48, 0xb9], HIGH + HANDOFF as u64),
        ([0x48, 0xba], rdx),
        ([0x49, 0xb8], r8),
        ([0x49, 0xb9], r9),
        ([0x48, 0xb8], entry),
    ] {
        arena[pc..pc + 2].copy_from_slice(&opcode);
        arena[pc + 2..pc + 10].copy_from_slice(&value.to_le_bytes());
        pc += 10;
    }
    arena[pc..pc + 7].copy_from_slice(&[0x48, 0x83, 0xec, 0x20, 0xff, 0xd0, 0xf4]);
    arena[VMCS * PAGE..VMCS * PAGE + 4].copy_from_slice(&revision.to_le_bytes());
    let mut put = |offset: usize, value: u64| {
        arena[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    };
    put(0, frames[1] | 7);
    put(PAGE, frames[2] | 7);
    put(RAM + PAGE + 256 * 8, 0x2003);
    put(RAM + 2 * PAGE, 0x3003);
    for group in 0..GROUPS {
        put(2 * PAGE + 8 * group, frames[3 + group] | 7);
        put(RAM + 3 * PAGE + 8 * group, ((4 + group) * PAGE) as u64 | 3);
    }
    put(RAM + GDT + 8, 0x00af_9b00_0000_ffff);
    put(RAM + GDT + 16, 0x00cf_9300_0000_ffff);
    let tss = (GDT + 0x80) as u64;
    put(
        RAM + GDT + 24,
        0x0000_8b00_0000_0067 | ((tss & 0xffff) << 16) | ((tss & 0xff_0000) << 16),
    );
    put(RAM + GDT + 32, HIGH >> 32);
    let mut map = |page: usize, writable: bool, executable: bool, guest_leaf: bool| {
        let group = page / 512;
        let index = page % 512;
        let rights = 1 | if writable { 2 } else { 0 } | if executable { 4 } else { 0 };
        put(
            (3 + group) * PAGE + 8 * index,
            frames[VMCS + 1 + page] | (6 << 3) | rights,
        );
        if guest_leaf {
            let gpa = (page * PAGE) as u64;
            let rights = 1 | if writable { 2 } else { 0 } | if executable { 0 } else { 1 << 63 };
            put(RAM + (4 + group) * PAGE + 8 * index, gpa | rights);
        }
    };
    for page in 1..4 + GROUPS {
        map(page, true, false, false);
    }
    map(TRAMPOLINE / PAGE, false, true, true);
    map(HANDOFF / PAGE, false, false, true);
    map(GDT / PAGE, true, false, true);
    if matches!(payload, Payload::Service) {
        map(FRAMEBUFFER / PAGE, true, false, true);
    } else {
        #[cfg(not(feature = "vmx-desktop-monitor"))]
        map(CALL_GPA / PAGE, true, false, true);
    }
    for (start, pages) in [
        (STACK / PAGE, stacks.early_pages()),
        (
            (stacks.entry_base().ok()? - HIGH) as usize / PAGE,
            stacks.entry_pages(),
        ),
        (
            (stacks.double_fault_base().ok()? - HIGH) as usize / PAGE,
            stacks.double_fault_pages(),
        ),
    ] {
        for page in start..start + pages as usize {
            map(page, true, false, true);
        }
    }
    for index in 0..pe.load_region_count() {
        let region = pe.load_region(index).ok()?;
        let start = (IMAGE + region.virtual_address() as usize) / PAGE;
        let end = start.checked_add(region.pages() as usize)?;
        if end > PAGES || !region.readable() || (region.writable() && region.executable()) {
            return None;
        }
        for page in start..end {
            map(page, region.writable(), region.executable(), true);
        }
    }
    let ept = EptPointer::new(PhysAddr::new(frames[0]).ok()?, true).ok()?;
    let launch = MinimalVmcsLaunch::long_mode_probe(
        ept,
        controls,
        host,
        VmxLongModeGuest {
            cr0: (guest_cr0 & !((1 << 2) | (1 << 3))) | (1 << 31) | (1 << 16) | (1 << 5) | 1,
            cr3: PhysAddr::new(PAGE as u64).ok()?,
            cr4: guest_cr4 | (1 << 5) | (1 << 9) | (1 << 10),
            rip: HIGH + TRAMPOLINE as u64,
            rsp: stack_top,
            gdt_base: HIGH + GDT as u64,
            tss_base: HIGH + tss,
        },
    )
    .ok()?;
    Some(PreparedGuest {
        vmcs: PhysAddr::new(frames[VMCS]).ok()?,
        ept,
        launch,
        image_end: HIGH + end as u64,
        artifact_version: executable.artifact().version(),
    })
}
