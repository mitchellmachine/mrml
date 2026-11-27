//! Opt-in signed L2 Gigakernel and service diagnostic. No installed devices.
use core::{arch::asm, cell::UnsafeCell};

use mrml_kernel::arch::x86_64::{
    ActivePageTables, EptPointer, MinimalVmcsLaunch, NativeVmx, PRIVILEGE_STACK_ARENA_PAGES,
    PrivilegeStackLayout, VirtAddr, VmxControlPolicy, VmxController, VmxHostState,
    VmxLongModeGuest,
};
use mrml_kernel::{
    ArtifactKind, FramebufferInfo, MemoryKind, MemoryRegion, PhysAddr, PixelFormat, SignedArtifact,
    TrustRoot, encode_handoff,
};

use mrml_interface_zstd_v3::{
    BorrowedReadView, BorrowedWriteView, DECOMPRESS_REQUEST_BYTES, DECOMPRESS_RESPONSE_BYTES,
    decode_decompress_response, encode_decompress_request,
};

const PAGE: usize = 4096;
const ZSTD_CONTENT: usize = 3;
const ZSTD_FRAME: usize = 12;
const ZSTD_OUTPUT: usize = 32;
const ZSTD_MEMORY: usize = 64;
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
    Kernel([u8; 32]),
    Zstd([u8; ZSTD_CONTENT]),
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
}

pub(super) struct ServiceLaunch {
    guest: PreparedGuest,
    expected: [u8; ZSTD_CONTENT],
}

impl ServiceLaunch {
    pub(super) fn run(
        self,
        controller: &mut VmxController<NativeVmx>,
        controls: VmxControlPolicy,
        ticks: u32,
    ) -> Option<()> {
        self.guest.run_to_exit(controller, controls, ticks, 0xe8)?;
        // SAFETY: the exact service vCPU is stopped and only its own reply
        // page can be written by the guest at this address. Copy the bounded
        // reply before interpreting it on the monitor side.
        let reply: [u8; DECOMPRESS_RESPONSE_BYTES + ZSTD_MEMORY] = unsafe {
            let ptr = SERVICE_ARENA.0.get().cast::<u8>().add(RAM + FRAMEBUFFER);
            ptr.cast::<[u8; DECOMPRESS_RESPONSE_BYTES + ZSTD_MEMORY]>()
                .read_volatile()
        };
        let (wire, output) = reply.split_at(DECOMPRESS_RESPONSE_BYTES);
        let decoded = decode_decompress_response(wire.try_into().ok()?)
            .ok()?
            .ok()?;
        (decoded == ZSTD_CONTENT as u64
            && output[ZSTD_OUTPUT..ZSTD_OUTPUT + ZSTD_CONTENT] == self.expected)
            .then_some(())
    }
}

impl PreparedGuest {
    pub(super) fn run(
        self,
        controller: &mut VmxController<NativeVmx>,
        controls: VmxControlPolicy,
        ticks: u32,
    ) -> Option<()> {
        self.run_to_exit(controller, controls, ticks, 0xe7)
    }

    fn run_to_exit(
        self,
        controller: &mut VmxController<NativeVmx>,
        controls: VmxControlPolicy,
        ticks: u32,
        port: u16,
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
        if observed_cw != probe_cw {
            return None;
        }
        let exit = controller.record_vm_exit_snapshot().ok()?;
        (exit.reason() == 30 && exit.qualification() == (u64::from(port) << 16) | (1 << 6))
            .then_some(())
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
    entropy: [u8; 32],
) -> Option<ServiceLaunch> {
    let expected: [u8; ZSTD_CONTENT] = entropy[..ZSTD_CONTENT].try_into().ok()?;
    let guest = prepare_payload(
        GuestPlatform {
            revision,
            controls,
            host,
            guest_cr0,
            guest_cr4,
        },
        Payload::Zstd(expected),
        include_bytes!(env!("MRML_VMX_SERVICE_BUNDLE")),
        root_digest(SERVICE_ROOT)?,
        root_digest(KERNEL_ROOT)?,
    )?;
    Some(ServiceLaunch { guest, expected })
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
        Payload::Kernel(_) => ArtifactKind::Kernel,
        Payload::Zstd(_) => ArtifactKind::ServiceImage,
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
        Payload::Kernel(_) => &ARENA,
        Payload::Zstd(_) => &SERVICE_ARENA,
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
    if matches!(payload, Payload::Zstd(_)) {
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
        Payload::Zstd(expected) => {
            let input = BorrowedReadView::within(0, ZSTD_FRAME as u64, ZSTD_MEMORY as u64)?;
            let output = BorrowedWriteView::within(
                ZSTD_OUTPUT as u64,
                ZSTD_CONTENT as u64,
                ZSTD_MEMORY as u64,
            )?;
            let wire = encode_decompress_request(input, output).ok()?;
            let request = &mut arena[RAM + HANDOFF..RAM + HANDOFF + PAGE];
            request[..DECOMPRESS_REQUEST_BYTES].copy_from_slice(&wire);
            // Same single raw block as the tested ABI-3 vector, with the
            // three output bytes selected from this boot's entropy.
            let header = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 3, 0x19, 0, 0];
            request[DECOMPRESS_REQUEST_BYTES..DECOMPRESS_REQUEST_BYTES + header.len()]
                .copy_from_slice(&header);
            request[DECOMPRESS_REQUEST_BYTES + header.len()..DECOMPRESS_REQUEST_BYTES + ZSTD_FRAME]
                .copy_from_slice(&expected);
            (HIGH + FRAMEBUFFER as u64, 0, 0)
        }
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
    if matches!(payload, Payload::Zstd(_)) {
        map(FRAMEBUFFER / PAGE, true, false, true);
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
    })
}
