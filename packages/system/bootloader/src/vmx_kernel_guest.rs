//! Opt-in signed L2 Gigakernel bootstrap. No installed services or device access.
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

const PAGE: usize = 4096;
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

#[repr(C, align(4096))]
struct Arena(UnsafeCell<[u8; ARENA_PAGES * PAGE]>);

// SAFETY: exclusive BSP preparation before VMX entry; no AP or device access.
unsafe impl Sync for Arena {}
static ARENA: Arena = Arena(UnsafeCell::new([0; ARENA_PAGES * PAGE]));

#[repr(C, align(16))]
struct FxState([u8; 512]);

pub(super) struct KernelLaunch {
    vmcs: PhysAddr,
    ept: EptPointer,
    launch: MinimalVmcsLaunch,
}

impl KernelLaunch {
    pub(super) fn run(self, controller: &mut VmxController<NativeVmx>) -> Option<()> {
        controller.clear_vmcs(self.vmcs).ok()?;
        controller.load_vmcs(self.vmcs, self.ept).ok()?;
        controller.program_minimal_vmcs(&self.launch).ok()?;
        let mut fx = FxState([0; 512]);
        // SAFETY: aligned host scratch; hosted BSP compiler uses legacy SSE,
        // and the signed L2 probe uses no extended AVX state.
        unsafe {
            asm!("fxsave64 [{}]", in(reg) fx.0.as_mut_ptr(), options(nostack, preserves_flags))
        };
        let launched = controller.launch();
        // SAFETY: VM entry is synchronous and has returned to the same BSP;
        // this area is host-only and was not mapped into the guest.
        unsafe { asm!("fxrstor64 [{}]", in(reg) fx.0.as_ptr(), options(nostack, preserves_flags)) };
        launched.ok()?;
        let exit = controller.record_vm_exit_snapshot().ok()?;
        (exit.reason() == 30 && exit.qualification() == (0xe7 << 16) | (1 << 6)).then_some(())
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
) -> Option<KernelLaunch> {
    let bundle = include_bytes!(env!("MRML_VMX_KERNEL_BUNDLE"));
    let root = root_digest(env!("MRML_VMX_KERNEL_ROOT"))?;
    let signed = SignedArtifact::decode(bundle).ok()?;
    let mut wrong = root;
    wrong[0] ^= 1;
    if signed
        .verify_executable(
            &TrustRoot::new(ArtifactKind::Kernel, wrong, 1),
            ArtifactKind::Kernel,
        )
        .is_ok()
    {
        return None;
    }
    let executable = signed
        .verify_executable(
            &TrustRoot::new(ArtifactKind::Kernel, root, 1),
            ArtifactKind::Kernel,
        )
        .ok()?;
    let pe = executable.image();
    let end = IMAGE.checked_add(pe.image_size() as usize)?;
    if end > PAGES * PAGE {
        return None;
    }
    // SAFETY: the entry is used once by the bootstrap CPU before guests run.
    let arena = unsafe { &mut *ARENA.0.get() };
    arena.fill(0);
    // SAFETY: the UEFI loader installed this BSP's validated four-level tables.
    let active = unsafe { ActivePageTables::current() }.ok()?;
    let mut frames = [0u64; ARENA_PAGES];
    let base = arena.as_ptr() as u64;
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
    let entry = pe
        .materialize_at(&mut arena[RAM + IMAGE..RAM + end], HIGH + IMAGE as u64)
        .ok()?;
    let stacks =
        PrivilegeStackLayout::new(HIGH + STACK as u64, PRIVILEGE_STACK_ARENA_PAGES).ok()?;
    let stack_top = stacks.early_top().ok()?.checked_add(8)?;
    let regions = [
        MemoryRegion::new(PhysAddr::new(FRAMEBUFFER as u64).ok()?, 1, MemoryKind::Mmio).ok()?,
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
    // Win64 ABI: RCX handoff, RDX length, R8/R9 guarded IST stack tops.
    // Caller RSP is 16-byte aligned. Reserve home space before CALL.
    let mut pc = RAM + TRAMPOLINE;
    for (opcode, value) in [
        ([0x48, 0xb9], HIGH + HANDOFF as u64),
        ([0x48, 0xba], handoff_len as u64),
        ([0x49, 0xb8], stacks.entry_top().ok()?),
        ([0x49, 0xb9], stacks.double_fault_top().ok()?),
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
    Some(KernelLaunch {
        vmcs: PhysAddr::new(frames[VMCS]).ok()?,
        ept,
        launch,
    })
}
