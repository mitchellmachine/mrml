use core::arch::{asm, x86_64::__cpuid};
use core::cell::UnsafeCell;

use mrml_kernel::arch::x86_64::{
    ActivePageTables, EptPointer, MinimalVmcsLaunch, NativeVmx, VirtAddr, VmxCapabilities,
    VmxControlPolicy, VmxController, VmxError, VmxHostState, VmxLongModeGuest, VmxPrerequisites,
    VmxState,
};
use mrml_kernel::{PAGE_SIZE, PhysAddr};

const GUEST_PAGES: usize = 7;
const LONG_BASE: usize = 1 + 2 * GUEST_PAGES;
const PAGE_COUNT: usize = LONG_BASE + 12;
const LONG_VMCS: usize = LONG_BASE;
const LONG_EPT: usize = LONG_BASE + 1;
const LONG_RAM: usize = LONG_BASE + 5;
const HIGH: u64 = 0xffff_8000_0000_0000;
const LONG_STACK_TOP: u64 = HIGH + 0x7000;
const LONG_MARKER: u64 = 0x6574_6174_7334_3647;
const VMXON_PAGE: usize = 0;
const VMCS_PAGE: usize = 1;
const EPT_PML4_PAGE: usize = 2;
const EPT_PDPT_PAGE: usize = 3;
const EPT_PD_PAGE: usize = 4;
const EPT_PT_PAGE: usize = 5;
const GUEST_CODE_PAGE: usize = 6;
const PRIVATE_BACKING_PAGE: usize = 7;
const GUEST_CODE_GPA: u64 = 0x1000;
const PRIVATE_GPAS: [u16; 2] = [0x2000, 0x3000];
const INITIAL_BYTES: [u8; 2] = [0xa5, 0x5a];
const WRITTEN_BYTES: [u8; 2] = [0x3c, 0xc3];

fn guest_page(guest: usize, first_guest_page: usize) -> usize {
    guest * GUEST_PAGES + first_guest_page
}

#[repr(C, align(4096))]
struct ProbeArena(UnsafeCell<[u8; PAGE_COUNT * PAGE_SIZE as usize]>);
unsafe impl Sync for ProbeArena {}

static ARENA: ProbeArena = ProbeArena(UnsafeCell::new([0; PAGE_COUNT * PAGE_SIZE as usize]));

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct DescriptorTable {
    limit: u16,
    base: u64,
}

pub(super) fn trace(stage: u8) {
    unsafe { asm!("out dx, al", in("dx") 0xe9u16, in("al") stage, options(nomem, nostack)) };
}

unsafe fn rdmsr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!("rdmsr", in("ecx") msr, out("eax") low, out("edx") high, options(nomem, nostack))
    };
    (u64::from(high) << 32) | u64::from(low)
}

unsafe fn control_registers() -> (u64, u64, u64) {
    let cr0: u64;
    let cr3: u64;
    let cr4: u64;
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    (cr0, cr3, cr4)
}

unsafe fn selectors() -> [u16; 7] {
    let mut result = [0u16; 7];
    unsafe {
        asm!("mov {0:x}, es", out(reg) result[0], options(nomem, nostack, preserves_flags));
        asm!("mov {0:x}, cs", out(reg) result[1], options(nomem, nostack, preserves_flags));
        asm!("mov {0:x}, ss", out(reg) result[2], options(nomem, nostack, preserves_flags));
        asm!("mov {0:x}, ds", out(reg) result[3], options(nomem, nostack, preserves_flags));
        asm!("mov {0:x}, fs", out(reg) result[4], options(nomem, nostack, preserves_flags));
        asm!("mov {0:x}, gs", out(reg) result[5], options(nomem, nostack, preserves_flags));
        asm!("str {0:x}", out(reg) result[6], options(nomem, nostack, preserves_flags));
    }
    result
}

unsafe fn descriptor_tables() -> (DescriptorTable, DescriptorTable) {
    let mut gdtr = DescriptorTable { limit: 0, base: 0 };
    let mut idtr = DescriptorTable { limit: 0, base: 0 };
    unsafe {
        asm!("sgdt [{}]", in(reg) &mut gdtr, options(nostack, preserves_flags));
        asm!("sidt [{}]", in(reg) &mut idtr, options(nostack, preserves_flags));
    }
    (gdtr, idtr)
}

unsafe fn task_register_base(gdtr: DescriptorTable, selector: u16) -> Result<u64, ()> {
    if selector & 7 != 0 {
        return Err(());
    }
    let offset = usize::from(selector & !7);
    if offset
        .checked_add(15)
        .is_none_or(|end| end > usize::from(gdtr.limit))
    {
        return Err(());
    }
    let address = gdtr.base.checked_add(offset as u64).ok_or(())?;
    let low = unsafe { (address as *const u64).read_unaligned() };
    let high = unsafe { ((address + 8) as *const u64).read_unaligned() };
    let descriptor_type = (low >> 40) & 0xf;
    if low & (1 << 47) == 0 || !matches!(descriptor_type, 9 | 11) {
        return Err(());
    }
    Ok(((low >> 16) & 0xffff)
        | ((low >> 32) & 0xff) << 16
        | ((low >> 56) & 0xff) << 24
        | (high & 0xffff_ffff) << 32)
}

unsafe fn physical_pages() -> Result<[PhysAddr; PAGE_COUNT], ()> {
    let tables = unsafe { ActivePageTables::current() }.map_err(|_| ())?;
    let base = ARENA.0.get().cast::<u8>() as u64;
    let mut pages = [PhysAddr::new(0).map_err(|_| ())?; PAGE_COUNT];
    for index in 0..PAGE_COUNT {
        let virtual_address = base.checked_add((index as u64) * PAGE_SIZE).ok_or(())?;
        let leaf = tables
            .leaf(VirtAddr::new(virtual_address).map_err(|_| ())?)
            .map_err(|_| ())?
            .ok_or(())?;
        if !leaf.writable()
            || leaf.user()
            || leaf.device_pat_index_three()
            || leaf.physical().get() & (PAGE_SIZE - 1) != 0
        {
            return Err(());
        }
        if pages[..index].contains(&leaf.physical()) {
            return Err(());
        }
        pages[index] = leaf.physical();
    }
    Ok(pages)
}

unsafe fn page(index: usize) -> *mut u8 {
    unsafe { ARENA.0.get().cast::<u8>().add(index * PAGE_SIZE as usize) }
}

unsafe fn prepare_pages(pages: &[PhysAddr; PAGE_COUNT], revision: u32) {
    unsafe { ARENA.0.get().write_bytes(0, 1) };
    unsafe { page(VMXON_PAGE).cast::<u32>().write(revision) };
    for guest in 0..2 {
        let peer = 1 - guest;
        let own_gpa = usize::from(PRIVATE_GPAS[guest]);
        let at = |local| guest_page(guest, local);
        // SAFETY: the BSP owns the validated, distinct arena frames before
        // VMX entry. Only the selected guest's code and data get EPT leaves.
        unsafe {
            page(at(VMCS_PAGE)).cast::<u32>().write(revision);
            let flags = 0b111u64;
            page(at(EPT_PML4_PAGE))
                .cast::<u64>()
                .write(pages[at(EPT_PDPT_PAGE)].get() | flags);
            page(at(EPT_PDPT_PAGE))
                .cast::<u64>()
                .write(pages[at(EPT_PD_PAGE)].get() | flags);
            page(at(EPT_PD_PAGE))
                .cast::<u64>()
                .write(pages[at(EPT_PT_PAGE)].get() | flags);
            let pt = page(at(EPT_PT_PAGE)).cast::<u64>();
            let write_back = 6 << 3;
            pt.add(GUEST_CODE_GPA as usize / PAGE_SIZE as usize)
                .write(pages[at(GUEST_CODE_PAGE)].get() | write_back | 0b101);
            pt.add(own_gpa / PAGE_SIZE as usize)
                .write(pages[at(PRIVATE_BACKING_PAGE)].get() | write_back | 0b011);
            let [own_lo, own_hi] = PRIVATE_GPAS[guest].to_le_bytes();
            let [peer_lo, peer_hi] = PRIVATE_GPAS[peer].to_le_bytes();
            // Set AL, store it, and yield at +5. On resume, increment the
            // restored AX and store AL again. The monitor verifies the second
            // marker before accepting the existing EPT-isolation result.
            let code = [
                0xb0,
                WRITTEN_BYTES[guest],
                0xa2,
                own_lo,
                own_hi,
                0x0f,
                0x01,
                0xc1,
                0x40,
                0xa2,
                own_lo,
                own_hi,
                0xa1,
                peer_lo,
                peer_hi,
                0x0f,
                0x01,
                0xc1,
            ];
            page(at(GUEST_CODE_PAGE)).copy_from_nonoverlapping(code.as_ptr(), code.len());
            page(at(PRIVATE_BACKING_PAGE)).write_volatile(INITIAL_BYTES[guest]);
        }
    }
}

fn observed_private_bytes() -> [u8; 2] {
    core::array::from_fn(|guest| {
        // SAFETY: only the BSP calls this between guest launches. Each index
        // selects a distinct mapped backing frame in the reserved arena.
        unsafe { page(guest_page(guest, PRIVATE_BACKING_PAGE)).read_volatile() }
    })
}

unsafe fn prepare_long_pages(pages: &[PhysAddr; PAGE_COUNT], revision: u32) {
    const NX: u64 = 1 << 63;
    // SAFETY: the BSP owns every distinct frame in the cleared diagnostic
    // arena. Indices below are confined to the 12 reserved long-mode frames.
    unsafe {
        page(LONG_VMCS).cast::<u32>().write(revision);
        for level in 0..3 {
            page(LONG_EPT + level)
                .cast::<u64>()
                .write(pages[LONG_EPT + level + 1].get() | 7);
        }
        let leaf = page(LONG_EPT + 3).cast::<u64>();
        for gpa_page in 1..=7 {
            // Guest page tables must allow CPU A/D updates. Only code has X.
            let rights = if gpa_page == 5 { 5 } else { 3 };
            leaf.add(gpa_page)
                .write(pages[LONG_RAM + gpa_page - 1].get() | (6 << 3) | rights);
        }
        page(LONG_RAM).cast::<u64>().add(256).write(0x2003);
        page(LONG_RAM + 1).cast::<u64>().write(0x3003);
        page(LONG_RAM + 2).cast::<u64>().write(0x4003);
        let guest_pt = page(LONG_RAM + 3).cast::<u64>();
        guest_pt.add(5).write(0x5001); // code RX
        guest_pt.add(6).write(0x6003 | NX); // stack RW/NX
        guest_pt.add(7).write(0x7001 | NX); // GDT/TSS read-only/NX
        let gdt = page(LONG_RAM + 6).cast::<u64>();
        gdt.add(1).write(0x00af_9b00_0000_ffff);
        gdt.add(2).write(0x00cf_9300_0000_ffff);
        gdt.add(3).write(0x0000_8b00_7080_0067);
        gdt.add(4).write(HIGH >> 32);
        // MOV RAX, imm64; MOV [RSP-8], RAX; OUT 0xE9, AL.
        // This port is only a test oracle: no guest I/O is forwarded.
        let mut code = [
            0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0x48, 0x89, 0x44, 0x24, 0xf8, 0xe6, 0xe9,
        ];
        code[2..10].copy_from_slice(&LONG_MARKER.to_le_bytes());
        page(LONG_RAM + 4).copy_from_nonoverlapping(code.as_ptr(), code.len());
    }
}

fn observed_long_stack_word(from_top: usize) -> u64 {
    assert!((1..=6).contains(&from_top));
    // SAFETY: read an aligned word of the reserved guest stack while
    // the long-mode vCPU is stopped and no guest can access the frame.
    unsafe {
        page(LONG_RAM + 5)
            .cast::<u64>()
            .add(PAGE_SIZE as usize / 8 - from_top)
            .read_volatile()
    }
}

#[derive(Clone, Copy)]
#[repr(u8)]
pub(super) enum ProbeFault {
    Cpu = 0x00,
    Capabilities = 0x01,
    Controls = 0x02,
    Pages = 0x03,
    Ept = 0x04,
    FirmwareUnlocked = 0x05,
    FirmwareDisabled = 0x06,
    HostControls = 0x07,
    GuestControls = 0x08,
    TaskRegister = 0x09,
    LaunchState = 0x0A,
    Vmxon = 0x0B,
    Clear = 0x0C,
    Load = 0x0D,
    Program = 0x0E,
    Launch = 0x0F,
    Exit = 0x10,
    Vmxoff = 0x11,
    BackingBytes = 0x12,
    Yield = 0x13,
    Reload = 0x14,
    Resume = 0x15,
    LongState = 0x16,
    LongExecution = 0x17,
    #[cfg(all(feature = "vmx-kernel-monitor", not(feature = "vmx-desktop-monitor")))]
    KernelPrepare = 0x18,
    #[cfg(all(feature = "vmx-kernel-monitor", not(feature = "vmx-desktop-monitor")))]
    KernelExit = 0x19,
    #[cfg(feature = "vmx-kernel-monitor")]
    Timer = 0x1A,
    #[cfg(feature = "vmx-kernel-monitor")]
    Service = 0x1B,
    #[cfg(feature = "vmx-desktop-monitor")]
    DesktopReply = 0x1C,
}

pub(super) fn mismatch_labels(masks: [u64; 4]) -> [[u8; 26]; 4] {
    let mut labels = [
        *b"CR0 ADD   0000000000000000",
        *b"CR0 CLEAR 0000000000000000",
        *b"CR4 ADD   0000000000000000",
        *b"CR4 CLEAR 0000000000000000",
    ];
    for (label, mask) in labels.iter_mut().zip(masks) {
        for (index, byte) in label[10..].iter_mut().enumerate() {
            *byte = b"0123456789ABCDEF"[((mask >> (60 - index * 4)) & 15) as usize];
        }
    }
    labels
}

impl ProbeFault {
    pub(super) fn label(self) -> [u8; 25] {
        let mut label = *b"VMX PROBE NOT PASSED - 00";
        let hex = b"0123456789ABCDEF";
        let code = self as usize;
        label[23] = hex[code >> 4];
        label[24] = hex[code & 15];
        label
    }
}

/// Runs a controlled boot-time VMX/EPT proof. QEMU execution is evidence of
/// this state machine only; it is not physical-platform or remote attestation.
pub(super) unsafe fn run(
    host_mismatch: &mut Option<[u64; 4]>,
    _entropy: [u8; 32],
    #[cfg(feature = "vmx-desktop-monitor")] framebuffer: mrml_kernel::FramebufferInfo,
) -> Result<(), ProbeFault> {
    trace(0xd0);
    if __cpuid(1).ecx & (1 << 5) == 0 {
        trace(0xe0);
        return Err(ProbeFault::Cpu);
    }
    // Observe firmware policy before testing other VMX prerequisites. Never change it.
    let feature_control = unsafe { rdmsr(0x3a) };
    if feature_control & 1 == 0 {
        return Err(ProbeFault::FirmwareUnlocked);
    }
    if feature_control & (1 << 2) == 0 {
        return Err(ProbeFault::FirmwareDisabled);
    }
    let (basic, _vmx_misc) = unsafe { (rdmsr(0x480), rdmsr(0x485)) };
    let secondary = unsafe { rdmsr(0x48b) };
    let capabilities = VmxCapabilities::from_msrs(basic, secondary, unsafe { rdmsr(0x48c) })
        .map_err(|_| ProbeFault::Capabilities)?;
    let true_controls = basic & (1 << 55) != 0;
    let controls = VmxControlPolicy::from_msrs(
        unsafe { rdmsr(if true_controls { 0x48d } else { 0x481 }) },
        unsafe { rdmsr(if true_controls { 0x48e } else { 0x482 }) },
        unsafe { rdmsr(if true_controls { 0x48f } else { 0x483 }) },
        unsafe { rdmsr(if true_controls { 0x490 } else { 0x484 }) },
        secondary,
    )
    .map_err(|_| ProbeFault::Controls)?;
    let pages = unsafe { physical_pages() }.map_err(|_| ProbeFault::Pages)?;
    // SAFETY: this is the BSP's sole preparation of the validated arena.
    unsafe {
        prepare_pages(&pages, capabilities.revision_id());
        prepare_long_pages(&pages, capabilities.revision_id());
    }
    let epts = [0, 1].map(|guest| EptPointer::new(pages[guest_page(guest, EPT_PML4_PAGE)], true));
    let [Ok(first_ept), Ok(second_ept)] = epts else {
        return Err(ProbeFault::Ept);
    };
    let (original_cr0, cr3, original_cr4) = unsafe { control_registers() };
    let vmx_cr4 = original_cr4 | (1 << 13);
    let prerequisites = VmxPrerequisites::new(
        feature_control,
        original_cr0,
        vmx_cr4,
        unsafe { rdmsr(0x486) },
        unsafe { rdmsr(0x487) },
        unsafe { rdmsr(0x488) },
        unsafe { rdmsr(0x489) },
    );
    let (prerequisites, cr0) = prerequisites.for_boot_probe().map_err(|_| {
        *host_mismatch = Some(prerequisites.host_control_mismatch());
        ProbeFault::HostControls
    })?;
    let (guest_cr0, guest_cr4) = prerequisites
        .unrestricted_guest_controls()
        .map_err(|_| ProbeFault::GuestControls)?;
    let selectors = unsafe { selectors() };
    let (gdtr, idtr) = unsafe { descriptor_tables() };
    let tr_base =
        unsafe { task_register_base(gdtr, selectors[6]) }.map_err(|_| ProbeFault::TaskRegister)?;
    let stack_pointer: u64;
    unsafe {
        asm!("mov {}, rsp", out(reg) stack_pointer, options(nomem, nostack, preserves_flags))
    };
    let host = VmxHostState {
        cr0,
        cr3,
        cr4: vmx_cr4,
        efer: unsafe { rdmsr(0xc000_0080) },
        pat: unsafe { rdmsr(0x277) },
        perf_global_control: 0,
        selectors,
        fs_base: unsafe { rdmsr(0xc000_0100) },
        gs_base: unsafe { rdmsr(0xc000_0101) },
        tr_base,
        gdtr_base: gdtr.base,
        idtr_base: idtr.base,
        sysenter_cs: unsafe { rdmsr(0x174) } as u32,
        sysenter_esp: unsafe { rdmsr(0x175) },
        sysenter_eip: unsafe { rdmsr(0x176) },
        stack_pointer,
        instruction_pointer: run as *const () as usize as u64,
    };
    let launches = [first_ept, second_ept].map(|ept| {
        MinimalVmcsLaunch::unrestricted_real_mode(
            ept,
            controls,
            host,
            guest_cr0,
            guest_cr4,
            GUEST_CODE_GPA as u16,
            0x5000,
        )
    });
    let [Ok(first_launch), Ok(second_launch)] = launches else {
        return Err(ProbeFault::LaunchState);
    };
    let long_ept = EptPointer::new(pages[LONG_EPT], true).map_err(|_| ProbeFault::Ept)?;
    let long_launch = MinimalVmcsLaunch::long_mode_probe(
        long_ept,
        controls,
        host,
        VmxLongModeGuest {
            cr0: guest_cr0 | (1 << 31) | (1 << 16) | (1 << 5) | 1,
            cr3: PhysAddr::new(0x1000).map_err(|_| ProbeFault::LongState)?,
            cr4: guest_cr4
                | (1 << 5)
                | if cfg!(feature = "vmx-kernel-monitor") {
                    (1 << 9) | (1 << 10)
                } else {
                    0
                },
            rip: HIGH + 0x5000,
            rsp: LONG_STACK_TOP,
            gdt_base: HIGH + 0x7000,
            tss_base: HIGH + 0x7080,
        },
    )
    .map_err(|_| ProbeFault::LongState)?;
    #[cfg(all(feature = "vmx-kernel-monitor", not(feature = "vmx-desktop-monitor")))]
    let kernel = super::vmx_kernel_guest::prepare(
        capabilities.revision_id(),
        controls,
        host,
        guest_cr0,
        guest_cr4,
        _entropy,
    )
    .ok_or_else(|| {
        trace(ProbeFault::KernelPrepare as u8);
        ProbeFault::KernelPrepare
    })?;
    #[cfg(feature = "vmx-kernel-monitor")]
    let service = super::vmx_kernel_guest::prepare_service(
        capabilities.revision_id(),
        controls,
        host,
        guest_cr0,
        guest_cr4,
    )
    .ok_or_else(|| {
        trace(ProbeFault::Service as u8);
        ProbeFault::Service
    })?;
    if cr0 != original_cr0 {
        // SAFETY: in the BSP diagnostic, the validator allowed only the missing
        // required NE bit; every other CR0 bit retains its original value.
        unsafe { asm!("mov cr0, {}", in(reg) cr0, options(nostack, preserves_flags)) };
    }
    unsafe { asm!("mov cr4, {}", in(reg) vmx_cr4, options(nostack, preserves_flags)) };
    let native =
        unsafe { NativeVmx::assume_cpl0_vmx_enabled(cfg!(feature = "vmx-kernel-monitor")) };
    let mut controller = VmxController::new(native, capabilities);
    let result = (|| {
        controller
            .enter_root(pages[VMXON_PAGE])
            .map_err(|_| ProbeFault::Vmxon)?;
        trace(0xd1);
        let mut expected = INITIAL_BYTES;
        let launches = [first_launch, second_launch];
        for (guest, launch) in launches.iter().enumerate() {
            let vmcs = pages[guest_page(guest, VMCS_PAGE)];
            controller.clear_vmcs(vmcs).map_err(|_| ProbeFault::Clear)?;
            controller
                .load_vmcs(vmcs, launch.ept_pointer())
                .map_err(|_| ProbeFault::Load)?;
            if controller.program_minimal_vmcs(launch).is_err() {
                trace(0xed);
                trace(controller.failed_vmwrite_index().unwrap_or(u8::MAX));
                return Err(ProbeFault::Program);
            }
            trace(0xd2 + 0x20 * guest as u8);
            controller.launch().map_err(|_| ProbeFault::Launch)?;
            trace(0xd3 + 0x20 * guest as u8);
            controller
                .park_boot_probe_guest(GUEST_CODE_GPA as u16 + 5)
                .map_err(|_| ProbeFault::Yield)?;
            expected[guest] = WRITTEN_BYTES[guest];
            if observed_private_bytes() != expected {
                return Err(ProbeFault::BackingBytes);
            }
            trace(0xd4 + 0x20 * guest as u8);
        }
        for (guest, launch) in launches.iter().enumerate() {
            let vmcs = pages[guest_page(guest, VMCS_PAGE)];
            controller
                .reload_boot_probe_guest(vmcs, launch.ept_pointer())
                .map_err(|_| ProbeFault::Reload)?;
            trace(0xd7 + 0x20 * guest as u8);
            controller.resume().map_err(|_| ProbeFault::Resume)?;
            trace(0xd8 + 0x20 * guest as u8);
            let violation = controller
                .record_vm_exit_snapshot()
                .and_then(|snapshot| {
                    snapshot.private_page_violation(
                        PhysAddr::new(u64::from(PRIVATE_GPAS[1 - guest]))
                            .map_err(|_| VmxError::InvalidVmExit)?,
                    )
                })
                .map_err(|_| ProbeFault::Exit)?;
            if violation.guest_physical_address() != u64::from(PRIVATE_GPAS[1 - guest])
                || !violation.attempted_read()
                || violation.attempted_write()
                || violation.attempted_execute()
            {
                return Err(ProbeFault::Exit);
            }
            expected[guest] = WRITTEN_BYTES[guest] + 1;
            if observed_private_bytes() != expected {
                return Err(ProbeFault::BackingBytes);
            }
            trace(0xd9 + 0x20 * guest as u8);
        }
        controller
            .clear_vmcs(pages[LONG_VMCS])
            .map_err(|_| ProbeFault::LongState)?;
        controller
            .load_vmcs(pages[LONG_VMCS], long_ept)
            .map_err(|_| ProbeFault::LongState)?;
        controller
            .program_minimal_vmcs(&long_launch)
            .map_err(|_| ProbeFault::LongState)?;
        trace(0xc0);
        controller.launch().map_err(|_| ProbeFault::LongExecution)?;
        let exit = controller
            .record_vm_exit_snapshot()
            .map_err(|_| ProbeFault::LongExecution)?;
        const IO_EXIT: u32 = 30;
        const EXACT_OUT_BYTE: u64 = (0xe9 << 16) | (1 << 6);
        if exit.reason() != IO_EXIT
            || exit.qualification() != EXACT_OUT_BYTE
            || observed_long_stack_word(1) != LONG_MARKER
            || observed_private_bytes() != expected
        {
            return Err(ProbeFault::LongExecution);
        }
        trace(0xc1);
        #[cfg(feature = "vmx-kernel-monitor")]
        {
            trace(0xc2);
            let timer_marker = !LONG_MARKER;
            const FX_SETUP_LEN: usize = 6 + 4 + 5 + 2;
            // SAFETY: the prior guest exited and cannot resume; rewrite only
            // its own fixture code page before VMCLEAR and INVEPT. Change the
            // MOV immediate, then replace the OUT with a loop that waits
            // on an initially clear byte in its own stack page. No instruction
            // is changed after launch; the host supplies only that data byte.
            unsafe {
                let code = page(LONG_RAM + 4);
                code.add(2)
                    .copy_from_nonoverlapping(timer_marker.to_le_bytes().as_ptr(), 8);
                let fx_setup = [
                    0x66, 0x0f, 0xd6, 0x44, 0x24, 0xd8, // movq [rsp - 40], xmm0
                    0xd9, 0x7c, 0x24, 0xd0, // fnstcw [rsp - 48]
                    0x66, 0x48, 0x0f, 0x6e, 0xc0, // movq xmm0, rax
                    0xd9, 0xe8, // fld1
                ];
                let tail = [
                    0x80, 0x7c, 0x24, 0xf0, 0, // cmp byte [rsp - 16], 0
                    0x74, 0xf9, // je back to cmp
                    0x48, 0xff, 0xc0, // inc rax
                    0x48, 0x89, 0x44, 0x24, 0xf8, // mov [rsp - 8], rax
                    0xdf, 0x7c, 0x24, 0xe8, // fistp qword [rsp - 24]
                    0x66, 0x0f, 0xd6, 0x44, 0x24, 0xe0, // movq [rsp - 32], xmm0
                    0xe6, 0xe9, // out 0xe9, al (trapped)
                ];
                let _: [u8; FX_SETUP_LEN] = fx_setup;
                code.add(15)
                    .copy_from_nonoverlapping(fx_setup.as_ptr(), FX_SETUP_LEN);
                code.add(15 + FX_SETUP_LEN)
                    .copy_from_nonoverlapping(tail.as_ptr(), tail.len());
                page(LONG_RAM + 5)
                    .add(PAGE_SIZE as usize - 16)
                    .write_volatile(0);
            }
            controller
                .clear_vmcs(pages[LONG_VMCS])
                .map_err(|_| ProbeFault::Timer)?;
            controller
                .load_vmcs(pages[LONG_VMCS], long_ept)
                .map_err(|_| ProbeFault::Timer)?;
            controller
                .program_minimal_vmcs(&long_launch)
                .map_err(|_| ProbeFault::Timer)?;
            // Convert fixed TSC-cycle budgets to the CPU's timer tick units.
            let shift = (_vmx_misc & 0x1f) as u32;
            let ticks = |cycles: u64| ((cycles >> shift).min(u64::from(u32::MAX)) as u32).max(1);
            controller
                .arm_boot_probe_timer(controls, ticks(1 << 23))
                .map_err(|_| ProbeFault::Timer)?;
            controller.launch().map_err(|_| ProbeFault::Timer)?;
            let cmp = HIGH + 0x5000 + 15 + FX_SETUP_LEN as u64;
            controller
                .park_boot_timer_probe([cmp, cmp + 5])
                .map_err(|_| ProbeFault::Timer)?;
            if observed_long_stack_word(1) != timer_marker
                || observed_long_stack_word(5) != 0
                || observed_long_stack_word(6) as u16 != 0x037f
            {
                return Err(ProbeFault::Timer);
            }
            trace(0xc4);
            #[cfg(not(feature = "vmx-desktop-monitor"))]
            super::vmx_kernel_guest::run_service_call(
                kernel,
                service,
                &mut controller,
                controls,
                ticks(1 << 32),
            )
            .ok_or(ProbeFault::KernelExit)?;
            #[cfg(not(feature = "vmx-desktop-monitor"))]
            trace(0xc3);
            #[cfg(feature = "vmx-desktop-monitor")]
            let desktop_vmcs = {
                let vmcs = super::vmx_kernel_guest::run_desktop_probe(
                    service, &mut controller, controls, ticks(1 << 32), framebuffer,
                )
                .ok_or(ProbeFault::DesktopReply)?;
                trace(0xcc);
                vmcs
            };
            // SAFETY: the exact timer-exited VMCS is parked, the other guest
            // has stopped, and this byte is in only the timer guest's stack.
            unsafe {
                page(LONG_RAM + 5)
                    .add(PAGE_SIZE as usize - 16)
                    .write_volatile(1);
            }
            controller
                .reload_boot_probe_guest(pages[LONG_VMCS], long_ept)
                .map_err(|_| ProbeFault::Timer)?;
            controller
                .arm_boot_probe_timer(controls, ticks(1 << 23))
                .map_err(|_| ProbeFault::Timer)?;
            controller.resume().map_err(|_| ProbeFault::Timer)?;
            let exit = controller
                .record_vm_exit_snapshot()
                .map_err(|_| ProbeFault::Timer)?;
            if exit.reason() != IO_EXIT
                || exit.qualification() != EXACT_OUT_BYTE
                || observed_long_stack_word(1) != timer_marker.wrapping_add(1)
                || observed_long_stack_word(3) != 1
                || observed_long_stack_word(4) != timer_marker
                || observed_private_bytes() != expected
            {
                return Err(ProbeFault::Timer);
            }
            #[cfg(feature = "vmx-desktop-monitor")]
            controller.clear_vmcs(desktop_vmcs).map_err(|_| ProbeFault::DesktopReply)?;
            trace(0xc5);
        }
        controller.leave_root().map_err(|_| ProbeFault::Vmxoff)?;
        Ok(())
    })();
    if result.is_err() {
        trace(0xef);
        if controller.state() != VmxState::Disabled && controller.leave_root().is_err() {
            loop {
                unsafe { asm!("cli; hlt", options(nomem, nostack)) }
            }
        }
    }
    unsafe { asm!("mov cr4, {}", in(reg) original_cr4, options(nostack, preserves_flags)) };
    if cr0 != original_cr0 {
        // SAFETY: VMX was never entered or VMXOFF completed; the original
        // hardware value is valid again and no guest can run.
        unsafe { asm!("mov cr0, {}", in(reg) original_cr0, options(nostack, preserves_flags)) };
    }
    result?;
    trace(0xdf);
    Ok(())
}
