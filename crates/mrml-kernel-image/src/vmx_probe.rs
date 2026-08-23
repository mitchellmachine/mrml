use core::arch::{asm, x86_64::__cpuid};
use core::cell::UnsafeCell;

use mrml_kernel::arch::x86_64::{
    ActivePageTables, EptPointer, MinimalVmcsLaunch, NativeVmx, VirtAddr, VmxCapabilities,
    VmxControlPolicy, VmxController, VmxHostState, VmxPrerequisites, VmxState,
};
use mrml_kernel::{PAGE_SIZE, PhysAddr};

const PAGE_COUNT: usize = 8;
const VMXON_PAGE: usize = 0;
const VMCS_PAGE: usize = 1;
const EPT_PML4_PAGE: usize = 2;
const EPT_PDPT_PAGE: usize = 3;
const EPT_PD_PAGE: usize = 4;
const EPT_PT_PAGE: usize = 5;
const GUEST_CODE_PAGE: usize = 6;
const PRIVATE_BACKING_PAGE: usize = 7;
const GUEST_CODE_GPA: u64 = 0x1000;
const PRIVATE_GPA: u64 = 0x2000;

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

fn trace(stage: u8) {
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
        if !leaf.writable() || leaf.user() || leaf.physical().get() & (PAGE_SIZE - 1) != 0 {
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
    unsafe { page(VMCS_PAGE).cast::<u32>().write(revision) };
    let flags = 0b111u64;
    unsafe {
        page(EPT_PML4_PAGE)
            .cast::<u64>()
            .write(pages[EPT_PDPT_PAGE].get() | flags)
    };
    unsafe {
        page(EPT_PDPT_PAGE)
            .cast::<u64>()
            .write(pages[EPT_PD_PAGE].get() | flags)
    };
    unsafe {
        page(EPT_PD_PAGE)
            .cast::<u64>()
            .write(pages[EPT_PT_PAGE].get() | flags)
    };
    let code_leaf = pages[GUEST_CODE_PAGE].get() | 0b101 | (6 << 3);
    unsafe { page(EPT_PT_PAGE).cast::<u64>().add(1).write(code_leaf) };
    // 16-bit MOV AX, moffs16 0x2000. The absent EPT leaf must exit before HLT.
    unsafe { page(GUEST_CODE_PAGE).copy_from_nonoverlapping([0xa1, 0x00, 0x20, 0xf4].as_ptr(), 4) };
    unsafe { page(PRIVATE_BACKING_PAGE).write_volatile(0xa5) };
}

/// Runs a controlled boot-time VMX/EPT proof. QEMU execution is evidence of
/// this state machine only; it is not physical-platform or remote attestation.
pub unsafe fn run() -> Result<(), ()> {
    trace(0xd0);
    if __cpuid(1).ecx & (1 << 5) == 0 {
        trace(0xe0);
        return Err(());
    }
    let basic = unsafe { rdmsr(0x480) };
    let secondary = unsafe { rdmsr(0x48b) };
    let capabilities =
        VmxCapabilities::from_msrs(basic, secondary, unsafe { rdmsr(0x48c) }).map_err(|_| ())?;
    let true_controls = basic & (1 << 55) != 0;
    let controls = VmxControlPolicy::from_msrs(
        unsafe { rdmsr(if true_controls { 0x48d } else { 0x481 }) },
        unsafe { rdmsr(if true_controls { 0x48e } else { 0x482 }) },
        unsafe { rdmsr(if true_controls { 0x48f } else { 0x483 }) },
        unsafe { rdmsr(if true_controls { 0x490 } else { 0x484 }) },
        secondary,
    )
    .map_err(|_| ())?;
    let pages = unsafe { physical_pages() }?;
    unsafe { prepare_pages(&pages, capabilities.revision_id()) };
    let ept = EptPointer::new(pages[EPT_PML4_PAGE], true).map_err(|_| ())?;
    let (cr0, cr3, original_cr4) = unsafe { control_registers() };
    let vmx_cr4 = original_cr4 | (1 << 13);
    VmxPrerequisites::new(
        unsafe { rdmsr(0x3a) },
        cr0,
        vmx_cr4,
        unsafe { rdmsr(0x486) },
        unsafe { rdmsr(0x487) },
        unsafe { rdmsr(0x488) },
        unsafe { rdmsr(0x489) },
    )
    .validate()
    .map_err(|_| ())?;
    let selectors = unsafe { selectors() };
    let (gdtr, idtr) = unsafe { descriptor_tables() };
    let tr_base = unsafe { task_register_base(gdtr, selectors[6]) }?;
    let stack_pointer: u64;
    unsafe {
        asm!("mov {}, rsp", out(reg) stack_pointer, options(nomem, nostack, preserves_flags))
    };
    let host = VmxHostState {
        cr0,
        cr3,
        cr4: vmx_cr4,
        efer: unsafe { rdmsr(0xc000_0080) },
        selectors,
        tr_base,
        gdtr_base: gdtr.base,
        idtr_base: idtr.base,
        stack_pointer,
        instruction_pointer: run as *const () as usize as u64,
    };
    let launch = MinimalVmcsLaunch::unrestricted_real_mode(
        ept,
        controls,
        host,
        GUEST_CODE_GPA as u16,
        0x3000,
    )
    .map_err(|_| ())?;
    unsafe { asm!("mov cr4, {}", in(reg) vmx_cr4, options(nostack, preserves_flags)) };
    let native = unsafe { NativeVmx::assume_cpl0_vmx_enabled() };
    let mut controller = VmxController::new(native, capabilities);
    let result = (|| {
        controller.enter_root(pages[VMXON_PAGE])?;
        trace(0xd1);
        controller.clear_vmcs(pages[VMCS_PAGE])?;
        controller.load_vmcs(pages[VMCS_PAGE], ept)?;
        controller.program_minimal_vmcs(&launch)?;
        trace(0xd2);
        controller.launch()?;
        trace(0xd3);
        let violation = controller.record_private_page_violation(
            PhysAddr::new(PRIVATE_GPA)
                .map_err(|_| mrml_kernel::arch::x86_64::VmxError::InvalidVmExit)?,
        )?;
        if !violation.attempted_read()
            || violation.attempted_write()
            || violation.attempted_execute()
        {
            return Err(mrml_kernel::arch::x86_64::VmxError::InvalidVmExit);
        }
        trace(0xd4);
        controller.leave_root()?;
        Ok(())
    })();
    if result.is_err() {
        trace(0xef);
        if controller.state() != VmxState::Disabled && controller.leave_root().is_err() {
            loop {
                unsafe { asm!("cli; hlt", options(nomem, nostack)) }
            }
        }
        unsafe { asm!("mov cr4, {}", in(reg) original_cr4, options(nostack, preserves_flags)) };
        return Err(());
    }
    unsafe { asm!("mov cr4, {}", in(reg) original_cr4, options(nostack, preserves_flags)) };
    trace(0xdf);
    Ok(())
}
