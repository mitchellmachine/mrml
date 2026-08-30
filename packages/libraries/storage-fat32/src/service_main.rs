#![no_std]
#![no_main]

use core::arch::{asm, naked_asm};
use mrml_interface_storage_block_provider_v1::BLOCK_PROVIDER_DEPENDENCY_HANDOFF_BYTES;
use mrml_interface_storage_filesystem_v3::{PROBE_REQUEST_BYTES, PROBE_RESPONSE_BYTES};
use mrml_kernel::{Capability, ObjectId};
use mrml_storage_fat32::{
    Fat32LaunchBinding, Fat32RawSyscall, Fat32ServiceLoop, Fat32SyscallFrame,
    Fat32UserspaceSyscalls,
};

const SCRATCH_BYTES: usize = 4096;

#[repr(C, align(4096))]
struct ServiceScratch([u8; SCRATCH_BYTES]);

static mut SERVICE_SCRATCH: ServiceScratch = ServiceScratch([0; SCRATCH_BYTES]);

#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text$a")]
extern "C" fn efi_main() -> ! {
    naked_asm!(
        "mov rdi, r13",
        "mov rsi, r14",
        "mov rdx, r12",
        "mov rcx, r15",
        "mov r8, rbx",
        "mov r9, r11",
        "sub rsp, 16",
        "mov qword ptr [rsp], r10",
        "call mrml_fat32_service",
        "ud2",
    )
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    halt()
}

struct Interrupt80;

unsafe impl Fat32RawSyscall for Interrupt80 {
    unsafe fn invoke(&mut self, frame: &mut Fat32SyscallFrame) {
        let mut rax = frame.rax;
        let mut rdi = frame.rdi;
        let mut rsi = frame.rsi;
        let mut rdx = frame.rdx;
        let mut r10 = frame.r10;
        let mut r8 = frame.r8;
        let mut r9 = frame.r9;
        unsafe {
            asm!(
                "int 0x80",
                inlateout("rax") rax,
                inlateout("rdi") rdi,
                inlateout("rsi") rsi,
                inlateout("rdx") rdx,
                inlateout("r10") r10,
                inlateout("r8") r8,
                inlateout("r9") r9,
                options(nostack)
            )
        };
        *frame = Fat32SyscallFrame {
            rax,
            rdi,
            rsi,
            rdx,
            r10,
            r8,
            r9,
        };
    }
}

#[unsafe(no_mangle)]
unsafe extern "sysv64" fn mrml_fat32_service(
    endpoint: u64,
    caller: u64,
    provider_generation: u64,
    launch_data_capability: u64,
    block_endpoint_capability: u64,
    launch_data_bytes: u64,
    filesystem_module_object: u64,
) -> ! {
    if endpoint == 0
        || caller == 0
        || provider_generation == 0
        || launch_data_capability == 0
        || launch_data_capability >> 32 == 0
        || block_endpoint_capability == 0
        || block_endpoint_capability >> 32 == 0
        || block_endpoint_capability == launch_data_capability
        || launch_data_bytes != BLOCK_PROVIDER_DEPENDENCY_HANDOFF_BYTES as u64
        || filesystem_module_object == 0
    {
        halt();
    }
    let mut syscalls =
        Fat32UserspaceSyscalls::new(Interrupt80, endpoint, caller).unwrap_or_else(|_| halt());
    let launch_data_capability = Capability::from_token(launch_data_capability);
    let block_endpoint_capability = Capability::from_token(block_endpoint_capability);
    let mut launch_data = [0; BLOCK_PROVIDER_DEPENDENCY_HANDOFF_BYTES];
    syscalls
        .read_launch_data(launch_data_capability, &mut launch_data)
        .unwrap_or_else(|_| halt());
    let _launch_binding = unsafe {
        Fat32LaunchBinding::from_installed_projection(
            &launch_data,
            ObjectId(filesystem_module_object),
            provider_generation,
            block_endpoint_capability,
        )
    }
    .unwrap_or_else(|_| halt());
    launch_data.fill(0);
    let mut service = Fat32ServiceLoop::new();
    let mut request = [0; PROBE_REQUEST_BYTES];
    let mut capability = [0; 1];
    let scratch = unsafe { &mut *core::ptr::addr_of_mut!(SERVICE_SCRATCH) };
    let mut response = [0; PROBE_RESPONSE_BYTES];
    unsafe { send_ready(endpoint, caller, provider_generation) };
    loop {
        service
            .serve_one(
                &mut syscalls,
                &mut request,
                &mut capability,
                &mut scratch.0,
                &mut response,
            )
            .unwrap_or_else(|_| halt());
    }
}

unsafe fn send_ready(endpoint: u64, caller: u64, provider_generation: u64) {
    let payload = provider_generation.to_le_bytes();
    let mut status = 4_u64;
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") status,
            in("rdi") endpoint,
            in("rsi") caller,
            inlateout("rdx") payload.as_ptr() as u64 => _,
            in("r10") payload.len() as u64,
            in("r8") 0_u64,
            in("r9") 0_u64,
            options(nostack)
        )
    };
    if status != 0 {
        halt();
    }
}

fn halt() -> ! {
    unsafe {
        asm!(
            "cli",
            "2:",
            "hlt",
            "jmp 2b",
            options(noreturn, nomem, nostack)
        )
    }
}
