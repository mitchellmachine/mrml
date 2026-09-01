#![no_std]
#![no_main]

use core::arch::{asm, naked_asm};
use mrml_interface_storage_block_provider_v1::BLOCK_PROVIDER_DEPENDENCY_HANDOFF_BYTES;
use mrml_kernel::{Capability, ObjectId};
use mrml_storage_fat32::{
    Fat32BlockMountBackend, Fat32BlockReadUserspaceTransport, Fat32DispatchService,
    Fat32DispatchUserspaceSyscalls, Fat32LaunchBinding, Fat32MountedProvider, Fat32RawSyscall,
    Fat32SyscallFrame, Fat32UserspaceSyscalls,
};

const SCRATCH_BYTES: usize = 4096;
const MOUNT_CAPACITY: usize = 4;
const OBJECT_CAPACITY: usize = 64;
const CHAIN_CAPACITY: usize = 64;

#[repr(C, align(4096))]
struct ServiceScratch([u8; SCRATCH_BYTES]);

static mut BLOCK_SCRATCH: ServiceScratch = ServiceScratch([0; SCRATCH_BYTES]);
static mut CLUSTER_SCRATCH: ServiceScratch = ServiceScratch([0; SCRATCH_BYTES]);
static mut STAGING_SCRATCH: ServiceScratch = ServiceScratch([0; SCRATCH_BYTES]);
static mut SHARED_SCRATCH: ServiceScratch = ServiceScratch([0; SCRATCH_BYTES]);

#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text$a")]
extern "C" fn efi_main() -> ! {
    naked_asm!(
        "sub rsp, 48",
        "mov qword ptr [rsp], r10",
        "mov qword ptr [rsp + 8], rdx",
        "mov qword ptr [rsp + 16], rbp",
        "mov qword ptr [rsp + 24], rsi",
        "mov qword ptr [rsp + 32], r9",
        "mov qword ptr [rsp + 40], r8",
        "mov rdi, r13",
        "mov rsi, r14",
        "mov rdx, r12",
        "mov rcx, r15",
        "mov r8, rbx",
        "mov r9, r11",
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
    block_provider_task: u64,
    local_read_capability: u64,
    provider_write_capability: u64,
    shared_generation: u64,
    shared_bytes: u64,
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
        || block_provider_task == 0
        || block_provider_task >> 32 == 0
        || local_read_capability == 0
        || local_read_capability >> 32 == 0
        || provider_write_capability == 0
        || provider_write_capability >> 32 == 0
        || local_read_capability == provider_write_capability
        || shared_generation == 0
        || shared_bytes != SCRATCH_BYTES as u64
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
    let launch_binding = unsafe {
        Fat32LaunchBinding::from_installed_projection(
            &launch_data,
            ObjectId(filesystem_module_object),
            provider_generation,
            block_endpoint_capability,
        )
    }
    .unwrap_or_else(|_| halt());
    launch_data.fill(0);
    syscalls
        .release_launch_data(launch_data_capability)
        .unwrap_or_else(|_| halt());
    let block = launch_binding.block();
    let logical_block_bytes = block.logical_block_bytes() as usize;
    if logical_block_bytes > SCRATCH_BYTES {
        halt();
    }
    let transport = unsafe {
        Fat32BlockReadUserspaceTransport::from_installed_projection(
            Interrupt80,
            launch_binding.block_endpoint_capability(),
            block_provider_task,
            Capability::from_token(local_read_capability),
            Capability::from_token(provider_write_capability),
            shared_bytes as usize,
        )
    }
    .unwrap_or_else(|_| halt());
    let block_scratch = unsafe { &mut *core::ptr::addr_of_mut!(BLOCK_SCRATCH) };
    let backend = Fat32BlockMountBackend::new(
        block,
        transport,
        &mut block_scratch.0[..logical_block_bytes],
    )
    .unwrap_or_else(|_| halt());
    let provider = Fat32MountedProvider::<_, MOUNT_CAPACITY, OBJECT_CAPACITY>::new(backend);
    let cluster_scratch = unsafe { &mut *core::ptr::addr_of_mut!(CLUSTER_SCRATCH) };
    let staging = unsafe { &mut *core::ptr::addr_of_mut!(STAGING_SCRATCH) };
    let mut service =
        Fat32DispatchService::<_, MOUNT_CAPACITY, OBJECT_CAPACITY, CHAIN_CAPACITY>::new(
            provider,
            &mut cluster_scratch.0,
            &mut staging.0,
        );
    let mut syscalls = Fat32DispatchUserspaceSyscalls::new(Interrupt80, endpoint, caller)
        .unwrap_or_else(|_| halt());
    let mut request = [0; mrml_storage_fat32::FAT32_DISPATCH_REQUEST_BYTES];
    let mut capability = [0; 1];
    let scratch = unsafe { &mut *core::ptr::addr_of_mut!(SHARED_SCRATCH) };
    let mut response = [0; mrml_storage_fat32::FAT32_DISPATCH_RESPONSE_BYTES];
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
