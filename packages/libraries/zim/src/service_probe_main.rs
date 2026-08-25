#![no_std]
#![no_main]

use core::arch::{asm, naked_asm};
use mrml_interface_zstd_v3::{
    BorrowedReadView, BorrowedWriteView, DECOMPRESS_RESPONSE_BYTES, decode_decompress_response,
    encode_decompress_request,
};
use mrml_kernel::Rights;

const FRAME: [u8; 10] = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 5, 0x2b, 0, 0, b'x'];
const SHARED_BYTES: u64 = mrml_kernel::PAGE_SIZE;

#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text$a")]
extern "C" fn efi_main() -> ! {
    naked_asm!(
        "mov rdi, r13",
        "mov rsi, r14",
        "mov rdx, r15",
        "mov rcx, r12",
        "sub rsp, 16",
        "call mrml_zim_probe",
        "ud2",
    )
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    halt()
}

/// Launch registers are fixed by the admitted consumer/provider route. The
/// interface request contains no endpoint, task, or capability identity.
#[unsafe(no_mangle)]
unsafe extern "sysv64" fn mrml_zim_probe(
    endpoint: u64,
    provider: u64,
    shared: u64,
    provider_generation: u64,
) -> ! {
    if endpoint == 0
        || provider == 0
        || shared == 0
        || shared >> 32 == 0
        || provider_generation == 0
    {
        halt();
    }

    let mut ready = [0; 8];
    let (ready_length, ready_capabilities) = unsafe { receive(&mut ready, &mut []) };
    if ready_length != ready.len()
        || ready_capabilities != 0
        || u64::from_le_bytes(ready) != provider_generation
    {
        halt();
    }

    unsafe { shared_call(8, shared, 0, FRAME.as_ptr().cast_mut(), FRAME.len()) };
    let request = encode_decompress_request(
        BorrowedReadView::within(0, FRAME.len() as u64, SHARED_BYTES).unwrap_or_else(|| halt()),
        BorrowedWriteView::within(64, 32, SHARED_BYTES).unwrap_or_else(|| halt()),
    )
    .unwrap_or_else(|_| halt());
    let descriptor =
        capability_descriptor(shared, Rights::MAP.union(Rights::READ).union(Rights::WRITE));
    unsafe { send(endpoint, provider, &request, &descriptor) };

    let mut response = [0; DECOMPRESS_RESPONSE_BYTES];
    let (response_length, response_capabilities) = unsafe { receive(&mut response, &mut []) };
    if response_length != response.len()
        || response_capabilities != 0
        || decode_decompress_response(&response) != Ok(Ok(5))
    {
        halt();
    }
    let mut output = [0; 5];
    unsafe { shared_call(7, shared, 64, output.as_mut_ptr(), output.len()) };
    if output != *b"xxxxx" {
        halt();
    }
    unsafe { terminate() }
}

fn capability_descriptor(capability: u64, rights: Rights) -> [u8; 16] {
    let mut descriptor = [0; 16];
    descriptor[..8].copy_from_slice(&capability.to_le_bytes());
    descriptor[8..10].copy_from_slice(&rights.bits().to_le_bytes());
    descriptor
}

unsafe fn send(endpoint: u64, receiver: u64, payload: &[u8], descriptor: &[u8; 16]) {
    let mut status = 4u64;
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") status,
            in("rdi") endpoint,
            in("rsi") receiver,
            inlateout("rdx") payload.as_ptr() as u64 => _,
            in("r10") payload.len() as u64,
            in("r8") descriptor.as_ptr() as u64,
            in("r9") 1u64,
            options(nostack)
        )
    };
    if status != 0 {
        halt();
    }
}

unsafe fn receive(payload: &mut [u8], capabilities: &mut [u64]) -> (usize, usize) {
    let mut status = 5u64;
    let payload_length: u64;
    let capability_count: u64;
    let capability_address = if capabilities.is_empty() {
        0
    } else {
        capabilities.as_mut_ptr() as u64
    };
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") status,
            in("rdi") payload.as_mut_ptr() as u64,
            in("rsi") payload.len() as u64,
            inlateout("rdx") capability_address => payload_length,
            inlateout("r10") capabilities.len() as u64 => capability_count,
            inlateout("r8") 0u64 => _,
            inlateout("r9") 0u64 => _,
            options(nostack)
        )
    };
    if status != 0 {
        halt();
    }
    (
        usize::try_from(payload_length).unwrap_or_else(|_| halt()),
        usize::try_from(capability_count).unwrap_or_else(|_| halt()),
    )
}

unsafe fn shared_call(
    operation: u64,
    capability: u64,
    offset: u64,
    buffer: *mut u8,
    length: usize,
) {
    let mut status = operation;
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") status,
            in("rdi") capability,
            in("rsi") offset,
            in("rdx") buffer as u64,
            in("r10") length as u64,
            in("r8") 0u64,
            in("r9") 0u64,
            options(nostack)
        )
    };
    if status != 0 {
        halt();
    }
}

unsafe fn terminate() -> ! {
    unsafe {
        asm!(
            "int 0x80",
            in("rax") 3u64,
            in("rdi") 0u64,
            in("rsi") 0u64,
            in("rdx") 0u64,
            in("r10") 0u64,
            in("r8") 0u64,
            in("r9") 0u64,
            options(noreturn, nostack)
        )
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
