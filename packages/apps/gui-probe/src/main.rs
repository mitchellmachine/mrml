#![cfg_attr(target_os = "uefi", no_main)]
#![cfg_attr(target_os = "uefi", no_std)]

#[cfg(target_os = "uefi")]
use core::arch::global_asm;

// This is a distinct ordinary application image. Its current executable slice
// proves placement/lifecycle identity only and terminates through the MRML task
// syscall boundary. The client library owns the surface protocol state machine;
// connecting it to the application IPC projection is a later dependency gate.
#[cfg(target_os = "uefi")]
global_asm!(
    r#"
        .section .text$a,"xr"
        .global efi_main
    efi_main:
        mov rax, 3
        xor rdi, rdi
        xor rsi, rsi
        xor rdx, rdx
        xor r10, r10
        xor r8, r8
        xor r9, r9
        int 0x80
        ud2
    "#
);

#[cfg(target_os = "uefi")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(not(target_os = "uefi"))]
fn main() {}
