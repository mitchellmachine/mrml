#![no_main]
#![no_std]

use core::arch::global_asm;

// This image is an ordinary application payload, not a service and not a UEFI
// loader. Its PE entry uses only the MRML task syscall boundary. Operation 3
// requests termination; no metadata or image byte grants the operation.
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

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
