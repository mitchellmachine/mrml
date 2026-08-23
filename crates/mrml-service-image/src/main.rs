#![no_std]
#![no_main]

use core::arch::{asm, global_asm};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    halt()
}

// This entry is assembly rather than a Rust ABI function because r12-r14 are
// intentional launch registers, not compiler-owned callee-saved temporaries.
#[cfg(not(feature = "preemption-probe"))]
global_asm!(
    r#"
            .section .text
            .global efi_main
        efi_main:
            mov r11, 0x6fe000
            cmp qword ptr [r11], r12
            je 3f
            lea rdi, [rip + mrml_service_buffer]
            mov qword ptr [rdi], 0
            mov qword ptr [rdi + 8], 0
            mov qword ptr [rdi + 16], 0
            mov qword ptr [rdi + 24], 0
            mov qword ptr [rdi + 32], 0
            mov qword ptr [rdi + 40], 0
            mov eax, 5
            mov esi, 48
            xor edx, edx
            xor r10d, r10d
            xor r8d, r8d
            xor r9d, r9d
            int 0x80
            cmp rax, 0
            jne 3f
            cmp rdx, 48
            jne 3f
            cmp r10, 0
            jne 3f
            lea r11, [rip + mrml_service_buffer]
            mov rax, 0x0807060504030201
            cmp qword ptr [r11], rax
            jne 3f
            mov rax, 0x1817161514131211
            cmp qword ptr [r11 + 8], rax
            jne 3f
            mov rax, 0x2827262524232221
            cmp qword ptr [r11 + 16], rax
            jne 3f
            mov rax, 0x3837363534333231
            cmp qword ptr [r11 + 24], rax
            jne 3f
            mov rax, 0x4847464544434241
            cmp qword ptr [r11 + 32], rax
            jne 3f
            mov rax, 0x5857565554535251
            cmp qword ptr [r11 + 40], rax
            jne 3f
            mov r11, 0x6fe000
            cmp qword ptr [r11], r12
            jne 3f
            int3
        3:
            ud2

            // Fix the secondary entry ABI exactly; assembly fails if the
            // receiver ever grows beyond its reserved 512-byte window.
            .org efi_main + 512, 0xcc
            .global mrml_service_sender
        mrml_service_sender:
            mov r11, 0x6fe000
            mov qword ptr [r11], r12
            lea r11, [rip + mrml_service_buffer]
            mov rax, 0x0807060504030201
            mov qword ptr [r11], rax
            mov rax, 0x1817161514131211
            mov qword ptr [r11 + 8], rax
            mov rax, 0x2827262524232221
            mov qword ptr [r11 + 16], rax
            mov rax, 0x3837363534333231
            mov qword ptr [r11 + 24], rax
            mov rax, 0x4847464544434241
            mov qword ptr [r11 + 32], rax
            mov rax, 0x5857565554535251
            mov qword ptr [r11 + 40], rax
            mov eax, 4
            mov rdi, r13
            mov rsi, r14
            mov rdx, r11
            mov r10d, 48
            xor r8d, r8d
            xor r9d, r9d
            int 0x80
            cmp r12, 2
            jne 4f
            mov eax, 2
            xor edi, edi
            xor esi, esi
            xor edx, edx
            xor r10d, r10d
            xor r8d, r8d
            xor r9d, r9d
            int 0x80
            ud2
        4:
            mov eax, 3
            xor edi, edi
            xor esi, esi
            xor edx, edx
            xor r10d, r10d
            xor r8d, r8d
            xor r9d, r9d
            int 0x80
            ud2

            .section .data
            .balign 8
            .global mrml_service_buffer
        mrml_service_buffer:
            .zero 48
    "#
);

#[cfg(feature = "preemption-probe")]
global_asm!(
    r#"
            .section .text
            .global efi_main
        efi_main:
        1:
            pause
            jmp 1b

            .org efi_main + 128, 0xcc
            .global mrml_service_sender
        mrml_service_sender:
            int3
        2:
            pause
            jmp 2b
    "#
);

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
