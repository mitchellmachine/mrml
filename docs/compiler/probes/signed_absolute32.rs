#![no_std]

#[unsafe(no_mangle)]
pub static TARGET: u8 = 7;

core::arch::global_asm!(
    ".section .text.entry,\"ax\",@progbits",
    ".globl entry",
    ".type entry,@function",
    "entry:",
    "mov rax, OFFSET TARGET",
    "mov eax, 42",
    "ret",
    ".size entry, .-entry",
);
