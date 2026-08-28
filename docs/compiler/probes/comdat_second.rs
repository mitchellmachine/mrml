#![no_std]

core::arch::global_asm!(
    ".section .text.helper,\"axG\",@progbits,helper,comdat",
    ".globl helper",
    ".type helper,@function",
    "helper:",
    "mov eax, 7",
    "ret",
    ".size helper, .-helper",
);
