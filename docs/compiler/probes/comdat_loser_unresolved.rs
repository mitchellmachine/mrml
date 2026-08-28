#![no_std]

core::arch::global_asm!(
    ".section .text.helper,\"axG\",@progbits,helper,comdat",
    ".globl helper",
    ".type helper,@function",
    "helper:",
    "call missing_loser_dependency",
    "mov eax, 9",
    "ret",
    ".size helper, .-helper",
);
