#![no_std]

use core::arch::global_asm;

global_asm!(
    ".data",
    ".globl shared_common",
    ".balign 8",
    "shared_common:",
    ".quad 7"
);
