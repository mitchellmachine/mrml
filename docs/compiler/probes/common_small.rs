#![no_std]

use core::arch::global_asm;

global_asm!(".comm shared_common,8,8");
