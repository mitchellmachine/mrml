#![no_std]

unsafe extern "C" {
    #[allow(dead_code)]
    fn helper() -> u64;
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn entry() -> ! {
    core::arch::naked_asm!("call helper", "mov rdi, rax", "mov eax, 60", "syscall",);
}
