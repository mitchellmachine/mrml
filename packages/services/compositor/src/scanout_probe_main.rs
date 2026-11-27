#![no_std]
#![no_main]

use core::arch::{asm, naked_asm};
use mrml_compositor::{
    BOOT_SCANOUT_PROBE_BYTES, BootScanoutProbeTransport, run_boot_scanout_probe,
};

// This probe is a signed service-image payload, never a firmware application.
// Launch registers carry a write-only shared-buffer grant and a reply endpoint.
// Neither its image nor the transfer ABI names physical memory or display MMIO.
static mut PRIVATE_FRAME: [u8; BOOT_SCANOUT_PROBE_BYTES] = [0; BOOT_SCANOUT_PROBE_BYTES];

#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text$a")]
extern "C" fn efi_main() -> ! {
    naked_asm!(
        "and rsp, -16",
        "mov rdi, r12",
        "mov rsi, r13",
        "mov rdx, r14",
        "call mrml_scanout_probe",
        "ud2",
    )
}

#[unsafe(no_mangle)]
extern "sysv64" fn mrml_scanout_probe(frame_grant: u64, reply_endpoint: u64, reply_task: u64) -> ! {
    if frame_grant == 0 || reply_endpoint == 0 || reply_task == 0 {
        exit();
    }
    // SAFETY: this one-shot image is mapped into a fresh service address
    // space with one task. No alias to the private frame leaves the image.
    let private = unsafe { &mut *core::ptr::addr_of_mut!(PRIVATE_FRAME) };
    let mut transport = TrapTransport {
        frame_grant,
        reply_endpoint,
        reply_task,
    };
    let _ = run_boot_scanout_probe(&mut transport, private);
    exit()
}

struct TrapTransport {
    frame_grant: u64,
    reply_endpoint: u64,
    reply_task: u64,
}

impl BootScanoutProbeTransport for TrapTransport {
    fn write_frame(&mut self, frame: &[u8; BOOT_SCANOUT_PROBE_BYTES]) -> bool {
        syscall(
            8,
            self.frame_grant,
            0,
            frame.as_ptr() as u64,
            frame.len() as u64,
        ) == 0
    }

    fn release_frame(&mut self) -> bool {
        syscall(12, self.frame_grant, 0, 0, 0) == 0
    }

    fn send_ready(&mut self, ready: &[u8; 16]) -> bool {
        syscall(
            4,
            self.reply_endpoint,
            self.reply_task,
            ready.as_ptr() as u64,
            ready.len() as u64,
        ) == 0
    }
}

fn syscall(mut op: u64, a: u64, b: u64, c: u64, length: u64) -> u64 {
    // SAFETY: this is the existing MRML buffered syscall ABI. Any slice lives
    // for the duration of the trap and is fully bounded by its supplied length.
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") op,
            inlateout("rdi") a => _,
            inlateout("rsi") b => _,
            inlateout("rdx") c => _,
            inlateout("r10") length => _,
            inlateout("r8") 0u64 => _,
            inlateout("r9") 0u64 => _,
            options(nostack),
        )
    }
    op
}

fn exit() -> ! {
    syscall(3, 0, 0, 0, 0);
    // SAFETY: an unexpected return must fault only this userspace task.
    unsafe { asm!("ud2", options(noreturn, nomem, nostack)) }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    exit()
}
