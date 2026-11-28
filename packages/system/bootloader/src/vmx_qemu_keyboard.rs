//! Exact keyboard transport for the opt-in nested QEMU diagnostic.
//! No commands are sent to the controller; the desktop never owns the ports.
use core::arch::{asm, x86_64::{__cpuid, _rdtsc}};
use mrml_boot_frame::BootScene;

const STATUS: u16 = 0x64;
const DATA: u16 = 0x60;
const OBF: u8 = 1;
const BAD_OR_AUX: u8 = 0xe0;
const WAIT_CYCLES: u64 = 16_000_000_000;

pub(super) struct QemuKeyboard {
    translated: Option<bool>,
}

impl QemuKeyboard {
    pub(super) fn probe() -> Option<Self> {
        let vendor = __cpuid(0x4000_0000);
        if __cpuid(1).ecx & (1 << 31) == 0
            || vendor.ebx.to_le_bytes() != *b"KVMK"
            || vendor.ecx.to_le_bytes() != *b"VMKV"
            || vendor.edx.to_le_bytes() != *b"M\0\0\0"
        {
            return None;
        }
        let keyboard = Self { translated: None };
        // Discard a bounded backlog before the host sends any test event.
        for _ in 0..32 {
            if keyboard.read_port(STATUS) & OBF == 0 {
                return Some(keyboard);
            }
            let _ = keyboard.read_port(DATA);
        }
        None
    }

    fn read_port(&self, port: u16) -> u8 {
        let byte: u8;
        // SAFETY: the sole constructor admits only the nested KVM fixture.
        // This private helper is used only for i8042 status and data reads.
        unsafe { asm!("in al, dx", in("dx") port, out("al") byte, options(nomem, nostack, preserves_flags)); }
        byte
    }

    pub(super) fn await_key(&mut self, scene: BootScene) -> Option<BootScene> {
        let (set1, set2) = match scene {
            BootScene::Enter => ([0x1c, 0x9c], [0x5a, 0xf0, 0x5a]),
            BootScene::TextA => ([0x1e, 0x9e], [0x1c, 0xf0, 0x1c]),
            _ => return None,
        };
        let start = cycles();
        let mut a = self.translated != Some(false);
        let mut b = self.translated != Some(true);
        let mut index = 0;
        while cycles().wrapping_sub(start) < WAIT_CYCLES {
            let status = self.read_port(STATUS);
            if status & OBF == 0 {
                core::hint::spin_loop();
                continue;
            }
            if status & BAD_OR_AUX != 0 {
                return None;
            }
            let byte = self.read_port(DATA);
            a &= set1.get(index) == Some(&byte);
            b &= set2.get(index) == Some(&byte);
            index += 1;
            if !a && !b {
                return None;
            }
            if (a && index == set1.len()) || (b && index == set2.len()) {
                self.translated = Some(a);
                return Some(scene);
            }
        }
        None
    }
}

fn cycles() -> u64 {
    // SAFETY: this diagnostic runs on the x86-64 BSP with a verified VMX timer.
    unsafe { _rdtsc() }
}
