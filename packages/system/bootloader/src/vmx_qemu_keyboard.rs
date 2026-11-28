//! Exact keyboard transport for the opt-in nested QEMU diagnostic.
//! No commands are sent to the controller; the desktop never owns the ports.
use core::arch::{
    asm,
    x86_64::{__cpuid, _rdtsc},
};
use mrml_boot_frame::{BootLetter, BootScene};

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
        unsafe {
            asm!("in al, dx", in("dx") port, out("al") byte, options(nomem, nostack, preserves_flags));
        }
        byte
    }

    /// After Enter established the translation mode, accept only an exact
    /// make/release pair for one ordinary letter or Escape.
    pub(super) fn await_text(&self) -> Option<BootScene> {
        const SET1: [u8; 26] = [
            0x1e, 0x30, 0x2e, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32, 0x31,
            0x18, 0x19, 0x10, 0x13, 0x1f, 0x14, 0x16, 0x2f, 0x11, 0x2d, 0x15, 0x2c,
        ];
        const SET2: [u8; 26] = [
            0x1c, 0x32, 0x21, 0x23, 0x24, 0x2b, 0x34, 0x33, 0x43, 0x3b, 0x42, 0x4b, 0x3a, 0x31,
            0x44, 0x4d, 0x15, 0x2d, 0x1b, 0x2c, 0x3c, 0x2a, 0x1d, 0x22, 0x35, 0x1a,
        ];
        let translated = self.translated?;
        let start = cycles();
        let make = self.wait_byte(start)?;
        let scene = if make == if translated { 0x01 } else { 0x76 } {
            BootScene::End
        } else {
            let table = if translated { SET1 } else { SET2 };
            let index = table.iter().position(|&code| code == make)?;
            BootScene::Letter(BootLetter::new(b'A' + index as u8)?)
        };
        let release = self.wait_byte(start)?;
        if translated {
            (release == make | 0x80).then_some(scene)
        } else {
            (release == 0xf0 && self.wait_byte(start)? == make).then_some(scene)
        }
    }

    fn wait_byte(&self, start: u64) -> Option<u8> {
        while cycles().wrapping_sub(start) < WAIT_CYCLES {
            let status = self.read_port(STATUS);
            if status & OBF != 0 {
                return (status & BAD_OR_AUX == 0).then(|| self.read_port(DATA));
            }
            core::hint::spin_loop();
        }
        None
    }

    pub(super) fn await_key(&mut self, scene: BootScene) -> Option<BootScene> {
        let (set1, set2) = match scene {
            BootScene::Enter => ([0x1c, 0x9c], [0x5a, 0xf0, 0x5a]),
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
