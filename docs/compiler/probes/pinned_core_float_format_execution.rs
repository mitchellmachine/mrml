#![no_std]

use core::fmt::{self, Write};
use core::panic::PanicInfo;

struct Buffer {
    bytes: [u8; 32],
    length: usize,
}

impl Write for Buffer {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.length.checked_add(value.len()).ok_or(fmt::Error)?;
        let output = self.bytes.get_mut(self.length..end).ok_or(fmt::Error)?;
        output.copy_from_slice(value.as_bytes());
        self.length = end;
        Ok(())
    }
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn entry() -> u32 {
    let mut output = Buffer {
        bytes: [0; 32],
        length: 0,
    };
    let value = core::hint::black_box(3.141592653589793f64);
    if write!(&mut output, "{value:.6}").is_ok()
        && output.bytes.get(..output.length) == Some(b"3.141593")
    {
        42
    } else {
        1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}
