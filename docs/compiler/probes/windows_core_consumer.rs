#![no_std]

#[unsafe(no_mangle)]
pub extern "C" fn entry(bytes: *const u8, length: usize) -> u64 {
    let bytes = unsafe { core::slice::from_raw_parts(bytes, length) };
    match core::str::from_utf8(bytes) {
        Ok(value) => value.len() as u64,
        Err(error) => error.valid_up_to() as u64,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}
