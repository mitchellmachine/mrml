#[unsafe(no_mangle)]
pub extern "C" fn entry() -> u32 {
    std::thread::sleep(std::time::Duration::from_millis(1));
    42
}
