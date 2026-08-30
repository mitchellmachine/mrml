#[unsafe(no_mangle)]
pub extern "C" fn entry() -> u32 {
    match std::thread::available_parallelism() {
        Ok(parallelism) if parallelism.get() != 0 => 42,
        _ => 1,
    }
}
