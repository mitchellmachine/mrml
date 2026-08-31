#[unsafe(no_mangle)]
pub extern "C" fn entry() -> u32 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) if duration.as_secs() >= 1_700_000_000 => 42,
        _ => 1,
    }
}
