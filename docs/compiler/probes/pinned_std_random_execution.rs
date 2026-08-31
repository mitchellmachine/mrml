#[unsafe(no_mangle)]
pub extern "C" fn entry() -> u32 {
    let state = std::collections::hash_map::RandomState::new();
    std::hint::black_box(state);
    42
}
