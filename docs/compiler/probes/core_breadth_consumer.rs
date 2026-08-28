//! Controlled pinned-libcore reachability probe; not an ABI declaration.
#![no_std]

unsafe extern "C" {
    #[link_name = "_RNvMNtCs5erv4YX8a5g_4core3stre12escape_debug"]
    fn core_escape_debug();
    #[link_name = "_RNvMNtCs5erv4YX8a5g_4core3stre12substr_range"]
    fn core_substr_range();
    #[link_name = "_RNvMNtCs5erv4YX8a5g_4core3stre9from_utf8"]
    fn core_from_utf8();
    #[link_name = "_RNvMNtNtNtCs5erv4YX8a5g_4core3num3imp3fmtNtB2_4Part5write"]
    fn core_part_write();
    #[link_name = "_RNvMs2_NtNtCs5erv4YX8a5g_4core3fmt8buildersNtB5_11DebugStruct6finish"]
    fn core_debug_finish();
}

#[unsafe(no_mangle)]
pub extern "C" fn entry() -> i32 {
    core::hint::black_box([
        core_escape_debug as *const () as usize,
        core_substr_range as *const () as usize,
        core_from_utf8 as *const () as usize,
        core_part_write as *const () as usize,
        core_debug_finish as *const () as usize,
    ]);
    42
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}
