#![no_std]

#[unsafe(no_mangle)]
pub static mut EXPORTED_INITIALIZED: i32 = 40;

#[unsafe(no_mangle)]
pub static mut EXPORTED_ZERO_FILL: i32 = 0;

macro_rules! state_group {
    ($module:ident, $function:ident, $initial:expr) => {
        mod $module {
            static mut INITIALIZED: i32 = $initial;
            static mut ZERO_FILL: [i32; 32] = [0; 32];

            #[unsafe(no_mangle)]
            #[inline(never)]
            pub extern "C" fn $function(delta: i32) -> i32 {
                unsafe {
                    let index = (delta as usize) & 31;
                    INITIALIZED = INITIALIZED.wrapping_add(delta);
                    ZERO_FILL[index] = ZERO_FILL[index].wrapping_add(delta);
                    INITIALIZED.wrapping_add(ZERO_FILL[index])
                }
            }
        }
    };
}

state_group!(group_0, state_part_0, 1);
state_group!(group_1, state_part_1, 2);
state_group!(group_2, state_part_2, 3);
state_group!(group_3, state_part_3, 4);
state_group!(group_4, state_part_4, 5);
state_group!(group_5, state_part_5, 6);
state_group!(group_6, state_part_6, 7);
state_group!(group_7, state_part_7, 14);

#[unsafe(no_mangle)]
pub extern "C" fn state_answer() -> i32 {
    unsafe {
        group_0::state_part_0(0)
            + group_1::state_part_1(0)
            + group_2::state_part_2(0)
            + group_3::state_part_3(0)
            + group_4::state_part_4(0)
            + group_5::state_part_5(0)
            + group_6::state_part_6(0)
            + group_7::state_part_7(0)
            + EXPORTED_INITIALIZED
            + EXPORTED_ZERO_FILL
            - 40
    }
}
