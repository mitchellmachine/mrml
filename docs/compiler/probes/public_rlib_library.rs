#![no_std]

macro_rules! part {
    ($name:ident, $value:expr) => {
        #[unsafe(no_mangle)]
        #[inline(never)]
        pub extern "C" fn $name() -> i32 {
            $value
        }
    };
}

mod group_0 {
    part!(rlib_part_0, 1);
    part!(rlib_part_1, 2);
    part!(rlib_part_2, 3);
    part!(rlib_part_3, 4);
}
mod group_1 {
    part!(rlib_part_4, 5);
    part!(rlib_part_5, 6);
    part!(rlib_part_6, 7);
    part!(rlib_part_7, 14);
}
mod group_2 {
    part!(rlib_part_8, 0);
    part!(rlib_part_9, 0);
    part!(rlib_part_10, 0);
    part!(rlib_part_11, 0);
}
mod group_3 {
    part!(rlib_part_12, 0);
    part!(rlib_part_13, 0);
    part!(rlib_part_14, 0);
    part!(rlib_part_15, 0);
}
mod group_4 {
    part!(rlib_part_16, 0);
    part!(rlib_part_17, 0);
    part!(rlib_part_18, 0);
    part!(rlib_part_19, 0);
}
mod group_5 {
    part!(rlib_part_20, 0);
    part!(rlib_part_21, 0);
    part!(rlib_part_22, 0);
    part!(rlib_part_23, 0);
}
mod group_6 {
    part!(rlib_part_24, 0);
    part!(rlib_part_25, 0);
    part!(rlib_part_26, 0);
    part!(rlib_part_27, 0);
}
mod group_7 {
    part!(rlib_part_28, 0);
    part!(rlib_part_29, 0);
    part!(rlib_part_30, 0);
    part!(rlib_part_31, 0);
}

#[unsafe(no_mangle)]
pub extern "C" fn rlib_answer() -> i32 {
    group_0::rlib_part_0()
        + group_0::rlib_part_1()
        + group_0::rlib_part_2()
        + group_0::rlib_part_3()
        + group_1::rlib_part_4()
        + group_1::rlib_part_5()
        + group_1::rlib_part_6()
        + group_1::rlib_part_7()
        + group_2::rlib_part_8()
        + group_2::rlib_part_9()
        + group_2::rlib_part_10()
        + group_2::rlib_part_11()
        + group_3::rlib_part_12()
        + group_3::rlib_part_13()
        + group_3::rlib_part_14()
        + group_3::rlib_part_15()
        + group_4::rlib_part_16()
        + group_4::rlib_part_17()
        + group_4::rlib_part_18()
        + group_4::rlib_part_19()
        + group_5::rlib_part_20()
        + group_5::rlib_part_21()
        + group_5::rlib_part_22()
        + group_5::rlib_part_23()
        + group_6::rlib_part_24()
        + group_6::rlib_part_25()
        + group_6::rlib_part_26()
        + group_6::rlib_part_27()
        + group_7::rlib_part_28()
        + group_7::rlib_part_29()
        + group_7::rlib_part_30()
        + group_7::rlib_part_31()
}
