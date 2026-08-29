extern crate std;

use mrml_rustc::{
    CodegenErrorKind, CompileErrorKind, ObjectFormat, TargetLayout, compile_source_function,
};
use std::{
    ffi::c_void,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Once,
        atomic::{AtomicU64, Ordering},
    },
    vec::Vec,
};

#[cfg(target_os = "windows")]
const FORMAT: ObjectFormat = ObjectFormat::Coff;
#[cfg(not(target_os = "windows"))]
const FORMAT: ObjectFormat = ObjectFormat::Elf64;
#[cfg(target_os = "windows")]
const TOOLCHAIN: &str = "nightly-2026-08-24-x86_64-pc-windows-gnullvm";
#[cfg(not(target_os = "windows"))]
const TOOLCHAIN: &str = "nightly-2026-08-24-x86_64-unknown-linux-gnu";
const COMMIT: &str = "fb6531d550e0075b9eb9a51464f404805eec87d9";
static ORACLE: Once = Once::new();
static ORACLE_DIRECTORY: AtomicU64 = AtomicU64::new(0);
const MRML_ABI_FACADE: &str = include_str!("oracle_support/mrml_abi.rs");
const MRML_V1_SCALAR_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(value: u64) -> u64 { value + 17 }";
const MRML_V1_STACK_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64) -> u64 { a + b * 2 + c * 3 + d * 4 + e * 5 + f * 6 + g * 7 + h * 8 }";
const MRML_V1_SLICE_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: &[u8]) -> u64 { input.len() as u64 }";
const MRML_V1_SLICE_CONTENT_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: &[u8]) -> u64 { input[0] as u64 + input[input.len() - 1] as u64 * 2 + input.len() as u64 * 3 }";
const MRML_V1_STR_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: &str) -> u64 { let bytes: &[u8] = input.as_bytes(); bytes[0] as u64 + bytes[bytes.len() - 1] as u64 * 2 + input.len() as u64 * 3 }";
const MRML_V1_MUT_SLICE_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: &mut [u8]) -> u64 { input[0] += 3; let last: usize = input.len() - 1; input[last] += 5; input[0] as u64 + input[last] as u64 * 2 + input.len() as u64 * 3 }";
const MRML_V1_SLICE_RETURN_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: &[u8]) -> &[u8] { input }";
const MRML_V1_MUT_SLICE_RETURN_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: &mut [u8]) -> &mut [u8] { input[0] += 1; input }";
const MRML_V1_STR_RETURN_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: &str, alternate: bool) -> &str { if alternate { \"MRML\" } else { input } }";
const MRML_V1_WIDE_NARROW_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(unsigned: u128, signed: i128) -> u64 { (unsigned as u32 as u64) ^ (signed as i16 as u64) }";
const MRML_V1_WIDE_RETURN_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { input }";
const MRML_V1_WIDE_UNSIGNED_TO_SIGNED_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> i128 { input as i128 }";
const MRML_V1_WIDE_SIGNED_TO_UNSIGNED_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> u128 { input as u128 }";
const MRML_V1_WIDE_UNSIGNED_NOT_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { !input }";
const MRML_V1_WIDE_SIGNED_NOT_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { !input }";
const MRML_V1_WIDE_SIGNED_NEGATE_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { -input }";
const MRML_V1_WIDE_BITAND_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { input & 1512366075204170947332355369683137040 }";
const MRML_V1_WIDE_BITOR_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { input | 1512366075204170947332355369683137040 }";
const MRML_V1_WIDE_BITXOR_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { input ^ 1512366075204170947332355369683137040 }";
const MRML_V1_WIDE_UNSIGNED_ADD_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { input + 17 }";
const MRML_V1_WIDE_SIGNED_ADD_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { input + 17 }";
const MRML_V1_WIDE_UNSIGNED_SUBTRACT_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { input - 17 }";
const MRML_V1_WIDE_SIGNED_SUBTRACT_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { input - 17 }";
const MRML_V1_WIDE_UNSIGNED_WRAPPING_ADD_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { input.wrapping_add(17) }";
const MRML_V1_WIDE_SIGNED_WRAPPING_SUBTRACT_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { input.wrapping_sub(17) }";
const MRML_V1_WIDE_UNSIGNED_WRAPPING_MULTIPLY_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { input.wrapping_mul(17) }";
const MRML_V1_WIDE_SIGNED_WRAPPING_MULTIPLY_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { input.wrapping_mul(-17) }";
const MRML_V1_WIDE_UNSIGNED_WRAPPING_NEGATE_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { input.wrapping_neg() }";
const MRML_V1_WIDE_SIGNED_WRAPPING_NEGATE_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { input.wrapping_neg() }";
const MRML_V1_WIDE_SIGNED_WRAPPING_ABSOLUTE_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { input.wrapping_abs() }";
const MRML_V1_WIDE_SIGNED_SATURATING_NEGATE_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { input.saturating_neg() }";
const MRML_V1_WIDE_SIGNED_SATURATING_ABSOLUTE_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { input.saturating_abs() }";
const MRML_V1_WIDE_UNSIGNED_SATURATING_ADD_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { input.saturating_add(17) }";
const MRML_V1_WIDE_SIGNED_SATURATING_ADD_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { input.saturating_add(17) }";
const MRML_V1_WIDE_UNSIGNED_SATURATING_SUBTRACT_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { input.saturating_sub(17) }";
const MRML_V1_WIDE_SIGNED_SATURATING_SUBTRACT_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { input.saturating_sub(17) }";
const MRML_V1_WIDE_UNSIGNED_ROTATE_LEFT_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128, distance: u32) -> u128 { input.rotate_left(distance) }";
const MRML_V1_WIDE_SIGNED_ROTATE_RIGHT_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128, distance: u32) -> i128 { input.rotate_right(distance) }";
const MRML_V1_WIDE_UNSIGNED_SWAP_BYTES_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { input.swap_bytes() }";
const MRML_V1_WIDE_SIGNED_TO_BIG_ENDIAN_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { input.to_be() }";
const MRML_V1_WIDE_UNSIGNED_TO_LITTLE_ENDIAN_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { input.to_le() }";
const MRML_V1_WIDE_SIGNED_REVERSE_BITS_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { input.reverse_bits() }";
const MRML_V1_WIDE_UNSIGNED_ISOLATE_HIGHEST_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { input.isolate_highest_one() }";
const MRML_V1_WIDE_SIGNED_ISOLATE_LOWEST_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { input.isolate_lowest_one() }";
const MRML_V1_WIDE_UNSIGNED_COUNT_ONES_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u32 { input.count_ones() }";
const MRML_V1_WIDE_UNSIGNED_BIT_WIDTH_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u32 { input.bit_width() }";
const MRML_V1_WIDE_SIGNED_COUNT_ZEROS_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> u32 { input.count_zeros() }";
const MRML_V1_WIDE_UNSIGNED_LEADING_ZEROS_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u32 { input.leading_zeros() }";
const MRML_V1_WIDE_SIGNED_TRAILING_ZEROS_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> u32 { input.trailing_zeros() }";
const MRML_V1_WIDE_UNSIGNED_LEADING_ONES_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u32 { input.leading_ones() }";
const MRML_V1_WIDE_SIGNED_TRAILING_ONES_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> u32 { input.trailing_ones() }";
const MRML_V1_WIDE_UNSIGNED_NEXT_POWER_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { input.next_power_of_two() }";
const MRML_V1_WIDE_UNSIGNED_WRAPPING_NEXT_POWER_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { input.wrapping_next_power_of_two() }";
const MRML_V1_WIDE_SIGNED_SIGNUM_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { input.signum() }";
const MRML_V1_WIDE_SIGNED_ABSOLUTE_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { input.abs() }";
const MRML_V1_WIDE_SIGNED_STRICT_ABSOLUTE_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { input.strict_abs() }";
const RUSTC_WIDE_SIGNED_STRICT_ABSOLUTE_SOURCE: &str = concat!(
    "#![feature(strict_overflow_ops)]\n",
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { input.strict_abs() }"
);
const MRML_V1_WIDE_SIGNED_UNSIGNED_ABSOLUTE_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> u128 { input.unsigned_abs() }";
const MRML_V1_WIDE_UNSIGNED_STRICT_NEGATE_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { input.strict_neg() }";
const MRML_V1_WIDE_SIGNED_STRICT_NEGATE_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { input.strict_neg() }";
const RUSTC_WIDE_UNSIGNED_STRICT_NEGATE_SOURCE: &str = concat!(
    "#![feature(strict_overflow_ops)]\n",
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { input.strict_neg() }"
);
const RUSTC_WIDE_SIGNED_STRICT_NEGATE_SOURCE: &str = concat!(
    "#![feature(strict_overflow_ops)]\n",
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { input.strict_neg() }"
);
const MRML_V1_WIDE_UNSIGNED_WRAPPING_SHIFT_LEFT_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128, distance: u32) -> u128 { input.wrapping_shl(distance) }";
const MRML_V1_WIDE_SIGNED_STRICT_SHIFT_RIGHT_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128, distance: u32) -> i128 { input.strict_shr(distance) }";
const RUSTC_WIDE_SIGNED_STRICT_SHIFT_RIGHT_SOURCE: &str = concat!(
    "#![feature(strict_overflow_ops)]\n",
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128, distance: u32) -> i128 { input.strict_shr(distance) }"
);
const MRML_V1_WIDE_SIGNED_UNBOUNDED_SHIFT_RIGHT_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128, distance: u32) -> i128 { input.unbounded_shr(distance) }";
const RUSTC_WIDE_SIGNED_UNBOUNDED_SHIFT_RIGHT_SOURCE: &str = concat!(
    "#![feature(unbounded_shifts)]\n",
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128, distance: u32) -> i128 { input.unbounded_shr(distance) }"
);
const MRML_V1_WIDE_UNSIGNED_POWER_OF_TWO_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u64 { input.is_power_of_two() as u64 }";
const MRML_V1_WIDE_UNSIGNED_IS_MULTIPLE_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128, divisor: u128) -> u64 { input.is_multiple_of(divisor) as u64 }";
const MRML_V1_WIDE_UNSIGNED_MIDPOINT_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(left: u128, right: u128) -> u128 { left.midpoint(right) }";
const MRML_V1_WIDE_SIGNED_MIDPOINT_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(left: i128, right: i128) -> i128 { left.midpoint(right) }";
const MRML_V1_WIDE_UNSIGNED_MINIMUM_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(left: u128, right: u128) -> u128 { left.min(right) }";
const MRML_V1_WIDE_UNSIGNED_MAXIMUM_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(left: u128, right: u128) -> u128 { left.max(right) }";
const MRML_V1_WIDE_SIGNED_MINIMUM_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(left: i128, right: i128) -> i128 { left.min(right) }";
const MRML_V1_WIDE_SIGNED_MAXIMUM_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(left: i128, right: i128) -> i128 { left.max(right) }";
const MRML_V1_WIDE_UNSIGNED_ABSOLUTE_DIFFERENCE_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(left: u128, right: u128) -> u128 { left.abs_diff(right) }";
const MRML_V1_WIDE_SIGNED_ABSOLUTE_DIFFERENCE_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(left: i128, right: i128) -> u128 { left.abs_diff(right) }";
const MRML_V1_WIDE_SIGNED_IS_POSITIVE_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> u64 { input.is_positive() as u64 }";
const MRML_V1_WIDE_SIGNED_IS_NEGATIVE_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> u64 { input.is_negative() as u64 }";
const RUSTC_WIDE_UNSIGNED_WRAPPING_NEXT_POWER_SOURCE: &str = concat!(
    "#![feature(wrapping_next_power_of_two)]\n",
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { input.wrapping_next_power_of_two() }"
);
const MRML_V1_WIDE_SIGNED_WRAPPING_DIVIDE_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { input.wrapping_div(-1) }";
const MRML_V1_WIDE_SIGNED_WRAPPING_REMAINDER_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { input.wrapping_rem(-1) }";
const MRML_V1_WIDE_UNSIGNED_EQUAL_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u64 { (input == 1512366075204170947332355369683137040) as u64 }";
const MRML_V1_WIDE_SIGNED_NOT_EQUAL_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> u64 { (input != -1512366075204170947332355369683137040) as u64 }";
const MRML_V1_WIDE_UNSIGNED_LESS_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u64 { (input < 1512366075204170947332355369683137040) as u64 }";
const MRML_V1_WIDE_SIGNED_GREATER_EQUAL_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> u64 { (input >= -1512366075204170947332355369683137040) as u64 }";
const MRML_V1_WIDE_UNSIGNED_MULTIPLY_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { input * 18446744073709551617 }";
const MRML_V1_WIDE_SIGNED_MULTIPLY_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { input * -17 }";
const MRML_V1_WIDE_SIGNED_MULTIPLY_OVERFLOW_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { input * -1 }";
const MRML_V1_WIDE_UNSIGNED_SHIFT_LEFT_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: u128, shift: u32) -> u128 { input << shift }";
const MRML_V1_WIDE_UNSIGNED_SHIFT_RIGHT_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: u128, shift: u32) -> u128 { input >> shift }";
const MRML_V1_WIDE_SIGNED_SHIFT_RIGHT_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: i128, shift: u32) -> i128 { input >> shift }";
const MRML_V1_WIDE_UNSIGNED_DIVIDE_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { input / 18446744073709551617 }";
const MRML_V1_WIDE_UNSIGNED_REMAINDER_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { input % 18446744073709551617 }";
const MRML_V1_WIDE_UNSIGNED_ZERO_DIVISOR_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { input / 0 }";
const MRML_V1_WIDE_UNSIGNED_WRAPPING_ZERO_DIVISOR_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { input.wrapping_div(0) }";
const MRML_V1_WIDE_SIGNED_DIVIDE_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { input / -17 }";
const MRML_V1_WIDE_SIGNED_REMAINDER_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { input % -17 }";
const MRML_V1_WIDE_SIGNED_DIVIDE_OVERFLOW_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { input / -1 }";
const MRML_V1_WIDE_SIGNED_REMAINDER_OVERFLOW_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { input % -1 }";
const MRML_V1_WIDE_CONDITIONAL_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: u128, choose: bool) -> u128 { if choose { input + 17 } else { 1512366075204170947332355369683137040 } }";
const MRML_V1_WIDE_SEQUENCE_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { { 7; input + 17 } }";
const MRML_V1_WIDE_LOCAL_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { let adjusted: u128 = input + 17; adjusted }";
const MRML_V1_WIDE_ASSIGN_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { let mut adjusted: u128 = input; adjusted = adjusted + 17; adjusted }";
const MRML_V1_WIDE_DISCARD_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { input + 3; input + 17 }";
const MRML_V1_WIDE_COMPOUND_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { let mut value: u128 = input; value += 18446744073709551617; value ^= 1512366075204170947332355369683137040; value -= 3; value &= 170141183460469231731687303715884105727; value |= 17; value }";
const MRML_V1_WIDE_HELPER_SOURCE: &str = "fn adjust(value: u128) -> u128 { value + 17 } #[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { adjust(input) }";
const MRML_V1_WIDE_HELPER_RETURN_SOURCE: &str = "fn adjust(value: u128, early: bool) -> u128 { if early { return value + 17; } value ^ 1512366075204170947332355369683137040 } #[mrml_abi::export(version = 1)] pub fn probe(input: u128, early: bool) -> u128 { adjust(input, early) }";
const MRML_V1_WIDE_UNSIGNED_MULTIPLY_ASSIGN_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { let mut value: u128 = input; value *= 18446744073709551617; value }";
const MRML_V1_WIDE_SIGNED_MULTIPLY_ASSIGN_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { let mut value: i128 = input; value *= -17; value }";
const MRML_V1_WIDE_UNSIGNED_DIVIDE_ASSIGN_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: u128) -> u128 { let mut value: u128 = input; value /= 18446744073709551617; value %= 257; value }";
const MRML_V1_WIDE_SIGNED_DIVIDE_ASSIGN_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: i128) -> i128 { let mut value: i128 = input; value /= -17; value %= 7; value }";
const MRML_V1_WIDE_UNSIGNED_SHIFT_ASSIGN_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: u128, shift: u32) -> u128 { let mut value: u128 = input; value <<= shift; value >>= 3; value }";
const MRML_V1_WIDE_SIGNED_SHIFT_ASSIGN_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(input: i128, shift: u32) -> i128 { let mut value: i128 = input; value >>= shift; value <<= 2; value }";
const MRML_V1_WIDE_UNSIGNED_CONSTANT_SOURCE: &str = "const fn matches(value: u128, distance: u32, expected: u128) -> bool { (value >> distance) == expected } const DISTANCE: u32 = 65; const WIDE: u128 = 1512366075204170947332355369683137040u128 >> DISTANCE; const MATCHES: bool = matches(1512366075204170947332355369683137040u128, DISTANCE, WIDE); #[mrml_abi::export(version = 1)] pub fn probe() -> u128 { if MATCHES { WIDE } else { 0 } }";
const MRML_V1_WIDE_SIGNED_CONSTANT_SOURCE: &str = "const fn matches(value: i128, distance: u32, expected: i128) -> bool { (value >> distance) == expected } const DISTANCE: u32 = 65; const WIDE: i128 = -1512366075204170947332355369683137040i128 >> DISTANCE; const MATCHES: bool = matches(-1512366075204170947332355369683137040i128, DISTANCE, WIDE); #[mrml_abi::export(version = 1)] pub fn probe() -> i128 { if MATCHES { WIDE } else { 0 } }";
const MRML_V1_WIDE_UNSIGNED_CONST_CALL_SOURCE: &str = "const fn select(value: u128) -> u128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> u128 { select(1512366075204170947332355369683137040) }";
const MRML_V1_WIDE_SIGNED_CONST_CALL_SOURCE: &str = "const fn select(value: i128) -> i128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> i128 { select(-1512366075204170947332355369683137040) }";
const MRML_V1_WIDE_UNSIGNED_NESTED_CONST_CALL_SOURCE: &str = "const fn select(value: u128) -> u128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> u128 { select(select(1512366075204170947332355369683137040)) }";
const MRML_V1_WIDE_SIGNED_NESTED_CONST_CALL_SOURCE: &str = "const fn select(value: i128) -> i128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> i128 { select(select(-1512366075204170947332355369683137040)) }";
const MRML_V1_WIDE_UNSIGNED_UNARY_CONST_CALL_SOURCE: &str = "const fn select(value: u128) -> u128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> u128 { select(!select(1512366075204170947332355369683137040)) }";
const MRML_V1_WIDE_SIGNED_UNARY_CONST_CALL_SOURCE: &str = "const fn select(value: i128) -> i128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> i128 { select(-select(1512366075204170947332355369683137040)) }";
const MRML_V1_WIDE_UNSIGNED_BITWISE_CONST_CALL_SOURCE: &str = "const fn select(value: u128) -> u128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> u128 { select(select(1512366075204170947332355369683137040) ^ !select(170141183460469231731687303715884105727)) }";
const MRML_V1_WIDE_SIGNED_BITWISE_CONST_CALL_SOURCE: &str = "const fn select(value: i128) -> i128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> i128 { select(select(-1512366075204170947332355369683137040) | select(17)) }";
const MRML_V1_WIDE_UNSIGNED_ARITHMETIC_CONST_CALL_SOURCE: &str = "const fn select(value: u128) -> u128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> u128 { select(select(1512366075204170947332355369683137040) + select(18446744073709551617) - 17) }";
const MRML_V1_WIDE_SIGNED_ARITHMETIC_CONST_CALL_SOURCE: &str = "const fn select(value: i128) -> i128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> i128 { select(select(-1512366075204170947332355369683137040) + select(18446744073709551617) - 17) }";
const MRML_V1_WIDE_UNSIGNED_MULTIPLY_CONST_CALL_SOURCE: &str = "const fn select(value: u128) -> u128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> u128 { select(select(18446744073709551617) * select(4294967297)) }";
const MRML_V1_WIDE_SIGNED_MULTIPLY_CONST_CALL_SOURCE: &str = "const fn select(value: i128) -> i128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> i128 { select(select(-18446744073709551617) * select(4294967297)) }";
const MRML_V1_WIDE_UNSIGNED_DIVIDE_CONST_CALL_SOURCE: &str = "const fn select(value: u128) -> u128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> u128 { select(select(340282366920938463463374607431768211455) / select(18446744073709551617) + select(340282366920938463463374607431768211455) % select(257)) }";
const MRML_V1_WIDE_SIGNED_DIVIDE_CONST_CALL_SOURCE: &str = "const fn select(value: i128) -> i128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> i128 { select(select(-1512366075204170947332355369683137040) / select(17) + select(-1512366075204170947332355369683137040) % select(17)) }";
const MRML_V1_WIDE_UNSIGNED_SHIFT_CONST_CALL_SOURCE: &str = "const fn select(value: u128) -> u128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> u128 { select(select(1512366075204170947332355369683137040) << 65 >> 17) }";
const MRML_V1_WIDE_SIGNED_SHIFT_CONST_CALL_SOURCE: &str = "const fn select(value: i128) -> i128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> i128 { select(select(-1512366075204170947332355369683137040) >> 65 << 17) }";
const MRML_V1_WIDE_UNSIGNED_CONDITIONAL_CONST_CALL_SOURCE: &str = "const fn select(value: u128) -> u128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> u128 { select(if true { select(1512366075204170947332355369683137040) } else { select(17) }) }";
const MRML_V1_WIDE_SIGNED_CONDITIONAL_CONST_CALL_SOURCE: &str = "const fn select(value: i128) -> i128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> i128 { select(if false { select(17) } else { select(-1512366075204170947332355369683137040) }) }";
const MRML_V1_WIDE_UNSIGNED_SEQUENCE_CONST_CALL_SOURCE: &str = "const fn select(value: u128) -> u128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> u128 { select({ 7; select(1512366075204170947332355369683137040) }) }";
const MRML_V1_WIDE_SIGNED_SEQUENCE_CONST_CALL_SOURCE: &str = "const fn select(value: i128) -> i128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> i128 { select({ 7; select(-1512366075204170947332355369683137040) }) }";
const MRML_V1_WIDE_UNSIGNED_CAST_CONST_CALL_SOURCE: &str = "const fn signed(value: i128) -> i128 { value } const fn select(value: u128) -> u128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> u128 { select(signed(-1512366075204170947332355369683137040i128) as u128) }";
const MRML_V1_WIDE_SIGNED_CAST_CONST_CALL_SOURCE: &str = "const fn unsigned(value: u128) -> u128 { value } const fn select(value: i128) -> i128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> i128 { select(unsigned(340282366920938463463374607431768211455u128) as i128) }";
const MRML_V1_WIDE_UNSIGNED_INLINE_CONST_CALL_SOURCE: &str = "const fn select(value: u128) -> u128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> u128 { select(const { select(1512366075204170947332355369683137040) + 17 }) }";
const MRML_V1_WIDE_SIGNED_INLINE_CONST_CALL_SOURCE: &str = "const fn select(value: i128) -> i128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> i128 { select(const { select(-1512366075204170947332355369683137040) - 17 }) }";
const MRML_V1_WIDE_UNSIGNED_COMPARE_CONST_CALL_SOURCE: &str = "const fn select(value: u128) -> u128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> u128 { select(if select(1512366075204170947332355369683137040) > select(17) { select(1512366075204170947332355369683137040) } else { select(17) }) }";
const MRML_V1_WIDE_SIGNED_COMPARE_CONST_CALL_SOURCE: &str = "const fn select(value: i128) -> i128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> i128 { select(if select(-1512366075204170947332355369683137040) < select(17) { select(-1512366075204170947332355369683137040) } else { select(17) }) }";
const MRML_V1_WIDE_UNSIGNED_LOGICAL_CONST_CALL_SOURCE: &str = "const fn select(value: u128) -> u128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> u128 { select(if select(1512366075204170947332355369683137040) > select(17) && !(select(17) == select(19)) { select(1512366075204170947332355369683137040) } else { select(17) }) }";
const MRML_V1_WIDE_SIGNED_LOGICAL_CONST_CALL_SOURCE: &str = "const fn select(value: i128) -> i128 { value } #[mrml_abi::export(version = 1)] pub fn probe() -> i128 { select(if select(-1512366075204170947332355369683137040) > select(17) || select(-17) != select(17) { select(-1512366075204170947332355369683137040) } else { select(17) }) }";
const MRML_V1_WIDE_UNSIGNED_MULTI_ARGUMENT_CONST_CALL_SOURCE: &str = "const fn select(value: u128) -> u128 { value } const fn combine(left: u128, right: u128, shift: u32) -> u128 { let mut value: u128 = left ^ right; value >>= shift; value } #[mrml_abi::export(version = 1)] pub fn probe() -> u128 { combine(select(1512366075204170947332355369683137040), select(170141183460469231731687303715884105727), 65) }";
const MRML_V1_WIDE_SIGNED_MULTI_ARGUMENT_CONST_CALL_SOURCE: &str = "const fn select(value: i128) -> i128 { value } const fn combine(left: i128, right: i128, shift: u32) -> i128 { let mut value: i128 = left + right; value >>= shift; value } #[mrml_abi::export(version = 1)] pub fn probe() -> i128 { combine(select(-1512366075204170947332355369683137040), select(18446744073709551617), 65) }";
const MRML_V1_UNSIGNED_WIDEN_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u64) -> u128 { input as u128 }";
const MRML_V1_SIGNED_WIDEN_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i64) -> i128 { input as i128 }";
const MRML_V1_NARROW_SIGNED_TO_UNSIGNED_WIDEN_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: i8) -> u128 { input as u128 }";
const MRML_V1_NARROW_UNSIGNED_TO_SIGNED_WIDEN_SOURCE: &str =
    "#[mrml_abi::export(version = 1)] pub fn probe(input: u32) -> i128 { input as i128 }";
const MRML_V1_U128_LITERAL_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe() -> u128 { 340282366920938463463374607431768211455 }";
const MRML_V1_I128_MAX_LITERAL_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe() -> i128 { 170141183460469231731687303715884105727 }";
const MRML_V1_I128_MIN_LITERAL_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe() -> i128 { -170141183460469231731687303715884105728 }";
#[cfg(target_os = "windows")]
const MRML_V1_SPLIT_SLICE_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(a: u64, b: u64, c: u64, input: &[u8]) -> u64 { a + b * 2 + c * 3 + input.len() as u64 }";
#[cfg(not(target_os = "windows"))]
const MRML_V1_SPLIT_SLICE_SOURCE: &str = "#[mrml_abi::export(version = 1)] pub fn probe(a: u64, b: u64, c: u64, d: u64, e: u64, input: &[u8]) -> u64 { a + b * 2 + c * 3 + d * 4 + e * 5 + input.len() as u64 }";

fn verify_oracle() {
    ORACLE.call_once(|| {
        let output = Command::new("rustup")
            .args(["run", TOOLCHAIN, "rustc", "-Vv"])
            .output()
            .expect("launch pinned rustc");
        assert!(output.status.success());
        assert!(String::from_utf8(output.stdout).unwrap().contains(COMMIT));
    });
}
fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
#[cfg(target_os = "windows")]
fn i32_at(b: &[u8], o: usize) -> i32 {
    i32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
#[cfg(not(target_os = "windows"))]
fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
#[cfg(not(target_os = "windows"))]
fn i64_at(b: &[u8], o: usize) -> i64 {
    i64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

struct ObjectImage {
    code: Vec<u8>,
    data: Vec<u8>,
    relocations: Vec<(usize, usize)>,
}

#[cfg(target_os = "windows")]
fn object_image(object: &[u8]) -> ObjectImage {
    let table = 20 + usize::from(u16_at(object, 16));
    let mut text = None;
    let mut data = None;
    for index in 0..usize::from(u16_at(object, 2)) {
        let h = table + index * 40;
        if object.get(h..h + 5) == Some(b".text") {
            text = Some((
                u32_at(object, h + 20) as usize,
                u32_at(object, h + 16) as usize,
                u32_at(object, h + 24) as usize,
                usize::from(u16_at(object, h + 32)),
            ));
        } else if object.get(h..h + 7) == Some(b".rdata\0") {
            data = Some((
                u32_at(object, h + 20) as usize,
                u32_at(object, h + 16) as usize,
            ));
        }
    }
    let (text_offset, text_size, relocation_offset, relocation_count) =
        text.expect("COFF object has no .text");
    let mut code = object[text_offset..text_offset + text_size].to_vec();
    let data = data.map_or_else(Vec::new, |(offset, size)| {
        object[offset..offset + size].to_vec()
    });
    let mut relocations = Vec::new();
    for index in 0..relocation_count {
        let offset = relocation_offset + index * 10;
        let patch = u32_at(object, offset) as usize;
        assert_eq!(u32_at(object, offset + 4), 1, "unexpected COFF symbol");
        assert_eq!(u16_at(object, offset + 8), 4, "unexpected COFF relocation");
        let addend = i32_at(&code, patch);
        assert!(addend >= 0, "negative COFF read-only addend");
        relocations.push((patch, addend as usize));
        code[patch..patch + 4].fill(0);
    }
    ObjectImage {
        code,
        data,
        relocations,
    }
}
#[cfg(not(target_os = "windows"))]
fn object_image(object: &[u8]) -> ObjectImage {
    let (table, stride) = (u64_at(object, 40) as usize, usize::from(u16_at(object, 58)));
    let names_h = table + usize::from(u16_at(object, 62)) * stride;
    let names =
        &object[u64_at(object, names_h + 24) as usize..][..u64_at(object, names_h + 32) as usize];
    let mut text = None;
    let mut data = None;
    let mut relocation_section = None;
    for index in 0..usize::from(u16_at(object, 60)) {
        let h = table + index * stride;
        let name = u32_at(object, h) as usize;
        if names.get(name..name + 6) == Some(b".text\0") {
            assert_eq!(u32_at(object, h + 4), 1, ".text is not PROGBITS");
            assert_ne!(u64_at(object, h + 8) & 4, 0, ".text is not executable");
            text = Some((
                u64_at(object, h + 24) as usize,
                u64_at(object, h + 32) as usize,
            ));
        } else if names.get(name..name + 8) == Some(b".rodata\0") {
            assert_eq!(u32_at(object, h + 4), 1, ".rodata is not PROGBITS");
            data = Some((
                u64_at(object, h + 24) as usize,
                u64_at(object, h + 32) as usize,
            ));
        } else if names.get(name..name + 11) == Some(b".rela.text\0") {
            assert_eq!(u32_at(object, h + 4), 4, ".rela.text is not RELA");
            relocation_section = Some((
                u64_at(object, h + 24) as usize,
                u64_at(object, h + 32) as usize,
            ));
        }
    }
    let (text_offset, text_size) = text.expect("ELF object has no .text");
    let mut code = object[text_offset..text_offset + text_size].to_vec();
    let data = data.map_or_else(Vec::new, |(offset, size)| {
        object[offset..offset + size].to_vec()
    });
    let mut relocations = Vec::new();
    if let Some((offset, size)) = relocation_section {
        assert_eq!(size % 24, 0, "invalid ELF RELA size");
        for index in 0..size / 24 {
            let relocation = offset + index * 24;
            let patch = u64_at(object, relocation) as usize;
            assert_eq!(u64_at(object, relocation + 8), (1u64 << 32) | 2);
            let addend = i64_at(object, relocation + 16)
                .checked_add(4)
                .expect("ELF addend overflow");
            assert!(addend >= 0, "negative ELF read-only addend");
            relocations.push((patch, addend as usize));
            code[patch..patch + 4].fill(0);
        }
    }
    ObjectImage {
        code,
        data,
        relocations,
    }
}

struct Executable {
    pointer: *mut u8,
    length: usize,
}
impl Executable {
    fn load(image: ObjectImage) -> Self {
        assert!(!image.code.is_empty());
        let data_offset = image.code.len().checked_add(15).unwrap() & !15;
        let length = data_offset.checked_add(image.data.len()).unwrap();
        let pointer = allocate(length);
        unsafe {
            std::ptr::copy_nonoverlapping(image.code.as_ptr(), pointer, image.code.len());
            std::ptr::copy_nonoverlapping(
                image.data.as_ptr(),
                pointer.add(data_offset),
                image.data.len(),
            );
        }
        for (patch, data_addend) in image.relocations {
            assert!(
                patch
                    .checked_add(4)
                    .is_some_and(|end| end <= image.code.len())
            );
            assert!(data_addend <= image.data.len());
            let target = unsafe { pointer.add(data_offset + data_addend) } as isize;
            let next = unsafe { pointer.add(patch + 4) } as isize;
            let displacement = i32::try_from(target - next).expect("relocation out of range");
            unsafe {
                pointer
                    .add(patch)
                    .cast::<i32>()
                    .write_unaligned(displacement)
            };
        }
        protect(pointer, length);
        Self { pointer, length }
    }
}
impl Drop for Executable {
    fn drop(&mut self) {
        release(self.pointer, self.length);
    }
}

#[cfg(target_os = "windows")]
unsafe extern "system" {
    fn VirtualAlloc(a: *mut c_void, n: usize, kind: u32, protection: u32) -> *mut c_void;
    fn VirtualProtect(a: *mut c_void, n: usize, protection: u32, old: *mut u32) -> i32;
    fn VirtualFree(a: *mut c_void, n: usize, kind: u32) -> i32;
    fn SetErrorMode(mode: u32) -> u32;
}
#[cfg(target_os = "windows")]
fn allocate(n: usize) -> *mut u8 {
    let p = unsafe { VirtualAlloc(std::ptr::null_mut(), n, 0x3000, 4) };
    assert!(!p.is_null());
    p.cast()
}
#[cfg(target_os = "windows")]
fn protect(p: *mut u8, n: usize) {
    let mut old = 0;
    assert_ne!(unsafe { VirtualProtect(p.cast(), n, 0x20, &mut old) }, 0);
}
#[cfg(target_os = "windows")]
fn release(p: *mut u8, _: usize) {
    assert_ne!(unsafe { VirtualFree(p.cast(), 0, 0x8000) }, 0);
}

#[cfg(not(target_os = "windows"))]
unsafe extern "C" {
    fn mmap(
        a: *mut c_void,
        n: usize,
        protection: i32,
        flags: i32,
        fd: i32,
        offset: isize,
    ) -> *mut c_void;
    fn mprotect(a: *mut c_void, n: usize, protection: i32) -> i32;
    fn munmap(a: *mut c_void, n: usize) -> i32;
    fn fork() -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn _exit(status: i32) -> !;
}
#[cfg(not(target_os = "windows"))]
fn allocate(n: usize) -> *mut u8 {
    let p = unsafe { mmap(std::ptr::null_mut(), n, 3, 0x22, -1, 0) };
    assert_ne!(p as isize, -1);
    p.cast()
}
#[cfg(not(target_os = "windows"))]
fn protect(p: *mut u8, n: usize) {
    assert_eq!(unsafe { mprotect(p.cast(), n, 5) }, 0);
}
#[cfg(not(target_os = "windows"))]
fn release(p: *mut u8, n: usize) {
    assert_eq!(unsafe { munmap(p.cast(), n) }, 0);
}

fn compile(source: &str) -> Executable {
    verify_oracle();
    let object = compile_source_function::<8192, 4096, 8, 8, 8, 128>(
        source,
        "probe",
        FORMAT,
        TargetLayout::X86_64,
    )
    .unwrap();
    Executable::load(object_image(object.bytes()))
}

struct OracleDirectory(PathBuf);

impl OracleDirectory {
    fn create() -> Self {
        for _ in 0..64 {
            let sequence = ORACLE_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "mrml-rustc-oracle-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create isolated oracle directory: {error}"),
            }
        }
        panic!("create isolated oracle directory: collision limit exceeded")
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for OracleDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove isolated oracle directory");
    }
}

#[cfg(target_os = "windows")]
fn pinned_rust_lld() -> PathBuf {
    let sysroot = Command::new("rustup")
        .args(["run", TOOLCHAIN, "rustc", "--print", "sysroot"])
        .output()
        .expect("locate pinned rustc sysroot");
    assert!(sysroot.status.success());
    let linker = PathBuf::from(
        String::from_utf8(sysroot.stdout)
            .expect("pinned rustc sysroot is UTF-8")
            .trim(),
    )
    .join("lib/rustlib/x86_64-pc-windows-gnullvm/bin/rust-lld.exe");
    assert!(linker.is_file(), "pinned rust-lld is unavailable");
    linker
}

fn rustc_mrml_v1_observations(source: &str, driver: &str) -> Vec<u64> {
    verify_oracle();
    let directory = OracleDirectory::create();
    let facade_source = directory.path().join("mrml_abi.rs");
    let shared_source = directory.path().join("shared.rs");
    #[cfg(target_os = "windows")]
    let facade_library = directory.path().join("mrml_abi.dll");
    #[cfg(not(target_os = "windows"))]
    let facade_library = directory.path().join("libmrml_abi.so");
    #[cfg(target_os = "windows")]
    let executable = directory.path().join("shared.exe");
    #[cfg(not(target_os = "windows"))]
    let executable = directory.path().join("shared");
    fs::write(&facade_source, MRML_ABI_FACADE).expect("write oracle facade source");
    fs::write(
        &shared_source,
        format!("{source}\nfn main() {{ {driver} }}"),
    )
    .expect("write shared oracle source");
    let mut facade_command = Command::new("rustup");
    facade_command.args([
        "run",
        TOOLCHAIN,
        "rustc",
        "--edition=2024",
        "--crate-name",
        "mrml_abi",
        "--crate-type",
        "proc-macro",
    ]);
    #[cfg(target_os = "windows")]
    facade_command
        .arg("-C")
        .arg(format!("linker={}", pinned_rust_lld().display()));
    let facade = facade_command
        .arg(&facade_source)
        .arg("-o")
        .arg(&facade_library)
        .output()
        .expect("compile pinned mrml_abi facade");
    assert!(
        facade.status.success(),
        "{}",
        String::from_utf8_lossy(&facade.stderr)
    );
    let mut oracle_command = Command::new("rustup");
    oracle_command.args(["run", TOOLCHAIN, "rustc", "--edition=2024", "--extern"]);
    oracle_command.arg(format!("mrml_abi={}", facade_library.display()));
    #[cfg(target_os = "windows")]
    oracle_command
        .arg("-C")
        .arg(format!("linker={}", pinned_rust_lld().display()));
    let oracle = oracle_command
        .arg(&shared_source)
        .arg("-o")
        .arg(&executable)
        .output()
        .expect("compile attributed source with pinned rustc");
    assert!(
        oracle.status.success(),
        "{}",
        String::from_utf8_lossy(&oracle.stderr)
    );
    #[cfg(target_os = "windows")]
    fs::copy(
        pinned_rust_lld()
            .parent()
            .expect("pinned rust-lld has a parent")
            .join("libunwind.dll"),
        directory.path().join("libunwind.dll"),
    )
    .expect("stage pinned rustc runtime library");
    let output = Command::new(&executable)
        .output()
        .expect("execute pinned rustc artifact");
    assert!(
        output.status.success(),
        "oracle execution failed with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("oracle output is UTF-8")
        .lines()
        .map(|line| line.parse().expect("oracle output is u64"))
        .collect()
}

#[test]
fn mrml_v1_scalar_facade_executes_with_the_host_call_plan() {
    let code = compile(MRML_V1_SCALAR_SOURCE);
    let probe: unsafe extern "C" fn(u64) -> u64 = unsafe { std::mem::transmute(code.pointer) };
    let actual: Vec<_> = [0, 1, 42, u64::MAX - 17]
        .into_iter()
        .map(|value| unsafe { probe(value) })
        .collect();
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            MRML_V1_SCALAR_SOURCE,
            "for value in [0, 1, 42, u64::MAX - 17] { println!(\"{}\", probe(value)); }",
        )
    );
}

#[test]
fn mrml_v1_scalar_facade_crosses_register_and_stack_arguments() {
    let code = compile(MRML_V1_STACK_SOURCE);
    let probe: unsafe extern "C" fn(u64, u64, u64, u64, u64, u64, u64, u64) -> u64 =
        unsafe { std::mem::transmute(code.pointer) };
    let cases = [
        [0, 0, 0, 0, 0, 0, 0, 0],
        [1, 2, 3, 4, 5, 6, 7, 8],
        [8, 7, 6, 5, 4, 3, 2, 1],
    ];
    let actual: Vec<_> = cases
        .map(|[a, b, c, d, e, f, g, h]| unsafe { probe(a, b, c, d, e, f, g, h) })
        .into_iter()
        .collect();
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            MRML_V1_STACK_SOURCE,
            "for [a, b, c, d, e, f, g, h] in [[0, 0, 0, 0, 0, 0, 0, 0], [1, 2, 3, 4, 5, 6, 7, 8], [8, 7, 6, 5, 4, 3, 2, 1]] { println!(\"{}\", probe(a, b, c, d, e, f, g, h)); }",
        )
    );
}

#[test]
fn mrml_v1_slice_facade_passes_pointer_and_length_words() {
    let code = compile(MRML_V1_SLICE_SOURCE);
    let probe: unsafe extern "C" fn(*const u8, u64) -> u64 =
        unsafe { std::mem::transmute(code.pointer) };
    let empty = [];
    let short = [10, 20, 30];
    let long = [0; 17];
    let actual: Vec<_> = [empty.as_slice(), short.as_slice(), long.as_slice()]
        .map(|input| unsafe { probe(input.as_ptr(), input.len() as u64) })
        .into_iter()
        .collect();
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            MRML_V1_SLICE_SOURCE,
            "for input in [&[][..], &[10, 20, 30][..], &[0; 17][..]] { println!(\"{}\", probe(input)); }",
        )
    );
}

#[test]
fn mrml_v1_slice_facade_reads_bytes_through_the_data_word() {
    let code = compile(MRML_V1_SLICE_CONTENT_SOURCE);
    let probe: unsafe extern "C" fn(*const u8, u64) -> u64 =
        unsafe { std::mem::transmute(code.pointer) };
    let one = [7];
    let short = [10, 20, 30];
    let long = [3, 5, 8, 13, 21, 34, 55];
    let actual: Vec<_> = [one.as_slice(), short.as_slice(), long.as_slice()]
        .map(|input| unsafe { probe(input.as_ptr(), input.len() as u64) })
        .into_iter()
        .collect();
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            MRML_V1_SLICE_CONTENT_SOURCE,
            "for input in [&[7][..], &[10, 20, 30][..], &[3, 5, 8, 13, 21, 34, 55][..]] { println!(\"{}\", probe(input)); }",
        )
    );
}

#[test]
fn mrml_v1_string_facade_reads_utf8_bytes_and_length() {
    let code = compile(MRML_V1_STR_SOURCE);
    let probe: unsafe extern "C" fn(*const u8, u64) -> u64 =
        unsafe { std::mem::transmute(code.pointer) };
    let ascii = "MRML";
    let multibyte = "Möbius";
    let actual: Vec<_> = [ascii, multibyte]
        .map(|input| unsafe { probe(input.as_ptr(), input.len() as u64) })
        .into_iter()
        .collect();
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            MRML_V1_STR_SOURCE,
            "for input in [\"MRML\", \"Möbius\"] { println!(\"{}\", probe(input)); }",
        )
    );
}

#[test]
fn mrml_v1_mutable_slice_facade_writes_through_the_data_word() {
    let code = compile(MRML_V1_MUT_SLICE_SOURCE);
    let probe: unsafe extern "C" fn(*mut u8, u64) -> u64 =
        unsafe { std::mem::transmute(code.pointer) };
    let mut input = [10, 20, 30, 40];
    let returned = unsafe { probe(input.as_mut_ptr(), input.len() as u64) };
    let mut actual = vec![returned];
    actual.extend(input.into_iter().map(u64::from));
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            MRML_V1_MUT_SLICE_SOURCE,
            "let mut input = [10, 20, 30, 40]; println!(\"{}\", probe(&mut input)); for byte in input { println!(\"{}\", byte); }",
        )
    );
}

unsafe fn call_mrml_v1_slice_return(
    function: *const u8,
    input: &[u8],
) -> (*const u8, u64) {
    let returned_pointer: *const u8;
    let returned_length: u64;
    #[cfg(target_os = "windows")]
    unsafe {
        core::arch::asm!(
            "sub rsp, 32",
            "call {function}",
            "add rsp, 32",
            function = in(reg) function,
            in("rcx") input.as_ptr(),
            inlateout("rdx") input.len() as u64 => returned_length,
            lateout("rax") returned_pointer,
            clobber_abi("C"),
        );
    }
    #[cfg(not(target_os = "windows"))]
    unsafe {
        core::arch::asm!(
            "call {function}",
            function = in(reg) function,
            in("rdi") input.as_ptr(),
            in("rsi") input.len() as u64,
            lateout("rax") returned_pointer,
            lateout("rdx") returned_length,
            clobber_abi("C"),
        );
    }
    (returned_pointer, returned_length)
}

#[test]
fn mrml_v1_slice_facade_returns_pointer_and_length_words() {
    let code = compile(MRML_V1_SLICE_RETURN_SOURCE);
    let input = [10, 20, 30, 40, 50];
    let (pointer, length) = unsafe { call_mrml_v1_slice_return(code.pointer, &input) };
    assert_eq!(pointer, input.as_ptr());
    let returned = unsafe { std::slice::from_raw_parts(pointer, length as usize) };
    let actual = vec![length, u64::from(returned[0]), u64::from(returned[length as usize - 1])];
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            MRML_V1_SLICE_RETURN_SOURCE,
            "let input = [10, 20, 30, 40, 50]; let returned = probe(&input); println!(\"{}\", returned.len()); println!(\"{}\", returned[0]); println!(\"{}\", returned[returned.len() - 1]);",
        )
    );
}

unsafe fn call_mrml_v1_mut_slice_return(
    function: *const u8,
    input: &mut [u8],
) -> (*mut u8, u64) {
    let returned_pointer: *mut u8;
    let returned_length: u64;
    #[cfg(target_os = "windows")]
    unsafe {
        core::arch::asm!(
            "sub rsp, 32",
            "call {function}",
            "add rsp, 32",
            function = in(reg) function,
            in("rcx") input.as_mut_ptr(),
            inlateout("rdx") input.len() as u64 => returned_length,
            lateout("rax") returned_pointer,
            clobber_abi("C"),
        );
    }
    #[cfg(not(target_os = "windows"))]
    unsafe {
        core::arch::asm!(
            "call {function}",
            function = in(reg) function,
            in("rdi") input.as_mut_ptr(),
            in("rsi") input.len() as u64,
            lateout("rax") returned_pointer,
            lateout("rdx") returned_length,
            clobber_abi("C"),
        );
    }
    (returned_pointer, returned_length)
}

#[test]
fn mrml_v1_mutable_slice_facade_returns_writable_borrowed_view() {
    let code = compile(MRML_V1_MUT_SLICE_RETURN_SOURCE);
    let mut input = [10, 20, 30, 40];
    let (pointer, length) = unsafe { call_mrml_v1_mut_slice_return(code.pointer, &mut input) };
    assert_eq!(pointer, input.as_mut_ptr());
    let returned = unsafe { std::slice::from_raw_parts_mut(pointer, length as usize) };
    returned[length as usize - 1] += 2;
    let mut actual = vec![length];
    actual.extend(input.into_iter().map(u64::from));
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            MRML_V1_MUT_SLICE_RETURN_SOURCE,
            "let mut input = [10, 20, 30, 40]; let returned = probe(&mut input); let length = returned.len(); returned[length - 1] += 2; println!(\"{}\", length); for byte in input { println!(\"{}\", byte); }",
        )
    );
}

unsafe fn call_mrml_v1_wide_narrow(
    function: *const u8,
    unsigned: u128,
    signed: i128,
) -> u64 {
    let returned: u64;
    #[cfg(target_os = "windows")]
    unsafe {
        core::arch::asm!(
            "sub rsp, 32",
            "call {function}",
            "add rsp, 32",
            function = in(reg) function,
            in("rcx") unsigned as u64,
            in("rdx") (unsigned >> 64) as u64,
            in("r8") signed as u64,
            in("r9") ((signed as u128) >> 64) as u64,
            lateout("rax") returned,
            clobber_abi("C"),
        );
    }
    #[cfg(not(target_os = "windows"))]
    unsafe {
        core::arch::asm!(
            "call {function}",
            function = in(reg) function,
            in("rdi") unsigned as u64,
            in("rsi") (unsigned >> 64) as u64,
            in("rdx") signed as u64,
            in("rcx") ((signed as u128) >> 64) as u64,
            lateout("rax") returned,
            clobber_abi("C"),
        );
    }
    returned
}

#[test]
fn mrml_v1_wide_integer_parameters_narrow_from_the_low_word() {
    let code = compile(MRML_V1_WIDE_NARROW_SOURCE);
    let inputs = [
        (
            0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128,
            0x1020_3040_5060_7080_90a0_b0c0_d0e0_f123u128 as i128,
        ),
        (
            0xfedc_ba98_7654_3210_0123_4567_89ab_cdefu128,
            -0x0102_0304_0506_0708_1112_1314_1516_1718i128,
        ),
    ];
    let actual = inputs
        .map(|(unsigned, signed)| unsafe {
            call_mrml_v1_wide_narrow(code.pointer, unsigned, signed)
        })
        .to_vec();
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            MRML_V1_WIDE_NARROW_SOURCE,
            "for (unsigned, signed) in [(0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128, 0x1020_3040_5060_7080_90a0_b0c0_d0e0_f123u128 as i128), (0xfedc_ba98_7654_3210_0123_4567_89ab_cdefu128, -0x0102_0304_0506_0708_1112_1314_1516_1718i128)] { println!(\"{}\", probe(unsigned, signed)); }",
        )
    );
}

unsafe fn call_mrml_v1_wide_return(function: *const u8, input: u128) -> u128 {
    let returned_low: u64;
    let returned_high: u64;
    #[cfg(target_os = "windows")]
    unsafe {
        core::arch::asm!(
            "sub rsp, 32",
            "call {function}",
            "add rsp, 32",
            function = in(reg) function,
            in("rcx") input as u64,
            inlateout("rdx") (input >> 64) as u64 => returned_high,
            lateout("rax") returned_low,
            clobber_abi("C"),
        );
    }
    #[cfg(not(target_os = "windows"))]
    unsafe {
        core::arch::asm!(
            "call {function}",
            function = in(reg) function,
            in("rdi") input as u64,
            in("rsi") (input >> 64) as u64,
            lateout("rax") returned_low,
            lateout("rdx") returned_high,
            clobber_abi("C"),
        );
    }
    (u128::from(returned_high) << 64) | u128::from(returned_low)
}

unsafe fn call_mrml_v1_wide_with_u32(function: *const u8, input: u128, word: u32) -> u128 {
    let returned_low: u64;
    let returned_high: u64;
    #[cfg(target_os = "windows")]
    unsafe {
        core::arch::asm!(
            "sub rsp, 32",
            "call {function}",
            "add rsp, 32",
            function = in(reg) function,
            in("rcx") input as u64,
            inlateout("rdx") (input >> 64) as u64 => returned_high,
            in("r8") u64::from(word),
            lateout("rax") returned_low,
            clobber_abi("C"),
        );
    }
    #[cfg(not(target_os = "windows"))]
    unsafe {
        core::arch::asm!(
            "call {function}",
            function = in(reg) function,
            in("rdi") input as u64,
            in("rsi") (input >> 64) as u64,
            inlateout("rdx") u64::from(word) => returned_high,
            lateout("rax") returned_low,
            clobber_abi("C"),
        );
    }
    (u128::from(returned_high) << 64) | u128::from(returned_low)
}

unsafe fn call_mrml_v1_two_wide_to_u64(function: *const u8, left: u128, right: u128) -> u64 {
    let returned: u64;
    let discarded: u64;
    #[cfg(target_os = "windows")]
    unsafe {
        core::arch::asm!(
            "sub rsp, 32",
            "call {function}",
            "add rsp, 32",
            function = in(reg) function,
            in("rcx") left as u64,
            inlateout("rdx") (left >> 64) as u64 => discarded,
            in("r8") right as u64,
            in("r9") (right >> 64) as u64,
            lateout("rax") returned,
            clobber_abi("C"),
        );
    }
    #[cfg(not(target_os = "windows"))]
    unsafe {
        core::arch::asm!(
            "call {function}",
            function = in(reg) function,
            in("rdi") left as u64,
            in("rsi") (left >> 64) as u64,
            inlateout("rdx") right as u64 => discarded,
            in("rcx") (right >> 64) as u64,
            lateout("rax") returned,
            clobber_abi("C"),
        );
    }
    let _ = discarded;
    returned
}

unsafe fn call_mrml_v1_two_wide_return(function: *const u8, left: u128, right: u128) -> u128 {
    let returned_low: u64;
    let returned_high: u64;
    #[cfg(target_os = "windows")]
    unsafe {
        core::arch::asm!(
            "sub rsp, 32",
            "call {function}",
            "add rsp, 32",
            function = in(reg) function,
            in("rcx") left as u64,
            inlateout("rdx") (left >> 64) as u64 => returned_high,
            in("r8") right as u64,
            in("r9") (right >> 64) as u64,
            lateout("rax") returned_low,
            clobber_abi("C"),
        );
    }
    #[cfg(not(target_os = "windows"))]
    unsafe {
        core::arch::asm!(
            "call {function}",
            function = in(reg) function,
            in("rdi") left as u64,
            in("rsi") (left >> 64) as u64,
            inlateout("rdx") right as u64 => returned_high,
            in("rcx") (right >> 64) as u64,
            lateout("rax") returned_low,
            clobber_abi("C"),
        );
    }
    (u128::from(returned_high) << 64) | u128::from(returned_low)
}

#[test]
fn mrml_v1_wide_integer_parameters_return_both_words() {
    let code = compile(MRML_V1_WIDE_RETURN_SOURCE);
    let inputs = [
        0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128,
        0xfedc_ba98_7654_3210_0123_4567_89ab_cdefu128,
    ];
    let actual = inputs
        .into_iter()
        .flat_map(|input| {
            let returned = unsafe { call_mrml_v1_wide_return(code.pointer, input) };
            [returned as u64, (returned >> 64) as u64]
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            MRML_V1_WIDE_RETURN_SOURCE,
            "for input in [0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128, 0xfedc_ba98_7654_3210_0123_4567_89ab_cdefu128] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        )
    );
}

#[test]
fn mrml_v1_wide_integer_casts_preserve_both_words() {
    let inputs = [
        0u128,
        1,
        i128::MAX as u128,
        i128::MIN as u128,
        u128::MAX,
        0x0123_4567_89ab_cdef_fedc_ba98_7654_3210,
    ];
    let unsigned_to_signed = compile(MRML_V1_WIDE_UNSIGNED_TO_SIGNED_SOURCE);
    let signed_to_unsigned = compile(MRML_V1_WIDE_SIGNED_TO_UNSIGNED_SOURCE);
    for (source, code, driver) in [
        (
            MRML_V1_WIDE_UNSIGNED_TO_SIGNED_SOURCE,
            &unsigned_to_signed,
            "for input in [0u128, 1, i128::MAX as u128, i128::MIN as u128, u128::MAX, 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }",
        ),
        (
            MRML_V1_WIDE_SIGNED_TO_UNSIGNED_SOURCE,
            &signed_to_unsigned,
            "for input in [0i128, 1, i128::MAX, i128::MIN, -1, 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210i128] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        ),
    ] {
        let actual = inputs
            .into_iter()
            .flat_map(|input| {
                let returned = unsafe { call_mrml_v1_wide_return(code.pointer, input) };
                [returned as u64, (returned >> 64) as u64]
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, rustc_mrml_v1_observations(source, driver));
    }
}

#[test]
fn mrml_v1_wide_integer_not_inverts_both_words() {
    let inputs = [
        0u128,
        1,
        i128::MAX as u128,
        i128::MIN as u128,
        u128::MAX,
        0x0123_4567_89ab_cdef_fedc_ba98_7654_3210,
    ];
    let unsigned = compile(MRML_V1_WIDE_UNSIGNED_NOT_SOURCE);
    let signed = compile(MRML_V1_WIDE_SIGNED_NOT_SOURCE);
    for (source, code, driver) in [
        (
            MRML_V1_WIDE_UNSIGNED_NOT_SOURCE,
            &unsigned,
            "for input in [0u128, 1, i128::MAX as u128, i128::MIN as u128, u128::MAX, 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        ),
        (
            MRML_V1_WIDE_SIGNED_NOT_SOURCE,
            &signed,
            "for input in [0i128, 1, i128::MAX, i128::MIN, -1, 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210i128] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }",
        ),
    ] {
        let actual = inputs
            .into_iter()
            .flat_map(|input| {
                let returned = unsafe { call_mrml_v1_wide_return(code.pointer, input) };
                [returned as u64, (returned >> 64) as u64]
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, rustc_mrml_v1_observations(source, driver));
    }
}

#[test]
fn mrml_v1_wide_signed_negation_matches_both_oracle_words() {
    let code = compile(MRML_V1_WIDE_SIGNED_NEGATE_SOURCE);
    let inputs = [
        0u128,
        1,
        i128::MAX as u128,
        (-1i128) as u128,
        (-0x0123_4567_89ab_cdef_fedc_ba98_7654_3210i128) as u128,
    ];
    let actual = inputs
        .into_iter()
        .flat_map(|input| {
            let returned = unsafe { call_mrml_v1_wide_return(code.pointer, input) };
            [returned as u64, (returned >> 64) as u64]
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            MRML_V1_WIDE_SIGNED_NEGATE_SOURCE,
            "for input in [0i128, 1, i128::MAX, -1, -0x0123_4567_89ab_cdef_fedc_ba98_7654_3210i128] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }",
        )
    );
}

#[test]
fn mrml_v1_wide_bitwise_operations_match_both_oracle_words() {
    let inputs = [
        0u128,
        1,
        i128::MAX as u128,
        i128::MIN as u128,
        u128::MAX,
        0x0123_4567_89ab_cdef_fedc_ba98_7654_3210,
    ];
    let driver = "for input in [0u128, 1, i128::MAX as u128, i128::MIN as u128, u128::MAX, 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }";
    for source in [
        MRML_V1_WIDE_BITAND_SOURCE,
        MRML_V1_WIDE_BITOR_SOURCE,
        MRML_V1_WIDE_BITXOR_SOURCE,
    ] {
        let code = compile(source);
        let actual = inputs
            .into_iter()
            .flat_map(|input| {
                let returned = unsafe { call_mrml_v1_wide_return(code.pointer, input) };
                [returned as u64, (returned >> 64) as u64]
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, rustc_mrml_v1_observations(source, driver));
    }
}

#[test]
fn mrml_v1_wide_checked_addition_matches_both_oracle_words() {
    let unsigned = compile(MRML_V1_WIDE_UNSIGNED_ADD_SOURCE);
    let signed = compile(MRML_V1_WIDE_SIGNED_ADD_SOURCE);
    let unsigned_inputs = [
        0u128,
        1,
        u64::MAX as u128,
        (u64::MAX as u128) << 64,
        u128::MAX - 17,
    ];
    let signed_inputs = [
        0u128,
        1,
        i128::MIN as u128,
        (-1i128) as u128,
        (i128::MAX - 17) as u128,
    ];
    for (source, code, inputs, driver) in [
        (
            MRML_V1_WIDE_UNSIGNED_ADD_SOURCE,
            &unsigned,
            unsigned_inputs,
            "for input in [0u128, 1, u64::MAX as u128, (u64::MAX as u128) << 64, u128::MAX - 17] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        ),
        (
            MRML_V1_WIDE_SIGNED_ADD_SOURCE,
            &signed,
            signed_inputs,
            "for input in [0i128, 1, i128::MIN, -1, i128::MAX - 17] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }",
        ),
    ] {
        let actual = inputs
            .into_iter()
            .flat_map(|input| {
                let returned = unsafe { call_mrml_v1_wide_return(code.pointer, input) };
                [returned as u64, (returned >> 64) as u64]
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, rustc_mrml_v1_observations(source, driver));
    }
}

#[test]
fn mrml_v1_wide_checked_subtraction_matches_both_oracle_words() {
    let unsigned = compile(MRML_V1_WIDE_UNSIGNED_SUBTRACT_SOURCE);
    let signed = compile(MRML_V1_WIDE_SIGNED_SUBTRACT_SOURCE);
    let unsigned_inputs = [
        17u128,
        18,
        u64::MAX as u128,
        (u64::MAX as u128) << 64,
        u128::MAX,
    ];
    let signed_inputs = [
        17u128,
        18,
        (i128::MIN + 17) as u128,
        (-1i128) as u128,
        i128::MAX as u128,
    ];
    for (source, code, inputs, driver) in [
        (
            MRML_V1_WIDE_UNSIGNED_SUBTRACT_SOURCE,
            &unsigned,
            unsigned_inputs,
            "for input in [17u128, 18, u64::MAX as u128, (u64::MAX as u128) << 64, u128::MAX] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        ),
        (
            MRML_V1_WIDE_SIGNED_SUBTRACT_SOURCE,
            &signed,
            signed_inputs,
            "for input in [17i128, 18, i128::MIN + 17, -1, i128::MAX] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }",
        ),
    ] {
        let actual = inputs
            .into_iter()
            .flat_map(|input| {
                let returned = unsafe { call_mrml_v1_wide_return(code.pointer, input) };
                [returned as u64, (returned >> 64) as u64]
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, rustc_mrml_v1_observations(source, driver));
    }
}

#[test]
fn mrml_v1_wide_wrapping_addition_and_subtraction_match_both_oracle_words() {
    for (source, inputs, driver) in [
        (
            MRML_V1_WIDE_UNSIGNED_WRAPPING_ADD_SOURCE,
            [0u128, 1, u64::MAX as u128, u128::MAX - 16, u128::MAX],
            "for input in [0u128, 1, u64::MAX as u128, u128::MAX - 16, u128::MAX] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        ),
        (
            MRML_V1_WIDE_SIGNED_WRAPPING_SUBTRACT_SOURCE,
            [0u128, 17, i128::MIN as u128, (-1i128) as u128, i128::MAX as u128],
            "for input in [0i128, 17, i128::MIN, -1, i128::MAX] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }",
        ),
    ] {
        let code = compile(source);
        let actual = inputs
            .into_iter()
            .flat_map(|input| {
                let returned = unsafe { call_mrml_v1_wide_return(code.pointer, input) };
                [returned as u64, (returned >> 64) as u64]
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, rustc_mrml_v1_observations(source, driver));
    }
}

#[test]
fn mrml_v1_wide_wrapping_multiplication_matches_both_oracle_words() {
    for (source, inputs, driver) in [
        (
            MRML_V1_WIDE_UNSIGNED_WRAPPING_MULTIPLY_SOURCE,
            [0u128, 1, u64::MAX as u128, u128::MAX / 17 + 1, u128::MAX],
            "for input in [0u128, 1, u64::MAX as u128, u128::MAX / 17 + 1, u128::MAX] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        ),
        (
            MRML_V1_WIDE_SIGNED_WRAPPING_MULTIPLY_SOURCE,
            [0u128, 1, (-1i128) as u128, i128::MIN as u128, i128::MAX as u128],
            "for input in [0i128, 1, -1, i128::MIN, i128::MAX] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }",
        ),
    ] {
        let code = compile(source);
        let actual = inputs
            .into_iter()
            .flat_map(|input| {
                let returned = unsafe { call_mrml_v1_wide_return(code.pointer, input) };
                [returned as u64, (returned >> 64) as u64]
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, rustc_mrml_v1_observations(source, driver));
    }
}

#[test]
fn mrml_v1_wide_wrapping_negation_matches_both_oracle_words() {
    for (source, inputs, driver) in [
        (
            MRML_V1_WIDE_UNSIGNED_WRAPPING_NEGATE_SOURCE,
            [0u128, 1, u64::MAX as u128, 1u128 << 127, u128::MAX],
            "for input in [0u128, 1, u64::MAX as u128, 1u128 << 127, u128::MAX] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        ),
        (
            MRML_V1_WIDE_SIGNED_WRAPPING_NEGATE_SOURCE,
            [0u128, 1, (-1i128) as u128, i128::MIN as u128, i128::MAX as u128],
            "for input in [0i128, 1, -1, i128::MIN, i128::MAX] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }",
        ),
    ] {
        let code = compile(source);
        let actual = inputs
            .into_iter()
            .flat_map(|input| {
                let returned = unsafe { call_mrml_v1_wide_return(code.pointer, input) };
                [returned as u64, (returned >> 64) as u64]
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, rustc_mrml_v1_observations(source, driver));
    }
}

#[test]
fn mrml_v1_wide_wrapping_absolute_value_matches_both_oracle_words() {
    let source = MRML_V1_WIDE_SIGNED_WRAPPING_ABSOLUTE_SOURCE;
    let inputs = [0u128, 1, (-1i128) as u128, i128::MIN as u128, i128::MAX as u128];
    let code = compile(source);
    let actual = inputs
        .into_iter()
        .flat_map(|input| {
            let returned = unsafe { call_mrml_v1_wide_return(code.pointer, input) };
            [returned as u64, (returned >> 64) as u64]
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            source,
            "for input in [0i128, 1, -1, i128::MIN, i128::MAX] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }",
        )
    );
}

#[test]
fn mrml_v1_wide_saturating_unary_operations_match_both_oracle_words() {
    let inputs = [0u128, 1, (-1i128) as u128, i128::MIN as u128, i128::MAX as u128];
    let driver = "for input in [0i128, 1, -1, i128::MIN, i128::MAX] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }";
    for source in [
        MRML_V1_WIDE_SIGNED_SATURATING_NEGATE_SOURCE,
        MRML_V1_WIDE_SIGNED_SATURATING_ABSOLUTE_SOURCE,
    ] {
        let code = compile(source);
        let actual = inputs
            .into_iter()
            .flat_map(|input| {
                let returned = unsafe { call_mrml_v1_wide_return(code.pointer, input) };
                [returned as u64, (returned >> 64) as u64]
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, rustc_mrml_v1_observations(source, driver));
    }
}

#[test]
fn mrml_v1_wide_saturating_addition_matches_both_oracle_words() {
    for (source, inputs, driver) in [
        (
            MRML_V1_WIDE_UNSIGNED_SATURATING_ADD_SOURCE,
            [0u128, 1, u64::MAX as u128, u128::MAX - 17, u128::MAX],
            "for input in [0u128, 1, u64::MAX as u128, u128::MAX - 17, u128::MAX] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        ),
        (
            MRML_V1_WIDE_SIGNED_SATURATING_ADD_SOURCE,
            [0u128, 1, i128::MIN as u128, (i128::MAX - 17) as u128, i128::MAX as u128],
            "for input in [0i128, 1, i128::MIN, i128::MAX - 17, i128::MAX] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }",
        ),
    ] {
        let code = compile(source);
        let actual = inputs
            .into_iter()
            .flat_map(|input| {
                let returned = unsafe { call_mrml_v1_wide_return(code.pointer, input) };
                [returned as u64, (returned >> 64) as u64]
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, rustc_mrml_v1_observations(source, driver));
    }
}

#[test]
fn mrml_v1_wide_saturating_subtraction_matches_both_oracle_words() {
    for (source, inputs, driver) in [
        (
            MRML_V1_WIDE_UNSIGNED_SATURATING_SUBTRACT_SOURCE,
            [0u128, 16, 17, u64::MAX as u128, u128::MAX],
            "for input in [0u128, 16, 17, u64::MAX as u128, u128::MAX] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        ),
        (
            MRML_V1_WIDE_SIGNED_SATURATING_SUBTRACT_SOURCE,
            [0u128, 17, i128::MIN as u128, (i128::MIN + 17) as u128, i128::MAX as u128],
            "for input in [0i128, 17, i128::MIN, i128::MIN + 17, i128::MAX] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }",
        ),
    ] {
        let code = compile(source);
        let actual = inputs
            .into_iter()
            .flat_map(|input| {
                let returned = unsafe { call_mrml_v1_wide_return(code.pointer, input) };
                [returned as u64, (returned >> 64) as u64]
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, rustc_mrml_v1_observations(source, driver));
    }
}

#[test]
fn mrml_v1_wide_rotations_match_both_oracle_words() {
    let distances = [0u32, 1, 63, 64, 65, 127, 128, 129, 255];
    for (source, input, driver) in [
        (
            MRML_V1_WIDE_UNSIGNED_ROTATE_LEFT_SOURCE,
            1512366075204170947332355369683137040u128,
            "for distance in [0u32, 1, 63, 64, 65, 127, 128, 129, 255] { let returned = probe(1512366075204170947332355369683137040u128, distance); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        ),
        (
            MRML_V1_WIDE_SIGNED_ROTATE_RIGHT_SOURCE,
            (-1512366075204170947332355369683137040i128) as u128,
            "for distance in [0u32, 1, 63, 64, 65, 127, 128, 129, 255] { let returned = probe(-1512366075204170947332355369683137040i128, distance); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }",
        ),
    ] {
        let code = compile(source);
        let actual = distances
            .into_iter()
            .flat_map(|distance| {
                let returned = unsafe { call_mrml_v1_wide_with_u32(code.pointer, input, distance) };
                [returned as u64, (returned >> 64) as u64]
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, rustc_mrml_v1_observations(source, driver));
    }
}

#[test]
fn mrml_v1_wide_byte_order_transforms_match_both_oracle_words() {
    let inputs = [
        0u128,
        1,
        0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128,
        1u128 << 127,
        u128::MAX,
    ];
    for (source, signed) in [
        (MRML_V1_WIDE_UNSIGNED_SWAP_BYTES_SOURCE, false),
        (MRML_V1_WIDE_SIGNED_TO_BIG_ENDIAN_SOURCE, true),
        (MRML_V1_WIDE_UNSIGNED_TO_LITTLE_ENDIAN_SOURCE, false),
        (MRML_V1_WIDE_SIGNED_REVERSE_BITS_SOURCE, true),
    ] {
        let code = compile(source);
        let actual = inputs
            .into_iter()
            .flat_map(|input| {
                let returned = unsafe { call_mrml_v1_wide_return(code.pointer, input) };
                [returned as u64, (returned >> 64) as u64]
            })
            .collect::<Vec<_>>();
        let driver = if signed {
            "for input in [0u128, 1, 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128, 1u128 << 127, u128::MAX] { let returned = probe(input as i128); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }"
        } else {
            "for input in [0u128, 1, 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128, 1u128 << 127, u128::MAX] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }"
        };
        assert_eq!(actual, rustc_mrml_v1_observations(source, driver));
    }
}

#[test]
fn mrml_v1_wide_bit_isolation_matches_both_oracle_words() {
    let inputs = [
        0u128,
        1,
        0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128,
        1u128 << 127,
        u128::MAX,
    ];
    for (source, signed) in [
        (MRML_V1_WIDE_UNSIGNED_ISOLATE_HIGHEST_SOURCE, false),
        (MRML_V1_WIDE_SIGNED_ISOLATE_LOWEST_SOURCE, true),
    ] {
        let code = compile(source);
        let actual = inputs
            .into_iter()
            .flat_map(|input| {
                let returned = unsafe { call_mrml_v1_wide_return(code.pointer, input) };
                [returned as u64, (returned >> 64) as u64]
            })
            .collect::<Vec<_>>();
        let driver = if signed {
            "for input in [0u128, 1, 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128, 1u128 << 127, u128::MAX] { let returned = probe(input as i128); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }"
        } else {
            "for input in [0u128, 1, 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128, 1u128 << 127, u128::MAX] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }"
        };
        assert_eq!(actual, rustc_mrml_v1_observations(source, driver));
    }
}

#[test]
fn mrml_v1_wide_population_counts_match_the_oracle() {
    let inputs = [
        0u128,
        1,
        0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128,
        1u128 << 127,
        u128::MAX,
    ];
    for (source, signed) in [
        (MRML_V1_WIDE_UNSIGNED_BIT_WIDTH_SOURCE, false),
        (MRML_V1_WIDE_UNSIGNED_COUNT_ONES_SOURCE, false),
        (MRML_V1_WIDE_SIGNED_COUNT_ZEROS_SOURCE, true),
        (MRML_V1_WIDE_UNSIGNED_LEADING_ZEROS_SOURCE, false),
        (MRML_V1_WIDE_SIGNED_TRAILING_ZEROS_SOURCE, true),
        (MRML_V1_WIDE_UNSIGNED_LEADING_ONES_SOURCE, false),
        (MRML_V1_WIDE_SIGNED_TRAILING_ONES_SOURCE, true),
    ] {
        let code = compile(source);
        let actual = inputs
            .into_iter()
            .map(|input| unsafe { call_mrml_v1_wide_return(code.pointer, input) as u64 })
            .collect::<Vec<_>>();
        let driver = if signed {
            "for input in [0u128, 1, 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128, 1u128 << 127, u128::MAX] { println!(\"{}\", probe(input as i128)); }"
        } else {
            "for input in [0u128, 1, 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128, 1u128 << 127, u128::MAX] { println!(\"{}\", probe(input)); }"
        };
        assert_eq!(actual, rustc_mrml_v1_observations(source, driver));
    }
}

#[test]
fn mrml_v1_wide_next_powers_of_two_match_both_oracle_words() {
    for (source, inputs) in [
        (
            MRML_V1_WIDE_UNSIGNED_NEXT_POWER_SOURCE,
            [0u128, 1, 3, (1u128 << 64) + 1, 1u128 << 127],
        ),
        (
            MRML_V1_WIDE_UNSIGNED_WRAPPING_NEXT_POWER_SOURCE,
            [0u128, 1, 3, (1u128 << 127) + 1, u128::MAX],
        ),
    ] {
        let code = compile(source);
        let actual = inputs
            .into_iter()
            .flat_map(|input| {
                let returned = unsafe { call_mrml_v1_wide_return(code.pointer, input) };
                [returned as u64, (returned >> 64) as u64]
            })
            .collect::<Vec<_>>();
        let driver = if source == MRML_V1_WIDE_UNSIGNED_NEXT_POWER_SOURCE {
            "for input in [0u128, 1, 3, (1u128 << 64) + 1, 1u128 << 127] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }"
        } else {
            "for input in [0u128, 1, 3, (1u128 << 127) + 1, u128::MAX] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }"
        };
        let oracle_source = if source == MRML_V1_WIDE_UNSIGNED_WRAPPING_NEXT_POWER_SOURCE {
            RUSTC_WIDE_UNSIGNED_WRAPPING_NEXT_POWER_SOURCE
        } else {
            source
        };
        assert_eq!(actual, rustc_mrml_v1_observations(oracle_source, driver));
    }
}

#[test]
fn mrml_v1_wide_next_power_of_two_overflow_traps() {
    #[cfg(target_os = "windows")]
    const CHILD: &str = "MRML_SEMANTIC_WIDE_NEXT_POWER_OVERFLOW_CHILD";
    let code = compile(MRML_V1_WIDE_UNSIGNED_NEXT_POWER_SOURCE);

    #[cfg(not(target_os = "windows"))]
    {
        let pid = unsafe { fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let _ = unsafe { call_mrml_v1_wide_return(code.pointer, (1u128 << 127) + 1) };
            unsafe { _exit(120) }
        }
        let mut status = 0;
        assert_eq!(unsafe { waitpid(pid, &mut status, 0) }, pid, "waitpid failed");
        assert_eq!(status & 0x7f, 4, "unexpected Unix wait status: {status:#x}");
        return;
    }

    #[cfg(target_os = "windows")]
    if std::env::var_os(CHILD).is_some() {
        unsafe { SetErrorMode(0x0001 | 0x0002) };
        let _ = unsafe { call_mrml_v1_wide_return(code.pointer, (1u128 << 127) + 1) };
        panic!("checked wide next-power overflow unexpectedly returned");
    }

    #[cfg(target_os = "windows")]
    let output = Command::new(std::env::current_exe().expect("locate semantic test binary"))
        .args([
            "--exact",
            "mrml_v1_wide_next_power_of_two_overflow_traps",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .output()
        .expect("launch isolated wide next-power trap probe");
    #[cfg(target_os = "windows")]
    {
        assert!(!output.status.success(), "generated next-power trap unexpectedly returned");
        assert_eq!(output.status.code(), Some(101));
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 child test stdout");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 child test stderr");
        assert!(
            stdout.contains("unexpected return code -1073741795")
                || stderr.contains("unexpected return code -1073741795"),
            "missing Windows illegal-instruction status; stdout: {stdout}; stderr: {stderr}"
        );
    }
}

#[test]
fn mrml_v1_wide_signed_signum_matches_both_oracle_words() {
    let source = MRML_V1_WIDE_SIGNED_SIGNUM_SOURCE;
    let code = compile(source);
    let inputs = [i128::MIN, -1, 0, 1, i128::MAX];
    let actual = inputs
        .into_iter()
        .flat_map(|input| {
            let returned = unsafe { call_mrml_v1_wide_return(code.pointer, input as u128) };
            [returned as u64, (returned >> 64) as u64]
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            source,
            "for input in [i128::MIN, -1, 0, 1, i128::MAX] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }",
        )
    );
}

#[test]
fn mrml_v1_wide_absolute_values_match_both_oracle_words() {
    let inputs = [0u128, 1, (-1i128) as u128, i128::MAX as u128, (-17i128) as u128];
    for (source, oracle_source, unsigned_result) in [
        (
            MRML_V1_WIDE_SIGNED_ABSOLUTE_SOURCE,
            MRML_V1_WIDE_SIGNED_ABSOLUTE_SOURCE,
            false,
        ),
        (
            MRML_V1_WIDE_SIGNED_STRICT_ABSOLUTE_SOURCE,
            RUSTC_WIDE_SIGNED_STRICT_ABSOLUTE_SOURCE,
            false,
        ),
        (
            MRML_V1_WIDE_SIGNED_UNSIGNED_ABSOLUTE_SOURCE,
            MRML_V1_WIDE_SIGNED_UNSIGNED_ABSOLUTE_SOURCE,
            true,
        ),
    ] {
        let code = compile(source);
        let actual = inputs
            .into_iter()
            .flat_map(|input| {
                let returned = unsafe { call_mrml_v1_wide_return(code.pointer, input) };
                [returned as u64, (returned >> 64) as u64]
            })
            .collect::<Vec<_>>();
        let driver = if unsigned_result {
            "for input in [0i128, 1, -1, i128::MAX, -17] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }"
        } else {
            "for input in [0i128, 1, -1, i128::MAX, -17] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }"
        };
        assert_eq!(actual, rustc_mrml_v1_observations(oracle_source, driver));
    }
}

#[test]
fn mrml_v1_wide_absolute_value_overflows_trap() {
    #[cfg(target_os = "windows")]
    const CHILD: &str = "MRML_SEMANTIC_WIDE_ABSOLUTE_OVERFLOW_CHILD";

    #[cfg(not(target_os = "windows"))]
    for source in [
        MRML_V1_WIDE_SIGNED_ABSOLUTE_SOURCE,
        MRML_V1_WIDE_SIGNED_STRICT_ABSOLUTE_SOURCE,
    ] {
        let code = compile(source);
        let pid = unsafe { fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let _ = unsafe { call_mrml_v1_wide_return(code.pointer, i128::MIN as u128) };
            unsafe { _exit(120) }
        }
        let mut status = 0;
        assert_eq!(unsafe { waitpid(pid, &mut status, 0) }, pid, "waitpid failed");
        assert_eq!(status & 0x7f, 4, "unexpected Unix wait status: {status:#x}");
    }

    #[cfg(target_os = "windows")]
    if let Some(mode) = std::env::var_os(CHILD) {
        unsafe { SetErrorMode(0x0001 | 0x0002) };
        let source = if mode == "strict" {
            MRML_V1_WIDE_SIGNED_STRICT_ABSOLUTE_SOURCE
        } else {
            MRML_V1_WIDE_SIGNED_ABSOLUTE_SOURCE
        };
        let code = compile(source);
        let _ = unsafe { call_mrml_v1_wide_return(code.pointer, i128::MIN as u128) };
        panic!("wide absolute-value overflow unexpectedly returned");
    }

    #[cfg(target_os = "windows")]
    for mode in ["checked", "strict"] {
        let output = Command::new(std::env::current_exe().expect("locate semantic test binary"))
            .args([
                "--exact",
                "mrml_v1_wide_absolute_value_overflows_trap",
                "--nocapture",
            ])
            .env(CHILD, mode)
            .output()
            .expect("launch isolated wide absolute-value trap probe");
        assert!(!output.status.success(), "generated absolute-value trap returned");
        assert_eq!(output.status.code(), Some(101));
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 child test stdout");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 child test stderr");
        assert!(
            stdout.contains("unexpected return code -1073741795")
                || stderr.contains("unexpected return code -1073741795"),
            "missing Windows illegal-instruction status for {mode}; stdout: {stdout}; stderr: {stderr}"
        );
    }
}

#[test]
fn mrml_v1_wide_strict_negation_matches_both_oracle_words() {
    for (source, oracle_source, inputs, driver) in [
        (
            MRML_V1_WIDE_UNSIGNED_STRICT_NEGATE_SOURCE,
            RUSTC_WIDE_UNSIGNED_STRICT_NEGATE_SOURCE,
            [0u128, 0, 0, 0, 0],
            "for input in [0u128, 0, 0, 0, 0] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        ),
        (
            MRML_V1_WIDE_SIGNED_STRICT_NEGATE_SOURCE,
            RUSTC_WIDE_SIGNED_STRICT_NEGATE_SOURCE,
            [0u128, 1, (-1i128) as u128, 17, (-17i128) as u128],
            "for input in [0i128, 1, -1, 17, -17] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }",
        ),
    ] {
        let code = compile(source);
        let actual = inputs
            .into_iter()
            .flat_map(|input| {
                let returned = unsafe { call_mrml_v1_wide_return(code.pointer, input) };
                [returned as u64, (returned >> 64) as u64]
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, rustc_mrml_v1_observations(oracle_source, driver));
    }
}

#[test]
fn mrml_v1_wide_strict_negation_overflows_trap() {
    #[cfg(target_os = "windows")]
    const CHILD: &str = "MRML_SEMANTIC_WIDE_STRICT_NEGATE_OVERFLOW_CHILD";

    #[cfg(not(target_os = "windows"))]
    for (source, input) in [
        (MRML_V1_WIDE_UNSIGNED_STRICT_NEGATE_SOURCE, 1u128),
        (MRML_V1_WIDE_SIGNED_STRICT_NEGATE_SOURCE, i128::MIN as u128),
    ] {
        let code = compile(source);
        let pid = unsafe { fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let _ = unsafe { call_mrml_v1_wide_return(code.pointer, input) };
            unsafe { _exit(120) }
        }
        let mut status = 0;
        assert_eq!(unsafe { waitpid(pid, &mut status, 0) }, pid, "waitpid failed");
        assert_eq!(status & 0x7f, 4, "unexpected Unix wait status: {status:#x}");
    }

    #[cfg(target_os = "windows")]
    if let Some(mode) = std::env::var_os(CHILD) {
        unsafe { SetErrorMode(0x0001 | 0x0002) };
        let (source, input) = if mode == "signed" {
            (MRML_V1_WIDE_SIGNED_STRICT_NEGATE_SOURCE, i128::MIN as u128)
        } else {
            (MRML_V1_WIDE_UNSIGNED_STRICT_NEGATE_SOURCE, 1u128)
        };
        let code = compile(source);
        let _ = unsafe { call_mrml_v1_wide_return(code.pointer, input) };
        panic!("wide strict-negation overflow unexpectedly returned");
    }

    #[cfg(target_os = "windows")]
    for mode in ["unsigned", "signed"] {
        let output = Command::new(std::env::current_exe().expect("locate semantic test binary"))
            .args([
                "--exact",
                "mrml_v1_wide_strict_negation_overflows_trap",
                "--nocapture",
            ])
            .env(CHILD, mode)
            .output()
            .expect("launch isolated wide strict-negation trap probe");
        assert!(!output.status.success(), "generated strict-negation trap returned");
        assert_eq!(output.status.code(), Some(101));
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 child test stdout");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 child test stderr");
        assert!(
            stdout.contains("unexpected return code -1073741795")
                || stderr.contains("unexpected return code -1073741795"),
            "missing Windows illegal-instruction status for {mode}; stdout: {stdout}; stderr: {stderr}"
        );
    }
}

#[test]
fn mrml_v1_wide_shift_methods_match_both_oracle_words() {
    let input = (-1512366075204170947332355369683137040i128) as u128;
    for (source, oracle_source, distances) in [
        (
            MRML_V1_WIDE_UNSIGNED_WRAPPING_SHIFT_LEFT_SOURCE,
            MRML_V1_WIDE_UNSIGNED_WRAPPING_SHIFT_LEFT_SOURCE,
            [0u32, 63, 64, 127, 128, u32::MAX],
        ),
        (
            MRML_V1_WIDE_SIGNED_STRICT_SHIFT_RIGHT_SOURCE,
            RUSTC_WIDE_SIGNED_STRICT_SHIFT_RIGHT_SOURCE,
            [0u32, 1, 63, 64, 65, 127],
        ),
        (
            MRML_V1_WIDE_SIGNED_UNBOUNDED_SHIFT_RIGHT_SOURCE,
            RUSTC_WIDE_SIGNED_UNBOUNDED_SHIFT_RIGHT_SOURCE,
            [0u32, 63, 64, 127, 128, u32::MAX],
        ),
    ] {
        let code = compile(source);
        let actual = distances
            .into_iter()
            .flat_map(|distance| {
                let returned = unsafe { call_mrml_v1_wide_with_u32(code.pointer, input, distance) };
                [returned as u64, (returned >> 64) as u64]
            })
            .collect::<Vec<_>>();
        let driver = if source == MRML_V1_WIDE_SIGNED_STRICT_SHIFT_RIGHT_SOURCE {
            "for distance in [0u32, 1, 63, 64, 65, 127] { let returned = probe(-1512366075204170947332355369683137040i128, distance); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }"
        } else if source == MRML_V1_WIDE_SIGNED_UNBOUNDED_SHIFT_RIGHT_SOURCE {
            "for distance in [0u32, 63, 64, 127, 128, u32::MAX] { let returned = probe(-1512366075204170947332355369683137040i128, distance); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }"
        } else {
            "for distance in [0u32, 63, 64, 127, 128, u32::MAX] { let returned = probe((-1512366075204170947332355369683137040i128) as u128, distance); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }"
        };
        assert_eq!(actual, rustc_mrml_v1_observations(oracle_source, driver));
    }
}

#[test]
fn mrml_v1_wide_strict_shift_distances_trap() {
    #[cfg(target_os = "windows")]
    const CHILD: &str = "MRML_SEMANTIC_WIDE_STRICT_SHIFT_CHILD";
    let code = compile(MRML_V1_WIDE_SIGNED_STRICT_SHIFT_RIGHT_SOURCE);

    #[cfg(not(target_os = "windows"))]
    for distance in [128u32, u32::MAX] {
        let pid = unsafe { fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let _ = unsafe { call_mrml_v1_wide_with_u32(code.pointer, (-17i128) as u128, distance) };
            unsafe { _exit(120) }
        }
        let mut status = 0;
        assert_eq!(unsafe { waitpid(pid, &mut status, 0) }, pid, "waitpid failed");
        assert_eq!(status & 0x7f, 4, "unexpected Unix wait status: {status:#x}");
    }

    #[cfg(target_os = "windows")]
    if let Some(mode) = std::env::var_os(CHILD) {
        unsafe { SetErrorMode(0x0001 | 0x0002) };
        let distance = if mode == "maximum" { u32::MAX } else { 128 };
        let _ = unsafe { call_mrml_v1_wide_with_u32(code.pointer, (-17i128) as u128, distance) };
        panic!("wide strict-shift overflow unexpectedly returned");
    }

    #[cfg(target_os = "windows")]
    for mode in ["width", "maximum"] {
        let output = Command::new(std::env::current_exe().expect("locate semantic test binary"))
            .args([
                "--exact",
                "mrml_v1_wide_strict_shift_distances_trap",
                "--nocapture",
            ])
            .env(CHILD, mode)
            .output()
            .expect("launch isolated wide strict-shift trap probe");
        assert!(!output.status.success(), "generated strict-shift trap returned");
        assert_eq!(output.status.code(), Some(101));
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 child test stdout");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 child test stderr");
        assert!(
            stdout.contains("unexpected return code -1073741795")
                || stderr.contains("unexpected return code -1073741795"),
            "missing Windows illegal-instruction status for {mode}; stdout: {stdout}; stderr: {stderr}"
        );
    }
}

#[test]
fn mrml_v1_wide_power_of_two_predicate_matches_the_oracle() {
    let source = MRML_V1_WIDE_UNSIGNED_POWER_OF_TWO_SOURCE;
    let code = compile(source);
    let inputs = [
        0u128,
        1,
        3,
        1u128 << 63,
        1u128 << 64,
        (1u128 << 64) + 1,
        1u128 << 127,
        u128::MAX,
    ];
    let actual = inputs
        .into_iter()
        .map(|input| unsafe { call_mrml_v1_wide_return(code.pointer, input) as u64 })
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            source,
            "for input in [0u128, 1, 3, 1u128 << 63, 1u128 << 64, (1u128 << 64) + 1, 1u128 << 127, u128::MAX] { println!(\"{}\", probe(input)); }",
        )
    );
}

#[test]
fn mrml_v1_wide_multiple_predicate_matches_the_oracle() {
    let source = MRML_V1_WIDE_UNSIGNED_IS_MULTIPLE_SOURCE;
    let code = compile(source);
    let inputs = [
        (0u128, 0u128),
        (1, 0),
        (0, 17),
        ((1u128 << 64) + 1, (1u128 << 64) + 1),
        (u128::MAX, 257),
        (u128::MAX - 1, 257),
    ];
    let actual = inputs
        .into_iter()
        .map(|(input, divisor)| unsafe {
            call_mrml_v1_two_wide_to_u64(code.pointer, input, divisor)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            source,
            "for (input, divisor) in [(0u128, 0u128), (1, 0), (0, 17), ((1u128 << 64) + 1, (1u128 << 64) + 1), (u128::MAX, 257), (u128::MAX - 1, 257)] { println!(\"{}\", probe(input, divisor)); }",
        )
    );
}

#[test]
fn mrml_v1_wide_unsigned_midpoints_match_both_oracle_words() {
    let source = MRML_V1_WIDE_UNSIGNED_MIDPOINT_SOURCE;
    let code = compile(source);
    let inputs = [
        (0u128, 0u128),
        (0, 1),
        (1, 2),
        (u64::MAX as u128, (u64::MAX as u128) + 1),
        (1u128 << 127, u128::MAX),
        (0, u128::MAX),
    ];
    let actual = inputs
        .into_iter()
        .flat_map(|(left, right)| {
            let returned = unsafe { call_mrml_v1_two_wide_return(code.pointer, left, right) };
            [returned as u64, (returned >> 64) as u64]
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            source,
            "for (left, right) in [(0u128, 0u128), (0, 1), (1, 2), (u64::MAX as u128, (u64::MAX as u128) + 1), (1u128 << 127, u128::MAX), (0, u128::MAX)] { let returned = probe(left, right); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        )
    );
}

#[test]
fn mrml_v1_wide_signed_midpoints_match_both_oracle_words() {
    let source = MRML_V1_WIDE_SIGNED_MIDPOINT_SOURCE;
    let code = compile(source);
    let inputs = [
        (i128::MIN, i128::MAX),
        (-2, -1),
        (-1, 0),
        (0, 1),
        (1, 2),
        (i128::MAX - 1, i128::MAX),
    ];
    let actual = inputs
        .into_iter()
        .flat_map(|(left, right)| {
            let returned = unsafe {
                call_mrml_v1_two_wide_return(code.pointer, left as u128, right as u128)
            };
            [returned as u64, (returned >> 64) as u64]
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            source,
            "for (left, right) in [(i128::MIN, i128::MAX), (-2, -1), (-1, 0), (0, 1), (1, 2), (i128::MAX - 1, i128::MAX)] { let returned = probe(left, right); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }",
        )
    );
}

#[test]
fn mrml_v1_wide_minima_and_maxima_match_both_oracle_words() {
    let inputs = [
        (0u128, 0u128),
        (1, 2),
        (u64::MAX as u128, (u64::MAX as u128) + 1),
        (i128::MIN as u128, i128::MAX as u128),
        (u128::MAX, 0),
    ];
    for (source, signed) in [
        (MRML_V1_WIDE_UNSIGNED_MINIMUM_SOURCE, false),
        (MRML_V1_WIDE_UNSIGNED_MAXIMUM_SOURCE, false),
        (MRML_V1_WIDE_SIGNED_MINIMUM_SOURCE, true),
        (MRML_V1_WIDE_SIGNED_MAXIMUM_SOURCE, true),
    ] {
        let code = compile(source);
        let actual = inputs
            .into_iter()
            .flat_map(|(left, right)| {
                let returned = unsafe { call_mrml_v1_two_wide_return(code.pointer, left, right) };
                [returned as u64, (returned >> 64) as u64]
            })
            .collect::<Vec<_>>();
        let driver = if signed {
            "for (left, right) in [(0i128, 0i128), (1, 2), (u64::MAX as i128, (u64::MAX as i128) + 1), (i128::MIN, i128::MAX), (-1, 0)] { let returned = probe(left, right); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }"
        } else {
            "for (left, right) in [(0u128, 0u128), (1, 2), (u64::MAX as u128, (u64::MAX as u128) + 1), (i128::MIN as u128, i128::MAX as u128), (u128::MAX, 0)] { let returned = probe(left, right); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }"
        };
        assert_eq!(actual, rustc_mrml_v1_observations(source, driver));
    }
}

#[test]
fn mrml_v1_wide_absolute_differences_match_both_oracle_words() {
    let inputs = [
        (0u128, 0u128),
        (1, 2),
        (2, 1),
        (u64::MAX as u128, (u64::MAX as u128) + 1),
        (i128::MIN as u128, i128::MAX as u128),
        (u128::MAX, 0),
    ];
    for (source, signed) in [
        (MRML_V1_WIDE_UNSIGNED_ABSOLUTE_DIFFERENCE_SOURCE, false),
        (MRML_V1_WIDE_SIGNED_ABSOLUTE_DIFFERENCE_SOURCE, true),
    ] {
        let code = compile(source);
        let actual = inputs
            .into_iter()
            .flat_map(|(left, right)| {
                let returned = unsafe { call_mrml_v1_two_wide_return(code.pointer, left, right) };
                [returned as u64, (returned >> 64) as u64]
            })
            .collect::<Vec<_>>();
        let driver = if signed {
            "for (left, right) in [(0i128, 0i128), (1, 2), (2, 1), (u64::MAX as i128, (u64::MAX as i128) + 1), (i128::MIN, i128::MAX), (-1, 0)] { let returned = probe(left, right); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }"
        } else {
            "for (left, right) in [(0u128, 0u128), (1, 2), (2, 1), (u64::MAX as u128, (u64::MAX as u128) + 1), (i128::MIN as u128, i128::MAX as u128), (u128::MAX, 0)] { let returned = probe(left, right); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }"
        };
        assert_eq!(actual, rustc_mrml_v1_observations(source, driver));
    }
}

#[test]
fn mrml_v1_wide_signed_sign_predicates_match_the_oracle() {
    let inputs = [i128::MIN, -1, 0, 1, i128::MAX];
    for source in [
        MRML_V1_WIDE_SIGNED_IS_POSITIVE_SOURCE,
        MRML_V1_WIDE_SIGNED_IS_NEGATIVE_SOURCE,
    ] {
        let code = compile(source);
        let actual = inputs
            .into_iter()
            .map(|input| unsafe { call_mrml_v1_wide_return(code.pointer, input as u128) as u64 })
            .collect::<Vec<_>>();
        let driver =
            "for input in [i128::MIN, -1, 0, 1, i128::MAX] { println!(\"{}\", probe(input)); }";
        assert_eq!(actual, rustc_mrml_v1_observations(source, driver));
    }
}

#[test]
fn mrml_v1_wide_wrapping_division_and_remainder_match_both_oracle_words() {
    let inputs = [0u128, 1, (-1i128) as u128, i128::MIN as u128, i128::MAX as u128];
    for (source, driver) in [
        (
            MRML_V1_WIDE_SIGNED_WRAPPING_DIVIDE_SOURCE,
            "for input in [0i128, 1, -1, i128::MIN, i128::MAX] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }",
        ),
        (
            MRML_V1_WIDE_SIGNED_WRAPPING_REMAINDER_SOURCE,
            "for input in [0i128, 1, -1, i128::MIN, i128::MAX] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }",
        ),
    ] {
        let code = compile(source);
        let actual = inputs
            .into_iter()
            .flat_map(|input| {
                let returned = unsafe { call_mrml_v1_wide_return(code.pointer, input) };
                [returned as u64, (returned >> 64) as u64]
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, rustc_mrml_v1_observations(source, driver));
    }
}

#[test]
fn mrml_v1_wide_equality_matches_the_oracle() {
    let equal = compile(MRML_V1_WIDE_UNSIGNED_EQUAL_SOURCE);
    let not_equal = compile(MRML_V1_WIDE_SIGNED_NOT_EQUAL_SOURCE);
    let inputs = [
        0u128,
        1512366075204170947332355369683137040,
        1512366075204170947332355369683137041,
        (-1512366075204170947332355369683137040i128) as u128,
        u128::MAX,
    ];
    for (source, code, driver) in [
        (
            MRML_V1_WIDE_UNSIGNED_EQUAL_SOURCE,
            &equal,
            "for input in [0u128, 1512366075204170947332355369683137040, 1512366075204170947332355369683137041, (-1512366075204170947332355369683137040i128) as u128, u128::MAX] { println!(\"{}\", probe(input)); }",
        ),
        (
            MRML_V1_WIDE_SIGNED_NOT_EQUAL_SOURCE,
            &not_equal,
            "for input in [0i128, 1512366075204170947332355369683137040, 1512366075204170947332355369683137041, -1512366075204170947332355369683137040i128, -1] { println!(\"{}\", probe(input)); }",
        ),
    ] {
        let actual = inputs
            .into_iter()
            .map(|input| unsafe { call_mrml_v1_wide_return(code.pointer, input) as u64 })
            .collect::<Vec<_>>();
        assert_eq!(actual, rustc_mrml_v1_observations(source, driver));
    }
}

#[test]
fn mrml_v1_wide_ordering_matches_the_oracle() {
    let unsigned = compile(MRML_V1_WIDE_UNSIGNED_LESS_SOURCE);
    let signed = compile(MRML_V1_WIDE_SIGNED_GREATER_EQUAL_SOURCE);
    let unsigned_inputs = [
        0u128,
        1512366075204170947332355369683137039,
        1512366075204170947332355369683137040,
        1512366075204170947332355369683137041,
        u128::MAX,
    ];
    let signed_inputs = [
        0u128,
        (-1512366075204170947332355369683137041i128) as u128,
        (-1512366075204170947332355369683137040i128) as u128,
        (-1512366075204170947332355369683137039i128) as u128,
        (-1i128) as u128,
    ];
    for (source, code, inputs, driver) in [
        (
            MRML_V1_WIDE_UNSIGNED_LESS_SOURCE,
            &unsigned,
            unsigned_inputs,
            "for input in [0u128, 1512366075204170947332355369683137039, 1512366075204170947332355369683137040, 1512366075204170947332355369683137041, u128::MAX] { println!(\"{}\", probe(input)); }",
        ),
        (
            MRML_V1_WIDE_SIGNED_GREATER_EQUAL_SOURCE,
            &signed,
            signed_inputs,
            "for input in [0i128, -1512366075204170947332355369683137041, -1512366075204170947332355369683137040, -1512366075204170947332355369683137039, -1] { println!(\"{}\", probe(input)); }",
        ),
    ] {
        let actual = inputs
            .into_iter()
            .map(|input| unsafe { call_mrml_v1_wide_return(code.pointer, input) as u64 })
            .collect::<Vec<_>>();
        assert_eq!(actual, rustc_mrml_v1_observations(source, driver));
    }
}

#[test]
fn mrml_v1_wide_checked_unsigned_multiplication_matches_both_oracle_words() {
    let code = compile(MRML_V1_WIDE_UNSIGNED_MULTIPLY_SOURCE);
    let inputs = [
        0u128,
        1,
        17,
        (u64::MAX - 1) as u128,
        u64::MAX as u128,
    ];
    let actual = inputs
        .into_iter()
        .flat_map(|input| {
            let returned = unsafe { call_mrml_v1_wide_return(code.pointer, input) };
            [returned as u64, (returned >> 64) as u64]
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            MRML_V1_WIDE_UNSIGNED_MULTIPLY_SOURCE,
            "for input in [0u128, 1, 17, (u64::MAX - 1) as u128, u64::MAX as u128] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        )
    );
}

#[test]
fn mrml_v1_wide_checked_signed_multiplication_matches_both_oracle_words() {
    let code = compile(MRML_V1_WIDE_SIGNED_MULTIPLY_SOURCE);
    let inputs = [
        0i128,
        1,
        -1,
        i128::MAX / 17,
        i128::MIN / 17,
    ];
    let actual = inputs
        .into_iter()
        .flat_map(|input| {
            let returned = unsafe { call_mrml_v1_wide_return(code.pointer, input as u128) };
            [returned as u64, (returned >> 64) as u64]
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            MRML_V1_WIDE_SIGNED_MULTIPLY_SOURCE,
            "for input in [0i128, 1, -1, i128::MAX / 17, i128::MIN / 17] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }",
        )
    );
}

#[test]
fn mrml_v1_wide_unsigned_multiplication_overflow_traps() {
    #[cfg(target_os = "windows")]
    const CHILD: &str = "MRML_SEMANTIC_WIDE_MULTIPLY_OVERFLOW_CHILD";
    let code = compile(MRML_V1_WIDE_UNSIGNED_MULTIPLY_SOURCE);

    #[cfg(not(target_os = "windows"))]
    {
        let pid = unsafe { fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let _ = unsafe { call_mrml_v1_wide_return(code.pointer, 1u128 << 64) };
            unsafe { _exit(120) }
        }
        let mut status = 0;
        assert_eq!(unsafe { waitpid(pid, &mut status, 0) }, pid, "waitpid failed");
        assert_eq!(status & 0x7f, 4, "unexpected Unix wait status: {status:#x}");
        return;
    }

    #[cfg(target_os = "windows")]
    if std::env::var_os(CHILD).is_some() {
        unsafe { SetErrorMode(0x0001 | 0x0002) };
        let _ = unsafe { call_mrml_v1_wide_return(code.pointer, 1u128 << 64) };
        panic!("checked wide multiplication overflow unexpectedly returned");
    }

    #[cfg(target_os = "windows")]
    let output = Command::new(std::env::current_exe().expect("locate semantic test binary"))
        .args([
            "--exact",
            "mrml_v1_wide_unsigned_multiplication_overflow_traps",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .output()
        .expect("launch isolated wide multiplication trap probe");
    #[cfg(target_os = "windows")]
    {
        assert!(!output.status.success(), "generated overflow trap unexpectedly returned");
        assert_eq!(output.status.code(), Some(101));
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 child test stdout");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 child test stderr");
        assert!(
            stdout.contains("unexpected return code -1073741795")
                || stderr.contains("unexpected return code -1073741795"),
            "missing Windows illegal-instruction status; stdout: {stdout}; stderr: {stderr}"
        );
    }
}

#[test]
fn mrml_v1_wide_signed_multiplication_overflow_traps() {
    #[cfg(target_os = "windows")]
    const CHILD: &str = "MRML_SEMANTIC_SIGNED_WIDE_MULTIPLY_OVERFLOW_CHILD";
    let code = compile(MRML_V1_WIDE_SIGNED_MULTIPLY_OVERFLOW_SOURCE);

    #[cfg(not(target_os = "windows"))]
    {
        let pid = unsafe { fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let _ = unsafe { call_mrml_v1_wide_return(code.pointer, i128::MIN as u128) };
            unsafe { _exit(120) }
        }
        let mut status = 0;
        assert_eq!(unsafe { waitpid(pid, &mut status, 0) }, pid, "waitpid failed");
        assert_eq!(status & 0x7f, 4, "unexpected Unix wait status: {status:#x}");
        return;
    }

    #[cfg(target_os = "windows")]
    if std::env::var_os(CHILD).is_some() {
        unsafe { SetErrorMode(0x0001 | 0x0002) };
        let _ = unsafe { call_mrml_v1_wide_return(code.pointer, i128::MIN as u128) };
        panic!("checked signed wide multiplication overflow unexpectedly returned");
    }

    #[cfg(target_os = "windows")]
    let output = Command::new(std::env::current_exe().expect("locate semantic test binary"))
        .args([
            "--exact",
            "mrml_v1_wide_signed_multiplication_overflow_traps",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .output()
        .expect("launch isolated signed wide multiplication trap probe");
    #[cfg(target_os = "windows")]
    {
        assert!(!output.status.success(), "generated overflow trap unexpectedly returned");
        assert_eq!(output.status.code(), Some(101));
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 child test stdout");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 child test stderr");
        assert!(
            stdout.contains("unexpected return code -1073741795")
                || stderr.contains("unexpected return code -1073741795"),
            "missing Windows illegal-instruction status; stdout: {stdout}; stderr: {stderr}"
        );
    }
}

#[test]
fn mrml_v1_wide_shifts_match_both_oracle_words() {
    let left = compile(MRML_V1_WIDE_UNSIGNED_SHIFT_LEFT_SOURCE);
    let unsigned_right = compile(MRML_V1_WIDE_UNSIGNED_SHIFT_RIGHT_SOURCE);
    let signed_right = compile(MRML_V1_WIDE_SIGNED_SHIFT_RIGHT_SOURCE);
    let input = 1512366075204170947332355369683137040u128;
    let shifts = [0u32, 1, 63, 64, 65, 127];
    for (source, code, driver) in [
        (
            MRML_V1_WIDE_UNSIGNED_SHIFT_LEFT_SOURCE,
            &left,
            "for shift in [0u32, 1, 63, 64, 65, 127] { let returned = probe(1512366075204170947332355369683137040u128, shift); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        ),
        (
            MRML_V1_WIDE_UNSIGNED_SHIFT_RIGHT_SOURCE,
            &unsigned_right,
            "for shift in [0u32, 1, 63, 64, 65, 127] { let returned = probe(1512366075204170947332355369683137040u128, shift); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        ),
        (
            MRML_V1_WIDE_SIGNED_SHIFT_RIGHT_SOURCE,
            &signed_right,
            "for shift in [0u32, 1, 63, 64, 65, 127] { let returned = probe(-1512366075204170947332355369683137040i128, shift); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }",
        ),
    ] {
        let input = if source == MRML_V1_WIDE_SIGNED_SHIFT_RIGHT_SOURCE {
            (-1512366075204170947332355369683137040i128) as u128
        } else {
            input
        };
        let actual = shifts
            .into_iter()
            .flat_map(|shift| {
                let returned = unsafe { call_mrml_v1_wide_with_u32(code.pointer, input, shift) };
                [returned as u64, (returned >> 64) as u64]
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, rustc_mrml_v1_observations(source, driver));
    }
}

#[test]
fn mrml_v1_wide_shift_count_overflow_traps() {
    #[cfg(target_os = "windows")]
    const CHILD: &str = "MRML_SEMANTIC_WIDE_SHIFT_OVERFLOW_CHILD";
    let code = compile(MRML_V1_WIDE_UNSIGNED_SHIFT_LEFT_SOURCE);

    #[cfg(not(target_os = "windows"))]
    {
        let pid = unsafe { fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let _ = unsafe { call_mrml_v1_wide_with_u32(code.pointer, 1, 128) };
            unsafe { _exit(120) }
        }
        let mut status = 0;
        assert_eq!(unsafe { waitpid(pid, &mut status, 0) }, pid, "waitpid failed");
        assert_eq!(status & 0x7f, 4, "unexpected Unix wait status: {status:#x}");
        return;
    }

    #[cfg(target_os = "windows")]
    if std::env::var_os(CHILD).is_some() {
        unsafe { SetErrorMode(0x0001 | 0x0002) };
        let _ = unsafe { call_mrml_v1_wide_with_u32(code.pointer, 1, 128) };
        panic!("checked wide shift count overflow unexpectedly returned");
    }

    #[cfg(target_os = "windows")]
    let output = Command::new(std::env::current_exe().expect("locate semantic test binary"))
        .args([
            "--exact",
            "mrml_v1_wide_shift_count_overflow_traps",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .output()
        .expect("launch isolated wide shift trap probe");
    #[cfg(target_os = "windows")]
    {
        assert!(!output.status.success(), "generated shift trap unexpectedly returned");
        assert_eq!(output.status.code(), Some(101));
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 child test stdout");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 child test stderr");
        assert!(
            stdout.contains("unexpected return code -1073741795")
                || stderr.contains("unexpected return code -1073741795"),
            "missing Windows illegal-instruction status; stdout: {stdout}; stderr: {stderr}"
        );
    }
}

#[test]
fn mrml_v1_wide_unsigned_division_and_remainder_match_both_oracle_words() {
    let quotient = compile(MRML_V1_WIDE_UNSIGNED_DIVIDE_SOURCE);
    let remainder = compile(MRML_V1_WIDE_UNSIGNED_REMAINDER_SOURCE);
    let divisor = 18446744073709551617u128;
    let inputs = [0u128, 1, divisor - 1, divisor, divisor + 1, u128::MAX];
    for (source, code, driver) in [
        (
            MRML_V1_WIDE_UNSIGNED_DIVIDE_SOURCE,
            &quotient,
            "for input in [0u128, 1, 18446744073709551616, 18446744073709551617, 18446744073709551618, u128::MAX] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        ),
        (
            MRML_V1_WIDE_UNSIGNED_REMAINDER_SOURCE,
            &remainder,
            "for input in [0u128, 1, 18446744073709551616, 18446744073709551617, 18446744073709551618, u128::MAX] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        ),
    ] {
        let actual = inputs
            .into_iter()
            .flat_map(|input| {
                let returned = unsafe { call_mrml_v1_wide_return(code.pointer, input) };
                [returned as u64, (returned >> 64) as u64]
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, rustc_mrml_v1_observations(source, driver));
    }
}

#[test]
fn mrml_v1_wide_zero_divisors_trap() {
    #[cfg(target_os = "windows")]
    const CHILD: &str = "MRML_SEMANTIC_WIDE_ZERO_DIVISOR_CHILD";
    let sources = [
        MRML_V1_WIDE_UNSIGNED_ZERO_DIVISOR_SOURCE,
        MRML_V1_WIDE_UNSIGNED_WRAPPING_ZERO_DIVISOR_SOURCE,
    ];

    #[cfg(not(target_os = "windows"))]
    {
        for source in sources {
            let code = compile(source);
            let pid = unsafe { fork() };
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                let _ = unsafe { call_mrml_v1_wide_return(code.pointer, u128::MAX) };
                unsafe { _exit(120) }
            }
            let mut status = 0;
            assert_eq!(unsafe { waitpid(pid, &mut status, 0) }, pid, "waitpid failed");
            assert_eq!(status & 0x7f, 4, "unexpected Unix wait status: {status:#x}");
        }
        return;
    }

    #[cfg(target_os = "windows")]
    if let Some(index) = std::env::var_os(CHILD) {
        let index = index.to_string_lossy().parse::<usize>().expect("child source index");
        let code = compile(sources[index]);
        unsafe { SetErrorMode(0x0001 | 0x0002) };
        let _ = unsafe { call_mrml_v1_wide_return(code.pointer, u128::MAX) };
        panic!("wide division by zero unexpectedly returned");
    }

    #[cfg(target_os = "windows")]
    for index in 0..sources.len() {
        let output = Command::new(std::env::current_exe().expect("locate semantic test binary"))
            .args(["--exact", "mrml_v1_wide_zero_divisors_trap", "--nocapture"])
            .env(CHILD, index.to_string())
            .output()
            .expect("launch isolated wide zero-divisor trap probe");
        assert!(!output.status.success(), "zero-divisor trap unexpectedly returned");
        assert_eq!(output.status.code(), Some(101));
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 child test stdout");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 child test stderr");
        assert!(
            stdout.contains("unexpected return code -1073741795")
                || stderr.contains("unexpected return code -1073741795"),
            "missing Windows illegal-instruction status; stdout: {stdout}; stderr: {stderr}"
        );
    }
}

#[test]
fn mrml_v1_wide_signed_division_and_remainder_match_both_oracle_words() {
    let quotient = compile(MRML_V1_WIDE_SIGNED_DIVIDE_SOURCE);
    let remainder = compile(MRML_V1_WIDE_SIGNED_REMAINDER_SOURCE);
    let inputs = [0i128, 1, -1, 17, -17, i128::MAX, i128::MIN];
    for (source, code, driver) in [
        (
            MRML_V1_WIDE_SIGNED_DIVIDE_SOURCE,
            &quotient,
            "for input in [0i128, 1, -1, 17, -17, i128::MAX, i128::MIN] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }",
        ),
        (
            MRML_V1_WIDE_SIGNED_REMAINDER_SOURCE,
            &remainder,
            "for input in [0i128, 1, -1, 17, -17, i128::MAX, i128::MIN] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }",
        ),
    ] {
        let actual = inputs
            .into_iter()
            .flat_map(|input| {
                let returned =
                    unsafe { call_mrml_v1_wide_return(code.pointer, input as u128) };
                [returned as u64, (returned >> 64) as u64]
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, rustc_mrml_v1_observations(source, driver));
    }
}

#[test]
fn mrml_v1_wide_signed_division_overflow_traps_for_both_operators() {
    #[cfg(target_os = "windows")]
    const CHILD: &str = "MRML_SEMANTIC_SIGNED_WIDE_DIVISION_OVERFLOW_CHILD";
    let divide = compile(MRML_V1_WIDE_SIGNED_DIVIDE_OVERFLOW_SOURCE);
    let remainder = compile(MRML_V1_WIDE_SIGNED_REMAINDER_OVERFLOW_SOURCE);

    #[cfg(not(target_os = "windows"))]
    for code in [&divide, &remainder] {
        let pid = unsafe { fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let _ = unsafe { call_mrml_v1_wide_return(code.pointer, i128::MIN as u128) };
            unsafe { _exit(120) }
        }
        let mut status = 0;
        assert_eq!(unsafe { waitpid(pid, &mut status, 0) }, pid, "waitpid failed");
        assert_eq!(status & 0x7f, 4, "unexpected Unix wait status: {status:#x}");
    }

    #[cfg(not(target_os = "windows"))]
    return;

    #[cfg(target_os = "windows")]
    if let Some(case) = std::env::var_os(CHILD) {
        unsafe { SetErrorMode(0x0001 | 0x0002) };
        let code = if case == "divide" { &divide } else { &remainder };
        let _ = unsafe { call_mrml_v1_wide_return(code.pointer, i128::MIN as u128) };
        panic!("signed wide division overflow unexpectedly returned");
    }

    #[cfg(target_os = "windows")]
    for case in ["divide", "remainder"] {
        let output = Command::new(std::env::current_exe().expect("locate semantic test binary"))
            .args([
                "--exact",
                "mrml_v1_wide_signed_division_overflow_traps_for_both_operators",
                "--nocapture",
            ])
            .env(CHILD, case)
            .output()
            .expect("launch isolated signed wide division trap probe");
        assert!(!output.status.success(), "{case} overflow trap unexpectedly returned");
        assert_eq!(output.status.code(), Some(101));
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 child test stdout");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 child test stderr");
        assert!(
            stdout.contains("unexpected return code -1073741795")
                || stderr.contains("unexpected return code -1073741795"),
            "missing Windows {case} illegal-instruction status; stdout: {stdout}; stderr: {stderr}"
        );
    }
}

#[test]
fn mrml_v1_wide_conditional_returns_match_both_oracle_words() {
    let code = compile(MRML_V1_WIDE_CONDITIONAL_SOURCE);
    let inputs = [0u128, 1, u64::MAX as u128, u128::MAX - 17];
    let mut actual = Vec::new();
    for input in inputs {
        for choose in [false, true] {
            let returned = unsafe {
                call_mrml_v1_wide_with_u32(code.pointer, input, u32::from(choose))
            };
            actual.extend([returned as u64, (returned >> 64) as u64]);
        }
    }
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            MRML_V1_WIDE_CONDITIONAL_SOURCE,
            "for input in [0u128, 1, u64::MAX as u128, u128::MAX - 17] { for choose in [false, true] { let returned = probe(input, choose); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); } }",
        )
    );
}

#[test]
fn mrml_v1_wide_block_sequence_returns_match_oracle_words() {
    let code = compile(MRML_V1_WIDE_SEQUENCE_SOURCE);
    let inputs = [0u128, 1, u64::MAX as u128, u128::MAX - 17];
    let actual = inputs
        .into_iter()
        .flat_map(|input| {
            let returned = unsafe { call_mrml_v1_wide_with_u32(code.pointer, input, 0) };
            [returned as u64, (returned >> 64) as u64]
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            MRML_V1_WIDE_SEQUENCE_SOURCE,
            "for input in [0u128, 1, u64::MAX as u128, u128::MAX - 17] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        )
    );
}

#[test]
fn mrml_v1_wide_local_returns_match_oracle_words() {
    let code = compile(MRML_V1_WIDE_LOCAL_SOURCE);
    let inputs = [0u128, 1, u64::MAX as u128, u128::MAX - 17];
    let actual = inputs
        .into_iter()
        .flat_map(|input| {
            let returned = unsafe { call_mrml_v1_wide_with_u32(code.pointer, input, 0) };
            [returned as u64, (returned >> 64) as u64]
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            MRML_V1_WIDE_LOCAL_SOURCE,
            "for input in [0u128, 1, u64::MAX as u128, u128::MAX - 17] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        )
    );
}

#[test]
fn mrml_v1_wide_local_assignment_matches_oracle_words() {
    let code = compile(MRML_V1_WIDE_ASSIGN_SOURCE);
    let inputs = [0u128, 1, u64::MAX as u128, u128::MAX - 17];
    let actual = inputs
        .into_iter()
        .flat_map(|input| {
            let returned = unsafe { call_mrml_v1_wide_with_u32(code.pointer, input, 0) };
            [returned as u64, (returned >> 64) as u64]
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            MRML_V1_WIDE_ASSIGN_SOURCE,
            "for input in [0u128, 1, u64::MAX as u128, u128::MAX - 17] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        )
    );
}

#[test]
fn mrml_v1_discarded_wide_expression_matches_oracle_words() {
    let code = compile(MRML_V1_WIDE_DISCARD_SOURCE);
    let inputs = [0u128, 1, u64::MAX as u128, u128::MAX - 17];
    let actual = inputs
        .into_iter()
        .flat_map(|input| {
            let returned = unsafe { call_mrml_v1_wide_with_u32(code.pointer, input, 0) };
            [returned as u64, (returned >> 64) as u64]
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            MRML_V1_WIDE_DISCARD_SOURCE,
            "for input in [0u128, 1, u64::MAX as u128, u128::MAX - 17] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        )
    );
}

#[test]
fn mrml_v1_wide_compound_assignments_match_oracle_words() {
    let code = compile(MRML_V1_WIDE_COMPOUND_SOURCE);
    let inputs = [0u128, 1, u64::MAX as u128, 1u128 << 96];
    let actual = inputs
        .into_iter()
        .flat_map(|input| {
            let returned = unsafe { call_mrml_v1_wide_with_u32(code.pointer, input, 0) };
            [returned as u64, (returned >> 64) as u64]
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            MRML_V1_WIDE_COMPOUND_SOURCE,
            "for input in [0u128, 1, u64::MAX as u128, 1u128 << 96] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        )
    );
}

#[test]
fn mrml_v1_wide_helper_call_matches_oracle_words() {
    let code = compile(MRML_V1_WIDE_HELPER_SOURCE);
    let inputs = [0u128, 1, u64::MAX as u128, u128::MAX - 17];
    let actual = inputs
        .into_iter()
        .flat_map(|input| {
            let returned = unsafe { call_mrml_v1_wide_with_u32(code.pointer, input, 0) };
            [returned as u64, (returned >> 64) as u64]
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            MRML_V1_WIDE_HELPER_SOURCE,
            "for input in [0u128, 1, u64::MAX as u128, u128::MAX - 17] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        )
    );
}

#[test]
fn mrml_v1_wide_helper_early_return_matches_oracle_words() {
    let code = compile(MRML_V1_WIDE_HELPER_RETURN_SOURCE);
    let inputs = [0u128, 1, u64::MAX as u128, u128::MAX - 17];
    let mut actual = Vec::new();
    for input in inputs {
        for early in [false, true] {
            let returned = unsafe {
                call_mrml_v1_wide_with_u32(code.pointer, input, u32::from(early))
            };
            actual.extend([returned as u64, (returned >> 64) as u64]);
        }
    }
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            MRML_V1_WIDE_HELPER_RETURN_SOURCE,
            "for input in [0u128, 1, u64::MAX as u128, u128::MAX - 17] { for early in [false, true] { let returned = probe(input, early); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); } }",
        )
    );
}

#[test]
fn mrml_v1_wide_multiply_assignments_match_oracle_words() {
    let unsigned = compile(MRML_V1_WIDE_UNSIGNED_MULTIPLY_ASSIGN_SOURCE);
    let unsigned_inputs = [0u128, 1, u32::MAX as u128, u64::MAX as u128];
    let actual_unsigned = unsigned_inputs
        .into_iter()
        .flat_map(|input| {
            let returned = unsafe { call_mrml_v1_wide_with_u32(unsigned.pointer, input, 0) };
            [returned as u64, (returned >> 64) as u64]
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual_unsigned,
        rustc_mrml_v1_observations(
            MRML_V1_WIDE_UNSIGNED_MULTIPLY_ASSIGN_SOURCE,
            "for input in [0u128, 1, u32::MAX as u128, u64::MAX as u128] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        )
    );

    let signed = compile(MRML_V1_WIDE_SIGNED_MULTIPLY_ASSIGN_SOURCE);
    let signed_inputs = [-1i128, 0, 1, i64::MIN as i128, i64::MAX as i128];
    let actual_signed = signed_inputs
        .into_iter()
        .flat_map(|input| {
            let returned = unsafe {
                call_mrml_v1_wide_with_u32(signed.pointer, input as u128, 0)
            };
            [returned as u64, (returned >> 64) as u64]
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual_signed,
        rustc_mrml_v1_observations(
            MRML_V1_WIDE_SIGNED_MULTIPLY_ASSIGN_SOURCE,
            "for input in [-1i128, 0, 1, i64::MIN as i128, i64::MAX as i128] { let returned = probe(input) as u128; println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        )
    );
}

#[test]
fn mrml_v1_wide_divide_and_remainder_assignments_match_oracle_words() {
    let unsigned = compile(MRML_V1_WIDE_UNSIGNED_DIVIDE_ASSIGN_SOURCE);
    let unsigned_inputs = [0u128, 1, u64::MAX as u128, u128::MAX];
    let actual_unsigned = unsigned_inputs
        .into_iter()
        .flat_map(|input| {
            let returned = unsafe { call_mrml_v1_wide_with_u32(unsigned.pointer, input, 0) };
            [returned as u64, (returned >> 64) as u64]
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual_unsigned,
        rustc_mrml_v1_observations(
            MRML_V1_WIDE_UNSIGNED_DIVIDE_ASSIGN_SOURCE,
            "for input in [0u128, 1, u64::MAX as u128, u128::MAX] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        )
    );

    let signed = compile(MRML_V1_WIDE_SIGNED_DIVIDE_ASSIGN_SOURCE);
    let signed_inputs = [i128::MIN, -17, -1, 0, 1, 17, i128::MAX];
    let actual_signed = signed_inputs
        .into_iter()
        .flat_map(|input| {
            let returned = unsafe {
                call_mrml_v1_wide_with_u32(signed.pointer, input as u128, 0)
            };
            [returned as u64, (returned >> 64) as u64]
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual_signed,
        rustc_mrml_v1_observations(
            MRML_V1_WIDE_SIGNED_DIVIDE_ASSIGN_SOURCE,
            "for input in [i128::MIN, -17, -1, 0, 1, 17, i128::MAX] { let returned = probe(input) as u128; println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        )
    );
}

#[test]
fn mrml_v1_wide_shift_assignments_match_oracle_words() {
    let unsigned = compile(MRML_V1_WIDE_UNSIGNED_SHIFT_ASSIGN_SOURCE);
    let unsigned_input = 1512366075204170947332355369683137040u128;
    let shifts = [0u32, 1, 63, 64, 65, 127];
    let actual_unsigned = shifts
        .into_iter()
        .flat_map(|shift| {
            let returned = unsafe {
                call_mrml_v1_wide_with_u32(unsigned.pointer, unsigned_input, shift)
            };
            [returned as u64, (returned >> 64) as u64]
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual_unsigned,
        rustc_mrml_v1_observations(
            MRML_V1_WIDE_UNSIGNED_SHIFT_ASSIGN_SOURCE,
            "for shift in [0u32, 1, 63, 64, 65, 127] { let returned = probe(1512366075204170947332355369683137040u128, shift); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }",
        )
    );

    let signed = compile(MRML_V1_WIDE_SIGNED_SHIFT_ASSIGN_SOURCE);
    let signed_input = -1512366075204170947332355369683137040i128;
    let actual_signed = shifts
        .into_iter()
        .flat_map(|shift| {
            let returned = unsafe {
                call_mrml_v1_wide_with_u32(signed.pointer, signed_input as u128, shift)
            };
            [returned as u64, (returned >> 64) as u64]
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual_signed,
        rustc_mrml_v1_observations(
            MRML_V1_WIDE_SIGNED_SHIFT_ASSIGN_SOURCE,
            "for shift in [0u32, 1, 63, 64, 65, 127] { let returned = probe(-1512366075204170947332355369683137040i128, shift); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }",
        )
    );
}

#[test]
fn mrml_v1_wide_named_constants_match_oracle_words() {
    for source in [
        MRML_V1_WIDE_UNSIGNED_CONSTANT_SOURCE,
        MRML_V1_WIDE_SIGNED_CONSTANT_SOURCE,
    ] {
        let code = compile(source);
        let returned = unsafe { call_mrml_v1_wide_return(code.pointer, 0) };
        let actual = vec![returned as u64, (returned >> 64) as u64];
        assert_eq!(
            actual,
            rustc_mrml_v1_observations(
                source,
                "let returned = probe() as u128; println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64);",
            )
        );
    }
}

#[test]
fn mrml_v1_wide_const_calls_match_oracle_words() {
    for source in [
        MRML_V1_WIDE_UNSIGNED_CONST_CALL_SOURCE,
        MRML_V1_WIDE_SIGNED_CONST_CALL_SOURCE,
        MRML_V1_WIDE_UNSIGNED_NESTED_CONST_CALL_SOURCE,
        MRML_V1_WIDE_SIGNED_NESTED_CONST_CALL_SOURCE,
        MRML_V1_WIDE_UNSIGNED_UNARY_CONST_CALL_SOURCE,
        MRML_V1_WIDE_SIGNED_UNARY_CONST_CALL_SOURCE,
        MRML_V1_WIDE_UNSIGNED_BITWISE_CONST_CALL_SOURCE,
        MRML_V1_WIDE_SIGNED_BITWISE_CONST_CALL_SOURCE,
        MRML_V1_WIDE_UNSIGNED_ARITHMETIC_CONST_CALL_SOURCE,
        MRML_V1_WIDE_SIGNED_ARITHMETIC_CONST_CALL_SOURCE,
        MRML_V1_WIDE_UNSIGNED_MULTIPLY_CONST_CALL_SOURCE,
        MRML_V1_WIDE_SIGNED_MULTIPLY_CONST_CALL_SOURCE,
        MRML_V1_WIDE_UNSIGNED_DIVIDE_CONST_CALL_SOURCE,
        MRML_V1_WIDE_SIGNED_DIVIDE_CONST_CALL_SOURCE,
        MRML_V1_WIDE_UNSIGNED_SHIFT_CONST_CALL_SOURCE,
        MRML_V1_WIDE_SIGNED_SHIFT_CONST_CALL_SOURCE,
        MRML_V1_WIDE_UNSIGNED_CONDITIONAL_CONST_CALL_SOURCE,
        MRML_V1_WIDE_SIGNED_CONDITIONAL_CONST_CALL_SOURCE,
        MRML_V1_WIDE_UNSIGNED_SEQUENCE_CONST_CALL_SOURCE,
        MRML_V1_WIDE_SIGNED_SEQUENCE_CONST_CALL_SOURCE,
        MRML_V1_WIDE_UNSIGNED_CAST_CONST_CALL_SOURCE,
        MRML_V1_WIDE_SIGNED_CAST_CONST_CALL_SOURCE,
        MRML_V1_WIDE_UNSIGNED_INLINE_CONST_CALL_SOURCE,
        MRML_V1_WIDE_SIGNED_INLINE_CONST_CALL_SOURCE,
        MRML_V1_WIDE_UNSIGNED_COMPARE_CONST_CALL_SOURCE,
        MRML_V1_WIDE_SIGNED_COMPARE_CONST_CALL_SOURCE,
        MRML_V1_WIDE_UNSIGNED_LOGICAL_CONST_CALL_SOURCE,
        MRML_V1_WIDE_SIGNED_LOGICAL_CONST_CALL_SOURCE,
        MRML_V1_WIDE_UNSIGNED_MULTI_ARGUMENT_CONST_CALL_SOURCE,
        MRML_V1_WIDE_SIGNED_MULTI_ARGUMENT_CONST_CALL_SOURCE,
    ] {
        let code = compile(source);
        let returned = unsafe { call_mrml_v1_wide_return(code.pointer, 0) };
        let actual = vec![returned as u64, (returned >> 64) as u64];
        assert_eq!(
            actual,
            rustc_mrml_v1_observations(
                source,
                "let returned = probe() as u128; println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64);",
            )
        );
    }
}

unsafe fn call_mrml_v1_word_to_wide(function: *const u8, input: u64) -> u128 {
    let returned_low: u64;
    let returned_high: u64;
    #[cfg(target_os = "windows")]
    unsafe {
        core::arch::asm!(
            "sub rsp, 32",
            "call {function}",
            "add rsp, 32",
            function = in(reg) function,
            in("rcx") input,
            lateout("rax") returned_low,
            lateout("rdx") returned_high,
            clobber_abi("C"),
        );
    }
    #[cfg(not(target_os = "windows"))]
    unsafe {
        core::arch::asm!(
            "call {function}",
            function = in(reg) function,
            in("rdi") input,
            lateout("rax") returned_low,
            lateout("rdx") returned_high,
            clobber_abi("C"),
        );
    }
    (u128::from(returned_high) << 64) | u128::from(returned_low)
}

#[test]
fn mrml_v1_one_word_widening_sets_the_exact_high_word() {
    let unsigned = compile(MRML_V1_UNSIGNED_WIDEN_SOURCE);
    let signed = compile(MRML_V1_SIGNED_WIDEN_SOURCE);
    let narrow_signed = compile(MRML_V1_NARROW_SIGNED_TO_UNSIGNED_WIDEN_SOURCE);
    let narrow_unsigned = compile(MRML_V1_NARROW_UNSIGNED_TO_SIGNED_WIDEN_SOURCE);
    let inputs = [0u64, 1, i64::MAX as u64, i64::MIN as u64, u64::MAX];
    let actual_unsigned = inputs
        .into_iter()
        .flat_map(|input| {
            let returned = unsafe { call_mrml_v1_word_to_wide(unsigned.pointer, input) };
            [returned as u64, (returned >> 64) as u64]
        })
        .collect::<Vec<_>>();
    let actual_signed = inputs
        .into_iter()
        .flat_map(|input| {
            let returned = unsafe { call_mrml_v1_word_to_wide(signed.pointer, input) };
            [returned as u64, (returned >> 64) as u64]
        })
        .collect::<Vec<_>>();
    let driver = "for input in [0u64, 1, i64::MAX as u64, i64::MIN as u64, u64::MAX] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }";
    assert_eq!(
        actual_unsigned,
        rustc_mrml_v1_observations(MRML_V1_UNSIGNED_WIDEN_SOURCE, driver)
    );
    let signed_driver = "for input in [0i64, 1, i64::MAX, i64::MIN, -1] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }";
    assert_eq!(
        actual_signed,
        rustc_mrml_v1_observations(MRML_V1_SIGNED_WIDEN_SOURCE, signed_driver)
    );
    let narrow_signed_inputs = [0u64, 1, i8::MAX as u64, i8::MIN as u64, u64::MAX];
    let actual_narrow_signed = narrow_signed_inputs
        .into_iter()
        .flat_map(|input| {
            let returned = unsafe { call_mrml_v1_word_to_wide(narrow_signed.pointer, input) };
            [returned as u64, (returned >> 64) as u64]
        })
        .collect::<Vec<_>>();
    let narrow_signed_driver = "for input in [0i8, 1, i8::MAX, i8::MIN, -1] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", (returned >> 64) as u64); }";
    assert_eq!(
        actual_narrow_signed,
        rustc_mrml_v1_observations(
            MRML_V1_NARROW_SIGNED_TO_UNSIGNED_WIDEN_SOURCE,
            narrow_signed_driver,
        )
    );
    let narrow_unsigned_inputs = [
        0u64,
        1,
        i32::MAX as u64,
        i32::MIN as u32 as u64,
        u32::MAX as u64,
    ];
    let actual_narrow_unsigned = narrow_unsigned_inputs
        .into_iter()
        .flat_map(|input| {
            let returned = unsafe { call_mrml_v1_word_to_wide(narrow_unsigned.pointer, input) };
            [returned as u64, (returned >> 64) as u64]
        })
        .collect::<Vec<_>>();
    let narrow_unsigned_driver = "for input in [0u32, 1, i32::MAX as u32, i32::MIN as u32, u32::MAX] { let returned = probe(input); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64); }";
    assert_eq!(
        actual_narrow_unsigned,
        rustc_mrml_v1_observations(
            MRML_V1_NARROW_UNSIGNED_TO_SIGNED_WIDEN_SOURCE,
            narrow_unsigned_driver,
        )
    );
}

unsafe fn call_mrml_v1_wide_literal(function: *const u8) -> u128 {
    let returned_low: u64;
    let returned_high: u64;
    #[cfg(target_os = "windows")]
    unsafe {
        core::arch::asm!(
            "sub rsp, 32",
            "call {function}",
            "add rsp, 32",
            function = in(reg) function,
            lateout("rax") returned_low,
            lateout("rdx") returned_high,
            clobber_abi("C"),
        );
    }
    #[cfg(not(target_os = "windows"))]
    unsafe {
        core::arch::asm!(
            "call {function}",
            function = in(reg) function,
            lateout("rax") returned_low,
            lateout("rdx") returned_high,
            clobber_abi("C"),
        );
    }
    (u128::from(returned_high) << 64) | u128::from(returned_low)
}

#[test]
fn mrml_v1_wide_integer_literals_return_exact_words() {
    for source in [
        MRML_V1_U128_LITERAL_SOURCE,
        MRML_V1_I128_MAX_LITERAL_SOURCE,
        MRML_V1_I128_MIN_LITERAL_SOURCE,
    ] {
        let code = compile(source);
        let returned = unsafe { call_mrml_v1_wide_literal(code.pointer) };
        let actual = [returned as u64, (returned >> 64) as u64];
        assert_eq!(
            actual.as_slice(),
            rustc_mrml_v1_observations(
                source,
                "let returned = probe(); println!(\"{}\", returned as u64); println!(\"{}\", ((returned as u128) >> 64) as u64);",
            )
        );
    }
}

unsafe fn call_mrml_v1_str_return(
    function: *const u8,
    input: &str,
    alternate: bool,
) -> (*const u8, u64) {
    let returned_pointer: *const u8;
    let returned_length: u64;
    #[cfg(target_os = "windows")]
    unsafe {
        core::arch::asm!(
            "sub rsp, 32",
            "call {function}",
            "add rsp, 32",
            function = in(reg) function,
            in("rcx") input.as_ptr(),
            inlateout("rdx") input.len() as u64 => returned_length,
            in("r8") u64::from(alternate),
            lateout("rax") returned_pointer,
            clobber_abi("C"),
        );
    }
    #[cfg(not(target_os = "windows"))]
    unsafe {
        core::arch::asm!(
            "call {function}",
            function = in(reg) function,
            in("rdi") input.as_ptr(),
            in("rsi") input.len() as u64,
            inlateout("rdx") u64::from(alternate) => returned_length,
            lateout("rax") returned_pointer,
            clobber_abi("C"),
        );
    }
    (returned_pointer, returned_length)
}

#[test]
fn mrml_v1_string_facade_returns_input_or_readonly_literal_words() {
    let code = compile(MRML_V1_STR_RETURN_SOURCE);
    let input = "Möbius";
    let mut actual = Vec::new();
    for alternate in [false, true] {
        let (pointer, length) = unsafe { call_mrml_v1_str_return(code.pointer, input, alternate) };
        let returned = unsafe { std::slice::from_raw_parts(pointer, length as usize) };
        actual.extend([
            length,
            u64::from(returned[0]),
            u64::from(returned[length as usize - 1]),
        ]);
    }
    assert_eq!(
        actual,
        rustc_mrml_v1_observations(
            MRML_V1_STR_RETURN_SOURCE,
            "for alternate in [false, true] { let returned = probe(\"Möbius\", alternate); println!(\"{}\", returned.len()); println!(\"{}\", returned.as_bytes()[0]); println!(\"{}\", returned.as_bytes()[returned.len() - 1]); }",
        )
    );
}

#[test]
fn mrml_v1_slice_facade_straddles_the_register_stack_boundary() {
    let code = compile(MRML_V1_SPLIT_SLICE_SOURCE);
    let input = [10, 20, 30, 40, 50, 60, 70];
    #[cfg(target_os = "windows")]
    let actual = {
        let probe: unsafe extern "C" fn(u64, u64, u64, *const u8, u64) -> u64 =
            unsafe { std::mem::transmute(code.pointer) };
        unsafe { probe(2, 3, 5, input.as_ptr(), input.len() as u64) }
    };
    #[cfg(not(target_os = "windows"))]
    let actual = {
        let probe: unsafe extern "C" fn(u64, u64, u64, u64, u64, *const u8, u64) -> u64 =
            unsafe { std::mem::transmute(code.pointer) };
        unsafe { probe(2, 3, 5, 7, 11, input.as_ptr(), input.len() as u64) }
    };
    #[cfg(target_os = "windows")]
    let driver =
        "let input = [10, 20, 30, 40, 50, 60, 70]; println!(\"{}\", probe(2, 3, 5, &input));";
    #[cfg(not(target_os = "windows"))]
    let driver = "let input = [10, 20, 30, 40, 50, 60, 70]; println!(\"{}\", probe(2, 3, 5, 7, 11, &input));";
    assert_eq!(
        vec![actual],
        rustc_mrml_v1_observations(MRML_V1_SPLIT_SLICE_SOURCE, driver)
    );
}

#[test]
fn nested_else_if_actions_and_returns_match_oracle() {
    let code = compile(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(primary: bool, first: bool, second: bool, input: u32) -> u32 { loop { loop { if primary { let selected: u32 = input + 1; selected + 100; return selected; } else if first { let selected: u32 = input + 2; return selected; } else if second { let selected: u32 = input + 3; return selected; } else { let selected: u32 = input + 4; return selected; } } } }",
    );
    let probe: unsafe extern "C" fn(bool, bool, bool, u32) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    for p in [false, true] {
        for a in [false, true] {
            for b in [false, true] {
                let expected = if p {
                    41
                } else if a {
                    42
                } else if b {
                    43
                } else {
                    44
                };
                assert_eq!(unsafe { probe(p, a, b, 40) }, expected);
            }
        }
    }
}

#[test]
fn nested_conditional_continue_and_break_actions_match_oracle() {
    let code = compile(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { let mut inner: u32 = 0; let mut total: u32 = 0; loop { loop { inner += 1; if inner % 2 == 0 { total += 10; continue; } total += inner; if inner == 5 { break; } } return total; } }",
    );
    let probe: unsafe extern "C" fn() -> u32 = unsafe { std::mem::transmute(code.pointer) };
    assert_eq!(unsafe { probe() }, 29);
}

#[test]
fn nested_reference_mutations_and_return_origins_match_oracle() {
    let code = compile(
        "fn select(input: &mut u32, primary: bool, alternative: bool) -> &mut u32 { loop { loop { if primary { *input += 3; return input; } else if alternative { *input += 5; return input; } else { *input += 7; return input; } } } } #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut u32, primary: bool, alternative: bool) -> u32 { let returned: &mut u32 = select(input, primary, alternative); *returned += 11; *returned }",
    );
    let probe: unsafe extern "C" fn(*mut u32, bool, bool) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    for p in [false, true] {
        for a in [false, true] {
            let mut actual = 20;
            let expected =
                20 + if p {
                    3
                } else if a {
                    5
                } else {
                    7
                } + 11;
            assert_eq!(
                (unsafe { probe(&mut actual, p, a) }, actual),
                (expected, expected)
            );
        }
    }
}

#[test]
fn subslice_then_index_reference_mutation_executes() {
    for code in [
        compile(
            "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32; 4], first: usize, second: usize, index: usize) -> u32 { let selected: &mut u32 = &mut input[first..][second..][index]; *selected += 13; *selected }",
        ),
        compile(
            "fn select(input: &mut [u32; 4], first: usize, second: usize, index: usize) -> &mut u32 { &mut input[first..][second..][index] } #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32; 4], first: usize, second: usize, index: usize) -> u32 { let selected: &mut u32 = select(input, first, second, index); *selected += 13; *selected }",
        ),
        compile(
            "fn select(input: &mut [u32; 4], first: usize, second: usize, index: usize) -> &mut u32 { let alias: &mut u32 = &mut input[first..][second..][index]; alias } #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32; 4], first: usize, second: usize, index: usize) -> u32 { let selected: &mut u32 = select(input, first, second, index); *selected += 13; *selected }",
        ),
    ] {
        let probe: unsafe extern "C" fn(*mut [u32; 4], usize, usize, usize) -> u32 =
            unsafe { std::mem::transmute(code.pointer) };
        for (first, second, index, target) in
            [(0, 1, 2, 3), (1, 1, 0, 2), (2, 0, 1, 3)]
        {
            let mut values = [10, 20, 30, 40];
            let expected = values[target] + 13;
            assert_eq!(
                unsafe { probe(&mut values, first, second, index) },
                expected
            );
            assert_eq!(values[target], expected);
            for (position, value) in values.into_iter().enumerate() {
                if position != target {
                    assert_eq!(value, [10, 20, 30, 40][position]);
                }
            }
        }
    }

    let code = compile(
        "fn select(input: &mut [u32], choose: bool) -> &mut [u32] { if choose { &mut input[0..][1..] } else { &mut input[1..][1..] } } #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32], choose: bool, index: usize) -> u32 { let selected: &mut [u32] = select(input, choose); selected[index] += 23; selected[index] }",
    );
    #[cfg(not(target_os = "windows"))]
    let probe: unsafe extern "C" fn(*mut u32, usize, bool, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    #[cfg(target_os = "windows")]
    let probe: unsafe extern "C" fn(*const usize, bool, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    for (choose, index, target) in [(true, 2, 3), (false, 2, 4), (true, 0, 1), (false, 0, 2)] {
        let mut values = [10, 20, 30, 40, 50];
        let expected = values[target] + 23;
        #[cfg(not(target_os = "windows"))]
        assert_eq!(
            unsafe { probe(values.as_mut_ptr(), values.len(), choose, index) },
            expected
        );
        #[cfg(target_os = "windows")]
        {
            let slice = [values.as_mut_ptr() as usize, values.len()];
            assert_eq!(unsafe { probe(slice.as_ptr(), choose, index) }, expected);
        }
        assert_eq!(values[target], expected);
        for (position, value) in values.into_iter().enumerate() {
            if position != target {
                assert_eq!(value, [10, 20, 30, 40, 50][position]);
            }
        }
    }

    let code = compile(
        "fn select(input: &mut [u32], choose: bool) -> &mut [u32] { if choose { return &mut input[0..][1..]; } &mut input[1..][1..] } #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32], choose: bool, index: usize) -> u32 { let selected: &mut [u32] = select(input, choose); selected[index] += 29; selected[index] }",
    );
    #[cfg(not(target_os = "windows"))]
    let probe: unsafe extern "C" fn(*mut u32, usize, bool, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    #[cfg(target_os = "windows")]
    let probe: unsafe extern "C" fn(*const usize, bool, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    for (choose, index, target) in [(true, 2, 3), (false, 2, 4), (true, 0, 1), (false, 0, 2)] {
        let mut values = [10, 20, 30, 40, 50];
        let expected = values[target] + 29;
        #[cfg(not(target_os = "windows"))]
        assert_eq!(
            unsafe { probe(values.as_mut_ptr(), values.len(), choose, index) },
            expected
        );
        #[cfg(target_os = "windows")]
        {
            let slice = [values.as_mut_ptr() as usize, values.len()];
            assert_eq!(unsafe { probe(slice.as_ptr(), choose, index) }, expected);
        }
        assert_eq!(values[target], expected);
        for (position, value) in values.into_iter().enumerate() {
            if position != target {
                assert_eq!(value, [10, 20, 30, 40, 50][position]);
            }
        }
    }

    let code = compile(
        "fn select(input: &[u32], first: usize, second: usize) -> &[u32] { &input[first..][second..] } #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &[u32], first: usize, second: usize, index: usize) -> u32 { let selected: &[u32] = select(input, first, second); selected[index] + 31 }",
    );
    #[cfg(not(target_os = "windows"))]
    let probe: unsafe extern "C" fn(*const u32, usize, usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    #[cfg(target_os = "windows")]
    let probe: unsafe extern "C" fn(*const usize, usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    for (first, second, index, target) in [(0, 1, 3, 4), (1, 1, 0, 2), (2, 0, 2, 4)] {
        let values = [10, 20, 30, 40, 50];
        let expected = values[target] + 31;
        #[cfg(not(target_os = "windows"))]
        assert_eq!(
            unsafe { probe(values.as_ptr(), values.len(), first, second, index) },
            expected
        );
        #[cfg(target_os = "windows")]
        {
            let slice = [values.as_ptr() as usize, values.len()];
            assert_eq!(unsafe { probe(slice.as_ptr(), first, second, index) }, expected);
        }
        assert_eq!(values, [10, 20, 30, 40, 50]);
    }

    let code = compile(
        "fn select(input: &mut [u32], first: usize, second: usize) -> &[u32] { let mutable: &mut [u32] = &mut input[first..][second..]; let shared: &[u32] = mutable; shared } #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32], first: usize, second: usize, index: usize) -> u32 { let selected: &[u32] = select(input, first, second); selected[index] + 37 }",
    );
    #[cfg(not(target_os = "windows"))]
    let probe: unsafe extern "C" fn(*mut u32, usize, usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    #[cfg(target_os = "windows")]
    let probe: unsafe extern "C" fn(*const usize, usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    for (first, second, index, target) in [(0, 1, 3, 4), (1, 1, 0, 2), (2, 0, 2, 4)] {
        let mut values = [10, 20, 30, 40, 50];
        let expected = values[target] + 37;
        #[cfg(not(target_os = "windows"))]
        assert_eq!(
            unsafe { probe(values.as_mut_ptr(), values.len(), first, second, index) },
            expected
        );
        #[cfg(target_os = "windows")]
        {
            let slice = [values.as_mut_ptr() as usize, values.len()];
            assert_eq!(unsafe { probe(slice.as_ptr(), first, second, index) }, expected);
        }
        assert_eq!(values, [10, 20, 30, 40, 50]);
    }

    let code = compile(
        "fn select(input: &mut [u32], first: usize, second: usize) -> &[u32] { let initial: &mut [u32] = &mut input[first..][second..]; let alias: &mut [u32] = initial; let shared: &[u32] = alias; shared } #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32], first: usize, second: usize, index: usize) -> u32 { let selected: &[u32] = select(input, first, second); selected[index] + 47 }",
    );
    #[cfg(not(target_os = "windows"))]
    let probe: unsafe extern "C" fn(*mut u32, usize, usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    #[cfg(target_os = "windows")]
    let probe: unsafe extern "C" fn(*const usize, usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    for (first, second, index, target) in [(0, 1, 3, 4), (1, 1, 0, 2), (2, 0, 2, 4)] {
        let mut values = [10, 20, 30, 40, 50];
        let expected = values[target] + 47;
        #[cfg(not(target_os = "windows"))]
        assert_eq!(
            unsafe { probe(values.as_mut_ptr(), values.len(), first, second, index) },
            expected
        );
        #[cfg(target_os = "windows")]
        {
            let slice = [values.as_mut_ptr() as usize, values.len()];
            assert_eq!(unsafe { probe(slice.as_ptr(), first, second, index) }, expected);
        }
        assert_eq!(values, [10, 20, 30, 40, 50]);
    }

    let code = compile(
        "fn select(input: &mut [u32], first: usize, second: usize) -> &[u32] { let mut selected: &mut [u32] = &mut input[first..][0..]; selected = &mut input[second..][1..]; let shared: &[u32] = selected; shared } #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32], first: usize, second: usize, index: usize) -> u32 { let selected: &[u32] = select(input, first, second); selected[index] + 53 }",
    );
    #[cfg(not(target_os = "windows"))]
    let probe: unsafe extern "C" fn(*mut u32, usize, usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    #[cfg(target_os = "windows")]
    let probe: unsafe extern "C" fn(*const usize, usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    for (first, second, index, target) in [(0, 0, 0, 1), (2, 1, 0, 2), (1, 0, 3, 4)] {
        let mut values = [10, 20, 30, 40, 50];
        let expected = values[target] + 53;
        #[cfg(not(target_os = "windows"))]
        assert_eq!(
            unsafe { probe(values.as_mut_ptr(), values.len(), first, second, index) },
            expected
        );
        #[cfg(target_os = "windows")]
        {
            let slice = [values.as_mut_ptr() as usize, values.len()];
            assert_eq!(
                unsafe { probe(slice.as_ptr(), first, second, index) },
                expected
            );
        }
        assert_eq!(values, [10, 20, 30, 40, 50]);
    }

    let code = compile(
        "fn select(input: &mut [u32], first: bool) -> &[u32] { if first { &input[0..][1..] } else { &input[1..][1..] } } #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32], first: bool, index: usize) -> u32 { let selected: &[u32] = select(input, first); selected[index] + 41 }",
    );
    #[cfg(not(target_os = "windows"))]
    let probe: unsafe extern "C" fn(*mut u32, usize, bool, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    #[cfg(target_os = "windows")]
    let probe: unsafe extern "C" fn(*const usize, bool, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    for (first, index, target) in [(true, 0, 1), (true, 3, 4), (false, 0, 2), (false, 2, 4)] {
        let mut values = [10, 20, 30, 40, 50];
        let expected = values[target] + 41;
        #[cfg(not(target_os = "windows"))]
        assert_eq!(
            unsafe { probe(values.as_mut_ptr(), values.len(), first, index) },
            expected
        );
        #[cfg(target_os = "windows")]
        {
            let slice = [values.as_mut_ptr() as usize, values.len()];
            assert_eq!(unsafe { probe(slice.as_ptr(), first, index) }, expected);
        }
        assert_eq!(values, [10, 20, 30, 40, 50]);
    }

    let code = compile(
        "fn select(input: &mut [u32], first: bool) -> &[u32] { if first { return &input[0..][1..]; } &input[1..][1..] } #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32], first: bool, index: usize) -> u32 { let selected: &[u32] = select(input, first); selected[index] + 43 }",
    );
    #[cfg(not(target_os = "windows"))]
    let probe: unsafe extern "C" fn(*mut u32, usize, bool, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    #[cfg(target_os = "windows")]
    let probe: unsafe extern "C" fn(*const usize, bool, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    for (first, index, target) in [(true, 0, 1), (true, 3, 4), (false, 0, 2), (false, 2, 4)] {
        let mut values = [10, 20, 30, 40, 50];
        let expected = values[target] + 43;
        #[cfg(not(target_os = "windows"))]
        assert_eq!(
            unsafe { probe(values.as_mut_ptr(), values.len(), first, index) },
            expected
        );
        #[cfg(target_os = "windows")]
        {
            let slice = [values.as_mut_ptr() as usize, values.len()];
            assert_eq!(unsafe { probe(slice.as_ptr(), first, index) }, expected);
        }
        assert_eq!(values, [10, 20, 30, 40, 50]);
    }

    for code in [
        compile(
            "fn select(input: &mut [u32; 4], start: usize, index: usize) -> &mut u32 { &mut input[start..][index] } #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32; 4], start: usize, index: usize) -> u32 { let selected: &mut u32 = select(input, start, index); *selected += 7; *selected }",
        ),
        compile(
            "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32; 4], start: usize, index: usize) -> u32 { let selected: &mut u32 = &mut input[start..][index]; *selected += 7; *selected }",
        ),
    ] {
        let probe: unsafe extern "C" fn(*mut [u32; 4], usize, usize) -> u32 =
            unsafe { std::mem::transmute(code.pointer) };
        for (start, index, target) in [(0, 2, 2), (1, 0, 1), (2, 1, 3)] {
            let mut values = [10, 20, 30, 40];
            let expected = values[target] + 7;
            assert_eq!(unsafe { probe(&mut values, start, index) }, expected);
            assert_eq!(values[target], expected);
            for (position, value) in values.into_iter().enumerate() {
                if position != target {
                    assert_eq!(value, [10, 20, 30, 40][position]);
                }
            }
        }
    }

    let code = compile(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32], start: usize, index: usize) -> u32 { let selected: &mut u32 = &mut input[start..][index]; *selected += 7; *selected }",
    );
    #[cfg(not(target_os = "windows"))]
    let probe: unsafe extern "C" fn(*mut u32, usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    #[cfg(target_os = "windows")]
    let probe: unsafe extern "C" fn(*const usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    for (start, index, target) in [(0, 2, 2), (1, 0, 1), (2, 1, 3)] {
        let mut values = [10, 20, 30, 40];
        let expected = values[target] + 7;
        #[cfg(not(target_os = "windows"))]
        assert_eq!(
            unsafe { probe(values.as_mut_ptr(), values.len(), start, index) },
            expected
        );
        #[cfg(target_os = "windows")]
        {
            let slice = [values.as_mut_ptr() as usize, values.len()];
            assert_eq!(unsafe { probe(slice.as_ptr(), start, index) }, expected);
        }
        assert_eq!(values[target], expected);
        for (position, value) in values.into_iter().enumerate() {
            if position != target {
                assert_eq!(value, [10, 20, 30, 40][position]);
            }
        }
    }

    let code = compile(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32; 4], start: usize, end: usize, index: usize) -> u32 { let selected: &mut u32 = &mut input[start..end][index]; *selected += 9; *selected }",
    );
    let probe: unsafe extern "C" fn(*mut [u32; 4], usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    for (start, end, index, target) in [(0, 3, 2, 2), (1, 4, 0, 1), (2, 4, 1, 3)] {
        let mut values = [10, 20, 30, 40];
        let expected = values[target] + 9;
        assert_eq!(unsafe { probe(&mut values, start, end, index) }, expected);
        assert_eq!(values[target], expected);
        for (position, value) in values.into_iter().enumerate() {
            if position != target {
                assert_eq!(value, [10, 20, 30, 40][position]);
            }
        }
    }

    let code = compile(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32], start: usize, end: usize, index: usize) -> u32 { let selected: &mut u32 = &mut input[start..end][index]; *selected += 9; *selected }",
    );
    #[cfg(not(target_os = "windows"))]
    let probe: unsafe extern "C" fn(*mut u32, usize, usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    #[cfg(target_os = "windows")]
    let probe: unsafe extern "C" fn(*const usize, usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    for (start, end, index, target) in [(0, 3, 2, 2), (1, 4, 0, 1), (2, 4, 1, 3)] {
        let mut values = [10, 20, 30, 40];
        let expected = values[target] + 9;
        #[cfg(not(target_os = "windows"))]
        assert_eq!(
            unsafe { probe(values.as_mut_ptr(), values.len(), start, end, index) },
            expected
        );
        #[cfg(target_os = "windows")]
        {
            let slice = [values.as_mut_ptr() as usize, values.len()];
            assert_eq!(unsafe { probe(slice.as_ptr(), start, end, index) }, expected);
        }
        assert_eq!(values[target], expected);
        for (position, value) in values.into_iter().enumerate() {
            if position != target {
                assert_eq!(value, [10, 20, 30, 40][position]);
            }
        }
    }

    let code = compile(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32; 4], start: usize, end: usize, index: usize) -> u32 { let selected: &mut u32 = &mut input[start..=end][index]; *selected += 11; *selected }",
    );
    let probe: unsafe extern "C" fn(*mut [u32; 4], usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    for (start, end, index, target) in [(0, 2, 2, 2), (1, 3, 0, 1), (2, 3, 1, 3)] {
        let mut values = [10, 20, 30, 40];
        let expected = values[target] + 11;
        assert_eq!(unsafe { probe(&mut values, start, end, index) }, expected);
        assert_eq!(values[target], expected);
        for (position, value) in values.into_iter().enumerate() {
            if position != target {
                assert_eq!(value, [10, 20, 30, 40][position]);
            }
        }
    }

    let code = compile(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32], start: usize, end: usize, index: usize) -> u32 { let selected: &mut u32 = &mut input[start..=end][index]; *selected += 11; *selected }",
    );
    #[cfg(not(target_os = "windows"))]
    let probe: unsafe extern "C" fn(*mut u32, usize, usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    #[cfg(target_os = "windows")]
    let probe: unsafe extern "C" fn(*const usize, usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    for (start, end, index, target) in [(0, 2, 2, 2), (1, 3, 0, 1), (2, 3, 1, 3)] {
        let mut values = [10, 20, 30, 40];
        let expected = values[target] + 11;
        #[cfg(not(target_os = "windows"))]
        assert_eq!(
            unsafe { probe(values.as_mut_ptr(), values.len(), start, end, index) },
            expected
        );
        #[cfg(target_os = "windows")]
        {
            let slice = [values.as_mut_ptr() as usize, values.len()];
            assert_eq!(unsafe { probe(slice.as_ptr(), start, end, index) }, expected);
        }
        assert_eq!(values[target], expected);
        for (position, value) in values.into_iter().enumerate() {
            if position != target {
                assert_eq!(value, [10, 20, 30, 40][position]);
            }
        }
    }

    for code in [
        compile(
            "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32], first: usize, second: usize, index: usize) -> u32 { let selected: &mut u32 = &mut input[first..][second..][index]; *selected += 13; *selected }",
        ),
        compile(
            "fn select(input: &mut [u32], first: usize, second: usize, index: usize) -> &mut u32 { &mut input[first..][second..][index] } #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32], first: usize, second: usize, index: usize) -> u32 { let selected: &mut u32 = select(input, first, second, index); *selected += 13; *selected }",
        ),
        compile(
            "fn select(input: &mut [u32], first: usize, second: usize, index: usize) -> &mut u32 { let alias: &mut u32 = &mut input[first..][second..][index]; alias } #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32], first: usize, second: usize, index: usize) -> u32 { let selected: &mut u32 = select(input, first, second, index); *selected += 13; *selected }",
        ),
    ] {
        #[cfg(not(target_os = "windows"))]
        let probe: unsafe extern "C" fn(*mut u32, usize, usize, usize, usize) -> u32 =
            unsafe { std::mem::transmute(code.pointer) };
        #[cfg(target_os = "windows")]
        let probe: unsafe extern "C" fn(*const usize, usize, usize, usize) -> u32 =
            unsafe { std::mem::transmute(code.pointer) };
        for (first, second, index, target) in
            [(0, 1, 2, 3), (1, 1, 0, 2), (2, 0, 1, 3)]
        {
            let mut values = [10, 20, 30, 40];
            let expected = values[target] + 13;
            #[cfg(not(target_os = "windows"))]
            assert_eq!(
                unsafe {
                    probe(
                        values.as_mut_ptr(),
                        values.len(),
                        first,
                        second,
                        index,
                    )
                },
                expected
            );
            #[cfg(target_os = "windows")]
            {
                let slice = [values.as_mut_ptr() as usize, values.len()];
                assert_eq!(
                    unsafe { probe(slice.as_ptr(), first, second, index) },
                    expected
                );
            }
            assert_eq!(values[target], expected);
            for (position, value) in values.into_iter().enumerate() {
                if position != target {
                    assert_eq!(value, [10, 20, 30, 40][position]);
                }
            }
        }
    }

    let code = compile(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32; 5], first: usize, second: usize, index: usize) -> u32 { let selected: &mut [u32] = &mut input[first..][second..]; selected[index] += 19; selected[index] }",
    );
    let probe: unsafe extern "C" fn(*mut [u32; 5], usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    for (first, second, index, target) in [(0, 1, 3, 4), (1, 1, 0, 2), (2, 0, 2, 4)] {
        let mut values = [10, 20, 30, 40, 50];
        let expected = values[target] + 19;
        assert_eq!(unsafe { probe(&mut values, first, second, index) }, expected);
        assert_eq!(values[target], expected);
        for (position, value) in values.into_iter().enumerate() {
            if position != target {
                assert_eq!(value, [10, 20, 30, 40, 50][position]);
            }
        }
    }

    let code = compile(
        "fn select(input: &mut [u32; 5], first: usize, second: usize) -> &mut [u32] { &mut input[first..][second..] } #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32; 5], first: usize, second: usize, index: usize) -> u32 { let selected: &mut [u32] = select(input, first, second); selected[index] += 19; selected[index] }",
    );
    let probe: unsafe extern "C" fn(*mut [u32; 5], usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    for (first, second, index, target) in [(0, 1, 3, 4), (1, 1, 0, 2), (2, 0, 2, 4)] {
        let mut values = [10, 20, 30, 40, 50];
        let expected = values[target] + 19;
        assert_eq!(unsafe { probe(&mut values, first, second, index) }, expected);
        assert_eq!(values[target], expected);
        for (position, value) in values.into_iter().enumerate() {
            if position != target {
                assert_eq!(value, [10, 20, 30, 40, 50][position]);
            }
        }
    }

    let code = compile(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32], first: usize, second: usize, index: usize) -> u32 { let selected: &mut [u32] = &mut input[first..][second..]; selected[index] += 19; selected[index] }",
    );
    #[cfg(not(target_os = "windows"))]
    let probe: unsafe extern "C" fn(*mut u32, usize, usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    #[cfg(target_os = "windows")]
    let probe: unsafe extern "C" fn(*const usize, usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    for (first, second, index, target) in [(0, 1, 3, 4), (1, 1, 0, 2), (2, 0, 2, 4)] {
        let mut values = [10, 20, 30, 40, 50];
        let expected = values[target] + 19;
        #[cfg(not(target_os = "windows"))]
        assert_eq!(
            unsafe { probe(values.as_mut_ptr(), values.len(), first, second, index) },
            expected
        );
        #[cfg(target_os = "windows")]
        {
            let slice = [values.as_mut_ptr() as usize, values.len()];
            assert_eq!(unsafe { probe(slice.as_ptr(), first, second, index) }, expected);
        }
        assert_eq!(values[target], expected);
        for (position, value) in values.into_iter().enumerate() {
            if position != target {
                assert_eq!(value, [10, 20, 30, 40, 50][position]);
            }
        }
    }

    for code in [
        compile(
            "fn select(input: &mut [u32], first: usize, second: usize) -> &mut [u32] { &mut input[first..][second..] } #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32], first: usize, second: usize, index: usize) -> u32 { let selected: &mut [u32] = select(input, first, second); selected[index] += 19; selected[index] }",
        ),
        compile(
            "fn select(input: &mut [u32], first: usize, second: usize) -> &mut [u32] { let alias: &mut [u32] = &mut input[first..][second..]; alias } #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32], first: usize, second: usize, index: usize) -> u32 { let selected: &mut [u32] = select(input, first, second); selected[index] += 19; selected[index] }",
        ),
        compile(
            "fn select(input: &mut [u32], first: usize, second: usize) -> &mut [u32] { let initial: &mut [u32] = &mut input[first..][second..]; let alias: &mut [u32] = initial; alias } #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32], first: usize, second: usize, index: usize) -> u32 { let selected: &mut [u32] = select(input, first, second); selected[index] += 19; selected[index] }",
        ),
    ] {
        #[cfg(not(target_os = "windows"))]
        let probe: unsafe extern "C" fn(*mut u32, usize, usize, usize, usize) -> u32 =
            unsafe { std::mem::transmute(code.pointer) };
        #[cfg(target_os = "windows")]
        let probe: unsafe extern "C" fn(*const usize, usize, usize, usize) -> u32 =
            unsafe { std::mem::transmute(code.pointer) };
        for (first, second, index, target) in
            [(0, 1, 3, 4), (1, 1, 0, 2), (2, 0, 2, 4)]
        {
            let mut values = [10, 20, 30, 40, 50];
            let expected = values[target] + 19;
            #[cfg(not(target_os = "windows"))]
            assert_eq!(
                unsafe { probe(values.as_mut_ptr(), values.len(), first, second, index) },
                expected
            );
            #[cfg(target_os = "windows")]
            {
                let slice = [values.as_mut_ptr() as usize, values.len()];
                assert_eq!(unsafe { probe(slice.as_ptr(), first, second, index) }, expected);
            }
            assert_eq!(values[target], expected);
            for (position, value) in values.into_iter().enumerate() {
                if position != target {
                    assert_eq!(value, [10, 20, 30, 40, 50][position]);
                }
            }
        }
    }

    for code in [
        compile(
            "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32; 5], first: usize, second: usize, third: usize, index: usize) -> u32 { let selected: &mut u32 = &mut input[first..][second..][third..][index]; *selected += 17; *selected }",
        ),
        compile(
            "fn select(input: &mut [u32; 5], first: usize, second: usize, index: usize) -> &mut u32 { &mut input[first..][second..][1..][index] } #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32; 5], first: usize, second: usize, third: usize, index: usize) -> u32 { let selected: &mut u32 = select(input, first, second, index); *selected += 17; *selected }",
        ),
    ] {
        let probe: unsafe extern "C" fn(*mut [u32; 5], usize, usize, usize, usize) -> u32 =
            unsafe { std::mem::transmute(code.pointer) };
        for (first, second, third, index, target) in
            [(0, 1, 1, 2, 4), (1, 1, 1, 0, 3), (2, 0, 1, 1, 4)]
        {
            let mut values = [10, 20, 30, 40, 50];
            let expected = values[target] + 17;
            assert_eq!(
                unsafe { probe(&mut values, first, second, third, index) },
                expected
            );
            assert_eq!(values[target], expected);
            for (position, value) in values.into_iter().enumerate() {
                if position != target {
                    assert_eq!(value, [10, 20, 30, 40, 50][position]);
                }
            }
        }
    }

    for code in [
        compile(
            "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32], first: usize, second: usize, third: usize, index: usize) -> u32 { let selected: &mut u32 = &mut input[first..][second..][third..][index]; *selected += 17; *selected }",
        ),
        compile(
            "fn select(input: &mut [u32], first: usize, second: usize, index: usize) -> &mut u32 { &mut input[first..][second..][1..][index] } #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32], first: usize, second: usize, third: usize, index: usize) -> u32 { let selected: &mut u32 = select(input, first, second, index); *selected += 17; *selected }",
        ),
    ] {
        #[cfg(not(target_os = "windows"))]
        let probe: unsafe extern "C" fn(*mut u32, usize, usize, usize, usize, usize) -> u32 =
            unsafe { std::mem::transmute(code.pointer) };
        #[cfg(target_os = "windows")]
        let probe: unsafe extern "C" fn(*const usize, usize, usize, usize, usize) -> u32 =
            unsafe { std::mem::transmute(code.pointer) };
        for (first, second, third, index, target) in
            [(0, 1, 1, 2, 4), (1, 1, 1, 0, 3), (2, 0, 1, 1, 4)]
        {
            let mut values = [10, 20, 30, 40, 50];
            let expected = values[target] + 17;
            #[cfg(not(target_os = "windows"))]
            assert_eq!(
                unsafe {
                    probe(
                        values.as_mut_ptr(),
                        values.len(),
                        first,
                        second,
                        third,
                        index,
                    )
                },
                expected
            );
            #[cfg(target_os = "windows")]
            {
                let slice = [values.as_mut_ptr() as usize, values.len()];
                assert_eq!(
                    unsafe { probe(slice.as_ptr(), first, second, third, index) },
                    expected
                );
            }
            assert_eq!(values[target], expected);
            for (position, value) in values.into_iter().enumerate() {
                if position != target {
                    assert_eq!(value, [10, 20, 30, 40, 50][position]);
                }
            }
        }
    }
}

#[test]
fn subslice_then_index_bounds_report_isolated_traps() {
    #[cfg(target_os = "windows")]
    const CHILD: &str = "MRML_SEMANTIC_SUBSLICE_INDEX_TRAP_CHILD";
    let code = compile(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32; 4], start: usize, index: usize) -> u32 { let selected: &mut u32 = &mut input[start..][index]; *selected }",
    );
    let probe: unsafe extern "C" fn(*mut [u32; 4], usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };

    #[cfg(not(target_os = "windows"))]
    {
        for (start, index) in [(5, 0), (1, 3)] {
            let pid = unsafe { fork() };
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                let mut values = [10, 20, 30, 40];
                let _ = unsafe { probe(&mut values, start, index) };
                unsafe { _exit(120) }
            }
            let mut status = 0;
            assert_eq!(
                unsafe { waitpid(pid, &mut status, 0) },
                pid,
                "waitpid failed"
            );
            assert_eq!(
                status & 0x7f,
                4,
                "unexpected Unix wait status for ({start}, {index}): {status:#x}"
            );
        }
        return;
    }

    #[cfg(target_os = "windows")]
    if let Some(case) = std::env::var_os(CHILD) {
        unsafe { SetErrorMode(0x0001 | 0x0002) };
        let (start, index) = if case == "range" { (5, 0) } else { (1, 3) };
        let mut values = [10, 20, 30, 40];
        let _ = unsafe { probe(&mut values, start, index) };
        panic!("nested bounds trap unexpectedly returned");
    }

    #[cfg(target_os = "windows")]
    for case in ["range", "index"] {
        let output = Command::new(std::env::current_exe().expect("locate semantic test binary"))
            .args([
                "--exact",
                "subslice_then_index_bounds_report_isolated_traps",
                "--nocapture",
            ])
            .env(CHILD, case)
            .output()
            .expect("launch isolated nested-bounds probe");
        assert_eq!(
            output.status.code(),
            Some(101),
            "unexpected Windows {case} test status: {}",
            output.status
        );
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 child test stdout");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 child test stderr");
        assert!(
            stdout.contains("unexpected return code -1073741795")
                || stderr.contains("unexpected return code -1073741795"),
            "missing Windows {case} illegal-instruction status; stdout: {stdout}; stderr: {stderr}"
        );
    }
}

#[test]
fn repeated_subslice_then_index_bounds_report_isolated_traps() {
    #[cfg(target_os = "windows")]
    const CHILD: &str = "MRML_SEMANTIC_REPEATED_SUBSLICE_INDEX_TRAP_CHILD";
    let code = compile(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32], first: usize, second: usize, third: usize, index: usize) -> u32 { let selected: &mut u32 = &mut input[first..][second..][third..][index]; *selected }",
    );
    #[cfg(not(target_os = "windows"))]
    let probe: unsafe extern "C" fn(*mut u32, usize, usize, usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    #[cfg(target_os = "windows")]
    let probe: unsafe extern "C" fn(*const usize, usize, usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };

    #[cfg(not(target_os = "windows"))]
    {
        for (first, second, third, index) in
            [(5, 0, 0, 0), (0, 5, 0, 0), (1, 1, 3, 0), (1, 1, 0, 2)]
        {
            let pid = unsafe { fork() };
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                let mut values = [10, 20, 30, 40];
                let _ = unsafe {
                    probe(
                        values.as_mut_ptr(),
                        values.len(),
                        first,
                        second,
                        third,
                        index,
                    )
                };
                unsafe { _exit(120) }
            }
            let mut status = 0;
            assert_eq!(
                unsafe { waitpid(pid, &mut status, 0) },
                pid,
                "waitpid failed"
            );
            assert_eq!(
                status & 0x7f,
                4,
                "unexpected Unix wait status for ({first}, {second}, {third}, {index}): {status:#x}"
            );
        }
        return;
    }

    #[cfg(target_os = "windows")]
    if let Some(case) = std::env::var_os(CHILD) {
        unsafe { SetErrorMode(0x0001 | 0x0002) };
        let (first, second, third, index) = match case.to_str() {
            Some("inner") => (5, 0, 0, 0),
            Some("middle") => (0, 5, 0, 0),
            Some("outer") => (1, 1, 3, 0),
            _ => (1, 1, 0, 2),
        };
        let mut values = [10, 20, 30, 40];
        let slice = [values.as_mut_ptr() as usize, values.len()];
        let _ = unsafe { probe(slice.as_ptr(), first, second, third, index) };
        panic!("repeated subslice bounds trap unexpectedly returned");
    }

    #[cfg(target_os = "windows")]
    for case in ["inner", "middle", "outer", "index"] {
        let output = Command::new(std::env::current_exe().expect("locate semantic test binary"))
            .args([
                "--exact",
                "repeated_subslice_then_index_bounds_report_isolated_traps",
                "--nocapture",
            ])
            .env(CHILD, case)
            .output()
            .expect("launch isolated repeated-subslice bounds probe");
        assert_eq!(
            output.status.code(),
            Some(101),
            "unexpected Windows {case} test status: {}",
            output.status
        );
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 child test stdout");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 child test stderr");
        assert!(
            stdout.contains("unexpected return code -1073741795")
                || stderr.contains("unexpected return code -1073741795"),
            "missing Windows {case} illegal-instruction status; stdout: {stdout}; stderr: {stderr}"
        );
    }
}

#[test]
fn inclusive_subslice_then_index_bounds_report_isolated_traps() {
    #[cfg(target_os = "windows")]
    const CHILD: &str = "MRML_SEMANTIC_INCLUSIVE_SUBSLICE_INDEX_TRAP_CHILD";
    let code = compile(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32; 4], start: usize, end: usize, index: usize) -> u32 { let selected: &mut u32 = &mut input[start..=end][index]; *selected }",
    );
    let probe: unsafe extern "C" fn(*mut [u32; 4], usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };

    #[cfg(not(target_os = "windows"))]
    {
        for (start, end, index) in [
            (0, usize::MAX, 0),
            (3, 1, 0),
            (0, 4, 0),
            (1, 3, 3),
        ] {
            let pid = unsafe { fork() };
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                let mut values = [10, 20, 30, 40];
                let _ = unsafe { probe(&mut values, start, end, index) };
                unsafe { _exit(120) }
            }
            let mut status = 0;
            assert_eq!(
                unsafe { waitpid(pid, &mut status, 0) },
                pid,
                "waitpid failed"
            );
            assert_eq!(
                status & 0x7f,
                4,
                "unexpected Unix wait status for ({start}, {end}, {index}): {status:#x}"
            );
        }
        return;
    }

    #[cfg(target_os = "windows")]
    if let Some(case) = std::env::var_os(CHILD) {
        unsafe { SetErrorMode(0x0001 | 0x0002) };
        let (start, end, index) = match case.to_str() {
            Some("inclusive-overflow") => (0, usize::MAX, 0),
            Some("reversed") => (3, 1, 0),
            Some("end") => (0, 4, 0),
            _ => (1, 3, 3),
        };
        let mut values = [10, 20, 30, 40];
        let _ = unsafe { probe(&mut values, start, end, index) };
        panic!("inclusive nested bounds trap unexpectedly returned");
    }

    #[cfg(target_os = "windows")]
    for case in ["inclusive-overflow", "reversed", "end", "index"] {
        let output = Command::new(std::env::current_exe().expect("locate semantic test binary"))
            .args([
                "--exact",
                "inclusive_subslice_then_index_bounds_report_isolated_traps",
                "--nocapture",
            ])
            .env(CHILD, case)
            .output()
            .expect("launch isolated inclusive nested-bounds probe");
        assert_eq!(
            output.status.code(),
            Some(101),
            "unexpected Windows {case} test status: {}",
            output.status
        );
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 child test stdout");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 child test stderr");
        assert!(
            stdout.contains("unexpected return code -1073741795")
                || stderr.contains("unexpected return code -1073741795"),
            "missing Windows {case} illegal-instruction status; stdout: {stdout}; stderr: {stderr}"
        );
    }
}

#[test]
fn inclusive_slice_subslice_then_index_bounds_report_isolated_traps() {
    #[cfg(target_os = "windows")]
    const CHILD: &str = "MRML_SEMANTIC_INCLUSIVE_SLICE_INDEX_TRAP_CHILD";
    let code = compile(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u32], start: usize, end: usize, index: usize) -> u32 { let selected: &mut u32 = &mut input[start..=end][index]; *selected }",
    );
    #[cfg(not(target_os = "windows"))]
    let probe: unsafe extern "C" fn(*mut u32, usize, usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    #[cfg(target_os = "windows")]
    let probe: unsafe extern "C" fn(*const usize, usize, usize, usize) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };

    #[cfg(not(target_os = "windows"))]
    {
        for (start, end, index) in [
            (0, usize::MAX, 0),
            (3, 1, 0),
            (0, 4, 0),
            (1, 3, 3),
        ] {
            let pid = unsafe { fork() };
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                let mut values = [10, 20, 30, 40];
                let _ = unsafe {
                    probe(
                        values.as_mut_ptr(),
                        values.len(),
                        start,
                        end,
                        index,
                    )
                };
                unsafe { _exit(120) }
            }
            let mut status = 0;
            assert_eq!(
                unsafe { waitpid(pid, &mut status, 0) },
                pid,
                "waitpid failed"
            );
            assert_eq!(
                status & 0x7f,
                4,
                "unexpected Unix wait status for ({start}, {end}, {index}): {status:#x}"
            );
        }
        return;
    }

    #[cfg(target_os = "windows")]
    if let Some(case) = std::env::var_os(CHILD) {
        unsafe { SetErrorMode(0x0001 | 0x0002) };
        let (start, end, index) = match case.to_str() {
            Some("inclusive-overflow") => (0, usize::MAX, 0),
            Some("reversed") => (3, 1, 0),
            Some("end") => (0, 4, 0),
            _ => (1, 3, 3),
        };
        let mut values = [10, 20, 30, 40];
        let slice = [values.as_mut_ptr() as usize, values.len()];
        let _ = unsafe { probe(slice.as_ptr(), start, end, index) };
        panic!("inclusive slice bounds trap unexpectedly returned");
    }

    #[cfg(target_os = "windows")]
    for case in ["inclusive-overflow", "reversed", "end", "index"] {
        let output = Command::new(std::env::current_exe().expect("locate semantic test binary"))
            .args([
                "--exact",
                "inclusive_slice_subslice_then_index_bounds_report_isolated_traps",
                "--nocapture",
            ])
            .env(CHILD, case)
            .output()
            .expect("launch isolated inclusive slice-bounds probe");
        assert_eq!(
            output.status.code(),
            Some(101),
            "unexpected Windows {case} test status: {}",
            output.status
        );
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 child test stdout");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 child test stderr");
        assert!(
            stdout.contains("unexpected return code -1073741795")
                || stderr.contains("unexpected return code -1073741795"),
            "missing Windows {case} illegal-instruction status; stdout: {stdout}; stderr: {stderr}"
        );
    }
}

#[test]
fn nested_branch_initializedness_matches_oracle() {
    let code = compile(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u32, choose: bool) -> u32 { let mut value: u32 = input; 'outer: loop { loop { if choose { value += 1; break 'outer; } else { value += 2; break 'outer; } } } value }",
    );
    let probe: unsafe extern "C" fn(u32, bool) -> u32 =
        unsafe { std::mem::transmute(code.pointer) };
    assert_eq!(unsafe { probe(40, true) }, 41);
    assert_eq!(unsafe { probe(40, false) }, 42);
}

#[test]
fn supported_inline_assembly_register_output_executes() {
    let code = compile(
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: u64) -> u64 { let mut output: u64 = 0; asm!(\"inc r10\", inout(\"r10\") input => output); output }",
    );
    let probe: unsafe extern "C" fn(u64) -> u64 = unsafe { std::mem::transmute(code.pointer) };
    for input in [0, 1, 40, u32::MAX as u64] {
        assert_eq!(unsafe { probe(input) }, input + 1);
    }
}

#[test]
fn checked_overflow_reports_an_isolated_trap_exit() {
    #[cfg(target_os = "windows")]
    const CHILD: &str = "MRML_SEMANTIC_OVERFLOW_CHILD";
    let code =
        compile("#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u32) -> u32 { input + 1 }");
    let probe: unsafe extern "C" fn(u32) -> u32 = unsafe { std::mem::transmute(code.pointer) };

    #[cfg(not(target_os = "windows"))]
    {
        let pid = unsafe { fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let _ = unsafe { probe(u32::MAX) };
            unsafe { _exit(120) }
        }
        let mut status = 0;
        assert_eq!(
            unsafe { waitpid(pid, &mut status, 0) },
            pid,
            "waitpid failed"
        );
        assert_eq!(status & 0x7f, 4, "unexpected Unix wait status: {status:#x}");
        return;
    }

    #[cfg(target_os = "windows")]
    if std::env::var_os(CHILD).is_some() {
        unsafe { SetErrorMode(0x0001 | 0x0002) };
        let _ = unsafe { probe(u32::MAX) };
        panic!("checked overflow unexpectedly returned");
    }

    #[cfg(target_os = "windows")]
    let output = Command::new(std::env::current_exe().expect("locate semantic test binary"))
        .args([
            "--exact",
            "checked_overflow_reports_an_isolated_trap_exit",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .output()
        .expect("launch isolated semantic trap probe");
    #[cfg(target_os = "windows")]
    let status = output.status;
    #[cfg(target_os = "windows")]
    assert!(
        !status.success(),
        "generated overflow trap unexpectedly returned"
    );
    #[cfg(target_os = "windows")]
    {
        assert_eq!(
            status.code(),
            Some(101),
            "unexpected Windows test status: {status}"
        );
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 child test stdout");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 child test stderr");
        assert!(
            stdout.contains("unexpected return code -1073741795")
                || stderr.contains("unexpected return code -1073741795"),
            "missing Windows illegal-instruction status; stdout: {stdout}; stderr: {stderr}"
        );
    }
}

#[test]
fn c_string_byte_view_lengths_and_emptiness_execute() {
    let lengths = compile(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(with_nul: bool) -> usize { if with_nul { c\"hello\".to_bytes_with_nul().len() } else { c\"hello\".to_bytes().len() } }",
    );
    let probe: unsafe extern "C" fn(bool) -> usize =
        unsafe { std::mem::transmute(lengths.pointer) };
    assert_eq!(unsafe { probe(false) }, 5);
    assert_eq!(unsafe { probe(true) }, 6);

    let empty = compile(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(with_nul: bool) -> bool { if with_nul { c\"\".to_bytes_with_nul().is_empty() } else { c\"\".to_bytes().is_empty() } }",
    );
    let probe: unsafe extern "C" fn(bool) -> bool = unsafe { std::mem::transmute(empty.pointer) };
    assert!(unsafe { probe(false) });
    assert!(!unsafe { probe(true) });
}

#[test]
fn relocated_c_string_byte_views_execute_with_exact_contents() {
    let code = compile(
        r####"#[unsafe(no_mangle)] pub extern "C" fn probe(raw: bool) -> &'static [u8] { if raw { cr##"raw\n"#text"##.to_bytes_with_nul() } else { c"hello\n".to_bytes() } }"####,
    );
    let probe: unsafe extern "C" fn(bool) -> &'static [u8] =
        unsafe { std::mem::transmute(code.pointer) };
    assert_eq!(unsafe { probe(false) }, b"hello\n");
    assert_eq!(unsafe { probe(true) }, b"raw\\n\"#text\0");
}

#[test]
fn unsupported_constructs_produce_typed_diagnostics_not_objects() {
    for source in [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(stop: bool) -> u64 { loop { loop { if stop { let value: u64 = 1; } } } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(stop: bool) -> u64 { loop { loop { if stop { return 1; 2; } } } }",
    ] {
        assert!(
            compile_source_function::<2048, 1024, 4, 4, 4, 64>(
                source,
                "probe",
                FORMAT,
                TargetLayout::X86_64
            )
            .is_err()
        );
    }
    let delayed = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u32, choose: bool) -> u32 { let value: u32; 'outer: loop { loop { if choose { value = input + 1; break 'outer; } else { value = input + 2; break 'outer; } } } value }";
    let error = compile_source_function::<2048, 1024, 4, 4, 4, 64>(
        delayed,
        "probe",
        FORMAT,
        TargetLayout::X86_64,
    )
    .unwrap_err();
    assert!(matches!(
        error.kind,
        CompileErrorKind::Codegen(CodegenErrorKind::ImmutableAssignment)
    ));
    let assembly = "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: u64) -> u64 { let mut output: u64 = 0; asm!(\"inc rbx\", inout(\"rbx\") input => output); output }";
    let error = compile_source_function::<2048, 1024, 4, 4, 4, 64>(
        assembly,
        "probe",
        FORMAT,
        TargetLayout::X86_64,
    )
    .unwrap_err();
    assert!(
        matches!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::InvalidInlineAssembly)
        ),
        "unexpected diagnostic: {error:?}"
    );
}
