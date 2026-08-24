#![no_std]

// Original MRML cases mapped to the actual rustc test suite at the installed
// nightly commit. No upstream source or expected-output text is reproduced.
//
// Reference commit: f7d782a3be46d6bb4b9792fe69a61db389ba1769
// Reference cases:
// - tests/ui/numbers-arithmetic/arith-unsigned.rs
// - tests/ui/numbers-arithmetic/div-mod.rs
// - tests/ui/numbers-arithmetic/shift.rs
// - tests/ui/numbers-arithmetic/bitwise-ops-platform.rs
// - tests/ui/numbers-arithmetic/overflowing-lsh-4.rs
// - tests/ui/numbers-arithmetic/overflowing-rsh-4.rs
// - tests/ui/numbers-arithmetic/overflowing-add.rs
// - tests/ui/numbers-arithmetic/overflowing-sub.rs
// - tests/ui/numbers-arithmetic/overflowing-mul.rs
// - tests/ui/numbers-arithmetic/overflowing-neg-nonzero.rs
// - tests/ui/numbers-arithmetic/i128-min-literal-parses.rs
// - tests/ui/consts/control-flow/short-circuit.rs
// - tests/ui/consts/control-flow/basics.rs
// - tests/ui/consts/return-in-const-fn.rs
// - tests/ui/for-loop-while/while.rs
// - tests/ui/for-loop-while/long-while.rs
// - tests/ui/for-loop-while/while-with-break.rs
// - tests/ui/for-loop-while/break.rs
// - tests/ui/for-loop-while/while-cont.rs
// - tests/ui/for-loop-while/loop-break-cont-1.rs
// - tests/ui/for-loop-while/loop-break-cont.rs
// - tests/ui/for-loop-while/loop-break-value.rs
// - tests/ui/for-loop-while/for-loop-has-unit-body.rs
// - tests/ui/expr/if-generic.rs
// - tests/ui/expr/weird-exprs.rs
// - tests/ui/binop/binops.rs
// - tests/ui/consts/min_const_fn/min_const_fn.rs
// - tests/ui/consts/const-meth-pattern.rs
// - tests/ui/consts/const_let_eq.rs
// - tests/ui/consts/const-eval/stable-metric/ctfe-simple-loop.rs
// - tests/ui/lint/unused/issue-117142-invalid-remove-parens.rs
// - tests/ui/liveness/var-defined-after-early-return.rs
// - tests/ui/codegen/issue-88043-bb-does-not-have-terminator.rs
// - tests/ui/expr/if/if-check.rs
// - tests/ui/consts/const-eval/issue-64970.rs
// - tests/ui/binding/if-let.rs
// - tests/ui/drop/dynamic-drop.rs
// - tests/ui/structs-enums/class-impl-very-parameterized-trait.rs
// - tests/ui/drop/drop-on-ret.rs
// - tests/ui/consts/const-fn-const-eval.rs
// - tests/ui/consts/const-extern-fn/const-extern-fn.rs
// - tests/ui/consts/const-negative.rs
// - tests/ui/consts/const-binops.rs
// - tests/ui/cast/constant-expression-cast-9942.rs
// - tests/ui/consts/const-block-items/assert-pass.rs
// - tests/ui/consts/const-block.rs
// - tests/ui/consts/const-blocks/const-block-in-array-size.rs
// - tests/ui/inline-const/referencing-local-variables.rs
// - tests/ui/consts/const-blocks/fn-call-in-const.rs
// - tests/ui/inline-const/const-expr-basic.rs
// - tests/ui/consts/consts-in-patterns.rs
// - tests/ui/binding/match-range.rs
// - tests/ui/binding/match-range-static.rs
// - tests/ui/match/guards.rs
// - tests/ui/match/guard-pattern-ordering-14865.rs
// - tests/ui/match/guard-arm-and-or-arm.rs
// - tests/ui/match/range-arm-and-ref-arm.rs
// - tests/ui/binding/match-pattern-bindings.rs
// - tests/ui/or-patterns/bindings-runpass-2.rs
// - tests/ui/or-patterns/missing-bindings.rs
// - tests/ui/or-patterns/inner-or-pat.rs
// - tests/ui/or-patterns/or-patterns-syntactic-pass.rs
// - tests/ui/match/large-match-mir-gen.rs
// - tests/ui/or-patterns/exhaustiveness-pass.rs
// - tests/ui/or-patterns/exhaustiveness-non-exhaustive.rs
// - tests/ui/error-codes/E0030.rs
// - tests/ui/match/match-range-fail-2.rs
// - tests/ui/consts/const-eval/const_signed_pat.rs
// - tests/ui/match/overeager-sub-match-pruning-13027.rs
// - tests/ui/half-open-range-patterns/range_pat_interactions0.rs
// - tests/ui/lint/unused_braces.rs
// - tests/ui/consts/const-fn-nested.rs
// - tests/codegen-llvm/overflow-checks.rs
// - tests/codegen-llvm/integer-overflow.rs
// - tests/codegen-llvm/abi-x86_64_sysv.rs

use mrml_rustc::{
    CodegenErrorKind, CodegenOptions, CompileErrorKind, ConstEvalError, ExecutionError,
    ExpressionErrorKind, ObjectFormat, TargetLayout, compile_source_function,
    compile_source_function_with_options,
};

fn compile(source: &str, format: ObjectFormat) -> Result<(), CompileErrorKind> {
    compile_source_function::<2048, 512, 4, 2, 4, 32>(source, "probe", format, TargetLayout::X86_64)
        .map(|_| ())
        .map_err(|error| error.kind)
}

fn compile_wide(source: &str, format: ObjectFormat) -> Result<(), CompileErrorKind> {
    compile_source_function::<4096, 3072, 4, 8, 8, 64>(
        source,
        "probe",
        format,
        TargetLayout::X86_64,
    )
    .map(|_| ())
    .map_err(|error| error.kind)
}

#[test]
fn rustc_binding_if_let_assignment_order_has_a_scalar_replacement() {
    // This original scalar case maps only the pinned test's ordered assignment
    // behavior. It does not claim support for `if let` or pattern matching.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: usize) -> usize { let mut clause: usize = 0; if value == 1 { clause = 1; } else if value == 2 { clause = 2; } else if value == 3 { clause = 3; } else { clause = 4; } clause }";
    assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_dynamic_drop_has_an_ordered_scalar_mutation_replacement() {
    // This original scalar case maps only source-ordered mutations in a
    // selected branch. It does not claim ownership, drop, allocation,
    // deferred initialization, tuples, unwinding, or coroutine support.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { let mut result = value; if value == 0 { result = 20; value + 1; result *= 2; result += 2; } else if value == 1 { result = 100; value * 3; result -= 58; } else { result = 126 / value; value + 10; result += 0; } result }";
    assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_weird_exprs_has_a_guarded_discarded_expression_replacement() {
    // The pinned test contains discarded expressions in unusual block
    // contexts. This original scalar replacement covers their ordered,
    // value-discarding behavior inside selected conditional branches only.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { let mut result = value; if value == 0 { result = 40; value + 1; result += 2; } else if value == 1 { result = 40; 84 / value; result += 2; } else { result = 40; value == 3; result += 2; } result }";
    assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_parameterized_class_has_a_scalar_mutate_then_return_replacement() {
    // The pinned method performs an expression, mutation, and return in each
    // selected branch. This original replacement covers only the scalar action
    // order; it does not claim structs, methods, generics, formatting, or
    // ownership behavior.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i32) -> bool { let mut hunger: i32 = value; if hunger > 0 { hunger + 10; hunger -= 2; return hunger == value - 2; } else { hunger - 10; hunger += 2; return hunger == value + 2; } false }";
    assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_arith_unsigned_and_div_mod_runtime_subset_reaches_native_objects() {
    let probes = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u8, divisor: u8) -> u8 { value / divisor }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u16, divisor: u16) -> u16 { value % divisor }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u32, right: u32) -> u32 { left + right * 3 }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u64, divisor: u64) -> u64 { value / divisor }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u64, divisor: u64) -> u64 { value % divisor }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u64, right: u64) -> u64 { left + right * 3 }",
    ];
    for source in probes {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_arith_unsigned_comparisons_emit_typed_bool_results() {
    let probes = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u8, right: u8) -> bool { left < right }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u16, right: u16) -> bool { left <= right }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u32, right: u32) -> bool { left > right }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u64, right: u64) -> bool { left >= right }",
    ];
    for source in probes {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_shift_and_platform_bitwise_runtime_subset_reaches_native_objects() {
    let probes = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u64, distance: u64) -> u64 { value << distance }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u64, distance: u64) -> u64 { value >> distance }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u64, right: u64) -> u64 { !(left ^ right) & 255 }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: usize, right: usize) -> usize { left | right }",
    ];
    for source in probes {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_signed_division_arithmetic_and_bitwise_cases_reach_native_objects() {
    let probes = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i8, right: i8) -> i8 { left / right + left % right }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i16, right: i16) -> i16 { left - right * 3 }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i32, right: i32) -> i32 { !(left ^ right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i64, right: i64) -> i64 { left >> right }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: isize, right: isize) -> isize { left | right }",
    ];
    for source in probes {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_negative_signed_constants_reach_native_objects() {
    let probes = [
        "static OFFSET: isize = -1; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: isize) -> isize { value + OFFSET }",
        "const MINIMUM: i8 = -128; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i8) -> i8 { value | MINIMUM }",
        "const OFFSET: i32 = -2; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i32) -> i32 { value + OFFSET }",
        "static OFFSET: isize = -4 + 3; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: isize) -> isize { value + OFFSET }",
        "static FACTOR: i32 = -3 * 3; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i32) -> i32 { value + FACTOR }",
        "static QUOTIENT: i16 = 3 / -1; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i16) -> i16 { value + QUOTIENT }",
        "static MASK: i8 = -8 | 3; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i8) -> i8 { value & MASK }",
    ];
    for source in probes {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }

    let mismatch = "const OFFSET: i32 = -1; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i64) -> i64 { value + OFFSET }";
    assert_eq!(
        compile(mismatch, ObjectFormat::Elf64),
        Err(CompileErrorKind::Codegen(
            mrml_rustc::CodegenErrorKind::RuntimeTypeMismatch
        ))
    );
}

#[test]
fn rustc_overflow_checks_codegen_modes_emit_distinct_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u8) -> u8 { value + 1 }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i8) -> i8 { value + 1 }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i16) -> i16 { -value }",
    ];
    for source in sources {
        for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
            let checked = compile_source_function_with_options::<2048, 512, 4, 2, 4, 32>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
                CodegenOptions::CHECKED,
            )
            .unwrap();
            let wrapping = compile_source_function_with_options::<2048, 512, 4, 2, 4, 32>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
                CodegenOptions::WRAPPING,
            )
            .unwrap();
            assert!(checked.len() > wrapping.len());
            assert_ne!(checked.bytes(), wrapping.bytes());
        }
    }
}

#[test]
fn rustc_unchecked_shift_masks_distance_to_the_integer_width() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u8, distance: u8) -> u8 { value << distance }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u16, distance: u16) -> u16 { value >> distance }",
    ];
    for source in sources {
        for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
            assert!(
                compile_source_function_with_options::<2048, 512, 4, 2, 4, 32>(
                    source,
                    "probe",
                    format,
                    TargetLayout::X86_64,
                    CodegenOptions::WRAPPING,
                )
                .is_ok()
            );
        }
    }
}

#[test]
fn rustc_boolean_short_circuit_cases_reach_both_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> bool { true || (1 / 0 > 0) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> bool { false && (1 / 0 > 0) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: bool, right: bool) -> bool { left && !right }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u64, guard: bool) -> bool { guard || (10 / value > 1) }",
    ];
    for source in sources {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_shift_static_initializers_reach_both_native_objects() {
    let source = "static SHIFTED: usize = 10_usize << 4_usize; #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> usize { SHIFTED }";
    assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_x86_64_abi_stack_arguments_reach_native_objects() {
    let windows = "#[unsafe(no_mangle)] pub extern \"C\" fn fifth(a: u64, b: u64, c: u64, d: u64, value: u64) -> u64 { value + a }";
    assert!(
        compile_source_function::<2048, 512, 4, 8, 4, 32>(
            windows,
            "fifth",
            ObjectFormat::Coff,
            TargetLayout::X86_64,
        )
        .is_ok()
    );

    let system_v = "#[unsafe(no_mangle)] pub extern \"C\" fn seventh(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, value: u64) -> u64 { value + a }";
    assert!(
        compile_source_function::<2048, 512, 4, 8, 4, 32>(
            system_v,
            "seventh",
            ObjectFormat::Elf64,
            TargetLayout::X86_64,
        )
        .is_ok()
    );
}

#[test]
fn rustc_deep_array_stack_slots_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: [u64; 8], after: u64) -> u64 { let copied = values; copied[7] + values[0] + after }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: [u8; 4], after: u8) -> u8 { values[0] + after }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_shift_cast_distance_reaches_both_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u8, distance: u8) -> u8 { value >> distance as usize }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> usize { -1000isize as usize >> 3usize }",
    ];
    for source in sources {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_div_mod_typed_locals_reach_both_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> isize { let x: isize = 15; let y: isize = 4; x / y + x % y }";
    assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_parameterized_typed_locals_reach_both_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u64) -> u64 { let doubled: u64 = value * 2; let adjusted: u64 = doubled + 1; adjusted + value }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u64, enabled: bool) -> bool { let positive: bool = value > 0; enabled && positive }",
    ];
    for source in sources {
        assert!(
            compile_source_function::<2048, 1024, 4, 4, 4, 64>(
                source,
                "probe",
                ObjectFormat::Elf64,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
        assert!(
            compile_source_function::<2048, 1024, 4, 4, 4, 64>(
                source,
                "probe",
                ObjectFormat::Coff,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_mutable_bitwise_locals_reach_both_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> isize { let mut a: isize = 1; let mut b: isize = 2; a ^= b; b ^= a; a = a ^ b; a | b }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u64) -> u64 { let mut x: u64 = value; x ^= 255; x += 1; x }",
    ];
    for source in sources {
        assert!(
            compile_source_function::<2048, 1024, 4, 4, 4, 64>(
                source,
                "probe",
                ObjectFormat::Elf64,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
        assert!(
            compile_source_function::<2048, 1024, 4, 4, 4, 64>(
                source,
                "probe",
                ObjectFormat::Coff,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_increment_decrement_and_inferred_local_cases_reach_native_objects() {
    // Mapped to i8-incr.rs, u8-incr.rs, u8-incr-decr.rs, u32-decr.rs,
    // i32-sub.rs, and the inferred binding form in short-circuit-let.rs.
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i8 { let mut x: i8 = -12; x = x + 1; x = x - 1; x }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { let mut x: u8 = 12; x = x + 1; x = x - 1; x }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { let mut x: u8 = 19; let mut y: u8 = 35; x = x + 7; y = y - 9; x }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { let mut word: u32 = 200000; word = word - 1; word }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i32 { let mut x: i32 = -400; x = 0 - x; x }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i32 { let mut x = 0; x += 1; x }",
    ];
    for source in sources {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_const_control_flow_if_expressions_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u32, right: u32) -> u32 { if left < right { right - left } else { left - right } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u64, guard: bool) -> u64 { if guard { value } else { 10 / value } }",
        "const X: u32 = 4; const Y: u32 = 5; #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { if X < Y { Y - X } else { X - Y } }",
    ];
    for source in sources {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_explicit_tail_return_reaches_native_objects() {
    let source =
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: usize) -> usize { return value; }";
    assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_const_control_flow_conditional_return_reaches_native_objects() {
    // Maps the base-case conditional return shape in consts/control-flow/basics.rs.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u64, stop: bool) -> u64 { let adjusted: u64 = value + 1; if stop { return adjusted; } adjusted + 1 }";
    assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_scalar_while_mutation_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: isize) -> isize { let mut y: isize = 0; while y < limit { y = y + 1; } y }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: isize) -> isize { let mut i: isize = 0; while i < limit { i += 1; } i }",
    ];
    for source in sources {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_long_while_loop_local_has_an_executable_replacement() {
    // Original scalar replacement for the per-iteration local declaration in
    // tests/ui/for-loop-while/long-while.rs at the pinned nightly commit. The
    // upstream print-free unused binding is strengthened here by using the
    // scoped value before each backedge.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u32, stop: u32) -> u32 { let mut i: u32 = 0; let mut total: u32 = 0; while i < limit { let current: u32 = i + 1; current + 10; i = current; if i % 2 == 0 { continue; } total += current; if i == stop { break; } } total }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<2048, 1024, 4, 4, 4, 64>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_while_with_break_conditional_block_has_an_executable_replacement() {
    // Original scalar replacement for the local/action/break ordering in
    // tests/ui/for-loop-while/while-with-break.rs at the pinned nightly commit.
    // Allocation, vectors, destructors, printing, and drop elaboration are not
    // claimed by this scalar control-flow slice.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u32, stop: u32) -> u32 { let mut i: u32 = 0; let mut total: u32 = 0; while i < limit { let current: u32 = i + 1; i = current; if i % 2 == 0 { let skipped: u32 = current; skipped + 10; continue; } if i == stop { let selected: u32 = current; selected + 20; total += selected; break; } total += current; } total }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<2048, 1536, 4, 4, 4, 64>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_loop_guarded_fallthrough_actions_have_an_executable_replacement() {
    // Original scalar replacement for the guarded mutation and subsequent
    // fallthrough order in tests/ui/for-loop-while/loop-no-reinit-needed-post-bot.rs
    // at the pinned nightly commit. Moves, destructors, user-defined calls, and
    // bottom-typed expressions are outside this control-flow slice.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u32) -> u32 { let mut i: u32 = 0; let mut total: u32 = 0; while i < limit { i += 1; if i % 3 == 0 { let selected: u32 = i; total += selected; } total += 1; } total }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<2048, 1536, 4, 4, 4, 64>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_loop_if_else_actions_have_an_executable_replacement() {
    // Original scalar replacement for the if/else loop ordering in
    // tests/ui/for-loop-while/loop-no-reinit-needed-post-bot.rs at the pinned
    // nightly commit. Moves, destructors, user-defined calls, and bottom-typed
    // expressions remain outside this control-flow slice.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u32) -> u32 { let mut i: u32 = 0; let mut total: u32 = 0; while i < limit { i += 1; if i % 3 == 0 { let selected: u32 = i; total += selected; } else { let fallback: u32 = 1; total += fallback; } total += 1; } total }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<2048, 1536, 4, 4, 4, 64>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_loop_else_if_chain_has_an_executable_replacement() {
    // Original scalar replacement for ordered alternative loop arms in
    // tests/ui/for-loop-while/loop-no-reinit-needed-post-bot.rs at the pinned
    // nightly commit. Moves, destructors, calls, and bottom types are excluded.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u32) -> u32 { let mut i: u32 = 0; let mut total: u32 = 0; while i < limit { i += 1; if i % 3 == 0 { let selected: u32 = i; total += selected; } else if i % 2 == 0 { let even: u32 = 2; total += even; } else { let fallback: u32 = 1; total += fallback; } } total }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<2048, 1536, 4, 4, 4, 64>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_loop_alternative_terminals_have_an_executable_replacement() {
    // Original scalar replacement for conditional break/continue ordering in
    // tests/ui/for-loop-while/loop-break-cont.rs and the alternative continue
    // edge in loop-no-reinit-needed-post-bot.rs at the pinned nightly commit.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u32, mode: u32) -> u32 { let mut i: u32 = 0; let mut total: u32 = 0; while i < limit { i += 1; if mode == 0 { let selected: u32 = i; total += selected; break; } else if mode == 1 { let repeated: u32 = 2; total += repeated; continue; } else if mode == 2 { let stopped: u32 = 3; total += stopped; break; } else { let returned: u32 = i + 40; return returned; } } total }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<2048, 1536, 4, 4, 4, 64>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_nested_unit_loop_has_an_executable_replacement() {
    // Original executable replacement for the inner `loop { break; }` unit
    // behavior in tests/ui/for-loop-while/nested-loop-break-unit.rs and the
    // immediate exit in loop-break-cont-1.rs at the pinned nightly commit.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u32) -> u32 { let mut i: u32 = 0; while i < limit { loop { break; } i += 1; } i }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<1024, 768, 2, 2, 2, 48>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_nested_loop_actions_have_an_executable_replacement() {
    // Original scalar extension of the inner-break scope observed in pinned
    // tests/ui/for-loop-while/nested-loop-break-unit.rs. The inner body uses
    // only MRML's bounded scalar local, expression, and assignment subset.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u32) -> u32 { let mut i: u32 = 0; let mut total: u32 = 0; while i < limit { loop { let selected: u32 = i + 1; selected + 10; total += selected; break; } i += 1; } total }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<2048, 1536, 4, 4, 4, 64>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_repeated_inner_loop_has_an_executable_replacement() {
    // Original bounded scalar extension of the nested exit targeting in pinned
    // tests/ui/for-loop-while/nested-loop-break-unit.rs. Each outer iteration
    // runs three inner iterations before the inner conditional break.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u32) -> u32 { let mut outer: u32 = 0; let mut inner: u32 = 0; let mut total: u32 = 0; while outer < limit { loop { let selected: u32 = inner + 1; inner = selected; total += selected; if selected == 3 { break; } } outer += 1; inner = 0; } total }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<2048, 1536, 4, 4, 4, 64>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_inner_loop_continue_has_an_executable_replacement() {
    // Original scalar replacement for the nested continue/break targeting in
    // pinned tests/ui/for-loop-while/loop-break-cont.rs. Even inner values take
    // the inner backedge before the later accumulator and break operations.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u32) -> u32 { let mut outer: u32 = 0; let mut inner: u32 = 0; let mut total: u32 = 0; while outer < limit { loop { let selected: u32 = inner + 1; inner = selected; if selected % 2 == 0 { continue; } total += selected; if selected == 5 { break; } } outer += 1; inner = 0; } total }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<2048, 1536, 4, 4, 4, 64>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_nested_while_has_an_executable_replacement() {
    // Original bounded scalar replacement for nested while flow in pinned
    // tests/ui/for-loop-while/while.rs and nested-loop-break-unit.rs.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u32) -> u32 { let mut outer: u32 = 0; let mut inner: u32 = 0; let mut total: u32 = 0; while outer < limit { while inner < 3 { inner += 1; total += inner; } outer += 1; inner = 0; } total }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<2048, 1536, 4, 4, 4, 64>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_nested_while_controls_have_an_executable_replacement() {
    // Original scalar replacement combining nested while, continue, and break
    // flow from pinned tests/ui/for-loop-while/while.rs and loop-break-cont.rs.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(outer_limit: u32, inner_limit: u32) -> u32 { let mut outer: u32 = 0; let mut inner: u32 = 0; let mut total: u32 = 0; while outer < outer_limit { while inner < inner_limit { let selected: u32 = inner + 1; inner = selected; if selected % 2 == 0 { continue; } total += selected; if selected == 5 { break; } } outer += 1; inner = 0; } total }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<3072, 2048, 4, 4, 4, 96>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_unconditional_break_in_nested_while_has_an_executable_replacement() {
    // Original scalar replacement for the nested unconditional exit targeting
    // in pinned tests/ui/for-loop-while/break.rs and nested-loop-break-unit.rs.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u32, enter: bool) -> u32 { let mut i: u32 = 0; while i < limit { while enter { break; } i += 1; } i }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<1536, 1024, 4, 4, 4, 48>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_return_from_nested_while_has_an_executable_replacement() {
    // Original scalar replacement for nested return cleanup in pinned
    // tests/ui/for-loop-while/loop-no-reinit-needed-post-bot.rs and the return
    // control family already mapped from consts/control-flow/basics.rs.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u32, enter: bool) -> u32 { let mut i: u32 = 0; while i < limit { while enter { let selected: u32 = i + 40; return selected; } i += 1; } i }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<1536, 1024, 4, 4, 4, 48>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_unit_return_from_nested_while_has_an_executable_replacement() {
    // Original nested-loop replacement for the valueless return shape in
    // pinned tests/ui/codegen/issue-88043-bb-does-not-have-terminator.rs.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u32, enter: bool) { let mut i: u32 = 0; while i < limit { while enter { let selected: u32 = i + 1; selected + 10; return; } i += 1; } }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<1536, 1024, 4, 4, 4, 48>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_conditional_unit_return_from_nested_while_has_an_executable_replacement() {
    // Original bounded scalar replacement for the conditional unit return in
    // pinned tests/ui/codegen/issue-88043-bb-does-not-have-terminator.rs.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u32, stop: u32) { let mut outer: u32 = 0; let mut inner: u32 = 0; while outer < limit { while inner < 3 { inner += 1; if inner == stop { return; } } outer += 1; inner = 0; } }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<2048, 1536, 4, 4, 4, 64>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_conditional_typed_return_from_nested_while_has_an_executable_replacement() {
    // Original scalar replacement for nested cleanup and guarded return in
    // pinned tests/ui/liveness/loop-no-reinit-needed-post-bot.rs.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u32, stop: u32) -> u32 { let mut outer: u32 = 0; let mut inner: u32 = 0; while outer < limit { while inner < 3 { inner += 1; if inner == stop { return outer + 40; } } outer += 1; inner = 0; } outer }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<2048, 1536, 4, 4, 4, 64>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_ordered_conditional_returns_in_nested_while_have_an_executable_replacement() {
    // Original bounded replacement for ordered guarded return edges in pinned
    // tests/ui/liveness/loop-no-reinit-needed-post-bot.rs and
    // tests/ui/consts/control-flow/basics.rs.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u32, first: u32, second: u32) -> u32 { let mut outer: u32 = 0; let mut inner: u32 = 0; while outer < limit { while inner < 3 { inner += 1; if inner == first { return outer + 40; } if inner == second { return outer + 50; } } outer += 1; inner = 0; } outer }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<3072, 2048, 4, 4, 4, 96>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_nested_continue_precedes_later_return() {
    // Original scalar replacement for ordered continue/return control in
    // pinned tests/ui/for-loop-while/loop-break-cont.rs and nested cleanup in
    // tests/ui/liveness/loop-no-reinit-needed-post-bot.rs.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u32, skip: u32, stop: u32) -> u32 { let mut outer: u32 = 0; let mut inner: u32 = 0; while outer < limit { while inner < 3 { inner += 1; if inner == skip { continue; } if inner == stop { return outer + 40; } } outer += 1; inner = 0; } outer }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<3072, 2048, 4, 4, 4, 96>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_multiple_ordered_nested_continues_have_an_executable_replacement() {
    // Original scalar replacement for repeated ordered continue edges in
    // pinned tests/ui/for-loop-while/loop-break-cont.rs.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u32, first: u32, second: u32) -> u32 { let mut outer: u32 = 0; let mut inner: u32 = 0; let mut total: u32 = 0; while outer < limit { while inner < 5 { inner += 1; if inner == first { continue; } if inner == second { continue; } total += inner; } outer += 1; inner = 0; } total }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<3072, 2048, 4, 4, 4, 96>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_positioned_nested_breaks_have_an_executable_replacement() {
    // Original scalar replacement for ordered conditional break edges in
    // pinned tests/ui/for-loop-while/break.rs and loop-break-cont.rs.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u32, first: u32, second: u32) -> u32 { let mut outer: u32 = 0; let mut inner: u32 = 0; let mut total: u32 = 0; while outer < limit { while inner < 5 { inner += 1; if inner == first { break; } total += inner; if inner == second { break; } } outer += 1; inner = 0; } total }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<3072, 2048, 4, 4, 4, 96>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_unconditional_nested_continue_has_an_executable_replacement() {
    // Original scalar replacement for the unconditional inner continue edge in
    // pinned tests/ui/for-loop-while/loop-break-cont.rs.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u32) -> u32 { let mut outer: u32 = 0; let mut inner: u32 = 0; while outer < limit { while inner < 3 { let selected: u32 = inner + 1; inner = selected; continue; let unreachable: u32 = 10 / 0; unreachable; return unreachable; } outer += 1; inner = 0; } outer }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<2048, 1536, 4, 4, 4, 64>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_inner_loop_with_conditional_only_exits_has_an_executable_replacement() {
    // Original scalar replacement for conditional backedges and return exits in
    // pinned tests/ui/for-loop-while/loop-break-cont.rs.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(enter: bool, stop: u32) -> u32 { let mut inner: u32 = 0; while enter { loop { inner += 1; if inner < stop { continue; } if inner == stop { return inner; } } } 0 }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<2048, 1536, 4, 4, 4, 64>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_diverging_empty_inner_loop_has_an_executable_replacement() {
    // Original scalar replacement for the diverging empty loop admitted by
    // pinned tests/ui/for-loop-while/loop-break-cont.rs.
    for source in [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(enter: bool) -> u32 { while enter { loop {} } 42 }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(enter: bool) -> u32 { while enter { loop { 1; } } 42 }",
    ] {
        for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
            assert!(
                compile_source_function::<1536, 1024, 4, 4, 4, 48>(
                    source,
                    "probe",
                    format,
                    TargetLayout::X86_64,
                )
                .is_ok()
            );
        }
    }
}

#[test]
fn rustc_empty_while_and_top_level_diverging_loops_have_executable_replacements() {
    // Original scalar replacements for empty and diverging loop bodies in
    // pinned tests/ui/for-loop-while/loop-break-cont.rs.
    for source in [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(enter: bool) -> u32 { while enter {} 42 }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { loop {} }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { loop { 1; } }",
    ] {
        for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
            assert!(
                compile_source_function::<1536, 1024, 4, 4, 4, 48>(
                    source,
                    "probe",
                    format,
                    TargetLayout::X86_64,
                )
                .is_ok()
            );
        }
    }
}

#[test]
fn rustc_diverging_helper_signatures_have_an_executable_replacement() {
    // Original bounded replacement for never-returning Rust helpers and their
    // coercion into an ordinary scalar branch result.
    let source = "fn diverge(seed: u32) -> ! { let mut value: u32 = seed; loop { value += 1; } } #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32, diverges: bool) -> u32 { let selected: u32 = if diverges { diverge(value) } else { value }; selected + 1 }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<2048, 1536, 4, 4, 4, 64>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_bounded_scalar_tuples_have_an_executable_replacement() {
    // Original heterogeneous scalar-tuple replacement covering tuple helper
    // arguments, nested returns, early frame cleanup, and numbered projection.
    let source = "fn identity(value: (u16, bool, char)) -> (u16, bool, char) { value } fn choose(value: (u16, bool, char), alternate: (u16, bool, char), first: bool) -> (u16, bool, char) { let copy: (u16, bool, char) = identity(value); if first { return copy; } identity(alternate) } #[unsafe(no_mangle)] pub extern \"C\" fn probe(first: u16, second: u16, flag: bool, choose_first: bool) -> u64 { let selected: (u16, bool, char) = choose((first, flag, 'x'), (second, !flag, 'y'), choose_first,); selected.0 as u64 + if selected.1 { 100 } else { 0 } + if selected.2 == 'x' { 10 } else { 20 } }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<4096, 3072, 8, 8, 8, 96>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_tuple_control_flow_is_lazy_and_single_evaluation() {
    // Original tuple-control replacement with an observably mutating condition;
    // each selected conditional or value-loop tuple evaluates it exactly once.
    let source = "fn toggle(flag: &mut bool) -> bool { *flag = !*flag; *flag } fn choose(value: (u16, bool, char), alternate: (u16, bool, char), flag: &mut bool, via_loop: bool) -> (u16, bool, char) { if via_loop { return loop { if toggle(flag) { break value; } break alternate; }; } if toggle(flag) { value } else { alternate } } #[unsafe(no_mangle)] pub extern \"C\" fn probe(first: u16, second: u16, initial: bool, via_loop: bool) -> u64 { let mut state: bool = initial; let selected: (u16, bool, char) = choose((first, false, 'x'), (second, true, 'y'), &mut state, via_loop); selected.0 as u64 + if selected.1 { 100 } else { 0 } + if selected.2 == 'x' { 10 } else { 20 } + if state { 1000 } else { 0 } }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<4096, 3072, 8, 8, 8, 128>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_tuple_sequences_preserve_single_evaluation() {
    // Original aggregate-sequencing replacement. Observable mutations before
    // tuple materialization and direct projection must each execute once.
    let source = "fn bump(value: &mut u16) { *value += 1; } fn sequenced(value: (u16, bool, char), count: &mut u16) -> (u16, bool, char) { bump(count); value } #[unsafe(no_mangle)] pub extern \"C\" fn probe(first: u16, second: u16, flag: bool) -> u64 { let mut count: u16 = 0; let selected: (u16, bool, char) = sequenced({ bump(&mut count); (first, flag, 'x') }, &mut count); let projected: u16 = { bump(&mut count); (second, !flag) }.0; selected.0 as u64 + projected as u64 + count as u64 * 100 + if selected.1 { 10 } else { 0 } + if selected.2 == 'x' { 1 } else { 0 } }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<4096, 3072, 8, 8, 8, 128>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_mutable_tuple_fields_reach_native_objects() {
    // Original bounded tuple-place replacement covering heterogeneous direct
    // and compound stores while a later scalar local occupies the stack.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: u16, second: u16, flag: bool) -> u64 { let mut values: (u16, bool, char) = (first, flag, 'x'); let guard: u16 = second; values.0 += guard; values.1 ^= true; values.2 = 'z'; values.0 as u64 + guard as u64 + if values.1 { 100 } else { 0 } + if values.2 == 'z' { 1 } else { 0 } }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<4096, 3072, 8, 8, 8, 128>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_nested_assignment_operands_reach_native_objects() {
    // Original bounded replacement for left-to-right compound RHS evaluation,
    // projected tuple reads, and lazy conditional operands at assignment sites.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(seed: u16, left: u16, right: u16, choose: bool) -> u16 { let mut result: u16 = seed; let pair: (u16, bool) = (right, choose); result = left + pair.0 * right; result = if choose { result ^ right } else { result ^ left }; result }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<2048, 1536, 8, 8, 8, 64>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_nested_assignment_indexes_reach_native_objects() {
    // Original bounded replacement for reference-index and by-value local-array
    // materialization reads nested inside assignment RHS expressions.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(seed: u16, values: &[u16; 2], index: usize, left: u16, right: u16) -> u16 { let mut result: u16 = seed; let local: [u16; 2] = [left, right]; result = values[index] + local[index]; result = result ^ local[1]; result }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<3072, 2048, 8, 8, 8, 96>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_scalar_initializer_read_order_reaches_native_objects() {
    // Original bounded replacement for initializer-before-binding scope,
    // sequential shadowing, and lazy scalar initializer branches.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u16, left: u16, right: u16, choose: bool) -> u16 { let first: u16 = input + left; let first: u16 = first + right; let selected: u16 = if choose { first ^ left } else { input ^ right }; selected }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<2048, 1536, 8, 8, 8, 64>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_scoped_expression_statement_reads_reach_native_objects() {
    // Original bounded replacement for top-level, conditional-arm, and loop
    // expression statements interleaved with scoped declarations.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u16, left: u16, right: u16, choose: bool) -> u16 { let first: u16 = input + left; if choose { let branch: u16 = first + right; branch ^ left; } else { first ^ input; } while choose { first ^ right; break; } first ^ left; first }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<3072, 2048, 8, 8, 8, 96>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_condition_return_and_scalar_tail_reads_reach_native_objects() {
    // Original bounded replacement for source-ordered branch/loop conditions,
    // conditional return values, and a final scalar tail.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u16, choose: bool, limit: u16) -> u16 { let first: u16 = input + 1; if choose { return first + input; } while first < limit { if first == input { let returned: u16 = first + limit; return returned + input; } break; } first + limit }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<3072, 2048, 8, 8, 8, 96>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_labeled_statement_loop_controls_have_an_executable_replacement() {
    // Original scalar replacement for same-loop labels in pinned
    // tests/ui/for-loop-while/loop-break-value.rs and loop-break-cont.rs.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u32, stop: u32) -> u32 { let mut i: u32 = 0; let mut total: u32 = 0; 'count: while i < limit { i += 1; if i % 2 == 0 { continue 'count; } else if i == stop { break 'count; } total += i; } 'once: loop { break 'once; } total }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<3072, 2048, 4, 4, 4, 96>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_cross_nested_labeled_controls_have_an_executable_replacement() {
    // Original scalar replacement for nested label targeting in pinned
    // tests/ui/for-loop-while/loop-break-value.rs and loop-break-cont.rs.
    for source in [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u32, stop: u32) -> u32 { let mut outer: u32 = 0; let mut total: u32 = 0; 'outer: while outer < limit { outer += 1; 'inner: loop { let selected: u32 = outer; if selected == 0 { continue 'inner; } if selected % 2 == 0 { continue 'outer; } if selected == stop { break 'outer; } break 'inner; } total += outer; } total }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u32) -> u32 { let mut outer: u32 = 0; 'outer: while outer < limit { outer += 1; 'inner: loop { continue 'outer; } } outer }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(enter: bool) -> u32 { let mut outer: u32 = 0; 'outer: while enter { outer += 1; 'inner: loop { break 'outer; } } outer }",
    ] {
        for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
            assert!(
                compile_source_function::<4096, 3072, 4, 4, 4, 128>(
                    source,
                    "probe",
                    format,
                    TargetLayout::X86_64,
                )
                .is_ok()
            );
        }
    }
}

#[test]
fn rustc_const_function_declarations_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub const extern \"C\" fn probe(value: usize) -> usize { return value; }",
        "#[unsafe(no_mangle)] pub const extern \"C\" fn probe(left: usize, right: usize) -> usize { left + right }",
        "#[unsafe(no_mangle)] pub const extern \"C\" fn probe(value: u8) -> u8 { value + 1 }",
    ];
    for source in sources {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_integer_const_function_calls_feed_native_objects() {
    let sources = [
        "const fn add(left: usize, right: usize) -> usize { left + right } const SUM: usize = add(40, 2); #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: usize) -> usize { value + SUM }",
        "const fn difference(left: u32, right: u32) -> u32 { left - right } const DELTA: u32 = difference(50, 8); #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { value + DELTA }",
        "const fn combine(a: u8, b: u8) -> u8 { a + b } const TOTAL: u8 = combine(30, 12); #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u8) -> u8 { value + TOTAL }",
        "const fn adjust(value: i32, offset: i32) -> i32 { value + offset } const TOTAL: i32 = adjust(-8, 50); #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i32) -> i32 { value + TOTAL }",
        "const fn minimum(value: i8) -> i8 { value } const MINIMUM: i8 = minimum(-128); #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i8) -> i8 { value | MINIMUM }",
        "const fn sub(left: u32, right: u32) -> u32 { left - right } const RESULT: u32 = sub(sub(88, 44), 22); #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { value + RESULT }",
        "const fn add(left: u8, right: u8) -> u8 { left + right } const RESULT: u8 = if true { add(20, 1) * 2 } else { add(255, 1) }; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u8) -> u8 { value + RESULT }",
    ];
    for source in sources {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_boolean_const_function_calls_feed_native_objects() {
    let sources = [
        "const fn invert(value: bool) -> bool { !value } const FLAG: bool = invert(false); #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: bool) -> bool { value && FLAG }",
        "const fn both(left: bool, right: bool) -> bool { left && right } const FLAG: bool = both(true, true); #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: bool) -> bool { value && FLAG }",
        "const fn positive(value: i32) -> bool { value > 0 } const FLAG: bool = positive(42); #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: bool) -> bool { value && FLAG }",
    ];
    for source in sources {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
    let choose = "const fn choose(condition: bool, left: u8, right: u8) -> u8 { if condition { left } else { right } } const VALUE: u8 = choose(true, 42, 0); #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u8) -> u8 { value + VALUE }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<2048, 512, 4, 4, 4, 32>(
                choose,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_recursive_integer_const_function_call_feeds_native_objects() {
    let source = "const fn gcd(left: u32, right: u32) -> u32 { if right == 0 { left } else { gcd(right, left % right) } } const VALUE: u32 = gcd(48, 18); #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { value + VALUE }";
    assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_statement_bodied_const_function_call_feeds_native_objects() {
    let sources = [
        "const fn identity(value: usize) -> usize { return value; } const VALUE: usize = identity(42); #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: usize) -> usize { value + VALUE }",
        "const fn adjust(value: i32) -> i32 { let offset: i32 = 2; if value < 0 { return -value + offset; } value + offset } const VALUE: i32 = adjust(-40); #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i32) -> i32 { value + VALUE }",
        "const fn enabled(value: bool) -> bool { let inverted: bool = !value; if inverted { return true; } false } const FLAG: bool = enabled(false); #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: bool) -> bool { value && FLAG }",
    ];
    for source in sources {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_mutable_scalar_const_function_locals_feed_native_objects() {
    let sources = [
        "const fn mutate(value: u32) -> u32 { let mut result: u32 = value; result += 2; result *= 2; result -= 42; result } const VALUE: u32 = mutate(40); #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { value + VALUE }",
        "const fn toggle(value: bool) -> bool { let mut result: bool = value; result ^= true; result } const FLAG: bool = toggle(false); #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: bool) -> bool { value && FLAG }",
        "const fn swap() -> u8 { let mut left: u8 = 1; let mut right: u8 = 2; left ^= right; right ^= left; left ^= right; left } const VALUE: u8 = swap(); #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u8) -> u8 { value + VALUE }",
    ];
    for source in sources {
        for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
            assert!(
                compile_source_function::<2048, 512, 4, 4, 4, 32>(
                    source,
                    "probe",
                    format,
                    TargetLayout::X86_64,
                )
                .is_ok()
            );
        }
    }
}

#[test]
fn rustc_const_function_statement_loops_feed_native_objects() {
    let sources = [
        "const fn count(limit: u32) -> u32 { let mut index: u32 = 0; while index < limit { index += 1; } index } const VALUE: u32 = count(35); #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { value + VALUE }",
        "const fn even_sum(limit: u32) -> u32 { let mut index: u32 = 0; let mut total: u32 = 0; while index < limit { index += 1; if index % 2 != 0 { continue; } total += index; if total >= 42 { break; } } total } const VALUE: u32 = even_sum(20); #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { value + VALUE }",
        "const fn until() -> u32 { let mut value: u32 = 0; loop { value += 1; if value == 42 { break; } } value } const VALUE: u32 = until(); #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { value + VALUE }",
        "const fn prime(value: u32) -> bool { let mut divisor: u32 = 3; if value % 2 == 0 { return false; } loop { if value % divisor == 0 { return false; } if divisor * divisor > value { return true; } divisor += 2; } false } const VALUE: u32 = if prime(113) { 42 } else { 0 }; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { value + VALUE }",
        "const fn immediate() -> u32 { loop { return 42; } } const VALUE: u32 = immediate(); #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { value + VALUE }",
        "const fn staged(limit: u32) -> u32 { let mut value: u32 = 0; while value < limit { value += 1; } value *= 2; value } const VALUE: u32 = staged(21); #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { value + VALUE }",
        "const fn classify(limit: u32) -> u32 { let mut value: u32 = 0; while value < limit { value += 1; } if value == 42 { return 7; } value += 1; value } const VALUE: u32 = classify(42); #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { value + VALUE }",
    ];
    for source in sources {
        for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
            let result = compile_source_function::<2048, 512, 4, 4, 4, 48>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            );
            assert!(result.is_ok(), "{source}: {result:?}");
        }
    }
}

#[test]
fn runtime_interleaved_statement_order_reaches_native_objects() {
    for source in [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u32) -> u32 { let mut value: u32 = 0; while value < limit { value += 1; } value *= 2; value }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u32) -> u32 { let mut value: u32 = 0; while value < limit { value += 1; } if value == 42 { return 7; } value += 1; value }",
    ] {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_sequential_while_loops_reach_native_objects() {
    // Original scalar probe for the two consecutive while-loop shape exercised
    // by tests/ui/for-loop-while/while.rs at the pinned nightly commit.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: u32, second: u32) -> u32 { let mut value: u32 = 0; while value < first { value += 1; } while value < second { value += 1; } value }";
    assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_post_loop_local_binding_reaches_native_objects() {
    // Original scalar replacement for the loop-then-binding statement order
    // present in tests/ui/for-loop-while/break.rs at the pinned nightly commit.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u32) -> u32 { let mut value: u32 = 0; while value < limit { value += 1; } let offset: u32 = value + 2; offset * 2 }";
    assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_guarded_local_binding_reaches_native_objects() {
    // Original scalar replacement for the early-return-then-binding order in
    // tests/ui/liveness/var-defined-after-early-return.rs and the scalar const
    // shape in tests/ui/consts/control-flow/basics.rs at the pinned commit.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32, stop: bool) -> u32 { if stop { return 7; } let adjusted: u32 = value + 1; adjusted * 2 }";
    assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_drop_on_return_scoped_local_replacement() {
    // Original scalar replacement for the branch-local-before-return order in
    // tests/ui/drop/drop-on-ret.rs at the pinned nightly commit. Strings,
    // allocation, destructors, and drop elaboration are outside this slice.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32, stop: bool) -> u32 { if stop { let selected: u32 = value + 1; selected + 10; return selected; } value * 2 }";
    assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_unconditional_early_return_reaches_native_objects() {
    // Original scalar replacement for the return-before-later-declarations
    // control-flow boundary in tests/ui/liveness/var-defined-after-early-return.rs
    // at the pinned nightly commit.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { let adjusted: u32 = value + 1; return adjusted; let unreachable: u32 = value + 2; unreachable }";
    assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_valueless_loop_return_reaches_native_objects() {
    // Original scalar replacement for the terminating loop branch in
    // tests/ui/codegen/issue-88043-bb-does-not-have-terminator.rs at the
    // pinned nightly commit.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(stop: bool) { loop { if stop { return; } } }";
    assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_exhaustive_conditional_returns_reach_native_objects() {
    // Original scalar replacement for the exhaustive else-if return chain in
    // tests/ui/expr/if/if-check.rs at the pinned nightly commit.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { if value == 0 { return 42; } else if value == 1 { return value + 41; } else if value == 2 { return 84 / value; } else { return 126 / value; } }";
    assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_non_exhaustive_else_if_returns_reach_native_objects() {
    // Original scalar replacement for the returning else-if chain with
    // fallthrough in tests/ui/expr/weird-exprs.rs at the pinned nightly commit.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { if value == 0 { return 42; } else if value == 1 { return 42 / value; } 84 / value }";
    assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_conditional_mutation_reaches_native_objects() {
    // Original scalar replacement for the guarded assignment in
    // tests/ui/consts/const-eval/issue-64970.rs at the pinned nightly commit.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32, select: bool) -> u32 { let mut result = value; if select { result = 42; } else { result = 1 / value; } if !select { result += 40; } result }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<2048, 768, 4, 4, 4, 48>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_conditional_branch_local_identities_reach_native_objects() {
    // Original branch-local shadowing probe paired with the pinned nightly's
    // conditional binding and mutation observations.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u16, mode: u16) -> u16 { let mut result: u16 = input; if mode == 0 { let branch: u16 = result + 1; result = branch; } else if mode == 1 { let branch: u16 = result + 2; result = branch; } else { let branch: u16 = result + 3; result = branch; } result }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<2048, 1024, 4, 4, 4, 64>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_sequential_conditional_local_identities_reach_native_objects() {
    // Original repeated-scope probe paired with the pinned nightly's lexical
    // binding and conditional mutation behavior.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u16, mode: u16) -> u16 { let mut result: u16 = input; result += 1; if mode == 0 { let branch: u16 = result + 1; result = branch; } else { let branch: u16 = result + 2; result = branch; } result += 3; let after: u16 = result; if mode == 2 { let second: u16 = after + 4; result = second; } else { let second: u16 = after + 5; result = second; } let tail: u16 = result; tail }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<4096, 2048, 4, 8, 8, 64>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_loop_scope_local_identities_reach_native_objects() {
    // Original loop/nested/branch scope probe paired with the pinned nightly's
    // lexical binding and loop-control behavior.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u16) -> u16 { let mut index: u16 = 0; let mut total: u16 = 0; while index < limit { let current: u16 = index + 1; loop { let nested: u16 = current; total += nested; break; } if current % 2 == 0 { let branch: u16 = current + 1; total += branch; } else { let branch: u16 = current + 2; total += branch; } index = current; } let after: u16 = total; after }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<8192, 4096, 4, 8, 8, 64>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_guarded_mutation_reaches_native_objects() {
    // Original scalar replacement for the guard-before-mutation ordering in
    // tests/ui/consts/control-flow/basics.rs at the pinned nightly commit.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32, stop: bool) -> u32 { let mut adjusted: u32 = value; if stop { return 7; } adjusted += 1; adjusted * 2 }";
    assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_guarded_fibonacci_loop_reaches_native_objects() {
    // Original scalar replacement for the base-case and iterative Fibonacci
    // control flow in tests/ui/consts/control-flow/basics.rs.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(n: u32) -> u32 { if n == 0 { return 0; } let mut previous: u32 = 0; let mut current: u32 = 1; let mut index: u32 = 1; while index < n { current += previous; previous = current - previous; index += 1; } current }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<2048, 512, 4, 4, 4, 32>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_alternating_guards_and_mutations_reach_native_objects() {
    // Original scalar replacement for repeated early-return decisions and
    // state changes represented in tests/ui/consts/control-flow/basics.rs.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32, first: bool, second: bool) -> u32 { let mut result: u32 = value; if first { return 1; } result += 1; if second { return 2; } result *= 2; result }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<2048, 512, 4, 4, 4, 32>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_post_loop_alternating_guards_reach_native_objects() {
    // Original scalar replacement combining the loop and repeated return
    // decisions represented in tests/ui/consts/control-flow/basics.rs.
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32, limit: u32, first: bool, second: bool) -> u32 { let mut index: u32 = 0; let mut result: u32 = value; while index < limit { index += 1; } if first && index == limit { return 1; } result += 1; if second && index == limit { return 2; } result *= 2; result }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        assert!(
            compile_source_function::<2048, 768, 4, 4, 4, 48>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
            )
            .is_ok()
        );
    }
}

#[test]
fn rustc_scalar_block_expressions_reach_native_objects() {
    // Original scalar replacements for the integral, unit, condition, and call
    // operand blocks exercised by tests/ui/consts/const-block.rs and
    // tests/ui/lint/unused_braces.rs at the pinned nightly commit.
    let probes = [
        "const BLOCK: u32 = { 40 + 2 }; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { { value + BLOCK } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32, guard: bool) -> u32 { if { guard } { { value } } else { { 84 / value } } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> () { {} }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { value + { let mut offset: u32 = 1; offset += 1; offset } }",
    ];
    for source in probes {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_scalar_constant_patterns_reach_native_objects() {
    // A bounded executable replacement for the scalar constant-pattern behavior
    // in tests/ui/consts/consts-in-patterns.rs at the pinned nightly commit.
    let probes = [
        "const SELECTED: u32 = 7; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { SELECTED => { let mut answer: u32 = 40; answer += 2; answer }, _ => 84 / value } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i8) -> i8 { match value { -7i8 => 42i8, _ => value } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: bool) -> u32 { match value { true => 42, _ => 0 } }",
        "const ZERO: u32 = 0; const SEVEN: u32 = 7; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { ZERO => 42, SEVEN => 84 / (value - 5), 9 => { let answer = 42; answer } _ => 420 / value } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: usize) -> usize { match value { 1usize..=5usize => 42usize, _ => 0usize } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: usize) -> usize { match value { 1usize..5usize => 42usize, _ => 0usize } }",
        "const START: isize = 1; const END: isize = 42; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: isize) -> isize { match value { START..=END => 42isize, _ => 0isize } }",
        "const MINIMUM: i8 = -5; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i8) -> i8 { match value { MINIMUM..=-1i8 => 42i8, _ => 0i8 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { 0 | 1..=10 => 42, 12 | 13 => 84 / (value - 10), _ => 420 / value } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i32) -> i32 { match value { -7..0 | 1 => 42, _ => value } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i32) -> i32 { match value { -5.. => 42, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i32) -> i32 { match value { ..-7 => 42, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i32) -> i32 { match value { ..=-7 => 42, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i32) -> i32 { match value { ..-7 | -5.. => 42, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { 1 if false => 1 / 0, 1..=2 => 42, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32, guard: bool) -> u32 { match value { 0 | 1..=10 if guard => 42, _ => 84 / value } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { 1 if 1 / (value - 2) > 0 => 0, 2 => 42, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: char) -> char { match value { 'a'..='z' => '*', _ => value } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: char) -> char { match value { '\\t' | '\\n' => '*', _ => value } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: char) -> char { match value { '\\u{3b1}'..='\\u{3c9}' => '*', _ => value } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { bound if bound < 7 => 84 / bound, selected if selected < 11 => selected + 32, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: char) -> bool { match value { bound if bound == '\\u{3bb}' => true, _ => false } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32, choose_first: bool) -> u32 { match value { _ if choose_first => 84 / value, 7 => 42, _ if value == 0 => 42, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { _ if value != 0 && 84 / value == 42 => 42, _ => value } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { number @ 1..=100 if number == 50 => number - 8, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { selected @ 42 => selected, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: char) -> char { match value { symbol @ 'a'..='z' => symbol, _ => '*' } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { selected @ _ if selected == 42 => selected, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { selected @ 1 | selected @ 2 => selected + 40, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { selected @ 1..=3 | selected @ 7..=9 if selected == 7 => 42, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { 42..=42 => 42, 41..42 => 41, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: char) -> char { match value { 'm'..='m' => '*', _ => value } }",
        "const START: u32 = 42; const END: u32 = 42; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { START..=END => 42, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u8) -> u8 { match value { 0..=255 => 42, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i8) -> i8 { match value { -128..=127 => 42, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: usize) -> usize { match value { 0..=18446744073709551615 => 42, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { (1 | 2) => value + 40, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { ((1 | 2) | (3..=4)) => 42, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32, accept: bool) -> u32 { match value { (| 1 | (5..=10)) if accept => 42, _ => value } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { selected @ (1 | 2) => selected + 40, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32, accept: bool) -> u32 { match value { selected @ ((1..=3) | (7 | 9)) if accept => selected + 35, _ => value } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { selected @ (| 1 | _) if selected == 42 => selected, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: bool) -> u32 { match value { true => 42, false => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: bool) -> u32 { match value { false => 0, true => 42, } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { selected => selected } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: bool) -> u32 { match value { selected @ (false | true) => if selected { 42 } else { 0 } } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { ; value + 1; let mut result: u32 = value; if false { 1 / 0 } else { 0 }; result += 2; result }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: bool) -> bool { value == true; !value; value }",
        "const fn adjust(value: u32) -> u32 { ; value + 1; let mut result: u32 = value; result += 2; result } const ANSWER: u32 = adjust(40); #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { ANSWER + value }",
    ];
    for source in probes {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
    for source in [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { 1 => 1 / 0, 2 => 1 / 0, 3 => 1 / 0, 4 => 1 / 0, 5 => 1 / 0, 6 => 1 / 0, 7 => 1 / 0, 8 => 42, _ => value } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32, accept: bool) -> u32 { match value { 1 if 1 / (value - 8) > 0 => 0, 2 => 1 / 0, 3 => 1 / 0, 4 => 1 / 0, 5 => 1 / 0, 6 => 1 / 0, 7 => 1 / 0, 8 if accept => 42, _ => value } }",
    ] {
        for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
            assert_eq!(
                compile_source_function::<4096, 1024, 4, 2, 4, 64>(
                    source,
                    "probe",
                    format,
                    TargetLayout::X86_64,
                )
                .map(|_| ())
                .map_err(|error| error.kind),
                Ok(())
            );
        }
    }

    let non_boolean_guard = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { 1 if 2 => 42, _ => 0 } }";
    assert_eq!(
        compile(non_boolean_guard, ObjectFormat::Elf64),
        Err(CompileErrorKind::Codegen(
            CodegenErrorKind::RuntimeTypeMismatch
        ))
    );
    let mixed_character_integer = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { 'a' => 42, _ => 0 } }";
    assert_eq!(
        compile(mixed_character_integer, ObjectFormat::Elf64),
        Err(CompileErrorKind::Codegen(
            CodegenErrorKind::RuntimeTypeMismatch
        ))
    );
    let inconsistent_binding = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { bound | 1 => 42, _ => 0 } }";
    assert_eq!(
        compile(inconsistent_binding, ObjectFormat::Elf64),
        Err(CompileErrorKind::Codegen(CodegenErrorKind::Expression(
            ExpressionErrorKind::InconsistentMatchBindings,
        )))
    );
    let mismatched_bindings = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { left @ 1 | right @ 2 => 42, _ => 0 } }";
    assert_eq!(
        compile(mismatched_bindings, ObjectFormat::Elf64),
        Err(CompileErrorKind::Codegen(CodegenErrorKind::Expression(
            ExpressionErrorKind::InconsistentMatchBindings,
        )))
    );
    let nested_mismatched_bindings = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { (left @ 1 | (right @ 2)) => 42, _ => 0 } }";
    assert_eq!(
        compile(nested_mismatched_bindings, ObjectFormat::Elf64),
        Err(CompileErrorKind::Codegen(CodegenErrorKind::Expression(
            ExpressionErrorKind::InconsistentMatchBindings,
        )))
    );
    let non_boolean_wildcard_guard = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { _ if value => 42, _ => 0 } }";
    assert_eq!(
        compile(non_boolean_wildcard_guard, ObjectFormat::Elf64),
        Err(CompileErrorKind::Codegen(
            CodegenErrorKind::RuntimeTypeMismatch
        ))
    );
    for non_exhaustive in [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: bool) -> u32 { match value { true => 42 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: bool) -> u32 { match value { true => 42, false if value => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { 0 => 42, 1 => 0 } }",
    ] {
        assert_eq!(
            compile(non_exhaustive, ObjectFormat::Elf64),
            Err(CompileErrorKind::Codegen(CodegenErrorKind::Expression(
                ExpressionErrorKind::NonExhaustiveMatch,
            )))
        );
    }
    for invalid_range in [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { 6..=1 => 42, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i32) -> i32 { match value { 0..0 => 42, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: char) -> char { match value { 'z'..='a' => '*', _ => value } }",
    ] {
        assert_eq!(
            compile(invalid_range, ObjectFormat::Elf64),
            Err(CompileErrorKind::Codegen(CodegenErrorKind::Expression(
                ExpressionErrorKind::InvalidRangeBounds,
            )))
        );
    }
    let boolean_range = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: bool) -> u32 { match value { false..=true => 42, _ => 0 } }";
    assert_eq!(
        compile(boolean_range, ObjectFormat::Elf64),
        Err(CompileErrorKind::Codegen(CodegenErrorKind::Expression(
            ExpressionErrorKind::InvalidRangeType,
        )))
    );
    for invalid_named_range in [
        "const START: u32 = 6; const END: u32 = 1; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { START..=END => 42, _ => 0 } }",
        "const START: i32 = -1; const END: i32 = -5; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i32) -> i32 { match value { START..=END => 42, _ => 0 } }",
        "const BOUND: u32 = 7; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { match value { BOUND..BOUND => 42, _ => 0 } }",
    ] {
        assert_eq!(
            compile(invalid_named_range, ObjectFormat::Elf64),
            Err(CompileErrorKind::Codegen(
                CodegenErrorKind::InvalidRangeBounds
            ))
        );
    }
    let named_boolean_range = "const LOW: bool = false; const HIGH: bool = true; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: bool) -> u32 { match value { LOW..=HIGH => 42, _ => 0 } }";
    assert_eq!(
        compile(named_boolean_range, ObjectFormat::Elf64),
        Err(CompileErrorKind::Codegen(
            CodegenErrorKind::InvalidRangeType
        ))
    );
    for overflowing_endpoint in [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u8) -> u8 { match value { 1..257 => 42, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u8) -> u8 { match value { 1..=256 => 42, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i8) -> i8 { match value { 0..129 => 42, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i8) -> i8 { match value { -129..0 => 42, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i8) -> i8 { match value { -10000.. => 42, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u64) -> u64 { match value { 0..=99999999999999999999 => 42, _ => 0 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: usize) -> usize { match value { 0..=18446744073709551616 => 42, _ => 0 } }",
    ] {
        assert_eq!(
            compile(overflowing_endpoint, ObjectFormat::Elf64),
            Err(CompileErrorKind::Codegen(
                CodegenErrorKind::RangeEndpointOutOfRange
            ))
        );
    }
}

#[test]
fn rustc_closed_scalar_inline_const_blocks_reach_native_objects() {
    // Original runtime and declaration probes for the pinned nightly's inline
    // const-block syntax. Module constants resolve inside the distinct inline
    // const boundary, while runtime parameters and locals are rejected.
    let probes = [
        "const fn offset() -> u32 { 2 } const OFFSET: u32 = const { offset() }; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32, guard: bool) -> u32 { if guard { value + const { OFFSET } } else { 84 / value + OFFSET - 2 } }",
        "const fn enabled() -> bool { true } const FLAG: bool = const { enabled() }; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: bool) -> bool { value == const { true == true } && FLAG }",
        "const fn offset() -> u32 { 2 } #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { value + const { offset() } }",
        "const fn enabled() -> bool { true } #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: bool) -> bool { value == const { enabled() } }",
        "const fn answer() -> u32 { 42 } #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { const { answer() } }",
        "const fn add(left: u32, right: u32) -> u32 { left + right } #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { value + const { add(1, 1) } }",
        "const fn less(left: u32, right: u32) -> bool { left < right } #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: bool) -> bool { value == const { less(1, 2) } }",
        "const fn adjust(value: i32, offset: i32) -> i32 { value + offset } #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i32) -> i32 { value + const { adjust(-8i32, 50i32) } }",
        "const OFFSET: u32 = const { let first = 1; let second = first + 1; second }; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { value + const { let base = 6; base / 3 } + OFFSET - 2 }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i32 { const { let x = 5 + 10; x / 3 } }",
        "const OFFSET: u32 = const { let mut value = 1; value += 1; value }; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { value + const { let mut base = 3; base *= 2; base /= 3; base } + OFFSET - 2 }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: bool) -> bool { value == const { let mut flag = false; flag |= true; flag } }",
        "const OFFSET: u8 = const { let value: u8 = 2; value }; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u8) -> u8 { value + const { let mut base: u8 = 40; base += OFFSET; base } - 40 }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: bool) -> bool { value == const { let flag: bool = 1 < 2; flag } }",
        "const OFFSET: u32 = const { let mut value = 1; value += 1; let scale = 10; value *= scale; let adjustment = 22; value += adjustment; value }; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { value + const { let mut base: u32 = 1; base += 1; let factor: u32 = 21; base *= factor; base } + OFFSET - 42 }",
        "const OFFSET: u32 = const { 20 + 22; 2 }; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { value + const { if false { 1 / 0 } else { 20 + 22 }; let factor = 1; 2 * factor } + OFFSET - 2 }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> () { const { let mut value = 40; value += 2; value; } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { value + const { if false { 1 / 0; }; 2 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32, guard: bool) -> u32 { if guard { value + const { if true { let mut selected: u32 = 40; selected += 2; selected } else { 1 / 0 } } - 40 } else { 84 / value } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32, guard: bool) -> u32 { if guard { value + const { if false { 1 / 0 } else if true { let selected = 2; selected } else { 1 / 0 } } } else { 84 / value } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> () { const {} }",
    ];
    for source in probes {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }

    let parameter_capture =
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { const { value } }";
    assert_eq!(
        compile(parameter_capture, ObjectFormat::Coff),
        Err(CompileErrorKind::Codegen(
            CodegenErrorKind::RuntimeExpressionUnsupported
        ))
    );
    let local_capture = "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { let value: u32 = 42; const { value } }";
    assert_eq!(
        compile(local_capture, ObjectFormat::Elf64),
        Err(CompileErrorKind::Codegen(
            CodegenErrorKind::RuntimeExpressionUnsupported
        ))
    );
    let non_const_call = "fn offset() -> u32 { 2 } #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { value + const { offset() } }";
    assert_eq!(
        compile(non_const_call, ObjectFormat::Coff),
        Err(CompileErrorKind::Codegen(
            CodegenErrorKind::RuntimeExpressionUnsupported
        ))
    );
    let invalid_inline_const = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> u32 { value + const { 1 / 0 } }";
    assert_eq!(
        compile(invalid_inline_const, ObjectFormat::Elf64),
        Err(CompileErrorKind::Codegen(CodegenErrorKind::Execution(
            ExecutionError::Arithmetic(ConstEvalError::DivisionByZero)
        )))
    );
    let overflowing_ascription = "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { const { let value: u8 = 256; value } }";
    assert_eq!(
        compile(overflowing_ascription, ObjectFormat::Coff),
        Err(CompileErrorKind::Codegen(CodegenErrorKind::Execution(
            ExecutionError::Arithmetic(ConstEvalError::Overflow)
        )))
    );
    for cross_boundary_control in [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> () { const { return } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> () { const { break } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> () { const { continue } }",
    ] {
        assert_eq!(
            compile(cross_boundary_control, ObjectFormat::Coff),
            Err(CompileErrorKind::Codegen(
                CodegenErrorKind::RuntimeExpressionUnsupported
            ))
        );
    }
}

#[test]
fn runtime_loop_return_reaches_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32) -> bool { let mut divisor: u32 = 3; loop { if value % divisor == 0 { return false; } divisor += 2; } false }";
    assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_conditional_while_break_reaches_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: isize) -> isize { let mut i: isize = 0; while i < limit { i += 1; if i == 10 { break; } } i }";
    assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_explicit_continue_and_unconditional_loop_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: isize) -> isize { let mut i: isize = limit; while i > 0 { i -= 1; continue; } i }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> usize { let value: usize = 42; loop { break; } value }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> usize { let mut i: usize = 0; loop { i += 1; if i == 10 { break; } } i }",
    ];
    for source in sources {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_interleaved_loop_control_reaches_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: usize) -> usize { let mut i: usize = 0; let mut is_even: bool = false; loop { if i == limit { break; } is_even = false; i += 1; if i % 2 != 0 { continue; } is_even = true; } if is_even { i } else { 0 } }";
    assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_immediate_break_loop_values_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> isize { let value: isize = loop { break 13; }; value }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: bool) -> bool { let value: bool = loop { break input; }; value }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u32) -> u32 { let value: u32 = loop { break input + 1; }; value }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u32) -> u32 { let value: u32 = 'value: loop { break 'value input + 1; }; value }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: bool) -> u32 { let value: () = 'value: loop { if first { break 'value; } else { break 'value (); } }; value; 42 }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u32) -> u32 { let value: u32 = 'outer: loop { break 'outer 'inner: loop { break 'inner input + 1; }; }; value }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(exit_outer: bool) -> u32 { let value: u32 = 'outer: loop { 'inner: loop { if exit_outer { break 'outer 42; } else { break 'inner false; } }; break 'outer 99; }; value }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { let first: u32 = 'outer1: loop { 'inner: while break 'inner { 1 / 0; } break 'outer1 123; }; let second: u32 = 'outer2: loop { while break 'outer2 567 { 1 / 0; } }; first + second }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { let first: () = loop { break (); break; }; first; let second: () = loop { break; break (); }; second; 42 }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { let first: () = loop { if true { break; } else { break break Default::default(); } }; first; let second: () = loop { if true { break Default::default(); } else { break; } }; second; 42 }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { let third: () = loop { break if true { Default::default() } else { break; }; }; third; 42 }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { let integer: u32 = Default::default(); let boolean: bool = Default::default(); integer; if boolean { 1 / 0 } else { integer + 42 } }",
    ];
    for source in sources {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()), "{source}");
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_loop_break_value_array_literals_have_a_scalar_index_replacement() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { [1u32, 3, 5][1] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { [17u32][0] }",
    ];
    for source in sources {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_loop_break_value_contextual_array_defaults_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u64 { (loop { break if true { break Default::default() } else { break [13u64, 14] }; })[0] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u64 { (loop { if false { break [1 / 0, 14] } else { break Default::default() } })[1] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u64 { (loop { break if false { break Default::default() } else { [42u64, 43] }; })[1] }",
    ];
    for source in sources {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_loop_break_value_fixed_array_locals_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u64 { let values: [u64; 3] = [13, 42, 99]; values[1] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(select: bool) -> u64 { let values: [u64; 2] = loop { break if select { break [13, 14] } else { break Default::default() }; }; let after: u64 = 14; values[0] + values[1] + after }",
    ];
    for source in sources {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_loop_break_value_runtime_array_indexes_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(index: usize) -> usize { [13usize, 42, 99][index] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(index: usize, divisor: usize) -> usize { let values = [84 / divisor, 42, 99]; values[index] }",
    ];
    for source in sources {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_loop_break_value_mutable_array_assignment_reaches_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(index: usize) -> usize { let mut values = [13usize, 42, 99]; let after = 1usize; values = [values[2], values[0], values[1]]; values[index] + after }";
    assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_loop_break_value_mutable_array_element_assignment_reaches_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(index: usize, value: usize) -> usize { let mut values = [13usize, 42, 99]; let after = 1usize; values[index] += value; values[index] + after }";
    assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_fixed_array_repeat_literals_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: usize) -> usize { let mut values = [input + 1; 3usize]; values[1] += 2; values[0] + values[1] + values[2] }";
    assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_zero_length_array_repeat_still_evaluates_its_operand() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: usize, divisor: usize) -> usize { let values: [usize; 0] = [input / divisor; 0]; 42 }";
    assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_const_let_eq_one_word_array_parameter_reaches_native_objects() {
    let source = "#[unsafe(no_mangle)] pub const extern \"C\" fn probe(values: [usize; 1], after: usize) -> usize { let copied = values; copied[0] + after }";
    assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_copy_out_of_array_multiword_parameter_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(before: usize, values: [usize; 2], after: usize) -> usize { before + values[0] * 10 + values[1] + after }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(before: usize, values: [usize; 3], after: usize) -> usize { before + values[0] + values[1] + values[2] + after }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: usize, b: usize, c: usize, d: usize, e: usize, values: [usize; 2], after: usize) -> usize { a + b * 2 + c * 3 + d * 4 + e * 5 + values[0] * 6 + values[1] * 7 + after * 8 }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_block_expression_fixed_array_returns_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: usize) -> [usize; 1] { [input + 1] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: usize) -> [usize; 2] { [input, input + 1] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: usize, after: usize) -> [usize; 3] { [input, 42, after] }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_fixed_length_packed_array_abi_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: [u8; 4]) -> [u8; 4] { let mut copied = values; copied[1] += 1; copied }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: [u16; 5]) -> [u16; 5] { let mut copied = values; copied[4] += 2; copied }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: [bool; 3]) -> [bool; 3] { let mut copied = values; copied[1] ^= true; copied }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_packed_fixed_array_local_slices_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8) -> u8 { let mut values = [input, 10, 20, 30]; let slice: &mut [u8] = &mut values[1..=2]; slice[1] += 2; values[2] + slice[0] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u16) -> u16 { let mut values = [input, 1000, 2000, 3000, 4000]; let slice: &mut [u16] = &mut values[1..4]; slice[1] += 2; values[2] + slice[0] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u32) -> u32 { let mut values = [input, 100000, 200000]; values = [input, values[1], values[2]]; let slice: &[u32] = &values[..2]; slice[0] + slice[1] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: bool) -> bool { let mut values = [input, false, true]; let slice: &mut [bool] = &mut values[1..]; slice[0] ^= true; values[1] && slice[1] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: char) -> char { let mut values = [input, 'x', 'y']; let slice: &mut [char] = &mut values[1..3]; slice[0] = 'z'; values[1] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(start: usize, end: usize) -> u8 { let mut values = [7u8, 10, 20, 30]; let slice: &mut [u8] = &mut values[start..end]; slice[0] += 2; values[start] + slice[1] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(start: usize) -> u8 { let end: usize = start + 2; if end == 3 { 42u8 } else { 1 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(start: usize) -> u8 { let end = start + 2; if end == 3 { 42u8 } else { 1 } }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_slice_subranges_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &mut [u16], start: usize, end: usize) -> u16 { let slice: &mut [u16] = &mut values[start..end]; slice[0] += 2; slice[0] + slice[1] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &[usize], start: usize, end: usize) -> usize { let slice: &[usize] = &values[start..=end]; slice.len() + slice[0] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &[usize], end: usize) -> usize { let slice: &[usize] = &values[..end]; slice.len() + slice[0] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &[usize], start: usize) -> usize { let slice: &[usize] = &values[start..]; slice.len() + slice[0] }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_independent_scalar_integer_widths_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8, wide: u64, signed: i16) -> u8 { let adjusted = wide + 2; let negative: i16 = signed + 2; if adjusted == 258 && negative == -1 { input + 1 } else { input } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8) -> u8 { let wide: u64 = 256; let signed: i16 = -3; if wide + 2 == 258 && signed + 2 == -1 { input + 1 } else { input } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8) -> u8 { let values: [u16; 3] = [256, 257, 258]; if values[1] == 257 { input + 1 } else { input } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8) -> u8 { let mut wide: u64 = 256; wide += 2; let mut signed: i16 = -3; signed += 2; let mut values: [u16; 3] = [256, 257, 258]; values[1] += 1; if wide == 258 && signed == -1 && values[1] == 258 { input + 1 } else { input } }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_unsigned_integer_predicates_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8) -> bool { input.is_power_of_two() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64, divisor: u64) -> bool { input.is_multiple_of(divisor) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: usize) -> bool { input.is_multiple_of(0) }",
        "const VALUE: bool = 16u16.is_power_of_two(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> bool { VALUE }",
        "const VALUE: bool = 0u32.is_multiple_of(0); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> bool { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_wrapping_integer_methods_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8, rhs: u8) -> u8 { input.wrapping_add(rhs) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i16, rhs: i16) -> i16 { input.wrapping_sub(rhs) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u32, rhs: u32) -> u32 { input.wrapping_mul(rhs) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64, rhs: i64) -> i64 { input.wrapping_mul(rhs) }",
        "const VALUE: u8 = 255u8.wrapping_add(43); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: i8 = (-128i8).wrapping_sub(1); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i8 { VALUE }",
        "const VALUE: u16 = 40000u16.wrapping_mul(3); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u16 { VALUE }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i8) -> i8 { input.wrapping_neg() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i16) -> i16 { input.wrapping_abs() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64) -> i64 { input.wrapping_abs() }",
        "const VALUE: i8 = (-128i8).wrapping_neg(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i8 { VALUE }",
        "const VALUE: i16 = (-32768i16).wrapping_abs(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i16 { VALUE }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i8, rhs: i8) -> i8 { input.wrapping_div(rhs) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u16, rhs: u16) -> u16 { input.wrapping_rem(rhs) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64, rhs: i64) -> i64 { input.wrapping_rem(rhs) }",
        "const VALUE: i8 = (-128i8).wrapping_div(-1); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i8 { VALUE }",
        "const VALUE: i16 = (-32768i16).wrapping_rem(-1); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i16 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_wrapping_mixed_signedness_arithmetic_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i8, right: u8) -> i8 { left.wrapping_add_unsigned(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i64, right: u64) -> i64 { left.wrapping_sub_unsigned(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u16, right: i16) -> u16 { left.wrapping_add_signed(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u64, right: i64) -> u64 { left.wrapping_sub_signed(right) }",
        "const VALUE: i8 = 127i8.wrapping_add_unsigned(255); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i8 { VALUE }",
        "const VALUE: u8 = 0u8.wrapping_add_signed(-1); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_strict_arithmetic_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u8, right: u8) -> u8 { left.strict_add(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i16, right: i16) -> i16 { left.strict_sub(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u32, right: u32) -> u32 { left.strict_mul(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i64, right: i64) -> i64 { left.strict_add(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u64, right: u64) -> u64 { left.strict_sub(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i8, right: i8) -> i8 { left.strict_mul(right) }",
        "const VALUE: u8 = 40u8.strict_add(2); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: i16 = 40i16.strict_sub(-2); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i16 { VALUE }",
        "const VALUE: u32 = 6u32.strict_mul(7); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_strict_mixed_signedness_arithmetic_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i8, right: u8) -> i8 { left.strict_add_unsigned(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i64, right: u64) -> i64 { left.strict_sub_unsigned(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u16, right: i16) -> u16 { left.strict_add_signed(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u64, right: i64) -> u64 { left.strict_sub_signed(right) }",
        "const VALUE: i8 = (-40i8).strict_add_unsigned(82); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i8 { VALUE }",
        "const VALUE: i128 = (-170141183460469231731687303715884105728i128).strict_add_unsigned(340282366920938463463374607431768211455u128); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i64 { VALUE as i64 }",
        "const VALUE: u8 = 40u8.strict_add_signed(2); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: u128 = 340282366920938463463374607431768211455u128.strict_sub_signed(170141183460469231731687303715884105727i128); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u64 { VALUE as u64 }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }

    for source in [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i8, right: i8) -> i8 { left.strict_add_unsigned(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u64, right: u64) -> u64 { left.strict_sub_signed(right) }",
    ] {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Err(CompileErrorKind::Codegen(
                CodegenErrorKind::RuntimeTypeMismatch
            )),
            "{source}"
        );
    }
}

#[test]
fn rustc_strict_division_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u8, right: u8) -> u8 { left.strict_div(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i16, right: i16) -> i16 { left.strict_rem(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i64, right: i64) -> i64 { left.strict_div_euclid(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i16, right: i16) -> i16 { left.strict_rem_euclid(right) }",
        "const VALUE: u8 = 84u8.strict_div(2); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: i16 = (-85i16).strict_rem(43); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i16 { VALUE }",
        "const VALUE: i64 = (-85i64).strict_div_euclid(43); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i64 { VALUE }",
        "const VALUE: i16 = (-85i16).strict_rem_euclid(43); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i16 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_strict_negation_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8) -> u8 { input.strict_neg() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i16) -> i16 { input.strict_neg() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64) -> i64 { input.strict_neg() }",
        "const VALUE: u8 = 0u8.strict_neg(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: i16 = 42i16.strict_neg(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i16 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_strict_shifts_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8, distance: u32) -> u8 { input.strict_shl(distance) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i16, distance: u32) -> i16 { input.strict_shr(distance) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64, distance: u32) -> u64 { input.strict_shl(distance) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64, distance: u32) -> i64 { input.strict_shr(distance) }",
        "const VALUE: u8 = 21u8.strict_shl(1); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: i16 = (-84i16).strict_shr(1); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i16 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_strict_powers_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8, exponent: u32) -> u8 { input.strict_pow(exponent) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i16, exponent: u32) -> i16 { input.strict_pow(exponent) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64, exponent: u32) -> u64 { input.strict_pow(exponent) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64, exponent: u32) -> i64 { input.strict_pow(exponent) }",
        "const VALUE: u8 = 42u8.strict_pow(1); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: i16 = (-2i16).strict_pow(5); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i16 { VALUE }",
        "const VALUE: u64 = 7u64.strict_pow(0); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u64 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_strict_absolute_values_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i8) -> i8 { input.strict_abs() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i16) -> i16 { input.strict_abs() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64) -> i64 { input.strict_abs() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: isize) -> isize { input.strict_abs() }",
        "const VALUE: i8 = (-42i8).strict_abs(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i8 { VALUE }",
        "const VALUE: i64 = 42i64.strict_abs(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i64 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_euclidean_integer_division_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8, rhs: u8) -> u8 { input.div_euclid(rhs) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i16, rhs: i16) -> i16 { input.rem_euclid(rhs) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64, rhs: i64) -> i64 { input.div_euclid(rhs) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64, rhs: i64) -> i64 { input.rem_euclid(rhs) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i8, rhs: i8) -> i8 { input.wrapping_div_euclid(rhs) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64, rhs: i64) -> i64 { input.wrapping_rem_euclid(rhs) }",
        "const VALUE: i8 = (-7i8).div_euclid(4); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i8 { VALUE }",
        "const VALUE: i16 = (-7i16).rem_euclid(4); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i16 { VALUE }",
        "const VALUE: i32 = 7i32.div_euclid(-4); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i32 { VALUE }",
        "const VALUE: u64 = 7u64.rem_euclid(4); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u64 { VALUE }",
        "const VALUE: i8 = (-128i8).wrapping_div_euclid(-1); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i8 { VALUE }",
        "const VALUE: i64 = (-9223372036854775808i64).wrapping_rem_euclid(-1); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i64 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_saturating_integer_unary_methods_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i8) -> i8 { input.saturating_neg() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i16) -> i16 { input.saturating_abs() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i32) -> i32 { input.saturating_neg() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64) -> i64 { input.saturating_abs() }",
        "const VALUE: i8 = (-128i8).saturating_neg(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i8 { VALUE }",
        "const VALUE: i16 = (-32768i16).saturating_abs(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i16 { VALUE }",
        "const VALUE: i32 = (-42i32).saturating_abs(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i32 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_saturating_integer_binary_methods_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8, rhs: u8) -> u8 { input.saturating_add(rhs) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i16, rhs: i16) -> i16 { input.saturating_sub(rhs) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64, rhs: u64) -> u64 { input.saturating_sub(rhs) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64, rhs: i64) -> i64 { input.saturating_add(rhs) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64, rhs: u64) -> u64 { input.saturating_mul(rhs) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i32, rhs: i32) -> i32 { input.saturating_mul(rhs) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64, rhs: i64) -> i64 { input.saturating_mul(rhs) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u32, rhs: u32) -> u32 { input.saturating_div(rhs) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64, rhs: i64) -> i64 { input.saturating_div(rhs) }",
        "const VALUE: u8 = 250u8.saturating_add(42); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: i16 = (-32768i16).saturating_sub(1); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i16 { VALUE }",
        "const VALUE: i32 = 2147483647i32.saturating_add(1); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i32 { VALUE }",
        "const VALUE: u64 = 0u64.saturating_sub(1); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u64 { VALUE }",
        "const VALUE: u8 = 32u8.saturating_mul(9); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: i16 = (-200i16).saturating_mul(200); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i16 { VALUE }",
        "const VALUE: i8 = (-128i8).saturating_div(-1); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i8 { VALUE }",
        "const VALUE: u64 = 84u64.saturating_div(2); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u64 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_saturating_mixed_signedness_arithmetic_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i8, right: u8) -> i8 { left.saturating_add_unsigned(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i64, right: u64) -> i64 { left.saturating_sub_unsigned(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u16, right: i16) -> u16 { left.saturating_add_signed(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u64, right: i64) -> u64 { left.saturating_sub_signed(right) }",
        "const VALUE: i8 = 127i8.saturating_add_unsigned(255); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i8 { VALUE }",
        "const VALUE: i128 = (-170141183460469231731687303715884105728i128).saturating_add_unsigned(340282366920938463463374607431768211455u128); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i64 { VALUE as i64 }",
        "const VALUE: u8 = 0u8.saturating_add_signed(-1); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: u128 = 340282366920938463463374607431768211455u128.saturating_sub_signed(-170141183460469231731687303715884105728i128); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u64 { VALUE as u64 }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_signed_integer_classification_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i8) -> i8 { input.signum() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i16) -> bool { input.is_positive() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i32) -> bool { input.is_negative() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64) -> i64 { input.signum() }",
        "const VALUE: i8 = (-128i8).signum(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i8 { VALUE }",
        "const VALUE: bool = (-1i16).is_negative(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> bool { VALUE }",
        "const VALUE: bool = 1i32.is_positive(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> bool { VALUE }",
        "const VALUE: bool = 0i64.is_positive(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> bool { VALUE }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64) -> i64 { input.abs() }",
        "const VALUE: i16 = (-12345i16).abs(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i16 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
    let minimum_abs = "const VALUE: i8 = (-128i8).abs(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i8 { VALUE }";
    assert!(matches!(
        compile_wide(minimum_abs, ObjectFormat::Elf64),
        Err(CompileErrorKind::Semantic(_))
    ));
    assert!(matches!(
        compile_wide(minimum_abs, ObjectFormat::Coff),
        Err(CompileErrorKind::Semantic(_))
    ));
}

#[test]
fn rustc_unsigned_absolute_values_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i8) -> u8 { input.unsigned_abs() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i16) -> u16 { input.unsigned_abs() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i32) -> u32 { input.unsigned_abs() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64) -> u64 { input.unsigned_abs() }",
        "const VALUE: u8 = (-128i8).unsigned_abs(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: u16 = (-32768i16).unsigned_abs(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u16 { VALUE }",
        "const VALUE: u32 = (-42i32).unsigned_abs(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_integer_absolute_differences_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i8, right: i8) -> u8 { left.abs_diff(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u16, right: u16) -> u16 { left.abs_diff(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i32, right: i32) -> u32 { left.abs_diff(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u64, right: u64) -> u64 { left.abs_diff(right) }",
        "const VALUE: u8 = (-128i8).abs_diff(127); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: u16 = 1u16.abs_diff(65535); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u16 { VALUE }",
        "const VALUE: u32 = (-42i32).abs_diff(42); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_integer_midpoints_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i8, right: i8) -> i8 { left.midpoint(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u16, right: u16) -> u16 { left.midpoint(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i64, right: i64) -> i64 { left.midpoint(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u64, right: u64) -> u64 { left.midpoint(right) }",
        "const VALUE: i8 = (-128i8).midpoint(127); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i8 { VALUE }",
        "const VALUE: u16 = 1u16.midpoint(65535); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u16 { VALUE }",
        "const VALUE: i64 = (-9223372036854775807i64).midpoint(9223372036854775807); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i64 { VALUE }",
        "const VALUE: u64 = 0u64.midpoint(18446744073709551615u64); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u64 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_integer_ordering_methods_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u8, right: u8) -> u8 { left.min(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i16, right: i16) -> i16 { left.max(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u32, low: u32, high: u32) -> u32 { value.clamp(low, high) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i64, low: i64, high: i64) -> i64 { value.clamp(low, high) }",
        "const VALUE: i8 = (-100i8).max(-42); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i8 { VALUE }",
        "const VALUE: u16 = 900u16.min(42); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u16 { VALUE }",
        "const VALUE: i32 = (-100i32).clamp(-42, 42); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i32 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_integer_div_ceil_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u8, right: u8) -> u8 { left.div_ceil(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u16, right: u16) -> u16 { left.div_ceil(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u64, right: u64) -> u64 { left.div_ceil(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: usize, right: usize) -> usize { left.div_ceil(right) }",
        "const VALUE: u8 = 0u8.div_ceil(1); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: u16 = 7u16.div_ceil(4); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u16 { VALUE }",
        "const VALUE: u64 = 18446744073709551615u64.div_ceil(2); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u64 { VALUE }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i8, right: i8) -> i8 { left.div_ceil(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i64, right: i64) -> i64 { left.div_ceil(right) }",
        "const VALUE: i8 = (-7i8).div_ceil(4); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i8 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_integer_div_floor_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u8, right: u8) -> u8 { left.div_floor(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i8, right: i8) -> i8 { left.div_floor(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i64, right: i64) -> i64 { left.div_floor(right) }",
        "const VALUE: i8 = (-7i8).div_floor(4); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i8 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_integer_next_multiple_of_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u8, right: u8) -> u8 { left.next_multiple_of(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u16, right: u16) -> u16 { left.next_multiple_of(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u64, right: u64) -> u64 { left.next_multiple_of(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: usize, right: usize) -> usize { left.next_multiple_of(right) }",
        "const VALUE: u8 = 0u8.next_multiple_of(1); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: u16 = 23u16.next_multiple_of(8); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u16 { VALUE }",
        "const VALUE: u64 = 18446744073709551614u64.next_multiple_of(2); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u64 { VALUE }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i8, right: i8) -> i8 { left.next_multiple_of(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: i64, right: i64) -> i64 { left.next_multiple_of(right) }",
        "const VALUE: i8 = (-23i8).next_multiple_of(8); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i8 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_integer_rotations_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8, distance: u32) -> u8 { input.rotate_left(distance) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i16, distance: u32) -> i16 { input.rotate_right(distance) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u32, distance: u32) -> u32 { input.rotate_left(distance) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64, distance: u32) -> i64 { input.rotate_right(distance) }",
        "const VALUE: u8 = 0x81u8.rotate_left(1); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: i16 = (-2i16).rotate_right(17); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i16 { VALUE }",
        "const VALUE: u32 = 0x12345678u32.rotate_left(68); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_wrapping_integer_shifts_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8, distance: u32) -> u8 { input.wrapping_shl(distance) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i16, distance: u32) -> i16 { input.wrapping_shr(distance) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u32, distance: u32) -> u32 { input.wrapping_shr(distance) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64, distance: u32) -> i64 { input.wrapping_shl(distance) }",
        "const VALUE: u8 = 0x81u8.wrapping_shl(9); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: i16 = (-2i16).wrapping_shr(17); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i16 { VALUE }",
        "const VALUE: u32 = 0x80000001u32.wrapping_shr(68); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_unbounded_integer_shifts_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8, distance: u32) -> u8 { input.unbounded_shl(distance) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i16, distance: u32) -> i16 { input.unbounded_shr(distance) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64, distance: u32) -> u64 { input.unbounded_shr(distance) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64, distance: u32) -> i64 { input.unbounded_shl(distance) }",
        "const VALUE: u8 = 3u8.unbounded_shl(8); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: i16 = (-3i16).unbounded_shr(16); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i16 { VALUE }",
        "const VALUE: u32 = 9u32.unbounded_shr(32); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { VALUE }",
        "const VALUE: i64 = (-1i64).unbounded_shl(64); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i64 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_wrapping_integer_powers_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8, exponent: u32) -> u8 { input.wrapping_pow(exponent) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i16, exponent: u32) -> i16 { input.wrapping_pow(exponent) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u32, exponent: u32) -> u32 { input.wrapping_pow(exponent) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64, exponent: u32) -> i64 { input.wrapping_pow(exponent) }",
        "const VALUE: u8 = 3u8.wrapping_pow(20); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: i16 = (-3i16).wrapping_pow(17); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i16 { VALUE }",
        "const VALUE: u64 = 5u64.wrapping_pow(0); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u64 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_saturating_integer_powers_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8, exponent: u32) -> u8 { input.saturating_pow(exponent) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i16, exponent: u32) -> i16 { input.saturating_pow(exponent) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64, exponent: u32) -> u64 { input.saturating_pow(exponent) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64, exponent: u32) -> i64 { input.saturating_pow(exponent) }",
        "const VALUE: u8 = 3u8.saturating_pow(20); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: i16 = (-3i16).saturating_pow(17); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i16 { VALUE }",
        "const VALUE: i16 = (-3i16).saturating_pow(18); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i16 { VALUE }",
        "const VALUE: u64 = 5u64.saturating_pow(0); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u64 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_integer_powers_reach_native_objects() {
    let runtime_sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8, exponent: u32) -> u8 { input.pow(exponent) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64, exponent: u32) -> i64 { input.pow(exponent) }",
    ];
    for source in runtime_sources {
        for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
            let checked = compile_source_function_with_options::<4096, 3072, 4, 8, 8, 64>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
                CodegenOptions::CHECKED,
            )
            .unwrap();
            let wrapping = compile_source_function_with_options::<4096, 3072, 4, 8, 8, 64>(
                source,
                "probe",
                format,
                TargetLayout::X86_64,
                CodegenOptions::WRAPPING,
            )
            .unwrap();
            assert_ne!(checked.bytes(), wrapping.bytes());
        }
    }
    for source in [
        "const VALUE: u8 = 255u8.pow(1); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: i16 = (-3i16).pow(3); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i16 { VALUE }",
        "const VALUE: u64 = 5u64.pow(0); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u64 { VALUE }",
    ] {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
    let overflow = "const VALUE: u8 = 16u8.pow(2); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }";
    for format in [ObjectFormat::Elf64, ObjectFormat::Coff] {
        let result = compile_wide(overflow, format);
        assert!(
            matches!(
                result,
                Err(CompileErrorKind::Semantic(
                    mrml_rustc::SemanticErrorKind::ConstantOutOfRange
                ))
            ),
            "{result:?}"
        );
    }
}

#[test]
fn rustc_integer_bit_and_byte_reordering_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8) -> u8 { input.reverse_bits() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i16) -> i16 { input.swap_bytes() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u32) -> u32 { input.reverse_bits() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64) -> i64 { input.to_be() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: usize) -> usize { input.to_le() }",
        "const VALUE: u8 = 0x81u8.reverse_bits(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: i16 = (-32767i16).swap_bytes(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i16 { VALUE }",
        "const VALUE: u32 = 0x12345678u32.to_be(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { VALUE }",
        "const VALUE: u64 = 0x123456789abcdef0u64.to_le(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u64 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_integer_endian_constructors_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8) -> u8 { u8::from_be(input) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i16) -> i16 { i16::from_le(input) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u32) -> u32 { u32::from_be(input) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64) -> i64 { i64::from_le(input) }",
        "const VALUE: u16 = u16::from_be(0x1234u16); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u16 { VALUE }",
        "const VALUE: i32 = i32::from_le(-305419896i32); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i32 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_integer_byte_array_constructors_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(bytes: [u8; 1]) -> u8 { u8::from_be_bytes(bytes) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(bytes: [u8; 2]) -> i16 { i16::from_le_bytes(bytes) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(bytes: [u8; 4]) -> u32 { u32::from_be_bytes(bytes) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(bytes: [u8; 8]) -> i64 { i64::from_ne_bytes(bytes) }",
        "const VALUE: u32 = u32::from_be_bytes([0x12, 0x34, 0x56, 0x78]); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { VALUE }",
        "const VALUE: i64 = i64::from_le_bytes([0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i64 { VALUE }",
        "const VALUE: u128 = u128::from_be_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u64 { VALUE as u64 }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_integer_byte_array_outputs_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8) -> [u8; 1] { input.to_be_bytes() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i16) -> [u8; 2] { input.to_le_bytes() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u32) -> [u8; 4] { input.to_be_bytes() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64) -> [u8; 8] { input.to_ne_bytes() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: usize) -> u8 { input.to_be_bytes()[0] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { 0x12345678u32.to_be_bytes()[0] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { (-2i16).to_le_bytes()[1] }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_integer_associated_constants_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { u8::MIN }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i16 { i16::MIN }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { u32::MAX }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i64 { i64::MAX }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> usize { usize::MAX }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { isize::BITS }",
        "const VALUE: u128 = u128::MAX; #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u64 { VALUE as u64 }",
        "const VALUE: i128 = i128::MIN; #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i64 { VALUE as i64 }",
        "const VALUE: u32 = usize::BITS; #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { VALUE }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i32 { i32::min_value() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u64 { u64::max_value() }",
        "const VALUE: isize = isize::min_value(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> isize { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_next_power_of_two_methods_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8) -> u8 { input.next_power_of_two() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64) -> u64 { input.wrapping_next_power_of_two() }",
        "const VALUE: u8 = 0u8.next_power_of_two(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: u16 = 3u16.next_power_of_two(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u16 { VALUE }",
        "const VALUE: u32 = 4294967295u32.wrapping_next_power_of_two(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_integer_logarithms_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8) -> u32 { input.ilog2() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i16) -> u32 { input.ilog10() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64, radix: u64) -> u32 { input.ilog(radix) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64, radix: i64) -> u32 { input.ilog(radix) }",
        "const VALUE: u32 = 255u8.ilog2(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { VALUE }",
        "const VALUE: u32 = 999i16.ilog10(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { VALUE }",
        "const VALUE: u32 = 81u32.ilog(3); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { VALUE }",
        "const VALUE: u32 = 625i64.ilog(5); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_integer_square_roots_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8) -> u8 { input.isqrt() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i16) -> i16 { input.isqrt() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64) -> u64 { input.isqrt() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64) -> i64 { input.isqrt() }",
        "const VALUE: u8 = 0u8.isqrt(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: i16 = 10i16.isqrt(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i16 { VALUE }",
        "const VALUE: u32 = 4294967295u32.isqrt(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { VALUE }",
        "const VALUE: i64 = 9223372036854775807i64.isqrt(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i64 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_integer_bit_counts_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8) -> u32 { input.count_ones() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i16) -> u32 { input.count_zeros() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u32) -> u32 { input.leading_zeros() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64) -> u32 { input.trailing_zeros() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i8) -> u32 { input.leading_ones() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64) -> u32 { input.trailing_ones() }",
        "const VALUE: u32 = 0x81u8.count_ones(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { VALUE }",
        "const VALUE: u32 = (-1i16).count_zeros(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { VALUE }",
        "const VALUE: u32 = 0x00100000u32.leading_zeros(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { VALUE }",
        "const VALUE: u32 = 0i64.trailing_zeros(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { VALUE }",
        "const VALUE: u32 = (-2i8).leading_ones(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { VALUE }",
        "const VALUE: u32 = 7u64.trailing_ones(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_unsigned_bit_introspection_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8) -> u32 { input.bit_width() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64) -> u32 { input.bit_width() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8) -> u8 { input.isolate_highest_one() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64) -> u64 { input.isolate_lowest_one() }",
        "const VALUE: u8 = 0b10110100u8.isolate_highest_one(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: u64 = 0x9000000000000040u64.isolate_lowest_one(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u64 { VALUE }",
        "const VALUE: u32 = 0x8001u16.bit_width(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u32 { VALUE }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i8) -> i8 { input.isolate_highest_one() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64) -> i64 { input.isolate_lowest_one() }",
        "const VALUE: i8 = (-44i8).isolate_highest_one(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i8 { VALUE }",
        "const VALUE: i64 = (-96i64).isolate_lowest_one(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i64 { VALUE }",
        "const VALUE: i8 = 0i8.isolate_highest_one(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i8 { VALUE }",
        "const VALUE: i64 = (-9223372036854775808i64).isolate_lowest_one(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i64 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_unsigned_bit_gather_scatter_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u8, right: u8) -> u8 { left.carryless_mul(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: u64, right: u64) -> u64 { left.carryless_mul(right) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u8, mask: u8) -> u8 { value.extract_bits(mask) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u64, mask: u64) -> u64 { value.extract_bits(mask) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u8, mask: u8) -> u8 { value.deposit_bits(mask) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u64, mask: u64) -> u64 { value.deposit_bits(mask) }",
        "const VALUE: u8 = 0b1011u8.carryless_mul(0b110); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: u8 = 0b10111100u8.extract_bits(0b00100100); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: u8 = 0b10101101u8.deposit_bits(0b01010101); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_unsigned_funnel_shifts_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8, n: u32) -> u8 { a.funnel_shl(b, n) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8, n: u32) -> u8 { a.funnel_shr(b, n) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u64, b: u64, n: u32) -> u64 { a.funnel_shl(b, n) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u64, b: u64, n: u32) -> u64 { a.funnel_shr(b, n) }",
        "const VALUE: u8 = 0x81u8.funnel_shl(0x42, 1); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: u8 = 0x81u8.funnel_shr(0x42, 1); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_same_width_integer_sign_casts_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8) -> i8 { input.cast_signed() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i8) -> u8 { input.cast_unsigned() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64) -> i64 { input.saturating_cast_signed() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64) -> u64 { input.saturating_cast_unsigned() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u16) -> i16 { input.strict_cast_signed() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i16) -> u16 { input.strict_cast_unsigned() }",
        "const VALUE: i8 = 255u8.cast_signed(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i8 { VALUE }",
        "const VALUE: u8 = (-1i8).cast_unsigned(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: i8 = 255u8.saturating_cast_signed(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i8 { VALUE }",
        "const VALUE: u8 = (-1i8).saturating_cast_unsigned(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_integer_width_casts_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u32) -> u8 { input.truncate::<u8>() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64) -> i16 { input.saturating_truncate::<i16>() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8) -> u64 { input.widen::<u64>() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i8) -> i64 { input.widen::<i64>() }",
        "const VALUE: u8 = 300u16.truncate::<u8>(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: i8 = 300i16.saturating_truncate::<i8>(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i8 { VALUE }",
        "const VALUE: i64 = (-42i8).widen::<i64>(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i64 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_generic_integer_casts_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64) -> u8 { input.saturating_cast::<u8>() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64) -> i8 { input.saturating_cast::<i8>() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i8) -> u64 { input.wrapping_cast::<u64>() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64) -> i16 { input.wrapping_cast::<i16>() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64) -> usize { input.strict_cast::<usize>() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: usize) -> i8 { input.strict_cast::<i8>() }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: i64) -> u8 { input.unchecked_cast::<u8>() }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: u8) -> i64 { input.unchecked_cast::<i64>() }",
        "const VALUE: u8 = (-42i16).saturating_cast::<u8>(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: i8 = 300u16.saturating_cast::<i8>(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i8 { VALUE }",
        "const VALUE: u8 = (-42i16).wrapping_cast::<u8>(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        "const VALUE: i64 = 42u8.strict_cast::<i64>(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i64 { VALUE }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }

    assert!(compile_wide(
        "const VALUE: u8 = (-1i8).strict_cast::<u8>(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        ObjectFormat::Elf64,
    )
    .is_err());
    assert!(compile_wide(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8) -> u16 { input.unchecked_cast::<u16>() }",
        ObjectFormat::Elf64,
    )
    .is_err());
}

#[test]
fn rustc_unchecked_integer_operations_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(a: u8, b: u8) -> u8 { a.unchecked_add(b) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(a: i16, b: i16) -> i16 { a.unchecked_sub(b) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(a: u32, b: u32) -> u32 { a.unchecked_mul(b) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(a: u32, b: u32) -> u32 { a.unchecked_div_exact(b) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(a: i64, b: i64) -> i64 { a.unchecked_div_exact(b) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(a: i64) -> i64 { a.unchecked_neg() }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(a: u8, n: u32) -> u8 { a.unchecked_shl(n) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(a: i64, n: u32) -> i64 { a.unchecked_shr(n) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(a: u16, n: u32) -> u16 { a.unchecked_shl_exact(n) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(a: i32, n: u32) -> i32 { a.unchecked_shr_exact(n) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(a: u8, b: u8, n: u32) -> u8 { a.unchecked_funnel_shl(b, n) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(a: u64, b: u64, n: u32) -> u64 { a.unchecked_funnel_shr(b, n) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(a: u64, b: u64) -> u64 { a.unchecked_disjoint_bitor(b) }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }

    assert!(compile_wide(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8) -> u8 { a.unchecked_add(b) }",
        ObjectFormat::Elf64,
    )
    .is_err());
}

#[test]
fn rustc_checked_exact_division_options_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u32, b: u32, fallback: u32) -> u32 { a.checked_div_exact(b).unwrap_or(fallback) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i64, b: i64, fallback: i64) -> i64 { a.checked_div_exact(b).unwrap_or(fallback) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u16, b: u16) -> u16 { a.checked_div_exact(b).unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u64, b: u64) -> bool { a.checked_div_exact(b).is_some() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i32, b: i32) -> bool { a.checked_div_exact(b).is_none() }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }

    assert!(compile_wide(
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u16) -> u8 { a.checked_div_exact(b).unwrap_or(0) }",
        ObjectFormat::Elf64,
    )
    .is_err());
    assert!(compile_wide(
        "const VALUE: u8 = 84u8.checked_div_exact(2).unwrap_or(0); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { VALUE }",
        ObjectFormat::Elf64,
    )
    .is_err());
}

#[test]
fn rustc_checked_arithmetic_options_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8, fallback: u8) -> u8 { a.checked_add(b).unwrap_or(fallback) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i16, b: i16) -> i16 { a.checked_sub(b).unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u32, b: u32) -> bool { a.checked_mul(b).is_some() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i64, b: i64) -> bool { a.checked_mul(b).is_none() }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_unsigned_mixed_arithmetic_options_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: i8, fallback: u8) -> u8 { a.checked_add_signed(b).unwrap_or(fallback) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u64, b: i64) -> u64 { a.checked_sub_signed(b).unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: usize, b: isize) -> bool { a.checked_add_signed(b).is_some() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u16, b: i16) -> bool { a.checked_sub_signed(b).is_none() }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_signed_difference_options_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8, fallback: i8) -> i8 { a.checked_signed_diff(b).unwrap_or(fallback) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u64, b: u64) -> i64 { a.checked_signed_diff(b).unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: usize, b: usize) -> bool { a.checked_signed_diff(b).is_some() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u16, b: u16) -> bool { a.checked_signed_diff(b).is_none() }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_signed_mixed_arithmetic_options_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i8, b: u8, fallback: i8) -> i8 { a.checked_add_unsigned(b).unwrap_or(fallback) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i64, b: u64) -> i64 { a.checked_sub_unsigned(b).unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: isize, b: usize) -> bool { a.checked_add_unsigned(b).is_some() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i16, b: u16) -> bool { a.checked_sub_unsigned(b).is_none() }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_division_and_remainder_options_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u32, b: u32, fallback: u32) -> u32 { a.checked_div(b).unwrap_or(fallback) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i64, b: i64) -> i64 { a.checked_rem(b).unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i16, b: i16) -> bool { a.checked_div(b).is_some() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8) -> bool { a.checked_rem(b).is_none() }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_euclidean_division_options_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i64, b: i64, fallback: i64) -> i64 { a.checked_div_euclid(b).unwrap_or(fallback) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i16, b: i16) -> i16 { a.checked_rem_euclid(b).unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u32, b: u32) -> bool { a.checked_div_euclid(b).is_some() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8) -> bool { a.checked_rem_euclid(b).is_none() }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_signed_unary_options_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i8, fallback: i8) -> i8 { a.checked_neg().unwrap_or(fallback) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i64) -> i64 { a.checked_abs().unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: isize) -> bool { a.checked_neg().is_some() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i16) -> bool { a.checked_abs().is_none() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, fallback: u8) -> u8 { a.checked_neg().unwrap_or(fallback) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u64) -> bool { a.checked_neg().is_some() }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_shift_options_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, n: u32, fallback: u8) -> u8 { a.checked_shl(n).unwrap_or(fallback) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i64, n: u32) -> i64 { a.checked_shr(n).unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i16, n: u32) -> bool { a.checked_shl(n).is_some() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u32, n: u32) -> bool { a.checked_shr(n).is_none() }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_power_options_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, n: u32, fallback: u8) -> u8 { a.checked_pow(n).unwrap_or(fallback) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i64, n: u32) -> i64 { a.checked_pow(n).unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i16, n: u32) -> bool { a.checked_pow(n).is_some() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u32, n: u32) -> bool { a.checked_pow(n).is_none() }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_next_power_of_two_options_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, fallback: u8) -> u8 { a.checked_next_power_of_two().unwrap_or(fallback) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u64) -> u64 { a.checked_next_power_of_two().unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: usize) -> bool { a.checked_next_power_of_two().is_some() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u16) -> bool { a.checked_next_power_of_two().is_none() }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_integer_square_root_options_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i8, fallback: i8) -> i8 { a.checked_isqrt().unwrap_or(fallback) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i64) -> i64 { a.checked_isqrt().unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: isize) -> bool { a.checked_isqrt().is_some() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i16) -> bool { a.checked_isqrt().is_none() }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_next_multiple_options_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8, fallback: u8) -> u8 { a.checked_next_multiple_of(b).unwrap_or(fallback) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i64, b: i64) -> i64 { a.checked_next_multiple_of(b).unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i16, b: i16) -> bool { a.checked_next_multiple_of(b).is_some() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u32, b: u32) -> bool { a.checked_next_multiple_of(b).is_none() }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_logarithm_options_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u64, radix: u64, fallback: u32) -> u32 { a.checked_ilog(radix).unwrap_or(fallback) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i16) -> u32 { a.checked_ilog2().unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8) -> bool { a.checked_ilog10().is_some() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i64, radix: i64) -> bool { a.checked_ilog(radix).is_none() }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_generic_checked_cast_options_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u16, fallback: u8) -> u8 { input.checked_cast::<u8>().unwrap_or(fallback) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64) -> u32 { input.checked_cast::<u32>().unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64) -> bool { input.checked_cast::<i32>().is_some() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i8) -> bool { input.checked_cast::<u64>().is_none() }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_generic_checked_truncation_options_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u32, fallback: u8) -> u8 { input.checked_truncate::<u8>().unwrap_or(fallback) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64) -> i16 { input.checked_truncate::<i16>().unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64) -> bool { input.checked_truncate::<u32>().is_some() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i16) -> bool { input.checked_truncate::<i8>().is_none() }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_integer_option_unwrap_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8) -> u8 { a.checked_add(b).unwrap() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i64, b: i64) -> i64 { a.checked_div(b).unwrap() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u64, b: u64) -> i64 { a.checked_signed_diff(b).unwrap() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64) -> i16 { input.checked_truncate::<i16>().unwrap() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64) -> u32 { input.checked_ilog2().unwrap() }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_integer_option_expect_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8) -> u8 { a.checked_add(b).expect(\"overflow\") }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u64, b: u64, message: &str) -> i64 { a.checked_signed_diff(b).expect(message) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64, message: &mut str) -> i16 { input.checked_truncate::<i16>().expect(message) }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_integer_option_unwrap_unchecked_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(a: u8, b: u8) -> u8 { a.checked_add(b).unwrap_unchecked() }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(a: u64, b: u64) -> i64 { a.checked_signed_diff(b).unwrap_unchecked() }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: i64) -> i16 { input.checked_truncate::<i16>().unwrap_unchecked() }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_integer_option_unwrap_or_else_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8, fallback: u8) -> u8 { a.checked_add(b).unwrap_or_else(|| fallback) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i64, b: i64) -> i64 { a.checked_div(b).unwrap_or_else(|| -1) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64, fallback: i16) -> i16 { input.checked_truncate::<i16>().unwrap_or_else(|| fallback) }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_integer_option_closure_predicates_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8, threshold: u8) -> bool { a.checked_add(b).is_some_and(|value| value > threshold) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64, expected: i16) -> bool { input.checked_truncate::<i16>().is_some_and(|value| value == expected) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u64, b: u64) -> bool { a.checked_signed_diff(b).is_none_or(|value| value >= -10) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64) -> bool { input.checked_ilog2().is_some_and(|value| value < 64) }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_integer_option_filters_reach_native_predicates() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8, threshold: u8) -> bool { a.checked_add(b).filter(|value| *value > threshold).is_some() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64, expected: i16) -> bool { input.checked_truncate::<i16>().filter(|value| *value == expected).is_none() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u64, b: u64) -> bool { a.checked_signed_diff(b).filter(|value| *value >= -10).is_some() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64) -> bool { input.checked_ilog2().filter(|value| *value < 64).is_none() }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_filtered_checked_options_reach_all_terminal_families() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8, threshold: u8) -> u8 { a.checked_add(b).filter(|value| *value > threshold).unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8, threshold: u8) -> bool { a.checked_add(b).filter(|value| *value > threshold).is_some_and(|value| value < 200) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8, threshold: u8, fallback: u32) -> u32 { a.checked_add(b).filter(|value| *value > threshold).map_or_else(|| fallback, |value| value as u32 * 2) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8, low: u8, high: u8) -> u32 { a.checked_add(b).filter(|value| *value > low).filter(|value| *value < high).map_or_default(|value| value as u32) }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_mapped_checked_options_compose_before_terminal_consumers() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8, offset: u32) -> u32 { a.checked_add(b).map(|value| value as u32 + offset).unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8, low: u32) -> u64 { a.checked_add(b).map(|value| value as u32 * 2).filter(|value| *value > low).map(|value| value as u64 + 1).map_or_default(|value| value) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8) -> bool { a.checked_add(b).map(|value| value as u64 + 1).is_some_and(|value| value < 200) }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_option_inspection_preserves_composable_payloads() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8) -> u8 { a.checked_add(b).inspect(|value| ()).unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8, threshold: u32) -> u64 { a.checked_add(b).map(|value| value as u32 * 2).inspect(|value| if *value > threshold { () } else { () }).filter(|value| *value > threshold).map(|value| value as u64 + 1).unwrap_or_default() }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_option_and_then_composes_producers() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8, limit: u8) -> u16 { a.checked_add(b).and_then(|sum| sum.checked_mul(limit)).map(|value| value as u16).unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u64, b: u64) -> bool { a.checked_signed_diff(b).and_then(|difference| difference.checked_abs()).is_some() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64, divisor: i16, fallback: i16) -> i16 { input.checked_truncate::<i16>().and_then(|value| value.checked_div(divisor)).unwrap_or(fallback) }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_option_or_else_recovers_lazily() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8, fallback: u8) -> u8 { a.checked_add(b).or_else(|| fallback.checked_add(1)).unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u64, b: u64, fallback: i64) -> bool { a.checked_signed_diff(b).or_else(|| fallback.checked_abs()).is_some() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8) -> u8 { a.checked_add(b).or_else(|| 1u8.checked_div(0)).unwrap_or_default() }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_option_or_selects_the_first_producer() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8, fallback: u8) -> u8 { a.checked_add(b).or(fallback.checked_add(1)).unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i64, b: i64, fallback: i64) -> i64 { a.checked_mul(b).or(fallback.checked_abs()).map(|value| value + 1).unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u64, b: u64, fallback: i64) -> bool { a.checked_signed_diff(b).or(fallback.checked_abs()).is_none() }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_option_xor_selects_exactly_one_producer() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8, fallback: u8) -> u8 { a.checked_add(b).xor(fallback.checked_add(1)).unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i64, b: i64, fallback: i64) -> i64 { a.checked_mul(b).xor(fallback.checked_abs()).map(|value| value + 1).unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u64, b: u64, fallback: i64) -> bool { a.checked_signed_diff(b).xor(fallback.checked_abs()).is_none() }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_option_and_sequences_producers() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8, fallback: u16) -> u16 { a.checked_add(b).and(fallback.checked_mul(1000)).unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: i8, b: i8, fallback: i64) -> i64 { a.checked_mul(b).and(fallback.checked_abs()).map(|value| value + 1).unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u64, b: u64, fallback: i16) -> bool { a.checked_signed_diff(b).and(fallback.checked_abs()).is_some_and(|value| value > 10) }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_boolean_option_constructors_preserve_eagerness() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(flag: bool, value: u16, fallback: u16) -> u16 { flag.then_some(value).unwrap_or(fallback) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(flag: bool, numerator: i64, divisor: i64) -> i64 { flag.then(|| numerator / divisor).unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(flag: bool, value: u8) -> u32 { flag.then_some(value).map(|present| present as u32 + 1).unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(flag: bool, value: i16) -> bool { flag.then(|| value).is_some_and(|present| present > 10) }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_scalar_let_shadowing_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8) -> u64 { let input: u16 = input as u16 + 1; let mut input: u64 = input as u64 * 2; input += 3; let input: u32 = input as u32 + 5; input as u64 }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i16) -> i64 { let input: i32 = input as i32 - 1; let input: i64 = input as i64 * -2; input }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_interleaved_nested_loop_controls_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u16, gate: bool, stop: u16) -> u16 { let mut outer: u16 = 0; while outer < limit { outer += 1; let seed: u16 = outer + limit; while seed < stop { if gate && seed == outer { continue; } let inner: u16 = seed + outer; if inner == stop { break; } if gate && inner == limit { return inner + outer; } outer += inner; break; } } outer }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_literal_aggregate_read_order_reaches_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: u16, second: u16, index: usize, choose: bool) -> u16 { let repeated: [u16; 3] = [first + second; 3]; let values: [u16; 3] = [first, repeated[index], if choose { second } else { first }]; let pair: (u16, u16) = (values[0], second + first); pair.0 }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_aggregate_copy_reads_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: [u16; 3], first: u16, second: u16) -> u16 { let copied: [u16; 3] = values; let pair: (u16, u16) = (first, second); let pair_copy: (u16, u16) = pair; copied[0] + pair_copy.1 }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_conditional_tuple_literal_reads_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: u16, second: u16, choose: bool) -> u16 { let selected: (u16, u16) = if choose { (first + 1, second) } else { (second + 2, first) }; selected.0 + selected.1 }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_conditional_array_literal_reads_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: u16, second: u16, left: u16, right: u16, choose: bool) -> u16 { let selected: [u16; 2] = if choose { [first + left, second] } else { [right, first + second] }; selected[0] + selected[1] }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_sequence_wrapped_aggregate_reads_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: u16, second: u16, left: u16, right: u16, prefix: u16) -> u16 { let pair: (u16, u16) = { prefix + first; (left, right) }; let values: [u16; 2] = { prefix + second; [first, left] }; pair.0 + values[1] }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_simple_fat_reference_initializer_reads_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &[u16], alternate: &[u16], text: &str, choose: bool, prefix: usize) -> usize { let direct: &[u16] = input; let selected: &[u16] = if choose { direct } else { alternate }; let copied_text: &str = { prefix; text }; selected.len() + copied_text.len() }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_call_derived_fat_reference_initializer_reads_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &[usize], prefix: usize, start: usize, end: usize, bias: usize) -> usize { let selected: &[usize] = { prefix; choose(input, start, end, bias) }; selected.len() } fn choose(values: &[usize], start: usize, end: usize, bias: usize) -> &[usize] { if bias == 0 { &values[start..end] } else { values } }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_identifier_aggregate_call_argument_reads_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: usize, second: usize, third: usize, left: usize, right: usize, prefix: usize, bias: usize) -> usize { let values = [first, second, third]; let pair = (left, right); let selected: &[usize] = { prefix; choose_aggregate(values, pair, bias) }; selected.len() } fn choose_aggregate(values: [usize; 3], pair: (usize, usize), bias: usize) -> &[usize] { pair.0; if bias == 0 { &values[..] } else { &values[1..] } }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_literal_aggregate_call_argument_reads_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: usize, second: usize, third: usize, left: usize, right: usize, prefix: usize, bias: usize, choose: bool) -> usize { let selected: &[usize] = { prefix; choose_literal([first, second, third], if choose { (left, right) } else { (right, left) }, bias) }; let repeated: &[usize] = choose_literal([first; 3], (left, right), bias); selected.len() + repeated.len() } fn choose_literal(values: [usize; 3], pair: (usize, usize), bias: usize) -> &[usize] { pair.0; if bias == 0 { &values[..] } else { &values[1..] } }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_conditional_array_call_argument_reads_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: usize, second: usize, third: usize, left: usize, right: usize, prefix: usize, bias: usize, choose: bool) -> usize { let selected: &[usize] = { prefix; choose_conditional(if choose { [first, second, third] } else { [third, second, first] }, (left, right), bias) }; selected.len() } fn choose_conditional(values: [usize; 3], pair: (usize, usize), bias: usize) -> &[usize] { pair.0; if bias == 0 { &values[..] } else { &values[1..] } }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_sequence_wrapped_array_call_argument_reads_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: usize, second: usize, third: usize, left: usize, right: usize, prefix: usize, bias: usize, choose: bool) -> usize { let selected: &[usize] = choose_wrapped({ prefix; if choose { [first, second, third] } else { [third, second, first] } }, (left, right), bias); selected.len() } fn choose_wrapped(values: [usize; 3], pair: (usize, usize), bias: usize) -> &[usize] { pair.0; if bias == 0 { &values[..] } else { &values[1..] } }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_sequence_wrapped_identifier_array_call_argument_reads_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: usize, second: usize, third: usize, left: usize, right: usize, prefix: usize, bias: usize) -> usize { let values = [first, second, third]; let selected: &[usize] = choose_wrapped({ prefix; values }, (left, right), bias); selected.len() } fn choose_wrapped(values: [usize; 3], pair: (usize, usize), bias: usize) -> &[usize] { pair.0; if bias == 0 { &values[..] } else { &values[1..] } }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_sequence_wrapped_default_array_call_argument_reads_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: usize, right: usize, prefix: usize, bias: usize) -> usize { let selected: &[usize] = choose_wrapped({ prefix; Default::default() }, (left, right), bias); selected.len() } fn choose_wrapped(values: [usize; 3], pair: (usize, usize), bias: usize) -> &[usize] { pair.0; if bias == 0 { &values[..] } else { &values[1..] } }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_nested_wrapped_array_call_argument_reads_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: usize, second: usize, third: usize, left: usize, right: usize, outer: usize, bias: usize, choose: bool) -> usize { let values = [first, second, third]; let selected: &[usize] = choose_wrapped({ outer; if choose { { left; values } } else { { right; [third, second, first] } } }, (left, right), bias); selected.len() } fn choose_wrapped(values: [usize; 3], pair: (usize, usize), bias: usize) -> &[usize] { pair.0; if bias == 0 { &values[..] } else { &values[1..] } }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_integer_byte_array_call_argument_reads_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64, prefix: u64, bias: usize) -> usize { let selected: &[u8] = choose_bytes(({ prefix; input }).to_le_bytes(), bias); selected.len() } fn choose_bytes(values: [u8; 8], bias: usize) -> &[u8] { if bias == 0 { &values[..] } else { &values[1..] } }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_array_producing_call_argument_reads_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: usize, second: usize, third: usize, left: usize, right: usize, prefix: usize, bias: usize, choose: bool) -> usize { let direct: &[usize] = choose_wrapped(make_array(first, second, third), (left, right), bias); let wrapped: &[usize] = choose_wrapped({ prefix; if choose { make_array(first, second, third) } else { make_array(third, second, first) } }, (left, right), bias); direct.len() + wrapped.len() } fn make_array(first: usize, second: usize, third: usize) -> [usize; 3] { [first, second, third] } fn choose_wrapped(values: [usize; 3], pair: (usize, usize), bias: usize) -> &[usize] { pair.0; if bias == 0 { &values[..] } else { &values[1..] } }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_tuple_producing_call_argument_reads_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: usize, second: usize, prefix: usize, bias: usize, choose: bool) -> usize { let direct = consume_tuple(make_tuple(first, second), bias); let wrapped = consume_tuple({ prefix; if choose { make_tuple(first, second) } else { make_tuple(second, first) } }, bias); direct + wrapped } fn make_tuple(first: usize, second: usize) -> (usize, usize) { (first, second) } fn consume_tuple(pair: (usize, usize), bias: usize) -> usize { pair.0 + pair.1 + bias }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_tuple_loop_break_field_reads_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: usize, second: usize, prefix: usize, bias: usize) -> usize { let wrapped = consume_tuple(loop { break { prefix; make_tuple(first, second) }; }, bias); wrapped } fn make_tuple(first: usize, second: usize) -> (usize, usize) { (first, second) } fn consume_tuple(pair: (usize, usize), bias: usize) -> usize { pair.0 + pair.1 + bias }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_direct_array_call_return_reads_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: usize, second: usize, third: usize, prefix: usize, bias: usize) -> [usize; 3] { prefix; if bias == 0 { return make_array(first, second, third); } make_array(third, second, first) } fn make_array(first: usize, second: usize, third: usize) -> [usize; 3] { [first, second, third] }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_direct_array_value_return_reads_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: usize, second: usize, third: usize, prefix: usize, bias: usize) -> [usize; 3] { prefix; if bias == 0 { return [first, second, third]; } [third; 3] }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_direct_array_identifier_return_reads_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: [u16; 3], choose: bool) -> [u16; 3] { if choose { return values; } values }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_conditional_array_return_reads_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: usize, second: usize, third: usize, fourth: usize, prefix: usize, bias: usize, choose: bool) -> [usize; 2] { prefix; if bias == 0 { return if choose { [first, second] } else { [third, fourth] }; } if choose { [fourth, third] } else { [second, first] } }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_sequence_wrapped_array_return_reads_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: usize, second: usize, prefix: usize, suffix: usize, bias: bool) -> [usize; 2] { if bias { return { prefix; [first, second] }; } { suffix; [second, first] } }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_wrapped_array_calls_are_materialized_once() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: usize, second: usize, third: usize, prefix: usize, bias: usize, wrapper: usize, suffix: usize) -> [usize; 3] { prefix; if bias == 0 { return { wrapper; make_array(first, second, third) }; } { suffix; make_array(third, second, first) } } fn make_array(first: usize, second: usize, third: usize) -> [usize; 3] { [first, second, third] }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_range_derived_fat_reference_initializer_reads_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &[usize], start: usize, end: usize, left: usize) -> usize { let local = [10usize, 20usize, 30usize, 40usize]; let from_local: &[usize] = &local[start..end]; let from_input: &[usize] = &input[left..]; from_local.len() + from_input.len() }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_conditional_wrapped_fat_reference_reads_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &[usize], choose: bool, prefix: usize, start: usize, end: usize, left: usize) -> usize { let local = [10usize, 20usize, 30usize, 40usize]; let selected: &[usize] = if choose { { prefix; &local[start..end] } } else { &input[left..] }; selected.len() }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_fat_reference_explicit_and_tail_return_reads_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &[usize], choose: bool, start: usize, end: usize, left: usize) -> &[usize] { if choose { return &input[start..end]; } &input[left..] }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_wrapped_fat_reference_returns_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &[usize], choose: bool, alternate: bool, prefix: usize, suffix: usize, start: usize, end: usize, left: usize) -> &[usize] { if choose { return { prefix; if alternate { &input[start..end] } else { &input[left..] } }; } { suffix; &input[start..] } }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_call_derived_fat_reference_returns_reach_native_objects() {
    let source = "fn select_slice(values: &[usize], start: usize, end: usize, bias: usize) -> &[usize] { if bias == 0 { &values[start..end] } else { values } } #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &[usize], choose_call: bool, start: usize, end: usize, bias: usize, prefix: usize) -> &[usize] { if choose_call { return select_slice(input, start, end, bias); } { prefix; select_slice(input, start, end, bias) } }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_initial_conditional_return_cfg_reaches_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: usize, stop: bool) -> usize { let first = input + 1; if stop { return first; } let second = first + 1; second }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_exhaustive_conditional_return_cfg_reaches_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8) -> u8 { if input == 0 { return 10; } else if input == 1 { return 20; } else if input == 2 { return 30; } else { return 40; } }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_conditional_action_cfg_reaches_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8, mode: u8) -> u8 { let mut result: u8 = input; if mode == 0 { result += 1; } else if mode == 1 { result += 2; } else { result += 3; } result }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_initial_loop_cfg_reaches_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u8, stop: u8) -> u8 { let mut index: u8 = 0; while index < limit { index += 1; if index == stop { break; } } index }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_conditional_loop_block_cfg_reaches_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(mode: u8) -> u8 { let mut value: u8 = 0; loop { if mode == 0 { value += 1; continue; } else if mode == 1 { value += 2; break; } else { return value; } } value }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_nested_loop_cfg_reaches_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(enter: bool, stop: bool) -> u8 { let mut value: u8 = 0; while enter { 'inner: loop { value += 1; if value == 1 { continue 'inner; } if stop { break 'inner; } break 'inner; } break; } value }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_unit_break_loop_cfg_reaches_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(enter: bool) -> u8 { let mut value: u8 = 0; while enter { loop { break; } value += 1; break; } value }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_post_terminal_loop_cfg_reaches_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { loop { continue; let unreachable: u8 = 1; if unreachable == 1 { break; } } 42 }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_post_terminal_nested_loop_cfg_reaches_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> u8 { loop { 'inner: loop { continue 'inner; let unreachable: u8 = 1; unreachable; } } }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_post_return_conditional_action_cfg_reaches_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(mode: bool) -> u8 { let mut result: u8 = 0; if mode { result = 1; return 1; result = 2; } result }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_initialized_move_path_roots_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u16) -> u16 { let first: u16 = input; let second: u16 = first + 1; second }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_wildcard_let_initializers_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64, divisor: u64) -> u64 { let _: u64 = input + 1; let _: [u64; 2] = [input, input + 2]; let _: u64 = 84 / divisor; input + 2 }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &[u8]) -> usize { let _: &[u8] = &values[..]; values.len() }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_underscore_assignments_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64, divisor: u64, choose: bool) -> u64 { _ = [input, input + 1]; _ = if choose { 84 / divisor } else { input + 2 }; input + 2 }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &[u8]) -> usize { _ = &values[..]; values.len() }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_prior_scalar_function_calls_reach_native_objects() {
    let sources = [
        "fn add(value: u16, offset: u16) -> u16 { let mut total: u16 = value; total += offset; total } fn twice(value: u16) -> u64 { let doubled: u16 = add(value, value); doubled as u64 } #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u8, choose: bool) -> u64 { if choose { twice(add(value as u16, 5)) } else { twice(add(value as u16, 6)) } }",
        "fn classify(value: u16) -> u64 { let adjusted: u16 = value + 1; if adjusted > 100 { return adjusted as u64 + 1; } else if adjusted > 50 { return 70; } else { return adjusted as u64; } } #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u16) -> u64 { classify(value) }",
        "fn adjust(value: u16, choose: bool) -> u64 { let mut total: u16 = value; if choose { let delta: u16 = 3; total += delta; } else if value > 10 { total *= 2; } else { total += 1; } total as u64 } #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u16, choose: bool) -> u64 { adjust(value, choose) + 5 }",
        "fn adjust(value: u64, choose: bool) -> u64 { let mut total: u64 = value; if choose { let delta: u64 = 3; total += delta; return total; } else if value > 10 { total *= 2; } else { total += 1; } total } #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u64, choose: bool) -> u64 { adjust(value, choose) + 5 }",
        "fn sum_to(limit: u64) -> u64 { let mut index: u64 = 0; let mut total: u64 = 0; while index < limit { let current: u64 = index; total += current; index += 1; } total } #[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u64) -> u64 { sum_to(limit) + 1 }",
        "fn odd_sum_until(limit: u64) -> u64 { let mut index: u64 = 0; let mut total: u64 = 0; while index < limit { index += 1; let current: u64 = index; if current % 2 == 0 { continue; } total += current; if total > 20 { break; } } total } #[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u64) -> u64 { odd_sum_until(limit) + 1 }",
        "fn find_three(limit: u64) -> u64 { let mut index: u64 = 0; while index < limit { let current: u64 = index; if current == 3 { return current + 10; } index += 1; } 99 } #[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u64) -> u64 { find_three(limit) + 1 }",
        "fn route_loop(limit: u64, return_five: bool) -> u64 { let mut index: u64 = 0; let mut total: u64 = 0; while index < limit { index += 1; if index == 5 && return_five { return 50; } else if index % 2 == 0 { continue; } else if index > 6 { break; } else { total += index; } } total } #[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u64, return_five: bool) -> u64 { route_loop(limit, return_five) + 1 }",
        "fn route_nested(limit: u64, skip_outer: bool, break_outer: bool, return_inner: bool) -> u64 { let mut outer: u64 = 0; let mut total: u64 = 0; 'outer: while outer < limit { outer += 1; let mut inner: u64 = 0; while inner < 5 { inner += 1; if skip_outer && inner == 2 { continue 'outer; } if break_outer && outer == 3 && inner == 3 { break 'outer; } if return_inner && outer == 2 && inner == 4 { return 70 + total; } if inner % 2 == 0 { continue; } total += outer * 10 + inner; if inner == 5 { break; } } } total } #[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u64, skip_outer: bool, break_outer: bool, return_inner: bool) -> u64 { route_nested(limit, skip_outer, break_outer, return_inner) + 1 }",
        "fn route_unconditional(limit: u64, stop: bool) -> u64 { let mut outer: u64 = 0; let mut total: u64 = 0; 'outer: loop { outer += 1; let mut inner: u64 = 0; loop { inner += 1; if inner == 2 { continue; } if stop && outer == 2 && inner == 3 { return 70 + total; } total += outer * 10 + inner; if inner >= 3 { break; } } if outer >= limit { break 'outer; } } total } #[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u64, stop: bool) -> u64 { route_unconditional(limit, stop) + 1 }",
        "fn maybe_spin(value: u64) -> u64 { if value == 0 { return 7; } loop {} } #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u64, call: bool) -> u64 { if call { maybe_spin(value) + 1 } else { 11 } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u64, choose: bool) -> u64 { route(value, choose) + 1 } fn route(value: u64, choose: bool) -> u64 { if choose { adjust(value, 3) } else { adjust(value, 5) } } fn adjust(value: u64, delta: u64) -> u64 { finish(value + delta) } fn finish(value: u64) -> u64 { if value > 20 { return value * 2; } value + 7 }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: char, choose: bool) -> char { select(value, choose) } fn select(value: char, choose: bool) -> char { if choose { identity(value) } else if value == '\0' { identity('\u{10ffff}') } else { identity('🦀') } } fn identity(value: char) -> char { value }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u64) -> u64 { forward(value); consume(()); 7 } fn forward(value: u64) { check(value); } fn check(value: u64) { if value == 0 { return; } value; } fn consume(unit: ()) { unit; }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *mut u16, fallback: usize, choose: bool) -> usize { let selected: *const u16 = select(input, fallback as *const u16, choose); selected.addr() } fn select(primary: *mut u16, fallback: *const u16, choose: bool) -> *const u16 { if choose { identity(primary) } else { identity(fallback) } } fn identity(value: *const u16) -> *const u16 { value }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: &mut u16, delta: u16) -> u16 { *update(value, delta) } fn update(value: &mut u16, delta: u16) -> &mut u16 { *value += delta; identity(value) } fn identity(value: &mut u16) -> &mut u16 { value }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: &mut u16) -> u16 { read(value) } fn read(value: &u16) -> u16 { *identity(value) } fn identity(value: &u16) -> &u16 { value }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: &mut bool) -> bool { *flip(value) } fn flip(value: &mut bool) -> &mut bool { *value = !*value; value }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: &char) -> char { *identity(value) } fn identity(value: &char) -> &char { value }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &mut [u16; 4], index: usize, delta: u16, mutate: bool) -> u16 { if mutate { update(values, index, delta)[index] } else { read(values, index) } } fn update(values: &mut [u16; 4], index: usize, delta: u16) -> &mut [u16; 4] { values[index] += delta; values } fn read(values: &[u16; 4], index: usize) -> u16 { values[index] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &mut [bool; 2]) -> bool { flip(values)[1] } fn flip(values: &mut [bool; 2]) -> &mut [bool; 2] { values[1] = !values[1]; values }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &[char; 2]) -> char { identity(values)[1] } fn identity(values: &[char; 2]) -> &[char; 2] { values }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() { let values: [(); 2] = [(); 2]; identity(&values)[1] } fn identity(values: &[(); 2]) -> &[(); 2] { values }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &[u16], text: &str, index: usize) -> usize { score(identity(values), text, index) } fn identity(values: &[u16]) -> &[u16] { values } fn score(values: &[u16], text: &str, index: usize) -> usize { values.len() + values[index] as usize + text.len() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &mut [u16], index: usize, early: bool) -> u16 { let selected: &mut [u16] = choose(values, early); selected[index] += 1; selected[index] } fn choose(values: &mut [u16], early: bool) -> &mut [u16] { if early { return identity(values); } identity(values) } fn identity(values: &mut [u16]) -> &mut [u16] { values }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(text: &str) -> usize { let returned: &str = identity(text); returned.len() } fn identity(text: &str) -> &str { text }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &[char]) -> char { identity(values)[0] } fn identity(values: &[char]) -> &[char] { values }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &mut [bool]) -> bool { let returned: &mut [bool] = identity(values); returned[0] = !returned[0]; returned[0] } fn identity(values: &mut [bool]) -> &mut [bool] { values }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() { let values: [(); 2] = [(); 2]; identity(&values[..])[1] } fn identity(values: &[()]) -> &[()] { values }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: u16, alternate: u16, first: bool) -> u16 { choose(value, alternate, first) } fn choose(value: u16, alternate: u16, first: bool) -> u16 { let offset: u16 = 1; loop { if first { break value + offset; } break alternate + offset; } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: &mut char, first: bool) -> char { *choose(value, first) } fn choose(value: &mut char, first: bool) -> &mut char { loop { if first { break value; } break value; } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &[bool], first: bool) -> usize { let returned: &[bool] = choose(values, first); returned.len() } fn choose(values: &[bool], first: bool) -> &[bool] { loop { if first { break values; } break values; } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() { finish() } fn finish() { loop { break; } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: u16, second: u16, third: u16, early: bool) -> u16 { let returned: [u16; 3] = choose([first, second, third], early); returned[0] + returned[1] + returned[2] } fn choose(values: [u16; 3], early: bool) -> [u16; 3] { if early { return identity(values); } identity(values) } fn identity(values: [u16; 3]) -> [u16; 3] { values }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: bool, second: bool) -> bool { identity([first, second])[1] } fn identity(values: [bool; 2]) -> [bool; 2] { values }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: char, second: char) -> char { identity([first, second])[1] } fn identity(values: [char; 2]) -> [char; 2] { values }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() { identity([(); 4])[3] } fn identity(values: [(); 4]) -> [(); 4] { values }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: u64, second: u64, third: u64) -> u64 { let returned: [u64; 3] = identity([first, second, third]); returned[0] + returned[1] + returned[2] } fn identity(values: [u64; 3]) -> [u64; 3] { values }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_integer_option_map_or_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8, offset: u32) -> u32 { a.checked_add(b).map_or(99u32, |value| value as u32 + offset) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u64, b: u64, threshold: i64) -> bool { a.checked_signed_diff(b).map_or(false, |value| value < threshold) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64, fallback: i64) -> i64 { input.checked_truncate::<i16>().map_or(fallback, |value| value as i64 * 2) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64) -> char { input.checked_ilog2().map_or('x', |value| if value > 3 { 'y' } else { 'z' }) }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_integer_option_map_or_else_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8, fallback: u32, offset: u32) -> u32 { a.checked_add(b).map_or_else(|| fallback, |value| value as u32 + offset) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u64, b: u64, fallback: bool, threshold: i64) -> bool { a.checked_signed_diff(b).map_or_else(|| fallback, |value| value < threshold) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64, fallback: i64) -> i64 { input.checked_truncate::<i16>().map_or_else(|| fallback, |value| value as i64 * 2) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64) -> char { input.checked_ilog2().map_or_else(|| 'x', |value| if value > 3 { 'y' } else { 'z' }) }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_integer_option_map_or_default_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u8, b: u8, offset: u32) -> u32 { a.checked_add(b).map_or_default(|value| value as u32 + offset) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: u64, b: u64, threshold: i64) -> bool { a.checked_signed_diff(b).map_or_default(|value| value < threshold) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64) -> i64 { input.checked_truncate::<i16>().map_or_default(|value| value as i64 * 2) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64) -> char { input.checked_ilog2().map_or_default(|value| if value > 3 { 'y' } else { 'z' }) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u64) -> *const u8 { input.checked_ilog2().map_or_default(|value| value as usize as *const u8) }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_checked_sign_cast_options_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u32, fallback: i32) -> i32 { input.checked_cast_signed().unwrap_or(fallback) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64) -> u64 { input.checked_cast_unsigned().unwrap_or_default() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u16) -> bool { input.checked_cast_signed().is_some() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i8) -> bool { input.checked_cast_unsigned().is_none() }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_signed_clamp_magnitude_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i8, limit: u8) -> i8 { value.clamp_magnitude(limit) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i64, limit: u64) -> i64 { value.clamp_magnitude(limit) }",
    ];
    for source in sources {
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }

    assert!(compile_wide(
        "const VALUE: i8 = 120i8.clamp_magnitude(100); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> i8 { VALUE }",
        ObjectFormat::Elf64,
    )
    .is_err());
}

#[test]
fn rustc_ascii_byte_predicates_reach_native_objects() {
    let methods = [
        "is_ascii",
        "is_ascii_alphabetic",
        "is_ascii_uppercase",
        "is_ascii_lowercase",
        "is_ascii_alphanumeric",
        "is_ascii_digit",
        "is_ascii_hexdigit",
        "is_ascii_punctuation",
        "is_ascii_graphic",
        "is_ascii_whitespace",
        "is_ascii_control",
    ];
    for method in methods {
        let mut source = [0u8; 192];
        let prefix = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8) -> bool { input.";
        let suffix = "() }";
        let length = prefix.len() + method.len() + suffix.len();
        source[..prefix.len()].copy_from_slice(prefix.as_bytes());
        source[prefix.len()..prefix.len() + method.len()].copy_from_slice(method.as_bytes());
        source[prefix.len() + method.len()..length].copy_from_slice(suffix.as_bytes());
        let runtime_source = core::str::from_utf8(&source[..length]).unwrap();
        assert_eq!(
            compile_wide(runtime_source, ObjectFormat::Elf64),
            Ok(()),
            "{runtime_source}"
        );
        assert_eq!(
            compile_wide(runtime_source, ObjectFormat::Coff),
            Ok(()),
            "{runtime_source}"
        );

        let const_prefix = "const VALUE: bool = 65u8.";
        let const_suffix = "(); #[unsafe(no_mangle)] pub extern \"C\" fn probe() -> bool { VALUE }";
        let length = const_prefix.len() + method.len() + const_suffix.len();
        source[..const_prefix.len()].copy_from_slice(const_prefix.as_bytes());
        source[const_prefix.len()..const_prefix.len() + method.len()]
            .copy_from_slice(method.as_bytes());
        source[const_prefix.len() + method.len()..length].copy_from_slice(const_suffix.as_bytes());
        let source = core::str::from_utf8(&source[..length]).unwrap();
        assert_eq!(
            compile_wide(source, ObjectFormat::Elf64),
            Ok(()),
            "{source}"
        );
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()), "{source}");
    }
}

#[test]
fn rustc_independent_aggregate_parameter_widths_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8, values: [u16; 3]) -> u8 { if values[1] == 257 { input + 1 } else { input } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8, values: &[u16; 3], slice: &[i32]) -> u8 { if values[1] == 257 && slice[0] == -3 { input + 1 } else { input } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8, flag: &bool, character: &char) -> u8 { if *flag && *character == 'z' { input + 1 } else { input } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8, wide: &mut u64, values: &mut [u16; 3], slice: &mut [i16]) -> u8 { *wide += 2; values[1] += 1; slice[0] += 2; if *wide == 258 && values[1] == 258 && slice[0] == -1 { input + 1 } else { input } }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_sixteen_element_fixed_arrays_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: [u8; 16]) -> [u8; 16] { let mut copied = values; copied[15] += 1; copied }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: usize) -> usize { let mut values = [input; 16]; values[15] += 1; values[15] }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_immutable_scalar_references_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(before: usize, input: &usize, after: usize) -> usize { let copied = input; before + *copied + after }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &i16) -> i16 { *input }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &bool) -> bool { *input }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &char) -> char { *input }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_thin_reference_returns_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &u16) -> &u16 { input }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut i32) -> &mut i32 { input }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &[u8; 4]) -> &[u8; 4] { input }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &u16) -> &u16 { let copied: &u16 = input; copied }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut u16) -> &mut u16 { &mut *input }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut u16) -> &u16 { input }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_slice_reference_returns_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &[u16]) -> &[u16] { input }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [i32]) -> &mut [i32] { input }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &[u8]) -> &[u8] { let copied: &[u8] = input; copied }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &[u16], start: usize, end: usize) -> &[u16] { &input[start..end] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u16], start: usize, end: usize) -> &mut [u16] { &mut input[start..end] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u16]) -> &[u16] { input }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_indexed_element_references_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &[u16], index: usize) -> &u16 { &input[index] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [i32], index: usize) -> &mut i32 { &mut input[index] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &[u8; 4], index: usize) -> &u8 { &input[index] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u16; 4], index: usize) -> &mut u16 { &mut input[index] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u16, index: usize) -> u16 { let mut values = [input, 40u16]; let selected: &mut u16 = &mut values[index]; *selected += 2; values[index] }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_conditional_slice_reference_returns_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &[u16], select: bool) -> &[u16] { if select { &input[..1] } else { &input[1..] } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u16], select: bool) -> &mut [u16] { if select { &mut input[..1] } else { &mut input[1..] } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u16], select: bool) -> &[u16] { if select { input } else { &input[1..] } }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_conditional_slice_reference_locals_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &[u16], select: bool) -> &[u16] { let selected: &[u16] = if select { &input[..1] } else { &input[1..] }; selected }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u16], select: bool) -> u16 { let selected: &mut [u16] = if select { &mut input[..1] } else { &mut input[1..] }; selected[0] += 2; selected[0] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &[u16], select: bool) -> usize { let selected = if select { &input[..1] } else { &input[1..] }; selected.len() }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_slice_reference_local_replacements_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &[u16], select: bool) -> &[u16] { let mut selected: &[u16] = &input[..1]; if select { selected = &input[1..]; } selected }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u16], select: bool) -> u16 { let mut selected: &mut [u16] = &mut input[..1]; if select { selected = &mut input[1..]; } selected[0] += 2; selected[0] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u16]) -> usize { let mut selected: &[u16] = input; selected = &input[1..]; selected.len() }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_string_slice_references_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &str) -> usize { input.len() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &str) -> bool { input.is_empty() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &str) -> &str { input }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &str, select: bool) -> &str { let selected: &str = if select { input } else { input }; selected }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut str) -> &str { input }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_utf8_checked_string_ranges_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &str, start: usize, end: usize) -> &str { &input[start..end] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &str, end: usize) -> &str { &input[..end] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &str, start: usize) -> &str { &input[start..] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &str) -> &str { &input[..] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &str, start: usize, end: usize) -> &str { &input[start..=end] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut str, start: usize, end: usize) -> &mut str { &mut input[start..end] }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_string_as_bytes_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &str) -> &[u8] { input.as_bytes() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &str, index: usize) -> u8 { let bytes: &[u8] = input.as_bytes(); bytes[index] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &str) -> usize { input.as_bytes().len() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut str) -> &[u8] { input.as_bytes() }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_string_character_boundary_checks_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &str, index: usize) -> bool { input.is_char_boundary(index) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &str) -> bool { input.is_char_boundary(0) && input.is_char_boundary(input.len()) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &str, index: usize) -> bool { let copied: &str = input; copied.is_char_boundary(index) }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_reference_data_pointers_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &[u16]) -> *const u16 { input.as_ptr() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut [u16]) -> *mut u16 { input.as_mut_ptr() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &str) -> *const u8 { input.as_ptr() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *mut u16) -> *const u16 { let copied: *const u16 = input; copied }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_scalar_raw_pointer_dereferences_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *const u16) -> u16 { *input }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *const u32) -> u32 { input.read() }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *const u32) -> u32 { input.read_unaligned() }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *mut u32) -> u32 { input.read_volatile() }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *mut u16) -> u16 { *input = 42; *input }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *mut i16) -> i16 { *input += 2; *input }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_scalar_raw_pointer_unchecked_references_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *const u32) -> u32 { *input.as_ref_unchecked() }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *mut i16) -> i16 { *input.as_ref_unchecked() }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *mut i16) -> i16 { let reference: &mut i16 = input.as_mut_unchecked(); *reference += 2; *reference }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_scalar_raw_pointer_writes_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *mut u32, value: u32) { input.write(value) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *mut u32, value: u32) { input.write_unaligned(value) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *mut u32, value: u32) { input.write_volatile(value) }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_scalar_raw_pointer_byte_fills_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *mut u8, value: u8, count: usize) { input.write_bytes(value, count) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *mut u16, value: u8, count: usize) { input.write_bytes(value, count) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *mut u32, value: u8, count: usize) { input.write_bytes(value, count) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *mut u64, value: u8, count: usize) { input.write_bytes(value, count) }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_scalar_raw_pointer_copies_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(source: *const u8, destination: *mut u8, count: usize) { source.copy_to(destination, count) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(source: *const u16, destination: *mut u16, count: usize) { source.copy_to(destination, count) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(source: *const u32, destination: *mut u32, count: usize) { source.copy_to_nonoverlapping(destination, count) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(source: *const u64, destination: *mut u64, count: usize) { source.copy_to_nonoverlapping(destination, count) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(source: *const u8, destination: *mut u8, count: usize) { destination.copy_from(source, count) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(source: *const u32, destination: *mut u32, count: usize) { destination.copy_from_nonoverlapping(source, count) }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_scalar_raw_pointer_replacements_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *mut u32, value: u32) -> u32 { input.replace(value) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *mut i16, value: i16) -> i16 { input.replace(value) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *mut bool, value: bool) -> bool { input.replace(value) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *mut char, value: char) -> char { input.replace(value) }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_scalar_raw_pointer_swaps_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(left: *mut u32, right: *mut u32) { left.swap(right) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(left: *mut i16, right: *mut i16) { left.swap(right) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(left: *mut bool, right: *mut bool) { left.swap(right) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(left: *mut char, right: *mut char) { left.swap(right) }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_scalar_raw_pointer_comparisons_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: *const u16, right: *const u16) -> bool { left == right }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: *const u16, right: *const u16) -> bool { left < right }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: *mut u16, right: *const u16) -> bool { left != right }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_scalar_raw_pointer_casts_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *const u16) -> usize { input as usize }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: usize) -> *const u8 { input as *const u8 }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *mut u16) -> *const u8 { input as *const u8 }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *const u16) -> *mut u16 { input as *mut u16 }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *const u16) -> u8 { input as u8 }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_scalar_raw_pointer_offsets_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *const u16, offset: usize) -> *const u16 { input.add(offset) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *mut i32, offset: usize) -> *mut i32 { input.sub(offset) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *const u8, offset: usize) -> *const u8 { input.wrapping_add(offset) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *const char, offset: usize) -> *const char { input.wrapping_sub(offset) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *const u64, forward: usize, back: usize) -> *const u64 { input.add(forward).sub(back) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *const u32, offset: isize) -> *const u32 { input.offset(offset) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *mut u64, offset: isize) -> *mut u64 { input.wrapping_offset(offset) }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_scalar_raw_pointer_distances_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(pointer: *const u16, origin: *const u16) -> isize { pointer.offset_from(origin) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(pointer: *mut u64, origin: *const u64) -> isize { pointer.offset_from(origin) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(pointer: *const char, origin: *mut char) -> isize { pointer.offset_from(origin) }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_unsigned_raw_pointer_distances_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(pointer: *const u16, origin: *const u16) -> usize { pointer.offset_from_unsigned(origin) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(pointer: *mut u64, origin: *const u64) -> usize { pointer.offset_from_unsigned(origin) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(pointer: *const u32, origin: *const u32) -> usize { pointer.byte_offset_from_unsigned(origin) }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_scalar_raw_pointer_alignment_offsets_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(pointer: *const u8, alignment: usize) -> usize { pointer.align_offset(alignment) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(pointer: *const u16, alignment: usize) -> usize { pointer.align_offset(alignment) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(pointer: *mut u32, alignment: usize) -> usize { pointer.align_offset(alignment) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(pointer: *const u64, alignment: usize) -> usize { pointer.align_offset(alignment) }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_scalar_raw_pointer_alignment_checks_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(pointer: *const u8) -> bool { pointer.is_aligned() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(pointer: *const u16) -> bool { pointer.is_aligned() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(pointer: *mut u32) -> bool { pointer.is_aligned() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(pointer: *const u64) -> bool { pointer.is_aligned() }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_scalar_raw_pointer_masks_and_explicit_alignment_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *const u32, mask: usize) -> *const u32 { input.mask(mask) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *mut i16, mask: usize) -> *mut i16 { input.mask(mask) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *const u32, alignment: usize) -> bool { input.is_aligned_to(alignment) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *mut char, alignment: usize) -> bool { input.is_aligned_to(alignment) }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_scalar_raw_pointer_drops_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *mut u32) { input.drop_in_place() }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *mut bool) { input.drop_in_place() }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *mut char) { input.drop_in_place() }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_raw_pointer_byte_offsets_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *const u32, offset: usize) -> *const u32 { input.byte_add(offset) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *mut u64, offset: usize) -> *mut u64 { input.byte_sub(offset) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(input: *const u16, offset: isize) -> *const u16 { input.byte_offset(offset) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *const u32, offset: usize) -> *const u32 { input.wrapping_byte_add(offset) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *const u64, offset: usize) -> *const u64 { input.wrapping_byte_sub(offset) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *mut u16, offset: isize) -> *mut u16 { input.wrapping_byte_offset(offset) }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn probe(pointer: *const u32, origin: *const u32) -> isize { pointer.byte_offset_from(origin) }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_raw_pointer_null_checks_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *const u16) -> bool { input.is_null() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *mut char) -> bool { input.is_null() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> bool { (0usize as *const u8).is_null() }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_raw_pointer_addresses_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *const u16) -> usize { input.addr() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *mut char) -> usize { input.addr() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *const u32) -> usize { input.expose_provenance() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *mut u64) -> usize { input.expose_provenance() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *const u32, address: usize) -> *const u32 { input.with_addr(address) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *mut u64, address: usize) -> *mut u64 { input.with_addr(address) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *const u8, address: usize) -> usize { input.with_addr(address).addr() }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_scalar_raw_pointer_metadata_replacement_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *const u8, metadata: *const u32) -> *const u32 { input.with_metadata_of(metadata) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *mut u8, metadata: *const i16) -> *mut i16 { input.with_metadata_of(metadata) }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *mut bool, metadata: *mut char) -> *mut char { input.with_metadata_of(metadata) }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_raw_pointer_mutability_casts_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *const u16) -> *mut u16 { input.cast_mut() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *mut char) -> *const char { input.cast_const() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *const u8) -> *const u8 { input.cast_mut().cast_const() }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_raw_pointer_pointee_casts_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *const u32) -> *const u8 { input.cast::<u8>() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *mut u32) -> *mut i16 { input.cast::<i16>() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *const bool) -> *const char { input.cast::<char>() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: *mut char) -> *mut bool { input.cast::<bool>() }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_typed_and_mutable_scalar_reference_copies_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &usize) -> usize { let copied: &usize = input; *copied }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut usize) -> usize { let copied: &mut usize = input; *copied }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_mutable_scalar_reference_pointees_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut usize) -> usize { *input = 40; *input += 2; *input }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut i16) -> i16 { let copied: &mut i16 = input; *copied += 2; *copied }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut bool) -> bool { *input ^= true; *input }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut char) -> char { *input = 'z'; *input }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_scalar_reference_creation_and_reborrows_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: usize) -> usize { let reference: &usize = &input; *reference }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i16) -> i16 { let mut local = input; let reference: &mut i16 = &mut local; *reference += 2; local }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &mut usize) -> usize { let reference: &mut usize = &mut *input; *reference += 2; *input }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: &usize) -> usize { let reference: &usize = &*input; *reference }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_fixed_array_references_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &[usize; 4], index: usize) -> usize { let copied: &[usize; 4] = values; copied[index] + copied[0] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &mut [usize; 4], index: usize) -> usize { let copied: &mut [usize; 4] = &mut *values; copied[index] += 2; values[index] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &mut [i16; 3]) -> i16 { values[1] = -12; values[1] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &mut [bool; 3]) -> bool { values[2] ^= true; values[2] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &mut [char; 2]) -> char { values[1] = 'z'; values[1] }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_expanded_fixed_array_local_references_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: usize, index: usize) -> usize { let values = [input, 10, 20, 30]; let reference: &[usize; 4] = &values; reference[index] + reference[0] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: usize, index: usize) -> usize { let mut values = [input, 10, 20, 30]; let reference: &mut [usize; 4] = &mut values; let copied: &mut [usize; 4] = &mut *reference; copied[index] += 2; copied[index] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i16) -> i16 { let mut values = [input, 0, 0]; let reference: &mut [i16; 3] = &mut values; reference[1] = -12; reference[1] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: bool) -> bool { let mut values = [input, false, true]; let reference: &mut [bool; 3] = &mut values; reference[1] ^= true; reference[1] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: char) -> char { let mut values = [input, 'a']; let reference: &mut [char; 2] = &mut values; reference[1] = 'z'; reference[1] }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_slice_references_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &[usize], index: usize) -> usize { let copied: &[usize] = values; copied[index] + copied[0] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &mut [usize], index: usize) -> usize { let copied: &mut [usize] = &mut *values; copied[index] += 2; values[index] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &[usize]) -> usize { values.len() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &mut [usize]) -> usize { let copied: &mut [usize] = &mut *values; copied.len() + values.len() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &[usize]) -> bool { values.is_empty() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &mut [usize]) -> bool { let copied: &mut [usize] = &mut *values; copied.is_empty() || values.is_empty() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &mut [i16]) -> i16 { values[1] = -12; values[1] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &mut [bool]) -> bool { values[2] ^= true; values[2] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &mut [char]) -> char { values[1] = 'z'; values[1] }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_fixed_array_reference_ranges_create_slices() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &[usize; 4]) -> usize { let slice: &[usize] = &values[1..3]; slice.len() + slice[0] + slice[1] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &mut [usize; 4]) -> usize { let slice: &mut [usize] = &mut values[1..=2]; slice[1] += 2; values[2] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &[usize; 4]) -> usize { let slice: &[usize] = &values[..2]; slice.len() + slice[1] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &[usize; 4]) -> usize { let slice: &[usize] = &values[2..]; slice.len() + slice[0] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &[usize; 4]) -> usize { let slice: &[usize] = &values[..]; slice.len() + slice[3] }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_runtime_fixed_array_reference_ranges_create_slices() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &mut [usize; 4], start: usize, end: usize) -> usize { let slice: &mut [usize] = &mut values[start..end]; slice[0] += 2; slice.len() + slice[0] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &[usize; 4], start: usize, end: usize) -> usize { let slice: &[usize] = &values[start..=end]; slice.len() + slice[0] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &[usize; 4], end: usize) -> usize { let slice: &[usize] = &values[..end]; slice.len() + slice[0] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(values: &[usize; 4], start: usize) -> usize { let slice: &[usize] = &values[start..]; slice.len() + slice[0] }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_contiguous_fixed_array_local_ranges_create_slices() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: usize, start: usize, end: usize) -> usize { let values = [input, 10, 20, 30]; let slice: &[usize] = &values[start..end]; slice.len() + slice[0] + values[2] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: usize, start: usize, end: usize) -> usize { let mut values = [input, 10, 20, 30]; let slice: &mut [usize] = &mut values[start..=end]; slice[1] += 2; values[2] + slice.len() }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: i64) -> i64 { let values = [input, 10, 20, 30]; let slice: &[i64] = &values[1..3]; slice[0] + slice[1] }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_zero_sized_array_abi_reaches_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: usize, empty: [u8; 0], b: usize, c: usize) -> usize { a + b * 10 + c * 100 }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(a: usize, units: [(); 3], b: usize, c: usize) -> usize { a + b * 10 + c * 100 }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8) -> [u8; 0] { [] }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8) -> [(); 3] { [(); 3] }",
    ];
    for source in sources {
        assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_contextual_default_array_returns_reach_native_objects() {
    let source = "#[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u16) -> [u16; 5] { if input == 0 { Default::default() } else { [input, 0, 0, 0, input] } }";
    assert_eq!(compile_wide(source, ObjectFormat::Elf64), Ok(()));
    assert_eq!(compile_wide(source, ObjectFormat::Coff), Ok(()));
}

#[test]
fn rustc_competing_break_loop_values_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: bool, input: isize) -> isize { let value: isize = loop { if first { break input + 1; } break 84 / input; }; value }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: bool) -> bool { let value: bool = loop { if first { break true; } break false; }; value }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: bool, input: isize) -> isize { let value: isize = 'value: loop { if first { break 'value input + 1; } break 'value 84 / input; }; value }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: bool, input: isize) -> isize { let value: isize = 'value: loop { if first { break 'value input + 1; } if input == 0 { break 'value 42; } if input == 1 { break 'value 43; } break 'value 84 / input; }; value }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(first: bool, input: isize) -> isize { let value: isize = 'value: loop { if first { break 'value input + 1; } else if input == 0 { break 'value 42; } else if input == 1 { break 'value 43; } else { break 'value 84 / input; } }; value }",
    ];
    for source in sources {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_unit_loop_bodies_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> () { () }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() { loop { break; } }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> () { let value: () = loop { break (); }; value }",
    ];
    for source in sources {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_implicit_unit_tails_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() {}",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() { let value: usize = 1; }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() { loop { break; } }",
    ];
    for source in sources {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_boolean_and_unit_equality_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: bool, right: bool) -> bool { left == right }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: bool, right: bool) -> bool { left != right }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> bool { () == () }",
    ];
    for source in sources {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_boolean_ordering_and_bitwise_ops_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: bool, right: bool) -> bool { left < right }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: bool, right: bool) -> bool { left >= right }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe() -> bool { () <= () }",
        "#[unsafe(no_mangle)] pub const extern \"C\" fn probe(left: bool, right: bool) -> bool { left & right }",
        "#[unsafe(no_mangle)] pub const extern \"C\" fn probe(left: bool, right: bool) -> bool { left | right }",
        "#[unsafe(no_mangle)] pub const extern \"C\" fn probe(left: bool, right: bool) -> bool { left ^ right }",
    ];
    for source in sources {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_boolean_constants_and_integer_const_comparisons_reach_native_objects() {
    let sources = [
        "const FLAG: bool = true && false; #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: bool) -> bool { FLAG || input }",
        "static ORDERED: bool = -1 < 2; #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: bool) -> bool { ORDERED && input }",
        "const SAME: bool = 3 == 3; #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: bool) -> bool { SAME ^ input }",
    ];
    for source in sources {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }

    let mismatch = "const FLAG: bool = true; #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: u8) -> u8 { input + FLAG }";
    assert_eq!(
        compile(mismatch, ObjectFormat::Elf64),
        Err(CompileErrorKind::Codegen(
            mrml_rustc::CodegenErrorKind::RuntimeTypeMismatch
        ))
    );
}

#[test]
fn rustc_integer_constant_casts_and_signed_const_if_reach_native_objects() {
    let sources = [
        "const OFFSET: i32 = if -1 < 2 { -1i8 as i32 } else { 1 / 0 }; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i32) -> i32 { value + OFFSET }",
        "const MASK: i8 = 255u16 as i8; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: i8) -> i8 { value & MASK }",
        "const ENABLED: bool = if false { 1 == 2 } else { -3 < 1 }; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: bool) -> bool { ENABLED && value }",
        "const SIZE: usize = 23 as usize; #[unsafe(no_mangle)] pub extern \"C\" fn probe(value: usize) -> usize { value + SIZE }",
    ];
    for source in sources {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_compound_constant_comparisons_reach_native_objects() {
    let sources = [
        "const SUM: i32 = 2 + 2; const PASS: bool = SUM == 4; #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: bool) -> bool { PASS && input }",
        "const BASE: i32 = -4; const PASS: bool = BASE + 3 == -1; #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: bool) -> bool { PASS && input }",
        "const LIMIT: u8 = 9; const PASS: bool = (LIMIT - 1) * 2 > 15; #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: bool) -> bool { PASS && input }",
        "const BASE: i16 = -4; const PASS: bool = if BASE < 0 { BASE * 2 <= -8 } else { 1 / 0 == 0 }; #[unsafe(no_mangle)] pub extern \"C\" fn probe(input: bool) -> bool { PASS && input }",
    ];
    for source in sources {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
}

#[test]
fn rustc_boolean_compound_assignments_reach_native_objects() {
    let sources = [
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: bool, right: bool) -> bool { let mut value: bool = left; value &= right; value }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: bool, right: bool) -> bool { let mut value: bool = left; value |= right; value }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(left: bool, right: bool) -> bool { let mut value: bool = left; value ^= right; value }",
        "#[unsafe(no_mangle)] pub extern \"C\" fn probe(limit: u64) -> bool { let mut i: u64 = 0; let mut value: bool = false; while i < limit { value ^= true; i += 1; } value }",
    ];
    for source in sources {
        assert_eq!(compile(source, ObjectFormat::Elf64), Ok(()));
        assert_eq!(compile(source, ObjectFormat::Coff), Ok(()));
    }
}
