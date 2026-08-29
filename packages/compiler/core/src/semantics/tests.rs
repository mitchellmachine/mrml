#[cfg(test)]
mod tests {
    use super::*;
    use crate::Parser;

    #[test]
    fn resolves_constants_in_declaration_order() {
        let source = "const PAGE: usize = 4096; const ARENA: usize = PAGE * 8; fn boot() {}";
        let module = Parser::new(source).parse_module::<4, 2>().unwrap();
        let table = analyze_constants::<4, 16, 4, 2>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(table.len(), 2);
        assert_eq!(table.get("PAGE").unwrap().value, 4096);
        assert_eq!(table.get("ARENA").unwrap().value, 32768);
        assert_eq!(table.resolve("boot"), None);
    }

    #[test]
    fn rejects_duplicate_names_across_item_kinds() {
        let source = "const VALUE: u32 = 1; fn VALUE() {}";
        let module = Parser::new(source).parse_module::<4, 2>().unwrap();
        let error = analyze_constants::<4, 8, 4, 2>(&module, TargetLayout::X86_64).unwrap_err();
        assert_eq!(error.kind, SemanticErrorKind::DuplicateDefinition);
        assert_eq!(&source[error.span.start..error.span.end], "VALUE");
    }

    #[test]
    fn rejects_duplicate_trait_and_value_names() {
        let source = "trait Value {} const Value: u32 = 1;";
        let module = Parser::new(source).parse_module::<4, 2>().unwrap();
        let error = analyze_constants::<4, 8, 4, 2>(&module, TargetLayout::X86_64).unwrap_err();
        assert_eq!(error.kind, SemanticErrorKind::DuplicateDefinition);
        assert_eq!(&source[error.span.start..error.span.end], "Value");
    }

    #[test]
    fn rejects_forward_references_and_unsupported_types() {
        let forward = Parser::new("const A: usize = B; const B: usize = 1;")
            .parse_module::<4, 2>()
            .unwrap();
        let error = analyze_constants::<4, 8, 4, 2>(&forward, TargetLayout::X86_64).unwrap_err();
        assert_eq!(
            error.kind,
            SemanticErrorKind::Execution(ExecutionError::UnknownConstant)
        );

        let unsupported = Parser::new("const A: f32 = 1;")
            .parse_module::<2, 2>()
            .unwrap();
        let error =
            analyze_constants::<2, 8, 2, 2>(&unsupported, TargetLayout::X86_64).unwrap_err();
        assert_eq!(error.kind, SemanticErrorKind::UnsupportedConstantType);
    }

    #[test]
    fn resolves_signed_literal_constants_with_declared_ranges() {
        let module = Parser::new(
            "const NEGATIVE: i8 = -128; static POSITIVE: i32 = 2147483647; const WORD: isize = -1;",
        )
        .parse_module::<4, 2>()
        .unwrap();
        let values = analyze_constants::<4, 16, 4, 2>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("NEGATIVE"), Some(128));
        assert_eq!(values.resolve("POSITIVE"), Some(i32::MAX as u128));
        assert_eq!(values.resolve("WORD"), Some(u64::MAX as u128));
        assert_eq!(
            values.resolve_type("NEGATIVE"),
            Some(crate::IntegerType::I8)
        );

        for source in ["const BAD: i8 = -129;", "const BAD: i8 = 128;"] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            assert_eq!(
                analyze_constants::<2, 8, 2, 2>(&module, TargetLayout::X86_64)
                    .unwrap_err()
                    .kind,
                SemanticErrorKind::ConstantOutOfRange
            );
        }
    }

    #[test]
    fn evaluates_signed_constant_arithmetic_in_the_declared_type() {
        let module = Parser::new(
            "const A: isize = -4 + 3; const B: isize = 3 - 4; const C: isize = -3 * 3; const D: isize = 3 / -1; const E: isize = 1024 >> 4; const F: i8 = -8 | 3;",
        )
        .parse_module::<8, 2>()
        .unwrap();
        let values = analyze_constants::<8, 32, 8, 2>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("A"), Some(u64::MAX as u128));
        assert_eq!(values.resolve("B"), Some(u64::MAX as u128));
        assert_eq!(values.resolve("C"), Some((u64::MAX - 8) as u128));
        assert_eq!(values.resolve("D"), Some((u64::MAX - 2) as u128));
        assert_eq!(values.resolve("E"), Some(64));
        assert_eq!(values.resolve("F"), Some(251));

        for source in [
            "const BAD: i8 = 127 + 1;",
            "const BAD: i8 = -128 - 1;",
            "const BAD: i8 = 64 * 2;",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            assert_eq!(
                analyze_constants::<2, 16, 2, 2>(&module, TargetLayout::X86_64)
                    .unwrap_err()
                    .kind,
                SemanticErrorKind::ConstantOutOfRange
            );
        }
    }

    #[test]
    fn evaluates_boolean_constants_and_integer_comparisons() {
        let module = Parser::new(
            "const A: bool = true && false; const B: bool = true || A; const C: bool = -1 < 2; const D: bool = 3 == 3; const E: bool = B ^ C;",
        )
        .parse_module::<8, 2>()
        .unwrap();
        let values = analyze_constants::<8, 32, 8, 2>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("A"), Some(0));
        assert_eq!(values.resolve("B"), Some(1));
        assert_eq!(values.resolve("C"), Some(1));
        assert_eq!(values.resolve("D"), Some(1));
        assert_eq!(values.resolve("E"), Some(0));
        assert!(values.resolves_bool("E"));

        let invalid = Parser::new("const BAD: bool = 1 + 2;")
            .parse_module::<2, 2>()
            .unwrap();
        assert_eq!(
            analyze_constants::<2, 8, 2, 2>(&invalid, TargetLayout::X86_64)
                .unwrap_err()
                .kind,
            SemanticErrorKind::Execution(ExecutionError::Arithmetic(ConstEvalError::InvalidCast))
        );
    }

    #[test]
    fn evaluates_signed_constant_casts_and_conditionals_lazily() {
        let module = Parser::new(
            "const WIDE: i32 = -1i8 as i32; const NARROW: i8 = 255u16 as i8; const CHOICE: i32 = if -1 < 2 { WIDE - 6 } else { 1 / 0 }; const FLAG: bool = if false { 1 == 2 } else { CHOICE == -7 };",
        )
        .parse_module::<8, 2>()
        .unwrap();
        let values = analyze_constants::<8, 48, 8, 2>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("WIDE"), Some(u32::MAX as u128));
        assert_eq!(values.resolve("NARROW"), Some(u8::MAX as u128));
        assert_eq!(values.resolve("CHOICE"), Some((u32::MAX - 6) as u128));
        assert_eq!(values.resolve("FLAG"), Some(1));

        let mismatch = Parser::new("const BAD: i16 = 1i8 as i32;")
            .parse_module::<2, 2>()
            .unwrap();
        assert_eq!(
            analyze_constants::<2, 8, 2, 2>(&mismatch, TargetLayout::X86_64)
                .unwrap_err()
                .kind,
            SemanticErrorKind::Execution(ExecutionError::Arithmetic(ConstEvalError::InvalidCast))
        );
    }

    #[test]
    fn compares_named_and_compound_typed_constant_operands() {
        let module = Parser::new(
            "const BASE: i32 = -4; const LIMIT: u8 = 9; const A: bool = BASE + 3 == -1; const B: bool = (LIMIT - 1) * 2 > 15; const C: bool = 1 < LIMIT; const D: bool = if A { BASE * 2 <= -8 } else { 1 / 0 == 0 };",
        )
        .parse_module::<8, 2>()
        .unwrap();
        let values = analyze_constants::<8, 64, 8, 2>(&module, TargetLayout::X86_64).unwrap();
        for name in ["A", "B", "C", "D"] {
            assert_eq!(values.resolve(name), Some(1));
        }

        let mixed = Parser::new("const BAD: bool = 1u8 < 2u16;")
            .parse_module::<2, 2>()
            .unwrap();
        assert_eq!(
            analyze_constants::<2, 8, 2, 2>(&mixed, TargetLayout::X86_64)
                .unwrap_err()
                .kind,
            SemanticErrorKind::Execution(ExecutionError::Arithmetic(ConstEvalError::InvalidCast))
        );

        let overflow = Parser::new("const BAD: bool = 255u8 + 1 > 0;")
            .parse_module::<2, 2>()
            .unwrap();
        assert_eq!(
            analyze_constants::<2, 16, 2, 2>(&overflow, TargetLayout::X86_64)
                .unwrap_err()
                .kind,
            SemanticErrorKind::Execution(ExecutionError::Arithmetic(ConstEvalError::Overflow))
        );
    }

    #[test]
    fn evaluates_bounded_integer_const_function_calls() {
        let module = Parser::new(
            "const fn add(left: usize, right: usize) -> usize { left + right } const BASE: usize = 40; const SUM: usize = add(BASE, 2);",
        )
        .parse_module::<4, 4>()
        .unwrap();
        let values = analyze_constants::<4, 32, 4, 4>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("SUM"), Some(42));

        for source in [
            "fn add(a: usize, b: usize) -> usize { a + b } const BAD: usize = add(1, 2);",
            "const BAD: usize = add(1, 2); const fn add(a: usize, b: usize) -> usize { a + b }",
            "const fn add(a: usize, b: usize) -> usize { a + b } const BAD: usize = add(1);",
            "const fn signed(a: i32) -> i32 { a } const BAD: i64 = signed(1);",
        ] {
            let module = Parser::new(source).parse_module::<4, 4>().unwrap();
            assert_eq!(
                analyze_constants::<4, 32, 4, 4>(&module, TargetLayout::X86_64)
                    .unwrap_err()
                    .kind,
                SemanticErrorKind::UnsupportedConstCall
            );
        }

        let signed = Parser::new(
            "const fn adjust(value: i32, offset: i32) -> i32 { value + offset } const ANSWER: i32 = adjust(-8, 50); const fn minimum(value: i8) -> i8 { value } const MINIMUM: i8 = minimum(-128);",
        )
        .parse_module::<4, 4>()
        .unwrap();
        let values = analyze_constants::<4, 32, 4, 4>(&signed, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("ANSWER"), Some(42));
        assert_eq!(values.resolve("MINIMUM"), Some(128));
    }

    #[test]
    fn inline_const_resolves_items_but_rejects_const_function_captures() {
        let module = Parser::new(
            "const ITEM: u32 = 42; const fn item() -> u32 { const { ITEM } } const RESULT: u32 = item();",
        )
        .parse_module::<4, 2>()
        .unwrap();
        let values = analyze_constants::<4, 32, 4, 2>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("RESULT"), Some(42));

        for source in [
            "const fn captured(value: u32) -> u32 { const { value } } const BAD: u32 = captured(42);",
            "const fn captured() -> u32 { let value: u32 = 42; const { value } } const BAD: u32 = captured();",
        ] {
            let module = Parser::new(source).parse_module::<4, 2>().unwrap();
            assert_eq!(
                analyze_constants::<4, 32, 4, 2>(&module, TargetLayout::X86_64)
                    .unwrap_err()
                    .kind,
                SemanticErrorKind::UnsupportedConstCall
            );
        }
    }

    #[test]
    fn inline_const_evaluates_bounded_scalar_const_function_calls() {
        let module = Parser::new(
            "const fn offset() -> u32 { 2 } const fn enabled() -> bool { true } const OFFSET: u32 = const { offset() }; const ENABLED: bool = const { enabled() };",
        )
        .parse_module::<6, 2>()
        .unwrap();
        let values = analyze_constants::<4, 48, 6, 2>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("OFFSET"), Some(2));
        assert_eq!(values.resolve("ENABLED"), Some(1));

        let non_const =
            Parser::new("fn offset() -> u32 { 2 } const BAD: u32 = const { offset() };")
                .parse_module::<4, 2>()
                .unwrap();
        assert_eq!(
            analyze_constants::<4, 32, 4, 2>(&non_const, TargetLayout::X86_64)
                .unwrap_err()
                .kind,
            SemanticErrorKind::UnsupportedConstCall
        );
    }

    #[test]
    fn evaluates_nested_prior_integer_const_function_calls_with_a_depth_bound() {
        let module = Parser::new(
            "const fn sub(left: u32, right: u32) -> u32 { left - right } const fn halve(value: u32) -> u32 { sub(value, 22) } const DIRECT: u32 = sub(sub(88, 44), 22); const THROUGH_BODY: u32 = halve(44);",
        )
        .parse_module::<8, 4>()
        .unwrap();
        let values = analyze_constants::<4, 64, 8, 4>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("DIRECT"), Some(22));
        assert_eq!(values.resolve("THROUGH_BODY"), Some(22));

        let shadowing = Parser::new(
            "const value: u32 = 99; const fn identity(value: u32) -> u32 { value } const RESULT: u32 = identity(42);",
        )
        .parse_module::<4, 2>()
        .unwrap();
        let values = analyze_constants::<4, 32, 4, 2>(&shadowing, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("RESULT"), Some(42));

        let too_deep = Parser::new(
            "const fn id(value: u8) -> u8 { value } const BAD: u8 = id(id(id(id(id(id(id(id(id(1)))))))));",
        )
        .parse_module::<4, 2>()
        .unwrap();
        assert_eq!(
            analyze_constants::<2, 64, 4, 2>(&too_deep, TargetLayout::X86_64)
                .unwrap_err()
                .kind,
            SemanticErrorKind::UnsupportedConstCall
        );
    }

    #[test]
    fn evaluates_integer_const_calls_as_composed_expression_operands() {
        let module = Parser::new(
            "const fn add(left: u8, right: u8) -> u8 { left + right } const fn adjust(value: i32, offset: i32) -> i32 { value + offset } const COMPOSED: u8 = add(20, 1) * 2; const LAZY: u8 = if add(1, 1) < 3 { add(40, 2) } else { add(255, 1) }; const SIGNED: i32 = adjust(-8, 50) - 84; const WIDE: u16 = add(254, 1) as u16 + 1; const PASS: bool = add(20, 22) == 42;",
        )
        .parse_module::<8, 4>()
        .unwrap();
        let values = analyze_constants::<8, 96, 8, 4>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("COMPOSED"), Some(42));
        assert_eq!(values.resolve("LAZY"), Some(42));
        assert_eq!(values.resolve("SIGNED"), Some((u32::MAX - 41) as u128));
        assert_eq!(values.resolve("WIDE"), Some(256));
        assert_eq!(values.resolve("PASS"), Some(1));

        let overflow =
            Parser::new("const fn maximum() -> u8 { 255 } const BAD: u8 = maximum() + 1;")
                .parse_module::<4, 2>()
                .unwrap();
        assert_eq!(
            analyze_constants::<2, 32, 4, 2>(&overflow, TargetLayout::X86_64)
                .unwrap_err()
                .kind,
            SemanticErrorKind::ConstantOutOfRange
        );
    }

    #[test]
    fn evaluates_typed_shift_distances_in_wide_const_functions() {
        let module = Parser::new(
            "const fn unsigned(value: u128, distance: u32) -> u128 { value >> distance } const fn signed(value: i128, distance: u32) -> i128 { value >> distance } const fn unsigned_assign(value: u128, distance: u32) -> u128 { let mut result: u128 = value; result >>= distance; result } const fn signed_assign(value: i128, distance: u32) -> i128 { let mut result: i128 = value; result >>= distance; result }",
        )
        .parse_module::<8, 4>()
        .unwrap();
        let values = analyze_constants::<2, 32, 8, 4>(&module, TargetLayout::X86_64).unwrap();
        let unsigned = 1512366075204170947332355369683137040u128;
        let signed = -1512366075204170947332355369683137040i128;
        assert_eq!(
            evaluate_scalar_const_function(
                &module,
                &values,
                TargetLayout::X86_64,
                "unsigned",
                &[unsigned, 65],
            ),
            Some(unsigned >> 65)
        );
        assert_eq!(
            evaluate_scalar_const_function(
                &module,
                &values,
                TargetLayout::X86_64,
                "signed",
                &[signed as u128, 65],
            ),
            Some((signed >> 65) as u128)
        );
        assert_eq!(
            evaluate_scalar_const_function(
                &module,
                &values,
                TargetLayout::X86_64,
                "unsigned_assign",
                &[unsigned, 65],
            ),
            Some(unsigned >> 65)
        );
        assert_eq!(
            evaluate_scalar_const_function(
                &module,
                &values,
                TargetLayout::X86_64,
                "signed_assign",
                &[signed as u128, 65],
            ),
            Some((signed >> 65) as u128)
        );
    }

    #[test]
    fn evaluates_typed_shift_distances_in_named_wide_constants() {
        let module = Parser::new(
            "const DISTANCE: u32 = 65; const UNSIGNED: u128 = 1512366075204170947332355369683137040u128 >> DISTANCE; const SIGNED: i128 = -1512366075204170947332355369683137040i128 >> DISTANCE; const UNSIGNED_MATCH: bool = (1512366075204170947332355369683137040u128 >> DISTANCE) == UNSIGNED; const SIGNED_MATCH: bool = (-1512366075204170947332355369683137040i128 >> DISTANCE) == SIGNED;",
        )
        .parse_module::<8, 2>()
        .unwrap();
        let values = analyze_constants::<8, 64, 8, 2>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(
            values.resolve("UNSIGNED"),
            Some(1512366075204170947332355369683137040u128 >> 65)
        );
        assert_eq!(
            values.resolve("SIGNED"),
            Some((-1512366075204170947332355369683137040i128 >> 65) as u128)
        );
        assert_eq!(values.resolve("UNSIGNED_MATCH"), Some(1));
        assert_eq!(values.resolve("SIGNED_MATCH"), Some(1));
    }

    #[test]
    fn evaluates_unconditional_early_returns_in_const_functions() {
        let module = Parser::new(
            "const fn integer(value: u8) -> u8 { let adjusted = value + 1; return adjusted; let ignored = 255 / 0; ignored } const fn boolean() -> bool { return true; false } const VALUE: u8 = integer(41); const FLAG: bool = boolean();",
        )
        .parse_module::<8, 2>()
        .unwrap();
        let values = analyze_constants::<4, 64, 8, 2>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("VALUE"), Some(42));
        assert_eq!(values.resolve("FLAG"), Some(1));
    }

    #[test]
    fn evaluates_exhaustive_conditional_returns_lazily_in_const_functions() {
        let module = Parser::new(
            "const fn choose(value: u8) -> u8 { if value == 0 { return 42; } else if value == 1 { return value + 41; } else if value == 2 { return 84 / value; } else { return 126 / value; } } const fn invert(select: bool) -> bool { if select { return false; } else { return true; } } const FIRST: u8 = choose(0); const MIDDLE: u8 = choose(1); const LATER: u8 = choose(2); const FALLBACK: u8 = choose(3); const FLAG: bool = invert(false);",
        )
        .parse_module::<10, 2>()
        .unwrap();
        let values = analyze_constants::<8, 96, 10, 2>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("FIRST"), Some(42));
        assert_eq!(values.resolve("MIDDLE"), Some(42));
        assert_eq!(values.resolve("LATER"), Some(42));
        assert_eq!(values.resolve("FALLBACK"), Some(42));
        assert_eq!(values.resolve("FLAG"), Some(1));
    }

    #[test]
    fn evaluates_non_exhaustive_return_chains_and_fallthrough_in_const_functions() {
        let module = Parser::new(
            "const fn choose(value: u8) -> u8 { if value == 0 { return 42; } else if value == 1 { return 42 / value; } 84 / value } const FIRST: u8 = choose(0); const SECOND: u8 = choose(1); const FALLTHROUGH: u8 = choose(2);",
        )
        .parse_module::<6, 2>()
        .unwrap();
        let values = analyze_constants::<4, 64, 6, 2>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("FIRST"), Some(42));
        assert_eq!(values.resolve("SECOND"), Some(42));
        assert_eq!(values.resolve("FALLTHROUGH"), Some(42));
    }

    #[test]
    fn evaluates_conditional_const_assignments_lazily() {
        let module = Parser::new(
            "const fn choose(value: u8) -> u8 { let mut result = value; if value == 0 { result = 40; value + 1; result += 2; return result; } else if value == 1 { result = 40; 84 / value; result += 2; return result; } else if value == 2 { result = 40; 42 / value; result += 2; return result; } else { result = 40; value + 10; result += 2; return result; } 1 / value } const FIRST: u8 = choose(0); const MIDDLE: u8 = choose(1); const LATER: u8 = choose(2); const FALLBACK: u8 = choose(3); const fn optional(value: u8) -> u8 { let mut result = 40; if value == 0 { result += 1; value + 1; result += 1; } else if value == 1 { result += 3; value + 1; result -= 1; } result } const UNSELECTED: u8 = optional(2);",
        )
        .parse_module::<8, 2>()
        .unwrap();
        let values = analyze_constants::<8, 96, 8, 2>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("FIRST"), Some(42));
        assert_eq!(values.resolve("MIDDLE"), Some(42));
        assert_eq!(values.resolve("LATER"), Some(42));
        assert_eq!(values.resolve("FALLBACK"), Some(42));
        assert_eq!(values.resolve("UNSELECTED"), Some(40));

        let selected_failure = Parser::new(
            "const fn fail(value: u8) -> u8 { let mut result = value; if value == 0 { result = 1; 1 / value; result += 1; } result } const BAD: u8 = fail(0);",
        )
        .parse_module::<4, 2>()
        .unwrap();
        assert!(analyze_constants::<2, 48, 4, 2>(&selected_failure, TargetLayout::X86_64).is_err());
    }

    #[test]
    fn evaluates_scoped_conditional_locals_in_const_functions() {
        let module = Parser::new(
            "const fn choose(value: u8, select: bool) -> u8 { let mut result = value; if select { let mut result: u8 = 40; result += 2; return result; } else { let selected: u8 = 84 / value; selected + 1; result = selected; } result } const SELECTED: u8 = choose(0, true); const FALLBACK: u8 = choose(2, false);",
        )
        .parse_module::<6, 4>()
        .unwrap();
        let values = analyze_constants::<4, 64, 6, 4>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("SELECTED"), Some(42));
        assert_eq!(values.resolve("FALLBACK"), Some(42));
    }

    #[test]
    fn evaluates_scoped_loop_locals_and_expressions_in_const_functions() {
        let module = Parser::new(
            "const fn count(limit: u8, stop: u8) -> u8 { let mut i: u8 = 0; let mut total: u8 = 0; while i < limit { loop { break; } let current: u8 = i + 1; current + 10; i = current; if i % 3 == 0 { let selected: u8 = current; total += selected; } else if i % 2 == 0 { let even: u8 = 2; total += even; } else { let fallback: u8 = 1; total += fallback; } if i % 2 == 0 { let skipped: u8 = current; skipped + 10; continue; } if i == stop { let selected: u8 = current; selected + 20; break; } total + current; } total } const STOPPED: u8 = count(5, 3); const COMPLETE: u8 = count(4, 99); const fn choose(value: u8) -> u8 { loop { if value == 0 { let selected: u8 = 42; selected + 1; return selected; } return value; } } const RETURNED: u8 = choose(0);",
        )
        .parse_module::<6, 4>()
        .unwrap();
        let values = analyze_constants::<4, 96, 6, 4>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("STOPPED"), Some(6));
        assert_eq!(values.resolve("COMPLETE"), Some(8));
        assert_eq!(values.resolve("RETURNED"), Some(42));
    }

    #[test]
    fn evaluates_terminal_control_from_loop_alternative_arms() {
        let module = Parser::new(
            "const fn probe(limit: u8, mode: u8) -> u8 { let mut i: u8 = 0; let mut total: u8 = 0; while i < limit { i += 1; if mode == 0 { let selected: u8 = i; total += selected; break; } else if mode == 1 { let repeated: u8 = 2; total += repeated; continue; } else if mode == 2 { let stopped: u8 = 3; total += stopped; break; } else { let returned: u8 = i + 40; return returned; } } total } const ZERO: u8 = probe(0, 99); const PRIMARY: u8 = probe(5, 0); const REPEATED: u8 = probe(5, 1); const LATER: u8 = probe(5, 2); const RETURNED: u8 = probe(5, 99);",
        )
        .parse_module::<8, 4>()
        .unwrap();
        let values = analyze_constants::<5, 96, 8, 4>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("ZERO"), Some(0));
        assert_eq!(values.resolve("PRIMARY"), Some(1));
        assert_eq!(values.resolve("REPEATED"), Some(10));
        assert_eq!(values.resolve("LATER"), Some(3));
        assert_eq!(values.resolve("RETURNED"), Some(41));
    }

    #[test]
    fn evaluates_scoped_actions_before_an_inner_loop_break() {
        let module = Parser::new(
            "const fn sum(limit: u16) -> u32 { let mut i: u16 = 0; let mut total: u32 = 0; while i < limit { loop { let selected: u32 = i as u32 + 1; selected + 10; total += selected; break; } i += 1; } total } const ZERO: u32 = sum(0); const ONE: u32 = sum(1); const FIVE: u32 = sum(5);",
        )
        .parse_module::<5, 2>()
        .unwrap();
        let values = analyze_constants::<3, 64, 5, 2>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("ZERO"), Some(0));
        assert_eq!(values.resolve("ONE"), Some(1));
        assert_eq!(values.resolve("FIVE"), Some(15));
    }

    #[test]
    fn evaluates_repeated_inner_iterations_until_a_conditional_break() {
        let module = Parser::new(
            "const fn sum(limit: u8) -> u16 { let mut outer: u8 = 0; let mut inner: u8 = 0; let mut total: u16 = 0; while outer < limit { loop { let selected: u8 = inner + 1; inner = selected; total += selected as u16; if selected == 3 { break; } } outer += 1; inner = 0; } total } const ZERO: u16 = sum(0); const ONE: u16 = sum(1); const FIVE: u16 = sum(5);",
        )
        .parse_module::<5, 4>()
        .unwrap();
        let values = analyze_constants::<3, 96, 5, 4>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("ZERO"), Some(0));
        assert_eq!(values.resolve("ONE"), Some(6));
        assert_eq!(values.resolve("FIVE"), Some(30));
    }

    #[test]
    fn evaluates_conditional_continue_inside_a_repeated_inner_loop() {
        let module = Parser::new(
            "const fn sum(limit: u8) -> u16 { let mut outer: u8 = 0; let mut inner: u8 = 0; let mut total: u16 = 0; while outer < limit { loop { let selected: u8 = inner + 1; inner = selected; if selected % 2 == 0 { continue; } total += selected as u16; if selected == 5 { break; } } outer += 1; inner = 0; } total } const ZERO: u16 = sum(0); const ONE: u16 = sum(1); const FIVE: u16 = sum(5);",
        )
        .parse_module::<5, 4>()
        .unwrap();
        let values = analyze_constants::<3, 96, 5, 4>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("ZERO"), Some(0));
        assert_eq!(values.resolve("ONE"), Some(9));
        assert_eq!(values.resolve("FIVE"), Some(45));
    }

    #[test]
    fn evaluates_ordered_continues_and_returns_inside_an_inner_loop() {
        let module = Parser::new(
            "const fn sum(limit: u8, first: u8, second: u8) -> u16 { let mut outer: u8 = 0; let mut inner: u8 = 0; let mut total: u16 = 0; while outer < limit { while inner < 5 { inner += 1; if inner == first { continue; } if inner == second { continue; } total += inner as u16; } outer += 1; inner = 0; } total } const fn choose(limit: u8, skip: u8, stop: u8) -> u8 { let mut outer: u8 = 0; let mut inner: u8 = 0; while outer < limit { while inner < 3 { inner += 1; if inner == skip { continue; } if inner == stop { return outer + 40; } } outer += 1; inner = 0; } outer } const TWO_SKIPS: u16 = sum(1, 1, 2); const SAME_SKIP: u16 = sum(1, 2, 2); const CONTINUE_WINS: u8 = choose(5, 1, 1); const RETURN_WINS: u8 = choose(5, 4, 1);",
        )
        .parse_module::<8, 4>()
        .unwrap();
        let values = analyze_constants::<4, 192, 8, 4>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("TWO_SKIPS"), Some(12));
        assert_eq!(values.resolve("SAME_SKIP"), Some(13));
        assert_eq!(values.resolve("CONTINUE_WINS"), Some(5));
        assert_eq!(values.resolve("RETURN_WINS"), Some(40));
    }

    #[test]
    fn evaluates_positioned_conditional_breaks_inside_an_inner_loop() {
        let module = Parser::new(
            "const fn sum(limit: u8, first: u8, second: u8) -> u16 { let mut outer: u8 = 0; let mut inner: u8 = 0; let mut total: u16 = 0; while outer < limit { while inner < 5 { inner += 1; if inner == first { break; } total += inner as u16; if inner == second { break; } } outer += 1; inner = 0; } total } const FIRST: u16 = sum(1, 1, 2); const SECOND: u16 = sum(1, 4, 2); const LATE: u16 = sum(1, 4, 4); const NATURAL: u16 = sum(1, 6, 7);",
        )
        .parse_module::<6, 4>()
        .unwrap();
        let values = analyze_constants::<4, 128, 6, 4>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("FIRST"), Some(0));
        assert_eq!(values.resolve("SECOND"), Some(3));
        assert_eq!(values.resolve("LATE"), Some(6));
        assert_eq!(values.resolve("NATURAL"), Some(15));
    }

    #[test]
    fn evaluates_actions_before_nested_branch_terminals() {
        let module = Parser::new(
            "const fn choose(mode: u8) -> u8 { let mut inner: u8 = 0; loop { loop { inner += 1; if mode == 0 { let result: u8 = inner + 40; result + 1; return result; } if mode == 1 && inner < 3 { inner += 1; continue; } if mode == 2 { inner += 4; break; } break; } return inner; } } const fn choose_else(primary: bool) -> u8 { loop { loop { if primary { let result: u8 = 40; return result; } else { let result: u8 = 50; return result; } } } } const fn choose_else_if(primary: bool, alternative: bool) -> u8 { let mut outer: u8 = 0; let mut inner: u8 = 0; while outer < 1 { loop { if primary { let selected: u8 = 60; return selected; } else if alternative { let result: u8 = 70; return result; } inner += 1; if inner == 1 { break; } } outer += 1; } 80 } const fn choose_chain(primary: bool, first: bool, second: bool) -> u8 { loop { loop { if primary { return 90; } else if first { return 91; } else if second { return 92; } else { return 93; } } } } const RETURNED: u8 = choose(0); const CONTINUED: u8 = choose(1); const BROKEN: u8 = choose(2); const FALLTHROUGH: u8 = choose(3); const PRIMARY: u8 = choose_else(true); const ELSE: u8 = choose_else(false); const ELSE_IF_PRIMARY: u8 = choose_else_if(true, false); const ELSE_IF_ALTERNATIVE: u8 = choose_else_if(false, true); const ELSE_IF_FALLTHROUGH: u8 = choose_else_if(false, false); const CHAIN_PRIMARY: u8 = choose_chain(true, true, true); const CHAIN_FIRST: u8 = choose_chain(false, true, true); const CHAIN_SECOND: u8 = choose_chain(false, false, true); const CHAIN_ELSE: u8 = choose_chain(false, false, false);",
        )
        .parse_module::<17, 4>()
        .unwrap();
        let values = analyze_constants::<13, 128, 17, 4>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("RETURNED"), Some(41));
        assert_eq!(values.resolve("CONTINUED"), Some(3));
        assert_eq!(values.resolve("BROKEN"), Some(5));
        assert_eq!(values.resolve("FALLTHROUGH"), Some(1));
        assert_eq!(values.resolve("PRIMARY"), Some(40));
        assert_eq!(values.resolve("ELSE"), Some(50));
        assert_eq!(values.resolve("ELSE_IF_PRIMARY"), Some(60));
        assert_eq!(values.resolve("ELSE_IF_ALTERNATIVE"), Some(70));
        assert_eq!(values.resolve("ELSE_IF_FALLTHROUGH"), Some(80));
        assert_eq!(values.resolve("CHAIN_PRIMARY"), Some(90));
        assert_eq!(values.resolve("CHAIN_FIRST"), Some(91));
        assert_eq!(values.resolve("CHAIN_SECOND"), Some(92));
        assert_eq!(values.resolve("CHAIN_ELSE"), Some(93));
    }

    #[test]
    fn evaluates_unconditional_continue_inside_an_inner_while_loop() {
        let module = Parser::new(
            "const fn count(limit: u8) -> u8 { let mut outer: u8 = 0; let mut inner: u8 = 0; while outer < limit { while inner < 3 { let selected: u8 = inner + 1; inner = selected; continue; let unreachable: u8 = 255 + 1; return unreachable; } outer += 1; inner = 0; } outer } const ZERO: u8 = count(0); const ONE: u8 = count(1); const FIVE: u8 = count(5);",
        )
        .parse_module::<5, 4>()
        .unwrap();
        let values = analyze_constants::<3, 96, 5, 4>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("ZERO"), Some(0));
        assert_eq!(values.resolve("ONE"), Some(1));
        assert_eq!(values.resolve("FIVE"), Some(5));
    }

    #[test]
    fn evaluates_inner_loop_with_only_conditional_continue_and_return() {
        let module = Parser::new(
            "const fn spin(enter: bool, stop: u16) -> u16 { let mut inner: u16 = 0; while enter { loop { inner += 1; if inner < stop { continue; } if inner == stop { return inner; } } } 0 } const SKIP: u16 = spin(false, 200); const ONE: u16 = spin(true, 1); const TWO_HUNDRED: u16 = spin(true, 200);",
        )
        .parse_module::<5, 4>()
        .unwrap();
        let values = analyze_constants::<3, 96, 5, 4>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("SKIP"), Some(0));
        assert_eq!(values.resolve("ONE"), Some(1));
        assert_eq!(values.resolve("TWO_HUNDRED"), Some(200));
    }

    #[test]
    fn bounds_empty_and_action_only_inner_loops() {
        let skipped = Parser::new(
            "const fn spin(enter: bool) -> u8 { while enter { loop {} } 42 } const VALUE: u8 = spin(false);",
        )
        .parse_module::<3, 2>()
        .unwrap();
        let values = analyze_constants::<2, 48, 3, 2>(&skipped, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("VALUE"), Some(42));

        for source in [
            "const fn spin() -> u8 { while true { loop {} } 0 } const BAD: u8 = spin();",
            "const fn spin() -> u8 { while true { loop { 1; } } 0 } const BAD: u8 = spin();",
        ] {
            let module = Parser::new(source).parse_module::<3, 2>().unwrap();
            assert_eq!(
                analyze_constants::<2, 48, 3, 2>(&module, TargetLayout::X86_64)
                    .unwrap_err()
                    .kind,
                SemanticErrorKind::ConstLoopLimitExceeded
            );
        }
    }

    #[test]
    fn evaluates_empty_while_and_bounds_top_level_diverging_loops() {
        let skipped = Parser::new(
            "const fn probe(enter: bool) -> u8 { while enter {} 42 } const VALUE: u8 = probe(false);",
        )
        .parse_module::<3, 2>()
        .unwrap();
        let values = analyze_constants::<2, 48, 3, 2>(&skipped, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("VALUE"), Some(42));

        for source in [
            "const fn spin() -> u8 { loop {} } const BAD: u8 = spin();",
            "const fn spin() -> u8 { loop { 1; } } const BAD: u8 = spin();",
        ] {
            let module = Parser::new(source).parse_module::<3, 2>().unwrap();
            assert_eq!(
                analyze_constants::<2, 48, 3, 2>(&module, TargetLayout::X86_64)
                    .unwrap_err()
                    .kind,
                SemanticErrorKind::ConstLoopLimitExceeded
            );
        }
    }

    #[test]
    fn evaluates_matching_labels_on_statement_loop_controls() {
        let module = Parser::new(
            "const fn sum(limit: u8, stop: u8) -> u16 { let mut i: u8 = 0; let mut total: u16 = 0; 'count: while i < limit { i += 1; if i % 2 == 0 { continue 'count; } else if i == stop { break 'count; } total += i as u16; } 'once: loop { break 'once; } total } const EARLY: u16 = sum(5, 3); const COMPLETE: u16 = sum(5, 99);",
        )
        .parse_module::<4, 4>()
        .unwrap();
        let values = analyze_constants::<3, 128, 4, 4>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("EARLY"), Some(1));
        assert_eq!(values.resolve("COMPLETE"), Some(9));
    }

    #[test]
    fn evaluates_labeled_controls_targeting_inner_and_outer_loops() {
        let module = Parser::new(
            "const fn sum(limit: u8) -> u16 { let mut outer: u8 = 0; let mut total: u16 = 0; 'outer: while outer < limit { outer += 1; 'inner: loop { let selected: u8 = outer; if selected == 0 { continue 'inner; } if selected % 2 == 0 { continue 'outer; } if selected == 5 { break 'outer; } break 'inner; } total += outer as u16; } total } const ZERO: u16 = sum(0); const FOUR: u16 = sum(4); const TEN: u16 = sum(10);",
        )
        .parse_module::<5, 4>()
        .unwrap();
        let values = analyze_constants::<3, 160, 5, 4>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("ZERO"), Some(0));
        assert_eq!(values.resolve("FOUR"), Some(4));
        assert_eq!(values.resolve("TEN"), Some(4));

        let direct = Parser::new(
            "const fn count(limit: u8) -> u8 { let mut outer: u8 = 0; 'outer: while outer < limit { outer += 1; 'inner: loop { continue 'outer; } } outer } const fn once(enter: bool) -> u8 { let mut outer: u8 = 0; 'outer: while enter { outer += 1; 'inner: loop { break 'outer; } } outer } const COUNT: u8 = count(5); const BREAK: u8 = once(true); const SKIP: u8 = once(false);",
        )
        .parse_module::<7, 4>()
        .unwrap();
        let values = analyze_constants::<4, 160, 7, 4>(&direct, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("COUNT"), Some(5));
        assert_eq!(values.resolve("BREAK"), Some(1));
        assert_eq!(values.resolve("SKIP"), Some(0));
    }

    #[test]
    fn evaluates_condition_headed_inner_while_loops() {
        let module = Parser::new(
            "const fn sum(limit: u8) -> u16 { let mut outer: u8 = 0; let mut inner: u8 = 0; let mut total: u16 = 0; while outer < limit { while inner < 3 { inner += 1; total += inner as u16; } outer += 1; inner = 0; } total } const ZERO: u16 = sum(0); const ONE: u16 = sum(1); const FIVE: u16 = sum(5);",
        )
        .parse_module::<5, 4>()
        .unwrap();
        let values = analyze_constants::<3, 96, 5, 4>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("ZERO"), Some(0));
        assert_eq!(values.resolve("ONE"), Some(6));
        assert_eq!(values.resolve("FIVE"), Some(30));
    }

    #[test]
    fn evaluates_nested_while_with_continue_and_break_controls() {
        let module = Parser::new(
            "const fn sum(outer_limit: u8, inner_limit: u8) -> u16 { let mut outer: u8 = 0; let mut inner: u8 = 0; let mut total: u16 = 0; while outer < outer_limit { while inner < inner_limit { let selected: u8 = inner + 1; inner = selected; if selected % 2 == 0 { continue; } total += selected as u16; if selected == 5 { break; } } outer += 1; inner = 0; } total } const ZERO: u16 = sum(0, 7); const HEAD_EXIT: u16 = sum(1, 0); const NATURAL: u16 = sum(1, 4); const BREAK: u16 = sum(1, 7); const FIVE: u16 = sum(5, 7);",
        )
        .parse_module::<7, 4>()
        .unwrap();
        let values = analyze_constants::<5, 128, 7, 4>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("ZERO"), Some(0));
        assert_eq!(values.resolve("HEAD_EXIT"), Some(0));
        assert_eq!(values.resolve("NATURAL"), Some(4));
        assert_eq!(values.resolve("BREAK"), Some(9));
        assert_eq!(values.resolve("FIVE"), Some(45));
    }

    #[test]
    fn distinguishes_unconditional_inner_break_from_while_fallthrough() {
        let module = Parser::new(
            "const fn count(limit: u8, enter: bool) -> u8 { let mut i: u8 = 0; while i < limit { while enter { break; } i += 1; } i } const FALSE_HEAD: u8 = count(5, false); const TRUE_BREAK: u8 = count(5, true);",
        )
        .parse_module::<4, 2>()
        .unwrap();
        let values = analyze_constants::<2, 48, 4, 2>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("FALSE_HEAD"), Some(5));
        assert_eq!(values.resolve("TRUE_BREAK"), Some(5));
    }

    #[test]
    fn evaluates_typed_return_from_an_inner_loop_body() {
        let module = Parser::new(
            "const fn probe(limit: u8, enter: bool) -> u8 { let mut i: u8 = 0; while i < limit { while enter { let selected: u8 = i + 40; return selected; } i += 1; } i } const FALSE_HEAD: u8 = probe(5, false); const TRUE_RETURN: u8 = probe(5, true);",
        )
        .parse_module::<4, 2>()
        .unwrap();
        let values = analyze_constants::<2, 64, 4, 2>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("FALSE_HEAD"), Some(5));
        assert_eq!(values.resolve("TRUE_RETURN"), Some(40));
    }

    #[test]
    fn evaluates_bounded_boolean_const_function_calls_and_parameters() {
        let module = Parser::new(
            "const fn invert(value: bool) -> bool { !value } const fn both(left: bool, right: bool) -> bool { left && right } const fn positive(value: i32) -> bool { value > 0 } const fn choose(condition: bool, left: u8, right: u8) -> u8 { if condition { left } else { right } } const FLAG: bool = invert(false) && both(true, positive(42)); const VALUE: u8 = choose(FLAG, 42, 0);",
        )
        .parse_module::<8, 4>()
        .unwrap();
        let values = analyze_constants::<4, 96, 8, 4>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("FLAG"), Some(1));
        assert_eq!(values.resolve("VALUE"), Some(42));

        let lazy = Parser::new(
            "const fn dangerous(value: u8) -> bool { value / 0 == 0 } const SAFE: bool = true || dangerous(1);",
        )
        .parse_module::<4, 2>()
        .unwrap();
        assert_eq!(
            analyze_constants::<2, 48, 4, 2>(&lazy, TargetLayout::X86_64)
                .unwrap()
                .resolve("SAFE"),
            Some(1)
        );

        for (source, expected) in [
            (
                "const fn integer() -> u8 { 1 } const BAD: bool = integer();",
                SemanticErrorKind::UnsupportedConstCall,
            ),
            (
                "const fn boolean() -> bool { true } const BAD: u8 = boolean();",
                SemanticErrorKind::UnsupportedConstCall,
            ),
            (
                "const fn boolean(value: bool) -> bool { value } const BAD: bool = boolean(1);",
                SemanticErrorKind::Execution(ExecutionError::Arithmetic(
                    ConstEvalError::InvalidCast,
                )),
            ),
        ] {
            let module = Parser::new(source).parse_module::<4, 2>().unwrap();
            assert_eq!(
                analyze_constants::<2, 32, 4, 2>(&module, TargetLayout::X86_64)
                    .unwrap_err()
                    .kind,
                expected
            );
        }
    }

    #[test]
    fn evaluates_terminating_self_recursive_const_functions_with_a_hard_limit() {
        let module = Parser::new(
            "const fn gcd(left: u32, right: u32) -> u32 { if right == 0 { left } else { gcd(right, left % right) } } const fn descend(value: i32) -> i32 { if value == 0 { -42 } else { descend(value - 1) } } const fn even(value: u8) -> bool { if value == 0 { true } else { !even(value - 1) } } const GCD: u32 = gcd(48, 18); const SIGNED: i32 = descend(4); const EVEN: bool = even(4);",
        )
        .parse_module::<8, 4>()
        .unwrap();
        let values = analyze_constants::<4, 128, 8, 4>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("GCD"), Some(6));
        assert_eq!(values.resolve("SIGNED"), Some((u32::MAX - 41) as u128));
        assert_eq!(values.resolve("EVEN"), Some(1));

        for source in [
            "const fn forever(value: u8) -> u8 { forever(value) } const BAD: u8 = forever(1);",
            "const fn first(value: u8) -> u8 { second(value) } const fn second(value: u8) -> u8 { first(value) } const BAD: u8 = first(1);",
        ] {
            let module = Parser::new(source).parse_module::<4, 2>().unwrap();
            assert_eq!(
                analyze_constants::<2, 64, 4, 2>(&module, TargetLayout::X86_64)
                    .unwrap_err()
                    .kind,
                SemanticErrorKind::UnsupportedConstCall
            );
        }
    }

    #[test]
    fn evaluates_const_function_locals_and_conditional_returns() {
        let module = Parser::new(
            "const fn adjust(value: i32) -> i32 { let offset: i32 = 2; if value < 0 { return -value + offset; } value + offset } const fn enabled(value: bool) -> bool { let inverted: bool = !value; if inverted { return true; } false } const fn identity(value: usize) -> usize { return value; } const ADJUSTED: i32 = adjust(-40); const ENABLED: bool = enabled(false); const IDENTITY: usize = identity(42);",
        )
        .parse_module::<8, 4>()
        .unwrap();
        let values = analyze_constants::<4, 96, 8, 4>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("ADJUSTED"), Some(42));
        assert_eq!(values.resolve("ENABLED"), Some(1));
        assert_eq!(values.resolve("IDENTITY"), Some(42));

        let guarded_local = Parser::new(
            "const fn guarded(value: u8, stop: bool) -> u8 { if stop { return 7; } let adjusted: u8 = value + 1; adjusted * 2 } const EARLY: u8 = guarded(255, true); const FALLTHROUGH: u8 = guarded(20, false);",
        )
        .parse_module::<3, 2>()
        .unwrap();
        let values =
            analyze_constants::<2, 64, 3, 2>(&guarded_local, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("EARLY"), Some(7));
        assert_eq!(values.resolve("FALLTHROUGH"), Some(42));

        let guarded_assignment = Parser::new(
            "const fn guarded(value: u8, stop: bool) -> u8 { let mut adjusted: u8 = value; if stop { return 7; } adjusted += 1; adjusted * 2 } const EARLY: u8 = guarded(255, true); const FALLTHROUGH: u8 = guarded(20, false);",
        )
        .parse_module::<3, 2>()
        .unwrap();
        let values =
            analyze_constants::<2, 64, 3, 2>(&guarded_assignment, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("EARLY"), Some(7));
        assert_eq!(values.resolve("FALLTHROUGH"), Some(42));

        let fibonacci = Parser::new(
            "const fn fibonacci(n: u32) -> u32 { if n == 0 { return 0; } let mut previous: u32 = 0; let mut current: u32 = 1; let mut index: u32 = 1; while index < n { current += previous; previous = current - previous; index += 1; } current } const ZERO: u32 = fibonacci(0); const ONE: u32 = fibonacci(1); const TEN: u32 = fibonacci(10);",
        )
        .parse_module::<4, 4>()
        .unwrap();
        let values = analyze_constants::<4, 96, 4, 4>(&fibonacci, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("ZERO"), Some(0));
        assert_eq!(values.resolve("ONE"), Some(1));
        assert_eq!(values.resolve("TEN"), Some(55));

        let alternating_guards = Parser::new(
            "const fn classify(value: u32, first: bool, second: bool) -> u32 { let mut result: u32 = value; if first { return 1; } result += 1; if second { return 2; } result *= 2; result } const FIRST: u32 = classify(4294967295, true, false); const SECOND: u32 = classify(20, false, true); const FALLTHROUGH: u32 = classify(20, false, false);",
        )
        .parse_module::<4, 4>()
        .unwrap();
        let values =
            analyze_constants::<4, 96, 4, 4>(&alternating_guards, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("FIRST"), Some(1));
        assert_eq!(values.resolve("SECOND"), Some(2));
        assert_eq!(values.resolve("FALLTHROUGH"), Some(42));

        let assignment = Parser::new(
            "const fn mutate() -> u8 { let mut value: u8 = 1; value += 1; value } const fn toggle() -> bool { let mut value: bool = false; value ^= true; value } const fn swap() -> u8 { let mut left: u8 = 1; let mut right: u8 = 2; left ^= right; right ^= left; left ^= right; left } const MUTATED: u8 = mutate(); const TOGGLED: bool = toggle(); const SWAPPED: u8 = swap();",
        )
        .parse_module::<8, 4>()
        .unwrap();
        let values = analyze_constants::<4, 64, 8, 4>(&assignment, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("MUTATED"), Some(2));
        assert_eq!(values.resolve("TOGGLED"), Some(1));
        assert_eq!(values.resolve("SWAPPED"), Some(2));

        for (source, expected) in [
            (
                "const fn immutable() -> u8 { let value: u8 = 1; value += 1; value } const BAD: u8 = immutable();",
                SemanticErrorKind::UnsupportedConstCall,
            ),
            (
                "const fn overflow() -> u8 { let mut value: u8 = 255; value += 1; value } const BAD: u8 = overflow();",
                SemanticErrorKind::ConstantOutOfRange,
            ),
            (
                "const fn divide() -> i32 { let mut value: i32 = 42; value /= 0; value } const BAD: i32 = divide();",
                SemanticErrorKind::Execution(ExecutionError::Arithmetic(
                    ConstEvalError::DivisionByZero,
                )),
            ),
        ] {
            let module = Parser::new(source).parse_module::<4, 2>().unwrap();
            assert_eq!(
                analyze_constants::<2, 48, 4, 2>(&module, TargetLayout::X86_64)
                    .unwrap_err()
                    .kind,
                expected
            );
        }
    }

    #[test]
    fn evaluates_bounded_const_function_statement_loops() {
        let module = Parser::new(
            "const fn count(limit: u32) -> u32 { let mut index: u32 = 0; while index < limit { index += 1; } index } const fn even_sum(limit: u32) -> u32 { let mut index: u32 = 0; let mut total: u32 = 0; while index < limit { index += 1; if index % 2 != 0 { continue; } total += index; if total >= 42 { break; } } total } const fn until() -> u32 { let mut value: u32 = 0; loop { value += 1; if value == 42 { break; } } value } const fn immediate() -> u32 { loop { return 42; } } const COUNT: u32 = count(35); const SUM: u32 = even_sum(20); const UNTIL: u32 = until(); const IMMEDIATE: u32 = immediate();",
        )
        .parse_module::<8, 4>()
        .unwrap();
        let values = analyze_constants::<4, 96, 8, 4>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("COUNT"), Some(35));
        assert_eq!(values.resolve("SUM"), Some(42));
        assert_eq!(values.resolve("UNTIL"), Some(42));
        assert_eq!(values.resolve("IMMEDIATE"), Some(42));

        let staged = Parser::new(
            "const fn staged(limit: u32) -> u32 { let mut value: u32 = 0; while value < limit { value += 1; } value *= 2; value } const STAGED: u32 = staged(21);",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let values = analyze_constants::<2, 64, 2, 2>(&staged, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("STAGED"), Some(42));

        let post_loop_return = Parser::new(
            "const fn classify(limit: u32) -> u32 { let mut value: u32 = 0; while value < limit { value += 1; } if value == 42 { return 7; } value += 1; value } const HIT: u32 = classify(42); const MISS: u32 = classify(3);",
        )
        .parse_module::<3, 2>()
        .unwrap();
        let values =
            analyze_constants::<2, 64, 3, 2>(&post_loop_return, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("HIT"), Some(7));
        assert_eq!(values.resolve("MISS"), Some(4));

        let post_loop_guards = Parser::new(
            "const fn classify(value: u32, limit: u32, first: bool, second: bool) -> u32 { let mut index: u32 = 0; let mut result: u32 = value; while index < limit { index += 1; } if first && index == limit { return 1; } result += 1; if second && index == limit { return 2; } result *= 2; result } const FIRST: u32 = classify(4294967295, 3, true, false); const SECOND: u32 = classify(20, 3, false, true); const FALLTHROUGH: u32 = classify(20, 3, false, false);",
        )
        .parse_module::<4, 4>()
        .unwrap();
        let values =
            analyze_constants::<4, 96, 4, 4>(&post_loop_guards, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("FIRST"), Some(1));
        assert_eq!(values.resolve("SECOND"), Some(2));
        assert_eq!(values.resolve("FALLTHROUGH"), Some(42));

        let sequential = Parser::new(
            "const fn traverse(first: u32, second: u32) -> u32 { let mut value: u32 = 0; while value < first { value += 1; } while value < second { value += 1; } value } const FORWARD: u32 = traverse(17, 42); const ALREADY_PAST: u32 = traverse(42, 17);",
        )
        .parse_module::<3, 2>()
        .unwrap();
        let values = analyze_constants::<2, 64, 3, 2>(&sequential, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("FORWARD"), Some(42));
        assert_eq!(values.resolve("ALREADY_PAST"), Some(42));

        let post_loop_local = Parser::new(
            "const fn finish(limit: u32) -> u32 { let mut value: u32 = 0; while value < limit { value += 1; } let offset: u32 = value + 2; offset * 2 } const FINISHED: u32 = finish(19);",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let values =
            analyze_constants::<2, 64, 2, 2>(&post_loop_local, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("FINISHED"), Some(42));

        let primes = Parser::new(
            "const fn prime(value: u32) -> bool { let mut divisor: u32 = 3; if value % 2 == 0 { return false; } loop { if value % divisor == 0 { return false; } if divisor * divisor > value { return true; } divisor += 2; } false } const PRIME: bool = prime(113); const COMPOSITE: bool = prime(117);",
        )
        .parse_module::<4, 4>()
        .unwrap();
        let values = analyze_constants::<4, 96, 4, 4>(&primes, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("PRIME"), Some(1));
        assert_eq!(values.resolve("COMPOSITE"), Some(0));

        let endless = Parser::new(
            "const fn endless() -> u8 { let mut value: u8 = 0; while true { value += 0; } value } const BAD: u8 = endless();",
        )
        .parse_module::<4, 2>()
        .unwrap();
        assert_eq!(
            analyze_constants::<2, 48, 4, 2>(&endless, TargetLayout::X86_64)
                .unwrap_err()
                .kind,
            SemanticErrorKind::ConstLoopLimitExceeded
        );

        let overflow = Parser::new(
            "const fn overflow() -> u8 { let mut value: u8 = 255; while true { value += 1; } value } const BAD: u8 = overflow();",
        )
        .parse_module::<4, 2>()
        .unwrap();
        assert_eq!(
            analyze_constants::<2, 48, 4, 2>(&overflow, TargetLayout::X86_64)
                .unwrap_err()
                .kind,
            SemanticErrorKind::ConstantOutOfRange
        );
    }

    #[test]
    fn translates_expression_errors_to_module_spans() {
        let source = "const VALUE: usize = 1 + ;";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let error = analyze_constants::<2, 8, 2, 2>(&module, TargetLayout::X86_64).unwrap_err();
        assert_eq!(
            error.kind,
            SemanticErrorKind::Expression(ExpressionErrorKind::ExpectedExpression)
        );
        let Some(Item::Const(constant)) = module.items()[0] else {
            panic!("expected constant")
        };
        assert_eq!(error.span.start, constant.initializer_span.end);
    }

    #[test]
    fn enforces_constant_capacity() {
        let module = Parser::new("const A: u8 = 1; const B: u8 = 2;")
            .parse_module::<2, 2>()
            .unwrap();
        let error = analyze_constants::<1, 8, 2, 2>(&module, TargetLayout::X86_64).unwrap_err();
        assert_eq!(error.kind, SemanticErrorKind::TooManyConstants);
    }

    #[test]
    fn resolves_immutable_statics_with_constants() {
        let module = Parser::new(
            "const BASE: usize = { 10 }; static SHIFTED: usize = { BASE << 4 }; const SELECTED: u32 = if { true } { { 42 } } else { { 1 / 0 } };",
        )
        .parse_module::<4, 2>()
        .unwrap();
        let values = analyze_constants::<4, 24, 4, 2>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("BASE"), Some(10));
        assert_eq!(values.resolve("SHIFTED"), Some(160));
        assert_eq!(values.resolve("SELECTED"), Some(42));
    }

    #[test]
    fn enforces_declared_integer_and_target_pointer_ranges() {
        let byte = Parser::new("const VALUE: u8 = 256;")
            .parse_module::<2, 2>()
            .unwrap();
        let error = analyze_constants::<2, 8, 2, 2>(&byte, TargetLayout::X86_64).unwrap_err();
        assert_eq!(error.kind, SemanticErrorKind::ConstantOutOfRange);

        let pointer = Parser::new("const VALUE: usize = 4294967296;")
            .parse_module::<2, 2>()
            .unwrap();
        let target = TargetLayout::new(32).unwrap();
        let error = analyze_constants::<2, 8, 2, 2>(&pointer, target).unwrap_err();
        assert_eq!(error.kind, SemanticErrorKind::ConstantOutOfRange);
        assert_eq!(TargetLayout::new(24), None);
    }

    #[test]
    fn evaluates_integer_width_cast_constants() {
        let module = Parser::new(
            "const TRUNCATED: u8 = 300u16.truncate::<u8>(); const SATURATED_HIGH: i8 = 300i16.saturating_truncate::<i8>(); const SATURATED_LOW: i8 = (-300i16).saturating_truncate::<i8>(); const WIDENED: i64 = (-42i8).widen::<i64>();",
        )
        .parse_module::<4, 2>()
        .unwrap();
        let values = analyze_constants::<4, 48, 4, 2>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("TRUNCATED"), Some(44));
        assert_eq!(values.resolve("SATURATED_HIGH"), Some(127));
        assert_eq!(values.resolve("SATURATED_LOW"), Some(128));
        assert_eq!(values.resolve("WIDENED"), Some(u128::from(u64::MAX - 41)));
    }

    #[test]
    fn evaluates_generic_integer_cast_constants() {
        let module = Parser::new(
            "const SATURATED_LOW: u8 = (-42i16).saturating_cast::<u8>(); const SATURATED_HIGH: i8 = 300u16.saturating_cast::<i8>(); const WRAPPED_NEGATIVE: u8 = (-42i16).wrapping_cast::<u8>(); const WRAPPED_HIGH: i8 = 300u16.wrapping_cast::<i8>(); const STRICT: i64 = 42u8.strict_cast::<i64>();",
        )
        .parse_module::<5, 2>()
        .unwrap();
        let values = analyze_constants::<5, 64, 5, 2>(&module, TargetLayout::X86_64).unwrap();
        assert_eq!(values.resolve("SATURATED_LOW"), Some(0));
        assert_eq!(values.resolve("SATURATED_HIGH"), Some(127));
        assert_eq!(values.resolve("WRAPPED_NEGATIVE"), Some(214));
        assert_eq!(values.resolve("WRAPPED_HIGH"), Some(44));
        assert_eq!(values.resolve("STRICT"), Some(42));

        let overflow = Parser::new("const VALUE: u8 = (-1i8).strict_cast::<u8>();")
            .parse_module::<1, 2>()
            .unwrap();
        assert!(analyze_constants::<1, 16, 1, 2>(&overflow, TargetLayout::X86_64).is_err());

        let unchecked = Parser::new("const VALUE: u16 = 42u8.unchecked_cast::<u16>();")
            .parse_module::<1, 2>()
            .unwrap();
        assert!(analyze_constants::<1, 16, 1, 2>(&unchecked, TargetLayout::X86_64).is_err());
    }
}
