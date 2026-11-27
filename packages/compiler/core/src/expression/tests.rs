#[cfg(test)]
mod tests {
    use super::*;

    fn evaluate(source: &str) -> Result<u128, ConstEvalError> {
        ExpressionParser::<64>::new(source)
            .parse()
            .unwrap()
            .evaluate(&NoConstants)
    }

    #[test]
    fn preserves_c_string_literal_identity_without_constant_aliasing() {
        for source in ["c\"hello\\n\"", "cr##\"raw\\n\"#text\"##"] {
            let tree = ExpressionParser::<2>::new(source).parse().unwrap();
            assert!(matches!(
                tree.expression(tree.root()).map(|expression| expression.kind),
                Some(ExprKind::CString(literal)) if literal == source
            ));
            assert_eq!(
                tree.evaluate(&NoConstants),
                Err(ConstEvalError::InvalidExpressionTree)
            );
        }
    }

    #[test]
    fn honors_rust_operator_precedence_and_parentheses() {
        assert_eq!(evaluate("2 + 3 * 4"), Ok(14));
        assert_eq!(evaluate("(2 + 3) * 4"), Ok(20));
        assert_eq!(evaluate("1 << 4 + 1"), Ok(32));
        assert_eq!(evaluate("1 | 2 == 3 && 7 > 2"), Ok(1));
    }

    #[test]
    fn parses_unary_dereference() {
        let tree = ExpressionParser::<4>::new("*value + 1").parse().unwrap();
        let Some(ExprKind::Binary { left, .. }) =
            tree.expression(tree.root()).map(|expr| expr.kind)
        else {
            panic!("expected binary expression")
        };
        assert!(matches!(
            tree.expression(left).map(|expr| expr.kind),
            Some(ExprKind::Unary {
                operator: UnaryOperator::Dereference,
                ..
            })
        ));
    }

    #[test]
    fn parses_shared_and_mutable_address_operations() {
        for (source, expected) in [
            ("&value", UnaryOperator::AddressOf),
            ("&mut value", UnaryOperator::AddressOfMut),
            ("&mut *value", UnaryOperator::AddressOfMut),
        ] {
            let tree = ExpressionParser::<4>::new(source).parse().unwrap();
            assert!(matches!(
                tree.expression(tree.root()).map(|expr| expr.kind),
                Some(ExprKind::Unary { operator, .. }) if operator == expected
            ));
        }
    }

    #[test]
    fn decodes_radices_separators_and_suffixes() {
        assert_eq!(evaluate("0xff_u16 + 0b1_010 + 0o7"), Ok(272));
        let typed = ExpressionParser::<2>::new("10_usize").parse().unwrap();
        assert!(matches!(
            typed
                .expression(typed.root())
                .map(|expression| expression.kind),
            Some(ExprKind::Integer(IntegerLiteral {
                value: 10,
                suffix: Some("usize")
            }))
        ));
        let error = ExpressionParser::<8>::new("12bananas").parse().unwrap_err();
        assert_eq!(error.kind, ExpressionErrorKind::InvalidIntegerSuffix);
    }

    #[test]
    fn requires_lowercase_integer_base_prefixes() {
        for source in ["0x2A_u8", "0o52_u8", "0b10_1010u8"] {
            assert_eq!(evaluate(source), Ok(42));
        }
        for source in ["1 + 0X2A", "1 + 0O52", "1 + 0B101010"] {
            let error = ExpressionParser::<4>::new(source).parse().unwrap_err();
            assert_eq!(error.kind, ExpressionErrorKind::InvalidIntegerRadixPrefix);
            assert_eq!(error.span, Span { start: 4, end: 6 });
        }
    }

    #[test]
    fn hexadecimal_character_escapes_require_two_digits_and_respect_literal_kind() {
        for (source, value) in [
            (r"'\x41'", 0x41),
            (r"'\x7F'", 0x7f),
            (r"'\u{80}'", 0x80),
            (r"b'\x80'", 0x80),
            (r"b'\xFF'", 0xff),
        ] {
            assert_eq!(evaluate(source), Ok(value));
        }
        for source in [
            r"'\x80'",
            r"'\x+A'",
            r"b'\x+A'",
            r"b'\xG1'",
            r"'\x4'",
            r"b'\x041'",
        ] {
            let error = ExpressionParser::<4>::new(source).parse().unwrap_err();
            assert_eq!(error.kind, ExpressionErrorKind::InvalidCharacter);
            assert_eq!(&source[error.span.start..error.span.end], source);
        }
    }

    #[test]
    fn unicode_character_escapes_count_hex_digits_and_validate_scalars() {
        for (source, scalar) in [
            (r"'\u{41}'", 0x41),
            (r"'\u{4__1_}'", 0x41),
            (r"'\u{0000_41}'", 0x41),
            (r"'\u{10_ff_ff}'", 0x10_ffff),
        ] {
            assert_eq!(evaluate(source), Ok(scalar));
        }
        for source in [
            r"'\u{_41}'",
            r"'\u{0000041}'",
            r"'\u{}'",
            r"'\u{D800}'",
            r"'\u{110000}'",
        ] {
            let error = ExpressionParser::<4>::new(source).parse().unwrap_err();
            assert_eq!(error.kind, ExpressionErrorKind::InvalidCharacter);
            assert_eq!(
                error.span,
                Span {
                    start: 0,
                    end: source.len()
                }
            );
        }
    }

    #[test]
    fn rejects_noncanonical_tuple_fields_at_the_index_token() {
        for source in ["pair.00", "pair.0_", "pair.0x0", "pair.0u8"] {
            let error = ExpressionParser::<4>::new(source).parse().unwrap_err();
            assert_eq!(error.kind, ExpressionErrorKind::InvalidTupleField);
            assert_eq!(
                error.span,
                Span {
                    start: 5,
                    end: source.len()
                }
            );
        }
        let tree = ExpressionParser::<4>::new("pair.0").parse().unwrap();
        assert!(matches!(
            tree.expression(tree.root())
                .map(|expression| expression.kind),
            Some(ExprKind::TupleField { field: 0, .. })
        ));
    }

    #[test]
    fn parses_and_evaluates_integer_casts_with_rust_precedence() {
        assert_eq!(evaluate("300 as u8"), Ok(44));
        assert_eq!(evaluate("255 as i8 as u16"), Ok(u128::from(u16::MAX)));
        assert_eq!(evaluate("1 + 2 as u8 * 3"), Ok(7));
        assert_eq!(
            evaluate("-1000isize as usize >> 3usize"),
            Ok(u128::from(u64::MAX - 999) >> 3)
        );
        let unsupported = ExpressionParser::<8>::new("1 as bool").parse().unwrap_err();
        assert_eq!(unsupported.kind, ExpressionErrorKind::UnsupportedCastType);
        let missing = ExpressionParser::<8>::new("1 as").parse().unwrap_err();
        assert_eq!(missing.kind, ExpressionErrorKind::ExpectedCastType);
    }

    #[test]
    fn resolves_named_constants() {
        struct Resolver;
        impl ConstantResolver for Resolver {
            fn resolve(&self, name: &str) -> Option<u128> {
                (name == "PAGE_SIZE").then_some(4096)
            }
        }
        let tree = ExpressionParser::<8>::new("PAGE_SIZE * 2").parse().unwrap();
        assert_eq!(tree.evaluate(&Resolver), Ok(8192));
        let unknown = ExpressionParser::<2>::new("UNKNOWN").parse().unwrap();
        assert_eq!(
            unknown.evaluate(&Resolver),
            Err(ConstEvalError::UnknownIdentifier)
        );
    }

    #[test]
    fn reports_arithmetic_failures_without_panicking() {
        assert_eq!(evaluate("1 / 0"), Err(ConstEvalError::DivisionByZero));
        assert_eq!(evaluate("0 - 1"), Err(ConstEvalError::Overflow));
        assert_eq!(evaluate("1 << 128"), Err(ConstEvalError::InvalidShift));
        assert_eq!(
            evaluate("340282366920938463463374607431768211455 + 1"),
            Err(ConstEvalError::Overflow)
        );
    }

    #[test]
    fn short_circuits_logical_operations() {
        assert_eq!(evaluate("0 && UNKNOWN"), Ok(0));
        assert_eq!(evaluate("1 || UNKNOWN"), Ok(1));
        assert_eq!(evaluate("false && UNKNOWN"), Ok(0));
        assert_eq!(evaluate("true || UNKNOWN"), Ok(1));
        assert_eq!(evaluate("!false"), Ok(1));
    }

    #[test]
    fn parses_and_evaluates_if_expressions_lazily() {
        assert_eq!(evaluate("if 2 < 3 { 40 + 2 } else { 1 / 0 }"), Ok(42));
        assert_eq!(evaluate("if false { UNKNOWN } else { 7 }"), Ok(7));
        assert_eq!(evaluate("if true { false } else { true }"), Ok(0));
        struct Resolver;
        impl ConstantResolver for Resolver {
            fn resolve(&self, name: &str) -> Option<u128> {
                match name {
                    "X" => Some(4),
                    "Y" => Some(5),
                    _ => None,
                }
            }
        }
        let upstream = ExpressionParser::<24>::new("if X < Y { Y - X } else { X - Y }")
            .parse()
            .unwrap();
        assert_eq!(upstream.evaluate(&Resolver), Ok(1));

        let missing_else = ExpressionParser::<16>::new("if true { 1 }")
            .parse()
            .unwrap_err();
        assert_eq!(missing_else.kind, ExpressionErrorKind::ExpectedElse);
        let missing_brace = ExpressionParser::<16>::new("if true 1 else { 2 }")
            .parse()
            .unwrap_err();
        assert_eq!(missing_brace.kind, ExpressionErrorKind::ExpectedOpenBrace);
    }

    #[test]
    fn parses_explicit_tail_return_only() {
        assert_eq!(evaluate("return 40 + 2;"), Ok(42));
        assert_eq!(evaluate("return true"), Ok(1));
        let nested = ExpressionParser::<16>::new("1 + return 2")
            .parse()
            .unwrap_err();
        assert_eq!(nested.kind, ExpressionErrorKind::TrailingToken);
        assert!(matches!(
            ExpressionParser::<16>::new("if true { return 1 } else { 2 }").parse(),
            Err(ExpressionError {
                kind: ExpressionErrorKind::ExpectedCloseBrace,
                ..
            })
        ));
    }

    #[test]
    fn parses_immediate_break_loop_values() {
        assert_eq!(evaluate("loop { break 13; }"), Ok(13));
        assert_eq!(evaluate("loop { break; }"), Ok(0));
        let unit = ExpressionParser::<8>::new("'value: loop { break 'value; }")
            .parse()
            .unwrap();
        assert_eq!(unit.evaluate(&NoConstants), Ok(0));
        assert_eq!(
            evaluate(
                "'outer: loop { break 'outer 'inner: loop { if false { break 'inner 1 / 0; } else { break 'inner 42; } }; }"
            ),
            Ok(42)
        );
        assert_eq!(
            evaluate(
                "'outer: loop { 'inner: loop { if true { break 'outer 42; } else { break 'inner 17; } }; break 'outer 99; }"
            ),
            Ok(42)
        );
        assert_eq!(
            evaluate(
                "'outer: loop { 'inner: loop { if false { break 'outer 1 / 0; } break 'inner 17; }; break 'outer 99; }"
            ),
            Ok(99)
        );
        assert_eq!(
            evaluate(
                "'outer: loop { 'inner: while break 'inner { 1 / 0; { 2 / 0; } } break 'outer 123; }"
            ),
            Ok(123)
        );
        assert_eq!(
            evaluate("'outer: loop { while break 'outer 567 { 1 / 0; } }"),
            Ok(567)
        );
        assert_eq!(
            ExpressionParser::<16>::new(
                "'outer: loop { 'inner: while break 'inner 1 { } break 'outer 2; }"
            )
            .parse()
            .unwrap_err()
            .kind,
            ExpressionErrorKind::InvalidLoopBreakTarget
        );
        assert_eq!(evaluate("'value: loop { break 'value 13; }"), Ok(13));
        assert_eq!(evaluate("loop { break (); break; }"), Ok(0));
        assert_eq!(evaluate("loop { break; break (); }"), Ok(0));
        assert_eq!(evaluate("loop { break 42; break 1 / 0; }"), Ok(42));
        assert_eq!(
            evaluate("loop { if true { break; } else { break break Default::default(); } }"),
            Ok(0)
        );
        assert_eq!(
            evaluate("loop { if true { break Default::default(); } else { break; } }"),
            Ok(0)
        );
        assert_eq!(
            evaluate("loop { break if true { Default::default() } else { break; }; }"),
            Ok(0)
        );
        assert_eq!(evaluate("Default::default()"), Ok(0));
        for source in ["Default::other()", "Default::default(1)"] {
            assert!(ExpressionParser::<8>::new(source).parse().is_err());
        }
        assert_eq!(
            ExpressionParser::<24>::new(
                "loop { break 1; break 2; break 3; break 4; break 5; break 6; }"
            )
            .parse()
            .unwrap_err()
            .kind,
            ExpressionErrorKind::TooManyLoopBreakBranches
        );
        let boolean = ExpressionParser::<8>::new("loop { break true; }")
            .parse()
            .unwrap();
        assert!(boolean.is_boolean_expression(boolean.root(), 0));
        assert_eq!(boolean.evaluate(&NoConstants), Ok(1));

        assert_eq!(evaluate("loop { break 13 }"), Ok(13));
        let missing_break = ExpressionParser::<8>::new("loop { 13 }")
            .parse()
            .unwrap_err();
        assert_eq!(missing_break.kind, ExpressionErrorKind::ExpectedExpression);

        assert_eq!(
            evaluate("loop { if true { break 13; } break 1 / 0; }"),
            Ok(13)
        );
        assert_eq!(
            evaluate("loop { if false { break 1 / 0; } break 42; }"),
            Ok(42)
        );
        assert_eq!(
            evaluate("'value: loop { if false { break 'value 1 / 0; } break 'value 42; }"),
            Ok(42)
        );
        assert_eq!(
            evaluate(
                "'value: loop { if false { break 'value 1 / 0; } if true { break 'value 42; } if true { break 'value 1 / 0; } break 'value 1 / 0; }"
            ),
            Ok(42)
        );
        assert_eq!(
            evaluate(
                "loop { if false { break 1; } if false { break 2; } if false { break 3; } if true { break 4; } break 5; }"
            ),
            Ok(4)
        );
        assert_eq!(
            evaluate(
                "'value: loop { if false { break 'value 1 / 0; } else if true { break 'value 42; } else { break 'value 1 / 0; } }"
            ),
            Ok(42)
        );
        assert_eq!(
            evaluate("loop { if true { break 13; } else { break 1 / 0; } }"),
            Ok(13)
        );
        let mixed_unit = ExpressionParser::<24>::new(
            "'value: loop { if false { break 'value 1 / 0; } else if true { break 'value; } else { break 'value (); } }",
        )
        .parse()
        .unwrap();
        assert_eq!(mixed_unit.evaluate(&NoConstants), Ok(0));
        assert_eq!(
            ExpressionParser::<32>::new(
                "loop { if false { break 1; } if false { break 2; } if false { break 3; } if false { break 4; } if true { break 5; } break 6; }"
            )
            .parse()
            .unwrap_err()
            .kind,
            ExpressionErrorKind::TooManyLoopBreakBranches
        );
        assert_eq!(
            ExpressionParser::<16>::new("loop { if true { break 1; } else break 2; }")
                .parse()
                .unwrap_err()
                .kind,
            ExpressionErrorKind::ExpectedOpenBrace
        );
        assert_eq!(
            ExpressionParser::<8>::new("'value loop { break 13; }")
                .parse()
                .unwrap_err()
                .kind,
            ExpressionErrorKind::ExpectedColon
        );
        for source in [
            "loop { break 'value 13; }",
            "loop { break 'value; }",
            "'value: loop { break 'other 13; }",
            "'value: loop { if true { break 'other 13; } break 42; }",
        ] {
            assert_eq!(
                ExpressionParser::<16>::new(source)
                    .parse()
                    .unwrap_err()
                    .kind,
                ExpressionErrorKind::UnknownLoopLabel
            );
        }
        assert_eq!(
            ExpressionParser::<24>::new(
                "'outer: loop { 'inner: loop { if true { break 'inner 13; } break 'inner 17; }; break 'outer 42; }",
            )
            .parse()
            .unwrap_err()
            .kind,
            ExpressionErrorKind::InvalidLoopBreakTarget
        );
        let conditional_bool =
            ExpressionParser::<16>::new("loop { if true { break false; } break true; }")
                .parse()
                .unwrap();
        assert!(conditional_bool.is_boolean_expression(conditional_bool.root(), 0));
    }

    #[test]
    fn parses_bounded_scalar_array_literals_and_indexes() {
        assert_eq!(evaluate("[1, 3u32, 5][1]"), Ok(3));
        assert_eq!(evaluate("[10, 20, 30,][2]"), Ok(30));
        assert_eq!(evaluate("[42u32; 3][2]"), Ok(42));
        assert_eq!(evaluate("[7; 0b100usize][3]"), Ok(7));
        assert_eq!(evaluate("[42u32; 16][15]"), Ok(42));
        assert_eq!(
            evaluate("[1 / 0, 42][1]"),
            Err(ConstEvalError::DivisionByZero)
        );
        assert_eq!(
            evaluate("(if true { [1, 42] } else { [1, 1 / 0] })[1]"),
            Ok(42)
        );
        assert_eq!(
            ExpressionParser::<16>::new("[1, 2][2]")
                .parse()
                .unwrap()
                .evaluate(&NoConstants),
            Err(ConstEvalError::ArrayIndexOutOfBounds)
        );
        assert_eq!(
            ExpressionParser::<40>::new(
                "[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]",
            )
            .parse()
            .unwrap_err()
            .kind,
            ExpressionErrorKind::TooManyArrayElements
        );
        assert_eq!(
            ExpressionParser::<8>::new("[42; 17]")
                .parse()
                .unwrap_err()
                .kind,
            ExpressionErrorKind::TooManyArrayElements
        );
        assert_eq!(
            ExpressionParser::<8>::new("[42; 2u8]")
                .parse()
                .unwrap_err()
                .kind,
            ExpressionErrorKind::InvalidIntegerSuffix
        );
        assert_eq!(
            evaluate(
                "(loop { break if true { break Default::default() } else { break [13, 14] }; })[0]"
            ),
            Ok(0)
        );
        assert_eq!(
            evaluate(
                "(loop { if false { break [1 / 0, 14] } else { break Default::default() } })[1]"
            ),
            Ok(0)
        );
        assert_eq!(
            evaluate(
                "(loop { break if false { break Default::default() } else { [42, 43] }; })[1]"
            ),
            Ok(43)
        );
        assert_eq!(
            ExpressionParser::<32>::new("(if true { Default::default() } else { [1, 2] })[2]")
                .parse()
                .unwrap()
                .evaluate(&NoConstants),
            Err(ConstEvalError::ArrayIndexOutOfBounds)
        );
    }

    #[test]
    fn parses_unit_values() {
        assert_eq!(evaluate("()"), Ok(0));
        assert_eq!(evaluate("if true { () } else { () }"), Ok(0));
        assert_eq!(evaluate("loop { break (); }"), Ok(0));
        let tree = ExpressionParser::<8>::new("()").parse().unwrap();
        assert!(!tree.is_boolean_expression(tree.root(), 0));
        assert_eq!(evaluate("true == false"), Ok(0));
        assert_eq!(evaluate("true != false"), Ok(1));
        assert_eq!(evaluate("() == ()"), Ok(1));
        assert_eq!(evaluate("false < true"), Ok(1));
        assert_eq!(evaluate("true >= false"), Ok(1));
        assert_eq!(evaluate("() <= ()"), Ok(1));
        assert_eq!(evaluate("true & false"), Ok(0));
        assert_eq!(evaluate("true | false"), Ok(1));
        assert_eq!(evaluate("true ^ true"), Ok(0));
        assert_eq!(
            evaluate("false & (1 / 0 > 0)"),
            Err(ConstEvalError::DivisionByZero)
        );
        assert_eq!(
            evaluate("true | (1 / 0 > 0)"),
            Err(ConstEvalError::DivisionByZero)
        );
    }

    #[test]
    fn parses_scalar_block_expressions() {
        assert_eq!(evaluate("{ 40 + 2 }"), Ok(42));
        assert_eq!(evaluate("unsafe { 40 + 2 }"), Ok(42));
        assert_eq!(evaluate("unsafe { unsafe { 40 + 2 } }"), Ok(42));
        let unsafe_tree = ExpressionParser::<8>::new("unsafe { 42 }").parse().unwrap();
        let Some(Expr {
            kind: ExprKind::UnsafeBlock { operand },
            ..
        }) = unsafe_tree.expression(unsafe_tree.root())
        else {
            panic!("expected typed unsafe block")
        };
        assert!(unsafe_tree.is_within_unsafe_block(*operand));
        assert_eq!(evaluate("{{ 40 + 2 }}"), Ok(42));
        assert_eq!(
            evaluate("if { true } { { 42 } } else { { 1 / 0 } }"),
            Ok(42)
        );
        assert_eq!(evaluate("{}"), Ok(0));
        assert_eq!(evaluate("{ let value = 42; value }"), Ok(42));
        assert_eq!(
            evaluate("{ let mut value: u8 = 40; value += 2; value }"),
            Ok(42)
        );
        assert_eq!(
            evaluate("{ let outer = 40; { let outer = outer + 2; outer } }"),
            Ok(42)
        );
        assert_eq!(evaluate("{ let value = 42; value; }"), Ok(0));
        assert_eq!(
            evaluate("{ { let local = 42; local }; local }"),
            Err(ConstEvalError::UnknownIdentifier)
        );
        assert_eq!(
            evaluate("if false { { let invalid = 1 / 0; invalid } } else { 42 }"),
            Ok(42)
        );
        let empty = ExpressionParser::<2>::new("{}").parse().unwrap();
        assert!(matches!(
            empty
                .expression(empty.root())
                .map(|expression| expression.kind),
            Some(ExprKind::Unit)
        ));
        assert_eq!(
            ExpressionParser::<8>::new("{ 42").parse().unwrap_err().kind,
            ExpressionErrorKind::ExpectedCloseBrace
        );
        assert_eq!(
            ExpressionParser::<8>::new("unsafe 42")
                .parse()
                .unwrap_err()
                .kind,
            ExpressionErrorKind::ExpectedOpenBrace
        );
    }

    #[test]
    fn parses_bounded_scalar_match_expressions() {
        assert_eq!(evaluate("match 7 { 7 => 42, _ => 1 / 0 }"), Ok(42));
        assert_eq!(evaluate("match 8 { 7 => 1 / 0, _ => 42, }"), Ok(42));
        assert_eq!(
            evaluate("match 7 { 7 => { let value = 42; value } _ => 0 }"),
            Ok(42)
        );
        assert_eq!(
            evaluate("match -7i8 { -7i8 => { let value = 40; value + 2 }, _ => 0 }"),
            Ok(42)
        );
        assert_eq!(evaluate("match false { true => 1 / 0, _ => 42 }"), Ok(42));
        assert_eq!(
            evaluate("match false { true => 1 / 0, false => 42 }"),
            Ok(42)
        );
        assert_eq!(
            evaluate("match true { false => 1 / 0, true => 42, }"),
            Ok(42)
        );
        assert_eq!(evaluate("match 42 { value => value }"), Ok(42));
        assert_eq!(
            evaluate("match true { selected @ (false | true) => if selected { 42 } else { 0 } }"),
            Ok(42)
        );
        assert_eq!(
            evaluate("match 42 { selected @ (1 | _) => selected }"),
            Ok(42)
        );
        assert_eq!(
            evaluate("match 3 { 1 => 1 / 0, 2 => 1 / 0, 3 => 42, 4 => 1 / 0, _ => 0 }"),
            Ok(42)
        );
        assert_eq!(
            evaluate(
                "match 8 { 1 => 1 / 0, 2 => 1 / 0, 3 => 1 / 0, 4 => 1 / 0, 5 => 1 / 0, 6 => 1 / 0, 7 => 1 / 0, 8 => 42, _ => 0 }"
            ),
            Ok(42)
        );
        assert_eq!(
            evaluate(
                "match 8 { 1 if 1 / 0 > 0 => 0, 2 => 1 / 0, 3 => 1 / 0, 4 => 1 / 0, 5 => 1 / 0, 6 => 1 / 0, 7 => 1 / 0, 8 if true => 42, _ => 0 }"
            ),
            Ok(42)
        );
        assert_eq!(
            evaluate("match 9 { 1 => 1 / 0, 2 => 1 / 0, 3 => 1 / 0, _ => 42 }"),
            Ok(42)
        );
        assert_eq!(evaluate("match 5 { 1..=5 => 42, _ => 0 }"), Ok(42));
        assert_eq!(evaluate("match 1 { 1..5 => 42, _ => 0 }"), Ok(42));
        assert_eq!(evaluate("match 5 { 1..5 => 1 / 0, _ => 42 }"), Ok(42));
        assert_eq!(
            evaluate("match 5 { 1 => 1 / 0, 2..=6 => 42, _ => 1 / 0 }"),
            Ok(42)
        );
        assert_eq!(evaluate("match 0 { 0 | 1..=10 => 42, _ => 0 }"), Ok(42));
        assert_eq!(evaluate("match 5 { 0 | 1..=10 => 42, _ => 0 }"), Ok(42));
        assert_eq!(
            evaluate("match 12 { 0 | 1..=10 => 1 / 0, 12 | 13 => 42, _ => 0 }"),
            Ok(42)
        );
        assert_eq!(evaluate("match 2 { (1 | 2) => 42, _ => 0 }"), Ok(42));
        assert_eq!(
            evaluate("match 3 { ((1 | 2) | (3 | 4)) => 42, _ => 0 }"),
            Ok(42)
        );
        assert_eq!(
            evaluate("match 9 { (| 1 | (5..=10)) if true => 42, _ => 0 }"),
            Ok(42)
        );
        assert_eq!(
            evaluate("match 99 { (1 | (_)) if false => 1 / 0, _ => 42 }"),
            Ok(42)
        );
        assert_eq!(evaluate("match 9 { 5.. => 42, _ => 0 }"), Ok(42));
        assert_eq!(evaluate("match 4 { ..5 => 42, _ => 0 }"), Ok(42));
        assert_eq!(evaluate("match 5 { ..5 => 1 / 0, _ => 42 }"), Ok(42));
        assert_eq!(evaluate("match 5 { ..=5 => 42, _ => 0 }"), Ok(42));
        assert_eq!(evaluate("match 42 { 42..=42 => 42, _ => 0 }"), Ok(42));
        assert_eq!(evaluate("match 41 { 41..42 => 42, _ => 0 }"), Ok(42));
        assert_eq!(evaluate("match 7 { ..3 | 7.. => 42, _ => 0 }"), Ok(42));
        assert_eq!(
            evaluate("match 1 { 1 if false => 1 / 0, 1..=2 => 42, _ => 0 }"),
            Ok(42)
        );
        assert_eq!(
            evaluate("match 2 { 1 if 1 / 0 > 0 => 0, 2 if true => 42, _ => 0 }"),
            Ok(42)
        );
        assert_eq!(
            evaluate("match 3 { 1..=3 if true => 42, _ => 1 / 0 }"),
            Ok(42)
        );
        assert_eq!(evaluate("match 5 { _ => 42 }"), Ok(42));
        assert_eq!(
            evaluate("match 5 { _ if false => 1 / 0, 5 => 42, _ => 0 }"),
            Ok(42)
        );
        assert_eq!(
            evaluate("match 5 { _ if true => 42, 5 => 1 / 0, _ => 0 }"),
            Ok(42)
        );
        assert_eq!(
            evaluate("match 0 { _ if false && 1 / 0 > 0 => 0, _ if true => 42, _ => 0 }"),
            Ok(42)
        );
        assert_eq!(
            evaluate("match 10 { x if x < 7 => 1 / 0, y if y < 11 => y + 32, _ => 0 }"),
            Ok(42)
        );
        assert_eq!(
            evaluate("match '\\u{3bb}' { scalar if scalar == '\\u{3bb}' => 42, _ => 0 }"),
            Ok(42)
        );
        assert_eq!(
            evaluate("match 50 { number @ 1..=100 if number == 50 => number - 8, _ => 0 }"),
            Ok(42)
        );
        assert_eq!(
            evaluate("match 42 { value @ _ if value == 42 => value, _ => 0 }"),
            Ok(42)
        );
        assert_eq!(
            evaluate("match '\u{6d}' { symbol @ 'a'..='z' => symbol, _ => '*' }"),
            Ok(109)
        );
        assert_eq!(
            evaluate("match 2 { selected @ 1 | selected @ 2 => selected + 40, _ => 0 }"),
            Ok(42)
        );
        assert_eq!(
            evaluate("match 7 { value @ 1..=3 | value @ 7..=9 if value == 7 => 42, _ => 0 }"),
            Ok(42)
        );
        assert_eq!(
            evaluate("match 2 { selected @ (1 | 2) => selected + 40, _ => 0 }"),
            Ok(42)
        );
        assert_eq!(
            evaluate("match 7 { selected @ ((1..=3) | (7 | 9)) if selected == 7 => 42, _ => 0 }"),
            Ok(42)
        );
        assert_eq!(
            evaluate("match 42 { selected @ (| 1 | _) if selected == 42 => selected, _ => 0 }"),
            Ok(42)
        );
        assert_eq!(evaluate("match 'c' { 'a'..='z' => 42, _ => 0 }"), Ok(42));
        assert_eq!(
            evaluate("match '\\n' { '\\t' | '\\n' => 42, _ => 0 }"),
            Ok(42)
        );
        assert_eq!(
            evaluate("match '\\u{3bb}' { '\u{3b1}'..='\u{3c9}' => 42, _ => 0 }"),
            Ok(42)
        );

        let missing_fallback = ExpressionParser::<16>::new("match 1 { 1 => 42 }")
            .parse()
            .unwrap_err();
        assert_eq!(
            missing_fallback.kind,
            ExpressionErrorKind::NonExhaustiveMatch
        );
        let missing_wildcard = ExpressionParser::<24>::new("match 1 { 1 => 42, 2 => 0 }")
            .parse()
            .unwrap_err();
        assert_eq!(
            missing_wildcard.kind,
            ExpressionErrorKind::NonExhaustiveMatch
        );
        for source in [
            "match true { true => 42 }",
            "match false { true => 1, false if false => 2 }",
            "match true { true if true => 42, false => 0 }",
        ] {
            assert_eq!(
                ExpressionParser::<32>::new(source)
                    .parse()
                    .unwrap_err()
                    .kind,
                ExpressionErrorKind::NonExhaustiveMatch
            );
        }
        let too_many = ExpressionParser::<128>::new(
            "match 1 { 1 => 1, 2 => 2, 3 => 3, 4 => 4, 5 => 5, 6 => 6, 7 => 7, 8 => 8, 9 => 9, _ => 0 }",
        )
        .parse()
        .unwrap_err();
        assert_eq!(too_many.kind, ExpressionErrorKind::TooManyMatchPatterns);
        let malformed_range = ExpressionParser::<24>::new("match 1 { 0.1 => 1, _ => 0 }")
            .parse()
            .unwrap_err();
        assert_eq!(
            malformed_range.kind,
            ExpressionErrorKind::ExpectedMatchPattern
        );
        let too_many_alternatives =
            ExpressionParser::<64>::new("match 1 { 0 | 1 | 2 | 3 | 4 => 42, _ => 0 }")
                .parse()
                .unwrap_err();
        assert_eq!(
            too_many_alternatives.kind,
            ExpressionErrorKind::TooManyMatchAlternatives
        );
        let too_many_nested_alternatives =
            ExpressionParser::<64>::new("match 1 { ((0 | 1) | (2 | (3 | 4))) => 42, _ => 0 }")
                .parse()
                .unwrap_err();
        assert_eq!(
            too_many_nested_alternatives.kind,
            ExpressionErrorKind::TooManyMatchAlternatives
        );
        let too_many_grouped_binding_alternatives = ExpressionParser::<64>::new(
            "match 1 { value @ ((0 | 1) | (2 | (3 | 4))) => value, _ => 0 }",
        )
        .parse()
        .unwrap_err();
        assert_eq!(
            too_many_grouped_binding_alternatives.kind,
            ExpressionErrorKind::TooManyMatchAlternatives
        );
        let empty_group = ExpressionParser::<24>::new("match 1 { () => 42, _ => 0 }")
            .parse()
            .unwrap_err();
        assert_eq!(empty_group.kind, ExpressionErrorKind::ExpectedMatchPattern);
        let trailing_alternative = ExpressionParser::<32>::new("match 1 { (1 |) => 42, _ => 0 }")
            .parse()
            .unwrap_err();
        assert_eq!(
            trailing_alternative.kind,
            ExpressionErrorKind::ExpectedMatchPattern
        );
        let missing_group_close = ExpressionParser::<32>::new("match 1 { (1 | 2 => 42, _ => 0 }")
            .parse()
            .unwrap_err();
        assert_eq!(
            missing_group_close.kind,
            ExpressionErrorKind::ExpectedCloseParen
        );
        let unbounded = ExpressionParser::<24>::new("match 1 { .. => 42, _ => 0 }")
            .parse()
            .unwrap_err();
        assert_eq!(unbounded.kind, ExpressionErrorKind::ExpectedMatchPattern);
        for source in [
            "match 5 { 6..=1 => 42, _ => 0 }",
            "match 0 { 0..0 => 42, _ => 0 }",
            "match -3 { -1..=-5 => 42, _ => 0 }",
            "match 'm' { 'z'..='a' => 42, _ => 0 }",
        ] {
            let invalid = ExpressionParser::<32>::new(source).parse().unwrap_err();
            assert_eq!(invalid.kind, ExpressionErrorKind::InvalidRangeBounds);
        }
        for source in [
            "match false { false..=true => 42, _ => 0 }",
            "match true { false.. => 42, _ => 0 }",
        ] {
            let invalid = ExpressionParser::<24>::new(source).parse().unwrap_err();
            assert_eq!(invalid.kind, ExpressionErrorKind::InvalidRangeType);
        }
        struct RangeResolver;
        impl ConstantResolver for RangeResolver {
            fn resolve(&self, name: &str) -> Option<u128> {
                match name {
                    "START" => Some(6),
                    "END" => Some(1),
                    _ => None,
                }
            }

            fn resolve_type(&self, name: &str) -> Option<IntegerType> {
                matches!(name, "START" | "END").then_some(IntegerType::U32)
            }
        }
        let named_invalid = ExpressionParser::<32>::new("match 5 { START..=END => 42, _ => 0 }")
            .parse()
            .unwrap();
        assert_eq!(
            named_invalid.evaluate(&RangeResolver),
            Err(ConstEvalError::InvalidRangeBounds)
        );
        let too_many_range_validations = concat!(
            "{ ",
            "match 0 { 0..=0 => 0, 1..=1 => 0, 2..=2 => 0, 3..=3 => 0, _ => 0 }; ",
            "match 0 { 0..=0 => 0, 1..=1 => 0, 2..=2 => 0, 3..=3 => 0, _ => 0 }; ",
            "match 0 { 0..=0 => 0, 1..=1 => 0, 2..=2 => 0, 3..=3 => 0, _ => 0 }; ",
            "match 0 { 0..=0 => 0, 1..=1 => 0, 2..=2 => 0, 3..=3 => 0, _ => 0 }; ",
            "match 0 { 0..=0 => 0, 1..=1 => 0, 2..=2 => 0, 3..=3 => 0, _ => 0 }; ",
            "match 0 { 0..=0 => 0, 1..=1 => 0, 2..=2 => 0, 3..=3 => 0, _ => 0 }; ",
            "match 0 { 0..=0 => 0, 1..=1 => 0, 2..=2 => 0, 3..=3 => 0, _ => 0 }; ",
            "match 0 { 0..=0 => 0, 1..=1 => 0, 2..=2 => 0, 3..=3 => 0, _ => 0 }; ",
            "match 0 { 0..=0 => 0, _ => 0 }; 0 }",
        );
        assert_eq!(
            ExpressionParser::<512>::new(too_many_range_validations)
                .parse()
                .unwrap_err()
                .kind,
            ExpressionErrorKind::TooManyRangeValidations
        );
        let inconsistent_binding =
            ExpressionParser::<24>::new("match 1 { value | 1 => 42, _ => 0 }")
                .parse()
                .unwrap_err();
        assert_eq!(
            inconsistent_binding.kind,
            ExpressionErrorKind::InconsistentMatchBindings
        );
        let mismatched_bindings =
            ExpressionParser::<40>::new("match 1 { left @ 1 | right @ 2 => 42, _ => 0 }")
                .parse()
                .unwrap_err();
        assert_eq!(
            mismatched_bindings.kind,
            ExpressionErrorKind::InconsistentMatchBindings
        );
        let nested_mismatched_bindings =
            ExpressionParser::<48>::new("match 1 { (left @ 1 | (right @ 2)) => 42, _ => 0 }")
                .parse()
                .unwrap_err();
        assert_eq!(
            nested_mismatched_bindings.kind,
            ExpressionErrorKind::InconsistentMatchBindings
        );
        let nested_at_in_group = ExpressionParser::<48>::new(
            "match 1 { outer @ (inner @ 1 | inner @ 2) => outer, _ => 0 }",
        )
        .parse()
        .unwrap_err();
        assert_eq!(
            nested_at_in_group.kind,
            ExpressionErrorKind::ExpectedMatchPattern
        );
        let non_identifier_at = ExpressionParser::<24>::new("match 1 { 1 @ 1 => 42, _ => 0 }")
            .parse()
            .unwrap_err();
        assert_eq!(
            non_identifier_at.kind,
            ExpressionErrorKind::ExpectedIdentifier
        );
        let nested_at = ExpressionParser::<32>::new("match 1 { outer @ inner @ 1 => 42, _ => 0 }")
            .parse()
            .unwrap_err();
        assert_eq!(nested_at.kind, ExpressionErrorKind::ExpectedMatchPattern);
        let invalid_scalar = ExpressionParser::<8>::new("'\\u{d800}'")
            .parse()
            .unwrap_err();
        assert_eq!(invalid_scalar.kind, ExpressionErrorKind::InvalidCharacter);
    }

    #[test]
    fn parses_closed_scalar_inline_const_blocks() {
        assert_eq!(evaluate("const { 40 + 2 }"), Ok(42));
        assert_eq!(evaluate("const { { 42 } }"), Ok(42));
        assert_eq!(evaluate("if true { const { 42 } } else { 1 / 0 }"), Ok(42));
        assert_eq!(evaluate("const {}"), Ok(0));
        assert_eq!(
            ExpressionParser::<8>::new("const 42")
                .parse()
                .unwrap_err()
                .kind,
            ExpressionErrorKind::ExpectedOpenBrace
        );
        struct Resolver;
        impl ConstantResolver for Resolver {
            fn resolve(&self, name: &str) -> Option<u128> {
                (name == "ITEM").then_some(42)
            }
        }
        let named = ExpressionParser::<8>::new("const { ITEM }")
            .parse()
            .unwrap();
        assert_eq!(named.evaluate(&Resolver), Ok(42));
    }

    #[test]
    fn parses_immutable_scalar_bindings_inside_inline_const() {
        assert_eq!(evaluate("const { let x = 5 + 10; x / 3 }"), Ok(5));
        assert_eq!(
            evaluate("const { let x = 20; let y = x + 1; y * 2 }"),
            Ok(42)
        );
        assert_eq!(
            evaluate("const { let x = 40; if true { x + 2 } else { 1 / 0 } }"),
            Ok(42)
        );
        assert_eq!(
            evaluate("const { let x = 1; const { x } }"),
            Err(ConstEvalError::UnknownIdentifier)
        );
        assert_eq!(
            ExpressionParser::<16>::new("const { let = 1; 1 }")
                .parse()
                .unwrap_err()
                .kind,
            ExpressionErrorKind::ExpectedIdentifier
        );
        assert_eq!(
            ExpressionParser::<16>::new("const { let x 1; x }")
                .parse()
                .unwrap_err()
                .kind,
            ExpressionErrorKind::ExpectedEquals
        );
        assert_eq!(
            ExpressionParser::<16>::new("const { let x = 1 x }")
                .parse()
                .unwrap_err()
                .kind,
            ExpressionErrorKind::ExpectedSemicolon
        );
        assert_eq!(
            ExpressionParser::<32>::new(
                "const { let a = 1; let b = 2; let c = 3; let d = 4; let e = 5; e }",
            )
            .parse()
            .unwrap_err()
            .kind,
            ExpressionErrorKind::TooManyInlineConstBindings
        );
    }

    #[test]
    fn evaluates_mutable_scalar_bindings_inside_inline_const() {
        assert_eq!(evaluate("const { let mut x = 5; x += 10; x / 3 }"), Ok(5));
        assert_eq!(
            evaluate("const { let mut x = 2; let y = 10; x *= y; x += 22; x }"),
            Ok(42)
        );
        assert_eq!(
            evaluate("const { let mut flag = false; flag |= true; flag }"),
            Ok(1)
        );
        assert_eq!(evaluate("const { let mut x = 1; x = 42; x }"), Ok(42));
        assert_eq!(
            ExpressionParser::<24>::new("const { let x = 1; x += 1; x }")
                .parse()
                .unwrap_err()
                .kind,
            ExpressionErrorKind::ImmutableInlineConstAssignment
        );
        assert_eq!(
            evaluate("const { let mut x = 340282366920938463463374607431768211455; x += 1; x }"),
            Err(ConstEvalError::Overflow)
        );
    }

    #[test]
    fn preserves_scalar_type_ascriptions_inside_inline_const() {
        assert_eq!(evaluate("const { let value: u8 = 42; value }"), Ok(42));
        assert_eq!(
            evaluate("const { let mut value: u8 = 40; value += 2; value }"),
            Ok(42)
        );
        assert_eq!(evaluate("const { let value: bool = 1 < 2; value }"), Ok(1));
        assert_eq!(
            evaluate("const { let value: u8 = 256; value }"),
            Err(ConstEvalError::Overflow)
        );
        assert_eq!(
            evaluate("const { let mut value: u8 = 250; value += 6; value }"),
            Err(ConstEvalError::Overflow)
        );
        assert_eq!(
            evaluate("const { let value: bool = 1; value }"),
            Err(ConstEvalError::InvalidCast)
        );
        assert_eq!(
            ExpressionParser::<16>::new("const { let value: = 1; value }")
                .parse()
                .unwrap_err()
                .kind,
            ExpressionErrorKind::ExpectedInlineConstType
        );
        assert_eq!(
            ExpressionParser::<16>::new("const { let value: String = 1; value }")
                .parse()
                .unwrap_err()
                .kind,
            ExpressionErrorKind::UnsupportedInlineConstType
        );
    }

    #[test]
    fn preserves_interleaved_inline_const_statement_order() {
        assert_eq!(
            evaluate(
                "const { let mut value = 1; value += 1; let scale = 10; value *= scale; let offset = 22; value += offset; value }"
            ),
            Ok(42)
        );
        assert_eq!(
            evaluate(
                "const { let mut value: u8 = 1; value += 1; let mut value: u8 = value * 10; value += 22; value }"
            ),
            Ok(42)
        );
        assert_eq!(
            ExpressionParser::<64>::new(
                "const { let mut value = 1; value += 1; let value = 2; value += 1; value }",
            )
            .parse()
            .unwrap_err()
            .kind,
            ExpressionErrorKind::ImmutableInlineConstAssignment
        );
        assert_eq!(
            ExpressionParser::<64>::new(
                "const { let a = 1; let b = 2; a; let c = 3; let d = 4; let e = 5; e }",
            )
            .parse()
            .unwrap_err()
            .kind,
            ExpressionErrorKind::TooManyInlineConstBindings
        );
        assert_eq!(
            ExpressionParser::<64>::new(
                "const { let mut a = 1; a += 1; let b = 2; let c = 3; let d = 4; let e = 5; e }",
            )
            .parse()
            .unwrap_err()
            .kind,
            ExpressionErrorKind::TooManyInlineConstBindings
        );
    }

    #[test]
    fn evaluates_inline_const_expression_statements_in_order() {
        assert_eq!(evaluate("const { 1 + 1; 42 }"), Ok(42));
        assert_eq!(
            evaluate(
                "const { let mut value = 1; value += 1; value; let scale = 21; value * scale }"
            ),
            Ok(42)
        );
        assert_eq!(
            evaluate("const { 1 / 0; 42 }"),
            Err(ConstEvalError::DivisionByZero)
        );
        assert_eq!(
            evaluate("const { if false { 1 / 0 } else { 1 }; 42 }"),
            Ok(42)
        );
        assert_eq!(
            ExpressionParser::<64>::new("const { 0; 1; 2; 3; 4; 5; 6; 7; 8; 9 }",)
                .parse()
                .unwrap_err()
                .kind,
            ExpressionErrorKind::TooManyInlineConstExpressionStatements
        );
    }

    #[test]
    fn inline_const_trailing_semicolons_produce_unit() {
        assert_eq!(evaluate("const { 42; }"), Ok(0));
        assert_eq!(evaluate("const { let value = 42; value; }"), Ok(0));
        assert_eq!(
            evaluate("const { let mut value = 40; value += 2; value; }"),
            Ok(0)
        );
        let tree = ExpressionParser::<32>::new("const { true; }")
            .parse()
            .unwrap();
        assert!(!tree.is_boolean_expression(tree.root(), 0));
        assert_eq!(
            ExpressionParser::<16>::new("const { return }")
                .parse()
                .unwrap()
                .evaluate(&NoConstants),
            Err(ConstEvalError::UnknownIdentifier)
        );
        assert_eq!(
            ExpressionParser::<16>::new("const { break }")
                .parse()
                .unwrap()
                .evaluate(&NoConstants),
            Err(ConstEvalError::UnknownIdentifier)
        );
    }

    #[test]
    fn parses_unit_if_statements_without_else() {
        assert_eq!(evaluate("if false { 1 / 0; }"), Ok(0));
        assert_eq!(evaluate("if true { 20 + 22; }"), Ok(0));
        assert_eq!(evaluate("if true {}"), Ok(0));
        assert_eq!(evaluate("const { if false { 1 / 0; }; 42 }"), Ok(42));
        assert_eq!(
            ExpressionParser::<16>::new("if true { 42 }")
                .parse()
                .unwrap_err()
                .kind,
            ExpressionErrorKind::ExpectedElse
        );
        assert_eq!(
            ExpressionParser::<32>::new("if true { 0; 1; 2; 3; 4; 5; 6; 7; 8; }")
                .parse()
                .unwrap_err()
                .kind,
            ExpressionErrorKind::TooManyInlineConstExpressionStatements
        );
    }

    #[test]
    fn evaluates_scoped_statements_inside_if_branches() {
        assert_eq!(
            evaluate("if true { let mut value: u8 = 40; value += 2; value } else { 1 / 0 }"),
            Ok(42)
        );
        assert_eq!(
            evaluate("if false { 1 / 0 } else { let first = 20; let second = 22; first + second }"),
            Ok(42)
        );
        assert_eq!(
            evaluate(
                "const { let outer = 40; if true { let outer = outer + 2; outer } else { 0 } }"
            ),
            Ok(42)
        );
        assert_eq!(
            evaluate("const { if true { let local = 42; local } else { 0 }; 7 }"),
            Ok(7)
        );
        assert_eq!(
            evaluate("const { if true { let local = 42; local } else { 0 }; local }"),
            Err(ConstEvalError::UnknownIdentifier)
        );
        assert_eq!(evaluate("if false { let value = 1 / 0; value; }"), Ok(0));
    }

    #[test]
    fn evaluates_else_if_chains_lazily() {
        assert_eq!(
            evaluate(
                "if false { 1 / 0 } else if true { let mut value = 40; value += 2; value } else { 1 / 0 }"
            ),
            Ok(42)
        );
        assert_eq!(
            evaluate("if false { 1 } else if false { 1 / 0 } else if true { 42 } else { 1 / 0 }"),
            Ok(42)
        );
        assert_eq!(evaluate("if false {} else if true { 20 + 22; }"), Ok(0));
        assert_eq!(
            ExpressionParser::<32>::new("if false { 0 } else if true { 42 }")
                .parse()
                .unwrap_err()
                .kind,
            ExpressionErrorKind::ExpectedElse
        );
    }

    #[test]
    fn enforces_arena_and_nesting_limits() {
        let arena = ExpressionParser::<2>::new("1 + 2").parse().unwrap_err();
        assert_eq!(arena.kind, ExpressionErrorKind::TooManyNodes);
        let nested = ExpressionParser::<128>::new(
            "((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((1))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))",
        )
        .parse()
        .unwrap_err();
        assert_eq!(nested.kind, ExpressionErrorKind::NestingLimitExceeded);
    }

    #[test]
    fn rejects_trailing_and_incomplete_syntax() {
        let trailing = ExpressionParser::<8>::new("1 2").parse().unwrap_err();
        assert_eq!(trailing.kind, ExpressionErrorKind::TrailingToken);
        let incomplete = ExpressionParser::<8>::new("1 +").parse().unwrap_err();
        assert_eq!(incomplete.kind, ExpressionErrorKind::ExpectedExpression);
        let group = ExpressionParser::<8>::new("(1 + 2").parse().unwrap_err();
        assert_eq!(group.kind, ExpressionErrorKind::ExpectedCloseParen);
    }
}
