#[cfg(test)]
mod tests {
    use super::*;

    type TestModule<'source> = Module<'source, 4, 4>;

    #[test]
    fn parses_function_signatures_without_allocation() {
        let source = "pub fn add(left: u32, right: &u32) -> core::primitive::u32 { left + *right }";
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        assert_eq!(module.item_count(), 1);
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert!(function.public);
        assert!(!function.constant);
        assert_eq!(function.abi, FunctionAbi::Rust);
        assert!(!function.no_mangle);
        assert_eq!(function.name, "add");
        assert_eq!(function.parameter_count(), 2);
        assert_eq!(function.parameters()[0].unwrap().ty.text, "u32");
        assert_eq!(function.parameters()[1].unwrap().ty.text, "&u32");
        assert_eq!(function.return_type.unwrap().text, "core::primitive::u32");
        assert_eq!(
            &source[function.body.start..function.body.end],
            "{ left + *right }"
        );
        assert_eq!(function.body_expression, "left + *right");
        assert_eq!(
            &source[function.body_expression_span.start..function.body_expression_span.end],
            function.body_expression
        );
    }

    #[test]
    fn leading_no_std_attributes_do_not_consume_item_capacity() {
        let source = "// crate header\n#![no_std]\n#![no_std]\nfn total() -> i32 { 42 }";
        let module = Parser::new(source).parse_module::<1, 0>().unwrap();
        assert_eq!(module.item_count(), 1);
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function");
        };
        assert_eq!(function.name, "total");
        assert_eq!(
            &source[function.name_span.start..function.name_span.end],
            "total"
        );
    }

    #[test]
    fn source_header_preserves_inner_attributes_and_original_offsets() {
        for header in [
            "\u{feff}",
            "\u{feff}#!/usr/bin/env rust-script\r\n#![no_std]\n",
            "#! /* ordinary */\n[no_std]\n",
            "#! // ordinary\n[no_std]\n",
            "#! /***/ /**/ \n[no_std]\n",
            "#! /* unfinished text on the shebang\n",
            "#! /** documentation */ [ignored_on_the_shebang]\n",
        ] {
            let function_source = "fn total() -> i32 { 42 }";
            let mut source = [0; 128];
            let length = header.len() + function_source.len();
            source[..header.len()].copy_from_slice(header.as_bytes());
            source[header.len()..length].copy_from_slice(function_source.as_bytes());
            let source = core::str::from_utf8(&source[..length]).unwrap();
            let module = Parser::new(source).parse_module::<1, 0>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(function.name_span.start, header.len() + "fn ".len());
            assert_eq!(
                &source[function.body_expression_span.start..function.body_expression_span.end],
                "42"
            );
        }
    }

    #[test]
    fn source_header_rejects_misplaced_prefixes() {
        for (source, token) in [
            (" \u{feff}fn total() -> i32 { 42 }", "\u{feff}"),
            ("\u{feff}\u{feff}fn total() -> i32 { 42 }", "\u{feff}"),
            (" #!/usr/bin/env rust-script\nfn total() -> i32 { 42 }", "/"),
            ("fn total() -> i32 { \u{feff}42 }", "\u{feff}"),
            (
                "#! /** documentation */\n[no_std]\nfn total() -> i32 { 42 }",
                "[",
            ),
            (
                "#! /// documentation\n[no_std]\nfn total() -> i32 { 42 }",
                "[",
            ),
        ] {
            let error = Parser::new(source).parse_module::<1, 0>().unwrap_err();
            assert_eq!(&source[error.span.start..error.span.end], token);
        }
    }

    #[test]
    fn leading_no_std_preserves_the_remaining_attribute_checks() {
        for (source, kind, token) in [
            (
                "#![no_std(extra)]",
                ParseErrorKind::ExpectedAttributeDelimiter,
                "(",
            ),
            ("#![other]", ParseErrorKind::UnsupportedAttribute, "other"),
            (
                "#[no_std] fn total() {}",
                ParseErrorKind::UnsupportedAttribute,
                "no_std",
            ),
            (
                "fn total() {}\n#![no_std]",
                ParseErrorKind::ExpectedAttributeDelimiter,
                "!",
            ),
        ] {
            let error = Parser::new(source).parse_module::<2, 0>().unwrap_err();
            assert_eq!(error.kind, kind);
            assert_eq!(&source[error.span.start..error.span.end], token);
        }
    }

    #[test]
    fn parses_bounded_marker_trait_declarations() {
        let source = "pub trait Sendable {} trait Local { /* marker */ }";
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        assert_eq!(module.item_count(), 2);
        let Some(Item::Trait(sendable)) = module.items()[0] else {
            panic!("expected public trait")
        };
        let Some(Item::Trait(local)) = module.items()[1] else {
            panic!("expected private trait")
        };
        assert!(sendable.public);
        assert_eq!(sendable.name, "Sendable");
        assert_eq!(&source[sendable.body.start..sendable.body.end], "{}");
        assert!(!local.public);
        assert_eq!(local.name, "Local");
    }

    #[test]
    fn parses_and_bounds_marker_supertraits() {
        let source = "trait Child: Parent + Visible {}";
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        let Some(Item::Trait(child)) = module.items()[0] else {
            panic!("expected trait")
        };
        assert_eq!(child.supertrait_count(), 2);
        assert_eq!(child.supertraits()[0].unwrap().name, "Parent");
        assert_eq!(child.supertraits()[1].unwrap().name, "Visible");

        let overflow = Parser::new(concat!(
            "trait Child: T0 + T1 + T2 + T3 + T4 + T5 + T6 + T7 + T8 {}"
        ))
        .parse_module::<2, 1>()
        .unwrap_err();
        assert_eq!(overflow.kind, ParseErrorKind::TooManySupertraits);
    }

    #[test]
    fn parses_parameterized_supertrait_paths() {
        let source = "trait Child<T, U>: Parent<T> + Pair<T, U> {}";
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        let Some(Item::Trait(child)) = module.items()[0] else {
            panic!("expected trait")
        };
        assert_eq!(child.supertraits()[0].unwrap().argument_count(), 1);
        assert_eq!(
            child.supertraits()[0].unwrap().arguments()[0].unwrap().text,
            "T"
        );
        assert_eq!(child.supertraits()[1].unwrap().argument_count(), 2);
        assert_eq!(
            child.supertraits()[1].unwrap().arguments()[1].unwrap().text,
            "U"
        );
    }

    #[test]
    fn desugars_associated_bindings_on_supertrait_paths() {
        let source = "trait Child: Parent<u8, Output = u16> {}";
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        let Some(Item::Trait(child)) = module.items()[0] else {
            panic!("expected trait")
        };
        assert_eq!(child.supertraits()[0].unwrap().argument_count(), 1);
        assert_eq!(
            child.supertraits()[0].unwrap().arguments()[0].unwrap().text,
            "u8"
        );
        assert_eq!(child.where_predicate_count(), 1);
        assert!(matches!(
            child.where_predicates()[0],
            Some(TraitImplementationWherePredicate::ProjectionEquality {
                self_type: TypeRef { text: "Self", .. },
                associated_type: "Output",
                expected_type: TypeRef { text: "u16", .. },
                ..
            })
        ));
    }

    #[test]
    fn parses_trait_declaration_where_requirements() {
        let source = "trait Child<T> where T: Parent<T>, Self: Visible {}";
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        let Some(Item::Trait(child)) = module.items()[0] else {
            panic!("expected trait")
        };
        assert_eq!(child.where_predicate_count(), 2);
        let first = child.where_predicates()[0].unwrap();
        assert_eq!(first.self_type().text, "T");
        assert_eq!(first.trait_name(), "Parent");
        assert_eq!(first.trait_arguments()[0].unwrap().text, "T");
        let second = child.where_predicates()[1].unwrap();
        assert_eq!(second.self_type().text, "Self");
        assert_eq!(second.trait_name(), "Visible");
    }

    #[test]
    fn desugars_associated_bindings_in_explicit_trait_where_clauses() {
        let source = "trait Child<T> where T: Parent<u8, Output = T> {}";
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        let Some(Item::Trait(child)) = module.items()[0] else {
            panic!("expected trait")
        };
        assert_eq!(child.where_predicate_count(), 2);
        assert_eq!(
            child.where_predicates()[0].unwrap().trait_argument_count(),
            1
        );
        assert!(matches!(
            child.where_predicates()[1],
            Some(TraitImplementationWherePredicate::ProjectionEquality {
                associated_type: "Output",
                expected_type: TypeRef { text: "T", .. },
                ..
            })
        ));
    }

    #[test]
    fn desugars_trait_parameter_bounds_into_declaration_requirements() {
        let source = "trait Child<T: Parent<T> + Visible, U: Parent<u8>> {}";
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        let Some(Item::Trait(child)) = module.items()[0] else {
            panic!("expected trait")
        };
        assert_eq!(child.generic_parameter_count(), 2);
        assert_eq!(child.where_predicate_count(), 3);
        assert_eq!(child.where_predicates()[0].unwrap().self_type().text, "T");
        assert_eq!(child.where_predicates()[0].unwrap().trait_name(), "Parent");
        assert_eq!(child.where_predicates()[1].unwrap().trait_name(), "Visible");
        assert_eq!(child.where_predicates()[2].unwrap().self_type().text, "U");
        assert_eq!(
            child.where_predicates()[2].unwrap().trait_arguments()[0]
                .unwrap()
                .text,
            "u8"
        );
    }

    #[test]
    fn desugars_associated_bindings_on_trait_parameter_bounds() {
        let source = "trait Child<T: Iterator<Item = T>> {}";
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        let Some(Item::Trait(child)) = module.items()[0] else {
            panic!("expected trait")
        };
        assert_eq!(child.where_predicate_count(), 2);
        assert!(matches!(
            child.where_predicates()[0],
            Some(TraitImplementationWherePredicate::Implemented {
                trait_name: "Iterator",
                trait_argument_count: 0,
                ..
            })
        ));
        assert!(matches!(
            child.where_predicates()[1],
            Some(TraitImplementationWherePredicate::ProjectionEquality {
                trait_name: "Iterator",
                associated_type: "Item",
                expected_type: TypeRef { text: "T", .. },
                ..
            })
        ));

        let mixed: TestModule<'_> = Parser::new("trait Child<T: Parent<u8, Output = T>> {}")
            .parse_module()
            .unwrap();
        let Some(Item::Trait(child)) = mixed.items()[0] else {
            panic!("expected trait")
        };
        assert_eq!(
            child.where_predicates()[0].unwrap().trait_argument_count(),
            1
        );
        assert_eq!(
            child.where_predicates()[1].unwrap().trait_arguments()[0]
                .unwrap()
                .text,
            "u8"
        );
    }

    #[test]
    fn parses_bounded_trait_associated_types_and_exact_values() {
        let source = concat!(
            "trait Iterator { type Item; type Error; } ",
            "impl Iterator for u32 { type Item = u8; type Error = core::result::Result; }"
        );
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        let Some(Item::Trait(declaration)) = module.items()[0] else {
            panic!("expected trait")
        };
        assert_eq!(declaration.associated_type_count(), 2);
        assert_eq!(declaration.associated_types()[0].unwrap().name, "Item");
        assert_eq!(declaration.associated_types()[0].unwrap().default, None);
        let Some(Item::TraitImplementation(implementation)) = module.items()[1] else {
            panic!("expected implementation")
        };
        assert_eq!(implementation.associated_type_count(), 2);
        assert_eq!(implementation.associated_types()[0].unwrap().name, "Item");
        assert_eq!(
            implementation.associated_types()[0].unwrap().value.text,
            "u8"
        );
    }

    #[test]
    fn parses_trait_associated_type_defaults() {
        let source = "trait Value<T> { type SelfValue = Self; type Input = T; type Byte = u8; }";
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        let Some(Item::Trait(declaration)) = module.items()[0] else {
            panic!("expected trait")
        };
        assert_eq!(
            declaration.associated_types()[0]
                .unwrap()
                .default
                .unwrap()
                .text,
            "Self"
        );
        assert_eq!(
            declaration.associated_types()[1]
                .unwrap()
                .default
                .unwrap()
                .text,
            "T"
        );
        assert_eq!(
            declaration.associated_types()[2]
                .unwrap()
                .default
                .unwrap()
                .text,
            "u8"
        );
    }

    #[test]
    fn bounds_associated_types_and_rejects_unsupported_bounds() {
        let overflow = Parser::new(concat!(
            "trait Values { type T0; type T1; type T2; type T3; type T4; ",
            "type T5; type T6; type T7; type T8; }"
        ))
        .parse_module::<2, 1>()
        .unwrap_err();
        assert_eq!(overflow.kind, ParseErrorKind::TooManyAssociatedTypes);

        let bound = Parser::new("trait Values { type Item: Copy; }")
            .parse_module::<2, 1>()
            .unwrap_err();
        assert_eq!(bound.kind, ParseErrorKind::ExpectedSemicolon);
    }

    #[test]
    fn rejects_unsupported_trait_contents_and_attributes() {
        let body = Parser::new("trait Value { fn value(); }")
            .parse_module::<2, 2>()
            .unwrap_err();
        assert_eq!(body.kind, ParseErrorKind::UnsupportedTraitBody);

        let attributed = Parser::new("#[unsafe(no_mangle)] trait Value {}")
            .parse_module::<2, 2>()
            .unwrap_err();
        assert_eq!(attributed.kind, ParseErrorKind::ExpectedItem);
    }

    #[test]
    fn parses_empty_exact_trait_implementations() {
        let source = "trait Visible {} impl Visible for core::primitive::u32 { /* empty */ }";
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        let Some(Item::TraitImplementation(implementation)) = module.items()[1] else {
            panic!("expected trait implementation")
        };
        assert_eq!(implementation.trait_name, "Visible");
        assert_eq!(implementation.self_type.text, "core::primitive::u32");
        assert_eq!(
            &source[implementation.self_type.span.start..implementation.self_type.span.end],
            implementation.self_type.text
        );
    }

    #[test]
    fn parses_bounded_trait_parameters_and_concrete_arguments() {
        let source = concat!(
            "trait Convert<Input, Output> {} ",
            "impl Convert<u8, core::primitive::u16> for u32 {} ",
            "fn check() where u32: Convert<u8, u16> {}"
        );
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        let Some(Item::Trait(declaration)) = module.items()[0] else {
            panic!("expected trait")
        };
        assert_eq!(
            declaration.generic_parameters(),
            &[Some("Input"), Some("Output")]
        );
        let Some(Item::TraitImplementation(implementation)) = module.items()[1] else {
            panic!("expected implementation")
        };
        assert_eq!(implementation.trait_argument_count(), 2);
        assert_eq!(
            implementation.trait_arguments()[1].unwrap().text,
            "core::primitive::u16"
        );
    }

    #[test]
    fn parses_trait_parameter_defaults() {
        let source = "trait Convert<Input = u8, Output = core::primitive::u16> {}";
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        let Some(Item::Trait(declaration)) = module.items()[0] else {
            panic!("expected trait")
        };
        assert_eq!(
            declaration.generic_parameter_defaults()[0].unwrap().text,
            "u8"
        );
        assert_eq!(
            declaration.generic_parameter_defaults()[1].unwrap().text,
            "core::primitive::u16"
        );
    }

    #[test]
    fn parses_bounded_flat_generic_trait_implementations() {
        let source =
            "trait Identity<Input> { type Output; } impl<T> Identity<T> for T { type Output = T; }";
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        let Some(Item::TraitImplementation(implementation)) = module.items()[1] else {
            panic!("expected implementation")
        };
        assert_eq!(implementation.generic_parameters(), &[Some("T")]);
        assert_eq!(implementation.trait_arguments()[0].unwrap().text, "T");
        assert_eq!(implementation.self_type.text, "T");
        assert_eq!(
            implementation.associated_types()[0].unwrap().value.text,
            "T"
        );
    }

    #[test]
    fn desugars_implementation_parameter_bounds_into_premises() {
        let source = concat!(
            "trait Parent<T> {} trait Visible {} trait Child<T> {} ",
            "impl<T: Parent<T> + Visible> Child<T> for T {}"
        );
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        let Some(Item::TraitImplementation(implementation)) = module.items()[3] else {
            panic!("expected implementation")
        };
        assert_eq!(implementation.generic_parameters(), &[Some("T")]);
        assert_eq!(implementation.where_predicate_count(), 2);
        assert_eq!(
            implementation.where_predicates()[0].unwrap().trait_name(),
            "Parent"
        );
        assert_eq!(
            implementation.where_predicates()[1].unwrap().trait_name(),
            "Visible"
        );
    }

    #[test]
    fn desugars_associated_bindings_on_implementation_parameter_bounds() {
        let source = concat!(
            "trait Iterator { type Item; } trait Child<T> {} ",
            "impl<T: Iterator<Item = T>> Child<T> for T {}"
        );
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        let Some(Item::TraitImplementation(implementation)) = module.items()[2] else {
            panic!("expected implementation")
        };
        assert_eq!(implementation.where_predicate_count(), 2);
        assert!(matches!(
            implementation.where_predicates()[1],
            Some(TraitImplementationWherePredicate::ProjectionEquality {
                associated_type: "Item",
                expected_type: TypeRef { text: "T", .. },
                ..
            })
        ));
    }

    #[test]
    fn decomposes_projection_valued_associated_types() {
        let source = concat!(
            "trait Parent<T> { type Output; } trait Child<T> { type Output; } ",
            "impl<T> Child<T> for T { type Output = <T as Parent<T>>::Output; }"
        );
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        let Some(Item::TraitImplementation(implementation)) = module.items()[2] else {
            panic!("expected implementation")
        };
        let value = implementation.associated_types()[0].unwrap().value;
        let projection = value.parse_trait_projection().unwrap().unwrap();
        assert_eq!(projection.self_type.text, "T");
        assert_eq!(projection.trait_name, "Parent");
        assert_eq!(projection.trait_arguments()[0].unwrap().text, "T");
        assert_eq!(projection.associated_type, "Output");
        assert_eq!(
            &source[projection.self_type.span.start..projection.self_type.span.end],
            "T"
        );
    }

    #[test]
    fn parses_bounded_generic_implementation_premises() {
        let source = concat!(
            "trait Parent<T> {} trait Child<T> {} ",
            "impl<T> Child<T> for T where T: Parent<T>, T: Parent<u8>, ",
            "<T as Parent<T>>::Output = T, {}"
        );
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        let Some(Item::TraitImplementation(implementation)) = module.items()[2] else {
            panic!("expected implementation")
        };
        assert_eq!(implementation.where_predicate_count(), 3);
        assert_eq!(
            implementation.where_predicates()[0]
                .unwrap()
                .self_type()
                .text,
            "T"
        );
        assert_eq!(
            implementation.where_predicates()[0]
                .unwrap()
                .trait_arguments()[0]
                .unwrap()
                .text,
            "T"
        );
        assert!(matches!(
            implementation.where_predicates()[2].unwrap(),
            TraitImplementationWherePredicate::ProjectionEquality {
                associated_type: "Output",
                expected_type: TypeRef { text: "T", .. },
                ..
            }
        ));
    }

    #[test]
    fn parses_concrete_exact_implementation_premises() {
        let source = concat!(
            "trait Parent<T> {} trait Child<T> {} ",
            "impl Child<u32> for u32 where u32: Parent<u32> {}"
        );
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        let Some(Item::TraitImplementation(implementation)) = module.items()[2] else {
            panic!("expected implementation")
        };
        assert_eq!(implementation.generic_parameter_count(), 0);
        assert_eq!(implementation.where_predicate_count(), 1);
        assert_eq!(
            implementation.where_predicates()[0]
                .unwrap()
                .self_type()
                .text,
            "u32"
        );
    }

    #[test]
    fn rejects_unsupported_trait_implementation_forms() {
        let missing_for = Parser::new("impl Visible core::primitive::u32 {}")
            .parse_module::<3, 1>()
            .unwrap_err();
        assert_eq!(missing_for.kind, ParseErrorKind::ExpectedFor);

        let body = Parser::new("impl Visible for u32 { fn value() {} }")
            .parse_module::<3, 1>()
            .unwrap_err();
        assert_eq!(
            body.kind,
            ParseErrorKind::UnsupportedTraitImplementationBody
        );

        let public = Parser::new("pub impl Visible for u32 {}")
            .parse_module::<3, 1>()
            .unwrap_err();
        assert_eq!(public.kind, ParseErrorKind::ExpectedItem);
    }

    #[test]
    fn parses_bounded_concrete_function_where_predicates() {
        let source = "fn check() -> u32 where core::primitive::u32: Visible, u8: Small, { 1 }";
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(function.return_type.unwrap().text, "u32");
        assert_eq!(function.where_predicate_count(), 2);
        let first = function.where_predicates()[0].unwrap();
        assert!(matches!(
            first,
            FunctionWherePredicate::Implemented {
                self_type: TypeRef {
                    text: "core::primitive::u32",
                    ..
                },
                trait_name: "Visible",
                ..
            }
        ));
        assert!(matches!(
            function.where_predicates()[1].unwrap(),
            FunctionWherePredicate::Implemented {
                trait_name: "Small",
                ..
            }
        ));
    }

    #[test]
    fn parses_concrete_projection_equality_where_predicates() {
        let source =
            "fn check() where <core::primitive::u32 as Iterator>::Item = core::primitive::u8, { }";
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert!(matches!(
            function.where_predicates()[0].unwrap(),
            FunctionWherePredicate::ProjectionEquality {
                self_type: TypeRef {
                    text: "core::primitive::u32",
                    ..
                },
                trait_name: "Iterator",
                associated_type: "Item",
                expected_type: TypeRef {
                    text: "core::primitive::u8",
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn bounds_and_rejects_unsupported_function_where_predicates() {
        let overflow = Parser::new(concat!(
            "fn check() where T0: Trait, T1: Trait, T2: Trait, T3: Trait, ",
            "T4: Trait, T5: Trait, T6: Trait, T7: Trait, T8: Trait {}"
        ))
        .parse_module::<2, 1>()
        .unwrap_err();
        assert_eq!(overflow.kind, ParseErrorKind::TooManyWherePredicates);

        let compound = Parser::new("fn check() where u32: First + Second {}")
            .parse_module::<2, 1>()
            .unwrap_err();
        assert_eq!(compound.kind, ParseErrorKind::ExpectedBody);
    }

    #[test]
    fn parses_unsafe_function_qualifiers() {
        let source = "unsafe fn rust(input: *const u8) -> u8 { *input } #[unsafe(no_mangle)] pub unsafe extern \"C\" fn exported(input: *mut u16) { *input = 42; } const unsafe fn constant() -> u8 { 1 }";
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        let Some(Item::Function(rust)) = module.items()[0] else {
            panic!("expected function")
        };
        let Some(Item::Function(exported)) = module.items()[1] else {
            panic!("expected function")
        };
        let Some(Item::Function(constant)) = module.items()[2] else {
            panic!("expected function")
        };
        assert!(rust.unsafe_function);
        assert_eq!(rust.abi, FunctionAbi::Rust);
        assert!(exported.public);
        assert!(exported.unsafe_function);
        assert_eq!(exported.abi, FunctionAbi::C);
        assert!(exported.no_mangle);
        assert!(constant.constant);
        assert!(constant.unsafe_function);
    }

    #[test]
    fn parses_explicit_unmangled_c_exports() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn answer() -> u64 { 42 }";
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert!(function.public);
        assert_eq!(function.abi, FunctionAbi::C);
        assert!(function.no_mangle);
        assert_eq!(function.name, "answer");
    }

    #[test]
    fn parses_versioned_mrml_abi_export_facade() {
        let source =
            "#[mrml_abi::export(version = 1)] pub fn answer(input: &[u8]) -> u64 { 42 }";
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert!(function.public);
        assert_eq!(function.abi, FunctionAbi::MrmlV1);
        assert!(function.no_mangle);
        assert_eq!(function.name, "answer");
        assert_eq!(function.parameters()[0].unwrap().ty.text, "&[u8]");

        for source in [
            "#[mrml_abi::export(version = 2)] pub fn answer() {}",
            "#[mrml_abi::export(version = 1)] #[mrml_abi::export(version = 1)] pub fn answer() {}",
            "#[mrml_abi::export(version = 1)] fn answer() {}",
            "#[mrml_abi::export(version = 1)] pub const fn answer() {}",
            "#[mrml_abi::export(version = 1)] pub extern \"C\" fn answer() {}",
            "#[mrml_abi::unknown(version = 1)] pub fn answer() {}",
            "#[mrml_abi::export(revision = 1)] pub fn answer() {}",
        ] {
            let error = Parser::new(source).parse_module::<2, 2>().unwrap_err();
            assert!(matches!(
                error.kind,
                ParseErrorKind::UnsupportedAbi | ParseErrorKind::UnsupportedAttribute
            ));
        }
    }

    #[test]
    fn parses_bounded_naked_function_attributes() {
        let source = concat!(
            "#[unsafe(no_mangle)] #[unsafe(naked)] ",
            "pub unsafe extern \"C\" fn entry() { naked_asm!(\"ret\"); }"
        );
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert!(function.no_mangle);
        assert!(function.naked);
        assert!(function.unsafe_function);
        assert_eq!(function.abi, FunctionAbi::C);

        let duplicate =
            Parser::new("#[unsafe(naked)] #[unsafe(naked)] unsafe extern \"C\" fn entry() {}")
                .parse_module::<1, 1>()
                .unwrap_err();
        assert_eq!(duplicate.kind, ParseErrorKind::UnsupportedAttribute);
    }

    #[test]
    fn parses_const_rust_and_c_abi_functions() {
        let source = "const fn identity(value: usize) -> usize { return value; } #[unsafe(no_mangle)] pub const extern \"C\" fn exported(value: u8) -> u8 { value + 1 }";
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        let Some(Item::Function(identity)) = module.items()[0] else {
            panic!("expected function")
        };
        assert!(identity.constant);
        assert_eq!(identity.abi, FunctionAbi::Rust);
        let Some(Item::Function(exported)) = module.items()[1] else {
            panic!("expected function")
        };
        assert!(exported.constant);
        assert_eq!(exported.abi, FunctionAbi::C);
        assert!(exported.no_mangle);
    }

    #[test]
    fn rejects_unknown_attributes_and_abis() {
        let attribute = Parser::new("#[unsafe(export_name)] fn answer() {}")
            .parse_module::<2, 2>()
            .unwrap_err();
        assert_eq!(attribute.kind, ParseErrorKind::UnsupportedAttribute);
        let abi = Parser::new("extern \"system\" fn answer() {}")
            .parse_module::<2, 2>()
            .unwrap_err();
        assert_eq!(abi.kind, ParseErrorKind::UnsupportedAbi);
    }

    #[test]
    fn accepts_trailing_parameter_comma_and_nested_delimiters() {
        let module: TestModule<'_> =
            Parser::new("fn f(value: Option<(u8, u8)>,) { call([value]); }")
                .parse_module()
                .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            function.parameters()[0].unwrap().ty.text,
            "Option<(u8, u8)>"
        );
    }

    #[test]
    fn parses_and_evaluates_typed_constants() {
        let source = "pub const BUFFER_BYTES: usize = (4 * 1024) + 16; fn ready() {}";
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        assert_eq!(module.item_count(), 2);
        let Some(Item::Const(constant)) = module.items()[0] else {
            panic!("expected constant")
        };
        assert!(constant.public);
        assert_eq!(constant.name, "BUFFER_BYTES");
        assert_eq!(constant.ty.text, "usize");
        assert_eq!(constant.initializer, "(4 * 1024) + 16");
        assert_eq!(
            &source[constant.initializer_span.start..constant.initializer_span.end],
            constant.initializer
        );
        let expression = constant.parse_initializer::<16>().unwrap();
        assert_eq!(expression.evaluate(&crate::NoConstants), Ok(4112));
    }

    #[test]
    fn parses_immutable_static_initializers() {
        let source = "static SHIFTED: usize = 10_usize << 4_usize;";
        let module: TestModule<'_> = Parser::new(source).parse_module().unwrap();
        let Some(Item::Static(value)) = module.items()[0] else {
            panic!("expected static")
        };
        assert!(!value.public);
        assert_eq!(value.name, "SHIFTED");
        assert_eq!(value.ty.text, "usize");
        assert_eq!(
            value
                .parse_initializer::<8>()
                .unwrap()
                .evaluate(&crate::NoConstants),
            Ok(160)
        );
    }

    #[test]
    fn parses_typed_local_bindings_and_tail_expression() {
        let module: TestModule<'_> =
            Parser::new("fn arithmetic() -> usize { let x: usize = 15; let y: usize = 4; x / y }")
                .parse_module()
                .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        assert_eq!(body.local_count(), 2);
        let locals = body.locals();
        assert_eq!(locals[0].unwrap().name, "x");
        assert_eq!(locals[0].unwrap().ty.unwrap().text, "usize");
        assert_eq!(locals[0].unwrap().initializer, "15");
        assert_eq!(locals[1].unwrap().name, "y");
        assert_eq!(body.tail_expression, "x / y");
    }

    #[test]
    fn parses_explicitly_uninitialized_scalar_local() {
        let module: TestModule<'_> = Parser::new("fn probe() -> u64 { let value: u64; value }")
            .parse_module()
            .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<1>().unwrap();
        let local = body.locals()[0].unwrap();
        assert_eq!(local.name, "value");
        assert_eq!(local.ty.unwrap().text, "u64");
        assert!(!local.initialized);
        assert!(local.initializer.is_empty());
    }

    #[test]
    fn bounds_and_validates_typed_local_bindings() {
        let module: TestModule<'_> =
            Parser::new("fn bounded() { let x: usize = 1; let y: usize = 2; x }")
                .parse_module()
                .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            function.parse_body::<1>().unwrap_err().kind,
            ParseErrorKind::TooManyLocals
        );

        let implicit_unit: TestModule<'_> = Parser::new("fn empty() { let x: usize = 1; }")
            .parse_module()
            .unwrap();
        let Some(Item::Function(function)) = implicit_unit.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<1>().unwrap();
        assert!(body.implicit_unit);
        assert_eq!(body.tail_expression, "()");
        assert_eq!(body.tail_span.start, body.tail_span.end);

        let empty: TestModule<'_> = Parser::new("fn empty() {}").parse_module().unwrap();
        let Some(Item::Function(function)) = empty.items()[0] else {
            panic!("expected function")
        };
        assert!(function.parse_body::<1>().unwrap().implicit_unit);
    }

    #[test]
    fn parses_mutable_locals_and_assignment_statements() {
        let module: TestModule<'_> = Parser::new(
            "fn swaps() -> isize { let mut a: isize = 1; let mut b: isize = 2; a ^= b; b ^= a; a = a ^ b; a | b }",
        )
        .parse_module()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        assert!(body.locals()[0].unwrap().mutable);
        assert_eq!(body.assignment_count(), 3);
        assert_eq!(
            body.assignments()[0].unwrap().operator,
            AssignmentOperator::BitXor
        );
        assert_eq!(
            body.assignments()[2].unwrap().operator,
            AssignmentOperator::Assign
        );
        assert_eq!(body.assignments()[2].unwrap().value, "a ^ b");
        assert_eq!(body.tail_expression, "a | b");
    }

    #[test]
    fn parses_bounded_conditional_assignments_in_body_order() {
        let module = Parser::new(
            "fn choose(value: u8, select: bool) -> u8 { let mut result = value; if select { let mut selected: u8 = result; selected += 1; selected + 10; return selected; } else if value == 1 { result -= 1; result + value; result += 2; return result; } else if value == 2 { result = 42; } else { result *= 2; result == value; result += 1; return result; } if result == 0 { result = 42; } result }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        assert_eq!(body.conditional_assignment_count(), 2);
        let first = body.conditional_assignments()[0].unwrap();
        assert_eq!(first.branch_count(), 3);
        let first_branch = first.branches()[0].unwrap();
        assert_eq!(first_branch.condition, "select");
        assert_eq!(first_branch.action_count(), 4);
        let Some(ConditionalAssignmentAction::Local(first_local)) = first_branch.actions()[0]
        else {
            panic!("expected local")
        };
        assert_eq!(first_local.name, "selected");
        assert!(first_local.mutable);
        let Some(ConditionalAssignmentAction::Assignment(first_assignment)) =
            first_branch.actions()[1]
        else {
            panic!("expected assignment")
        };
        assert_eq!(first_assignment.operator, AssignmentOperator::Add);
        let Some(ConditionalAssignmentAction::Expression(expression)) = first_branch.actions()[2]
        else {
            panic!("expected expression")
        };
        assert_eq!(expression.expression, "selected + 10");
        let Some(ConditionalAssignmentAction::Return(return_statement)) = first_branch.actions()[3]
        else {
            panic!("expected return")
        };
        assert_eq!(return_statement.value, "selected");
        assert_eq!(first.branches()[1].unwrap().condition, "value == 1");
        let Some(ConditionalAssignmentAction::Assignment(assignment)) =
            first.branches()[1].unwrap().actions()[0]
        else {
            panic!("expected assignment")
        };
        assert_eq!(assignment.operator, AssignmentOperator::Subtract);
        assert_eq!(first.branches()[2].unwrap().condition, "value == 2");
        assert_eq!(first.else_action_count(), 4);
        let Some(ConditionalAssignmentAction::Assignment(assignment)) = first.else_actions()[0]
        else {
            panic!("expected assignment")
        };
        assert_eq!(assignment.operator, AssignmentOperator::Multiply);
        assert_eq!(
            body.conditional_assignments()[1]
                .unwrap()
                .else_action_count(),
            0
        );
        assert_eq!(body.statements()[0], Some(BodyStatement::Local(0)));
        assert_eq!(
            body.statements()[1],
            Some(BodyStatement::ConditionalAssignment(0))
        );

        let crowded = Parser::new(
            "fn crowded(value: u8) -> u8 { let mut result = value; if true { result = 0; } if true { result = 1; } if true { result = 2; } if true { result = 3; } if true { result = 4; } if true { result = 5; } if true { result = 6; } if true { result = 7; } if true { result = 8; } result }",
        )
        .parse_module::<2, 1>()
        .unwrap();
        let Some(Item::Function(function)) = crowded.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            function.parse_body::<1>().unwrap_err().kind,
            ParseErrorKind::TooManyConditionalAssignments
        );

        let too_many_branches = Parser::new(
            "fn crowded(value: u8) -> u8 { let mut result = value; if value == 0 { result = 0; } else if value == 1 { result = 1; } else if value == 2 { result = 2; } else if value == 3 { result = 3; } else if value == 4 { result = 4; } else { result = 5; } result }",
        )
        .parse_module::<2, 1>()
        .unwrap();
        let Some(Item::Function(function)) = too_many_branches.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            function.parse_body::<1>().unwrap_err().kind,
            ParseErrorKind::TooManyConditionalAssignmentBranches
        );

        let too_many_in_branch = Parser::new(
            "fn crowded(value: u8) -> u8 { let mut result = value; if true { result = 0; result = 1; result = 2; result = 3; result = 4; } result }",
        )
        .parse_module::<2, 1>()
        .unwrap();
        let Some(Item::Function(function)) = too_many_in_branch.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            function.parse_body::<1>().unwrap_err().kind,
            ParseErrorKind::TooManyConditionalBranchActions
        );
    }

    #[test]
    fn parses_indexed_assignment_targets() {
        let source = "fn mutate(index: usize) -> usize { let mut values = [1usize, 2]; values[  index + 1  ] += 3; values[0] }";
        let module = Parser::new(source).parse_module::<2, 2>().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        let assignment = body.assignments()[0].unwrap();
        assert_eq!(assignment.binding_name(), "values");
        assert_eq!(assignment.index(), Some("index + 1"));
        let index_start = function.body_expression.find("index + 1  ]").unwrap();
        assert_eq!(
            assignment.index_span(),
            Some(Span {
                start: index_start,
                end: index_start + "index + 1".len(),
            })
        );
        assert_eq!(assignment.name, "values");
        assert_eq!(
            assignment.projection,
            Some(AssignmentProjection::Index {
                expression: "index + 1",
                span: assignment.index_span().unwrap(),
            })
        );
        assert_eq!(assignment.operator, AssignmentOperator::Add);
        assert_eq!(assignment.value, "3");
    }

    #[test]
    fn parses_tuple_field_assignment_targets() {
        let module = Parser::new(
            "fn mutate(value: u16) -> u16 { let mut pair = (value, false); pair.0 += 3; pair.0 }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        let assignment = body.assignments()[0].unwrap();
        assert_eq!(assignment.binding_name(), "pair");
        assert_eq!(assignment.tuple_field(), Some(0));
        assert!(matches!(
            assignment.projection,
            Some(AssignmentProjection::TupleField { field: 0, .. })
        ));
        assert_eq!(assignment.operator, AssignmentOperator::Add);
        assert_eq!(assignment.value, "3");
    }

    #[test]
    fn parses_dereference_assignment_targets() {
        let module = Parser::new(
            "fn mutate(value: &mut u64) -> u64 { *value += 2; *value = *value + 1; *value }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        let compound = body.assignments()[0].unwrap();
        assert!(compound.dereferences());
        assert_eq!(compound.binding_name(), "value");
        assert_eq!(compound.operator, AssignmentOperator::Add);
        assert_eq!(compound.value, "2");
        let plain = body.assignments()[1].unwrap();
        assert!(plain.dereferences());
        assert_eq!(plain.binding_name(), "value");
        assert_eq!(plain.operator, AssignmentOperator::Assign);
        assert_eq!(plain.value, "*value + 1");
    }

    #[test]
    fn rejects_ambiguous_assignment_projections() {
        for source in [
            "fn bad() { let mut pair = (1u8, 2u8); pair.left = 3; }",
            "fn bad() { let mut pair = (1u8, 2u8); pair.00 = 3; }",
            "fn bad() { let mut pair = (1u8, 2u8); pair.0x0 = 3; }",
            "fn bad() { let mut pair = (1u8, 2u8); pair.0usize = 3; }",
        ] {
            let module = Parser::new(source).parse_module::<2, 1>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(
                function.parse_body::<2>().unwrap_err().kind,
                ParseErrorKind::ExpectedAssignmentTarget
            );
        }
    }

    #[test]
    fn parses_inferred_local_bindings() {
        let module = Parser::new("fn value() -> i32 { let mut x = 0; x += 1; x }")
            .parse_module::<2, 1>()
            .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        let local = body.locals()[0].unwrap();
        assert!(local.ty.is_none());
        assert!(local.mutable);
        assert_eq!(local.initializer, "0");
    }

    #[test]
    fn separates_conditional_returns_from_tail_if_expressions() {
        let module = Parser::new(
            "fn choose(value: u64, guard: bool) -> u64 { if guard { return value; } value + 1 }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        assert_eq!(body.conditional_return_count(), 1);
        let conditional = body.conditional_returns()[0].unwrap();
        assert_eq!(conditional.condition, "guard");
        assert_eq!(conditional.value, "value");
        assert_eq!(body.tail_expression, "value + 1");

        let tail_if = Parser::new(
            "fn choose(value: u64, guard: bool) -> u64 { if guard { value } else { value + 1 } }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = tail_if.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        assert_eq!(body.conditional_return_count(), 0);
        assert!(body.tail_expression.starts_with("if guard"));

        let guarded_local = Parser::new(
            "fn guarded(value: u64, stop: bool) -> u64 { if stop { return 7; } let adjusted: u64 = value + 1; adjusted * 2 }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = guarded_local.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        assert_eq!(
            body.statements()[0],
            Some(BodyStatement::ConditionalReturn(0))
        );
        assert_eq!(body.statements()[1], Some(BodyStatement::Local(0)));
        assert_eq!(body.locals()[0].unwrap().initializer, "value + 1");
        assert_eq!(body.tail_expression, "adjusted * 2");

        let guarded_assignment = Parser::new(
            "fn guarded(value: u64, stop: bool) -> u64 { let mut adjusted: u64 = value; if stop { return 7; } adjusted += 1; adjusted * 2 }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = guarded_assignment.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        assert_eq!(body.statements()[0], Some(BodyStatement::Local(0)));
        assert_eq!(
            body.statements()[1],
            Some(BodyStatement::ConditionalReturn(0))
        );
        assert_eq!(body.statements()[2], Some(BodyStatement::Assignment(0)));
        assert_eq!(
            body.assignments()[0].unwrap().operator,
            AssignmentOperator::Add
        );

        let guarded_loop = Parser::new(
            "fn fibonacci(n: u32) -> u32 { if n == 0 { return 0; } let mut previous: u32 = 0; let mut current: u32 = 1; let mut index: u32 = 1; while index < n { current += previous; previous = current - previous; index += 1; } current }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = guarded_loop.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        assert_eq!(
            body.statements()[0],
            Some(BodyStatement::ConditionalReturn(0))
        );
        assert_eq!(body.statements()[1], Some(BodyStatement::Local(0)));
        assert_eq!(body.statements()[2], Some(BodyStatement::Local(1)));
        assert_eq!(body.statements()[3], Some(BodyStatement::Local(2)));
        assert_eq!(body.statements()[4], Some(BodyStatement::Loop(0)));
        assert_eq!(body.while_loops()[0].unwrap().operation_count(), 3);

        let alternating_guards = Parser::new(
            "fn classify(value: u32, first: bool, second: bool) -> u32 { let mut result: u32 = value; if first { return 1; } result += 1; if second { return 2; } result *= 2; result }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = alternating_guards.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        assert_eq!(body.statements()[0], Some(BodyStatement::Local(0)));
        assert_eq!(
            body.statements()[1],
            Some(BodyStatement::ConditionalReturn(0))
        );
        assert_eq!(body.statements()[2], Some(BodyStatement::Assignment(0)));
        assert_eq!(
            body.statements()[3],
            Some(BodyStatement::ConditionalReturn(1))
        );
        assert_eq!(body.statements()[4], Some(BodyStatement::Assignment(1)));
    }

    #[test]
    fn parses_bounded_scalar_while_loops() {
        let module = Parser::new(
            "fn count(limit: u64) -> u64 { let mut i: u64 = 0; let mut total: u64 = 0; while i < limit { let current: u64 = i + 1; current + 10; total += current; i = current; if i == 10 { let marker: u64 = i; marker + 1; total += marker; break; } } total }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        assert_eq!(body.statement_count(), 3);
        assert!(core::mem::size_of::<BodyStatement>() <= 2 * core::mem::size_of::<usize>());
        assert_eq!(body.statements()[0], Some(BodyStatement::Local(0)));
        assert_eq!(body.statements()[1], Some(BodyStatement::Local(1)));
        assert_eq!(body.statements()[2], Some(BodyStatement::Loop(0)));
        assert_eq!(body.while_loop_count(), 1);
        let loop_statement = body.while_loops()[0].unwrap();
        assert_eq!(loop_statement.condition, Some("i < limit"));
        assert_eq!(loop_statement.assignment_count(), 3);
        assert_eq!(loop_statement.operation_count(), 5);
        let Some(LoopOperation::Local(current)) = loop_statement.operations()[0] else {
            panic!("expected loop local")
        };
        assert_eq!(current.name, "current");
        assert_eq!(current.initializer, "i + 1");
        let Some(LoopOperation::Expression(expression)) = loop_statement.operations()[1] else {
            panic!("expected loop expression")
        };
        assert_eq!(expression.expression, "current + 10");
        let Some(LoopOperation::Assignment(total)) = loop_statement.operations()[2] else {
            panic!("expected total assignment")
        };
        let Some(LoopOperation::Assignment(increment)) = loop_statement.operations()[3] else {
            panic!("expected increment assignment")
        };
        assert_eq!(total.name, "total");
        assert_eq!(increment.name, "i");
        assert_eq!(increment.operator, AssignmentOperator::Assign);
        assert_eq!(increment.value, "current");
        let Some(LoopOperation::ConditionalBlock(control_index)) = loop_statement.operations()[4]
        else {
            panic!("expected conditional block")
        };
        let control = loop_statement.conditional_blocks()[control_index].unwrap();
        assert_eq!(control.condition, "i == 10");
        assert_eq!(control.action_count(), 3);
        assert!(matches!(
            control.actions()[0],
            Some(ConditionalLoopAction::Local(local)) if local.name == "marker"
        ));
        assert!(matches!(
            control.actions()[1],
            Some(ConditionalLoopAction::Expression(expression))
                if expression.expression == "marker + 1"
        ));
        assert!(matches!(
            control.actions()[2],
            Some(ConditionalLoopAction::Assignment(assignment))
                if assignment.name == "total"
        ));
        assert_eq!(control.terminal, Some(ConditionalLoopTerminal::Break));
        assert_eq!(body.tail_expression, "total");

        let action_only = Parser::new(
            "fn guarded(limit: u64) -> u64 { let mut i: u64 = 0; let mut total: u64 = 0; while i < limit { i += 1; if i % 2 == 0 { let selected: u64 = i; total += selected; } else if i % 3 == 0 { let third: u64 = 3; total += third; } else { let fallback: u64 = 1; total += fallback; } total + 1; } total }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = action_only.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        let loop_statement = body.while_loops()[0].unwrap();
        let Some(LoopOperation::ConditionalBlock(index)) = loop_statement.operations()[1] else {
            panic!("expected action-only conditional block")
        };
        let block = loop_statement.conditional_blocks()[index].unwrap();
        assert_eq!(block.action_count(), 2);
        assert_eq!(block.terminal, None);
        let else_index = block.else_arm.expect("expected else arm");
        let else_arm = loop_statement.conditional_else_arms()[else_index].unwrap();
        assert_eq!(else_arm.action_count(), 2);
        assert_eq!(else_arm.terminal, None);
        assert_eq!(else_arm.condition, Some("i % 3 == 0"));
        assert_eq!(block.else_arm_count, 2);
        let final_arm = loop_statement.conditional_else_arms()[else_index + 1].unwrap();
        assert_eq!(final_arm.condition, None);

        let nested_unit = Parser::new(
            "fn nested(limit: u64) -> u64 { let mut i: u64 = 0; let mut total: u64 = 0; let mut inner: u64 = 0; while i < limit { loop { let selected: u64 = inner + 1; inner = selected; if selected % 2 == 0 { continue; } total += selected; if selected == 5 { break; } } i += 1; inner = 0; } total }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = nested_unit.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let loop_statement = body.while_loops()[0].unwrap();
        let Some(LoopOperation::NestedBlock(index)) = loop_statement.operations()[0] else {
            panic!("expected nested action block")
        };
        let nested = loop_statement.nested_blocks()[index].unwrap();
        assert_eq!(nested.action_count(), 3);
        assert_eq!(
            nested.conditional_breaks()[0]
                .expect("expected conditional break")
                .condition,
            "selected == 5"
        );
        assert_eq!(
            nested.conditional_continues()[0]
                .expect("expected conditional continue")
                .condition,
            "selected % 2 == 0"
        );
        assert_eq!(nested.conditional_continue_action_indices(), &[2]);

        let nested_return = Parser::new(
            "fn nested(limit: u64, stop: u64) { let mut outer: u64 = 0; let mut inner: u64 = 0; while outer < limit { while inner < 3 { inner += 1; if inner == stop { return; } } outer += 1; inner = 0; } }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = nested_return.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let outer = body.while_loops()[0].unwrap();
        let Some(LoopOperation::NestedBlock(index)) = outer.operations()[0] else {
            panic!("expected nested while block")
        };
        let inner = outer.nested_blocks()[index].unwrap();
        assert_eq!(
            inner.conditional_returns()[0]
                .expect("expected conditional return")
                .value,
            "()"
        );
        assert_eq!(inner.conditional_return_action_indices(), &[1]);

        let nested_branch_actions = Parser::new(
            "fn nested(limit: u64, stop: u64) -> u64 { let mut outer: u64 = 0; let mut inner: u64 = 0; while outer < limit { while inner < 3 { inner += 1; if inner == stop { let result: u64 = outer + inner; result + 1; return result; } } outer += 1; inner = 0; } outer }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = nested_branch_actions.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let outer = body.while_loops()[0].unwrap();
        let Some(LoopOperation::NestedBlock(index)) = outer.operations()[0] else {
            panic!("expected nested while block")
        };
        let inner = outer.nested_blocks()[index].unwrap();
        let branch = inner.conditional_blocks()[0].unwrap();
        assert_eq!(branch.condition, "inner == stop");
        assert_eq!(branch.action_count(), 2);
        assert!(matches!(
            branch.actions()[0],
            Some(ConditionalLoopAction::Local(local)) if local.name == "result"
        ));
        assert!(matches!(
            branch.actions()[1],
            Some(ConditionalLoopAction::Expression(expression))
                if expression.expression == "result + 1"
        ));
        assert!(matches!(
            branch.terminal,
            NestedLoopUnconditionalControl::Return(LoopReturn {
                value: "result",
                ..
            })
        ));
        assert_eq!(inner.conditional_block_action_indices(), &[1]);
        assert_eq!(inner.conditional_block_control_orders(), &[0]);

        let nested_branch_else = Parser::new(
            "fn nested(limit: u64, stop: u64) -> u64 { let mut outer: u64 = 0; let mut inner: u64 = 0; while outer < limit { loop { if inner == stop { let result: u64 = outer + inner; return result; } else { inner += 1; continue; } } } outer }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = nested_branch_else.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let outer = body.while_loops()[0].unwrap();
        let Some(LoopOperation::NestedBlock(index)) = outer.operations()[0] else {
            panic!("expected nested loop block")
        };
        let inner = outer.nested_blocks()[index].unwrap();
        let branch = inner.conditional_blocks()[0].unwrap();
        let else_arm = branch.else_arm().expect("expected nested else arm");
        assert_eq!(branch.action_count(), 1);
        assert_eq!(else_arm.action_count(), 1);
        assert!(matches!(
            else_arm.actions()[0],
            Some(ConditionalLoopAction::Assignment(assignment))
                if assignment.binding_name() == "inner"
        ));
        assert_eq!(
            else_arm.terminal,
            NestedLoopUnconditionalControl::Continue(NestedLoopControlTarget::Inner)
        );

        let nested_branch_else_if = Parser::new(
            "fn nested(primary: bool, alternative: bool) -> u8 { loop { loop { if primary { return 40; } else if alternative { let result: u8 = 50; return result; } } } }",
        )
        .parse_module::<1, 2>()
        .unwrap();
        let Some(Item::Function(function)) = nested_branch_else_if.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        let outer = body.while_loops()[0].unwrap();
        let Some(LoopOperation::NestedBlock(index)) = outer.operations()[0] else {
            panic!("expected nested loop block")
        };
        let branch = outer.nested_blocks()[index].unwrap().conditional_blocks()[0].unwrap();
        let else_if = branch.else_arm().expect("expected nested else-if arm");
        assert_eq!(else_if.condition(), Some("alternative"));
        assert!(else_if.condition_span().end > else_if.condition_span().start);
        assert_eq!(else_if.action_count(), 1);
        assert!(matches!(
            else_if.terminal,
            NestedLoopUnconditionalControl::Return(LoopReturn {
                value: "result",
                ..
            })
        ));

        let nested_branch_chain = Parser::new(
            "fn nested(primary: bool, first: bool, second: bool) -> u8 { loop { loop { if primary { return 40; } else if first { return 50; } else if second { return 60; } else { return 70; } } } }",
        )
        .parse_module::<1, 4>()
        .unwrap();
        let Some(Item::Function(function)) = nested_branch_chain.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let outer = body.while_loops()[0].unwrap();
        let Some(LoopOperation::NestedBlock(index)) = outer.operations()[0] else {
            panic!("expected nested loop block")
        };
        let branch = outer.nested_blocks()[index].unwrap().conditional_blocks()[0].unwrap();
        assert_eq!(branch.else_arm_count(), 3);
        let arms = branch.else_arms();
        assert_eq!(arms[0].unwrap().condition(), Some("first"));
        assert_eq!(arms[1].unwrap().condition(), Some("second"));
        assert_eq!(arms[2].unwrap().condition(), None);

        let multiple_returns = Parser::new(
            "fn nested(limit: u64, first: u64, second: u64) -> u64 { let mut outer: u64 = 0; let mut inner: u64 = 0; while outer < limit { while inner < 3 { inner += 1; if inner == first { return 40; } if inner == second { return 50; } } outer += 1; inner = 0; } outer }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = multiple_returns.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let outer = body.while_loops()[0].unwrap();
        let Some(LoopOperation::NestedBlock(index)) = outer.operations()[0] else {
            panic!("expected nested while block")
        };
        let inner = outer.nested_blocks()[index].unwrap();
        assert_eq!(inner.conditional_returns().len(), 2);
        assert_eq!(inner.conditional_returns()[0].unwrap().value, "40");
        assert_eq!(inner.conditional_returns()[1].unwrap().value, "50");
        assert_eq!(inner.conditional_return_action_indices(), &[1, 1]);
        assert_eq!(inner.conditional_return_control_orders(), &[0, 1]);

        let continue_before_return = Parser::new(
            "fn nested(limit: u64, skip: u64, stop: u64) -> u64 { let mut outer: u64 = 0; let mut inner: u64 = 0; while outer < limit { while inner < 3 { inner += 1; if inner == skip { continue; } if inner == stop { return outer + 40; } } outer += 1; inner = 0; } outer }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = continue_before_return.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let outer = body.while_loops()[0].unwrap();
        let Some(LoopOperation::NestedBlock(index)) = outer.operations()[0] else {
            panic!("expected nested while block")
        };
        let inner = outer.nested_blocks()[index].unwrap();
        assert_eq!(inner.conditional_continue_action_indices(), &[1]);
        assert_eq!(inner.conditional_continue_control_orders(), &[0]);
        assert_eq!(inner.conditional_return_action_indices(), &[1]);
        assert_eq!(inner.conditional_return_control_orders(), &[1]);

        let multiple_continues = Parser::new(
            "fn nested(limit: u64, first: u64, second: u64) -> u64 { let mut outer: u64 = 0; let mut inner: u64 = 0; while outer < limit { while inner < 4 { inner += 1; if inner == first { continue; } if inner == second { continue; } } outer += 1; inner = 0; } outer }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = multiple_continues.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let outer = body.while_loops()[0].unwrap();
        let Some(LoopOperation::NestedBlock(index)) = outer.operations()[0] else {
            panic!("expected nested while block")
        };
        let inner = outer.nested_blocks()[index].unwrap();
        assert_eq!(inner.conditional_continues().len(), 2);
        assert_eq!(inner.conditional_continue_action_indices(), &[1, 1]);
        assert_eq!(inner.conditional_continue_control_orders(), &[0, 1]);

        let unconditional_continue = Parser::new(
            "fn nested(limit: u64) -> u64 { let mut outer: u64 = 0; let mut inner: u64 = 0; while outer < limit { while inner < 3 { let selected: u64 = inner + 1; inner = selected; continue; let unreachable: u64 = selected + 10; unreachable; } outer += 1; inner = 0; } outer }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = unconditional_continue.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let outer = body.while_loops()[0].unwrap();
        let Some(LoopOperation::NestedBlock(index)) = outer.operations()[0] else {
            panic!("expected nested while block")
        };
        let inner = outer.nested_blocks()[index].unwrap();
        assert_eq!(
            inner.unconditional_controls(),
            &[Some(NestedLoopUnconditionalControl::Continue(
                NestedLoopControlTarget::Inner
            ))]
        );
        assert_eq!(inner.unconditional_control_action_indices(), &[2]);
        assert_eq!(inner.action_count(), 4);

        let conditional_only_loop = Parser::new(
            "fn nested(enter: bool, stop: u64) -> u64 { let mut inner: u64 = 0; while enter { loop { inner += 1; if inner < stop { continue; } if inner == stop { return inner; } } } 0 }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = conditional_only_loop.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let outer = body.while_loops()[0].unwrap();
        let Some(LoopOperation::NestedBlock(index)) = outer.operations()[0] else {
            panic!("expected nested loop block")
        };
        let inner = outer.nested_blocks()[index].unwrap();
        assert!(inner.entry_condition.is_none());
        assert_eq!(inner.conditional_continues().len(), 1);
        assert_eq!(inner.conditional_returns().len(), 1);
        assert!(inner.unconditional_controls().is_empty());

        for (source, expected_actions) in [
            (
                "fn nested(enter: bool) -> u64 { while enter { loop {} } 42 }",
                0,
            ),
            (
                "fn nested(enter: bool) -> u64 { while enter { loop { 1; } } 42 }",
                1,
            ),
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<2>().unwrap();
            let outer = body.while_loops()[0].unwrap();
            let Some(LoopOperation::NestedBlock(index)) = outer.operations()[0] else {
                panic!("expected diverging nested block")
            };
            let inner = outer.nested_blocks()[index].unwrap();
            assert_eq!(inner.action_count(), expected_actions);
            assert!(inner.unconditional_controls().is_empty());
            assert!(inner.conditional_breaks().is_empty());
        }

        let crowded_unconditional = Parser::new(
            "fn nested() { loop { loop { break; continue; return; break; continue; } } }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = crowded_unconditional.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            function.parse_body::<4>().unwrap_err().kind,
            ParseErrorKind::TooManyNestedLoopUnconditionalControls
        );

        let crowded_continues = Parser::new(
            "fn nested(a: bool, b: bool, c: bool, d: bool) { loop { loop { if a { continue; } if b { continue; } if c { continue; } if d { continue; } if true { continue; } } } }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = crowded_continues.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            function.parse_body::<4>().unwrap_err().kind,
            ParseErrorKind::TooManyNestedLoopConditionalContinues
        );

        let multiple_breaks = Parser::new(
            "fn nested(limit: u64, first: u64, second: u64) -> u64 { let mut outer: u64 = 0; let mut inner: u64 = 0; let mut total: u64 = 0; while outer < limit { while inner < 5 { inner += 1; if inner == first { break; } total += inner; if inner == second { break; } } outer += 1; inner = 0; } total }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = multiple_breaks.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let outer = body.while_loops()[0].unwrap();
        let Some(LoopOperation::NestedBlock(index)) = outer.operations()[0] else {
            panic!("expected nested while block")
        };
        let inner = outer.nested_blocks()[index].unwrap();
        assert_eq!(inner.conditional_breaks().len(), 2);
        assert_eq!(inner.conditional_break_action_indices(), &[1, 2]);
        assert_eq!(inner.conditional_break_control_orders(), &[0, 1]);

        let crowded_breaks = Parser::new(
            "fn nested(a: bool, b: bool, c: bool, d: bool) { loop { loop { if a { break; } if b { break; } if c { break; } if d { break; } if true { break; } } } }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = crowded_breaks.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            function.parse_body::<4>().unwrap_err().kind,
            ParseErrorKind::TooManyNestedLoopConditionalBreaks
        );

        let crowded_returns = Parser::new(
            "fn nested(a: bool, b: bool, c: bool, d: bool) -> u64 { loop { loop { if a { return 1; } if b { return 2; } if c { return 3; } if d { return 4; } if true { return 5; } } } }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = crowded_returns.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            function.parse_body::<4>().unwrap_err().kind,
            ParseErrorKind::TooManyNestedLoopConditionalReturns
        );

        let nested_while = Parser::new(
            "fn nested(limit: u64) -> u64 { let mut outer: u64 = 0; let mut inner: u64 = 0; let mut total: u64 = 0; while outer < limit { while inner < 3 { inner += 1; total += inner; } outer += 1; inner = 0; } total }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = nested_while.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let outer = body.while_loops()[0].unwrap();
        let Some(LoopOperation::NestedBlock(index)) = outer.operations()[0] else {
            panic!("expected nested while block")
        };
        let inner = outer.nested_blocks()[index].unwrap();
        assert_eq!(
            inner
                .entry_condition
                .expect("expected while condition")
                .condition,
            "inner < 3"
        );
        assert!(inner.conditional_breaks().is_empty());
        assert!(matches!(
            loop_statement.operations()[1],
            Some(LoopOperation::Assignment(_))
        ));

        for (source, expected) in [
            (
                "fn crowded() { loop { loop { 1; 2; 3; 4; 5; break; } break; } }",
                ParseErrorKind::TooManyNestedLoopActions,
            ),
            (
                "fn crowded() { loop { loop { 1; break; } loop { 2; break; } loop { 3; break; } loop { 4; break; } loop { 5; break; } break; } }",
                ParseErrorKind::TooManyNestedLoopBlocks,
            ),
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            assert_eq!(function.parse_body::<2>().unwrap_err().kind, expected);
        }

        let too_many_conditional_actions = Parser::new(
            "fn crowded(limit: u64) -> u64 { let mut i: u64 = 0; while i < limit { i += 1; if i == limit { i + 1; i + 2; i + 3; i + 4; i + 5; break; } } i }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = too_many_conditional_actions.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            function.parse_body::<2>().unwrap_err().kind,
            ParseErrorKind::TooManyConditionalLoopActions
        );

        let too_many_else_arms = Parser::new(
            "fn crowded() -> u64 { loop { if true { 1; } else { 2; } if true { 3; } else { 4; } if true { 5; } else { 6; } if true { 7; } else { 8; } if true { 9; } else { 10; } break; } 0 }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = too_many_else_arms.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            function.parse_body::<2>().unwrap_err().kind,
            ParseErrorKind::TooManyConditionalLoopElseArms
        );

        let post_loop = Parser::new(
            "fn staged(limit: u64) -> u64 { let mut value: u64 = 0; while value < limit { value += 1; } value *= 2; value }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = post_loop.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        assert_eq!(body.statements()[0], Some(BodyStatement::Local(0)));
        assert_eq!(body.statements()[1], Some(BodyStatement::Loop(0)));
        assert_eq!(body.statements()[2], Some(BodyStatement::Assignment(0)));
        assert_eq!(
            body.assignments()[0].unwrap().operator,
            AssignmentOperator::Multiply
        );

        let post_loop_return = Parser::new(
            "fn classify(limit: u64) -> u64 { let mut value: u64 = 0; while value < limit { value += 1; } if value == 42 { return 7; } value += 1; value }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = post_loop_return.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        assert_eq!(body.statements()[0], Some(BodyStatement::Local(0)));
        assert_eq!(body.statements()[1], Some(BodyStatement::Loop(0)));
        assert_eq!(
            body.statements()[2],
            Some(BodyStatement::ConditionalReturn(0))
        );
        assert_eq!(body.statements()[3], Some(BodyStatement::Assignment(0)));

        let post_loop_guards = Parser::new(
            "fn classify(value: u32, limit: u32, first: bool, second: bool) -> u32 { let mut index: u32 = 0; let mut result: u32 = value; while index < limit { index += 1; } if first && index == limit { return 1; } result += 1; if second && index == limit { return 2; } result *= 2; result }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = post_loop_guards.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        assert_eq!(body.statements()[0], Some(BodyStatement::Local(0)));
        assert_eq!(body.statements()[1], Some(BodyStatement::Local(1)));
        assert_eq!(body.statements()[2], Some(BodyStatement::Loop(0)));
        assert_eq!(
            body.statements()[3],
            Some(BodyStatement::ConditionalReturn(0))
        );
        assert_eq!(body.statements()[4], Some(BodyStatement::Assignment(0)));
        assert_eq!(
            body.statements()[5],
            Some(BodyStatement::ConditionalReturn(1))
        );
        assert_eq!(body.statements()[6], Some(BodyStatement::Assignment(1)));

        let sequential_loops = Parser::new(
            "fn traverse(first: u64, second: u64) -> u64 { let mut value: u64 = 0; while value < first { value += 1; } while value < second { value += 1; } value }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = sequential_loops.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        assert_eq!(body.while_loop_count(), 2);
        assert_eq!(body.statements()[0], Some(BodyStatement::Local(0)));
        assert_eq!(body.statements()[1], Some(BodyStatement::Loop(0)));
        assert_eq!(body.statements()[2], Some(BodyStatement::Loop(1)));
        assert_eq!(
            body.while_loops()[0].unwrap().condition,
            Some("value < first")
        );
        assert_eq!(
            body.while_loops()[1].unwrap().condition,
            Some("value < second")
        );

        let post_loop_local = Parser::new(
            "fn finish(limit: u64) -> u64 { let mut value: u64 = 0; while value < limit { value += 1; } let offset: u64 = value + 2; offset * 2 }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = post_loop_local.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        assert_eq!(body.statements()[0], Some(BodyStatement::Local(0)));
        assert_eq!(body.statements()[1], Some(BodyStatement::Loop(0)));
        assert_eq!(body.statements()[2], Some(BodyStatement::Local(1)));
        assert_eq!(body.locals()[1].unwrap().initializer, "value + 2");
        assert_eq!(body.tail_expression, "offset * 2");

        let unconditional = Parser::new(
            "fn once() -> u64 { let mut value: u64 = 0; loop { value += 1; if value == 1 { break; } } value }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = unconditional.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        let loop_statement = body.while_loops()[0].unwrap();
        assert_eq!(loop_statement.condition, None);
        assert!(matches!(
            loop_statement.operations()[1],
            Some(LoopOperation::ConditionalBreak(control)) if control.condition == "value == 1"
        ));

        let returning = Parser::new(
            "fn classify(value: u64) -> bool { loop { if value == 42 { return true; } if value != 42 { return false; } } false }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = returning.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        let loop_statement = body.while_loops()[0].unwrap();
        assert!(matches!(
            loop_statement.operations()[0],
            Some(LoopOperation::ConditionalReturn(value))
                if value.condition == "value == 42" && value.value == "true"
        ));

        let immediate_return = Parser::new("fn answer() -> u64 { loop { return 42; } }")
            .parse_module::<2, 1>()
            .unwrap();
        let Some(Item::Function(function)) = immediate_return.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<1>().unwrap();
        assert!(body.tail_diverges);
        assert!(!body.implicit_unit);
        assert_eq!(body.tail_expression, "");
        assert!(matches!(
            body.while_loops()[0].unwrap().operations()[0],
            Some(LoopOperation::Return(value)) if value.value == "42"
        ));

        let controls = Parser::new(
            "fn controls(limit: u64) -> u64 { let mut value: u64 = 0; while value < limit { value += 1; continue; } loop { break; } value }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = controls.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        assert!(matches!(
            body.while_loops()[0].unwrap().operations()[1],
            Some(LoopOperation::Continue)
        ));
        assert!(matches!(
            body.while_loops()[1].unwrap().operations()[0],
            Some(LoopOperation::Break)
        ));

        let oversized = Parser::new(
            "fn too_many(limit: u64) -> u64 { let mut i: u64 = 0; while i < limit { i += 1; i += 1; i += 1; i += 1; i += 1; } i }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = oversized.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            function.parse_body::<2>().unwrap_err().kind,
            ParseErrorKind::TooManyLoopAssignments
        );

        let too_many_operations = Parser::new(
            "fn crowded() -> u64 { loop { if true { continue; } if true { continue; } if true { continue; } if true { continue; } if true { continue; } if true { continue; } if true { continue; } if true { continue; } break; } 0 }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = too_many_operations.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            function.parse_body::<2>().unwrap_err().kind,
            ParseErrorKind::TooManyLoopOperations
        );
    }

    #[test]
    fn parses_empty_while_and_diverging_loop_bodies() {
        let empty_while = Parser::new("fn probe(enter: bool) -> u64 { while enter {} 42 }")
            .parse_module::<2, 2>()
            .unwrap();
        let Some(Item::Function(function)) = empty_while.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        assert_eq!(body.while_loops()[0].unwrap().operation_count(), 0);
        assert_eq!(body.tail_expression, "42");
        assert!(!body.tail_diverges);

        for source in [
            "fn spin() -> u64 { loop {} }",
            "fn spin() -> u64 { loop { 1; } }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let body = function.parse_body::<2>().unwrap();
            assert!(body.tail_diverges);
            assert_eq!(body.tail_expression, "");
            assert_eq!(
                body.while_loops()[0].unwrap().operation_count(),
                usize::from(source.contains("1;"))
            );
        }
    }

    #[test]
    fn parses_matching_labels_on_statement_loop_controls() {
        let module = Parser::new(
            "fn sum(limit: u64, stop: u64) -> u64 { let mut i: u64 = 0; let mut total: u64 = 0; 'count: while i < limit { i += 1; if i % 2 == 0 { continue 'count; } else if i == stop { break 'count; } total += i; } 'once: loop { break 'once; } total }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        assert_eq!(body.while_loop_count(), 2);
        assert_eq!(body.while_loops()[0].unwrap().label, Some("'count"));
        assert_eq!(body.while_loops()[1].unwrap().label, Some("'once"));

        for source in [
            "fn bad() { 'outer loop { break 'missing; } }",
            "fn bad() { 'outer: loop { continue 'missing; } }",
            "fn bad() { 'outer: loop { if true { break 'missing; } } }",
        ] {
            let module = Parser::new(source).parse_module::<2, 2>().unwrap();
            let Some(Item::Function(function)) = module.items()[0] else {
                panic!("expected function")
            };
            let error = function.parse_body::<2>().unwrap_err();
            assert!(matches!(
                error.kind,
                ParseErrorKind::ExpectedColon | ParseErrorKind::UnknownLoopLabel
            ));
        }
    }

    #[test]
    fn resolves_inner_and_outer_targets_in_labeled_nested_loops() {
        let module = Parser::new(
            "fn sum(limit: u64) -> u64 { let mut outer: u64 = 0; let mut total: u64 = 0; 'outer: while outer < limit { outer += 1; 'inner: loop { let selected: u64 = outer; if selected == 0 { continue 'inner; } if selected % 2 == 0 { continue 'outer; } if selected == 5 { break 'outer; } break 'inner; } total += outer; } total }",
        )
        .parse_module::<2, 4>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<4>().unwrap();
        let outer = body.while_loops()[0].unwrap();
        assert_eq!(outer.label, Some("'outer"));
        let Some(LoopOperation::NestedBlock(index)) = outer.operations()[1] else {
            panic!("expected nested labeled loop")
        };
        let inner = outer.nested_blocks()[index].unwrap();
        assert_eq!(inner.label, Some("'inner"));
        assert_eq!(
            inner.conditional_continue_targets(),
            &[
                NestedLoopControlTarget::Inner,
                NestedLoopControlTarget::Outer
            ]
        );
        assert_eq!(
            inner.conditional_break_targets(),
            &[NestedLoopControlTarget::Outer]
        );
        assert_eq!(
            inner.unconditional_controls(),
            &[Some(NestedLoopUnconditionalControl::Break(
                NestedLoopControlTarget::Inner
            ))]
        );

        let shadowed = Parser::new(
            "fn shadow(enter: bool) -> u64 { 'same: while enter { 'same: loop { break 'same; } break 'same; } 42 }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = shadowed.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        let outer = body.while_loops()[0].unwrap();
        let Some(LoopOperation::NestedUnitLoop) = outer.operations()[0] else {
            panic!("expected shadowed label to target the inner loop")
        };

        let unknown = Parser::new(
            "fn bad(enter: bool) { 'outer: while enter { 'inner: loop { break 'missing; } } }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = unknown.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            function.parse_body::<2>().unwrap_err().kind,
            ParseErrorKind::UnknownLoopLabel
        );
    }

    #[test]
    fn const_types_and_initializers_preserve_nested_delimiters() {
        let module: TestModule<'_> = Parser::new("const VALUE: Option<[u8; 4]> = (1 + (2 * 3));")
            .parse_module()
            .unwrap();
        let Some(Item::Const(constant)) = module.items()[0] else {
            panic!("expected constant")
        };
        assert_eq!(constant.ty.text, "Option<[u8; 4]>");
        assert_eq!(
            constant
                .parse_initializer::<16>()
                .unwrap()
                .evaluate(&crate::NoConstants),
            Ok(7)
        );
    }

    #[test]
    fn rejects_empty_unterminated_and_mismatched_const_initializers() {
        let empty = Parser::new("const VALUE: usize = ;")
            .parse_module::<2, 2>()
            .unwrap_err();
        assert_eq!(empty.kind, ParseErrorKind::ExpectedInitializer);
        let unterminated = Parser::new("const VALUE: usize = 1")
            .parse_module::<2, 2>()
            .unwrap_err();
        assert_eq!(unterminated.kind, ParseErrorKind::ExpectedSemicolon);
        let mismatched = Parser::new("const VALUE: usize = (1];")
            .parse_module::<2, 2>()
            .unwrap_err();
        assert_eq!(mismatched.kind, ParseErrorKind::UnexpectedClosingDelimiter);
    }

    #[test]
    fn rejects_mismatched_and_unterminated_bodies() {
        let mismatch = Parser::new("fn f() { (] }")
            .parse_module::<2, 2>()
            .unwrap_err();
        assert_eq!(mismatch.kind, ParseErrorKind::UnexpectedClosingDelimiter);
        let unterminated = Parser::new("fn f() {").parse_module::<2, 2>().unwrap_err();
        assert_eq!(unterminated.kind, ParseErrorKind::UnterminatedDelimiter);
    }

    #[test]
    fn rejects_body_nesting_beyond_the_fixed_limit() {
        let source = "fn f() {((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((x))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))}";
        let error = Parser::new(source).parse_module::<2, 2>().unwrap_err();
        assert_eq!(error.kind, ParseErrorKind::NestingLimitExceeded);
        assert!(error.span.start < source.len());
    }

    #[test]
    fn preserves_bounded_expression_statements_in_body_order() {
        let module = Parser::new(
            "fn probe(value: u32) -> u32 { ; value + 1; let next = value + 2; next; value + 3 }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        assert_eq!(body.statements()[0], Some(BodyStatement::Expression(0)));
        assert_eq!(body.statements()[1], Some(BodyStatement::Expression(1)));
        assert_eq!(body.statements()[2], Some(BodyStatement::Local(0)));
        assert_eq!(body.statements()[3], Some(BodyStatement::Expression(2)));
        assert_eq!(body.expression_statements()[0].unwrap().expression, "");
        assert_eq!(
            body.expression_statements()[1].unwrap().expression,
            "value + 1"
        );
        assert_eq!(body.expression_statements()[2].unwrap().expression, "next");
        assert_eq!(body.tail_expression, "value + 3");

        let crowded = Parser::new("fn crowded() -> u32 { 0; 1; 2; 3; 4; 5; 6; 7; 8; 42 }")
            .parse_module::<2, 1>()
            .unwrap();
        let Some(Item::Function(function)) = crowded.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            function.parse_body::<1>().unwrap_err().kind,
            ParseErrorKind::TooManyExpressionStatements
        );
    }

    #[test]
    fn preserves_scoped_unsafe_expression_statements() {
        let module =
            Parser::new("fn probe() -> u32 { unsafe { asm!(\"pause\"); } unsafe { 40 + 2; }; 42 }")
                .parse_module::<2, 2>()
                .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        assert_eq!(body.expression_statement_count(), 2);
        assert_eq!(
            body.expression_statements()[0].unwrap().expression,
            "asm!(\"pause\")"
        );
        assert!(body.expression_statements()[0].unwrap().unsafe_context);
        assert_eq!(
            body.expression_statements()[1].unwrap().expression,
            "40 + 2"
        );
        assert!(body.expression_statements()[1].unwrap().unsafe_context);
        assert_eq!(body.tail_expression, "42");
    }

    #[test]
    fn preserves_bounded_early_returns_in_body_order() {
        let module = Parser::new(
            "fn probe(value: u32) -> u32 { let adjusted = value + 1; return adjusted; let unreachable = value + 2; unreachable }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        assert_eq!(body.return_count(), 1);
        assert_eq!(body.returns()[0].unwrap().value, "adjusted");
        assert_eq!(body.statements()[0], Some(BodyStatement::Local(0)));
        assert_eq!(body.statements()[1], Some(BodyStatement::Return(0)));
        assert_eq!(body.statements()[2], Some(BodyStatement::Local(1)));
        assert!(!body.tail_diverges);

        let unit =
            Parser::new("fn stop(flag: bool) { if flag { return; } loop { if flag { return; } } }")
                .parse_module::<2, 2>()
                .unwrap();
        let Some(Item::Function(function)) = unit.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        assert_eq!(body.conditional_returns()[0].unwrap().value, "()");
        assert!(matches!(
            body.while_loops()[0].unwrap().operations()[0],
            Some(LoopOperation::ConditionalReturn(value)) if value.value == "()"
        ));

        let unit = Parser::new("fn stop() { return; let unreachable = (); unreachable }")
            .parse_module::<2, 1>()
            .unwrap();
        let Some(Item::Function(function)) = unit.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<1>().unwrap();
        assert_eq!(body.returns()[0].unwrap().value, "()");

        let module = Parser::new(
            "fn probe() -> u8 { return 0; return 1; return 2; return 3; return 4; return 5; return 6; return 7; return 8; }",
        )
        .parse_module::<2, 1>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            function.parse_body::<1>().unwrap_err().kind,
            ParseErrorKind::TooManyReturns
        );
    }

    #[test]
    fn parses_bounded_exhaustive_conditional_returns() {
        let module = Parser::new(
            "fn choose(value: u32, select: bool) -> u32 { let adjusted = value + 1; if select { return adjusted; } else { return value; } }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        assert_eq!(body.conditional_return_else_count(), 1);
        let conditional = body.conditional_return_elses()[0].unwrap();
        assert_eq!(conditional.branch_count(), 1);
        assert_eq!(conditional.branches()[0].unwrap().condition, "select");
        assert_eq!(conditional.branches()[0].unwrap().value, "adjusted");
        assert_eq!(conditional.else_value.unwrap().value, "value");
        assert_eq!(
            body.statements()[1],
            Some(BodyStatement::ConditionalReturnElse(0))
        );
        assert!(body.tail_diverges);

        let chain = Parser::new(
            "fn choose(value: u8) -> u8 { if value == 0 { return 10; } else if value == 1 { return 20; } else if value == 2 { return 30; } else { return 40; } }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = chain.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        let conditional = body.conditional_return_elses()[0].unwrap();
        assert_eq!(conditional.branch_count(), 3);
        assert_eq!(conditional.branches()[1].unwrap().condition, "value == 1");
        assert_eq!(conditional.branches()[2].unwrap().value, "30");
        assert_eq!(conditional.else_value.unwrap().value, "40");

        let fallthrough = Parser::new(
            "fn choose(value: u8) -> u8 { if value == 0 { return 42; } else if value == 1 { return 42 / value; } 84 / value }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = fallthrough.items()[0] else {
            panic!("expected function")
        };
        let body = function.parse_body::<2>().unwrap();
        let conditional = body.conditional_return_elses()[0].unwrap();
        assert_eq!(conditional.branch_count(), 2);
        assert!(conditional.else_value.is_none());
        assert_eq!(body.tail_expression, "84 / value");
        assert!(!body.tail_diverges);

        let crowded = Parser::new(
            "fn choose(first: bool, second: bool) -> u8 { if first { return 1; } else { return 2; } if second { return 3; } else { return 4; } }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = crowded.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            function.parse_body::<1>().unwrap_err().kind,
            ParseErrorKind::TooManyLocals
        );

        let crowded = Parser::new(
            "fn choose(value: u8) -> u8 { if value == 0 { return 0; } else if value == 1 { return 1; } else if value == 2 { return 2; } else if value == 3 { return 3; } else if value == 4 { return 4; } else { return 5; } }",
        )
        .parse_module::<2, 2>()
        .unwrap();
        let Some(Item::Function(function)) = crowded.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            function.parse_body::<2>().unwrap_err().kind,
            ParseErrorKind::TooManyConditionalReturnBranches
        );
    }

    #[test]
    fn enforces_item_and_parameter_capacity() {
        let items = Parser::new("fn a() {} fn b() {}")
            .parse_module::<1, 1>()
            .unwrap_err();
        assert_eq!(items.kind, ParseErrorKind::TooManyItems);
        let parameters = Parser::new("fn a(a: u8, b: u8) {}")
            .parse_module::<1, 1>()
            .unwrap_err();
        assert_eq!(parameters.kind, ParseErrorKind::TooManyParameters);
    }

    #[test]
    fn locates_unsupported_struct_and_enum_headers() {
        for (source, kind, header) in [
            (
                "struct Point;",
                ParseErrorKind::UnsupportedStructDeclaration,
                "struct Point",
            ),
            (
                "pub struct Pair(u8, u8);",
                ParseErrorKind::UnsupportedStructDeclaration,
                "struct Pair",
            ),
            (
                "struct Point { x: u8 }",
                ParseErrorKind::UnsupportedStructDeclaration,
                "struct Point",
            ),
            (
                "fn start() {}\r\npub enum Color { Red, Green }",
                ParseErrorKind::UnsupportedEnumDeclaration,
                "enum Color",
            ),
            (
                "enum Shape<T> where T: Copy { Circle(T) }",
                ParseErrorKind::UnsupportedEnumDeclaration,
                "enum Shape",
            ),
        ] {
            let error = Parser::new(source).parse_module::<2, 2>().unwrap_err();
            assert_eq!(error.kind, kind);
            assert_eq!(&source[error.span.start..error.span.end], header);
        }
    }

    #[test]
    fn locates_missing_struct_and_enum_names_or_bodies() {
        for (source, kind, offending_token) in [
            ("struct { x: u8 }", ParseErrorKind::ExpectedStructName, "{"),
            ("enum 42 { Red }", ParseErrorKind::ExpectedEnumName, "42"),
            ("struct Point = 1;", ParseErrorKind::ExpectedStructBody, "="),
            ("enum Color;", ParseErrorKind::ExpectedEnumBody, ";"),
        ] {
            let error = Parser::new(source).parse_module::<2, 2>().unwrap_err();
            assert_eq!(error.kind, kind);
            assert_eq!(&source[error.span.start..error.span.end], offending_token);
        }
        let source = "struct Point\n";
        let error = Parser::new(source).parse_module::<2, 2>().unwrap_err();
        assert_eq!(error.kind, ParseErrorKind::ExpectedStructBody);
        assert_eq!(error.span, Span { start: 12, end: 12 });
    }

    #[test]
    fn rejects_non_items_and_missing_types() {
        let item = Parser::new("use module::Value;")
            .parse_module::<2, 2>()
            .unwrap_err();
        assert_eq!(item.kind, ParseErrorKind::ExpectedItem);
        let ty = Parser::new("fn f(value:) {}")
            .parse_module::<2, 2>()
            .unwrap_err();
        assert_eq!(ty.kind, ParseErrorKind::ExpectedType);
    }
}
