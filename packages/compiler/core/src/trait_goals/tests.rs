#[cfg(test)]
mod tests {
    use super::*;
    use crate::Parser;

    #[test]
    fn lowers_source_trait_declarations_to_stable_bounded_identities() {
        let source = "trait First {} const VALUE: u8 = 1; pub trait Second {}";
        let module = Parser::new(source).parse_module::<4, 2>().unwrap();
        let table = SourceTraitDeclarationTable::from_module(&module).unwrap();
        assert_eq!(table.len(), 2);
        let first = table.get("First").unwrap();
        let second = table.get("Second").unwrap();
        assert_eq!(first.id, TraitId::new(0));
        assert_eq!(second.id, TraitId::new(1));
        assert!(!first.public);
        assert!(second.public);
        assert_eq!(
            &source[second.name_span.start..second.name_span.end],
            "Second"
        );
    }

    #[test]
    fn source_trait_identity_admission_rejects_duplicates_and_overflow() {
        let duplicate = Parser::new("trait Same {} trait Same {}")
            .parse_module::<65, 1>()
            .unwrap();
        assert_eq!(
            SourceTraitDeclarationTable::from_module(&duplicate),
            Err(SourceTraitDeclarationError::DuplicateName)
        );

        let source = concat!(
            "trait T00 {} trait T01 {} trait T02 {} trait T03 {} trait T04 {} ",
            "trait T05 {} trait T06 {} trait T07 {} trait T08 {} trait T09 {} ",
            "trait T10 {} trait T11 {} trait T12 {} trait T13 {} trait T14 {} ",
            "trait T15 {} trait T16 {} trait T17 {} trait T18 {} trait T19 {} ",
            "trait T20 {} trait T21 {} trait T22 {} trait T23 {} trait T24 {} ",
            "trait T25 {} trait T26 {} trait T27 {} trait T28 {} trait T29 {} ",
            "trait T30 {} trait T31 {} trait T32 {} trait T33 {} trait T34 {} ",
            "trait T35 {} trait T36 {} trait T37 {} trait T38 {} trait T39 {} ",
            "trait T40 {} trait T41 {} trait T42 {} trait T43 {} trait T44 {} ",
            "trait T45 {} trait T46 {} trait T47 {} trait T48 {} trait T49 {} ",
            "trait T50 {} trait T51 {} trait T52 {} trait T53 {} trait T54 {} ",
            "trait T55 {} trait T56 {} trait T57 {} trait T58 {} trait T59 {} ",
            "trait T60 {} trait T61 {} trait T62 {} trait T63 {} trait T64 {}",
        );
        let overflow = Parser::new(source).parse_module::<65, 1>().unwrap();
        assert_eq!(
            SourceTraitDeclarationTable::from_module(&overflow),
            Err(SourceTraitDeclarationError::TooManyDeclarations)
        );
    }

    #[test]
    fn resolves_forward_supertraits_and_rejects_invalid_graphs() {
        let module = Parser::new("trait Child: Parent {} trait Parent {}")
            .parse_module::<4, 1>()
            .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let child = traits.get("Child").unwrap();
        assert_eq!(child.supertrait_count(), 1);
        assert_eq!(
            child.supertraits()[0].unwrap().trait_id,
            traits.get("Parent").unwrap().id
        );

        let unknown = Parser::new("trait Child: Missing {}")
            .parse_module::<2, 1>()
            .unwrap();
        assert_eq!(
            SourceTraitDeclarationTable::from_module(&unknown),
            Err(SourceTraitDeclarationError::UnknownSupertrait)
        );

        let duplicate = Parser::new("trait Child: Parent + Parent {} trait Parent {}")
            .parse_module::<3, 1>()
            .unwrap();
        assert_eq!(
            SourceTraitDeclarationTable::from_module(&duplicate),
            Err(SourceTraitDeclarationError::DuplicateSupertrait)
        );

        let distinct = Parser::new("trait Child: Parent<u8> + Parent<u16> {} trait Parent<T> {}")
            .parse_module::<3, 1>()
            .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&distinct).unwrap();
        assert_eq!(traits.get("Child").unwrap().supertrait_count(), 2);

        let duplicate_instantiation =
            Parser::new("trait Child: Parent<u8> + Parent<u8> {} trait Parent<T> {}")
                .parse_module::<3, 1>()
                .unwrap();
        assert_eq!(
            SourceTraitDeclarationTable::from_module(&duplicate_instantiation),
            Err(SourceTraitDeclarationError::DuplicateSupertrait)
        );

        let cyclic = Parser::new("trait First: Second {} trait Second: First {}")
            .parse_module::<3, 1>()
            .unwrap();
        assert_eq!(
            SourceTraitDeclarationTable::from_module(&cyclic),
            Err(SourceTraitDeclarationError::CyclicSupertrait)
        );

        let parameterized = Parser::new("trait Child<T>: Parent<T> {} trait Parent<T> {}")
            .parse_module::<3, 1>()
            .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&parameterized).unwrap();
        let child = traits.get("Child").unwrap();
        assert_eq!(
            child.supertraits()[0].unwrap().arguments(),
            &[Some(SourceTraitSupertraitArgument::Parameter(0))]
        );

        let wrong_arity = Parser::new("trait Child<T>: Parent {} trait Parent<T> {}")
            .parse_module::<3, 1>()
            .unwrap();
        assert_eq!(
            SourceTraitDeclarationTable::from_module(&wrong_arity),
            Err(SourceTraitDeclarationError::WrongSupertraitArgumentCount)
        );

        let concrete = Parser::new("trait Child<T>: Parent<u8> {} trait Parent<T> {}")
            .parse_module::<3, 1>()
            .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&concrete).unwrap();
        assert!(matches!(
            traits.get("Child").unwrap().supertraits()[0]
                .unwrap()
                .arguments()[0],
            Some(SourceTraitSupertraitArgument::Concrete(TypeRef {
                text: "u8",
                ..
            }))
        ));

        let self_argument = Parser::new("trait Child: Parent<Self> {} trait Parent<T> {}")
            .parse_module::<3, 1>()
            .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&self_argument).unwrap();
        assert_eq!(
            traits.get("Child").unwrap().supertraits()[0]
                .unwrap()
                .arguments(),
            &[Some(SourceTraitSupertraitArgument::SelfType)]
        );

        let compound = Parser::new("trait Child<T>: Parent<Vec<T>> {} trait Parent<T> {}")
            .parse_module::<3, 1>()
            .unwrap();
        assert_eq!(
            SourceTraitDeclarationTable::from_module(&compound),
            Err(SourceTraitDeclarationError::UnsupportedSupertraitArgument)
        );
    }

    #[test]
    fn lowers_exact_source_trait_implementations_into_solver_facts() {
        let source = concat!(
            "trait Visible {} trait Persisted {} ",
            "impl Visible for core::primitive::u32 {} ",
            "impl Persisted for core::primitive::u32 {}"
        );
        let module = Parser::new(source).parse_module::<8, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        assert_eq!(implementations.types().len(), 1);
        let self_type = implementations.get_type("core::primitive::u32").unwrap().id;
        let goal = canonicalize_implemented_trait_goal(ImplementedTraitGoal::new(
            traits.get("Visible").unwrap().id,
            TraitGoalType::Concrete(self_type),
        ))
        .unwrap();
        assert!(matches!(
            implementations.implementations().solve(goal),
            TraitGoalSolution::Unique(_)
        ));
    }

    #[test]
    fn lowers_bounded_concrete_source_trait_arguments() {
        let source = concat!(
            "trait Convert<Input> { type Output; } ",
            "impl Convert<u8> for u32 { type Output = u16; } ",
            "impl Convert<u16> for u32 { type Output = u32; } ",
            "fn check() where u32: Convert<u8>, <u32 as Convert<u8>>::Output = u16 {}"
        );
        let module = Parser::new(source).parse_module::<8, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();

        let wrong_arity = Parser::new("trait Convert<T> {} impl Convert for u32 {}")
            .parse_module::<4, 1>()
            .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&wrong_arity).unwrap();
        assert_eq!(
            SourceTraitImplementationTable::from_module(&wrong_arity, &traits)
                .unwrap_err()
                .kind,
            SourceTraitImplementationErrorKind::WrongTraitArgumentCount
        );

        let duplicate = Parser::new("trait Convert<T, T> {}")
            .parse_module::<2, 1>()
            .unwrap();
        assert_eq!(
            SourceTraitDeclarationTable::from_module(&duplicate),
            Err(SourceTraitDeclarationError::DuplicateGenericParameter)
        );
    }

    #[test]
    fn materializes_trailing_source_trait_defaults() {
        let exact = concat!(
            "trait Convert<Input = u8> { type Output; } ",
            "impl Convert for u32 { type Output = u16; } ",
            "fn check() where u32: Convert, <u32 as Convert>::Output = u16 {}"
        );
        let module = Parser::new(exact).parse_module::<8, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        assert_eq!(
            traits
                .get("Convert")
                .unwrap()
                .required_generic_parameter_count(),
            0
        );
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();

        let dependent = concat!(
            "trait Pair<T = u8, U = T> { type Output = U; } ",
            "impl Pair for u32 {} impl Pair<u16> for u16 {} ",
            "fn check() where u32: Pair, <u32 as Pair>::Output = u8, ",
            "u16: Pair<u16>, <u16 as Pair<u16>>::Output = u16 {}"
        );
        let module = Parser::new(dependent).parse_module::<12, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();

        let generic = concat!(
            "trait Parent<Input = u8> {} trait Child: Parent {} ",
            "impl<T> Parent for T {} impl<T> Child for T {} ",
            "fn check() where u32: Child, u32: Parent {}"
        );
        let module = Parser::new(generic).parse_module::<10, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();

        let self_default = concat!(
            "trait Identity<T = Self> { type Output = T; } ",
            "trait Child: Identity {} impl<T> Identity for T {} impl<T> Child for T {} ",
            "fn check() where u32: Child, u32: Identity, ",
            "<u32 as Identity>::Output = u32 {}"
        );
        let module = Parser::new(self_default).parse_module::<12, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();

        let invalid = |source| {
            let module = Parser::new(source).parse_module::<3, 1>().unwrap();
            SourceTraitDeclarationTable::from_module(&module).unwrap_err()
        };
        assert_eq!(
            invalid("trait Bad<T = u8, U> {}"),
            SourceTraitDeclarationError::NonTrailingGenericParameterDefault
        );
        assert_eq!(
            invalid("trait Bad<T = U, U = u8> {}"),
            SourceTraitDeclarationError::UnsupportedGenericParameterDefault
        );

        let duplicate_declaration = Parser::new(concat!(
            "trait Parent<T = u8, U = T> {} ",
            "trait Child where Self: Parent, Self: Parent<u8, u8> {}"
        ))
        .parse_module::<4, 1>()
        .unwrap();
        assert_eq!(
            SourceTraitDeclarationTable::from_module(&duplicate_declaration),
            Err(SourceTraitDeclarationError::DuplicateRequirement)
        );

        let duplicate_implementation = Parser::new(concat!(
            "trait Parent<T = u8, U = T> {} trait Child {} ",
            "impl<T> Child for T where T: Parent, T: Parent<u8, u8> {}"
        ))
        .parse_module::<6, 1>()
        .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&duplicate_implementation).unwrap();
        assert_eq!(
            SourceTraitImplementationTable::from_module(&duplicate_implementation, &traits)
                .unwrap_err()
                .kind,
            SourceTraitImplementationErrorKind::DuplicatePremise
        );
    }

    #[test]
    fn lowers_flat_generic_source_implementations_and_values() {
        let source = concat!(
            "trait Identity<Input> { type Output; } ",
            "impl<T> Identity<T> for T { type Output = T; } ",
            "fn check() where u32: Identity<u32>, ",
            "<u8 as Identity<u8>>::Output = u8 {}"
        );
        let module = Parser::new(source).parse_module::<8, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();

        let overlap = Parser::new(concat!(
            "trait Identity<Input> {} ",
            "impl Identity<u32> for u32 {} impl<T> Identity<T> for T {}"
        ))
        .parse_module::<6, 1>()
        .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&overlap).unwrap();
        assert_eq!(
            SourceTraitImplementationTable::from_module(&overlap, &traits)
                .unwrap_err()
                .kind,
            SourceTraitImplementationErrorKind::Goal(
                TraitGoalError::OverlappingExactAndGenericImplementation
            )
        );

        let unconstrained = Parser::new("trait Identity<Input> {} impl<T> Identity<u8> for u32 {}")
            .parse_module::<4, 1>()
            .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&unconstrained).unwrap();
        assert_eq!(
            SourceTraitImplementationTable::from_module(&unconstrained, &traits)
                .unwrap_err()
                .kind,
            SourceTraitImplementationErrorKind::UnconstrainedGenericParameter
        );
    }

    #[test]
    fn proves_bounded_generic_source_implementation_premises() {
        let satisfied = concat!(
            "trait Parent<Input> {} trait Child<Input> { type Output; } ",
            "impl Parent<u32> for u32 {} ",
            "impl<T> Child<T> for T where T: Parent<T> { type Output = T; } ",
            "fn check() where u32: Child<u32>, <u32 as Child<u32>>::Output = u32 {}"
        );
        let module = Parser::new(satisfied).parse_module::<10, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();

        let missing = satisfied.replace("u32: Child<u32>", "u8: Child<u8>");
        let module = Parser::new(&missing).parse_module::<10, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        assert_eq!(
            implementations
                .prove_module(&module, &traits)
                .unwrap_err()
                .kind,
            SourceTraitObligationErrorKind::Unsatisfied
        );

        let duplicate = Parser::new(concat!(
            "trait Parent<T> {} trait Child<T> {} ",
            "impl<T> Child<T> for T where T: Parent<T>, T: Parent<T> {}"
        ))
        .parse_module::<6, 1>()
        .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&duplicate).unwrap();
        assert_eq!(
            SourceTraitImplementationTable::from_module(&duplicate, &traits)
                .unwrap_err()
                .kind,
            SourceTraitImplementationErrorKind::DuplicatePremise
        );
    }

    #[test]
    fn proves_source_implementation_parameter_bounds() {
        let source = concat!(
            "trait Parent<T> {} trait Child<T> {} ",
            "impl<T> Parent<T> for T {} impl<T: Parent<T>> Child<T> for T {} ",
            "fn check() where u32: Child<u32> {}"
        );
        let module = Parser::new(source).parse_module::<8, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();

        let missing = source.replace("impl<T> Parent<T> for T {} ", "");
        let module = Parser::new(&missing).parse_module::<8, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        assert_eq!(
            implementations
                .prove_module(&module, &traits)
                .unwrap_err()
                .kind,
            SourceTraitObligationErrorKind::Unsatisfied
        );

        let duplicate = Parser::new(concat!(
            "trait Parent<T> {} trait Child<T> {} ",
            "impl<T: Parent<T>> Child<T> for T where T: Parent<T> {}"
        ))
        .parse_module::<6, 1>()
        .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&duplicate).unwrap();
        assert_eq!(
            SourceTraitImplementationTable::from_module(&duplicate, &traits)
                .unwrap_err()
                .kind,
            SourceTraitImplementationErrorKind::DuplicatePremise
        );
    }

    #[test]
    fn proves_trait_declaration_where_requirements() {
        let generic = concat!(
            "trait Parent<T> {} trait Child<T> where T: Parent<T> {} ",
            "impl<T> Parent<T> for T {} impl<T> Child<T> for T {} ",
            "fn check() where u32: Child<u32> {}"
        );
        let module = Parser::new(generic).parse_module::<10, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();

        let missing = generic.replace("impl<T> Parent<T> for T {} ", "");
        let module = Parser::new(&missing).parse_module::<10, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        assert_eq!(
            implementations
                .prove_module(&module, &traits)
                .unwrap_err()
                .kind,
            SourceTraitObligationErrorKind::Unsatisfied
        );

        let projection = concat!(
            "trait Parent<T> { type Output; } ",
            "trait Child<T> where <T as Parent<T>>::Output = T {} ",
            "impl<T> Parent<T> for T { type Output = T; } impl<T> Child<T> for T {} ",
            "fn check() where u32: Child<u32> {}"
        );
        let module = Parser::new(projection).parse_module::<10, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();

        let mismatch = projection.replace("type Output = T", "type Output = u8");
        let module = Parser::new(&mismatch).parse_module::<10, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        assert_eq!(
            implementations
                .prove_module(&module, &traits)
                .unwrap_err()
                .kind,
            SourceTraitObligationErrorKind::Unsatisfied
        );

        let exact = concat!(
            "trait Gate<T> {} trait Child where Self: Gate<u8> {} ",
            "impl Gate<u8> for u32 {} impl Child for u32 {} ",
            "fn check() where u32: Child {}"
        );
        let module = Parser::new(exact).parse_module::<8, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();

        let missing = exact.replace("impl Gate<u8> for u32 {} ", "");
        let module = Parser::new(&missing).parse_module::<8, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        assert_eq!(
            implementations
                .prove_module(&module, &traits)
                .unwrap_err()
                .kind,
            SourceTraitObligationErrorKind::Unsatisfied
        );
    }

    #[test]
    fn resolves_forward_associated_types_in_declaration_requirements() {
        let source = concat!(
            "trait Child<T> where <T as Parent<T>>::Output = T {} ",
            "trait Parent<T> { type Output; } ",
            "impl<T> Parent<T> for T { type Output = T; } impl<T> Child<T> for T {} ",
            "fn check() where u32: Child<u32> {}"
        );
        let module = Parser::new(source).parse_module::<10, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();
    }

    #[test]
    fn trait_declaration_where_requirements_fail_closed() {
        let error = |source| {
            let module = Parser::new(source).parse_module::<6, 1>().unwrap();
            SourceTraitDeclarationTable::from_module(&module).unwrap_err()
        };
        assert_eq!(
            error("trait Child where Self: Missing {}"),
            SourceTraitDeclarationError::UnknownRequirementTrait
        );
        assert_eq!(
            error("trait Parent<T> {} trait Child where Self: Parent {}"),
            SourceTraitDeclarationError::WrongRequirementArgumentCount
        );
        assert_eq!(
            error("trait Parent<T> {} trait Child<T> where Vec<T>: Parent<T> {}"),
            SourceTraitDeclarationError::UnsupportedRequirementType
        );
        assert_eq!(
            error("trait Parent {} trait Child where Self: Parent, Self: Parent {}"),
            SourceTraitDeclarationError::DuplicateRequirement
        );
        assert_eq!(
            error(concat!(
                "trait Parent { type Output; } ",
                "trait Child where <Self as Parent>::Missing = u8 {}"
            )),
            SourceTraitDeclarationError::UnknownRequirementAssociatedType
        );
    }

    #[test]
    fn proves_trait_declaration_parameter_bounds() {
        let source = concat!(
            "trait Parent<T> {} trait Visible {} ",
            "trait Child<T: Parent<T> + Visible> {} ",
            "impl<T> Parent<T> for T {} impl<T> Visible for T {} ",
            "impl<T> Child<T> for T {} fn check() where u32: Child<u32> {}"
        );
        let module = Parser::new(source).parse_module::<10, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();

        let missing = source.replace("impl<T> Visible for T {} ", "");
        let module = Parser::new(&missing).parse_module::<10, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        assert_eq!(
            implementations
                .prove_module(&module, &traits)
                .unwrap_err()
                .kind,
            SourceTraitObligationErrorKind::Unsatisfied
        );

        let duplicate = Parser::new(concat!(
            "trait Parent<T> {} trait Child<T: Parent<T>> where T: Parent<T> {}"
        ))
        .parse_module::<4, 1>()
        .unwrap();
        assert_eq!(
            SourceTraitDeclarationTable::from_module(&duplicate),
            Err(SourceTraitDeclarationError::DuplicateRequirement)
        );
    }

    #[test]
    fn proves_associated_bindings_on_source_parameter_bounds() {
        let declaration_bound = concat!(
            "trait Iterator { type Item; } trait Child<T: Iterator<Item = T>> {} ",
            "impl<T> Iterator for T { type Item = T; } impl<T> Child<T> for T {} ",
            "fn check() where u32: Child<u32> {}"
        );
        let module = Parser::new(declaration_bound)
            .parse_module::<10, 1>()
            .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();

        let implementation_bound = concat!(
            "trait Iterator { type Item; } trait Child<T> {} ",
            "impl<T> Iterator for T { type Item = T; } ",
            "impl<T: Iterator<Item = T>> Child<T> for T {} ",
            "fn check() where u32: Child<u32> {}"
        );
        let module = Parser::new(implementation_bound)
            .parse_module::<10, 1>()
            .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();

        let mismatch = implementation_bound.replace("type Item = T", "type Item = u8");
        let module = Parser::new(&mismatch).parse_module::<10, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        assert_eq!(
            implementations
                .prove_module(&module, &traits)
                .unwrap_err()
                .kind,
            SourceTraitObligationErrorKind::Unsatisfied
        );

        let mixed = concat!(
            "trait Parent<Input> { type Output; } trait Child<T> {} ",
            "impl<T> Parent<u8> for T { type Output = T; } ",
            "impl<T: Parent<u8, Output = T>> Child<T> for T {} ",
            "fn check() where u32: Child<u32> {}"
        );
        let module = Parser::new(mixed).parse_module::<10, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();
    }

    #[test]
    fn proves_associated_bindings_in_explicit_source_where_clauses() {
        let source = concat!(
            "trait Parent<Input> { type Output; } ",
            "trait Child<T> where T: Parent<u8, Output = T> {} ",
            "impl<T> Parent<u8> for T { type Output = T; } impl<T> Child<T> for T {} ",
            "fn check() where u32: Child<u32> {}"
        );
        let module = Parser::new(source).parse_module::<10, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();

        let implementation = concat!(
            "trait Parent<Input> { type Output; } trait Child<T> {} ",
            "impl<T> Parent<u8> for T { type Output = T; } ",
            "impl<T> Child<T> for T where T: Parent<u8, Output = T> {} ",
            "fn check() where u32: Child<u32> {}"
        );
        let module = Parser::new(implementation).parse_module::<10, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();
    }

    #[test]
    fn proves_inherited_source_supertrait_premises() {
        let satisfied = concat!(
            "trait Parent {} trait Child<Input>: Parent {} ",
            "impl Parent for u32 {} impl<T> Child<T> for T {} ",
            "fn check() where u32: Child<u32> {}"
        );
        let module = Parser::new(satisfied).parse_module::<10, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();

        let missing = satisfied.replace("impl Parent for u32 {} ", "");
        let module = Parser::new(&missing).parse_module::<10, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        assert_eq!(
            implementations
                .prove_module(&module, &traits)
                .unwrap_err()
                .kind,
            SourceTraitObligationErrorKind::Unsatisfied
        );

        let conditional = concat!(
            "trait Parent {} trait Gate {} trait Child: Parent {} ",
            "impl Parent for u32 {} impl Gate for u32 {} ",
            "impl Child for u32 where u32: Gate {} ",
            "fn check() where u32: Child {}"
        );
        let module = Parser::new(conditional).parse_module::<10, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();

        let duplicate_explicit = satisfied.replace(
            "impl<T> Child<T> for T {}",
            "impl<T> Child<T> for T where T: Parent {}",
        );
        let module = Parser::new(&duplicate_explicit)
            .parse_module::<10, 1>()
            .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();
    }

    #[test]
    fn proves_generic_source_projection_equality_premises() {
        let satisfied = concat!(
            "trait Parent<Input> { type Output; } trait Child<Input> {} ",
            "impl Parent<u32> for u32 { type Output = u8; } ",
            "impl<T> Child<T> for T where <T as Parent<T>>::Output = u8 {} ",
            "fn check() where u32: Child<u32> {}"
        );
        let module = Parser::new(satisfied).parse_module::<10, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();

        let mismatch = satisfied.replace("::Output = u8 {}", "::Output = u16 {}");
        let module = Parser::new(&mismatch).parse_module::<10, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        assert_eq!(
            implementations
                .prove_module(&module, &traits)
                .unwrap_err()
                .kind,
            SourceTraitObligationErrorKind::Unsatisfied
        );
    }

    #[test]
    fn proves_premise_bearing_exact_source_implementations() {
        let satisfied = concat!(
            "trait Parent<Input> {} trait Child<Input> { type Output; } ",
            "impl Parent<u32> for u32 {} ",
            "impl Child<u32> for u32 where u32: Parent<u32> { type Output = u8; } ",
            "fn check() where u32: Child<u32>, <u32 as Child<u32>>::Output = u8 {}"
        );
        let module = Parser::new(satisfied).parse_module::<10, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();

        let missing = satisfied.replace("impl Parent<u32> for u32 {} ", "");
        let module = Parser::new(&missing).parse_module::<10, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        assert_eq!(
            implementations
                .prove_module(&module, &traits)
                .unwrap_err()
                .kind,
            SourceTraitObligationErrorKind::Unsatisfied
        );

        let overlap = Parser::new(concat!(
            "trait Parent<T> {} trait Child<T> {} ",
            "impl Child<u32> for u32 {} ",
            "impl Child<u32> for u32 where u32: Parent<u32> {}"
        ))
        .parse_module::<8, 1>()
        .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&overlap).unwrap();
        assert_eq!(
            SourceTraitImplementationTable::from_module(&overlap, &traits)
                .unwrap_err()
                .kind,
            SourceTraitImplementationErrorKind::Goal(
                TraitGoalError::OverlappingExactAndGenericImplementation
            )
        );
    }

    #[test]
    fn normalizes_projection_valued_generic_source_associated_types() {
        let satisfied = concat!(
            "trait Parent<Input> { type Output; } trait Child<Input> { type Output; } ",
            "impl<T> Parent<T> for T { type Output = T; } ",
            "impl<T> Child<T> for T { type Output = <T as Parent<T>>::Output; } ",
            "fn check() where u32: Child<u32>, <u32 as Child<u32>>::Output = u32 {}"
        );
        let module = Parser::new(satisfied).parse_module::<10, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();

        let missing = satisfied.replace("impl<T> Parent<T> for T { type Output = T; } ", "");
        let module = Parser::new(&missing).parse_module::<10, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        assert_eq!(
            implementations
                .prove_module(&module, &traits)
                .unwrap_err()
                .kind,
            SourceTraitObligationErrorKind::Unsatisfied
        );

        let exact_source = concat!(
            "trait Parent { type Output; } trait Child { type Output; } ",
            "impl Parent for u32 { type Output = u8; } ",
            "impl Child for u32 { type Output = <u32 as Parent>::Output; } ",
            "fn check() where <u32 as Child>::Output = u8 {}"
        );
        let exact = Parser::new(exact_source).parse_module::<8, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&exact).unwrap();
        let implementations = SourceTraitImplementationTable::from_module(&exact, &traits).unwrap();
        implementations.prove_module(&exact, &traits).unwrap();
    }

    #[test]
    fn applies_and_overrides_source_associated_type_defaults() {
        let source = concat!(
            "trait Value<T> { type SelfValue = Self; type Input = T; type Byte = u8; } ",
            "impl<T> Value<T> for T { type Byte = u16; } ",
            "fn check() where <u32 as Value<u32>>::SelfValue = u32, ",
            "<u32 as Value<u32>>::Input = u32, <u32 as Value<u32>>::Byte = u16 {}"
        );
        let module = Parser::new(source).parse_module::<8, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();

        let exact = concat!(
            "trait Value { type Output = u8; } impl Value for u32 {} ",
            "fn check() where <u32 as Value>::Output = u8 {}"
        );
        let module = Parser::new(exact).parse_module::<6, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();

        let unsupported = Parser::new("trait Value<T> { type Output = Vec<T>; }")
            .parse_module::<2, 1>()
            .unwrap();
        assert_eq!(
            SourceTraitDeclarationTable::from_module(&unsupported),
            Err(SourceTraitDeclarationError::UnsupportedAssociatedTypeDefault)
        );
    }

    #[test]
    fn normalizes_projection_valued_source_associated_type_defaults() {
        let generic = concat!(
            "trait Child<T> { type Output = <T as Parent<T>>::Output; } ",
            "trait Parent<T> { type Output; } ",
            "impl<T> Parent<T> for T { type Output = T; } impl<T> Child<T> for T {} ",
            "fn check() where <u32 as Child<u32>>::Output = u32 {}"
        );
        let module = Parser::new(generic).parse_module::<10, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();

        let exact = concat!(
            "trait Parent { type Output; } ",
            "trait Child { type Output = <Self as Parent>::Output; } ",
            "impl Parent for u32 { type Output = u8; } impl Child for u32 {} ",
            "fn check() where <u32 as Child>::Output = u8 {}"
        );
        let module = Parser::new(exact).parse_module::<8, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();

        let missing = exact.replace("impl Parent for u32 { type Output = u8; } ", "");
        let module = Parser::new(&missing).parse_module::<8, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        assert_eq!(
            implementations
                .prove_module(&module, &traits)
                .unwrap_err()
                .kind,
            SourceTraitObligationErrorKind::Unsatisfied
        );

        let unknown = Parser::new(concat!(
            "trait Parent { type Output; } ",
            "trait Child { type Output = <Self as Parent>::Missing; }"
        ))
        .parse_module::<4, 1>()
        .unwrap();
        assert_eq!(
            SourceTraitDeclarationTable::from_module(&unknown),
            Err(SourceTraitDeclarationError::UnknownAssociatedTypeDefaultProjection)
        );
    }

    #[test]
    fn source_trait_implementation_lowering_fails_closed() {
        let unknown = Parser::new("impl Missing for u32 {}")
            .parse_module::<4, 1>()
            .unwrap();
        let no_traits = SourceTraitDeclarationTable::from_module(&unknown).unwrap();
        let error = SourceTraitImplementationTable::from_module(&unknown, &no_traits).unwrap_err();
        assert_eq!(error.kind, SourceTraitImplementationErrorKind::UnknownTrait);

        let unsupported = Parser::new("trait Value {} impl Value for &u32 {}")
            .parse_module::<4, 1>()
            .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&unsupported).unwrap();
        let error = SourceTraitImplementationTable::from_module(&unsupported, &traits).unwrap_err();
        assert_eq!(
            error.kind,
            SourceTraitImplementationErrorKind::UnsupportedSelfType
        );

        let overlap = Parser::new("trait Value {} impl Value for u32 {} impl Value for u32 {}")
            .parse_module::<4, 1>()
            .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&overlap).unwrap();
        let error = SourceTraitImplementationTable::from_module(&overlap, &traits).unwrap_err();
        assert_eq!(
            error.kind,
            SourceTraitImplementationErrorKind::Goal(TraitGoalError::OverlappingImplementation)
        );

        let type_overflow = concat!(
            "trait Value {} ",
            "impl Value for T00 {} impl Value for T01 {} impl Value for T02 {} impl Value for T03 {} ",
            "impl Value for T04 {} impl Value for T05 {} impl Value for T06 {} impl Value for T07 {} ",
            "impl Value for T08 {} impl Value for T09 {} impl Value for T10 {} impl Value for T11 {} ",
            "impl Value for T12 {} impl Value for T13 {} impl Value for T14 {} impl Value for T15 {} ",
            "impl Value for T16 {} impl Value for T17 {} impl Value for T18 {} impl Value for T19 {} ",
            "impl Value for T20 {} impl Value for T21 {} impl Value for T22 {} impl Value for T23 {} ",
            "impl Value for T24 {} impl Value for T25 {} impl Value for T26 {} impl Value for T27 {} ",
            "impl Value for T28 {} impl Value for T29 {} impl Value for T30 {} impl Value for T31 {} ",
            "impl Value for T32 {} impl Value for T33 {} impl Value for T34 {} impl Value for T35 {} ",
            "impl Value for T36 {} impl Value for T37 {} impl Value for T38 {} impl Value for T39 {} ",
            "impl Value for T40 {} impl Value for T41 {} impl Value for T42 {} impl Value for T43 {} ",
            "impl Value for T44 {} impl Value for T45 {} impl Value for T46 {} impl Value for T47 {} ",
            "impl Value for T48 {} impl Value for T49 {} impl Value for T50 {} impl Value for T51 {} ",
            "impl Value for T52 {} impl Value for T53 {} impl Value for T54 {} impl Value for T55 {} ",
            "impl Value for T56 {} impl Value for T57 {} impl Value for T58 {} impl Value for T59 {} ",
            "impl Value for T60 {} impl Value for T61 {} impl Value for T62 {} impl Value for T63 {} ",
            "impl Value for T64 {}",
        );
        let overflow = Parser::new(type_overflow).parse_module::<66, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&overflow).unwrap();
        let error = SourceTraitImplementationTable::from_module(&overflow, &traits).unwrap_err();
        assert_eq!(error.kind, SourceTraitImplementationErrorKind::TooManyTypes);
    }

    #[test]
    fn exact_source_implementations_require_transitive_supertraits() {
        let satisfied = Parser::new(concat!(
            "trait Leaf {} trait Parent: Leaf {} trait Child: Parent {} ",
            "impl Child for u32 {} impl Leaf for u32 {} impl Parent for u32 {}"
        ))
        .parse_module::<8, 1>()
        .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&satisfied).unwrap();
        SourceTraitImplementationTable::from_module(&satisfied, &traits).unwrap();

        let missing = Parser::new(concat!(
            "trait Leaf {} trait Parent: Leaf {} trait Child: Parent {} ",
            "impl Child for u32 {} impl Parent for u32 {}"
        ))
        .parse_module::<8, 1>()
        .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&missing).unwrap();
        let error = SourceTraitImplementationTable::from_module(&missing, &traits).unwrap_err();
        assert_eq!(
            error.kind,
            SourceTraitImplementationErrorKind::MissingSupertraitImplementation
        );

        let generic_parent = Parser::new(concat!(
            "trait Parent {} trait Child: Parent {} ",
            "impl<T> Parent for T {} impl Child for u32 {}"
        ))
        .parse_module::<8, 1>()
        .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&generic_parent).unwrap();
        SourceTraitImplementationTable::from_module(&generic_parent, &traits).unwrap();

        let conditional_parent = Parser::new(concat!(
            "trait Gate {} trait Parent {} trait Child: Parent {} ",
            "impl Gate for u32 {} impl Parent for u32 where u32: Gate {} ",
            "impl Child for u32 {}"
        ))
        .parse_module::<10, 1>()
        .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&conditional_parent).unwrap();
        SourceTraitImplementationTable::from_module(&conditional_parent, &traits).unwrap();

        let unavailable = Parser::new(concat!(
            "trait Gate {} trait Parent {} trait Child: Parent {} ",
            "impl Parent for u32 where u32: Gate {} impl Child for u32 {}"
        ))
        .parse_module::<8, 1>()
        .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&unavailable).unwrap();
        assert_eq!(
            SourceTraitImplementationTable::from_module(&unavailable, &traits)
                .unwrap_err()
                .kind,
            SourceTraitImplementationErrorKind::MissingSupertraitImplementation
        );
    }

    #[test]
    fn instantiates_parameterized_source_supertraits() {
        let exact = Parser::new(concat!(
            "trait Root<T> {} trait Parent<T>: Root<T> {} trait Child<T>: Parent<T> {} ",
            "impl Root<u8> for u32 {} impl Parent<u8> for u32 {} impl Child<u8> for u32 {}"
        ))
        .parse_module::<10, 1>()
        .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&exact).unwrap();
        SourceTraitImplementationTable::from_module(&exact, &traits).unwrap();

        let generic = Parser::new(concat!(
            "trait Parent<T> {} trait Child<T>: Parent<T> {} ",
            "impl<T> Parent<T> for T {} impl<T> Child<T> for T {} ",
            "fn check() where u32: Child<u32> {}"
        ))
        .parse_module::<10, 1>()
        .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&generic).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&generic, &traits).unwrap();
        implementations.prove_module(&generic, &traits).unwrap();

        let mismatch = Parser::new(concat!(
            "trait Parent<T> {} trait Child<T>: Parent<T> {} ",
            "impl Parent<u16> for u32 {} impl Child<u8> for u32 {}"
        ))
        .parse_module::<8, 1>()
        .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&mismatch).unwrap();
        assert_eq!(
            SourceTraitImplementationTable::from_module(&mismatch, &traits)
                .unwrap_err()
                .kind,
            SourceTraitImplementationErrorKind::MissingSupertraitImplementation
        );

        let concrete = Parser::new(concat!(
            "trait Root<T> {} trait Parent<T>: Root<u8> {} trait Child<T>: Parent<T> {} ",
            "impl Root<u8> for u32 {} impl Parent<u16> for u32 {} impl Child<u16> for u32 {}"
        ))
        .parse_module::<10, 1>()
        .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&concrete).unwrap();
        SourceTraitImplementationTable::from_module(&concrete, &traits).unwrap();

        let generic_concrete = Parser::new(concat!(
            "trait Parent<T> {} trait Child<T>: Parent<u8> {} ",
            "impl Parent<u8> for u32 {} impl<T> Child<T> for u32 {} ",
            "fn check() where u32: Child<u16> {}"
        ))
        .parse_module::<10, 1>()
        .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&generic_concrete).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&generic_concrete, &traits).unwrap();
        implementations
            .prove_module(&generic_concrete, &traits)
            .unwrap();

        let self_argument = Parser::new(concat!(
            "trait Root<T> {} trait Parent<T>: Root<Self> {} trait Child: Parent<Self> {} ",
            "impl<T> Root<T> for T {} impl<T> Parent<T> for T {} impl Child for u32 {}"
        ))
        .parse_module::<10, 1>()
        .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&self_argument).unwrap();
        SourceTraitImplementationTable::from_module(&self_argument, &traits).unwrap();

        let distinct = Parser::new(concat!(
            "trait Parent<T> {} trait Child: Parent<u8> + Parent<u16> {} ",
            "impl Parent<u8> for u32 {} impl Parent<u16> for u32 {} impl Child for u32 {}"
        ))
        .parse_module::<8, 1>()
        .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&distinct).unwrap();
        SourceTraitImplementationTable::from_module(&distinct, &traits).unwrap();

        let missing_distinct = Parser::new(concat!(
            "trait Parent<T> {} trait Child: Parent<u8> + Parent<u16> {} ",
            "impl Parent<u8> for u32 {} impl Child for u32 {}"
        ))
        .parse_module::<8, 1>()
        .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&missing_distinct).unwrap();
        assert_eq!(
            SourceTraitImplementationTable::from_module(&missing_distinct, &traits)
                .unwrap_err()
                .kind,
            SourceTraitImplementationErrorKind::MissingSupertraitImplementation
        );
    }

    #[test]
    fn proves_associated_bindings_on_source_supertraits() {
        let source = concat!(
            "trait Parent<Input> { type Output; } ",
            "trait Child: Parent<u8, Output = u16> {} ",
            "impl Parent<u8> for u32 { type Output = u16; } impl Child for u32 {} ",
            "fn check() where u32: Child {}"
        );
        let module = Parser::new(source).parse_module::<8, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();

        let mismatch = source.replace("{ type Output = u16; }", "{ type Output = u8; }");
        let module = Parser::new(&mismatch).parse_module::<8, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        assert_eq!(
            implementations
                .prove_module(&module, &traits)
                .unwrap_err()
                .kind,
            SourceTraitObligationErrorKind::Unsatisfied
        );
    }

    #[test]
    fn lowers_exact_source_associated_type_values_for_projection() {
        let source = concat!(
            "trait Iterator { type Item; } ",
            "impl Iterator for u32 { type Item = u8; }"
        );
        let module = Parser::new(source).parse_module::<4, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        let trait_id = traits.get("Iterator").unwrap().id;
        let associated_id = traits.get_associated_type(trait_id, "Item").unwrap().id;
        let self_type = implementations.get_type("u32").unwrap().id;
        let value_type = implementations.get_type("u8").unwrap().id;
        let goal = canonicalize_implemented_trait_goal(ImplementedTraitGoal::new(
            trait_id,
            TraitGoalType::Concrete(self_type),
        ))
        .unwrap();
        assert_eq!(
            implementations.associated_type_values().normalize(
                implementations.implementations(),
                goal,
                associated_id
            ),
            TraitProjectionSolution::Unique(value_type)
        );
    }

    #[test]
    fn proves_concrete_source_projection_equalities() {
        let source = concat!(
            "trait Iterator { type Item; } ",
            "impl Iterator for u32 { type Item = u8; } ",
            "fn check() where <u32 as Iterator>::Item = u8 {}"
        );
        let module = Parser::new(source).parse_module::<6, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        implementations.prove_module(&module, &traits).unwrap();

        for (expected, kind) in [
            ("u16", SourceTraitObligationErrorKind::ProjectionMismatch),
            ("u8", SourceTraitObligationErrorKind::UnknownAssociatedType),
        ] {
            let source = if kind == SourceTraitObligationErrorKind::UnknownAssociatedType {
                "trait Iterator { type Item; } impl Iterator for u32 { type Item = u8; } fn check() where <u32 as Iterator>::Missing = u8 {}"
            } else {
                "trait Iterator { type Item; } impl Iterator for u32 { type Item = u8; } fn check() where <u32 as Iterator>::Item = u16 {}"
            };
            let module = Parser::new(source).parse_module::<6, 1>().unwrap();
            let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
            let implementations =
                SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
            let error = implementations.prove_module(&module, &traits).unwrap_err();
            assert_eq!(error.kind, kind, "expected {expected}");
        }
    }

    #[test]
    fn exact_source_associated_values_require_one_declared_value_each() {
        let missing = Parser::new("trait Iterator { type Item; } impl Iterator for u32 {}")
            .parse_module::<4, 1>()
            .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&missing).unwrap();
        assert_eq!(
            SourceTraitImplementationTable::from_module(&missing, &traits)
                .unwrap_err()
                .kind,
            SourceTraitImplementationErrorKind::MissingAssociatedTypeValue
        );

        let unknown = Parser::new(concat!(
            "trait Iterator { type Item; } ",
            "impl Iterator for u32 { type Other = u8; }"
        ))
        .parse_module::<4, 1>()
        .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&unknown).unwrap();
        assert_eq!(
            SourceTraitImplementationTable::from_module(&unknown, &traits)
                .unwrap_err()
                .kind,
            SourceTraitImplementationErrorKind::UnknownAssociatedType
        );

        let duplicate = Parser::new(concat!(
            "trait Iterator { type Item; } ",
            "impl Iterator for u32 { type Item = u8; type Item = u16; }"
        ))
        .parse_module::<4, 1>()
        .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&duplicate).unwrap();
        assert_eq!(
            SourceTraitImplementationTable::from_module(&duplicate, &traits)
                .unwrap_err()
                .kind,
            SourceTraitImplementationErrorKind::DuplicateAssociatedTypeValue
        );

        let declaration_duplicate = Parser::new("trait Iterator { type Item; type Item; }")
            .parse_module::<2, 1>()
            .unwrap();
        assert_eq!(
            SourceTraitDeclarationTable::from_module(&declaration_duplicate),
            Err(SourceTraitDeclarationError::DuplicateAssociatedType)
        );

        let source_capacity = concat!(
            "trait T0 { type A0; type A1; type A2; type A3; type A4; type A5; type A6; type A7; } ",
            "trait T1 { type B0; type B1; type B2; type B3; type B4; type B5; type B6; type B7; } ",
            "trait T2 { type C0; type C1; type C2; type C3; type C4; type C5; type C6; type C7; } ",
            "trait T3 { type D0; type D1; type D2; type D3; type D4; type D5; type D6; type D7; } ",
            "trait T4 { type E0; type E1; type E2; type E3; type E4; type E5; type E6; type E7; } ",
            "trait T5 { type F0; type F1; type F2; type F3; type F4; type F5; type F6; type F7; } ",
            "trait T6 { type G0; type G1; type G2; type G3; type G4; type G5; type G6; type G7; } ",
            "trait T7 { type H0; type H1; type H2; type H3; type H4; type H5; type H6; type H7; } ",
            "trait T8 { type I0; }"
        );
        let overflow = Parser::new(source_capacity).parse_module::<9, 1>().unwrap();
        assert_eq!(
            SourceTraitDeclarationTable::from_module(&overflow),
            Err(SourceTraitDeclarationError::TooManyAssociatedTypes)
        );
    }

    #[test]
    fn proves_concrete_source_function_obligations() {
        let source = concat!(
            "trait Visible {} trait Small {} ",
            "impl Visible for core::primitive::u32 {} impl Small for u8 {} ",
            "fn check() where core::primitive::u32: Visible, u8: Small {}"
        );
        let module = Parser::new(source).parse_module::<8, 1>().unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&module).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&module, &traits).unwrap();
        let Some(Item::Function(function)) = module.items()[4] else {
            panic!("expected checked function")
        };
        implementations.prove_function(&function, &traits).unwrap();
    }

    #[test]
    fn source_function_obligations_reject_missing_unknown_and_duplicate_predicates() {
        let missing = Parser::new("trait Visible {} fn check() where u32: Visible {}")
            .parse_module::<4, 1>()
            .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&missing).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&missing, &traits).unwrap();
        let Some(Item::Function(function)) = missing.items()[1] else {
            panic!("expected function")
        };
        assert_eq!(
            implementations
                .prove_function(&function, &traits)
                .unwrap_err()
                .kind,
            SourceTraitObligationErrorKind::Unsatisfied
        );

        let unknown = Parser::new("fn check() where u32: Missing {}")
            .parse_module::<4, 1>()
            .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&unknown).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&unknown, &traits).unwrap();
        let Some(Item::Function(function)) = unknown.items()[0] else {
            panic!("expected function")
        };
        assert_eq!(
            implementations
                .prove_function(&function, &traits)
                .unwrap_err()
                .kind,
            SourceTraitObligationErrorKind::UnknownTrait
        );

        let duplicate = Parser::new(concat!(
            "trait Visible {} impl Visible for u32 {} ",
            "fn check() where u32: Visible, u32: Visible {}"
        ))
        .parse_module::<5, 1>()
        .unwrap();
        let traits = SourceTraitDeclarationTable::from_module(&duplicate).unwrap();
        let implementations =
            SourceTraitImplementationTable::from_module(&duplicate, &traits).unwrap();
        let Some(Item::Function(function)) = duplicate.items()[2] else {
            panic!("expected function")
        };
        assert_eq!(
            implementations
                .prove_function(&function, &traits)
                .unwrap_err()
                .kind,
            SourceTraitObligationErrorKind::DuplicatePredicate
        );
    }

    fn concrete_clause(
        trait_id: u32,
        type_id: u32,
        premise: Option<(u32, u32)>,
    ) -> TraitWhereClause {
        let mut clause = TraitWhereClause::new(
            0,
            BoundImplementedTraitGoal::new(
                TraitId::new(trait_id),
                BoundTraitGoalType::Concrete(TraitTypeId::new(type_id)),
            ),
        )
        .unwrap();
        if let Some((premise_trait, premise_type)) = premise {
            clause
                .push_premise(BoundImplementedTraitGoal::new(
                    TraitId::new(premise_trait),
                    BoundTraitGoalType::Concrete(TraitTypeId::new(premise_type)),
                ))
                .unwrap();
        }
        clause
    }

    #[test]
    fn canonicalizes_inference_variables_by_first_occurrence() {
        let first = TraitInferenceVariableId::new(41);
        let second = TraitInferenceVariableId::new(7);
        let mut goal =
            ImplementedTraitGoal::new(TraitId::new(3), TraitGoalType::InferenceVariable(first));
        goal.push_argument(TraitGoalType::Concrete(TraitTypeId::new(9)))
            .unwrap();
        goal.push_argument(TraitGoalType::InferenceVariable(second))
            .unwrap();
        goal.push_argument(TraitGoalType::InferenceVariable(first))
            .unwrap();

        let canonical = canonicalize_implemented_trait_goal(goal).unwrap();
        assert_eq!(canonical.variable_count(), 2);
        assert_eq!(
            canonical.self_type,
            CanonicalTraitGoalType::BoundVariable(0)
        );
        assert_eq!(
            canonical.arguments(),
            &[
                Some(CanonicalTraitGoalType::Concrete(TraitTypeId::new(9))),
                Some(CanonicalTraitGoalType::BoundVariable(1)),
                Some(CanonicalTraitGoalType::BoundVariable(0)),
            ]
        );
    }

    #[test]
    fn alpha_equivalent_goals_have_identical_canonical_forms() {
        let mut left = ImplementedTraitGoal::new(
            TraitId::new(5),
            TraitGoalType::InferenceVariable(TraitInferenceVariableId::new(10)),
        );
        left.push_argument(TraitGoalType::InferenceVariable(
            TraitInferenceVariableId::new(11),
        ))
        .unwrap();
        let mut right = ImplementedTraitGoal::new(
            TraitId::new(5),
            TraitGoalType::InferenceVariable(TraitInferenceVariableId::new(90)),
        );
        right
            .push_argument(TraitGoalType::InferenceVariable(
                TraitInferenceVariableId::new(2),
            ))
            .unwrap();

        assert_eq!(
            canonicalize_implemented_trait_goal(left),
            canonicalize_implemented_trait_goal(right)
        );
    }

    #[test]
    fn projection_bearing_term_arena_interns_acyclic_nested_terms() {
        let mut arena = TraitGoalTermArena::EMPTY;
        let leaf = arena
            .intern_type(TraitGoalType::Concrete(TraitTypeId::new(10)))
            .unwrap();
        assert_eq!(
            arena
                .intern_type(TraitGoalType::Concrete(TraitTypeId::new(10)))
                .unwrap(),
            leaf
        );
        let projection_goal = ProjectionBearingTraitGoal::new(TraitId::new(900), leaf);
        let projection = arena
            .intern_projection(projection_goal, TraitAssociatedTypeId::new(1))
            .unwrap();
        assert_eq!(
            arena
                .intern_projection(projection_goal, TraitAssociatedTypeId::new(1))
                .unwrap(),
            projection
        );
        let mut nested_goal = ProjectionBearingTraitGoal::new(TraitId::new(901), projection);
        nested_goal.push_argument(leaf).unwrap();
        let nested = arena
            .intern_projection(nested_goal, TraitAssociatedTypeId::new(2))
            .unwrap();
        assert_eq!(nested.get(), 2);
        assert_eq!(arena.terms().len(), 3);
        assert_eq!(
            arena.get(nested),
            Some(TraitGoalTerm::Projection {
                goal: nested_goal,
                associated_type_id: TraitAssociatedTypeId::new(2),
            })
        );
    }

    #[test]
    fn projection_bearing_term_arena_rejects_forward_references() {
        let mut arena = TraitGoalTermArena::EMPTY;
        assert_eq!(
            arena.intern_projection(
                ProjectionBearingTraitGoal::new(TraitId::new(902), TraitGoalTermId::new(0)),
                TraitAssociatedTypeId::new(1),
            ),
            Err(TraitGoalError::InvalidTraitGoalTermReference)
        );
        let leaf = arena
            .intern_type(TraitGoalType::Concrete(TraitTypeId::new(1)))
            .unwrap();
        let mut invalid = ProjectionBearingTraitGoal::new(TraitId::new(903), leaf);
        invalid.push_argument(TraitGoalTermId::new(63)).unwrap();
        assert_eq!(
            arena.intern_projection(invalid, TraitAssociatedTypeId::new(1)),
            Err(TraitGoalError::InvalidTraitGoalTermReference)
        );
    }

    #[test]
    fn projection_bearing_term_arena_has_fixed_capacity() {
        let mut arena = TraitGoalTermArena::EMPTY;
        for index in 0..MAX_TRAIT_GOAL_TERMS {
            assert_eq!(
                arena
                    .intern_type(TraitGoalType::Concrete(TraitTypeId::new(index as u32)))
                    .unwrap(),
                TraitGoalTermId::new(index as u8)
            );
        }
        assert_eq!(
            arena.intern_type(TraitGoalType::Concrete(TraitTypeId::new(999))),
            Err(TraitGoalError::TooManyTraitGoalTerms)
        );
    }

    #[test]
    fn normalizes_projection_bearing_argument_terms_and_inference() {
        let variable = TraitInferenceVariableId::in_universe(TraitUniverseIndex::new(16), 0);
        let associated = TraitAssociatedTypeId::new(1);
        let mut arena = TraitGoalTermArena::EMPTY;
        let inferred = arena
            .intern_type(TraitGoalType::InferenceVariable(variable))
            .unwrap();
        let concrete = arena
            .intern_type(TraitGoalType::Concrete(TraitTypeId::new(20)))
            .unwrap();
        let inner = arena
            .intern_projection(
                ProjectionBearingTraitGoal::new(TraitId::new(910), inferred),
                associated,
            )
            .unwrap();
        let mut outer_goal = ProjectionBearingTraitGoal::new(TraitId::new(911), concrete);
        outer_goal.push_argument(inner).unwrap();
        let outer = arena.intern_projection(outer_goal, associated).unwrap();

        let inner_implementation = TraitImplementationId::new(230);
        let outer_implementation = TraitImplementationId::new(231);
        let mut exact = TraitImplementationDatabase::EMPTY;
        exact
            .insert(TraitImplementationHeader::new(
                inner_implementation,
                TraitId::new(910),
                TraitTypeId::new(10),
            ))
            .unwrap();
        let mut outer_header = TraitImplementationHeader::new(
            outer_implementation,
            TraitId::new(911),
            TraitTypeId::new(20),
        );
        outer_header.push_argument(TraitTypeId::new(30)).unwrap();
        exact.insert(outer_header).unwrap();
        let mut values = TraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &exact,
                TraitAssociatedTypeValue::new(
                    inner_implementation,
                    associated,
                    TraitTypeId::new(30),
                ),
            )
            .unwrap();
        values
            .insert(
                &exact,
                TraitAssociatedTypeValue::new(
                    outer_implementation,
                    associated,
                    TraitTypeId::new(40),
                ),
            )
            .unwrap();
        let TraitGoalTermNormalizationSolution::Unique(answer) =
            normalize_inferred_trait_goal_term(
                &exact,
                &GenericTraitImplementationDatabase::EMPTY,
                &TraitWhereClauseDatabase::EMPTY,
                &values,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                &arena,
                outer,
            )
            .unwrap()
        else {
            panic!("projection-bearing argument should normalize");
        };
        assert_eq!(answer.value, TraitGoalType::Concrete(TraitTypeId::new(40)));
        assert_eq!(
            answer.substitution.binding(variable),
            Some(TraitGoalType::Concrete(TraitTypeId::new(10)))
        );
    }

    #[test]
    fn solves_implemented_goals_with_projection_bearing_arguments() {
        let variable = TraitInferenceVariableId::in_universe(TraitUniverseIndex::new(17), 0);
        let associated = TraitAssociatedTypeId::new(1);
        let mut arena = TraitGoalTermArena::EMPTY;
        let inferred = arena
            .intern_type(TraitGoalType::InferenceVariable(variable))
            .unwrap();
        let concrete = arena
            .intern_type(TraitGoalType::Concrete(TraitTypeId::new(30)))
            .unwrap();
        let projection = arena
            .intern_projection(
                ProjectionBearingTraitGoal::new(TraitId::new(912), inferred),
                associated,
            )
            .unwrap();
        let mut goal = ProjectionBearingTraitGoal::new(TraitId::new(913), concrete);
        goal.push_argument(projection).unwrap();

        let projection_implementation = TraitImplementationId::new(232);
        let root_implementation = TraitImplementationId::new(233);
        let mut exact = TraitImplementationDatabase::EMPTY;
        exact
            .insert(TraitImplementationHeader::new(
                projection_implementation,
                TraitId::new(912),
                TraitTypeId::new(10),
            ))
            .unwrap();
        let mut root_header = TraitImplementationHeader::new(
            root_implementation,
            TraitId::new(913),
            TraitTypeId::new(30),
        );
        root_header.push_argument(TraitTypeId::new(20)).unwrap();
        exact.insert(root_header).unwrap();
        let mut values = TraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &exact,
                TraitAssociatedTypeValue::new(
                    projection_implementation,
                    associated,
                    TraitTypeId::new(20),
                ),
            )
            .unwrap();
        let InferredTraitGoalSolution::Unique(answer) = solve_projection_bearing_trait_goal(
            &exact,
            &GenericTraitImplementationDatabase::EMPTY,
            &TraitWhereClauseDatabase::EMPTY,
            &values,
            &GenericTraitAssociatedTypeDatabase::EMPTY,
            &arena,
            goal,
        )
        .unwrap() else {
            panic!("projection-bearing implemented goal should prove");
        };
        assert_eq!(
            answer.substitution.binding(variable),
            Some(TraitGoalType::Concrete(TraitTypeId::new(10)))
        );
    }

    #[test]
    fn solves_existential_projection_bearing_term_binders() {
        let parameter = TraitGenericParameterId::new(0);
        let associated = TraitAssociatedTypeId::new(1);
        let mut arena = BoundTraitGoalTermArena::EMPTY;
        let inferred = arena
            .intern_type(BoundTraitGoalType::Parameter(parameter))
            .unwrap();
        let concrete = arena
            .intern_type(BoundTraitGoalType::Concrete(TraitTypeId::new(30)))
            .unwrap();
        let projection = arena
            .intern_projection(
                BoundProjectionBearingTraitGoal::new(TraitId::new(914), inferred),
                associated,
            )
            .unwrap();
        let mut bound_goal = BoundProjectionBearingTraitGoal::new(TraitId::new(915), concrete);
        bound_goal.push_argument(projection).unwrap();
        let query = ExistsProjectionBearingTraitGoal::new(1, arena, bound_goal).unwrap();

        let projection_implementation = TraitImplementationId::new(234);
        let root_implementation = TraitImplementationId::new(235);
        let mut exact = TraitImplementationDatabase::EMPTY;
        exact
            .insert(TraitImplementationHeader::new(
                projection_implementation,
                TraitId::new(914),
                TraitTypeId::new(10),
            ))
            .unwrap();
        let mut root_header = TraitImplementationHeader::new(
            root_implementation,
            TraitId::new(915),
            TraitTypeId::new(30),
        );
        root_header.push_argument(TraitTypeId::new(20)).unwrap();
        exact.insert(root_header).unwrap();
        let mut values = TraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &exact,
                TraitAssociatedTypeValue::new(
                    projection_implementation,
                    associated,
                    TraitTypeId::new(20),
                ),
            )
            .unwrap();
        let universe = TraitUniverseIndex::new(18);
        let InferredTraitGoalSolution::Unique(answer) = solve_exists_projection_bearing_trait_goal(
            &exact,
            &GenericTraitImplementationDatabase::EMPTY,
            &TraitWhereClauseDatabase::EMPTY,
            &values,
            &GenericTraitAssociatedTypeDatabase::EMPTY,
            universe,
            query,
        )
        .unwrap() else {
            panic!("projection-bearing existential binder should prove");
        };
        assert_eq!(
            answer
                .substitution
                .binding(TraitInferenceVariableId::in_universe(universe, 0)),
            Some(TraitGoalType::Concrete(TraitTypeId::new(10)))
        );

        let mut invalid_arena = BoundTraitGoalTermArena::EMPTY;
        let invalid = invalid_arena
            .intern_type(BoundTraitGoalType::Parameter(TraitGenericParameterId::new(
                1,
            )))
            .unwrap();
        assert_eq!(
            ExistsProjectionBearingTraitGoal::new(
                1,
                invalid_arena,
                BoundProjectionBearingTraitGoal::new(TraitId::new(916), invalid),
            ),
            Err(TraitGoalError::UnboundGenericParameter)
        );
    }

    #[test]
    fn solves_universal_projection_bearing_term_binders() {
        let parameter = TraitGenericParameterId::new(0);
        let associated = TraitAssociatedTypeId::new(1);
        let mut arena = BoundTraitGoalTermArena::EMPTY;
        let bound = arena
            .intern_type(BoundTraitGoalType::Parameter(parameter))
            .unwrap();
        let projection = arena
            .intern_projection(
                BoundProjectionBearingTraitGoal::new(TraitId::new(760), bound),
                associated,
            )
            .unwrap();
        let query = ForAllProjectionBearingTraitGoal::new(
            1,
            arena,
            BoundProjectionBearingTraitGoal::new(TraitId::new(761), projection),
        )
        .unwrap();

        let projected_id = GenericTraitImplementationId::new(210);
        let projected = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(760),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        let root = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(761),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic.insert(projected_id, projected).unwrap();
        generic
            .insert(GenericTraitImplementationId::new(211), root)
            .unwrap();
        let mut values = GenericTraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &generic,
                GenericTraitAssociatedTypeValue::new(
                    projected_id,
                    associated,
                    BoundTraitGoalType::Parameter(parameter),
                ),
            )
            .unwrap();
        assert_eq!(
            solve_for_all_projection_bearing_trait_goal(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                TraitUniverseIndex::ROOT,
                query,
            ),
            Ok(TraitProofSolution::Proven)
        );
        assert_eq!(
            solve_for_all_projection_bearing_trait_goal(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                TraitUniverseIndex::new(u16::MAX),
                query,
            ),
            Err(TraitGoalError::UniverseOverflow)
        );
    }

    #[test]
    fn solves_universal_projection_equalities_with_rigid_placeholders() {
        let parameter = TraitGenericParameterId::new(0);
        let associated = TraitAssociatedTypeId::new(1);
        let query = ForAllTraitProjectionEquality::new(
            1,
            BoundTraitProjection::new(
                BoundImplementedTraitGoal::new(
                    TraitId::new(762),
                    BoundTraitGoalType::Parameter(parameter),
                ),
                associated,
            ),
            BoundTraitGoalType::Parameter(parameter),
        )
        .unwrap();
        let implementation_id = GenericTraitImplementationId::new(209);
        let implementation = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(762),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic.insert(implementation_id, implementation).unwrap();
        let mut values = GenericTraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &generic,
                GenericTraitAssociatedTypeValue::new(
                    implementation_id,
                    associated,
                    BoundTraitGoalType::Parameter(parameter),
                ),
            )
            .unwrap();
        assert_eq!(
            solve_for_all_trait_projection_equality(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                TraitUniverseIndex::ROOT,
                query,
            ),
            Ok(TraitProofSolution::Proven)
        );
        assert_eq!(
            solve_for_all_trait_projection_equality(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                TraitUniverseIndex::new(u16::MAX),
                query,
            ),
            Err(TraitGoalError::UniverseOverflow)
        );
    }

    #[test]
    fn elaborates_projection_bearing_clause_heads() {
        let parameter = TraitGenericParameterId::new(0);
        let associated = TraitAssociatedTypeId::new(1);
        let mut arena = BoundTraitGoalTermArena::EMPTY;
        let bound = arena
            .intern_type(BoundTraitGoalType::Parameter(parameter))
            .unwrap();
        let projection = arena
            .intern_projection(
                BoundProjectionBearingTraitGoal::new(TraitId::new(960), bound),
                associated,
            )
            .unwrap();
        let mut consequence = BoundProjectionBearingTraitGoal::new(TraitId::new(961), bound);
        consequence.push_argument(projection).unwrap();
        let mut clause = ProjectionBearingTraitClause::new(1, arena, consequence).unwrap();
        clause
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(964),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let clause_id = TraitWhereClauseId::new(90);
        let mut clauses = ProjectionBearingTraitClauseDatabase::EMPTY;
        clauses.insert(clause_id, clause).unwrap();

        let implementation_id = TraitImplementationId::new(236);
        let mut exact = TraitImplementationDatabase::EMPTY;
        exact
            .insert(TraitImplementationHeader::new(
                implementation_id,
                TraitId::new(960),
                TraitTypeId::new(10),
            ))
            .unwrap();
        exact
            .insert(TraitImplementationHeader::new(
                TraitImplementationId::new(237),
                TraitId::new(964),
                TraitTypeId::new(10),
            ))
            .unwrap();
        let mut values = TraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &exact,
                TraitAssociatedTypeValue::new(implementation_id, associated, TraitTypeId::new(20)),
            )
            .unwrap();
        let variable = TraitInferenceVariableId::in_universe(TraitUniverseIndex::new(19), 0);
        let mut query = ImplementedTraitGoal::new(
            TraitId::new(961),
            TraitGoalType::InferenceVariable(variable),
        );
        query
            .push_argument(TraitGoalType::Concrete(TraitTypeId::new(20)))
            .unwrap();
        let ProjectionBearingTraitClauseSolution::Unique(answer) = clauses
            .elaborate_existential(
                &exact,
                &GenericTraitImplementationDatabase::EMPTY,
                &TraitWhereClauseDatabase::EMPTY,
                &values,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                query,
            )
            .unwrap()
        else {
            panic!("projection-bearing clause head should elaborate");
        };
        assert_eq!(answer.clause_id, clause_id);
        assert_eq!(
            answer.substitution.binding(variable),
            Some(TraitGoalType::Concrete(TraitTypeId::new(10)))
        );

        let mut missing_premise_exact = TraitImplementationDatabase::EMPTY;
        missing_premise_exact
            .insert(TraitImplementationHeader::new(
                implementation_id,
                TraitId::new(960),
                TraitTypeId::new(10),
            ))
            .unwrap();
        let mut missing_premise_values = TraitAssociatedTypeDatabase::EMPTY;
        missing_premise_values
            .insert(
                &missing_premise_exact,
                TraitAssociatedTypeValue::new(implementation_id, associated, TraitTypeId::new(20)),
            )
            .unwrap();
        assert_eq!(
            clauses.elaborate_existential(
                &missing_premise_exact,
                &GenericTraitImplementationDatabase::EMPTY,
                &TraitWhereClauseDatabase::EMPTY,
                &missing_premise_values,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                query,
            ),
            Ok(ProjectionBearingTraitClauseSolution::NoSolution)
        );

        let mut mismatch = ImplementedTraitGoal::new(
            TraitId::new(961),
            TraitGoalType::InferenceVariable(variable),
        );
        mismatch
            .push_argument(TraitGoalType::Concrete(TraitTypeId::new(21)))
            .unwrap();
        assert_eq!(
            clauses.elaborate_existential(
                &exact,
                &GenericTraitImplementationDatabase::EMPTY,
                &TraitWhereClauseDatabase::EMPTY,
                &values,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                mismatch,
            ),
            Ok(ProjectionBearingTraitClauseSolution::NoSolution)
        );
    }

    #[test]
    fn projection_bearing_clause_heads_fail_closed_on_unconstrained_parameters() {
        let parameter = TraitGenericParameterId::new(0);
        let mut arena = BoundTraitGoalTermArena::EMPTY;
        let bound = arena
            .intern_type(BoundTraitGoalType::Parameter(parameter))
            .unwrap();
        let projection = arena
            .intern_projection(
                BoundProjectionBearingTraitGoal::new(TraitId::new(962), bound),
                TraitAssociatedTypeId::new(1),
            )
            .unwrap();
        let clause = ProjectionBearingTraitClause::new(
            1,
            arena,
            BoundProjectionBearingTraitGoal::new(TraitId::new(963), projection),
        )
        .unwrap();
        let mut clauses = ProjectionBearingTraitClauseDatabase::EMPTY;
        clauses.insert(TraitWhereClauseId::new(91), clause).unwrap();
        assert_eq!(
            clauses.elaborate_existential(
                &TraitImplementationDatabase::EMPTY,
                &GenericTraitImplementationDatabase::EMPTY,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                ImplementedTraitGoal::new(
                    TraitId::new(963),
                    TraitGoalType::Concrete(TraitTypeId::new(20)),
                ),
            ),
            Ok(ProjectionBearingTraitClauseSolution::Ambiguous)
        );
    }

    #[test]
    fn recursively_solves_projection_bearing_clauses_and_reports_cycles() {
        let parameter = TraitGenericParameterId::new(0);
        let associated = TraitAssociatedTypeId::new(1);
        let mut outer_arena = BoundTraitGoalTermArena::EMPTY;
        let outer_parameter = outer_arena
            .intern_type(BoundTraitGoalType::Parameter(parameter))
            .unwrap();
        let projection = outer_arena
            .intern_projection(
                BoundProjectionBearingTraitGoal::new(TraitId::new(970), outer_parameter),
                associated,
            )
            .unwrap();
        let mut outer_head =
            BoundProjectionBearingTraitGoal::new(TraitId::new(971), outer_parameter);
        outer_head.push_argument(projection).unwrap();
        let mut outer = ProjectionBearingTraitClause::new(1, outer_arena, outer_head).unwrap();
        outer
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(972),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();

        let mut inner_arena = BoundTraitGoalTermArena::EMPTY;
        let inner_parameter = inner_arena
            .intern_type(BoundTraitGoalType::Parameter(parameter))
            .unwrap();
        let inner = ProjectionBearingTraitClause::new(
            1,
            inner_arena,
            BoundProjectionBearingTraitGoal::new(TraitId::new(972), inner_parameter),
        )
        .unwrap();
        let mut projection_clauses = ProjectionBearingTraitClauseDatabase::EMPTY;
        projection_clauses
            .insert(TraitWhereClauseId::new(92), outer)
            .unwrap();
        projection_clauses
            .insert(TraitWhereClauseId::new(93), inner)
            .unwrap();

        let implementation_id = TraitImplementationId::new(238);
        let mut exact = TraitImplementationDatabase::EMPTY;
        exact
            .insert(TraitImplementationHeader::new(
                implementation_id,
                TraitId::new(970),
                TraitTypeId::new(10),
            ))
            .unwrap();
        let mut values = TraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &exact,
                TraitAssociatedTypeValue::new(implementation_id, associated, TraitTypeId::new(20)),
            )
            .unwrap();
        let parameter_type = BoundTraitGoalType::Parameter(parameter);
        let mut query = BoundImplementedTraitGoal::new(TraitId::new(971), parameter_type);
        query
            .push_argument(BoundTraitGoalType::Concrete(TraitTypeId::new(20)))
            .unwrap();
        let universe = TraitUniverseIndex::new(20);
        let InferredTraitGoalSolution::Unique(answer) =
            solve_exists_trait_goal_with_projection_clauses(
                &exact,
                &GenericTraitImplementationDatabase::EMPTY,
                &TraitWhereClauseDatabase::EMPTY,
                &projection_clauses,
                &values,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                universe,
                ExistsImplementedTraitGoal::new(1, query).unwrap(),
            )
            .unwrap()
        else {
            panic!("nested projection-bearing clauses should prove");
        };
        assert_eq!(
            answer
                .substitution
                .binding(TraitInferenceVariableId::in_universe(universe, 0)),
            Some(TraitGoalType::Concrete(TraitTypeId::new(10)))
        );

        let mut cyclic_inner = inner;
        let mut cyclic_premise = BoundImplementedTraitGoal::new(TraitId::new(971), parameter_type);
        cyclic_premise
            .push_argument(BoundTraitGoalType::Concrete(TraitTypeId::new(20)))
            .unwrap();
        cyclic_inner.push_premise(cyclic_premise).unwrap();
        let mut cyclic = ProjectionBearingTraitClauseDatabase::EMPTY;
        cyclic.insert(TraitWhereClauseId::new(92), outer).unwrap();
        cyclic
            .insert(TraitWhereClauseId::new(94), cyclic_inner)
            .unwrap();
        assert_eq!(
            solve_exists_trait_goal_with_projection_clauses(
                &exact,
                &GenericTraitImplementationDatabase::EMPTY,
                &TraitWhereClauseDatabase::EMPTY,
                &cyclic,
                &values,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                universe,
                ExistsImplementedTraitGoal::new(1, query).unwrap(),
            ),
            Ok(InferredTraitGoalSolution::Cycle)
        );
    }

    #[test]
    fn recursive_projection_bearing_clauses_report_depth_overflow() {
        let parameter = TraitGenericParameterId::new(0);
        let mut clauses = ProjectionBearingTraitClauseDatabase::EMPTY;
        for index in 0..=MAX_TRAIT_PROOF_DEPTH + 1 {
            let mut arena = BoundTraitGoalTermArena::EMPTY;
            let term = arena
                .intern_type(BoundTraitGoalType::Parameter(parameter))
                .unwrap();
            let mut clause = ProjectionBearingTraitClause::new(
                1,
                arena,
                BoundProjectionBearingTraitGoal::new(TraitId::new(980 + index as u32), term),
            )
            .unwrap();
            if index <= MAX_TRAIT_PROOF_DEPTH {
                clause
                    .push_premise(BoundImplementedTraitGoal::new(
                        TraitId::new(981 + index as u32),
                        BoundTraitGoalType::Parameter(parameter),
                    ))
                    .unwrap();
            }
            clauses
                .insert(TraitWhereClauseId::new(100 + index as u32), clause)
                .unwrap();
        }
        assert_eq!(
            solve_exists_trait_goal_with_projection_clauses(
                &TraitImplementationDatabase::EMPTY,
                &GenericTraitImplementationDatabase::EMPTY,
                &TraitWhereClauseDatabase::EMPTY,
                &clauses,
                &TraitAssociatedTypeDatabase::EMPTY,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                TraitUniverseIndex::new(21),
                ExistsImplementedTraitGoal::new(
                    1,
                    BoundImplementedTraitGoal::new(
                        TraitId::new(980),
                        BoundTraitGoalType::Parameter(parameter),
                    ),
                )
                .unwrap(),
            ),
            Ok(InferredTraitGoalSolution::Overflow)
        );
    }

    #[test]
    fn recursive_projection_bearing_clause_selection_preserves_ambiguity() {
        let parameter = TraitGenericParameterId::new(0);
        let mut clauses = ProjectionBearingTraitClauseDatabase::EMPTY;
        for (id, premise_trait) in [(120, 1001), (121, 1002)] {
            let mut arena = BoundTraitGoalTermArena::EMPTY;
            let term = arena
                .intern_type(BoundTraitGoalType::Parameter(parameter))
                .unwrap();
            let mut clause = ProjectionBearingTraitClause::new(
                1,
                arena,
                BoundProjectionBearingTraitGoal::new(TraitId::new(1000), term),
            )
            .unwrap();
            clause
                .push_premise(BoundImplementedTraitGoal::new(
                    TraitId::new(premise_trait),
                    BoundTraitGoalType::Parameter(parameter),
                ))
                .unwrap();
            clauses.insert(TraitWhereClauseId::new(id), clause).unwrap();
        }
        let mut exact = TraitImplementationDatabase::EMPTY;
        for (id, trait_id) in [(250, 1001), (251, 1002)] {
            exact
                .insert(TraitImplementationHeader::new(
                    TraitImplementationId::new(id),
                    TraitId::new(trait_id),
                    TraitTypeId::new(10),
                ))
                .unwrap();
        }
        assert_eq!(
            solve_exists_trait_goal_with_projection_clauses(
                &exact,
                &GenericTraitImplementationDatabase::EMPTY,
                &TraitWhereClauseDatabase::EMPTY,
                &clauses,
                &TraitAssociatedTypeDatabase::EMPTY,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                TraitUniverseIndex::new(22),
                ExistsImplementedTraitGoal::new(
                    1,
                    BoundImplementedTraitGoal::new(
                        TraitId::new(1000),
                        BoundTraitGoalType::Parameter(parameter),
                    ),
                )
                .unwrap(),
            ),
            Ok(InferredTraitGoalSolution::Ambiguous)
        );
    }

    #[test]
    fn projection_bearing_implementation_admission_is_conservatively_coherent() {
        fn implementation(self_type: u32) -> ProjectionBearingTraitClause {
            let parameter = TraitGenericParameterId::new(0);
            let mut arena = BoundTraitGoalTermArena::EMPTY;
            let self_term = arena
                .intern_type(BoundTraitGoalType::Concrete(TraitTypeId::new(self_type)))
                .unwrap();
            let parameter_term = arena
                .intern_type(BoundTraitGoalType::Parameter(parameter))
                .unwrap();
            let projection = arena
                .intern_projection(
                    BoundProjectionBearingTraitGoal::new(TraitId::new(1101), parameter_term),
                    TraitAssociatedTypeId::new(1),
                )
                .unwrap();
            let mut head = BoundProjectionBearingTraitGoal::new(TraitId::new(1100), self_term);
            head.push_argument(projection).unwrap();
            ProjectionBearingTraitClause::new(1, arena, head).unwrap()
        }

        let first = implementation(10);
        let disjoint = implementation(11);
        let mut implementations = ProjectionBearingGenericTraitImplementationDatabase::EMPTY;
        implementations
            .insert(GenericTraitImplementationId::new(300), first)
            .unwrap();
        implementations
            .insert(GenericTraitImplementationId::new(301), disjoint)
            .unwrap();
        assert_eq!(
            implementations.insert(GenericTraitImplementationId::new(302), first),
            Err(TraitGoalError::OverlappingGenericImplementation)
        );

        let mut exact_overlap = TraitImplementationHeader::new(
            TraitImplementationId::new(252),
            TraitId::new(1100),
            TraitTypeId::new(10),
        );
        exact_overlap.push_argument(TraitTypeId::new(20)).unwrap();
        let mut exact = TraitImplementationDatabase::EMPTY;
        exact.insert(exact_overlap).unwrap();
        let mut exact_checked = ProjectionBearingGenericTraitImplementationDatabase::EMPTY;
        assert_eq!(
            exact_checked.insert_coherent(
                &exact,
                &GenericTraitImplementationDatabase::EMPTY,
                GenericTraitImplementationId::new(303),
                first,
            ),
            Err(TraitGoalError::OverlappingExactAndGenericImplementation)
        );

        let mut flat_head = BoundImplementedTraitGoal::new(
            TraitId::new(1100),
            BoundTraitGoalType::Concrete(TraitTypeId::new(10)),
        );
        flat_head
            .push_argument(BoundTraitGoalType::Concrete(TraitTypeId::new(20)))
            .unwrap();
        let mut flat = GenericTraitImplementationDatabase::EMPTY;
        flat.insert(
            GenericTraitImplementationId::new(304),
            TraitWhereClause::new(0, flat_head).unwrap(),
        )
        .unwrap();
        let mut flat_checked = ProjectionBearingGenericTraitImplementationDatabase::EMPTY;
        assert_eq!(
            flat_checked.insert_coherent(
                &TraitImplementationDatabase::EMPTY,
                &flat,
                GenericTraitImplementationId::new(305),
                first,
            ),
            Err(TraitGoalError::OverlappingExactAndGenericImplementation)
        );
        let mut disjoint_checked = ProjectionBearingGenericTraitImplementationDatabase::EMPTY;
        disjoint_checked
            .insert_coherent(
                &exact,
                &flat,
                GenericTraitImplementationId::new(306),
                implementation(12),
            )
            .unwrap();

        let parameter = TraitGenericParameterId::new(0);
        let mut repeated_arena = BoundTraitGoalTermArena::EMPTY;
        let repeated_term = repeated_arena
            .intern_type(BoundTraitGoalType::Parameter(parameter))
            .unwrap();
        let mut repeated_head =
            BoundProjectionBearingTraitGoal::new(TraitId::new(1105), repeated_term);
        repeated_head.push_argument(repeated_term).unwrap();
        let repeated = ProjectionBearingTraitClause::new(1, repeated_arena, repeated_head).unwrap();
        let mut unequal_arena = BoundTraitGoalTermArena::EMPTY;
        let ten = unequal_arena
            .intern_type(BoundTraitGoalType::Concrete(TraitTypeId::new(10)))
            .unwrap();
        let eleven = unequal_arena
            .intern_type(BoundTraitGoalType::Concrete(TraitTypeId::new(11)))
            .unwrap();
        let mut unequal_head = BoundProjectionBearingTraitGoal::new(TraitId::new(1105), ten);
        unequal_head.push_argument(eleven).unwrap();
        let unequal = ProjectionBearingTraitClause::new(0, unequal_arena, unequal_head).unwrap();
        let mut repeated_checked = ProjectionBearingGenericTraitImplementationDatabase::EMPTY;
        repeated_checked
            .insert(GenericTraitImplementationId::new(307), repeated)
            .unwrap();
        repeated_checked
            .insert(GenericTraitImplementationId::new(308), unequal)
            .unwrap();

        let mut unequal_exact = TraitImplementationHeader::new(
            TraitImplementationId::new(256),
            TraitId::new(1105),
            TraitTypeId::new(10),
        );
        unequal_exact.push_argument(TraitTypeId::new(11)).unwrap();
        let mut exact_disjoint = TraitImplementationDatabase::EMPTY;
        exact_disjoint.insert(unequal_exact).unwrap();
        let mut repeated_exact_checked = ProjectionBearingGenericTraitImplementationDatabase::EMPTY;
        repeated_exact_checked
            .insert_coherent(
                &exact_disjoint,
                &GenericTraitImplementationDatabase::EMPTY,
                GenericTraitImplementationId::new(309),
                repeated,
            )
            .unwrap();
        let mut unequal_flat_head = BoundImplementedTraitGoal::new(
            TraitId::new(1105),
            BoundTraitGoalType::Concrete(TraitTypeId::new(10)),
        );
        unequal_flat_head
            .push_argument(BoundTraitGoalType::Concrete(TraitTypeId::new(11)))
            .unwrap();
        let mut unequal_flat = GenericTraitImplementationDatabase::EMPTY;
        unequal_flat
            .insert(
                GenericTraitImplementationId::new(313),
                TraitWhereClause::new(0, unequal_flat_head).unwrap(),
            )
            .unwrap();
        let mut repeated_flat_checked = ProjectionBearingGenericTraitImplementationDatabase::EMPTY;
        repeated_flat_checked
            .insert_coherent(
                &TraitImplementationDatabase::EMPTY,
                &unequal_flat,
                GenericTraitImplementationId::new(314),
                repeated,
            )
            .unwrap();
    }

    #[test]
    fn selects_projection_bearing_implementation_and_proves_premises() {
        let parameter = TraitGenericParameterId::new(0);
        let associated = TraitAssociatedTypeId::new(1);
        let mut arena = BoundTraitGoalTermArena::EMPTY;
        let term = arena
            .intern_type(BoundTraitGoalType::Parameter(parameter))
            .unwrap();
        let projection = arena
            .intern_projection(
                BoundProjectionBearingTraitGoal::new(TraitId::new(1110), term),
                associated,
            )
            .unwrap();
        let mut head = BoundProjectionBearingTraitGoal::new(TraitId::new(1111), term);
        head.push_argument(projection).unwrap();
        let mut implementation = ProjectionBearingTraitClause::new(1, arena, head).unwrap();
        implementation
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(1112),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        implementation
            .push_projection_bearing_premise(BoundProjectionBearingTraitGoal::new(
                TraitId::new(1113),
                projection,
            ))
            .unwrap();
        let implementation_id = GenericTraitImplementationId::new(310);
        let mut implementations = ProjectionBearingGenericTraitImplementationDatabase::EMPTY;
        implementations
            .insert(implementation_id, implementation)
            .unwrap();

        let projection_implementation_id = TraitImplementationId::new(253);
        let mut exact = TraitImplementationDatabase::EMPTY;
        exact
            .insert(TraitImplementationHeader::new(
                projection_implementation_id,
                TraitId::new(1110),
                TraitTypeId::new(10),
            ))
            .unwrap();
        exact
            .insert(TraitImplementationHeader::new(
                TraitImplementationId::new(255),
                TraitId::new(1113),
                TraitTypeId::new(20),
            ))
            .unwrap();
        exact
            .insert(TraitImplementationHeader::new(
                TraitImplementationId::new(254),
                TraitId::new(1112),
                TraitTypeId::new(10),
            ))
            .unwrap();
        let mut values = TraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &exact,
                TraitAssociatedTypeValue::new(
                    projection_implementation_id,
                    associated,
                    TraitTypeId::new(20),
                ),
            )
            .unwrap();
        let variable = TraitInferenceVariableId::in_universe(TraitUniverseIndex::new(23), 0);
        let mut query = ImplementedTraitGoal::new(
            TraitId::new(1111),
            TraitGoalType::InferenceVariable(variable),
        );
        query
            .push_argument(TraitGoalType::Concrete(TraitTypeId::new(20)))
            .unwrap();
        let ProjectionBearingGenericTraitImplementationSolution::Unique(answer) = implementations
            .select_existential(
                &exact,
                &GenericTraitImplementationDatabase::EMPTY,
                &TraitWhereClauseDatabase::EMPTY,
                &values,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                query,
            )
            .unwrap()
        else {
            panic!("projection-bearing implementation should select");
        };
        assert_eq!(answer.implementation_id, implementation_id);
        assert_eq!(
            answer.substitution.binding(variable),
            Some(TraitGoalType::Concrete(TraitTypeId::new(10)))
        );

        let mut missing_premise = TraitImplementationDatabase::EMPTY;
        missing_premise
            .insert(TraitImplementationHeader::new(
                projection_implementation_id,
                TraitId::new(1110),
                TraitTypeId::new(10),
            ))
            .unwrap();
        missing_premise
            .insert(TraitImplementationHeader::new(
                TraitImplementationId::new(255),
                TraitId::new(1113),
                TraitTypeId::new(20),
            ))
            .unwrap();
        let mut missing_values = TraitAssociatedTypeDatabase::EMPTY;
        missing_values
            .insert(
                &missing_premise,
                TraitAssociatedTypeValue::new(
                    projection_implementation_id,
                    associated,
                    TraitTypeId::new(20),
                ),
            )
            .unwrap();
        assert_eq!(
            implementations.select_existential(
                &missing_premise,
                &GenericTraitImplementationDatabase::EMPTY,
                &TraitWhereClauseDatabase::EMPTY,
                &missing_values,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                query,
            ),
            Ok(ProjectionBearingGenericTraitImplementationSolution::NoSolution)
        );

        let mut inner_arena = BoundTraitGoalTermArena::EMPTY;
        let inner_term = inner_arena
            .intern_type(BoundTraitGoalType::Parameter(parameter))
            .unwrap();
        let inner = ProjectionBearingTraitClause::new(
            1,
            inner_arena,
            BoundProjectionBearingTraitGoal::new(TraitId::new(1112), inner_term),
        )
        .unwrap();
        implementations
            .insert(GenericTraitImplementationId::new(311), inner)
            .unwrap();
        let mut bound_query = BoundImplementedTraitGoal::new(
            TraitId::new(1111),
            BoundTraitGoalType::Parameter(parameter),
        );
        bound_query
            .push_argument(BoundTraitGoalType::Concrete(TraitTypeId::new(20)))
            .unwrap();
        assert!(matches!(
            solve_exists_trait_goal_with_projection_implementations(
                &missing_premise,
                &GenericTraitImplementationDatabase::EMPTY,
                &TraitWhereClauseDatabase::EMPTY,
                &ProjectionBearingTraitClauseDatabase::EMPTY,
                &implementations,
                &missing_values,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                TraitUniverseIndex::new(24),
                ExistsImplementedTraitGoal::new(1, bound_query).unwrap(),
            ),
            Ok(InferredTraitGoalSolution::Unique(_))
        ));

        let mut cyclic_inner = inner;
        let mut cycle_premise = BoundImplementedTraitGoal::new(
            TraitId::new(1111),
            BoundTraitGoalType::Parameter(parameter),
        );
        cycle_premise
            .push_argument(BoundTraitGoalType::Concrete(TraitTypeId::new(20)))
            .unwrap();
        cyclic_inner.push_premise(cycle_premise).unwrap();
        let mut cyclic = ProjectionBearingGenericTraitImplementationDatabase::EMPTY;
        cyclic.insert(implementation_id, implementation).unwrap();
        cyclic
            .insert(GenericTraitImplementationId::new(312), cyclic_inner)
            .unwrap();
        assert_eq!(
            solve_exists_trait_goal_with_projection_implementations(
                &missing_premise,
                &GenericTraitImplementationDatabase::EMPTY,
                &TraitWhereClauseDatabase::EMPTY,
                &ProjectionBearingTraitClauseDatabase::EMPTY,
                &cyclic,
                &missing_values,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                TraitUniverseIndex::new(24),
                ExistsImplementedTraitGoal::new(1, bound_query).unwrap(),
            ),
            Ok(InferredTraitGoalSolution::Cycle)
        );
    }

    #[test]
    fn recursive_projection_bearing_implementations_report_depth_overflow() {
        let parameter = TraitGenericParameterId::new(0);
        let mut implementations = ProjectionBearingGenericTraitImplementationDatabase::EMPTY;
        for index in 0..=MAX_TRAIT_PROOF_DEPTH + 1 {
            let mut arena = BoundTraitGoalTermArena::EMPTY;
            let term = arena
                .intern_type(BoundTraitGoalType::Parameter(parameter))
                .unwrap();
            let mut implementation = ProjectionBearingTraitClause::new(
                1,
                arena,
                BoundProjectionBearingTraitGoal::new(TraitId::new(1200 + index as u32), term),
            )
            .unwrap();
            if index <= MAX_TRAIT_PROOF_DEPTH {
                implementation
                    .push_premise(BoundImplementedTraitGoal::new(
                        TraitId::new(1201 + index as u32),
                        BoundTraitGoalType::Parameter(parameter),
                    ))
                    .unwrap();
            }
            implementations
                .insert(
                    GenericTraitImplementationId::new(330 + index as u32),
                    implementation,
                )
                .unwrap();
        }
        assert_eq!(
            solve_exists_trait_goal_with_projection_implementations(
                &TraitImplementationDatabase::EMPTY,
                &GenericTraitImplementationDatabase::EMPTY,
                &TraitWhereClauseDatabase::EMPTY,
                &ProjectionBearingTraitClauseDatabase::EMPTY,
                &implementations,
                &TraitAssociatedTypeDatabase::EMPTY,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                TraitUniverseIndex::new(25),
                ExistsImplementedTraitGoal::new(
                    1,
                    BoundImplementedTraitGoal::new(
                        TraitId::new(1200),
                        BoundTraitGoalType::Parameter(parameter),
                    ),
                )
                .unwrap(),
            ),
            Ok(InferredTraitGoalSolution::Overflow)
        );
    }

    #[test]
    fn flat_premises_refine_projection_bearing_premises() {
        let parameter = TraitGenericParameterId::new(0);
        let associated = TraitAssociatedTypeId::new(1);
        let mut arena = BoundTraitGoalTermArena::EMPTY;
        let term = arena
            .intern_type(BoundTraitGoalType::Parameter(parameter))
            .unwrap();
        let projection = arena
            .intern_projection(
                BoundProjectionBearingTraitGoal::new(TraitId::new(1303), term),
                associated,
            )
            .unwrap();
        let mut implementation = ProjectionBearingTraitClause::new(
            1,
            arena,
            BoundProjectionBearingTraitGoal::new(TraitId::new(1300), term),
        )
        .unwrap();
        implementation
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(1301),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        implementation
            .push_projection_bearing_premise(BoundProjectionBearingTraitGoal::new(
                TraitId::new(1302),
                projection,
            ))
            .unwrap();
        let mut implementations = ProjectionBearingGenericTraitImplementationDatabase::EMPTY;
        implementations
            .insert(GenericTraitImplementationId::new(350), implementation)
            .unwrap();

        let mut exact = TraitImplementationDatabase::EMPTY;
        exact
            .insert(TraitImplementationHeader::new(
                TraitImplementationId::new(260),
                TraitId::new(1301),
                TraitTypeId::new(10),
            ))
            .unwrap();
        for (id, self_type) in [(261, 10), (262, 11)] {
            exact
                .insert(TraitImplementationHeader::new(
                    TraitImplementationId::new(id),
                    TraitId::new(1303),
                    TraitTypeId::new(self_type),
                ))
                .unwrap();
        }
        exact
            .insert(TraitImplementationHeader::new(
                TraitImplementationId::new(263),
                TraitId::new(1302),
                TraitTypeId::new(20),
            ))
            .unwrap();
        let mut values = TraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &exact,
                TraitAssociatedTypeValue::new(
                    TraitImplementationId::new(261),
                    associated,
                    TraitTypeId::new(20),
                ),
            )
            .unwrap();
        values
            .insert(
                &exact,
                TraitAssociatedTypeValue::new(
                    TraitImplementationId::new(262),
                    associated,
                    TraitTypeId::new(21),
                ),
            )
            .unwrap();
        let universe = TraitUniverseIndex::new(26);
        let InferredTraitGoalSolution::Unique(answer) =
            solve_exists_trait_goal_with_projection_implementations(
                &exact,
                &GenericTraitImplementationDatabase::EMPTY,
                &TraitWhereClauseDatabase::EMPTY,
                &ProjectionBearingTraitClauseDatabase::EMPTY,
                &implementations,
                &values,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                universe,
                ExistsImplementedTraitGoal::new(
                    1,
                    BoundImplementedTraitGoal::new(
                        TraitId::new(1300),
                        BoundTraitGoalType::Parameter(parameter),
                    ),
                )
                .unwrap(),
            )
            .unwrap()
        else {
            panic!("flat premise should refine projected premise");
        };
        assert_eq!(
            answer
                .substitution
                .binding(TraitInferenceVariableId::in_universe(universe, 0)),
            Some(TraitGoalType::Concrete(TraitTypeId::new(10)))
        );
    }

    #[test]
    fn projection_bearing_premises_refine_flat_premises() {
        let parameter = TraitGenericParameterId::new(0);
        let associated = TraitAssociatedTypeId::new(1);
        let mut arena = BoundTraitGoalTermArena::EMPTY;
        let term = arena
            .intern_type(BoundTraitGoalType::Parameter(parameter))
            .unwrap();
        let projection = arena
            .intern_projection(
                BoundProjectionBearingTraitGoal::new(TraitId::new(1403), term),
                associated,
            )
            .unwrap();
        let mut implementation = ProjectionBearingTraitClause::new(
            1,
            arena,
            BoundProjectionBearingTraitGoal::new(TraitId::new(1400), term),
        )
        .unwrap();
        implementation
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(1401),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        implementation
            .push_projection_bearing_premise(BoundProjectionBearingTraitGoal::new(
                TraitId::new(1402),
                projection,
            ))
            .unwrap();
        let mut implementations = ProjectionBearingGenericTraitImplementationDatabase::EMPTY;
        implementations
            .insert(GenericTraitImplementationId::new(360), implementation)
            .unwrap();
        let mut exact = TraitImplementationDatabase::EMPTY;
        for (id, self_type) in [(270, 10), (271, 11)] {
            exact
                .insert(TraitImplementationHeader::new(
                    TraitImplementationId::new(id),
                    TraitId::new(1401),
                    TraitTypeId::new(self_type),
                ))
                .unwrap();
        }
        let projection_id = TraitImplementationId::new(272);
        exact
            .insert(TraitImplementationHeader::new(
                projection_id,
                TraitId::new(1403),
                TraitTypeId::new(10),
            ))
            .unwrap();
        exact
            .insert(TraitImplementationHeader::new(
                TraitImplementationId::new(273),
                TraitId::new(1402),
                TraitTypeId::new(20),
            ))
            .unwrap();
        let mut values = TraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &exact,
                TraitAssociatedTypeValue::new(projection_id, associated, TraitTypeId::new(20)),
            )
            .unwrap();
        let universe = TraitUniverseIndex::new(27);
        let InferredTraitGoalSolution::Unique(answer) =
            solve_exists_trait_goal_with_projection_implementations(
                &exact,
                &GenericTraitImplementationDatabase::EMPTY,
                &TraitWhereClauseDatabase::EMPTY,
                &ProjectionBearingTraitClauseDatabase::EMPTY,
                &implementations,
                &values,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                universe,
                ExistsImplementedTraitGoal::new(
                    1,
                    BoundImplementedTraitGoal::new(
                        TraitId::new(1400),
                        BoundTraitGoalType::Parameter(parameter),
                    ),
                )
                .unwrap(),
            )
            .unwrap()
        else {
            panic!("projected premise should refine flat premise");
        };
        assert_eq!(
            answer
                .substitution
                .binding(TraitInferenceVariableId::in_universe(universe, 0)),
            Some(TraitGoalType::Concrete(TraitTypeId::new(10)))
        );
    }

    #[test]
    fn projection_bearing_term_normalization_reports_depth_overflow() {
        let associated = TraitAssociatedTypeId::new(1);
        let mut arena = TraitGoalTermArena::EMPTY;
        let mut term = arena
            .intern_type(TraitGoalType::Concrete(TraitTypeId::new(0)))
            .unwrap();
        let mut exact = TraitImplementationDatabase::EMPTY;
        let mut values = TraitAssociatedTypeDatabase::EMPTY;
        for index in 0..=MAX_TRAIT_PROJECTION_DEPTH {
            let implementation_id = TraitImplementationId::new(240 + index as u32);
            exact
                .insert(TraitImplementationHeader::new(
                    implementation_id,
                    TraitId::new(920 + index as u32),
                    TraitTypeId::new(index as u32),
                ))
                .unwrap();
            values
                .insert(
                    &exact,
                    TraitAssociatedTypeValue::new(
                        implementation_id,
                        associated,
                        TraitTypeId::new(index as u32 + 1),
                    ),
                )
                .unwrap();
            term = arena
                .intern_projection(
                    ProjectionBearingTraitGoal::new(TraitId::new(920 + index as u32), term),
                    associated,
                )
                .unwrap();
        }
        assert_eq!(
            normalize_inferred_trait_goal_term(
                &exact,
                &GenericTraitImplementationDatabase::EMPTY,
                &TraitWhereClauseDatabase::EMPTY,
                &values,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                &arena,
                term,
            ),
            Ok(TraitGoalTermNormalizationSolution::Overflow)
        );
    }

    #[test]
    fn canonicalizes_predicates_in_one_shared_variable_universe() {
        let shared = TraitInferenceVariableId::new(70);
        let distinct = TraitInferenceVariableId::new(4);
        let first =
            ImplementedTraitGoal::new(TraitId::new(1), TraitGoalType::InferenceVariable(shared));
        let mut second =
            ImplementedTraitGoal::new(TraitId::new(2), TraitGoalType::InferenceVariable(shared));
        second
            .push_argument(TraitGoalType::InferenceVariable(distinct))
            .unwrap();
        let mut predicates = ImplementedTraitPredicates::EMPTY;
        predicates.push(first).unwrap();
        predicates.push(second).unwrap();

        let canonical = canonicalize_implemented_trait_predicates(predicates).unwrap();
        assert_eq!(canonical.variables(), &[Some(shared), Some(distinct)]);
        assert_eq!(
            canonical.predicates(),
            &[
                Some(CanonicalImplementedTraitGoal {
                    trait_id: TraitId::new(1),
                    self_type: CanonicalTraitGoalType::BoundVariable(0),
                    arguments: [None; MAX_TRAIT_GOAL_ARGUMENTS],
                    argument_count: 0,
                    variable_count: 1,
                }),
                Some(CanonicalImplementedTraitGoal {
                    trait_id: TraitId::new(2),
                    self_type: CanonicalTraitGoalType::BoundVariable(0),
                    arguments: [
                        Some(CanonicalTraitGoalType::BoundVariable(1)),
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                    ],
                    argument_count: 1,
                    variable_count: 2,
                }),
            ]
        );
    }

    #[test]
    fn rejects_predicate_capacity_overflow() {
        let mut predicates = ImplementedTraitPredicates::EMPTY;
        for index in 0..MAX_TRAIT_PREDICATES {
            predicates
                .push(ImplementedTraitGoal::new(
                    TraitId::new(index as u32),
                    TraitGoalType::Concrete(TraitTypeId::new(index as u32)),
                ))
                .unwrap();
        }
        assert_eq!(
            predicates.push(ImplementedTraitGoal::new(
                TraitId::new(99),
                TraitGoalType::Concrete(TraitTypeId::new(99)),
            )),
            Err(TraitGoalError::TooManyPredicates)
        );
    }

    #[test]
    fn rejects_shared_variable_capacity_overflow_across_predicates() {
        let mut first = ImplementedTraitGoal::new(
            TraitId::new(1),
            TraitGoalType::InferenceVariable(TraitInferenceVariableId::new(0)),
        );
        for variable in 1..MAX_CANONICAL_TRAIT_VARIABLES {
            first
                .push_argument(TraitGoalType::InferenceVariable(
                    TraitInferenceVariableId::new(variable as u32),
                ))
                .unwrap();
        }
        let second = ImplementedTraitGoal::new(
            TraitId::new(2),
            TraitGoalType::InferenceVariable(TraitInferenceVariableId::new(99)),
        );
        let mut predicates = ImplementedTraitPredicates::EMPTY;
        predicates.push(first).unwrap();
        predicates.push(second).unwrap();
        assert_eq!(
            canonicalize_implemented_trait_predicates(predicates),
            Err(TraitGoalError::TooManyCanonicalVariables)
        );
    }

    #[test]
    fn instantiates_bounded_where_clause_parameters_consistently() {
        let first = TraitGenericParameterId::new(0);
        let second = TraitGenericParameterId::new(1);
        let mut consequence =
            BoundImplementedTraitGoal::new(TraitId::new(10), BoundTraitGoalType::Parameter(first));
        consequence
            .push_argument(BoundTraitGoalType::Parameter(second))
            .unwrap();
        let mut clause = TraitWhereClause::new(2, consequence).unwrap();
        let mut premise =
            BoundImplementedTraitGoal::new(TraitId::new(11), BoundTraitGoalType::Parameter(second));
        premise
            .push_argument(BoundTraitGoalType::Parameter(first))
            .unwrap();
        premise
            .push_argument(BoundTraitGoalType::Concrete(TraitTypeId::new(99)))
            .unwrap();
        clause.push_premise(premise).unwrap();

        let instantiated = clause
            .instantiate(&[TraitTypeId::new(20), TraitTypeId::new(30)])
            .unwrap();
        let mut query = ImplementedTraitGoal::new(
            TraitId::new(10),
            TraitGoalType::Concrete(TraitTypeId::new(20)),
        );
        query
            .push_argument(TraitGoalType::Concrete(TraitTypeId::new(30)))
            .unwrap();
        assert_eq!(
            clause.elaborate(query),
            Ok(TraitWhereClauseElaboration::Unique(instantiated))
        );
        assert_eq!(
            instantiated.consequence,
            ImplementedTraitGoal {
                trait_id: TraitId::new(10),
                self_type: TraitGoalType::Concrete(TraitTypeId::new(20)),
                arguments: [
                    Some(TraitGoalType::Concrete(TraitTypeId::new(30))),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                ],
                argument_count: 1,
            }
        );
        let premise = instantiated.premises.predicates()[0].unwrap();
        assert_eq!(
            premise.self_type,
            TraitGoalType::Concrete(TraitTypeId::new(30))
        );
        assert_eq!(
            premise.arguments(),
            &[
                Some(TraitGoalType::Concrete(TraitTypeId::new(20))),
                Some(TraitGoalType::Concrete(TraitTypeId::new(99))),
            ]
        );
    }

    #[test]
    fn instantiates_projection_where_clause_premises_and_bounds_combined_capacity() {
        let first = TraitGenericParameterId::new(0);
        let second = TraitGenericParameterId::new(1);
        let mut clause = TraitWhereClause::new(
            2,
            BoundImplementedTraitGoal::new(TraitId::new(700), BoundTraitGoalType::Parameter(first)),
        )
        .unwrap();
        clause
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(701),
                BoundTraitGoalType::Parameter(second),
            ))
            .unwrap();
        clause
            .push_projection_premise(
                BoundTraitProjection::new(
                    BoundImplementedTraitGoal::new(
                        TraitId::new(702),
                        BoundTraitGoalType::Parameter(first),
                    ),
                    TraitAssociatedTypeId::new(3),
                ),
                BoundTraitGoalType::Parameter(second),
            )
            .unwrap();
        let instantiated = clause
            .instantiate(&[TraitTypeId::new(10), TraitTypeId::new(20)])
            .unwrap();
        assert_eq!(instantiated.premises.predicates().len(), 1);
        assert_eq!(instantiated.projection_premises.predicates().len(), 1);
        assert_eq!(
            instantiated.projection_premises.predicates()[0],
            Some(InferredTraitProjectionEquality {
                goal: ImplementedTraitGoal::new(
                    TraitId::new(702),
                    TraitGoalType::Concrete(TraitTypeId::new(10)),
                ),
                associated_type_id: TraitAssociatedTypeId::new(3),
                expected: TraitGoalType::Concrete(TraitTypeId::new(20)),
            })
        );

        for index in 2..MAX_TRAIT_PREDICATES {
            clause
                .push_premise(BoundImplementedTraitGoal::new(
                    TraitId::new(710 + index as u32),
                    BoundTraitGoalType::Parameter(first),
                ))
                .unwrap();
        }
        assert_eq!(
            clause.push_projection_premise(
                BoundTraitProjection::new(
                    BoundImplementedTraitGoal::new(
                        TraitId::new(799),
                        BoundTraitGoalType::Parameter(first),
                    ),
                    TraitAssociatedTypeId::new(1),
                ),
                BoundTraitGoalType::Parameter(second),
            ),
            Err(TraitGoalError::TooManyPredicates)
        );
    }

    #[test]
    fn legacy_clause_proof_fails_closed_on_projection_premises() {
        let consequence = BoundImplementedTraitGoal::new(
            TraitId::new(703),
            BoundTraitGoalType::Concrete(TraitTypeId::new(1)),
        );
        let mut clause = TraitWhereClause::new(0, consequence).unwrap();
        clause
            .push_projection_premise(
                BoundTraitProjection::new(
                    BoundImplementedTraitGoal::new(
                        TraitId::new(704),
                        BoundTraitGoalType::Concrete(TraitTypeId::new(2)),
                    ),
                    TraitAssociatedTypeId::new(1),
                ),
                BoundTraitGoalType::Concrete(TraitTypeId::new(3)),
            )
            .unwrap();
        let mut clauses = TraitWhereClauseDatabase::EMPTY;
        clauses.insert(TraitWhereClauseId::new(70), clause).unwrap();
        let goal = ImplementedTraitGoal::new(
            TraitId::new(703),
            TraitGoalType::Concrete(TraitTypeId::new(1)),
        );
        let TraitWhereClauseSolution::Unique(answer) = clauses.elaborate(goal).unwrap() else {
            panic!("projection-bearing clause should elaborate before proof");
        };
        assert!(answer.instantiated.has_projection_premises());
        assert_eq!(
            solve_concrete_trait_goal(&TraitImplementationDatabase::EMPTY, &clauses, goal),
            Ok(TraitProofSolution::NoSolution)
        );
        assert_eq!(
            solve_rigid_trait_goal(&TraitImplementationDatabase::EMPTY, &clauses, goal),
            Ok(TraitProofSolution::NoSolution)
        );
    }

    #[test]
    fn concrete_projection_aware_proof_checks_associated_premises() {
        let associated = TraitAssociatedTypeId::new(1);
        let mut clause = TraitWhereClause::new(
            0,
            BoundImplementedTraitGoal::new(
                TraitId::new(705),
                BoundTraitGoalType::Concrete(TraitTypeId::new(1)),
            ),
        )
        .unwrap();
        clause
            .push_projection_premise(
                BoundTraitProjection::new(
                    BoundImplementedTraitGoal::new(
                        TraitId::new(706),
                        BoundTraitGoalType::Concrete(TraitTypeId::new(2)),
                    ),
                    associated,
                ),
                BoundTraitGoalType::Concrete(TraitTypeId::new(3)),
            )
            .unwrap();
        let mut clauses = TraitWhereClauseDatabase::EMPTY;
        clauses.insert(TraitWhereClauseId::new(71), clause).unwrap();

        let projection_implementation = TraitImplementationId::new(219);
        let mut exact = TraitImplementationDatabase::EMPTY;
        exact
            .insert(TraitImplementationHeader::new(
                projection_implementation,
                TraitId::new(706),
                TraitTypeId::new(2),
            ))
            .unwrap();
        let mut matching_values = TraitAssociatedTypeDatabase::EMPTY;
        matching_values
            .insert(
                &exact,
                TraitAssociatedTypeValue::new(
                    projection_implementation,
                    associated,
                    TraitTypeId::new(3),
                ),
            )
            .unwrap();
        let goal = ImplementedTraitGoal::new(
            TraitId::new(705),
            TraitGoalType::Concrete(TraitTypeId::new(1)),
        );
        assert_eq!(
            solve_concrete_trait_goal_with_projection_environment(
                &exact,
                &GenericTraitImplementationDatabase::EMPTY,
                &clauses,
                &matching_values,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                goal,
            ),
            Ok(TraitProofSolution::Proven)
        );

        let mut mismatching_values = TraitAssociatedTypeDatabase::EMPTY;
        mismatching_values
            .insert(
                &exact,
                TraitAssociatedTypeValue::new(
                    projection_implementation,
                    associated,
                    TraitTypeId::new(4),
                ),
            )
            .unwrap();
        assert_eq!(
            solve_concrete_trait_goal_with_projection_environment(
                &exact,
                &GenericTraitImplementationDatabase::EMPTY,
                &clauses,
                &mismatching_values,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                goal,
            ),
            Ok(TraitProofSolution::NoSolution)
        );
    }

    #[test]
    fn rigid_proof_checks_concrete_projection_premises_and_rejects_symbolic_ones() {
        let parameter = TraitGenericParameterId::new(0);
        let associated = TraitAssociatedTypeId::new(1);
        let mut concrete_projection_clause = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(707),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        concrete_projection_clause
            .push_projection_premise(
                BoundTraitProjection::new(
                    BoundImplementedTraitGoal::new(
                        TraitId::new(708),
                        BoundTraitGoalType::Concrete(TraitTypeId::new(2)),
                    ),
                    associated,
                ),
                BoundTraitGoalType::Concrete(TraitTypeId::new(3)),
            )
            .unwrap();
        let mut symbolic_projection_clause = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(709),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        symbolic_projection_clause
            .push_projection_premise(
                BoundTraitProjection::new(
                    BoundImplementedTraitGoal::new(
                        TraitId::new(708),
                        BoundTraitGoalType::Concrete(TraitTypeId::new(2)),
                    ),
                    associated,
                ),
                BoundTraitGoalType::Parameter(parameter),
            )
            .unwrap();
        let mut clauses = TraitWhereClauseDatabase::EMPTY;
        clauses
            .insert(TraitWhereClauseId::new(72), concrete_projection_clause)
            .unwrap();
        clauses
            .insert(TraitWhereClauseId::new(73), symbolic_projection_clause)
            .unwrap();

        let projection_implementation = TraitImplementationId::new(218);
        let mut exact = TraitImplementationDatabase::EMPTY;
        exact
            .insert(TraitImplementationHeader::new(
                projection_implementation,
                TraitId::new(708),
                TraitTypeId::new(2),
            ))
            .unwrap();
        let mut values = TraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &exact,
                TraitAssociatedTypeValue::new(
                    projection_implementation,
                    associated,
                    TraitTypeId::new(3),
                ),
            )
            .unwrap();
        let placeholder = TraitGoalType::Placeholder(TraitPlaceholder::new(
            TraitUniverseIndex::new(4),
            TraitPlaceholderId::new(0),
        ));
        let concrete_goal = ImplementedTraitGoal::new(TraitId::new(707), placeholder);
        assert_eq!(
            solve_rigid_trait_goal_with_concrete_projection_environment(
                &exact,
                &GenericTraitImplementationDatabase::EMPTY,
                &clauses,
                &values,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                concrete_goal,
            ),
            Ok(TraitProofSolution::Proven)
        );
        assert_eq!(
            solve_rigid_trait_goal_with_generics(
                &exact,
                &GenericTraitImplementationDatabase::EMPTY,
                &clauses,
                concrete_goal,
            ),
            Ok(TraitProofSolution::NoSolution)
        );
        assert_eq!(
            solve_rigid_trait_goal_with_concrete_projection_environment(
                &exact,
                &GenericTraitImplementationDatabase::EMPTY,
                &clauses,
                &values,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                ImplementedTraitGoal::new(TraitId::new(709), placeholder),
            ),
            Ok(TraitProofSolution::NoSolution)
        );
    }

    #[test]
    fn rigid_projection_normalization_preserves_placeholder_identity() {
        let parameter = TraitGenericParameterId::new(0);
        let associated = TraitAssociatedTypeId::new(1);
        let implementation_id = GenericTraitImplementationId::new(217);
        let implementation = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(710),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic.insert(implementation_id, implementation).unwrap();
        let mut values = GenericTraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &generic,
                GenericTraitAssociatedTypeValue::new(
                    implementation_id,
                    associated,
                    BoundTraitGoalType::Parameter(parameter),
                ),
            )
            .unwrap();

        let mut outer = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(711),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        outer
            .push_projection_premise(
                BoundTraitProjection::new(
                    BoundImplementedTraitGoal::new(
                        TraitId::new(710),
                        BoundTraitGoalType::Parameter(parameter),
                    ),
                    associated,
                ),
                BoundTraitGoalType::Parameter(parameter),
            )
            .unwrap();
        let mut clauses = TraitWhereClauseDatabase::EMPTY;
        clauses.insert(TraitWhereClauseId::new(74), outer).unwrap();
        let placeholder = TraitGoalType::Placeholder(TraitPlaceholder::new(
            TraitUniverseIndex::new(5),
            TraitPlaceholderId::new(0),
        ));
        assert_eq!(
            solve_rigid_trait_goal_with_projection_environment(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &clauses,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                ImplementedTraitGoal::new(TraitId::new(711), placeholder),
            ),
            Ok(TraitProofSolution::Proven)
        );
    }

    #[test]
    fn rigid_projection_normalization_reports_symbolic_cycles() {
        let parameter = TraitGenericParameterId::new(0);
        let associated = TraitAssociatedTypeId::new(1);
        let implementation_id = GenericTraitImplementationId::new(216);
        let implementation = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(712),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic.insert(implementation_id, implementation).unwrap();
        let mut values = GenericTraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &generic,
                GenericTraitAssociatedTypeValue::new_projection(
                    implementation_id,
                    associated,
                    BoundTraitProjection::new(
                        BoundImplementedTraitGoal::new(
                            TraitId::new(712),
                            BoundTraitGoalType::Parameter(parameter),
                        ),
                        associated,
                    ),
                ),
            )
            .unwrap();
        let mut outer = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(713),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        outer
            .push_projection_premise(
                BoundTraitProjection::new(
                    BoundImplementedTraitGoal::new(
                        TraitId::new(712),
                        BoundTraitGoalType::Parameter(parameter),
                    ),
                    associated,
                ),
                BoundTraitGoalType::Parameter(parameter),
            )
            .unwrap();
        let mut clauses = TraitWhereClauseDatabase::EMPTY;
        clauses.insert(TraitWhereClauseId::new(75), outer).unwrap();
        let placeholder = TraitGoalType::Placeholder(TraitPlaceholder::new(
            TraitUniverseIndex::new(6),
            TraitPlaceholderId::new(0),
        ));
        assert_eq!(
            solve_rigid_trait_goal_with_projection_environment(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &clauses,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                ImplementedTraitGoal::new(TraitId::new(713), placeholder),
            ),
            Ok(TraitProofSolution::Cycle)
        );
    }

    #[test]
    fn rigid_projection_normalization_proves_selected_implementation_premises() {
        let parameter = TraitGenericParameterId::new(0);
        let associated = TraitAssociatedTypeId::new(1);
        let projected_id = GenericTraitImplementationId::new(214);
        let mut projected = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(714),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        projected
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(715),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let prerequisite = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(715),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic.insert(projected_id, projected).unwrap();
        generic
            .insert(GenericTraitImplementationId::new(215), prerequisite)
            .unwrap();
        let mut values = GenericTraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &generic,
                GenericTraitAssociatedTypeValue::new(
                    projected_id,
                    associated,
                    BoundTraitGoalType::Parameter(parameter),
                ),
            )
            .unwrap();
        let mut outer = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(716),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        outer
            .push_projection_premise(
                BoundTraitProjection::new(
                    BoundImplementedTraitGoal::new(
                        TraitId::new(714),
                        BoundTraitGoalType::Parameter(parameter),
                    ),
                    associated,
                ),
                BoundTraitGoalType::Parameter(parameter),
            )
            .unwrap();
        let mut clauses = TraitWhereClauseDatabase::EMPTY;
        clauses.insert(TraitWhereClauseId::new(76), outer).unwrap();
        let placeholder = TraitGoalType::Placeholder(TraitPlaceholder::new(
            TraitUniverseIndex::new(7),
            TraitPlaceholderId::new(0),
        ));
        let goal = ImplementedTraitGoal::new(TraitId::new(716), placeholder);
        assert_eq!(
            solve_rigid_trait_goal_with_projection_environment(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &clauses,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                goal,
            ),
            Ok(TraitProofSolution::Proven)
        );

        let mut missing = GenericTraitImplementationDatabase::EMPTY;
        missing.insert(projected_id, projected).unwrap();
        assert_eq!(
            solve_rigid_trait_goal_with_projection_environment(
                &TraitImplementationDatabase::EMPTY,
                &missing,
                &clauses,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                goal,
            ),
            Ok(TraitProofSolution::NoSolution)
        );
    }

    #[test]
    fn rigid_projection_normalization_bounds_recursive_implementation_proof() {
        let parameter = TraitGenericParameterId::new(0);
        let associated = TraitAssociatedTypeId::new(1);
        let implementation_id = GenericTraitImplementationId::new(213);
        let mut recursive = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(717),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        recursive
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(717),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic.insert(implementation_id, recursive).unwrap();
        let mut values = GenericTraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &generic,
                GenericTraitAssociatedTypeValue::new(
                    implementation_id,
                    associated,
                    BoundTraitGoalType::Parameter(parameter),
                ),
            )
            .unwrap();
        let mut outer = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(718),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        outer
            .push_projection_premise(
                BoundTraitProjection::new(
                    BoundImplementedTraitGoal::new(
                        TraitId::new(717),
                        BoundTraitGoalType::Parameter(parameter),
                    ),
                    associated,
                ),
                BoundTraitGoalType::Parameter(parameter),
            )
            .unwrap();
        let mut clauses = TraitWhereClauseDatabase::EMPTY;
        clauses.insert(TraitWhereClauseId::new(77), outer).unwrap();
        let placeholder = TraitGoalType::Placeholder(TraitPlaceholder::new(
            TraitUniverseIndex::new(8),
            TraitPlaceholderId::new(0),
        ));
        assert_eq!(
            solve_rigid_trait_goal_with_projection_environment(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &clauses,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                ImplementedTraitGoal::new(TraitId::new(718), placeholder),
            ),
            Ok(TraitProofSolution::Cycle)
        );
    }

    #[test]
    fn rigid_projection_normalization_reports_implementation_proof_overflow() {
        let parameter = TraitGenericParameterId::new(0);
        let associated = TraitAssociatedTypeId::new(1);
        let projected_id = GenericTraitImplementationId::new(180);
        let mut projected = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(719),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        projected
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(720),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic.insert(projected_id, projected).unwrap();
        for index in 0..MAX_TRAIT_PROOF_DEPTH {
            let mut implementation = TraitWhereClause::new(
                1,
                BoundImplementedTraitGoal::new(
                    TraitId::new(720 + index as u32),
                    BoundTraitGoalType::Parameter(parameter),
                ),
            )
            .unwrap();
            implementation
                .push_premise(BoundImplementedTraitGoal::new(
                    TraitId::new(721 + index as u32),
                    BoundTraitGoalType::Parameter(parameter),
                ))
                .unwrap();
            generic
                .insert(
                    GenericTraitImplementationId::new(181 + index as u32),
                    implementation,
                )
                .unwrap();
        }
        let mut values = GenericTraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &generic,
                GenericTraitAssociatedTypeValue::new(
                    projected_id,
                    associated,
                    BoundTraitGoalType::Parameter(parameter),
                ),
            )
            .unwrap();
        let mut outer = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(750),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        outer
            .push_projection_premise(
                BoundTraitProjection::new(
                    BoundImplementedTraitGoal::new(
                        TraitId::new(719),
                        BoundTraitGoalType::Parameter(parameter),
                    ),
                    associated,
                ),
                BoundTraitGoalType::Parameter(parameter),
            )
            .unwrap();
        let mut clauses = TraitWhereClauseDatabase::EMPTY;
        clauses.insert(TraitWhereClauseId::new(78), outer).unwrap();
        let placeholder = TraitGoalType::Placeholder(TraitPlaceholder::new(
            TraitUniverseIndex::new(9),
            TraitPlaceholderId::new(0),
        ));
        assert_eq!(
            solve_rigid_trait_goal_with_projection_environment(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &clauses,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                ImplementedTraitGoal::new(TraitId::new(750), placeholder),
            ),
            Ok(TraitProofSolution::Overflow)
        );
    }

    #[test]
    fn projection_aware_clause_proof_refines_and_retries_mixed_premises() {
        let parameter = TraitGenericParameterId::new(0);
        let associated = TraitAssociatedTypeId::new(1);
        let mut clause = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(800),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        clause
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(801),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        clause
            .push_projection_premise(
                BoundTraitProjection::new(
                    BoundImplementedTraitGoal::new(
                        TraitId::new(802),
                        BoundTraitGoalType::Concrete(TraitTypeId::new(20)),
                    ),
                    associated,
                ),
                BoundTraitGoalType::Parameter(parameter),
            )
            .unwrap();
        let mut clauses = TraitWhereClauseDatabase::EMPTY;
        clauses.insert(TraitWhereClauseId::new(80), clause).unwrap();

        let projection_implementation = TraitImplementationId::new(220);
        let mut exact = TraitImplementationDatabase::EMPTY;
        for (id, ty) in [(221, 10), (222, 11)] {
            exact
                .insert(TraitImplementationHeader::new(
                    TraitImplementationId::new(id),
                    TraitId::new(801),
                    TraitTypeId::new(ty),
                ))
                .unwrap();
        }
        exact
            .insert(TraitImplementationHeader::new(
                projection_implementation,
                TraitId::new(802),
                TraitTypeId::new(20),
            ))
            .unwrap();
        let mut values = TraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &exact,
                TraitAssociatedTypeValue::new(
                    projection_implementation,
                    associated,
                    TraitTypeId::new(10),
                ),
            )
            .unwrap();
        let query = ExistsImplementedTraitGoal::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(800),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        let InferredTraitGoalSolution::Unique(answer) =
            solve_exists_trait_goal_with_projection_environment(
                &exact,
                &GenericTraitImplementationDatabase::EMPTY,
                &clauses,
                &values,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                TraitUniverseIndex::ROOT,
                query,
            )
            .unwrap()
        else {
            panic!("projection premise should refine the deferred trait premise");
        };
        assert_eq!(
            answer
                .substitution
                .binding(TraitInferenceVariableId::new(0)),
            Some(TraitGoalType::Concrete(TraitTypeId::new(10)))
        );

        let mut contradictory = TraitImplementationDatabase::EMPTY;
        contradictory
            .insert(TraitImplementationHeader::new(
                TraitImplementationId::new(223),
                TraitId::new(801),
                TraitTypeId::new(11),
            ))
            .unwrap();
        contradictory
            .insert(TraitImplementationHeader::new(
                projection_implementation,
                TraitId::new(802),
                TraitTypeId::new(20),
            ))
            .unwrap();
        assert_eq!(
            solve_exists_trait_goal_with_projection_environment(
                &contradictory,
                &GenericTraitImplementationDatabase::EMPTY,
                &clauses,
                &values,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                TraitUniverseIndex::ROOT,
                query,
            ),
            Ok(InferredTraitGoalSolution::NoSolution)
        );
    }

    #[test]
    fn projection_aware_generic_proof_solves_associated_premises() {
        let parameter = TraitGenericParameterId::new(0);
        let associated = TraitAssociatedTypeId::new(1);
        let mut implementation = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(803),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        implementation
            .push_projection_premise(
                BoundTraitProjection::new(
                    BoundImplementedTraitGoal::new(
                        TraitId::new(804),
                        BoundTraitGoalType::Concrete(TraitTypeId::new(20)),
                    ),
                    associated,
                ),
                BoundTraitGoalType::Parameter(parameter),
            )
            .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(GenericTraitImplementationId::new(224), implementation)
            .unwrap();
        let projection_implementation = TraitImplementationId::new(225);
        let mut exact = TraitImplementationDatabase::EMPTY;
        exact
            .insert(TraitImplementationHeader::new(
                projection_implementation,
                TraitId::new(804),
                TraitTypeId::new(20),
            ))
            .unwrap();
        let mut values = TraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &exact,
                TraitAssociatedTypeValue::new(
                    projection_implementation,
                    associated,
                    TraitTypeId::new(44),
                ),
            )
            .unwrap();
        let query = ExistsImplementedTraitGoal::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(803),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        let InferredTraitGoalSolution::Unique(answer) =
            solve_exists_trait_goal_with_projection_environment(
                &exact,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &values,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                TraitUniverseIndex::new(15),
                query,
            )
            .unwrap()
        else {
            panic!("generic projection premise should prove");
        };
        assert_eq!(
            answer
                .substitution
                .binding(TraitInferenceVariableId::in_universe(
                    TraitUniverseIndex::new(15),
                    0,
                )),
            Some(TraitGoalType::Concrete(TraitTypeId::new(44)))
        );
    }

    #[test]
    fn projection_normalization_recursively_proves_projection_premises() {
        let parameter = TraitGenericParameterId::new(0);
        let associated = TraitAssociatedTypeId::new(1);
        let mut root = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(805),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        root.push_projection_premise(
            BoundTraitProjection::new(
                BoundImplementedTraitGoal::new(
                    TraitId::new(806),
                    BoundTraitGoalType::Concrete(TraitTypeId::new(20)),
                ),
                associated,
            ),
            BoundTraitGoalType::Parameter(parameter),
        )
        .unwrap();
        let mut clauses = TraitWhereClauseDatabase::EMPTY;
        clauses.insert(TraitWhereClauseId::new(81), root).unwrap();

        let implementation_id = GenericTraitImplementationId::new(226);
        let mut projected_implementation = TraitWhereClause::new(
            0,
            BoundImplementedTraitGoal::new(
                TraitId::new(806),
                BoundTraitGoalType::Concrete(TraitTypeId::new(20)),
            ),
        )
        .unwrap();
        projected_implementation
            .push_projection_premise(
                BoundTraitProjection::new(
                    BoundImplementedTraitGoal::new(
                        TraitId::new(807),
                        BoundTraitGoalType::Concrete(TraitTypeId::new(30)),
                    ),
                    associated,
                ),
                BoundTraitGoalType::Concrete(TraitTypeId::new(40)),
            )
            .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(implementation_id, projected_implementation)
            .unwrap();
        let mut generic_values = GenericTraitAssociatedTypeDatabase::EMPTY;
        generic_values
            .insert(
                &generic,
                GenericTraitAssociatedTypeValue::new(
                    implementation_id,
                    associated,
                    BoundTraitGoalType::Concrete(TraitTypeId::new(50)),
                ),
            )
            .unwrap();
        let prerequisite_id = TraitImplementationId::new(227);
        let mut exact = TraitImplementationDatabase::EMPTY;
        exact
            .insert(TraitImplementationHeader::new(
                prerequisite_id,
                TraitId::new(807),
                TraitTypeId::new(30),
            ))
            .unwrap();
        let mut exact_values = TraitAssociatedTypeDatabase::EMPTY;
        exact_values
            .insert(
                &exact,
                TraitAssociatedTypeValue::new(prerequisite_id, associated, TraitTypeId::new(40)),
            )
            .unwrap();
        let query = ExistsImplementedTraitGoal::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(805),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        let InferredTraitGoalSolution::Unique(answer) =
            solve_exists_trait_goal_with_projection_environment(
                &exact,
                &generic,
                &clauses,
                &exact_values,
                &generic_values,
                TraitUniverseIndex::ROOT,
                query,
            )
            .unwrap()
        else {
            panic!("nested projection premise should prove recursively");
        };
        assert_eq!(
            answer
                .substitution
                .binding(TraitInferenceVariableId::new(0)),
            Some(TraitGoalType::Concrete(TraitTypeId::new(50)))
        );
    }

    #[test]
    fn recursive_projection_premise_proof_reports_bounded_overflow() {
        let associated = TraitAssociatedTypeId::new(1);
        let implementation_id = GenericTraitImplementationId::new(228);
        let mut implementation = TraitWhereClause::new(
            0,
            BoundImplementedTraitGoal::new(
                TraitId::new(808),
                BoundTraitGoalType::Concrete(TraitTypeId::new(9)),
            ),
        )
        .unwrap();
        implementation
            .push_projection_premise(
                BoundTraitProjection::new(
                    BoundImplementedTraitGoal::new(
                        TraitId::new(808),
                        BoundTraitGoalType::Concrete(TraitTypeId::new(9)),
                    ),
                    associated,
                ),
                BoundTraitGoalType::Concrete(TraitTypeId::new(9)),
            )
            .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic.insert(implementation_id, implementation).unwrap();
        let mut values = GenericTraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &generic,
                GenericTraitAssociatedTypeValue::new(
                    implementation_id,
                    associated,
                    BoundTraitGoalType::Concrete(TraitTypeId::new(9)),
                ),
            )
            .unwrap();
        let query = ExistsImplementedTraitGoal::new(
            0,
            BoundImplementedTraitGoal::new(
                TraitId::new(808),
                BoundTraitGoalType::Concrete(TraitTypeId::new(9)),
            ),
        )
        .unwrap();
        assert_eq!(
            solve_exists_trait_goal_with_projection_environment(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                TraitUniverseIndex::ROOT,
                query,
            ),
            Ok(InferredTraitGoalSolution::Overflow)
        );
    }

    #[test]
    fn instantiates_where_clause_parameters_as_rigid_universe_placeholders() {
        let mut consequence = BoundImplementedTraitGoal::new(
            TraitId::new(20),
            BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
        );
        consequence
            .push_argument(BoundTraitGoalType::Parameter(TraitGenericParameterId::new(
                1,
            )))
            .unwrap();
        let mut clause = TraitWhereClause::new(2, consequence).unwrap();
        clause
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(21),
                BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
            ))
            .unwrap();
        let universe = TraitUniverseIndex::new(7);
        let instantiated = clause.instantiate_rigid(universe).unwrap();
        let first = TraitPlaceholder::new(universe, TraitPlaceholderId::new(0));
        let second = TraitPlaceholder::new(universe, TraitPlaceholderId::new(1));
        assert_eq!(
            instantiated.consequence.self_type,
            TraitGoalType::Placeholder(first)
        );
        assert_eq!(
            instantiated.consequence.arguments(),
            &[Some(TraitGoalType::Placeholder(second))]
        );
        assert_eq!(
            instantiated.premises.predicates()[0].unwrap().self_type,
            TraitGoalType::Placeholder(first)
        );
        assert_ne!(
            instantiated,
            clause
                .instantiate_rigid(TraitUniverseIndex::new(8))
                .unwrap()
        );
        assert_eq!(
            canonicalize_implemented_trait_goal(instantiated.consequence)
                .unwrap()
                .self_type,
            CanonicalTraitGoalType::Placeholder(first)
        );
    }

    #[test]
    fn bounds_trait_placeholder_universe_creation() {
        assert_eq!(
            TraitUniverseIndex::ROOT.next(),
            Ok(TraitUniverseIndex::new(1))
        );
        assert_eq!(
            TraitUniverseIndex::new(u16::MAX).next(),
            Err(TraitGoalError::UniverseOverflow)
        );
    }

    #[test]
    fn canonicalization_distinguishes_inference_variable_universes() {
        let root = TraitInferenceVariableId::new(5);
        let nested = TraitInferenceVariableId::in_universe(TraitUniverseIndex::new(1), 5);
        assert_ne!(root, nested);
        assert_eq!(root.universe(), TraitUniverseIndex::ROOT);
        assert_eq!(nested.universe(), TraitUniverseIndex::new(1));
        let mut goal =
            ImplementedTraitGoal::new(TraitId::new(1), TraitGoalType::InferenceVariable(root));
        goal.push_argument(TraitGoalType::InferenceVariable(nested))
            .unwrap();
        let canonical = canonicalize_implemented_trait_goal(goal).unwrap();
        assert_eq!(
            canonical.self_type,
            CanonicalTraitGoalType::BoundVariable(0)
        );
        assert_eq!(
            canonical.arguments(),
            &[Some(CanonicalTraitGoalType::BoundVariable(1))]
        );
    }

    #[test]
    fn rejects_inference_assignments_that_leak_newer_universes() {
        let root = TraitInferenceVariableId::new(1);
        let nested = TraitInferenceVariableId::in_universe(TraitUniverseIndex::new(1), 2);
        let root_placeholder =
            TraitPlaceholder::new(TraitUniverseIndex::ROOT, TraitPlaceholderId::new(1));
        let nested_placeholder =
            TraitPlaceholder::new(TraitUniverseIndex::new(1), TraitPlaceholderId::new(1));
        assert!(
            TraitUniverseAssignment::new(root, TraitGoalType::Concrete(TraitTypeId::new(9)),)
                .is_ok()
        );
        assert!(
            TraitUniverseAssignment::new(root, TraitGoalType::Placeholder(root_placeholder))
                .is_ok()
        );
        assert!(
            TraitUniverseAssignment::new(nested, TraitGoalType::Placeholder(nested_placeholder),)
                .is_ok()
        );
        assert_eq!(
            TraitUniverseAssignment::new(root, TraitGoalType::Placeholder(nested_placeholder),),
            Err(TraitGoalError::UniverseLeak)
        );
        assert_eq!(
            TraitUniverseAssignment::new(root, TraitGoalType::InferenceVariable(nested)),
            Err(TraitGoalError::UniverseLeak)
        );
    }

    #[test]
    fn elaborates_bound_clauses_against_rigid_placeholder_goals() {
        let parameter = TraitGenericParameterId::new(0);
        let mut consequence = BoundImplementedTraitGoal::new(
            TraitId::new(30),
            BoundTraitGoalType::Parameter(parameter),
        );
        consequence
            .push_argument(BoundTraitGoalType::Parameter(parameter))
            .unwrap();
        let mut clause = TraitWhereClause::new(1, consequence).unwrap();
        clause
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(31),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let placeholder =
            TraitPlaceholder::new(TraitUniverseIndex::new(2), TraitPlaceholderId::new(7));
        let mut query =
            ImplementedTraitGoal::new(TraitId::new(30), TraitGoalType::Placeholder(placeholder));
        query
            .push_argument(TraitGoalType::Placeholder(placeholder))
            .unwrap();
        let TraitWhereClauseElaboration::Unique(instantiated) =
            clause.elaborate_rigid(query).unwrap()
        else {
            panic!("expected one rigid clause answer");
        };
        assert_eq!(
            instantiated.premises.predicates()[0].unwrap().self_type,
            TraitGoalType::Placeholder(placeholder)
        );

        let mut mismatch = query;
        mismatch.arguments[0] = Some(TraitGoalType::Placeholder(TraitPlaceholder::new(
            TraitUniverseIndex::new(2),
            TraitPlaceholderId::new(8),
        )));
        assert_eq!(
            clause.elaborate_rigid(mismatch),
            Ok(TraitWhereClauseElaboration::NoSolution)
        );
    }

    #[test]
    fn rigid_clause_database_rejects_inference_queries() {
        let clause = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(40),
                BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
            ),
        )
        .unwrap();
        let mut database = TraitWhereClauseDatabase::EMPTY;
        database.insert(TraitWhereClauseId::new(1), clause).unwrap();
        let placeholder =
            TraitPlaceholder::new(TraitUniverseIndex::new(1), TraitPlaceholderId::new(0));
        let rigid =
            ImplementedTraitGoal::new(TraitId::new(40), TraitGoalType::Placeholder(placeholder));
        assert!(matches!(
            database.elaborate_rigid(rigid),
            Ok(TraitWhereClauseSolution::Unique(_))
        ));
        assert_eq!(
            database.elaborate_rigid(ImplementedTraitGoal::new(
                TraitId::new(40),
                TraitGoalType::InferenceVariable(TraitInferenceVariableId::new(0)),
            )),
            Err(TraitGoalError::NonRigidClauseQuery)
        );
    }

    #[test]
    fn recursively_proves_skolemized_rigid_clause_premises() {
        let parameter = TraitGenericParameterId::new(0);
        let mut root = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(50),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        root.push_premise(BoundImplementedTraitGoal::new(
            TraitId::new(51),
            BoundTraitGoalType::Parameter(parameter),
        ))
        .unwrap();
        let leaf = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(51),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        let mut clauses = TraitWhereClauseDatabase::EMPTY;
        clauses.insert(TraitWhereClauseId::new(1), root).unwrap();
        clauses.insert(TraitWhereClauseId::new(2), leaf).unwrap();
        let placeholder =
            TraitPlaceholder::new(TraitUniverseIndex::new(3), TraitPlaceholderId::new(4));
        assert_eq!(
            solve_rigid_trait_goal(
                &TraitImplementationDatabase::EMPTY,
                &clauses,
                ImplementedTraitGoal::new(
                    TraitId::new(50),
                    TraitGoalType::Placeholder(placeholder),
                ),
            ),
            Ok(TraitProofSolution::Proven)
        );
    }

    #[test]
    fn rigid_recursive_proof_reports_cycles_and_rejects_inference() {
        let parameter = TraitGenericParameterId::new(0);
        let mut cycle = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(60),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        cycle
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(60),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let mut clauses = TraitWhereClauseDatabase::EMPTY;
        clauses.insert(TraitWhereClauseId::new(1), cycle).unwrap();
        let placeholder =
            TraitPlaceholder::new(TraitUniverseIndex::new(1), TraitPlaceholderId::new(0));
        assert_eq!(
            solve_rigid_trait_goal(
                &TraitImplementationDatabase::EMPTY,
                &clauses,
                ImplementedTraitGoal::new(
                    TraitId::new(60),
                    TraitGoalType::Placeholder(placeholder),
                ),
            ),
            Ok(TraitProofSolution::Cycle)
        );
        assert_eq!(
            solve_rigid_trait_goal(
                &TraitImplementationDatabase::EMPTY,
                &clauses,
                ImplementedTraitGoal::new(
                    TraitId::new(60),
                    TraitGoalType::InferenceVariable(TraitInferenceVariableId::new(0)),
                ),
            ),
            Err(TraitGoalError::NonRigidClauseQuery)
        );
    }

    #[test]
    fn rejects_unbound_or_wrong_arity_where_clause_parameters() {
        let unbound = BoundImplementedTraitGoal::new(
            TraitId::new(1),
            BoundTraitGoalType::Parameter(TraitGenericParameterId::new(1)),
        );
        assert_eq!(
            TraitWhereClause::new(1, unbound),
            Err(TraitGoalError::UnboundGenericParameter)
        );
        let clause = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(1),
                BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
            ),
        )
        .unwrap();
        assert_eq!(
            clause.instantiate(&[]),
            Err(TraitGoalError::WrongGenericArgumentCount)
        );
        assert_eq!(
            TraitWhereClause::new(
                MAX_TRAIT_GENERIC_PARAMETERS + 1,
                BoundImplementedTraitGoal::new(
                    TraitId::new(1),
                    BoundTraitGoalType::Concrete(TraitTypeId::new(1)),
                ),
            ),
            Err(TraitGoalError::TooManyGenericParameters)
        );
    }

    #[test]
    fn classifies_clause_mismatch_ambiguity_and_nonconcrete_queries() {
        let parameter = TraitGenericParameterId::new(0);
        let mut repeated = BoundImplementedTraitGoal::new(
            TraitId::new(1),
            BoundTraitGoalType::Parameter(parameter),
        );
        repeated
            .push_argument(BoundTraitGoalType::Parameter(parameter))
            .unwrap();
        let repeated = TraitWhereClause::new(1, repeated).unwrap();
        let mut mismatch = ImplementedTraitGoal::new(
            TraitId::new(1),
            TraitGoalType::Concrete(TraitTypeId::new(10)),
        );
        mismatch
            .push_argument(TraitGoalType::Concrete(TraitTypeId::new(11)))
            .unwrap();
        assert_eq!(
            repeated.elaborate(mismatch),
            Ok(TraitWhereClauseElaboration::NoSolution)
        );

        let unconstrained = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(2),
                BoundTraitGoalType::Concrete(TraitTypeId::new(20)),
            ),
        )
        .unwrap();
        let concrete = ImplementedTraitGoal::new(
            TraitId::new(2),
            TraitGoalType::Concrete(TraitTypeId::new(20)),
        );
        assert_eq!(
            unconstrained.elaborate(concrete),
            Ok(TraitWhereClauseElaboration::Ambiguous)
        );

        let inference = ImplementedTraitGoal::new(
            TraitId::new(2),
            TraitGoalType::InferenceVariable(TraitInferenceVariableId::new(0)),
        );
        assert_eq!(
            unconstrained.elaborate(inference),
            Err(TraitGoalError::NonConcreteClauseQuery)
        );
    }

    #[test]
    fn clause_database_returns_identified_unique_answers_or_no_solution() {
        let parameter = TraitGenericParameterId::new(0);
        let consequence = BoundImplementedTraitGoal::new(
            TraitId::new(40),
            BoundTraitGoalType::Parameter(parameter),
        );
        let mut clause = TraitWhereClause::new(1, consequence).unwrap();
        clause
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(41),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let mut database = TraitWhereClauseDatabase::EMPTY;
        let id = TraitWhereClauseId::new(9);
        database.insert(id, clause).unwrap();
        let query = ImplementedTraitGoal::new(
            TraitId::new(40),
            TraitGoalType::Concrete(TraitTypeId::new(70)),
        );
        let TraitWhereClauseElaboration::Unique(instantiated) = clause.elaborate(query).unwrap()
        else {
            panic!("expected direct clause elaboration");
        };
        assert_eq!(
            database.elaborate(query),
            Ok(TraitWhereClauseSolution::Unique(TraitWhereClauseAnswer {
                clause_id: id,
                instantiated,
            }))
        );
        assert_eq!(
            database.elaborate(ImplementedTraitGoal::new(
                TraitId::new(99),
                TraitGoalType::Concrete(TraitTypeId::new(70)),
            )),
            Ok(TraitWhereClauseSolution::NoSolution)
        );
    }

    #[test]
    fn clause_database_reports_overlapping_candidates_as_ambiguous() {
        let generic = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(1),
                BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
            ),
        )
        .unwrap();
        let concrete = TraitWhereClause::new(
            0,
            BoundImplementedTraitGoal::new(
                TraitId::new(1),
                BoundTraitGoalType::Concrete(TraitTypeId::new(5)),
            ),
        )
        .unwrap();
        let mut database = TraitWhereClauseDatabase::EMPTY;
        database
            .insert(TraitWhereClauseId::new(1), generic)
            .unwrap();
        database
            .insert(TraitWhereClauseId::new(2), concrete)
            .unwrap();
        assert_eq!(
            database.elaborate(ImplementedTraitGoal::new(
                TraitId::new(1),
                TraitGoalType::Concrete(TraitTypeId::new(5)),
            )),
            Ok(TraitWhereClauseSolution::Ambiguous)
        );
    }

    #[test]
    fn clause_database_preserves_unconstrained_candidate_ambiguity() {
        let clause = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(2),
                BoundTraitGoalType::Concrete(TraitTypeId::new(8)),
            ),
        )
        .unwrap();
        let mut database = TraitWhereClauseDatabase::EMPTY;
        database.insert(TraitWhereClauseId::new(3), clause).unwrap();
        assert_eq!(
            database.elaborate(ImplementedTraitGoal::new(
                TraitId::new(2),
                TraitGoalType::Concrete(TraitTypeId::new(8)),
            )),
            Ok(TraitWhereClauseSolution::Ambiguous)
        );
    }

    #[test]
    fn clause_database_rejects_duplicates_and_capacity_overflow() {
        let clause = TraitWhereClause::new(
            0,
            BoundImplementedTraitGoal::new(
                TraitId::new(1),
                BoundTraitGoalType::Concrete(TraitTypeId::new(1)),
            ),
        )
        .unwrap();
        let distinct = TraitWhereClause::new(
            0,
            BoundImplementedTraitGoal::new(
                TraitId::new(2),
                BoundTraitGoalType::Concrete(TraitTypeId::new(2)),
            ),
        )
        .unwrap();
        let mut duplicates = TraitWhereClauseDatabase::EMPTY;
        duplicates
            .insert(TraitWhereClauseId::new(1), clause)
            .unwrap();
        assert_eq!(
            duplicates.insert(TraitWhereClauseId::new(1), distinct),
            Err(TraitGoalError::DuplicateWhereClauseId)
        );
        assert_eq!(
            duplicates.insert(TraitWhereClauseId::new(2), clause),
            Err(TraitGoalError::DuplicateWhereClause)
        );

        let mut full = TraitWhereClauseDatabase::EMPTY;
        for index in 0..MAX_TRAIT_WHERE_CLAUSES {
            full.insert(
                TraitWhereClauseId::new(index as u32),
                TraitWhereClause::new(
                    0,
                    BoundImplementedTraitGoal::new(
                        TraitId::new(index as u32),
                        BoundTraitGoalType::Concrete(TraitTypeId::new(index as u32)),
                    ),
                )
                .unwrap(),
            )
            .unwrap();
        }
        assert_eq!(
            full.insert(
                TraitWhereClauseId::new(100),
                TraitWhereClause::new(
                    0,
                    BoundImplementedTraitGoal::new(
                        TraitId::new(100),
                        BoundTraitGoalType::Concrete(TraitTypeId::new(100)),
                    ),
                )
                .unwrap(),
            ),
            Err(TraitGoalError::TooManyWhereClauses)
        );
    }

    #[test]
    fn generic_head_overlap_honors_repeated_parameter_equality() {
        let parameter = TraitGenericParameterId::new(0);
        let mut repeated_head = BoundImplementedTraitGoal::new(
            TraitId::new(70),
            BoundTraitGoalType::Parameter(parameter),
        );
        repeated_head
            .push_argument(BoundTraitGoalType::Parameter(parameter))
            .unwrap();
        let repeated = TraitWhereClause::new(1, repeated_head).unwrap();

        let mut equal_head = BoundImplementedTraitGoal::new(
            TraitId::new(70),
            BoundTraitGoalType::Concrete(TraitTypeId::new(3)),
        );
        equal_head
            .push_argument(BoundTraitGoalType::Concrete(TraitTypeId::new(3)))
            .unwrap();
        let equal = TraitWhereClause::new(0, equal_head).unwrap();

        let mut unequal_head = BoundImplementedTraitGoal::new(
            TraitId::new(70),
            BoundTraitGoalType::Concrete(TraitTypeId::new(3)),
        );
        unequal_head
            .push_argument(BoundTraitGoalType::Concrete(TraitTypeId::new(4)))
            .unwrap();
        let unequal = TraitWhereClause::new(0, unequal_head).unwrap();

        assert!(generic_trait_implementation_heads_overlap(repeated, equal));
        assert!(!generic_trait_implementation_heads_overlap(
            repeated, unequal
        ));
        assert!(!generic_trait_implementation_heads_overlap(
            repeated,
            concrete_clause(71, 3, None),
        ));
    }

    #[test]
    fn generic_head_overlap_unifies_parameters_from_both_binders() {
        let mut left = BoundImplementedTraitGoal::new(
            TraitId::new(80),
            BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
        );
        left.push_argument(BoundTraitGoalType::Parameter(TraitGenericParameterId::new(
            1,
        )))
        .unwrap();
        let left = TraitWhereClause::new(2, left).unwrap();
        let mut right = BoundImplementedTraitGoal::new(
            TraitId::new(80),
            BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
        );
        right
            .push_argument(BoundTraitGoalType::Parameter(TraitGenericParameterId::new(
                0,
            )))
            .unwrap();
        let right = TraitWhereClause::new(1, right).unwrap();
        assert!(generic_trait_implementation_heads_overlap(left, right));
    }

    #[test]
    fn generic_implementation_database_rejects_overlap_ids_and_overflow() {
        let parameter = TraitGenericParameterId::new(0);
        let generic = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(90),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        let concrete = concrete_clause(90, 5, None);
        let distinct = concrete_clause(91, 5, None);
        let mut database = GenericTraitImplementationDatabase::EMPTY;
        database
            .insert(GenericTraitImplementationId::new(1), generic)
            .unwrap();
        assert_eq!(
            database.insert(GenericTraitImplementationId::new(2), concrete),
            Err(TraitGoalError::OverlappingGenericImplementation)
        );
        assert_eq!(
            database.insert(GenericTraitImplementationId::new(1), distinct),
            Err(TraitGoalError::DuplicateGenericImplementationId)
        );
        database
            .insert(GenericTraitImplementationId::new(2), distinct)
            .unwrap();

        let mut full = GenericTraitImplementationDatabase::EMPTY;
        for index in 0..MAX_GENERIC_TRAIT_IMPLEMENTATIONS {
            full.insert(
                GenericTraitImplementationId::new(index as u32),
                concrete_clause(index as u32, index as u32, None),
            )
            .unwrap();
        }
        assert_eq!(
            full.insert(
                GenericTraitImplementationId::new(100),
                concrete_clause(100, 100, None),
            ),
            Err(TraitGoalError::TooManyGenericImplementations)
        );
    }

    #[test]
    fn selects_one_coherent_generic_implementation_and_instantiates_premises() {
        let parameter = TraitGenericParameterId::new(0);
        let mut implementation = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(100),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        implementation
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(101),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let id = GenericTraitImplementationId::new(7);
        let mut database = GenericTraitImplementationDatabase::EMPTY;
        database.insert(id, implementation).unwrap();
        let query = ImplementedTraitGoal::new(
            TraitId::new(100),
            TraitGoalType::Concrete(TraitTypeId::new(55)),
        );
        let GenericTraitImplementationSolution::Unique(answer) = database.select(query).unwrap()
        else {
            panic!("expected one coherent generic implementation");
        };
        assert_eq!(answer.implementation_id, id);
        assert_eq!(
            answer.instantiated.premises.predicates()[0]
                .unwrap()
                .self_type,
            TraitGoalType::Concrete(TraitTypeId::new(55))
        );
        assert_eq!(
            database.select(ImplementedTraitGoal::new(
                TraitId::new(102),
                TraitGoalType::Concrete(TraitTypeId::new(55)),
            )),
            Ok(GenericTraitImplementationSolution::NoSolution)
        );
    }

    #[test]
    fn generic_selection_preserves_unconstrained_ambiguity_and_rejects_inference() {
        let mut implementation = TraitWhereClause::new(
            2,
            BoundImplementedTraitGoal::new(
                TraitId::new(110),
                BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
            ),
        )
        .unwrap();
        implementation
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(111),
                BoundTraitGoalType::Parameter(TraitGenericParameterId::new(1)),
            ))
            .unwrap();
        let mut database = GenericTraitImplementationDatabase::EMPTY;
        database
            .insert(GenericTraitImplementationId::new(1), implementation)
            .unwrap();
        assert_eq!(
            database.select(ImplementedTraitGoal::new(
                TraitId::new(110),
                TraitGoalType::Concrete(TraitTypeId::new(1)),
            )),
            Ok(GenericTraitImplementationSolution::Ambiguous)
        );
        assert_eq!(
            database.select(ImplementedTraitGoal::new(
                TraitId::new(110),
                TraitGoalType::InferenceVariable(TraitInferenceVariableId::new(0)),
            )),
            Err(TraitGoalError::NonConcreteClauseQuery)
        );
    }

    #[test]
    fn rigid_generic_selection_preserves_placeholder_universes() {
        let parameter = TraitGenericParameterId::new(0);
        let mut head = BoundImplementedTraitGoal::new(
            TraitId::new(260),
            BoundTraitGoalType::Parameter(parameter),
        );
        head.push_argument(BoundTraitGoalType::Parameter(parameter))
            .unwrap();
        let mut implementations = GenericTraitImplementationDatabase::EMPTY;
        implementations
            .insert(
                GenericTraitImplementationId::new(1),
                TraitWhereClause::new(1, head).unwrap(),
            )
            .unwrap();
        let placeholder =
            TraitPlaceholder::new(TraitUniverseIndex::new(3), TraitPlaceholderId::new(7));
        let mut goal =
            ImplementedTraitGoal::new(TraitId::new(260), TraitGoalType::Placeholder(placeholder));
        goal.push_argument(TraitGoalType::Placeholder(placeholder))
            .unwrap();
        let GenericTraitImplementationSolution::Unique(answer) =
            implementations.select_rigid(goal).unwrap()
        else {
            panic!("expected one rigid generic implementation");
        };
        assert_eq!(
            answer.arguments(),
            &[Some(TraitGoalType::Placeholder(placeholder))]
        );

        let mut different_universe = goal;
        different_universe.arguments[0] = Some(TraitGoalType::Placeholder(TraitPlaceholder::new(
            TraitUniverseIndex::new(4),
            TraitPlaceholderId::new(7),
        )));
        assert_eq!(
            implementations.select_rigid(different_universe),
            Ok(GenericTraitImplementationSolution::NoSolution)
        );
        assert_eq!(
            implementations.select_rigid(ImplementedTraitGoal::new(
                TraitId::new(260),
                TraitGoalType::InferenceVariable(TraitInferenceVariableId::new(0)),
            )),
            Err(TraitGoalError::NonRigidClauseQuery)
        );
    }

    #[test]
    fn recursively_proves_rigid_generic_implementation_premises() {
        let parameter = TraitGenericParameterId::new(0);
        let mut root = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(270),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        root.push_premise(BoundImplementedTraitGoal::new(
            TraitId::new(271),
            BoundTraitGoalType::Parameter(parameter),
        ))
        .unwrap();
        let leaf = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(271),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(GenericTraitImplementationId::new(1), root)
            .unwrap();
        let goal = ImplementedTraitGoal::new(
            TraitId::new(270),
            TraitGoalType::Placeholder(TraitPlaceholder::new(
                TraitUniverseIndex::new(5),
                TraitPlaceholderId::new(0),
            )),
        );
        assert_eq!(
            solve_rigid_trait_goal_with_generics(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                goal,
            ),
            Ok(TraitProofSolution::NoSolution)
        );
        generic
            .insert(GenericTraitImplementationId::new(2), leaf)
            .unwrap();
        assert_eq!(
            solve_rigid_trait_goal_with_generics(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                goal,
            ),
            Ok(TraitProofSolution::Proven)
        );
    }

    #[test]
    fn rigid_generic_proof_reports_cycles_and_rejects_inference() {
        let parameter = TraitGenericParameterId::new(0);
        let mut cycle = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(280),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        cycle
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(280),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(GenericTraitImplementationId::new(1), cycle)
            .unwrap();
        assert_eq!(
            solve_rigid_trait_goal_with_generics(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                ImplementedTraitGoal::new(
                    TraitId::new(280),
                    TraitGoalType::Placeholder(TraitPlaceholder::new(
                        TraitUniverseIndex::new(1),
                        TraitPlaceholderId::new(1),
                    )),
                ),
            ),
            Ok(TraitProofSolution::Cycle)
        );
        assert_eq!(
            solve_rigid_trait_goal_with_generics(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                ImplementedTraitGoal::new(
                    TraitId::new(280),
                    TraitGoalType::InferenceVariable(TraitInferenceVariableId::new(0)),
                ),
            ),
            Err(TraitGoalError::NonRigidClauseQuery)
        );
    }

    #[test]
    fn rigid_coinduction_accepts_only_fully_declared_cycles() {
        let parameter = TraitGenericParameterId::new(0);
        let first_trait = TraitId::new(281);
        let second_trait = TraitId::new(282);
        let mut first = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(first_trait, BoundTraitGoalType::Parameter(parameter)),
        )
        .unwrap();
        first
            .push_premise(BoundImplementedTraitGoal::new(
                second_trait,
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let mut second = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(second_trait, BoundTraitGoalType::Parameter(parameter)),
        )
        .unwrap();
        second
            .push_premise(BoundImplementedTraitGoal::new(
                first_trait,
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(GenericTraitImplementationId::new(3), first)
            .unwrap();
        generic
            .insert(GenericTraitImplementationId::new(4), second)
            .unwrap();
        let goal = ImplementedTraitGoal::new(
            first_trait,
            TraitGoalType::Placeholder(TraitPlaceholder::new(
                TraitUniverseIndex::new(1),
                TraitPlaceholderId::new(2),
            )),
        );

        assert_eq!(
            solve_rigid_trait_goal_with_coinduction(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &CoinductiveTraitDatabase::EMPTY,
                goal,
            ),
            Ok(TraitProofSolution::Cycle)
        );
        let mut coinductive = CoinductiveTraitDatabase::EMPTY;
        coinductive.insert(first_trait).unwrap();
        assert_eq!(
            solve_rigid_trait_goal_with_coinduction(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &coinductive,
                goal,
            ),
            Ok(TraitProofSolution::Cycle)
        );
        coinductive.insert(second_trait).unwrap();
        assert_eq!(coinductive.trait_count(), 2);
        assert_eq!(
            solve_rigid_trait_goal_with_coinduction(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &coinductive,
                goal,
            ),
            Ok(TraitProofSolution::Proven)
        );
        assert_eq!(
            coinductive.insert(first_trait),
            Err(TraitGoalError::DuplicateCoinductiveTrait)
        );

        let mut full = CoinductiveTraitDatabase::EMPTY;
        for index in 0..MAX_COINDUCTIVE_TRAITS {
            full.insert(TraitId::new(2_000 + index as u32)).unwrap();
        }
        assert_eq!(
            full.insert(TraitId::new(3_000)),
            Err(TraitGoalError::TooManyCoinductiveTraits)
        );
    }

    #[test]
    fn rigid_coinduction_preserves_projection_premise_checks() {
        let parameter = TraitGenericParameterId::new(0);
        let recursive_trait = TraitId::new(283);
        let projected_trait = TraitId::new(284);
        let associated = TraitAssociatedTypeId::new(3);
        let mut recursive = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                recursive_trait,
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        recursive
            .push_projection_premise(
                BoundTraitProjection::new(
                    BoundImplementedTraitGoal::new(
                        projected_trait,
                        BoundTraitGoalType::Parameter(parameter),
                    ),
                    associated,
                ),
                BoundTraitGoalType::Concrete(TraitTypeId::new(20)),
            )
            .unwrap();
        recursive
            .push_premise(BoundImplementedTraitGoal::new(
                recursive_trait,
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let projected = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                projected_trait,
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        let projected_id = GenericTraitImplementationId::new(6);
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(GenericTraitImplementationId::new(5), recursive)
            .unwrap();
        generic.insert(projected_id, projected).unwrap();
        let mut values = GenericTraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &generic,
                GenericTraitAssociatedTypeValue::new(
                    projected_id,
                    associated,
                    BoundTraitGoalType::Concrete(TraitTypeId::new(20)),
                ),
            )
            .unwrap();
        let goal = ImplementedTraitGoal::new(
            recursive_trait,
            TraitGoalType::Placeholder(TraitPlaceholder::new(
                TraitUniverseIndex::new(2),
                TraitPlaceholderId::new(0),
            )),
        );
        let mut coinductive = CoinductiveTraitDatabase::EMPTY;
        coinductive.insert(recursive_trait).unwrap();

        assert_eq!(
            solve_rigid_trait_goal_with_projection_environment(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                goal,
            ),
            Ok(TraitProofSolution::Cycle)
        );
        assert_eq!(
            solve_rigid_trait_goal_with_coinductive_projection_environment(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                &coinductive,
                goal,
            ),
            Ok(TraitProofSolution::Proven)
        );
        assert_eq!(
            solve_rigid_trait_goal_with_coinductive_projection_environment(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                &coinductive,
                goal,
            ),
            Ok(TraitProofSolution::NoSolution)
        );
    }

    #[test]
    fn inferred_coinduction_requires_a_fully_resolved_cycle() {
        let parameter = TraitGenericParameterId::new(0);
        let recursive_trait = TraitId::new(285);
        let constraining_trait = TraitId::new(286);
        let mut resolved = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                recursive_trait,
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        resolved
            .push_premise(BoundImplementedTraitGoal::new(
                constraining_trait,
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        resolved
            .push_premise(BoundImplementedTraitGoal::new(
                recursive_trait,
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(GenericTraitImplementationId::new(7), resolved)
            .unwrap();
        let mut exact = TraitImplementationDatabase::EMPTY;
        exact
            .insert(TraitImplementationHeader::new(
                TraitImplementationId::new(270),
                constraining_trait,
                TraitTypeId::new(10),
            ))
            .unwrap();
        let query = ExistsImplementedTraitGoal::new(
            1,
            BoundImplementedTraitGoal::new(
                recursive_trait,
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        let mut coinductive = CoinductiveTraitDatabase::EMPTY;
        coinductive.insert(recursive_trait).unwrap();

        assert_eq!(
            solve_exists_trait_goal_with_environment(
                &exact,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                TraitUniverseIndex::ROOT,
                query,
            ),
            Ok(InferredTraitGoalSolution::Cycle)
        );
        let InferredTraitGoalSolution::Unique(answer) = solve_exists_trait_goal_with_coinduction(
            &exact,
            &generic,
            &TraitWhereClauseDatabase::EMPTY,
            &coinductive,
            TraitUniverseIndex::ROOT,
            query,
        )
        .unwrap() else {
            panic!("resolved coinductive cycle should preserve its substitution");
        };
        assert_eq!(
            answer
                .substitution
                .binding(TraitInferenceVariableId::new(0)),
            Some(TraitGoalType::Concrete(TraitTypeId::new(10)))
        );

        let mut unresolved = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(287),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        unresolved
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(287),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let mut unresolved_generic = GenericTraitImplementationDatabase::EMPTY;
        unresolved_generic
            .insert(GenericTraitImplementationId::new(8), unresolved)
            .unwrap();
        let mut unresolved_coinductive = CoinductiveTraitDatabase::EMPTY;
        unresolved_coinductive.insert(TraitId::new(287)).unwrap();
        let unresolved_query = ExistsImplementedTraitGoal::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(287),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        assert_eq!(
            solve_exists_trait_goal_with_coinduction(
                &TraitImplementationDatabase::EMPTY,
                &unresolved_generic,
                &TraitWhereClauseDatabase::EMPTY,
                &unresolved_coinductive,
                TraitUniverseIndex::ROOT,
                unresolved_query,
            ),
            Ok(InferredTraitGoalSolution::Cycle)
        );
    }

    #[test]
    fn inferred_coinduction_accepts_projection_resolved_cycles() {
        let parameter = TraitGenericParameterId::new(0);
        let recursive_trait = TraitId::new(288);
        let projected_trait = TraitId::new(289);
        let associated = TraitAssociatedTypeId::new(4);
        let mut recursive = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                recursive_trait,
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        recursive
            .push_projection_premise(
                BoundTraitProjection::new(
                    BoundImplementedTraitGoal::new(
                        projected_trait,
                        BoundTraitGoalType::Parameter(parameter),
                    ),
                    associated,
                ),
                BoundTraitGoalType::Concrete(TraitTypeId::new(10)),
            )
            .unwrap();
        recursive
            .push_premise(BoundImplementedTraitGoal::new(
                recursive_trait,
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let projected = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                projected_trait,
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        let projected_id = GenericTraitImplementationId::new(10);
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(GenericTraitImplementationId::new(9), recursive)
            .unwrap();
        generic.insert(projected_id, projected).unwrap();
        let mut values = GenericTraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &generic,
                GenericTraitAssociatedTypeValue::new(
                    projected_id,
                    associated,
                    BoundTraitGoalType::Parameter(parameter),
                ),
            )
            .unwrap();
        let query = ExistsImplementedTraitGoal::new(
            1,
            BoundImplementedTraitGoal::new(
                recursive_trait,
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        let mut coinductive = CoinductiveTraitDatabase::EMPTY;
        coinductive.insert(recursive_trait).unwrap();

        assert_eq!(
            solve_exists_trait_goal_with_projection_environment(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                TraitUniverseIndex::ROOT,
                query,
            ),
            Ok(InferredTraitGoalSolution::Cycle)
        );
        let result = solve_exists_trait_goal_with_coinductive_projection_environment(
            &TraitImplementationDatabase::EMPTY,
            &generic,
            &TraitWhereClauseDatabase::EMPTY,
            &TraitAssociatedTypeDatabase::EMPTY,
            &values,
            &coinductive,
            TraitUniverseIndex::ROOT,
            query,
        )
        .unwrap();
        let InferredTraitGoalSolution::Unique(answer) = result else {
            panic!("projection-resolved coinductive cycle returned {result:?}");
        };
        assert_eq!(
            answer
                .substitution
                .binding(TraitInferenceVariableId::new(0)),
            Some(TraitGoalType::Concrete(TraitTypeId::new(10)))
        );
        assert_eq!(
            solve_exists_trait_goal_with_coinductive_projection_environment(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                &coinductive,
                TraitUniverseIndex::ROOT,
                query,
            ),
            Ok(InferredTraitGoalSolution::NoSolution)
        );
    }

    #[test]
    fn rigid_generic_proof_reports_depth_overflow() {
        let parameter = TraitGenericParameterId::new(0);
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        for index in 0..=MAX_TRAIT_PROOF_DEPTH {
            let mut implementation = TraitWhereClause::new(
                1,
                BoundImplementedTraitGoal::new(
                    TraitId::new(290 + index as u32),
                    BoundTraitGoalType::Parameter(parameter),
                ),
            )
            .unwrap();
            if index < MAX_TRAIT_PROOF_DEPTH {
                implementation
                    .push_premise(BoundImplementedTraitGoal::new(
                        TraitId::new(291 + index as u32),
                        BoundTraitGoalType::Parameter(parameter),
                    ))
                    .unwrap();
            }
            generic
                .insert(
                    GenericTraitImplementationId::new(index as u32),
                    implementation,
                )
                .unwrap();
        }
        assert_eq!(
            solve_rigid_trait_goal_with_generics(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                ImplementedTraitGoal::new(
                    TraitId::new(290),
                    TraitGoalType::Placeholder(TraitPlaceholder::new(
                        TraitUniverseIndex::new(2),
                        TraitPlaceholderId::new(0),
                    )),
                ),
            ),
            Ok(TraitProofSolution::Overflow)
        );
    }

    #[test]
    fn universal_goal_instantiation_creates_distinct_fresh_placeholders() {
        let mut goal = BoundImplementedTraitGoal::new(
            TraitId::new(320),
            BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
        );
        goal.push_argument(BoundTraitGoalType::Parameter(TraitGenericParameterId::new(
            1,
        )))
        .unwrap();
        let goal = ForAllImplementedTraitGoal::new(2, goal).unwrap();
        let instantiated = goal
            .instantiate_in_universe(TraitUniverseIndex::new(6))
            .unwrap();
        assert_eq!(
            instantiated.self_type,
            TraitGoalType::Placeholder(TraitPlaceholder::new(
                TraitUniverseIndex::new(6),
                TraitPlaceholderId::new(0),
            ))
        );
        assert_eq!(
            instantiated.arguments()[0],
            Some(TraitGoalType::Placeholder(TraitPlaceholder::new(
                TraitUniverseIndex::new(6),
                TraitPlaceholderId::new(1),
            )))
        );
        assert_eq!(goal.parameter_count(), 2);
    }

    #[test]
    fn proves_universal_goal_through_rigid_generic_premises() {
        let parameter = TraitGenericParameterId::new(0);
        let mut root = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(330),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        root.push_premise(BoundImplementedTraitGoal::new(
            TraitId::new(331),
            BoundTraitGoalType::Parameter(parameter),
        ))
        .unwrap();
        let leaf = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(331),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(GenericTraitImplementationId::new(1), root)
            .unwrap();
        generic
            .insert(GenericTraitImplementationId::new(2), leaf)
            .unwrap();
        let goal = ForAllImplementedTraitGoal::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(330),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        assert_eq!(
            solve_for_all_trait_goal_with_generics(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                TraitUniverseIndex::ROOT,
                goal,
            ),
            Ok(TraitProofSolution::Proven)
        );
    }

    #[test]
    fn universal_goal_preserves_ambiguity_and_universe_overflow() {
        let mut ambiguous = TraitWhereClause::new(
            2,
            BoundImplementedTraitGoal::new(
                TraitId::new(340),
                BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
            ),
        )
        .unwrap();
        ambiguous
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(341),
                BoundTraitGoalType::Parameter(TraitGenericParameterId::new(1)),
            ))
            .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(GenericTraitImplementationId::new(1), ambiguous)
            .unwrap();
        let goal = ForAllImplementedTraitGoal::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(340),
                BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
            ),
        )
        .unwrap();
        assert_eq!(
            solve_for_all_trait_goal_with_generics(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                TraitUniverseIndex::ROOT,
                goal,
            ),
            Ok(TraitProofSolution::Ambiguous)
        );
        assert_eq!(
            solve_for_all_trait_goal_with_generics(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                TraitUniverseIndex::new(u16::MAX),
                goal,
            ),
            Err(TraitGoalError::UniverseOverflow)
        );
        assert_eq!(
            ForAllImplementedTraitGoal::new(
                1,
                BoundImplementedTraitGoal::new(
                    TraitId::new(340),
                    BoundTraitGoalType::Parameter(TraitGenericParameterId::new(1)),
                ),
            ),
            Err(TraitGoalError::UnboundGenericParameter)
        );
    }

    #[test]
    fn existential_goal_recovers_universe_aware_bindings() {
        let mut implementation = TraitImplementationHeader::new(
            TraitImplementationId::new(51),
            TraitId::new(350),
            TraitTypeId::new(10),
        );
        implementation.push_argument(TraitTypeId::new(20)).unwrap();
        let mut implementations = TraitImplementationDatabase::EMPTY;
        implementations.insert(implementation).unwrap();
        let mut goal = BoundImplementedTraitGoal::new(
            TraitId::new(350),
            BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
        );
        goal.push_argument(BoundTraitGoalType::Parameter(TraitGenericParameterId::new(
            1,
        )))
        .unwrap();
        let goal = ExistsImplementedTraitGoal::new(2, goal).unwrap();
        let ExistentialTraitGoalSolution::Unique(answer) =
            solve_exists_trait_goal_exact(&implementations, TraitUniverseIndex::new(7), goal)
                .unwrap()
        else {
            panic!("expected one existential answer");
        };
        assert_eq!(answer.implementation_id, TraitImplementationId::new(51));
        assert_eq!(
            answer.substitution.bindings(),
            [
                Some(TraitInferenceBinding {
                    variable: TraitInferenceVariableId::in_universe(TraitUniverseIndex::new(7), 0,),
                    concrete_type: TraitTypeId::new(10),
                }),
                Some(TraitInferenceBinding {
                    variable: TraitInferenceVariableId::in_universe(TraitUniverseIndex::new(7), 1,),
                    concrete_type: TraitTypeId::new(20),
                }),
            ]
        );
        assert_eq!(goal.parameter_count(), 2);
    }

    #[test]
    fn existential_goal_enforces_repeated_variables() {
        let parameter = TraitGenericParameterId::new(0);
        let mut goal = BoundImplementedTraitGoal::new(
            TraitId::new(351),
            BoundTraitGoalType::Parameter(parameter),
        );
        goal.push_argument(BoundTraitGoalType::Parameter(parameter))
            .unwrap();
        let goal = ExistsImplementedTraitGoal::new(1, goal).unwrap();
        let mut implementations = TraitImplementationDatabase::EMPTY;
        let mut unequal = TraitImplementationHeader::new(
            TraitImplementationId::new(1),
            TraitId::new(351),
            TraitTypeId::new(10),
        );
        unequal.push_argument(TraitTypeId::new(20)).unwrap();
        implementations.insert(unequal).unwrap();
        assert_eq!(
            solve_exists_trait_goal_exact(&implementations, TraitUniverseIndex::ROOT, goal),
            Ok(ExistentialTraitGoalSolution::NoSolution)
        );
        let mut equal = TraitImplementationHeader::new(
            TraitImplementationId::new(2),
            TraitId::new(351),
            TraitTypeId::new(30),
        );
        equal.push_argument(TraitTypeId::new(30)).unwrap();
        implementations.insert(equal).unwrap();
        let ExistentialTraitGoalSolution::Unique(answer) =
            solve_exists_trait_goal_exact(&implementations, TraitUniverseIndex::ROOT, goal)
                .unwrap()
        else {
            panic!("expected the equal exact header");
        };
        assert_eq!(
            answer
                .substitution
                .binding(TraitInferenceVariableId::new(0)),
            Some(TraitTypeId::new(30))
        );
    }

    #[test]
    fn existential_goal_preserves_ambiguity_and_rejects_invalid_binders() {
        let goal = ExistsImplementedTraitGoal::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(352),
                BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
            ),
        )
        .unwrap();
        let mut implementations = TraitImplementationDatabase::EMPTY;
        for (id, ty) in [(1, 10), (2, 20)] {
            implementations
                .insert(TraitImplementationHeader::new(
                    TraitImplementationId::new(id),
                    TraitId::new(352),
                    TraitTypeId::new(ty),
                ))
                .unwrap();
        }
        assert_eq!(
            solve_exists_trait_goal_exact(&implementations, TraitUniverseIndex::new(2), goal),
            Ok(ExistentialTraitGoalSolution::Ambiguous)
        );
        assert_eq!(
            solve_exists_trait_goal_exact(
                &implementations,
                TraitUniverseIndex::new(2),
                ExistsImplementedTraitGoal::new(
                    0,
                    BoundImplementedTraitGoal::new(
                        TraitId::new(353),
                        BoundTraitGoalType::Concrete(TraitTypeId::new(1)),
                    ),
                )
                .unwrap(),
            ),
            Ok(ExistentialTraitGoalSolution::NoSolution)
        );
        assert_eq!(
            ExistsImplementedTraitGoal::new(
                1,
                BoundImplementedTraitGoal::new(
                    TraitId::new(352),
                    BoundTraitGoalType::Parameter(TraitGenericParameterId::new(1)),
                ),
            ),
            Err(TraitGoalError::UnboundGenericParameter)
        );
    }

    #[test]
    fn generic_existential_selection_retains_symbolic_identity() {
        let parameter = TraitGenericParameterId::new(0);
        let mut implementation = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(360),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        implementation
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(361),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(GenericTraitImplementationId::new(61), implementation)
            .unwrap();
        let goal = ExistsImplementedTraitGoal::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(360),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        let variable = TraitInferenceVariableId::in_universe(TraitUniverseIndex::new(8), 0);
        let GenericExistentialTraitGoalSolution::Unique(answer) =
            solve_exists_trait_goal_generic(&generic, TraitUniverseIndex::new(8), goal).unwrap()
        else {
            panic!("expected one symbolic generic answer");
        };
        assert_eq!(
            answer.substitution.binding(variable),
            Some(TraitGoalType::InferenceVariable(variable))
        );
        assert_eq!(
            answer.instantiated.premises.predicates()[0]
                .unwrap()
                .self_type,
            TraitGoalType::InferenceVariable(variable)
        );
    }

    #[test]
    fn generic_existential_selection_composes_equality_and_concrete_constraints() {
        let parameter = TraitGenericParameterId::new(0);
        let mut repeated_head = BoundImplementedTraitGoal::new(
            TraitId::new(362),
            BoundTraitGoalType::Parameter(parameter),
        );
        repeated_head
            .push_argument(BoundTraitGoalType::Parameter(parameter))
            .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(
                GenericTraitImplementationId::new(1),
                TraitWhereClause::new(1, repeated_head).unwrap(),
            )
            .unwrap();
        let mut query = BoundImplementedTraitGoal::new(
            TraitId::new(362),
            BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
        );
        query
            .push_argument(BoundTraitGoalType::Parameter(TraitGenericParameterId::new(
                1,
            )))
            .unwrap();
        let query = ExistsImplementedTraitGoal::new(2, query).unwrap();
        let first = TraitInferenceVariableId::in_universe(TraitUniverseIndex::new(9), 0);
        let second = TraitInferenceVariableId::in_universe(TraitUniverseIndex::new(9), 1);
        let GenericExistentialTraitGoalSolution::Unique(answer) =
            solve_exists_trait_goal_generic(&generic, TraitUniverseIndex::new(9), query).unwrap()
        else {
            panic!("expected one equality-constrained answer");
        };
        assert_eq!(
            answer.substitution.binding(first),
            Some(TraitGoalType::InferenceVariable(first))
        );
        assert_eq!(
            answer.substitution.binding(second),
            Some(TraitGoalType::InferenceVariable(first))
        );

        let concrete = TraitWhereClause::new(
            0,
            BoundImplementedTraitGoal::new(
                TraitId::new(363),
                BoundTraitGoalType::Concrete(TraitTypeId::new(55)),
            ),
        )
        .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(GenericTraitImplementationId::new(2), concrete)
            .unwrap();
        let query = ExistsImplementedTraitGoal::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(363),
                BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
            ),
        )
        .unwrap();
        let GenericExistentialTraitGoalSolution::Unique(answer) =
            solve_exists_trait_goal_generic(&generic, TraitUniverseIndex::new(4), query).unwrap()
        else {
            panic!("expected one concrete-constrained answer");
        };
        assert_eq!(
            answer
                .substitution
                .binding(TraitInferenceVariableId::in_universe(
                    TraitUniverseIndex::new(4),
                    0,
                )),
            Some(TraitGoalType::Concrete(TraitTypeId::new(55)))
        );
    }

    #[test]
    fn generic_existential_selection_preserves_ambiguity_and_rejects_rigid_queries() {
        let mut implementation = TraitWhereClause::new(
            2,
            BoundImplementedTraitGoal::new(
                TraitId::new(364),
                BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
            ),
        )
        .unwrap();
        implementation
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(365),
                BoundTraitGoalType::Parameter(TraitGenericParameterId::new(1)),
            ))
            .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(GenericTraitImplementationId::new(1), implementation)
            .unwrap();
        let query = ExistsImplementedTraitGoal::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(364),
                BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
            ),
        )
        .unwrap();
        assert_eq!(
            solve_exists_trait_goal_generic(&generic, TraitUniverseIndex::ROOT, query),
            Ok(GenericExistentialTraitGoalSolution::Ambiguous)
        );
        assert_eq!(
            generic.select_existential(ImplementedTraitGoal::new(
                TraitId::new(364),
                TraitGoalType::Placeholder(TraitPlaceholder::new(
                    TraitUniverseIndex::new(1),
                    TraitPlaceholderId::new(0),
                )),
            )),
            Err(TraitGoalError::NonExistentialClauseQuery)
        );
        assert_eq!(
            generic.select_existential(ImplementedTraitGoal::new(
                TraitId::new(999),
                TraitGoalType::InferenceVariable(TraitInferenceVariableId::new(0)),
            )),
            Ok(GenericExistentialTraitGoalSolution::NoSolution)
        );
    }

    #[test]
    fn inferred_generic_proof_composes_exact_premise_bindings() {
        let parameter = TraitGenericParameterId::new(0);
        let mut implementation = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(370),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        implementation
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(371),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(GenericTraitImplementationId::new(1), implementation)
            .unwrap();
        let mut exact = TraitImplementationDatabase::EMPTY;
        exact
            .insert(TraitImplementationHeader::new(
                TraitImplementationId::new(1),
                TraitId::new(371),
                TraitTypeId::new(77),
            ))
            .unwrap();
        let goal = ExistsImplementedTraitGoal::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(370),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        let variable = TraitInferenceVariableId::in_universe(TraitUniverseIndex::new(10), 0);
        let InferredTraitGoalSolution::Unique(answer) = solve_exists_trait_goal_with_generics(
            &exact,
            &generic,
            TraitUniverseIndex::new(10),
            goal,
        )
        .unwrap() else {
            panic!("expected inferred premise proof");
        };
        assert_eq!(
            answer.substitution.binding(variable),
            Some(TraitGoalType::Concrete(TraitTypeId::new(77)))
        );
    }

    #[test]
    fn inferred_generic_proof_recurses_and_rejects_conflicting_premises() {
        let parameter = TraitGenericParameterId::new(0);
        let mut root = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(372),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        root.push_premise(BoundImplementedTraitGoal::new(
            TraitId::new(373),
            BoundTraitGoalType::Parameter(parameter),
        ))
        .unwrap();
        let mut middle = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(373),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        middle
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(374),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(GenericTraitImplementationId::new(1), root)
            .unwrap();
        generic
            .insert(GenericTraitImplementationId::new(2), middle)
            .unwrap();
        let mut exact = TraitImplementationDatabase::EMPTY;
        exact
            .insert(TraitImplementationHeader::new(
                TraitImplementationId::new(1),
                TraitId::new(374),
                TraitTypeId::new(88),
            ))
            .unwrap();
        let goal = ExistsImplementedTraitGoal::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(372),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        assert!(matches!(
            solve_exists_trait_goal_with_generics(&exact, &generic, TraitUniverseIndex::ROOT, goal,),
            Ok(InferredTraitGoalSolution::Unique(_))
        ));

        let mut conflicting = root;
        conflicting
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(375),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(GenericTraitImplementationId::new(3), conflicting)
            .unwrap();
        exact
            .insert(TraitImplementationHeader::new(
                TraitImplementationId::new(2),
                TraitId::new(375),
                TraitTypeId::new(99),
            ))
            .unwrap();
        assert_eq!(
            solve_exists_trait_goal_with_generics(&exact, &generic, TraitUniverseIndex::ROOT, goal,),
            Ok(InferredTraitGoalSolution::NoSolution)
        );
    }

    #[test]
    fn inferred_generic_proof_reports_cycles_and_ambiguity() {
        let parameter = TraitGenericParameterId::new(0);
        let mut cycle = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(380),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        cycle
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(380),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(GenericTraitImplementationId::new(1), cycle)
            .unwrap();
        let goal = ExistsImplementedTraitGoal::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(380),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        assert_eq!(
            solve_exists_trait_goal_with_generics(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                TraitUniverseIndex::ROOT,
                goal,
            ),
            Ok(InferredTraitGoalSolution::Cycle)
        );

        let mut exact = TraitImplementationDatabase::EMPTY;
        for (id, ty) in [(1, 1), (2, 2)] {
            exact
                .insert(TraitImplementationHeader::new(
                    TraitImplementationId::new(id),
                    TraitId::new(380),
                    TraitTypeId::new(ty),
                ))
                .unwrap();
        }
        assert_eq!(
            solve_exists_trait_goal_with_generics(&exact, &generic, TraitUniverseIndex::ROOT, goal,),
            Ok(InferredTraitGoalSolution::Ambiguous)
        );
    }

    #[test]
    fn inferred_generic_proof_reports_depth_overflow() {
        let parameter = TraitGenericParameterId::new(0);
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        for index in 0..=MAX_TRAIT_PROOF_DEPTH {
            let mut implementation = TraitWhereClause::new(
                1,
                BoundImplementedTraitGoal::new(
                    TraitId::new(390 + index as u32),
                    BoundTraitGoalType::Parameter(parameter),
                ),
            )
            .unwrap();
            if index < MAX_TRAIT_PROOF_DEPTH {
                implementation
                    .push_premise(BoundImplementedTraitGoal::new(
                        TraitId::new(391 + index as u32),
                        BoundTraitGoalType::Parameter(parameter),
                    ))
                    .unwrap();
            }
            generic
                .insert(
                    GenericTraitImplementationId::new(index as u32),
                    implementation,
                )
                .unwrap();
        }
        let goal = ExistsImplementedTraitGoal::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(390),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        assert_eq!(
            solve_exists_trait_goal_with_generics(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                TraitUniverseIndex::ROOT,
                goal,
            ),
            Ok(InferredTraitGoalSolution::Overflow)
        );
    }

    #[test]
    fn inferred_where_clause_elaboration_retains_symbolic_answers() {
        let parameter = TraitGenericParameterId::new(0);
        let clause_id = TraitWhereClauseId::new(71);
        let mut clauses = TraitWhereClauseDatabase::EMPTY;
        clauses
            .insert(
                clause_id,
                TraitWhereClause::new(
                    1,
                    BoundImplementedTraitGoal::new(
                        TraitId::new(410),
                        BoundTraitGoalType::Parameter(parameter),
                    ),
                )
                .unwrap(),
            )
            .unwrap();
        let variable = TraitInferenceVariableId::in_universe(TraitUniverseIndex::new(11), 0);
        let InferredTraitWhereClauseSolution::Unique(answer) = clauses
            .elaborate_existential(ImplementedTraitGoal::new(
                TraitId::new(410),
                TraitGoalType::InferenceVariable(variable),
            ))
            .unwrap()
        else {
            panic!("expected one inferred where clause");
        };
        assert_eq!(answer.clause_id, clause_id);
        assert_eq!(
            answer.substitution.binding(variable),
            Some(TraitGoalType::InferenceVariable(variable))
        );
    }

    #[test]
    fn inferred_where_clause_premises_refine_root_answers() {
        let parameter = TraitGenericParameterId::new(0);
        let mut clause = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(411),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        clause
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(412),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let mut clauses = TraitWhereClauseDatabase::EMPTY;
        clauses.insert(TraitWhereClauseId::new(1), clause).unwrap();
        let mut exact = TraitImplementationDatabase::EMPTY;
        exact
            .insert(TraitImplementationHeader::new(
                TraitImplementationId::new(1),
                TraitId::new(412),
                TraitTypeId::new(66),
            ))
            .unwrap();
        let goal = ExistsImplementedTraitGoal::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(411),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        let variable = TraitInferenceVariableId::in_universe(TraitUniverseIndex::new(12), 0);
        let InferredTraitGoalSolution::Unique(answer) = solve_exists_trait_goal_with_environment(
            &exact,
            &GenericTraitImplementationDatabase::EMPTY,
            &clauses,
            TraitUniverseIndex::new(12),
            goal,
        )
        .unwrap() else {
            panic!("expected inferred clause premise proof");
        };
        assert_eq!(
            answer.substitution.binding(variable),
            Some(TraitGoalType::Concrete(TraitTypeId::new(66)))
        );
    }

    #[test]
    fn inferred_where_clause_proof_composes_with_generic_premises() {
        let parameter = TraitGenericParameterId::new(0);
        let mut clause = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(413),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        clause
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(414),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let mut clauses = TraitWhereClauseDatabase::EMPTY;
        clauses.insert(TraitWhereClauseId::new(1), clause).unwrap();
        let mut implementation = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(414),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        implementation
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(415),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(GenericTraitImplementationId::new(1), implementation)
            .unwrap();
        let mut exact = TraitImplementationDatabase::EMPTY;
        exact
            .insert(TraitImplementationHeader::new(
                TraitImplementationId::new(1),
                TraitId::new(415),
                TraitTypeId::new(67),
            ))
            .unwrap();
        let goal = ExistsImplementedTraitGoal::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(413),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        let InferredTraitGoalSolution::Unique(answer) = solve_exists_trait_goal_with_environment(
            &exact,
            &generic,
            &clauses,
            TraitUniverseIndex::ROOT,
            goal,
        )
        .unwrap() else {
            panic!("expected clause/generic inferred chain");
        };
        assert_eq!(
            answer
                .substitution
                .binding(TraitInferenceVariableId::new(0)),
            Some(TraitGoalType::Concrete(TraitTypeId::new(67)))
        );
    }

    #[test]
    fn inferred_where_clauses_preserve_ambiguity_and_cycles() {
        let parameter = TraitGenericParameterId::new(0);
        let mut clauses = TraitWhereClauseDatabase::EMPTY;
        for (id, premise_trait) in [(1, 421), (2, 422)] {
            let mut clause = TraitWhereClause::new(
                1,
                BoundImplementedTraitGoal::new(
                    TraitId::new(420),
                    BoundTraitGoalType::Parameter(parameter),
                ),
            )
            .unwrap();
            clause
                .push_premise(BoundImplementedTraitGoal::new(
                    TraitId::new(premise_trait),
                    BoundTraitGoalType::Parameter(parameter),
                ))
                .unwrap();
            clauses.insert(TraitWhereClauseId::new(id), clause).unwrap();
        }
        let query = ImplementedTraitGoal::new(
            TraitId::new(420),
            TraitGoalType::InferenceVariable(TraitInferenceVariableId::new(0)),
        );
        assert_eq!(
            clauses.elaborate_existential(query),
            Ok(InferredTraitWhereClauseSolution::Ambiguous)
        );

        let mut cycle = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(423),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        cycle
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(423),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let mut clauses = TraitWhereClauseDatabase::EMPTY;
        clauses.insert(TraitWhereClauseId::new(3), cycle).unwrap();
        let goal = ExistsImplementedTraitGoal::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(423),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        assert_eq!(
            solve_exists_trait_goal_with_environment(
                &TraitImplementationDatabase::EMPTY,
                &GenericTraitImplementationDatabase::EMPTY,
                &clauses,
                TraitUniverseIndex::ROOT,
                goal,
            ),
            Ok(InferredTraitGoalSolution::Cycle)
        );
    }

    #[test]
    fn inferred_where_clause_proof_reports_depth_overflow() {
        let parameter = TraitGenericParameterId::new(0);
        let mut clauses = TraitWhereClauseDatabase::EMPTY;
        for index in 0..=MAX_TRAIT_PROOF_DEPTH {
            let mut clause = TraitWhereClause::new(
                1,
                BoundImplementedTraitGoal::new(
                    TraitId::new(430 + index as u32),
                    BoundTraitGoalType::Parameter(parameter),
                ),
            )
            .unwrap();
            if index < MAX_TRAIT_PROOF_DEPTH {
                clause
                    .push_premise(BoundImplementedTraitGoal::new(
                        TraitId::new(431 + index as u32),
                        BoundTraitGoalType::Parameter(parameter),
                    ))
                    .unwrap();
            }
            clauses
                .insert(TraitWhereClauseId::new(index as u32), clause)
                .unwrap();
        }
        let goal = ExistsImplementedTraitGoal::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(430),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        assert_eq!(
            solve_exists_trait_goal_with_environment(
                &TraitImplementationDatabase::EMPTY,
                &GenericTraitImplementationDatabase::EMPTY,
                &clauses,
                TraitUniverseIndex::ROOT,
                goal,
            ),
            Ok(InferredTraitGoalSolution::Overflow)
        );
    }

    #[test]
    fn recursively_proves_generic_implementation_premises() {
        let parameter = TraitGenericParameterId::new(0);
        let mut root = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(120),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        root.push_premise(BoundImplementedTraitGoal::new(
            TraitId::new(121),
            BoundTraitGoalType::Parameter(parameter),
        ))
        .unwrap();
        let mut middle = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(121),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        middle
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(122),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(GenericTraitImplementationId::new(1), root)
            .unwrap();
        generic
            .insert(GenericTraitImplementationId::new(2), middle)
            .unwrap();
        let mut exact = TraitImplementationDatabase::EMPTY;
        exact
            .insert(TraitImplementationHeader::new(
                TraitImplementationId::new(1),
                TraitId::new(122),
                TraitTypeId::new(5),
            ))
            .unwrap();
        let query = ImplementedTraitGoal::new(
            TraitId::new(120),
            TraitGoalType::Concrete(TraitTypeId::new(5)),
        );
        assert_eq!(
            solve_concrete_trait_goal_with_generics(
                &exact,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                query,
            ),
            Ok(TraitProofSolution::Proven)
        );
        assert_eq!(
            solve_concrete_trait_goal_with_generics(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                query,
            ),
            Ok(TraitProofSolution::NoSolution)
        );
    }

    #[test]
    fn recursive_generic_proof_reports_cycles() {
        let parameter = TraitGenericParameterId::new(0);
        let mut cycle = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(130),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        cycle
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(130),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(GenericTraitImplementationId::new(1), cycle)
            .unwrap();
        assert_eq!(
            solve_concrete_trait_goal_with_generics(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                ImplementedTraitGoal::new(
                    TraitId::new(130),
                    TraitGoalType::Concrete(TraitTypeId::new(1)),
                ),
            ),
            Ok(TraitProofSolution::Cycle)
        );
    }

    #[test]
    fn recursive_generic_proof_rejects_exact_generic_collisions() {
        let mut exact = TraitImplementationDatabase::EMPTY;
        exact
            .insert(TraitImplementationHeader::new(
                TraitImplementationId::new(1),
                TraitId::new(140),
                TraitTypeId::new(1),
            ))
            .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(
                GenericTraitImplementationId::new(1),
                TraitWhereClause::new(
                    1,
                    BoundImplementedTraitGoal::new(
                        TraitId::new(140),
                        BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
                    ),
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            solve_concrete_trait_goal_with_generics(
                &exact,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                ImplementedTraitGoal::new(
                    TraitId::new(140),
                    TraitGoalType::Concrete(TraitTypeId::new(1)),
                ),
            ),
            Ok(TraitProofSolution::Ambiguous)
        );
    }

    #[test]
    fn rejects_exact_generic_overlap_in_either_admission_order() {
        let parameter = TraitGenericParameterId::new(0);
        let generic_implementation = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(150),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        let exact_implementation = TraitImplementationHeader::new(
            TraitImplementationId::new(1),
            TraitId::new(150),
            TraitTypeId::new(7),
        );

        let mut exact = TraitImplementationDatabase::EMPTY;
        exact.insert(exact_implementation).unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        assert_eq!(
            generic.insert_coherent_with_exact(
                &exact,
                GenericTraitImplementationId::new(1),
                generic_implementation,
            ),
            Err(TraitGoalError::OverlappingExactAndGenericImplementation)
        );

        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(GenericTraitImplementationId::new(1), generic_implementation)
            .unwrap();
        let mut exact = TraitImplementationDatabase::EMPTY;
        assert_eq!(
            exact.insert_coherent_with_generics(&generic, exact_implementation),
            Err(TraitGoalError::OverlappingExactAndGenericImplementation)
        );
    }

    #[test]
    fn admits_disjoint_exact_and_generic_implementations() {
        let mut exact_implementation = TraitImplementationHeader::new(
            TraitImplementationId::new(1),
            TraitId::new(160),
            TraitTypeId::new(1),
        );
        exact_implementation
            .push_argument(TraitTypeId::new(2))
            .unwrap();
        let mut exact = TraitImplementationDatabase::EMPTY;
        exact.insert(exact_implementation).unwrap();
        let parameter = TraitGenericParameterId::new(0);
        let mut generic_implementation = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(160),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        generic_implementation
            .consequence
            .push_argument(BoundTraitGoalType::Parameter(parameter))
            .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        assert_eq!(
            generic.insert_coherent_with_exact(
                &exact,
                GenericTraitImplementationId::new(1),
                generic_implementation,
            ),
            Ok(())
        );
    }

    #[test]
    fn recursively_proves_bounded_clause_premises_from_exact_facts() {
        let mut implementations = TraitImplementationDatabase::EMPTY;
        implementations
            .insert(TraitImplementationHeader::new(
                TraitImplementationId::new(30),
                TraitId::new(3),
                TraitTypeId::new(9),
            ))
            .unwrap();
        let mut clauses = TraitWhereClauseDatabase::EMPTY;
        clauses
            .insert(
                TraitWhereClauseId::new(1),
                concrete_clause(1, 9, Some((2, 9))),
            )
            .unwrap();
        clauses
            .insert(
                TraitWhereClauseId::new(2),
                concrete_clause(2, 9, Some((3, 9))),
            )
            .unwrap();
        let root = ImplementedTraitGoal::new(
            TraitId::new(1),
            TraitGoalType::Concrete(TraitTypeId::new(9)),
        );
        assert_eq!(
            solve_concrete_trait_goal(&implementations, &clauses, root),
            Ok(TraitProofSolution::Proven)
        );
        assert_eq!(
            solve_concrete_trait_goal(&TraitImplementationDatabase::EMPTY, &clauses, root,),
            Ok(TraitProofSolution::NoSolution)
        );
    }

    #[test]
    fn reports_recursive_trait_cycles_explicitly() {
        let mut clauses = TraitWhereClauseDatabase::EMPTY;
        clauses
            .insert(
                TraitWhereClauseId::new(1),
                concrete_clause(1, 4, Some((2, 4))),
            )
            .unwrap();
        clauses
            .insert(
                TraitWhereClauseId::new(2),
                concrete_clause(2, 4, Some((1, 4))),
            )
            .unwrap();
        assert_eq!(
            solve_concrete_trait_goal(
                &TraitImplementationDatabase::EMPTY,
                &clauses,
                ImplementedTraitGoal::new(
                    TraitId::new(1),
                    TraitGoalType::Concrete(TraitTypeId::new(4)),
                ),
            ),
            Ok(TraitProofSolution::Cycle)
        );
    }

    #[test]
    fn reports_recursive_trait_depth_overflow_explicitly() {
        let mut clauses = TraitWhereClauseDatabase::EMPTY;
        for depth in 0..=MAX_TRAIT_PROOF_DEPTH {
            clauses
                .insert(
                    TraitWhereClauseId::new(depth as u32),
                    concrete_clause(depth as u32, 1, Some(((depth + 1) as u32, 1))),
                )
                .unwrap();
        }
        assert_eq!(
            solve_concrete_trait_goal(
                &TraitImplementationDatabase::EMPTY,
                &clauses,
                ImplementedTraitGoal::new(
                    TraitId::new(0),
                    TraitGoalType::Concrete(TraitTypeId::new(1)),
                ),
            ),
            Ok(TraitProofSolution::Overflow)
        );

        let mut boundary_cycle = TraitWhereClauseDatabase::EMPTY;
        for depth in 0..MAX_TRAIT_PROOF_DEPTH {
            let next = if depth + 1 == MAX_TRAIT_PROOF_DEPTH {
                0
            } else {
                depth + 1
            };
            boundary_cycle
                .insert(
                    TraitWhereClauseId::new(depth as u32),
                    concrete_clause(depth as u32, 2, Some((next as u32, 2))),
                )
                .unwrap();
        }
        assert_eq!(
            solve_concrete_trait_goal(
                &TraitImplementationDatabase::EMPTY,
                &boundary_cycle,
                ImplementedTraitGoal::new(
                    TraitId::new(0),
                    TraitGoalType::Concrete(TraitTypeId::new(2)),
                ),
            ),
            Ok(TraitProofSolution::Cycle)
        );
    }

    #[test]
    fn propagates_recursive_premise_ambiguity() {
        let mut clauses = TraitWhereClauseDatabase::EMPTY;
        clauses
            .insert(
                TraitWhereClauseId::new(1),
                concrete_clause(1, 5, Some((2, 5))),
            )
            .unwrap();
        clauses
            .insert(TraitWhereClauseId::new(2), concrete_clause(2, 5, None))
            .unwrap();
        clauses
            .insert(
                TraitWhereClauseId::new(3),
                TraitWhereClause::new(
                    1,
                    BoundImplementedTraitGoal::new(
                        TraitId::new(2),
                        BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
                    ),
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            solve_concrete_trait_goal(
                &TraitImplementationDatabase::EMPTY,
                &clauses,
                ImplementedTraitGoal::new(
                    TraitId::new(1),
                    TraitGoalType::Concrete(TraitTypeId::new(5)),
                ),
            ),
            Ok(TraitProofSolution::Ambiguous)
        );
    }

    #[test]
    fn preserves_placeholders_and_concrete_types_without_binding_them() {
        let mut goal = ImplementedTraitGoal::new(
            TraitId::new(1),
            TraitGoalType::Placeholder(TraitPlaceholder::new(
                TraitUniverseIndex::ROOT,
                TraitPlaceholderId::new(4),
            )),
        );
        goal.push_argument(TraitGoalType::Concrete(TraitTypeId::new(8)))
            .unwrap();
        let canonical = canonicalize_implemented_trait_goal(goal).unwrap();
        assert_eq!(canonical.variable_count(), 0);
        assert_eq!(
            canonical.self_type,
            CanonicalTraitGoalType::Placeholder(TraitPlaceholder::new(
                TraitUniverseIndex::ROOT,
                TraitPlaceholderId::new(4),
            ))
        );
    }

    #[test]
    fn rejects_argument_capacity_overflow() {
        let mut goal = ImplementedTraitGoal::new(
            TraitId::new(1),
            TraitGoalType::Concrete(TraitTypeId::new(0)),
        );
        for index in 0..MAX_TRAIT_GOAL_ARGUMENTS {
            goal.push_argument(TraitGoalType::Concrete(TraitTypeId::new(index as u32)))
                .unwrap();
        }
        assert_eq!(
            goal.push_argument(TraitGoalType::Concrete(TraitTypeId::new(99))),
            Err(TraitGoalError::TooManyArguments)
        );
    }

    #[test]
    fn rejects_canonical_variable_capacity_overflow() {
        let mut goal = ImplementedTraitGoal::new(
            TraitId::new(1),
            TraitGoalType::InferenceVariable(TraitInferenceVariableId::new(0)),
        );
        for index in 0..MAX_TRAIT_GOAL_ARGUMENTS {
            goal.push_argument(TraitGoalType::InferenceVariable(
                TraitInferenceVariableId::new((index + 1) as u32),
            ))
            .unwrap();
        }
        assert_eq!(
            canonicalize_implemented_trait_goal(goal),
            Err(TraitGoalError::TooManyCanonicalVariables)
        );
    }

    #[test]
    fn selects_one_exact_concrete_implementation() {
        let mut database = TraitImplementationDatabase::EMPTY;
        let mut implementation = TraitImplementationHeader::new(
            TraitImplementationId::new(12),
            TraitId::new(3),
            TraitTypeId::new(8),
        );
        implementation.push_argument(TraitTypeId::new(9)).unwrap();
        database.insert(implementation).unwrap();
        let mut goal = ImplementedTraitGoal::new(
            TraitId::new(3),
            TraitGoalType::Concrete(TraitTypeId::new(8)),
        );
        goal.push_argument(TraitGoalType::Concrete(TraitTypeId::new(9)))
            .unwrap();

        assert_eq!(
            database.solve(canonicalize_implemented_trait_goal(goal).unwrap()),
            TraitGoalSolution::Unique(TraitGoalAnswer {
                implementation_id: TraitImplementationId::new(12),
                bindings: [None; MAX_CANONICAL_TRAIT_VARIABLES],
                binding_count: 0,
            })
        );
    }

    #[test]
    fn normalizes_exact_registered_associated_type_values() {
        let implementation_id = TraitImplementationId::new(12);
        let associated_type_id = TraitAssociatedTypeId::new(4);
        let mut implementations = TraitImplementationDatabase::EMPTY;
        implementations
            .insert(TraitImplementationHeader::new(
                implementation_id,
                TraitId::new(3),
                TraitTypeId::new(8),
            ))
            .unwrap();
        let mut associated_types = TraitAssociatedTypeDatabase::EMPTY;
        associated_types
            .insert(
                &implementations,
                TraitAssociatedTypeValue::new(
                    implementation_id,
                    associated_type_id,
                    TraitTypeId::new(90),
                ),
            )
            .unwrap();
        let goal = ImplementedTraitGoal::new(
            TraitId::new(3),
            TraitGoalType::Concrete(TraitTypeId::new(8)),
        );
        let goal = canonicalize_implemented_trait_goal(goal).unwrap();
        assert_eq!(
            associated_types.normalize(&implementations, goal, associated_type_id),
            TraitProjectionSolution::Unique(TraitTypeId::new(90))
        );
        assert_eq!(
            associated_types.normalize(&implementations, goal, TraitAssociatedTypeId::new(99),),
            TraitProjectionSolution::NoSolution
        );
    }

    #[test]
    fn projection_normalization_preserves_implementation_ambiguity() {
        let mut implementations = TraitImplementationDatabase::EMPTY;
        let mut associated_types = TraitAssociatedTypeDatabase::EMPTY;
        for (id, self_type, value) in [(1, 10, 100), (2, 20, 200)] {
            let implementation_id = TraitImplementationId::new(id);
            implementations
                .insert(TraitImplementationHeader::new(
                    implementation_id,
                    TraitId::new(5),
                    TraitTypeId::new(self_type),
                ))
                .unwrap();
            associated_types
                .insert(
                    &implementations,
                    TraitAssociatedTypeValue::new(
                        implementation_id,
                        TraitAssociatedTypeId::new(1),
                        TraitTypeId::new(value),
                    ),
                )
                .unwrap();
        }
        let inference = canonicalize_implemented_trait_goal(ImplementedTraitGoal::new(
            TraitId::new(5),
            TraitGoalType::InferenceVariable(TraitInferenceVariableId::new(0)),
        ))
        .unwrap();
        assert_eq!(
            associated_types.normalize(&implementations, inference, TraitAssociatedTypeId::new(1),),
            TraitProjectionSolution::Ambiguous
        );
        let absent = canonicalize_implemented_trait_goal(ImplementedTraitGoal::new(
            TraitId::new(6),
            TraitGoalType::Concrete(TraitTypeId::new(10)),
        ))
        .unwrap();
        assert_eq!(
            associated_types.normalize(&implementations, absent, TraitAssociatedTypeId::new(1),),
            TraitProjectionSolution::NoSolution
        );
    }

    #[test]
    fn rejects_stale_duplicate_and_excess_associated_type_values() {
        let implementation_id = TraitImplementationId::new(1);
        let mut implementations = TraitImplementationDatabase::EMPTY;
        implementations
            .insert(TraitImplementationHeader::new(
                implementation_id,
                TraitId::new(1),
                TraitTypeId::new(1),
            ))
            .unwrap();
        let mut values = TraitAssociatedTypeDatabase::EMPTY;
        assert_eq!(
            values.insert(
                &implementations,
                TraitAssociatedTypeValue::new(
                    TraitImplementationId::new(99),
                    TraitAssociatedTypeId::new(0),
                    TraitTypeId::new(0),
                ),
            ),
            Err(TraitGoalError::UnknownImplementationId)
        );
        for index in 0..MAX_TRAIT_ASSOCIATED_TYPE_VALUES {
            values
                .insert(
                    &implementations,
                    TraitAssociatedTypeValue::new(
                        implementation_id,
                        TraitAssociatedTypeId::new(index as u32),
                        TraitTypeId::new(index as u32),
                    ),
                )
                .unwrap();
        }
        assert_eq!(
            values.insert(
                &implementations,
                TraitAssociatedTypeValue::new(
                    implementation_id,
                    TraitAssociatedTypeId::new(0),
                    TraitTypeId::new(500),
                ),
            ),
            Err(TraitGoalError::DuplicateAssociatedTypeValue)
        );
        assert_eq!(
            values.insert(
                &implementations,
                TraitAssociatedTypeValue::new(
                    implementation_id,
                    TraitAssociatedTypeId::new(100),
                    TraitTypeId::new(100),
                ),
            ),
            Err(TraitGoalError::TooManyAssociatedTypeValues)
        );
    }

    #[test]
    fn normalizes_generic_associated_type_parameters_after_proof() {
        let parameter = TraitGenericParameterId::new(0);
        let implementation_id = GenericTraitImplementationId::new(21);
        let mut implementation = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(170),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        implementation
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(171),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let mut implementations = GenericTraitImplementationDatabase::EMPTY;
        implementations
            .insert(implementation_id, implementation)
            .unwrap();
        let associated_type_id = TraitAssociatedTypeId::new(2);
        let mut values = GenericTraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &implementations,
                GenericTraitAssociatedTypeValue::new(
                    implementation_id,
                    associated_type_id,
                    BoundTraitGoalType::Parameter(parameter),
                ),
            )
            .unwrap();
        let goal = ImplementedTraitGoal::new(
            TraitId::new(170),
            TraitGoalType::Concrete(TraitTypeId::new(44)),
        );
        assert_eq!(
            values.normalize(
                &TraitImplementationDatabase::EMPTY,
                &implementations,
                &TraitWhereClauseDatabase::EMPTY,
                goal,
                associated_type_id,
            ),
            Ok(TraitProjectionSolution::NoSolution)
        );
        let mut exact = TraitImplementationDatabase::EMPTY;
        exact
            .insert(TraitImplementationHeader::new(
                TraitImplementationId::new(1),
                TraitId::new(171),
                TraitTypeId::new(44),
            ))
            .unwrap();
        assert_eq!(
            values.normalize(
                &exact,
                &implementations,
                &TraitWhereClauseDatabase::EMPTY,
                goal,
                associated_type_id,
            ),
            Ok(TraitProjectionSolution::Unique(TraitTypeId::new(44)))
        );
    }

    #[test]
    fn generic_projection_preserves_ambiguity_and_missing_values() {
        let implementation_id = GenericTraitImplementationId::new(22);
        let implementation = TraitWhereClause::new(
            0,
            BoundImplementedTraitGoal::new(
                TraitId::new(180),
                BoundTraitGoalType::Concrete(TraitTypeId::new(3)),
            ),
        )
        .unwrap();
        let mut implementations = GenericTraitImplementationDatabase::EMPTY;
        implementations
            .insert(implementation_id, implementation)
            .unwrap();
        let values = GenericTraitAssociatedTypeDatabase::EMPTY;
        let goal = ImplementedTraitGoal::new(
            TraitId::new(180),
            TraitGoalType::Concrete(TraitTypeId::new(3)),
        );
        assert_eq!(
            values.normalize(
                &TraitImplementationDatabase::EMPTY,
                &implementations,
                &TraitWhereClauseDatabase::EMPTY,
                goal,
                TraitAssociatedTypeId::new(1),
            ),
            Ok(TraitProjectionSolution::NoSolution)
        );
        let mut exact = TraitImplementationDatabase::EMPTY;
        exact
            .insert(TraitImplementationHeader::new(
                TraitImplementationId::new(3),
                TraitId::new(180),
                TraitTypeId::new(3),
            ))
            .unwrap();
        assert_eq!(
            values.normalize(
                &exact,
                &implementations,
                &TraitWhereClauseDatabase::EMPTY,
                goal,
                TraitAssociatedTypeId::new(1),
            ),
            Ok(TraitProjectionSolution::Ambiguous)
        );
    }

    #[test]
    fn rejects_stale_duplicate_and_unbound_generic_associated_values() {
        let implementation_id = GenericTraitImplementationId::new(23);
        let mut implementations = GenericTraitImplementationDatabase::EMPTY;
        implementations
            .insert(
                implementation_id,
                TraitWhereClause::new(
                    1,
                    BoundImplementedTraitGoal::new(
                        TraitId::new(190),
                        BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
                    ),
                )
                .unwrap(),
            )
            .unwrap();
        let associated_type_id = TraitAssociatedTypeId::new(1);
        let value = GenericTraitAssociatedTypeValue::new(
            implementation_id,
            associated_type_id,
            BoundTraitGoalType::Concrete(TraitTypeId::new(9)),
        );
        let mut values = GenericTraitAssociatedTypeDatabase::EMPTY;
        assert_eq!(values.insert(&implementations, value), Ok(()));
        assert_eq!(
            values.insert(&implementations, value),
            Err(TraitGoalError::DuplicateGenericAssociatedTypeValue)
        );
        assert_eq!(
            values.insert(
                &implementations,
                GenericTraitAssociatedTypeValue::new(
                    GenericTraitImplementationId::new(99),
                    TraitAssociatedTypeId::new(2),
                    BoundTraitGoalType::Concrete(TraitTypeId::new(9)),
                ),
            ),
            Err(TraitGoalError::UnknownGenericImplementationId)
        );
        assert_eq!(
            values.insert(
                &implementations,
                GenericTraitAssociatedTypeValue::new(
                    implementation_id,
                    TraitAssociatedTypeId::new(2),
                    BoundTraitGoalType::Parameter(TraitGenericParameterId::new(1)),
                ),
            ),
            Err(TraitGoalError::UnboundGenericParameter)
        );
        assert_eq!(
            values.insert(
                &implementations,
                GenericTraitAssociatedTypeValue::new_projection(
                    implementation_id,
                    TraitAssociatedTypeId::new(3),
                    BoundTraitProjection::new(
                        BoundImplementedTraitGoal::new(
                            TraitId::new(191),
                            BoundTraitGoalType::Parameter(TraitGenericParameterId::new(1)),
                        ),
                        TraitAssociatedTypeId::new(1),
                    ),
                ),
            ),
            Err(TraitGoalError::UnboundGenericParameter)
        );
    }

    #[test]
    fn unified_projection_selects_exact_or_proven_generic_values() {
        let associated_type_id = TraitAssociatedTypeId::new(4);
        let exact_id = TraitImplementationId::new(31);
        let mut exact = TraitImplementationDatabase::EMPTY;
        exact
            .insert(TraitImplementationHeader::new(
                exact_id,
                TraitId::new(200),
                TraitTypeId::new(1),
            ))
            .unwrap();
        let mut exact_values = TraitAssociatedTypeDatabase::EMPTY;
        exact_values
            .insert(
                &exact,
                TraitAssociatedTypeValue::new(exact_id, associated_type_id, TraitTypeId::new(10)),
            )
            .unwrap();

        let parameter = TraitGenericParameterId::new(0);
        let generic_id = GenericTraitImplementationId::new(32);
        let mut generic_clause = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(201),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        generic_clause
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(202),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic.insert(generic_id, generic_clause).unwrap();
        let mut generic_values = GenericTraitAssociatedTypeDatabase::EMPTY;
        generic_values
            .insert(
                &generic,
                GenericTraitAssociatedTypeValue::new(
                    generic_id,
                    associated_type_id,
                    BoundTraitGoalType::Parameter(parameter),
                ),
            )
            .unwrap();
        exact
            .insert(TraitImplementationHeader::new(
                TraitImplementationId::new(33),
                TraitId::new(202),
                TraitTypeId::new(2),
            ))
            .unwrap();

        assert_eq!(
            normalize_concrete_trait_projection(
                &exact,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &exact_values,
                &generic_values,
                ImplementedTraitGoal::new(
                    TraitId::new(200),
                    TraitGoalType::Concrete(TraitTypeId::new(1)),
                ),
                associated_type_id,
            ),
            Ok(TraitProjectionSolution::Unique(TraitTypeId::new(10)))
        );
        assert_eq!(
            normalize_concrete_trait_projection(
                &exact,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &exact_values,
                &generic_values,
                ImplementedTraitGoal::new(
                    TraitId::new(201),
                    TraitGoalType::Concrete(TraitTypeId::new(2)),
                ),
                associated_type_id,
            ),
            Ok(TraitProjectionSolution::Unique(TraitTypeId::new(2)))
        );
        assert_eq!(
            normalize_concrete_trait_projection(
                &exact,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &exact_values,
                &generic_values,
                ImplementedTraitGoal::new(
                    TraitId::new(203),
                    TraitGoalType::Concrete(TraitTypeId::new(2)),
                ),
                associated_type_id,
            ),
            Ok(TraitProjectionSolution::NoSolution)
        );
    }

    #[test]
    fn unified_projection_rejects_unchecked_family_collisions() {
        let goal = ImplementedTraitGoal::new(
            TraitId::new(210),
            TraitGoalType::Concrete(TraitTypeId::new(5)),
        );
        let mut exact = TraitImplementationDatabase::EMPTY;
        exact
            .insert(TraitImplementationHeader::new(
                TraitImplementationId::new(1),
                TraitId::new(210),
                TraitTypeId::new(5),
            ))
            .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(
                GenericTraitImplementationId::new(1),
                TraitWhereClause::new(
                    1,
                    BoundImplementedTraitGoal::new(
                        TraitId::new(210),
                        BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
                    ),
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            normalize_concrete_trait_projection(
                &exact,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                goal,
                TraitAssociatedTypeId::new(1),
            ),
            Ok(TraitProjectionSolution::Ambiguous)
        );
    }

    #[test]
    fn normalizes_nested_generic_projection_into_exact_value() {
        let parameter = TraitGenericParameterId::new(0);
        let generic_id = GenericTraitImplementationId::new(41);
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(
                generic_id,
                TraitWhereClause::new(
                    1,
                    BoundImplementedTraitGoal::new(
                        TraitId::new(220),
                        BoundTraitGoalType::Parameter(parameter),
                    ),
                )
                .unwrap(),
            )
            .unwrap();
        let outer_associated = TraitAssociatedTypeId::new(1);
        let inner_associated = TraitAssociatedTypeId::new(2);
        let mut generic_values = GenericTraitAssociatedTypeDatabase::EMPTY;
        generic_values
            .insert(
                &generic,
                GenericTraitAssociatedTypeValue::new_projection(
                    generic_id,
                    outer_associated,
                    BoundTraitProjection::new(
                        BoundImplementedTraitGoal::new(
                            TraitId::new(221),
                            BoundTraitGoalType::Parameter(parameter),
                        ),
                        inner_associated,
                    ),
                ),
            )
            .unwrap();
        let exact_id = TraitImplementationId::new(42);
        let mut exact = TraitImplementationDatabase::EMPTY;
        exact
            .insert(TraitImplementationHeader::new(
                exact_id,
                TraitId::new(221),
                TraitTypeId::new(6),
            ))
            .unwrap();
        let mut exact_values = TraitAssociatedTypeDatabase::EMPTY;
        exact_values
            .insert(
                &exact,
                TraitAssociatedTypeValue::new(exact_id, inner_associated, TraitTypeId::new(77)),
            )
            .unwrap();
        assert_eq!(
            normalize_concrete_trait_projection(
                &exact,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &exact_values,
                &generic_values,
                ImplementedTraitGoal::new(
                    TraitId::new(220),
                    TraitGoalType::Concrete(TraitTypeId::new(6)),
                ),
                outer_associated,
            ),
            Ok(TraitProjectionSolution::Unique(TraitTypeId::new(77)))
        );
    }

    #[test]
    fn nested_projection_reports_cycles() {
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        let mut values = GenericTraitAssociatedTypeDatabase::EMPTY;
        let associated = TraitAssociatedTypeId::new(1);
        for (id, trait_id, next_trait_id) in [(1, 230, 231), (2, 231, 230)] {
            let implementation_id = GenericTraitImplementationId::new(id);
            generic
                .insert(
                    implementation_id,
                    TraitWhereClause::new(
                        0,
                        BoundImplementedTraitGoal::new(
                            TraitId::new(trait_id),
                            BoundTraitGoalType::Concrete(TraitTypeId::new(8)),
                        ),
                    )
                    .unwrap(),
                )
                .unwrap();
            values
                .insert(
                    &generic,
                    GenericTraitAssociatedTypeValue::new_projection(
                        implementation_id,
                        associated,
                        BoundTraitProjection::new(
                            BoundImplementedTraitGoal::new(
                                TraitId::new(next_trait_id),
                                BoundTraitGoalType::Concrete(TraitTypeId::new(8)),
                            ),
                            associated,
                        ),
                    ),
                )
                .unwrap();
        }
        assert_eq!(
            normalize_concrete_trait_projection(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                ImplementedTraitGoal::new(
                    TraitId::new(230),
                    TraitGoalType::Concrete(TraitTypeId::new(8)),
                ),
                associated,
            ),
            Ok(TraitProjectionSolution::Cycle)
        );
    }

    #[test]
    fn nested_projection_reports_depth_overflow() {
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        let mut values = GenericTraitAssociatedTypeDatabase::EMPTY;
        let associated = TraitAssociatedTypeId::new(1);
        for index in 0..=MAX_TRAIT_PROJECTION_DEPTH {
            let implementation_id = GenericTraitImplementationId::new(index as u32);
            generic
                .insert(
                    implementation_id,
                    TraitWhereClause::new(
                        0,
                        BoundImplementedTraitGoal::new(
                            TraitId::new(240 + index as u32),
                            BoundTraitGoalType::Concrete(TraitTypeId::new(9)),
                        ),
                    )
                    .unwrap(),
                )
                .unwrap();
            if index < MAX_TRAIT_PROJECTION_DEPTH {
                values
                    .insert(
                        &generic,
                        GenericTraitAssociatedTypeValue::new_projection(
                            implementation_id,
                            associated,
                            BoundTraitProjection::new(
                                BoundImplementedTraitGoal::new(
                                    TraitId::new(241 + index as u32),
                                    BoundTraitGoalType::Concrete(TraitTypeId::new(9)),
                                ),
                                associated,
                            ),
                        ),
                    )
                    .unwrap();
            }
        }
        assert_eq!(
            normalize_concrete_trait_projection(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                ImplementedTraitGoal::new(
                    TraitId::new(240),
                    TraitGoalType::Concrete(TraitTypeId::new(9)),
                ),
                associated,
            ),
            Ok(TraitProjectionSolution::Overflow)
        );
    }

    #[test]
    fn inferred_projection_equality_recovers_exact_input_and_output() {
        let implementation_id = TraitImplementationId::new(81);
        let associated_type_id = TraitAssociatedTypeId::new(1);
        let mut exact = TraitImplementationDatabase::EMPTY;
        exact
            .insert(TraitImplementationHeader::new(
                implementation_id,
                TraitId::new(500),
                TraitTypeId::new(10),
            ))
            .unwrap();
        let mut values = TraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &exact,
                TraitAssociatedTypeValue::new(
                    implementation_id,
                    associated_type_id,
                    TraitTypeId::new(99),
                ),
            )
            .unwrap();
        let query = ExistsTraitProjectionEquality::new(
            2,
            BoundTraitProjection::new(
                BoundImplementedTraitGoal::new(
                    TraitId::new(500),
                    BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
                ),
                associated_type_id,
            ),
            BoundTraitGoalType::Parameter(TraitGenericParameterId::new(1)),
        )
        .unwrap();
        let InferredTraitProjectionSolution::Unique(answer) =
            solve_exists_trait_projection_equality(
                &exact,
                &GenericTraitImplementationDatabase::EMPTY,
                &TraitWhereClauseDatabase::EMPTY,
                &values,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                TraitUniverseIndex::new(13),
                query,
            )
            .unwrap()
        else {
            panic!("expected exact inferred projection equality");
        };
        assert_eq!(
            answer
                .substitution
                .binding(TraitInferenceVariableId::in_universe(
                    TraitUniverseIndex::new(13),
                    0,
                )),
            Some(TraitGoalType::Concrete(TraitTypeId::new(10)))
        );
        assert_eq!(
            answer
                .substitution
                .binding(TraitInferenceVariableId::in_universe(
                    TraitUniverseIndex::new(13),
                    1,
                )),
            Some(TraitGoalType::Concrete(TraitTypeId::new(99)))
        );
    }

    #[test]
    fn inferred_projection_equality_unifies_generic_associated_parameters() {
        let parameter = TraitGenericParameterId::new(0);
        let implementation_id = GenericTraitImplementationId::new(82);
        let associated_type_id = TraitAssociatedTypeId::new(1);
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(
                implementation_id,
                TraitWhereClause::new(
                    1,
                    BoundImplementedTraitGoal::new(
                        TraitId::new(501),
                        BoundTraitGoalType::Parameter(parameter),
                    ),
                )
                .unwrap(),
            )
            .unwrap();
        let mut values = GenericTraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &generic,
                GenericTraitAssociatedTypeValue::new(
                    implementation_id,
                    associated_type_id,
                    BoundTraitGoalType::Parameter(parameter),
                ),
            )
            .unwrap();
        let query = ExistsTraitProjectionEquality::new(
            2,
            BoundTraitProjection::new(
                BoundImplementedTraitGoal::new(
                    TraitId::new(501),
                    BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
                ),
                associated_type_id,
            ),
            BoundTraitGoalType::Parameter(TraitGenericParameterId::new(1)),
        )
        .unwrap();
        let InferredTraitProjectionSolution::Unique(answer) =
            solve_exists_trait_projection_equality(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                TraitUniverseIndex::ROOT,
                query,
            )
            .unwrap()
        else {
            panic!("expected generic inferred projection equality");
        };
        assert_eq!(
            answer
                .substitution
                .binding(TraitInferenceVariableId::new(1)),
            Some(TraitGoalType::InferenceVariable(
                TraitInferenceVariableId::new(0)
            ))
        );
    }

    #[test]
    fn inferred_projection_equality_proves_generic_premises_and_rejects_mismatch() {
        let parameter = TraitGenericParameterId::new(0);
        let implementation_id = GenericTraitImplementationId::new(83);
        let associated_type_id = TraitAssociatedTypeId::new(1);
        let mut implementation = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(502),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        implementation
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(503),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic.insert(implementation_id, implementation).unwrap();
        let mut generic_values = GenericTraitAssociatedTypeDatabase::EMPTY;
        generic_values
            .insert(
                &generic,
                GenericTraitAssociatedTypeValue::new(
                    implementation_id,
                    associated_type_id,
                    BoundTraitGoalType::Parameter(parameter),
                ),
            )
            .unwrap();
        let mut exact = TraitImplementationDatabase::EMPTY;
        exact
            .insert(TraitImplementationHeader::new(
                TraitImplementationId::new(1),
                TraitId::new(503),
                TraitTypeId::new(44),
            ))
            .unwrap();
        let matching = ExistsTraitProjectionEquality::new(
            1,
            BoundTraitProjection::new(
                BoundImplementedTraitGoal::new(
                    TraitId::new(502),
                    BoundTraitGoalType::Parameter(parameter),
                ),
                associated_type_id,
            ),
            BoundTraitGoalType::Concrete(TraitTypeId::new(44)),
        )
        .unwrap();
        assert!(matches!(
            solve_exists_trait_projection_equality(
                &exact,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &generic_values,
                TraitUniverseIndex::ROOT,
                matching,
            ),
            Ok(InferredTraitProjectionSolution::Unique(_))
        ));
        let mismatch = ExistsTraitProjectionEquality::new(
            1,
            matching.projection,
            BoundTraitGoalType::Concrete(TraitTypeId::new(45)),
        )
        .unwrap();
        assert_eq!(
            solve_exists_trait_projection_equality(
                &exact,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &generic_values,
                TraitUniverseIndex::ROOT,
                mismatch,
            ),
            Ok(InferredTraitProjectionSolution::NoSolution)
        );
    }

    #[test]
    fn inferred_projection_equality_reports_nested_cycles_and_ambiguity() {
        let parameter = TraitGenericParameterId::new(0);
        let associated_type_id = TraitAssociatedTypeId::new(1);
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        let mut values = GenericTraitAssociatedTypeDatabase::EMPTY;
        let implementation_id = GenericTraitImplementationId::new(84);
        generic
            .insert(
                implementation_id,
                TraitWhereClause::new(
                    1,
                    BoundImplementedTraitGoal::new(
                        TraitId::new(504),
                        BoundTraitGoalType::Parameter(parameter),
                    ),
                )
                .unwrap(),
            )
            .unwrap();
        values
            .insert(
                &generic,
                GenericTraitAssociatedTypeValue::new_projection(
                    implementation_id,
                    associated_type_id,
                    BoundTraitProjection::new(
                        BoundImplementedTraitGoal::new(
                            TraitId::new(504),
                            BoundTraitGoalType::Parameter(parameter),
                        ),
                        associated_type_id,
                    ),
                ),
            )
            .unwrap();
        let query = ExistsTraitProjectionEquality::new(
            1,
            BoundTraitProjection::new(
                BoundImplementedTraitGoal::new(
                    TraitId::new(504),
                    BoundTraitGoalType::Parameter(parameter),
                ),
                associated_type_id,
            ),
            BoundTraitGoalType::Parameter(parameter),
        )
        .unwrap();
        assert_eq!(
            solve_exists_trait_projection_equality(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                TraitUniverseIndex::ROOT,
                query,
            ),
            Ok(InferredTraitProjectionSolution::Cycle)
        );

        let mut exact = TraitImplementationDatabase::EMPTY;
        for (id, ty) in [(1, 1), (2, 2)] {
            exact
                .insert(TraitImplementationHeader::new(
                    TraitImplementationId::new(id),
                    TraitId::new(505),
                    TraitTypeId::new(ty),
                ))
                .unwrap();
        }
        let ambiguous = ExistsTraitProjectionEquality::new(
            1,
            BoundTraitProjection::new(
                BoundImplementedTraitGoal::new(
                    TraitId::new(505),
                    BoundTraitGoalType::Parameter(parameter),
                ),
                associated_type_id,
            ),
            BoundTraitGoalType::Parameter(parameter),
        )
        .unwrap();
        assert_eq!(
            solve_exists_trait_projection_equality(
                &exact,
                &GenericTraitImplementationDatabase::EMPTY,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                TraitUniverseIndex::ROOT,
                ambiguous,
            ),
            Ok(InferredTraitProjectionSolution::Ambiguous)
        );
    }

    #[test]
    fn inferred_projection_equality_reports_nested_depth_overflow() {
        let parameter = TraitGenericParameterId::new(0);
        let associated = TraitAssociatedTypeId::new(1);
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        let mut values = GenericTraitAssociatedTypeDatabase::EMPTY;
        for index in 0..=MAX_TRAIT_PROJECTION_DEPTH {
            let implementation_id = GenericTraitImplementationId::new(100 + index as u32);
            generic
                .insert(
                    implementation_id,
                    TraitWhereClause::new(
                        1,
                        BoundImplementedTraitGoal::new(
                            TraitId::new(510 + index as u32),
                            BoundTraitGoalType::Parameter(parameter),
                        ),
                    )
                    .unwrap(),
                )
                .unwrap();
            if index < MAX_TRAIT_PROJECTION_DEPTH {
                values
                    .insert(
                        &generic,
                        GenericTraitAssociatedTypeValue::new_projection(
                            implementation_id,
                            associated,
                            BoundTraitProjection::new(
                                BoundImplementedTraitGoal::new(
                                    TraitId::new(511 + index as u32),
                                    BoundTraitGoalType::Parameter(parameter),
                                ),
                                associated,
                            ),
                        ),
                    )
                    .unwrap();
            }
        }
        let query = ExistsTraitProjectionEquality::new(
            1,
            BoundTraitProjection::new(
                BoundImplementedTraitGoal::new(
                    TraitId::new(510),
                    BoundTraitGoalType::Parameter(parameter),
                ),
                associated,
            ),
            BoundTraitGoalType::Parameter(parameter),
        )
        .unwrap();
        assert_eq!(
            solve_exists_trait_projection_equality(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                TraitUniverseIndex::ROOT,
                query,
            ),
            Ok(InferredTraitProjectionSolution::Overflow)
        );
    }

    #[test]
    fn inferred_predicate_conjunction_defers_ambiguity_until_projection_refines_it() {
        let parameter = TraitGenericParameterId::new(0);
        let associated = TraitAssociatedTypeId::new(1);
        let mut exact = TraitImplementationDatabase::EMPTY;
        for (id, ty) in [(201, 10), (202, 11)] {
            exact
                .insert(TraitImplementationHeader::new(
                    TraitImplementationId::new(id),
                    TraitId::new(600),
                    TraitTypeId::new(ty),
                ))
                .unwrap();
        }
        let projection_implementation = TraitImplementationId::new(203);
        exact
            .insert(TraitImplementationHeader::new(
                projection_implementation,
                TraitId::new(601),
                TraitTypeId::new(20),
            ))
            .unwrap();
        let mut values = TraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &exact,
                TraitAssociatedTypeValue::new(
                    projection_implementation,
                    associated,
                    TraitTypeId::new(10),
                ),
            )
            .unwrap();

        let mut query = ExistsTraitPredicateConjunction::new(1).unwrap();
        query
            .push(BoundTraitPredicate::Implemented(
                BoundImplementedTraitGoal::new(
                    TraitId::new(600),
                    BoundTraitGoalType::Parameter(parameter),
                ),
            ))
            .unwrap();
        query
            .push(BoundTraitPredicate::ProjectionEquality {
                projection: BoundTraitProjection::new(
                    BoundImplementedTraitGoal::new(
                        TraitId::new(601),
                        BoundTraitGoalType::Concrete(TraitTypeId::new(20)),
                    ),
                    associated,
                ),
                expected: BoundTraitGoalType::Parameter(parameter),
            })
            .unwrap();
        let InferredTraitGoalSolution::Unique(answer) = solve_exists_trait_predicate_conjunction(
            &exact,
            &GenericTraitImplementationDatabase::EMPTY,
            &TraitWhereClauseDatabase::EMPTY,
            &values,
            &GenericTraitAssociatedTypeDatabase::EMPTY,
            TraitUniverseIndex::ROOT,
            query,
        )
        .unwrap() else {
            panic!("projection should refine the deferred implementation predicate");
        };
        assert_eq!(
            answer
                .substitution
                .binding(TraitInferenceVariableId::new(0)),
            Some(TraitGoalType::Concrete(TraitTypeId::new(10)))
        );
    }

    #[test]
    fn solves_mixed_universal_trait_predicate_conjunctions() {
        let parameter = TraitGenericParameterId::new(0);
        let associated = TraitAssociatedTypeId::new(1);
        let projected_id = GenericTraitImplementationId::new(207);
        let projected = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(770),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        let implemented = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(771),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic.insert(projected_id, projected).unwrap();
        generic
            .insert(GenericTraitImplementationId::new(208), implemented)
            .unwrap();
        let mut values = GenericTraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &generic,
                GenericTraitAssociatedTypeValue::new(
                    projected_id,
                    associated,
                    BoundTraitGoalType::Parameter(parameter),
                ),
            )
            .unwrap();
        let mut query = ForAllTraitPredicateConjunction::new(1).unwrap();
        query
            .push(BoundTraitPredicate::Implemented(
                BoundImplementedTraitGoal::new(
                    TraitId::new(771),
                    BoundTraitGoalType::Parameter(parameter),
                ),
            ))
            .unwrap();
        query
            .push(BoundTraitPredicate::ProjectionEquality {
                projection: BoundTraitProjection::new(
                    BoundImplementedTraitGoal::new(
                        TraitId::new(770),
                        BoundTraitGoalType::Parameter(parameter),
                    ),
                    associated,
                ),
                expected: BoundTraitGoalType::Parameter(parameter),
            })
            .unwrap();
        assert_eq!(
            solve_for_all_trait_predicate_conjunction(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                TraitUniverseIndex::ROOT,
                query,
            ),
            Ok(TraitProofSolution::Proven)
        );
        assert_eq!(
            solve_for_all_trait_predicate_conjunction(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                TraitUniverseIndex::new(u16::MAX),
                query,
            ),
            Err(TraitGoalError::UniverseOverflow)
        );

        let mut contradictory = ForAllTraitPredicateConjunction::new(1).unwrap();
        contradictory
            .push(BoundTraitPredicate::ProjectionEquality {
                projection: BoundTraitProjection::new(
                    BoundImplementedTraitGoal::new(
                        TraitId::new(770),
                        BoundTraitGoalType::Parameter(parameter),
                    ),
                    associated,
                ),
                expected: BoundTraitGoalType::Concrete(TraitTypeId::new(1)),
            })
            .unwrap();
        assert_eq!(
            solve_for_all_trait_predicate_conjunction(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                TraitUniverseIndex::ROOT,
                contradictory,
            ),
            Ok(TraitProofSolution::NoSolution)
        );

        let empty = ForAllTraitPredicateConjunction::new(1).unwrap();
        assert_eq!(
            solve_for_all_trait_predicate_conjunction(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                TraitUniverseIndex::ROOT,
                empty,
            ),
            Ok(TraitProofSolution::Proven)
        );
        let mut overfull = ForAllTraitPredicateConjunction::new(1).unwrap();
        for _ in 0..MAX_TRAIT_PREDICATES {
            overfull
                .push(BoundTraitPredicate::Implemented(
                    BoundImplementedTraitGoal::new(
                        TraitId::new(771),
                        BoundTraitGoalType::Parameter(parameter),
                    ),
                ))
                .unwrap();
        }
        assert_eq!(
            overfull.push(BoundTraitPredicate::Implemented(
                BoundImplementedTraitGoal::new(
                    TraitId::new(771),
                    BoundTraitGoalType::Parameter(parameter),
                ),
            )),
            Err(TraitGoalError::TooManyPredicates)
        );

        let mut recursive = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(772),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        recursive
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(772),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let mut recursive_generic = GenericTraitImplementationDatabase::EMPTY;
        recursive_generic
            .insert(GenericTraitImplementationId::new(206), recursive)
            .unwrap();
        let mut cyclic = ForAllTraitPredicateConjunction::new(1).unwrap();
        cyclic
            .push(BoundTraitPredicate::Implemented(
                BoundImplementedTraitGoal::new(
                    TraitId::new(772),
                    BoundTraitGoalType::Parameter(parameter),
                ),
            ))
            .unwrap();
        assert_eq!(
            solve_for_all_trait_predicate_conjunction(
                &TraitImplementationDatabase::EMPTY,
                &recursive_generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                TraitUniverseIndex::ROOT,
                cyclic,
            ),
            Ok(TraitProofSolution::Cycle)
        );
    }

    #[test]
    fn solves_nested_universal_predicates_with_distinct_placeholder_universes() {
        let outer = TraitGenericParameterId::new(0);
        let inner = TraitGenericParameterId::new(1);
        let associated = TraitAssociatedTypeId::new(1);
        let identity_id = GenericTraitImplementationId::new(204);
        let identity = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(780),
                BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
            ),
        )
        .unwrap();
        let inner_implemented = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(781),
                BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
            ),
        )
        .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic.insert(identity_id, identity).unwrap();
        generic
            .insert(GenericTraitImplementationId::new(205), inner_implemented)
            .unwrap();
        let mut values = GenericTraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &generic,
                GenericTraitAssociatedTypeValue::new(
                    identity_id,
                    associated,
                    BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
                ),
            )
            .unwrap();

        let mut query = NestedForAllTraitPredicateConjunction::new(1).unwrap();
        query.push_binder(1).unwrap();
        query
            .push(BoundTraitPredicate::Implemented(
                BoundImplementedTraitGoal::new(
                    TraitId::new(781),
                    BoundTraitGoalType::Parameter(inner),
                ),
            ))
            .unwrap();
        query
            .push(BoundTraitPredicate::ProjectionEquality {
                projection: BoundTraitProjection::new(
                    BoundImplementedTraitGoal::new(
                        TraitId::new(780),
                        BoundTraitGoalType::Parameter(outer),
                    ),
                    associated,
                ),
                expected: BoundTraitGoalType::Parameter(outer),
            })
            .unwrap();
        assert_eq!(query.binder_count(), 2);
        assert_eq!(query.total_parameter_count(), 2);
        assert_eq!(
            solve_nested_for_all_trait_predicate_conjunction(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                TraitUniverseIndex::ROOT,
                query,
            ),
            Ok(TraitProofSolution::Proven)
        );

        let mut cross_universe = NestedForAllTraitPredicateConjunction::new(1).unwrap();
        cross_universe.push_binder(1).unwrap();
        cross_universe
            .push(BoundTraitPredicate::ProjectionEquality {
                projection: BoundTraitProjection::new(
                    BoundImplementedTraitGoal::new(
                        TraitId::new(780),
                        BoundTraitGoalType::Parameter(outer),
                    ),
                    associated,
                ),
                expected: BoundTraitGoalType::Parameter(inner),
            })
            .unwrap();
        assert_eq!(
            solve_nested_for_all_trait_predicate_conjunction(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                TraitUniverseIndex::ROOT,
                cross_universe,
            ),
            Ok(TraitProofSolution::NoSolution)
        );
        assert_eq!(
            solve_nested_for_all_trait_predicate_conjunction(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                TraitUniverseIndex::new(u16::MAX - 1),
                cross_universe,
            ),
            Err(TraitGoalError::UniverseOverflow)
        );

        let mut closed_prefix = NestedForAllTraitPredicateConjunction::new(1).unwrap();
        closed_prefix
            .push(BoundTraitPredicate::Implemented(
                BoundImplementedTraitGoal::new(
                    TraitId::new(781),
                    BoundTraitGoalType::Parameter(outer),
                ),
            ))
            .unwrap();
        assert_eq!(
            closed_prefix.push_binder(1),
            Err(TraitGoalError::InvalidGoal)
        );
        assert_eq!(
            NestedForAllTraitPredicateConjunction::new(1)
                .unwrap()
                .push_binder(MAX_TRAIT_GENERIC_PARAMETERS),
            Err(TraitGoalError::TooManyGenericParameters)
        );

        let mut recursive = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(782),
                BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
            ),
        )
        .unwrap();
        recursive
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(782),
                BoundTraitGoalType::Parameter(TraitGenericParameterId::new(0)),
            ))
            .unwrap();
        let mut recursive_generic = GenericTraitImplementationDatabase::EMPTY;
        recursive_generic
            .insert(GenericTraitImplementationId::new(203), recursive)
            .unwrap();
        let mut cyclic = NestedForAllTraitPredicateConjunction::new(1).unwrap();
        cyclic.push_binder(1).unwrap();
        cyclic
            .push(BoundTraitPredicate::Implemented(
                BoundImplementedTraitGoal::new(
                    TraitId::new(782),
                    BoundTraitGoalType::Parameter(inner),
                ),
            ))
            .unwrap();
        assert_eq!(
            solve_nested_for_all_trait_predicate_conjunction(
                &TraitImplementationDatabase::EMPTY,
                &recursive_generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                TraitUniverseIndex::ROOT,
                cyclic,
            ),
            Ok(TraitProofSolution::Cycle)
        );
    }

    #[test]
    fn solves_bounded_independent_universal_predicate_branches() {
        let parameter = TraitGenericParameterId::new(0);
        let associated = TraitAssociatedTypeId::new(1);
        let implemented = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(790),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        let projected_id = GenericTraitImplementationId::new(201);
        let projected = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(791),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(GenericTraitImplementationId::new(200), implemented)
            .unwrap();
        generic.insert(projected_id, projected).unwrap();
        let mut values = GenericTraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &generic,
                GenericTraitAssociatedTypeValue::new(
                    projected_id,
                    associated,
                    BoundTraitGoalType::Parameter(parameter),
                ),
            )
            .unwrap();

        let mut first = NestedForAllTraitPredicateConjunction::new(1).unwrap();
        first
            .push(BoundTraitPredicate::Implemented(
                BoundImplementedTraitGoal::new(
                    TraitId::new(790),
                    BoundTraitGoalType::Parameter(parameter),
                ),
            ))
            .unwrap();
        let mut second = NestedForAllTraitPredicateConjunction::new(1).unwrap();
        second
            .push(BoundTraitPredicate::ProjectionEquality {
                projection: BoundTraitProjection::new(
                    BoundImplementedTraitGoal::new(
                        TraitId::new(791),
                        BoundTraitGoalType::Parameter(parameter),
                    ),
                    associated,
                ),
                expected: BoundTraitGoalType::Parameter(parameter),
            })
            .unwrap();
        let mut forest = ForAllTraitPredicateBranchForest::EMPTY;
        forest.push_branch(first).unwrap();
        forest.push_branch(second).unwrap();
        assert_eq!(forest.branch_count(), 2);
        assert_eq!(forest.total_binder_count(), 2);
        assert_eq!(forest.total_predicate_count(), 2);
        assert_eq!(
            solve_for_all_trait_predicate_branch_forest(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                TraitUniverseIndex::ROOT,
                forest,
            ),
            Ok(TraitProofSolution::Proven)
        );
        assert_eq!(
            solve_for_all_trait_predicate_branch_forest(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                TraitUniverseIndex::new(u16::MAX - 1),
                forest,
            ),
            Err(TraitGoalError::UniverseOverflow)
        );

        let mut missing = NestedForAllTraitPredicateConjunction::new(1).unwrap();
        missing
            .push(BoundTraitPredicate::Implemented(
                BoundImplementedTraitGoal::new(
                    TraitId::new(792),
                    BoundTraitGoalType::Parameter(parameter),
                ),
            ))
            .unwrap();
        let mut failing = ForAllTraitPredicateBranchForest::EMPTY;
        failing.push_branch(first).unwrap();
        failing.push_branch(missing).unwrap();
        assert_eq!(
            solve_for_all_trait_predicate_branch_forest(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                TraitUniverseIndex::ROOT,
                failing,
            ),
            Ok(TraitProofSolution::NoSolution)
        );

        let mut predicate_full = NestedForAllTraitPredicateConjunction::new(1).unwrap();
        for _ in 0..MAX_TRAIT_PREDICATES {
            predicate_full
                .push(BoundTraitPredicate::Implemented(
                    BoundImplementedTraitGoal::new(
                        TraitId::new(790),
                        BoundTraitGoalType::Parameter(parameter),
                    ),
                ))
                .unwrap();
        }
        let mut predicate_bounded = ForAllTraitPredicateBranchForest::EMPTY;
        predicate_bounded.push_branch(predicate_full).unwrap();
        assert_eq!(
            predicate_bounded.push_branch(first),
            Err(TraitGoalError::TooManyPredicates)
        );

        let mut eight_levels = NestedForAllTraitPredicateConjunction::new(0).unwrap();
        for _ in 1..MAX_TRAIT_GENERIC_PARAMETERS {
            eight_levels.push_binder(0).unwrap();
        }
        let mut binder_bounded = ForAllTraitPredicateBranchForest::EMPTY;
        binder_bounded.push_branch(eight_levels).unwrap();
        binder_bounded.push_branch(eight_levels).unwrap();
        assert_eq!(
            binder_bounded.push_branch(NestedForAllTraitPredicateConjunction::new(0).unwrap()),
            Err(TraitGoalError::TooManyBinderLevels)
        );

        let mut branch_bounded = ForAllTraitPredicateBranchForest::EMPTY;
        let empty = NestedForAllTraitPredicateConjunction::new(0).unwrap();
        for _ in 0..MAX_TRAIT_PREDICATES {
            branch_bounded.push_branch(empty).unwrap();
        }
        assert_eq!(
            branch_bounded.push_branch(empty),
            Err(TraitGoalError::TooManyPredicates)
        );

        let mut recursive = TraitWhereClause::new(
            1,
            BoundImplementedTraitGoal::new(
                TraitId::new(793),
                BoundTraitGoalType::Parameter(parameter),
            ),
        )
        .unwrap();
        recursive
            .push_premise(BoundImplementedTraitGoal::new(
                TraitId::new(793),
                BoundTraitGoalType::Parameter(parameter),
            ))
            .unwrap();
        let mut recursive_generic = generic;
        recursive_generic
            .insert(GenericTraitImplementationId::new(202), recursive)
            .unwrap();
        let mut recursive_branch = NestedForAllTraitPredicateConjunction::new(1).unwrap();
        recursive_branch
            .push(BoundTraitPredicate::Implemented(
                BoundImplementedTraitGoal::new(
                    TraitId::new(793),
                    BoundTraitGoalType::Parameter(parameter),
                ),
            ))
            .unwrap();
        let mut cyclic = ForAllTraitPredicateBranchForest::EMPTY;
        cyclic.push_branch(first).unwrap();
        cyclic.push_branch(second).unwrap();
        cyclic.push_branch(recursive_branch).unwrap();
        assert_eq!(
            solve_for_all_trait_predicate_branch_forest(
                &TraitImplementationDatabase::EMPTY,
                &recursive_generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                TraitUniverseIndex::ROOT,
                cyclic,
            ),
            Ok(TraitProofSolution::Cycle)
        );
        let mut coinductive = CoinductiveTraitDatabase::EMPTY;
        coinductive.insert(TraitId::new(793)).unwrap();
        assert_eq!(
            solve_for_all_trait_predicate_branch_forest_with_coinduction(
                &TraitImplementationDatabase::EMPTY,
                &recursive_generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                &coinductive,
                TraitUniverseIndex::ROOT,
                cyclic,
            ),
            Ok(TraitProofSolution::Proven)
        );
    }

    #[test]
    fn inferred_predicate_conjunction_rejects_cross_predicate_contradictions() {
        let parameter = TraitGenericParameterId::new(0);
        let associated = TraitAssociatedTypeId::new(1);
        let mut exact = TraitImplementationDatabase::EMPTY;
        exact
            .insert(TraitImplementationHeader::new(
                TraitImplementationId::new(204),
                TraitId::new(602),
                TraitTypeId::new(11),
            ))
            .unwrap();
        let projection_implementation = TraitImplementationId::new(205);
        exact
            .insert(TraitImplementationHeader::new(
                projection_implementation,
                TraitId::new(603),
                TraitTypeId::new(20),
            ))
            .unwrap();
        let mut values = TraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &exact,
                TraitAssociatedTypeValue::new(
                    projection_implementation,
                    associated,
                    TraitTypeId::new(10),
                ),
            )
            .unwrap();
        let mut query = ExistsTraitPredicateConjunction::new(1).unwrap();
        query
            .push(BoundTraitPredicate::Implemented(
                BoundImplementedTraitGoal::new(
                    TraitId::new(602),
                    BoundTraitGoalType::Parameter(parameter),
                ),
            ))
            .unwrap();
        query
            .push(BoundTraitPredicate::ProjectionEquality {
                projection: BoundTraitProjection::new(
                    BoundImplementedTraitGoal::new(
                        TraitId::new(603),
                        BoundTraitGoalType::Concrete(TraitTypeId::new(20)),
                    ),
                    associated,
                ),
                expected: BoundTraitGoalType::Parameter(parameter),
            })
            .unwrap();
        assert_eq!(
            solve_exists_trait_predicate_conjunction(
                &exact,
                &GenericTraitImplementationDatabase::EMPTY,
                &TraitWhereClauseDatabase::EMPTY,
                &values,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                TraitUniverseIndex::ROOT,
                query,
            ),
            Ok(InferredTraitGoalSolution::NoSolution)
        );
    }

    #[test]
    fn inferred_predicate_conjunction_bounds_and_preserves_unresolved_ambiguity() {
        assert_eq!(
            ExistsTraitPredicateConjunction::new(MAX_TRAIT_GENERIC_PARAMETERS + 1),
            Err(TraitGoalError::TooManyGenericParameters)
        );
        let parameter = TraitGenericParameterId::new(0);
        let predicate = BoundTraitPredicate::Implemented(BoundImplementedTraitGoal::new(
            TraitId::new(604),
            BoundTraitGoalType::Parameter(parameter),
        ));
        let mut overfull = ExistsTraitPredicateConjunction::new(1).unwrap();
        for _ in 0..MAX_TRAIT_PREDICATES {
            overfull.push(predicate).unwrap();
        }
        assert_eq!(
            overfull.push(predicate),
            Err(TraitGoalError::TooManyPredicates)
        );

        let mut exact = TraitImplementationDatabase::EMPTY;
        for (id, ty) in [(206, 1), (207, 2)] {
            exact
                .insert(TraitImplementationHeader::new(
                    TraitImplementationId::new(id),
                    TraitId::new(604),
                    TraitTypeId::new(ty),
                ))
                .unwrap();
        }
        let mut ambiguous = ExistsTraitPredicateConjunction::new(1).unwrap();
        ambiguous.push(predicate).unwrap();
        assert_eq!(
            solve_exists_trait_predicate_conjunction(
                &exact,
                &GenericTraitImplementationDatabase::EMPTY,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &GenericTraitAssociatedTypeDatabase::EMPTY,
                TraitUniverseIndex::ROOT,
                ambiguous,
            ),
            Ok(InferredTraitGoalSolution::Ambiguous)
        );
    }

    #[test]
    fn inferred_predicate_conjunction_handles_empty_and_cyclic_queries() {
        let empty = ExistsTraitPredicateConjunction::new(1).unwrap();
        let InferredTraitGoalSolution::Unique(answer) = solve_exists_trait_predicate_conjunction(
            &TraitImplementationDatabase::EMPTY,
            &GenericTraitImplementationDatabase::EMPTY,
            &TraitWhereClauseDatabase::EMPTY,
            &TraitAssociatedTypeDatabase::EMPTY,
            &GenericTraitAssociatedTypeDatabase::EMPTY,
            TraitUniverseIndex::new(14),
            empty,
        )
        .unwrap() else {
            panic!("empty conjunction should preserve its existential universe");
        };
        let variable = TraitInferenceVariableId::in_universe(TraitUniverseIndex::new(14), 0);
        assert_eq!(
            answer.substitution.binding(variable),
            Some(TraitGoalType::InferenceVariable(variable))
        );

        let associated = TraitAssociatedTypeId::new(1);
        let implementation_id = GenericTraitImplementationId::new(208);
        let mut generic = GenericTraitImplementationDatabase::EMPTY;
        generic
            .insert(
                implementation_id,
                TraitWhereClause::new(
                    0,
                    BoundImplementedTraitGoal::new(
                        TraitId::new(605),
                        BoundTraitGoalType::Concrete(TraitTypeId::new(9)),
                    ),
                )
                .unwrap(),
            )
            .unwrap();
        let mut values = GenericTraitAssociatedTypeDatabase::EMPTY;
        values
            .insert(
                &generic,
                GenericTraitAssociatedTypeValue::new_projection(
                    implementation_id,
                    associated,
                    BoundTraitProjection::new(
                        BoundImplementedTraitGoal::new(
                            TraitId::new(605),
                            BoundTraitGoalType::Concrete(TraitTypeId::new(9)),
                        ),
                        associated,
                    ),
                ),
            )
            .unwrap();
        let mut cyclic = ExistsTraitPredicateConjunction::new(0).unwrap();
        cyclic
            .push(BoundTraitPredicate::ProjectionEquality {
                projection: BoundTraitProjection::new(
                    BoundImplementedTraitGoal::new(
                        TraitId::new(605),
                        BoundTraitGoalType::Concrete(TraitTypeId::new(9)),
                    ),
                    associated,
                ),
                expected: BoundTraitGoalType::Concrete(TraitTypeId::new(9)),
            })
            .unwrap();
        assert_eq!(
            solve_exists_trait_predicate_conjunction(
                &TraitImplementationDatabase::EMPTY,
                &generic,
                &TraitWhereClauseDatabase::EMPTY,
                &TraitAssociatedTypeDatabase::EMPTY,
                &values,
                TraitUniverseIndex::ROOT,
                cyclic,
            ),
            Ok(InferredTraitGoalSolution::Cycle)
        );
    }

    #[test]
    fn reports_no_solution_for_rigid_mismatches() {
        let mut database = TraitImplementationDatabase::EMPTY;
        database
            .insert(TraitImplementationHeader::new(
                TraitImplementationId::new(1),
                TraitId::new(2),
                TraitTypeId::new(3),
            ))
            .unwrap();
        for self_type in [
            TraitGoalType::Concrete(TraitTypeId::new(4)),
            TraitGoalType::Placeholder(TraitPlaceholder::new(
                TraitUniverseIndex::ROOT,
                TraitPlaceholderId::new(3),
            )),
        ] {
            let goal = ImplementedTraitGoal::new(TraitId::new(2), self_type);
            assert_eq!(
                database.solve(canonicalize_implemented_trait_goal(goal).unwrap()),
                TraitGoalSolution::NoSolution
            );
        }
    }

    #[test]
    fn returns_one_bounded_inference_answer() {
        let mut database = TraitImplementationDatabase::EMPTY;
        database
            .insert(TraitImplementationHeader::new(
                TraitImplementationId::new(1),
                TraitId::new(2),
                TraitTypeId::new(3),
            ))
            .unwrap();
        let goal = ImplementedTraitGoal::new(
            TraitId::new(2),
            TraitGoalType::InferenceVariable(TraitInferenceVariableId::new(99)),
        );
        let canonicalized = canonicalize_implemented_trait_goal_with_variables(goal).unwrap();
        let answer = TraitGoalAnswer {
            implementation_id: TraitImplementationId::new(1),
            bindings: [
                Some(TraitTypeId::new(3)),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ],
            binding_count: 1,
        };
        assert_eq!(
            database.solve(canonicalized.goal),
            TraitGoalSolution::Unique(answer)
        );
        let substitution = answer.substitute(canonicalized).unwrap();
        assert_eq!(
            substitution.binding(TraitInferenceVariableId::new(99)),
            Some(TraitTypeId::new(3))
        );
        assert_eq!(
            substitution.binding(TraitInferenceVariableId::new(100)),
            None
        );
    }

    #[test]
    fn restores_first_occurrence_variable_identities_in_answers() {
        let mut database = TraitImplementationDatabase::EMPTY;
        let mut implementation = TraitImplementationHeader::new(
            TraitImplementationId::new(5),
            TraitId::new(7),
            TraitTypeId::new(20),
        );
        implementation.push_argument(TraitTypeId::new(30)).unwrap();
        database.insert(implementation).unwrap();
        let mut goal = ImplementedTraitGoal::new(
            TraitId::new(7),
            TraitGoalType::InferenceVariable(TraitInferenceVariableId::new(900)),
        );
        goal.push_argument(TraitGoalType::InferenceVariable(
            TraitInferenceVariableId::new(100),
        ))
        .unwrap();
        let canonicalized = canonicalize_implemented_trait_goal_with_variables(goal).unwrap();
        let TraitGoalSolution::Unique(answer) = database.solve(canonicalized.goal) else {
            panic!("expected one exact answer");
        };
        let substitution = answer.substitute(canonicalized).unwrap();
        assert_eq!(
            substitution.bindings(),
            [
                Some(TraitInferenceBinding {
                    variable: TraitInferenceVariableId::new(900),
                    concrete_type: TraitTypeId::new(20),
                }),
                Some(TraitInferenceBinding {
                    variable: TraitInferenceVariableId::new(100),
                    concrete_type: TraitTypeId::new(30),
                }),
            ]
        );
    }

    #[test]
    fn reports_ambiguity_for_multiple_inference_answers() {
        let mut database = TraitImplementationDatabase::EMPTY;
        for (implementation, self_type) in [(1, 3), (2, 4)] {
            database
                .insert(TraitImplementationHeader::new(
                    TraitImplementationId::new(implementation),
                    TraitId::new(2),
                    TraitTypeId::new(self_type),
                ))
                .unwrap();
        }
        let goal = ImplementedTraitGoal::new(
            TraitId::new(2),
            TraitGoalType::InferenceVariable(TraitInferenceVariableId::new(99)),
        );
        assert_eq!(
            database.solve(canonicalize_implemented_trait_goal(goal).unwrap()),
            TraitGoalSolution::Ambiguous
        );
    }

    #[test]
    fn repeated_canonical_variables_require_equal_concrete_types() {
        let mut database = TraitImplementationDatabase::EMPTY;
        let mut implementation = TraitImplementationHeader::new(
            TraitImplementationId::new(1),
            TraitId::new(2),
            TraitTypeId::new(3),
        );
        implementation.push_argument(TraitTypeId::new(4)).unwrap();
        database.insert(implementation).unwrap();
        let variable = TraitInferenceVariableId::new(9);
        let mut goal =
            ImplementedTraitGoal::new(TraitId::new(2), TraitGoalType::InferenceVariable(variable));
        goal.push_argument(TraitGoalType::InferenceVariable(variable))
            .unwrap();
        assert_eq!(
            database.solve(canonicalize_implemented_trait_goal(goal).unwrap()),
            TraitGoalSolution::NoSolution
        );
    }

    #[test]
    fn rejects_duplicate_ids_and_overlapping_exact_headers() {
        let mut database = TraitImplementationDatabase::EMPTY;
        let first = TraitImplementationHeader::new(
            TraitImplementationId::new(1),
            TraitId::new(2),
            TraitTypeId::new(3),
        );
        database.insert(first).unwrap();
        assert_eq!(
            database.insert(TraitImplementationHeader::new(
                TraitImplementationId::new(1),
                TraitId::new(4),
                TraitTypeId::new(5),
            )),
            Err(TraitGoalError::DuplicateImplementationId)
        );
        assert_eq!(
            database.insert(TraitImplementationHeader::new(
                TraitImplementationId::new(7),
                TraitId::new(2),
                TraitTypeId::new(3),
            )),
            Err(TraitGoalError::OverlappingImplementation)
        );
    }

    #[test]
    fn rejects_implementation_capacity_overflow() {
        let mut database = TraitImplementationDatabase::EMPTY;
        for index in 0..MAX_TRAIT_IMPLEMENTATIONS {
            database
                .insert(TraitImplementationHeader::new(
                    TraitImplementationId::new(index as u32),
                    TraitId::new(1),
                    TraitTypeId::new(index as u32),
                ))
                .unwrap();
        }
        assert_eq!(
            database.insert(TraitImplementationHeader::new(
                TraitImplementationId::new(999),
                TraitId::new(1),
                TraitTypeId::new(999),
            )),
            Err(TraitGoalError::TooManyImplementations)
        );
    }
}
