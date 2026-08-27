use crate::{
    Function, FunctionWherePredicate, Item, MAX_FUNCTION_WHERE_PREDICATES,
    MAX_TRAIT_ASSOCIATED_TYPES, MAX_TRAIT_SUPERTRAITS, Module, Span, TypeRef,
};

pub const MAX_TRAIT_GOAL_ARGUMENTS: usize = 8;
pub const MAX_CANONICAL_TRAIT_VARIABLES: usize = 8;
pub const MAX_TRAIT_IMPLEMENTATIONS: usize = 64;
pub const MAX_TRAIT_PREDICATES: usize = 8;
pub const MAX_TRAIT_GENERIC_PARAMETERS: usize = 8;
pub const MAX_TRAIT_WHERE_CLAUSES: usize = 64;
pub const MAX_TRAIT_PROOF_DEPTH: usize = 16;
pub const MAX_TRAIT_ASSOCIATED_TYPE_VALUES: usize = 64;
pub const MAX_TRAIT_PROJECTION_DEPTH: usize = 16;
pub const MAX_GENERIC_TRAIT_IMPLEMENTATIONS: usize = 64;
pub const MAX_TRAIT_GOAL_TERMS: usize = 64;
pub const MAX_COINDUCTIVE_TRAITS: usize = 64;
pub const MAX_SOURCE_TRAIT_DECLARATIONS: usize = 64;
pub const MAX_SOURCE_TRAIT_TYPES: usize = 64;
pub const MAX_SOURCE_ASSOCIATED_TYPES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TraitId(u32);

impl TraitId {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceTraitDeclaration<'source> {
    pub id: TraitId,
    pub name: &'source str,
    pub name_span: Span,
    pub public: bool,
    pub generic_parameter_count: usize,
    generic_parameters: [Option<&'source str>; MAX_TRAIT_GENERIC_PARAMETERS],
    generic_parameter_defaults: [Option<TypeRef<'source>>; MAX_TRAIT_GENERIC_PARAMETERS],
    supertraits: [Option<SourceTraitSupertrait<'source>>; MAX_TRAIT_SUPERTRAITS],
    supertrait_count: usize,
    where_predicates:
        [Option<crate::TraitImplementationWherePredicate<'source>>; MAX_FUNCTION_WHERE_PREDICATES],
    where_predicate_count: usize,
    associated_types: [Option<TraitAssociatedTypeId>; MAX_TRAIT_ASSOCIATED_TYPES],
    associated_type_count: usize,
}

impl<'source> SourceTraitDeclaration<'source> {
    pub fn supertraits(&self) -> &[Option<SourceTraitSupertrait<'source>>] {
        &self.supertraits[..self.supertrait_count]
    }

    pub const fn supertrait_count(&self) -> usize {
        self.supertrait_count
    }

    pub fn generic_parameters(&self) -> &[Option<&'source str>] {
        &self.generic_parameters[..self.generic_parameter_count]
    }

    pub fn generic_parameter_defaults(&self) -> &[Option<TypeRef<'source>>] {
        &self.generic_parameter_defaults[..self.generic_parameter_count]
    }

    pub fn required_generic_parameter_count(&self) -> usize {
        self.generic_parameter_defaults()
            .iter()
            .position(Option::is_some)
            .unwrap_or(self.generic_parameter_count)
    }

    fn supports_argument_count(&self, count: usize) -> bool {
        count >= self.required_generic_parameter_count() && count <= self.generic_parameter_count
    }

    pub fn where_predicates(&self) -> &[Option<crate::TraitImplementationWherePredicate<'source>>] {
        &self.where_predicates[..self.where_predicate_count]
    }

    pub const fn where_predicate_count(&self) -> usize {
        self.where_predicate_count
    }

    pub fn associated_types(&self) -> &[Option<TraitAssociatedTypeId>] {
        &self.associated_types[..self.associated_type_count]
    }

    pub const fn associated_type_count(&self) -> usize {
        self.associated_type_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceTraitSupertrait<'source> {
    pub trait_id: TraitId,
    arguments: [Option<SourceTraitSupertraitArgument<'source>>; MAX_TRAIT_GOAL_ARGUMENTS],
    argument_count: usize,
}

impl<'source> SourceTraitSupertrait<'source> {
    pub fn arguments(&self) -> &[Option<SourceTraitSupertraitArgument<'source>>] {
        &self.arguments[..self.argument_count]
    }

    pub const fn argument_count(&self) -> usize {
        self.argument_count
    }

    fn same_requirement(&self, other: &Self) -> bool {
        self.trait_id == other.trait_id
            && self.argument_count == other.argument_count
            && self
                .arguments()
                .iter()
                .zip(other.arguments())
                .all(|(left, right)| match (left.unwrap(), right.unwrap()) {
                    (
                        SourceTraitSupertraitArgument::Concrete(left),
                        SourceTraitSupertraitArgument::Concrete(right),
                    ) => left.text == right.text,
                    (left, right) => left == right,
                })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceTraitSupertraitArgument<'source> {
    SelfType,
    Parameter(u8),
    Concrete(TypeRef<'source>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceTraitAssociatedType<'source> {
    pub id: TraitAssociatedTypeId,
    pub trait_id: TraitId,
    pub name: &'source str,
    pub span: Span,
    pub default: Option<TypeRef<'source>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceTraitDeclarationError {
    TooManyDeclarations,
    DuplicateName,
    UnknownSupertrait,
    DuplicateSupertrait,
    CyclicSupertrait,
    TooManyAssociatedTypes,
    DuplicateAssociatedType,
    DuplicateGenericParameter,
    WrongSupertraitArgumentCount,
    UnsupportedSupertraitArgument,
    UnknownRequirementTrait,
    WrongRequirementArgumentCount,
    UnsupportedRequirementType,
    DuplicateRequirement,
    UnknownRequirementAssociatedType,
    UnsupportedAssociatedTypeDefault,
    UnknownAssociatedTypeDefaultTrait,
    WrongAssociatedTypeDefaultArgumentCount,
    UnknownAssociatedTypeDefaultProjection,
    NonTrailingGenericParameterDefault,
    UnsupportedGenericParameterDefault,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceTraitDeclarationTable<'source> {
    declarations: [Option<SourceTraitDeclaration<'source>>; MAX_SOURCE_TRAIT_DECLARATIONS],
    count: usize,
    associated_types: [Option<SourceTraitAssociatedType<'source>>; MAX_SOURCE_ASSOCIATED_TYPES],
    associated_type_count: usize,
}

impl<'source> SourceTraitDeclarationTable<'source> {
    pub fn from_module<const MAX_ITEMS: usize, const MAX_PARAMETERS: usize>(
        module: &Module<'source, MAX_ITEMS, MAX_PARAMETERS>,
    ) -> Result<Self, SourceTraitDeclarationError> {
        let mut table = Self {
            declarations: [None; MAX_SOURCE_TRAIT_DECLARATIONS],
            count: 0,
            associated_types: [None; MAX_SOURCE_ASSOCIATED_TYPES],
            associated_type_count: 0,
        };
        for item in module.items().iter().flatten() {
            let Item::Trait(declaration) = item else {
                continue;
            };
            if table.declarations[..table.count]
                .iter()
                .flatten()
                .any(|known| known.name == declaration.name)
            {
                return Err(SourceTraitDeclarationError::DuplicateName);
            }
            if table.count == MAX_SOURCE_TRAIT_DECLARATIONS {
                return Err(SourceTraitDeclarationError::TooManyDeclarations);
            }
            table.declarations[table.count] = Some(SourceTraitDeclaration {
                id: TraitId::new(table.count as u32),
                name: declaration.name,
                name_span: declaration.name_span,
                public: declaration.public,
                generic_parameter_count: declaration.generic_parameter_count(),
                generic_parameters: {
                    let mut parameters = [None; MAX_TRAIT_GENERIC_PARAMETERS];
                    parameters[..declaration.generic_parameter_count()]
                        .copy_from_slice(declaration.generic_parameters());
                    parameters
                },
                generic_parameter_defaults: {
                    let mut defaults = [None; MAX_TRAIT_GENERIC_PARAMETERS];
                    defaults[..declaration.generic_parameter_count()]
                        .copy_from_slice(declaration.generic_parameter_defaults());
                    defaults
                },
                supertraits: [None; MAX_TRAIT_SUPERTRAITS],
                supertrait_count: 0,
                where_predicates: [None; MAX_FUNCTION_WHERE_PREDICATES],
                where_predicate_count: 0,
                associated_types: [None; MAX_TRAIT_ASSOCIATED_TYPES],
                associated_type_count: 0,
            });
            table.count += 1;
        }
        for item in module.items().iter().flatten() {
            let Item::Trait(declaration) = item else {
                continue;
            };
            let index = table.get(declaration.name).unwrap().id.get() as usize;
            for (parameter_index, parameter) in declaration
                .generic_parameters()
                .iter()
                .flatten()
                .enumerate()
            {
                if declaration.generic_parameters()[..parameter_index]
                    .iter()
                    .flatten()
                    .any(|known| known == parameter)
                {
                    return Err(SourceTraitDeclarationError::DuplicateGenericParameter);
                }
            }
            let mut saw_default = false;
            for (default_index, default) in
                declaration.generic_parameter_defaults().iter().enumerate()
            {
                match default {
                    Some(default) => {
                        saw_default = true;
                        let parameter_index = declaration
                            .generic_parameters()
                            .iter()
                            .position(|parameter| *parameter == Some(default.text));
                        if parameter_index.is_some_and(|index| index >= default_index)
                            || (parameter_index.is_none()
                                && default.text != "Self"
                                && !supported_source_trait_type(default.text))
                        {
                            return Err(
                                SourceTraitDeclarationError::UnsupportedGenericParameterDefault,
                            );
                        }
                    }
                    None if saw_default => {
                        return Err(
                            SourceTraitDeclarationError::NonTrailingGenericParameterDefault,
                        );
                    }
                    None => {}
                }
            }
            let mut associated_types = [None; MAX_TRAIT_ASSOCIATED_TYPES];
            let mut associated_type_count = 0usize;
            for source_associated in declaration.associated_types().iter().flatten() {
                if declaration.associated_types()[..associated_type_count]
                    .iter()
                    .flatten()
                    .any(|known| known.name == source_associated.name)
                {
                    return Err(SourceTraitDeclarationError::DuplicateAssociatedType);
                }
                if let Some(default) = source_associated.default {
                    let projection = default.parse_trait_projection().map_err(|_| {
                        SourceTraitDeclarationError::UnsupportedAssociatedTypeDefault
                    })?;
                    if projection.is_none()
                        && default.text != "Self"
                        && !declaration
                            .generic_parameters()
                            .contains(&Some(default.text))
                        && !supported_source_trait_type(default.text)
                    {
                        return Err(SourceTraitDeclarationError::UnsupportedAssociatedTypeDefault);
                    }
                }
                let slot = table
                    .associated_types
                    .get_mut(table.associated_type_count)
                    .ok_or(SourceTraitDeclarationError::TooManyAssociatedTypes)?;
                let id = TraitAssociatedTypeId::new(table.associated_type_count as u32);
                *slot = Some(SourceTraitAssociatedType {
                    id,
                    trait_id: TraitId::new(index as u32),
                    name: source_associated.name,
                    span: source_associated.span,
                    default: source_associated.default,
                });
                table.associated_type_count += 1;
                associated_types[associated_type_count] = Some(id);
                associated_type_count += 1;
            }
            let resolved = table.declarations[index].as_mut().unwrap();
            resolved.associated_types = associated_types;
            resolved.associated_type_count = associated_type_count;
        }
        for item in module.items().iter().flatten() {
            let Item::Trait(declaration) = item else {
                continue;
            };
            let index = table.get(declaration.name).unwrap().id.get() as usize;
            for source_associated in declaration.associated_types().iter().flatten() {
                let Some(default) = source_associated.default else {
                    continue;
                };
                let Some(projection) = default
                    .parse_trait_projection()
                    .map_err(|_| SourceTraitDeclarationError::UnsupportedAssociatedTypeDefault)?
                else {
                    continue;
                };
                let target = table
                    .get(projection.trait_name)
                    .ok_or(SourceTraitDeclarationError::UnknownAssociatedTypeDefaultTrait)?;
                if !target.supports_argument_count(projection.trait_argument_count()) {
                    return Err(
                        SourceTraitDeclarationError::WrongAssociatedTypeDefaultArgumentCount,
                    );
                }
                let supported = |source: TypeRef<'source>| {
                    source.text == "Self"
                        || declaration
                            .generic_parameters()
                            .contains(&Some(source.text))
                        || supported_source_trait_type(source.text)
                };
                if !supported(projection.self_type)
                    || projection
                        .trait_arguments()
                        .iter()
                        .flatten()
                        .any(|argument| !supported(*argument))
                {
                    return Err(SourceTraitDeclarationError::UnsupportedAssociatedTypeDefault);
                }
                if table
                    .get_associated_type(target.id, projection.associated_type)
                    .is_none()
                {
                    return Err(
                        SourceTraitDeclarationError::UnknownAssociatedTypeDefaultProjection,
                    );
                }
            }
            let mut supertraits: [Option<SourceTraitSupertrait<'source>>; MAX_TRAIT_SUPERTRAITS] =
                [None; MAX_TRAIT_SUPERTRAITS];
            let mut supertrait_count = 0usize;
            for source_supertrait in declaration.supertraits().iter().flatten() {
                let target = table
                    .get(source_supertrait.name)
                    .ok_or(SourceTraitDeclarationError::UnknownSupertrait)?;
                if !target.supports_argument_count(source_supertrait.argument_count()) {
                    return Err(SourceTraitDeclarationError::WrongSupertraitArgumentCount);
                }
                let mut arguments = [None; MAX_TRAIT_GOAL_ARGUMENTS];
                for (argument_index, argument) in
                    source_supertrait.arguments().iter().flatten().enumerate()
                {
                    let parameter_index = declaration
                        .generic_parameters()
                        .iter()
                        .position(|parameter| *parameter == Some(argument.text));
                    arguments[argument_index] = Some(if argument.text == "Self" {
                        SourceTraitSupertraitArgument::SelfType
                    } else if let Some(parameter_index) = parameter_index {
                        SourceTraitSupertraitArgument::Parameter(parameter_index as u8)
                    } else if supported_source_trait_type(argument.text) {
                        SourceTraitSupertraitArgument::Concrete(*argument)
                    } else {
                        return Err(SourceTraitDeclarationError::UnsupportedSupertraitArgument);
                    });
                }
                for argument_index in
                    source_supertrait.argument_count()..target.generic_parameter_count
                {
                    let default = target.generic_parameter_defaults()[argument_index].unwrap();
                    arguments[argument_index] = Some(if default.text == "Self" {
                        SourceTraitSupertraitArgument::SelfType
                    } else if let Some(parameter_index) = target
                        .generic_parameters()
                        .iter()
                        .position(|parameter| *parameter == Some(default.text))
                    {
                        arguments[parameter_index].unwrap()
                    } else {
                        SourceTraitSupertraitArgument::Concrete(default)
                    });
                }
                let resolved = SourceTraitSupertrait {
                    trait_id: target.id,
                    arguments,
                    argument_count: target.generic_parameter_count,
                };
                if supertraits[..supertrait_count]
                    .iter()
                    .flatten()
                    .any(|known| known.same_requirement(&resolved))
                {
                    return Err(SourceTraitDeclarationError::DuplicateSupertrait);
                }
                supertraits[supertrait_count] = Some(resolved);
                supertrait_count += 1;
            }
            let mut where_predicates = [None; MAX_FUNCTION_WHERE_PREDICATES];
            let mut where_predicate_count = 0usize;
            for predicate in declaration.where_predicates().iter().flatten() {
                if where_predicates[..where_predicate_count]
                    .iter()
                    .flatten()
                    .any(|known| source_implementation_predicates_same(known, predicate, &table))
                {
                    return Err(SourceTraitDeclarationError::DuplicateRequirement);
                }
                let target = table
                    .get(predicate.trait_name())
                    .ok_or(SourceTraitDeclarationError::UnknownRequirementTrait)?;
                if !target.supports_argument_count(predicate.trait_argument_count()) {
                    return Err(SourceTraitDeclarationError::WrongRequirementArgumentCount);
                }
                let supported = |source: TypeRef<'source>| {
                    source.text == "Self"
                        || declaration
                            .generic_parameters()
                            .contains(&Some(source.text))
                        || supported_source_trait_type(source.text)
                };
                if !supported(predicate.self_type())
                    || predicate
                        .trait_arguments()
                        .iter()
                        .flatten()
                        .any(|argument| !supported(*argument))
                {
                    return Err(SourceTraitDeclarationError::UnsupportedRequirementType);
                }
                if let crate::TraitImplementationWherePredicate::ProjectionEquality {
                    associated_type,
                    expected_type,
                    ..
                } = predicate
                {
                    if table
                        .get_associated_type(target.id, associated_type)
                        .is_none()
                    {
                        return Err(SourceTraitDeclarationError::UnknownRequirementAssociatedType);
                    }
                    if !supported(*expected_type) {
                        return Err(SourceTraitDeclarationError::UnsupportedRequirementType);
                    }
                }
                where_predicates[where_predicate_count] = Some(*predicate);
                where_predicate_count += 1;
            }
            let resolved = table.declarations[index].as_mut().unwrap();
            resolved.supertraits = supertraits;
            resolved.supertrait_count = supertrait_count;
            resolved.where_predicates = where_predicates;
            resolved.where_predicate_count = where_predicate_count;
        }
        let mut states = [0u8; MAX_SOURCE_TRAIT_DECLARATIONS];
        for index in 0..table.count {
            table.visit_supertraits(index, &mut states)?;
        }
        Ok(table)
    }

    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn declarations(&self) -> &[Option<SourceTraitDeclaration<'source>>] {
        &self.declarations[..self.count]
    }

    pub fn get(&self, name: &str) -> Option<SourceTraitDeclaration<'source>> {
        self.declarations()
            .iter()
            .flatten()
            .copied()
            .find(|declaration| declaration.name == name)
    }

    pub fn get_by_id(&self, id: TraitId) -> Option<SourceTraitDeclaration<'source>> {
        self.declarations()
            .get(id.get() as usize)
            .copied()
            .flatten()
    }

    pub fn associated_types(&self) -> &[Option<SourceTraitAssociatedType<'source>>] {
        &self.associated_types[..self.associated_type_count]
    }

    pub fn get_associated_type(
        &self,
        trait_id: TraitId,
        name: &str,
    ) -> Option<SourceTraitAssociatedType<'source>> {
        self.associated_types()
            .iter()
            .flatten()
            .copied()
            .find(|associated| associated.trait_id == trait_id && associated.name == name)
    }

    pub fn get_associated_type_by_id(
        &self,
        id: TraitAssociatedTypeId,
    ) -> Option<SourceTraitAssociatedType<'source>> {
        self.associated_types()
            .get(id.get() as usize)
            .copied()
            .flatten()
    }

    fn visit_supertraits(
        &self,
        index: usize,
        states: &mut [u8; MAX_SOURCE_TRAIT_DECLARATIONS],
    ) -> Result<(), SourceTraitDeclarationError> {
        match states[index] {
            1 => return Err(SourceTraitDeclarationError::CyclicSupertrait),
            2 => return Ok(()),
            _ => {}
        }
        states[index] = 1;
        let declaration = self.declarations[index].unwrap();
        for supertrait in declaration.supertraits().iter().flatten() {
            self.visit_supertraits(supertrait.trait_id.get() as usize, states)?;
        }
        states[index] = 2;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceTraitType<'source> {
    pub id: TraitTypeId,
    pub name: &'source str,
    pub span: Span,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceTraitImplementationErrorKind {
    UnknownTrait,
    UnsupportedSelfType,
    TooManyTypes,
    MissingSupertraitImplementation,
    AmbiguousSupertraitImplementation,
    UnknownAssociatedType,
    DuplicateAssociatedTypeValue,
    MissingAssociatedTypeValue,
    WrongTraitArgumentCount,
    DuplicateGenericParameter,
    UnconstrainedGenericParameter,
    UnknownPremiseTrait,
    DuplicatePremise,
    UnsupportedAssociatedTypeProjection,
    Goal(TraitGoalError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceTraitObligationErrorKind {
    UnknownTrait,
    UnknownType,
    DuplicatePredicate,
    UnknownAssociatedType,
    ProjectionMismatch,
    Unsatisfied,
    Ambiguous,
    Goal(TraitGoalError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceTraitObligationError {
    pub kind: SourceTraitObligationErrorKind,
    pub span: Span,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceTraitImplementationError {
    pub kind: SourceTraitImplementationErrorKind,
    pub span: Span,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceTraitImplementationTable<'source> {
    types: [Option<SourceTraitType<'source>>; MAX_SOURCE_TRAIT_TYPES],
    type_count: usize,
    implementations: TraitImplementationDatabase,
    associated_types: TraitAssociatedTypeDatabase,
    generic_implementations: GenericTraitImplementationDatabase,
    generic_associated_types: GenericTraitAssociatedTypeDatabase,
}

impl<'source> SourceTraitImplementationTable<'source> {
    pub fn from_module<const MAX_ITEMS: usize, const MAX_PARAMETERS: usize>(
        module: &Module<'source, MAX_ITEMS, MAX_PARAMETERS>,
        traits: &SourceTraitDeclarationTable<'source>,
    ) -> Result<Self, SourceTraitImplementationError> {
        let mut table = Self {
            types: [None; MAX_SOURCE_TRAIT_TYPES],
            type_count: 0,
            implementations: TraitImplementationDatabase::EMPTY,
            associated_types: TraitAssociatedTypeDatabase::EMPTY,
            generic_implementations: GenericTraitImplementationDatabase::EMPTY,
            generic_associated_types: GenericTraitAssociatedTypeDatabase::EMPTY,
        };
        for item in module.items().iter().flatten() {
            match item {
                Item::TraitImplementation(implementation) => {
                    if !implementation
                        .generic_parameters()
                        .contains(&Some(implementation.self_type.text))
                    {
                        table.intern_type(implementation.self_type)?;
                    }
                    for argument in implementation.trait_arguments().iter().flatten() {
                        if !implementation
                            .generic_parameters()
                            .contains(&Some(argument.text))
                        {
                            table.intern_type(*argument)?;
                        }
                    }
                    for associated in implementation.associated_types().iter().flatten() {
                        let projection = associated.value.parse_trait_projection().map_err(|_| {
                            SourceTraitImplementationError {
                                kind: SourceTraitImplementationErrorKind::UnsupportedAssociatedTypeProjection,
                                span: associated.value.span,
                            }
                        })?;
                        if let Some(projection) = projection {
                            if !implementation
                                .generic_parameters()
                                .contains(&Some(projection.self_type.text))
                            {
                                table.intern_type(projection.self_type)?;
                            }
                            for argument in projection.trait_arguments().iter().flatten() {
                                if !implementation
                                    .generic_parameters()
                                    .contains(&Some(argument.text))
                                {
                                    table.intern_type(*argument)?;
                                }
                            }
                        } else if !implementation
                            .generic_parameters()
                            .contains(&Some(associated.value.text))
                        {
                            table.intern_type(associated.value)?;
                        }
                    }
                    for predicate in implementation.where_predicates().iter().flatten() {
                        if !implementation
                            .generic_parameters()
                            .contains(&Some(predicate.self_type().text))
                        {
                            table.intern_type(predicate.self_type())?;
                        }
                        for argument in predicate.trait_arguments().iter().flatten() {
                            if !implementation
                                .generic_parameters()
                                .contains(&Some(argument.text))
                            {
                                table.intern_type(*argument)?;
                            }
                        }
                        if let crate::TraitImplementationWherePredicate::ProjectionEquality {
                            expected_type,
                            ..
                        } = predicate
                        {
                            if !implementation
                                .generic_parameters()
                                .contains(&Some(expected_type.text))
                            {
                                table.intern_type(*expected_type)?;
                            }
                        }
                    }
                }
                Item::Function(function) => {
                    for predicate in function.where_predicates().iter().flatten() {
                        match predicate {
                            FunctionWherePredicate::Implemented { self_type, .. } => {
                                table.intern_type(*self_type)?;
                            }
                            FunctionWherePredicate::ProjectionEquality {
                                self_type,
                                expected_type,
                                ..
                            } => {
                                table.intern_type(*self_type)?;
                                table.intern_type(*expected_type)?;
                            }
                        }
                        let arguments = match predicate {
                            FunctionWherePredicate::Implemented {
                                trait_arguments, ..
                            }
                            | FunctionWherePredicate::ProjectionEquality {
                                trait_arguments, ..
                            } => trait_arguments,
                        };
                        for argument in arguments.iter().flatten() {
                            table.intern_type(*argument)?;
                        }
                    }
                }
                Item::Trait(declaration) => {
                    for default in declaration.generic_parameter_defaults().iter().flatten() {
                        if default.text != "Self"
                            && !declaration
                                .generic_parameters()
                                .contains(&Some(default.text))
                        {
                            table.intern_type(*default)?;
                        }
                    }
                    for supertrait in declaration.supertraits().iter().flatten() {
                        for argument in supertrait.arguments().iter().flatten() {
                            if argument.text != "Self"
                                && !declaration
                                    .generic_parameters()
                                    .contains(&Some(argument.text))
                            {
                                table.intern_type(*argument)?;
                            }
                        }
                    }
                    for predicate in declaration.where_predicates().iter().flatten() {
                        if predicate.self_type().text != "Self"
                            && !declaration
                                .generic_parameters()
                                .contains(&Some(predicate.self_type().text))
                        {
                            table.intern_type(predicate.self_type())?;
                        }
                        for argument in predicate.trait_arguments().iter().flatten() {
                            if argument.text != "Self"
                                && !declaration
                                    .generic_parameters()
                                    .contains(&Some(argument.text))
                            {
                                table.intern_type(*argument)?;
                            }
                        }
                        if let crate::TraitImplementationWherePredicate::ProjectionEquality {
                            expected_type,
                            ..
                        } = predicate
                        {
                            if expected_type.text != "Self"
                                && !declaration
                                    .generic_parameters()
                                    .contains(&Some(expected_type.text))
                            {
                                table.intern_type(*expected_type)?;
                            }
                        }
                    }
                    for associated in declaration.associated_types().iter().flatten() {
                        if let Some(default) = associated.default {
                            let projection = default.parse_trait_projection().map_err(|_| {
                                SourceTraitImplementationError {
                                    kind: SourceTraitImplementationErrorKind::UnsupportedAssociatedTypeProjection,
                                    span: default.span,
                                }
                            })?;
                            if let Some(projection) = projection {
                                if projection.self_type.text != "Self"
                                    && !declaration
                                        .generic_parameters()
                                        .contains(&Some(projection.self_type.text))
                                {
                                    table.intern_type(projection.self_type)?;
                                }
                                for argument in projection.trait_arguments().iter().flatten() {
                                    if argument.text != "Self"
                                        && !declaration
                                            .generic_parameters()
                                            .contains(&Some(argument.text))
                                    {
                                        table.intern_type(*argument)?;
                                    }
                                }
                            } else if default.text != "Self"
                                && !declaration
                                    .generic_parameters()
                                    .contains(&Some(default.text))
                            {
                                table.intern_type(default)?;
                            }
                        }
                    }
                }
                Item::Const(_) | Item::Static(_) => {}
            }
        }
        let mut implementation_count = 0u32;
        for item in module.items().iter().flatten() {
            let Item::TraitImplementation(implementation) = item else {
                continue;
            };
            if !source_implementation_is_exact_fact(implementation, traits) {
                continue;
            }
            let declaration =
                traits
                    .get(implementation.trait_name)
                    .ok_or(SourceTraitImplementationError {
                        kind: SourceTraitImplementationErrorKind::UnknownTrait,
                        span: implementation.trait_name_span,
                    })?;
            if !declaration.supports_argument_count(implementation.trait_argument_count()) {
                return Err(SourceTraitImplementationError {
                    kind: SourceTraitImplementationErrorKind::WrongTraitArgumentCount,
                    span: implementation.trait_name_span,
                });
            }
            let trait_id = declaration.id;
            let self_type = table.get_type(implementation.self_type.text).unwrap().id;
            let mut header = TraitImplementationHeader::new(
                TraitImplementationId::new(implementation_count),
                trait_id,
                self_type,
            );
            for argument in implementation.trait_arguments().iter().flatten() {
                header
                    .push_argument(table.get_type(argument.text).unwrap().id)
                    .map_err(|kind| SourceTraitImplementationError {
                        kind: SourceTraitImplementationErrorKind::Goal(kind),
                        span: argument.span,
                    })?;
            }
            for argument_index in
                implementation.trait_argument_count()..declaration.generic_parameter_count
            {
                let default = declaration.generic_parameter_defaults()[argument_index].unwrap();
                let value = if default.text == "Self" {
                    header.self_type
                } else {
                    declaration
                        .generic_parameters()
                        .iter()
                        .position(|parameter| *parameter == Some(default.text))
                        .map(|parameter_index| header.arguments()[parameter_index].unwrap())
                        .unwrap_or_else(|| table.get_type(default.text).unwrap().id)
                };
                header
                    .push_argument(value)
                    .map_err(|kind| SourceTraitImplementationError {
                        kind: SourceTraitImplementationErrorKind::Goal(kind),
                        span: default.span,
                    })?;
            }
            table.implementations.insert(header).map_err(|kind| {
                SourceTraitImplementationError {
                    kind: SourceTraitImplementationErrorKind::Goal(kind),
                    span: implementation.trait_name_span,
                }
            })?;
            implementation_count += 1;
        }
        let mut generic_implementation_count = 0u32;
        for item in module.items().iter().flatten() {
            let Item::TraitImplementation(implementation) = item else {
                continue;
            };
            if source_implementation_is_exact_fact(implementation, traits) {
                continue;
            }
            for (index, parameter) in implementation
                .generic_parameters()
                .iter()
                .flatten()
                .enumerate()
            {
                if implementation.generic_parameters()[..index].contains(&Some(*parameter)) {
                    return Err(SourceTraitImplementationError {
                        kind: SourceTraitImplementationErrorKind::DuplicateGenericParameter,
                        span: implementation.trait_name_span,
                    });
                }
            }
            let declaration =
                traits
                    .get(implementation.trait_name)
                    .ok_or(SourceTraitImplementationError {
                        kind: SourceTraitImplementationErrorKind::UnknownTrait,
                        span: implementation.trait_name_span,
                    })?;
            if !declaration.supports_argument_count(implementation.trait_argument_count()) {
                return Err(SourceTraitImplementationError {
                    kind: SourceTraitImplementationErrorKind::WrongTraitArgumentCount,
                    span: implementation.trait_name_span,
                });
            }
            let mut consequence = BoundImplementedTraitGoal::new(
                declaration.id,
                source_bound_type(implementation.self_type, implementation, &table)?,
            );
            for argument in implementation.trait_arguments().iter().flatten() {
                consequence
                    .push_argument(source_bound_type(*argument, implementation, &table)?)
                    .map_err(|kind| SourceTraitImplementationError {
                        kind: SourceTraitImplementationErrorKind::Goal(kind),
                        span: argument.span,
                    })?;
            }
            for argument_index in
                implementation.trait_argument_count()..declaration.generic_parameter_count
            {
                let default = declaration.generic_parameter_defaults()[argument_index].unwrap();
                let value = if default.text == "Self" {
                    consequence.self_type
                } else {
                    declaration
                        .generic_parameters()
                        .iter()
                        .position(|parameter| *parameter == Some(default.text))
                        .map(|parameter_index| consequence.arguments()[parameter_index].unwrap())
                        .unwrap_or_else(|| {
                            BoundTraitGoalType::Concrete(table.get_type(default.text).unwrap().id)
                        })
                };
                consequence.push_argument(value).map_err(|kind| {
                    SourceTraitImplementationError {
                        kind: SourceTraitImplementationErrorKind::Goal(kind),
                        span: default.span,
                    }
                })?;
            }
            for parameter_index in 0..implementation.generic_parameter_count() {
                let parameter = BoundTraitGoalType::Parameter(TraitGenericParameterId::new(
                    parameter_index as u8,
                ));
                if consequence.self_type != parameter
                    && !consequence.arguments().contains(&Some(parameter))
                {
                    return Err(SourceTraitImplementationError {
                        kind: SourceTraitImplementationErrorKind::UnconstrainedGenericParameter,
                        span: implementation.trait_name_span,
                    });
                }
            }
            let mut clause =
                TraitWhereClause::new(implementation.generic_parameter_count(), consequence)
                    .map_err(|kind| SourceTraitImplementationError {
                        kind: SourceTraitImplementationErrorKind::Goal(kind),
                        span: implementation.trait_name_span,
                    })?;
            for (predicate_index, predicate) in implementation
                .where_predicates()
                .iter()
                .flatten()
                .enumerate()
            {
                if implementation.where_predicates()[..predicate_index]
                    .iter()
                    .flatten()
                    .any(|known| source_implementation_predicates_same(known, predicate, traits))
                {
                    return Err(SourceTraitImplementationError {
                        kind: SourceTraitImplementationErrorKind::DuplicatePremise,
                        span: predicate.trait_name_span(),
                    });
                }
                let premise_trait =
                    traits
                        .get(predicate.trait_name())
                        .ok_or(SourceTraitImplementationError {
                            kind: SourceTraitImplementationErrorKind::UnknownPremiseTrait,
                            span: predicate.trait_name_span(),
                        })?;
                if !premise_trait.supports_argument_count(predicate.trait_argument_count()) {
                    return Err(SourceTraitImplementationError {
                        kind: SourceTraitImplementationErrorKind::WrongTraitArgumentCount,
                        span: predicate.trait_name_span(),
                    });
                }
                let mut premise = BoundImplementedTraitGoal::new(
                    premise_trait.id,
                    source_bound_type(predicate.self_type(), implementation, &table)?,
                );
                for argument in predicate.trait_arguments().iter().flatten() {
                    premise
                        .push_argument(source_bound_type(*argument, implementation, &table)?)
                        .map_err(|kind| SourceTraitImplementationError {
                            kind: SourceTraitImplementationErrorKind::Goal(kind),
                            span: argument.span,
                        })?;
                }
                push_source_bound_trait_defaults(
                    &mut premise,
                    &premise_trait,
                    predicate.trait_argument_count(),
                    &table,
                )?;
                match predicate {
                    crate::TraitImplementationWherePredicate::Implemented { .. } => clause
                        .push_premise(premise)
                        .map_err(|kind| SourceTraitImplementationError {
                            kind: SourceTraitImplementationErrorKind::Goal(kind),
                            span: predicate.trait_name_span(),
                        })?,
                    crate::TraitImplementationWherePredicate::ProjectionEquality {
                        associated_type,
                        associated_type_span,
                        expected_type,
                        ..
                    } => {
                        let associated = traits
                            .get_associated_type(premise_trait.id, associated_type)
                            .ok_or(SourceTraitImplementationError {
                                kind: SourceTraitImplementationErrorKind::UnknownAssociatedType,
                                span: *associated_type_span,
                            })?;
                        let expected = source_bound_type(*expected_type, implementation, &table)?;
                        clause
                            .push_projection_premise(
                                BoundTraitProjection::new(premise, associated.id),
                                expected,
                            )
                            .map_err(|kind| SourceTraitImplementationError {
                                kind: SourceTraitImplementationErrorKind::Goal(kind),
                                span: *associated_type_span,
                            })?;
                    }
                }
            }
            for supertrait in declaration.supertraits().iter().flatten() {
                let mut inherited =
                    BoundImplementedTraitGoal::new(supertrait.trait_id, consequence.self_type);
                for source_argument in supertrait.arguments().iter().flatten() {
                    let argument = match source_argument {
                        SourceTraitSupertraitArgument::SelfType => consequence.self_type,
                        SourceTraitSupertraitArgument::Parameter(parameter_index) => {
                            consequence.arguments()[*parameter_index as usize].unwrap()
                        }
                        SourceTraitSupertraitArgument::Concrete(source_type) => {
                            BoundTraitGoalType::Concrete(
                                table.get_type(source_type.text).unwrap().id,
                            )
                        }
                    };
                    inherited.push_argument(argument).map_err(|kind| {
                        SourceTraitImplementationError {
                            kind: SourceTraitImplementationErrorKind::Goal(kind),
                            span: implementation.trait_name_span,
                        }
                    })?;
                }
                if !clause.premises().contains(&Some(inherited)) {
                    clause.push_premise(inherited).map_err(|kind| {
                        SourceTraitImplementationError {
                            kind: SourceTraitImplementationErrorKind::Goal(kind),
                            span: implementation.trait_name_span,
                        }
                    })?;
                }
            }
            for predicate in declaration.where_predicates().iter().flatten() {
                let required_trait = traits.get(predicate.trait_name()).unwrap();
                let mut required = BoundImplementedTraitGoal::new(
                    required_trait.id,
                    source_declaration_bound_type(
                        predicate.self_type(),
                        &declaration,
                        consequence,
                        &table,
                    )?,
                );
                for argument in predicate.trait_arguments().iter().flatten() {
                    required
                        .push_argument(source_declaration_bound_type(
                            *argument,
                            &declaration,
                            consequence,
                            &table,
                        )?)
                        .map_err(|kind| SourceTraitImplementationError {
                            kind: SourceTraitImplementationErrorKind::Goal(kind),
                            span: argument.span,
                        })?;
                }
                push_source_bound_trait_defaults(
                    &mut required,
                    &required_trait,
                    predicate.trait_argument_count(),
                    &table,
                )?;
                match predicate {
                    crate::TraitImplementationWherePredicate::Implemented { .. } => {
                        if !clause.premises().contains(&Some(required)) {
                            clause.push_premise(required).map_err(|kind| {
                                SourceTraitImplementationError {
                                    kind: SourceTraitImplementationErrorKind::Goal(kind),
                                    span: predicate.trait_name_span(),
                                }
                            })?;
                        }
                    }
                    crate::TraitImplementationWherePredicate::ProjectionEquality {
                        associated_type,
                        associated_type_span,
                        expected_type,
                        ..
                    } => {
                        let associated = traits
                            .get_associated_type(required_trait.id, associated_type)
                            .unwrap();
                        let expected = source_declaration_bound_type(
                            *expected_type,
                            &declaration,
                            consequence,
                            &table,
                        )?;
                        clause
                            .push_projection_premise(
                                BoundTraitProjection::new(required, associated.id),
                                expected,
                            )
                            .map_err(|kind| SourceTraitImplementationError {
                                kind: SourceTraitImplementationErrorKind::Goal(kind),
                                span: *associated_type_span,
                            })?;
                    }
                }
            }
            table
                .generic_implementations
                .insert_coherent_with_exact(
                    &table.implementations,
                    GenericTraitImplementationId::new(generic_implementation_count),
                    clause,
                )
                .map_err(|kind| SourceTraitImplementationError {
                    kind: SourceTraitImplementationErrorKind::Goal(kind),
                    span: implementation.trait_name_span,
                })?;
            generic_implementation_count += 1;
        }
        let mut implementation_index = 0u32;
        for item in module.items().iter().flatten() {
            let Item::TraitImplementation(implementation) = item else {
                continue;
            };
            if !source_implementation_is_exact_fact(implementation, traits) {
                continue;
            }
            let trait_id = traits.get(implementation.trait_name).unwrap().id;
            let declaration = traits.get_by_id(trait_id).unwrap();
            let mut seen = [None; MAX_TRAIT_ASSOCIATED_TYPES];
            let mut seen_count = 0usize;
            for source_value in implementation.associated_types().iter().flatten() {
                let associated = traits
                    .get_associated_type(trait_id, source_value.name)
                    .ok_or(SourceTraitImplementationError {
                        kind: SourceTraitImplementationErrorKind::UnknownAssociatedType,
                        span: source_value.name_span,
                    })?;
                if seen[..seen_count].contains(&Some(associated.id)) {
                    return Err(SourceTraitImplementationError {
                        kind: SourceTraitImplementationErrorKind::DuplicateAssociatedTypeValue,
                        span: source_value.name_span,
                    });
                }
                seen[seen_count] = Some(associated.id);
                seen_count += 1;
                let value = table.get_type(source_value.value.text).unwrap().id;
                table
                    .associated_types
                    .insert(
                        &table.implementations,
                        TraitAssociatedTypeValue::new(
                            TraitImplementationId::new(implementation_index),
                            associated.id,
                            value,
                        ),
                    )
                    .map_err(|kind| SourceTraitImplementationError {
                        kind: SourceTraitImplementationErrorKind::Goal(kind),
                        span: source_value.name_span,
                    })?;
            }
            for associated_id in declaration.associated_types().iter().flatten() {
                if seen[..seen_count].contains(&Some(*associated_id)) {
                    continue;
                }
                let associated = traits.get_associated_type_by_id(*associated_id).unwrap();
                let default = associated.default.ok_or(SourceTraitImplementationError {
                    kind: SourceTraitImplementationErrorKind::MissingAssociatedTypeValue,
                    span: implementation.trait_name_span,
                })?;
                let source_value = if default.text == "Self" {
                    implementation.self_type
                } else if let Some(index) = declaration
                    .generic_parameters()
                    .iter()
                    .position(|parameter| *parameter == Some(default.text))
                {
                    source_declaration_implementation_argument(index, &declaration, implementation)
                } else {
                    default
                };
                let source_value = if source_value.text == "Self" {
                    implementation.self_type
                } else {
                    source_value
                };
                let value = table.get_type(source_value.text).unwrap().id;
                table
                    .associated_types
                    .insert(
                        &table.implementations,
                        TraitAssociatedTypeValue::new(
                            TraitImplementationId::new(implementation_index),
                            associated.id,
                            value,
                        ),
                    )
                    .map_err(|kind| SourceTraitImplementationError {
                        kind: SourceTraitImplementationErrorKind::Goal(kind),
                        span: associated.span,
                    })?;
                seen[seen_count] = Some(associated.id);
                seen_count += 1;
            }
            if declaration.associated_type_count() != seen_count {
                return Err(SourceTraitImplementationError {
                    kind: SourceTraitImplementationErrorKind::MissingAssociatedTypeValue,
                    span: implementation.trait_name_span,
                });
            }
            implementation_index += 1;
        }
        let mut generic_implementation_index = 0u32;
        for item in module.items().iter().flatten() {
            let Item::TraitImplementation(implementation) = item else {
                continue;
            };
            if source_implementation_is_exact_fact(implementation, traits) {
                continue;
            }
            let trait_id = traits.get(implementation.trait_name).unwrap().id;
            let declaration = traits.get_by_id(trait_id).unwrap();
            let mut seen = [None; MAX_TRAIT_ASSOCIATED_TYPES];
            let mut seen_count = 0usize;
            for source_value in implementation.associated_types().iter().flatten() {
                let associated = traits
                    .get_associated_type(trait_id, source_value.name)
                    .ok_or(SourceTraitImplementationError {
                        kind: SourceTraitImplementationErrorKind::UnknownAssociatedType,
                        span: source_value.name_span,
                    })?;
                if seen[..seen_count].contains(&Some(associated.id)) {
                    return Err(SourceTraitImplementationError {
                        kind: SourceTraitImplementationErrorKind::DuplicateAssociatedTypeValue,
                        span: source_value.name_span,
                    });
                }
                seen[seen_count] = Some(associated.id);
                seen_count += 1;
                let projection = source_value.value.parse_trait_projection().map_err(|_| {
                    SourceTraitImplementationError {
                        kind:
                            SourceTraitImplementationErrorKind::UnsupportedAssociatedTypeProjection,
                        span: source_value.value.span,
                    }
                })?;
                let value = if let Some(projection) = projection {
                    let projected_trait = traits.get(projection.trait_name).ok_or(
                        SourceTraitImplementationError {
                            kind: SourceTraitImplementationErrorKind::UnknownTrait,
                            span: projection.trait_name_span,
                        },
                    )?;
                    if !projected_trait.supports_argument_count(projection.trait_argument_count()) {
                        return Err(SourceTraitImplementationError {
                            kind: SourceTraitImplementationErrorKind::WrongTraitArgumentCount,
                            span: projection.trait_name_span,
                        });
                    }
                    let projected_associated = traits
                        .get_associated_type(projected_trait.id, projection.associated_type)
                        .ok_or(SourceTraitImplementationError {
                            kind: SourceTraitImplementationErrorKind::UnknownAssociatedType,
                            span: projection.associated_type_span,
                        })?;
                    let mut goal = BoundImplementedTraitGoal::new(
                        projected_trait.id,
                        source_bound_type(projection.self_type, implementation, &table)?,
                    );
                    for argument in projection.trait_arguments().iter().flatten() {
                        goal.push_argument(source_bound_type(*argument, implementation, &table)?)
                            .map_err(|kind| SourceTraitImplementationError {
                                kind: SourceTraitImplementationErrorKind::Goal(kind),
                                span: argument.span,
                            })?;
                    }
                    push_source_bound_trait_defaults(
                        &mut goal,
                        &projected_trait,
                        projection.trait_argument_count(),
                        &table,
                    )?;
                    GenericTraitAssociatedTypeValue::new_projection(
                        GenericTraitImplementationId::new(generic_implementation_index),
                        associated.id,
                        BoundTraitProjection::new(goal, projected_associated.id),
                    )
                } else {
                    GenericTraitAssociatedTypeValue::new(
                        GenericTraitImplementationId::new(generic_implementation_index),
                        associated.id,
                        source_bound_type(source_value.value, implementation, &table)?,
                    )
                };
                table
                    .generic_associated_types
                    .insert(&table.generic_implementations, value)
                    .map_err(|kind| SourceTraitImplementationError {
                        kind: SourceTraitImplementationErrorKind::Goal(kind),
                        span: source_value.name_span,
                    })?;
            }
            for associated_id in declaration.associated_types().iter().flatten() {
                if seen[..seen_count].contains(&Some(*associated_id)) {
                    continue;
                }
                let associated = traits.get_associated_type_by_id(*associated_id).unwrap();
                let default = associated.default.ok_or(SourceTraitImplementationError {
                    kind: SourceTraitImplementationErrorKind::MissingAssociatedTypeValue,
                    span: implementation.trait_name_span,
                })?;
                let projection = default.parse_trait_projection().unwrap();
                let value = if let Some(projection) = projection {
                    let projected_trait = traits.get(projection.trait_name).unwrap();
                    let projected_associated = traits
                        .get_associated_type(projected_trait.id, projection.associated_type)
                        .unwrap();
                    let mut goal = BoundImplementedTraitGoal::new(
                        projected_trait.id,
                        source_declaration_implementation_bound_type(
                            projection.self_type,
                            &declaration,
                            implementation,
                            &table,
                        )?,
                    );
                    for argument in projection.trait_arguments().iter().flatten() {
                        goal.push_argument(source_declaration_implementation_bound_type(
                            *argument,
                            &declaration,
                            implementation,
                            &table,
                        )?)
                        .map_err(|kind| {
                            SourceTraitImplementationError {
                                kind: SourceTraitImplementationErrorKind::Goal(kind),
                                span: argument.span,
                            }
                        })?;
                    }
                    push_source_bound_trait_defaults(
                        &mut goal,
                        &projected_trait,
                        projection.trait_argument_count(),
                        &table,
                    )?;
                    GenericTraitAssociatedTypeValue::new_projection(
                        GenericTraitImplementationId::new(generic_implementation_index),
                        associated.id,
                        BoundTraitProjection::new(goal, projected_associated.id),
                    )
                } else {
                    GenericTraitAssociatedTypeValue::new(
                        GenericTraitImplementationId::new(generic_implementation_index),
                        associated.id,
                        source_declaration_implementation_bound_type(
                            default,
                            &declaration,
                            implementation,
                            &table,
                        )?,
                    )
                };
                table
                    .generic_associated_types
                    .insert(&table.generic_implementations, value)
                    .map_err(|kind| SourceTraitImplementationError {
                        kind: SourceTraitImplementationErrorKind::Goal(kind),
                        span: associated.span,
                    })?;
                seen[seen_count] = Some(associated.id);
                seen_count += 1;
            }
            if declaration.associated_type_count() != seen_count {
                return Err(SourceTraitImplementationError {
                    kind: SourceTraitImplementationErrorKind::MissingAssociatedTypeValue,
                    span: implementation.trait_name_span,
                });
            }
            generic_implementation_index += 1;
        }
        for item in module.items().iter().flatten() {
            let Item::TraitImplementation(implementation) = item else {
                continue;
            };
            if !source_implementation_is_exact_fact(implementation, traits) {
                continue;
            }
            let trait_id = traits.get(implementation.trait_name).unwrap().id;
            let declaration = traits.get_by_id(trait_id).unwrap();
            let self_type = table.get_type(implementation.self_type.text).unwrap().id;
            let mut trait_arguments = [TraitTypeId::new(0); MAX_TRAIT_GOAL_ARGUMENTS];
            for (index, argument) in implementation
                .trait_arguments()
                .iter()
                .flatten()
                .enumerate()
            {
                trait_arguments[index] = table.get_type(argument.text).unwrap().id;
            }
            for argument_index in
                implementation.trait_argument_count()..declaration.generic_parameter_count
            {
                let default = declaration.generic_parameter_defaults()[argument_index].unwrap();
                trait_arguments[argument_index] = if default.text == "Self" {
                    self_type
                } else {
                    declaration
                        .generic_parameters()
                        .iter()
                        .position(|parameter| *parameter == Some(default.text))
                        .map(|parameter_index| trait_arguments[parameter_index])
                        .unwrap_or_else(|| table.get_type(default.text).unwrap().id)
                };
            }
            table
                .prove_supertraits(
                    trait_id,
                    &trait_arguments[..declaration.generic_parameter_count],
                    self_type,
                    traits,
                    0,
                )
                .map_err(|kind| SourceTraitImplementationError {
                    kind,
                    span: implementation.trait_name_span,
                })?;
        }
        Ok(table)
    }

    pub fn types(&self) -> &[Option<SourceTraitType<'source>>] {
        &self.types[..self.type_count]
    }

    pub fn get_type(&self, name: &str) -> Option<SourceTraitType<'source>> {
        self.types()
            .iter()
            .flatten()
            .copied()
            .find(|ty| ty.name == name)
    }

    pub const fn implementations(&self) -> &TraitImplementationDatabase {
        &self.implementations
    }

    pub const fn associated_type_values(&self) -> &TraitAssociatedTypeDatabase {
        &self.associated_types
    }

    pub const fn generic_implementations(&self) -> &GenericTraitImplementationDatabase {
        &self.generic_implementations
    }

    pub const fn generic_associated_type_values(&self) -> &GenericTraitAssociatedTypeDatabase {
        &self.generic_associated_types
    }

    pub fn prove_function<const MAX_PARAMETERS: usize>(
        &self,
        function: &Function<'source, MAX_PARAMETERS>,
        traits: &SourceTraitDeclarationTable<'source>,
    ) -> Result<(), SourceTraitObligationError> {
        for (index, predicate) in function.where_predicates().iter().flatten().enumerate() {
            if function.where_predicates()[..index]
                .iter()
                .flatten()
                .any(|known| match (known, predicate) {
                    (
                        FunctionWherePredicate::Implemented {
                            self_type: left_self,
                            trait_name: left_trait,
                            trait_arguments: left_arguments,
                            trait_argument_count: left_count,
                            ..
                        },
                        FunctionWherePredicate::Implemented {
                            self_type: right_self,
                            trait_name: right_trait,
                            trait_arguments: right_arguments,
                            trait_argument_count: right_count,
                            ..
                        },
                    ) => {
                        left_self.text == right_self.text
                            && left_trait == right_trait
                            && left_count == right_count
                            && left_arguments[..*left_count]
                                .iter()
                                .zip(&right_arguments[..*right_count])
                                .all(|(left, right)| left.unwrap().text == right.unwrap().text)
                    }
                    (
                        FunctionWherePredicate::ProjectionEquality {
                            self_type: left_self,
                            trait_name: left_trait,
                            trait_arguments: left_arguments,
                            trait_argument_count: left_count,
                            associated_type: left_associated,
                            expected_type: left_expected,
                            ..
                        },
                        FunctionWherePredicate::ProjectionEquality {
                            self_type: right_self,
                            trait_name: right_trait,
                            trait_arguments: right_arguments,
                            trait_argument_count: right_count,
                            associated_type: right_associated,
                            expected_type: right_expected,
                            ..
                        },
                    ) => {
                        left_self.text == right_self.text
                            && left_trait == right_trait
                            && left_count == right_count
                            && left_arguments[..*left_count]
                                .iter()
                                .zip(&right_arguments[..*right_count])
                                .all(|(left, right)| left.unwrap().text == right.unwrap().text)
                            && left_associated == right_associated
                            && left_expected.text == right_expected.text
                    }
                    _ => false,
                })
            {
                return Err(SourceTraitObligationError {
                    kind: SourceTraitObligationErrorKind::DuplicatePredicate,
                    span: match predicate {
                        FunctionWherePredicate::Implemented {
                            trait_name_span, ..
                        }
                        | FunctionWherePredicate::ProjectionEquality {
                            trait_name_span, ..
                        } => *trait_name_span,
                    },
                });
            }
            let (
                self_type_ref,
                trait_name,
                trait_name_span,
                trait_arguments,
                trait_argument_count,
                projection,
            ) = match predicate {
                FunctionWherePredicate::Implemented {
                    self_type,
                    trait_name,
                    trait_name_span,
                    trait_arguments,
                    trait_argument_count,
                } => (
                    *self_type,
                    *trait_name,
                    *trait_name_span,
                    trait_arguments,
                    *trait_argument_count,
                    None,
                ),
                FunctionWherePredicate::ProjectionEquality {
                    self_type,
                    trait_name,
                    trait_name_span,
                    trait_arguments,
                    trait_argument_count,
                    associated_type,
                    associated_type_span,
                    expected_type,
                } => (
                    *self_type,
                    *trait_name,
                    *trait_name_span,
                    trait_arguments,
                    *trait_argument_count,
                    Some((*associated_type, *associated_type_span, *expected_type)),
                ),
            };
            let declaration = traits.get(trait_name).ok_or(SourceTraitObligationError {
                kind: SourceTraitObligationErrorKind::UnknownTrait,
                span: trait_name_span,
            })?;
            if !declaration.supports_argument_count(trait_argument_count) {
                return Err(SourceTraitObligationError {
                    kind: SourceTraitObligationErrorKind::Goal(
                        TraitGoalError::WrongGenericArgumentCount,
                    ),
                    span: trait_name_span,
                });
            }
            let trait_id = declaration.id;
            let self_type = self
                .get_type(self_type_ref.text)
                .ok_or(SourceTraitObligationError {
                    kind: SourceTraitObligationErrorKind::UnknownType,
                    span: self_type_ref.span,
                })?
                .id;
            let mut source_goal =
                ImplementedTraitGoal::new(trait_id, TraitGoalType::Concrete(self_type));
            for argument in trait_arguments[..trait_argument_count].iter().flatten() {
                let argument_type =
                    self.get_type(argument.text)
                        .ok_or(SourceTraitObligationError {
                            kind: SourceTraitObligationErrorKind::UnknownType,
                            span: argument.span,
                        })?;
                source_goal
                    .push_argument(TraitGoalType::Concrete(argument_type.id))
                    .map_err(|kind| SourceTraitObligationError {
                        kind: SourceTraitObligationErrorKind::Goal(kind),
                        span: argument.span,
                    })?;
            }
            for argument_index in trait_argument_count..declaration.generic_parameter_count {
                let default = declaration.generic_parameter_defaults()[argument_index].unwrap();
                let argument = if default.text == "Self" {
                    TraitGoalType::Concrete(self_type)
                } else {
                    declaration
                        .generic_parameters()
                        .iter()
                        .position(|parameter| *parameter == Some(default.text))
                        .map(|parameter_index| source_goal.arguments()[parameter_index].unwrap())
                        .unwrap_or_else(|| {
                            TraitGoalType::Concrete(self.get_type(default.text).unwrap().id)
                        })
                };
                source_goal
                    .push_argument(argument)
                    .map_err(|kind| SourceTraitObligationError {
                        kind: SourceTraitObligationErrorKind::Goal(kind),
                        span: default.span,
                    })?;
            }
            canonicalize_implemented_trait_goal(source_goal).map_err(|kind| {
                SourceTraitObligationError {
                    kind: SourceTraitObligationErrorKind::Goal(kind),
                    span: trait_name_span,
                }
            })?;
            if let Some((associated_name, associated_span, expected_type_ref)) = projection {
                let associated = traits
                    .get_associated_type(trait_id, associated_name)
                    .ok_or(SourceTraitObligationError {
                        kind: SourceTraitObligationErrorKind::UnknownAssociatedType,
                        span: associated_span,
                    })?;
                let expected_type =
                    self.get_type(expected_type_ref.text)
                        .ok_or(SourceTraitObligationError {
                            kind: SourceTraitObligationErrorKind::UnknownType,
                            span: expected_type_ref.span,
                        })?;
                match normalize_concrete_trait_projection(
                    &self.implementations,
                    &self.generic_implementations,
                    &TraitWhereClauseDatabase::EMPTY,
                    &self.associated_types,
                    &self.generic_associated_types,
                    source_goal,
                    associated.id,
                )
                .map_err(|kind| SourceTraitObligationError {
                    kind: SourceTraitObligationErrorKind::Goal(kind),
                    span: associated_span,
                })? {
                    TraitProjectionSolution::Unique(value) if value == expected_type.id => continue,
                    TraitProjectionSolution::Unique(_) => {
                        return Err(SourceTraitObligationError {
                            kind: SourceTraitObligationErrorKind::ProjectionMismatch,
                            span: expected_type_ref.span,
                        });
                    }
                    TraitProjectionSolution::NoSolution => {
                        return Err(SourceTraitObligationError {
                            kind: SourceTraitObligationErrorKind::Unsatisfied,
                            span: associated_span,
                        });
                    }
                    TraitProjectionSolution::Ambiguous => {
                        return Err(SourceTraitObligationError {
                            kind: SourceTraitObligationErrorKind::Ambiguous,
                            span: associated_span,
                        });
                    }
                    TraitProjectionSolution::Cycle => {
                        return Err(SourceTraitObligationError {
                            kind: SourceTraitObligationErrorKind::Goal(TraitGoalError::InvalidGoal),
                            span: associated_span,
                        });
                    }
                    TraitProjectionSolution::Overflow => {
                        return Err(SourceTraitObligationError {
                            kind: SourceTraitObligationErrorKind::Goal(TraitGoalError::InvalidGoal),
                            span: associated_span,
                        });
                    }
                }
            }
            match solve_concrete_trait_goal_with_projection_environment(
                &self.implementations,
                &self.generic_implementations,
                &TraitWhereClauseDatabase::EMPTY,
                &self.associated_types,
                &self.generic_associated_types,
                source_goal,
            )
            .map_err(|kind| SourceTraitObligationError {
                kind: SourceTraitObligationErrorKind::Goal(kind),
                span: trait_name_span,
            })? {
                TraitProofSolution::Proven => {}
                TraitProofSolution::NoSolution => {
                    return Err(SourceTraitObligationError {
                        kind: SourceTraitObligationErrorKind::Unsatisfied,
                        span: trait_name_span,
                    });
                }
                TraitProofSolution::Ambiguous => {
                    return Err(SourceTraitObligationError {
                        kind: SourceTraitObligationErrorKind::Ambiguous,
                        span: trait_name_span,
                    });
                }
                TraitProofSolution::Cycle | TraitProofSolution::Overflow => {
                    return Err(SourceTraitObligationError {
                        kind: SourceTraitObligationErrorKind::Goal(TraitGoalError::InvalidGoal),
                        span: trait_name_span,
                    });
                }
            }
        }
        Ok(())
    }

    pub fn prove_module<const MAX_ITEMS: usize, const MAX_PARAMETERS: usize>(
        &self,
        module: &Module<'source, MAX_ITEMS, MAX_PARAMETERS>,
        traits: &SourceTraitDeclarationTable<'source>,
    ) -> Result<(), SourceTraitObligationError> {
        for item in module.items().iter().flatten() {
            if let Item::Function(function) = item {
                self.prove_function(function, traits)?;
            }
        }
        Ok(())
    }

    fn intern_type(
        &mut self,
        source_type: TypeRef<'source>,
    ) -> Result<TraitTypeId, SourceTraitImplementationError> {
        if !supported_source_trait_type(source_type.text) {
            return Err(SourceTraitImplementationError {
                kind: SourceTraitImplementationErrorKind::UnsupportedSelfType,
                span: source_type.span,
            });
        }
        if let Some(known) = self.get_type(source_type.text) {
            return Ok(known.id);
        }
        let slot = self
            .types
            .get_mut(self.type_count)
            .ok_or(SourceTraitImplementationError {
                kind: SourceTraitImplementationErrorKind::TooManyTypes,
                span: source_type.span,
            })?;
        let id = TraitTypeId::new(self.type_count as u32);
        *slot = Some(SourceTraitType {
            id,
            name: source_type.text,
            span: source_type.span,
        });
        self.type_count += 1;
        Ok(id)
    }

    fn prove_supertraits(
        &self,
        trait_id: TraitId,
        trait_arguments: &[TraitTypeId],
        self_type: TraitTypeId,
        traits: &SourceTraitDeclarationTable<'source>,
        depth: usize,
    ) -> Result<(), SourceTraitImplementationErrorKind> {
        if depth == MAX_SOURCE_TRAIT_DECLARATIONS {
            return Err(SourceTraitImplementationErrorKind::Goal(
                TraitGoalError::InvalidGoal,
            ));
        }
        let declaration = traits
            .get_by_id(trait_id)
            .ok_or(SourceTraitImplementationErrorKind::UnknownTrait)?;
        for supertrait in declaration.supertraits().iter().flatten() {
            let mut goal =
                ImplementedTraitGoal::new(supertrait.trait_id, TraitGoalType::Concrete(self_type));
            let mut inherited_arguments = [TraitTypeId::new(0); MAX_TRAIT_GOAL_ARGUMENTS];
            for (index, source_argument) in supertrait.arguments().iter().flatten().enumerate() {
                let argument = match source_argument {
                    SourceTraitSupertraitArgument::SelfType => self_type,
                    SourceTraitSupertraitArgument::Parameter(parameter_index) => {
                        trait_arguments[*parameter_index as usize]
                    }
                    SourceTraitSupertraitArgument::Concrete(source_type) => {
                        self.get_type(source_type.text).unwrap().id
                    }
                };
                inherited_arguments[index] = argument;
                goal.push_argument(TraitGoalType::Concrete(argument))
                    .map_err(SourceTraitImplementationErrorKind::Goal)?;
            }
            match solve_concrete_trait_goal_with_projection_environment(
                &self.implementations,
                &self.generic_implementations,
                &TraitWhereClauseDatabase::EMPTY,
                &self.associated_types,
                &self.generic_associated_types,
                goal,
            )
            .map_err(SourceTraitImplementationErrorKind::Goal)?
            {
                TraitProofSolution::Proven => {}
                TraitProofSolution::NoSolution => {
                    return Err(
                        SourceTraitImplementationErrorKind::MissingSupertraitImplementation,
                    );
                }
                TraitProofSolution::Ambiguous => {
                    return Err(
                        SourceTraitImplementationErrorKind::AmbiguousSupertraitImplementation,
                    );
                }
                TraitProofSolution::Cycle | TraitProofSolution::Overflow => {
                    return Err(SourceTraitImplementationErrorKind::Goal(
                        TraitGoalError::InvalidGoal,
                    ));
                }
            }
            self.prove_supertraits(
                supertrait.trait_id,
                &inherited_arguments[..supertrait.argument_count()],
                self_type,
                traits,
                depth + 1,
            )?;
        }
        Ok(())
    }
}

fn source_implementation_is_exact_fact(
    implementation: &crate::TraitImplementation<'_>,
    traits: &SourceTraitDeclarationTable<'_>,
) -> bool {
    implementation.generic_parameter_count() == 0
        && implementation.where_predicate_count() == 0
        && traits
            .get(implementation.trait_name)
            .is_some_and(|declaration| {
                declaration.where_predicate_count() == 0
                    && !declaration.associated_types().iter().flatten().any(|id| {
                        let associated = traits.get_associated_type_by_id(*id).unwrap();
                        implementation
                            .associated_types()
                            .iter()
                            .flatten()
                            .all(|value| value.name != associated.name)
                            && associated.default.is_some_and(|default| {
                                matches!(default.parse_trait_projection(), Ok(Some(_)))
                            })
                    })
            })
        && !implementation
            .associated_types()
            .iter()
            .flatten()
            .any(|value| matches!(value.value.parse_trait_projection(), Ok(Some(_))))
}

fn source_implementation_predicates_same(
    left: &crate::TraitImplementationWherePredicate<'_>,
    right: &crate::TraitImplementationWherePredicate<'_>,
    traits: &SourceTraitDeclarationTable<'_>,
) -> bool {
    let Some(declaration) = traits.get(left.trait_name()) else {
        return false;
    };
    let common = left.self_type().text == right.self_type().text
        && left.trait_name() == right.trait_name()
        && (0..declaration.generic_parameter_count).all(|index| {
            let left = source_predicate_effective_argument(left, &declaration, index);
            let right = source_predicate_effective_argument(right, &declaration, index);
            left.zip(right)
                .is_some_and(|(left, right)| left.text == right.text)
        });
    if !common {
        return false;
    }
    match (left, right) {
        (
            crate::TraitImplementationWherePredicate::Implemented { .. },
            crate::TraitImplementationWherePredicate::Implemented { .. },
        ) => true,
        (
            crate::TraitImplementationWherePredicate::ProjectionEquality {
                associated_type: left_associated,
                expected_type: left_expected,
                ..
            },
            crate::TraitImplementationWherePredicate::ProjectionEquality {
                associated_type: right_associated,
                expected_type: right_expected,
                ..
            },
        ) => left_associated == right_associated && left_expected.text == right_expected.text,
        _ => false,
    }
}

fn source_bound_type(
    source: TypeRef<'_>,
    implementation: &crate::TraitImplementation<'_>,
    table: &SourceTraitImplementationTable<'_>,
) -> Result<BoundTraitGoalType, SourceTraitImplementationError> {
    if let Some(index) = implementation
        .generic_parameters()
        .iter()
        .position(|parameter| *parameter == Some(source.text))
    {
        return Ok(BoundTraitGoalType::Parameter(TraitGenericParameterId::new(
            index as u8,
        )));
    }
    table
        .get_type(source.text)
        .map(|ty| BoundTraitGoalType::Concrete(ty.id))
        .ok_or(SourceTraitImplementationError {
            kind: SourceTraitImplementationErrorKind::UnsupportedSelfType,
            span: source.span,
        })
}

fn source_declaration_bound_type(
    source: TypeRef<'_>,
    declaration: &SourceTraitDeclaration<'_>,
    consequence: BoundImplementedTraitGoal,
    table: &SourceTraitImplementationTable<'_>,
) -> Result<BoundTraitGoalType, SourceTraitImplementationError> {
    if source.text == "Self" {
        return Ok(consequence.self_type);
    }
    if let Some(index) = declaration
        .generic_parameters()
        .iter()
        .position(|parameter| *parameter == Some(source.text))
    {
        return Ok(consequence.arguments()[index].unwrap());
    }
    table
        .get_type(source.text)
        .map(|ty| BoundTraitGoalType::Concrete(ty.id))
        .ok_or(SourceTraitImplementationError {
            kind: SourceTraitImplementationErrorKind::UnsupportedSelfType,
            span: source.span,
        })
}

fn source_declaration_implementation_bound_type(
    source: TypeRef<'_>,
    declaration: &SourceTraitDeclaration<'_>,
    implementation: &crate::TraitImplementation<'_>,
    table: &SourceTraitImplementationTable<'_>,
) -> Result<BoundTraitGoalType, SourceTraitImplementationError> {
    if source.text == "Self" {
        return source_bound_type(implementation.self_type, implementation, table);
    }
    if let Some(index) = declaration
        .generic_parameters()
        .iter()
        .position(|parameter| *parameter == Some(source.text))
    {
        let source_argument =
            source_declaration_implementation_argument(index, declaration, implementation);
        if source_argument.text == "Self" {
            return source_bound_type(implementation.self_type, implementation, table);
        }
        return source_bound_type(source_argument, implementation, table);
    }
    table
        .get_type(source.text)
        .map(|ty| BoundTraitGoalType::Concrete(ty.id))
        .ok_or(SourceTraitImplementationError {
            kind: SourceTraitImplementationErrorKind::UnsupportedSelfType,
            span: source.span,
        })
}

fn source_declaration_implementation_argument<'source>(
    index: usize,
    declaration: &SourceTraitDeclaration<'source>,
    implementation: &crate::TraitImplementation<'source>,
) -> TypeRef<'source> {
    if let Some(argument) = implementation
        .trait_arguments()
        .get(index)
        .copied()
        .flatten()
    {
        return argument;
    }
    let default = declaration.generic_parameter_defaults()[index].unwrap();
    declaration
        .generic_parameters()
        .iter()
        .position(|parameter| *parameter == Some(default.text))
        .map(|parameter_index| {
            source_declaration_implementation_argument(parameter_index, declaration, implementation)
        })
        .unwrap_or(default)
}

fn source_predicate_effective_argument<'source>(
    predicate: &crate::TraitImplementationWherePredicate<'source>,
    declaration: &SourceTraitDeclaration<'source>,
    index: usize,
) -> Option<TypeRef<'source>> {
    if let Some(argument) = predicate.trait_arguments().get(index).copied().flatten() {
        return Some(argument);
    }
    let default = declaration
        .generic_parameter_defaults()
        .get(index)
        .copied()
        .flatten()?;
    if default.text == "Self" {
        return Some(predicate.self_type());
    }
    declaration
        .generic_parameters()
        .iter()
        .position(|parameter| *parameter == Some(default.text))
        .and_then(|parameter_index| {
            source_predicate_effective_argument(predicate, declaration, parameter_index)
        })
        .or(Some(default))
}

fn push_source_bound_trait_defaults(
    goal: &mut BoundImplementedTraitGoal,
    declaration: &SourceTraitDeclaration<'_>,
    provided_count: usize,
    table: &SourceTraitImplementationTable<'_>,
) -> Result<(), SourceTraitImplementationError> {
    for argument_index in provided_count..declaration.generic_parameter_count {
        let default = declaration.generic_parameter_defaults()[argument_index].unwrap();
        let value = if default.text == "Self" {
            goal.self_type
        } else {
            declaration
                .generic_parameters()
                .iter()
                .position(|parameter| *parameter == Some(default.text))
                .map(|parameter_index| goal.arguments()[parameter_index].unwrap())
                .unwrap_or_else(|| {
                    BoundTraitGoalType::Concrete(table.get_type(default.text).unwrap().id)
                })
        };
        goal.push_argument(value)
            .map_err(|kind| SourceTraitImplementationError {
                kind: SourceTraitImplementationErrorKind::Goal(kind),
                span: default.span,
            })?;
    }
    Ok(())
}

fn supported_source_trait_type(name: &str) -> bool {
    !name.is_empty()
        && name.split("::").all(|segment| {
            let mut bytes = segment.bytes();
            bytes
                .next()
                .is_some_and(|first| first == b'_' || first.is_ascii_alphabetic())
                && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
        })
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TraitAssociatedTypeId(u32);

impl TraitAssociatedTypeId {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TraitTypeId(u32);

impl TraitTypeId {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TraitInferenceVariableId {
    universe: TraitUniverseIndex,
    id: u32,
}

impl TraitInferenceVariableId {
    pub const fn new(value: u32) -> Self {
        Self::in_universe(TraitUniverseIndex::ROOT, value)
    }

    pub const fn in_universe(universe: TraitUniverseIndex, value: u32) -> Self {
        Self {
            universe,
            id: value,
        }
    }

    pub const fn get(self) -> u32 {
        self.id
    }

    pub const fn universe(self) -> TraitUniverseIndex {
        self.universe
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TraitPlaceholderId(u32);

impl TraitPlaceholderId {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TraitUniverseIndex(u16);

impl TraitUniverseIndex {
    pub const ROOT: Self = Self(0);

    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u16 {
        self.0
    }

    pub fn next(self) -> Result<Self, TraitGoalError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(TraitGoalError::UniverseOverflow)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TraitPlaceholder {
    pub universe: TraitUniverseIndex,
    pub id: TraitPlaceholderId,
}

impl TraitPlaceholder {
    pub const fn new(universe: TraitUniverseIndex, id: TraitPlaceholderId) -> Self {
        Self { universe, id }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraitGoalType {
    Concrete(TraitTypeId),
    InferenceVariable(TraitInferenceVariableId),
    Placeholder(TraitPlaceholder),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraitUniverseAssignment {
    variable: TraitInferenceVariableId,
    value: TraitGoalType,
}

impl TraitUniverseAssignment {
    pub fn new(
        variable: TraitInferenceVariableId,
        value: TraitGoalType,
    ) -> Result<Self, TraitGoalError> {
        let value_universe = match value {
            TraitGoalType::Concrete(_) => TraitUniverseIndex::ROOT,
            TraitGoalType::InferenceVariable(variable) => variable.universe(),
            TraitGoalType::Placeholder(placeholder) => placeholder.universe,
        };
        if value_universe > variable.universe() {
            return Err(TraitGoalError::UniverseLeak);
        }
        Ok(Self { variable, value })
    }

    pub const fn variable(self) -> TraitInferenceVariableId {
        self.variable
    }

    pub const fn value(self) -> TraitGoalType {
        self.value
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TraitGenericParameterId(u8);

impl TraitGenericParameterId {
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundTraitGoalType {
    Concrete(TraitTypeId),
    Parameter(TraitGenericParameterId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalTraitGoalType {
    Concrete(TraitTypeId),
    BoundVariable(u8),
    Placeholder(TraitPlaceholder),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImplementedTraitGoal {
    pub trait_id: TraitId,
    pub self_type: TraitGoalType,
    arguments: [Option<TraitGoalType>; MAX_TRAIT_GOAL_ARGUMENTS],
    argument_count: usize,
}

impl ImplementedTraitGoal {
    pub const fn new(trait_id: TraitId, self_type: TraitGoalType) -> Self {
        Self {
            trait_id,
            self_type,
            arguments: [None; MAX_TRAIT_GOAL_ARGUMENTS],
            argument_count: 0,
        }
    }

    pub fn push_argument(&mut self, argument: TraitGoalType) -> Result<(), TraitGoalError> {
        let slot = self
            .arguments
            .get_mut(self.argument_count)
            .ok_or(TraitGoalError::TooManyArguments)?;
        *slot = Some(argument);
        self.argument_count += 1;
        Ok(())
    }

    pub fn arguments(&self) -> &[Option<TraitGoalType>] {
        &self.arguments[..self.argument_count]
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TraitGoalTermId(u8);

impl TraitGoalTermId {
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionBearingTraitGoal {
    pub trait_id: TraitId,
    pub self_type: TraitGoalTermId,
    arguments: [Option<TraitGoalTermId>; MAX_TRAIT_GOAL_ARGUMENTS],
    argument_count: usize,
}

impl ProjectionBearingTraitGoal {
    pub const fn new(trait_id: TraitId, self_type: TraitGoalTermId) -> Self {
        Self {
            trait_id,
            self_type,
            arguments: [None; MAX_TRAIT_GOAL_ARGUMENTS],
            argument_count: 0,
        }
    }

    pub fn push_argument(&mut self, argument: TraitGoalTermId) -> Result<(), TraitGoalError> {
        let slot = self
            .arguments
            .get_mut(self.argument_count)
            .ok_or(TraitGoalError::TooManyArguments)?;
        *slot = Some(argument);
        self.argument_count += 1;
        Ok(())
    }

    pub fn arguments(&self) -> &[Option<TraitGoalTermId>] {
        &self.arguments[..self.argument_count]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraitGoalTerm {
    Type(TraitGoalType),
    Projection {
        goal: ProjectionBearingTraitGoal,
        associated_type_id: TraitAssociatedTypeId,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraitGoalTermArena {
    terms: [Option<TraitGoalTerm>; MAX_TRAIT_GOAL_TERMS],
    term_count: usize,
}

impl TraitGoalTermArena {
    pub const EMPTY: Self = Self {
        terms: [None; MAX_TRAIT_GOAL_TERMS],
        term_count: 0,
    };

    pub fn intern_type(&mut self, ty: TraitGoalType) -> Result<TraitGoalTermId, TraitGoalError> {
        self.intern(TraitGoalTerm::Type(ty))
    }

    pub fn intern_projection(
        &mut self,
        goal: ProjectionBearingTraitGoal,
        associated_type_id: TraitAssociatedTypeId,
    ) -> Result<TraitGoalTermId, TraitGoalError> {
        validate_projection_bearing_goal(goal, self.term_count)?;
        self.intern(TraitGoalTerm::Projection {
            goal,
            associated_type_id,
        })
    }

    pub fn get(&self, id: TraitGoalTermId) -> Option<TraitGoalTerm> {
        self.terms.get(id.get() as usize).copied().flatten()
    }

    pub fn terms(&self) -> &[Option<TraitGoalTerm>] {
        &self.terms[..self.term_count]
    }

    fn intern(&mut self, term: TraitGoalTerm) -> Result<TraitGoalTermId, TraitGoalError> {
        if let Some((index, _)) = self.terms[..self.term_count]
            .iter()
            .enumerate()
            .find(|(_, existing)| **existing == Some(term))
        {
            return Ok(TraitGoalTermId::new(index as u8));
        }
        let slot = self
            .terms
            .get_mut(self.term_count)
            .ok_or(TraitGoalError::TooManyTraitGoalTerms)?;
        let id = TraitGoalTermId::new(self.term_count as u8);
        *slot = Some(term);
        self.term_count += 1;
        Ok(id)
    }
}

fn validate_projection_bearing_goal(
    goal: ProjectionBearingTraitGoal,
    term_count: usize,
) -> Result<(), TraitGoalError> {
    if goal.argument_count > goal.arguments.len()
        || goal.arguments[..goal.argument_count]
            .iter()
            .any(Option::is_none)
        || goal.arguments[goal.argument_count..]
            .iter()
            .any(Option::is_some)
    {
        return Err(TraitGoalError::InvalidGoal);
    }
    if goal.self_type.get() as usize >= term_count
        || goal.arguments().iter().any(|argument| {
            argument
                .as_ref()
                .is_none_or(|argument| argument.get() as usize >= term_count)
        })
    {
        return Err(TraitGoalError::InvalidTraitGoalTermReference);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundProjectionBearingTraitGoal {
    pub trait_id: TraitId,
    pub self_type: TraitGoalTermId,
    arguments: [Option<TraitGoalTermId>; MAX_TRAIT_GOAL_ARGUMENTS],
    argument_count: usize,
}

impl BoundProjectionBearingTraitGoal {
    pub const fn new(trait_id: TraitId, self_type: TraitGoalTermId) -> Self {
        Self {
            trait_id,
            self_type,
            arguments: [None; MAX_TRAIT_GOAL_ARGUMENTS],
            argument_count: 0,
        }
    }

    pub fn push_argument(&mut self, argument: TraitGoalTermId) -> Result<(), TraitGoalError> {
        let slot = self
            .arguments
            .get_mut(self.argument_count)
            .ok_or(TraitGoalError::TooManyArguments)?;
        *slot = Some(argument);
        self.argument_count += 1;
        Ok(())
    }

    pub fn arguments(&self) -> &[Option<TraitGoalTermId>] {
        &self.arguments[..self.argument_count]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundTraitGoalTerm {
    Type(BoundTraitGoalType),
    Projection {
        goal: BoundProjectionBearingTraitGoal,
        associated_type_id: TraitAssociatedTypeId,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundTraitGoalTermArena {
    terms: [Option<BoundTraitGoalTerm>; MAX_TRAIT_GOAL_TERMS],
    term_count: usize,
}

impl BoundTraitGoalTermArena {
    pub const EMPTY: Self = Self {
        terms: [None; MAX_TRAIT_GOAL_TERMS],
        term_count: 0,
    };

    pub fn intern_type(
        &mut self,
        ty: BoundTraitGoalType,
    ) -> Result<TraitGoalTermId, TraitGoalError> {
        self.intern(BoundTraitGoalTerm::Type(ty))
    }

    pub fn intern_projection(
        &mut self,
        goal: BoundProjectionBearingTraitGoal,
        associated_type_id: TraitAssociatedTypeId,
    ) -> Result<TraitGoalTermId, TraitGoalError> {
        validate_bound_projection_bearing_goal(goal, self.term_count)?;
        self.intern(BoundTraitGoalTerm::Projection {
            goal,
            associated_type_id,
        })
    }

    pub fn get(&self, id: TraitGoalTermId) -> Option<BoundTraitGoalTerm> {
        self.terms.get(id.get() as usize).copied().flatten()
    }

    pub fn terms(&self) -> &[Option<BoundTraitGoalTerm>] {
        &self.terms[..self.term_count]
    }

    fn intern(&mut self, term: BoundTraitGoalTerm) -> Result<TraitGoalTermId, TraitGoalError> {
        if let Some((index, _)) = self.terms[..self.term_count]
            .iter()
            .enumerate()
            .find(|(_, existing)| **existing == Some(term))
        {
            return Ok(TraitGoalTermId::new(index as u8));
        }
        let slot = self
            .terms
            .get_mut(self.term_count)
            .ok_or(TraitGoalError::TooManyTraitGoalTerms)?;
        let id = TraitGoalTermId::new(self.term_count as u8);
        *slot = Some(term);
        self.term_count += 1;
        Ok(id)
    }
}

fn validate_bound_projection_bearing_goal(
    goal: BoundProjectionBearingTraitGoal,
    term_count: usize,
) -> Result<(), TraitGoalError> {
    if goal.argument_count > goal.arguments.len()
        || goal.arguments[..goal.argument_count]
            .iter()
            .any(Option::is_none)
        || goal.arguments[goal.argument_count..]
            .iter()
            .any(Option::is_some)
    {
        return Err(TraitGoalError::InvalidGoal);
    }
    if goal.self_type.get() as usize >= term_count
        || goal.arguments().iter().any(|argument| {
            argument
                .as_ref()
                .is_none_or(|argument| argument.get() as usize >= term_count)
        })
    {
        return Err(TraitGoalError::InvalidTraitGoalTermReference);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstantiatedProjectionBearingTraitGoal {
    pub arena: TraitGoalTermArena,
    pub goal: ProjectionBearingTraitGoal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExistsProjectionBearingTraitGoal {
    parameter_count: usize,
    arena: BoundTraitGoalTermArena,
    goal: BoundProjectionBearingTraitGoal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForAllProjectionBearingTraitGoal {
    parameter_count: usize,
    arena: BoundTraitGoalTermArena,
    goal: BoundProjectionBearingTraitGoal,
}

impl ForAllProjectionBearingTraitGoal {
    pub fn new(
        parameter_count: usize,
        arena: BoundTraitGoalTermArena,
        goal: BoundProjectionBearingTraitGoal,
    ) -> Result<Self, TraitGoalError> {
        if parameter_count > MAX_TRAIT_GENERIC_PARAMETERS {
            return Err(TraitGoalError::TooManyGenericParameters);
        }
        validate_bound_projection_bearing_goal(goal, arena.term_count)?;
        for term in arena.terms().iter().flatten() {
            if let BoundTraitGoalTerm::Type(ty) = term {
                validate_bound_type(*ty, parameter_count)?;
            }
        }
        Ok(Self {
            parameter_count,
            arena,
            goal,
        })
    }

    pub const fn parameter_count(self) -> usize {
        self.parameter_count
    }

    pub fn instantiate_in_universe(
        self,
        universe: TraitUniverseIndex,
    ) -> Result<InstantiatedProjectionBearingTraitGoal, TraitGoalError> {
        let mut arguments = [TraitGoalType::Placeholder(TraitPlaceholder::new(
            universe,
            TraitPlaceholderId::new(0),
        )); MAX_TRAIT_GENERIC_PARAMETERS];
        for (index, argument) in arguments[..self.parameter_count].iter_mut().enumerate() {
            *argument = TraitGoalType::Placeholder(TraitPlaceholder::new(
                universe,
                TraitPlaceholderId::new(index as u32),
            ));
        }
        instantiate_bound_term_goal(&self.arena, self.goal, &arguments[..self.parameter_count])
    }
}

impl ExistsProjectionBearingTraitGoal {
    pub fn new(
        parameter_count: usize,
        arena: BoundTraitGoalTermArena,
        goal: BoundProjectionBearingTraitGoal,
    ) -> Result<Self, TraitGoalError> {
        if parameter_count > MAX_TRAIT_GENERIC_PARAMETERS {
            return Err(TraitGoalError::TooManyGenericParameters);
        }
        validate_bound_projection_bearing_goal(goal, arena.term_count)?;
        for term in arena.terms().iter().flatten() {
            if let BoundTraitGoalTerm::Type(ty) = term {
                validate_bound_type(*ty, parameter_count)?;
            }
        }
        Ok(Self {
            parameter_count,
            arena,
            goal,
        })
    }

    pub fn instantiate_in_universe(
        self,
        universe: TraitUniverseIndex,
    ) -> Result<InstantiatedProjectionBearingTraitGoal, TraitGoalError> {
        let mut arguments =
            [TraitGoalType::InferenceVariable(TraitInferenceVariableId::in_universe(universe, 0));
                MAX_TRAIT_GENERIC_PARAMETERS];
        for (index, argument) in arguments[..self.parameter_count].iter_mut().enumerate() {
            *argument = TraitGoalType::InferenceVariable(TraitInferenceVariableId::in_universe(
                universe,
                index as u32,
            ));
        }
        instantiate_bound_term_goal(&self.arena, self.goal, &arguments[..self.parameter_count])
    }
}

fn instantiate_bound_term_goal(
    bound_arena: &BoundTraitGoalTermArena,
    bound_goal: BoundProjectionBearingTraitGoal,
    arguments: &[TraitGoalType],
) -> Result<InstantiatedProjectionBearingTraitGoal, TraitGoalError> {
    let mut arena = TraitGoalTermArena::EMPTY;
    let mut mapped = [None; MAX_TRAIT_GOAL_TERMS];
    for (index, term) in bound_arena.terms().iter().enumerate() {
        let term = term.as_ref().copied().ok_or(TraitGoalError::InvalidGoal)?;
        let instantiated = match term {
            BoundTraitGoalTerm::Type(ty) => {
                arena.intern_type(instantiate_bound_type(ty, arguments)?)?
            }
            BoundTraitGoalTerm::Projection {
                goal,
                associated_type_id,
            } => arena.intern_projection(
                map_bound_projection_bearing_goal(goal, &mapped[..index])?,
                associated_type_id,
            )?,
        };
        mapped[index] = Some(instantiated);
    }
    Ok(InstantiatedProjectionBearingTraitGoal {
        arena,
        goal: map_bound_projection_bearing_goal(bound_goal, &mapped[..bound_arena.term_count])?,
    })
}

fn map_bound_projection_bearing_goal(
    goal: BoundProjectionBearingTraitGoal,
    mapped: &[Option<TraitGoalTermId>],
) -> Result<ProjectionBearingTraitGoal, TraitGoalError> {
    let self_type = mapped
        .get(goal.self_type.get() as usize)
        .and_then(Option::as_ref)
        .copied()
        .ok_or(TraitGoalError::InvalidTraitGoalTermReference)?;
    let mut instantiated = ProjectionBearingTraitGoal::new(goal.trait_id, self_type);
    for argument in goal.arguments() {
        instantiated.push_argument(
            mapped
                .get(
                    argument
                        .as_ref()
                        .copied()
                        .ok_or(TraitGoalError::InvalidGoal)?
                        .get() as usize,
                )
                .and_then(Option::as_ref)
                .copied()
                .ok_or(TraitGoalError::InvalidTraitGoalTermReference)?,
        )?;
    }
    Ok(instantiated)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImplementedTraitPredicates {
    predicates: [Option<ImplementedTraitGoal>; MAX_TRAIT_PREDICATES],
    predicate_count: usize,
}

impl ImplementedTraitPredicates {
    pub const EMPTY: Self = Self {
        predicates: [None; MAX_TRAIT_PREDICATES],
        predicate_count: 0,
    };

    pub fn push(&mut self, predicate: ImplementedTraitGoal) -> Result<(), TraitGoalError> {
        let slot = self
            .predicates
            .get_mut(self.predicate_count)
            .ok_or(TraitGoalError::TooManyPredicates)?;
        *slot = Some(predicate);
        self.predicate_count += 1;
        Ok(())
    }

    pub fn predicates(&self) -> &[Option<ImplementedTraitGoal>] {
        &self.predicates[..self.predicate_count]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundImplementedTraitGoal {
    pub trait_id: TraitId,
    pub self_type: BoundTraitGoalType,
    arguments: [Option<BoundTraitGoalType>; MAX_TRAIT_GOAL_ARGUMENTS],
    argument_count: usize,
}

impl BoundImplementedTraitGoal {
    pub const fn new(trait_id: TraitId, self_type: BoundTraitGoalType) -> Self {
        Self {
            trait_id,
            self_type,
            arguments: [None; MAX_TRAIT_GOAL_ARGUMENTS],
            argument_count: 0,
        }
    }

    pub fn push_argument(&mut self, argument: BoundTraitGoalType) -> Result<(), TraitGoalError> {
        let slot = self
            .arguments
            .get_mut(self.argument_count)
            .ok_or(TraitGoalError::TooManyArguments)?;
        *slot = Some(argument);
        self.argument_count += 1;
        Ok(())
    }

    pub fn arguments(&self) -> &[Option<BoundTraitGoalType>] {
        &self.arguments[..self.argument_count]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForAllImplementedTraitGoal {
    parameter_count: usize,
    pub goal: BoundImplementedTraitGoal,
}

impl ForAllImplementedTraitGoal {
    pub fn new(
        parameter_count: usize,
        goal: BoundImplementedTraitGoal,
    ) -> Result<Self, TraitGoalError> {
        if parameter_count > MAX_TRAIT_GENERIC_PARAMETERS {
            return Err(TraitGoalError::TooManyGenericParameters);
        }
        validate_bound_goal(goal, parameter_count)?;
        Ok(Self {
            parameter_count,
            goal,
        })
    }

    pub const fn parameter_count(self) -> usize {
        self.parameter_count
    }

    pub fn instantiate_in_universe(
        self,
        universe: TraitUniverseIndex,
    ) -> Result<ImplementedTraitGoal, TraitGoalError> {
        let mut arguments = [TraitGoalType::Placeholder(TraitPlaceholder::new(
            universe,
            TraitPlaceholderId::new(0),
        )); MAX_TRAIT_GENERIC_PARAMETERS];
        for (index, argument) in arguments[..self.parameter_count].iter_mut().enumerate() {
            *argument = TraitGoalType::Placeholder(TraitPlaceholder::new(
                universe,
                TraitPlaceholderId::new(index as u32),
            ));
        }
        instantiate_bound_goal(self.goal, &arguments[..self.parameter_count])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExistsImplementedTraitGoal {
    parameter_count: usize,
    pub goal: BoundImplementedTraitGoal,
}

impl ExistsImplementedTraitGoal {
    pub fn new(
        parameter_count: usize,
        goal: BoundImplementedTraitGoal,
    ) -> Result<Self, TraitGoalError> {
        if parameter_count > MAX_TRAIT_GENERIC_PARAMETERS {
            return Err(TraitGoalError::TooManyGenericParameters);
        }
        validate_bound_goal(goal, parameter_count)?;
        Ok(Self {
            parameter_count,
            goal,
        })
    }

    pub const fn parameter_count(self) -> usize {
        self.parameter_count
    }

    pub fn instantiate_in_universe(
        self,
        universe: TraitUniverseIndex,
    ) -> Result<ImplementedTraitGoal, TraitGoalError> {
        let mut arguments =
            [TraitGoalType::InferenceVariable(TraitInferenceVariableId::in_universe(universe, 0));
                MAX_TRAIT_GENERIC_PARAMETERS];
        for (index, argument) in arguments[..self.parameter_count].iter_mut().enumerate() {
            *argument = TraitGoalType::InferenceVariable(TraitInferenceVariableId::in_universe(
                universe,
                index as u32,
            ));
        }
        instantiate_bound_goal(self.goal, &arguments[..self.parameter_count])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstantiatedTraitWhereClause {
    pub consequence: ImplementedTraitGoal,
    pub premises: ImplementedTraitPredicates,
    pub projection_premises: InferredTraitProjectionPredicates,
}

impl InstantiatedTraitWhereClause {
    pub const fn has_projection_premises(self) -> bool {
        !self.projection_premises.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraitWhereClauseElaboration {
    Unique(InstantiatedTraitWhereClause),
    Ambiguous,
    NoSolution,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraitWhereClause {
    parameter_count: usize,
    pub consequence: BoundImplementedTraitGoal,
    premises: [Option<BoundImplementedTraitGoal>; MAX_TRAIT_PREDICATES],
    premise_count: usize,
    projection_premises: [Option<(BoundTraitProjection, BoundTraitGoalType)>; MAX_TRAIT_PREDICATES],
    projection_premise_count: usize,
}

impl TraitWhereClause {
    pub fn new(
        parameter_count: usize,
        consequence: BoundImplementedTraitGoal,
    ) -> Result<Self, TraitGoalError> {
        if parameter_count > MAX_TRAIT_GENERIC_PARAMETERS {
            return Err(TraitGoalError::TooManyGenericParameters);
        }
        validate_bound_goal(consequence, parameter_count)?;
        Ok(Self {
            parameter_count,
            consequence,
            premises: [None; MAX_TRAIT_PREDICATES],
            premise_count: 0,
            projection_premises: [None; MAX_TRAIT_PREDICATES],
            projection_premise_count: 0,
        })
    }

    pub const fn parameter_count(&self) -> usize {
        self.parameter_count
    }

    pub fn push_premise(
        &mut self,
        premise: BoundImplementedTraitGoal,
    ) -> Result<(), TraitGoalError> {
        validate_bound_goal(premise, self.parameter_count)?;
        if self.premise_count + self.projection_premise_count >= MAX_TRAIT_PREDICATES {
            return Err(TraitGoalError::TooManyPredicates);
        }
        let slot = self
            .premises
            .get_mut(self.premise_count)
            .ok_or(TraitGoalError::TooManyPredicates)?;
        *slot = Some(premise);
        self.premise_count += 1;
        Ok(())
    }

    pub fn premises(&self) -> &[Option<BoundImplementedTraitGoal>] {
        &self.premises[..self.premise_count]
    }

    pub fn push_projection_premise(
        &mut self,
        projection: BoundTraitProjection,
        expected: BoundTraitGoalType,
    ) -> Result<(), TraitGoalError> {
        validate_bound_goal(projection.goal, self.parameter_count)?;
        validate_bound_type(expected, self.parameter_count)?;
        if self.premise_count + self.projection_premise_count >= MAX_TRAIT_PREDICATES {
            return Err(TraitGoalError::TooManyPredicates);
        }
        let slot = self
            .projection_premises
            .get_mut(self.projection_premise_count)
            .ok_or(TraitGoalError::TooManyPredicates)?;
        *slot = Some((projection, expected));
        self.projection_premise_count += 1;
        Ok(())
    }

    pub fn projection_premises(&self) -> &[Option<(BoundTraitProjection, BoundTraitGoalType)>] {
        &self.projection_premises[..self.projection_premise_count]
    }

    pub fn instantiate(
        self,
        arguments: &[TraitTypeId],
    ) -> Result<InstantiatedTraitWhereClause, TraitGoalError> {
        if arguments.len() != self.parameter_count {
            return Err(TraitGoalError::WrongGenericArgumentCount);
        }
        let mut goal_arguments =
            [TraitGoalType::Concrete(TraitTypeId::new(0)); MAX_TRAIT_GENERIC_PARAMETERS];
        for (index, argument) in arguments.iter().copied().enumerate() {
            goal_arguments[index] = TraitGoalType::Concrete(argument);
        }
        self.instantiate_goal_types(&goal_arguments[..arguments.len()])
    }

    pub fn instantiate_rigid(
        self,
        universe: TraitUniverseIndex,
    ) -> Result<InstantiatedTraitWhereClause, TraitGoalError> {
        let mut arguments = [TraitGoalType::Placeholder(TraitPlaceholder::new(
            universe,
            TraitPlaceholderId::new(0),
        )); MAX_TRAIT_GENERIC_PARAMETERS];
        for (index, argument) in arguments[..self.parameter_count].iter_mut().enumerate() {
            *argument = TraitGoalType::Placeholder(TraitPlaceholder::new(
                universe,
                TraitPlaceholderId::new(index as u32),
            ));
        }
        self.instantiate_goal_types(&arguments[..self.parameter_count])
    }

    fn instantiate_goal_types(
        self,
        arguments: &[TraitGoalType],
    ) -> Result<InstantiatedTraitWhereClause, TraitGoalError> {
        if arguments.len() != self.parameter_count {
            return Err(TraitGoalError::WrongGenericArgumentCount);
        }
        let consequence = instantiate_bound_goal(self.consequence, arguments)?;
        let mut premises = ImplementedTraitPredicates::EMPTY;
        for premise in self.premises().iter() {
            premises.push(instantiate_bound_goal(
                premise
                    .as_ref()
                    .copied()
                    .ok_or(TraitGoalError::InvalidGoal)?,
                arguments,
            )?)?;
        }
        let mut projection_premises = InferredTraitProjectionPredicates::EMPTY;
        for premise in self.projection_premises() {
            let (projection, expected) = premise
                .as_ref()
                .copied()
                .ok_or(TraitGoalError::InvalidGoal)?;
            projection_premises.push(InferredTraitProjectionEquality {
                goal: instantiate_bound_goal(projection.goal, arguments)?,
                associated_type_id: projection.associated_type_id,
                expected: instantiate_bound_type(expected, arguments)?,
            })?;
        }
        Ok(InstantiatedTraitWhereClause {
            consequence,
            premises,
            projection_premises,
        })
    }

    pub fn elaborate(
        self,
        consequence: ImplementedTraitGoal,
    ) -> Result<TraitWhereClauseElaboration, TraitGoalError> {
        validate_concrete_goal(consequence)?;
        if self.consequence.trait_id != consequence.trait_id
            || self.consequence.argument_count != consequence.argument_count
        {
            return Ok(TraitWhereClauseElaboration::NoSolution);
        }
        let mut bindings = [None; MAX_TRAIT_GENERIC_PARAMETERS];
        if !bound_type_matches_concrete(
            self.consequence.self_type,
            concrete_goal_type(consequence.self_type)?,
            &mut bindings,
        ) {
            return Ok(TraitWhereClauseElaboration::NoSolution);
        }
        for (bound, concrete) in self
            .consequence
            .arguments()
            .iter()
            .zip(consequence.arguments())
        {
            let bound = bound.as_ref().copied().ok_or(TraitGoalError::InvalidGoal)?;
            let concrete = concrete
                .as_ref()
                .copied()
                .ok_or(TraitGoalError::InvalidGoal)?;
            if !bound_type_matches_concrete(bound, concrete_goal_type(concrete)?, &mut bindings) {
                return Ok(TraitWhereClauseElaboration::NoSolution);
            }
        }
        let mut arguments = [TraitTypeId::new(0); MAX_TRAIT_GENERIC_PARAMETERS];
        for (index, binding) in bindings[..self.parameter_count].iter().enumerate() {
            let Some(binding) = binding else {
                return Ok(TraitWhereClauseElaboration::Ambiguous);
            };
            arguments[index] = *binding;
        }
        self.instantiate(&arguments[..self.parameter_count])
            .map(TraitWhereClauseElaboration::Unique)
    }

    fn rigid_bindings(
        self,
        consequence: ImplementedTraitGoal,
    ) -> Result<Option<[Option<TraitGoalType>; MAX_TRAIT_GENERIC_PARAMETERS]>, TraitGoalError> {
        validate_rigid_goal(consequence)?;
        if self.consequence.trait_id != consequence.trait_id
            || self.consequence.argument_count != consequence.argument_count
        {
            return Ok(None);
        }
        let mut bindings = [None; MAX_TRAIT_GENERIC_PARAMETERS];
        if !bound_type_matches_rigid(
            self.consequence.self_type,
            rigid_goal_type(consequence.self_type)?,
            &mut bindings,
        ) {
            return Ok(None);
        }
        for (bound, concrete) in self
            .consequence
            .arguments()
            .iter()
            .zip(consequence.arguments())
        {
            let bound = bound.as_ref().copied().ok_or(TraitGoalError::InvalidGoal)?;
            let rigid = concrete
                .as_ref()
                .copied()
                .ok_or(TraitGoalError::InvalidGoal)?;
            if !bound_type_matches_rigid(bound, rigid_goal_type(rigid)?, &mut bindings) {
                return Ok(None);
            }
        }
        Ok(Some(bindings))
    }

    pub fn elaborate_rigid(
        self,
        consequence: ImplementedTraitGoal,
    ) -> Result<TraitWhereClauseElaboration, TraitGoalError> {
        validate_rigid_goal(consequence)?;
        if self.consequence.trait_id != consequence.trait_id
            || self.consequence.argument_count != consequence.argument_count
        {
            return Ok(TraitWhereClauseElaboration::NoSolution);
        }
        let mut bindings = [None; MAX_TRAIT_GENERIC_PARAMETERS];
        if !bound_type_matches_rigid(
            self.consequence.self_type,
            rigid_goal_type(consequence.self_type)?,
            &mut bindings,
        ) {
            return Ok(TraitWhereClauseElaboration::NoSolution);
        }
        for (bound, rigid) in self
            .consequence
            .arguments()
            .iter()
            .zip(consequence.arguments())
        {
            let bound = bound.as_ref().copied().ok_or(TraitGoalError::InvalidGoal)?;
            let rigid = rigid.as_ref().copied().ok_or(TraitGoalError::InvalidGoal)?;
            if !bound_type_matches_rigid(bound, rigid_goal_type(rigid)?, &mut bindings) {
                return Ok(TraitWhereClauseElaboration::NoSolution);
            }
        }
        let mut arguments =
            [TraitGoalType::Concrete(TraitTypeId::new(0)); MAX_TRAIT_GENERIC_PARAMETERS];
        for (index, binding) in bindings[..self.parameter_count].iter().enumerate() {
            let Some(binding) = binding else {
                return Ok(TraitWhereClauseElaboration::Ambiguous);
            };
            arguments[index] = *binding;
        }
        self.instantiate_goal_types(&arguments[..self.parameter_count])
            .map(TraitWhereClauseElaboration::Unique)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GenericTraitImplementationId(u32);

impl GenericTraitImplementationId {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IdentifiedGenericTraitImplementation {
    id: GenericTraitImplementationId,
    implementation: TraitWhereClause,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenericTraitImplementationAnswer {
    pub implementation_id: GenericTraitImplementationId,
    pub instantiated: InstantiatedTraitWhereClause,
    arguments: [Option<TraitGoalType>; MAX_TRAIT_GENERIC_PARAMETERS],
    argument_count: usize,
}

impl GenericTraitImplementationAnswer {
    pub fn arguments(&self) -> &[Option<TraitGoalType>] {
        &self.arguments[..self.argument_count]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenericTraitImplementationSolution {
    Unique(GenericTraitImplementationAnswer),
    Ambiguous,
    NoSolution,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SymbolicTraitGoalSubstitution {
    bindings: [Option<TraitUniverseAssignment>; MAX_CANONICAL_TRAIT_VARIABLES],
    binding_count: usize,
}

impl SymbolicTraitGoalSubstitution {
    pub fn bindings(&self) -> &[Option<TraitUniverseAssignment>] {
        &self.bindings[..self.binding_count]
    }

    pub fn binding(&self, variable: TraitInferenceVariableId) -> Option<TraitGoalType> {
        self.bindings()
            .iter()
            .flatten()
            .find(|binding| binding.variable() == variable)
            .map(|binding| binding.value())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenericExistentialTraitGoalAnswer {
    pub implementation_id: GenericTraitImplementationId,
    pub instantiated: InstantiatedTraitWhereClause,
    pub substitution: SymbolicTraitGoalSubstitution,
    arguments: [TraitGoalType; MAX_TRAIT_GENERIC_PARAMETERS],
    argument_count: usize,
}

impl GenericExistentialTraitGoalAnswer {
    pub fn arguments(&self) -> &[TraitGoalType] {
        &self.arguments[..self.argument_count]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenericExistentialTraitGoalSolution {
    Unique(GenericExistentialTraitGoalAnswer),
    Ambiguous,
    NoSolution,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InferredTraitGoalAnswer {
    pub substitution: SymbolicTraitGoalSubstitution,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InferredTraitGoalSolution {
    Unique(InferredTraitGoalAnswer),
    Ambiguous,
    NoSolution,
    Cycle,
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InferredTraitProjectionAnswer {
    pub substitution: SymbolicTraitGoalSubstitution,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InferredTraitProjectionSolution {
    Unique(InferredTraitProjectionAnswer),
    Ambiguous,
    NoSolution,
    Cycle,
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraitGoalTermNormalizationAnswer {
    pub value: TraitGoalType,
    pub substitution: SymbolicTraitGoalSubstitution,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraitGoalTermNormalizationSolution {
    Unique(TraitGoalTermNormalizationAnswer),
    Ambiguous,
    NoSolution,
    Cycle,
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenericTraitImplementationDatabase {
    implementations:
        [Option<IdentifiedGenericTraitImplementation>; MAX_GENERIC_TRAIT_IMPLEMENTATIONS],
    implementation_count: usize,
}

impl GenericTraitImplementationDatabase {
    pub const EMPTY: Self = Self {
        implementations: [None; MAX_GENERIC_TRAIT_IMPLEMENTATIONS],
        implementation_count: 0,
    };

    pub fn insert(
        &mut self,
        id: GenericTraitImplementationId,
        implementation: TraitWhereClause,
    ) -> Result<(), TraitGoalError> {
        for existing in self.implementations[..self.implementation_count]
            .iter()
            .flatten()
            .copied()
        {
            if existing.id == id {
                return Err(TraitGoalError::DuplicateGenericImplementationId);
            }
            if generic_trait_implementation_heads_overlap(existing.implementation, implementation) {
                return Err(TraitGoalError::OverlappingGenericImplementation);
            }
        }
        let slot = self
            .implementations
            .get_mut(self.implementation_count)
            .ok_or(TraitGoalError::TooManyGenericImplementations)?;
        *slot = Some(IdentifiedGenericTraitImplementation { id, implementation });
        self.implementation_count += 1;
        Ok(())
    }

    pub fn insert_coherent_with_exact(
        &mut self,
        exact: &TraitImplementationDatabase,
        id: GenericTraitImplementationId,
        implementation: TraitWhereClause,
    ) -> Result<(), TraitGoalError> {
        if exact.implementations[..exact.implementation_count]
            .iter()
            .flatten()
            .copied()
            .any(|header| generic_trait_implementation_overlaps_exact(implementation, header))
        {
            return Err(TraitGoalError::OverlappingExactAndGenericImplementation);
        }
        self.insert(id, implementation)
    }

    pub fn select(
        &self,
        goal: ImplementedTraitGoal,
    ) -> Result<GenericTraitImplementationSolution, TraitGoalError> {
        validate_concrete_goal(goal)?;
        let mut selected = None;
        for implementation in self.implementations[..self.implementation_count]
            .iter()
            .flatten()
            .copied()
        {
            match implementation.implementation.elaborate(goal)? {
                TraitWhereClauseElaboration::Unique(instantiated) => {
                    if selected.is_some() {
                        return Ok(GenericTraitImplementationSolution::Ambiguous);
                    }
                    let arguments = implementation
                        .implementation
                        .rigid_bindings(goal)?
                        .ok_or(TraitGoalError::InvalidGoal)?;
                    selected = Some(GenericTraitImplementationAnswer {
                        implementation_id: implementation.id,
                        instantiated,
                        arguments,
                        argument_count: implementation.implementation.parameter_count,
                    });
                }
                TraitWhereClauseElaboration::Ambiguous => {
                    return Ok(GenericTraitImplementationSolution::Ambiguous);
                }
                TraitWhereClauseElaboration::NoSolution => {}
            }
        }
        Ok(selected.map_or(
            GenericTraitImplementationSolution::NoSolution,
            GenericTraitImplementationSolution::Unique,
        ))
    }

    pub fn select_rigid(
        &self,
        goal: ImplementedTraitGoal,
    ) -> Result<GenericTraitImplementationSolution, TraitGoalError> {
        validate_rigid_goal(goal)?;
        let mut selected = None;
        for implementation in self.implementations[..self.implementation_count]
            .iter()
            .flatten()
            .copied()
        {
            match implementation.implementation.elaborate_rigid(goal)? {
                TraitWhereClauseElaboration::Unique(instantiated) => {
                    if selected.is_some() {
                        return Ok(GenericTraitImplementationSolution::Ambiguous);
                    }
                    let arguments = implementation
                        .implementation
                        .rigid_bindings(goal)?
                        .ok_or(TraitGoalError::InvalidGoal)?;
                    selected = Some(GenericTraitImplementationAnswer {
                        implementation_id: implementation.id,
                        instantiated,
                        arguments,
                        argument_count: implementation.implementation.parameter_count,
                    });
                }
                TraitWhereClauseElaboration::Ambiguous => {
                    return Ok(GenericTraitImplementationSolution::Ambiguous);
                }
                TraitWhereClauseElaboration::NoSolution => {}
            }
        }
        Ok(selected.map_or(
            GenericTraitImplementationSolution::NoSolution,
            GenericTraitImplementationSolution::Unique,
        ))
    }

    pub fn select_existential(
        &self,
        goal: ImplementedTraitGoal,
    ) -> Result<GenericExistentialTraitGoalSolution, TraitGoalError> {
        validate_existential_goal(goal)?;
        let canonicalized = canonicalize_implemented_trait_goal_with_variables(goal)?;
        let mut selected = None;
        for implementation in self.implementations[..self.implementation_count]
            .iter()
            .flatten()
            .copied()
        {
            match match_generic_existential_head(implementation.implementation, canonicalized)? {
                GenericExistentialHeadMatch::Unique {
                    arguments,
                    substitution,
                } => {
                    if selected.is_some() {
                        return Ok(GenericExistentialTraitGoalSolution::Ambiguous);
                    }
                    selected = Some(GenericExistentialTraitGoalAnswer {
                        implementation_id: implementation.id,
                        instantiated: implementation.implementation.instantiate_goal_types(
                            &arguments[..implementation.implementation.parameter_count],
                        )?,
                        substitution,
                        arguments,
                        argument_count: implementation.implementation.parameter_count,
                    });
                }
                GenericExistentialHeadMatch::Ambiguous => {
                    return Ok(GenericExistentialTraitGoalSolution::Ambiguous);
                }
                GenericExistentialHeadMatch::NoSolution => {}
            }
        }
        Ok(selected.map_or(
            GenericExistentialTraitGoalSolution::NoSolution,
            GenericExistentialTraitGoalSolution::Unique,
        ))
    }

    fn find(
        &self,
        id: GenericTraitImplementationId,
    ) -> Option<IdentifiedGenericTraitImplementation> {
        self.implementations[..self.implementation_count]
            .iter()
            .flatten()
            .copied()
            .find(|implementation| implementation.id == id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GenericExistentialHeadMatch {
    Unique {
        arguments: [TraitGoalType; MAX_TRAIT_GENERIC_PARAMETERS],
        substitution: SymbolicTraitGoalSubstitution,
    },
    Ambiguous,
    NoSolution,
}

fn match_generic_existential_head(
    implementation: TraitWhereClause,
    query: CanonicalizedImplementedTraitGoal,
) -> Result<GenericExistentialHeadMatch, TraitGoalError> {
    if implementation.consequence.trait_id != query.goal.trait_id
        || implementation.consequence.argument_count != query.goal.argument_count
    {
        return Ok(GenericExistentialHeadMatch::NoSolution);
    }
    let mut unifier = FlatExistentialHeadUnifier::NEW;
    if !unifier.unify(implementation.consequence.self_type, query.goal.self_type)? {
        return Ok(GenericExistentialHeadMatch::NoSolution);
    }
    for (implementation, query) in implementation
        .consequence
        .arguments()
        .iter()
        .zip(query.goal.arguments())
    {
        let implementation = implementation
            .as_ref()
            .copied()
            .ok_or(TraitGoalError::InvalidGoal)?;
        let query = query.as_ref().copied().ok_or(TraitGoalError::InvalidGoal)?;
        if !unifier.unify(implementation, query)? {
            return Ok(GenericExistentialHeadMatch::NoSolution);
        }
    }

    let mut arguments =
        [TraitGoalType::Concrete(TraitTypeId::new(0)); MAX_TRAIT_GENERIC_PARAMETERS];
    for (index, argument) in arguments[..implementation.parameter_count]
        .iter_mut()
        .enumerate()
    {
        let root = unifier.root(index);
        *argument = if let Some(concrete) = unifier.concrete[root] {
            TraitGoalType::Concrete(concrete)
        } else if let Some(variable) = existential_root_representative(unifier, root, query) {
            TraitGoalType::InferenceVariable(variable)
        } else {
            return Ok(GenericExistentialHeadMatch::Ambiguous);
        };
    }

    let mut bindings = [None; MAX_CANONICAL_TRAIT_VARIABLES];
    for (index, variable) in query.variables().iter().enumerate() {
        let variable = variable
            .as_ref()
            .copied()
            .ok_or(TraitGoalError::InvalidGoal)?;
        let root = unifier.root(MAX_TRAIT_GENERIC_PARAMETERS + index);
        let value = unifier.concrete[root]
            .map(TraitGoalType::Concrete)
            .or_else(|| {
                existential_root_representative(unifier, root, query)
                    .map(TraitGoalType::InferenceVariable)
            })
            .ok_or(TraitGoalError::InvalidGoal)?;
        bindings[index] = Some(TraitUniverseAssignment::new(variable, value)?);
    }
    Ok(GenericExistentialHeadMatch::Unique {
        arguments,
        substitution: SymbolicTraitGoalSubstitution {
            bindings,
            binding_count: query.variable_count,
        },
    })
}

fn existential_root_representative(
    unifier: FlatExistentialHeadUnifier,
    root: usize,
    query: CanonicalizedImplementedTraitGoal,
) -> Option<TraitInferenceVariableId> {
    query
        .variables()
        .iter()
        .enumerate()
        .filter_map(|(index, variable)| {
            (unifier.root(MAX_TRAIT_GENERIC_PARAMETERS + index) == root)
                .then(|| variable.as_ref().copied())
                .flatten()
        })
        .min()
}

#[derive(Clone, Copy)]
struct FlatExistentialHeadUnifier {
    parents: [u8; MAX_TRAIT_GENERIC_PARAMETERS + MAX_CANONICAL_TRAIT_VARIABLES],
    concrete: [Option<TraitTypeId>; MAX_TRAIT_GENERIC_PARAMETERS + MAX_CANONICAL_TRAIT_VARIABLES],
}

impl FlatExistentialHeadUnifier {
    const NEW: Self = Self {
        parents: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        concrete: [None; MAX_TRAIT_GENERIC_PARAMETERS + MAX_CANONICAL_TRAIT_VARIABLES],
    };

    fn unify(
        &mut self,
        implementation: BoundTraitGoalType,
        query: CanonicalTraitGoalType,
    ) -> Result<bool, TraitGoalError> {
        match (implementation, query) {
            (
                BoundTraitGoalType::Concrete(implementation),
                CanonicalTraitGoalType::Concrete(query),
            ) => Ok(implementation == query),
            (
                BoundTraitGoalType::Concrete(implementation),
                CanonicalTraitGoalType::BoundVariable(query),
            ) => Ok(self.constrain(
                MAX_TRAIT_GENERIC_PARAMETERS + query as usize,
                implementation,
            )),
            (
                BoundTraitGoalType::Parameter(implementation),
                CanonicalTraitGoalType::Concrete(query),
            ) => Ok(self.constrain(implementation.get() as usize, query)),
            (
                BoundTraitGoalType::Parameter(implementation),
                CanonicalTraitGoalType::BoundVariable(query),
            ) => Ok(self.union(
                implementation.get() as usize,
                MAX_TRAIT_GENERIC_PARAMETERS + query as usize,
            )),
            (_, CanonicalTraitGoalType::Placeholder(_)) => {
                Err(TraitGoalError::NonExistentialClauseQuery)
            }
        }
    }

    fn root(self, mut variable: usize) -> usize {
        while self.parents[variable] as usize != variable {
            variable = self.parents[variable] as usize;
        }
        variable
    }

    fn constrain(&mut self, variable: usize, concrete: TraitTypeId) -> bool {
        let root = self.root(variable);
        match self.concrete[root] {
            Some(existing) => existing == concrete,
            None => {
                self.concrete[root] = Some(concrete);
                true
            }
        }
    }

    fn union(&mut self, left: usize, right: usize) -> bool {
        let left = self.root(left);
        let right = self.root(right);
        if left == right {
            return true;
        }
        match (self.concrete[left], self.concrete[right]) {
            (Some(left), Some(right)) if left != right => return false,
            _ => {}
        }
        self.parents[right] = left as u8;
        if self.concrete[left].is_none() {
            self.concrete[left] = self.concrete[right];
        }
        true
    }
}

pub fn generic_trait_implementation_heads_overlap(
    left: TraitWhereClause,
    right: TraitWhereClause,
) -> bool {
    if left.consequence.trait_id != right.consequence.trait_id
        || left.consequence.argument_count != right.consequence.argument_count
    {
        return false;
    }
    let mut unifier = FlatGenericHeadUnifier::NEW;
    if !unifier.unify(left.consequence.self_type, right.consequence.self_type) {
        return false;
    }
    left.consequence
        .arguments()
        .iter()
        .zip(right.consequence.arguments())
        .all(|(left, right)| {
            left.zip(*right)
                .is_some_and(|(left, right)| unifier.unify(left, right))
        })
}

pub fn generic_trait_implementation_overlaps_exact(
    generic: TraitWhereClause,
    exact: TraitImplementationHeader,
) -> bool {
    if generic.consequence.trait_id != exact.trait_id
        || generic.consequence.argument_count != exact.argument_count
    {
        return false;
    }
    let mut bindings = [None; MAX_TRAIT_GENERIC_PARAMETERS];
    if !bound_type_matches_exact(
        generic.consequence.self_type,
        exact.self_type,
        &mut bindings,
    ) {
        return false;
    }
    generic
        .consequence
        .arguments()
        .iter()
        .zip(exact.arguments())
        .all(|(generic, exact)| {
            generic.zip(*exact).is_some_and(|(generic, exact)| {
                bound_type_matches_exact(generic, exact, &mut bindings)
            })
        })
}

fn bound_type_matches_exact(
    generic: BoundTraitGoalType,
    exact: TraitTypeId,
    bindings: &mut [Option<TraitTypeId>; MAX_TRAIT_GENERIC_PARAMETERS],
) -> bool {
    match generic {
        BoundTraitGoalType::Concrete(generic) => generic == exact,
        BoundTraitGoalType::Parameter(parameter) => {
            let Some(binding) = bindings.get_mut(parameter.get() as usize) else {
                return false;
            };
            match *binding {
                Some(generic) => generic == exact,
                None => {
                    *binding = Some(exact);
                    true
                }
            }
        }
    }
}

const FLAT_GENERIC_HEAD_VARIABLES: usize = MAX_TRAIT_GENERIC_PARAMETERS * 2;

#[derive(Clone, Copy)]
struct FlatGenericHeadUnifier {
    parents: [u8; FLAT_GENERIC_HEAD_VARIABLES],
    concrete: [Option<TraitTypeId>; FLAT_GENERIC_HEAD_VARIABLES],
}

impl FlatGenericHeadUnifier {
    const NEW: Self = Self {
        parents: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        concrete: [None; FLAT_GENERIC_HEAD_VARIABLES],
    };

    fn unify(&mut self, left: BoundTraitGoalType, right: BoundTraitGoalType) -> bool {
        match (left, right) {
            (BoundTraitGoalType::Concrete(left), BoundTraitGoalType::Concrete(right)) => {
                left == right
            }
            (BoundTraitGoalType::Parameter(left), BoundTraitGoalType::Concrete(right)) => {
                self.constrain(left.get() as usize, right)
            }
            (BoundTraitGoalType::Concrete(left), BoundTraitGoalType::Parameter(right)) => {
                self.constrain(MAX_TRAIT_GENERIC_PARAMETERS + right.get() as usize, left)
            }
            (BoundTraitGoalType::Parameter(left), BoundTraitGoalType::Parameter(right)) => self
                .union(
                    left.get() as usize,
                    MAX_TRAIT_GENERIC_PARAMETERS + right.get() as usize,
                ),
        }
    }

    fn root(&self, mut variable: usize) -> usize {
        while self.parents[variable] as usize != variable {
            variable = self.parents[variable] as usize;
        }
        variable
    }

    fn constrain(&mut self, variable: usize, concrete: TraitTypeId) -> bool {
        let root = self.root(variable);
        match self.concrete[root] {
            Some(existing) => existing == concrete,
            None => {
                self.concrete[root] = Some(concrete);
                true
            }
        }
    }

    fn union(&mut self, left: usize, right: usize) -> bool {
        let left = self.root(left);
        let right = self.root(right);
        if left == right {
            return true;
        }
        match (self.concrete[left], self.concrete[right]) {
            (Some(left), Some(right)) if left != right => return false,
            _ => {}
        }
        self.parents[right] = left as u8;
        if self.concrete[left].is_none() {
            self.concrete[left] = self.concrete[right];
        }
        true
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TraitWhereClauseId(u32);

impl TraitWhereClauseId {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraitWhereClauseAnswer {
    pub clause_id: TraitWhereClauseId,
    pub instantiated: InstantiatedTraitWhereClause,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraitWhereClauseSolution {
    Unique(TraitWhereClauseAnswer),
    Ambiguous,
    NoSolution,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InferredTraitWhereClauseAnswer {
    pub clause_id: TraitWhereClauseId,
    pub instantiated: InstantiatedTraitWhereClause,
    pub substitution: SymbolicTraitGoalSubstitution,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InferredTraitWhereClauseSolution {
    Unique(InferredTraitWhereClauseAnswer),
    Ambiguous,
    NoSolution,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraitProofSolution {
    Proven,
    Ambiguous,
    NoSolution,
    Cycle,
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoinductiveTraitDatabase {
    traits: [Option<TraitId>; MAX_COINDUCTIVE_TRAITS],
    trait_count: usize,
}

impl CoinductiveTraitDatabase {
    pub const EMPTY: Self = Self {
        traits: [None; MAX_COINDUCTIVE_TRAITS],
        trait_count: 0,
    };

    pub fn insert(&mut self, trait_id: TraitId) -> Result<(), TraitGoalError> {
        if self.traits[..self.trait_count].contains(&Some(trait_id)) {
            return Err(TraitGoalError::DuplicateCoinductiveTrait);
        }
        let slot = self
            .traits
            .get_mut(self.trait_count)
            .ok_or(TraitGoalError::TooManyCoinductiveTraits)?;
        *slot = Some(trait_id);
        self.trait_count += 1;
        Ok(())
    }

    pub fn contains(self, trait_id: TraitId) -> bool {
        self.traits[..self.trait_count].contains(&Some(trait_id))
    }

    pub const fn trait_count(self) -> usize {
        self.trait_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IdentifiedTraitWhereClause {
    id: TraitWhereClauseId,
    clause: TraitWhereClause,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraitWhereClauseDatabase {
    clauses: [Option<IdentifiedTraitWhereClause>; MAX_TRAIT_WHERE_CLAUSES],
    clause_count: usize,
}

impl TraitWhereClauseDatabase {
    pub const EMPTY: Self = Self {
        clauses: [None; MAX_TRAIT_WHERE_CLAUSES],
        clause_count: 0,
    };

    pub fn insert(
        &mut self,
        id: TraitWhereClauseId,
        clause: TraitWhereClause,
    ) -> Result<(), TraitGoalError> {
        for existing in self.clauses[..self.clause_count].iter().flatten().copied() {
            if existing.id == id {
                return Err(TraitGoalError::DuplicateWhereClauseId);
            }
            if existing.clause == clause {
                return Err(TraitGoalError::DuplicateWhereClause);
            }
        }
        let slot = self
            .clauses
            .get_mut(self.clause_count)
            .ok_or(TraitGoalError::TooManyWhereClauses)?;
        *slot = Some(IdentifiedTraitWhereClause { id, clause });
        self.clause_count += 1;
        Ok(())
    }

    pub fn elaborate(
        &self,
        consequence: ImplementedTraitGoal,
    ) -> Result<TraitWhereClauseSolution, TraitGoalError> {
        validate_concrete_goal(consequence)?;
        let mut selected = None;
        for candidate in self.clauses[..self.clause_count].iter().flatten().copied() {
            match candidate.clause.elaborate(consequence)? {
                TraitWhereClauseElaboration::Unique(instantiated) => {
                    if selected.is_some() {
                        return Ok(TraitWhereClauseSolution::Ambiguous);
                    }
                    selected = Some(TraitWhereClauseAnswer {
                        clause_id: candidate.id,
                        instantiated,
                    });
                }
                TraitWhereClauseElaboration::Ambiguous => {
                    return Ok(TraitWhereClauseSolution::Ambiguous);
                }
                TraitWhereClauseElaboration::NoSolution => {}
            }
        }
        Ok(selected.map_or(
            TraitWhereClauseSolution::NoSolution,
            TraitWhereClauseSolution::Unique,
        ))
    }

    pub fn elaborate_rigid(
        &self,
        consequence: ImplementedTraitGoal,
    ) -> Result<TraitWhereClauseSolution, TraitGoalError> {
        validate_rigid_goal(consequence)?;
        let mut selected = None;
        for candidate in self.clauses[..self.clause_count].iter().flatten().copied() {
            match candidate.clause.elaborate_rigid(consequence)? {
                TraitWhereClauseElaboration::Unique(instantiated) => {
                    if selected.is_some() {
                        return Ok(TraitWhereClauseSolution::Ambiguous);
                    }
                    selected = Some(TraitWhereClauseAnswer {
                        clause_id: candidate.id,
                        instantiated,
                    });
                }
                TraitWhereClauseElaboration::Ambiguous => {
                    return Ok(TraitWhereClauseSolution::Ambiguous);
                }
                TraitWhereClauseElaboration::NoSolution => {}
            }
        }
        Ok(selected.map_or(
            TraitWhereClauseSolution::NoSolution,
            TraitWhereClauseSolution::Unique,
        ))
    }

    pub fn elaborate_existential(
        &self,
        consequence: ImplementedTraitGoal,
    ) -> Result<InferredTraitWhereClauseSolution, TraitGoalError> {
        validate_existential_goal(consequence)?;
        let canonicalized = canonicalize_implemented_trait_goal_with_variables(consequence)?;
        let mut selected = None;
        for candidate in self.clauses[..self.clause_count].iter().flatten().copied() {
            match match_generic_existential_head(candidate.clause, canonicalized)? {
                GenericExistentialHeadMatch::Unique {
                    arguments,
                    substitution,
                } => {
                    if selected.is_some() {
                        return Ok(InferredTraitWhereClauseSolution::Ambiguous);
                    }
                    selected = Some(InferredTraitWhereClauseAnswer {
                        clause_id: candidate.id,
                        instantiated: candidate.clause.instantiate_goal_types(
                            &arguments[..candidate.clause.parameter_count],
                        )?,
                        substitution,
                    });
                }
                GenericExistentialHeadMatch::Ambiguous => {
                    return Ok(InferredTraitWhereClauseSolution::Ambiguous);
                }
                GenericExistentialHeadMatch::NoSolution => {}
            }
        }
        Ok(selected.map_or(
            InferredTraitWhereClauseSolution::NoSolution,
            InferredTraitWhereClauseSolution::Unique,
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionBearingTraitClause {
    parameter_count: usize,
    arena: BoundTraitGoalTermArena,
    consequence: BoundProjectionBearingTraitGoal,
    premises: [Option<BoundImplementedTraitGoal>; MAX_TRAIT_PREDICATES],
    premise_count: usize,
    term_premises: [Option<BoundProjectionBearingTraitGoal>; MAX_TRAIT_PREDICATES],
    term_premise_count: usize,
}

impl ProjectionBearingTraitClause {
    pub fn new(
        parameter_count: usize,
        arena: BoundTraitGoalTermArena,
        consequence: BoundProjectionBearingTraitGoal,
    ) -> Result<Self, TraitGoalError> {
        let bound = ExistsProjectionBearingTraitGoal::new(parameter_count, arena, consequence)?;
        Ok(Self {
            parameter_count: bound.parameter_count,
            arena: bound.arena,
            consequence: bound.goal,
            premises: [None; MAX_TRAIT_PREDICATES],
            premise_count: 0,
            term_premises: [None; MAX_TRAIT_PREDICATES],
            term_premise_count: 0,
        })
    }

    pub fn push_premise(
        &mut self,
        premise: BoundImplementedTraitGoal,
    ) -> Result<(), TraitGoalError> {
        validate_bound_goal(premise, self.parameter_count)?;
        if self.premise_count + self.term_premise_count >= MAX_TRAIT_PREDICATES {
            return Err(TraitGoalError::TooManyPredicates);
        }
        let slot = self
            .premises
            .get_mut(self.premise_count)
            .ok_or(TraitGoalError::TooManyPredicates)?;
        *slot = Some(premise);
        self.premise_count += 1;
        Ok(())
    }

    pub fn premises(&self) -> &[Option<BoundImplementedTraitGoal>] {
        &self.premises[..self.premise_count]
    }

    pub fn push_projection_bearing_premise(
        &mut self,
        premise: BoundProjectionBearingTraitGoal,
    ) -> Result<(), TraitGoalError> {
        validate_bound_projection_bearing_goal(premise, self.arena.term_count)?;
        if self.premise_count + self.term_premise_count >= MAX_TRAIT_PREDICATES {
            return Err(TraitGoalError::TooManyPredicates);
        }
        let slot = self
            .term_premises
            .get_mut(self.term_premise_count)
            .ok_or(TraitGoalError::TooManyPredicates)?;
        *slot = Some(premise);
        self.term_premise_count += 1;
        Ok(())
    }

    pub fn projection_bearing_premises(&self) -> &[Option<BoundProjectionBearingTraitGoal>] {
        &self.term_premises[..self.term_premise_count]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IdentifiedProjectionBearingTraitClause {
    id: TraitWhereClauseId,
    clause: ProjectionBearingTraitClause,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionBearingTraitClauseAnswer {
    pub clause_id: TraitWhereClauseId,
    pub substitution: SymbolicTraitGoalSubstitution,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionBearingTraitClauseSolution {
    Unique(ProjectionBearingTraitClauseAnswer),
    Ambiguous,
    NoSolution,
    Cycle,
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionBearingTraitClauseDatabase {
    clauses: [Option<IdentifiedProjectionBearingTraitClause>; MAX_TRAIT_WHERE_CLAUSES],
    clause_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IdentifiedProjectionBearingGenericTraitImplementation {
    id: GenericTraitImplementationId,
    implementation: ProjectionBearingTraitClause,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionBearingGenericTraitImplementationDatabase {
    implementations: [Option<IdentifiedProjectionBearingGenericTraitImplementation>;
        MAX_GENERIC_TRAIT_IMPLEMENTATIONS],
    implementation_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionBearingGenericTraitImplementationAnswer {
    pub implementation_id: GenericTraitImplementationId,
    pub substitution: SymbolicTraitGoalSubstitution,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionBearingGenericTraitImplementationSolution {
    Unique(ProjectionBearingGenericTraitImplementationAnswer),
    Ambiguous,
    NoSolution,
    Cycle,
    Overflow,
}

impl ProjectionBearingGenericTraitImplementationDatabase {
    pub const EMPTY: Self = Self {
        implementations: [None; MAX_GENERIC_TRAIT_IMPLEMENTATIONS],
        implementation_count: 0,
    };

    pub fn insert(
        &mut self,
        id: GenericTraitImplementationId,
        implementation: ProjectionBearingTraitClause,
    ) -> Result<(), TraitGoalError> {
        for existing in self.implementations[..self.implementation_count]
            .iter()
            .flatten()
        {
            if existing.id == id {
                return Err(TraitGoalError::DuplicateGenericImplementationId);
            }
            if projection_bearing_heads_may_overlap(existing.implementation, implementation)? {
                return Err(TraitGoalError::OverlappingGenericImplementation);
            }
        }
        let slot = self
            .implementations
            .get_mut(self.implementation_count)
            .ok_or(TraitGoalError::TooManyGenericImplementations)?;
        *slot = Some(IdentifiedProjectionBearingGenericTraitImplementation { id, implementation });
        self.implementation_count += 1;
        Ok(())
    }

    pub fn insert_coherent(
        &mut self,
        exact: &TraitImplementationDatabase,
        flat: &GenericTraitImplementationDatabase,
        id: GenericTraitImplementationId,
        implementation: ProjectionBearingTraitClause,
    ) -> Result<(), TraitGoalError> {
        if exact.implementations[..exact.implementation_count]
            .iter()
            .flatten()
            .any(|header| projection_bearing_head_may_overlap_exact(implementation, *header))
            || flat.implementations[..flat.implementation_count]
                .iter()
                .flatten()
                .any(|candidate| {
                    projection_bearing_head_may_overlap_flat(
                        implementation,
                        candidate.implementation,
                    )
                })
        {
            return Err(TraitGoalError::OverlappingExactAndGenericImplementation);
        }
        self.insert(id, implementation)
    }

    pub fn select_existential(
        &self,
        exact_implementations: &TraitImplementationDatabase,
        generic_implementations: &GenericTraitImplementationDatabase,
        clauses: &TraitWhereClauseDatabase,
        exact_values: &TraitAssociatedTypeDatabase,
        generic_values: &GenericTraitAssociatedTypeDatabase,
        query: ImplementedTraitGoal,
    ) -> Result<ProjectionBearingGenericTraitImplementationSolution, TraitGoalError> {
        validate_existential_goal(query)?;
        let canonicalized = canonicalize_implemented_trait_goal_with_variables(query)?;
        let mut state = InferenceConstraintState::new(canonicalized)?;
        let environment = TraitProjectionEnvironment {
            exact_implementations,
            generic_implementations,
            clauses,
            exact_values,
            generic_values,
        };
        let mut stack = [None; MAX_TRAIT_PROOF_DEPTH];
        let (solution, implementation_id) =
            self.solve_in_state(environment, None, query, &mut state, &mut stack, 0)?;
        Ok(match solution {
            TraitProofSolution::Proven => {
                ProjectionBearingGenericTraitImplementationSolution::Unique(
                    ProjectionBearingGenericTraitImplementationAnswer {
                        implementation_id: implementation_id.ok_or(TraitGoalError::InvalidGoal)?,
                        substitution: state.substitution()?,
                    },
                )
            }
            TraitProofSolution::Ambiguous => {
                ProjectionBearingGenericTraitImplementationSolution::Ambiguous
            }
            TraitProofSolution::NoSolution => {
                ProjectionBearingGenericTraitImplementationSolution::NoSolution
            }
            TraitProofSolution::Cycle => ProjectionBearingGenericTraitImplementationSolution::Cycle,
            TraitProofSolution::Overflow => {
                ProjectionBearingGenericTraitImplementationSolution::Overflow
            }
        })
    }

    fn solve_in_state(
        &self,
        environment: TraitProjectionEnvironment<'_>,
        projection_clauses: Option<&ProjectionBearingTraitClauseDatabase>,
        query: ImplementedTraitGoal,
        state: &mut InferenceConstraintState,
        stack: &mut [Option<ImplementedTraitGoal>; MAX_TRAIT_PROOF_DEPTH],
        depth: usize,
    ) -> Result<(TraitProofSolution, Option<GenericTraitImplementationId>), TraitGoalError> {
        let initial = *state;
        let mut selected = None;
        for candidate in self.implementations[..self.implementation_count]
            .iter()
            .flatten()
        {
            let mut state = initial;
            match elaborate_projection_bearing_clause(
                candidate.implementation,
                query,
                environment,
                &mut state,
                projection_clauses,
                Some(self),
                stack,
                depth,
            )? {
                TraitProofSolution::Proven => {
                    if selected.is_some() {
                        return Ok((TraitProofSolution::Ambiguous, None));
                    }
                    selected = Some((candidate.id, state));
                }
                TraitProofSolution::Ambiguous => {
                    return Ok((TraitProofSolution::Ambiguous, None));
                }
                TraitProofSolution::NoSolution => {}
                TraitProofSolution::Cycle => {
                    return Ok((TraitProofSolution::Cycle, None));
                }
                TraitProofSolution::Overflow => {
                    return Ok((TraitProofSolution::Overflow, None));
                }
            }
        }
        let Some((id, selected_state)) = selected else {
            return Ok((TraitProofSolution::NoSolution, None));
        };
        *state = selected_state;
        Ok((TraitProofSolution::Proven, Some(id)))
    }
}

fn projection_bearing_heads_may_overlap(
    left: ProjectionBearingTraitClause,
    right: ProjectionBearingTraitClause,
) -> Result<bool, TraitGoalError> {
    if left.consequence.trait_id != right.consequence.trait_id
        || left.consequence.argument_count != right.consequence.argument_count
    {
        return Ok(false);
    }
    let mut unifier = FlatGenericHeadUnifier::NEW;
    if !bound_term_pair_may_overlap(
        &left.arena,
        left.consequence.self_type,
        &right.arena,
        right.consequence.self_type,
        &mut unifier,
    )? {
        return Ok(false);
    }
    for (left_term, right_term) in left
        .consequence
        .arguments()
        .iter()
        .zip(right.consequence.arguments())
    {
        if !bound_term_pair_may_overlap(
            &left.arena,
            left_term
                .as_ref()
                .copied()
                .ok_or(TraitGoalError::InvalidGoal)?,
            &right.arena,
            right_term
                .as_ref()
                .copied()
                .ok_or(TraitGoalError::InvalidGoal)?,
            &mut unifier,
        )? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn bound_term_pair_may_overlap(
    left_arena: &BoundTraitGoalTermArena,
    left: TraitGoalTermId,
    right_arena: &BoundTraitGoalTermArena,
    right: TraitGoalTermId,
    unifier: &mut FlatGenericHeadUnifier,
) -> Result<bool, TraitGoalError> {
    let left = left_arena
        .get(left)
        .ok_or(TraitGoalError::InvalidTraitGoalTermReference)?;
    let right = right_arena
        .get(right)
        .ok_or(TraitGoalError::InvalidTraitGoalTermReference)?;
    Ok(match (left, right) {
        (BoundTraitGoalTerm::Type(left), BoundTraitGoalTerm::Type(right)) => {
            unifier.unify(left, right)
        }
        _ => true,
    })
}

fn projection_bearing_head_may_overlap_exact(
    projection: ProjectionBearingTraitClause,
    exact: TraitImplementationHeader,
) -> bool {
    if projection.consequence.trait_id != exact.trait_id
        || projection.consequence.argument_count != exact.argument_count
    {
        return false;
    }
    let mut bindings = [None; MAX_TRAIT_GENERIC_PARAMETERS];
    if !bound_term_may_match_concrete(
        &projection.arena,
        projection.consequence.self_type,
        exact.self_type,
        &mut bindings,
    ) {
        return false;
    }
    projection
        .consequence
        .arguments()
        .iter()
        .zip(exact.arguments())
        .all(|(term, exact)| {
            term.zip(*exact).is_some_and(|(term, exact)| {
                bound_term_may_match_concrete(&projection.arena, term, exact, &mut bindings)
            })
        })
}

fn projection_bearing_head_may_overlap_flat(
    projection: ProjectionBearingTraitClause,
    flat: TraitWhereClause,
) -> bool {
    if projection.consequence.trait_id != flat.consequence.trait_id
        || projection.consequence.argument_count != flat.consequence.argument_count
    {
        return false;
    }
    let mut unifier = FlatGenericHeadUnifier::NEW;
    if !bound_term_may_match_bound_leaf(
        &projection.arena,
        projection.consequence.self_type,
        flat.consequence.self_type,
        &mut unifier,
    ) {
        return false;
    }
    projection
        .consequence
        .arguments()
        .iter()
        .zip(flat.consequence.arguments())
        .all(|(term, flat)| {
            term.zip(*flat).is_some_and(|(term, flat)| {
                bound_term_may_match_bound_leaf(&projection.arena, term, flat, &mut unifier)
            })
        })
}

fn bound_term_may_match_concrete(
    arena: &BoundTraitGoalTermArena,
    term: TraitGoalTermId,
    concrete: TraitTypeId,
    bindings: &mut [Option<TraitTypeId>; MAX_TRAIT_GENERIC_PARAMETERS],
) -> bool {
    match arena.get(term) {
        Some(BoundTraitGoalTerm::Type(term)) => bound_type_matches_exact(term, concrete, bindings),
        Some(BoundTraitGoalTerm::Projection { .. }) => true,
        None => false,
    }
}

fn bound_term_may_match_bound_leaf(
    arena: &BoundTraitGoalTermArena,
    term: TraitGoalTermId,
    flat: BoundTraitGoalType,
    unifier: &mut FlatGenericHeadUnifier,
) -> bool {
    match arena.get(term) {
        Some(BoundTraitGoalTerm::Type(term)) => unifier.unify(term, flat),
        Some(BoundTraitGoalTerm::Projection { .. }) => true,
        None => false,
    }
}

impl ProjectionBearingTraitClauseDatabase {
    pub const EMPTY: Self = Self {
        clauses: [None; MAX_TRAIT_WHERE_CLAUSES],
        clause_count: 0,
    };

    pub fn insert(
        &mut self,
        id: TraitWhereClauseId,
        clause: ProjectionBearingTraitClause,
    ) -> Result<(), TraitGoalError> {
        for existing in self.clauses[..self.clause_count].iter().flatten() {
            if existing.id == id {
                return Err(TraitGoalError::DuplicateWhereClauseId);
            }
            if existing.clause == clause {
                return Err(TraitGoalError::DuplicateWhereClause);
            }
        }
        let slot = self
            .clauses
            .get_mut(self.clause_count)
            .ok_or(TraitGoalError::TooManyWhereClauses)?;
        *slot = Some(IdentifiedProjectionBearingTraitClause { id, clause });
        self.clause_count += 1;
        Ok(())
    }

    pub fn elaborate_existential(
        &self,
        exact_implementations: &TraitImplementationDatabase,
        generic_implementations: &GenericTraitImplementationDatabase,
        clauses: &TraitWhereClauseDatabase,
        exact_values: &TraitAssociatedTypeDatabase,
        generic_values: &GenericTraitAssociatedTypeDatabase,
        query: ImplementedTraitGoal,
    ) -> Result<ProjectionBearingTraitClauseSolution, TraitGoalError> {
        validate_existential_goal(query)?;
        let canonicalized = canonicalize_implemented_trait_goal_with_variables(query)?;
        let mut state = InferenceConstraintState::new(canonicalized)?;
        let environment = TraitProjectionEnvironment {
            exact_implementations,
            generic_implementations,
            clauses,
            exact_values,
            generic_values,
        };
        let mut stack = [None; MAX_TRAIT_PROOF_DEPTH];
        let (solution, clause_id) =
            self.solve_in_state(environment, query, &mut state, &mut stack, 0)?;
        Ok(match solution {
            TraitProofSolution::Proven => {
                ProjectionBearingTraitClauseSolution::Unique(ProjectionBearingTraitClauseAnswer {
                    clause_id: clause_id.ok_or(TraitGoalError::InvalidGoal)?,
                    substitution: state.substitution()?,
                })
            }
            TraitProofSolution::Ambiguous => ProjectionBearingTraitClauseSolution::Ambiguous,
            TraitProofSolution::NoSolution => ProjectionBearingTraitClauseSolution::NoSolution,
            TraitProofSolution::Cycle => ProjectionBearingTraitClauseSolution::Cycle,
            TraitProofSolution::Overflow => ProjectionBearingTraitClauseSolution::Overflow,
        })
    }

    fn solve_in_state(
        &self,
        environment: TraitProjectionEnvironment<'_>,
        query: ImplementedTraitGoal,
        state: &mut InferenceConstraintState,
        stack: &mut [Option<ImplementedTraitGoal>; MAX_TRAIT_PROOF_DEPTH],
        depth: usize,
    ) -> Result<(TraitProofSolution, Option<TraitWhereClauseId>), TraitGoalError> {
        let initial = *state;
        let mut selected = None;
        for candidate in self.clauses[..self.clause_count].iter().flatten() {
            let mut state = initial;
            match elaborate_projection_bearing_clause(
                candidate.clause,
                query,
                environment,
                &mut state,
                Some(self),
                None,
                stack,
                depth,
            )? {
                TraitProofSolution::Proven => {
                    if selected.is_some() {
                        return Ok((TraitProofSolution::Ambiguous, None));
                    }
                    selected = Some((candidate.id, state));
                }
                TraitProofSolution::Ambiguous => {
                    return Ok((TraitProofSolution::Ambiguous, None));
                }
                TraitProofSolution::NoSolution => {}
                TraitProofSolution::Cycle => {
                    return Ok((TraitProofSolution::Cycle, None));
                }
                TraitProofSolution::Overflow => {
                    return Ok((TraitProofSolution::Overflow, None));
                }
            }
        }
        let Some((id, selected_state)) = selected else {
            return Ok((TraitProofSolution::NoSolution, None));
        };
        *state = selected_state;
        Ok((TraitProofSolution::Proven, Some(id)))
    }
}

fn elaborate_projection_bearing_clause(
    clause: ProjectionBearingTraitClause,
    query: ImplementedTraitGoal,
    environment: TraitProjectionEnvironment<'_>,
    state: &mut InferenceConstraintState,
    projection_clauses: Option<&ProjectionBearingTraitClauseDatabase>,
    projection_implementations: Option<&ProjectionBearingGenericTraitImplementationDatabase>,
    stack: &mut [Option<ImplementedTraitGoal>; MAX_TRAIT_PROOF_DEPTH],
    depth: usize,
) -> Result<TraitProofSolution, TraitGoalError> {
    if clause.consequence.trait_id != query.trait_id
        || clause.consequence.argument_count != query.argument_count
    {
        return Ok(TraitProofSolution::NoSolution);
    }
    let mut arguments = [None; MAX_TRAIT_GENERIC_PARAMETERS];
    if !bind_direct_bound_term(
        &clause.arena,
        clause.consequence.self_type,
        query.self_type,
        clause.parameter_count,
        &mut arguments,
        state,
    )? {
        return Ok(TraitProofSolution::NoSolution);
    }
    for (bound, query) in clause.consequence.arguments().iter().zip(query.arguments()) {
        if !bind_direct_bound_term(
            &clause.arena,
            bound.as_ref().copied().ok_or(TraitGoalError::InvalidGoal)?,
            query.as_ref().copied().ok_or(TraitGoalError::InvalidGoal)?,
            clause.parameter_count,
            &mut arguments,
            state,
        )? {
            return Ok(TraitProofSolution::NoSolution);
        }
    }
    if arguments[..clause.parameter_count]
        .iter()
        .any(Option::is_none)
    {
        return Ok(TraitProofSolution::Ambiguous);
    }
    let mut instantiated_arguments =
        [TraitGoalType::Concrete(TraitTypeId::new(0)); MAX_TRAIT_GENERIC_PARAMETERS];
    for (index, argument) in arguments[..clause.parameter_count].iter().enumerate() {
        instantiated_arguments[index] = argument.ok_or(TraitGoalError::InvalidGoal)?;
    }
    let instantiated = instantiate_bound_term_goal(
        &clause.arena,
        clause.consequence,
        &instantiated_arguments[..clause.parameter_count],
    )?;
    let normalized = match environment.normalize_projection_bearing_goal(
        &instantiated.arena,
        instantiated.goal,
        state,
    )? {
        ProjectionBearingGoalNormalizationSolution::Unique(goal) => goal,
        ProjectionBearingGoalNormalizationSolution::Ambiguous => {
            return Ok(TraitProofSolution::Ambiguous);
        }
        ProjectionBearingGoalNormalizationSolution::NoSolution => {
            return Ok(TraitProofSolution::NoSolution);
        }
        ProjectionBearingGoalNormalizationSolution::Cycle => {
            return Ok(TraitProofSolution::Cycle);
        }
        ProjectionBearingGoalNormalizationSolution::Overflow => {
            return Ok(TraitProofSolution::Overflow);
        }
    };
    if normalized.trait_id != query.trait_id
        || normalized.argument_count != query.argument_count
        || !state.unify_types(normalized.self_type, query.self_type)?
    {
        return Ok(TraitProofSolution::NoSolution);
    }
    for (normalized, query) in normalized.arguments().iter().zip(query.arguments()) {
        if !state.unify_types(
            normalized
                .as_ref()
                .copied()
                .ok_or(TraitGoalError::InvalidGoal)?,
            query.as_ref().copied().ok_or(TraitGoalError::InvalidGoal)?,
        )? {
            return Ok(TraitProofSolution::NoSolution);
        }
    }
    let mut premises = ImplementedTraitPredicates::EMPTY;
    for premise in clause.premises() {
        premises.push(instantiate_bound_goal(
            premise
                .as_ref()
                .copied()
                .ok_or(TraitGoalError::InvalidGoal)?,
            &instantiated_arguments[..clause.parameter_count],
        )?)?;
    }
    solve_projection_clause_mixed_premises(
        clause,
        &instantiated_arguments[..clause.parameter_count],
        premises,
        query,
        environment,
        projection_clauses,
        projection_implementations,
        state,
        stack,
        depth,
    )
}

fn solve_projection_clause_mixed_premises(
    clause: ProjectionBearingTraitClause,
    arguments: &[TraitGoalType],
    flat_premises: ImplementedTraitPredicates,
    query: ImplementedTraitGoal,
    environment: TraitProjectionEnvironment<'_>,
    projection_clauses: Option<&ProjectionBearingTraitClauseDatabase>,
    projection_implementations: Option<&ProjectionBearingGenericTraitImplementationDatabase>,
    state: &mut InferenceConstraintState,
    stack: &mut [Option<ImplementedTraitGoal>; MAX_TRAIT_PROOF_DEPTH],
    depth: usize,
) -> Result<TraitProofSolution, TraitGoalError> {
    if flat_premises.predicates().is_empty() && clause.projection_bearing_premises().is_empty() {
        return Ok(TraitProofSolution::Proven);
    }
    let goal = state.apply_goal(query)?;
    if stack[..depth].contains(&Some(goal)) {
        return Ok(TraitProofSolution::Cycle);
    }
    if depth >= MAX_TRAIT_PROOF_DEPTH {
        return Ok(TraitProofSolution::Overflow);
    }
    stack[depth] = Some(goal);
    let mut pending_flat = flat_premises;
    let mut pending_terms = clause.term_premises;
    let mut pending_term_count = clause.term_premise_count;
    let result = 'solve: loop {
        if pending_flat.predicates().is_empty() && pending_term_count == 0 {
            break TraitProofSolution::Proven;
        }
        let mut next_flat = ImplementedTraitPredicates::EMPTY;
        let mut next_terms = [None; MAX_TRAIT_PREDICATES];
        let mut next_term_count = 0usize;
        let mut proven_count = 0usize;
        for premise in pending_flat.predicates() {
            let premise = premise
                .as_ref()
                .copied()
                .ok_or(TraitGoalError::InvalidGoal)?;
            let saved = *state;
            match solve_inferred_trait_goal_inner(
                environment.exact_implementations,
                environment.generic_implementations,
                environment.clauses,
                projection_clauses,
                projection_implementations,
                Some(environment),
                None,
                0,
                premise,
                state,
                stack,
                depth + 1,
            )? {
                TraitProofSolution::Proven => proven_count += 1,
                TraitProofSolution::Ambiguous => {
                    *state = saved;
                    next_flat.push(premise)?;
                }
                other => break 'solve other,
            }
        }
        for premise in pending_terms[..pending_term_count].iter().copied() {
            let premise = premise.ok_or(TraitGoalError::InvalidGoal)?;
            let saved = *state;
            let instantiated = instantiate_bound_term_goal(&clause.arena, premise, arguments)?;
            let normalized = match environment.normalize_projection_bearing_goal(
                &instantiated.arena,
                instantiated.goal,
                state,
            )? {
                ProjectionBearingGoalNormalizationSolution::Unique(goal) => goal,
                ProjectionBearingGoalNormalizationSolution::Ambiguous => {
                    *state = saved;
                    next_terms[next_term_count] = Some(premise);
                    next_term_count += 1;
                    continue;
                }
                ProjectionBearingGoalNormalizationSolution::NoSolution => {
                    break 'solve TraitProofSolution::NoSolution;
                }
                ProjectionBearingGoalNormalizationSolution::Cycle => {
                    break 'solve TraitProofSolution::Cycle;
                }
                ProjectionBearingGoalNormalizationSolution::Overflow => {
                    break 'solve TraitProofSolution::Overflow;
                }
            };
            match solve_inferred_trait_goal_inner(
                environment.exact_implementations,
                environment.generic_implementations,
                environment.clauses,
                projection_clauses,
                projection_implementations,
                Some(environment),
                None,
                0,
                normalized,
                state,
                stack,
                depth + 1,
            )? {
                TraitProofSolution::Proven => proven_count += 1,
                TraitProofSolution::Ambiguous => {
                    *state = saved;
                    next_terms[next_term_count] = Some(premise);
                    next_term_count += 1;
                }
                other => break 'solve other,
            }
        }
        if proven_count == 0 {
            break TraitProofSolution::Ambiguous;
        }
        pending_flat = next_flat;
        pending_terms = next_terms;
        pending_term_count = next_term_count;
    };
    stack[depth] = None;
    Ok(result)
}

fn bind_direct_bound_term(
    arena: &BoundTraitGoalTermArena,
    term_id: TraitGoalTermId,
    query: TraitGoalType,
    parameter_count: usize,
    arguments: &mut [Option<TraitGoalType>; MAX_TRAIT_GENERIC_PARAMETERS],
    state: &mut InferenceConstraintState,
) -> Result<bool, TraitGoalError> {
    match arena
        .get(term_id)
        .ok_or(TraitGoalError::InvalidTraitGoalTermReference)?
    {
        BoundTraitGoalTerm::Projection { .. } => Ok(true),
        BoundTraitGoalTerm::Type(BoundTraitGoalType::Concrete(concrete)) => {
            state.unify_types(TraitGoalType::Concrete(concrete), query)
        }
        BoundTraitGoalTerm::Type(BoundTraitGoalType::Parameter(parameter)) => {
            let index = parameter.get() as usize;
            if index >= parameter_count {
                return Err(TraitGoalError::UnboundGenericParameter);
            }
            match arguments[index] {
                Some(existing) => state.unify_types(existing, query),
                None => {
                    arguments[index] = Some(state.apply_type(query)?);
                    Ok(true)
                }
            }
        }
    }
}

pub fn solve_concrete_trait_goal(
    implementations: &TraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    goal: ImplementedTraitGoal,
) -> Result<TraitProofSolution, TraitGoalError> {
    let mut stack = [None; MAX_TRAIT_PROOF_DEPTH];
    solve_concrete_trait_goal_inner(implementations, clauses, goal, &mut stack, 0)
}

fn solve_concrete_trait_goal_inner(
    implementations: &TraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    goal: ImplementedTraitGoal,
    stack: &mut [Option<ImplementedTraitGoal>; MAX_TRAIT_PROOF_DEPTH],
    depth: usize,
) -> Result<TraitProofSolution, TraitGoalError> {
    validate_concrete_goal(goal)?;
    match implementations.solve(canonicalize_implemented_trait_goal(goal)?) {
        TraitGoalSolution::Unique(_) => return Ok(TraitProofSolution::Proven),
        TraitGoalSolution::Ambiguous => return Ok(TraitProofSolution::Ambiguous),
        TraitGoalSolution::NoSolution => {}
    }
    if stack[..depth].contains(&Some(goal)) {
        return Ok(TraitProofSolution::Cycle);
    }
    if depth >= MAX_TRAIT_PROOF_DEPTH {
        return Ok(TraitProofSolution::Overflow);
    }
    stack[depth] = Some(goal);
    let solution = match clauses.elaborate(goal)? {
        TraitWhereClauseSolution::Unique(answer) => {
            if answer.instantiated.has_projection_premises() {
                return Ok(TraitProofSolution::NoSolution);
            }
            let mut result = TraitProofSolution::Proven;
            for premise in answer.instantiated.premises.predicates().iter() {
                let premise = premise
                    .as_ref()
                    .copied()
                    .ok_or(TraitGoalError::InvalidGoal)?;
                let premise = solve_concrete_trait_goal_inner(
                    implementations,
                    clauses,
                    premise,
                    stack,
                    depth + 1,
                )?;
                if premise != TraitProofSolution::Proven {
                    result = premise;
                    break;
                }
            }
            result
        }
        TraitWhereClauseSolution::Ambiguous => TraitProofSolution::Ambiguous,
        TraitWhereClauseSolution::NoSolution => TraitProofSolution::NoSolution,
    };
    stack[depth] = None;
    Ok(solution)
}

pub fn solve_rigid_trait_goal(
    implementations: &TraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    goal: ImplementedTraitGoal,
) -> Result<TraitProofSolution, TraitGoalError> {
    let mut stack = [None; MAX_TRAIT_PROOF_DEPTH];
    solve_rigid_trait_goal_inner(implementations, clauses, goal, &mut stack, 0)
}

pub fn solve_concrete_trait_goal_with_generics(
    implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    goal: ImplementedTraitGoal,
) -> Result<TraitProofSolution, TraitGoalError> {
    let mut stack = [None; MAX_TRAIT_PROOF_DEPTH];
    solve_concrete_trait_goal_with_generics_inner(
        implementations,
        generic_implementations,
        clauses,
        goal,
        &mut stack,
        0,
    )
}

fn solve_concrete_trait_goal_with_generics_inner(
    implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    goal: ImplementedTraitGoal,
    stack: &mut [Option<ImplementedTraitGoal>; MAX_TRAIT_PROOF_DEPTH],
    depth: usize,
) -> Result<TraitProofSolution, TraitGoalError> {
    validate_concrete_goal(goal)?;
    let exact = implementations.solve(canonicalize_implemented_trait_goal(goal)?);
    let generic = generic_implementations.select(goal)?;
    match (exact, generic) {
        (TraitGoalSolution::Unique(_), GenericTraitImplementationSolution::NoSolution) => {
            return Ok(TraitProofSolution::Proven);
        }
        (TraitGoalSolution::Unique(_), _)
        | (TraitGoalSolution::Ambiguous, _)
        | (_, GenericTraitImplementationSolution::Ambiguous) => {
            return Ok(TraitProofSolution::Ambiguous);
        }
        (TraitGoalSolution::NoSolution, GenericTraitImplementationSolution::Unique(answer)) => {
            if answer.instantiated.has_projection_premises() {
                return Ok(TraitProofSolution::NoSolution);
            }
            if stack[..depth].contains(&Some(goal)) {
                return Ok(TraitProofSolution::Cycle);
            }
            if depth >= MAX_TRAIT_PROOF_DEPTH {
                return Ok(TraitProofSolution::Overflow);
            }
            stack[depth] = Some(goal);
            let result = solve_generic_premises(
                implementations,
                generic_implementations,
                clauses,
                answer.instantiated.premises,
                stack,
                depth + 1,
            )?;
            stack[depth] = None;
            return Ok(result);
        }
        (TraitGoalSolution::NoSolution, GenericTraitImplementationSolution::NoSolution) => {}
    }
    if stack[..depth].contains(&Some(goal)) {
        return Ok(TraitProofSolution::Cycle);
    }
    if depth >= MAX_TRAIT_PROOF_DEPTH {
        return Ok(TraitProofSolution::Overflow);
    }
    stack[depth] = Some(goal);
    let solution = match clauses.elaborate(goal)? {
        TraitWhereClauseSolution::Unique(answer) => {
            if answer.instantiated.has_projection_premises() {
                TraitProofSolution::NoSolution
            } else {
                solve_generic_premises(
                    implementations,
                    generic_implementations,
                    clauses,
                    answer.instantiated.premises,
                    stack,
                    depth + 1,
                )?
            }
        }
        TraitWhereClauseSolution::Ambiguous => TraitProofSolution::Ambiguous,
        TraitWhereClauseSolution::NoSolution => TraitProofSolution::NoSolution,
    };
    stack[depth] = None;
    Ok(solution)
}

fn solve_generic_premises(
    implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    premises: ImplementedTraitPredicates,
    stack: &mut [Option<ImplementedTraitGoal>; MAX_TRAIT_PROOF_DEPTH],
    depth: usize,
) -> Result<TraitProofSolution, TraitGoalError> {
    for premise in premises.predicates().iter() {
        let premise = premise
            .as_ref()
            .copied()
            .ok_or(TraitGoalError::InvalidGoal)?;
        let result = solve_concrete_trait_goal_with_generics_inner(
            implementations,
            generic_implementations,
            clauses,
            premise,
            stack,
            depth,
        )?;
        if result != TraitProofSolution::Proven {
            return Ok(result);
        }
    }
    Ok(TraitProofSolution::Proven)
}

pub fn solve_rigid_trait_goal_with_generics(
    implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    goal: ImplementedTraitGoal,
) -> Result<TraitProofSolution, TraitGoalError> {
    let mut stack = [None; MAX_TRAIT_PROOF_DEPTH];
    solve_rigid_trait_goal_with_generics_inner(
        implementations,
        generic_implementations,
        clauses,
        None,
        None,
        goal,
        &mut stack,
        0,
    )
}

pub fn solve_rigid_trait_goal_with_coinduction(
    implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    coinductive_traits: &CoinductiveTraitDatabase,
    goal: ImplementedTraitGoal,
) -> Result<TraitProofSolution, TraitGoalError> {
    let mut stack = [None; MAX_TRAIT_PROOF_DEPTH];
    solve_rigid_trait_goal_with_coinduction_inner(
        implementations,
        generic_implementations,
        clauses,
        coinductive_traits,
        goal,
        &mut stack,
        0,
    )
}

fn solve_rigid_trait_goal_with_coinduction_inner(
    implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    coinductive_traits: &CoinductiveTraitDatabase,
    goal: ImplementedTraitGoal,
    stack: &mut [Option<ImplementedTraitGoal>; MAX_TRAIT_PROOF_DEPTH],
    depth: usize,
) -> Result<TraitProofSolution, TraitGoalError> {
    validate_rigid_goal(goal)?;
    let exact = implementations.solve(canonicalize_implemented_trait_goal(goal)?);
    let generic = generic_implementations.select_rigid(goal)?;
    match (exact, generic) {
        (TraitGoalSolution::Unique(_), GenericTraitImplementationSolution::NoSolution) => {
            return Ok(TraitProofSolution::Proven);
        }
        (TraitGoalSolution::Unique(_), _)
        | (TraitGoalSolution::Ambiguous, _)
        | (_, GenericTraitImplementationSolution::Ambiguous) => {
            return Ok(TraitProofSolution::Ambiguous);
        }
        (TraitGoalSolution::NoSolution, GenericTraitImplementationSolution::Unique(answer)) => {
            if let Some(cycle_start) = stack[..depth].iter().position(|entry| *entry == Some(goal))
            {
                return Ok(classify_coinductive_cycle(
                    coinductive_traits,
                    stack,
                    cycle_start,
                    depth,
                ));
            }
            if depth >= MAX_TRAIT_PROOF_DEPTH {
                return Ok(TraitProofSolution::Overflow);
            }
            stack[depth] = Some(goal);
            let result = solve_coinductive_rigid_premises(
                implementations,
                generic_implementations,
                clauses,
                coinductive_traits,
                answer.instantiated,
                stack,
                depth + 1,
            )?;
            stack[depth] = None;
            return Ok(result);
        }
        (TraitGoalSolution::NoSolution, GenericTraitImplementationSolution::NoSolution) => {}
    }
    if let Some(cycle_start) = stack[..depth].iter().position(|entry| *entry == Some(goal)) {
        return Ok(classify_coinductive_cycle(
            coinductive_traits,
            stack,
            cycle_start,
            depth,
        ));
    }
    if depth >= MAX_TRAIT_PROOF_DEPTH {
        return Ok(TraitProofSolution::Overflow);
    }
    stack[depth] = Some(goal);
    let solution = match clauses.elaborate_rigid(goal)? {
        TraitWhereClauseSolution::Unique(answer) => solve_coinductive_rigid_premises(
            implementations,
            generic_implementations,
            clauses,
            coinductive_traits,
            answer.instantiated,
            stack,
            depth + 1,
        )?,
        TraitWhereClauseSolution::Ambiguous => TraitProofSolution::Ambiguous,
        TraitWhereClauseSolution::NoSolution => TraitProofSolution::NoSolution,
    };
    stack[depth] = None;
    Ok(solution)
}

fn solve_coinductive_rigid_premises(
    implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    coinductive_traits: &CoinductiveTraitDatabase,
    instantiated: InstantiatedTraitWhereClause,
    stack: &mut [Option<ImplementedTraitGoal>; MAX_TRAIT_PROOF_DEPTH],
    depth: usize,
) -> Result<TraitProofSolution, TraitGoalError> {
    if instantiated.has_projection_premises() {
        return Ok(TraitProofSolution::NoSolution);
    }
    for premise in instantiated.premises.predicates() {
        let premise = premise
            .as_ref()
            .copied()
            .ok_or(TraitGoalError::InvalidGoal)?;
        let result = solve_rigid_trait_goal_with_coinduction_inner(
            implementations,
            generic_implementations,
            clauses,
            coinductive_traits,
            premise,
            stack,
            depth,
        )?;
        if result != TraitProofSolution::Proven {
            return Ok(result);
        }
    }
    Ok(TraitProofSolution::Proven)
}

fn classify_coinductive_cycle(
    coinductive_traits: &CoinductiveTraitDatabase,
    stack: &[Option<ImplementedTraitGoal>; MAX_TRAIT_PROOF_DEPTH],
    cycle_start: usize,
    depth: usize,
) -> TraitProofSolution {
    if stack[cycle_start..depth]
        .iter()
        .all(|entry| entry.is_some_and(|goal| coinductive_traits.contains(goal.trait_id)))
    {
        TraitProofSolution::Proven
    } else {
        TraitProofSolution::Cycle
    }
}

fn classify_optional_coinductive_cycle(
    coinductive_traits: Option<&CoinductiveTraitDatabase>,
    stack: &[Option<ImplementedTraitGoal>; MAX_TRAIT_PROOF_DEPTH],
    cycle_start: usize,
    depth: usize,
) -> TraitProofSolution {
    coinductive_traits.map_or(TraitProofSolution::Cycle, |coinductive_traits| {
        classify_coinductive_cycle(coinductive_traits, stack, cycle_start, depth)
    })
}

pub fn solve_rigid_trait_goal_with_projection_environment(
    implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    exact_values: &TraitAssociatedTypeDatabase,
    generic_values: &GenericTraitAssociatedTypeDatabase,
    goal: ImplementedTraitGoal,
) -> Result<TraitProofSolution, TraitGoalError> {
    let mut stack = [None; MAX_TRAIT_PROOF_DEPTH];
    let environment = TraitProjectionEnvironment {
        exact_implementations: implementations,
        generic_implementations,
        clauses,
        exact_values,
        generic_values,
    };
    solve_rigid_trait_goal_with_generics_inner(
        implementations,
        generic_implementations,
        clauses,
        Some(environment),
        None,
        goal,
        &mut stack,
        0,
    )
}

pub fn solve_rigid_trait_goal_with_coinductive_projection_environment(
    implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    exact_values: &TraitAssociatedTypeDatabase,
    generic_values: &GenericTraitAssociatedTypeDatabase,
    coinductive_traits: &CoinductiveTraitDatabase,
    goal: ImplementedTraitGoal,
) -> Result<TraitProofSolution, TraitGoalError> {
    let mut stack = [None; MAX_TRAIT_PROOF_DEPTH];
    let environment = TraitProjectionEnvironment {
        exact_implementations: implementations,
        generic_implementations,
        clauses,
        exact_values,
        generic_values,
    };
    solve_rigid_trait_goal_with_generics_inner(
        implementations,
        generic_implementations,
        clauses,
        Some(environment),
        Some(coinductive_traits),
        goal,
        &mut stack,
        0,
    )
}

pub fn solve_rigid_trait_goal_with_concrete_projection_environment(
    implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    exact_values: &TraitAssociatedTypeDatabase,
    generic_values: &GenericTraitAssociatedTypeDatabase,
    goal: ImplementedTraitGoal,
) -> Result<TraitProofSolution, TraitGoalError> {
    solve_rigid_trait_goal_with_projection_environment(
        implementations,
        generic_implementations,
        clauses,
        exact_values,
        generic_values,
        goal,
    )
}

pub fn solve_for_all_trait_goal_with_generics(
    implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    parent_universe: TraitUniverseIndex,
    goal: ForAllImplementedTraitGoal,
) -> Result<TraitProofSolution, TraitGoalError> {
    let universe = parent_universe.next()?;
    solve_rigid_trait_goal_with_generics(
        implementations,
        generic_implementations,
        clauses,
        goal.instantiate_in_universe(universe)?,
    )
}

fn solve_rigid_trait_goal_with_generics_inner(
    implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    environment: Option<TraitProjectionEnvironment<'_>>,
    coinductive_traits: Option<&CoinductiveTraitDatabase>,
    goal: ImplementedTraitGoal,
    stack: &mut [Option<ImplementedTraitGoal>; MAX_TRAIT_PROOF_DEPTH],
    depth: usize,
) -> Result<TraitProofSolution, TraitGoalError> {
    validate_rigid_goal(goal)?;
    let exact = implementations.solve(canonicalize_implemented_trait_goal(goal)?);
    let generic = generic_implementations.select_rigid(goal)?;
    match (exact, generic) {
        (TraitGoalSolution::Unique(_), GenericTraitImplementationSolution::NoSolution) => {
            return Ok(TraitProofSolution::Proven);
        }
        (TraitGoalSolution::Unique(_), _)
        | (TraitGoalSolution::Ambiguous, _)
        | (_, GenericTraitImplementationSolution::Ambiguous) => {
            return Ok(TraitProofSolution::Ambiguous);
        }
        (TraitGoalSolution::NoSolution, GenericTraitImplementationSolution::Unique(answer)) => {
            if let Some(cycle_start) = stack[..depth].iter().position(|entry| *entry == Some(goal))
            {
                return Ok(classify_optional_coinductive_cycle(
                    coinductive_traits,
                    stack,
                    cycle_start,
                    depth,
                ));
            }
            if depth >= MAX_TRAIT_PROOF_DEPTH {
                return Ok(TraitProofSolution::Overflow);
            }
            stack[depth] = Some(goal);
            let result = solve_rigid_generic_premises(
                implementations,
                generic_implementations,
                clauses,
                environment,
                coinductive_traits,
                answer.instantiated,
                stack,
                depth + 1,
            )?;
            stack[depth] = None;
            return Ok(result);
        }
        (TraitGoalSolution::NoSolution, GenericTraitImplementationSolution::NoSolution) => {}
    }
    if let Some(cycle_start) = stack[..depth].iter().position(|entry| *entry == Some(goal)) {
        return Ok(classify_optional_coinductive_cycle(
            coinductive_traits,
            stack,
            cycle_start,
            depth,
        ));
    }
    if depth >= MAX_TRAIT_PROOF_DEPTH {
        return Ok(TraitProofSolution::Overflow);
    }
    stack[depth] = Some(goal);
    let solution = match clauses.elaborate_rigid(goal)? {
        TraitWhereClauseSolution::Unique(answer) => solve_rigid_generic_premises(
            implementations,
            generic_implementations,
            clauses,
            environment,
            coinductive_traits,
            answer.instantiated,
            stack,
            depth + 1,
        )?,
        TraitWhereClauseSolution::Ambiguous => TraitProofSolution::Ambiguous,
        TraitWhereClauseSolution::NoSolution => TraitProofSolution::NoSolution,
    };
    stack[depth] = None;
    Ok(solution)
}

fn solve_rigid_generic_premises(
    implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    environment: Option<TraitProjectionEnvironment<'_>>,
    coinductive_traits: Option<&CoinductiveTraitDatabase>,
    instantiated: InstantiatedTraitWhereClause,
    stack: &mut [Option<ImplementedTraitGoal>; MAX_TRAIT_PROOF_DEPTH],
    depth: usize,
) -> Result<TraitProofSolution, TraitGoalError> {
    if instantiated.has_projection_premises() && environment.is_none() {
        return Ok(TraitProofSolution::NoSolution);
    }
    for premise in instantiated.premises.predicates().iter() {
        let premise = premise
            .as_ref()
            .copied()
            .ok_or(TraitGoalError::InvalidGoal)?;
        let result = solve_rigid_trait_goal_with_generics_inner(
            implementations,
            generic_implementations,
            clauses,
            environment,
            coinductive_traits,
            premise,
            stack,
            depth,
        )?;
        if result != TraitProofSolution::Proven {
            return Ok(result);
        }
    }
    let Some(environment) = environment else {
        return Ok(TraitProofSolution::Proven);
    };
    for premise in instantiated.projection_premises.predicates() {
        let premise = premise
            .as_ref()
            .copied()
            .ok_or(TraitGoalError::InvalidGoal)?;
        let goal = match validate_rigid_goal(premise.goal) {
            Ok(()) => ConcreteTraitProjectionGoal {
                goal: premise.goal,
                associated_type_id: premise.associated_type_id,
            },
            Err(TraitGoalError::NonRigidClauseQuery) => {
                return Ok(TraitProofSolution::NoSolution);
            }
            Err(error) => return Err(error),
        };
        let expected = match premise.expected {
            TraitGoalType::Concrete(_) | TraitGoalType::Placeholder(_) => premise.expected,
            TraitGoalType::InferenceVariable(_) => {
                return Ok(TraitProofSolution::NoSolution);
            }
        };
        let mut projection_stack = [None; MAX_TRAIT_PROJECTION_DEPTH];
        match environment.normalize_rigid_inner(goal, &mut projection_stack, 0, stack, depth)? {
            InferredProjectionValueSolution::Unique(actual) if actual == expected => {}
            InferredProjectionValueSolution::Unique(_)
            | InferredProjectionValueSolution::NoSolution => {
                return Ok(TraitProofSolution::NoSolution);
            }
            InferredProjectionValueSolution::Ambiguous => {
                return Ok(TraitProofSolution::Ambiguous);
            }
            InferredProjectionValueSolution::Cycle => return Ok(TraitProofSolution::Cycle),
            InferredProjectionValueSolution::Overflow => return Ok(TraitProofSolution::Overflow),
        }
    }
    Ok(TraitProofSolution::Proven)
}

fn solve_rigid_trait_goal_inner(
    implementations: &TraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    goal: ImplementedTraitGoal,
    stack: &mut [Option<ImplementedTraitGoal>; MAX_TRAIT_PROOF_DEPTH],
    depth: usize,
) -> Result<TraitProofSolution, TraitGoalError> {
    validate_rigid_goal(goal)?;
    match implementations.solve(canonicalize_implemented_trait_goal(goal)?) {
        TraitGoalSolution::Unique(_) => return Ok(TraitProofSolution::Proven),
        TraitGoalSolution::Ambiguous => return Ok(TraitProofSolution::Ambiguous),
        TraitGoalSolution::NoSolution => {}
    }
    if stack[..depth].contains(&Some(goal)) {
        return Ok(TraitProofSolution::Cycle);
    }
    if depth >= MAX_TRAIT_PROOF_DEPTH {
        return Ok(TraitProofSolution::Overflow);
    }
    stack[depth] = Some(goal);
    let solution = match clauses.elaborate_rigid(goal)? {
        TraitWhereClauseSolution::Unique(answer) => {
            if answer.instantiated.has_projection_premises() {
                return Ok(TraitProofSolution::NoSolution);
            }
            let mut result = TraitProofSolution::Proven;
            for premise in answer.instantiated.premises.predicates().iter() {
                let premise = premise
                    .as_ref()
                    .copied()
                    .ok_or(TraitGoalError::InvalidGoal)?;
                let premise = solve_rigid_trait_goal_inner(
                    implementations,
                    clauses,
                    premise,
                    stack,
                    depth + 1,
                )?;
                if premise != TraitProofSolution::Proven {
                    result = premise;
                    break;
                }
            }
            result
        }
        TraitWhereClauseSolution::Ambiguous => TraitProofSolution::Ambiguous,
        TraitWhereClauseSolution::NoSolution => TraitProofSolution::NoSolution,
    };
    stack[depth] = None;
    Ok(solution)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalImplementedTraitGoal {
    pub trait_id: TraitId,
    pub self_type: CanonicalTraitGoalType,
    arguments: [Option<CanonicalTraitGoalType>; MAX_TRAIT_GOAL_ARGUMENTS],
    argument_count: usize,
    variable_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalizedImplementedTraitGoal {
    pub goal: CanonicalImplementedTraitGoal,
    variables: [Option<TraitInferenceVariableId>; MAX_CANONICAL_TRAIT_VARIABLES],
    variable_count: usize,
}

impl CanonicalizedImplementedTraitGoal {
    pub fn variables(&self) -> &[Option<TraitInferenceVariableId>] {
        &self.variables[..self.variable_count]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalizedImplementedTraitPredicates {
    predicates: [Option<CanonicalImplementedTraitGoal>; MAX_TRAIT_PREDICATES],
    predicate_count: usize,
    variables: [Option<TraitInferenceVariableId>; MAX_CANONICAL_TRAIT_VARIABLES],
    variable_count: usize,
}

impl CanonicalizedImplementedTraitPredicates {
    pub fn predicates(&self) -> &[Option<CanonicalImplementedTraitGoal>] {
        &self.predicates[..self.predicate_count]
    }

    pub fn variables(&self) -> &[Option<TraitInferenceVariableId>] {
        &self.variables[..self.variable_count]
    }
}

impl CanonicalImplementedTraitGoal {
    pub fn arguments(&self) -> &[Option<CanonicalTraitGoalType>] {
        &self.arguments[..self.argument_count]
    }

    pub const fn variable_count(&self) -> usize {
        self.variable_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraitGoalError {
    TooManyArguments,
    TooManyCanonicalVariables,
    TooManyGenericParameters,
    TooManyBinderLevels,
    TooManyCoinductiveTraits,
    DuplicateCoinductiveTrait,
    TooManyPredicates,
    TooManyTraitGoalTerms,
    InvalidTraitGoalTermReference,
    TooManyWhereClauses,
    DuplicateWhereClauseId,
    DuplicateWhereClause,
    TooManyAssociatedTypeValues,
    DuplicateAssociatedTypeValue,
    DuplicateGenericAssociatedTypeValue,
    UnknownImplementationId,
    UnknownGenericImplementationId,
    UniverseOverflow,
    UniverseLeak,
    NonRigidClauseQuery,
    NonExistentialClauseQuery,
    TooManyGenericImplementations,
    DuplicateGenericImplementationId,
    OverlappingGenericImplementation,
    OverlappingExactAndGenericImplementation,
    NonConcreteClauseQuery,
    UnboundGenericParameter,
    WrongGenericArgumentCount,
    InvalidGoal,
    TooManyImplementations,
    DuplicateImplementationId,
    OverlappingImplementation,
}

fn validate_bound_goal(
    goal: BoundImplementedTraitGoal,
    parameter_count: usize,
) -> Result<(), TraitGoalError> {
    if goal.argument_count > goal.arguments.len()
        || goal.arguments[..goal.argument_count]
            .iter()
            .any(Option::is_none)
        || goal.arguments[goal.argument_count..]
            .iter()
            .any(Option::is_some)
    {
        return Err(TraitGoalError::InvalidGoal);
    }
    validate_bound_type(goal.self_type, parameter_count)?;
    for argument in goal.arguments().iter() {
        validate_bound_type(
            argument
                .as_ref()
                .copied()
                .ok_or(TraitGoalError::InvalidGoal)?,
            parameter_count,
        )?;
    }
    Ok(())
}

fn validate_concrete_goal(goal: ImplementedTraitGoal) -> Result<(), TraitGoalError> {
    if goal.argument_count > goal.arguments.len()
        || goal.arguments[..goal.argument_count]
            .iter()
            .any(Option::is_none)
        || goal.arguments[goal.argument_count..]
            .iter()
            .any(Option::is_some)
    {
        return Err(TraitGoalError::InvalidGoal);
    }
    concrete_goal_type(goal.self_type)?;
    for argument in goal.arguments().iter() {
        concrete_goal_type(
            argument
                .as_ref()
                .copied()
                .ok_or(TraitGoalError::InvalidGoal)?,
        )?;
    }
    Ok(())
}

fn validate_existential_goal(goal: ImplementedTraitGoal) -> Result<(), TraitGoalError> {
    canonicalize_implemented_trait_goal(goal)?;
    if matches!(goal.self_type, TraitGoalType::Placeholder(_))
        || goal
            .arguments()
            .iter()
            .flatten()
            .any(|argument| matches!(argument, TraitGoalType::Placeholder(_)))
    {
        return Err(TraitGoalError::NonExistentialClauseQuery);
    }
    Ok(())
}

fn validate_rigid_goal(goal: ImplementedTraitGoal) -> Result<(), TraitGoalError> {
    if goal.argument_count > goal.arguments.len()
        || goal.arguments[..goal.argument_count]
            .iter()
            .any(Option::is_none)
        || goal.arguments[goal.argument_count..]
            .iter()
            .any(Option::is_some)
    {
        return Err(TraitGoalError::InvalidGoal);
    }
    rigid_goal_type(goal.self_type)?;
    for argument in goal.arguments().iter() {
        rigid_goal_type(
            argument
                .as_ref()
                .copied()
                .ok_or(TraitGoalError::InvalidGoal)?,
        )?;
    }
    Ok(())
}

fn rigid_goal_type(ty: TraitGoalType) -> Result<TraitGoalType, TraitGoalError> {
    match ty {
        TraitGoalType::Concrete(_) | TraitGoalType::Placeholder(_) => Ok(ty),
        TraitGoalType::InferenceVariable(_) => Err(TraitGoalError::NonRigidClauseQuery),
    }
}

fn concrete_goal_type(ty: TraitGoalType) -> Result<TraitTypeId, TraitGoalError> {
    match ty {
        TraitGoalType::Concrete(ty) => Ok(ty),
        TraitGoalType::InferenceVariable(_) | TraitGoalType::Placeholder(_) => {
            Err(TraitGoalError::NonConcreteClauseQuery)
        }
    }
}

fn bound_type_matches_concrete(
    bound: BoundTraitGoalType,
    concrete: TraitTypeId,
    bindings: &mut [Option<TraitTypeId>; MAX_TRAIT_GENERIC_PARAMETERS],
) -> bool {
    match bound {
        BoundTraitGoalType::Concrete(bound) => bound == concrete,
        BoundTraitGoalType::Parameter(parameter) => {
            let Some(binding) = bindings.get_mut(parameter.get() as usize) else {
                return false;
            };
            match *binding {
                Some(bound) => bound == concrete,
                None => {
                    *binding = Some(concrete);
                    true
                }
            }
        }
    }
}

fn bound_type_matches_rigid(
    bound: BoundTraitGoalType,
    rigid: TraitGoalType,
    bindings: &mut [Option<TraitGoalType>; MAX_TRAIT_GENERIC_PARAMETERS],
) -> bool {
    match bound {
        BoundTraitGoalType::Concrete(bound) => rigid == TraitGoalType::Concrete(bound),
        BoundTraitGoalType::Parameter(parameter) => {
            let Some(binding) = bindings.get_mut(parameter.get() as usize) else {
                return false;
            };
            match *binding {
                Some(bound) => bound == rigid,
                None => {
                    *binding = Some(rigid);
                    true
                }
            }
        }
    }
}

fn validate_bound_type(
    ty: BoundTraitGoalType,
    parameter_count: usize,
) -> Result<(), TraitGoalError> {
    if let BoundTraitGoalType::Parameter(parameter) = ty {
        if parameter.get() as usize >= parameter_count {
            return Err(TraitGoalError::UnboundGenericParameter);
        }
    }
    Ok(())
}

fn instantiate_bound_goal(
    goal: BoundImplementedTraitGoal,
    arguments: &[TraitGoalType],
) -> Result<ImplementedTraitGoal, TraitGoalError> {
    validate_bound_goal(goal, arguments.len())?;
    let mut instantiated = ImplementedTraitGoal::new(
        goal.trait_id,
        instantiate_bound_type(goal.self_type, arguments)?,
    );
    for argument in goal.arguments().iter() {
        instantiated.push_argument(instantiate_bound_type(
            argument
                .as_ref()
                .copied()
                .ok_or(TraitGoalError::InvalidGoal)?,
            arguments,
        )?)?;
    }
    Ok(instantiated)
}

fn instantiate_bound_type(
    ty: BoundTraitGoalType,
    arguments: &[TraitGoalType],
) -> Result<TraitGoalType, TraitGoalError> {
    match ty {
        BoundTraitGoalType::Concrete(ty) => Ok(TraitGoalType::Concrete(ty)),
        BoundTraitGoalType::Parameter(parameter) => arguments
            .get(parameter.get() as usize)
            .copied()
            .ok_or(TraitGoalError::UnboundGenericParameter),
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TraitImplementationId(u32);

impl TraitImplementationId {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraitAssociatedTypeValue {
    pub implementation_id: TraitImplementationId,
    pub associated_type_id: TraitAssociatedTypeId,
    pub value: TraitTypeId,
}

impl TraitAssociatedTypeValue {
    pub const fn new(
        implementation_id: TraitImplementationId,
        associated_type_id: TraitAssociatedTypeId,
        value: TraitTypeId,
    ) -> Self {
        Self {
            implementation_id,
            associated_type_id,
            value,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraitProjectionSolution {
    Unique(TraitTypeId),
    Ambiguous,
    NoSolution,
    Cycle,
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraitAssociatedTypeDatabase {
    values: [Option<TraitAssociatedTypeValue>; MAX_TRAIT_ASSOCIATED_TYPE_VALUES],
    value_count: usize,
}

impl TraitAssociatedTypeDatabase {
    pub const EMPTY: Self = Self {
        values: [None; MAX_TRAIT_ASSOCIATED_TYPE_VALUES],
        value_count: 0,
    };

    pub fn insert(
        &mut self,
        implementations: &TraitImplementationDatabase,
        value: TraitAssociatedTypeValue,
    ) -> Result<(), TraitGoalError> {
        if !implementations.contains_id(value.implementation_id) {
            return Err(TraitGoalError::UnknownImplementationId);
        }
        if self.values[..self.value_count]
            .iter()
            .flatten()
            .any(|existing| {
                existing.implementation_id == value.implementation_id
                    && existing.associated_type_id == value.associated_type_id
            })
        {
            return Err(TraitGoalError::DuplicateAssociatedTypeValue);
        }
        let slot = self
            .values
            .get_mut(self.value_count)
            .ok_or(TraitGoalError::TooManyAssociatedTypeValues)?;
        *slot = Some(value);
        self.value_count += 1;
        Ok(())
    }

    pub fn normalize(
        &self,
        implementations: &TraitImplementationDatabase,
        goal: CanonicalImplementedTraitGoal,
        associated_type_id: TraitAssociatedTypeId,
    ) -> TraitProjectionSolution {
        let answer = match implementations.solve(goal) {
            TraitGoalSolution::Unique(answer) => answer,
            TraitGoalSolution::Ambiguous => return TraitProjectionSolution::Ambiguous,
            TraitGoalSolution::NoSolution => return TraitProjectionSolution::NoSolution,
        };
        self.values[..self.value_count]
            .iter()
            .flatten()
            .find(|value| {
                value.implementation_id == answer.implementation_id
                    && value.associated_type_id == associated_type_id
            })
            .map_or(TraitProjectionSolution::NoSolution, |value| {
                TraitProjectionSolution::Unique(value.value)
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenericTraitAssociatedTypeValue {
    pub implementation_id: GenericTraitImplementationId,
    pub associated_type_id: TraitAssociatedTypeId,
    pub value: GenericTraitAssociatedTypeTerm,
}

impl GenericTraitAssociatedTypeValue {
    pub const fn new(
        implementation_id: GenericTraitImplementationId,
        associated_type_id: TraitAssociatedTypeId,
        value: BoundTraitGoalType,
    ) -> Self {
        Self {
            implementation_id,
            associated_type_id,
            value: GenericTraitAssociatedTypeTerm::Type(value),
        }
    }

    pub const fn new_projection(
        implementation_id: GenericTraitImplementationId,
        associated_type_id: TraitAssociatedTypeId,
        projection: BoundTraitProjection,
    ) -> Self {
        Self {
            implementation_id,
            associated_type_id,
            value: GenericTraitAssociatedTypeTerm::Projection(projection),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenericTraitAssociatedTypeTerm {
    Type(BoundTraitGoalType),
    Projection(BoundTraitProjection),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundTraitProjection {
    pub goal: BoundImplementedTraitGoal,
    pub associated_type_id: TraitAssociatedTypeId,
}

impl BoundTraitProjection {
    pub const fn new(
        goal: BoundImplementedTraitGoal,
        associated_type_id: TraitAssociatedTypeId,
    ) -> Self {
        Self {
            goal,
            associated_type_id,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExistsTraitProjectionEquality {
    parameter_count: usize,
    pub projection: BoundTraitProjection,
    pub expected: BoundTraitGoalType,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForAllTraitProjectionEquality {
    parameter_count: usize,
    pub projection: BoundTraitProjection,
    pub expected: BoundTraitGoalType,
}

impl ForAllTraitProjectionEquality {
    pub fn new(
        parameter_count: usize,
        projection: BoundTraitProjection,
        expected: BoundTraitGoalType,
    ) -> Result<Self, TraitGoalError> {
        if parameter_count > MAX_TRAIT_GENERIC_PARAMETERS {
            return Err(TraitGoalError::TooManyGenericParameters);
        }
        validate_bound_goal(projection.goal, parameter_count)?;
        validate_bound_type(expected, parameter_count)?;
        Ok(Self {
            parameter_count,
            projection,
            expected,
        })
    }

    pub const fn parameter_count(self) -> usize {
        self.parameter_count
    }

    pub fn instantiate_in_universe(
        self,
        universe: TraitUniverseIndex,
    ) -> Result<InferredTraitProjectionEquality, TraitGoalError> {
        let mut arguments = [TraitGoalType::Placeholder(TraitPlaceholder::new(
            universe,
            TraitPlaceholderId::new(0),
        )); MAX_TRAIT_GENERIC_PARAMETERS];
        for (index, argument) in arguments[..self.parameter_count].iter_mut().enumerate() {
            *argument = TraitGoalType::Placeholder(TraitPlaceholder::new(
                universe,
                TraitPlaceholderId::new(index as u32),
            ));
        }
        Ok(InferredTraitProjectionEquality {
            goal: instantiate_bound_goal(self.projection.goal, &arguments[..self.parameter_count])?,
            associated_type_id: self.projection.associated_type_id,
            expected: instantiate_bound_type(self.expected, &arguments[..self.parameter_count])?,
        })
    }
}

impl ExistsTraitProjectionEquality {
    pub fn new(
        parameter_count: usize,
        projection: BoundTraitProjection,
        expected: BoundTraitGoalType,
    ) -> Result<Self, TraitGoalError> {
        if parameter_count > MAX_TRAIT_GENERIC_PARAMETERS {
            return Err(TraitGoalError::TooManyGenericParameters);
        }
        validate_bound_goal(projection.goal, parameter_count)?;
        validate_bound_type(expected, parameter_count)?;
        Ok(Self {
            parameter_count,
            projection,
            expected,
        })
    }

    pub const fn parameter_count(self) -> usize {
        self.parameter_count
    }

    pub fn instantiate_in_universe(
        self,
        universe: TraitUniverseIndex,
    ) -> Result<InferredTraitProjectionEquality, TraitGoalError> {
        let mut arguments =
            [TraitGoalType::InferenceVariable(TraitInferenceVariableId::in_universe(universe, 0));
                MAX_TRAIT_GENERIC_PARAMETERS];
        for (index, argument) in arguments[..self.parameter_count].iter_mut().enumerate() {
            *argument = TraitGoalType::InferenceVariable(TraitInferenceVariableId::in_universe(
                universe,
                index as u32,
            ));
        }
        Ok(InferredTraitProjectionEquality {
            goal: instantiate_bound_goal(self.projection.goal, &arguments[..self.parameter_count])?,
            associated_type_id: self.projection.associated_type_id,
            expected: instantiate_bound_type(self.expected, &arguments[..self.parameter_count])?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InferredTraitProjectionEquality {
    pub goal: ImplementedTraitGoal,
    pub associated_type_id: TraitAssociatedTypeId,
    pub expected: TraitGoalType,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InferredTraitProjectionPredicates {
    predicates: [Option<InferredTraitProjectionEquality>; MAX_TRAIT_PREDICATES],
    predicate_count: usize,
}

impl InferredTraitProjectionPredicates {
    pub const EMPTY: Self = Self {
        predicates: [None; MAX_TRAIT_PREDICATES],
        predicate_count: 0,
    };

    pub fn push(
        &mut self,
        predicate: InferredTraitProjectionEquality,
    ) -> Result<(), TraitGoalError> {
        let slot = self
            .predicates
            .get_mut(self.predicate_count)
            .ok_or(TraitGoalError::TooManyPredicates)?;
        *slot = Some(predicate);
        self.predicate_count += 1;
        Ok(())
    }

    pub fn predicates(&self) -> &[Option<InferredTraitProjectionEquality>] {
        &self.predicates[..self.predicate_count]
    }

    pub const fn is_empty(self) -> bool {
        self.predicate_count == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundTraitPredicate {
    Implemented(BoundImplementedTraitGoal),
    ProjectionEquality {
        projection: BoundTraitProjection,
        expected: BoundTraitGoalType,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InferredTraitPredicate {
    Implemented(ImplementedTraitGoal),
    ProjectionEquality(InferredTraitProjectionEquality),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExistsTraitPredicateConjunction {
    parameter_count: usize,
    predicates: [Option<BoundTraitPredicate>; MAX_TRAIT_PREDICATES],
    predicate_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForAllTraitPredicateConjunction {
    parameter_count: usize,
    predicates: [Option<BoundTraitPredicate>; MAX_TRAIT_PREDICATES],
    predicate_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NestedForAllTraitPredicateConjunction {
    binder_parameter_counts: [usize; MAX_TRAIT_GENERIC_PARAMETERS],
    binder_count: usize,
    total_parameter_count: usize,
    predicates: [Option<BoundTraitPredicate>; MAX_TRAIT_PREDICATES],
    predicate_count: usize,
}

impl NestedForAllTraitPredicateConjunction {
    pub fn new(outer_parameter_count: usize) -> Result<Self, TraitGoalError> {
        if outer_parameter_count > MAX_TRAIT_GENERIC_PARAMETERS {
            return Err(TraitGoalError::TooManyGenericParameters);
        }
        let mut binder_parameter_counts = [0; MAX_TRAIT_GENERIC_PARAMETERS];
        binder_parameter_counts[0] = outer_parameter_count;
        Ok(Self {
            binder_parameter_counts,
            binder_count: 1,
            total_parameter_count: outer_parameter_count,
            predicates: [None; MAX_TRAIT_PREDICATES],
            predicate_count: 0,
        })
    }

    pub fn push_binder(&mut self, parameter_count: usize) -> Result<(), TraitGoalError> {
        if self.predicate_count != 0 {
            return Err(TraitGoalError::InvalidGoal);
        }
        let total = self
            .total_parameter_count
            .checked_add(parameter_count)
            .ok_or(TraitGoalError::TooManyGenericParameters)?;
        if total > MAX_TRAIT_GENERIC_PARAMETERS {
            return Err(TraitGoalError::TooManyGenericParameters);
        }
        if self.binder_count >= MAX_TRAIT_GENERIC_PARAMETERS {
            return Err(TraitGoalError::TooManyBinderLevels);
        }
        self.binder_parameter_counts[self.binder_count] = parameter_count;
        self.binder_count += 1;
        self.total_parameter_count = total;
        Ok(())
    }

    pub const fn binder_count(self) -> usize {
        self.binder_count
    }

    pub const fn total_parameter_count(self) -> usize {
        self.total_parameter_count
    }

    pub fn push(&mut self, predicate: BoundTraitPredicate) -> Result<(), TraitGoalError> {
        match predicate {
            BoundTraitPredicate::Implemented(goal) => {
                validate_bound_goal(goal, self.total_parameter_count)?;
            }
            BoundTraitPredicate::ProjectionEquality {
                projection,
                expected,
            } => {
                validate_bound_goal(projection.goal, self.total_parameter_count)?;
                validate_bound_type(expected, self.total_parameter_count)?;
            }
        }
        let slot = self
            .predicates
            .get_mut(self.predicate_count)
            .ok_or(TraitGoalError::TooManyPredicates)?;
        *slot = Some(predicate);
        self.predicate_count += 1;
        Ok(())
    }

    pub fn predicates(&self) -> &[Option<BoundTraitPredicate>] {
        &self.predicates[..self.predicate_count]
    }

    fn instantiate_arguments(
        self,
        parent_universe: TraitUniverseIndex,
    ) -> Result<([TraitGoalType; MAX_TRAIT_GENERIC_PARAMETERS], usize), TraitGoalError> {
        let mut arguments =
            [TraitGoalType::Concrete(TraitTypeId::new(0)); MAX_TRAIT_GENERIC_PARAMETERS];
        let mut universe = parent_universe;
        let mut offset = 0usize;
        for parameter_count in self.binder_parameter_counts[..self.binder_count]
            .iter()
            .copied()
        {
            universe = universe.next()?;
            for local_index in 0..parameter_count {
                arguments[offset + local_index] = TraitGoalType::Placeholder(
                    TraitPlaceholder::new(universe, TraitPlaceholderId::new(local_index as u32)),
                );
            }
            offset += parameter_count;
        }
        Ok((arguments, offset))
    }

    fn advance_universe(
        self,
        mut parent_universe: TraitUniverseIndex,
    ) -> Result<TraitUniverseIndex, TraitGoalError> {
        for _ in 0..self.binder_count {
            parent_universe = parent_universe.next()?;
        }
        Ok(parent_universe)
    }

    fn instantiate_predicate(
        self,
        predicate: BoundTraitPredicate,
        arguments: &[TraitGoalType],
    ) -> Result<InferredTraitPredicate, TraitGoalError> {
        match predicate {
            BoundTraitPredicate::Implemented(goal) => Ok(InferredTraitPredicate::Implemented(
                instantiate_bound_goal(goal, arguments)?,
            )),
            BoundTraitPredicate::ProjectionEquality {
                projection,
                expected,
            } => Ok(InferredTraitPredicate::ProjectionEquality(
                InferredTraitProjectionEquality {
                    goal: instantiate_bound_goal(projection.goal, arguments)?,
                    associated_type_id: projection.associated_type_id,
                    expected: instantiate_bound_type(expected, arguments)?,
                },
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForAllTraitPredicateBranchForest {
    branches: [Option<NestedForAllTraitPredicateConjunction>; MAX_TRAIT_PREDICATES],
    branch_count: usize,
    total_binder_count: usize,
    total_predicate_count: usize,
}

impl ForAllTraitPredicateBranchForest {
    pub const EMPTY: Self = Self {
        branches: [None; MAX_TRAIT_PREDICATES],
        branch_count: 0,
        total_binder_count: 0,
        total_predicate_count: 0,
    };

    pub fn push_branch(
        &mut self,
        branch: NestedForAllTraitPredicateConjunction,
    ) -> Result<(), TraitGoalError> {
        let binder_count = self
            .total_binder_count
            .checked_add(branch.binder_count)
            .ok_or(TraitGoalError::TooManyBinderLevels)?;
        if binder_count > MAX_TRAIT_PROOF_DEPTH {
            return Err(TraitGoalError::TooManyBinderLevels);
        }
        let predicate_count = self
            .total_predicate_count
            .checked_add(branch.predicate_count)
            .ok_or(TraitGoalError::TooManyPredicates)?;
        if predicate_count > MAX_TRAIT_PREDICATES {
            return Err(TraitGoalError::TooManyPredicates);
        }
        let slot = self
            .branches
            .get_mut(self.branch_count)
            .ok_or(TraitGoalError::TooManyPredicates)?;
        *slot = Some(branch);
        self.branch_count += 1;
        self.total_binder_count = binder_count;
        self.total_predicate_count = predicate_count;
        Ok(())
    }

    pub fn branches(&self) -> &[Option<NestedForAllTraitPredicateConjunction>] {
        &self.branches[..self.branch_count]
    }

    pub const fn branch_count(self) -> usize {
        self.branch_count
    }

    pub const fn total_binder_count(self) -> usize {
        self.total_binder_count
    }

    pub const fn total_predicate_count(self) -> usize {
        self.total_predicate_count
    }
}

impl ForAllTraitPredicateConjunction {
    pub fn new(parameter_count: usize) -> Result<Self, TraitGoalError> {
        if parameter_count > MAX_TRAIT_GENERIC_PARAMETERS {
            return Err(TraitGoalError::TooManyGenericParameters);
        }
        Ok(Self {
            parameter_count,
            predicates: [None; MAX_TRAIT_PREDICATES],
            predicate_count: 0,
        })
    }

    pub const fn parameter_count(self) -> usize {
        self.parameter_count
    }

    pub fn push(&mut self, predicate: BoundTraitPredicate) -> Result<(), TraitGoalError> {
        match predicate {
            BoundTraitPredicate::Implemented(goal) => {
                validate_bound_goal(goal, self.parameter_count)?;
            }
            BoundTraitPredicate::ProjectionEquality {
                projection,
                expected,
            } => {
                validate_bound_goal(projection.goal, self.parameter_count)?;
                validate_bound_type(expected, self.parameter_count)?;
            }
        }
        let slot = self
            .predicates
            .get_mut(self.predicate_count)
            .ok_or(TraitGoalError::TooManyPredicates)?;
        *slot = Some(predicate);
        self.predicate_count += 1;
        Ok(())
    }

    pub fn predicates(&self) -> &[Option<BoundTraitPredicate>] {
        &self.predicates[..self.predicate_count]
    }

    fn instantiate_predicate(
        self,
        predicate: BoundTraitPredicate,
        universe: TraitUniverseIndex,
    ) -> Result<InferredTraitPredicate, TraitGoalError> {
        let mut arguments = [TraitGoalType::Placeholder(TraitPlaceholder::new(
            universe,
            TraitPlaceholderId::new(0),
        )); MAX_TRAIT_GENERIC_PARAMETERS];
        for (index, argument) in arguments[..self.parameter_count].iter_mut().enumerate() {
            *argument = TraitGoalType::Placeholder(TraitPlaceholder::new(
                universe,
                TraitPlaceholderId::new(index as u32),
            ));
        }
        match predicate {
            BoundTraitPredicate::Implemented(goal) => Ok(InferredTraitPredicate::Implemented(
                instantiate_bound_goal(goal, &arguments[..self.parameter_count])?,
            )),
            BoundTraitPredicate::ProjectionEquality {
                projection,
                expected,
            } => Ok(InferredTraitPredicate::ProjectionEquality(
                InferredTraitProjectionEquality {
                    goal: instantiate_bound_goal(
                        projection.goal,
                        &arguments[..self.parameter_count],
                    )?,
                    associated_type_id: projection.associated_type_id,
                    expected: instantiate_bound_type(expected, &arguments[..self.parameter_count])?,
                },
            )),
        }
    }
}

impl ExistsTraitPredicateConjunction {
    pub fn new(parameter_count: usize) -> Result<Self, TraitGoalError> {
        if parameter_count > MAX_TRAIT_GENERIC_PARAMETERS {
            return Err(TraitGoalError::TooManyGenericParameters);
        }
        Ok(Self {
            parameter_count,
            predicates: [None; MAX_TRAIT_PREDICATES],
            predicate_count: 0,
        })
    }

    pub const fn parameter_count(self) -> usize {
        self.parameter_count
    }

    pub fn push(&mut self, predicate: BoundTraitPredicate) -> Result<(), TraitGoalError> {
        match predicate {
            BoundTraitPredicate::Implemented(goal) => {
                validate_bound_goal(goal, self.parameter_count)?;
            }
            BoundTraitPredicate::ProjectionEquality {
                projection,
                expected,
            } => {
                validate_bound_goal(projection.goal, self.parameter_count)?;
                validate_bound_type(expected, self.parameter_count)?;
            }
        }
        let slot = self
            .predicates
            .get_mut(self.predicate_count)
            .ok_or(TraitGoalError::TooManyPredicates)?;
        *slot = Some(predicate);
        self.predicate_count += 1;
        Ok(())
    }

    pub fn predicates(&self) -> &[Option<BoundTraitPredicate>] {
        &self.predicates[..self.predicate_count]
    }

    fn instantiate_predicate(
        self,
        predicate: BoundTraitPredicate,
        universe: TraitUniverseIndex,
    ) -> Result<InferredTraitPredicate, TraitGoalError> {
        let mut arguments =
            [TraitGoalType::InferenceVariable(TraitInferenceVariableId::in_universe(universe, 0));
                MAX_TRAIT_GENERIC_PARAMETERS];
        for (index, argument) in arguments[..self.parameter_count].iter_mut().enumerate() {
            *argument = TraitGoalType::InferenceVariable(TraitInferenceVariableId::in_universe(
                universe,
                index as u32,
            ));
        }
        match predicate {
            BoundTraitPredicate::Implemented(goal) => Ok(InferredTraitPredicate::Implemented(
                instantiate_bound_goal(goal, &arguments[..self.parameter_count])?,
            )),
            BoundTraitPredicate::ProjectionEquality {
                projection,
                expected,
            } => Ok(InferredTraitPredicate::ProjectionEquality(
                InferredTraitProjectionEquality {
                    goal: instantiate_bound_goal(
                        projection.goal,
                        &arguments[..self.parameter_count],
                    )?,
                    associated_type_id: projection.associated_type_id,
                    expected: instantiate_bound_type(expected, &arguments[..self.parameter_count])?,
                },
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenericTraitAssociatedTypeDatabase {
    values: [Option<GenericTraitAssociatedTypeValue>; MAX_TRAIT_ASSOCIATED_TYPE_VALUES],
    value_count: usize,
}

impl GenericTraitAssociatedTypeDatabase {
    pub const EMPTY: Self = Self {
        values: [None; MAX_TRAIT_ASSOCIATED_TYPE_VALUES],
        value_count: 0,
    };

    pub fn insert(
        &mut self,
        implementations: &GenericTraitImplementationDatabase,
        value: GenericTraitAssociatedTypeValue,
    ) -> Result<(), TraitGoalError> {
        let implementation = implementations
            .find(value.implementation_id)
            .ok_or(TraitGoalError::UnknownGenericImplementationId)?;
        match value.value {
            GenericTraitAssociatedTypeTerm::Type(BoundTraitGoalType::Parameter(parameter))
                if parameter.get() as usize >= implementation.implementation.parameter_count =>
            {
                return Err(TraitGoalError::UnboundGenericParameter);
            }
            GenericTraitAssociatedTypeTerm::Projection(projection) => validate_bound_goal(
                projection.goal,
                implementation.implementation.parameter_count,
            )?,
            GenericTraitAssociatedTypeTerm::Type(_) => {}
        }
        if self.values[..self.value_count]
            .iter()
            .flatten()
            .any(|existing| {
                existing.implementation_id == value.implementation_id
                    && existing.associated_type_id == value.associated_type_id
            })
        {
            return Err(TraitGoalError::DuplicateGenericAssociatedTypeValue);
        }
        let slot = self
            .values
            .get_mut(self.value_count)
            .ok_or(TraitGoalError::TooManyAssociatedTypeValues)?;
        *slot = Some(value);
        self.value_count += 1;
        Ok(())
    }

    pub fn normalize(
        &self,
        exact: &TraitImplementationDatabase,
        implementations: &GenericTraitImplementationDatabase,
        clauses: &TraitWhereClauseDatabase,
        goal: ImplementedTraitGoal,
        associated_type_id: TraitAssociatedTypeId,
    ) -> Result<TraitProjectionSolution, TraitGoalError> {
        normalize_concrete_trait_projection(
            exact,
            implementations,
            clauses,
            &TraitAssociatedTypeDatabase::EMPTY,
            self,
            goal,
            associated_type_id,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConcreteTraitProjectionGoal {
    goal: ImplementedTraitGoal,
    associated_type_id: TraitAssociatedTypeId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InferredProjectionValueSolution {
    Unique(TraitGoalType),
    Ambiguous,
    NoSolution,
    Cycle,
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProjectionBearingGoalNormalizationSolution {
    Unique(ImplementedTraitGoal),
    Ambiguous,
    NoSolution,
    Cycle,
    Overflow,
}

#[derive(Clone, Copy)]
struct TraitProjectionEnvironment<'a> {
    exact_implementations: &'a TraitImplementationDatabase,
    generic_implementations: &'a GenericTraitImplementationDatabase,
    clauses: &'a TraitWhereClauseDatabase,
    exact_values: &'a TraitAssociatedTypeDatabase,
    generic_values: &'a GenericTraitAssociatedTypeDatabase,
}

impl TraitProjectionEnvironment<'_> {
    fn normalize_rigid_inner(
        self,
        projection: ConcreteTraitProjectionGoal,
        stack: &mut [Option<ConcreteTraitProjectionGoal>; MAX_TRAIT_PROJECTION_DEPTH],
        depth: usize,
        proof_stack: &mut [Option<ImplementedTraitGoal>; MAX_TRAIT_PROOF_DEPTH],
        proof_depth: usize,
    ) -> Result<InferredProjectionValueSolution, TraitGoalError> {
        validate_rigid_goal(projection.goal)?;
        if stack[..depth].contains(&Some(projection)) {
            return Ok(InferredProjectionValueSolution::Cycle);
        }
        if depth >= MAX_TRAIT_PROJECTION_DEPTH {
            return Ok(InferredProjectionValueSolution::Overflow);
        }
        stack[depth] = Some(projection);
        let result =
            self.normalize_rigid_selected(projection, stack, depth, proof_stack, proof_depth);
        stack[depth] = None;
        result
    }

    fn normalize_rigid_selected(
        self,
        projection: ConcreteTraitProjectionGoal,
        stack: &mut [Option<ConcreteTraitProjectionGoal>; MAX_TRAIT_PROJECTION_DEPTH],
        depth: usize,
        proof_stack: &mut [Option<ImplementedTraitGoal>; MAX_TRAIT_PROOF_DEPTH],
        proof_depth: usize,
    ) -> Result<InferredProjectionValueSolution, TraitGoalError> {
        let canonical = canonicalize_implemented_trait_goal(projection.goal)?;
        let exact = self.exact_implementations.solve(canonical);
        let generic = self.generic_implementations.select_rigid(projection.goal)?;
        let answer = match (exact, generic) {
            (TraitGoalSolution::Unique(answer), GenericTraitImplementationSolution::NoSolution) => {
                let Some(value) = self.exact_values.values[..self.exact_values.value_count]
                    .iter()
                    .flatten()
                    .find(|value| {
                        value.implementation_id == answer.implementation_id
                            && value.associated_type_id == projection.associated_type_id
                    })
                else {
                    return Ok(InferredProjectionValueSolution::NoSolution);
                };
                return Ok(InferredProjectionValueSolution::Unique(
                    TraitGoalType::Concrete(value.value),
                ));
            }
            (TraitGoalSolution::NoSolution, GenericTraitImplementationSolution::Unique(answer)) => {
                answer
            }
            (TraitGoalSolution::NoSolution, GenericTraitImplementationSolution::NoSolution) => {
                return Ok(InferredProjectionValueSolution::NoSolution);
            }
            (TraitGoalSolution::Unique(_), _)
            | (TraitGoalSolution::Ambiguous, _)
            | (_, GenericTraitImplementationSolution::Ambiguous) => {
                return Ok(InferredProjectionValueSolution::Ambiguous);
            }
        };
        if !answer.instantiated.premises.predicates().is_empty()
            || answer.instantiated.has_projection_premises()
        {
            if proof_stack[..proof_depth].contains(&Some(projection.goal)) {
                return Ok(InferredProjectionValueSolution::Cycle);
            }
            if proof_depth >= MAX_TRAIT_PROOF_DEPTH {
                return Ok(InferredProjectionValueSolution::Overflow);
            }
            proof_stack[proof_depth] = Some(projection.goal);
            let proof = solve_rigid_generic_premises(
                self.exact_implementations,
                self.generic_implementations,
                self.clauses,
                Some(self),
                None,
                answer.instantiated,
                proof_stack,
                proof_depth + 1,
            )?;
            proof_stack[proof_depth] = None;
            match proof {
                TraitProofSolution::Proven => {}
                TraitProofSolution::Ambiguous => {
                    return Ok(InferredProjectionValueSolution::Ambiguous);
                }
                TraitProofSolution::NoSolution => {
                    return Ok(InferredProjectionValueSolution::NoSolution);
                }
                TraitProofSolution::Cycle => return Ok(InferredProjectionValueSolution::Cycle),
                TraitProofSolution::Overflow => {
                    return Ok(InferredProjectionValueSolution::Overflow);
                }
            }
        }
        let Some(value) = self.generic_values.values[..self.generic_values.value_count]
            .iter()
            .flatten()
            .find(|value| {
                value.implementation_id == answer.implementation_id
                    && value.associated_type_id == projection.associated_type_id
            })
        else {
            return Ok(InferredProjectionValueSolution::NoSolution);
        };
        match value.value {
            GenericTraitAssociatedTypeTerm::Type(value) => {
                Ok(InferredProjectionValueSolution::Unique(
                    instantiate_generic_associated_type_rigid(value, answer)?,
                ))
            }
            GenericTraitAssociatedTypeTerm::Projection(nested) => {
                let goal = instantiate_generic_projection_goal(nested.goal, answer)?;
                self.normalize_rigid_inner(
                    ConcreteTraitProjectionGoal {
                        goal,
                        associated_type_id: nested.associated_type_id,
                    },
                    stack,
                    depth + 1,
                    proof_stack,
                    proof_depth,
                )
            }
        }
    }

    fn normalize_inner(
        self,
        projection: ConcreteTraitProjectionGoal,
        stack: &mut [Option<ConcreteTraitProjectionGoal>; MAX_TRAIT_PROJECTION_DEPTH],
        depth: usize,
    ) -> Result<TraitProjectionSolution, TraitGoalError> {
        validate_concrete_goal(projection.goal)?;
        if stack[..depth].contains(&Some(projection)) {
            return Ok(TraitProjectionSolution::Cycle);
        }
        if depth >= MAX_TRAIT_PROJECTION_DEPTH {
            return Ok(TraitProjectionSolution::Overflow);
        }
        stack[depth] = Some(projection);
        let result = self.normalize_selected(projection, stack, depth);
        stack[depth] = None;
        result
    }

    fn normalize_selected(
        self,
        projection: ConcreteTraitProjectionGoal,
        stack: &mut [Option<ConcreteTraitProjectionGoal>; MAX_TRAIT_PROJECTION_DEPTH],
        depth: usize,
    ) -> Result<TraitProjectionSolution, TraitGoalError> {
        let canonical = canonicalize_implemented_trait_goal(projection.goal)?;
        let exact = self.exact_implementations.solve(canonical);
        let generic = self.generic_implementations.select(projection.goal)?;
        let answer = match (exact, generic) {
            (TraitGoalSolution::Unique(_), GenericTraitImplementationSolution::NoSolution) => {
                return Ok(self.exact_values.normalize(
                    self.exact_implementations,
                    canonical,
                    projection.associated_type_id,
                ));
            }
            (TraitGoalSolution::NoSolution, GenericTraitImplementationSolution::Unique(answer)) => {
                answer
            }
            (TraitGoalSolution::NoSolution, GenericTraitImplementationSolution::NoSolution) => {
                return Ok(TraitProjectionSolution::NoSolution);
            }
            (TraitGoalSolution::Unique(_), _)
            | (TraitGoalSolution::Ambiguous, _)
            | (_, GenericTraitImplementationSolution::Ambiguous) => {
                return Ok(TraitProjectionSolution::Ambiguous);
            }
        };
        match solve_concrete_trait_goal_with_generics(
            self.exact_implementations,
            self.generic_implementations,
            self.clauses,
            projection.goal,
        )? {
            TraitProofSolution::Proven => {}
            TraitProofSolution::Ambiguous => return Ok(TraitProjectionSolution::Ambiguous),
            TraitProofSolution::NoSolution => return Ok(TraitProjectionSolution::NoSolution),
            TraitProofSolution::Cycle => return Ok(TraitProjectionSolution::Cycle),
            TraitProofSolution::Overflow => return Ok(TraitProjectionSolution::Overflow),
        }
        let Some(value) = self.generic_values.values[..self.generic_values.value_count]
            .iter()
            .flatten()
            .find(|value| {
                value.implementation_id == answer.implementation_id
                    && value.associated_type_id == projection.associated_type_id
            })
        else {
            return Ok(TraitProjectionSolution::NoSolution);
        };
        match value.value {
            GenericTraitAssociatedTypeTerm::Type(value) => Ok(TraitProjectionSolution::Unique(
                instantiate_generic_associated_type(value, answer)?,
            )),
            GenericTraitAssociatedTypeTerm::Projection(nested) => {
                let goal = instantiate_generic_projection_goal(nested.goal, answer)?;
                self.normalize_inner(
                    ConcreteTraitProjectionGoal {
                        goal,
                        associated_type_id: nested.associated_type_id,
                    },
                    stack,
                    depth + 1,
                )
            }
        }
    }

    fn normalize_inferred_inner(
        self,
        projection: ConcreteTraitProjectionGoal,
        state: &mut InferenceConstraintState,
        stack: &mut [Option<ConcreteTraitProjectionGoal>; MAX_TRAIT_PROJECTION_DEPTH],
        depth: usize,
        premise_depth: usize,
    ) -> Result<InferredProjectionValueSolution, TraitGoalError> {
        let projection = ConcreteTraitProjectionGoal {
            goal: state.apply_goal(projection.goal)?,
            associated_type_id: projection.associated_type_id,
        };
        if stack[..depth].contains(&Some(projection)) {
            return Ok(InferredProjectionValueSolution::Cycle);
        }
        if depth >= MAX_TRAIT_PROJECTION_DEPTH {
            return Ok(InferredProjectionValueSolution::Overflow);
        }
        stack[depth] = Some(projection);
        let result =
            self.normalize_inferred_selected(projection, state, stack, depth, premise_depth);
        stack[depth] = None;
        result
    }

    fn normalize_inferred_selected(
        self,
        projection: ConcreteTraitProjectionGoal,
        state: &mut InferenceConstraintState,
        stack: &mut [Option<ConcreteTraitProjectionGoal>; MAX_TRAIT_PROJECTION_DEPTH],
        depth: usize,
        premise_depth: usize,
    ) -> Result<InferredProjectionValueSolution, TraitGoalError> {
        if premise_depth >= MAX_TRAIT_PROJECTION_DEPTH {
            return Ok(InferredProjectionValueSolution::Overflow);
        }
        let mut proof_stack = [None; MAX_TRAIT_PROOF_DEPTH];
        match solve_inferred_trait_goal_inner(
            self.exact_implementations,
            self.generic_implementations,
            self.clauses,
            None,
            None,
            Some(self),
            None,
            premise_depth + 1,
            projection.goal,
            state,
            &mut proof_stack,
            0,
        )? {
            TraitProofSolution::Proven => {}
            TraitProofSolution::Ambiguous => {
                return Ok(InferredProjectionValueSolution::Ambiguous);
            }
            TraitProofSolution::NoSolution => {
                return Ok(InferredProjectionValueSolution::NoSolution);
            }
            TraitProofSolution::Cycle => return Ok(InferredProjectionValueSolution::Cycle),
            TraitProofSolution::Overflow => return Ok(InferredProjectionValueSolution::Overflow),
        }
        let goal = state.apply_goal(projection.goal)?;
        let canonicalized = canonicalize_implemented_trait_goal_with_variables(goal)?;
        let exact = self.exact_implementations.solve(canonicalized.goal);
        let generic = self.generic_implementations.select_existential(goal)?;
        match (exact, generic) {
            (
                TraitGoalSolution::Unique(answer),
                GenericExistentialTraitGoalSolution::NoSolution,
            ) => {
                let Some(value) = self.exact_values.values[..self.exact_values.value_count]
                    .iter()
                    .flatten()
                    .find(|value| {
                        value.implementation_id == answer.implementation_id
                            && value.associated_type_id == projection.associated_type_id
                    })
                else {
                    return Ok(InferredProjectionValueSolution::NoSolution);
                };
                Ok(InferredProjectionValueSolution::Unique(
                    TraitGoalType::Concrete(value.value),
                ))
            }
            (
                TraitGoalSolution::NoSolution,
                GenericExistentialTraitGoalSolution::Unique(answer),
            ) => {
                state.merge_symbolic(answer.substitution)?;
                let Some(value) = self.generic_values.values[..self.generic_values.value_count]
                    .iter()
                    .flatten()
                    .find(|value| {
                        value.implementation_id == answer.implementation_id
                            && value.associated_type_id == projection.associated_type_id
                    })
                else {
                    return Ok(InferredProjectionValueSolution::NoSolution);
                };
                match value.value {
                    GenericTraitAssociatedTypeTerm::Type(value) => {
                        Ok(InferredProjectionValueSolution::Unique(state.apply_type(
                            instantiate_bound_type(value, answer.arguments())?,
                        )?))
                    }
                    GenericTraitAssociatedTypeTerm::Projection(nested) => {
                        let goal = instantiate_bound_goal(nested.goal, answer.arguments())?;
                        self.normalize_inferred_inner(
                            ConcreteTraitProjectionGoal {
                                goal,
                                associated_type_id: nested.associated_type_id,
                            },
                            state,
                            stack,
                            depth + 1,
                            premise_depth,
                        )
                    }
                }
            }
            (TraitGoalSolution::NoSolution, GenericExistentialTraitGoalSolution::NoSolution) => {
                Ok(InferredProjectionValueSolution::NoSolution)
            }
            (TraitGoalSolution::Unique(_), _)
            | (TraitGoalSolution::Ambiguous, _)
            | (_, GenericExistentialTraitGoalSolution::Ambiguous) => {
                Ok(InferredProjectionValueSolution::Ambiguous)
            }
        }
    }

    fn normalize_goal_term_inner(
        self,
        arena: &TraitGoalTermArena,
        term_id: TraitGoalTermId,
        state: &mut InferenceConstraintState,
        stack: &mut [Option<TraitGoalTermId>; MAX_TRAIT_PROJECTION_DEPTH],
        depth: usize,
    ) -> Result<InferredProjectionValueSolution, TraitGoalError> {
        if stack[..depth].contains(&Some(term_id)) {
            return Ok(InferredProjectionValueSolution::Cycle);
        }
        if depth >= MAX_TRAIT_PROJECTION_DEPTH {
            return Ok(InferredProjectionValueSolution::Overflow);
        }
        let term = arena
            .get(term_id)
            .ok_or(TraitGoalError::InvalidTraitGoalTermReference)?;
        stack[depth] = Some(term_id);
        let result = (|| match term {
            TraitGoalTerm::Type(ty) => Ok(InferredProjectionValueSolution::Unique(
                state.apply_type(ty)?,
            )),
            TraitGoalTerm::Projection {
                goal,
                associated_type_id,
            } => {
                let self_type = match self.normalize_goal_term_inner(
                    arena,
                    goal.self_type,
                    state,
                    stack,
                    depth + 1,
                )? {
                    InferredProjectionValueSolution::Unique(value) => value,
                    other => return Ok(other),
                };
                let mut normalized = ImplementedTraitGoal::new(goal.trait_id, self_type);
                for argument in goal.arguments() {
                    let argument = argument
                        .as_ref()
                        .copied()
                        .ok_or(TraitGoalError::InvalidGoal)?;
                    let argument = match self.normalize_goal_term_inner(
                        arena,
                        argument,
                        state,
                        stack,
                        depth + 1,
                    )? {
                        InferredProjectionValueSolution::Unique(value) => value,
                        other => return Ok(other),
                    };
                    normalized.push_argument(argument)?;
                }
                let mut projection_stack = [None; MAX_TRAIT_PROJECTION_DEPTH];
                self.normalize_inferred_inner(
                    ConcreteTraitProjectionGoal {
                        goal: normalized,
                        associated_type_id,
                    },
                    state,
                    &mut projection_stack,
                    0,
                    0,
                )
            }
        })();
        stack[depth] = None;
        result
    }

    fn normalize_rigid_goal_term_inner(
        self,
        arena: &TraitGoalTermArena,
        term_id: TraitGoalTermId,
        term_stack: &mut [Option<TraitGoalTermId>; MAX_TRAIT_PROJECTION_DEPTH],
        term_depth: usize,
        proof_stack: &mut [Option<ImplementedTraitGoal>; MAX_TRAIT_PROOF_DEPTH],
        proof_depth: usize,
    ) -> Result<InferredProjectionValueSolution, TraitGoalError> {
        if term_stack[..term_depth].contains(&Some(term_id)) {
            return Ok(InferredProjectionValueSolution::Cycle);
        }
        if term_depth >= MAX_TRAIT_PROJECTION_DEPTH {
            return Ok(InferredProjectionValueSolution::Overflow);
        }
        let term = arena
            .get(term_id)
            .ok_or(TraitGoalError::InvalidTraitGoalTermReference)?;
        term_stack[term_depth] = Some(term_id);
        let result = (|| match term {
            TraitGoalTerm::Type(ty) => {
                rigid_goal_type(ty)?;
                Ok(InferredProjectionValueSolution::Unique(ty))
            }
            TraitGoalTerm::Projection {
                goal,
                associated_type_id,
            } => {
                let self_type = match self.normalize_rigid_goal_term_inner(
                    arena,
                    goal.self_type,
                    term_stack,
                    term_depth + 1,
                    proof_stack,
                    proof_depth,
                )? {
                    InferredProjectionValueSolution::Unique(value) => value,
                    other => return Ok(other),
                };
                let mut normalized = ImplementedTraitGoal::new(goal.trait_id, self_type);
                for argument in goal.arguments() {
                    let argument = argument
                        .as_ref()
                        .copied()
                        .ok_or(TraitGoalError::InvalidGoal)?;
                    let argument = match self.normalize_rigid_goal_term_inner(
                        arena,
                        argument,
                        term_stack,
                        term_depth + 1,
                        proof_stack,
                        proof_depth,
                    )? {
                        InferredProjectionValueSolution::Unique(value) => value,
                        other => return Ok(other),
                    };
                    normalized.push_argument(argument)?;
                }
                let mut projection_stack = [None; MAX_TRAIT_PROJECTION_DEPTH];
                self.normalize_rigid_inner(
                    ConcreteTraitProjectionGoal {
                        goal: normalized,
                        associated_type_id,
                    },
                    &mut projection_stack,
                    0,
                    proof_stack,
                    proof_depth,
                )
            }
        })();
        term_stack[term_depth] = None;
        result
    }

    fn normalize_rigid_projection_bearing_goal(
        self,
        arena: &TraitGoalTermArena,
        goal: ProjectionBearingTraitGoal,
        proof_stack: &mut [Option<ImplementedTraitGoal>; MAX_TRAIT_PROOF_DEPTH],
    ) -> Result<ProjectionBearingGoalNormalizationSolution, TraitGoalError> {
        validate_projection_bearing_goal(goal, arena.term_count)?;
        let mut term_stack = [None; MAX_TRAIT_PROJECTION_DEPTH];
        let self_type = match self.normalize_rigid_goal_term_inner(
            arena,
            goal.self_type,
            &mut term_stack,
            0,
            proof_stack,
            0,
        )? {
            InferredProjectionValueSolution::Unique(value) => value,
            InferredProjectionValueSolution::Ambiguous => {
                return Ok(ProjectionBearingGoalNormalizationSolution::Ambiguous);
            }
            InferredProjectionValueSolution::NoSolution => {
                return Ok(ProjectionBearingGoalNormalizationSolution::NoSolution);
            }
            InferredProjectionValueSolution::Cycle => {
                return Ok(ProjectionBearingGoalNormalizationSolution::Cycle);
            }
            InferredProjectionValueSolution::Overflow => {
                return Ok(ProjectionBearingGoalNormalizationSolution::Overflow);
            }
        };
        let mut normalized = ImplementedTraitGoal::new(goal.trait_id, self_type);
        for argument in goal.arguments() {
            let mut term_stack = [None; MAX_TRAIT_PROJECTION_DEPTH];
            let argument = match self.normalize_rigid_goal_term_inner(
                arena,
                argument
                    .as_ref()
                    .copied()
                    .ok_or(TraitGoalError::InvalidGoal)?,
                &mut term_stack,
                0,
                proof_stack,
                0,
            )? {
                InferredProjectionValueSolution::Unique(value) => value,
                InferredProjectionValueSolution::Ambiguous => {
                    return Ok(ProjectionBearingGoalNormalizationSolution::Ambiguous);
                }
                InferredProjectionValueSolution::NoSolution => {
                    return Ok(ProjectionBearingGoalNormalizationSolution::NoSolution);
                }
                InferredProjectionValueSolution::Cycle => {
                    return Ok(ProjectionBearingGoalNormalizationSolution::Cycle);
                }
                InferredProjectionValueSolution::Overflow => {
                    return Ok(ProjectionBearingGoalNormalizationSolution::Overflow);
                }
            };
            normalized.push_argument(argument)?;
        }
        Ok(ProjectionBearingGoalNormalizationSolution::Unique(
            normalized,
        ))
    }

    fn normalize_projection_bearing_goal(
        self,
        arena: &TraitGoalTermArena,
        goal: ProjectionBearingTraitGoal,
        state: &mut InferenceConstraintState,
    ) -> Result<ProjectionBearingGoalNormalizationSolution, TraitGoalError> {
        validate_projection_bearing_goal(goal, arena.term_count)?;
        let mut stack = [None; MAX_TRAIT_PROJECTION_DEPTH];
        let self_type =
            match self.normalize_goal_term_inner(arena, goal.self_type, state, &mut stack, 0)? {
                InferredProjectionValueSolution::Unique(value) => value,
                InferredProjectionValueSolution::Ambiguous => {
                    return Ok(ProjectionBearingGoalNormalizationSolution::Ambiguous);
                }
                InferredProjectionValueSolution::NoSolution => {
                    return Ok(ProjectionBearingGoalNormalizationSolution::NoSolution);
                }
                InferredProjectionValueSolution::Cycle => {
                    return Ok(ProjectionBearingGoalNormalizationSolution::Cycle);
                }
                InferredProjectionValueSolution::Overflow => {
                    return Ok(ProjectionBearingGoalNormalizationSolution::Overflow);
                }
            };
        let mut normalized = ImplementedTraitGoal::new(goal.trait_id, self_type);
        for argument in goal.arguments() {
            let mut stack = [None; MAX_TRAIT_PROJECTION_DEPTH];
            let argument = match self.normalize_goal_term_inner(
                arena,
                argument
                    .as_ref()
                    .copied()
                    .ok_or(TraitGoalError::InvalidGoal)?,
                state,
                &mut stack,
                0,
            )? {
                InferredProjectionValueSolution::Unique(value) => value,
                InferredProjectionValueSolution::Ambiguous => {
                    return Ok(ProjectionBearingGoalNormalizationSolution::Ambiguous);
                }
                InferredProjectionValueSolution::NoSolution => {
                    return Ok(ProjectionBearingGoalNormalizationSolution::NoSolution);
                }
                InferredProjectionValueSolution::Cycle => {
                    return Ok(ProjectionBearingGoalNormalizationSolution::Cycle);
                }
                InferredProjectionValueSolution::Overflow => {
                    return Ok(ProjectionBearingGoalNormalizationSolution::Overflow);
                }
            };
            normalized.push_argument(argument)?;
        }
        Ok(ProjectionBearingGoalNormalizationSolution::Unique(
            normalized,
        ))
    }
}

fn instantiate_generic_associated_type(
    value: BoundTraitGoalType,
    answer: GenericTraitImplementationAnswer,
) -> Result<TraitTypeId, TraitGoalError> {
    match value {
        BoundTraitGoalType::Concrete(value) => Ok(value),
        BoundTraitGoalType::Parameter(parameter) => answer
            .arguments()
            .get(parameter.get() as usize)
            .and_then(Option::as_ref)
            .copied()
            .ok_or(TraitGoalError::UnboundGenericParameter)
            .and_then(concrete_goal_type),
    }
}

fn instantiate_generic_associated_type_rigid(
    value: BoundTraitGoalType,
    answer: GenericTraitImplementationAnswer,
) -> Result<TraitGoalType, TraitGoalError> {
    match value {
        BoundTraitGoalType::Concrete(value) => Ok(TraitGoalType::Concrete(value)),
        BoundTraitGoalType::Parameter(parameter) => answer
            .arguments()
            .get(parameter.get() as usize)
            .and_then(Option::as_ref)
            .copied()
            .ok_or(TraitGoalError::UnboundGenericParameter)
            .and_then(rigid_goal_type),
    }
}

fn instantiate_generic_projection_goal(
    goal: BoundImplementedTraitGoal,
    answer: GenericTraitImplementationAnswer,
) -> Result<ImplementedTraitGoal, TraitGoalError> {
    let mut arguments =
        [TraitGoalType::Concrete(TraitTypeId::new(0)); MAX_TRAIT_GENERIC_PARAMETERS];
    for (index, argument) in answer.arguments().iter().enumerate() {
        arguments[index] = argument
            .as_ref()
            .copied()
            .ok_or(TraitGoalError::UnboundGenericParameter)?;
    }
    instantiate_bound_goal(goal, &arguments[..answer.argument_count])
}

pub fn normalize_concrete_trait_projection(
    exact_implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    exact_values: &TraitAssociatedTypeDatabase,
    generic_values: &GenericTraitAssociatedTypeDatabase,
    goal: ImplementedTraitGoal,
    associated_type_id: TraitAssociatedTypeId,
) -> Result<TraitProjectionSolution, TraitGoalError> {
    let environment = TraitProjectionEnvironment {
        exact_implementations,
        generic_implementations,
        clauses,
        exact_values,
        generic_values,
    };
    let mut stack = [None; MAX_TRAIT_PROJECTION_DEPTH];
    environment.normalize_inner(
        ConcreteTraitProjectionGoal {
            goal,
            associated_type_id,
        },
        &mut stack,
        0,
    )
}

pub fn normalize_inferred_trait_goal_term(
    exact_implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    exact_values: &TraitAssociatedTypeDatabase,
    generic_values: &GenericTraitAssociatedTypeDatabase,
    arena: &TraitGoalTermArena,
    term_id: TraitGoalTermId,
) -> Result<TraitGoalTermNormalizationSolution, TraitGoalError> {
    let mut state = InferenceConstraintState::from_term_arena(arena)?;
    let environment = TraitProjectionEnvironment {
        exact_implementations,
        generic_implementations,
        clauses,
        exact_values,
        generic_values,
    };
    let mut stack = [None; MAX_TRAIT_PROJECTION_DEPTH];
    match environment.normalize_goal_term_inner(arena, term_id, &mut state, &mut stack, 0)? {
        InferredProjectionValueSolution::Unique(value) => Ok(
            TraitGoalTermNormalizationSolution::Unique(TraitGoalTermNormalizationAnswer {
                value: state.apply_type(value)?,
                substitution: state.substitution()?,
            }),
        ),
        InferredProjectionValueSolution::Ambiguous => {
            Ok(TraitGoalTermNormalizationSolution::Ambiguous)
        }
        InferredProjectionValueSolution::NoSolution => {
            Ok(TraitGoalTermNormalizationSolution::NoSolution)
        }
        InferredProjectionValueSolution::Cycle => Ok(TraitGoalTermNormalizationSolution::Cycle),
        InferredProjectionValueSolution::Overflow => {
            Ok(TraitGoalTermNormalizationSolution::Overflow)
        }
    }
}

pub fn solve_projection_bearing_trait_goal(
    exact_implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    exact_values: &TraitAssociatedTypeDatabase,
    generic_values: &GenericTraitAssociatedTypeDatabase,
    arena: &TraitGoalTermArena,
    goal: ProjectionBearingTraitGoal,
) -> Result<InferredTraitGoalSolution, TraitGoalError> {
    let mut state = InferenceConstraintState::from_term_arena(arena)?;
    let environment = TraitProjectionEnvironment {
        exact_implementations,
        generic_implementations,
        clauses,
        exact_values,
        generic_values,
    };
    let goal = match environment.normalize_projection_bearing_goal(arena, goal, &mut state)? {
        ProjectionBearingGoalNormalizationSolution::Unique(goal) => goal,
        ProjectionBearingGoalNormalizationSolution::Ambiguous => {
            return Ok(InferredTraitGoalSolution::Ambiguous);
        }
        ProjectionBearingGoalNormalizationSolution::NoSolution => {
            return Ok(InferredTraitGoalSolution::NoSolution);
        }
        ProjectionBearingGoalNormalizationSolution::Cycle => {
            return Ok(InferredTraitGoalSolution::Cycle);
        }
        ProjectionBearingGoalNormalizationSolution::Overflow => {
            return Ok(InferredTraitGoalSolution::Overflow);
        }
    };
    let mut stack = [None; MAX_TRAIT_PROOF_DEPTH];
    match solve_inferred_trait_goal_inner(
        exact_implementations,
        generic_implementations,
        clauses,
        None,
        None,
        Some(environment),
        None,
        0,
        goal,
        &mut state,
        &mut stack,
        0,
    )? {
        TraitProofSolution::Proven => {
            Ok(InferredTraitGoalSolution::Unique(InferredTraitGoalAnswer {
                substitution: state.substitution()?,
            }))
        }
        TraitProofSolution::Ambiguous => Ok(InferredTraitGoalSolution::Ambiguous),
        TraitProofSolution::NoSolution => Ok(InferredTraitGoalSolution::NoSolution),
        TraitProofSolution::Cycle => Ok(InferredTraitGoalSolution::Cycle),
        TraitProofSolution::Overflow => Ok(InferredTraitGoalSolution::Overflow),
    }
}

pub fn solve_exists_projection_bearing_trait_goal(
    exact_implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    exact_values: &TraitAssociatedTypeDatabase,
    generic_values: &GenericTraitAssociatedTypeDatabase,
    universe: TraitUniverseIndex,
    goal: ExistsProjectionBearingTraitGoal,
) -> Result<InferredTraitGoalSolution, TraitGoalError> {
    let instantiated = goal.instantiate_in_universe(universe)?;
    solve_projection_bearing_trait_goal(
        exact_implementations,
        generic_implementations,
        clauses,
        exact_values,
        generic_values,
        &instantiated.arena,
        instantiated.goal,
    )
}

pub fn solve_for_all_projection_bearing_trait_goal(
    exact_implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    exact_values: &TraitAssociatedTypeDatabase,
    generic_values: &GenericTraitAssociatedTypeDatabase,
    parent_universe: TraitUniverseIndex,
    goal: ForAllProjectionBearingTraitGoal,
) -> Result<TraitProofSolution, TraitGoalError> {
    let universe = parent_universe.next()?;
    let instantiated = goal.instantiate_in_universe(universe)?;
    let environment = TraitProjectionEnvironment {
        exact_implementations,
        generic_implementations,
        clauses,
        exact_values,
        generic_values,
    };
    let mut stack = [None; MAX_TRAIT_PROOF_DEPTH];
    let goal = match environment.normalize_rigid_projection_bearing_goal(
        &instantiated.arena,
        instantiated.goal,
        &mut stack,
    )? {
        ProjectionBearingGoalNormalizationSolution::Unique(goal) => goal,
        ProjectionBearingGoalNormalizationSolution::Ambiguous => {
            return Ok(TraitProofSolution::Ambiguous);
        }
        ProjectionBearingGoalNormalizationSolution::NoSolution => {
            return Ok(TraitProofSolution::NoSolution);
        }
        ProjectionBearingGoalNormalizationSolution::Cycle => {
            return Ok(TraitProofSolution::Cycle);
        }
        ProjectionBearingGoalNormalizationSolution::Overflow => {
            return Ok(TraitProofSolution::Overflow);
        }
    };
    solve_rigid_trait_goal_with_generics_inner(
        exact_implementations,
        generic_implementations,
        clauses,
        Some(environment),
        None,
        goal,
        &mut stack,
        0,
    )
}

pub fn solve_for_all_trait_projection_equality(
    exact_implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    exact_values: &TraitAssociatedTypeDatabase,
    generic_values: &GenericTraitAssociatedTypeDatabase,
    parent_universe: TraitUniverseIndex,
    query: ForAllTraitProjectionEquality,
) -> Result<TraitProofSolution, TraitGoalError> {
    let universe = parent_universe.next()?;
    let query = query.instantiate_in_universe(universe)?;
    validate_rigid_goal(query.goal)?;
    rigid_goal_type(query.expected)?;
    let environment = TraitProjectionEnvironment {
        exact_implementations,
        generic_implementations,
        clauses,
        exact_values,
        generic_values,
    };
    let mut projection_stack = [None; MAX_TRAIT_PROJECTION_DEPTH];
    let mut proof_stack = [None; MAX_TRAIT_PROOF_DEPTH];
    match environment.normalize_rigid_inner(
        ConcreteTraitProjectionGoal {
            goal: query.goal,
            associated_type_id: query.associated_type_id,
        },
        &mut projection_stack,
        0,
        &mut proof_stack,
        0,
    )? {
        InferredProjectionValueSolution::Unique(actual) if actual == query.expected => {
            Ok(TraitProofSolution::Proven)
        }
        InferredProjectionValueSolution::Unique(_)
        | InferredProjectionValueSolution::NoSolution => Ok(TraitProofSolution::NoSolution),
        InferredProjectionValueSolution::Ambiguous => Ok(TraitProofSolution::Ambiguous),
        InferredProjectionValueSolution::Cycle => Ok(TraitProofSolution::Cycle),
        InferredProjectionValueSolution::Overflow => Ok(TraitProofSolution::Overflow),
    }
}

pub fn solve_exists_trait_projection_equality(
    exact_implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    exact_values: &TraitAssociatedTypeDatabase,
    generic_values: &GenericTraitAssociatedTypeDatabase,
    universe: TraitUniverseIndex,
    query: ExistsTraitProjectionEquality,
) -> Result<InferredTraitProjectionSolution, TraitGoalError> {
    let variable_count = query.parameter_count();
    let query = query.instantiate_in_universe(universe)?;
    let mut state = InferenceConstraintState::from_universe(universe, variable_count)?;
    let environment = TraitProjectionEnvironment {
        exact_implementations,
        generic_implementations,
        clauses,
        exact_values,
        generic_values,
    };
    let mut stack = [None; MAX_TRAIT_PROJECTION_DEPTH];
    match environment.normalize_inferred_inner(
        ConcreteTraitProjectionGoal {
            goal: query.goal,
            associated_type_id: query.associated_type_id,
        },
        &mut state,
        &mut stack,
        0,
        0,
    )? {
        InferredProjectionValueSolution::Unique(value) => {
            if !state.unify_types(value, query.expected)? {
                return Ok(InferredTraitProjectionSolution::NoSolution);
            }
            Ok(InferredTraitProjectionSolution::Unique(
                InferredTraitProjectionAnswer {
                    substitution: state.substitution()?,
                },
            ))
        }
        InferredProjectionValueSolution::Ambiguous => {
            Ok(InferredTraitProjectionSolution::Ambiguous)
        }
        InferredProjectionValueSolution::NoSolution => {
            Ok(InferredTraitProjectionSolution::NoSolution)
        }
        InferredProjectionValueSolution::Cycle => Ok(InferredTraitProjectionSolution::Cycle),
        InferredProjectionValueSolution::Overflow => Ok(InferredTraitProjectionSolution::Overflow),
    }
}

fn solve_inferred_trait_predicate_with_stack(
    environment: Option<TraitProjectionEnvironment<'_>>,
    coinductive_traits: Option<&CoinductiveTraitDatabase>,
    premise_depth: usize,
    exact: &TraitImplementationDatabase,
    generic: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    projection_clauses: Option<&ProjectionBearingTraitClauseDatabase>,
    projection_implementations: Option<&ProjectionBearingGenericTraitImplementationDatabase>,
    predicate: InferredTraitPredicate,
    state: &mut InferenceConstraintState,
    proof_stack: &mut [Option<ImplementedTraitGoal>; MAX_TRAIT_PROOF_DEPTH],
    proof_depth: usize,
) -> Result<TraitProofSolution, TraitGoalError> {
    match predicate {
        InferredTraitPredicate::Implemented(goal) => solve_inferred_trait_goal_inner(
            exact,
            generic,
            clauses,
            projection_clauses,
            projection_implementations,
            environment,
            coinductive_traits,
            premise_depth,
            goal,
            state,
            proof_stack,
            proof_depth,
        ),
        InferredTraitPredicate::ProjectionEquality(projection) => {
            let Some(environment) = environment else {
                return Ok(TraitProofSolution::NoSolution);
            };
            let mut stack = [None; MAX_TRAIT_PROJECTION_DEPTH];
            match environment.normalize_inferred_inner(
                ConcreteTraitProjectionGoal {
                    goal: projection.goal,
                    associated_type_id: projection.associated_type_id,
                },
                state,
                &mut stack,
                0,
                premise_depth,
            )? {
                InferredProjectionValueSolution::Unique(value) => {
                    if state.unify_types(value, projection.expected)? {
                        Ok(TraitProofSolution::Proven)
                    } else {
                        Ok(TraitProofSolution::NoSolution)
                    }
                }
                InferredProjectionValueSolution::Ambiguous => Ok(TraitProofSolution::Ambiguous),
                InferredProjectionValueSolution::NoSolution => Ok(TraitProofSolution::NoSolution),
                InferredProjectionValueSolution::Cycle => Ok(TraitProofSolution::Cycle),
                InferredProjectionValueSolution::Overflow => Ok(TraitProofSolution::Overflow),
            }
        }
    }
}

pub fn solve_exists_trait_predicate_conjunction(
    exact_implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    exact_values: &TraitAssociatedTypeDatabase,
    generic_values: &GenericTraitAssociatedTypeDatabase,
    universe: TraitUniverseIndex,
    query: ExistsTraitPredicateConjunction,
) -> Result<InferredTraitGoalSolution, TraitGoalError> {
    let mut state = InferenceConstraintState::from_universe(universe, query.parameter_count())?;
    let environment = TraitProjectionEnvironment {
        exact_implementations,
        generic_implementations,
        clauses,
        exact_values,
        generic_values,
    };
    let mut pending = [None; MAX_TRAIT_PREDICATES];
    let mut pending_count = 0usize;
    for predicate in query.predicates() {
        pending[pending_count] = Some(
            query.instantiate_predicate(
                predicate
                    .as_ref()
                    .copied()
                    .ok_or(TraitGoalError::InvalidGoal)?,
                universe,
            )?,
        );
        pending_count += 1;
    }

    while pending_count != 0 {
        let mut next = [None; MAX_TRAIT_PREDICATES];
        let mut next_count = 0usize;
        let mut proven_count = 0usize;
        for predicate in pending[..pending_count].iter().copied() {
            let predicate = predicate.ok_or(TraitGoalError::InvalidGoal)?;
            let saved = state;
            let mut proof_stack = [None; MAX_TRAIT_PROOF_DEPTH];
            match solve_inferred_trait_predicate_with_stack(
                Some(environment),
                None,
                0,
                exact_implementations,
                generic_implementations,
                clauses,
                None,
                None,
                predicate,
                &mut state,
                &mut proof_stack,
                0,
            )? {
                TraitProofSolution::Proven => proven_count += 1,
                TraitProofSolution::Ambiguous => {
                    state = saved;
                    next[next_count] = Some(predicate);
                    next_count += 1;
                }
                TraitProofSolution::NoSolution => {
                    return Ok(InferredTraitGoalSolution::NoSolution);
                }
                TraitProofSolution::Cycle => return Ok(InferredTraitGoalSolution::Cycle),
                TraitProofSolution::Overflow => return Ok(InferredTraitGoalSolution::Overflow),
            }
        }
        if proven_count == 0 {
            return Ok(InferredTraitGoalSolution::Ambiguous);
        }
        pending = next;
        pending_count = next_count;
    }

    Ok(InferredTraitGoalSolution::Unique(InferredTraitGoalAnswer {
        substitution: state.substitution()?,
    }))
}

fn solve_rigid_trait_predicate(
    exact_implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    environment: TraitProjectionEnvironment<'_>,
    coinductive_traits: Option<&CoinductiveTraitDatabase>,
    predicate: InferredTraitPredicate,
) -> Result<TraitProofSolution, TraitGoalError> {
    let mut proof_stack = [None; MAX_TRAIT_PROOF_DEPTH];
    match predicate {
        InferredTraitPredicate::Implemented(goal) => solve_rigid_trait_goal_with_generics_inner(
            exact_implementations,
            generic_implementations,
            clauses,
            Some(environment),
            coinductive_traits,
            goal,
            &mut proof_stack,
            0,
        ),
        InferredTraitPredicate::ProjectionEquality(projection) => {
            validate_rigid_goal(projection.goal)?;
            rigid_goal_type(projection.expected)?;
            let mut projection_stack = [None; MAX_TRAIT_PROJECTION_DEPTH];
            match environment.normalize_rigid_inner(
                ConcreteTraitProjectionGoal {
                    goal: projection.goal,
                    associated_type_id: projection.associated_type_id,
                },
                &mut projection_stack,
                0,
                &mut proof_stack,
                0,
            )? {
                InferredProjectionValueSolution::Unique(actual)
                    if actual == projection.expected =>
                {
                    Ok(TraitProofSolution::Proven)
                }
                InferredProjectionValueSolution::Unique(_)
                | InferredProjectionValueSolution::NoSolution => Ok(TraitProofSolution::NoSolution),
                InferredProjectionValueSolution::Ambiguous => Ok(TraitProofSolution::Ambiguous),
                InferredProjectionValueSolution::Cycle => Ok(TraitProofSolution::Cycle),
                InferredProjectionValueSolution::Overflow => Ok(TraitProofSolution::Overflow),
            }
        }
    }
}

pub fn solve_for_all_trait_predicate_conjunction(
    exact_implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    exact_values: &TraitAssociatedTypeDatabase,
    generic_values: &GenericTraitAssociatedTypeDatabase,
    parent_universe: TraitUniverseIndex,
    query: ForAllTraitPredicateConjunction,
) -> Result<TraitProofSolution, TraitGoalError> {
    let universe = parent_universe.next()?;
    let environment = TraitProjectionEnvironment {
        exact_implementations,
        generic_implementations,
        clauses,
        exact_values,
        generic_values,
    };
    for predicate in query.predicates() {
        let predicate = query.instantiate_predicate(
            predicate
                .as_ref()
                .copied()
                .ok_or(TraitGoalError::InvalidGoal)?,
            universe,
        )?;
        let result = solve_rigid_trait_predicate(
            exact_implementations,
            generic_implementations,
            clauses,
            environment,
            None,
            predicate,
        )?;
        if result != TraitProofSolution::Proven {
            return Ok(result);
        }
    }
    Ok(TraitProofSolution::Proven)
}

pub fn solve_nested_for_all_trait_predicate_conjunction(
    exact_implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    exact_values: &TraitAssociatedTypeDatabase,
    generic_values: &GenericTraitAssociatedTypeDatabase,
    parent_universe: TraitUniverseIndex,
    query: NestedForAllTraitPredicateConjunction,
) -> Result<TraitProofSolution, TraitGoalError> {
    solve_nested_for_all_trait_predicate_conjunction_inner(
        exact_implementations,
        generic_implementations,
        clauses,
        exact_values,
        generic_values,
        None,
        parent_universe,
        query,
    )
}

pub fn solve_nested_for_all_trait_predicate_conjunction_with_coinduction(
    exact_implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    exact_values: &TraitAssociatedTypeDatabase,
    generic_values: &GenericTraitAssociatedTypeDatabase,
    coinductive_traits: &CoinductiveTraitDatabase,
    parent_universe: TraitUniverseIndex,
    query: NestedForAllTraitPredicateConjunction,
) -> Result<TraitProofSolution, TraitGoalError> {
    solve_nested_for_all_trait_predicate_conjunction_inner(
        exact_implementations,
        generic_implementations,
        clauses,
        exact_values,
        generic_values,
        Some(coinductive_traits),
        parent_universe,
        query,
    )
}

fn solve_nested_for_all_trait_predicate_conjunction_inner(
    exact_implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    exact_values: &TraitAssociatedTypeDatabase,
    generic_values: &GenericTraitAssociatedTypeDatabase,
    coinductive_traits: Option<&CoinductiveTraitDatabase>,
    parent_universe: TraitUniverseIndex,
    query: NestedForAllTraitPredicateConjunction,
) -> Result<TraitProofSolution, TraitGoalError> {
    let (arguments, argument_count) = query.instantiate_arguments(parent_universe)?;
    let environment = TraitProjectionEnvironment {
        exact_implementations,
        generic_implementations,
        clauses,
        exact_values,
        generic_values,
    };
    for predicate in query.predicates() {
        let predicate = query.instantiate_predicate(
            predicate
                .as_ref()
                .copied()
                .ok_or(TraitGoalError::InvalidGoal)?,
            &arguments[..argument_count],
        )?;
        let result = solve_rigid_trait_predicate(
            exact_implementations,
            generic_implementations,
            clauses,
            environment,
            coinductive_traits,
            predicate,
        )?;
        if result != TraitProofSolution::Proven {
            return Ok(result);
        }
    }
    Ok(TraitProofSolution::Proven)
}

pub fn solve_for_all_trait_predicate_branch_forest_with_coinduction(
    exact_implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    exact_values: &TraitAssociatedTypeDatabase,
    generic_values: &GenericTraitAssociatedTypeDatabase,
    coinductive_traits: &CoinductiveTraitDatabase,
    parent_universe: TraitUniverseIndex,
    forest: ForAllTraitPredicateBranchForest,
) -> Result<TraitProofSolution, TraitGoalError> {
    let mut branch_parent = parent_universe;
    for branch in forest.branches() {
        let branch = branch
            .as_ref()
            .copied()
            .ok_or(TraitGoalError::InvalidGoal)?;
        let result = solve_nested_for_all_trait_predicate_conjunction_with_coinduction(
            exact_implementations,
            generic_implementations,
            clauses,
            exact_values,
            generic_values,
            coinductive_traits,
            branch_parent,
            branch,
        )?;
        if result != TraitProofSolution::Proven {
            return Ok(result);
        }
        branch_parent = branch.advance_universe(branch_parent)?;
    }
    Ok(TraitProofSolution::Proven)
}

pub fn solve_for_all_trait_predicate_branch_forest(
    exact_implementations: &TraitImplementationDatabase,
    generic_implementations: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    exact_values: &TraitAssociatedTypeDatabase,
    generic_values: &GenericTraitAssociatedTypeDatabase,
    parent_universe: TraitUniverseIndex,
    forest: ForAllTraitPredicateBranchForest,
) -> Result<TraitProofSolution, TraitGoalError> {
    let mut branch_parent = parent_universe;
    for branch in forest.branches() {
        let branch = branch
            .as_ref()
            .copied()
            .ok_or(TraitGoalError::InvalidGoal)?;
        let result = solve_nested_for_all_trait_predicate_conjunction(
            exact_implementations,
            generic_implementations,
            clauses,
            exact_values,
            generic_values,
            branch_parent,
            branch,
        )?;
        if result != TraitProofSolution::Proven {
            return Ok(result);
        }
        branch_parent = branch.advance_universe(branch_parent)?;
    }
    Ok(TraitProofSolution::Proven)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraitImplementationHeader {
    pub id: TraitImplementationId,
    pub trait_id: TraitId,
    pub self_type: TraitTypeId,
    arguments: [Option<TraitTypeId>; MAX_TRAIT_GOAL_ARGUMENTS],
    argument_count: usize,
}

impl TraitImplementationHeader {
    pub const fn new(id: TraitImplementationId, trait_id: TraitId, self_type: TraitTypeId) -> Self {
        Self {
            id,
            trait_id,
            self_type,
            arguments: [None; MAX_TRAIT_GOAL_ARGUMENTS],
            argument_count: 0,
        }
    }

    pub fn push_argument(&mut self, argument: TraitTypeId) -> Result<(), TraitGoalError> {
        let slot = self
            .arguments
            .get_mut(self.argument_count)
            .ok_or(TraitGoalError::TooManyArguments)?;
        *slot = Some(argument);
        self.argument_count += 1;
        Ok(())
    }

    pub fn arguments(&self) -> &[Option<TraitTypeId>] {
        &self.arguments[..self.argument_count]
    }

    fn head_matches(self, other: Self) -> bool {
        self.trait_id == other.trait_id
            && self.self_type == other.self_type
            && self.arguments() == other.arguments()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraitGoalAnswer {
    pub implementation_id: TraitImplementationId,
    bindings: [Option<TraitTypeId>; MAX_CANONICAL_TRAIT_VARIABLES],
    binding_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraitInferenceBinding {
    pub variable: TraitInferenceVariableId,
    pub concrete_type: TraitTypeId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraitGoalSubstitution {
    bindings: [Option<TraitInferenceBinding>; MAX_CANONICAL_TRAIT_VARIABLES],
    binding_count: usize,
}

impl TraitGoalSubstitution {
    pub fn bindings(&self) -> &[Option<TraitInferenceBinding>] {
        &self.bindings[..self.binding_count]
    }

    pub fn binding(&self, variable: TraitInferenceVariableId) -> Option<TraitTypeId> {
        self.bindings()
            .iter()
            .flatten()
            .find(|binding| binding.variable == variable)
            .map(|binding| binding.concrete_type)
    }
}

impl TraitGoalAnswer {
    pub fn bindings(&self) -> &[Option<TraitTypeId>] {
        &self.bindings[..self.binding_count]
    }

    pub fn binding(&self, variable: u8) -> Option<TraitTypeId> {
        self.bindings().get(variable as usize).copied().flatten()
    }

    pub fn substitute(
        &self,
        canonicalized: CanonicalizedImplementedTraitGoal,
    ) -> Option<TraitGoalSubstitution> {
        if self.binding_count != canonicalized.variable_count {
            return None;
        }
        let mut bindings = [None; MAX_CANONICAL_TRAIT_VARIABLES];
        for (index, variable) in canonicalized.variables().iter().enumerate() {
            bindings[index] = Some(TraitInferenceBinding {
                variable: variable.as_ref().copied()?,
                concrete_type: self.bindings[index]?,
            });
        }
        Some(TraitGoalSubstitution {
            bindings,
            binding_count: self.binding_count,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraitGoalSolution {
    Unique(TraitGoalAnswer),
    Ambiguous,
    NoSolution,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExistentialTraitGoalAnswer {
    pub implementation_id: TraitImplementationId,
    pub substitution: TraitGoalSubstitution,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExistentialTraitGoalSolution {
    Unique(ExistentialTraitGoalAnswer),
    Ambiguous,
    NoSolution,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraitImplementationDatabase {
    implementations: [Option<TraitImplementationHeader>; MAX_TRAIT_IMPLEMENTATIONS],
    implementation_count: usize,
}

impl TraitImplementationDatabase {
    pub const EMPTY: Self = Self {
        implementations: [None; MAX_TRAIT_IMPLEMENTATIONS],
        implementation_count: 0,
    };

    pub fn insert(
        &mut self,
        implementation: TraitImplementationHeader,
    ) -> Result<(), TraitGoalError> {
        if implementation.argument_count > implementation.arguments.len()
            || implementation.arguments[..implementation.argument_count]
                .iter()
                .any(Option::is_none)
            || implementation.arguments[implementation.argument_count..]
                .iter()
                .any(Option::is_some)
        {
            return Err(TraitGoalError::InvalidGoal);
        }
        for existing in self.implementations[..self.implementation_count]
            .iter()
            .flatten()
            .copied()
        {
            if existing.id == implementation.id {
                return Err(TraitGoalError::DuplicateImplementationId);
            }
            if existing.head_matches(implementation) {
                return Err(TraitGoalError::OverlappingImplementation);
            }
        }
        let slot = self
            .implementations
            .get_mut(self.implementation_count)
            .ok_or(TraitGoalError::TooManyImplementations)?;
        *slot = Some(implementation);
        self.implementation_count += 1;
        Ok(())
    }

    pub fn insert_coherent_with_generics(
        &mut self,
        generic: &GenericTraitImplementationDatabase,
        implementation: TraitImplementationHeader,
    ) -> Result<(), TraitGoalError> {
        if generic.implementations[..generic.implementation_count]
            .iter()
            .flatten()
            .copied()
            .any(|candidate| {
                generic_trait_implementation_overlaps_exact(
                    candidate.implementation,
                    implementation,
                )
            })
        {
            return Err(TraitGoalError::OverlappingExactAndGenericImplementation);
        }
        self.insert(implementation)
    }

    pub fn solve(&self, goal: CanonicalImplementedTraitGoal) -> TraitGoalSolution {
        let mut selected = None;
        for implementation in self.implementations[..self.implementation_count]
            .iter()
            .flatten()
            .copied()
        {
            let Some(bindings) = implementation_matches_goal(implementation, goal) else {
                continue;
            };
            if selected.is_some() {
                return TraitGoalSolution::Ambiguous;
            }
            selected = Some(TraitGoalAnswer {
                implementation_id: implementation.id,
                bindings,
                binding_count: goal.variable_count,
            });
        }
        selected.map_or(TraitGoalSolution::NoSolution, TraitGoalSolution::Unique)
    }

    fn contains_id(&self, id: TraitImplementationId) -> bool {
        self.implementations[..self.implementation_count]
            .iter()
            .flatten()
            .any(|implementation| implementation.id == id)
    }
}

pub fn solve_exists_trait_goal_exact(
    implementations: &TraitImplementationDatabase,
    universe: TraitUniverseIndex,
    goal: ExistsImplementedTraitGoal,
) -> Result<ExistentialTraitGoalSolution, TraitGoalError> {
    let instantiated = goal.instantiate_in_universe(universe)?;
    let canonicalized = canonicalize_implemented_trait_goal_with_variables(instantiated)?;
    match implementations.solve(canonicalized.goal) {
        TraitGoalSolution::Unique(answer) => Ok(ExistentialTraitGoalSolution::Unique(
            ExistentialTraitGoalAnswer {
                implementation_id: answer.implementation_id,
                substitution: answer
                    .substitute(canonicalized)
                    .ok_or(TraitGoalError::InvalidGoal)?,
            },
        )),
        TraitGoalSolution::Ambiguous => Ok(ExistentialTraitGoalSolution::Ambiguous),
        TraitGoalSolution::NoSolution => Ok(ExistentialTraitGoalSolution::NoSolution),
    }
}

pub fn solve_exists_trait_goal_generic(
    implementations: &GenericTraitImplementationDatabase,
    universe: TraitUniverseIndex,
    goal: ExistsImplementedTraitGoal,
) -> Result<GenericExistentialTraitGoalSolution, TraitGoalError> {
    implementations.select_existential(goal.instantiate_in_universe(universe)?)
}

pub fn solve_exists_trait_goal_with_generics(
    exact: &TraitImplementationDatabase,
    generic: &GenericTraitImplementationDatabase,
    universe: TraitUniverseIndex,
    goal: ExistsImplementedTraitGoal,
) -> Result<InferredTraitGoalSolution, TraitGoalError> {
    solve_exists_trait_goal_with_environment(
        exact,
        generic,
        &TraitWhereClauseDatabase::EMPTY,
        universe,
        goal,
    )
}

pub fn solve_exists_trait_goal_with_environment(
    exact: &TraitImplementationDatabase,
    generic: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    universe: TraitUniverseIndex,
    goal: ExistsImplementedTraitGoal,
) -> Result<InferredTraitGoalSolution, TraitGoalError> {
    let goal = goal.instantiate_in_universe(universe)?;
    let canonicalized = canonicalize_implemented_trait_goal_with_variables(goal)?;
    let mut state = InferenceConstraintState::new(canonicalized)?;
    let mut stack = [None; MAX_TRAIT_PROOF_DEPTH];
    match solve_inferred_trait_goal_inner(
        exact, generic, clauses, None, None, None, None, 0, goal, &mut state, &mut stack, 0,
    )? {
        TraitProofSolution::Proven => {
            Ok(InferredTraitGoalSolution::Unique(InferredTraitGoalAnswer {
                substitution: state.substitution()?,
            }))
        }
        TraitProofSolution::Ambiguous => Ok(InferredTraitGoalSolution::Ambiguous),
        TraitProofSolution::NoSolution => Ok(InferredTraitGoalSolution::NoSolution),
        TraitProofSolution::Cycle => Ok(InferredTraitGoalSolution::Cycle),
        TraitProofSolution::Overflow => Ok(InferredTraitGoalSolution::Overflow),
    }
}

pub fn solve_exists_trait_goal_with_projection_environment(
    exact: &TraitImplementationDatabase,
    generic: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    exact_values: &TraitAssociatedTypeDatabase,
    generic_values: &GenericTraitAssociatedTypeDatabase,
    universe: TraitUniverseIndex,
    goal: ExistsImplementedTraitGoal,
) -> Result<InferredTraitGoalSolution, TraitGoalError> {
    let goal = goal.instantiate_in_universe(universe)?;
    let canonicalized = canonicalize_implemented_trait_goal_with_variables(goal)?;
    let mut state = InferenceConstraintState::new(canonicalized)?;
    let mut stack = [None; MAX_TRAIT_PROOF_DEPTH];
    let environment = TraitProjectionEnvironment {
        exact_implementations: exact,
        generic_implementations: generic,
        clauses,
        exact_values,
        generic_values,
    };
    match solve_inferred_trait_goal_inner(
        exact,
        generic,
        clauses,
        None,
        None,
        Some(environment),
        None,
        0,
        goal,
        &mut state,
        &mut stack,
        0,
    )? {
        TraitProofSolution::Proven => {
            Ok(InferredTraitGoalSolution::Unique(InferredTraitGoalAnswer {
                substitution: state.substitution()?,
            }))
        }
        TraitProofSolution::Ambiguous => Ok(InferredTraitGoalSolution::Ambiguous),
        TraitProofSolution::NoSolution => Ok(InferredTraitGoalSolution::NoSolution),
        TraitProofSolution::Cycle => Ok(InferredTraitGoalSolution::Cycle),
        TraitProofSolution::Overflow => Ok(InferredTraitGoalSolution::Overflow),
    }
}

pub fn solve_exists_trait_goal_with_coinduction(
    exact: &TraitImplementationDatabase,
    generic: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    coinductive_traits: &CoinductiveTraitDatabase,
    universe: TraitUniverseIndex,
    goal: ExistsImplementedTraitGoal,
) -> Result<InferredTraitGoalSolution, TraitGoalError> {
    let goal = goal.instantiate_in_universe(universe)?;
    let canonicalized = canonicalize_implemented_trait_goal_with_variables(goal)?;
    let mut state = InferenceConstraintState::new(canonicalized)?;
    let mut stack = [None; MAX_TRAIT_PROOF_DEPTH];
    match solve_inferred_trait_goal_inner(
        exact,
        generic,
        clauses,
        None,
        None,
        None,
        Some(coinductive_traits),
        0,
        goal,
        &mut state,
        &mut stack,
        0,
    )? {
        TraitProofSolution::Proven => {
            Ok(InferredTraitGoalSolution::Unique(InferredTraitGoalAnswer {
                substitution: state.substitution()?,
            }))
        }
        TraitProofSolution::Ambiguous => Ok(InferredTraitGoalSolution::Ambiguous),
        TraitProofSolution::NoSolution => Ok(InferredTraitGoalSolution::NoSolution),
        TraitProofSolution::Cycle => Ok(InferredTraitGoalSolution::Cycle),
        TraitProofSolution::Overflow => Ok(InferredTraitGoalSolution::Overflow),
    }
}

pub fn solve_exists_trait_goal_with_coinductive_projection_environment(
    exact: &TraitImplementationDatabase,
    generic: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    exact_values: &TraitAssociatedTypeDatabase,
    generic_values: &GenericTraitAssociatedTypeDatabase,
    coinductive_traits: &CoinductiveTraitDatabase,
    universe: TraitUniverseIndex,
    goal: ExistsImplementedTraitGoal,
) -> Result<InferredTraitGoalSolution, TraitGoalError> {
    let goal = goal.instantiate_in_universe(universe)?;
    let canonicalized = canonicalize_implemented_trait_goal_with_variables(goal)?;
    let mut state = InferenceConstraintState::new(canonicalized)?;
    let mut stack = [None; MAX_TRAIT_PROOF_DEPTH];
    let environment = TraitProjectionEnvironment {
        exact_implementations: exact,
        generic_implementations: generic,
        clauses,
        exact_values,
        generic_values,
    };
    match solve_inferred_trait_goal_inner(
        exact,
        generic,
        clauses,
        None,
        None,
        Some(environment),
        Some(coinductive_traits),
        0,
        goal,
        &mut state,
        &mut stack,
        0,
    )? {
        TraitProofSolution::Proven => {
            Ok(InferredTraitGoalSolution::Unique(InferredTraitGoalAnswer {
                substitution: state.substitution()?,
            }))
        }
        TraitProofSolution::Ambiguous => Ok(InferredTraitGoalSolution::Ambiguous),
        TraitProofSolution::NoSolution => Ok(InferredTraitGoalSolution::NoSolution),
        TraitProofSolution::Cycle => Ok(InferredTraitGoalSolution::Cycle),
        TraitProofSolution::Overflow => Ok(InferredTraitGoalSolution::Overflow),
    }
}

pub fn solve_concrete_trait_goal_with_projection_environment(
    exact: &TraitImplementationDatabase,
    generic: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    exact_values: &TraitAssociatedTypeDatabase,
    generic_values: &GenericTraitAssociatedTypeDatabase,
    goal: ImplementedTraitGoal,
) -> Result<TraitProofSolution, TraitGoalError> {
    validate_concrete_goal(goal)?;
    let canonicalized = canonicalize_implemented_trait_goal_with_variables(goal)?;
    let mut state = InferenceConstraintState::new(canonicalized)?;
    let mut stack = [None; MAX_TRAIT_PROOF_DEPTH];
    let environment = TraitProjectionEnvironment {
        exact_implementations: exact,
        generic_implementations: generic,
        clauses,
        exact_values,
        generic_values,
    };
    solve_inferred_trait_goal_inner(
        exact,
        generic,
        clauses,
        None,
        None,
        Some(environment),
        None,
        0,
        goal,
        &mut state,
        &mut stack,
        0,
    )
}

pub fn solve_exists_trait_goal_with_projection_clauses(
    exact: &TraitImplementationDatabase,
    generic: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    projection_clauses: &ProjectionBearingTraitClauseDatabase,
    exact_values: &TraitAssociatedTypeDatabase,
    generic_values: &GenericTraitAssociatedTypeDatabase,
    universe: TraitUniverseIndex,
    goal: ExistsImplementedTraitGoal,
) -> Result<InferredTraitGoalSolution, TraitGoalError> {
    let goal = goal.instantiate_in_universe(universe)?;
    let canonicalized = canonicalize_implemented_trait_goal_with_variables(goal)?;
    let mut state = InferenceConstraintState::new(canonicalized)?;
    let mut stack = [None; MAX_TRAIT_PROOF_DEPTH];
    let environment = TraitProjectionEnvironment {
        exact_implementations: exact,
        generic_implementations: generic,
        clauses,
        exact_values,
        generic_values,
    };
    match solve_inferred_trait_goal_inner(
        exact,
        generic,
        clauses,
        Some(projection_clauses),
        None,
        Some(environment),
        None,
        0,
        goal,
        &mut state,
        &mut stack,
        0,
    )? {
        TraitProofSolution::Proven => {
            Ok(InferredTraitGoalSolution::Unique(InferredTraitGoalAnswer {
                substitution: state.substitution()?,
            }))
        }
        TraitProofSolution::Ambiguous => Ok(InferredTraitGoalSolution::Ambiguous),
        TraitProofSolution::NoSolution => Ok(InferredTraitGoalSolution::NoSolution),
        TraitProofSolution::Cycle => Ok(InferredTraitGoalSolution::Cycle),
        TraitProofSolution::Overflow => Ok(InferredTraitGoalSolution::Overflow),
    }
}

pub fn solve_exists_trait_goal_with_projection_implementations(
    exact: &TraitImplementationDatabase,
    generic: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    projection_clauses: &ProjectionBearingTraitClauseDatabase,
    projection_implementations: &ProjectionBearingGenericTraitImplementationDatabase,
    exact_values: &TraitAssociatedTypeDatabase,
    generic_values: &GenericTraitAssociatedTypeDatabase,
    universe: TraitUniverseIndex,
    goal: ExistsImplementedTraitGoal,
) -> Result<InferredTraitGoalSolution, TraitGoalError> {
    let goal = goal.instantiate_in_universe(universe)?;
    let canonicalized = canonicalize_implemented_trait_goal_with_variables(goal)?;
    let mut state = InferenceConstraintState::new(canonicalized)?;
    let mut stack = [None; MAX_TRAIT_PROOF_DEPTH];
    let environment = TraitProjectionEnvironment {
        exact_implementations: exact,
        generic_implementations: generic,
        clauses,
        exact_values,
        generic_values,
    };
    match solve_inferred_trait_goal_inner(
        exact,
        generic,
        clauses,
        Some(projection_clauses),
        Some(projection_implementations),
        Some(environment),
        None,
        0,
        goal,
        &mut state,
        &mut stack,
        0,
    )? {
        TraitProofSolution::Proven => {
            Ok(InferredTraitGoalSolution::Unique(InferredTraitGoalAnswer {
                substitution: state.substitution()?,
            }))
        }
        TraitProofSolution::Ambiguous => Ok(InferredTraitGoalSolution::Ambiguous),
        TraitProofSolution::NoSolution => Ok(InferredTraitGoalSolution::NoSolution),
        TraitProofSolution::Cycle => Ok(InferredTraitGoalSolution::Cycle),
        TraitProofSolution::Overflow => Ok(InferredTraitGoalSolution::Overflow),
    }
}

fn solve_inferred_trait_goal_inner(
    exact: &TraitImplementationDatabase,
    generic: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    projection_clauses: Option<&ProjectionBearingTraitClauseDatabase>,
    projection_implementations: Option<&ProjectionBearingGenericTraitImplementationDatabase>,
    environment: Option<TraitProjectionEnvironment<'_>>,
    coinductive_traits: Option<&CoinductiveTraitDatabase>,
    premise_depth: usize,
    goal: ImplementedTraitGoal,
    state: &mut InferenceConstraintState,
    stack: &mut [Option<ImplementedTraitGoal>; MAX_TRAIT_PROOF_DEPTH],
    depth: usize,
) -> Result<TraitProofSolution, TraitGoalError> {
    let goal = state.apply_goal(goal)?;
    validate_existential_goal(goal)?;
    let canonicalized = canonicalize_implemented_trait_goal_with_variables(goal)?;
    let exact_solution = exact.solve(canonicalized.goal);
    let generic_solution = generic.select_existential(goal)?;
    match (exact_solution, generic_solution) {
        (TraitGoalSolution::Unique(answer), GenericExistentialTraitGoalSolution::NoSolution) => {
            let substitution = answer
                .substitute(canonicalized)
                .ok_or(TraitGoalError::InvalidGoal)?;
            state.merge_concrete(substitution)?;
            Ok(TraitProofSolution::Proven)
        }
        (TraitGoalSolution::NoSolution, GenericExistentialTraitGoalSolution::Unique(answer)) => {
            if answer.instantiated.has_projection_premises() && environment.is_none() {
                return Ok(TraitProofSolution::NoSolution);
            }
            state.merge_symbolic(answer.substitution)?;
            solve_inferred_premises(
                exact,
                generic,
                clauses,
                projection_clauses,
                projection_implementations,
                environment,
                coinductive_traits,
                premise_depth,
                goal,
                answer.instantiated,
                state,
                stack,
                depth,
            )
        }
        (TraitGoalSolution::NoSolution, GenericExistentialTraitGoalSolution::NoSolution) => {
            match clauses.elaborate_existential(goal)? {
                InferredTraitWhereClauseSolution::Unique(answer) => {
                    if answer.instantiated.has_projection_premises() && environment.is_none() {
                        return Ok(TraitProofSolution::NoSolution);
                    }
                    state.merge_symbolic(answer.substitution)?;
                    solve_inferred_premises(
                        exact,
                        generic,
                        clauses,
                        projection_clauses,
                        projection_implementations,
                        environment,
                        coinductive_traits,
                        premise_depth,
                        goal,
                        answer.instantiated,
                        state,
                        stack,
                        depth,
                    )
                }
                InferredTraitWhereClauseSolution::Ambiguous => Ok(TraitProofSolution::Ambiguous),
                InferredTraitWhereClauseSolution::NoSolution => {
                    let Some(environment) = environment else {
                        return Ok(TraitProofSolution::NoSolution);
                    };
                    if let Some(projection_implementations) = projection_implementations {
                        let (solution, _) = projection_implementations.solve_in_state(
                            environment,
                            projection_clauses,
                            goal,
                            state,
                            stack,
                            depth,
                        )?;
                        if solution != TraitProofSolution::NoSolution {
                            return Ok(solution);
                        }
                    }
                    let Some(projection_clauses) = projection_clauses else {
                        return Ok(TraitProofSolution::NoSolution);
                    };
                    projection_clauses
                        .solve_in_state(environment, goal, state, stack, depth)
                        .map(|(solution, _)| solution)
                }
            }
        }
        (TraitGoalSolution::Unique(_), _)
        | (TraitGoalSolution::Ambiguous, _)
        | (_, GenericExistentialTraitGoalSolution::Ambiguous) => Ok(TraitProofSolution::Ambiguous),
    }
}

fn solve_inferred_premises(
    exact: &TraitImplementationDatabase,
    generic: &GenericTraitImplementationDatabase,
    clauses: &TraitWhereClauseDatabase,
    projection_clauses: Option<&ProjectionBearingTraitClauseDatabase>,
    projection_implementations: Option<&ProjectionBearingGenericTraitImplementationDatabase>,
    environment: Option<TraitProjectionEnvironment<'_>>,
    coinductive_traits: Option<&CoinductiveTraitDatabase>,
    premise_depth: usize,
    goal: ImplementedTraitGoal,
    instantiated: InstantiatedTraitWhereClause,
    state: &mut InferenceConstraintState,
    stack: &mut [Option<ImplementedTraitGoal>; MAX_TRAIT_PROOF_DEPTH],
    depth: usize,
) -> Result<TraitProofSolution, TraitGoalError> {
    let goal = state.apply_goal(goal)?;
    if let Some(cycle_start) = find_inferred_cycle_start(state, stack, depth, goal)? {
        return classify_inferred_coinductive_cycle(
            coinductive_traits,
            state,
            stack,
            cycle_start,
            depth,
        );
    }
    if depth >= MAX_TRAIT_PROOF_DEPTH {
        return Ok(TraitProofSolution::Overflow);
    }
    stack[depth] = Some(goal);
    let mut pending = [None; MAX_TRAIT_PREDICATES];
    let mut pending_count = 0usize;
    for premise in instantiated.premises.predicates() {
        if pending_count >= MAX_TRAIT_PREDICATES {
            return Err(TraitGoalError::TooManyPredicates);
        }
        pending[pending_count] = Some(InferredTraitPredicate::Implemented(
            premise
                .as_ref()
                .copied()
                .ok_or(TraitGoalError::InvalidGoal)?,
        ));
        pending_count += 1;
    }
    for premise in instantiated.projection_premises.predicates() {
        if pending_count >= MAX_TRAIT_PREDICATES {
            return Err(TraitGoalError::TooManyPredicates);
        }
        pending[pending_count] = Some(InferredTraitPredicate::ProjectionEquality(
            premise
                .as_ref()
                .copied()
                .ok_or(TraitGoalError::InvalidGoal)?,
        ));
        pending_count += 1;
    }

    let result = 'solve: loop {
        if pending_count == 0 {
            break TraitProofSolution::Proven;
        }
        let mut next = [None; MAX_TRAIT_PREDICATES];
        let mut next_count = 0usize;
        let mut proven_count = 0usize;
        let mut deferred_cycle_count = 0usize;
        for predicate in pending[..pending_count].iter().copied() {
            let predicate = predicate.ok_or(TraitGoalError::InvalidGoal)?;
            let saved = *state;
            match solve_inferred_trait_predicate_with_stack(
                environment,
                coinductive_traits,
                premise_depth,
                exact,
                generic,
                clauses,
                projection_clauses,
                projection_implementations,
                predicate,
                state,
                stack,
                depth + 1,
            )? {
                TraitProofSolution::Proven => proven_count += 1,
                TraitProofSolution::Ambiguous => {
                    *state = saved;
                    next[next_count] = Some(predicate);
                    next_count += 1;
                }
                TraitProofSolution::Cycle
                    if coinductive_traits.is_some()
                        && match predicate {
                            InferredTraitPredicate::Implemented(goal) => {
                                validate_rigid_goal(state.apply_goal(goal)?).is_err()
                            }
                            InferredTraitPredicate::ProjectionEquality(_) => false,
                        } =>
                {
                    *state = saved;
                    next[next_count] = Some(predicate);
                    next_count += 1;
                    deferred_cycle_count += 1;
                }
                other => break 'solve other,
            }
        }
        if proven_count == 0 {
            break if deferred_cycle_count != 0 {
                TraitProofSolution::Cycle
            } else {
                TraitProofSolution::Ambiguous
            };
        }
        pending = next;
        pending_count = next_count;
    };
    stack[depth] = None;
    Ok(result)
}

fn find_inferred_cycle_start(
    state: &InferenceConstraintState,
    stack: &[Option<ImplementedTraitGoal>; MAX_TRAIT_PROOF_DEPTH],
    depth: usize,
    goal: ImplementedTraitGoal,
) -> Result<Option<usize>, TraitGoalError> {
    for (index, entry) in stack[..depth].iter().enumerate() {
        let entry = entry.as_ref().copied().ok_or(TraitGoalError::InvalidGoal)?;
        if state.apply_goal(entry)? == goal {
            return Ok(Some(index));
        }
    }
    Ok(None)
}

fn classify_inferred_coinductive_cycle(
    coinductive_traits: Option<&CoinductiveTraitDatabase>,
    state: &InferenceConstraintState,
    stack: &[Option<ImplementedTraitGoal>; MAX_TRAIT_PROOF_DEPTH],
    cycle_start: usize,
    depth: usize,
) -> Result<TraitProofSolution, TraitGoalError> {
    let Some(coinductive_traits) = coinductive_traits else {
        return Ok(TraitProofSolution::Cycle);
    };
    for entry in &stack[cycle_start..depth] {
        let goal = state.apply_goal(entry.as_ref().copied().ok_or(TraitGoalError::InvalidGoal)?)?;
        if validate_rigid_goal(goal).is_err() || !coinductive_traits.contains(goal.trait_id) {
            return Ok(TraitProofSolution::Cycle);
        }
    }
    Ok(TraitProofSolution::Proven)
}

#[derive(Clone, Copy)]
struct InferenceConstraintState {
    variables: [Option<TraitInferenceVariableId>; MAX_CANONICAL_TRAIT_VARIABLES],
    parents: [u8; MAX_CANONICAL_TRAIT_VARIABLES],
    concrete: [Option<TraitTypeId>; MAX_CANONICAL_TRAIT_VARIABLES],
    variable_count: usize,
}

impl InferenceConstraintState {
    fn new(goal: CanonicalizedImplementedTraitGoal) -> Result<Self, TraitGoalError> {
        let mut variables = [None; MAX_CANONICAL_TRAIT_VARIABLES];
        for (index, variable) in goal.variables().iter().enumerate() {
            variables[index] = Some(
                variable
                    .as_ref()
                    .copied()
                    .ok_or(TraitGoalError::InvalidGoal)?,
            );
        }
        Ok(Self {
            variables,
            parents: [0, 1, 2, 3, 4, 5, 6, 7],
            concrete: [None; MAX_CANONICAL_TRAIT_VARIABLES],
            variable_count: goal.variable_count,
        })
    }

    fn from_universe(
        universe: TraitUniverseIndex,
        variable_count: usize,
    ) -> Result<Self, TraitGoalError> {
        if variable_count > MAX_CANONICAL_TRAIT_VARIABLES {
            return Err(TraitGoalError::TooManyCanonicalVariables);
        }
        let mut variables = [None; MAX_CANONICAL_TRAIT_VARIABLES];
        for (index, variable) in variables[..variable_count].iter_mut().enumerate() {
            *variable = Some(TraitInferenceVariableId::in_universe(
                universe,
                index as u32,
            ));
        }
        Ok(Self {
            variables,
            parents: [0, 1, 2, 3, 4, 5, 6, 7],
            concrete: [None; MAX_CANONICAL_TRAIT_VARIABLES],
            variable_count,
        })
    }

    fn from_term_arena(arena: &TraitGoalTermArena) -> Result<Self, TraitGoalError> {
        let mut variables = [None; MAX_CANONICAL_TRAIT_VARIABLES];
        let mut variable_count = 0usize;
        for term in arena.terms().iter().flatten() {
            let TraitGoalTerm::Type(TraitGoalType::InferenceVariable(variable)) = term else {
                continue;
            };
            if variables[..variable_count].contains(&Some(*variable)) {
                continue;
            }
            let slot = variables
                .get_mut(variable_count)
                .ok_or(TraitGoalError::TooManyCanonicalVariables)?;
            *slot = Some(*variable);
            variable_count += 1;
        }
        Ok(Self {
            variables,
            parents: [0, 1, 2, 3, 4, 5, 6, 7],
            concrete: [None; MAX_CANONICAL_TRAIT_VARIABLES],
            variable_count,
        })
    }

    fn merge_concrete(
        &mut self,
        substitution: TraitGoalSubstitution,
    ) -> Result<(), TraitGoalError> {
        for binding in substitution.bindings().iter().flatten() {
            let index = self
                .variable_index(binding.variable)
                .ok_or(TraitGoalError::InvalidGoal)?;
            if !self.constrain(index, binding.concrete_type) {
                return Err(TraitGoalError::InvalidGoal);
            }
        }
        Ok(())
    }

    fn merge_symbolic(
        &mut self,
        substitution: SymbolicTraitGoalSubstitution,
    ) -> Result<(), TraitGoalError> {
        for assignment in substitution.bindings().iter().flatten() {
            let variable = self
                .variable_index(assignment.variable())
                .ok_or(TraitGoalError::InvalidGoal)?;
            let accepted = match assignment.value() {
                TraitGoalType::Concrete(concrete) => self.constrain(variable, concrete),
                TraitGoalType::InferenceVariable(other) => {
                    let other = self
                        .variable_index(other)
                        .ok_or(TraitGoalError::InvalidGoal)?;
                    self.union(variable, other)
                }
                TraitGoalType::Placeholder(_) => return Err(TraitGoalError::UniverseLeak),
            };
            if !accepted {
                return Err(TraitGoalError::InvalidGoal);
            }
        }
        Ok(())
    }

    fn apply_goal(
        &self,
        goal: ImplementedTraitGoal,
    ) -> Result<ImplementedTraitGoal, TraitGoalError> {
        let mut applied =
            ImplementedTraitGoal::new(goal.trait_id, self.apply_type(goal.self_type)?);
        for argument in goal.arguments().iter() {
            applied.push_argument(
                self.apply_type(
                    argument
                        .as_ref()
                        .copied()
                        .ok_or(TraitGoalError::InvalidGoal)?,
                )?,
            )?;
        }
        Ok(applied)
    }

    fn apply_type(&self, ty: TraitGoalType) -> Result<TraitGoalType, TraitGoalError> {
        let TraitGoalType::InferenceVariable(variable) = ty else {
            return Ok(ty);
        };
        let index = self
            .variable_index(variable)
            .ok_or(TraitGoalError::InvalidGoal)?;
        let root = self.root(index);
        Ok(self.concrete[root].map(TraitGoalType::Concrete).unwrap_or(
            TraitGoalType::InferenceVariable(
                self.representative(root)
                    .ok_or(TraitGoalError::InvalidGoal)?,
            ),
        ))
    }

    fn unify_types(
        &mut self,
        left: TraitGoalType,
        right: TraitGoalType,
    ) -> Result<bool, TraitGoalError> {
        let left = self.apply_type(left)?;
        let right = self.apply_type(right)?;
        match (left, right) {
            (TraitGoalType::Concrete(left), TraitGoalType::Concrete(right)) => Ok(left == right),
            (TraitGoalType::InferenceVariable(left), TraitGoalType::Concrete(right))
            | (TraitGoalType::Concrete(right), TraitGoalType::InferenceVariable(left)) => {
                let left = self
                    .variable_index(left)
                    .ok_or(TraitGoalError::InvalidGoal)?;
                Ok(self.constrain(left, right))
            }
            (TraitGoalType::InferenceVariable(left), TraitGoalType::InferenceVariable(right)) => {
                let left = self
                    .variable_index(left)
                    .ok_or(TraitGoalError::InvalidGoal)?;
                let right = self
                    .variable_index(right)
                    .ok_or(TraitGoalError::InvalidGoal)?;
                Ok(self.union(left, right))
            }
            (TraitGoalType::Placeholder(_), _) | (_, TraitGoalType::Placeholder(_)) => {
                Err(TraitGoalError::NonExistentialClauseQuery)
            }
        }
    }

    fn substitution(self) -> Result<SymbolicTraitGoalSubstitution, TraitGoalError> {
        let mut bindings = [None; MAX_CANONICAL_TRAIT_VARIABLES];
        for (index, variable) in self.variables[..self.variable_count].iter().enumerate() {
            let variable = variable
                .as_ref()
                .copied()
                .ok_or(TraitGoalError::InvalidGoal)?;
            bindings[index] = Some(TraitUniverseAssignment::new(
                variable,
                self.apply_type(TraitGoalType::InferenceVariable(variable))?,
            )?);
        }
        Ok(SymbolicTraitGoalSubstitution {
            bindings,
            binding_count: self.variable_count,
        })
    }

    fn variable_index(self, variable: TraitInferenceVariableId) -> Option<usize> {
        self.variables[..self.variable_count]
            .iter()
            .position(|candidate| *candidate == Some(variable))
    }

    fn root(self, mut variable: usize) -> usize {
        while self.parents[variable] as usize != variable {
            variable = self.parents[variable] as usize;
        }
        variable
    }

    fn representative(self, root: usize) -> Option<TraitInferenceVariableId> {
        self.variables[..self.variable_count]
            .iter()
            .enumerate()
            .filter_map(|(index, variable)| {
                (self.root(index) == root).then_some(*variable).flatten()
            })
            .min()
    }

    fn constrain(&mut self, variable: usize, concrete: TraitTypeId) -> bool {
        let root = self.root(variable);
        match self.concrete[root] {
            Some(existing) => existing == concrete,
            None => {
                self.concrete[root] = Some(concrete);
                true
            }
        }
    }

    fn union(&mut self, left: usize, right: usize) -> bool {
        let left = self.root(left);
        let right = self.root(right);
        if left == right {
            return true;
        }
        match (self.concrete[left], self.concrete[right]) {
            (Some(left), Some(right)) if left != right => return false,
            _ => {}
        }
        self.parents[right] = left as u8;
        if self.concrete[left].is_none() {
            self.concrete[left] = self.concrete[right];
        }
        true
    }
}

fn implementation_matches_goal(
    implementation: TraitImplementationHeader,
    goal: CanonicalImplementedTraitGoal,
) -> Option<[Option<TraitTypeId>; MAX_CANONICAL_TRAIT_VARIABLES]> {
    let mut bindings = [None; MAX_CANONICAL_TRAIT_VARIABLES];
    if implementation.trait_id != goal.trait_id
        || implementation.argument_count != goal.argument_count
        || !canonical_type_matches_concrete(goal.self_type, implementation.self_type, &mut bindings)
    {
        return None;
    }
    let matches =
        goal.arguments()
            .iter()
            .zip(implementation.arguments())
            .all(|(goal, implementation)| {
                goal.zip(*implementation)
                    .is_some_and(|(goal, implementation)| {
                        canonical_type_matches_concrete(goal, implementation, &mut bindings)
                    })
            });
    matches.then_some(bindings)
}

fn canonical_type_matches_concrete(
    goal: CanonicalTraitGoalType,
    implementation: TraitTypeId,
    bindings: &mut [Option<TraitTypeId>; MAX_CANONICAL_TRAIT_VARIABLES],
) -> bool {
    match goal {
        CanonicalTraitGoalType::Concrete(goal) => goal.0 == implementation.0,
        CanonicalTraitGoalType::BoundVariable(variable) => {
            let Some(binding) = bindings.get_mut(variable as usize) else {
                return false;
            };
            match *binding {
                Some(bound) => bound == implementation,
                None => {
                    *binding = Some(implementation);
                    true
                }
            }
        }
        CanonicalTraitGoalType::Placeholder(_) => false,
    }
}

pub fn canonicalize_implemented_trait_goal(
    goal: ImplementedTraitGoal,
) -> Result<CanonicalImplementedTraitGoal, TraitGoalError> {
    Ok(canonicalize_implemented_trait_goal_with_variables(goal)?.goal)
}

pub fn canonicalize_implemented_trait_goal_with_variables(
    goal: ImplementedTraitGoal,
) -> Result<CanonicalizedImplementedTraitGoal, TraitGoalError> {
    let mut variables = [None; MAX_CANONICAL_TRAIT_VARIABLES];
    let mut variable_count = 0usize;
    let goal = canonicalize_goal(goal, &mut variables, &mut variable_count)?;
    Ok(CanonicalizedImplementedTraitGoal {
        goal,
        variables,
        variable_count,
    })
}

pub fn canonicalize_implemented_trait_predicates(
    predicates: ImplementedTraitPredicates,
) -> Result<CanonicalizedImplementedTraitPredicates, TraitGoalError> {
    if predicates.predicate_count > predicates.predicates.len()
        || predicates.predicates[..predicates.predicate_count]
            .iter()
            .any(Option::is_none)
        || predicates.predicates[predicates.predicate_count..]
            .iter()
            .any(Option::is_some)
    {
        return Err(TraitGoalError::InvalidGoal);
    }
    let mut variables = [None; MAX_CANONICAL_TRAIT_VARIABLES];
    let mut variable_count = 0usize;
    let mut canonical = [None; MAX_TRAIT_PREDICATES];
    for (index, predicate) in predicates.predicates().iter().enumerate() {
        canonical[index] = Some(canonicalize_goal(
            predicate
                .as_ref()
                .copied()
                .ok_or(TraitGoalError::InvalidGoal)?,
            &mut variables,
            &mut variable_count,
        )?);
    }
    Ok(CanonicalizedImplementedTraitPredicates {
        predicates: canonical,
        predicate_count: predicates.predicate_count,
        variables,
        variable_count,
    })
}

fn canonicalize_goal(
    goal: ImplementedTraitGoal,
    variables: &mut [Option<TraitInferenceVariableId>; MAX_CANONICAL_TRAIT_VARIABLES],
    variable_count: &mut usize,
) -> Result<CanonicalImplementedTraitGoal, TraitGoalError> {
    if goal.argument_count > goal.arguments.len()
        || goal.arguments[..goal.argument_count]
            .iter()
            .any(Option::is_none)
        || goal.arguments[goal.argument_count..]
            .iter()
            .any(Option::is_some)
    {
        return Err(TraitGoalError::InvalidGoal);
    }
    let self_type = canonicalize_type(goal.self_type, variables, variable_count)?;
    let mut arguments = [None; MAX_TRAIT_GOAL_ARGUMENTS];
    for (index, argument) in goal.arguments().iter().enumerate() {
        arguments[index] = Some(canonicalize_type(
            argument.ok_or(TraitGoalError::InvalidGoal)?,
            variables,
            variable_count,
        )?);
    }
    Ok(CanonicalImplementedTraitGoal {
        trait_id: goal.trait_id,
        self_type,
        arguments,
        argument_count: goal.argument_count,
        variable_count: *variable_count,
    })
}

fn canonicalize_type(
    ty: TraitGoalType,
    variables: &mut [Option<TraitInferenceVariableId>; MAX_CANONICAL_TRAIT_VARIABLES],
    variable_count: &mut usize,
) -> Result<CanonicalTraitGoalType, TraitGoalError> {
    match ty {
        TraitGoalType::Concrete(id) => Ok(CanonicalTraitGoalType::Concrete(id)),
        TraitGoalType::Placeholder(id) => Ok(CanonicalTraitGoalType::Placeholder(id)),
        TraitGoalType::InferenceVariable(id) => {
            let index = variables[..*variable_count]
                .iter()
                .position(|variable| *variable == Some(id))
                .unwrap_or(*variable_count);
            if index == *variable_count {
                let slot = variables
                    .get_mut(index)
                    .ok_or(TraitGoalError::TooManyCanonicalVariables)?;
                *slot = Some(id);
                *variable_count += 1;
            }
            let bound =
                u8::try_from(index).map_err(|_| TraitGoalError::TooManyCanonicalVariables)?;
            Ok(CanonicalTraitGoalType::BoundVariable(bound))
        }
    }
}
