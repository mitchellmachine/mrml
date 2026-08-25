//! Bounded canonical trait-goal foundations.
//!
//! It provides stable, allocation-free identities, first-occurrence
//! canonicalization, exact concrete-header selection, and bounded response
//! substitutions without confusing inference variables, placeholders, or
//! concrete types.

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
        Ok(InstantiatedTraitWhereClause {
            consequence,
            premises,
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
pub enum TraitProofSolution {
    Proven,
    Ambiguous,
    NoSolution,
    Cycle,
    Overflow,
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
        TraitWhereClauseSolution::Unique(answer) => solve_generic_premises(
            implementations,
            generic_implementations,
            clauses,
            answer.instantiated.premises,
            stack,
            depth + 1,
        )?,
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
        goal,
        &mut stack,
        0,
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
            if stack[..depth].contains(&Some(goal)) {
                return Ok(TraitProofSolution::Cycle);
            }
            if depth >= MAX_TRAIT_PROOF_DEPTH {
                return Ok(TraitProofSolution::Overflow);
            }
            stack[depth] = Some(goal);
            let result = solve_rigid_generic_premises(
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
    let solution = match clauses.elaborate_rigid(goal)? {
        TraitWhereClauseSolution::Unique(answer) => solve_rigid_generic_premises(
            implementations,
            generic_implementations,
            clauses,
            answer.instantiated.premises,
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
    premises: ImplementedTraitPredicates,
    stack: &mut [Option<ImplementedTraitGoal>; MAX_TRAIT_PROOF_DEPTH],
    depth: usize,
) -> Result<TraitProofSolution, TraitGoalError> {
    for premise in premises.predicates().iter() {
        let premise = premise
            .as_ref()
            .copied()
            .ok_or(TraitGoalError::InvalidGoal)?;
        let result = solve_rigid_trait_goal_with_generics_inner(
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
    TooManyPredicates,
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

#[derive(Clone, Copy)]
struct TraitProjectionEnvironment<'a> {
    exact_implementations: &'a TraitImplementationDatabase,
    generic_implementations: &'a GenericTraitImplementationDatabase,
    clauses: &'a TraitWhereClauseDatabase,
    exact_values: &'a TraitAssociatedTypeDatabase,
    generic_values: &'a GenericTraitAssociatedTypeDatabase,
}

impl TraitProjectionEnvironment<'_> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
