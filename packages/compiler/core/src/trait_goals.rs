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
pub const MAX_TRAIT_GOAL_TERMS: usize = 64;

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
        goal,
        &mut stack,
        0,
    )
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
                environment,
                answer.instantiated,
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
            environment,
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
        if total > MAX_TRAIT_GENERIC_PARAMETERS || self.binder_count >= MAX_TRAIT_GENERIC_PARAMETERS
        {
            return Err(TraitGoalError::TooManyGenericParameters);
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
    predicate: InferredTraitPredicate,
) -> Result<TraitProofSolution, TraitGoalError> {
    let mut proof_stack = [None; MAX_TRAIT_PROOF_DEPTH];
    match predicate {
        InferredTraitPredicate::Implemented(goal) => solve_rigid_trait_goal_with_generics_inner(
            exact_implementations,
            generic_implementations,
            clauses,
            Some(environment),
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
            predicate,
        )?;
        if result != TraitProofSolution::Proven {
            return Ok(result);
        }
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
        exact, generic, clauses, None, None, None, 0, goal, &mut state, &mut stack, 0,
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
    premise_depth: usize,
    goal: ImplementedTraitGoal,
    instantiated: InstantiatedTraitWhereClause,
    state: &mut InferenceConstraintState,
    stack: &mut [Option<ImplementedTraitGoal>; MAX_TRAIT_PROOF_DEPTH],
    depth: usize,
) -> Result<TraitProofSolution, TraitGoalError> {
    let goal = state.apply_goal(goal)?;
    if stack[..depth].contains(&Some(goal)) {
        return Ok(TraitProofSolution::Cycle);
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
        for predicate in pending[..pending_count].iter().copied() {
            let predicate = predicate.ok_or(TraitGoalError::InvalidGoal)?;
            let saved = *state;
            match solve_inferred_trait_predicate_with_stack(
                environment,
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
                other => break 'solve other,
            }
        }
        if proven_count == 0 {
            break TraitProofSolution::Ambiguous;
        }
        pending = next;
        pending_count = next_count;
    };
    stack[depth] = None;
    Ok(result)
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
