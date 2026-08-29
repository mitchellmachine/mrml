fn validate_stable_export<const MAX_PARAMETERS: usize>(
    function: &Function<'_, MAX_PARAMETERS>,
    abi: X86_64Abi,
) -> Result<(), CodegenError> {
    if !function.public || !function.no_mangle {
        return Err(CodegenError {
            kind: CodegenErrorKind::StableExportRequired,
            span: function.name_span,
        });
    }
    if function.abi == FunctionAbi::C {
        return Ok(());
    }
    if function.abi != FunctionAbi::MrmlV1 {
        return Err(CodegenError {
            kind: CodegenErrorKind::StableExportRequired,
            span: function.name_span,
        });
    }
    let signature = crate::validate_mrml_v1_signature(function).map_err(|error| {
        let span = match error.location {
            crate::MrmlV1SignatureLocation::Function => function.name_span,
            crate::MrmlV1SignatureLocation::Parameter(index) => function.parameters()[index]
                .map_or(function.name_span, |parameter| parameter.ty.span),
            crate::MrmlV1SignatureLocation::Return => function
                .return_type
                .map_or(function.name_span, |return_type| return_type.span),
        };
        CodegenError {
            kind: CodegenErrorKind::MrmlV1Signature(error.kind),
            span,
        }
    })?;
    let target = match abi {
        X86_64Abi::SystemV => crate::MrmlV1Target::X86_64SystemV,
        X86_64Abi::Windows => crate::MrmlV1Target::X86_64Windows,
    };
    let plan = crate::plan_mrml_v1_call(target, &signature).map_err(|error| CodegenError {
        kind: CodegenErrorKind::TooManyAbiParameters,
        span: function.parameters()[error.parameter]
            .map_or(function.name_span, |parameter| parameter.ty.span),
    })?;
    for (index, (value, ty)) in plan
        .parameters()
        .iter()
        .flatten()
        .zip(signature.parameters().iter().flatten())
        .enumerate()
    {
        if value.words().len() != 1
            && !matches!(
                ty,
                crate::MrmlV1Type::Slice { .. }
                    | crate::MrmlV1Type::Str { .. }
                    | crate::MrmlV1Type::Integer(
                        crate::MrmlV1Integer::U128 | crate::MrmlV1Integer::I128
                    )
            )
        {
            return Err(CodegenError {
                kind: CodegenErrorKind::MrmlV1MultiwordValueUnsupported,
                span: function.parameters()[index]
                    .map_or(function.name_span, |parameter| parameter.ty.span),
            });
        }
    }
    if plan.return_value.words().len() > 1
        && !matches!(
            signature.return_type,
            crate::MrmlV1Type::Slice { .. }
                | crate::MrmlV1Type::Str { .. }
                | crate::MrmlV1Type::Integer(
                    crate::MrmlV1Integer::U128 | crate::MrmlV1Integer::I128
                )
        )
    {
        return Err(CodegenError {
            kind: CodegenErrorKind::MrmlV1MultiwordValueUnsupported,
            span: function
                .return_type
                .map_or(function.name_span, |return_type| return_type.span),
        });
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeExpressionType {
    Never,
    Unit,
    Default,
    Integer(Option<crate::IntegerType>),
    Bool,
    Char,
    Reference {
        target: RuntimeReferenceTarget,
        mutable: bool,
    },
    RawPointer {
        pointee: RuntimeArrayElementType,
        mutable: bool,
    },
    Array {
        element: RuntimeArrayElementType,
        count: usize,
    },
    Tuple {
        elements: [Option<RuntimeTupleElementType>; crate::expression::MAX_TUPLE_ELEMENTS],
        element_count: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeArrayElementType {
    Unit,
    Default,
    Integer(Option<crate::IntegerType>),
    Bool,
    Char,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeTupleElementType {
    Scalar(RuntimeArrayElementType),
    Reference {
        pointee: RuntimeArrayElementType,
        mutable: bool,
    },
    RawPointer {
        pointee: RuntimeArrayElementType,
        mutable: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeReferenceTarget {
    Scalar(RuntimeArrayElementType),
    Slice(RuntimeArrayElementType),
    Str,
    Array {
        element: RuntimeArrayElementType,
        count: usize,
        layout: RuntimeReferenceArrayLayout,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeReferenceArrayLayout {
    Native,
}

fn runtime_reference_target_type(
    target: RuntimeReferenceTarget,
) -> Result<RuntimeExpressionType, CodegenErrorKind> {
    match target {
        RuntimeReferenceTarget::Scalar(element) => Ok(runtime_type_from_array_element(element)),
        RuntimeReferenceTarget::Slice(_) | RuntimeReferenceTarget::Str => {
            Err(CodegenErrorKind::RuntimeExpressionUnsupported)
        }
        RuntimeReferenceTarget::Array { element, count, .. } => {
            Ok(RuntimeExpressionType::Array { element, count })
        }
    }
}

fn runtime_reference_target_from_type(
    ty: RuntimeExpressionType,
) -> Result<RuntimeReferenceTarget, CodegenErrorKind> {
    match ty {
        RuntimeExpressionType::Array { element, count } => Ok(RuntimeReferenceTarget::Array {
            element,
            count,
            layout: RuntimeReferenceArrayLayout::Native,
        }),
        RuntimeExpressionType::Reference { .. } | RuntimeExpressionType::RawPointer { .. } => {
            Err(CodegenErrorKind::RuntimeExpressionUnsupported)
        }
        scalar => Ok(RuntimeReferenceTarget::Scalar(runtime_array_element_type(
            scalar,
        )?)),
    }
}

fn runtime_array_element_type(
    ty: RuntimeExpressionType,
) -> Result<RuntimeArrayElementType, CodegenErrorKind> {
    match ty {
        RuntimeExpressionType::Never => Err(CodegenErrorKind::RuntimeTypeMismatch),
        RuntimeExpressionType::Unit => Ok(RuntimeArrayElementType::Unit),
        RuntimeExpressionType::Default => Ok(RuntimeArrayElementType::Default),
        RuntimeExpressionType::Integer(ty) => Ok(RuntimeArrayElementType::Integer(ty)),
        RuntimeExpressionType::Bool => Ok(RuntimeArrayElementType::Bool),
        RuntimeExpressionType::Char => Ok(RuntimeArrayElementType::Char),
        RuntimeExpressionType::Array { .. }
        | RuntimeExpressionType::Tuple { .. }
        | RuntimeExpressionType::Reference { .. }
        | RuntimeExpressionType::RawPointer { .. } => Err(CodegenErrorKind::RuntimeTypeMismatch),
    }
}

fn runtime_type_from_array_element(element: RuntimeArrayElementType) -> RuntimeExpressionType {
    match element {
        RuntimeArrayElementType::Unit => RuntimeExpressionType::Unit,
        RuntimeArrayElementType::Default => RuntimeExpressionType::Default,
        RuntimeArrayElementType::Integer(ty) => RuntimeExpressionType::Integer(ty),
        RuntimeArrayElementType::Bool => RuntimeExpressionType::Bool,
        RuntimeArrayElementType::Char => RuntimeExpressionType::Char,
    }
}

fn runtime_tuple_element_type(
    ty: RuntimeExpressionType,
) -> Result<RuntimeTupleElementType, CodegenErrorKind> {
    match ty {
        RuntimeExpressionType::Unit => Ok(RuntimeTupleElementType::Scalar(
            RuntimeArrayElementType::Unit,
        )),
        RuntimeExpressionType::Default => Ok(RuntimeTupleElementType::Scalar(
            RuntimeArrayElementType::Default,
        )),
        RuntimeExpressionType::Integer(ty) => Ok(RuntimeTupleElementType::Scalar(
            RuntimeArrayElementType::Integer(ty),
        )),
        RuntimeExpressionType::Bool => Ok(RuntimeTupleElementType::Scalar(
            RuntimeArrayElementType::Bool,
        )),
        RuntimeExpressionType::Char => Ok(RuntimeTupleElementType::Scalar(
            RuntimeArrayElementType::Char,
        )),
        RuntimeExpressionType::Reference {
            target: RuntimeReferenceTarget::Scalar(pointee),
            mutable,
        } => Ok(RuntimeTupleElementType::Reference { pointee, mutable }),
        RuntimeExpressionType::RawPointer { pointee, mutable } => {
            Ok(RuntimeTupleElementType::RawPointer { pointee, mutable })
        }
        RuntimeExpressionType::Never
        | RuntimeExpressionType::Array { .. }
        | RuntimeExpressionType::Tuple { .. }
        | RuntimeExpressionType::Reference { .. } => Err(CodegenErrorKind::RuntimeTypeMismatch),
    }
}

fn runtime_type_from_tuple_element(element: RuntimeTupleElementType) -> RuntimeExpressionType {
    match element {
        RuntimeTupleElementType::Scalar(element) => runtime_type_from_array_element(element),
        RuntimeTupleElementType::Reference { pointee, mutable } => {
            RuntimeExpressionType::Reference {
                target: RuntimeReferenceTarget::Scalar(pointee),
                mutable,
            }
        }
        RuntimeTupleElementType::RawPointer { pointee, mutable } => {
            RuntimeExpressionType::RawPointer { pointee, mutable }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeLocalId(usize);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeLocal<'source> {
    id: RuntimeLocalId,
    name: &'source str,
    ty: RuntimeExpressionType,
    mutable: bool,
    initialized: bool,
    stack_slots: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimePlaceBase {
    Local { id: RuntimeLocalId, index: usize },
    Parameter { index: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimePlaceIdentity {
    Local(RuntimeLocalId),
    Parameter(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimePlaceAccess {
    Read,
    Write,
    ReadModifyWrite,
}

impl RuntimePlaceAccess {
    const fn from_operator(operator: crate::AssignmentOperator) -> Self {
        if matches!(operator, crate::AssignmentOperator::Assign) {
            Self::Write
        } else {
            Self::ReadModifyWrite
        }
    }

    const fn reads_previous_value(self) -> bool {
        matches!(self, Self::ReadModifyWrite)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimePlace<'source> {
    base: RuntimePlaceBase,
    projection: Option<crate::parser::AssignmentProjection<'source>>,
    ty: RuntimeExpressionType,
    mutable: bool,
    access: RuntimePlaceAccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimePlaceProjection {
    Dereference,
    Index,
    ArrayElement(usize),
    TupleField(usize),
    Subslice,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimePlaceProjections {
    items: [Option<RuntimePlaceProjection>; MAX_RUNTIME_PLACE_PROJECTIONS],
    count: usize,
}

impl RuntimePlaceProjections {
    const EMPTY: Self = Self {
        items: [None; MAX_RUNTIME_PLACE_PROJECTIONS],
        count: 0,
    };

    const fn single(projection: RuntimePlaceProjection) -> Self {
        let mut items = [None; MAX_RUNTIME_PLACE_PROJECTIONS];
        items[0] = Some(projection);
        Self { items, count: 1 }
    }

    fn from_assignment(
        projection: Option<crate::parser::AssignmentProjection<'_>>,
    ) -> Result<Self, CodegenErrorKind> {
        let mut projections = Self::EMPTY;
        if let Some(projection) = projection {
            projections.push(match projection {
                crate::parser::AssignmentProjection::Dereference { .. } => {
                    RuntimePlaceProjection::Dereference
                }
                crate::parser::AssignmentProjection::Index { .. } => RuntimePlaceProjection::Index,
                crate::parser::AssignmentProjection::TupleField { field, .. } => {
                    RuntimePlaceProjection::TupleField(field)
                }
            })?;
        }
        Ok(projections)
    }

    fn from_assignment_with_array_identity<
        R: ConstantResolver,
        const MAX_EXPRESSION_NODES: usize,
    >(
        assignment: &crate::Assignment<'_>,
        base_ty: RuntimeExpressionType,
        resolver: &R,
    ) -> Result<Self, CodegenErrorKind> {
        let mut projections = Self::from_assignment(assignment.projection)?;
        let RuntimeExpressionType::Array { count, .. } = base_ty else {
            return Ok(projections);
        };
        if projections != Self::single(RuntimePlaceProjection::Index) {
            return Ok(projections);
        }
        let Ok(tree) = assignment.parse_index::<MAX_EXPRESSION_NODES>() else {
            return Ok(projections);
        };
        let Ok(index) = tree.evaluate_at(tree.root(), resolver) else {
            return Ok(projections);
        };
        let Ok(index) = usize::try_from(index) else {
            return Ok(projections);
        };
        if index < count {
            projections.items[0] = Some(RuntimePlaceProjection::ArrayElement(index));
        }
        Ok(projections)
    }

    fn push(&mut self, projection: RuntimePlaceProjection) -> Result<(), CodegenErrorKind> {
        let slot = self
            .items
            .get_mut(self.count)
            .ok_or(CodegenErrorKind::TooManyRuntimePlaceProjections)?;
        *slot = Some(projection);
        self.count += 1;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
struct RuntimeCalleeProjectedOrigin {
    local: usize,
    projections: RuntimePlaceProjections,
    ty: RuntimeExpressionType,
    origin: usize,
    generation: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
struct RuntimeCalleeProjectedOrigins<const MAX_ORIGINS: usize> {
    entries: [Option<RuntimeCalleeProjectedOrigin>; MAX_ORIGINS],
    count: usize,
}

#[cfg_attr(not(test), allow(dead_code))]
impl<const MAX_ORIGINS: usize> RuntimeCalleeProjectedOrigins<MAX_ORIGINS> {
    const EMPTY: Self = Self {
        entries: [None; MAX_ORIGINS],
        count: 0,
    };

    fn set(
        &mut self,
        local: usize,
        base_type: RuntimeExpressionType,
        projections: RuntimePlaceProjections,
        origin: usize,
    ) -> Option<()> {
        if projections.count == 0 {
            return None;
        }
        let ty = runtime_place_projected_type(base_type, projections)?;
        if let Some(entry) = self.entries[..self.count]
            .iter_mut()
            .flatten()
            .find(|entry| entry.local == local && entry.projections == projections)
        {
            entry.ty = ty;
            entry.origin = origin;
            entry.generation = entry.generation.checked_add(1)?;
            return Some(());
        }
        let slot = self.entries.get_mut(self.count)?;
        *slot = Some(RuntimeCalleeProjectedOrigin {
            local,
            projections,
            ty,
            origin,
            generation: 0,
        });
        self.count = self.count.checked_add(1)?;
        Some(())
    }

    fn get(
        &self,
        local: usize,
        projections: RuntimePlaceProjections,
    ) -> Option<RuntimeCalleeProjectedOrigin> {
        self.entries[..self.count]
            .iter()
            .flatten()
            .find(|entry| entry.local == local && entry.projections == projections)
            .copied()
    }

    fn clear(&mut self, local: usize, projections: RuntimePlaceProjections) -> Option<()> {
        let index = self.entries[..self.count].iter().position(|entry| {
            entry.is_some_and(|entry| entry.local == local && entry.projections == projections)
        })?;
        for shifted in index..self.count.checked_sub(1)? {
            self.entries[shifted] = self.entries[shifted + 1];
        }
        self.count -= 1;
        self.entries[self.count] = None;
        Some(())
    }

    fn intersect(self, other: Self) -> Self {
        let mut joined = Self::EMPTY;
        for left in self.entries[..self.count].iter().flatten() {
            let Some(right) = other.get(left.local, left.projections) else {
                continue;
            };
            if left.ty != right.ty || left.origin != right.origin {
                continue;
            }
            let Some(slot) = joined.entries.get_mut(joined.count) else {
                break;
            };
            *slot = Some(RuntimeCalleeProjectedOrigin {
                generation: left.generation.max(right.generation),
                ..*left
            });
            joined.count += 1;
        }
        joined
    }

    fn retain_local_prefix(self, local_count: usize) -> Self {
        let mut retained = Self::EMPTY;
        for entry in self.entries[..self.count].iter().flatten() {
            if entry.local >= local_count {
                continue;
            }
            retained.entries[retained.count] = Some(*entry);
            retained.count += 1;
        }
        retained
    }

    fn has_same_origins(self, other: Self) -> bool {
        self.count == other.count
            && self.entries[..self.count].iter().flatten().all(|left| {
                other
                    .get(left.local, left.projections)
                    .is_some_and(|right| left.ty == right.ty && left.origin == right.origin)
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeReadPlace<'source> {
    name: &'source str,
    span: Span,
    projections: RuntimePlaceProjections,
}

fn discover_runtime_read_place<'source, const MAX_NODES: usize>(
    tree: &crate::ExpressionTree<'source, MAX_NODES>,
    id: crate::ExprId,
) -> Result<Option<RuntimeReadPlace<'source>>, CodegenErrorKind> {
    fn recurse<'source, const MAX_NODES: usize>(
        tree: &crate::ExpressionTree<'source, MAX_NODES>,
        id: crate::ExprId,
        depth: usize,
    ) -> Result<Option<RuntimeReadPlace<'source>>, CodegenErrorKind> {
        if depth == 64 {
            return Err(CodegenErrorKind::Lowering(
                IrErrorKind::NestingLimitExceeded,
            ));
        }
        let expression = tree
            .expression(id)
            .ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)?;
        let place = match expression.kind {
            ExprKind::Identifier(name) => Some(RuntimeReadPlace {
                name,
                span: expression.span,
                projections: RuntimePlaceProjections::EMPTY,
            }),
            ExprKind::Unary {
                operator: crate::UnaryOperator::Dereference,
                operand,
            } => {
                let mut place = recurse(tree, operand, depth + 1)?;
                if let Some(place) = place.as_mut() {
                    place
                        .projections
                        .push(RuntimePlaceProjection::Dereference)?;
                }
                place
            }
            ExprKind::Index { base, .. } => {
                let mut place = recurse(tree, base, depth + 1)?;
                if let Some(place) = place.as_mut() {
                    place.projections.push(RuntimePlaceProjection::Index)?;
                }
                place
            }
            ExprKind::TupleField { base, field } => {
                let mut place = recurse(tree, base, depth + 1)?;
                if let Some(place) = place.as_mut() {
                    place
                        .projections
                        .push(RuntimePlaceProjection::TupleField(field))?;
                }
                place
            }
            ExprKind::RangeIndex { base, .. } => {
                let mut place = recurse(tree, base, depth + 1)?;
                if let Some(place) = place.as_mut() {
                    place.projections.push(RuntimePlaceProjection::Subslice)?;
                }
                place
            }
            ExprKind::Ascribe { operand, .. }
            | ExprKind::InlineConst { operand }
            | ExprKind::LoopBreak { operand }
            | ExprKind::Return { operand } => recurse(tree, operand, depth + 1)?,
            ExprKind::Sequence { then, .. } => recurse(tree, then, depth + 1)?,
            _ => None,
        };
        Ok(place)
    }

    recurse(tree, id, 0)
}

fn refine_constant_array_read_place<
    'source,
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_NODES: usize,
>(
    function: &Function<'source, MAX_PARAMETERS>,
    resolver: &R,
    locals: &[Option<RuntimeLocal<'source>>],
    tree: &crate::ExpressionTree<'source, MAX_NODES>,
    id: crate::ExprId,
    mut place: RuntimeReadPlace<'source>,
) -> Result<RuntimeReadPlace<'source>, CodegenErrorKind> {
    let Some(ExprKind::Index { base, index }) =
        tree.expression(id).map(|expression| expression.kind)
    else {
        return Ok(place);
    };
    if place.projections.count != 1
        || place.projections.items[0] != Some(RuntimePlaceProjection::Index)
        || !matches!(
            tree.expression(base).map(|expression| expression.kind),
            Some(ExprKind::Identifier(_))
        )
    {
        return Ok(place);
    }
    let ty = locals
        .iter()
        .rev()
        .flatten()
        .find(|local| local.name == place.name)
        .map(|local| local.ty)
        .or_else(|| {
            function
                .parameters()
                .iter()
                .flatten()
                .find(|parameter| parameter.name == place.name)
                .and_then(|parameter| runtime_type_from_text(parameter.ty.text))
        });
    let Some(RuntimeExpressionType::Array { count, .. }) = ty else {
        return Ok(place);
    };
    let Ok(index) = tree.evaluate_at(index, resolver) else {
        return Ok(place);
    };
    let index = usize::try_from(index).map_err(|_| CodegenErrorKind::ValueOutOfRange)?;
    if index >= count {
        return Err(CodegenErrorKind::ValueOutOfRange);
    }
    place.projections.items[0] = Some(RuntimePlaceProjection::ArrayElement(index));
    Ok(place)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeLocalFact<'source> {
    id: RuntimeLocalId,
    name: &'source str,
    ty: RuntimeExpressionType,
    mutable: bool,
    initialized: bool,
    declaration_span: Option<Span>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimePlaceAccessFact {
    base: RuntimePlaceIdentity,
    projections: RuntimePlaceProjections,
    ty: RuntimeExpressionType,
    access: RuntimePlaceAccess,
    span: Span,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeMovePathId(usize);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeMovePathFact {
    id: RuntimeMovePathId,
    parent: Option<RuntimeMovePathId>,
    base: RuntimePlaceIdentity,
    projections: RuntimePlaceProjections,
    ty: RuntimeExpressionType,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeInitializationOrigin {
    Parameter,
    LocalDeclaration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeInitializationFact {
    path: RuntimeMovePathId,
    origin: RuntimeInitializationOrigin,
    span: Option<Span>,
    event: RuntimeOwnershipEventId,
    location: RuntimeOwnershipEventLocation,
    expression_path: RuntimeOwnershipExpressionPath,
    expression_conditional: Option<RuntimeConditionalExpressionId>,
    expression_point: Option<RuntimeExpressionProgramPointId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeOwnershipEventId(usize);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeOwnershipExpressionPath {
    else_bits: u64,
    depth: usize,
}

impl RuntimeOwnershipExpressionPath {
    const ROOT: Self = Self {
        else_bits: 0,
        depth: 0,
    };

    fn branch(self, else_branch: bool) -> Result<Self, CodegenErrorKind> {
        if self.depth >= 64 {
            return Err(CodegenErrorKind::InvalidRuntimePlaceFacts);
        }
        Ok(Self {
            else_bits: self.else_bits | ((else_branch as u64) << self.depth),
            depth: self.depth + 1,
        })
    }

    const fn is_valid(self) -> bool {
        self.depth <= 64 && (self.depth == 64 || self.else_bits < (1u64 << self.depth))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeConditionalExpressionId(usize);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeExpressionProgramPointId(usize);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeExpressionProgramPointKind {
    Root,
    Condition(RuntimeConditionalExpressionId),
    Then(RuntimeConditionalExpressionId),
    Else(RuntimeConditionalExpressionId),
    Join(RuntimeConditionalExpressionId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeExpressionProgramPointFact {
    id: RuntimeExpressionProgramPointId,
    location: RuntimeOwnershipEventLocation,
    kind: RuntimeExpressionProgramPointKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeExpressionControlFlowEdgeFact {
    from: RuntimeExpressionProgramPointId,
    to: RuntimeExpressionProgramPointId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeConditionalExpressionFact {
    id: RuntimeConditionalExpressionId,
    location: RuntimeOwnershipEventLocation,
    span: Span,
    parent: Option<RuntimeConditionalExpressionId>,
    parent_path: RuntimeOwnershipExpressionPath,
    entry: RuntimeExpressionProgramPointId,
    condition: RuntimeExpressionProgramPointId,
    then_branch: RuntimeExpressionProgramPointId,
    else_branch: RuntimeExpressionProgramPointId,
    join: RuntimeExpressionProgramPointId,
    then_exit: Option<RuntimeExpressionProgramPointId>,
    else_exit: Option<RuntimeExpressionProgramPointId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeOwnershipEventLocation {
    Unassigned,
    ParameterEntry,
    TopLevelStatement(usize),
    ConditionalReturnCondition {
        statement_index: usize,
        branch_index: usize,
    },
    ConditionalReturnValue {
        statement_index: usize,
        branch_index: usize,
    },
    ConditionalReturnElseValue {
        statement_index: usize,
    },
    ConditionalAssignmentCondition {
        statement_index: usize,
        branch_index: usize,
    },
    ConditionalAssignmentAction {
        statement_index: usize,
        branch_index: Option<usize>,
        action_index: usize,
    },
    ConditionalAssignmentReturnValue {
        statement_index: usize,
        branch_index: Option<usize>,
        action_index: usize,
    },
    LoopHeader {
        statement_index: usize,
    },
    LoopOperation {
        statement_index: usize,
        operation_index: usize,
    },
    LoopConditionalReturnCondition {
        statement_index: usize,
        operation_index: usize,
    },
    LoopConditionalReturnValue {
        statement_index: usize,
        operation_index: usize,
    },
    LoopReturnValue {
        statement_index: usize,
        operation_index: usize,
    },
    LoopConditionalCondition {
        statement_index: usize,
        operation_index: usize,
        arm_index: usize,
    },
    LoopConditionalAction {
        statement_index: usize,
        operation_index: usize,
        arm_index: usize,
        action_index: usize,
    },
    LoopConditionalTerminal {
        statement_index: usize,
        operation_index: usize,
        arm_index: usize,
    },
    NestedLoopHeader {
        statement_index: usize,
        operation_index: usize,
    },
    NestedLoopControlCondition {
        statement_index: usize,
        operation_index: usize,
        action_index: usize,
        control_order: usize,
    },
    NestedLoopControlValue {
        statement_index: usize,
        operation_index: usize,
        action_index: usize,
        control_order: usize,
    },
    NestedLoopAction {
        statement_index: usize,
        operation_index: usize,
        action_index: usize,
    },
    NestedLoopBranchCondition {
        statement_index: usize,
        operation_index: usize,
        branch_index: usize,
    },
    NestedLoopBranchAction {
        statement_index: usize,
        operation_index: usize,
        branch_index: usize,
        action_index: usize,
    },
    NestedLoopBranchValue {
        statement_index: usize,
        operation_index: usize,
        branch_index: usize,
    },
    NestedLoopBranchElseAction {
        statement_index: usize,
        operation_index: usize,
        branch_index: usize,
        alternative_index: usize,
        action_index: usize,
    },
    NestedLoopBranchElseCondition {
        statement_index: usize,
        operation_index: usize,
        branch_index: usize,
        alternative_index: usize,
    },
    NestedLoopBranchElseValue {
        statement_index: usize,
        operation_index: usize,
        branch_index: usize,
        alternative_index: usize,
    },
    ReturnValue {
        statement_index: usize,
    },
    Tail,
    EmissionExpansion,
}

const fn runtime_ownership_location_statement_index(
    location: RuntimeOwnershipEventLocation,
) -> Option<usize> {
    match location {
        RuntimeOwnershipEventLocation::TopLevelStatement(statement_index)
        | RuntimeOwnershipEventLocation::ConditionalReturnCondition {
            statement_index, ..
        }
        | RuntimeOwnershipEventLocation::ConditionalReturnValue {
            statement_index, ..
        }
        | RuntimeOwnershipEventLocation::ConditionalReturnElseValue { statement_index }
        | RuntimeOwnershipEventLocation::ConditionalAssignmentCondition {
            statement_index, ..
        }
        | RuntimeOwnershipEventLocation::ConditionalAssignmentAction {
            statement_index, ..
        }
        | RuntimeOwnershipEventLocation::ConditionalAssignmentReturnValue {
            statement_index, ..
        }
        | RuntimeOwnershipEventLocation::LoopHeader { statement_index }
        | RuntimeOwnershipEventLocation::LoopOperation {
            statement_index, ..
        }
        | RuntimeOwnershipEventLocation::LoopConditionalReturnCondition {
            statement_index, ..
        }
        | RuntimeOwnershipEventLocation::LoopConditionalReturnValue {
            statement_index, ..
        }
        | RuntimeOwnershipEventLocation::LoopReturnValue {
            statement_index, ..
        }
        | RuntimeOwnershipEventLocation::LoopConditionalCondition {
            statement_index, ..
        }
        | RuntimeOwnershipEventLocation::LoopConditionalAction {
            statement_index, ..
        }
        | RuntimeOwnershipEventLocation::LoopConditionalTerminal {
            statement_index, ..
        }
        | RuntimeOwnershipEventLocation::NestedLoopHeader {
            statement_index, ..
        }
        | RuntimeOwnershipEventLocation::NestedLoopControlCondition {
            statement_index, ..
        }
        | RuntimeOwnershipEventLocation::NestedLoopControlValue {
            statement_index, ..
        }
        | RuntimeOwnershipEventLocation::NestedLoopAction {
            statement_index, ..
        }
        | RuntimeOwnershipEventLocation::NestedLoopBranchCondition {
            statement_index, ..
        }
        | RuntimeOwnershipEventLocation::NestedLoopBranchAction {
            statement_index, ..
        }
        | RuntimeOwnershipEventLocation::NestedLoopBranchValue {
            statement_index, ..
        }
        | RuntimeOwnershipEventLocation::NestedLoopBranchElseAction {
            statement_index, ..
        }
        | RuntimeOwnershipEventLocation::NestedLoopBranchElseCondition {
            statement_index, ..
        }
        | RuntimeOwnershipEventLocation::NestedLoopBranchElseValue {
            statement_index, ..
        }
        | RuntimeOwnershipEventLocation::ReturnValue { statement_index } => Some(statement_index),
        RuntimeOwnershipEventLocation::Unassigned
        | RuntimeOwnershipEventLocation::ParameterEntry
        | RuntimeOwnershipEventLocation::Tail
        | RuntimeOwnershipEventLocation::EmissionExpansion => None,
    }
}

const MAX_RUNTIME_CONDITIONAL_ACTION_ORIGINS: usize =
    crate::parser::MAX_CONDITIONAL_ASSIGNMENT_BRANCHES + 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeOwnershipStatementShape {
    Plain,
    ConditionalReturn {
        branch_count: usize,
        has_else: bool,
    },
    ConditionalAssignment {
        branch_count: usize,
        action_counts: [usize; MAX_RUNTIME_CONDITIONAL_ACTION_ORIGINS],
    },
    Loop {
        operation_count: usize,
    },
    Return,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimePlaceEffectKind {
    Copy,
    Move,
    SharedBorrow,
    MutableBorrow,
    LoanUse,
    LoanMutation,
    Write,
    ReadModifyWrite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeReadEffectContext {
    Value,
    Move,
    SharedBorrow,
    MutableBorrow,
    Unclassified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimePlaceEffectFact {
    path: RuntimeMovePathId,
    kind: RuntimePlaceEffectKind,
    span: Span,
    event: RuntimeOwnershipEventId,
    location: RuntimeOwnershipEventLocation,
    expression_path: RuntimeOwnershipExpressionPath,
    expression_conditional: Option<RuntimeConditionalExpressionId>,
    expression_point: Option<RuntimeExpressionProgramPointId>,
    loan_generation_borrower: Option<RuntimeLocalId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
struct RuntimeLoanId(usize);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
struct RuntimeLoanFact {
    id: RuntimeLoanId,
    borrower: RuntimeLocalId,
    borrowed_path: RuntimeMovePathId,
    kind: RuntimePlaceEffectKind,
    issue_effect: usize,
    generation_event: RuntimeOwnershipEventId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeBasicBlockId(usize);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeBasicBlockSource {
    TopLevel,
    ConditionalReturnBranch {
        statement_index: usize,
        branch_index: usize,
    },
    ConditionalAssignmentCondition {
        statement_index: usize,
        branch_index: usize,
    },
    ConditionalAssignmentActions {
        statement_index: usize,
        branch_index: usize,
    },
    ConditionalAssignmentElseActions {
        statement_index: usize,
    },
    ConditionalAssignmentUnreachableActions {
        statement_index: usize,
        branch_index: Option<usize>,
        first_action: usize,
        action_count: usize,
    },
    LoopBody {
        statement_index: usize,
        first_operation: usize,
        operation_count: usize,
    },
    LoopConditionalCondition {
        statement_index: usize,
        operation_index: usize,
        arm_index: usize,
    },
    LoopConditionalActions {
        statement_index: usize,
        operation_index: usize,
        arm_index: usize,
        action_count: usize,
    },
    NestedLoopHeader {
        statement_index: usize,
        operation_index: usize,
    },
    NestedLoopControl {
        statement_index: usize,
        operation_index: usize,
        action_index: usize,
        control_order: usize,
    },
    NestedLoopAction {
        statement_index: usize,
        operation_index: usize,
        action_index: usize,
    },
    NestedLoopBranchCondition {
        statement_index: usize,
        operation_index: usize,
        branch_index: usize,
    },
    NestedLoopBranchActions {
        statement_index: usize,
        operation_index: usize,
        branch_index: usize,
        action_count: usize,
    },
    NestedLoopBranchElseActions {
        statement_index: usize,
        operation_index: usize,
        branch_index: usize,
        alternative_index: usize,
        action_count: usize,
    },
    NestedLoopBranchElseCondition {
        statement_index: usize,
        operation_index: usize,
        branch_index: usize,
        alternative_index: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeBasicBlockFact {
    id: RuntimeBasicBlockId,
    source: RuntimeBasicBlockSource,
    first_statement: usize,
    statement_count: usize,
    reachable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeControlFlowTarget {
    Block(RuntimeBasicBlockId),
    Return,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeControlFlowEdgeKind {
    Unconditional,
    True,
    False,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeControlFlowEdgeFact {
    from: RuntimeBasicBlockId,
    target: RuntimeControlFlowTarget,
    kind: RuntimeControlFlowEdgeKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeOwnershipControlPoint {
    Entry,
    Block(RuntimeBasicBlockId),
    Edge(usize),
    Unreachable,
}

struct RuntimeBodyFacts<'source> {
    locals: [Option<RuntimeLocalFact<'source>>; MAX_RUNTIME_LOCAL_FACTS],
    local_count: usize,
    assignment_accesses: [Option<RuntimePlaceAccessFact>; MAX_RUNTIME_PLACE_ACCESS_FACTS],
    assignment_access_count: usize,
    assignment_reads: [Option<RuntimePlaceAccessFact>; MAX_RUNTIME_PLACE_ACCESS_FACTS],
    assignment_read_count: usize,
    accesses: [Option<RuntimePlaceAccessFact>; MAX_RUNTIME_PLACE_ACCESS_FACTS],
    access_count: usize,
    move_paths: [Option<RuntimeMovePathFact>; MAX_RUNTIME_MOVE_PATH_FACTS],
    move_path_count: usize,
    initializations: [Option<RuntimeInitializationFact>; MAX_RUNTIME_INITIALIZATION_FACTS],
    initialization_count: usize,
    effects: [Option<RuntimePlaceEffectFact>; MAX_RUNTIME_PLACE_EFFECT_FACTS],
    effect_count: usize,
    ownership_event_count: usize,
    ownership_events_single_path: bool,
    current_ownership_event_location: RuntimeOwnershipEventLocation,
    current_ownership_expression_path: RuntimeOwnershipExpressionPath,
    conditional_expressions:
        [Option<RuntimeConditionalExpressionFact>; MAX_RUNTIME_OWNERSHIP_EVENT_FACTS],
    conditional_expression_count: usize,
    current_conditional_expression: Option<RuntimeConditionalExpressionId>,
    expression_program_points:
        [Option<RuntimeExpressionProgramPointFact>; MAX_RUNTIME_EXPRESSION_PROGRAM_POINT_FACTS],
    expression_program_point_count: usize,
    current_expression_program_point: Option<RuntimeExpressionProgramPointId>,
    pending_loan_generation_borrower: Option<RuntimeLocalId>,
    current_loan_generation_borrower: Option<RuntimeLocalId>,
    expression_control_flow_edges: [Option<RuntimeExpressionControlFlowEdgeFact>;
        MAX_RUNTIME_EXPRESSION_CONTROL_FLOW_EDGE_FACTS],
    expression_control_flow_edge_count: usize,
    ownership_statement_count: usize,
    ownership_has_tail: bool,
    ownership_statement_shapes:
        [Option<RuntimeOwnershipStatementShape>; crate::parser::MAX_BODY_STATEMENTS],
    basic_blocks: [Option<RuntimeBasicBlockFact>; MAX_RUNTIME_BASIC_BLOCK_FACTS],
    basic_block_count: usize,
    control_flow_edges: [Option<RuntimeControlFlowEdgeFact>; MAX_RUNTIME_CONTROL_FLOW_EDGE_FACTS],
    control_flow_edge_count: usize,
    control_flow_complete: bool,
}

impl<'source> RuntimeBodyFacts<'source> {
    const EMPTY: Self = Self {
        locals: [None; MAX_RUNTIME_LOCAL_FACTS],
        local_count: 0,
        assignment_accesses: [None; MAX_RUNTIME_PLACE_ACCESS_FACTS],
        assignment_access_count: 0,
        assignment_reads: [None; MAX_RUNTIME_PLACE_ACCESS_FACTS],
        assignment_read_count: 0,
        accesses: [None; MAX_RUNTIME_PLACE_ACCESS_FACTS],
        access_count: 0,
        move_paths: [None; MAX_RUNTIME_MOVE_PATH_FACTS],
        move_path_count: 0,
        initializations: [None; MAX_RUNTIME_INITIALIZATION_FACTS],
        initialization_count: 0,
        effects: [None; MAX_RUNTIME_PLACE_EFFECT_FACTS],
        effect_count: 0,
        ownership_event_count: 0,
        ownership_events_single_path: true,
        current_ownership_event_location: RuntimeOwnershipEventLocation::Unassigned,
        current_ownership_expression_path: RuntimeOwnershipExpressionPath::ROOT,
        conditional_expressions: [None; MAX_RUNTIME_OWNERSHIP_EVENT_FACTS],
        conditional_expression_count: 0,
        current_conditional_expression: None,
        expression_program_points: [None; MAX_RUNTIME_EXPRESSION_PROGRAM_POINT_FACTS],
        expression_program_point_count: 0,
        current_expression_program_point: None,
        pending_loan_generation_borrower: None,
        current_loan_generation_borrower: None,
        expression_control_flow_edges: [None; MAX_RUNTIME_EXPRESSION_CONTROL_FLOW_EDGE_FACTS],
        expression_control_flow_edge_count: 0,
        ownership_statement_count: 0,
        ownership_has_tail: false,
        ownership_statement_shapes: [None; crate::parser::MAX_BODY_STATEMENTS],
        basic_blocks: [None; MAX_RUNTIME_BASIC_BLOCK_FACTS],
        basic_block_count: 0,
        control_flow_edges: [None; MAX_RUNTIME_CONTROL_FLOW_EDGE_FACTS],
        control_flow_edge_count: 0,
        control_flow_complete: false,
    };

    fn observe_expression_path_shape<const MAX_NODES: usize>(
        &mut self,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
    ) {
        if tree.nodes().iter().flatten().any(|expression| {
            matches!(
                expression.kind,
                ExprKind::If { .. } | ExprKind::LoopBreakIf { .. }
            )
        }) {
            self.ownership_events_single_path = false;
        }
    }

    fn push_conditional_expression(
        &mut self,
        span: Span,
    ) -> Result<RuntimeConditionalExpressionId, CodegenErrorKind> {
        if span.end < span.start
            || matches!(
                self.current_ownership_event_location,
                RuntimeOwnershipEventLocation::Unassigned
                    | RuntimeOwnershipEventLocation::ParameterEntry
                    | RuntimeOwnershipEventLocation::EmissionExpansion
            )
        {
            return Err(CodegenErrorKind::InvalidRuntimePlaceFacts);
        }
        if self.conditional_expression_count >= self.conditional_expressions.len() {
            return Err(CodegenErrorKind::TooManyRuntimeOwnershipEventFacts);
        }
        let has_current_point = self
            .current_expression_program_point
            .is_some_and(|current| {
                self.expression_program_points
                    .get(current.0)
                    .and_then(|point| *point)
                    .is_some_and(|point| point.location == self.current_ownership_event_location)
            });
        let additional_points = if has_current_point { 4 } else { 5 };
        if self
            .expression_program_point_count
            .checked_add(additional_points)
            .is_none_or(|count| count > self.expression_program_points.len())
        {
            return Err(CodegenErrorKind::TooManyRuntimeOwnershipEventFacts);
        }
        let entry = self.ensure_expression_program_point()?;
        let id = RuntimeConditionalExpressionId(self.conditional_expression_count);
        let condition =
            self.push_expression_program_point(RuntimeExpressionProgramPointKind::Condition(id))?;
        let then_branch =
            self.push_expression_program_point(RuntimeExpressionProgramPointKind::Then(id))?;
        let else_branch =
            self.push_expression_program_point(RuntimeExpressionProgramPointKind::Else(id))?;
        let join =
            self.push_expression_program_point(RuntimeExpressionProgramPointKind::Join(id))?;
        self.conditional_expressions[self.conditional_expression_count] =
            Some(RuntimeConditionalExpressionFact {
                id,
                location: self.current_ownership_event_location,
                span,
                parent: self.current_conditional_expression,
                parent_path: self.current_ownership_expression_path,
                entry,
                condition,
                then_branch,
                else_branch,
                join,
                then_exit: None,
                else_exit: None,
            });
        self.conditional_expression_count += 1;
        Ok(id)
    }

    fn push_expression_program_point(
        &mut self,
        kind: RuntimeExpressionProgramPointKind,
    ) -> Result<RuntimeExpressionProgramPointId, CodegenErrorKind> {
        let slot = self
            .expression_program_points
            .get_mut(self.expression_program_point_count)
            .ok_or(CodegenErrorKind::TooManyRuntimeOwnershipEventFacts)?;
        let id = RuntimeExpressionProgramPointId(self.expression_program_point_count);
        *slot = Some(RuntimeExpressionProgramPointFact {
            id,
            location: self.current_ownership_event_location,
            kind,
        });
        self.expression_program_point_count += 1;
        Ok(id)
    }

    fn ensure_expression_program_point(
        &mut self,
    ) -> Result<RuntimeExpressionProgramPointId, CodegenErrorKind> {
        if let Some(current) = self.current_expression_program_point
            && self
                .expression_program_points
                .get(current.0)
                .and_then(|point| *point)
                .is_some_and(|point| point.location == self.current_ownership_event_location)
        {
            return Ok(current);
        }
        let root = self.push_expression_program_point(RuntimeExpressionProgramPointKind::Root)?;
        self.current_expression_program_point = Some(root);
        Ok(root)
    }

    fn current_expression_program_point_at_location(
        &self,
    ) -> Option<RuntimeExpressionProgramPointId> {
        self.current_expression_program_point.filter(|point| {
            self.expression_program_points
                .get(point.0)
                .and_then(|point| *point)
                .is_some_and(|point| point.location == self.current_ownership_event_location)
        })
    }

    fn set_conditional_expression_exit(
        &mut self,
        conditional: RuntimeConditionalExpressionId,
        else_branch: bool,
        exit: RuntimeExpressionProgramPointId,
    ) -> Result<(), CodegenErrorKind> {
        let fact = self
            .conditional_expressions
            .get_mut(conditional.0)
            .and_then(Option::as_mut)
            .ok_or(CodegenErrorKind::InvalidRuntimePlaceFacts)?;
        let slot = if else_branch {
            &mut fact.else_exit
        } else {
            &mut fact.then_exit
        };
        if slot.is_some() {
            return Err(CodegenErrorKind::InvalidRuntimePlaceFacts);
        }
        *slot = Some(exit);
        Ok(())
    }

    fn push_expression_control_flow_edge(
        &mut self,
        edge: RuntimeExpressionControlFlowEdgeFact,
    ) -> Result<(), CodegenErrorKind> {
        let slot = self
            .expression_control_flow_edges
            .get_mut(self.expression_control_flow_edge_count)
            .ok_or(CodegenErrorKind::TooManyRuntimeControlFlowEdgeFacts)?;
        *slot = Some(edge);
        self.expression_control_flow_edge_count += 1;
        Ok(())
    }

    fn build_expression_control_flow(&mut self) -> Result<(), CodegenErrorKind> {
        if self.expression_control_flow_edge_count != 0 {
            return Err(CodegenErrorKind::InvalidRuntimeControlFlowFacts);
        }
        let required_edges = self
            .conditional_expression_count
            .checked_mul(5)
            .ok_or(CodegenErrorKind::TooManyRuntimeControlFlowEdgeFacts)?;
        if required_edges > self.expression_control_flow_edges.len() {
            return Err(CodegenErrorKind::TooManyRuntimeControlFlowEdgeFacts);
        }
        for index in 0..self.conditional_expression_count {
            let conditional = self.conditional_expressions[index]
                .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
            let then_exit = conditional
                .then_exit
                .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
            let else_exit = conditional
                .else_exit
                .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
            for edge in [
                RuntimeExpressionControlFlowEdgeFact {
                    from: conditional.entry,
                    to: conditional.condition,
                },
                RuntimeExpressionControlFlowEdgeFact {
                    from: conditional.condition,
                    to: conditional.then_branch,
                },
                RuntimeExpressionControlFlowEdgeFact {
                    from: conditional.condition,
                    to: conditional.else_branch,
                },
                RuntimeExpressionControlFlowEdgeFact {
                    from: then_exit,
                    to: conditional.join,
                },
                RuntimeExpressionControlFlowEdgeFact {
                    from: else_exit,
                    to: conditional.join,
                },
            ] {
                self.push_expression_control_flow_edge(edge)?;
            }
        }
        Ok(())
    }

    fn record_ownership_statement_shapes<const MAX_PARAMETERS: usize>(
        &mut self,
        body: &crate::FunctionBody<'_, MAX_PARAMETERS>,
    ) -> Result<(), CodegenErrorKind> {
        for (statement_index, statement) in body.statements().iter().flatten().enumerate() {
            let shape = match statement {
                crate::BodyStatement::ConditionalReturn(index) => {
                    body.conditional_returns()
                        .get(*index)
                        .and_then(|value| *value)
                        .ok_or(CodegenErrorKind::InvalidRuntimePlaceFacts)?;
                    RuntimeOwnershipStatementShape::ConditionalReturn {
                        branch_count: 1,
                        has_else: false,
                    }
                }
                crate::BodyStatement::ConditionalReturnElse(index) => {
                    let conditional = body
                        .conditional_return_elses()
                        .get(*index)
                        .and_then(|value| *value)
                        .ok_or(CodegenErrorKind::InvalidRuntimePlaceFacts)?;
                    RuntimeOwnershipStatementShape::ConditionalReturn {
                        branch_count: conditional.branches().iter().flatten().count(),
                        has_else: conditional.else_value.is_some(),
                    }
                }
                crate::BodyStatement::ConditionalAssignment(index) => {
                    let conditional = body
                        .conditional_assignments()
                        .get(*index)
                        .and_then(|value| *value)
                        .ok_or(CodegenErrorKind::InvalidRuntimePlaceFacts)?;
                    let branch_count = conditional.branches().iter().flatten().count();
                    let mut action_counts = [0; MAX_RUNTIME_CONDITIONAL_ACTION_ORIGINS];
                    for (branch_index, branch) in
                        conditional.branches().iter().flatten().enumerate()
                    {
                        action_counts[branch_index] = branch.actions().iter().flatten().count();
                    }
                    action_counts[crate::parser::MAX_CONDITIONAL_ASSIGNMENT_BRANCHES] =
                        conditional.else_actions().iter().flatten().count();
                    RuntimeOwnershipStatementShape::ConditionalAssignment {
                        branch_count,
                        action_counts,
                    }
                }
                crate::BodyStatement::Return(index) => {
                    body.returns()
                        .get(*index)
                        .and_then(|value| *value)
                        .ok_or(CodegenErrorKind::InvalidRuntimePlaceFacts)?;
                    RuntimeOwnershipStatementShape::Return
                }
                crate::BodyStatement::Loop(index) => {
                    let loop_statement = body
                        .while_loops()
                        .get(*index)
                        .and_then(Option::as_ref)
                        .ok_or(CodegenErrorKind::InvalidRuntimePlaceFacts)?;
                    RuntimeOwnershipStatementShape::Loop {
                        operation_count: loop_statement.operations().iter().flatten().count(),
                    }
                }
                crate::BodyStatement::Local(_)
                | crate::BodyStatement::Assignment(_)
                | crate::BodyStatement::Expression(_) => RuntimeOwnershipStatementShape::Plain,
            };
            self.ownership_statement_shapes[statement_index] = Some(shape);
        }
        Ok(())
    }

    fn ownership_location_is_valid(&self, location: RuntimeOwnershipEventLocation) -> bool {
        let shape = runtime_ownership_location_statement_index(location)
            .and_then(|index| self.ownership_statement_shapes.get(index))
            .and_then(|shape| *shape);
        match (location, shape) {
            (RuntimeOwnershipEventLocation::ParameterEntry, _)
            | (RuntimeOwnershipEventLocation::EmissionExpansion, _) => true,
            (RuntimeOwnershipEventLocation::Tail, _) => self.ownership_has_tail,
            (RuntimeOwnershipEventLocation::TopLevelStatement(_), Some(shape)) => {
                shape == RuntimeOwnershipStatementShape::Plain
            }
            (
                RuntimeOwnershipEventLocation::ConditionalReturnCondition { branch_index, .. }
                | RuntimeOwnershipEventLocation::ConditionalReturnValue { branch_index, .. },
                Some(RuntimeOwnershipStatementShape::ConditionalReturn { branch_count, .. }),
            ) => branch_index < branch_count,
            (
                RuntimeOwnershipEventLocation::ConditionalReturnElseValue { .. },
                Some(RuntimeOwnershipStatementShape::ConditionalReturn { has_else, .. }),
            ) => has_else,
            (
                RuntimeOwnershipEventLocation::ConditionalAssignmentCondition {
                    branch_index, ..
                },
                Some(RuntimeOwnershipStatementShape::ConditionalAssignment {
                    branch_count, ..
                }),
            ) => branch_index < branch_count,
            (
                RuntimeOwnershipEventLocation::ConditionalAssignmentAction {
                    branch_index,
                    action_index,
                    ..
                }
                | RuntimeOwnershipEventLocation::ConditionalAssignmentReturnValue {
                    branch_index,
                    action_index,
                    ..
                },
                Some(RuntimeOwnershipStatementShape::ConditionalAssignment {
                    branch_count,
                    action_counts,
                }),
            ) => {
                let slot =
                    branch_index.unwrap_or(crate::parser::MAX_CONDITIONAL_ASSIGNMENT_BRANCHES);
                slot < action_counts.len()
                    && branch_index.is_none_or(|index| index < branch_count)
                    && action_index < action_counts[slot]
            }
            (
                RuntimeOwnershipEventLocation::ReturnValue { .. },
                Some(RuntimeOwnershipStatementShape::Return),
            ) => true,
            (
                RuntimeOwnershipEventLocation::LoopHeader { .. },
                Some(RuntimeOwnershipStatementShape::Loop { .. }),
            ) => true,
            (
                RuntimeOwnershipEventLocation::LoopOperation {
                    operation_index, ..
                }
                | RuntimeOwnershipEventLocation::LoopConditionalReturnCondition {
                    operation_index,
                    ..
                }
                | RuntimeOwnershipEventLocation::LoopConditionalReturnValue {
                    operation_index, ..
                }
                | RuntimeOwnershipEventLocation::LoopReturnValue {
                    operation_index, ..
                }
                | RuntimeOwnershipEventLocation::LoopConditionalCondition {
                    operation_index, ..
                }
                | RuntimeOwnershipEventLocation::LoopConditionalAction {
                    operation_index, ..
                }
                | RuntimeOwnershipEventLocation::LoopConditionalTerminal {
                    operation_index, ..
                }
                | RuntimeOwnershipEventLocation::NestedLoopHeader {
                    operation_index, ..
                }
                | RuntimeOwnershipEventLocation::NestedLoopControlCondition {
                    operation_index, ..
                }
                | RuntimeOwnershipEventLocation::NestedLoopControlValue {
                    operation_index, ..
                }
                | RuntimeOwnershipEventLocation::NestedLoopAction {
                    operation_index, ..
                }
                | RuntimeOwnershipEventLocation::NestedLoopBranchCondition {
                    operation_index, ..
                }
                | RuntimeOwnershipEventLocation::NestedLoopBranchAction {
                    operation_index, ..
                }
                | RuntimeOwnershipEventLocation::NestedLoopBranchValue {
                    operation_index, ..
                }
                | RuntimeOwnershipEventLocation::NestedLoopBranchElseAction {
                    operation_index, ..
                }
                | RuntimeOwnershipEventLocation::NestedLoopBranchElseCondition {
                    operation_index,
                    ..
                }
                | RuntimeOwnershipEventLocation::NestedLoopBranchElseValue {
                    operation_index, ..
                },
                Some(RuntimeOwnershipStatementShape::Loop { operation_count }),
            ) => operation_index < operation_count,
            (RuntimeOwnershipEventLocation::Unassigned, _)
            | (RuntimeOwnershipEventLocation::TopLevelStatement(_), _)
            | (RuntimeOwnershipEventLocation::ConditionalReturnCondition { .. }, _)
            | (RuntimeOwnershipEventLocation::ConditionalReturnValue { .. }, _)
            | (RuntimeOwnershipEventLocation::ConditionalReturnElseValue { .. }, _)
            | (RuntimeOwnershipEventLocation::ConditionalAssignmentCondition { .. }, _)
            | (RuntimeOwnershipEventLocation::ConditionalAssignmentAction { .. }, _)
            | (RuntimeOwnershipEventLocation::ConditionalAssignmentReturnValue { .. }, _)
            | (RuntimeOwnershipEventLocation::LoopHeader { .. }, _)
            | (RuntimeOwnershipEventLocation::LoopOperation { .. }, _)
            | (RuntimeOwnershipEventLocation::LoopConditionalReturnCondition { .. }, _)
            | (RuntimeOwnershipEventLocation::LoopConditionalReturnValue { .. }, _)
            | (RuntimeOwnershipEventLocation::LoopReturnValue { .. }, _)
            | (RuntimeOwnershipEventLocation::LoopConditionalCondition { .. }, _)
            | (RuntimeOwnershipEventLocation::LoopConditionalAction { .. }, _)
            | (RuntimeOwnershipEventLocation::LoopConditionalTerminal { .. }, _)
            | (RuntimeOwnershipEventLocation::NestedLoopHeader { .. }, _)
            | (RuntimeOwnershipEventLocation::NestedLoopControlCondition { .. }, _)
            | (RuntimeOwnershipEventLocation::NestedLoopControlValue { .. }, _)
            | (RuntimeOwnershipEventLocation::NestedLoopAction { .. }, _)
            | (RuntimeOwnershipEventLocation::NestedLoopBranchCondition { .. }, _)
            | (RuntimeOwnershipEventLocation::NestedLoopBranchAction { .. }, _)
            | (RuntimeOwnershipEventLocation::NestedLoopBranchValue { .. }, _)
            | (RuntimeOwnershipEventLocation::NestedLoopBranchElseAction { .. }, _)
            | (RuntimeOwnershipEventLocation::NestedLoopBranchElseCondition { .. }, _)
            | (RuntimeOwnershipEventLocation::NestedLoopBranchElseValue { .. }, _)
            | (RuntimeOwnershipEventLocation::ReturnValue { .. }, _) => false,
        }
    }

    fn expression_origin_is_valid(
        &self,
        location: RuntimeOwnershipEventLocation,
        path: RuntimeOwnershipExpressionPath,
        conditional: Option<RuntimeConditionalExpressionId>,
    ) -> bool {
        if !path.is_valid() {
            return false;
        }
        let Some(conditional) = conditional else {
            return path == RuntimeOwnershipExpressionPath::ROOT;
        };
        let Some(fact) = self
            .conditional_expressions
            .get(conditional.0)
            .and_then(|fact| *fact)
        else {
            return false;
        };
        if fact.id != conditional || fact.location != location {
            return false;
        }
        if path == fact.parent_path {
            return true;
        }
        path.depth == fact.parent_path.depth + 1
            && (path.else_bits & ((1u64 << fact.parent_path.depth).wrapping_sub(1)))
                == fact.parent_path.else_bits
    }

    fn expression_program_point_is_valid(
        &self,
        location: RuntimeOwnershipEventLocation,
        point: RuntimeExpressionProgramPointId,
    ) -> bool {
        self.expression_program_points
            .get(point.0)
            .and_then(|point| *point)
            .is_some_and(|point| {
                point.id.0 < self.expression_program_point_count && point.location == location
            })
    }

    fn top_level_block_for_statement(&self, statement_index: usize) -> Option<RuntimeBasicBlockId> {
        self.basic_blocks[..self.basic_block_count]
            .iter()
            .flatten()
            .find(|block| {
                block.source == RuntimeBasicBlockSource::TopLevel
                    && statement_index >= block.first_statement
                    && block
                        .first_statement
                        .checked_add(block.statement_count)
                        .is_some_and(|end| statement_index < end)
            })
            .map(|block| block.id)
    }

    fn block_with_source(&self, source: RuntimeBasicBlockSource) -> Option<RuntimeBasicBlockId> {
        self.basic_blocks[..self.basic_block_count]
            .iter()
            .flatten()
            .find(|block| block.source == source)
            .map(|block| block.id)
    }

    fn block_with_source_matching(
        &self,
        matches_source: impl Fn(RuntimeBasicBlockSource) -> bool,
    ) -> Option<RuntimeBasicBlockId> {
        self.basic_blocks[..self.basic_block_count]
            .iter()
            .flatten()
            .find(|block| matches_source(block.source))
            .map(|block| block.id)
    }

    fn return_edge(
        &self,
        from: RuntimeBasicBlockId,
        kind: RuntimeControlFlowEdgeKind,
    ) -> Option<usize> {
        self.control_flow_edges[..self.control_flow_edge_count]
            .iter()
            .position(|edge| {
                edge.is_some_and(|edge| {
                    edge.from == from
                        && edge.target == RuntimeControlFlowTarget::Return
                        && edge.kind == kind
                })
            })
    }

    fn conditional_return_block(
        &self,
        statement_index: usize,
        branch_index: usize,
    ) -> Option<RuntimeBasicBlockId> {
        if branch_index == 0 {
            self.top_level_block_for_statement(statement_index)
        } else {
            self.block_with_source(RuntimeBasicBlockSource::ConditionalReturnBranch {
                statement_index,
                branch_index,
            })
        }
    }

    fn conditional_assignment_action_block(
        &self,
        statement_index: usize,
        branch_index: Option<usize>,
        action_index: usize,
    ) -> Option<RuntimeBasicBlockId> {
        if let Some(block) = self.basic_blocks[..self.basic_block_count]
            .iter()
            .flatten()
            .find(|block| {
                matches!(
                    block.source,
                    RuntimeBasicBlockSource::ConditionalAssignmentUnreachableActions {
                        statement_index: source_statement,
                        branch_index: source_branch,
                        first_action,
                        action_count,
                    } if source_statement == statement_index
                        && source_branch == branch_index
                        && action_index >= first_action
                        && first_action
                            .checked_add(action_count)
                            .is_some_and(|end| action_index < end)
                )
            })
        {
            return Some(block.id);
        }
        self.block_with_source(match branch_index {
            Some(branch_index) => RuntimeBasicBlockSource::ConditionalAssignmentActions {
                statement_index,
                branch_index,
            },
            None => RuntimeBasicBlockSource::ConditionalAssignmentElseActions { statement_index },
        })
    }

    fn loop_body_block_for_operation(
        &self,
        statement_index: usize,
        operation_index: usize,
    ) -> Option<RuntimeBasicBlockId> {
        self.basic_blocks[..self.basic_block_count]
            .iter()
            .flatten()
            .find(|block| {
                matches!(
                    block.source,
                    RuntimeBasicBlockSource::LoopBody {
                        statement_index: source_statement,
                        first_operation,
                        operation_count,
                    } if source_statement == statement_index
                        && operation_index >= first_operation
                        && first_operation
                            .checked_add(operation_count)
                            .is_some_and(|end| operation_index < end)
                )
            })
            .map(|block| block.id)
    }

    fn loop_conditional_action_block(
        &self,
        statement_index: usize,
        operation_index: usize,
        arm_index: usize,
        action_index: Option<usize>,
    ) -> Option<RuntimeBasicBlockId> {
        self.basic_blocks[..self.basic_block_count]
            .iter()
            .flatten()
            .find(|block| {
                matches!(
                    block.source,
                    RuntimeBasicBlockSource::LoopConditionalActions {
                        statement_index: source_statement,
                        operation_index: source_operation,
                        arm_index: source_arm,
                        action_count,
                    } if source_statement == statement_index
                        && source_operation == operation_index
                        && source_arm == arm_index
                        && action_index.is_none_or(|index| index < action_count)
                )
            })
            .map(|block| block.id)
    }

    fn nested_loop_control_block(
        &self,
        statement_index: usize,
        operation_index: usize,
        action_index: usize,
        control_order: usize,
    ) -> Option<RuntimeBasicBlockId> {
        self.block_with_source(RuntimeBasicBlockSource::NestedLoopControl {
            statement_index,
            operation_index,
            action_index,
            control_order,
        })
    }

    fn ownership_control_point(
        &self,
        location: RuntimeOwnershipEventLocation,
    ) -> Option<RuntimeOwnershipControlPoint> {
        if !self.control_flow_complete {
            return None;
        }
        match location {
            RuntimeOwnershipEventLocation::ParameterEntry => {
                Some(RuntimeOwnershipControlPoint::Entry)
            }
            RuntimeOwnershipEventLocation::TopLevelStatement(statement_index)
            | RuntimeOwnershipEventLocation::ReturnValue { statement_index } => self
                .top_level_block_for_statement(statement_index)
                .map(RuntimeOwnershipControlPoint::Block),
            RuntimeOwnershipEventLocation::ConditionalReturnCondition {
                statement_index,
                branch_index,
            } => self
                .conditional_return_block(statement_index, branch_index)
                .map(RuntimeOwnershipControlPoint::Block),
            RuntimeOwnershipEventLocation::ConditionalReturnValue {
                statement_index,
                branch_index,
            } => {
                let block = self.conditional_return_block(statement_index, branch_index)?;
                self.return_edge(block, RuntimeControlFlowEdgeKind::True)
                    .map(RuntimeOwnershipControlPoint::Edge)
            }
            RuntimeOwnershipEventLocation::ConditionalReturnElseValue { statement_index } => {
                let RuntimeOwnershipStatementShape::ConditionalReturn { branch_count, .. } = self
                    .ownership_statement_shapes
                    .get(statement_index)
                    .and_then(|shape| *shape)?
                else {
                    return None;
                };
                let block =
                    self.conditional_return_block(statement_index, branch_count.checked_sub(1)?)?;
                self.return_edge(block, RuntimeControlFlowEdgeKind::False)
                    .map(RuntimeOwnershipControlPoint::Edge)
            }
            RuntimeOwnershipEventLocation::ConditionalAssignmentCondition {
                statement_index,
                branch_index,
            } => {
                let block = if branch_index == 0 {
                    self.top_level_block_for_statement(statement_index)
                } else {
                    self.block_with_source(
                        RuntimeBasicBlockSource::ConditionalAssignmentCondition {
                            statement_index,
                            branch_index,
                        },
                    )
                }?;
                Some(RuntimeOwnershipControlPoint::Block(block))
            }
            RuntimeOwnershipEventLocation::ConditionalAssignmentAction {
                statement_index,
                branch_index,
                action_index,
            } => self
                .conditional_assignment_action_block(statement_index, branch_index, action_index)
                .map(RuntimeOwnershipControlPoint::Block),
            RuntimeOwnershipEventLocation::ConditionalAssignmentReturnValue {
                statement_index,
                branch_index,
                action_index,
            } => {
                let block = self.conditional_assignment_action_block(
                    statement_index,
                    branch_index,
                    action_index,
                )?;
                self.return_edge(block, RuntimeControlFlowEdgeKind::Unconditional)
                    .map(RuntimeOwnershipControlPoint::Edge)
            }
            RuntimeOwnershipEventLocation::LoopHeader { statement_index } => self
                .top_level_block_for_statement(statement_index)
                .map(RuntimeOwnershipControlPoint::Block),
            RuntimeOwnershipEventLocation::LoopOperation {
                statement_index,
                operation_index,
            }
            | RuntimeOwnershipEventLocation::LoopConditionalReturnCondition {
                statement_index,
                operation_index,
            } => self
                .loop_body_block_for_operation(statement_index, operation_index)
                .map(RuntimeOwnershipControlPoint::Block),
            RuntimeOwnershipEventLocation::LoopConditionalReturnValue {
                statement_index,
                operation_index,
            } => {
                let block = self.loop_body_block_for_operation(statement_index, operation_index)?;
                self.return_edge(block, RuntimeControlFlowEdgeKind::True)
                    .map(RuntimeOwnershipControlPoint::Edge)
            }
            RuntimeOwnershipEventLocation::LoopReturnValue {
                statement_index,
                operation_index,
            } => {
                let block = self.loop_body_block_for_operation(statement_index, operation_index)?;
                self.return_edge(block, RuntimeControlFlowEdgeKind::Unconditional)
                    .map(RuntimeOwnershipControlPoint::Edge)
            }
            RuntimeOwnershipEventLocation::LoopConditionalCondition {
                statement_index,
                operation_index,
                arm_index,
            } => {
                let block = if arm_index == 0 {
                    self.loop_body_block_for_operation(statement_index, operation_index)
                } else {
                    self.block_with_source(RuntimeBasicBlockSource::LoopConditionalCondition {
                        statement_index,
                        operation_index,
                        arm_index,
                    })
                }?;
                Some(RuntimeOwnershipControlPoint::Block(block))
            }
            RuntimeOwnershipEventLocation::LoopConditionalAction {
                statement_index,
                operation_index,
                arm_index,
                action_index,
            } => self
                .loop_conditional_action_block(
                    statement_index,
                    operation_index,
                    arm_index,
                    Some(action_index),
                )
                .map(RuntimeOwnershipControlPoint::Block),
            RuntimeOwnershipEventLocation::LoopConditionalTerminal {
                statement_index,
                operation_index,
                arm_index,
            } => {
                let block = self.loop_conditional_action_block(
                    statement_index,
                    operation_index,
                    arm_index,
                    None,
                )?;
                self.return_edge(block, RuntimeControlFlowEdgeKind::Unconditional)
                    .map(RuntimeOwnershipControlPoint::Edge)
            }
            RuntimeOwnershipEventLocation::NestedLoopHeader {
                statement_index,
                operation_index,
            } => self
                .block_with_source(RuntimeBasicBlockSource::NestedLoopHeader {
                    statement_index,
                    operation_index,
                })
                .map(RuntimeOwnershipControlPoint::Block),
            RuntimeOwnershipEventLocation::NestedLoopControlCondition {
                statement_index,
                operation_index,
                action_index,
                control_order,
            } => self
                .nested_loop_control_block(
                    statement_index,
                    operation_index,
                    action_index,
                    control_order,
                )
                .map(RuntimeOwnershipControlPoint::Block),
            RuntimeOwnershipEventLocation::NestedLoopControlValue {
                statement_index,
                operation_index,
                action_index,
                control_order,
            } => {
                let block = self.nested_loop_control_block(
                    statement_index,
                    operation_index,
                    action_index,
                    control_order,
                )?;
                self.return_edge(block, RuntimeControlFlowEdgeKind::True)
                    .or_else(|| self.return_edge(block, RuntimeControlFlowEdgeKind::Unconditional))
                    .map(RuntimeOwnershipControlPoint::Edge)
            }
            RuntimeOwnershipEventLocation::NestedLoopAction {
                statement_index,
                operation_index,
                action_index,
            } => self
                .block_with_source(RuntimeBasicBlockSource::NestedLoopAction {
                    statement_index,
                    operation_index,
                    action_index,
                })
                .map(RuntimeOwnershipControlPoint::Block),
            RuntimeOwnershipEventLocation::NestedLoopBranchCondition {
                statement_index,
                operation_index,
                branch_index,
            } => self
                .block_with_source(RuntimeBasicBlockSource::NestedLoopBranchCondition {
                    statement_index,
                    operation_index,
                    branch_index,
                })
                .map(RuntimeOwnershipControlPoint::Block),
            RuntimeOwnershipEventLocation::NestedLoopBranchAction {
                statement_index,
                operation_index,
                branch_index,
                ..
            } => self
                .block_with_source_matching(|source| {
                    matches!(
                        source,
                        RuntimeBasicBlockSource::NestedLoopBranchActions {
                            statement_index: stored_statement,
                            operation_index: stored_operation,
                            branch_index: stored_branch,
                            ..
                        } if stored_statement == statement_index
                            && stored_operation == operation_index
                            && stored_branch == branch_index
                    )
                })
                .map(RuntimeOwnershipControlPoint::Block),
            RuntimeOwnershipEventLocation::NestedLoopBranchValue {
                statement_index,
                operation_index,
                branch_index,
            } => {
                let block = self.block_with_source_matching(|source| {
                    matches!(
                        source,
                        RuntimeBasicBlockSource::NestedLoopBranchActions {
                            statement_index: stored_statement,
                            operation_index: stored_operation,
                            branch_index: stored_branch,
                            ..
                        } if stored_statement == statement_index
                            && stored_operation == operation_index
                            && stored_branch == branch_index
                    )
                })?;
                self.return_edge(block, RuntimeControlFlowEdgeKind::Unconditional)
                    .map(RuntimeOwnershipControlPoint::Edge)
            }
            RuntimeOwnershipEventLocation::NestedLoopBranchElseAction {
                statement_index,
                operation_index,
                branch_index,
                alternative_index,
                ..
            } => self
                .block_with_source_matching(|source| {
                    matches!(
                        source,
                        RuntimeBasicBlockSource::NestedLoopBranchElseActions {
                            statement_index: stored_statement,
                            operation_index: stored_operation,
                            branch_index: stored_branch,
                            alternative_index: stored_alternative,
                            ..
                        } if stored_statement == statement_index
                            && stored_operation == operation_index
                            && stored_branch == branch_index
                            && stored_alternative == alternative_index
                    )
                })
                .map(RuntimeOwnershipControlPoint::Block),
            RuntimeOwnershipEventLocation::NestedLoopBranchElseCondition {
                statement_index,
                operation_index,
                branch_index,
                alternative_index,
            } => self
                .block_with_source(RuntimeBasicBlockSource::NestedLoopBranchElseCondition {
                    statement_index,
                    operation_index,
                    branch_index,
                    alternative_index,
                })
                .map(RuntimeOwnershipControlPoint::Block),
            RuntimeOwnershipEventLocation::NestedLoopBranchElseValue {
                statement_index,
                operation_index,
                branch_index,
                alternative_index,
            } => {
                let block = self.block_with_source_matching(|source| {
                    matches!(
                        source,
                        RuntimeBasicBlockSource::NestedLoopBranchElseActions {
                            statement_index: stored_statement,
                            operation_index: stored_operation,
                            branch_index: stored_branch,
                            alternative_index: stored_alternative,
                            ..
                        } if stored_statement == statement_index
                            && stored_operation == operation_index
                            && stored_branch == branch_index
                            && stored_alternative == alternative_index
                    )
                })?;
                self.return_edge(block, RuntimeControlFlowEdgeKind::Unconditional)
                    .map(RuntimeOwnershipControlPoint::Edge)
            }
            RuntimeOwnershipEventLocation::Tail => {
                let Some(block) = self.basic_blocks[..self.basic_block_count]
                    .iter()
                    .flatten()
                    .filter(|block| block.source == RuntimeBasicBlockSource::TopLevel)
                    .max_by_key(|block| block.first_statement)
                else {
                    return self
                        .ownership_has_tail
                        .then_some(RuntimeOwnershipControlPoint::Unreachable);
                };
                self.return_edge(block.id, RuntimeControlFlowEdgeKind::Unconditional)
                    .map(RuntimeOwnershipControlPoint::Edge)
                    .or_else(|| {
                        (self.ownership_has_tail
                            && self.control_flow_edges[..self.control_flow_edge_count]
                                .iter()
                                .flatten()
                                .any(|edge| edge.from == block.id))
                        .then_some(RuntimeOwnershipControlPoint::Unreachable)
                    })
            }
            RuntimeOwnershipEventLocation::Unassigned
            | RuntimeOwnershipEventLocation::EmissionExpansion => None,
        }
    }

    fn push_local(
        &mut self,
        name: &'source str,
        ty: RuntimeExpressionType,
        mutable: bool,
        initialized: bool,
        declaration_span: Option<Span>,
    ) -> Result<RuntimeLocalId, CodegenErrorKind> {
        if self.local_count >= self.locals.len() {
            return Err(CodegenErrorKind::TooManyRuntimeLocalFacts);
        }
        let id = RuntimeLocalId(self.local_count);
        self.push_move_path_root(
            RuntimePlaceIdentity::Local(id),
            ty,
            RuntimeInitializationOrigin::LocalDeclaration,
            declaration_span,
            initialized,
        )?;
        self.locals[self.local_count] = Some(RuntimeLocalFact {
            id,
            name,
            ty,
            mutable,
            initialized,
            declaration_span,
        });
        self.local_count += 1;
        Ok(id)
    }

    fn push_initialized_move_path_root(
        &mut self,
        base: RuntimePlaceIdentity,
        ty: RuntimeExpressionType,
        origin: RuntimeInitializationOrigin,
        span: Option<Span>,
    ) -> Result<RuntimeMovePathId, CodegenErrorKind> {
        self.push_move_path_root(base, ty, origin, span, true)
    }

    fn push_move_path_root(
        &mut self,
        base: RuntimePlaceIdentity,
        ty: RuntimeExpressionType,
        origin: RuntimeInitializationOrigin,
        span: Option<Span>,
        initialized: bool,
    ) -> Result<RuntimeMovePathId, CodegenErrorKind> {
        let child_count = match ty {
            RuntimeExpressionType::Tuple {
                elements,
                element_count,
            } => {
                if element_count > elements.len()
                    || elements[..element_count].iter().any(Option::is_none)
                {
                    return Err(CodegenErrorKind::InvalidRuntimePlaceFacts);
                }
                element_count
            }
            _ => 0,
        };
        let required_paths = child_count
            .checked_add(1)
            .and_then(|count| self.move_path_count.checked_add(count))
            .ok_or(CodegenErrorKind::TooManyRuntimeMovePathFacts)?;
        if required_paths > self.move_paths.len() {
            return Err(CodegenErrorKind::TooManyRuntimeMovePathFacts);
        }
        if initialized && self.initialization_count >= self.initializations.len() {
            return Err(CodegenErrorKind::TooManyRuntimeInitializationFacts);
        }
        if initialized && self.ownership_event_count >= MAX_RUNTIME_OWNERSHIP_EVENT_FACTS {
            return Err(CodegenErrorKind::TooManyRuntimeOwnershipEventFacts);
        }
        let root = RuntimeMovePathId(self.move_path_count);
        self.move_paths[self.move_path_count] = Some(RuntimeMovePathFact {
            id: root,
            parent: None,
            base,
            projections: RuntimePlaceProjections::EMPTY,
            ty,
        });
        self.move_path_count += 1;
        if let RuntimeExpressionType::Tuple {
            elements,
            element_count,
        } = ty
        {
            for (field, element) in elements[..element_count].iter().enumerate() {
                let element = element.ok_or(CodegenErrorKind::InvalidRuntimePlaceFacts)?;
                let id = RuntimeMovePathId(self.move_path_count);
                self.move_paths[self.move_path_count] = Some(RuntimeMovePathFact {
                    id,
                    parent: Some(root),
                    base,
                    projections: RuntimePlaceProjections::single(
                        RuntimePlaceProjection::TupleField(field),
                    ),
                    ty: runtime_type_from_tuple_element(element),
                });
                self.move_path_count += 1;
            }
        }
        if initialized {
            self.initializations[self.initialization_count] = Some(RuntimeInitializationFact {
                path: root,
                origin,
                span,
                event: RuntimeOwnershipEventId(self.ownership_event_count),
                location: match origin {
                    RuntimeInitializationOrigin::Parameter => {
                        RuntimeOwnershipEventLocation::ParameterEntry
                    }
                    RuntimeInitializationOrigin::LocalDeclaration => {
                        self.current_ownership_event_location
                    }
                },
                expression_path: match origin {
                    RuntimeInitializationOrigin::Parameter => RuntimeOwnershipExpressionPath::ROOT,
                    RuntimeInitializationOrigin::LocalDeclaration => {
                        self.current_ownership_expression_path
                    }
                },
                expression_conditional: match origin {
                    RuntimeInitializationOrigin::Parameter => None,
                    RuntimeInitializationOrigin::LocalDeclaration => {
                        self.current_conditional_expression
                    }
                },
                expression_point: match origin {
                    RuntimeInitializationOrigin::Parameter => None,
                    RuntimeInitializationOrigin::LocalDeclaration => {
                        self.current_expression_program_point_at_location()
                    }
                },
            });
            self.initialization_count += 1;
            self.ownership_event_count += 1;
        }
        Ok(root)
    }

    fn push_initialized_parameter(
        &mut self,
        index: usize,
        ty: RuntimeExpressionType,
        span: Option<Span>,
    ) -> Result<(), CodegenErrorKind> {
        self.push_initialized_move_path_root(
            RuntimePlaceIdentity::Parameter(index),
            ty,
            RuntimeInitializationOrigin::Parameter,
            span,
        )?;
        Ok(())
    }

    fn find_move_path(
        &self,
        base: RuntimePlaceIdentity,
        projections: RuntimePlaceProjections,
    ) -> Option<RuntimeMovePathId> {
        self.move_paths
            .get(..self.move_path_count)?
            .iter()
            .flatten()
            .find(|path| path.base == base && path.projections == projections)
            .map(|path| path.id)
    }

    fn push_place_effect(
        &mut self,
        path: RuntimeMovePathId,
        kind: RuntimePlaceEffectKind,
        span: Span,
    ) -> Result<(), CodegenErrorKind> {
        let expression_point = self.current_expression_program_point_at_location();
        let slot = self
            .effects
            .get_mut(self.effect_count)
            .ok_or(CodegenErrorKind::TooManyRuntimePlaceEffectFacts)?;
        if self.ownership_event_count >= MAX_RUNTIME_OWNERSHIP_EVENT_FACTS {
            return Err(CodegenErrorKind::TooManyRuntimeOwnershipEventFacts);
        }
        *slot = Some(RuntimePlaceEffectFact {
            path,
            kind,
            span,
            event: RuntimeOwnershipEventId(self.ownership_event_count),
            location: self.current_ownership_event_location,
            expression_path: self.current_ownership_expression_path,
            expression_conditional: self.current_conditional_expression,
            expression_point,
            loan_generation_borrower: if matches!(
                kind,
                RuntimePlaceEffectKind::SharedBorrow | RuntimePlaceEffectKind::MutableBorrow
            ) {
                self.current_loan_generation_borrower
            } else {
                None
            },
        });
        self.effect_count += 1;
        self.ownership_event_count += 1;
        Ok(())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn direct_loan_fact(&self, initialization_index: usize) -> Option<RuntimeLoanFact> {
        self.direct_loan_fact_at_depth(initialization_index, 0)
    }

    fn direct_loan_fact_at_depth(
        &self,
        initialization_index: usize,
        depth: usize,
    ) -> Option<RuntimeLoanFact> {
        if depth > self.initialization_count.checked_add(self.effect_count)? {
            return None;
        }
        let initialization = self
            .initializations
            .get(initialization_index)
            .and_then(|initialization| *initialization)?;
        if initialization.origin != RuntimeInitializationOrigin::LocalDeclaration {
            return None;
        }
        let root = self
            .move_paths
            .get(initialization.path.0)
            .and_then(|path| *path)?;
        let RuntimePlaceIdentity::Local(borrower) = root.base else {
            return None;
        };
        let local = self.locals.get(borrower.0).and_then(|local| *local)?;
        if local.mutable
            && self.effects[..self.effect_count]
                .iter()
                .flatten()
                .any(|effect| {
                    self.move_paths
                        .get(effect.path.0)
                        .and_then(|path| *path)
                        .is_some_and(|path| {
                            path.base == RuntimePlaceIdentity::Local(borrower)
                                && path.projections.count == 0
                                && effect.kind == RuntimePlaceEffectKind::Write
                                && (!matches!(
                                effect.location,
                                RuntimeOwnershipEventLocation::TopLevelStatement(_)
                                    | RuntimeOwnershipEventLocation::ConditionalAssignmentAction {
                                        ..
                                    }
                                    | RuntimeOwnershipEventLocation::LoopOperation { .. }
                                    | RuntimeOwnershipEventLocation::LoopConditionalAction {
                                        ..
                                    }
                                    | RuntimeOwnershipEventLocation::NestedLoopAction { .. }
                                    | RuntimeOwnershipEventLocation::NestedLoopBranchAction {
                                        ..
                                    }
                                    | RuntimeOwnershipEventLocation::NestedLoopBranchElseAction {
                                        ..
                                    }
                            ))
                        })
                })
        {
            return None;
        }
        let RuntimeExpressionType::Reference { mutable, .. } = root.ty else {
            return None;
        };
        let direct = self
            .effects
            .get(..self.effect_count)?
            .iter()
            .enumerate()
            .filter_map(|(index, effect)| effect.map(|effect| (index, effect)))
            .filter(|(_, effect)| {
                effect.event.0 < initialization.event.0
                    && effect.location == initialization.location
                    && effect.expression_path == initialization.expression_path
                    && effect.expression_conditional == initialization.expression_conditional
                    && matches!(
                        (mutable, effect.kind),
                        (
                            false,
                            RuntimePlaceEffectKind::SharedBorrow
                                | RuntimePlaceEffectKind::MutableBorrow
                        ) | (true, RuntimePlaceEffectKind::MutableBorrow)
                    )
            })
            .max_by_key(|(_, effect)| effect.event.0)
            .map(|(issue_effect, effect)| RuntimeLoanFact {
                id: RuntimeLoanId(initialization_index),
                borrower,
                borrowed_path: effect.path,
                kind: if mutable {
                    RuntimePlaceEffectKind::MutableBorrow
                } else {
                    RuntimePlaceEffectKind::SharedBorrow
                },
                issue_effect,
                generation_event: initialization.event,
            });
        if direct.is_some() {
            return direct;
        }

        let (move_effect, moved) = self.effects[..self.effect_count]
            .iter()
            .enumerate()
            .filter_map(|(index, effect)| effect.map(|effect| (index, effect)))
            .find(|(_, effect)| {
                effect.kind == RuntimePlaceEffectKind::Move
                    && effect.event.0.checked_add(1) == Some(initialization.event.0)
                    && effect.location == initialization.location
                    && effect.expression_path == initialization.expression_path
                    && effect.expression_conditional == initialization.expression_conditional
            })?;
        let moved_path = self.move_paths.get(moved.path.0).and_then(|path| *path)?;
        let source_loan = if moved_path.projections == RuntimePlaceProjections::EMPTY {
            match moved_path.base {
                RuntimePlaceIdentity::Local(source) => self
                    .direct_moved_source_loan_before_at_depth(
                        source,
                        moved.event,
                        depth.checked_add(1)?,
                    )?,
                RuntimePlaceIdentity::Parameter(_) => {
                    let RuntimeExpressionType::Reference {
                        mutable: source_mutable,
                        ..
                    } = moved_path.ty
                    else {
                        return None;
                    };
                    if source_mutable != mutable {
                        return None;
                    }
                    RuntimeLoanFact {
                        id: RuntimeLoanId(MAX_RUNTIME_INITIALIZATION_FACTS + move_effect),
                        borrower,
                        borrowed_path: moved.path,
                        kind: if mutable {
                            RuntimePlaceEffectKind::MutableBorrow
                        } else {
                            RuntimePlaceEffectKind::SharedBorrow
                        },
                        issue_effect: move_effect,
                        generation_event: moved.event,
                    }
                }
            }
        } else {
            self.direct_tuple_field_assigned_loan_origin_before(moved.path, moved.event)
                .or_else(|| self.direct_tuple_field_loan_origin_before(moved.path, moved.event))
                .or_else(|| self.direct_tuple_field_value_origin_before(moved.path, moved.event))?
        };
        matches!(
            (mutable, source_loan.kind),
            (false, RuntimePlaceEffectKind::SharedBorrow)
                | (true, RuntimePlaceEffectKind::MutableBorrow)
        )
        .then_some(RuntimeLoanFact {
            id: RuntimeLoanId(initialization_index),
            borrower,
            borrowed_path: source_loan.borrowed_path,
            kind: source_loan.kind,
            issue_effect: move_effect,
            generation_event: initialization.event,
        })
    }

    fn direct_tuple_field_loan_origin_before(
        &self,
        field_path: RuntimeMovePathId,
        before: RuntimeOwnershipEventId,
    ) -> Option<RuntimeLoanFact> {
        let field = self.move_paths.get(field_path.0).and_then(|path| *path)?;
        let RuntimePlaceProjections {
            items:
                [
                    Some(RuntimePlaceProjection::TupleField(field_index)),
                    None,
                    None,
                    None,
                ],
            count: 1,
        } = field.projections
        else {
            return None;
        };
        let root_id = field.parent?;
        let root = self.move_paths.get(root_id.0).and_then(|path| *path)?;
        if root.base != field.base || root.projections != RuntimePlaceProjections::EMPTY {
            return None;
        }
        let RuntimeExpressionType::Tuple {
            elements,
            element_count,
        } = root.ty
        else {
            return None;
        };
        let RuntimeExpressionType::Reference { mutable, .. } = field.ty else {
            return None;
        };
        let mut reference_count = 0usize;
        let mut target_ordinal = None;
        for (index, element) in elements[..element_count].iter().enumerate() {
            if matches!(element, Some(RuntimeTupleElementType::Reference { .. })) {
                if index == field_index {
                    target_ordinal = Some(reference_count);
                }
                reference_count = reference_count.checked_add(1)?;
            }
        }
        let target_ordinal = target_ordinal?;
        let initialization = self.initializations[..self.initialization_count]
            .iter()
            .flatten()
            .filter(|initialization| {
                initialization.path == root_id && initialization.event.0 < before.0
            })
            .max_by_key(|initialization| initialization.event.0)?;
        if self.effects[..self.effect_count]
            .iter()
            .flatten()
            .any(|effect| {
                (effect.path == root_id || effect.path == field_path)
                    && effect.kind == RuntimePlaceEffectKind::Write
                    && runtime_ownership_position_precedes(
                        self,
                        initialization.event,
                        initialization.location,
                        effect.event,
                        effect.location,
                    )
                    && effect.event.0 < before.0
            })
        {
            return None;
        }
        let mut borrow_count = 0usize;
        let mut selected = None;
        for (issue_effect, effect) in self.effects[..self.effect_count]
            .iter()
            .enumerate()
            .filter_map(|(index, effect)| effect.map(|effect| (index, effect)))
            .filter(|(_, effect)| {
                effect.event.0 < initialization.event.0
                    && effect.location == initialization.location
                    && effect.expression_path == initialization.expression_path
                    && effect.expression_conditional == initialization.expression_conditional
                    && matches!(
                        effect.kind,
                        RuntimePlaceEffectKind::SharedBorrow
                            | RuntimePlaceEffectKind::MutableBorrow
                    )
            })
        {
            if borrow_count == target_ordinal {
                selected = Some((issue_effect, effect));
            }
            borrow_count = borrow_count.checked_add(1)?;
        }
        let (issue_effect, origin) = selected?;
        if borrow_count != reference_count
            || !matches!(
                (mutable, origin.kind),
                (false, RuntimePlaceEffectKind::SharedBorrow)
                    | (true, RuntimePlaceEffectKind::MutableBorrow)
            )
        {
            return None;
        }
        let RuntimePlaceIdentity::Local(borrower) = root.base else {
            return None;
        };
        Some(RuntimeLoanFact {
            id: RuntimeLoanId(MAX_RUNTIME_INITIALIZATION_FACTS + issue_effect),
            borrower,
            borrowed_path: origin.path,
            kind: origin.kind,
            issue_effect,
            generation_event: initialization.event,
        })
    }

    fn direct_assigned_loan_fact(&self, effect_index: usize) -> Option<RuntimeLoanFact> {
        let generation = self.effects.get(effect_index).and_then(|effect| *effect)?;
        if generation.kind != RuntimePlaceEffectKind::Write {
            return None;
        }
        if !matches!(
            generation.location,
            RuntimeOwnershipEventLocation::TopLevelStatement(_)
                | RuntimeOwnershipEventLocation::ConditionalAssignmentAction { .. }
                | RuntimeOwnershipEventLocation::LoopOperation { .. }
                | RuntimeOwnershipEventLocation::LoopConditionalAction { .. }
                | RuntimeOwnershipEventLocation::NestedLoopAction { .. }
                | RuntimeOwnershipEventLocation::NestedLoopBranchAction { .. }
                | RuntimeOwnershipEventLocation::NestedLoopBranchElseAction { .. }
        ) {
            return None;
        }
        let root = self
            .move_paths
            .get(generation.path.0)
            .and_then(|path| *path)?;
        if root.projections.count != 0 {
            return None;
        }
        let RuntimePlaceIdentity::Local(borrower) = root.base else {
            return None;
        };
        let local = self.locals.get(borrower.0).and_then(|local| *local)?;
        if !local.mutable && local.initialized {
            return None;
        }
        let RuntimeExpressionType::Reference { mutable, .. } = root.ty else {
            return None;
        };
        self.effects
            .get(..effect_index)?
            .iter()
            .enumerate()
            .filter_map(|(index, effect)| effect.map(|effect| (index, effect)))
            .filter(|(_, effect)| {
                effect.event.0 < generation.event.0
                    && effect.location == generation.location
                    && effect.expression_path == generation.expression_path
                    && effect.expression_conditional == generation.expression_conditional
                    && matches!(
                        (mutable, effect.kind),
                        (false, RuntimePlaceEffectKind::SharedBorrow)
                            | (true, RuntimePlaceEffectKind::MutableBorrow)
                    )
            })
            .max_by_key(|(_, effect)| effect.event.0)
            .map(|(issue_effect, effect)| RuntimeLoanFact {
                id: RuntimeLoanId(MAX_RUNTIME_INITIALIZATION_FACTS + effect_index),
                borrower,
                borrowed_path: effect.path,
                kind: effect.kind,
                issue_effect,
                generation_event: generation.event,
            })
    }

    fn direct_tuple_field_assigned_loan_origin_before(
        &self,
        field_path: RuntimeMovePathId,
        before: RuntimeOwnershipEventId,
    ) -> Option<RuntimeLoanFact> {
        let generation_index = self.effects[..self.effect_count]
            .iter()
            .enumerate()
            .filter_map(|(index, effect)| effect.map(|effect| (index, effect)))
            .filter(|(_, effect)| {
                effect.path == field_path
                    && effect.kind == RuntimePlaceEffectKind::Write
                    && effect.event.0 < before.0
            })
            .max_by_key(|(_, effect)| effect.event.0)?
            .0;
        self.direct_tuple_field_assigned_loan_origin_at(generation_index)
    }

    fn direct_tuple_field_assigned_loan_origin_at(
        &self,
        generation_index: usize,
    ) -> Option<RuntimeLoanFact> {
        let generation = self
            .effects
            .get(generation_index)
            .and_then(|effect| *effect)?;
        if generation.kind != RuntimePlaceEffectKind::Write {
            return None;
        }
        let field = self
            .move_paths
            .get(generation.path.0)
            .and_then(|path| *path)?;
        if !matches!(
            field.projections,
            RuntimePlaceProjections {
                items: [
                    Some(RuntimePlaceProjection::TupleField(_)),
                    None,
                    None,
                    None,
                ],
                count: 1,
            }
        ) {
            return None;
        }
        let RuntimeExpressionType::Reference { mutable, .. } = field.ty else {
            return None;
        };
        let RuntimePlaceIdentity::Local(borrower) = field.base else {
            return None;
        };
        self.effects[..generation_index]
            .iter()
            .enumerate()
            .filter_map(|(index, effect)| effect.map(|effect| (index, effect)))
            .filter(|(_, effect)| {
                effect.event.0 < generation.event.0
                    && effect.location == generation.location
                    && effect.expression_path == generation.expression_path
                    && effect.expression_conditional == generation.expression_conditional
                    && matches!(
                        (mutable, effect.kind),
                        (false, RuntimePlaceEffectKind::SharedBorrow)
                            | (true, RuntimePlaceEffectKind::MutableBorrow)
                    )
            })
            .max_by_key(|(_, effect)| effect.event.0)
            .map(|(issue_effect, origin)| RuntimeLoanFact {
                id: RuntimeLoanId(MAX_RUNTIME_INITIALIZATION_FACTS + generation_index),
                borrower,
                borrowed_path: origin.path,
                kind: origin.kind,
                issue_effect,
                generation_event: generation.event,
            })
    }

    fn direct_tuple_field_assigned_value_origin_at(
        &self,
        generation_index: usize,
    ) -> Option<RuntimeLoanFact> {
        let generation = self
            .effects
            .get(generation_index)
            .and_then(|effect| *effect)?;
        if generation.kind != RuntimePlaceEffectKind::Write {
            return None;
        }
        let field = self
            .move_paths
            .get(generation.path.0)
            .and_then(|path| *path)?;
        if !matches!(
            field.projections,
            RuntimePlaceProjections {
                items: [
                    Some(RuntimePlaceProjection::TupleField(_)),
                    None,
                    None,
                    None,
                ],
                count: 1,
            }
        ) {
            return None;
        }
        let RuntimeExpressionType::Reference { mutable, .. } = field.ty else {
            return None;
        };
        let RuntimePlaceIdentity::Local(borrower) = field.base else {
            return None;
        };
        self.effects[..generation_index]
            .iter()
            .enumerate()
            .filter_map(|(index, effect)| effect.map(|effect| (index, effect)))
            .filter(|(_, effect)| {
                effect.event.0 < generation.event.0
                    && effect.location == generation.location
                    && effect.expression_path == generation.expression_path
                    && effect.expression_conditional == generation.expression_conditional
                    && matches!(
                        effect.kind,
                        RuntimePlaceEffectKind::Copy | RuntimePlaceEffectKind::Move
                    )
                    && self
                        .move_paths
                        .get(effect.path.0)
                        .and_then(|path| *path)
                        .is_some_and(|path| {
                            matches!(
                                path.ty,
                                RuntimeExpressionType::Reference {
                                    mutable: source_mutable,
                                    ..
                                } if source_mutable == mutable
                            )
                        })
            })
            .max_by_key(|(_, effect)| effect.event.0)
            .map(|(issue_effect, origin)| RuntimeLoanFact {
                id: RuntimeLoanId(MAX_RUNTIME_INITIALIZATION_FACTS + generation_index),
                borrower,
                borrowed_path: origin.path,
                kind: if mutable {
                    RuntimePlaceEffectKind::MutableBorrow
                } else {
                    RuntimePlaceEffectKind::SharedBorrow
                },
                issue_effect,
                generation_event: generation.event,
            })
    }

    fn direct_tuple_field_value_origin_before(
        &self,
        field_path: RuntimeMovePathId,
        before: RuntimeOwnershipEventId,
    ) -> Option<RuntimeLoanFact> {
        let field = self.move_paths.get(field_path.0).and_then(|path| *path)?;
        let RuntimePlaceProjections {
            items:
                [
                    Some(RuntimePlaceProjection::TupleField(field_index)),
                    None,
                    None,
                    None,
                ],
            count: 1,
        } = field.projections
        else {
            return None;
        };
        let root_id = field.parent?;
        let root = self.move_paths.get(root_id.0).and_then(|path| *path)?;
        let RuntimeExpressionType::Tuple {
            elements,
            element_count,
        } = root.ty
        else {
            return None;
        };
        let RuntimeExpressionType::Reference { mutable, .. } = field.ty else {
            return None;
        };
        let mut reference_count = 0usize;
        let mut target_ordinal = None;
        for (index, element) in elements[..element_count].iter().enumerate() {
            if matches!(element, Some(RuntimeTupleElementType::Reference { .. })) {
                if index == field_index {
                    target_ordinal = Some(reference_count);
                }
                reference_count = reference_count.checked_add(1)?;
            }
        }
        let target_ordinal = target_ordinal?;
        let initialization = self.initializations[..self.initialization_count]
            .iter()
            .flatten()
            .filter(|initialization| {
                initialization.path == root_id && initialization.event.0 < before.0
            })
            .max_by_key(|initialization| initialization.event.0)?;
        if self.effects[..self.effect_count]
            .iter()
            .flatten()
            .any(|effect| {
                (effect.path == root_id || effect.path == field_path)
                    && effect.kind == RuntimePlaceEffectKind::Write
                    && effect.event.0 > initialization.event.0
                    && effect.event.0 < before.0
            })
        {
            return None;
        }
        let mut value_count = 0usize;
        let mut selected = None;
        for (issue_effect, effect) in self.effects[..self.effect_count]
            .iter()
            .enumerate()
            .filter_map(|(index, effect)| effect.map(|effect| (index, effect)))
            .filter(|(_, effect)| {
                effect.event.0 < initialization.event.0
                    && effect.location == initialization.location
                    && effect.expression_path == initialization.expression_path
                    && effect.expression_conditional == initialization.expression_conditional
                    && matches!(
                        effect.kind,
                        RuntimePlaceEffectKind::Copy | RuntimePlaceEffectKind::Move
                    )
                    && self
                        .move_paths
                        .get(effect.path.0)
                        .and_then(|path| *path)
                        .is_some_and(|path| {
                            matches!(path.ty, RuntimeExpressionType::Reference { .. })
                        })
            })
        {
            if value_count == target_ordinal {
                selected = Some((issue_effect, effect));
            }
            value_count = value_count.checked_add(1)?;
        }
        let (issue_effect, origin) = selected?;
        let RuntimeExpressionType::Reference {
            mutable: source_mutable,
            ..
        } = self
            .move_paths
            .get(origin.path.0)
            .and_then(|path| *path)?
            .ty
        else {
            return None;
        };
        if value_count != reference_count || source_mutable != mutable {
            return None;
        }
        let RuntimePlaceIdentity::Local(borrower) = root.base else {
            return None;
        };
        Some(RuntimeLoanFact {
            id: RuntimeLoanId(MAX_RUNTIME_INITIALIZATION_FACTS + issue_effect),
            borrower,
            borrowed_path: origin.path,
            kind: if mutable {
                RuntimePlaceEffectKind::MutableBorrow
            } else {
                RuntimePlaceEffectKind::SharedBorrow
            },
            issue_effect,
            generation_event: initialization.event,
        })
    }

    fn direct_expression_loan_fact(&self, effect_index: usize) -> Option<RuntimeLoanFact> {
        let issue = self.effects.get(effect_index).and_then(|effect| *effect)?;
        let borrower = issue.loan_generation_borrower?;
        let initialization = self.initializations[..self.initialization_count]
            .iter()
            .flatten()
            .filter(|initialization| {
                initialization.event.0 > issue.event.0
                    && self
                        .move_paths
                        .get(initialization.path.0)
                        .and_then(|path| *path)
                        .is_some_and(|path| {
                            path.base == RuntimePlaceIdentity::Local(borrower)
                                && matches!(path.ty, RuntimeExpressionType::Reference { .. })
                        })
            })
            .min_by_key(|initialization| initialization.event.0);
        let assignment = self.effects[..self.effect_count]
            .iter()
            .flatten()
            .filter(|effect| {
                effect.kind == RuntimePlaceEffectKind::Write
                    && effect.event.0 > issue.event.0
                    && self
                        .move_paths
                        .get(effect.path.0)
                        .and_then(|path| *path)
                        .is_some_and(|path| {
                            path.base == RuntimePlaceIdentity::Local(borrower)
                                && matches!(path.ty, RuntimeExpressionType::Reference { .. })
                        })
            })
            .min_by_key(|effect| effect.event.0);
        let (generation_path, generation_event) = match (initialization, assignment) {
            (Some(initialization), Some(assignment)) => {
                if initialization.event.0 < assignment.event.0 {
                    (initialization.path, initialization.event)
                } else {
                    (assignment.path, assignment.event)
                }
            }
            (Some(initialization), None) => (initialization.path, initialization.event),
            (None, Some(assignment)) => (assignment.path, assignment.event),
            (None, None) => return None,
        };
        let RuntimeExpressionType::Reference { mutable, .. } = self
            .move_paths
            .get(generation_path.0)
            .and_then(|path| *path)?
            .ty
        else {
            return None;
        };
        if !matches!(
            (mutable, issue.kind),
            (false, RuntimePlaceEffectKind::SharedBorrow)
                | (true, RuntimePlaceEffectKind::MutableBorrow)
        ) {
            return None;
        }
        Some(RuntimeLoanFact {
            id: RuntimeLoanId(
                MAX_RUNTIME_INITIALIZATION_FACTS + MAX_RUNTIME_PLACE_EFFECT_FACTS + effect_index,
            ),
            borrower,
            borrowed_path: issue.path,
            kind: issue.kind,
            issue_effect: effect_index,
            generation_event,
        })
    }

    fn moved_expression_loan_fact_at_depth(
        &self,
        effect_index: usize,
        move_depth: usize,
    ) -> Option<RuntimeLoanFact> {
        if move_depth >= self.initialization_count {
            return None;
        }
        let source = self.direct_expression_loan_fact(effect_index)?;
        let (mut generation_event, mut generation_location) =
            self.direct_loan_generation_position(source)?;
        let mut borrower = source.borrower;
        let mut issue_effect = source.issue_effect;
        for _ in 0..=move_depth {
            let source_path = self.initializations[..self.initialization_count]
                .iter()
                .flatten()
                .find(|initialization| initialization.event == generation_event)
                .map(|initialization| initialization.path)
                .or_else(|| {
                    self.effects[..self.effect_count]
                        .iter()
                        .flatten()
                        .find(|effect| {
                            effect.kind == RuntimePlaceEffectKind::Write
                                && effect.event == generation_event
                        })
                        .map(|effect| effect.path)
                })?;
            let source_path_fact = self.move_paths.get(source_path.0).and_then(|path| *path)?;
            if source_path_fact.base != RuntimePlaceIdentity::Local(borrower)
                || !matches!(source_path_fact.ty, RuntimeExpressionType::Reference { .. })
            {
                return None;
            }
            let (next_issue, moved) = self.effects[..self.effect_count]
                .iter()
                .enumerate()
                .filter_map(|(index, effect)| effect.map(|effect| (index, effect)))
                .filter(|(_, effect)| {
                    effect.path == source_path
                        && effect.kind == RuntimePlaceEffectKind::Move
                        && runtime_ownership_position_precedes(
                            self,
                            generation_event,
                            generation_location,
                            effect.event,
                            effect.location,
                        )
                        && !self.effects[..self.effect_count]
                            .iter()
                            .flatten()
                            .any(|replacement| {
                                replacement.path == source_path
                                    && replacement.kind == RuntimePlaceEffectKind::Write
                                    && runtime_ownership_position_precedes(
                                        self,
                                        generation_event,
                                        generation_location,
                                        replacement.event,
                                        replacement.location,
                                    )
                                    && runtime_ownership_position_precedes(
                                        self,
                                        replacement.event,
                                        replacement.location,
                                        effect.event,
                                        effect.location,
                                    )
                            })
                })
                .min_by_key(|(_, effect)| effect.event.0)?;
            let generation = self.initializations[..self.initialization_count]
                .iter()
                .flatten()
                .find(|initialization| {
                    moved.event.0.checked_add(1) == Some(initialization.event.0)
                        && initialization.location == moved.location
                        && initialization.expression_path == moved.expression_path
                        && initialization.expression_conditional == moved.expression_conditional
                })?;
            let destination = self
                .move_paths
                .get(generation.path.0)
                .and_then(|path| *path)?;
            let RuntimePlaceIdentity::Local(next_borrower) = destination.base else {
                return None;
            };
            let RuntimeExpressionType::Reference { mutable, .. } = destination.ty else {
                return None;
            };
            if destination.projections != RuntimePlaceProjections::EMPTY
                || !matches!(
                    (mutable, source.kind),
                    (false, RuntimePlaceEffectKind::SharedBorrow)
                        | (true, RuntimePlaceEffectKind::MutableBorrow)
                )
            {
                return None;
            }
            borrower = next_borrower;
            issue_effect = next_issue;
            generation_event = generation.event;
            generation_location = generation.location;
        }
        Some(RuntimeLoanFact {
            id: RuntimeLoanId(
                MAX_RUNTIME_INITIALIZATION_FACTS
                    + 2 * MAX_RUNTIME_PLACE_EFFECT_FACTS
                    + move_depth.checked_mul(MAX_RUNTIME_PLACE_EFFECT_FACTS)?
                    + effect_index,
            ),
            borrower,
            borrowed_path: source.borrowed_path,
            kind: source.kind,
            issue_effect,
            generation_event,
        })
    }

    fn moved_replaced_projected_loan_fact_at_depth(
        &self,
        initialization_index: usize,
        replacement_depth: usize,
    ) -> Option<RuntimeLoanFact> {
        if replacement_depth >= self.effect_count {
            return None;
        }
        let destination_generation = self
            .initializations
            .get(initialization_index)
            .and_then(|initialization| *initialization)?;
        let destination = self
            .move_paths
            .get(destination_generation.path.0)
            .and_then(|path| *path)?;
        let RuntimePlaceIdentity::Local(borrower) = destination.base else {
            return None;
        };
        if destination.projections != RuntimePlaceProjections::EMPTY
            || !matches!(destination.ty, RuntimeExpressionType::Reference { .. })
        {
            return None;
        }
        let (move_effect, moved) = self.effects[..self.effect_count]
            .iter()
            .enumerate()
            .filter_map(|(index, effect)| effect.map(|effect| (index, effect)))
            .find(|(_, effect)| {
                effect.kind == RuntimePlaceEffectKind::Move
                    && effect.event.0.checked_add(1) == Some(destination_generation.event.0)
                    && effect.location == destination_generation.location
                    && effect.expression_path == destination_generation.expression_path
                    && effect.expression_conditional
                        == destination_generation.expression_conditional
            })?;
        let field = self.move_paths.get(moved.path.0).and_then(|path| *path)?;
        if !matches!(
            field.projections,
            RuntimePlaceProjections {
                items: [
                    Some(RuntimePlaceProjection::TupleField(_)),
                    None,
                    None,
                    None,
                ],
                count: 1,
            }
        ) || !matches!(field.ty, RuntimeExpressionType::Reference { .. })
        {
            return None;
        }
        let latest_write = self.effects[..self.effect_count]
            .iter()
            .flatten()
            .filter(|effect| {
                effect.path == moved.path
                    && effect.kind == RuntimePlaceEffectKind::Write
                    && effect.event.0 < moved.event.0
            })
            .max_by_key(|effect| effect.event.0)?;
        let mut before = latest_write.event;
        let mut origin = None;
        for depth in 0..=replacement_depth {
            let candidate = self
                .direct_tuple_field_assigned_loan_origin_before(moved.path, before)
                .or_else(|| self.direct_tuple_field_loan_origin_before(moved.path, before))
                .or_else(|| self.direct_tuple_field_value_origin_before(moved.path, before))?;
            if depth == replacement_depth {
                origin = Some(candidate);
                break;
            }
            before = candidate.generation_event;
        }
        let origin = origin?;
        Some(RuntimeLoanFact {
            id: RuntimeLoanId(
                MAX_RUNTIME_INITIALIZATION_FACTS
                    + 2 * MAX_RUNTIME_PLACE_EFFECT_FACTS
                    + MAX_RUNTIME_INITIALIZATION_FACTS * MAX_RUNTIME_PLACE_EFFECT_FACTS
                    + replacement_depth.checked_mul(MAX_RUNTIME_INITIALIZATION_FACTS)?
                    + initialization_index,
            ),
            borrower,
            borrowed_path: origin.borrowed_path,
            kind: origin.kind,
            issue_effect: move_effect,
            generation_event: destination_generation.event,
        })
    }

    fn direct_loan_for_borrower_before(
        &self,
        borrower: RuntimeLocalId,
        before: RuntimeOwnershipEventId,
    ) -> Option<RuntimeLoanFact> {
        self.direct_loan_for_borrower_before_at_depth(borrower, before, 0)
    }

    fn direct_loan_for_borrower_before_at_depth(
        &self,
        borrower: RuntimeLocalId,
        before: RuntimeOwnershipEventId,
        depth: usize,
    ) -> Option<RuntimeLoanFact> {
        if depth > self.initialization_count.checked_add(self.effect_count)? {
            return None;
        }
        (0..self.initialization_count)
            .filter_map(|index| self.direct_loan_fact_at_depth(index, depth))
            .chain((0..self.effect_count).filter_map(|index| self.direct_assigned_loan_fact(index)))
            .chain(
                (0..self.effect_count).filter_map(|index| self.direct_expression_loan_fact(index)),
            )
            .chain((0..self.initialization_count).flat_map(|move_depth| {
                (0..self.effect_count).filter_map(move |index| {
                    self.moved_expression_loan_fact_at_depth(index, move_depth)
                })
            }))
            .chain((0..self.effect_count).flat_map(|replacement_depth| {
                (0..self.initialization_count).filter_map(move |index| {
                    self.moved_replaced_projected_loan_fact_at_depth(index, replacement_depth)
                })
            }))
            .filter(|loan| loan.borrower == borrower && loan.generation_event.0 < before.0)
            .max_by_key(|loan| loan.generation_event.0)
    }

    fn direct_moved_source_loan_before_at_depth(
        &self,
        borrower: RuntimeLocalId,
        before: RuntimeOwnershipEventId,
        depth: usize,
    ) -> Option<RuntimeLoanFact> {
        if depth > self.initialization_count.checked_add(self.effect_count)? {
            return None;
        }
        let initialization = self.initializations[..self.initialization_count]
            .iter()
            .enumerate()
            .filter_map(|(index, initialization)| {
                initialization
                    .filter(|initialization| {
                        initialization.event.0 < before.0
                            && self
                                .move_paths
                                .get(initialization.path.0)
                                .and_then(|path| *path)
                                .is_some_and(|path| {
                                    path.base == RuntimePlaceIdentity::Local(borrower)
                                        && path.projections == RuntimePlaceProjections::EMPTY
                                })
                    })
                    .map(|initialization| (index, initialization.event))
            })
            .max_by_key(|(_, event)| event.0);
        let assignment = self.effects[..self.effect_count]
            .iter()
            .enumerate()
            .filter_map(|(index, effect)| {
                effect
                    .filter(|effect| {
                        effect.event.0 < before.0
                            && effect.kind == RuntimePlaceEffectKind::Write
                            && self
                                .move_paths
                                .get(effect.path.0)
                                .and_then(|path| *path)
                                .is_some_and(|path| {
                                    path.base == RuntimePlaceIdentity::Local(borrower)
                                        && path.projections == RuntimePlaceProjections::EMPTY
                                })
                    })
                    .map(|effect| (index, effect.event))
            })
            .max_by_key(|(_, event)| event.0);
        match (initialization, assignment) {
            (Some((_, initialized)), Some((effect, assigned))) if assigned.0 > initialized.0 => {
                self.direct_assigned_loan_fact(effect).or_else(|| {
                    (0..self.effect_count)
                        .filter_map(|index| self.direct_expression_loan_fact(index))
                        .filter(|loan| {
                            loan.borrower == borrower && loan.generation_event == assigned
                        })
                        .max_by_key(|loan| loan.issue_effect)
                })
            }
            (Some((index, _)), _) => self.direct_loan_fact_at_depth(index, depth),
            (None, Some((effect, assigned))) => {
                self.direct_assigned_loan_fact(effect).or_else(|| {
                    (0..self.effect_count)
                        .filter_map(|index| self.direct_expression_loan_fact(index))
                        .filter(|loan| {
                            loan.borrower == borrower && loan.generation_event == assigned
                        })
                        .max_by_key(|loan| loan.issue_effect)
                })
            }
            (None, None) => None,
        }
    }

    fn direct_reference_value_source_before(
        &self,
        borrower: RuntimeLocalId,
        before: RuntimeOwnershipEventId,
    ) -> Option<(RuntimeMovePathId, RuntimePlaceEffectFact)> {
        let borrower_path = self.find_move_path(
            RuntimePlaceIdentity::Local(borrower),
            RuntimePlaceProjections::EMPTY,
        )?;
        let destination = self
            .move_paths
            .get(borrower_path.0)
            .and_then(|path| *path)?;
        let RuntimeExpressionType::Reference {
            mutable: destination_mutable,
            ..
        } = destination.ty
        else {
            return None;
        };
        let initialization = self.initializations[..self.initialization_count]
            .iter()
            .flatten()
            .filter(|initialization| {
                initialization.path == borrower_path && initialization.event.0 < before.0
            })
            .max_by_key(|initialization| initialization.event.0)?;
        let source = self.effects[..self.effect_count]
            .iter()
            .flatten()
            .find(|effect| {
                matches!(
                    effect.kind,
                    RuntimePlaceEffectKind::Copy | RuntimePlaceEffectKind::Move
                ) && effect.event.0.checked_add(1) == Some(initialization.event.0)
                    && effect.location == initialization.location
                    && effect.expression_path == initialization.expression_path
                    && effect.expression_conditional == initialization.expression_conditional
            })?;
        let source_path = self.move_paths.get(source.path.0).and_then(|path| *path)?;
        let RuntimeExpressionType::Reference {
            mutable: source_mutable,
            ..
        } = source_path.ty
        else {
            return None;
        };
        (source_mutable == destination_mutable
            && (!destination_mutable || source.kind == RuntimePlaceEffectKind::Move))
            .then_some((source.path, *source))
    }

    fn direct_loan_generation_position(
        &self,
        loan: RuntimeLoanFact,
    ) -> Option<(RuntimeOwnershipEventId, RuntimeOwnershipEventLocation)> {
        if loan.id.0 < MAX_RUNTIME_INITIALIZATION_FACTS {
            let initialization = self
                .initializations
                .get(loan.id.0)
                .and_then(|initialization| *initialization)?;
            (initialization.event == loan.generation_event)
                .then_some((initialization.event, initialization.location))
        } else if loan.id.0 < MAX_RUNTIME_INITIALIZATION_FACTS + MAX_RUNTIME_PLACE_EFFECT_FACTS {
            let effect_index = loan.id.0.checked_sub(MAX_RUNTIME_INITIALIZATION_FACTS)?;
            let effect = self.effects.get(effect_index).and_then(|effect| *effect)?;
            (effect.event == loan.generation_event).then_some((effect.event, effect.location))
        } else if loan.id.0 < MAX_RUNTIME_INITIALIZATION_FACTS + 2 * MAX_RUNTIME_PLACE_EFFECT_FACTS
        {
            let effect_index = loan
                .id
                .0
                .checked_sub(MAX_RUNTIME_INITIALIZATION_FACTS + MAX_RUNTIME_PLACE_EFFECT_FACTS)?;
            let derived = self.direct_expression_loan_fact(effect_index)?;
            if derived.generation_event != loan.generation_event {
                return None;
            }
            self.initializations[..self.initialization_count]
                .iter()
                .flatten()
                .find(|initialization| initialization.event == loan.generation_event)
                .map(|initialization| (initialization.event, initialization.location))
                .or_else(|| {
                    self.effects[..self.effect_count]
                        .iter()
                        .flatten()
                        .find(|effect| effect.event == loan.generation_event)
                        .map(|effect| (effect.event, effect.location))
                })
        } else if loan.id.0
            < MAX_RUNTIME_INITIALIZATION_FACTS
                + 2 * MAX_RUNTIME_PLACE_EFFECT_FACTS
                + MAX_RUNTIME_INITIALIZATION_FACTS * MAX_RUNTIME_PLACE_EFFECT_FACTS
        {
            let moved_index = loan.id.0.checked_sub(
                MAX_RUNTIME_INITIALIZATION_FACTS + 2 * MAX_RUNTIME_PLACE_EFFECT_FACTS,
            )?;
            let move_depth = moved_index / MAX_RUNTIME_PLACE_EFFECT_FACTS;
            let effect_index = moved_index % MAX_RUNTIME_PLACE_EFFECT_FACTS;
            let derived = self.moved_expression_loan_fact_at_depth(effect_index, move_depth)?;
            let generation = self.initializations[..self.initialization_count]
                .iter()
                .flatten()
                .find(|initialization| initialization.event == derived.generation_event)?;
            (derived.generation_event == loan.generation_event)
                .then_some((generation.event, generation.location))
        } else {
            let replaced_index = loan.id.0.checked_sub(
                MAX_RUNTIME_INITIALIZATION_FACTS
                    + 2 * MAX_RUNTIME_PLACE_EFFECT_FACTS
                    + MAX_RUNTIME_INITIALIZATION_FACTS * MAX_RUNTIME_PLACE_EFFECT_FACTS,
            )?;
            let replacement_depth = replaced_index / MAX_RUNTIME_INITIALIZATION_FACTS;
            let initialization_index = replaced_index % MAX_RUNTIME_INITIALIZATION_FACTS;
            let derived = self.moved_replaced_projected_loan_fact_at_depth(
                initialization_index,
                replacement_depth,
            )?;
            let generation = self
                .initializations
                .get(initialization_index)
                .and_then(|generation| *generation)?;
            (derived.generation_event == loan.generation_event)
                .then_some((generation.event, generation.location))
        }
    }

    fn push_assignment_access(
        &mut self,
        fact: RuntimePlaceAccessFact,
    ) -> Result<(), CodegenErrorKind> {
        let slot = self
            .assignment_accesses
            .get_mut(self.assignment_access_count)
            .ok_or(CodegenErrorKind::TooManyRuntimePlaceAccessFacts)?;
        *slot = Some(fact);
        self.assignment_access_count += 1;
        Ok(())
    }

    fn push_assignment_read(
        &mut self,
        fact: RuntimePlaceAccessFact,
        context: RuntimeReadEffectContext,
    ) -> Result<(), CodegenErrorKind> {
        if fact.access != RuntimePlaceAccess::Read {
            return Err(CodegenErrorKind::InvalidRuntimePlaceFacts);
        }
        if self.assignment_read_count >= self.assignment_reads.len() {
            return Err(CodegenErrorKind::TooManyRuntimePlaceAccessFacts);
        }
        let exact_path = self.find_move_path(fact.base, fact.projections);
        let reference_root = (fact.projections.count != 0
            || context == RuntimeReadEffectContext::Unclassified)
            .then(|| self.find_move_path(fact.base, RuntimePlaceProjections::EMPTY))
            .flatten()
            .filter(|path| {
                let Some(root) = self
                    .move_paths
                    .get(path.0)
                    .and_then(|path| *path)
                    .filter(|path| matches!(path.ty, RuntimeExpressionType::Reference { .. }))
                else {
                    return false;
                };
                let RuntimePlaceIdentity::Local(borrower) = root.base else {
                    return false;
                };
                self.direct_loan_for_borrower_before(
                    borrower,
                    RuntimeOwnershipEventId(self.ownership_event_count),
                )
                .is_some()
            });
        let effect = exact_path.or(reference_root).and_then(|path| {
            let path_ty = self.move_paths.get(path.0).and_then(|path| *path)?.ty;
            let kind = if reference_root == Some(path) {
                RuntimePlaceEffectKind::LoanUse
            } else {
                match context {
                    RuntimeReadEffectContext::Value if runtime_type_is_copy(path_ty) => {
                        RuntimePlaceEffectKind::Copy
                    }
                    RuntimeReadEffectContext::Move if !runtime_type_is_copy(path_ty) => {
                        RuntimePlaceEffectKind::Move
                    }
                    RuntimeReadEffectContext::SharedBorrow => RuntimePlaceEffectKind::SharedBorrow,
                    RuntimeReadEffectContext::MutableBorrow => {
                        RuntimePlaceEffectKind::MutableBorrow
                    }
                    RuntimeReadEffectContext::Value
                    | RuntimeReadEffectContext::Move
                    | RuntimeReadEffectContext::Unclassified => {
                        return None;
                    }
                }
            };
            Some(RuntimePlaceEffectFact {
                path,
                kind,
                span: fact.span,
                event: RuntimeOwnershipEventId(self.ownership_event_count),
                location: self.current_ownership_event_location,
                expression_path: self.current_ownership_expression_path,
                expression_conditional: self.current_conditional_expression,
                expression_point: self.current_expression_program_point_at_location(),
                loan_generation_borrower: if matches!(
                    kind,
                    RuntimePlaceEffectKind::SharedBorrow | RuntimePlaceEffectKind::MutableBorrow
                ) {
                    self.current_loan_generation_borrower
                } else {
                    None
                },
            })
        });
        if effect.is_some() && self.effect_count >= self.effects.len() {
            return Err(CodegenErrorKind::TooManyRuntimePlaceEffectFacts);
        }
        if effect.is_some() && self.ownership_event_count >= MAX_RUNTIME_OWNERSHIP_EVENT_FACTS {
            return Err(CodegenErrorKind::TooManyRuntimeOwnershipEventFacts);
        }
        self.assignment_reads[self.assignment_read_count] = Some(fact);
        self.assignment_read_count += 1;
        if let Some(effect) = effect {
            self.effects[self.effect_count] = Some(effect);
            self.effect_count += 1;
            self.ownership_event_count += 1;
        }
        Ok(())
    }

    fn push_basic_block(
        &mut self,
        first_statement: usize,
        reachable: bool,
    ) -> Result<RuntimeBasicBlockId, CodegenErrorKind> {
        let slot = self
            .basic_blocks
            .get_mut(self.basic_block_count)
            .ok_or(CodegenErrorKind::TooManyRuntimeBasicBlockFacts)?;
        let id = RuntimeBasicBlockId(self.basic_block_count);
        *slot = Some(RuntimeBasicBlockFact {
            id,
            source: RuntimeBasicBlockSource::TopLevel,
            first_statement,
            statement_count: 0,
            reachable,
        });
        self.basic_block_count += 1;
        Ok(id)
    }

    fn push_conditional_return_branch_block(
        &mut self,
        statement_index: usize,
        branch_index: usize,
        reachable: bool,
    ) -> Result<RuntimeBasicBlockId, CodegenErrorKind> {
        let id = self.push_basic_block(statement_index, reachable)?;
        let fact = self
            .basic_blocks
            .get_mut(id.0)
            .and_then(Option::as_mut)
            .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
        fact.source = RuntimeBasicBlockSource::ConditionalReturnBranch {
            statement_index,
            branch_index,
        };
        Ok(id)
    }

    fn push_sourced_basic_block(
        &mut self,
        statement_index: usize,
        reachable: bool,
        source: RuntimeBasicBlockSource,
    ) -> Result<RuntimeBasicBlockId, CodegenErrorKind> {
        let id = self.push_basic_block(statement_index, reachable)?;
        let fact = self
            .basic_blocks
            .get_mut(id.0)
            .and_then(Option::as_mut)
            .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
        fact.source = source;
        Ok(id)
    }

    fn push_loop_body_block(
        &mut self,
        statement_index: usize,
        first_operation: usize,
        reachable: bool,
    ) -> Result<RuntimeBasicBlockId, CodegenErrorKind> {
        self.push_sourced_basic_block(
            statement_index,
            reachable,
            RuntimeBasicBlockSource::LoopBody {
                statement_index,
                first_operation,
                operation_count: 0,
            },
        )
    }

    fn extend_loop_body_block(&mut self, id: RuntimeBasicBlockId) -> Result<(), CodegenErrorKind> {
        let fact = self
            .basic_blocks
            .get_mut(id.0)
            .and_then(Option::as_mut)
            .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
        let RuntimeBasicBlockSource::LoopBody {
            operation_count, ..
        } = &mut fact.source
        else {
            return Err(CodegenErrorKind::InvalidRuntimeControlFlowFacts);
        };
        *operation_count = operation_count
            .checked_add(1)
            .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
        Ok(())
    }

    fn extend_basic_block(&mut self, id: RuntimeBasicBlockId) -> Result<(), CodegenErrorKind> {
        let fact = self
            .basic_blocks
            .get_mut(id.0)
            .and_then(Option::as_mut)
            .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
        fact.statement_count = fact
            .statement_count
            .checked_add(1)
            .ok_or(CodegenErrorKind::TooManyRuntimeBasicBlockFacts)?;
        Ok(())
    }

    fn push_control_flow_edge(
        &mut self,
        edge: RuntimeControlFlowEdgeFact,
    ) -> Result<(), CodegenErrorKind> {
        let slot = self
            .control_flow_edges
            .get_mut(self.control_flow_edge_count)
            .ok_or(CodegenErrorKind::TooManyRuntimeControlFlowEdgeFacts)?;
        *slot = Some(edge);
        self.control_flow_edge_count += 1;
        Ok(())
    }
}

fn runtime_array_type(text: &str) -> Option<RuntimeExpressionType> {
    let body = text.trim().strip_prefix('[')?.strip_suffix(']')?;
    let (element, count) = body.split_once(';')?;
    let count = count.trim().parse::<usize>().ok()?;
    if count > crate::expression::MAX_ARRAY_ELEMENTS {
        return None;
    }
    let element = match element.trim() {
        "()" => RuntimeArrayElementType::Unit,
        "bool" => RuntimeArrayElementType::Bool,
        "char" => RuntimeArrayElementType::Char,
        name => RuntimeArrayElementType::Integer(Some(crate::IntegerType::from_name(name)?)),
    };
    Some(RuntimeExpressionType::Array { element, count })
}

fn runtime_tuple_type(text: &str) -> Option<RuntimeExpressionType> {
    let body = text.trim().strip_prefix('(')?.strip_suffix(')')?;
    if !body.contains(',') {
        return None;
    }
    let mut elements = [None; crate::expression::MAX_TUPLE_ELEMENTS];
    let mut element_count = 0usize;
    for element in body
        .split(',')
        .map(str::trim)
        .filter(|element| !element.is_empty())
    {
        if element_count == elements.len() {
            return None;
        }
        elements[element_count] =
            Some(runtime_tuple_element_type(runtime_type_from_text(element)?).ok()?);
        element_count += 1;
    }
    (element_count != 0).then_some(RuntimeExpressionType::Tuple {
        elements,
        element_count,
    })
}

fn runtime_reference_type(text: &str) -> Option<RuntimeExpressionType> {
    let target = text.trim().strip_prefix('&')?.trim();
    let target = target.strip_prefix("'static ").map_or(target, str::trim);
    let (target, mutable) = target
        .strip_prefix("mut ")
        .map_or((target, false), |target| (target.trim(), true));
    let target = match runtime_array_type(target) {
        Some(RuntimeExpressionType::Array { element, count }) => RuntimeReferenceTarget::Array {
            element,
            count,
            layout: RuntimeReferenceArrayLayout::Native,
        },
        _ if target == "str" => RuntimeReferenceTarget::Str,
        _ if target.starts_with('[') && target.ends_with(']') => {
            let element = match target.strip_prefix('[')?.strip_suffix(']')?.trim() {
                "()" => RuntimeArrayElementType::Unit,
                "bool" => RuntimeArrayElementType::Bool,
                "char" => RuntimeArrayElementType::Char,
                name => {
                    RuntimeArrayElementType::Integer(Some(crate::IntegerType::from_name(name)?))
                }
            };
            RuntimeReferenceTarget::Slice(element)
        }
        _ => RuntimeReferenceTarget::Scalar(match target {
            "bool" => RuntimeArrayElementType::Bool,
            "char" => RuntimeArrayElementType::Char,
            name => RuntimeArrayElementType::Integer(Some(crate::IntegerType::from_name(name)?)),
        }),
    };
    Some(RuntimeExpressionType::Reference { target, mutable })
}

fn runtime_reference_has_static_lifetime(text: &str) -> bool {
    text.trim()
        .strip_prefix('&')
        .is_some_and(|target| target.trim().starts_with("'static "))
}

fn runtime_raw_pointer_type(text: &str) -> Option<RuntimeExpressionType> {
    let target = text.trim().strip_prefix('*')?.trim();
    let (target, mutable) = if let Some(target) = target.strip_prefix("const ") {
        (target.trim(), false)
    } else {
        (target.strip_prefix("mut ")?.trim(), true)
    };
    let pointee = match target {
        "bool" => RuntimeArrayElementType::Bool,
        "char" => RuntimeArrayElementType::Char,
        name => RuntimeArrayElementType::Integer(Some(crate::IntegerType::from_name(name)?)),
    };
    Some(RuntimeExpressionType::RawPointer { pointee, mutable })
}

fn runtime_type_from_text(text: &str) -> Option<RuntimeExpressionType> {
    runtime_array_type(text)
        .or_else(|| runtime_tuple_type(text))
        .or_else(|| runtime_reference_type(text))
        .or_else(|| runtime_raw_pointer_type(text))
        .or_else(|| match text {
            "()" => Some(RuntimeExpressionType::Unit),
            "bool" => Some(RuntimeExpressionType::Bool),
            "char" => Some(RuntimeExpressionType::Char),
            name => Some(RuntimeExpressionType::Integer(Some(
                crate::IntegerType::from_name(name)?,
            ))),
        })
}

fn resolve_runtime_local_type<
    'source,
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    function: &Function<'source, MAX_PARAMETERS>,
    resolver: &R,
    locals: &[Option<RuntimeLocal<'source>>],
    local: &crate::LocalBinding<'source>,
    operand_type: &str,
    body_start: usize,
) -> Result<RuntimeExpressionType, CodegenError> {
    let tree = local
        .parse_initializer::<MAX_EXPRESSION_NODES>()
        .map_err(|error| CodegenError {
            kind: CodegenErrorKind::Expression(error.kind),
            span: translate_span(body_start + local.initializer_span.start, error.span),
        })?;
    let initializer_type =
        runtime_expression_type_with_locals(function, resolver, locals, &tree, tree.root(), 0)
            .map_err(|kind| CodegenError {
                kind,
                span: translate_span(body_start, local.initializer_span),
            })?;
    let local_type = if let Some(ty) = local.ty {
        runtime_type_from_text(ty.text).ok_or(CodegenError {
            kind: CodegenErrorKind::UnsupportedRuntimeType,
            span: translate_span(body_start, ty.span),
        })?
    } else {
        match initializer_type {
            RuntimeExpressionType::Never | RuntimeExpressionType::Default => {
                return Err(CodegenError {
                    kind: CodegenErrorKind::RuntimeTypeMismatch,
                    span: translate_span(body_start, local.initializer_span),
                });
            }
            RuntimeExpressionType::Integer(None) => {
                RuntimeExpressionType::Integer(crate::IntegerType::from_name(operand_type))
            }
            inferred => inferred,
        }
    };
    if !runtime_types_compatible(initializer_type, local_type) {
        return Err(CodegenError {
            kind: CodegenErrorKind::RuntimeTypeMismatch,
            span: translate_span(body_start, local.initializer_span),
        });
    }
    Ok(local_type)
}

#[allow(clippy::too_many_arguments)]
fn preanalyze_runtime_local_binding<
    'source,
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    function: &Function<'source, MAX_PARAMETERS>,
    resolver: &R,
    local: crate::LocalBinding<'source>,
    operand_type: &str,
    body_start: usize,
    facts: &mut RuntimeBodyFacts<'source>,
    locals: &mut [Option<RuntimeLocal<'source>>; MAX_PARAMETERS],
    local_count: &mut usize,
) -> Result<(), CodegenError> {
    if !local.initialized {
        let ty = local
            .ty
            .and_then(|ty| runtime_type_from_text(ty.text))
            .filter(|ty| runtime_type_supports_uninitialized_scalar(*ty))
            .ok_or(CodegenError {
                kind: CodegenErrorKind::UnsupportedRuntimeType,
                span: translate_span(body_start, local.name_span),
            })?;
        let stack_slots = runtime_local_stack_slots(ty);
        let id = facts
            .push_local(
                local.name,
                ty,
                local.mutable,
                false,
                Some(translate_span(body_start, local.name_span)),
            )
            .map_err(|kind| CodegenError {
                kind,
                span: translate_span(body_start, local.name_span),
            })?;
        let slot = locals.get_mut(*local_count).ok_or(CodegenError {
            kind: CodegenErrorKind::TooManyRuntimeLocals,
            span: translate_span(body_start, local.name_span),
        })?;
        *slot = Some(RuntimeLocal {
            id,
            name: local.name,
            ty,
            mutable: local.mutable,
            initialized: local.initialized,
            stack_slots,
        });
        *local_count += 1;
        return Ok(());
    }
    let ty = resolve_runtime_local_type::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
        function,
        resolver,
        &locals[..*local_count],
        &local,
        operand_type,
        body_start,
    )?;
    let tree = local
        .parse_initializer::<MAX_EXPRESSION_NODES>()
        .map_err(|error| CodegenError {
            kind: CodegenErrorKind::Expression(error.kind),
            span: translate_span(body_start + local.initializer_span.start, error.span),
        })?;
    let expression_reference_generation =
        local.name != "_"
            && matches!(ty, RuntimeExpressionType::Reference { .. })
            && (matches!(
                tree.expression(tree.root())
                    .map(|expression| expression.kind),
                Some(ExprKind::If { .. } | ExprKind::LoopBreakIf { .. })
            ) || runtime_expression_reference_call_origin::<
                R,
                MAX_PARAMETERS,
                MAX_EXPRESSION_NODES,
            >(resolver, &tree, tree.root())
            .is_some());
    facts.pending_loan_generation_borrower =
        expression_reference_generation.then_some(RuntimeLocalId(facts.local_count));
    let literal_aggregate = matches!(
        tree.expression(tree.root())
            .map(|expression| expression.kind),
        Some(ExprKind::Array { .. } | ExprKind::ArrayRepeat { .. } | ExprKind::Tuple { .. })
    );
    let literal_conditional_tuple = runtime_type_is_tuple(ty)
        && matches!(
            tree.expression(tree.root()).map(|expression| expression.kind),
            Some(
                ExprKind::If {
                    then_branch,
                    else_branch,
                    ..
                } | ExprKind::LoopBreakIf {
                    then_branch,
                    else_branch,
                    ..
                }
            ) if matches!(
                tree.expression(then_branch).map(|expression| expression.kind),
                Some(ExprKind::Tuple { .. })
            ) && matches!(
                tree.expression(else_branch).map(|expression| expression.kind),
                Some(ExprKind::Tuple { .. })
            )
        );
    let direct_conditional_array = match (
        ty,
        tree.expression(tree.root())
            .map(|expression| expression.kind),
    ) {
        (
            RuntimeExpressionType::Array { count, .. },
            Some(
                ExprKind::If {
                    condition,
                    then_branch,
                    else_branch,
                }
                | ExprKind::LoopBreakIf {
                    condition,
                    then_branch,
                    else_branch,
                },
            ),
        ) => match (
            tree.expression(then_branch)
                .map(|expression| expression.kind),
            tree.expression(else_branch)
                .map(|expression| expression.kind),
        ) {
            (
                Some(ExprKind::Array {
                    elements: then_elements,
                    element_count: then_count,
                }),
                Some(ExprKind::Array {
                    elements: else_elements,
                    element_count: else_count,
                }),
            ) if then_count == count && else_count == count => {
                Some((condition, then_elements, else_elements, count))
            }
            _ => None,
        },
        _ => None,
    };
    let direct_sequence_aggregate = match (
        ty,
        tree.expression(tree.root())
            .map(|expression| expression.kind),
    ) {
        (RuntimeExpressionType::Array { count, .. }, Some(ExprKind::Sequence { first, then })) => {
            match tree.expression(then).map(|expression| expression.kind) {
                Some(ExprKind::Array {
                    elements,
                    element_count,
                }) if element_count == count => Some((first, Some(elements), count)),
                _ => None,
            }
        }
        (
            RuntimeExpressionType::Tuple { element_count, .. },
            Some(ExprKind::Sequence { first, then }),
        ) if matches!(
            tree.expression(then).map(|expression| expression.kind),
            Some(ExprKind::Tuple {
                element_count: count,
                ..
            }) if count == element_count
        ) =>
        {
            Some((first, None, element_count))
        }
        _ => None,
    };
    let simple_fat_reference = runtime_type_is_fat_reference(ty)
        && (runtime_fat_reference_preanalysis_supported(&tree, tree.root(), 0)
            || runtime_fat_reference_call_preanalysis_supported(
                function,
                resolver,
                &locals[..*local_count],
                &tree,
                tree.root(),
                0,
            )
            .map_err(|kind| CodegenError {
                kind,
                span: local.initializer_span,
            })?);
    let simple_fat_sequence = if runtime_type_is_fat_reference(ty)
        && let Some(ExprKind::Sequence { first, then }) = tree
            .expression(tree.root())
            .map(|expression| expression.kind)
        && matches!(
            tree.expression(then).map(|expression| expression.kind),
            Some(ExprKind::Identifier(_))
        ) {
        Some((first, then))
    } else {
        None
    };
    if let RuntimeExpressionType::Array { count, .. } = ty {
        let supported = runtime_return_array_preanalysis_supported(
            function,
            resolver,
            &locals[..*local_count],
            &tree,
            tree.root(),
            count,
            0,
        )
        .map_err(|kind| CodegenError {
            kind,
            span: local.initializer_span,
        })?;
        if supported {
            preanalyze_runtime_return_array_reads(
                facts,
                &locals[..*local_count],
                function,
                resolver,
                &tree,
                tree.root(),
                count,
                0,
                local.initializer_span,
            )?;
        }
    } else if let Some((first, then)) = simple_fat_sequence {
        for expression in [first, then] {
            preanalyze_runtime_expression_at_reads(
                facts,
                &locals[..*local_count],
                function,
                resolver,
                &tree,
                expression,
                local.initializer_span,
            )?;
        }
    } else if let Some((first, Some(elements), count)) = direct_sequence_aggregate {
        for element in &elements[..count] {
            let element = element.ok_or(CodegenError {
                kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                span: local.initializer_span,
            })?;
            for expression in [first, element] {
                preanalyze_runtime_expression_at_reads(
                    facts,
                    &locals[..*local_count],
                    function,
                    resolver,
                    &tree,
                    expression,
                    local.initializer_span,
                )?;
            }
        }
    } else if let Some((condition, then_elements, else_elements, count)) = direct_conditional_array
    {
        for index in 0..count {
            let then_element = then_elements[index].ok_or(CodegenError {
                kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                span: local.initializer_span,
            })?;
            let else_element = else_elements[index].ok_or(CodegenError {
                kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                span: local.initializer_span,
            })?;
            for expression in [condition, then_element, else_element] {
                preanalyze_runtime_expression_at_reads(
                    facts,
                    &locals[..*local_count],
                    function,
                    resolver,
                    &tree,
                    expression,
                    local.initializer_span,
                )?;
            }
        }
    } else if (!runtime_type_is_array(ty)
        && !runtime_type_is_tuple(ty)
        && !runtime_type_is_fat_reference(ty))
        || literal_aggregate
        || literal_conditional_tuple
        || matches!(direct_sequence_aggregate, Some((_, None, _)))
        || simple_fat_reference
    {
        let direct_identifier = matches!(
            tree.expression(tree.root())
                .map(|expression| expression.kind),
            Some(ExprKind::Identifier(_))
        );
        let direct_place = discover_runtime_read_place(&tree, tree.root())
            .map_err(|kind| CodegenError {
                kind,
                span: local.initializer_span,
            })?
            .is_some();
        let coercion_root = direct_place
            || matches!(
                tree.expression(tree.root())
                    .map(|expression| expression.kind),
                Some(ExprKind::If { .. } | ExprKind::LoopBreakIf { .. })
            );
        let context = match (coercion_root, local.ty, ty) {
            (true, Some(_), RuntimeExpressionType::Reference { mutable: true, .. }) => {
                RuntimeReadEffectContext::MutableBorrow
            }
            (true, Some(_), RuntimeExpressionType::Reference { mutable: false, .. }) => {
                RuntimeReadEffectContext::SharedBorrow
            }
            (true, _, _) if direct_identifier => RuntimeReadEffectContext::Value,
            _ if runtime_type_is_copy(ty) => RuntimeReadEffectContext::Value,
            _ => RuntimeReadEffectContext::Move,
        };
        preanalyze_runtime_expression_at_reads_with_tuple(
            facts,
            &locals[..*local_count],
            function,
            resolver,
            &tree,
            tree.root(),
            context,
            runtime_type_is_tuple(ty).then_some(ty),
            local.initializer_span,
        )?;
    } else if (runtime_type_is_array(ty) || runtime_type_is_tuple(ty))
        && let Some(ExprKind::Identifier(name)) = tree
            .expression(tree.root())
            .map(|expression| expression.kind)
    {
        let (base, base_type) = locals
            .iter()
            .rev()
            .flatten()
            .find(|candidate| candidate.name == name)
            .map(|candidate| (RuntimePlaceIdentity::Local(candidate.id), candidate.ty))
            .or_else(|| {
                function
                    .parameters()
                    .iter()
                    .flatten()
                    .enumerate()
                    .find(|(_, parameter)| parameter.name == name)
                    .and_then(|(index, parameter)| {
                        runtime_type_from_text(parameter.ty.text)
                            .map(|ty| (RuntimePlaceIdentity::Parameter(index), ty))
                    })
            })
            .ok_or(CodegenError {
                kind: CodegenErrorKind::UnknownRuntimeName,
                span: local.initializer_span,
            })?;
        let root_span = tree
            .expression(tree.root())
            .ok_or(CodegenError {
                kind: CodegenErrorKind::RuntimeExpressionUnsupported,
                span: local.initializer_span,
            })?
            .span;
        let (projection, read_count) = match ty {
            RuntimeExpressionType::Array { count, .. } => (RuntimePlaceProjection::Index, count),
            RuntimeExpressionType::Tuple { element_count, .. } => {
                (RuntimePlaceProjection::TupleField(0), element_count)
            }
            _ => {
                return Err(CodegenError {
                    kind: CodegenErrorKind::RuntimeTypeMismatch,
                    span: local.initializer_span,
                });
            }
        };
        for field in 0..read_count {
            let projection = match projection {
                RuntimePlaceProjection::TupleField(_) => RuntimePlaceProjection::TupleField(field),
                other => other,
            };
            facts
                .push_assignment_read(
                    RuntimePlaceAccessFact {
                        base,
                        projections: RuntimePlaceProjections::single(projection),
                        ty: base_type,
                        access: RuntimePlaceAccess::Read,
                        span: root_span,
                    },
                    RuntimeReadEffectContext::Value,
                )
                .map_err(|kind| CodegenError {
                    kind,
                    span: local.initializer_span,
                })?;
        }
    }
    facts.pending_loan_generation_borrower = None;
    facts.current_loan_generation_borrower = None;
    if local.name == "_" {
        return Ok(());
    }
    if !runtime_type_is_copy(ty)
        && !matches!(
            (local.ty, ty),
            (Some(_), RuntimeExpressionType::Reference { .. })
        )
        && let Some(expression) = tree.expression(tree.root())
        && let ExprKind::Identifier(name) = expression.kind
    {
        let (base, source_type) = locals
            .iter()
            .rev()
            .flatten()
            .find(|candidate| candidate.name == name)
            .map(|candidate| (RuntimePlaceIdentity::Local(candidate.id), candidate.ty))
            .or_else(|| {
                function
                    .parameters()
                    .iter()
                    .flatten()
                    .enumerate()
                    .find(|(_, parameter)| parameter.name == name)
                    .and_then(|(index, parameter)| {
                        runtime_type_from_text(parameter.ty.text)
                            .map(|ty| (RuntimePlaceIdentity::Parameter(index), ty))
                    })
            })
            .ok_or(CodegenError {
                kind: CodegenErrorKind::UnknownRuntimeName,
                span: translate_span(body_start, local.initializer_span),
            })?;
        if source_type != ty {
            return Err(CodegenError {
                kind: CodegenErrorKind::RuntimeTypeMismatch,
                span: translate_span(body_start, local.initializer_span),
            });
        }
        let path = facts
            .find_move_path(base, RuntimePlaceProjections::EMPTY)
            .ok_or(CodegenError {
                kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                span: translate_span(body_start, local.initializer_span),
            })?;
        facts
            .push_place_effect(
                path,
                RuntimePlaceEffectKind::Move,
                translate_span(body_start + local.initializer_span.start, expression.span),
            )
            .map_err(|kind| CodegenError {
                kind,
                span: translate_span(body_start, local.initializer_span),
            })?;
    }
    let stack_slots = runtime_local_stack_slots(ty);
    let id = facts
        .push_local(
            local.name,
            ty,
            local.mutable,
            local.initialized,
            Some(translate_span(body_start, local.name_span)),
        )
        .map_err(|kind| CodegenError {
            kind,
            span: translate_span(body_start, local.name_span),
        })?;
    let slot = locals.get_mut(*local_count).ok_or(CodegenError {
        kind: CodegenErrorKind::TooManyRuntimeLocals,
        span: translate_span(body_start, local.name_span),
    })?;
    *slot = Some(RuntimeLocal {
        id,
        name: local.name,
        ty,
        mutable: local.mutable,
        initialized: local.initialized,
        stack_slots,
    });
    *local_count += 1;
    Ok(())
}

fn resolve_runtime_assignment_place<'source, const MAX_PARAMETERS: usize>(
    function: &Function<'source, MAX_PARAMETERS>,
    locals: &[Option<RuntimeLocal<'source>>],
    assignment: &crate::Assignment<'source>,
) -> Result<RuntimePlace<'source>, CodegenErrorKind> {
    let name = assignment.binding_name();
    let (base, ty, binding_mutable, binding_initialized) = if let Some((index, local)) =
        locals.iter().enumerate().rev().find_map(|(index, local)| {
            local
                .filter(|local| local.name == name)
                .map(|local| (index, local))
        }) {
        (
            RuntimePlaceBase::Local {
                id: local.id,
                index,
            },
            local.ty,
            local.mutable,
            local.initialized,
        )
    } else if let Some((index, parameter)) = function
        .parameters()
        .iter()
        .flatten()
        .enumerate()
        .find(|(_, parameter)| parameter.name == name)
    {
        (
            RuntimePlaceBase::Parameter { index },
            runtime_type_from_text(parameter.ty.text)
                .ok_or(CodegenErrorKind::UnsupportedRuntimeType)?,
            false,
            true,
        )
    } else {
        return Err(CodegenErrorKind::UnknownRuntimeName);
    };
    let mutable = match assignment.projection {
        Some(crate::parser::AssignmentProjection::Dereference { .. }) => match ty {
            RuntimeExpressionType::Reference { mutable, .. }
            | RuntimeExpressionType::RawPointer { mutable, .. } => mutable,
            _ => binding_mutable,
        },
        Some(crate::parser::AssignmentProjection::Index { .. }) => match ty {
            RuntimeExpressionType::Reference { mutable, .. } => mutable,
            _ => binding_mutable,
        },
        None if assignment.operator == crate::AssignmentOperator::Assign
            && !binding_initialized =>
        {
            true
        }
        _ => binding_mutable,
    };
    Ok(RuntimePlace {
        base,
        projection: assignment.projection,
        ty,
        mutable,
        access: RuntimePlaceAccess::from_operator(assignment.operator),
    })
}

fn push_read<'source, const MAX_PARAMETERS: usize>(
    facts: &mut RuntimeBodyFacts<'source>,
    locals: &[Option<RuntimeLocal<'source>>],
    function: &Function<'source, MAX_PARAMETERS>,
    place: RuntimeReadPlace<'source>,
    context: RuntimeReadEffectContext,
    assignment_span: Span,
) -> Result<(), CodegenError> {
    let resolved = locals
        .iter()
        .rev()
        .flatten()
        .find(|local| local.name == place.name)
        .map(|local| (RuntimePlaceIdentity::Local(local.id), local.ty))
        .or_else(|| {
            function
                .parameters()
                .iter()
                .flatten()
                .enumerate()
                .find(|(_, parameter)| parameter.name == place.name)
                .and_then(|(index, parameter)| {
                    runtime_type_from_text(parameter.ty.text)
                        .map(|ty| (RuntimePlaceIdentity::Parameter(index), ty))
                })
        });
    if let Some((base, ty)) = resolved {
        facts
            .push_assignment_read(
                RuntimePlaceAccessFact {
                    base,
                    projections: place.projections,
                    ty,
                    access: RuntimePlaceAccess::Read,
                    span: place.span,
                },
                context,
            )
            .map_err(|kind| CodegenError {
                kind,
                span: assignment_span,
            })?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn preanalyze_runtime_expression_at_reads_with_tuple<
    'source,
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    facts: &mut RuntimeBodyFacts<'source>,
    locals: &[Option<RuntimeLocal<'source>>],
    function: &Function<'source, MAX_PARAMETERS>,
    resolver: &R,
    tree: &crate::ExpressionTree<'source, MAX_EXPRESSION_NODES>,
    root: crate::ExprId,
    root_context: RuntimeReadEffectContext,
    tuple_expected: Option<RuntimeExpressionType>,
    expression_span: Span,
) -> Result<(), CodegenError> {
    #[allow(clippy::too_many_arguments)]
    fn recurse<
        'source,
        R: ConstantResolver,
        const MAX_PARAMETERS: usize,
        const MAX_EXPRESSION_NODES: usize,
    >(
        facts: &mut RuntimeBodyFacts<'source>,
        locals: &[Option<RuntimeLocal<'source>>],
        function: &Function<'source, MAX_PARAMETERS>,
        resolver: &R,
        tree: &crate::ExpressionTree<'source, MAX_EXPRESSION_NODES>,
        id: crate::ExprId,
        context: RuntimeReadEffectContext,
        depth: usize,
        assignment_span: Span,
    ) -> Result<(), CodegenError> {
        if depth == 64 {
            return Err(CodegenError {
                kind: CodegenErrorKind::Lowering(IrErrorKind::NestingLimitExceeded),
                span: assignment_span,
            });
        }
        let expression = tree.expression(id).ok_or(CodegenError {
            kind: CodegenErrorKind::RuntimeExpressionUnsupported,
            span: assignment_span,
        })?;
        if let ExprKind::Sequence { first, then } = expression.kind {
            let generation_borrower = facts.current_loan_generation_borrower;
            facts.current_loan_generation_borrower = None;
            recurse(
                facts,
                locals,
                function,
                resolver,
                tree,
                first,
                RuntimeReadEffectContext::Value,
                depth + 1,
                assignment_span,
            )?;
            facts.current_loan_generation_borrower = generation_borrower;
            recurse(
                facts,
                locals,
                function,
                resolver,
                tree,
                then,
                context,
                depth + 1,
                assignment_span,
            )?;
            return Ok(());
        }
        if let ExprKind::Index { base, index } = expression.kind {
            let base_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )
            .map_err(|kind| CodegenError {
                kind,
                span: assignment_span,
            })?;
            match base_type {
                RuntimeExpressionType::Reference { .. } => {
                    recurse(
                        facts,
                        locals,
                        function,
                        resolver,
                        tree,
                        base,
                        RuntimeReadEffectContext::Unclassified,
                        depth + 1,
                        assignment_span,
                    )?;
                    recurse(
                        facts,
                        locals,
                        function,
                        resolver,
                        tree,
                        index,
                        RuntimeReadEffectContext::Value,
                        depth + 1,
                        assignment_span,
                    )?;
                    return Ok(());
                }
                RuntimeExpressionType::Array { count, .. } => {
                    if let Some(ExprKind::Identifier(name)) =
                        tree.expression(base).map(|expression| expression.kind)
                    {
                        let base_span = tree
                            .expression(base)
                            .ok_or(CodegenError {
                                kind: CodegenErrorKind::RuntimeExpressionUnsupported,
                                span: assignment_span,
                            })?
                            .span;
                        let constant_index = tree
                            .evaluate_at(index, resolver)
                            .ok()
                            .and_then(|index| usize::try_from(index).ok())
                            .filter(|index| *index < count);
                        let place = RuntimeReadPlace {
                            name,
                            span: base_span,
                            projections: RuntimePlaceProjections::single(constant_index.map_or(
                                RuntimePlaceProjection::Index,
                                RuntimePlaceProjection::ArrayElement,
                            )),
                        };
                        let reads = if constant_index.is_some() { 1 } else { count };
                        for _ in 0..reads {
                            push_read(
                                facts,
                                locals,
                                function,
                                place,
                                RuntimeReadEffectContext::Unclassified,
                                assignment_span,
                            )?;
                        }
                    } else if runtime_return_array_preanalysis_supported(
                        function,
                        resolver,
                        locals,
                        tree,
                        base,
                        count,
                        depth + 1,
                    )
                    .map_err(|kind| CodegenError {
                        kind,
                        span: assignment_span,
                    })? {
                        preanalyze_runtime_return_array_reads(
                            facts,
                            locals,
                            function,
                            resolver,
                            tree,
                            base,
                            count,
                            depth + 1,
                            assignment_span,
                        )?;
                    }
                    recurse(
                        facts,
                        locals,
                        function,
                        resolver,
                        tree,
                        index,
                        RuntimeReadEffectContext::Value,
                        depth + 1,
                        assignment_span,
                    )?;
                    return Ok(());
                }
                _ => {}
            }
        }
        if let Some(place) = discover_runtime_read_place(tree, id).map_err(|kind| CodegenError {
            kind,
            span: assignment_span,
        })? {
            let place =
                refine_constant_array_read_place(function, resolver, locals, tree, id, place)
                    .map_err(|kind| CodegenError {
                        kind,
                        span: assignment_span,
                    })?;
            push_read(facts, locals, function, place, context, assignment_span)?;
            if let ExprKind::Index { index, .. } = expression.kind {
                recurse(
                    facts,
                    locals,
                    function,
                    resolver,
                    tree,
                    index,
                    RuntimeReadEffectContext::Value,
                    depth + 1,
                    assignment_span,
                )?;
            }
            return Ok(());
        }

        macro_rules! visit {
            ($operand:expr) => {
                recurse(
                    facts,
                    locals,
                    function,
                    resolver,
                    tree,
                    $operand,
                    context,
                    depth + 1,
                    assignment_span,
                )
            };
        }
        macro_rules! visit_as {
            ($operand:expr, $context:expr) => {
                recurse(
                    facts,
                    locals,
                    function,
                    resolver,
                    tree,
                    $operand,
                    $context,
                    depth + 1,
                    assignment_span,
                )
            };
        }
        macro_rules! visit_value {
            ($operand:expr) => {
                visit_as!($operand, RuntimeReadEffectContext::Value)
            };
        }
        match expression.kind {
            ExprKind::Cast { operand, .. }
            | ExprKind::Ascribe { operand, .. }
            | ExprKind::Return { operand }
            | ExprKind::LoopBreak { operand } => visit!(operand)?,
            ExprKind::Unary {
                operator:
                    operator @ (crate::UnaryOperator::AddressOf | crate::UnaryOperator::AddressOfMut),
                operand,
            } => {
                let borrow_context = match operator {
                    crate::UnaryOperator::AddressOf => RuntimeReadEffectContext::SharedBorrow,
                    crate::UnaryOperator::AddressOfMut => RuntimeReadEffectContext::MutableBorrow,
                    _ => unreachable!(),
                };
                match tree.expression(operand).map(|expression| expression.kind) {
                    Some(ExprKind::Identifier(name)) => {
                        let span = tree
                            .expression(operand)
                            .ok_or(CodegenError {
                                kind: CodegenErrorKind::RuntimeExpressionUnsupported,
                                span: assignment_span,
                            })?
                            .span;
                        push_read(
                            facts,
                            locals,
                            function,
                            RuntimeReadPlace {
                                name,
                                span,
                                projections: RuntimePlaceProjections::EMPTY,
                            },
                            borrow_context,
                            assignment_span,
                        )?;
                    }
                    Some(ExprKind::Index { base, index }) => {
                        if let Some(ExprKind::RangeIndex { .. }) =
                            tree.expression(base).map(|expression| expression.kind)
                        {
                            let mut ranges = [None; 64];
                            let mut range_count = 0usize;
                            let mut current = base;
                            while let Some(ExprKind::RangeIndex {
                                base: next,
                                start,
                                end,
                                ..
                            }) = tree.expression(current).map(|expression| expression.kind)
                            {
                                let slot = ranges.get_mut(range_count).ok_or(CodegenError {
                                    kind: CodegenErrorKind::Lowering(
                                        IrErrorKind::NestingLimitExceeded,
                                    ),
                                    span: assignment_span,
                                })?;
                                *slot = Some((start, end));
                                range_count += 1;
                                current = next;
                            }
                            for (start, end) in ranges[..range_count].iter().rev().flatten() {
                                if let Some(start) = start {
                                    visit_value!(*start)?;
                                }
                                if let Some(end) = end {
                                    visit_value!(*end)?;
                                }
                            }
                            let mut place = discover_runtime_read_place(tree, base)
                                .map_err(|kind| CodegenError {
                                    kind,
                                    span: assignment_span,
                                })?
                                .ok_or(CodegenError {
                                    kind: CodegenErrorKind::RuntimeExpressionUnsupported,
                                    span: assignment_span,
                                })?;
                            place
                                .projections
                                .push(RuntimePlaceProjection::Index)
                                .map_err(|kind| CodegenError {
                                    kind,
                                    span: assignment_span,
                                })?;
                            push_read(
                                facts,
                                locals,
                                function,
                                place,
                                borrow_context,
                                assignment_span,
                            )?;
                            visit_value!(index)?;
                            return Ok(());
                        }
                        let base_type = runtime_expression_type_with_locals(
                            function,
                            resolver,
                            locals,
                            tree,
                            base,
                            depth + 1,
                        )
                        .map_err(|kind| CodegenError {
                            kind,
                            span: assignment_span,
                        })?;
                        if matches!(base_type, RuntimeExpressionType::Array { .. })
                            && let Some(ExprKind::Identifier(name)) =
                                tree.expression(base).map(|expression| expression.kind)
                        {
                            let span = tree
                                .expression(base)
                                .ok_or(CodegenError {
                                    kind: CodegenErrorKind::RuntimeExpressionUnsupported,
                                    span: assignment_span,
                                })?
                                .span;
                            push_read(
                                facts,
                                locals,
                                function,
                                RuntimeReadPlace {
                                    name,
                                    span,
                                    projections: RuntimePlaceProjections::single(
                                        RuntimePlaceProjection::Index,
                                    ),
                                },
                                borrow_context,
                                assignment_span,
                            )?;
                        } else {
                            visit_as!(base, borrow_context)?;
                        }
                        visit_value!(index)?;
                    }
                    Some(ExprKind::Unary {
                        operator: crate::UnaryOperator::Dereference,
                        operand: reference,
                    }) => {
                        if let Some(ExprKind::Identifier(name)) =
                            tree.expression(reference).map(|expression| expression.kind)
                        {
                            let span = tree
                                .expression(reference)
                                .ok_or(CodegenError {
                                    kind: CodegenErrorKind::RuntimeExpressionUnsupported,
                                    span: assignment_span,
                                })?
                                .span;
                            push_read(
                                facts,
                                locals,
                                function,
                                RuntimeReadPlace {
                                    name,
                                    span,
                                    projections: RuntimePlaceProjections::EMPTY,
                                },
                                borrow_context,
                                assignment_span,
                            )?;
                        } else {
                            visit_as!(reference, borrow_context)?;
                        }
                    }
                    Some(ExprKind::RangeIndex { base, .. }) if matches!(
                        tree.expression(base).map(|expression| expression.kind),
                        Some(ExprKind::RangeIndex { .. })
                    ) => {
                        let mut ranges = [None; 64];
                        let mut range_count = 0usize;
                        let mut current = operand;
                        while let Some(ExprKind::RangeIndex {
                            base: next,
                            start,
                            end,
                            ..
                        }) = tree.expression(current).map(|expression| expression.kind)
                        {
                            let slot = ranges.get_mut(range_count).ok_or(CodegenError {
                                kind: CodegenErrorKind::Lowering(
                                    IrErrorKind::NestingLimitExceeded,
                                ),
                                span: assignment_span,
                            })?;
                            *slot = Some((start, end));
                            range_count += 1;
                            current = next;
                        }
                        for (start, end) in ranges[..range_count].iter().rev().flatten() {
                            if let Some(start) = start {
                                visit_value!(*start)?;
                            }
                            if let Some(end) = end {
                                visit_value!(*end)?;
                            }
                        }
                        let place = discover_runtime_read_place(tree, operand)
                            .map_err(|kind| CodegenError {
                                kind,
                                span: assignment_span,
                            })?
                            .ok_or(CodegenError {
                                kind: CodegenErrorKind::RuntimeExpressionUnsupported,
                                span: assignment_span,
                            })?;
                        push_read(
                            facts,
                            locals,
                            function,
                            place,
                            borrow_context,
                            assignment_span,
                        )?;
                    }
                    Some(ExprKind::RangeIndex {
                        base, start, end, ..
                    }) => {
                        if let Some(start) = start {
                            visit_value!(start)?;
                        }
                        if let Some(end) = end {
                            visit_value!(end)?;
                        }
                        let base_type = runtime_expression_type_with_locals(
                            function,
                            resolver,
                            locals,
                            tree,
                            base,
                            depth + 1,
                        )
                        .map_err(|kind| CodegenError {
                            kind,
                            span: assignment_span,
                        })?;
                        if matches!(base_type, RuntimeExpressionType::Array { .. })
                            && let Some(ExprKind::Identifier(name)) =
                                tree.expression(base).map(|expression| expression.kind)
                        {
                            let span = tree
                                .expression(base)
                                .ok_or(CodegenError {
                                    kind: CodegenErrorKind::RuntimeExpressionUnsupported,
                                    span: assignment_span,
                                })?
                                .span;
                            push_read(
                                facts,
                                locals,
                                function,
                                RuntimeReadPlace {
                                    name,
                                    span,
                                    projections: RuntimePlaceProjections::single(
                                        RuntimePlaceProjection::Subslice,
                                    ),
                                },
                                borrow_context,
                                assignment_span,
                            )?;
                        } else {
                            visit_as!(base, borrow_context)?;
                        }
                    }
                    _ => {}
                }
            }
            ExprKind::Unary { operand, .. } => visit!(operand)?,
            ExprKind::Sequence { first, then } => {
                visit!(first)?;
                visit!(then)?;
            }
            ExprKind::Binary { left, right, .. } => {
                visit_value!(left)?;
                visit_value!(right)?;
            }
            ExprKind::If {
                condition,
                then_branch,
                else_branch,
            }
            | ExprKind::LoopBreakIf {
                condition,
                then_branch,
                else_branch,
            } => {
                let parent_conditional = facts.current_conditional_expression;
                let conditional =
                    facts
                        .push_conditional_expression(expression.span)
                        .map_err(|kind| CodegenError {
                            kind,
                            span: assignment_span,
                        })?;
                let conditional_fact =
                    facts.conditional_expressions[conditional.0].ok_or(CodegenError {
                        kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                        span: assignment_span,
                    })?;
                facts.current_conditional_expression = Some(conditional);
                facts.current_expression_program_point = Some(conditional_fact.condition);
                let generation_borrower = facts.current_loan_generation_borrower;
                facts.current_loan_generation_borrower = None;
                visit_value!(condition)?;
                facts.current_loan_generation_borrower = generation_borrower;
                let parent_path = facts.current_ownership_expression_path;
                for (else_branch, branch) in [(false, then_branch), (true, else_branch)] {
                    facts.current_conditional_expression = Some(conditional);
                    facts.current_expression_program_point = Some(if else_branch {
                        conditional_fact.else_branch
                    } else {
                        conditional_fact.then_branch
                    });
                    facts.current_ownership_expression_path = parent_path
                        .branch(else_branch)
                        .map_err(|kind| CodegenError {
                            kind,
                            span: assignment_span,
                        })?;
                    facts.current_loan_generation_borrower = facts.pending_loan_generation_borrower;
                    let result = recurse(
                        facts,
                        locals,
                        function,
                        resolver,
                        tree,
                        branch,
                        context,
                        depth + 1,
                        assignment_span,
                    );
                    let exit = facts.current_expression_program_point.ok_or(CodegenError {
                        kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                        span: assignment_span,
                    })?;
                    facts
                        .set_conditional_expression_exit(conditional, else_branch, exit)
                        .map_err(|kind| CodegenError {
                            kind,
                            span: assignment_span,
                        })?;
                    facts.current_ownership_expression_path = parent_path;
                    facts.current_loan_generation_borrower = generation_borrower;
                    result?;
                }
                facts.current_conditional_expression = parent_conditional;
                facts.current_expression_program_point = Some(conditional_fact.join);
            }
            ExprKind::Array {
                elements,
                element_count,
            } => {
                for element in elements[..element_count].iter().flatten() {
                    visit_value!(*element)?;
                }
            }
            ExprKind::Tuple {
                elements,
                element_count,
            } => {
                for element in elements[..element_count].iter().flatten() {
                    visit_value!(*element)?;
                }
            }
            ExprKind::ArrayRepeat { element, .. } => visit_value!(element)?,
            ExprKind::Call {
                callee,
                arguments,
                argument_count,
            } => {
                if !runtime_call_arguments_preanalysis_supported(
                    function,
                    resolver,
                    locals,
                    tree,
                    id,
                    depth + 1,
                )
                .map_err(|kind| CodegenError {
                    kind,
                    span: assignment_span,
                })? {
                    return Ok(());
                }
                let target = resolver
                    .resolve_runtime_call::<MAX_PARAMETERS>(callee, argument_count)
                    .ok_or(CodegenError {
                        kind: CodegenErrorKind::RuntimeExpressionUnsupported,
                        span: assignment_span,
                    })?;
                let result_may_carry_reference = matches!(
                    target.return_type,
                    crate::ScalarType::Reference { .. }
                        | crate::ScalarType::ArrayReference { .. }
                        | crate::ScalarType::SliceReference { .. }
                        | crate::ScalarType::StrReference { .. }
                );
                let result_origin_parameter = runtime_reference_call_origin_parameter::<
                    MAX_PARAMETERS,
                    MAX_EXPRESSION_NODES,
                >(target);
                for (parameter_index, (parameter, argument)) in target.parameters
                    [..target.parameter_count]
                    .iter()
                    .zip(arguments[..argument_count].iter())
                    .enumerate()
                {
                    let parameter = parameter.ok_or(CodegenError {
                        kind: CodegenErrorKind::RuntimeExpressionUnsupported,
                        span: assignment_span,
                    })?;
                    let argument = argument.ok_or(CodegenError {
                        kind: CodegenErrorKind::RuntimeExpressionUnsupported,
                        span: assignment_span,
                    })?;
                    let expected = runtime_type_from_scalar(parameter.ty);
                    if let RuntimeExpressionType::Array { count, .. } = expected {
                        preanalyze_runtime_return_array_reads(
                            facts,
                            locals,
                            function,
                            resolver,
                            tree,
                            argument,
                            count,
                            depth + 1,
                            assignment_span,
                        )?;
                    } else if let expected @ RuntimeExpressionType::Tuple { .. } = expected {
                        recurse_tuple_value(
                            facts,
                            locals,
                            function,
                            resolver,
                            tree,
                            argument,
                            expected,
                            depth + 1,
                            assignment_span,
                        )?;
                    } else if let RuntimeExpressionType::Array { count, .. } = expected
                        && let Some(ExprKind::Sequence { first, then }) =
                            tree.expression(argument).map(|expression| expression.kind)
                    {
                        match tree.expression(then).map(|expression| expression.kind) {
                            Some(ExprKind::DefaultValue) => {
                                for _ in 0..count {
                                    visit_value!(first)?;
                                }
                            }
                            Some(ExprKind::Identifier(name)) => {
                                let span = tree
                                    .expression(then)
                                    .ok_or(CodegenError {
                                        kind: CodegenErrorKind::RuntimeExpressionUnsupported,
                                        span: assignment_span,
                                    })?
                                    .span;
                                for _ in 0..count {
                                    visit!(first)?;
                                    push_read(
                                        facts,
                                        locals,
                                        function,
                                        RuntimeReadPlace {
                                            name,
                                            span,
                                            projections: RuntimePlaceProjections::single(
                                                RuntimePlaceProjection::Index,
                                            ),
                                        },
                                        RuntimeReadEffectContext::Value,
                                        assignment_span,
                                    )?;
                                }
                            }
                            Some(ExprKind::Array {
                                elements,
                                element_count,
                            }) if element_count == count => {
                                for element in elements[..element_count].iter().flatten() {
                                    visit_value!(first)?;
                                    visit_value!(*element)?;
                                }
                            }
                            Some(ExprKind::ArrayRepeat {
                                element,
                                count: repeat,
                            }) if repeat == count => {
                                for _ in 0..count {
                                    visit_value!(first)?;
                                    visit_value!(element)?;
                                }
                            }
                            Some(
                                ExprKind::If {
                                    condition,
                                    then_branch,
                                    else_branch,
                                }
                                | ExprKind::LoopBreakIf {
                                    condition,
                                    then_branch,
                                    else_branch,
                                },
                            ) => {
                                let (
                                    Some(ExprKind::Array {
                                        elements: then_elements,
                                        element_count: then_count,
                                    }),
                                    Some(ExprKind::Array {
                                        elements: else_elements,
                                        element_count: else_count,
                                    }),
                                ) = (
                                    tree.expression(then_branch)
                                        .map(|expression| expression.kind),
                                    tree.expression(else_branch)
                                        .map(|expression| expression.kind),
                                )
                                else {
                                    return Err(CodegenError {
                                        kind: CodegenErrorKind::RuntimeExpressionUnsupported,
                                        span: assignment_span,
                                    });
                                };
                                if then_count != count || else_count != count {
                                    return Err(CodegenError {
                                        kind: CodegenErrorKind::RuntimeTypeMismatch,
                                        span: assignment_span,
                                    });
                                }
                                for index in 0..count {
                                    for operand in [
                                        first,
                                        condition,
                                        then_elements[index].ok_or(CodegenError {
                                            kind: CodegenErrorKind::RuntimeExpressionUnsupported,
                                            span: assignment_span,
                                        })?,
                                        else_elements[index].ok_or(CodegenError {
                                            kind: CodegenErrorKind::RuntimeExpressionUnsupported,
                                            span: assignment_span,
                                        })?,
                                    ] {
                                        visit_value!(operand)?;
                                    }
                                }
                            }
                            _ => {
                                return Err(CodegenError {
                                    kind: CodegenErrorKind::RuntimeExpressionUnsupported,
                                    span: assignment_span,
                                });
                            }
                        }
                    } else if let RuntimeExpressionType::Array { count, .. } = expected
                        && let Some(
                            ExprKind::If {
                                condition,
                                then_branch,
                                else_branch,
                            }
                            | ExprKind::LoopBreakIf {
                                condition,
                                then_branch,
                                else_branch,
                            },
                        ) = tree.expression(argument).map(|expression| expression.kind)
                        && let (
                            Some(ExprKind::Array {
                                elements: then_elements,
                                element_count: then_count,
                            }),
                            Some(ExprKind::Array {
                                elements: else_elements,
                                element_count: else_count,
                            }),
                        ) = (
                            tree.expression(then_branch)
                                .map(|expression| expression.kind),
                            tree.expression(else_branch)
                                .map(|expression| expression.kind),
                        )
                        && then_count == count
                        && else_count == count
                    {
                        for index in 0..count {
                            for operand in [
                                condition,
                                then_elements[index].ok_or(CodegenError {
                                    kind: CodegenErrorKind::RuntimeExpressionUnsupported,
                                    span: assignment_span,
                                })?,
                                else_elements[index].ok_or(CodegenError {
                                    kind: CodegenErrorKind::RuntimeExpressionUnsupported,
                                    span: assignment_span,
                                })?,
                            ] {
                                visit_value!(operand)?;
                            }
                        }
                    } else if matches!(
                        expected,
                        RuntimeExpressionType::Array { .. } | RuntimeExpressionType::Tuple { .. }
                    ) && let Some(ExprKind::Identifier(name)) =
                        tree.expression(argument).map(|expression| expression.kind)
                    {
                        let span = tree
                            .expression(argument)
                            .ok_or(CodegenError {
                                kind: CodegenErrorKind::RuntimeExpressionUnsupported,
                                span: assignment_span,
                            })?
                            .span;
                        let (projection, count) = match expected {
                            RuntimeExpressionType::Array { count, .. } => {
                                (RuntimePlaceProjection::Index, count)
                            }
                            RuntimeExpressionType::Tuple { element_count, .. } => {
                                (RuntimePlaceProjection::TupleField(0), element_count)
                            }
                            _ => unreachable!(),
                        };
                        for field in 0..count {
                            push_read(
                                facts,
                                locals,
                                function,
                                RuntimeReadPlace {
                                    name,
                                    span,
                                    projections: RuntimePlaceProjections::single(
                                        match projection {
                                            RuntimePlaceProjection::TupleField(_) => {
                                                RuntimePlaceProjection::TupleField(field)
                                            }
                                            other => other,
                                        },
                                    ),
                                },
                                RuntimeReadEffectContext::Value,
                                assignment_span,
                            )?;
                        }
                    } else {
                        let coercion_root = discover_runtime_read_place(tree, argument)
                            .map_err(|kind| CodegenError {
                                kind,
                                span: assignment_span,
                            })?
                            .is_some()
                            || matches!(
                                tree.expression(argument).map(|expression| expression.kind),
                                Some(ExprKind::If { .. } | ExprKind::LoopBreakIf { .. })
                            );
                        let carries_result_origin =
                            result_origin_parameter == Some(parameter_index);
                        let persistent_result_context = carries_result_origin.then(|| {
                            match runtime_type_from_scalar(target.return_type) {
                                RuntimeExpressionType::Reference { mutable: true, .. } => {
                                    RuntimeReadEffectContext::MutableBorrow
                                }
                                RuntimeExpressionType::Reference { mutable: false, .. } => {
                                    RuntimeReadEffectContext::SharedBorrow
                                }
                                _ => RuntimeReadEffectContext::Unclassified,
                            }
                        });
                        let argument_context = match (coercion_root, persistent_result_context, expected) {
                            (true, Some(context), RuntimeExpressionType::Reference { .. }) => context,
                            (true, _, RuntimeExpressionType::Reference { mutable: true, .. }) => {
                                RuntimeReadEffectContext::MutableBorrow
                            }
                            (true, _, RuntimeExpressionType::Reference { mutable: false, .. }) => {
                                RuntimeReadEffectContext::SharedBorrow
                            }
                            (_, _, _) if runtime_type_is_copy(expected) => RuntimeReadEffectContext::Value,
                            _ => RuntimeReadEffectContext::Move,
                        };
                        let generation_borrower = facts.current_loan_generation_borrower;
                        if carries_result_origin
                            || (result_may_carry_reference
                                && matches!(expected, RuntimeExpressionType::Reference { .. }))
                        {
                            facts.current_loan_generation_borrower =
                                facts.pending_loan_generation_borrower;
                        }
                        let result = recurse(
                            facts,
                            locals,
                            function,
                            resolver,
                            tree,
                            argument,
                            argument_context,
                            depth + 1,
                            assignment_span,
                        );
                        facts.current_loan_generation_borrower = generation_borrower;
                        result?;
                    }
                }
            }
            // Inline const operands cannot capture runtime locals. Other compound
            // expression families remain outside this bounded preanalysis slice.
            _ => {}
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn recurse_tuple_value<
        'source,
        R: ConstantResolver,
        const MAX_PARAMETERS: usize,
        const MAX_EXPRESSION_NODES: usize,
    >(
        facts: &mut RuntimeBodyFacts<'source>,
        locals: &[Option<RuntimeLocal<'source>>],
        function: &Function<'source, MAX_PARAMETERS>,
        resolver: &R,
        tree: &crate::ExpressionTree<'source, MAX_EXPRESSION_NODES>,
        id: crate::ExprId,
        expected: RuntimeExpressionType,
        depth: usize,
        assignment_span: Span,
    ) -> Result<(), CodegenError> {
        if depth == 64 {
            return Err(CodegenError {
                kind: CodegenErrorKind::Lowering(IrErrorKind::NestingLimitExceeded),
                span: assignment_span,
            });
        }
        let RuntimeExpressionType::Tuple {
            elements: expected_elements,
            element_count,
        } = expected
        else {
            return Err(CodegenError {
                kind: CodegenErrorKind::RuntimeTypeMismatch,
                span: assignment_span,
            });
        };
        let expression = tree.expression(id).ok_or(CodegenError {
            kind: CodegenErrorKind::RuntimeExpressionUnsupported,
            span: assignment_span,
        })?;
        match expression.kind {
            ExprKind::Call { .. } => recurse(
                facts,
                locals,
                function,
                resolver,
                tree,
                id,
                RuntimeReadEffectContext::Value,
                depth + 1,
                assignment_span,
            ),
            ExprKind::InlineConst { operand } => recurse_tuple_value(
                facts,
                locals,
                function,
                resolver,
                tree,
                operand,
                expected,
                depth + 1,
                assignment_span,
            ),
            ExprKind::Sequence { first, then } => {
                recurse(
                    facts,
                    locals,
                    function,
                    resolver,
                    tree,
                    first,
                    RuntimeReadEffectContext::Value,
                    depth + 1,
                    assignment_span,
                )?;
                recurse_tuple_value(
                    facts,
                    locals,
                    function,
                    resolver,
                    tree,
                    then,
                    expected,
                    depth + 1,
                    assignment_span,
                )
            }
            ExprKind::If {
                condition,
                then_branch,
                else_branch,
            }
            | ExprKind::LoopBreakIf {
                condition,
                then_branch,
                else_branch,
            } => {
                let parent_conditional = facts.current_conditional_expression;
                let conditional =
                    facts
                        .push_conditional_expression(expression.span)
                        .map_err(|kind| CodegenError {
                            kind,
                            span: assignment_span,
                        })?;
                let conditional_fact =
                    facts.conditional_expressions[conditional.0].ok_or(CodegenError {
                        kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                        span: assignment_span,
                    })?;
                facts.current_conditional_expression = Some(conditional);
                facts.current_expression_program_point = Some(conditional_fact.condition);
                recurse(
                    facts,
                    locals,
                    function,
                    resolver,
                    tree,
                    condition,
                    RuntimeReadEffectContext::Value,
                    depth + 1,
                    assignment_span,
                )?;
                let parent_path = facts.current_ownership_expression_path;
                for (else_branch, branch) in [(false, then_branch), (true, else_branch)] {
                    facts.current_conditional_expression = Some(conditional);
                    facts.current_expression_program_point = Some(if else_branch {
                        conditional_fact.else_branch
                    } else {
                        conditional_fact.then_branch
                    });
                    facts.current_ownership_expression_path = parent_path
                        .branch(else_branch)
                        .map_err(|kind| CodegenError {
                            kind,
                            span: assignment_span,
                        })?;
                    let result = recurse_tuple_value(
                        facts,
                        locals,
                        function,
                        resolver,
                        tree,
                        branch,
                        expected,
                        depth + 1,
                        assignment_span,
                    );
                    let exit = facts.current_expression_program_point.ok_or(CodegenError {
                        kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                        span: assignment_span,
                    })?;
                    facts
                        .set_conditional_expression_exit(conditional, else_branch, exit)
                        .map_err(|kind| CodegenError {
                            kind,
                            span: assignment_span,
                        })?;
                    facts.current_ownership_expression_path = parent_path;
                    result?;
                }
                facts.current_conditional_expression = parent_conditional;
                facts.current_expression_program_point = Some(conditional_fact.join);
                Ok(())
            }
            ExprKind::Tuple {
                elements,
                element_count: actual_count,
            } => {
                if actual_count != element_count {
                    return Err(CodegenError {
                        kind: CodegenErrorKind::RuntimeTypeMismatch,
                        span: assignment_span,
                    });
                }
                for (field, element) in elements[..actual_count].iter().enumerate() {
                    let element = element.ok_or(CodegenError {
                        kind: CodegenErrorKind::RuntimeExpressionUnsupported,
                        span: assignment_span,
                    })?;
                    let expected_element = expected_elements[field].ok_or(CodegenError {
                        kind: CodegenErrorKind::RuntimeTypeMismatch,
                        span: assignment_span,
                    })?;
                    recurse(
                        facts,
                        locals,
                        function,
                        resolver,
                        tree,
                        element,
                        if runtime_type_is_copy(runtime_type_from_tuple_element(expected_element)) {
                            RuntimeReadEffectContext::Value
                        } else {
                            RuntimeReadEffectContext::Move
                        },
                        depth + 1,
                        assignment_span,
                    )?;
                }
                Ok(())
            }
            _ => {
                for field in 0..element_count {
                    recurse_tuple_field(
                        facts,
                        locals,
                        function,
                        resolver,
                        tree,
                        id,
                        field,
                        expected,
                        depth + 1,
                        assignment_span,
                    )?;
                }
                Ok(())
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn recurse_tuple_field<
        'source,
        R: ConstantResolver,
        const MAX_PARAMETERS: usize,
        const MAX_EXPRESSION_NODES: usize,
    >(
        facts: &mut RuntimeBodyFacts<'source>,
        locals: &[Option<RuntimeLocal<'source>>],
        function: &Function<'source, MAX_PARAMETERS>,
        resolver: &R,
        tree: &crate::ExpressionTree<'source, MAX_EXPRESSION_NODES>,
        id: crate::ExprId,
        field: usize,
        expected: RuntimeExpressionType,
        depth: usize,
        assignment_span: Span,
    ) -> Result<(), CodegenError> {
        if depth == 64 {
            return Err(CodegenError {
                kind: CodegenErrorKind::Lowering(IrErrorKind::NestingLimitExceeded),
                span: assignment_span,
            });
        }
        let RuntimeExpressionType::Tuple {
            elements: expected_elements,
            element_count: expected_count,
        } = expected
        else {
            return Err(CodegenError {
                kind: CodegenErrorKind::RuntimeTypeMismatch,
                span: assignment_span,
            });
        };
        if field >= expected_count {
            return Err(CodegenError {
                kind: CodegenErrorKind::ValueOutOfRange,
                span: assignment_span,
            });
        }
        let expected_element = expected_elements[field].ok_or(CodegenError {
            kind: CodegenErrorKind::RuntimeTypeMismatch,
            span: assignment_span,
        })?;
        let field_context =
            if runtime_type_is_copy(runtime_type_from_tuple_element(expected_element)) {
                RuntimeReadEffectContext::Value
            } else {
                RuntimeReadEffectContext::Move
            };
        let expression = tree.expression(id).ok_or(CodegenError {
            kind: CodegenErrorKind::RuntimeExpressionUnsupported,
            span: assignment_span,
        })?;
        match expression.kind {
            ExprKind::Tuple {
                elements,
                element_count,
            } => {
                let element = elements
                    .get(field)
                    .filter(|_| field < element_count)
                    .and_then(|element| *element)
                    .ok_or(CodegenError {
                        kind: CodegenErrorKind::RuntimeExpressionUnsupported,
                        span: assignment_span,
                    })?;
                recurse(
                    facts,
                    locals,
                    function,
                    resolver,
                    tree,
                    element,
                    field_context,
                    depth + 1,
                    assignment_span,
                )
            }
            ExprKind::Identifier(name) => push_read(
                facts,
                locals,
                function,
                RuntimeReadPlace {
                    name,
                    span: expression.span,
                    projections: RuntimePlaceProjections::single(
                        RuntimePlaceProjection::TupleField(field),
                    ),
                },
                field_context,
                assignment_span,
            ),
            ExprKind::Return { operand }
            | ExprKind::LoopBreak { operand }
            | ExprKind::Ascribe { operand, .. }
            | ExprKind::InlineConst { operand } => recurse_tuple_field(
                facts,
                locals,
                function,
                resolver,
                tree,
                operand,
                field,
                expected,
                depth + 1,
                assignment_span,
            ),
            ExprKind::Sequence { first, then } => {
                recurse(
                    facts,
                    locals,
                    function,
                    resolver,
                    tree,
                    first,
                    RuntimeReadEffectContext::Value,
                    depth + 1,
                    assignment_span,
                )?;
                recurse_tuple_field(
                    facts,
                    locals,
                    function,
                    resolver,
                    tree,
                    then,
                    field,
                    expected,
                    depth + 1,
                    assignment_span,
                )
            }
            _ => recurse_tuple_value(
                facts,
                locals,
                function,
                resolver,
                tree,
                id,
                expected,
                depth + 1,
                assignment_span,
            ),
        }
    }

    facts
        .ensure_expression_program_point()
        .map_err(|kind| CodegenError {
            kind,
            span: expression_span,
        })?;
    facts.observe_expression_path_shape(tree);
    if let Some(expected) = tuple_expected {
        recurse_tuple_value(
            facts,
            locals,
            function,
            resolver,
            tree,
            root,
            expected,
            0,
            expression_span,
        )
    } else {
        recurse(
            facts,
            locals,
            function,
            resolver,
            tree,
            root,
            root_context,
            0,
            expression_span,
        )
    }
}

fn preanalyze_runtime_expression_at_reads<
    'source,
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    facts: &mut RuntimeBodyFacts<'source>,
    locals: &[Option<RuntimeLocal<'source>>],
    function: &Function<'source, MAX_PARAMETERS>,
    resolver: &R,
    tree: &crate::ExpressionTree<'source, MAX_EXPRESSION_NODES>,
    root: crate::ExprId,
    expression_span: Span,
) -> Result<(), CodegenError> {
    preanalyze_runtime_expression_at_reads_with_tuple(
        facts,
        locals,
        function,
        resolver,
        tree,
        root,
        RuntimeReadEffectContext::Value,
        None,
        expression_span,
    )
}

fn preanalyze_runtime_expression_reads<
    'source,
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    facts: &mut RuntimeBodyFacts<'source>,
    locals: &[Option<RuntimeLocal<'source>>],
    function: &Function<'source, MAX_PARAMETERS>,
    resolver: &R,
    tree: &crate::ExpressionTree<'source, MAX_EXPRESSION_NODES>,
    expression_span: Span,
) -> Result<(), CodegenError> {
    preanalyze_runtime_expression_at_reads(
        facts,
        locals,
        function,
        resolver,
        tree,
        tree.root(),
        expression_span,
    )
}

fn preanalyze_runtime_assignment_reads<
    'source,
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    facts: &mut RuntimeBodyFacts<'source>,
    locals: &[Option<RuntimeLocal<'source>>],
    function: &Function<'source, MAX_PARAMETERS>,
    resolver: &R,
    assignment: &crate::Assignment<'source>,
) -> Result<(), CodegenError> {
    let tree = assignment
        .parse_value::<MAX_EXPRESSION_NODES>()
        .map_err(|error| CodegenError {
            kind: CodegenErrorKind::Expression(error.kind),
            span: translate_span(assignment.value_span.start, error.span),
        })?;
    let ty = runtime_expression_type_with_locals(function, resolver, locals, &tree, tree.root(), 0)
        .map_err(|kind| CodegenError {
            kind,
            span: assignment.value_span,
        })?;
    let direct_place = discover_runtime_read_place(&tree, tree.root())
        .map_err(|kind| CodegenError {
            kind,
            span: assignment.value_span,
        })?
        .is_some();
    let assignment_reborrow = if assignment.projection.is_none()
        && assignment.binding_name() != "_"
        && assignment.operator == crate::AssignmentOperator::Assign
        && (direct_place
            || matches!(
                tree.expression(tree.root())
                    .map(|expression| expression.kind),
                Some(ExprKind::If { .. } | ExprKind::LoopBreakIf { .. })
            )) {
        let target =
            resolve_runtime_assignment_place(function, locals, assignment).map_err(|kind| {
                CodegenError {
                    kind,
                    span: assignment.name_span,
                }
            })?;
        match (target.ty, ty) {
            (
                RuntimeExpressionType::Reference {
                    mutable: expected_mutable,
                    ..
                },
                RuntimeExpressionType::Reference {
                    mutable: actual_mutable,
                    ..
                },
            ) if !expected_mutable || actual_mutable => Some(if expected_mutable {
                RuntimeReadEffectContext::MutableBorrow
            } else {
                RuntimeReadEffectContext::SharedBorrow
            }),
            _ => None,
        }
    } else {
        None
    };
    let context = if let Some(context) = assignment_reborrow {
        context
    } else if runtime_type_is_copy(ty) {
        RuntimeReadEffectContext::Value
    } else {
        RuntimeReadEffectContext::Move
    };
    let expression_reference_generation =
        if matches!(
            assignment.projection,
            None | Some(crate::parser::AssignmentProjection::TupleField { .. })
        ) && assignment.operator == crate::AssignmentOperator::Assign
            && matches!(ty, RuntimeExpressionType::Reference { .. })
            && (matches!(
                tree.expression(tree.root())
                    .map(|expression| expression.kind),
                Some(ExprKind::If { .. } | ExprKind::LoopBreakIf { .. })
            ) || runtime_expression_reference_call_origin::<
                R,
                MAX_PARAMETERS,
                MAX_EXPRESSION_NODES,
            >(resolver, &tree, tree.root())
            .is_some())
        {
            resolve_runtime_assignment_place(function, locals, assignment)
                .ok()
                .and_then(|target| match target.base {
                    RuntimePlaceBase::Local { id, .. } => Some(id),
                    RuntimePlaceBase::Parameter { .. } => None,
                })
        } else {
            None
        };
    facts.pending_loan_generation_borrower = expression_reference_generation;
    let result = preanalyze_runtime_expression_at_reads_with_tuple(
        facts,
        locals,
        function,
        resolver,
        &tree,
        tree.root(),
        context,
        matches!(ty, RuntimeExpressionType::Tuple { .. }).then_some(ty),
        assignment.value_span,
    );
    facts.pending_loan_generation_borrower = None;
    facts.current_loan_generation_borrower = None;
    result
}

fn preanalyze_x86_64_inline_local_access(
    facts: &mut RuntimeBodyFacts<'_>,
    local: RuntimeLocal<'_>,
    access: RuntimePlaceAccess,
    span: Span,
    body_start: usize,
) -> Result<(), CodegenError> {
    preanalyze_x86_64_inline_place_access(
        facts,
        RuntimePlaceIdentity::Local(local.id),
        local.ty,
        RuntimePlaceProjections::EMPTY,
        access,
        span,
        body_start,
    )
}

fn preanalyze_x86_64_inline_place_access(
    facts: &mut RuntimeBodyFacts<'_>,
    base: RuntimePlaceIdentity,
    ty: RuntimeExpressionType,
    projections: RuntimePlaceProjections,
    access: RuntimePlaceAccess,
    span: Span,
    body_start: usize,
) -> Result<(), CodegenError> {
    facts
        .push_assignment_access(RuntimePlaceAccessFact {
            base,
            projections,
            ty,
            access,
            span,
        })
        .map_err(|kind| CodegenError {
            kind,
            span: translate_span(body_start, span),
        })?;
    let path = facts.find_move_path(base, projections);
    if projections == RuntimePlaceProjections::EMPTY && path.is_none() {
        return Err(CodegenError {
            kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
            span: translate_span(body_start, span),
        });
    }
    let effect = match access {
        RuntimePlaceAccess::Write => RuntimePlaceEffectKind::Write,
        RuntimePlaceAccess::ReadModifyWrite => RuntimePlaceEffectKind::ReadModifyWrite,
        RuntimePlaceAccess::Read => {
            return Err(CodegenError {
                kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                span: translate_span(body_start, span),
            });
        }
    };
    if let Some(path) = path {
        facts
            .push_place_effect(path, effect, span)
            .map_err(|kind| CodegenError {
                kind,
                span: translate_span(body_start, span),
            })?;
    }
    Ok(())
}

fn preanalyze_x86_64_inline_output_index<
    'source,
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    facts: &mut RuntimeBodyFacts<'source>,
    place: X86_64InlineOutputPlace<'source>,
    locals: &[Option<RuntimeLocal<'source>>],
    function: &Function<'source, MAX_PARAMETERS>,
    resolver: &R,
    span: Span,
) -> Result<(), CodegenError> {
    let index = match place.storage {
        X86_64InlineOutputStorage::LocalDynamicArray { index, .. }
        | X86_64InlineOutputStorage::LocalDynamicReferenceArray { index, .. }
        | X86_64InlineOutputStorage::ParameterDynamicReferenceArray { index, .. }
        | X86_64InlineOutputStorage::LocalDynamicSlice { index, .. }
        | X86_64InlineOutputStorage::ParameterDynamicSlice { index, .. } => index,
        _ => return Ok(()),
    };
    let tree = crate::ExpressionParser::<MAX_EXPRESSION_NODES>::new(index)
        .parse()
        .map_err(|error| CodegenError {
            kind: CodegenErrorKind::Expression(error.kind),
            span,
        })?;
    let ty = runtime_expression_type_with_locals(function, resolver, locals, &tree, tree.root(), 0)
        .map_err(|kind| CodegenError { kind, span })?;
    if !matches!(
        ty,
        RuntimeExpressionType::Integer(None)
            | RuntimeExpressionType::Integer(Some(crate::IntegerType::Usize))
    ) {
        return Err(CodegenError {
            kind: CodegenErrorKind::RuntimeTypeMismatch,
            span,
        });
    }
    preanalyze_runtime_expression_reads(facts, locals, function, resolver, &tree, span)
}

fn preanalyze_runtime_expression_statement_reads<
    'source,
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    facts: &mut RuntimeBodyFacts<'source>,
    locals: &[Option<RuntimeLocal<'source>>],
    function: &Function<'source, MAX_PARAMETERS>,
    resolver: &R,
    statement: &crate::ExpressionStatement<'source>,
    body_start: usize,
) -> Result<(), CodegenError> {
    if statement.expression.is_empty() {
        return Ok(());
    }
    match x86_64_inline_assembly(statement.expression) {
        Ok(Some(_)) if !function.unsafe_function && !statement.unsafe_context => {
            return Err(CodegenError {
                kind: CodegenErrorKind::InlineAssemblyRequiresUnsafe,
                span: translate_span(body_start, statement.span),
            });
        }
        Ok(Some(
            X86_64InlineAssembly::Nop
            | X86_64InlineAssembly::NopCClobber
            | X86_64InlineAssembly::Pause,
        )) => return Ok(()),
        Ok(Some(X86_64InlineAssembly::Int3Noreturn)) if statement.terminal => return Ok(()),
        Ok(Some(X86_64InlineAssembly::Int3Noreturn)) => {
            return Err(CodegenError {
                kind: CodegenErrorKind::InvalidInlineAssembly,
                span: translate_span(body_start, statement.span),
            });
        }
        Ok(Some(X86_64InlineAssembly::HaltLoopNoreturn)) if statement.terminal => return Ok(()),
        Ok(Some(X86_64InlineAssembly::HaltLoopNoreturn)) => {
            return Err(CodegenError {
                kind: CodegenErrorKind::InvalidInlineAssembly,
                span: translate_span(body_start, statement.span),
            });
        }
        Ok(Some(X86_64InlineAssembly::Int80Noreturn { inputs })) if statement.terminal => {
            for input in inputs {
                let tree = crate::ExpressionParser::<MAX_EXPRESSION_NODES>::new(input)
                    .parse()
                    .map_err(|error| CodegenError {
                        kind: CodegenErrorKind::Expression(error.kind),
                        span: translate_span(body_start + statement.span.start, error.span),
                    })?;
                let ty = runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    &tree,
                    tree.root(),
                    0,
                )
                .map_err(|kind| CodegenError {
                    kind,
                    span: translate_span(body_start, statement.span),
                })?;
                if ty != RuntimeExpressionType::Integer(Some(crate::IntegerType::U64)) {
                    return Err(CodegenError {
                        kind: CodegenErrorKind::RuntimeTypeMismatch,
                        span: translate_span(body_start, statement.span),
                    });
                }
                preanalyze_runtime_expression_reads(
                    facts,
                    locals,
                    function,
                    resolver,
                    &tree,
                    statement.span,
                )?;
            }
            return Ok(());
        }
        Ok(Some(X86_64InlineAssembly::Int80Noreturn { .. })) => {
            return Err(CodegenError {
                kind: CodegenErrorKind::InvalidInlineAssembly,
                span: translate_span(body_start, statement.span),
            });
        }
        Ok(Some(X86_64InlineAssembly::Int80Returning { operands })) => {
            for operand in operands {
                let tree = crate::ExpressionParser::<MAX_EXPRESSION_NODES>::new(operand.input)
                    .parse()
                    .map_err(|error| CodegenError {
                        kind: CodegenErrorKind::Expression(error.kind),
                        span: translate_span(body_start + statement.span.start, error.span),
                    })?;
                let ty = runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    &tree,
                    tree.root(),
                    0,
                )
                .map_err(|kind| CodegenError {
                    kind,
                    span: translate_span(body_start, statement.span),
                })?;
                if ty != RuntimeExpressionType::Integer(Some(crate::IntegerType::U64)) {
                    return Err(CodegenError {
                        kind: CodegenErrorKind::RuntimeTypeMismatch,
                        span: translate_span(body_start, statement.span),
                    });
                }
                preanalyze_runtime_expression_reads(
                    facts,
                    locals,
                    function,
                    resolver,
                    &tree,
                    statement.span,
                )?;
            }
            for operand in operands {
                if !operand.inout {
                    continue;
                }
                let output = operand.output.unwrap_or(operand.input);
                if output == "_" {
                    continue;
                }
                let (_, local) = x86_64_inline_output_local(function, locals, output, true)
                    .map_err(|kind| CodegenError {
                        kind,
                        span: translate_span(body_start, statement.span),
                    })?;
                if !local.mutable {
                    let path = facts
                        .find_move_path(
                            RuntimePlaceIdentity::Local(local.id),
                            RuntimePlaceProjections::EMPTY,
                        )
                        .ok_or(CodegenError {
                            kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                            span: translate_span(body_start, statement.span),
                        })?;
                    if facts.initializations[..facts.initialization_count]
                        .iter()
                        .flatten()
                        .any(|initialization| initialization.path == path)
                        || facts.effects[..facts.effect_count]
                            .iter()
                            .flatten()
                            .any(|effect| {
                                effect.path == path
                                    && matches!(effect.kind, RuntimePlaceEffectKind::Write)
                            })
                    {
                        return Err(CodegenError {
                            kind: CodegenErrorKind::ImmutableAssignment,
                            span: translate_span(body_start, statement.span),
                        });
                    }
                }
                preanalyze_x86_64_inline_local_access(
                    facts,
                    local,
                    RuntimePlaceAccess::Write,
                    statement.span,
                    body_start,
                )?;
            }
            return Ok(());
        }
        Ok(Some(X86_64InlineAssembly::CompareRegister { input, .. })) => {
            let tree = crate::ExpressionParser::<MAX_EXPRESSION_NODES>::new(input)
                .parse()
                .map_err(|error| CodegenError {
                    kind: CodegenErrorKind::Expression(error.kind),
                    span: translate_span(body_start + statement.span.start, error.span),
                })?;
            let ty = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                &tree,
                tree.root(),
                0,
            )
            .map_err(|kind| CodegenError {
                kind,
                span: translate_span(body_start, statement.span),
            })?;
            if ty != RuntimeExpressionType::Integer(Some(crate::IntegerType::U64)) {
                return Err(CodegenError {
                    kind: CodegenErrorKind::RuntimeTypeMismatch,
                    span: translate_span(body_start, statement.span),
                });
            }
            return preanalyze_runtime_expression_reads(
                facts,
                locals,
                function,
                resolver,
                &tree,
                statement.span,
            );
        }
        Ok(Some(X86_64InlineAssembly::SetRegister { output, .. })) => {
            if output == "_" {
                return Ok(());
            }
            let place = x86_64_inline_output_place(function, locals, output).map_err(|kind| {
                CodegenError {
                    kind,
                    span: translate_span(body_start, statement.span),
                }
            })?;
            preanalyze_x86_64_inline_output_index::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
                facts,
                place,
                locals,
                function,
                resolver,
                statement.span,
            )?;
            return preanalyze_x86_64_inline_place_access(
                facts,
                place.base,
                place.ty,
                place.projections,
                RuntimePlaceAccess::Write,
                statement.span,
                body_start,
            );
        }
        Ok(Some(X86_64InlineAssembly::IncrementRegister { input, output, .. })) => {
            if let Some(output) = output {
                let tree = crate::ExpressionParser::<MAX_EXPRESSION_NODES>::new(input)
                    .parse()
                    .map_err(|error| CodegenError {
                        kind: CodegenErrorKind::Expression(error.kind),
                        span: translate_span(body_start + statement.span.start, error.span),
                    })?;
                let ty = runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    &tree,
                    tree.root(),
                    0,
                )
                .map_err(|kind| CodegenError {
                    kind,
                    span: translate_span(body_start, statement.span),
                })?;
                if ty != RuntimeExpressionType::Integer(Some(crate::IntegerType::U64)) {
                    return Err(CodegenError {
                        kind: CodegenErrorKind::RuntimeTypeMismatch,
                        span: translate_span(body_start, statement.span),
                    });
                }
                preanalyze_runtime_expression_reads(
                    facts,
                    locals,
                    function,
                    resolver,
                    &tree,
                    statement.span,
                )?;
                let place =
                    x86_64_inline_output_place(function, locals, output).map_err(|kind| {
                        CodegenError {
                            kind,
                            span: translate_span(body_start, statement.span),
                        }
                    })?;
                preanalyze_x86_64_inline_output_index::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
                    facts,
                    place,
                    locals,
                    function,
                    resolver,
                    statement.span,
                )?;
                return preanalyze_x86_64_inline_place_access(
                    facts,
                    place.base,
                    place.ty,
                    place.projections,
                    RuntimePlaceAccess::Write,
                    statement.span,
                    body_start,
                );
            }
            let place = x86_64_inline_output_place(function, locals, input).map_err(|kind| {
                CodegenError {
                    kind,
                    span: translate_span(body_start, statement.span),
                }
            })?;
            preanalyze_x86_64_inline_output_index::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
                facts,
                place,
                locals,
                function,
                resolver,
                statement.span,
            )?;
            return preanalyze_x86_64_inline_place_access(
                facts,
                place.base,
                place.ty,
                place.projections,
                RuntimePlaceAccess::ReadModifyWrite,
                statement.span,
                body_start,
            );
        }
        Ok(Some(X86_64InlineAssembly::AddRaxRcx { left, right })) => {
            let (_, local) =
                x86_64_inline_output_local(function, locals, left, false).map_err(|kind| {
                    CodegenError {
                        kind,
                        span: translate_span(body_start, statement.span),
                    }
                })?;
            let tree = crate::ExpressionParser::<MAX_EXPRESSION_NODES>::new(right)
                .parse()
                .map_err(|error| CodegenError {
                    kind: CodegenErrorKind::Expression(error.kind),
                    span: translate_span(body_start + statement.span.start, error.span),
                })?;
            let ty = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                &tree,
                tree.root(),
                0,
            )
            .map_err(|kind| CodegenError {
                kind,
                span: translate_span(body_start, statement.span),
            })?;
            if ty != RuntimeExpressionType::Integer(Some(crate::IntegerType::U64)) {
                return Err(CodegenError {
                    kind: CodegenErrorKind::RuntimeTypeMismatch,
                    span: translate_span(body_start, statement.span),
                });
            }
            preanalyze_runtime_expression_reads(
                facts,
                locals,
                function,
                resolver,
                &tree,
                statement.span,
            )?;
            return preanalyze_x86_64_inline_local_access(
                facts,
                local,
                RuntimePlaceAccess::ReadModifyWrite,
                statement.span,
                body_start,
            );
        }
        Ok(None) => {}
        Err(kind) => {
            return Err(CodegenError {
                kind,
                span: translate_span(body_start, statement.span),
            });
        }
    }
    let tree = statement
        .parse::<MAX_EXPRESSION_NODES>()
        .map_err(|error| CodegenError {
            kind: CodegenErrorKind::Expression(error.kind),
            span: translate_span(body_start + statement.span.start, error.span),
        })?;
    preanalyze_runtime_expression_reads(facts, locals, function, resolver, &tree, statement.span)
}

#[allow(clippy::too_many_arguments)]
fn preanalyze_runtime_return_array_element_reads<
    'source,
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    facts: &mut RuntimeBodyFacts<'source>,
    locals: &[Option<RuntimeLocal<'source>>],
    function: &Function<'source, MAX_PARAMETERS>,
    resolver: &R,
    tree: &crate::ExpressionTree<'source, MAX_EXPRESSION_NODES>,
    id: crate::ExprId,
    index: usize,
    depth: usize,
    expression_span: Span,
) -> Result<(), CodegenError> {
    if depth == 64 {
        return Err(CodegenError {
            kind: CodegenErrorKind::Lowering(IrErrorKind::NestingLimitExceeded),
            span: expression_span,
        });
    }
    let expression = tree.expression(id).ok_or(CodegenError {
        kind: CodegenErrorKind::RuntimeExpressionUnsupported,
        span: expression_span,
    })?;
    match expression.kind {
        ExprKind::DefaultValue => Ok(()),
        ExprKind::Identifier(name) => push_read(
            facts,
            locals,
            function,
            RuntimeReadPlace {
                name,
                span: expression.span,
                projections: RuntimePlaceProjections::single(RuntimePlaceProjection::Index),
            },
            RuntimeReadEffectContext::Value,
            expression_span,
        ),
        ExprKind::Array {
            elements,
            element_count,
        } => {
            let element = elements
                .get(index)
                .filter(|_| index < element_count)
                .and_then(|element| *element)
                .ok_or(CodegenError {
                    kind: CodegenErrorKind::RuntimeExpressionUnsupported,
                    span: expression_span,
                })?;
            preanalyze_runtime_expression_at_reads(
                facts,
                locals,
                function,
                resolver,
                tree,
                element,
                expression_span,
            )
        }
        ExprKind::ArrayRepeat { element, count } => {
            if index >= count {
                return Err(CodegenError {
                    kind: CodegenErrorKind::RuntimeTypeMismatch,
                    span: expression_span,
                });
            }
            preanalyze_runtime_expression_at_reads(
                facts,
                locals,
                function,
                resolver,
                tree,
                element,
                expression_span,
            )
        }
        ExprKind::IntegerToBytes { base, .. } => preanalyze_runtime_expression_at_reads(
            facts,
            locals,
            function,
            resolver,
            tree,
            base,
            expression_span,
        ),
        ExprKind::If {
            condition,
            then_branch,
            else_branch,
        }
        | ExprKind::LoopBreakIf {
            condition,
            then_branch,
            else_branch,
        } => {
            let parent_conditional = facts.current_conditional_expression;
            let conditional =
                facts
                    .push_conditional_expression(expression.span)
                    .map_err(|kind| CodegenError {
                        kind,
                        span: expression_span,
                    })?;
            let conditional_fact =
                facts.conditional_expressions[conditional.0].ok_or(CodegenError {
                    kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                    span: expression_span,
                })?;
            facts.current_conditional_expression = Some(conditional);
            facts.current_expression_program_point = Some(conditional_fact.condition);
            preanalyze_runtime_expression_at_reads(
                facts,
                locals,
                function,
                resolver,
                tree,
                condition,
                expression_span,
            )?;
            let parent_path = facts.current_ownership_expression_path;
            for (else_branch, branch) in [(false, then_branch), (true, else_branch)] {
                facts.current_conditional_expression = Some(conditional);
                facts.current_expression_program_point = Some(if else_branch {
                    conditional_fact.else_branch
                } else {
                    conditional_fact.then_branch
                });
                facts.current_ownership_expression_path =
                    parent_path
                        .branch(else_branch)
                        .map_err(|kind| CodegenError {
                            kind,
                            span: expression_span,
                        })?;
                let result = preanalyze_runtime_return_array_element_reads(
                    facts,
                    locals,
                    function,
                    resolver,
                    tree,
                    branch,
                    index,
                    depth + 1,
                    expression_span,
                );
                let exit = facts.current_expression_program_point.ok_or(CodegenError {
                    kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                    span: expression_span,
                })?;
                facts
                    .set_conditional_expression_exit(conditional, else_branch, exit)
                    .map_err(|kind| CodegenError {
                        kind,
                        span: expression_span,
                    })?;
                facts.current_ownership_expression_path = parent_path;
                result?;
            }
            facts.current_conditional_expression = parent_conditional;
            facts.current_expression_program_point = Some(conditional_fact.join);
            Ok(())
        }
        ExprKind::InlineConst { operand }
        | ExprKind::LoopBreak { operand }
        | ExprKind::Return { operand } => preanalyze_runtime_return_array_element_reads(
            facts,
            locals,
            function,
            resolver,
            tree,
            operand,
            index,
            depth + 1,
            expression_span,
        ),
        ExprKind::Sequence { first, then } => {
            preanalyze_runtime_expression_at_reads(
                facts,
                locals,
                function,
                resolver,
                tree,
                first,
                expression_span,
            )?;
            preanalyze_runtime_return_array_element_reads(
                facts,
                locals,
                function,
                resolver,
                tree,
                then,
                index,
                depth + 1,
                expression_span,
            )
        }
        _ => Err(CodegenError {
            kind: CodegenErrorKind::RuntimeExpressionUnsupported,
            span: expression_span,
        }),
    }
}

fn runtime_return_array_preanalysis_supported<
    'source,
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    function: &Function<'source, MAX_PARAMETERS>,
    resolver: &R,
    locals: &[Option<RuntimeLocal<'source>>],
    tree: &crate::ExpressionTree<'source, MAX_EXPRESSION_NODES>,
    id: crate::ExprId,
    count: usize,
    depth: usize,
) -> Result<bool, CodegenErrorKind> {
    if depth == 64 {
        return Ok(false);
    }
    match tree.expression(id).map(|expression| expression.kind) {
        Some(ExprKind::Call { .. }) => {
            let ty = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                id,
                depth + 1,
            )?;
            Ok(
                matches!(ty, RuntimeExpressionType::Array { count: actual, .. } if actual == count)
                    && runtime_call_arguments_preanalysis_supported(
                        function,
                        resolver,
                        locals,
                        tree,
                        id,
                        depth + 1,
                    )?,
            )
        }
        Some(ExprKind::ArrayRepeat { count: actual, .. }) => Ok(actual == count),
        Some(ExprKind::IntegerToBytes { .. }) => {
            let ty = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                id,
                depth + 1,
            )?;
            Ok(matches!(ty, RuntimeExpressionType::Array { count: actual, .. } if actual == count))
        }
        Some(
            ExprKind::InlineConst { operand }
            | ExprKind::LoopBreak { operand }
            | ExprKind::Return { operand },
        ) => runtime_return_array_preanalysis_supported(
            function,
            resolver,
            locals,
            tree,
            operand,
            count,
            depth + 1,
        ),
        Some(ExprKind::Sequence { then, .. }) => runtime_return_array_preanalysis_supported(
            function,
            resolver,
            locals,
            tree,
            then,
            count,
            depth + 1,
        ),
        Some(
            ExprKind::If {
                then_branch,
                else_branch,
                ..
            }
            | ExprKind::LoopBreakIf {
                then_branch,
                else_branch,
                ..
            },
        ) => Ok(runtime_return_array_preanalysis_supported(
            function,
            resolver,
            locals,
            tree,
            then_branch,
            count,
            depth + 1,
        )? && runtime_return_array_preanalysis_supported(
            function,
            resolver,
            locals,
            tree,
            else_branch,
            count,
            depth + 1,
        )?),
        Some(_) => Ok((0..count)
            .all(|index| runtime_array_element_preanalysis_supported(tree, id, index, depth + 1))),
        None => Ok(false),
    }
}

#[allow(clippy::too_many_arguments)]
fn preanalyze_runtime_return_array_reads<
    'source,
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    facts: &mut RuntimeBodyFacts<'source>,
    locals: &[Option<RuntimeLocal<'source>>],
    function: &Function<'source, MAX_PARAMETERS>,
    resolver: &R,
    tree: &crate::ExpressionTree<'source, MAX_EXPRESSION_NODES>,
    id: crate::ExprId,
    count: usize,
    depth: usize,
    expression_span: Span,
) -> Result<(), CodegenError> {
    if depth == 64 {
        return Err(CodegenError {
            kind: CodegenErrorKind::Lowering(IrErrorKind::NestingLimitExceeded),
            span: expression_span,
        });
    }
    match tree.expression(id).map(|expression| expression.kind) {
        Some(ExprKind::Call { .. } | ExprKind::ArrayRepeat { .. }) => {
            preanalyze_runtime_expression_at_reads(
                facts,
                locals,
                function,
                resolver,
                tree,
                id,
                expression_span,
            )
        }
        Some(ExprKind::IntegerToBytes { base, .. }) => preanalyze_runtime_expression_at_reads(
            facts,
            locals,
            function,
            resolver,
            tree,
            base,
            expression_span,
        ),
        Some(
            ExprKind::InlineConst { operand }
            | ExprKind::LoopBreak { operand }
            | ExprKind::Return { operand },
        ) => preanalyze_runtime_return_array_reads(
            facts,
            locals,
            function,
            resolver,
            tree,
            operand,
            count,
            depth + 1,
            expression_span,
        ),
        Some(ExprKind::Sequence { first, then }) => {
            preanalyze_runtime_expression_at_reads(
                facts,
                locals,
                function,
                resolver,
                tree,
                first,
                expression_span,
            )?;
            preanalyze_runtime_return_array_reads(
                facts,
                locals,
                function,
                resolver,
                tree,
                then,
                count,
                depth + 1,
                expression_span,
            )
        }
        Some(
            ExprKind::If {
                condition,
                then_branch,
                else_branch,
            }
            | ExprKind::LoopBreakIf {
                condition,
                then_branch,
                else_branch,
            },
        ) => {
            let parent_conditional = facts.current_conditional_expression;
            let conditional_span = tree
                .expression(id)
                .ok_or(CodegenError {
                    kind: CodegenErrorKind::RuntimeExpressionUnsupported,
                    span: expression_span,
                })?
                .span;
            let conditional = facts
                .push_conditional_expression(conditional_span)
                .map_err(|kind| CodegenError {
                    kind,
                    span: expression_span,
                })?;
            let conditional_fact =
                facts.conditional_expressions[conditional.0].ok_or(CodegenError {
                    kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                    span: expression_span,
                })?;
            facts.current_conditional_expression = Some(conditional);
            facts.current_expression_program_point = Some(conditional_fact.condition);
            preanalyze_runtime_expression_at_reads(
                facts,
                locals,
                function,
                resolver,
                tree,
                condition,
                expression_span,
            )?;
            let parent_path = facts.current_ownership_expression_path;
            for (else_branch, branch) in [(false, then_branch), (true, else_branch)] {
                facts.current_conditional_expression = Some(conditional);
                facts.current_expression_program_point = Some(if else_branch {
                    conditional_fact.else_branch
                } else {
                    conditional_fact.then_branch
                });
                facts.current_ownership_expression_path =
                    parent_path
                        .branch(else_branch)
                        .map_err(|kind| CodegenError {
                            kind,
                            span: expression_span,
                        })?;
                let result = preanalyze_runtime_return_array_reads(
                    facts,
                    locals,
                    function,
                    resolver,
                    tree,
                    branch,
                    count,
                    depth + 1,
                    expression_span,
                );
                let exit = facts.current_expression_program_point.ok_or(CodegenError {
                    kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                    span: expression_span,
                })?;
                facts
                    .set_conditional_expression_exit(conditional, else_branch, exit)
                    .map_err(|kind| CodegenError {
                        kind,
                        span: expression_span,
                    })?;
                facts.current_ownership_expression_path = parent_path;
                result?;
            }
            facts.current_conditional_expression = parent_conditional;
            facts.current_expression_program_point = Some(conditional_fact.join);
            Ok(())
        }
        Some(_) => {
            for index in 0..count {
                preanalyze_runtime_return_array_element_reads(
                    facts,
                    locals,
                    function,
                    resolver,
                    tree,
                    id,
                    index,
                    depth + 1,
                    expression_span,
                )?;
            }
            Ok(())
        }
        None => Err(CodegenError {
            kind: CodegenErrorKind::RuntimeExpressionUnsupported,
            span: expression_span,
        }),
    }
}

#[allow(clippy::too_many_arguments)]
fn preanalyze_runtime_source_expression_reads_with_expected_return<
    'source,
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    facts: &mut RuntimeBodyFacts<'source>,
    locals: &[Option<RuntimeLocal<'source>>],
    function: &Function<'source, MAX_PARAMETERS>,
    resolver: &R,
    expression: &'source str,
    expression_span: Span,
    body_start: usize,
    expected_return: bool,
) -> Result<(), CodegenError> {
    let tree = crate::ExpressionParser::<MAX_EXPRESSION_NODES>::new(expression)
        .parse()
        .map_err(|error| CodegenError {
            kind: CodegenErrorKind::Expression(error.kind),
            span: translate_span(body_start + expression_span.start, error.span),
        })?;
    let ty = runtime_expression_type_with_locals(function, resolver, locals, &tree, tree.root(), 0)
        .map_err(|kind| CodegenError {
            kind,
            span: translate_span(body_start, expression_span),
        })?;
    if let RuntimeExpressionType::Array { count, .. } = ty {
        let supported = runtime_return_array_preanalysis_supported(
            function,
            resolver,
            locals,
            &tree,
            tree.root(),
            count,
            0,
        )
        .map_err(|kind| CodegenError {
            kind,
            span: translate_span(body_start, expression_span),
        })?;
        if supported {
            preanalyze_runtime_return_array_reads(
                facts,
                locals,
                function,
                resolver,
                &tree,
                tree.root(),
                count,
                0,
                expression_span,
            )?;
        }
        return Ok(());
    }
    if let expected @ RuntimeExpressionType::Tuple { .. } = ty {
        let supported = runtime_tuple_value_preanalysis_supported(
            function,
            resolver,
            locals,
            &tree,
            tree.root(),
            expected,
            0,
        )
        .map_err(|kind| CodegenError {
            kind,
            span: translate_span(body_start, expression_span),
        })?;
        if supported {
            preanalyze_runtime_expression_at_reads_with_tuple(
                facts,
                locals,
                function,
                resolver,
                &tree,
                tree.root(),
                RuntimeReadEffectContext::Value,
                Some(expected),
                expression_span,
            )?;
        }
        return Ok(());
    }
    let fat_reference_supported = runtime_type_is_fat_reference(ty)
        && (runtime_fat_reference_return_preanalysis_supported(&tree, tree.root(), 0)
            || runtime_fat_reference_call_preanalysis_supported(
                function,
                resolver,
                locals,
                &tree,
                tree.root(),
                0,
            )
            .map_err(|kind| CodegenError {
                kind,
                span: translate_span(body_start, expression_span),
            })?);
    if runtime_type_stack_slots(ty) != 1 && !fat_reference_supported {
        return Ok(());
    }
    let direct_place = discover_runtime_read_place(&tree, tree.root())
        .map_err(|kind| CodegenError {
            kind,
            span: translate_span(body_start, expression_span),
        })?
        .is_some();
    let expected_reborrow = if expected_return
        && (direct_place
            || matches!(
                tree.expression(tree.root())
                    .map(|expression| expression.kind),
                Some(ExprKind::If { .. } | ExprKind::LoopBreakIf { .. })
            )) {
        let expected = function
            .return_type
            .and_then(|return_type| runtime_type_from_text(return_type.text));
        match (expected, ty) {
            (
                Some(RuntimeExpressionType::Reference {
                    mutable: expected_mutable,
                    ..
                }),
                RuntimeExpressionType::Reference {
                    mutable: actual_mutable,
                    ..
                },
            ) if !expected_mutable || actual_mutable => Some(if expected_mutable {
                RuntimeReadEffectContext::MutableBorrow
            } else {
                RuntimeReadEffectContext::SharedBorrow
            }),
            _ => None,
        }
    } else {
        None
    };
    let context = if let Some(context) = expected_reborrow {
        context
    } else if runtime_type_is_copy(ty) {
        RuntimeReadEffectContext::Value
    } else {
        RuntimeReadEffectContext::Move
    };
    preanalyze_runtime_expression_at_reads_with_tuple(
        facts,
        locals,
        function,
        resolver,
        &tree,
        tree.root(),
        context,
        None,
        expression_span,
    )
}

fn preanalyze_runtime_source_expression_reads<
    'source,
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    facts: &mut RuntimeBodyFacts<'source>,
    locals: &[Option<RuntimeLocal<'source>>],
    function: &Function<'source, MAX_PARAMETERS>,
    resolver: &R,
    expression: &'source str,
    expression_span: Span,
    body_start: usize,
) -> Result<(), CodegenError> {
    preanalyze_runtime_source_expression_reads_with_expected_return::<
        R,
        MAX_PARAMETERS,
        MAX_EXPRESSION_NODES,
    >(
        facts,
        locals,
        function,
        resolver,
        expression,
        expression_span,
        body_start,
        false,
    )
}

fn preanalyze_runtime_return_expression_reads<
    'source,
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    facts: &mut RuntimeBodyFacts<'source>,
    locals: &[Option<RuntimeLocal<'source>>],
    function: &Function<'source, MAX_PARAMETERS>,
    resolver: &R,
    expression: &'source str,
    expression_span: Span,
    body_start: usize,
) -> Result<(), CodegenError> {
    preanalyze_runtime_source_expression_reads_with_expected_return::<
        R,
        MAX_PARAMETERS,
        MAX_EXPRESSION_NODES,
    >(
        facts,
        locals,
        function,
        resolver,
        expression,
        expression_span,
        body_start,
        true,
    )
}

fn preanalyze_runtime_assignment_access<
    'source,
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    facts: &mut RuntimeBodyFacts<'source>,
    locals: &[Option<RuntimeLocal<'source>>],
    function: &Function<'source, MAX_PARAMETERS>,
    resolver: &R,
    assignment: &crate::Assignment<'source>,
) -> Result<(), CodegenError> {
    fn mutually_exclusive_conditional_assignment_arms(
        left: RuntimeOwnershipEventLocation,
        right: RuntimeOwnershipEventLocation,
    ) -> bool {
        matches!(
            (left, right),
            (
                RuntimeOwnershipEventLocation::ConditionalAssignmentAction {
                    statement_index: left_statement,
                    branch_index: left_branch,
                    ..
                },
                RuntimeOwnershipEventLocation::ConditionalAssignmentAction {
                    statement_index: right_statement,
                    branch_index: right_branch,
                    ..
                }
            ) if left_statement == right_statement && left_branch != right_branch
        )
    }

    preanalyze_runtime_assignment_reads::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
        facts, locals, function, resolver, assignment,
    )?;
    if assignment.binding_name() == "_" {
        return Ok(());
    }
    let place = resolve_runtime_assignment_place(function, locals, assignment).map_err(|kind| {
        CodegenError {
            kind,
            span: assignment.name_span,
        }
    })?;
    let base = match place.base {
        RuntimePlaceBase::Local { id, .. } => RuntimePlaceIdentity::Local(id),
        RuntimePlaceBase::Parameter { index } => RuntimePlaceIdentity::Parameter(index),
    };
    let base_ty = facts.move_paths[..facts.move_path_count]
        .iter()
        .flatten()
        .find(|path| path.base == base && path.projections == RuntimePlaceProjections::EMPTY)
        .map(|path| path.ty)
        .ok_or(CodegenError {
            kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
            span: assignment.name_span,
        })?;
    let projections = RuntimePlaceProjections::from_assignment_with_array_identity::<
        R,
        MAX_EXPRESSION_NODES,
    >(assignment, base_ty, resolver)
    .map_err(|kind| CodegenError {
        kind,
        span: assignment.name_span,
    })?;
    if let RuntimePlaceBase::Local { id, .. } = place.base
        && let Some(local) = locals.iter().flatten().find(|local| local.id == id)
        && !local.mutable
        && !local.initialized
    {
        let path = facts
            .find_move_path(base, RuntimePlaceProjections::EMPTY)
            .ok_or(CodegenError {
                kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                span: assignment.name_span,
            })?;
        if projections != RuntimePlaceProjections::EMPTY
            || assignment.operator != crate::AssignmentOperator::Assign
            || facts.initializations[..facts.initialization_count]
                .iter()
                .flatten()
                .any(|initialization| initialization.path == path)
            || facts.effects[..facts.effect_count]
                .iter()
                .flatten()
                .any(|effect| {
                    effect.path == path
                        && matches!(effect.kind, RuntimePlaceEffectKind::Write)
                        && !mutually_exclusive_conditional_assignment_arms(
                            effect.location,
                            facts.current_ownership_event_location,
                        )
                })
        {
            return Err(CodegenError {
                kind: CodegenErrorKind::ImmutableAssignment,
                span: assignment.name_span,
            });
        }
    }
    facts
        .push_assignment_access(RuntimePlaceAccessFact {
            base,
            projections,
            ty: place.ty,
            access: place.access,
            span: assignment.name_span,
        })
        .map_err(|kind| CodegenError {
            kind,
            span: assignment.name_span,
        })?;
    if let Some(path) = facts.find_move_path(base, projections) {
        let kind = match place.access {
            RuntimePlaceAccess::Write => RuntimePlaceEffectKind::Write,
            RuntimePlaceAccess::ReadModifyWrite => RuntimePlaceEffectKind::ReadModifyWrite,
            RuntimePlaceAccess::Read => {
                return Err(CodegenError {
                    kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                    span: assignment.name_span,
                });
            }
        };
        facts
            .push_place_effect(path, kind, assignment.name_span)
            .map_err(|kind| CodegenError {
                kind,
                span: assignment.name_span,
            })?;
    } else if projections.count != 0
        && let Some(path) = facts.find_move_path(base, RuntimePlaceProjections::EMPTY)
        && let Some(root) = facts.move_paths.get(path.0).and_then(|path| *path)
        && matches!(root.ty, RuntimeExpressionType::Reference { .. })
        && match root.base {
            RuntimePlaceIdentity::Local(borrower) => facts
                .direct_loan_for_borrower_before(
                    borrower,
                    RuntimeOwnershipEventId(facts.ownership_event_count),
                )
                .is_some(),
            RuntimePlaceIdentity::Parameter(_) => true,
        }
    {
        facts
            .push_place_effect(
                path,
                RuntimePlaceEffectKind::LoanMutation,
                assignment.name_span,
            )
            .map_err(|kind| CodegenError {
                kind,
                span: assignment.name_span,
            })?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn preanalyze_runtime_conditional_actions<
    'source,
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    function: &Function<'source, MAX_PARAMETERS>,
    resolver: &R,
    actions: &[Option<crate::ConditionalAssignmentAction<'source>>],
    statement_index: usize,
    branch_index: Option<usize>,
    operand_type: &str,
    body_start: usize,
    facts: &mut RuntimeBodyFacts<'source>,
    outer_locals: &[Option<RuntimeLocal<'source>>; MAX_PARAMETERS],
    outer_local_count: usize,
) -> Result<(), CodegenError> {
    let mut locals = *outer_locals;
    let mut local_count = outer_local_count;
    for (action_index, action) in actions.iter().flatten().enumerate() {
        facts.current_ownership_event_location =
            RuntimeOwnershipEventLocation::ConditionalAssignmentAction {
                statement_index,
                branch_index,
                action_index,
            };
        match *action {
            crate::ConditionalAssignmentAction::Local(local) => {
                preanalyze_runtime_local_binding::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
                    function,
                    resolver,
                    local,
                    operand_type,
                    body_start,
                    facts,
                    &mut locals,
                    &mut local_count,
                )?;
            }
            crate::ConditionalAssignmentAction::Assignment(assignment) => {
                preanalyze_runtime_assignment_access::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
                    facts,
                    &locals[..local_count],
                    function,
                    resolver,
                    &assignment,
                )?;
            }
            crate::ConditionalAssignmentAction::Expression(statement) => {
                preanalyze_runtime_expression_statement_reads::<
                    R,
                    MAX_PARAMETERS,
                    MAX_EXPRESSION_NODES,
                >(
                    facts,
                    &locals[..local_count],
                    function,
                    resolver,
                    &statement,
                    body_start,
                )?;
            }
            crate::ConditionalAssignmentAction::Return(value) => {
                facts.current_ownership_event_location =
                    RuntimeOwnershipEventLocation::ConditionalAssignmentReturnValue {
                        statement_index,
                        branch_index,
                        action_index,
                    };
                preanalyze_runtime_return_expression_reads::<
                    R,
                    MAX_PARAMETERS,
                    MAX_EXPRESSION_NODES,
                >(
                    facts,
                    &locals[..local_count],
                    function,
                    resolver,
                    value.value,
                    value.value_span,
                    body_start,
                )?;
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn preanalyze_runtime_loop_actions<
    'source,
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    function: &Function<'source, MAX_PARAMETERS>,
    resolver: &R,
    actions: &[Option<crate::ConditionalLoopAction<'source>>],
    operand_type: &str,
    body_start: usize,
    facts: &mut RuntimeBodyFacts<'source>,
    outer_locals: &[Option<RuntimeLocal<'source>>; MAX_PARAMETERS],
    outer_local_count: usize,
    statement_index: usize,
    operation_index: usize,
    arm_index: usize,
) -> Result<([Option<RuntimeLocal<'source>>; MAX_PARAMETERS], usize), CodegenError> {
    let mut locals = *outer_locals;
    let mut local_count = outer_local_count;
    for (action_index, action) in actions.iter().flatten().enumerate() {
        facts.current_ownership_event_location =
            RuntimeOwnershipEventLocation::LoopConditionalAction {
                statement_index,
                operation_index,
                arm_index,
                action_index,
            };
        match *action {
            crate::ConditionalLoopAction::Local(local) => {
                preanalyze_runtime_local_binding::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
                    function,
                    resolver,
                    local,
                    operand_type,
                    body_start,
                    facts,
                    &mut locals,
                    &mut local_count,
                )?;
            }
            crate::ConditionalLoopAction::Assignment(assignment) => {
                preanalyze_runtime_assignment_access::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
                    facts,
                    &locals[..local_count],
                    function,
                    resolver,
                    &assignment,
                )?;
            }
            crate::ConditionalLoopAction::Expression(statement) => {
                preanalyze_runtime_expression_statement_reads::<
                    R,
                    MAX_PARAMETERS,
                    MAX_EXPRESSION_NODES,
                >(
                    facts,
                    &locals[..local_count],
                    function,
                    resolver,
                    &statement,
                    body_start,
                )?;
            }
        }
    }
    Ok((locals, local_count))
}

#[allow(clippy::too_many_arguments)]
fn preanalyze_runtime_nested_loop_block<
    'source,
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    function: &Function<'source, MAX_PARAMETERS>,
    resolver: &R,
    block: &crate::NestedLoopBlock<'source>,
    operand_type: &str,
    body_start: usize,
    facts: &mut RuntimeBodyFacts<'source>,
    outer_locals: &[Option<RuntimeLocal<'source>>; MAX_PARAMETERS],
    outer_local_count: usize,
    statement_index: usize,
    operation_index: usize,
) -> Result<(), CodegenError> {
    let mut locals = *outer_locals;
    let mut local_count = outer_local_count;
    if let Some(condition) = block.entry_condition {
        facts.current_ownership_event_location = RuntimeOwnershipEventLocation::NestedLoopHeader {
            statement_index,
            operation_index,
        };
        preanalyze_runtime_source_expression_reads::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
            facts,
            &locals[..local_count],
            function,
            resolver,
            condition.condition,
            condition.condition_span,
            body_start,
        )?;
    }
    let control_count = block
        .conditional_blocks()
        .len()
        .checked_add(block.conditional_returns().len())
        .and_then(|count| count.checked_add(block.conditional_continues().len()))
        .and_then(|count| count.checked_add(block.conditional_breaks().len()))
        .and_then(|count| count.checked_add(block.unconditional_controls().len()))
        .ok_or(CodegenError {
            kind: CodegenErrorKind::OutputTooSmall,
            span: function.name_span,
        })?;
    for action_index in 0..=block.action_count() {
        for control_order in 0..control_count {
            for (branch_index, ((branch, stored_action_index), stored_order)) in block
                .conditional_blocks()
                .iter()
                .zip(block.conditional_block_action_indices())
                .zip(block.conditional_block_control_orders())
                .enumerate()
            {
                if action_index != *stored_action_index || control_order != *stored_order {
                    continue;
                }
                let branch = branch.ok_or(CodegenError {
                    kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                    span: function.name_span,
                })?;
                facts.current_ownership_event_location =
                    RuntimeOwnershipEventLocation::NestedLoopBranchCondition {
                        statement_index,
                        operation_index,
                        branch_index,
                    };
                preanalyze_runtime_source_expression_reads::<
                    R,
                    MAX_PARAMETERS,
                    MAX_EXPRESSION_NODES,
                >(
                    facts,
                    &locals[..local_count],
                    function,
                    resolver,
                    branch.condition,
                    branch.condition_span,
                    body_start,
                )?;
                let mut branch_locals = locals;
                let mut branch_local_count = local_count;
                for (branch_action_index, branch_action) in
                    branch.actions().iter().copied().enumerate()
                {
                    let branch_action = branch_action.ok_or(CodegenError {
                        kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                        span: function.name_span,
                    })?;
                    facts.current_ownership_event_location =
                        RuntimeOwnershipEventLocation::NestedLoopBranchAction {
                            statement_index,
                            operation_index,
                            branch_index,
                            action_index: branch_action_index,
                        };
                    match branch_action {
                        crate::ConditionalLoopAction::Local(local) => {
                            preanalyze_runtime_local_binding::<
                                R,
                                MAX_PARAMETERS,
                                MAX_EXPRESSION_NODES,
                            >(
                                function,
                                resolver,
                                local,
                                operand_type,
                                body_start,
                                facts,
                                &mut branch_locals,
                                &mut branch_local_count,
                            )?;
                        }
                        crate::ConditionalLoopAction::Assignment(assignment) => {
                            preanalyze_runtime_assignment_access::<
                                R,
                                MAX_PARAMETERS,
                                MAX_EXPRESSION_NODES,
                            >(
                                facts,
                                &branch_locals[..branch_local_count],
                                function,
                                resolver,
                                &assignment,
                            )?;
                        }
                        crate::ConditionalLoopAction::Expression(statement) => {
                            preanalyze_runtime_expression_statement_reads::<
                                R,
                                MAX_PARAMETERS,
                                MAX_EXPRESSION_NODES,
                            >(
                                facts,
                                &branch_locals[..branch_local_count],
                                function,
                                resolver,
                                &statement,
                                body_start,
                            )?;
                        }
                    }
                }
                if let crate::NestedLoopUnconditionalControl::Return(value) = branch.terminal {
                    facts.current_ownership_event_location =
                        RuntimeOwnershipEventLocation::NestedLoopBranchValue {
                            statement_index,
                            operation_index,
                            branch_index,
                        };
                    preanalyze_runtime_return_expression_reads::<
                        R,
                        MAX_PARAMETERS,
                        MAX_EXPRESSION_NODES,
                    >(
                        facts,
                        &branch_locals[..branch_local_count],
                        function,
                        resolver,
                        value.value,
                        value.value_span,
                        body_start,
                    )?;
                }
                for (alternative_index, else_arm) in branch.else_arms().iter().copied().enumerate()
                {
                    let else_arm = else_arm.ok_or(CodegenError {
                        kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                        span: function.name_span,
                    })?;
                    if let Some(condition) = else_arm.condition() {
                        facts.current_ownership_event_location =
                            RuntimeOwnershipEventLocation::NestedLoopBranchElseCondition {
                                statement_index,
                                operation_index,
                                branch_index,
                                alternative_index,
                            };
                        preanalyze_runtime_source_expression_reads::<
                            R,
                            MAX_PARAMETERS,
                            MAX_EXPRESSION_NODES,
                        >(
                            facts,
                            &locals[..local_count],
                            function,
                            resolver,
                            condition,
                            else_arm.condition_span(),
                            body_start,
                        )?;
                    }
                    let mut else_locals = locals;
                    let mut else_local_count = local_count;
                    for (else_action_index, action) in
                        else_arm.actions().iter().copied().enumerate()
                    {
                        let action = action.ok_or(CodegenError {
                            kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                            span: function.name_span,
                        })?;
                        facts.current_ownership_event_location =
                            RuntimeOwnershipEventLocation::NestedLoopBranchElseAction {
                                statement_index,
                                operation_index,
                                branch_index,
                                alternative_index,
                                action_index: else_action_index,
                            };
                        match action {
                            crate::ConditionalLoopAction::Local(local) => {
                                preanalyze_runtime_local_binding::<
                                    R,
                                    MAX_PARAMETERS,
                                    MAX_EXPRESSION_NODES,
                                >(
                                    function,
                                    resolver,
                                    local,
                                    operand_type,
                                    body_start,
                                    facts,
                                    &mut else_locals,
                                    &mut else_local_count,
                                )?;
                            }
                            crate::ConditionalLoopAction::Assignment(assignment) => {
                                preanalyze_runtime_assignment_access::<
                                    R,
                                    MAX_PARAMETERS,
                                    MAX_EXPRESSION_NODES,
                                >(
                                    facts,
                                    &else_locals[..else_local_count],
                                    function,
                                    resolver,
                                    &assignment,
                                )?;
                            }
                            crate::ConditionalLoopAction::Expression(statement) => {
                                preanalyze_runtime_expression_statement_reads::<
                                    R,
                                    MAX_PARAMETERS,
                                    MAX_EXPRESSION_NODES,
                                >(
                                    facts,
                                    &else_locals[..else_local_count],
                                    function,
                                    resolver,
                                    &statement,
                                    body_start,
                                )?;
                            }
                        }
                    }
                    if let crate::NestedLoopUnconditionalControl::Return(value) = else_arm.terminal
                    {
                        facts.current_ownership_event_location =
                            RuntimeOwnershipEventLocation::NestedLoopBranchElseValue {
                                statement_index,
                                operation_index,
                                branch_index,
                                alternative_index,
                            };
                        preanalyze_runtime_return_expression_reads::<
                            R,
                            MAX_PARAMETERS,
                            MAX_EXPRESSION_NODES,
                        >(
                            facts,
                            &else_locals[..else_local_count],
                            function,
                            resolver,
                            value.value,
                            value.value_span,
                            body_start,
                        )?;
                    }
                }
            }
            for ((control, stored_action_index), stored_order) in block
                .unconditional_controls()
                .iter()
                .flatten()
                .zip(block.unconditional_control_action_indices())
                .zip(block.unconditional_control_orders())
            {
                if action_index != *stored_action_index || control_order != *stored_order {
                    continue;
                }
                if let crate::NestedLoopUnconditionalControl::Return(value) = control {
                    facts.current_ownership_event_location =
                        RuntimeOwnershipEventLocation::NestedLoopControlValue {
                            statement_index,
                            operation_index,
                            action_index,
                            control_order,
                        };
                    preanalyze_runtime_return_expression_reads::<
                        R,
                        MAX_PARAMETERS,
                        MAX_EXPRESSION_NODES,
                    >(
                        facts,
                        &locals[..local_count],
                        function,
                        resolver,
                        value.value,
                        value.value_span,
                        body_start,
                    )?;
                }
            }
            for ((condition, stored_action_index), stored_order) in block
                .conditional_breaks()
                .iter()
                .flatten()
                .zip(block.conditional_break_action_indices())
                .zip(block.conditional_break_control_orders())
            {
                if action_index == *stored_action_index && control_order == *stored_order {
                    facts.current_ownership_event_location =
                        RuntimeOwnershipEventLocation::NestedLoopControlCondition {
                            statement_index,
                            operation_index,
                            action_index,
                            control_order,
                        };
                    preanalyze_runtime_source_expression_reads::<
                        R,
                        MAX_PARAMETERS,
                        MAX_EXPRESSION_NODES,
                    >(
                        facts,
                        &locals[..local_count],
                        function,
                        resolver,
                        condition.condition,
                        condition.condition_span,
                        body_start,
                    )?;
                }
            }
            for ((conditional, stored_action_index), stored_order) in block
                .conditional_returns()
                .iter()
                .flatten()
                .zip(block.conditional_return_action_indices())
                .zip(block.conditional_return_control_orders())
            {
                if action_index != *stored_action_index || control_order != *stored_order {
                    continue;
                }
                facts.current_ownership_event_location =
                    RuntimeOwnershipEventLocation::NestedLoopControlCondition {
                        statement_index,
                        operation_index,
                        action_index,
                        control_order,
                    };
                preanalyze_runtime_return_expression_reads::<
                    R,
                    MAX_PARAMETERS,
                    MAX_EXPRESSION_NODES,
                >(
                    facts,
                    &locals[..local_count],
                    function,
                    resolver,
                    conditional.condition,
                    conditional.condition_span,
                    body_start,
                )?;
                facts.current_ownership_event_location =
                    RuntimeOwnershipEventLocation::NestedLoopControlValue {
                        statement_index,
                        operation_index,
                        action_index,
                        control_order,
                    };
                preanalyze_runtime_source_expression_reads::<
                    R,
                    MAX_PARAMETERS,
                    MAX_EXPRESSION_NODES,
                >(
                    facts,
                    &locals[..local_count],
                    function,
                    resolver,
                    conditional.value,
                    conditional.value_span,
                    body_start,
                )?;
            }
            for ((condition, stored_action_index), stored_order) in block
                .conditional_continues()
                .iter()
                .flatten()
                .zip(block.conditional_continue_action_indices())
                .zip(block.conditional_continue_control_orders())
            {
                if action_index == *stored_action_index && control_order == *stored_order {
                    facts.current_ownership_event_location =
                        RuntimeOwnershipEventLocation::NestedLoopControlCondition {
                            statement_index,
                            operation_index,
                            action_index,
                            control_order,
                        };
                    preanalyze_runtime_source_expression_reads::<
                        R,
                        MAX_PARAMETERS,
                        MAX_EXPRESSION_NODES,
                    >(
                        facts,
                        &locals[..local_count],
                        function,
                        resolver,
                        condition.condition,
                        condition.condition_span,
                        body_start,
                    )?;
                }
            }
        }
        if action_index == block.action_count() {
            break;
        }
        let action = block.actions()[action_index].ok_or(CodegenError {
            kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
            span: function.name_span,
        })?;
        facts.current_ownership_event_location = RuntimeOwnershipEventLocation::NestedLoopAction {
            statement_index,
            operation_index,
            action_index,
        };
        match action {
            crate::ConditionalLoopAction::Local(local) => {
                preanalyze_runtime_local_binding::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
                    function,
                    resolver,
                    local,
                    operand_type,
                    body_start,
                    facts,
                    &mut locals,
                    &mut local_count,
                )?;
            }
            crate::ConditionalLoopAction::Assignment(assignment) => {
                preanalyze_runtime_assignment_access::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
                    facts,
                    &locals[..local_count],
                    function,
                    resolver,
                    &assignment,
                )?;
            }
            crate::ConditionalLoopAction::Expression(statement) => {
                preanalyze_runtime_expression_statement_reads::<
                    R,
                    MAX_PARAMETERS,
                    MAX_EXPRESSION_NODES,
                >(
                    facts,
                    &locals[..local_count],
                    function,
                    resolver,
                    &statement,
                    body_start,
                )?;
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn preanalyze_runtime_loop_declarations<
    'source,
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    function: &Function<'source, MAX_PARAMETERS>,
    resolver: &R,
    loop_statement: &crate::WhileLoop<'source>,
    operand_type: &str,
    body_start: usize,
    facts: &mut RuntimeBodyFacts<'source>,
    outer_locals: &[Option<RuntimeLocal<'source>>; MAX_PARAMETERS],
    outer_local_count: usize,
    statement_index: usize,
) -> Result<(), CodegenError> {
    let mut locals = *outer_locals;
    let mut local_count = outer_local_count;
    if let Some(condition) = loop_statement.condition {
        facts.current_ownership_event_location =
            RuntimeOwnershipEventLocation::LoopHeader { statement_index };
        preanalyze_runtime_source_expression_reads::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
            facts,
            &locals[..local_count],
            function,
            resolver,
            condition,
            loop_statement.condition_span,
            body_start,
        )?;
    }
    for (operation_index, operation) in loop_statement.operations().iter().flatten().enumerate() {
        facts.current_ownership_event_location = RuntimeOwnershipEventLocation::LoopOperation {
            statement_index,
            operation_index,
        };
        match *operation {
            crate::LoopOperation::Local(local) => {
                preanalyze_runtime_local_binding::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
                    function,
                    resolver,
                    local,
                    operand_type,
                    body_start,
                    facts,
                    &mut locals,
                    &mut local_count,
                )?;
            }
            crate::LoopOperation::Assignment(assignment) => {
                preanalyze_runtime_assignment_access::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
                    facts,
                    &locals[..local_count],
                    function,
                    resolver,
                    &assignment,
                )?;
            }
            crate::LoopOperation::NestedBlock(index) => {
                let block = loop_statement.nested_blocks()[index].ok_or(CodegenError {
                    kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                    span: function.name_span,
                })?;
                preanalyze_runtime_nested_loop_block::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
                    function,
                    resolver,
                    &block,
                    operand_type,
                    body_start,
                    facts,
                    &locals,
                    local_count,
                    statement_index,
                    operation_index,
                )?;
            }
            crate::LoopOperation::ConditionalBlock(index) => {
                let block = loop_statement.conditional_blocks()[index].ok_or(CodegenError {
                    kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                    span: function.name_span,
                })?;
                facts.current_ownership_event_location =
                    RuntimeOwnershipEventLocation::LoopConditionalCondition {
                        statement_index,
                        operation_index,
                        arm_index: 0,
                    };
                preanalyze_runtime_source_expression_reads::<
                    R,
                    MAX_PARAMETERS,
                    MAX_EXPRESSION_NODES,
                >(
                    facts,
                    &locals[..local_count],
                    function,
                    resolver,
                    block.condition,
                    block.condition_span,
                    body_start,
                )?;
                let (block_locals, block_local_count) =
                    preanalyze_runtime_loop_actions::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
                        function,
                        resolver,
                        block.actions(),
                        operand_type,
                        body_start,
                        facts,
                        &locals,
                        local_count,
                        statement_index,
                        operation_index,
                        0,
                    )?;
                if let Some(crate::ConditionalLoopTerminal::Return(value)) = block.terminal {
                    facts.current_ownership_event_location =
                        RuntimeOwnershipEventLocation::LoopConditionalTerminal {
                            statement_index,
                            operation_index,
                            arm_index: 0,
                        };
                    preanalyze_runtime_return_expression_reads::<
                        R,
                        MAX_PARAMETERS,
                        MAX_EXPRESSION_NODES,
                    >(
                        facts,
                        &block_locals[..block_local_count],
                        function,
                        resolver,
                        value.value,
                        value.value_span,
                        body_start,
                    )?;
                }
                if let Some(else_index) = block.else_arm {
                    for (else_offset, arm) in loop_statement.conditional_else_arms()
                        [else_index..else_index + block.else_arm_count]
                        .iter()
                        .flatten()
                        .enumerate()
                    {
                        let arm_index = else_offset + 1;
                        if let Some(condition) = arm.condition {
                            facts.current_ownership_event_location =
                                RuntimeOwnershipEventLocation::LoopConditionalCondition {
                                    statement_index,
                                    operation_index,
                                    arm_index,
                                };
                            preanalyze_runtime_source_expression_reads::<
                                R,
                                MAX_PARAMETERS,
                                MAX_EXPRESSION_NODES,
                            >(
                                facts,
                                &locals[..local_count],
                                function,
                                resolver,
                                condition,
                                arm.condition_span,
                                body_start,
                            )?;
                        }
                        let (arm_locals, arm_local_count) = preanalyze_runtime_loop_actions::<
                            R,
                            MAX_PARAMETERS,
                            MAX_EXPRESSION_NODES,
                        >(
                            function,
                            resolver,
                            arm.actions(),
                            operand_type,
                            body_start,
                            facts,
                            &locals,
                            local_count,
                            statement_index,
                            operation_index,
                            arm_index,
                        )?;
                        if let Some(crate::ConditionalLoopTerminal::Return(value)) = arm.terminal {
                            facts.current_ownership_event_location =
                                RuntimeOwnershipEventLocation::LoopConditionalTerminal {
                                    statement_index,
                                    operation_index,
                                    arm_index,
                                };
                            preanalyze_runtime_return_expression_reads::<
                                R,
                                MAX_PARAMETERS,
                                MAX_EXPRESSION_NODES,
                            >(
                                facts,
                                &arm_locals[..arm_local_count],
                                function,
                                resolver,
                                value.value,
                                value.value_span,
                                body_start,
                            )?;
                        }
                    }
                }
            }
            crate::LoopOperation::Expression(statement) => {
                preanalyze_runtime_expression_statement_reads::<
                    R,
                    MAX_PARAMETERS,
                    MAX_EXPRESSION_NODES,
                >(
                    facts,
                    &locals[..local_count],
                    function,
                    resolver,
                    &statement,
                    body_start,
                )?;
            }
            crate::LoopOperation::ConditionalBreak(control)
            | crate::LoopOperation::ConditionalContinue(control) => {
                preanalyze_runtime_source_expression_reads::<
                    R,
                    MAX_PARAMETERS,
                    MAX_EXPRESSION_NODES,
                >(
                    facts,
                    &locals[..local_count],
                    function,
                    resolver,
                    control.condition,
                    control.condition_span,
                    body_start,
                )?;
            }
            crate::LoopOperation::ConditionalReturn(control) => {
                facts.current_ownership_event_location =
                    RuntimeOwnershipEventLocation::LoopConditionalReturnCondition {
                        statement_index,
                        operation_index,
                    };
                preanalyze_runtime_source_expression_reads::<
                    R,
                    MAX_PARAMETERS,
                    MAX_EXPRESSION_NODES,
                >(
                    facts,
                    &locals[..local_count],
                    function,
                    resolver,
                    control.condition,
                    control.condition_span,
                    body_start,
                )?;
                facts.current_ownership_event_location =
                    RuntimeOwnershipEventLocation::LoopConditionalReturnValue {
                        statement_index,
                        operation_index,
                    };
                preanalyze_runtime_return_expression_reads::<
                    R,
                    MAX_PARAMETERS,
                    MAX_EXPRESSION_NODES,
                >(
                    facts,
                    &locals[..local_count],
                    function,
                    resolver,
                    control.value,
                    control.value_span,
                    body_start,
                )?;
            }
            crate::LoopOperation::Return(value) => {
                facts.current_ownership_event_location =
                    RuntimeOwnershipEventLocation::LoopReturnValue {
                        statement_index,
                        operation_index,
                    };
                preanalyze_runtime_return_expression_reads::<
                    R,
                    MAX_PARAMETERS,
                    MAX_EXPRESSION_NODES,
                >(
                    facts,
                    &locals[..local_count],
                    function,
                    resolver,
                    value.value,
                    value.value_span,
                    body_start,
                )?;
            }
            crate::LoopOperation::Break
            | crate::LoopOperation::Continue
            | crate::LoopOperation::NestedUnitLoop => {}
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn preanalyze_runtime_top_level_statement<
    'source,
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    function: &Function<'source, MAX_PARAMETERS>,
    resolver: &R,
    body: &crate::FunctionBody<'source, MAX_PARAMETERS>,
    statement: crate::BodyStatement,
    statement_index: usize,
    operand_type: &str,
    body_start: usize,
    facts: &mut RuntimeBodyFacts<'source>,
    locals: &mut [Option<RuntimeLocal<'source>>; MAX_PARAMETERS],
    local_count: &mut usize,
) -> Result<(), CodegenError> {
    match statement {
        crate::BodyStatement::Local(index) => {
            let local = body.locals()[index].ok_or(CodegenError {
                kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                span: function.name_span,
            })?;
            preanalyze_runtime_local_binding::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
                function,
                resolver,
                local,
                operand_type,
                body_start,
                facts,
                locals,
                local_count,
            )?;
        }
        crate::BodyStatement::ConditionalAssignment(index) => {
            let conditional = body.conditional_assignments()[index].ok_or(CodegenError {
                kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                span: function.name_span,
            })?;
            for (branch_index, branch) in conditional.branches().iter().flatten().enumerate() {
                facts.current_ownership_event_location =
                    RuntimeOwnershipEventLocation::ConditionalAssignmentCondition {
                        statement_index,
                        branch_index,
                    };
                preanalyze_runtime_source_expression_reads::<
                    R,
                    MAX_PARAMETERS,
                    MAX_EXPRESSION_NODES,
                >(
                    facts,
                    &locals[..*local_count],
                    function,
                    resolver,
                    branch.condition,
                    branch.condition_span,
                    body_start,
                )?;
                preanalyze_runtime_conditional_actions::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
                    function,
                    resolver,
                    branch.actions(),
                    statement_index,
                    Some(branch_index),
                    operand_type,
                    body_start,
                    facts,
                    locals,
                    *local_count,
                )?;
            }
            preanalyze_runtime_conditional_actions::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
                function,
                resolver,
                conditional.else_actions(),
                statement_index,
                None,
                operand_type,
                body_start,
                facts,
                locals,
                *local_count,
            )?;
        }
        crate::BodyStatement::Assignment(index) => {
            let assignment = body.assignments()[index].ok_or(CodegenError {
                kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                span: function.name_span,
            })?;
            preanalyze_runtime_assignment_access::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
                facts,
                &locals[..*local_count],
                function,
                resolver,
                &assignment,
            )?;
        }
        crate::BodyStatement::Expression(index) => {
            let statement = body.expression_statements()[index].ok_or(CodegenError {
                kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                span: function.name_span,
            })?;
            preanalyze_runtime_expression_statement_reads::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
                facts,
                &locals[..*local_count],
                function,
                resolver,
                &statement,
                body_start,
            )?;
        }
        crate::BodyStatement::ConditionalReturn(index) => {
            let conditional = body.conditional_returns()[index].ok_or(CodegenError {
                kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                span: function.name_span,
            })?;
            facts.current_ownership_event_location =
                RuntimeOwnershipEventLocation::ConditionalReturnCondition {
                    statement_index,
                    branch_index: 0,
                };
            preanalyze_runtime_source_expression_reads::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
                facts,
                &locals[..*local_count],
                function,
                resolver,
                conditional.condition,
                conditional.condition_span,
                body_start,
            )?;
            facts.current_ownership_event_location =
                RuntimeOwnershipEventLocation::ConditionalReturnValue {
                    statement_index,
                    branch_index: 0,
                };
            preanalyze_runtime_return_expression_reads::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
                facts,
                &locals[..*local_count],
                function,
                resolver,
                conditional.value,
                conditional.value_span,
                body_start,
            )?;
        }
        crate::BodyStatement::ConditionalReturnElse(index) => {
            let conditional = body.conditional_return_elses()[index].ok_or(CodegenError {
                kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                span: function.name_span,
            })?;
            for (branch_index, branch) in conditional.branches().iter().flatten().enumerate() {
                facts.current_ownership_event_location =
                    RuntimeOwnershipEventLocation::ConditionalReturnCondition {
                        statement_index,
                        branch_index,
                    };
                preanalyze_runtime_source_expression_reads::<
                    R,
                    MAX_PARAMETERS,
                    MAX_EXPRESSION_NODES,
                >(
                    facts,
                    &locals[..*local_count],
                    function,
                    resolver,
                    branch.condition,
                    branch.condition_span,
                    body_start,
                )?;
                facts.current_ownership_event_location =
                    RuntimeOwnershipEventLocation::ConditionalReturnValue {
                        statement_index,
                        branch_index,
                    };
                preanalyze_runtime_return_expression_reads::<
                    R,
                    MAX_PARAMETERS,
                    MAX_EXPRESSION_NODES,
                >(
                    facts,
                    &locals[..*local_count],
                    function,
                    resolver,
                    branch.value,
                    branch.value_span,
                    body_start,
                )?;
            }
            if let Some(value) = conditional.else_value {
                facts.current_ownership_event_location =
                    RuntimeOwnershipEventLocation::ConditionalReturnElseValue { statement_index };
                preanalyze_runtime_return_expression_reads::<
                    R,
                    MAX_PARAMETERS,
                    MAX_EXPRESSION_NODES,
                >(
                    facts,
                    &locals[..*local_count],
                    function,
                    resolver,
                    value.value,
                    value.value_span,
                    body_start,
                )?;
            }
        }
        crate::BodyStatement::Return(index) => {
            let value = body.returns()[index].ok_or(CodegenError {
                kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                span: function.name_span,
            })?;
            facts.current_ownership_event_location =
                RuntimeOwnershipEventLocation::ReturnValue { statement_index };
            preanalyze_runtime_return_expression_reads::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
                facts,
                &locals[..*local_count],
                function,
                resolver,
                value.value,
                value.value_span,
                body_start,
            )?;
        }
        crate::BodyStatement::Loop(_) => {}
    }
    Ok(())
}

fn conditional_actions_terminate(
    actions: &[Option<crate::ConditionalAssignmentAction<'_>>],
) -> Result<bool, CodegenErrorKind> {
    let mut terminates = false;
    for action in actions {
        let action = action.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
        if matches!(action, crate::ConditionalAssignmentAction::Return(_)) {
            terminates = true;
        }
    }
    Ok(terminates)
}

fn conditional_actions_have_unreachable_fallthrough(
    actions: &[Option<crate::ConditionalAssignmentAction<'_>>],
) -> Result<bool, CodegenErrorKind> {
    let terminates = conditional_actions_terminate(actions)?;
    Ok(terminates
        && !matches!(
            actions.last().and_then(|action| *action),
            Some(crate::ConditionalAssignmentAction::Return(_))
        ))
}

fn push_unreachable_conditional_action_suffixes(
    actions: &[Option<crate::ConditionalAssignmentAction<'_>>],
    statement_index: usize,
    branch_index: Option<usize>,
    continuation: Option<RuntimeBasicBlockId>,
    facts: &mut RuntimeBodyFacts<'_>,
) -> Result<(), CodegenErrorKind> {
    let Some(first_return) = actions
        .iter()
        .position(|action| matches!(action, Some(crate::ConditionalAssignmentAction::Return(_))))
    else {
        return Ok(());
    };
    let mut first_action = first_return
        .checked_add(1)
        .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
    while first_action < actions.len() {
        let suffix = &actions[first_action..];
        let terminal_offset = suffix.iter().position(|action| {
            matches!(action, Some(crate::ConditionalAssignmentAction::Return(_)))
        });
        let action_count = if let Some(offset) = terminal_offset {
            offset
                .checked_add(1)
                .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?
        } else {
            suffix.len()
        };
        for action in &suffix[..action_count] {
            action.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
        }
        let block = facts.push_sourced_basic_block(
            statement_index,
            false,
            RuntimeBasicBlockSource::ConditionalAssignmentUnreachableActions {
                statement_index,
                branch_index,
                first_action,
                action_count,
            },
        )?;
        let target = if terminal_offset.is_some() {
            RuntimeControlFlowTarget::Return
        } else {
            RuntimeControlFlowTarget::Block(
                continuation.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?,
            )
        };
        facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
            from: block,
            target,
            kind: RuntimeControlFlowEdgeKind::Unconditional,
        })?;
        first_action = first_action
            .checked_add(action_count)
            .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
    }
    Ok(())
}

fn conditional_loop_terminal_is_break(
    terminal: Option<crate::ConditionalLoopTerminal<'_>>,
) -> bool {
    matches!(terminal, Some(crate::ConditionalLoopTerminal::Break))
}

fn conditional_loop_block_arms<'source>(
    loop_statement: &'source crate::WhileLoop<'source>,
    block: &crate::ConditionalLoopBlock<'source>,
) -> Result<&'source [Option<crate::ConditionalLoopArm<'source>>], CodegenErrorKind> {
    let Some(else_index) = block.else_arm else {
        return Ok(&[]);
    };
    let end = else_index
        .checked_add(block.else_arm_count)
        .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
    loop_statement
        .conditional_else_arms()
        .get(else_index..end)
        .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)
}

fn conditional_loop_block_all_paths_terminate(
    loop_statement: &crate::WhileLoop<'_>,
    block: &crate::ConditionalLoopBlock<'_>,
) -> Result<bool, CodegenErrorKind> {
    if block.terminal.is_none() {
        return Ok(false);
    }
    let arms = conditional_loop_block_arms(loop_statement, block)?;
    let Some(last) = arms.last().copied().flatten() else {
        return Ok(false);
    };
    if last.condition.is_some() {
        return Ok(false);
    }
    for arm in arms {
        let arm = arm.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
        if arm.terminal.is_none() {
            return Ok(false);
        }
    }
    Ok(true)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeNestedLoopControl {
    Break {
        target: crate::NestedLoopControlTarget,
        conditional: bool,
    },
    Continue {
        target: crate::NestedLoopControlTarget,
        conditional: bool,
    },
    Return {
        conditional: bool,
    },
    ConditionalBlock {
        branch_index: usize,
        terminal: RuntimeNestedLoopBranchTerminal,
        alternative_terminals:
            [Option<RuntimeNestedLoopBranchTerminal>; crate::MAX_NESTED_LOOP_CONDITIONAL_ELSE_ARMS],
        alternative_count: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeNestedLoopBranchTerminal {
    Break(crate::NestedLoopControlTarget),
    Continue(crate::NestedLoopControlTarget),
    Return,
}

fn runtime_nested_loop_branch_terminal(
    terminal: crate::NestedLoopUnconditionalControl<'_>,
) -> RuntimeNestedLoopBranchTerminal {
    match terminal {
        crate::NestedLoopUnconditionalControl::Break(target) => {
            RuntimeNestedLoopBranchTerminal::Break(target)
        }
        crate::NestedLoopUnconditionalControl::Continue(target) => {
            RuntimeNestedLoopBranchTerminal::Continue(target)
        }
        crate::NestedLoopUnconditionalControl::Return(_) => RuntimeNestedLoopBranchTerminal::Return,
    }
}

fn record_nested_loop_control(
    found: &mut Option<RuntimeNestedLoopControl>,
    control: RuntimeNestedLoopControl,
) -> Result<(), CodegenErrorKind> {
    if found.replace(control).is_some() {
        return Err(CodegenErrorKind::InvalidRuntimeControlFlowFacts);
    }
    Ok(())
}

fn nested_loop_control_at(
    block: &crate::NestedLoopBlock<'_>,
    action_index: usize,
    control_order: usize,
) -> Result<Option<RuntimeNestedLoopControl>, CodegenErrorKind> {
    let mut found = None;
    for (branch_index, ((branch, stored_action_index), stored_order)) in block
        .conditional_blocks()
        .iter()
        .zip(block.conditional_block_action_indices())
        .zip(block.conditional_block_control_orders())
        .enumerate()
    {
        if action_index != *stored_action_index || control_order != *stored_order {
            continue;
        }
        let branch = branch.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
        let terminal = runtime_nested_loop_branch_terminal(branch.terminal);
        let mut alternative_terminals = [None; crate::MAX_NESTED_LOOP_CONDITIONAL_ELSE_ARMS];
        for (alternative_index, arm) in branch.else_arms().iter().copied().enumerate() {
            let arm = arm.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
            alternative_terminals[alternative_index] =
                Some(runtime_nested_loop_branch_terminal(arm.terminal));
        }
        record_nested_loop_control(
            &mut found,
            RuntimeNestedLoopControl::ConditionalBlock {
                branch_index,
                terminal,
                alternative_terminals,
                alternative_count: branch.else_arm_count(),
            },
        )?;
    }
    for ((control, stored_action_index), stored_order) in block
        .unconditional_controls()
        .iter()
        .zip(block.unconditional_control_action_indices())
        .zip(block.unconditional_control_orders())
    {
        if action_index != *stored_action_index || control_order != *stored_order {
            continue;
        }
        let control = control.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
        let control = match control {
            crate::NestedLoopUnconditionalControl::Break(target) => {
                RuntimeNestedLoopControl::Break {
                    target,
                    conditional: false,
                }
            }
            crate::NestedLoopUnconditionalControl::Continue(target) => {
                RuntimeNestedLoopControl::Continue {
                    target,
                    conditional: false,
                }
            }
            crate::NestedLoopUnconditionalControl::Return(_) => {
                RuntimeNestedLoopControl::Return { conditional: false }
            }
        };
        record_nested_loop_control(&mut found, control)?;
    }
    for (((control, stored_action_index), stored_order), target) in block
        .conditional_breaks()
        .iter()
        .zip(block.conditional_break_action_indices())
        .zip(block.conditional_break_control_orders())
        .zip(block.conditional_break_targets())
    {
        control.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
        if action_index == *stored_action_index && control_order == *stored_order {
            record_nested_loop_control(
                &mut found,
                RuntimeNestedLoopControl::Break {
                    target: *target,
                    conditional: true,
                },
            )?;
        }
    }
    for (((control, stored_action_index), stored_order), target) in block
        .conditional_continues()
        .iter()
        .zip(block.conditional_continue_action_indices())
        .zip(block.conditional_continue_control_orders())
        .zip(block.conditional_continue_targets())
    {
        control.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
        if action_index == *stored_action_index && control_order == *stored_order {
            record_nested_loop_control(
                &mut found,
                RuntimeNestedLoopControl::Continue {
                    target: *target,
                    conditional: true,
                },
            )?;
        }
    }
    for ((control, stored_action_index), stored_order) in block
        .conditional_returns()
        .iter()
        .zip(block.conditional_return_action_indices())
        .zip(block.conditional_return_control_orders())
    {
        control.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
        if action_index == *stored_action_index && control_order == *stored_order {
            record_nested_loop_control(
                &mut found,
                RuntimeNestedLoopControl::Return { conditional: true },
            )?;
        }
    }
    Ok(found)
}

fn nested_loop_control_count(
    block: &crate::NestedLoopBlock<'_>,
) -> Result<usize, CodegenErrorKind> {
    block
        .conditional_blocks()
        .len()
        .checked_add(block.unconditional_controls().len())
        .and_then(|count| count.checked_add(block.conditional_breaks().len()))
        .and_then(|count| count.checked_add(block.conditional_continues().len()))
        .and_then(|count| count.checked_add(block.conditional_returns().len()))
        .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)
}

fn validate_nested_loop_conditional_branch(
    branch: crate::parser::NestedLoopConditionalBlock<'_>,
) -> Result<(), CodegenErrorKind> {
    for action in branch.actions() {
        action.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
    }
    let alternatives = branch.else_arms();
    for (index, alternative) in alternatives.iter().copied().enumerate() {
        let alternative = alternative.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
        if alternative.condition().is_none() && index + 1 != alternatives.len() {
            return Err(CodegenErrorKind::InvalidRuntimeControlFlowFacts);
        }
        for action in alternative.actions() {
            action.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
        }
    }
    Ok(())
}

fn nested_loop_has_supported_control_flow(
    block: &crate::NestedLoopBlock<'_>,
) -> Result<bool, CodegenErrorKind> {
    for branch in block.conditional_blocks() {
        let branch = branch.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
        validate_nested_loop_conditional_branch(branch)?;
    }
    for action in block.actions() {
        action.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
    }
    let control_count = nested_loop_control_count(block)?;
    let mut seen = 0usize;
    for action_index in 0..=block.action_count() {
        for control_order in 0..control_count {
            let Some(_control) = nested_loop_control_at(block, action_index, control_order)? else {
                continue;
            };
            seen = seen
                .checked_add(1)
                .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
        }
    }
    if seen != control_count {
        return Err(CodegenErrorKind::InvalidRuntimeControlFlowFacts);
    }
    Ok(true)
}

fn nested_loop_has_inner_exit(block: &crate::NestedLoopBlock<'_>) -> bool {
    block.entry_condition.is_some()
        || block
            .unconditional_controls()
            .iter()
            .flatten()
            .any(|control| {
                matches!(
                    control,
                    crate::NestedLoopUnconditionalControl::Break(
                        crate::NestedLoopControlTarget::Inner
                    )
                )
            })
        || block
            .conditional_break_targets()
            .contains(&crate::NestedLoopControlTarget::Inner)
        || block.conditional_blocks().iter().flatten().any(|branch| {
            matches!(
                branch.terminal,
                crate::NestedLoopUnconditionalControl::Break(crate::NestedLoopControlTarget::Inner)
            ) || branch.else_arms().iter().flatten().any(|arm| {
                matches!(
                    arm.terminal,
                    crate::NestedLoopUnconditionalControl::Break(
                        crate::NestedLoopControlTarget::Inner
                    )
                )
            })
        })
}

fn nested_loop_has_outer_break(block: &crate::NestedLoopBlock<'_>) -> bool {
    block
        .unconditional_controls()
        .iter()
        .flatten()
        .any(|control| {
            matches!(
                control,
                crate::NestedLoopUnconditionalControl::Break(crate::NestedLoopControlTarget::Outer)
            )
        })
        || block
            .conditional_break_targets()
            .contains(&crate::NestedLoopControlTarget::Outer)
        || block.conditional_blocks().iter().flatten().any(|branch| {
            matches!(
                branch.terminal,
                crate::NestedLoopUnconditionalControl::Break(crate::NestedLoopControlTarget::Outer)
            ) || branch.else_arms().iter().flatten().any(|arm| {
                matches!(
                    arm.terminal,
                    crate::NestedLoopUnconditionalControl::Break(
                        crate::NestedLoopControlTarget::Outer
                    )
                )
            })
        })
}

fn loop_has_supported_initial_control_flow(
    loop_statement: &crate::WhileLoop<'_>,
) -> Result<bool, CodegenErrorKind> {
    for operation in loop_statement.operations() {
        let operation = operation.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
        if let crate::LoopOperation::NestedBlock(index) = operation {
            let block = loop_statement
                .nested_blocks()
                .get(index)
                .and_then(|block| *block)
                .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
            if !nested_loop_has_supported_control_flow(&block)? {
                return Ok(false);
            }
        }
        if let crate::LoopOperation::ConditionalBlock(index) = operation {
            let block = loop_statement
                .conditional_blocks()
                .get(index)
                .and_then(|block| *block)
                .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
            for action in block.actions() {
                action.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
            }
            let arms = conditional_loop_block_arms(loop_statement, &block)?;
            if block.else_arm.is_some() && arms.is_empty() {
                return Err(CodegenErrorKind::InvalidRuntimeControlFlowFacts);
            }
            for (arm_index, arm) in arms.iter().enumerate() {
                let arm = arm.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
                if arm.condition.is_none() && arm_index + 1 != arms.len() {
                    return Err(CodegenErrorKind::InvalidRuntimeControlFlowFacts);
                }
                for action in arm.actions() {
                    action.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
                }
            }
        }
    }
    Ok(true)
}

fn loop_exit_paths(
    loop_statement: &crate::WhileLoop<'_>,
) -> Result<(bool, bool), CodegenErrorKind> {
    let mut has_any_exit = loop_statement.condition.is_some();
    let mut has_reachable_exit = loop_statement.condition.is_some();
    let mut operation_reachable = true;
    for operation in loop_statement.operations().iter().flatten() {
        let direct_exit = matches!(
            operation,
            crate::LoopOperation::Break | crate::LoopOperation::ConditionalBreak(_)
        );
        has_any_exit |= direct_exit;
        has_reachable_exit |= operation_reachable && direct_exit;
        let mut universally_terminates = matches!(
            operation,
            crate::LoopOperation::Break
                | crate::LoopOperation::Continue
                | crate::LoopOperation::Return(_)
        );
        if let crate::LoopOperation::ConditionalBlock(index) = operation {
            let block = loop_statement
                .conditional_blocks()
                .get(*index)
                .and_then(|block| *block)
                .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
            let mut block_has_break = conditional_loop_terminal_is_break(block.terminal);
            for arm in conditional_loop_block_arms(loop_statement, &block)? {
                let arm = arm.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
                block_has_break |= conditional_loop_terminal_is_break(arm.terminal);
            }
            has_any_exit |= block_has_break;
            has_reachable_exit |= operation_reachable && block_has_break;
            universally_terminates =
                conditional_loop_block_all_paths_terminate(loop_statement, &block)?;
        }
        if let crate::LoopOperation::NestedBlock(index) = operation {
            let block = loop_statement
                .nested_blocks()
                .get(*index)
                .and_then(|block| *block)
                .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
            let block_has_outer_break = nested_loop_has_outer_break(&block);
            has_any_exit |= block_has_outer_break;
            has_reachable_exit |= operation_reachable && block_has_outer_break;
            universally_terminates = !nested_loop_has_inner_exit(&block);
        }
        operation_reachable &= !universally_terminates;
    }
    Ok((has_any_exit, has_reachable_exit))
}

fn conditional_loop_terminal_target(
    terminal: Option<crate::ConditionalLoopTerminal<'_>>,
    header: RuntimeBasicBlockId,
    continuation: Option<RuntimeBasicBlockId>,
) -> Result<Option<RuntimeControlFlowTarget>, CodegenErrorKind> {
    match terminal {
        None => Ok(None),
        Some(crate::ConditionalLoopTerminal::Break) => Ok(Some(RuntimeControlFlowTarget::Block(
            continuation.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?,
        ))),
        Some(crate::ConditionalLoopTerminal::Continue) => {
            Ok(Some(RuntimeControlFlowTarget::Block(header)))
        }
        Some(crate::ConditionalLoopTerminal::Return(_)) => {
            Ok(Some(RuntimeControlFlowTarget::Return))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn push_conditional_loop_block_control_flow(
    loop_statement: &crate::WhileLoop<'_>,
    block: &crate::ConditionalLoopBlock<'_>,
    statement_index: usize,
    operation_index: usize,
    primary_condition: RuntimeBasicBlockId,
    header: RuntimeBasicBlockId,
    continuation: Option<RuntimeBasicBlockId>,
    reachable: bool,
    facts: &mut RuntimeBodyFacts<'_>,
) -> Result<Option<RuntimeBasicBlockId>, CodegenErrorKind> {
    let all_paths_terminate = conditional_loop_block_all_paths_terminate(loop_statement, block)?;
    let next = if all_paths_terminate {
        None
    } else {
        Some(facts.push_loop_body_block(statement_index, operation_index + 1, reachable)?)
    };
    let primary_actions = facts.push_sourced_basic_block(
        statement_index,
        reachable,
        RuntimeBasicBlockSource::LoopConditionalActions {
            statement_index,
            operation_index,
            arm_index: 0,
            action_count: block.action_count(),
        },
    )?;
    facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
        from: primary_condition,
        target: RuntimeControlFlowTarget::Block(primary_actions),
        kind: RuntimeControlFlowEdgeKind::True,
    })?;
    let primary_target = conditional_loop_terminal_target(block.terminal, header, continuation)?
        .or(next.map(RuntimeControlFlowTarget::Block))
        .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
    facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
        from: primary_actions,
        target: primary_target,
        kind: RuntimeControlFlowEdgeKind::Unconditional,
    })?;

    let arms = conditional_loop_block_arms(loop_statement, block)?;
    let mut false_source = primary_condition;
    let mut has_unconditional_arm = false;
    for (else_index, arm) in arms.iter().enumerate() {
        let arm = arm.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
        let arm_index = else_index + 1;
        let condition = if arm.condition.is_some() {
            let condition = facts.push_sourced_basic_block(
                statement_index,
                reachable,
                RuntimeBasicBlockSource::LoopConditionalCondition {
                    statement_index,
                    operation_index,
                    arm_index,
                },
            )?;
            facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                from: false_source,
                target: RuntimeControlFlowTarget::Block(condition),
                kind: RuntimeControlFlowEdgeKind::False,
            })?;
            Some(condition)
        } else {
            has_unconditional_arm = true;
            None
        };
        let actions = facts.push_sourced_basic_block(
            statement_index,
            reachable,
            RuntimeBasicBlockSource::LoopConditionalActions {
                statement_index,
                operation_index,
                arm_index,
                action_count: arm.action_count(),
            },
        )?;
        if let Some(condition) = condition {
            facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                from: condition,
                target: RuntimeControlFlowTarget::Block(actions),
                kind: RuntimeControlFlowEdgeKind::True,
            })?;
            false_source = condition;
        } else {
            facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                from: false_source,
                target: RuntimeControlFlowTarget::Block(actions),
                kind: RuntimeControlFlowEdgeKind::False,
            })?;
        }
        let target = conditional_loop_terminal_target(arm.terminal, header, continuation)?
            .or(next.map(RuntimeControlFlowTarget::Block))
            .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
        facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
            from: actions,
            target,
            kind: RuntimeControlFlowEdgeKind::Unconditional,
        })?;
        if has_unconditional_arm {
            break;
        }
    }
    if !has_unconditional_arm {
        facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
            from: false_source,
            target: RuntimeControlFlowTarget::Block(
                next.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?,
            ),
            kind: RuntimeControlFlowEdgeKind::False,
        })?;
    }
    Ok(next)
}

fn push_pending_control_flow_edge(
    facts: &mut RuntimeBodyFacts<'_>,
    pending: Option<(RuntimeBasicBlockId, RuntimeControlFlowEdgeKind)>,
    target: RuntimeBasicBlockId,
) -> Result<(), CodegenErrorKind> {
    let (from, kind) = pending.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
    facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
        from,
        target: RuntimeControlFlowTarget::Block(target),
        kind,
    })
}

fn nested_loop_control_target(
    control: RuntimeNestedLoopControl,
    nested_header: RuntimeBasicBlockId,
    after_nested: Option<RuntimeBasicBlockId>,
    outer_header: RuntimeBasicBlockId,
    outer_continuation: Option<RuntimeBasicBlockId>,
) -> Result<RuntimeControlFlowTarget, CodegenErrorKind> {
    match control {
        RuntimeNestedLoopControl::Break { target, .. } => {
            let target = if target == crate::NestedLoopControlTarget::Inner {
                after_nested.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?
            } else {
                outer_continuation.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?
            };
            Ok(RuntimeControlFlowTarget::Block(target))
        }
        RuntimeNestedLoopControl::Continue { target, .. } => Ok(RuntimeControlFlowTarget::Block(
            if target == crate::NestedLoopControlTarget::Inner {
                nested_header
            } else {
                outer_header
            },
        )),
        RuntimeNestedLoopControl::Return { .. } => Ok(RuntimeControlFlowTarget::Return),
        RuntimeNestedLoopControl::ConditionalBlock { terminal, .. } => {
            nested_loop_branch_control_target(
                terminal,
                nested_header,
                after_nested,
                outer_header,
                outer_continuation,
            )
        }
    }
}

fn nested_loop_branch_control_target(
    terminal: RuntimeNestedLoopBranchTerminal,
    nested_header: RuntimeBasicBlockId,
    after_nested: Option<RuntimeBasicBlockId>,
    outer_header: RuntimeBasicBlockId,
    outer_continuation: Option<RuntimeBasicBlockId>,
) -> Result<RuntimeControlFlowTarget, CodegenErrorKind> {
    match terminal {
        RuntimeNestedLoopBranchTerminal::Break(target) => {
            let target = if target == crate::NestedLoopControlTarget::Inner {
                after_nested.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?
            } else {
                outer_continuation.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?
            };
            Ok(RuntimeControlFlowTarget::Block(target))
        }
        RuntimeNestedLoopBranchTerminal::Continue(target) => Ok(RuntimeControlFlowTarget::Block(
            if target == crate::NestedLoopControlTarget::Inner {
                nested_header
            } else {
                outer_header
            },
        )),
        RuntimeNestedLoopBranchTerminal::Return => Ok(RuntimeControlFlowTarget::Return),
    }
}

#[allow(clippy::too_many_arguments)]
fn push_nested_loop_block_control_flow(
    block: &crate::NestedLoopBlock<'_>,
    statement_index: usize,
    operation_index: usize,
    outer_body: RuntimeBasicBlockId,
    outer_header: RuntimeBasicBlockId,
    outer_continuation: Option<RuntimeBasicBlockId>,
    reachable: bool,
    facts: &mut RuntimeBodyFacts<'_>,
) -> Result<Option<RuntimeBasicBlockId>, CodegenErrorKind> {
    let after_nested = if nested_loop_has_inner_exit(block) {
        Some(facts.push_loop_body_block(statement_index, operation_index + 1, reachable)?)
    } else {
        None
    };
    let nested_header = facts.push_sourced_basic_block(
        statement_index,
        reachable,
        RuntimeBasicBlockSource::NestedLoopHeader {
            statement_index,
            operation_index,
        },
    )?;
    facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
        from: outer_body,
        target: RuntimeControlFlowTarget::Block(nested_header),
        kind: RuntimeControlFlowEdgeKind::Unconditional,
    })?;
    let mut pending = if block.entry_condition.is_some() {
        facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
            from: nested_header,
            target: RuntimeControlFlowTarget::Block(
                after_nested.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?,
            ),
            kind: RuntimeControlFlowEdgeKind::False,
        })?;
        Some((nested_header, RuntimeControlFlowEdgeKind::True))
    } else {
        Some((nested_header, RuntimeControlFlowEdgeKind::Unconditional))
    };
    let mut event_reachable = reachable;
    let control_count = nested_loop_control_count(block)?;
    let mut seen = 0usize;
    for action_index in 0..=block.action_count() {
        for control_order in 0..control_count {
            let Some(control) = nested_loop_control_at(block, action_index, control_order)? else {
                continue;
            };
            seen = seen
                .checked_add(1)
                .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
            let control_source = match control {
                RuntimeNestedLoopControl::ConditionalBlock { branch_index, .. } => {
                    RuntimeBasicBlockSource::NestedLoopBranchCondition {
                        statement_index,
                        operation_index,
                        branch_index,
                    }
                }
                _ => RuntimeBasicBlockSource::NestedLoopControl {
                    statement_index,
                    operation_index,
                    action_index,
                    control_order,
                },
            };
            let control_block =
                facts.push_sourced_basic_block(statement_index, event_reachable, control_source)?;
            if pending.is_some() {
                push_pending_control_flow_edge(facts, pending, control_block)?;
            }
            let target = nested_loop_control_target(
                control,
                nested_header,
                after_nested,
                outer_header,
                outer_continuation,
            )?;
            let conditional = matches!(
                control,
                RuntimeNestedLoopControl::Break {
                    conditional: true,
                    ..
                } | RuntimeNestedLoopControl::Continue {
                    conditional: true,
                    ..
                } | RuntimeNestedLoopControl::Return { conditional: true }
                    | RuntimeNestedLoopControl::ConditionalBlock { .. }
            );
            let exhaustive_branch = matches!(
                control,
                RuntimeNestedLoopControl::ConditionalBlock {
                    alternative_count,
                    branch_index,
                    ..
                } if alternative_count != 0
                    && block
                        .conditional_blocks()
                        .get(branch_index)
                        .and_then(|branch| *branch)
                        .and_then(|branch| branch.else_arms().last().copied().flatten())
                        .is_some_and(|arm| arm.condition().is_none())
            );
            let mut branch_fallthrough = (conditional && !exhaustive_branch)
                .then_some((control_block, RuntimeControlFlowEdgeKind::False));
            if let RuntimeNestedLoopControl::ConditionalBlock {
                branch_index,
                alternative_terminals,
                alternative_count,
                ..
            } = control
            {
                let branch = block
                    .conditional_blocks()
                    .get(branch_index)
                    .and_then(|branch| *branch)
                    .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
                let action_block = facts.push_sourced_basic_block(
                    statement_index,
                    event_reachable,
                    RuntimeBasicBlockSource::NestedLoopBranchActions {
                        statement_index,
                        operation_index,
                        branch_index,
                        action_count: branch.action_count(),
                    },
                )?;
                facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                    from: control_block,
                    target: RuntimeControlFlowTarget::Block(action_block),
                    kind: RuntimeControlFlowEdgeKind::True,
                })?;
                facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                    from: action_block,
                    target,
                    kind: RuntimeControlFlowEdgeKind::Unconditional,
                })?;
                let mut preceding_condition = control_block;
                for (alternative_index, else_arm) in branch.else_arms().iter().copied().enumerate()
                {
                    let else_arm =
                        else_arm.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
                    let else_terminal = alternative_terminals
                        .get(alternative_index)
                        .copied()
                        .flatten()
                        .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
                    let else_block = facts.push_sourced_basic_block(
                        statement_index,
                        event_reachable,
                        RuntimeBasicBlockSource::NestedLoopBranchElseActions {
                            statement_index,
                            operation_index,
                            branch_index,
                            alternative_index,
                            action_count: else_arm.action_count(),
                        },
                    )?;
                    let else_entry = if else_arm.condition().is_some() {
                        let else_condition = facts.push_sourced_basic_block(
                            statement_index,
                            event_reachable,
                            RuntimeBasicBlockSource::NestedLoopBranchElseCondition {
                                statement_index,
                                operation_index,
                                branch_index,
                                alternative_index,
                            },
                        )?;
                        facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                            from: else_condition,
                            target: RuntimeControlFlowTarget::Block(else_block),
                            kind: RuntimeControlFlowEdgeKind::True,
                        })?;
                        branch_fallthrough =
                            Some((else_condition, RuntimeControlFlowEdgeKind::False));
                        else_condition
                    } else {
                        branch_fallthrough = None;
                        else_block
                    };
                    facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                        from: preceding_condition,
                        target: RuntimeControlFlowTarget::Block(else_entry),
                        kind: RuntimeControlFlowEdgeKind::False,
                    })?;
                    if else_arm.condition().is_some() {
                        preceding_condition = else_entry;
                    }
                    facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                        from: else_block,
                        target: nested_loop_branch_control_target(
                            else_terminal,
                            nested_header,
                            after_nested,
                            outer_header,
                            outer_continuation,
                        )?,
                        kind: RuntimeControlFlowEdgeKind::Unconditional,
                    })?;
                }
                if alternative_count != branch.else_arm_count() {
                    return Err(CodegenErrorKind::InvalidRuntimeControlFlowFacts);
                }
            } else {
                facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                    from: control_block,
                    target,
                    kind: if conditional {
                        RuntimeControlFlowEdgeKind::True
                    } else {
                        RuntimeControlFlowEdgeKind::Unconditional
                    },
                })?;
            }
            pending = branch_fallthrough;
            if !conditional || exhaustive_branch {
                event_reachable = false;
            }
        }
        if action_index == block.action_count() {
            break;
        }
        let action_block = facts.push_sourced_basic_block(
            statement_index,
            event_reachable,
            RuntimeBasicBlockSource::NestedLoopAction {
                statement_index,
                operation_index,
                action_index,
            },
        )?;
        if pending.is_some() {
            push_pending_control_flow_edge(facts, pending, action_block)?;
        }
        pending = Some((action_block, RuntimeControlFlowEdgeKind::Unconditional));
    }
    if seen != control_count {
        return Err(CodegenErrorKind::InvalidRuntimeControlFlowFacts);
    }
    if let Some((from, kind)) = pending {
        facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
            from,
            target: RuntimeControlFlowTarget::Block(nested_header),
            kind,
        })?;
    }
    Ok(after_nested)
}

fn preanalyze_runtime_body_control_flow<'source, const MAX_PARAMETERS: usize>(
    body: &crate::FunctionBody<'source, MAX_PARAMETERS>,
    facts: &mut RuntimeBodyFacts<'source>,
) -> Result<(), CodegenErrorKind> {
    for statement in body.statements().iter().flatten() {
        match statement {
            crate::BodyStatement::ConditionalAssignment(_) => {}
            crate::BodyStatement::Loop(index) => {
                let loop_statement = body
                    .while_loops()
                    .get(*index)
                    .and_then(|loop_statement| *loop_statement)
                    .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
                if !loop_has_supported_initial_control_flow(&loop_statement)? {
                    return Err(CodegenErrorKind::UnsupportedRuntimeControlFlow);
                }
            }
            _ => {}
        }
    }

    let mut current = facts.push_basic_block(0, true)?;
    let mut current_reachable = true;
    let mut terminated = false;
    let statement_count = body.statement_count();
    for (statement_index, statement) in body.statements().iter().flatten().enumerate() {
        facts.extend_basic_block(current)?;
        match statement {
            crate::BodyStatement::ConditionalReturn(_) => {
                let next = facts.push_basic_block(statement_index + 1, current_reachable)?;
                facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                    from: current,
                    target: RuntimeControlFlowTarget::Return,
                    kind: RuntimeControlFlowEdgeKind::True,
                })?;
                facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                    from: current,
                    target: RuntimeControlFlowTarget::Block(next),
                    kind: RuntimeControlFlowEdgeKind::False,
                })?;
                current = next;
                terminated = false;
            }
            crate::BodyStatement::ConditionalReturnElse(index) => {
                let conditional = body
                    .conditional_return_elses()
                    .get(*index)
                    .and_then(|conditional| *conditional)
                    .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
                let mut condition_block = current;
                let branch_count = conditional.branch_count();
                if branch_count == 0 {
                    return Err(CodegenErrorKind::InvalidRuntimeControlFlowFacts);
                }
                for branch_index in 0..branch_count {
                    facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                        from: condition_block,
                        target: RuntimeControlFlowTarget::Return,
                        kind: RuntimeControlFlowEdgeKind::True,
                    })?;
                    if branch_index + 1 < branch_count {
                        let next = facts.push_conditional_return_branch_block(
                            statement_index,
                            branch_index + 1,
                            current_reachable,
                        )?;
                        facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                            from: condition_block,
                            target: RuntimeControlFlowTarget::Block(next),
                            kind: RuntimeControlFlowEdgeKind::False,
                        })?;
                        condition_block = next;
                    } else if conditional.else_value.is_some() {
                        facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                            from: condition_block,
                            target: RuntimeControlFlowTarget::Return,
                            kind: RuntimeControlFlowEdgeKind::False,
                        })?;
                        terminated = true;
                    } else {
                        let next =
                            facts.push_basic_block(statement_index + 1, current_reachable)?;
                        facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                            from: condition_block,
                            target: RuntimeControlFlowTarget::Block(next),
                            kind: RuntimeControlFlowEdgeKind::False,
                        })?;
                        current = next;
                        terminated = false;
                    }
                }
                if terminated && statement_index + 1 < statement_count {
                    current = facts.push_basic_block(statement_index + 1, false)?;
                    current_reachable = false;
                    terminated = false;
                }
            }
            crate::BodyStatement::ConditionalAssignment(index) => {
                let conditional = body
                    .conditional_assignments()
                    .get(*index)
                    .and_then(|conditional| *conditional)
                    .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
                let branch_count = conditional.branch_count();
                if branch_count == 0 {
                    return Err(CodegenErrorKind::InvalidRuntimeControlFlowFacts);
                }
                let mut every_path_terminates = conditional.else_action_count() != 0
                    && conditional_actions_terminate(conditional.else_actions())?;
                let mut has_unreachable_fallthrough =
                    conditional_actions_have_unreachable_fallthrough(conditional.else_actions())?;
                for branch in conditional.branches() {
                    let branch = branch.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
                    every_path_terminates &= conditional_actions_terminate(branch.actions())?;
                    has_unreachable_fallthrough |=
                        conditional_actions_have_unreachable_fallthrough(branch.actions())?;
                }
                let continuation_reachable = current_reachable && !every_path_terminates;
                let continuation = if every_path_terminates && !has_unreachable_fallthrough {
                    None
                } else {
                    Some(facts.push_basic_block(statement_index + 1, continuation_reachable)?)
                };
                let mut condition_block = current;
                for (branch_index, branch) in conditional.branches().iter().enumerate() {
                    let branch = branch.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
                    let branch_condition = condition_block;
                    let actions = facts.push_sourced_basic_block(
                        statement_index,
                        current_reachable,
                        RuntimeBasicBlockSource::ConditionalAssignmentActions {
                            statement_index,
                            branch_index,
                        },
                    )?;
                    facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                        from: branch_condition,
                        target: RuntimeControlFlowTarget::Block(actions),
                        kind: RuntimeControlFlowEdgeKind::True,
                    })?;
                    facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                        from: actions,
                        target: if conditional_actions_terminate(branch.actions())? {
                            RuntimeControlFlowTarget::Return
                        } else {
                            RuntimeControlFlowTarget::Block(
                                continuation
                                    .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?,
                            )
                        },
                        kind: RuntimeControlFlowEdgeKind::Unconditional,
                    })?;
                    push_unreachable_conditional_action_suffixes(
                        branch.actions(),
                        statement_index,
                        Some(branch_index),
                        continuation,
                        facts,
                    )?;
                    let false_target = if branch_index + 1 < branch_count {
                        let next = facts.push_sourced_basic_block(
                            statement_index,
                            current_reachable,
                            RuntimeBasicBlockSource::ConditionalAssignmentCondition {
                                statement_index,
                                branch_index: branch_index + 1,
                            },
                        )?;
                        condition_block = next;
                        RuntimeControlFlowTarget::Block(next)
                    } else if conditional.else_action_count() != 0 {
                        let else_actions = facts.push_sourced_basic_block(
                            statement_index,
                            current_reachable,
                            RuntimeBasicBlockSource::ConditionalAssignmentElseActions {
                                statement_index,
                            },
                        )?;
                        facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                            from: else_actions,
                            target: if conditional_actions_terminate(conditional.else_actions())? {
                                RuntimeControlFlowTarget::Return
                            } else {
                                RuntimeControlFlowTarget::Block(
                                    continuation
                                        .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?,
                                )
                            },
                            kind: RuntimeControlFlowEdgeKind::Unconditional,
                        })?;
                        push_unreachable_conditional_action_suffixes(
                            conditional.else_actions(),
                            statement_index,
                            None,
                            continuation,
                            facts,
                        )?;
                        RuntimeControlFlowTarget::Block(else_actions)
                    } else {
                        RuntimeControlFlowTarget::Block(
                            continuation.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?,
                        )
                    };
                    facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                        from: branch_condition,
                        target: false_target,
                        kind: RuntimeControlFlowEdgeKind::False,
                    })?;
                }
                if let Some(next) = continuation {
                    current = next;
                    current_reachable = continuation_reachable;
                    terminated = false;
                } else {
                    terminated = true;
                    if statement_index + 1 < statement_count {
                        current = facts.push_basic_block(statement_index + 1, false)?;
                        current_reachable = false;
                        terminated = false;
                    }
                }
            }
            crate::BodyStatement::Loop(index) => {
                let loop_statement = body
                    .while_loops()
                    .get(*index)
                    .and_then(|loop_statement| *loop_statement)
                    .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
                let header = current;
                let (has_any_exit, has_reachable_exit) = loop_exit_paths(&loop_statement)?;
                let continuation_reachable = current_reachable && has_reachable_exit;
                let continuation = if has_any_exit {
                    Some(facts.push_basic_block(statement_index + 1, continuation_reachable)?)
                } else {
                    None
                };
                let mut body_block =
                    facts.push_loop_body_block(statement_index, 0, current_reachable)?;
                let mut body_path_reachable = current_reachable;
                if loop_statement.condition.is_some() {
                    facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                        from: header,
                        target: RuntimeControlFlowTarget::Block(body_block),
                        kind: RuntimeControlFlowEdgeKind::True,
                    })?;
                    facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                        from: header,
                        target: RuntimeControlFlowTarget::Block(
                            continuation.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?,
                        ),
                        kind: RuntimeControlFlowEdgeKind::False,
                    })?;
                } else {
                    facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                        from: header,
                        target: RuntimeControlFlowTarget::Block(body_block),
                        kind: RuntimeControlFlowEdgeKind::Unconditional,
                    })?;
                }
                let mut body_terminated = false;
                for (operation_index, operation) in loop_statement.operations().iter().enumerate() {
                    let operation =
                        operation.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
                    if body_terminated {
                        body_block =
                            facts.push_loop_body_block(statement_index, operation_index, false)?;
                        body_path_reachable = false;
                        body_terminated = false;
                    }
                    facts.extend_loop_body_block(body_block)?;
                    if let crate::LoopOperation::NestedBlock(index) = operation {
                        let block = loop_statement
                            .nested_blocks()
                            .get(index)
                            .and_then(|block| *block)
                            .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
                        if let Some(next) = push_nested_loop_block_control_flow(
                            &block,
                            statement_index,
                            operation_index,
                            body_block,
                            header,
                            continuation,
                            body_path_reachable,
                            facts,
                        )? {
                            body_block = next;
                        } else {
                            body_terminated = true;
                        }
                        continue;
                    }
                    if let crate::LoopOperation::ConditionalBlock(index) = operation {
                        let block = loop_statement
                            .conditional_blocks()
                            .get(index)
                            .and_then(|block| *block)
                            .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
                        if let Some(next) = push_conditional_loop_block_control_flow(
                            &loop_statement,
                            &block,
                            statement_index,
                            operation_index,
                            body_block,
                            header,
                            continuation,
                            body_path_reachable,
                            facts,
                        )? {
                            body_block = next;
                        } else {
                            body_terminated = true;
                        }
                        continue;
                    }
                    let conditional_target = match operation {
                        crate::LoopOperation::ConditionalBreak(_) => {
                            Some(RuntimeControlFlowTarget::Block(
                                continuation
                                    .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?,
                            ))
                        }
                        crate::LoopOperation::ConditionalContinue(_) => {
                            Some(RuntimeControlFlowTarget::Block(header))
                        }
                        crate::LoopOperation::ConditionalReturn(_) => {
                            Some(RuntimeControlFlowTarget::Return)
                        }
                        _ => None,
                    };
                    if let Some(target) = conditional_target {
                        let next = facts.push_loop_body_block(
                            statement_index,
                            operation_index + 1,
                            body_path_reachable,
                        )?;
                        facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                            from: body_block,
                            target,
                            kind: RuntimeControlFlowEdgeKind::True,
                        })?;
                        facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                            from: body_block,
                            target: RuntimeControlFlowTarget::Block(next),
                            kind: RuntimeControlFlowEdgeKind::False,
                        })?;
                        body_block = next;
                    } else {
                        let terminal = match operation {
                            crate::LoopOperation::Break => Some(RuntimeControlFlowTarget::Block(
                                continuation
                                    .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?,
                            )),
                            crate::LoopOperation::Continue => {
                                Some(RuntimeControlFlowTarget::Block(header))
                            }
                            crate::LoopOperation::Return(_) => {
                                Some(RuntimeControlFlowTarget::Return)
                            }
                            _ => None,
                        };
                        if let Some(target) = terminal {
                            facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                                from: body_block,
                                target,
                                kind: RuntimeControlFlowEdgeKind::Unconditional,
                            })?;
                            body_terminated = true;
                        }
                    }
                }
                if !body_terminated {
                    facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                        from: body_block,
                        target: RuntimeControlFlowTarget::Block(header),
                        kind: RuntimeControlFlowEdgeKind::Unconditional,
                    })?;
                }
                if let Some(next) = continuation {
                    current = next;
                    current_reachable = continuation_reachable;
                    terminated = false;
                } else {
                    terminated = true;
                    if statement_index + 1 < statement_count {
                        current = facts.push_basic_block(statement_index + 1, false)?;
                        current_reachable = false;
                        terminated = false;
                    }
                }
            }
            crate::BodyStatement::Return(_) => {
                facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
                    from: current,
                    target: RuntimeControlFlowTarget::Return,
                    kind: RuntimeControlFlowEdgeKind::Unconditional,
                })?;
                terminated = true;
                if statement_index + 1 < statement_count {
                    current = facts.push_basic_block(statement_index + 1, false)?;
                    current_reachable = false;
                    terminated = false;
                }
            }
            _ => {}
        }
    }
    if !terminated {
        facts.push_control_flow_edge(RuntimeControlFlowEdgeFact {
            from: current,
            target: RuntimeControlFlowTarget::Return,
            kind: RuntimeControlFlowEdgeKind::Unconditional,
        })?;
    }
    facts.control_flow_complete = true;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ValidatedRuntimeBody;

fn validate_runtime_body_for_emission<'source, const MAX_PARAMETERS: usize>(
    body: &crate::FunctionBody<'source, MAX_PARAMETERS>,
    facts: &RuntimeBodyFacts<'source>,
) -> Result<ValidatedRuntimeBody, CodegenErrorKind> {
    if !facts.control_flow_complete || facts.basic_block_count == 0 {
        return Err(CodegenErrorKind::UnsupportedRuntimeControlFlow);
    }
    for statement in body.statements().iter().copied() {
        let statement = statement.ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
        match statement {
            crate::BodyStatement::Local(index) => {
                body.locals()
                    .get(index)
                    .copied()
                    .flatten()
                    .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
            }
            crate::BodyStatement::Assignment(index) => {
                body.assignments()
                    .get(index)
                    .copied()
                    .flatten()
                    .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
            }
            crate::BodyStatement::ConditionalReturn(index) => {
                body.conditional_returns()
                    .get(index)
                    .copied()
                    .flatten()
                    .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
            }
            crate::BodyStatement::ConditionalReturnElse(index) => {
                body.conditional_return_elses()
                    .get(index)
                    .copied()
                    .flatten()
                    .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
            }
            crate::BodyStatement::ConditionalAssignment(index) => {
                body.conditional_assignments()
                    .get(index)
                    .copied()
                    .flatten()
                    .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
            }
            crate::BodyStatement::Expression(index) => {
                body.expression_statements()
                    .get(index)
                    .copied()
                    .flatten()
                    .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
            }
            crate::BodyStatement::Return(index) => {
                body.returns()
                    .get(index)
                    .copied()
                    .flatten()
                    .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
            }
            crate::BodyStatement::Loop(index) => {
                let loop_statement = body
                    .while_loops()
                    .get(index)
                    .copied()
                    .flatten()
                    .ok_or(CodegenErrorKind::InvalidRuntimeControlFlowFacts)?;
                if !loop_has_supported_initial_control_flow(&loop_statement)? {
                    return Err(CodegenErrorKind::UnsupportedRuntimeControlFlow);
                }
            }
        }
    }
    Ok(ValidatedRuntimeBody)
}

fn runtime_expression_initializedness_is_supported(facts: &RuntimeBodyFacts<'_>) -> bool {
    if facts.conditional_expression_count == 0 {
        return true;
    }
    let mut has_incoming = [false; MAX_RUNTIME_EXPRESSION_PROGRAM_POINT_FACTS];
    let mut has_outgoing = [false; MAX_RUNTIME_EXPRESSION_PROGRAM_POINT_FACTS];
    for edge in facts.expression_control_flow_edges[..facts.expression_control_flow_edge_count]
        .iter()
        .flatten()
    {
        if edge.from.0 >= facts.expression_program_point_count
            || edge.to.0 >= facts.expression_program_point_count
        {
            return false;
        }
        let Some(from) = facts.expression_program_points[edge.from.0] else {
            return false;
        };
        let Some(to) = facts.expression_program_points[edge.to.0] else {
            return false;
        };
        if from.location != to.location {
            return false;
        }
        has_outgoing[edge.from.0] = true;
        has_incoming[edge.to.0] = true;
    }
    for conditional in facts.conditional_expressions[..facts.conditional_expression_count]
        .iter()
        .flatten()
        .filter(|conditional| conditional.parent.is_none())
    {
        let mut roots = 0usize;
        let mut sinks = 0usize;
        for point in facts.expression_program_points[..facts.expression_program_point_count]
            .iter()
            .flatten()
            .filter(|point| point.location == conditional.location)
        {
            roots += usize::from(!has_incoming[point.id.0]);
            sinks += usize::from(!has_outgoing[point.id.0]);
        }
        if roots != 1 || sinks != 1 {
            return false;
        }
        if facts.initializations[..facts.initialization_count]
            .iter()
            .flatten()
            .any(|fact| fact.location == conditional.location && fact.expression_point.is_none())
            || facts.effects[..facts.effect_count]
                .iter()
                .flatten()
                .any(|fact| {
                    fact.location == conditional.location && fact.expression_point.is_none()
                })
        {
            return false;
        }
    }
    true
}

fn validate_runtime_initializedness(
    facts: &RuntimeBodyFacts<'_>,
    fallback_span: Span,
) -> Result<(), CodegenError> {
    if !facts.control_flow_complete || facts.basic_block_count == 0 {
        return Ok(());
    }
    if !facts.ownership_events_single_path
        && !runtime_expression_initializedness_is_supported(facts)
    {
        return Err(CodegenError {
            kind: CodegenErrorKind::RuntimeExpressionUnsupported,
            span: fallback_span,
        });
    }

    fn set_path_state(
        facts: &RuntimeBodyFacts<'_>,
        initialized: &mut [u64; RUNTIME_INITIALIZED_STATE_WORDS],
        path: RuntimeMovePathId,
        state: bool,
    ) -> Result<(), CodegenErrorKind> {
        fn set(initialized: &mut [u64; RUNTIME_INITIALIZED_STATE_WORDS], path: usize, state: bool) {
            let mask = 1u64 << (path % 64);
            if state {
                initialized[path / 64] |= mask;
            } else {
                initialized[path / 64] &= !mask;
            }
        }

        fn get(initialized: &[u64; RUNTIME_INITIALIZED_STATE_WORDS], path: usize) -> bool {
            initialized[path / 64] & (1u64 << (path % 64)) != 0
        }

        let path_fact = facts
            .move_paths
            .get(path.0)
            .and_then(|path| *path)
            .ok_or(CodegenErrorKind::InvalidRuntimePlaceFacts)?;
        set(initialized, path.0, state);
        if path_fact.parent.is_none() {
            for child in facts.move_paths[..facts.move_path_count]
                .iter()
                .flatten()
                .filter(|candidate| candidate.parent == Some(path))
            {
                set(initialized, child.id.0, state);
            }
        } else if let Some(parent) = path_fact.parent {
            let mut has_child = false;
            let mut all_children_initialized = true;
            for child in facts.move_paths[..facts.move_path_count]
                .iter()
                .flatten()
                .filter(|candidate| candidate.parent == Some(parent))
            {
                has_child = true;
                all_children_initialized &= get(initialized, child.id.0);
            }
            if !has_child {
                return Err(CodegenErrorKind::InvalidRuntimePlaceFacts);
            }
            set(initialized, parent.0, all_children_initialized);
        }
        Ok(())
    }

    fn apply_effect(
        facts: &RuntimeBodyFacts<'_>,
        effect: RuntimePlaceEffectFact,
        initialized: &mut [u64; RUNTIME_INITIALIZED_STATE_WORDS],
        check_reads: bool,
    ) -> Result<(), CodegenError> {
        if effect.path.0 >= facts.move_path_count {
            return Err(CodegenError {
                kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                span: effect.span,
            });
        }
        let is_initialized = initialized[effect.path.0 / 64] & (1u64 << (effect.path.0 % 64)) != 0;
        if check_reads
            && matches!(
                effect.kind,
                RuntimePlaceEffectKind::Copy
                    | RuntimePlaceEffectKind::Move
                    | RuntimePlaceEffectKind::SharedBorrow
                    | RuntimePlaceEffectKind::MutableBorrow
                    | RuntimePlaceEffectKind::LoanUse
                    | RuntimePlaceEffectKind::LoanMutation
                    | RuntimePlaceEffectKind::ReadModifyWrite
            )
            && !is_initialized
        {
            return Err(CodegenError {
                kind: CodegenErrorKind::RuntimeUseAfterMove,
                span: effect.span,
            });
        }
        match effect.kind {
            RuntimePlaceEffectKind::Move => {
                set_path_state(facts, initialized, effect.path, false).map_err(|kind| {
                    CodegenError {
                        kind,
                        span: effect.span,
                    }
                })?;
            }
            RuntimePlaceEffectKind::Write => {
                set_path_state(facts, initialized, effect.path, true).map_err(|kind| {
                    CodegenError {
                        kind,
                        span: effect.span,
                    }
                })?;
            }
            RuntimePlaceEffectKind::Copy
            | RuntimePlaceEffectKind::SharedBorrow
            | RuntimePlaceEffectKind::MutableBorrow
            | RuntimePlaceEffectKind::LoanUse
            | RuntimePlaceEffectKind::LoanMutation
            | RuntimePlaceEffectKind::ReadModifyWrite => {}
        }
        Ok(())
    }

    fn apply_expression_point_events(
        facts: &RuntimeBodyFacts<'_>,
        point: RuntimeExpressionProgramPointId,
        initialized: &mut [u64; RUNTIME_INITIALIZED_STATE_WORDS],
        check_reads: bool,
        fallback_span: Span,
    ) -> Result<(), CodegenError> {
        let mut initialization_index = 0usize;
        let mut effect_index = 0usize;
        for expected_event in 0..facts.ownership_event_count {
            let initialization = facts
                .initializations
                .get(initialization_index)
                .and_then(|fact| *fact)
                .filter(|fact| fact.event == RuntimeOwnershipEventId(expected_event));
            if let Some(initialization) = initialization {
                if initialization.expression_point == Some(point) {
                    set_path_state(facts, initialized, initialization.path, true).map_err(
                        |kind| CodegenError {
                            kind,
                            span: initialization.span.unwrap_or(fallback_span),
                        },
                    )?;
                }
                initialization_index += 1;
                continue;
            }
            let effect = facts
                .effects
                .get(effect_index)
                .and_then(|fact| *fact)
                .filter(|fact| fact.event == RuntimeOwnershipEventId(expected_event))
                .ok_or(CodegenError {
                    kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                    span: fallback_span,
                })?;
            if effect.expression_point == Some(point) {
                apply_effect(facts, effect, initialized, check_reads)?;
            }
            effect_index += 1;
        }
        if initialization_index != facts.initialization_count || effect_index != facts.effect_count
        {
            return Err(CodegenError {
                kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                span: fallback_span,
            });
        }
        Ok(())
    }

    fn apply_expression_location(
        facts: &RuntimeBodyFacts<'_>,
        location: RuntimeOwnershipEventLocation,
        initialized: &mut [u64; RUNTIME_INITIALIZED_STATE_WORDS],
        check_reads: bool,
        fallback_span: Span,
    ) -> Result<(), CodegenError> {
        #[allow(clippy::too_many_arguments)]
        fn walk(
            facts: &RuntimeBodyFacts<'_>,
            location: RuntimeOwnershipEventLocation,
            start: RuntimeExpressionProgramPointId,
            stop: Option<RuntimeExpressionProgramPointId>,
            mut state: [u64; RUNTIME_INITIALIZED_STATE_WORDS],
            check_reads: bool,
            fallback_span: Span,
            point_count: usize,
            processed: &mut usize,
            depth: usize,
        ) -> Result<([u64; RUNTIME_INITIALIZED_STATE_WORDS], bool), CodegenError> {
            if depth >= 64 {
                return Err(CodegenError {
                    kind: CodegenErrorKind::InvalidRuntimeControlFlowFacts,
                    span: fallback_span,
                });
            }
            let mut current = start;
            loop {
                if Some(current) == stop {
                    return Ok((state, true));
                }
                *processed = processed.checked_add(1).ok_or(CodegenError {
                    kind: CodegenErrorKind::InvalidRuntimeControlFlowFacts,
                    span: fallback_span,
                })?;
                if *processed > point_count {
                    return Err(CodegenError {
                        kind: CodegenErrorKind::InvalidRuntimeControlFlowFacts,
                        span: fallback_span,
                    });
                }
                let point = facts
                    .expression_program_points
                    .get(current.0)
                    .and_then(|point| *point)
                    .filter(|point| point.location == location)
                    .ok_or(CodegenError {
                        kind: CodegenErrorKind::InvalidRuntimeControlFlowFacts,
                        span: fallback_span,
                    })?;
                apply_expression_point_events(
                    facts,
                    current,
                    &mut state,
                    check_reads,
                    fallback_span,
                )?;
                if let RuntimeExpressionProgramPointKind::Condition(conditional_id) = point.kind {
                    let conditional = facts
                        .conditional_expressions
                        .get(conditional_id.0)
                        .and_then(|conditional| *conditional)
                        .filter(|conditional| conditional.location == location)
                        .ok_or(CodegenError {
                            kind: CodegenErrorKind::InvalidRuntimeControlFlowFacts,
                            span: fallback_span,
                        })?;
                    let (then_state, then_reached_join) = walk(
                        facts,
                        location,
                        conditional.then_branch,
                        Some(conditional.join),
                        state,
                        check_reads,
                        fallback_span,
                        point_count,
                        processed,
                        depth + 1,
                    )?;
                    let (mut else_state, else_reached_join) = walk(
                        facts,
                        location,
                        conditional.else_branch,
                        Some(conditional.join),
                        state,
                        check_reads,
                        fallback_span,
                        point_count,
                        processed,
                        depth + 1,
                    )?;
                    if !then_reached_join || !else_reached_join {
                        return Err(CodegenError {
                            kind: CodegenErrorKind::InvalidRuntimeControlFlowFacts,
                            span: fallback_span,
                        });
                    }
                    for (target, source) in else_state.iter_mut().zip(then_state) {
                        *target &= source;
                    }
                    state = else_state;
                    current = conditional.join;
                    continue;
                }
                let mut next = None;
                for edge in facts.expression_control_flow_edges
                    [..facts.expression_control_flow_edge_count]
                    .iter()
                    .flatten()
                    .filter(|edge| edge.from == current)
                {
                    if next.replace(edge.to).is_some() {
                        return Err(CodegenError {
                            kind: CodegenErrorKind::InvalidRuntimeControlFlowFacts,
                            span: fallback_span,
                        });
                    }
                }
                let Some(successor) = next else {
                    return Ok((state, false));
                };
                current = successor;
            }
        }

        let mut point_count = 0usize;
        let mut root = None;
        for point in facts.expression_program_points[..facts.expression_program_point_count]
            .iter()
            .flatten()
            .filter(|point| point.location == location)
        {
            point_count += 1;
            let has_incoming = facts.expression_control_flow_edges
                [..facts.expression_control_flow_edge_count]
                .iter()
                .flatten()
                .any(|edge| edge.to == point.id);
            if !has_incoming && root.replace(point.id).is_some() {
                return Err(CodegenError {
                    kind: CodegenErrorKind::InvalidRuntimeControlFlowFacts,
                    span: fallback_span,
                });
            }
        }
        let root = root.ok_or(CodegenError {
            kind: CodegenErrorKind::InvalidRuntimeControlFlowFacts,
            span: fallback_span,
        })?;
        let mut processed = 0usize;
        let (result, reached_stop) = walk(
            facts,
            location,
            root,
            None,
            *initialized,
            check_reads,
            fallback_span,
            point_count,
            &mut processed,
            0,
        )?;
        if reached_stop {
            return Err(CodegenError {
                kind: CodegenErrorKind::InvalidRuntimeControlFlowFacts,
                span: fallback_span,
            });
        }
        if processed != point_count {
            return Err(CodegenError {
                kind: CodegenErrorKind::InvalidRuntimeControlFlowFacts,
                span: fallback_span,
            });
        }
        *initialized = result;
        Ok(())
    }

    fn apply_events(
        facts: &RuntimeBodyFacts<'_>,
        point: RuntimeOwnershipControlPoint,
        initialized: &mut [u64; RUNTIME_INITIALIZED_STATE_WORDS],
        check_reads: bool,
        fallback_span: Span,
    ) -> Result<(), CodegenError> {
        let mut initialization_index = 0usize;
        let mut effect_index = 0usize;
        let mut processed_expression_points = [false; MAX_RUNTIME_EXPRESSION_PROGRAM_POINT_FACTS];
        for expected_event in 0..facts.ownership_event_count {
            let initialization = facts
                .initializations
                .get(initialization_index)
                .and_then(|fact| *fact)
                .filter(|fact| fact.event == RuntimeOwnershipEventId(expected_event));
            if let Some(initialization) = initialization {
                if facts.ownership_control_point(initialization.location) == Some(point) {
                    if !facts.ownership_events_single_path
                        && initialization
                            .expression_point
                            .is_some_and(|expression_point| {
                                !processed_expression_points[expression_point.0]
                            })
                    {
                        apply_expression_location(
                            facts,
                            initialization.location,
                            initialized,
                            check_reads,
                            fallback_span,
                        )?;
                        for expression_point in facts.expression_program_points
                            [..facts.expression_program_point_count]
                            .iter()
                            .flatten()
                            .filter(|expression_point| {
                                expression_point.location == initialization.location
                            })
                        {
                            processed_expression_points[expression_point.id.0] = true;
                        }
                    } else if facts.ownership_events_single_path
                        || initialization.expression_point.is_none()
                    {
                        set_path_state(facts, initialized, initialization.path, true).map_err(
                            |kind| CodegenError {
                                kind,
                                span: initialization.span.unwrap_or(fallback_span),
                            },
                        )?;
                    }
                }
                initialization_index += 1;
                continue;
            }
            let effect = facts
                .effects
                .get(effect_index)
                .and_then(|fact| *fact)
                .filter(|fact| fact.event == RuntimeOwnershipEventId(expected_event))
                .ok_or(CodegenError {
                    kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                    span: fallback_span,
                })?;
            if facts.ownership_control_point(effect.location) == Some(point) {
                if !facts.ownership_events_single_path
                    && effect.expression_point.is_some_and(|expression_point| {
                        !processed_expression_points[expression_point.0]
                    })
                {
                    apply_expression_location(
                        facts,
                        effect.location,
                        initialized,
                        check_reads,
                        fallback_span,
                    )?;
                    for expression_point in facts.expression_program_points
                        [..facts.expression_program_point_count]
                        .iter()
                        .flatten()
                        .filter(|expression_point| expression_point.location == effect.location)
                    {
                        processed_expression_points[expression_point.id.0] = true;
                    }
                } else if facts.ownership_events_single_path || effect.expression_point.is_none() {
                    apply_effect(facts, effect, initialized, check_reads)?;
                }
            }
            effect_index += 1;
        }
        if initialization_index != facts.initialization_count || effect_index != facts.effect_count
        {
            return Err(CodegenError {
                kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                span: fallback_span,
            });
        }
        Ok(())
    }

    let mut entry_state = [0; RUNTIME_INITIALIZED_STATE_WORDS];
    apply_events(
        facts,
        RuntimeOwnershipControlPoint::Entry,
        &mut entry_state,
        false,
        fallback_span,
    )?;
    let mut block_inputs =
        [[u64::MAX; RUNTIME_INITIALIZED_STATE_WORDS]; MAX_RUNTIME_BASIC_BLOCK_FACTS];
    let mut block_outputs =
        [[u64::MAX; RUNTIME_INITIALIZED_STATE_WORDS]; MAX_RUNTIME_BASIC_BLOCK_FACTS];
    let convergence_limit = facts
        .basic_block_count
        .checked_mul(facts.move_path_count.max(1))
        .and_then(|value| value.checked_add(1))
        .ok_or(CodegenError {
            kind: CodegenErrorKind::InvalidRuntimeControlFlowFacts,
            span: fallback_span,
        })?;
    let mut converged = false;
    for _ in 0..convergence_limit {
        let mut changed = false;
        for block_index in 0..facts.basic_block_count {
            let block = facts.basic_blocks[block_index].ok_or(CodegenError {
                kind: CodegenErrorKind::InvalidRuntimeControlFlowFacts,
                span: fallback_span,
            })?;
            if block.id.0 != block_index {
                return Err(CodegenError {
                    kind: CodegenErrorKind::InvalidRuntimeControlFlowFacts,
                    span: fallback_span,
                });
            }
            if !block.reachable {
                continue;
            }
            let mut incoming = [u64::MAX; RUNTIME_INITIALIZED_STATE_WORDS];
            let mut has_predecessor = false;
            if block.id == RuntimeBasicBlockId(0) {
                incoming = entry_state;
                has_predecessor = true;
            }
            for (edge_index, edge) in facts.control_flow_edges[..facts.control_flow_edge_count]
                .iter()
                .enumerate()
            {
                let edge = edge.ok_or(CodegenError {
                    kind: CodegenErrorKind::InvalidRuntimeControlFlowFacts,
                    span: fallback_span,
                })?;
                if edge.target != RuntimeControlFlowTarget::Block(block.id) {
                    continue;
                }
                let predecessor = facts
                    .basic_blocks
                    .get(edge.from.0)
                    .and_then(|fact| *fact)
                    .ok_or(CodegenError {
                        kind: CodegenErrorKind::InvalidRuntimeControlFlowFacts,
                        span: fallback_span,
                    })?;
                if !predecessor.reachable {
                    continue;
                }
                let mut edge_state = block_outputs[edge.from.0];
                apply_events(
                    facts,
                    RuntimeOwnershipControlPoint::Edge(edge_index),
                    &mut edge_state,
                    false,
                    fallback_span,
                )?;
                if has_predecessor {
                    for word_index in 0..RUNTIME_INITIALIZED_STATE_WORDS {
                        incoming[word_index] &= edge_state[word_index];
                    }
                } else {
                    incoming = edge_state;
                    has_predecessor = true;
                }
            }
            if !has_predecessor {
                return Err(CodegenError {
                    kind: CodegenErrorKind::InvalidRuntimeControlFlowFacts,
                    span: fallback_span,
                });
            }
            let mut outgoing = incoming;
            apply_events(
                facts,
                RuntimeOwnershipControlPoint::Block(block.id),
                &mut outgoing,
                false,
                fallback_span,
            )?;
            if block_inputs[block_index] != incoming || block_outputs[block_index] != outgoing {
                block_inputs[block_index] = incoming;
                block_outputs[block_index] = outgoing;
                changed = true;
            }
        }
        if !changed {
            converged = true;
            break;
        }
    }
    if !converged {
        return Err(CodegenError {
            kind: CodegenErrorKind::InvalidRuntimeControlFlowFacts,
            span: fallback_span,
        });
    }

    for (block_index, input) in block_inputs[..facts.basic_block_count].iter().enumerate() {
        let block = facts.basic_blocks[block_index].ok_or(CodegenError {
            kind: CodegenErrorKind::InvalidRuntimeControlFlowFacts,
            span: fallback_span,
        })?;
        if !block.reachable {
            continue;
        }
        let mut state = *input;
        apply_events(
            facts,
            RuntimeOwnershipControlPoint::Block(block.id),
            &mut state,
            true,
            fallback_span,
        )?;
    }
    for (edge_index, edge) in facts.control_flow_edges[..facts.control_flow_edge_count]
        .iter()
        .enumerate()
    {
        let edge = edge.ok_or(CodegenError {
            kind: CodegenErrorKind::InvalidRuntimeControlFlowFacts,
            span: fallback_span,
        })?;
        let predecessor = facts
            .basic_blocks
            .get(edge.from.0)
            .and_then(|fact| *fact)
            .ok_or(CodegenError {
                kind: CodegenErrorKind::InvalidRuntimeControlFlowFacts,
                span: fallback_span,
            })?;
        if predecessor.reachable {
            let mut state = block_outputs[edge.from.0];
            apply_events(
                facts,
                RuntimeOwnershipControlPoint::Edge(edge_index),
                &mut state,
                true,
                fallback_span,
            )?;
        }
    }
    Ok(())
}

fn runtime_ownership_point_index(
    facts: &RuntimeBodyFacts<'_>,
    point: RuntimeOwnershipControlPoint,
) -> Option<usize> {
    match point {
        RuntimeOwnershipControlPoint::Entry => Some(0),
        RuntimeOwnershipControlPoint::Block(block) if block.0 < facts.basic_block_count => {
            Some(1 + block.0)
        }
        RuntimeOwnershipControlPoint::Edge(edge) if edge < facts.control_flow_edge_count => {
            Some(1 + facts.basic_block_count + edge)
        }
        RuntimeOwnershipControlPoint::Block(_)
        | RuntimeOwnershipControlPoint::Edge(_)
        | RuntimeOwnershipControlPoint::Unreachable => None,
    }
}

fn runtime_ownership_point_reaches_avoiding(
    facts: &RuntimeBodyFacts<'_>,
    from: RuntimeOwnershipControlPoint,
    to: RuntimeOwnershipControlPoint,
    blocked: &[bool; MAX_RUNTIME_OWNERSHIP_CONTROL_POINTS],
) -> bool {
    fn push_point<const N: usize>(
        index: usize,
        visited: &mut [bool; N],
        pending: &mut [usize; N],
        pending_count: &mut usize,
    ) {
        if !visited[index] {
            visited[index] = true;
            pending[*pending_count] = index;
            *pending_count += 1;
        }
    }

    let Some(target) = runtime_ownership_point_index(facts, to) else {
        return false;
    };
    if blocked[target] {
        return false;
    }
    let mut visited = *blocked;
    let mut pending = [0usize; MAX_RUNTIME_OWNERSHIP_CONTROL_POINTS];
    let mut pending_count = 0usize;
    match from {
        RuntimeOwnershipControlPoint::Entry if facts.basic_block_count != 0 => {
            push_point(1, &mut visited, &mut pending, &mut pending_count);
        }
        RuntimeOwnershipControlPoint::Block(block) => {
            for (edge_index, edge) in facts.control_flow_edges[..facts.control_flow_edge_count]
                .iter()
                .enumerate()
            {
                if edge.is_some_and(|edge| edge.from == block) {
                    push_point(
                        1 + facts.basic_block_count + edge_index,
                        &mut visited,
                        &mut pending,
                        &mut pending_count,
                    );
                }
            }
        }
        RuntimeOwnershipControlPoint::Edge(edge_index) => {
            if let Some(RuntimeControlFlowEdgeFact {
                target: RuntimeControlFlowTarget::Block(block),
                ..
            }) = facts
                .control_flow_edges
                .get(edge_index)
                .and_then(|edge| *edge)
            {
                push_point(1 + block.0, &mut visited, &mut pending, &mut pending_count);
            }
        }
        RuntimeOwnershipControlPoint::Entry | RuntimeOwnershipControlPoint::Unreachable => {}
    }
    let mut cursor = 0usize;
    while cursor < pending_count {
        let current = pending[cursor];
        cursor += 1;
        if current == target {
            return true;
        }
        if current == 0 {
            if facts.basic_block_count != 0 {
                push_point(1, &mut visited, &mut pending, &mut pending_count);
            }
        } else if current <= facts.basic_block_count {
            let block = RuntimeBasicBlockId(current - 1);
            for (edge_index, edge) in facts.control_flow_edges[..facts.control_flow_edge_count]
                .iter()
                .enumerate()
            {
                if edge.is_some_and(|edge| edge.from == block) {
                    push_point(
                        1 + facts.basic_block_count + edge_index,
                        &mut visited,
                        &mut pending,
                        &mut pending_count,
                    );
                }
            }
        } else {
            let edge_index = current - 1 - facts.basic_block_count;
            if let Some(RuntimeControlFlowEdgeFact {
                target: RuntimeControlFlowTarget::Block(block),
                ..
            }) = facts
                .control_flow_edges
                .get(edge_index)
                .and_then(|edge| *edge)
            {
                push_point(1 + block.0, &mut visited, &mut pending, &mut pending_count);
            }
        }
    }
    false
}

fn runtime_ownership_point_reaches(
    facts: &RuntimeBodyFacts<'_>,
    from: RuntimeOwnershipControlPoint,
    to: RuntimeOwnershipControlPoint,
) -> bool {
    runtime_ownership_point_reaches_avoiding(
        facts,
        from,
        to,
        &[false; MAX_RUNTIME_OWNERSHIP_CONTROL_POINTS],
    )
}

fn runtime_ownership_event_precedes(
    facts: &RuntimeBodyFacts<'_>,
    earlier: RuntimePlaceEffectFact,
    later: RuntimePlaceEffectFact,
) -> bool {
    let (Some(earlier_point), Some(later_point)) = (
        facts.ownership_control_point(earlier.location),
        facts.ownership_control_point(later.location),
    ) else {
        return false;
    };
    if earlier_point == later_point && earlier.event.0 < later.event.0 {
        return true;
    }
    runtime_ownership_point_reaches(facts, earlier_point, later_point)
}

fn runtime_ownership_position_precedes(
    facts: &RuntimeBodyFacts<'_>,
    earlier_event: RuntimeOwnershipEventId,
    earlier_location: RuntimeOwnershipEventLocation,
    later_event: RuntimeOwnershipEventId,
    later_location: RuntimeOwnershipEventLocation,
) -> bool {
    let (Some(earlier_point), Some(later_point)) = (
        facts.ownership_control_point(earlier_location),
        facts.ownership_control_point(later_location),
    ) else {
        return false;
    };
    if earlier_point == later_point {
        return earlier_event.0 < later_event.0;
    }
    runtime_ownership_point_reaches(facts, earlier_point, later_point)
}

fn runtime_effect_uses_loan(kind: RuntimePlaceEffectKind) -> bool {
    matches!(
        kind,
        RuntimePlaceEffectKind::LoanUse | RuntimePlaceEffectKind::LoanMutation
    )
}

fn runtime_specific_loan_is_active_at_effect(
    facts: &RuntimeBodyFacts<'_>,
    loan: RuntimeLoanFact,
    effect: RuntimePlaceEffectFact,
) -> bool {
    let Some((generation_event, generation_location)) = facts.direct_loan_generation_position(loan)
    else {
        return false;
    };
    if !runtime_ownership_position_precedes(
        facts,
        generation_event,
        generation_location,
        effect.event,
        effect.location,
    ) {
        return false;
    }
    let (Some(generation_point), Some(effect_point)) = (
        facts.ownership_control_point(generation_location),
        facts.ownership_control_point(effect.location),
    ) else {
        return false;
    };
    let mut blocked = [false; MAX_RUNTIME_OWNERSHIP_CONTROL_POINTS];
    for replacement in (0..facts.initialization_count)
        .filter_map(|index| facts.direct_loan_fact(index))
        .chain((0..facts.effect_count).filter_map(|index| facts.direct_assigned_loan_fact(index)))
        .chain((0..facts.effect_count).filter_map(|index| facts.direct_expression_loan_fact(index)))
        .chain((0..facts.initialization_count).flat_map(|move_depth| {
            (0..facts.effect_count).filter_map(move |index| {
                facts.moved_expression_loan_fact_at_depth(index, move_depth)
            })
        }))
        .chain((0..facts.effect_count).flat_map(|replacement_depth| {
            (0..facts.initialization_count).filter_map(move |index| {
                facts.moved_replaced_projected_loan_fact_at_depth(index, replacement_depth)
            })
        }))
        .filter(|replacement| {
            replacement.borrower == loan.borrower
                && replacement.generation_event != loan.generation_event
        })
    {
        let Some((replacement_event, replacement_location)) =
            facts.direct_loan_generation_position(replacement)
        else {
            return false;
        };
        if !runtime_ownership_position_precedes(
            facts,
            generation_event,
            generation_location,
            replacement_event,
            replacement_location,
        ) || !runtime_ownership_position_precedes(
            facts,
            replacement_event,
            replacement_location,
            effect.event,
            effect.location,
        ) {
            continue;
        }
        let Some(replacement_point) = facts.ownership_control_point(replacement_location) else {
            return false;
        };
        if replacement_point == generation_point || replacement_point == effect_point {
            return false;
        }
        let Some(index) = runtime_ownership_point_index(facts, replacement_point) else {
            return false;
        };
        blocked[index] = true;
    }
    generation_point == effect_point
        || runtime_ownership_point_reaches_avoiding(facts, generation_point, effect_point, &blocked)
}

fn runtime_effect_uses_specific_loan(
    facts: &RuntimeBodyFacts<'_>,
    loan: RuntimeLoanFact,
    effect: RuntimePlaceEffectFact,
) -> bool {
    runtime_effect_uses_loan(effect.kind)
        && runtime_specific_loan_is_active_at_effect(facts, loan, effect)
}

fn runtime_effect_reaches_specific_loan_use(
    facts: &RuntimeBodyFacts<'_>,
    loan: RuntimeLoanFact,
    earlier: RuntimePlaceEffectFact,
    later: RuntimePlaceEffectFact,
) -> bool {
    if !runtime_effect_uses_specific_loan(facts, loan, later)
        || !runtime_ownership_event_precedes(facts, earlier, later)
    {
        return false;
    }
    if later.event.0 < earlier.event.0 && loan.generation_event.0 <= later.event.0 {
        return false;
    }
    let (Some(earlier_point), Some(later_point)) = (
        facts.ownership_control_point(earlier.location),
        facts.ownership_control_point(later.location),
    ) else {
        return false;
    };
    let mut blocked = [false; MAX_RUNTIME_OWNERSHIP_CONTROL_POINTS];
    let Some((_, generation_location)) = facts.direct_loan_generation_position(loan) else {
        return false;
    };
    let Some(generation_point) = facts.ownership_control_point(generation_location) else {
        return false;
    };
    if generation_point != earlier_point && generation_point != later_point {
        let Some(index) = runtime_ownership_point_index(facts, generation_point) else {
            return false;
        };
        blocked[index] = true;
    }
    for replacement in (0..facts.initialization_count)
        .filter_map(|index| facts.direct_loan_fact(index))
        .chain((0..facts.effect_count).filter_map(|index| facts.direct_assigned_loan_fact(index)))
        .chain((0..facts.effect_count).filter_map(|index| facts.direct_expression_loan_fact(index)))
        .chain((0..facts.initialization_count).flat_map(|move_depth| {
            (0..facts.effect_count).filter_map(move |index| {
                facts.moved_expression_loan_fact_at_depth(index, move_depth)
            })
        }))
        .chain((0..facts.effect_count).flat_map(|replacement_depth| {
            (0..facts.initialization_count).filter_map(move |index| {
                facts.moved_replaced_projected_loan_fact_at_depth(index, replacement_depth)
            })
        }))
        .filter(|replacement| {
            replacement.borrower == loan.borrower
                && replacement.generation_event != loan.generation_event
        })
    {
        let Some((replacement_event, replacement_location)) =
            facts.direct_loan_generation_position(replacement)
        else {
            return false;
        };
        if !runtime_ownership_position_precedes(
            facts,
            earlier.event,
            earlier.location,
            replacement_event,
            replacement_location,
        ) || !runtime_ownership_position_precedes(
            facts,
            replacement_event,
            replacement_location,
            later.event,
            later.location,
        ) {
            continue;
        }
        let Some(replacement_point) = facts.ownership_control_point(replacement_location) else {
            return false;
        };
        if replacement_point == earlier_point || replacement_point == later_point {
            return false;
        }
        let Some(index) = runtime_ownership_point_index(facts, replacement_point) else {
            return false;
        };
        blocked[index] = true;
    }
    earlier_point == later_point
        || runtime_ownership_point_reaches_avoiding(facts, earlier_point, later_point, &blocked)
}

fn runtime_loan_may_borrow_path(
    facts: &RuntimeBodyFacts<'_>,
    loan: RuntimeLoanFact,
    target: RuntimeMovePathId,
    include_intermediate: bool,
    depth: usize,
) -> Option<bool> {
    if depth > facts.initialization_count.checked_add(facts.effect_count)? {
        return None;
    }
    let target_path = facts.move_paths.get(target.0).and_then(|path| *path)?;
    if target_path.base == RuntimePlaceIdentity::Local(loan.borrower)
        && target_path.projections == RuntimePlaceProjections::EMPTY
    {
        return Some(false);
    }
    if include_intermediate
        && runtime_move_path_is_ancestor_or_same(facts, target, loan.borrowed_path)?
    {
        return Some(true);
    }
    let path = facts
        .move_paths
        .get(loan.borrowed_path.0)
        .and_then(|path| *path)?;
    let issue = facts
        .effects
        .get(loan.issue_effect)
        .and_then(|effect| *effect)?;
    if path.projections.count != 0 {
        if loan.borrowed_path == target {
            return Some(true);
        }
        for generation_index in facts.effects[..facts.effect_count]
            .iter()
            .enumerate()
            .filter_map(|(index, effect)| effect.map(|effect| (index, effect)))
            .filter(|(_, effect)| {
                effect.path == loan.borrowed_path
                    && effect.kind == RuntimePlaceEffectKind::Write
                    && effect.event.0 < issue.event.0
            })
            .map(|(index, _)| index)
        {
            if let Some(origin) = facts
                .direct_tuple_field_assigned_loan_origin_at(generation_index)
                .or_else(|| facts.direct_tuple_field_assigned_value_origin_at(generation_index))
                && runtime_loan_may_borrow_path(
                    facts,
                    origin,
                    target,
                    include_intermediate,
                    depth + 1,
                )?
            {
                return Some(true);
            }
        }
        if let Some(root) = path.parent {
            let initialization = facts.initializations[..facts.initialization_count]
                .iter()
                .flatten()
                .filter(|initialization| {
                    initialization.path == root && initialization.event.0 < issue.event.0
                })
                .max_by_key(|initialization| initialization.event.0)?;
            let initialization_end =
                RuntimeOwnershipEventId(initialization.event.0.checked_add(1)?);
            for origin in [
                facts.direct_tuple_field_loan_origin_before(loan.borrowed_path, initialization_end),
                facts
                    .direct_tuple_field_value_origin_before(loan.borrowed_path, initialization_end),
            ]
            .into_iter()
            .flatten()
            {
                if runtime_loan_may_borrow_path(
                    facts,
                    origin,
                    target,
                    include_intermediate,
                    depth + 1,
                )? {
                    return Some(true);
                }
            }
        }
        return Some(false);
    }
    let RuntimePlaceIdentity::Local(parent_borrower) = path.base else {
        return Some(loan.borrowed_path == target);
    };
    let mut found_parent = false;
    for parent in (0..facts.initialization_count)
        .filter_map(|index| facts.direct_loan_fact(index))
        .chain((0..facts.effect_count).filter_map(|index| facts.direct_assigned_loan_fact(index)))
        .chain((0..facts.effect_count).filter_map(|index| facts.direct_expression_loan_fact(index)))
        .chain((0..facts.initialization_count).flat_map(|move_depth| {
            (0..facts.effect_count).filter_map(move |index| {
                facts.moved_expression_loan_fact_at_depth(index, move_depth)
            })
        }))
        .chain((0..facts.effect_count).flat_map(|replacement_depth| {
            (0..facts.initialization_count).filter_map(move |index| {
                facts.moved_replaced_projected_loan_fact_at_depth(index, replacement_depth)
            })
        }))
        .filter(|parent| {
            parent.borrower == parent_borrower
                && runtime_specific_loan_is_active_at_effect(facts, *parent, issue)
        })
    {
        found_parent = true;
        if runtime_loan_may_borrow_path(facts, parent, target, include_intermediate, depth + 1)? {
            return Some(true);
        }
    }
    Some(!found_parent && loan.borrowed_path == target)
}

fn runtime_move_path_is_ancestor_or_same(
    facts: &RuntimeBodyFacts<'_>,
    ancestor: RuntimeMovePathId,
    descendant: RuntimeMovePathId,
) -> Option<bool> {
    let mut current = Some(descendant);
    for _ in 0..=facts.move_path_count {
        let Some(path) = current else {
            return Some(false);
        };
        if path == ancestor {
            return Some(true);
        }
        current = facts.move_paths.get(path.0).and_then(|fact| *fact)?.parent;
    }
    None
}

fn validate_runtime_bounded_direct_loan_liveness(
    facts: &RuntimeBodyFacts<'_>,
    fallback_span: Span,
) -> Result<(), CodegenError> {
    if !facts.control_flow_complete {
        return Ok(());
    }
    for generation_index in 0..facts
        .initialization_count
        .checked_add(facts.effect_count)
        .and_then(|count| count.checked_add(facts.effect_count))
        .and_then(|count| {
            facts
                .initialization_count
                .checked_mul(facts.effect_count)
                .and_then(|moved| count.checked_add(moved))
        })
        .and_then(|count| {
            facts
                .initialization_count
                .checked_mul(facts.effect_count)
                .and_then(|replaced| count.checked_add(replaced))
        })
        .ok_or(CodegenError {
            kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
            span: fallback_span,
        })?
    {
        let assigned_start = facts.initialization_count;
        let expression_start = assigned_start + facts.effect_count;
        let moved_expression_start = expression_start + facts.effect_count;
        let replaced_projected_start =
            moved_expression_start + facts.initialization_count * facts.effect_count;
        let loan = if generation_index < assigned_start {
            facts.direct_loan_fact(generation_index)
        } else if generation_index < expression_start {
            facts.direct_assigned_loan_fact(generation_index - assigned_start)
        } else if generation_index < moved_expression_start {
            facts.direct_expression_loan_fact(generation_index - expression_start)
        } else if generation_index < replaced_projected_start {
            let moved_index = generation_index - moved_expression_start;
            let move_depth = moved_index / facts.effect_count;
            let effect_index = moved_index % facts.effect_count;
            facts.moved_expression_loan_fact_at_depth(effect_index, move_depth)
        } else {
            let replaced_index = generation_index - replaced_projected_start;
            let replacement_depth = replaced_index / facts.initialization_count;
            let initialization_index = replaced_index % facts.initialization_count;
            facts.moved_replaced_projected_loan_fact_at_depth(
                initialization_index,
                replacement_depth,
            )
        };
        let Some(loan) = loan else {
            continue;
        };
        let issue = facts
            .effects
            .get(loan.issue_effect)
            .and_then(|effect| *effect)
            .ok_or(CodegenError {
                kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                span: fallback_span,
            })?;
        let borrower_path = facts
            .find_move_path(
                RuntimePlaceIdentity::Local(loan.borrower),
                RuntimePlaceProjections::EMPTY,
            )
            .ok_or(CodegenError {
                kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                span: fallback_span,
            })?;
        let direct_borrowed = facts
            .move_paths
            .get(loan.borrowed_path.0)
            .and_then(|path| *path)
            .ok_or(CodegenError {
                kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                span: fallback_span,
            })?;
        let parent_borrower = (direct_borrowed.projections.count == 0)
            .then_some(direct_borrowed.base)
            .and_then(|base| match base {
                RuntimePlaceIdentity::Local(parent) => Some(parent),
                RuntimePlaceIdentity::Parameter(_) => None,
            });
        for parent in (0..facts.initialization_count)
            .filter_map(|index| facts.direct_loan_fact(index))
            .chain(
                (0..facts.effect_count).filter_map(|index| facts.direct_assigned_loan_fact(index)),
            )
            .chain(
                (0..facts.effect_count)
                    .filter_map(|index| facts.direct_expression_loan_fact(index)),
            )
            .chain((0..facts.initialization_count).flat_map(|move_depth| {
                (0..facts.effect_count).filter_map(move |index| {
                    facts.moved_expression_loan_fact_at_depth(index, move_depth)
                })
            }))
            .chain((0..facts.effect_count).flat_map(|replacement_depth| {
                (0..facts.initialization_count).filter_map(move |index| {
                    facts.moved_replaced_projected_loan_fact_at_depth(index, replacement_depth)
                })
            }))
            .filter(|parent| {
                parent_borrower == Some(parent.borrower)
                    && parent.kind == RuntimePlaceEffectKind::MutableBorrow
                    && runtime_specific_loan_is_active_at_effect(facts, *parent, issue)
            })
        {
            let parent_path = facts
                .find_move_path(
                    RuntimePlaceIdentity::Local(parent.borrower),
                    RuntimePlaceProjections::EMPTY,
                )
                .ok_or(CodegenError {
                    kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                    span: fallback_span,
                })?;
            for parent_use in
                facts.effects[..facts.effect_count]
                    .iter()
                    .flatten()
                    .filter(|effect| {
                        effect.path == parent_path
                            && match loan.kind {
                                RuntimePlaceEffectKind::MutableBorrow => {
                                    runtime_effect_uses_specific_loan(facts, parent, **effect)
                                }
                                RuntimePlaceEffectKind::SharedBorrow => {
                                    effect.kind == RuntimePlaceEffectKind::LoanMutation
                                        && runtime_effect_uses_specific_loan(
                                            facts, parent, **effect,
                                        )
                                }
                                RuntimePlaceEffectKind::Copy
                                | RuntimePlaceEffectKind::Move
                                | RuntimePlaceEffectKind::LoanUse
                                | RuntimePlaceEffectKind::LoanMutation
                                | RuntimePlaceEffectKind::Write
                                | RuntimePlaceEffectKind::ReadModifyWrite => false,
                            }
                            && runtime_ownership_event_precedes(facts, issue, **effect)
                    })
            {
                let child_used_later =
                    facts.effects[..facts.effect_count]
                        .iter()
                        .flatten()
                        .any(|effect| {
                            effect.path == borrower_path
                                && runtime_effect_reaches_specific_loan_use(
                                    facts,
                                    loan,
                                    *parent_use,
                                    *effect,
                                )
                        });
                if child_used_later {
                    return Err(CodegenError {
                        kind: CodegenErrorKind::RuntimeBorrowConflict,
                        span: parent_use.span,
                    });
                }
            }
        }
        for (conflict_index, conflict) in facts.effects[..facts.effect_count]
            .iter()
            .enumerate()
            .filter_map(|(index, effect)| effect.map(|effect| (index, effect)))
        {
            let sibling_origin = facts
                .direct_expression_loan_fact(conflict_index)
                .is_some_and(|sibling| {
                    sibling.borrower == loan.borrower
                        && sibling.generation_event == loan.generation_event
                });
            let conflicts_with_loan = match loan.kind {
                RuntimePlaceEffectKind::SharedBorrow => matches!(
                    conflict.kind,
                    RuntimePlaceEffectKind::Move
                        | RuntimePlaceEffectKind::MutableBorrow
                        | RuntimePlaceEffectKind::Write
                        | RuntimePlaceEffectKind::ReadModifyWrite
                        | RuntimePlaceEffectKind::LoanMutation
                ),
                RuntimePlaceEffectKind::MutableBorrow => matches!(
                    conflict.kind,
                    RuntimePlaceEffectKind::Copy
                        | RuntimePlaceEffectKind::Move
                        | RuntimePlaceEffectKind::SharedBorrow
                        | RuntimePlaceEffectKind::MutableBorrow
                        | RuntimePlaceEffectKind::Write
                        | RuntimePlaceEffectKind::ReadModifyWrite
                        | RuntimePlaceEffectKind::LoanMutation
                ),
                RuntimePlaceEffectKind::Copy
                | RuntimePlaceEffectKind::Move
                | RuntimePlaceEffectKind::LoanUse
                | RuntimePlaceEffectKind::LoanMutation
                | RuntimePlaceEffectKind::Write
                | RuntimePlaceEffectKind::ReadModifyWrite => false,
            };
            if conflict.event == issue.event
                || sibling_origin
                || !conflicts_with_loan
                || !runtime_ownership_event_precedes(facts, issue, conflict)
                || !runtime_loan_may_borrow_path(
                    facts,
                    loan,
                    conflict.path,
                    matches!(
                        conflict.kind,
                        RuntimePlaceEffectKind::Move
                            | RuntimePlaceEffectKind::SharedBorrow
                            | RuntimePlaceEffectKind::MutableBorrow
                            | RuntimePlaceEffectKind::LoanMutation
                    ),
                    0,
                )
                .ok_or(CodegenError {
                    kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                    span: fallback_span,
                })?
            {
                continue;
            }
            let used_after_conflict =
                facts.effects[..facts.effect_count]
                    .iter()
                    .flatten()
                    .any(|effect| {
                        effect.path == borrower_path
                            && runtime_effect_reaches_specific_loan_use(
                                facts, loan, conflict, *effect,
                            )
                    });
            if used_after_conflict {
                return Err(CodegenError {
                    kind: CodegenErrorKind::RuntimeBorrowConflict,
                    span: conflict.span,
                });
            }
        }
    }
    Ok(())
}

const fn runtime_location_is_exact_function_return_value(
    location: RuntimeOwnershipEventLocation,
) -> bool {
    matches!(
        location,
        RuntimeOwnershipEventLocation::ConditionalReturnValue { .. }
            | RuntimeOwnershipEventLocation::ConditionalReturnElseValue { .. }
            | RuntimeOwnershipEventLocation::ConditionalAssignmentReturnValue { .. }
            | RuntimeOwnershipEventLocation::LoopConditionalReturnValue { .. }
            | RuntimeOwnershipEventLocation::LoopReturnValue { .. }
            | RuntimeOwnershipEventLocation::LoopConditionalTerminal { .. }
            | RuntimeOwnershipEventLocation::NestedLoopControlValue { .. }
            | RuntimeOwnershipEventLocation::NestedLoopBranchValue { .. }
            | RuntimeOwnershipEventLocation::NestedLoopBranchElseValue { .. }
            | RuntimeOwnershipEventLocation::ReturnValue { .. }
            | RuntimeOwnershipEventLocation::Tail
    )
}

fn runtime_conditional_tuple_field_origins_outlive_function(
    facts: &RuntimeBodyFacts<'_>,
    path_id: RuntimeMovePathId,
    returned_at: RuntimePlaceEffectFact,
    depth: usize,
) -> Option<Option<bool>> {
    let field = facts.move_paths.get(path_id.0).and_then(|path| *path)?;
    let RuntimePlaceProjections {
        items:
            [
                Some(RuntimePlaceProjection::TupleField(field_index)),
                None,
                None,
                None,
            ],
        count: 1,
    } = field.projections
    else {
        return Some(None);
    };
    let root_id = field.parent?;
    let root = facts.move_paths.get(root_id.0).and_then(|path| *path)?;
    let RuntimeExpressionType::Tuple {
        elements,
        element_count,
    } = root.ty
    else {
        return Some(None);
    };
    let RuntimeExpressionType::Reference {
        mutable: target_mutable,
        ..
    } = field.ty
    else {
        return Some(None);
    };
    let mut reference_count = 0usize;
    let mut target_ordinal = None;
    for (index, element) in elements[..element_count].iter().enumerate() {
        if matches!(element, Some(RuntimeTupleElementType::Reference { .. })) {
            if index == field_index {
                target_ordinal = Some(reference_count);
            }
            reference_count = reference_count.checked_add(1)?;
        }
    }
    let target_ordinal = target_ordinal?;
    let initialization = facts.initializations[..facts.initialization_count]
        .iter()
        .flatten()
        .filter(|initialization| {
            initialization.path == root_id && initialization.event.0 < returned_at.event.0
        })
        .max_by_key(|initialization| initialization.event.0)?;
    if facts.effects[..facts.effect_count]
        .iter()
        .flatten()
        .any(|effect| {
            (effect.path == root_id || effect.path == path_id)
                && effect.kind == RuntimePlaceEffectKind::Write
                && effect.event.0 > initialization.event.0
                && effect.event.0 < returned_at.event.0
        })
    {
        return Some(None);
    }
    let mut group_count = 0usize;
    let mut last_conditional = None;
    let mut target_is_conditional = false;
    let mut target_outlives = true;
    for effect in facts.effects[..facts.effect_count]
        .iter()
        .flatten()
        .filter(|effect| {
            effect.event.0 < initialization.event.0
                && effect.location == initialization.location
                && matches!(
                    effect.kind,
                    RuntimePlaceEffectKind::Copy
                        | RuntimePlaceEffectKind::Move
                        | RuntimePlaceEffectKind::SharedBorrow
                        | RuntimePlaceEffectKind::MutableBorrow
                )
                && (matches!(
                    effect.kind,
                    RuntimePlaceEffectKind::SharedBorrow | RuntimePlaceEffectKind::MutableBorrow
                ) || facts
                    .move_paths
                    .get(effect.path.0)
                    .and_then(|path| *path)
                    .is_some_and(|path| matches!(path.ty, RuntimeExpressionType::Reference { .. })))
        })
    {
        let expression_conditional = match effect.expression_conditional {
            Some(mut conditional) => {
                let mut outermost = None;
                for _ in 0..=facts.conditional_expression_count {
                    let fact = facts
                        .conditional_expressions
                        .get(conditional.0)
                        .and_then(|fact| *fact)?;
                    let Some(parent) = fact.parent else {
                        outermost = Some(conditional);
                        break;
                    };
                    conditional = parent;
                }
                Some(outermost?)
            }
            None => None,
        };
        let new_group =
            expression_conditional.is_none() || expression_conditional != last_conditional;
        if new_group {
            group_count = group_count.checked_add(1)?;
        }
        last_conditional = expression_conditional;
        if group_count.checked_sub(1)? != target_ordinal || expression_conditional.is_none() {
            continue;
        }
        target_is_conditional = true;
        let source_mutable = match effect.kind {
            RuntimePlaceEffectKind::SharedBorrow => false,
            RuntimePlaceEffectKind::MutableBorrow => true,
            RuntimePlaceEffectKind::Copy | RuntimePlaceEffectKind::Move => {
                let RuntimeExpressionType::Reference { mutable, .. } = facts
                    .move_paths
                    .get(effect.path.0)
                    .and_then(|path| *path)?
                    .ty
                else {
                    return None;
                };
                mutable
            }
            _ => return None,
        };
        if source_mutable != target_mutable
            || !runtime_path_outlives_function_at_effect(facts, effect.path, *effect, depth + 1)?
        {
            target_outlives = false;
        }
    }
    if group_count != reference_count || !target_is_conditional {
        Some(None)
    } else {
        Some(Some(target_outlives))
    }
}

fn runtime_path_outlives_function_at_effect(
    facts: &RuntimeBodyFacts<'_>,
    path_id: RuntimeMovePathId,
    returned_at: RuntimePlaceEffectFact,
    depth: usize,
) -> Option<bool> {
    if depth > facts.initialization_count.checked_add(facts.effect_count)? {
        return None;
    }
    let path = facts.move_paths.get(path_id.0).and_then(|path| *path)?;
    match path.base {
        RuntimePlaceIdentity::Parameter(_) => Some(true),
        RuntimePlaceIdentity::Local(local) => {
            if path.projections != RuntimePlaceProjections::EMPTY {
                let RuntimeExpressionType::Reference { .. } = path.ty else {
                    return Some(false);
                };
                if let Some(outlives) = runtime_conditional_tuple_field_origins_outlive_function(
                    facts,
                    path_id,
                    returned_at,
                    depth,
                )? {
                    return Some(outlives);
                }
                let latest_write = facts.effects[..facts.effect_count]
                    .iter()
                    .flatten()
                    .filter(|effect| {
                        effect.path == path_id
                            && effect.kind == RuntimePlaceEffectKind::Write
                            && effect.event.0 < returned_at.event.0
                    })
                    .max_by_key(|effect| effect.event.0);
                if let Some(latest_write) = latest_write {
                    for origin in (0..facts.effect_count)
                        .filter_map(|index| facts.direct_expression_loan_fact(index))
                        .filter(|origin| {
                            origin.borrower == local
                                && origin.generation_event == latest_write.event
                        })
                    {
                        let issue = facts
                            .effects
                            .get(origin.issue_effect)
                            .and_then(|effect| *effect)?;
                        if !runtime_path_outlives_function_at_effect(
                            facts,
                            origin.borrowed_path,
                            issue,
                            depth + 1,
                        )? {
                            return Some(false);
                        }
                    }
                }
                for (index, write) in facts.effects[..facts.effect_count]
                    .iter()
                    .enumerate()
                    .filter_map(|(index, effect)| effect.map(|effect| (index, effect)))
                    .filter(|(_, effect)| {
                        effect.path == path_id
                            && effect.kind == RuntimePlaceEffectKind::Write
                            && effect.event.0 < returned_at.event.0
                            && facts
                                .ownership_control_point(effect.location)
                                .is_some_and(|point| {
                                    point == RuntimeOwnershipControlPoint::Entry
                                        || runtime_ownership_point_reaches(
                                            facts,
                                            RuntimeOwnershipControlPoint::Entry,
                                            point,
                                        )
                                })
                    })
                {
                    if !runtime_ownership_position_precedes(
                        facts,
                        write.event,
                        write.location,
                        returned_at.event,
                        returned_at.location,
                    ) {
                        continue;
                    }
                    if (0..facts.effect_count)
                        .filter_map(|effect_index| facts.direct_expression_loan_fact(effect_index))
                        .any(|origin| {
                            origin.borrower == local && origin.generation_event == write.event
                        })
                    {
                        continue;
                    }
                    let origin = facts
                        .direct_tuple_field_assigned_loan_origin_at(index)
                        .or_else(|| facts.direct_tuple_field_assigned_value_origin_at(index))?;
                    let issue = facts
                        .effects
                        .get(origin.issue_effect)
                        .and_then(|effect| *effect)?;
                    if !runtime_path_outlives_function_at_effect(
                        facts,
                        origin.borrowed_path,
                        issue,
                        depth + 1,
                    )? {
                        return Some(false);
                    }
                }
                let root_id = path.parent?;
                let initialization = facts.initializations[..facts.initialization_count]
                    .iter()
                    .flatten()
                    .filter(|initialization| {
                        initialization.path == root_id
                            && initialization.event.0 < returned_at.event.0
                    })
                    .max_by_key(|initialization| initialization.event.0)?;
                let initialization_end =
                    RuntimeOwnershipEventId(initialization.event.0.checked_add(1)?);
                let origin = facts
                    .direct_tuple_field_loan_origin_before(path_id, initialization_end)
                    .or_else(|| {
                        facts.direct_tuple_field_value_origin_before(path_id, initialization_end)
                    })?;
                let issue = facts
                    .effects
                    .get(origin.issue_effect)
                    .and_then(|effect| *effect)?;
                let initialization_outlives = runtime_path_outlives_function_at_effect(
                    facts,
                    origin.borrowed_path,
                    issue,
                    depth + 1,
                )?;
                return Some(initialization_outlives);
            }
            let RuntimeExpressionType::Reference { .. } = path.ty else {
                return Some(false);
            };
            let mut found = false;
            for loan in (0..facts.initialization_count)
                .filter_map(|index| facts.direct_loan_fact(index))
                .chain(
                    (0..facts.effect_count)
                        .filter_map(|index| facts.direct_assigned_loan_fact(index)),
                )
                .chain(
                    (0..facts.effect_count)
                        .filter_map(|index| facts.direct_expression_loan_fact(index)),
                )
                .chain((0..facts.initialization_count).flat_map(|move_depth| {
                    (0..facts.effect_count).filter_map(move |index| {
                        facts.moved_expression_loan_fact_at_depth(index, move_depth)
                    })
                }))
                .chain((0..facts.effect_count).flat_map(|replacement_depth| {
                    (0..facts.initialization_count).filter_map(move |index| {
                        facts.moved_replaced_projected_loan_fact_at_depth(index, replacement_depth)
                    })
                }))
                .filter(|loan| {
                    loan.borrower == local
                        && runtime_specific_loan_is_active_at_effect(facts, *loan, returned_at)
                })
            {
                found = true;
                let issue = facts
                    .effects
                    .get(loan.issue_effect)
                    .and_then(|effect| *effect)?;
                if !runtime_path_outlives_function_at_effect(
                    facts,
                    loan.borrowed_path,
                    issue,
                    depth + 1,
                )? {
                    return Some(false);
                }
            }
            if found {
                Some(true)
            } else if let Some((source, moved_at)) =
                facts.direct_reference_value_source_before(local, returned_at.event)
            {
                runtime_path_outlives_function_at_effect(facts, source, moved_at, depth + 1)
            } else {
                Some(false)
            }
        }
    }
}

fn validate_runtime_function_return_outlives(
    facts: &RuntimeBodyFacts<'_>,
    fallback_span: Span,
) -> Result<(), CodegenError> {
    if !facts.control_flow_complete {
        return Ok(());
    }
    for returned in facts.effects[..facts.effect_count]
        .iter()
        .flatten()
        .filter(|effect| {
            runtime_location_is_exact_function_return_value(effect.location)
                && (matches!(
                    effect.kind,
                    RuntimePlaceEffectKind::SharedBorrow | RuntimePlaceEffectKind::MutableBorrow
                ) || (matches!(
                    effect.kind,
                    RuntimePlaceEffectKind::Copy | RuntimePlaceEffectKind::Move
                ) && facts
                    .move_paths
                    .get(effect.path.0)
                    .and_then(|path| *path)
                    .is_some_and(|path| {
                        matches!(path.ty, RuntimeExpressionType::Reference { .. })
                    })))
        })
    {
        if !runtime_path_outlives_function_at_effect(facts, returned.path, *returned, 0).ok_or(
            CodegenError {
                kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                span: fallback_span,
            },
        )? {
            return Err(CodegenError {
                kind: CodegenErrorKind::RuntimeReferenceOutlivesFunction,
                span: returned.span,
            });
        }
    }
    Ok(())
}

fn preanalyze_runtime_body_declarations<
    'source,
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    function: &Function<'source, MAX_PARAMETERS>,
    resolver: &R,
    body: &crate::FunctionBody<'source, MAX_PARAMETERS>,
    operand_type: &str,
    body_start: usize,
    facts: &mut RuntimeBodyFacts<'source>,
) -> Result<usize, CodegenError> {
    facts.ownership_statement_count = body.statement_count();
    let tail_diverges = x86_64_body_tail_diverges(body);
    facts.ownership_has_tail = !tail_diverges && !body.tail_expression.is_empty();
    facts
        .record_ownership_statement_shapes(body)
        .map_err(|kind| CodegenError {
            kind,
            span: body.tail_span,
        })?;
    for (index, parameter) in function.parameters().iter().enumerate() {
        let Some(parameter) = parameter else {
            continue;
        };
        let ty = runtime_type_from_text(parameter.ty.text).ok_or(CodegenError {
            kind: CodegenErrorKind::UnsupportedParameterType,
            span: parameter.ty.span,
        })?;
        facts
            .push_initialized_parameter(index, ty, Some(parameter.span))
            .map_err(|kind| CodegenError {
                kind,
                span: parameter.span,
            })?;
    }
    let mut locals: [Option<RuntimeLocal<'source>>; MAX_PARAMETERS] = [None; MAX_PARAMETERS];
    let mut local_count = 0usize;
    let mut saw_loop = false;
    for (statement_index, statement) in body.statements().iter().flatten().enumerate() {
        if matches!(statement, crate::BodyStatement::Loop(_)) {
            saw_loop = true;
            break;
        }
        facts.current_ownership_event_location =
            RuntimeOwnershipEventLocation::TopLevelStatement(statement_index);
        preanalyze_runtime_top_level_statement::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
            function,
            resolver,
            body,
            *statement,
            statement_index,
            operand_type,
            body_start,
            facts,
            &mut locals,
            &mut local_count,
        )?;
    }
    for (statement_index, statement) in body.statements().iter().flatten().enumerate() {
        if let crate::BodyStatement::Loop(index) = statement {
            let loop_statement = body
                .while_loops()
                .get(*index)
                .and_then(|value| *value)
                .ok_or(CodegenError {
                    kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
                    span: body.tail_span,
                })?;
            facts.current_ownership_event_location =
                RuntimeOwnershipEventLocation::TopLevelStatement(statement_index);
            preanalyze_runtime_loop_declarations::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
                function,
                resolver,
                &loop_statement,
                operand_type,
                body_start,
                facts,
                &locals,
                local_count,
                statement_index,
            )?;
        }
    }
    if saw_loop {
        let mut after_first_loop = false;
        for (statement_index, statement) in body.statements().iter().flatten().enumerate() {
            if matches!(statement, crate::BodyStatement::Loop(_)) {
                after_first_loop = true;
                continue;
            }
            if after_first_loop {
                facts.current_ownership_event_location =
                    RuntimeOwnershipEventLocation::TopLevelStatement(statement_index);
                preanalyze_runtime_top_level_statement::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
                    function,
                    resolver,
                    body,
                    *statement,
                    statement_index,
                    operand_type,
                    body_start,
                    facts,
                    &mut locals,
                    &mut local_count,
                )?;
            }
        }
    }
    if !tail_diverges && !body.tail_expression.is_empty() {
        facts.current_ownership_event_location = RuntimeOwnershipEventLocation::Tail;
        preanalyze_runtime_return_expression_reads::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
            facts,
            &locals[..local_count],
            function,
            resolver,
            body.tail_expression,
            body.tail_span,
            body_start,
        )?;
    }
    if facts.current_ownership_expression_path != RuntimeOwnershipExpressionPath::ROOT
        || facts.current_conditional_expression.is_some()
        || facts.pending_loan_generation_borrower.is_some()
        || facts.current_loan_generation_borrower.is_some()
    {
        return Err(CodegenError {
            kind: CodegenErrorKind::InvalidRuntimePlaceFacts,
            span: body.tail_span,
        });
    }
    facts.current_ownership_event_location = RuntimeOwnershipEventLocation::EmissionExpansion;
    preanalyze_runtime_body_control_flow(body, facts).map_err(|kind| CodegenError {
        kind,
        span: body.tail_span,
    })?;
    facts
        .build_expression_control_flow()
        .map_err(|kind| CodegenError {
            kind,
            span: body.tail_span,
        })?;
    validate_runtime_initializedness(facts, body.tail_span)?;
    validate_runtime_bounded_direct_loan_liveness(facts, body.tail_span)?;
    if function
        .return_type
        .and_then(|return_type| runtime_reference_type(return_type.text))
        .is_some()
    {
        validate_runtime_function_return_outlives(facts, body.tail_span)?;
    }
    Ok(facts.local_count)
}

fn runtime_place_projected_type(
    mut ty: RuntimeExpressionType,
    projections: RuntimePlaceProjections,
) -> Option<RuntimeExpressionType> {
    if projections.count > MAX_RUNTIME_PLACE_PROJECTIONS
        || projections.items[..projections.count]
            .iter()
            .any(Option::is_none)
        || projections.items[projections.count..]
            .iter()
            .any(Option::is_some)
    {
        return None;
    }
    for projection in projections.items[..projections.count].iter().flatten() {
        ty = match (*projection, ty) {
            (
                RuntimePlaceProjection::Dereference,
                RuntimeExpressionType::Reference { target, .. },
            ) => match target {
                RuntimeReferenceTarget::Scalar(element) => runtime_type_from_array_element(element),
                RuntimeReferenceTarget::Array { element, count, .. } => {
                    RuntimeExpressionType::Array { element, count }
                }
                RuntimeReferenceTarget::Slice(_) | RuntimeReferenceTarget::Str => return None,
            },
            (
                RuntimePlaceProjection::Dereference,
                RuntimeExpressionType::RawPointer { pointee, .. },
            ) => runtime_type_from_array_element(pointee),
            (RuntimePlaceProjection::Index, RuntimeExpressionType::Array { element, .. }) => {
                runtime_type_from_array_element(element)
            }
            (
                RuntimePlaceProjection::ArrayElement(index),
                RuntimeExpressionType::Array { element, count },
            ) => {
                if index >= count {
                    return None;
                }
                runtime_type_from_array_element(element)
            }
            (
                RuntimePlaceProjection::Index,
                RuntimeExpressionType::Reference {
                    target:
                        RuntimeReferenceTarget::Array { element, .. }
                        | RuntimeReferenceTarget::Slice(element),
                    ..
                },
            ) => runtime_type_from_array_element(element),
            (
                RuntimePlaceProjection::TupleField(field),
                RuntimeExpressionType::Tuple {
                    elements,
                    element_count,
                },
            ) => {
                if field >= element_count {
                    return None;
                }
                let Some(element) = elements[field] else {
                    return None;
                };
                runtime_type_from_tuple_element(element)
            }
            (
                RuntimePlaceProjection::Subslice,
                ty @ (RuntimeExpressionType::Array { .. }
                | RuntimeExpressionType::Reference {
                    target:
                        RuntimeReferenceTarget::Array { .. }
                        | RuntimeReferenceTarget::Slice(_)
                        | RuntimeReferenceTarget::Str,
                    ..
                }),
            ) => ty,
            _ => return None,
        };
    }
    Some(ty)
}

fn runtime_place_projections_valid(
    ty: RuntimeExpressionType,
    projections: RuntimePlaceProjections,
) -> bool {
    runtime_place_projected_type(ty, projections).is_some()
}

fn runtime_type_stack_slots(ty: RuntimeExpressionType) -> usize {
    match ty {
        RuntimeExpressionType::Never => 0,
        RuntimeExpressionType::Integer(Some(integer)) => {
            runtime_integer_layout(integer.name()).map_or(1, |layout| layout.words)
        }
        RuntimeExpressionType::Array { count, .. } => count,
        RuntimeExpressionType::Tuple { element_count, .. } => element_count,
        RuntimeExpressionType::Reference {
            target: RuntimeReferenceTarget::Slice(_) | RuntimeReferenceTarget::Str,
            ..
        } => 2,
        _ => 1,
    }
}

fn runtime_parameter_stack_slots(text: &str) -> usize {
    runtime_type_from_text(text).map_or(1, runtime_type_stack_slots)
}

fn runtime_type_is_copy(ty: RuntimeExpressionType) -> bool {
    match ty {
        RuntimeExpressionType::Reference { mutable: true, .. } => false,
        RuntimeExpressionType::Tuple {
            elements,
            element_count,
        } => {
            element_count <= elements.len()
                && elements[..element_count].iter().all(|element| {
                    element.is_some_and(|element| {
                        runtime_type_is_copy(runtime_type_from_tuple_element(element))
                    })
                })
        }
        _ => true,
    }
}

fn runtime_type_is_fat_reference(ty: RuntimeExpressionType) -> bool {
    matches!(
        ty,
        RuntimeExpressionType::Reference {
            target: RuntimeReferenceTarget::Slice(_) | RuntimeReferenceTarget::Str,
            ..
        }
    )
}

fn runtime_fat_reference_preanalysis_supported<const MAX_NODES: usize>(
    tree: &crate::ExpressionTree<'_, MAX_NODES>,
    id: crate::ExprId,
    depth: usize,
) -> bool {
    if depth == 64 {
        return false;
    }
    match tree.expression(id).map(|expression| expression.kind) {
        Some(ExprKind::Identifier(_) | ExprKind::String(_) | ExprKind::ByteString(_)) => true,
        Some(ExprKind::CStrToBytes { base, .. }) => matches!(
            tree.expression(base).map(|expression| expression.kind),
            Some(ExprKind::CString(_))
        ),
        Some(ExprKind::Unary {
            operator: crate::UnaryOperator::AddressOf | crate::UnaryOperator::AddressOfMut,
            operand,
        }) => matches!(
            tree.expression(operand).map(|expression| expression.kind),
            Some(ExprKind::RangeIndex { .. })
        ),
        Some(
            ExprKind::If {
                then_branch,
                else_branch,
                ..
            }
            | ExprKind::LoopBreakIf {
                then_branch,
                else_branch,
                ..
            },
        ) => {
            runtime_fat_reference_preanalysis_supported(tree, then_branch, depth + 1)
                && runtime_fat_reference_preanalysis_supported(tree, else_branch, depth + 1)
        }
        Some(
            ExprKind::LoopBreak { operand }
            | ExprKind::Return { operand }
            | ExprKind::InlineConst { operand },
        ) => runtime_fat_reference_preanalysis_supported(tree, operand, depth + 1),
        Some(ExprKind::Sequence { then, .. }) => {
            runtime_fat_reference_preanalysis_supported(tree, then, depth + 1)
        }
        _ => false,
    }
}

fn runtime_fat_reference_call_preanalysis_supported<
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_NODES: usize,
>(
    function: &Function<'_, MAX_PARAMETERS>,
    resolver: &R,
    locals: &[Option<RuntimeLocal<'_>>],
    tree: &crate::ExpressionTree<'_, MAX_NODES>,
    id: crate::ExprId,
    depth: usize,
) -> Result<bool, CodegenErrorKind> {
    if depth == 64 {
        return Ok(false);
    }
    match tree.expression(id).map(|expression| expression.kind) {
        Some(ExprKind::Call { .. }) => runtime_call_arguments_preanalysis_supported(
            function,
            resolver,
            locals,
            tree,
            id,
            depth + 1,
        ),
        Some(
            ExprKind::If {
                then_branch,
                else_branch,
                ..
            }
            | ExprKind::LoopBreakIf {
                then_branch,
                else_branch,
                ..
            },
        ) => Ok(runtime_fat_reference_call_preanalysis_supported(
            function,
            resolver,
            locals,
            tree,
            then_branch,
            depth + 1,
        )? && runtime_fat_reference_call_preanalysis_supported(
            function,
            resolver,
            locals,
            tree,
            else_branch,
            depth + 1,
        )?),
        Some(
            ExprKind::LoopBreak { operand }
            | ExprKind::Return { operand }
            | ExprKind::InlineConst { operand },
        ) => runtime_fat_reference_call_preanalysis_supported(
            function,
            resolver,
            locals,
            tree,
            operand,
            depth + 1,
        ),
        Some(ExprKind::Sequence { then, .. }) => runtime_fat_reference_call_preanalysis_supported(
            function,
            resolver,
            locals,
            tree,
            then,
            depth + 1,
        ),
        _ => Ok(false),
    }
}

fn runtime_call_arguments_preanalysis_supported<
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_NODES: usize,
>(
    function: &Function<'_, MAX_PARAMETERS>,
    resolver: &R,
    locals: &[Option<RuntimeLocal<'_>>],
    tree: &crate::ExpressionTree<'_, MAX_NODES>,
    id: crate::ExprId,
    depth: usize,
) -> Result<bool, CodegenErrorKind> {
    if depth == 64 {
        return Ok(false);
    }
    let Some(ExprKind::Call {
        callee,
        arguments,
        argument_count,
    }) = tree.expression(id).map(|expression| expression.kind)
    else {
        return Ok(false);
    };
    let Some(target) = resolver.resolve_runtime_call::<MAX_PARAMETERS>(callee, argument_count)
    else {
        return Ok(false);
    };
    if target.parameter_count != argument_count {
        return Ok(false);
    }
    for (parameter, argument) in target.parameters[..target.parameter_count]
        .iter()
        .zip(arguments[..argument_count].iter())
    {
        let (Some(parameter), Some(argument)) = (parameter, argument) else {
            return Ok(false);
        };
        let expected = runtime_type_from_scalar(parameter.ty);
        let actual = runtime_expression_type_with_locals(
            function,
            resolver,
            locals,
            tree,
            *argument,
            depth + 1,
        )?;
        if !runtime_types_compatible(actual, expected)
            && !matches!(
                (actual, expected),
                (
                    RuntimeExpressionType::Default,
                    RuntimeExpressionType::Array { .. }
                )
            )
        {
            return Ok(false);
        }
        if runtime_type_stack_slots(expected) == 1 {
            continue;
        }
        if runtime_type_is_fat_reference(expected)
            && (runtime_fat_reference_preanalysis_supported(tree, *argument, depth + 1)
                || runtime_fat_reference_call_preanalysis_supported(
                    function,
                    resolver,
                    locals,
                    tree,
                    *argument,
                    depth + 1,
                )?)
        {
            continue;
        }
        if matches!(expected, RuntimeExpressionType::Array { .. })
            && runtime_array_call_argument_preanalysis_supported(
                function,
                resolver,
                locals,
                tree,
                *argument,
                expected,
                depth + 1,
            )?
        {
            continue;
        }
        if matches!(expected, RuntimeExpressionType::Tuple { .. })
            && runtime_tuple_value_preanalysis_supported(
                function,
                resolver,
                locals,
                tree,
                *argument,
                expected,
                depth + 1,
            )?
        {
            continue;
        }
        if runtime_aggregate_call_argument_preanalysis_supported(
            tree,
            *argument,
            expected,
            depth + 1,
        ) {
            continue;
        }
        return Ok(false);
    }
    Ok(true)
}

fn runtime_reference_call_origin_parameter<const MAX_PARAMETERS: usize, const MAX_NODES: usize>(
    target: crate::RuntimeCallTarget<'_, MAX_PARAMETERS>,
) -> Option<usize> {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ParameterProjection {
        Identity,
        Index,
        Subslice,
        SubsliceIndex,
    }

    fn parameter_projection(projections: RuntimePlaceProjections) -> Option<ParameterProjection> {
        let mut items = &projections.items[..projections.count];
        if items.first() == Some(&Some(RuntimePlaceProjection::Dereference)) {
            items = &items[1..];
        }
        match items {
            [] => Some(ParameterProjection::Identity),
            [Some(RuntimePlaceProjection::Index)] => Some(ParameterProjection::Index),
            _ if items
                .iter()
                .all(|projection| *projection == Some(RuntimePlaceProjection::Subslice)) =>
            {
                Some(ParameterProjection::Subslice)
            }
            _ if items.last() == Some(&Some(RuntimePlaceProjection::Index))
                && items[..items.len().checked_sub(1)?]
                    .iter()
                    .all(|projection| {
                        *projection == Some(RuntimePlaceProjection::Subslice)
                    }) =>
            {
                Some(ParameterProjection::SubsliceIndex)
            }
            _ => None,
        }
    }

    fn compatible_place<const MAX_PARAMETERS: usize>(
        target: crate::RuntimeCallTarget<'_, MAX_PARAMETERS>,
        place: RuntimeReadPlace<'_>,
        local_names: &[Option<&str>; MAX_PARAMETERS],
        local_origins: &[Option<usize>; MAX_PARAMETERS],
        projected_origins: &RuntimeCalleeProjectedOrigins<MAX_PARAMETERS>,
        local_count: usize,
    ) -> Option<usize> {
        for index in (0..local_count).rev() {
            if local_names[index] == Some(place.name) {
                if place.projections.count == 0 {
                    return local_origins[index];
                }
                if !place.projections.items[..place.projections.count]
                    .iter()
                    .any(|projection| {
                        matches!(projection, Some(RuntimePlaceProjection::TupleField(_)))
                    })
                {
                    return local_origins[index];
                }
                let mut origin_projections = place.projections;
                if origin_projections.items[origin_projections.count.checked_sub(1)?]
                    == Some(RuntimePlaceProjection::Dereference)
                {
                    origin_projections.count -= 1;
                    origin_projections.items[origin_projections.count] = None;
                }
                let projected = projected_origins.get(index, origin_projections)?;
                return runtime_types_compatible(
                    projected.ty,
                    runtime_type_from_scalar(target.return_type),
                )
                .then_some(projected.origin);
            }
        }
        let RuntimeExpressionType::Reference {
            target: result_target,
            mutable: result_mutable,
        } = runtime_type_from_scalar(target.return_type)
        else {
            return None;
        };
        target.parameters[..target.parameter_count]
            .iter()
            .enumerate()
            .find_map(|(index, parameter)| {
                let parameter = parameter.as_ref()?;
                let RuntimeExpressionType::Reference {
                    target: parameter_target,
                    mutable: parameter_mutable,
                } = runtime_type_from_scalar(parameter.ty)
                else {
                    return None;
                };
                if parameter.name != place.name || (result_mutable && !parameter_mutable) {
                    return None;
                }
                let projection = parameter_projection(place.projections);
                let compatible = (projection == Some(ParameterProjection::Identity)
                    && parameter_target == result_target)
                    || (matches!(
                        projection,
                        Some(
                            ParameterProjection::Index
                                | ParameterProjection::SubsliceIndex
                        )
                    ) && matches!(
                        (parameter_target, result_target),
                        (
                            RuntimeReferenceTarget::Array {
                                element: parameter_element,
                                ..
                            }
                                | RuntimeReferenceTarget::Slice(parameter_element),
                            RuntimeReferenceTarget::Scalar(result_element),
                        ) if parameter_element == result_element
                    ))
                    || (projection == Some(ParameterProjection::Subslice)
                        && matches!(
                            (parameter_target, result_target),
                            (
                                RuntimeReferenceTarget::Array {
                                    element: parameter_element,
                                    ..
                                }
                                    | RuntimeReferenceTarget::Slice(parameter_element),
                                RuntimeReferenceTarget::Slice(result_element),
                            ) if parameter_element == result_element
                        ));
                compatible.then_some(index)
            })
    }

    fn recurse<const MAX_PARAMETERS: usize, const MAX_NODES: usize>(
        target: crate::RuntimeCallTarget<'_, MAX_PARAMETERS>,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        id: crate::ExprId,
        depth: usize,
        local_names: &[Option<&str>; MAX_PARAMETERS],
        local_origins: &[Option<usize>; MAX_PARAMETERS],
        projected_origins: &RuntimeCalleeProjectedOrigins<MAX_PARAMETERS>,
        local_count: usize,
    ) -> Option<usize> {
        if depth == 64 {
            return None;
        }
        if let Some(place) = discover_runtime_read_place(tree, id).ok().flatten() {
            return compatible_place(
                target,
                place,
                local_names,
                local_origins,
                projected_origins,
                local_count,
            );
        }
        match tree.expression(id)?.kind {
            ExprKind::Unary {
                operator: crate::UnaryOperator::AddressOf | crate::UnaryOperator::AddressOfMut,
                operand,
            }
            | ExprKind::Ascribe { operand, .. }
            | ExprKind::InlineConst { operand }
            | ExprKind::Return { operand }
            | ExprKind::LoopBreak { operand } => recurse(
                target,
                tree,
                operand,
                depth + 1,
                local_names,
                local_origins,
                projected_origins,
                local_count,
            ),
            ExprKind::Sequence { then, .. } => recurse(
                target,
                tree,
                then,
                depth + 1,
                local_names,
                local_origins,
                projected_origins,
                local_count,
            ),
            ExprKind::If {
                then_branch,
                else_branch,
                ..
            }
            | ExprKind::LoopBreakIf {
                then_branch,
                else_branch,
                ..
            } => {
                let then_origin = recurse(
                    target,
                    tree,
                    then_branch,
                    depth + 1,
                    local_names,
                    local_origins,
                    projected_origins,
                    local_count,
                )?;
                let else_origin = recurse(
                    target,
                    tree,
                    else_branch,
                    depth + 1,
                    local_names,
                    local_origins,
                    projected_origins,
                    local_count,
                )?;
                (then_origin == else_origin).then_some(then_origin)
            }
            _ => None,
        }
    }

    fn local_explicit_type_is_return_compatible<const MAX_PARAMETERS: usize>(
        target: crate::RuntimeCallTarget<'_, MAX_PARAMETERS>,
        local: crate::LocalBinding<'_>,
    ) -> bool {
        local.ty.is_none_or(|ty| {
            runtime_type_from_text(ty.text).is_some_and(|ty| {
                runtime_types_compatible(ty, runtime_type_from_scalar(target.return_type))
            })
        })
    }

    fn local_is_return_compatible<const MAX_PARAMETERS: usize>(
        target: crate::RuntimeCallTarget<'_, MAX_PARAMETERS>,
        ty: Option<RuntimeExpressionType>,
        origin: Option<usize>,
    ) -> bool {
        ty.map_or(origin.is_some(), |ty| {
            runtime_types_compatible(ty, runtime_type_from_scalar(target.return_type))
        })
    }

    fn local_origin<const MAX_PARAMETERS: usize, const MAX_NODES: usize>(
        target: crate::RuntimeCallTarget<'_, MAX_PARAMETERS>,
        local: crate::LocalBinding<'_>,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        local_names: &[Option<&str>; MAX_PARAMETERS],
        local_origins: &[Option<usize>; MAX_PARAMETERS],
        projected_origins: &RuntimeCalleeProjectedOrigins<MAX_PARAMETERS>,
        local_count: usize,
    ) -> Option<usize> {
        if !local_explicit_type_is_return_compatible(target, local) {
            return None;
        }
        recurse(
            target,
            tree,
            tree.root(),
            0,
            local_names,
            local_origins,
            projected_origins,
            local_count,
        )
    }

    fn inferred_reference_expression_type<const MAX_PARAMETERS: usize, const MAX_NODES: usize>(
        target: crate::RuntimeCallTarget<'_, MAX_PARAMETERS>,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        id: crate::ExprId,
        local_names: &[Option<&str>; MAX_PARAMETERS],
        local_types: &[Option<RuntimeExpressionType>; MAX_PARAMETERS],
        local_count: usize,
        depth: usize,
    ) -> Option<RuntimeExpressionType> {
        if depth == 64 {
            return None;
        }
        let expression = tree.expression(id)?;
        match expression.kind {
            ExprKind::Identifier(name) => {
                for index in (0..local_count).rev() {
                    if local_names[index] == Some(name) {
                        return local_types[index];
                    }
                }
                target.parameters[..target.parameter_count]
                    .iter()
                    .flatten()
                    .find(|parameter| parameter.name == name)
                    .map(|parameter| runtime_type_from_scalar(parameter.ty))
            }
            ExprKind::TupleField { .. } => {
                let place = discover_runtime_read_place(tree, id).ok().flatten()?;
                let base = (0..local_count)
                    .rev()
                    .find(|index| local_names[*index] == Some(place.name))
                    .and_then(|index| local_types[index])
                    .or_else(|| {
                        target.parameters[..target.parameter_count]
                            .iter()
                            .flatten()
                            .find(|parameter| parameter.name == place.name)
                            .map(|parameter| runtime_type_from_scalar(parameter.ty))
                    })?;
                runtime_place_projected_type(base, place.projections)
            }
            ExprKind::Unary { operator, operand }
                if matches!(
                    operator,
                    crate::UnaryOperator::AddressOf | crate::UnaryOperator::AddressOfMut
                ) =>
            {
                let place = discover_runtime_read_place(tree, operand).ok().flatten()?;
                let base = (0..local_count)
                    .rev()
                    .find(|index| local_names[*index] == Some(place.name))
                    .and_then(|index| local_types[index])
                    .or_else(|| {
                        target.parameters[..target.parameter_count]
                            .iter()
                            .flatten()
                            .find(|parameter| parameter.name == place.name)
                            .map(|parameter| runtime_type_from_scalar(parameter.ty))
                    })?;
                let projected = runtime_place_projected_type(base, place.projections)?;
                let target = if place.projections.items[..place.projections.count]
                    .contains(&Some(RuntimePlaceProjection::Subslice))
                {
                    match projected {
                        RuntimeExpressionType::Array { element, .. } => {
                            RuntimeReferenceTarget::Slice(element)
                        }
                        RuntimeExpressionType::Reference {
                            target:
                                RuntimeReferenceTarget::Array { element, .. }
                                | RuntimeReferenceTarget::Slice(element),
                            ..
                        } => RuntimeReferenceTarget::Slice(element),
                        _ => return None,
                    }
                } else {
                    match projected {
                        RuntimeExpressionType::Array { element, count } => {
                            RuntimeReferenceTarget::Array {
                                element,
                                count,
                                layout: RuntimeReferenceArrayLayout::Native,
                            }
                        }
                        RuntimeExpressionType::Bool => {
                            RuntimeReferenceTarget::Scalar(RuntimeArrayElementType::Bool)
                        }
                        RuntimeExpressionType::Char => {
                            RuntimeReferenceTarget::Scalar(RuntimeArrayElementType::Char)
                        }
                        RuntimeExpressionType::Integer(ty) => {
                            RuntimeReferenceTarget::Scalar(RuntimeArrayElementType::Integer(ty))
                        }
                        RuntimeExpressionType::Unit => {
                            RuntimeReferenceTarget::Scalar(RuntimeArrayElementType::Unit)
                        }
                        _ => return None,
                    }
                };
                Some(RuntimeExpressionType::Reference {
                    target,
                    mutable: operator == crate::UnaryOperator::AddressOfMut,
                })
            }
            ExprKind::Ascribe {
                operand,
                target: ascribed,
            } => {
                let operand_ty = inferred_reference_expression_type(
                    target,
                    tree,
                    operand,
                    local_names,
                    local_types,
                    local_count,
                    depth + 1,
                )?;
                let target_ty = runtime_type_from_scalar(ascribed);
                runtime_types_compatible(operand_ty, target_ty).then_some(target_ty)
            }
            ExprKind::InlineConst { operand }
            | ExprKind::Return { operand }
            | ExprKind::LoopBreak { operand } => inferred_reference_expression_type(
                target,
                tree,
                operand,
                local_names,
                local_types,
                local_count,
                depth + 1,
            ),
            ExprKind::Sequence { then, .. } => inferred_reference_expression_type(
                target,
                tree,
                then,
                local_names,
                local_types,
                local_count,
                depth + 1,
            ),
            ExprKind::If {
                then_branch,
                else_branch,
                ..
            }
            | ExprKind::LoopBreakIf {
                then_branch,
                else_branch,
                ..
            } => {
                let then_ty = inferred_reference_expression_type(
                    target,
                    tree,
                    then_branch,
                    local_names,
                    local_types,
                    local_count,
                    depth + 1,
                )?;
                let else_ty = inferred_reference_expression_type(
                    target,
                    tree,
                    else_branch,
                    local_names,
                    local_types,
                    local_count,
                    depth + 1,
                )?;
                (then_ty == else_ty).then_some(then_ty)
            }
            _ => None,
        }
    }

    fn local_type<const MAX_PARAMETERS: usize, const MAX_NODES: usize>(
        target: crate::RuntimeCallTarget<'_, MAX_PARAMETERS>,
        local: crate::LocalBinding<'_>,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        local_names: &[Option<&str>; MAX_PARAMETERS],
        local_types: &[Option<RuntimeExpressionType>; MAX_PARAMETERS],
        local_count: usize,
        origin: Option<usize>,
    ) -> Option<RuntimeExpressionType> {
        let inferred = || {
            inferred_reference_expression_type(
                target,
                tree,
                tree.root(),
                local_names,
                local_types,
                local_count,
                0,
            )
        };
        if let Some(declared) = local.ty.and_then(|ty| runtime_type_from_text(ty.text)) {
            if matches!(declared, RuntimeExpressionType::Reference { .. })
                && !inferred()
                    .is_some_and(|initializer| runtime_types_compatible(initializer, declared))
            {
                return None;
            }
            return Some(declared);
        }
        origin
            .map(|_| runtime_type_from_scalar(target.return_type))
            .or_else(inferred)
    }

    fn apply_projected_initializer<const MAX_PARAMETERS: usize, const MAX_NODES: usize>(
        target: crate::RuntimeCallTarget<'_, MAX_PARAMETERS>,
        tree: &crate::ExpressionTree<'_, MAX_NODES>,
        local_index: usize,
        local_type: Option<RuntimeExpressionType>,
        local_names: &[Option<&str>; MAX_PARAMETERS],
        local_origins: &[Option<usize>; MAX_PARAMETERS],
        projected_origins: &mut RuntimeCalleeProjectedOrigins<MAX_PARAMETERS>,
        local_types: &[Option<RuntimeExpressionType>; MAX_PARAMETERS],
        local_count: usize,
    ) -> Option<()> {
        let Some(local_type) = local_type else {
            return Some(());
        };
        let local_type @ RuntimeExpressionType::Tuple { element_count, .. } = local_type else {
            return Some(());
        };
        let ExprKind::Tuple {
            elements,
            element_count: initializer_count,
        } = tree.expression(tree.root())?.kind
        else {
            return Some(());
        };
        if initializer_count != element_count {
            return None;
        }
        let return_type = runtime_type_from_scalar(target.return_type);
        for field in 0..element_count {
            let projections =
                RuntimePlaceProjections::single(RuntimePlaceProjection::TupleField(field));
            let projected_type = runtime_place_projected_type(local_type, projections)?;
            if !runtime_types_compatible(projected_type, return_type) {
                continue;
            }
            let element = elements[field]?;
            let element_type = inferred_reference_expression_type(
                target,
                tree,
                element,
                local_names,
                local_types,
                local_count,
                0,
            )?;
            if !runtime_types_compatible(element_type, projected_type) {
                return None;
            }
            if let Some(origin) = recurse(
                target,
                tree,
                element,
                0,
                local_names,
                local_origins,
                projected_origins,
                local_count,
            ) {
                projected_origins.set(local_index, local_type, projections, origin)?;
            }
        }
        Some(())
    }

    fn apply_assignment<const MAX_PARAMETERS: usize, const MAX_NODES: usize>(
        target: crate::RuntimeCallTarget<'_, MAX_PARAMETERS>,
        assignment: crate::Assignment<'_>,
        local_names: &[Option<&str>; MAX_PARAMETERS],
        local_origins: &mut [Option<usize>; MAX_PARAMETERS],
        projected_origins: &mut RuntimeCalleeProjectedOrigins<MAX_PARAMETERS>,
        local_types: &[Option<RuntimeExpressionType>; MAX_PARAMETERS],
        local_mutability: &[bool; MAX_PARAMETERS],
        local_return_compatibility: &[bool; MAX_PARAMETERS],
        local_count: usize,
        allow_projected: bool,
    ) -> Option<()> {
        if assignment.operator != crate::AssignmentOperator::Assign {
            return None;
        }
        let local_index = (0..local_count)
            .rev()
            .find(|index| local_names[*index] == Some(assignment.name))?;
        if !local_mutability[local_index] {
            return None;
        }
        let tree = crate::ExpressionParser::<MAX_NODES>::new(assignment.value)
            .parse()
            .ok()?;
        let origin = recurse(
            target,
            &tree,
            tree.root(),
            0,
            local_names,
            local_origins,
            projected_origins,
            local_count,
        );
        let assignment_type = inferred_reference_expression_type(
            target,
            &tree,
            tree.root(),
            local_names,
            local_types,
            local_count,
            0,
        )?;
        if let Some(projection) = assignment.projection {
            if !allow_projected {
                return None;
            }
            let projections = RuntimePlaceProjections::from_assignment(Some(projection)).ok()?;
            let projected_type =
                runtime_place_projected_type(local_types[local_index]?, projections)?;
            if !runtime_types_compatible(assignment_type, projected_type) {
                return None;
            }
            if let Some(origin) = origin {
                projected_origins.set(
                    local_index,
                    local_types[local_index]?,
                    projections,
                    origin,
                )?;
            } else {
                let _ = projected_origins.clear(local_index, projections);
            }
            return Some(());
        }
        if !local_types[local_index]
            .is_some_and(|local_type| runtime_types_compatible(assignment_type, local_type))
        {
            return None;
        }
        if !local_return_compatibility[local_index] {
            return None;
        }
        local_origins[local_index] = origin;
        Some(())
    }

    enum ConditionalActionOutcome {
        FallsThrough,
        Returns(usize),
    }

    fn apply_conditional_actions<'source, const MAX_PARAMETERS: usize, const MAX_NODES: usize>(
        target: crate::RuntimeCallTarget<'source, MAX_PARAMETERS>,
        actions: &[Option<crate::ConditionalAssignmentAction<'source>>],
        local_names: &mut [Option<&'source str>; MAX_PARAMETERS],
        local_origins: &mut [Option<usize>; MAX_PARAMETERS],
        projected_origins: &mut RuntimeCalleeProjectedOrigins<MAX_PARAMETERS>,
        local_types: &mut [Option<RuntimeExpressionType>; MAX_PARAMETERS],
        local_mutability: &mut [bool; MAX_PARAMETERS],
        local_return_compatibility: &mut [bool; MAX_PARAMETERS],
        local_count: &mut usize,
    ) -> Option<ConditionalActionOutcome> {
        for (action_index, action) in actions.iter().enumerate() {
            let action = action.as_ref()?;
            match *action {
                crate::ConditionalAssignmentAction::Local(local) => {
                    let tree = local.parse_initializer::<MAX_NODES>().ok()?;
                    let local_origin = local_origin(
                        target,
                        local,
                        &tree,
                        local_names,
                        local_origins,
                        projected_origins,
                        *local_count,
                    );
                    let local_type = local_type(
                        target,
                        local,
                        &tree,
                        local_names,
                        local_types,
                        *local_count,
                        local_origin,
                    );
                    apply_projected_initializer(
                        target,
                        &tree,
                        *local_count,
                        local_type,
                        local_names,
                        local_origins,
                        projected_origins,
                        local_types,
                        *local_count,
                    )?;
                    *local_names.get_mut(*local_count)? = Some(local.name);
                    *local_origins.get_mut(*local_count)? = local_origin;
                    *local_types.get_mut(*local_count)? = local_type;
                    *local_mutability.get_mut(*local_count)? = local.mutable;
                    *local_return_compatibility.get_mut(*local_count)? =
                        local_is_return_compatible(target, local_type, local_origin);
                    *local_count = local_count.checked_add(1)?;
                }
                crate::ConditionalAssignmentAction::Assignment(assignment) => {
                    apply_assignment::<MAX_PARAMETERS, MAX_NODES>(
                        target,
                        assignment,
                        local_names,
                        local_origins,
                        projected_origins,
                        local_types,
                        local_mutability,
                        local_return_compatibility,
                        *local_count,
                        true,
                    )?;
                }
                crate::ConditionalAssignmentAction::Expression(_) => return None,
                crate::ConditionalAssignmentAction::Return(value) => {
                    if actions[action_index + 1..].iter().any(Option::is_some) {
                        return None;
                    }
                    let tree = value.parse_value::<MAX_NODES>().ok()?;
                    let origin = recurse(
                        target,
                        &tree,
                        tree.root(),
                        0,
                        local_names,
                        local_origins,
                        projected_origins,
                        *local_count,
                    )?;
                    return Some(ConditionalActionOutcome::Returns(origin));
                }
            }
        }
        Some(ConditionalActionOutcome::FallsThrough)
    }

    fn apply_conditional_loop_actions<
        'source,
        const MAX_PARAMETERS: usize,
        const MAX_NODES: usize,
    >(
        target: crate::RuntimeCallTarget<'source, MAX_PARAMETERS>,
        actions: &[Option<crate::ConditionalLoopAction<'source>>],
        local_names: &mut [Option<&'source str>; MAX_PARAMETERS],
        local_origins: &mut [Option<usize>; MAX_PARAMETERS],
        projected_origins: &mut RuntimeCalleeProjectedOrigins<MAX_PARAMETERS>,
        local_types: &mut [Option<RuntimeExpressionType>; MAX_PARAMETERS],
        local_mutability: &mut [bool; MAX_PARAMETERS],
        local_return_compatibility: &mut [bool; MAX_PARAMETERS],
        local_count: &mut usize,
        allow_direct_assignment: bool,
    ) -> Option<()> {
        for action in actions.iter() {
            match *action.as_ref()? {
                crate::ConditionalLoopAction::Local(local) => {
                    let tree = local.parse_initializer::<MAX_NODES>().ok()?;
                    let local_origin = local_origin(
                        target,
                        local,
                        &tree,
                        local_names,
                        local_origins,
                        projected_origins,
                        *local_count,
                    );
                    let local_type = local_type(
                        target,
                        local,
                        &tree,
                        local_names,
                        local_types,
                        *local_count,
                        local_origin,
                    );
                    apply_projected_initializer(
                        target,
                        &tree,
                        *local_count,
                        local_type,
                        local_names,
                        local_origins,
                        projected_origins,
                        local_types,
                        *local_count,
                    )?;
                    *local_names.get_mut(*local_count)? = Some(local.name);
                    *local_origins.get_mut(*local_count)? = local_origin;
                    *local_types.get_mut(*local_count)? = local_type;
                    *local_mutability.get_mut(*local_count)? = local.mutable;
                    *local_return_compatibility.get_mut(*local_count)? =
                        local_is_return_compatible(target, local_type, local_origin);
                    *local_count = local_count.checked_add(1)?;
                }
                crate::ConditionalLoopAction::Assignment(assignment) => {
                    if !allow_direct_assignment {
                        let value = assignment.parse_value::<MAX_NODES>().ok()?;
                        let place = discover_runtime_read_place(&value, value.root()).ok()??;
                        if !place.projections.items[..place.projections.count]
                            .iter()
                            .any(|projection| {
                                matches!(projection, Some(RuntimePlaceProjection::TupleField(_)))
                            })
                        {
                            return None;
                        }
                    }
                    apply_assignment::<MAX_PARAMETERS, MAX_NODES>(
                        target,
                        assignment,
                        local_names,
                        local_origins,
                        projected_origins,
                        local_types,
                        local_mutability,
                        local_return_compatibility,
                        *local_count,
                        true,
                    )?;
                }
                crate::ConditionalLoopAction::Expression(_) => return None,
            }
        }
        Some(())
    }

    fn merge_loop_exit_origins<const MAX_PARAMETERS: usize>(
        joined_origins: &mut [Option<usize>; MAX_PARAMETERS],
        joined_projected_origins: &mut RuntimeCalleeProjectedOrigins<MAX_PARAMETERS>,
        outcome_count: &mut usize,
        outcome_origins: [Option<usize>; MAX_PARAMETERS],
        outcome_projected_origins: RuntimeCalleeProjectedOrigins<MAX_PARAMETERS>,
        local_count: usize,
    ) -> Option<()> {
        if *outcome_count == 0 {
            *joined_origins = outcome_origins;
            *joined_projected_origins = outcome_projected_origins;
        } else {
            for local_index in 0..local_count {
                if joined_origins[local_index] != outcome_origins[local_index] {
                    joined_origins[local_index] = None;
                }
            }
            *joined_projected_origins =
                joined_projected_origins.intersect(outcome_projected_origins);
        }
        *outcome_count = outcome_count.checked_add(1)?;
        Some(())
    }

    #[derive(Clone, Copy)]
    struct NestedLoopOriginOutcomes<const MAX_PARAMETERS: usize> {
        inner_exit: Option<(
            [Option<usize>; MAX_PARAMETERS],
            RuntimeCalleeProjectedOrigins<MAX_PARAMETERS>,
        )>,
        outer_break: Option<(
            [Option<usize>; MAX_PARAMETERS],
            RuntimeCalleeProjectedOrigins<MAX_PARAMETERS>,
        )>,
        outer_continue: Option<(
            [Option<usize>; MAX_PARAMETERS],
            RuntimeCalleeProjectedOrigins<MAX_PARAMETERS>,
        )>,
    }

    fn analyze_nested_loop_origins<
        'source,
        F,
        const MAX_PARAMETERS: usize,
        const MAX_NODES: usize,
    >(
        target: crate::RuntimeCallTarget<'source, MAX_PARAMETERS>,
        block: crate::NestedLoopBlock<'source>,
        local_names: [Option<&'source str>; MAX_PARAMETERS],
        local_origins: [Option<usize>; MAX_PARAMETERS],
        projected_origins: RuntimeCalleeProjectedOrigins<MAX_PARAMETERS>,
        local_types: [Option<RuntimeExpressionType>; MAX_PARAMETERS],
        local_mutability: [bool; MAX_PARAMETERS],
        local_return_compatibility: [bool; MAX_PARAMETERS],
        local_count: usize,
        merge: &mut F,
    ) -> Option<NestedLoopOriginOutcomes<MAX_PARAMETERS>>
    where
        F: FnMut(usize) -> Option<()>,
    {
        let state_at_from =
            |action_index: usize,
             mut origins: [Option<usize>; MAX_PARAMETERS],
             mut projected: RuntimeCalleeProjectedOrigins<MAX_PARAMETERS>| {
                let mut names = local_names;
                let mut types = local_types;
                let mut mutability = local_mutability;
                let mut compatibility = local_return_compatibility;
                let mut count = local_count;
                apply_conditional_loop_actions::<MAX_PARAMETERS, MAX_NODES>(
                    target,
                    block.actions().get(..action_index)?,
                    &mut names,
                    &mut origins,
                    &mut projected,
                    &mut types,
                    &mut mutability,
                    &mut compatibility,
                    &mut count,
                    true,
                )?;
                Some((
                    names,
                    origins,
                    projected,
                    types,
                    mutability,
                    compatibility,
                    count,
                ))
            };
        let state_at =
            |action_index: usize| state_at_from(action_index, local_origins, projected_origins);
        let state_at_branch_from =
            |branch_index: usize,
             source_origins: [Option<usize>; MAX_PARAMETERS],
             source_projected: RuntimeCalleeProjectedOrigins<MAX_PARAMETERS>| {
                let branch = block
                    .conditional_blocks()
                    .get(branch_index)
                    .copied()
                    .flatten()?;
                let (
                    mut names,
                    mut origins,
                    mut projected,
                    mut types,
                    mut mutability,
                    mut compatibility,
                    mut count,
                ) = state_at_from(
                    *block.conditional_block_action_indices().get(branch_index)?,
                    source_origins,
                    source_projected,
                )?;
                apply_conditional_loop_actions::<MAX_PARAMETERS, MAX_NODES>(
                    target,
                    branch.actions(),
                    &mut names,
                    &mut origins,
                    &mut projected,
                    &mut types,
                    &mut mutability,
                    &mut compatibility,
                    &mut count,
                    true,
                )?;
                Some((
                    names,
                    origins,
                    projected,
                    types,
                    mutability,
                    compatibility,
                    count,
                ))
            };
        let state_at_branch = |branch_index: usize| {
            state_at_branch_from(branch_index, local_origins, projected_origins)
        };
        let prefix_preserves_state = |action_index: usize| -> Option<bool> {
            let (_, origins, projected, _, _, _, _) = state_at(action_index)?;
            Some(
                origins[..local_count] == local_origins[..local_count]
                    && projected
                        .retain_local_prefix(local_count)
                        .has_same_origins(projected_origins),
            )
        };
        let branch_preserves_state = |branch_index: usize| -> Option<bool> {
            let (_, origins, projected, _, _, _, _) = state_at_branch(branch_index)?;
            Some(
                origins[..local_count] == local_origins[..local_count]
                    && projected
                        .retain_local_prefix(local_count)
                        .has_same_origins(projected_origins),
            )
        };
        let normalized_backedge_is_stable = |backedge_action_index: usize,
                                             prefix_bounded: bool|
         -> Option<bool> {
            let (_, candidate_origins, candidate_projected, _, _, _, _) =
                state_at(backedge_action_index)?;
            let candidate_projected = candidate_projected.retain_local_prefix(local_count);
            let (_, repeated_origins, repeated_projected, _, _, _, _) = state_at_from(
                backedge_action_index,
                candidate_origins,
                candidate_projected,
            )?;
            if repeated_origins[..local_count] != candidate_origins[..local_count]
                || !repeated_projected
                    .retain_local_prefix(local_count)
                    .has_same_origins(candidate_projected)
            {
                return Some(false);
            }
            let prefix_matches = |action_index: usize| -> Option<bool> {
                let (_, initial_origins, initial_projected, _, _, _, _) = state_at(action_index)?;
                let (_, repeated_origins, repeated_projected, _, _, _, _) =
                    state_at_from(action_index, candidate_origins, candidate_projected)?;
                Some(
                    initial_origins[..local_count] == repeated_origins[..local_count]
                        && initial_projected
                            .retain_local_prefix(local_count)
                            .has_same_origins(repeated_projected.retain_local_prefix(local_count)),
                )
            };
            for action_index in block
                .conditional_break_action_indices()
                .iter()
                .chain(block.conditional_continue_action_indices())
                .chain(block.conditional_return_action_indices())
                .chain(block.unconditional_control_action_indices())
                .filter(|action_index| !prefix_bounded || **action_index <= backedge_action_index)
            {
                if !prefix_matches(*action_index)? {
                    return Some(false);
                }
            }
            Some(true)
        };
        let joined_backedge_header_is_stable = || -> Option<bool> {
            let mut terminal = None;
            for ((control, action_index), control_order) in block
                .unconditional_controls()
                .iter()
                .flatten()
                .zip(block.unconditional_control_action_indices())
                .zip(block.unconditional_control_orders())
            {
                if terminal.is_none_or(|(_, _, order)| *control_order < order) {
                    terminal = Some((*control, *action_index, *control_order));
                }
            }
            let terminal_is_inner_continue = terminal.is_some_and(|(control, _, _)| {
                matches!(
                    control,
                    crate::NestedLoopUnconditionalControl::Continue(
                        crate::NestedLoopControlTarget::Inner
                    )
                )
            });
            let terminal_order = terminal.map_or(usize::MAX, |(_, _, order)| order);
            let mut header_origins = local_origins;
            let mut header_projected = projected_origins.retain_local_prefix(local_count);
            let next_header = |source_origins, source_projected| {
                let mut joined_origins = local_origins;
                let mut joined_projected = projected_origins.retain_local_prefix(local_count);
                let mut joined_count = 1usize;
                for ((action_index, target_kind), control_order) in block
                    .conditional_continue_action_indices()
                    .iter()
                    .zip(block.conditional_continue_targets())
                    .zip(block.conditional_continue_control_orders())
                {
                    if *target_kind != crate::NestedLoopControlTarget::Inner
                        || *control_order >= terminal_order
                    {
                        continue;
                    }
                    let (_, origins, projected, _, _, _, _) =
                        state_at_from(*action_index, source_origins, source_projected)?;
                    merge_loop_exit_origins(
                        &mut joined_origins,
                        &mut joined_projected,
                        &mut joined_count,
                        origins,
                        projected.retain_local_prefix(local_count),
                        local_count,
                    )?;
                }
                for (branch_index, (branch, control_order)) in block
                    .conditional_blocks()
                    .iter()
                    .flatten()
                    .zip(block.conditional_block_control_orders())
                    .enumerate()
                {
                    if *control_order >= terminal_order
                        || !matches!(
                            branch.terminal,
                            crate::NestedLoopUnconditionalControl::Continue(
                                crate::NestedLoopControlTarget::Inner
                            )
                        )
                    {
                        continue;
                    }
                    let (_, origins, projected, _, _, _, _) =
                        state_at_branch_from(branch_index, source_origins, source_projected)?;
                    merge_loop_exit_origins(
                        &mut joined_origins,
                        &mut joined_projected,
                        &mut joined_count,
                        origins,
                        projected.retain_local_prefix(local_count),
                        local_count,
                    )?;
                }
                if terminal_is_inner_continue {
                    let (_, action_index, _) = terminal?;
                    let (_, origins, projected, _, _, _, _) =
                        state_at_from(action_index, source_origins, source_projected)?;
                    merge_loop_exit_origins(
                        &mut joined_origins,
                        &mut joined_projected,
                        &mut joined_count,
                        origins,
                        projected.retain_local_prefix(local_count),
                        local_count,
                    )?;
                } else if terminal.is_none() {
                    let (_, origins, projected, _, _, _, _) =
                        state_at_from(block.action_count(), source_origins, source_projected)?;
                    merge_loop_exit_origins(
                        &mut joined_origins,
                        &mut joined_projected,
                        &mut joined_count,
                        origins,
                        projected.retain_local_prefix(local_count),
                        local_count,
                    )?;
                }
                Some((joined_origins, joined_projected))
            };
            let iteration_limit = local_count
                .checked_add(header_projected.count)?
                .checked_add(1)?;
            let mut converged = false;
            for _ in 0..iteration_limit {
                let (next_origins, next_projected) = next_header(header_origins, header_projected)?;
                if next_origins[..local_count] == header_origins[..local_count]
                    && next_projected.has_same_origins(header_projected)
                {
                    converged = true;
                    break;
                }
                header_origins = next_origins;
                header_projected = next_projected;
            }
            if !converged {
                return Some(false);
            }

            let prefix_matches = |action_index: usize| -> Option<bool> {
                let (_, initial_origins, initial_projected, _, _, _, _) = state_at(action_index)?;
                let (_, repeated_origins, repeated_projected, _, _, _, _) =
                    state_at_from(action_index, header_origins, header_projected)?;
                Some(
                    initial_origins[..local_count] == repeated_origins[..local_count]
                        && initial_projected
                            .retain_local_prefix(local_count)
                            .has_same_origins(repeated_projected.retain_local_prefix(local_count)),
                )
            };
            let branch_prefix_matches = |branch_index: usize| -> Option<bool> {
                let (_, initial_origins, initial_projected, _, _, _, _) =
                    state_at_branch(branch_index)?;
                let (_, repeated_origins, repeated_projected, _, _, _, _) =
                    state_at_branch_from(branch_index, header_origins, header_projected)?;
                Some(
                    initial_origins[..local_count] == repeated_origins[..local_count]
                        && initial_projected
                            .retain_local_prefix(local_count)
                            .has_same_origins(repeated_projected.retain_local_prefix(local_count)),
                )
            };
            for ((action_index, _), control_order) in block
                .conditional_break_action_indices()
                .iter()
                .zip(block.conditional_break_targets())
                .zip(block.conditional_break_control_orders())
            {
                if *control_order < terminal_order && !prefix_matches(*action_index)? {
                    return Some(false);
                }
            }
            for (action_index, control_order) in block
                .conditional_return_action_indices()
                .iter()
                .zip(block.conditional_return_control_orders())
            {
                if *control_order < terminal_order && !prefix_matches(*action_index)? {
                    return Some(false);
                }
            }
            for ((action_index, target_kind), control_order) in block
                .conditional_continue_action_indices()
                .iter()
                .zip(block.conditional_continue_targets())
                .zip(block.conditional_continue_control_orders())
            {
                if *control_order < terminal_order
                    && *target_kind == crate::NestedLoopControlTarget::Outer
                    && !prefix_matches(*action_index)?
                {
                    return Some(false);
                }
            }
            for (branch_index, (branch, control_order)) in block
                .conditional_blocks()
                .iter()
                .flatten()
                .zip(block.conditional_block_control_orders())
                .enumerate()
            {
                if *control_order >= terminal_order
                    || matches!(
                        branch.terminal,
                        crate::NestedLoopUnconditionalControl::Continue(
                            crate::NestedLoopControlTarget::Inner
                        )
                    )
                {
                    continue;
                }
                if !branch_prefix_matches(branch_index)? {
                    return Some(false);
                }
            }
            if !terminal_is_inner_continue
                && let Some((_, action_index, _)) = terminal
                && !prefix_matches(action_index)?
            {
                return Some(false);
            }
            Some(true)
        };
        let mut exit_origins = [None; MAX_PARAMETERS];
        let mut exit_projected_origins = RuntimeCalleeProjectedOrigins::EMPTY;
        let mut exit_count = 0usize;
        let mut outer_break_origins = [None; MAX_PARAMETERS];
        let mut outer_break_projected_origins = RuntimeCalleeProjectedOrigins::EMPTY;
        let mut outer_break_count = 0usize;
        let mut outer_continue_origins = [None; MAX_PARAMETERS];
        let mut outer_continue_projected_origins = RuntimeCalleeProjectedOrigins::EMPTY;
        let mut outer_continue_count = 0usize;
        for (branch_index, (branch, control_order)) in block
            .conditional_blocks()
            .iter()
            .flatten()
            .zip(block.conditional_block_control_orders())
            .enumerate()
        {
            if block
                .unconditional_control_orders()
                .iter()
                .any(|order| order < control_order)
            {
                continue;
            }
            match branch.terminal {
                crate::NestedLoopUnconditionalControl::Break(target_kind) => {
                    let (_, origins, projected, _, _, _, _) = state_at_branch(branch_index)?;
                    let (joined_origins, joined_projected, outcome_count) = match target_kind {
                        crate::NestedLoopControlTarget::Inner => (
                            &mut exit_origins,
                            &mut exit_projected_origins,
                            &mut exit_count,
                        ),
                        crate::NestedLoopControlTarget::Outer => (
                            &mut outer_break_origins,
                            &mut outer_break_projected_origins,
                            &mut outer_break_count,
                        ),
                    };
                    merge_loop_exit_origins(
                        joined_origins,
                        joined_projected,
                        outcome_count,
                        origins,
                        projected.retain_local_prefix(local_count),
                        local_count,
                    )?;
                }
                crate::NestedLoopUnconditionalControl::Continue(
                    crate::NestedLoopControlTarget::Inner,
                ) => {
                    if !branch_preserves_state(branch_index)?
                        && !joined_backedge_header_is_stable()?
                    {
                        return None;
                    }
                }
                crate::NestedLoopUnconditionalControl::Continue(
                    crate::NestedLoopControlTarget::Outer,
                ) => {
                    let (_, origins, projected, _, _, _, _) = state_at_branch(branch_index)?;
                    merge_loop_exit_origins(
                        &mut outer_continue_origins,
                        &mut outer_continue_projected_origins,
                        &mut outer_continue_count,
                        origins,
                        projected.retain_local_prefix(local_count),
                        local_count,
                    )?;
                }
                crate::NestedLoopUnconditionalControl::Return(_) => {}
            }
        }
        for ((action_index, target_kind), control_order) in block
            .conditional_break_action_indices()
            .iter()
            .zip(block.conditional_break_targets())
            .zip(block.conditional_break_control_orders())
        {
            if block
                .unconditional_control_orders()
                .iter()
                .any(|order| order < control_order)
            {
                continue;
            }
            let (_, origins, projected, _, _, _, _) = state_at(*action_index)?;
            let (joined_origins, joined_projected, outcome_count) = match *target_kind {
                crate::NestedLoopControlTarget::Inner => (
                    &mut exit_origins,
                    &mut exit_projected_origins,
                    &mut exit_count,
                ),
                crate::NestedLoopControlTarget::Outer => (
                    &mut outer_break_origins,
                    &mut outer_break_projected_origins,
                    &mut outer_break_count,
                ),
            };
            merge_loop_exit_origins(
                joined_origins,
                joined_projected,
                outcome_count,
                origins,
                projected.retain_local_prefix(local_count),
                local_count,
            )?;
        }
        for ((action_index, target_kind), control_order) in block
            .conditional_continue_action_indices()
            .iter()
            .zip(block.conditional_continue_targets())
            .zip(block.conditional_continue_control_orders())
        {
            if block
                .unconditional_control_orders()
                .iter()
                .any(|order| order < control_order)
            {
                continue;
            }
            match *target_kind {
                crate::NestedLoopControlTarget::Inner => {
                    if !prefix_preserves_state(*action_index)?
                        && !normalized_backedge_is_stable(block.action_count(), false)?
                        && !joined_backedge_header_is_stable()?
                    {
                        return None;
                    }
                }
                crate::NestedLoopControlTarget::Outer => {
                    let (_, origins, projected, _, _, _, _) = state_at(*action_index)?;
                    merge_loop_exit_origins(
                        &mut outer_continue_origins,
                        &mut outer_continue_projected_origins,
                        &mut outer_continue_count,
                        origins,
                        projected.retain_local_prefix(local_count),
                        local_count,
                    )?;
                }
            }
        }
        for ((control, action_index), control_order) in block
            .unconditional_controls()
            .iter()
            .flatten()
            .zip(block.unconditional_control_action_indices())
            .zip(block.unconditional_control_orders())
        {
            if block
                .unconditional_control_orders()
                .iter()
                .any(|order| order < control_order)
            {
                continue;
            }
            match *control {
                crate::NestedLoopUnconditionalControl::Break(
                    crate::NestedLoopControlTarget::Inner,
                ) => {
                    let (_, origins, projected, _, _, _, _) = state_at(*action_index)?;
                    merge_loop_exit_origins(
                        &mut exit_origins,
                        &mut exit_projected_origins,
                        &mut exit_count,
                        origins,
                        projected.retain_local_prefix(local_count),
                        local_count,
                    )?;
                }
                crate::NestedLoopUnconditionalControl::Continue(
                    crate::NestedLoopControlTarget::Inner,
                ) if prefix_preserves_state(*action_index)?
                    || normalized_backedge_is_stable(*action_index, true)?
                    || joined_backedge_header_is_stable()? => {}
                crate::NestedLoopUnconditionalControl::Break(
                    crate::NestedLoopControlTarget::Outer,
                ) => {
                    let (_, origins, projected, _, _, _, _) = state_at(*action_index)?;
                    merge_loop_exit_origins(
                        &mut outer_break_origins,
                        &mut outer_break_projected_origins,
                        &mut outer_break_count,
                        origins,
                        projected.retain_local_prefix(local_count),
                        local_count,
                    )?;
                }
                crate::NestedLoopUnconditionalControl::Continue(
                    crate::NestedLoopControlTarget::Outer,
                ) => {
                    let (_, origins, projected, _, _, _, _) = state_at(*action_index)?;
                    merge_loop_exit_origins(
                        &mut outer_continue_origins,
                        &mut outer_continue_projected_origins,
                        &mut outer_continue_count,
                        origins,
                        projected.retain_local_prefix(local_count),
                        local_count,
                    )?;
                }
                crate::NestedLoopUnconditionalControl::Return(_) => {}
                _ => return None,
            }
        }
        if block.unconditional_controls().is_empty()
            && !prefix_preserves_state(block.action_count())?
            && !normalized_backedge_is_stable(block.action_count(), false)?
            && !joined_backedge_header_is_stable()?
        {
            return None;
        }
        for ((control, action_index), control_order) in block
            .unconditional_controls()
            .iter()
            .flatten()
            .zip(block.unconditional_control_action_indices())
            .zip(block.unconditional_control_orders())
        {
            let crate::NestedLoopUnconditionalControl::Return(value) = *control else {
                continue;
            };
            if block
                .unconditional_control_orders()
                .iter()
                .any(|order| order < control_order)
            {
                continue;
            }
            let (names, origins, projected, _, _, _, count) = state_at(*action_index)?;
            let tree = value.parse_value::<MAX_NODES>().ok()?;
            merge(recurse(
                target,
                &tree,
                tree.root(),
                0,
                &names,
                &origins,
                &projected,
                count,
            )?)?;
        }
        for ((value, action_index), control_order) in block
            .conditional_returns()
            .iter()
            .flatten()
            .zip(block.conditional_return_action_indices())
            .zip(block.conditional_return_control_orders())
        {
            if block
                .unconditional_control_orders()
                .iter()
                .any(|order| order < control_order)
            {
                continue;
            }
            let (names, origins, projected, _, _, _, count) = state_at(*action_index)?;
            let tree = value.parse_value::<MAX_NODES>().ok()?;
            merge(recurse(
                target,
                &tree,
                tree.root(),
                0,
                &names,
                &origins,
                &projected,
                count,
            )?)?;
        }
        for (branch_index, (branch, control_order)) in block
            .conditional_blocks()
            .iter()
            .flatten()
            .zip(block.conditional_block_control_orders())
            .enumerate()
        {
            if block
                .unconditional_control_orders()
                .iter()
                .any(|order| order < control_order)
            {
                continue;
            }
            let crate::NestedLoopUnconditionalControl::Return(value) = branch.terminal else {
                continue;
            };
            let (names, origins, projected, _, _, _, count) = state_at_branch(branch_index)?;
            let tree = value.parse_value::<MAX_NODES>().ok()?;
            merge(recurse(
                target,
                &tree,
                tree.root(),
                0,
                &names,
                &origins,
                &projected,
                count,
            )?)?;
        }
        if block.entry_condition.is_some() {
            merge_loop_exit_origins(
                &mut exit_origins,
                &mut exit_projected_origins,
                &mut exit_count,
                local_origins,
                projected_origins,
                local_count,
            )?;
        }
        Some(NestedLoopOriginOutcomes {
            inner_exit: (exit_count != 0).then_some((exit_origins, exit_projected_origins)),
            outer_break: (outer_break_count != 0)
                .then_some((outer_break_origins, outer_break_projected_origins)),
            outer_continue: (outer_continue_count != 0)
                .then_some((outer_continue_origins, outer_continue_projected_origins)),
        })
    }

    let body =
        crate::parser::parse_function_body::<MAX_PARAMETERS, MAX_NODES>(target.body_expression)
            .ok()?;
    let mut origin = None;
    let mut local_names = [None; MAX_PARAMETERS];
    let mut local_origins = [None; MAX_PARAMETERS];
    let mut projected_origins = RuntimeCalleeProjectedOrigins::EMPTY;
    let mut local_types = [None; MAX_PARAMETERS];
    let mut local_mutability = [false; MAX_PARAMETERS];
    let mut local_return_compatibility = [false; MAX_PARAMETERS];
    let mut local_count = 0usize;
    let mut merge = |candidate: usize| -> Option<()> {
        if origin.is_some_and(|existing| existing != candidate) {
            return None;
        }
        origin = Some(candidate);
        Some(())
    };
    for statement in body.statements().iter().flatten() {
        match *statement {
            crate::BodyStatement::ConditionalReturn(index) => {
                let value = body
                    .conditional_returns()
                    .get(index)
                    .and_then(|value| *value)?;
                let tree = value.parse_value::<MAX_NODES>().ok()?;
                merge(recurse(
                    target,
                    &tree,
                    tree.root(),
                    0,
                    &local_names,
                    &local_origins,
                    &projected_origins,
                    local_count,
                )?)?;
            }
            crate::BodyStatement::ConditionalReturnElse(index) => {
                let values = body
                    .conditional_return_elses()
                    .get(index)
                    .and_then(|value| *value)?;
                for branch in values.branches().iter().flatten() {
                    let tree = branch.parse_value::<MAX_NODES>().ok()?;
                    merge(recurse(
                        target,
                        &tree,
                        tree.root(),
                        0,
                        &local_names,
                        &local_origins,
                        &projected_origins,
                        local_count,
                    )?)?;
                }
                if let Some(value) = values.else_value {
                    let tree = value.parse_value::<MAX_NODES>().ok()?;
                    merge(recurse(
                        target,
                        &tree,
                        tree.root(),
                        0,
                        &local_names,
                        &local_origins,
                        &projected_origins,
                        local_count,
                    )?)?;
                }
            }
            crate::BodyStatement::Return(index) => {
                let value = body.returns().get(index).and_then(|value| *value)?;
                let tree = value.parse_value::<MAX_NODES>().ok()?;
                merge(recurse(
                    target,
                    &tree,
                    tree.root(),
                    0,
                    &local_names,
                    &local_origins,
                    &projected_origins,
                    local_count,
                )?)?;
            }
            crate::BodyStatement::Local(index) => {
                let local = body.locals().get(index).and_then(|local| *local)?;
                let tree = local.parse_initializer::<MAX_NODES>().ok()?;
                let local_origin = local_origin(
                    target,
                    local,
                    &tree,
                    &local_names,
                    &local_origins,
                    &projected_origins,
                    local_count,
                );
                let local_type = local_type(
                    target,
                    local,
                    &tree,
                    &local_names,
                    &local_types,
                    local_count,
                    local_origin,
                );
                apply_projected_initializer(
                    target,
                    &tree,
                    local_count,
                    local_type,
                    &local_names,
                    &local_origins,
                    &mut projected_origins,
                    &local_types,
                    local_count,
                )?;
                *local_names.get_mut(local_count)? = Some(local.name);
                *local_origins.get_mut(local_count)? = local_origin;
                *local_types.get_mut(local_count)? = local_type;
                *local_mutability.get_mut(local_count)? = local.mutable;
                *local_return_compatibility.get_mut(local_count)? =
                    local_is_return_compatible(target, local_type, local_origin);
                local_count += 1;
            }
            crate::BodyStatement::Assignment(index) => {
                let assignment = body.assignments().get(index).and_then(|value| *value)?;
                apply_assignment::<MAX_PARAMETERS, MAX_NODES>(
                    target,
                    assignment,
                    &local_names,
                    &mut local_origins,
                    &mut projected_origins,
                    &local_types,
                    &local_mutability,
                    &local_return_compatibility,
                    local_count,
                    true,
                )?;
            }
            crate::BodyStatement::ConditionalAssignment(index) => {
                let conditional = body
                    .conditional_assignments()
                    .get(index)
                    .and_then(|value| *value)?;
                let base_origins = local_origins;
                let base_projected_origins = projected_origins;
                let mut joined_origins = [None; MAX_PARAMETERS];
                let mut joined_projected_origins = RuntimeCalleeProjectedOrigins::EMPTY;
                let mut ambiguous = [false; MAX_PARAMETERS];
                let mut outcome_count = 0usize;
                let mut merge_outcome =
                    |outcome: [Option<usize>; MAX_PARAMETERS],
                     projected_outcome: RuntimeCalleeProjectedOrigins<MAX_PARAMETERS>|
                     -> Option<()> {
                        if outcome_count == 0 {
                            joined_origins = outcome;
                            joined_projected_origins = projected_outcome;
                        } else {
                            for local_index in 0..local_count {
                                if joined_origins[local_index] != outcome[local_index] {
                                    joined_origins[local_index] = None;
                                    ambiguous[local_index] = true;
                                }
                            }
                            joined_projected_origins =
                                joined_projected_origins.intersect(projected_outcome);
                        }
                        outcome_count = outcome_count.checked_add(1)?;
                        Some(())
                    };
                for branch in conditional.branches().iter().flatten() {
                    let mut branch_names = local_names;
                    let mut branch_origins = base_origins;
                    let mut branch_projected_origins = projected_origins;
                    let mut branch_types = local_types;
                    let mut branch_mutability = local_mutability;
                    let mut branch_return_compatibility = local_return_compatibility;
                    let mut branch_local_count = local_count;
                    let outcome = apply_conditional_actions::<MAX_PARAMETERS, MAX_NODES>(
                        target,
                        branch.actions(),
                        &mut branch_names,
                        &mut branch_origins,
                        &mut branch_projected_origins,
                        &mut branch_types,
                        &mut branch_mutability,
                        &mut branch_return_compatibility,
                        &mut branch_local_count,
                    )?;
                    match outcome {
                        ConditionalActionOutcome::FallsThrough => {
                            merge_outcome(
                                branch_origins,
                                branch_projected_origins.retain_local_prefix(local_count),
                            )?;
                        }
                        ConditionalActionOutcome::Returns(candidate) => merge(candidate)?,
                    }
                }
                if conditional.else_action_count() == 0 {
                    merge_outcome(base_origins, base_projected_origins)?;
                } else {
                    let mut else_names = local_names;
                    let mut else_origins = base_origins;
                    let mut else_projected_origins = projected_origins;
                    let mut else_types = local_types;
                    let mut else_mutability = local_mutability;
                    let mut else_return_compatibility = local_return_compatibility;
                    let mut else_local_count = local_count;
                    let outcome = apply_conditional_actions::<MAX_PARAMETERS, MAX_NODES>(
                        target,
                        conditional.else_actions(),
                        &mut else_names,
                        &mut else_origins,
                        &mut else_projected_origins,
                        &mut else_types,
                        &mut else_mutability,
                        &mut else_return_compatibility,
                        &mut else_local_count,
                    )?;
                    match outcome {
                        ConditionalActionOutcome::FallsThrough => merge_outcome(
                            else_origins,
                            else_projected_origins.retain_local_prefix(local_count),
                        )?,
                        ConditionalActionOutcome::Returns(candidate) => merge(candidate)?,
                    }
                }
                if outcome_count != 0 {
                    projected_origins = joined_projected_origins;
                    for local_index in 0..local_count {
                        local_origins[local_index] = (!ambiguous[local_index])
                            .then_some(joined_origins[local_index])
                            .flatten();
                    }
                }
            }
            crate::BodyStatement::Loop(index) => {
                let loop_statement = body.while_loops().get(index).and_then(|value| *value)?;
                let has_local_state_operation = loop_statement.operations().iter().flatten().any(
                    |operation| match *operation {
                        crate::LoopOperation::Local(_) | crate::LoopOperation::Assignment(_) => {
                            true
                        }
                        crate::LoopOperation::ConditionalBlock(block_index) => {
                            let Some(block) = loop_statement
                                .conditional_blocks()
                                .get(block_index)
                                .and_then(|value| *value)
                            else {
                                return false;
                            };
                            let primary_has_state =
                                block.actions().iter().flatten().any(|action| {
                                    matches!(
                                        action,
                                        crate::ConditionalLoopAction::Local(_)
                                            | crate::ConditionalLoopAction::Assignment(_)
                                    )
                                });
                            let Some(else_index) = block.else_arm else {
                                return primary_has_state;
                            };
                            let Some(else_end) = else_index.checked_add(block.else_arm_count)
                            else {
                                return false;
                            };
                            let Some(arms) = loop_statement
                                .conditional_else_arms()
                                .get(else_index..else_end)
                            else {
                                return false;
                            };
                            primary_has_state
                                || arms.iter().flatten().any(|arm| {
                                    arm.actions().iter().flatten().any(|action| {
                                        matches!(
                                            action,
                                            crate::ConditionalLoopAction::Local(_)
                                                | crate::ConditionalLoopAction::Assignment(_)
                                        )
                                    })
                                })
                        }
                        crate::LoopOperation::NestedBlock(block_index) => loop_statement
                            .nested_blocks()
                            .get(block_index)
                            .and_then(|value| *value)
                            .is_some_and(|block| {
                                block.actions().iter().flatten().any(|action| {
                                    matches!(
                                        action,
                                        crate::ConditionalLoopAction::Local(_)
                                            | crate::ConditionalLoopAction::Assignment(_)
                                    )
                                }) || block
                                    .conditional_break_targets()
                                    .iter()
                                    .chain(block.conditional_continue_targets())
                                    .any(|target| *target == crate::NestedLoopControlTarget::Outer)
                                    || block.conditional_blocks().iter().flatten().any(|branch| {
                                        branch.actions().iter().flatten().any(|action| {
                                            matches!(
                                                action,
                                                crate::ConditionalLoopAction::Local(_)
                                                    | crate::ConditionalLoopAction::Assignment(_)
                                            )
                                        }) || matches!(
                                            branch.terminal,
                                            crate::NestedLoopUnconditionalControl::Break(
                                                crate::NestedLoopControlTarget::Outer
                                            ) | crate::NestedLoopUnconditionalControl::Continue(
                                                crate::NestedLoopControlTarget::Outer
                                            )
                                        )
                                    })
                                    || block.unconditional_controls().iter().flatten().any(
                                        |control| {
                                            matches!(
                                                control,
                                                crate::NestedLoopUnconditionalControl::Break(
                                                    crate::NestedLoopControlTarget::Outer
                                                ) | crate::NestedLoopUnconditionalControl::Continue(
                                                    crate::NestedLoopControlTarget::Outer
                                                )
                                            )
                                        },
                                    )
                            }),
                        _ => false,
                    },
                );
                if has_local_state_operation {
                    let incoming_origins = local_origins;
                    let incoming_projected_origins = projected_origins;
                    let mut iteration_names = local_names;
                    let mut iteration_origins = incoming_origins;
                    let mut iteration_projected_origins = projected_origins;
                    let mut iteration_types = local_types;
                    let mut iteration_mutability = local_mutability;
                    let mut iteration_return_compatibility = local_return_compatibility;
                    let mut iteration_local_count = local_count;
                    let mut iteration_reaches_backedge = true;
                    let mut break_origins = [None; MAX_PARAMETERS];
                    let mut break_projected_origins = RuntimeCalleeProjectedOrigins::EMPTY;
                    let mut break_outcome_count = 0usize;
                    let mut backedge_origins = [None; MAX_PARAMETERS];
                    let mut backedge_projected_origins = RuntimeCalleeProjectedOrigins::EMPTY;
                    let mut backedge_outcome_count = 0usize;
                    for operation in loop_statement.operations().iter().flatten() {
                        match *operation {
                            crate::LoopOperation::Local(local) => {
                                let tree = local.parse_initializer::<MAX_NODES>().ok()?;
                                let local_origin = local_origin(
                                    target,
                                    local,
                                    &tree,
                                    &iteration_names,
                                    &iteration_origins,
                                    &iteration_projected_origins,
                                    iteration_local_count,
                                );
                                let local_type = local_type(
                                    target,
                                    local,
                                    &tree,
                                    &iteration_names,
                                    &iteration_types,
                                    iteration_local_count,
                                    local_origin,
                                );
                                apply_projected_initializer(
                                    target,
                                    &tree,
                                    iteration_local_count,
                                    local_type,
                                    &iteration_names,
                                    &iteration_origins,
                                    &mut iteration_projected_origins,
                                    &iteration_types,
                                    iteration_local_count,
                                )?;
                                *iteration_names.get_mut(iteration_local_count)? = Some(local.name);
                                *iteration_origins.get_mut(iteration_local_count)? = local_origin;
                                *iteration_types.get_mut(iteration_local_count)? = local_type;
                                *iteration_mutability.get_mut(iteration_local_count)? =
                                    local.mutable;
                                *iteration_return_compatibility.get_mut(iteration_local_count)? =
                                    local_is_return_compatible(target, local_type, local_origin);
                                iteration_local_count = iteration_local_count.checked_add(1)?;
                            }
                            crate::LoopOperation::Assignment(assignment) => {
                                apply_assignment::<MAX_PARAMETERS, MAX_NODES>(
                                    target,
                                    assignment,
                                    &iteration_names,
                                    &mut iteration_origins,
                                    &mut iteration_projected_origins,
                                    &iteration_types,
                                    &iteration_mutability,
                                    &iteration_return_compatibility,
                                    iteration_local_count,
                                    true,
                                )?;
                            }
                            crate::LoopOperation::ConditionalReturn(value) => {
                                let tree = value.parse_value::<MAX_NODES>().ok()?;
                                merge(recurse(
                                    target,
                                    &tree,
                                    tree.root(),
                                    0,
                                    &iteration_names,
                                    &iteration_origins,
                                    &iteration_projected_origins,
                                    iteration_local_count,
                                )?)?;
                            }
                            crate::LoopOperation::ConditionalBreak(_) => {
                                merge_loop_exit_origins(
                                    &mut break_origins,
                                    &mut break_projected_origins,
                                    &mut break_outcome_count,
                                    iteration_origins,
                                    iteration_projected_origins.retain_local_prefix(local_count),
                                    local_count,
                                )?;
                            }
                            crate::LoopOperation::ConditionalContinue(_) => {
                                merge_loop_exit_origins(
                                    &mut backedge_origins,
                                    &mut backedge_projected_origins,
                                    &mut backedge_outcome_count,
                                    iteration_origins,
                                    iteration_projected_origins.retain_local_prefix(local_count),
                                    local_count,
                                )?;
                            }
                            crate::LoopOperation::Return(value) => {
                                let tree = value.parse_value::<MAX_NODES>().ok()?;
                                merge(recurse(
                                    target,
                                    &tree,
                                    tree.root(),
                                    0,
                                    &iteration_names,
                                    &iteration_origins,
                                    &iteration_projected_origins,
                                    iteration_local_count,
                                )?)?;
                                iteration_reaches_backedge = false;
                                break;
                            }
                            crate::LoopOperation::Break => {
                                merge_loop_exit_origins(
                                    &mut break_origins,
                                    &mut break_projected_origins,
                                    &mut break_outcome_count,
                                    iteration_origins,
                                    iteration_projected_origins.retain_local_prefix(local_count),
                                    local_count,
                                )?;
                                iteration_reaches_backedge = false;
                                break;
                            }
                            crate::LoopOperation::Continue => {
                                merge_loop_exit_origins(
                                    &mut backedge_origins,
                                    &mut backedge_projected_origins,
                                    &mut backedge_outcome_count,
                                    iteration_origins,
                                    iteration_projected_origins.retain_local_prefix(local_count),
                                    local_count,
                                )?;
                                iteration_reaches_backedge = false;
                                break;
                            }
                            crate::LoopOperation::ConditionalBlock(block_index) => {
                                let block = loop_statement
                                    .conditional_blocks()
                                    .get(block_index)
                                    .and_then(|value| *value)?;
                                let base_origins = iteration_origins;
                                let base_projected_origins = iteration_projected_origins;
                                let mut joined_origins = [None; MAX_PARAMETERS];
                                let mut joined_projected_origins =
                                    RuntimeCalleeProjectedOrigins::EMPTY;
                                let mut ambiguous = [false; MAX_PARAMETERS];
                                let mut outcome_count = 0usize;
                                let mut merge_outcome =
                                    |outcome: [Option<usize>; MAX_PARAMETERS],
                                     projected_outcome: RuntimeCalleeProjectedOrigins<
                                        MAX_PARAMETERS,
                                    >|
                                     -> Option<()> {
                                        if outcome_count == 0 {
                                            joined_origins = outcome;
                                            joined_projected_origins = projected_outcome;
                                        } else {
                                            for local_index in 0..iteration_local_count {
                                                if joined_origins[local_index]
                                                    != outcome[local_index]
                                                {
                                                    joined_origins[local_index] = None;
                                                    ambiguous[local_index] = true;
                                                }
                                            }
                                            joined_projected_origins = joined_projected_origins
                                                .intersect(projected_outcome);
                                        }
                                        outcome_count = outcome_count.checked_add(1)?;
                                        Some(())
                                    };
                                let mut apply_arm =
                                    |actions: &[Option<crate::ConditionalLoopAction<'_>>],
                                     terminal: Option<crate::ConditionalLoopTerminal<'_>>|
                                     -> Option<()> {
                                        let mut arm_names = iteration_names;
                                        let mut arm_origins = base_origins;
                                        let mut arm_projected_origins = base_projected_origins;
                                        let mut arm_types = iteration_types;
                                        let mut arm_mutability = iteration_mutability;
                                        let mut arm_return_compatibility =
                                            iteration_return_compatibility;
                                        let mut arm_local_count = iteration_local_count;
                                        apply_conditional_loop_actions::<MAX_PARAMETERS, MAX_NODES>(
                                            target,
                                            actions,
                                            &mut arm_names,
                                            &mut arm_origins,
                                            &mut arm_projected_origins,
                                            &mut arm_types,
                                            &mut arm_mutability,
                                            &mut arm_return_compatibility,
                                            &mut arm_local_count,
                                            true,
                                        )?;
                                        match terminal {
                                            None => merge_outcome(
                                                arm_origins,
                                                arm_projected_origins
                                                    .retain_local_prefix(iteration_local_count),
                                            ),
                                            Some(crate::ConditionalLoopTerminal::Return(value)) => {
                                                let tree = value.parse_value::<MAX_NODES>().ok()?;
                                                merge(recurse(
                                                    target,
                                                    &tree,
                                                    tree.root(),
                                                    0,
                                                    &arm_names,
                                                    &arm_origins,
                                                    &arm_projected_origins,
                                                    arm_local_count,
                                                )?)
                                            }
                                            Some(crate::ConditionalLoopTerminal::Break) => {
                                                merge_loop_exit_origins(
                                                    &mut break_origins,
                                                    &mut break_projected_origins,
                                                    &mut break_outcome_count,
                                                    arm_origins,
                                                    arm_projected_origins
                                                        .retain_local_prefix(local_count),
                                                    local_count,
                                                )
                                            }
                                            Some(crate::ConditionalLoopTerminal::Continue) => {
                                                merge_loop_exit_origins(
                                                    &mut backedge_origins,
                                                    &mut backedge_projected_origins,
                                                    &mut backedge_outcome_count,
                                                    arm_origins,
                                                    arm_projected_origins
                                                        .retain_local_prefix(local_count),
                                                    local_count,
                                                )
                                            }
                                        }
                                    };
                                apply_arm(block.actions(), block.terminal)?;
                                let mut has_unconditional_else = false;
                                if let Some(else_index) = block.else_arm {
                                    let else_end = else_index.checked_add(block.else_arm_count)?;
                                    let arms = loop_statement
                                        .conditional_else_arms()
                                        .get(else_index..else_end)?;
                                    for arm in arms.iter().flatten() {
                                        has_unconditional_else |= arm.condition.is_none();
                                        apply_arm(arm.actions(), arm.terminal)?;
                                    }
                                }
                                drop(apply_arm);
                                if !has_unconditional_else {
                                    merge_outcome(base_origins, base_projected_origins)?;
                                }
                                if outcome_count != 0 {
                                    for local_index in 0..iteration_local_count {
                                        iteration_origins[local_index] = (!ambiguous[local_index])
                                            .then_some(joined_origins[local_index])
                                            .flatten();
                                    }
                                    iteration_projected_origins = joined_projected_origins;
                                }
                            }
                            crate::LoopOperation::NestedBlock(block_index) => {
                                let block = loop_statement
                                    .nested_blocks()
                                    .get(block_index)
                                    .and_then(|value| *value)?;
                                let nested_outcomes =
                                    analyze_nested_loop_origins::<_, MAX_PARAMETERS, MAX_NODES>(
                                        target,
                                        block,
                                        iteration_names,
                                        iteration_origins,
                                        iteration_projected_origins,
                                        iteration_types,
                                        iteration_mutability,
                                        iteration_return_compatibility,
                                        iteration_local_count,
                                        &mut merge,
                                    )?;
                                if let Some((origins, projected)) = nested_outcomes.outer_break {
                                    merge_loop_exit_origins(
                                        &mut break_origins,
                                        &mut break_projected_origins,
                                        &mut break_outcome_count,
                                        origins,
                                        projected.retain_local_prefix(local_count),
                                        local_count,
                                    )?;
                                }
                                if let Some((origins, projected)) = nested_outcomes.outer_continue {
                                    merge_loop_exit_origins(
                                        &mut backedge_origins,
                                        &mut backedge_projected_origins,
                                        &mut backedge_outcome_count,
                                        origins,
                                        projected.retain_local_prefix(local_count),
                                        local_count,
                                    )?;
                                }
                                let Some((nested_origins, nested_projected_origins)) =
                                    nested_outcomes.inner_exit
                                else {
                                    iteration_reaches_backedge = false;
                                    break;
                                };
                                iteration_origins[..iteration_local_count]
                                    .copy_from_slice(&nested_origins[..iteration_local_count]);
                                iteration_projected_origins = nested_projected_origins;
                            }
                            _ => return None,
                        }
                    }
                    if iteration_reaches_backedge {
                        merge_loop_exit_origins(
                            &mut backedge_origins,
                            &mut backedge_projected_origins,
                            &mut backedge_outcome_count,
                            iteration_origins,
                            iteration_projected_origins.retain_local_prefix(local_count),
                            local_count,
                        )?;
                    }
                    if loop_statement.condition.is_some() {
                        let mut natural_origins = incoming_origins;
                        let mut natural_projected_origins = incoming_projected_origins;
                        if backedge_outcome_count != 0 {
                            for local_index in 0..local_count {
                                natural_origins[local_index] = (incoming_origins[local_index]
                                    == backedge_origins[local_index])
                                    .then_some(incoming_origins[local_index])
                                    .flatten();
                            }
                            natural_projected_origins =
                                incoming_projected_origins.intersect(backedge_projected_origins);
                        }
                        merge_loop_exit_origins(
                            &mut break_origins,
                            &mut break_projected_origins,
                            &mut break_outcome_count,
                            natural_origins,
                            natural_projected_origins.retain_local_prefix(local_count),
                            local_count,
                        )?;
                    }
                    if break_outcome_count == 0 {
                        local_origins = incoming_origins;
                        projected_origins = incoming_projected_origins;
                    } else {
                        local_origins[..local_count].copy_from_slice(&break_origins[..local_count]);
                        projected_origins = break_projected_origins;
                    }
                    continue;
                }
                for operation in loop_statement.operations().iter().flatten() {
                    match *operation {
                        crate::LoopOperation::ConditionalReturn(value) => {
                            let tree = value.parse_value::<MAX_NODES>().ok()?;
                            merge(recurse(
                                target,
                                &tree,
                                tree.root(),
                                0,
                                &local_names,
                                &local_origins,
                                &projected_origins,
                                local_count,
                            )?)?;
                        }
                        crate::LoopOperation::Return(value) => {
                            let tree = value.parse_value::<MAX_NODES>().ok()?;
                            merge(recurse(
                                target,
                                &tree,
                                tree.root(),
                                0,
                                &local_names,
                                &local_origins,
                                &projected_origins,
                                local_count,
                            )?)?;
                        }
                        crate::LoopOperation::Break
                        | crate::LoopOperation::Continue
                        | crate::LoopOperation::ConditionalBreak(_)
                        | crate::LoopOperation::ConditionalContinue(_) => {}
                        crate::LoopOperation::ConditionalBlock(block_index) => {
                            let block = loop_statement
                                .conditional_blocks()
                                .get(block_index)
                                .and_then(|value| *value)?;
                            let mut block_names = local_names;
                            let mut block_origins = local_origins;
                            let mut block_projected_origins = projected_origins;
                            let mut block_types = local_types;
                            let mut block_mutability = local_mutability;
                            let mut block_return_compatibility = local_return_compatibility;
                            let mut block_local_count = local_count;
                            apply_conditional_loop_actions::<MAX_PARAMETERS, MAX_NODES>(
                                target,
                                block.actions(),
                                &mut block_names,
                                &mut block_origins,
                                &mut block_projected_origins,
                                &mut block_types,
                                &mut block_mutability,
                                &mut block_return_compatibility,
                                &mut block_local_count,
                                false,
                            )?;
                            if let Some(crate::ConditionalLoopTerminal::Return(value)) =
                                block.terminal
                            {
                                let tree = value.parse_value::<MAX_NODES>().ok()?;
                                merge(recurse(
                                    target,
                                    &tree,
                                    tree.root(),
                                    0,
                                    &block_names,
                                    &block_origins,
                                    &block_projected_origins,
                                    block_local_count,
                                )?)?;
                            }
                            if let Some(else_index) = block.else_arm {
                                let else_end = else_index.checked_add(block.else_arm_count)?;
                                let arms = loop_statement
                                    .conditional_else_arms()
                                    .get(else_index..else_end)?;
                                for arm in arms.iter().flatten() {
                                    let mut arm_names = local_names;
                                    let mut arm_origins = local_origins;
                                    let mut arm_projected_origins = projected_origins;
                                    let mut arm_types = local_types;
                                    let mut arm_mutability = local_mutability;
                                    let mut arm_return_compatibility = local_return_compatibility;
                                    let mut arm_local_count = local_count;
                                    apply_conditional_loop_actions::<MAX_PARAMETERS, MAX_NODES>(
                                        target,
                                        arm.actions(),
                                        &mut arm_names,
                                        &mut arm_origins,
                                        &mut arm_projected_origins,
                                        &mut arm_types,
                                        &mut arm_mutability,
                                        &mut arm_return_compatibility,
                                        &mut arm_local_count,
                                        false,
                                    )?;
                                    if let Some(crate::ConditionalLoopTerminal::Return(value)) =
                                        arm.terminal
                                    {
                                        let tree = value.parse_value::<MAX_NODES>().ok()?;
                                        merge(recurse(
                                            target,
                                            &tree,
                                            tree.root(),
                                            0,
                                            &arm_names,
                                            &arm_origins,
                                            &arm_projected_origins,
                                            arm_local_count,
                                        )?)?;
                                    }
                                }
                            }
                        }
                        crate::LoopOperation::NestedBlock(block_index) => {
                            let block = loop_statement
                                .nested_blocks()
                                .get(block_index)
                                .and_then(|value| *value)?;
                            analyze_nested_loop_origins::<_, MAX_PARAMETERS, MAX_NODES>(
                                target,
                                block,
                                local_names,
                                local_origins,
                                projected_origins,
                                local_types,
                                local_mutability,
                                local_return_compatibility,
                                local_count,
                                &mut merge,
                            )?;
                        }
                        crate::LoopOperation::Local(_)
                        | crate::LoopOperation::Assignment(_)
                        | crate::LoopOperation::Expression(_)
                        | crate::LoopOperation::NestedUnitLoop => return None,
                    }
                }
            }
            crate::BodyStatement::Expression(_) => return None,
        }
    }
    if !x86_64_body_tail_diverges(&body) && !body.tail_expression.is_empty() {
        let tree = body.parse_tail::<MAX_NODES>().ok()?;
        merge(recurse(
            target,
            &tree,
            tree.root(),
            0,
            &local_names,
            &local_origins,
            &projected_origins,
            local_count,
        )?)?;
    }
    origin
}

fn runtime_expression_reference_call_origin<
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_NODES: usize,
>(
    resolver: &R,
    tree: &crate::ExpressionTree<'_, MAX_NODES>,
    id: crate::ExprId,
) -> Option<usize> {
    let ExprKind::Call {
        callee,
        argument_count,
        ..
    } = tree.expression(id)?.kind
    else {
        return None;
    };
    let target = resolver.resolve_runtime_call::<MAX_PARAMETERS>(callee, argument_count)?;
    runtime_reference_call_origin_parameter::<MAX_PARAMETERS, MAX_NODES>(target)
}

fn runtime_tuple_value_preanalysis_supported<
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_NODES: usize,
>(
    function: &Function<'_, MAX_PARAMETERS>,
    resolver: &R,
    locals: &[Option<RuntimeLocal<'_>>],
    tree: &crate::ExpressionTree<'_, MAX_NODES>,
    id: crate::ExprId,
    expected: RuntimeExpressionType,
    depth: usize,
) -> Result<bool, CodegenErrorKind> {
    if depth == 64 {
        return Ok(false);
    }
    let RuntimeExpressionType::Tuple { element_count, .. } = expected else {
        return Ok(false);
    };
    match tree.expression(id).map(|expression| expression.kind) {
        Some(ExprKind::Call { .. }) => runtime_call_arguments_preanalysis_supported(
            function,
            resolver,
            locals,
            tree,
            id,
            depth + 1,
        ),
        Some(ExprKind::InlineConst { operand }) => runtime_tuple_value_preanalysis_supported(
            function,
            resolver,
            locals,
            tree,
            operand,
            expected,
            depth + 1,
        ),
        Some(ExprKind::Sequence { then, .. }) => runtime_tuple_value_preanalysis_supported(
            function,
            resolver,
            locals,
            tree,
            then,
            expected,
            depth + 1,
        ),
        Some(
            ExprKind::If {
                then_branch,
                else_branch,
                ..
            }
            | ExprKind::LoopBreakIf {
                then_branch,
                else_branch,
                ..
            },
        ) => Ok(runtime_tuple_value_preanalysis_supported(
            function,
            resolver,
            locals,
            tree,
            then_branch,
            expected,
            depth + 1,
        )? && runtime_tuple_value_preanalysis_supported(
            function,
            resolver,
            locals,
            tree,
            else_branch,
            expected,
            depth + 1,
        )?),
        Some(ExprKind::Tuple {
            elements,
            element_count: actual_count,
        }) => {
            Ok(actual_count == element_count
                && elements[..actual_count].iter().all(Option::is_some))
        }
        Some(ExprKind::Identifier(_)) => Ok(true),
        Some(ExprKind::Return { .. } | ExprKind::LoopBreak { .. } | ExprKind::Ascribe { .. }) => {
            for field in 0..element_count {
                if !runtime_tuple_field_preanalysis_supported(
                    function,
                    resolver,
                    locals,
                    tree,
                    id,
                    field,
                    expected,
                    depth + 1,
                )? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

#[allow(clippy::too_many_arguments)]
fn runtime_tuple_field_preanalysis_supported<
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_NODES: usize,
>(
    function: &Function<'_, MAX_PARAMETERS>,
    resolver: &R,
    locals: &[Option<RuntimeLocal<'_>>],
    tree: &crate::ExpressionTree<'_, MAX_NODES>,
    id: crate::ExprId,
    field: usize,
    expected: RuntimeExpressionType,
    depth: usize,
) -> Result<bool, CodegenErrorKind> {
    if depth == 64 {
        return Ok(false);
    }
    match tree.expression(id).map(|expression| expression.kind) {
        Some(ExprKind::Tuple {
            elements,
            element_count,
        }) => Ok(field < element_count && elements.get(field).is_some_and(Option::is_some)),
        Some(ExprKind::Identifier(_)) => Ok(true),
        Some(
            ExprKind::Return { operand }
            | ExprKind::LoopBreak { operand }
            | ExprKind::Ascribe { operand, .. }
            | ExprKind::InlineConst { operand },
        ) => runtime_tuple_field_preanalysis_supported(
            function,
            resolver,
            locals,
            tree,
            operand,
            field,
            expected,
            depth + 1,
        ),
        Some(ExprKind::Sequence { then, .. }) => runtime_tuple_field_preanalysis_supported(
            function,
            resolver,
            locals,
            tree,
            then,
            field,
            expected,
            depth + 1,
        ),
        Some(ExprKind::Call { .. } | ExprKind::If { .. } | ExprKind::LoopBreakIf { .. }) => {
            runtime_tuple_value_preanalysis_supported(
                function,
                resolver,
                locals,
                tree,
                id,
                expected,
                depth + 1,
            )
        }
        _ => Ok(false),
    }
}

fn runtime_array_call_argument_preanalysis_supported<
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_NODES: usize,
>(
    function: &Function<'_, MAX_PARAMETERS>,
    resolver: &R,
    locals: &[Option<RuntimeLocal<'_>>],
    tree: &crate::ExpressionTree<'_, MAX_NODES>,
    id: crate::ExprId,
    expected: RuntimeExpressionType,
    depth: usize,
) -> Result<bool, CodegenErrorKind> {
    if depth == 64 {
        return Ok(false);
    }
    let RuntimeExpressionType::Array { count, .. } = expected else {
        return Ok(false);
    };
    runtime_return_array_preanalysis_supported(
        function,
        resolver,
        locals,
        tree,
        id,
        count,
        depth + 1,
    )
}

fn runtime_aggregate_call_argument_preanalysis_supported<const MAX_NODES: usize>(
    tree: &crate::ExpressionTree<'_, MAX_NODES>,
    id: crate::ExprId,
    expected: RuntimeExpressionType,
    depth: usize,
) -> bool {
    if depth == 64 {
        return false;
    }
    let kind = tree.expression(id).map(|expression| expression.kind);
    if let RuntimeExpressionType::Array { count, .. } = expected {
        if let Some(ExprKind::ArrayRepeat { count: repeat, .. }) = kind {
            return repeat == count;
        }
        return kind.is_some()
            && (0..count).all(|index| {
                runtime_array_element_preanalysis_supported(tree, id, index, depth + 1)
            });
    }
    match (expected, kind) {
        (RuntimeExpressionType::Array { .. }, Some(ExprKind::Identifier(_)))
        | (RuntimeExpressionType::Array { .. }, Some(ExprKind::DefaultValue))
        | (RuntimeExpressionType::Tuple { .. }, Some(ExprKind::Identifier(_))) => true,
        (
            RuntimeExpressionType::Array { count, .. },
            Some(ExprKind::Array {
                elements,
                element_count,
            }),
        ) => element_count == count && elements[..element_count].iter().all(Option::is_some),
        (
            RuntimeExpressionType::Array { count, .. },
            Some(ExprKind::ArrayRepeat { count: repeat, .. }),
        ) => repeat == count,
        (RuntimeExpressionType::Array { count, .. }, Some(ExprKind::Sequence { then, .. })) => {
            runtime_wrapped_array_call_argument_preanalysis_supported(tree, then, count)
        }
        (
            RuntimeExpressionType::Array { count, .. },
            Some(
                ExprKind::If {
                    then_branch,
                    else_branch,
                    ..
                }
                | ExprKind::LoopBreakIf {
                    then_branch,
                    else_branch,
                    ..
                },
            ),
        ) => matches!(
            (
                tree.expression(then_branch).map(|expression| expression.kind),
                tree.expression(else_branch).map(|expression| expression.kind),
            ),
            (
                Some(ExprKind::Array {
                    elements: then_elements,
                    element_count: then_count,
                }),
                Some(ExprKind::Array {
                    elements: else_elements,
                    element_count: else_count,
                }),
            ) if then_count == count
                && else_count == count
                && then_elements[..then_count].iter().all(Option::is_some)
                && else_elements[..else_count].iter().all(Option::is_some)
        ),
        (
            RuntimeExpressionType::Tuple { element_count, .. },
            Some(ExprKind::Tuple {
                elements,
                element_count: actual_count,
            }),
        ) => actual_count == element_count && elements[..actual_count].iter().all(Option::is_some),
        (
            expected @ RuntimeExpressionType::Tuple { .. },
            Some(
                ExprKind::If {
                    then_branch,
                    else_branch,
                    ..
                }
                | ExprKind::LoopBreakIf {
                    then_branch,
                    else_branch,
                    ..
                },
            ),
        ) => {
            runtime_aggregate_call_argument_preanalysis_supported(
                tree,
                then_branch,
                expected,
                depth + 1,
            ) && runtime_aggregate_call_argument_preanalysis_supported(
                tree,
                else_branch,
                expected,
                depth + 1,
            )
        }
        (
            expected @ RuntimeExpressionType::Tuple { .. },
            Some(
                ExprKind::InlineConst { operand }
                | ExprKind::LoopBreak { operand }
                | ExprKind::Return { operand },
            ),
        ) => runtime_aggregate_call_argument_preanalysis_supported(
            tree,
            operand,
            expected,
            depth + 1,
        ),
        (expected @ RuntimeExpressionType::Tuple { .. }, Some(ExprKind::Sequence { then, .. })) => {
            runtime_aggregate_call_argument_preanalysis_supported(tree, then, expected, depth + 1)
        }
        _ => false,
    }
}

fn runtime_array_element_preanalysis_supported<const MAX_NODES: usize>(
    tree: &crate::ExpressionTree<'_, MAX_NODES>,
    id: crate::ExprId,
    index: usize,
    depth: usize,
) -> bool {
    if depth == 64 {
        return false;
    }
    match tree.expression(id).map(|expression| expression.kind) {
        Some(ExprKind::DefaultValue | ExprKind::Identifier(_)) => true,
        Some(ExprKind::Array {
            elements,
            element_count,
        }) => index < element_count && elements[index].is_some(),
        Some(ExprKind::ArrayRepeat { count, .. }) => index < count,
        Some(ExprKind::IntegerToBytes { .. }) => true,
        Some(
            ExprKind::If {
                then_branch,
                else_branch,
                ..
            }
            | ExprKind::LoopBreakIf {
                then_branch,
                else_branch,
                ..
            },
        ) => {
            runtime_array_element_preanalysis_supported(tree, then_branch, index, depth + 1)
                && runtime_array_element_preanalysis_supported(tree, else_branch, index, depth + 1)
        }
        Some(
            ExprKind::InlineConst { operand }
            | ExprKind::LoopBreak { operand }
            | ExprKind::Return { operand },
        ) => runtime_array_element_preanalysis_supported(tree, operand, index, depth + 1),
        Some(ExprKind::Sequence { then, .. }) => {
            runtime_array_element_preanalysis_supported(tree, then, index, depth + 1)
        }
        _ => false,
    }
}

fn runtime_wrapped_array_call_argument_preanalysis_supported<const MAX_NODES: usize>(
    tree: &crate::ExpressionTree<'_, MAX_NODES>,
    id: crate::ExprId,
    count: usize,
) -> bool {
    match tree.expression(id).map(|expression| expression.kind) {
        Some(ExprKind::DefaultValue) => true,
        Some(ExprKind::Identifier(_)) => true,
        Some(ExprKind::Array {
            elements,
            element_count,
        }) => element_count == count && elements[..element_count].iter().all(Option::is_some),
        Some(ExprKind::ArrayRepeat { count: repeat, .. }) => repeat == count,
        Some(
            ExprKind::If {
                then_branch,
                else_branch,
                ..
            }
            | ExprKind::LoopBreakIf {
                then_branch,
                else_branch,
                ..
            },
        ) => matches!(
            (
                tree.expression(then_branch).map(|expression| expression.kind),
                tree.expression(else_branch).map(|expression| expression.kind),
            ),
            (
                Some(ExprKind::Array {
                    elements: then_elements,
                    element_count: then_count,
                }),
                Some(ExprKind::Array {
                    elements: else_elements,
                    element_count: else_count,
                }),
            ) if then_count == count
                && else_count == count
                && then_elements[..then_count].iter().all(Option::is_some)
                && else_elements[..else_count].iter().all(Option::is_some)
        ),
        _ => false,
    }
}

fn runtime_fat_reference_return_preanalysis_supported<const MAX_NODES: usize>(
    tree: &crate::ExpressionTree<'_, MAX_NODES>,
    id: crate::ExprId,
    depth: usize,
) -> bool {
    if depth == 64 {
        return false;
    }
    match tree.expression(id).map(|expression| expression.kind) {
        Some(ExprKind::Identifier(_) | ExprKind::String(_) | ExprKind::ByteString(_)) => true,
        Some(ExprKind::CStrToBytes { base, .. }) => matches!(
            tree.expression(base).map(|expression| expression.kind),
            Some(ExprKind::CString(_))
        ),
        Some(ExprKind::Unary {
            operator: crate::UnaryOperator::AddressOf | crate::UnaryOperator::AddressOfMut,
            operand,
        }) => matches!(
            tree.expression(operand).map(|expression| expression.kind),
            Some(ExprKind::RangeIndex { .. })
        ),
        Some(
            ExprKind::If {
                then_branch,
                else_branch,
                ..
            }
            | ExprKind::LoopBreakIf {
                then_branch,
                else_branch,
                ..
            },
        ) => {
            runtime_fat_reference_return_preanalysis_supported(tree, then_branch, depth + 1)
                && runtime_fat_reference_return_preanalysis_supported(tree, else_branch, depth + 1)
        }
        Some(
            ExprKind::LoopBreak { operand }
            | ExprKind::Return { operand }
            | ExprKind::InlineConst { operand },
        ) => runtime_fat_reference_return_preanalysis_supported(tree, operand, depth + 1),
        Some(ExprKind::Sequence { then, .. }) => {
            runtime_fat_reference_return_preanalysis_supported(tree, then, depth + 1)
        }
        _ => false,
    }
}

fn runtime_type_is_array(ty: RuntimeExpressionType) -> bool {
    matches!(ty, RuntimeExpressionType::Array { .. })
}

fn runtime_type_is_tuple(ty: RuntimeExpressionType) -> bool {
    matches!(ty, RuntimeExpressionType::Tuple { .. })
}

fn runtime_type_supports_uninitialized_scalar(ty: RuntimeExpressionType) -> bool {
    matches!(
        ty,
        RuntimeExpressionType::Integer(Some(_))
            | RuntimeExpressionType::Bool
            | RuntimeExpressionType::Char
            | RuntimeExpressionType::RawPointer { .. }
            | RuntimeExpressionType::Reference {
                target: RuntimeReferenceTarget::Scalar(_),
                ..
            }
            | RuntimeExpressionType::Reference {
                target: RuntimeReferenceTarget::Str,
                mutable: false,
            }
    )
}

fn runtime_local_stack_slots(ty: RuntimeExpressionType) -> usize {
    let RuntimeExpressionType::Array { element, count } = ty else {
        return runtime_type_stack_slots(ty);
    };
    let Some(element_bytes @ (1 | 2 | 4)) = runtime_array_element_bytes(element) else {
        return count;
    };
    element_bytes
        .checked_mul(count)
        .and_then(|bytes| bytes.checked_add(7))
        .map_or(count, |bytes| bytes / 8)
}

fn runtime_expression_width(ty: RuntimeExpressionType) -> Option<RuntimeWidth> {
    match ty {
        RuntimeExpressionType::Integer(Some(integer_type)) => runtime_width(integer_type.name()),
        RuntimeExpressionType::Char => runtime_width("char"),
        RuntimeExpressionType::Array {
            element: RuntimeArrayElementType::Integer(Some(integer_type)),
            ..
        } => runtime_width(integer_type.name()),
        RuntimeExpressionType::Array {
            element: RuntimeArrayElementType::Char,
            ..
        } => runtime_width("char"),
        _ => None,
    }
}

fn runtime_type_from_scalar(ty: crate::ScalarType) -> RuntimeExpressionType {
    match ty {
        crate::ScalarType::Never => RuntimeExpressionType::Never,
        crate::ScalarType::Integer(ty) => RuntimeExpressionType::Integer(Some(ty)),
        crate::ScalarType::Bool => RuntimeExpressionType::Bool,
        crate::ScalarType::Char => RuntimeExpressionType::Char,
        crate::ScalarType::Unit => RuntimeExpressionType::Unit,
        crate::ScalarType::Array { element, count } => RuntimeExpressionType::Array {
            element: match element {
                crate::CallArrayElement::Unit => RuntimeArrayElementType::Unit,
                crate::CallArrayElement::Integer(ty) => RuntimeArrayElementType::Integer(Some(ty)),
                crate::CallArrayElement::Bool => RuntimeArrayElementType::Bool,
                crate::CallArrayElement::Char => RuntimeArrayElementType::Char,
            },
            count,
        },
        crate::ScalarType::Tuple {
            elements,
            element_count,
        } => {
            let mut runtime_elements = [None; crate::expression::MAX_TUPLE_ELEMENTS];
            for (index, element) in elements[..element_count].iter().enumerate() {
                runtime_elements[index] = element.map(|element| {
                    RuntimeTupleElementType::Scalar(match element {
                        crate::CallArrayElement::Unit => RuntimeArrayElementType::Unit,
                        crate::CallArrayElement::Integer(ty) => {
                            RuntimeArrayElementType::Integer(Some(ty))
                        }
                        crate::CallArrayElement::Bool => RuntimeArrayElementType::Bool,
                        crate::CallArrayElement::Char => RuntimeArrayElementType::Char,
                    })
                });
            }
            RuntimeExpressionType::Tuple {
                elements: runtime_elements,
                element_count,
            }
        }
        crate::ScalarType::RawPointer { pointee, mutable } => RuntimeExpressionType::RawPointer {
            pointee: match pointee {
                crate::PointerPointee::Integer(ty) => RuntimeArrayElementType::Integer(Some(ty)),
                crate::PointerPointee::Bool => RuntimeArrayElementType::Bool,
                crate::PointerPointee::Char => RuntimeArrayElementType::Char,
            },
            mutable,
        },
        crate::ScalarType::Reference { target, mutable } => RuntimeExpressionType::Reference {
            target: RuntimeReferenceTarget::Scalar(match target {
                crate::PointerPointee::Integer(ty) => RuntimeArrayElementType::Integer(Some(ty)),
                crate::PointerPointee::Bool => RuntimeArrayElementType::Bool,
                crate::PointerPointee::Char => RuntimeArrayElementType::Char,
            }),
            mutable,
        },
        crate::ScalarType::ArrayReference {
            element,
            count,
            mutable,
        } => RuntimeExpressionType::Reference {
            target: RuntimeReferenceTarget::Array {
                element: match element {
                    crate::CallArrayElement::Unit => RuntimeArrayElementType::Unit,
                    crate::CallArrayElement::Integer(ty) => {
                        RuntimeArrayElementType::Integer(Some(ty))
                    }
                    crate::CallArrayElement::Bool => RuntimeArrayElementType::Bool,
                    crate::CallArrayElement::Char => RuntimeArrayElementType::Char,
                },
                count,
                layout: RuntimeReferenceArrayLayout::Native,
            },
            mutable,
        },
        crate::ScalarType::SliceReference { element, mutable } => {
            RuntimeExpressionType::Reference {
                target: RuntimeReferenceTarget::Slice(match element {
                    crate::CallArrayElement::Unit => RuntimeArrayElementType::Unit,
                    crate::CallArrayElement::Integer(ty) => {
                        RuntimeArrayElementType::Integer(Some(ty))
                    }
                    crate::CallArrayElement::Bool => RuntimeArrayElementType::Bool,
                    crate::CallArrayElement::Char => RuntimeArrayElementType::Char,
                }),
                mutable,
            }
        }
        crate::ScalarType::StrReference { mutable } => RuntimeExpressionType::Reference {
            target: RuntimeReferenceTarget::Str,
            mutable,
        },
    }
}

fn runtime_array_element_bytes(element: RuntimeArrayElementType) -> Option<usize> {
    match element {
        RuntimeArrayElementType::Unit | RuntimeArrayElementType::Default => Some(0),
        RuntimeArrayElementType::Bool => Some(1),
        RuntimeArrayElementType::Char => Some(4),
        RuntimeArrayElementType::Integer(Some(ty)) => Some(usize::from(ty.bits(64)?) / 8),
        RuntimeArrayElementType::Integer(None) => None,
    }
}

fn runtime_array_abi_layout(ty: RuntimeExpressionType) -> Option<(usize, usize, usize)> {
    let RuntimeExpressionType::Array { element, count } = ty else {
        return None;
    };
    let element_bytes = runtime_array_element_bytes(element)?;
    let total_bytes = element_bytes.checked_mul(count)?;
    let words = total_bytes.checked_add(7)? / 8;
    Some((element_bytes, total_bytes, words))
}

fn runtime_array_elements_in_word(ty: RuntimeExpressionType, word: usize) -> Option<usize> {
    let RuntimeExpressionType::Array { element, count } = ty else {
        return None;
    };
    let element_bytes = runtime_array_element_bytes(element)?;
    Some(
        (0..count)
            .filter(|index| index * element_bytes / 8 == word)
            .count(),
    )
}

fn runtime_types_compatible(left: RuntimeExpressionType, right: RuntimeExpressionType) -> bool {
    match (left, right) {
        (RuntimeExpressionType::Never, _) => true,
        (RuntimeExpressionType::Default, _) | (_, RuntimeExpressionType::Default) => true,
        (RuntimeExpressionType::Unit, RuntimeExpressionType::Unit) => true,
        (RuntimeExpressionType::Bool, RuntimeExpressionType::Bool) => true,
        (RuntimeExpressionType::Char, RuntimeExpressionType::Char) => true,
        (
            RuntimeExpressionType::Reference {
                target: left,
                mutable: left_mutable,
            },
            RuntimeExpressionType::Reference {
                target: right,
                mutable: right_mutable,
            },
        ) => {
            let targets_compatible = match (left, right) {
                (RuntimeReferenceTarget::Scalar(left), RuntimeReferenceTarget::Scalar(right)) => {
                    left == right
                }
                (RuntimeReferenceTarget::Slice(left), RuntimeReferenceTarget::Slice(right)) => {
                    left == right
                }
                (RuntimeReferenceTarget::Str, RuntimeReferenceTarget::Str) => true,
                (
                    RuntimeReferenceTarget::Array {
                        element: left,
                        count: left_count,
                        ..
                    },
                    RuntimeReferenceTarget::Array {
                        element: right,
                        count: right_count,
                        ..
                    },
                ) => left == right && left_count == right_count,
                _ => false,
            };
            targets_compatible
                && (left_mutable == right_mutable || (left_mutable && !right_mutable))
        }
        (
            RuntimeExpressionType::RawPointer {
                pointee: left,
                mutable: left_mutable,
            },
            RuntimeExpressionType::RawPointer {
                pointee: right,
                mutable: right_mutable,
            },
        ) => left == right && (left_mutable == right_mutable || (left_mutable && !right_mutable)),
        (RuntimeExpressionType::Integer(left), RuntimeExpressionType::Integer(right)) => {
            left.is_none() || right.is_none() || left == right
        }
        (
            RuntimeExpressionType::Tuple {
                elements: left,
                element_count: left_count,
            },
            RuntimeExpressionType::Tuple {
                elements: right,
                element_count: right_count,
            },
        ) => {
            left_count == right_count
                && left[..left_count]
                    .iter()
                    .zip(&right[..right_count])
                    .all(|(left, right)| match (left, right) {
                        (Some(left), Some(right)) => runtime_types_compatible(
                            runtime_type_from_tuple_element(*left),
                            runtime_type_from_tuple_element(*right),
                        ),
                        _ => false,
                    })
        }
        (
            RuntimeExpressionType::Array {
                element: left,
                count: left_count,
            },
            RuntimeExpressionType::Array {
                element: right,
                count: right_count,
            },
        ) => {
            left_count == right_count
                && (left == RuntimeArrayElementType::Default
                    || right == RuntimeArrayElementType::Default
                    || left == right
                    || matches!(
                        (left, right),
                        (
                            RuntimeArrayElementType::Integer(None),
                            RuntimeArrayElementType::Integer(Some(_))
                        ) | (
                            RuntimeArrayElementType::Integer(Some(_)),
                            RuntimeArrayElementType::Integer(None)
                        )
                    ))
        }
        _ => false,
    }
}

fn reference_source_name<'source, const MAX_NODES: usize>(
    tree: &crate::ExpressionTree<'source, MAX_NODES>,
    id: crate::ExprId,
) -> Option<&'source str> {
    match tree.expression(id)?.kind {
        ExprKind::Identifier(name) => Some(name),
        ExprKind::StrAsBytes { base } => reference_source_name(tree, base),
        ExprKind::Unary {
            operator: crate::UnaryOperator::AddressOf | crate::UnaryOperator::AddressOfMut,
            operand,
        } => match tree.expression(operand)?.kind {
            ExprKind::Unary {
                operator: crate::UnaryOperator::Dereference,
                operand,
            } => reference_source_name(tree, operand),
            _ => None,
        },
        _ => None,
    }
}

fn constant_range_bounds<R: ConstantResolver, const MAX_NODES: usize>(
    tree: &crate::ExpressionTree<'_, MAX_NODES>,
    start: Option<crate::ExprId>,
    end: Option<crate::ExprId>,
    inclusive: bool,
    count: usize,
    resolver: &R,
) -> Result<(usize, usize), CodegenErrorKind> {
    let evaluate = |id| {
        tree.evaluate_at(id, resolver)
            .map_err(|error| match error {
                crate::ConstEvalError::UnknownIdentifier => {
                    CodegenErrorKind::RuntimeExpressionUnsupported
                }
                error => CodegenErrorKind::Execution(ExecutionError::Arithmetic(error)),
            })
            .and_then(|value| usize::try_from(value).map_err(|_| CodegenErrorKind::ValueOutOfRange))
    };
    let start = start.map_or(Ok(0), evaluate)?;
    let mut end = end.map_or_else(
        || {
            if inclusive {
                Err(CodegenErrorKind::RuntimeExpressionUnsupported)
            } else {
                Ok(count)
            }
        },
        evaluate,
    )?;
    if inclusive {
        end = end
            .checked_add(1)
            .ok_or(CodegenErrorKind::ValueOutOfRange)?;
    }
    if start > end || end > count {
        return Err(CodegenErrorKind::ValueOutOfRange);
    }
    Ok((start, end))
}

fn unify_integer_types(
    left: RuntimeExpressionType,
    right: RuntimeExpressionType,
) -> Result<Option<crate::IntegerType>, CodegenErrorKind> {
    let (RuntimeExpressionType::Integer(left), RuntimeExpressionType::Integer(right)) =
        (left, right)
    else {
        return Err(CodegenErrorKind::RuntimeTypeMismatch);
    };
    if left.is_some() && right.is_some() && left != right {
        return Err(CodegenErrorKind::RuntimeTypeMismatch);
    }
    Ok(left.or(right))
}

fn evaluate_runtime_call_arguments<R: ConstantResolver, const MAX_NODES: usize>(
    tree: &crate::ExpressionTree<'_, MAX_NODES>,
    arguments: [Option<crate::ExprId>; MAX_CALL_ARGUMENTS],
    argument_count: usize,
    resolver: &R,
) -> Result<[u128; MAX_CALL_ARGUMENTS], CodegenErrorKind> {
    let mut values = [0u128; MAX_CALL_ARGUMENTS];
    for (index, argument) in arguments[..argument_count].iter().enumerate() {
        values[index] = tree
            .evaluate_at(
                argument.ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)?,
                resolver,
            )
            .map_err(|error| CodegenErrorKind::Execution(ExecutionError::Arithmetic(error)))?;
    }
    Ok(values)
}

fn validate_runtime_inline_const<
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_NODES: usize,
>(
    function: &Function<'_, MAX_PARAMETERS>,
    resolver: &R,
    locals: &[Option<RuntimeLocal<'_>>],
    tree: &crate::ExpressionTree<'_, MAX_NODES>,
    id: crate::ExprId,
    depth: usize,
) -> Result<(), CodegenErrorKind> {
    if depth == 64 {
        return Err(CodegenErrorKind::Lowering(
            IrErrorKind::NestingLimitExceeded,
        ));
    }
    let expression = tree
        .expression(id)
        .ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)?;
    let recurse = |operand| {
        validate_runtime_inline_const(function, resolver, locals, tree, operand, depth + 1)
    };
    match expression.kind {
        ExprKind::Identifier(name) => {
            let captures_local = locals.iter().flatten().any(|local| local.name == name)
                || function
                    .parameters()
                    .iter()
                    .flatten()
                    .any(|parameter| parameter.name == name);
            if captures_local
                || (!resolver.resolves_bool(name) && resolver.resolve_type(name).is_none())
            {
                return Err(CodegenErrorKind::RuntimeExpressionUnsupported);
            }
        }
        ExprKind::Call {
            callee,
            arguments,
            argument_count,
            ..
        } if evaluate_runtime_call_arguments(tree, arguments, argument_count, resolver)
            .and_then(|values| {
                resolver
                    .resolve_call(callee, &values[..argument_count])
                    .ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)
            })
            .is_ok()
            && (resolver.call_resolves_bool(callee, argument_count)
                || resolver.resolve_call_type(callee, argument_count).is_some()) => {}
        ExprKind::Call { .. } => return Err(CodegenErrorKind::RuntimeExpressionUnsupported),
        ExprKind::Array {
            elements,
            element_count,
        } => {
            for element in elements[..element_count].iter().flatten() {
                recurse(*element)?;
            }
        }
        ExprKind::ArrayRepeat { element, .. } => recurse(element)?,
        ExprKind::Tuple {
            elements,
            element_count,
        } => {
            for element in elements[..element_count].iter().flatten() {
                recurse(*element)?;
            }
        }
        ExprKind::TupleField { base, .. } => recurse(base)?,
        ExprKind::Index { base, index } => {
            recurse(base)?;
            recurse(index)?;
        }
        ExprKind::RangeIndex {
            base, start, end, ..
        } => {
            recurse(base)?;
            if let Some(start) = start {
                recurse(start)?;
            }
            if let Some(end) = end {
                recurse(end)?;
            }
        }
        ExprKind::SliceLen { base } => recurse(base)?,
        ExprKind::SliceIsEmpty { base } => recurse(base)?,
        ExprKind::StrAsBytes { base } => recurse(base)?,
        ExprKind::CStrToBytes { base, .. } => recurse(base)?,
        ExprKind::StrIsCharBoundary { base, index } => {
            recurse(base)?;
            recurse(index)?;
        }
        ExprKind::ReferenceAsPointer { base, .. } => recurse(base)?,
        ExprKind::RawPointerIsNull { base } | ExprKind::RawPointerIsAligned { base } => {
            recurse(base)?
        }
        ExprKind::RawPointerAddress { base }
        | ExprKind::RawPointerMutability { base, .. }
        | ExprKind::RawPointerPointeeCast { base, .. }
        | ExprKind::RawPointerAsReference { base, .. } => recurse(base)?,
        ExprKind::RawPointerWithAddress { base, address } => {
            recurse(base)?;
            recurse(address)?;
        }
        ExprKind::RawPointerWithMetadata { base, metadata } => {
            recurse(base)?;
            recurse(metadata)?;
        }
        ExprKind::RawPointerWrite { base, value, .. } => {
            recurse(base)?;
            recurse(value)?;
        }
        ExprKind::RawPointerWriteBytes { base, value, count } => {
            recurse(base)?;
            recurse(value)?;
            recurse(count)?;
        }
        ExprKind::RawPointerCopy {
            source,
            destination,
            count,
            destination_first,
            ..
        } => {
            if destination_first {
                recurse(destination)?;
                recurse(source)?;
            } else {
                recurse(source)?;
                recurse(destination)?;
            }
            recurse(count)?;
        }
        ExprKind::RawPointerSwap { left, right } => {
            recurse(left)?;
            recurse(right)?;
        }
        ExprKind::RawPointerOffset { base, offset, .. } => {
            recurse(base)?;
            recurse(offset)?;
        }
        ExprKind::RawPointerDifference {
            pointer, origin, ..
        } => {
            recurse(pointer)?;
            recurse(origin)?;
        }
        ExprKind::RawPointerAlignOffset { base, alignment } => {
            recurse(base)?;
            recurse(alignment)?;
        }
        ExprKind::RawPointerMask { base, mask } => {
            recurse(base)?;
            recurse(mask)?;
        }
        ExprKind::RawPointerIsAlignedTo { base, alignment } => {
            recurse(base)?;
            recurse(alignment)?;
        }
        ExprKind::RawPointerDrop { base } => recurse(base)?,
        ExprKind::UnsignedIntegerPredicate { base, argument, .. } => {
            recurse(base)?;
            if let Some(argument) = argument {
                recurse(argument)?;
            }
        }
        ExprKind::SignedIntegerPredicate { base, .. } => recurse(base)?,
        ExprKind::AsciiPredicate { base, .. } => recurse(base)?,
        ExprKind::WrappingArithmetic { base, argument, .. } => {
            recurse(base)?;
            recurse(argument)?;
        }
        ExprKind::UncheckedIntegerOperation {
            base,
            argument,
            second_argument,
            ..
        } => {
            recurse(base)?;
            if let Some(argument) = argument {
                recurse(argument)?;
            }
            if let Some(second_argument) = second_argument {
                recurse(second_argument)?;
            }
        }
        ExprKind::CheckedIntegerOption { base, argument, .. } => {
            recurse(base)?;
            if let Some(argument) = argument {
                recurse(argument)?;
            }
        }
        ExprKind::IntegerOptionUnwrapOr {
            option, fallback, ..
        } => {
            recurse(option)?;
            if let Some(fallback) = fallback {
                recurse(fallback)?;
            }
        }
        ExprKind::IntegerOptionPredicate {
            option, closure, ..
        } => {
            recurse(option)?;
            if let Some(closure) = closure {
                recurse(closure)?;
            }
        }
        ExprKind::IntegerOptionMapOr {
            option,
            default,
            closure,
        } => {
            recurse(option)?;
            recurse(default)?;
            recurse(closure)?;
        }
        ExprKind::IntegerOptionMapOrElse {
            option,
            default_closure,
            map_closure,
        } => {
            recurse(option)?;
            recurse(default_closure)?;
            recurse(map_closure)?;
        }
        ExprKind::IntegerOptionMapOrDefault {
            option,
            map_closure,
        } => {
            recurse(option)?;
            recurse(map_closure)?;
        }
        ExprKind::IntegerOptionMap { option, closure } => {
            recurse(option)?;
            recurse(closure)?;
        }
        ExprKind::IntegerOptionAndThen { option, closure } => {
            recurse(option)?;
            recurse(closure)?;
        }
        ExprKind::IntegerOptionOrElse { option, closure } => {
            recurse(option)?;
            recurse(closure)?;
        }
        ExprKind::IntegerOptionOr {
            option,
            alternative,
        } => {
            recurse(option)?;
            recurse(alternative)?;
        }
        ExprKind::IntegerOptionXor {
            option,
            alternative,
        } => {
            recurse(option)?;
            recurse(alternative)?;
        }
        ExprKind::IntegerOptionAnd {
            option,
            alternative,
        } => {
            recurse(option)?;
            recurse(alternative)?;
        }
        ExprKind::IntegerOptionThenSome { condition, value } => {
            recurse(condition)?;
            recurse(value)?;
        }
        ExprKind::IntegerOptionThen { condition, closure } => {
            recurse(condition)?;
            recurse(closure)?;
        }
        ExprKind::IntegerOptionInspect { option, closure } => {
            recurse(option)?;
            recurse(closure)?;
        }
        ExprKind::IntegerOptionFilter { option, closure } => {
            recurse(option)?;
            recurse(closure)?;
        }
        ExprKind::Closure { body, .. } => recurse(body)?,
        ExprKind::SaturatingArithmetic { base, argument, .. } => {
            recurse(base)?;
            recurse(argument)?;
        }
        ExprKind::IntegerRotate { base, distance, .. } => {
            recurse(base)?;
            recurse(distance)?;
        }
        ExprKind::IntegerFunnelShift {
            base,
            other,
            distance,
            ..
        } => {
            recurse(base)?;
            recurse(other)?;
            recurse(distance)?;
        }
        ExprKind::IntegerSignCast { base, .. } | ExprKind::IntegerWidthCast { base, .. } => {
            recurse(base)?
        }
        ExprKind::IntegerClampMagnitude { base, limit } => {
            recurse(base)?;
            recurse(limit)?;
        }
        ExprKind::IntegerEndianFrom { value, .. } => recurse(value)?,
        ExprKind::IntegerFromBytes { bytes, .. } => recurse(bytes)?,
        ExprKind::IntegerToBytes { base, .. } => recurse(base)?,
        ExprKind::IntegerAssociatedConstant { .. } => {}
        ExprKind::IntegerWrappingShift { base, distance, .. } => {
            recurse(base)?;
            recurse(distance)?;
        }
        ExprKind::IntegerWrappingPower { base, exponent, .. } => {
            recurse(base)?;
            recurse(exponent)?;
        }
        ExprKind::IntegerBitTransform { base, .. } => recurse(base)?,
        ExprKind::IntegerUnsignedAbsolute { base } => recurse(base)?,
        ExprKind::IntegerPairTransform { base, other, .. } => {
            recurse(base)?;
            recurse(other)?;
        }
        ExprKind::IntegerClamp {
            base,
            minimum,
            maximum,
        } => {
            recurse(base)?;
            recurse(minimum)?;
            recurse(maximum)?;
        }
        ExprKind::IntegerBitCount { base, .. } => recurse(base)?,
        ExprKind::IntegerLogarithm { base, radix, .. } => {
            recurse(base)?;
            if let Some(radix) = radix {
                recurse(radix)?;
            }
        }
        ExprKind::Cast { operand, .. }
        | ExprKind::Ascribe { operand, .. }
        | ExprKind::Unary { operand, .. }
        | ExprKind::Return { operand }
        | ExprKind::LoopBreak { operand }
        | ExprKind::InlineConst { operand }
        | ExprKind::UnsafeBlock { operand } => recurse(operand)?,
        ExprKind::Binary { left, right, .. } => {
            recurse(left)?;
            recurse(right)?;
        }
        ExprKind::Sequence { first, then } => {
            recurse(first)?;
            recurse(then)?;
        }
        ExprKind::If {
            condition,
            then_branch,
            else_branch,
        }
        | ExprKind::LoopBreakIf {
            condition,
            then_branch,
            else_branch,
        } => {
            recurse(condition)?;
            recurse(then_branch)?;
            recurse(else_branch)?;
        }
        ExprKind::Unit
        | ExprKind::DefaultValue
        | ExprKind::Integer(_)
        | ExprKind::Bool(_)
        | ExprKind::Char(_)
        | ExprKind::ByteChar(_)
        | ExprKind::String(_)
        | ExprKind::ByteString(_)
        | ExprKind::CString(_)
        | ExprKind::ClosureParameter { .. } => {}
    }
    Ok(())
}

fn runtime_expression_type<
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_NODES: usize,
>(
    function: &Function<'_, MAX_PARAMETERS>,
    resolver: &R,
    tree: &crate::ExpressionTree<'_, MAX_NODES>,
    id: crate::ExprId,
    depth: usize,
) -> Result<RuntimeExpressionType, CodegenErrorKind> {
    runtime_expression_type_with_locals(function, resolver, &[], tree, id, depth)
}

fn checked_option_integer_type<
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_NODES: usize,
>(
    function: &Function<'_, MAX_PARAMETERS>,
    resolver: &R,
    locals: &[Option<RuntimeLocal<'_>>],
    tree: &crate::ExpressionTree<'_, MAX_NODES>,
    id: crate::ExprId,
    depth: usize,
) -> Result<crate::IntegerType, CodegenErrorKind> {
    let expression = tree
        .expression(id)
        .ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)?;
    if let ExprKind::IntegerOptionFilter { option, .. } = expression.kind {
        return checked_option_integer_type(function, resolver, locals, tree, option, depth + 1);
    }
    if let ExprKind::IntegerOptionMap { option, closure } = expression.kind {
        let input_type =
            checked_option_integer_type(function, resolver, locals, tree, option, depth + 1)?;
        let closure_expression = tree
            .expression(closure)
            .ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)?;
        let ExprKind::Closure {
            parameter: Some(parameter),
            body,
        } = closure_expression.kind
        else {
            return Err(CodegenErrorKind::RuntimeTypeMismatch);
        };
        let mut closure_tree = *tree;
        closure_tree
            .bind_closure_parameter(parameter, input_type)
            .map_err(CodegenErrorKind::Expression)?;
        let RuntimeExpressionType::Integer(Some(output_type)) =
            runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                &closure_tree,
                body,
                depth + 1,
            )?
        else {
            return Err(CodegenErrorKind::RuntimeTypeMismatch);
        };
        return Ok(output_type);
    }
    if let ExprKind::IntegerOptionAndThen { option, closure } = expression.kind {
        let input_type =
            checked_option_integer_type(function, resolver, locals, tree, option, depth + 1)?;
        let closure_expression = tree
            .expression(closure)
            .ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)?;
        let ExprKind::Closure {
            parameter: Some(parameter),
            body,
        } = closure_expression.kind
        else {
            return Err(CodegenErrorKind::RuntimeTypeMismatch);
        };
        let mut closure_tree = *tree;
        closure_tree
            .bind_closure_parameter(parameter, input_type)
            .map_err(CodegenErrorKind::Expression)?;
        return checked_option_integer_type(
            function,
            resolver,
            locals,
            &closure_tree,
            body,
            depth + 1,
        );
    }
    if let ExprKind::IntegerOptionOrElse { option, closure } = expression.kind {
        let input_type =
            checked_option_integer_type(function, resolver, locals, tree, option, depth + 1)?;
        let closure_expression = tree
            .expression(closure)
            .ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)?;
        let ExprKind::Closure {
            parameter: None,
            body,
        } = closure_expression.kind
        else {
            return Err(CodegenErrorKind::RuntimeTypeMismatch);
        };
        let output_type =
            checked_option_integer_type(function, resolver, locals, tree, body, depth + 1)?;
        return (output_type == input_type)
            .then_some(input_type)
            .ok_or(CodegenErrorKind::RuntimeTypeMismatch);
    }
    if let ExprKind::IntegerOptionOr {
        option,
        alternative,
    } = expression.kind
    {
        let input_type =
            checked_option_integer_type(function, resolver, locals, tree, option, depth + 1)?;
        let alternative_type =
            checked_option_integer_type(function, resolver, locals, tree, alternative, depth + 1)?;
        return (alternative_type == input_type)
            .then_some(input_type)
            .ok_or(CodegenErrorKind::RuntimeTypeMismatch);
    }
    if let ExprKind::IntegerOptionXor {
        option,
        alternative,
    } = expression.kind
    {
        let input_type =
            checked_option_integer_type(function, resolver, locals, tree, option, depth + 1)?;
        let alternative_type =
            checked_option_integer_type(function, resolver, locals, tree, alternative, depth + 1)?;
        return (alternative_type == input_type)
            .then_some(input_type)
            .ok_or(CodegenErrorKind::RuntimeTypeMismatch);
    }
    if let ExprKind::IntegerOptionAnd {
        option,
        alternative,
    } = expression.kind
    {
        checked_option_integer_type(function, resolver, locals, tree, option, depth + 1)?;
        return checked_option_integer_type(
            function,
            resolver,
            locals,
            tree,
            alternative,
            depth + 1,
        );
    }
    if let ExprKind::IntegerOptionThenSome { condition, value } = expression.kind {
        if runtime_expression_type_with_locals(
            function,
            resolver,
            locals,
            tree,
            condition,
            depth + 1,
        )? != RuntimeExpressionType::Bool
        {
            return Err(CodegenErrorKind::RuntimeTypeMismatch);
        }
        let RuntimeExpressionType::Integer(Some(output_type)) =
            runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                value,
                depth + 1,
            )?
        else {
            return Err(CodegenErrorKind::RuntimeTypeMismatch);
        };
        return Ok(output_type);
    }
    if let ExprKind::IntegerOptionThen { condition, closure } = expression.kind {
        if runtime_expression_type_with_locals(
            function,
            resolver,
            locals,
            tree,
            condition,
            depth + 1,
        )? != RuntimeExpressionType::Bool
        {
            return Err(CodegenErrorKind::RuntimeTypeMismatch);
        }
        let closure_expression = tree
            .expression(closure)
            .ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)?;
        let ExprKind::Closure {
            parameter: None,
            body,
        } = closure_expression.kind
        else {
            return Err(CodegenErrorKind::RuntimeTypeMismatch);
        };
        let RuntimeExpressionType::Integer(Some(output_type)) =
            runtime_expression_type_with_locals(function, resolver, locals, tree, body, depth + 1)?
        else {
            return Err(CodegenErrorKind::RuntimeTypeMismatch);
        };
        return Ok(output_type);
    }
    if let ExprKind::IntegerOptionInspect { option, closure } = expression.kind {
        let input_type =
            checked_option_integer_type(function, resolver, locals, tree, option, depth + 1)?;
        let closure_expression = tree
            .expression(closure)
            .ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)?;
        let ExprKind::Closure {
            parameter: Some(parameter),
            body,
        } = closure_expression.kind
        else {
            return Err(CodegenErrorKind::RuntimeTypeMismatch);
        };
        let mut closure_tree = *tree;
        closure_tree
            .bind_closure_reference_parameter(parameter, input_type)
            .map_err(CodegenErrorKind::Expression)?;
        if runtime_expression_type_with_locals(
            function,
            resolver,
            locals,
            &closure_tree,
            body,
            depth + 1,
        )? != RuntimeExpressionType::Unit
        {
            return Err(CodegenErrorKind::RuntimeTypeMismatch);
        }
        return Ok(input_type);
    }
    let ExprKind::CheckedIntegerOption {
        base, operation, ..
    } = expression.kind
    else {
        return Err(CodegenErrorKind::RuntimeTypeMismatch);
    };
    let base_type =
        runtime_expression_type_with_locals(function, resolver, locals, tree, base, depth + 1)?;
    match operation {
        crate::expression::CheckedIntegerOptionOperation::Cast(target)
        | crate::expression::CheckedIntegerOptionOperation::Truncate(target) => Ok(target),
        crate::expression::CheckedIntegerOptionOperation::SignedDifference => {
            let RuntimeExpressionType::Integer(Some(source)) = base_type else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            source
                .signed_counterpart()
                .ok_or(CodegenErrorKind::RuntimeTypeMismatch)
        }
        crate::expression::CheckedIntegerOptionOperation::Logarithm { .. } => {
            Ok(crate::IntegerType::U32)
        }
        crate::expression::CheckedIntegerOptionOperation::SignCast { signed } => {
            let RuntimeExpressionType::Integer(Some(source)) = base_type else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            if signed {
                source.signed_counterpart()
            } else {
                source.unsigned_counterpart()
            }
            .ok_or(CodegenErrorKind::RuntimeTypeMismatch)
        }
        _ => {
            let RuntimeExpressionType::Integer(Some(source)) = base_type else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            Ok(source)
        }
    }
}

fn validate_option_filter<
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_NODES: usize,
>(
    function: &Function<'_, MAX_PARAMETERS>,
    resolver: &R,
    locals: &[Option<RuntimeLocal<'_>>],
    tree: &crate::ExpressionTree<'_, MAX_NODES>,
    id: crate::ExprId,
    depth: usize,
) -> Result<Option<crate::ExprId>, CodegenErrorKind> {
    let expression = tree
        .expression(id)
        .ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)?;
    let ExprKind::IntegerOptionFilter { option, closure } = expression.kind else {
        return Ok(None);
    };
    let result_type =
        checked_option_integer_type(function, resolver, locals, tree, option, depth + 1)?;
    let closure_expression = tree
        .expression(closure)
        .ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)?;
    let ExprKind::Closure {
        parameter: Some(parameter),
        body,
    } = closure_expression.kind
    else {
        return Err(CodegenErrorKind::RuntimeTypeMismatch);
    };
    let mut closure_tree = *tree;
    closure_tree
        .bind_closure_reference_parameter(parameter, result_type)
        .map_err(CodegenErrorKind::Expression)?;
    if runtime_expression_type_with_locals(
        function,
        resolver,
        locals,
        &closure_tree,
        body,
        depth + 1,
    )? != RuntimeExpressionType::Bool
    {
        return Err(CodegenErrorKind::RuntimeTypeMismatch);
    }
    Ok(Some(option))
}

fn validate_runtime_range_endpoints<
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_NODES: usize,
>(
    function: &Function<'_, MAX_PARAMETERS>,
    resolver: &R,
    locals: &[Option<RuntimeLocal<'_>>],
    tree: &crate::ExpressionTree<'_, MAX_NODES>,
) -> Result<(), CodegenErrorKind> {
    for validation in tree.range_validations().iter().flatten() {
        let layout = match runtime_expression_type_with_locals(
            function,
            resolver,
            locals,
            tree,
            validation.scrutinee,
            1,
        )? {
            RuntimeExpressionType::Integer(Some(ty)) => {
                runtime_integer_layout(ty.name()).ok_or(CodegenErrorKind::UnsupportedRuntimeType)?
            }
            RuntimeExpressionType::Char => {
                runtime_integer_layout("char").ok_or(CodegenErrorKind::UnsupportedRuntimeType)?
            }
            RuntimeExpressionType::Integer(None) => continue,
            RuntimeExpressionType::Bool => return Err(CodegenErrorKind::InvalidRangeType),
            RuntimeExpressionType::Never
            | RuntimeExpressionType::Unit
            | RuntimeExpressionType::Default => {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            RuntimeExpressionType::Array { .. }
            | RuntimeExpressionType::Tuple { .. }
            | RuntimeExpressionType::Reference { .. }
            | RuntimeExpressionType::RawPointer { .. } => {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
        };
        for endpoint in [validation.start, validation.end].into_iter().flatten() {
            let expression = tree
                .expression(endpoint)
                .ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)?;
            let fits = match expression.kind {
                ExprKind::Integer(literal) => {
                    runtime_integer_literal_fits(layout, literal.value, false)
                }
                ExprKind::Unary {
                    operator: crate::UnaryOperator::Negate,
                    operand,
                } => match tree.expression(operand).map(|operand| operand.kind) {
                    Some(ExprKind::Integer(literal)) => {
                        runtime_integer_literal_fits(layout, literal.value, true)
                    }
                    _ => true,
                },
                ExprKind::Identifier(name) => match resolver.resolve_type(name) {
                    Some(ty) => {
                        let Some(endpoint_layout) = runtime_integer_layout(ty.name()) else {
                            return Err(CodegenErrorKind::UnsupportedRuntimeType);
                        };
                        endpoint_layout == layout
                    }
                    None => true,
                },
                ExprKind::Char(value) => u128::from(value) <= layout.maximum,
                ExprKind::Bool(_) => return Err(CodegenErrorKind::InvalidRangeType),
                _ => true,
            };
            if !fits {
                return Err(CodegenErrorKind::RangeEndpointOutOfRange);
            }
        }
    }
    Ok(())
}

fn runtime_integer_literal_fits(
    layout: RuntimeIntegerLayout,
    magnitude: u128,
    negative: bool,
) -> bool {
    if negative {
        layout.signed && magnitude <= layout.minimum.unsigned_abs()
    } else {
        magnitude <= layout.maximum
    }
}

fn runtime_expression_type_with_locals<
    R: ConstantResolver,
    const MAX_PARAMETERS: usize,
    const MAX_NODES: usize,
>(
    function: &Function<'_, MAX_PARAMETERS>,
    resolver: &R,
    locals: &[Option<RuntimeLocal<'_>>],
    tree: &crate::ExpressionTree<'_, MAX_NODES>,
    id: crate::ExprId,
    depth: usize,
) -> Result<RuntimeExpressionType, CodegenErrorKind> {
    if depth == 0 {
        tree.validate_ranges(resolver, 64)
            .map_err(|error| match error {
                crate::ConstEvalError::InvalidRangeType => CodegenErrorKind::InvalidRangeType,
                crate::ConstEvalError::InvalidRangeBounds => CodegenErrorKind::InvalidRangeBounds,
                error => CodegenErrorKind::Execution(ExecutionError::Arithmetic(error)),
            })?;
        validate_runtime_range_endpoints(function, resolver, locals, tree)?;
    }
    if depth == 64 {
        return Err(CodegenErrorKind::Lowering(
            IrErrorKind::NestingLimitExceeded,
        ));
    }
    let expression = tree
        .expression(id)
        .ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)?;
    let unsafe_context = function.unsafe_function || tree.is_within_unsafe_block(id);
    match expression.kind {
        ExprKind::UnsafeBlock { operand } => runtime_expression_type_with_locals(
            function,
            resolver,
            locals,
            tree,
            operand,
            depth + 1,
        ),
        ExprKind::Unit => Ok(RuntimeExpressionType::Unit),
        ExprKind::DefaultValue => Ok(RuntimeExpressionType::Default),
        ExprKind::Array {
            elements,
            element_count,
        } => {
            let mut element_type = RuntimeArrayElementType::Default;
            for element in elements[..element_count].iter().flatten() {
                let current = runtime_array_element_type(runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    *element,
                    depth + 1,
                )?)?;
                if element_type == RuntimeArrayElementType::Default {
                    element_type = current;
                } else if current != RuntimeArrayElementType::Default && current != element_type {
                    let compatible_integer = matches!(
                        (element_type, current),
                        (
                            RuntimeArrayElementType::Integer(None),
                            RuntimeArrayElementType::Integer(Some(_))
                        ) | (
                            RuntimeArrayElementType::Integer(Some(_)),
                            RuntimeArrayElementType::Integer(None)
                        )
                    );
                    if !compatible_integer {
                        return Err(CodegenErrorKind::RuntimeTypeMismatch);
                    }
                    if matches!(element_type, RuntimeArrayElementType::Integer(None)) {
                        element_type = current;
                    }
                }
            }
            Ok(RuntimeExpressionType::Array {
                element: element_type,
                count: element_count,
            })
        }
        ExprKind::ArrayRepeat { element, count } => Ok(RuntimeExpressionType::Array {
            element: runtime_array_element_type(runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                element,
                depth + 1,
            )?)?,
            count,
        }),
        ExprKind::Tuple {
            elements,
            element_count,
        } => {
            let mut types = [None; crate::expression::MAX_TUPLE_ELEMENTS];
            for (index, element) in elements[..element_count].iter().enumerate() {
                let element = element.ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)?;
                types[index] = Some(runtime_tuple_element_type(
                    runtime_expression_type_with_locals(
                        function,
                        resolver,
                        locals,
                        tree,
                        element,
                        depth + 1,
                    )?,
                )?);
            }
            Ok(RuntimeExpressionType::Tuple {
                elements: types,
                element_count,
            })
        }
        ExprKind::TupleField { base, field } => {
            let RuntimeExpressionType::Tuple {
                elements,
                element_count,
            } = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )?
            else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            if field >= element_count {
                return Err(CodegenErrorKind::ValueOutOfRange);
            }
            Ok(runtime_type_from_tuple_element(
                elements[field].ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)?,
            ))
        }
        ExprKind::Index { base, index } => {
            let index_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                index,
                depth + 1,
            )?;
            if !matches!(
                index_type,
                RuntimeExpressionType::Integer(None)
                    | RuntimeExpressionType::Integer(Some(crate::IntegerType::Usize))
            ) {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            let base_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )?;
            let element = match base_type {
                RuntimeExpressionType::Array { element, .. }
                | RuntimeExpressionType::Reference {
                    target: RuntimeReferenceTarget::Array { element, .. },
                    ..
                }
                | RuntimeExpressionType::Reference {
                    target: RuntimeReferenceTarget::Slice(element),
                    ..
                } => element,
                _ => return Err(CodegenErrorKind::RuntimeTypeMismatch),
            };
            Ok(runtime_type_from_array_element(element))
        }
        ExprKind::RangeIndex {
            base, start, end, ..
        } => {
            for bound in [start, end].into_iter().flatten() {
                if !matches!(
                    runtime_expression_type_with_locals(
                        function,
                        resolver,
                        locals,
                        tree,
                        bound,
                        depth + 1,
                    )?,
                    RuntimeExpressionType::Integer(None)
                        | RuntimeExpressionType::Integer(Some(crate::IntegerType::Usize))
                ) {
                    return Err(CodegenErrorKind::RuntimeTypeMismatch);
                }
            }
            match runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )? {
                RuntimeExpressionType::Reference {
                    target:
                        RuntimeReferenceTarget::Array { element, .. }
                        | RuntimeReferenceTarget::Slice(element),
                    mutable,
                } => Ok(RuntimeExpressionType::Reference {
                    target: RuntimeReferenceTarget::Slice(element),
                    mutable,
                }),
                _ => Err(CodegenErrorKind::RuntimeExpressionUnsupported),
            }
        }
        ExprKind::SliceLen { base } => {
            let base_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )?;
            if !matches!(
                base_type,
                RuntimeExpressionType::Reference {
                    target: RuntimeReferenceTarget::Slice(_) | RuntimeReferenceTarget::Str,
                    ..
                }
            ) {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(RuntimeExpressionType::Integer(Some(
                crate::IntegerType::Usize,
            )))
        }
        ExprKind::RawPointerDrop { base } => {
            if !unsafe_context {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            if !matches!(
                runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    base,
                    depth + 1,
                )?,
                RuntimeExpressionType::RawPointer { mutable: true, .. }
            ) {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(RuntimeExpressionType::Unit)
        }
        ExprKind::UnsignedIntegerPredicate {
            base,
            argument,
            power_of_two,
        } => {
            let base_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )?;
            let RuntimeExpressionType::Integer(Some(integer_type)) = base_type else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            if integer_type.is_signed()
                || (!power_of_two
                    && !runtime_types_compatible(
                        runtime_expression_type_with_locals(
                            function,
                            resolver,
                            locals,
                            tree,
                            argument.ok_or(CodegenErrorKind::RuntimeTypeMismatch)?,
                            depth + 1,
                        )?,
                        base_type,
                    ))
            {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(RuntimeExpressionType::Bool)
        }
        ExprKind::SignedIntegerPredicate { base, .. } => {
            let RuntimeExpressionType::Integer(Some(integer_type)) =
                runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    base,
                    depth + 1,
                )?
            else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            if !integer_type.is_signed() {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(RuntimeExpressionType::Bool)
        }
        ExprKind::AsciiPredicate { base, .. } => {
            if runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )? != RuntimeExpressionType::Integer(Some(crate::IntegerType::U8))
            {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(RuntimeExpressionType::Bool)
        }
        ExprKind::SliceIsEmpty { base } => {
            let base_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )?;
            if !matches!(
                base_type,
                RuntimeExpressionType::Reference {
                    target: RuntimeReferenceTarget::Slice(_) | RuntimeReferenceTarget::Str,
                    ..
                }
            ) {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(RuntimeExpressionType::Bool)
        }
        ExprKind::StrAsBytes { base } => {
            let base_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )?;
            let RuntimeExpressionType::Reference {
                target: RuntimeReferenceTarget::Str,
                ..
            } = base_type
            else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            Ok(RuntimeExpressionType::Reference {
                target: RuntimeReferenceTarget::Slice(RuntimeArrayElementType::Integer(Some(
                    crate::IntegerType::U8,
                ))),
                mutable: false,
            })
        }
        ExprKind::CStrToBytes { base, .. } => {
            if !matches!(
                tree.expression(base).map(|expression| expression.kind),
                Some(ExprKind::CString(_))
            ) {
                return Err(CodegenErrorKind::UnsupportedCStringLiteral);
            }
            Ok(RuntimeExpressionType::Reference {
                target: RuntimeReferenceTarget::Slice(RuntimeArrayElementType::Integer(Some(
                    crate::IntegerType::U8,
                ))),
                mutable: false,
            })
        }
        ExprKind::StrIsCharBoundary { base, index } => {
            if !matches!(
                runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    base,
                    depth + 1,
                )?,
                RuntimeExpressionType::Reference {
                    target: RuntimeReferenceTarget::Str,
                    ..
                }
            ) || !matches!(
                runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    index,
                    depth + 1,
                )?,
                RuntimeExpressionType::Integer(None)
                    | RuntimeExpressionType::Integer(Some(crate::IntegerType::Usize))
            ) {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(RuntimeExpressionType::Bool)
        }
        ExprKind::ReferenceAsPointer { base, mutable } => {
            if matches!(
                tree.expression(base).map(|expression| expression.kind),
                Some(ExprKind::CString(_))
            ) {
                if mutable {
                    return Err(CodegenErrorKind::ImmutableAssignment);
                }
                return Ok(RuntimeExpressionType::RawPointer {
                    pointee: RuntimeArrayElementType::Integer(Some(crate::IntegerType::I8)),
                    mutable: false,
                });
            }
            let base_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )?;
            let (pointee, base_mutable) = match base_type {
                RuntimeExpressionType::Reference {
                    target:
                        RuntimeReferenceTarget::Slice(pointee)
                        | RuntimeReferenceTarget::Array {
                            element: pointee, ..
                        },
                    mutable,
                } => (pointee, mutable),
                RuntimeExpressionType::Reference {
                    target: RuntimeReferenceTarget::Str,
                    mutable,
                } => (
                    RuntimeArrayElementType::Integer(Some(crate::IntegerType::U8)),
                    mutable,
                ),
                _ => return Err(CodegenErrorKind::RuntimeTypeMismatch),
            };
            if mutable && !base_mutable {
                return Err(CodegenErrorKind::ImmutableAssignment);
            }
            Ok(RuntimeExpressionType::RawPointer { pointee, mutable })
        }
        ExprKind::RawPointerIsNull { base } => {
            if !matches!(
                runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    base,
                    depth + 1,
                )?,
                RuntimeExpressionType::RawPointer { .. }
            ) {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(RuntimeExpressionType::Bool)
        }
        ExprKind::RawPointerIsAligned { base } => {
            if !matches!(
                runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    base,
                    depth + 1,
                )?,
                RuntimeExpressionType::RawPointer { .. }
            ) {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(RuntimeExpressionType::Bool)
        }
        ExprKind::RawPointerAddress { base } => {
            if !matches!(
                runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    base,
                    depth + 1,
                )?,
                RuntimeExpressionType::RawPointer { .. }
            ) {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(RuntimeExpressionType::Integer(Some(
                crate::IntegerType::Usize,
            )))
        }
        ExprKind::RawPointerMutability { base, mutable } => {
            let RuntimeExpressionType::RawPointer { pointee, .. } =
                runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    base,
                    depth + 1,
                )?
            else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            Ok(RuntimeExpressionType::RawPointer { pointee, mutable })
        }
        ExprKind::RawPointerPointeeCast { base, pointee } => {
            let RuntimeExpressionType::RawPointer { mutable, .. } =
                runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    base,
                    depth + 1,
                )?
            else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            let pointee = match pointee {
                crate::PointerPointee::Integer(ty) => RuntimeArrayElementType::Integer(Some(ty)),
                crate::PointerPointee::Bool => RuntimeArrayElementType::Bool,
                crate::PointerPointee::Char => RuntimeArrayElementType::Char,
            };
            Ok(RuntimeExpressionType::RawPointer { pointee, mutable })
        }
        ExprKind::RawPointerAsReference { base, mutable } => {
            if !unsafe_context {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            let RuntimeExpressionType::RawPointer {
                pointee,
                mutable: pointer_mutable,
            } = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )?
            else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            if mutable && !pointer_mutable {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(RuntimeExpressionType::Reference {
                target: RuntimeReferenceTarget::Scalar(pointee),
                mutable,
            })
        }
        ExprKind::RawPointerWithAddress { base, address } => {
            let base_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )?;
            if !matches!(base_type, RuntimeExpressionType::RawPointer { .. })
                || !matches!(
                    runtime_expression_type_with_locals(
                        function,
                        resolver,
                        locals,
                        tree,
                        address,
                        depth + 1,
                    )?,
                    RuntimeExpressionType::Integer(None)
                        | RuntimeExpressionType::Integer(Some(crate::IntegerType::Usize))
                )
            {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(base_type)
        }
        ExprKind::RawPointerWithMetadata { base, metadata } => {
            let RuntimeExpressionType::RawPointer { mutable, .. } =
                runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    base,
                    depth + 1,
                )?
            else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            let RuntimeExpressionType::RawPointer { pointee, .. } =
                runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    metadata,
                    depth + 1,
                )?
            else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            Ok(RuntimeExpressionType::RawPointer { pointee, mutable })
        }
        ExprKind::RawPointerWrite {
            base,
            value,
            returns_old,
        } => {
            if !unsafe_context {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            let RuntimeExpressionType::RawPointer {
                pointee,
                mutable: true,
            } = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )?
            else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            let expected = runtime_type_from_array_element(pointee);
            let actual = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                value,
                depth + 1,
            )?;
            if !runtime_types_compatible(actual, expected) {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            if returns_old {
                Ok(expected)
            } else {
                Ok(RuntimeExpressionType::Unit)
            }
        }
        ExprKind::RawPointerWriteBytes { base, value, count } => {
            if !unsafe_context {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            let RuntimeExpressionType::RawPointer { mutable: true, .. } =
                runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    base,
                    depth + 1,
                )?
            else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            if !matches!(
                runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    value,
                    depth + 1,
                )?,
                RuntimeExpressionType::Integer(None)
                    | RuntimeExpressionType::Integer(Some(crate::IntegerType::U8))
            ) || !matches!(
                runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    count,
                    depth + 1,
                )?,
                RuntimeExpressionType::Integer(None)
                    | RuntimeExpressionType::Integer(Some(crate::IntegerType::Usize))
            ) {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(RuntimeExpressionType::Unit)
        }
        ExprKind::RawPointerCopy {
            source,
            destination,
            count,
            ..
        } => {
            if !unsafe_context {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            let RuntimeExpressionType::RawPointer { pointee, .. } =
                runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    source,
                    depth + 1,
                )?
            else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            if runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                destination,
                depth + 1,
            )? != (RuntimeExpressionType::RawPointer {
                pointee,
                mutable: true,
            }) || !matches!(
                runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    count,
                    depth + 1,
                )?,
                RuntimeExpressionType::Integer(None)
                    | RuntimeExpressionType::Integer(Some(crate::IntegerType::Usize))
            ) {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(RuntimeExpressionType::Unit)
        }
        ExprKind::RawPointerSwap { left, right } => {
            if !unsafe_context {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            let RuntimeExpressionType::RawPointer {
                pointee,
                mutable: true,
            } = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                left,
                depth + 1,
            )?
            else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            if runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                right,
                depth + 1,
            )? != (RuntimeExpressionType::RawPointer {
                pointee,
                mutable: true,
            }) {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(RuntimeExpressionType::Unit)
        }
        ExprKind::WrappingArithmetic {
            base,
            argument,
            operator,
            euclidean,
            euclidean_wrapping: _,
            strict,
            mixed_signedness,
        } => {
            let base_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )?;
            let argument_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                argument,
                depth + 1,
            )?;
            match base_type {
                RuntimeExpressionType::RawPointer { .. }
                    if !euclidean
                        && !strict
                        && matches!(
                            operator,
                            crate::BinaryOperator::Add | crate::BinaryOperator::Subtract
                        )
                        && matches!(
                            argument_type,
                            RuntimeExpressionType::Integer(None)
                                | RuntimeExpressionType::Integer(Some(crate::IntegerType::Usize))
                        ) =>
                {
                    Ok(base_type)
                }
                RuntimeExpressionType::Integer(Some(integer_type)) => {
                    let expected_argument = if mixed_signedness {
                        if integer_type.is_signed() {
                            integer_type.unsigned_counterpart()
                        } else {
                            integer_type.signed_counterpart()
                        }
                        .map(|ty| RuntimeExpressionType::Integer(Some(ty)))
                    } else {
                        Some(base_type)
                    };
                    if expected_argument == Some(argument_type)
                        || (!mixed_signedness
                            && argument_type == RuntimeExpressionType::Integer(None))
                    {
                        Ok(base_type)
                    } else {
                        Err(CodegenErrorKind::RuntimeTypeMismatch)
                    }
                }
                _ => Err(CodegenErrorKind::RuntimeTypeMismatch),
            }
        }
        ExprKind::UncheckedIntegerOperation {
            base,
            argument,
            second_argument,
            operator,
            unary,
            disjoint,
            funnel,
        } => {
            if !unsafe_context {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            let base_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )?;
            let RuntimeExpressionType::Integer(Some(integer_type)) = base_type else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            if funnel {
                let argument = argument.ok_or(CodegenErrorKind::RuntimeTypeMismatch)?;
                let distance = second_argument.ok_or(CodegenErrorKind::RuntimeTypeMismatch)?;
                if integer_type.is_signed()
                    || runtime_expression_type_with_locals(
                        function,
                        resolver,
                        locals,
                        tree,
                        argument,
                        depth + 1,
                    )? != base_type
                    || !matches!(
                        runtime_expression_type_with_locals(
                            function,
                            resolver,
                            locals,
                            tree,
                            distance,
                            depth + 1,
                        )?,
                        RuntimeExpressionType::Integer(None)
                            | RuntimeExpressionType::Integer(Some(crate::IntegerType::U32))
                    )
                {
                    return Err(CodegenErrorKind::RuntimeTypeMismatch);
                }
                return Ok(base_type);
            }
            if second_argument.is_some() {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            if unary {
                if argument.is_some() {
                    return Err(CodegenErrorKind::RuntimeTypeMismatch);
                }
                return if integer_type.is_signed() {
                    Ok(base_type)
                } else {
                    Err(CodegenErrorKind::RuntimeTypeMismatch)
                };
            }
            let argument = argument.ok_or(CodegenErrorKind::RuntimeTypeMismatch)?;
            let argument_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                argument,
                depth + 1,
            )?;
            if matches!(
                operator,
                crate::BinaryOperator::ShiftLeft | crate::BinaryOperator::ShiftRight
            ) {
                if !matches!(
                    argument_type,
                    RuntimeExpressionType::Integer(None)
                        | RuntimeExpressionType::Integer(Some(crate::IntegerType::U32))
                ) {
                    return Err(CodegenErrorKind::RuntimeTypeMismatch);
                }
            } else if argument_type != base_type {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            if disjoint && integer_type.is_signed() {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(base_type)
        }
        ExprKind::CheckedIntegerOption { .. } => {
            Err(CodegenErrorKind::RuntimeExpressionUnsupported)
        }
        ExprKind::IntegerOptionUnwrapOr {
            option,
            fallback,
            trap,
            message,
            unchecked,
            lazy,
        } => {
            if unchecked && !unsafe_context {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            if matches!(
                tree.expression(option).map(|expression| expression.kind),
                Some(
                    ExprKind::IntegerOptionMap { .. }
                        | ExprKind::IntegerOptionAndThen { .. }
                        | ExprKind::IntegerOptionOrElse { .. }
                        | ExprKind::IntegerOptionOr { .. }
                        | ExprKind::IntegerOptionXor { .. }
                        | ExprKind::IntegerOptionAnd { .. }
                        | ExprKind::IntegerOptionThenSome { .. }
                        | ExprKind::IntegerOptionThen { .. }
                )
            ) {
                let result_type =
                    RuntimeExpressionType::Integer(Some(checked_option_integer_type(
                        function,
                        resolver,
                        locals,
                        tree,
                        option,
                        depth + 1,
                    )?));
                let producer = match tree
                    .expression(option)
                    .ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)?
                    .kind
                {
                    ExprKind::IntegerOptionMap { option, .. }
                    | ExprKind::IntegerOptionAndThen { option, .. }
                    | ExprKind::IntegerOptionOrElse { option, .. }
                    | ExprKind::IntegerOptionOr { option, .. }
                    | ExprKind::IntegerOptionXor { option, .. }
                    | ExprKind::IntegerOptionAnd { option, .. } => Some(option),
                    ExprKind::IntegerOptionThenSome { .. } | ExprKind::IntegerOptionThen { .. } => {
                        None
                    }
                    _ => unreachable!(),
                };
                if let Some(producer) = producer {
                    let mut producer_tree = *tree;
                    producer_tree
                        .replace_kind(
                            id,
                            ExprKind::IntegerOptionUnwrapOr {
                                option: producer,
                                fallback: None,
                                trap: true,
                                message: false,
                                unchecked: false,
                                lazy: false,
                            },
                        )
                        .map_err(CodegenErrorKind::Expression)?;
                    runtime_expression_type_with_locals(
                        function,
                        resolver,
                        locals,
                        &producer_tree,
                        id,
                        depth + 1,
                    )?;
                }
                let fallback_matches = if let Some(fallback) = fallback {
                    let fallback_expression = tree
                        .expression(fallback)
                        .ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)?;
                    let fallback_value = if lazy {
                        let ExprKind::Closure {
                            parameter: None,
                            body,
                        } = fallback_expression.kind
                        else {
                            return Err(CodegenErrorKind::RuntimeTypeMismatch);
                        };
                        body
                    } else {
                        fallback
                    };
                    let fallback_type = runtime_expression_type_with_locals(
                        function,
                        resolver,
                        locals,
                        tree,
                        fallback_value,
                        depth + 1,
                    )?;
                    if message {
                        matches!(
                            fallback_type,
                            RuntimeExpressionType::Reference {
                                target: RuntimeReferenceTarget::Str,
                                ..
                            }
                        )
                    } else {
                        runtime_types_compatible(fallback_type, result_type)
                    }
                } else {
                    !message && !lazy
                };
                return fallback_matches
                    .then_some(result_type)
                    .ok_or(CodegenErrorKind::RuntimeTypeMismatch);
            }
            if let Some(ExprKind::IntegerOptionInspect {
                option: producer, ..
            }) = tree.expression(option).map(|expression| expression.kind)
            {
                let result_type =
                    RuntimeExpressionType::Integer(Some(checked_option_integer_type(
                        function,
                        resolver,
                        locals,
                        tree,
                        option,
                        depth + 1,
                    )?));
                let mut producer_tree = *tree;
                producer_tree
                    .replace_kind(
                        id,
                        ExprKind::IntegerOptionUnwrapOr {
                            option: producer,
                            fallback,
                            trap,
                            message,
                            unchecked,
                            lazy,
                        },
                    )
                    .map_err(CodegenErrorKind::Expression)?;
                let producer_result = runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    &producer_tree,
                    id,
                    depth + 1,
                )?;
                if message || runtime_types_compatible(producer_result, result_type) {
                    return Ok(result_type);
                }
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            if let Some(producer) =
                validate_option_filter(function, resolver, locals, tree, option, depth + 1)?
            {
                let mut producer_tree = *tree;
                producer_tree
                    .replace_kind(
                        id,
                        ExprKind::IntegerOptionUnwrapOr {
                            option: producer,
                            fallback,
                            trap,
                            message,
                            unchecked,
                            lazy,
                        },
                    )
                    .map_err(CodegenErrorKind::Expression)?;
                return runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    &producer_tree,
                    id,
                    depth + 1,
                );
            }
            let option = tree
                .expression(option)
                .ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)?;
            let ExprKind::CheckedIntegerOption {
                base,
                argument,
                operation,
            } = option.kind
            else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            let base_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )?;
            let result_type = match operation {
                crate::expression::CheckedIntegerOptionOperation::ExactDivision
                | crate::expression::CheckedIntegerOptionOperation::Division { .. }
                | crate::expression::CheckedIntegerOptionOperation::Arithmetic(_)
                | crate::expression::CheckedIntegerOptionOperation::NextMultiple
                    if argument.is_some_and(|argument| {
                        runtime_expression_type_with_locals(
                            function,
                            resolver,
                            locals,
                            tree,
                            argument,
                            depth + 1,
                        ) == Ok(base_type)
                    }) =>
                {
                    base_type
                }
                crate::expression::CheckedIntegerOptionOperation::Cast(target)
                    if argument.is_none() =>
                {
                    RuntimeExpressionType::Integer(Some(target))
                }
                crate::expression::CheckedIntegerOptionOperation::Truncate(target)
                    if argument.is_none()
                        && matches!(base_type, RuntimeExpressionType::Integer(Some(source)) if source.supports_width_cast(target, crate::expression::IntegerWidthCastMode::Truncate)) =>
                {
                    RuntimeExpressionType::Integer(Some(target))
                }
                crate::expression::CheckedIntegerOptionOperation::SignedUnary { absolute }
                    if argument.is_none()
                        && matches!(base_type, RuntimeExpressionType::Integer(Some(source)) if !absolute || source.is_signed()) =>
                {
                    base_type
                }
                crate::expression::CheckedIntegerOptionOperation::SquareRoot
                    if argument.is_none()
                        && matches!(base_type, RuntimeExpressionType::Integer(Some(source)) if source.is_signed()) =>
                {
                    base_type
                }
                crate::expression::CheckedIntegerOptionOperation::SignedDifference
                    if argument.is_some_and(|argument| {
                        runtime_expression_type_with_locals(
                            function,
                            resolver,
                            locals,
                            tree,
                            argument,
                            depth + 1,
                        ) == Ok(base_type)
                    }) =>
                {
                    let RuntimeExpressionType::Integer(Some(source)) = base_type else {
                        return Err(CodegenErrorKind::RuntimeTypeMismatch);
                    };
                    if source.is_signed() {
                        return Err(CodegenErrorKind::RuntimeTypeMismatch);
                    }
                    RuntimeExpressionType::Integer(Some(
                        source
                            .signed_counterpart()
                            .ok_or(CodegenErrorKind::RuntimeTypeMismatch)?,
                    ))
                }
                crate::expression::CheckedIntegerOptionOperation::NextPowerOfTwo
                    if argument.is_none()
                        && matches!(base_type, RuntimeExpressionType::Integer(Some(source)) if !source.is_signed()) =>
                {
                    base_type
                }
                crate::expression::CheckedIntegerOptionOperation::Logarithm { .. }
                    if argument.is_none_or(|argument| {
                        runtime_expression_type_with_locals(
                            function,
                            resolver,
                            locals,
                            tree,
                            argument,
                            depth + 1,
                        ) == Ok(base_type)
                    }) =>
                {
                    RuntimeExpressionType::Integer(Some(crate::IntegerType::U32))
                }
                crate::expression::CheckedIntegerOptionOperation::UnsignedMixedArithmetic {
                    ..
                } if argument.is_some_and(|argument| {
                    let RuntimeExpressionType::Integer(Some(source)) = base_type else {
                        return false;
                    };
                    !source.is_signed()
                        && source.signed_counterpart().is_some_and(|signed| {
                            runtime_expression_type_with_locals(
                                function,
                                resolver,
                                locals,
                                tree,
                                argument,
                                depth + 1,
                            ) == Ok(RuntimeExpressionType::Integer(Some(signed)))
                        })
                }) =>
                {
                    base_type
                }
                crate::expression::CheckedIntegerOptionOperation::SignedMixedArithmetic {
                    ..
                } if argument.is_some_and(|argument| {
                    let RuntimeExpressionType::Integer(Some(source)) = base_type else {
                        return false;
                    };
                    source.is_signed()
                        && source.unsigned_counterpart().is_some_and(|unsigned| {
                            runtime_expression_type_with_locals(
                                function,
                                resolver,
                                locals,
                                tree,
                                argument,
                                depth + 1,
                            ) == Ok(RuntimeExpressionType::Integer(Some(unsigned)))
                        })
                }) =>
                {
                    base_type
                }
                crate::expression::CheckedIntegerOptionOperation::Shift { .. }
                | crate::expression::CheckedIntegerOptionOperation::Power
                    if argument.is_some_and(|argument| {
                        matches!(
                            runtime_expression_type_with_locals(
                                function,
                                resolver,
                                locals,
                                tree,
                                argument,
                                depth + 1,
                            ),
                            Ok(RuntimeExpressionType::Integer(None))
                                | Ok(RuntimeExpressionType::Integer(Some(
                                    crate::IntegerType::U32
                                )))
                        )
                    }) =>
                {
                    base_type
                }
                crate::expression::CheckedIntegerOptionOperation::SignCast { signed }
                    if argument.is_none() =>
                {
                    let RuntimeExpressionType::Integer(Some(source)) = base_type else {
                        return Err(CodegenErrorKind::RuntimeTypeMismatch);
                    };
                    if source.is_signed() == signed {
                        return Err(CodegenErrorKind::RuntimeTypeMismatch);
                    }
                    RuntimeExpressionType::Integer(Some(
                        if signed {
                            source.signed_counterpart()
                        } else {
                            source.unsigned_counterpart()
                        }
                        .ok_or(CodegenErrorKind::RuntimeTypeMismatch)?,
                    ))
                }
                _ => return Err(CodegenErrorKind::RuntimeTypeMismatch),
            };
            let fallback_matches = if let Some(fallback) = fallback {
                let fallback_expression = tree
                    .expression(fallback)
                    .ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)?;
                let fallback_value = if lazy {
                    let ExprKind::Closure {
                        parameter: None,
                        body,
                    } = fallback_expression.kind
                    else {
                        return Err(CodegenErrorKind::RuntimeTypeMismatch);
                    };
                    body
                } else {
                    fallback
                };
                let fallback_type = runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    fallback_value,
                    depth + 1,
                )?;
                if message {
                    matches!(
                        fallback_type,
                        RuntimeExpressionType::Reference {
                            target: RuntimeReferenceTarget::Str,
                            ..
                        }
                    )
                } else {
                    runtime_types_compatible(fallback_type, result_type)
                }
            } else {
                !message && !lazy
            };
            if !matches!(base_type, RuntimeExpressionType::Integer(Some(_))) || !fallback_matches {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(result_type)
        }
        ExprKind::IntegerOptionPredicate {
            option,
            some,
            closure,
        } => {
            let option_expression = tree
                .expression(option)
                .ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)?;
            if let ExprKind::IntegerOptionInspect {
                option: producer, ..
            } = option_expression.kind
            {
                checked_option_integer_type(function, resolver, locals, tree, option, depth + 1)?;
                let mut producer_tree = *tree;
                producer_tree
                    .replace_kind(
                        id,
                        ExprKind::IntegerOptionPredicate {
                            option: producer,
                            some,
                            closure,
                        },
                    )
                    .map_err(CodegenErrorKind::Expression)?;
                return runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    &producer_tree,
                    id,
                    depth + 1,
                );
            }
            if matches!(
                option_expression.kind,
                ExprKind::IntegerOptionMap { .. }
                    | ExprKind::IntegerOptionAndThen { .. }
                    | ExprKind::IntegerOptionOrElse { .. }
                    | ExprKind::IntegerOptionOr { .. }
                    | ExprKind::IntegerOptionXor { .. }
                    | ExprKind::IntegerOptionAnd { .. }
                    | ExprKind::IntegerOptionThenSome { .. }
                    | ExprKind::IntegerOptionThen { .. }
            ) {
                let producer = match option_expression.kind {
                    ExprKind::IntegerOptionMap { option, .. }
                    | ExprKind::IntegerOptionAndThen { option, .. }
                    | ExprKind::IntegerOptionOrElse { option, .. }
                    | ExprKind::IntegerOptionOr { option, .. }
                    | ExprKind::IntegerOptionXor { option, .. }
                    | ExprKind::IntegerOptionAnd { option, .. } => Some(option),
                    ExprKind::IntegerOptionThenSome { .. } | ExprKind::IntegerOptionThen { .. } => {
                        None
                    }
                    _ => unreachable!(),
                };
                let input_type = checked_option_integer_type(
                    function,
                    resolver,
                    locals,
                    tree,
                    option,
                    depth + 1,
                )?;
                if let Some(producer) = producer {
                    let mut producer_tree = *tree;
                    producer_tree
                        .replace_kind(
                            id,
                            ExprKind::IntegerOptionPredicate {
                                option: producer,
                                some,
                                closure: None,
                            },
                        )
                        .map_err(CodegenErrorKind::Expression)?;
                    runtime_expression_type_with_locals(
                        function,
                        resolver,
                        locals,
                        &producer_tree,
                        id,
                        depth + 1,
                    )?;
                }
                if let Some(closure) = closure {
                    let closure_expression = tree
                        .expression(closure)
                        .ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)?;
                    let ExprKind::Closure {
                        parameter: Some(parameter),
                        body,
                    } = closure_expression.kind
                    else {
                        return Err(CodegenErrorKind::RuntimeTypeMismatch);
                    };
                    let mut closure_tree = *tree;
                    closure_tree
                        .bind_closure_parameter(parameter, input_type)
                        .map_err(CodegenErrorKind::Expression)?;
                    if runtime_expression_type_with_locals(
                        function,
                        resolver,
                        locals,
                        &closure_tree,
                        body,
                        depth + 1,
                    )? != RuntimeExpressionType::Bool
                    {
                        return Err(CodegenErrorKind::RuntimeTypeMismatch);
                    }
                }
                return Ok(RuntimeExpressionType::Bool);
            }
            if let ExprKind::IntegerOptionFilter {
                option: producer,
                closure: filter_closure,
            } = option_expression.kind
            {
                let mut producer_tree = *tree;
                producer_tree
                    .replace_kind(
                        id,
                        ExprKind::IntegerOptionPredicate {
                            option: producer,
                            some,
                            closure,
                        },
                    )
                    .map_err(CodegenErrorKind::Expression)?;
                runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    &producer_tree,
                    id,
                    depth + 1,
                )?;
                let result_type = checked_option_integer_type(
                    function,
                    resolver,
                    locals,
                    tree,
                    producer,
                    depth + 1,
                )?;
                let filter_expression = tree
                    .expression(filter_closure)
                    .ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)?;
                let ExprKind::Closure {
                    parameter: Some(parameter),
                    body,
                } = filter_expression.kind
                else {
                    return Err(CodegenErrorKind::RuntimeTypeMismatch);
                };
                let mut filter_tree = *tree;
                filter_tree
                    .bind_closure_reference_parameter(parameter, result_type)
                    .map_err(CodegenErrorKind::Expression)?;
                if runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    &filter_tree,
                    body,
                    depth + 1,
                )? != RuntimeExpressionType::Bool
                {
                    return Err(CodegenErrorKind::RuntimeTypeMismatch);
                }
                return Ok(RuntimeExpressionType::Bool);
            }
            let option = option_expression;
            let ExprKind::CheckedIntegerOption {
                base,
                argument,
                operation,
            } = option.kind
            else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            let base_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )?;
            let producer_valid = match operation {
                crate::expression::CheckedIntegerOptionOperation::ExactDivision => argument
                    .is_some_and(|argument| {
                        runtime_expression_type_with_locals(
                            function,
                            resolver,
                            locals,
                            tree,
                            argument,
                            depth + 1,
                        ) == Ok(base_type)
                    }),
                crate::expression::CheckedIntegerOptionOperation::Division { .. } => argument
                    .is_some_and(|argument| {
                        runtime_expression_type_with_locals(
                            function,
                            resolver,
                            locals,
                            tree,
                            argument,
                            depth + 1,
                        ) == Ok(base_type)
                    }),
                crate::expression::CheckedIntegerOptionOperation::Arithmetic(_) => argument
                    .is_some_and(|argument| {
                        runtime_expression_type_with_locals(
                            function,
                            resolver,
                            locals,
                            tree,
                            argument,
                            depth + 1,
                        ) == Ok(base_type)
                    }),
                crate::expression::CheckedIntegerOptionOperation::NextMultiple => argument
                    .is_some_and(|argument| {
                        runtime_expression_type_with_locals(
                            function,
                            resolver,
                            locals,
                            tree,
                            argument,
                            depth + 1,
                        ) == Ok(base_type)
                    }),
                crate::expression::CheckedIntegerOptionOperation::SignedUnary { absolute } => {
                    argument.is_none()
                        && matches!(base_type, RuntimeExpressionType::Integer(Some(source)) if !absolute || source.is_signed())
                }
                crate::expression::CheckedIntegerOptionOperation::SquareRoot => {
                    argument.is_none()
                        && matches!(base_type, RuntimeExpressionType::Integer(Some(source)) if source.is_signed())
                }
                crate::expression::CheckedIntegerOptionOperation::SignedDifference => argument
                    .is_some_and(|argument| {
                        runtime_expression_type_with_locals(
                            function,
                            resolver,
                            locals,
                            tree,
                            argument,
                            depth + 1,
                        ) == Ok(base_type)
                            && matches!(base_type, RuntimeExpressionType::Integer(Some(source)) if !source.is_signed())
                    }),
                crate::expression::CheckedIntegerOptionOperation::NextPowerOfTwo => {
                    argument.is_none()
                        && matches!(base_type, RuntimeExpressionType::Integer(Some(source)) if !source.is_signed())
                }
                crate::expression::CheckedIntegerOptionOperation::Logarithm { .. } => argument
                    .is_none_or(|argument| {
                        runtime_expression_type_with_locals(
                            function,
                            resolver,
                            locals,
                            tree,
                            argument,
                            depth + 1,
                        ) == Ok(base_type)
                    }),
                crate::expression::CheckedIntegerOptionOperation::UnsignedMixedArithmetic {
                    ..
                } => argument.is_some_and(|argument| {
                    let RuntimeExpressionType::Integer(Some(source)) = base_type else {
                        return false;
                    };
                    !source.is_signed()
                        && source.signed_counterpart().is_some_and(|signed| {
                            runtime_expression_type_with_locals(
                                function,
                                resolver,
                                locals,
                                tree,
                                argument,
                                depth + 1,
                            ) == Ok(RuntimeExpressionType::Integer(Some(signed)))
                        })
                }),
                crate::expression::CheckedIntegerOptionOperation::SignedMixedArithmetic {
                    ..
                } => argument.is_some_and(|argument| {
                    let RuntimeExpressionType::Integer(Some(source)) = base_type else {
                        return false;
                    };
                    source.is_signed()
                        && source.unsigned_counterpart().is_some_and(|unsigned| {
                            runtime_expression_type_with_locals(
                                function,
                                resolver,
                                locals,
                                tree,
                                argument,
                                depth + 1,
                            ) == Ok(RuntimeExpressionType::Integer(Some(unsigned)))
                        })
                }),
                crate::expression::CheckedIntegerOptionOperation::Shift { .. }
                | crate::expression::CheckedIntegerOptionOperation::Power => {
                    argument.is_some_and(|argument| {
                        matches!(
                            runtime_expression_type_with_locals(
                                function,
                                resolver,
                                locals,
                                tree,
                                argument,
                                depth + 1,
                            ),
                            Ok(RuntimeExpressionType::Integer(None))
                                | Ok(RuntimeExpressionType::Integer(Some(
                                    crate::IntegerType::U32
                                )))
                        )
                    })
                }
                crate::expression::CheckedIntegerOptionOperation::Cast(_) => argument.is_none(),
                crate::expression::CheckedIntegerOptionOperation::Truncate(target) => {
                    argument.is_none()
                        && matches!(base_type, RuntimeExpressionType::Integer(Some(source)) if source.supports_width_cast(target, crate::expression::IntegerWidthCastMode::Truncate))
                }
                crate::expression::CheckedIntegerOptionOperation::SignCast { signed } => {
                    argument.is_none()
                        && matches!(base_type, RuntimeExpressionType::Integer(Some(source)) if source.is_signed() != signed)
                }
            };
            if !matches!(base_type, RuntimeExpressionType::Integer(Some(_))) || !producer_valid {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            if let Some(closure) = closure {
                let closure = tree
                    .expression(closure)
                    .ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)?;
                let ExprKind::Closure {
                    parameter: Some(parameter),
                    body,
                } = closure.kind
                else {
                    return Err(CodegenErrorKind::RuntimeTypeMismatch);
                };
                let result_type = match operation {
                    crate::expression::CheckedIntegerOptionOperation::Cast(target)
                    | crate::expression::CheckedIntegerOptionOperation::Truncate(target) => {
                        RuntimeExpressionType::Integer(Some(target))
                    }
                    crate::expression::CheckedIntegerOptionOperation::SignedDifference => {
                        let RuntimeExpressionType::Integer(Some(source)) = base_type else {
                            return Err(CodegenErrorKind::RuntimeTypeMismatch);
                        };
                        RuntimeExpressionType::Integer(Some(
                            source
                                .signed_counterpart()
                                .ok_or(CodegenErrorKind::RuntimeTypeMismatch)?,
                        ))
                    }
                    crate::expression::CheckedIntegerOptionOperation::Logarithm { .. } => {
                        RuntimeExpressionType::Integer(Some(crate::IntegerType::U32))
                    }
                    crate::expression::CheckedIntegerOptionOperation::SignCast { signed } => {
                        let RuntimeExpressionType::Integer(Some(source)) = base_type else {
                            return Err(CodegenErrorKind::RuntimeTypeMismatch);
                        };
                        RuntimeExpressionType::Integer(Some(
                            if signed {
                                source.signed_counterpart()
                            } else {
                                source.unsigned_counterpart()
                            }
                            .ok_or(CodegenErrorKind::RuntimeTypeMismatch)?,
                        ))
                    }
                    _ => base_type,
                };
                let RuntimeExpressionType::Integer(Some(result_type)) = result_type else {
                    return Err(CodegenErrorKind::RuntimeTypeMismatch);
                };
                let mut closure_tree = *tree;
                closure_tree
                    .bind_closure_parameter(parameter, result_type)
                    .map_err(CodegenErrorKind::Expression)?;
                if runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    &closure_tree,
                    body,
                    depth + 1,
                )? != RuntimeExpressionType::Bool
                {
                    return Err(CodegenErrorKind::RuntimeTypeMismatch);
                }
            }
            Ok(RuntimeExpressionType::Bool)
        }
        ExprKind::IntegerOptionMapOr {
            option,
            default,
            closure,
        } => {
            let mut producer_tree = *tree;
            producer_tree
                .replace_kind(
                    id,
                    ExprKind::IntegerOptionPredicate {
                        option,
                        some: true,
                        closure: None,
                    },
                )
                .map_err(CodegenErrorKind::Expression)?;
            runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                &producer_tree,
                id,
                depth + 1,
            )?;
            let input_type =
                checked_option_integer_type(function, resolver, locals, tree, option, depth + 1)?;
            let closure_expression = tree
                .expression(closure)
                .ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)?;
            let ExprKind::Closure {
                parameter: Some(parameter),
                body,
            } = closure_expression.kind
            else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            let mut closure_tree = *tree;
            closure_tree
                .bind_closure_parameter(parameter, input_type)
                .map_err(CodegenErrorKind::Expression)?;
            let default_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                default,
                depth + 1,
            )?;
            let mapped_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                &closure_tree,
                body,
                depth + 1,
            )?;
            if !runtime_types_compatible(default_type, mapped_type) {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            let output_type = match (default_type, mapped_type) {
                (RuntimeExpressionType::Integer(None), typed)
                | (typed, RuntimeExpressionType::Integer(None)) => typed,
                (typed, _) => typed,
            };
            if matches!(
                output_type,
                RuntimeExpressionType::Default | RuntimeExpressionType::Array { .. }
            ) || runtime_type_stack_slots(output_type) != 1
            {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(output_type)
        }
        ExprKind::IntegerOptionMapOrElse {
            option,
            default_closure,
            map_closure,
        } => {
            let default_expression = tree
                .expression(default_closure)
                .ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)?;
            let ExprKind::Closure {
                parameter: None,
                body: default,
            } = default_expression.kind
            else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            let mut mapped_tree = *tree;
            mapped_tree
                .replace_kind(
                    id,
                    ExprKind::IntegerOptionMapOr {
                        option,
                        default,
                        closure: map_closure,
                    },
                )
                .map_err(CodegenErrorKind::Expression)?;
            runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                &mapped_tree,
                id,
                depth + 1,
            )
        }
        ExprKind::IntegerOptionMapOrDefault {
            option,
            map_closure,
        } => {
            let input_type =
                checked_option_integer_type(function, resolver, locals, tree, option, depth + 1)?;
            let map_expression = tree
                .expression(map_closure)
                .ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)?;
            let ExprKind::Closure {
                parameter: Some(parameter),
                body,
            } = map_expression.kind
            else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            let mut mapped_tree = *tree;
            mapped_tree
                .bind_closure_parameter(parameter, input_type)
                .map_err(CodegenErrorKind::Expression)?;
            mapped_tree
                .replace_kind(
                    id,
                    ExprKind::IntegerOptionMapOr {
                        option,
                        default: body,
                        closure: map_closure,
                    },
                )
                .map_err(CodegenErrorKind::Expression)?;
            let output = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                &mapped_tree,
                id,
                depth + 1,
            )?;
            if matches!(output, RuntimeExpressionType::Reference { .. }) {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(output)
        }
        ExprKind::IntegerOptionMap { .. } => {
            checked_option_integer_type(function, resolver, locals, tree, id, depth + 1)?;
            Err(CodegenErrorKind::RuntimeExpressionUnsupported)
        }
        ExprKind::IntegerOptionAndThen { .. } => {
            checked_option_integer_type(function, resolver, locals, tree, id, depth + 1)?;
            Err(CodegenErrorKind::RuntimeExpressionUnsupported)
        }
        ExprKind::IntegerOptionOrElse { .. } => {
            checked_option_integer_type(function, resolver, locals, tree, id, depth + 1)?;
            Err(CodegenErrorKind::RuntimeExpressionUnsupported)
        }
        ExprKind::IntegerOptionOr { .. } => {
            checked_option_integer_type(function, resolver, locals, tree, id, depth + 1)?;
            Err(CodegenErrorKind::RuntimeExpressionUnsupported)
        }
        ExprKind::IntegerOptionXor { .. } => {
            checked_option_integer_type(function, resolver, locals, tree, id, depth + 1)?;
            Err(CodegenErrorKind::RuntimeExpressionUnsupported)
        }
        ExprKind::IntegerOptionAnd { .. } => {
            checked_option_integer_type(function, resolver, locals, tree, id, depth + 1)?;
            Err(CodegenErrorKind::RuntimeExpressionUnsupported)
        }
        ExprKind::IntegerOptionThenSome { .. } | ExprKind::IntegerOptionThen { .. } => {
            checked_option_integer_type(function, resolver, locals, tree, id, depth + 1)?;
            Err(CodegenErrorKind::RuntimeExpressionUnsupported)
        }
        ExprKind::IntegerOptionInspect { .. } => {
            checked_option_integer_type(function, resolver, locals, tree, id, depth + 1)?;
            Err(CodegenErrorKind::RuntimeExpressionUnsupported)
        }
        ExprKind::IntegerOptionFilter { .. } => Err(CodegenErrorKind::RuntimeExpressionUnsupported),
        ExprKind::SaturatingArithmetic {
            base,
            argument,
            mixed_signedness,
            ..
        } => {
            let base_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )?;
            let argument_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                argument,
                depth + 1,
            )?;
            let RuntimeExpressionType::Integer(Some(integer_type)) = base_type else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            let expected_argument = if mixed_signedness {
                if integer_type.is_signed() {
                    integer_type.unsigned_counterpart()
                } else {
                    integer_type.signed_counterpart()
                }
                .map(|ty| RuntimeExpressionType::Integer(Some(ty)))
            } else {
                Some(base_type)
            };
            if expected_argument != Some(argument_type) {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(base_type)
        }
        ExprKind::IntegerRotate { base, distance, .. } => {
            let base_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )?;
            if !matches!(base_type, RuntimeExpressionType::Integer(Some(_)))
                || !matches!(
                    runtime_expression_type_with_locals(
                        function,
                        resolver,
                        locals,
                        tree,
                        distance,
                        depth + 1,
                    )?,
                    RuntimeExpressionType::Integer(None)
                        | RuntimeExpressionType::Integer(Some(crate::IntegerType::U32))
                )
            {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(base_type)
        }
        ExprKind::IntegerFunnelShift {
            base,
            other,
            distance,
            ..
        } => {
            let base_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )?;
            let other_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                other,
                depth + 1,
            )?;
            let RuntimeExpressionType::Integer(Some(integer_type)) = base_type else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            if integer_type.is_signed()
                || other_type != base_type
                || !matches!(
                    runtime_expression_type_with_locals(
                        function,
                        resolver,
                        locals,
                        tree,
                        distance,
                        depth + 1
                    )?,
                    RuntimeExpressionType::Integer(None)
                        | RuntimeExpressionType::Integer(Some(crate::IntegerType::U32))
                )
            {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(base_type)
        }
        ExprKind::IntegerSignCast { base, signed, .. } => {
            let RuntimeExpressionType::Integer(Some(source_type)) =
                runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    base,
                    depth + 1,
                )?
            else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            if source_type.is_signed() == signed {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            let target_type = if signed {
                source_type.signed_counterpart()
            } else {
                source_type.unsigned_counterpart()
            }
            .ok_or(CodegenErrorKind::RuntimeTypeMismatch)?;
            Ok(RuntimeExpressionType::Integer(Some(target_type)))
        }
        ExprKind::IntegerWidthCast { base, target, mode } => {
            if mode == crate::expression::IntegerWidthCastMode::Unchecked && !unsafe_context {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            let RuntimeExpressionType::Integer(Some(source_type)) =
                runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    base,
                    depth + 1,
                )?
            else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            if !source_type.supports_width_cast(target, mode) {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(RuntimeExpressionType::Integer(Some(target)))
        }
        ExprKind::IntegerClampMagnitude { base, limit } => {
            let base_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )?;
            let RuntimeExpressionType::Integer(Some(integer_type)) = base_type else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            let expected_limit = integer_type
                .unsigned_counterpart()
                .map(|ty| RuntimeExpressionType::Integer(Some(ty)));
            if !integer_type.is_signed()
                || expected_limit
                    != Some(runtime_expression_type_with_locals(
                        function,
                        resolver,
                        locals,
                        tree,
                        limit,
                        depth + 1,
                    )?)
            {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(base_type)
        }
        ExprKind::IntegerEndianFrom {
            value,
            integer_type,
            ..
        } => {
            let value_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                value,
                depth + 1,
            )?;
            if value_type != RuntimeExpressionType::Integer(None)
                && value_type != RuntimeExpressionType::Integer(Some(integer_type))
            {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(RuntimeExpressionType::Integer(Some(integer_type)))
        }
        ExprKind::IntegerFromBytes {
            bytes,
            integer_type,
            ..
        } => {
            let count = integer_type
                .bits(64)
                .map(|bits| usize::from(bits / 8))
                .ok_or(CodegenErrorKind::UnsupportedRuntimeType)?;
            let expected = RuntimeExpressionType::Array {
                element: RuntimeArrayElementType::Integer(Some(crate::IntegerType::U8)),
                count,
            };
            let actual = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                bytes,
                depth + 1,
            )?;
            if !runtime_types_compatible(actual, expected) {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(RuntimeExpressionType::Integer(Some(integer_type)))
        }
        ExprKind::IntegerToBytes { base, .. } => {
            let RuntimeExpressionType::Integer(Some(integer_type)) =
                runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    base,
                    depth + 1,
                )?
            else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            let count = integer_type
                .bits(64)
                .map(|bits| usize::from(bits / 8))
                .ok_or(CodegenErrorKind::UnsupportedRuntimeType)?;
            Ok(RuntimeExpressionType::Array {
                element: RuntimeArrayElementType::Integer(Some(crate::IntegerType::U8)),
                count,
            })
        }
        ExprKind::IntegerAssociatedConstant {
            integer_type,
            constant,
        } => Ok(RuntimeExpressionType::Integer(Some(
            if constant == crate::expression::IntegerAssociatedConstant::Bits {
                crate::IntegerType::U32
            } else {
                integer_type
            },
        ))),
        ExprKind::IntegerWrappingShift { base, distance, .. } => {
            let base_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )?;
            if !matches!(base_type, RuntimeExpressionType::Integer(Some(_)))
                || !matches!(
                    runtime_expression_type_with_locals(
                        function,
                        resolver,
                        locals,
                        tree,
                        distance,
                        depth + 1,
                    )?,
                    RuntimeExpressionType::Integer(None)
                        | RuntimeExpressionType::Integer(Some(crate::IntegerType::U32))
                )
            {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(base_type)
        }
        ExprKind::IntegerWrappingPower { base, exponent, .. } => {
            let base_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )?;
            if !matches!(base_type, RuntimeExpressionType::Integer(Some(_)))
                || !matches!(
                    runtime_expression_type_with_locals(
                        function,
                        resolver,
                        locals,
                        tree,
                        exponent,
                        depth + 1,
                    )?,
                    RuntimeExpressionType::Integer(None)
                        | RuntimeExpressionType::Integer(Some(crate::IntegerType::U32))
                )
            {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(base_type)
        }
        ExprKind::IntegerBitTransform { base, transform } => {
            let base_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )?;
            let RuntimeExpressionType::Integer(Some(integer_type)) = base_type else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            if matches!(
                transform,
                crate::expression::IntegerBitTransform::WrappingNegate
                    | crate::expression::IntegerBitTransform::WrappingAbsolute
                    | crate::expression::IntegerBitTransform::Absolute
                    | crate::expression::IntegerBitTransform::StrictAbsolute
                    | crate::expression::IntegerBitTransform::SaturatingNegate
                    | crate::expression::IntegerBitTransform::SaturatingAbsolute
                    | crate::expression::IntegerBitTransform::Signum
            ) && !integer_type.is_signed()
                || (matches!(
                    transform,
                    crate::expression::IntegerBitTransform::NextPowerOfTwo
                        | crate::expression::IntegerBitTransform::WrappingNextPowerOfTwo
                ) && integer_type.is_signed())
            {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(base_type)
        }
        ExprKind::IntegerUnsignedAbsolute { base } => {
            let RuntimeExpressionType::Integer(Some(base_type)) =
                runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    base,
                    depth + 1,
                )?
            else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            let result_type = base_type
                .unsigned_counterpart()
                .ok_or(CodegenErrorKind::RuntimeTypeMismatch)?;
            Ok(RuntimeExpressionType::Integer(Some(result_type)))
        }
        ExprKind::IntegerPairTransform {
            base,
            other,
            transform,
        } => {
            let base_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )?;
            let RuntimeExpressionType::Integer(Some(integer_type)) = base_type else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            if !runtime_types_compatible(
                runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    other,
                    depth + 1,
                )?,
                base_type,
            ) {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            if matches!(
                transform,
                crate::expression::IntegerPairTransform::CarrylessMultiply
                    | crate::expression::IntegerPairTransform::ExtractBits
                    | crate::expression::IntegerPairTransform::DepositBits
            ) && integer_type.is_signed()
            {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            let result_type =
                if transform == crate::expression::IntegerPairTransform::AbsoluteDifference {
                    integer_type.unsigned_counterpart().unwrap_or(integer_type)
                } else {
                    integer_type
                };
            Ok(RuntimeExpressionType::Integer(Some(result_type)))
        }
        ExprKind::IntegerClamp {
            base,
            minimum,
            maximum,
        } => {
            let base_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )?;
            if !matches!(base_type, RuntimeExpressionType::Integer(Some(_))) {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            for bound in [minimum, maximum] {
                let bound_type = runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    bound,
                    depth + 1,
                )?;
                if !runtime_types_compatible(bound_type, base_type) {
                    return Err(CodegenErrorKind::RuntimeTypeMismatch);
                }
            }
            Ok(base_type)
        }
        ExprKind::IntegerBitCount { base, count } => {
            let base_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )?;
            let RuntimeExpressionType::Integer(Some(integer_type)) = base_type else {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            };
            if count == crate::expression::IntegerBitCount::Width && integer_type.is_signed() {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(RuntimeExpressionType::Integer(Some(
                crate::IntegerType::U32,
            )))
        }
        ExprKind::IntegerLogarithm { base, radix, .. } => {
            let base_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )?;
            if !matches!(base_type, RuntimeExpressionType::Integer(Some(_))) {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            if let Some(radix) = radix {
                let radix_type = runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    radix,
                    depth + 1,
                )?;
                if !runtime_types_compatible(radix_type, base_type) {
                    return Err(CodegenErrorKind::RuntimeTypeMismatch);
                }
            }
            Ok(RuntimeExpressionType::Integer(Some(
                crate::IntegerType::U32,
            )))
        }
        ExprKind::RawPointerOffset {
            base,
            offset,
            wrapping,
            signed,
            ..
        } => {
            if !wrapping && !unsafe_context {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            let base_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )?;
            if !matches!(base_type, RuntimeExpressionType::RawPointer { .. }) {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            let offset_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                offset,
                depth + 1,
            )?;
            let offset_matches = if signed {
                matches!(
                    offset_type,
                    RuntimeExpressionType::Integer(None)
                        | RuntimeExpressionType::Integer(Some(crate::IntegerType::Isize))
                )
            } else {
                matches!(
                    offset_type,
                    RuntimeExpressionType::Integer(None)
                        | RuntimeExpressionType::Integer(Some(crate::IntegerType::Usize))
                )
            };
            if !offset_matches {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(base_type)
        }
        ExprKind::RawPointerDifference {
            pointer,
            origin,
            unsigned,
            ..
        } => {
            if !unsafe_context {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            let pointer_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                pointer,
                depth + 1,
            )?;
            let origin_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                origin,
                depth + 1,
            )?;
            if !matches!(pointer_type, RuntimeExpressionType::RawPointer { .. })
                || !matches!(origin_type, RuntimeExpressionType::RawPointer { .. })
                || (!runtime_types_compatible(pointer_type, origin_type)
                    && !runtime_types_compatible(origin_type, pointer_type))
            {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(RuntimeExpressionType::Integer(Some(if unsigned {
                crate::IntegerType::Usize
            } else {
                crate::IntegerType::Isize
            })))
        }
        ExprKind::RawPointerAlignOffset { base, alignment } => {
            if !matches!(
                runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    base,
                    depth + 1,
                )?,
                RuntimeExpressionType::RawPointer { .. }
            ) || !matches!(
                runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    alignment,
                    depth + 1,
                )?,
                RuntimeExpressionType::Integer(None)
                    | RuntimeExpressionType::Integer(Some(crate::IntegerType::Usize))
            ) {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(RuntimeExpressionType::Integer(Some(
                crate::IntegerType::Usize,
            )))
        }
        ExprKind::RawPointerMask { base, mask } => {
            let base_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                base,
                depth + 1,
            )?;
            if !matches!(base_type, RuntimeExpressionType::RawPointer { .. })
                || !matches!(
                    runtime_expression_type_with_locals(
                        function,
                        resolver,
                        locals,
                        tree,
                        mask,
                        depth + 1,
                    )?,
                    RuntimeExpressionType::Integer(None)
                        | RuntimeExpressionType::Integer(Some(crate::IntegerType::Usize))
                )
            {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(base_type)
        }
        ExprKind::RawPointerIsAlignedTo { base, alignment } => {
            if !matches!(
                runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    base,
                    depth + 1,
                )?,
                RuntimeExpressionType::RawPointer { .. }
            ) || !matches!(
                runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    alignment,
                    depth + 1,
                )?,
                RuntimeExpressionType::Integer(None)
                    | RuntimeExpressionType::Integer(Some(crate::IntegerType::Usize))
            ) {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(RuntimeExpressionType::Bool)
        }
        ExprKind::Integer(literal) => Ok(RuntimeExpressionType::Integer(
            literal.suffix.and_then(crate::IntegerType::from_name),
        )),
        ExprKind::Bool(_) => Ok(RuntimeExpressionType::Bool),
        ExprKind::Char(_) => Ok(RuntimeExpressionType::Char),
        ExprKind::ByteChar(_) => Ok(RuntimeExpressionType::Integer(Some(crate::IntegerType::U8))),
        ExprKind::String(_) => Ok(RuntimeExpressionType::Reference {
            target: RuntimeReferenceTarget::Str,
            mutable: false,
        }),
        ExprKind::ByteString(_) => Ok(RuntimeExpressionType::Reference {
            target: RuntimeReferenceTarget::Slice(RuntimeArrayElementType::Integer(Some(
                crate::IntegerType::U8,
            ))),
            mutable: false,
        }),
        ExprKind::CString(_) => Err(CodegenErrorKind::UnsupportedCStringLiteral),
        ExprKind::Closure { .. } => Err(CodegenErrorKind::RuntimeExpressionUnsupported),
        ExprKind::ClosureParameter {
            target: Some(crate::expression::ClosureParameterTarget::Integer(target)),
            ..
        } => Ok(RuntimeExpressionType::Integer(Some(target))),
        ExprKind::ClosureParameter {
            target: Some(crate::expression::ClosureParameterTarget::IntegerReference(target)),
            ..
        } => Ok(RuntimeExpressionType::Reference {
            target: RuntimeReferenceTarget::Scalar(RuntimeArrayElementType::Integer(Some(target))),
            mutable: false,
        }),
        ExprKind::ClosureParameter { target: None, .. } => {
            Err(CodegenErrorKind::RuntimeExpressionUnsupported)
        }
        ExprKind::Identifier(name) => Ok(locals
            .iter()
            .flatten()
            .rev()
            .find(|local| local.name == name)
            .map(|local| local.ty)
            .or_else(|| {
                function
                    .parameters()
                    .iter()
                    .flatten()
                    .find(|parameter| parameter.name == name)
                    .map(|parameter| {
                        if let Some(array) = runtime_array_type(parameter.ty.text) {
                            array
                        } else if let Some(reference) = runtime_reference_type(parameter.ty.text) {
                            reference
                        } else if let Some(pointer) = runtime_raw_pointer_type(parameter.ty.text) {
                            pointer
                        } else if parameter.ty.text == "bool" {
                            RuntimeExpressionType::Bool
                        } else if parameter.ty.text == "char" {
                            RuntimeExpressionType::Char
                        } else {
                            RuntimeExpressionType::Integer(crate::IntegerType::from_name(
                                parameter.ty.text,
                            ))
                        }
                    })
            })
            .unwrap_or_else(|| {
                if resolver.resolves_bool(name) {
                    RuntimeExpressionType::Bool
                } else {
                    RuntimeExpressionType::Integer(resolver.resolve_type(name))
                }
            })),
        ExprKind::Call {
            callee,
            argument_count,
            ..
        } => {
            if let Some(target) =
                resolver.resolve_runtime_call::<MAX_PARAMETERS>(callee, argument_count)
            {
                Ok(runtime_type_from_scalar(target.return_type))
            } else if resolver.call_resolves_bool(callee, argument_count) {
                Ok(RuntimeExpressionType::Bool)
            } else {
                resolver
                    .resolve_call_type(callee, argument_count)
                    .map(|ty| RuntimeExpressionType::Integer(Some(ty)))
                    .ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)
            }
        }
        ExprKind::InlineConst { operand } => {
            validate_runtime_inline_const(function, resolver, locals, tree, operand, depth + 1)?;
            runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                operand,
                depth + 1,
            )
        }
        ExprKind::Cast { operand, target } => {
            let operand_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                operand,
                depth + 1,
            )?;
            match target {
                crate::CastType::Integer(target) => {
                    if !matches!(
                        operand_type,
                        RuntimeExpressionType::Integer(_)
                            | RuntimeExpressionType::RawPointer { .. }
                            | RuntimeExpressionType::Bool
                    ) {
                        return Err(CodegenErrorKind::RuntimeTypeMismatch);
                    }
                    if runtime_width(target.name()).is_none()
                        && !runtime_integer_layout(target.name())
                            .is_some_and(|layout| layout.words == 2)
                    {
                        return Err(CodegenErrorKind::UnsupportedRuntimeType);
                    }
                    Ok(RuntimeExpressionType::Integer(Some(target)))
                }
                crate::CastType::RawPointer { pointee, mutable } => {
                    if !matches!(
                        operand_type,
                        RuntimeExpressionType::Integer(_) | RuntimeExpressionType::RawPointer { .. }
                    ) {
                        return Err(CodegenErrorKind::RuntimeTypeMismatch);
                    }
                    let pointee = match pointee {
                        crate::PointerPointee::Integer(ty) => {
                            RuntimeArrayElementType::Integer(Some(ty))
                        }
                        crate::PointerPointee::Bool => RuntimeArrayElementType::Bool,
                        crate::PointerPointee::Char => RuntimeArrayElementType::Char,
                    };
                    Ok(RuntimeExpressionType::RawPointer { pointee, mutable })
                }
            }
        }
        ExprKind::Ascribe { operand, target } => {
            let operand_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                operand,
                depth + 1,
            )?;
            match target {
                crate::ScalarType::Bool if operand_type == RuntimeExpressionType::Bool => {
                    Ok(RuntimeExpressionType::Bool)
                }
                crate::ScalarType::Integer(target)
                    if matches!(operand_type, RuntimeExpressionType::Integer(_)) =>
                {
                    Ok(RuntimeExpressionType::Integer(Some(target)))
                }
                crate::ScalarType::Char if operand_type == RuntimeExpressionType::Char => {
                    Ok(RuntimeExpressionType::Char)
                }
                crate::ScalarType::Unit if operand_type == RuntimeExpressionType::Unit => {
                    Ok(RuntimeExpressionType::Unit)
                }
                crate::ScalarType::RawPointer { .. }
                    if operand_type == runtime_type_from_scalar(target) =>
                {
                    Ok(operand_type)
                }
                crate::ScalarType::Reference { .. }
                    if operand_type == runtime_type_from_scalar(target) =>
                {
                    Ok(operand_type)
                }
                crate::ScalarType::ArrayReference { .. }
                    if operand_type == runtime_type_from_scalar(target) =>
                {
                    Ok(operand_type)
                }
                crate::ScalarType::Array { .. }
                    if operand_type == runtime_type_from_scalar(target) =>
                {
                    Ok(operand_type)
                }
                crate::ScalarType::SliceReference { .. }
                | crate::ScalarType::StrReference { .. }
                    if operand_type == runtime_type_from_scalar(target) =>
                {
                    Ok(operand_type)
                }
                _ => Err(CodegenErrorKind::RuntimeTypeMismatch),
            }
        }
        ExprKind::If {
            condition,
            then_branch,
            else_branch,
        }
        | ExprKind::LoopBreakIf {
            condition,
            then_branch,
            else_branch,
        } => {
            if runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                condition,
                depth + 1,
            )? != RuntimeExpressionType::Bool
            {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            let then_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                then_branch,
                depth + 1,
            )?;
            let else_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                else_branch,
                depth + 1,
            )?;
            if !runtime_types_compatible(then_type, else_type) {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            Ok(match (then_type, else_type) {
                (RuntimeExpressionType::Default, resolved)
                | (resolved, RuntimeExpressionType::Default) => resolved,
                (RuntimeExpressionType::Integer(None), resolved)
                | (resolved, RuntimeExpressionType::Integer(None)) => resolved,
                (resolved, _) => resolved,
            })
        }
        ExprKind::Return { operand } | ExprKind::LoopBreak { operand } => {
            runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                operand,
                depth + 1,
            )
        }
        ExprKind::Sequence { first, then } => {
            runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                first,
                depth + 1,
            )?;
            runtime_expression_type_with_locals(function, resolver, locals, tree, then, depth + 1)
        }
        ExprKind::Unary {
            operator: crate::UnaryOperator::Not,
            operand,
        } => runtime_expression_type_with_locals(
            function,
            resolver,
            locals,
            tree,
            operand,
            depth + 1,
        ),
        ExprKind::Unary {
            operator: crate::UnaryOperator::Negate,
            operand,
        } => {
            let operand_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                operand,
                depth + 1,
            )?;
            if matches!(operand_type, RuntimeExpressionType::Integer(_)) {
                Ok(operand_type)
            } else {
                Err(CodegenErrorKind::RuntimeTypeMismatch)
            }
        }
        ExprKind::Unary {
            operator: crate::UnaryOperator::Dereference,
            operand,
        } => {
            let operand_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                operand,
                depth + 1,
            )?;
            match operand_type {
                RuntimeExpressionType::Reference { target, .. } => {
                    runtime_reference_target_type(target)
                }
                RuntimeExpressionType::RawPointer { pointee, .. } => {
                    if !unsafe_context {
                        return Err(CodegenErrorKind::RuntimeTypeMismatch);
                    }
                    Ok(runtime_type_from_array_element(pointee))
                }
                _ => Err(CodegenErrorKind::RuntimeTypeMismatch),
            }
        }
        ExprKind::Unary {
            operator:
                operator @ (crate::UnaryOperator::AddressOf | crate::UnaryOperator::AddressOfMut),
            operand,
        } => {
            let operand_kind = tree
                .expression(operand)
                .map(|expression| expression.kind)
                .ok_or(CodegenErrorKind::RuntimeExpressionUnsupported)?;
            let target = match operand_kind {
                ExprKind::Identifier(name) => {
                    let local = locals
                        .iter()
                        .flatten()
                        .rev()
                        .find(|local| local.name == name);
                    if let Some(local) = local {
                        if operator == crate::UnaryOperator::AddressOfMut && !local.mutable {
                            return Err(CodegenErrorKind::ImmutableAssignment);
                        }
                    } else {
                        function
                            .parameters()
                            .iter()
                            .flatten()
                            .find(|parameter| parameter.name == name)
                            .ok_or(CodegenErrorKind::UnknownRuntimeName)?;
                        if operator == crate::UnaryOperator::AddressOfMut {
                            return Err(CodegenErrorKind::ImmutableAssignment);
                        }
                    }
                    runtime_reference_target_from_type(runtime_expression_type_with_locals(
                        function,
                        resolver,
                        locals,
                        tree,
                        operand,
                        depth + 1,
                    )?)?
                }
                ExprKind::Unary {
                    operator: crate::UnaryOperator::Dereference,
                    operand: reference,
                } => {
                    let reference_type = runtime_expression_type_with_locals(
                        function,
                        resolver,
                        locals,
                        tree,
                        reference,
                        depth + 1,
                    )?;
                    let RuntimeExpressionType::Reference { target, mutable } = reference_type
                    else {
                        return Err(CodegenErrorKind::RuntimeTypeMismatch);
                    };
                    if operator == crate::UnaryOperator::AddressOfMut && !mutable {
                        return Err(CodegenErrorKind::ImmutableAssignment);
                    }
                    target
                }
                ExprKind::RangeIndex {
                    base,
                    start,
                    end,
                    inclusive,
                } => {
                    let base_type = runtime_expression_type_with_locals(
                        function,
                        resolver,
                        locals,
                        tree,
                        base,
                        depth + 1,
                    )?;
                    let (target, count, mutable) = match base_type {
                        RuntimeExpressionType::Reference {
                            target:
                                RuntimeReferenceTarget::Array {
                                    element,
                                    count,
                                    layout: RuntimeReferenceArrayLayout::Native,
                                },
                            mutable,
                        } => (RuntimeReferenceTarget::Slice(element), Some(count), mutable),
                        RuntimeExpressionType::Reference {
                            target: RuntimeReferenceTarget::Slice(element),
                            mutable,
                        } => (RuntimeReferenceTarget::Slice(element), None, mutable),
                        RuntimeExpressionType::Reference {
                            target: RuntimeReferenceTarget::Str,
                            mutable,
                        } => (RuntimeReferenceTarget::Str, None, mutable),
                        RuntimeExpressionType::Array { element, count } => {
                            let Some(ExprKind::Identifier(name)) =
                                tree.expression(base).map(|expression| expression.kind)
                            else {
                                return Err(CodegenErrorKind::RuntimeTypeMismatch);
                            };
                            let local = locals
                                .iter()
                                .flatten()
                                .rev()
                                .find(|local| local.name == name)
                                .ok_or(CodegenErrorKind::RuntimeTypeMismatch)?;
                            (
                                RuntimeReferenceTarget::Slice(element),
                                Some(count),
                                local.mutable,
                            )
                        }
                        _ => return Err(CodegenErrorKind::RuntimeTypeMismatch),
                    };
                    if operator == crate::UnaryOperator::AddressOfMut && !mutable {
                        return Err(CodegenErrorKind::ImmutableAssignment);
                    }
                    if inclusive && end.is_none() {
                        return Err(CodegenErrorKind::RuntimeExpressionUnsupported);
                    }
                    for endpoint in [start, end].into_iter().flatten() {
                        if !matches!(
                            runtime_expression_type_with_locals(
                                function,
                                resolver,
                                locals,
                                tree,
                                endpoint,
                                depth + 1,
                            )?,
                            RuntimeExpressionType::Integer(None)
                                | RuntimeExpressionType::Integer(Some(crate::IntegerType::Usize))
                        ) {
                            return Err(CodegenErrorKind::RuntimeTypeMismatch);
                        }
                    }
                    if let Some(count) = count {
                        match constant_range_bounds(tree, start, end, inclusive, count, resolver) {
                            Ok(_) | Err(CodegenErrorKind::RuntimeExpressionUnsupported) => {}
                            Err(error) => return Err(error),
                        }
                    }
                    target
                }
                ExprKind::Index { base, index } => {
                    if !matches!(
                        runtime_expression_type_with_locals(
                            function,
                            resolver,
                            locals,
                            tree,
                            index,
                            depth + 1,
                        )?,
                        RuntimeExpressionType::Integer(None)
                            | RuntimeExpressionType::Integer(Some(crate::IntegerType::Usize))
                    ) {
                        return Err(CodegenErrorKind::RuntimeTypeMismatch);
                    }
                    let base_type = runtime_expression_type_with_locals(
                        function,
                        resolver,
                        locals,
                        tree,
                        base,
                        depth + 1,
                    )?;
                    let (element, mutable) = match base_type {
                        RuntimeExpressionType::Reference {
                            target:
                                RuntimeReferenceTarget::Array { element, .. }
                                | RuntimeReferenceTarget::Slice(element),
                            mutable,
                        } => (element, mutable),
                        RuntimeExpressionType::Array { element, .. } => {
                            let Some(ExprKind::Identifier(name)) =
                                tree.expression(base).map(|expression| expression.kind)
                            else {
                                return Err(CodegenErrorKind::RuntimeTypeMismatch);
                            };
                            let mutable = locals
                                .iter()
                                .flatten()
                                .rev()
                                .find(|local| local.name == name)
                                .is_some_and(|local| local.mutable);
                            (element, mutable)
                        }
                        _ => return Err(CodegenErrorKind::RuntimeTypeMismatch),
                    };
                    if operator == crate::UnaryOperator::AddressOfMut && !mutable {
                        return Err(CodegenErrorKind::ImmutableAssignment);
                    }
                    runtime_reference_target_from_type(runtime_type_from_array_element(element))?
                }
                _ => return Err(CodegenErrorKind::RuntimeExpressionUnsupported),
            };
            Ok(RuntimeExpressionType::Reference {
                target,
                mutable: operator == crate::UnaryOperator::AddressOfMut,
            })
        }
        ExprKind::Binary {
            operator,
            left,
            right,
        } => {
            if matches!(
                operator,
                crate::BinaryOperator::LogicalAnd | crate::BinaryOperator::LogicalOr
            ) {
                if runtime_expression_type_with_locals(
                    function,
                    resolver,
                    locals,
                    tree,
                    left,
                    depth + 1,
                )? == RuntimeExpressionType::Bool
                    && runtime_expression_type_with_locals(
                        function,
                        resolver,
                        locals,
                        tree,
                        right,
                        depth + 1,
                    )? == RuntimeExpressionType::Bool
                {
                    return Ok(RuntimeExpressionType::Bool);
                }
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            let left_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                left,
                depth + 1,
            )?;
            let right_type = runtime_expression_type_with_locals(
                function,
                resolver,
                locals,
                tree,
                right,
                depth + 1,
            )?;
            if matches!(
                operator,
                crate::BinaryOperator::Equal
                    | crate::BinaryOperator::NotEqual
                    | crate::BinaryOperator::Less
                    | crate::BinaryOperator::LessEqual
                    | crate::BinaryOperator::Greater
                    | crate::BinaryOperator::GreaterEqual
            ) && matches!(
                (left_type, right_type),
                (RuntimeExpressionType::Bool, RuntimeExpressionType::Bool)
                    | (RuntimeExpressionType::Unit, RuntimeExpressionType::Unit)
                    | (RuntimeExpressionType::Char, RuntimeExpressionType::Char)
            ) {
                return Ok(RuntimeExpressionType::Bool);
            }
            if matches!(
                operator,
                crate::BinaryOperator::Equal
                    | crate::BinaryOperator::NotEqual
                    | crate::BinaryOperator::Less
                    | crate::BinaryOperator::LessEqual
                    | crate::BinaryOperator::Greater
                    | crate::BinaryOperator::GreaterEqual
            ) && matches!(left_type, RuntimeExpressionType::RawPointer { .. })
                && matches!(right_type, RuntimeExpressionType::RawPointer { .. })
                && (runtime_types_compatible(left_type, right_type)
                    || runtime_types_compatible(right_type, left_type))
            {
                return Ok(RuntimeExpressionType::Bool);
            }
            if matches!(
                operator,
                crate::BinaryOperator::BitAnd
                    | crate::BinaryOperator::BitOr
                    | crate::BinaryOperator::BitXor
            ) && matches!(
                (left_type, right_type),
                (RuntimeExpressionType::Bool, RuntimeExpressionType::Bool)
            ) {
                return Ok(RuntimeExpressionType::Bool);
            }
            if matches!(
                operator,
                crate::BinaryOperator::ShiftLeft | crate::BinaryOperator::ShiftRight
            ) {
                if !matches!(right_type, RuntimeExpressionType::Integer(_)) {
                    return Err(CodegenErrorKind::RuntimeTypeMismatch);
                }
                return match left_type {
                    RuntimeExpressionType::Integer(_) => Ok(left_type),
                    RuntimeExpressionType::Never
                    | RuntimeExpressionType::Unit
                    | RuntimeExpressionType::Default
                    | RuntimeExpressionType::Array { .. }
                    | RuntimeExpressionType::Tuple { .. }
                    | RuntimeExpressionType::Reference { .. }
                    | RuntimeExpressionType::RawPointer { .. }
                    | RuntimeExpressionType::Bool
                    | RuntimeExpressionType::Char => Err(CodegenErrorKind::RuntimeTypeMismatch),
                };
            }
            let integer_type = unify_integer_types(left_type, right_type)?;
            if matches!(
                operator,
                crate::BinaryOperator::Equal
                    | crate::BinaryOperator::NotEqual
                    | crate::BinaryOperator::Less
                    | crate::BinaryOperator::LessEqual
                    | crate::BinaryOperator::Greater
                    | crate::BinaryOperator::GreaterEqual
            ) {
                Ok(RuntimeExpressionType::Bool)
            } else {
                Ok(RuntimeExpressionType::Integer(integer_type))
            }
        }
    }
}
