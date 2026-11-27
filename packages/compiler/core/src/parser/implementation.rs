use crate::{
    ExpressionError, ExpressionParser, ExpressionTree, LexError, Lexer, Span, Token, TokenKind,
};

const MAX_DELIMITER_DEPTH: usize = 64;
const MAX_LOOP_ASSIGNMENTS: usize = 4;
pub const MAX_LOOP_OPERATIONS: usize = 8;
pub const MAX_CONDITIONAL_LOOP_ACTIONS: usize = 4;
pub const MAX_CONDITIONAL_LOOP_ELSE_ARMS: usize = 4;
pub const MAX_NESTED_LOOP_ACTIONS: usize = 4;
pub const MAX_NESTED_LOOP_BLOCKS: usize = 4;
pub const MAX_NESTED_LOOP_CONDITIONAL_BLOCKS: usize = 4;
pub const MAX_NESTED_LOOP_CONDITIONAL_ELSE_ARMS: usize = 4;
pub const MAX_NESTED_LOOP_CONDITIONAL_BREAKS: usize = 4;
pub const MAX_NESTED_LOOP_CONDITIONAL_CONTINUES: usize = 4;
pub const MAX_NESTED_LOOP_CONDITIONAL_RETURNS: usize = 4;
pub const MAX_NESTED_LOOP_UNCONDITIONAL_CONTROLS: usize = 4;
pub const MAX_BODY_STATEMENTS: usize = 32;
pub const MAX_BODY_EXPRESSION_STATEMENTS: usize = 8;
pub const MAX_BODY_RETURNS: usize = 8;
pub const MAX_CONDITIONAL_RETURN_BRANCHES: usize = 4;
pub const MAX_BODY_CONDITIONAL_ASSIGNMENTS: usize = 8;
pub const MAX_FUNCTION_WHERE_PREDICATES: usize = 8;
pub const MAX_TRAIT_SUPERTRAITS: usize = 8;
pub const MAX_TRAIT_ASSOCIATED_TYPES: usize = 8;
pub const MAX_SOURCE_TRAIT_ARGUMENTS: usize = 8;
pub const MAX_CONDITIONAL_ASSIGNMENT_BRANCHES: usize = 4;
pub const MAX_CONDITIONAL_BRANCH_ACTIONS: usize = 4;
const MAX_BODY_TAIL_EXPRESSION_NODES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TypeRef<'source> {
    pub text: &'source str,
    pub span: Span,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraitProjectionTypeRef<'source> {
    pub self_type: TypeRef<'source>,
    pub trait_name: &'source str,
    pub trait_name_span: Span,
    trait_arguments: [Option<TypeRef<'source>>; MAX_SOURCE_TRAIT_ARGUMENTS],
    trait_argument_count: usize,
    pub associated_type: &'source str,
    pub associated_type_span: Span,
}

impl<'source> TraitProjectionTypeRef<'source> {
    pub fn trait_arguments(&self) -> &[Option<TypeRef<'source>>] {
        &self.trait_arguments[..self.trait_argument_count]
    }

    pub const fn trait_argument_count(&self) -> usize {
        self.trait_argument_count
    }
}

impl<'source> TypeRef<'source> {
    pub fn parse_trait_projection(
        self,
    ) -> Result<Option<TraitProjectionTypeRef<'source>>, ParseError> {
        let mut parser = Parser::new(self.text);
        if parser.take_text("<")?.is_none() {
            return Ok(None);
        }
        let self_type = parser.type_until_text("as")?;
        let as_token = parser.take()?;
        if !as_token.is_some_and(|token| token.text == "as") {
            return Err(parser.error(ParseErrorKind::ExpectedIdentifier, as_token));
        }
        let trait_name = parser.identifier()?;
        let (trait_arguments, trait_argument_count, consumed_projection_close) =
            parser.source_trait_arguments()?;
        if !consumed_projection_close {
            let close = parser.take()?;
            if !close.is_some_and(|token| token.text == ">") {
                return Err(parser.error(ParseErrorKind::ExpectedType, close));
            }
        }
        let separator = parser.take()?;
        if !separator.is_some_and(|token| token.text == "::") {
            return Err(parser.error(ParseErrorKind::ExpectedIdentifier, separator));
        }
        let associated_type = parser.identifier()?;
        if let Some(extra) = parser.take()? {
            return Err(parser.error(ParseErrorKind::ExpectedSemicolon, Some(extra)));
        }
        let offset = self.span.start;
        let offset_type = |ty: TypeRef<'source>| TypeRef {
            text: ty.text,
            span: Span {
                start: ty.span.start + offset,
                end: ty.span.end + offset,
            },
        };
        let mut adjusted_arguments = [None; MAX_SOURCE_TRAIT_ARGUMENTS];
        for (index, argument) in trait_arguments[..trait_argument_count]
            .iter()
            .flatten()
            .enumerate()
        {
            adjusted_arguments[index] = Some(offset_type(*argument));
        }
        Ok(Some(TraitProjectionTypeRef {
            self_type: offset_type(self_type),
            trait_name: trait_name.text,
            trait_name_span: Span {
                start: trait_name.span.start + offset,
                end: trait_name.span.end + offset,
            },
            trait_arguments: adjusted_arguments,
            trait_argument_count,
            associated_type: associated_type.text,
            associated_type_span: Span {
                start: associated_type.span.start + offset,
                end: associated_type.span.end + offset,
            },
        }))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Parameter<'source> {
    pub name: &'source str,
    pub span: Span,
    pub ty: TypeRef<'source>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FunctionWherePredicate<'source> {
    Implemented {
        self_type: TypeRef<'source>,
        trait_name: &'source str,
        trait_name_span: Span,
        trait_arguments: [Option<TypeRef<'source>>; MAX_SOURCE_TRAIT_ARGUMENTS],
        trait_argument_count: usize,
    },
    ProjectionEquality {
        self_type: TypeRef<'source>,
        trait_name: &'source str,
        trait_name_span: Span,
        trait_arguments: [Option<TypeRef<'source>>; MAX_SOURCE_TRAIT_ARGUMENTS],
        trait_argument_count: usize,
        associated_type: &'source str,
        associated_type_span: Span,
        expected_type: TypeRef<'source>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FunctionAbi {
    Rust,
    C,
    MrmlV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Function<'source, const MAX_PARAMETERS: usize> {
    pub public: bool,
    pub constant: bool,
    pub unsafe_function: bool,
    pub abi: FunctionAbi,
    pub no_mangle: bool,
    pub naked: bool,
    pub name: &'source str,
    pub name_span: Span,
    parameters: [Option<Parameter<'source>>; MAX_PARAMETERS],
    parameter_count: usize,
    pub return_type: Option<TypeRef<'source>>,
    where_predicates: [Option<FunctionWherePredicate<'source>>; MAX_FUNCTION_WHERE_PREDICATES],
    where_predicate_count: usize,
    pub body: Span,
    pub body_expression: &'source str,
    pub body_expression_span: Span,
}

impl<'source, const MAX_PARAMETERS: usize> Function<'source, MAX_PARAMETERS> {
    pub fn parameters(&self) -> &[Option<Parameter<'source>>] {
        &self.parameters[..self.parameter_count]
    }

    pub const fn parameter_count(&self) -> usize {
        self.parameter_count
    }

    pub fn where_predicates(&self) -> &[Option<FunctionWherePredicate<'source>>] {
        &self.where_predicates[..self.where_predicate_count]
    }

    pub const fn where_predicate_count(&self) -> usize {
        self.where_predicate_count
    }

    pub fn parse_body_expression<const MAX_NODES: usize>(
        &self,
    ) -> Result<ExpressionTree<'source, MAX_NODES>, ExpressionError> {
        ExpressionParser::new(self.body_expression).parse()
    }

    pub fn parse_body<const MAX_LOCALS: usize>(
        &self,
    ) -> Result<FunctionBody<'source, MAX_LOCALS>, ParseError> {
        BodyParser::new(self.body_expression).parse::<MAX_LOCALS, MAX_BODY_TAIL_EXPRESSION_NODES>()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalBinding<'source> {
    pub mutable: bool,
    pub initialized: bool,
    pub name: &'source str,
    pub name_span: Span,
    pub ty: Option<TypeRef<'source>>,
    pub initializer: &'source str,
    pub initializer_span: Span,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssignmentOperator {
    Assign,
    Add,
    Subtract,
    Multiply,
    Divide,
    Remainder,
    BitAnd,
    BitOr,
    BitXor,
    ShiftLeft,
    ShiftRight,
}

impl AssignmentOperator {
    fn from_text(text: &str) -> Option<Self> {
        Some(match text {
            "=" => Self::Assign,
            "+=" => Self::Add,
            "-=" => Self::Subtract,
            "*=" => Self::Multiply,
            "/=" => Self::Divide,
            "%=" => Self::Remainder,
            "&=" => Self::BitAnd,
            "|=" => Self::BitOr,
            "^=" => Self::BitXor,
            "<<=" => Self::ShiftLeft,
            ">>=" => Self::ShiftRight,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssignmentProjection<'source> {
    Dereference {
        span: Span,
    },
    Index {
        expression: &'source str,
        span: Span,
    },
    TupleField {
        field: usize,
        span: Span,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Assignment<'source> {
    pub name: &'source str,
    pub name_span: Span,
    pub projection: Option<AssignmentProjection<'source>>,
    pub operator: AssignmentOperator,
    pub value: &'source str,
    pub value_span: Span,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConditionalAssignmentAction<'source> {
    Local(LocalBinding<'source>),
    Assignment(Assignment<'source>),
    Expression(ExpressionStatement<'source>),
    Return(LoopReturn<'source>),
}

type ConditionalAssignmentBlock<'source> = (
    [Option<ConditionalAssignmentAction<'source>>; MAX_CONDITIONAL_BRANCH_ACTIONS],
    usize,
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConditionalAssignment<'source> {
    branches: [Option<ConditionalAssignmentBranch<'source>>; MAX_CONDITIONAL_ASSIGNMENT_BRANCHES],
    branch_count: usize,
    else_actions: [Option<ConditionalAssignmentAction<'source>>; MAX_CONDITIONAL_BRANCH_ACTIONS],
    else_action_count: usize,
}

impl<'source> ConditionalAssignment<'source> {
    pub fn branches(&self) -> &[Option<ConditionalAssignmentBranch<'source>>] {
        &self.branches[..self.branch_count]
    }

    pub const fn branch_count(&self) -> usize {
        self.branch_count
    }

    pub fn else_actions(&self) -> &[Option<ConditionalAssignmentAction<'source>>] {
        &self.else_actions[..self.else_action_count]
    }

    pub const fn else_action_count(&self) -> usize {
        self.else_action_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConditionalAssignmentBranch<'source> {
    pub condition: &'source str,
    pub condition_span: Span,
    actions: [Option<ConditionalAssignmentAction<'source>>; MAX_CONDITIONAL_BRANCH_ACTIONS],
    action_count: usize,
}

impl<'source> ConditionalAssignmentBranch<'source> {
    pub fn actions(&self) -> &[Option<ConditionalAssignmentAction<'source>>] {
        &self.actions[..self.action_count]
    }

    pub const fn action_count(&self) -> usize {
        self.action_count
    }

    pub fn parse_condition<const MAX_NODES: usize>(
        &self,
    ) -> Result<ExpressionTree<'source, MAX_NODES>, ExpressionError> {
        ExpressionParser::new(self.condition).parse()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConditionalReturn<'source> {
    pub condition: &'source str,
    pub condition_span: Span,
    pub value: &'source str,
    pub value_span: Span,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConditionalReturnElse<'source> {
    branches: [Option<ConditionalReturn<'source>>; MAX_CONDITIONAL_RETURN_BRANCHES],
    branch_count: usize,
    pub else_value: Option<LoopReturn<'source>>,
}

impl<'source> ConditionalReturnElse<'source> {
    pub fn branches(&self) -> &[Option<ConditionalReturn<'source>>] {
        &self.branches[..self.branch_count]
    }

    pub const fn branch_count(&self) -> usize {
        self.branch_count
    }
}

impl<'source> ConditionalReturn<'source> {
    pub fn parse_condition<const MAX_NODES: usize>(
        &self,
    ) -> Result<ExpressionTree<'source, MAX_NODES>, ExpressionError> {
        ExpressionParser::new(self.condition).parse()
    }

    pub fn parse_value<const MAX_NODES: usize>(
        &self,
    ) -> Result<ExpressionTree<'source, MAX_NODES>, ExpressionError> {
        ExpressionParser::new(self.value).parse()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConditionalLoopControl<'source> {
    pub condition: &'source str,
    pub condition_span: Span,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConditionalLoopAction<'source> {
    Local(LocalBinding<'source>),
    Assignment(Assignment<'source>),
    Expression(ExpressionStatement<'source>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConditionalLoopTerminal<'source> {
    Break,
    Continue,
    Return(LoopReturn<'source>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConditionalLoopArm<'source> {
    pub condition: Option<&'source str>,
    pub condition_span: Span,
    actions: [Option<ConditionalLoopAction<'source>>; MAX_CONDITIONAL_LOOP_ACTIONS],
    action_count: usize,
    pub terminal: Option<ConditionalLoopTerminal<'source>>,
}

impl<'source> ConditionalLoopArm<'source> {
    pub fn actions(&self) -> &[Option<ConditionalLoopAction<'source>>] {
        &self.actions[..self.action_count]
    }

    pub const fn action_count(&self) -> usize {
        self.action_count
    }

    pub fn parse_condition<const MAX_NODES: usize>(
        &self,
    ) -> Result<Option<ExpressionTree<'source, MAX_NODES>>, ExpressionError> {
        self.condition
            .map(|condition| ExpressionParser::new(condition).parse())
            .transpose()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NestedLoopBlock<'source> {
    pub label: Option<&'source str>,
    pub entry_condition: Option<ConditionalLoopControl<'source>>,
    actions: [Option<ConditionalLoopAction<'source>>; MAX_NESTED_LOOP_ACTIONS],
    action_count: usize,
    conditional_blocks:
        [Option<NestedLoopConditionalBlock<'source>>; MAX_NESTED_LOOP_CONDITIONAL_BLOCKS],
    conditional_block_action_indices: [usize; MAX_NESTED_LOOP_CONDITIONAL_BLOCKS],
    conditional_block_control_orders: [usize; MAX_NESTED_LOOP_CONDITIONAL_BLOCKS],
    conditional_block_count: usize,
    unconditional_controls:
        [Option<NestedLoopUnconditionalControl<'source>>; MAX_NESTED_LOOP_UNCONDITIONAL_CONTROLS],
    unconditional_control_action_indices: [usize; MAX_NESTED_LOOP_UNCONDITIONAL_CONTROLS],
    unconditional_control_orders: [usize; MAX_NESTED_LOOP_UNCONDITIONAL_CONTROLS],
    unconditional_control_count: usize,
    conditional_breaks:
        [Option<ConditionalLoopControl<'source>>; MAX_NESTED_LOOP_CONDITIONAL_BREAKS],
    conditional_break_action_indices: [usize; MAX_NESTED_LOOP_CONDITIONAL_BREAKS],
    conditional_break_control_orders: [usize; MAX_NESTED_LOOP_CONDITIONAL_BREAKS],
    conditional_break_targets: [NestedLoopControlTarget; MAX_NESTED_LOOP_CONDITIONAL_BREAKS],
    conditional_break_count: usize,
    conditional_continues:
        [Option<ConditionalLoopControl<'source>>; MAX_NESTED_LOOP_CONDITIONAL_CONTINUES],
    conditional_continue_action_indices: [usize; MAX_NESTED_LOOP_CONDITIONAL_CONTINUES],
    conditional_continue_control_orders: [usize; MAX_NESTED_LOOP_CONDITIONAL_CONTINUES],
    conditional_continue_targets: [NestedLoopControlTarget; MAX_NESTED_LOOP_CONDITIONAL_CONTINUES],
    conditional_continue_count: usize,
    conditional_returns: [Option<ConditionalReturn<'source>>; MAX_NESTED_LOOP_CONDITIONAL_RETURNS],
    conditional_return_action_indices: [usize; MAX_NESTED_LOOP_CONDITIONAL_RETURNS],
    conditional_return_control_orders: [usize; MAX_NESTED_LOOP_CONDITIONAL_RETURNS],
    conditional_return_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NestedLoopConditionalBlock<'source> {
    pub condition: &'source str,
    pub condition_span: Span,
    actions: [Option<ConditionalLoopAction<'source>>; MAX_CONDITIONAL_LOOP_ACTIONS],
    action_count: usize,
    pub terminal: NestedLoopUnconditionalControl<'source>,
    else_arms: [Option<NestedLoopConditionalArm<'source>>; MAX_NESTED_LOOP_CONDITIONAL_ELSE_ARMS],
    else_arm_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NestedLoopConditionalArm<'source> {
    condition: Option<&'source str>,
    condition_span: Span,
    actions: [Option<ConditionalLoopAction<'source>>; MAX_CONDITIONAL_LOOP_ACTIONS],
    action_count: usize,
    pub terminal: NestedLoopUnconditionalControl<'source>,
}

impl<'source> NestedLoopConditionalBlock<'source> {
    pub fn actions(&self) -> &[Option<ConditionalLoopAction<'source>>] {
        &self.actions[..self.action_count]
    }

    pub const fn action_count(&self) -> usize {
        self.action_count
    }

    pub const fn else_arm(&self) -> Option<&NestedLoopConditionalArm<'source>> {
        if self.else_arm_count == 0 {
            None
        } else {
            self.else_arms[0].as_ref()
        }
    }

    pub fn else_arms(&self) -> &[Option<NestedLoopConditionalArm<'source>>] {
        &self.else_arms[..self.else_arm_count]
    }

    pub const fn else_arm_count(&self) -> usize {
        self.else_arm_count
    }

    pub fn parse_condition<const MAX_NODES: usize>(
        &self,
    ) -> Result<ExpressionTree<'source, MAX_NODES>, ExpressionError> {
        ExpressionParser::new(self.condition).parse()
    }
}

impl<'source> NestedLoopConditionalArm<'source> {
    pub const fn condition(&self) -> Option<&'source str> {
        self.condition
    }

    pub const fn condition_span(&self) -> Span {
        self.condition_span
    }

    pub fn parse_condition<const MAX_NODES: usize>(
        &self,
    ) -> Result<Option<ExpressionTree<'source, MAX_NODES>>, ExpressionError> {
        self.condition
            .map(ExpressionParser::new)
            .map(|parser| parser.parse())
            .transpose()
    }

    pub fn actions(&self) -> &[Option<ConditionalLoopAction<'source>>] {
        &self.actions[..self.action_count]
    }

    pub const fn action_count(&self) -> usize {
        self.action_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NestedLoopUnconditionalControl<'source> {
    Break(NestedLoopControlTarget),
    Continue(NestedLoopControlTarget),
    Return(LoopReturn<'source>),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum NestedLoopControlTarget {
    #[default]
    Inner,
    Outer,
}

impl<'source> NestedLoopBlock<'source> {
    pub fn actions(&self) -> &[Option<ConditionalLoopAction<'source>>] {
        &self.actions[..self.action_count]
    }

    pub const fn action_count(&self) -> usize {
        self.action_count
    }

    pub fn conditional_blocks(&self) -> &[Option<NestedLoopConditionalBlock<'source>>] {
        &self.conditional_blocks[..self.conditional_block_count]
    }

    pub fn conditional_block_action_indices(&self) -> &[usize] {
        &self.conditional_block_action_indices[..self.conditional_block_count]
    }

    pub fn conditional_block_control_orders(&self) -> &[usize] {
        &self.conditional_block_control_orders[..self.conditional_block_count]
    }

    pub fn unconditional_controls(&self) -> &[Option<NestedLoopUnconditionalControl<'source>>] {
        &self.unconditional_controls[..self.unconditional_control_count]
    }

    pub fn unconditional_control_action_indices(&self) -> &[usize] {
        &self.unconditional_control_action_indices[..self.unconditional_control_count]
    }

    pub fn unconditional_control_orders(&self) -> &[usize] {
        &self.unconditional_control_orders[..self.unconditional_control_count]
    }

    pub fn conditional_breaks(&self) -> &[Option<ConditionalLoopControl<'source>>] {
        &self.conditional_breaks[..self.conditional_break_count]
    }

    pub fn conditional_break_action_indices(&self) -> &[usize] {
        &self.conditional_break_action_indices[..self.conditional_break_count]
    }

    pub fn conditional_break_control_orders(&self) -> &[usize] {
        &self.conditional_break_control_orders[..self.conditional_break_count]
    }

    pub fn conditional_break_targets(&self) -> &[NestedLoopControlTarget] {
        &self.conditional_break_targets[..self.conditional_break_count]
    }

    pub fn conditional_continues(&self) -> &[Option<ConditionalLoopControl<'source>>] {
        &self.conditional_continues[..self.conditional_continue_count]
    }

    pub fn conditional_continue_action_indices(&self) -> &[usize] {
        &self.conditional_continue_action_indices[..self.conditional_continue_count]
    }

    pub fn conditional_continue_control_orders(&self) -> &[usize] {
        &self.conditional_continue_control_orders[..self.conditional_continue_count]
    }

    pub fn conditional_continue_targets(&self) -> &[NestedLoopControlTarget] {
        &self.conditional_continue_targets[..self.conditional_continue_count]
    }

    pub fn conditional_returns(&self) -> &[Option<ConditionalReturn<'source>>] {
        &self.conditional_returns[..self.conditional_return_count]
    }

    pub fn conditional_return_action_indices(&self) -> &[usize] {
        &self.conditional_return_action_indices[..self.conditional_return_count]
    }

    pub fn conditional_return_control_orders(&self) -> &[usize] {
        &self.conditional_return_control_orders[..self.conditional_return_count]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConditionalLoopBlock<'source> {
    pub condition: &'source str,
    pub condition_span: Span,
    actions: [Option<ConditionalLoopAction<'source>>; MAX_CONDITIONAL_LOOP_ACTIONS],
    action_count: usize,
    pub terminal: Option<ConditionalLoopTerminal<'source>>,
    pub else_arm: Option<usize>,
    pub else_arm_count: usize,
}

impl<'source> ConditionalLoopBlock<'source> {
    pub fn actions(&self) -> &[Option<ConditionalLoopAction<'source>>] {
        &self.actions[..self.action_count]
    }

    pub const fn action_count(&self) -> usize {
        self.action_count
    }

    pub fn parse_condition<const MAX_NODES: usize>(
        &self,
    ) -> Result<ExpressionTree<'source, MAX_NODES>, ExpressionError> {
        ExpressionParser::new(self.condition).parse()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoopReturn<'source> {
    pub value: &'source str,
    pub value_span: Span,
}

impl<'source> LoopReturn<'source> {
    pub fn parse_value<const MAX_NODES: usize>(
        &self,
    ) -> Result<ExpressionTree<'source, MAX_NODES>, ExpressionError> {
        ExpressionParser::new(self.value).parse()
    }
}

impl<'source> ConditionalLoopControl<'source> {
    pub fn parse_condition<const MAX_NODES: usize>(
        &self,
    ) -> Result<ExpressionTree<'source, MAX_NODES>, ExpressionError> {
        ExpressionParser::new(self.condition).parse()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoopOperation<'source> {
    Local(LocalBinding<'source>),
    Assignment(Assignment<'source>),
    Expression(ExpressionStatement<'source>),
    Break,
    Continue,
    ConditionalBreak(ConditionalLoopControl<'source>),
    ConditionalContinue(ConditionalLoopControl<'source>),
    ConditionalReturn(ConditionalReturn<'source>),
    ConditionalBlock(usize),
    Return(LoopReturn<'source>),
    NestedUnitLoop,
    NestedBlock(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyStatement {
    Local(usize),
    Assignment(usize),
    ConditionalReturn(usize),
    Loop(usize),
    Expression(usize),
    Return(usize),
    ConditionalReturnElse(usize),
    ConditionalAssignment(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpressionStatement<'source> {
    pub expression: &'source str,
    pub span: Span,
    pub unsafe_context: bool,
    pub terminal: bool,
}

impl<'source> ExpressionStatement<'source> {
    pub fn parse<const MAX_NODES: usize>(
        &self,
    ) -> Result<ExpressionTree<'source, MAX_NODES>, ExpressionError> {
        ExpressionParser::new(self.expression).parse()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WhileLoop<'source> {
    pub label: Option<&'source str>,
    pub condition: Option<&'source str>,
    pub condition_span: Span,
    operations: [Option<LoopOperation<'source>>; MAX_LOOP_OPERATIONS],
    operation_count: usize,
    assignment_count: usize,
    conditional_blocks: [Option<ConditionalLoopBlock<'source>>; MAX_LOOP_OPERATIONS],
    conditional_block_count: usize,
    conditional_else_arms: [Option<ConditionalLoopArm<'source>>; MAX_CONDITIONAL_LOOP_ELSE_ARMS],
    conditional_else_arm_count: usize,
    nested_blocks: [Option<NestedLoopBlock<'source>>; MAX_NESTED_LOOP_BLOCKS],
    nested_block_count: usize,
}

impl<'source> WhileLoop<'source> {
    pub fn parse_condition<const MAX_NODES: usize>(
        &self,
    ) -> Result<Option<ExpressionTree<'source, MAX_NODES>>, ExpressionError> {
        self.condition
            .map(|condition| ExpressionParser::new(condition).parse())
            .transpose()
    }

    pub fn operations(&self) -> &[Option<LoopOperation<'source>>] {
        &self.operations[..self.operation_count]
    }

    pub const fn assignment_count(&self) -> usize {
        self.assignment_count
    }

    pub const fn operation_count(&self) -> usize {
        self.operation_count
    }

    pub fn conditional_blocks(&self) -> &[Option<ConditionalLoopBlock<'source>>] {
        &self.conditional_blocks[..self.conditional_block_count]
    }

    pub const fn conditional_block_count(&self) -> usize {
        self.conditional_block_count
    }

    pub fn conditional_else_arms(&self) -> &[Option<ConditionalLoopArm<'source>>] {
        &self.conditional_else_arms[..self.conditional_else_arm_count]
    }

    pub fn nested_blocks(&self) -> &[Option<NestedLoopBlock<'source>>] {
        &self.nested_blocks[..self.nested_block_count]
    }
}

impl<'source> Assignment<'source> {
    pub const fn binding_name(&self) -> &'source str {
        self.name
    }

    pub const fn dereferences(&self) -> bool {
        matches!(
            self.projection,
            Some(AssignmentProjection::Dereference { .. })
        )
    }

    pub const fn index(&self) -> Option<&'source str> {
        match self.projection {
            Some(AssignmentProjection::Index { expression, .. }) => Some(expression),
            _ => None,
        }
    }

    pub const fn tuple_field(&self) -> Option<usize> {
        match self.projection {
            Some(AssignmentProjection::TupleField { field, .. }) => Some(field),
            _ => None,
        }
    }

    pub const fn index_span(&self) -> Option<Span> {
        match self.projection {
            Some(AssignmentProjection::Index { span, .. }) => Some(span),
            _ => None,
        }
    }

    pub fn parse_index<const MAX_NODES: usize>(
        &self,
    ) -> Result<ExpressionTree<'source, MAX_NODES>, ExpressionError> {
        ExpressionParser::new(self.index().unwrap_or("")).parse()
    }

    pub fn parse_value<const MAX_NODES: usize>(
        &self,
    ) -> Result<ExpressionTree<'source, MAX_NODES>, ExpressionError> {
        ExpressionParser::new(self.value).parse()
    }
}

impl<'source> LocalBinding<'source> {
    pub fn parse_initializer<const MAX_NODES: usize>(
        &self,
    ) -> Result<ExpressionTree<'source, MAX_NODES>, ExpressionError> {
        ExpressionParser::new(self.initializer).parse()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FunctionBody<'source, const MAX_LOCALS: usize> {
    statements: [Option<BodyStatement>; MAX_BODY_STATEMENTS],
    statement_count: usize,
    locals: [Option<LocalBinding<'source>>; MAX_LOCALS],
    local_count: usize,
    assignments: [Option<Assignment<'source>>; MAX_LOCALS],
    assignment_count: usize,
    conditional_returns: [Option<ConditionalReturn<'source>>; MAX_LOCALS],
    conditional_return_count: usize,
    conditional_return_elses: [Option<ConditionalReturnElse<'source>>; MAX_LOCALS],
    conditional_return_else_count: usize,
    conditional_assignments:
        [Option<ConditionalAssignment<'source>>; MAX_BODY_CONDITIONAL_ASSIGNMENTS],
    conditional_assignment_count: usize,
    while_loops: [Option<WhileLoop<'source>>; MAX_LOCALS],
    while_loop_count: usize,
    expression_statements: [Option<ExpressionStatement<'source>>; MAX_BODY_EXPRESSION_STATEMENTS],
    expression_statement_count: usize,
    returns: [Option<LoopReturn<'source>>; MAX_BODY_RETURNS],
    return_count: usize,
    pub tail_expression: &'source str,
    pub tail_span: Span,
    pub implicit_unit: bool,
    pub tail_diverges: bool,
}

impl<'source, const MAX_LOCALS: usize> FunctionBody<'source, MAX_LOCALS> {
    pub fn statements(&self) -> &[Option<BodyStatement>] {
        &self.statements[..self.statement_count]
    }

    pub const fn statement_count(&self) -> usize {
        self.statement_count
    }

    fn push_statement(&mut self, statement: BodyStatement) -> bool {
        let Some(slot) = self.statements.get_mut(self.statement_count) else {
            return false;
        };
        *slot = Some(statement);
        self.statement_count += 1;
        true
    }

    pub fn locals(&self) -> &[Option<LocalBinding<'source>>] {
        &self.locals[..self.local_count]
    }

    pub const fn local_count(&self) -> usize {
        self.local_count
    }

    pub fn assignments(&self) -> &[Option<Assignment<'source>>] {
        &self.assignments[..self.assignment_count]
    }

    pub const fn assignment_count(&self) -> usize {
        self.assignment_count
    }

    pub fn conditional_returns(&self) -> &[Option<ConditionalReturn<'source>>] {
        &self.conditional_returns[..self.conditional_return_count]
    }

    pub const fn conditional_return_count(&self) -> usize {
        self.conditional_return_count
    }

    pub fn conditional_return_elses(&self) -> &[Option<ConditionalReturnElse<'source>>] {
        &self.conditional_return_elses[..self.conditional_return_else_count]
    }

    pub const fn conditional_return_else_count(&self) -> usize {
        self.conditional_return_else_count
    }

    pub fn conditional_assignments(&self) -> &[Option<ConditionalAssignment<'source>>] {
        &self.conditional_assignments[..self.conditional_assignment_count]
    }

    pub const fn conditional_assignment_count(&self) -> usize {
        self.conditional_assignment_count
    }

    pub fn while_loops(&self) -> &[Option<WhileLoop<'source>>] {
        &self.while_loops[..self.while_loop_count]
    }

    pub const fn while_loop_count(&self) -> usize {
        self.while_loop_count
    }

    pub fn expression_statements(&self) -> &[Option<ExpressionStatement<'source>>] {
        &self.expression_statements[..self.expression_statement_count]
    }

    pub const fn expression_statement_count(&self) -> usize {
        self.expression_statement_count
    }

    pub fn returns(&self) -> &[Option<LoopReturn<'source>>] {
        &self.returns[..self.return_count]
    }

    pub const fn return_count(&self) -> usize {
        self.return_count
    }

    pub fn parse_tail<const MAX_NODES: usize>(
        &self,
    ) -> Result<ExpressionTree<'source, MAX_NODES>, ExpressionError> {
        ExpressionParser::new(self.tail_expression).parse()
    }
}

pub(crate) fn parse_function_body<
    'source,
    const MAX_LOCALS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    source: &'source str,
) -> Result<FunctionBody<'source, MAX_LOCALS>, ParseError> {
    BodyParser::new(source).parse::<MAX_LOCALS, MAX_EXPRESSION_NODES>()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConstItem<'source> {
    pub public: bool,
    pub name: &'source str,
    pub name_span: Span,
    pub ty: TypeRef<'source>,
    pub initializer: &'source str,
    pub initializer_span: Span,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraitDeclaration<'source> {
    pub public: bool,
    pub name: &'source str,
    pub name_span: Span,
    generic_parameters: [Option<&'source str>; MAX_SOURCE_TRAIT_ARGUMENTS],
    generic_parameter_defaults: [Option<TypeRef<'source>>; MAX_SOURCE_TRAIT_ARGUMENTS],
    generic_parameter_count: usize,
    supertraits: [Option<TraitSupertrait<'source>>; MAX_TRAIT_SUPERTRAITS],
    supertrait_count: usize,
    where_predicates:
        [Option<TraitImplementationWherePredicate<'source>>; MAX_FUNCTION_WHERE_PREDICATES],
    where_predicate_count: usize,
    associated_types: [Option<TraitAssociatedTypeDeclaration<'source>>; MAX_TRAIT_ASSOCIATED_TYPES],
    associated_type_count: usize,
    pub body: Span,
}

impl<'source> TraitDeclaration<'source> {
    pub fn generic_parameters(&self) -> &[Option<&'source str>] {
        &self.generic_parameters[..self.generic_parameter_count]
    }

    pub fn generic_parameter_defaults(&self) -> &[Option<TypeRef<'source>>] {
        &self.generic_parameter_defaults[..self.generic_parameter_count]
    }

    pub const fn generic_parameter_count(&self) -> usize {
        self.generic_parameter_count
    }
    pub fn supertraits(&self) -> &[Option<TraitSupertrait<'source>>] {
        &self.supertraits[..self.supertrait_count]
    }

    pub const fn supertrait_count(&self) -> usize {
        self.supertrait_count
    }

    pub fn where_predicates(&self) -> &[Option<TraitImplementationWherePredicate<'source>>] {
        &self.where_predicates[..self.where_predicate_count]
    }

    pub const fn where_predicate_count(&self) -> usize {
        self.where_predicate_count
    }

    pub fn associated_types(&self) -> &[Option<TraitAssociatedTypeDeclaration<'source>>] {
        &self.associated_types[..self.associated_type_count]
    }

    pub const fn associated_type_count(&self) -> usize {
        self.associated_type_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraitAssociatedTypeDeclaration<'source> {
    pub name: &'source str,
    pub span: Span,
    pub default: Option<TypeRef<'source>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraitSupertrait<'source> {
    pub name: &'source str,
    pub span: Span,
    arguments: [Option<TypeRef<'source>>; MAX_SOURCE_TRAIT_ARGUMENTS],
    argument_count: usize,
}

impl<'source> TraitSupertrait<'source> {
    pub fn arguments(&self) -> &[Option<TypeRef<'source>>] {
        &self.arguments[..self.argument_count]
    }

    pub const fn argument_count(&self) -> usize {
        self.argument_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraitImplementation<'source> {
    generic_parameters: [Option<&'source str>; MAX_SOURCE_TRAIT_ARGUMENTS],
    generic_parameter_count: usize,
    pub trait_name: &'source str,
    pub trait_name_span: Span,
    trait_arguments: [Option<TypeRef<'source>>; MAX_SOURCE_TRAIT_ARGUMENTS],
    trait_argument_count: usize,
    pub self_type: TypeRef<'source>,
    where_predicates:
        [Option<TraitImplementationWherePredicate<'source>>; MAX_FUNCTION_WHERE_PREDICATES],
    where_predicate_count: usize,
    associated_types:
        [Option<TraitAssociatedTypeImplementation<'source>>; MAX_TRAIT_ASSOCIATED_TYPES],
    associated_type_count: usize,
    pub body: Span,
}

impl<'source> TraitImplementation<'source> {
    pub fn generic_parameters(&self) -> &[Option<&'source str>] {
        &self.generic_parameters[..self.generic_parameter_count]
    }

    pub const fn generic_parameter_count(&self) -> usize {
        self.generic_parameter_count
    }

    pub fn where_predicates(&self) -> &[Option<TraitImplementationWherePredicate<'source>>] {
        &self.where_predicates[..self.where_predicate_count]
    }

    pub const fn where_predicate_count(&self) -> usize {
        self.where_predicate_count
    }
    pub fn trait_arguments(&self) -> &[Option<TypeRef<'source>>] {
        &self.trait_arguments[..self.trait_argument_count]
    }

    pub const fn trait_argument_count(&self) -> usize {
        self.trait_argument_count
    }
    pub fn associated_types(&self) -> &[Option<TraitAssociatedTypeImplementation<'source>>] {
        &self.associated_types[..self.associated_type_count]
    }

    pub const fn associated_type_count(&self) -> usize {
        self.associated_type_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraitImplementationWherePredicate<'source> {
    Implemented {
        self_type: TypeRef<'source>,
        trait_name: &'source str,
        trait_name_span: Span,
        trait_arguments: [Option<TypeRef<'source>>; MAX_SOURCE_TRAIT_ARGUMENTS],
        trait_argument_count: usize,
    },
    ProjectionEquality {
        self_type: TypeRef<'source>,
        trait_name: &'source str,
        trait_name_span: Span,
        trait_arguments: [Option<TypeRef<'source>>; MAX_SOURCE_TRAIT_ARGUMENTS],
        trait_argument_count: usize,
        associated_type: &'source str,
        associated_type_span: Span,
        expected_type: TypeRef<'source>,
    },
}

impl<'source> TraitImplementationWherePredicate<'source> {
    pub const fn self_type(&self) -> TypeRef<'source> {
        match self {
            Self::Implemented { self_type, .. } | Self::ProjectionEquality { self_type, .. } => {
                *self_type
            }
        }
    }

    pub const fn trait_name(&self) -> &'source str {
        match self {
            Self::Implemented { trait_name, .. } | Self::ProjectionEquality { trait_name, .. } => {
                trait_name
            }
        }
    }

    pub const fn trait_name_span(&self) -> Span {
        match self {
            Self::Implemented {
                trait_name_span, ..
            }
            | Self::ProjectionEquality {
                trait_name_span, ..
            } => *trait_name_span,
        }
    }

    pub fn trait_arguments(&self) -> &[Option<TypeRef<'source>>] {
        match self {
            Self::Implemented {
                trait_arguments,
                trait_argument_count,
                ..
            }
            | Self::ProjectionEquality {
                trait_arguments,
                trait_argument_count,
                ..
            } => &trait_arguments[..*trait_argument_count],
        }
    }

    pub const fn trait_argument_count(&self) -> usize {
        match self {
            Self::Implemented {
                trait_argument_count,
                ..
            }
            | Self::ProjectionEquality {
                trait_argument_count,
                ..
            } => *trait_argument_count,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraitAssociatedTypeImplementation<'source> {
    pub name: &'source str,
    pub name_span: Span,
    pub value: TypeRef<'source>,
}

impl<'source> ConstItem<'source> {
    pub fn parse_initializer<const MAX_NODES: usize>(
        &self,
    ) -> Result<ExpressionTree<'source, MAX_NODES>, ExpressionError> {
        ExpressionParser::new(self.initializer).parse()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Item<'source, const MAX_PARAMETERS: usize> {
    Function(Function<'source, MAX_PARAMETERS>),
    Const(ConstItem<'source>),
    Static(ConstItem<'source>),
    Trait(TraitDeclaration<'source>),
    TraitImplementation(TraitImplementation<'source>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Module<'source, const MAX_ITEMS: usize, const MAX_PARAMETERS: usize> {
    items: [Option<Item<'source, MAX_PARAMETERS>>; MAX_ITEMS],
    item_count: usize,
}

impl<'source, const MAX_ITEMS: usize, const MAX_PARAMETERS: usize>
    Module<'source, MAX_ITEMS, MAX_PARAMETERS>
{
    pub fn items(&self) -> &[Option<Item<'source, MAX_PARAMETERS>>] {
        &self.items[..self.item_count]
    }

    pub const fn item_count(&self) -> usize {
        self.item_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseErrorKind {
    Lexical(LexError),
    ExpectedItem,
    ExpectedStructName,
    ExpectedEnumName,
    ExpectedStructBody,
    ExpectedEnumBody,
    UnsupportedStructDeclaration,
    UnsupportedEnumDeclaration,
    UnsupportedAttribute,
    UnsupportedAbi,
    ExpectedAttributeDelimiter,
    ExpectedIdentifier,
    ExpectedAssignmentTarget,
    ExpectedParameterSeparator,
    ExpectedType,
    ExpectedEquals,
    ExpectedInitializer,
    ExpectedSemicolon,
    ExpectedColon,
    ExpectedBody,
    UnsupportedTraitBody,
    ExpectedFor,
    UnsupportedTraitImplementationBody,
    UnknownLoopLabel,
    UnexpectedClosingDelimiter,
    UnterminatedDelimiter,
    NestingLimitExceeded,
    TooManyItems,
    TooManyParameters,
    TooManyWherePredicates,
    TooManySupertraits,
    TooManyAssociatedTypes,
    TooManyGenericArguments,
    TooManyLocals,
    TooManyLoopAssignments,
    TooManyLoopOperations,
    TooManyConditionalLoopActions,
    TooManyConditionalLoopElseArms,
    TooManyNestedLoopActions,
    TooManyNestedLoopBlocks,
    TooManyNestedLoopConditionalBlocks,
    TooManyNestedLoopConditionalBreaks,
    TooManyNestedLoopConditionalContinues,
    TooManyNestedLoopConditionalReturns,
    TooManyNestedLoopUnconditionalControls,
    TooManyExpressionStatements,
    TooManyReturns,
    TooManyConditionalReturnBranches,
    TooManyConditionalAssignments,
    TooManyConditionalAssignmentBranches,
    TooManyConditionalBranchActions,
    ExpectedTailExpression,
}

impl ParseErrorKind {
    pub(crate) const fn aggregate_declaration_message(self) -> Option<&'static str> {
        match self {
            Self::ExpectedStructName => Some("expected a name after `struct`"),
            Self::ExpectedEnumName => Some("expected a name after `enum`"),
            Self::ExpectedStructBody => Some("expected `{`, `(`, or `;` after the struct name"),
            Self::ExpectedEnumBody => Some("expected `{` after the enum name"),
            Self::UnsupportedStructDeclaration => Some(
                "struct declarations are unsupported by the experimental MRML compiler. Use the upstream Rust compiler for this source",
            ),
            Self::UnsupportedEnumDeclaration => Some(
                "enum declarations are unsupported by the experimental MRML compiler. Use the upstream Rust compiler for this source",
            ),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseError {
    pub kind: ParseErrorKind,
    pub span: Span,
}

pub struct Parser<'source> {
    source: &'source str,
    lexer: Lexer<'source>,
    lookahead: Option<Token<'source>>,
}

#[derive(Clone)]
struct BodyParser<'source> {
    source: &'source str,
    lexer: Lexer<'source>,
    lookahead: Option<Token<'source>>,
}

impl<'source> BodyParser<'source> {
    const fn new(source: &'source str) -> Self {
        Self {
            source,
            lexer: Lexer::new(source),
            lookahead: None,
        }
    }

    fn lexical(error: LexError) -> ParseError {
        ParseError {
            kind: ParseErrorKind::Lexical(error),
            span: error.span,
        }
    }

    fn peek(&mut self) -> Result<Option<Token<'source>>, ParseError> {
        if self.lookahead.is_none() {
            self.lookahead = self.lexer.next_token().map_err(Self::lexical)?;
        }
        Ok(self.lookahead)
    }

    fn take(&mut self) -> Result<Option<Token<'source>>, ParseError> {
        if let Some(token) = self.lookahead.take() {
            Ok(Some(token))
        } else {
            self.lexer.next_token().map_err(Self::lexical)
        }
    }

    fn error(&self, kind: ParseErrorKind, token: Option<Token<'source>>) -> ParseError {
        ParseError {
            kind,
            span: token.map_or(
                Span {
                    start: self.source.len(),
                    end: self.source.len(),
                },
                |token| token.span,
            ),
        }
    }

    fn delimited_until(
        &mut self,
        terminator: &str,
        missing: ParseErrorKind,
    ) -> Result<(Span, Token<'source>), ParseError> {
        let mut depth = 0usize;
        let mut first = None;
        let mut end = 0usize;
        loop {
            let token = self.take()?.ok_or_else(|| self.error(missing, None))?;
            if depth == 0 && token.text == terminator {
                let start = first.ok_or_else(|| self.error(missing, Some(token)))?;
                return Ok((Span { start, end }, token));
            }
            match token.kind {
                TokenKind::OpenParen | TokenKind::OpenBrace | TokenKind::OpenBracket => {
                    if depth == MAX_DELIMITER_DEPTH {
                        return Err(self.error(ParseErrorKind::NestingLimitExceeded, Some(token)));
                    }
                    depth = depth.checked_add(1).ok_or_else(|| {
                        self.error(ParseErrorKind::NestingLimitExceeded, Some(token))
                    })?;
                }
                TokenKind::CloseParen | TokenKind::CloseBrace | TokenKind::CloseBracket => {
                    depth = depth.checked_sub(1).ok_or_else(|| {
                        self.error(ParseErrorKind::UnexpectedClosingDelimiter, Some(token))
                    })?;
                }
                _ => {}
            }
            first.get_or_insert(token.span.start);
            end = token.span.end;
        }
    }

    fn return_value(&mut self) -> Result<(&'source str, Span), ParseError> {
        if let Some(semicolon) = self
            .peek()?
            .filter(|token| token.kind == TokenKind::Semicolon)
        {
            self.take()?;
            return Ok((
                "()",
                Span {
                    start: semicolon.span.start,
                    end: semicolon.span.start,
                },
            ));
        }
        let (span, _) = self.delimited_until(";", ParseErrorKind::ExpectedSemicolon)?;
        Ok((&self.source[span.start..span.end], span))
    }

    fn parse_local<const MAX_LOCALS: usize>(
        &mut self,
        body: &mut FunctionBody<'source, MAX_LOCALS>,
    ) -> Result<bool, ParseError> {
        if !self.peek()?.is_some_and(|token| token.text == "let") {
            return Ok(false);
        }
        let let_token = self
            .peek()?
            .ok_or_else(|| self.error(ParseErrorKind::ExpectedIdentifier, None))?;
        if body.local_count == MAX_LOCALS {
            return Err(self.error(ParseErrorKind::TooManyLocals, Some(let_token)));
        }
        let Some(local) = self.local_record()? else {
            return Ok(false);
        };
        if !body.push_statement(BodyStatement::Local(body.local_count)) {
            return Err(self.error(ParseErrorKind::TooManyLocals, Some(let_token)));
        }
        body.locals[body.local_count] = Some(local);
        body.local_count += 1;
        Ok(true)
    }

    fn local_record(&mut self) -> Result<Option<LocalBinding<'source>>, ParseError> {
        if !self.peek()?.is_some_and(|token| token.text == "let") {
            return Ok(None);
        }
        self.take()?;
        let mutable = self.peek()?.is_some_and(|token| token.text == "mut");
        if mutable {
            self.take()?;
        }
        let name = self.take()?;
        let Some(name) = name.filter(|token| token.kind == TokenKind::Identifier) else {
            return Err(self.error(ParseErrorKind::ExpectedIdentifier, name));
        };
        if mutable && name.text == "_" {
            return Err(self.error(ParseErrorKind::ExpectedIdentifier, Some(name)));
        }
        let ty = if self
            .peek()?
            .is_some_and(|token| token.kind == TokenKind::Colon)
        {
            self.take()?;
            let mut uninitialized_probe = self.clone();
            let explicit_type = uninitialized_probe.take()?;
            if let Some(explicit_type) = explicit_type {
                let explicit_type_span = if explicit_type.kind == TokenKind::Identifier {
                    Some(explicit_type.span)
                } else if explicit_type.text == "*" {
                    let pointer_kind = uninitialized_probe.take()?;
                    let pointee = uninitialized_probe.take()?;
                    match (pointer_kind, pointee) {
                        (Some(pointer_kind), Some(pointee))
                            if matches!(pointer_kind.text, "const" | "mut")
                                && pointee.kind == TokenKind::Identifier =>
                        {
                            Some(Span {
                                start: explicit_type.span.start,
                                end: pointee.span.end,
                            })
                        }
                        _ => None,
                    }
                } else if explicit_type.text == "&" {
                    let mut pointee = uninitialized_probe.take()?;
                    if pointee.is_some_and(|token| token.text == "mut") {
                        pointee = uninitialized_probe.take()?;
                    }
                    pointee
                        .filter(|pointee| pointee.kind == TokenKind::Identifier)
                        .map(|pointee| Span {
                            start: explicit_type.span.start,
                            end: pointee.span.end,
                        })
                } else {
                    None
                };
                let terminator = uninitialized_probe.peek()?;
                if let (Some(explicit_type_span), Some(terminator)) =
                    (explicit_type_span, terminator)
                    && terminator.text == ";"
                {
                    uninitialized_probe.take()?;
                    *self = uninitialized_probe;
                    return Ok(Some(LocalBinding {
                        mutable,
                        initialized: false,
                        name: name.text,
                        name_span: name.span,
                        ty: Some(TypeRef {
                            text: &self.source[explicit_type_span.start..explicit_type_span.end],
                            span: explicit_type_span,
                        }),
                        initializer: "",
                        initializer_span: terminator.span,
                    }));
                }
            }
            let (ty_span, _) = self.delimited_until("=", ParseErrorKind::ExpectedEquals)?;
            Some(TypeRef {
                text: &self.source[ty_span.start..ty_span.end],
                span: ty_span,
            })
        } else {
            let equals = self.take()?;
            if !equals.is_some_and(|token| token.text == "=") {
                return Err(self.error(ParseErrorKind::ExpectedEquals, equals));
            }
            None
        };
        let (initializer_span, _) = self.delimited_until(";", ParseErrorKind::ExpectedSemicolon)?;
        Ok(Some(LocalBinding {
            mutable,
            initialized: true,
            name: name.text,
            name_span: name.span,
            ty,
            initializer: &self.source[initializer_span.start..initializer_span.end],
            initializer_span,
        }))
    }

    fn parse_assignment<const MAX_LOCALS: usize>(
        &mut self,
        body: &mut FunctionBody<'source, MAX_LOCALS>,
    ) -> Result<bool, ParseError> {
        let Some(first) = self.peek()? else {
            return Ok(false);
        };
        if first.kind != TokenKind::Identifier && first.text != "*" {
            return Ok(false);
        }
        let mut probe = self.clone();
        probe.take()?;
        let (name, dereference) = if first.text == "*" {
            let Some(name) = probe.take()? else {
                return Ok(false);
            };
            if name.kind != TokenKind::Identifier {
                return Ok(false);
            }
            (name, true)
        } else {
            if matches!(first.text, "if" | "while" | "loop" | "let") {
                return Ok(false);
            }
            (first, false)
        };
        let (projection, target_end, invalid_projection) = if dereference {
            (
                Some(AssignmentProjection::Dereference { span: first.span }),
                name.span.end,
                None,
            )
        } else {
            probe.assignment_projection(name.span.end)?
        };
        let Some(operator_token) = probe.peek()? else {
            return Ok(false);
        };
        let Some(operator) = AssignmentOperator::from_text(operator_token.text) else {
            return Ok(false);
        };
        if let Some(span) = invalid_projection {
            return Err(ParseError {
                kind: ParseErrorKind::ExpectedAssignmentTarget,
                span,
            });
        }
        probe.take()?;
        if body.assignment_count == MAX_LOCALS {
            return Err(probe.error(ParseErrorKind::TooManyLocals, Some(name)));
        }
        let value_span = match probe.delimited_until(";", ParseErrorKind::ExpectedSemicolon) {
            Ok((span, _)) => span,
            Err(error) if error.kind == ParseErrorKind::ExpectedSemicolon => return Ok(false),
            Err(error) => return Err(error),
        };
        let assignment = Assignment {
            name: name.text,
            name_span: Span {
                start: first.span.start,
                end: target_end,
            },
            projection,
            operator,
            value: &self.source[value_span.start..value_span.end],
            value_span,
        };
        if !body.push_statement(BodyStatement::Assignment(body.assignment_count)) {
            return Err(probe.error(ParseErrorKind::TooManyLocals, Some(name)));
        }
        body.assignments[body.assignment_count] = Some(assignment);
        body.assignment_count += 1;
        *self = probe;
        Ok(true)
    }

    fn assignment_record(&mut self) -> Result<Option<Assignment<'source>>, ParseError> {
        let Some(first) = self.peek()? else {
            return Ok(None);
        };
        if first.kind != TokenKind::Identifier && first.text != "*" {
            return Ok(None);
        }
        let mut probe = self.clone();
        probe.take()?;
        let (name, dereference) = if first.text == "*" {
            let Some(name) = probe.take()? else {
                return Ok(None);
            };
            if name.kind != TokenKind::Identifier {
                return Ok(None);
            }
            (name, true)
        } else {
            (first, false)
        };
        let (projection, target_end, invalid_projection) = if dereference {
            (
                Some(AssignmentProjection::Dereference { span: first.span }),
                name.span.end,
                None,
            )
        } else {
            probe.assignment_projection(name.span.end)?
        };
        let Some(operator_token) = probe.take()? else {
            return Ok(None);
        };
        let Some(operator) = AssignmentOperator::from_text(operator_token.text) else {
            return Ok(None);
        };
        if let Some(span) = invalid_projection {
            return Err(ParseError {
                kind: ParseErrorKind::ExpectedAssignmentTarget,
                span,
            });
        }
        let (value_span, _) = probe.delimited_until(";", ParseErrorKind::ExpectedSemicolon)?;
        *self = probe;
        Ok(Some(Assignment {
            name: name.text,
            name_span: Span {
                start: first.span.start,
                end: target_end,
            },
            projection,
            operator,
            value: &self.source[value_span.start..value_span.end],
            value_span,
        }))
    }

    fn assignment_projection(
        &mut self,
        name_end: usize,
    ) -> Result<(Option<AssignmentProjection<'source>>, usize, Option<Span>), ParseError> {
        if self.peek()?.is_some_and(|token| token.text == ".") {
            let dot = self.take()?.unwrap();
            let Some(field) = self.take()? else {
                return Ok((None, dot.span.end, Some(dot.span)));
            };
            if field.kind != TokenKind::Integer {
                return Ok((None, field.span.end, Some(field.span)));
            }
            let Ok(field_index) = field.text.parse::<usize>() else {
                return Ok((None, field.span.end, Some(field.span)));
            };
            return Ok((
                Some(AssignmentProjection::TupleField {
                    field: field_index,
                    span: field.span,
                }),
                field.span.end,
                None,
            ));
        }
        if !self
            .peek()?
            .is_some_and(|token| token.kind == TokenKind::OpenBracket)
        {
            return Ok((None, name_end, None));
        }
        self.take()?;
        let (expression_span, close) =
            self.delimited_until("]", ParseErrorKind::UnterminatedDelimiter)?;
        let expression = &self.source[expression_span.start..expression_span.end];
        let trimmed = expression.trim();
        let leading = expression.len() - expression.trim_start().len();
        let span = Span {
            start: expression_span.start + leading,
            end: expression_span.start + leading + trimmed.len(),
        };
        Ok((
            Some(AssignmentProjection::Index {
                expression: trimmed,
                span,
            }),
            close.span.end,
            None,
        ))
    }

    fn expression_statement_record(
        &mut self,
    ) -> Result<Option<ExpressionStatement<'source>>, ParseError> {
        if self.peek()?.is_some_and(|token| token.text == "unsafe") {
            let mut probe = self.clone();
            probe.take()?;
            let open = probe.take()?;
            if !open.is_some_and(|token| token.kind == TokenKind::OpenBrace) {
                return Err(probe.error(ParseErrorKind::ExpectedBody, open));
            }
            let Some(mut statement) = probe.plain_expression_statement_record()? else {
                return Ok(None);
            };
            let close = probe.take()?;
            if !close.is_some_and(|token| token.kind == TokenKind::CloseBrace) {
                return Err(probe.error(ParseErrorKind::UnexpectedClosingDelimiter, close));
            }
            if probe
                .peek()?
                .is_some_and(|token| token.kind == TokenKind::Semicolon)
            {
                probe.take()?;
            }
            statement.unsafe_context = true;
            *self = probe;
            return Ok(Some(statement));
        }
        self.plain_expression_statement_record()
    }

    fn plain_expression_statement_record(
        &mut self,
    ) -> Result<Option<ExpressionStatement<'source>>, ParseError> {
        let Some(first) = self.peek()? else {
            return Ok(None);
        };
        if first.kind == TokenKind::Semicolon {
            self.take()?;
            return Ok(Some(ExpressionStatement {
                expression: "",
                span: Span {
                    start: first.span.start,
                    end: first.span.start,
                },
                unsafe_context: false,
                terminal: false,
            }));
        }
        if matches!(
            first.text,
            "let" | "while" | "loop" | "return" | "break" | "continue"
        ) {
            return Ok(None);
        }
        let mut probe = self.clone();
        let span = match probe.delimited_until(";", ParseErrorKind::ExpectedSemicolon) {
            Ok((span, _)) => span,
            Err(error)
                if matches!(
                    error.kind,
                    ParseErrorKind::ExpectedSemicolon | ParseErrorKind::UnexpectedClosingDelimiter
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        *self = probe;
        Ok(Some(ExpressionStatement {
            expression: &self.source[span.start..span.end],
            span,
            unsafe_context: false,
            terminal: false,
        }))
    }

    fn matching_loop_control_label(
        &mut self,
        loop_label: Option<&'source str>,
    ) -> Result<(), ParseError> {
        let Some(label) = self
            .peek()?
            .filter(|token| token.kind == TokenKind::Lifetime)
        else {
            return Ok(());
        };
        self.take()?;
        if loop_label != Some(label.text) {
            return Err(self.error(ParseErrorKind::UnknownLoopLabel, Some(label)));
        }
        Ok(())
    }

    fn nested_loop_control_target(
        &mut self,
        inner_label: Option<&'source str>,
        outer_label: Option<&'source str>,
    ) -> Result<NestedLoopControlTarget, ParseError> {
        let Some(label) = self
            .peek()?
            .filter(|token| token.kind == TokenKind::Lifetime)
        else {
            return Ok(NestedLoopControlTarget::Inner);
        };
        self.take()?;
        if inner_label == Some(label.text) {
            Ok(NestedLoopControlTarget::Inner)
        } else if outer_label == Some(label.text) {
            Ok(NestedLoopControlTarget::Outer)
        } else {
            Err(self.error(ParseErrorKind::UnknownLoopLabel, Some(label)))
        }
    }

    fn nested_loop_conditional_arm(
        &mut self,
        assignment_count: &mut usize,
        inner_label: Option<&'source str>,
        outer_label: Option<&'source str>,
    ) -> Result<NestedLoopConditionalArm<'source>, ParseError> {
        let mut actions = [None; MAX_CONDITIONAL_LOOP_ACTIONS];
        let mut action_count = 0usize;
        loop {
            let candidate = self.peek()?;
            if candidate.is_some_and(|token| matches!(token.text, "break" | "continue" | "return"))
            {
                let control = self
                    .take()?
                    .ok_or_else(|| self.error(ParseErrorKind::ExpectedBody, candidate))?;
                let terminal = if control.text == "return" {
                    let (value, value_span) = self.return_value()?;
                    NestedLoopUnconditionalControl::Return(LoopReturn { value, value_span })
                } else {
                    let target = self.nested_loop_control_target(inner_label, outer_label)?;
                    let semicolon = self.take()?;
                    if !semicolon.is_some_and(|token| token.kind == TokenKind::Semicolon) {
                        return Err(self.error(ParseErrorKind::ExpectedSemicolon, semicolon));
                    }
                    if control.text == "continue" {
                        NestedLoopUnconditionalControl::Continue(target)
                    } else {
                        NestedLoopUnconditionalControl::Break(target)
                    }
                };
                let close = self.take()?;
                if !close.is_some_and(|token| token.kind == TokenKind::CloseBrace) {
                    return Err(self.error(ParseErrorKind::UnexpectedClosingDelimiter, close));
                }
                return Ok(NestedLoopConditionalArm {
                    condition: None,
                    condition_span: Span { start: 0, end: 0 },
                    actions,
                    action_count,
                    terminal,
                });
            }
            if candidate.is_some_and(|token| token.kind == TokenKind::CloseBrace) {
                return Err(self.error(ParseErrorKind::ExpectedBody, candidate));
            }
            if action_count == MAX_CONDITIONAL_LOOP_ACTIONS {
                return Err(self.error(ParseErrorKind::TooManyConditionalLoopActions, candidate));
            }
            let action = if let Some(local) = self.local_record()? {
                ConditionalLoopAction::Local(local)
            } else {
                let assignment_name = self.peek()?;
                if let Some(assignment) = self.assignment_record()? {
                    if *assignment_count == MAX_LOOP_ASSIGNMENTS {
                        return Err(
                            self.error(ParseErrorKind::TooManyLoopAssignments, assignment_name)
                        );
                    }
                    *assignment_count += 1;
                    ConditionalLoopAction::Assignment(assignment)
                } else if let Some(expression) = self.expression_statement_record()? {
                    ConditionalLoopAction::Expression(expression)
                } else {
                    return Err(self.error(ParseErrorKind::ExpectedBody, candidate));
                }
            };
            actions[action_count] = Some(action);
            action_count += 1;
        }
    }

    fn conditional_loop_arm(
        &mut self,
        assignment_count: &mut usize,
        loop_label: Option<&'source str>,
    ) -> Result<ConditionalLoopArm<'source>, ParseError> {
        let mut actions = [None; MAX_CONDITIONAL_LOOP_ACTIONS];
        let mut action_count = 0usize;
        loop {
            let next = self.peek()?;
            if next.is_some_and(|token| token.kind == TokenKind::CloseBrace) {
                self.take()?;
                return Ok(ConditionalLoopArm {
                    condition: None,
                    condition_span: Span { start: 0, end: 0 },
                    actions,
                    action_count,
                    terminal: None,
                });
            }
            if next.is_some_and(|token| matches!(token.text, "break" | "continue" | "return")) {
                let control = self
                    .take()?
                    .ok_or_else(|| self.error(ParseErrorKind::ExpectedBody, self.lookahead))?;
                let terminal = if control.text == "return" {
                    let (value, value_span) = self.return_value()?;
                    ConditionalLoopTerminal::Return(LoopReturn { value, value_span })
                } else {
                    self.matching_loop_control_label(loop_label)?;
                    let semicolon = self.take()?;
                    if !semicolon.is_some_and(|token| token.kind == TokenKind::Semicolon) {
                        return Err(self.error(ParseErrorKind::ExpectedSemicolon, semicolon));
                    }
                    if control.text == "break" {
                        ConditionalLoopTerminal::Break
                    } else {
                        ConditionalLoopTerminal::Continue
                    }
                };
                let close = self.take()?;
                if !close.is_some_and(|token| token.kind == TokenKind::CloseBrace) {
                    return Err(self.error(ParseErrorKind::UnexpectedClosingDelimiter, close));
                }
                return Ok(ConditionalLoopArm {
                    condition: None,
                    condition_span: Span { start: 0, end: 0 },
                    actions,
                    action_count,
                    terminal: Some(terminal),
                });
            }
            if action_count == MAX_CONDITIONAL_LOOP_ACTIONS {
                return Err(self.error(ParseErrorKind::TooManyConditionalLoopActions, next));
            }
            let action = if let Some(local) = self.local_record()? {
                ConditionalLoopAction::Local(local)
            } else {
                let assignment_name = self.peek()?;
                if let Some(assignment) = self.assignment_record()? {
                    if *assignment_count == MAX_LOOP_ASSIGNMENTS {
                        return Err(
                            self.error(ParseErrorKind::TooManyLoopAssignments, assignment_name)
                        );
                    }
                    *assignment_count += 1;
                    ConditionalLoopAction::Assignment(assignment)
                } else if let Some(expression) = self.expression_statement_record()? {
                    ConditionalLoopAction::Expression(expression)
                } else {
                    return Err(self.error(ParseErrorKind::ExpectedBody, next));
                }
            };
            actions[action_count] = Some(action);
            action_count += 1;
        }
    }

    fn return_record(&mut self) -> Result<Option<LoopReturn<'source>>, ParseError> {
        if !self.peek()?.is_some_and(|token| token.text == "return") {
            return Ok(None);
        }
        let mut probe = self.clone();
        probe.take()?;
        let (value, value_span) = match probe.return_value() {
            Ok(value) => value,
            Err(error) if error.kind == ParseErrorKind::ExpectedSemicolon => return Ok(None),
            Err(error) => return Err(error),
        };
        *self = probe;
        Ok(Some(LoopReturn { value, value_span }))
    }

    fn conditional_assignment_block(
        &mut self,
    ) -> Result<Option<ConditionalAssignmentBlock<'source>>, ParseError> {
        let mut actions = [None; MAX_CONDITIONAL_BRANCH_ACTIONS];
        let mut action_count = 0usize;
        loop {
            let next = self.peek()?;
            if next.is_some_and(|token| token.kind == TokenKind::CloseBrace) {
                if action_count == 0 {
                    return Ok(None);
                }
                self.take()?;
                return Ok(Some((actions, action_count)));
            }
            if action_count == MAX_CONDITIONAL_BRANCH_ACTIONS {
                return Err(self.error(ParseErrorKind::TooManyConditionalBranchActions, next));
            }
            let action = if let Some(local) = self.local_record()? {
                ConditionalAssignmentAction::Local(local)
            } else if let Some(assignment) = self.assignment_record()? {
                ConditionalAssignmentAction::Assignment(assignment)
            } else if let Some(return_statement) = self.return_record()? {
                ConditionalAssignmentAction::Return(return_statement)
            } else if let Some(expression) = self.expression_statement_record()? {
                ConditionalAssignmentAction::Expression(expression)
            } else {
                return Ok(None);
            };
            actions[action_count] = Some(action);
            action_count += 1;
        }
    }

    fn parse_conditional_assignment<const MAX_LOCALS: usize>(
        &mut self,
        body: &mut FunctionBody<'source, MAX_LOCALS>,
    ) -> Result<bool, ParseError> {
        let Some(if_token) = self.peek()?.filter(|token| token.text == "if") else {
            return Ok(false);
        };
        let mut probe = self.clone();
        probe.take()?;
        let mut branches = [None; MAX_CONDITIONAL_ASSIGNMENT_BRANCHES];
        let mut branch_count = 0usize;
        let else_actions;
        let else_action_count;
        loop {
            if branch_count == MAX_CONDITIONAL_ASSIGNMENT_BRANCHES {
                let next = probe.peek()?;
                return Err(probe.error(ParseErrorKind::TooManyConditionalAssignmentBranches, next));
            }
            if probe
                .peek()?
                .is_some_and(|token| token.kind == TokenKind::OpenBrace)
            {
                return Ok(false);
            }
            let (condition_span, _) = probe.delimited_until("{", ParseErrorKind::ExpectedBody)?;
            let Some((actions, action_count)) = probe.conditional_assignment_block()? else {
                return Ok(false);
            };
            branches[branch_count] = Some(ConditionalAssignmentBranch {
                condition: &self.source[condition_span.start..condition_span.end],
                condition_span,
                actions,
                action_count,
            });
            branch_count += 1;
            if !probe.peek()?.is_some_and(|token| token.text == "else") {
                else_actions = [None; MAX_CONDITIONAL_BRANCH_ACTIONS];
                else_action_count = 0;
                break;
            }
            probe.take()?;
            if probe.peek()?.is_some_and(|token| token.text == "if") {
                probe.take()?;
                continue;
            }
            let else_open = probe.take()?;
            if !else_open.is_some_and(|token| token.kind == TokenKind::OpenBrace) {
                return Ok(false);
            }
            let Some((actions, action_count)) = probe.conditional_assignment_block()? else {
                return Ok(false);
            };
            else_actions = actions;
            else_action_count = action_count;
            break;
        }
        if body.conditional_assignment_count == MAX_BODY_CONDITIONAL_ASSIGNMENTS {
            return Err(self.error(
                ParseErrorKind::TooManyConditionalAssignments,
                Some(if_token),
            ));
        }
        if !body.push_statement(BodyStatement::ConditionalAssignment(
            body.conditional_assignment_count,
        )) {
            return Err(self.error(
                ParseErrorKind::TooManyConditionalAssignments,
                Some(if_token),
            ));
        }
        body.conditional_assignments[body.conditional_assignment_count] =
            Some(ConditionalAssignment {
                branches,
                branch_count,
                else_actions,
                else_action_count,
            });
        body.conditional_assignment_count += 1;
        *self = probe;
        Ok(true)
    }

    fn parse_conditional_return<const MAX_LOCALS: usize>(
        &mut self,
        body: &mut FunctionBody<'source, MAX_LOCALS>,
    ) -> Result<bool, ParseError> {
        if !self.peek()?.is_some_and(|token| token.text == "if") {
            return Ok(false);
        }
        let mut probe = self.clone();
        probe.take()?;
        if probe
            .peek()?
            .is_some_and(|token| token.kind == TokenKind::OpenBrace)
        {
            return Ok(false);
        }
        let (condition_span, _) = probe.delimited_until("{", ParseErrorKind::ExpectedBody)?;
        let Some(return_token) = probe.take()? else {
            return Ok(false);
        };
        if return_token.text != "return" {
            return Ok(false);
        }
        let (value, value_span) = probe.return_value()?;
        let close = probe.take()?;
        if !close.is_some_and(|token| token.kind == TokenKind::CloseBrace) {
            return Err(probe.error(ParseErrorKind::UnexpectedClosingDelimiter, close));
        }
        if probe.peek()?.is_some_and(|token| token.text == "else") {
            return Ok(false);
        }
        if body.conditional_return_count == MAX_LOCALS {
            return Err(probe.error(ParseErrorKind::TooManyLocals, Some(return_token)));
        }
        let conditional_return = ConditionalReturn {
            condition: &self.source[condition_span.start..condition_span.end],
            condition_span,
            value,
            value_span,
        };
        if !body.push_statement(BodyStatement::ConditionalReturn(
            body.conditional_return_count,
        )) {
            return Err(probe.error(ParseErrorKind::TooManyLocals, Some(return_token)));
        }
        body.conditional_returns[body.conditional_return_count] = Some(conditional_return);
        body.conditional_return_count += 1;
        *self = probe;
        Ok(true)
    }

    fn parse_conditional_return_else<const MAX_LOCALS: usize>(
        &mut self,
        body: &mut FunctionBody<'source, MAX_LOCALS>,
    ) -> Result<bool, ParseError> {
        if !self.peek()?.is_some_and(|token| token.text == "if") {
            return Ok(false);
        }
        let mut probe = self.clone();
        let if_token = probe.take()?.unwrap();
        let mut branches = [None; MAX_CONDITIONAL_RETURN_BRANCHES];
        let mut branch_count = 0usize;
        let else_value;
        loop {
            if branch_count == MAX_CONDITIONAL_RETURN_BRANCHES {
                let next = probe.peek()?;
                return Err(probe.error(ParseErrorKind::TooManyConditionalReturnBranches, next));
            }
            if probe
                .peek()?
                .is_some_and(|token| token.kind == TokenKind::OpenBrace)
            {
                return Ok(false);
            }
            let (condition_span, _) = probe.delimited_until("{", ParseErrorKind::ExpectedBody)?;
            let Some(_branch_return) = probe.take()?.filter(|token| token.text == "return") else {
                return Ok(false);
            };
            let (value, value_span) = probe.return_value()?;
            let close = probe.take()?;
            if !close.is_some_and(|token| token.kind == TokenKind::CloseBrace) {
                return Err(probe.error(ParseErrorKind::UnexpectedClosingDelimiter, close));
            }
            branches[branch_count] = Some(ConditionalReturn {
                condition: &self.source[condition_span.start..condition_span.end],
                condition_span,
                value,
                value_span,
            });
            branch_count += 1;
            if !probe.peek()?.is_some_and(|token| token.text == "else") {
                if branch_count == 1 {
                    return Ok(false);
                }
                else_value = None;
                break;
            }
            probe.take()?;
            if probe.peek()?.is_some_and(|token| token.text == "if") {
                probe.take()?;
                continue;
            }
            let else_open = probe.take()?;
            if !else_open.is_some_and(|token| token.kind == TokenKind::OpenBrace) {
                return Err(probe.error(ParseErrorKind::ExpectedBody, else_open));
            }
            let Some(_else_return) = probe.take()?.filter(|token| token.text == "return") else {
                return Ok(false);
            };
            let (value, value_span) = probe.return_value()?;
            let else_close = probe.take()?;
            if !else_close.is_some_and(|token| token.kind == TokenKind::CloseBrace) {
                return Err(probe.error(ParseErrorKind::UnexpectedClosingDelimiter, else_close));
            }
            else_value = Some(LoopReturn { value, value_span });
            break;
        }
        if body.conditional_return_else_count == MAX_LOCALS {
            return Err(probe.error(ParseErrorKind::TooManyLocals, Some(if_token)));
        }
        if !body.push_statement(BodyStatement::ConditionalReturnElse(
            body.conditional_return_else_count,
        )) {
            return Err(probe.error(ParseErrorKind::TooManyLocals, Some(if_token)));
        }
        body.conditional_return_elses[body.conditional_return_else_count] =
            Some(ConditionalReturnElse {
                branches,
                branch_count,
                else_value,
            });
        body.conditional_return_else_count += 1;
        *self = probe;
        Ok(true)
    }

    fn parse_expression_statement<const MAX_LOCALS: usize>(
        &mut self,
        body: &mut FunctionBody<'source, MAX_LOCALS>,
    ) -> Result<bool, ParseError> {
        let Some(first) = self.peek()? else {
            return Ok(false);
        };
        if first.kind == TokenKind::Semicolon {
            if body.expression_statement_count == MAX_BODY_EXPRESSION_STATEMENTS {
                return Err(self.error(ParseErrorKind::TooManyExpressionStatements, Some(first)));
            }
            self.take()?;
            if !body.push_statement(BodyStatement::Expression(body.expression_statement_count)) {
                return Err(self.error(ParseErrorKind::TooManyExpressionStatements, Some(first)));
            }
            body.expression_statements[body.expression_statement_count] =
                Some(ExpressionStatement {
                    expression: "",
                    span: Span {
                        start: first.span.start,
                        end: first.span.start,
                    },
                    unsafe_context: false,
                    terminal: false,
                });
            body.expression_statement_count += 1;
            return Ok(true);
        }
        if matches!(
            first.text,
            "let" | "while" | "loop" | "return" | "break" | "continue"
        ) {
            return Ok(false);
        }
        if first.text == "unsafe" {
            let mut probe = self.clone();
            if let Some(statement) = probe.expression_statement_record()? {
                if body.expression_statement_count == MAX_BODY_EXPRESSION_STATEMENTS {
                    return Err(
                        self.error(ParseErrorKind::TooManyExpressionStatements, Some(first))
                    );
                }
                if !body.push_statement(BodyStatement::Expression(body.expression_statement_count))
                {
                    return Err(
                        self.error(ParseErrorKind::TooManyExpressionStatements, Some(first))
                    );
                }
                body.expression_statements[body.expression_statement_count] = Some(statement);
                body.expression_statement_count += 1;
                *self = probe;
                return Ok(true);
            }
        }
        if first.kind == TokenKind::Identifier {
            let mut assignment_probe = self.clone();
            let name = assignment_probe.take()?.unwrap();
            assignment_probe.assignment_projection(name.span.end)?;
            if assignment_probe
                .peek()?
                .is_some_and(|token| AssignmentOperator::from_text(token.text).is_some())
            {
                return Ok(false);
            }
        }
        let mut probe = self.clone();
        let span = match probe.delimited_until(";", ParseErrorKind::ExpectedSemicolon) {
            Ok((span, _)) => span,
            Err(error) if error.kind == ParseErrorKind::ExpectedSemicolon => return Ok(false),
            Err(error) => return Err(error),
        };
        if body.expression_statement_count == MAX_BODY_EXPRESSION_STATEMENTS {
            return Err(self.error(ParseErrorKind::TooManyExpressionStatements, Some(first)));
        }
        if !body.push_statement(BodyStatement::Expression(body.expression_statement_count)) {
            return Err(self.error(ParseErrorKind::TooManyExpressionStatements, Some(first)));
        }
        body.expression_statements[body.expression_statement_count] = Some(ExpressionStatement {
            expression: &self.source[span.start..span.end],
            span,
            unsafe_context: false,
            terminal: false,
        });
        body.expression_statement_count += 1;
        *self = probe;
        Ok(true)
    }

    fn parse_return<const MAX_LOCALS: usize>(
        &mut self,
        body: &mut FunctionBody<'source, MAX_LOCALS>,
    ) -> Result<bool, ParseError> {
        let Some(return_token) = self.peek()?.filter(|token| token.text == "return") else {
            return Ok(false);
        };
        let mut probe = self.clone();
        probe.take()?;
        let (value, value_span) = match probe.return_value() {
            Ok(value) => value,
            Err(error) if error.kind == ParseErrorKind::ExpectedSemicolon => return Ok(false),
            Err(error) => return Err(error),
        };
        if body.return_count == MAX_BODY_RETURNS {
            return Err(self.error(ParseErrorKind::TooManyReturns, Some(return_token)));
        }
        if !body.push_statement(BodyStatement::Return(body.return_count)) {
            return Err(self.error(ParseErrorKind::TooManyReturns, Some(return_token)));
        }
        body.returns[body.return_count] = Some(LoopReturn { value, value_span });
        body.return_count += 1;
        *self = probe;
        Ok(true)
    }

    fn parse<const MAX_LOCALS: usize, const MAX_EXPRESSION_NODES: usize>(
        mut self,
    ) -> Result<FunctionBody<'source, MAX_LOCALS>, ParseError> {
        let mut body = FunctionBody {
            statements: [None; MAX_BODY_STATEMENTS],
            statement_count: 0,
            locals: [None; MAX_LOCALS],
            local_count: 0,
            assignments: [None; MAX_LOCALS],
            assignment_count: 0,
            conditional_returns: [None; MAX_LOCALS],
            conditional_return_count: 0,
            conditional_return_elses: [None; MAX_LOCALS],
            conditional_return_else_count: 0,
            conditional_assignments: [None; MAX_BODY_CONDITIONAL_ASSIGNMENTS],
            conditional_assignment_count: 0,
            while_loops: [None; MAX_LOCALS],
            while_loop_count: 0,
            expression_statements: [None; MAX_BODY_EXPRESSION_STATEMENTS],
            expression_statement_count: 0,
            returns: [None; MAX_BODY_RETURNS],
            return_count: 0,
            tail_expression: "",
            tail_span: Span { start: 0, end: 0 },
            implicit_unit: false,
            tail_diverges: false,
        };
        loop {
            let before = body.statement_count;
            while self.parse_local(&mut body)? {}
            while self.parse_assignment(&mut body)? {}
            while self.parse_conditional_return_else(&mut body)? {}
            while self.parse_conditional_return(&mut body)? {}
            while self.parse_conditional_assignment(&mut body)? {}
            while self.parse_return(&mut body)? {}
            while self.parse_expression_statement(&mut body)? {}
            if body.statement_count == before {
                break;
            }
        }
        let mut tail = self.peek()?;
        if let Some(tail_token) =
            tail.filter(|token| token.text == "loop" || token.kind == TokenKind::Lifetime)
        {
            let tail_end = self.source.trim_end().len();
            let candidate = &self.source[tail_token.span.start..tail_end];
            if ExpressionParser::<MAX_EXPRESSION_NODES>::new(candidate)
                .parse()
                .is_ok()
            {
                body.tail_span = Span {
                    start: tail_token.span.start,
                    end: tail_end,
                };
                body.tail_expression = candidate;
                return Ok(body);
            }
        }
        while self.peek()?.is_some_and(|token| {
            matches!(token.text, "while" | "loop") || token.kind == TokenKind::Lifetime
        }) {
            let mut probe = self.clone();
            let label = if probe
                .peek()?
                .is_some_and(|token| token.kind == TokenKind::Lifetime)
            {
                let label = probe.take()?.ok_or_else(|| {
                    probe.error(ParseErrorKind::ExpectedIdentifier, probe.lookahead)
                })?;
                let colon = probe.take()?;
                if !colon.is_some_and(|token| token.kind == TokenKind::Colon) {
                    return Err(probe.error(ParseErrorKind::ExpectedColon, colon));
                }
                Some(label.text)
            } else {
                None
            };
            let loop_token = probe
                .take()?
                .ok_or_else(|| probe.error(ParseErrorKind::ExpectedBody, probe.lookahead))?;
            if !matches!(loop_token.text, "while" | "loop") {
                return Err(probe.error(ParseErrorKind::ExpectedBody, Some(loop_token)));
            }
            let condition_span = if loop_token.text == "while" {
                probe.delimited_until("{", ParseErrorKind::ExpectedBody)?.0
            } else {
                let open = probe.take()?;
                if !open.is_some_and(|token| token.kind == TokenKind::OpenBrace) {
                    return Err(probe.error(ParseErrorKind::ExpectedBody, open));
                }
                Span {
                    start: loop_token.span.end,
                    end: loop_token.span.end,
                }
            };
            let mut operations = [None; MAX_LOOP_OPERATIONS];
            let mut operation_count = 0usize;
            let mut assignment_count = 0usize;
            let mut conditional_blocks = [None; MAX_LOOP_OPERATIONS];
            let mut conditional_block_count = 0usize;
            let mut conditional_else_arms = [None; MAX_CONDITIONAL_LOOP_ELSE_ARMS];
            let mut conditional_else_arm_count = 0usize;
            let mut nested_blocks = [None; MAX_NESTED_LOOP_BLOCKS];
            let mut nested_block_count = 0usize;
            loop {
                let next = probe.peek()?;
                if next.is_some_and(|token| token.kind == TokenKind::CloseBrace) {
                    probe.take()?;
                    break;
                }
                if operation_count == MAX_LOOP_OPERATIONS {
                    return Err(probe.error(ParseErrorKind::TooManyLoopOperations, next));
                }
                if next.is_some_and(|token| {
                    matches!(token.text, "loop" | "while") || token.kind == TokenKind::Lifetime
                }) {
                    let inner_label = if probe
                        .peek()?
                        .is_some_and(|token| token.kind == TokenKind::Lifetime)
                    {
                        let label = probe.take()?.ok_or_else(|| {
                            probe.error(ParseErrorKind::ExpectedIdentifier, probe.lookahead)
                        })?;
                        let colon = probe.take()?;
                        if !colon.is_some_and(|token| token.kind == TokenKind::Colon) {
                            return Err(probe.error(ParseErrorKind::ExpectedColon, colon));
                        }
                        Some(label.text)
                    } else {
                        None
                    };
                    let inner_loop = probe.take()?.ok_or_else(|| {
                        probe.error(ParseErrorKind::ExpectedBody, probe.lookahead)
                    })?;
                    if !matches!(inner_loop.text, "loop" | "while") {
                        return Err(probe.error(ParseErrorKind::ExpectedBody, Some(inner_loop)));
                    }
                    let entry_condition = if inner_loop.text == "while" {
                        let (span, _) = probe.delimited_until("{", ParseErrorKind::ExpectedBody)?;
                        Some(ConditionalLoopControl {
                            condition: &self.source[span.start..span.end],
                            condition_span: span,
                        })
                    } else {
                        let open = probe.take()?;
                        if !open.is_some_and(|token| token.kind == TokenKind::OpenBrace) {
                            return Err(probe.error(ParseErrorKind::ExpectedBody, open));
                        }
                        None
                    };
                    let mut actions = [None; MAX_NESTED_LOOP_ACTIONS];
                    let mut action_count = 0usize;
                    let mut nested_conditional_blocks = [None; MAX_NESTED_LOOP_CONDITIONAL_BLOCKS];
                    let mut nested_conditional_block_action_indices =
                        [0usize; MAX_NESTED_LOOP_CONDITIONAL_BLOCKS];
                    let mut nested_conditional_block_control_orders =
                        [0usize; MAX_NESTED_LOOP_CONDITIONAL_BLOCKS];
                    let mut nested_conditional_block_count = 0usize;
                    let mut conditional_breaks = [None; MAX_NESTED_LOOP_CONDITIONAL_BREAKS];
                    let mut conditional_break_action_indices =
                        [0usize; MAX_NESTED_LOOP_CONDITIONAL_BREAKS];
                    let mut conditional_break_control_orders =
                        [0usize; MAX_NESTED_LOOP_CONDITIONAL_BREAKS];
                    let mut conditional_break_targets =
                        [NestedLoopControlTarget::Inner; MAX_NESTED_LOOP_CONDITIONAL_BREAKS];
                    let mut conditional_break_count = 0usize;
                    let mut conditional_continues = [None; MAX_NESTED_LOOP_CONDITIONAL_CONTINUES];
                    let mut conditional_continue_action_indices =
                        [0usize; MAX_NESTED_LOOP_CONDITIONAL_CONTINUES];
                    let mut conditional_continue_control_orders =
                        [0usize; MAX_NESTED_LOOP_CONDITIONAL_CONTINUES];
                    let mut conditional_continue_targets =
                        [NestedLoopControlTarget::Inner; MAX_NESTED_LOOP_CONDITIONAL_CONTINUES];
                    let mut conditional_continue_count = 0usize;
                    let mut control_order = 0usize;
                    let mut conditional_returns = [None; MAX_NESTED_LOOP_CONDITIONAL_RETURNS];
                    let mut conditional_return_action_indices =
                        [0usize; MAX_NESTED_LOOP_CONDITIONAL_RETURNS];
                    let mut conditional_return_control_orders =
                        [0usize; MAX_NESTED_LOOP_CONDITIONAL_RETURNS];
                    let mut conditional_return_count = 0usize;
                    let mut unconditional_controls = [None; MAX_NESTED_LOOP_UNCONDITIONAL_CONTROLS];
                    let mut unconditional_control_action_indices =
                        [0usize; MAX_NESTED_LOOP_UNCONDITIONAL_CONTROLS];
                    let mut unconditional_control_orders =
                        [0usize; MAX_NESTED_LOOP_UNCONDITIONAL_CONTROLS];
                    let mut unconditional_control_count = 0usize;
                    loop {
                        let next = probe.peek()?;
                        if next.is_some_and(|token| token.kind == TokenKind::CloseBrace) {
                            probe.take()?;
                            break;
                        }
                        if next.is_some_and(|token| token.text == "break") {
                            probe.take()?;
                            let target = probe.nested_loop_control_target(inner_label, label)?;
                            let semicolon = probe.take()?;
                            if !semicolon.is_some_and(|token| token.kind == TokenKind::Semicolon) {
                                return Err(
                                    probe.error(ParseErrorKind::ExpectedSemicolon, semicolon)
                                );
                            }
                            if unconditional_control_count == MAX_NESTED_LOOP_UNCONDITIONAL_CONTROLS
                            {
                                return Err(probe.error(
                                    ParseErrorKind::TooManyNestedLoopUnconditionalControls,
                                    next,
                                ));
                            }
                            unconditional_controls[unconditional_control_count] =
                                Some(NestedLoopUnconditionalControl::Break(target));
                            unconditional_control_action_indices[unconditional_control_count] =
                                action_count;
                            unconditional_control_orders[unconditional_control_count] =
                                control_order;
                            unconditional_control_count += 1;
                            control_order += 1;
                            continue;
                        }
                        if next.is_some_and(|token| token.text == "continue") {
                            probe.take()?;
                            let target = probe.nested_loop_control_target(inner_label, label)?;
                            let semicolon = probe.take()?;
                            if !semicolon.is_some_and(|token| token.kind == TokenKind::Semicolon) {
                                return Err(
                                    probe.error(ParseErrorKind::ExpectedSemicolon, semicolon)
                                );
                            }
                            if unconditional_control_count == MAX_NESTED_LOOP_UNCONDITIONAL_CONTROLS
                            {
                                return Err(probe.error(
                                    ParseErrorKind::TooManyNestedLoopUnconditionalControls,
                                    next,
                                ));
                            }
                            unconditional_controls[unconditional_control_count] =
                                Some(NestedLoopUnconditionalControl::Continue(target));
                            unconditional_control_action_indices[unconditional_control_count] =
                                action_count;
                            unconditional_control_orders[unconditional_control_count] =
                                control_order;
                            unconditional_control_count += 1;
                            control_order += 1;
                            continue;
                        }
                        if next.is_some_and(|token| token.text == "return") {
                            probe.take()?;
                            let (value, value_span) = probe.return_value()?;
                            if unconditional_control_count == MAX_NESTED_LOOP_UNCONDITIONAL_CONTROLS
                            {
                                return Err(probe.error(
                                    ParseErrorKind::TooManyNestedLoopUnconditionalControls,
                                    next,
                                ));
                            }
                            unconditional_controls[unconditional_control_count] =
                                Some(NestedLoopUnconditionalControl::Return(LoopReturn {
                                    value,
                                    value_span,
                                }));
                            unconditional_control_action_indices[unconditional_control_count] =
                                action_count;
                            unconditional_control_orders[unconditional_control_count] =
                                control_order;
                            unconditional_control_count += 1;
                            control_order += 1;
                            continue;
                        }
                        if next.is_some_and(|token| token.text == "if") {
                            probe.take()?;
                            let (condition_span, _) =
                                probe.delimited_until("{", ParseErrorKind::ExpectedBody)?;
                            let primary = probe.nested_loop_conditional_arm(
                                &mut assignment_count,
                                inner_label,
                                label,
                            )?;
                            let mut else_arms = [None; MAX_NESTED_LOOP_CONDITIONAL_ELSE_ARMS];
                            let mut else_arm_count = 0usize;
                            while probe.peek()?.is_some_and(|token| token.text == "else") {
                                probe.take()?;
                                if else_arm_count == MAX_NESTED_LOOP_CONDITIONAL_ELSE_ARMS {
                                    return Err(probe.error(
                                        ParseErrorKind::TooManyConditionalLoopElseArms,
                                        probe.lookahead,
                                    ));
                                }
                                let else_condition_span = if probe
                                    .peek()?
                                    .is_some_and(|token| token.text == "if")
                                {
                                    probe.take()?;
                                    Some(
                                        probe.delimited_until("{", ParseErrorKind::ExpectedBody)?.0,
                                    )
                                } else {
                                    let open = probe.take()?;
                                    if !open.is_some_and(|token| token.kind == TokenKind::OpenBrace)
                                    {
                                        return Err(probe.error(ParseErrorKind::ExpectedBody, open));
                                    }
                                    None
                                };
                                let mut arm = probe.nested_loop_conditional_arm(
                                    &mut assignment_count,
                                    inner_label,
                                    label,
                                )?;
                                if let Some(span) = else_condition_span {
                                    arm.condition = Some(&self.source[span.start..span.end]);
                                    arm.condition_span = span;
                                }
                                else_arms[else_arm_count] = Some(arm);
                                else_arm_count += 1;
                                if arm.condition.is_none() {
                                    break;
                                }
                            }
                            let condition = ConditionalLoopControl {
                                condition: &self.source[condition_span.start..condition_span.end],
                                condition_span,
                            };
                            let this_control_order = control_order;
                            control_order += 1;
                            if primary.action_count != 0 || else_arm_count != 0 {
                                if nested_conditional_block_count
                                    == MAX_NESTED_LOOP_CONDITIONAL_BLOCKS
                                {
                                    let error_token = probe.peek()?;
                                    return Err(probe.error(
                                        ParseErrorKind::TooManyNestedLoopConditionalBlocks,
                                        error_token,
                                    ));
                                }
                                nested_conditional_blocks[nested_conditional_block_count] =
                                    Some(NestedLoopConditionalBlock {
                                        condition: &self.source
                                            [condition_span.start..condition_span.end],
                                        condition_span,
                                        actions: primary.actions,
                                        action_count: primary.action_count,
                                        terminal: primary.terminal,
                                        else_arms,
                                        else_arm_count,
                                    });
                                nested_conditional_block_action_indices
                                    [nested_conditional_block_count] = action_count;
                                nested_conditional_block_control_orders
                                    [nested_conditional_block_count] = this_control_order;
                                nested_conditional_block_count += 1;
                                continue;
                            }
                            if let NestedLoopUnconditionalControl::Continue(control_target) =
                                primary.terminal
                            {
                                if conditional_continue_count
                                    == MAX_NESTED_LOOP_CONDITIONAL_CONTINUES
                                {
                                    let error_token = probe.peek()?;
                                    return Err(probe.error(
                                        ParseErrorKind::TooManyNestedLoopConditionalContinues,
                                        error_token,
                                    ));
                                }
                                conditional_continues[conditional_continue_count] = Some(condition);
                                conditional_continue_action_indices[conditional_continue_count] =
                                    action_count;
                                conditional_continue_control_orders[conditional_continue_count] =
                                    this_control_order;
                                conditional_continue_targets[conditional_continue_count] =
                                    control_target;
                                conditional_continue_count += 1;
                                continue;
                            }
                            if let NestedLoopUnconditionalControl::Return(return_value) =
                                primary.terminal
                            {
                                if conditional_return_count == MAX_NESTED_LOOP_CONDITIONAL_RETURNS {
                                    let error_token = probe.peek()?;
                                    return Err(probe.error(
                                        ParseErrorKind::TooManyNestedLoopConditionalReturns,
                                        error_token,
                                    ));
                                }
                                conditional_returns[conditional_return_count] =
                                    Some(ConditionalReturn {
                                        condition: condition.condition,
                                        condition_span,
                                        value: return_value.value,
                                        value_span: return_value.value_span,
                                    });
                                conditional_return_action_indices[conditional_return_count] =
                                    action_count;
                                conditional_return_control_orders[conditional_return_count] =
                                    this_control_order;
                                conditional_return_count += 1;
                                continue;
                            }
                            if conditional_break_count == MAX_NESTED_LOOP_CONDITIONAL_BREAKS {
                                let error_token = probe.peek()?;
                                return Err(probe.error(
                                    ParseErrorKind::TooManyNestedLoopConditionalBreaks,
                                    error_token,
                                ));
                            }
                            let NestedLoopUnconditionalControl::Break(control_target) =
                                primary.terminal
                            else {
                                let error_token = probe.peek()?;
                                return Err(probe.error(ParseErrorKind::ExpectedBody, error_token));
                            };
                            conditional_breaks[conditional_break_count] = Some(condition);
                            conditional_break_action_indices[conditional_break_count] =
                                action_count;
                            conditional_break_control_orders[conditional_break_count] =
                                this_control_order;
                            conditional_break_targets[conditional_break_count] = control_target;
                            conditional_break_count += 1;
                            continue;
                        }
                        if action_count == MAX_NESTED_LOOP_ACTIONS {
                            return Err(probe.error(ParseErrorKind::TooManyNestedLoopActions, next));
                        }
                        let action = if let Some(local) = probe.local_record()? {
                            ConditionalLoopAction::Local(local)
                        } else {
                            let assignment_name = probe.peek()?;
                            if let Some(assignment) = probe.assignment_record()? {
                                if assignment_count == MAX_LOOP_ASSIGNMENTS {
                                    return Err(probe.error(
                                        ParseErrorKind::TooManyLoopAssignments,
                                        assignment_name,
                                    ));
                                }
                                assignment_count += 1;
                                ConditionalLoopAction::Assignment(assignment)
                            } else if let Some(expression) = probe.expression_statement_record()? {
                                ConditionalLoopAction::Expression(expression)
                            } else {
                                return Err(probe.error(ParseErrorKind::ExpectedBody, next));
                            }
                        };
                        actions[action_count] = Some(action);
                        action_count += 1;
                    }
                    operations[operation_count] = Some(
                        if entry_condition.is_none()
                            && action_count == 0
                            && unconditional_control_count == 1
                            && matches!(
                                unconditional_controls[0],
                                Some(NestedLoopUnconditionalControl::Break(
                                    NestedLoopControlTarget::Inner
                                ))
                            )
                            && conditional_break_count == 0
                            && conditional_continue_count == 0
                            && conditional_return_count == 0
                        {
                            LoopOperation::NestedUnitLoop
                        } else {
                            if nested_block_count == MAX_NESTED_LOOP_BLOCKS {
                                return Err(probe.error(
                                    ParseErrorKind::TooManyNestedLoopBlocks,
                                    probe.lookahead,
                                ));
                            }
                            nested_blocks[nested_block_count] = Some(NestedLoopBlock {
                                label: inner_label,
                                entry_condition,
                                actions,
                                action_count,
                                conditional_blocks: nested_conditional_blocks,
                                conditional_block_action_indices:
                                    nested_conditional_block_action_indices,
                                conditional_block_control_orders:
                                    nested_conditional_block_control_orders,
                                conditional_block_count: nested_conditional_block_count,
                                unconditional_controls,
                                unconditional_control_action_indices,
                                unconditional_control_orders,
                                unconditional_control_count,
                                conditional_breaks,
                                conditional_break_action_indices,
                                conditional_break_control_orders,
                                conditional_break_targets,
                                conditional_break_count,
                                conditional_continues,
                                conditional_continue_action_indices,
                                conditional_continue_control_orders,
                                conditional_continue_targets,
                                conditional_continue_count,
                                conditional_returns,
                                conditional_return_action_indices,
                                conditional_return_control_orders,
                                conditional_return_count,
                            });
                            let index = nested_block_count;
                            nested_block_count += 1;
                            LoopOperation::NestedBlock(index)
                        },
                    );
                    operation_count += 1;
                    continue;
                }
                if next.is_some_and(|token| token.text == "if") {
                    probe.take()?;
                    let (condition_span, _) =
                        probe.delimited_until("{", ParseErrorKind::ExpectedBody)?;
                    let mut actions = [None; MAX_CONDITIONAL_LOOP_ACTIONS];
                    let mut action_count = 0usize;
                    let (control, terminal) = loop {
                        let next = probe.peek()?;
                        if next.is_some_and(|token| token.kind == TokenKind::CloseBrace) {
                            probe.take()?;
                            break (None, None);
                        }
                        if next.is_some_and(|token| {
                            matches!(token.text, "break" | "continue" | "return")
                        }) {
                            let control = probe.take()?.ok_or_else(|| {
                                probe.error(ParseErrorKind::ExpectedBody, probe.lookahead)
                            })?;
                            let terminal = if control.text == "return" {
                                let (value, value_span) = probe.return_value()?;
                                ConditionalLoopTerminal::Return(LoopReturn { value, value_span })
                            } else {
                                probe.matching_loop_control_label(label)?;
                                let semicolon = probe.take()?;
                                if !semicolon
                                    .is_some_and(|token| token.kind == TokenKind::Semicolon)
                                {
                                    return Err(
                                        probe.error(ParseErrorKind::ExpectedSemicolon, semicolon)
                                    );
                                }
                                if control.text == "break" {
                                    ConditionalLoopTerminal::Break
                                } else {
                                    ConditionalLoopTerminal::Continue
                                }
                            };
                            break (Some(control), Some(terminal));
                        }
                        if action_count == MAX_CONDITIONAL_LOOP_ACTIONS {
                            return Err(
                                probe.error(ParseErrorKind::TooManyConditionalLoopActions, next)
                            );
                        }
                        let action = if let Some(local) = probe.local_record()? {
                            ConditionalLoopAction::Local(local)
                        } else {
                            let assignment_name = probe.peek()?;
                            if let Some(assignment) = probe.assignment_record()? {
                                if assignment_count == MAX_LOOP_ASSIGNMENTS {
                                    return Err(probe.error(
                                        ParseErrorKind::TooManyLoopAssignments,
                                        assignment_name,
                                    ));
                                }
                                assignment_count += 1;
                                ConditionalLoopAction::Assignment(assignment)
                            } else if let Some(expression) = probe.expression_statement_record()? {
                                ConditionalLoopAction::Expression(expression)
                            } else {
                                return Err(probe.error(ParseErrorKind::ExpectedBody, next));
                            }
                        };
                        actions[action_count] = Some(action);
                        action_count += 1;
                    };
                    if control.is_some() {
                        let close = probe.take()?;
                        if !close.is_some_and(|token| token.kind == TokenKind::CloseBrace) {
                            return Err(
                                probe.error(ParseErrorKind::UnexpectedClosingDelimiter, close)
                            );
                        }
                    }
                    let else_arm_start = conditional_else_arm_count;
                    while probe.peek()?.is_some_and(|token| token.text == "else") {
                        probe.take()?;
                        if conditional_else_arm_count == MAX_CONDITIONAL_LOOP_ELSE_ARMS {
                            return Err(probe.error(
                                ParseErrorKind::TooManyConditionalLoopElseArms,
                                probe.lookahead,
                            ));
                        }
                        let (arm_condition, arm_condition_span) =
                            if probe.peek()?.is_some_and(|token| token.text == "if") {
                                probe.take()?;
                                let (span, _) =
                                    probe.delimited_until("{", ParseErrorKind::ExpectedBody)?;
                                (Some(&self.source[span.start..span.end]), span)
                            } else {
                                let open = probe.take()?;
                                if !open.is_some_and(|token| token.kind == TokenKind::OpenBrace) {
                                    return Err(probe.error(ParseErrorKind::ExpectedBody, open));
                                }
                                (None, Span { start: 0, end: 0 })
                            };
                        let mut arm = probe.conditional_loop_arm(&mut assignment_count, label)?;
                        arm.condition = arm_condition;
                        arm.condition_span = arm_condition_span;
                        conditional_else_arms[conditional_else_arm_count] = Some(arm);
                        conditional_else_arm_count += 1;
                        if arm.condition.is_none() {
                            break;
                        }
                    }
                    let else_arm_count = conditional_else_arm_count - else_arm_start;
                    let else_arm = (else_arm_count != 0).then_some(else_arm_start);
                    let conditional = ConditionalLoopControl {
                        condition: &self.source[condition_span.start..condition_span.end],
                        condition_span,
                    };
                    operations[operation_count] =
                        Some(if action_count != 0 || else_arm.is_some() {
                            conditional_blocks[conditional_block_count] =
                                Some(ConditionalLoopBlock {
                                    condition: conditional.condition,
                                    condition_span: conditional.condition_span,
                                    actions,
                                    action_count,
                                    terminal,
                                    else_arm,
                                    else_arm_count,
                                });
                            let index = conditional_block_count;
                            conditional_block_count += 1;
                            LoopOperation::ConditionalBlock(index)
                        } else if control.is_some_and(|control| control.text == "break") {
                            LoopOperation::ConditionalBreak(conditional)
                        } else if control.is_some_and(|control| control.text == "continue") {
                            LoopOperation::ConditionalContinue(conditional)
                        } else {
                            let Some(ConditionalLoopTerminal::Return(LoopReturn {
                                value,
                                value_span,
                            })) = terminal
                            else {
                                return Err(
                                    probe.error(ParseErrorKind::ExpectedInitializer, control)
                                );
                            };
                            LoopOperation::ConditionalReturn(ConditionalReturn {
                                condition: conditional.condition,
                                condition_span: conditional.condition_span,
                                value,
                                value_span,
                            })
                        });
                    operation_count += 1;
                    continue;
                }
                if next.is_some_and(|token| matches!(token.text, "break" | "continue" | "return")) {
                    let control = probe.take()?.ok_or_else(|| {
                        probe.error(ParseErrorKind::ExpectedBody, probe.lookahead)
                    })?;
                    if control.text == "return" {
                        let (value, value_span) = probe.return_value()?;
                        operations[operation_count] =
                            Some(LoopOperation::Return(LoopReturn { value, value_span }));
                    } else {
                        probe.matching_loop_control_label(label)?;
                        let semicolon = probe.take()?;
                        if !semicolon.is_some_and(|token| token.kind == TokenKind::Semicolon) {
                            return Err(probe.error(ParseErrorKind::ExpectedSemicolon, semicolon));
                        }
                        operations[operation_count] = Some(if control.text == "break" {
                            LoopOperation::Break
                        } else {
                            LoopOperation::Continue
                        });
                    }
                    operation_count += 1;
                    continue;
                }
                if let Some(local) = probe.local_record()? {
                    operations[operation_count] = Some(LoopOperation::Local(local));
                    operation_count += 1;
                    continue;
                }
                let assignment_name = probe.peek()?;
                if let Some(assignment) = probe.assignment_record()? {
                    if assignment_count == MAX_LOOP_ASSIGNMENTS {
                        return Err(
                            probe.error(ParseErrorKind::TooManyLoopAssignments, assignment_name)
                        );
                    }
                    operations[operation_count] = Some(LoopOperation::Assignment(assignment));
                    operation_count += 1;
                    assignment_count += 1;
                    continue;
                }
                if let Some(expression) = probe.expression_statement_record()? {
                    operations[operation_count] = Some(LoopOperation::Expression(expression));
                    operation_count += 1;
                    continue;
                }
                let name = probe.peek()?;
                return Err(probe.error(ParseErrorKind::ExpectedIdentifier, name));
            }
            if body.while_loop_count == MAX_LOCALS {
                return Err(probe.error(ParseErrorKind::TooManyLocals, Some(loop_token)));
            }
            let loop_statement = WhileLoop {
                label,
                condition: (loop_token.text == "while")
                    .then_some(&self.source[condition_span.start..condition_span.end]),
                condition_span,
                operations,
                operation_count,
                assignment_count,
                conditional_blocks,
                conditional_block_count,
                conditional_else_arms,
                conditional_else_arm_count,
                nested_blocks,
                nested_block_count,
            };
            if !body.push_statement(BodyStatement::Loop(body.while_loop_count)) {
                return Err(probe.error(ParseErrorKind::TooManyLocals, Some(loop_token)));
            }
            body.while_loops[body.while_loop_count] = Some(loop_statement);
            body.while_loop_count += 1;
            self = probe;
        }
        if body.while_loop_count != 0 {
            loop {
                let before = body.statement_count;
                while self.parse_local(&mut body)? {}
                while self.parse_assignment(&mut body)? {}
                while self.parse_conditional_return_else(&mut body)? {}
                while self.parse_conditional_return(&mut body)? {}
                while self.parse_conditional_assignment(&mut body)? {}
                while self.parse_return(&mut body)? {}
                while self.parse_expression_statement(&mut body)? {}
                if body.statement_count == before {
                    break;
                }
            }
            tail = self.peek()?;
        }
        let tail_end = self.source.trim_end().len();
        if let Some(tail) = tail {
            body.tail_span = Span {
                start: tail.span.start,
                end: tail_end,
            };
            body.tail_expression = &self.source[body.tail_span.start..body.tail_span.end];
        } else {
            body.tail_span = Span {
                start: tail_end,
                end: tail_end,
            };
            if let Some(BodyStatement::Expression(index)) = body.statements[..body.statement_count]
                .iter()
                .flatten()
                .next_back()
                .copied()
                && let Some(statement) = body.expression_statements[index].as_mut()
            {
                statement.terminal = true;
            }
            let last_loop_diverges = body.while_loops[..body.while_loop_count]
                .iter()
                .flatten()
                .next_back()
                .is_some_and(|loop_statement| {
                    loop_statement.condition.is_none()
                        && !loop_statement
                            .operations()
                            .iter()
                            .flatten()
                            .any(|operation| {
                                matches!(
                                    operation,
                                    LoopOperation::Break | LoopOperation::ConditionalBreak(_)
                                ) || matches!(
                                    operation,
                                    LoopOperation::ConditionalBlock(index)
                                        if loop_statement.conditional_blocks()[*index]
                                            .is_some_and(|block| {
                                                block.terminal
                                                    == Some(ConditionalLoopTerminal::Break)
                                            })
                                )
                            })
                });
            let exhaustive_chain_diverges = body.conditional_return_elses
                [..body.conditional_return_else_count]
                .iter()
                .flatten()
                .any(|conditional| conditional.else_value.is_some());
            if body.return_count != 0 || exhaustive_chain_diverges || last_loop_diverges {
                body.tail_expression = "";
                body.tail_diverges = true;
            } else {
                body.tail_expression = "()";
                body.implicit_unit = true;
            }
        }
        Ok(body)
    }
}

impl<'source> Parser<'source> {
    pub const fn new(source: &'source str) -> Self {
        Self {
            source,
            lexer: Lexer::new(source),
            lookahead: None,
        }
    }

    fn lexical(error: LexError) -> ParseError {
        ParseError {
            kind: ParseErrorKind::Lexical(error),
            span: error.span,
        }
    }

    fn peek(&mut self) -> Result<Option<Token<'source>>, ParseError> {
        if self.lookahead.is_none() {
            self.lookahead = self.lexer.next_token().map_err(Self::lexical)?;
        }
        Ok(self.lookahead)
    }

    fn take(&mut self) -> Result<Option<Token<'source>>, ParseError> {
        if let Some(token) = self.lookahead.take() {
            Ok(Some(token))
        } else {
            self.lexer.next_token().map_err(Self::lexical)
        }
    }

    fn eof_span(&self) -> Span {
        Span {
            start: self.source.len(),
            end: self.source.len(),
        }
    }

    fn error(&self, kind: ParseErrorKind, token: Option<Token<'source>>) -> ParseError {
        ParseError {
            kind,
            span: token.map_or_else(|| self.eof_span(), |value| value.span),
        }
    }

    fn take_text(&mut self, text: &str) -> Result<Option<Token<'source>>, ParseError> {
        if self.peek()?.is_some_and(|token| token.text == text) {
            self.take()
        } else {
            Ok(None)
        }
    }

    fn identifier(&mut self) -> Result<Token<'source>, ParseError> {
        let token = self.take()?;
        match token {
            Some(value) if value.kind == TokenKind::Identifier => Ok(value),
            _ => Err(self.error(ParseErrorKind::ExpectedIdentifier, token)),
        }
    }

    fn expect_kind(
        &mut self,
        kind: TokenKind,
        error: ParseErrorKind,
    ) -> Result<Token<'source>, ParseError> {
        let token = self.take()?;
        match token {
            Some(value) if value.kind == kind => Ok(value),
            _ => Err(self.error(error, token)),
        }
    }

    fn type_until(&mut self, terminators: &[TokenKind]) -> Result<TypeRef<'source>, ParseError> {
        let Some(first) = self.peek()? else {
            return Err(self.error(ParseErrorKind::ExpectedType, None));
        };
        if terminators.contains(&first.kind) {
            return Err(self.error(ParseErrorKind::ExpectedType, Some(first)));
        }
        let start = first.span.start;
        let mut end = start;
        let mut angle_depth = 0usize;
        let mut delimiter_depth = 0usize;
        loop {
            let Some(token) = self.peek()? else {
                return Err(self.error(ParseErrorKind::UnterminatedDelimiter, None));
            };
            if angle_depth == 0 && delimiter_depth == 0 && terminators.contains(&token.kind) {
                break;
            }
            match token.text {
                "<" => angle_depth = angle_depth.saturating_add(1),
                ">" if angle_depth != 0 => angle_depth -= 1,
                ">>" if angle_depth != 0 => angle_depth = angle_depth.saturating_sub(2),
                _ => {}
            }
            match token.kind {
                TokenKind::OpenParen | TokenKind::OpenBracket => {
                    delimiter_depth = delimiter_depth.saturating_add(1);
                }
                TokenKind::CloseParen | TokenKind::CloseBracket if delimiter_depth != 0 => {
                    delimiter_depth -= 1;
                }
                _ => {}
            }
            end = token.span.end;
            self.take()?;
        }
        let text = self.source[start..end].trim_end();
        Ok(TypeRef {
            text,
            span: Span {
                start,
                end: start + text.len(),
            },
        })
    }

    fn type_until_kind_or_text(
        &mut self,
        terminator_kind: TokenKind,
        terminator_text: &str,
    ) -> Result<TypeRef<'source>, ParseError> {
        let Some(first) = self.peek()? else {
            return Err(self.error(ParseErrorKind::ExpectedType, None));
        };
        if first.kind == terminator_kind || first.text == terminator_text {
            return Err(self.error(ParseErrorKind::ExpectedType, Some(first)));
        }
        let start = first.span.start;
        let mut end = start;
        let mut angle_depth = 0usize;
        let mut delimiter_depth = 0usize;
        loop {
            let Some(token) = self.peek()? else {
                return Err(self.error(ParseErrorKind::UnterminatedDelimiter, None));
            };
            if angle_depth == 0
                && delimiter_depth == 0
                && (token.kind == terminator_kind || token.text == terminator_text)
            {
                break;
            }
            match token.text {
                "<" => angle_depth = angle_depth.saturating_add(1),
                ">" if angle_depth != 0 => angle_depth -= 1,
                ">>" if angle_depth != 0 => angle_depth = angle_depth.saturating_sub(2),
                _ => {}
            }
            match token.kind {
                TokenKind::OpenParen | TokenKind::OpenBracket => {
                    delimiter_depth = delimiter_depth.saturating_add(1);
                }
                TokenKind::CloseParen | TokenKind::CloseBracket if delimiter_depth != 0 => {
                    delimiter_depth -= 1;
                }
                _ => {}
            }
            end = token.span.end;
            self.take()?;
        }
        let text = self.source[start..end].trim_end();
        Ok(TypeRef {
            text,
            span: Span {
                start,
                end: start + text.len(),
            },
        })
    }

    fn type_until_text(&mut self, terminator: &str) -> Result<TypeRef<'source>, ParseError> {
        let Some(first) = self.peek()? else {
            return Err(self.error(ParseErrorKind::ExpectedType, None));
        };
        if first.text == terminator {
            return Err(self.error(ParseErrorKind::ExpectedType, Some(first)));
        }
        let start = first.span.start;
        let mut end = start;
        let mut angle_depth = 0usize;
        let mut delimiters = [TokenKind::OpenParen; 64];
        let mut delimiter_depth = 0usize;
        loop {
            let Some(token) = self.peek()? else {
                return Err(self.error(ParseErrorKind::UnterminatedDelimiter, None));
            };
            if angle_depth == 0 && delimiter_depth == 0 && token.text == terminator {
                break;
            }
            match token.text {
                "<" => angle_depth = angle_depth.saturating_add(1),
                ">" if angle_depth != 0 => angle_depth -= 1,
                ">>" if angle_depth != 0 => angle_depth = angle_depth.saturating_sub(2),
                _ => {}
            }
            let open = match token.kind {
                TokenKind::OpenParen => Some(TokenKind::OpenParen),
                TokenKind::OpenBracket => Some(TokenKind::OpenBracket),
                _ => None,
            };
            if let Some(open) = open {
                if delimiter_depth == delimiters.len() {
                    return Err(self.error(ParseErrorKind::NestingLimitExceeded, Some(token)));
                }
                delimiters[delimiter_depth] = open;
                delimiter_depth += 1;
            }
            let expected = match token.kind {
                TokenKind::CloseParen => Some(TokenKind::OpenParen),
                TokenKind::CloseBracket => Some(TokenKind::OpenBracket),
                _ => None,
            };
            if let Some(expected) = expected {
                if delimiter_depth == 0 || delimiters[delimiter_depth - 1] != expected {
                    return Err(self.error(ParseErrorKind::UnexpectedClosingDelimiter, Some(token)));
                }
                delimiter_depth -= 1;
            }
            end = token.span.end;
            self.take()?;
        }
        if angle_depth != 0 || delimiter_depth != 0 {
            let token = self.peek()?;
            return Err(self.error(ParseErrorKind::UnterminatedDelimiter, token));
        }
        let text = self.source[start..end].trim_end();
        Ok(TypeRef {
            text,
            span: Span {
                start,
                end: start + text.len(),
            },
        })
    }

    fn type_until_comma_or_generic_close(&mut self) -> Result<TypeRef<'source>, ParseError> {
        let Some(first) = self.peek()? else {
            return Err(self.error(ParseErrorKind::ExpectedType, None));
        };
        if first.text == "," || first.text == ">" || first.text == ">>" {
            return Err(self.error(ParseErrorKind::ExpectedType, Some(first)));
        }
        let start = first.span.start;
        let mut end = start;
        let mut angle_depth = 0usize;
        loop {
            let Some(token) = self.peek()? else {
                return Err(self.error(ParseErrorKind::UnterminatedDelimiter, None));
            };
            if angle_depth == 0 && (token.text == "," || token.text == ">" || token.text == ">>") {
                break;
            }
            match token.text {
                "<" => angle_depth += 1,
                ">" if angle_depth != 0 => angle_depth -= 1,
                ">>" if angle_depth > 1 => angle_depth -= 2,
                _ => {}
            }
            end = token.span.end;
            self.take()?;
        }
        let text = self.source[start..end].trim_end();
        Ok(TypeRef {
            text,
            span: Span {
                start,
                end: start + text.len(),
            },
        })
    }

    fn source_trait_arguments(
        &mut self,
    ) -> Result<
        (
            [Option<TypeRef<'source>>; MAX_SOURCE_TRAIT_ARGUMENTS],
            usize,
            bool,
        ),
        ParseError,
    > {
        let mut arguments = [None; MAX_SOURCE_TRAIT_ARGUMENTS];
        let mut count = 0usize;
        if self.take_text("<")?.is_none() {
            return Ok((arguments, count, false));
        }
        loop {
            if count == MAX_SOURCE_TRAIT_ARGUMENTS {
                let token = self.peek()?;
                return Err(self.error(ParseErrorKind::TooManyGenericArguments, token));
            }
            let Some(first) = self.peek()? else {
                return Err(self.error(ParseErrorKind::UnterminatedDelimiter, None));
            };
            let start = first.span.start;
            let mut end = start;
            let mut nested = 0usize;
            let mut consumed_nested_and_outer_close = false;
            loop {
                let token = self
                    .peek()?
                    .ok_or_else(|| self.error(ParseErrorKind::UnterminatedDelimiter, None))?;
                if nested == 0 && (token.text == "," || token.text == ">" || token.text == ">>") {
                    break;
                }
                if token.text == ">>" && nested == 1 {
                    end = token.span.start + 1;
                    self.take()?;
                    consumed_nested_and_outer_close = true;
                    break;
                }
                match token.text {
                    "<" => nested += 1,
                    ">" if nested != 0 => nested -= 1,
                    ">>" if nested > 1 => nested -= 2,
                    _ => {}
                }
                end = token.span.end;
                self.take()?;
            }
            if end == start {
                let token = self.peek()?;
                return Err(self.error(ParseErrorKind::ExpectedType, token));
            }
            let text = self.source[start..end].trim_end();
            arguments[count] = Some(TypeRef {
                text,
                span: Span {
                    start,
                    end: start + text.len(),
                },
            });
            count += 1;
            if consumed_nested_and_outer_close {
                return Ok((arguments, count, false));
            }
            if self.take_text(",")?.is_some() {
                continue;
            }
            let close = self.take()?;
            if !close.is_some_and(|token| token.text == ">" || token.text == ">>") {
                return Err(self.error(ParseErrorKind::UnterminatedDelimiter, close));
            }
            return Ok((arguments, count, close.unwrap().text == ">>"));
        }
    }

    fn initializer(&mut self) -> Result<(&'source str, Span), ParseError> {
        let Some(first) = self.peek()? else {
            return Err(self.error(ParseErrorKind::ExpectedInitializer, None));
        };
        if first.kind == TokenKind::Semicolon {
            return Err(self.error(ParseErrorKind::ExpectedInitializer, Some(first)));
        }
        let start = first.span.start;
        let mut end = start;
        let mut delimiters = [TokenKind::OpenParen; 64];
        let mut depth = 0usize;
        loop {
            let Some(token) = self.peek()? else {
                return Err(self.error(ParseErrorKind::ExpectedSemicolon, None));
            };
            if depth == 0 && token.kind == TokenKind::Semicolon {
                self.take()?;
                let text = self.source[start..end].trim_end();
                return Ok((
                    text,
                    Span {
                        start,
                        end: start + text.len(),
                    },
                ));
            }
            let open = match token.kind {
                TokenKind::OpenParen => Some(TokenKind::OpenParen),
                TokenKind::OpenBrace => Some(TokenKind::OpenBrace),
                TokenKind::OpenBracket => Some(TokenKind::OpenBracket),
                _ => None,
            };
            if let Some(open) = open {
                if depth == delimiters.len() {
                    return Err(self.error(ParseErrorKind::NestingLimitExceeded, Some(token)));
                }
                delimiters[depth] = open;
                depth += 1;
            }
            let expected = match token.kind {
                TokenKind::CloseParen => Some(TokenKind::OpenParen),
                TokenKind::CloseBrace => Some(TokenKind::OpenBrace),
                TokenKind::CloseBracket => Some(TokenKind::OpenBracket),
                _ => None,
            };
            if let Some(expected) = expected {
                if depth == 0 || delimiters[depth - 1] != expected {
                    return Err(self.error(ParseErrorKind::UnexpectedClosingDelimiter, Some(token)));
                }
                depth -= 1;
            }
            end = token.span.end;
            self.take()?;
        }
    }

    fn body(&mut self) -> Result<Span, ParseError> {
        let open = self.expect_kind(TokenKind::OpenBrace, ParseErrorKind::ExpectedBody)?;
        let mut delimiters = [TokenKind::OpenBrace; 64];
        let mut depth = 1usize;
        while let Some(token) = self.take()? {
            let matching_open = match token.kind {
                TokenKind::OpenParen => Some(TokenKind::OpenParen),
                TokenKind::OpenBrace => Some(TokenKind::OpenBrace),
                TokenKind::OpenBracket => Some(TokenKind::OpenBracket),
                _ => None,
            };
            if let Some(kind) = matching_open {
                if depth == delimiters.len() {
                    return Err(self.error(ParseErrorKind::NestingLimitExceeded, Some(token)));
                }
                delimiters[depth] = kind;
                depth += 1;
                continue;
            }
            let expected = match token.kind {
                TokenKind::CloseParen => Some(TokenKind::OpenParen),
                TokenKind::CloseBrace => Some(TokenKind::OpenBrace),
                TokenKind::CloseBracket => Some(TokenKind::OpenBracket),
                _ => None,
            };
            if let Some(expected) = expected {
                if delimiters[depth - 1] != expected {
                    return Err(self.error(ParseErrorKind::UnexpectedClosingDelimiter, Some(token)));
                }
                depth -= 1;
                if depth == 0 {
                    return Ok(Span {
                        start: open.span.start,
                        end: token.span.end,
                    });
                }
            }
        }
        Err(self.error(ParseErrorKind::UnterminatedDelimiter, None))
    }

    fn function<const MAX_PARAMETERS: usize>(
        &mut self,
        public: bool,
        constant: bool,
        unsafe_function: bool,
        abi: FunctionAbi,
        no_mangle: bool,
        naked: bool,
    ) -> Result<Function<'source, MAX_PARAMETERS>, ParseError> {
        let name = self.identifier()?;
        self.expect_kind(
            TokenKind::OpenParen,
            ParseErrorKind::ExpectedParameterSeparator,
        )?;
        let mut parameters = [None; MAX_PARAMETERS];
        let mut parameter_count = 0usize;
        if self
            .peek()?
            .is_some_and(|token| token.kind != TokenKind::CloseParen)
        {
            loop {
                if parameter_count == MAX_PARAMETERS {
                    let token = self.peek()?;
                    return Err(self.error(ParseErrorKind::TooManyParameters, token));
                }
                let parameter_name = self.identifier()?;
                self.expect_kind(TokenKind::Colon, ParseErrorKind::ExpectedParameterSeparator)?;
                let ty = self.type_until(&[TokenKind::Comma, TokenKind::CloseParen])?;
                parameters[parameter_count] = Some(Parameter {
                    name: parameter_name.text,
                    span: Span {
                        start: parameter_name.span.start,
                        end: ty.span.end,
                    },
                    ty,
                });
                parameter_count += 1;
                if self.take_text(",")?.is_some() {
                    if self
                        .peek()?
                        .is_some_and(|token| token.kind == TokenKind::CloseParen)
                    {
                        break;
                    }
                } else {
                    break;
                }
            }
        }
        self.expect_kind(
            TokenKind::CloseParen,
            ParseErrorKind::ExpectedParameterSeparator,
        )?;
        let return_type = if self.take_text("->")?.is_some() {
            Some(self.type_until_kind_or_text(TokenKind::OpenBrace, "where")?)
        } else {
            None
        };
        let mut where_predicates = [None; MAX_FUNCTION_WHERE_PREDICATES];
        let mut where_predicate_count = 0usize;
        if self.take_text("where")?.is_some() {
            loop {
                if where_predicate_count == MAX_FUNCTION_WHERE_PREDICATES {
                    let token = self.peek()?;
                    return Err(self.error(ParseErrorKind::TooManyWherePredicates, token));
                }
                let predicate = if self.take_text("<")?.is_some() {
                    let self_type = self.type_until_text("as")?;
                    let as_token = self.take()?;
                    if !as_token.is_some_and(|token| token.text == "as") {
                        return Err(self.error(ParseErrorKind::ExpectedIdentifier, as_token));
                    }
                    let trait_name = self.identifier()?;
                    let (trait_arguments, trait_argument_count, consumed_projection_close) =
                        self.source_trait_arguments()?;
                    if !consumed_projection_close {
                        let close = self.take()?;
                        if !close.is_some_and(|token| token.text == ">") {
                            return Err(self.error(ParseErrorKind::ExpectedType, close));
                        }
                    }
                    let separator = self.take()?;
                    if !separator.is_some_and(|token| token.text == "::") {
                        return Err(self.error(ParseErrorKind::ExpectedIdentifier, separator));
                    }
                    let associated_type = self.identifier()?;
                    let equals = self.take()?;
                    if !equals.is_some_and(|token| token.text == "=") {
                        return Err(self.error(ParseErrorKind::ExpectedType, equals));
                    }
                    let expected_type = self.type_until_kind_or_text(TokenKind::OpenBrace, ",")?;
                    FunctionWherePredicate::ProjectionEquality {
                        self_type,
                        trait_name: trait_name.text,
                        trait_name_span: trait_name.span,
                        trait_arguments,
                        trait_argument_count,
                        associated_type: associated_type.text,
                        associated_type_span: associated_type.span,
                        expected_type,
                    }
                } else {
                    let self_type = self.type_until(&[TokenKind::Colon])?;
                    self.expect_kind(TokenKind::Colon, ParseErrorKind::ExpectedColon)?;
                    let trait_name = self.identifier()?;
                    let (trait_arguments, trait_argument_count, consumed_outer_close) =
                        self.source_trait_arguments()?;
                    if consumed_outer_close {
                        let token = self.peek()?;
                        return Err(self.error(ParseErrorKind::ExpectedBody, token));
                    }
                    FunctionWherePredicate::Implemented {
                        self_type,
                        trait_name: trait_name.text,
                        trait_name_span: trait_name.span,
                        trait_arguments,
                        trait_argument_count,
                    }
                };
                where_predicates[where_predicate_count] = Some(predicate);
                where_predicate_count += 1;
                if self.take_text(",")?.is_none() {
                    break;
                }
                if self
                    .peek()?
                    .is_some_and(|token| token.kind == TokenKind::OpenBrace)
                {
                    break;
                }
            }
        }
        let body = self.body()?;
        let untrimmed = &self.source[body.start + 1..body.end - 1];
        let body_expression = untrimmed.trim();
        let body_expression_start =
            body.start + 1 + (untrimmed.len() - untrimmed.trim_start().len());
        Ok(Function {
            public,
            constant,
            unsafe_function,
            abi,
            no_mangle,
            naked,
            name: name.text,
            name_span: name.span,
            parameters,
            parameter_count,
            return_type,
            where_predicates,
            where_predicate_count,
            body,
            body_expression,
            body_expression_span: Span {
                start: body_expression_start,
                end: body_expression_start + body_expression.len(),
            },
        })
    }

    fn crate_attributes(&mut self) -> Result<(), ParseError> {
        while self
            .peek()?
            .is_some_and(|token| token.kind == TokenKind::Pound)
        {
            let mut probe = self.lexer.clone();
            let Some(bang) = probe.next_token().map_err(Self::lexical)? else {
                break;
            };
            if bang.kind != TokenKind::Bang {
                break;
            }
            self.take()?;
            self.take()?;
            self.expect_kind(
                TokenKind::OpenBracket,
                ParseErrorKind::ExpectedAttributeDelimiter,
            )?;
            let attribute = self.identifier()?;
            if attribute.text != "no_std" {
                return Err(self.error(ParseErrorKind::UnsupportedAttribute, Some(attribute)));
            }
            self.expect_kind(
                TokenKind::CloseBracket,
                ParseErrorKind::ExpectedAttributeDelimiter,
            )?;
        }
        Ok(())
    }

    fn function_attributes(&mut self) -> Result<(bool, bool, Option<FunctionAbi>), ParseError> {
        let mut no_mangle = false;
        let mut naked = false;
        let mut export_abi = None;
        while self.take_text("#")?.is_some() {
            self.expect_kind(
                TokenKind::OpenBracket,
                ParseErrorKind::ExpectedAttributeDelimiter,
            )?;
            let namespace = self.identifier()?;
            if namespace.text == "mrml_abi" {
                let separator = self.take()?;
                if !separator.is_some_and(|token| token.text == "::") {
                    return Err(self.error(ParseErrorKind::UnsupportedAttribute, separator));
                }
                let attribute = self.identifier()?;
                if attribute.text != "export" || export_abi.is_some() {
                    return Err(self.error(ParseErrorKind::UnsupportedAttribute, Some(attribute)));
                }
                self.expect_kind(
                    TokenKind::OpenParen,
                    ParseErrorKind::ExpectedAttributeDelimiter,
                )?;
                let version = self.identifier()?;
                if version.text != "version" {
                    return Err(self.error(ParseErrorKind::UnsupportedAttribute, Some(version)));
                }
                let equals = self.take()?;
                if !equals.is_some_and(|token| token.text == "=") {
                    return Err(self.error(ParseErrorKind::UnsupportedAttribute, equals));
                }
                let value = self.take()?;
                if !value.is_some_and(|token| token.text == "1") {
                    return Err(self.error(ParseErrorKind::UnsupportedAbi, value));
                }
                self.expect_kind(
                    TokenKind::CloseParen,
                    ParseErrorKind::ExpectedAttributeDelimiter,
                )?;
                export_abi = Some(FunctionAbi::MrmlV1);
            } else {
                if namespace.text != "unsafe" {
                    return Err(
                        self.error(ParseErrorKind::UnsupportedAttribute, Some(namespace))
                    );
                }
                self.expect_kind(
                    TokenKind::OpenParen,
                    ParseErrorKind::ExpectedAttributeDelimiter,
                )?;
                let attribute = self.identifier()?;
                match attribute.text {
                    "no_mangle" if !no_mangle => no_mangle = true,
                    "naked" if !naked => naked = true,
                    _ => {
                        return Err(
                            self.error(ParseErrorKind::UnsupportedAttribute, Some(attribute))
                        );
                    }
                }
                self.expect_kind(
                    TokenKind::CloseParen,
                    ParseErrorKind::ExpectedAttributeDelimiter,
                )?;
            }
            self.expect_kind(
                TokenKind::CloseBracket,
                ParseErrorKind::ExpectedAttributeDelimiter,
            )?;
        }
        Ok((no_mangle, naked, export_abi))
    }

    fn const_item(&mut self, public: bool) -> Result<ConstItem<'source>, ParseError> {
        let name = self.identifier()?;
        self.expect_kind(TokenKind::Colon, ParseErrorKind::ExpectedType)?;
        let ty = self.type_until_text("=")?;
        if self.take_text("=")?.is_none() {
            let token = self.peek()?;
            return Err(self.error(ParseErrorKind::ExpectedEquals, token));
        }
        let (initializer, initializer_span) = self.initializer()?;
        Ok(ConstItem {
            public,
            name: name.text,
            name_span: name.span,
            ty,
            initializer,
            initializer_span,
        })
    }

    fn trait_where_predicates(
        &mut self,
    ) -> Result<
        (
            [Option<TraitImplementationWherePredicate<'source>>; MAX_FUNCTION_WHERE_PREDICATES],
            usize,
        ),
        ParseError,
    > {
        let mut where_predicates = [None; MAX_FUNCTION_WHERE_PREDICATES];
        let mut where_predicate_count = 0usize;
        if self.take_text("where")?.is_none() {
            return Ok((where_predicates, where_predicate_count));
        }
        loop {
            if where_predicate_count == MAX_FUNCTION_WHERE_PREDICATES {
                let token = self.peek()?;
                return Err(self.error(ParseErrorKind::TooManyWherePredicates, token));
            }
            let predicate = if self.take_text("<")?.is_some() {
                let predicate_self = self.type_until_text("as")?;
                let as_token = self.take()?;
                if !as_token.is_some_and(|token| token.text == "as") {
                    return Err(self.error(ParseErrorKind::ExpectedIdentifier, as_token));
                }
                let predicate_trait = self.identifier()?;
                let (trait_arguments, trait_argument_count, consumed_projection_close) =
                    self.source_trait_arguments()?;
                if !consumed_projection_close {
                    let close = self.take()?;
                    if !close.is_some_and(|token| token.text == ">") {
                        return Err(self.error(ParseErrorKind::ExpectedType, close));
                    }
                }
                let separator = self.take()?;
                if !separator.is_some_and(|token| token.text == "::") {
                    return Err(self.error(ParseErrorKind::ExpectedIdentifier, separator));
                }
                let associated_type = self.identifier()?;
                let equals = self.take()?;
                if !equals.is_some_and(|token| token.text == "=") {
                    return Err(self.error(ParseErrorKind::ExpectedEquals, equals));
                }
                let expected_type = self.type_until_kind_or_text(TokenKind::OpenBrace, ",")?;
                Some(TraitImplementationWherePredicate::ProjectionEquality {
                    self_type: predicate_self,
                    trait_name: predicate_trait.text,
                    trait_name_span: predicate_trait.span,
                    trait_arguments,
                    trait_argument_count,
                    associated_type: associated_type.text,
                    associated_type_span: associated_type.span,
                    expected_type,
                })
            } else {
                let predicate_self = self.type_until(&[TokenKind::Colon])?;
                self.expect_kind(TokenKind::Colon, ParseErrorKind::ExpectedColon)?;
                let predicate_trait = self.identifier()?;
                let (trait_arguments, trait_argument_count, consumed_outer_close) =
                    self.source_trait_arguments()?;
                if consumed_outer_close {
                    let token = self.peek()?;
                    return Err(self.error(ParseErrorKind::ExpectedBody, token));
                }
                self.push_implemented_trait_bound(
                    predicate_self,
                    predicate_trait,
                    trait_arguments,
                    trait_argument_count,
                    &mut where_predicates,
                    &mut where_predicate_count,
                )?;
                None
            };
            if let Some(predicate) = predicate {
                where_predicates[where_predicate_count] = Some(predicate);
                where_predicate_count += 1;
            }
            if self.take_text(",")?.is_none() {
                break;
            }
            if self
                .peek()?
                .is_some_and(|token| token.kind == TokenKind::OpenBrace)
            {
                break;
            }
        }
        Ok((where_predicates, where_predicate_count))
    }

    fn push_implemented_trait_bound(
        &self,
        self_type: TypeRef<'source>,
        bound: Token<'source>,
        trait_arguments: [Option<TypeRef<'source>>; MAX_SOURCE_TRAIT_ARGUMENTS],
        trait_argument_count: usize,
        predicates: &mut [Option<TraitImplementationWherePredicate<'source>>;
                 MAX_FUNCTION_WHERE_PREDICATES],
        predicate_count: &mut usize,
    ) -> Result<(), ParseError> {
        let has_binding = trait_arguments[..trait_argument_count]
            .iter()
            .flatten()
            .any(|argument| argument.text.contains('='));
        if !has_binding {
            if *predicate_count == MAX_FUNCTION_WHERE_PREDICATES {
                return Err(self.error(ParseErrorKind::TooManyWherePredicates, None));
            }
            predicates[*predicate_count] = Some(TraitImplementationWherePredicate::Implemented {
                self_type,
                trait_name: bound.text,
                trait_name_span: bound.span,
                trait_arguments,
                trait_argument_count,
            });
            *predicate_count += 1;
            return Ok(());
        }
        let mut positional_arguments = [None; MAX_SOURCE_TRAIT_ARGUMENTS];
        let mut positional_argument_count = 0usize;
        let binding_count = trait_arguments[..trait_argument_count]
            .iter()
            .flatten()
            .filter(|argument| argument.text.contains('='))
            .count();
        for argument in trait_arguments[..trait_argument_count].iter().flatten() {
            if !argument.text.contains('=') {
                positional_arguments[positional_argument_count] = Some(*argument);
                positional_argument_count += 1;
            }
        }
        if *predicate_count + 1 + binding_count > MAX_FUNCTION_WHERE_PREDICATES {
            return Err(self.error(ParseErrorKind::TooManyWherePredicates, None));
        }
        predicates[*predicate_count] = Some(TraitImplementationWherePredicate::Implemented {
            self_type,
            trait_name: bound.text,
            trait_name_span: bound.span,
            trait_arguments: positional_arguments,
            trait_argument_count: positional_argument_count,
        });
        *predicate_count += 1;
        for argument in trait_arguments[..trait_argument_count].iter().flatten() {
            if !argument.text.contains('=') {
                continue;
            }
            let Some(equals) = argument.text.find('=') else {
                unreachable!()
            };
            if argument.text[equals + 1..].contains('=') {
                return Err(self.error(ParseErrorKind::ExpectedType, None));
            }
            let name_text = argument.text[..equals].trim();
            let expected_text = argument.text[equals + 1..].trim();
            if name_text.is_empty()
                || expected_text.is_empty()
                || !name_text.bytes().enumerate().all(|(index, byte)| {
                    byte == b'_'
                        || byte.is_ascii_alphabetic()
                        || (index != 0 && byte.is_ascii_digit())
                })
            {
                return Err(self.error(ParseErrorKind::ExpectedType, None));
            }
            let name_offset = argument.text[..equals].find(name_text).unwrap();
            let expected_offset =
                equals + 1 + argument.text[equals + 1..].find(expected_text).unwrap();
            predicates[*predicate_count] =
                Some(TraitImplementationWherePredicate::ProjectionEquality {
                    self_type,
                    trait_name: bound.text,
                    trait_name_span: bound.span,
                    trait_arguments: positional_arguments,
                    trait_argument_count: positional_argument_count,
                    associated_type: name_text,
                    associated_type_span: Span {
                        start: argument.span.start + name_offset,
                        end: argument.span.start + name_offset + name_text.len(),
                    },
                    expected_type: TypeRef {
                        text: expected_text,
                        span: Span {
                            start: argument.span.start + expected_offset,
                            end: argument.span.start + expected_offset + expected_text.len(),
                        },
                    },
                });
            *predicate_count += 1;
        }
        Ok(())
    }

    fn trait_declaration(&mut self, public: bool) -> Result<TraitDeclaration<'source>, ParseError> {
        let name = self.identifier()?;
        let mut generic_parameters = [None; MAX_SOURCE_TRAIT_ARGUMENTS];
        let mut generic_parameter_defaults = [None; MAX_SOURCE_TRAIT_ARGUMENTS];
        let mut generic_parameter_count = 0usize;
        let mut where_predicates = [None; MAX_FUNCTION_WHERE_PREDICATES];
        let mut where_predicate_count = 0usize;
        if self.take_text("<")?.is_some() {
            loop {
                if generic_parameter_count == MAX_SOURCE_TRAIT_ARGUMENTS {
                    let token = self.peek()?;
                    return Err(self.error(ParseErrorKind::TooManyGenericArguments, token));
                }
                let parameter = self.identifier()?;
                generic_parameters[generic_parameter_count] = Some(parameter.text);
                generic_parameter_count += 1;
                let mut consumed_declaration_close = false;
                if self.take_text(":")?.is_some() {
                    loop {
                        let bound = self.identifier()?;
                        let (trait_arguments, trait_argument_count, consumed_outer_close) =
                            self.source_trait_arguments()?;
                        self.push_implemented_trait_bound(
                            TypeRef {
                                text: parameter.text,
                                span: parameter.span,
                            },
                            bound,
                            trait_arguments,
                            trait_argument_count,
                            &mut where_predicates,
                            &mut where_predicate_count,
                        )?;
                        if consumed_outer_close {
                            consumed_declaration_close = true;
                            break;
                        }
                        if self.take_text("+")?.is_none() {
                            break;
                        }
                    }
                }
                if consumed_declaration_close {
                    break;
                }
                if self.take_text("=")?.is_some() {
                    generic_parameter_defaults[generic_parameter_count - 1] =
                        Some(self.type_until_comma_or_generic_close()?);
                }
                if self.take_text(",")?.is_some() {
                    continue;
                }
                let close = self.take()?;
                if !close.is_some_and(|token| token.text == ">") {
                    return Err(self.error(ParseErrorKind::UnterminatedDelimiter, close));
                }
                break;
            }
        }
        let mut supertraits = [None; MAX_TRAIT_SUPERTRAITS];
        let mut supertrait_count = 0usize;
        if self.take_text(":")?.is_some() {
            loop {
                if supertrait_count == MAX_TRAIT_SUPERTRAITS {
                    let token = self.peek()?;
                    return Err(self.error(ParseErrorKind::TooManySupertraits, token));
                }
                let supertrait = self.identifier()?;
                let (mut arguments, mut argument_count, consumed_outer_close) =
                    self.source_trait_arguments()?;
                if consumed_outer_close {
                    let token = self.peek()?;
                    return Err(self.error(ParseErrorKind::ExpectedBody, token));
                }
                if arguments[..argument_count]
                    .iter()
                    .flatten()
                    .any(|argument| argument.text.contains('='))
                {
                    let mut desugared = [None; MAX_FUNCTION_WHERE_PREDICATES];
                    let mut desugared_count = 0usize;
                    self.push_implemented_trait_bound(
                        TypeRef {
                            text: "Self",
                            span: name.span,
                        },
                        supertrait,
                        arguments,
                        argument_count,
                        &mut desugared,
                        &mut desugared_count,
                    )?;
                    let Some(TraitImplementationWherePredicate::Implemented {
                        trait_arguments,
                        trait_argument_count,
                        ..
                    }) = desugared[0]
                    else {
                        unreachable!()
                    };
                    arguments = trait_arguments;
                    argument_count = trait_argument_count;
                    if where_predicate_count + desugared_count - 1 > MAX_FUNCTION_WHERE_PREDICATES {
                        return Err(
                            self.error(ParseErrorKind::TooManyWherePredicates, Some(supertrait))
                        );
                    }
                    for predicate in desugared[1..desugared_count].iter().flatten() {
                        where_predicates[where_predicate_count] = Some(*predicate);
                        where_predicate_count += 1;
                    }
                }
                supertraits[supertrait_count] = Some(TraitSupertrait {
                    name: supertrait.text,
                    span: supertrait.span,
                    arguments,
                    argument_count,
                });
                supertrait_count += 1;
                if self.take_text("+")?.is_none() {
                    break;
                }
            }
        }
        let (explicit_predicates, explicit_predicate_count) = self.trait_where_predicates()?;
        if where_predicate_count + explicit_predicate_count > MAX_FUNCTION_WHERE_PREDICATES {
            let token = self.peek()?;
            return Err(self.error(ParseErrorKind::TooManyWherePredicates, token));
        }
        where_predicates[where_predicate_count..where_predicate_count + explicit_predicate_count]
            .copy_from_slice(&explicit_predicates[..explicit_predicate_count]);
        where_predicate_count += explicit_predicate_count;
        let open = self.expect_kind(TokenKind::OpenBrace, ParseErrorKind::ExpectedBody)?;
        let mut associated_types = [None; MAX_TRAIT_ASSOCIATED_TYPES];
        let mut associated_type_count = 0usize;
        let close = loop {
            if self
                .peek()?
                .is_some_and(|token| token.kind == TokenKind::CloseBrace)
            {
                break self.take()?.unwrap();
            }
            if associated_type_count == MAX_TRAIT_ASSOCIATED_TYPES {
                let token = self.peek()?;
                return Err(self.error(ParseErrorKind::TooManyAssociatedTypes, token));
            }
            let keyword = self.take()?;
            if !keyword.is_some_and(|token| token.text == "type") {
                return Err(self.error(ParseErrorKind::UnsupportedTraitBody, keyword));
            }
            let associated = self.identifier()?;
            let default = if self.take_text("=")?.is_some() {
                Some(self.type_until(&[TokenKind::Semicolon])?)
            } else {
                None
            };
            self.expect_kind(TokenKind::Semicolon, ParseErrorKind::ExpectedSemicolon)?;
            associated_types[associated_type_count] = Some(TraitAssociatedTypeDeclaration {
                name: associated.text,
                span: associated.span,
                default,
            });
            associated_type_count += 1;
        };
        Ok(TraitDeclaration {
            public,
            name: name.text,
            name_span: name.span,
            generic_parameters,
            generic_parameter_defaults,
            generic_parameter_count,
            supertraits,
            supertrait_count,
            where_predicates,
            where_predicate_count,
            associated_types,
            associated_type_count,
            body: Span {
                start: open.span.start,
                end: close.span.end,
            },
        })
    }

    fn trait_implementation(&mut self) -> Result<TraitImplementation<'source>, ParseError> {
        let mut generic_parameters = [None; MAX_SOURCE_TRAIT_ARGUMENTS];
        let mut generic_parameter_count = 0usize;
        let mut where_predicates = [None; MAX_FUNCTION_WHERE_PREDICATES];
        let mut where_predicate_count = 0usize;
        if self.take_text("<")?.is_some() {
            loop {
                if generic_parameter_count == MAX_SOURCE_TRAIT_ARGUMENTS {
                    let token = self.peek()?;
                    return Err(self.error(ParseErrorKind::TooManyGenericArguments, token));
                }
                let parameter = self.identifier()?;
                generic_parameters[generic_parameter_count] = Some(parameter.text);
                generic_parameter_count += 1;
                let mut consumed_implementation_close = false;
                if self.take_text(":")?.is_some() {
                    loop {
                        let bound = self.identifier()?;
                        let (trait_arguments, trait_argument_count, consumed_outer_close) =
                            self.source_trait_arguments()?;
                        self.push_implemented_trait_bound(
                            TypeRef {
                                text: parameter.text,
                                span: parameter.span,
                            },
                            bound,
                            trait_arguments,
                            trait_argument_count,
                            &mut where_predicates,
                            &mut where_predicate_count,
                        )?;
                        if consumed_outer_close {
                            consumed_implementation_close = true;
                            break;
                        }
                        if self.take_text("+")?.is_none() {
                            break;
                        }
                    }
                }
                if consumed_implementation_close {
                    break;
                }
                if self.take_text(",")?.is_some() {
                    continue;
                }
                let close = self.take()?;
                if !close.is_some_and(|token| token.text == ">") {
                    return Err(self.error(ParseErrorKind::UnterminatedDelimiter, close));
                }
                break;
            }
        }
        let trait_name = self.identifier()?;
        let (trait_arguments, trait_argument_count, consumed_outer_close) =
            self.source_trait_arguments()?;
        if consumed_outer_close {
            let token = self.peek()?;
            return Err(self.error(ParseErrorKind::ExpectedFor, token));
        }
        let for_keyword = self.take()?;
        if !for_keyword.is_some_and(|token| token.text == "for") {
            return Err(self.error(ParseErrorKind::ExpectedFor, for_keyword));
        }
        let self_type = self.type_until_kind_or_text(TokenKind::OpenBrace, "where")?;
        let (explicit_predicates, explicit_predicate_count) = self.trait_where_predicates()?;
        if where_predicate_count + explicit_predicate_count > MAX_FUNCTION_WHERE_PREDICATES {
            let token = self.peek()?;
            return Err(self.error(ParseErrorKind::TooManyWherePredicates, token));
        }
        where_predicates[where_predicate_count..where_predicate_count + explicit_predicate_count]
            .copy_from_slice(&explicit_predicates[..explicit_predicate_count]);
        where_predicate_count += explicit_predicate_count;
        let open = self.expect_kind(TokenKind::OpenBrace, ParseErrorKind::ExpectedBody)?;
        let mut associated_types = [None; MAX_TRAIT_ASSOCIATED_TYPES];
        let mut associated_type_count = 0usize;
        let close = loop {
            if self
                .peek()?
                .is_some_and(|token| token.kind == TokenKind::CloseBrace)
            {
                break self.take()?.unwrap();
            }
            if associated_type_count == MAX_TRAIT_ASSOCIATED_TYPES {
                let token = self.peek()?;
                return Err(self.error(ParseErrorKind::TooManyAssociatedTypes, token));
            }
            let keyword = self.take()?;
            if !keyword.is_some_and(|token| token.text == "type") {
                return Err(self.error(ParseErrorKind::UnsupportedTraitImplementationBody, keyword));
            }
            let associated = self.identifier()?;
            let equals = self.take()?;
            if !equals.is_some_and(|token| token.text == "=") {
                return Err(self.error(ParseErrorKind::ExpectedEquals, equals));
            }
            let value = self.type_until(&[TokenKind::Semicolon])?;
            self.expect_kind(TokenKind::Semicolon, ParseErrorKind::ExpectedSemicolon)?;
            associated_types[associated_type_count] = Some(TraitAssociatedTypeImplementation {
                name: associated.text,
                name_span: associated.span,
                value,
            });
            associated_type_count += 1;
        };
        Ok(TraitImplementation {
            generic_parameters,
            generic_parameter_count,
            trait_name: trait_name.text,
            trait_name_span: trait_name.span,
            trait_arguments,
            trait_argument_count,
            self_type,
            where_predicates,
            where_predicate_count,
            associated_types,
            associated_type_count,
            body: Span {
                start: open.span.start,
                end: close.span.end,
            },
        })
    }

    fn unsupported_aggregate_declaration(
        &mut self,
        keyword: Token<'source>,
    ) -> Result<ParseError, ParseError> {
        let is_struct = keyword.text == "struct";
        let name = self.take()?;
        let Some(name) = name.filter(|token| {
            token.kind == TokenKind::Identifier
                && !matches!(token.text, "_" | "fn" | "struct" | "enum" | "pub" | "where")
        }) else {
            let kind = if is_struct {
                ParseErrorKind::ExpectedStructName
            } else {
                ParseErrorKind::ExpectedEnumName
            };
            return Ok(self.error(kind, name));
        };

        let next = self.peek()?;
        let has_body_start = next.is_some_and(|token| {
            matches!(token.text, "{" | "<" | "where")
                || (is_struct && matches!(token.kind, TokenKind::OpenParen | TokenKind::Semicolon))
        });
        if !has_body_start {
            let kind = if is_struct {
                ParseErrorKind::ExpectedStructBody
            } else {
                ParseErrorKind::ExpectedEnumBody
            };
            let span = next.map_or(
                Span {
                    start: name.span.end,
                    end: name.span.end,
                },
                |token| token.span,
            );
            return Ok(ParseError { kind, span });
        }

        let kind = if is_struct {
            ParseErrorKind::UnsupportedStructDeclaration
        } else {
            ParseErrorKind::UnsupportedEnumDeclaration
        };
        Ok(ParseError {
            kind,
            span: Span {
                start: keyword.span.start,
                end: name.span.end,
            },
        })
    }

    pub fn parse_module<const MAX_ITEMS: usize, const MAX_PARAMETERS: usize>(
        mut self,
    ) -> Result<Module<'source, MAX_ITEMS, MAX_PARAMETERS>, ParseError> {
        // The supported source subset already compiles without a standard library.
        self.crate_attributes()?;
        let mut module = Module {
            items: [None; MAX_ITEMS],
            item_count: 0,
        };
        while self.peek()?.is_some() {
            if module.item_count == MAX_ITEMS {
                let token = self.peek()?;
                return Err(self.error(ParseErrorKind::TooManyItems, token));
            }
            let (no_mangle, naked, export_abi) = self.function_attributes()?;
            let public = self.take_text("pub")?.is_some();
            let keyword = self.take()?;
            if let Some(keyword) = keyword
                && matches!(keyword.text, "struct" | "enum")
                && !no_mangle
                && !naked
                && export_abi.is_none()
            {
                return Err(self.unsupported_aggregate_declaration(keyword)?);
            }
            let item = match keyword.map(|token| token.text) {
                Some("fn") => Item::Function(self.function(
                    public,
                    false,
                    false,
                    FunctionAbi::Rust,
                    no_mangle,
                    naked,
                )?),
                Some("extern") => {
                    let abi = self.take()?;
                    if !abi.is_some_and(|token| {
                        token.kind == TokenKind::String && token.text == "\"C\""
                    }) {
                        return Err(self.error(ParseErrorKind::UnsupportedAbi, abi));
                    }
                    let function_keyword = self.take()?;
                    if !function_keyword.is_some_and(|token| token.text == "fn") {
                        return Err(self.error(ParseErrorKind::ExpectedItem, function_keyword));
                    }
                    Item::Function(self.function(
                        public,
                        false,
                        false,
                        FunctionAbi::C,
                        no_mangle,
                        naked,
                    )?)
                }
                Some("const") => match self.peek()?.map(|token| token.text) {
                    Some("fn") => {
                        self.take()?;
                        Item::Function(self.function(
                            public,
                            true,
                            false,
                            FunctionAbi::Rust,
                            no_mangle,
                            naked,
                        )?)
                    }
                    Some("extern") => {
                        self.take()?;
                        let abi = self.take()?;
                        if !abi.is_some_and(|token| {
                            token.kind == TokenKind::String && token.text == "\"C\""
                        }) {
                            return Err(self.error(ParseErrorKind::UnsupportedAbi, abi));
                        }
                        let function_keyword = self.take()?;
                        if !function_keyword.is_some_and(|token| token.text == "fn") {
                            return Err(self.error(ParseErrorKind::ExpectedItem, function_keyword));
                        }
                        Item::Function(self.function(
                            public,
                            true,
                            false,
                            FunctionAbi::C,
                            no_mangle,
                            naked,
                        )?)
                    }
                    Some("unsafe") => {
                        self.take()?;
                        let qualifier = self.take()?;
                        match qualifier.map(|token| token.text) {
                            Some("fn") => Item::Function(self.function(
                                public,
                                true,
                                true,
                                FunctionAbi::Rust,
                                no_mangle,
                                naked,
                            )?),
                            Some("extern") => {
                                let abi = self.take()?;
                                if !abi.is_some_and(|token| {
                                    token.kind == TokenKind::String && token.text == "\"C\""
                                }) {
                                    return Err(self.error(ParseErrorKind::UnsupportedAbi, abi));
                                }
                                let function_keyword = self.take()?;
                                if !function_keyword.is_some_and(|token| token.text == "fn") {
                                    return Err(
                                        self.error(ParseErrorKind::ExpectedItem, function_keyword)
                                    );
                                }
                                Item::Function(self.function(
                                    public,
                                    true,
                                    true,
                                    FunctionAbi::C,
                                    no_mangle,
                                    naked,
                                )?)
                            }
                            _ => return Err(self.error(ParseErrorKind::ExpectedItem, qualifier)),
                        }
                    }
                    _ if !no_mangle && !naked => Item::Const(self.const_item(public)?),
                    _ => {
                        let token = self.peek()?;
                        return Err(self.error(ParseErrorKind::ExpectedItem, token));
                    }
                },
                Some("unsafe") => {
                    let qualifier = self.take()?;
                    match qualifier.map(|token| token.text) {
                        Some("fn") => Item::Function(self.function(
                            public,
                            false,
                            true,
                            FunctionAbi::Rust,
                            no_mangle,
                            naked,
                        )?),
                        Some("extern") => {
                            let abi = self.take()?;
                            if !abi.is_some_and(|token| {
                                token.kind == TokenKind::String && token.text == "\"C\""
                            }) {
                                return Err(self.error(ParseErrorKind::UnsupportedAbi, abi));
                            }
                            let function_keyword = self.take()?;
                            if !function_keyword.is_some_and(|token| token.text == "fn") {
                                return Err(
                                    self.error(ParseErrorKind::ExpectedItem, function_keyword)
                                );
                            }
                            Item::Function(self.function(
                                public,
                                false,
                                true,
                                FunctionAbi::C,
                                no_mangle,
                                naked,
                            )?)
                        }
                        _ => return Err(self.error(ParseErrorKind::ExpectedItem, qualifier)),
                    }
                }
                Some("static") if !no_mangle && !naked => Item::Static(self.const_item(public)?),
                Some("trait") if !no_mangle && !naked => {
                    Item::Trait(self.trait_declaration(public)?)
                }
                Some("impl") if !no_mangle && !naked && !public => {
                    Item::TraitImplementation(self.trait_implementation()?)
                }
                _ => return Err(self.error(ParseErrorKind::ExpectedItem, keyword)),
            };
            let item = if let Some(export_abi) = export_abi {
                match item {
                    Item::Function(mut function)
                        if function.public
                            && !function.constant
                            && function.abi == FunctionAbi::Rust
                            && !function.naked =>
                    {
                        function.abi = export_abi;
                        function.no_mangle = true;
                        Item::Function(function)
                    }
                    _ => {
                        return Err(self.error(ParseErrorKind::UnsupportedAttribute, keyword));
                    }
                }
            } else {
                item
            };
            module.items[module.item_count] = Some(item);
            module.item_count += 1;
        }
        Ok(module)
    }
}
