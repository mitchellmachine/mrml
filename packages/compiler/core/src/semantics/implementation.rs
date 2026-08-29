use crate::{
    BinaryOperator, ConstEvalError, ConstantResolver, ExecutionError, ExprId, ExprKind,
    ExpressionErrorKind, ExpressionTree, IrErrorKind, Item, Module, Span, UnaryOperator,
    lower_expression_with_pointer_bits,
};

pub const MAX_CONSTANT_IR_INSTRUCTIONS: usize = 256;
pub const MAX_CONSTANT_STACK_VALUES: usize = 64;
pub const MAX_CONST_CALL_DEPTH: usize = 8;
pub const MAX_CONST_FUNCTION_EXPRESSION_NODES: usize = 16;
pub const MAX_CONST_LOOP_ITERATIONS: usize = 65_536;
const MAX_CONST_CALL_BINDINGS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetLayout {
    pointer_bits: u8,
}
impl TargetLayout {
    pub const X86_64: Self = Self { pointer_bits: 64 };
    pub const NVPTX64: Self = Self { pointer_bits: 64 };

    pub const fn new(pointer_bits: u8) -> Option<Self> {
        if matches!(pointer_bits, 16 | 32 | 64) {
            Some(Self { pointer_bits })
        } else {
            None
        }
    }

    pub const fn pointer_bits(self) -> u8 {
        self.pointer_bits
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Constant<'source> {
    pub name: &'source str,
    pub ty: &'source str,
    pub value: u128,
    pub span: Span,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConstantTable<'source, const MAX_CONSTANTS: usize> {
    constants: [Option<Constant<'source>>; MAX_CONSTANTS],
    count: usize,
}

impl<'source, const MAX_CONSTANTS: usize> ConstantTable<'source, MAX_CONSTANTS> {
    pub fn constants(&self) -> &[Option<Constant<'source>>] {
        &self.constants[..self.count]
    }

    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn get(&self, name: &str) -> Option<&Constant<'source>> {
        self.constants()
            .iter()
            .flatten()
            .find(|constant| constant.name == name)
    }
}

impl<const MAX_CONSTANTS: usize> ConstantResolver for ConstantTable<'_, MAX_CONSTANTS> {
    fn resolve(&self, name: &str) -> Option<u128> {
        self.get(name).map(|constant| constant.value)
    }

    fn resolve_type(&self, name: &str) -> Option<crate::IntegerType> {
        self.get(name)
            .and_then(|constant| crate::IntegerType::from_name(constant.ty))
    }

    fn resolves_bool(&self, name: &str) -> bool {
        self.get(name).is_some_and(|constant| constant.ty == "bool")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticErrorKind {
    DuplicateDefinition,
    TooManyConstants,
    UnsupportedConstantType,
    ConstantOutOfRange,
    Expression(ExpressionErrorKind),
    Lowering(IrErrorKind),
    Execution(ExecutionError),
    UnsupportedConstCall,
    ConstLoopLimitExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemanticError {
    pub kind: SemanticErrorKind,
    pub span: Span,
}

pub fn analyze_constants<
    'source,
    const MAX_CONSTANTS: usize,
    const MAX_EXPRESSION_NODES: usize,
    const MAX_ITEMS: usize,
    const MAX_PARAMETERS: usize,
>(
    module: &Module<'source, MAX_ITEMS, MAX_PARAMETERS>,
    target: TargetLayout,
) -> Result<ConstantTable<'source, MAX_CONSTANTS>, SemanticError> {
    let mut symbols = [None; MAX_ITEMS];
    let mut table = ConstantTable {
        constants: [None; MAX_CONSTANTS],
        count: 0,
    };

    for (symbol_count, item) in module.items().iter().flatten().enumerate() {
        let Some((name, name_span)) = (match item {
            Item::Function(function) => Some((function.name, function.name_span)),
            Item::Const(constant) | Item::Static(constant) => {
                Some((constant.name, constant.name_span))
            }
            Item::Trait(declaration) => Some((declaration.name, declaration.name_span)),
            Item::TraitImplementation(_) => None,
        }) else {
            continue;
        };
        if symbols[..symbol_count].contains(&Some(name)) {
            return Err(SemanticError {
                kind: SemanticErrorKind::DuplicateDefinition,
                span: name_span,
            });
        }
        symbols[symbol_count] = Some(name);

        let constant = match item {
            Item::Const(constant) | Item::Static(constant) => constant,
            Item::Function(_) | Item::Trait(_) | Item::TraitImplementation(_) => continue,
        };
        if table.count == MAX_CONSTANTS {
            return Err(SemanticError {
                kind: SemanticErrorKind::TooManyConstants,
                span: constant.name_span,
            });
        }
        if constant.ty.text == "bool" {
            let tree = constant
                .parse_initializer::<MAX_EXPRESSION_NODES>()
                .map_err(|error| SemanticError {
                    kind: SemanticErrorKind::Expression(error.kind),
                    span: Span {
                        start: constant.initializer_span.start + error.span.start,
                        end: constant.initializer_span.start + error.span.end,
                    },
                })?;
            let value = if expression_contains_call(&tree, tree.root(), 0) {
                let resolver =
                    ConstCallResolver::from_constants(&table).map_err(|kind| SemanticError {
                        kind,
                        span: constant.initializer_span,
                    })?;
                evaluate_call_aware_boolean(
                    &ConstCallContext { module, target },
                    symbol_count,
                    &tree,
                    tree.root(),
                    &resolver,
                    ConstEvalDepth::ROOT,
                )
                .map_err(|kind| SemanticError {
                    kind,
                    span: constant.initializer_span,
                })?
            } else {
                evaluate_boolean_constant(&tree, tree.root(), &table, 0).map_err(|error| {
                    SemanticError {
                        kind: SemanticErrorKind::Execution(error),
                        span: constant.initializer_span,
                    }
                })?
            };
            table.constants[table.count] = Some(Constant {
                name: constant.name,
                ty: constant.ty.text,
                value: u128::from(value),
                span: Span {
                    start: constant.name_span.start,
                    end: constant.initializer_span.end,
                },
            });
            table.count += 1;
            continue;
        }
        let Some(integer_type) = crate::IntegerType::from_name(constant.ty.text) else {
            return Err(SemanticError {
                kind: SemanticErrorKind::UnsupportedConstantType,
                span: constant.ty.span,
            });
        };
        let tree = constant
            .parse_initializer::<MAX_EXPRESSION_NODES>()
            .map_err(|error| SemanticError {
                kind: SemanticErrorKind::Expression(error.kind),
                span: Span {
                    start: constant.initializer_span.start + error.span.start,
                    end: constant.initializer_span.start + error.span.end,
                },
            })?;
        let requires_typed_evaluation = expression_contains_call(&tree, tree.root(), 0)
            || tree.nodes().iter().flatten().any(|expression| {
                matches!(
                    expression.kind,
                    ExprKind::Binary {
                        operator: BinaryOperator::ShiftLeft | BinaryOperator::ShiftRight,
                        ..
                    }
                        | ExprKind::WrappingArithmetic { .. }
                        | ExprKind::SaturatingArithmetic { .. }
                        | ExprKind::IntegerRotate { .. }
                        | ExprKind::IntegerFunnelShift { .. }
                        | ExprKind::IntegerSignCast { .. }
                        | ExprKind::IntegerWidthCast { .. }
                        | ExprKind::IntegerClampMagnitude { .. }
                        | ExprKind::IntegerEndianFrom { .. }
                        | ExprKind::IntegerFromBytes { .. }
                        | ExprKind::IntegerAssociatedConstant { .. }
                        | ExprKind::IntegerWrappingShift { .. }
                        | ExprKind::IntegerWrappingPower { .. }
                        | ExprKind::IntegerBitTransform { .. }
                        | ExprKind::IntegerUnsignedAbsolute { .. }
                        | ExprKind::IntegerPairTransform { .. }
                        | ExprKind::IntegerClamp { .. }
                        | ExprKind::IntegerBitCount { .. }
                        | ExprKind::IntegerLogarithm { .. }
                )
            });
        let call_value = if requires_typed_evaluation {
            let resolver =
                ConstCallResolver::from_constants(&table).map_err(|kind| SemanticError {
                    kind,
                    span: constant.initializer_span,
                })?;
            let context = ConstCallContext { module, target };
            Some(
                evaluate_integer_const_expression(
                    &context,
                    symbol_count,
                    &tree,
                    tree.root(),
                    integer_type,
                    &resolver,
                    ConstEvalDepth::ROOT,
                )
                .map_err(|kind| SemanticError {
                    kind: if kind
                        == SemanticErrorKind::Execution(ExecutionError::Arithmetic(
                            ConstEvalError::Overflow,
                        )) {
                        SemanticErrorKind::ConstantOutOfRange
                    } else {
                        kind
                    },
                    span: constant.initializer_span,
                })?,
            )
        } else {
            None
        };
        let value = if let Some(value) = call_value {
            value
        } else if integer_type.is_signed() {
            evaluate_signed_integer(&tree, tree.root(), integer_type, target, &table, 0).map_err(
                |error| SemanticError {
                    kind: if error == ExecutionError::Arithmetic(ConstEvalError::Overflow) {
                        SemanticErrorKind::ConstantOutOfRange
                    } else {
                        SemanticErrorKind::Execution(error)
                    },
                    span: constant.initializer_span,
                },
            )?
        } else {
            let program = lower_expression_with_pointer_bits::<
                MAX_CONSTANT_IR_INSTRUCTIONS,
                MAX_EXPRESSION_NODES,
            >(&tree, target.pointer_bits())
            .map_err(|error| SemanticError {
                kind: SemanticErrorKind::Lowering(error.kind),
                span: Span {
                    start: constant.initializer_span.start + error.span.start,
                    end: constant.initializer_span.start + error.span.end,
                },
            })?;
            program
                .execute::<_, MAX_CONSTANT_STACK_VALUES>(&table)
                .map_err(|error| SemanticError {
                    kind: SemanticErrorKind::Execution(error),
                    span: constant.initializer_span,
                })?
        };
        let in_range = if integer_type.is_signed() {
            let bits = integer_type
                .bits(target.pointer_bits())
                .ok_or(SemanticError {
                    kind: SemanticErrorKind::UnsupportedConstantType,
                    span: constant.ty.span,
                })?;
            value & signed_mask(bits) == value
        } else {
            value <= maximum_unsigned_value(constant.ty.text, target)
        };
        if !in_range {
            return Err(SemanticError {
                kind: SemanticErrorKind::ConstantOutOfRange,
                span: constant.initializer_span,
            });
        }
        table.constants[table.count] = Some(Constant {
            name: constant.name,
            ty: constant.ty.text,
            value,
            span: Span {
                start: constant.name_span.start,
                end: constant.initializer_span.end,
            },
        });
        table.count += 1;
    }
    Ok(table)
}

#[derive(Clone, Copy)]
enum ConstCallType {
    Integer(crate::IntegerType),
    Bool,
}

#[derive(Clone, Copy)]
struct ConstCallArgument<'source> {
    name: &'source str,
    ty: ConstCallType,
    value: u128,
    mutable: bool,
}

#[derive(Clone, Copy)]
struct ConstCallResolver<'source> {
    arguments: [Option<ConstCallArgument<'source>>; MAX_CONST_CALL_BINDINGS],
    count: usize,
    constant_count: usize,
}

impl<'source> ConstCallResolver<'source> {
    fn from_constants<const MAX_CONSTANTS: usize>(
        constants: &ConstantTable<'source, MAX_CONSTANTS>,
    ) -> Result<Self, SemanticErrorKind> {
        let mut resolver = Self {
            arguments: [None; MAX_CONST_CALL_BINDINGS],
            count: 0,
            constant_count: 0,
        };
        for constant in constants.constants().iter().flatten() {
            let ty = if constant.ty == "bool" {
                ConstCallType::Bool
            } else if let Some(ty) = crate::IntegerType::from_name(constant.ty) {
                ConstCallType::Integer(ty)
            } else {
                continue;
            };
            resolver.push(ConstCallArgument {
                name: constant.name,
                ty,
                value: constant.value,
                mutable: false,
            })?;
        }
        resolver.constant_count = resolver.count;
        Ok(resolver)
    }

    fn push(&mut self, argument: ConstCallArgument<'source>) -> Result<(), SemanticErrorKind> {
        if self.count == MAX_CONST_CALL_BINDINGS {
            return Err(SemanticErrorKind::UnsupportedConstCall);
        }
        self.arguments[self.count] = Some(argument);
        self.count += 1;
        Ok(())
    }

    fn binding(&self, name: &str) -> Option<ConstCallArgument<'source>> {
        self.arguments[..self.count]
            .iter()
            .rev()
            .flatten()
            .find(|argument| argument.name == name)
            .copied()
    }

    fn has_nonconstant_binding(&self, name: &str) -> bool {
        self.arguments[self.constant_count..self.count]
            .iter()
            .flatten()
            .any(|argument| argument.name == name)
    }

    fn has_module_constant(&self, name: &str) -> bool {
        self.arguments[..self.constant_count]
            .iter()
            .rev()
            .flatten()
            .any(|argument| argument.name == name)
    }

    fn assign(&mut self, name: &str, value: u128) -> Result<(), SemanticErrorKind> {
        let binding = self.arguments[..self.count]
            .iter_mut()
            .rev()
            .flatten()
            .find(|argument| argument.name == name)
            .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
        if !binding.mutable {
            return Err(SemanticErrorKind::UnsupportedConstCall);
        }
        binding.value = value;
        Ok(())
    }

    fn truncate(&mut self, count: usize) -> Result<(), SemanticErrorKind> {
        if count < self.constant_count || count > self.count {
            return Err(SemanticErrorKind::UnsupportedConstCall);
        }
        for argument in &mut self.arguments[count..self.count] {
            *argument = None;
        }
        self.count = count;
        Ok(())
    }
}

impl ConstantResolver for ConstCallResolver<'_> {
    fn resolve(&self, name: &str) -> Option<u128> {
        self.arguments[..self.count]
            .iter()
            .rev()
            .flatten()
            .find(|argument| argument.name == name)
            .map(|argument| argument.value)
    }

    fn resolve_type(&self, name: &str) -> Option<crate::IntegerType> {
        self.arguments[..self.count]
            .iter()
            .rev()
            .flatten()
            .find(|argument| argument.name == name)
            .and_then(|argument| match argument.ty {
                ConstCallType::Integer(ty) => Some(ty),
                ConstCallType::Bool => None,
            })
    }

    fn resolves_bool(&self, name: &str) -> bool {
        self.arguments[..self.count]
            .iter()
            .rev()
            .flatten()
            .find(|argument| argument.name == name)
            .is_some_and(|argument| matches!(argument.ty, ConstCallType::Bool))
    }
}

struct ConstCallContext<'module, 'source, const MAX_ITEMS: usize, const MAX_PARAMETERS: usize> {
    module: &'module Module<'source, MAX_ITEMS, MAX_PARAMETERS>,
    target: TargetLayout,
}

pub(crate) fn evaluate_scalar_const_function<
    'source,
    const MAX_CONSTANTS: usize,
    const MAX_ITEMS: usize,
    const MAX_PARAMETERS: usize,
>(
    module: &Module<'source, MAX_ITEMS, MAX_PARAMETERS>,
    constants: &ConstantTable<'source, MAX_CONSTANTS>,
    target: TargetLayout,
    name: &str,
    arguments: &[u128],
) -> Option<u128> {
    let (index, function) =
        module
            .items()
            .iter()
            .enumerate()
            .find_map(|(index, item)| match item.as_ref()? {
                Item::Function(function) if function.name == name => Some((index, function)),
                _ => None,
            })?;
    if !function.constant
        || function.abi != crate::FunctionAbi::Rust
        || function.parameter_count() != arguments.len()
    {
        return None;
    }
    let context = ConstCallContext { module, target };
    let mut resolver = ConstCallResolver::from_constants(constants).ok()?;
    for (parameter, value) in function.parameters().iter().flatten().zip(arguments) {
        let (ty, value) = if parameter.ty.text == "bool" {
            if *value > 1 {
                return None;
            }
            (ConstCallType::Bool, *value)
        } else {
            let ty = crate::IntegerType::from_name(parameter.ty.text)?;
            let bits = ty.bits(target.pointer_bits())?;
            let mask = signed_mask(bits);
            let raw = *value;
            let value = raw & mask;
            if ty.is_signed() {
                let sign_extended = if value & (1u128 << (bits - 1)) != 0 {
                    value | !mask
                } else {
                    value
                };
                if raw != value && raw != sign_extended {
                    return None;
                }
            } else if raw != value {
                return None;
            }
            (ConstCallType::Integer(ty), value)
        };
        resolver
            .push(ConstCallArgument {
                name: parameter.name,
                ty,
                value,
                mutable: false,
            })
            .ok()?;
    }
    let symbol_count = index.checked_add(1)?;
    if function
        .return_type
        .is_some_and(|return_type| return_type.text == "bool")
    {
        let value = evaluate_boolean_const_function_body(
            &context,
            symbol_count,
            function,
            &mut resolver,
            ConstEvalDepth::ROOT.enter_call().ok()?,
        )
        .ok()?;
        return Some(u128::from(value));
    }
    let ty = function
        .return_type
        .and_then(|return_type| crate::IntegerType::from_name(return_type.text))?;
    let value = evaluate_integer_const_function_body(
        &context,
        symbol_count,
        function,
        ty,
        &mut resolver,
        ConstEvalDepth::ROOT.enter_call().ok()?,
    )
    .ok()?;
    Some(value)
}

#[derive(Clone, Copy)]
struct ConstEvalDepth {
    calls: usize,
    expressions: usize,
}

impl ConstEvalDepth {
    const ROOT: Self = Self {
        calls: 0,
        expressions: 0,
    };

    fn enter_call(self) -> Result<Self, SemanticErrorKind> {
        if self.calls == MAX_CONST_CALL_DEPTH {
            Err(SemanticErrorKind::UnsupportedConstCall)
        } else {
            Ok(Self {
                calls: self.calls + 1,
                expressions: self.expressions,
            })
        }
    }

    fn enter_expression(self) -> Result<Self, SemanticErrorKind> {
        if self.expressions == 64 {
            Err(SemanticErrorKind::Execution(ExecutionError::Arithmetic(
                ConstEvalError::NestingLimitExceeded,
            )))
        } else {
            Ok(Self {
                calls: self.calls,
                expressions: self.expressions + 1,
            })
        }
    }
}

fn evaluate_integer_const_call<
    const MAX_EXPRESSION_NODES: usize,
    const MAX_ITEMS: usize,
    const MAX_PARAMETERS: usize,
>(
    context: &ConstCallContext<'_, '_, MAX_ITEMS, MAX_PARAMETERS>,
    symbol_count: usize,
    call_tree: &ExpressionTree<'_, MAX_EXPRESSION_NODES>,
    call_id: ExprId,
    declared_type: crate::IntegerType,
    constants: &ConstCallResolver<'_>,
    depth: ConstEvalDepth,
) -> Result<u128, SemanticErrorKind> {
    let depth = depth.enter_call()?;
    let Some(ExprKind::Call {
        callee,
        arguments,
        argument_count,
    }) = call_tree
        .expression(call_id)
        .map(|expression| expression.kind)
    else {
        return Err(SemanticErrorKind::UnsupportedConstCall);
    };
    let (function_index, function) = context.module.items()[..symbol_count]
        .iter()
        .enumerate()
        .find_map(|(index, item)| match item.as_ref()? {
            Item::Function(function) if function.name == callee => Some((index, function)),
            _ => None,
        })
        .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
    let return_type = function
        .return_type
        .and_then(|return_type| crate::IntegerType::from_name(return_type.text))
        .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
    if !function.constant
        || function.abi != crate::FunctionAbi::Rust
        || function.parameter_count() != argument_count
        || return_type != declared_type
    {
        return Err(SemanticErrorKind::UnsupportedConstCall);
    }
    let mut values = [None; MAX_PARAMETERS];
    for (index, parameter) in function.parameters().iter().flatten().enumerate() {
        let argument = arguments[index].ok_or(SemanticErrorKind::UnsupportedConstCall)?;
        let (ty, value, in_range) = if parameter.ty.text == "bool" {
            let value = evaluate_boolean_const_expression(
                context,
                symbol_count,
                call_tree,
                argument,
                constants,
                depth,
            )?;
            (ConstCallType::Bool, u128::from(value), true)
        } else {
            let ty = crate::IntegerType::from_name(parameter.ty.text)
                .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
            let value = evaluate_integer_const_expression(
                context,
                symbol_count,
                call_tree,
                argument,
                ty,
                constants,
                depth,
            )?;
            let in_range = if ty.is_signed() {
                let bits = ty
                    .bits(context.target.pointer_bits())
                    .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
                value & signed_mask(bits) == value
            } else {
                value <= maximum_unsigned_value(ty.name(), context.target)
            };
            (ConstCallType::Integer(ty), value, in_range)
        };
        if !in_range {
            return Err(SemanticErrorKind::ConstantOutOfRange);
        }
        values[index] = Some(ConstCallArgument {
            name: parameter.name,
            ty,
            value,
            mutable: false,
        });
    }
    let mut resolver = *constants;
    for value in values[..argument_count].iter().flatten() {
        resolver.push(*value)?;
    }
    let body_symbol_count = function_index
        .checked_add(1)
        .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
    let value = evaluate_integer_const_function_body::<MAX_ITEMS, MAX_PARAMETERS>(
        context,
        body_symbol_count,
        function,
        return_type,
        &mut resolver,
        depth,
    )?;
    if !return_type.is_signed()
        && value > maximum_unsigned_value(return_type.name(), context.target)
    {
        return Err(SemanticErrorKind::ConstantOutOfRange);
    }
    Ok(value)
}

fn evaluate_boolean_const_call<
    const MAX_EXPRESSION_NODES: usize,
    const MAX_ITEMS: usize,
    const MAX_PARAMETERS: usize,
>(
    context: &ConstCallContext<'_, '_, MAX_ITEMS, MAX_PARAMETERS>,
    symbol_count: usize,
    call_tree: &ExpressionTree<'_, MAX_EXPRESSION_NODES>,
    call_id: ExprId,
    constants: &ConstCallResolver<'_>,
    depth: ConstEvalDepth,
) -> Result<bool, SemanticErrorKind> {
    let depth = depth.enter_call()?;
    let Some(ExprKind::Call {
        callee,
        arguments,
        argument_count,
    }) = call_tree
        .expression(call_id)
        .map(|expression| expression.kind)
    else {
        return Err(SemanticErrorKind::UnsupportedConstCall);
    };
    let (function_index, function) = context.module.items()[..symbol_count]
        .iter()
        .enumerate()
        .find_map(|(index, item)| match item.as_ref()? {
            Item::Function(function) if function.name == callee => Some((index, function)),
            _ => None,
        })
        .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
    if !function.constant
        || function.abi != crate::FunctionAbi::Rust
        || function.parameter_count() != argument_count
        || !function
            .return_type
            .is_some_and(|return_type| return_type.text == "bool")
    {
        return Err(SemanticErrorKind::UnsupportedConstCall);
    }
    let mut values = [None; MAX_PARAMETERS];
    for (index, parameter) in function.parameters().iter().flatten().enumerate() {
        let argument = arguments[index].ok_or(SemanticErrorKind::UnsupportedConstCall)?;
        let (ty, value) = if parameter.ty.text == "bool" {
            (
                ConstCallType::Bool,
                u128::from(evaluate_boolean_const_expression(
                    context,
                    symbol_count,
                    call_tree,
                    argument,
                    constants,
                    depth,
                )?),
            )
        } else {
            let ty = crate::IntegerType::from_name(parameter.ty.text)
                .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
            let value = evaluate_integer_const_expression(
                context,
                symbol_count,
                call_tree,
                argument,
                ty,
                constants,
                depth,
            )?;
            let in_range = if ty.is_signed() {
                let bits = ty
                    .bits(context.target.pointer_bits())
                    .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
                value & signed_mask(bits) == value
            } else {
                value <= maximum_unsigned_value(ty.name(), context.target)
            };
            if !in_range {
                return Err(SemanticErrorKind::ConstantOutOfRange);
            }
            (ConstCallType::Integer(ty), value)
        };
        values[index] = Some(ConstCallArgument {
            name: parameter.name,
            ty,
            value,
            mutable: false,
        });
    }
    let mut resolver = *constants;
    for value in values[..argument_count].iter().flatten() {
        resolver.push(*value)?;
    }
    let body_symbol_count = function_index
        .checked_add(1)
        .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
    evaluate_boolean_const_function_body::<MAX_ITEMS, MAX_PARAMETERS>(
        context,
        body_symbol_count,
        function,
        &mut resolver,
        depth,
    )
}

fn evaluate_integer_const_function_body<
    'source,
    const MAX_ITEMS: usize,
    const MAX_PARAMETERS: usize,
>(
    context: &ConstCallContext<'_, 'source, MAX_ITEMS, MAX_PARAMETERS>,
    symbol_count: usize,
    function: &crate::Function<'source, MAX_PARAMETERS>,
    return_type: crate::IntegerType,
    resolver: &mut ConstCallResolver<'source>,
    depth: ConstEvalDepth,
) -> Result<u128, SemanticErrorKind> {
    let body = function
        .parse_body::<MAX_PARAMETERS>()
        .map_err(|_| SemanticErrorKind::UnsupportedConstCall)?;
    if let Some(value) = evaluate_const_body_statements(
        context,
        symbol_count,
        &body,
        ConstCallType::Integer(return_type),
        resolver,
        depth,
    )? {
        return Ok(value);
    }
    if body.tail_diverges {
        return Err(SemanticErrorKind::UnsupportedConstCall);
    }
    let tail = body
        .parse_tail::<MAX_CONST_FUNCTION_EXPRESSION_NODES>()
        .map_err(|error| SemanticErrorKind::Expression(error.kind))?;
    evaluate_integer_const_expression(
        context,
        symbol_count,
        &tail,
        tail.root(),
        return_type,
        resolver,
        depth,
    )
}

fn evaluate_boolean_const_function_body<
    'source,
    const MAX_ITEMS: usize,
    const MAX_PARAMETERS: usize,
>(
    context: &ConstCallContext<'_, 'source, MAX_ITEMS, MAX_PARAMETERS>,
    symbol_count: usize,
    function: &crate::Function<'source, MAX_PARAMETERS>,
    resolver: &mut ConstCallResolver<'source>,
    depth: ConstEvalDepth,
) -> Result<bool, SemanticErrorKind> {
    let body = function
        .parse_body::<MAX_PARAMETERS>()
        .map_err(|_| SemanticErrorKind::UnsupportedConstCall)?;
    if let Some(value) = evaluate_const_body_statements(
        context,
        symbol_count,
        &body,
        ConstCallType::Bool,
        resolver,
        depth,
    )? {
        return Ok(value != 0);
    }
    if body.tail_diverges {
        return Err(SemanticErrorKind::UnsupportedConstCall);
    }
    let tail = body
        .parse_tail::<MAX_CONST_FUNCTION_EXPRESSION_NODES>()
        .map_err(|error| SemanticErrorKind::Expression(error.kind))?;
    evaluate_boolean_const_expression(context, symbol_count, &tail, tail.root(), resolver, depth)
}

fn evaluate_const_body_statements<'source, const MAX_ITEMS: usize, const MAX_PARAMETERS: usize>(
    context: &ConstCallContext<'_, 'source, MAX_ITEMS, MAX_PARAMETERS>,
    symbol_count: usize,
    body: &crate::FunctionBody<'source, MAX_PARAMETERS>,
    return_type: ConstCallType,
    resolver: &mut ConstCallResolver<'source>,
    depth: ConstEvalDepth,
) -> Result<Option<u128>, SemanticErrorKind> {
    for statement in body.statements().iter().flatten() {
        match statement {
            crate::BodyStatement::Local(index) => {
                let local = body.locals()[*index]
                    .as_ref()
                    .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
                evaluate_const_local(context, symbol_count, local, resolver, depth)?;
            }
            crate::BodyStatement::Assignment(index) => {
                let assignment = body.assignments()[*index]
                    .as_ref()
                    .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
                evaluate_const_assignment(context, symbol_count, assignment, resolver, depth)?;
            }
            crate::BodyStatement::ConditionalReturn(index) => {
                let conditional = body.conditional_returns()[*index]
                    .as_ref()
                    .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
                let condition = conditional
                    .parse_condition::<MAX_CONST_FUNCTION_EXPRESSION_NODES>()
                    .map_err(|error| SemanticErrorKind::Expression(error.kind))?;
                if evaluate_boolean_const_expression(
                    context,
                    symbol_count,
                    &condition,
                    condition.root(),
                    resolver,
                    depth,
                )? {
                    let value = conditional
                        .parse_value::<MAX_CONST_FUNCTION_EXPRESSION_NODES>()
                        .map_err(|error| SemanticErrorKind::Expression(error.kind))?;
                    return Ok(Some(match return_type {
                        ConstCallType::Bool => u128::from(evaluate_boolean_const_expression(
                            context,
                            symbol_count,
                            &value,
                            value.root(),
                            resolver,
                            depth,
                        )?),
                        ConstCallType::Integer(ty) => evaluate_integer_const_expression(
                            context,
                            symbol_count,
                            &value,
                            value.root(),
                            ty,
                            resolver,
                            depth,
                        )?,
                    }));
                }
            }
            crate::BodyStatement::ConditionalReturnElse(index) => {
                let conditional = body.conditional_return_elses()[*index]
                    .as_ref()
                    .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
                let mut selected = None;
                for branch in conditional.branches().iter().flatten() {
                    let condition = branch
                        .parse_condition::<MAX_CONST_FUNCTION_EXPRESSION_NODES>()
                        .map_err(|error| SemanticErrorKind::Expression(error.kind))?;
                    if evaluate_boolean_const_expression(
                        context,
                        symbol_count,
                        &condition,
                        condition.root(),
                        resolver,
                        depth,
                    )? {
                        selected = Some(crate::LoopReturn {
                            value: branch.value,
                            value_span: branch.value_span,
                        });
                        break;
                    }
                }
                let selected = match selected.as_ref().or(conditional.else_value.as_ref()) {
                    Some(selected) => selected,
                    None => continue,
                };
                let value = selected
                    .parse_value::<MAX_CONST_FUNCTION_EXPRESSION_NODES>()
                    .map_err(|error| SemanticErrorKind::Expression(error.kind))?;
                return Ok(Some(match return_type {
                    ConstCallType::Bool => u128::from(evaluate_boolean_const_expression(
                        context,
                        symbol_count,
                        &value,
                        value.root(),
                        resolver,
                        depth,
                    )?),
                    ConstCallType::Integer(ty) => evaluate_integer_const_expression(
                        context,
                        symbol_count,
                        &value,
                        value.root(),
                        ty,
                        resolver,
                        depth,
                    )?,
                }));
            }
            crate::BodyStatement::ConditionalAssignment(index) => {
                let conditional = body.conditional_assignments()[*index]
                    .as_ref()
                    .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
                let mut selected = false;
                for branch in conditional.branches().iter().flatten() {
                    let condition = branch
                        .parse_condition::<MAX_CONST_FUNCTION_EXPRESSION_NODES>()
                        .map_err(|error| SemanticErrorKind::Expression(error.kind))?;
                    if evaluate_boolean_const_expression(
                        context,
                        symbol_count,
                        &condition,
                        condition.root(),
                        resolver,
                        depth,
                    )? {
                        let binding_checkpoint = resolver.count;
                        for action in branch.actions().iter().flatten() {
                            match action {
                                crate::ConditionalAssignmentAction::Local(local) => {
                                    evaluate_const_local(
                                        context,
                                        symbol_count,
                                        local,
                                        resolver,
                                        depth,
                                    )?;
                                }
                                crate::ConditionalAssignmentAction::Assignment(assignment) => {
                                    evaluate_const_assignment(
                                        context,
                                        symbol_count,
                                        assignment,
                                        resolver,
                                        depth,
                                    )?;
                                }
                                crate::ConditionalAssignmentAction::Expression(statement) => {
                                    evaluate_const_expression_statement(
                                        context,
                                        symbol_count,
                                        statement,
                                        resolver,
                                        depth,
                                    )?;
                                }
                                crate::ConditionalAssignmentAction::Return(return_statement) => {
                                    return Ok(Some(evaluate_const_return_statement(
                                        context,
                                        symbol_count,
                                        return_statement,
                                        return_type,
                                        resolver,
                                        depth,
                                    )?));
                                }
                            }
                        }
                        resolver.truncate(binding_checkpoint)?;
                        selected = true;
                        break;
                    }
                }
                if !selected {
                    let binding_checkpoint = resolver.count;
                    for action in conditional.else_actions().iter().flatten() {
                        match action {
                            crate::ConditionalAssignmentAction::Local(local) => {
                                evaluate_const_local(
                                    context,
                                    symbol_count,
                                    local,
                                    resolver,
                                    depth,
                                )?;
                            }
                            crate::ConditionalAssignmentAction::Assignment(assignment) => {
                                evaluate_const_assignment(
                                    context,
                                    symbol_count,
                                    assignment,
                                    resolver,
                                    depth,
                                )?;
                            }
                            crate::ConditionalAssignmentAction::Expression(statement) => {
                                evaluate_const_expression_statement(
                                    context,
                                    symbol_count,
                                    statement,
                                    resolver,
                                    depth,
                                )?;
                            }
                            crate::ConditionalAssignmentAction::Return(return_statement) => {
                                return Ok(Some(evaluate_const_return_statement(
                                    context,
                                    symbol_count,
                                    return_statement,
                                    return_type,
                                    resolver,
                                    depth,
                                )?));
                            }
                        }
                    }
                    resolver.truncate(binding_checkpoint)?;
                }
            }
            crate::BodyStatement::Loop(index) => {
                let loop_statement = body.while_loops()[*index]
                    .as_ref()
                    .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
                if let Some(value) = evaluate_const_loop(
                    context,
                    symbol_count,
                    loop_statement,
                    return_type,
                    resolver,
                    depth,
                )? {
                    return Ok(Some(value));
                }
            }
            crate::BodyStatement::Expression(index) => {
                let statement = body.expression_statements()[*index]
                    .as_ref()
                    .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
                evaluate_const_expression_statement(
                    context,
                    symbol_count,
                    statement,
                    resolver,
                    depth,
                )?;
            }
            crate::BodyStatement::Return(index) => {
                let return_statement = body.returns()[*index]
                    .as_ref()
                    .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
                let value = return_statement
                    .parse_value::<MAX_CONST_FUNCTION_EXPRESSION_NODES>()
                    .map_err(|error| SemanticErrorKind::Expression(error.kind))?;
                return Ok(Some(match return_type {
                    ConstCallType::Bool => u128::from(evaluate_boolean_const_expression(
                        context,
                        symbol_count,
                        &value,
                        value.root(),
                        resolver,
                        depth,
                    )?),
                    ConstCallType::Integer(ty) => evaluate_integer_const_expression(
                        context,
                        symbol_count,
                        &value,
                        value.root(),
                        ty,
                        resolver,
                        depth,
                    )?,
                }));
            }
        }
    }
    Ok(None)
}

fn evaluate_const_expression_statement<
    'source,
    const MAX_ITEMS: usize,
    const MAX_PARAMETERS: usize,
>(
    context: &ConstCallContext<'_, 'source, MAX_ITEMS, MAX_PARAMETERS>,
    symbol_count: usize,
    statement: &crate::ExpressionStatement<'source>,
    resolver: &mut ConstCallResolver<'source>,
    depth: ConstEvalDepth,
) -> Result<(), SemanticErrorKind> {
    if statement.expression.is_empty() {
        return Ok(());
    }
    let tree = statement
        .parse::<MAX_CONST_FUNCTION_EXPRESSION_NODES>()
        .map_err(|error| SemanticErrorKind::Expression(error.kind))?;
    if tree.is_boolean_expression(tree.root(), 0) {
        evaluate_boolean_const_expression(
            context,
            symbol_count,
            &tree,
            tree.root(),
            resolver,
            depth,
        )?;
    } else if matches!(
        tree.expression(tree.root())
            .map(|expression| expression.kind),
        Some(ExprKind::Unit)
    ) {
        tree.evaluate(resolver)
            .map_err(|error| SemanticErrorKind::Execution(ExecutionError::Arithmetic(error)))?;
    } else {
        let ty = integer_expression_type(context, symbol_count, &tree, tree.root(), resolver)
            .unwrap_or(crate::IntegerType::I32);
        evaluate_integer_const_expression(
            context,
            symbol_count,
            &tree,
            tree.root(),
            ty,
            resolver,
            depth,
        )?;
    }
    Ok(())
}

fn evaluate_const_return_statement<'source, const MAX_ITEMS: usize, const MAX_PARAMETERS: usize>(
    context: &ConstCallContext<'_, 'source, MAX_ITEMS, MAX_PARAMETERS>,
    symbol_count: usize,
    return_statement: &crate::LoopReturn<'source>,
    return_type: ConstCallType,
    resolver: &mut ConstCallResolver<'source>,
    depth: ConstEvalDepth,
) -> Result<u128, SemanticErrorKind> {
    let value = return_statement
        .parse_value::<MAX_CONST_FUNCTION_EXPRESSION_NODES>()
        .map_err(|error| SemanticErrorKind::Expression(error.kind))?;
    match return_type {
        ConstCallType::Bool => Ok(u128::from(evaluate_boolean_const_expression(
            context,
            symbol_count,
            &value,
            value.root(),
            resolver,
            depth,
        )?)),
        ConstCallType::Integer(ty) => evaluate_integer_const_expression(
            context,
            symbol_count,
            &value,
            value.root(),
            ty,
            resolver,
            depth,
        ),
    }
}

fn evaluate_const_local<'source, const MAX_ITEMS: usize, const MAX_PARAMETERS: usize>(
    context: &ConstCallContext<'_, 'source, MAX_ITEMS, MAX_PARAMETERS>,
    symbol_count: usize,
    local: &crate::LocalBinding<'source>,
    resolver: &mut ConstCallResolver<'source>,
    depth: ConstEvalDepth,
) -> Result<(), SemanticErrorKind> {
    let tree = local
        .parse_initializer::<MAX_CONST_FUNCTION_EXPRESSION_NODES>()
        .map_err(|error| SemanticErrorKind::Expression(error.kind))?;
    let ty = match local.ty.map(|ty| ty.text) {
        Some("bool") => ConstCallType::Bool,
        Some(name) => ConstCallType::Integer(
            crate::IntegerType::from_name(name).ok_or(SemanticErrorKind::UnsupportedConstCall)?,
        ),
        None if tree.is_boolean_expression(tree.root(), 0) => ConstCallType::Bool,
        None => ConstCallType::Integer(
            integer_expression_type(context, symbol_count, &tree, tree.root(), resolver)
                .unwrap_or(crate::IntegerType::I32),
        ),
    };
    let value = match ty {
        ConstCallType::Bool => u128::from(evaluate_boolean_const_expression(
            context,
            symbol_count,
            &tree,
            tree.root(),
            resolver,
            depth,
        )?),
        ConstCallType::Integer(ty) => evaluate_integer_const_expression(
            context,
            symbol_count,
            &tree,
            tree.root(),
            ty,
            resolver,
            depth,
        )?,
    };
    if local.name == "_" {
        Ok(())
    } else {
        resolver.push(ConstCallArgument {
            name: local.name,
            ty,
            value,
            mutable: local.mutable,
        })
    }
}

fn evaluate_const_assignment<'source, const MAX_ITEMS: usize, const MAX_PARAMETERS: usize>(
    context: &ConstCallContext<'_, 'source, MAX_ITEMS, MAX_PARAMETERS>,
    symbol_count: usize,
    assignment: &crate::Assignment<'source>,
    resolver: &mut ConstCallResolver<'source>,
    depth: ConstEvalDepth,
) -> Result<(), SemanticErrorKind> {
    if assignment.index().is_some() {
        return Err(SemanticErrorKind::UnsupportedConstCall);
    }
    if assignment.binding_name() == "_" {
        if assignment.operator != crate::AssignmentOperator::Assign {
            return Err(SemanticErrorKind::UnsupportedConstCall);
        }
        let tree = assignment
            .parse_value::<MAX_CONST_FUNCTION_EXPRESSION_NODES>()
            .map_err(|error| SemanticErrorKind::Expression(error.kind))?;
        if tree.is_boolean_expression(tree.root(), 0) {
            evaluate_boolean_const_expression(
                context,
                symbol_count,
                &tree,
                tree.root(),
                resolver,
                depth,
            )?;
        } else {
            let ty = integer_expression_type(context, symbol_count, &tree, tree.root(), resolver)
                .unwrap_or(crate::IntegerType::I32);
            evaluate_integer_const_expression(
                context,
                symbol_count,
                &tree,
                tree.root(),
                ty,
                resolver,
                depth,
            )?;
        }
        return Ok(());
    }
    let binding = resolver
        .binding(assignment.binding_name())
        .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
    if !binding.mutable {
        return Err(SemanticErrorKind::UnsupportedConstCall);
    }
    let tree = assignment
        .parse_value::<MAX_CONST_FUNCTION_EXPRESSION_NODES>()
        .map_err(|error| SemanticErrorKind::Expression(error.kind))?;
    let value = match binding.ty {
        ConstCallType::Bool => {
            let right = evaluate_boolean_const_expression(
                context,
                symbol_count,
                &tree,
                tree.root(),
                resolver,
                depth,
            )?;
            let left = binding.value != 0;
            u128::from(match assignment.operator {
                crate::AssignmentOperator::Assign => right,
                crate::AssignmentOperator::BitAnd => left && right,
                crate::AssignmentOperator::BitOr => left || right,
                crate::AssignmentOperator::BitXor => left != right,
                _ => return Err(SemanticErrorKind::UnsupportedConstCall),
            })
        }
        ConstCallType::Integer(ty) => {
            let right_type = if matches!(
                assignment.operator,
                crate::AssignmentOperator::ShiftLeft | crate::AssignmentOperator::ShiftRight
            ) {
                integer_expression_type(context, symbol_count, &tree, tree.root(), resolver)
                    .unwrap_or(ty)
            } else {
                ty
            };
            let right = evaluate_integer_const_expression(
                context,
                symbol_count,
                &tree,
                tree.root(),
                right_type,
                resolver,
                depth,
            )?;
            if assignment.operator == crate::AssignmentOperator::Assign {
                right
            } else {
                let operator = match assignment.operator {
                    crate::AssignmentOperator::Add => BinaryOperator::Add,
                    crate::AssignmentOperator::Subtract => BinaryOperator::Subtract,
                    crate::AssignmentOperator::Multiply => BinaryOperator::Multiply,
                    crate::AssignmentOperator::Divide => BinaryOperator::Divide,
                    crate::AssignmentOperator::Remainder => BinaryOperator::Remainder,
                    crate::AssignmentOperator::BitAnd => BinaryOperator::BitAnd,
                    crate::AssignmentOperator::BitOr => BinaryOperator::BitOr,
                    crate::AssignmentOperator::BitXor => BinaryOperator::BitXor,
                    crate::AssignmentOperator::ShiftLeft => BinaryOperator::ShiftLeft,
                    crate::AssignmentOperator::ShiftRight => BinaryOperator::ShiftRight,
                    crate::AssignmentOperator::Assign => BinaryOperator::Add,
                };
                let bits = ty
                    .bits(context.target.pointer_bits())
                    .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
                if ty.is_signed() {
                    evaluate_call_aware_signed_binary(operator, binding.value, right, bits)
                } else {
                    evaluate_call_aware_unsigned_binary(operator, binding.value, right, bits)
                }
                .map_err(|error| SemanticErrorKind::Execution(ExecutionError::Arithmetic(error)))?
            }
        }
    };
    resolver.assign(assignment.binding_name(), value)
}

fn evaluate_const_loop<'source, const MAX_ITEMS: usize, const MAX_PARAMETERS: usize>(
    context: &ConstCallContext<'_, 'source, MAX_ITEMS, MAX_PARAMETERS>,
    symbol_count: usize,
    loop_statement: &crate::WhileLoop<'source>,
    return_type: ConstCallType,
    resolver: &mut ConstCallResolver<'source>,
    depth: ConstEvalDepth,
) -> Result<Option<u128>, SemanticErrorKind> {
    let condition = loop_statement
        .parse_condition::<MAX_CONST_FUNCTION_EXPRESSION_NODES>()
        .map_err(|error| SemanticErrorKind::Expression(error.kind))?;
    let mut iterations = 0usize;
    loop {
        if let Some(condition) = condition.as_ref()
            && !evaluate_boolean_const_expression(
                context,
                symbol_count,
                condition,
                condition.root(),
                resolver,
                depth,
            )?
        {
            break;
        }
        if iterations == MAX_CONST_LOOP_ITERATIONS {
            return Err(SemanticErrorKind::ConstLoopLimitExceeded);
        }
        iterations = iterations
            .checked_add(1)
            .ok_or(SemanticErrorKind::ConstLoopLimitExceeded)?;
        let binding_checkpoint = resolver.count;
        let mut break_loop = false;
        let mut continue_loop = false;
        for operation in loop_statement.operations().iter().flatten() {
            match operation {
                crate::LoopOperation::Local(local) => {
                    evaluate_const_local(context, symbol_count, local, resolver, depth)?;
                }
                crate::LoopOperation::Assignment(assignment) => {
                    evaluate_const_assignment(context, symbol_count, assignment, resolver, depth)?;
                }
                crate::LoopOperation::Expression(statement) => {
                    evaluate_const_expression_statement(
                        context,
                        symbol_count,
                        statement,
                        resolver,
                        depth,
                    )?;
                }
                crate::LoopOperation::NestedUnitLoop => {}
                crate::LoopOperation::NestedBlock(index) => {
                    let block = loop_statement.nested_blocks()[*index]
                        .as_ref()
                        .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
                    let mut nested_iterations = 0usize;
                    'nested: loop {
                        if nested_iterations == MAX_CONST_LOOP_ITERATIONS {
                            return Err(SemanticErrorKind::ConstLoopLimitExceeded);
                        }
                        nested_iterations += 1;
                        if let Some(condition) = block.entry_condition {
                            let tree = condition
                                .parse_condition::<MAX_CONST_FUNCTION_EXPRESSION_NODES>()
                                .map_err(|error| SemanticErrorKind::Expression(error.kind))?;
                            if !evaluate_boolean_const_expression(
                                context,
                                symbol_count,
                                &tree,
                                tree.root(),
                                resolver,
                                depth,
                            )? {
                                break;
                            }
                        }
                        let nested_checkpoint = resolver.count;
                        for action_index in 0..=block.action_count() {
                            let control_count = block
                                .conditional_blocks()
                                .len()
                                .checked_add(block.conditional_returns().len())
                                .and_then(|count| {
                                    count.checked_add(block.conditional_continues().len())
                                })
                                .and_then(|count| {
                                    count.checked_add(block.conditional_breaks().len())
                                })
                                .and_then(|count| {
                                    count.checked_add(block.unconditional_controls().len())
                                })
                                .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
                            for control_order in 0..control_count {
                                for ((branch, branch_action_index), branch_control_order) in block
                                    .conditional_blocks()
                                    .iter()
                                    .flatten()
                                    .zip(block.conditional_block_action_indices())
                                    .zip(block.conditional_block_control_orders())
                                {
                                    if action_index != *branch_action_index
                                        || control_order != *branch_control_order
                                    {
                                        continue;
                                    }
                                    let condition = branch
                                        .parse_condition::<MAX_CONST_FUNCTION_EXPRESSION_NODES>()
                                        .map_err(|error| {
                                            SemanticErrorKind::Expression(error.kind)
                                        })?;
                                    let condition_is_true = evaluate_boolean_const_expression(
                                        context,
                                        symbol_count,
                                        &condition,
                                        condition.root(),
                                        resolver,
                                        depth,
                                    )?;
                                    let selected = if condition_is_true {
                                        Some((branch.actions(), branch.terminal))
                                    } else {
                                        let mut selected = None;
                                        for else_arm in branch.else_arms().iter().flatten() {
                                            if let Some(condition) = else_arm
                                                .parse_condition::<
                                                    MAX_CONST_FUNCTION_EXPRESSION_NODES,
                                                >()
                                                .map_err(|error| {
                                                    SemanticErrorKind::Expression(error.kind)
                                                })?
                                            {
                                                if !evaluate_boolean_const_expression(
                                                    context,
                                                    symbol_count,
                                                    &condition,
                                                    condition.root(),
                                                    resolver,
                                                    depth,
                                                )? {
                                                    continue;
                                                }
                                            }
                                            selected =
                                                Some((else_arm.actions(), else_arm.terminal));
                                            break;
                                        }
                                        selected
                                    };
                                    let Some((selected_actions, selected_terminal)) = selected
                                    else {
                                        continue;
                                    };
                                    let branch_checkpoint = resolver.count;
                                    for action in selected_actions.iter().flatten() {
                                        match action {
                                            crate::ConditionalLoopAction::Local(local) => {
                                                evaluate_const_local(
                                                    context,
                                                    symbol_count,
                                                    local,
                                                    resolver,
                                                    depth,
                                                )?;
                                            }
                                            crate::ConditionalLoopAction::Assignment(
                                                assignment,
                                            ) => {
                                                evaluate_const_assignment(
                                                    context,
                                                    symbol_count,
                                                    assignment,
                                                    resolver,
                                                    depth,
                                                )?;
                                            }
                                            crate::ConditionalLoopAction::Expression(statement) => {
                                                evaluate_const_expression_statement(
                                                    context,
                                                    symbol_count,
                                                    statement,
                                                    resolver,
                                                    depth,
                                                )?;
                                            }
                                        }
                                    }
                                    match selected_terminal {
                                        crate::NestedLoopUnconditionalControl::Break(target) => {
                                            resolver.truncate(branch_checkpoint)?;
                                            resolver.truncate(nested_checkpoint)?;
                                            if target == crate::NestedLoopControlTarget::Outer {
                                                break_loop = true;
                                            }
                                            break 'nested;
                                        }
                                        crate::NestedLoopUnconditionalControl::Continue(target) => {
                                            resolver.truncate(branch_checkpoint)?;
                                            resolver.truncate(nested_checkpoint)?;
                                            if target == crate::NestedLoopControlTarget::Outer {
                                                continue_loop = true;
                                                break 'nested;
                                            }
                                            continue 'nested;
                                        }
                                        crate::NestedLoopUnconditionalControl::Return(value) => {
                                            return Ok(Some(evaluate_const_return_statement(
                                                context,
                                                symbol_count,
                                                &value,
                                                return_type,
                                                resolver,
                                                depth,
                                            )?));
                                        }
                                    }
                                }
                                for ((control, action_index_for_control), stored_control_order) in
                                    block
                                        .unconditional_controls()
                                        .iter()
                                        .flatten()
                                        .zip(block.unconditional_control_action_indices())
                                        .zip(block.unconditional_control_orders())
                                {
                                    if action_index != *action_index_for_control
                                        || control_order != *stored_control_order
                                    {
                                        continue;
                                    }
                                    match control {
                                        crate::NestedLoopUnconditionalControl::Break(target) => {
                                            resolver.truncate(nested_checkpoint)?;
                                            if *target == crate::NestedLoopControlTarget::Outer {
                                                break_loop = true;
                                            }
                                            break 'nested;
                                        }
                                        crate::NestedLoopUnconditionalControl::Continue(target) => {
                                            resolver.truncate(nested_checkpoint)?;
                                            if *target == crate::NestedLoopControlTarget::Outer {
                                                continue_loop = true;
                                                break 'nested;
                                            }
                                            continue 'nested;
                                        }
                                        crate::NestedLoopUnconditionalControl::Return(value) => {
                                            return Ok(Some(evaluate_const_return_statement(
                                                context,
                                                symbol_count,
                                                value,
                                                return_type,
                                                resolver,
                                                depth,
                                            )?));
                                        }
                                    }
                                }
                                for (
                                    ((condition, break_action_index), break_control_order),
                                    target,
                                ) in block
                                    .conditional_breaks()
                                    .iter()
                                    .flatten()
                                    .zip(block.conditional_break_action_indices())
                                    .zip(block.conditional_break_control_orders())
                                    .zip(block.conditional_break_targets())
                                {
                                    if action_index == *break_action_index
                                        && control_order == *break_control_order
                                    {
                                        let tree = condition
                                            .parse_condition::<MAX_CONST_FUNCTION_EXPRESSION_NODES>(
                                            )
                                            .map_err(|error| {
                                                SemanticErrorKind::Expression(error.kind)
                                            })?;
                                        if evaluate_boolean_const_expression(
                                            context,
                                            symbol_count,
                                            &tree,
                                            tree.root(),
                                            resolver,
                                            depth,
                                        )? {
                                            resolver.truncate(nested_checkpoint)?;
                                            if *target == crate::NestedLoopControlTarget::Outer {
                                                break_loop = true;
                                            }
                                            break 'nested;
                                        }
                                    }
                                }
                                for ((conditional, return_action_index), return_control_order) in
                                    block
                                        .conditional_returns()
                                        .iter()
                                        .flatten()
                                        .zip(block.conditional_return_action_indices())
                                        .zip(block.conditional_return_control_orders())
                                {
                                    if action_index == *return_action_index
                                        && control_order == *return_control_order
                                    {
                                        let condition = conditional
                                            .parse_condition::<MAX_CONST_FUNCTION_EXPRESSION_NODES>(
                                            )
                                            .map_err(|error| {
                                                SemanticErrorKind::Expression(error.kind)
                                            })?;
                                        if evaluate_boolean_const_expression(
                                            context,
                                            symbol_count,
                                            &condition,
                                            condition.root(),
                                            resolver,
                                            depth,
                                        )? {
                                            let value = crate::LoopReturn {
                                                value: conditional.value,
                                                value_span: conditional.value_span,
                                            };
                                            return Ok(Some(evaluate_const_return_statement(
                                                context,
                                                symbol_count,
                                                &value,
                                                return_type,
                                                resolver,
                                                depth,
                                            )?));
                                        }
                                    }
                                }
                                for (
                                    ((condition, continue_action_index), continue_control_order),
                                    target,
                                ) in block
                                    .conditional_continues()
                                    .iter()
                                    .flatten()
                                    .zip(block.conditional_continue_action_indices())
                                    .zip(block.conditional_continue_control_orders())
                                    .zip(block.conditional_continue_targets())
                                {
                                    if action_index == *continue_action_index
                                        && control_order == *continue_control_order
                                    {
                                        let tree = condition
                                            .parse_condition::<MAX_CONST_FUNCTION_EXPRESSION_NODES>(
                                            )
                                            .map_err(|error| {
                                                SemanticErrorKind::Expression(error.kind)
                                            })?;
                                        if evaluate_boolean_const_expression(
                                            context,
                                            symbol_count,
                                            &tree,
                                            tree.root(),
                                            resolver,
                                            depth,
                                        )? {
                                            resolver.truncate(nested_checkpoint)?;
                                            if *target == crate::NestedLoopControlTarget::Outer {
                                                continue_loop = true;
                                                break 'nested;
                                            }
                                            continue 'nested;
                                        }
                                    }
                                }
                            }
                            if action_index == block.action_count() {
                                break;
                            }
                            let action = block.actions()[action_index]
                                .as_ref()
                                .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
                            match action {
                                crate::ConditionalLoopAction::Local(local) => evaluate_const_local(
                                    context,
                                    symbol_count,
                                    local,
                                    resolver,
                                    depth,
                                )?,
                                crate::ConditionalLoopAction::Assignment(assignment) => {
                                    evaluate_const_assignment(
                                        context,
                                        symbol_count,
                                        assignment,
                                        resolver,
                                        depth,
                                    )?;
                                }
                                crate::ConditionalLoopAction::Expression(statement) => {
                                    evaluate_const_expression_statement(
                                        context,
                                        symbol_count,
                                        statement,
                                        resolver,
                                        depth,
                                    )?;
                                }
                            }
                        }
                        resolver.truncate(nested_checkpoint)?;
                    }
                    if break_loop || continue_loop {
                        break;
                    }
                }
                crate::LoopOperation::ConditionalBlock(index) => {
                    let block = loop_statement.conditional_blocks()[*index]
                        .as_ref()
                        .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
                    let condition = block
                        .parse_condition::<MAX_CONST_FUNCTION_EXPRESSION_NODES>()
                        .map_err(|error| SemanticErrorKind::Expression(error.kind))?;
                    let condition_selected = evaluate_boolean_const_expression(
                        context,
                        symbol_count,
                        &condition,
                        condition.root(),
                        resolver,
                        depth,
                    )?;
                    let (actions, terminal) = if condition_selected {
                        (block.actions(), block.terminal)
                    } else {
                        let mut selected = None;
                        if let Some(else_index) = block.else_arm {
                            for arm in loop_statement.conditional_else_arms()
                                [else_index..else_index + block.else_arm_count]
                                .iter()
                                .flatten()
                            {
                                let arm_selected = if let Some(condition) = arm
                                    .parse_condition::<MAX_CONST_FUNCTION_EXPRESSION_NODES>()
                                    .map_err(|error| SemanticErrorKind::Expression(error.kind))?
                                {
                                    evaluate_boolean_const_expression(
                                        context,
                                        symbol_count,
                                        &condition,
                                        condition.root(),
                                        resolver,
                                        depth,
                                    )?
                                } else {
                                    true
                                };
                                if arm_selected {
                                    selected = Some((arm.actions(), arm.terminal));
                                    break;
                                }
                            }
                        }
                        let Some(selected) = selected else {
                            continue;
                        };
                        selected
                    };
                    let block_checkpoint = resolver.count;
                    for action in actions.iter().flatten() {
                        match action {
                            crate::ConditionalLoopAction::Local(local) => {
                                evaluate_const_local(
                                    context,
                                    symbol_count,
                                    local,
                                    resolver,
                                    depth,
                                )?;
                            }
                            crate::ConditionalLoopAction::Assignment(assignment) => {
                                evaluate_const_assignment(
                                    context,
                                    symbol_count,
                                    assignment,
                                    resolver,
                                    depth,
                                )?;
                            }
                            crate::ConditionalLoopAction::Expression(statement) => {
                                evaluate_const_expression_statement(
                                    context,
                                    symbol_count,
                                    statement,
                                    resolver,
                                    depth,
                                )?;
                            }
                        }
                    }
                    match terminal {
                        Some(crate::ConditionalLoopTerminal::Break) => break_loop = true,
                        Some(crate::ConditionalLoopTerminal::Continue) => {}
                        Some(crate::ConditionalLoopTerminal::Return(return_statement)) => {
                            return Ok(Some(evaluate_const_return_statement(
                                context,
                                symbol_count,
                                &return_statement,
                                return_type,
                                resolver,
                                depth,
                            )?));
                        }
                        None => {
                            resolver.truncate(block_checkpoint)?;
                            continue;
                        }
                    }
                    resolver.truncate(block_checkpoint)?;
                    break;
                }
                crate::LoopOperation::Break => {
                    break_loop = true;
                    break;
                }
                crate::LoopOperation::Continue => break,
                crate::LoopOperation::ConditionalBreak(conditional)
                | crate::LoopOperation::ConditionalContinue(conditional) => {
                    let tree = conditional
                        .parse_condition::<MAX_CONST_FUNCTION_EXPRESSION_NODES>()
                        .map_err(|error| SemanticErrorKind::Expression(error.kind))?;
                    if evaluate_boolean_const_expression(
                        context,
                        symbol_count,
                        &tree,
                        tree.root(),
                        resolver,
                        depth,
                    )? {
                        if matches!(operation, crate::LoopOperation::ConditionalBreak(_)) {
                            break_loop = true;
                        }
                        break;
                    }
                }
                crate::LoopOperation::ConditionalReturn(conditional) => {
                    let condition = conditional
                        .parse_condition::<MAX_CONST_FUNCTION_EXPRESSION_NODES>()
                        .map_err(|error| SemanticErrorKind::Expression(error.kind))?;
                    if evaluate_boolean_const_expression(
                        context,
                        symbol_count,
                        &condition,
                        condition.root(),
                        resolver,
                        depth,
                    )? {
                        let value = conditional
                            .parse_value::<MAX_CONST_FUNCTION_EXPRESSION_NODES>()
                            .map_err(|error| SemanticErrorKind::Expression(error.kind))?;
                        return Ok(Some(match return_type {
                            ConstCallType::Bool => u128::from(evaluate_boolean_const_expression(
                                context,
                                symbol_count,
                                &value,
                                value.root(),
                                resolver,
                                depth,
                            )?),
                            ConstCallType::Integer(ty) => evaluate_integer_const_expression(
                                context,
                                symbol_count,
                                &value,
                                value.root(),
                                ty,
                                resolver,
                                depth,
                            )?,
                        }));
                    }
                }
                crate::LoopOperation::Return(loop_return) => {
                    let value = loop_return
                        .parse_value::<MAX_CONST_FUNCTION_EXPRESSION_NODES>()
                        .map_err(|error| SemanticErrorKind::Expression(error.kind))?;
                    return Ok(Some(match return_type {
                        ConstCallType::Bool => u128::from(evaluate_boolean_const_expression(
                            context,
                            symbol_count,
                            &value,
                            value.root(),
                            resolver,
                            depth,
                        )?),
                        ConstCallType::Integer(ty) => evaluate_integer_const_expression(
                            context,
                            symbol_count,
                            &value,
                            value.root(),
                            ty,
                            resolver,
                            depth,
                        )?,
                    }));
                }
            }
        }
        resolver.truncate(binding_checkpoint)?;
        if break_loop {
            break;
        }
    }
    Ok(None)
}

fn evaluate_boolean_const_expression<
    const MAX_NODES: usize,
    const MAX_ITEMS: usize,
    const MAX_PARAMETERS: usize,
>(
    context: &ConstCallContext<'_, '_, MAX_ITEMS, MAX_PARAMETERS>,
    symbol_count: usize,
    tree: &ExpressionTree<'_, MAX_NODES>,
    id: ExprId,
    constants: &ConstCallResolver<'_>,
    depth: ConstEvalDepth,
) -> Result<bool, SemanticErrorKind> {
    if inline_const_has_invalid_capture(tree, id, constants, false, 0) {
        return Err(SemanticErrorKind::UnsupportedConstCall);
    }
    if expression_contains_call(tree, id, 0) {
        evaluate_call_aware_boolean(context, symbol_count, tree, id, constants, depth)
    } else {
        evaluate_boolean_constant(tree, id, constants, 0).map_err(SemanticErrorKind::Execution)
    }
}

fn evaluate_integer_const_expression<
    const MAX_EXPRESSION_NODES: usize,
    const MAX_ITEMS: usize,
    const MAX_PARAMETERS: usize,
>(
    context: &ConstCallContext<'_, '_, MAX_ITEMS, MAX_PARAMETERS>,
    symbol_count: usize,
    tree: &ExpressionTree<'_, MAX_EXPRESSION_NODES>,
    id: ExprId,
    ty: crate::IntegerType,
    constants: &ConstCallResolver<'_>,
    depth: ConstEvalDepth,
) -> Result<u128, SemanticErrorKind> {
    if inline_const_has_invalid_capture(tree, id, constants, false, 0) {
        return Err(SemanticErrorKind::UnsupportedConstCall);
    }
    if matches!(
        tree.expression(id).map(|expression| expression.kind),
        Some(ExprKind::Call { .. })
    ) {
        return evaluate_integer_const_call::<MAX_EXPRESSION_NODES, MAX_ITEMS, MAX_PARAMETERS>(
            context,
            symbol_count,
            tree,
            id,
            ty,
            constants,
            depth,
        );
    }
    if expression_contains_call(tree, id, 0) {
        return evaluate_call_aware_integer(context, symbol_count, tree, id, ty, constants, depth);
    }
    if tree.nodes().iter().flatten().any(|expression| {
        matches!(
            expression.kind,
            ExprKind::Binary {
                operator: BinaryOperator::ShiftLeft | BinaryOperator::ShiftRight,
                ..
            }
                | ExprKind::WrappingArithmetic { .. }
                | ExprKind::SaturatingArithmetic { .. }
                | ExprKind::IntegerRotate { .. }
                | ExprKind::IntegerFunnelShift { .. }
                | ExprKind::IntegerSignCast { .. }
                | ExprKind::IntegerWidthCast { .. }
                | ExprKind::IntegerClampMagnitude { .. }
                | ExprKind::IntegerEndianFrom { .. }
                | ExprKind::IntegerFromBytes { .. }
                | ExprKind::IntegerAssociatedConstant { .. }
                | ExprKind::IntegerWrappingShift { .. }
                | ExprKind::IntegerWrappingPower { .. }
                | ExprKind::IntegerBitTransform { .. }
                | ExprKind::IntegerUnsignedAbsolute { .. }
                | ExprKind::IntegerPairTransform { .. }
                | ExprKind::IntegerClamp { .. }
                | ExprKind::IntegerBitCount { .. }
                | ExprKind::IntegerLogarithm { .. }
        )
    }) {
        return evaluate_call_aware_integer(context, symbol_count, tree, id, ty, constants, depth);
    }
    if ty.is_signed() {
        evaluate_signed_integer(tree, id, ty, context.target, constants, 0)
            .map_err(SemanticErrorKind::Execution)
    } else if id != tree.root() {
        tree.evaluate_at(id, constants)
            .map_err(|error| SemanticErrorKind::Execution(ExecutionError::Arithmetic(error)))
    } else {
        let program = lower_expression_with_pointer_bits::<
            MAX_CONSTANT_IR_INSTRUCTIONS,
            MAX_EXPRESSION_NODES,
        >(tree, context.target.pointer_bits())
        .map_err(|error| SemanticErrorKind::Lowering(error.kind))?;
        program
            .execute::<_, MAX_CONSTANT_STACK_VALUES>(constants)
            .map_err(SemanticErrorKind::Execution)
    }
}

fn inline_const_has_invalid_capture<const MAX_NODES: usize>(
    tree: &ExpressionTree<'_, MAX_NODES>,
    id: ExprId,
    constants: &ConstCallResolver<'_>,
    inside_inline_const: bool,
    depth: usize,
) -> bool {
    if depth == 64 {
        return true;
    }
    let Some(expression) = tree.expression(id) else {
        return true;
    };
    let recurse = |operand, inside| {
        inline_const_has_invalid_capture(tree, operand, constants, inside, depth + 1)
    };
    match expression.kind {
        ExprKind::Identifier(name) if inside_inline_const => {
            constants.has_nonconstant_binding(name) || !constants.has_module_constant(name)
        }
        ExprKind::Call {
            arguments,
            argument_count,
            ..
        } => arguments[..argument_count]
            .iter()
            .flatten()
            .any(|argument| recurse(*argument, inside_inline_const)),
        ExprKind::Array {
            elements,
            element_count,
        } => elements[..element_count]
            .iter()
            .flatten()
            .any(|element| recurse(*element, inside_inline_const)),
        ExprKind::ArrayRepeat { element, .. } => recurse(element, inside_inline_const),
        ExprKind::Tuple {
            elements,
            element_count,
        } => elements[..element_count]
            .iter()
            .flatten()
            .any(|element| recurse(*element, inside_inline_const)),
        ExprKind::TupleField { base, .. } => recurse(base, inside_inline_const),
        ExprKind::Index { base, index } => {
            recurse(base, inside_inline_const) || recurse(index, inside_inline_const)
        }
        ExprKind::RangeIndex {
            base, start, end, ..
        } => {
            recurse(base, inside_inline_const)
                || start.is_some_and(|start| recurse(start, inside_inline_const))
                || end.is_some_and(|end| recurse(end, inside_inline_const))
        }
        ExprKind::SliceLen { base }
        | ExprKind::SliceIsEmpty { base }
        | ExprKind::StrAsBytes { base }
        | ExprKind::CStrToBytes { base, .. }
        | ExprKind::ReferenceAsPointer { base, .. } => recurse(base, inside_inline_const),
        ExprKind::RawPointerIsNull { base } | ExprKind::RawPointerIsAligned { base } => {
            recurse(base, inside_inline_const)
        }
        ExprKind::RawPointerAddress { base }
        | ExprKind::RawPointerMutability { base, .. }
        | ExprKind::RawPointerPointeeCast { base, .. }
        | ExprKind::RawPointerAsReference { base, .. } => recurse(base, inside_inline_const),
        ExprKind::RawPointerWithAddress { base, address } => {
            recurse(base, inside_inline_const) || recurse(address, inside_inline_const)
        }
        ExprKind::RawPointerWithMetadata { base, metadata } => {
            recurse(base, inside_inline_const) || recurse(metadata, inside_inline_const)
        }
        ExprKind::RawPointerWrite { base, value, .. } => {
            recurse(base, inside_inline_const) || recurse(value, inside_inline_const)
        }
        ExprKind::RawPointerWriteBytes { base, value, count } => {
            recurse(base, inside_inline_const)
                || recurse(value, inside_inline_const)
                || recurse(count, inside_inline_const)
        }
        ExprKind::RawPointerCopy {
            source,
            destination,
            count,
            ..
        } => {
            recurse(source, inside_inline_const)
                || recurse(destination, inside_inline_const)
                || recurse(count, inside_inline_const)
        }
        ExprKind::RawPointerSwap { left, right } => {
            recurse(left, inside_inline_const) || recurse(right, inside_inline_const)
        }
        ExprKind::RawPointerOffset { base, offset, .. } => {
            recurse(base, inside_inline_const) || recurse(offset, inside_inline_const)
        }
        ExprKind::RawPointerDifference {
            pointer, origin, ..
        } => recurse(pointer, inside_inline_const) || recurse(origin, inside_inline_const),
        ExprKind::RawPointerAlignOffset { base, alignment } => {
            recurse(base, inside_inline_const) || recurse(alignment, inside_inline_const)
        }
        ExprKind::RawPointerMask { base, mask } => {
            recurse(base, inside_inline_const) || recurse(mask, inside_inline_const)
        }
        ExprKind::RawPointerIsAlignedTo { base, alignment } => {
            recurse(base, inside_inline_const) || recurse(alignment, inside_inline_const)
        }
        ExprKind::RawPointerDrop { base } => recurse(base, inside_inline_const),
        ExprKind::UnsignedIntegerPredicate { base, argument, .. } => {
            recurse(base, inside_inline_const)
                || argument.is_some_and(|argument| recurse(argument, inside_inline_const))
        }
        ExprKind::SignedIntegerPredicate { base, .. } => recurse(base, inside_inline_const),
        ExprKind::AsciiPredicate { base, .. } => recurse(base, inside_inline_const),
        ExprKind::WrappingArithmetic { base, argument, .. } => {
            recurse(base, inside_inline_const) || recurse(argument, inside_inline_const)
        }
        ExprKind::UncheckedIntegerOperation {
            base,
            argument,
            second_argument,
            ..
        } => {
            recurse(base, inside_inline_const)
                || argument.is_some_and(|argument| recurse(argument, inside_inline_const))
                || second_argument.is_some_and(|argument| recurse(argument, inside_inline_const))
        }
        ExprKind::CheckedIntegerOption { base, argument, .. } => {
            recurse(base, inside_inline_const)
                || argument.is_some_and(|argument| recurse(argument, inside_inline_const))
        }
        ExprKind::IntegerOptionUnwrapOr {
            option, fallback, ..
        } => {
            recurse(option, inside_inline_const)
                || fallback.is_some_and(|fallback| recurse(fallback, inside_inline_const))
        }
        ExprKind::IntegerOptionPredicate {
            option, closure, ..
        } => {
            recurse(option, inside_inline_const)
                || closure.is_some_and(|closure| recurse(closure, inside_inline_const))
        }
        ExprKind::IntegerOptionMapOr {
            option,
            default,
            closure,
        } => {
            recurse(option, inside_inline_const)
                || recurse(default, inside_inline_const)
                || recurse(closure, inside_inline_const)
        }
        ExprKind::IntegerOptionMapOrElse {
            option,
            default_closure,
            map_closure,
        } => {
            recurse(option, inside_inline_const)
                || recurse(default_closure, inside_inline_const)
                || recurse(map_closure, inside_inline_const)
        }
        ExprKind::IntegerOptionMapOrDefault {
            option,
            map_closure,
        } => recurse(option, inside_inline_const) || recurse(map_closure, inside_inline_const),
        ExprKind::IntegerOptionMap { option, closure } => {
            recurse(option, inside_inline_const) || recurse(closure, inside_inline_const)
        }
        ExprKind::IntegerOptionAndThen { option, closure } => {
            recurse(option, inside_inline_const) || recurse(closure, inside_inline_const)
        }
        ExprKind::IntegerOptionOrElse { option, closure } => {
            recurse(option, inside_inline_const) || recurse(closure, inside_inline_const)
        }
        ExprKind::IntegerOptionOr {
            option,
            alternative,
        } => recurse(option, inside_inline_const) || recurse(alternative, inside_inline_const),
        ExprKind::IntegerOptionXor {
            option,
            alternative,
        } => recurse(option, inside_inline_const) || recurse(alternative, inside_inline_const),
        ExprKind::IntegerOptionAnd {
            option,
            alternative,
        } => recurse(option, inside_inline_const) || recurse(alternative, inside_inline_const),
        ExprKind::IntegerOptionThenSome { condition, value } => {
            recurse(condition, inside_inline_const) || recurse(value, inside_inline_const)
        }
        ExprKind::IntegerOptionThen { condition, closure } => {
            recurse(condition, inside_inline_const) || recurse(closure, inside_inline_const)
        }
        ExprKind::IntegerOptionInspect { option, closure } => {
            recurse(option, inside_inline_const) || recurse(closure, inside_inline_const)
        }
        ExprKind::IntegerOptionFilter { option, closure } => {
            recurse(option, inside_inline_const) || recurse(closure, inside_inline_const)
        }
        ExprKind::Closure { body, .. } => recurse(body, inside_inline_const),
        ExprKind::SaturatingArithmetic { base, argument, .. } => {
            recurse(base, inside_inline_const) || recurse(argument, inside_inline_const)
        }
        ExprKind::IntegerRotate { base, distance, .. } => {
            recurse(base, inside_inline_const) || recurse(distance, inside_inline_const)
        }
        ExprKind::IntegerFunnelShift {
            base,
            other,
            distance,
            ..
        } => {
            recurse(base, inside_inline_const)
                || recurse(other, inside_inline_const)
                || recurse(distance, inside_inline_const)
        }
        ExprKind::IntegerSignCast { base, .. } | ExprKind::IntegerWidthCast { base, .. } => {
            recurse(base, inside_inline_const)
        }
        ExprKind::IntegerClampMagnitude { base, limit } => {
            recurse(base, inside_inline_const) || recurse(limit, inside_inline_const)
        }
        ExprKind::IntegerEndianFrom { value, .. } => recurse(value, inside_inline_const),
        ExprKind::IntegerFromBytes { bytes, .. } => recurse(bytes, inside_inline_const),
        ExprKind::IntegerToBytes { base, .. } => recurse(base, inside_inline_const),
        ExprKind::IntegerAssociatedConstant { .. } => false,
        ExprKind::IntegerWrappingShift { base, distance, .. } => {
            recurse(base, inside_inline_const) || recurse(distance, inside_inline_const)
        }
        ExprKind::IntegerWrappingPower { base, exponent, .. } => {
            recurse(base, inside_inline_const) || recurse(exponent, inside_inline_const)
        }
        ExprKind::IntegerBitTransform { base, .. } => recurse(base, inside_inline_const),
        ExprKind::IntegerUnsignedAbsolute { base } => recurse(base, inside_inline_const),
        ExprKind::IntegerPairTransform { base, other, .. } => {
            recurse(base, inside_inline_const) || recurse(other, inside_inline_const)
        }
        ExprKind::IntegerClamp {
            base,
            minimum,
            maximum,
        } => {
            recurse(base, inside_inline_const)
                || recurse(minimum, inside_inline_const)
                || recurse(maximum, inside_inline_const)
        }
        ExprKind::IntegerBitCount { base, .. } => recurse(base, inside_inline_const),
        ExprKind::IntegerLogarithm { base, radix, .. } => {
            recurse(base, inside_inline_const)
                || radix.is_some_and(|radix| recurse(radix, inside_inline_const))
        }
        ExprKind::StrIsCharBoundary { base, index } => {
            recurse(base, inside_inline_const) || recurse(index, inside_inline_const)
        }
        ExprKind::InlineConst { operand } => recurse(operand, true),
        ExprKind::Cast { operand, .. }
        | ExprKind::Ascribe { operand, .. }
        | ExprKind::Unary { operand, .. }
        | ExprKind::Return { operand }
        | ExprKind::UnsafeBlock { operand }
        | ExprKind::LoopBreak { operand } => recurse(operand, inside_inline_const),
        ExprKind::Binary { left, right, .. } => {
            recurse(left, inside_inline_const) || recurse(right, inside_inline_const)
        }
        ExprKind::Sequence { first, then } => {
            recurse(first, inside_inline_const) || recurse(then, inside_inline_const)
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
            recurse(condition, inside_inline_const)
                || recurse(then_branch, inside_inline_const)
                || recurse(else_branch, inside_inline_const)
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
        | ExprKind::ClosureParameter { .. }
        | ExprKind::Identifier(_) => false,
    }
}

fn expression_contains_call<const MAX_NODES: usize>(
    tree: &ExpressionTree<'_, MAX_NODES>,
    id: ExprId,
    depth: usize,
) -> bool {
    if depth == 64 {
        return true;
    }
    let Some(expression) = tree.expression(id) else {
        return true;
    };
    let recurse = |operand| expression_contains_call(tree, operand, depth + 1);
    match expression.kind {
        ExprKind::Call { .. } => true,
        ExprKind::Array {
            elements,
            element_count,
        } => elements[..element_count]
            .iter()
            .flatten()
            .any(|element| recurse(*element)),
        ExprKind::ArrayRepeat { element, .. } => recurse(element),
        ExprKind::Tuple {
            elements,
            element_count,
        } => elements[..element_count]
            .iter()
            .flatten()
            .any(|element| recurse(*element)),
        ExprKind::TupleField { base, .. } => recurse(base),
        ExprKind::Index { base, index } => recurse(base) || recurse(index),
        ExprKind::RangeIndex {
            base, start, end, ..
        } => recurse(base) || start.is_some_and(recurse) || end.is_some_and(recurse),
        ExprKind::SliceLen { base }
        | ExprKind::SliceIsEmpty { base }
        | ExprKind::StrAsBytes { base }
        | ExprKind::CStrToBytes { base, .. }
        | ExprKind::ReferenceAsPointer { base, .. } => recurse(base),
        ExprKind::RawPointerIsNull { base } | ExprKind::RawPointerIsAligned { base } => {
            recurse(base)
        }
        ExprKind::RawPointerAddress { base }
        | ExprKind::RawPointerMutability { base, .. }
        | ExprKind::RawPointerPointeeCast { base, .. }
        | ExprKind::RawPointerAsReference { base, .. } => recurse(base),
        ExprKind::RawPointerWithAddress { base, address } => recurse(base) || recurse(address),
        ExprKind::RawPointerWithMetadata { base, metadata } => recurse(base) || recurse(metadata),
        ExprKind::RawPointerWrite { base, value, .. } => recurse(base) || recurse(value),
        ExprKind::RawPointerWriteBytes { base, value, count } => {
            recurse(base) || recurse(value) || recurse(count)
        }
        ExprKind::RawPointerCopy {
            source,
            destination,
            count,
            ..
        } => recurse(source) || recurse(destination) || recurse(count),
        ExprKind::RawPointerSwap { left, right } => recurse(left) || recurse(right),
        ExprKind::RawPointerOffset { base, offset, .. } => recurse(base) || recurse(offset),
        ExprKind::RawPointerDifference {
            pointer, origin, ..
        } => recurse(pointer) || recurse(origin),
        ExprKind::RawPointerAlignOffset { base, alignment } => recurse(base) || recurse(alignment),
        ExprKind::RawPointerMask { base, mask } => recurse(base) || recurse(mask),
        ExprKind::RawPointerIsAlignedTo { base, alignment } => recurse(base) || recurse(alignment),
        ExprKind::RawPointerDrop { base } => recurse(base),
        ExprKind::UnsignedIntegerPredicate { base, argument, .. } => {
            recurse(base) || argument.is_some_and(recurse)
        }
        ExprKind::SignedIntegerPredicate { base, .. } => recurse(base),
        ExprKind::AsciiPredicate { base, .. } => recurse(base),
        ExprKind::WrappingArithmetic { base, argument, .. } => recurse(base) || recurse(argument),
        ExprKind::UncheckedIntegerOperation {
            base,
            argument,
            second_argument,
            ..
        } => recurse(base) || argument.is_some_and(recurse) || second_argument.is_some_and(recurse),
        ExprKind::CheckedIntegerOption { base, argument, .. } => {
            recurse(base) || argument.is_some_and(recurse)
        }
        ExprKind::IntegerOptionUnwrapOr {
            option, fallback, ..
        } => recurse(option) || fallback.is_some_and(recurse),
        ExprKind::IntegerOptionPredicate {
            option, closure, ..
        } => recurse(option) || closure.is_some_and(recurse),
        ExprKind::IntegerOptionMapOr {
            option,
            default,
            closure,
        } => recurse(option) || recurse(default) || recurse(closure),
        ExprKind::IntegerOptionMapOrElse {
            option,
            default_closure,
            map_closure,
        } => recurse(option) || recurse(default_closure) || recurse(map_closure),
        ExprKind::IntegerOptionMapOrDefault {
            option,
            map_closure,
        } => recurse(option) || recurse(map_closure),
        ExprKind::IntegerOptionMap { option, closure } => recurse(option) || recurse(closure),
        ExprKind::IntegerOptionAndThen { option, closure } => recurse(option) || recurse(closure),
        ExprKind::IntegerOptionOrElse { option, closure } => recurse(option) || recurse(closure),
        ExprKind::IntegerOptionOr {
            option,
            alternative,
        } => recurse(option) || recurse(alternative),
        ExprKind::IntegerOptionXor {
            option,
            alternative,
        } => recurse(option) || recurse(alternative),
        ExprKind::IntegerOptionAnd {
            option,
            alternative,
        } => recurse(option) || recurse(alternative),
        ExprKind::IntegerOptionThenSome { condition, value } => {
            recurse(condition) || recurse(value)
        }
        ExprKind::IntegerOptionThen { condition, closure } => {
            recurse(condition) || recurse(closure)
        }
        ExprKind::IntegerOptionInspect { option, closure } => recurse(option) || recurse(closure),
        ExprKind::IntegerOptionFilter { option, closure } => recurse(option) || recurse(closure),
        ExprKind::Closure { body, .. } => recurse(body),
        ExprKind::SaturatingArithmetic { base, argument, .. } => recurse(base) || recurse(argument),
        ExprKind::IntegerRotate { base, distance, .. } => recurse(base) || recurse(distance),
        ExprKind::IntegerFunnelShift {
            base,
            other,
            distance,
            ..
        } => recurse(base) || recurse(other) || recurse(distance),
        ExprKind::IntegerSignCast { base, .. } | ExprKind::IntegerWidthCast { base, .. } => {
            recurse(base)
        }
        ExprKind::IntegerClampMagnitude { base, limit } => recurse(base) || recurse(limit),
        ExprKind::IntegerEndianFrom { value, .. } => recurse(value),
        ExprKind::IntegerFromBytes { bytes, .. } => recurse(bytes),
        ExprKind::IntegerToBytes { base, .. } => recurse(base),
        ExprKind::IntegerAssociatedConstant { .. } => false,
        ExprKind::IntegerWrappingShift { base, distance, .. } => recurse(base) || recurse(distance),
        ExprKind::IntegerWrappingPower { base, exponent, .. } => recurse(base) || recurse(exponent),
        ExprKind::IntegerBitTransform { base, .. } => recurse(base),
        ExprKind::IntegerUnsignedAbsolute { base } => recurse(base),
        ExprKind::IntegerPairTransform { base, other, .. } => recurse(base) || recurse(other),
        ExprKind::IntegerClamp {
            base,
            minimum,
            maximum,
        } => recurse(base) || recurse(minimum) || recurse(maximum),
        ExprKind::IntegerBitCount { base, .. } => recurse(base),
        ExprKind::IntegerLogarithm { base, radix, .. } => {
            recurse(base) || radix.is_some_and(recurse)
        }
        ExprKind::StrIsCharBoundary { base, index } => recurse(base) || recurse(index),
        ExprKind::Cast { operand, .. }
        | ExprKind::Ascribe { operand, .. }
        | ExprKind::Unary { operand, .. }
        | ExprKind::Return { operand }
        | ExprKind::LoopBreak { operand }
        | ExprKind::InlineConst { operand }
        | ExprKind::UnsafeBlock { operand } => recurse(operand),
        ExprKind::Binary { left, right, .. } => recurse(left) || recurse(right),
        ExprKind::Sequence { first, then } => recurse(first) || recurse(then),
        ExprKind::If {
            condition,
            then_branch,
            else_branch,
        }
        | ExprKind::LoopBreakIf {
            condition,
            then_branch,
            else_branch,
        } => recurse(condition) || recurse(then_branch) || recurse(else_branch),
        ExprKind::Unit
        | ExprKind::DefaultValue
        | ExprKind::Integer(_)
        | ExprKind::Bool(_)
        | ExprKind::Char(_)
        | ExprKind::ByteChar(_)
        | ExprKind::String(_)
        | ExprKind::ByteString(_)
        | ExprKind::CString(_)
        | ExprKind::ClosureParameter { .. }
        | ExprKind::Identifier(_) => false,
    }
}

fn evaluate_call_aware_integer<
    const MAX_EXPRESSION_NODES: usize,
    const MAX_ITEMS: usize,
    const MAX_PARAMETERS: usize,
>(
    context: &ConstCallContext<'_, '_, MAX_ITEMS, MAX_PARAMETERS>,
    symbol_count: usize,
    tree: &ExpressionTree<'_, MAX_EXPRESSION_NODES>,
    id: ExprId,
    ty: crate::IntegerType,
    constants: &ConstCallResolver<'_>,
    depth: ConstEvalDepth,
) -> Result<u128, SemanticErrorKind> {
    let depth = depth.enter_expression()?;
    let bits = ty
        .bits(context.target.pointer_bits())
        .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
    let mask = signed_mask(bits);
    let maximum = maximum_unsigned_value(ty.name(), context.target);
    let expression =
        tree.expression(id)
            .ok_or(SemanticErrorKind::Execution(ExecutionError::Arithmetic(
                ConstEvalError::InvalidExpressionTree,
            )))?;
    let arithmetic_error = |error| SemanticErrorKind::Execution(ExecutionError::Arithmetic(error));
    let recurse = |operand| {
        evaluate_call_aware_integer(context, symbol_count, tree, operand, ty, constants, depth)
    };
    let value = match expression.kind {
        ExprKind::Integer(literal) => {
            if literal.suffix.is_some_and(|suffix| suffix != ty.name())
                || (!ty.is_signed() && literal.value > maximum)
                || (ty.is_signed() && literal.value > signed_maximum(bits) as u128)
            {
                return Err(arithmetic_error(ConstEvalError::Overflow));
            }
            literal.value
        }
        ExprKind::Identifier(name) => {
            if constants.resolve_type(name) != Some(ty) {
                return Err(arithmetic_error(ConstEvalError::InvalidCast));
            }
            constants.resolve(name).ok_or(SemanticErrorKind::Execution(
                ExecutionError::UnknownConstant,
            ))?
        }
        ExprKind::Call { .. } => {
            evaluate_integer_const_call(context, symbol_count, tree, id, ty, constants, depth)?
        }
        ExprKind::Unary {
            operator: UnaryOperator::Negate,
            operand,
        } if ty.is_signed() => {
            if let Some(ExprKind::Integer(literal)) =
                tree.expression(operand).map(|operand| operand.kind)
            {
                let limit = 1u128 << (bits - 1);
                if literal.suffix.is_some_and(|suffix| suffix != ty.name()) || literal.value > limit
                {
                    return Err(arithmetic_error(ConstEvalError::Overflow));
                }
                0u128.wrapping_sub(literal.value) & mask
            } else {
                let value = decode_signed(recurse(operand)?, bits);
                encode_signed(
                    value
                        .checked_neg()
                        .ok_or(arithmetic_error(ConstEvalError::Overflow))?,
                    bits,
                )
                .map_err(|error| match error {
                    ExecutionError::Arithmetic(error) => arithmetic_error(error),
                    other => SemanticErrorKind::Execution(other),
                })?
            }
        }
        ExprKind::Unary {
            operator: UnaryOperator::Not,
            operand,
        } => !recurse(operand)? & mask,
        ExprKind::Cast { operand, target } => {
            if target != crate::CastType::Integer(ty) {
                return Err(arithmetic_error(ConstEvalError::InvalidCast));
            }
            let source_type =
                integer_expression_type(context, symbol_count, tree, operand, constants)
                    .unwrap_or(ty);
            let source = evaluate_call_aware_integer(
                context,
                symbol_count,
                tree,
                operand,
                source_type,
                constants,
                depth,
            )?;
            crate::expression::cast_integer(source, ty, context.target.pointer_bits())
                .map_err(arithmetic_error)?
        }
        ExprKind::If {
            condition,
            then_branch,
            else_branch,
        } => {
            let condition = if expression_contains_call(tree, condition, 0) {
                evaluate_call_aware_boolean(
                    context,
                    symbol_count,
                    tree,
                    condition,
                    constants,
                    depth,
                )?
            } else {
                evaluate_boolean_constant(tree, condition, constants, 0)
                    .map_err(SemanticErrorKind::Execution)?
            };
            if condition {
                recurse(then_branch)?
            } else {
                recurse(else_branch)?
            }
        }
        ExprKind::Return { operand }
        | ExprKind::LoopBreak { operand }
        | ExprKind::InlineConst { operand } => recurse(operand)?,
        ExprKind::Binary {
            operator,
            left,
            right,
        } => {
            let left_bits = recurse(left)?;
            let right_bits = if matches!(
                operator,
                BinaryOperator::ShiftLeft | BinaryOperator::ShiftRight
            ) {
                let right_type = integer_expression_type(
                    context,
                    symbol_count,
                    tree,
                    right,
                    constants,
                )
                .unwrap_or(ty);
                evaluate_call_aware_integer(
                    context,
                    symbol_count,
                    tree,
                    right,
                    right_type,
                    constants,
                    depth,
                )?
            } else {
                recurse(right)?
            };
            if ty.is_signed() {
                evaluate_call_aware_signed_binary(operator, left_bits, right_bits, bits)
                    .map_err(arithmetic_error)?
            } else {
                evaluate_call_aware_unsigned_binary(operator, left_bits, right_bits, bits)
                    .map_err(arithmetic_error)?
            }
        }
        ExprKind::WrappingArithmetic {
            base,
            argument,
            operator,
            euclidean,
            euclidean_wrapping,
            strict,
            mixed_signedness,
        } => {
            let base_type = integer_expression_type(context, symbol_count, tree, base, constants);
            let argument_type = if mixed_signedness {
                if ty.is_signed() {
                    ty.unsigned_counterpart()
                } else {
                    ty.signed_counterpart()
                }
            } else {
                Some(ty)
            };
            if base_type.is_some_and(|base_type| base_type != ty)
                || (base_type.is_none() && ty != crate::IntegerType::I32)
                || integer_expression_type(context, symbol_count, tree, argument, constants)
                    .is_some_and(|actual| Some(actual) != argument_type)
            {
                return Err(arithmetic_error(ConstEvalError::InvalidCast));
            }
            let left = recurse(base)?;
            let right = evaluate_call_aware_integer(
                context,
                symbol_count,
                tree,
                argument,
                argument_type.ok_or_else(|| arithmetic_error(ConstEvalError::InvalidCast))?,
                constants,
                depth,
            )?;
            if euclidean {
                return euclidean_integer_arithmetic(
                    left,
                    right,
                    bits,
                    ty.is_signed(),
                    operator,
                    euclidean_wrapping,
                )
                .map_err(arithmetic_error);
            }
            if strict {
                if mixed_signedness {
                    return strict_mixed_integer_arithmetic(
                        left,
                        right,
                        bits,
                        ty.is_signed(),
                        operator,
                    )
                    .map_err(arithmetic_error);
                }
                return if ty.is_signed() {
                    evaluate_call_aware_signed_binary(operator, left, right, bits)
                } else {
                    evaluate_call_aware_unsigned_binary(operator, left, right, bits)
                }
                .map_err(arithmetic_error);
            }
            match operator {
                BinaryOperator::Add => left.overflowing_add(right).0 & mask,
                BinaryOperator::Subtract => left.overflowing_sub(right).0 & mask,
                BinaryOperator::Multiply => left.overflowing_mul(right).0 & mask,
                BinaryOperator::Divide | BinaryOperator::Remainder => {
                    if right == 0 {
                        return Err(arithmetic_error(ConstEvalError::DivisionByZero));
                    }
                    if ty.is_signed() {
                        let minimum = 1_u128 << (bits - 1);
                        if left == minimum && right == mask {
                            if operator == BinaryOperator::Divide {
                                minimum
                            } else {
                                0
                            }
                        } else {
                            evaluate_call_aware_signed_binary(operator, left, right, bits)
                                .map_err(arithmetic_error)?
                        }
                    } else if operator == BinaryOperator::Divide {
                        left / right
                    } else {
                        left % right
                    }
                }
                _ => return Err(arithmetic_error(ConstEvalError::InvalidExpressionTree)),
            }
        }
        ExprKind::SaturatingArithmetic {
            base,
            argument,
            operator,
            mixed_signedness,
        } => {
            let base_type = integer_expression_type(context, symbol_count, tree, base, constants);
            let argument_type = if mixed_signedness {
                if ty.is_signed() {
                    ty.unsigned_counterpart()
                } else {
                    ty.signed_counterpart()
                }
            } else {
                Some(ty)
            };
            if base_type.is_some_and(|base_type| base_type != ty)
                || (base_type.is_none() && ty != crate::IntegerType::I32)
                || integer_expression_type(context, symbol_count, tree, argument, constants)
                    .is_some_and(|actual| Some(actual) != argument_type)
            {
                return Err(arithmetic_error(ConstEvalError::InvalidCast));
            }
            let left = recurse(base)?;
            let right = evaluate_call_aware_integer(
                context,
                symbol_count,
                tree,
                argument,
                argument_type.ok_or_else(|| arithmetic_error(ConstEvalError::InvalidCast))?,
                constants,
                depth,
            )?;
            if operator == BinaryOperator::Divide && right & signed_mask(bits) == 0 {
                return Err(arithmetic_error(ConstEvalError::DivisionByZero));
            }
            if mixed_signedness {
                saturating_mixed_integer_arithmetic(left, right, bits, ty.is_signed(), operator)
            } else {
                saturating_integer_arithmetic(left, right, bits, ty.is_signed(), operator)
            }
        }
        ExprKind::IntegerRotate {
            base,
            distance,
            left,
        } => {
            let base_type = integer_expression_type(context, symbol_count, tree, base, constants);
            if base_type.is_some_and(|base_type| base_type != ty)
                || (base_type.is_none() && ty != crate::IntegerType::I32)
                || integer_expression_type(context, symbol_count, tree, distance, constants)
                    .is_some_and(|distance_type| distance_type != crate::IntegerType::U32)
            {
                return Err(arithmetic_error(ConstEvalError::InvalidCast));
            }
            let value = recurse(base)?;
            let distance = evaluate_call_aware_integer(
                context,
                symbol_count,
                tree,
                distance,
                crate::IntegerType::U32,
                constants,
                depth,
            )?;
            rotate_integer_bits(value, distance, bits, left)
        }
        ExprKind::IntegerFunnelShift {
            base,
            other,
            distance,
            left,
        } => {
            if ty.is_signed()
                || integer_expression_type(context, symbol_count, tree, base, constants)
                    .is_some_and(|actual| actual != ty)
                || integer_expression_type(context, symbol_count, tree, other, constants)
                    .is_some_and(|actual| actual != ty)
                || integer_expression_type(context, symbol_count, tree, distance, constants)
                    .is_some_and(|actual| actual != crate::IntegerType::U32)
            {
                return Err(arithmetic_error(ConstEvalError::InvalidCast));
            }
            let first = recurse(base)? & signed_mask(bits);
            let second = recurse(other)? & signed_mask(bits);
            let distance = evaluate_call_aware_integer(
                context,
                symbol_count,
                tree,
                distance,
                crate::IntegerType::U32,
                constants,
                depth,
            )?;
            if distance >= u128::from(bits) {
                return Err(arithmetic_error(ConstEvalError::InvalidShift));
            }
            funnel_shift_bits(first, second, distance, bits, left)
        }
        ExprKind::IntegerSignCast {
            base,
            signed,
            saturating,
            strict,
        } => {
            if ty.is_signed() != signed {
                return Err(arithmetic_error(ConstEvalError::InvalidCast));
            }
            let source_type = if signed {
                ty.unsigned_counterpart()
            } else {
                ty.signed_counterpart()
            }
            .ok_or_else(|| arithmetic_error(ConstEvalError::InvalidCast))?;
            if integer_expression_type(context, symbol_count, tree, base, constants)
                .is_some_and(|actual| actual != source_type)
            {
                return Err(arithmetic_error(ConstEvalError::InvalidCast));
            }
            let value = evaluate_call_aware_integer(
                context,
                symbol_count,
                tree,
                base,
                source_type,
                constants,
                depth,
            )? & signed_mask(bits);
            sign_cast_bits(value, bits, signed, saturating, strict).map_err(arithmetic_error)?
        }
        ExprKind::IntegerWidthCast { base, target, mode } => {
            if ty != target {
                return Err(arithmetic_error(ConstEvalError::InvalidCast));
            }
            let source_type = integer_expression_type(context, symbol_count, tree, base, constants)
                .ok_or_else(|| arithmetic_error(ConstEvalError::InvalidCast))?;
            if !source_type.supports_width_cast(target, mode) {
                return Err(arithmetic_error(ConstEvalError::InvalidCast));
            }
            let source_bits = source_type
                .bits(context.target.pointer_bits())
                .ok_or_else(|| arithmetic_error(ConstEvalError::InvalidCast))?;
            let value = evaluate_call_aware_integer(
                context,
                symbol_count,
                tree,
                base,
                source_type,
                constants,
                depth,
            )?;
            width_cast_bits(
                value,
                source_bits,
                bits,
                source_type.is_signed(),
                target.is_signed(),
                mode,
            )
            .map_err(arithmetic_error)?
        }
        ExprKind::IntegerWrappingShift {
            base,
            distance,
            left,
            unbounded,
            strict,
        } => {
            let base_type = integer_expression_type(context, symbol_count, tree, base, constants);
            if base_type.is_some_and(|base_type| base_type != ty)
                || (base_type.is_none() && ty != crate::IntegerType::I32)
                || integer_expression_type(context, symbol_count, tree, distance, constants)
                    .is_some_and(|distance_type| distance_type != crate::IntegerType::U32)
            {
                return Err(arithmetic_error(ConstEvalError::InvalidCast));
            }
            let value = recurse(base)?;
            let distance = evaluate_call_aware_integer(
                context,
                symbol_count,
                tree,
                distance,
                crate::IntegerType::U32,
                constants,
                depth,
            )?;
            if strict && distance >= u128::from(bits) {
                return Err(arithmetic_error(ConstEvalError::InvalidShift));
            }
            shift_integer_bits(value, distance, bits, left, ty.is_signed(), unbounded)
        }
        ExprKind::IntegerWrappingPower {
            base,
            exponent,
            mode,
        } => {
            let base_type = integer_expression_type(context, symbol_count, tree, base, constants);
            if base_type.is_some_and(|base_type| base_type != ty)
                || (base_type.is_none() && ty != crate::IntegerType::I32)
                || integer_expression_type(context, symbol_count, tree, exponent, constants)
                    .is_some_and(|exponent_type| exponent_type != crate::IntegerType::U32)
            {
                return Err(arithmetic_error(ConstEvalError::InvalidCast));
            }
            let value = recurse(base)?;
            let exponent = evaluate_call_aware_integer(
                context,
                symbol_count,
                tree,
                exponent,
                crate::IntegerType::U32,
                constants,
                depth,
            )?;
            integer_power_bits(value, exponent, bits, ty.is_signed(), mode)
                .map_err(arithmetic_error)?
        }
        ExprKind::IntegerClampMagnitude { .. } => {
            return Err(SemanticErrorKind::UnsupportedConstCall);
        }
        ExprKind::IntegerEndianFrom {
            value,
            integer_type,
            little,
        } => {
            if ty != integer_type
                || integer_expression_type(context, symbol_count, tree, value, constants)
                    .is_some_and(|actual| actual != integer_type)
            {
                return Err(arithmetic_error(ConstEvalError::InvalidCast));
            }
            let value = evaluate_call_aware_integer(
                context,
                symbol_count,
                tree,
                value,
                integer_type,
                constants,
                depth,
            )?;
            transform_integer_bits(
                value,
                bits,
                if little {
                    crate::expression::IntegerBitTransform::ToLittleEndian
                } else {
                    crate::expression::IntegerBitTransform::ToBigEndian
                },
            )
        }
        ExprKind::IntegerFromBytes {
            bytes: byte_array,
            integer_type,
            order,
        } => {
            if ty != integer_type {
                return Err(arithmetic_error(ConstEvalError::InvalidCast));
            }
            let value = tree
                .evaluate_byte_array(byte_array, usize::from(bits / 8), constants)
                .map_err(arithmetic_error)?;
            integer_from_packed_bytes(value, bits, order)
        }
        ExprKind::IntegerAssociatedConstant {
            integer_type,
            constant,
        } => integer_associated_constant_value(integer_type, constant, ty, context.target)
            .map_err(arithmetic_error)?,
        ExprKind::IntegerBitTransform { base, transform } => {
            let base_type = integer_expression_type(context, symbol_count, tree, base, constants);
            if base_type.is_some_and(|base_type| base_type != ty)
                || (base_type.is_none() && ty != crate::IntegerType::I32)
                || (matches!(
                    transform,
                    crate::expression::IntegerBitTransform::WrappingNegate
                        | crate::expression::IntegerBitTransform::WrappingAbsolute
                        | crate::expression::IntegerBitTransform::Absolute
                        | crate::expression::IntegerBitTransform::StrictAbsolute
                        | crate::expression::IntegerBitTransform::SaturatingNegate
                        | crate::expression::IntegerBitTransform::SaturatingAbsolute
                        | crate::expression::IntegerBitTransform::Signum
                ) && !ty.is_signed())
                || (matches!(
                    transform,
                    crate::expression::IntegerBitTransform::NextPowerOfTwo
                        | crate::expression::IntegerBitTransform::WrappingNextPowerOfTwo
                ) && ty.is_signed())
            {
                return Err(arithmetic_error(ConstEvalError::InvalidCast));
            }
            let value = recurse(base)?;
            if transform == crate::expression::IntegerBitTransform::StrictNegate
                && if ty.is_signed() {
                    value == 1_u128 << (bits - 1)
                } else {
                    value != 0
                }
            {
                return Err(arithmetic_error(ConstEvalError::Overflow));
            }
            if transform == crate::expression::IntegerBitTransform::IntegerSquareRoot
                && ty.is_signed()
                && value & (1_u128 << (bits - 1)) != 0
            {
                return Err(arithmetic_error(ConstEvalError::InvalidCast));
            }
            if matches!(
                transform,
                crate::expression::IntegerBitTransform::Absolute
                    | crate::expression::IntegerBitTransform::StrictAbsolute
            ) && value == 1_u128 << (bits - 1)
            {
                return Err(arithmetic_error(ConstEvalError::Overflow));
            }
            if transform == crate::expression::IntegerBitTransform::NextPowerOfTwo
                && next_power_of_two_integer_bits(value, bits) == 0
                && value > 1
            {
                return Err(arithmetic_error(ConstEvalError::Overflow));
            }
            transform_integer_bits(value, bits, transform)
        }
        ExprKind::IntegerUnsignedAbsolute { base } => {
            let base_type = integer_expression_type(context, symbol_count, tree, base, constants)
                .unwrap_or(crate::IntegerType::I32);
            if base_type.unsigned_counterpart() != Some(ty) {
                return Err(arithmetic_error(ConstEvalError::InvalidCast));
            }
            let base_bits = base_type
                .bits(context.target.pointer_bits())
                .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
            let value = evaluate_call_aware_integer(
                context,
                symbol_count,
                tree,
                base,
                base_type,
                constants,
                depth,
            )?;
            if value & (1_u128 << (base_bits - 1)) == 0 {
                value
            } else {
                0_u128.wrapping_sub(value) & signed_mask(base_bits)
            }
        }
        ExprKind::IntegerPairTransform {
            base,
            other,
            transform,
        } => {
            let base_type = integer_expression_type(context, symbol_count, tree, base, constants)
                .unwrap_or(crate::IntegerType::I32);
            if integer_expression_type(context, symbol_count, tree, other, constants)
                .is_some_and(|other_type| other_type != base_type)
                || (matches!(
                    transform,
                    crate::expression::IntegerPairTransform::CarrylessMultiply
                        | crate::expression::IntegerPairTransform::ExtractBits
                        | crate::expression::IntegerPairTransform::DepositBits
                ) && base_type.is_signed())
            {
                return Err(arithmetic_error(ConstEvalError::InvalidCast));
            }
            let result_type =
                if transform == crate::expression::IntegerPairTransform::AbsoluteDifference {
                    base_type.unsigned_counterpart().unwrap_or(base_type)
                } else {
                    base_type
                };
            if result_type != ty {
                return Err(arithmetic_error(ConstEvalError::InvalidCast));
            }
            let base_bits = base_type
                .bits(context.target.pointer_bits())
                .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
            let left = evaluate_call_aware_integer(
                context,
                symbol_count,
                tree,
                base,
                base_type,
                constants,
                depth,
            )?;
            let right = evaluate_call_aware_integer(
                context,
                symbol_count,
                tree,
                other,
                base_type,
                constants,
                depth,
            )?;
            match transform {
                crate::expression::IntegerPairTransform::Minimum => {
                    if integer_bits_less_than(right, left, base_bits, base_type.is_signed()) {
                        right
                    } else {
                        left
                    }
                }
                crate::expression::IntegerPairTransform::Maximum => {
                    if integer_bits_less_than(left, right, base_bits, base_type.is_signed()) {
                        right
                    } else {
                        left
                    }
                }
                crate::expression::IntegerPairTransform::AbsoluteDifference => {
                    absolute_difference_integer_bits(left, right, base_bits, base_type.is_signed())
                }
                crate::expression::IntegerPairTransform::Midpoint => {
                    midpoint_integer_bits(left, right, base_bits, base_type.is_signed())
                }
                crate::expression::IntegerPairTransform::CarrylessMultiply => {
                    carryless_multiply_integer_bits(left, right, base_bits)
                }
                crate::expression::IntegerPairTransform::ExtractBits => {
                    extract_integer_bits(left, right, base_bits)
                }
                crate::expression::IntegerPairTransform::DepositBits => {
                    deposit_integer_bits(left, right, base_bits)
                }
                crate::expression::IntegerPairTransform::DivideFloor => {
                    divide_floor_integer_bits(left, right, base_bits, base_type.is_signed())
                        .map_err(arithmetic_error)?
                }
                crate::expression::IntegerPairTransform::DivideCeiling => {
                    divide_ceiling_integer_bits(left, right, base_bits, base_type.is_signed())
                        .map_err(arithmetic_error)?
                }
                crate::expression::IntegerPairTransform::NextMultiple => {
                    next_multiple_integer_bits(left, right, base_bits, base_type.is_signed())
                        .map_err(arithmetic_error)?
                }
            }
        }
        ExprKind::IntegerClamp {
            base,
            minimum,
            maximum,
        } => {
            let base_type = integer_expression_type(context, symbol_count, tree, base, constants)
                .unwrap_or(crate::IntegerType::I32);
            if base_type != ty
                || [minimum, maximum].into_iter().any(|bound| {
                    integer_expression_type(context, symbol_count, tree, bound, constants)
                        .is_some_and(|bound_type| bound_type != base_type)
                })
            {
                return Err(arithmetic_error(ConstEvalError::InvalidCast));
            }
            let value = evaluate_call_aware_integer(
                context,
                symbol_count,
                tree,
                base,
                base_type,
                constants,
                depth,
            )?;
            let minimum = evaluate_call_aware_integer(
                context,
                symbol_count,
                tree,
                minimum,
                base_type,
                constants,
                depth,
            )?;
            let maximum = evaluate_call_aware_integer(
                context,
                symbol_count,
                tree,
                maximum,
                base_type,
                constants,
                depth,
            )?;
            if integer_bits_less_than(maximum, minimum, bits, base_type.is_signed()) {
                return Err(arithmetic_error(ConstEvalError::InvalidRangeBounds));
            }
            if integer_bits_less_than(value, minimum, bits, base_type.is_signed()) {
                minimum
            } else if integer_bits_less_than(maximum, value, bits, base_type.is_signed()) {
                maximum
            } else {
                value
            }
        }
        ExprKind::IntegerBitCount { base, count } => {
            if ty != crate::IntegerType::U32 {
                return Err(arithmetic_error(ConstEvalError::InvalidCast));
            }
            let base_type = integer_expression_type(context, symbol_count, tree, base, constants)
                .unwrap_or(crate::IntegerType::I32);
            if count == crate::expression::IntegerBitCount::Width && base_type.is_signed() {
                return Err(arithmetic_error(ConstEvalError::InvalidCast));
            }
            let base_bits = base_type
                .bits(context.target.pointer_bits())
                .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
            let value = evaluate_call_aware_integer(
                context,
                symbol_count,
                tree,
                base,
                base_type,
                constants,
                depth,
            )?;
            u128::from(count_integer_bits(value, base_bits, count))
        }
        ExprKind::IntegerLogarithm {
            base,
            radix,
            binary,
        } => {
            if ty != crate::IntegerType::U32 {
                return Err(arithmetic_error(ConstEvalError::InvalidCast));
            }
            let base_type = integer_expression_type(context, symbol_count, tree, base, constants)
                .unwrap_or(crate::IntegerType::I32);
            let base_bits = base_type
                .bits(context.target.pointer_bits())
                .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
            if radix.is_some_and(|radix| {
                integer_expression_type(context, symbol_count, tree, radix, constants)
                    .is_some_and(|radix_type| radix_type != base_type)
            }) {
                return Err(arithmetic_error(ConstEvalError::InvalidCast));
            }
            let value = evaluate_call_aware_integer(
                context,
                symbol_count,
                tree,
                base,
                base_type,
                constants,
                depth,
            )?;
            let radix = if let Some(radix) = radix {
                evaluate_call_aware_integer(
                    context,
                    symbol_count,
                    tree,
                    radix,
                    base_type,
                    constants,
                    depth,
                )?
            } else if binary {
                2
            } else {
                10
            };
            u128::from(
                integer_logarithm(value, radix, base_bits, base_type.is_signed())
                    .map_err(arithmetic_error)?,
            )
        }
        _ => return Err(arithmetic_error(ConstEvalError::InvalidCast)),
    };
    if (!ty.is_signed() && value > maximum) || (ty.is_signed() && value & mask != value) {
        return Err(arithmetic_error(ConstEvalError::Overflow));
    }
    Ok(value)
}

fn integer_expression_type<
    const MAX_NODES: usize,
    const MAX_ITEMS: usize,
    const MAX_PARAMETERS: usize,
>(
    context: &ConstCallContext<'_, '_, MAX_ITEMS, MAX_PARAMETERS>,
    symbol_count: usize,
    tree: &ExpressionTree<'_, MAX_NODES>,
    id: ExprId,
    constants: &ConstCallResolver<'_>,
) -> Option<crate::IntegerType> {
    match tree.expression(id)?.kind {
        ExprKind::InlineConst { operand } => {
            integer_expression_type(context, symbol_count, tree, operand, constants)
        }
        ExprKind::Call { callee, .. } => context.module.items()[..symbol_count]
            .iter()
            .flatten()
            .find_map(|item| match item {
                Item::Function(function)
                    if function.name == callee
                        && function.constant
                        && function.abi == crate::FunctionAbi::Rust =>
                {
                    function
                        .return_type
                        .and_then(|return_type| crate::IntegerType::from_name(return_type.text))
                }
                _ => None,
            }),
        _ => expression_integer_type(tree, id, constants),
    }
}

fn evaluate_call_aware_boolean<
    const MAX_NODES: usize,
    const MAX_ITEMS: usize,
    const MAX_PARAMETERS: usize,
>(
    context: &ConstCallContext<'_, '_, MAX_ITEMS, MAX_PARAMETERS>,
    symbol_count: usize,
    tree: &ExpressionTree<'_, MAX_NODES>,
    id: ExprId,
    constants: &ConstCallResolver<'_>,
    depth: ConstEvalDepth,
) -> Result<bool, SemanticErrorKind> {
    let depth = depth.enter_expression()?;
    let expression =
        tree.expression(id)
            .ok_or(SemanticErrorKind::Execution(ExecutionError::Arithmetic(
                ConstEvalError::InvalidExpressionTree,
            )))?;
    let recurse = |operand| {
        evaluate_call_aware_boolean(context, symbol_count, tree, operand, constants, depth)
    };
    match expression.kind {
        ExprKind::Bool(value) => Ok(value),
        ExprKind::Identifier(name) if constants.resolves_bool(name) => constants
            .resolve(name)
            .map(|value| value != 0)
            .ok_or(SemanticErrorKind::Execution(
                ExecutionError::UnknownConstant,
            )),
        ExprKind::Call { .. } => {
            evaluate_boolean_const_call(context, symbol_count, tree, id, constants, depth)
        }
        ExprKind::InlineConst { operand } => recurse(operand),
        ExprKind::Unary {
            operator: UnaryOperator::Not,
            operand,
        } => Ok(!recurse(operand)?),
        ExprKind::If {
            condition,
            then_branch,
            else_branch,
        } => {
            if recurse(condition)? {
                recurse(then_branch)
            } else {
                recurse(else_branch)
            }
        }
        ExprKind::Binary {
            operator,
            left,
            right,
        } if matches!(
            operator,
            BinaryOperator::LogicalAnd
                | BinaryOperator::LogicalOr
                | BinaryOperator::BitAnd
                | BinaryOperator::BitOr
                | BinaryOperator::BitXor
        ) =>
        {
            let left = recurse(left)?;
            if operator == BinaryOperator::LogicalAnd && !left {
                return Ok(false);
            }
            if operator == BinaryOperator::LogicalOr && left {
                return Ok(true);
            }
            let right = recurse(right)?;
            Ok(match operator {
                BinaryOperator::LogicalAnd | BinaryOperator::BitAnd => left && right,
                BinaryOperator::LogicalOr | BinaryOperator::BitOr => left || right,
                BinaryOperator::BitXor => left != right,
                _ => false,
            })
        }
        ExprKind::Binary {
            operator,
            left,
            right,
        } if matches!(
            operator,
            BinaryOperator::Equal
                | BinaryOperator::NotEqual
                | BinaryOperator::Less
                | BinaryOperator::LessEqual
                | BinaryOperator::Greater
                | BinaryOperator::GreaterEqual
        ) =>
        {
            let left_type = integer_expression_type(context, symbol_count, tree, left, constants);
            let right_type = integer_expression_type(context, symbol_count, tree, right, constants);
            if left_type.is_some() && right_type.is_some() && left_type != right_type {
                return Err(SemanticErrorKind::Execution(ExecutionError::Arithmetic(
                    ConstEvalError::InvalidCast,
                )));
            }
            let ty = left_type.or(right_type).unwrap_or(crate::IntegerType::I32);
            let left = evaluate_call_aware_integer(
                context,
                symbol_count,
                tree,
                left,
                ty,
                constants,
                depth,
            )?;
            let right = evaluate_call_aware_integer(
                context,
                symbol_count,
                tree,
                right,
                ty,
                constants,
                depth,
            )?;
            let ordering = if ty.is_signed() {
                let bits = ty
                    .bits(context.target.pointer_bits())
                    .ok_or(SemanticErrorKind::UnsupportedConstCall)?;
                decode_signed(left, bits).cmp(&decode_signed(right, bits))
            } else {
                left.cmp(&right)
            };
            Ok(compare_ordering(operator, ordering))
        }
        _ => Err(SemanticErrorKind::Execution(ExecutionError::Arithmetic(
            ConstEvalError::InvalidCast,
        ))),
    }
}

fn evaluate_call_aware_unsigned_binary(
    operator: BinaryOperator,
    left: u128,
    right: u128,
    bits: u8,
) -> Result<u128, ConstEvalError> {
    let maximum = signed_mask(bits);
    let checked = |value: Option<u128>| {
        value
            .filter(|value| *value <= maximum)
            .ok_or(ConstEvalError::Overflow)
    };
    match operator {
        BinaryOperator::Add => checked(left.checked_add(right)),
        BinaryOperator::Subtract => checked(left.checked_sub(right)),
        BinaryOperator::Multiply => checked(left.checked_mul(right)),
        BinaryOperator::Divide if right == 0 => Err(ConstEvalError::DivisionByZero),
        BinaryOperator::Divide => Ok(left / right),
        BinaryOperator::Remainder if right == 0 => Err(ConstEvalError::DivisionByZero),
        BinaryOperator::Remainder => Ok(left % right),
        BinaryOperator::BitAnd => Ok(left & right),
        BinaryOperator::BitOr => Ok(left | right),
        BinaryOperator::BitXor => Ok(left ^ right),
        BinaryOperator::ShiftLeft | BinaryOperator::ShiftRight => {
            let distance = u32::try_from(right).map_err(|_| ConstEvalError::InvalidShift)?;
            if distance >= u32::from(bits) {
                return Err(ConstEvalError::InvalidShift);
            }
            if operator == BinaryOperator::ShiftLeft {
                checked(left.checked_shl(distance))
            } else {
                Ok(left >> distance)
            }
        }
        _ => Err(ConstEvalError::InvalidCast),
    }
}

fn evaluate_call_aware_signed_binary(
    operator: BinaryOperator,
    left_bits: u128,
    right_bits: u128,
    bits: u8,
) -> Result<u128, ConstEvalError> {
    let left = decode_signed(left_bits, bits);
    let right = decode_signed(right_bits, bits);
    let encode = |value: Option<i128>| {
        encode_signed(value.ok_or(ConstEvalError::Overflow)?, bits).map_err(|error| match error {
            ExecutionError::Arithmetic(error) => error,
            _ => ConstEvalError::InvalidExpressionTree,
        })
    };
    match operator {
        BinaryOperator::Add => encode(left.checked_add(right)),
        BinaryOperator::Subtract => encode(left.checked_sub(right)),
        BinaryOperator::Multiply => encode(left.checked_mul(right)),
        BinaryOperator::Divide if right == 0 => Err(ConstEvalError::DivisionByZero),
        BinaryOperator::Divide => encode(left.checked_div(right)),
        BinaryOperator::Remainder if right == 0 => Err(ConstEvalError::DivisionByZero),
        BinaryOperator::Remainder => encode(left.checked_rem(right)),
        BinaryOperator::BitAnd => Ok(left_bits & right_bits),
        BinaryOperator::BitOr => Ok(left_bits | right_bits),
        BinaryOperator::BitXor => Ok(left_bits ^ right_bits),
        BinaryOperator::ShiftLeft | BinaryOperator::ShiftRight => {
            let distance = u32::try_from(right).map_err(|_| ConstEvalError::InvalidShift)?;
            if distance >= u32::from(bits) {
                return Err(ConstEvalError::InvalidShift);
            }
            if operator == BinaryOperator::ShiftLeft {
                encode(left.checked_shl(distance))
            } else {
                encode(left.checked_shr(distance))
            }
        }
        _ => Err(ConstEvalError::InvalidCast),
    }
}

#[derive(Clone, Copy)]
enum ComparisonInteger {
    Signed(i128),
    Unsigned(u128),
}

fn evaluate_boolean_constant<R: ConstantResolver, const MAX_NODES: usize>(
    tree: &ExpressionTree<'_, MAX_NODES>,
    id: ExprId,
    constants: &R,
    depth: usize,
) -> Result<bool, ExecutionError> {
    if depth == 64 {
        return Err(ExecutionError::Arithmetic(
            ConstEvalError::NestingLimitExceeded,
        ));
    }
    let expression = tree.expression(id).ok_or(ExecutionError::Arithmetic(
        ConstEvalError::InvalidExpressionTree,
    ))?;
    match expression.kind {
        ExprKind::Bool(value) => Ok(value),
        ExprKind::InlineConst { operand } => {
            evaluate_boolean_constant(tree, operand, constants, depth + 1)
        }
        ExprKind::Identifier(name) if constants.resolves_bool(name) => constants
            .resolve(name)
            .map(|value| value != 0)
            .ok_or(ExecutionError::UnknownConstant),
        ExprKind::UnsignedIntegerPredicate { base, argument, .. } => {
            let base_type = expression_integer_type(tree, base, constants)
                .filter(|ty| !ty.is_signed())
                .ok_or(ExecutionError::Arithmetic(ConstEvalError::InvalidCast))?;
            if argument.is_some_and(|argument| {
                expression_integer_type(tree, argument, constants)
                    .is_some_and(|argument_type| argument_type != base_type)
            }) {
                return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidCast));
            }
            tree.evaluate_at(id, constants)
                .map(|value| value != 0)
                .map_err(ExecutionError::Arithmetic)
        }
        ExprKind::SignedIntegerPredicate { base, positive } => {
            let base_type = expression_integer_type(tree, base, constants)
                .filter(|ty| ty.is_signed())
                .ok_or(ExecutionError::Arithmetic(ConstEvalError::InvalidCast))?;
            let bits = base_type
                .bits(64)
                .ok_or(ExecutionError::Arithmetic(ConstEvalError::InvalidCast))?;
            let value = tree
                .evaluate_at(base, constants)
                .map_err(ExecutionError::Arithmetic)?;
            let value = decode_signed(value & signed_mask(bits), bits);
            Ok(if positive { value > 0 } else { value < 0 })
        }
        ExprKind::AsciiPredicate { base, .. } => {
            if expression_integer_type(tree, base, constants) != Some(crate::IntegerType::U8) {
                return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidCast));
            }
            tree.evaluate_at(id, constants)
                .map(|value| value != 0)
                .map_err(ExecutionError::Arithmetic)
        }
        ExprKind::Unary {
            operator: UnaryOperator::Not,
            operand,
        } => Ok(!evaluate_boolean_constant(
            tree,
            operand,
            constants,
            depth + 1,
        )?),
        ExprKind::If {
            condition,
            then_branch,
            else_branch,
        } => {
            if evaluate_boolean_constant(tree, condition, constants, depth + 1)? {
                evaluate_boolean_constant(tree, then_branch, constants, depth + 1)
            } else {
                evaluate_boolean_constant(tree, else_branch, constants, depth + 1)
            }
        }
        ExprKind::Binary {
            operator,
            left,
            right,
        } if matches!(
            operator,
            BinaryOperator::LogicalAnd
                | BinaryOperator::LogicalOr
                | BinaryOperator::BitAnd
                | BinaryOperator::BitOr
                | BinaryOperator::BitXor
        ) =>
        {
            let left = evaluate_boolean_constant(tree, left, constants, depth + 1)?;
            if operator == BinaryOperator::LogicalAnd && !left {
                return Ok(false);
            }
            if operator == BinaryOperator::LogicalOr && left {
                return Ok(true);
            }
            let right = evaluate_boolean_constant(tree, right, constants, depth + 1)?;
            Ok(match operator {
                BinaryOperator::LogicalAnd | BinaryOperator::BitAnd => left && right,
                BinaryOperator::LogicalOr | BinaryOperator::BitOr => left || right,
                BinaryOperator::BitXor => left != right,
                _ => false,
            })
        }
        ExprKind::Binary {
            operator,
            left,
            right,
        } if matches!(
            operator,
            BinaryOperator::Equal
                | BinaryOperator::NotEqual
                | BinaryOperator::Less
                | BinaryOperator::LessEqual
                | BinaryOperator::Greater
                | BinaryOperator::GreaterEqual
        ) =>
        {
            if let (Ok(left), Ok(right)) = (
                evaluate_boolean_constant(tree, left, constants, depth + 1),
                evaluate_boolean_constant(tree, right, constants, depth + 1),
            ) {
                return Ok(compare_ordering(operator, left.cmp(&right)));
            }
            let left_type = expression_integer_type(tree, left, constants);
            let right_type = expression_integer_type(tree, right, constants);
            if left_type.is_some() && right_type.is_some() && left_type != right_type {
                return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidCast));
            }
            let inferred_type = left_type.or(right_type).unwrap_or(crate::IntegerType::I32);
            let left = evaluate_comparison_integer(tree, left, inferred_type, constants)?;
            let right = evaluate_comparison_integer(tree, right, inferred_type, constants)?;
            let ordering = match (left, right) {
                (ComparisonInteger::Signed(left), ComparisonInteger::Signed(right)) => {
                    left.cmp(&right)
                }
                (ComparisonInteger::Unsigned(left), ComparisonInteger::Unsigned(right)) => {
                    left.cmp(&right)
                }
                _ => return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidCast)),
            };
            Ok(compare_ordering(operator, ordering))
        }
        _ => Err(ExecutionError::Arithmetic(ConstEvalError::InvalidCast)),
    }
}

fn compare_ordering(operator: BinaryOperator, ordering: core::cmp::Ordering) -> bool {
    match operator {
        BinaryOperator::Equal => ordering.is_eq(),
        BinaryOperator::NotEqual => !ordering.is_eq(),
        BinaryOperator::Less => ordering.is_lt(),
        BinaryOperator::LessEqual => !ordering.is_gt(),
        BinaryOperator::Greater => ordering.is_gt(),
        BinaryOperator::GreaterEqual => !ordering.is_lt(),
        _ => false,
    }
}

fn evaluate_comparison_integer<R: ConstantResolver, const MAX_NODES: usize>(
    tree: &ExpressionTree<'_, MAX_NODES>,
    id: ExprId,
    inferred_type: crate::IntegerType,
    constants: &R,
) -> Result<ComparisonInteger, ExecutionError> {
    let expression = tree.expression(id).ok_or(ExecutionError::Arithmetic(
        ConstEvalError::InvalidExpressionTree,
    ))?;
    match expression.kind {
        ExprKind::InlineConst { operand } => {
            evaluate_comparison_integer(tree, operand, inferred_type, constants)
        }
        ExprKind::Integer(literal) => {
            if literal
                .suffix
                .and_then(crate::IntegerType::from_name)
                .is_some_and(|ty| ty.is_signed())
            {
                i128::try_from(literal.value)
                    .map(ComparisonInteger::Signed)
                    .map_err(|_| ExecutionError::Arithmetic(ConstEvalError::Overflow))
            } else if literal.suffix.is_none() {
                if inferred_type.is_signed() {
                    i128::try_from(literal.value)
                        .map(ComparisonInteger::Signed)
                        .map_err(|_| ExecutionError::Arithmetic(ConstEvalError::Overflow))
                } else {
                    Ok(ComparisonInteger::Unsigned(literal.value))
                }
            } else {
                Ok(ComparisonInteger::Unsigned(literal.value))
            }
        }
        ExprKind::Unary {
            operator: UnaryOperator::Negate,
            operand,
        } => match tree.expression(operand).map(|operand| operand.kind) {
            Some(ExprKind::Integer(literal)) => {
                let magnitude = i128::try_from(literal.value)
                    .map_err(|_| ExecutionError::Arithmetic(ConstEvalError::Overflow))?;
                Ok(ComparisonInteger::Signed(-magnitude))
            }
            _ => Err(ExecutionError::Arithmetic(ConstEvalError::InvalidCast)),
        },
        ExprKind::Identifier(name) => {
            let ty = constants
                .resolve_type(name)
                .ok_or(ExecutionError::Arithmetic(ConstEvalError::InvalidCast))?;
            let value = constants
                .resolve(name)
                .ok_or(ExecutionError::UnknownConstant)?;
            if ty.is_signed() {
                let bits = ty
                    .bits(64)
                    .ok_or(ExecutionError::Arithmetic(ConstEvalError::InvalidCast))?;
                Ok(ComparisonInteger::Signed(decode_signed(value, bits)))
            } else {
                Ok(ComparisonInteger::Unsigned(value))
            }
        }
        ExprKind::Binary { .. } | ExprKind::If { .. } | ExprKind::Cast { .. } => {
            let ty = expression_integer_type(tree, id, constants).unwrap_or(inferred_type);
            if ty.is_signed() {
                let value =
                    evaluate_signed_integer(tree, id, ty, TargetLayout::X86_64, constants, 0)?;
                let bits = ty
                    .bits(64)
                    .ok_or(ExecutionError::Arithmetic(ConstEvalError::InvalidCast))?;
                Ok(ComparisonInteger::Signed(decode_signed(value, bits)))
            } else {
                let value = tree
                    .evaluate_at(id, constants)
                    .map_err(ExecutionError::Arithmetic)?;
                let bits = ty
                    .bits(64)
                    .ok_or(ExecutionError::Arithmetic(ConstEvalError::InvalidCast))?;
                if value > signed_mask(bits) {
                    return Err(ExecutionError::Arithmetic(ConstEvalError::Overflow));
                }
                Ok(ComparisonInteger::Unsigned(value))
            }
        }
        _ => Err(ExecutionError::Arithmetic(ConstEvalError::InvalidCast)),
    }
}

fn evaluate_signed_integer<R: ConstantResolver, const MAX_NODES: usize>(
    tree: &ExpressionTree<'_, MAX_NODES>,
    id: ExprId,
    ty: crate::IntegerType,
    target: TargetLayout,
    constants: &R,
    depth: usize,
) -> Result<u128, ExecutionError> {
    if depth == 64 {
        return Err(ExecutionError::Arithmetic(
            ConstEvalError::NestingLimitExceeded,
        ));
    }
    let bits = ty
        .bits(target.pointer_bits())
        .ok_or(ExecutionError::Arithmetic(ConstEvalError::InvalidCast))?;
    let expression = tree.expression(id).ok_or(ExecutionError::Arithmetic(
        ConstEvalError::InvalidExpressionTree,
    ))?;
    let recurse =
        |operand| evaluate_signed_integer(tree, operand, ty, target, constants, depth + 1);
    let value = match expression.kind {
        ExprKind::InlineConst { operand } => recurse(operand)?,
        ExprKind::Integer(literal) => {
            if literal.suffix.is_some_and(|suffix| suffix != ty.name())
                || literal.value > signed_maximum(bits) as u128
            {
                return Err(ExecutionError::Arithmetic(ConstEvalError::Overflow));
            }
            literal.value
        }
        ExprKind::Identifier(name) => {
            if constants.resolve_type(name) != Some(ty) {
                return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidCast));
            }
            constants
                .resolve(name)
                .ok_or(ExecutionError::UnknownConstant)?
        }
        ExprKind::Unary {
            operator: UnaryOperator::Negate,
            operand,
        } => {
            if let Some(ExprKind::Integer(literal)) =
                tree.expression(operand).map(|operand| operand.kind)
            {
                let limit = 1u128 << (bits - 1);
                if literal.suffix.is_some_and(|suffix| suffix != ty.name()) || literal.value > limit
                {
                    return Err(ExecutionError::Arithmetic(ConstEvalError::Overflow));
                }
                0u128.wrapping_sub(literal.value) & signed_mask(bits)
            } else {
                let operand = decode_signed(recurse(operand)?, bits);
                encode_signed(
                    operand
                        .checked_neg()
                        .ok_or(ExecutionError::Arithmetic(ConstEvalError::Overflow))?,
                    bits,
                )?
            }
        }
        ExprKind::Unary {
            operator: UnaryOperator::Not,
            operand,
        } => !recurse(operand)? & signed_mask(bits),
        ExprKind::Cast {
            operand,
            target: cast,
        } => {
            if cast != crate::CastType::Integer(ty) {
                return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidCast));
            }
            let source_type = expression_integer_type(tree, operand, constants).unwrap_or(ty);
            if source_type.is_signed() {
                let operand = evaluate_signed_integer(
                    tree,
                    operand,
                    source_type,
                    target,
                    constants,
                    depth + 1,
                )?;
                let source_bits = source_type
                    .bits(target.pointer_bits())
                    .ok_or(ExecutionError::Arithmetic(ConstEvalError::InvalidCast))?;
                encode_signed(decode_signed(operand, source_bits), bits)?
            } else {
                let operand = match tree.expression(operand).map(|operand| operand.kind) {
                    Some(ExprKind::Integer(literal)) => literal.value,
                    Some(ExprKind::Identifier(name))
                        if constants.resolve_type(name) == Some(source_type) =>
                    {
                        constants
                            .resolve(name)
                            .ok_or(ExecutionError::UnknownConstant)?
                    }
                    _ => return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidCast)),
                };
                operand & signed_mask(bits)
            }
        }
        ExprKind::If {
            condition,
            then_branch,
            else_branch,
        } => {
            if evaluate_boolean_constant(tree, condition, constants, depth + 1)? {
                recurse(then_branch)?
            } else {
                recurse(else_branch)?
            }
        }
        ExprKind::Binary {
            operator,
            left,
            right,
        } => {
            let left_bits = recurse(left)?;
            let right_bits = recurse(right)?;
            let left = decode_signed(left_bits, bits);
            let right = decode_signed(right_bits, bits);
            let arithmetic = |result: Option<i128>| {
                encode_signed(
                    result.ok_or(ExecutionError::Arithmetic(ConstEvalError::Overflow))?,
                    bits,
                )
            };
            match operator {
                BinaryOperator::Add => arithmetic(left.checked_add(right))?,
                BinaryOperator::Subtract => arithmetic(left.checked_sub(right))?,
                BinaryOperator::Multiply => arithmetic(left.checked_mul(right))?,
                BinaryOperator::Divide => {
                    if right == 0 {
                        return Err(ExecutionError::Arithmetic(ConstEvalError::DivisionByZero));
                    }
                    arithmetic(left.checked_div(right))?
                }
                BinaryOperator::Remainder => {
                    if right == 0 {
                        return Err(ExecutionError::Arithmetic(ConstEvalError::DivisionByZero));
                    }
                    arithmetic(left.checked_rem(right))?
                }
                BinaryOperator::BitAnd => left_bits & right_bits,
                BinaryOperator::BitOr => left_bits | right_bits,
                BinaryOperator::BitXor => left_bits ^ right_bits,
                BinaryOperator::ShiftLeft => {
                    let distance = u32::try_from(right)
                        .map_err(|_| ExecutionError::Arithmetic(ConstEvalError::InvalidShift))?;
                    if distance >= u32::from(bits) {
                        return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidShift));
                    }
                    arithmetic(left.checked_shl(distance))?
                }
                BinaryOperator::ShiftRight => {
                    let distance = u32::try_from(right)
                        .map_err(|_| ExecutionError::Arithmetic(ConstEvalError::InvalidShift))?;
                    if distance >= u32::from(bits) {
                        return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidShift));
                    }
                    arithmetic(left.checked_shr(distance))?
                }
                _ => {
                    return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidCast));
                }
            }
        }
        ExprKind::IntegerRotate {
            base,
            distance,
            left,
        } => {
            let base_type = expression_integer_type(tree, base, constants);
            if base_type.is_some_and(|base_type| base_type != ty)
                || (base_type.is_none() && ty != crate::IntegerType::I32)
                || expression_integer_type(tree, distance, constants)
                    .is_some_and(|distance_type| distance_type != crate::IntegerType::U32)
            {
                return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidCast));
            }
            let value = recurse(base)?;
            let distance = tree
                .evaluate_at(distance, constants)
                .map_err(ExecutionError::Arithmetic)?;
            rotate_integer_bits(value, distance, bits, left)
        }
        ExprKind::IntegerFunnelShift {
            base,
            other,
            distance,
            left,
        } => {
            if ty.is_signed()
                || expression_integer_type(tree, base, constants).is_some_and(|actual| actual != ty)
                || expression_integer_type(tree, other, constants)
                    .is_some_and(|actual| actual != ty)
                || expression_integer_type(tree, distance, constants)
                    .is_some_and(|actual| actual != crate::IntegerType::U32)
            {
                return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidCast));
            }
            let first = recurse(base)? & signed_mask(bits);
            let second = recurse(other)? & signed_mask(bits);
            let distance = tree
                .evaluate_at(distance, constants)
                .map_err(ExecutionError::Arithmetic)?;
            if distance >= u128::from(bits) {
                return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidShift));
            }
            funnel_shift_bits(first, second, distance, bits, left)
        }
        ExprKind::IntegerSignCast {
            base,
            signed,
            saturating,
            strict,
        } => {
            if ty.is_signed() != signed {
                return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidCast));
            }
            let source_type = if signed {
                ty.unsigned_counterpart()
            } else {
                ty.signed_counterpart()
            }
            .ok_or(ExecutionError::Arithmetic(ConstEvalError::InvalidCast))?;
            if expression_integer_type(tree, base, constants)
                .is_some_and(|actual| actual != source_type)
            {
                return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidCast));
            }
            let value = recurse(base)? & signed_mask(bits);
            sign_cast_bits(value, bits, signed, saturating, strict)
                .map_err(ExecutionError::Arithmetic)?
        }
        ExprKind::IntegerWidthCast {
            base,
            target: cast_target,
            mode,
        } => {
            if ty != cast_target {
                return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidCast));
            }
            let source_type = expression_integer_type(tree, base, constants)
                .ok_or(ExecutionError::Arithmetic(ConstEvalError::InvalidCast))?;
            if !source_type.supports_width_cast(cast_target, mode) {
                return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidCast));
            }
            let source_bits = source_type
                .bits(target.pointer_bits())
                .ok_or(ExecutionError::Arithmetic(ConstEvalError::InvalidCast))?;
            let value =
                evaluate_signed_integer(tree, base, source_type, target, constants, depth + 1)?;
            width_cast_bits(
                value,
                source_bits,
                bits,
                source_type.is_signed(),
                cast_target.is_signed(),
                mode,
            )
            .map_err(ExecutionError::Arithmetic)?
        }
        ExprKind::IntegerClampMagnitude { .. } => {
            return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidCast));
        }
        ExprKind::IntegerEndianFrom {
            value,
            integer_type,
            little,
        } => {
            if ty != integer_type
                || expression_integer_type(tree, value, constants)
                    .is_some_and(|actual| actual != integer_type)
            {
                return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidCast));
            }
            let value = recurse(value)?;
            transform_integer_bits(
                value,
                bits,
                if little {
                    crate::expression::IntegerBitTransform::ToLittleEndian
                } else {
                    crate::expression::IntegerBitTransform::ToBigEndian
                },
            )
        }
        ExprKind::IntegerFromBytes {
            bytes: byte_array,
            integer_type,
            order,
        } => {
            if ty != integer_type {
                return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidCast));
            }
            let value = tree
                .evaluate_byte_array(byte_array, usize::from(bits / 8), constants)
                .map_err(ExecutionError::Arithmetic)?;
            integer_from_packed_bytes(value, bits, order)
        }
        ExprKind::IntegerAssociatedConstant {
            integer_type,
            constant,
        } => integer_associated_constant_value(integer_type, constant, ty, target)
            .map_err(ExecutionError::Arithmetic)?,
        ExprKind::IntegerWrappingShift {
            base,
            distance,
            left,
            unbounded,
            strict,
        } => {
            let base_type = expression_integer_type(tree, base, constants);
            if base_type.is_some_and(|base_type| base_type != ty)
                || (base_type.is_none() && ty != crate::IntegerType::I32)
                || expression_integer_type(tree, distance, constants)
                    .is_some_and(|distance_type| distance_type != crate::IntegerType::U32)
            {
                return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidCast));
            }
            let value = recurse(base)?;
            let distance = tree
                .evaluate_at(distance, constants)
                .map_err(ExecutionError::Arithmetic)?;
            if strict && distance >= u128::from(bits) {
                return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidShift));
            }
            shift_integer_bits(value, distance, bits, left, true, unbounded)
        }
        ExprKind::IntegerWrappingPower {
            base,
            exponent,
            mode,
        } => {
            let base_type = expression_integer_type(tree, base, constants);
            if base_type.is_some_and(|base_type| base_type != ty)
                || (base_type.is_none() && ty != crate::IntegerType::I32)
                || expression_integer_type(tree, exponent, constants)
                    .is_some_and(|exponent_type| exponent_type != crate::IntegerType::U32)
            {
                return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidCast));
            }
            let value = recurse(base)?;
            let exponent = tree
                .evaluate_at(exponent, constants)
                .map_err(ExecutionError::Arithmetic)?;
            integer_power_bits(value, exponent, bits, true, mode)
                .map_err(ExecutionError::Arithmetic)?
        }
        ExprKind::IntegerBitTransform { base, transform } => {
            let base_type = expression_integer_type(tree, base, constants);
            if base_type.is_some_and(|base_type| base_type != ty)
                || (base_type.is_none() && ty != crate::IntegerType::I32)
                || matches!(
                    transform,
                    crate::expression::IntegerBitTransform::NextPowerOfTwo
                        | crate::expression::IntegerBitTransform::WrappingNextPowerOfTwo
                )
            {
                return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidCast));
            }
            let value = recurse(base)?;
            if transform == crate::expression::IntegerBitTransform::StrictNegate
                && value == 1_u128 << (bits - 1)
            {
                return Err(ExecutionError::Arithmetic(ConstEvalError::Overflow));
            }
            if transform == crate::expression::IntegerBitTransform::IntegerSquareRoot
                && value & (1_u128 << (bits - 1)) != 0
            {
                return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidCast));
            }
            if matches!(
                transform,
                crate::expression::IntegerBitTransform::Absolute
                    | crate::expression::IntegerBitTransform::StrictAbsolute
            ) && value == 1_u128 << (bits - 1)
            {
                return Err(ExecutionError::Arithmetic(ConstEvalError::Overflow));
            }
            transform_integer_bits(value, bits, transform)
        }
        ExprKind::WrappingArithmetic {
            base,
            argument,
            operator,
            euclidean,
            euclidean_wrapping,
            strict,
            mixed_signedness,
        } => {
            let base_type = expression_integer_type(tree, base, constants);
            let argument_type = if mixed_signedness {
                ty.unsigned_counterpart()
            } else {
                Some(ty)
            };
            if base_type.is_some_and(|base_type| base_type != ty)
                || (base_type.is_none() && ty != crate::IntegerType::I32)
                || expression_integer_type(tree, argument, constants)
                    .is_some_and(|actual| Some(actual) != argument_type)
            {
                return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidCast));
            }
            let left = recurse(base)?;
            let right = recurse(argument)?;
            if euclidean {
                return euclidean_integer_arithmetic(
                    left,
                    right,
                    bits,
                    true,
                    operator,
                    euclidean_wrapping,
                )
                .map_err(ExecutionError::Arithmetic);
            }
            if strict {
                if mixed_signedness {
                    return strict_mixed_integer_arithmetic(left, right, bits, true, operator)
                        .map_err(ExecutionError::Arithmetic);
                }
                return evaluate_call_aware_signed_binary(operator, left, right, bits)
                    .map_err(ExecutionError::Arithmetic);
            }
            match operator {
                BinaryOperator::Add => left.overflowing_add(right).0,
                BinaryOperator::Subtract => left.overflowing_sub(right).0,
                BinaryOperator::Multiply => left.overflowing_mul(right).0,
                BinaryOperator::Divide | BinaryOperator::Remainder => {
                    if right == 0 {
                        return Err(ExecutionError::Arithmetic(ConstEvalError::DivisionByZero));
                    }
                    let minimum = 1_u128 << (bits - 1);
                    if left == minimum && right == signed_mask(bits) {
                        if operator == BinaryOperator::Divide {
                            minimum
                        } else {
                            0
                        }
                    } else {
                        evaluate_call_aware_signed_binary(operator, left, right, bits)
                            .map_err(ExecutionError::Arithmetic)?
                    }
                }
                _ => {
                    return Err(ExecutionError::Arithmetic(
                        ConstEvalError::InvalidExpressionTree,
                    ));
                }
            }
        }
        ExprKind::SaturatingArithmetic {
            base,
            argument,
            operator,
            mixed_signedness,
        } => {
            let base_type = expression_integer_type(tree, base, constants);
            let argument_type = if mixed_signedness {
                ty.unsigned_counterpart()
            } else {
                Some(ty)
            };
            if base_type.is_some_and(|base_type| base_type != ty)
                || (base_type.is_none() && ty != crate::IntegerType::I32)
                || expression_integer_type(tree, argument, constants)
                    .is_some_and(|actual| Some(actual) != argument_type)
            {
                return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidCast));
            }
            let left = recurse(base)?;
            let right = recurse(argument)?;
            if operator == BinaryOperator::Divide && right & signed_mask(bits) == 0 {
                return Err(ExecutionError::Arithmetic(ConstEvalError::DivisionByZero));
            }
            if mixed_signedness {
                saturating_mixed_integer_arithmetic(left, right, bits, true, operator)
            } else {
                saturating_integer_arithmetic(left, right, bits, true, operator)
            }
        }
        _ => return Err(ExecutionError::Arithmetic(ConstEvalError::InvalidCast)),
    };
    Ok(value & signed_mask(bits))
}

fn expression_integer_type<R: ConstantResolver, const MAX_NODES: usize>(
    tree: &ExpressionTree<'_, MAX_NODES>,
    id: ExprId,
    constants: &R,
) -> Option<crate::IntegerType> {
    match tree.expression(id)?.kind {
        ExprKind::InlineConst { operand } => expression_integer_type(tree, operand, constants),
        ExprKind::Integer(literal) => literal.suffix.and_then(crate::IntegerType::from_name),
        ExprKind::Identifier(name) => constants.resolve_type(name),
        ExprKind::Cast {
            target: crate::CastType::Integer(target),
            ..
        } => Some(target),
        ExprKind::Cast {
            target: crate::CastType::RawPointer { .. },
            ..
        } => None,
        ExprKind::Unary { operand, .. } => expression_integer_type(tree, operand, constants),
        ExprKind::Binary { left, right, .. } => expression_integer_type(tree, left, constants)
            .or_else(|| expression_integer_type(tree, right, constants)),
        ExprKind::WrappingArithmetic { base, .. } => expression_integer_type(tree, base, constants),
        ExprKind::SaturatingArithmetic { base, .. } => {
            expression_integer_type(tree, base, constants)
        }
        ExprKind::IntegerRotate { base, .. } => expression_integer_type(tree, base, constants),
        ExprKind::IntegerFunnelShift { base, .. } => expression_integer_type(tree, base, constants),
        ExprKind::IntegerSignCast { base, signed, .. } => {
            let source =
                expression_integer_type(tree, base, constants).unwrap_or(crate::IntegerType::I32);
            if signed {
                source.signed_counterpart()
            } else {
                source.unsigned_counterpart()
            }
        }
        ExprKind::IntegerWidthCast { target, .. } => Some(target),
        ExprKind::IntegerClampMagnitude { base, .. } => {
            expression_integer_type(tree, base, constants)
        }
        ExprKind::IntegerEndianFrom { integer_type, .. } => Some(integer_type),
        ExprKind::IntegerFromBytes { integer_type, .. } => Some(integer_type),
        ExprKind::IntegerAssociatedConstant {
            integer_type,
            constant,
        } => Some(
            if constant == crate::expression::IntegerAssociatedConstant::Bits {
                crate::IntegerType::U32
            } else {
                integer_type
            },
        ),
        ExprKind::IntegerWrappingShift { base, .. } => {
            expression_integer_type(tree, base, constants)
        }
        ExprKind::IntegerWrappingPower { base, .. } => {
            expression_integer_type(tree, base, constants)
        }
        ExprKind::IntegerBitTransform { base, .. } => {
            expression_integer_type(tree, base, constants)
        }
        ExprKind::IntegerUnsignedAbsolute { base } => {
            expression_integer_type(tree, base, constants)
                .unwrap_or(crate::IntegerType::I32)
                .unsigned_counterpart()
        }
        ExprKind::IntegerPairTransform {
            base, transform, ..
        } => {
            let base_type =
                expression_integer_type(tree, base, constants).unwrap_or(crate::IntegerType::I32);
            Some(
                if transform == crate::expression::IntegerPairTransform::AbsoluteDifference {
                    base_type.unsigned_counterpart().unwrap_or(base_type)
                } else {
                    base_type
                },
            )
        }
        ExprKind::IntegerClamp { base, .. } => expression_integer_type(tree, base, constants),
        ExprKind::IntegerBitCount { .. } | ExprKind::IntegerLogarithm { .. } => {
            Some(crate::IntegerType::U32)
        }
        ExprKind::If {
            then_branch,
            else_branch,
            ..
        } => expression_integer_type(tree, then_branch, constants)
            .or_else(|| expression_integer_type(tree, else_branch, constants)),
        _ => None,
    }
}

const fn signed_mask(bits: u8) -> u128 {
    if bits == 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    }
}

fn rotate_integer_bits(value: u128, distance: u128, bits: u8, left: bool) -> u128 {
    let mask = signed_mask(bits);
    let distance = (distance % u128::from(bits)) as u32;
    if distance == 0 {
        return value & mask;
    }
    let value = value & mask;
    if left {
        ((value << distance) | (value >> (u32::from(bits) - distance))) & mask
    } else {
        ((value >> distance) | (value << (u32::from(bits) - distance))) & mask
    }
}

fn funnel_shift_bits(first: u128, second: u128, distance: u128, bits: u8, left: bool) -> u128 {
    let distance = distance as u32;
    let mask = signed_mask(bits);
    if distance == 0 {
        return (if left { first } else { second }) & mask;
    }
    let complement = u32::from(bits) - distance;
    if left {
        ((first << distance) | (second >> complement)) & mask
    } else {
        ((first << complement) | (second >> distance)) & mask
    }
}

fn sign_cast_bits(
    value: u128,
    bits: u8,
    signed: bool,
    saturating: bool,
    strict: bool,
) -> Result<u128, ConstEvalError> {
    let sign_bit = 1u128 << (bits - 1);
    let out_of_range = value & sign_bit != 0;
    if strict && out_of_range {
        return Err(ConstEvalError::Overflow);
    }
    if saturating && out_of_range {
        return Ok(if signed { sign_bit - 1 } else { 0 });
    }
    Ok(value & signed_mask(bits))
}

fn width_cast_bits(
    value: u128,
    source_bits: u8,
    target_bits: u8,
    source_signed: bool,
    target_signed: bool,
    mode: crate::expression::IntegerWidthCastMode,
) -> Result<u128, ConstEvalError> {
    use crate::expression::IntegerWidthCastMode;

    let target_mask = signed_mask(target_bits);
    if mode == IntegerWidthCastMode::Unchecked {
        return Err(ConstEvalError::InvalidCast);
    }
    if mode == IntegerWidthCastMode::Wrapping {
        return Ok(value & target_mask);
    }
    if matches!(
        mode,
        IntegerWidthCastMode::Truncate
            | IntegerWidthCastMode::SaturatingTruncate
            | IntegerWidthCastMode::Widen
    ) && !source_signed
    {
        let value = value & signed_mask(source_bits);
        return Ok(if mode == IntegerWidthCastMode::SaturatingTruncate {
            value.min(target_mask)
        } else {
            value & target_mask
        });
    }
    if matches!(
        mode,
        IntegerWidthCastMode::Truncate
            | IntegerWidthCastMode::SaturatingTruncate
            | IntegerWidthCastMode::Widen
    ) {
        let value = decode_signed(value & signed_mask(source_bits), source_bits);
        let value = if mode == IntegerWidthCastMode::SaturatingTruncate {
            value.clamp(
                if target_bits == 128 {
                    i128::MIN
                } else {
                    -(1_i128 << (target_bits - 1))
                },
                signed_maximum(target_bits),
            )
        } else {
            value
        };
        return Ok((value as u128) & target_mask);
    }

    let (below_minimum, above_maximum) = if source_signed {
        let value = decode_signed(value & signed_mask(source_bits), source_bits);
        if target_signed {
            let minimum = if target_bits == 128 {
                i128::MIN
            } else {
                -(1_i128 << (target_bits - 1))
            };
            (value < minimum, value > signed_maximum(target_bits))
        } else {
            (value < 0, value >= 0 && (value as u128) > target_mask)
        }
    } else {
        let value = value & signed_mask(source_bits);
        let maximum = if target_signed {
            signed_maximum(target_bits) as u128
        } else {
            target_mask
        };
        (false, value > maximum)
    };
    if mode == IntegerWidthCastMode::Strict && (below_minimum || above_maximum) {
        return Err(ConstEvalError::Overflow);
    }
    if mode == IntegerWidthCastMode::Saturating {
        if below_minimum {
            return Ok(if target_signed {
                1_u128 << (target_bits - 1)
            } else {
                0
            });
        }
        if above_maximum {
            return Ok(if target_signed {
                signed_maximum(target_bits) as u128
            } else {
                target_mask
            });
        }
    }
    Ok(if source_signed {
        (decode_signed(value & signed_mask(source_bits), source_bits) as u128) & target_mask
    } else {
        value & target_mask
    })
}

fn saturating_integer_arithmetic(
    left: u128,
    right: u128,
    bits: u8,
    signed: bool,
    operator: BinaryOperator,
) -> u128 {
    let mask = signed_mask(bits);
    if signed {
        let left = decode_signed(left & mask, bits);
        let right = decode_signed(right & mask, bits);
        let value = match operator {
            BinaryOperator::Add => left.saturating_add(right),
            BinaryOperator::Subtract => left.saturating_sub(right),
            BinaryOperator::Multiply => left.saturating_mul(right),
            BinaryOperator::Divide => left.saturating_div(right),
            _ => unreachable!(),
        };
        let minimum = if bits == 128 {
            i128::MIN
        } else {
            -(1_i128 << (bits - 1))
        };
        value.clamp(minimum, signed_maximum(bits)) as u128 & mask
    } else {
        match operator {
            BinaryOperator::Add => left.saturating_add(right).min(mask),
            BinaryOperator::Subtract => left.saturating_sub(right),
            BinaryOperator::Multiply => left.saturating_mul(right).min(mask),
            BinaryOperator::Divide => (left & mask) / (right & mask),
            _ => unreachable!(),
        }
    }
}

fn saturating_mixed_integer_arithmetic(
    left: u128,
    right: u128,
    bits: u8,
    receiver_signed: bool,
    operator: BinaryOperator,
) -> u128 {
    match strict_mixed_integer_arithmetic(left, right, bits, receiver_signed, operator) {
        Ok(value) => value,
        Err(ConstEvalError::Overflow) if receiver_signed => match operator {
            BinaryOperator::Add => signed_mask(bits) >> 1,
            BinaryOperator::Subtract => 1_u128 << (bits - 1),
            _ => unreachable!(),
        },
        Err(ConstEvalError::Overflow) => {
            let right_is_negative = decode_signed(right, bits) < 0;
            match (operator, right_is_negative) {
                (BinaryOperator::Add, false) | (BinaryOperator::Subtract, true) => {
                    signed_mask(bits)
                }
                (BinaryOperator::Add, true) | (BinaryOperator::Subtract, false) => 0,
                _ => unreachable!(),
            }
        }
        Err(_) => unreachable!(),
    }
}

fn euclidean_integer_arithmetic(
    left: u128,
    right: u128,
    bits: u8,
    signed: bool,
    operator: BinaryOperator,
    wrapping: bool,
) -> Result<u128, ConstEvalError> {
    let mask = signed_mask(bits);
    let right = right & mask;
    if right == 0 {
        return Err(ConstEvalError::DivisionByZero);
    }
    if !signed {
        return Ok(if operator == BinaryOperator::Divide {
            (left & mask) / right
        } else {
            (left & mask) % right
        });
    }
    let left = decode_signed(left & mask, bits);
    let right = decode_signed(right, bits);
    if wrapping && left == -(1_i128 << (bits - 1)) && right == -1 {
        return Ok(if operator == BinaryOperator::Divide {
            left as u128 & mask
        } else {
            0
        });
    }
    let value = if operator == BinaryOperator::Divide {
        left.checked_div_euclid(right)
    } else {
        left.checked_rem_euclid(right)
    }
    .ok_or(ConstEvalError::Overflow)?;
    Ok(value as u128 & mask)
}

fn absolute_difference_integer_bits(left: u128, right: u128, bits: u8, signed: bool) -> u128 {
    let mask = signed_mask(bits);
    let left = left & mask;
    let right = right & mask;
    let left_first = if signed {
        decode_signed(left, bits) >= decode_signed(right, bits)
    } else {
        left >= right
    };
    if left_first {
        left.wrapping_sub(right) & mask
    } else {
        right.wrapping_sub(left) & mask
    }
}

fn integer_bits_less_than(left: u128, right: u128, bits: u8, signed: bool) -> bool {
    if signed {
        decode_signed(left, bits) < decode_signed(right, bits)
    } else {
        left < right
    }
}

fn integer_from_packed_bytes(
    value: u128,
    bits: u8,
    order: crate::expression::IntegerByteOrder,
) -> u128 {
    if order != crate::expression::IntegerByteOrder::Big {
        return value;
    }
    let bytes = bits / 8;
    let mut result = 0u128;
    let mut index = 0u8;
    while index < bytes {
        result |= (value >> (u32::from(index) * 8) & 0xff) << (u32::from(bytes - index - 1) * 8);
        index += 1;
    }
    result
}

fn midpoint_integer_bits(left: u128, right: u128, bits: u8, signed: bool) -> u128 {
    let mask = signed_mask(bits);
    let left = left & mask;
    let right = right & mask;
    let differing = left ^ right;
    let mut midpoint = if signed && differing & (1_u128 << (bits - 1)) != 0 {
        ((differing | !mask) as i128 >> 1) as u128 & mask
    } else {
        differing >> 1
    }
    .wrapping_add(left & right)
        & mask;
    if signed && midpoint & (1_u128 << (bits - 1)) != 0 {
        midpoint = midpoint.wrapping_add(differing & 1) & mask;
    }
    midpoint
}

fn carryless_multiply_integer_bits(mut left: u128, mut right: u128, bits: u8) -> u128 {
    let mask = signed_mask(bits);
    let mut result = 0_u128;
    while right != 0 {
        if right & 1 != 0 {
            result ^= left;
        }
        left = left.wrapping_shl(1) & mask;
        right >>= 1;
    }
    result & mask
}

fn extract_integer_bits(value: u128, mut mask: u128, bits: u8) -> u128 {
    mask &= signed_mask(bits);
    let mut result = 0_u128;
    let mut output = 1_u128;
    while mask != 0 {
        let selected = mask & 0_u128.wrapping_sub(mask);
        if value & selected != 0 {
            result |= output;
        }
        mask &= mask - 1;
        output = output.wrapping_shl(1);
    }
    result
}

fn deposit_integer_bits(value: u128, mut mask: u128, bits: u8) -> u128 {
    mask &= signed_mask(bits);
    let mut result = 0_u128;
    let mut input = 1_u128;
    while mask != 0 {
        let selected = mask & 0_u128.wrapping_sub(mask);
        if value & input != 0 {
            result |= selected;
        }
        mask &= mask - 1;
        input = input.wrapping_shl(1);
    }
    result
}

fn divide_ceiling_integer_bits(
    left: u128,
    right: u128,
    bits: u8,
    signed: bool,
) -> Result<u128, ConstEvalError> {
    if right == 0 {
        return Err(ConstEvalError::DivisionByZero);
    }
    if !signed {
        return Ok(left / right + u128::from(!left.is_multiple_of(right)));
    }
    let left = decode_signed(left, bits);
    let right = decode_signed(right, bits);
    let quotient = left.checked_div(right).ok_or(ConstEvalError::Overflow)?;
    let remainder = left.checked_rem(right).ok_or(ConstEvalError::Overflow)?;
    let result = if remainder != 0 && (left < 0) == (right < 0) {
        quotient.checked_add(1).ok_or(ConstEvalError::Overflow)?
    } else {
        quotient
    };
    encode_signed(result, bits).map_err(|error| match error {
        ExecutionError::Arithmetic(error) => error,
        _ => ConstEvalError::InvalidExpressionTree,
    })
}

fn divide_floor_integer_bits(
    left: u128,
    right: u128,
    bits: u8,
    signed: bool,
) -> Result<u128, ConstEvalError> {
    if right == 0 {
        return Err(ConstEvalError::DivisionByZero);
    }
    if !signed {
        return Ok(left / right);
    }
    let left = decode_signed(left, bits);
    let right = decode_signed(right, bits);
    let quotient = left.checked_div(right).ok_or(ConstEvalError::Overflow)?;
    let remainder = left.checked_rem(right).ok_or(ConstEvalError::Overflow)?;
    let result = if remainder != 0 && (left < 0) != (right < 0) {
        quotient.checked_sub(1).ok_or(ConstEvalError::Overflow)?
    } else {
        quotient
    };
    encode_signed(result, bits).map_err(|error| match error {
        ExecutionError::Arithmetic(error) => error,
        _ => ConstEvalError::InvalidExpressionTree,
    })
}

fn next_multiple_integer_bits(
    left: u128,
    right: u128,
    bits: u8,
    signed: bool,
) -> Result<u128, ConstEvalError> {
    if right == 0 {
        return Err(ConstEvalError::DivisionByZero);
    }
    if signed {
        let left = decode_signed(left, bits);
        let right = decode_signed(right, bits);
        if right == -1 {
            return Ok(left as u128 & signed_mask(bits));
        }
        let remainder = left.checked_rem(right).ok_or(ConstEvalError::Overflow)?;
        let adjusted = if (remainder > 0 && right < 0) || (remainder < 0 && right > 0) {
            remainder
                .checked_add(right)
                .ok_or(ConstEvalError::Overflow)?
        } else {
            remainder
        };
        let result = if adjusted == 0 {
            left
        } else {
            left.checked_add(
                right
                    .checked_sub(adjusted)
                    .ok_or(ConstEvalError::Overflow)?,
            )
            .ok_or(ConstEvalError::Overflow)?
        };
        return encode_signed(result, bits).map_err(|error| match error {
            ExecutionError::Arithmetic(error) => error,
            _ => ConstEvalError::InvalidExpressionTree,
        });
    }
    let remainder = left % right;
    if remainder == 0 {
        return Ok(left);
    }
    left.checked_add(right - remainder)
        .filter(|value| *value <= signed_mask(bits))
        .ok_or(ConstEvalError::Overflow)
}

fn integer_power_bits(
    value: u128,
    mut exponent: u128,
    bits: u8,
    signed: bool,
    mode: crate::expression::IntegerPowerMode,
) -> Result<u128, ConstEvalError> {
    use crate::expression::IntegerPowerMode;
    let mask = signed_mask(bits);
    let mut base = value & mask;
    let mut result = 1_u128;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = match mode {
                IntegerPowerMode::Checked | IntegerPowerMode::Strict => {
                    checked_integer_multiply(result, base, bits, signed)
                        .ok_or(ConstEvalError::Overflow)?
                }
                IntegerPowerMode::Wrapping => result.wrapping_mul(base) & mask,
                IntegerPowerMode::Saturating => saturating_integer_arithmetic(
                    result,
                    base,
                    bits,
                    signed,
                    BinaryOperator::Multiply,
                ),
            };
        }
        exponent >>= 1;
        if exponent == 0 {
            break;
        }
        base = match mode {
            IntegerPowerMode::Checked | IntegerPowerMode::Strict => {
                checked_integer_multiply(base, base, bits, signed)
                    .ok_or(ConstEvalError::Overflow)?
            }
            IntegerPowerMode::Wrapping => base.wrapping_mul(base) & mask,
            IntegerPowerMode::Saturating => {
                saturating_integer_arithmetic(base, base, bits, signed, BinaryOperator::Multiply)
            }
        };
    }
    Ok(result)
}

fn checked_integer_multiply(left: u128, right: u128, bits: u8, signed: bool) -> Option<u128> {
    let mask = signed_mask(bits);
    if signed {
        let value =
            decode_signed(left & mask, bits).checked_mul(decode_signed(right & mask, bits))?;
        let minimum = -(1_i128 << (bits - 1));
        (minimum..=signed_maximum(bits))
            .contains(&value)
            .then_some(value as u128 & mask)
    } else {
        (left & mask)
            .checked_mul(right & mask)
            .filter(|value| *value <= mask)
    }
}

fn shift_integer_bits(
    value: u128,
    distance: u128,
    bits: u8,
    left: bool,
    signed: bool,
    unbounded: bool,
) -> u128 {
    let mask = signed_mask(bits);
    let value = value & mask;
    if unbounded && distance >= u128::from(bits) {
        return if !left && signed && value & (1_u128 << (bits - 1)) != 0 {
            mask
        } else {
            0
        };
    }
    let distance = (distance % u128::from(bits)) as u32;
    if left {
        (value << distance) & mask
    } else if signed && value & (1_u128 << (bits - 1)) != 0 {
        ((value | !mask) as i128 >> distance) as u128 & mask
    } else {
        value >> distance
    }
}

fn transform_integer_bits(
    value: u128,
    bits: u8,
    transform: crate::expression::IntegerBitTransform,
) -> u128 {
    use crate::expression::IntegerBitTransform;
    let mask = signed_mask(bits);
    let value = value & mask;
    match transform {
        IntegerBitTransform::IsolateHighestOne => {
            if value == 0 {
                0
            } else {
                1_u128 << (127 - value.leading_zeros())
            }
        }
        IntegerBitTransform::IsolateLowestOne => value & 0_u128.wrapping_sub(value),
        IntegerBitTransform::SwapBytes | IntegerBitTransform::ToBigEndian => {
            value.swap_bytes() >> (128 - bits)
        }
        IntegerBitTransform::ReverseBits => value.reverse_bits() >> (128 - bits),
        IntegerBitTransform::ToLittleEndian => value,
        IntegerBitTransform::WrappingNegate | IntegerBitTransform::StrictNegate => {
            0_u128.wrapping_sub(value) & mask
        }
        IntegerBitTransform::SaturatingNegate => {
            if value == 1_u128 << (bits - 1) {
                (1_u128 << (bits - 1)) - 1
            } else {
                0_u128.wrapping_sub(value) & mask
            }
        }
        IntegerBitTransform::WrappingAbsolute
        | IntegerBitTransform::Absolute
        | IntegerBitTransform::StrictAbsolute => {
            if value & (1_u128 << (bits - 1)) == 0 {
                value
            } else {
                0_u128.wrapping_sub(value) & mask
            }
        }
        IntegerBitTransform::SaturatingAbsolute => {
            if value == 1_u128 << (bits - 1) {
                (1_u128 << (bits - 1)) - 1
            } else if value & (1_u128 << (bits - 1)) == 0 {
                value
            } else {
                0_u128.wrapping_sub(value) & mask
            }
        }
        IntegerBitTransform::NextPowerOfTwo | IntegerBitTransform::WrappingNextPowerOfTwo => {
            next_power_of_two_integer_bits(value, bits)
        }
        IntegerBitTransform::IntegerSquareRoot => integer_square_root(value, bits),
        IntegerBitTransform::Signum => {
            if value == 0 {
                0
            } else if value & (1_u128 << (bits - 1)) == 0 {
                1
            } else {
                mask
            }
        }
    }
}

fn integer_square_root(mut value: u128, bits: u8) -> u128 {
    let mut result = 0_u128;
    let mut bit = 1_u128 << (bits - 2);
    while bit > value {
        bit >>= 2;
    }
    while bit != 0 {
        if value >= result + bit {
            value -= result + bit;
            result = (result >> 1) + bit;
        } else {
            result >>= 1;
        }
        bit >>= 2;
    }
    result
}

fn next_power_of_two_integer_bits(value: u128, bits: u8) -> u128 {
    let mask = signed_mask(bits);
    let value = value & mask;
    if value <= 1 {
        return 1;
    }
    let mut result = value - 1;
    let mut shift = 1_u32;
    while shift < u32::from(bits) {
        result |= result >> shift;
        shift <<= 1;
    }
    result.wrapping_add(1) & mask
}

fn count_integer_bits(value: u128, bits: u8, count: crate::expression::IntegerBitCount) -> u32 {
    use crate::expression::IntegerBitCount;
    let value = value & signed_mask(bits);
    match count {
        IntegerBitCount::Width => u32::from(bits) - (value << (128 - bits)).leading_zeros(),
        IntegerBitCount::Ones => value.count_ones(),
        IntegerBitCount::Zeros => u32::from(bits) - value.count_ones(),
        IntegerBitCount::LeadingZeros => (value << (128 - bits)).leading_zeros(),
        IntegerBitCount::TrailingZeros => value.trailing_zeros().min(u32::from(bits)),
        IntegerBitCount::LeadingOnes => {
            ((!value & signed_mask(bits)) << (128 - bits)).leading_zeros()
        }
        IntegerBitCount::TrailingOnes => (!value & signed_mask(bits))
            .trailing_zeros()
            .min(u32::from(bits)),
    }
}

fn integer_logarithm(
    value: u128,
    radix: u128,
    bits: u8,
    signed: bool,
) -> Result<u32, ConstEvalError> {
    let mask = signed_mask(bits);
    if value & mask == 0
        || (signed && decode_signed(value & mask, bits) <= 0)
        || radix & mask < 2
        || (signed && decode_signed(radix & mask, bits) < 2)
    {
        return Err(ConstEvalError::InvalidCast);
    }
    let mut value = value & mask;
    let radix = radix & mask;
    let mut result = 0_u32;
    while value >= radix {
        value /= radix;
        result += 1;
    }
    Ok(result)
}

const fn signed_maximum(bits: u8) -> i128 {
    if bits == 128 {
        i128::MAX
    } else {
        (1i128 << (bits - 1)) - 1
    }
}

fn decode_signed(value: u128, bits: u8) -> i128 {
    if bits == 128 {
        value as i128
    } else {
        ((value << (128 - bits)) as i128) >> (128 - bits)
    }
}

fn strict_mixed_integer_arithmetic(
    left: u128,
    right: u128,
    bits: u8,
    receiver_signed: bool,
    operator: BinaryOperator,
) -> Result<u128, ConstEvalError> {
    let mask = signed_mask(bits);
    let left = left & mask;
    let right = right & mask;
    if receiver_signed {
        let signed_left = decode_signed(left, bits);
        let magnitude = signed_left.unsigned_abs();
        let half = 1_u128 << (bits - 1);
        let maximum = half - 1;
        let bound = match operator {
            BinaryOperator::Add if signed_left >= 0 => maximum - signed_left as u128,
            BinaryOperator::Add => maximum + magnitude,
            BinaryOperator::Subtract if signed_left >= 0 => half + signed_left as u128,
            BinaryOperator::Subtract => half - magnitude,
            _ => return Err(ConstEvalError::InvalidExpressionTree),
        };
        if right > bound {
            return Err(ConstEvalError::Overflow);
        }
    } else {
        let signed_right = decode_signed(right, bits);
        let magnitude = signed_right.unsigned_abs();
        let overflows = match (operator, signed_right >= 0) {
            (BinaryOperator::Add, true) | (BinaryOperator::Subtract, false) => {
                left > mask - magnitude
            }
            (BinaryOperator::Add, false) | (BinaryOperator::Subtract, true) => left < magnitude,
            _ => return Err(ConstEvalError::InvalidExpressionTree),
        };
        if overflows {
            return Err(ConstEvalError::Overflow);
        }
    }
    Ok(match operator {
        BinaryOperator::Add => left.wrapping_add(right) & mask,
        BinaryOperator::Subtract => left.wrapping_sub(right) & mask,
        _ => return Err(ConstEvalError::InvalidExpressionTree),
    })
}

fn encode_signed(value: i128, bits: u8) -> Result<u128, ExecutionError> {
    let minimum = if bits == 128 {
        i128::MIN
    } else {
        -(1i128 << (bits - 1))
    };
    if value < minimum || value > signed_maximum(bits) {
        return Err(ExecutionError::Arithmetic(ConstEvalError::Overflow));
    }
    Ok(value as u128 & signed_mask(bits))
}

fn integer_associated_constant_value(
    integer_type: crate::IntegerType,
    constant: crate::expression::IntegerAssociatedConstant,
    expected_type: crate::IntegerType,
    target: TargetLayout,
) -> Result<u128, ConstEvalError> {
    let bits = integer_type
        .bits(target.pointer_bits())
        .ok_or(ConstEvalError::InvalidCast)?;
    let result_type = if constant == crate::expression::IntegerAssociatedConstant::Bits {
        crate::IntegerType::U32
    } else {
        integer_type
    };
    if expected_type != result_type {
        return Err(ConstEvalError::InvalidCast);
    }
    let mask = signed_mask(bits);
    Ok(match constant {
        crate::expression::IntegerAssociatedConstant::Minimum if integer_type.is_signed() => {
            1u128 << (bits - 1)
        }
        crate::expression::IntegerAssociatedConstant::Minimum => 0,
        crate::expression::IntegerAssociatedConstant::Maximum if integer_type.is_signed() => {
            mask >> 1
        }
        crate::expression::IntegerAssociatedConstant::Maximum => mask,
        crate::expression::IntegerAssociatedConstant::Bits => u128::from(bits),
    })
}

fn maximum_unsigned_value(ty: &str, target: TargetLayout) -> u128 {
    match ty {
        "u8" => u128::from(u8::MAX),
        "u16" => u128::from(u16::MAX),
        "u32" => u128::from(u32::MAX),
        "u64" => u128::from(u64::MAX),
        "u128" => u128::MAX,
        "usize" => u128::MAX >> (128 - target.pointer_bits),
        _ => 0,
    }
}
