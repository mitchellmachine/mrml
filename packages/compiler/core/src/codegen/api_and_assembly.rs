use crate::expression::MAX_CALL_ARGUMENTS;
use crate::{
    ConstantResolver, ExecutionError, ExprKind, ExpressionErrorKind, Function, FunctionAbi,
    IrErrorKind, LoopOperation, ParseErrorKind, Span, lower_expression,
};

const MAX_FUNCTION_IR_INSTRUCTIONS: usize = 256;
const MAX_FUNCTION_STACK_VALUES: usize = 64;
const X86_64_RETURN_CONSTANT_BYTES: usize = 11;
const MAX_X86_64_ABI_PARAMETERS: usize = 16;
const MAX_RUNTIME_LOCAL_FACTS: usize = 256;
const MAX_RUNTIME_PLACE_ACCESS_FACTS: usize = 256;
const MAX_RUNTIME_MOVE_PATH_FACTS: usize = (MAX_RUNTIME_LOCAL_FACTS + MAX_X86_64_ABI_PARAMETERS)
    * (crate::expression::MAX_TUPLE_ELEMENTS + 1);
const MAX_RUNTIME_INITIALIZATION_FACTS: usize = 512;
const MAX_RUNTIME_PLACE_EFFECT_FACTS: usize =
    MAX_RUNTIME_LOCAL_FACTS + (MAX_RUNTIME_PLACE_ACCESS_FACTS * 2);
const MAX_RUNTIME_OWNERSHIP_EVENT_FACTS: usize =
    MAX_RUNTIME_INITIALIZATION_FACTS + MAX_RUNTIME_PLACE_EFFECT_FACTS;
const MAX_RUNTIME_EXPRESSION_PROGRAM_POINT_FACTS: usize = MAX_RUNTIME_OWNERSHIP_EVENT_FACTS * 5;
const MAX_RUNTIME_EXPRESSION_CONTROL_FLOW_EDGE_FACTS: usize = MAX_RUNTIME_OWNERSHIP_EVENT_FACTS * 5;
const MAX_RUNTIME_BASIC_BLOCK_FACTS: usize = 64;
const RUNTIME_INITIALIZED_STATE_WORDS: usize = MAX_RUNTIME_MOVE_PATH_FACTS.div_ceil(64);
const MAX_RUNTIME_CONTROL_FLOW_EDGE_FACTS: usize = 128;
const MAX_RUNTIME_OWNERSHIP_CONTROL_POINTS: usize =
    1 + MAX_RUNTIME_BASIC_BLOCK_FACTS + MAX_RUNTIME_CONTROL_FLOW_EDGE_FACTS;
const MAX_RUNTIME_PLACE_PROJECTIONS: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum X86_64Abi {
    SystemV,
    Windows,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodegenOptions {
    pub overflow_checks: bool,
}

impl CodegenOptions {
    pub const CHECKED: Self = Self {
        overflow_checks: true,
    };
    pub const WRAPPING: Self = Self {
        overflow_checks: false,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MachineCode<const MAX_BYTES: usize> {
    bytes: [u8; MAX_BYTES],
    length: usize,
}

impl<const MAX_BYTES: usize> MachineCode<MAX_BYTES> {
    fn from_bytes(source: &[u8]) -> Result<Self, CodegenErrorKind> {
        let mut bytes = [0; MAX_BYTES];
        let output = bytes
            .get_mut(..source.len())
            .ok_or(CodegenErrorKind::OutputTooSmall)?;
        output.copy_from_slice(source);
        Ok(Self {
            bytes,
            length: source.len(),
        })
    }

    #[cfg(test)]
    pub(crate) fn from_bytes_for_test(source: &[u8]) -> Self {
        Self::from_bytes(source).expect("test machine code fits its declared capacity")
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    pub const fn len(&self) -> usize {
        self.length
    }

    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X86_64ExternalRelocation<'symbol> {
    pub offset: usize,
    pub symbol: &'symbol str,
    pub kind: X86_64ExternalRelocationKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum X86_64ExternalRelocationKind {
    Branch,
    RipRelativeMemory,
}

pub const MAX_X86_64_EXTERNAL_RELOCATIONS: usize = 8;
pub const MAX_X86_64_READONLY_DATA_BYTES: usize = 1024;
pub const MAX_X86_64_READONLY_RELOCATIONS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X86_64ReadonlyDataRelocation {
    pub offset: usize,
    pub data_offset: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X86_64RuntimeMachineCode<const MAX_BYTES: usize> {
    pub code: MachineCode<MAX_BYTES>,
    readonly_data: [u8; MAX_X86_64_READONLY_DATA_BYTES],
    readonly_data_length: usize,
    readonly_relocations: [X86_64ReadonlyDataRelocation; MAX_X86_64_READONLY_RELOCATIONS],
    readonly_relocation_count: usize,
}

impl<const MAX_BYTES: usize> X86_64RuntimeMachineCode<MAX_BYTES> {
    pub fn readonly_data(&self) -> &[u8] {
        &self.readonly_data[..self.readonly_data_length]
    }

    pub fn readonly_relocations(&self) -> &[X86_64ReadonlyDataRelocation] {
        &self.readonly_relocations[..self.readonly_relocation_count]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X86_64RelocatableMachineCode<'symbol, const MAX_BYTES: usize> {
    pub code: MachineCode<MAX_BYTES>,
    relocations: [X86_64ExternalRelocation<'symbol>; MAX_X86_64_EXTERNAL_RELOCATIONS],
    relocation_count: usize,
}

impl<'symbol, const MAX_BYTES: usize> X86_64RelocatableMachineCode<'symbol, MAX_BYTES> {
    pub fn relocations(&self) -> &[X86_64ExternalRelocation<'symbol>] {
        &self.relocations[..self.relocation_count]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodegenErrorKind {
    StableExportRequired,
    MrmlV1Signature(crate::MrmlV1SignatureErrorKind),
    MrmlV1MultiwordValueUnsupported,
    ParametersUnsupported,
    TooManyAbiParameters,
    UnsupportedParameterType,
    UnsupportedRuntimeType,
    UnsupportedRuntimeOperator,
    UnknownRuntimeName,
    RuntimeTypeMismatch,
    InvalidRangeType,
    InvalidRangeBounds,
    RangeEndpointOutOfRange,
    RuntimeExpressionUnsupported,
    MissingReturnType,
    UnsupportedReturnType,
    UnsupportedLifetimeElision,
    UnsupportedLifetimeRelation,
    Expression(ExpressionErrorKind),
    Body(ParseErrorKind),
    Lowering(IrErrorKind),
    Execution(ExecutionError),
    ValueOutOfRange,
    OutputTooSmall,
    TooManyRuntimeLocals,
    TooManyRuntimeLocalFacts,
    TooManyRuntimePlaceAccessFacts,
    TooManyRuntimeMovePathFacts,
    TooManyRuntimeInitializationFacts,
    TooManyRuntimePlaceEffectFacts,
    TooManyRuntimeOwnershipEventFacts,
    TooManyRuntimeBasicBlockFacts,
    TooManyRuntimeControlFlowEdgeFacts,
    TooManyRuntimePlaceProjections,
    InvalidRuntimePlaceFacts,
    InvalidRuntimeControlFlowFacts,
    UnsupportedRuntimeControlFlow,
    UnsupportedCStringLiteral,
    RuntimeUseAfterMove,
    RuntimeBorrowConflict,
    RuntimeReferenceOutlivesFunction,
    DuplicateLocal,
    ImmutableAssignment,
    NakedFunctionMustBeUnsafe,
    NakedFunctionRequiresCAbi,
    NakedFunctionParametersUnsupported,
    NakedFunctionReturnUnsupported,
    InvalidNakedAssembly,
    InlineAssemblyRequiresUnsafe,
    InvalidInlineAssembly,
}

#[derive(Clone, Copy)]
struct ConstantLocal<'source> {
    name: &'source str,
    value: u128,
    ty: crate::IntegerType,
    mutable: bool,
}

struct LocalResolver<'values, 'source, R, const MAX_LOCALS: usize> {
    outer: &'values R,
    values: &'values [Option<ConstantLocal<'source>>; MAX_LOCALS],
    count: usize,
}

impl<R: ConstantResolver, const MAX_LOCALS: usize> ConstantResolver
    for LocalResolver<'_, '_, R, MAX_LOCALS>
{
    fn resolve(&self, name: &str) -> Option<u128> {
        self.values[..self.count]
            .iter()
            .rev()
            .flatten()
            .find(|value| value.name == name)
            .map(|value| value.value)
            .or_else(|| self.outer.resolve(name))
    }

    fn resolve_type(&self, name: &str) -> Option<crate::IntegerType> {
        self.values[..self.count]
            .iter()
            .rev()
            .flatten()
            .find(|value| value.name == name)
            .map(|value| value.ty)
            .or_else(|| self.outer.resolve_type(name))
    }

    fn resolves_bool(&self, name: &str) -> bool {
        self.outer.resolves_bool(name)
    }

    fn resolve_call(&self, name: &str, arguments: &[u128]) -> Option<u128> {
        self.outer.resolve_call(name, arguments)
    }

    fn resolve_call_type(&self, name: &str, argument_count: usize) -> Option<crate::IntegerType> {
        self.outer.resolve_call_type(name, argument_count)
    }

    fn call_resolves_bool(&self, name: &str, argument_count: usize) -> bool {
        self.outer.call_resolves_bool(name, argument_count)
    }

    fn resolve_runtime_call<const MAX_PARAMETERS: usize>(
        &self,
        name: &str,
        argument_count: usize,
    ) -> Option<crate::RuntimeCallTarget<'_, MAX_PARAMETERS>> {
        self.outer.resolve_runtime_call(name, argument_count)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodegenError {
    pub kind: CodegenErrorKind,
    pub span: Span,
}

pub fn compile_x86_64_constant_function<
    'source,
    R: ConstantResolver,
    const MAX_BYTES: usize,
    const MAX_PARAMETERS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    function: &Function<'source, MAX_PARAMETERS>,
    resolver: &R,
) -> Result<MachineCode<MAX_BYTES>, CodegenError> {
    if !function.public || function.abi != FunctionAbi::C || !function.no_mangle {
        return Err(CodegenError {
            kind: CodegenErrorKind::StableExportRequired,
            span: function.name_span,
        });
    }
    if function.parameter_count() != 0 {
        return Err(CodegenError {
            kind: CodegenErrorKind::ParametersUnsupported,
            span: function.name_span,
        });
    }
    let return_type = function.return_type.ok_or(CodegenError {
        kind: CodegenErrorKind::MissingReturnType,
        span: function.name_span,
    })?;
    runtime_width(return_type.text).ok_or(CodegenError {
        kind: CodegenErrorKind::UnsupportedReturnType,
        span: return_type.span,
    })?;
    let return_integer_type =
        crate::IntegerType::from_name(return_type.text).ok_or(CodegenError {
            kind: CodegenErrorKind::UnsupportedReturnType,
            span: return_type.span,
        })?;
    let body = function
        .parse_body::<MAX_PARAMETERS>()
        .map_err(|error| CodegenError {
            kind: CodegenErrorKind::Body(error.kind),
            span: translate_span(function.body_expression_span.start, error.span),
        })?;
    let mut local_values: [Option<ConstantLocal<'source>>; MAX_PARAMETERS] = [None; MAX_PARAMETERS];
    let mut local_count = 0usize;
    for local in body.locals().iter().flatten() {
        let tree = local
            .parse_initializer::<MAX_EXPRESSION_NODES>()
            .map_err(|error| CodegenError {
                kind: CodegenErrorKind::Expression(error.kind),
                span: translate_span(
                    function.body_expression_span.start + local.initializer_span.start,
                    error.span,
                ),
            })?;
        let expression_type = runtime_expression_type(function, resolver, &tree, tree.root(), 0)
            .map_err(|kind| CodegenError {
                kind,
                span: translate_span(function.body_expression_span.start, local.initializer_span),
            })?;
        let local_type = if let Some(ty) = local.ty {
            let integer_type = crate::IntegerType::from_name(ty.text).ok_or(CodegenError {
                kind: CodegenErrorKind::UnsupportedRuntimeType,
                span: translate_span(function.body_expression_span.start, ty.span),
            })?;
            if runtime_width(ty.text).is_none() {
                return Err(CodegenError {
                    kind: CodegenErrorKind::UnsupportedRuntimeType,
                    span: translate_span(function.body_expression_span.start, ty.span),
                });
            }
            integer_type
        } else {
            match expression_type {
                RuntimeExpressionType::Never
                | RuntimeExpressionType::Unit
                | RuntimeExpressionType::Default
                | RuntimeExpressionType::Array { .. }
                | RuntimeExpressionType::Tuple { .. }
                | RuntimeExpressionType::Reference { .. }
                | RuntimeExpressionType::RawPointer { .. } => {
                    return Err(CodegenError {
                        kind: CodegenErrorKind::RuntimeTypeMismatch,
                        span: translate_span(
                            function.body_expression_span.start,
                            local.initializer_span,
                        ),
                    });
                }
                RuntimeExpressionType::Integer(Some(ty)) => ty,
                RuntimeExpressionType::Integer(None) => return_integer_type,
                RuntimeExpressionType::Bool | RuntimeExpressionType::Char => {
                    return Err(CodegenError {
                        kind: CodegenErrorKind::RuntimeTypeMismatch,
                        span: translate_span(
                            function.body_expression_span.start,
                            local.initializer_span,
                        ),
                    });
                }
            }
        };
        if !runtime_types_compatible(
            expression_type,
            RuntimeExpressionType::Integer(Some(local_type)),
        ) {
            return Err(CodegenError {
                kind: CodegenErrorKind::RuntimeTypeMismatch,
                span: translate_span(function.body_expression_span.start, local.initializer_span),
            });
        }
        let program = lower_expression::<MAX_FUNCTION_IR_INSTRUCTIONS, MAX_EXPRESSION_NODES>(&tree)
            .map_err(|error| CodegenError {
                kind: CodegenErrorKind::Lowering(error.kind),
                span: translate_span(
                    function.body_expression_span.start + local.initializer_span.start,
                    error.span,
                ),
            })?;
        let resolver = LocalResolver {
            outer: resolver,
            values: &local_values,
            count: local_count,
        };
        let value = program
            .execute::<_, MAX_FUNCTION_STACK_VALUES>(&resolver)
            .map_err(|error| CodegenError {
                kind: CodegenErrorKind::Execution(error),
                span: translate_span(function.body_expression_span.start, local.initializer_span),
            })?;
        if crate::expression::cast_integer(value, local_type, 64) != Ok(value) {
            return Err(CodegenError {
                kind: CodegenErrorKind::ValueOutOfRange,
                span: translate_span(function.body_expression_span.start, local.initializer_span),
            });
        }
        if local.name != "_" {
            local_values[local_count] = Some(ConstantLocal {
                name: local.name,
                value,
                ty: local_type,
                mutable: local.mutable,
            });
            local_count += 1;
        }
    }
    for assignment in body.assignments().iter().flatten() {
        if assignment.index().is_some() {
            return Err(CodegenError {
                kind: CodegenErrorKind::RuntimeExpressionUnsupported,
                span: translate_span(function.body_expression_span.start, assignment.name_span),
            });
        }
        if assignment.binding_name() == "_" {
            if assignment.operator != crate::AssignmentOperator::Assign {
                return Err(CodegenError {
                    kind: CodegenErrorKind::UnsupportedRuntimeOperator,
                    span: translate_span(function.body_expression_span.start, assignment.name_span),
                });
            }
            let tree = assignment
                .parse_value::<MAX_EXPRESSION_NODES>()
                .map_err(|error| CodegenError {
                    kind: CodegenErrorKind::Expression(error.kind),
                    span: translate_span(
                        function.body_expression_span.start + assignment.value_span.start,
                        error.span,
                    ),
                })?;
            let local_resolver = LocalResolver {
                outer: resolver,
                values: &local_values,
                count: local_count,
            };
            runtime_expression_type(function, &local_resolver, &tree, tree.root(), 0).map_err(
                |kind| CodegenError {
                    kind,
                    span: translate_span(
                        function.body_expression_span.start,
                        assignment.value_span,
                    ),
                },
            )?;
            let program =
                lower_expression::<MAX_FUNCTION_IR_INSTRUCTIONS, MAX_EXPRESSION_NODES>(&tree)
                    .map_err(|error| CodegenError {
                        kind: CodegenErrorKind::Lowering(error.kind),
                        span: translate_span(
                            function.body_expression_span.start + assignment.value_span.start,
                            error.span,
                        ),
                    })?;
            program
                .execute::<_, MAX_FUNCTION_STACK_VALUES>(&local_resolver)
                .map_err(|error| CodegenError {
                    kind: CodegenErrorKind::Execution(error),
                    span: translate_span(
                        function.body_expression_span.start,
                        assignment.value_span,
                    ),
                })?;
            continue;
        }
        let index = local_values[..local_count]
            .iter()
            .rposition(|value| value.is_some_and(|value| value.name == assignment.binding_name()))
            .ok_or(CodegenError {
                kind: CodegenErrorKind::UnknownRuntimeName,
                span: translate_span(function.body_expression_span.start, assignment.name_span),
            })?;
        let target = local_values[index].ok_or(CodegenError {
            kind: CodegenErrorKind::UnknownRuntimeName,
            span: translate_span(function.body_expression_span.start, assignment.name_span),
        })?;
        if !target.mutable {
            return Err(CodegenError {
                kind: CodegenErrorKind::ImmutableAssignment,
                span: translate_span(function.body_expression_span.start, assignment.name_span),
            });
        }
        let tree = assignment
            .parse_value::<MAX_EXPRESSION_NODES>()
            .map_err(|error| CodegenError {
                kind: CodegenErrorKind::Expression(error.kind),
                span: translate_span(
                    function.body_expression_span.start + assignment.value_span.start,
                    error.span,
                ),
            })?;
        let expression_type = runtime_expression_type(function, resolver, &tree, tree.root(), 0)
            .map_err(|kind| CodegenError {
                kind,
                span: translate_span(function.body_expression_span.start, assignment.value_span),
            })?;
        if !runtime_types_compatible(
            expression_type,
            RuntimeExpressionType::Integer(Some(target.ty)),
        ) {
            return Err(CodegenError {
                kind: CodegenErrorKind::RuntimeTypeMismatch,
                span: translate_span(function.body_expression_span.start, assignment.value_span),
            });
        }
        let program = lower_expression::<MAX_FUNCTION_IR_INSTRUCTIONS, MAX_EXPRESSION_NODES>(&tree)
            .map_err(|error| CodegenError {
                kind: CodegenErrorKind::Lowering(error.kind),
                span: translate_span(
                    function.body_expression_span.start + assignment.value_span.start,
                    error.span,
                ),
            })?;
        let local_resolver = LocalResolver {
            outer: resolver,
            values: &local_values,
            count: local_count,
        };
        let right = program
            .execute::<_, MAX_FUNCTION_STACK_VALUES>(&local_resolver)
            .map_err(|error| CodegenError {
                kind: CodegenErrorKind::Execution(error),
                span: translate_span(function.body_expression_span.start, assignment.value_span),
            })?;
        let value = if assignment.operator == crate::AssignmentOperator::Assign {
            right
        } else {
            crate::expression::evaluate_binary(
                assignment_binary_operator(assignment.operator).ok_or(CodegenError {
                    kind: CodegenErrorKind::UnsupportedRuntimeOperator,
                    span: translate_span(function.body_expression_span.start, assignment.name_span),
                })?,
                target.value,
                right,
            )
            .map_err(|error| CodegenError {
                kind: CodegenErrorKind::Execution(ExecutionError::Arithmetic(error)),
                span: translate_span(function.body_expression_span.start, assignment.value_span),
            })?
        };
        if crate::expression::cast_integer(value, target.ty, 64) != Ok(value) {
            return Err(CodegenError {
                kind: CodegenErrorKind::ValueOutOfRange,
                span: translate_span(function.body_expression_span.start, assignment.value_span),
            });
        }
        local_values[index] = Some(ConstantLocal { value, ..target });
    }
    let tree = body
        .parse_tail::<MAX_EXPRESSION_NODES>()
        .map_err(|error| CodegenError {
            kind: CodegenErrorKind::Expression(error.kind),
            span: translate_span(
                function.body_expression_span.start + body.tail_span.start,
                error.span,
            ),
        })?;
    let expression_type = runtime_expression_type(function, resolver, &tree, tree.root(), 0)
        .map_err(|kind| CodegenError {
            kind,
            span: function.body_expression_span,
        })?;
    let expected_type =
        RuntimeExpressionType::Integer(crate::IntegerType::from_name(return_type.text));
    if !runtime_types_compatible(expression_type, expected_type) {
        return Err(CodegenError {
            kind: CodegenErrorKind::RuntimeTypeMismatch,
            span: function.body_expression_span,
        });
    }
    let program = lower_expression::<MAX_FUNCTION_IR_INSTRUCTIONS, MAX_EXPRESSION_NODES>(&tree)
        .map_err(|error| CodegenError {
            kind: CodegenErrorKind::Lowering(error.kind),
            span: translate_span(function.body_expression_span.start, error.span),
        })?;
    let resolver = LocalResolver {
        outer: resolver,
        values: &local_values,
        count: local_count,
    };
    let value = program
        .execute::<_, MAX_FUNCTION_STACK_VALUES>(&resolver)
        .map_err(|error| CodegenError {
            kind: CodegenErrorKind::Execution(error),
            span: function.body_expression_span,
        })?;
    let trusted_typed_value = match tree
        .expression(tree.root())
        .map(|expression| expression.kind)
    {
        Some(ExprKind::Identifier(name)) => {
            resolver.resolve_type(name) == Some(return_integer_type)
        }
        Some(ExprKind::IntegerAssociatedConstant {
            integer_type,
            constant,
        }) => {
            constant != crate::expression::IntegerAssociatedConstant::Bits
                && integer_type == return_integer_type
        }
        _ => false,
    };
    if crate::expression::cast_integer(value, return_integer_type, 64) != Ok(value)
        && !trusted_typed_value
    {
        return Err(CodegenError {
            kind: CodegenErrorKind::ValueOutOfRange,
            span: function.body_expression_span,
        });
    }
    if MAX_BYTES < X86_64_RETURN_CONSTANT_BYTES {
        return Err(CodegenError {
            kind: CodegenErrorKind::OutputTooSmall,
            span: function.body_expression_span,
        });
    }

    let mut bytes = [0u8; MAX_BYTES];
    // REX.W + MOV r64, imm64; RET. The System V and Windows x64 ABIs both
    // return an integer no wider than 64 bits in RAX.
    bytes[0] = 0x48;
    bytes[1] = 0xb8;
    bytes[2..10].copy_from_slice(&(value as u64).to_le_bytes());
    bytes[10] = 0xc3;
    Ok(MachineCode {
        bytes,
        length: X86_64_RETURN_CONSTANT_BYTES,
    })
}

pub fn compile_x86_64_function<
    'source,
    R: ConstantResolver,
    const MAX_BYTES: usize,
    const MAX_PARAMETERS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    function: &Function<'source, MAX_PARAMETERS>,
    resolver: &R,
    abi: X86_64Abi,
) -> Result<MachineCode<MAX_BYTES>, CodegenError> {
    compile_x86_64_function_with_options::<R, MAX_BYTES, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
        function,
        resolver,
        abi,
        CodegenOptions::CHECKED,
    )
}

pub fn compile_x86_64_function_with_options<
    'source,
    R: ConstantResolver,
    const MAX_BYTES: usize,
    const MAX_PARAMETERS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    function: &Function<'source, MAX_PARAMETERS>,
    resolver: &R,
    abi: X86_64Abi,
    options: CodegenOptions,
) -> Result<MachineCode<MAX_BYTES>, CodegenError> {
    let output = compile_x86_64_runtime_function_with_options::<
        R,
        MAX_BYTES,
        MAX_PARAMETERS,
        MAX_EXPRESSION_NODES,
    >(function, resolver, abi, options)?;
    if !output.readonly_data().is_empty() || !output.readonly_relocations().is_empty() {
        return Err(CodegenError {
            kind: CodegenErrorKind::RuntimeExpressionUnsupported,
            span: function.body_expression_span,
        });
    }
    Ok(output.code)
}

pub fn compile_x86_64_runtime_function_with_options<
    'source,
    R: ConstantResolver,
    const MAX_BYTES: usize,
    const MAX_PARAMETERS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    function: &Function<'source, MAX_PARAMETERS>,
    resolver: &R,
    abi: X86_64Abi,
    options: CodegenOptions,
) -> Result<X86_64RuntimeMachineCode<MAX_BYTES>, CodegenError> {
    if function.naked {
        let output = compile_x86_64_naked_relocatable(function)?;
        if !output.relocations().is_empty() {
            return Err(CodegenError {
                kind: CodegenErrorKind::InvalidNakedAssembly,
                span: function.body_expression_span,
            });
        }
        return Ok(X86_64RuntimeMachineCode {
            code: output.code,
            readonly_data: [0; MAX_X86_64_READONLY_DATA_BYTES],
            readonly_data_length: 0,
            readonly_relocations: [X86_64ReadonlyDataRelocation {
                offset: 0,
                data_offset: 0,
            }; MAX_X86_64_READONLY_RELOCATIONS],
            readonly_relocation_count: 0,
        });
    }
    let parsed_body = function
        .parse_body::<MAX_PARAMETERS>()
        .map_err(|error| CodegenError {
            kind: CodegenErrorKind::Body(error.kind),
            span: translate_span(function.body_expression_span.start, error.span),
        })?;
    let mut body_has_aggregate_local = false;
    for local in parsed_body.locals().iter().flatten() {
        if local
            .ty
            .and_then(|ty| runtime_array_type(ty.text))
            .is_some()
        {
            body_has_aggregate_local = true;
            break;
        }
        if local
            .ty
            .and_then(|ty| runtime_tuple_type(ty.text))
            .is_some()
        {
            body_has_aggregate_local = true;
            break;
        }
        if local.initializer.as_bytes().contains(&b'[') {
            body_has_aggregate_local = true;
            break;
        }
        if let Ok(tree) = local.parse_initializer::<MAX_EXPRESSION_NODES>()
            && runtime_expression_type(function, resolver, &tree, tree.root(), 0).is_ok_and(|ty| {
                matches!(
                    ty,
                    RuntimeExpressionType::Array { .. } | RuntimeExpressionType::Tuple { .. }
                )
            })
        {
            body_has_aggregate_local = true;
            break;
        }
    }
    let tail_requires_runtime = if parsed_body.tail_span.start == parsed_body.tail_span.end {
        false
    } else {
        parsed_body
            .parse_tail::<MAX_EXPRESSION_NODES>()
            .map_err(|error| CodegenError {
                kind: CodegenErrorKind::Expression(error.kind),
                span: translate_span(
                    function.body_expression_span.start + parsed_body.tail_span.start,
                    error.span,
                ),
            })?
            .nodes()
            .iter()
            .flatten()
            .any(|expression| matches!(expression.kind, ExprKind::CStrToBytes { .. }))
    };
    let body_requires_runtime = body_has_aggregate_local
        || tail_requires_runtime
        || parsed_body.assignment_count() != 0
        || parsed_body.conditional_return_count() != 0
        || parsed_body.conditional_return_else_count() != 0
        || parsed_body.conditional_assignment_count() != 0
        || parsed_body.while_loop_count() != 0
        || parsed_body.expression_statement_count() != 0
        || parsed_body.return_count() != 0;
    if function.abi != FunctionAbi::MrmlV1
        && function.parameter_count() == 0
        && !body_requires_runtime
        && function
            .return_type
            .and_then(|return_type| runtime_width(return_type.text))
            .is_some()
    {
        let code =
            compile_x86_64_constant_function::<R, MAX_BYTES, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
                function, resolver,
            )?;
        return Ok(X86_64RuntimeMachineCode {
            code,
            readonly_data: [0; MAX_X86_64_READONLY_DATA_BYTES],
            readonly_data_length: 0,
            readonly_relocations: [X86_64ReadonlyDataRelocation {
                offset: 0,
                data_offset: 0,
            }; MAX_X86_64_READONLY_RELOCATIONS],
            readonly_relocation_count: 0,
        });
    }
    validate_stable_export(function, abi)?;
    if function.parameter_count() > MAX_X86_64_ABI_PARAMETERS {
        return Err(CodegenError {
            kind: CodegenErrorKind::TooManyAbiParameters,
            span: function.name_span,
        });
    }
    let return_type_text = function.return_type.map_or("()", |ty| ty.text);
    let return_type_span = function
        .return_type
        .map_or(function.name_span, |ty| ty.span);
    let returns_unit = return_type_text == "()";
    let returns_never = return_type_text == "!";
    let returns_bool = return_type_text == "bool";
    let returns_char = return_type_text == "char";
    let return_array = runtime_array_type(return_type_text);
    let return_reference = runtime_reference_type(return_type_text);
    let return_pointer = runtime_raw_pointer_type(return_type_text);
    if return_reference.is_some() {
        let returns_static = runtime_reference_has_static_lifetime(return_type_text);
        let mut has_reference_parameter = false;
        for parameter in function.parameters().iter().flatten() {
            if runtime_reference_type(parameter.ty.text).is_some() {
                has_reference_parameter = true;
                if returns_static && !runtime_reference_has_static_lifetime(parameter.ty.text) {
                    return Err(CodegenError {
                        kind: CodegenErrorKind::UnsupportedLifetimeRelation,
                        span: parameter.ty.span,
                    });
                }
            }
        }
        if !returns_static && !has_reference_parameter {
            return Err(CodegenError {
                kind: CodegenErrorKind::UnsupportedLifetimeElision,
                span: return_type_span,
            });
        }
    }
    let returns_zero_sized_array = return_array
        .and_then(runtime_array_abi_layout)
        .is_some_and(|(_, bytes, _)| bytes == 0);
    let returns_value_free = returns_unit || returns_never || returns_zero_sized_array;
    if !returns_unit
        && !returns_never
        && !returns_bool
        && !returns_char
        && runtime_width(return_type_text).is_none()
        && return_array.is_none()
        && return_reference.is_none()
        && return_pointer.is_none()
    {
        return Err(CodegenError {
            kind: CodegenErrorKind::UnsupportedReturnType,
            span: return_type_span,
        });
    }
    if let Some(RuntimeExpressionType::Array { element, .. }) = return_array
        && !matches!(
            element,
            RuntimeArrayElementType::Unit
                | RuntimeArrayElementType::Bool
                | RuntimeArrayElementType::Char
                | RuntimeArrayElementType::Integer(Some(_))
        )
    {
        return Err(CodegenError {
            kind: CodegenErrorKind::UnsupportedReturnType,
            span: return_type_span,
        });
    }
    if let Some(RuntimeExpressionType::Reference { target, .. }) = return_reference
        && !matches!(
            target,
            RuntimeReferenceTarget::Scalar(
                RuntimeArrayElementType::Bool
                    | RuntimeArrayElementType::Char
                    | RuntimeArrayElementType::Integer(Some(_))
            ) | RuntimeReferenceTarget::Array {
                element: RuntimeArrayElementType::Bool
                    | RuntimeArrayElementType::Char
                    | RuntimeArrayElementType::Integer(Some(_)),
                ..
            } | RuntimeReferenceTarget::Slice(
                RuntimeArrayElementType::Bool
                    | RuntimeArrayElementType::Char
                    | RuntimeArrayElementType::Integer(Some(_))
            ) | RuntimeReferenceTarget::Str
        )
    {
        return Err(CodegenError {
            kind: CodegenErrorKind::UnsupportedReturnType,
            span: return_type_span,
        });
    }
    let returns_boolean_like = returns_bool
        || matches!(
            return_array,
            Some(RuntimeExpressionType::Array {
                element: RuntimeArrayElementType::Bool,
                ..
            })
        );
    let operand_type = match return_array {
        Some(RuntimeExpressionType::Array {
            element: RuntimeArrayElementType::Integer(Some(element)),
            ..
        }) => element.name(),
        Some(RuntimeExpressionType::Array {
            element: RuntimeArrayElementType::Char,
            ..
        }) => "char",
        Some(_) => "u64",
        None if returns_bool
            || returns_unit
            || returns_never
            || return_reference.is_some()
            || return_pointer.is_some() =>
        {
            "u64"
        }
        None => return_type_text,
    };
    let mut integer_operand_type = None;
    for parameter in function.parameters().iter().flatten() {
        if runtime_raw_pointer_type(parameter.ty.text).is_some() {
            continue;
        }
        if let Some(RuntimeExpressionType::Reference { target, .. }) =
            runtime_reference_type(parameter.ty.text)
        {
            let element = match target {
                RuntimeReferenceTarget::Scalar(element)
                | RuntimeReferenceTarget::Slice(element)
                | RuntimeReferenceTarget::Array { element, .. } => element,
                RuntimeReferenceTarget::Str => continue,
            };
            match element {
                RuntimeArrayElementType::Bool | RuntimeArrayElementType::Char => continue,
                RuntimeArrayElementType::Integer(Some(pointee)) => {
                    if integer_operand_type.is_none() {
                        integer_operand_type = Some(pointee.name());
                    }
                    continue;
                }
                _ => {
                    return Err(CodegenError {
                        kind: CodegenErrorKind::UnsupportedParameterType,
                        span: parameter.ty.span,
                    });
                }
            }
        }
        if let Some(RuntimeExpressionType::Array { element, count }) =
            runtime_array_type(parameter.ty.text)
        {
            if runtime_array_element_bytes(element) == Some(0) || count == 0 {
                continue;
            }
            match element {
                RuntimeArrayElementType::Bool | RuntimeArrayElementType::Char => continue,
                RuntimeArrayElementType::Integer(Some(element)) => {
                    if integer_operand_type.is_none() {
                        integer_operand_type = Some(element.name());
                    }
                    continue;
                }
                _ => {
                    return Err(CodegenError {
                        kind: CodegenErrorKind::UnsupportedParameterType,
                        span: parameter.ty.span,
                    });
                }
            }
        }
        if parameter.ty.text == "bool" {
            continue;
        }
        if runtime_width(parameter.ty.text).is_none() {
            return Err(CodegenError {
                kind: CodegenErrorKind::UnsupportedParameterType,
                span: parameter.ty.span,
            });
        }
        if integer_operand_type.is_none() {
            integer_operand_type = Some(parameter.ty.text);
        }
    }
    let operand_type =
        if (returns_boolean_like || returns_value_free) && integer_operand_type.is_some() {
            integer_operand_type.unwrap_or("u64")
        } else {
            operand_type
        };
    let expected_type = if returns_never {
        RuntimeExpressionType::Never
    } else if returns_unit {
        RuntimeExpressionType::Unit
    } else if returns_bool {
        RuntimeExpressionType::Bool
    } else if returns_char {
        RuntimeExpressionType::Char
    } else if let Some(array) = return_array {
        array
    } else if let Some(reference) = return_reference {
        reference
    } else if let Some(pointer) = return_pointer {
        pointer
    } else {
        RuntimeExpressionType::Integer(crate::IntegerType::from_name(return_type_text))
    };
    let width = runtime_width(operand_type).ok_or(CodegenError {
        kind: CodegenErrorKind::UnsupportedRuntimeType,
        span: function.name_span,
    })?;
    let returns_fat_reference = matches!(
        return_reference,
        Some(RuntimeExpressionType::Reference {
            target: RuntimeReferenceTarget::Slice(_) | RuntimeReferenceTarget::Str,
            ..
        })
    );
    let uses_sret = (function.abi != FunctionAbi::MrmlV1
        && abi == X86_64Abi::Windows
        && returns_fat_reference)
        || return_array.and_then(runtime_array_abi_layout).is_some_and(
            |(_, bytes, words)| match abi {
                X86_64Abi::Windows => bytes != 0 && !matches!(bytes, 1 | 2 | 4 | 8),
                X86_64Abi::SystemV => words > 2,
            },
        );
    let saved_parameter_slots = function
        .parameters()
        .iter()
        .flatten()
        .try_fold(0usize, |total, parameter| {
            let slots = runtime_parameter_stack_slots(parameter.ty.text);
            total.checked_add(slots)
        })
        .and_then(|slots| slots.checked_add(usize::from(uses_sret)))
        .ok_or(CodegenError {
            kind: CodegenErrorKind::TooManyAbiParameters,
            span: function.name_span,
        })?;
    let body = function
        .parse_body::<MAX_PARAMETERS>()
        .map_err(|error| CodegenError {
            kind: CodegenErrorKind::Body(error.kind),
            span: translate_span(function.body_expression_span.start, error.span),
        })?;
    let mut body_facts = RuntimeBodyFacts::EMPTY;
    let preanalyzed_local_count =
        preanalyze_runtime_body_declarations::<R, MAX_PARAMETERS, MAX_EXPRESSION_NODES>(
            function,
            resolver,
            &body,
            operand_type,
            function.body_expression_span.start,
            &mut body_facts,
        )?;
    let validated_body =
        validate_runtime_body_for_emission(&body, &body_facts).map_err(|kind| CodegenError {
            kind,
            span: function.body_expression_span,
        })?;
    let mut emitter = RuntimeEmitter::<_, MAX_BYTES, MAX_PARAMETERS> {
        bytes: [0; MAX_BYTES],
        length: 0,
        readonly_data: [0; MAX_X86_64_READONLY_DATA_BYTES],
        readonly_data_length: 0,
        readonly_relocations: [X86_64ReadonlyDataRelocation {
            offset: 0,
            data_offset: 0,
        }; MAX_X86_64_READONLY_RELOCATIONS],
        readonly_relocation_count: 0,
        trap_patches: [0; MAX_BYTES],
        trap_count: 0,
        function,
        resolver,
        abi,
        width,
        overflow_checks: options.overflow_checks,
        uses_sret,
        saved_parameter_slots,
        locals: [None; MAX_PARAMETERS],
        saved_locals: 0,
        body_facts: &mut body_facts,
        preanalyzed_local_count,
        preanalyzed_local_cursor: 0,
        preanalyzed_assignment_access_cursor: 0,
        preanalyzed_assignment_read_cursor: 0,
        evaluation_depth: 0,
        runtime_call_depth: 0,
        runtime_call_names: [None; 8],
        runtime_call_local_floor: None,
    };
    emitter.emit_prologue(validated_body)?;
    for statement in body.statements().iter().flatten() {
        match statement {
            crate::BodyStatement::Loop(_) => break,
            crate::BodyStatement::Local(index) => {
                let local = body.locals()[*index].unwrap();
                emitter.emit_local::<MAX_EXPRESSION_NODES>(
                    &local,
                    operand_type,
                    function.body_expression_span.start,
                )?;
            }
            crate::BodyStatement::Assignment(index) => {
                let assignment = body.assignments()[*index].unwrap();
                emitter.emit_assignment::<MAX_EXPRESSION_NODES>(
                    &assignment,
                    function.body_expression_span.start,
                )?;
            }
            crate::BodyStatement::ConditionalReturn(index) => {
                let conditional = body.conditional_returns()[*index].unwrap();
                emitter.emit_conditional_return::<MAX_EXPRESSION_NODES>(
                    &conditional,
                    expected_type,
                    function.body_expression_span.start,
                )?;
            }
            crate::BodyStatement::ConditionalReturnElse(index) => {
                let conditional = body.conditional_return_elses()[*index].unwrap();
                emitter.emit_conditional_return_else::<MAX_EXPRESSION_NODES>(
                    &conditional,
                    expected_type,
                    function.body_expression_span.start,
                )?;
            }
            crate::BodyStatement::ConditionalAssignment(index) => {
                let conditional = body.conditional_assignments()[*index].unwrap();
                emitter.emit_conditional_assignment::<MAX_EXPRESSION_NODES>(
                    &conditional,
                    expected_type,
                    operand_type,
                    function.body_expression_span.start,
                )?;
            }
            crate::BodyStatement::Expression(index) => {
                let statement = body.expression_statements()[*index].unwrap();
                emitter.emit_expression_statement::<MAX_EXPRESSION_NODES>(
                    &statement,
                    function.body_expression_span.start,
                )?;
            }
            crate::BodyStatement::Return(index) => {
                let return_statement = body.returns()[*index].unwrap();
                emitter.emit_return::<MAX_EXPRESSION_NODES>(
                    &return_statement,
                    expected_type,
                    function.body_expression_span.start,
                )?;
            }
        }
    }
    for loop_statement in body.while_loops().iter().flatten() {
        let condition_tree = loop_statement
            .parse_condition::<MAX_EXPRESSION_NODES>()
            .map_err(|error| CodegenError {
                kind: CodegenErrorKind::Expression(error.kind),
                span: translate_span(
                    function.body_expression_span.start + loop_statement.condition_span.start,
                    error.span,
                ),
            })?;
        if let Some(tree) = condition_tree.as_ref() {
            let condition_type = runtime_expression_type_with_locals(
                function,
                emitter.resolver,
                &emitter.locals[..emitter.saved_locals],
                tree,
                tree.root(),
                0,
            )
            .map_err(|kind| CodegenError {
                kind,
                span: translate_span(
                    function.body_expression_span.start,
                    loop_statement.condition_span,
                ),
            })?;
            if condition_type != RuntimeExpressionType::Bool {
                return Err(CodegenError {
                    kind: CodegenErrorKind::RuntimeTypeMismatch,
                    span: translate_span(
                        function.body_expression_span.start,
                        loop_statement.condition_span,
                    ),
                });
            }
        }
        let loop_start = emitter.length;
        let mut exit_patches = [None;
            1 + crate::parser::MAX_LOOP_OPERATIONS
                * (crate::MAX_NESTED_LOOP_CONDITIONAL_BREAKS
                    + crate::parser::MAX_NESTED_LOOP_CONDITIONAL_BLOCKS
                    + crate::MAX_NESTED_LOOP_UNCONDITIONAL_CONTROLS)];
        let mut exit_count = 0usize;
        if let Some(tree) = condition_tree.as_ref() {
            emitter.emit_expression(tree, tree.root(), 0)?;
            emitter.emit(&[0x48, 0x85, 0xc0])?;
            exit_patches[exit_count] = Some(emitter.emit_forward_branch(0x84)?);
            exit_count += 1;
        }
        let local_checkpoint = emitter.saved_locals;
        let mut ends_with_unconditional_control = false;
        for operation in loop_statement.operations().iter().flatten() {
            if let LoopOperation::Local(local) = operation {
                emitter.emit_local::<MAX_EXPRESSION_NODES>(
                    local,
                    operand_type,
                    function.body_expression_span.start,
                )?;
                ends_with_unconditional_control = false;
                continue;
            }
            if let LoopOperation::Expression(statement) = operation {
                emitter.emit_expression_statement::<MAX_EXPRESSION_NODES>(
                    statement,
                    function.body_expression_span.start,
                )?;
                ends_with_unconditional_control = false;
                continue;
            }
            if let LoopOperation::NestedBlock(index) = operation {
                let block = loop_statement.nested_blocks()[*index].ok_or(CodegenError {
                    kind: CodegenErrorKind::Body(ParseErrorKind::ExpectedBody),
                    span: function.body_expression_span,
                })?;
                let nested_checkpoint = emitter.saved_locals;
                let nested_start = emitter.length;
                let entry_exit = if let Some(condition) = block.entry_condition {
                    let tree = condition
                        .parse_condition::<MAX_EXPRESSION_NODES>()
                        .map_err(|error| CodegenError {
                            kind: CodegenErrorKind::Expression(error.kind),
                            span: translate_span(
                                function.body_expression_span.start
                                    + condition.condition_span.start,
                                error.span,
                            ),
                        })?;
                    let condition_type = runtime_expression_type_with_locals(
                        function,
                        emitter.resolver,
                        &emitter.locals[..emitter.saved_locals],
                        &tree,
                        tree.root(),
                        0,
                    )
                    .map_err(|kind| CodegenError {
                        kind,
                        span: translate_span(
                            function.body_expression_span.start,
                            condition.condition_span,
                        ),
                    })?;
                    if condition_type != RuntimeExpressionType::Bool {
                        return Err(CodegenError {
                            kind: CodegenErrorKind::RuntimeTypeMismatch,
                            span: translate_span(
                                function.body_expression_span.start,
                                condition.condition_span,
                            ),
                        });
                    }
                    emitter.emit_expression(&tree, tree.root(), 0)?;
                    emitter.emit(&[0x48, 0x85, 0xc0])?;
                    Some(emitter.emit_forward_branch(0x84)?)
                } else {
                    None
                };
                let mut nested_exit_patches = [None;
                    crate::MAX_NESTED_LOOP_CONDITIONAL_BREAKS
                        + crate::parser::MAX_NESTED_LOOP_CONDITIONAL_BLOCKS
                        + crate::MAX_NESTED_LOOP_UNCONDITIONAL_CONTROLS];
                let mut nested_exit_count = 0usize;
                for action_index in 0..=block.action_count() {
                    let control_count = block
                        .conditional_blocks()
                        .len()
                        .checked_add(block.conditional_returns().len())
                        .and_then(|count| count.checked_add(block.conditional_continues().len()))
                        .and_then(|count| count.checked_add(block.conditional_breaks().len()))
                        .and_then(|count| count.checked_add(block.unconditional_controls().len()))
                        .ok_or(CodegenError {
                            kind: CodegenErrorKind::OutputTooSmall,
                            span: function.body_expression_span,
                        })?;
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
                                .parse_condition::<MAX_EXPRESSION_NODES>()
                                .map_err(|error| CodegenError {
                                    kind: CodegenErrorKind::Expression(error.kind),
                                    span: translate_span(
                                        function.body_expression_span.start
                                            + branch.condition_span.start,
                                        error.span,
                                    ),
                                })?;
                            emitter.emit_inline_loop_arm_condition(&condition)?;
                            let false_branch = emitter.emit_forward_branch(0x84)?;
                            let branch_checkpoint = emitter.saved_locals;
                            for branch_action in branch.actions().iter().flatten() {
                                match branch_action {
                                    crate::ConditionalLoopAction::Local(local) => {
                                        emitter.emit_local::<MAX_EXPRESSION_NODES>(
                                            local,
                                            operand_type,
                                            function.body_expression_span.start,
                                        )?;
                                    }
                                    crate::ConditionalLoopAction::Assignment(assignment) => {
                                        emitter.emit_assignment::<MAX_EXPRESSION_NODES>(
                                            assignment,
                                            function.body_expression_span.start,
                                        )?;
                                    }
                                    crate::ConditionalLoopAction::Expression(statement) => {
                                        emitter.emit_expression_statement::<MAX_EXPRESSION_NODES>(
                                            statement,
                                            function.body_expression_span.start,
                                        )?;
                                    }
                                }
                            }
                            match branch.terminal {
                                crate::NestedLoopUnconditionalControl::Break(target) => {
                                    if target == crate::NestedLoopControlTarget::Outer {
                                        emitter.emit_stack_cleanup_to(local_checkpoint)?;
                                        exit_patches[exit_count] =
                                            Some(emitter.emit_unconditional_forward_branch()?);
                                        exit_count += 1;
                                    } else {
                                        emitter.emit_stack_cleanup_to(nested_checkpoint)?;
                                        nested_exit_patches[nested_exit_count] =
                                            Some(emitter.emit_unconditional_forward_branch()?);
                                        nested_exit_count += 1;
                                    }
                                }
                                crate::NestedLoopUnconditionalControl::Continue(target) => {
                                    if target == crate::NestedLoopControlTarget::Outer {
                                        emitter.emit_stack_cleanup_to(local_checkpoint)?;
                                        emitter.emit_backward_branch(loop_start)?;
                                    } else {
                                        emitter.emit_stack_cleanup_to(nested_checkpoint)?;
                                        emitter.emit_backward_branch(nested_start)?;
                                    }
                                }
                                crate::NestedLoopUnconditionalControl::Return(value) => {
                                    emitter.emit_return::<MAX_EXPRESSION_NODES>(
                                        &value,
                                        expected_type,
                                        function.body_expression_span.start,
                                    )?;
                                }
                            }
                            emitter.truncate_scoped_locals(branch_checkpoint)?;
                            if branch.else_arm_count() != 0 {
                                emitter.patch_forward_branch(false_branch)?;
                                for else_arm in branch.else_arms().iter().flatten() {
                                    let else_false_branch = if let Some(condition) = else_arm
                                        .parse_condition::<MAX_EXPRESSION_NODES>()
                                        .map_err(|error| CodegenError {
                                            kind: CodegenErrorKind::Expression(error.kind),
                                            span: translate_span(
                                                function.body_expression_span.start
                                                    + else_arm.condition_span().start,
                                                error.span,
                                            ),
                                        })? {
                                        emitter.emit_inline_loop_arm_condition(&condition)?;
                                        Some(emitter.emit_forward_branch(0x84)?)
                                    } else {
                                        None
                                    };
                                    let else_checkpoint = emitter.saved_locals;
                                    for branch_action in else_arm.actions().iter().flatten() {
                                        match branch_action {
                                            crate::ConditionalLoopAction::Local(local) => {
                                                emitter.emit_local::<MAX_EXPRESSION_NODES>(
                                                    local,
                                                    operand_type,
                                                    function.body_expression_span.start,
                                                )?;
                                            }
                                            crate::ConditionalLoopAction::Assignment(
                                                assignment,
                                            ) => {
                                                emitter.emit_assignment::<MAX_EXPRESSION_NODES>(
                                                    assignment,
                                                    function.body_expression_span.start,
                                                )?;
                                            }
                                            crate::ConditionalLoopAction::Expression(statement) => {
                                                emitter
                                                .emit_expression_statement::<MAX_EXPRESSION_NODES>(
                                                    statement,
                                                    function.body_expression_span.start,
                                                )?;
                                            }
                                        }
                                    }
                                    match else_arm.terminal {
                                        crate::NestedLoopUnconditionalControl::Break(target) => {
                                            if target == crate::NestedLoopControlTarget::Outer {
                                                emitter.emit_stack_cleanup_to(local_checkpoint)?;
                                                exit_patches[exit_count] = Some(
                                                    emitter.emit_unconditional_forward_branch()?,
                                                );
                                                exit_count += 1;
                                            } else {
                                                emitter.emit_stack_cleanup_to(nested_checkpoint)?;
                                                nested_exit_patches[nested_exit_count] = Some(
                                                    emitter.emit_unconditional_forward_branch()?,
                                                );
                                                nested_exit_count += 1;
                                            }
                                        }
                                        crate::NestedLoopUnconditionalControl::Continue(target) => {
                                            if target == crate::NestedLoopControlTarget::Outer {
                                                emitter.emit_stack_cleanup_to(local_checkpoint)?;
                                                emitter.emit_backward_branch(loop_start)?;
                                            } else {
                                                emitter.emit_stack_cleanup_to(nested_checkpoint)?;
                                                emitter.emit_backward_branch(nested_start)?;
                                            }
                                        }
                                        crate::NestedLoopUnconditionalControl::Return(value) => {
                                            emitter.emit_return::<MAX_EXPRESSION_NODES>(
                                                &value,
                                                expected_type,
                                                function.body_expression_span.start,
                                            )?;
                                        }
                                    }
                                    emitter.truncate_scoped_locals(else_checkpoint)?;
                                    if let Some(else_false_branch) = else_false_branch {
                                        emitter.patch_forward_branch(else_false_branch)?;
                                    }
                                }
                            } else {
                                emitter.patch_forward_branch(false_branch)?;
                            }
                        }
                        for ((control, control_action_index), stored_control_order) in block
                            .unconditional_controls()
                            .iter()
                            .flatten()
                            .zip(block.unconditional_control_action_indices())
                            .zip(block.unconditional_control_orders())
                        {
                            if action_index != *control_action_index
                                || control_order != *stored_control_order
                            {
                                continue;
                            }
                            match control {
                                crate::NestedLoopUnconditionalControl::Break(target) => {
                                    if *target == crate::NestedLoopControlTarget::Outer {
                                        emitter.emit_stack_cleanup_to(local_checkpoint)?;
                                        exit_patches[exit_count] =
                                            Some(emitter.emit_unconditional_forward_branch()?);
                                        exit_count += 1;
                                    } else {
                                        emitter.emit_stack_cleanup_to(nested_checkpoint)?;
                                        nested_exit_patches[nested_exit_count] =
                                            Some(emitter.emit_unconditional_forward_branch()?);
                                        nested_exit_count += 1;
                                    }
                                }
                                crate::NestedLoopUnconditionalControl::Continue(target) => {
                                    if *target == crate::NestedLoopControlTarget::Outer {
                                        emitter.emit_stack_cleanup_to(local_checkpoint)?;
                                        emitter.emit_backward_branch(loop_start)?;
                                    } else {
                                        emitter.emit_stack_cleanup_to(nested_checkpoint)?;
                                        emitter.emit_backward_branch(nested_start)?;
                                    }
                                }
                                crate::NestedLoopUnconditionalControl::Return(value) => {
                                    emitter.emit_return::<MAX_EXPRESSION_NODES>(
                                        value,
                                        expected_type,
                                        function.body_expression_span.start,
                                    )?;
                                }
                            }
                        }
                        for (((condition, break_action_index), break_control_order), target) in
                            block
                                .conditional_breaks()
                                .iter()
                                .flatten()
                                .zip(block.conditional_break_action_indices())
                                .zip(block.conditional_break_control_orders())
                                .zip(block.conditional_break_targets())
                        {
                            if action_index != *break_action_index
                                || control_order != *break_control_order
                            {
                                continue;
                            }
                            let tree = condition
                                .parse_condition::<MAX_EXPRESSION_NODES>()
                                .map_err(|error| CodegenError {
                                    kind: CodegenErrorKind::Expression(error.kind),
                                    span: translate_span(
                                        function.body_expression_span.start
                                            + condition.condition_span.start,
                                        error.span,
                                    ),
                                })?;
                            let condition_type = runtime_expression_type_with_locals(
                                function,
                                emitter.resolver,
                                &emitter.locals[..emitter.saved_locals],
                                &tree,
                                tree.root(),
                                0,
                            )
                            .map_err(|kind| CodegenError {
                                kind,
                                span: translate_span(
                                    function.body_expression_span.start,
                                    condition.condition_span,
                                ),
                            })?;
                            if condition_type != RuntimeExpressionType::Bool {
                                return Err(CodegenError {
                                    kind: CodegenErrorKind::RuntimeTypeMismatch,
                                    span: translate_span(
                                        function.body_expression_span.start,
                                        condition.condition_span,
                                    ),
                                });
                            }
                            emitter.emit_expression(&tree, tree.root(), 0)?;
                            emitter.emit(&[0x48, 0x85, 0xc0])?;
                            let skip_break = emitter.emit_forward_branch(0x84)?;
                            if *target == crate::NestedLoopControlTarget::Outer {
                                emitter.emit_stack_cleanup_to(local_checkpoint)?;
                                exit_patches[exit_count] =
                                    Some(emitter.emit_unconditional_forward_branch()?);
                                exit_count += 1;
                            } else {
                                emitter.emit_stack_cleanup_to(nested_checkpoint)?;
                                nested_exit_patches[nested_exit_count] =
                                    Some(emitter.emit_unconditional_forward_branch()?);
                                nested_exit_count += 1;
                            }
                            emitter.patch_forward_branch(skip_break)?;
                        }
                        for ((conditional, return_action_index), return_control_order) in block
                            .conditional_returns()
                            .iter()
                            .flatten()
                            .zip(block.conditional_return_action_indices())
                            .zip(block.conditional_return_control_orders())
                        {
                            if action_index == *return_action_index
                                && control_order == *return_control_order
                            {
                                emitter.emit_conditional_return::<MAX_EXPRESSION_NODES>(
                                    conditional,
                                    expected_type,
                                    function.body_expression_span.start,
                                )?;
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
                            if action_index != *continue_action_index
                                || control_order != *continue_control_order
                            {
                                continue;
                            }
                            let tree = condition
                                .parse_condition::<MAX_EXPRESSION_NODES>()
                                .map_err(|error| CodegenError {
                                    kind: CodegenErrorKind::Expression(error.kind),
                                    span: translate_span(
                                        function.body_expression_span.start
                                            + condition.condition_span.start,
                                        error.span,
                                    ),
                                })?;
                            let condition_type = runtime_expression_type_with_locals(
                                function,
                                emitter.resolver,
                                &emitter.locals[..emitter.saved_locals],
                                &tree,
                                tree.root(),
                                0,
                            )
                            .map_err(|kind| CodegenError {
                                kind,
                                span: translate_span(
                                    function.body_expression_span.start,
                                    condition.condition_span,
                                ),
                            })?;
                            if condition_type != RuntimeExpressionType::Bool {
                                return Err(CodegenError {
                                    kind: CodegenErrorKind::RuntimeTypeMismatch,
                                    span: translate_span(
                                        function.body_expression_span.start,
                                        condition.condition_span,
                                    ),
                                });
                            }
                            emitter.emit_expression(&tree, tree.root(), 0)?;
                            emitter.emit(&[0x48, 0x85, 0xc0])?;
                            let skip_continue = emitter.emit_forward_branch(0x84)?;
                            if *target == crate::NestedLoopControlTarget::Outer {
                                emitter.emit_stack_cleanup_to(local_checkpoint)?;
                                emitter.emit_backward_branch(loop_start)?;
                            } else {
                                emitter.emit_stack_cleanup_to(nested_checkpoint)?;
                                emitter.emit_backward_branch(nested_start)?;
                            }
                            emitter.patch_forward_branch(skip_continue)?;
                        }
                    }
                    if action_index == block.action_count() {
                        break;
                    }
                    let action = block.actions()[action_index].ok_or(CodegenError {
                        kind: CodegenErrorKind::Body(ParseErrorKind::ExpectedBody),
                        span: function.body_expression_span,
                    })?;
                    match action {
                        crate::ConditionalLoopAction::Local(local) => {
                            emitter.emit_local::<MAX_EXPRESSION_NODES>(
                                &local,
                                operand_type,
                                function.body_expression_span.start,
                            )?;
                        }
                        crate::ConditionalLoopAction::Assignment(assignment) => {
                            emitter.emit_assignment::<MAX_EXPRESSION_NODES>(
                                &assignment,
                                function.body_expression_span.start,
                            )?;
                        }
                        crate::ConditionalLoopAction::Expression(statement) => {
                            emitter.emit_expression_statement::<MAX_EXPRESSION_NODES>(
                                &statement,
                                function.body_expression_span.start,
                            )?;
                        }
                    }
                }
                emitter.emit_stack_cleanup_to(nested_checkpoint)?;
                emitter.truncate_scoped_locals(nested_checkpoint)?;
                if block.unconditional_controls().is_empty() {
                    emitter.emit_backward_branch(nested_start)?;
                }
                for patch in nested_exit_patches[..nested_exit_count].iter().flatten() {
                    emitter.patch_forward_branch(*patch)?;
                }
                if let Some(entry_exit) = entry_exit {
                    emitter.patch_forward_branch(entry_exit)?;
                }
                ends_with_unconditional_control = false;
                continue;
            }
            if matches!(operation, LoopOperation::NestedUnitLoop) {
                ends_with_unconditional_control = false;
                continue;
            }
            if let LoopOperation::ConditionalBlock(index) = operation {
                let block = loop_statement.conditional_blocks()[*index].ok_or(CodegenError {
                    kind: CodegenErrorKind::Body(ParseErrorKind::ExpectedBody),
                    span: function.body_expression_span,
                })?;
                let condition_tree =
                    block
                        .parse_condition::<MAX_EXPRESSION_NODES>()
                        .map_err(|error| CodegenError {
                            kind: CodegenErrorKind::Expression(error.kind),
                            span: translate_span(
                                function.body_expression_span.start + block.condition_span.start,
                                error.span,
                            ),
                        })?;
                let condition_type = runtime_expression_type_with_locals(
                    function,
                    emitter.resolver,
                    &emitter.locals[..emitter.saved_locals],
                    &condition_tree,
                    condition_tree.root(),
                    0,
                )
                .map_err(|kind| CodegenError {
                    kind,
                    span: translate_span(function.body_expression_span.start, block.condition_span),
                })?;
                if condition_type != RuntimeExpressionType::Bool {
                    return Err(CodegenError {
                        kind: CodegenErrorKind::RuntimeTypeMismatch,
                        span: translate_span(
                            function.body_expression_span.start,
                            block.condition_span,
                        ),
                    });
                }
                emitter.emit_expression(&condition_tree, condition_tree.root(), 0)?;
                emitter.emit(&[0x48, 0x85, 0xc0])?;
                let skip_block = emitter.emit_forward_branch(0x84)?;
                let block_checkpoint = emitter.saved_locals;
                for action in block.actions().iter().flatten() {
                    match action {
                        crate::ConditionalLoopAction::Local(local) => {
                            emitter.emit_local::<MAX_EXPRESSION_NODES>(
                                local,
                                operand_type,
                                function.body_expression_span.start,
                            )?;
                        }
                        crate::ConditionalLoopAction::Assignment(assignment) => {
                            emitter.emit_assignment::<MAX_EXPRESSION_NODES>(
                                assignment,
                                function.body_expression_span.start,
                            )?;
                        }
                        crate::ConditionalLoopAction::Expression(statement) => {
                            emitter.emit_expression_statement::<MAX_EXPRESSION_NODES>(
                                statement,
                                function.body_expression_span.start,
                            )?;
                        }
                    }
                }
                match block.terminal {
                    Some(crate::ConditionalLoopTerminal::Break) => {
                        emitter.emit_stack_cleanup_to(local_checkpoint)?;
                        exit_patches[exit_count] =
                            Some(emitter.emit_unconditional_forward_branch()?);
                        exit_count += 1;
                    }
                    Some(crate::ConditionalLoopTerminal::Continue) => {
                        emitter.emit_stack_cleanup_to(local_checkpoint)?;
                        emitter.emit_backward_branch(loop_start)?;
                    }
                    Some(crate::ConditionalLoopTerminal::Return(return_statement)) => {
                        emitter.emit_return::<MAX_EXPRESSION_NODES>(
                            &return_statement,
                            expected_type,
                            function.body_expression_span.start,
                        )?;
                    }
                    None => emitter.emit_stack_cleanup_to(block_checkpoint)?,
                }
                emitter.truncate_scoped_locals(block_checkpoint)?;
                let mut end_patches = [None; crate::MAX_CONDITIONAL_LOOP_ELSE_ARMS + 1];
                let mut end_patch_count = 0usize;
                if block.else_arm.is_some() {
                    end_patches[end_patch_count] =
                        Some(emitter.emit_unconditional_forward_branch()?);
                    end_patch_count += 1;
                }
                emitter.patch_forward_branch(skip_block)?;
                if let Some(else_index) = block.else_arm {
                    for else_arm in loop_statement.conditional_else_arms()
                        [else_index..else_index + block.else_arm_count]
                        .iter()
                        .flatten()
                    {
                        let skip_arm = if let Some(condition_tree) = else_arm
                            .parse_condition::<MAX_EXPRESSION_NODES>()
                            .map_err(|error| CodegenError {
                                kind: CodegenErrorKind::Expression(error.kind),
                                span: translate_span(
                                    function.body_expression_span.start
                                        + else_arm.condition_span.start,
                                    error.span,
                                ),
                            })? {
                            let condition_type = runtime_expression_type_with_locals(
                                function,
                                emitter.resolver,
                                &emitter.locals[..emitter.saved_locals],
                                &condition_tree,
                                condition_tree.root(),
                                0,
                            )
                            .map_err(|kind| CodegenError {
                                kind,
                                span: translate_span(
                                    function.body_expression_span.start,
                                    else_arm.condition_span,
                                ),
                            })?;
                            if condition_type != RuntimeExpressionType::Bool {
                                return Err(CodegenError {
                                    kind: CodegenErrorKind::RuntimeTypeMismatch,
                                    span: translate_span(
                                        function.body_expression_span.start,
                                        else_arm.condition_span,
                                    ),
                                });
                            }
                            emitter.emit_expression(&condition_tree, condition_tree.root(), 0)?;
                            emitter.emit(&[0x48, 0x85, 0xc0])?;
                            Some(emitter.emit_forward_branch(0x84)?)
                        } else {
                            None
                        };
                        let else_checkpoint = emitter.saved_locals;
                        for action in else_arm.actions().iter().flatten() {
                            match action {
                                crate::ConditionalLoopAction::Local(local) => {
                                    emitter.emit_local::<MAX_EXPRESSION_NODES>(
                                        local,
                                        operand_type,
                                        function.body_expression_span.start,
                                    )?;
                                }
                                crate::ConditionalLoopAction::Assignment(assignment) => {
                                    emitter.emit_assignment::<MAX_EXPRESSION_NODES>(
                                        assignment,
                                        function.body_expression_span.start,
                                    )?;
                                }
                                crate::ConditionalLoopAction::Expression(statement) => {
                                    emitter.emit_expression_statement::<MAX_EXPRESSION_NODES>(
                                        statement,
                                        function.body_expression_span.start,
                                    )?;
                                }
                            }
                        }
                        match else_arm.terminal {
                            Some(crate::ConditionalLoopTerminal::Break) => {
                                emitter.emit_stack_cleanup_to(local_checkpoint)?;
                                exit_patches[exit_count] =
                                    Some(emitter.emit_unconditional_forward_branch()?);
                                exit_count += 1;
                            }
                            Some(crate::ConditionalLoopTerminal::Continue) => {
                                emitter.emit_stack_cleanup_to(local_checkpoint)?;
                                emitter.emit_backward_branch(loop_start)?;
                            }
                            Some(crate::ConditionalLoopTerminal::Return(return_statement)) => {
                                emitter.emit_return::<MAX_EXPRESSION_NODES>(
                                    &return_statement,
                                    expected_type,
                                    function.body_expression_span.start,
                                )?;
                            }
                            None => emitter.emit_stack_cleanup_to(else_checkpoint)?,
                        }
                        emitter.truncate_scoped_locals(else_checkpoint)?;
                        end_patches[end_patch_count] =
                            Some(emitter.emit_unconditional_forward_branch()?);
                        end_patch_count += 1;
                        if let Some(skip_arm) = skip_arm {
                            emitter.patch_forward_branch(skip_arm)?;
                        } else {
                            break;
                        }
                    }
                    for patch in end_patches[..end_patch_count].iter().flatten() {
                        emitter.patch_forward_branch(*patch)?;
                    }
                }
                ends_with_unconditional_control = false;
                continue;
            }
            if let LoopOperation::Return(loop_return) = operation {
                let value_tree =
                    loop_return
                        .parse_value::<MAX_EXPRESSION_NODES>()
                        .map_err(|error| CodegenError {
                            kind: CodegenErrorKind::Expression(error.kind),
                            span: translate_span(
                                function.body_expression_span.start + loop_return.value_span.start,
                                error.span,
                            ),
                        })?;
                let value_type = runtime_expression_type_with_locals(
                    function,
                    emitter.resolver,
                    &emitter.locals[..emitter.saved_locals],
                    &value_tree,
                    value_tree.root(),
                    0,
                )
                .map_err(|kind| CodegenError {
                    kind,
                    span: translate_span(
                        function.body_expression_span.start,
                        loop_return.value_span,
                    ),
                })?;
                if !runtime_types_compatible(value_type, expected_type) {
                    return Err(CodegenError {
                        kind: CodegenErrorKind::RuntimeTypeMismatch,
                        span: translate_span(
                            function.body_expression_span.start,
                            loop_return.value_span,
                        ),
                    });
                }
                emitter.emit_typed_return(&value_tree, value_tree.root(), expected_type)?;
                ends_with_unconditional_control = true;
                break;
            }
            if let LoopOperation::ConditionalReturn(control) = operation {
                let condition_tree =
                    control
                        .parse_condition::<MAX_EXPRESSION_NODES>()
                        .map_err(|error| CodegenError {
                            kind: CodegenErrorKind::Expression(error.kind),
                            span: translate_span(
                                function.body_expression_span.start + control.condition_span.start,
                                error.span,
                            ),
                        })?;
                let condition_type = runtime_expression_type_with_locals(
                    function,
                    emitter.resolver,
                    &emitter.locals[..emitter.saved_locals],
                    &condition_tree,
                    condition_tree.root(),
                    0,
                )
                .map_err(|kind| CodegenError {
                    kind,
                    span: translate_span(
                        function.body_expression_span.start,
                        control.condition_span,
                    ),
                })?;
                if condition_type != RuntimeExpressionType::Bool {
                    return Err(CodegenError {
                        kind: CodegenErrorKind::RuntimeTypeMismatch,
                        span: translate_span(
                            function.body_expression_span.start,
                            control.condition_span,
                        ),
                    });
                }
                let value_tree =
                    control
                        .parse_value::<MAX_EXPRESSION_NODES>()
                        .map_err(|error| CodegenError {
                            kind: CodegenErrorKind::Expression(error.kind),
                            span: translate_span(
                                function.body_expression_span.start + control.value_span.start,
                                error.span,
                            ),
                        })?;
                let value_type = runtime_expression_type_with_locals(
                    function,
                    emitter.resolver,
                    &emitter.locals[..emitter.saved_locals],
                    &value_tree,
                    value_tree.root(),
                    0,
                )
                .map_err(|kind| CodegenError {
                    kind,
                    span: translate_span(function.body_expression_span.start, control.value_span),
                })?;
                if !runtime_types_compatible(value_type, expected_type) {
                    return Err(CodegenError {
                        kind: CodegenErrorKind::RuntimeTypeMismatch,
                        span: translate_span(
                            function.body_expression_span.start,
                            control.value_span,
                        ),
                    });
                }
                emitter.emit_expression(&condition_tree, condition_tree.root(), 0)?;
                emitter.emit(&[0x48, 0x85, 0xc0])?;
                let skip_return = emitter.emit_forward_branch(0x84)?;
                emitter.emit_typed_return(&value_tree, value_tree.root(), expected_type)?;
                emitter.patch_forward_branch(skip_return)?;
                ends_with_unconditional_control = false;
                continue;
            }
            let LoopOperation::Assignment(assignment) = operation else {
                let (conditional, is_break) = match operation {
                    LoopOperation::ConditionalBreak(control) => (Some(control), true),
                    LoopOperation::ConditionalContinue(control) => (Some(control), false),
                    LoopOperation::Break => (None, true),
                    LoopOperation::Continue => (None, false),
                    LoopOperation::ConditionalReturn(_) => continue,
                    LoopOperation::ConditionalBlock(_) => continue,
                    LoopOperation::Return(_) => continue,
                    LoopOperation::Local(_) => continue,
                    LoopOperation::Expression(_) => continue,
                    LoopOperation::NestedUnitLoop => continue,
                    LoopOperation::NestedBlock(_) => continue,
                    LoopOperation::Assignment(_) => continue,
                };
                if let Some(control) = conditional {
                    let tree =
                        control
                            .parse_condition::<MAX_EXPRESSION_NODES>()
                            .map_err(|error| CodegenError {
                                kind: CodegenErrorKind::Expression(error.kind),
                                span: translate_span(
                                    function.body_expression_span.start
                                        + control.condition_span.start,
                                    error.span,
                                ),
                            })?;
                    let ty = runtime_expression_type_with_locals(
                        function,
                        emitter.resolver,
                        &emitter.locals[..emitter.saved_locals],
                        &tree,
                        tree.root(),
                        0,
                    )
                    .map_err(|kind| CodegenError {
                        kind,
                        span: translate_span(
                            function.body_expression_span.start,
                            control.condition_span,
                        ),
                    })?;
                    if ty != RuntimeExpressionType::Bool {
                        return Err(CodegenError {
                            kind: CodegenErrorKind::RuntimeTypeMismatch,
                            span: translate_span(
                                function.body_expression_span.start,
                                control.condition_span,
                            ),
                        });
                    }
                    emitter.emit_expression(&tree, tree.root(), 0)?;
                    emitter.emit(&[0x48, 0x85, 0xc0])?;
                    let skip_control = emitter.emit_forward_branch(0x84)?;
                    emitter.emit_stack_cleanup_to(local_checkpoint)?;
                    if is_break {
                        exit_patches[exit_count] =
                            Some(emitter.emit_unconditional_forward_branch()?);
                        exit_count += 1;
                    } else {
                        emitter.emit_backward_branch(loop_start)?;
                    }
                    emitter.patch_forward_branch(skip_control)?;
                    ends_with_unconditional_control = false;
                } else {
                    emitter.emit_stack_cleanup_to(local_checkpoint)?;
                    if is_break {
                        exit_patches[exit_count] =
                            Some(emitter.emit_unconditional_forward_branch()?);
                        exit_count += 1;
                    } else {
                        emitter.emit_backward_branch(loop_start)?;
                    }
                    ends_with_unconditional_control = true;
                }
                continue;
            };
            ends_with_unconditional_control = false;
            emitter.emit_assignment::<MAX_EXPRESSION_NODES>(
                assignment,
                function.body_expression_span.start,
            )?;
        }
        if !ends_with_unconditional_control {
            emitter.emit_stack_cleanup_to(local_checkpoint)?;
            emitter.emit_backward_branch(loop_start)?;
        }
        emitter.truncate_scoped_locals(local_checkpoint)?;
        for patch in exit_patches[..exit_count].iter().flatten().copied() {
            emitter.patch_forward_branch(patch)?;
        }
    }
    let mut saw_loop_statement = false;
    for statement in body.statements().iter().flatten() {
        match statement {
            crate::BodyStatement::Loop(_) => saw_loop_statement = true,
            crate::BodyStatement::Local(index) if saw_loop_statement => {
                let local = body.locals()[*index].unwrap();
                emitter.emit_local::<MAX_EXPRESSION_NODES>(
                    &local,
                    operand_type,
                    function.body_expression_span.start,
                )?;
            }
            crate::BodyStatement::Assignment(index) if saw_loop_statement => {
                let assignment = body.assignments()[*index].unwrap();
                emitter.emit_assignment::<MAX_EXPRESSION_NODES>(
                    &assignment,
                    function.body_expression_span.start,
                )?;
            }
            crate::BodyStatement::ConditionalReturn(index) if saw_loop_statement => {
                let conditional = body.conditional_returns()[*index].unwrap();
                emitter.emit_conditional_return::<MAX_EXPRESSION_NODES>(
                    &conditional,
                    expected_type,
                    function.body_expression_span.start,
                )?;
            }
            crate::BodyStatement::ConditionalReturnElse(index) if saw_loop_statement => {
                let conditional = body.conditional_return_elses()[*index].unwrap();
                emitter.emit_conditional_return_else::<MAX_EXPRESSION_NODES>(
                    &conditional,
                    expected_type,
                    function.body_expression_span.start,
                )?;
            }
            crate::BodyStatement::ConditionalAssignment(index) if saw_loop_statement => {
                let conditional = body.conditional_assignments()[*index].unwrap();
                emitter.emit_conditional_assignment::<MAX_EXPRESSION_NODES>(
                    &conditional,
                    expected_type,
                    operand_type,
                    function.body_expression_span.start,
                )?;
            }
            crate::BodyStatement::Expression(index) if saw_loop_statement => {
                let statement = body.expression_statements()[*index].unwrap();
                emitter.emit_expression_statement::<MAX_EXPRESSION_NODES>(
                    &statement,
                    function.body_expression_span.start,
                )?;
            }
            crate::BodyStatement::Return(index) if saw_loop_statement => {
                let return_statement = body.returns()[*index].unwrap();
                emitter.emit_return::<MAX_EXPRESSION_NODES>(
                    &return_statement,
                    expected_type,
                    function.body_expression_span.start,
                )?;
            }
            _ => {}
        }
    }
    if x86_64_body_tail_diverges(&body) {
        return emitter.finish();
    }
    let tree = body
        .parse_tail::<MAX_EXPRESSION_NODES>()
        .map_err(|error| CodegenError {
            kind: CodegenErrorKind::Expression(error.kind),
            span: translate_span(
                function.body_expression_span.start + body.tail_span.start,
                error.span,
            ),
        })?;
    let expression_type = runtime_expression_type_with_locals(
        function,
        emitter.resolver,
        &emitter.locals[..emitter.saved_locals],
        &tree,
        tree.root(),
        0,
    )
    .map_err(|kind| CodegenError {
        kind,
        span: translate_span(function.body_expression_span.start, body.tail_span),
    })?;
    if !runtime_types_compatible(expression_type, expected_type) {
        return Err(CodegenError {
            kind: CodegenErrorKind::RuntimeTypeMismatch,
            span: translate_span(function.body_expression_span.start, body.tail_span),
        });
    }
    emitter.emit_typed_return(&tree, tree.root(), expected_type)?;
    emitter.finish()
}

pub fn compile_x86_64_naked_relocatable<
    'source,
    const MAX_BYTES: usize,
    const MAX_PARAMETERS: usize,
>(
    function: &Function<'source, MAX_PARAMETERS>,
) -> Result<X86_64RelocatableMachineCode<'source, MAX_BYTES>, CodegenError> {
    let error = |kind| CodegenError {
        kind,
        span: function.body_expression_span,
    };
    if !function.unsafe_function {
        return Err(error(CodegenErrorKind::NakedFunctionMustBeUnsafe));
    }
    if function.constant || function.abi != FunctionAbi::C {
        return Err(error(CodegenErrorKind::NakedFunctionRequiresCAbi));
    }
    if function.parameter_count() != 0 || function.where_predicate_count() != 0 {
        return Err(error(CodegenErrorKind::NakedFunctionParametersUnsupported));
    }
    if function
        .return_type
        .is_some_and(|return_type| return_type.text != "!" && return_type.text != "()")
    {
        return Err(error(CodegenErrorKind::NakedFunctionReturnUnsupported));
    }
    let mut source = function.body_expression.trim();
    source = source
        .strip_prefix("naked_asm!(")
        .ok_or_else(|| error(CodegenErrorKind::InvalidNakedAssembly))?;
    if let Some(without_semicolon) = source.strip_suffix(";") {
        source = without_semicolon.trim_end();
    }
    source = source
        .strip_suffix(')')
        .ok_or_else(|| error(CodegenErrorKind::InvalidNakedAssembly))?;
    let mut instructions = [""; 8];
    let mut instruction_count = 0usize;
    let mut att_syntax = false;
    let mut remaining = source.trim();
    while !remaining.is_empty() {
        if matches!(
            remaining,
            "options(raw)"
                | "options(att_syntax)"
                | "options(raw, att_syntax)"
                | "options(att_syntax, raw)"
        ) {
            att_syntax = remaining.contains("att_syntax");
            remaining = "";
            continue;
        }
        if instruction_count == 8 {
            return Err(error(CodegenErrorKind::InvalidNakedAssembly));
        }
        let literal = remaining
            .strip_prefix('"')
            .ok_or_else(|| error(CodegenErrorKind::InvalidNakedAssembly))?;
        let close = literal
            .find('"')
            .ok_or_else(|| error(CodegenErrorKind::InvalidNakedAssembly))?;
        let instruction = literal[..close].trim();
        if instruction.as_bytes().contains(&b'\\') {
            return Err(error(CodegenErrorKind::InvalidNakedAssembly));
        }
        remaining = literal[close + 1..].trim_start();
        if !remaining.is_empty() {
            remaining = remaining
                .strip_prefix(',')
                .ok_or_else(|| error(CodegenErrorKind::InvalidNakedAssembly))?
                .trim_start();
            if remaining.is_empty() {
                return Err(error(CodegenErrorKind::InvalidNakedAssembly));
            }
        }
        instructions[instruction_count] = instruction;
        instruction_count += 1;
    }
    if instruction_count == 0 {
        return Err(error(CodegenErrorKind::InvalidNakedAssembly));
    }
    let instructions = &instructions[..instruction_count];
    let mut offsets = [0usize; 8];
    let mut labels = [None; 8];
    let mut length = 0usize;
    for (index, instruction) in instructions.iter().enumerate() {
        offsets[index] = length;
        if let Some(label) = x86_64_naked_label_definition(instruction) {
            let slot = &mut labels[(label - 2) as usize];
            if slot.replace(length).is_some() {
                return Err(error(CodegenErrorKind::InvalidNakedAssembly));
            }
            continue;
        }
        let encoding_length = if x86_64_naked_label_branch(instruction).is_some()
            || x86_64_naked_external_branch(instruction, att_syntax).is_some()
        {
            5
        } else if let Some(external) =
            x86_64_naked_external_memory_instruction(instruction, att_syntax)
        {
            external.length
        } else {
            encode_x86_64_naked_instruction_for_syntax(instruction, att_syntax)
                .ok_or_else(|| error(CodegenErrorKind::InvalidNakedAssembly))?
                .1
        };
        length = length
            .checked_add(encoding_length)
            .ok_or_else(|| error(CodegenErrorKind::OutputTooSmall))?;
        if length > MAX_BYTES {
            return Err(error(CodegenErrorKind::OutputTooSmall));
        }
    }
    let mut bytes = [0u8; MAX_BYTES];
    let mut terminating = false;
    let mut emitted_length = 0usize;
    let mut relocations = [X86_64ExternalRelocation {
        offset: 0,
        symbol: "",
        kind: X86_64ExternalRelocationKind::Branch,
    }; MAX_X86_64_EXTERNAL_RELOCATIONS];
    let mut relocation_count = 0usize;
    for (index, instruction) in instructions.iter().enumerate() {
        if x86_64_naked_label_definition(instruction).is_some() {
            continue;
        }
        let (encoding, encoding_length, is_terminating) =
            if let Some((label, direction)) = x86_64_naked_label_branch(instruction) {
                let target = labels[(label - 2) as usize]
                    .ok_or_else(|| error(CodegenErrorKind::InvalidNakedAssembly))?;
                let origin = offsets[index]
                    .checked_add(5)
                    .ok_or_else(|| error(CodegenErrorKind::InvalidNakedAssembly))?;
                if (direction == b'f' && target <= offsets[index])
                    || (direction == b'b' && target > offsets[index])
                {
                    return Err(error(CodegenErrorKind::InvalidNakedAssembly));
                }
                let displacement = i64::try_from(target)
                    .ok()
                    .and_then(|target| i64::try_from(origin).ok().map(|origin| target - origin))
                    .and_then(|displacement| i32::try_from(displacement).ok())
                    .ok_or_else(|| error(CodegenErrorKind::InvalidNakedAssembly))?;
                let mut encoding = [0u8; 10];
                encoding[0] = 0xe9;
                encoding[1..5].copy_from_slice(&displacement.to_le_bytes());
                (encoding, 5, true)
            } else if let Some(symbol) = x86_64_naked_external_branch(instruction, att_syntax) {
                let Some(relocation) = relocations.get_mut(relocation_count) else {
                    return Err(error(CodegenErrorKind::InvalidNakedAssembly));
                };
                *relocation = X86_64ExternalRelocation {
                    offset: emitted_length
                        .checked_add(1)
                        .ok_or_else(|| error(CodegenErrorKind::OutputTooSmall))?,
                    symbol,
                    kind: X86_64ExternalRelocationKind::Branch,
                };
                relocation_count += 1;
                ([0xe9, 0, 0, 0, 0, 0, 0, 0, 0, 0], 5, true)
            } else if let Some(external) =
                x86_64_naked_external_memory_instruction(instruction, att_syntax)
            {
                let Some(relocation) = relocations.get_mut(relocation_count) else {
                    return Err(error(CodegenErrorKind::InvalidNakedAssembly));
                };
                *relocation = X86_64ExternalRelocation {
                    offset: emitted_length
                        .checked_add(external.relocation_offset)
                        .ok_or_else(|| error(CodegenErrorKind::OutputTooSmall))?,
                    symbol: external.symbol,
                    kind: X86_64ExternalRelocationKind::RipRelativeMemory,
                };
                relocation_count += 1;
                (external.encoding, external.length, external.terminating)
            } else {
                encode_x86_64_naked_instruction_for_syntax(instruction, att_syntax)
                    .ok_or_else(|| error(CodegenErrorKind::InvalidNakedAssembly))?
            };
        terminating = is_terminating;
        let end = emitted_length + encoding_length;
        bytes[emitted_length..end].copy_from_slice(&encoding[..encoding_length]);
        emitted_length = end;
    }
    if !terminating {
        return Err(error(CodegenErrorKind::InvalidNakedAssembly));
    }
    let code = MachineCode::from_bytes(&bytes[..emitted_length]).map_err(error)?;
    Ok(X86_64RelocatableMachineCode {
        code,
        relocations,
        relocation_count,
    })
}

#[derive(Clone, Copy)]
enum X86_64InlineAssembly<'source> {
    Nop,
    NopCClobber,
    Pause,
    Int3Noreturn,
    HaltLoopNoreturn,
    Int80Noreturn {
        inputs: [&'source str; 7],
    },
    Int80Returning {
        operands: [X86_64Int80Operand<'source>; 7],
    },
    CompareRegister {
        register: X86_64InlineRegister,
        input: &'source str,
    },
    SetRegister {
        register: X86_64InlineRegister,
        output: &'source str,
    },
    IncrementRegister {
        register: X86_64InlineRegister,
        input: &'source str,
        output: Option<&'source str>,
    },
    AddRaxRcx {
        left: &'source str,
        right: &'source str,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct X86_64InlineRegister(u8);

impl X86_64InlineRegister {
    const RAX: Self = Self(0);

    fn from_name(name: &str) -> Option<Self> {
        let code = x86_64_naked_register(name)?;
        (!matches!(code, 3..=5)).then_some(Self(code))
    }

    fn code(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy)]
enum X86_64InlineOperandKind {
    Input,
    Output,
    InOut,
}

#[derive(Clone, Copy)]
struct X86_64Int80Operand<'source> {
    input: &'source str,
    inout: bool,
    output: Option<&'source str>,
}

fn x86_64_inline_assembly(
    expression: &str,
) -> Result<Option<X86_64InlineAssembly<'_>>, CodegenErrorKind> {
    let expression = expression.trim();
    let Some(arguments) = expression.strip_prefix("asm!(") else {
        return Ok(None);
    };
    let arguments = arguments
        .strip_suffix(')')
        .ok_or(CodegenErrorKind::InvalidInlineAssembly)?
        .trim();
    if let Some(arguments) = arguments.strip_prefix("\"nop\"") {
        let arguments = arguments.trim();
        if arguments.is_empty() {
            return Ok(Some(X86_64InlineAssembly::Nop));
        }
        if arguments == ", clobber_abi(\"C\")" {
            return Ok(Some(X86_64InlineAssembly::NopCClobber));
        }
        let options = arguments
            .strip_prefix(',')
            .ok_or(CodegenErrorKind::InvalidInlineAssembly)?
            .trim()
            .strip_prefix("options(")
            .and_then(|options| options.strip_suffix(')'))
            .ok_or(CodegenErrorKind::InvalidInlineAssembly)?;
        x86_64_inline_assembly_options(options, true, false)?;
        return Ok(Some(X86_64InlineAssembly::Nop));
    }
    if let Some(arguments) = arguments.strip_prefix("\"pause\"") {
        let arguments = arguments.trim();
        if arguments.is_empty() {
            return Ok(Some(X86_64InlineAssembly::Pause));
        }
        let options = arguments
            .strip_prefix(',')
            .ok_or(CodegenErrorKind::InvalidInlineAssembly)?
            .trim()
            .strip_prefix("options(")
            .and_then(|options| options.strip_suffix(')'))
            .ok_or(CodegenErrorKind::InvalidInlineAssembly)?;
        x86_64_inline_assembly_options(options, true, false)?;
        return Ok(Some(X86_64InlineAssembly::Pause));
    }
    if let Some(arguments) = arguments.strip_prefix("\"int3\"") {
        return match arguments.trim() {
            ", options(noreturn, nostack)" | ", options(nostack, noreturn)" => {
                Ok(Some(X86_64InlineAssembly::Int3Noreturn))
            }
            _ => Err(CodegenErrorKind::InvalidInlineAssembly),
        };
    }
    if let Some(arguments) = arguments.strip_prefix("\"cli\"") {
        let arguments = x86_64_inline_exact_field(arguments, "\"2:\"")?;
        let arguments = x86_64_inline_exact_field(arguments, "\"hlt\"")?;
        let arguments = x86_64_inline_exact_field(arguments, "\"jmp 2b\"")?;
        return match arguments.trim() {
            ", options(noreturn, nomem, nostack)"
            | ", options(noreturn, nostack, nomem)"
            | ", options(nomem, noreturn, nostack)"
            | ", options(nomem, nostack, noreturn)"
            | ", options(nostack, noreturn, nomem)"
            | ", options(nostack, nomem, noreturn)" => {
                Ok(Some(X86_64InlineAssembly::HaltLoopNoreturn))
            }
            _ => Err(CodegenErrorKind::InvalidInlineAssembly),
        };
    }
    if let Some(arguments) = arguments.strip_prefix("\"int 0x80\"") {
        return x86_64_int80(arguments).map(Some);
    }
    if let Some(named) = arguments.strip_prefix("\"add {") {
        let separator = named
            .find("}, {")
            .ok_or(CodegenErrorKind::InvalidInlineAssembly)?;
        let left_name = &named[..separator];
        let right_template = &named[separator + 4..];
        let template_end = right_template
            .find("}\"")
            .ok_or(CodegenErrorKind::InvalidInlineAssembly)?;
        let right_name = &right_template[..template_end];
        if left_name == right_name
            || x86_64_naked_external_symbol(left_name) != Some(left_name)
            || x86_64_naked_external_symbol(right_name) != Some(right_name)
        {
            return Err(CodegenErrorKind::InvalidInlineAssembly);
        }
        let declarations = right_template[template_end + 2..]
            .trim()
            .strip_prefix(',')
            .ok_or(CodegenErrorKind::InvalidInlineAssembly)?
            .trim();
        let declarations = x86_64_inline_operand_with_options(declarations, false, true)?;
        let (left_declaration, right_declaration) = declarations
            .split_once(',')
            .ok_or(CodegenErrorKind::InvalidInlineAssembly)?;
        let (declared_left, left) = left_declaration
            .split_once('=')
            .ok_or(CodegenErrorKind::InvalidInlineAssembly)?;
        let (declared_right, right) = right_declaration
            .split_once('=')
            .ok_or(CodegenErrorKind::InvalidInlineAssembly)?;
        if declared_left.trim() != left_name || declared_right.trim() != right_name {
            return Err(CodegenErrorKind::InvalidInlineAssembly);
        }
        let left = left
            .trim()
            .strip_prefix("inout(reg)")
            .ok_or(CodegenErrorKind::InvalidInlineAssembly)?
            .trim();
        let right = right
            .trim()
            .strip_prefix("in(reg)")
            .ok_or(CodegenErrorKind::InvalidInlineAssembly)?
            .trim();
        if left.is_empty()
            || right.is_empty()
            || left.contains("=>")
            || left.contains(',')
            || right.contains(',')
        {
            return Err(CodegenErrorKind::InvalidInlineAssembly);
        }
        return Ok(Some(X86_64InlineAssembly::AddRaxRcx { left, right }));
    }
    if let Some(named) = arguments.strip_prefix("\"inc {") {
        let template_end = named
            .find("}\"")
            .ok_or(CodegenErrorKind::InvalidInlineAssembly)?;
        let operand_name = &named[..template_end];
        if x86_64_naked_external_symbol(operand_name) != Some(operand_name) {
            return Err(CodegenErrorKind::InvalidInlineAssembly);
        }
        let arguments = named[template_end + 2..]
            .trim()
            .strip_prefix(',')
            .ok_or(CodegenErrorKind::InvalidInlineAssembly)?
            .trim();
        let (declared_name, operand) = arguments
            .split_once('=')
            .ok_or(CodegenErrorKind::InvalidInlineAssembly)?;
        if declared_name.trim() != operand_name {
            return Err(CodegenErrorKind::InvalidInlineAssembly);
        }
        let operand = operand
            .trim()
            .strip_prefix("inout(reg)")
            .ok_or(CodegenErrorKind::InvalidInlineAssembly)?
            .trim();
        let operand = x86_64_inline_operand_with_options(operand, false, true)?;
        let (input, output) = x86_64_inline_inout_places(operand)?;
        return Ok(Some(X86_64InlineAssembly::IncrementRegister {
            register: X86_64InlineRegister::RAX,
            input,
            output,
        }));
    }
    let (arguments, preserves_flags, operand_kind, register) =
        x86_64_inline_fixed_register_operand(arguments)
            .ok_or(CodegenErrorKind::InvalidInlineAssembly)?;
    let has_output = matches!(
        operand_kind,
        X86_64InlineOperandKind::Output | X86_64InlineOperandKind::InOut
    );
    let input = x86_64_inline_operand_with_options(arguments, preserves_flags, has_output)?;
    match operand_kind {
        X86_64InlineOperandKind::Input => Ok(Some(X86_64InlineAssembly::CompareRegister {
            register,
            input,
        })),
        X86_64InlineOperandKind::Output => Ok(Some(X86_64InlineAssembly::SetRegister {
            register,
            output: input,
        })),
        X86_64InlineOperandKind::InOut => {
            let (input, output) = x86_64_inline_inout_places(input)?;
            Ok(Some(X86_64InlineAssembly::IncrementRegister {
                register,
                input,
                output,
            }))
        }
    }
}

fn x86_64_body_tail_diverges<const MAX_LOCALS: usize>(
    body: &crate::FunctionBody<'_, MAX_LOCALS>,
) -> bool {
    if body.tail_diverges {
        return true;
    }
    if !body.implicit_unit {
        return false;
    }
    let Some(crate::BodyStatement::Expression(index)) =
        body.statements().iter().flatten().next_back().copied()
    else {
        return false;
    };
    body.expression_statements()
        .get(index)
        .and_then(|statement| *statement)
        .is_some_and(|statement| {
            statement.terminal
                && matches!(
                    x86_64_inline_assembly(statement.expression),
                    Ok(Some(
                        X86_64InlineAssembly::Int3Noreturn
                            | X86_64InlineAssembly::HaltLoopNoreturn
                            | X86_64InlineAssembly::Int80Noreturn { .. }
                    ))
                )
        })
}

fn x86_64_inline_exact_field<'source>(
    arguments: &'source str,
    expected: &str,
) -> Result<&'source str, CodegenErrorKind> {
    arguments
        .trim()
        .strip_prefix(',')
        .map(str::trim_start)
        .and_then(|arguments| arguments.strip_prefix(expected))
        .ok_or(CodegenErrorKind::InvalidInlineAssembly)
}

fn x86_64_int80_fields(arguments: &str) -> Result<[&str; 9], CodegenErrorKind> {
    let mut fields = [""; 9];
    let mut field_count = 0usize;
    let mut start = 0usize;
    let mut depth = 0usize;
    for (index, byte) in arguments.as_bytes().iter().copied().enumerate() {
        match byte {
            b'(' | b'[' | b'{' => {
                depth = depth
                    .checked_add(1)
                    .ok_or(CodegenErrorKind::InvalidInlineAssembly)?
            }
            b')' | b']' | b'}' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or(CodegenErrorKind::InvalidInlineAssembly)?
            }
            b',' if depth == 0 => {
                if field_count == fields.len() {
                    return Err(CodegenErrorKind::InvalidInlineAssembly);
                }
                fields[field_count] = arguments[start..index].trim();
                field_count += 1;
                start = index + 1;
            }
            _ => {}
        }
    }
    if depth != 0 || field_count == fields.len() {
        return Err(CodegenErrorKind::InvalidInlineAssembly);
    }
    fields[field_count] = arguments[start..].trim();
    field_count += 1;
    if field_count != fields.len() || fields[0] != "" {
        return Err(CodegenErrorKind::InvalidInlineAssembly);
    }
    Ok(fields)
}

fn x86_64_int80(arguments: &str) -> Result<X86_64InlineAssembly<'_>, CodegenErrorKind> {
    let fields = x86_64_int80_fields(arguments)?;
    let registers = ["rax", "rdi", "rsi", "rdx", "r10", "r8", "r9"];
    if fields[8] == "options(noreturn, nostack)" || fields[8] == "options(nostack, noreturn)" {
        let mut inputs = [""; 7];
        for (index, register) in registers.iter().enumerate() {
            let prefix = x86_64_int80_operand_prefix("in", register)?;
            inputs[index] = fields[index + 1]
                .strip_prefix(prefix)
                .map(str::trim)
                .filter(|input| !input.is_empty())
                .ok_or(CodegenErrorKind::InvalidInlineAssembly)?;
        }
        return Ok(X86_64InlineAssembly::Int80Noreturn { inputs });
    }
    if fields[8] != "options(nostack)" {
        return Err(CodegenErrorKind::InvalidInlineAssembly);
    }
    let empty = X86_64Int80Operand {
        input: "",
        inout: false,
        output: None,
    };
    let mut operands = [empty; 7];
    for (index, register) in registers.iter().enumerate() {
        let field = fields[index + 1];
        let input_prefix = x86_64_int80_operand_prefix("in", register)?;
        if index != 0
            && let Some(input) = field.strip_prefix(input_prefix).map(str::trim)
            && !input.is_empty()
        {
            operands[index] = X86_64Int80Operand {
                input,
                inout: false,
                output: None,
            };
            continue;
        }
        let inout_prefix = x86_64_int80_operand_prefix("inlateout", register)?;
        let declaration = field
            .strip_prefix(inout_prefix)
            .map(str::trim)
            .ok_or(CodegenErrorKind::InvalidInlineAssembly)?;
        let (input, output) = x86_64_inline_inout_places(declaration)?;
        let effective_output = output.unwrap_or(input);
        if effective_output != "_"
            && x86_64_naked_external_symbol(effective_output) != Some(effective_output)
        {
            return Err(CodegenErrorKind::InvalidInlineAssembly);
        }
        operands[index] = X86_64Int80Operand {
            input,
            inout: true,
            output,
        };
    }
    Ok(X86_64InlineAssembly::Int80Returning { operands })
}

fn x86_64_int80_operand_prefix(
    kind: &str,
    register: &str,
) -> Result<&'static str, CodegenErrorKind> {
    match (kind, register) {
        ("in", "rax") => Ok("in(\"rax\")"),
        ("in", "rdi") => Ok("in(\"rdi\")"),
        ("in", "rsi") => Ok("in(\"rsi\")"),
        ("in", "rdx") => Ok("in(\"rdx\")"),
        ("in", "r10") => Ok("in(\"r10\")"),
        ("in", "r8") => Ok("in(\"r8\")"),
        ("in", "r9") => Ok("in(\"r9\")"),
        ("inlateout", "rax") => Ok("inlateout(\"rax\")"),
        ("inlateout", "rdi") => Ok("inlateout(\"rdi\")"),
        ("inlateout", "rsi") => Ok("inlateout(\"rsi\")"),
        ("inlateout", "rdx") => Ok("inlateout(\"rdx\")"),
        ("inlateout", "r10") => Ok("inlateout(\"r10\")"),
        ("inlateout", "r8") => Ok("inlateout(\"r8\")"),
        ("inlateout", "r9") => Ok("inlateout(\"r9\")"),
        _ => Err(CodegenErrorKind::InvalidInlineAssembly),
    }
}

fn x86_64_inline_fixed_register_operand(
    arguments: &str,
) -> Option<(&str, bool, X86_64InlineOperandKind, X86_64InlineRegister)> {
    let template = arguments.strip_prefix('"')?;
    let template_end = template.find('"')?;
    let instruction = &template[..template_end];
    let (register_name, operand_kind, operand_keyword, preserves_flags) =
        if let Some(operands) = instruction.strip_prefix("cmp ") {
            let (left, right) = operands.split_once(", ")?;
            if left != right {
                return None;
            }
            (left, X86_64InlineOperandKind::Input, "in", false)
        } else if let Some(operands) = instruction.strip_prefix("mov ") {
            let (destination, source) = operands.split_once(", ")?;
            if source != "7" {
                return None;
            }
            (
                destination,
                X86_64InlineOperandKind::Output,
                "lateout",
                true,
            )
        } else if let Some(register) = instruction.strip_prefix("inc ") {
            (register, X86_64InlineOperandKind::InOut, "inout", false)
        } else {
            return None;
        };
    let register = X86_64InlineRegister::from_name(register_name)?;
    let operand = template[template_end + 1..]
        .trim()
        .strip_prefix(',')?
        .trim()
        .strip_prefix(operand_keyword)?
        .strip_prefix("(\"")?;
    let declared_end = operand.find("\")")?;
    if &operand[..declared_end] != register_name {
        return None;
    }
    Some((
        operand[declared_end + 2..].trim(),
        preserves_flags,
        operand_kind,
        register,
    ))
}

fn x86_64_inline_move_from_rax(register: X86_64InlineRegister) -> [u8; 3] {
    let code = register.code();
    [0x48 | (code >> 3), 0x89, 0xc0 | (code & 7)]
}

fn x86_64_inline_move_to_rax(register: X86_64InlineRegister) -> [u8; 3] {
    let code = register.code();
    [0x48 | ((code >> 3) << 2), 0x89, 0xc0 | ((code & 7) << 3)]
}

fn x86_64_inline_compare_self(register: X86_64InlineRegister) -> [u8; 3] {
    let code = register.code();
    [
        0x48 | ((code >> 3) * 5),
        0x39,
        0xc0 | ((code & 7) << 3) | (code & 7),
    ]
}

fn x86_64_inline_increment(register: X86_64InlineRegister) -> [u8; 3] {
    let code = register.code();
    [0x48 | (code >> 3), 0xff, 0xc0 | (code & 7)]
}

fn x86_64_inline_set_seven(register: X86_64InlineRegister) -> [u8; 7] {
    let code = register.code();
    [
        0x48 | (code >> 3),
        0xc7,
        0xc0 | (code & 7),
        0x07,
        0x00,
        0x00,
        0x00,
    ]
}

fn x86_64_inline_operand_with_options(
    arguments: &str,
    preserves_flags: bool,
    has_output: bool,
) -> Result<&str, CodegenErrorKind> {
    let (operand, options) = if let Some(options_start) = arguments.rfind(", options(") {
        let options = arguments[options_start + 2..]
            .strip_prefix("options(")
            .and_then(|options| options.strip_suffix(')'))
            .ok_or(CodegenErrorKind::InvalidInlineAssembly)?;
        (&arguments[..options_start], Some(options))
    } else {
        (arguments, None)
    };
    let operand = operand.trim();
    if operand.is_empty() {
        return Err(CodegenErrorKind::InvalidInlineAssembly);
    }
    if let Some(options) = options {
        x86_64_inline_assembly_options(options, preserves_flags, has_output)?;
    }
    Ok(operand)
}

fn x86_64_inline_inout_places(operand: &str) -> Result<(&str, Option<&str>), CodegenErrorKind> {
    let mut operands = operand.split("=>");
    let input = operands.next().unwrap_or_default().trim();
    let output = operands.next().map(str::trim);
    if operands.next().is_some() || input.is_empty() || output.is_some_and(str::is_empty) {
        return Err(CodegenErrorKind::InvalidInlineAssembly);
    }
    Ok((input, output))
}

fn x86_64_inline_assembly_options(
    options: &str,
    allow_preserves_flags: bool,
    has_output: bool,
) -> Result<(), CodegenErrorKind> {
    let mut seen_nomem = false;
    let mut seen_nostack = false;
    let mut seen_preserves_flags = false;
    let mut seen_pure = false;
    let mut seen_readonly = false;
    let mut option_count = 0usize;
    for option in options.split(',').map(str::trim) {
        let seen = match option {
            "nomem" => &mut seen_nomem,
            "nostack" => &mut seen_nostack,
            "preserves_flags" if allow_preserves_flags => &mut seen_preserves_flags,
            "pure" => &mut seen_pure,
            "readonly" if has_output => &mut seen_readonly,
            _ => return Err(CodegenErrorKind::InvalidInlineAssembly),
        };
        if option.is_empty() || *seen {
            return Err(CodegenErrorKind::InvalidInlineAssembly);
        }
        *seen = true;
        option_count += 1;
    }
    if option_count == 0 {
        return Err(CodegenErrorKind::InvalidInlineAssembly);
    }
    if seen_nomem && seen_readonly || seen_pure && (!has_output || !(seen_nomem || seen_readonly)) {
        return Err(CodegenErrorKind::InvalidInlineAssembly);
    }
    Ok(())
}

fn x86_64_inline_output_local<'source, const MAX_PARAMETERS: usize>(
    function: &Function<'source, MAX_PARAMETERS>,
    locals: &[Option<RuntimeLocal<'source>>],
    output: &str,
    allow_immutable: bool,
) -> Result<(usize, RuntimeLocal<'source>), CodegenErrorKind> {
    if x86_64_naked_external_symbol(output) != Some(output) {
        return Err(CodegenErrorKind::InvalidInlineAssembly);
    }
    if let Some((index, local)) = locals.iter().enumerate().rev().find_map(|(index, local)| {
        local
            .filter(|local| local.name == output)
            .map(|local| (index, local))
    }) {
        if !local.mutable && !allow_immutable {
            return Err(CodegenErrorKind::ImmutableAssignment);
        }
        if local.ty != RuntimeExpressionType::Integer(Some(crate::IntegerType::U64)) {
            return Err(CodegenErrorKind::RuntimeTypeMismatch);
        }
        return Ok((index, local));
    }
    if function
        .parameters()
        .iter()
        .flatten()
        .any(|parameter| parameter.name == output)
    {
        return Err(CodegenErrorKind::ImmutableAssignment);
    }
    Err(CodegenErrorKind::UnknownRuntimeName)
}

fn x86_64_inline_output_tuple_field<'source, const MAX_PARAMETERS: usize>(
    function: &Function<'source, MAX_PARAMETERS>,
    locals: &[Option<RuntimeLocal<'source>>],
    output: &str,
) -> Result<Option<(usize, RuntimeLocal<'source>, usize)>, CodegenErrorKind> {
    let Some((name, field)) = output.rsplit_once('.') else {
        return Ok(None);
    };
    if name.contains('.') || x86_64_naked_external_symbol(name) != Some(name) {
        return Err(CodegenErrorKind::InvalidInlineAssembly);
    }
    let field = field
        .parse::<usize>()
        .map_err(|_| CodegenErrorKind::InvalidInlineAssembly)?;
    let (index, local) = locals
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, local)| {
            local
                .filter(|local| local.name == name)
                .map(|local| (index, local))
        })
        .ok_or_else(|| {
            if function
                .parameters()
                .iter()
                .flatten()
                .any(|parameter| parameter.name == name)
            {
                CodegenErrorKind::ImmutableAssignment
            } else {
                CodegenErrorKind::UnknownRuntimeName
            }
        })?;
    if !local.mutable {
        return Err(CodegenErrorKind::ImmutableAssignment);
    }
    let RuntimeExpressionType::Tuple {
        elements,
        element_count,
    } = local.ty
    else {
        return Err(CodegenErrorKind::RuntimeTypeMismatch);
    };
    let element = elements
        .get(field)
        .filter(|_| field < element_count)
        .and_then(|element| *element)
        .ok_or(CodegenErrorKind::ValueOutOfRange)?;
    if runtime_type_from_tuple_element(element)
        != RuntimeExpressionType::Integer(Some(crate::IntegerType::U64))
    {
        return Err(CodegenErrorKind::RuntimeTypeMismatch);
    }
    Ok(Some((index, local, field)))
}

fn x86_64_inline_output_array_element<'source, const MAX_PARAMETERS: usize>(
    function: &Function<'source, MAX_PARAMETERS>,
    locals: &[Option<RuntimeLocal<'source>>],
    output: &str,
) -> Result<Option<(usize, RuntimeLocal<'source>, usize)>, CodegenErrorKind> {
    let Some(output) = output.strip_suffix(']') else {
        return Ok(None);
    };
    let Some((name, element)) = output.rsplit_once('[') else {
        return Err(CodegenErrorKind::InvalidInlineAssembly);
    };
    if name.contains(['[', ']']) || x86_64_naked_external_symbol(name) != Some(name) {
        return Err(CodegenErrorKind::InvalidInlineAssembly);
    }
    let Ok(element) = element.parse::<usize>() else {
        return Ok(None);
    };
    if !locals.iter().flatten().any(|local| local.name == name) {
        if let Some(parameter) = function
            .parameters()
            .iter()
            .flatten()
            .find(|parameter| parameter.name == name)
        {
            let ty = runtime_type_from_text(parameter.ty.text)
                .ok_or(CodegenErrorKind::RuntimeTypeMismatch)?;
            if matches!(
                ty,
                RuntimeExpressionType::Reference {
                    target: RuntimeReferenceTarget::Array { .. } | RuntimeReferenceTarget::Slice(_),
                    mutable: true,
                }
            ) {
                return Ok(None);
            }
        }
    }
    let (index, local) = locals
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, local)| {
            local
                .filter(|local| local.name == name)
                .map(|local| (index, local))
        })
        .ok_or_else(|| {
            if function
                .parameters()
                .iter()
                .flatten()
                .any(|parameter| parameter.name == name)
            {
                CodegenErrorKind::ImmutableAssignment
            } else {
                CodegenErrorKind::UnknownRuntimeName
            }
        })?;
    if !local.mutable {
        return Err(CodegenErrorKind::ImmutableAssignment);
    }
    let RuntimeExpressionType::Array { element: ty, count } = local.ty else {
        if matches!(
            local.ty,
            RuntimeExpressionType::Reference {
                target: RuntimeReferenceTarget::Array { .. } | RuntimeReferenceTarget::Slice(_),
                mutable: true,
            }
        ) {
            return Ok(None);
        }
        return Err(CodegenErrorKind::RuntimeTypeMismatch);
    };
    if element >= count {
        return Err(CodegenErrorKind::ValueOutOfRange);
    }
    if runtime_type_from_array_element(ty)
        != RuntimeExpressionType::Integer(Some(crate::IntegerType::U64))
    {
        return Err(CodegenErrorKind::RuntimeTypeMismatch);
    }
    Ok(Some((index, local, element)))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct X86_64InlineOutputPlace<'source> {
    base: RuntimePlaceIdentity,
    ty: RuntimeExpressionType,
    projections: RuntimePlaceProjections,
    storage: X86_64InlineOutputStorage<'source>,
    marker: core::marker::PhantomData<&'source ()>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum X86_64InlineOutputStorage<'source> {
    LocalStack {
        local_index: usize,
        offset: usize,
    },
    LocalPointer {
        local_index: usize,
    },
    ParameterPointer {
        parameter_index: usize,
    },
    LocalDynamicArray {
        local_index: usize,
        element: RuntimeArrayElementType,
        count: usize,
        index: &'source str,
    },
    LocalDynamicReferenceArray {
        local_index: usize,
        element: RuntimeArrayElementType,
        count: usize,
        layout: RuntimeReferenceArrayLayout,
        index: &'source str,
    },
    ParameterDynamicReferenceArray {
        parameter_index: usize,
        element: RuntimeArrayElementType,
        count: usize,
        layout: RuntimeReferenceArrayLayout,
        index: &'source str,
    },
    LocalDynamicSlice {
        local_index: usize,
        element: RuntimeArrayElementType,
        index: &'source str,
    },
    ParameterDynamicSlice {
        parameter_index: usize,
        element: RuntimeArrayElementType,
        index: &'source str,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum X86_64InlineResolvedOutputStorage<'source> {
    StackSlot(usize),
    PointerSlot(usize),
    DynamicArray {
        local_index: usize,
        element: RuntimeArrayElementType,
        count: usize,
        index: &'source str,
    },
    DynamicReferenceArray {
        pointer_slot: usize,
        element: RuntimeArrayElementType,
        count: usize,
        layout: RuntimeReferenceArrayLayout,
        index: &'source str,
    },
    DynamicSlice {
        pointer_slot: usize,
        length_slot: usize,
        element: RuntimeArrayElementType,
        index: &'source str,
    },
}

fn x86_64_inline_output_place<'source, const MAX_PARAMETERS: usize>(
    function: &Function<'source, MAX_PARAMETERS>,
    locals: &[Option<RuntimeLocal<'source>>],
    output: &'source str,
) -> Result<X86_64InlineOutputPlace<'source>, CodegenErrorKind> {
    if let Some((local_index, local, field)) =
        x86_64_inline_output_tuple_field(function, locals, output)?
    {
        return Ok(X86_64InlineOutputPlace {
            base: RuntimePlaceIdentity::Local(local.id),
            ty: local.ty,
            projections: RuntimePlaceProjections::single(RuntimePlaceProjection::TupleField(field)),
            storage: X86_64InlineOutputStorage::LocalStack {
                local_index,
                offset: field,
            },
            marker: core::marker::PhantomData,
        });
    }
    if let Some((local_index, local, element)) =
        x86_64_inline_output_array_element(function, locals, output)?
    {
        return Ok(X86_64InlineOutputPlace {
            base: RuntimePlaceIdentity::Local(local.id),
            ty: local.ty,
            projections: RuntimePlaceProjections::single(RuntimePlaceProjection::ArrayElement(
                element,
            )),
            storage: X86_64InlineOutputStorage::LocalStack {
                local_index,
                offset: element,
            },
            marker: core::marker::PhantomData,
        });
    }
    if let Some(output) = output.strip_suffix(']') {
        let (name, index) = output
            .rsplit_once('[')
            .ok_or(CodegenErrorKind::InvalidInlineAssembly)?;
        if name.contains(['[', ']'])
            || x86_64_naked_external_symbol(name) != Some(name)
            || index.is_empty()
        {
            return Err(CodegenErrorKind::InvalidInlineAssembly);
        }
        if let Some((local_index, local)) =
            locals
                .iter()
                .enumerate()
                .rev()
                .find_map(|(local_index, local)| {
                    local
                        .filter(|local| local.name == name)
                        .map(|local| (local_index, local))
                })
        {
            if !local.mutable {
                return Err(CodegenErrorKind::ImmutableAssignment);
            }
            let (element, count, layout, reference, slice) = match local.ty {
                RuntimeExpressionType::Array { element, count } => {
                    (element, count, None, false, false)
                }
                RuntimeExpressionType::Reference {
                    target:
                        RuntimeReferenceTarget::Array {
                            element,
                            count,
                            layout,
                        },
                    mutable: true,
                } => (element, count, Some(layout), true, false),
                RuntimeExpressionType::Reference {
                    target: RuntimeReferenceTarget::Slice(element),
                    mutable: true,
                } => (element, 0, None, true, true),
                _ => return Err(CodegenErrorKind::RuntimeTypeMismatch),
            };
            if runtime_type_from_array_element(element)
                != RuntimeExpressionType::Integer(Some(crate::IntegerType::U64))
            {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            let mut projections = RuntimePlaceProjections::EMPTY;
            if reference && !slice {
                projections.push(RuntimePlaceProjection::Dereference)?;
            }
            projections.push(RuntimePlaceProjection::Index)?;
            return Ok(X86_64InlineOutputPlace {
                base: RuntimePlaceIdentity::Local(local.id),
                ty: local.ty,
                projections,
                storage: if slice {
                    X86_64InlineOutputStorage::LocalDynamicSlice {
                        local_index,
                        element,
                        index,
                    }
                } else if let Some(layout) = layout {
                    X86_64InlineOutputStorage::LocalDynamicReferenceArray {
                        local_index,
                        element,
                        count,
                        layout,
                        index,
                    }
                } else {
                    X86_64InlineOutputStorage::LocalDynamicArray {
                        local_index,
                        element,
                        count,
                        index,
                    }
                },
                marker: core::marker::PhantomData,
            });
        }
        if let Some((parameter_index, parameter)) = function
            .parameters()
            .iter()
            .flatten()
            .enumerate()
            .find(|(_, parameter)| parameter.name == name)
        {
            let ty = runtime_type_from_text(parameter.ty.text)
                .ok_or(CodegenErrorKind::RuntimeTypeMismatch)?;
            let (element, storage, slice) = match ty {
                RuntimeExpressionType::Reference {
                    target:
                        RuntimeReferenceTarget::Array {
                            element,
                            count,
                            layout,
                        },
                    mutable: true,
                } => (
                    element,
                    X86_64InlineOutputStorage::ParameterDynamicReferenceArray {
                        parameter_index,
                        element,
                        count,
                        layout,
                        index,
                    },
                    false,
                ),
                RuntimeExpressionType::Reference {
                    target: RuntimeReferenceTarget::Slice(element),
                    mutable: true,
                } => (
                    element,
                    X86_64InlineOutputStorage::ParameterDynamicSlice {
                        parameter_index,
                        element,
                        index,
                    },
                    true,
                ),
                RuntimeExpressionType::Reference { mutable: false, .. } => {
                    return Err(CodegenErrorKind::ImmutableAssignment);
                }
                _ => return Err(CodegenErrorKind::RuntimeTypeMismatch),
            };
            if runtime_type_from_array_element(element)
                != RuntimeExpressionType::Integer(Some(crate::IntegerType::U64))
            {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            let mut projections = RuntimePlaceProjections::EMPTY;
            if !slice {
                projections.push(RuntimePlaceProjection::Dereference)?;
            }
            projections.push(RuntimePlaceProjection::Index)?;
            return Ok(X86_64InlineOutputPlace {
                base: RuntimePlaceIdentity::Parameter(parameter_index),
                ty,
                projections,
                storage,
                marker: core::marker::PhantomData,
            });
        }
        return Err(CodegenErrorKind::UnknownRuntimeName);
    }
    if let Some(name) = output.strip_prefix('*') {
        if name.is_empty() || x86_64_naked_external_symbol(name) != Some(name) {
            return Err(CodegenErrorKind::InvalidInlineAssembly);
        }
        let mutable_u64_pointee = |ty| {
            matches!(
                ty,
                RuntimeExpressionType::Reference {
                    target: RuntimeReferenceTarget::Scalar(RuntimeArrayElementType::Integer(Some(
                        crate::IntegerType::U64
                    ))),
                    mutable: true,
                } | RuntimeExpressionType::RawPointer {
                    pointee: RuntimeArrayElementType::Integer(Some(crate::IntegerType::U64)),
                    mutable: true,
                }
            )
        };
        if let Some((local_index, local)) =
            locals.iter().enumerate().rev().find_map(|(index, local)| {
                local
                    .filter(|local| local.name == name)
                    .map(|local| (index, local))
            })
        {
            if !mutable_u64_pointee(local.ty) {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            return Ok(X86_64InlineOutputPlace {
                base: RuntimePlaceIdentity::Local(local.id),
                ty: local.ty,
                projections: RuntimePlaceProjections::single(RuntimePlaceProjection::Dereference),
                storage: X86_64InlineOutputStorage::LocalPointer { local_index },
                marker: core::marker::PhantomData,
            });
        }
        if let Some((parameter_index, parameter)) = function
            .parameters()
            .iter()
            .flatten()
            .enumerate()
            .find(|(_, parameter)| parameter.name == name)
        {
            let ty = runtime_type_from_text(parameter.ty.text)
                .ok_or(CodegenErrorKind::RuntimeTypeMismatch)?;
            if !mutable_u64_pointee(ty) {
                return Err(CodegenErrorKind::RuntimeTypeMismatch);
            }
            return Ok(X86_64InlineOutputPlace {
                base: RuntimePlaceIdentity::Parameter(parameter_index),
                ty,
                projections: RuntimePlaceProjections::single(RuntimePlaceProjection::Dereference),
                storage: X86_64InlineOutputStorage::ParameterPointer { parameter_index },
                marker: core::marker::PhantomData,
            });
        }
        return Err(CodegenErrorKind::UnknownRuntimeName);
    }
    let (local_index, local) = x86_64_inline_output_local(function, locals, output, false)?;
    Ok(X86_64InlineOutputPlace {
        base: RuntimePlaceIdentity::Local(local.id),
        ty: local.ty,
        projections: RuntimePlaceProjections::EMPTY,
        storage: X86_64InlineOutputStorage::LocalStack {
            local_index,
            offset: 0,
        },
        marker: core::marker::PhantomData,
    })
}

fn encode_x86_64_naked_instruction_for_syntax(
    instruction: &str,
    att_syntax: bool,
) -> Option<([u8; 10], usize, bool)> {
    if att_syntax {
        encode_x86_64_naked_att_instruction(instruction)
    } else {
        encode_x86_64_naked_instruction(instruction)
    }
}

fn x86_64_naked_label_definition(instruction: &str) -> Option<u8> {
    let bytes = instruction.as_bytes();
    (bytes.len() == 2 && (b'2'..=b'9').contains(&bytes[0]) && bytes[1] == b':')
        .then(|| bytes[0] - b'0')
}

fn x86_64_naked_label_branch(instruction: &str) -> Option<(u8, u8)> {
    let bytes = instruction.as_bytes();
    (bytes.len() == 6
        && &bytes[..4] == b"jmp "
        && (b'2'..=b'9').contains(&bytes[4])
        && (bytes[5] == b'f' || bytes[5] == b'b'))
        .then(|| (bytes[4] - b'0', bytes[5]))
}

fn x86_64_naked_external_branch(instruction: &str, att_syntax: bool) -> Option<&str> {
    if x86_64_naked_label_branch(instruction).is_some() {
        return None;
    }
    let symbol = instruction.strip_prefix("jmp ")?;
    if symbol.is_empty()
        || symbol.starts_with('[')
        || symbol.starts_with('*')
        || symbol.starts_with('%')
        || (!att_syntax && x86_64_naked_register(symbol).is_some())
    {
        return None;
    }
    x86_64_naked_external_symbol(symbol)
}

fn x86_64_naked_external_symbol(symbol: &str) -> Option<&str> {
    let mut bytes = symbol.bytes();
    let first = bytes.next()?;
    if !(first == b'_' || first.is_ascii_alphabetic())
        || !bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
    {
        return None;
    }
    Some(symbol)
}

struct X86_64NakedExternalMemory<'symbol> {
    encoding: [u8; 10],
    length: usize,
    relocation_offset: usize,
    terminating: bool,
    symbol: &'symbol str,
}

fn x86_64_naked_external_memory_instruction(
    instruction: &str,
    att_syntax: bool,
) -> Option<X86_64NakedExternalMemory<'_>> {
    let (mnemonic, operands) = instruction.split_once(' ')?;
    let operands = operands.trim();
    let (prefix, opcode, wide, register, operand, terminating) = if att_syntax {
        match mnemonic {
            "jmp" => (None, 0xff, false, 4, operands.strip_prefix('*')?, true),
            "movq" => {
                let (source, destination) = x86_64_naked_att_operands(operands)?;
                let source = source.trim();
                let destination = destination.trim();
                if let Some(register) = x86_64_naked_att_register(destination) {
                    (None, 0x8b, true, register, source, false)
                } else {
                    (
                        None,
                        0x89,
                        true,
                        x86_64_naked_att_register(source)?,
                        destination,
                        false,
                    )
                }
            }
            "lgdt" | "lidt" | "invlpg" => (
                Some(0x0f),
                0x01,
                false,
                match mnemonic {
                    "lgdt" => 2,
                    "lidt" => 3,
                    _ => 7,
                },
                operands,
                false,
            ),
            _ => return None,
        }
    } else {
        match mnemonic {
            "jmp" => (None, 0xff, false, 4, operands, true),
            "mov" => {
                let (destination, source) = operands.split_once(',')?;
                let destination = destination.trim();
                let source = source.trim();
                if let Some(register) = x86_64_naked_register(destination) {
                    (None, 0x8b, true, register, source, false)
                } else {
                    (
                        None,
                        0x89,
                        true,
                        x86_64_naked_register(source)?,
                        destination,
                        false,
                    )
                }
            }
            "lgdt" | "lidt" | "invlpg" => (
                Some(0x0f),
                0x01,
                false,
                match mnemonic {
                    "lgdt" => 2,
                    "lidt" => 3,
                    _ => 7,
                },
                operands,
                false,
            ),
            _ => return None,
        }
    };
    let symbol = if att_syntax {
        let open = operand.find('(')?;
        if operand[open + 1..].strip_suffix(')')?.trim() != "%rip" {
            return None;
        }
        x86_64_naked_external_symbol(operand[..open].trim())?
    } else {
        let expression = operand.strip_prefix('[')?.strip_suffix(']')?.trim();
        let mut tokens = expression.split_whitespace();
        if tokens.next()? != "rip" || tokens.next()? != "+" {
            return None;
        }
        let symbol = x86_64_naked_external_symbol(tokens.next()?)?;
        if tokens.next().is_some() {
            return None;
        }
        symbol
    };
    let mut encoding = [0u8; 10];
    let mut length = 0usize;
    let rex = 0x40 | ((wide as u8) << 3) | ((register >> 3) << 2);
    if rex != 0x40 {
        encoding[length] = rex;
        length += 1;
    }
    if let Some(prefix) = prefix {
        encoding[length] = prefix;
        length += 1;
    }
    encoding[length] = opcode;
    length += 1;
    encoding[length] = ((register & 7) << 3) | 5;
    length += 1;
    let relocation_offset = length;
    length += 4;
    Some(X86_64NakedExternalMemory {
        encoding,
        length,
        relocation_offset,
        terminating,
        symbol,
    })
}

fn encode_x86_64_naked_instruction(instruction: &str) -> Option<([u8; 10], usize, bool)> {
    let fixed = match instruction {
        "nop" => Some(([0x90, 0, 0, 0, 0, 0, 0, 0, 0, 0], 1, false)),
        "ret" => Some(([0xc3, 0, 0, 0, 0, 0, 0, 0, 0, 0], 1, true)),
        "int3" => Some(([0xcc, 0, 0, 0, 0, 0, 0, 0, 0, 0], 1, false)),
        "ud2" => Some(([0x0f, 0x0b, 0, 0, 0, 0, 0, 0, 0, 0], 2, true)),
        "cli" => Some(([0xfa, 0, 0, 0, 0, 0, 0, 0, 0, 0], 1, false)),
        "sti" => Some(([0xfb, 0, 0, 0, 0, 0, 0, 0, 0, 0], 1, false)),
        "hlt" => Some(([0xf4, 0, 0, 0, 0, 0, 0, 0, 0, 0], 1, true)),
        "swapgs" => Some(([0x0f, 0x01, 0xf8, 0, 0, 0, 0, 0, 0, 0], 3, false)),
        "iretq" => Some(([0x48, 0xcf, 0, 0, 0, 0, 0, 0, 0, 0], 2, true)),
        _ => None,
    };
    if fixed.is_some() {
        return fixed;
    }
    let (mnemonic, operands) = instruction.split_once(' ')?;
    let operands = operands.trim();
    match mnemonic {
        "push" | "pop" => {
            let register = x86_64_naked_register(operands);
            let opcode = if mnemonic == "push" { 0x50 } else { 0x58 };
            if let Some(register) = register {
                if register < 8 {
                    Some(([opcode + register, 0, 0, 0, 0, 0, 0, 0, 0, 0], 1, false))
                } else {
                    Some((
                        [0x41, opcode + (register & 7), 0, 0, 0, 0, 0, 0, 0, 0],
                        2,
                        false,
                    ))
                }
            } else if mnemonic == "push" {
                let (immediate, negative) = x86_64_naked_signed_immediate(operands)?;
                if negative {
                    let immediate = i64::from_le_bytes(immediate.to_le_bytes());
                    let immediate = i32::try_from(immediate).ok()?;
                    if let Ok(immediate) = i8::try_from(immediate) {
                        Some(([0x6a, immediate as u8, 0, 0, 0, 0, 0, 0, 0, 0], 2, false))
                    } else {
                        let mut encoding = [0u8; 10];
                        encoding[0] = 0x68;
                        encoding[1..5].copy_from_slice(&immediate.to_le_bytes());
                        Some((encoding, 5, false))
                    }
                } else if immediate <= i8::MAX as u64 {
                    Some(([0x6a, immediate as u8, 0, 0, 0, 0, 0, 0, 0, 0], 2, false))
                } else if immediate <= i32::MAX as u64 {
                    let mut encoding = [0u8; 10];
                    encoding[0] = 0x68;
                    encoding[1..5].copy_from_slice(&(immediate as u32).to_le_bytes());
                    Some((encoding, 5, false))
                } else {
                    None
                }
            } else {
                None
            }
        }
        "jmp" => {
            if let Some(register) = x86_64_naked_register(operands) {
                if register < 8 {
                    Some(([0xff, 0xe0 + register, 0, 0, 0, 0, 0, 0, 0, 0], 2, true))
                } else {
                    Some((
                        [0x41, 0xff, 0xe0 + (register & 7), 0, 0, 0, 0, 0, 0, 0],
                        3,
                        true,
                    ))
                }
            } else {
                let address = x86_64_naked_memory_address(operands)?;
                encode_x86_64_naked_memory(None, 0xff, false, 4, address, true)
            }
        }
        "mov" => {
            let (destination, source) = operands.split_once(',')?;
            let destination = destination.trim();
            let source = source.trim();
            if let Some(destination) = x86_64_naked_register(destination) {
                if let Some(source) = x86_64_naked_register(source) {
                    let rex = 0x48 | ((source >> 3) << 2) | (destination >> 3);
                    let modrm = 0xc0 | ((source & 7) << 3) | (destination & 7);
                    Some(([rex, 0x89, modrm, 0, 0, 0, 0, 0, 0, 0], 3, false))
                } else if let Some(address) = x86_64_naked_memory_address(source) {
                    encode_x86_64_naked_memory(None, 0x8b, true, destination, address, false)
                } else {
                    let (immediate, _) = x86_64_naked_signed_immediate(source)?;
                    let mut encoding = [0u8; 10];
                    encoding[0] = 0x48 | (destination >> 3);
                    encoding[1] = 0xb8 + (destination & 7);
                    encoding[2..10].copy_from_slice(&immediate.to_le_bytes());
                    Some((encoding, 10, false))
                }
            } else {
                let address = x86_64_naked_memory_address(destination)?;
                let source = x86_64_naked_register(source)?;
                encode_x86_64_naked_memory(None, 0x89, true, source, address, false)
            }
        }
        "lgdt" | "lidt" | "invlpg" => {
            let address = x86_64_naked_memory_address(operands)?;
            let extension = match mnemonic {
                "lgdt" => 2,
                "lidt" => 3,
                _ => 7,
            };
            encode_x86_64_naked_memory(Some(0x0f), 0x01, false, extension, address, false)
        }
        _ => None,
    }
}

fn encode_x86_64_naked_att_instruction(instruction: &str) -> Option<([u8; 10], usize, bool)> {
    if !instruction.contains(' ') {
        if let Some(fixed) = encode_x86_64_naked_instruction(instruction) {
            return Some(fixed);
        }
    }
    let (mnemonic, operands) = instruction.split_once(' ')?;
    let operands = operands.trim();
    match mnemonic {
        "push" | "pushq" | "pop" | "popq" => {
            let push = mnemonic.starts_with("push");
            let opcode = if push { 0x50 } else { 0x58 };
            if let Some(register) = x86_64_naked_att_register(operands) {
                if register < 8 {
                    Some(([opcode + register, 0, 0, 0, 0, 0, 0, 0, 0, 0], 1, false))
                } else {
                    Some((
                        [0x41, opcode + (register & 7), 0, 0, 0, 0, 0, 0, 0, 0],
                        2,
                        false,
                    ))
                }
            } else if push {
                let (immediate, negative) =
                    x86_64_naked_signed_immediate(operands.strip_prefix('$')?)?;
                let immediate = if negative {
                    i32::try_from(i64::from_le_bytes(immediate.to_le_bytes())).ok()?
                } else {
                    i32::try_from(immediate).ok()?
                };
                if let Ok(immediate) = i8::try_from(immediate) {
                    Some(([0x6a, immediate as u8, 0, 0, 0, 0, 0, 0, 0, 0], 2, false))
                } else {
                    let mut encoding = [0u8; 10];
                    encoding[0] = 0x68;
                    encoding[1..5].copy_from_slice(&immediate.to_le_bytes());
                    Some((encoding, 5, false))
                }
            } else {
                None
            }
        }
        "jmp" => {
            let operand = operands.strip_prefix('*')?;
            if let Some(register) = x86_64_naked_att_register(operand) {
                if register < 8 {
                    Some(([0xff, 0xe0 + register, 0, 0, 0, 0, 0, 0, 0, 0], 2, true))
                } else {
                    Some((
                        [0x41, 0xff, 0xe0 + (register & 7), 0, 0, 0, 0, 0, 0, 0],
                        3,
                        true,
                    ))
                }
            } else {
                let address = x86_64_naked_att_memory_address(operand)?;
                encode_x86_64_naked_memory(None, 0xff, false, 4, address, true)
            }
        }
        "movq" | "movabsq" => {
            let (source, destination) = x86_64_naked_att_operands(operands)?;
            let source = source.trim();
            let destination = destination.trim();
            if let Some(destination) = x86_64_naked_att_register(destination) {
                if let Some(source) = x86_64_naked_att_register(source) {
                    if mnemonic == "movabsq" {
                        return None;
                    }
                    let rex = 0x48 | ((source >> 3) << 2) | (destination >> 3);
                    let modrm = 0xc0 | ((source & 7) << 3) | (destination & 7);
                    Some(([rex, 0x89, modrm, 0, 0, 0, 0, 0, 0, 0], 3, false))
                } else if let Some(immediate) = source.strip_prefix('$') {
                    let (immediate, _) = x86_64_naked_signed_immediate(immediate)?;
                    let mut encoding = [0u8; 10];
                    encoding[0] = 0x48 | (destination >> 3);
                    encoding[1] = 0xb8 + (destination & 7);
                    encoding[2..10].copy_from_slice(&immediate.to_le_bytes());
                    Some((encoding, 10, false))
                } else if mnemonic == "movq" {
                    let address = x86_64_naked_att_memory_address(source)?;
                    encode_x86_64_naked_memory(None, 0x8b, true, destination, address, false)
                } else {
                    None
                }
            } else if mnemonic == "movq" {
                let address = x86_64_naked_att_memory_address(destination)?;
                let source = x86_64_naked_att_register(source)?;
                encode_x86_64_naked_memory(None, 0x89, true, source, address, false)
            } else {
                None
            }
        }
        "lgdt" | "lidt" | "invlpg" => {
            let address = x86_64_naked_att_memory_address(operands)?;
            let extension = match mnemonic {
                "lgdt" => 2,
                "lidt" => 3,
                _ => 7,
            };
            encode_x86_64_naked_memory(Some(0x0f), 0x01, false, extension, address, false)
        }
        _ => None,
    }
}

fn x86_64_naked_att_operands(operands: &str) -> Option<(&str, &str)> {
    let mut depth = 0u8;
    for (index, byte) in operands.bytes().enumerate() {
        match byte {
            b'(' => depth = depth.checked_add(1)?,
            b')' => depth = depth.checked_sub(1)?,
            b',' if depth == 0 => return Some((&operands[..index], &operands[index + 1..])),
            _ => {}
        }
    }
    None
}

fn x86_64_naked_att_register(register: &str) -> Option<u8> {
    x86_64_naked_register(register.strip_prefix('%')?)
}

fn x86_64_naked_att_memory_address(operand: &str) -> Option<X86_64NakedMemoryAddress> {
    let Some(open) = operand.find('(') else {
        return Some(X86_64NakedMemoryAddress {
            base: None,
            index: None,
            scale: 0,
            displacement: x86_64_naked_i32(operand.trim())?,
        });
    };
    let displacement = operand[..open].trim();
    let registers = operand[open + 1..].strip_suffix(')')?;
    if registers.contains(')') {
        return None;
    }
    let mut fields = registers.split(',');
    let base = match fields.next()?.trim() {
        "" => None,
        base => Some(x86_64_naked_att_register(base)?),
    };
    let index = fields.next().map(str::trim);
    let scale = fields.next().map(str::trim);
    if fields.next().is_some() {
        return None;
    }
    let (index, scale) = match (index, scale) {
        (None, None) => (None, 0),
        (Some(index), scale) if !index.is_empty() => {
            let index = x86_64_naked_att_register(index)?;
            if index == 4 {
                return None;
            }
            let scale = scale.map_or(Some(0), x86_64_naked_scale)?;
            (Some(index), scale)
        }
        _ => return None,
    };
    let displacement = if displacement.is_empty() {
        0
    } else {
        x86_64_naked_i32(displacement)?
    };
    Some(X86_64NakedMemoryAddress {
        base,
        index,
        scale,
        displacement,
    })
}

fn encode_x86_64_naked_memory(
    prefix: Option<u8>,
    opcode: u8,
    wide: bool,
    register: u8,
    address: X86_64NakedMemoryAddress,
    terminating: bool,
) -> Option<([u8; 10], usize, bool)> {
    if register >= 16
        || address.base.is_some_and(|base| base >= 16)
        || address.index.is_some_and(|index| index >= 16)
    {
        return None;
    }
    let mut encoding = [0u8; 10];
    let mut length = 0usize;
    let rex = 0x40
        | ((wide as u8) << 3)
        | ((register >> 3) << 2)
        | (address.index.map_or(0, |index| index >> 3) << 1)
        | address.base.map_or(0, |base| base >> 3);
    if rex != 0x40 {
        encoding[length] = rex;
        length += 1;
    }
    if let Some(prefix) = prefix {
        encoding[length] = prefix;
        length += 1;
    }
    encoding[length] = opcode;
    length += 1;
    let register = (register & 7) << 3;
    let displacement_size = if address.base.is_none() {
        4
    } else if address.displacement == 0 && address.base? & 7 != 5 {
        0
    } else if i8::try_from(address.displacement).is_ok() {
        1
    } else {
        4
    };
    let mode = match (address.base, displacement_size) {
        (None, _) => 0,
        (_, 0) => 0,
        (_, 1) => 0x40,
        _ => 0x80,
    };
    let base = address.base.map_or(5, |base| base & 7);
    let uses_sib = address.base.is_none() || address.index.is_some() || base == 4;
    encoding[length] = mode | register | if uses_sib { 4 } else { base };
    length += 1;
    if uses_sib {
        let index = address.index.map_or(4, |index| index & 7);
        encoding[length] = (address.scale << 6) | (index << 3) | base;
        length += 1;
    }
    match displacement_size {
        0 => {}
        1 => {
            encoding[length] = address.displacement as i8 as u8;
            length += 1;
        }
        _ => {
            encoding[length..length + 4].copy_from_slice(&address.displacement.to_le_bytes());
            length += 4;
        }
    }
    Some((encoding, length, terminating))
}

#[derive(Clone, Copy)]
struct X86_64NakedMemoryAddress {
    base: Option<u8>,
    index: Option<u8>,
    scale: u8,
    displacement: i32,
}

fn x86_64_naked_memory_address(operand: &str) -> Option<X86_64NakedMemoryAddress> {
    let expression = operand.strip_prefix('[')?.strip_suffix(']')?.trim();
    let mut tokens = expression.split_whitespace();
    let first = tokens.next()?;
    let Some(first_register) = x86_64_naked_register(first) else {
        let displacement = x86_64_naked_i32(first)?;
        return tokens.next().is_none().then_some(X86_64NakedMemoryAddress {
            base: None,
            index: None,
            scale: 0,
            displacement,
        });
    };
    let Some(operator) = tokens.next() else {
        return Some(X86_64NakedMemoryAddress {
            base: Some(first_register),
            index: None,
            scale: 0,
            displacement: 0,
        });
    };
    if operator == "*" {
        if first_register == 4 {
            return None;
        }
        let scale = x86_64_naked_scale(tokens.next()?)?;
        let mut address = X86_64NakedMemoryAddress {
            base: None,
            index: Some(first_register),
            scale,
            displacement: 0,
        };
        let Some(displacement_operator) = tokens.next() else {
            return Some(address);
        };
        if displacement_operator != "+" && displacement_operator != "-" {
            return None;
        }
        address.displacement = x86_64_naked_displacement(tokens.next()?, displacement_operator)?;
        return tokens.next().is_none().then_some(address);
    }
    let mut address = X86_64NakedMemoryAddress {
        base: Some(first_register),
        index: None,
        scale: 0,
        displacement: 0,
    };
    if operator != "+" && operator != "-" {
        return None;
    }
    let next = tokens.next()?;
    if let Some(index) = x86_64_naked_register(next) {
        if operator != "+" || index == 4 || tokens.next()? != "*" {
            return None;
        }
        address.index = Some(index);
        address.scale = x86_64_naked_scale(tokens.next()?)?;
        let Some(displacement_operator) = tokens.next() else {
            return Some(address);
        };
        if displacement_operator != "+" && displacement_operator != "-" {
            return None;
        }
        address.displacement = x86_64_naked_displacement(tokens.next()?, displacement_operator)?;
    } else {
        address.displacement = x86_64_naked_displacement(next, operator)?;
    }
    tokens.next().is_none().then_some(address)
}

fn x86_64_naked_scale(scale: &str) -> Option<u8> {
    Some(match scale {
        "1" => 0,
        "2" => 1,
        "4" => 2,
        "8" => 3,
        _ => return None,
    })
}

fn x86_64_naked_i32(value: &str) -> Option<i32> {
    let (bits, negative) = x86_64_naked_signed_immediate(value)?;
    if negative {
        i32::try_from(i64::from_le_bytes(bits.to_le_bytes())).ok()
    } else {
        i32::try_from(bits).ok()
    }
}

fn x86_64_naked_displacement(value: &str, operator: &str) -> Option<i32> {
    let magnitude = x86_64_naked_immediate(value)?;
    if operator == "+" {
        i32::try_from(magnitude).ok()
    } else {
        let magnitude = i64::try_from(magnitude).ok()?;
        i32::try_from(-magnitude).ok()
    }
}

fn x86_64_naked_immediate(source: &str) -> Option<u64> {
    let (radix, digits) = source
        .strip_prefix("0x")
        .map_or((10u64, source), |digits| (16, digits));
    let mut value = 0u64;
    let mut saw_digit = false;
    let mut separator = false;
    for byte in digits.bytes() {
        if byte == b'_' && saw_digit && !separator {
            separator = true;
            continue;
        }
        let digit = match byte {
            b'0'..=b'9' => (byte - b'0') as u64,
            b'a'..=b'f' if radix == 16 => (byte - b'a' + 10) as u64,
            b'A'..=b'F' if radix == 16 => (byte - b'A' + 10) as u64,
            _ => return None,
        };
        if digit >= radix {
            return None;
        }
        value = value.checked_mul(radix)?.checked_add(digit)?;
        saw_digit = true;
        separator = false;
    }
    (saw_digit && !separator).then_some(value)
}

fn x86_64_naked_signed_immediate(source: &str) -> Option<(u64, bool)> {
    let Some(magnitude) = source.strip_prefix('-') else {
        return Some((x86_64_naked_immediate(source)?, false));
    };
    let magnitude = x86_64_naked_immediate(magnitude)?;
    if magnitude > 1u64 << 63 {
        return None;
    }
    Some((0u64.wrapping_sub(magnitude), true))
}

fn x86_64_naked_register(register: &str) -> Option<u8> {
    Some(match register {
        "rax" => 0,
        "rcx" => 1,
        "rdx" => 2,
        "rbx" => 3,
        "rsp" => 4,
        "rbp" => 5,
        "rsi" => 6,
        "rdi" => 7,
        "r8" => 8,
        "r9" => 9,
        "r10" => 10,
        "r11" => 11,
        "r12" => 12,
        "r13" => 13,
        "r14" => 14,
        "r15" => 15,
        _ => return None,
    })
}
