use crate::{LexError, Lexer, Span, Token, TokenKind};

const MAX_EXPRESSION_DEPTH: usize = 64;
pub const MAX_CALL_ARGUMENTS: usize = 4;
const MAX_INLINE_CONST_BINDINGS: usize = 4;
const MAX_INLINE_CONST_ASSIGNMENTS: usize = 8;
const MAX_INLINE_CONST_EXPRESSION_STATEMENTS: usize = 8;
const MAX_MATCH_PATTERNS: usize = 8;
const MAX_MATCH_ALTERNATIVES: usize = 4;
const MAX_RANGE_VALIDATIONS: usize = MAX_MATCH_PATTERNS * MAX_MATCH_ALTERNATIVES;
const MAX_LOOP_BREAK_BRANCHES: usize = 4;
pub(crate) const MAX_ARRAY_ELEMENTS: usize = 16;
pub(crate) const MAX_TUPLE_ELEMENTS: usize = 4;

type InlineConstBinding<'source> = (&'source str, ExprKind<'source>, bool, Option<ScalarType>);

#[derive(Clone, Copy)]
enum MatchPattern<'source> {
    Wildcard,
    Binding(&'source str),
    Value(ExprId),
    Range {
        start: Option<ExprId>,
        end: Option<ExprId>,
        inclusive: bool,
    },
    BindingAt {
        name: &'source str,
        pattern: MatchPatternBody,
    },
}
#[derive(Clone, Copy)]
enum MatchPatternBody {
    Wildcard,
    Value(ExprId),
    Range {
        start: Option<ExprId>,
        end: Option<ExprId>,
        inclusive: bool,
    },
}

#[derive(Clone, Copy)]
enum PatternOrderValue {
    Unsigned(u128),
    Signed(i128),
    Character(u32),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ValueLoopControlTarget {
    Current,
    Enclosing,
}

impl PatternOrderValue {
    fn compare(self, other: Self) -> Option<core::cmp::Ordering> {
        use core::cmp::Ordering;

        Some(match (self, other) {
            (Self::Unsigned(left), Self::Unsigned(right)) => left.cmp(&right),
            (Self::Signed(left), Self::Signed(right)) => left.cmp(&right),
            (Self::Signed(left), Self::Unsigned(right)) => {
                if left < 0 {
                    Ordering::Less
                } else {
                    (left as u128).cmp(&right)
                }
            }
            (Self::Unsigned(left), Self::Signed(right)) => {
                if right < 0 {
                    Ordering::Greater
                } else {
                    left.cmp(&(right as u128))
                }
            }
            (Self::Character(left), Self::Character(right)) => left.cmp(&right),
            _ => return None,
        })
    }
}

#[derive(Clone, Copy)]
struct MatchArmPattern<'source> {
    alternatives: [Option<MatchPattern<'source>>; MAX_MATCH_ALTERNATIVES],
    alternative_count: usize,
    guard: Option<ExprId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RangeValidation {
    pub(crate) scrutinee: ExprId,
    pub(crate) start: Option<ExprId>,
    pub(crate) end: Option<ExprId>,
    pub(crate) inclusive: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExprId(usize);

impl ExprId {
    pub const fn index(self) -> usize {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnaryOperator {
    Negate,
    Not,
    Dereference,
    AddressOf,
    AddressOfMut,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BinaryOperator {
    LogicalOr,
    LogicalAnd,
    BitOr,
    BitXor,
    BitAnd,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    ShiftLeft,
    ShiftRight,
    Add,
    Subtract,
    Multiply,
    Divide,
    Remainder,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegerType {
    U8,
    U16,
    U32,
    U64,
    U128,
    Usize,
    I8,
    I16,
    I32,
    I64,
    I128,
    Isize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegerWidthCastMode {
    Truncate,
    SaturatingTruncate,
    Widen,
    Saturating,
    Wrapping,
    Strict,
    Unchecked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckedIntegerOptionOperation {
    ExactDivision,
    Division { remainder: bool, euclidean: bool },
    Arithmetic(BinaryOperator),
    SignedUnary { absolute: bool },
    Shift { left: bool },
    Power,
    NextPowerOfTwo,
    Logarithm { binary: bool },
    NextMultiple,
    UnsignedMixedArithmetic { subtract: bool },
    SignedMixedArithmetic { subtract: bool },
    SquareRoot,
    SignedDifference,
    Truncate(IntegerType),
    Cast(IntegerType),
    SignCast { signed: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScalarType {
    Never,
    Integer(IntegerType),
    Bool,
    Char,
    Unit,
    Array {
        element: CallArrayElement,
        count: usize,
    },
    Tuple {
        elements: [Option<CallArrayElement>; MAX_TUPLE_ELEMENTS],
        element_count: usize,
    },
    RawPointer {
        pointee: PointerPointee,
        mutable: bool,
    },
    Reference {
        target: PointerPointee,
        mutable: bool,
    },
    ArrayReference {
        element: CallArrayElement,
        count: usize,
        mutable: bool,
    },
    SliceReference {
        element: CallArrayElement,
        mutable: bool,
    },
    StrReference {
        mutable: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeCallParameter<'source> {
    pub name: &'source str,
    pub ty: ScalarType,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeCallTarget<'source, const MAX_PARAMETERS: usize> {
    pub name: &'source str,
    pub parameters: [Option<RuntimeCallParameter<'source>>; MAX_PARAMETERS],
    pub parameter_count: usize,
    pub return_type: ScalarType,
    pub return_type_name: &'source str,
    pub body_expression: &'source str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PointerPointee {
    Integer(IntegerType),
    Bool,
    Char,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallArrayElement {
    Unit,
    Integer(IntegerType),
    Bool,
    Char,
}

impl CallArrayElement {
    fn from_name(name: &str) -> Option<Self> {
        match name.trim() {
            "()" => Some(Self::Unit),
            "bool" => Some(Self::Bool),
            "char" => Some(Self::Char),
            name => IntegerType::from_name(name).map(Self::Integer),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CastType {
    Integer(IntegerType),
    RawPointer {
        pointee: PointerPointee,
        mutable: bool,
    },
}

impl ScalarType {
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        match name {
            "!" => Some(Self::Never),
            "bool" => Some(Self::Bool),
            "char" => Some(Self::Char),
            "()" => Some(Self::Unit),
            _ => {
                if let Some(integer) = IntegerType::from_name(name) {
                    return Some(Self::Integer(integer));
                }
                if let Some(body) = name
                    .trim()
                    .strip_prefix('[')
                    .and_then(|body| body.strip_suffix(']'))
                {
                    let (element, count) = body.split_once(';')?;
                    let count = count.trim().parse::<usize>().ok()?;
                    if count > MAX_ARRAY_ELEMENTS {
                        return None;
                    }
                    return Some(Self::Array {
                        element: CallArrayElement::from_name(element)?,
                        count,
                    });
                }
                if let Some(body) = name
                    .trim()
                    .strip_prefix('(')
                    .and_then(|body| body.strip_suffix(')'))
                    && body.contains(',')
                {
                    let mut elements = [None; MAX_TUPLE_ELEMENTS];
                    let mut element_count = 0usize;
                    for element in body
                        .split(',')
                        .map(str::trim)
                        .filter(|part| !part.is_empty())
                    {
                        if element_count == MAX_TUPLE_ELEMENTS {
                            return None;
                        }
                        elements[element_count] = Some(CallArrayElement::from_name(element)?);
                        element_count += 1;
                    }
                    if element_count == 0 {
                        return None;
                    }
                    return Some(Self::Tuple {
                        elements,
                        element_count,
                    });
                }
                if let Some(target) = name.trim().strip_prefix('&') {
                    let target = target.trim();
                    let (target, mutable) = target
                        .strip_prefix("mut ")
                        .map_or((target, false), |target| (target.trim(), true));
                    if let Some(body) = target
                        .strip_prefix('[')
                        .and_then(|body| body.strip_suffix(']'))
                    {
                        if let Some((element, count)) = body.split_once(';') {
                            let count = count.trim().parse::<usize>().ok()?;
                            if count > MAX_ARRAY_ELEMENTS {
                                return None;
                            }
                            return Some(Self::ArrayReference {
                                element: CallArrayElement::from_name(element)?,
                                count,
                                mutable,
                            });
                        }
                        return Some(Self::SliceReference {
                            element: CallArrayElement::from_name(body)?,
                            mutable,
                        });
                    }
                    if target == "str" {
                        return Some(Self::StrReference { mutable });
                    }
                    let target = match target {
                        "bool" => PointerPointee::Bool,
                        "char" => PointerPointee::Char,
                        name => PointerPointee::Integer(IntegerType::from_name(name)?),
                    };
                    return Some(Self::Reference { target, mutable });
                }
                let target = name.trim().strip_prefix('*')?.trim();
                let (target, mutable) = if let Some(target) = target.strip_prefix("const ") {
                    (target.trim(), false)
                } else {
                    (target.strip_prefix("mut ")?.trim(), true)
                };
                let pointee = match target {
                    "bool" => PointerPointee::Bool,
                    "char" => PointerPointee::Char,
                    name => PointerPointee::Integer(IntegerType::from_name(name)?),
                };
                Some(Self::RawPointer { pointee, mutable })
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntegerLiteral<'source> {
    pub value: u128,
    pub suffix: Option<&'source str>,
}

impl IntegerType {
    pub const fn supports_width_cast(self, target: Self, mode: IntegerWidthCastMode) -> bool {
        if matches!(
            mode,
            IntegerWidthCastMode::Saturating
                | IntegerWidthCastMode::Wrapping
                | IntegerWidthCastMode::Strict
                | IntegerWidthCastMode::Unchecked
        ) {
            return true;
        }
        if self.is_signed() != target.is_signed() {
            return false;
        }
        match mode {
            IntegerWidthCastMode::Saturating
            | IntegerWidthCastMode::Wrapping
            | IntegerWidthCastMode::Strict
            | IntegerWidthCastMode::Unchecked => unreachable!(),
            IntegerWidthCastMode::Truncate | IntegerWidthCastMode::SaturatingTruncate => match self
            {
                Self::U8 | Self::I8 => matches!(target, Self::U8 | Self::I8),
                Self::U16 | Self::I16 => {
                    matches!(target, Self::U8 | Self::I8 | Self::U16 | Self::I16)
                }
                Self::U32 | Self::I32 => matches!(
                    target,
                    Self::U8 | Self::I8 | Self::U16 | Self::I16 | Self::U32 | Self::I32
                ),
                Self::U64 | Self::I64 => {
                    !matches!(target, Self::U128 | Self::I128 | Self::Usize | Self::Isize)
                }
                Self::U128 | Self::I128 => !matches!(target, Self::Usize | Self::Isize),
                Self::Usize | Self::Isize => matches!(
                    target,
                    Self::U8 | Self::I8 | Self::U16 | Self::I16 | Self::Usize | Self::Isize
                ),
            },
            IntegerWidthCastMode::Widen => match self {
                Self::U8 | Self::I8 => true,
                Self::U16 | Self::I16 => !matches!(target, Self::U8 | Self::I8),
                Self::U32 | Self::I32 => matches!(
                    target,
                    Self::U32 | Self::I32 | Self::U64 | Self::I64 | Self::U128 | Self::I128
                ),
                Self::U64 | Self::I64 => {
                    matches!(target, Self::U64 | Self::I64 | Self::U128 | Self::I128)
                }
                Self::U128 | Self::I128 => matches!(target, Self::U128 | Self::I128),
                Self::Usize | Self::Isize => matches!(target, Self::Usize | Self::Isize),
            },
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "u8" => Self::U8,
            "u16" => Self::U16,
            "u32" => Self::U32,
            "u64" => Self::U64,
            "u128" => Self::U128,
            "usize" => Self::Usize,
            "i8" => Self::I8,
            "i16" => Self::I16,
            "i32" => Self::I32,
            "i64" => Self::I64,
            "i128" => Self::I128,
            "isize" => Self::Isize,
            _ => return None,
        })
    }

    pub const fn bits(self, pointer_bits: u8) -> Option<u8> {
        Some(match self {
            Self::U8 | Self::I8 => 8,
            Self::U16 | Self::I16 => 16,
            Self::U32 | Self::I32 => 32,
            Self::U64 | Self::I64 => 64,
            Self::U128 | Self::I128 => 128,
            Self::Usize | Self::Isize if matches!(pointer_bits, 16 | 32 | 64) => pointer_bits,
            Self::Usize | Self::Isize => return None,
        })
    }

    pub const fn is_signed(self) -> bool {
        matches!(
            self,
            Self::I8 | Self::I16 | Self::I32 | Self::I64 | Self::I128 | Self::Isize
        )
    }

    pub const fn unsigned_counterpart(self) -> Option<Self> {
        Some(match self {
            Self::I8 => Self::U8,
            Self::I16 => Self::U16,
            Self::I32 => Self::U32,
            Self::I64 => Self::U64,
            Self::I128 => Self::U128,
            Self::Isize => Self::Usize,
            _ => return None,
        })
    }

    pub const fn signed_counterpart(self) -> Option<Self> {
        Some(match self {
            Self::U8 => Self::I8,
            Self::U16 => Self::I16,
            Self::U32 => Self::I32,
            Self::U64 => Self::I64,
            Self::U128 => Self::I128,
            Self::Usize => Self::Isize,
            _ => return None,
        })
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::U8 => "u8",
            Self::U16 => "u16",
            Self::U32 => "u32",
            Self::U64 => "u64",
            Self::U128 => "u128",
            Self::Usize => "usize",
            Self::I8 => "i8",
            Self::I16 => "i16",
            Self::I32 => "i32",
            Self::I64 => "i64",
            Self::I128 => "i128",
            Self::Isize => "isize",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExprKind<'source> {
    Unit,
    DefaultValue,
    Array {
        elements: [Option<ExprId>; MAX_ARRAY_ELEMENTS],
        element_count: usize,
    },
    ArrayRepeat {
        element: ExprId,
        count: usize,
    },
    Tuple {
        elements: [Option<ExprId>; MAX_TUPLE_ELEMENTS],
        element_count: usize,
    },
    TupleField {
        base: ExprId,
        field: usize,
    },
    Index {
        base: ExprId,
        index: ExprId,
    },
    RangeIndex {
        base: ExprId,
        start: Option<ExprId>,
        end: Option<ExprId>,
        inclusive: bool,
    },
    SliceLen {
        base: ExprId,
    },
    SliceIsEmpty {
        base: ExprId,
    },
    StrAsBytes {
        base: ExprId,
    },
    CStrToBytes {
        base: ExprId,
        with_nul: bool,
    },
    StrIsCharBoundary {
        base: ExprId,
        index: ExprId,
    },
    ReferenceAsPointer {
        base: ExprId,
        mutable: bool,
    },
    RawPointerIsNull {
        base: ExprId,
    },
    RawPointerIsAligned {
        base: ExprId,
    },
    RawPointerAddress {
        base: ExprId,
    },
    RawPointerMutability {
        base: ExprId,
        mutable: bool,
    },
    RawPointerPointeeCast {
        base: ExprId,
        pointee: PointerPointee,
    },
    RawPointerAsReference {
        base: ExprId,
        mutable: bool,
    },
    RawPointerWithAddress {
        base: ExprId,
        address: ExprId,
    },
    RawPointerWithMetadata {
        base: ExprId,
        metadata: ExprId,
    },
    RawPointerWrite {
        base: ExprId,
        value: ExprId,
        returns_old: bool,
    },
    RawPointerWriteBytes {
        base: ExprId,
        value: ExprId,
        count: ExprId,
    },
    RawPointerCopy {
        source: ExprId,
        destination: ExprId,
        count: ExprId,
        overlapping: bool,
        destination_first: bool,
    },
    RawPointerSwap {
        left: ExprId,
        right: ExprId,
    },
    RawPointerOffset {
        base: ExprId,
        offset: ExprId,
        subtract: bool,
        wrapping: bool,
        signed: bool,
        bytes: bool,
    },
    RawPointerDifference {
        pointer: ExprId,
        origin: ExprId,
        bytes: bool,
        unsigned: bool,
    },
    RawPointerAlignOffset {
        base: ExprId,
        alignment: ExprId,
    },
    RawPointerMask {
        base: ExprId,
        mask: ExprId,
    },
    RawPointerIsAlignedTo {
        base: ExprId,
        alignment: ExprId,
    },
    RawPointerDrop {
        base: ExprId,
    },
    UnsignedIntegerPredicate {
        base: ExprId,
        argument: Option<ExprId>,
        power_of_two: bool,
    },
    SignedIntegerPredicate {
        base: ExprId,
        positive: bool,
    },
    AsciiPredicate {
        base: ExprId,
        predicate: AsciiPredicate,
    },
    WrappingArithmetic {
        base: ExprId,
        argument: ExprId,
        operator: BinaryOperator,
        euclidean: bool,
        euclidean_wrapping: bool,
        strict: bool,
        mixed_signedness: bool,
    },
    SaturatingArithmetic {
        base: ExprId,
        argument: ExprId,
        operator: BinaryOperator,
        mixed_signedness: bool,
    },
    IntegerRotate {
        base: ExprId,
        distance: ExprId,
        left: bool,
    },
    IntegerFunnelShift {
        base: ExprId,
        other: ExprId,
        distance: ExprId,
        left: bool,
    },
    IntegerSignCast {
        base: ExprId,
        signed: bool,
        saturating: bool,
        strict: bool,
    },
    IntegerWidthCast {
        base: ExprId,
        target: IntegerType,
        mode: IntegerWidthCastMode,
    },
    UncheckedIntegerOperation {
        base: ExprId,
        argument: Option<ExprId>,
        second_argument: Option<ExprId>,
        operator: BinaryOperator,
        unary: bool,
        disjoint: bool,
        funnel: bool,
    },
    CheckedIntegerOption {
        base: ExprId,
        argument: Option<ExprId>,
        operation: CheckedIntegerOptionOperation,
    },
    IntegerOptionUnwrapOr {
        option: ExprId,
        fallback: Option<ExprId>,
        trap: bool,
        message: bool,
        unchecked: bool,
        lazy: bool,
    },
    IntegerOptionPredicate {
        option: ExprId,
        some: bool,
        closure: Option<ExprId>,
    },
    IntegerOptionMapOr {
        option: ExprId,
        default: ExprId,
        closure: ExprId,
    },
    IntegerOptionMapOrElse {
        option: ExprId,
        default_closure: ExprId,
        map_closure: ExprId,
    },
    IntegerOptionMapOrDefault {
        option: ExprId,
        map_closure: ExprId,
    },
    IntegerOptionMap {
        option: ExprId,
        closure: ExprId,
    },
    IntegerOptionAndThen {
        option: ExprId,
        closure: ExprId,
    },
    IntegerOptionOrElse {
        option: ExprId,
        closure: ExprId,
    },
    IntegerOptionOr {
        option: ExprId,
        alternative: ExprId,
    },
    IntegerOptionXor {
        option: ExprId,
        alternative: ExprId,
    },
    IntegerOptionAnd {
        option: ExprId,
        alternative: ExprId,
    },
    IntegerOptionThenSome {
        condition: ExprId,
        value: ExprId,
    },
    IntegerOptionThen {
        condition: ExprId,
        closure: ExprId,
    },
    IntegerOptionInspect {
        option: ExprId,
        closure: ExprId,
    },
    IntegerOptionFilter {
        option: ExprId,
        closure: ExprId,
    },
    IntegerClampMagnitude {
        base: ExprId,
        limit: ExprId,
    },
    IntegerEndianFrom {
        value: ExprId,
        integer_type: IntegerType,
        little: bool,
    },
    IntegerFromBytes {
        bytes: ExprId,
        integer_type: IntegerType,
        order: IntegerByteOrder,
    },
    IntegerToBytes {
        base: ExprId,
        order: IntegerByteOrder,
    },
    IntegerAssociatedConstant {
        integer_type: IntegerType,
        constant: IntegerAssociatedConstant,
    },
    IntegerWrappingShift {
        base: ExprId,
        distance: ExprId,
        left: bool,
        unbounded: bool,
        strict: bool,
    },
    IntegerWrappingPower {
        base: ExprId,
        exponent: ExprId,
        mode: IntegerPowerMode,
    },
    IntegerBitTransform {
        base: ExprId,
        transform: IntegerBitTransform,
    },
    IntegerUnsignedAbsolute {
        base: ExprId,
    },
    IntegerPairTransform {
        base: ExprId,
        other: ExprId,
        transform: IntegerPairTransform,
    },
    IntegerClamp {
        base: ExprId,
        minimum: ExprId,
        maximum: ExprId,
    },
    IntegerBitCount {
        base: ExprId,
        count: IntegerBitCount,
    },
    IntegerLogarithm {
        base: ExprId,
        radix: Option<ExprId>,
        binary: bool,
    },
    Integer(IntegerLiteral<'source>),
    Bool(bool),
    Char(u32),
    ByteChar(u8),
    String(&'source str),
    ByteString(&'source str),
    CString(&'source str),
    Closure {
        parameter: Option<ExprId>,
        body: ExprId,
    },
    ClosureParameter {
        binding: ExprId,
        target: Option<ClosureParameterTarget>,
    },
    Identifier(&'source str),
    Call {
        callee: &'source str,
        arguments: [Option<ExprId>; MAX_CALL_ARGUMENTS],
        argument_count: usize,
    },
    InlineConst {
        operand: ExprId,
    },
    UnsafeBlock {
        operand: ExprId,
    },
    Ascribe {
        operand: ExprId,
        target: ScalarType,
    },
    Sequence {
        first: ExprId,
        then: ExprId,
    },
    Cast {
        operand: ExprId,
        target: CastType,
    },
    Unary {
        operator: UnaryOperator,
        operand: ExprId,
    },
    Binary {
        operator: BinaryOperator,
        left: ExprId,
        right: ExprId,
    },
    If {
        condition: ExprId,
        then_branch: ExprId,
        else_branch: ExprId,
    },
    Return {
        operand: ExprId,
    },
    LoopBreak {
        operand: ExprId,
    },
    LoopBreakIf {
        condition: ExprId,
        then_branch: ExprId,
        else_branch: ExprId,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClosureParameterTarget {
    Integer(IntegerType),
    IntegerReference(IntegerType),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegerAssociatedConstant {
    Minimum,
    Maximum,
    Bits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegerByteOrder {
    Big,
    Little,
    Native,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AsciiPredicate {
    Ascii,
    Alphabetic,
    Uppercase,
    Lowercase,
    Alphanumeric,
    Digit,
    HexDigit,
    Punctuation,
    Graphic,
    Whitespace,
    Control,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegerBitTransform {
    IsolateHighestOne,
    IsolateLowestOne,
    SwapBytes,
    ReverseBits,
    ToBigEndian,
    ToLittleEndian,
    WrappingNegate,
    StrictNegate,
    WrappingAbsolute,
    Absolute,
    StrictAbsolute,
    SaturatingNegate,
    SaturatingAbsolute,
    NextPowerOfTwo,
    WrappingNextPowerOfTwo,
    IntegerSquareRoot,
    Signum,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegerPairTransform {
    Minimum,
    Maximum,
    AbsoluteDifference,
    Midpoint,
    CarrylessMultiply,
    ExtractBits,
    DepositBits,
    DivideFloor,
    DivideCeiling,
    NextMultiple,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegerPowerMode {
    Checked,
    Strict,
    Wrapping,
    Saturating,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegerBitCount {
    Width,
    Ones,
    Zeros,
    LeadingZeros,
    TrailingZeros,
    LeadingOnes,
    TrailingOnes,
}

impl AsciiPredicate {
    pub(crate) const fn matches(self, value: u8) -> bool {
        match self {
            Self::Ascii => value.is_ascii(),
            Self::Alphabetic => value.is_ascii_alphabetic(),
            Self::Uppercase => value.is_ascii_uppercase(),
            Self::Lowercase => value.is_ascii_lowercase(),
            Self::Alphanumeric => value.is_ascii_alphanumeric(),
            Self::Digit => value.is_ascii_digit(),
            Self::HexDigit => value.is_ascii_hexdigit(),
            Self::Punctuation => value.is_ascii_punctuation(),
            Self::Graphic => value.is_ascii_graphic(),
            Self::Whitespace => value.is_ascii_whitespace(),
            Self::Control => value.is_ascii_control(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Expr<'source> {
    pub kind: ExprKind<'source>,
    pub span: Span,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpressionErrorKind {
    Lexical(LexError),
    ExpectedExpression,
    ExpectedColon,
    ExpectedCloseParen,
    ExpectedOpenBrace,
    ExpectedCloseBrace,
    ExpectedIdentifier,
    ExpectedEquals,
    ExpectedSemicolon,
    ExpectedInlineConstType,
    UnsupportedInlineConstType,
    ExpectedElse,
    ExpectedMatchPattern,
    ExpectedFatArrow,
    ExpectedComma,
    ExpectedWildcardPattern,
    NonExhaustiveMatch,
    TooManyMatchPatterns,
    TooManyMatchAlternatives,
    TooManyRangeValidations,
    InconsistentMatchBindings,
    TrailingToken,
    InvalidInteger,
    InvalidIntegerSuffix,
    InvalidTupleField,
    InvalidCharacter,
    InvalidRangeType,
    InvalidRangeBounds,
    ExpectedCastType,
    UnsupportedCastType,
    IntegerOverflow,
    TooManyNodes,
    TooManyCallArguments,
    TooManyArrayElements,
    TooManyTupleElements,
    TooManyInlineConstBindings,
    TooManyInlineConstAssignments,
    TooManyInlineConstExpressionStatements,
    TooManyLoopBreakBranches,
    ImmutableInlineConstAssignment,
    UnsupportedInlineConstAssignment,
    NestingLimitExceeded,
    InvalidExpressionTree,
    InvalidLoopBreakTarget,
    UnknownLoopLabel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpressionError {
    pub kind: ExpressionErrorKind,
    pub span: Span,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpressionTree<'source, const MAX_NODES: usize> {
    nodes: [Option<Expr<'source>>; MAX_NODES],
    node_count: usize,
    range_validations: [Option<RangeValidation>; MAX_RANGE_VALIDATIONS],
    range_validation_count: usize,
    root: ExprId,
}

impl<'source, const MAX_NODES: usize> ExpressionTree<'source, MAX_NODES> {
    pub fn nodes(&self) -> &[Option<Expr<'source>>] {
        &self.nodes[..self.node_count]
    }

    pub const fn root(&self) -> ExprId {
        self.root
    }

    pub(crate) fn bind_closure_parameter(
        &mut self,
        parameter: ExprId,
        target: IntegerType,
    ) -> Result<(), ExpressionErrorKind> {
        self.bind_closure_parameter_target(parameter, ClosureParameterTarget::Integer(target))
    }

    pub(crate) fn bind_closure_reference_parameter(
        &mut self,
        parameter: ExprId,
        target: IntegerType,
    ) -> Result<(), ExpressionErrorKind> {
        self.bind_closure_parameter_target(
            parameter,
            ClosureParameterTarget::IntegerReference(target),
        )
    }

    fn bind_closure_parameter_target(
        &mut self,
        parameter: ExprId,
        target: ClosureParameterTarget,
    ) -> Result<(), ExpressionErrorKind> {
        if !matches!(
            self.nodes.get(parameter.0).and_then(Option::as_ref),
            Some(Expr {
                kind: ExprKind::ClosureParameter { binding, target: bound },
                ..
            }) if *binding == parameter && bound.is_none_or(|bound| bound == target)
        ) {
            return Err(ExpressionErrorKind::InvalidExpressionTree);
        }
        for expression in self.nodes[..self.node_count].iter_mut().flatten() {
            if matches!(
                expression.kind,
                ExprKind::ClosureParameter { binding, .. } if binding == parameter
            ) {
                expression.kind = ExprKind::ClosureParameter {
                    binding: parameter,
                    target: Some(target),
                };
            }
        }
        Ok(())
    }

    pub(crate) fn replace_kind(
        &mut self,
        id: ExprId,
        kind: ExprKind<'source>,
    ) -> Result<(), ExpressionErrorKind> {
        let expression = self
            .nodes
            .get_mut(id.0)
            .and_then(Option::as_mut)
            .ok_or(ExpressionErrorKind::InvalidExpressionTree)?;
        expression.kind = kind;
        Ok(())
    }

    pub(crate) fn range_validations(&self) -> &[Option<RangeValidation>] {
        &self.range_validations[..self.range_validation_count]
    }

    pub fn expression(&self, id: ExprId) -> Option<&Expr<'source>> {
        self.nodes.get(id.index()).and_then(Option::as_ref)
    }

    pub(crate) fn is_within_unsafe_block(&self, id: ExprId) -> bool {
        let Some(span) = self.expression(id).map(|expression| expression.span) else {
            return false;
        };
        self.nodes().iter().flatten().any(|expression| {
            matches!(expression.kind, ExprKind::UnsafeBlock { .. })
                && expression.span.start <= span.start
                && span.end <= expression.span.end
        })
    }

    pub(crate) fn is_boolean_expression(&self, id: ExprId, depth: usize) -> bool {
        if depth == MAX_EXPRESSION_DEPTH {
            return false;
        }
        let Some(expression) = self.expression(id) else {
            return false;
        };
        match expression.kind {
            ExprKind::Bool(_) => true,
            ExprKind::Unit
            | ExprKind::DefaultValue
            | ExprKind::Array { .. }
            | ExprKind::ArrayRepeat { .. }
            | ExprKind::Tuple { .. }
            | ExprKind::TupleField { .. }
            | ExprKind::Index { .. }
            | ExprKind::RangeIndex { .. }
            | ExprKind::SliceLen { .. }
            | ExprKind::StrAsBytes { .. }
            | ExprKind::CStrToBytes { .. }
            | ExprKind::StrIsCharBoundary { .. }
            | ExprKind::ReferenceAsPointer { .. }
            | ExprKind::RawPointerIsNull { .. }
            | ExprKind::RawPointerIsAligned { .. }
            | ExprKind::RawPointerAddress { .. }
            | ExprKind::RawPointerMutability { .. }
            | ExprKind::RawPointerPointeeCast { .. }
            | ExprKind::RawPointerAsReference { .. }
            | ExprKind::RawPointerWithAddress { .. }
            | ExprKind::RawPointerWithMetadata { .. }
            | ExprKind::RawPointerWrite { .. }
            | ExprKind::RawPointerWriteBytes { .. }
            | ExprKind::RawPointerCopy { .. }
            | ExprKind::RawPointerSwap { .. }
            | ExprKind::RawPointerOffset { .. }
            | ExprKind::RawPointerDifference { .. }
            | ExprKind::RawPointerAlignOffset { .. }
            | ExprKind::RawPointerMask { .. }
            | ExprKind::RawPointerIsAlignedTo { .. }
            | ExprKind::RawPointerDrop { .. }
            | ExprKind::WrappingArithmetic { .. }
            | ExprKind::SaturatingArithmetic { .. }
            | ExprKind::IntegerRotate { .. }
            | ExprKind::IntegerFunnelShift { .. }
            | ExprKind::IntegerSignCast { .. }
            | ExprKind::IntegerWidthCast { .. }
            | ExprKind::UncheckedIntegerOperation { .. }
            | ExprKind::CheckedIntegerOption { .. }
            | ExprKind::IntegerOptionUnwrapOr { .. }
            | ExprKind::IntegerOptionPredicate { .. }
            | ExprKind::IntegerOptionMapOr { .. }
            | ExprKind::IntegerOptionMapOrElse { .. }
            | ExprKind::IntegerOptionMapOrDefault { .. }
            | ExprKind::IntegerOptionMap { .. }
            | ExprKind::IntegerOptionAndThen { .. }
            | ExprKind::IntegerOptionOrElse { .. }
            | ExprKind::IntegerOptionOr { .. }
            | ExprKind::IntegerOptionXor { .. }
            | ExprKind::IntegerOptionAnd { .. }
            | ExprKind::IntegerOptionThenSome { .. }
            | ExprKind::IntegerOptionThen { .. }
            | ExprKind::IntegerOptionInspect { .. }
            | ExprKind::IntegerOptionFilter { .. }
            | ExprKind::IntegerClampMagnitude { .. }
            | ExprKind::IntegerEndianFrom { .. }
            | ExprKind::IntegerFromBytes { .. }
            | ExprKind::IntegerToBytes { .. }
            | ExprKind::IntegerAssociatedConstant { .. }
            | ExprKind::IntegerWrappingShift { .. }
            | ExprKind::IntegerWrappingPower { .. }
            | ExprKind::IntegerBitTransform { .. }
            | ExprKind::IntegerUnsignedAbsolute { .. }
            | ExprKind::IntegerPairTransform { .. }
            | ExprKind::IntegerClamp { .. }
            | ExprKind::IntegerBitCount { .. }
            | ExprKind::IntegerLogarithm { .. }
            | ExprKind::Integer(_)
            | ExprKind::Char(_)
            | ExprKind::ByteChar(_)
            | ExprKind::String(_)
            | ExprKind::ByteString(_)
            | ExprKind::CString(_)
            | ExprKind::Closure { .. }
            | ExprKind::ClosureParameter { .. }
            | ExprKind::Identifier(_)
            | ExprKind::Call { .. }
            | ExprKind::Cast { .. } => false,
            ExprKind::SliceIsEmpty { .. }
            | ExprKind::UnsignedIntegerPredicate { .. }
            | ExprKind::SignedIntegerPredicate { .. }
            | ExprKind::AsciiPredicate { .. } => true,
            ExprKind::Ascribe {
                operand,
                target: ScalarType::Bool,
            } => self.is_boolean_expression(operand, depth + 1),
            ExprKind::Ascribe {
                target:
                    ScalarType::Never
                    | ScalarType::Integer(_)
                    | ScalarType::Char
                    | ScalarType::Unit
                    | ScalarType::Array { .. }
                    | ScalarType::Tuple { .. }
                    | ScalarType::RawPointer { .. }
                    | ScalarType::Reference { .. }
                    | ScalarType::ArrayReference { .. }
                    | ScalarType::SliceReference { .. }
                    | ScalarType::StrReference { .. },
                ..
            } => false,
            ExprKind::Sequence { then, .. } => self.is_boolean_expression(then, depth + 1),
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
                self.is_boolean_expression(then_branch, depth + 1)
                    && self.is_boolean_expression(else_branch, depth + 1)
            }
            ExprKind::Return { operand } | ExprKind::LoopBreak { operand } => {
                self.is_boolean_expression(operand, depth + 1)
            }
            ExprKind::InlineConst { operand } | ExprKind::UnsafeBlock { operand } => {
                self.is_boolean_expression(operand, depth + 1)
            }
            ExprKind::Unary {
                operator: UnaryOperator::Not,
                operand,
            } => self.is_boolean_expression(operand, depth + 1),
            ExprKind::Unary {
                operator:
                    UnaryOperator::Negate
                    | UnaryOperator::Dereference
                    | UnaryOperator::AddressOf
                    | UnaryOperator::AddressOfMut,
                ..
            } => false,
            ExprKind::Binary { operator, .. } => matches!(
                operator,
                BinaryOperator::LogicalOr
                    | BinaryOperator::LogicalAnd
                    | BinaryOperator::Equal
                    | BinaryOperator::NotEqual
                    | BinaryOperator::Less
                    | BinaryOperator::LessEqual
                    | BinaryOperator::Greater
                    | BinaryOperator::GreaterEqual
            ),
        }
    }

    pub fn evaluate<R: ConstantResolver>(&self, resolver: &R) -> Result<u128, ConstEvalError> {
        self.validate_ranges(resolver, 64)?;
        self.evaluate_node(self.root, resolver, 0)
    }

    pub(crate) fn evaluate_at<R: ConstantResolver>(
        &self,
        id: ExprId,
        resolver: &R,
    ) -> Result<u128, ConstEvalError> {
        self.evaluate_node(id, resolver, 0)
    }

    pub(crate) fn validate_ranges<R: ConstantResolver>(
        &self,
        resolver: &R,
        pointer_bits: u8,
    ) -> Result<(), ConstEvalError> {
        for validation in self.range_validations[..self.range_validation_count]
            .iter()
            .flatten()
        {
            let (Some(start_id), Some(end_id)) = (validation.start, validation.end) else {
                continue;
            };
            let start = self.resolved_pattern_order_value(start_id, resolver, pointer_bits)?;
            let end = self.resolved_pattern_order_value(end_id, resolver, pointer_bits)?;
            let (Some(start), Some(end)) = (start, end) else {
                continue;
            };
            let Some(order) = start.compare(end) else {
                return Err(ConstEvalError::InvalidRangeType);
            };
            let invalid = if validation.inclusive {
                order == core::cmp::Ordering::Greater
            } else {
                order != core::cmp::Ordering::Less
            };
            if invalid {
                return Err(ConstEvalError::InvalidRangeBounds);
            }
        }
        Ok(())
    }

    fn resolved_pattern_order_value<R: ConstantResolver>(
        &self,
        id: ExprId,
        resolver: &R,
        pointer_bits: u8,
    ) -> Result<Option<PatternOrderValue>, ConstEvalError> {
        let expression = self
            .expression(id)
            .ok_or(ConstEvalError::InvalidExpressionTree)?;
        match expression.kind {
            ExprKind::Integer(literal) => {
                if literal
                    .suffix
                    .and_then(IntegerType::from_name)
                    .is_some_and(IntegerType::is_signed)
                {
                    Ok(i128::try_from(literal.value)
                        .ok()
                        .map(PatternOrderValue::Signed))
                } else {
                    Ok(Some(PatternOrderValue::Unsigned(literal.value)))
                }
            }
            ExprKind::Unary {
                operator: UnaryOperator::Negate,
                operand,
            } => {
                let Some(ExprKind::Integer(literal)) =
                    self.expression(operand).map(|operand| operand.kind)
                else {
                    return Ok(None);
                };
                let minimum_magnitude = (i128::MAX as u128) + 1;
                let value = if literal.value == minimum_magnitude {
                    i128::MIN
                } else {
                    -i128::try_from(literal.value).map_err(|_| ConstEvalError::Overflow)?
                };
                Ok(Some(PatternOrderValue::Signed(value)))
            }
            ExprKind::Char(value) => Ok(Some(PatternOrderValue::Character(value))),
            ExprKind::Bool(_) => Err(ConstEvalError::InvalidRangeType),
            ExprKind::Identifier(name) if resolver.resolves_bool(name) => {
                Err(ConstEvalError::InvalidRangeType)
            }
            ExprKind::Identifier(name) => {
                let Some(ty) = resolver.resolve_type(name) else {
                    return Ok(None);
                };
                let Some(value) = resolver.resolve(name) else {
                    return Ok(None);
                };
                if ty.is_signed() {
                    let bits = ty.bits(pointer_bits).ok_or(ConstEvalError::InvalidCast)?;
                    let signed = if bits == 128 {
                        value as i128
                    } else {
                        let mask = (1u128 << bits) - 1;
                        let value = value & mask;
                        if value & (1u128 << (bits - 1)) == 0 {
                            value as i128
                        } else {
                            (value | !mask) as i128
                        }
                    };
                    Ok(Some(PatternOrderValue::Signed(signed)))
                } else {
                    Ok(Some(PatternOrderValue::Unsigned(value)))
                }
            }
            _ => Ok(None),
        }
    }

    fn evaluate_node<R: ConstantResolver>(
        &self,
        id: ExprId,
        resolver: &R,
        depth: usize,
    ) -> Result<u128, ConstEvalError> {
        if depth == MAX_EXPRESSION_DEPTH {
            return Err(ConstEvalError::NestingLimitExceeded);
        }
        let expression = self
            .expression(id)
            .ok_or(ConstEvalError::InvalidExpressionTree)?;
        match expression.kind {
            ExprKind::Unit | ExprKind::DefaultValue => Ok(0),
            ExprKind::Array { .. } | ExprKind::ArrayRepeat { .. } | ExprKind::Tuple { .. } => {
                Err(ConstEvalError::InvalidExpressionTree)
            }
            ExprKind::TupleField { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::Index { base, index } => {
                let index = self.evaluate_node(index, resolver, depth + 1)?;
                let index =
                    usize::try_from(index).map_err(|_| ConstEvalError::ArrayIndexOutOfBounds)?;
                if self
                    .array_length(base, depth + 1)
                    .is_some_and(|length| index >= length)
                {
                    return Err(ConstEvalError::ArrayIndexOutOfBounds);
                }
                self.evaluate_array_element(base, index, resolver, depth + 1)
            }
            ExprKind::RangeIndex { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::SliceLen { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::SliceIsEmpty { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::StrAsBytes { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::CStrToBytes { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::StrIsCharBoundary { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::ReferenceAsPointer { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::RawPointerIsNull { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::RawPointerIsAligned { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::RawPointerAddress { .. }
            | ExprKind::RawPointerMutability { .. }
            | ExprKind::RawPointerPointeeCast { .. }
            | ExprKind::RawPointerAsReference { .. }
            | ExprKind::RawPointerWithAddress { .. }
            | ExprKind::RawPointerWithMetadata { .. }
            | ExprKind::RawPointerWrite { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::RawPointerWriteBytes { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::RawPointerCopy { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::RawPointerSwap { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::RawPointerOffset { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::RawPointerDifference { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::RawPointerAlignOffset { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::RawPointerMask { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::RawPointerIsAlignedTo { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::RawPointerDrop { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::UnsignedIntegerPredicate {
                base,
                argument,
                power_of_two,
            } => {
                let value = self.evaluate_node(base, resolver, depth + 1)?;
                let result = if power_of_two {
                    value != 0 && value & (value - 1) == 0
                } else {
                    let divisor = self.evaluate_node(
                        argument.ok_or(ConstEvalError::InvalidExpressionTree)?,
                        resolver,
                        depth + 1,
                    )?;
                    if divisor == 0 {
                        value == 0
                    } else {
                        value % divisor == 0
                    }
                };
                Ok(u128::from(result))
            }
            ExprKind::SignedIntegerPredicate { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::AsciiPredicate { base, predicate } => {
                let value = self.evaluate_node(base, resolver, depth + 1)?;
                let value = u8::try_from(value).map_err(|_| ConstEvalError::Overflow)?;
                Ok(u128::from(predicate.matches(value)))
            }
            ExprKind::WrappingArithmetic { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::SaturatingArithmetic { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::IntegerRotate { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::IntegerFunnelShift { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::IntegerSignCast { .. }
            | ExprKind::IntegerWidthCast { .. }
            | ExprKind::UncheckedIntegerOperation { .. }
            | ExprKind::CheckedIntegerOption { .. }
            | ExprKind::IntegerOptionUnwrapOr { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::IntegerOptionPredicate { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::IntegerOptionMapOr { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::IntegerOptionMapOrElse { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::IntegerOptionMapOrDefault { .. } => {
                Err(ConstEvalError::InvalidExpressionTree)
            }
            ExprKind::IntegerOptionMap { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::IntegerOptionAndThen { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::IntegerOptionOrElse { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::IntegerOptionOr { .. }
            | ExprKind::IntegerOptionXor { .. }
            | ExprKind::IntegerOptionAnd { .. }
            | ExprKind::IntegerOptionThenSome { .. }
            | ExprKind::IntegerOptionThen { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::IntegerOptionInspect { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::IntegerOptionFilter { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::IntegerClampMagnitude { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::IntegerEndianFrom { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::IntegerFromBytes { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::IntegerToBytes { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::IntegerAssociatedConstant { .. } => {
                Err(ConstEvalError::InvalidExpressionTree)
            }
            ExprKind::IntegerWrappingShift { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::IntegerWrappingPower { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::IntegerBitTransform { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::IntegerUnsignedAbsolute { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::IntegerPairTransform { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::IntegerClamp { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::IntegerBitCount { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::IntegerLogarithm { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::Integer(literal) => Ok(literal.value),
            ExprKind::Bool(value) => Ok(u128::from(value)),
            ExprKind::Char(value) => Ok(u128::from(value)),
            ExprKind::ByteChar(value) => Ok(u128::from(value)),
            ExprKind::String(_) | ExprKind::ByteString(_) | ExprKind::CString(_) => {
                Err(ConstEvalError::InvalidExpressionTree)
            }
            ExprKind::Closure { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::ClosureParameter { .. } => Err(ConstEvalError::InvalidExpressionTree),
            ExprKind::Identifier(name) => resolver
                .resolve(name)
                .ok_or(ConstEvalError::UnknownIdentifier),
            ExprKind::Call {
                callee,
                arguments,
                argument_count,
            } => {
                let mut values = [0u128; MAX_CALL_ARGUMENTS];
                for (index, argument) in arguments[..argument_count].iter().enumerate() {
                    values[index] = self.evaluate_node(
                        argument.ok_or(ConstEvalError::InvalidExpressionTree)?,
                        resolver,
                        depth + 1,
                    )?;
                }
                resolver
                    .resolve_call(callee, &values[..argument_count])
                    .ok_or(ConstEvalError::UnsupportedCall)
            }
            ExprKind::Cast { operand, target } => {
                let value = self.evaluate_node(operand, resolver, depth + 1)?;
                match target {
                    CastType::Integer(target) => cast_integer(value, target, 64),
                    CastType::RawPointer { .. } => Err(ConstEvalError::InvalidCast),
                }
            }
            ExprKind::Ascribe { operand, target } => {
                let value = self.evaluate_node(operand, resolver, depth + 1)?;
                match target {
                    ScalarType::Integer(target) => ascribe_integer(value, target, 64),
                    ScalarType::Bool if self.is_boolean_expression(operand, depth + 1) => {
                        Ok(u128::from(value != 0))
                    }
                    ScalarType::Bool => Err(ConstEvalError::InvalidCast),
                    ScalarType::Char
                        if self.expression(operand).is_some_and(|expression| {
                            matches!(expression.kind, ExprKind::Char(_))
                        }) =>
                    {
                        Ok(value)
                    }
                    ScalarType::Char => Err(ConstEvalError::InvalidCast),
                    ScalarType::Unit
                        if self.expression(operand).is_some_and(|expression| {
                            matches!(expression.kind, ExprKind::Unit)
                        }) =>
                    {
                        Ok(0)
                    }
                    ScalarType::Never | ScalarType::Unit => Err(ConstEvalError::InvalidCast),
                    ScalarType::RawPointer { .. } => Err(ConstEvalError::InvalidCast),
                    ScalarType::Array { .. } => Err(ConstEvalError::InvalidCast),
                    ScalarType::Tuple { .. } => Err(ConstEvalError::InvalidCast),
                    ScalarType::Reference { .. } => Err(ConstEvalError::InvalidCast),
                    ScalarType::ArrayReference { .. } => Err(ConstEvalError::InvalidCast),
                    ScalarType::SliceReference { .. } | ScalarType::StrReference { .. } => {
                        Err(ConstEvalError::InvalidCast)
                    }
                }
            }
            ExprKind::Unary { operator, operand } => {
                let value = self.evaluate_node(operand, resolver, depth + 1)?;
                match operator {
                    UnaryOperator::Negate
                        if let Some(target) = self.expression(operand).and_then(|expression| {
                            match expression.kind {
                                ExprKind::Integer(literal) => literal
                                    .suffix
                                    .and_then(IntegerType::from_name)
                                    .filter(|target| target.is_signed()),
                                _ => None,
                            }
                        }) =>
                    {
                        negate_signed_magnitude(value, target, 64)
                    }
                    UnaryOperator::Negate => {
                        0u128.checked_sub(value).ok_or(ConstEvalError::Overflow)
                    }
                    UnaryOperator::Not if self.is_boolean_expression(operand, depth + 1) => {
                        Ok(u128::from(value == 0))
                    }
                    UnaryOperator::Not => Ok(!value),
                    UnaryOperator::Dereference
                    | UnaryOperator::AddressOf
                    | UnaryOperator::AddressOfMut => Err(ConstEvalError::InvalidExpressionTree),
                }
            }
            ExprKind::Binary {
                operator,
                left,
                right,
            } => {
                let left = self.evaluate_node(left, resolver, depth + 1)?;
                if operator == BinaryOperator::LogicalAnd && left == 0 {
                    return Ok(0);
                }
                if operator == BinaryOperator::LogicalOr && left != 0 {
                    return Ok(1);
                }
                let right = self.evaluate_node(right, resolver, depth + 1)?;
                evaluate_binary(operator, left, right)
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
                if self.evaluate_node(condition, resolver, depth + 1)? != 0 {
                    self.evaluate_node(then_branch, resolver, depth + 1)
                } else {
                    self.evaluate_node(else_branch, resolver, depth + 1)
                }
            }
            ExprKind::Return { operand } | ExprKind::LoopBreak { operand } => {
                self.evaluate_node(operand, resolver, depth + 1)
            }
            ExprKind::InlineConst { operand } | ExprKind::UnsafeBlock { operand } => {
                self.evaluate_node(operand, resolver, depth + 1)
            }
            ExprKind::Sequence { first, then } => {
                self.evaluate_node(first, resolver, depth + 1)?;
                self.evaluate_node(then, resolver, depth + 1)
            }
        }
    }

    fn evaluate_array_element<R: ConstantResolver>(
        &self,
        id: ExprId,
        index: usize,
        resolver: &R,
        depth: usize,
    ) -> Result<u128, ConstEvalError> {
        if depth == MAX_EXPRESSION_DEPTH {
            return Err(ConstEvalError::NestingLimitExceeded);
        }
        let expression = self
            .expression(id)
            .ok_or(ConstEvalError::InvalidExpressionTree)?;
        match expression.kind {
            ExprKind::DefaultValue => Ok(0),
            ExprKind::Array {
                elements,
                element_count,
            } => {
                if index >= element_count {
                    return Err(ConstEvalError::ArrayIndexOutOfBounds);
                }
                let mut selected = None;
                for (element_index, element) in elements[..element_count].iter().enumerate() {
                    let element = element.ok_or(ConstEvalError::InvalidExpressionTree)?;
                    let value = self.evaluate_node(element, resolver, depth + 1)?;
                    if element_index == index {
                        selected = Some(value);
                    }
                }
                selected.ok_or(ConstEvalError::ArrayIndexOutOfBounds)
            }
            ExprKind::ArrayRepeat { element, count } => {
                if index >= count {
                    return Err(ConstEvalError::ArrayIndexOutOfBounds);
                }
                self.evaluate_node(element, resolver, depth + 1)
            }
            ExprKind::IntegerToBytes { base, order } => {
                let integer_type = self
                    .resolved_integer_type(base, resolver, depth + 1)
                    .ok_or(ConstEvalError::InvalidExpressionTree)?;
                let bits = integer_type.bits(64).ok_or(ConstEvalError::InvalidCast)?;
                let count = usize::from(bits / 8);
                if index >= count {
                    return Err(ConstEvalError::ArrayIndexOutOfBounds);
                }
                let value = self.evaluate_node(base, resolver, depth + 1)?;
                let byte_index = if order == IntegerByteOrder::Big {
                    count - index - 1
                } else {
                    index
                };
                Ok(value >> (byte_index * 8) & 0xff)
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
                let selected = if self.evaluate_node(condition, resolver, depth + 1)? != 0 {
                    then_branch
                } else {
                    else_branch
                };
                self.evaluate_array_element(selected, index, resolver, depth + 1)
            }
            ExprKind::InlineConst { operand }
            | ExprKind::UnsafeBlock { operand }
            | ExprKind::LoopBreak { operand }
            | ExprKind::Return { operand } => {
                self.evaluate_array_element(operand, index, resolver, depth + 1)
            }
            _ => Err(ConstEvalError::InvalidExpressionTree),
        }
    }

    fn array_length(&self, id: ExprId, depth: usize) -> Option<usize> {
        if depth == MAX_EXPRESSION_DEPTH {
            return None;
        }
        let expression = self.expression(id)?;
        match expression.kind {
            ExprKind::Array { element_count, .. } => Some(element_count),
            ExprKind::ArrayRepeat { count, .. } => Some(count),
            ExprKind::IntegerToBytes { base, .. } => self
                .expression(base)
                .and_then(|expression| match expression.kind {
                    ExprKind::Integer(literal) => literal.suffix.and_then(IntegerType::from_name),
                    ExprKind::Cast {
                        target: CastType::Integer(integer_type),
                        ..
                    }
                    | ExprKind::Ascribe {
                        target: ScalarType::Integer(integer_type),
                        ..
                    } => Some(integer_type),
                    _ => None,
                })
                .and_then(|integer_type| integer_type.bits(64))
                .map(|bits| usize::from(bits / 8)),
            ExprKind::If {
                then_branch,
                else_branch,
                ..
            }
            | ExprKind::LoopBreakIf {
                then_branch,
                else_branch,
                ..
            } => match (
                self.array_length(then_branch, depth + 1),
                self.array_length(else_branch, depth + 1),
            ) {
                (Some(left), Some(right)) if left == right => Some(left),
                (Some(length), None) | (None, Some(length)) => Some(length),
                _ => None,
            },
            ExprKind::InlineConst { operand }
            | ExprKind::UnsafeBlock { operand }
            | ExprKind::LoopBreak { operand }
            | ExprKind::Return { operand } => self.array_length(operand, depth + 1),
            ExprKind::Sequence { then, .. } => self.array_length(then, depth + 1),
            _ => None,
        }
    }

    pub(crate) fn evaluate_byte_array<R: ConstantResolver>(
        &self,
        id: ExprId,
        count: usize,
        resolver: &R,
    ) -> Result<u128, ConstEvalError> {
        if self.array_length(id, 0) != Some(count) {
            return Err(ConstEvalError::InvalidExpressionTree);
        }
        let mut value = 0u128;
        let mut index = 0usize;
        while index < count {
            let byte = self.evaluate_array_element(id, index, resolver, 0)?;
            let byte = u8::try_from(byte).map_err(|_| ConstEvalError::Overflow)?;
            value |= u128::from(byte) << (index * 8);
            index += 1;
        }
        Ok(value)
    }

    fn resolved_integer_type<R: ConstantResolver>(
        &self,
        id: ExprId,
        resolver: &R,
        depth: usize,
    ) -> Option<IntegerType> {
        if depth == MAX_EXPRESSION_DEPTH {
            return None;
        }
        match self.expression(id)?.kind {
            ExprKind::Integer(literal) => literal.suffix.and_then(IntegerType::from_name),
            ExprKind::Identifier(name) => resolver.resolve_type(name),
            ExprKind::Cast {
                target: CastType::Integer(integer_type),
                ..
            }
            | ExprKind::Ascribe {
                target: ScalarType::Integer(integer_type),
                ..
            }
            | ExprKind::IntegerAssociatedConstant { integer_type, .. }
            | ExprKind::IntegerEndianFrom { integer_type, .. }
            | ExprKind::IntegerFromBytes { integer_type, .. } => Some(integer_type),
            ExprKind::Unary { operand, .. }
            | ExprKind::InlineConst { operand }
            | ExprKind::UnsafeBlock { operand }
            | ExprKind::Return { operand }
            | ExprKind::LoopBreak { operand } => {
                self.resolved_integer_type(operand, resolver, depth + 1)
            }
            _ => None,
        }
    }
}

pub trait ConstantResolver {
    fn resolve(&self, name: &str) -> Option<u128>;

    fn resolve_type(&self, _: &str) -> Option<IntegerType> {
        None
    }

    fn resolves_bool(&self, _: &str) -> bool {
        false
    }

    fn resolve_call(&self, _: &str, _: &[u128]) -> Option<u128> {
        None
    }

    fn resolve_call_type(&self, _: &str, _: usize) -> Option<IntegerType> {
        None
    }

    fn resolve_call_parameter_type(
        &self,
        _: &str,
        _: usize,
        _: usize,
    ) -> Option<IntegerType> {
        None
    }

    fn call_resolves_bool(&self, _: &str, _: usize) -> bool {
        false
    }

    fn resolve_runtime_call<const MAX_PARAMETERS: usize>(
        &self,
        _: &str,
        _: usize,
    ) -> Option<RuntimeCallTarget<'_, MAX_PARAMETERS>> {
        None
    }
}

pub struct NoConstants;

impl ConstantResolver for NoConstants {
    fn resolve(&self, _name: &str) -> Option<u128> {
        None
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConstEvalError {
    UnknownIdentifier,
    DivisionByZero,
    Overflow,
    InvalidShift,
    InvalidCast,
    InvalidExpressionTree,
    NestingLimitExceeded,
    UnsupportedCall,
    ArrayIndexOutOfBounds,
    InvalidRangeType,
    InvalidRangeBounds,
}

pub(crate) fn cast_integer(
    value: u128,
    target: IntegerType,
    pointer_bits: u8,
) -> Result<u128, ConstEvalError> {
    let bits = target
        .bits(pointer_bits)
        .ok_or(ConstEvalError::InvalidCast)?;
    let mask = if bits == 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    };
    let truncated = value & mask;
    if target.is_signed() && bits != 128 && truncated & (1u128 << (bits - 1)) != 0 {
        Ok(truncated | !mask)
    } else {
        Ok(truncated)
    }
}

pub(crate) fn ascribe_integer(
    value: u128,
    target: IntegerType,
    pointer_bits: u8,
) -> Result<u128, ConstEvalError> {
    let normalized = cast_integer(value, target, pointer_bits)?;
    if normalized == value {
        Ok(value)
    } else {
        Err(ConstEvalError::Overflow)
    }
}

pub(crate) fn negate_signed_magnitude(
    magnitude: u128,
    target: IntegerType,
    pointer_bits: u8,
) -> Result<u128, ConstEvalError> {
    if !target.is_signed() {
        return Err(ConstEvalError::InvalidCast);
    }
    let bits = target
        .bits(pointer_bits)
        .ok_or(ConstEvalError::InvalidCast)?;
    let limit = 1u128 << (bits - 1);
    if magnitude > limit {
        return Err(ConstEvalError::Overflow);
    }
    cast_integer(0u128.wrapping_sub(magnitude), target, pointer_bits)
}

pub(crate) fn evaluate_binary(
    operator: BinaryOperator,
    left: u128,
    right: u128,
) -> Result<u128, ConstEvalError> {
    match operator {
        BinaryOperator::LogicalOr => Ok(u128::from(left != 0 || right != 0)),
        BinaryOperator::LogicalAnd => Ok(u128::from(left != 0 && right != 0)),
        BinaryOperator::BitOr => Ok(left | right),
        BinaryOperator::BitXor => Ok(left ^ right),
        BinaryOperator::BitAnd => Ok(left & right),
        BinaryOperator::Equal => Ok(u128::from(left == right)),
        BinaryOperator::NotEqual => Ok(u128::from(left != right)),
        BinaryOperator::Less => Ok(u128::from(left < right)),
        BinaryOperator::LessEqual => Ok(u128::from(left <= right)),
        BinaryOperator::Greater => Ok(u128::from(left > right)),
        BinaryOperator::GreaterEqual => Ok(u128::from(left >= right)),
        BinaryOperator::ShiftLeft => left
            .checked_shl(u32::try_from(right).map_err(|_| ConstEvalError::InvalidShift)?)
            .ok_or(ConstEvalError::InvalidShift),
        BinaryOperator::ShiftRight => left
            .checked_shr(u32::try_from(right).map_err(|_| ConstEvalError::InvalidShift)?)
            .ok_or(ConstEvalError::InvalidShift),
        BinaryOperator::Add => left.checked_add(right).ok_or(ConstEvalError::Overflow),
        BinaryOperator::Subtract => left.checked_sub(right).ok_or(ConstEvalError::Overflow),
        BinaryOperator::Multiply => left.checked_mul(right).ok_or(ConstEvalError::Overflow),
        BinaryOperator::Divide => left
            .checked_div(right)
            .ok_or(ConstEvalError::DivisionByZero),
        BinaryOperator::Remainder => left
            .checked_rem(right)
            .ok_or(ConstEvalError::DivisionByZero),
    }
}

#[derive(Clone)]
pub struct ExpressionParser<'source, const MAX_NODES: usize> {
    lexer: Lexer<'source>,
    lookahead: Option<Token<'source>>,
    nodes: [Option<Expr<'source>>; MAX_NODES],
    node_count: usize,
    range_validations: [Option<RangeValidation>; MAX_RANGE_VALIDATIONS],
    range_validation_count: usize,
    source_len: usize,
}

impl<'source, const MAX_NODES: usize> ExpressionParser<'source, MAX_NODES> {
    pub const fn new(source: &'source str) -> Self {
        Self {
            lexer: Lexer::new(source),
            lookahead: None,
            nodes: [None; MAX_NODES],
            node_count: 0,
            range_validations: [None; MAX_RANGE_VALIDATIONS],
            range_validation_count: 0,
            source_len: source.len(),
        }
    }

    fn lexical(error: LexError) -> ExpressionError {
        ExpressionError {
            kind: ExpressionErrorKind::Lexical(error),
            span: error.span,
        }
    }

    fn peek(&mut self) -> Result<Option<Token<'source>>, ExpressionError> {
        if self.lookahead.is_none() {
            self.lookahead = self.lexer.next_token().map_err(Self::lexical)?;
        }
        Ok(self.lookahead)
    }

    fn take(&mut self) -> Result<Option<Token<'source>>, ExpressionError> {
        if let Some(token) = self.lookahead.take() {
            Ok(Some(token))
        } else {
            self.lexer.next_token().map_err(Self::lexical)
        }
    }

    fn error(&self, kind: ExpressionErrorKind, token: Option<Token<'source>>) -> ExpressionError {
        ExpressionError {
            kind,
            span: token.map_or(
                Span {
                    start: self.source_len,
                    end: self.source_len,
                },
                |value| value.span,
            ),
        }
    }

    fn push(&mut self, expression: Expr<'source>) -> Result<ExprId, ExpressionError> {
        if self.node_count == MAX_NODES {
            return Err(ExpressionError {
                kind: ExpressionErrorKind::TooManyNodes,
                span: expression.span,
            });
        }
        let id = ExprId(self.node_count);
        self.nodes[self.node_count] = Some(expression);
        self.node_count += 1;
        Ok(id)
    }

    fn record_range_validation(
        &mut self,
        scrutinee: ExprId,
        start: Option<ExprId>,
        end: Option<ExprId>,
        inclusive: bool,
    ) -> Result<(), ExpressionError> {
        if self.range_validation_count == MAX_RANGE_VALIDATIONS {
            return Err(ExpressionError {
                kind: ExpressionErrorKind::TooManyRangeValidations,
                span: Span {
                    start: start
                        .or(end)
                        .and_then(|bound| self.node_span(bound).ok())
                        .map_or(0, |span| span.start),
                    end: end
                        .or(start)
                        .and_then(|bound| self.node_span(bound).ok())
                        .map_or(self.source_len, |span| span.end),
                },
            });
        }
        self.range_validations[self.range_validation_count] = Some(RangeValidation {
            scrutinee,
            start,
            end,
            inclusive,
        });
        self.range_validation_count += 1;
        Ok(())
    }

    fn node_span(&self, id: ExprId) -> Result<Span, ExpressionError> {
        self.nodes
            .get(id.index())
            .and_then(Option::as_ref)
            .map(|expression| expression.span)
            .ok_or(ExpressionError {
                kind: ExpressionErrorKind::InvalidExpressionTree,
                span: Span {
                    start: self.source_len,
                    end: self.source_len,
                },
            })
    }

    fn pattern_order_value(&self, id: ExprId) -> Option<PatternOrderValue> {
        let expression = self.nodes.get(id.index()).and_then(Option::as_ref)?;
        match expression.kind {
            ExprKind::Integer(literal) => {
                if literal
                    .suffix
                    .and_then(IntegerType::from_name)
                    .is_some_and(IntegerType::is_signed)
                {
                    i128::try_from(literal.value)
                        .ok()
                        .map(PatternOrderValue::Signed)
                } else {
                    Some(PatternOrderValue::Unsigned(literal.value))
                }
            }
            ExprKind::Unary {
                operator: UnaryOperator::Negate,
                operand,
            } => {
                let operand = self.nodes.get(operand.index()).and_then(Option::as_ref)?;
                let ExprKind::Integer(literal) = operand.kind else {
                    return None;
                };
                if literal
                    .suffix
                    .and_then(IntegerType::from_name)
                    .is_some_and(|ty| !ty.is_signed())
                {
                    return None;
                }
                let minimum_magnitude = (i128::MAX as u128) + 1;
                let value = if literal.value == minimum_magnitude {
                    i128::MIN
                } else {
                    -i128::try_from(literal.value).ok()?
                };
                Some(PatternOrderValue::Signed(value))
            }
            ExprKind::Char(value) => Some(PatternOrderValue::Character(value)),
            _ => None,
        }
    }

    fn node_is_unit(&self, id: ExprId, depth: usize) -> bool {
        if depth == MAX_EXPRESSION_DEPTH {
            return false;
        }
        let Some(expression) = self.nodes.get(id.index()).and_then(Option::as_ref) else {
            return false;
        };
        match expression.kind {
            ExprKind::Unit => true,
            ExprKind::DefaultValue => false,
            ExprKind::InlineConst { operand }
            | ExprKind::UnsafeBlock { operand }
            | ExprKind::Return { operand }
            | ExprKind::LoopBreak { operand } => self.node_is_unit(operand, depth + 1),
            ExprKind::Sequence { then, .. } => self.node_is_unit(then, depth + 1),
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
                self.node_is_unit(then_branch, depth + 1)
                    && self.node_is_unit(else_branch, depth + 1)
            }
            _ => false,
        }
    }

    fn atom(&mut self, depth: usize) -> Result<ExprId, ExpressionError> {
        if depth == MAX_EXPRESSION_DEPTH {
            return Err(self.error(ExpressionErrorKind::NestingLimitExceeded, self.lookahead));
        }
        let token = self.take()?;
        match token {
            Some(token) if token.text == "break" => {
                if self
                    .peek()?
                    .is_some_and(|next| next.kind == TokenKind::CloseBrace)
                {
                    return self.push(Expr {
                        kind: ExprKind::Identifier(token.text),
                        span: token.span,
                    });
                }
                let operand = self.nested_loop_break_operand(depth + 1)?;
                let operand_span = self.node_span(operand)?;
                self.push(Expr {
                    kind: ExprKind::LoopBreak { operand },
                    span: Span {
                        start: token.span.start,
                        end: operand_span.end,
                    },
                })
            }
            Some(token) if token.kind == TokenKind::Integer => {
                let literal = decode_integer(token)?;
                self.push(Expr {
                    kind: ExprKind::Integer(literal),
                    span: token.span,
                })
            }
            Some(token) if token.kind == TokenKind::Character => self.push(Expr {
                kind: ExprKind::Char(decode_character(token)?),
                span: token.span,
            }),
            Some(token) if token.kind == TokenKind::ByteCharacter => self.push(Expr {
                kind: ExprKind::ByteChar(decode_byte_character(token)?),
                span: token.span,
            }),
            Some(token) if token.kind == TokenKind::String => self.push(Expr {
                kind: ExprKind::String(token.text),
                span: token.span,
            }),
            Some(token) if token.kind == TokenKind::ByteString => self.push(Expr {
                kind: ExprKind::ByteString(token.text),
                span: token.span,
            }),
            Some(token) if token.kind == TokenKind::CString => self.push(Expr {
                kind: ExprKind::CString(token.text),
                span: token.span,
            }),
            Some(token) if token.kind == TokenKind::Operator && token.text == "||" => {
                let body = self.expression(0, depth + 1)?;
                self.push(Expr {
                    kind: ExprKind::Closure {
                        parameter: None,
                        body,
                    },
                    span: Span {
                        start: token.span.start,
                        end: self.node_span(body)?.end,
                    },
                })
            }
            Some(token) if token.kind == TokenKind::Operator && token.text == "|" => {
                let parameter = self.take()?;
                let Some(parameter) = parameter.filter(|value| value.kind == TokenKind::Identifier)
                else {
                    return Err(self.error(ExpressionErrorKind::ExpectedExpression, parameter));
                };
                let close = self.take()?;
                if !close
                    .is_some_and(|value| value.kind == TokenKind::Operator && value.text == "|")
                {
                    return Err(self.error(ExpressionErrorKind::ExpectedExpression, close));
                }
                let body = self.expression(0, depth + 1)?;
                let binding = ExprId(self.node_count);
                let placeholder = self.push(Expr {
                    kind: ExprKind::ClosureParameter {
                        binding,
                        target: None,
                    },
                    span: parameter.span,
                })?;
                self.substitute_identifier(
                    body,
                    parameter.text,
                    ExprKind::ClosureParameter {
                        binding,
                        target: None,
                    },
                    depth + 1,
                )?;
                self.push(Expr {
                    kind: ExprKind::Closure {
                        parameter: Some(placeholder),
                        body,
                    },
                    span: Span {
                        start: token.span.start,
                        end: self.node_span(body)?.end,
                    },
                })
            }
            Some(token) if token.text == "if" => self.if_expression(token, depth + 1),
            Some(token) if token.text == "match" => self.match_expression(token, depth + 1),
            Some(token) if token.text == "loop" => {
                self.loop_break_expression(token, None, depth + 1)
            }
            Some(label) if label.kind == TokenKind::Lifetime => {
                let colon = self.take()?;
                if !colon.is_some_and(|token| token.kind == TokenKind::Colon) {
                    return Err(self.error(ExpressionErrorKind::ExpectedColon, colon));
                }
                let loop_token = self.take()?;
                let Some(loop_token) = loop_token.filter(|token| token.text == "loop") else {
                    return Err(self.error(ExpressionErrorKind::ExpectedExpression, loop_token));
                };
                self.loop_break_expression(loop_token, Some(label), depth + 1)
            }
            Some(token) if token.text == "const" => self.const_block_expression(token, depth + 1),
            Some(token) if token.text == "unsafe" => self.unsafe_block_expression(token, depth + 1),
            Some(token) if token.kind == TokenKind::Identifier => {
                if let Some(integer_type) = IntegerType::from_name(token.text)
                    && self
                        .peek()?
                        .is_some_and(|next| next.kind == TokenKind::PathSeparator)
                {
                    self.take()?;
                    let member = self.take()?;
                    let Some(member) = member else {
                        return Err(self.error(ExpressionErrorKind::ExpectedExpression, member));
                    };
                    let constant = match member.text {
                        "MIN" => Some(IntegerAssociatedConstant::Minimum),
                        "MAX" => Some(IntegerAssociatedConstant::Maximum),
                        "BITS" => Some(IntegerAssociatedConstant::Bits),
                        _ => None,
                    };
                    if let Some(constant) = constant {
                        return self.push(Expr {
                            kind: ExprKind::IntegerAssociatedConstant {
                                integer_type,
                                constant,
                            },
                            span: Span {
                                start: token.span.start,
                                end: member.span.end,
                            },
                        });
                    }
                    let legacy_constant = match member.text {
                        "min_value" => Some(IntegerAssociatedConstant::Minimum),
                        "max_value" => Some(IntegerAssociatedConstant::Maximum),
                        _ => None,
                    };
                    if let Some(constant) = legacy_constant {
                        let open = self.take()?;
                        if !open.is_some_and(|open| open.kind == TokenKind::OpenParen) {
                            return Err(self.error(ExpressionErrorKind::ExpectedExpression, open));
                        }
                        let close = self.take()?;
                        let Some(close) = close.filter(|close| close.kind == TokenKind::CloseParen)
                        else {
                            return Err(self.error(ExpressionErrorKind::ExpectedCloseParen, close));
                        };
                        return self.push(Expr {
                            kind: ExprKind::IntegerAssociatedConstant {
                                integer_type,
                                constant,
                            },
                            span: Span {
                                start: token.span.start,
                                end: close.span.end,
                            },
                        });
                    }
                    if !matches!(
                        member.text,
                        "from_be" | "from_le" | "from_be_bytes" | "from_le_bytes" | "from_ne_bytes"
                    ) {
                        return Err(
                            self.error(ExpressionErrorKind::ExpectedExpression, Some(member))
                        );
                    }
                    let open = self.take()?;
                    if !open.is_some_and(|open| open.kind == TokenKind::OpenParen) {
                        return Err(self.error(ExpressionErrorKind::ExpectedExpression, open));
                    }
                    let value = self.expression(0, depth + 1)?;
                    let close = self.take()?;
                    let Some(close) = close.filter(|close| close.kind == TokenKind::CloseParen)
                    else {
                        return Err(self.error(ExpressionErrorKind::ExpectedCloseParen, close));
                    };
                    let kind = match member.text {
                        "from_be" | "from_le" => ExprKind::IntegerEndianFrom {
                            value,
                            integer_type,
                            little: member.text == "from_le",
                        },
                        "from_be_bytes" => ExprKind::IntegerFromBytes {
                            bytes: value,
                            integer_type,
                            order: IntegerByteOrder::Big,
                        },
                        "from_le_bytes" => ExprKind::IntegerFromBytes {
                            bytes: value,
                            integer_type,
                            order: IntegerByteOrder::Little,
                        },
                        "from_ne_bytes" => ExprKind::IntegerFromBytes {
                            bytes: value,
                            integer_type,
                            order: IntegerByteOrder::Native,
                        },
                        _ => unreachable!(),
                    };
                    return self.push(Expr {
                        kind,
                        span: Span {
                            start: token.span.start,
                            end: close.span.end,
                        },
                    });
                }
                if token.text == "Default"
                    && self
                        .peek()?
                        .is_some_and(|next| next.kind == TokenKind::PathSeparator)
                {
                    self.take()?;
                    let method = self.take()?;
                    if !method.is_some_and(|method| method.text == "default") {
                        return Err(self.error(ExpressionErrorKind::ExpectedExpression, method));
                    }
                    let open = self.take()?;
                    if !open.is_some_and(|open| open.kind == TokenKind::OpenParen) {
                        return Err(self.error(ExpressionErrorKind::ExpectedExpression, open));
                    }
                    let close = self.take()?;
                    let Some(close) = close.filter(|close| close.kind == TokenKind::CloseParen)
                    else {
                        return Err(self.error(ExpressionErrorKind::ExpectedCloseParen, close));
                    };
                    return self.push(Expr {
                        kind: ExprKind::DefaultValue,
                        span: Span {
                            start: token.span.start,
                            end: close.span.end,
                        },
                    });
                }
                if matches!(token.text, "true" | "false") {
                    return self.push(Expr {
                        kind: ExprKind::Bool(token.text == "true"),
                        span: token.span,
                    });
                }
                if token.text == "_" {
                    return Err(self.error(ExpressionErrorKind::ExpectedExpression, Some(token)));
                }
                if !self
                    .peek()?
                    .is_some_and(|next| next.kind == TokenKind::OpenParen)
                {
                    return self.push(Expr {
                        kind: ExprKind::Identifier(token.text),
                        span: token.span,
                    });
                }
                self.take()?;
                let mut arguments = [None; MAX_CALL_ARGUMENTS];
                let mut argument_count = 0usize;
                if !self
                    .peek()?
                    .is_some_and(|next| next.kind == TokenKind::CloseParen)
                {
                    loop {
                        if argument_count == MAX_CALL_ARGUMENTS {
                            let token = self.peek()?;
                            return Err(
                                self.error(ExpressionErrorKind::TooManyCallArguments, token)
                            );
                        }
                        arguments[argument_count] = Some(self.expression(0, depth + 1)?);
                        argument_count += 1;
                        if !self
                            .peek()?
                            .is_some_and(|next| next.kind == TokenKind::Comma)
                        {
                            break;
                        }
                        self.take()?;
                        if self
                            .peek()?
                            .is_some_and(|next| next.kind == TokenKind::CloseParen)
                        {
                            break;
                        }
                    }
                }
                let close = self.take()?;
                let Some(close) = close.filter(|close| close.kind == TokenKind::CloseParen) else {
                    return Err(self.error(ExpressionErrorKind::ExpectedCloseParen, close));
                };
                self.push(Expr {
                    kind: ExprKind::Call {
                        callee: token.text,
                        arguments,
                        argument_count,
                    },
                    span: Span {
                        start: token.span.start,
                        end: close.span.end,
                    },
                })
            }
            Some(open) if open.kind == TokenKind::OpenBracket => {
                let mut elements = [None; MAX_ARRAY_ELEMENTS];
                let mut element_count = 0usize;
                if !self
                    .peek()?
                    .is_some_and(|token| token.kind == TokenKind::CloseBracket)
                {
                    let first = self.expression(0, depth + 1)?;
                    if self
                        .peek()?
                        .is_some_and(|token| token.kind == TokenKind::Semicolon)
                    {
                        self.take()?;
                        let count = self.take()?;
                        let Some(count) = count.filter(|token| token.kind == TokenKind::Integer)
                        else {
                            return Err(self.error(ExpressionErrorKind::ExpectedExpression, count));
                        };
                        let literal = decode_integer(count)?;
                        if literal.suffix.is_some_and(|suffix| suffix != "usize") {
                            return Err(
                                self.error(ExpressionErrorKind::InvalidIntegerSuffix, Some(count))
                            );
                        }
                        let repeat = usize::try_from(literal.value).map_err(|_| {
                            self.error(ExpressionErrorKind::TooManyArrayElements, Some(count))
                        })?;
                        if repeat > MAX_ARRAY_ELEMENTS {
                            return Err(
                                self.error(ExpressionErrorKind::TooManyArrayElements, Some(count))
                            );
                        }
                        let close = self.take()?;
                        let Some(close) =
                            close.filter(|token| token.kind == TokenKind::CloseBracket)
                        else {
                            return Err(self.error(ExpressionErrorKind::ExpectedExpression, close));
                        };
                        return self.push(Expr {
                            kind: ExprKind::ArrayRepeat {
                                element: first,
                                count: repeat,
                            },
                            span: Span {
                                start: open.span.start,
                                end: close.span.end,
                            },
                        });
                    } else {
                        elements[0] = Some(first);
                        element_count = 1;
                        loop {
                            if !self
                                .peek()?
                                .is_some_and(|token| token.kind == TokenKind::Comma)
                            {
                                break;
                            }
                            self.take()?;
                            if self
                                .peek()?
                                .is_some_and(|token| token.kind == TokenKind::CloseBracket)
                            {
                                break;
                            }
                            if element_count == MAX_ARRAY_ELEMENTS {
                                let token = self.peek()?;
                                return Err(
                                    self.error(ExpressionErrorKind::TooManyArrayElements, token)
                                );
                            }
                            elements[element_count] = Some(self.expression(0, depth + 1)?);
                            element_count += 1;
                        }
                    }
                }
                let close = self.take()?;
                let Some(close) = close.filter(|token| token.kind == TokenKind::CloseBracket)
                else {
                    return Err(self.error(ExpressionErrorKind::ExpectedExpression, close));
                };
                self.push(Expr {
                    kind: ExprKind::Array {
                        elements,
                        element_count,
                    },
                    span: Span {
                        start: open.span.start,
                        end: close.span.end,
                    },
                })
            }
            Some(token) if token.kind == TokenKind::OpenParen => {
                if self
                    .peek()?
                    .is_some_and(|value| value.kind == TokenKind::CloseParen)
                {
                    let close = self.take()?.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedCloseParen, self.lookahead)
                    })?;
                    return self.push(Expr {
                        kind: ExprKind::Unit,
                        span: Span {
                            start: token.span.start,
                            end: close.span.end,
                        },
                    });
                }
                let first = self.expression(0, depth + 1)?;
                if self
                    .peek()?
                    .is_some_and(|value| value.kind == TokenKind::Comma)
                {
                    let mut elements = [None; MAX_TUPLE_ELEMENTS];
                    elements[0] = Some(first);
                    let mut element_count = 1usize;
                    while self
                        .peek()?
                        .is_some_and(|value| value.kind == TokenKind::Comma)
                    {
                        self.take()?;
                        if self
                            .peek()?
                            .is_some_and(|value| value.kind == TokenKind::CloseParen)
                        {
                            break;
                        }
                        if element_count == MAX_TUPLE_ELEMENTS {
                            return Err(self
                                .error(ExpressionErrorKind::TooManyTupleElements, self.lookahead));
                        }
                        elements[element_count] = Some(self.expression(0, depth + 1)?);
                        element_count += 1;
                    }
                    let close = self.take()?;
                    let Some(close) = close.filter(|value| value.kind == TokenKind::CloseParen)
                    else {
                        return Err(self.error(ExpressionErrorKind::ExpectedCloseParen, close));
                    };
                    return self.push(Expr {
                        kind: ExprKind::Tuple {
                            elements,
                            element_count,
                        },
                        span: Span {
                            start: token.span.start,
                            end: close.span.end,
                        },
                    });
                }
                let close = self.take()?;
                if !close.is_some_and(|value| value.kind == TokenKind::CloseParen) {
                    return Err(self.error(ExpressionErrorKind::ExpectedCloseParen, close));
                }
                Ok(first)
            }
            Some(token) if token.kind == TokenKind::OpenBrace => {
                self.block_expression(token, depth + 1)
            }
            _ => Err(self.error(ExpressionErrorKind::ExpectedExpression, token)),
        }
    }

    fn block_expression(
        &mut self,
        _open: Token<'source>,
        depth: usize,
    ) -> Result<ExprId, ExpressionError> {
        let (inner, _) = self.scalar_branch_block(depth + 1)?;
        Ok(inner)
    }

    fn unsafe_block_expression(
        &mut self,
        unsafe_token: Token<'source>,
        depth: usize,
    ) -> Result<ExprId, ExpressionError> {
        let open = self.take()?;
        let Some(_open) = open.filter(|token| token.kind == TokenKind::OpenBrace) else {
            return Err(self.error(ExpressionErrorKind::ExpectedOpenBrace, open));
        };
        let (operand, end) = self.scalar_branch_block(depth + 1)?;
        self.push(Expr {
            kind: ExprKind::UnsafeBlock { operand },
            span: Span {
                start: unsafe_token.span.start,
                end,
            },
        })
    }

    fn const_block_expression(
        &mut self,
        const_token: Token<'source>,
        depth: usize,
    ) -> Result<ExprId, ExpressionError> {
        let open = self.take()?;
        let Some(open) = open.filter(|token| token.kind == TokenKind::OpenBrace) else {
            return Err(self.error(ExpressionErrorKind::ExpectedOpenBrace, open));
        };
        let mut bindings: [Option<InlineConstBinding<'source>>; MAX_INLINE_CONST_BINDINGS] =
            [None; MAX_INLINE_CONST_BINDINGS];
        let mut binding_count = 0usize;
        while self.peek()?.is_some_and(|token| token.text == "let") {
            self.inline_const_binding(&mut bindings, &mut binding_count, depth + 1)?;
        }
        if binding_count == 0
            && self
                .peek()?
                .is_some_and(|token| token.kind == TokenKind::CloseBrace)
        {
            let inner = self.block_expression(open, depth + 1)?;
            return self.push(Expr {
                kind: ExprKind::InlineConst { operand: inner },
                span: Span {
                    start: const_token.span.start,
                    end: self.node_span(inner)?.end,
                },
            });
        }
        let mut assignment_count = 0usize;
        let mut statements = [None; MAX_INLINE_CONST_EXPRESSION_STATEMENTS];
        let mut statement_count = 0usize;
        let tail = loop {
            if let Some(close) = self
                .peek()?
                .filter(|token| token.kind == TokenKind::CloseBrace)
            {
                break self.push(Expr {
                    kind: ExprKind::Unit,
                    span: Span {
                        start: close.span.start,
                        end: close.span.start,
                    },
                })?;
            }
            if self.peek()?.is_some_and(|token| token.text == "let") {
                self.inline_const_binding(&mut bindings, &mut binding_count, depth + 1)?;
                continue;
            }
            if self.inline_const_assignment(
                &mut bindings,
                binding_count,
                &mut assignment_count,
                depth + 1,
            )? {
                continue;
            }
            let expression = self.expression(0, depth + 1)?;
            for (name, replacement, _, _) in bindings[..binding_count].iter().flatten().rev() {
                self.substitute_identifier(expression, name, *replacement, depth + 1)?;
            }
            if self
                .peek()?
                .is_some_and(|token| token.kind == TokenKind::Semicolon)
            {
                let semicolon = self.take()?;
                if statement_count == MAX_INLINE_CONST_EXPRESSION_STATEMENTS {
                    return Err(self.error(
                        ExpressionErrorKind::TooManyInlineConstExpressionStatements,
                        semicolon,
                    ));
                }
                statements[statement_count] = Some(expression);
                statement_count += 1;
            } else {
                break expression;
            }
        };
        let inner = {
            let mut inner = tail;
            let close = self.take()?;
            if !close.is_some_and(|token| token.kind == TokenKind::CloseBrace) {
                return Err(self.error(ExpressionErrorKind::ExpectedCloseBrace, close));
            }
            for first in statements[..statement_count].iter().flatten().rev() {
                let first_span = self.node_span(*first)?;
                let then_span = self.node_span(inner)?;
                inner = self.push(Expr {
                    kind: ExprKind::Sequence {
                        first: *first,
                        then: inner,
                    },
                    span: Span {
                        start: first_span.start,
                        end: then_span.end,
                    },
                })?;
            }
            inner
        };
        let inner_span = self.node_span(inner)?;
        self.push(Expr {
            kind: ExprKind::InlineConst { operand: inner },
            span: Span {
                start: const_token.span.start,
                end: inner_span.end,
            },
        })
    }

    fn inline_const_binding(
        &mut self,
        bindings: &mut [Option<InlineConstBinding<'source>>; MAX_INLINE_CONST_BINDINGS],
        binding_count: &mut usize,
        depth: usize,
    ) -> Result<(), ExpressionError> {
        let let_token = self.take()?;
        if *binding_count == MAX_INLINE_CONST_BINDINGS {
            return Err(self.error(ExpressionErrorKind::TooManyInlineConstBindings, let_token));
        }
        let mutable = if self.peek()?.is_some_and(|token| token.text == "mut") {
            self.take()?;
            true
        } else {
            false
        };
        let name = self.take()?;
        let Some(name) = name.filter(|token| token.kind == TokenKind::Identifier) else {
            return Err(self.error(ExpressionErrorKind::ExpectedIdentifier, name));
        };
        let annotation = if self
            .peek()?
            .is_some_and(|token| token.kind == TokenKind::Colon)
        {
            self.take()?;
            let ty = self.take()?;
            let Some(ty) = ty.filter(|token| token.kind == TokenKind::Identifier) else {
                return Err(self.error(ExpressionErrorKind::ExpectedInlineConstType, ty));
            };
            Some(ScalarType::from_name(ty.text).ok_or(ExpressionError {
                kind: ExpressionErrorKind::UnsupportedInlineConstType,
                span: ty.span,
            })?)
        } else {
            None
        };
        let equals = self.take()?;
        if !equals.is_some_and(|token| token.kind == TokenKind::Operator && token.text == "=") {
            return Err(self.error(ExpressionErrorKind::ExpectedEquals, equals));
        }
        let initializer = self.expression(0, depth + 1)?;
        let semicolon = self.take()?;
        if !semicolon.is_some_and(|token| token.kind == TokenKind::Semicolon) {
            return Err(self.error(ExpressionErrorKind::ExpectedSemicolon, semicolon));
        }
        for (binding_name, replacement, _, _) in bindings[..*binding_count].iter().flatten().rev() {
            self.substitute_identifier(initializer, binding_name, *replacement, depth + 1)?;
        }
        let mut replacement = self
            .nodes
            .get(initializer.index())
            .and_then(Option::as_ref)
            .map(|expression| expression.kind)
            .ok_or(ExpressionError {
                kind: ExpressionErrorKind::InvalidExpressionTree,
                span: name.span,
            })?;
        if let Some(target) = annotation {
            let operand = self.push(Expr {
                kind: replacement,
                span: self.node_span(initializer)?,
            })?;
            let ascribed = self.push(Expr {
                kind: ExprKind::Ascribe { operand, target },
                span: Span {
                    start: name.span.start,
                    end: self.node_span(initializer)?.end,
                },
            })?;
            replacement = self.nodes[ascribed.index()]
                .as_ref()
                .ok_or(ExpressionError {
                    kind: ExpressionErrorKind::InvalidExpressionTree,
                    span: name.span,
                })?
                .kind;
        }
        bindings[*binding_count] = Some((name.text, replacement, mutable, annotation));
        *binding_count += 1;
        Ok(())
    }

    fn inline_const_assignment(
        &mut self,
        bindings: &mut [Option<InlineConstBinding<'source>>; MAX_INLINE_CONST_BINDINGS],
        binding_count: usize,
        assignment_count: &mut usize,
        depth: usize,
    ) -> Result<bool, ExpressionError> {
        let saved_lexer = self.lexer.clone();
        let saved_lookahead = self.lookahead;
        let Some(name) = self
            .take()?
            .filter(|token| token.kind == TokenKind::Identifier)
        else {
            self.lexer = saved_lexer;
            self.lookahead = saved_lookahead;
            return Ok(false);
        };
        let Some(binding_index) = bindings[..binding_count]
            .iter()
            .rposition(|binding| binding.is_some_and(|binding| binding.0 == name.text))
        else {
            self.lexer = saved_lexer;
            self.lookahead = saved_lookahead;
            return Ok(false);
        };
        let operator = self.take()?;
        let Some(operator) = operator.filter(|token| {
            token.kind == TokenKind::Operator
                && matches!(
                    token.text,
                    "=" | "+=" | "-=" | "*=" | "/=" | "%=" | "&=" | "|=" | "^=" | "<<=" | ">>="
                )
        }) else {
            self.lexer = saved_lexer;
            self.lookahead = saved_lookahead;
            return Ok(false);
        };
        if *assignment_count == MAX_INLINE_CONST_ASSIGNMENTS {
            return Err(ExpressionError {
                kind: ExpressionErrorKind::TooManyInlineConstAssignments,
                span: operator.span,
            });
        }
        let (_, previous, mutable, annotation) =
            bindings[binding_index].ok_or(ExpressionError {
                kind: ExpressionErrorKind::InvalidExpressionTree,
                span: name.span,
            })?;
        if !mutable {
            return Err(ExpressionError {
                kind: ExpressionErrorKind::ImmutableInlineConstAssignment,
                span: name.span,
            });
        }
        let value = self.expression(0, depth + 1)?;
        let semicolon = self.take()?;
        if !semicolon.is_some_and(|token| token.kind == TokenKind::Semicolon) {
            return Err(self.error(ExpressionErrorKind::ExpectedSemicolon, semicolon));
        }
        for (binding_name, replacement, _, _) in bindings[..binding_count].iter().flatten().rev() {
            self.substitute_identifier(value, binding_name, *replacement, depth + 1)?;
        }
        let value_kind = self
            .nodes
            .get(value.index())
            .and_then(Option::as_ref)
            .map(|expression| expression.kind)
            .ok_or(ExpressionError {
                kind: ExpressionErrorKind::InvalidExpressionTree,
                span: name.span,
            })?;
        let mut replacement = if operator.text == "=" {
            value_kind
        } else {
            let binary_operator = match operator.text {
                "+=" => BinaryOperator::Add,
                "-=" => BinaryOperator::Subtract,
                "*=" => BinaryOperator::Multiply,
                "/=" => BinaryOperator::Divide,
                "%=" => BinaryOperator::Remainder,
                "&=" => BinaryOperator::BitAnd,
                "|=" => BinaryOperator::BitOr,
                "^=" => BinaryOperator::BitXor,
                "<<=" => BinaryOperator::ShiftLeft,
                ">>=" => BinaryOperator::ShiftRight,
                _ => {
                    return Err(ExpressionError {
                        kind: ExpressionErrorKind::UnsupportedInlineConstAssignment,
                        span: operator.span,
                    });
                }
            };
            let previous = self.push(Expr {
                kind: previous,
                span: name.span,
            })?;
            let value_span = self.node_span(value)?;
            let updated = self.push(Expr {
                kind: ExprKind::Binary {
                    operator: binary_operator,
                    left: previous,
                    right: value,
                },
                span: Span {
                    start: name.span.start,
                    end: value_span.end,
                },
            })?;
            self.nodes[updated.index()]
                .as_ref()
                .map(|expression| expression.kind)
                .ok_or(ExpressionError {
                    kind: ExpressionErrorKind::InvalidExpressionTree,
                    span: name.span,
                })?
        };
        if let Some(target) = annotation {
            let operand = self.push(Expr {
                kind: replacement,
                span: self.node_span(value)?,
            })?;
            let ascribed = self.push(Expr {
                kind: ExprKind::Ascribe { operand, target },
                span: Span {
                    start: name.span.start,
                    end: self.node_span(value)?.end,
                },
            })?;
            replacement = self.nodes[ascribed.index()]
                .as_ref()
                .ok_or(ExpressionError {
                    kind: ExpressionErrorKind::InvalidExpressionTree,
                    span: name.span,
                })?
                .kind;
        }
        bindings[binding_index] = Some((name.text, replacement, mutable, annotation));
        *assignment_count += 1;
        Ok(true)
    }

    fn substitute_identifier(
        &mut self,
        id: ExprId,
        name: &str,
        replacement: ExprKind<'source>,
        depth: usize,
    ) -> Result<(), ExpressionError> {
        if depth == MAX_EXPRESSION_DEPTH {
            return Err(ExpressionError {
                kind: ExpressionErrorKind::NestingLimitExceeded,
                span: self.node_span(id)?,
            });
        }
        let expression = self
            .nodes
            .get(id.index())
            .and_then(Option::as_ref)
            .copied()
            .ok_or(ExpressionError {
                kind: ExpressionErrorKind::InvalidExpressionTree,
                span: Span {
                    start: self.source_len,
                    end: self.source_len,
                },
            })?;
        match expression.kind {
            ExprKind::Identifier(identifier) if identifier == name => {
                self.nodes[id.index()] = Some(Expr {
                    kind: replacement,
                    span: expression.span,
                });
            }
            ExprKind::Call {
                arguments,
                argument_count,
                ..
            } => {
                for argument in arguments[..argument_count].iter().flatten() {
                    self.substitute_identifier(*argument, name, replacement, depth + 1)?;
                }
            }
            ExprKind::Array {
                elements,
                element_count,
            } => {
                for element in elements[..element_count].iter().flatten() {
                    self.substitute_identifier(*element, name, replacement, depth + 1)?;
                }
            }
            ExprKind::ArrayRepeat { element, .. } => {
                self.substitute_identifier(element, name, replacement, depth + 1)?;
            }
            ExprKind::Tuple {
                elements,
                element_count,
            } => {
                for element in elements[..element_count].iter().flatten() {
                    self.substitute_identifier(*element, name, replacement, depth + 1)?;
                }
            }
            ExprKind::TupleField { base, .. } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
            }
            ExprKind::Index { base, index } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
                self.substitute_identifier(index, name, replacement, depth + 1)?;
            }
            ExprKind::RangeIndex {
                base, start, end, ..
            } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
                if let Some(start) = start {
                    self.substitute_identifier(start, name, replacement, depth + 1)?;
                }
                if let Some(end) = end {
                    self.substitute_identifier(end, name, replacement, depth + 1)?;
                }
            }
            ExprKind::SliceLen { base }
            | ExprKind::SliceIsEmpty { base }
            | ExprKind::StrAsBytes { base }
            | ExprKind::CStrToBytes { base, .. }
            | ExprKind::ReferenceAsPointer { base, .. } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
            }
            ExprKind::RawPointerIsNull { base } | ExprKind::RawPointerIsAligned { base } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
            }
            ExprKind::RawPointerAddress { base }
            | ExprKind::RawPointerMutability { base, .. }
            | ExprKind::RawPointerPointeeCast { base, .. }
            | ExprKind::RawPointerAsReference { base, .. } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
            }
            ExprKind::RawPointerWithAddress { base, address } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
                self.substitute_identifier(address, name, replacement, depth + 1)?;
            }
            ExprKind::RawPointerWithMetadata { base, metadata } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
                self.substitute_identifier(metadata, name, replacement, depth + 1)?;
            }
            ExprKind::RawPointerWrite { base, value, .. } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
                self.substitute_identifier(value, name, replacement, depth + 1)?;
            }
            ExprKind::RawPointerWriteBytes { base, value, count } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
                self.substitute_identifier(value, name, replacement, depth + 1)?;
                self.substitute_identifier(count, name, replacement, depth + 1)?;
            }
            ExprKind::RawPointerCopy {
                source,
                destination,
                count,
                ..
            } => {
                self.substitute_identifier(source, name, replacement, depth + 1)?;
                self.substitute_identifier(destination, name, replacement, depth + 1)?;
                self.substitute_identifier(count, name, replacement, depth + 1)?;
            }
            ExprKind::RawPointerSwap { left, right } => {
                self.substitute_identifier(left, name, replacement, depth + 1)?;
                self.substitute_identifier(right, name, replacement, depth + 1)?;
            }
            ExprKind::RawPointerOffset { base, offset, .. } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
                self.substitute_identifier(offset, name, replacement, depth + 1)?;
            }
            ExprKind::RawPointerDifference {
                pointer, origin, ..
            } => {
                self.substitute_identifier(pointer, name, replacement, depth + 1)?;
                self.substitute_identifier(origin, name, replacement, depth + 1)?;
            }
            ExprKind::RawPointerAlignOffset { base, alignment } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
                self.substitute_identifier(alignment, name, replacement, depth + 1)?;
            }
            ExprKind::RawPointerMask { base, mask } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
                self.substitute_identifier(mask, name, replacement, depth + 1)?;
            }
            ExprKind::RawPointerIsAlignedTo { base, alignment } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
                self.substitute_identifier(alignment, name, replacement, depth + 1)?;
            }
            ExprKind::RawPointerDrop { base } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
            }
            ExprKind::UnsignedIntegerPredicate { base, argument, .. } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
                if let Some(argument) = argument {
                    self.substitute_identifier(argument, name, replacement, depth + 1)?;
                }
            }
            ExprKind::SignedIntegerPredicate { base, .. } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
            }
            ExprKind::AsciiPredicate { base, .. } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
            }
            ExprKind::WrappingArithmetic { base, argument, .. } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
                self.substitute_identifier(argument, name, replacement, depth + 1)?;
            }
            ExprKind::UncheckedIntegerOperation {
                base,
                argument,
                second_argument,
                ..
            } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
                if let Some(argument) = argument {
                    self.substitute_identifier(argument, name, replacement, depth + 1)?;
                }
                if let Some(second_argument) = second_argument {
                    self.substitute_identifier(second_argument, name, replacement, depth + 1)?;
                }
            }
            ExprKind::CheckedIntegerOption { base, argument, .. } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
                if let Some(argument) = argument {
                    self.substitute_identifier(argument, name, replacement, depth + 1)?;
                }
            }
            ExprKind::IntegerOptionUnwrapOr {
                option, fallback, ..
            } => {
                self.substitute_identifier(option, name, replacement, depth + 1)?;
                if let Some(fallback) = fallback {
                    self.substitute_identifier(fallback, name, replacement, depth + 1)?;
                }
            }
            ExprKind::IntegerOptionPredicate {
                option, closure, ..
            } => {
                self.substitute_identifier(option, name, replacement, depth + 1)?;
                if let Some(closure) = closure {
                    self.substitute_identifier(closure, name, replacement, depth + 1)?;
                }
            }
            ExprKind::IntegerOptionMapOr {
                option,
                default,
                closure,
            } => {
                self.substitute_identifier(option, name, replacement, depth + 1)?;
                self.substitute_identifier(default, name, replacement, depth + 1)?;
                self.substitute_identifier(closure, name, replacement, depth + 1)?;
            }
            ExprKind::IntegerOptionMapOrElse {
                option,
                default_closure,
                map_closure,
            } => {
                self.substitute_identifier(option, name, replacement, depth + 1)?;
                self.substitute_identifier(default_closure, name, replacement, depth + 1)?;
                self.substitute_identifier(map_closure, name, replacement, depth + 1)?;
            }
            ExprKind::IntegerOptionMapOrDefault {
                option,
                map_closure,
            } => {
                self.substitute_identifier(option, name, replacement, depth + 1)?;
                self.substitute_identifier(map_closure, name, replacement, depth + 1)?;
            }
            ExprKind::IntegerOptionMap { option, closure } => {
                self.substitute_identifier(option, name, replacement, depth + 1)?;
                self.substitute_identifier(closure, name, replacement, depth + 1)?;
            }
            ExprKind::IntegerOptionAndThen { option, closure } => {
                self.substitute_identifier(option, name, replacement, depth + 1)?;
                self.substitute_identifier(closure, name, replacement, depth + 1)?;
            }
            ExprKind::IntegerOptionOrElse { option, closure } => {
                self.substitute_identifier(option, name, replacement, depth + 1)?;
                self.substitute_identifier(closure, name, replacement, depth + 1)?;
            }
            ExprKind::IntegerOptionOr {
                option,
                alternative,
            } => {
                self.substitute_identifier(option, name, replacement, depth + 1)?;
                self.substitute_identifier(alternative, name, replacement, depth + 1)?;
            }
            ExprKind::IntegerOptionXor {
                option,
                alternative,
            } => {
                self.substitute_identifier(option, name, replacement, depth + 1)?;
                self.substitute_identifier(alternative, name, replacement, depth + 1)?;
            }
            ExprKind::IntegerOptionAnd {
                option,
                alternative,
            } => {
                self.substitute_identifier(option, name, replacement, depth + 1)?;
                self.substitute_identifier(alternative, name, replacement, depth + 1)?;
            }
            ExprKind::IntegerOptionThenSome { condition, value } => {
                self.substitute_identifier(condition, name, replacement, depth + 1)?;
                self.substitute_identifier(value, name, replacement, depth + 1)?;
            }
            ExprKind::IntegerOptionThen { condition, closure } => {
                self.substitute_identifier(condition, name, replacement, depth + 1)?;
                self.substitute_identifier(closure, name, replacement, depth + 1)?;
            }
            ExprKind::IntegerOptionInspect { option, closure } => {
                self.substitute_identifier(option, name, replacement, depth + 1)?;
                self.substitute_identifier(closure, name, replacement, depth + 1)?;
            }
            ExprKind::IntegerOptionFilter { option, closure } => {
                self.substitute_identifier(option, name, replacement, depth + 1)?;
                self.substitute_identifier(closure, name, replacement, depth + 1)?;
            }
            ExprKind::Closure { body, .. } => {
                self.substitute_identifier(body, name, replacement, depth + 1)?;
            }
            ExprKind::SaturatingArithmetic { base, argument, .. } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
                self.substitute_identifier(argument, name, replacement, depth + 1)?;
            }
            ExprKind::IntegerRotate { base, distance, .. } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
                self.substitute_identifier(distance, name, replacement, depth + 1)?;
            }
            ExprKind::IntegerFunnelShift {
                base,
                other,
                distance,
                ..
            } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
                self.substitute_identifier(other, name, replacement, depth + 1)?;
                self.substitute_identifier(distance, name, replacement, depth + 1)?;
            }
            ExprKind::IntegerSignCast { base, .. } | ExprKind::IntegerWidthCast { base, .. } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
            }
            ExprKind::IntegerClampMagnitude { base, limit } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
                self.substitute_identifier(limit, name, replacement, depth + 1)?;
            }
            ExprKind::IntegerEndianFrom { value, .. } => {
                self.substitute_identifier(value, name, replacement, depth + 1)?;
            }
            ExprKind::IntegerFromBytes { bytes, .. } => {
                self.substitute_identifier(bytes, name, replacement, depth + 1)?;
            }
            ExprKind::IntegerToBytes { base, .. } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
            }
            ExprKind::IntegerAssociatedConstant { .. } => {}
            ExprKind::IntegerWrappingShift { base, distance, .. } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
                self.substitute_identifier(distance, name, replacement, depth + 1)?;
            }
            ExprKind::IntegerWrappingPower { base, exponent, .. } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
                self.substitute_identifier(exponent, name, replacement, depth + 1)?;
            }
            ExprKind::IntegerBitTransform { base, .. } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
            }
            ExprKind::IntegerUnsignedAbsolute { base } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
            }
            ExprKind::IntegerPairTransform { base, other, .. } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
                self.substitute_identifier(other, name, replacement, depth + 1)?;
            }
            ExprKind::IntegerClamp {
                base,
                minimum,
                maximum,
            } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
                self.substitute_identifier(minimum, name, replacement, depth + 1)?;
                self.substitute_identifier(maximum, name, replacement, depth + 1)?;
            }
            ExprKind::IntegerBitCount { base, .. } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
            }
            ExprKind::IntegerLogarithm { base, radix, .. } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
                if let Some(radix) = radix {
                    self.substitute_identifier(radix, name, replacement, depth + 1)?;
                }
            }
            ExprKind::StrIsCharBoundary { base, index } => {
                self.substitute_identifier(base, name, replacement, depth + 1)?;
                self.substitute_identifier(index, name, replacement, depth + 1)?;
            }
            ExprKind::Cast { operand, .. }
            | ExprKind::Ascribe { operand, .. }
            | ExprKind::Unary { operand, .. }
            | ExprKind::UnsafeBlock { operand }
            | ExprKind::Return { operand }
            | ExprKind::LoopBreak { operand } => {
                self.substitute_identifier(operand, name, replacement, depth + 1)?;
            }
            ExprKind::Binary { left, right, .. } => {
                self.substitute_identifier(left, name, replacement, depth + 1)?;
                self.substitute_identifier(right, name, replacement, depth + 1)?;
            }
            ExprKind::Sequence { first, then } => {
                self.substitute_identifier(first, name, replacement, depth + 1)?;
                self.substitute_identifier(then, name, replacement, depth + 1)?;
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
                self.substitute_identifier(condition, name, replacement, depth + 1)?;
                self.substitute_identifier(then_branch, name, replacement, depth + 1)?;
                self.substitute_identifier(else_branch, name, replacement, depth + 1)?;
            }
            ExprKind::InlineConst { .. }
            | ExprKind::Unit
            | ExprKind::DefaultValue
            | ExprKind::Integer(_)
            | ExprKind::Bool(_)
            | ExprKind::Char(_)
            | ExprKind::ByteChar(_)
            | ExprKind::String(_)
            | ExprKind::ByteString(_)
            | ExprKind::CString(_)
            | ExprKind::ClosureParameter { .. }
            | ExprKind::Identifier(_) => {}
        }
        Ok(())
    }

    fn if_expression(
        &mut self,
        if_token: Token<'source>,
        depth: usize,
    ) -> Result<ExprId, ExpressionError> {
        if depth == MAX_EXPRESSION_DEPTH {
            return Err(self.error(ExpressionErrorKind::NestingLimitExceeded, Some(if_token)));
        }
        let condition = self.expression(0, depth + 1)?;
        let open = self.take()?;
        if !open.is_some_and(|token| token.kind == TokenKind::OpenBrace) {
            return Err(self.error(ExpressionErrorKind::ExpectedOpenBrace, open));
        }
        let (then_branch, then_end) = self.scalar_branch_block(depth + 1)?;
        let has_else = self.peek()?.is_some_and(|token| token.text == "else");
        if !has_else && !self.node_is_unit(then_branch, depth + 1) {
            let token = self.peek()?;
            return Err(self.error(ExpressionErrorKind::ExpectedElse, token));
        }
        let (else_branch, end) = if has_else {
            self.take()?;
            if let Some(nested_if) = self.peek()?.filter(|token| token.text == "if") {
                self.take()?;
                let branch = self.if_expression(nested_if, depth + 1)?;
                (branch, self.node_span(branch)?.end)
            } else {
                let open = self.take()?;
                if !open.is_some_and(|token| token.kind == TokenKind::OpenBrace) {
                    return Err(self.error(ExpressionErrorKind::ExpectedOpenBrace, open));
                }
                self.scalar_branch_block(depth + 1)?
            }
        } else {
            let unit = self.push(Expr {
                kind: ExprKind::Unit,
                span: Span {
                    start: then_end,
                    end: then_end,
                },
            })?;
            (unit, then_end)
        };
        self.push(Expr {
            kind: ExprKind::If {
                condition,
                then_branch,
                else_branch,
            },
            span: Span {
                start: if_token.span.start,
                end,
            },
        })
    }

    fn match_pattern_bound(&mut self, depth: usize) -> Result<ExprId, ExpressionError> {
        if depth == MAX_EXPRESSION_DEPTH {
            return Err(self.error(ExpressionErrorKind::NestingLimitExceeded, self.lookahead));
        }
        let token = self.take()?;
        match token {
            Some(token) if token.kind == TokenKind::Integer => self.push(Expr {
                kind: ExprKind::Integer(decode_integer(token)?),
                span: token.span,
            }),
            Some(token) if token.kind == TokenKind::Character => self.push(Expr {
                kind: ExprKind::Char(decode_character(token)?),
                span: token.span,
            }),
            Some(token) if token.kind == TokenKind::ByteCharacter => self.push(Expr {
                kind: ExprKind::ByteChar(decode_byte_character(token)?),
                span: token.span,
            }),
            Some(token) if matches!(token.text, "true" | "false") => self.push(Expr {
                kind: ExprKind::Bool(token.text == "true"),
                span: token.span,
            }),
            Some(token)
                if token.kind == TokenKind::Identifier
                    && token.text != "_"
                    && token.text != "mut" =>
            {
                self.push(Expr {
                    kind: ExprKind::Identifier(token.text),
                    span: token.span,
                })
            }
            Some(minus) if minus.kind == TokenKind::Operator && minus.text == "-" => {
                let literal = self.take()?;
                let Some(literal) = literal.filter(|token| token.kind == TokenKind::Integer) else {
                    return Err(self.error(ExpressionErrorKind::ExpectedMatchPattern, literal));
                };
                let operand = self.push(Expr {
                    kind: ExprKind::Integer(decode_integer(literal)?),
                    span: literal.span,
                })?;
                self.push(Expr {
                    kind: ExprKind::Unary {
                        operator: UnaryOperator::Negate,
                        operand,
                    },
                    span: Span {
                        start: minus.span.start,
                        end: literal.span.end,
                    },
                })
            }
            _ => Err(self.error(ExpressionErrorKind::ExpectedMatchPattern, token)),
        }
    }

    fn match_pattern(&mut self, depth: usize) -> Result<MatchPattern<'source>, ExpressionError> {
        if self
            .peek()?
            .is_some_and(|token| token.kind == TokenKind::Identifier && token.text == "_")
        {
            self.take()?;
            return Ok(MatchPattern::Wildcard);
        }
        let start = if self
            .peek()?
            .is_some_and(|token| token.kind == TokenKind::Dot)
        {
            None
        } else {
            Some(self.match_pattern_bound(depth + 1)?)
        };
        let has_at = start.is_some()
            && self
                .peek()?
                .is_some_and(|token| token.kind == TokenKind::Operator && token.text == "@");
        if let Some(start) = start.filter(|_| has_at) {
            let name = self
                .nodes
                .get(start.index())
                .and_then(Option::as_ref)
                .and_then(|expression| match expression.kind {
                    ExprKind::Identifier(name) => Some(name),
                    _ => None,
                })
                .ok_or_else(|| {
                    self.error(ExpressionErrorKind::ExpectedIdentifier, self.lookahead)
                })?;
            self.take()?;
            let pattern = match self.match_pattern(depth + 1)? {
                MatchPattern::Wildcard => MatchPatternBody::Wildcard,
                MatchPattern::Value(value) => MatchPatternBody::Value(value),
                MatchPattern::Range {
                    start,
                    end,
                    inclusive,
                } => MatchPatternBody::Range {
                    start,
                    end,
                    inclusive,
                },
                MatchPattern::Binding(_) | MatchPattern::BindingAt { .. } => {
                    return Err(
                        self.error(ExpressionErrorKind::ExpectedMatchPattern, self.lookahead)
                    );
                }
            };
            return Ok(MatchPattern::BindingAt { name, pattern });
        }
        if start.is_some()
            && !self
                .peek()?
                .is_some_and(|token| token.kind == TokenKind::Dot)
        {
            let start = start.ok_or(ExpressionError {
                kind: ExpressionErrorKind::InvalidExpressionTree,
                span: Span {
                    start: self.source_len,
                    end: self.source_len,
                },
            })?;
            if let Some(name) = self
                .nodes
                .get(start.index())
                .and_then(Option::as_ref)
                .and_then(|expression| match expression.kind {
                    ExprKind::Identifier(name) => Some(name),
                    _ => None,
                })
                .filter(|name| {
                    name.as_bytes()
                        .first()
                        .is_some_and(|byte| byte.is_ascii_lowercase())
                })
            {
                return Ok(MatchPattern::Binding(name));
            }
            return Ok(MatchPattern::Value(start));
        }
        self.take()?;
        let second_dot = self.take()?;
        if !second_dot.is_some_and(|token| token.kind == TokenKind::Dot) {
            return Err(self.error(ExpressionErrorKind::ExpectedMatchPattern, second_dot));
        }
        let inclusive = if self
            .peek()?
            .is_some_and(|token| token.kind == TokenKind::Operator && token.text == "=")
        {
            self.take()?;
            true
        } else {
            false
        };
        let end = if !inclusive
            && self.peek()?.is_some_and(|token| {
                token.kind == TokenKind::FatArrow
                    || (token.kind == TokenKind::Operator && token.text == "|")
            }) {
            None
        } else {
            Some(self.match_pattern_bound(depth + 1)?)
        };
        if start.into_iter().chain(end).any(|bound| {
            self.nodes
                .get(bound.index())
                .and_then(Option::as_ref)
                .is_some_and(|expression| matches!(expression.kind, ExprKind::Bool(_)))
        }) {
            let start_span = start
                .and_then(|bound| self.node_span(bound).ok())
                .or_else(|| end.and_then(|bound| self.node_span(bound).ok()));
            let end_span = end
                .and_then(|bound| self.node_span(bound).ok())
                .or(start_span);
            return Err(ExpressionError {
                kind: ExpressionErrorKind::InvalidRangeType,
                span: Span {
                    start: start_span.map_or(0, |span| span.start),
                    end: end_span.map_or(self.source_len, |span| span.end),
                },
            });
        }
        if let (Some(start), Some(end), Some(order)) = (
            start,
            end,
            start
                .and_then(|start| self.pattern_order_value(start))
                .zip(end.and_then(|end| self.pattern_order_value(end)))
                .and_then(|(start, end)| start.compare(end)),
        ) {
            let invalid = if inclusive {
                order == core::cmp::Ordering::Greater
            } else {
                order != core::cmp::Ordering::Less
            };
            if invalid {
                return Err(ExpressionError {
                    kind: ExpressionErrorKind::InvalidRangeBounds,
                    span: Span {
                        start: self.node_span(start)?.start,
                        end: self.node_span(end)?.end,
                    },
                });
            }
        }
        Ok(MatchPattern::Range {
            start,
            end,
            inclusive,
        })
    }

    fn append_match_pattern_alternatives(
        &mut self,
        alternatives: &mut [Option<MatchPattern<'source>>; MAX_MATCH_ALTERNATIVES],
        alternative_count: &mut usize,
        depth: usize,
    ) -> Result<(), ExpressionError> {
        self.append_match_pattern_alternatives_with_binding(
            alternatives,
            alternative_count,
            depth,
            None,
        )
    }

    fn append_match_pattern_alternatives_with_binding(
        &mut self,
        alternatives: &mut [Option<MatchPattern<'source>>; MAX_MATCH_ALTERNATIVES],
        alternative_count: &mut usize,
        depth: usize,
        binding: Option<&'source str>,
    ) -> Result<(), ExpressionError> {
        if depth == MAX_EXPRESSION_DEPTH {
            return Err(self.error(ExpressionErrorKind::NestingLimitExceeded, self.lookahead));
        }
        if binding.is_none() {
            let saved_lexer = self.lexer.clone();
            let saved_lookahead = self.lookahead;
            let candidate = self.take()?;
            let at = self.take()?;
            let grouped_binding = candidate
                .filter(|token| token.kind == TokenKind::Identifier && token.text != "_")
                .filter(|_| {
                    at.is_some_and(|token| token.kind == TokenKind::Operator && token.text == "@")
                })
                .filter(|_| {
                    self.peek()
                        .ok()
                        .flatten()
                        .is_some_and(|token| token.kind == TokenKind::OpenParen)
                });
            if let Some(candidate) = grouped_binding {
                return self.append_match_pattern_alternatives_with_binding(
                    alternatives,
                    alternative_count,
                    depth + 1,
                    Some(candidate.text),
                );
            }
            self.lexer = saved_lexer;
            self.lookahead = saved_lookahead;
        }
        if self
            .peek()?
            .is_some_and(|token| token.kind == TokenKind::OpenParen)
        {
            self.take()?;
            if self
                .peek()?
                .is_some_and(|token| token.kind == TokenKind::Operator && token.text == "|")
            {
                self.take()?;
            }
            loop {
                if self
                    .peek()?
                    .is_some_and(|token| token.kind == TokenKind::CloseParen)
                {
                    return Err(
                        self.error(ExpressionErrorKind::ExpectedMatchPattern, self.lookahead)
                    );
                }
                self.append_match_pattern_alternatives_with_binding(
                    alternatives,
                    alternative_count,
                    depth + 1,
                    binding,
                )?;
                if !self
                    .peek()?
                    .is_some_and(|token| token.kind == TokenKind::Operator && token.text == "|")
                {
                    break;
                }
                self.take()?;
            }
            let close = self.take()?;
            if !close.is_some_and(|token| token.kind == TokenKind::CloseParen) {
                return Err(self.error(ExpressionErrorKind::ExpectedCloseParen, close));
            }
            return Ok(());
        }
        if *alternative_count == MAX_MATCH_ALTERNATIVES {
            return Err(self.error(
                ExpressionErrorKind::TooManyMatchAlternatives,
                self.lookahead,
            ));
        }
        let pattern = self.match_pattern(depth + 1)?;
        alternatives[*alternative_count] = Some(if let Some(name) = binding {
            let pattern = match pattern {
                MatchPattern::Wildcard => MatchPatternBody::Wildcard,
                MatchPattern::Value(value) => MatchPatternBody::Value(value),
                MatchPattern::Range {
                    start,
                    end,
                    inclusive,
                } => MatchPatternBody::Range {
                    start,
                    end,
                    inclusive,
                },
                MatchPattern::Binding(_) | MatchPattern::BindingAt { .. } => {
                    return Err(
                        self.error(ExpressionErrorKind::ExpectedMatchPattern, self.lookahead)
                    );
                }
            };
            MatchPattern::BindingAt { name, pattern }
        } else {
            pattern
        });
        *alternative_count += 1;
        Ok(())
    }

    fn match_pattern_condition(
        &mut self,
        scrutinee: ExprId,
        pattern: MatchPattern<'source>,
    ) -> Result<ExprId, ExpressionError> {
        match pattern {
            MatchPattern::Wildcard => self.push(Expr {
                kind: ExprKind::Bool(true),
                span: self.node_span(scrutinee)?,
            }),
            MatchPattern::Binding(_) => self.push(Expr {
                kind: ExprKind::Bool(true),
                span: self.node_span(scrutinee)?,
            }),
            MatchPattern::BindingAt { pattern, .. } => {
                let pattern = match pattern {
                    MatchPatternBody::Wildcard => MatchPattern::Wildcard,
                    MatchPatternBody::Value(value) => MatchPattern::Value(value),
                    MatchPatternBody::Range {
                        start,
                        end,
                        inclusive,
                    } => MatchPattern::Range {
                        start,
                        end,
                        inclusive,
                    },
                };
                self.match_pattern_condition(scrutinee, pattern)
            }
            MatchPattern::Value(pattern) => self.push(Expr {
                kind: ExprKind::Binary {
                    operator: BinaryOperator::Equal,
                    left: scrutinee,
                    right: pattern,
                },
                span: Span {
                    start: self.node_span(scrutinee)?.start,
                    end: self.node_span(pattern)?.end,
                },
            }),
            MatchPattern::Range {
                start,
                end,
                inclusive,
            } => {
                self.record_range_validation(scrutinee, start, end, inclusive)?;
                match (start, end) {
                    (Some(start), Some(end)) => {
                        let lower = self.push(Expr {
                            kind: ExprKind::Binary {
                                operator: BinaryOperator::GreaterEqual,
                                left: scrutinee,
                                right: start,
                            },
                            span: Span {
                                start: self.node_span(scrutinee)?.start,
                                end: self.node_span(start)?.end,
                            },
                        })?;
                        let upper = self.push(Expr {
                            kind: ExprKind::Binary {
                                operator: if inclusive {
                                    BinaryOperator::LessEqual
                                } else {
                                    BinaryOperator::Less
                                },
                                left: scrutinee,
                                right: end,
                            },
                            span: Span {
                                start: self.node_span(scrutinee)?.start,
                                end: self.node_span(end)?.end,
                            },
                        })?;
                        self.push(Expr {
                            kind: ExprKind::Binary {
                                operator: BinaryOperator::LogicalAnd,
                                left: lower,
                                right: upper,
                            },
                            span: Span {
                                start: self.node_span(lower)?.start,
                                end: self.node_span(upper)?.end,
                            },
                        })
                    }
                    (Some(start), None) => self.push(Expr {
                        kind: ExprKind::Binary {
                            operator: BinaryOperator::GreaterEqual,
                            left: scrutinee,
                            right: start,
                        },
                        span: Span {
                            start: self.node_span(scrutinee)?.start,
                            end: self.node_span(start)?.end,
                        },
                    }),
                    (None, Some(end)) => self.push(Expr {
                        kind: ExprKind::Binary {
                            operator: if inclusive {
                                BinaryOperator::LessEqual
                            } else {
                                BinaryOperator::Less
                            },
                            left: scrutinee,
                            right: end,
                        },
                        span: Span {
                            start: self.node_span(scrutinee)?.start,
                            end: self.node_span(end)?.end,
                        },
                    }),
                    (None, None) => Err(ExpressionError {
                        kind: ExpressionErrorKind::ExpectedMatchPattern,
                        span: self.node_span(scrutinee)?,
                    }),
                }
            }
        }
    }

    fn match_patterns_cover_supported_domain(
        &self,
        patterns: &[Option<MatchArmPattern<'source>>; MAX_MATCH_PATTERNS],
        pattern_count: usize,
    ) -> bool {
        let mut covers_false = false;
        let mut covers_true = false;
        for pattern in patterns[..pattern_count].iter().flatten() {
            if pattern.guard.is_some() {
                continue;
            }
            for alternative in pattern.alternatives[..pattern.alternative_count]
                .iter()
                .flatten()
            {
                let body = match alternative {
                    MatchPattern::Wildcard | MatchPattern::Binding(_) => return true,
                    MatchPattern::BindingAt { pattern, .. } => Some(*pattern),
                    MatchPattern::Value(value) => {
                        if let Some(Expr {
                            kind: ExprKind::Bool(value),
                            ..
                        }) = self.nodes.get(value.index()).and_then(Option::as_ref)
                        {
                            if *value {
                                covers_true = true;
                            } else {
                                covers_false = true;
                            }
                        }
                        None
                    }
                    MatchPattern::Range { .. } => None,
                };
                match body {
                    Some(MatchPatternBody::Wildcard) => return true,
                    Some(MatchPatternBody::Value(value)) => {
                        if let Some(Expr {
                            kind: ExprKind::Bool(value),
                            ..
                        }) = self.nodes.get(value.index()).and_then(Option::as_ref)
                        {
                            if *value {
                                covers_true = true;
                            } else {
                                covers_false = true;
                            }
                        }
                    }
                    Some(MatchPatternBody::Range { .. }) | None => {}
                }
            }
        }
        covers_false && covers_true
    }

    fn match_expression(
        &mut self,
        match_token: Token<'source>,
        depth: usize,
    ) -> Result<ExprId, ExpressionError> {
        if depth == MAX_EXPRESSION_DEPTH {
            return Err(self.error(ExpressionErrorKind::NestingLimitExceeded, Some(match_token)));
        }
        let scrutinee = self.expression(0, depth + 1)?;
        let open = self.take()?;
        if !open.is_some_and(|token| token.kind == TokenKind::OpenBrace) {
            return Err(self.error(ExpressionErrorKind::ExpectedOpenBrace, open));
        }
        let mut patterns = [None; MAX_MATCH_PATTERNS];
        let mut branches = [None; MAX_MATCH_PATTERNS];
        let mut pattern_count = 0usize;
        let mut exhaustive_fallback = None;
        let mut exhaustive_close = None;
        loop {
            let leading_wildcard = self
                .peek()?
                .is_some_and(|token| token.kind == TokenKind::Identifier && token.text == "_");
            if leading_wildcard {
                self.take()?.ok_or(ExpressionError {
                    kind: ExpressionErrorKind::InvalidExpressionTree,
                    span: match_token.span,
                })?;
            }
            if leading_wildcard && !self.peek()?.is_some_and(|token| token.text == "if") {
                break;
            }
            if pattern_count == MAX_MATCH_PATTERNS {
                return Err(self.error(ExpressionErrorKind::TooManyMatchPatterns, self.lookahead));
            }
            let mut alternatives = [None; MAX_MATCH_ALTERNATIVES];
            let mut alternative_count = 0usize;
            if leading_wildcard {
                alternatives[0] = Some(MatchPattern::Wildcard);
                alternative_count = 1;
            } else {
                loop {
                    self.append_match_pattern_alternatives(
                        &mut alternatives,
                        &mut alternative_count,
                        depth + 1,
                    )?;
                    if !self
                        .peek()?
                        .is_some_and(|token| token.kind == TokenKind::Operator && token.text == "|")
                    {
                        break;
                    }
                    self.take()?;
                }
            }
            let binding = alternatives[..alternative_count]
                .iter()
                .flatten()
                .find_map(|pattern| match pattern {
                    MatchPattern::Binding(name) | MatchPattern::BindingAt { name, .. } => {
                        Some(*name)
                    }
                    MatchPattern::Wildcard
                    | MatchPattern::Value(_)
                    | MatchPattern::Range { .. } => None,
                });
            if let Some(binding) = binding {
                let consistent = alternatives[..alternative_count].iter().flatten().all(
                    |pattern| match pattern {
                        MatchPattern::Binding(name) | MatchPattern::BindingAt { name, .. } => {
                            *name == binding
                        }
                        MatchPattern::Wildcard
                        | MatchPattern::Value(_)
                        | MatchPattern::Range { .. } => false,
                    },
                );
                if !consistent {
                    return Err(self.error(
                        ExpressionErrorKind::InconsistentMatchBindings,
                        self.lookahead,
                    ));
                }
            }
            let guard = if self.peek()?.is_some_and(|token| token.text == "if") {
                self.take()?;
                Some(self.expression(0, depth + 1)?)
            } else {
                None
            };
            let arrow = self.take()?;
            if !arrow.is_some_and(|token| token.kind == TokenKind::FatArrow) {
                return Err(self.error(ExpressionErrorKind::ExpectedFatArrow, arrow));
            }
            let block_arm = self
                .peek()?
                .is_some_and(|token| token.kind == TokenKind::OpenBrace);
            let branch = self.expression(0, depth + 1)?;
            if let Some(binding) = binding {
                let scrutinee_kind = self
                    .nodes
                    .get(scrutinee.index())
                    .and_then(Option::as_ref)
                    .map(|expression| expression.kind)
                    .ok_or(ExpressionError {
                        kind: ExpressionErrorKind::InvalidExpressionTree,
                        span: match_token.span,
                    })?;
                if let Some(guard) = guard {
                    self.substitute_identifier(guard, binding, scrutinee_kind, depth + 1)?;
                }
                self.substitute_identifier(branch, binding, scrutinee_kind, depth + 1)?;
            }
            patterns[pattern_count] = Some(MatchArmPattern {
                alternatives,
                alternative_count,
                guard,
            });
            branches[pattern_count] = Some(branch);
            pattern_count += 1;
            let has_comma = self
                .peek()?
                .is_some_and(|token| token.kind == TokenKind::Comma);
            if has_comma {
                self.take()?;
            }
            let closes_match = self
                .peek()?
                .is_some_and(|token| token.kind == TokenKind::CloseBrace);
            if closes_match {
                if !self.match_patterns_cover_supported_domain(&patterns, pattern_count) {
                    return Err(self.error(ExpressionErrorKind::NonExhaustiveMatch, self.lookahead));
                }
                exhaustive_fallback = branches[pattern_count - 1].take();
                pattern_count -= 1;
                exhaustive_close = self.take()?;
                break;
            }
            if !has_comma && !block_arm {
                return Err(self.error(ExpressionErrorKind::ExpectedComma, self.lookahead));
            }
        }
        let (else_branch, close) =
            if let (Some(else_branch), Some(close)) = (exhaustive_fallback, exhaustive_close) {
                (else_branch, close)
            } else {
                let arrow = self.take()?;
                if !arrow.is_some_and(|token| token.kind == TokenKind::FatArrow) {
                    return Err(self.error(ExpressionErrorKind::ExpectedFatArrow, arrow));
                }
                let else_branch = self.expression(0, depth + 1)?;
                if self
                    .peek()?
                    .is_some_and(|token| token.kind == TokenKind::Comma)
                {
                    self.take()?;
                }
                let close = self.take()?;
                let Some(close) = close.filter(|token| token.kind == TokenKind::CloseBrace) else {
                    return Err(self.error(ExpressionErrorKind::ExpectedCloseBrace, close));
                };
                (else_branch, close)
            };
        let mut decision = else_branch;
        for index in (0..pattern_count).rev() {
            let pattern = patterns[index].ok_or(ExpressionError {
                kind: ExpressionErrorKind::InvalidExpressionTree,
                span: match_token.span,
            })?;
            let then_branch = branches[index].ok_or(ExpressionError {
                kind: ExpressionErrorKind::InvalidExpressionTree,
                span: match_token.span,
            })?;
            let mut condition = None;
            for alternative in pattern.alternatives[..pattern.alternative_count]
                .iter()
                .flatten()
                .copied()
            {
                let alternative = self.match_pattern_condition(scrutinee, alternative)?;
                condition = Some(if let Some(previous) = condition {
                    self.push(Expr {
                        kind: ExprKind::Binary {
                            operator: BinaryOperator::LogicalOr,
                            left: previous,
                            right: alternative,
                        },
                        span: Span {
                            start: self.node_span(previous)?.start,
                            end: self.node_span(alternative)?.end,
                        },
                    })?
                } else {
                    alternative
                });
            }
            let condition = condition.ok_or(ExpressionError {
                kind: ExpressionErrorKind::InvalidExpressionTree,
                span: match_token.span,
            })?;
            let condition = if let Some(guard) = pattern.guard {
                self.push(Expr {
                    kind: ExprKind::Binary {
                        operator: BinaryOperator::LogicalAnd,
                        left: condition,
                        right: guard,
                    },
                    span: Span {
                        start: self.node_span(condition)?.start,
                        end: self.node_span(guard)?.end,
                    },
                })?
            } else {
                condition
            };
            decision = self.push(Expr {
                kind: ExprKind::If {
                    condition,
                    then_branch,
                    else_branch: decision,
                },
                span: Span {
                    start: match_token.span.start,
                    end: close.span.end,
                },
            })?;
        }
        Ok(decision)
    }

    fn scalar_branch_block(&mut self, depth: usize) -> Result<(ExprId, usize), ExpressionError> {
        let mut bindings: [Option<InlineConstBinding<'source>>; MAX_INLINE_CONST_BINDINGS] =
            [None; MAX_INLINE_CONST_BINDINGS];
        let mut binding_count = 0usize;
        let mut assignment_count = 0usize;
        let mut statements = [None; MAX_INLINE_CONST_EXPRESSION_STATEMENTS];
        let mut statement_count = 0usize;
        let tail = loop {
            if let Some(close) = self
                .peek()?
                .filter(|token| token.kind == TokenKind::CloseBrace)
            {
                break self.push(Expr {
                    kind: ExprKind::Unit,
                    span: Span {
                        start: close.span.start,
                        end: close.span.start,
                    },
                })?;
            }
            if self.peek()?.is_some_and(|token| token.text == "let") {
                self.inline_const_binding(&mut bindings, &mut binding_count, depth + 1)?;
                continue;
            }
            if self.inline_const_assignment(
                &mut bindings,
                binding_count,
                &mut assignment_count,
                depth + 1,
            )? {
                continue;
            }
            let expression = self.expression(0, depth + 1)?;
            for (name, replacement, _, _) in bindings[..binding_count].iter().flatten().rev() {
                self.substitute_identifier(expression, name, *replacement, depth + 1)?;
            }
            if self
                .peek()?
                .is_some_and(|token| token.kind == TokenKind::Semicolon)
            {
                let semicolon = self.take()?;
                if statement_count == MAX_INLINE_CONST_EXPRESSION_STATEMENTS {
                    return Err(self.error(
                        ExpressionErrorKind::TooManyInlineConstExpressionStatements,
                        semicolon,
                    ));
                }
                statements[statement_count] = Some(expression);
                statement_count += 1;
            } else {
                break expression;
            }
        };
        let close = self.take()?;
        let Some(close) = close.filter(|token| token.kind == TokenKind::CloseBrace) else {
            return Err(self.error(ExpressionErrorKind::ExpectedCloseBrace, close));
        };
        let mut branch = tail;
        for first in statements[..statement_count].iter().flatten().rev() {
            branch = self.push(Expr {
                kind: ExprKind::Sequence {
                    first: *first,
                    then: branch,
                },
                span: Span {
                    start: self.node_span(*first)?.start,
                    end: self.node_span(branch)?.end,
                },
            })?;
        }
        Ok((branch, close.span.end))
    }

    fn loop_break_expression(
        &mut self,
        loop_token: Token<'source>,
        label: Option<Token<'source>>,
        depth: usize,
    ) -> Result<ExprId, ExpressionError> {
        if depth == MAX_EXPRESSION_DEPTH {
            return Err(self.error(ExpressionErrorKind::NestingLimitExceeded, Some(loop_token)));
        }
        let open = self.take()?;
        if !open.is_some_and(|token| token.kind == TokenKind::OpenBrace) {
            return Err(self.error(ExpressionErrorKind::ExpectedOpenBrace, open));
        }
        if self
            .peek()?
            .is_some_and(|token| token.kind == TokenKind::Lifetime)
        {
            return self.cross_nested_loop_break_expression(loop_token, label, depth + 1);
        }
        if self.peek()?.is_some_and(|token| token.text == "while") {
            self.take()?;
            return self.while_break_condition_expression(loop_token, label, None, depth + 1);
        }
        let mut conditions = [None; MAX_LOOP_BREAK_BRANCHES];
        let mut branches = [None; MAX_LOOP_BREAK_BRANCHES];
        let mut branch_count = 0usize;
        let mut control = self.take()?;
        let (operand, close) = loop {
            if !control.is_some_and(|token| token.text == "if") {
                if !control.is_some_and(|token| token.text == "break") {
                    return Err(self.error(ExpressionErrorKind::ExpectedExpression, control));
                }
                let break_token = control.ok_or(ExpressionError {
                    kind: ExpressionErrorKind::InvalidExpressionTree,
                    span: Span {
                        start: loop_token.span.start,
                        end: loop_token.span.end,
                    },
                })?;
                self.loop_break_label(label)?;
                let operand = self.loop_break_operand(depth + 1)?;
                if self.peek()?.is_some_and(|token| token.text == "break") {
                    if branch_count == MAX_LOOP_BREAK_BRANCHES {
                        return Err(self.error(
                            ExpressionErrorKind::TooManyLoopBreakBranches,
                            Some(break_token),
                        ));
                    }
                    let condition = self.push(Expr {
                        kind: ExprKind::Bool(true),
                        span: break_token.span,
                    })?;
                    conditions[branch_count] = Some(condition);
                    branches[branch_count] = Some(operand);
                    branch_count += 1;
                    control = self.take()?;
                    continue;
                }
                let close = self.take()?;
                let Some(close) = close.filter(|token| token.kind == TokenKind::CloseBrace) else {
                    return Err(self.error(ExpressionErrorKind::ExpectedCloseBrace, close));
                };
                break (operand, close);
            }
            if branch_count == MAX_LOOP_BREAK_BRANCHES {
                return Err(self.error(ExpressionErrorKind::TooManyLoopBreakBranches, control));
            }
            let condition = self.expression(0, depth + 1)?;
            let open = self.take()?;
            if !open.is_some_and(|token| token.kind == TokenKind::OpenBrace) {
                return Err(self.error(ExpressionErrorKind::ExpectedOpenBrace, open));
            }
            let break_token = self.take()?;
            if !break_token.is_some_and(|token| token.text == "break") {
                return Err(self.error(ExpressionErrorKind::ExpectedExpression, break_token));
            }
            self.loop_break_label(label)?;
            let then_branch = self.loop_break_operand(depth + 1)?;
            let close = self.take()?;
            if !close.is_some_and(|token| token.kind == TokenKind::CloseBrace) {
                return Err(self.error(ExpressionErrorKind::ExpectedCloseBrace, close));
            }
            conditions[branch_count] = Some(condition);
            branches[branch_count] = Some(then_branch);
            branch_count += 1;
            control = self.take()?;
            if !control.is_some_and(|token| token.text == "else") {
                continue;
            }
            let alternative = self.take()?;
            if alternative.is_some_and(|token| token.text == "if") {
                control = alternative;
                continue;
            }
            if !alternative.is_some_and(|token| token.kind == TokenKind::OpenBrace) {
                return Err(self.error(ExpressionErrorKind::ExpectedOpenBrace, alternative));
            }
            let fallback_break = self.take()?;
            if !fallback_break.is_some_and(|token| token.text == "break") {
                return Err(self.error(ExpressionErrorKind::ExpectedExpression, fallback_break));
            }
            self.loop_break_label(label)?;
            let operand = self.loop_break_operand(depth + 1)?;
            let alternative_close = self.take()?;
            if !alternative_close.is_some_and(|token| token.kind == TokenKind::CloseBrace) {
                return Err(self.error(ExpressionErrorKind::ExpectedCloseBrace, alternative_close));
            }
            let close = self.take()?;
            let Some(close) = close.filter(|token| token.kind == TokenKind::CloseBrace) else {
                return Err(self.error(ExpressionErrorKind::ExpectedCloseBrace, close));
            };
            break (operand, close);
        };
        let span = Span {
            start: label.map_or(loop_token.span.start, |label| label.span.start),
            end: close.span.end,
        };
        if branch_count == 0 {
            return self.push(Expr {
                kind: ExprKind::LoopBreak { operand },
                span,
            });
        }
        let mut result = operand;
        for index in (0..branch_count).rev() {
            result = self.push(Expr {
                kind: ExprKind::LoopBreakIf {
                    condition: conditions[index].ok_or(ExpressionError {
                        kind: ExpressionErrorKind::InvalidExpressionTree,
                        span,
                    })?,
                    then_branch: branches[index].ok_or(ExpressionError {
                        kind: ExpressionErrorKind::InvalidExpressionTree,
                        span,
                    })?,
                    else_branch: result,
                },
                span,
            })?;
        }
        Ok(result)
    }

    fn cross_nested_loop_break_expression(
        &mut self,
        outer_loop: Token<'source>,
        outer_label: Option<Token<'source>>,
        depth: usize,
    ) -> Result<ExprId, ExpressionError> {
        if depth == MAX_EXPRESSION_DEPTH {
            return Err(self.error(ExpressionErrorKind::NestingLimitExceeded, Some(outer_loop)));
        }
        let inner_label = self
            .take()?
            .ok_or_else(|| self.error(ExpressionErrorKind::ExpectedExpression, self.lookahead))?;
        let colon = self.take()?;
        if !colon.is_some_and(|token| token.kind == TokenKind::Colon) {
            return Err(self.error(ExpressionErrorKind::ExpectedColon, colon));
        }
        let inner_loop = self.take()?;
        if inner_loop.is_some_and(|token| token.text == "while") {
            return self.while_break_condition_expression(
                outer_loop,
                outer_label,
                Some(inner_label),
                depth + 1,
            );
        }
        if !inner_loop.is_some_and(|token| token.text == "loop") {
            return Err(self.error(ExpressionErrorKind::ExpectedExpression, inner_loop));
        }
        let open = self.take()?;
        if !open.is_some_and(|token| token.kind == TokenKind::OpenBrace) {
            return Err(self.error(ExpressionErrorKind::ExpectedOpenBrace, open));
        }

        let mut conditions = [None; MAX_LOOP_BREAK_BRANCHES];
        let mut outer_branches = [None; MAX_LOOP_BREAK_BRANCHES];
        let mut branch_count = 0usize;
        let mut control = self.take()?;
        let inner_operand = loop {
            if !control.is_some_and(|token| token.text == "if") {
                if !control.is_some_and(|token| token.text == "break") {
                    return Err(self.error(ExpressionErrorKind::ExpectedExpression, control));
                }
                if self.value_loop_break_target(Some(inner_label), outer_label)?
                    != ValueLoopControlTarget::Current
                {
                    return Err(self.error(ExpressionErrorKind::InvalidLoopBreakTarget, control));
                }
                let operand = self.loop_break_operand(depth + 1)?;
                let close = self.take()?;
                if !close.is_some_and(|token| token.kind == TokenKind::CloseBrace) {
                    return Err(self.error(ExpressionErrorKind::ExpectedCloseBrace, close));
                }
                break operand;
            }
            if branch_count == MAX_LOOP_BREAK_BRANCHES {
                return Err(self.error(ExpressionErrorKind::TooManyLoopBreakBranches, control));
            }
            let condition = self.expression(0, depth + 1)?;
            let open = self.take()?;
            if !open.is_some_and(|token| token.kind == TokenKind::OpenBrace) {
                return Err(self.error(ExpressionErrorKind::ExpectedOpenBrace, open));
            }
            let break_token = self.take()?;
            if !break_token.is_some_and(|token| token.text == "break") {
                return Err(self.error(ExpressionErrorKind::ExpectedExpression, break_token));
            }
            if self.value_loop_break_target(Some(inner_label), outer_label)?
                != ValueLoopControlTarget::Enclosing
            {
                return Err(self.error(ExpressionErrorKind::InvalidLoopBreakTarget, break_token));
            }
            let branch = self.loop_break_operand(depth + 1)?;
            let close = self.take()?;
            if !close.is_some_and(|token| token.kind == TokenKind::CloseBrace) {
                return Err(self.error(ExpressionErrorKind::ExpectedCloseBrace, close));
            }
            conditions[branch_count] = Some(condition);
            outer_branches[branch_count] = Some(branch);
            branch_count += 1;
            control = self.take()?;
            if !control.is_some_and(|token| token.text == "else") {
                continue;
            }
            let alternative = self.take()?;
            if alternative.is_some_and(|token| token.text == "if") {
                control = alternative;
                continue;
            }
            if !alternative.is_some_and(|token| token.kind == TokenKind::OpenBrace) {
                return Err(self.error(ExpressionErrorKind::ExpectedOpenBrace, alternative));
            }
            let break_token = self.take()?;
            if !break_token.is_some_and(|token| token.text == "break") {
                return Err(self.error(ExpressionErrorKind::ExpectedExpression, break_token));
            }
            if self.value_loop_break_target(Some(inner_label), outer_label)?
                != ValueLoopControlTarget::Current
            {
                return Err(self.error(ExpressionErrorKind::InvalidLoopBreakTarget, break_token));
            }
            let operand = self.loop_break_operand(depth + 1)?;
            let alternative_close = self.take()?;
            if !alternative_close.is_some_and(|token| token.kind == TokenKind::CloseBrace) {
                return Err(self.error(ExpressionErrorKind::ExpectedCloseBrace, alternative_close));
            }
            let inner_close = self.take()?;
            if !inner_close.is_some_and(|token| token.kind == TokenKind::CloseBrace) {
                return Err(self.error(ExpressionErrorKind::ExpectedCloseBrace, inner_close));
            }
            break operand;
        };

        let semicolon = self.take()?;
        if !semicolon.is_some_and(|token| token.kind == TokenKind::Semicolon) {
            return Err(self.error(ExpressionErrorKind::TrailingToken, semicolon));
        }
        let outer_break = self.take()?;
        if !outer_break.is_some_and(|token| token.text == "break") {
            return Err(self.error(ExpressionErrorKind::ExpectedExpression, outer_break));
        }
        if self.value_loop_break_target(outer_label, None)? != ValueLoopControlTarget::Current {
            return Err(self.error(ExpressionErrorKind::InvalidLoopBreakTarget, outer_break));
        }
        let fallback = self.loop_break_operand(depth + 1)?;
        let close = self.take()?;
        let Some(close) = close.filter(|token| token.kind == TokenKind::CloseBrace) else {
            return Err(self.error(ExpressionErrorKind::ExpectedCloseBrace, close));
        };
        let span = Span {
            start: outer_label.map_or(outer_loop.span.start, |label| label.span.start),
            end: close.span.end,
        };
        let mut result = self.push(Expr {
            kind: ExprKind::Sequence {
                first: inner_operand,
                then: fallback,
            },
            span,
        })?;
        for index in (0..branch_count).rev() {
            result = self.push(Expr {
                kind: ExprKind::LoopBreakIf {
                    condition: conditions[index].ok_or(ExpressionError {
                        kind: ExpressionErrorKind::InvalidExpressionTree,
                        span,
                    })?,
                    then_branch: outer_branches[index].ok_or(ExpressionError {
                        kind: ExpressionErrorKind::InvalidExpressionTree,
                        span,
                    })?,
                    else_branch: result,
                },
                span,
            })?;
        }
        Ok(result)
    }

    fn while_break_condition_expression(
        &mut self,
        outer_loop: Token<'source>,
        outer_label: Option<Token<'source>>,
        inner_label: Option<Token<'source>>,
        depth: usize,
    ) -> Result<ExprId, ExpressionError> {
        if depth == MAX_EXPRESSION_DEPTH {
            return Err(self.error(ExpressionErrorKind::NestingLimitExceeded, Some(outer_loop)));
        }
        let break_token = self.take()?;
        if !break_token.is_some_and(|token| token.text == "break") {
            return Err(self.error(ExpressionErrorKind::ExpectedExpression, break_token));
        }
        let target = self.value_loop_break_target(inner_label, outer_label)?;
        let operand = self.loop_break_condition_operand(depth + 1)?;
        if target == ValueLoopControlTarget::Current && !self.node_is_unit(operand, depth + 1) {
            return Err(self.error(ExpressionErrorKind::InvalidLoopBreakTarget, break_token));
        }
        let open = self.take()?;
        if !open.is_some_and(|token| token.kind == TokenKind::OpenBrace) {
            return Err(self.error(ExpressionErrorKind::ExpectedOpenBrace, open));
        }
        self.skip_unreachable_brace_body()?;

        let span_start = outer_label.map_or(outer_loop.span.start, |label| label.span.start);
        if target == ValueLoopControlTarget::Enclosing {
            let close = self.take()?;
            let Some(close) = close.filter(|token| token.kind == TokenKind::CloseBrace) else {
                return Err(self.error(ExpressionErrorKind::ExpectedCloseBrace, close));
            };
            return self.push(Expr {
                kind: ExprKind::LoopBreak { operand },
                span: Span {
                    start: span_start,
                    end: close.span.end,
                },
            });
        }

        let outer_break = self.take()?;
        if !outer_break.is_some_and(|token| token.text == "break") {
            return Err(self.error(ExpressionErrorKind::ExpectedExpression, outer_break));
        }
        if self.value_loop_break_target(outer_label, None)? != ValueLoopControlTarget::Current {
            return Err(self.error(ExpressionErrorKind::InvalidLoopBreakTarget, outer_break));
        }
        let fallback = self.loop_break_operand(depth + 1)?;
        let close = self.take()?;
        let Some(close) = close.filter(|token| token.kind == TokenKind::CloseBrace) else {
            return Err(self.error(ExpressionErrorKind::ExpectedCloseBrace, close));
        };
        self.push(Expr {
            kind: ExprKind::Sequence {
                first: operand,
                then: fallback,
            },
            span: Span {
                start: span_start,
                end: close.span.end,
            },
        })
    }

    fn loop_break_condition_operand(&mut self, depth: usize) -> Result<ExprId, ExpressionError> {
        if let Some(open) = self
            .peek()?
            .filter(|token| token.kind == TokenKind::OpenBrace)
        {
            return self.push(Expr {
                kind: ExprKind::Unit,
                span: Span {
                    start: open.span.start,
                    end: open.span.start,
                },
            });
        }
        self.expression(0, depth + 1)
    }

    fn skip_unreachable_brace_body(&mut self) -> Result<(), ExpressionError> {
        let mut depth = 1usize;
        while depth != 0 {
            let token = self.take()?;
            let Some(token) = token else {
                return Err(self.error(ExpressionErrorKind::ExpectedCloseBrace, None));
            };
            if token.kind == TokenKind::OpenBrace {
                if depth == MAX_EXPRESSION_DEPTH {
                    return Err(self.error(ExpressionErrorKind::NestingLimitExceeded, Some(token)));
                }
                depth += 1;
            } else if token.kind == TokenKind::CloseBrace {
                depth -= 1;
            }
        }
        Ok(())
    }

    fn loop_break_operand(&mut self, depth: usize) -> Result<ExprId, ExpressionError> {
        if let Some(close) = self
            .peek()?
            .filter(|token| token.kind == TokenKind::CloseBrace)
        {
            return self.push(Expr {
                kind: ExprKind::Unit,
                span: Span {
                    start: close.span.start,
                    end: close.span.start,
                },
            });
        }
        if let Some(semicolon) = self
            .peek()?
            .filter(|token| token.kind == TokenKind::Semicolon)
        {
            self.take()?;
            return self.push(Expr {
                kind: ExprKind::Unit,
                span: Span {
                    start: semicolon.span.start,
                    end: semicolon.span.start,
                },
            });
        }
        let operand = self.expression(0, depth + 1)?;
        if self
            .peek()?
            .is_some_and(|token| token.kind == TokenKind::CloseBrace)
        {
            return Ok(operand);
        }
        let semicolon = self.take()?;
        if !semicolon.is_some_and(|token| token.kind == TokenKind::Semicolon) {
            return Err(self.error(ExpressionErrorKind::TrailingToken, semicolon));
        }
        Ok(operand)
    }

    fn nested_loop_break_operand(&mut self, depth: usize) -> Result<ExprId, ExpressionError> {
        if let Some(semicolon) = self
            .peek()?
            .filter(|token| token.kind == TokenKind::Semicolon)
        {
            return self.push(Expr {
                kind: ExprKind::Unit,
                span: Span {
                    start: semicolon.span.start,
                    end: semicolon.span.start,
                },
            });
        }
        self.expression(0, depth + 1)
    }

    fn loop_break_label(
        &mut self,
        expected: Option<Token<'source>>,
    ) -> Result<(), ExpressionError> {
        let _ = self.value_loop_break_target(expected, None)?;
        Ok(())
    }

    fn value_loop_break_target(
        &mut self,
        current: Option<Token<'source>>,
        enclosing: Option<Token<'source>>,
    ) -> Result<ValueLoopControlTarget, ExpressionError> {
        let Some(actual) = self
            .peek()?
            .filter(|token| token.kind == TokenKind::Lifetime)
        else {
            return Ok(ValueLoopControlTarget::Current);
        };
        self.take()?;
        if current.is_some_and(|expected| expected.text == actual.text) {
            Ok(ValueLoopControlTarget::Current)
        } else if enclosing.is_some_and(|expected| expected.text == actual.text) {
            Ok(ValueLoopControlTarget::Enclosing)
        } else {
            Err(self.error(ExpressionErrorKind::UnknownLoopLabel, Some(actual)))
        }
    }

    fn unary(&mut self, depth: usize) -> Result<ExprId, ExpressionError> {
        if depth == MAX_EXPRESSION_DEPTH {
            return Err(self.error(ExpressionErrorKind::NestingLimitExceeded, self.lookahead));
        }
        if let Some(token) = self.peek()?
            && matches!(token.text, "-" | "!" | "*" | "&")
        {
            self.take()?;
            let operator = match token.text {
                "-" => UnaryOperator::Negate,
                "!" => UnaryOperator::Not,
                "*" => UnaryOperator::Dereference,
                "&" => {
                    if self.peek()?.is_some_and(|token| token.text == "mut") {
                        self.take()?;
                        UnaryOperator::AddressOfMut
                    } else {
                        UnaryOperator::AddressOf
                    }
                }
                _ => unreachable!(),
            };
            let operand = self.unary(depth + 1)?;
            let end = self.node_span(operand)?.end;
            return self.push(Expr {
                kind: ExprKind::Unary { operator, operand },
                span: Span {
                    start: token.span.start,
                    end,
                },
            });
        }
        self.postfix(depth + 1)
    }

    fn postfix(&mut self, depth: usize) -> Result<ExprId, ExpressionError> {
        if depth == MAX_EXPRESSION_DEPTH {
            return Err(self.error(ExpressionErrorKind::NestingLimitExceeded, self.lookahead));
        }
        let mut base = self.atom(depth + 1)?;
        while let Some(token) = self.peek()? {
            if token.kind == TokenKind::OpenBracket {
                self.take()?;
                let range_starts_here = self
                    .peek()?
                    .is_some_and(|token| token.kind == TokenKind::Dot);
                let first = if range_starts_here {
                    None
                } else {
                    Some(self.expression(0, depth + 1)?)
                };
                let is_range = self
                    .peek()?
                    .is_some_and(|token| token.kind == TokenKind::Dot);
                if is_range {
                    self.take()?;
                    let second_dot = self.take()?;
                    if !second_dot.is_some_and(|token| token.kind == TokenKind::Dot) {
                        return Err(self.error(ExpressionErrorKind::ExpectedExpression, second_dot));
                    }
                    let inclusive = if self.peek()?.is_some_and(|token| token.text == "=") {
                        self.take()?;
                        true
                    } else {
                        false
                    };
                    let end = if self
                        .peek()?
                        .is_some_and(|token| token.kind == TokenKind::CloseBracket)
                    {
                        None
                    } else {
                        Some(self.expression(0, depth + 1)?)
                    };
                    let close = self.take()?;
                    let Some(close) = close.filter(|token| token.kind == TokenKind::CloseBracket)
                    else {
                        return Err(self.error(ExpressionErrorKind::ExpectedExpression, close));
                    };
                    let start_span = self.node_span(base)?.start;
                    base = self.push(Expr {
                        kind: ExprKind::RangeIndex {
                            base,
                            start: first,
                            end,
                            inclusive,
                        },
                        span: Span {
                            start: start_span,
                            end: close.span.end,
                        },
                    })?;
                    continue;
                }
                let index = first.ok_or_else(|| {
                    self.error(ExpressionErrorKind::ExpectedExpression, self.lookahead)
                })?;
                let close = self.take()?;
                let Some(close) = close.filter(|token| token.kind == TokenKind::CloseBracket)
                else {
                    return Err(self.error(ExpressionErrorKind::ExpectedExpression, close));
                };
                let start = self.node_span(base)?.start;
                base = self.push(Expr {
                    kind: ExprKind::Index { base, index },
                    span: Span {
                        start,
                        end: close.span.end,
                    },
                })?;
                continue;
            }
            if token.kind != TokenKind::Dot {
                break;
            }
            let mut probe = self.clone();
            probe.take()?;
            if probe
                .peek()?
                .is_some_and(|token| token.kind == TokenKind::Dot)
            {
                break;
            }
            self.take()?;
            let method = self.take()?;
            if let Some(field) = method.filter(|field| field.kind == TokenKind::Integer) {
                let field_index = field.tuple_field_index().ok_or_else(|| {
                    self.error(ExpressionErrorKind::InvalidTupleField, Some(field))
                })?;
                let start = self.node_span(base)?.start;
                base = self.push(Expr {
                    kind: ExprKind::TupleField {
                        base,
                        field: field_index,
                    },
                    span: Span {
                        start,
                        end: field.span.end,
                    },
                })?;
                continue;
            }
            if method.is_some_and(|method| {
                matches!(
                    method.text,
                    "truncate"
                        | "checked_truncate"
                        | "saturating_truncate"
                        | "widen"
                        | "saturating_cast"
                        | "wrapping_cast"
                        | "strict_cast"
                        | "checked_cast"
                        | "unchecked_cast"
                )
            }) {
                let method = method.expect("method was checked");
                let separator = self.take()?;
                if !separator.is_some_and(|token| token.kind == TokenKind::PathSeparator) {
                    return Err(self.error(ExpressionErrorKind::ExpectedCastType, separator));
                }
                let open_generic = self.take()?;
                if !open_generic.is_some_and(|token| token.text == "<") {
                    return Err(self.error(ExpressionErrorKind::ExpectedCastType, open_generic));
                }
                let target = self.take()?;
                let Some(target) = target.filter(|token| token.kind == TokenKind::Identifier)
                else {
                    return Err(self.error(ExpressionErrorKind::ExpectedCastType, target));
                };
                let target_type = IntegerType::from_name(target.text).ok_or_else(|| {
                    self.error(ExpressionErrorKind::UnsupportedCastType, Some(target))
                })?;
                let close_generic = self.take()?;
                if !close_generic.is_some_and(|token| token.text == ">") {
                    return Err(self.error(ExpressionErrorKind::ExpectedCastType, close_generic));
                }
                let open = self.take()?;
                if !open.is_some_and(|token| token.kind == TokenKind::OpenParen) {
                    return Err(self.error(ExpressionErrorKind::ExpectedExpression, open));
                }
                let close = self.take()?;
                let Some(close) = close.filter(|token| token.kind == TokenKind::CloseParen) else {
                    return Err(self.error(ExpressionErrorKind::ExpectedExpression, close));
                };
                let kind = if matches!(method.text, "checked_cast" | "checked_truncate") {
                    ExprKind::CheckedIntegerOption {
                        base,
                        argument: None,
                        operation: if method.text == "checked_truncate" {
                            CheckedIntegerOptionOperation::Truncate(target_type)
                        } else {
                            CheckedIntegerOptionOperation::Cast(target_type)
                        },
                    }
                } else {
                    let mode = match method.text {
                        "truncate" => IntegerWidthCastMode::Truncate,
                        "saturating_truncate" => IntegerWidthCastMode::SaturatingTruncate,
                        "widen" => IntegerWidthCastMode::Widen,
                        "saturating_cast" => IntegerWidthCastMode::Saturating,
                        "wrapping_cast" => IntegerWidthCastMode::Wrapping,
                        "strict_cast" => IntegerWidthCastMode::Strict,
                        "unchecked_cast" => IntegerWidthCastMode::Unchecked,
                        _ => unreachable!(),
                    };
                    ExprKind::IntegerWidthCast {
                        base,
                        target: target_type,
                        mode,
                    }
                };
                base = self.push(Expr {
                    kind,
                    span: Span {
                        start: self.node_span(base)?.start,
                        end: close.span.end,
                    },
                })?;
                continue;
            }
            if method.is_some_and(|method| method.text == "cast") {
                let separator = self.take()?;
                if !separator.is_some_and(|token| token.kind == TokenKind::PathSeparator) {
                    return Err(self.error(ExpressionErrorKind::ExpectedCastType, separator));
                }
                let open_generic = self.take()?;
                if !open_generic.is_some_and(|token| token.text == "<") {
                    return Err(self.error(ExpressionErrorKind::ExpectedCastType, open_generic));
                }
                let pointee = self.take()?;
                let Some(pointee) = pointee.filter(|token| token.kind == TokenKind::Identifier)
                else {
                    return Err(self.error(ExpressionErrorKind::ExpectedCastType, pointee));
                };
                let pointee =
                    match pointee.text {
                        "bool" => PointerPointee::Bool,
                        "char" => PointerPointee::Char,
                        name => PointerPointee::Integer(IntegerType::from_name(name).ok_or_else(
                            || self.error(ExpressionErrorKind::UnsupportedCastType, Some(pointee)),
                        )?),
                    };
                let close_generic = self.take()?;
                if !close_generic.is_some_and(|token| token.text == ">") {
                    return Err(self.error(ExpressionErrorKind::ExpectedCastType, close_generic));
                }
                let open = self.take()?;
                if !open.is_some_and(|token| token.kind == TokenKind::OpenParen) {
                    return Err(self.error(ExpressionErrorKind::ExpectedExpression, open));
                }
                let close = self.take()?;
                let Some(close) = close.filter(|token| token.kind == TokenKind::CloseParen) else {
                    return Err(self.error(ExpressionErrorKind::ExpectedExpression, close));
                };
                base = self.push(Expr {
                    kind: ExprKind::RawPointerPointeeCast { base, pointee },
                    span: Span {
                        start: self.node_span(base)?.start,
                        end: close.span.end,
                    },
                })?;
                continue;
            }
            let Some(method) = method.filter(|method| {
                matches!(
                    method.text,
                    "len"
                        | "is_empty"
                        | "as_bytes"
                        | "to_bytes"
                        | "to_bytes_with_nul"
                        | "is_char_boundary"
                        | "as_ptr"
                        | "as_mut_ptr"
                        | "add"
                        | "sub"
                        | "wrapping_add"
                        | "wrapping_sub"
                        | "wrapping_mul"
                        | "wrapping_div"
                        | "wrapping_rem"
                        | "rotate_left"
                        | "rotate_right"
                        | "funnel_shl"
                        | "funnel_shr"
                        | "cast_signed"
                        | "cast_unsigned"
                        | "saturating_cast_signed"
                        | "saturating_cast_unsigned"
                        | "strict_cast_signed"
                        | "strict_cast_unsigned"
                        | "checked_cast_signed"
                        | "checked_cast_unsigned"
                        | "unchecked_add"
                        | "unchecked_sub"
                        | "unchecked_mul"
                        | "unchecked_div_exact"
                        | "unchecked_neg"
                        | "unchecked_shl"
                        | "unchecked_shr"
                        | "unchecked_shl_exact"
                        | "unchecked_shr_exact"
                        | "unchecked_funnel_shl"
                        | "unchecked_funnel_shr"
                        | "unchecked_disjoint_bitor"
                        | "checked_div_exact"
                        | "checked_div"
                        | "checked_rem"
                        | "checked_div_euclid"
                        | "checked_rem_euclid"
                        | "checked_neg"
                        | "checked_abs"
                        | "checked_shl"
                        | "checked_shr"
                        | "checked_pow"
                        | "checked_next_power_of_two"
                        | "checked_ilog"
                        | "checked_ilog2"
                        | "checked_ilog10"
                        | "checked_next_multiple_of"
                        | "checked_add_signed"
                        | "checked_sub_signed"
                        | "checked_add_unsigned"
                        | "checked_sub_unsigned"
                        | "checked_isqrt"
                        | "checked_signed_diff"
                        | "checked_add"
                        | "checked_sub"
                        | "checked_mul"
                        | "expect"
                        | "unwrap"
                        | "unwrap_unchecked"
                        | "unwrap_or"
                        | "unwrap_or_else"
                        | "unwrap_or_default"
                        | "is_some"
                        | "is_none"
                        | "is_some_and"
                        | "is_none_or"
                        | "map_or"
                        | "map_or_else"
                        | "map_or_default"
                        | "map"
                        | "and_then"
                        | "or_else"
                        | "or"
                        | "xor"
                        | "and"
                        | "then_some"
                        | "then"
                        | "inspect"
                        | "filter"
                        | "clamp_magnitude"
                        | "wrapping_shl"
                        | "wrapping_shr"
                        | "unbounded_shl"
                        | "unbounded_shr"
                        | "wrapping_pow"
                        | "saturating_pow"
                        | "pow"
                        | "div_euclid"
                        | "rem_euclid"
                        | "wrapping_div_euclid"
                        | "wrapping_rem_euclid"
                        | "ilog"
                        | "ilog2"
                        | "ilog10"
                        | "signum"
                        | "bit_width"
                        | "isolate_highest_one"
                        | "isolate_lowest_one"
                        | "is_positive"
                        | "is_negative"
                        | "swap_bytes"
                        | "reverse_bits"
                        | "to_be"
                        | "to_le"
                        | "to_be_bytes"
                        | "to_le_bytes"
                        | "to_ne_bytes"
                        | "wrapping_neg"
                        | "strict_neg"
                        | "strict_abs"
                        | "wrapping_abs"
                        | "abs"
                        | "unsigned_abs"
                        | "saturating_neg"
                        | "saturating_abs"
                        | "next_power_of_two"
                        | "wrapping_next_power_of_two"
                        | "isqrt"
                        | "strict_add"
                        | "strict_sub"
                        | "strict_add_signed"
                        | "strict_sub_signed"
                        | "strict_add_unsigned"
                        | "strict_sub_unsigned"
                        | "wrapping_add_signed"
                        | "wrapping_sub_signed"
                        | "wrapping_add_unsigned"
                        | "wrapping_sub_unsigned"
                        | "strict_mul"
                        | "strict_div"
                        | "strict_rem"
                        | "strict_div_euclid"
                        | "strict_rem_euclid"
                        | "strict_shl"
                        | "strict_shr"
                        | "strict_pow"
                        | "saturating_add"
                        | "saturating_sub"
                        | "saturating_add_signed"
                        | "saturating_sub_signed"
                        | "saturating_add_unsigned"
                        | "saturating_sub_unsigned"
                        | "saturating_mul"
                        | "saturating_div"
                        | "abs_diff"
                        | "midpoint"
                        | "min"
                        | "max"
                        | "clamp"
                        | "div_floor"
                        | "div_ceil"
                        | "next_multiple_of"
                        | "carryless_mul"
                        | "extract_bits"
                        | "deposit_bits"
                        | "count_ones"
                        | "count_zeros"
                        | "leading_zeros"
                        | "trailing_zeros"
                        | "leading_ones"
                        | "trailing_ones"
                        | "offset"
                        | "wrapping_offset"
                        | "offset_from"
                        | "offset_from_unsigned"
                        | "align_offset"
                        | "is_aligned_to"
                        | "mask"
                        | "drop_in_place"
                        | "byte_add"
                        | "byte_sub"
                        | "byte_offset"
                        | "wrapping_byte_add"
                        | "wrapping_byte_sub"
                        | "wrapping_byte_offset"
                        | "byte_offset_from"
                        | "byte_offset_from_unsigned"
                        | "is_null"
                        | "is_aligned"
                        | "addr"
                        | "expose_provenance"
                        | "cast_const"
                        | "cast_mut"
                        | "as_ref_unchecked"
                        | "as_mut_unchecked"
                        | "read"
                        | "read_unaligned"
                        | "read_volatile"
                        | "replace"
                        | "swap"
                        | "write"
                        | "write_bytes"
                        | "copy_to"
                        | "copy_to_nonoverlapping"
                        | "copy_from"
                        | "copy_from_nonoverlapping"
                        | "write_unaligned"
                        | "write_volatile"
                        | "with_addr"
                        | "with_metadata_of"
                        | "is_power_of_two"
                        | "is_multiple_of"
                        | "is_ascii"
                        | "is_ascii_alphabetic"
                        | "is_ascii_uppercase"
                        | "is_ascii_lowercase"
                        | "is_ascii_alphanumeric"
                        | "is_ascii_digit"
                        | "is_ascii_hexdigit"
                        | "is_ascii_punctuation"
                        | "is_ascii_graphic"
                        | "is_ascii_whitespace"
                        | "is_ascii_control"
                )
            }) else {
                return Err(self.error(ExpressionErrorKind::ExpectedExpression, method));
            };
            let open = self.take()?;
            if !open.is_some_and(|open| open.kind == TokenKind::OpenParen) {
                return Err(self.error(ExpressionErrorKind::ExpectedExpression, open));
            }
            let argument = if matches!(
                method.text,
                "is_char_boundary"
                    | "align_offset"
                    | "is_aligned_to"
                    | "mask"
                    | "add"
                    | "sub"
                    | "wrapping_add"
                    | "wrapping_sub"
                    | "wrapping_mul"
                    | "wrapping_div"
                    | "wrapping_rem"
                    | "unchecked_add"
                    | "unchecked_sub"
                    | "unchecked_mul"
                    | "unchecked_div_exact"
                    | "unchecked_shl"
                    | "unchecked_shr"
                    | "unchecked_shl_exact"
                    | "unchecked_shr_exact"
                    | "unchecked_funnel_shl"
                    | "unchecked_funnel_shr"
                    | "unchecked_disjoint_bitor"
                    | "checked_div_exact"
                    | "checked_div"
                    | "checked_rem"
                    | "checked_div_euclid"
                    | "checked_rem_euclid"
                    | "checked_shl"
                    | "checked_shr"
                    | "checked_pow"
                    | "checked_ilog"
                    | "checked_next_multiple_of"
                    | "checked_add_signed"
                    | "checked_sub_signed"
                    | "checked_add_unsigned"
                    | "checked_sub_unsigned"
                    | "checked_signed_diff"
                    | "checked_add"
                    | "checked_sub"
                    | "checked_mul"
                    | "expect"
                    | "is_some_and"
                    | "is_none_or"
                    | "map_or"
                    | "map_or_else"
                    | "map_or_default"
                    | "map"
                    | "and_then"
                    | "or_else"
                    | "or"
                    | "xor"
                    | "and"
                    | "then_some"
                    | "then"
                    | "inspect"
                    | "filter"
                    | "unwrap_or"
                    | "unwrap_or_else"
                    | "strict_add"
                    | "strict_sub"
                    | "strict_add_signed"
                    | "strict_sub_signed"
                    | "strict_add_unsigned"
                    | "strict_sub_unsigned"
                    | "wrapping_add_signed"
                    | "wrapping_sub_signed"
                    | "wrapping_add_unsigned"
                    | "wrapping_sub_unsigned"
                    | "strict_mul"
                    | "strict_div"
                    | "strict_rem"
                    | "strict_div_euclid"
                    | "strict_rem_euclid"
                    | "strict_shl"
                    | "strict_shr"
                    | "strict_pow"
                    | "saturating_add"
                    | "saturating_sub"
                    | "saturating_add_signed"
                    | "saturating_sub_signed"
                    | "saturating_add_unsigned"
                    | "saturating_sub_unsigned"
                    | "saturating_mul"
                    | "saturating_div"
                    | "div_euclid"
                    | "rem_euclid"
                    | "wrapping_div_euclid"
                    | "wrapping_rem_euclid"
                    | "ilog"
                    | "rotate_left"
                    | "rotate_right"
                    | "funnel_shl"
                    | "funnel_shr"
                    | "wrapping_shl"
                    | "wrapping_shr"
                    | "unbounded_shl"
                    | "unbounded_shr"
                    | "wrapping_pow"
                    | "saturating_pow"
                    | "pow"
                    | "abs_diff"
                    | "midpoint"
                    | "div_floor"
                    | "div_ceil"
                    | "next_multiple_of"
                    | "carryless_mul"
                    | "extract_bits"
                    | "deposit_bits"
                    | "clamp_magnitude"
                    | "offset"
                    | "wrapping_offset"
                    | "offset_from"
                    | "offset_from_unsigned"
                    | "byte_add"
                    | "byte_sub"
                    | "byte_offset"
                    | "wrapping_byte_add"
                    | "wrapping_byte_sub"
                    | "wrapping_byte_offset"
                    | "byte_offset_from"
                    | "byte_offset_from_unsigned"
                    | "replace"
                    | "swap"
                    | "write"
                    | "write_bytes"
                    | "copy_to"
                    | "copy_to_nonoverlapping"
                    | "copy_from"
                    | "copy_from_nonoverlapping"
                    | "write_unaligned"
                    | "write_volatile"
                    | "with_addr"
                    | "with_metadata_of"
                    | "is_multiple_of"
                    | "min"
                    | "max"
                    | "clamp"
            ) {
                Some(self.expression(0, depth + 1)?)
            } else {
                None
            };
            let second_argument = if matches!(
                method.text,
                "write_bytes"
                    | "funnel_shl"
                    | "funnel_shr"
                    | "unchecked_funnel_shl"
                    | "unchecked_funnel_shr"
                    | "copy_to"
                    | "copy_to_nonoverlapping"
                    | "copy_from"
                    | "copy_from_nonoverlapping"
                    | "map_or"
                    | "map_or_else"
                    | "clamp"
            ) {
                let comma = self.take()?;
                if !comma.is_some_and(|token| token.kind == TokenKind::Comma) {
                    return Err(self.error(ExpressionErrorKind::ExpectedExpression, comma));
                }
                Some(self.expression(0, depth + 1)?)
            } else {
                None
            };
            let close = self.take()?;
            let Some(close) = close.filter(|close| close.kind == TokenKind::CloseParen) else {
                return Err(self.error(ExpressionErrorKind::ExpectedExpression, close));
            };
            let start = self.node_span(base)?.start;
            let kind = match method.text {
                "len" => ExprKind::SliceLen { base },
                "is_empty" => ExprKind::SliceIsEmpty { base },
                "as_bytes" => ExprKind::StrAsBytes { base },
                "to_bytes" => ExprKind::CStrToBytes {
                    base,
                    with_nul: false,
                },
                "to_bytes_with_nul" => ExprKind::CStrToBytes {
                    base,
                    with_nul: true,
                },
                "as_ptr" => ExprKind::ReferenceAsPointer {
                    base,
                    mutable: false,
                },
                "as_mut_ptr" => ExprKind::ReferenceAsPointer {
                    base,
                    mutable: true,
                },
                "is_null" => ExprKind::RawPointerIsNull { base },
                "is_power_of_two" => ExprKind::UnsignedIntegerPredicate {
                    base,
                    argument: None,
                    power_of_two: true,
                },
                "is_multiple_of" => ExprKind::UnsignedIntegerPredicate {
                    base,
                    argument,
                    power_of_two: false,
                },
                "is_positive" | "is_negative" => ExprKind::SignedIntegerPredicate {
                    base,
                    positive: method.text == "is_positive",
                },
                "wrapping_add"
                | "wrapping_sub"
                | "wrapping_mul"
                | "wrapping_div"
                | "wrapping_rem"
                | "strict_add"
                | "strict_sub"
                | "strict_add_signed"
                | "strict_sub_signed"
                | "strict_add_unsigned"
                | "strict_sub_unsigned"
                | "wrapping_add_signed"
                | "wrapping_sub_signed"
                | "wrapping_add_unsigned"
                | "wrapping_sub_unsigned"
                | "strict_mul"
                | "strict_div"
                | "strict_rem" => ExprKind::WrappingArithmetic {
                    base,
                    argument: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                    operator: match method.text {
                        "wrapping_add"
                        | "strict_add"
                        | "strict_add_signed"
                        | "strict_add_unsigned"
                        | "wrapping_add_signed"
                        | "wrapping_add_unsigned" => BinaryOperator::Add,
                        "wrapping_sub"
                        | "strict_sub"
                        | "strict_sub_signed"
                        | "strict_sub_unsigned"
                        | "wrapping_sub_signed"
                        | "wrapping_sub_unsigned" => BinaryOperator::Subtract,
                        "wrapping_mul" | "strict_mul" => BinaryOperator::Multiply,
                        "wrapping_div" | "strict_div" => BinaryOperator::Divide,
                        "wrapping_rem" | "strict_rem" => BinaryOperator::Remainder,
                        _ => unreachable!(),
                    },
                    euclidean: false,
                    euclidean_wrapping: false,
                    strict: method.text.starts_with("strict_"),
                    mixed_signedness: method.text.ends_with("_signed")
                        || method.text.ends_with("_unsigned"),
                },
                "div_euclid"
                | "rem_euclid"
                | "wrapping_div_euclid"
                | "wrapping_rem_euclid"
                | "strict_div_euclid"
                | "strict_rem_euclid" => ExprKind::WrappingArithmetic {
                    base,
                    argument: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                    operator: if matches!(
                        method.text,
                        "div_euclid" | "wrapping_div_euclid" | "strict_div_euclid"
                    ) {
                        BinaryOperator::Divide
                    } else {
                        BinaryOperator::Remainder
                    },
                    euclidean: true,
                    euclidean_wrapping: method.text.starts_with("wrapping_"),
                    strict: method.text.starts_with("strict_"),
                    mixed_signedness: false,
                },
                "saturating_add"
                | "saturating_sub"
                | "saturating_add_signed"
                | "saturating_sub_signed"
                | "saturating_add_unsigned"
                | "saturating_sub_unsigned"
                | "saturating_mul"
                | "saturating_div" => ExprKind::SaturatingArithmetic {
                    base,
                    argument: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                    operator: match method.text {
                        "saturating_add" | "saturating_add_signed" | "saturating_add_unsigned" => {
                            BinaryOperator::Add
                        }
                        "saturating_sub" | "saturating_sub_signed" | "saturating_sub_unsigned" => {
                            BinaryOperator::Subtract
                        }
                        "saturating_mul" => BinaryOperator::Multiply,
                        "saturating_div" => BinaryOperator::Divide,
                        _ => unreachable!(),
                    },
                    mixed_signedness: method.text.ends_with("_signed")
                        || method.text.ends_with("_unsigned"),
                },
                "rotate_left" | "rotate_right" => ExprKind::IntegerRotate {
                    base,
                    distance: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                    left: method.text == "rotate_left",
                },
                "funnel_shl" | "funnel_shr" => ExprKind::IntegerFunnelShift {
                    base,
                    other: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                    distance: second_argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                    left: method.text == "funnel_shl",
                },
                "cast_signed"
                | "cast_unsigned"
                | "saturating_cast_signed"
                | "saturating_cast_unsigned"
                | "strict_cast_signed"
                | "strict_cast_unsigned" => ExprKind::IntegerSignCast {
                    base,
                    signed: method.text.ends_with("_signed"),
                    saturating: method.text.starts_with("saturating_"),
                    strict: method.text.starts_with("strict_"),
                },
                "checked_cast_signed" | "checked_cast_unsigned" => ExprKind::CheckedIntegerOption {
                    base,
                    argument: None,
                    operation: CheckedIntegerOptionOperation::SignCast {
                        signed: method.text.ends_with("_signed"),
                    },
                },
                "unchecked_add"
                | "unchecked_sub"
                | "unchecked_mul"
                | "unchecked_div_exact"
                | "unchecked_neg"
                | "unchecked_shl"
                | "unchecked_shr"
                | "unchecked_shl_exact"
                | "unchecked_shr_exact"
                | "unchecked_funnel_shl"
                | "unchecked_funnel_shr"
                | "unchecked_disjoint_bitor" => ExprKind::UncheckedIntegerOperation {
                    base,
                    argument,
                    second_argument,
                    unary: method.text == "unchecked_neg",
                    disjoint: method.text == "unchecked_disjoint_bitor",
                    funnel: matches!(method.text, "unchecked_funnel_shl" | "unchecked_funnel_shr"),
                    operator: match method.text {
                        "unchecked_add" => BinaryOperator::Add,
                        "unchecked_sub" => BinaryOperator::Subtract,
                        "unchecked_mul" => BinaryOperator::Multiply,
                        "unchecked_div_exact" => BinaryOperator::Divide,
                        "unchecked_neg" => BinaryOperator::Subtract,
                        "unchecked_shl" | "unchecked_shl_exact" | "unchecked_funnel_shl" => {
                            BinaryOperator::ShiftLeft
                        }
                        "unchecked_shr" | "unchecked_shr_exact" | "unchecked_funnel_shr" => {
                            BinaryOperator::ShiftRight
                        }
                        "unchecked_disjoint_bitor" => BinaryOperator::BitOr,
                        _ => unreachable!(),
                    },
                },
                "checked_div_exact" => ExprKind::CheckedIntegerOption {
                    base,
                    argument: Some(argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?),
                    operation: CheckedIntegerOptionOperation::ExactDivision,
                },
                "checked_div" | "checked_rem" | "checked_div_euclid" | "checked_rem_euclid" => {
                    ExprKind::CheckedIntegerOption {
                        base,
                        argument: Some(argument.ok_or_else(|| {
                            self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                        })?),
                        operation: CheckedIntegerOptionOperation::Division {
                            remainder: matches!(method.text, "checked_rem" | "checked_rem_euclid"),
                            euclidean: method.text.ends_with("_euclid"),
                        },
                    }
                }
                "checked_neg" | "checked_abs" => ExprKind::CheckedIntegerOption {
                    base,
                    argument: None,
                    operation: CheckedIntegerOptionOperation::SignedUnary {
                        absolute: method.text == "checked_abs",
                    },
                },
                "checked_shl" | "checked_shr" => ExprKind::CheckedIntegerOption {
                    base,
                    argument: Some(argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?),
                    operation: CheckedIntegerOptionOperation::Shift {
                        left: method.text == "checked_shl",
                    },
                },
                "checked_pow" => ExprKind::CheckedIntegerOption {
                    base,
                    argument: Some(argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?),
                    operation: CheckedIntegerOptionOperation::Power,
                },
                "checked_next_power_of_two" => ExprKind::CheckedIntegerOption {
                    base,
                    argument: None,
                    operation: CheckedIntegerOptionOperation::NextPowerOfTwo,
                },
                "checked_ilog" | "checked_ilog2" | "checked_ilog10" => {
                    ExprKind::CheckedIntegerOption {
                        base,
                        argument: if method.text == "checked_ilog" {
                            Some(argument.ok_or_else(|| {
                                self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                            })?)
                        } else {
                            None
                        },
                        operation: CheckedIntegerOptionOperation::Logarithm {
                            binary: method.text == "checked_ilog2",
                        },
                    }
                }
                "checked_next_multiple_of" => ExprKind::CheckedIntegerOption {
                    base,
                    argument: Some(argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?),
                    operation: CheckedIntegerOptionOperation::NextMultiple,
                },
                "checked_add_signed" | "checked_sub_signed" => ExprKind::CheckedIntegerOption {
                    base,
                    argument: Some(argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?),
                    operation: CheckedIntegerOptionOperation::UnsignedMixedArithmetic {
                        subtract: method.text == "checked_sub_signed",
                    },
                },
                "checked_add_unsigned" | "checked_sub_unsigned" => ExprKind::CheckedIntegerOption {
                    base,
                    argument: Some(argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?),
                    operation: CheckedIntegerOptionOperation::SignedMixedArithmetic {
                        subtract: method.text == "checked_sub_unsigned",
                    },
                },
                "checked_isqrt" => ExprKind::CheckedIntegerOption {
                    base,
                    argument: None,
                    operation: CheckedIntegerOptionOperation::SquareRoot,
                },
                "checked_signed_diff" => ExprKind::CheckedIntegerOption {
                    base,
                    argument: Some(argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?),
                    operation: CheckedIntegerOptionOperation::SignedDifference,
                },
                "checked_add" | "checked_sub" | "checked_mul" => ExprKind::CheckedIntegerOption {
                    base,
                    argument: Some(argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?),
                    operation: CheckedIntegerOptionOperation::Arithmetic(match method.text {
                        "checked_add" => BinaryOperator::Add,
                        "checked_sub" => BinaryOperator::Subtract,
                        "checked_mul" => BinaryOperator::Multiply,
                        _ => unreachable!(),
                    }),
                },
                "unwrap_or" => ExprKind::IntegerOptionUnwrapOr {
                    option: base,
                    fallback: Some(argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?),
                    trap: false,
                    message: false,
                    unchecked: false,
                    lazy: false,
                },
                "unwrap_or_default" => ExprKind::IntegerOptionUnwrapOr {
                    option: base,
                    fallback: None,
                    trap: false,
                    message: false,
                    unchecked: false,
                    lazy: false,
                },
                "unwrap" => ExprKind::IntegerOptionUnwrapOr {
                    option: base,
                    fallback: None,
                    trap: true,
                    message: false,
                    unchecked: false,
                    lazy: false,
                },
                "expect" => ExprKind::IntegerOptionUnwrapOr {
                    option: base,
                    fallback: Some(argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?),
                    trap: true,
                    message: true,
                    unchecked: false,
                    lazy: false,
                },
                "unwrap_unchecked" => ExprKind::IntegerOptionUnwrapOr {
                    option: base,
                    fallback: None,
                    trap: false,
                    message: false,
                    unchecked: true,
                    lazy: false,
                },
                "unwrap_or_else" => ExprKind::IntegerOptionUnwrapOr {
                    option: base,
                    fallback: Some(argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?),
                    trap: false,
                    message: false,
                    unchecked: false,
                    lazy: true,
                },
                "is_some" | "is_none" => ExprKind::IntegerOptionPredicate {
                    option: base,
                    some: method.text == "is_some",
                    closure: None,
                },
                "is_some_and" | "is_none_or" => ExprKind::IntegerOptionPredicate {
                    option: base,
                    some: method.text == "is_none_or",
                    closure: Some(argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?),
                },
                "map_or" => ExprKind::IntegerOptionMapOr {
                    option: base,
                    default: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                    closure: second_argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                },
                "map_or_else" => ExprKind::IntegerOptionMapOrElse {
                    option: base,
                    default_closure: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                    map_closure: second_argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                },
                "map_or_default" => ExprKind::IntegerOptionMapOrDefault {
                    option: base,
                    map_closure: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                },
                "map" => ExprKind::IntegerOptionMap {
                    option: base,
                    closure: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                },
                "and_then" => ExprKind::IntegerOptionAndThen {
                    option: base,
                    closure: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                },
                "or_else" => ExprKind::IntegerOptionOrElse {
                    option: base,
                    closure: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                },
                "or" => ExprKind::IntegerOptionOr {
                    option: base,
                    alternative: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                },
                "xor" => ExprKind::IntegerOptionXor {
                    option: base,
                    alternative: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                },
                "and" => ExprKind::IntegerOptionAnd {
                    option: base,
                    alternative: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                },
                "then_some" => ExprKind::IntegerOptionThenSome {
                    condition: base,
                    value: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                },
                "then" => ExprKind::IntegerOptionThen {
                    condition: base,
                    closure: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                },
                "inspect" => ExprKind::IntegerOptionInspect {
                    option: base,
                    closure: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                },
                "filter" => ExprKind::IntegerOptionFilter {
                    option: base,
                    closure: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                },
                "clamp_magnitude" => ExprKind::IntegerClampMagnitude {
                    base,
                    limit: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                },
                "wrapping_shl" | "wrapping_shr" | "unbounded_shl" | "unbounded_shr"
                | "strict_shl" | "strict_shr" => ExprKind::IntegerWrappingShift {
                    base,
                    distance: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                    left: matches!(method.text, "wrapping_shl" | "unbounded_shl" | "strict_shl"),
                    unbounded: method.text.starts_with("unbounded_"),
                    strict: method.text.starts_with("strict_"),
                },
                "pow" | "strict_pow" | "wrapping_pow" | "saturating_pow" => {
                    ExprKind::IntegerWrappingPower {
                        base,
                        exponent: argument.ok_or_else(|| {
                            self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                        })?,
                        mode: match method.text {
                            "pow" => IntegerPowerMode::Checked,
                            "strict_pow" => IntegerPowerMode::Strict,
                            "wrapping_pow" => IntegerPowerMode::Wrapping,
                            "saturating_pow" => IntegerPowerMode::Saturating,
                            _ => unreachable!(),
                        },
                    }
                }
                "ilog" | "ilog2" | "ilog10" => ExprKind::IntegerLogarithm {
                    base,
                    radix: if method.text == "ilog" {
                        Some(argument.ok_or_else(|| {
                            self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                        })?)
                    } else {
                        None
                    },
                    binary: method.text == "ilog2",
                },
                "unsigned_abs" => ExprKind::IntegerUnsignedAbsolute { base },
                "to_be_bytes" | "to_le_bytes" | "to_ne_bytes" => ExprKind::IntegerToBytes {
                    base,
                    order: match method.text {
                        "to_be_bytes" => IntegerByteOrder::Big,
                        "to_le_bytes" => IntegerByteOrder::Little,
                        "to_ne_bytes" => IntegerByteOrder::Native,
                        _ => unreachable!(),
                    },
                },
                "min" | "max" | "abs_diff" | "midpoint" | "carryless_mul" | "extract_bits"
                | "deposit_bits" | "div_floor" | "div_ceil" | "next_multiple_of" => {
                    ExprKind::IntegerPairTransform {
                        base,
                        other: argument.ok_or_else(|| {
                            self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                        })?,
                        transform: match method.text {
                            "min" => IntegerPairTransform::Minimum,
                            "max" => IntegerPairTransform::Maximum,
                            "abs_diff" => IntegerPairTransform::AbsoluteDifference,
                            "midpoint" => IntegerPairTransform::Midpoint,
                            "carryless_mul" => IntegerPairTransform::CarrylessMultiply,
                            "extract_bits" => IntegerPairTransform::ExtractBits,
                            "deposit_bits" => IntegerPairTransform::DepositBits,
                            "div_floor" => IntegerPairTransform::DivideFloor,
                            "div_ceil" => IntegerPairTransform::DivideCeiling,
                            "next_multiple_of" => IntegerPairTransform::NextMultiple,
                            _ => unreachable!(),
                        },
                    }
                }
                "clamp" => ExprKind::IntegerClamp {
                    base,
                    minimum: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                    maximum: second_argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                },
                "isolate_highest_one"
                | "isolate_lowest_one"
                | "swap_bytes"
                | "reverse_bits"
                | "to_be"
                | "to_le"
                | "wrapping_neg"
                | "strict_neg"
                | "strict_abs"
                | "wrapping_abs"
                | "abs"
                | "saturating_neg"
                | "saturating_abs"
                | "next_power_of_two"
                | "wrapping_next_power_of_two"
                | "isqrt"
                | "signum" => ExprKind::IntegerBitTransform {
                    base,
                    transform: match method.text {
                        "isolate_highest_one" => IntegerBitTransform::IsolateHighestOne,
                        "isolate_lowest_one" => IntegerBitTransform::IsolateLowestOne,
                        "swap_bytes" => IntegerBitTransform::SwapBytes,
                        "reverse_bits" => IntegerBitTransform::ReverseBits,
                        "to_be" => IntegerBitTransform::ToBigEndian,
                        "to_le" => IntegerBitTransform::ToLittleEndian,
                        "wrapping_neg" => IntegerBitTransform::WrappingNegate,
                        "strict_neg" => IntegerBitTransform::StrictNegate,
                        "wrapping_abs" => IntegerBitTransform::WrappingAbsolute,
                        "abs" => IntegerBitTransform::Absolute,
                        "strict_abs" => IntegerBitTransform::StrictAbsolute,
                        "saturating_neg" => IntegerBitTransform::SaturatingNegate,
                        "saturating_abs" => IntegerBitTransform::SaturatingAbsolute,
                        "next_power_of_two" => IntegerBitTransform::NextPowerOfTwo,
                        "wrapping_next_power_of_two" => IntegerBitTransform::WrappingNextPowerOfTwo,
                        "isqrt" => IntegerBitTransform::IntegerSquareRoot,
                        "signum" => IntegerBitTransform::Signum,
                        _ => unreachable!(),
                    },
                },
                "bit_width" | "count_ones" | "count_zeros" | "leading_zeros" | "trailing_zeros"
                | "leading_ones" | "trailing_ones" => ExprKind::IntegerBitCount {
                    base,
                    count: match method.text {
                        "bit_width" => IntegerBitCount::Width,
                        "count_ones" => IntegerBitCount::Ones,
                        "count_zeros" => IntegerBitCount::Zeros,
                        "leading_zeros" => IntegerBitCount::LeadingZeros,
                        "trailing_zeros" => IntegerBitCount::TrailingZeros,
                        "leading_ones" => IntegerBitCount::LeadingOnes,
                        "trailing_ones" => IntegerBitCount::TrailingOnes,
                        _ => unreachable!(),
                    },
                },
                "is_ascii"
                | "is_ascii_alphabetic"
                | "is_ascii_uppercase"
                | "is_ascii_lowercase"
                | "is_ascii_alphanumeric"
                | "is_ascii_digit"
                | "is_ascii_hexdigit"
                | "is_ascii_punctuation"
                | "is_ascii_graphic"
                | "is_ascii_whitespace"
                | "is_ascii_control" => ExprKind::AsciiPredicate {
                    base,
                    predicate: match method.text {
                        "is_ascii" => AsciiPredicate::Ascii,
                        "is_ascii_alphabetic" => AsciiPredicate::Alphabetic,
                        "is_ascii_uppercase" => AsciiPredicate::Uppercase,
                        "is_ascii_lowercase" => AsciiPredicate::Lowercase,
                        "is_ascii_alphanumeric" => AsciiPredicate::Alphanumeric,
                        "is_ascii_digit" => AsciiPredicate::Digit,
                        "is_ascii_hexdigit" => AsciiPredicate::HexDigit,
                        "is_ascii_punctuation" => AsciiPredicate::Punctuation,
                        "is_ascii_graphic" => AsciiPredicate::Graphic,
                        "is_ascii_whitespace" => AsciiPredicate::Whitespace,
                        "is_ascii_control" => AsciiPredicate::Control,
                        _ => unreachable!(),
                    },
                },
                "is_aligned" => ExprKind::RawPointerIsAligned { base },
                "addr" | "expose_provenance" => ExprKind::RawPointerAddress { base },
                "cast_const" => ExprKind::RawPointerMutability {
                    base,
                    mutable: false,
                },
                "cast_mut" => ExprKind::RawPointerMutability {
                    base,
                    mutable: true,
                },
                "as_ref_unchecked" | "as_mut_unchecked" => ExprKind::RawPointerAsReference {
                    base,
                    mutable: method.text == "as_mut_unchecked",
                },
                "read" | "read_unaligned" | "read_volatile" => ExprKind::Unary {
                    operator: UnaryOperator::Dereference,
                    operand: base,
                },
                "replace" | "write" | "write_unaligned" | "write_volatile" => {
                    ExprKind::RawPointerWrite {
                        base,
                        value: argument.ok_or_else(|| {
                            self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                        })?,
                        returns_old: method.text == "replace",
                    }
                }
                "write_bytes" => ExprKind::RawPointerWriteBytes {
                    base,
                    value: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                    count: second_argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                },
                "copy_to" | "copy_to_nonoverlapping" => ExprKind::RawPointerCopy {
                    source: base,
                    destination: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                    count: second_argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                    overlapping: method.text == "copy_to",
                    destination_first: false,
                },
                "copy_from" | "copy_from_nonoverlapping" => ExprKind::RawPointerCopy {
                    source: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                    destination: base,
                    count: second_argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                    overlapping: method.text == "copy_from",
                    destination_first: true,
                },
                "swap" => ExprKind::RawPointerSwap {
                    left: base,
                    right: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                },
                "with_addr" => ExprKind::RawPointerWithAddress {
                    base,
                    address: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                },
                "with_metadata_of" => ExprKind::RawPointerWithMetadata {
                    base,
                    metadata: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                },
                "is_char_boundary" => ExprKind::StrIsCharBoundary {
                    base,
                    index: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                },
                "align_offset" => ExprKind::RawPointerAlignOffset {
                    base,
                    alignment: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                },
                "is_aligned_to" => ExprKind::RawPointerIsAlignedTo {
                    base,
                    alignment: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                },
                "mask" => ExprKind::RawPointerMask {
                    base,
                    mask: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                },
                "drop_in_place" => ExprKind::RawPointerDrop { base },
                "offset_from"
                | "offset_from_unsigned"
                | "byte_offset_from"
                | "byte_offset_from_unsigned" => ExprKind::RawPointerDifference {
                    pointer: base,
                    origin: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                    bytes: matches!(
                        method.text,
                        "byte_offset_from" | "byte_offset_from_unsigned"
                    ),
                    unsigned: matches!(
                        method.text,
                        "offset_from_unsigned" | "byte_offset_from_unsigned"
                    ),
                },
                method => ExprKind::RawPointerOffset {
                    base,
                    offset: argument.ok_or_else(|| {
                        self.error(ExpressionErrorKind::ExpectedExpression, Some(close))
                    })?,
                    subtract: matches!(method, "sub" | "byte_sub" | "wrapping_byte_sub"),
                    wrapping: matches!(
                        method,
                        "wrapping_offset"
                            | "wrapping_byte_add"
                            | "wrapping_byte_sub"
                            | "wrapping_byte_offset"
                    ),
                    signed: matches!(
                        method,
                        "offset" | "wrapping_offset" | "byte_offset" | "wrapping_byte_offset"
                    ),
                    bytes: matches!(
                        method,
                        "byte_add"
                            | "byte_sub"
                            | "byte_offset"
                            | "wrapping_byte_add"
                            | "wrapping_byte_sub"
                            | "wrapping_byte_offset"
                    ),
                },
            };
            base = self.push(Expr {
                kind,
                span: Span {
                    start,
                    end: close.span.end,
                },
            })?;
        }
        Ok(base)
    }

    fn cast(&mut self, depth: usize) -> Result<ExprId, ExpressionError> {
        if depth == MAX_EXPRESSION_DEPTH {
            return Err(self.error(ExpressionErrorKind::NestingLimitExceeded, self.lookahead));
        }
        let mut operand = self.unary(depth + 1)?;
        while self.peek()?.is_some_and(|token| token.text == "as") {
            self.take()?;
            let target = self.take()?;
            let Some(first) = target else {
                return Err(self.error(ExpressionErrorKind::ExpectedCastType, None));
            };
            let (target, end) = if first.kind == TokenKind::Identifier {
                let Some(integer_type) = IntegerType::from_name(first.text) else {
                    return Err(self.error(ExpressionErrorKind::UnsupportedCastType, Some(first)));
                };
                (CastType::Integer(integer_type), first.span.end)
            } else if first.text == "*" {
                let qualifier = self.take()?;
                let Some(qualifier) = qualifier.filter(|token| {
                    token.kind == TokenKind::Identifier && matches!(token.text, "const" | "mut")
                }) else {
                    return Err(self.error(ExpressionErrorKind::ExpectedCastType, qualifier));
                };
                let pointee = self.take()?;
                let Some(pointee) = pointee.filter(|token| token.kind == TokenKind::Identifier)
                else {
                    return Err(self.error(ExpressionErrorKind::ExpectedCastType, pointee));
                };
                let pointee_type = match pointee.text {
                    "bool" => PointerPointee::Bool,
                    "char" => PointerPointee::Char,
                    name => {
                        let Some(integer) = IntegerType::from_name(name) else {
                            return Err(
                                self.error(ExpressionErrorKind::UnsupportedCastType, Some(pointee))
                            );
                        };
                        PointerPointee::Integer(integer)
                    }
                };
                (
                    CastType::RawPointer {
                        pointee: pointee_type,
                        mutable: qualifier.text == "mut",
                    },
                    pointee.span.end,
                )
            } else {
                return Err(self.error(ExpressionErrorKind::ExpectedCastType, Some(first)));
            };
            let span = Span {
                start: self.node_span(operand)?.start,
                end,
            };
            operand = self.push(Expr {
                kind: ExprKind::Cast { operand, target },
                span,
            })?;
        }
        Ok(operand)
    }

    fn expression(
        &mut self,
        minimum_precedence: u8,
        depth: usize,
    ) -> Result<ExprId, ExpressionError> {
        if depth == MAX_EXPRESSION_DEPTH {
            return Err(self.error(ExpressionErrorKind::NestingLimitExceeded, self.lookahead));
        }
        let mut left = self.cast(depth + 1)?;
        while let Some(token) = self.peek()? {
            let Some((operator, precedence)) = binary_operator(token.text) else {
                break;
            };
            if precedence < minimum_precedence {
                break;
            }
            self.take()?;
            let right = self.expression(precedence + 1, depth + 1)?;
            let span = Span {
                start: self.node_span(left)?.start,
                end: self.node_span(right)?.end,
            };
            left = self.push(Expr {
                kind: ExprKind::Binary {
                    operator,
                    left,
                    right,
                },
                span,
            })?;
        }
        Ok(left)
    }

    pub fn parse(mut self) -> Result<ExpressionTree<'source, MAX_NODES>, ExpressionError> {
        let root = if self.peek()?.is_some_and(|token| token.text == "return") {
            let keyword = self.take()?.ok_or_else(|| {
                self.error(ExpressionErrorKind::ExpectedExpression, self.lookahead)
            })?;
            let operand = self.expression(0, 1)?;
            let end = self.node_span(operand)?.end;
            if self
                .peek()?
                .is_some_and(|token| token.kind == TokenKind::Semicolon)
            {
                self.take()?;
            }
            self.push(Expr {
                kind: ExprKind::Return { operand },
                span: Span {
                    start: keyword.span.start,
                    end,
                },
            })?
        } else {
            self.expression(0, 0)?
        };
        if let Some(token) = self.take()? {
            return Err(self.error(ExpressionErrorKind::TrailingToken, Some(token)));
        }
        Ok(ExpressionTree {
            nodes: self.nodes,
            node_count: self.node_count,
            range_validations: self.range_validations,
            range_validation_count: self.range_validation_count,
            root,
        })
    }
}

fn binary_operator(text: &str) -> Option<(BinaryOperator, u8)> {
    Some(match text {
        "||" => (BinaryOperator::LogicalOr, 1),
        "&&" => (BinaryOperator::LogicalAnd, 2),
        "|" => (BinaryOperator::BitOr, 3),
        "^" => (BinaryOperator::BitXor, 4),
        "&" => (BinaryOperator::BitAnd, 5),
        "==" => (BinaryOperator::Equal, 6),
        "!=" => (BinaryOperator::NotEqual, 6),
        "<" => (BinaryOperator::Less, 7),
        "<=" => (BinaryOperator::LessEqual, 7),
        ">" => (BinaryOperator::Greater, 7),
        ">=" => (BinaryOperator::GreaterEqual, 7),
        "<<" => (BinaryOperator::ShiftLeft, 8),
        ">>" => (BinaryOperator::ShiftRight, 8),
        "+" => (BinaryOperator::Add, 9),
        "-" => (BinaryOperator::Subtract, 9),
        "*" => (BinaryOperator::Multiply, 10),
        "/" => (BinaryOperator::Divide, 10),
        "%" => (BinaryOperator::Remainder, 10),
        _ => return None,
    })
}

fn decode_integer(token: Token<'_>) -> Result<IntegerLiteral<'_>, ExpressionError> {
    let bytes = token.text.as_bytes();
    let (radix, mut position) = match bytes {
        [b'0', b'x' | b'X', ..] => (16u32, 2usize),
        [b'0', b'o' | b'O', ..] => (8, 2),
        [b'0', b'b' | b'B', ..] => (2, 2),
        _ => (10, 0),
    };
    let mut value = 0u128;
    let mut digit_count = 0usize;
    while let Some(&byte) = bytes.get(position) {
        if byte == b'_' {
            position += 1;
            continue;
        }
        let Some(digit) = (byte as char).to_digit(radix) else {
            break;
        };
        value = value
            .checked_mul(u128::from(radix))
            .and_then(|current| current.checked_add(u128::from(digit)))
            .ok_or(ExpressionError {
                kind: ExpressionErrorKind::IntegerOverflow,
                span: token.span,
            })?;
        digit_count += 1;
        position += 1;
    }
    if digit_count == 0 {
        return Err(ExpressionError {
            kind: ExpressionErrorKind::InvalidInteger,
            span: token.span,
        });
    }
    let suffix = &token.text[position..];
    if !suffix.is_empty()
        && !matches!(
            suffix,
            "u8" | "u16"
                | "u32"
                | "u64"
                | "u128"
                | "usize"
                | "i8"
                | "i16"
                | "i32"
                | "i64"
                | "i128"
                | "isize"
        )
    {
        return Err(ExpressionError {
            kind: ExpressionErrorKind::InvalidIntegerSuffix,
            span: token.span,
        });
    }
    Ok(IntegerLiteral {
        value,
        suffix: (!suffix.is_empty()).then_some(suffix),
    })
}

fn decode_character(token: Token<'_>) -> Result<u32, ExpressionError> {
    let invalid = || ExpressionError {
        kind: ExpressionErrorKind::InvalidCharacter,
        span: token.span,
    };
    let inner = token
        .text
        .strip_prefix('\'')
        .and_then(|value| value.strip_suffix('\''))
        .ok_or_else(invalid)?;
    if let Some(escaped) = inner.strip_prefix('\\') {
        return match escaped {
            "0" => Ok(0),
            "t" => Ok(u32::from(b'\t')),
            "n" => Ok(u32::from(b'\n')),
            "r" => Ok(u32::from(b'\r')),
            "\\" => Ok(u32::from(b'\\')),
            "'" => Ok(u32::from(b'\'')),
            "\"" => Ok(u32::from(b'\"')),
            value if value.starts_with('x') && value.len() == 3 => {
                u32::from_str_radix(&value[1..], 16).map_err(|_| invalid())
            }
            value if value.starts_with("u{") && value.ends_with('}') => {
                let scalar =
                    u32::from_str_radix(&value[2..value.len() - 1], 16).map_err(|_| invalid())?;
                char::from_u32(scalar).map(u32::from).ok_or_else(invalid)
            }
            _ => Err(invalid()),
        };
    }
    let mut characters = inner.chars();
    let character = characters.next().ok_or_else(invalid)?;
    if characters.next().is_some() {
        return Err(invalid());
    }
    Ok(u32::from(character))
}

fn decode_byte_character(token: Token<'_>) -> Result<u8, ExpressionError> {
    let invalid = || ExpressionError {
        kind: ExpressionErrorKind::InvalidCharacter,
        span: token.span,
    };
    let inner = token
        .text
        .strip_prefix("b'")
        .and_then(|value| value.strip_suffix('\''))
        .ok_or_else(invalid)?;
    if let Some(escaped) = inner.strip_prefix('\\') {
        return match escaped {
            "0" => Ok(0),
            "t" => Ok(b'\t'),
            "n" => Ok(b'\n'),
            "r" => Ok(b'\r'),
            "\\" => Ok(b'\\'),
            "'" => Ok(b'\''),
            "\"" => Ok(b'\"'),
            value if value.starts_with('x') && value.len() == 3 => {
                u8::from_str_radix(&value[1..], 16).map_err(|_| invalid())
            }
            _ => Err(invalid()),
        };
    }
    let bytes = inner.as_bytes();
    if bytes.len() == 1 && bytes[0].is_ascii() {
        Ok(bytes[0])
    } else {
        Err(invalid())
    }
}
