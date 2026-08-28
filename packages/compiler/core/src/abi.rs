use crate::{Function, FunctionAbi};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MrmlV1Integer {
    U8,
    U16,
    U32,
    U64,
    U128,
    I8,
    I16,
    I32,
    I64,
    I128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MrmlV1Pointee {
    Integer(MrmlV1Integer),
    Bool,
    Char,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MrmlV1Type {
    Unit,
    Integer(MrmlV1Integer),
    Bool,
    Char,
    RawPointer {
        pointee: MrmlV1Pointee,
        mutable: bool,
    },
    Reference {
        pointee: MrmlV1Pointee,
        mutable: bool,
    },
    Slice {
        element: MrmlV1Pointee,
        mutable: bool,
    },
    Str {
        mutable: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MrmlV1Target {
    X86_64SystemV,
    X86_64Windows,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MrmlV1LayoutFieldKind {
    Value,
    Pointer,
    Length,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MrmlV1LayoutField {
    pub kind: MrmlV1LayoutFieldKind,
    pub offset: u8,
    pub size: u8,
    pub alignment: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MrmlV1Layout {
    pub size: u8,
    pub alignment: u8,
    fields: [Option<MrmlV1LayoutField>; 2],
    field_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MrmlV1Register {
    Rax,
    Rcx,
    Rdx,
    Rdi,
    Rsi,
    R8,
    R9,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MrmlV1CallLocation {
    Register(MrmlV1Register),
    CalleeStack { offset: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MrmlV1CallValue {
    words: [Option<MrmlV1CallLocation>; 2],
    word_count: usize,
}

impl MrmlV1CallValue {
    pub fn words(&self) -> &[Option<MrmlV1CallLocation>] {
        &self.words[..self.word_count]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MrmlV1CallPlan<const MAX_PARAMETERS: usize> {
    parameters: [Option<MrmlV1CallValue>; MAX_PARAMETERS],
    parameter_count: usize,
    pub return_value: MrmlV1CallValue,
    pub stack_word_count: usize,
}

impl<const MAX_PARAMETERS: usize> MrmlV1CallPlan<MAX_PARAMETERS> {
    pub fn parameters(&self) -> &[Option<MrmlV1CallValue>] {
        &self.parameters[..self.parameter_count]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MrmlV1CallPlanError {
    pub parameter: usize,
}

impl MrmlV1Layout {
    pub fn fields(&self) -> &[Option<MrmlV1LayoutField>] {
        &self.fields[..self.field_count]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MrmlV1SignatureErrorKind {
    NotMrmlV1Export,
    PlatformSizedInteger,
    UnsupportedType,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MrmlV1SignatureLocation {
    Function,
    Parameter(usize),
    Return,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MrmlV1SignatureError {
    pub kind: MrmlV1SignatureErrorKind,
    pub location: MrmlV1SignatureLocation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MrmlV1Signature<const MAX_PARAMETERS: usize> {
    parameters: [Option<MrmlV1Type>; MAX_PARAMETERS],
    parameter_count: usize,
    pub return_type: MrmlV1Type,
}

impl<const MAX_PARAMETERS: usize> MrmlV1Signature<MAX_PARAMETERS> {
    pub fn parameters(&self) -> &[Option<MrmlV1Type>] {
        &self.parameters[..self.parameter_count]
    }
}

fn integer(text: &str) -> Option<MrmlV1Integer> {
    Some(match text {
        "u8" => MrmlV1Integer::U8,
        "u16" => MrmlV1Integer::U16,
        "u32" => MrmlV1Integer::U32,
        "u64" => MrmlV1Integer::U64,
        "u128" => MrmlV1Integer::U128,
        "i8" => MrmlV1Integer::I8,
        "i16" => MrmlV1Integer::I16,
        "i32" => MrmlV1Integer::I32,
        "i64" => MrmlV1Integer::I64,
        "i128" => MrmlV1Integer::I128,
        _ => return None,
    })
}

fn pointee(text: &str) -> Option<MrmlV1Pointee> {
    integer(text)
        .map(MrmlV1Pointee::Integer)
        .or_else(|| match text {
            "bool" => Some(MrmlV1Pointee::Bool),
            "char" => Some(MrmlV1Pointee::Char),
            _ => None,
        })
}

const fn scalar_layout(size: u8, alignment: u8, kind: MrmlV1LayoutFieldKind) -> MrmlV1Layout {
    MrmlV1Layout {
        size,
        alignment,
        fields: [
            Some(MrmlV1LayoutField {
                kind,
                offset: 0,
                size,
                alignment,
            }),
            None,
        ],
        field_count: 1,
    }
}

const fn integer_size(integer: MrmlV1Integer) -> u8 {
    match integer {
        MrmlV1Integer::U8 | MrmlV1Integer::I8 => 1,
        MrmlV1Integer::U16 | MrmlV1Integer::I16 => 2,
        MrmlV1Integer::U32 | MrmlV1Integer::I32 => 4,
        MrmlV1Integer::U64 | MrmlV1Integer::I64 => 8,
        MrmlV1Integer::U128 | MrmlV1Integer::I128 => 16,
    }
}

pub const fn layout_mrml_v1_type(target: MrmlV1Target, ty: MrmlV1Type) -> MrmlV1Layout {
    let pointer_size = match target {
        MrmlV1Target::X86_64SystemV | MrmlV1Target::X86_64Windows => 8,
    };
    match ty {
        MrmlV1Type::Unit => MrmlV1Layout {
            size: 0,
            alignment: 1,
            fields: [None, None],
            field_count: 0,
        },
        MrmlV1Type::Integer(integer) => {
            let size = integer_size(integer);
            scalar_layout(size, size, MrmlV1LayoutFieldKind::Value)
        }
        MrmlV1Type::Bool => scalar_layout(1, 1, MrmlV1LayoutFieldKind::Value),
        MrmlV1Type::Char => scalar_layout(4, 4, MrmlV1LayoutFieldKind::Value),
        MrmlV1Type::RawPointer { .. } | MrmlV1Type::Reference { .. } => {
            scalar_layout(pointer_size, pointer_size, MrmlV1LayoutFieldKind::Pointer)
        }
        MrmlV1Type::Slice { .. } | MrmlV1Type::Str { .. } => MrmlV1Layout {
            size: pointer_size * 2,
            alignment: pointer_size,
            fields: [
                Some(MrmlV1LayoutField {
                    kind: MrmlV1LayoutFieldKind::Pointer,
                    offset: 0,
                    size: pointer_size,
                    alignment: pointer_size,
                }),
                Some(MrmlV1LayoutField {
                    kind: MrmlV1LayoutFieldKind::Length,
                    offset: pointer_size,
                    size: 8,
                    alignment: 8,
                }),
            ],
            field_count: 2,
        },
    }
}

const fn parameter_register(target: MrmlV1Target, word: usize) -> Option<MrmlV1Register> {
    match (target, word) {
        (MrmlV1Target::X86_64SystemV, 0) => Some(MrmlV1Register::Rdi),
        (MrmlV1Target::X86_64SystemV, 1) => Some(MrmlV1Register::Rsi),
        (MrmlV1Target::X86_64SystemV, 2) => Some(MrmlV1Register::Rdx),
        (MrmlV1Target::X86_64SystemV, 3) => Some(MrmlV1Register::Rcx),
        (MrmlV1Target::X86_64SystemV, 4) => Some(MrmlV1Register::R8),
        (MrmlV1Target::X86_64SystemV, 5) => Some(MrmlV1Register::R9),
        (MrmlV1Target::X86_64Windows, 0) => Some(MrmlV1Register::Rcx),
        (MrmlV1Target::X86_64Windows, 1) => Some(MrmlV1Register::Rdx),
        (MrmlV1Target::X86_64Windows, 2) => Some(MrmlV1Register::R8),
        (MrmlV1Target::X86_64Windows, 3) => Some(MrmlV1Register::R9),
        _ => None,
    }
}

const fn register_word_count(target: MrmlV1Target) -> usize {
    match target {
        MrmlV1Target::X86_64SystemV => 6,
        MrmlV1Target::X86_64Windows => 4,
    }
}

const fn first_stack_offset(target: MrmlV1Target) -> u32 {
    match target {
        MrmlV1Target::X86_64SystemV => 8,
        MrmlV1Target::X86_64Windows => 40,
    }
}

fn parameter_word_location(
    target: MrmlV1Target,
    word: usize,
    parameter: usize,
) -> Result<MrmlV1CallLocation, MrmlV1CallPlanError> {
    if let Some(register) = parameter_register(target, word) {
        return Ok(MrmlV1CallLocation::Register(register));
    }
    let stack_word = word - register_word_count(target);
    let byte_offset = stack_word
        .checked_mul(8)
        .and_then(|offset| {
            usize::try_from(first_stack_offset(target))
                .ok()?
                .checked_add(offset)
        })
        .and_then(|offset| u32::try_from(offset).ok())
        .ok_or(MrmlV1CallPlanError { parameter })?;
    Ok(MrmlV1CallLocation::CalleeStack {
        offset: byte_offset,
    })
}

fn call_word_count(target: MrmlV1Target, ty: MrmlV1Type) -> usize {
    usize::from(layout_mrml_v1_type(target, ty).size).div_ceil(8)
}

pub fn plan_mrml_v1_call<const MAX_PARAMETERS: usize>(
    target: MrmlV1Target,
    signature: &MrmlV1Signature<MAX_PARAMETERS>,
) -> Result<MrmlV1CallPlan<MAX_PARAMETERS>, MrmlV1CallPlanError> {
    let mut parameters = [None; MAX_PARAMETERS];
    let mut next_word = 0usize;
    for (index, ty) in signature.parameters().iter().flatten().enumerate() {
        let word_count = call_word_count(target, *ty);
        let mut words = [None; 2];
        for word in &mut words[..word_count] {
            *word = Some(parameter_word_location(target, next_word, index)?);
            next_word += 1;
        }
        parameters[index] = Some(MrmlV1CallValue { words, word_count });
    }
    let return_word_count = call_word_count(target, signature.return_type);
    let mut return_words = [None; 2];
    if return_word_count >= 1 {
        return_words[0] = Some(MrmlV1CallLocation::Register(MrmlV1Register::Rax));
    }
    if return_word_count == 2 {
        return_words[1] = Some(MrmlV1CallLocation::Register(MrmlV1Register::Rdx));
    }
    Ok(MrmlV1CallPlan {
        parameters,
        parameter_count: signature.parameter_count,
        return_value: MrmlV1CallValue {
            words: return_words,
            word_count: return_word_count,
        },
        stack_word_count: next_word.saturating_sub(register_word_count(target)),
    })
}

pub fn classify_mrml_v1_type(text: &str) -> Result<MrmlV1Type, MrmlV1SignatureErrorKind> {
    let text = text.trim();
    if matches!(text, "usize" | "isize") {
        return Err(MrmlV1SignatureErrorKind::PlatformSizedInteger);
    }
    if text == "()" {
        return Ok(MrmlV1Type::Unit);
    }
    if let Some(integer) = integer(text) {
        return Ok(MrmlV1Type::Integer(integer));
    }
    if text == "bool" {
        return Ok(MrmlV1Type::Bool);
    }
    if text == "char" {
        return Ok(MrmlV1Type::Char);
    }
    if let Some(rest) = text.strip_prefix("*const ") {
        return pointee(rest.trim())
            .map(|pointee| MrmlV1Type::RawPointer {
                pointee,
                mutable: false,
            })
            .ok_or(MrmlV1SignatureErrorKind::UnsupportedType);
    }
    if let Some(rest) = text.strip_prefix("*mut ") {
        return pointee(rest.trim())
            .map(|pointee| MrmlV1Type::RawPointer {
                pointee,
                mutable: true,
            })
            .ok_or(MrmlV1SignatureErrorKind::UnsupportedType);
    }
    let (rest, mutable) = if let Some(rest) = text.strip_prefix("&mut ") {
        (rest.trim(), true)
    } else if let Some(rest) = text.strip_prefix('&') {
        (rest.trim(), false)
    } else {
        return Err(MrmlV1SignatureErrorKind::UnsupportedType);
    };
    if rest == "str" {
        return Ok(MrmlV1Type::Str { mutable });
    }
    if let Some(element) = rest
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        return pointee(element.trim())
            .map(|element| MrmlV1Type::Slice { element, mutable })
            .ok_or(MrmlV1SignatureErrorKind::UnsupportedType);
    }
    pointee(rest)
        .map(|pointee| MrmlV1Type::Reference { pointee, mutable })
        .ok_or(MrmlV1SignatureErrorKind::UnsupportedType)
}

pub fn validate_mrml_v1_signature<const MAX_PARAMETERS: usize>(
    function: &Function<'_, MAX_PARAMETERS>,
) -> Result<MrmlV1Signature<MAX_PARAMETERS>, MrmlV1SignatureError> {
    if !function.public || function.abi != FunctionAbi::MrmlV1 || !function.no_mangle {
        return Err(MrmlV1SignatureError {
            kind: MrmlV1SignatureErrorKind::NotMrmlV1Export,
            location: MrmlV1SignatureLocation::Function,
        });
    }
    let mut parameters = [None; MAX_PARAMETERS];
    for (index, parameter) in function.parameters().iter().flatten().enumerate() {
        parameters[index] = Some(classify_mrml_v1_type(parameter.ty.text).map_err(|kind| {
            MrmlV1SignatureError {
                kind,
                location: MrmlV1SignatureLocation::Parameter(index),
            }
        })?);
    }
    let return_type = match function.return_type {
        Some(ty) => classify_mrml_v1_type(ty.text).map_err(|kind| MrmlV1SignatureError {
            kind,
            location: MrmlV1SignatureLocation::Return,
        })?,
        None => MrmlV1Type::Unit,
    };
    Ok(MrmlV1Signature {
        parameters,
        parameter_count: function.parameter_count(),
        return_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Item, Module, Parser};

    fn exported(source: &str) -> Function<'_, 8> {
        let module: Module<'_, 1, 8> = Parser::new(source).parse_module().unwrap();
        let Some(Item::Function(function)) = module.items()[0] else {
            panic!("expected function");
        };
        function
    }

    #[test]
    fn validates_current_v1_scalar_pointer_and_view_types() {
        let function = exported(concat!(
            "#[mrml_abi::export(version = 1)] pub fn exchange(",
            "a: u8, b: i128, c: bool, d: char, e: *const u32, ",
            "f: &mut i16, g: &[u8], h: &mut str) -> u64 { 0 }"
        ));
        let signature = validate_mrml_v1_signature(&function).unwrap();
        assert_eq!(signature.parameters().len(), 8);
        assert_eq!(
            signature.parameters()[6],
            Some(MrmlV1Type::Slice {
                element: MrmlV1Pointee::Integer(MrmlV1Integer::U8),
                mutable: false,
            })
        );
        assert_eq!(
            signature.return_type,
            MrmlV1Type::Integer(MrmlV1Integer::U64)
        );
    }

    #[test]
    fn rejects_platform_sized_integer_with_exact_location() {
        let function =
            exported("#[mrml_abi::export(version = 1)] pub fn bad(value: usize) -> u8 { 0 }");
        assert_eq!(
            validate_mrml_v1_signature(&function).unwrap_err(),
            MrmlV1SignatureError {
                kind: MrmlV1SignatureErrorKind::PlatformSizedInteger,
                location: MrmlV1SignatureLocation::Parameter(0),
            }
        );
    }

    #[test]
    fn rejects_undefined_aggregate_and_reports_return_location() {
        let function =
            exported("#[mrml_abi::export(version = 1)] pub fn bad() -> (u8, u8) { (0, 0) }");
        let error = validate_mrml_v1_signature(&function).unwrap_err();
        assert_eq!(error.kind, MrmlV1SignatureErrorKind::UnsupportedType);
        assert_eq!(error.location, MrmlV1SignatureLocation::Return);
    }

    #[test]
    fn rejects_non_facade_function() {
        let function = exported("pub fn ordinary(value: u8) -> u8 { value }");
        let error = validate_mrml_v1_signature(&function).unwrap_err();
        assert_eq!(error.kind, MrmlV1SignatureErrorKind::NotMrmlV1Export);
        assert_eq!(error.location, MrmlV1SignatureLocation::Function);
    }

    #[test]
    fn defines_identical_x86_64_view_layouts_for_both_calling_conventions() {
        let slice = MrmlV1Type::Slice {
            element: MrmlV1Pointee::Integer(MrmlV1Integer::U8),
            mutable: false,
        };
        let system_v = layout_mrml_v1_type(MrmlV1Target::X86_64SystemV, slice);
        let windows = layout_mrml_v1_type(MrmlV1Target::X86_64Windows, slice);
        assert_eq!(system_v, windows);
        assert_eq!(system_v.size, 16);
        assert_eq!(system_v.alignment, 8);
        assert_eq!(system_v.fields().len(), 2);
        assert_eq!(
            system_v.fields()[0].unwrap().kind,
            MrmlV1LayoutFieldKind::Pointer
        );
        assert_eq!(system_v.fields()[0].unwrap().offset, 0);
        assert_eq!(
            system_v.fields()[1].unwrap().kind,
            MrmlV1LayoutFieldKind::Length
        );
        assert_eq!(system_v.fields()[1].unwrap().offset, 8);
    }

    #[test]
    fn defines_fixed_scalar_widths_without_platform_sized_integers() {
        for (ty, size) in [
            (MrmlV1Type::Bool, 1),
            (MrmlV1Type::Char, 4),
            (MrmlV1Type::Integer(MrmlV1Integer::U16), 2),
            (MrmlV1Type::Integer(MrmlV1Integer::I64), 8),
            (MrmlV1Type::Integer(MrmlV1Integer::U128), 16),
        ] {
            let layout = layout_mrml_v1_type(MrmlV1Target::X86_64SystemV, ty);
            assert_eq!(layout.size, size);
            assert_eq!(layout.alignment, size);
            assert_eq!(layout.fields().len(), 1);
        }
    }

    #[test]
    fn plans_system_v_view_words_and_stack_offsets() {
        let function = exported(concat!(
            "#[mrml_abi::export(version = 1)] pub fn view(",
            "a: u64, b: u64, c: u64, d: u64, e: u64, input: &[u8]) -> &[u8] { input }"
        ));
        let signature = validate_mrml_v1_signature(&function).unwrap();
        let plan = plan_mrml_v1_call(MrmlV1Target::X86_64SystemV, &signature).unwrap();
        assert_eq!(
            plan.parameters()[5].unwrap().words(),
            &[
                Some(MrmlV1CallLocation::Register(MrmlV1Register::R9)),
                Some(MrmlV1CallLocation::CalleeStack { offset: 8 }),
            ]
        );
        assert_eq!(plan.stack_word_count, 1);
        assert_eq!(
            plan.return_value.words(),
            &[
                Some(MrmlV1CallLocation::Register(MrmlV1Register::Rax)),
                Some(MrmlV1CallLocation::Register(MrmlV1Register::Rdx)),
            ]
        );
    }

    #[test]
    fn plans_windows_shadow_space_and_ordered_view_words() {
        let function = exported(concat!(
            "#[mrml_abi::export(version = 1)] pub fn view(",
            "a: u64, b: u64, c: u64, input: &str) { }"
        ));
        let signature = validate_mrml_v1_signature(&function).unwrap();
        let plan = plan_mrml_v1_call(MrmlV1Target::X86_64Windows, &signature).unwrap();
        assert_eq!(
            plan.parameters()[3].unwrap().words(),
            &[
                Some(MrmlV1CallLocation::Register(MrmlV1Register::R9)),
                Some(MrmlV1CallLocation::CalleeStack { offset: 40 }),
            ]
        );
        assert_eq!(plan.stack_word_count, 1);
        assert!(plan.return_value.words().is_empty());
    }
}
