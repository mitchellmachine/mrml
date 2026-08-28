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
}
