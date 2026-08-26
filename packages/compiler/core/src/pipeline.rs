use crate::semantics::evaluate_scalar_const_function;
use crate::{
    CodegenErrorKind, CodegenOptions, ConstantResolver, ConstantTable, Item, Module, ObjectError,
    ObjectFile, ParseErrorKind, Parser, SemanticErrorKind, SourceTraitDeclarationError,
    SourceTraitDeclarationTable, SourceTraitImplementationError, SourceTraitImplementationTable,
    SourceTraitObligationError, Span, TargetLayout, X86_64Abi, analyze_constants,
    compile_x86_64_function_with_options, emit_elf64_x86_64, emit_x86_64_coff,
};

struct PipelineResolver<
    'module,
    'source,
    const MAX_CONSTANTS: usize,
    const MAX_ITEMS: usize,
    const MAX_PARAMETERS: usize,
> {
    module: &'module Module<'source, MAX_ITEMS, MAX_PARAMETERS>,
    constants: &'module ConstantTable<'source, MAX_CONSTANTS>,
    target: TargetLayout,
}

impl<const MAX_CONSTANTS: usize, const MAX_ITEMS: usize, const MAX_PARAMETERS: usize>
    ConstantResolver for PipelineResolver<'_, '_, MAX_CONSTANTS, MAX_ITEMS, MAX_PARAMETERS>
{
    fn resolve(&self, name: &str) -> Option<u128> {
        self.constants.resolve(name)
    }

    fn resolve_type(&self, name: &str) -> Option<crate::IntegerType> {
        self.constants.resolve_type(name)
    }

    fn resolves_bool(&self, name: &str) -> bool {
        self.constants.resolves_bool(name)
    }

    fn resolve_call(&self, name: &str, arguments: &[u128]) -> Option<u128> {
        evaluate_scalar_const_function(self.module, self.constants, self.target, name, arguments)
    }

    fn resolve_call_type(&self, name: &str, argument_count: usize) -> Option<crate::IntegerType> {
        self.module
            .items()
            .iter()
            .flatten()
            .find_map(|item| match item {
                Item::Function(function)
                    if function.name == name
                        && function.constant
                        && function.abi == crate::FunctionAbi::Rust
                        && function.parameter_count() == argument_count =>
                {
                    function
                        .return_type
                        .and_then(|return_type| crate::IntegerType::from_name(return_type.text))
                }
                _ => None,
            })
    }

    fn call_resolves_bool(&self, name: &str, argument_count: usize) -> bool {
        self.module.items().iter().flatten().any(|item| {
            matches!(item, Item::Function(function)
                if function.name == name
                    && function.constant
                    && function.abi == crate::FunctionAbi::Rust
                    && function.parameter_count() == argument_count
                    && function.return_type.is_some_and(|return_type| return_type.text == "bool"))
        })
    }

    fn resolve_runtime_call<const CALL_PARAMETERS: usize>(
        &self,
        name: &str,
        argument_count: usize,
    ) -> Option<crate::RuntimeCallTarget<'_, CALL_PARAMETERS>> {
        if argument_count > CALL_PARAMETERS {
            return None;
        }
        let function = self
            .module
            .items()
            .iter()
            .flatten()
            .find_map(|item| match item {
                Item::Function(function)
                    if function.name == name
                        && !function.constant
                        && !function.unsafe_function
                        && function.abi == crate::FunctionAbi::Rust
                        && function.parameter_count() == argument_count =>
                {
                    Some(function)
                }
                _ => None,
            })?;
        let return_type = function
            .return_type
            .map_or(Some(crate::ScalarType::Unit), |ty| scalar_type(ty.text))?;
        let return_type_name = function.return_type.map_or("()", |ty| ty.text);
        let mut parameters = [None; CALL_PARAMETERS];
        for (index, parameter) in function.parameters().iter().flatten().enumerate() {
            let ty = scalar_type(parameter.ty.text)?;
            if ty == crate::ScalarType::Never {
                return None;
            }
            parameters[index] = Some(crate::RuntimeCallParameter {
                name: parameter.name,
                ty,
            });
        }
        Some(crate::RuntimeCallTarget {
            name: function.name,
            parameters,
            parameter_count: argument_count,
            return_type,
            return_type_name,
            body_expression: function.body_expression,
        })
    }
}

fn scalar_type(name: &str) -> Option<crate::ScalarType> {
    crate::ScalarType::from_name(name)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectFormat {
    Elf64,
    Coff,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompileErrorKind {
    Parse(ParseErrorKind),
    Semantic(SemanticErrorKind),
    TraitDeclaration(SourceTraitDeclarationError),
    TraitImplementation(SourceTraitImplementationError),
    TraitObligation(SourceTraitObligationError),
    FunctionNotFound,
    Codegen(CodegenErrorKind),
    Object(ObjectError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompileError {
    pub kind: CompileErrorKind,
    pub span: Option<Span>,
}

impl CompileError {
    pub const fn message(&self) -> &'static str {
        match self.kind {
            CompileErrorKind::Parse(_) => "source parsing failed",
            CompileErrorKind::Semantic(_) => "semantic analysis failed",
            CompileErrorKind::TraitDeclaration(_) => "trait declaration admission failed",
            CompileErrorKind::TraitImplementation(_) => "trait implementation admission failed",
            CompileErrorKind::TraitObligation(_) => "trait obligation proof failed",
            CompileErrorKind::FunctionNotFound => "requested function was not found",
            CompileErrorKind::Codegen(_) => "machine-code generation failed",
            CompileErrorKind::Object(_) => "object emission failed",
        }
    }
}

impl core::fmt::Display for CompileError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.message())?;
        if let Some(span) = self.span {
            write!(formatter, " at bytes {}..{}", span.start, span.end)?;
        }
        Ok(())
    }
}

pub fn compile_source_function<
    const MAX_OBJECT_BYTES: usize,
    const MAX_CODE_BYTES: usize,
    const MAX_ITEMS: usize,
    const MAX_PARAMETERS: usize,
    const MAX_CONSTANTS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    source: &str,
    function_name: &str,
    format: ObjectFormat,
    target: TargetLayout,
) -> Result<ObjectFile<MAX_OBJECT_BYTES>, CompileError> {
    compile_source_function_with_options::<
        MAX_OBJECT_BYTES,
        MAX_CODE_BYTES,
        MAX_ITEMS,
        MAX_PARAMETERS,
        MAX_CONSTANTS,
        MAX_EXPRESSION_NODES,
    >(
        source,
        function_name,
        format,
        target,
        CodegenOptions::CHECKED,
    )
}

pub fn compile_source_function_with_options<
    const MAX_OBJECT_BYTES: usize,
    const MAX_CODE_BYTES: usize,
    const MAX_ITEMS: usize,
    const MAX_PARAMETERS: usize,
    const MAX_CONSTANTS: usize,
    const MAX_EXPRESSION_NODES: usize,
>(
    source: &str,
    function_name: &str,
    format: ObjectFormat,
    target: TargetLayout,
    options: CodegenOptions,
) -> Result<ObjectFile<MAX_OBJECT_BYTES>, CompileError> {
    let module = Parser::new(source)
        .parse_module::<MAX_ITEMS, MAX_PARAMETERS>()
        .map_err(|error| CompileError {
            kind: CompileErrorKind::Parse(error.kind),
            span: Some(error.span),
        })?;
    let constants =
        analyze_constants::<MAX_CONSTANTS, MAX_EXPRESSION_NODES, MAX_ITEMS, MAX_PARAMETERS>(
            &module, target,
        )
        .map_err(|error| CompileError {
            kind: CompileErrorKind::Semantic(error.kind),
            span: Some(error.span),
        })?;
    let function = module
        .items()
        .iter()
        .flatten()
        .find_map(|item| match item {
            Item::Function(function) if function.name == function_name => Some(function),
            _ => None,
        })
        .ok_or(CompileError {
            kind: CompileErrorKind::FunctionNotFound,
            span: None,
        })?;
    let traits =
        SourceTraitDeclarationTable::from_module(&module).map_err(|error| CompileError {
            kind: CompileErrorKind::TraitDeclaration(error),
            span: None,
        })?;
    let implementations =
        SourceTraitImplementationTable::from_module(&module, &traits).map_err(|error| {
            CompileError {
                kind: CompileErrorKind::TraitImplementation(error),
                span: Some(error.span),
            }
        })?;
    implementations
        .prove_module(&module, &traits)
        .map_err(|error| CompileError {
            kind: CompileErrorKind::TraitObligation(error),
            span: Some(error.span),
        })?;
    let abi = match format {
        ObjectFormat::Elf64 => X86_64Abi::SystemV,
        ObjectFormat::Coff => X86_64Abi::Windows,
    };
    let resolver = PipelineResolver {
        module: &module,
        constants: &constants,
        target,
    };
    let code = compile_x86_64_function_with_options::<
        _,
        MAX_CODE_BYTES,
        MAX_PARAMETERS,
        MAX_EXPRESSION_NODES,
    >(function, &resolver, abi, options)
    .map_err(|error| CompileError {
        kind: CompileErrorKind::Codegen(error.kind),
        span: Some(error.span),
    })?;
    match format {
        ObjectFormat::Elf64 => emit_elf64_x86_64(function.name, &code),
        ObjectFormat::Coff => emit_x86_64_coff(function.name, &code),
    }
    .map_err(|error| CompileError {
        kind: CompileErrorKind::Object(error),
        span: Some(function.name_span),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    type Artifact = ObjectFile<1024>;

    fn compile(source: &str, name: &str, format: ObjectFormat) -> Result<Artifact, CompileError> {
        compile_source_function::<1024, 256, 8, 4, 8, 32>(
            source,
            name,
            format,
            TargetLayout::X86_64,
        )
    }

    fn compile_wide(
        source: &str,
        name: &str,
        format: ObjectFormat,
    ) -> Result<ObjectFile<4096>, CompileError> {
        compile_source_function::<4096, 2048, 8, 8, 8, 64>(
            source,
            name,
            format,
            TargetLayout::X86_64,
        )
    }

    #[test]
    fn compiles_source_to_both_native_object_formats() {
        let source = "const BASE: u64 = 40; #[unsafe(no_mangle)] pub extern \"C\" fn answer() -> u64 { BASE + 2 }";
        let elf = compile(source, "answer", ObjectFormat::Elf64).unwrap();
        assert_eq!(&elf.bytes()[..4], b"\x7fELF");
        let coff = compile(source, "answer", ObjectFormat::Coff).unwrap();
        assert_eq!(&coff.bytes()[..2], &0x8664u16.to_le_bytes());
    }

    #[test]
    fn enforces_concrete_source_trait_obligations_before_codegen() {
        let satisfied = concat!(
            "trait Visible {} impl Visible for u32 {} ",
            "#[unsafe(no_mangle)] pub extern \"C\" fn answer() -> u64 where u32: Visible { 42 }"
        );
        compile(satisfied, "answer", ObjectFormat::Coff).unwrap();

        let missing = concat!(
            "trait Visible {} ",
            "#[unsafe(no_mangle)] pub extern \"C\" fn answer() -> u64 where u32: Visible { 42 }"
        );
        let error = compile(missing, "answer", ObjectFormat::Coff).unwrap_err();
        assert!(matches!(
            error.kind,
            CompileErrorKind::TraitObligation(SourceTraitObligationError {
                kind: crate::SourceTraitObligationErrorKind::Unsatisfied,
                ..
            })
        ));
        assert_eq!(
            &missing[error.span.unwrap().start..error.span.unwrap().end],
            "Visible"
        );
    }

    #[test]
    fn rejects_source_implementations_with_missing_supertraits_before_codegen() {
        let source = concat!(
            "trait Parent {} trait Child: Parent {} impl Child for u32 {} ",
            "#[unsafe(no_mangle)] pub extern \"C\" fn answer() -> u64 { 42 }"
        );
        let error = compile(source, "answer", ObjectFormat::Coff).unwrap_err();
        assert!(matches!(
            error.kind,
            CompileErrorKind::TraitImplementation(SourceTraitImplementationError {
                kind: crate::SourceTraitImplementationErrorKind::MissingSupertraitImplementation,
                ..
            })
        ));
    }

    #[test]
    fn rejects_missing_source_associated_type_values_before_codegen() {
        let complete = concat!(
            "trait Iterator { type Item; } impl Iterator for u32 { type Item = u8; } ",
            "#[unsafe(no_mangle)] pub extern \"C\" fn answer() -> u64 { 42 }"
        );
        compile(complete, "answer", ObjectFormat::Coff).unwrap();

        let source = concat!(
            "trait Iterator { type Item; } impl Iterator for u32 {} ",
            "#[unsafe(no_mangle)] pub extern \"C\" fn answer() -> u64 { 42 }"
        );
        let error = compile(source, "answer", ObjectFormat::Coff).unwrap_err();
        assert!(matches!(
            error.kind,
            CompileErrorKind::TraitImplementation(SourceTraitImplementationError {
                kind: crate::SourceTraitImplementationErrorKind::MissingAssociatedTypeValue,
                ..
            })
        ));
    }

    #[test]
    fn proves_source_projection_equalities_before_codegen() {
        let complete = concat!(
            "trait Iterator { type Item; } impl Iterator for u32 { type Item = u8; } ",
            "#[unsafe(no_mangle)] pub extern \"C\" fn answer() -> u64 ",
            "where <u32 as Iterator>::Item = u8 { 42 }"
        );
        compile(complete, "answer", ObjectFormat::Coff).unwrap();

        let mismatch = complete.replace("= u8 { 42 }", "= u16 { 42 }");
        let error = compile(&mismatch, "answer", ObjectFormat::Coff).unwrap_err();
        assert!(matches!(
            error.kind,
            CompileErrorKind::TraitObligation(SourceTraitObligationError {
                kind: crate::SourceTraitObligationErrorKind::ProjectionMismatch,
                ..
            })
        ));
    }

    #[test]
    fn proves_concrete_source_trait_arguments_before_codegen() {
        let source = concat!(
            "trait Convert<Input> { type Output; } ",
            "impl Convert<u8> for u32 { type Output = u16; } ",
            "#[unsafe(no_mangle)] pub extern \"C\" fn answer() -> u64 ",
            "where u32: Convert<u8>, <u32 as Convert<u8>>::Output = u16 { 42 }"
        );
        compile(source, "answer", ObjectFormat::Coff).unwrap();

        let missing = source.replace("u32: Convert<u8>", "u32: Convert<u16>");
        let error = compile(&missing, "answer", ObjectFormat::Coff).unwrap_err();
        assert!(matches!(
            error.kind,
            CompileErrorKind::TraitObligation(SourceTraitObligationError {
                kind: crate::SourceTraitObligationErrorKind::Unsatisfied,
                ..
            })
        ));
    }

    #[test]
    fn proves_flat_generic_source_implementations_before_codegen() {
        let source = concat!(
            "trait Identity<Input> { type Output; } ",
            "impl<T> Identity<T> for T { type Output = T; } ",
            "#[unsafe(no_mangle)] pub extern \"C\" fn answer() -> u64 ",
            "where u32: Identity<u32>, <u8 as Identity<u8>>::Output = u8 { 42 }"
        );
        compile(source, "answer", ObjectFormat::Coff).unwrap();

        let mismatch = source.replace("::Output = u8", "::Output = u16");
        let error = compile(&mismatch, "answer", ObjectFormat::Coff).unwrap_err();
        assert!(matches!(
            error.kind,
            CompileErrorKind::TraitObligation(SourceTraitObligationError {
                kind: crate::SourceTraitObligationErrorKind::ProjectionMismatch,
                ..
            })
        ));
    }

    #[test]
    fn proves_projection_valued_generic_associated_types_before_codegen() {
        let source = concat!(
            "trait Parent<Input> { type Output; } trait Child<Input> { type Output; } ",
            "impl<T> Parent<T> for T { type Output = T; } ",
            "impl<T> Child<T> for T { type Output = <T as Parent<T>>::Output; } ",
            "#[unsafe(no_mangle)] pub extern \"C\" fn answer() -> u64 ",
            "where <u32 as Child<u32>>::Output = u32 { 42 }"
        );
        compile(source, "answer", ObjectFormat::Coff).unwrap();

        let missing = source.replace("impl<T> Parent<T> for T { type Output = T; } ", "");
        let error = compile(&missing, "answer", ObjectFormat::Coff).unwrap_err();
        assert!(matches!(
            error.kind,
            CompileErrorKind::TraitObligation(SourceTraitObligationError {
                kind: crate::SourceTraitObligationErrorKind::Unsatisfied,
                ..
            })
        ));
    }

    #[test]
    fn proves_generic_source_implementation_premises_before_codegen() {
        let source = concat!(
            "trait Parent<Input> {} trait Child<Input> { type Output; } ",
            "impl Parent<u32> for u32 {} ",
            "impl<T> Child<T> for T where T: Parent<T> { type Output = T; } ",
            "#[unsafe(no_mangle)] pub extern \"C\" fn answer() -> u64 ",
            "where u32: Child<u32>, <u32 as Child<u32>>::Output = u32 { 42 }"
        );
        compile(source, "answer", ObjectFormat::Coff).unwrap();

        let missing = source.replace("impl Parent<u32> for u32 {} ", "");
        let error = compile(&missing, "answer", ObjectFormat::Coff).unwrap_err();
        assert!(matches!(
            error.kind,
            CompileErrorKind::TraitObligation(SourceTraitObligationError {
                kind: crate::SourceTraitObligationErrorKind::Unsatisfied,
                ..
            })
        ));
    }

    #[test]
    fn proves_generic_source_projection_premises_before_codegen() {
        let source = concat!(
            "trait Parent<Input> { type Output; } trait Child<Input> {} ",
            "impl Parent<u32> for u32 { type Output = u8; } ",
            "impl<T> Child<T> for T where <T as Parent<T>>::Output = u8 {} ",
            "#[unsafe(no_mangle)] pub extern \"C\" fn answer() -> u64 ",
            "where u32: Child<u32> { 42 }"
        );
        compile(source, "answer", ObjectFormat::Coff).unwrap();

        let mismatch = source.replace("::Output = u8 {}", "::Output = u16 {}");
        let error = compile(&mismatch, "answer", ObjectFormat::Coff).unwrap_err();
        assert!(matches!(
            error.kind,
            CompileErrorKind::TraitObligation(SourceTraitObligationError {
                kind: crate::SourceTraitObligationErrorKind::Unsatisfied,
                ..
            })
        ));
    }

    #[test]
    fn proves_premise_bearing_exact_implementations_before_codegen() {
        let source = concat!(
            "trait Parent<Input> {} trait Child<Input> { type Output; } ",
            "impl Parent<u32> for u32 {} ",
            "impl Child<u32> for u32 where u32: Parent<u32> { type Output = u8; } ",
            "#[unsafe(no_mangle)] pub extern \"C\" fn answer() -> u64 ",
            "where u32: Child<u32>, <u32 as Child<u32>>::Output = u8 { 42 }"
        );
        compile(source, "answer", ObjectFormat::Coff).unwrap();

        let missing = source.replace("impl Parent<u32> for u32 {} ", "");
        let error = compile(&missing, "answer", ObjectFormat::Coff).unwrap_err();
        assert!(matches!(
            error.kind,
            CompileErrorKind::TraitObligation(SourceTraitObligationError {
                kind: crate::SourceTraitObligationErrorKind::Unsatisfied,
                ..
            })
        ));
    }

    #[test]
    fn reports_each_pipeline_boundary() {
        let parse = compile("fn broken(", "broken", ObjectFormat::Elf64).unwrap_err();
        assert!(matches!(parse.kind, CompileErrorKind::Parse(_)));

        let semantic = compile(
            "const VALUE: f32 = 1; #[unsafe(no_mangle)] pub extern \"C\" fn value() -> u64 { 1 }",
            "value",
            ObjectFormat::Elf64,
        )
        .unwrap_err();
        assert!(matches!(semantic.kind, CompileErrorKind::Semantic(_)));

        let missing = compile(
            "#[unsafe(no_mangle)] pub extern \"C\" fn answer() -> u64 { 42 }",
            "other",
            ObjectFormat::Elf64,
        )
        .unwrap_err();
        assert_eq!(missing.kind, CompileErrorKind::FunctionNotFound);

        let codegen = compile(
            "#[unsafe(no_mangle)] pub extern \"C\" fn answer(value: f64) -> f64 { value + 1 }",
            "answer",
            ObjectFormat::Elf64,
        )
        .unwrap_err();
        assert!(matches!(codegen.kind, CompileErrorKind::Codegen(_)));
    }

    #[test]
    fn selects_the_object_formats_native_calling_convention() {
        let source =
            "#[unsafe(no_mangle)] pub extern \"C\" fn identity(value: u64) -> u64 { value }";
        let elf = compile(source, "identity", ObjectFormat::Elf64).unwrap();
        assert_eq!(
            &elf.bytes()[64..75],
            &[0x57, 0x48, 0x8b, 0x44, 0x24, 0, 0x48, 0x83, 0xc4, 8, 0xc3]
        );
        let coff = compile(source, "identity", ObjectFormat::Coff).unwrap();
        assert_eq!(
            &coff.bytes()[60..71],
            &[0x51, 0x48, 0x8b, 0x44, 0x24, 0, 0x48, 0x83, 0xc4, 8, 0xc3]
        );
    }

    #[test]
    fn diagnostics_include_bounded_source_locations() {
        let source = "#[unsafe(no_mangle)] pub extern \"C\" fn answer() -> u64 { 1 + }";
        let error = compile(source, "answer", ObjectFormat::Elf64).unwrap_err();
        let span = error.span.unwrap();
        assert!(span.start <= span.end);
        assert!(span.end <= source.len());
        assert_eq!(error.message(), "machine-code generation failed");
    }

    #[test]
    fn inlines_earlier_scalar_rust_functions_without_relocations() {
        let source = "fn add(value: u16, offset: u16) -> u16 { let mut total: u16 = value; total += offset; total } fn twice(value: u16) -> u64 { let doubled: u16 = add(value, value); doubled as u64 } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u8) -> u64 { twice(add(value as u16, 5)) }";
        let elf = compile(source, "answer", ObjectFormat::Elf64).unwrap();
        assert_eq!(&elf.bytes()[..4], b"\x7fELF");
        let coff = compile(source, "answer", ObjectFormat::Coff).unwrap();
        assert_eq!(&coff.bytes()[..2], &0x8664u16.to_le_bytes());

        let forward = "#[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u64) -> u64 { later(value) } fn later(value: u64) -> u64 { value + 1 }";
        assert!(compile(forward, "answer", ObjectFormat::Elf64).is_ok());

        let recursive = "fn recurse(value: u64) -> u64 { recurse(value) } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u64) -> u64 { recurse(value) }";
        let error = compile(recursive, "answer", ObjectFormat::Elf64).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::RuntimeExpressionUnsupported)
        );

        let mutual_recursion = "fn first(value: u64) -> u64 { second(value) } fn second(value: u64) -> u64 { first(value) } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u64) -> u64 { first(value) }";
        let error = compile(mutual_recursion, "answer", ObjectFormat::Elf64).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::RuntimeExpressionUnsupported)
        );

        let character = "#[unsafe(no_mangle)] pub extern \"C\" fn answer(value: char, choose: bool) -> char { select(value, choose) } fn select(value: char, choose: bool) -> char { if choose { identity(value) } else { identity('🦀') } } fn identity(value: char) -> char { value }";
        assert!(compile(character, "answer", ObjectFormat::Coff).is_ok());

        let wrong_character = "fn identity(value: char) -> char { value } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u64) -> char { identity(value) }";
        let error = compile(wrong_character, "answer", ObjectFormat::Elf64).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::RuntimeTypeMismatch)
        );

        let unit = "#[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u64) -> u64 { forward(value); consume(()); 7 } fn forward(value: u64) { check(value); } fn check(value: u64) { if value == 0 { return; } value; } fn consume(unit: ()) { unit; }";
        assert!(compile(unit, "answer", ObjectFormat::Elf64).is_ok());

        let wrong_unit = "fn check(value: u64) { value; } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u64) -> u64 { check(value) + 1 }";
        let error = compile(wrong_unit, "answer", ObjectFormat::Elf64).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::RuntimeTypeMismatch)
        );

        let raw_pointer = "#[unsafe(no_mangle)] pub extern \"C\" fn answer(input: *mut u16, fallback: usize, choose: bool) -> usize { let selected: *const u16 = select(input, fallback as *const u16, choose); selected.addr() } fn select(primary: *mut u16, fallback: *const u16, choose: bool) -> *const u16 { if choose { identity(primary) } else { identity(fallback) } } fn identity(value: *const u16) -> *const u16 { value }";
        assert!(compile(raw_pointer, "answer", ObjectFormat::Coff).is_ok());

        let wrong_pointee = "fn identity(value: *const u32) -> *const u32 { value } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: *const u16) -> *const u32 { identity(value) }";
        let error = compile(wrong_pointee, "answer", ObjectFormat::Elf64).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::RuntimeTypeMismatch)
        );

        let wrong_mutability = "fn identity(value: *mut u16) -> *mut u16 { value } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: *const u16) -> *mut u16 { identity(value) }";
        let error = compile(wrong_mutability, "answer", ObjectFormat::Elf64).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::RuntimeTypeMismatch)
        );

        let reference = "#[unsafe(no_mangle)] pub extern \"C\" fn answer(value: &mut u16, delta: u16, mutate: bool) -> u16 { if mutate { *update(value, delta) } else { read(value) } } fn update(value: &mut u16, delta: u16) -> &mut u16 { *value += delta; identity_mut(value) } fn identity_mut(value: &mut u16) -> &mut u16 { value } fn read(value: &u16) -> u16 { *identity(value) } fn identity(value: &u16) -> &u16 { value }";
        assert!(compile(reference, "answer", ObjectFormat::Elf64).is_ok());

        let boolean_reference = "#[unsafe(no_mangle)] pub extern \"C\" fn answer(value: &mut bool) -> bool { *flip(value) } fn flip(value: &mut bool) -> &mut bool { *value = !*value; value }";
        assert!(compile(boolean_reference, "answer", ObjectFormat::Coff).is_ok());

        let character_reference = "#[unsafe(no_mangle)] pub extern \"C\" fn answer(value: &char) -> char { *identity(value) } fn identity(value: &char) -> &char { value }";
        assert!(compile(character_reference, "answer", ObjectFormat::Elf64).is_ok());

        let wrong_reference_target = "fn identity(value: &u32) -> &u32 { value } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: &u16) -> u32 { *identity(value) }";
        let error = compile(wrong_reference_target, "answer", ObjectFormat::Coff).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::RuntimeTypeMismatch)
        );

        let wrong_reference_mutability = "fn identity(value: &mut u16) -> &mut u16 { value } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: &u16) -> u16 { *identity(value) }";
        let error = compile(wrong_reference_mutability, "answer", ObjectFormat::Coff).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::RuntimeTypeMismatch)
        );

        let array_reference = "#[unsafe(no_mangle)] pub extern \"C\" fn answer(values: &mut [u16; 4], index: usize, delta: u16, mutate: bool) -> u16 { if mutate { update(values, index, delta)[index] } else { read(values, index) } } fn update(values: &mut [u16; 4], index: usize, delta: u16) -> &mut [u16; 4] { values[index] += delta; values } fn read(values: &[u16; 4], index: usize) -> u16 { identity(values)[index] } fn identity(values: &[u16; 4]) -> &[u16; 4] { values }";
        assert!(compile(array_reference, "answer", ObjectFormat::Coff).is_ok());

        let wrong_array_count = "fn identity(values: &[u16; 3]) -> &[u16; 3] { values } #[unsafe(no_mangle)] pub extern \"C\" fn answer(values: &[u16; 4]) -> u16 { identity(values)[0] }";
        let error = compile(wrong_array_count, "answer", ObjectFormat::Elf64).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::RuntimeTypeMismatch)
        );

        let wrong_array_element = "fn identity(values: &[bool; 4]) -> &[bool; 4] { values } #[unsafe(no_mangle)] pub extern \"C\" fn answer(values: &[u16; 4]) -> bool { identity(values)[0] }";
        let error = compile(wrong_array_element, "answer", ObjectFormat::Elf64).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::RuntimeTypeMismatch)
        );

        let wrong_array_mutability = "fn identity(values: &mut [u16; 4]) -> &mut [u16; 4] { values } #[unsafe(no_mangle)] pub extern \"C\" fn answer(values: &[u16; 4]) -> u16 { identity(values)[0] }";
        let error = compile(wrong_array_mutability, "answer", ObjectFormat::Coff).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::RuntimeTypeMismatch)
        );

        let slice_parameter = "fn sum(values: &[u16], index: usize) -> usize { values.len() + values[index] as usize } #[unsafe(no_mangle)] pub extern \"C\" fn answer(values: &[u16], index: usize) -> usize { sum(values, index) }";
        assert!(compile(slice_parameter, "answer", ObjectFormat::Elf64).is_ok());

        let mutable_slice_parameter = "fn bump(values: &mut [u16], index: usize) -> u16 { values[index] += 1; values[index] } #[unsafe(no_mangle)] pub extern \"C\" fn answer(values: &mut [u16], index: usize) -> u16 { bump(values, index) }";
        assert!(compile(mutable_slice_parameter, "answer", ObjectFormat::Coff).is_ok());

        let string_parameter = "fn measure(text: &str) -> usize { text.len() } #[unsafe(no_mangle)] pub extern \"C\" fn answer(text: &str) -> usize { measure(text) }";
        assert!(compile(string_parameter, "answer", ObjectFormat::Elf64).is_ok());

        let slice_return = "fn choose(values: &[u16], early: bool) -> &[u16] { if early { return values; } values } #[unsafe(no_mangle)] pub extern \"C\" fn answer(values: &[u16], early: bool) -> usize { let returned: &[u16] = choose(values, early); returned.len() + returned[0] as usize }";
        assert!(compile(slice_return, "answer", ObjectFormat::Coff).is_ok());

        let mutable_slice_return = "fn identity(values: &mut [u16]) -> &mut [u16] { values } #[unsafe(no_mangle)] pub extern \"C\" fn answer(values: &mut [u16]) -> usize { let returned: &mut [u16] = identity(values); returned[0] += 1; returned.len() + returned[0] as usize }";
        assert!(compile(mutable_slice_return, "answer", ObjectFormat::Elf64).is_ok());

        let string_return = "fn identity(text: &str) -> &str { text } #[unsafe(no_mangle)] pub extern \"C\" fn answer(text: &str) -> usize { let returned: &str = identity(text); returned.len() }";
        assert!(compile(string_return, "answer", ObjectFormat::Coff).is_ok());

        let wrong_slice_element = "fn first(values: &[u32]) -> u32 { values[0] } #[unsafe(no_mangle)] pub extern \"C\" fn answer(values: &[u16]) -> u32 { first(values) }";
        let error = compile(wrong_slice_element, "answer", ObjectFormat::Coff).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::RuntimeTypeMismatch)
        );

        let wrong_slice_mutability = "fn first(values: &mut [u16]) -> u16 { values[0] } #[unsafe(no_mangle)] pub extern \"C\" fn answer(values: &[u16]) -> u16 { first(values) }";
        let error = compile(wrong_slice_mutability, "answer", ObjectFormat::Coff).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::RuntimeTypeMismatch)
        );

        let wrong_fat_kind = "fn measure(text: &str) -> usize { text.len() } #[unsafe(no_mangle)] pub extern \"C\" fn answer(values: &[u8]) -> usize { measure(values) }";
        let error = compile(wrong_fat_kind, "answer", ObjectFormat::Elf64).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::RuntimeTypeMismatch)
        );

        let value_loop = "fn choose(value: u16, alternate: u16, first: bool) -> u16 { let offset: u16 = 1; loop { if first { break value + offset; } break alternate + offset; } } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u16, alternate: u16, first: bool) -> u16 { choose(value, alternate, first) }";
        assert!(compile(value_loop, "answer", ObjectFormat::Coff).is_ok());

        let unit_value_loop = "fn finish() { loop { break; } } #[unsafe(no_mangle)] pub extern \"C\" fn answer() { finish() }";
        assert!(compile(unit_value_loop, "answer", ObjectFormat::Elf64).is_ok());

        let reference_value_loop = "fn choose(value: &mut u16, first: bool) -> &mut u16 { loop { if first { break value; } break value; } } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: &mut u16, first: bool) -> u16 { let returned: &mut u16 = choose(value, first); *returned += 1; *value }";
        let result = compile(reference_value_loop, "answer", ObjectFormat::Coff);
        assert!(result.is_ok(), "{result:?}");

        let slice_value_loop = "fn choose(values: &[u16], first: bool) -> &[u16] { loop { if first { break values; } break values; } } #[unsafe(no_mangle)] pub extern \"C\" fn answer(values: &[u16], first: bool) -> usize { let returned: &[u16] = choose(values, first); returned.len() }";
        let result = compile(slice_value_loop, "answer", ObjectFormat::Elf64);
        assert!(result.is_ok(), "{result:?}");

        let wrong_value_loop_type = "fn choose(value: u16, flag: bool) -> u16 { loop { if flag { break value; } break false; } } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u16, flag: bool) -> u16 { choose(value, flag) }";
        let error = compile(wrong_value_loop_type, "answer", ObjectFormat::Coff).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::RuntimeTypeMismatch)
        );

        let array_value_parameter = "fn sum(values: [u16; 3]) -> u16 { values[0] + values[1] + values[2] } #[unsafe(no_mangle)] pub extern \"C\" fn answer(first: u16, second: u16, third: u16) -> u16 { sum([first, second, third]) }";
        let result = compile_wide(array_value_parameter, "answer", ObjectFormat::Coff);
        assert!(result.is_ok(), "{result:?}");

        let array_value_return = "fn choose(values: [u16; 3], early: bool) -> [u16; 3] { let copy: [u16; 3] = values; if early { return copy; } copy } #[unsafe(no_mangle)] pub extern \"C\" fn answer(first: u16, second: u16, third: u16, early: bool) -> u16 { let returned: [u16; 3] = choose([first, second, third], early); returned[0] + returned[1] + returned[2] }";
        let result = compile_wide(array_value_return, "answer", ObjectFormat::Elf64);
        assert!(result.is_ok(), "{result:?}");

        let direct_array_value_index = "fn identity(values: [char; 2]) -> [char; 2] { values } #[unsafe(no_mangle)] pub extern \"C\" fn answer(first: char, second: char) -> char { identity([first, second])[1] }";
        let result = compile_wide(direct_array_value_index, "answer", ObjectFormat::Coff);
        assert!(result.is_ok(), "{result:?}");

        let wrong_array_value_count = "fn identity(values: [u16; 3]) -> [u16; 3] { values } #[unsafe(no_mangle)] pub extern \"C\" fn answer(values: [u16; 2]) -> u16 { identity(values)[0] }";
        let error =
            compile_wide(wrong_array_value_count, "answer", ObjectFormat::Elf64).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::RuntimeTypeMismatch)
        );

        let wrong_array_value_element = "fn identity(values: [bool; 2]) -> [bool; 2] { values } #[unsafe(no_mangle)] pub extern \"C\" fn answer(values: [u16; 2]) -> bool { identity(values)[0] }";
        let error =
            compile_wide(wrong_array_value_element, "answer", ObjectFormat::Coff).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::RuntimeTypeMismatch)
        );

        let diverging_helper = "fn diverge(seed: u64) -> ! { let mut value: u64 = seed; loop { value += 1; } } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u64, diverges: bool) -> u64 { if diverges { diverge(value); } value + 1 }";
        let result = compile(diverging_helper, "answer", ObjectFormat::Coff);
        assert!(result.is_ok(), "{result:?}");

        let diverging_value = "fn diverge() -> ! { loop {} } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u64, diverges: bool) -> u64 { let selected: u64 = if diverges { diverge() } else { value }; selected }";
        let result = compile(diverging_value, "answer", ObjectFormat::Elf64);
        assert!(result.is_ok(), "{result:?}");

        let invalid_never_tail = "fn bad(value: u64) -> ! { 1 } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u64) -> u64 { bad(value) }";
        let error = compile(invalid_never_tail, "answer", ObjectFormat::Elf64).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::RuntimeTypeMismatch)
        );

        let tuple_helpers = "fn identity(value: (u16, bool, char)) -> (u16, bool, char) { value } fn choose(value: (u16, bool, char), alternate: (u16, bool, char), first: bool) -> (u16, bool, char) { let copy: (u16, bool, char) = identity(value); if first { return copy; } identity(alternate) } #[unsafe(no_mangle)] pub extern \"C\" fn answer(first: u16, second: u16, flag: bool, choose_first: bool) -> u64 { let selected: (u16, bool, char) = choose((first, flag, 'x'), (second, !flag, 'y'), choose_first); selected.0 as u64 + if selected.1 { 100 } else { 0 } + if selected.2 == 'x' { 10 } else { 20 } }";
        let result = compile_wide(tuple_helpers, "answer", ObjectFormat::Coff);
        assert!(result.is_ok(), "{result:?}");

        let tuple_assignment = "#[unsafe(no_mangle)] pub extern \"C\" fn answer(first: u16, second: u16, flag: bool) -> u64 { let mut selected: (u16, bool) = (first, flag); selected = (second, !flag); selected.0 as u64 + if selected.1 { 100 } else { 0 } }";
        let result = compile_wide(tuple_assignment, "answer", ObjectFormat::Elf64);
        assert!(result.is_ok(), "{result:?}");

        let singleton_and_unit = "fn identity(value: (u64,)) -> (u64,) { value } fn carry(value: ((), bool)) -> ((), bool) { value } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u64, flag: bool) -> u64 { let unit: ((), bool) = carry(((), flag)); identity((value,)).0 + if unit.1 { 1 } else { 0 } }";
        let result = compile_wide(singleton_and_unit, "answer", ObjectFormat::Coff);
        assert!(result.is_ok(), "{result:?}");

        let four_element_tuple = "#[unsafe(no_mangle)] pub extern \"C\" fn answer(first: u8, second: u16, flag: bool) -> u64 { let values: (u8, u16, bool, char) = (first, second, flag, 'z'); values.0 as u64 + values.1 as u64 + if values.2 { 1 } else { 0 } + if values.3 == 'z' { 2 } else { 0 } }";
        let result = compile_wide(four_element_tuple, "answer", ObjectFormat::Elf64);
        assert!(result.is_ok(), "{result:?}");

        let wrong_tuple_count = "fn identity(value: (u16, bool, char)) -> (u16, bool, char) { value } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u16, flag: bool) -> u16 { identity((value, flag)).0 }";
        let error = compile_wide(wrong_tuple_count, "answer", ObjectFormat::Elf64).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::RuntimeTypeMismatch)
        );

        let wrong_tuple_element = "fn identity(value: (u16, bool, char)) -> (u16, bool, char) { value } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u16) -> u16 { identity((value, value, 'x')).0 }";
        let error = compile_wide(wrong_tuple_element, "answer", ObjectFormat::Coff).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::RuntimeTypeMismatch)
        );

        let tuple_field_out_of_range = "#[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u16, flag: bool) -> u16 { let pair: (u16, bool) = (value, flag); pair.2 }";
        let error =
            compile_wide(tuple_field_out_of_range, "answer", ObjectFormat::Elf64).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::ValueOutOfRange)
        );

        let too_many_tuple_elements = "#[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u16) -> u16 { (value, false, 'x', (), value).0 }";
        let error =
            compile_wide(too_many_tuple_elements, "answer", ObjectFormat::Coff).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::Expression(
                crate::ExpressionErrorKind::TooManyTupleElements
            ))
        );

        let public_tuple_parameter = "#[unsafe(no_mangle)] pub extern \"C\" fn answer(value: (u16, bool)) -> u16 { value.0 }";
        let error = compile_wide(public_tuple_parameter, "answer", ObjectFormat::Coff).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::UnsupportedParameterType)
        );

        let public_tuple_return = "#[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u16) -> (u16, bool) { (value, true) }";
        let error = compile_wide(public_tuple_return, "answer", ObjectFormat::Elf64).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::UnsupportedReturnType)
        );

        let tuple_conditional = "fn choose(value: (u16, bool), alternate: (u16, bool), first: bool) -> (u16, bool) { if first { value } else { alternate } } #[unsafe(no_mangle)] pub extern \"C\" fn answer(first: u16, second: u16, flag: bool, choose_first: bool) -> u64 { let selected: (u16, bool) = choose((first, flag), (second, !flag), choose_first); selected.0 as u64 + if selected.1 { 100 } else { 0 } }";
        let result = compile_wide(tuple_conditional, "answer", ObjectFormat::Coff);
        assert!(result.is_ok(), "{result:?}");

        let tuple_value_loop = "fn choose(value: (u16, bool), alternate: (u16, bool), first: bool) -> (u16, bool) { loop { if first { break value; } break alternate; } } #[unsafe(no_mangle)] pub extern \"C\" fn answer(first: u16, second: u16, flag: bool, choose_first: bool) -> u64 { let selected: (u16, bool) = choose((first, flag), (second, !flag), choose_first); selected.0 as u64 + if selected.1 { 100 } else { 0 } }";
        let result = compile_wide(tuple_value_loop, "answer", ObjectFormat::Elf64);
        assert!(result.is_ok(), "{result:?}");

        let tuple_sequence = "fn bump(value: &mut u16) { *value += 1; } fn choose(value: (u16, bool), count: &mut u16) -> (u16, bool) { bump(count); value } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u16, flag: bool) -> u64 { let mut count: u16 = 0; let selected: (u16, bool) = choose({ bump(&mut count); (value, flag) }, &mut count); selected.0 as u64 + count as u64 + if selected.1 { 100 } else { 0 } }";
        let result = compile_wide(tuple_sequence, "answer", ObjectFormat::Coff);
        assert!(result.is_ok(), "{result:?}");

        let tuple_field_assignment = "#[unsafe(no_mangle)] pub extern \"C\" fn answer(first: u16, second: u16, flag: bool) -> u64 { let mut selected: (u16, bool, char) = (first, flag, 'x'); selected.0 += second; selected.1 ^= true; selected.2 = 'z'; selected.0 as u64 + if selected.1 { 100 } else { 0 } + if selected.2 == 'z' { 1 } else { 0 } }";
        let result = compile_wide(tuple_field_assignment, "answer", ObjectFormat::Elf64);
        assert!(result.is_ok(), "{result:?}");

        let immutable_tuple_field = "#[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u16) -> u16 { let selected: (u16, bool) = (value, false); selected.0 = 1; selected.0 }";
        let error = compile_wide(immutable_tuple_field, "answer", ObjectFormat::Coff).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::ImmutableAssignment)
        );

        let tuple_assignment_out_of_range = "#[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u16) -> u16 { let mut selected: (u16, bool) = (value, false); selected.2 = true; selected.0 }";
        let error =
            compile_wide(tuple_assignment_out_of_range, "answer", ObjectFormat::Elf64).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::ValueOutOfRange)
        );

        let capture = "fn bad(value: u64) -> u64 { hidden + value } #[unsafe(no_mangle)] pub extern \"C\" fn answer(hidden: u64) -> u64 { bad(1) }";
        let error = compile(capture, "answer", ObjectFormat::Elf64).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::UnknownRuntimeName)
        );

        let wrong_type = "fn choose(value: bool) -> bool { value } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u64) -> bool { choose(value) }";
        let error = compile(wrong_type, "answer", ObjectFormat::Elf64).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::RuntimeTypeMismatch)
        );

        let early_return = "fn stop(value: u64) -> u64 { let next: u64 = value + 1; if next > 10 { return next; } next * 2 } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u64) -> u64 { stop(value) }";
        assert!(compile(early_return, "answer", ObjectFormat::Elf64).is_ok());

        let boolean_return = "fn large(value: u16) -> bool { if value > 10 { return true; } false } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u16) -> bool { large(value) }";
        assert!(compile(boolean_return, "answer", ObjectFormat::Coff).is_ok());

        let conditional_actions = "fn adjust(value: u16, choose: bool) -> u64 { let mut total: u16 = value; if choose { total += 3; } else { total += 1; } total as u64 } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u16, choose: bool) -> u64 { adjust(value, choose) }";
        assert!(compile(conditional_actions, "answer", ObjectFormat::Elf64).is_ok());

        let branch_return = "fn adjust(value: u64, choose: bool) -> u64 { let mut total: u64 = value; if choose { total += 1; return total; } else { total += 2; } total } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u64, choose: bool) -> u64 { adjust(value, choose) }";
        assert!(compile(branch_return, "answer", ObjectFormat::Elf64).is_ok());

        let exhaustive_actions = "fn adjust(value: u64, choose: bool) -> u64 { let mut total: u64 = value; if choose { total += 1; return total; } else { total += 2; return total; } } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u64, choose: bool) -> u64 { adjust(value, choose) }";
        assert!(compile(exhaustive_actions, "answer", ObjectFormat::Coff).is_ok());

        let wrong_branch_return = "fn adjust(value: u64, choose: bool) -> u64 { let mut total: u64 = value; if choose { total += 1; return false; } else { total += 2; } total } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u64, choose: bool) -> u64 { adjust(value, choose) }";
        let error = compile(wrong_branch_return, "answer", ObjectFormat::Elf64).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::RuntimeTypeMismatch)
        );

        let loop_body = "fn count(value: u16) -> u64 { let mut current: u16 = 0; while current < value { current += 1; } current as u64 } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u16) -> u64 { count(value) }";
        assert!(compile(loop_body, "answer", ObjectFormat::Elf64).is_ok());

        let loop_control = "fn count(value: u64) -> u64 { let mut current: u64 = 0; while current < value { if current == 3 { break; } current += 1; } current } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u64) -> u64 { count(value) }";
        assert!(compile(loop_control, "answer", ObjectFormat::Elf64).is_ok());

        let loop_continue = "fn count(value: u64) -> u64 { let mut current: u64 = 0; while current < value { current += 1; continue; } current } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u64) -> u64 { count(value) }";
        assert!(compile(loop_continue, "answer", ObjectFormat::Coff).is_ok());

        let loop_return = "fn count(value: u64) -> u64 { let mut current: u64 = 0; while current < value { if current == 3 { return current; } current += 1; } current } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u64) -> u64 { count(value) }";
        assert!(compile(loop_return, "answer", ObjectFormat::Elf64).is_ok());

        let direct_loop_return = "fn first(value: u64) -> u64 { while value > 0 { return value + 1; } 9 } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u64) -> u64 { first(value) }";
        assert!(compile(direct_loop_return, "answer", ObjectFormat::Coff).is_ok());

        let wrong_loop_return = "fn count(value: u64) -> u64 { let mut current: u64 = 0; while current < value { if current == 3 { return false; } current += 1; } current } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u64) -> u64 { count(value) }";
        let error = compile(wrong_loop_return, "answer", ObjectFormat::Elf64).unwrap_err();
        assert_eq!(
            error.kind,
            CompileErrorKind::Codegen(CodegenErrorKind::RuntimeTypeMismatch)
        );

        let structured_loop = "fn select(value: u64, choose: bool) -> u64 { let mut total: u64 = 0; while total < value { if choose { total += 1; break; } else { total += 1; continue; } } total } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u64, choose: bool) -> u64 { select(value, choose) }";
        assert!(compile(structured_loop, "answer", ObjectFormat::Elf64).is_ok());

        let nested_loop = "fn count(value: u64) -> u64 { let mut current: u64 = 0; while current < value { while current < 3 { current += 1; } current += 1; } current } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u64) -> u64 { count(value) }";
        assert!(compile(nested_loop, "answer", ObjectFormat::Elf64).is_ok());

        let nested_unit_loop = "fn spin(value: u64) -> u64 { while value > 0 { loop {} } value } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u64) -> u64 { spin(value) }";
        assert!(compile(nested_unit_loop, "answer", ObjectFormat::Elf64).is_ok());

        let unconditional_loop = "fn spin(value: u64) -> u64 { loop {} } #[unsafe(no_mangle)] pub extern \"C\" fn answer(value: u64) -> u64 { spin(value) }";
        assert!(compile(unconditional_loop, "answer", ObjectFormat::Elf64).is_ok());
    }
}
