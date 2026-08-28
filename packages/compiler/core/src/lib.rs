#![no_std]
#![forbid(unsafe_code)]

//! The MRML-owned Rust compiler.
//!
//! This crate begins at the lexical compatibility boundary. It deliberately
//! contains no source copied from the upstream compiler or standard library;
//! its tests describe independently observed language behavior.

pub mod abi;
pub mod codegen;
pub mod expression;
pub mod ir;
pub mod lexer;
pub mod linker;
pub mod object;
pub mod parser;
pub mod pipeline;
pub mod semantics;
pub mod trait_goals;

pub use abi::{
    MrmlV1CallLocation, MrmlV1CallPlan, MrmlV1CallPlanError, MrmlV1CallValue, MrmlV1Integer,
    MrmlV1Layout, MrmlV1LayoutField, MrmlV1LayoutFieldKind, MrmlV1Pointee, MrmlV1Register,
    MrmlV1Signature, MrmlV1SignatureError, MrmlV1SignatureErrorKind, MrmlV1SignatureLocation,
    MrmlV1Target, MrmlV1Type, classify_mrml_v1_type, layout_mrml_v1_type, plan_mrml_v1_call,
    validate_mrml_v1_signature,
};
pub use codegen::{
    CodegenError, CodegenErrorKind, CodegenOptions, MAX_X86_64_EXTERNAL_RELOCATIONS,
    MAX_X86_64_READONLY_DATA_BYTES, MAX_X86_64_READONLY_RELOCATIONS, MachineCode, X86_64Abi,
    X86_64ExternalRelocation, X86_64ExternalRelocationKind, X86_64ReadonlyDataRelocation,
    X86_64RelocatableMachineCode, X86_64RuntimeMachineCode, compile_x86_64_constant_function,
    compile_x86_64_function, compile_x86_64_function_with_options,
    compile_x86_64_naked_relocatable, compile_x86_64_runtime_function_with_options,
};
pub use expression::{
    BinaryOperator, CallArrayElement, CastType, ConstEvalError, ConstantResolver, Expr, ExprId,
    ExprKind, ExpressionError, ExpressionErrorKind, ExpressionParser, ExpressionTree,
    IntegerLiteral, IntegerType, NoConstants, PointerPointee, RuntimeCallParameter,
    RuntimeCallTarget, ScalarType, UnaryOperator,
};
pub use ir::{
    ExecutionError, Instruction, IrError, IrErrorKind, IrProgram, lower_expression,
    lower_expression_with_pointer_bits,
};
pub use lexer::{LexError, LexErrorKind, Lexer, Span, Token, TokenKind};
pub use linker::{
    ArchiveMember, ArchiveMembers, ArchiveSymbol, ElfImage, ElfLinkSectionSelections,
    ElfObjectSymbolDefinition, ElfObjectSymbolInventory, ElfSectionKind, ElfSectionSelection,
    ElfSelectedDefinition, ElfSelectedDefinitions, ElfSelectedLayout, ElfSelectedLinkedImage,
    ElfSelectedObject, ElfSelectedRelocation, ElfSelectedRelocationKind,
    ElfSelectedRelocationTarget, ElfSelectedRelocations, ElfSelectedSection,
    ElfSelectedSectionLayout, ElfSelectedSections, ElfSelectedSymbolBinding, ElfSelectedSymbolKind,
    ElfSelectedSymbolVisibility, ElfUnwindData, ElfUnwindRelocation, ElfWritableAbsoluteRelocation,
    ElfWritableAbsoluteTarget, ElfWritableData, ElfWritableReference, ElfWritableTarget,
    LinkDefinition, LinkDefinitionTarget, LinkInput, LinkInputSelection, LinkRelocation,
    LinkRelocationTarget, LinkedImage, LinkerError, MAX_ARCHIVE_MEMBERS, MAX_ARCHIVE_SYMBOLS,
    MAX_LINK_DEFINITIONS, MAX_LINK_INPUTS, MAX_LINK_RELOCATIONS, MAX_PE_RUNTIME_FUNCTIONS, PeImage,
    PeRuntimeFunction, PeWritableData, PeWritableRelocation, decode_unix_archive,
    decode_x86_64_coff, decode_x86_64_coff_runtime_functions, decode_x86_64_coff_text_fragment,
    decode_x86_64_coff_with_definitions, decode_x86_64_coff_writable_data,
    decode_x86_64_coff_writable_data_fragment, decode_x86_64_elf,
    decode_x86_64_elf_selected_definitions, decode_x86_64_elf_selected_relocations,
    decode_x86_64_elf_selected_sections, decode_x86_64_elf_unwind,
    decode_x86_64_elf_with_definitions, decode_x86_64_elf_writable, inventory_x86_64_elf_symbols,
    layout_x86_64_elf_selected_sections, link_x86_64_elf_executable,
    link_x86_64_elf_executable_with_unwind, link_x86_64_elf_executable_with_unwind_and_writable,
    link_x86_64_elf_selected_executable, link_x86_64_elf_selected_sections, link_x86_64_pe,
    link_x86_64_pe_with_data_and_unwind, link_x86_64_pe_with_unwind, link_x86_64_static,
    select_ordered_static_link_inputs, select_ordered_static_link_members,
    select_static_link_inputs, select_x86_64_elf_link_sections, select_x86_64_elf_sections,
    x86_64_coff_text_fragment_count, x86_64_coff_unwind_section_count,
    x86_64_coff_writable_section_count,
};
pub use object::{
    MAX_X86_64_RELOCATIONS, ObjectError, ObjectFile, X86_64PcRelativeRelocation,
    X86_64PcRelativeRelocationKind, X86_64ReadonlyRelocation, emit_elf64_x86_64,
    emit_elf64_x86_64_with_readonly_data, emit_elf64_x86_64_with_relocation,
    emit_elf64_x86_64_with_relocations, emit_x86_64_coff, emit_x86_64_coff_with_readonly_data,
    emit_x86_64_coff_with_relocation, emit_x86_64_coff_with_relocations,
};
pub use parser::{
    Assignment, AssignmentOperator, BodyStatement, ConditionalAssignment,
    ConditionalAssignmentAction, ConditionalAssignmentBranch, ConditionalLoopAction,
    ConditionalLoopArm, ConditionalLoopBlock, ConditionalLoopControl, ConditionalLoopTerminal,
    ConditionalReturn, ConditionalReturnElse, ConstItem, ExpressionStatement, Function,
    FunctionAbi, FunctionBody, FunctionWherePredicate, Item, LocalBinding, LoopOperation,
    LoopReturn, MAX_BODY_CONDITIONAL_ASSIGNMENTS, MAX_BODY_EXPRESSION_STATEMENTS, MAX_BODY_RETURNS,
    MAX_BODY_STATEMENTS, MAX_CONDITIONAL_ASSIGNMENT_BRANCHES, MAX_CONDITIONAL_BRANCH_ACTIONS,
    MAX_CONDITIONAL_LOOP_ACTIONS, MAX_CONDITIONAL_LOOP_ELSE_ARMS, MAX_CONDITIONAL_RETURN_BRANCHES,
    MAX_FUNCTION_WHERE_PREDICATES, MAX_LOOP_OPERATIONS, MAX_NESTED_LOOP_ACTIONS,
    MAX_NESTED_LOOP_BLOCKS, MAX_NESTED_LOOP_CONDITIONAL_BREAKS,
    MAX_NESTED_LOOP_CONDITIONAL_CONTINUES, MAX_NESTED_LOOP_CONDITIONAL_ELSE_ARMS,
    MAX_NESTED_LOOP_CONDITIONAL_RETURNS, MAX_NESTED_LOOP_UNCONDITIONAL_CONTROLS,
    MAX_SOURCE_TRAIT_ARGUMENTS, MAX_TRAIT_ASSOCIATED_TYPES, MAX_TRAIT_SUPERTRAITS, Module,
    NestedLoopBlock, NestedLoopControlTarget, NestedLoopUnconditionalControl, Parameter,
    ParseError, ParseErrorKind, Parser, TraitAssociatedTypeDeclaration,
    TraitAssociatedTypeImplementation, TraitDeclaration, TraitImplementation,
    TraitImplementationWherePredicate, TraitProjectionTypeRef, TraitSupertrait, TypeRef, WhileLoop,
};
pub use pipeline::{
    CompileError, CompileErrorKind, ObjectFormat, compile_source_function,
    compile_source_function_with_options,
};
pub use semantics::{
    Constant, ConstantTable, MAX_CONST_CALL_DEPTH, MAX_CONST_FUNCTION_EXPRESSION_NODES,
    MAX_CONST_LOOP_ITERATIONS, MAX_CONSTANT_IR_INSTRUCTIONS, MAX_CONSTANT_STACK_VALUES,
    SemanticError, SemanticErrorKind, TargetLayout, analyze_constants,
};
pub use trait_goals::{
    BoundImplementedTraitGoal, BoundProjectionBearingTraitGoal, BoundTraitGoalTerm,
    BoundTraitGoalTermArena, BoundTraitGoalType, BoundTraitPredicate, BoundTraitProjection,
    CanonicalImplementedTraitGoal, CanonicalTraitGoalType, CanonicalizedImplementedTraitGoal,
    CanonicalizedImplementedTraitPredicates, ExistentialTraitGoalAnswer,
    ExistentialTraitGoalSolution, ExistsImplementedTraitGoal, ExistsProjectionBearingTraitGoal,
    ExistsTraitPredicateConjunction, ExistsTraitProjectionEquality, ForAllImplementedTraitGoal,
    GenericExistentialTraitGoalAnswer, GenericExistentialTraitGoalSolution,
    GenericTraitAssociatedTypeDatabase, GenericTraitAssociatedTypeTerm,
    GenericTraitAssociatedTypeValue, GenericTraitImplementationAnswer,
    GenericTraitImplementationDatabase, GenericTraitImplementationId,
    GenericTraitImplementationSolution, ImplementedTraitGoal, ImplementedTraitPredicates,
    InferredTraitGoalAnswer, InferredTraitGoalSolution, InferredTraitProjectionAnswer,
    InferredTraitProjectionEquality, InferredTraitProjectionPredicates,
    InferredTraitProjectionSolution, InferredTraitWhereClauseAnswer,
    InferredTraitWhereClauseSolution, InstantiatedProjectionBearingTraitGoal,
    InstantiatedTraitWhereClause, MAX_CANONICAL_TRAIT_VARIABLES, MAX_GENERIC_TRAIT_IMPLEMENTATIONS,
    MAX_SOURCE_ASSOCIATED_TYPES, MAX_SOURCE_TRAIT_DECLARATIONS, MAX_SOURCE_TRAIT_TYPES,
    MAX_TRAIT_ASSOCIATED_TYPE_VALUES, MAX_TRAIT_GENERIC_PARAMETERS, MAX_TRAIT_GOAL_ARGUMENTS,
    MAX_TRAIT_GOAL_TERMS, MAX_TRAIT_IMPLEMENTATIONS, MAX_TRAIT_PREDICATES,
    MAX_TRAIT_PROJECTION_DEPTH, MAX_TRAIT_PROOF_DEPTH, MAX_TRAIT_WHERE_CLAUSES,
    ProjectionBearingGenericTraitImplementationAnswer,
    ProjectionBearingGenericTraitImplementationDatabase,
    ProjectionBearingGenericTraitImplementationSolution, ProjectionBearingTraitClause,
    ProjectionBearingTraitClauseAnswer, ProjectionBearingTraitClauseDatabase,
    ProjectionBearingTraitClauseSolution, ProjectionBearingTraitGoal, SourceTraitAssociatedType,
    SourceTraitDeclaration, SourceTraitDeclarationError, SourceTraitDeclarationTable,
    SourceTraitImplementationError, SourceTraitImplementationErrorKind,
    SourceTraitImplementationTable, SourceTraitObligationError, SourceTraitObligationErrorKind,
    SourceTraitSupertrait, SourceTraitSupertraitArgument, SourceTraitType,
    SymbolicTraitGoalSubstitution, TraitAssociatedTypeDatabase, TraitAssociatedTypeId,
    TraitAssociatedTypeValue, TraitGenericParameterId, TraitGoalAnswer, TraitGoalError,
    TraitGoalSolution, TraitGoalSubstitution, TraitGoalTerm, TraitGoalTermArena, TraitGoalTermId,
    TraitGoalTermNormalizationAnswer, TraitGoalTermNormalizationSolution, TraitGoalType, TraitId,
    TraitImplementationDatabase, TraitImplementationHeader, TraitImplementationId,
    TraitInferenceBinding, TraitInferenceVariableId, TraitPlaceholder, TraitPlaceholderId,
    TraitProjectionSolution, TraitProofSolution, TraitTypeId, TraitUniverseAssignment,
    TraitUniverseIndex, TraitWhereClause, TraitWhereClauseAnswer, TraitWhereClauseDatabase,
    TraitWhereClauseElaboration, TraitWhereClauseId, TraitWhereClauseSolution,
    canonicalize_implemented_trait_goal, canonicalize_implemented_trait_goal_with_variables,
    canonicalize_implemented_trait_predicates, generic_trait_implementation_heads_overlap,
    generic_trait_implementation_overlaps_exact, normalize_concrete_trait_projection,
    normalize_inferred_trait_goal_term, solve_concrete_trait_goal,
    solve_concrete_trait_goal_with_generics, solve_exists_projection_bearing_trait_goal,
    solve_exists_trait_goal_exact, solve_exists_trait_goal_generic,
    solve_exists_trait_goal_with_environment, solve_exists_trait_goal_with_generics,
    solve_exists_trait_goal_with_projection_clauses,
    solve_exists_trait_goal_with_projection_environment,
    solve_exists_trait_goal_with_projection_implementations,
    solve_exists_trait_predicate_conjunction, solve_exists_trait_projection_equality,
    solve_for_all_trait_goal_with_generics, solve_projection_bearing_trait_goal,
    solve_rigid_trait_goal, solve_rigid_trait_goal_with_generics,
};
