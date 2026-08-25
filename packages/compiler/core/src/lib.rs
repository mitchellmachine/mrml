#![no_std]
#![forbid(unsafe_code)]

//! The MRML-owned Rust compiler.
//!
//! This crate begins at the lexical compatibility boundary. It deliberately
//! contains no source copied from the upstream compiler or standard library;
//! its tests describe independently observed language behavior.

pub mod codegen;
pub mod expression;
pub mod ir;
pub mod lexer;
pub mod object;
pub mod parser;
pub mod pipeline;
pub mod semantics;
pub mod trait_goals;

pub use codegen::{
    CodegenError, CodegenErrorKind, CodegenOptions, MachineCode, X86_64Abi,
    compile_x86_64_constant_function, compile_x86_64_function,
    compile_x86_64_function_with_options,
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
pub use object::{ObjectError, ObjectFile, emit_elf64_x86_64, emit_x86_64_coff};
pub use parser::{
    Assignment, AssignmentOperator, BodyStatement, ConditionalAssignment,
    ConditionalAssignmentAction, ConditionalAssignmentBranch, ConditionalLoopAction,
    ConditionalLoopArm, ConditionalLoopBlock, ConditionalLoopControl, ConditionalLoopTerminal,
    ConditionalReturn, ConditionalReturnElse, ConstItem, ExpressionStatement, Function,
    FunctionAbi, FunctionBody, Item, LocalBinding, LoopOperation, LoopReturn,
    MAX_BODY_CONDITIONAL_ASSIGNMENTS, MAX_BODY_EXPRESSION_STATEMENTS, MAX_BODY_RETURNS,
    MAX_BODY_STATEMENTS, MAX_CONDITIONAL_ASSIGNMENT_BRANCHES, MAX_CONDITIONAL_BRANCH_ACTIONS,
    MAX_CONDITIONAL_LOOP_ACTIONS, MAX_CONDITIONAL_LOOP_ELSE_ARMS, MAX_CONDITIONAL_RETURN_BRANCHES,
    MAX_LOOP_OPERATIONS, MAX_NESTED_LOOP_ACTIONS, MAX_NESTED_LOOP_BLOCKS,
    MAX_NESTED_LOOP_CONDITIONAL_BREAKS, MAX_NESTED_LOOP_CONDITIONAL_CONTINUES,
    MAX_NESTED_LOOP_CONDITIONAL_RETURNS, MAX_NESTED_LOOP_UNCONDITIONAL_CONTROLS, Module,
    NestedLoopBlock, NestedLoopControlTarget, NestedLoopUnconditionalControl, Parameter,
    ParseError, ParseErrorKind, Parser, TypeRef, WhileLoop,
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
    MAX_TRAIT_ASSOCIATED_TYPE_VALUES, MAX_TRAIT_GENERIC_PARAMETERS, MAX_TRAIT_GOAL_ARGUMENTS,
    MAX_TRAIT_GOAL_TERMS, MAX_TRAIT_IMPLEMENTATIONS, MAX_TRAIT_PREDICATES,
    MAX_TRAIT_PROJECTION_DEPTH, MAX_TRAIT_PROOF_DEPTH, MAX_TRAIT_WHERE_CLAUSES,
    ProjectionBearingTraitClause, ProjectionBearingTraitClauseAnswer,
    ProjectionBearingTraitClauseDatabase, ProjectionBearingTraitClauseSolution,
    ProjectionBearingTraitGoal, SymbolicTraitGoalSubstitution, TraitAssociatedTypeDatabase,
    TraitAssociatedTypeId, TraitAssociatedTypeValue, TraitGenericParameterId, TraitGoalAnswer,
    TraitGoalError, TraitGoalSolution, TraitGoalSubstitution, TraitGoalTerm, TraitGoalTermArena,
    TraitGoalTermId, TraitGoalTermNormalizationAnswer, TraitGoalTermNormalizationSolution,
    TraitGoalType, TraitId, TraitImplementationDatabase, TraitImplementationHeader,
    TraitImplementationId, TraitInferenceBinding, TraitInferenceVariableId, TraitPlaceholder,
    TraitPlaceholderId, TraitProjectionSolution, TraitProofSolution, TraitTypeId,
    TraitUniverseAssignment, TraitUniverseIndex, TraitWhereClause, TraitWhereClauseAnswer,
    TraitWhereClauseDatabase, TraitWhereClauseElaboration, TraitWhereClauseId,
    TraitWhereClauseSolution, canonicalize_implemented_trait_goal,
    canonicalize_implemented_trait_goal_with_variables, canonicalize_implemented_trait_predicates,
    generic_trait_implementation_heads_overlap, generic_trait_implementation_overlaps_exact,
    normalize_concrete_trait_projection, normalize_inferred_trait_goal_term,
    solve_concrete_trait_goal, solve_concrete_trait_goal_with_generics,
    solve_exists_projection_bearing_trait_goal, solve_exists_trait_goal_exact,
    solve_exists_trait_goal_generic, solve_exists_trait_goal_with_environment,
    solve_exists_trait_goal_with_generics, solve_exists_trait_goal_with_projection_environment,
    solve_exists_trait_predicate_conjunction, solve_exists_trait_projection_equality,
    solve_for_all_trait_goal_with_generics, solve_projection_bearing_trait_goal,
    solve_rigid_trait_goal, solve_rigid_trait_goal_with_generics,
};
