# MRML Rust compiler

`mrml-rustc` is an original, dependency-free Rust compiler implementation for
MRML. It is being bootstrapped against the observable behavior of the pinned
Rust nightly while remaining suitable for MRML's `no_std`, no-global-`alloc`
environment.

Current repository builds and tests use `mrml build` and `mrml test`; Cargo is
reserved for the locked stage-zero `mrml` frontend. Cargo command blocks later
in this file are dated historical oracle evidence, not current contributor
instructions.

The long-term target is contemporary and forward-looking Rust semantics with
MRML-specific security and systems integration. Rust 2024 is the floor, not the
destination. The compiler does not promise Rust 2015/2018/2021, every stable or
nightly release, historical unsoundness, rustc implementation quirks,
diagnostic wording, or unstable Rust ABI/symbol compatibility. It remains a
Rust compiler and must not deliberately break modern Rust merely to diverge.
The normative feature classifications, Polonius and trait-solver prerequisites,
security profiles, gap matrix, and priority rules are in
[`docs/COMPILER.md`](../../docs/COMPILER.md).

The initial reference compiler is `rustc 1.100.0-nightly`, commit
`f7d782a3be46d6bb4b9792fe69a61db389ba1769` (2026-08-19). The rustup `rust-src`
component does not contain the rustc compiler suites, so the matching official
`rust-lang/rust` commit is the test source of truth. Its durable generation
record is [`ORACLE-0001`](../../docs/compiler/oracles/ORACLE-0001.md).
Consequently:

- `tests/conformance.rs` records original black-box language observations used
  to bootstrap and later regression-test the MRML compiler.
- `tests/rustc_nightly_replacements.rs` maps original executable MRML probes to
  exact files in the pinned rustc UI and LLVM-codegen suites. The first slice
  covers unsigned arithmetic, division/remainder, shifts, platform-width bit
  operations, overflow checks, and x86-64 ABI boundaries.
- Unit tests beside compiler modules test bounded internal behavior.
- No upstream Rust source or test text is copied into this crate.
- The current upstream nightly is only the stage-zero oracle. Each test must
  eventually run through an MRML-owned parser, type checker, lowering pipeline,
  code generator, and test runner.

An oracle generation is exact and reproducible; whichever nightly is installed
today is not a substitute. Future generations retain earlier metadata, rerun
the corpus against both versions, classify semantic differences, and update
MRML behavior only deliberately. Modern successor semantics take priority over
legacy behavior unless current MRML source or a required probe depends on it.
Unsupported borrowing, traits, provenance, unsafe behavior, ABI, assembly,
const evaluation, control flow, and security metadata continue to fail closed.

The implemented bootstrap grammar currently recognizes module-level `fn`, `const fn`,
typed `const`, immutable typed `static`, bounded `trait Name { type Item; }`, and exact
`impl Trait for Type { type Item = Value; }` items, optional `pub`, named typed parameters, optional return
types, up to eight concrete `where Type: Trait` predicates, nested generic and
tuple/array type syntax, balanced function bodies, and
bounded constant initializers. Function bodies additionally parse a bounded
prefix of typed or inferred `let` bindings, including `let mut`, followed by bounded simple
or compound assignment statements, up to eight conditional-action
statements, conditional-return statements, up to eight
standalone value-return statements, up to eight scalar expression statements,
and one tail expression. Empty `;` statements
occupy the same bounded stream as explicit no-ops. Expression results are
discarded only after their lazy or checked evaluation completes, and statements
may interleave with locals and assignments before or after a loop sequence. The
AST borrows source text and uses
caller-selected fixed item and parameter capacities; nesting is capped at 64
delimiters. Capacity and malformed-input failures carry bounded source spans.
Runtime emission additionally retains fixed tables of at most 256 monotonic
local facts and 256 source-ordered runtime place-access facts. Scope cleanup may
reuse stack storage but cannot reuse semantic local identity. Assignment facts
retain the resolved local or parameter identity, parsed projection, type,
source span, and whether the operation is a plain write or read-modify-write.
Runtime identifier loads append `Read` facts for the same stable base identity,
including specialized tuple, array, range, and address paths that do not use the
ordinary scalar loader. Constants do not become local/parameter access facts.
Persistent facts use a source-independent list of at most four `Dereference`,
summary `Index`, exact `ArrayElement`, `TupleField`, or `Subslice` projections rather than borrowing the
assignment parser representation. Assignment facts translate their existing
single projection into that list. An in-bounds constant index on a directly
owned fixed-array local or parameter retains its exact element number, while
runtime indexes, reference/slice indexes, compound bases, and aggregate
materialization retain the conservative summary `Index`. Specialized local
tuple-field, array-element, and local-array range reads retain their
corresponding projection. Each
projection is validated against the type produced by the preceding step, and
overflow fails with `TooManyRuntimePlaceProjections`.
Final emission validates their identity, projection/type, and mutability
invariants and fails explicitly on capacity exhaustion or inconsistent facts.
These ephemeral place-access tables are groundwork for typed ownership and CFG
analysis. Bounded move, borrow, and initializedness facts now exist, and direct
reference-local initialization can derive a stable issuance identity from the
matching same-origin borrow effect without another fixed arena. General loan
liveness, conflicts, invalidation, regions, and complete nested place discovery
remain unimplemented.

Conditional action blocks retain up to four source-ordered local declarations,
assignments, discarded scalar expressions, or value returns in each selected
`if`, `else if`, or `else` arm. Branch locals may shadow enclosing locals, are
visible to later actions in the same arm, and are removed at the arm's native
fallthrough edge and from the const evaluator before subsequent statements.
They cannot leak into another arm or the enclosing function body. Assignments
reuse the ordinary mutability, width, type, and operator checks. Conditions must
be Boolean and only the selected arm is evaluated. The fixed conditional-action
arena holds eight records independently of the top-level local-binding capacity.
Exhausting the shared runtime-local arena fails with `TooManyRuntimeLocals`
before indexing or emitting an object.

Standalone `return value;` statements retain their position among declarations,
mutations, loops, and discarded expressions. Runtime emission checks the value
against the declared return type and restores the complete native stack frame
before returning. Later unreachable source remains parsed and type-checked.
Bounded const-function evaluation terminates immediately with the returned
integer or Boolean value. The original replacement is mapped to pinned nightly
`tests/ui/liveness/var-defined-after-early-return.rs`; no upstream test text is
copied.
Valueless `return;` uses the same fixed record with an explicit unit value. It
works as a top-level statement and as a conditional or unconditional loop
operation, and returning unit from an integer function is rejected. The
original loop replacement maps to pinned nightly
`tests/ui/codegen/issue-88043-bb-does-not-have-terminator.rs`.

The expression layer uses a fixed-capacity AST arena and implements Rust's
precedence ordering for unary operations and the arithmetic, shift, comparison,
bitwise, and short-circuit logical binary operators. It decodes decimal, binary,
octal, and hexadecimal integer tokens with the built-in integer suffix names.
Its current constant evaluator uses a `u128` bit representation for layout-like
expressions: it checks overflow, division by zero, and shift ranges, and resolves
names through a caller-supplied trait without allocation. Built-in integer `as`
casts carry explicit signedness and width, including an IR-selected pointer
width. It is not yet Rust's complete type-directed constant evaluator;
references, aggregates, and unrestricted const function calls remain
unsupported.
Bounded `if condition { expression } else { expression }` values are represented
directly in the expression arena. Conditions must be Boolean and both branches
must have compatible types. Direct evaluation, lowered IR, and native code all
select only the taken branch; malformed delimiters and missing `else` clauses
produce bounded diagnostics.
Scalar block expressions `{ expression }` transparently retain the inner value
and type without consuming another arena node. Empty `{}` blocks produce the
existing unit value. Blocks nest under the same depth bound and work in
constants, conditions, branches, locals, return values, IR, and native code;
statement-bearing blocks reuse the same scoped parser as conditional branches.
They may introduce four typed or inferred scalar bindings, perform eight
assignments, interleave eight expression statements, shadow outer names, and
produce either an explicit tail value or implicit unit. Their names do not leak
past the closing brace, while enclosing runtime identifiers remain available.
Scalar inline const blocks `const { expression }` and `const {}` retain a
distinct fixed-arena AST boundary while using the same value, type, IR, and
native-code paths. Prior module constants resolve inside that boundary. Runtime
parameters and locals are rejected rather than captured, including during
bounded const-function evaluation. An inline const used as a module-constant
initializer may call the existing bounded prior scalar `const fn` subset,
including Boolean results. Closed zero-argument prior Rust `const fn` calls are
also folded when used directly in a runtime function, with their integer or
Boolean type retained through IR and native emission. Up to four closed scalar
arguments are evaluated in source order, range-checked and normalized against
the callee's declared integer or Boolean parameter types, then bound in the
existing fixed-capacity const evaluator. Arguments that depend on runtime
parameters or locals remain rejected. Inline const blocks additionally accept
up to four source-ordered scalar `let` statements followed by a value
expression. Bindings may be inferred or explicitly annotated with a supported
integer or Boolean scalar type. An explicit ascription is retained as its own
checked expression node rather than treated as a truncating cast, and each
subsequent assignment retains that declared type. Bindings may be mutable; up
to eight direct or arithmetic,
remainder, shift, and bitwise compound assignments create successive checked
expression versions in source order. Immutable targets are rejected. Bindings
are substituted only within their current inline boundary, so nested inline
consts cannot capture them; dependent bindings retain declaration order. Let
declarations may also follow assignments, so mutation, later declarations,
and scalar shadowing are folded in source order under the same four-binding
and eight-assignment limits. Up to eight scalar expression statements may be
interleaved with those declarations and mutations. An explicit sequence node
evaluates each statement in lexical order, discards only its completed value,
and retains compile-time failures before evaluating the tail. Lowered IR uses
an explicit checked stack pop for the same boundary. Non-scalar annotations,
general control-flow statements, and items inside inline const remain separate
work. A trailing semicolon after any supported statement sequence supplies an
implicit unit tail, including after declarations and mutations. `return`,
`break`, and `continue` do not cross the inline-const boundary and fail closed.
Scalar branch blocks accept up to eight expression statements and an implicit
unit tail. Consequently an `if` without `else` is accepted only when its then
branch is unit-valued; a value tail is rejected rather than silently discarded.
The conditional retains lazy evaluation through direct folding, IR, and native
emission.
Each scalar conditional branch may also introduce its own four bounded typed or
inferred bindings, apply up to eight assignments, and interleave expression
statements. Branch-local substitution preserves shadowing and does not leak a
name into the enclosing inline block. Outer closed bindings remain visible in
branch initializers, and untaken initializers remain unevaluated.
Rust `else if` spelling is represented as a nested bounded conditional rather
than flattened or eagerly selected. Every link retains its own scoped branch
budgets, type checks, and lazy alternatives under the common expression-depth
limit. A final no-`else` link remains restricted to a unit-valued branch.
Bounded scalar `match` expressions accept up to eight source-ordered integer,
Boolean, signed-integer, or named constant patterns. A final `_` fallback is
required unless fixed-capacity coverage analysis proves both Boolean literals
are covered by unguarded arms or finds an unguarded irrefutable scalar binding
or wildcard alternative. In a proven match, the final arm becomes the lowering
default without synthesizing an unreachable expression. Guards never count
toward coverage, and incomplete supported matches produce
`NonExhaustiveMatch`. Integer patterns may also be inclusive `start..=end` or exclusive
`start..end` ranges with literal, signed, or named constant bounds. Ranges lower
to typed lower/upper comparisons. Open-ended `start..`, `..end`, and `..=end`
integer patterns use the corresponding single comparison; a completely
unbounded `..` arm is rejected rather than conflated with `_`. Each arm may
join up to four exact or range patterns with `|`; their conditions short-circuit
in source order. Top-level scalar alternatives may be grouped in recursively
nested parentheses or begin with `|`; groups flatten into the same bounded
four-alternative representation and therefore cannot bypass its capacity or
expression-depth limits. An optional Boolean `if` guard executes only after at
least one alternative matches; a false guard continues to the next arm. The combined
condition then enters the existing lazy conditional representation. Only the
first matching, guard-accepting arm executes through direct evaluation, IR, and
native code. Any arm may use a scoped scalar statement block, and the comma
after such a block arm is optional as in Rust. Character literals are a
distinct scalar type rather than integer aliases. ASCII, standard escaped,
two-digit hexadecimal, and validated Unicode-scalar spellings work in exact,
alternative, and bounded character range patterns; invalid Unicode scalar
values are rejected. A lowercase scalar identifier may bind an entire
scrutinee for one arm; the binding is substituted only into that arm's guard
and body, and successive irrefutable bindings retain source-ordered guard
fallthrough. Uppercase identifiers remain named constant patterns. Binding
alternatives require the same binding name in every branch. Guarded `_` arms
may appear before the required final unguarded
fallback; they participate in the same source-ordered, lazy guard selection,
and a match containing only the final `_` is valid. A scalar `name @ pattern`
may bind an exact, range, character, or wildcard subpattern and exposes the
scrutinee only to that arm's guard and body. Non-identifier left sides, nested
`@`, and inconsistent alternatives are rejected. Scalar `|` alternatives may
each bind the same name, including exact and range `@` patterns; a missing or
differently named binding produces a dedicated diagnostic before lowering.
Parenthesized alternatives inside a scalar `name @ (...)` subpattern flatten
into individually bound alternatives, so the same name is available in the
guard and body regardless of which exact, range, or wildcard branch matched.
Nested `@` bindings within such a group fail closed. Floating-point ranges,
binding modes, aggregate destructuring, and matches beyond eight non-fallback
arms remain separate work. Exhaustiveness for integer or character ranges,
named constants, and aggregates also remains separate type-aware work. Literal range
ordering is validated during parsing; named
integer endpoints retain one of thirty-two fixed-capacity validation records and
are checked after constant resolution with their declared signedness and target
pointer width. Reversed inclusive ranges and empty or reversed exclusive ranges
produce `InvalidRangeBounds`, while a one-value inclusive range remains valid.
The ordering check handles unsigned, signed, and character literals without
conflating their representations. Literal or named Boolean ranges are rejected
with `InvalidRangeType` rather than inheriting MRML's separately supported
Boolean comparison operators. The same metadata retains the scrutinee and both
closed or open endpoints, allowing code generation to reject a literal outside
the matched `u8` through `u64`, `i8` through `i64`, or 64-bit pointer-sized
integer type with `RangeEndpointOutOfRange` before emitting partial code.
An immediate value-producing loop expression of the form
`loop { break expression; }` is represented in the same fixed-capacity arena.
Its operand retains its integer or Boolean type through direct evaluation, IR
lowering, local initialization, and native emission. Up to four source-ordered
`if condition { break value; }` exits may precede the required fallback break.
The same exits may use a structured `if`/`else if`/`else` chain, matching the
scalar control-flow shape in the pinned `loop-break-value.rs` oracle. Every
condition must be Boolean, all five possible values unify to one type, and only
the selected operand is evaluated. These forms accept one
lifetime-style loop label and matching labeled breaks; missing colons, unknown
break labels, and a fifth conditional exit fail with dedicated expression
diagnostics. General iterating loop expressions, larger break-value graphs,
coercion and truly diverging nested loops remain separate work. A directly
nested labeled loop may use up to four conditional breaks targeting its
enclosing value loop, then complete through its own typed break before an outer
fallback. The inner completion value is evaluated and discarded rather than
unified with the outer exits; wrong-level targets receive
`InvalidLoopBreakTarget`. A Boolean inner value and `u32` outer values emitted
148-byte COFF and 544-byte ELF64 objects whose callers passed both the direct
outer exit and inner-completion/fallback paths. A terminating labeled value
loop may also be the operand of an enclosing labeled break, preserving both
labels, the inner value's type, and lazy inner alternatives through evaluation,
IR, and native code. Its original probe emitted 139-byte COFF and 536-byte ELF64
objects and passed zero, ordinary, and million-valued inputs through independent
native callers. The two pinned forms whose `while` condition itself is an
unconditional labeled `break` are also represented: a unit break can terminate
the current inner `while` before an outer fallback, while a valued break can
exit the enclosing value loop. The unreachable body is consumed with bounded,
balanced-brace scanning and is never evaluated; a non-unit value targeting the
inner `while` is rejected with `InvalidLoopBreakTarget`. Their combined probe
emitted 93-byte COFF and 488-byte ELF64 objects and returned 690 through
independent nightly-built callers on Windows gnullvm and Arch Linux WSL. Both
bodies contain division by zero, so executing either unreachable edge would
trap. Up to five source-ordered immediate breaks may also occupy the same value
loop. A constant-true internal edge preserves the first unconditional result
while retaining later unreachable operands for ordinary branch type checking;
the sixth break fails with `TooManyLoopBreakBranches`. This covers the pinned
unit pairs `break (); break;` and `break; break ();` without discarding their
second operands. Their combined probe emitted 169-byte COFF and 560-byte ELF64
objects and returned 42 through independent Windows gnullvm and Arch Linux WSL
callers. A separate regression rejects an unreachable Boolean value after an
integer break, and a trapping later integer operand remains unevaluated. An
associated `Default::default()` expression now retains an unresolved default
type until a scalar unit, integer, or Boolean context is available. It lowers
to the corresponding zero representation; an unconstrained inferred local is
rejected rather than silently choosing a type, and malformed method names or
arguments fail during parsing. Nested unlabeled `break` operands share their
single terminating semicolon with the enclosing break, while a value
immediately before the closing brace accepts Rust's semicolonless tail form.
Together these features
cover the oracle's three remaining scalar unit/default shapes, including
`break break Default::default()` and a break whose operand is an `if` with a
nested valueless break. Their combined probe emitted 207-byte COFF and 600-byte
ELF64 objects and returned 42 through independent Windows gnullvm and Arch
Linux WSL callers. Unconstrained aggregate defaults and general trait method
dispatch remain outside this scalar implementation. An original labeled
four-guard probe and
its structured-alternative counterpart each emitted
deterministic 407-byte COFF and 800-byte ELF64 objects. Independent
pinned-nightly callers selected every exit, covered signed results, and passed
a selected zero input that would trap if fallback division were evaluated.
Fixed-size scalar array literals now retain up to sixteen homogeneous elements in
the fixed expression arena, accept a trailing comma, and support constant or
runtime `usize` postfix indexes. Array construction evaluates every element in
source order before indexing, while an enclosing conditional array expression
still evaluates only its selected arm. A compile-time out-of-bounds index or a
seventeenth element fails with a bounded error; runtime out-of-bounds indexes reach
`UD2`. Runtime typing preserves the element type and length, rejects mixed
scalar element types, and rejects non-`usize` variable indexes. Index extraction
lowers through IR and native code without representing the aggregate as a
packed integer. The pinned `loop-break-value.rs` array literals therefore have
an original scalar-index replacement: its 93-byte COFF and 488-byte ELF64
objects returned the middle value `3` through independent Windows gnullvm and
Arch Linux WSL callers. Array-valued conditional loop-break branches now also
unify a `Default::default()` arm with a same-length fixed scalar array arm.
Scalar repeat literals `[expression; length]` accept an unsuffixed or `usize`
literal length up to sixteen and reuse the same fixed-array typing,
indexing, local storage, and mutation paths. Other integer suffixes and a
seventeenth element are rejected before lowering. An original bounded replacement covers
the first repeat-and-mutate shape from pinned nightly
`tests/ui/array-slice-vec/mutability-inherits-through-fixed-length-vec.rs`;
iteration over array references remains outside this slice. The exact pinned
run-pass test compiled and ran unchanged on both hosts. Repeat operands have a
distinct expression representation and are evaluated exactly once before their
value is copied, including when the length is zero. The pinned intentional
failure `tests/ui/array-slice-vec/eval-empty-array-expr.rs` printed its expected
panic on both hosts. MRML's zero-length division replacement emitted 131-byte
COFF and 528-byte ELF64 objects; an independent Linux call with a zero divisor
terminated with `SIGILL`. The bounded repeat-and-mutate replacement emitted
438-byte COFF and 832-byte ELF64 objects after single-evaluation materialization;
independent callers observed 5, 35, and 3,000,005 for zero, ordinary, and
million-valued inputs on Windows gnullvm and Arch Linux WSL.
Constant indexing preserves conditional-arm laziness, including a trapping
element in an unselected array arm, and materializes a selected default element
as zero. A combined probe covering both branch orders and a semicolonless tail
`break` emitted
93-byte COFF and 488-byte ELF64 objects; independent pinned-nightly callers on
both hosts observed 43. Immutable fixed-array locals now retain their up to
sixteen scalar elements in contiguous stack backing. One-, two-, and four-byte
elements are packed into their native layout; eight-byte elements occupy one
slot apiece. Both explicit
`[scalar; N]` annotations and inferred literal types are accepted, including a
typed contextual default or loop-break array initializer. Constant indexes load
the selected slot while preserving parameter offsets, surrounding scalar
locals, scoped cleanup, and both native ABIs. A contextual loop-array probe
emitted 208-byte COFF and 600-byte ELF64 objects; independent pinned-nightly
callers observed 14 for its default path and 41 for its selected path on both
hosts. Runtime indexes evaluate once and dispatch across the bounded temporary
or local slots. A conditional-array probe emitted 352-byte COFF and 744-byte
ELF64 objects; independent callers observed 42, 42, 13, and 99 across both arms
and three indexes, including a zero divisor hidden in the unselected arm. An
out-of-bounds Linux call terminated with `SIGILL`. Mutable fixed-array locals
also support whole-array `=` assignment. The complete right-hand array is
materialized before any destination slot is overwritten, so self-referential
permutations retain Rust's value semantics; assignment from either conditional
branch follows the same path. Compound aggregate assignment is rejected. A
probe that permuted `[13, 42, 99]`, retained a following scalar local, and then
used a runtime index emitted 373-byte COFF and 768-byte ELF64 objects;
independent callers observed 100, 14, and 43 on both hosts. Indexed element
assignment now accepts constant or runtime `usize` indexes and all scalar
assignment operators supported by the element type. The index is evaluated
once before the right-hand side, compound assignment loads and updates the
selected element, a constant out-of-bounds target is rejected, and a runtime
out-of-bounds store reaches `UD2`. A mutable-array
compound-assignment probe emitted 452-byte COFF and 848-byte ELF64 objects;
independent callers observed 24, 48, and 101 across all three elements on
Windows gnullvm and Arch Linux WSL. Out-of-bounds calls terminated with
illegal-instruction status `0xC000001D` on Windows and `SIGILL` on Linux.
One-element fixed scalar array parameters now use the shared one-eightbyte
x86-64 ABI class. Integer, Boolean, and character elements retain their scalar
normalization through direct indexing and copies into fixed-array locals on
both Windows and System V. The exact pinned nightly
`tests/ui/consts/const_let_eq.rs` compiled and ran unchanged on both hosts. An
original `const fn` replacement emitted 128-byte COFF and 520-byte ELF64
objects; independent pinned-nightly callers passed `[0]`, `[13]`, and
`[1_000_000]` with following scalar arguments. Two-to-sixteen-element 64-bit
integer arrays additionally follow their platform ABI classes: Windows copies
elements from the caller-provided indirect argument, while System V consumes a
two-eightbyte array from registers when both are available and otherwise rolls
the whole aggregate back to its by-value stack area. Larger arrays use that
stack area directly. Following scalar arguments retain their independent
register allocation. The exact pinned nightly
`tests/ui/array-slice-vec/copy-out-of-array-1.rs` compiled and ran unchanged on
both hosts. Independent two-word probes emitted 216-byte COFF and 600-byte ELF64
objects; three-word indirect/by-value probes emitted 244-byte COFF and 640-byte
ELF64 objects. A register-exhaustion probe placed a two-word array pointer in a
Windows stack argument and rolled the same array back to the System V stack
while retaining the following sixth integer register; its 459-byte COFF and
840-byte ELF64 objects produced 204 and 120 on both hosts. Fixed-array returns
use the corresponding result classes: one scalar element returns in `RAX`, a
two-word System V array returns in `RAX`/`RDX`, and Windows multiword or System V
three-to-sixteen-word arrays use a preserved hidden result pointer while shifting
ordinary parameters to their ABI-defined locations. Tail values, explicit
returns, and conditional returns share the same materialization path. The exact
pinned nightly `tests/ui/parser/block-expr-statement-vs-expr.rs` compiled and ran
unchanged on both hosts. Independent one-, two-, and three-word return probes
emitted 137-, 167-, and 168-byte COFF objects and 528-, 544-, and 552-byte ELF64
objects; pinned-nightly callers observed `[42]`, `[13, 14]`, and `[13, 42, 99]`
on both hosts. Narrow integer, Boolean, and character arrays use their compact
one-, two-, or four-byte element layout at the ABI boundary and in fixed-array
local backing. Array-expression temporaries remain independently auditable
until local initialization packs them after left-to-right evaluation. Windows packs total sizes of one,
two, four, or eight bytes into a direct integer argument/result and otherwise
uses its indirect aggregate class. System V packs up to two eightbytes into
registers and rolls the complete value back to its stack class when necessary.
The exact pinned nightly `tests/ui/array-slice-vec/vec-fixed-length.rs` compiled
and ran unchanged on both hosts. Independent mutate-and-return callers passed a
four-byte `[u8; 4]`, a ten-byte `[u16; 5]`, and a three-byte `[bool; 3]` on both
ABIs. Their COFF objects were 553, 608, and 411 bytes; their ELF64 objects were
944, 1,048, and 824 bytes. Zero-length arrays and arrays of unit elements now
follow their zero-sized ABI classes without transporting result bytes. System V
omits zero-sized arguments from register allocation, while Windows preserves
their positional argument slots; later scalar arguments therefore arrive in
the same locations as pinned nightly on each platform. Array expressions still
evaluate normally, and unit elements retain their auditable internal slots.
Independent callers passed zero-length and three-unit parameters between scalar
arguments and consumed both zero-sized return forms on both hosts. The four
COFF objects were 195, 201, 99, and 119 bytes; their ELF64 counterparts were
584, 592, 488, and 512 bytes. Whole-array `Default::default()` values acquire
their fixed array type from returns and typed locals, then use the same direct
or indirect ABI materialization as explicit literals. A conditional `[u16; 5]`
default-return probe emitted 439-byte COFF and 856-byte ELF64 objects;
independent callers observed both the all-zero default and the explicitly
initialized alternative on both hosts. The fixed-array arena, runtime indexes,
locals, assignments, parameter classes, and return classes now share a
sixteen-element bound. Array cleanup switches to a 32-bit stack adjustment at
the exact 128-byte boundary. An independent `[u8; 16]` caller exercised
parameter transport, a copied mutable local, last-element assignment, and
return transport on both ABIs; the resulting objects were 1,602-byte COFF and
2,184-byte ELF64. Immutable references to supported integer scalars, `bool`,
and `char` now use a typed thin-pointer runtime representation. Reference
parameters occupy their ordinary pointer-sized ABI slot, inferred locals can
copy the pointer without truncation, and unary `*` emits width- and
signedness-correct pointee loads. Independent callers observed 42 through a
copied `&u64` between surrounding scalar arguments, preserved `-1234i16`, and
loaded `true` plus crab emoji `char` values on both hosts. The four COFF objects
were 156, 111, 111, and 110 bytes; their ELF64 counterparts were 544, 496, 504,
and 504 bytes. Explicitly typed scalar-reference locals preserve the same
pointer identity. `&mut T` parameters and typed locals share that representation
for dereference and scalar pointee mutation. Plain and compound assignments
store through mutable references with the pointee's exact integer, Boolean, or
character width; immutable references reject stores. Independent callers
mutated `40u64` to 42 and observed both the returned value and changed memory
through 156-byte COFF and 544-byte ELF64 objects. Defaults without a
constraining type remain separate work. Scalar locals and saved scalar
parameters now support shared address-taking, mutable locals support mutable
address-taking, and existing scalar references support `&*value` and
`&mut *value` reborrows with mutability checks. An independent caller used a
mutable local reference and then a mutable reborrow to change external memory
from 40 to 42 through 199-byte COFF and 584-byte ELF64 objects. Thin shared or
mutable scalar and fixed-array references may also be function results. Tail
values, typed local copies, and reborrows return the original pointer in `RAX`;
`&mut T` coerces one-way to `&T`, while the reverse conversion is rejected.
Independent callers preserved identity for `&u16` and `&[u8; 4]` and changed
`40i32` to 42 through a returned `&mut i32`. Their COFF objects were 110, 109,
and 108 bytes and their ELF64 objects were each 504 bytes; the shared coercion
object was 111-byte COFF and 504-byte ELF64. Shared and mutable slice references
may also be function results. Windows returns their data pointer and length
through hidden two-word result storage, while System V returns the pair in
`RAX` and `RDX`. Independent callers preserved full-slice identity and length,
returned a mutable subrange at the expected offset, and changed its backing
array through 147-byte and 238-byte COFF objects plus 520-byte and 616-byte
ELF64 objects. Shared and mutable references may target indexed elements of
fixed-array references, slice references, and fixed-array locals. Runtime
indexes are evaluated once and checked before the element address is formed;
mutable access requires mutable backing. Independent callers observed exact
element-pointer offsets, changed a slice element through a returned reference,
and mutated then reread a local-array element through 166-byte, 170-byte, and
399-byte COFF objects plus 552-byte, 560-byte, and 792-byte ELF64 objects. An
index equal to the slice length reached Windows `0xC000001D` and Linux
`SIGILL`. Aggregate reference parameters now include fixed arrays up to
sixteen elements. Conditional tail expressions may select shared or mutable
slice results, including subranges with different data offsets and lengths.
Independent callers selected both branches of a 360-byte COFF and 720-byte
ELF64 object and observed the exact first-element and trailing-slice fat
pointers. Conditional slice values may also initialize typed or inferred
locals; both words remain available to later returns, `len()`, indexing, and
mutation. Independent callers exercised both local-selection branches through
330-byte and 461-byte COFF objects plus 704-byte and 840-byte ELF64 objects,
preserving returned offsets and mutating the selected backing element. Mutable
slice-reference bindings may replace both pointer and length through ordinary
or conditional assignment. Independent callers observed both the original and
replaced values through a 355-byte COFF and 728-byte ELF64 object. Explicitly
shared locals initialized from mutable references retain shared mutability
metadata after the permitted one-way coercion. Shared and mutable string-slice
references use a distinct two-word `str` target while sharing the native fat-
pointer ABI. Parameters, typed and conditional locals, `len()`, `is_empty()`,
returns, and mutable-to-shared coercion are supported. Independent callers
observed byte length 8 for `"rust🦀"`, empty/nonempty results, and pointer/length
identity through 106-byte, 128-byte, 141-byte, and 194-byte COFF objects plus
504-byte, 512-byte, 512-byte, and 568-byte ELF64 objects. Integer indexing is
rejected because Rust strings are not byte-indexable. Shared and mutable
`start..end`, `start..=end`, `..end`, `start..`, and `..` string ranges perform
the ordinary range checks and additionally verify both derived endpoints are
UTF-8 character boundaries before forming the result. An independent caller
selected the crab from `"a🦀z"` through a 322-byte COFF and 696-byte ELF64
object. Interior-byte start and end endpoints separately reached Windows
`0xC000001D` and Linux `SIGILL`. `str::as_bytes()` performs a zero-cost target
conversion to a shared `u8` slice, including from a mutable string receiver;
the resulting fat pointer supports locals, returns, length methods, and
bounds-checked byte indexing. Independent callers preserved pointer and byte
length for `"rust🦀"` and read its leading UTF-8 byte `0xF0` through 143-byte
and 161-byte COFF objects plus 512-byte and 560-byte ELF64 objects. Coercion to
a mutable byte slice is rejected. `str::is_char_boundary(index)` evaluates its
`usize` argument once, returns true at zero, the byte length, ASCII boundaries,
and multibyte leading bytes, and returns false for continuation-byte or out-of-
range indexes. Native callers exercised all five cases through a 214-byte COFF
and 600-byte ELF64 object. Non-string receivers and non-`usize` arguments are
rejected. Shared and mutable slice references expose their data address through
`as_ptr()` and `as_mut_ptr()`, while string slices expose their byte address
through `as_ptr()`. Thin `*const T` and `*mut T` values for supported scalar
pointees may be passed, returned, and stored in locals, including the standard
mutable-to-const coercion; const-to-mutable coercion is rejected. Independent
Windows and Linux callers verified pointer identity and mutated the original
slice through a returned mutable pointer. The four functions emitted 119-,
123-, 117-, and 112-byte COFF objects plus 504-, 512-, 504-, and 504-byte ELF64
objects. Scalar raw pointers now support exact-width
loads, mutable stores, and the same integer compound assignments as mutable
scalar references; writes through `*const T` are rejected. Native callers read
10 through a shared pointer and updated an `i16` from 40 to 42 through 109- and
188-byte COFF objects plus 496- and 584-byte ELF64 objects. Rust, const, and C-
ABI functions accept the `unsafe fn` qualifier in its ordinary position after
`const` and before `extern`; the native raw-pointer probes retain that explicit
unsafe boundary without changing their deterministic object bytes.
Scalar raw pointers convert directly to shared references with
`as_ref_unchecked()` and mutable pointers convert to mutable references with
`as_mut_unchecked()`. The address is preserved while the runtime type changes,
so existing reference loads, locals, mutation, and reborrowing apply. A const
pointer cannot produce a mutable reference, and non-pointer receivers are
rejected. An independent Linux caller read 42 and mutated an `i16` from 40 to
42 through 496- and 584-byte ELF64 objects.
The scalar `read()`, `read_unaligned()`, and `read_volatile()` methods reuse the
same typed load path for shared or mutable pointers. An independent caller
observed aligned, deliberately unaligned, and volatile `u32` values through
108-, 118-, and 117-byte COFF objects plus 496-, 512-, and 504-byte ELF64
objects; non-pointer receivers are rejected.
Mutable scalar raw pointers additionally support unit-valued `write()`,
`write_unaligned()`, and `write_volatile()` expressions. The receiver is
evaluated before the value, which is checked against the exact pointee type and
stored at its Boolean, character, or integer width. Independent native callers
observed aligned, deliberately unaligned, and volatile `u32` mutations through
128-, 138-, and 137-byte COFF objects plus 512-, 528-, and 528-byte ELF64
objects. Shared pointers, non-pointers, and mismatched values are rejected.
`write_bytes(value, count)` evaluates its mutable scalar pointer, `u8` fill
value, and `usize` element count in source order, then writes the repeated byte
across `count * size_of::<T>()` bytes. The generated bounded x86-64 loop handles
one-, two-, four-, and eight-byte scalar pointees and performs no access for a
zero count. Shared pointers, non-`u8` values, and non-`usize` counts are
rejected. Both native object formats are covered by original replacements. An
independent Linux caller used 560-byte `u32` and `u16` ELF64 objects to verify
full fills, a partial fill that preserved the following element, and a zero-
count no-op.
Scalar raw pointers also support `copy_to()`, `copy_from()`, and their
`_nonoverlapping` forms with a matching mutable destination and `usize` element
count. The overlapping forms implement memmove ordering, including backward
copying when the destination begins above the source; the nonoverlapping forms
use the forward path under Rust's caller-side nonoverlap contract. Receivers and
arguments retain source evaluation order. An independent Linux caller verified
both overlap directions, receiver-first `copy_from`, and a separate `u32`
nonoverlapping copy through 616- and 568-byte ELF64 objects. Const destinations,
mismatched pointees, and non-`usize` counts are rejected.
`replace(value)` follows the same receiver-first typed store path but returns the
previous scalar pointee value. An independent native caller observed two
successive old/new `u32` pairs through a 145-byte COFF and 536-byte ELF64
object. Signed integers, Booleans, and characters retain their exact widths;
shared pointers and mismatched values are rejected.
`swap(other)` evaluates both mutable pointers in source order, requires matching
scalar pointees, exchanges their exact-width values, and returns unit. An
independent native caller swapped and restored two `u32` values through a
156-byte COFF and 544-byte ELF64 object. Shared operands and different pointee
types are rejected.
`drop_in_place()` accepts mutable pointers to the currently supported scalar
pointees, evaluates the receiver, and returns unit. Those pointees have no drop
glue, so an independent native caller observed its `u32` unchanged through a
108-byte COFF and 496-byte ELF64 object. Shared pointers and non-pointers are
rejected; aggregate destructor lowering remains separate work.
Pointers with compatible scalar pointees support `==`, `!=`, `<`, `<=`, `>`,
and `>=`, using unsigned address ordering and mutable-to-const compatibility.
An independent caller exercised equal, ascending, and descending addresses
through a 206-byte COFF and 600-byte ELF64 object. Comparisons between different
pointee types remain rejected. Integer-to-pointer, pointer-to-integer,
and thin pointer-to-pointer `as` casts support the bounded scalar pointees,
including pointee and mutability changes; non-integer scalar sources remain
type errors. An independent caller preserved an address through `usize`, `u8`,
and differently typed raw-pointer views through a 206-byte COFF and 592-byte
ELF64 object. Constant evaluation continues to reject address casts. Raw
pointer `with_metadata_of(other)` is supported for the current sized scalar
pointees. Both operands are evaluated in source order; the result preserves the
receiver's address, provenance-facing representation, and mutability while
taking the other pointer's pointee type. Non-pointer operands are rejected.
An independent Linux caller verified const and mutable conversions, pointer
identity, and an in-place `i16` mutation through 520- and 512-byte ELF64
objects. Unsized metadata remains tied to future raw-slice and trait-object
support rather than being represented as scalar metadata.
Raw pointers support element-scaled `add`, `sub`, `wrapping_add`, and
`wrapping_sub` with `usize` offsets plus `offset` and `wrapping_offset` with
`isize` offsets while preserving pointee and mutability. The signed forms
preserve negative two's-complement offsets after element scaling; unsigned and
signed method arguments are not interchangeable. Non-pointer receivers and
other offset widths are rejected. Independent native callers advanced and
rewound 4- and 8-byte array pointers to the expected elements through 142-,
143-, 130-, and 128-byte COFF objects plus 536-, 528-, 520-, and 520-byte ELF64
objects. `offset_from` accepts compatible scalar pointees, returns their signed
element distance as `isize`, and rejects different pointees or non-pointer
operands. A native caller measured both 3 and -3 between elements of the same
`u32` array through a 128-byte COFF and 520-byte ELF64 object.
The pinned-nightly `offset_from_unsigned` and `byte_offset_from_unsigned`
counterparts require the same compatible scalar pointer types and return
`usize`. An independent native caller measured three elements and twelve bytes
through 137- and 138-byte COFF objects plus 528- and 536-byte ELF64 objects.
`align_offset(usize)` validates a nonzero power-of-two alignment, returns zero
for an already aligned address, computes the forward scalar-element count when
reachable, and returns `usize::MAX` when repeated element steps cannot reach the
requested alignment. Invalid alignments reach the shared native trap. Native
callers matched the pinned nightly across 192 address/alignment combinations
for one- and four-byte pointees through 201- and 228-byte COFF objects plus
592- and 624-byte ELF64 objects; non-pointer and non-`usize` operands are
rejected.
`is_aligned()` derives the required alignment from the scalar pointee type and
returns a Boolean without dereferencing the address. Independent native callers
matched the pinned nightly across aligned and deliberately misaligned `u32`
addresses through a 128-byte COFF and 520-byte ELF64 object; non-pointer
receivers are rejected.
Pinned `mask(usize)` preserves the scalar pointer type and mutability while
applying a bitmask to its address. `is_aligned_to(usize)` checks an explicit
alignment after validating that it is a nonzero power of two; invalid runtime
alignments reach the shared native trap. An independent Linux caller recovered
an original pointer from a tagged address and checked aligned and deliberately
misaligned addresses through 512- and 560-byte ELF64 objects. A separate
invalid-alignment caller terminated with `SIGILL`. Non-pointer receivers and
non-`usize` arguments are rejected.
`byte_add`, `byte_sub`, `byte_offset`, their three wrapping counterparts, and
`byte_offset_from` use one-byte scaling while preserving the original pointer
type. Native callers advanced three bytes, rewound three bytes, and measured an
eight-byte distance across two `u32` elements through 121-, 124-, and 129-byte
COFF objects plus 512-, 512-, and 520-byte ELF64 objects. Shared
and mutable raw pointers support `is_null()`, including pointers formed by
integer casts. Native callers distinguished a null pointer from live slice
backing through a 118-byte COFF and 512-byte ELF64 object; non-pointer receivers
are rejected. `addr()` extracts a pointer's `usize` address, and
`expose_provenance()` exposes that address for later provenance-free
reconstruction. The latter passed independent native callers through a
119-byte COFF and 512-byte ELF64 object. `with_addr(usize)` replaces its address
and retains the original raw-pointer
pointee and mutability type. Native callers matched a live array address and
retargeted it to another element through 106- and 122-byte COFF objects plus
496- and 512-byte ELF64 objects. Non-pointer receivers and non-`usize`
replacement addresses are rejected. Shared
and mutable raw pointers also support `cast_mut()` and `cast_const()`, changing
only the pointer mutability while retaining its pointee and address. Independent
native callers preserved live array addresses through 110- and 112-byte COFF
objects plus two 504-byte ELF64 objects; non-pointer receivers are rejected. Shared
and mutable raw pointers accept `cast::<U>()` with scalar integer, Boolean, or
character pointees. The cast retains receiver mutability and address while
changing its pointee type. An independent native caller matched a live
`*const u32` cast to `*const u8` through a 114-byte COFF and 504-byte ELF64
object; non-pointer receivers and unsupported pointees are rejected. Shared
and mutable fixed-array references remain one-word pointers, retain their
element/count metadata through typed local copies and reborrows, and support
bounds-checked constant or runtime indexing plus exact-width mutable element
stores. Independent callers changed `[40usize, 10, 20, 30]` through a runtime
index and observed `[40, 10, 22, 30]` plus the returned sum 62 through 237-byte
COFF and 624-byte ELF64 objects. References can also target MRML's internal
fixed-array locals. Their contiguous positive-stride backing uses the element's
native width and is preserved through typed copies and reborrows. Independent
callers mutated indexes 0, 2, and 3
and observed 42, 22, and 32 through 272-byte COFF and 656-byte ELF64 objects.
Shared and mutable scalar-element slice parameters use their native two-word
fat-pointer representation. The Windows prologue follows pinned rustc by
dereferencing an indirect pair, while System V captures separate data and
length argument words. Typed copies and reborrows preserve both words;
constant and runtime indexing checks the saved length before exact-width reads
or mutable stores. Independent callers passed a four-element mutable slice,
changed index 2 from 20 to 22, and observed the changed backing array plus the
returned sum 62 through 337-byte COFF and 720-byte ELF64 objects. The postfix
`len()` method reads the preserved runtime length from shared
or mutable slice references, including typed copies and mutable reborrows. A
native four-element probe added the copied and original lengths and returned 8
through 146-byte COFF and 528-byte ELF64 objects. The `is_empty()` method tests
that same runtime length and normalizes the result to Rust `bool`. Independent
callers observed true for an empty slice and false for a one-element slice
through 130-byte COFF and 520-byte ELF64 objects.
Constant `start..end`, `start..=end`, `..end`, `start..`, and `..` ranges over
native fixed-array references create shared or mutable slice fat pointers.
Bounds and mutability are checked before code emission; typed locals retain the
adjusted data address and derived length. Independent callers sliced elements
1 through 2 from a four-element mutable array reference, changed 20 to 22, and
observed length 2 plus the changed backing array through 309-byte COFF and
696-byte ELF64 objects. Unsuffixed or `usize` runtime endpoints use the same
range forms. Each endpoint is evaluated once; inclusive-end overflow,
`start > end`, and `end > array_len` reach `UD2` before pointer use. Native
callers selected elements 1 through 2 dynamically, observed length 2, changed
20 to 22, and returned 34 through 422-byte COFF and 808-byte ELF64 objects. A
reversed range produced Windows `0xC000001D` and Linux `SIGILL`. Ranges over
slice references use the same five forms with the fat pointer's runtime length
as their upper bound. Shared and mutable subslices retain the adjusted address
and derived length; omitted ends load the saved base length. A mutable `u16`
subslice probe selected elements 1 through 2, changed 10 to 12, returned 32,
and exposed the changed backing slice through 430-byte COFF and 816-byte ELF64
objects. Both `start > end` and `end > slice.len()` reached Windows
`0xC000001D` and Linux `SIGILL` before pointer use. Ranges over
fixed-array locals use positive-stride contiguous stack backing, so shared and
mutable slices preserve aliasing with the original local. Native callers
dynamically selected elements 1 through 2 from an eight-byte-element local,
mutated 20 to 22 through the slice, then observed that value through the array
and returned 34 through 439-byte COFF and 832-byte ELF64 objects. Packed one-,
two-, and four-byte local probes additionally mutated through `u8` and `u16`
slices and copied a `u32` array before slicing it. Independent Windows and Arch
Linux callers observed 32, 3,002, and 100,007; their COFF objects were 641, 685,
and 671 bytes and their ELF64 objects were 1,032, 1,072, and 1,064 bytes.
Boolean and character local slices have object-emission regressions for their
exact-width stores. Narrow-return functions now admit auxiliary `usize`
parameters without changing the arithmetic width; runtime range endpoints use
that path while ordinary mixed-width arithmetic remains rejected. A dynamic
`u8` local-range probe returned 32 through 744-byte COFF and 1,136-byte ELF64
objects. Reversed endpoints reached Windows `0xC000001D` and Linux `SIGILL`.
Typed and inferred `usize` locals in a narrow-return function retain their own
per-expression arithmetic and comparison width. A computed-endpoint probe
observed `254usize + 2 == 256` without a false `u8` overflow through 196-byte
COFF and 584-byte ELF64 objects; `usize::MAX + 2` reached `UD2` on both hosts.
Independent scalar integer parameters and locals now generalize that model to
all supported signed and unsigned widths. A `u8` result probe combined `u64`
and `i16` parameters, inferred and typed locals, arithmetic, comparisons, and
normalization; independent callers observed 42 and 41 through 370-byte COFF and
760-byte ELF64 objects, while `u64::MAX + 2` trapped on both hosts. A differently
typed packed `[u16; 3]` local also returned 42 through 377-byte COFF and 768-byte
ELF64 objects. Cross-width binary operands remain rejected by runtime typing.
Supported fixed arrays, fixed-array references, scalar references, and slices
may likewise have element widths independent of the function result. A by-value
`[u16; 3]` parameter and a combined `&[u16; 3]`/`&[i32]` probe each returned 42
from a `u8` function through both platform ABI classes. Their COFF objects were
279 and 346 bytes; their ELF64 objects were 688 and 736 bytes. Boolean and
character reference combinations have both-format regressions, and an explicit
`[u32; 2]` element-to-`u64` cast is now positive coverage.
Direct and compound assignment select the lvalue's width independently of the
function result. A `u8` function mutated `u64` and `i16` scalar locals plus a
packed `[u16; 3]` local and returned 42 through 757-byte COFF and 1,152-byte
ELF64 objects. A second probe performed the same exact-width operations through
`&mut u64`, `&mut [u16; 3]`, and `&mut [i16]`, preserving externally visible
aliasing through 646-byte COFF and 1,032-byte ELF64 objects. A parameterized
`u64` compound assignment emitted 239-byte COFF and 624-byte ELF64 objects;
`u64::MAX += 2` reached `UD2` on both hosts.
Array elements are still evaluated left to right; completed temporary slots are
packed or reordered only afterward when positive-stride local backing is
required.
The zero-sized unit value `()` is a distinct runtime expression type. It flows
through condition branches, locals, immediate loop breaks, IR, and native code.
Value-producing loops treat a valueless `break;` as the same unit type as
`break ();`, including mixed guarded and structured alternative exits with
labels. This covers the pinned oracle's scalar `regular_break` forms. A
132-byte COFF and 528-byte ELF64 probe passed both alternatives through
independent native callers. Both explicit `-> ()` and an omitted function
return type select a C-ABI void result. Empty, declaration-only, and supported
statement-ending bodies receive an implicit unit tail with a zero-width source
span at the body boundary. Unit is not silently compatible with integers or
Booleans.
Boolean and unit operands support Rust's equality and ordering comparisons.
Boolean operands additionally support eager `&`, `|`, and `^`; unlike `&&` and
`||`, IR evaluates both operands. Results remain Boolean through direct
evaluation, IR, and native code. Mixed Boolean, unit, and integer operands are
rejected.
Mutable Boolean locals support `&=`, `|=`, and `^=` in straight-line and loop
bodies using the same eager bitwise semantics. Arithmetic, remainder, and shift
compound assignments on Boolean targets remain type errors.
An explicit tail `return expression;` is also represented in the arena and
flows through the same typing, IR, and native paths as an implicit tail value.
Function bodies may additionally contain bounded prefix statements of the form
`if condition { return expression; }`. Their conditions and return values are
type-checked, and each native return removes the complete saved parameter/local
frame before `RET`. Exhaustive `if`/`else if` return chains retain up to four
condition-and-value branches plus a final `else` value in a separate bounded
record. Native and const paths
evaluate only the selected branch, and an exhaustive return is accepted as a
diverging body without a synthetic fallback value. Typed conditional and unconditional returns are supported
inside bounded loops. Returns in arbitrary nested blocks, `else` statement arms,
other than the exhaustive form above, and arbitrary statement blocks remain
deliberately rejected.
The same bounded chain may omit its final `else` when it contains at least two
returning conditions. If every condition is false, native execution and const
evaluation continue with subsequent statements and the function tail. A
single conditional return retains the smaller pre-existing record.
Bounded scalar `while condition { ... }` and `loop { ... }` statements retain
up to eight source-ordered operations, including typed or inferred local
declarations, discarded scalar expressions, up to four mutations, and
unconditional or conditional `break`, `continue`, and typed function returns.
While and control conditions must be Boolean, each assignment target must be
mutable, and assignment types are checked exactly as for straight-line
statements. Each iteration receives a lexical local scope: declarations may
shadow enclosing names, remain visible to later operations, and are removed
before every backedge, taken break, or taken continue. A return includes the
live iteration slots in its complete frame cleanup. Const evaluation restores
the same scope after every iteration while retaining mutations to enclosing
locals. Native emission uses checked forward exits and signed 32-bit backedges.
Capacity overflow is diagnosed before object emission. Empty and action-only
unconditional inner loops are retained as diverging backedges; const evaluation
stops them at the shared 65,536-iteration limit rather than treating natural
fallthrough as an exit. The exact unit-valued inner form `loop { break; }` is
accepted as a nested loop operation.
The same divergence rules apply to top-level loop statements. Empty `while`
bodies recheck their Boolean head, and empty or action-only unconditional loops
emit a signed backedge without requiring a synthetic exit. Source after a
diverging loop remains parsed and type-checked. Const evaluation reports the
same loop-limit diagnostic for an entered nonterminating body.
Up to four inner loops may each perform up to four scoped scalar locals,
assignments, or discarded expressions before an optional control. Inner
locals are removed while mutations to enclosing locals survive. Dedicated
capacity diagnostics reject a fifth inner action or block. The inner break is
consumed locally and cannot exit the containing loop.
The inner exit may instead be a terminal `if condition { break; }`. A false
condition cleans the iteration's inner locals and repeats from the inner action
block; a true condition performs the same cleanup and resumes the containing
loop after the inner operation. Conditions are Boolean, may read inner locals,
and use the existing 65,536-iteration const-evaluation bound.
Up to four ordered `if condition { continue; }` edges may split the inner action
block. A taken edge cleans all inner locals and targets the inner backedge; a
false condition retains them for the remaining actions and controls. Continue
and return edges share exact source ordering. A fifth conditional continue is
rejected before lowering.
Up to four ordered `if condition { break; }` edges may likewise occur before,
between, or after inner actions. A true guard cleans the inner scope and exits
only the nested loop; a false guard preserves that scope for later actions and
controls. Break, continue, and return edges share one exact source order, and a
fifth conditional break is rejected before lowering.
An inner block may instead use a Boolean `while` head. The condition is checked
before every inner iteration, false exits only the inner loop, and natural body
fallthrough cleans inner locals before returning to the inner head. The same
bounded actions and optional conditional controls remain available in its body.
An explicit unconditional `break;` in that body is retained separately from
natural closing-brace fallthrough: the former exits after one entered iteration,
while the latter returns to the head. This distinction prevents a true-headed
`while { break; }` from being lowered as an infinite backedge.
A nested `loop` or `while` body may terminate with a typed function `return`.
Its value is checked and emitted while inner locals remain live, then the normal
function epilogue removes the complete inner and outer frame. A false inner
`while` head bypasses the return and resumes after the nested operation.
An unconditional terminal `continue;` cleans the complete inner iteration
scope and targets the nested loop's own head. For an inner `while`, the head
condition is rechecked before the next iteration; it never skips the remaining
operations of the containing loop.
Unconditional inner `break`, `continue`, and function-return controls retain
their exact position in the same bounded control stream. Source after a taken
edge remains parsed and native-type-checked as unreachable Rust source, while
const evaluation and emitted execution do not evaluate it. Up to four such
controls are retained so later unreachable controls receive the same checking;
a fifth produces a dedicated capacity diagnostic before lowering.
Up to four conditional function returns may occur at ordered positions among
the inner actions. Each false guard advances to the next operation without
changing the inner scope; the first true guard returns after full-frame cleanup.
A fifth guarded return is rejected before lowering.
Conditional returns also retain their order relative to the inner conditional
continue. If both guards at one action position are true, the source-earlier
control edge wins; a taken continue therefore suppresses every later return in
that iteration.
An unconditional inner `loop` may use only conditional continue and function
return controls. False guards reach the inner backedge rather than escaping the
loop, while the first true return performs full-frame cleanup. This preserves
Rust's diverging-loop behavior without requiring a synthetic break edge.
Statement-level `while` and `loop`, plus their directly nested `while` or
`loop`, may carry Rust lifetime-style labels. Matching labeled `break` and
`continue` work in direct operations and bounded `if`/`else if`/`else` control
arms. A nested control may target either its own label or the enclosing
statement loop's label, with Rust-style inner-label shadowing; missing colons
and unknown labels fail with dedicated bounded diagnostics. General deeper
statement-loop nesting and break values in statement-loop operations remain
unsupported. Three native probes cover conditional inner and outer targets,
direct outer continue, and direct outer break. They emitted deterministic 439-,
198-, and 181-byte COFF objects and 832-, 592-, and 576-byte ELF64 objects;
independent pinned-nightly callers passed zero-iteration, ordinary, early-exit,
and 60,000-iteration paths on both hosts.
Conditional loop-control blocks may perform up to four local declarations,
assignments, or discarded scalar expressions before a terminal `break`,
`continue`, or typed function return. Their actions are lazy and receive a
nested lexical scope. Taken break/continue edges remove both the conditional
block's locals and the containing iteration's locals; a return cleans the full
live frame. False conditions allocate no block slots and continue with later
loop operations. A fifth prefix action fails with
`TooManyConditionalLoopActions` before lowering.
The terminal control operation may be omitted. A selected action-only block
cleans its lexical locals and falls through to the next loop operation; an
unselected block performs no actions or stack changes.
Loop conditionals may additionally carry a bounded chain of up to four
`else if` or final `else` arms with the same action and terminal-control forms.
The first matching arm is selected lazily, and each has an independent lexical
scope. The compact alternative-arm arena keeps the common `WhileLoop` record
bounded, and a fifth arm fails with
`TooManyConditionalLoopElseArms` before lowering.
An unconditional loop with no break edge is a diverging body tail, so a
non-unit function ending in a loop return needs no synthetic fallback value.
Const qualification is retained on both Rust-ABI and `extern "C"` function
items and is distinct from a module constant declaration. Qualifying an
otherwise supported exported C function does not change its runtime ABI or
machine code. The bounded scalar call evaluator described below interprets a
restricted subset of const-function bodies; complete const-safety analysis is
not implied by parsing the modifier.

The first semantic pass builds a fixed-capacity constant table, rejects duplicate
module names across functions and constants, resolves dependencies in declaration
order, translates initializer diagnostics back into module source spans, and
checks values against their declared integer type. Root positive and negative
signed literals are range-checked against that declared width and stored as
their low-width two's-complement bit pattern. Signed add, subtract, multiply,
divide, remainder, bitwise operations, and shifts execute in the declared type
with checked overflow, zero-divisor, and shift-distance failures. `usize` and
`isize` range checking uses an explicit validated target pointer width instead
of inheriting the compiler host's layout. Boolean constants support literals,
named prior Boolean constants, short-circuit `&&` and `||`, eager Boolean
bitwise operations, and integer or Boolean comparisons. Signed constant `if`
expressions select only the taken branch, and integer `as` casts preserve source
signedness while applying the destination width. Constant calls and
floating-point values remain unsupported except for a bounded integer scalar
call boundary. A root constant initializer may call a prior Rust-ABI
`const fn` with at most four signed or unsigned integer arguments when every
parameter and the return type match exactly. Arguments and results are
range-checked in their declared widths. Calls may be nested directly as call
arguments, and a function body may directly return a call to an earlier
function. Calls also compose with checked same-typed integer arithmetic,
integer casts, lazy `if` branches, and integer equality or ordering conditions.
Evaluation uses a fixed 64-binding environment and rejects a ninth nested call.
Boolean parameters and return values retain their type in the same environment;
Boolean calls compose with lazy or eager logical operations, integer predicates,
and integer-returning conditionals. A function body may resolve itself as well
as earlier declarations, enabling terminating direct recursion within the same
eight-call limit. Forward mutual recursion, non-const calls, methods, and
runtime calls are rejected.
Const-function bodies use a separate 16-node expression arena and the bounded
body parser. A fixed 32-entry statement stream records locals, assignments,
conditional returns, and loops in source order while compatibility views remain
available for the native backend migration. They may introduce up to the
caller-selected local capacity of
typed or inferred integer and Boolean locals, perform source-ordered
conditional returns, or use an explicit tail `return`. Mutable scalar locals
support direct assignment, checked arithmetic/remainder/shift compound
assignments, integer bitwise compound assignments, and Boolean bitwise compound
assignments. Immutable targets and type mismatches fail before mutation; an
arithmetic failure is transactional because the new value is committed only
after successful evaluation. Bounded `while` and `loop` statements reevaluate
their Boolean condition, execute scalar assignments in source order, and honor
conditional or unconditional `break` and `continue`. Each loop permits at most
65,536 body iterations; exceeding that budget reports
`ConstLoopLimitExceeded`. A loop may conditionally or unconditionally return an
integer or Boolean value of the const function's declared type. Nested statement loops remain
outside the parser boundary. This design avoids treating statement text as a
whole expression and keeps each recursive call frame's stack use bounded.
Const evaluation consumes the ordered stream and supports a scalar assignment
after a loop. Native code generation uses the same statement indices to emit
every pre-loop local, assignment, and conditional return directly in source
order, then dispatches post-loop locals, assignments, and conditional returns
on their respective control-flow edges. Consecutive bounded loop statements retain their source order in both
const evaluation and native emission. A typed or inferred local binding may
also immediately follow the loop sequence; its initializer observes the final
loop state and its native stack slot is created only on that fallthrough edge.
A bounded assignment may follow a conditional return. Const evaluation and
native emission execute it only on the fallthrough edge and preserve checked
arithmetic behavior. Before the first loop, bounded locals, assignments, and
conditional returns may alternate repeatedly; parsing and native emission both
consume the same ordered statement stream. The identical bounded sequencer is
used after the loop sequence, so fallthrough locals, mutations, and guarded
returns may likewise alternate without category-based reordering.
Comparison operands may be named or compound integer expressions. Unsuffixed
literals inherit the other operand's concrete type; incompatible concrete
widths and narrow arithmetic overflow are rejected before comparison.

Expressions lower into a separate fixed-capacity, target-independent stack IR.
The IR has checked arithmetic, explicit constant loads, normalization, and
forward conditional branches; `&&` and `||` therefore retain short-circuit
behavior after lowering. A bounded interpreter provides the bootstrap execution
backend and independently checks stack overflow, underflow, invalid branches,
unknown constants, and malformed final state. Constant semantic analysis now
uses the parse → AST → IR → interpreter path, while differential tests compare
that path with direct AST evaluation.

The first native backend accepts expression-bodied functions returning `u8`,
`u16`, `u32`, `u64`, or 64-bit `usize`. Native object export requires the honest
stable boundary `#[unsafe(no_mangle)] pub extern "C" fn`; ordinary Rust-ABI
functions are rejected because Rust symbol mangling and its native ABI are not
stable contracts. Zero-parameter functions resolve and execute their checked IR
at compile time, validate the declared return range, and emit the canonical
11-byte x86-64 `MOV RAX, imm64; RET` body. Parameter expressions use an
ABI-specific prologue that saves up to four Windows x64 or six System V AMD64
register arguments in bounded stack storage. The typed runtime backend accepts
`u8`, `u16`, `u32`, `u64`, 64-bit `usize`, `i8`, `i16`, `i32`, `i64`, and 64-bit
`isize` parameters and returns. It emits literals, same-typed named signed or
unsigned module constants, integer negation and bitwise not, add, subtract, multiply, divide,
remainder, bit operations, shifts, and signed or unsigned comparisons. Boolean
parameters and returns support logical not plus branch-based short-circuit
`&&` and `||`; mixed integer comparisons and Boolean guards are type-checked.
Runtime integer casts preserve their concrete target type, reject mismatched
function returns and unsupported 128-bit targets, and emit x86-64 zero/sign
extension. Shift right-hand operands may use a different integer cast type,
matching the selected upstream `shift.rs` cases.
Narrow
ABI inputs are explicitly zero- or sign-extended and results are normalized to
their declared width. The minimum signed literal is accepted through unary
negation. Comparison expressions are type-checked as `bool`; returning them from
an integer function is rejected. Checked arithmetic is the default: overflow,
division by zero, `MIN / -1`, `MIN % -1`, and an
out-of-range shift branch to one shared `UD2` trap. `CodegenOptions::WRAPPING`
and the driver spelling `-C overflow-checks=no` disable add, subtract, and
multiply overflow traps and emit width-correct wrapping results. In that mode,
shift distances are masked to the low `log2(type_width)` bits, matching rustc's
`overflowing-lsh-4.rs` and `overflowing-rsh-4.rs` requirements. Output storage is fixed-capacity, and
unsupported signatures,
expressions, names, ranges, ABIs, operators, and output sizes carry source spans.
Up to 16 parameters are supported. Arguments beyond the first four Windows x64
or first six System V AMD64 register arguments are loaded from their ABI stack
slots with checked displacement arithmetic and saved into the same bounded
evaluation frame. Larger signatures are rejected before emission.
Zero-parameter integer functions may use typed or inferred locals. Initializers
are parsed, type-checked, lowered, and interpreted in declaration order; each
binding becomes visible only after successful evaluation. Sequential scalar
bindings may shadow an earlier local or parameter, including with a different
integer type. A shadowing initializer still resolves the previous binding,
while later reads and assignments select the newest binding. Forward
references, unsupported types, and out-of-range values are rejected.
The scalar wildcard pattern in `let _ = initializer;` and explicitly typed
variants evaluates the initializer in source order but creates no name and no
persistent local stack slot. Supported scalar, fixed-array, and fat-reference
initializers retain their ordinary checks and traps before their temporary
values are discarded. `let mut _` and using `_` as a value are rejected.
The underscore assignment statement `_ = expression;` uses the same supported
discard boundary without declaring or resolving an assignment target. Its
right-hand scalar, fixed-array, or fat-reference expression executes normally,
including lazy branches and traps, before the result is released. Compound and
indexed underscore assignments are rejected.
Parameterized functions emit independently typed integer locals and Boolean
locals into bounded stack slots. Later initializers and the tail can reload those slots;
parameter offsets incorporate saved locals and temporary expression depth, and
the epilogue checks and removes the complete combined frame. Mutable integer
and array frames use signed-eight-bit stack displacements only through offset
127 and switch to checked 32-bit displacements at 128 bytes. Array unpacking
uses volatile `R10` scratch storage on both x86-64 ABIs so it cannot overwrite a
later unsaved argument register. Independent callers exercised both an
indirect eight-word array with a copied local at a 136-byte load and a packed
four-byte array followed by a scalar argument. They observed 42 on both hosts;
the corrected deep-array objects were 367-byte COFF and 784-byte ELF64, while
the packed objects were 235 and 624 bytes.
Mutable integer
locals support `=`, `+=`, `-=`, `*=`, `/=`, `%=`, `&=`, `|=`, `^=`, `<<=`, and
`>>=` with the same checked or wrapping arithmetic policy as expressions.
Boolean locals support simple assignment. Assignment to an immutable or unknown
binding, type mismatch, invalid operation, and out-of-range constant result are
reported with bounded source spans.
Local annotations may be omitted. Explicit integer suffixes and Boolean
expressions determine their own types; unsuffixed integer initializers use the
function's supported integer context. A conflicting suffix or native frame
width is rejected rather than silently converted. This is a bounded bootstrap
subset of Rust's constraint-based type inference, not a claim of complete
inference.

The object layer wraps one emitted x86-64 function in deterministic ELF64 or
AMD64 COFF relocatable bytes. Both writers emit the native file header, `.text`,
external function symbol, symbol/string tables, and the required section table
without filesystem access or allocation. ELF section offsets are aligned and
COFF supports both inline eight-byte names and long string-table names. All
offset conversion, output capacity, empty names, and embedded NULs are checked
before an artifact is returned. Relocations and multi-function objects are not
yet supported because the current native function has no external references.

Statements, other item kinds, attributes, generics, full name resolution and
type checking, typed constant evaluation, general function/control-flow IR,
runtime machine-code generation, object relocations and multi-section emission,
linking, and Cargo-compatible package orchestration remain future milestones and
are not represented as complete.

## Verification evidence

The initial compiler slice was verified on 2026-08-21 against pinned nightly
`rustc 1.100.0-nightly (f7d782a3b 2026-08-19)`.

The official `rust-lang/rust` repository was sparse-checked out at the full
matching commit. Its `tests/ui` tree contains 7,401 files marked `run-pass` or
`check-pass`. The first oracle slice executed these upstream `run-pass` files
unchanged with that nightly under native Linux: `arith-unsigned.rs`,
`div-mod.rs`, `shift.rs`, and `bitwise-ops-platform.rs` from
`tests/ui/numbers-arithmetic/`, plus
`tests/ui/consts/control-flow/short-circuit.rs`; all five exited successfully. Original MRML
probes mapped to those cases and to `tests/codegen-llvm/overflow-checks.rs`,
`integer-overflow.rs`, and `abi-x86_64_sysv.rs` run through both MRML object
backends. Unsupported narrow and signed cases are asserted as explicit errors,
not counted as compatibility passes.
The next oracle slice ran `i8-incr.rs`, `u8-incr.rs`, `u8-incr-decr.rs`,
`u32-decr.rs`, and `i32-sub.rs` unchanged with the same pinned Linux nightly;
all five also exited successfully before their executable MRML replacements
were added.
The complete upstream `tests/ui/consts/control-flow/basics.rs` also compiled and
ran unchanged under the pinned nightly. The current MRML replacement covers its
module-constant absolute-difference `if` expression and its recursive scalar
Euclidean GCD behavior. An original scalar iterative Fibonacci replacement now
covers the same early base case and loop state transitions without copying the
upstream tuple representation. Recursive loops, tuple forms outside the bounded
runtime slice below, macros, and general matches remain separate future slices.
The complete upstream `tests/ui/consts/return-in-const-fn.rs` likewise compiled
and ran unchanged under the pinned nightly before its explicit tail-return
replacement was added.
The complete upstream `tests/ui/for-loop-while/while.rs` and `long-while.rs`
also compiled and ran unchanged. MRML replacements cover their scalar counter
mutation, million-iteration termination behavior, and bounded per-iteration
scalar local scope. Printing remains outside this slice.
The complete upstream `tests/ui/consts/const-fn-const-eval.rs` and
`tests/ui/consts/const-extern-fn/const-extern-fn.rs` also compiled and ran
unchanged. MRML replacements cover const-qualified scalar declarations and
runtime C-ABI execution, but not their compile-time calls, arrays, references,
unsafe functions, closures, or floating-point cases.
The complete upstream `tests/ui/for-loop-while/while-with-break.rs` and
`break.rs` also ran unchanged. The MRML replacement covers the scalar `while`
portion with a post-mutation conditional break; allocation/drop behavior,
iterators, and general statement sequencing remain outside that slice.
The complete upstream `tests/ui/for-loop-while/while-cont.rs` and
`loop-break-cont-1.rs` then compiled and ran unchanged. Original MRML probes
cover condition rechecking after a final explicit `continue`, immediate
unconditional loop exit, and mutation inside an unconditional loop followed by
a conditional break. The complete upstream `loop-break-cont.rs` subsequently
compiled and ran unchanged. Its interleaved conditional-break, mutation,
conditional-continue, and post-continue mutation shape now has an original MRML
replacement; printing and assertions remain oracle-side behavior.
The complete upstream `tests/ui/for-loop-while/loop-break-value.rs` also compiled
and ran unchanged under the pinned nightly. Original MRML replacements cover
its immediate scalar integer, Boolean, and valueless or explicit-unit
break-value forms, including matching labels. The oracle file's array-valued
breaks, references, trait coercions, never type, matches, and more general
nested control-flow graphs are not claimed by this slice. Its fixed scalar
array literals now have bounded direct-index coverage, including contextual
array defaults selected through conditional loop-break branches and retained in
fixed-array locals, plus bounded runtime `usize` indexes and whole-array
or indexed-element assignment for mutable locals. Replacements
cover bounded cross-nested value exits, terminating nested value-loop operands,
up to five compatible competing scalar values, both sequential and structured
alternative syntax, lazy selection of the taken break edge, and the oracle's
labeled `break`-as-`while`-condition cases plus its two source orders for
unreachable unit sibling breaks, its three scalar
`Default::default()`/nested-break forms,
and the three directly indexed array/default branch shapes. General `while`
condition expressions, aggregate parameters or returns, unconstrained
aggregate defaults, and arbitrary nested value-loop graphs remain outside this
bounded slice.
The complete upstream `tests/ui/for-loop-while/for-loop-has-unit-body.rs` and
`loop-break-cont-1.rs` also compiled and ran unchanged for the unit slice.
Original MRML probes cover unit expressions, unit locals, unit-valued immediate
breaks, an actual unit-returning unconditional loop function, and implicit unit
tails after empty, local-only, and loop-statement bodies; `for` iterator
desugaring and the oracle's `std::mem::zeroed` call remain separate work.
The complete upstream `tests/ui/expr/if-generic.rs` and `weird-exprs.rs` then
compiled and ran unchanged. Original scalar replacements cover their Boolean
equality and unit-equality behavior; generics, closures, references, function
calls, macros, and the remaining unusual expression forms are not claimed.
The complete upstream run-pass `tests/ui/binop/binops.rs` also compiled and ran
unchanged. Its Boolean ordering and bitwise truth tables and unit ordering have
original scalar MRML replacements. The pinned diagnostic test
`tests/ui/consts/min_const_fn/min_const_fn.rs` was rejected by rustc at its
annotated invalid const-function cases as expected; MRML replacements map only
its accepted const-qualified Boolean `&`, `|`, and `^` declarations.
The exact pinned check-pass
`tests/ui/lint/unused/issue-117142-invalid-remove-parens.rs` compiled and ran
unchanged (with its ordinary unused-value warnings), establishing the Boolean
`|=` oracle. Original replacements cover all three Boolean compound assignments
and an ordered-loop Boolean parity mutation.
The complete upstream run-pass `tests/ui/consts/const-negative.rs` compiled and
ran unchanged under the pinned Linux nightly. Original MRML replacements cover
negative `isize` and `i32` constants, the exact `i8` minimum, both x86-64 object
formats, and rejection when a constant's signed width differs from its runtime
expression context. The complete upstream `tests/ui/consts/const-binops.rs`
also compiled and ran unchanged. MRML replacements cover its signed integer
add, subtract, multiply, divide, bitwise, and shift subset. A following
replacement covers Boolean `&&`/`||`, Boolean names and bitwise operations, and
the oracle's signed and unsigned integer equality and ordering constants.
Floating-point declarations remain outside the claimed coverage.
The pinned run-pass `tests/ui/cast/constant-expression-cast-9942.rs` compiled
and ran unchanged, as did the previously selected complete const-control-flow
oracle. Original MRML replacements cover integer constant casts, signed and
Boolean lazy `if` values, truncation, sign extension, and an untaken invalid
arithmetic branch. Pointer, character, enum, and floating-point casts are not
claimed.
The pinned check-pass `tests/ui/consts/const-block-items/assert-pass.rs`
compiled and ran unchanged. Its arithmetic equality observation has an original
module-constant replacement, extended with named signed and narrow unsigned
compound comparison operands. Const-block item syntax and `assert!` expansion
remain outside this slice.
The complete pinned run-pass `tests/ui/consts/const-fn.rs` and
`const-fn-const-eval.rs` compiled and ran unchanged. Original MRML replacements
now execute prior integer scalar `const fn` declarations with checked argument
binding and feed their results into both native object formats. Generics,
arrays, and unsafe calls remain outside this call boundary.
The pinned run-pass `tests/ui/consts/const-fn-nested.rs` compiled and ran
unchanged. Its call-as-argument shape has an original MRML replacement, along
with direct prior-function calls from a const-function body and fail-closed
coverage for the eight-call nesting limit. Calls embedded in arithmetic and
general call statements are not claimed.
An additional original black-box observation compiled and ran with the same
pinned nightly before its MRML replacement was added. It covers calls as
checked `u8` arithmetic operands, a call comparison selecting a lazy branch,
an integer cast followed by wider arithmetic, and a Boolean comparison result.
The corresponding adversarial cases reject intermediate narrow overflow and
skip an overflowing call in an untaken branch.
The Boolean call observation was also compiled and run under the pinned
nightly after confirming the accepted Boolean const-function declarations in
`tests/ui/consts/min_const_fn/min_const_fn.rs` and the Boolean const result in
the run-pass `tests/ui/consts/const-meth-pattern.rs`. Original replacements
cover Boolean parameters and results, integer predicates returning Boolean,
lazy nested calls, Boolean-to-integer function composition, exact mismatch
rejection, and an untaken invalid arithmetic path. Associated methods and
method patterns remain outside the claimed MRML boundary.
The pinned `tests/ui/consts/control-flow/basics.rs` was rerun unchanged for the
direct-recursion slice. Its Euclidean GCD call now has an original MRML
replacement. Additional regressions cover signed countdown and Boolean parity
recursion, stop nontermination at the eight-call bound, and reject forward
mutual recursion before evaluating its cycle.
The pinned run-pass `tests/ui/consts/return-in-const-fn.rs` was rerun unchanged
for the statement-body slice. Its explicit return has an original MRML
replacement alongside integer and Boolean locals and conditional returns. A
regression source that previously exhausted the Windows debug driver's default
process stack now compiles normally. The Windows driver records an 8 MiB PE
stack reserve through a linker directive while retaining its 256-node public
expression capacity; the reserve is demand-committed by the operating system.
The complete pinned run-pass `tests/ui/consts/const_let_eq.rs` also compiled and
ran unchanged. Original MRML replacements cover its scalar direct and compound
assignment boundary, plus Boolean mutation and an integer XOR swap. Deferred
initialization, projections, and aggregates remain outside this slice. Its
empty and scalar no-effect statements now have original bounded replacements
in the shared source-ordered body stream. Adversarial cases reject immutable assignment and preserve
checked overflow and division-by-zero failures.
The pinned file was rerun unchanged on both hosts for this statement slice. An
additional original oracle interleaves an empty statement, discarded integer,
Boolean, and lazy conditional expressions, a local declaration, and a later
assignment. The same ordered representation executes inside bounded const
functions and the runtime backend. MRML's 363-byte COFF and 768-byte ELF objects
passed independent `no_std` callers on three paths, including zero-divisor paths
protected by short-circuit and conditional selection. A ninth expression
statement produces `TooManyExpressionStatements`.
The pinned check-pass
`tests/ui/consts/const-eval/stable-metric/ctfe-simple-loop.rs` compiled and ran
unchanged. Its mutable scalar `while` behavior has an original MRML replacement,
extended with ordered conditional continue/break and an unconditional `loop`.
An endless `while true` regression stops at the exact MRML iteration budget,
and a loop overflow fails before committing the assignment.
The complete pinned run-pass `tests/ui/consts/consts-in-patterns.rs` also
compiled and ran unchanged. Its signed zero-argument call has an original MRML
replacement alongside negative-argument signed arithmetic and exact `i8::MIN`
binding. A subsequent original oracle covers a named scalar constant pattern,
signed literal pattern, wildcard fallback, omitted block-arm comma, and lazy
arm selection. General pattern forms and reference constants are not claimed.

Windows used the supported native GNU/LLVM host:

```powershell
$env:RUSTFLAGS = '-C link-arg=/stack:16777216'
cargo +nightly-x86_64-pc-windows-gnullvm test `
  -p mrml-rustc -p mrml-rustc-driver `
  --target x86_64-pc-windows-gnullvm --offline
cargo +nightly-x86_64-pc-windows-gnullvm clippy `
  -p mrml-rustc -p mrml-rustc-driver --all-targets --no-deps --offline -- `
  -D warnings
cargo +nightly-x86_64-pc-windows-gnullvm check -p mrml-rustc `
  --target x86_64-unknown-uefi --offline
cargo +nightly-x86_64-pc-windows-gnullvm check -p mrml-rustc `
  --target nvptx64-nvidia-cuda --offline
```

The 555 Windows library, conformance, rustc-nightly-replacement, and driver
tests passed.
A checked-option `and_then` probe emitted a 261-byte COFF object and a 656-byte
ELF64 object. Independent pinned-nightly callers observed the mapped value 60,
outer-addition overflow as `None`, and inner-multiplication overflow as `None`
on Windows and Arch Linux WSL.
A checked-option `or_else` probe emitted a 224-byte COFF object and a 616-byte
ELF64 object. Independent pinned-nightly callers proved that `Some` skips the
fallback, `None` can recover to `Some`, and a second failure remains `None` on
both hosts.
An eager checked-option `or` probe emitted a 244-byte COFF object and a
640-byte ELF64 object. Independent pinned-nightly callers observed first-`Some`
preference, recovery from an outer `None`, and propagation when both producers
returned `None` on Windows and Arch Linux WSL.
An eager checked-option `xor` probe emitted a 271-byte COFF object and a
664-byte ELF64 object. Independent pinned-nightly callers exercised the full
validity truth table: left-only and right-only `Some` selected their respective
values, while both-`Some` and both-`None` produced `None` on both hosts.
An eager cross-width checked-option `and` probe emitted a 248-byte COFF object
and a 640-byte ELF64 object. Independent pinned-nightly callers observed the
right-hand `u16` value only when both the left `u8` and right `u16` producers
succeeded; either failure and the combined failure produced `None` on both
hosts.
A Boolean-option probe covering eager `then_some` and lazy `then` emitted a
283-byte COFF object and a 672-byte ELF64 object. Independent pinned-nightly
callers observed both present and absent eager values, a selected lazy quotient,
and a false lazy edge whose closure contained division by zero but was not
executed, on Windows and Arch Linux WSL.
A scalar-shadowing probe emitted a 265-byte COFF object and a 656-byte ELF64
object. Independent pinned-nightly callers observed parameter shadowing across
`u8`, `u16`, `u64`, and `u32`, mutation of the newest binding, and final values
10, 42, and 520 on Windows and Arch Linux WSL.
A wildcard-let probe emitted a 256-byte COFF object and a 648-byte ELF64 object.
Independent pinned-nightly callers observed zero, ordinary, and `u64` boundary
results after MRML evaluated and discarded scalar arithmetic, a two-element
array, and integer division without retaining a wildcard binding on either
host.
An underscore-assignment probe emitted a 282-byte COFF object and a 672-byte
ELF64 object. Independent pinned-nightly callers observed discarded array and
conditional arithmetic, a selected quotient, and a false edge that skipped
division by zero while preserving zero, ordinary, and `u64` boundary results
on both hosts.
A release driver emitted a 93-byte COFF object. Rust's bundled `rust-lld`
accepted it as the sole input to a 1 KiB PE executable with `/entry:answer
/subsystem:console /nodefaultlib`; the resulting executable returned status 42.

The runtime-expression increment additionally emitted a 179-byte COFF object
for `(left * 3 + right) / 2`. A separate nightly-produced `no_std` caller object
linked with it using only bundled `rust-lld`; the executable validated
`calculate(20, 24) == 42` and exited normally. An independently linked
`value + 1` artifact invoked with `u64::MAX` terminated with Windows status
`0xC000001D`, confirming the generated overflow edge reaches `UD2`.

A 196-byte COFF narrow-integer artifact executed the rustc arithmetic probe
`255u8 / 10 + 255u8 % 10 == 30`. Checked `255u8 + 1` reached `UD2`, while the
130-byte object emitted with `-C overflow-checks=no` returned the wrapped value
zero through an independently compiled C-ABI caller.
Unchecked `1u8 << 17` returned 2 after distance masking, and an exported
`left: u8, right: u8 -> bool` comparison returned both true and false correctly
through independent callers.

A 353-byte signed COFF artifact produced `-10` for the combined negative
division, remainder, and arithmetic-shift probe. A wrapping signed-add object
returned `i8::MIN` for `i8::MAX + 1`; the corresponding checked object and an
unchecked `i8::MIN / -1` object both reached the shared `UD2` trap.

Separate `guard || dangerous_rhs` and `guard && dangerous_rhs` COFF objects
returned correctly for true and false inputs. Both skipped a right-hand
`10 / 0` expression when the left operand determined the result, while ordinary
nonzero right-hand evaluations still produced the expected Boolean values.
Zero-parameter `true || dangerous_rhs` and `false && dangerous_rhs` objects
also linked against an independently nightly-compiled caller and exited
normally, covering Boolean literals and literal-driven short circuiting.
An immutable `static SHIFTED: usize = 10_usize << 4_usize` from the upstream
shift-test pattern was evaluated through bounded IR; the emitted function
returned 160 through an independently nightly-compiled caller.
A fifth-argument Windows x64 function consumed its first stack argument and
returned 42 through a separately compiled caller. The backend also rejects a
seventeenth argument and uses non-sign-extending 32-bit stack cleanup for the
maximum 16-argument frame.
The typed-local `isize` probe derived from `div-mod.rs` evaluated
`15 / 4 + 15 % 4`, emitted a 107-byte COFF object, and returned 6 through a
separate caller.
Parameterized runtime-local probes emitted 185-byte arithmetic and 153-byte
Boolean COFF objects. Independent calls returned 31 for input 10 and exercised
all true/false Boolean-local paths successfully.
The upstream shift pattern `value >> distance as usize` emitted a 139-byte COFF
object and returned 10 for `(160u8, 4u8)` through a separate caller.
Preserved literal suffixes also drive signed unary semantics: the upstream
platform-bitwise pattern `-1000isize as usize >> 3usize` emitted a 113-byte COFF
object and returned 2,305,843,009,213,693,827.
The mutable-local XOR-swap sequence selected from `bitwise-ops-platform.rs`
emitted a 93-byte COFF object and returned 3. A parameterized mutable-local
probe using `^=` and checked `+=` emitted a 157-byte object and returned 241 for
input 15 through an independently nightly-compiled caller.
Replacement probes now also map the mutation forms from `i8-incr.rs`,
`u8-incr.rs`, `u8-incr-decr.rs`, `u32-decr.rs`, and `i32-sub.rs`, plus the
inferred binding form exercised by `short-circuit-let.rs`. An inferred `i32`
mutation object was 255 bytes and returned 42 through an independently
nightly-compiled Windows caller.
Runtime `if` probes emitted 212-byte absolute-difference and 165-byte lazy-choice
COFF objects. An independent caller exercised both comparison directions,
skipped an untaken division by zero, evaluated the ordinary division branch,
and exited normally.
The explicit `usize` tail-return probe emitted a 105-byte COFF object and
preserved both 42 and `usize::MAX` through an independently compiled caller.
A conditional-return probe derived from the base-case shape in
`consts/control-flow/basics.rs` emitted a 190-byte COFF object. Its independently
compiled caller observed 41 through the early path and 42 through the fallthrough
path, including cleanup of one saved local and both parameters.
A scalar counter loop emitted a 172-byte COFF object. Its independent caller
validated zero iterations, one iteration, and one million checked increments.
A two-local summation loop with ordered `sum += i; i += 1;` mutations emitted a
209-byte COFF object and returned 0, 45, and 499,500 for limits 0, 10, and 1,000.
A const-qualified C-ABI addition function emitted a 122-byte COFF object and
returned 42 through an independently compiled caller.
A conditional-break counter emitted a 224-byte COFF object. Independent calls
proved zero-entry exit, natural exit at 5, and break exit at 10 despite a limit
of 100.
Explicit-continue, immediate-loop-break, and conditional-loop-break probes
emitted 200-byte, 114-byte, and 190-byte COFF objects. Their independent caller
proved zero and one-million iteration condition rechecking, immediate return of
42, and loop termination at 10.
An ordered interleaved-control probe emitted a 337-byte COFF object. Its caller
covered zero entry, odd and even exits at 21 and 22, a taken continue that skips
the later mutation, and one million iterations.
Immediate integer and Boolean break-value expressions emitted 144-byte and
126-byte COFF objects. The independent caller observed integer results 1 and 42
and both Boolean values through the native ABI.
A competing-break expression emitted a 202-byte COFF object. Its caller selected
the first value with a zero input without evaluating a trapping division on the
fallback edge, then selected the fallback value and returned 42.
A unit-returning loop function with no written tail expression emitted a
106-byte COFF object and returned normally through an independently compiled
native void call.
Boolean equality, Boolean inequality, and unit equality emitted 127-byte,
131-byte, and 109-byte COFF objects. An independent caller exercised equal and
unequal truth-table rows and observed unit equality as true.
Boolean ordering, `&`, `|`, and `^` emitted 126-byte, 122-byte, 121-byte, and
122-byte COFF objects. The independent caller passed representative true and
false rows for each operation; AST and IR adversarial tests separately prove
bitwise operands are evaluated eagerly.
A chained Boolean compound-assignment function and a loop-parity mutation
emitted 200-byte and 231-byte COFF objects. Independent calls exercised all four
input rows plus zero, one, and one million loop iterations.
The Boolean-constant replacement emitted a 145-byte COFF object. A separately
compiled `no_std` caller exercised both input rows through named false and true
compound constants and exited normally.
The cast/conditional slice emitted 165-byte signed and 129-byte Boolean COFF
objects. An independent `no_std` caller observed 42 from the sign-extended
selected branch and passed both Boolean input rows.
The compound-comparison replacement emitted a 157-byte COFF object. Its
independent `no_std` caller exercised both Boolean input rows after signed and
narrow unsigned compile-time comparisons.
The first const-call replacement emitted a 127-byte COFF object. An independent
`no_std` caller observed the called `add(40, 2)` result through two runtime
inputs.
The signed const-call replacement emitted a 169-byte COFF object; its caller
observed 42 and -42 from a constant produced by `adjust(-8, 50)`.
The nested const-call replacement emitted a 149-byte COFF object. Its
independently compiled `no_std` caller observed 22 and 42 and exited normally.
The composed const-call replacement emitted a 152-byte COFF object. Its
independent `no_std` caller observed 42 and 43 after a call comparison and
checked call-result multiplication selected at compile time.
The Boolean const-call replacement emitted a 151-byte COFF object. Its
independent `no_std` caller observed 42 and 43 after Boolean calls selected an
integer result at compile time.
The recursive GCD replacement emitted a 152-byte COFF object. Its independent
`no_std` caller observed 6 and 42 after bounded compile-time recursion.
The statement-bodied const-call replacement emitted a 172-byte COFF object.
Its independent `no_std` caller observed 42 and -42. The debug driver compiled
the same source successfully with an inspected 8,388,608-byte PE stack reserve.
The mutable-local const-call replacement emitted a 150-byte COFF object. Its
independent caller observed 42 and 43 after three checked compile-time
assignments.
The const-loop replacement emitted a 147-byte COFF object. Its independent
caller observed 42 and 43 after compile-time mutation, continue, and break.
The conditional-return const-loop replacement, derived from the scalar prime
shape in `consts/control-flow/basics.rs`, emitted a 154-byte COFF object. Its
independent caller observed 42 and 43; the unchanged pinned rustc test also
compiled and ran successfully.
The corresponding runtime prime emitted a 433-byte COFF object. Its independent
`no_std` caller exercised a loop return of true for 113 and an earlier loop
return of false for 117, including complete parameter/local frame cleanup.
An unconditional runtime loop-return probe with no tail expression emitted a
146-byte COFF object and returned 42 from inside the loop through a separately
compiled caller. A const variant maps the same form back to the pinned
explicit-return oracle without inventing an unreachable fallback value.
An original black-box source containing both const and runtime tail-free loop
returns compiled and ran with the pinned nightly before this behavior was
claimed for MRML.
The first ordered-statement const replacement executes a loop before a final
`*=` mutation. It emitted a 150-byte COFF object whose independent caller
observed 42 and 43. An original pinned-nightly observation independently
confirmed that the post-loop mutation produces 42 rather than the reordered 21.
The runtime form emitted a 266-byte COFF object. Its independent caller observed
zero for zero iterations and 42 for 21 iterations, directly proving the final
mutation executes after the loop.
A post-loop conditional-return replacement followed by another assignment
emitted a 308-byte COFF object. Its caller observed fallthrough value 4 and
returned value 7 after 42 iterations, covering `loop → condition → return or
assignment` order. The matching original black-box source passed both
assertions with the pinned nightly before MRML coverage was claimed.
A consecutive-loop replacement maps the two-`while` shape in the unchanged
pinned `tests/ui/for-loop-while/while.rs` oracle. It emitted a 296-byte COFF
object; an independent caller observed 42 with increasing bounds, 42 when the
second loop began past its bound, and zero when both loops had zero iterations.
The loop-local replacement maps the per-iteration binding in unchanged pinned
`tests/ui/for-loop-while/long-while.rs`. That oracle compiled and ran with the
exact dated nightly on both hosts. MRML's 425-byte COFF object passed an
independent nightly-built caller across zero and one iteration, conditional
continue, conditional break, ordinary termination, and 60,000 iterations. Its
discarded expression consumes the scoped binding before each control edge;
post-loop lookup of that binding is rejected, and runtime-local capacity
exhaustion fails before emission.
The conditional-loop-block replacement maps the local/action/break order in
unchanged pinned `tests/ui/for-loop-while/while-with-break.rs`; vectors,
allocation, destructors, printing, and drop elaboration are not claimed. The
oracle compiled and ran with the exact dated nightly on both hosts. MRML's
525-byte COFF object passed an independent nightly-built caller through false
conditions, a taken action-bearing continue, a taken action-bearing break,
ordinary completion, and 60,000 iterations. Unit and const coverage additionally
exercise action-bearing conditional returns and reject a fifth prefix action.
An action-only conditional-loop replacement maps the guarded mutation and
subsequent fallthrough order in pinned
`tests/ui/for-loop-while/loop-no-reinit-needed-post-bot.rs`; moves, destructors,
user-defined calls, and bottom-typed expressions are not claimed. Its native
probe emitted 377-byte COFF and 768-byte ELF64 objects. Independent
nightly-built callers exercise selected and unselected arms, scoped locals,
post-arm fallthrough, and 60,000 iterations on both supported hosts. The exact
unchanged pinned oracle also compiled and ran successfully on both hosts.
A loop `if`/`else` replacement maps the two-arm ordering from the same pinned
oracle. MRML's 440-byte COFF and 832-byte ELF64 objects passed independent
nightly-built callers across true and false arms, scoped locals, post-arm
fallthrough, and 60,000 iterations. Const evaluation covers both arms, while a
capacity regression rejects a fifth else arm.
A chained-alternative replacement extends that pinned ordering with an original
three-way scalar probe. Its 534-byte COFF and 928-byte ELF64 objects passed
independent nightly-built callers across first-, second-, and fallback-arm
selection, zero iterations, and 60,000 iterations. Conditions are evaluated in
source order and later arms remain lazy after the first match.
An alternative-terminal replacement maps conditional control ordering in
pinned `tests/ui/for-loop-while/loop-break-cont.rs` and the alternative
continue edge in `loop-no-reinit-needed-post-bot.rs`. Its 576-byte COFF and
968-byte ELF64 objects passed independent nightly-built callers through a
primary break, else-if continue, later else-if break, fallback return, zero
iterations, and 60,000 continues. Const evaluation exercises the same edges.
The immediate nested-unit-loop replacement maps unchanged pinned
`tests/ui/for-loop-while/nested-loop-break-unit.rs` and the immediate exit in
`loop-break-cont-1.rs`. The exact oracle compiled and ran on both hosts. MRML's
193-byte COFF and 584-byte ELF64 objects passed independent nightly-built
callers at zero, one, 42, and 60,000 outer iterations, proving the inner break
does not target the outer exit.
A scoped inner-action extension emitted 334-byte COFF and 728-byte ELF64
objects. Independent nightly-built callers observed triangular sums at zero,
one, five, and 60,000 outer iterations, proving inner locals are cleaned after
each break while enclosing accumulator mutations persist. Const evaluation and
capacity regressions cover the same scope and fixed-arena boundaries.
A repeated-inner-loop extension emitted 373-byte COFF and 768-byte ELF64
objects. Independent nightly-built callers exercised three inner iterations per
outer iteration at outer counts zero, one, five, and 60,000. The conditional
break reads the scoped selected value, while each false backedge and true exit
cleans that slot without discarding enclosing mutations. Const evaluation
produced the same zero, six, and thirty results for its bounded cases.
The inner-continue replacement maps nested continue/break targeting from pinned
`tests/ui/for-loop-while/loop-break-cont.rs`. Its 454-byte COFF and 848-byte
ELF64 objects passed independent nightly-built callers through even-value
continues, odd-value fallthrough, later conditional break, zero iterations, and
300,000 inner iterations. Const evaluation produced zero, nine, and forty-five
for the corresponding bounded cases.
The positioned inner-break replacement maps ordered nested break edges from
pinned `tests/ui/for-loop-while/break.rs` and `loop-break-cont.rs`. Its 442-byte
COFF and 832-byte ELF64 objects passed independent nightly-built callers through
early, middle, late, natural, zero-iteration, and 60,000-outer-iteration paths.
Const evaluation produced zero, three, six, and fifteen for the bounded cases.
The unconditional inner-continue replacement maps the nested backedge from
pinned `tests/ui/for-loop-while/loop-break-cont.rs`. Its 319-byte COFF and
712-byte ELF64 objects passed independent nightly-built callers at zero, one,
five, and 60,000 outer iterations while rechecking the inner `while` head and
cleaning a scoped local before every backedge. Const evaluation produced the
same bounded results.
The ordered-unreachable-control extension retains a local, discarded division
by zero, and return after that taken continue. Its 385-byte COFF and 776-byte
ELF64 objects passed the same independent callers without evaluating the
unreachable division, while a separate invalid Boolean local after the edge was
still rejected during native type checking. Const evaluation likewise skipped
the unreachable overflow and return; parser regressions cover the four-control
capacity boundary.
The conditional-only inner-loop replacement maps the backedge/return shape from
pinned `tests/ui/for-loop-while/loop-break-cont.rs`. Its 270-byte COFF and
664-byte ELF64 objects passed independent nightly-built callers through false
outer entry, immediate return, two conditional continues, and 60,000 inner
iterations. Const evaluation independently covered false entry and one- and
200-iteration returns.
The diverging-inner-loop replacement maps empty and action-only loop bodies from
pinned `tests/ui/for-loop-while/loop-break-cont.rs`. Its 125-byte COFF and
520-byte ELF64 objects passed independent nightly-built callers through the
false enclosing condition, returning 42. Machine-code inspection confirms a
signed backward jump, and const evaluation reports the exact loop-limit error
for both entered shapes instead of allowing fallthrough.
The top-level empty-loop replacement extends the same pinned oracle mapping to
empty `while`, empty `loop`, and action-only `loop` statements. Its 120-byte
COFF and 512-byte ELF64 empty-while objects passed independent nightly-built
callers through the false head and returned 42. Both object backends contain
checked negative backedges for the diverging forms, and const evaluation stops
them at the exact shared iteration limit.
The same-loop-label replacement maps labels from pinned
`tests/ui/for-loop-while/loop-break-value.rs` and `loop-break-cont.rs`. Its
379-byte COFF and 776-byte ELF64 objects passed independent nightly-built
callers through labeled conditional continue, labeled else-if break, a labeled
immediate loop exit, zero iterations, and two 60,000-iteration paths. Const
evaluation produced one and nine for early and complete bounded cases; parser
regressions reject a missing colon and unknown direct or conditional labels.
The nested-while replacement maps nested scalar while flow from pinned
`tests/ui/for-loop-while/while.rs` and the nested targeting observed in
`nested-loop-break-unit.rs`. Its 361-byte COFF and 752-byte ELF64 objects passed
independent nightly-built callers at zero, one, five, and 60,000 outer
iterations, with three condition-headed inner iterations each. Const evaluation
produced matching zero, six, and thirty results.
A combined nested-while-control replacement emitted 489-byte COFF and 880-byte
ELF64 objects. Independent nightly-built callers covered immediate head exit,
natural head exhaustion, taken and false conditional continue, later
conditional break, zero outer iterations, and 60,000 outer repetitions. The
const evaluator produced matching zero, four, nine, and forty-five path results.
The unconditional nested-while-break regression maps pinned `break.rs` and
`nested-loop-break-unit.rs`. Its 211-byte COFF and 608-byte ELF64 objects passed
independent nightly-built callers with false and true heads through 60,000 outer
iterations. Const coverage independently distinguishes false-head exit from a
true-head unconditional break.
The nested-while-return replacement maps nested cleanup and return control from
pinned `loop-no-reinit-needed-post-bot.rs` and the existing const-control-flow
oracle family. Its 269-byte COFF and 664-byte ELF64 objects passed independent
nightly-built callers through false-head fallthrough, true-head typed return,
zero outer iterations, and 60,000 fallthrough iterations. Const evaluation
returned five and forty on the corresponding paths.
The valueless nested-while-return replacement maps the unit-return shape from
pinned `tests/ui/codegen/issue-88043-bb-does-not-have-terminator.rs`. Its
300-byte COFF and 696-byte ELF64 objects passed independent nightly-built
callers through zero-iteration, false-head, entered-return, and 60,000-iteration
paths.
The conditional valueless-return extension maps that pinned test's guarded
return shape without calls or heap values. It emitted a 344-byte COFF object
and a 736-byte ELF64 object. A pinned-nightly Linux caller exercised immediate
outer exit, returns on the first and third inner iterations, and 60,000 natural
inner-loop exits.
The typed conditional nested-return replacement maps guarded nested cleanup in
pinned `tests/ui/liveness/loop-no-reinit-needed-post-bot.rs`. Its 388-byte COFF
and 784-byte ELF64 objects passed pinned-nightly callers through zero outer
iterations, returns on the first and third inner iterations, and 60,000 natural
inner-loop exits. The Windows oracle was a separate `no_std` object linked with
bundled `rust-lld`, the generated object, and no CRT or SDK libraries.
The ordered nested-return extension emitted 470-byte COFF and 864-byte ELF64
objects. Pinned-nightly native callers proved zero-iteration fallthrough,
first- and second-guard selection, source-order priority for equal guards, and
60,000 natural inner-loop exits. The Windows caller was again `no_std` and
linked without CRT or SDK libraries.
The nested continue-before-return regression emitted 429-byte COFF and 824-byte
ELF64 objects. Pinned-nightly callers proved that an earlier taken continue
suppresses a simultaneously true later return, while false and differently
positioned continue guards preserve the later return. Zero and 60,000-iteration
fallthrough paths also passed; the Windows caller used no CRT or SDK libraries.
The multiple-continue extension emitted 442-byte COFF and 832-byte ELF64
objects. Pinned-nightly callers distinguished first-only, second-only, and
duplicate continue guards and passed a 60,000-outer-iteration path. Const
evaluation independently produced matching 12, 13, 5, and 40 results across
multiple continues and ordered continue/return edges. A fifth continue has a
dedicated pre-lowering capacity diagnostic.
A post-loop local-binding replacement emitted a 291-byte COFF object. Its
independent caller observed 4 on the zero-iteration path and 42 after 19
iterations, proving the initializer reads the loop's final value instead of a
hoisted value.
A guarded local-binding replacement maps the statement order in the pinned
`tests/ui/liveness/var-defined-after-early-return.rs` run-pass test and the
scalar const shape in `tests/ui/consts/control-flow/basics.rs`. It emitted a
226-byte COFF object. Its independent caller returned 7 before an otherwise
overflowing initializer and returned 42 through the ordinary fallthrough path.
A guarded-mutation replacement emitted a 241-byte COFF object. Its independent
caller returned 7 without executing an overflowing `+=` and returned 42 after
the ordinary mutation path.
The guarded iterative-Fibonacci replacement emitted a 374-byte COFF object.
Its independent caller observed 0, 1, 55, and 6,765 for inputs 0, 1, 10, and
20, covering the early return, zero-iteration fallthrough, and dependent
three-local loop mutations.
An alternating two-guard replacement emitted a 289-byte COFF object. Its
independent caller observed the first return, the second return after one
mutation, and the final value 42 after both mutations. Supplying `u32::MAX` to
the first-return path proves the skipped mutation cannot be hoisted.
A post-loop alternating-guard replacement emitted a 458-byte COFF object. Its
independent caller covered three loop iterations followed by the first return,
the second return, or final value 42, plus a zero-iteration fallthrough. The
first path again used `u32::MAX` to prove the post-loop mutation remains lazy.
A scalar-block replacement emitted a 206-byte COFF object. Its independent
caller observed 42 through both selected branches and passed a zero divisor on
the untaken division edge. Unit and nested value blocks also compile through
both object writers.
An original scoped-block oracle then passed under the pinned nightly with a
runtime operand, typed mutable local, nested shadowing, and explicit tails.
MRML's runtime replacement emitted a 244-byte COFF object and 632-byte ELF
object. Independent callers observed the same selected, fallback, and
zero-divisor-skipping paths, while a separate regression proves inner names do
not escape their closing brace.
A separate scalar-match oracle passed under the same pinned nightly with a
named constant pattern, a signed literal pattern, a wildcard fallback, and an
omitted comma after a block arm. MRML emitted a 256-byte COFF object and a
648-byte ELF object for the runtime replacement. Independent callers observed
42 through both the selected and fallback arms; the selected input would make
the unselected division denominator zero, directly exercising lazy arm
selection on both hosts.
The follow-on ordered-match oracle exercised three distinct patterns plus the
wildcard and returned 42 through every path under the pinned nightly. MRML's
corresponding 351-byte COFF and 744-byte ELF objects passed independent callers
on all four paths. The first zero-valued pattern also skipped a wildcard
division by zero, while middle-arm execution proved earlier nonmatches do not
select or evaluate their bodies.
The unchanged pinned `tests/ui/binding/match-range.rs`, `match-range-static.rs`,
and `tests/ui/consts/const-eval/const_signed_pat.rs` then passed with the
reference nightly. MRML replacements cover their inclusive and exclusive
integer boundaries, an exact arm before a range, signed bounds, and named
constant bounds. Character coverage is recorded separately below; floating-point
ranges are not claimed. An
original seven-path oracle passed the same nightly. Its 390-byte COFF and
784-byte ELF replacements passed independent callers at both inclusive bounds,
both exclusive interior edges, the exclusive end fallback, an exact arm, and a
zero input that skips a dividing fallback.
The unchanged pinned
`tests/ui/match/overeager-sub-match-pruning-13027.rs` and
`tests/ui/half-open-range-patterns/range_pat_interactions0.rs` then ran
successfully under the reference nightly. Original MRML replacements map their
scalar exact-or-range alternatives and overlap ordering; bindings and
collections are not claimed. A nine-path oracle
passed the same nightly, and MRML's 470-byte COFF and 864-byte ELF objects passed
independent callers through every exact and range alternative plus the
wildcard. The zero alternative skipped a dividing fallback on both hosts.
The open-ended subset from `range_pat_interactions0.rs` now has direct MRML
coverage for exclusive and inclusive upper bounds, lower-only bounds, and an
open range joined with an exact alternative. An original eight-path oracle
passed the pinned nightly. MRML's 659-byte COFF and 1,056-byte ELF objects passed
independent callers across each boundary and the wildcard fallback on both
hosts.
Scalar guards from `overeager-sub-match-pruning-13027.rs` now have original
MRML coverage over exact, range, and alternative patterns. A companion oracle
passed the pinned nightly with true guards, false-guard fallthrough, overlapping
later arms, and a mismatched pattern whose guard would divide by zero. MRML's
635-byte COFF and 1,032-byte ELF objects passed all five paths through
independent callers on both hosts. A non-Boolean guard is rejected during type
checking.
The character-range case in the unchanged pinned `match-range.rs` oracle now
has a distinct MRML `char` implementation. An original oracle extended it with
ASCII boundaries, standard escapes, Unicode-scalar escapes, alternatives, and
a fallback. MRML's 362-byte COFF and 752-byte ELF objects passed all six paths
through independently nightly-compiled callers on both hosts. The caller
explicitly acknowledges rustc's `improper_ctypes` warning for `char` in a C ABI;
MRML nevertheless keeps `char` type-distinct from `u32` and rejects mixed
comparisons.
The unchanged pinned `tests/ui/match/guards.rs` then compiled and ran on both
hosts. Its scalar whole-scrutinee binding case has an original three-path MRML
replacement with two successive guarded bindings and a wildcard fallback. The
first accepted arm, false-guard fallthrough into the second binding, and final
fallback passed independently compiled callers against MRML's 302-byte COFF
and 704-byte ELF objects. A binding is scoped to its own guard and body, while
an attempted binding alternative is rejected rather than given inconsistent
Rust semantics. Struct destructuring from the pinned test is not claimed.
The unchanged pinned `guard-pattern-ordering-14865.rs` and
`guard-arm-and-or-arm.rs` tests also compiled and ran on both hosts. Their
guarded-wildcard ordering has an original four-path scalar replacement: a true
leading guard, false-guard fallthrough to an exact arm, a later guarded
wildcard, and the final fallback. MRML's 304-byte COFF and 704-byte ELF objects
passed independent callers on all paths. The replacement additionally checks
short-circuiting inside a wildcard guard and rejects a non-Boolean guard. Enum
construction, enum destructuring, and enum alternatives from the pinned tests
are not claimed.
The unchanged pinned `range-arm-and-ref-arm.rs` and
`binding/match-pattern-bindings.rs` tests then compiled and ran on both hosts.
MRML maps their scalar `name @ range` and `name @ _` behavior with an original
five-path replacement covering an accepted guarded range, false-guard
fallthrough, an exact binding, a guarded wildcard binding, and the final
fallback. Its 358-byte COFF and 760-byte ELF objects passed independent callers
on every path. Exact and character-range `@` forms also reach both object
formats in the replacement suite. Reference binding modes, `Option` patterns,
string patterns, and `let` patterns from the pinned tests are not claimed.
The pinned `or-patterns/bindings-runpass-2.rs` test then compiled and ran on
both hosts, while pinned `missing-bindings.rs` produced its expected E0408
diagnostic under the specified 2018 edition. An original six-path scalar oracle
covers identical exact bindings, identical range bindings, a guard accepted at
each end of separated ranges, false-guard fallthrough, and the final fallback.
MRML's 457-byte COFF and 856-byte ELF objects passed independent callers on
both hosts. Original negative replacements reject both a missing binding and
differently named bindings with `InconsistentMatchBindings`; nested aggregate
and parenthesized or-patterns from the pinned tests are not claimed.
The pinned `error-codes/E0030.rs` and `match/match-range-fail-2.rs` tests then
produced their expected E0030 diagnostics on both hosts. Original MRML negative
replacements reject reversed unsigned, reversed signed, reversed character,
and equal exclusive literal ranges. A three-path boundary oracle proves an
equal inclusive range selects its arm, a one-value exclusive interval selects
its arm, and the adjacent fallback remains reachable. MRML's 276-byte COFF and
680-byte ELF objects passed independent callers on both hosts. Validation of
target-width endpoint overflow is covered separately below.
The unchanged pinned `binding/match-range-static.rs` named-bound test then ran
on both hosts. Original MRML replacements accept equal inclusive named bounds
and reject reversed unsigned, reversed signed, equal exclusive, and Boolean
named bounds after resolution. A companion three-path named-bound oracle passed
independent callers against 276-byte COFF and 680-byte ELF objects on both
hosts. The validation metadata is fixed at thirty-two records and cannot allocate.
The pinned `match/validate-range-endpoints.rs` test then produced its expected
unsigned, signed, and E0030 diagnostics on both hosts. Original MRML negative
replacements reject overflowing `u8`, `i8`, `u64`, and 64-bit `usize`
endpoints, including negative and open-ended cases, with
`RangeEndpointOutOfRange`. Valid full-width `u8`, `i8`, and `usize` ranges reach
both object formats. A maximum-`u8` three-path oracle passed independent callers
against MRML's 187-byte COFF and 592-byte ELF objects on both hosts.
The unchanged pinned `or-patterns/inner-or-pat.rs` `or1` revision and
`or-patterns/or-patterns-syntactic-pass.rs` then compiled with the exact nightly
on Windows and compiled and ran under that nightly on Arch Linux WSL. MRML's
original scalar replacement recursively groups four exact/range alternatives,
accepts a leading `|`, applies a lazy Boolean guard, and proves both a later arm
and the final fallback. Its 402-byte COFF and 800-byte ELF objects passed
independent `no_std` callers on six paths. Empty and trailing-alternative groups,
a missing close delimiter, inconsistent nested bindings, and a fifth flattened
alternative fail closed. Aggregate patterns, strings, and grouped alternatives
inside aggregate subpatterns from the pinned tests are not claimed.
An original follow-up oracle exercises a scalar binding around recursively
grouped exact and range alternatives, a leading `|` plus wildcard group, guard
fallthrough, and binding use in both the guard and result. It passed the exact
pinned nightly on both hosts. MRML's 417-byte COFF and 816-byte ELF objects then
passed independent `no_std` callers on seven paths. A nested second `@` and a
fifth flattened bound alternative are rejected before lowering.
The unchanged pinned `match/large-match-mir-gen.rs` regression compiled with the
exact nightly on Windows and compiled and ran under that nightly on Arch Linux
WSL. MRML does not claim its string and enum surface; an original eight-arm
scalar replacement instead proves source order, two arms sharing a value with
guard fallthrough, selection of the eighth guarded arm, the final fallback, and
lazy earlier division bodies. Its 680-byte COFF and 1,080-byte ELF objects passed
independent `no_std` callers on eight paths. A ninth non-fallback arm produces
`TooManyMatchPatterns`, and the coupled range-validation arena now admits the
maximum eight arms times four alternatives while rejecting a thirty-third
range record.
The unchanged pinned `or-patterns/exhaustiveness-pass.rs` test compiled with the
exact nightly on Windows and compiled and ran on Arch Linux WSL; the unchanged
`exhaustiveness-non-exhaustive.rs` test produced E0004 on both hosts. Original
MRML replacements accept both source orders of exhaustive Boolean literals,
grouped `@` Boolean alternatives, and an irrefutable scalar binding without a
wildcard fallback. Missing Boolean variants, guarded-only coverage, and partial
integer literals fail with `NonExhaustiveMatch`. A two-path oracle passed the
exact nightly, and MRML's 151-byte COFF and 552-byte ELF objects passed
independent `no_std` callers for both Boolean values.
A closed inline-const replacement emitted a 277-byte COFF object. Its
independent caller observed 42 through both selected branches and passed zero
through an untaken division edge. The updated object resolves its offset from a
module constant inside the inline const boundary. The unchanged pinned
`tests/ui/consts/const-blocks/const-block-in-array-size.rs` test also compiled
and ran successfully under the reference nightly. Pinned
`tests/ui/inline-const/referencing-local-variables.rs` produced its expected
E0435 rejection; original MRML regressions reject both parameter and local
captures. The unchanged pinned
`tests/ui/consts/const-blocks/fn-call-in-const.rs` run-pass test also executed
successfully; original integer and Boolean replacements evaluate a prior scalar
const call inside the inline boundary before feeding its result to native code.
The same 277-byte COFF and 664-byte ELF objects now fold `offset()` directly
from the exported runtime body; their independent callers pass both branches
and the untaken zero-divisor case. A zero-parameter exported probe separately
exercises the IR call-load path, and non-const calls fail closed. The final
argument-bearing objects fold `add(1, 1)` directly; IR regression coverage
proves two operands retain source order. An original integer, Boolean, and
signed-argument oracle passed under the pinned nightly before this behavior was
claimed.
The unchanged pinned `tests/ui/inline-const/const-expr-basic.rs` run-pass test
also executed successfully. Its immutable `let` plus division shape has an
original MRML replacement, extended with two dependent bindings and a lazy
tail. Final compile-time folding restores the 277-byte COFF and 664-byte ELF
objects; an inline division by zero is rejected during compilation instead of
being deferred to a runtime trap.
An original mutable inline-const oracle then passed under the pinned nightly.
MRML replacements cover ordered integer assignment and arithmetic plus Boolean
bitwise mutation. Their final folded artifacts remain 277-byte COFF and
664-byte ELF objects and pass the same independent selected, fallback, and
untaken-division paths.
An original typed inline-const oracle then passed under that nightly on both
the Windows compile boundary and Linux execution boundary. Narrow integer and
Boolean annotations, plus mutation that retains the declared narrow type, have
original MRML replacements. The pinned nightly independently rejected both an
out-of-range `u8` initializer and an integer initializer ascribed as `bool`.
MRML reports the corresponding bounded compile-time errors. The resulting
typed replacement again emitted 277-byte COFF and 664-byte ELF objects; both
independent native callers passed all three branch and lazy-division cases.
An original interleaved-statement oracle then produced 42 through both later
declarations and scalar shadowing under the pinned nightly. The MRML
replacement folds alternating declarations and mutations in lexical order.
Its 277-byte COFF and 664-byte ELF objects passed the same independent native
callers without introducing runtime storage or allocation.
An original expression-statement oracle passed under the pinned nightly with a
discarded scalar const call and a lazy conditional statement. The MRML
replacement preserves the same evaluated/discarded sequencing and rejects an
executed division by zero before reaching the tail. Final folding again emitted
277-byte COFF and 664-byte ELF objects whose independent callers passed every
selected, fallback, and skipped-division path.
An original trailing-semicolon oracle then confirmed the pinned nightly returns
unit after declarations, mutations, and a discarded path statement. The
unchanged pinned `tests/ui/inline-const/expr-with-block.rs` check-pass test also
compiled and ran. Its accompanying cross-control-flow test produced the
expected errors for `return`, `break`, and `continue` attempting to escape the
inline boundary; original MRML adversarial probes fail closed for the same
spellings. The unit replacement emitted a 103-byte COFF object and 496-byte ELF
object. Independent callers linked and returned normally on both hosts.
An original unit-if oracle then passed under the pinned nightly with both an
untaken division and a taken discarded arithmetic statement. A companion
oracle produced E0317 for a value-valued branch without `else`. MRML preserves
the same acceptance boundary. The selected replacement emitted a 277-byte COFF
object and 664-byte ELF object; independent callers passed selected, fallback,
and skipped-division paths on both hosts.
An original scoped-branch oracle then produced 42 through an outer binding,
branch-local shadowing, and mutation while leaving a division-by-zero
initializer untaken. MRML reproduces that lexical scope and laziness. Final
folding emitted a 206-byte COFF object and 592-byte ELF object; both independent
callers passed all three runtime paths.
An original three-link `else if` oracle selected its third branch under the
pinned nightly while skipping division-by-zero expressions and an invalid
initializer in every other branch. MRML's nested replacement produced the same
42 and retained scoped locals. Its 206-byte COFF and 592-byte ELF objects passed
all independent caller paths.
Signed compound constants emitted 168-byte add and 130-byte mask COFF objects.
A separately compiled `no_std` caller linked them with bundled `rust-lld` and
observed `43 + (-4 + 3) == 42` and `-1 & (-8 | 3) == -5`. This native probe
initially exposed and then regression-tested the required narrow signed-constant
sign extension at the code-generation boundary.
An exhaustive-return replacement mapped to pinned
`tests/ui/expr/if/if-check.rs` now follows its `else if` shape. It emitted a
deterministic 345-byte COFF object and 736-byte ELF object. Independent `no_std`
callers selected the first, both middle, and final return paths on their native
hosts. The zero-valued first path would divide by zero if selection leaked into
either later division, proving ordered lazy execution. The linked Windows and
Linux processes both exited successfully.
A non-exhaustive chain mapped to the returning `else if` fallthrough in pinned
`tests/ui/expr/weird-exprs.rs` emitted a deterministic 262-byte COFF object and
656-byte ELF object. Independent `no_std` callers selected the first return,
the second return, and the ordinary tail. Passing zero to the first branch
would trap if either later division executed, proving that successful early
return prevents both later branch and tail evaluation on both hosts.
A guarded-mutation replacement mapped to pinned
`tests/ui/consts/const-eval/issue-64970.rs` emitted a deterministic 259-byte
COFF object and 656-byte ELF object. Independent `no_std` callers selected the
true assignment, false assignment, and a later conditional compound mutation.
The zero-valued true path would divide by zero if the false assignment executed;
all three paths returned the expected values on both native hosts.
A bounded mutation-chain replacement maps the ordered assignment behavior in
pinned `tests/ui/binding/if-let.rs` to original scalar Boolean conditions; it
does not claim `if let` or pattern support. Up to four guarded assignments and
an optional final `else` are represented without allocation. The unchanged
pinned test compiled on Windows and compiled and ran on Arch Linux WSL. MRML's
554-byte COFF and 944-byte ELF objects passed independent `no_std` callers on
the first, two middle, fallback, and two later fallthrough-mutation paths. The
zero-valued first path proves later division expressions remain unevaluated,
and a fifth guarded assignment is rejected with
`TooManyConditionalAssignmentBranches`.
Conditional assignment branches now contain up to four ordered scalar
assignments rather than exactly one. An original replacement maps this narrow
sequencing property to pinned `tests/ui/drop/dynamic-drop.rs`; allocation,
ownership, destructors, deferred initialization, general tuples, unwinding, and
coroutines are explicitly not claimed. The unchanged pinned editions 2015 and
2018 revisions compiled and ran on Windows, and edition 2015 compiled and ran
on Arch Linux WSL. MRML's 868-byte COFF and 1,264-byte ELF objects passed
independent `no_std` callers on six paths, covering ordered noncommutative
updates in first, middle, fallback, and later fallthrough blocks. The zero path
would divide by zero if an unselected later block executed.
The same branch storage now preserves a bounded source-ordered mixture of
assignments and discarded scalar expression statements. A fifth mixed action fails with
`TooManyConditionalBranchActions`. An additional original replacement maps
this narrow behavior to the unusual discarded block expressions in pinned
`tests/ui/expr/weird-exprs.rs`; the unchanged test compiled and ran with the
exact dated nightly on both hosts. MRML's 996-byte COFF and 1,392-byte ELF
objects passed independent `no_std` callers on six paths. The zero path has no
dangerous assignment, but would divide by zero if a later branch's discarded
expression leaked across selection. A selected discarded division-by-zero
expression is separately rejected during const evaluation, proving these
statements execute rather than disappear.
Value-return actions now share that ordered branch stream. Native lowering
checks each return against the declared function type and emits the normal
frame epilogue; const evaluation immediately propagates the selected value.
An original scalar replacement maps the expression/mutation/return order in
pinned `tests/ui/structs-enums/class-impl-very-parameterized-trait.rs`; structs,
methods, generics, formatting, and ownership are not claimed. The unchanged
pinned run-pass test compiled and ran with the exact dated nightly on both
hosts. MRML's 602-byte COFF and 992-byte ELF objects passed independent
`no_std` callers through first, middle, later-return, and ordinary fallthrough
paths. Passing zero would trap if either the unselected later expression or the
post-conditional tail executed. A Boolean return in an integer function is
rejected at native code generation.
Branch-local declarations now participate in that same action stream without
requiring an assignment action. Native lowering permits lexical shadowing,
addresses the newest binding, includes live branch slots in return cleanup, and
removes them before fallthrough; const evaluation applies the same scope
boundary while preserving mutations to enclosing locals. An original scalar
replacement maps the local-before-return order in pinned
`tests/ui/drop/drop-on-ret.rs`; strings, allocation, destructors, and drop
elaboration are explicitly not claimed. The unchanged pinned run-pass test
compiled and ran with the exact dated nightly on both hosts. MRML's 339-byte
COFF and 736-byte ELF objects passed independent nightly-built callers through
a shadowing early return and two ordinary fallthrough values. The selected
zero-valued call additionally proves the discarded division in the unselected
arm remains lazy.

Linux used native Arch Linux WSL2 `x86_64-unknown-linux-gnu` with the identical
nightly commit:

```bash
cargo test -p mrml-rustc -p mrml-rustc-driver --offline
cargo clippy -p mrml-rustc -p mrml-rustc-driver \
  --all-targets --no-deps --offline -- -D warnings
cargo run --release -p mrml-rustc-driver --bin mrml-rustc --offline -- \
  --emit elf64 --function answer answer.rs -o answer.o
$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld \
  -flavor gnu -shared -o libanswer.so answer.o
readelf -h -S -s answer.o
```

The 447 Linux library, conformance, rustc-nightly-replacement, and driver tests
passed. The driver emitted a 496-byte ELF64 relocatable object;
the bundled linker accepted it as shared-object input. `readelf` independently
reported five canonical sections, a global 11-byte `answer` function in `.text`,
and valid linked symbol/string tables.

The runtime-expression source emitted a 568-byte ELF64 object. Native nightly
linked that object into a Linux caller, which executed
`calculate(20, 24) == 42` successfully. This independently exercises System V
argument preservation and generated multiply, checked add, and divide paths.
Separate 600-byte checked and 520-byte wrapping narrow-integer ELF objects also
linked and executed successfully, returning 30 and zero for the corresponding
rustc-derived probes.
Unchecked narrow shift and typed Boolean comparison ELF objects were also linked
into native callers and executed successfully.
A 752-byte signed ELF artifact returned `-10` for the same negative arithmetic
probe, and a 528-byte wrapping artifact returned `i8::MIN` successfully.
The signed compound-constant slice emitted 560-byte add and 520-byte mask ELF
objects; an independent nightly-built Linux caller linked and executed both,
observing the same 42 and -5 results as Windows.
The Boolean-constant replacement emitted a 536-byte ELF object. Its independent
nightly-built caller exercised both false and true inputs successfully.
Unsigned integer `is_power_of_two` and `is_multiple_of` now work in constant
initializers and emitted runtime functions for every supported unsigned width.
The zero-divisor rule matches Rust, including `0.is_multiple_of(0) == true`,
while signed receivers and explicitly mismatched divisor types fail closed.
The complete inherent `u8` ASCII classification family now works in constants
and runtime functions: ASCII, alphabetic, uppercase, lowercase, alphanumeric,
digit, hexadecimal digit, punctuation, graphic, whitespace, and control-byte
predicates. Eleven independently emitted System V objects were linked into a
pinned-nightly caller and matched Rust for every byte from zero through 255.
Primitive signed and unsigned integers now support width-normalized
`wrapping_add`, `wrapping_sub`, and `wrapping_mul` in module constants and
runtime functions. The same syntax remains type-directed for raw pointers, so
their existing `wrapping_add` and `wrapping_sub` element offsets are preserved.
Four emitted System V integer objects matched pinned Rust across ordinary and
overflowing narrow, 32-bit, and 64-bit boundary cases.
Stable `wrapping_add_signed`, `wrapping_sub_signed`,
`wrapping_add_unsigned`, and `wrapping_sub_unsigned` require the corresponding
same-width opposite-signed argument and wrap the mathematical result to the
receiver type. Four 512- to 520-byte System V objects matched pinned Rust across
eight narrow and full-width cross-sign boundaries, including both signed and
unsigned extrema.
Stable primitive `strict_add`, `strict_sub`, and `strict_mul` preserve matching
signed or unsigned receiver types and trap on overflow independently of the
runtime overflow-check setting. Three System V objects emitted explicitly with
`-C overflow-checks=no` matched ordinary pinned-Rust results; independent
narrow signed/unsigned and full-width overflow probes all trapped.
Stable `strict_add_signed`, `strict_sub_signed`, `strict_add_unsigned`, and
`strict_sub_unsigned` require the corresponding same-width opposite-signed
argument and preserve the receiver type. Constants through 128 bits use exact
mathematical bounds, while native 8- through 64-bit operations trap on overflow
independently of the runtime overflow-check setting. Four 536- to 544-byte
System V objects matched pinned Rust across eight narrow and full-width
cross-sign boundary cases. Separate signed-add, signed-subtract, unsigned-add,
and unsigned-subtract overflow callers all terminated at MRML trap instructions.
Stable `strict_div`, `strict_rem`, `strict_div_euclid`, and
`strict_rem_euclid` likewise retain exact receiver types and ignore disabled
overflow checks. Five unchecked-mode System V objects matched truncating and
Euclidean pinned-Rust results. Independent probes proved divisor-zero and every
signed minimum/negative-one division or remainder form traps.
Stable `strict_neg` supports signed and unsigned primitive receivers. It
returns ordinary signed negations and unsigned zero, while signed minima and
every nonzero unsigned value overflow. Two unchecked-mode System V objects
matched pinned Rust for representable values, and independent signed and
unsigned overflow probes trapped.
Stable `strict_shl(u32)` and `strict_shr(u32)` preserve ordinary signed and
unsigned shift behavior below the receiver width and trap at or above it even
when overflow checks are disabled. Two unchecked-mode System V objects matched
pinned Rust from zero through width-minus-one, including signed arithmetic
right shift; exact-width and `u32::MAX` distance probes trapped.
Stable `strict_pow(u32)` uses bounded exponentiation by squaring while forcing
overflow checks for every intermediate product. Two unchecked-mode System V
objects matched pinned Rust for exponent zero, signed parity, ordinary and
large valid powers; narrow unsigned and full-width signed overflow probes
trapped.
Stable signed primitive `strict_abs` returns representable absolute values and
traps on the receiver minimum independently of overflow settings. Its
narrow-width lowering uses explicit receiver-range validation rather than the
64-bit `neg` overflow flag, also correcting checked ordinary narrow `abs`.
Unchecked i8 and i64 System V objects matched pinned Rust across signs, zero,
extrema-adjacent values, and both minimum-value probes trapped.
Signed integers additionally support `wrapping_neg` and `wrapping_abs` in
constants and runtime functions. Both preserve the receiver width, including
the two's-complement minimum value whose mathematical negation is not
representable; unsigned and Boolean receivers fail closed.
Four emitted System V objects matched pinned Rust for positive, negative, zero,
and minimum/maximum values at 8, 16, 32, and 64 bits.
Primitive signed and unsigned integers also support `wrapping_div` and
`wrapping_rem`. Division by zero retains Rust's trap behavior, while signed
minimum divided by negative one wraps to the minimum and its remainder is zero
instead of taking x86-64's division-overflow fault.
Four emitted System V objects matched pinned Rust across signed and unsigned
ordinary cases and the signed minimum/negative-one exception at narrow and
full widths.
Primitive signed and unsigned integers support `div_euclid` and `rem_euclid`
with exact-type arguments in constants and runtime functions. Signed negative
remainders are corrected into the nonnegative Euclidean range with the quotient
adjusted by divisor sign; zero divisors and signed minimum divided by negative
one trap.
Four System V objects matched pinned Rust across every operand-sign pairing,
unsigned extrema, and a signed-minimum ordinary divisor. Separate zero-divisor
and signed-overflow probes terminated with MRML trap instructions.
The `wrapping_div_euclid` and `wrapping_rem_euclid` variants retain identical
zero-divisor and signed correction behavior, but map signed minimum divided by
negative one to the minimum quotient and zero remainder instead of trapping.
Two System V objects matched pinned Rust across all divisor/dividend sign
pairings and both results of the signed minimum/negative-one exception.
Signed integers support `signum`, `is_positive`, and `is_negative` in constants
and runtime functions. `signum` preserves the receiver type and produces
negative one, zero, or one; both predicates return Boolean and treat zero as
neither positive nor negative. Unsigned and Boolean receivers fail closed.
Four emitted System V objects matched pinned Rust across zero, extrema, and
ordinary negative and positive values at 8, 16, 32, and 64 bits.
Signed integer `abs` works in constants and runtime functions. Constant
evaluation rejects the unrepresentable minimum magnitude; checked runtime code
traps on that input, while `-C overflow-checks=no` retains Rust's wrapping
minimum result. Unsigned and Boolean receivers fail closed.
Four checked and unchecked System V objects matched pinned Rust across ordinary
values and unchecked minimum inputs at 8, 16, 32, and 64 bits.
Signed integer `saturating_neg` and `saturating_abs` return the signed maximum
for the minimum input and otherwise perform ordinary negation or magnitude.
Their result is independent of runtime overflow-check settings; unsigned and
Boolean receivers fail closed.
Four emitted System V objects matched pinned Rust across minima, zero, ordinary
negative and positive values, and maxima at 8, 16, 32, and 64 bits.
Primitive signed and unsigned integers support `saturating_add`,
`saturating_sub`, `saturating_mul`, and `saturating_div` in constants and runtime
functions. Division by zero retains Rust's trap behavior, while signed minimum
divided by negative one saturates to the signed maximum.
They require an argument of the receiver's exact type and clamp overflow or
underflow to that type's minimum or maximum independently of runtime
overflow-check settings.
Four emitted System V objects matched pinned Rust across zero, ordinary signed
and unsigned products, narrow saturation, 64-bit high-half overflow, both
signed saturation directions, and the signed minimum multiplied by negative
one.
Stable `saturating_add_signed`, `saturating_sub_signed`,
`saturating_add_unsigned`, and `saturating_sub_unsigned` require the
corresponding same-width opposite-signed argument and clamp to the receiver's
numeric bounds. Constants through 128 bits and native 8- through 64-bit paths
select the lower or upper bound from both the operation and argument sign.
Four 552- to 568-byte System V objects matched pinned Rust across twelve exact,
underflowing, and overflowing cross-sign boundary cases.
Two additional System V objects matched pinned Rust for ordinary signed and
unsigned division, mixed signs, extrema, and signed minimum divided by negative
one; the zero-divisor probe terminated with MRML's trap instruction.
Signed integer `unsigned_abs` returns the corresponding same-width unsigned
type in constants and runtime functions, including `isize -> usize`. It accepts
every signed minimum without overflow and rejects unsigned or Boolean receivers
and signed return-type mismatches.
Four emitted System V objects matched pinned Rust across ordinary values and
signed minima at 8, 16, 32, and 64 bits.
Primitive integer `abs_diff` requires matching receiver and argument types. It
returns the receiver type for unsigned integers and the corresponding unsigned
type for signed integers, selecting subtraction order before arithmetic so the
full signed minimum-to-maximum distance remains representable.
Four emitted System V objects matched pinned Rust for both operand orders,
equal inputs, unsigned boundaries, and signed extrema across 8 through 64 bits.
Stable primitive integer `midpoint` requires matching receiver and argument
types and returns the same type. Its overflow-free bitwise average rounds
toward zero for signed values, including odd negative sums, without widening
or allocating. Four linked System V objects matched pinned Rust across operand
orders, exact and fractional averages, mixed signs, and narrow/full-width
extrema.
Primitive `min`, `max`, and `clamp` likewise require exact matching
integer types in constants and runtime functions. Their comparisons honor
signed ordering, and `clamp` traps when its minimum exceeds its maximum before
selecting either bound.
Primitive `div_floor` supports ordinary unsigned division and the pinned
nightly's `int_roundings` signed form. Signed results round toward negative
infinity when a nonzero remainder has the opposite sign from the divisor;
division by zero and signed minimum divided by negative one trap. Signed 8- and
64-bit System V objects of 560 bytes each matched pinned Rust across every
operand-sign pairing, zero, and signed minima with ordinary divisors.
Primitive `div_ceil` supports stable unsigned integers and the pinned nightly's
`int_roundings` signed form. It returns the quotient rounded toward positive
infinity, requires a same-typed divisor, and traps on division by zero or signed
minimum divided by negative one. Its native lowering derives the rounding
increment from the hardware remainder and operand signs without risking an
overflowing numerator adjustment. Signed 8- and 64-bit System V objects of 560
and 552 bytes matched pinned Rust across all operand-sign pairings, zero, and a
signed minimum with an ordinary divisor, in addition to the existing unsigned
coverage.
Primitive `next_multiple_of` supports stable unsigned integers and the pinned
nightly's `int_roundings` signed form. Positive signed divisors round upward and
negative divisors round downward to the corresponding multiple; negative one
accepts the signed minimum without division overflow. Constant overflow is
rejected; checked runtime objects trap, while `-C overflow-checks=no` objects
wrap at receiver width. Signed 8- and 64-bit System V objects of 632 and 584
bytes matched pinned Rust across every operand-sign pairing, zero, extrema, and
the signed-minimum/negative-one exception, in addition to the existing
unsigned overflow and divisor-zero coverage.
Primitive signed and unsigned integers also support `rotate_left(u32)` and
`rotate_right(u32)` in constants and runtime functions. Native 8-, 16-, 32-,
and 64-bit objects matched pinned Rust for zero, sub-width, exact-width, and
multiple-width distances while retaining signed values as raw bit patterns.
The `wrapping_shl(u32)` and `wrapping_shr(u32)` methods apply the distance modulo
the receiver width in constants and runtime functions. Right shifts preserve
Rust's arithmetic behavior for signed receivers and logical behavior for
unsigned receivers; non-`u32` distances fail closed.
Four emitted System V objects matched pinned Rust through zero, width-adjacent,
hardware-mask-adjacent, and `u32::MAX` distances across narrow and full-width
signed and unsigned receivers.
The stable `unbounded_shl(u32)` and `unbounded_shr(u32)` methods retain ordinary
shift results below the receiver width. At or above that width, left shifts and
unsigned right shifts return zero, while signed right shifts return zero or
negative one according to the receiver's sign.
Four System V objects matched pinned Rust across narrow and full widths, both
signed-right input signs, and distances immediately around the width through
`u32::MAX`.
Primitive signed and unsigned integers support `wrapping_pow(u32)` through a
bounded-register exponentiation-by-squaring runtime loop and the equivalent
width-normalized constant evaluator. Exponent zero returns one, and each
intermediate product wraps to the receiver width.
Four emitted System V objects matched pinned Rust across signed and unsigned
8-, 16-, 32-, and 64-bit bases with zero through `u32::MAX` exponents.
The parallel `saturating_pow(u32)` method clamps every intermediate product to
the receiver's signed or unsigned range. It preserves exponent-zero and
negative-base parity semantics in both constants and runtime functions.
Four System V objects matched pinned Rust across 8-, 16-, and 64-bit signed and
unsigned bases, zero and maximum exponents, ordinary products, and positive or
negative saturation.
Ordinary primitive integer `pow(u32)` uses the same bounded exponentiation loop
while honoring `-C overflow-checks`: checked objects trap on the first
unrepresentable intermediate product and unchecked objects wrap at receiver
width. Constant powers always reject overflow.
Two checked and two unchecked System V objects matched pinned Rust across
ordinary signed and unsigned powers, exponent zero, single-power extrema,
wrapping overflow, and an explicit checked-overflow trap.
The unary `swap_bytes`, `reverse_bits`, `to_be`, and `to_le` methods now retain
the receiver width and signed bit pattern in constants and native functions.
The current little-endian targets use byte reversal for big-endian conversion
and identity for little-endian conversion. Five linked System V artifacts
matched pinned Rust across 8-, 16-, 32-, and 64-bit boundary values.
The `count_ones`, `count_zeros`, `leading_zeros`, `trailing_zeros`,
`leading_ones`, and `trailing_ones` methods
evaluate each signed or unsigned receiver in its own width and return `u32`, as
Rust requires. Six native objects matched pinned Rust for zero, all-ones,
sign-bit, and sparse-bit cases, including the full-width zero results and
signed narrow representation masks.
Stable unsigned `bit_width` and signed or unsigned `isolate_highest_one` and
`isolate_lowest_one` work in constants and runtime functions from 8 through 64
bits. Zero remains zero for both isolation methods and has width zero; other
values retain exactly their highest or lowest set bit or report the highest
set-bit index plus one. Signed isolation operates on the primitive's raw
two's-complement representation, so a negative value's highest isolated bit is
its sign bit.
Signed and unsigned primitive `from_be` and `from_le` associated functions
accept one exact-type integer in constants and runtime functions. On the
supported little-endian targets, `from_be` reverses the primitive's bytes while
`from_le` preserves them; both retain the declared signed representation.
The parallel `from_be_bytes`, `from_le_bytes`, and `from_ne_bytes` constructors
require an exact `[u8; size_of::<Self>()]` value. Fixed-array literals and native
array parameters are packed without allocation; big-endian input reverses the
packed word on the supported little-endian targets, while little and native
orders preserve it. Constant evaluation supports the full 16-byte `u128` and
`i128` forms even though native scalar exports remain bounded to 64 bits.
The inverse `to_be_bytes`, `to_le_bytes`, and `to_ne_bytes` methods produce an
exact `[u8; size_of::<Self>()]` expression. Native 8- through 64-bit receivers
may return that fixed array, store it through existing array paths, or index an
individual byte; explicitly typed constant receivers use the same ordering in
the bounded IR evaluator.
All twelve primitive integer types expose their stable `MIN`, `MAX`, and `BITS`
associated constants. `MIN` and `MAX` retain the named primitive type, including
the target pointer width and signed two's-complement boundary, while `BITS`
produces `u32`. Values through 64 bits reach native functions directly; `u128`
and `i128` boundaries participate in constant evaluation and may be explicitly
cast into a supported x86-64 ABI result. The legacy stable `min_value()` and
`max_value()` associated functions resolve to the same typed boundaries and
require an empty argument list.
Six 504- to 568-byte System V objects matched pinned Rust across zero, adjacent
low bits, sparse patterns, both width boundaries, and unsigned maxima.
Pinned-nightly unsigned `carryless_mul`, `extract_bits`, and `deposit_bits`
support exact-type operands in constants and runtime functions. Carryless
multiplication uses truncated polynomial arithmetic over bits; extraction packs
mask-selected source bits toward the least-significant end, while deposition
scatters the receiver's low bits into mask-selected positions. Six 552- to
576-byte System V objects matched pinned Rust at 8 and 64 bits across zero and
full masks, sparse high/low masks, mixed values, and unsigned maxima.
Pinned-nightly unsigned `funnel_shl` and `funnel_shr` combine two same-width
integers across an exact `u32` distance in constants and runtime functions.
Distances must be smaller than the receiver width; zero selects the left input
for `funnel_shl` and the right input for `funnel_shr`, while out-of-range
runtime distances trap.
Stable same-width `cast_signed` and `cast_unsigned` preserve the receiver's bit
pattern while changing signedness in constants and runtime functions. The
pinned-nightly `saturating_cast_signed`/`saturating_cast_unsigned` variants
clamp unsigned values above the signed maximum or negative signed values to
zero; `strict_cast_signed` and `strict_cast_unsigned` trap for those same
out-of-range inputs. All variants require the exact opposite-signed integer of
the same width as their result.
Pinned-nightly signed `clamp_magnitude` accepts the exact unsigned counterpart
as its limit and clamps runtime values to the symmetric inclusive range around
zero. Limits above the signed maximum leave the receiver unchanged, including
the signed minimum. The method remains runtime-only, matching its non-const
definition in the pinned toolchain.
Unsigned primitives support stable `next_power_of_two` and pinned-nightly
`wrapping_next_power_of_two`. Zero maps to one; checked runtime objects trap
when the rounded power exceeds the receiver width, while unchecked and explicit
wrapping forms return zero. Constant ordinary calls always reject overflow.
Checked, unchecked, and explicit-wrapping System V objects matched pinned Rust
across zero, exact and adjacent powers, and narrow/full-width overflow.
The stable `ilog2`, `ilog10`, and `ilog` methods return `u32` for signed and
unsigned primitive receivers in constants and runtime functions. They round
down through a bounded division loop and trap for zero, nonpositive signed
receivers, or radices below two.
Four System V objects matched pinned Rust across exact powers, adjacent values,
extrema, and arbitrary radices; three invalid-domain probes trapped.
Stable signed and unsigned primitive `isqrt` returns the floor of the integer
square root in constants and runtime functions. A bounded restoring algorithm
uses only fixed-width integer registers, and signed negative inputs trap as
pinned Rust requires. Four linked System V objects matched pinned Rust across
zero, exact squares, adjacent values, and narrow/full-width extrema; an
independent signed-negative probe trapped with an illegal instruction.
The cast/conditional slice emitted 552-byte signed and 520-byte Boolean ELF
objects. A separate nightly-built caller linked and executed both successfully.
The compound-comparison replacement emitted a 552-byte ELF object and passed
both rows through an independent nightly-built Linux caller.
The first const-call replacement emitted a 520-byte ELF object and produced 42
and 50 through an independent nightly-built caller.
The signed const-call replacement emitted a 560-byte ELF object and produced 42
and -42 through an independent nightly-built caller.
The nested const-call replacement emitted a 544-byte ELF object. Its
independent nightly-built caller observed 22 and 42 and exited normally.
The composed const-call replacement emitted a 544-byte ELF object and passed
the same 42 and 43 assertions through an independent native caller.
The Boolean const-call replacement emitted a 544-byte ELF object and passed
the same assertions through an independent native caller.
The recursive GCD replacement emitted a 544-byte ELF object and passed native
results 6 and 42.
The statement-bodied const-call replacement emitted a 560-byte ELF object and
passed results 42 and -42. The native Linux debug driver also compiled the same
source successfully.
The mutable-local replacement emitted a 544-byte ELF object and passed the same
42 and 43 native results.
The const-loop replacement emitted a 544-byte ELF object and passed the same
native results.
The conditional-return const-loop replacement emitted a 552-byte ELF object
and passed native results 42 and 43 through an independent nightly-built caller.
The runtime prime emitted an 824-byte ELF object and passed the same 113/117
Boolean return-path assertions through an independent System V caller.
The unconditional runtime loop-return probe emitted a 536-byte ELF object and
returned 42 through an independent nightly-built System V caller.
The ordered-statement const replacement emitted a 544-byte ELF object and
passed the same independent 42/43 assertions.
The runtime ordered-statement replacement emitted a 656-byte ELF object and
passed the same zero/42 sequencing assertions through a System V caller.
The post-loop return/assignment replacement emitted a 704-byte ELF object and
passed the same 4/7 path assertions through an independent System V caller.
The consecutive-loop replacement emitted a 688-byte ELF object and passed the
same increasing-bound, already-past, and zero-iteration assertions through an
independent System V caller. The unchanged pinned nightly oracle also compiled
and ran successfully in this verification pass.
The post-loop local-binding replacement emitted a 688-byte ELF object and
passed the same zero-iteration and iterated assertions through an independent
System V caller. An original scalar source passed the same assertions with the
pinned nightly before MRML coverage was claimed.
The guarded local-binding replacement emitted a 616-byte ELF object and passed
the same early-return trap-skipping and ordinary fallthrough assertions. The
original scalar oracle produced the same results with the pinned nightly.
The guarded-mutation replacement emitted a 632-byte ELF object and passed the
same trap-skipping and fallthrough assertions. Both its original scalar oracle
and the unchanged pinned `consts/control-flow/basics.rs` test passed under the
reference nightly.
The guarded iterative-Fibonacci replacement emitted a 768-byte ELF object and
passed the identical four results through an independent System V caller. Its
original const oracle also compiled, evaluated, and ran under the pinned
nightly.
The alternating-guard replacement emitted a 680-byte ELF object and passed the
same three control-flow paths through an independent System V caller. Its
compile-time oracle produced 1, 2, and 42 under the pinned nightly.
The post-loop alternating-guard replacement emitted an 840-byte ELF object and
passed the identical four branch/iteration cases. Its compile-time oracle
produced the same results under the pinned nightly.
The scalar-block replacement emitted a 592-byte ELF object and passed the same
lazy branch assertions. The original scalar oracle and unchanged pinned
`tests/ui/consts/const-block.rs` run-pass test both executed successfully;
MRML claims only their scalar integral and unit block forms.
The closed inline-const replacement emitted a 664-byte ELF object and passed
the same selected, fallback, and skipped-division assertions through an
independent nightly-built Linux caller.
The paired short-circuit ELF objects passed the same division-by-zero skip and
ordinary evaluation probes through a native Linux caller.
The literal-driven pair likewise linked into and passed a native Linux caller.
The immutable-static shift object also linked into a native caller and returned
160.
A seventh-argument System V function consumed its first stack argument and
returned 42 through a native caller.
The cast-distance shift emitted a 528-byte ELF64 object and returned 10 through
a native caller.
The suffix-aware negative cast/shift emitted a 504-byte ELF64 object and
returned the same platform-width value through that caller.
The typed-local div/remainder probe emitted a 496-byte ELF64 object and returned
6 through a native caller.
Parameterized runtime-local probes emitted 576-byte arithmetic and 544-byte
Boolean ELF64 objects and passed the identical native caller assertions.
The mutable-local XOR-swap and parameterized mutation probes emitted 496-byte
and 560-byte ELF64 objects. A native nightly-compiled Linux caller observed the
same results, 3 and 241.
The inferred `i32` mutation probe emitted a 648-byte ELF64 object and returned
42 through an independently nightly-compiled Linux caller.
The corresponding runtime `if` probes emitted 616-byte and 552-byte ELF64
objects and passed the identical four native branch assertions.
The tail-return probe emitted a 496-byte ELF64 object and preserved the same two
values through a native Linux caller.
The conditional-return probe emitted a 584-byte ELF64 object and passed both
native branch assertions with the System V frame layout.
The scalar counter loop emitted a 576-byte ELF64 object and passed the identical
zero, one, and million-iteration assertions.
The loop-local action probe emitted an 816-byte ELF64 object and passed the same
zero-, one-, break-, continue-, completion-, and 60,000-iteration assertions as
its Windows counterpart through an independent nightly-built System V caller.
The conditional-loop-block probe emitted a 920-byte ELF64 object and passed the
same conditional continue, conditional break, completion, and long-iteration
assertions through an independent nightly-built System V caller.
The ordered summation loop emitted a 608-byte ELF64 object and passed the same
three summation assertions.
The const-qualified addition function emitted a 512-byte ELF64 object and
returned 42 through a native Linux caller.
The conditional-break counter emitted a 616-byte ELF64 object and passed the
same three exit-path assertions.
The corresponding explicit-continue, immediate-loop-break, and
conditional-loop-break objects were 592, 504, and 576 bytes. A native
nightly-compiled caller passed the same zero, million-iteration, immediate-exit,
and conditional-exit assertions.
The ordered interleaved-control ELF64 object was 728 bytes and passed the same
zero, odd, even, skipped-mutation, and million-iteration assertions.
The corresponding integer and Boolean break-value ELF64 objects were 528 and
512 bytes and passed the identical independent caller assertions.
The competing-break ELF64 object was 592 bytes and passed the same lazy
division-by-zero skip and selected-fallback assertions.
The corresponding implicit-unit loop object was 496 bytes and returned normally
through the independent Linux void call.
The corresponding equality objects were 520, 528, and 496 bytes on ELF64 and
passed the identical native truth-table assertions.
The corresponding Boolean ordering and bitwise ELF64 objects were 520, 512,
512, and 512 bytes and passed the same native truth-table assertions.
The Boolean compound and loop-parity ELF64 objects were 584 and 624 bytes and
passed the identical truth-table and iteration assertions.

The exact constant array-element identity milestone passed all 695 compiler and
driver tests on Windows gnullvm and all 695 in release mode on native Arch Linux
WSL, plus warnings-denied Clippy on both hosts. Its adversarial unit test proves
that an owned `values[1]` read and assignment retain `ArrayElement(1)`, a
`values[index]` assignment remains summary `Index`, and an out-of-bounds exact
projection fails validation. Existing native array-index replacements preserve
the differential COFF/ELF execution gate. This is precise place evidence only:
it neither adds array move paths nor permits rustc-rejected indexed moves from
non-`Copy` arrays.

The mutable-reference tuple-field milestone passed all 697 compiler and driver
tests on Windows gnullvm and all 697 in release mode on native Arch Linux WSL,
plus warnings-denied Clippy on both hosts. Bounded tuple elements can now retain
scalar values, thin scalar references, or scalar raw pointers without admitting
fat references, arrays, nested tuples, or a public tuple ABI. Inferred
`&mut` fields follow the exact pinned rustc oracle: a field can move once, a
sibling remains usable, a whole-tuple move requires every field initialized,
and an exact field write restores tuple completeness. The accepted probe emits
both COFF and ELF64 objects; duplicate field moves fail with
`RuntimeUseAfterMove`. The Arch release gate initially exposed a fixed-state
stack regression from an overbroad reference target; narrowing the retained
tuple reference to its actual scalar scope restored the ordinary gate without
raising stack limits. Implicit coercion reborrows remain a loan-analysis
dependency and are not claimed as moves.

The direct loan-identity foundation at `f51a785` passed all 697 compiler and
driver tests on Windows gnullvm and all 697 in release mode on native Arch Linux
WSL, plus warnings-denied Clippy on both hosts. A derived, allocation-free view
links each tested direct shared borrow, mutable borrow, and direct mutable
reborrow to the initialized reference local, borrowed move path, borrow kind,
and issuance-effect index; its stable ID is the dense initialization index.
Parameter initialization does not derive a loan. This is issuance identity
only: it does not claim complete loan discovery, liveness, invalidation,
conflict checking, regions, NLL, or acceptance of overlapping aliases.

Security review searched both crates for direct `std`/`alloc` imports and unsafe
blocks and found none. `cargo tree -p mrml-rustc-driver --offline` showed only
original workspace crates. Adversarial tests cover truncated output, capacity
exhaustion, nesting limits, malformed delimiters and literals, integer and
offset overflow, invalid names, unresolved symbols, invalid shifts, division by
zero, duplicate definitions, and source-bounded diagnostics. The driver caps
source input at 1 MiB and refuses an already existing output path. No claim is
made that a compromised host protects compiler input or output.

Pinned-nightly generic integer `truncate::<T>`, `saturating_truncate::<T>`, and
`widen::<T>` calls are accepted for the exact same-signedness source/target
pairs implemented by that toolchain's `TruncateTarget` and `WidenTarget`
traits. Constant evaluation and x86-64 code generation preserve truncation,
saturation, signed extension, and unsigned extension semantics; unsupported
width, signedness, and pointer-sized pairs are rejected as type mismatches.

Pinned-nightly generic `saturating_cast::<T>`, `wrapping_cast::<T>`, and
`strict_cast::<T>` support every integer source/target pair exposed by
`BoundedCastFromInt` and `CheckedCastFromInt`. Runtime and constant paths apply
numeric-bound saturation, Rust `as` wrapping, and unconditional strict overflow
traps across signedness and width changes. Runtime expressions can additionally
consume the `Option`-returning `checked_cast::<T>` through the supported option
consumers described below. The same consumers accept `checked_cast_signed` on
unsigned integers and `checked_cast_unsigned` on signed integers. Unsafe
functions can additionally use
`unchecked_cast::<T>` for every integer pair; safe functions and constants
reject it, and valid callers receive the direct representability-assuming cast.
Pinned-nightly `checked_truncate::<T>` is also available through those consumers
for every same-signedness `TruncateTarget` pair, returning `None` when the value
does not fit the same-size-or-smaller target.

Unsafe functions can use the stable `unchecked_add`, `unchecked_sub`,
`unchecked_mul`, `unchecked_neg`, `unchecked_shl`, and `unchecked_shr` integer
methods and pinned-nightly `unchecked_div_exact`, `unchecked_shl_exact`,
`unchecked_shr_exact`, `unchecked_funnel_shl`, `unchecked_funnel_shr`, and
`unchecked_disjoint_bitor`. They emit the direct
unchecked scalar operation for callers that uphold Rust's documented
preconditions. Calls from safe functions, constant initializers, invalid
receiver/argument types, invalid arity, unsigned negation, and signed disjoint
bit-or are rejected; unsafe blocks are not accepted as a substitute because
this bounded parser does not yet represent their safety context.

Runtime integer expressions can consume stable `checked_add`, `checked_sub`,
`checked_mul`, `checked_div`, `checked_rem`, `checked_div_euclid`,
`checked_rem_euclid`, `checked_neg`, `checked_abs`,
`checked_shl`, `checked_shr`, `checked_pow`, and unsigned
`checked_next_power_of_two`, plus `checked_ilog`, `checked_ilog2`, and
`checked_ilog10`, and `checked_next_multiple_of`, pinned-nightly
`checked_div_exact`, generic
`checked_cast::<T>`, and same-width checked sign-cast results with
`Option::unwrap_or`, `Option::unwrap_or_else`, and
`Option::unwrap_or_default`, extract them with `Option::unwrap` or
`Option::expect`, or extract them in an unsafe function with
`Option::unwrap_unchecked`; callers can observe them with `Option::is_some` and
`Option::is_none`, `Option::is_some_and`, and `Option::is_none_or`, or map them
with `Option::map_or`, `Option::map_or_else`, or `Option::map_or_default`.
Non-overflowing arithmetic, valid divisions and remainders,
exact nonzero divisions, and representable casts return their scalar value or
`Some`; inexact exact-divisions, zero divisors, signed `MIN / -1`, and
signed `MIN` negation/absolute-value, and out-of-range casts select the eagerly
evaluated fallback, zero default, or `None` without trapping.
Unsigned `checked_neg` succeeds only for zero and otherwise selects the same
fallback/default/predicate outcome.
Shift counts use Rust's required `u32` type and counts at least as large as the
receiver width likewise select the fallback, zero default, or `None`.
Checked exponentiation uses exponentiation by squaring, accepts Rust's required
`u32` exponent, and rejects overflow at either accumulator multiplication or
factor squaring.
Checked next-power-of-two accepts zero as one and returns `None` when rounding
would exceed the unsigned receiver's highest representable power of two.
Checked logarithms return a `u32` through the same consumers. Zero or negative
receivers and generic radices below two produce `None`; positive receivers use
integer floor-logarithm semantics.
Checked Euclidean division uses a nonnegative remainder for signed receivers,
while retaining the checked zero-divisor and signed `MIN / -1` behavior.
Checked next-multiple preserves Rust's signed rounding semantics and returns
`None` for a zero divisor or an unrepresentable rounded result.
Unsigned receivers additionally support `checked_add_signed` and
`checked_sub_signed` with their exact same-width signed counterparts, including
signed `MIN`, unsigned underflow, and unsigned overflow boundaries.
Signed receivers support the complementary `checked_add_unsigned` and
`checked_sub_unsigned` methods, using exact distance-to-`MIN`/`MAX` checks even
when a `u64` operand cannot be represented as signed.
Signed `checked_isqrt` returns the integer floor root for nonnegative receivers
and `None` for negatives, sharing the direct `isqrt` backend without its trap.
Unsigned `checked_signed_diff` returns the same-width signed counterpart when
the mathematical difference lies within its complete `MIN..=MAX` range.
Signed and unsigned division receivers
require a same-type divisor, and explicit fallbacks match the option's result
type. `Option::unwrap` returns the checked value when present and reaches the
compiler's shared invalid-operation trap when the checked operation produces
`None`. `Option::expect` accepts a string literal or runtime `&str` message,
evaluates a runtime message after the checked receiver, and uses the same
bounded trap because this compiler does not embed diagnostic formatting in
generated freestanding objects. String literals now have their own expression
node and type as immutable `&str`; other runtime uses remain rejected until
object data and relocation emission are implemented.
Unsafe `Option::unwrap_unchecked` returns the producer's candidate directly
without testing its validity flag; safe functions reject the call, and callers
must uphold Rust's `Some` precondition. These consumers share one
value-plus-validity emitter while
direct `Option` returns, option locals, other option consumers, and constant
evaluation remain outside this milestone until their enum ABI and value
representation are implemented.

Checked integer options additionally support lazy `Option::unwrap_or_else`
with a bounded zero-argument closure. The closure body may capture existing
runtime parameters and locals through the compiler's lexical environment. It
is emitted only on the `None` edge, so traps and other checked evaluation in a
fallback remain skipped for `Some`. Zero-argument closures now have a distinct
expression node; using one as a first-class runtime value remains unsupported
until closure layout and callable ABI support are implemented.

Bounded one-argument closures support checked-option `is_some_and` and
`is_none_or`. The compiler substitutes the closure parameter with a typed
candidate-stack node, preserving exact cast, logarithm, signed-difference, and
ordinary producer result types without extending its function-local lifetime.
Captured parameters and locals remain available. Predicate bodies execute only
for `Some`; `None` returns `false` for `is_some_and` and `true` for `is_none_or`.

Checked integer options can be filtered by a bounded predicate before
`is_some` or `is_none`. Matching Rust's API, the filter closure receives an
immutable reference to the candidate rather than a copied value; the compiler
backs that borrow with the candidate's temporary stack slot, limits it to the
lazy predicate evaluation, and preserves exact producer integer types. An
existing `None` skips the predicate, while a false result changes `Some` to
`None`. Filtered options, including multiple filters in source order, feed the
same unwrap, expect, unsafe unchecked extraction, fallback, closure-predicate,
and mapping consumers as direct checked producers.

Checked integer options support lazy `Option::map` as a composable producer.
Its one-argument closure runs only for `Some`, may capture parameters and
locals, and may change the candidate to another built-in integer type. Mapped
options preserve `None` without evaluating the closure and can be mapped or
filtered again before reaching any existing checked-option terminal consumer.
Non-integer mapped option payloads remain outside the current scalar option
representation.

Checked integer options support lazy `Option::and_then` composition. Its typed
one-argument closure runs only for `Some` and must return another supported
checked-integer option producer. The outer and inner validity flags are
composed without materializing Rust's public enum ABI, and the resulting
integer payload type may differ from the input type. Chained producers feed the
same maps, filters, inspections, predicates, and terminal consumers as direct
checked operations.

Checked integer options also support lazy `Option::or_else`. Its bounded
zero-argument closure executes only for `None`, may capture runtime parameters
and locals, and must return another supported checked producer with the same
integer payload type. A present outer value is preserved without evaluating
the fallback, while a fallback failure retains `None` for later composition or
terminal consumption.

Checked integer options support eager `Option::or` for a second supported
checked producer with the same integer payload type. The receiver and
alternative are evaluated in source order regardless of receiver validity,
then the receiver is selected when present and the alternative otherwise.
This preserves Rust's eager argument semantics while retaining the internal
value-plus-validity representation for further composition.

Checked integer options support eager `Option::xor` between two checked
producers with the same integer payload type. Both operands are evaluated in
source order, and the result remains present only when exactly one operand is
present. If both succeed or both fail, the result is `None`; otherwise the
successful operand's value remains available to later option combinators.

Checked integer options support eager `Option::and` with a second checked
producer. Both operands execute in source order even when the receiver is
`None`. A present receiver yields the alternative option; an absent receiver
forces `None` after the alternative has executed. The alternative may use a
different built-in integer payload type, and that type is retained through
later option combinators and terminal consumers.

Boolean receivers can construct integer options through eager `bool::then_some`
and lazy `bool::then`. `then_some` evaluates its integer argument before using
the receiver as the option validity flag. `then` requires a bounded
zero-argument closure and executes its integer body only when the receiver is
true. Both producers retain the payload's concrete integer type and compose
with the existing maps, filters, predicates, and terminal consumers.

Checked integer options also support composable `Option::inspect`. Its closure
receives an immutable reference to a present candidate, must return unit, and
is skipped for `None`. After inspection the original candidate, integer type,
and validity are preserved for subsequent maps, filters, or terminal consumers.

Checked-option `map_or` evaluates its default eagerly, then executes its
bounded one-argument mapping closure only for `Some`. The closure may capture
parameters and locals, and its mapped result has an independent compatible
one-word scalar type rather than being forced to the checked producer's type.
Closures remain compiler-internal expression nodes rather than first-class
runtime values.

Checked-option `map_or_else` makes both output paths lazy. Its zero-argument
default closure executes only for `None`, while its typed one-argument mapping
closure executes only for `Some`. Both closures may capture parameters and
locals and must produce compatible one-word scalar results.

Checked-option `map_or_default` executes its typed one-argument mapping closure
only for `Some` and produces the mapped result type's `Default` value for
`None`. Integer, boolean, character, and scalar raw-pointer outputs use their
all-zero default representation; reference outputs are rejected because Rust
references do not implement `Default`. Captured parameters and locals remain
available to the mapping closure.

Runtime expressions can call a safe, non-const Rust-ABI function declared
before or after the selected export, with up to four built-in integer, Boolean,
character, unit, by-value fixed-array, bounded heterogeneous scalar-tuple, thin
scalar raw-pointer, thin scalar-reference, or thin fixed-array-reference
parameters and a result from the same families. A helper result may also be the
never type `!` when its
parsed body has an existing structurally diverging loop; `!` then coerces into
the surrounding supported result type without emitting a return edge. Never
parameters and public never-returning exports are not claimed. Pointer,
reference, and array signatures preserve their
target or element, fixed count, and const/mutability distinctions; mutable
values may coerce or reborrow as immutable values, while the reverse direction
and mismatched targets fail type checking.
Arguments execute eagerly in source order, are normalized to their declared
types, and become immutable lexical bindings while the body is emitted. A
callee body may additionally sequence bounded scalar local declarations,
assignments, and discarded expression statements before its tail value; its
temporary frame is removed without disturbing the returned register value.
Bounded `if`/`else if`/`else` action blocks may introduce scoped scalar locals,
perform assignments, and evaluate discarded expressions. Conditions and arms
remain lazy, branch locals are removed at their join, and mutations of an
enclosing callee local persist into its tail value. An action arm may also
return after any of those operations. That edge removes both its branch locals
and the remaining callee frame before reaching the same inline return join;
sibling arms may continue to a tail value, or every arm may return and make the
tail unreachable.
Condition-headed `while` statements may sequence scalar locals, assignments,
and discarded expressions in an inlined callee. The condition is re-evaluated
against persistent callee locals, iteration locals are removed before the
backedge, and the false edge continues to later statements or the tail. Empty
and multi-iteration cases use the same emitted control-flow graph.
Same-loop `break` and `continue` statements work unconditionally or behind a
Boolean condition. Both controls remove live iteration locals first; continue
targets the condition backedge, while break joins the condition-false exit.
Later operations remain reachable only on conditional-control fallthrough.
Scalar returns may also occur directly or conditionally in a loop body. A taken
return removes the iteration frame and the rest of the callee frame before
joining caller execution; an untaken conditional return retains the iteration
locals and proceeds to later operations or the normal backedge. A false loop
condition still reaches the callee's later statements and tail.
One-level `if`/`else if`/`else` blocks inside those loops may combine scoped
scalar actions with terminal `break`, `continue`, or scalar `return` edges.
Each arm removes exactly its branch locals on ordinary fallthrough, the full
iteration frame on a loop-control edge, or the full callee frame on return;
untaken conditions continue through sibling arms and nonterminal arms join the
later loop operations. Loop blocks nested inside those conditional arms remain
outside this bounded subset.
One nested condition-headed `while` is also lowered from the parser's bounded
nested-loop representation. Its ordered scalar actions and conditional or
unconditional controls preserve distinct inner and outer checkpoints: an inner
control removes only inner iteration locals, a labeled outer control also
removes the outer iteration frame, and a nested return removes the complete
callee frame before joining caller execution. Inner and outer `break` and
`continue`, zero-entry inner loops, and normal inner fallthrough are supported;
nesting beyond this parser representation still fails closed.
Statement-position unconditional `loop` bodies use the same bounded outer and
nested representations. Explicit and conditional break, continue, and return
edges retain their existing cleanup targets; a body without an exit emits a
real backedge, so an unreachable later tail is not exposed to the caller.
A diverging statement loop may be the callee's effective tail and therefore
inhabits its declared scalar return type without emitting cleanup or caller
fallthrough. A helper's effective tail may instead be a bounded value-producing
`loop { break value; }` expression accepted by the existing expression parser.
Conditional break alternatives preserve scalar, unit, thin-reference, slice,
and string result transport after earlier helper locals and before caller-frame
cleanup. This does not add arbitrary actions or backedges to the value-loop
expression grammar; more complex statement loops continue through the separate
loop IR above.
Direct scalar `return` statements, conditional early returns, and exhaustive
`if`/`else if`/`else` return chains are remapped to a per-call inline join.
Every returning edge removes only that callee's arguments and locals before
skipping the remaining body, while a fallthrough tail performs the same cleanup
once on its normal edge.
Calls may nest to eight levels and are inlined into the selected exported
function, so the object still contains one symbol and no call relocations. The
bounded active-call-name stack rejects direct and mutual recursion before
expanding a cycle; acyclic forward and backward chains remain declaration-order
independent. Caller-local capture, unsafe or foreign-ABI callees, deeper loop
nesting, aggregate helper signatures other than fixed arrays, and recursion fail
closed. An
original nested statement-body probe produced a 516-byte COFF object and a
904-byte ELF64 object. A separate multi-return probe produced 334-byte COFF and
728-byte ELF64 objects. A conditional-action probe produced 402-byte COFF and
792-byte ELF64 objects. A mixed action/return probe produced 345-byte COFF and
736-byte ELF64 objects. A normal-exit loop probe produced 274-byte COFF and
664-byte ELF64 objects. A controlled-loop probe produced 398-byte COFF and
792-byte ELF64 objects. A loop-return probe produced 314-byte COFF and 704-byte
ELF64 objects. A structured loop-arm probe produced a 469-byte COFF object and
an 856-byte ELF64 object. Independent pinned-nightly callers exercised taken
and untaken loop returns, alternating continue edges, threshold break, zero,
one, and 100 requested iterations, returning and falling-through action arms,
an `else if` chain whose sibling arms continue, break, return, and mutate, all
three mutation arms, scoped-local cleanup, persistent outer mutation,
normal-tail and both early-return edges, caller-side result composition,
Boolean branches, and inputs at narrow-width boundaries on Windows and Arch
Linux WSL. A nested condition-headed loop probe produced an 819-byte COFF
object and a 1208-byte ELF64 object; pinned-nightly callers matched an
independent Rust reference across 128 combinations of loop bounds and inner
continue, inner break, labeled outer continue, labeled outer break, nested
return, and normal-completion choices on both hosts.
A terminating unconditional-loop probe produced a 588-byte COFF object and a
984-byte ELF64 object. Pinned-nightly callers matched an independent Rust
reference across 26 combinations of bounds and nested-return selection,
exercising unconditional outer and inner backedges, inner continue and break,
labeled outer break, normal tail composition, and a nested early return on both
hosts. A separate emission test retains an actually diverging empty backedge.
A divergent-tail branch probe produced a 238-byte COFF object and a 624-byte
ELF64 object. Pinned-nightly callers exercised four bypass inputs and the
callee's reachable early-return edge on both hosts; the unexecuted nonzero call
path is the emitted infinite backedge and has no synthetic caller join.
A three-helper forward-call chain produced a 478-byte COFF object and an
872-byte ELF64 object. Pinned-nightly callers matched an independent reference
across 52 values and branch choices on both hosts, including forward calls from
the export and between helpers, eager argument composition, conditional arms,
and the final helper's early-return boundary. Separate direct and mutual cycles
were rejected by the active-call check.
A forward character-helper chain produced a 261-byte COFF object and a 656-byte
ELF64 object. Pinned-nightly callers matched an independent Rust reference for
14 input/branch combinations on both hosts, covering NUL, ASCII, non-ASCII,
emoji, both valid sides of the surrogate gap, and `U+10FFFF`. Integer arguments
to character parameters fail type checking rather than being reinterpreted as
Unicode scalar values.
A forward unit-helper chain produced a 211-byte COFF object and a 608-byte
ELF64 object. Pinned-nightly callers returned the same composed result for
eight integer boundary inputs on both hosts, covering statement-position unit
calls, implicit unit tails, an explicit valueless early return, forward unit
composition, and a bound `()` parameter. Using a unit call as an integer
operand fails type checking.
A forward raw-pointer helper chain produced a 174-byte COFF object and a
568-byte ELF64 object. Pinned-nightly callers matched selected pointer addresses
for both branch choices across eight fallback address bit patterns on Windows
and Arch Linux, covering mutable-to-const argument coercion, exact thin-pointer
returns, a typed pointer local, and address extraction after the inlined calls.
Separate adversarial sources reject mismatched pointees and const-to-mutable
arguments.
A scalar-reference helper chain produced a 232-byte COFF object and a 624-byte
ELF64 object. Pinned-nightly callers matched six independent read-only and
mutating cases on Windows and Arch Linux, proving shared reborrowing, mutation
through `&mut u16`, exact mutable-reference returns across nested inline-frame
cleanup, and caller-visible pointee updates. Object-emission tests additionally
cover Boolean and character reference parameters and returns. Separate
adversarial sources reject mismatched scalar targets and shared-to-mutable
arguments.
A fixed-array-reference helper chain produced a 312-byte COFF object and a
704-byte ELF64 object. Pinned-nightly callers matched read-only and mutating
paths at all four element indexes on Windows and Arch Linux, including
mutable-to-shared reborrowing, exact mutable array-reference returns used as
index bases, caller-visible single-element updates, and preservation of every
untouched element. Object-emission tests additionally cover Boolean, character,
and locally sourced unit-element arrays. Separate adversarial sources reject
element, count, and shared-to-mutable mismatches.
A slice/string-reference helper chain produced an 802-byte COFF object and an
1184-byte ELF64 object. Pinned-nightly callers matched 24 independent cases on
Windows and Arch Linux, covering empty, ASCII, multibyte UTF-8, and non-ASCII
strings; varied slice lengths and indexes; mutable-to-shared reborrowing;
two-word arguments; direct composition of returned slices into another helper;
normal and explicit-early mutable slice returns; caller-visible mutation; and
string lengths. Object-emission tests additionally cover Boolean, character,
and locally sourced unit slices, direct indexing of returned slices, and fat
locals. Separate adversarial sources reject element, mutability, and slice/string
kind mismatches. These references use a compiler-internal two-register return
transport while calls remain inlined; this is not a general public Rust ABI
implementation.
A value-producing helper-loop chain produced a 797-byte COFF object and a
1192-byte ELF64 object. Pinned-nightly callers matched 72 independent cases on
Windows and Arch Linux, covering both conditional break alternatives across six
boundary-value pairs and scalar, mutable-reference, and slice result consumers.
The slice path selected observably different full and one-element subslices;
the same chain also exercised a valueless unit break and helper-local cleanup.
Object-emission tests additionally cover character references and Boolean
slices. A mixed Boolean/integer break source fails type checking.
A by-value fixed-array helper chain used separate wide and packed probes. The
three-word `[u64; 3]` path produced an 840-byte COFF object and a 1232-byte
ELF64 object; the packed `[u16; 4]` path produced 1698-byte COFF and 2088-byte
ELF64 objects. Pinned-nightly callers matched 84 independent cases on Windows
and Arch Linux, covering nested helper calls, normal and explicit-early returns,
observably reversed arrays, runtime indexing, zero and integer-width boundary
values, packed local layout, and return-frame removal beneath arrays larger
than two machine words. Object-emission tests additionally cover Boolean,
character, and unit arrays. Separate adversarial sources reject element and
count mismatches. This is fixed-array transport within inlined calls, not a
general tuple, struct, enum, or public Rust aggregate ABI implementation.
A bounded heterogeneous scalar-tuple helper chain produced a 760-byte COFF
object and an 1152-byte ELF64 object. Independent pinned-nightly callers matched
five paths on Windows and Arch Linux, covering nested tuple helpers, eager
two-tuple argument evaluation, a normal and explicit-early three-element tuple
return, Boolean and character fields, numbered projection, local frame removal,
zero, ordinary, and `u16::MAX` values, and a valid trailing call-argument comma.
Object-emission tests additionally cover singleton and unit-element tuples,
typed local reassignment, count and element mismatches, out-of-range fields,
the four-element capacity boundary, and rejection at both public parameter and
return ABI boundaries. Tuple elements are limited to built-in
integers, Boolean, character, and unit; tuple nesting, destructuring, references
in tuples, ownership, and public tuple ABI transport are not claimed. Numeric
fields of mutable local tuples support the separately evidenced bounded stores
below.
A tuple-control probe produced an 854-byte COFF object and a 1248-byte ELF64
object. Independent pinned-nightly callers matched four conditional and
value-loop paths on Windows and Arch Linux. Its helper condition toggled a
caller-visible Boolean reference: both the selected tuple fields and final
state prove the condition ran exactly once, the unselected aggregate remained
lazy, and normal versus loop-break tuple materialization agreed at zero and
`u16::MAX` boundaries. General tuple sequencing and nested tuple control-flow
graphs remain outside this bounded slice.
A tuple-sequencing probe produced a 657-byte COFF object and a 1048-byte ELF64
object. Independent callers matched four paths on Windows and Arch Linux,
including zero and `u16::MAX` inputs. Three caller-observable increments around
tuple argument materialization, helper return, and direct field projection prove
that each ordered statement ran exactly once before its tuple consumer. This
slice covers scalar statement prefixes and inline-constant wrappers; tuple
destructuring, field mutation, nesting, and general aggregate statement values
remain outside it.
A mutable tuple-place probe produced a 398-byte COFF object and a 792-byte ELF64
object. Independent callers matched four paths on Windows and Arch Linux,
including zero and `u16::MAX` inputs. Direct integer and character stores plus a
Boolean compound store preserved a later scalar stack local and the other tuple
fields. The compiler rejects immutable tuple places, out-of-range fields, wrong
value types, and invalid Boolean compound operators. This remains limited to
numeric fields of mutable bounded scalar-tuple locals; tuple references, nested
places, destructuring, and public tuple ABI transport are not claimed.
A diverging `-> !` helper produced a 172-byte COFF object and a 568-byte ELF64
object. Independent pinned-nightly callers matched six reachable non-diverging
branch cases on Windows and Arch Linux, including zero and integer-width
boundaries. Object-emission tests retain the helper's unconditional loop
backedge, exercise never-to-scalar branch coercion, and reject a falsely
declared never-returning helper with a returning integer tail. This is bounded
bottom-type propagation for inlined safe Rust helpers, not a public never ABI,
never parameters, arbitrary control-flow divergence analysis, or general
never-type support.

Assignment places now have a bounded source-independent parser representation:
the base binding is stored once with either no projection or one dereference,
index, or numeric tuple-field projection. Index expressions retain normalized
text and an exact body-relative span without later bracket searches. Numeric
tuple fields are parsed once, while non-numeric and suffixed tuple assignment
fields fail closed after the parser confirms an assignment operator; method-call
expressions are not misclassified as assignments. This is a prerequisite for
typed place analysis only. Parser/semantic local IDs, arbitrary projection
lists, body-wide read/write/move/borrow facts, CFG blocks, loans, regions, and a
borrow checker remain unimplemented.

Runtime write places now add a stable-identity layer above that syntax. Each
active local and each inlined-helper parameter receives a checked monotonic
`RuntimeLocalId`; popping scoped locals never rewinds the allocator, so a later
binding cannot inherit the identity of an earlier binding merely by reusing its
fixed-array or stack position. Non-wildcard assignments resolve once to a typed
base (exact local ID plus current storage index, or parameter index), the parsed
projection, effective mutability, and an explicit `Write` or
`ReadModifyWrite` access. Direct, tuple-field, fixed-array, reference-array,
slice, dereference, and indexed-local stores all use that access fact when
deciding whether to load the previous value; only the compound operation itself
still depends on the specific operator. A local store validates the ID before
using its storage index. The runtime emitter now retains those monotonic local
facts and source-ordered assignment access facts in separate fixed 256-entry
tables through final validation, even after active stack entries are removed.
An adversarial unit test covers both access classes, same-name shadowing, scope
cleanup, storage-index reuse, monotonic identity, corrupt fact rejection, and
both exact fact-table capacity failures. Projection tests cover valid and
out-of-range tuple fields, valid indexes, malformed holes, and the exact four-
step capacity failure.

Read-place syntax discovery now recursively peels identifiers, dereferences,
indexes, tuple fields, subslices, transparent wrappers, and sequence tails into
the same base-to-leaf projection representation. It is independently bounded by
the existing four-projection capacity and the 64-level lowering depth. Direct
scalar dereference emission consumes the discovered place and records exactly
one dereference read instead of first recording an empty base read. The
specialized direct aggregate paths use the same expression-place recorder.
Discovery is not yet run across a complete body or consumed by every nested
emission family. Parser/semantic local IDs, complete typed body facts, CFGs,
initialization, moves, borrows, loans, and regions remain outside this slice.

The bounded read-place-discovery milestone passed all 565 compiler and driver
tests on Windows gnullvm and all 565 in release mode on native Arch Linux WSL,
plus warnings-denied Clippy on both hosts. Its adversarial tests prove
base-to-leaf ordering for a dereference/index/tuple-field chain, the exact fifth-
projection failure, and the absence of a duplicate empty read fact for direct
dereferences. Existing pinned-nightly native scalar-reference and raw-pointer
replacement cases preserve differential executable coverage.

Runtime local and access facts now reside in a standalone fixed-capacity body
table outside the x86 emitter's machine-code buffers. A pre-emission pass types
the supported leading straight-line named-local prefix and assigns stable IDs,
mutability, types, and translated declaration spans before the prologue exists.
It mirrors the emitter's complete supported declaration order: pre-loop top-
level statements, every parsed loop, and post-loop top-level statements. Direct
loop locals remain active for later loop operations; nested-loop and conditional-
arm actions copy the active loop environment and discard it without rewinding
the monotonic fact identity. The next loop starts from the outer environment, so
same-named scoped locals retain distinct IDs and later declarations cannot
inherit them.
The same traversal pre-resolves every supported non-wildcard assignment target
into a separate fixed 256-entry expectation table. Each expectation retains the
stable local/parameter identity, source-independent projections, base type,
`Write` or `ReadModifyWrite` class, and span. Emission consumes exact matches at
assignment sites while continuing to append actual reads and writes to the true
emission-order access ledger, so precomputed writes never move ahead of RHS
reads. Missing, reordered, malformed, or identity-drifted expectations fail
closed.
Assignment RHS expressions whose root is a discoverable identifier, dereference,
index, tuple field, subslice, wrapper, or sequence tail additionally reserve a
separate fixed 256-entry read-expectation table. Each root is resolved against
the exact active scope and consumed through the ordinary identifier-read path,
including specialized projected emitters. Scalar compound RHS expressions now
visit casts, ascriptions, unary wrappers, return/break values, sequences, binary
operands, and conditional condition/arms in exact emission order. Each
discoverable projected place remains one read rather than a projected read plus
a duplicate empty base read. Typed nested-index dispatch distinguishes
reference-base reads, a constant local-array element read, and every element
materialized for runtime local-array indexing before visiting its runtime index.
Compound array bases, method/call, aggregate, and non-assignment body reads
remain outside this slice.
Scalar local initializers use the same bounded visitor before the declared
binding enters the active environment. Reads in a shadowing initializer retain
the previous binding's stable ID; the replacement binding receives its new ID
afterward. Direct array literals, single-evaluation array repeats, and tuple
literals now plan their scalar operand reads in exact materialization order.
Direct identifier-backed array and tuple copies additionally plan the same
per-element `Index` or numbered `TupleField` reads used by emission. Conditional
tuple initializers with direct literal branches plan the condition once and both
branches' scalar operands. Direct conditional array literals follow their
different emitter order by planning condition, then element, and else element
for every materialized index. Wrapped or non-literal conditional aggregates
remain emission-time fact families. Fat-reference initializers now recursively
plan supported non-call identifiers, conditionals, transparent return/break/
inline-const wrappers, sequences, and range-derived slice/string values.
Range-derived slice and string initializers plan runtime start/end reads
before the base read, retaining the exact `Subslice` projection for a local-
array base. Recursion is capped at 64 levels. Call-derived fat-reference
initializers additionally plan left-to-right call-argument reads when every
argument is a one-slot scalar, another supported fat reference, a direct
identifier-backed array or tuple, an array literal or single-evaluation repeat,
an array accepted by the bounded recursive element planner, or a supported
literal/conditional/wrapped tuple. The array planner covers identifiers,
contextual defaults, literals, repeats, integer-to-byte arrays, direct and
wrapped array-producing calls, conditionals, transparent return/break/inline-
const wrappers, and nested sequences. Tuple-producing calls and their supported
whole-value wrappers are planned once. Sequence prefixes remain
ahead of those arguments. Identifier-backed arrays plan one `Index` read per
element and tuples plan numbered `TupleField` reads. Direct conditional arrays
plan condition, then element, and else element separately for every index.
Supported sequence-wrapped arrays plan their prefix before every materialized
element, including nested branch prefixes and conditions; identifier elements
retain exact `Index` reads and defaults add no false place read. Direct root
repeats retain their separate single-evaluation rule. Integer-to-byte arrays
repeat their scalar base reads once for each emitted byte. Direct array-producing
calls plan their arguments once, while calls under per-element wrappers repeat
their complete argument schedule for every index. Unsupported aggregate-leaf
call arguments remain later work because their specialized
materializers require separate facts.
Direct identifier, range-derived, and recursively conditional fat-reference
explicit returns and final tails now plan their condition, endpoint, and base
reads in exact emission order. Call-derived and unsupported wrapped return
forms remain outside the slice.
Direct sequence-wrapped tuple literals additionally plan their prefix once,
whereas direct sequence-wrapped array literals plan their prefix before every
element, preserving the two materializers' actual order.
Supported scalar expression statements now use that visitor at top level,
inside conditional arms, in direct and nested loop actions, and after loops.
Their reads are reserved in exact scoped emission order without introducing a
second name-resolution or access-classification path. Conditions, control
values, and scalar tails now use the same path for supported top-level branches
and returns, while heads, direct conditional loop controls, conditional loop
blocks/arms, branch-local returns, explicit returns, and the final scalar tail.
Nested-loop blocks additionally mirror entry conditions and every stored control
at its exact action boundary and control order before activating the following
local or action.
Method/call families beyond that bounded initializer slice, wrapped/non-literal
conditional-array and otherwise unsupported aggregate call-argument
materialization, unsupported
fat-reference returns, aggregate tails,
remain outside this preanalysis slice.
The emitter consumes those declarations exactly once. Inlined-helper parameters
and later scoped locals append to the table's dynamic tail, so expansion cannot
steal a reserved source identity. The prepass now enumerates all declaration
and assignment-target forms represented by the supported runtime body and loop
parsers, plus assignment RHS root-place and supported nested scalar reads. It is
not a complete typed body IR.

The nested assignment-read milestone passed all 574 compiler and driver tests
on Windows gnullvm and all 574 in release mode on native Arch Linux WSL, plus
warnings-denied Clippy on both hosts. Its adversarial unit test proves exact
left-to-right parameter and stable local-tuple-field identity order through
nested binary and conditional expressions. Its original replacement emits both
COFF and ELF64 objects through the same assignment shapes.

The typed assignment-index milestone passed all 576 compiler and driver tests
on Windows gnullvm and all 576 in release mode on native Arch Linux WSL, plus
warnings-denied Clippy on both hosts. Its adversarial unit test proves the exact
distinct fact order for reference-array runtime indexing, two-element local-
array runtime materialization, its runtime index, and constant local-array
indexing. Its original replacement emits both COFF and ELF64 objects through
the same typed index families.

The scalar initializer-read milestone passed all 578 compiler and driver tests
on Windows gnullvm and all 578 in release mode on native Arch Linux WSL, plus
warnings-denied Clippy on both hosts. Its adversarial unit test proves nine exact
parameter and local identities across initializer-before-binding shadowing and
a lazy conditional initializer. Existing branch and loop fact tests now include
their initializer reads. Its original replacement emits both COFF and ELF64
objects through the same shadowing and conditional shapes.

The expression-statement read milestone passed all 580 compiler and driver
tests on Windows gnullvm and all 580 in release mode on native Arch Linux WSL,
plus warnings-denied Clippy on both hosts. Its adversarial unit test proves 12
exact parameter and stable-local identities across initializer, conditional-arm,
loop, nested-scope, and post-loop statement order. Its original replacement
emits both COFF and ELF64 objects through the same scoped statement shapes.

The condition/return/scalar-tail read milestone passed all 582 compiler and
driver tests on Windows gnullvm and all 582 in release mode on native Arch Linux
WSL, plus warnings-denied Clippy on both hosts. Its adversarial unit test proves
14 exact parameter and stable-local identities across a top-level condition and
return, while head, in-loop condition, branch-local initializer and return, and
the final scalar tail. Its original replacement emits both COFF and ELF64
objects through those same control and scope shapes.

The interleaved nested-loop control-read milestone passed all 584 compiler and
driver tests on Windows gnullvm and all 584 in release mode on native Arch Linux
WSL, plus warnings-denied Clippy on both hosts. Its adversarial unit test proves
20 exact parameter and stable-local read identities across the outer while head,
nested entry condition, controls before and after a nested local declaration,
conditional return value, later assignment RHS, and final tail. Its original
replacement emits both COFF and ELF64 objects through the same ordered controls.

The literal aggregate-read milestone passed all 586 compiler and driver tests
on Windows gnullvm and all 586 in release mode on native Arch Linux WSL, plus
warnings-denied Clippy on both hosts. Its adversarial unit test proves 14 exact
read identities across a single-evaluation array repeat, an array literal with
runtime local-array indexing and a lazy conditional element, a tuple literal,
and the scalar tuple-field tail. Its original replacement emits both COFF and
ELF64 objects through the same materialization shapes.

The aggregate-copy read milestone passed all 588 compiler and driver tests on
Windows gnullvm and all 588 in release mode on native Arch Linux WSL, plus
warnings-denied Clippy on both hosts. Its adversarial unit test proves three
array-element projection facts for a by-value array parameter, two numbered
tuple-field facts for a local tuple copy, and the later copied-tuple tail. Its
original replacement emits both COFF and ELF64 objects through those copies.

The conditional tuple-literal read milestone passed all 590 compiler and driver
tests on Windows gnullvm and all 590 in release mode on native Arch Linux WSL,
plus warnings-denied Clippy on both hosts. Its adversarial unit test proves one
condition read followed by both direct tuple-literal branch operand orders and
the final projected local read. Its original replacement emits both COFF and
ELF64 objects through the same single-condition tuple materialization.

The conditional array-literal read milestone passed all 592 compiler and driver
tests on Windows gnullvm and all 592 in release mode on native Arch Linux WSL,
plus warnings-denied Clippy on both hosts. Its adversarial unit test proves the
emitter's exact repeated sequence of condition, then-element reads, and else-
element reads for each index, followed by the projected local tail. Its original
replacement emits both COFF and ELF64 objects through the same materialization.

The sequence-wrapped aggregate read milestone passed all 594 compiler and driver
tests on Windows gnullvm and all 594 in release mode on native Arch Linux WSL,
plus warnings-denied Clippy on both hosts. Its adversarial unit test proves one
tuple prefix followed by its two operands, then an array prefix repeated before
each element, followed by projected reads from both locals. Its original
replacement emits both COFF and ELF64 objects through the same wrappers.

The simple fat-reference initializer read milestone passed all 596 compiler and
driver tests on Windows gnullvm and all 596 in release mode on native Arch Linux
WSL, plus warnings-denied Clippy on both hosts. Its adversarial unit test proves
six exact parameter/local identities across a direct slice copy, conditional
slice selection, and sequence-wrapped string copy. Its original replacement
emits both COFF and ELF64 objects through the same initializer families.

The range-derived fat-reference initializer read milestone passed all 598
compiler and driver tests on Windows gnullvm and all 598 in release mode on
native Arch Linux WSL, plus warnings-denied Clippy on both hosts. Its adversarial
unit test proves runtime start/end reads precede the projected local-array base,
then an open-ended slice start precedes its reference base. Its original
replacement emits both COFF and ELF64 objects through those range families.

The conditional/wrapped fat-reference initializer milestone passed all 600
compiler and driver tests on Windows gnullvm and all 600 in release mode on
native Arch Linux WSL, plus warnings-denied Clippy on both hosts. Its adversarial
unit test proves condition, nested sequence prefix, runtime range endpoints,
projected local-array base, alternate endpoint, and alternate reference base in
the emitter's exact order. Its original replacement emits both COFF and ELF64
objects through the same recursive initializer family.

The fat-reference explicit/tail return milestone passed all 602 compiler and
driver tests on Windows gnullvm and all 602 in release mode on native Arch Linux
WSL, plus warnings-denied Clippy on both hosts. Its adversarial unit test proves
the branch condition, explicit-return start/end/base, and fallthrough-tail
start/base facts in exact order. Its original replacement emits both COFF and
ELF64 objects through the same explicit and tail return paths.

The call-derived fat-reference initializer milestone passed all 604 compiler
and driver tests on Windows gnullvm and all 604 in release mode on native Arch
Linux WSL, plus warnings-denied Clippy on both hosts. Its adversarial unit test
proves a sequence prefix followed by four scalar/fat-reference call arguments
in exact left-to-right order before inlined helper emission. Its original
replacement emits both COFF and ELF64 objects through the same call-derived
slice-reference initializer.

The identifier-aggregate call-argument milestone passed all 606 compiler and
driver tests on Windows gnullvm and all 606 in release mode on native Arch Linux
WSL, plus warnings-denied Clippy on both hosts. Its adversarial unit test proves
five initializer reads followed by a sequence prefix, three projected local-
array reads, two distinctly numbered local-tuple-field reads, and the trailing
scalar argument. Its original replacement emits both COFF and ELF64 objects
through the same inlined helper call.

The literal-aggregate call-argument milestone passed all 608 compiler and driver
tests on Windows gnullvm and all 608 in release mode on native Arch Linux WSL,
plus warnings-denied Clippy on both hosts. Its adversarial unit test proves a
sequence prefix, three array-literal operands, a single tuple condition and both
literal branches, a trailing scalar argument, then a single-evaluation array
repeat and literal tuple in exact materializer order. Its original replacement
emits both COFF and ELF64 objects through the same two inlined calls.

The conditional-array call-argument milestone passed all 610 compiler and
driver tests on Windows gnullvm and all 610 in release mode on native Arch Linux
WSL, plus warnings-denied Clippy on both hosts. Its adversarial unit test proves
an outer prefix followed by condition/then-element/else-element repeated for all
three indexes, then the tuple operands and trailing scalar argument. Its
original replacement emits both COFF and ELF64 objects through the same inlined
helper call.

The sequence-wrapped array call-argument milestone passed all 612 compiler and
driver tests on Windows gnullvm and all 612 in release mode on native Arch Linux
WSL, plus warnings-denied Clippy on both hosts. Its adversarial unit test proves
the array materializer's exact order: prefix, condition, then element, and else
element repeated for each of three indexes before the later tuple and scalar
arguments. Its original replacement emits both COFF and ELF64 objects through
the same inlined helper call.

The sequence-wrapped identifier-array call-argument milestone passed all 614
compiler and driver tests on Windows gnullvm and all 614 in release mode on
native Arch Linux WSL, plus warnings-denied Clippy on both hosts. Its adversarial
unit test proves three initializer reads followed by three repetitions of the
prefix and the same stable local-array identity with an `Index` projection,
before the tuple and trailing scalar arguments. Its original replacement emits
both COFF and ELF64 objects through the same inlined helper call.

The sequence-wrapped default-array call-argument milestone passed all 616
compiler and driver tests on Windows gnullvm and all 616 in release mode on
native Arch Linux WSL, plus warnings-denied Clippy on both hosts. Its adversarial
unit test proves the prefix is repeated for all three contextual default-array
elements without inventing element-place reads, before the tuple and trailing
scalar arguments. Its original replacement emits both COFF and ELF64 objects
through the same inlined helper call.

The recursive array call-argument milestone passed all 618 compiler and driver
tests on Windows gnullvm and all 618 in release mode on native Arch Linux WSL,
plus warnings-denied Clippy on both hosts. Its adversarial unit test proves 24
facts across a local-array initializer, three repetitions of an outer prefix,
condition, nested branch prefixes, exact local `Index` reads and reversed
literal-branch operands, then the tuple and scalar arguments. Its original
replacement emits both COFF and ELF64 objects through the same nested inlined
helper call.

The integer-byte array call-argument milestone passed all 620 compiler and
driver tests on Windows gnullvm and all 620 in release mode on native Arch Linux
WSL, plus warnings-denied Clippy on both hosts. Its adversarial unit test proves
17 facts: a sequence prefix and integer base repeated for all eight little-
endian output bytes, followed by the scalar bias argument. Its original
replacement emits both COFF and ELF64 objects through the same inlined byte-
slice helper call.

The array-producing call-argument milestone passed all 622 compiler and driver
tests on Windows gnullvm and all 622 in release mode on native Arch Linux WSL,
plus warnings-denied Clippy on both hosts. Its adversarial unit test proves 33
facts: one complete direct inner-call argument list, then three repetitions of a
wrapped prefix, condition, and both inner-call argument lists, followed by the
outer tuple and scalar arguments. Its original replacement emits both COFF and
ELF64 objects through the same direct and wrapped array-returning helpers.

The tuple-producing call-argument milestone passed all 624 compiler and driver
tests on Windows gnullvm and all 624 in release mode on native Arch Linux WSL,
plus warnings-denied Clippy on both hosts. Its adversarial unit test proves the
direct inner tuple call once, a sequence prefix and conditional once, both
branch call-argument lists once, the trailing scalar arguments, and two stable
final-tail local reads. Its original replacement emits both COFF and ELF64
objects through the same whole-tuple helper paths.

The assignment root-read milestone passed all 572 compiler and driver tests on
Windows gnullvm and all 572 in release mode on native Arch Linux WSL, plus
warnings-denied Clippy on both hosts. Strengthened adversarial tests prove four
stable branch/nested/root identities in both sequential and loop bodies, exact
expectation consumption, and fail-closed rejection when a planned read is
corrupted into a write. Existing COFF/ELF replacements cover those assignments.

The assignment-access expectation milestone passed all 572 compiler and driver
tests on Windows gnullvm and all 572 in release mode on native Arch Linux WSL,
plus warnings-denied Clippy on both hosts. Existing adversarial tests now prove
six sequential/conditional and four loop/nested/branch assignment expectations,
exact `Write` versus `ReadModifyWrite` classification, consumption, and corrupt-
identity rejection. Existing native COFF/ELF replacements exercise those sites.

The loop-scope declaration milestone passed all 572 compiler and driver tests
on Windows gnullvm and all 572 in release mode on native Arch Linux WSL, plus
warnings-denied Clippy on both hosts. Its adversarial unit test proves exact
outer, loop, nested-loop, conditional-arm, and post-loop ID order with scoped
branch spans, while its original differential replacement emits both COFF and
ELF64 objects.

The sequential top-level declaration milestone passed all 570 compiler and
driver tests on Windows gnullvm and all 570 in release mode on native Arch Linux
WSL, plus warnings-denied Clippy on both hosts. Its adversarial unit test proves
seven monotonic IDs across two conditional scopes, intervening assignments, and
later top-level declarations. Its original differential replacement emits both
COFF and ELF64 objects.

The conditional branch-local identity milestone passed all 568 compiler and
driver tests on Windows gnullvm and all 568 in release mode on native Arch Linux
WSL, plus warnings-denied Clippy on both hosts. Its adversarial unit test proves
that three same-named branch locals receive distinct declaration spans and
monotonic IDs, and its original differential replacement emits both COFF and
ELF64 objects.

The typed body-fact ownership milestone passed all 566 compiler and driver tests
on Windows gnullvm and all 566 in release mode on native Arch Linux WSL, plus
warnings-denied Clippy on both hosts. Its adversarial test independently builds
the table before emission, proves explicit and inferred local types and source-
ordered IDs, and corrupts the consumption order to require
`InvalidRuntimePlaceFacts`. Existing pinned-nightly typed-local, shadowing,
scoped-local, and inlined-helper native replacements preserve differential
executable coverage.

The bounded runtime-read-fact milestone passed all 563 compiler and driver
tests on Windows gnullvm and all 563 in release mode on native Arch Linux WSL,
plus warnings-denied Clippy on both hosts. The source remained `no_std`,
allocation-free, and free of unsafe blocks under the repository hygiene scan.

The runtime-place-identity milestone passed all 563 compiler and driver tests
on Windows gnullvm and all 563 in release mode on native Arch Linux WSL, plus
warnings-denied Clippy on both hosts. Existing native-object replacement tests
continue to cover direct, indexed, tuple-field, dereference, scoped, shadowed,
and inlined-helper assignment paths on COFF and ELF64.

The structured-place milestone passed all 562 compiler and driver tests on
Windows gnullvm and all 562 in release mode on native Arch Linux WSL, plus
warnings-denied Clippy on both hosts. Verification temporarily used the last
valid edition-2024 manifest value because an unrelated uncommitted root-only
`edition = "future"` experiment cannot be loaded by current Cargo without
per-package unstable-edition opt-ins; the unrelated manifest edit was restored
after the gates and is not part of this compiler milestone.

There was no prior MRML compiler baseline. A release-mode one-function smoke
compile, including process startup and filesystem I/O, took 22.050 ms on the
Windows development host and 0.005 seconds under Arch Linux WSL2. These are
single observations, not throughput benchmarks or regression thresholds.

The direct shared-loan liveness milestone passed all 699 compiler and driver
tests on Windows gnullvm and all 699 in release mode on native Arch Linux WSL,
plus warnings-denied Clippy on both hosts. Both workspace gates used rustc
`1.100.0-nightly` commit `fb6531d550e0075b9eb9a51464f404805eec87d9`
dated 2026-08-23; differential observations remain tied to immutable oracle
commit `f7d782a3be46d6bb4b9792fe69a61db389ba1769`. The implementation records
shared-reference borrower uses and rejects an exact mutable borrow followed by
a later use in the same validated control segment or its immediate exit. It
does not claim cross-block liveness, mutable-loan invalidation, regions, or a
complete borrow checker. The hygiene scan remained empty.

The bounded CFG shared-loan milestone passed all 701 compiler and driver tests
on Windows gnullvm and all 701 in release mode on native Arch Linux WSL, plus
warnings-denied Clippy on both hosts using rustc workspace commit
`fb6531d550e0075b9eb9a51464f404805eec87d9`. A fixed-capacity traversal now
orders loan issuance, exact mutable-borrow conflicts, and later shared borrower
uses across reachable block and edge control points, including real cycles.
Mutually unreachable control points do not manufacture conflicts. This remains
direct shared-loan evidence, not mutable-loan invalidation, regions, reborrow
completion, or a complete borrow checker. The hygiene scan remained empty.

The direct mutable-loan invalidation milestone passed all 703 compiler and
driver tests on Windows gnullvm and all 703 in release mode on native Arch
Linux WSL, plus warnings-denied Clippy on both hosts using rustc workspace
commit `fb6531d550e0075b9eb9a51464f404805eec87d9`. Uses of a reference local are
classified as loan uses only when its initialization and borrow effects derive
a direct loan identity. A later exact-path copy, move, shared/mutable borrow,
write, or read-modify-write conflicts with a live direct mutable loan; the same
access is accepted after the mutable borrower’s last reachable use. A forged
loan-use effect on an unrelated reference parameter fails structural
validation. This does not claim implicit reborrows, indirect alias identity,
regions, or a complete borrow checker. The hygiene scan remained empty.

The explicit mutable-reborrow suspension milestone passed all 705 compiler and
driver tests on Windows gnullvm and all 705 in release mode on native Arch
Linux WSL, plus warnings-denied Clippy on both hosts using rustc workspace
commit `fb6531d550e0075b9eb9a51464f404805eec87d9`. Direct reborrow ancestry is
followed with an initialization-count bound to the original owner path. A
mutable parent is rejected before a later child use and restored after the
child’s last use; owner-path mutation follows the same child liveness, while
shared/shared parent reads remain compatible. The pinned oracle independently
confirmed all accepted/rejected pairs. This does not claim implicit coercion
reborrows, general shared-child mutation classification, regions, or complete
Polonius semantics. The hygiene scan remained empty.

The expected-type implicit mutable-reborrow milestone passed all 707 compiler
and driver tests on Windows gnullvm and all 707 in release mode on native Arch
Linux WSL, plus warnings-denied Clippy on both hosts using rustc workspace
commit `fb6531d550e0075b9eb9a51464f404805eec87d9`. A direct identifier used to
initialize an explicitly typed reference binding records a shared or mutable
borrow rather than a move; an inferred `&mut` binding remains a consuming move.
The existing ancestry analysis then enforces temporary mutable-parent
suspension and last-use restoration. The pinned oracle confirmed E0503 for a
premature parent use, acceptance after the child’s last use, and E0382 for the
inferred move. This does not claim general coercion sites, access-sensitive
shared-child mutation, regions, or complete Polonius semantics. The hygiene
scan remained empty.

The access-sensitive direct-loan milestone passed all 709 compiler and driver
tests on Windows gnullvm and all 709 in release mode on native Arch Linux WSL,
plus warnings-denied compiler-only Clippy on both hosts using rustc workspace
commit `fb6531d550e0075b9eb9a51464f404805eec87d9`. Assignment through a direct
mutable-reference borrower is now a distinct loan mutation: a live shared child
blocks mutation through its mutable parent while retaining compatible parent
reads, and the parent mutation is restored after the child's last reachable
use. The pinned oracle independently confirmed the rejected and accepted
pairs. Reassignable reference bindings are deliberately excluded from derived
direct-loan identity until initialization generations can prevent stale loans;
this does not claim general coercion sites, regions, or complete Polonius
semantics. The `no_std`/allocation/unsafe hygiene scan remained empty.

The conditional action-return outlives milestone at `68124775` passed all 765
compiler and driver tests on Windows gnullvm and all 765 in release mode on
native Arch Linux WSL, plus warnings-denied compiler-only Clippy on both hosts
using pinned rustc commit
`f7d782a3be46d6bb4b9792fe69a61db389ba1769`. The pinned oracle rejected an
identity-call result rooted in conditional-action local storage with E0515 and
accepted the equivalent parameter-backed direct and locally stored call
results. Conditional return actions now receive a distinct shape-validated
ownership location mapped to the exact CFG return edge. The outlives gate also
checks exact reference-typed `Copy` and `Move` return effects while preserving
the existing pointee-path treatment for borrow effects. Ordinary conditional
actions, non-reference values, malformed locations, and ambiguous ancestry are
not promoted into accepted return facts. This remains bounded call-origin and
escape analysis, not general interprocedural lifetime inference or complete
Polonius semantics. The `no_std`/allocation/unsafe hygiene scan remained empty.

The explicit reference-reassignment generation milestone passed all 711
compiler and driver tests on Windows gnullvm and all 711 in release mode on
native Arch Linux WSL, plus warnings-denied compiler-only Clippy on both hosts
using rustc workspace commit
`fb6531d550e0075b9eb9a51464f404805eec87d9`. An unconditional top-level write
of an explicit borrow into a mutable reference binding now establishes a new
loan generation using existing bounded event identities. Later uses select the
new generation, while a child created before replacement remains associated
with the old loan. The pinned oracle confirmed the clean replacement, old-child
survival, and new-child E0506 cases. Conditional, expression-conditional, and
loop-carried replacements are deliberately excluded until path-sensitive
generation joins exist; moved reference values are not yet indirect loan
origins. The hygiene scan remained empty.

The typed reference-assignment reborrow milestone passed all 713 compiler and
driver tests on Windows gnullvm and all 713 in release mode on native Arch
Linux WSL, plus warnings-denied compiler-only Clippy on both hosts using rustc
workspace commit `fb6531d550e0075b9eb9a51464f404805eec87d9`. A plain direct
reference identifier assigned into an existing typed reference binding now
uses the destination reference type as coercion context and records its implicit
borrow before the destination write. The pinned oracle confirmed E0503 while a
reassigned mutable child remains live and accepted parent use after the child’s
last use. Existing branch-only use-after-move coverage now uses a call-derived
move, because the oracle confirms direct typed reference assignment is a
reborrow. Projected, compound, conditional-RHS, and call-derived assignments do
not claim this coercion behavior. The hygiene scan remained empty.

The conditional loan-generation join milestone passed all 715 compiler and
driver tests on Windows gnullvm and all 715 in release mode on native Arch
Linux WSL, plus warnings-denied compiler-only Clippy on both hosts using rustc
workspace commit `fb6531d550e0075b9eb9a51464f404805eec87d9`. A fixed 193-point
reachability set derived from the existing 64-block/128-edge bounds now tests
whether direct reference generations reach a use while avoiding all intervening
replacements. Non-exhaustive replacement preserves the original generation on
the bypass path; exhaustive replacement kills it. Conflict-to-use analysis
also retains path correlation, preventing mutually exclusive replacement and
old-loan use from manufacturing a conflict. The pinned oracle confirmed E0499
for the bypass case and acceptance for exhaustive replacement. Expression-
conditional and loop-carried generations remain unsupported. The hygiene scan
remained empty.

The multi-parent reborrow-ancestry milestone retained the 715-test cross-host
gate and warnings-denied compiler-only Clippy on Windows gnullvm and native
Arch Linux release mode. A child issued after a conditional generation join now
recursively follows every parent loan active at its issue point, applies
suspension to every mutable parent, and checks conflicts against every possible
ultimate owner path. The traversal is bounded by the existing combined
initialization/effect count and malformed ancestry cycles fail closed. The
pinned oracle confirmed E0499 when a bypass path leaves the original owner live
through the child, and acceptance when exhaustive replacement removes that
owner. This does not claim loop-carried or expression-conditional generations.

The loop-carried loan-generation milestone passed all 717 compiler and driver
tests on Windows gnullvm and all 717 in release mode on native Arch Linux WSL,
plus warnings-denied compiler-only Clippy on both hosts using rustc workspace
commit `fb6531d550e0075b9eb9a51464f404805eec87d9`. Direct reference assignments
inside loop operations, conditional loop actions, and nested loop actions now
participate in bounded generation reaching definitions. Zero-iteration bypass
paths conservatively retain the pre-loop generation, while an unconditional
replacement before every reachable exit kills it. A repeated dynamic issuance
from one static assignment uses that assignment's fixed generation identity.
The pinned oracle confirmed E0499 for both bypass cases and acceptance for both
mandatory-replacement cases. This does not claim per-iteration regions,
expression-conditional generations, or broader coercion sites. The
`no_std`/allocation/unsafe hygiene scan remained empty.

The expression-conditional loan-origin milestone passed all 719 compiler and
driver tests on Windows gnullvm and all 719 in release mode on native Arch
Linux WSL, plus warnings-denied compiler-only Clippy on both hosts using rustc
workspace commit `fb6531d550e0075b9eb9a51464f404805eec87d9`. Direct local
initializers and direct assignments whose value is a conditional reference now
retain one bounded alternative loan origin per final branch value, all sharing
the destination initialization or write generation. Nested branches are
preserved, mutually exclusive siblings do not manufacture conflicts, and
sequence-prefix temporary borrows are not promoted into destination origins.
The pinned oracle confirmed E0499 for branch alternatives that may borrow the
later-mutated owner and acceptance when every alternative borrows another
owner, for both initialization and reassignment. This does not claim indirect
reference moves, non-direct destinations, general coercion-site coverage, or
regions. The `no_std`/allocation/unsafe hygiene scan remained empty.

The conditional reference-identifier reborrow milestone passed all 721 compiler
and driver tests on Windows gnullvm and all 721 in release mode on native Arch
Linux WSL, plus warnings-denied compiler-only Clippy on both hosts using rustc
workspace commit `fb6531d550e0075b9eb9a51464f404805eec87d9`. Explicitly typed
direct local initializers and direct assignments now propagate their expected
shared or mutable reference context through conditional final values. Identifier
branches therefore record reborrows, including parent suspension and restoration,
while conditions and sequence prefixes remain ordinary value evaluation. The
pinned oracle confirmed E0499 when an alternative child may retain the later-
mutated owner and acceptance when the child ends before parent reuse, for both
initialization and assignment. This does not claim projected, call-argument,
return, indirect-destination, or general region coverage. The
`no_std`/allocation/unsafe hygiene scan remained empty.

The projected reference-place reborrow milestone passed all 723 compiler and
driver tests on Windows gnullvm and all 723 in release mode on native Arch Linux
WSL, plus warnings-denied compiler-only Clippy on both hosts using rustc workspace
commit `fb6531d550e0075b9eb9a51464f404805eec87d9`. An explicit expected shared or
mutable reference type now propagates through a direct projected place at local
initialization and direct assignment sites. Numeric tuple-field probes preserve
parent suspension, reject a competing live mutable reborrow with the oracle's
E0499 behavior, and restore access after the child's last use. Inferred projected
reference bindings remain moves and the existing partial-move gate remains green.
This does not claim call-argument, return, indirect-destination, or general region
coverage. The `no_std`/allocation/unsafe hygiene scan remained empty.

The non-escaping call-argument reborrow milestone passed all 725 compiler and
driver tests on Windows gnullvm and all 725 in release mode on native Arch Linux
WSL, plus warnings-denied compiler-only Clippy on both hosts using rustc workspace
commit `fb6531d550e0075b9eb9a51464f404805eec87d9`. Direct, projected, sequence-tail,
and conditional place arguments use the callee parameter's expected shared or
mutable reference context when the call result cannot carry a reference. The
pinned future-edition oracle accepted parent reuse after a unit-returning call
and rejected a call competing with a still-live mutable child with E0499. Calls
whose result may carry a reference deliberately retain consuming classification:
their result must first acquire an argument-derived loan origin so analysis does
not unsoundly end the borrow at call completion. Return coercions and general
regions remain unimplemented. The `no_std`/allocation/unsafe hygiene scan remained
empty.

The identity call-result loan-origin milestone passed all 727 compiler and driver
tests on Windows gnullvm and all 727 in release mode on native Arch Linux WSL,
plus warnings-denied compiler-only Clippy on both hosts using rustc workspace
commit `fb6531d550e0075b9eb9a51464f404805eec87d9`. The bounded callee-body audit
accepts statement-free direct, transparent-wrapper, sequence-tail, and conditional
reference results only when every result path resolves to one compatible reference
parameter. That argument's borrow is tagged with the caller destination generation
for direct initialization and assignment, so a live returned child rejects a
competing owner borrow with the pinned oracle's E0499 behavior and the owner is
restored after the child's last use. Unused children no longer manufacture old
move failures across conditional joins or loop exits. Statement-bearing,
ambiguous, unsupported, and locally derived result bodies retain conservative
classification. This does not claim general interprocedural regions or return
coercions. The `no_std`/allocation/unsafe hygiene scan remained empty.

The conditional-return call-result origin milestone passed all 729 compiler and
driver tests on Windows gnullvm and all 729 in release mode on native Arch Linux
WSL, plus warnings-denied compiler-only Clippy on both hosts using rustc workspace
commit `fb6531d550e0075b9eb9a51464f404805eec87d9`. The bounded callee proof now
merges top-level explicit returns, conditional returns, else-if chains, exhaustive
else values, and a continuing tail, requiring every retained result to name the
same compatible reference parameter. Initializer and assignment probes preserve
that argument origin across the call, match the pinned future-edition oracle's
E0499 while the returned child is live, and restore the owner afterward. Locals,
assignments, expression statements, loops, missing values, parse failures, and
differing origins fail the proof closed. General local/loop interprocedural flow,
regions, and return coercions remain unimplemented. The
`no_std`/allocation/unsafe hygiene scan remained empty.

The local-alias call-result origin milestone passed all 731 compiler and driver
tests on Windows gnullvm and all 731 in release mode on native Arch Linux WSL,
plus warnings-denied compiler-only Clippy on both hosts using the pinned rustc
commit `f7d782a3be46d6bb4b9792fe69a61db389ba1769`. A bounded callee proof may now
carry one compatible reference-parameter origin through ordered immutable local
initializers into top-level returns or the tail. Local lookup is newest-first,
and an unresolved shadow blocks fallback to an older parameter name. Caller
initializer and assignment probes match the pinned future-edition oracle: a
live returned child rejects a competing mutable borrow with E0499, while owner
access is restored after the child's last use. Assignments, expression
statements, loops, ambiguous origins, parse failures, and capacity exhaustion
still fail the proof closed. The updated Arch nightly commit
`fb6531d550e0075b9eb9a51464f404805eec87d9` was also identified, but its release
build crashed inside LLVM `PromotePass`; it is not promoted to oracle or passing
evidence. General loop flow, regions, and return coercions remain unimplemented.
The `no_std`/allocation/unsafe hygiene scan remained empty.

The direct loop-return call-result origin milestone passed all 733 compiler and
driver tests on Windows gnullvm and all 733 in release mode on native Arch Linux
WSL, plus warnings-denied compiler-only Clippy on both hosts using pinned rustc
commit `f7d782a3be46d6bb4b9792fe69a61db389ba1769`. The bounded callee proof now
visits direct and conditional return operations in top-level `while` and `loop`
bodies and requires those results, all other returns, and any reachable tail to
resolve to the same compatible reference parameter. Break and continue paths do
not manufacture origins. Initializer and assignment probes match the oracle's
E0499 conflict while the returned child is live and restore the owner after its
last use. Loop-local declarations, assignments, expression statements,
conditional action blocks, nested loops, differing origins, and malformed or
over-capacity bodies still fail closed. This does not claim general loop dataflow,
regions, or return coercions. The `no_std`/allocation/unsafe hygiene scan remained
empty.

The conditional loop-block call-result origin milestone passed all 735 compiler
and driver tests on Windows gnullvm and all 735 in release mode on native Arch
Linux WSL, plus warnings-denied compiler-only Clippy on both hosts using pinned
rustc commit `f7d782a3be46d6bb4b9792fe69a61db389ba1769`. The bounded callee proof now
visits action-free `if`/`else if`/`else` blocks represented inside a top-level
loop, merging every explicit return terminal with all other function exits.
Break, continue, and fallthrough arms manufacture no result origin. Caller
initializer and assignment probes match the oracle's E0499 behavior while the
returned child is live and restore the owner after its last use. Any branch
action, invalid else-arm range, nested loop, mutation, differing origin, parse
failure, or capacity failure rejects the proof. This does not claim branch-local
dataflow, nested-loop origins, regions, or return coercions. The
`no_std`/allocation/unsafe hygiene scan remained empty.

The nested-loop call-result origin milestone passed all 737 compiler and driver
tests on Windows gnullvm and all 737 in release mode on native Arch Linux WSL,
plus warnings-denied compiler-only Clippy on both hosts using pinned rustc commit
`f7d782a3be46d6bb4b9792fe69a61db389ba1769`. Action-free parser-represented
nested loop blocks now contribute their explicit unconditional and conditional
return values to the same bounded callee-origin merge used by every other exit.
Nested break/continue controls manufacture no result origin. Caller initializer
and assignment probes match the oracle's E0499 behavior while the returned child
is live and restore the owner after its last use. Any nested action, unsupported
nested-unit shape, mutation, differing origin, malformed input, or capacity
failure rejects the proof. This does not claim nested local dataflow, regions,
or return coercions. The `no_std`/allocation/unsafe hygiene scan remained empty.

The return coercion-site reborrow milestone passed all 738 compiler and driver
tests on Windows gnullvm and all 738 in release mode on native Arch Linux WSL,
plus warnings-denied compiler-only Clippy on both hosts using pinned rustc commit
`f7d782a3be46d6bb4b9792fe69a61db389ba1769`. Explicit returns, conditional
returns, supported loop and conditional-action returns, and the final tail now
apply the declared shared or mutable reference type to direct, projected, and
conditional reference places. Explicitly typed mutable-reference locals record
reborrows at those coercion sites, while inferred bindings remain moves and a
fallthrough use is rejected as `RuntimeUseAfterMove`. The pinned future-edition
oracle accepted the explicit reborrow case and rejected the inferred move with
E0382. Indirect unsupported shapes retain conservative move classification;
general regions remain unimplemented. The `no_std`/allocation/unsafe hygiene
scan remained empty.

The direct shared-loan owner-conflict milestones passed all 742 compiler and
driver tests on Windows gnullvm and all 742 in release mode on native Arch
Linux WSL, plus warnings-denied compiler-only Clippy on both hosts using pinned
rustc commit `f7d782a3be46d6bb4b9792fe69a61db389ba1769`. A live shared loan
now conflicts with a direct owner `Write`, `ReadModifyWrite`, or non-`Copy`
`Move`, in addition to the previously handled mutable borrow. Existing bounded
CFG reachability still permits mutation or movement after the shared borrower's
last use. The pinned future-edition oracle rejected the live mutation with
E0506 and the live owner move with E0505, and accepted both post-last-use
controls. This does not claim indirect alias invalidation or general regions.
The `no_std`/allocation/unsafe hygiene scan remained empty.

The nested-reborrow ancestor-invalidation milestone passed all 744 compiler and
driver tests on Windows gnullvm and all 744 in release mode on native Arch
Linux WSL, plus warnings-denied compiler-only Clippy on both hosts using pinned
rustc commit `f7d782a3be46d6bb4b9792fe69a61db389ba1769`. Mutable and shared
grandchild reborrows now suspend every mutable ancestor for mutation-through-
alias conflicts, not only their immediate parent. The bounded ancestry walk
distinguishes ultimate-owner paths from intermediate reference paths and never
treats a loan as borrowing its own borrower binding. That preserves legal
reference-generation replacement cycles while rejecting a live grandchild
followed by ancestor mutation. The pinned future-edition oracle rejected both
live mutable/shared grandchild cases with E0503 and accepted both post-last-use
controls. This does not claim unrestricted regions or arbitrary alias analysis.
The `no_std`/allocation/unsafe hygiene scan remained empty.

The local-reference ancestor-move milestone passed all 750 compiler and driver
tests on Windows gnullvm and all 750 in release mode on native Arch Linux WSL,
plus warnings-denied compiler-only Clippy on both hosts using pinned rustc commit
`f7d782a3be46d6bb4b9792fe69a61db389ba1769`. Moving a local reference
ancestor now checks the bounded intermediate-loan relation and is rejected while
a shared or mutable child remains live; it is accepted after the child's last
reachable use. The pinned future-edition oracle rejected both live-child cases
with E0505 and accepted both last-use controls. Legal reference-generation
replacement remains accepted. This does not claim unrestricted regions or
arbitrary alias analysis. The `no_std`/allocation/unsafe hygiene scan remained
empty.

The call-reborrow ancestor-invalidation milestone passed all 746 compiler and
driver tests on Windows gnullvm and all 746 in release mode on native Arch
Linux WSL, plus warnings-denied compiler-only Clippy on both hosts using pinned
rustc commit `f7d782a3be46d6bb4b9792fe69a61db389ba1769`. A mutable
call-scoped reborrow through a local reference now checks intermediate ancestry,
so it conflicts with a live shared child of that ancestor. The existing
ultimate-owner relation remains separate for destination replacement, preserving
the legal old-pointee generation cycle. The pinned future-edition oracle rejected
the live call reborrow with E0502 and accepted the post-last-use control. This
does not claim arbitrary interprocedural effects or unrestricted regions. The
`no_std`/allocation/unsafe hygiene scan remained empty.

The shared-call ancestor-invalidation milestone passed all 748 compiler and
driver tests on Windows gnullvm and all 748 in release mode on native Arch
Linux WSL, plus warnings-denied compiler-only Clippy on both hosts using pinned
rustc commit `f7d782a3be46d6bb4b9792fe69a61db389ba1769`. A shared
call-scoped reborrow through a local reference now also checks intermediate
ancestry when the active child is mutable. Shared-on-shared remains compatible,
and bounded reachability restores the ancestor after the mutable child’s last
use. The pinned future-edition oracle rejected the live shared call reborrow
with E0502 and accepted the post-last-use control. This does not claim arbitrary
interprocedural effects or unrestricted regions. The
`no_std`/allocation/unsafe hygiene scan remained empty.

The projected-reference path-ancestor milestone passed all 752 compiler and
driver tests on Windows gnullvm and all 752 in release mode on native Arch Linux
WSL, plus warnings-denied compiler-only Clippy on both hosts using pinned rustc
commit `f7d782a3be46d6bb4b9792fe69a61db389ba1769`. A move of a tuple root
now overlaps a live shared or mutable child borrowed through one of its
reference fields. The fixed-capacity parent walk rejects malformed IDs and
cycles, while sibling-field moves, post-last-use moves, and reference-binding
replacement remain accepted. The pinned future-edition oracle rejected both
live whole-root moves with E0505 and accepted the precision controls. Whole-
tuple post-use emission remains outside the native-object subset and fails
closed independently; its borrow-analysis control is not promoted to native
execution evidence. This does not claim general place overlap, unrestricted
regions, or arbitrary alias analysis. The `no_std`/allocation/unsafe hygiene
scan remained empty.

The moved-reference loan-identity milestone passed all 754 compiler and driver
tests on Windows gnullvm and all 754 in release mode on native Arch Linux WSL,
plus warnings-denied compiler-only Clippy on both hosts using pinned rustc commit
`f7d782a3be46d6bb4b9792fe69a61db389ba1769`. Moving a direct `&mut`
value into an inferred local now transfers its single direct loan origin through
one-hop and chained moves. A later child therefore continues to protect the
ultimate owner, while the consumed source remains subject to initializedness.
The lookup follows bounded earlier events and selects the source's latest direct
assignment generation, preventing revival of its prior owner. The pinned oracle
rejected live shared and mutable descendants and latest-owner mutation with
E0503, while accepting post-last-use mutation, direct use through the moved
binding, and mutation of the superseded owner. Existing conditional-generation
regressions remain green, but conditional multi-origin and projected reference-
value moves are not claimed. This does not claim general alias tracking or
regions. The `no_std`/allocation/unsafe hygiene scan remained empty.

The moved conditional-loan-origin milestone passed all 756 compiler and driver
tests on Windows gnullvm and all 756 in release mode on native Arch Linux WSL,
plus warnings-denied compiler-only Clippy on both hosts using pinned rustc commit
`f7d782a3be46d6bb4b9792fe69a61db389ba1769`. One immediate precise root
move of a conditional reference local now derives a destination loan for every
retained branch-origin effect. Conflicts against either possible owner therefore
survive the move, while unrelated-owner access and access after the moved
child's last use remain accepted. The derived category is capped by the existing
place-effect ledger and refuses stale origins across source-generation
replacement. The pinned oracle rejected the shared/mutable live-child cases and
accepted both precision controls. Chained conditional-origin and projected
reference-value moves remain unimplemented; this does not claim general alias
tracking or regions. The `no_std`/allocation/unsafe hygiene scan remained empty.

The conditional-loan move-chain milestone passed all 758 compiler and driver
tests on Windows gnullvm and all 758 in release mode on native Arch Linux WSL,
plus warnings-denied compiler-only Clippy on both hosts using pinned rustc commit
`f7d782a3be46d6bb4b9792fe69a61db389ba1769`. Conditional branch origins
now survive bounded chains of precise root reference moves. The derived relation
enumerates every origin at every actual move depth using checked
`initialization_count * effect_count` work and depth-qualified loan IDs, retaining
intermediate generations and rechecking replacement at each hop. The pinned
oracle rejected two- and three-hop shared/mutable live-child cases against both
possible owners, while accepting unrelated-owner and post-last-use controls.
Projected reference-value moves and general region/outlives propagation remain
unimplemented; this does not claim complete Polonius semantics. The
`no_std`/allocation/unsafe hygiene scan remained empty.

The projected tuple-field loan-origin milestone at `6c0a9387` passed all 760
compiler and driver tests on Windows gnullvm and all 760 in release mode on
native Arch Linux WSL, plus warnings-denied compiler-only Clippy on both hosts
using pinned rustc commit
`f7d782a3be46d6bb4b9792fe69a61db389ba1769`. Moving one direct
reference-typed tuple field into an inferred local now retains that field's
shared or mutable loan origin, so a descendant continues to protect the exact
owner. Exact effect count/order, mutability, tuple shape, and absence of an
intervening write are required; ambiguous shapes fail closed. The tests reject
live-child mutation for first and later reference fields while accepting sibling
owner mutation and post-last-use access. This does not claim nested projected
moves, projected move chains, aggregate provenance, or general regions. The
`no_std`/allocation/unsafe hygiene scan remained empty.

The projected tuple-field loan-chain stabilization milestone at `bf91efb9`
passed all 762 compiler and driver tests on Windows gnullvm and all 762 in
release mode on native Arch Linux WSL, plus warnings-denied compiler-only Clippy
on both hosts using pinned rustc commit
`f7d782a3be46d6bb4b9792fe69a61db389ba1769`. The existing bounded,
event-decreasing root-move relation now has explicit evidence that a direct
tuple-field origin survives two- and three-hop later moves. The pinned oracle
rejected live shared/mutable descendants with E0503 and accepted post-last-use,
sibling-owner, and latest-generation replacement controls. This is evidence for
chains after one directly initialized tuple-field source, not nested projections,
multiple projected-source hops, aggregate provenance, or general regions. The
`no_std`/allocation/unsafe hygiene scan remained empty.

The direct callee-local reassignment milestone extends that bounded proof through
straight-line plain assignment to a mutable reference local. The proof retains a
fixed newest-first name/origin/mutability state and resolves each RHS before
replacing the destination generation. A returned child therefore continues to
reject a competing mutable owner borrow while live and releases the owner after
its last use. Immutable destinations, projected or compound writes, local-backed
RHS values, conditional assignments, and expression statements remain
conservative. The exact dated oracle accepted the reassigned-alias callee and
post-last-use control and rejected the live competing borrow with E0499. Windows
gnullvm and native Arch Linux WSL each pass 639 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 985 compiler
tests per host. This is not general interprocedural dataflow or regions.

The conditional callee-local reassignment milestone copies the fixed local-
origin state for each conditional outcome and joins it per local. Explicit
branches and `else` start from the same incoming generation; a missing `else`
adds that unchanged fallthrough outcome. Equal parameter origins remain exact,
while differing origins make only the affected local conservative. Unsupported
branch actions, projected or compound writes, immutable destinations, and
local-backed RHS values fail closed. The exact dated oracle accepted equal-
origin branches and owner reuse after the returned child's last use, and
rejected a live competing mutable owner borrow with E0499. The Windows gnullvm
canonical suite passes 639 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 985 compiler tests. The Arch WSL
rerun was blocked before compiler execution by concurrent invalid isolation
metadata in `org.mrml.library.uefi`; it is not passing evidence for this
increment. This is not general interprocedural CFG, alias, or region analysis.

The branch-local callee-origin milestone gives each conditional action block a
fixed-capacity copy of the incoming name/origin/mutability state. Supported local
reference declarations can feed later direct assignments in the same branch;
newest-first shadowing stays branch-scoped, and those entries are discarded
before joining only the pre-existing locals. A local-backed branch alias makes
the result conservative. Returns, expressions, projected or compound writes,
and other unsupported actions still fail closed. The exact dated oracle accepted
same-origin branch-local aliases and post-last-use owner reuse and rejected a
live competing mutable owner borrow with E0499. Windows gnullvm and native Arch
Linux WSL each pass 639 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 985 compiler tests per host. This
is not arbitrary branch dataflow, nested projections, or general regions.

The branch-local return-origin milestone resolves a terminal explicit return
against the scoped aliases accumulated earlier in that conditional action block.
Its parameter origin joins the callee's other exits, while that terminal path is
not merged into the conditional fallthrough state. Local-backed, nonterminal,
malformed, or unsupported return shapes fail the entire proof conservative. The
exact dated oracle accepted a branch-local early return with a parameter-backed
tail and post-last-use owner reuse, and rejected a live competing mutable owner
borrow with E0499. Windows gnullvm and native Arch Linux WSL each pass 639
library tests, one component-interface probe, 10 conformance tests, and 335
replacement tests: 985 compiler tests per host. This is not general control-flow
or region inference.

The loop callee-local reassignment milestone handles a `while` body made only of
supported direct assignments. It applies one bounded transfer from the incoming
local-origin state and joins the result with that same zero-iteration state.
Equal origins remain exact; changed origins become unknown. Mixed controls,
returns, locals, expressions, nested loops, and unsupported assignments fail
conservative. The exact dated oracle accepted the same-origin loop and owner
reuse after the returned child's last use, and rejected a live competing mutable
owner borrow with E0499. Windows gnullvm and native Arch Linux WSL each pass 639
library tests, one component-interface probe, 10 conformance tests, and 335
replacement tests: 985 compiler tests per host. This is not general loop fixed-
point, path-sensitive, alias, or region analysis.

The loop-local callee-origin milestone extends that stable transfer with bounded
local reference declarations before later direct assignments. Per-iteration
names, origins, and mutability are discarded before the pre-loop locals join the
zero-iteration state. Same-parameter origins remain exact, while local-backed or
changed origins become conservative; mixed controls and unsupported operations
still fail closed. The exact dated oracle accepted the loop-local alias and
post-last-use owner reuse and rejected a live competing mutable owner borrow with
E0499. Windows gnullvm and native Arch Linux WSL each pass 639 library tests,
one component-interface probe, 10 conformance tests, and 335 replacement tests:
985 compiler tests per host. One concurrent Arch run exited during replacements
without a stable failure summary; an immediate complete rerun passed 985. This
is not a general loop fixed point, path-sensitive analysis, or region solver.

The conditional-loop arm-local return milestone gives each supported `if`/
`else if`/`else` arm inside a loop an independent fixed-capacity local alias
state for a terminal return. The returned parameter origin joins other callee
exits; local-backed returns fail closed. Arm assignments and expressions remain
unsupported because their loop-carried fallthrough effects are not modeled. The
exact dated oracle accepted the loop-arm local alias and post-last-use owner
reuse and rejected a live competing mutable owner borrow with E0499. Windows
gnullvm and native Arch Linux WSL each pass 639 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 985 compiler
tests per host. This is not general loop dataflow, nested projections, or region
inference.

The nested-loop local return milestone carries local-only alias actions into the
supported unconditional and conditional returns of one parsed nested loop block.
The block's fixed scoped origin state resolves each return and merges its exact
parameter origin with other exits. Local-backed returns, assignments, and
expressions fail conservative. The exact dated oracle accepted the nested-loop
local alias and post-last-use owner reuse and rejected a live competing mutable
owner borrow with E0499. Windows gnullvm and native Arch Linux WSL each pass 639
library tests, one component-interface probe, 10 conformance tests, and 335
replacement tests: 985 compiler tests per host. This is not a general nested-
loop fixed point, path-sensitive analysis, or region solver.

The indexed aggregate call-origin milestone recognizes a scalar-reference
return whose exact read place is rooted at a compatible array-reference or
slice-reference parameter and contains `Index`, optionally after one explicit
`Dereference`. Element type and mutability must match. The caller retains the
whole parameter origin, so a live indexed competitor conflicts and owner access
returns after the child's last use. Identity, mismatched, shared-to-mutable,
deeper, and unrelated projections fail closed. The exact dated oracle accepted
the indexed array-element return and post-last-use reuse and rejected the live
competitor with E0499. Windows gnullvm and native Arch Linux WSL each pass 640
library tests, one component-interface probe, 10 conformance tests, and 335
replacement tests: 986 compiler tests per host. This is the first non-tuple
aggregate provenance slice, not general aggregate or index-sensitive alias
analysis.

The indexed slice evidence uses a distinct mutable-slice call target and caller,
not the fixed-array target as a proxy. Both canonical hosts retain the same 986
tests. The exact dated oracle accepted indexed slice owner reuse after the
returned child's last use and rejected a live indexed competitor with E0499 and
E0503. This adds direct evidence for the already bounded slice projection path;
it does not add general subslice, disjoint-index, or aggregate alias analysis.

The subslice call-origin milestone retains an array/slice-reference parameter
origin through an exact `Subslice` place into a matching slice-reference result,
with at most one explicit preceding dereference. Element type and mutability must
match. An unprojected unclassified read of a loan-backed fat-reference local is
now a `LoanUse`; this keeps a returned subslice live when later indexed without
forging a projected access fact. Array and slice live competitors conflict,
while post-last-use restoration succeeds. ORACLE-0002 rejected both live cases
with E0499 and additionally reported E0503 for the slice case. Both canonical
hosts pass 640 library tests, one component-interface probe, 10 conformance
tests, and 335 replacement tests: 986 compiler tests per host. General subslice
disjointness, deeper projections, and region inference remain unsupported.

One direct callee local alias now preserves those exact indexed-element or
subslice origins. An explicit alias type must equal the declared call return
type before the interprocedural proof retains an origin; inferred aliases use
the initializer's already compatible result. Focused caller tests cover live
conflicts and post-last-use restoration, while a mismatched annotation fails
conservative.

The explicit compatibility result is retained with bounded local state and is
checked again by plain assignment transfer. A mutable local whose declared type
does not match the call return therefore cannot regain an origin through a
later direct or conditional assignment. All modeled local scopes carry the same
state without allocating a second type environment.

For an inferred local, that state is true only when its initializer already
retained a compatible parameter origin. Originless inferred locals cannot gain
an origin through later assignment, closing the slice-to-scalar case
conservatively until this proof owns a complete local type environment.

The proof now owns a fixed local type slot and reuses the canonical place-
projection type walker for bounded reference inference. Exact annotations,
address-of indexed or subslice places, identifiers, transparent wrappers,
sequence tails, and equal conditional results feed the same state. Consequently
a local-backed inferred reference can be replaced by a compatible parameter-
backed reference without fabricating provenance; mismatched annotations and
ascriptions remain unknown.

Mutable local references may now coerce to compatible shared call returns. The
callee argument still contributes its mutable borrow effect, while the derived
destination loan is attenuated to shared. This retains caller liveness and
rejects mutation before the shared result's last use without granting mutable
authority to the result.

The two-word slice path has separate coverage: a mutable subslice flows through
mutable and shared callee locals into a shared slice result. Later indexing is a
loan use, so live caller mutation conflicts while mutation after the last index
read succeeds.

Plain alias assignments additionally compare the inferred RHS reference type
with the local's retained type before updating provenance. This preserves
directional mutable-to-shared coercion but rejects shared-to-mutable transfer
independently of the declared function return.

Projected callee origins now have a separate fixed-capacity typed state keyed by
stable local index and a canonical nonempty projection. It retains final type,
parameter origin, and monotonic generation; branch intersection keeps only
identical typed origins.

The first connected transfer is an exact straight-line numeric tuple-field
assignment on a mutable local. The resolver validates the RHS reference type,
replaces or clears that field's generation, and uses the exact field origin for
return inference while preserving root-origin handling for dereferences and
subslice paths. Focused tests cover replacement from the first parameter to the
second, local-backed clearing, invalid fields, a live competing borrow, and
post-last-use owner reuse. The exact dated oracle accepts the two-parameter
replacement and rejects
the live competitor with E0499; it rejects a local-backed initialization followed
by parameter replacement with E0515, so that shape remains outside MRML's
accepted subset. Windows and Arch each pass 641 library, 1 component, 10
conformance, and 335 replacement tests (987 per host).

Exhaustive conditional tuple-field assignments now use a copy of the bounded
projected state per arm and intersect only arms that fall through. Identical
typed origins survive, while unequal origins and an implicit incoming `else`
path clear the evidence. Focused caller tests preserve the second parameter's
loan through the returned child, reject a live competing reborrow, and allow
owner reuse after last use. ORACLE-0002 accepts that exact both-arm shape and
rejects the live competitor with E0499. Projected loop writes require the
separately bounded stable-loop rule below; this is not general conditional
aggregate or region inference.

A bounded loop transfer now preserves an already established tuple-field origin
only when one modeled iteration produces the same typed origin as the zero-
iteration incoming state. The supported iteration is an identity reborrow of
the field; its trailing dereference is normalized back to the exact stored field
key. Missing or changed evidence intersects away. Focused caller tests reject a
live competing borrow and accept owner reuse after the returned child's last
use. ORACLE-0002 accepts the same exact shape and rejects the competitor with
E0499. Both hosts remain at 987 tests; arbitrary loop fixed points remain
unsupported.

Exact identity and conditional same-parameter call summaries now have focused
owner-invalidation evidence through a shared child of the returned mutable
reference. Direct mutation of the original parameter fails while that child is
live and succeeds after its last use. The pinned oracle rejects both overlaps
with E0503 and accepts both controls; Windows and Arch remain at 987 tests.
Unknown call-result ancestry remains conservative.

The same identity and conditional same-parameter results now preserve outlives
origins through a mutable-to-shared child returned from the caller. Parameter-
backed children are accepted, while equivalent children of local-backed call
results fail closed. The pinned oracle accepts both parameter returns and
rejects both local escapes with E0515. Windows and Arch each pass 642 library
tests, one component-interface probe, 10 conformance tests, and 335 replacement
tests: 988 compiler tests per host.

Explicit return and conditional early-return/tail joins now retain that same
call-derived shared-child origin. Parameter-backed children remain valid at all
sites; equivalent local-backed children fail the bounded outlives check. The
pinned oracle accepts both parameter forms and rejects both local escapes with
E0515. Windows and Arch remain at 988 compiler tests per host.

Loop-contained direct and conditional returns now carry the same call-derived
shared-child outlives origin. Parameter-backed identity and conditional results
are accepted, and equivalent loop-local children fail closed. The pinned oracle
accepts both parameter forms and rejects both local escapes with E0515. Windows
and Arch remain at 988 compiler tests per host; general loop dataflow remains
unsupported.

Shared children of projected mutable-reference call results also retain the
callee summary's proven second-parameter origin. Straight-line and exhaustive
conditional tuple-field replacement calls accept a parameter-backed second
argument, while matching calls supplied with caller-local storage fail the
bounded return-outlives check. The pinned oracle accepts both parameter forms
and rejects both local escapes with E0515. Windows and Arch remain at 988
compiler tests per host; general interprocedural lifetime inference remains
unsupported.

Explicit returns and conditional early-return/tail joins now preserve that same
projected call-derived shared-child origin. Parameter-backed forms pass, while
matching local-backed forms fail the bounded outlives check. The pinned oracle
reports E0515 at both local return sites. Windows and Arch remain at 988 compiler
tests per host; general interprocedural lifetime inference remains unsupported.

Direct and conditional returns inside supported `loop` blocks now preserve the
same projected call-derived shared-child origin. Parameter-backed second
arguments pass, while matching loop-local second arguments fail the bounded
outlives check. The pinned oracle accepts both parameter forms and rejects both
local escapes with E0515. Windows and Arch remain at 988 compiler tests per
host; general loop and region fixed points remain unsupported.

Nested supported `loop` returns preserve that projected shared-child origin.
Direct places passed to reference-typed call parameters now receive Rust's
implicit reborrow effect. Every reference argument loan remains live with a
reference result, while only the proven origin supplies returned-pointer
ancestry. The pinned oracle and MRML accept the nonterminal backedge after the
result dies and reject a competing non-origin borrow while it remains live
(E0499 / `RuntimeBorrowConflict`). An inner-loop-local origin still fails with
E0515. Both hosts pass 988 compiler tests; general loop fixed points are absent.

A local-backed non-origin argument also prevents returning the otherwise
parameter-origin result. This retains the distinction between returned-pointer
ancestry and the lifetime of every call-argument loan; MRML's bounded outlives
failure matches the pinned oracle's E0515. Both hosts remain at 988 tests.
Once the result's last use has occurred, the tied non-origin local loan ends and
subsequent local mutation is accepted, matching the pinned oracle.
Conditional same-place arguments also inherit the expected call-reference
reborrow context in both arms. A live result blocks a competing borrow, while
post-last-use mutation succeeds; the pinned oracle matches with E0499 and
acceptance respectively. Both hosts remain at 988 compiler tests.
When the two conditional arms select distinct owners, the joined result retains
both possible loans while live and releases both after last use. MRML's two
`RuntimeBorrowConflict` cases match pinned-oracle E0503, and both post-use
mutations are accepted. Both hosts remain at 988 compiler tests.
The same joined origin set now has return-outlives coverage. An all-parameter
conditional call result may return a shared child; substituting local storage in
either possible origin set fails closed and matches pinned-oracle E0515. Both
hosts remain at 988 compiler tests.
Scalar shared-reference parameters/results now have a bounded identity-call
path. The returned shared loan blocks owner mutation while live and releases
after last use, matching pinned-oracle E0502 and acceptance. Both hosts remain
at 988 compiler tests; general shared-reference call inference is unsupported.
The shared identity result also participates in bounded return-outlives checks:
parameter ancestry passes and local ancestry fails, matching pinned-oracle
E0515. A new focused unit raises both hosts to 989 compiler tests (643 library,
one component, 10 conformance, and 335 replacement tests).
Conditional shared-call arguments also preserve both possible immutable loans
at the join. A live result blocks mutation of either owner, and last use releases
both; pinned rustc matches with E0506 and post-use acceptance. Both hosts remain
at 989 compiler tests.
Conditional shared-call results also retain their full origin set at a function
return. Two parameter arms pass; replacing either possible origin with local
storage fails closed and matches pinned-oracle E0515. Both hosts remain at 989
compiler tests.
Loop-carried loan liveness now separates dynamic borrower generations at the
static reinitialization point. A later use in the same iteration still blocks
owner mutation, while an old loan does not flow through the next iteration's
generation after its last use. The pinned oracle matches with E0506 and an
accepted copy-before-mutation case. Both hosts remain at 989 compiler tests.
Mutable-reference calls now retain the same paired evidence: mutation before a
later result use fails, while copying first releases the exclusive loan before
mutation and the next iteration. Pinned rustc matches with E0503 and acceptance;
both hosts remain at 989 compiler tests.
Conditional shared-call joins now retain the same paired evidence across loop
generations for both possible owners. Either same-iteration owner mutation fails
before a later result use; copying first releases both candidate loans before
mutation and the backedge. Pinned rustc matches with E0506 and acceptance; both
hosts remain at 989 compiler tests.
Nested `while` control flow retains the same joined generation boundary at the
inner backedge. A later same-iteration result use protects either possible owner;
copying first releases both candidate loans before mutation across the nested
loop structure. Pinned rustc matches with E0506 and acceptance; both hosts
remain at 989 compiler tests. This remains bounded CFG evidence.
Nonterminal conditional arms inside a supported callee `while` now participate
in the one-iteration origin transfer. Each arm receives the incoming bounded
local/projected state, fallthrough outcomes intersect, an absent final `else`
adds the unchanged path, and the result still intersects the zero-iteration
state. Direct assignment is enabled for existing aliases on modeled fallthrough
and terminal-return arms; a terminal return observes the post-assignment state.
Nested-loop handling preserves its projected-only guard. The pinned oracle
accepts stable same-origin arm reborrows and rejects a local-backed arm with
E0515. Both hosts remain at 989 compiler tests; this is not a general loop fixed
point or region solver.
Mixed terminal/fallthrough arms now use two distinct destinations in that same
bounded transfer. A supported `return` contributes function-exit origin evidence
and is excluded from the backedge join; nonterminal arms alone form iteration
state before the mandatory zero-iteration intersection. Terminal direct alias
assignment is applied before return-origin resolution. The pinned oracle accepts
the stable parameter-backed pair and terminal same-origin assignment, and rejects
immediate or loop-carried local-backed returns with E0515. Both hosts remain at
989 compiler tests. Break/continue, expressions, nested-loop transfer, and
general fixed points remain unsupported.

Nested-loop return summaries now consume the parser's exact action index and
control order for every unconditional or conditional return. A reachable return
receives only its source-preceding action prefix, and returns after an earlier
unconditional nested control are ignored as unreachable. This admits exact
direct parameter reassignments without letting a later reassignment rewrite an
earlier return's origin. The pinned oracle accepts the ordered parameter-backed
case and rejects the corresponding earlier local-backed return with E0515.
Windows and native Arch Linux WSL each pass 643 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 989 compiler
tests per host. This is bounded source-ordered transfer, not a nested-loop fixed
point or region solver.
Nested inner-loop state edges now have a separate stability gate. Every normal
backedge and conditional or unconditional break/continue prefix must preserve
the incoming outer local and projected origins before return-origin inference is
accepted. Exact restoration to the same parameter is supported; a local-backed
or changed origin fails closed. The pinned oracle accepts restore-before-
backedge and rejects the unrestored cycle with E0515. Windows and native Arch
Linux WSL each pass 643 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 989 compiler tests per host. This
does not claim a general nested-loop fixed point or region solver.
Direct conditional-return operations are now accepted in the same loop state
transfer after supported local declarations and assignments. A taken return
uses the exact current alias/projected state for the function-exit origin; the
false path continues toward later operations and the existing iteration join.
The pinned oracle accepts a stable parameter reborrow and rejects a local-backed
replacement with E0515. Windows and native Arch Linux WSL each pass 643 library
tests, one component-interface probe, 10 conformance tests, and 335 replacement
tests: 989 compiler tests per host. Unconditional returns and mixed loop control
remain conservative.
Direct unconditional returns now resolve against the same current transfer
state, end the iteration, and disconnect later syntactic operations from the
backedge. Condition-headed loops preserve only their zero-iteration input as a
continuation. The pinned oracle accepts a stable parameter reborrow followed by
an unreachable suffix and rejects a local-backed return with E0515. Both hosts
remain at 989 compiler tests; mixed break/continue exits remain conservative.
Direct break exits now carry the current outer origin state past the loop.
Condition-headed loops join it with the zero-iteration input, whereas an
unconditional loop has only the break outcome. Loop-local facts are discarded.
The pinned oracle accepts an unconditional parameter overwrite and rejects the
equivalent `while` zero-iteration/local path with E0515. Both hosts remain at
989 compiler tests; conditional break/continue transfer remains conservative.
Conditional breaks now feed a bounded exit accumulator without contaminating
the false path's later operations or backedge. Multiple break outcomes
intersect; `while` adds its natural/zero exit and an unconditional loop does not.
The pinned oracle accepts a parameter-backed break with local state only on the
continuing path and rejects a local-backed break with E0515. Both hosts remain
at 989 compiler tests. Conditional continue and block-terminal breaks remain
conservative.
Direct continue now terminates the current operation suffix and carries its
current origin state to the backedge. The pinned oracle accepts a parameter-
backed conditional return before that continue and identifies the later local
assignment as unreachable. Both hosts remain at 989 compiler tests; conditional
continue still needs a multi-backedge join.
Conditional continue now feeds a bounded backedge accumulator while its false
path continues through the remaining operations. Direct continue and normal
fallthrough contribute to the same intersection before a `while` natural exit
is computed. The pinned oracle accepts stable parameter-backed outcomes and
rejects a local-backed fallthrough backedge with E0515. Both hosts remain at 989
compiler tests; conditional-block terminal continue remains conservative.
Conditional action-block terminal break and continue arms now route their
post-action origin state to loop exits and backedges instead of contaminating
the later-operation fallthrough join. The pinned oracle accepts parameter-
backed terminal controls and rejects a local-backed break arm with E0515. Both
hosts remain at 989 compiler tests; nested-loop state transfer and general fixed
points remain incomplete.
Nested inner-break outcomes now export their exact outer-visible origin state to
later outer-loop operations. Condition-headed inner loops join zero iterations;
inner continue and normal backedges must remain stable. The pinned oracle
accepts a parameter overwrite before an inner break and rejects local-backed
and zero-iteration/local exits with E0515. Both hosts remain at 989 compiler
tests; general nested fixed points remain incomplete.
Labeled nested breaks and continues now carry distinct outer-visible states to
the enclosing loop's exit and backedge joins. Only inner-loop exits fall through
to later outer operations, and controls ordered after an unconditional edge are
unreachable. The pinned oracle accepts parameter-backed labeled break and
continue paths and rejects local-backed equivalents with E0515. Both hosts pass
643 library tests, one component-interface probe, 10 conformance tests, and 335
replacement tests: 989 compiler tests per host. General nested fixed points
remain incomplete.
Focused mixed-path cases now pair a conditional outer-target break or continue
with an independently reachable inner exit. Parameter-backed states remain
exact at both destinations; making either selected path local-backed fails
closed and matches pinned-oracle E0515. Windows and Arch remain at 989 compiler
tests per host. This is destination-separation evidence, not a general nested-
loop fixed point.
Nested normal backedges additionally admit a single normalized candidate when
the full action transfer is idempotent on exact replay. All stored control
prefixes must expose the same retained origins from the incoming and normalized
headers, preventing an early exit from inheriting a later overwrite. The pinned
oracle accepts normalization before every exit and rejects the reversed order
with E0515. Both hosts remain at 989 compiler tests; multi-step and branching
fixed points remain incomplete.
Conditional inner continues now share that normalized candidate proof. A
continue after the parameter overwrite is accepted when all control prefixes
agree across both headers; controls before normalization still fail closed and
match pinned-oracle E0515. Both hosts remain at 989 compiler tests.
Unconditional inner continues use a prefix-bounded candidate ending at the
control's exact action index. Exact replay and all earlier control prefixes must
agree, while unreachable suffix actions are ignored. The pinned oracle accepts
normalization before return/continue and rejects a return before normalization
with E0515. Both hosts remain at 989 compiler tests; iterative multi-backedge
fixed points remain incomplete.
Multiple conditional inner continues now contribute to a bounded header meet
alongside initial entry and normal fallthrough. One replay must reproduce that
header exactly, and all exit prefixes must agree between initial and joined
states. The pinned oracle accepts differing continue origins normalized before
every exit and rejects an early local-backed break with E0515. Both hosts remain
at 989 compiler tests; unconditional mixed-backedge and general iterative fixed
points remain incomplete.
The joined-header proof now stops at the earliest unconditional nested-loop
exit. Only earlier conditional inner continues contribute backedges, the
terminal prefix must agree across headers, and its suffix is unreachable. The
pinned oracle accepts a normalized unconditional break after differing
backedges and rejects an earlier local-backed break with E0515. Both hosts
remain at 989 compiler tests; nested branching and broader iterative fixed
points remain incomplete.
An unconditional inner continue instead joins its prefix into the bounded
header with earlier conditional backedges. Exact convergence remains mandatory,
only exit prefixes require invariance, and the terminal suffix is unreachable.
The pinned oracle accepts mixed parameter/local backedges normalized before a
return and rejects an earlier local-backed return with E0515. Both hosts remain
at 989 compiler tests; nested branching and broader iterative fixed points
remain incomplete.
Nested headers now iterate the monotone origin meet to a bounded fixed point.
Each direct or projected origin fact can only be dropped once, establishing an
exact `local_count + projected_origin_count + 1` transfer limit; nonconvergence
fails closed. A multi-step alias chain converges and returns the parameter only
after an explicit restoring assignment. The pinned oracle accepts that ordering
and rejects an earlier exit with E0499. Both hosts remain at 989 compiler tests.
Flat modeled nested actions/controls now have iterative header convergence;
nested branch-action representation and general regions remain incomplete.
Nested conditional branches can now retain up to four scoped actions before a
target-aware terminal in a dedicated parser record, including their exact
position among surrounding actions and controls. The record now also retains
one explicit bounded `else` action/terminal arm. Compilation, constant
native emission rejects that form. Constant evaluation selects one arm,
executes its actions with lexical truncation, and routes its target-aware
terminal under the existing loop bound. CFG preanalysis emits a
distinct else-action block from the condition's false edge, routes both
terminals independently, and maps else actions/returns to distinct ownership
locations. Branch assignment generations in either arm reuse the bounded
direct-assignment origin rule. CFG construction for the single-arm form emits
separate condition and action blocks with explicit false fallthrough and true
terminal routing; ownership preanalysis gives conditions, scoped actions, and
return values distinct mapped locations. Reference-return records apply their
exact scoped action prefix before resolving origins: parameter reborrows are
admitted while local-backed returns fail closed. Reference break/continue
records transfer their scoped state to inner/outer exit destinations and outer
continues. Inner continues participate in the existing monotone bounded header
join, with post-backedge exits admitted only when their state is invariant at
the converged header. The bounded constant evaluator executes these records using lexical resolver
truncation and the existing loop limit for inner/outer
break, continue, and return. Focused tests cover retained branch actions,
CFG/ownership mapping, all constant terminal kinds, untaken fallthrough, and
the fail-closed reference boundary. Direct and inline x86-64 emitters now lower
scalar-only branch actions, scoped stack cleanup, and target-aware terminals;
reference-return lowering is admitted only after the origin proof, while
reference break/continue forms use the bounded destination/backedge transfer.
Separate return, continue, and break probes reach ELF64 and COFF objects.
Windows and native Arch Linux WSL each pass 645 library tests, one component-
interface probe, 10 conformance tests, and 336 replacement tests: 992 compiler
tests per host.
Nested-loop ordered-return and stable-edge analysis is now factored over an
explicit incoming state and composes after outer-loop declarations, assignments,
and branch joins. Stable nested edges preserve that state for later outer
operations. The pinned oracle accepts an outer same-origin reassignment before a
nested return and rejects the local-backed counterpart with E0515. Both hosts
remain at 989 compiler tests; general nested-loop exit-state transfer and fixed
points remain incomplete.

Exact typed tuple literals now seed the same projected state when a local is
declared. Every reference field is checked against the declared tuple element
and return type; only a parameter-backed element records an origin. Scalar and
local-backed fields remain without origin evidence, and invalid or over-capacity
initializers fail closed. The transfer is shared by top-level, conditional-
action, conditional-loop, and loop-body locals. Focused tests cover direct
return, local-backed rejection, stable loop identity reborrow, caller conflict,
and post-last-use restoration. The pinned oracle accepts those exact parameter-
backed shapes and rejects the live competitor with E0499. Both hosts remain at
987 tests.

A mutable grandchild reborrow through an exact tuple-field child now has focused
cross-host and oracle coverage. The ultimate parameter owner remains suspended
while the grandchild is live and is restored after last use; the oracle rejects
the live competitor with E0499. Both hosts remain at 987 tests.

An exact identity-call result assigned into an existing mutable-reference local
now has focused projected-argument ancestry coverage. A tuple-field argument
remains connected through the call result to its ultimate owner; the oracle
rejects a live competitor with E0499 and accepts restoration after last use.
Both hosts remain at 987 tests.

The exact call-assignment path also retains both owners when its argument is a
conditional choice between two tuple fields. The pinned oracle rejects live use
of either owner with E0503 and accepts both after last use. Windows and Arch
remain at 987 tests.

A shared call through an exact tuple-field parent now has focused invalidation
coverage against a live mutable child of that field. The pinned oracle rejects
the overlap with E0502 and accepts the call after the child's last use. Windows
and Arch remain at 987 tests.

The complementary mutable call through an exact tuple-field parent is rejected
while a shared child remains live and accepted after that child's last use. The
pinned oracle reports E0502 for the overlap. Windows and Arch remain at 987
tests.

Explicit mutable-to-shared assignment from an exact or conditional tuple field
now has focused ancestry coverage. Every possible owner remains protected from a
live competing mutable reborrow and is restored after the shared child's last
use. The pinned oracle reports E0503 for direct live-owner use. Windows and Arch
remain at 987 tests.

Multi-field initialization uses one independent key per tuple field. An exact
conditional reference element records an origin only when both arms resolve to
the same parameter; differing first/second origins remain unavailable. Focused
direct and caller tests cover the equal-origin result, ambiguity, live conflict,
and post-last-use restoration. The pinned oracle accepts the equal-second-
parameter conditional element and rejects its live competing borrow with E0499.

An exact initialized field may be consumed into one explicitly typed reference
local and returned without losing its parameter origin. The equal-origin
conditional multi-field path uses the same transfer. The initializer hook now
treats non-tuple or unavailable local types as neutral, preventing unrelated
reference locals from aborting a valid callee proof, while malformed tuple
initializers still fail closed. Focused direct/caller tests and ORACLE-0002 cover
the moved alias, live E0499 conflict, and post-last-use owner restoration. Both
hosts remain at 987 tests.

Focused projected-origin evidence now includes two successive consuming typed
reference locals and a consuming local after either an exhaustive equal-origin
conditional field assignment or a stable loop self-reborrow. The parameter
origin remains attached to each exact generation. The pinned oracle accepts the
chain and both post-control-flow forms, accepts restoration after last use, and
rejects the live move-chain competitor with E0499. Both hosts remain at 987
tests; this is bounded move propagation, not general alias or region inference.

The reference RHS type walker now resolves exact numeric tuple fields. A field
may replace a compatible root reference alias and transfer its parameter origin;
a local-backed field clears that origin. Inferred local-backed aliases still
accept a later compatible parameter replacement, as the exact oracle does, so
initializer origin is not used as a substitute for type compatibility. Focused
tests and ORACLE-0002 cover both accepted replacements, local-backed clearing,
live E0499 conflict, and post-last-use restoration. Both hosts remain at 987
tests.

Exact tuple-field RHS assignment now participates in the existing root-alias
conditional and loop joins. Exhaustive equal-origin branches retain the field
origin; a missing branch exposes a differing incoming alias and clears it. A
stable loop reassigns the alias from an identity reborrow of the same field and
intersects that with the zero-iteration incoming state, rejecting a differing
origin. Focused tests and ORACLE-0002 cover both accepted forms, conservative
controls, live E0499 conflict, and post-last-use restoration. Both hosts remain
at 987 tests.

Conditional action blocks now support a branch-local typed tuple whose exact
field is assigned into an outer root alias. Projected entries are compacted to
the pre-branch local-index prefix before fallthrough states intersect, so a
later local reusing the same bounded slot cannot observe stale branch provenance.
Focused state, direct, caller, and stale-slot tests plus ORACLE-0002 cover the
accepted equal-origin transfer, E0499 live conflict, E0515 local-backed return,
and post-last-use restoration. Both hosts remain at 987 tests.

A supported loop may now form an iteration-local typed tuple from an identity
reborrow of an outer alias and assign the field back into that alias. Its exact
origin survives only when it equals the zero-iteration incoming origin; a local-
backed tuple makes the result unavailable. The loop intersection also removes
the scoped projected entry. Focused caller/control tests and ORACLE-0002 cover
the accepted form, E0499 live conflict, E0515 local-backed escape, and restoration
after last use. Both hosts remain at 987 tests.

A conditional block within a supported loop may now assign an exact typed tuple
field into a branch-local mutable-reference alias immediately before returning
it. This path is restricted to a discovered tuple-field RHS, and every reachable
return must retain the same parameter origin. Pinned-oracle evidence accepts the
parameter-backed reborrow and post-last-use owner reuse and rejects a live
competitor and a local-backed field return. Both hosts remain at 987 tests.

Nested loop blocks now have focused coverage for the same exact tuple-field
assignment before a conditional return. Pinned-oracle evidence accepts the
parameter-backed result and owner restoration after last use and rejects live
competition and local-backed escape. Both hosts remain at 987 tests.

Conditional assignment from two exact tuple-field reborrows now traces each
projected loan back through the field's recorded initializer and reassignment
origin. Both possible owners remain protected while the selected child is live
and become available after its last use. The pinned oracle rejects both live
competitors with E0499 and accepts both restoration controls; Windows and Arch
remain at 987 tests.

An overwritten tuple reference field now retains the initializer, intermediate,
and latest exact owners for descendants moved from that field. The pinned oracle
rejects the original owner with E0503 and replacement owner with E0499 while the
child remains live and accepts both after last use. Windows and Arch remain at
987 tests.

The conditional projected-reassignment milestone extends the bounded tuple-field
loan chain across a conditional shared-reference assignment. The exact dated
oracle rejects mutation of either conditional owner and of the field's replaced
initialization owner while a moved descendant remains live, accepts unrelated
mutation, and accepts mutation of both conditional owners after the descendant's
last use. MRML gives the conditional generation and prior exact field origin
distinct bounded fact identities and carries both through liveness, mutable-
parent suspension, and return-outlives traversal. Two successive exact field
writes likewise retain the initialization owner, intermediate owner, and latest
owner until the moved descendant's last use. Windows gnullvm and native
Arch Linux WSL each pass 420 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 766 compiler tests per host. The
unchanged driver and warnings-denied Clippy were not re-executed. This does not
claim path-sensitive branch selection, nested projections, general aggregate
provenance, named regions, or complete Polonius semantics. The
`no_std`/allocation/unsafe hygiene scan remained empty.

Mutable-reference parameter roots now participate in dereference-write loan
invalidation. A direct shared assignment, an exact tuple-field shared
assignment, and a conditional choice between two such fields all reject direct
owner mutation while the assigned child remains live and accept owner mutation
after its last use. The pinned oracle rejects the direct parameter form with
E0506, rejects the conditional projected form with E0503, and accepts the
last-use control. Windows gnullvm and native Arch Linux WSL each pass 641
library tests, one component-interface probe, 10 conformance tests, and 335
replacement tests: 987 compiler tests per host. This does not establish general
regions or arbitrary projected-place invalidation.

Focused nested-owner coverage now carries that same invalidation through two
successive mutable local reborrows and a final shared grandchild. The incoming
owner cannot be written while the grandchild remains live and becomes writable
after its last use. The pinned oracle rejects the overlap with E0503 and accepts
the restoration control. Both hosts remain at 987 compiler tests; this is exact
bounded ancestry evidence, not general region inference.

Conditional mutable-parent reassignment now has focused direct-owner mutation
coverage after a shared child is formed. The initializer owner and optional
replacement owner both remain protected while the child is live and both become
writable after its last use. The pinned oracle rejects each overlap with E0503
and accepts the combined restoration control. Both hosts remain at 987 compiler
tests; path-sensitive regions remain unsupported.

The matching single-exit loop-carried case now protects both the pre-loop owner
and the owner assigned before `break` from direct mutation while a post-loop
shared child is live. Both become writable after the child's last use. The
pinned oracle rejects each overlap with E0503 and accepts the combined control;
both hosts remain at 987 compiler tests. General loop fixed points remain
unsupported.

The projected conditional-return outlives milestone validates every retained
origin of the latest reference assignment when an exact tuple field is returned.
The exact dated oracle rejects a conditional local/parameter generation with
E0515 and accepts a directly projected parameter plus a conditional generation
whose two branches both trace to that parameter. MRML now reports its bounded
outlives diagnostic for the mixed generation instead of degrading to invalid
internal place facts. Windows gnullvm and native Arch Linux WSL each pass 420
library tests, one component-interface probe, 10 conformance tests, and 335
replacement tests: 766 compiler tests per host. Formatting and the
`no_std`/allocation/unsafe hygiene scan pass. The Manifest V2 workspace rejects
the obsolete Cargo package selector, so warnings-denied Clippy was not exercised.
This remains exact one-step tuple-field provenance, not general aggregate escape
analysis, path-sensitive branch selection, named lifetime inference, or complete
Polonius semantics.

The conditional tuple-initialization return milestone groups reference origins
created before one tuple-root initialization by exact reference-field ordinal.
It distinguishes reference-value copies and moves from fresh shared or mutable
borrows, then requires every conditional origin of the selected returned field
to outlive the function. The exact oracle rejects a mixed local/parameter field
with E0515 and accepts two parameter-backed branches. Sibling controls with a
local-backed reference in the other field remain accepted for either selected
field position. Windows gnullvm and native Arch Linux WSL each pass the same 766
compiler tests. This is bounded one-level tuple initialization, not nested tuple
types, arbitrary nested conditional grouping, named lifetime inference, or
complete Polonius semantics.

The moved projected-return evidence confirms that exact tuple-field origins
survive one projected move into a reference local before return. Direct and
conditional initializations, mutually exclusive assignments, and disconnected
post-`break` writes preserve the same accepted/rejected outcomes as direct field
returns. Windows gnullvm and native Arch Linux WSL each pass the same 766
compiler tests. This is independently authored oracle and MRML evidence for the
existing bounded moved-loan relation, not general alias analysis or regions.

Projected identity-call return evidence composes the conditional mutable tuple-
field origin set with the existing bounded call-argument relation. Both a direct
identity-call tail and one stored call result reject a possible local-backed
origin and accept all parameter-backed branches. Windows gnullvm and native Arch
Linux WSL each pass the same 766 compiler tests. This is bounded composition of
existing facts, not general interprocedural lifetime inference or regions.

The trait-goal canonicalization foundation introduces allocation-free stable
trait, type, inference-variable, and placeholder identities plus an eight-
argument implemented goal. Canonicalization numbers inference variables by
first occurrence, preserves repeated-variable equality, leaves placeholders and
concrete types distinct, and makes alpha-equivalent goals identical. Argument
and canonical-variable overflow fail explicitly. It does not parse traits,
select implementations, normalize projections, decide ambiguity, check
coherence, or handle solver cycles. Windows gnullvm and native Arch Linux WSL
each pass 425 library tests, one component-interface probe, 10 conformance tests,
and 335 replacement tests: 771 compiler tests per host. The core remains
`no_std`, allocation-free, and `unsafe`-free.

The exact trait-implementation selection milestone adds a fixed 64-header
database over the canonical goal form. Insertion rejects duplicate stable IDs
and overlapping exact concrete heads. Solving returns one exact implementation
for a rigid ground match, no solution for concrete or placeholder mismatch, and
ambiguity for an inference-bearing match because answer substitutions are not
yet represented. A fixed per-candidate binding table enforces equality across
repeated canonical-variable occurrences. Capacity overflow fails explicitly.
Windows gnullvm and native Arch Linux WSL each pass 431 library tests, one
component-interface probe, 10 conformance tests, and 335 replacement tests: 777
compiler tests per host. This is not generic unification, where-clause solving,
projection normalization, recursive goal handling, specialization, complete
coherence, or source-level trait support.

The bounded trait-answer milestone retains the fixed bindings produced while
matching an exact header. A unique answer contains the stable implementation ID
and an eight-slot canonical-variable substitution; a one-variable query can
therefore return its concrete binding. Two matching concrete headers still
produce ambiguity, mismatches produce no solution, and repeated variables must
bind equally. Windows gnullvm and native Arch Linux WSL each pass 432 library
tests, one component-interface probe, 10 conformance tests, and 335 replacement
tests: 778 compiler tests per host. The result is not generic unification,
where-clause solving, projection normalization, recursive goal handling, answer
composition, specialization, complete coherence, or source-level trait support.

The bounded response-substitution milestone retains the caller's inference-
variable identities alongside the canonical goal. A unique answer can then be
mapped back to fixed `(inference variable, concrete type)` bindings in canonical
first-occurrence order. Missing bindings or mismatched response arity fail
closed; lookup is fixed-capacity and allocation-free. Windows gnullvm and native
Arch Linux WSL each pass 433 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 779 compiler tests per host. This
does not implement generic unification, nested answer composition, where-clause
solving, projections, recursive goals, or source-level trait support.

The bounded predicate-conjunction milestone stores up to eight implemented-
trait predicates and canonicalizes them together in one shared eight-variable
universe. The same inference identity reused in separate predicates maps to the
same canonical bound variable; predicate-count and aggregate variable overflow
fail explicitly. Windows gnullvm and native Arch Linux WSL each pass 436 library
tests, one component-interface probe, 10 conformance tests, and 335 replacement
tests: 782 compiler tests per host. This does not elaborate or solve where
clauses, introduce binders or generic impls, recurse, or compose answers. The
`mrml build mrml-rustc` frontend gate passes on both hosts. The obsolete Cargo
package selector rejects the documented compiler-only Clippy command before
compilation, so no new warnings-denied Clippy evidence is claimed.

The bounded where-clause binder milestone adds a distinct generic-parameter
term and represents one bound consequence plus up to eight bound premises over
eight parameters. Construction rejects out-of-scope parameters and excess
capacity. Concrete instantiation requires exact arity and replaces every
repeated parameter consistently through the consequence and premises. Windows
gnullvm and native Arch Linux WSL each pass 438 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 784 compiler
tests per host. This is allocation-free binder representation and instantiation,
not clause elaboration, generic impl selection, source syntax, projection
normalization, or recursive solving.

The single-clause elaboration milestone structurally matches one fully concrete
implemented-trait query against a bound consequence. It infers generic arguments
in a fixed array and instantiates the premises only when all parameters are
constrained. Repeated parameters must match equal concrete types; mismatches
produce no solution, unconstrained parameters remain ambiguous, and inference-
bearing or placeholder queries fail closed. Windows gnullvm and native Arch
Linux WSL each pass 439 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 785 compiler tests per host. This
does not add a clause database, multi-candidate combination, recursion, cycles,
projection normalization, or source syntax.

The identified clause-database milestone adds a fixed 64-clause table. Insertion
rejects duplicate stable IDs and structurally identical clauses. Potentially
overlapping distinct clauses remain stored, but a query with multiple unique
matches or any unconstrained matching candidate fails closed as ambiguous; one
match returns the stable clause ID and instantiated premises. Windows gnullvm
and native Arch Linux WSL each pass 443 library tests, one component-interface
probe, 10 conformance tests, and 335 replacement tests: 789 compiler tests per
host. The database performs no recursive premise solving, cycle handling,
projection normalization, or source integration.

The bounded recursive-proof milestone first accepts an exact concrete
implementation fact, otherwise elaborates one unique clause and proves each of
its concrete premises. A fixed 16-goal stack returns distinct `Proven`,
`NoSolution`, `Ambiguous`, `Cycle`, and `Overflow` outcomes; a cycle closing at
the stack boundary is identified before overflow. Windows gnullvm and native
Arch Linux WSL each pass 447 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 793 compiler tests per host. This
does not recurse over inference-bearing goals, cache answers, apply coinduction,
normalize projections, or integrate source trait syntax.

The exact associated-type normalization milestone adds stable associated-type
IDs and a fixed 64-value table keyed by `(implementation, associated type)`.
Values must reference an implementation already registered in the exact header
database; stale IDs, duplicate keys, and overflow fail. Normalization reuses the
canonical implementation selector and preserves its unique, ambiguous, and no-
solution outcomes. Windows gnullvm and native Arch Linux WSL each pass 450
library tests, one component-interface probe, 10 conformance tests, and 335
replacement tests: 796 compiler tests per host. Values cannot contain generic
parameters or nested projections, and there is no source integration or
recursive normalization.

The rigid-placeholder universe milestone adds an explicit 16-bit universe to
each stable placeholder identity. A bound clause can instantiate its parameters
as distinct rigid placeholders in a caller-selected fresh universe;
canonicalization preserves them, placeholders from separate universes do not
alias, and universe increment overflow fails explicitly. Windows gnullvm and
native Arch Linux WSL each pass 452 library tests, one component-interface
probe, 10 conformance tests, and 335 replacement tests: 798 compiler tests per
host. This is a higher-ranked prerequisite, not leak checking, universe-relation
reasoning, higher-ranked matching, or source `for<...>` support.

The inference-universe leak-check milestone records the creation universe in
each inference-variable identity; the existing `new(id)` constructor continues
to create a root variable. Canonicalization keeps equal numeric IDs from
different universes distinct. Checked assignments accept concrete and same-or-
older-universe values but reject a newer placeholder or inference variable with
`UniverseLeak`. Windows gnullvm and native Arch Linux WSL each pass 454 library
tests, one component-interface probe, 10 conformance tests, and 335 replacement
tests: 800 compiler tests per host. General unification, higher-ranked candidate
matching, universe relations beyond this ordering, and source `for<...>` remain
unsupported.

The rigid clause-matching milestone accepts bound-clause queries containing only
concrete types and rigid placeholders. Generic parameters can bind either kind;
repeated parameters require exact equality and instantiated premises retain the
same placeholder universe and identity. The 64-clause database preserves unique,
ambiguous, and no-solution classification, while inference-bearing rigid queries
fail explicitly. Windows gnullvm and native Arch Linux WSL each pass 456 library
tests, one component-interface probe, 10 conformance tests, and 335 replacement
tests: 802 compiler tests per host. Recursive rigid proof, complete higher-ranked
reasoning, general unification, and source `for<...>` remain unsupported.

The bounded rigid-proof milestone applies the existing 16-frame proof stack to
goals containing concrete types and skolem placeholders. Exact concrete facts
may close a branch; otherwise one unique rigid clause is elaborated and every
premise is recursively proved. `Proven`, `NoSolution`, `Ambiguous`, `Cycle`, and
`Overflow` remain distinct, while inference-bearing entry goals fail. Windows
gnullvm and native Arch Linux WSL each pass 458 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 804 compiler
tests per host. Mixed inference/skolem unification, coinduction, complete higher-
ranked reasoning, and source `for<...>` remain unsupported.

The flat generic-head coherence milestone adds a 64-entry identified generic-
implementation table. A fixed 16-node equality unifier decides whether two
concrete/parameter heads share any instantiation across their separate binders.
Concrete constraints propagate through unions, so repeated parameters overlap
equal concrete positions but remain disjoint from unequal ones. Duplicate IDs,
satisfiable overlap, and capacity overflow fail. Windows gnullvm and native Arch
Linux WSL each pass 461 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 807 compiler tests per host.
Premises do not waive head conflicts; cross-family coherence, specialization,
and source impl syntax remain unsupported.

The coherent generic-selection milestone matches a concrete query against the
admitted 64-entry generic implementation table. A fully constrained match
returns its stable implementation ID and instantiated premises; an absent head
returns no solution, while a parameter used only by premises remains ambiguous.
Inference-bearing queries fail at this concrete boundary. Windows gnullvm and
native Arch Linux WSL each pass 463 library tests, one component-interface
probe, 10 conformance tests, and 335 replacement tests: 809 compiler tests per
host. Recursive generic-implementation proof, specialization, source impl syntax,
and mixed inference selection remain unsupported.

The recursive generic-proof milestone sends each instantiated premise back
through the existing 16-frame concrete proof stack. Exact facts, further generic
implementations, and bounded where clauses can discharge a branch; missing
premises, ambiguity, cycles, and overflow remain distinct. An exact/generic
collision fails closed as ambiguity until admission is coherent across both
families. Windows gnullvm and native Arch Linux WSL each pass 466 library tests,
one component-interface probe, 10 conformance tests, and 335 replacement tests:
812 compiler tests per host. Inference-bearing generic proof, specialization,
cross-family coherence, source impl syntax, and mixed inference selection remain
unsupported.

The cross-family coherence milestone adds symmetric bounded admission methods
for exact and generic implementations. A concrete header that instantiates a
generic head is rejected in either insertion order, including conflicts imposed
by repeated generic parameters; disjoint heads remain admissible. The proof
solver preserves defensive ambiguity for unchecked legacy collisions. Windows
gnullvm and native Arch Linux WSL each pass 468 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 814 compiler
tests per host. Premise-aware coherence, specialization, source impl syntax, and
mixed inference selection remain unsupported.

The generic associated-type normalization milestone adds a separate fixed
64-value table keyed by stable generic-implementation and associated-type IDs.
Values may be concrete or name one bound implementation parameter. The selected
implementation answer retains its fixed substitution, and normalization first
requires every instantiated premise to prove. Missing premises and values return
no solution; unchecked selection collisions, proof cycles, and proof overflow
remain ambiguous. Stale IDs, duplicate keys, and unbound parameters fail
explicitly. Windows gnullvm and native Arch Linux WSL each pass 471 library
tests, one component-interface probe, 10 conformance tests, and 335 replacement
tests: 817 compiler tests per host. Nested projection terms, premise projection
goals, specialization, source associated-type syntax, and mixed inference
selection remain unsupported.

The unified concrete-projection milestone chooses between exact and generic
implementation families before reading their separate fixed value tables. Exact
facts return exact values; generic candidates retain recursive premise proof and
parameter substitution. Missing implementations or values return no solution,
and any unchecked cross-family collision fails closed as ambiguity. Windows
gnullvm and native Arch Linux WSL each pass 473 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 819 compiler
tests per host. Nested projections, projection answer composition,
specialization, source associated-type syntax, and mixed inference selection
remain unsupported.

The bounded nested-projection milestone permits a generic associated value to
hold a projection template over the same implementation binder. The selected
substitution instantiates that goal and recursive normalization may cross exact
or generic implementation families. A separate 16-frame visited stack reports
exact projection cycles and acyclic overflow distinctly; invalid template
parameters fail during admission. Windows gnullvm and native Arch Linux WSL each
pass 476 library tests, one component-interface probe, 10 conformance tests, and
335 replacement tests: 822 compiler tests per host. Projection-bearing type
arguments and premises, inference projections, coinduction, specialization,
source syntax, and mixed inference selection remain unsupported.

The rigid generic-selection and proof milestone retains generic substitutions as
concrete-or-placeholder terms. Rigid selection preserves exact placeholder
identity and universe, rejects repeated-parameter mismatches, and recursively
proves instantiated generic or rigid-clause premises through the existing
16-frame stack. Missing premises, ambiguity, cycles, and overflow remain
distinct; inference-bearing inputs fail explicitly. Windows gnullvm and native
Arch Linux WSL each pass 480 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 826 compiler tests per host. Mixed
inference/skolem unification, binder introduction, coinduction, specialization,
source higher-ranked syntax, and mixed inference selection remain unsupported.

The universal trait-goal milestone adds an explicit binder over at most eight
implemented-trait parameters. Solving advances a caller-relative universe,
creates a distinct rigid placeholder for each parameter, and proves the
instantiated goal through rigid generic solving. Invalid indices and universe
exhaustion fail explicitly; unconstrained implementation parameters remain
ambiguous. Windows gnullvm and native Arch Linux WSL each pass 483 library tests,
one component-interface probe, 10 conformance tests, and 335 replacement tests:
829 compiler tests per host. Nested binders, leak-aware answer inversion, mixed
generic inference, `for<...>` source syntax, and mixed inference selection remain
unsupported.

The exact existential trait-goal milestone binds at most eight parameters as
inference variables in a caller-selected universe. Canonical exact selection
restores a unique answer as substitutions keyed to the original identities;
repeated parameters enforce equality, and ambiguity/no solution remain explicit.
Invalid binder indices fail at construction. Windows gnullvm and native Arch
Linux WSL each pass 486 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 832 compiler tests per host.
Generic inference candidates, inferred premise proof, projection composition,
universal answer inversion, source existential syntax, and mixed inference
selection remain unsupported.

The symbolic generic-existential milestone matches canonical inference-bearing
queries against coherent flat generic heads with a fixed 16-node constraint
graph. Concrete constraints produce concrete bindings; unresolved equality
classes map to their oldest universe-safe query representative, and selected
premises retain those symbolic terms. Head-unconstrained implementation
parameters remain ambiguous; rigid inputs fail explicitly. Windows gnullvm and
native Arch Linux WSL each pass 489 library tests, one component-interface probe,
10 conformance tests, and 335 replacement tests: 835 compiler tests per host.
Recursive inferred-premise proof, nested/projection unification, cross-family
answer composition, source existential syntax, and general mixed inference
selection remain unsupported.

The recursive inferred-proof milestone keeps one fixed union/concrete state for
the root existential variables. Each exact or generic implementation answer
refines that state before generic premises recurse through the existing 16-frame
stack. Exact premises can resolve symbolic variables, generic chains propagate
the result, contradictory premises return no solution, and cross-family
ambiguity, cycles, and overflow remain distinct. Unrelated premise variables
fail explicitly. Windows gnullvm and native Arch Linux WSL each pass 493 library
tests, one component-interface probe, 10 conformance tests, and 335 replacement
tests: 839 compiler tests per host. Inference-aware where clauses, projection
constraints, backtracking, caching, coinduction, source syntax, and general
mixed inference selection remain unsupported.

The inferred where-clause milestone applies the existing flat symbolic matcher
to the bounded clause database and returns stable clause identity, instantiated
premises, and a universe-checked substitution. Recursive inferred proof consults
a clause only after exact and generic candidates return no solution and composes
clause/generic/exact chains in the same root constraint state. Multiple clauses,
cycles, and acyclic overflow remain distinct. Windows gnullvm and native Arch
Linux WSL each pass 498 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 844 compiler tests per host.
Environment layering, implied bounds, negative reasoning, projection predicates,
backtracking, caching, coinduction, source syntax, and general mixed inference
selection remain unsupported.

The inferred projection-equality milestone binds a projection and expected type
over the existing bounded existential universe. Exact or generic trait proof
refines the root constraint state before the selected associated value is
instantiated and unified with the expectation. Generic parameter values remain
symbolic when appropriate, while nested projection templates reuse the fixed
16-frame cycle and overflow guard. Windows gnullvm and native Arch Linux WSL
each pass 503 library tests, one component-interface probe, 10 conformance
tests, and 335 replacement tests: 849 compiler tests per host. Projection-
bearing type terms and premises, predicate conjunction composition,
backtracking, caching, coinduction, source syntax, and general normalization
remain unsupported.

The mixed inferred-predicate milestone groups up to eight implemented-trait and
projection-equality predicates beneath one bounded existential binder. Every
predicate shares the same fixed root constraint state. Ambiguous attempts are
rolled back and retried after another predicate refines that state; a full pass
without progress remains ambiguous instead of selecting speculatively. Empty
conjunctions, cross-predicate contradictions, projection cycles, and capacity
limits fail or resolve explicitly. Windows gnullvm and native Arch Linux WSL
each pass 507 library tests, one component-interface probe, 10 conformance
tests, and 335 replacement tests: 853 compiler tests per host. Projection
equalities in where-clause premises, general projection-bearing type terms,
backtracking, caching, coinduction, source syntax, and general normalization
remain unsupported.

The projection-premise representation milestone lets a bounded where clause or
generic implementation retain projection equalities beside implemented-trait
premises under one combined eight-entry limit. Instantiation substitutes the
same concrete, rigid, or inference terms into the projection goal and expected
term. Legacy proof APIs do not possess associated-value environments and return
no solution when such a premise is selected. Windows gnullvm and native Arch
Linux WSL each pass 509 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 855 compiler tests per host.
Projection-aware recursive premise proof, general projection-bearing type
terms, backtracking, caching, coinduction, source syntax, and general
normalization remain unsupported.

The projection-aware inferred-proof milestone schedules instantiated trait and
projection-equality premises under one shared root constraint state. Ambiguous
premises roll back tentative constraints and retry after another premise proves.
Projection normalization may recursively prove projection-bearing generic
implementations through the same associated-value environment; a separate
16-transition nesting budget bounds that projection-to-proof recursion. Direct
refinement, contradiction, deferred mixed premises, generic premises, nested
proof, and adversarial overflow have focused tests. Windows gnullvm and native
Arch Linux WSL each pass 513 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 859 compiler tests per host.
Concrete/rigid projection-premise proof, general projection-bearing type terms,
backtracking, caching, coinduction, source syntax, and general normalization
remain unsupported.

The concrete projection-premise entry point validates a fully concrete goal and
reuses the bounded projection-aware inference engine with zero inference
binders. It checks clause and generic-implementation associated-value premises
under the existing fixed proof, projection, and predicate limits. Matching
values prove and mismatches remain no solution; environment-free concrete proof
continues to fail closed. Windows gnullvm and native Arch Linux WSL each pass 531
library tests, one component probe, 10 conformance tests, and 335 replacement
tests: 877 compiler tests per host. Rigid projection-premise proof,
backtracking, caching, coinduction, and source syntax remain unsupported.

The rigid concrete-projection entry point threads the associated-value
environment through rigid generic and clause recursion. It proves fully
concrete projection predicates beneath a skolemized outer goal while preserving
the existing fixed proof/projection limits. Mismatches remain no solution;
environment-free proof and projection predicates containing placeholders fail
closed. Windows gnullvm and native Arch Linux WSL each pass 532 library tests,
one component probe, 10 conformance tests, and 335 replacement tests: 878
compiler tests per host. Symbolic rigid projection normalization remains
unsupported.

The symbolic rigid-projection milestone selects premise-free generic associated
values for rigid goals, preserves placeholder identities in parameter-valued
results, and follows nested associated projections through the fixed 16-frame
visited stack. Placeholder identity and symbolic self-cycle tests are explicit.
Associated values whose selected implementations carry trait or projection
premises remain fail closed. Windows gnullvm and native Arch Linux WSL each pass
534 library tests, one component probe, 10 conformance tests, and 335 replacement
tests: 880 compiler tests per host.

The premise-bearing rigid-normalization milestone proves the selected generic
implementation's instantiated trait and projection premises before returning an
associated value. The caller's fixed 16-frame rigid proof stack is threaded
through normalization while nested projections retain their separate fixed
visited stack. Satisfied/missing prerequisites, recursive cycles, and proof-
depth overflow have focused tests. Windows gnullvm and native Arch Linux WSL each
pass 537 library tests, one component probe, 10 conformance tests, and 335
replacement tests: 883 compiler tests per host.

The universal projection-term binder mirrors the fixed existential bound-term
arena but maps each parameter to a fresh placeholder in the successor universe.
Rigid term normalization retains placeholder identity through associated
projections and then invokes the bounded rigid solver. A parameter-valued
projection and universe overflow have focused tests. Windows gnullvm and native
Arch Linux WSL each pass 538 library tests, one component probe, 10 conformance
tests, and 335 replacement tests: 884 compiler tests per host. Nested/mixed
higher-ranked term binders and source syntax remain unsupported.

The universal projection-equality binder maps its projection and expected term
to fresh placeholders in the successor universe, then uses premise-aware rigid
normalization and exact symbolic comparison. Universe overflow remains explicit.
Windows gnullvm and native Arch Linux WSL each pass 539 library tests, one
component probe, 10 conformance tests, and 335 replacement tests: 885 compiler
tests per host. Nested/mixed higher-ranked predicates and source syntax remain
unsupported.

The mixed universal-predicate binder stores up to eight implemented-trait or
projection-equality predicates under one fresh placeholder universe. Each is
checked by the premise-aware rigid environment without inference refinement.
Mixed success, contradiction, empty conjunction, capacity, recursive cycle, and
universe-overflow tests are explicit. Windows gnullvm and native Arch Linux WSL
each pass 540 library tests, one component probe, 10 conformance tests, and 335
replacement tests: 886 compiler tests per host. Nested higher-ranked binders and
source syntax remain unsupported.

The nested universal-prefix representation stores a fixed sequence of binder
levels before one terminal mixed predicate conjunction. Every level advances the
universe and restarts its local placeholder IDs; globally indexed parameters
retain exact scope. Level count and total parameters are fixed-capacity, and a
binder cannot be appended after predicates. Distinct-universe identity, mismatch,
valid proof, scope/universe overflow, closed-prefix admission, and recursive-cycle
tests are explicit. Windows gnullvm and native Arch Linux WSL each pass 541
library tests, one component probe, 10 conformance tests, and 335 replacement
tests: 887 compiler tests per host. Branching scopes, term-nested binders, and
source syntax remain unsupported.

The universal branch forest combines up to eight independent nested prefixes
and assigns each a consecutive, non-overlapping universe segment. Global caps of
eight predicates and 16 binder levels prevent branch amplification. Mixed branch
success, missing later obligations, later-segment universe overflow, every
capacity boundary, and recursive cycles have focused tests. Windows gnullvm and
native Arch Linux WSL each pass 542 library tests, one component probe, 10
conformance tests, and 335 replacement tests: 888 compiler tests per host.
Predicate-nested binders and source syntax remain unsupported.

The rigid coinduction path uses an explicit fixed classification of at most 64
coinductive trait identities. A repeated proof path is accepted only when every
goal in the cycle is classified; ordinary and mixed cycles remain `Cycle`.
Duplicate and capacity admission fail explicitly. Windows gnullvm and native
Arch Linux WSL each pass 543 library tests, one component probe, 10 conformance
tests, and 335 replacement tests: 889 compiler tests per host. Projection-
premise, inference, and source-level coinduction remain unsupported at this
milestone.

The coinductive projection-premise entry point threads the same explicit trait
classification through rigid proof with associated values. Projection equality
is normalized and checked before a classified trait cycle can succeed; missing
values remain `NoSolution`, unclassified paths remain `Cycle`, and projection-
normalization cycles are not coinductive. Windows gnullvm and native Arch Linux
WSL each pass 544 library tests, one component probe, 10 conformance tests, and
335 replacement tests: 890 compiler tests per host. Inference and source-level
coinduction remain unsupported.

The universal coinduction entry point applies explicit trait classification to
implemented predicates inside nested branch forests. Disjoint universe segments
and rigid projection equality remain unchanged; only a repeated fully classified
trait cycle succeeds. The mixed regression covers an ordinary predicate, a
projection equality, and a later coinductive cycle. Windows gnullvm and native
Arch Linux WSL each pass 544 library tests, one component probe, 10 conformance
tests, and 335 replacement tests: 890 compiler tests per host. Inference and
source integration remain unsupported.

The resolved-inference coinduction entry point reapplies the current
substitution across the repeated proof path. Every cycle goal must be inference-
free and explicitly classified. A preceding exact sibling can resolve the query
variable and the successful cycle preserves that concrete substitution; an
unresolved classified self-cycle remains `Cycle`. Windows gnullvm and native
Arch Linux WSL each pass 545 library tests, one component probe, 10 conformance
tests, and 335 replacement tests: 891 compiler tests per host. Backtracking over
unresolved coinductive answers and source integration remain unsupported.

The projection-resolved coinduction entry point defers an unresolved classified
implemented-trait cycle within the fixed predicate scheduler while another
predicate may refine the state. A rigid projection equality can bind the query
variable before retry; missing values remain `NoSolution`, and no progress
remains `Cycle`. Windows gnullvm and native Arch Linux WSL each pass 546 library
tests, one component probe, 10 conformance tests, and 335 replacement tests: 892
compiler tests per host. General candidate backtracking and source integration
remain unsupported.

The source marker-trait milestone admits allocation-free `trait Name {}` and
`pub trait Name {}` items through the canonical module parser. The existing
module item bound limits syntax admission; a separate 64-entry table assigns
source-order `TraitId` identities for solver-facing lookup. Duplicate trait
names and declaration-table overflow fail explicitly, and traits participate in
the existing cross-kind duplicate-definition check. Comments are allowed in an
otherwise empty marker body. Generic parameters, supertraits, associated items,
methods, `impl` items, and trait use in types remain unsupported and fail closed.
Windows gnullvm and native Arch Linux WSL each pass 551 library tests, one
component probe, 10 conformance tests, and 335 replacement tests: 897 compiler
tests per host.

The exact source-implementation milestone admits allocation-free
`impl Trait for Type {}` items with empty bodies. Lowering resolves the trait
through the declaration table, interns up to 64 source-order nominal path type
identities, and inserts identified headers into the existing exact
implementation database. Thus existing exact selection and overlap rejection
operate on source-derived facts. Unknown traits, duplicate heads, non-path self
types, nonempty bodies, and type capacity overflow fail explicitly. Generic,
negative, unsafe, and default implementations, trait arguments, associated
items, and use-site trait obligations remain unsupported. Windows gnullvm and
native Arch Linux WSL each pass 555 library tests, one component probe, 10
conformance tests, and 335 replacement tests: 901 compiler tests per host.

The concrete source-obligation milestone retains up to eight
`where Type: Trait` predicates on each function signature, including after an
explicit return type. The module source environment interns their nominal type
paths with implementation self types, resolves declared trait identities, and
proves every function predicate through the exact implementation database
before the production pipeline enters code generation. Unsatisfied or unknown
traits, duplicate predicates, unsupported compound/generic bounds, unsupported
self types, and capacity overflow fail explicitly with source spans. Generic
parameters, inferred obligations from operations, trait arguments, associated
items, and method dispatch remain unsupported. Windows gnullvm and native Arch
Linux WSL each pass 560 library tests, one component probe, 10 conformance
tests, and 335 replacement tests: 906 compiler tests per host.

The bounded source-supertrait milestone admits up to eight `+`-separated
supertraits on each marker declaration. A two-pass declaration admission resolves
forward names into stable trait IDs, rejects missing or duplicate edges, and
performs a fixed 64-node acyclicity check. Exact implementation admission then
checks every direct and transitive supertrait against the complete source exact-
implementation database, independent of item order, before obligations or code
generation run. Missing ancestors fail with the implementation source span.
Generic supertraits, associated items, `?Sized`, higher-ranked bounds, and
generic implementations remain unsupported. Windows gnullvm and native Arch
Linux WSL each pass 564 library tests, one component probe, 10 conformance
tests, and 335 replacement tests: 910 compiler tests per host.

The exact source-associated-type milestone admits up to eight `type Name;`
declarations in each trait and requires one exact `type Name = Type;` value in
every implementation of that trait. Declaration identities are stable in source
order and lower into the existing bounded associated-value database, so the
existing exact projection normalizer can recover the declared value. Missing,
unknown, duplicate, and capacity-exhausted declarations or values fail closed.
Associated-type defaults, bounds, generics, methods, and source projection syntax
remain unsupported. Windows gnullvm and native Arch Linux WSL each pass 569
library tests, one component probe, 10 conformance tests, and 335 replacement
tests: 915 compiler tests per host.

The concrete source-projection milestone admits bounded function predicates of
the form `where <Type as Trait>::Item = Expected`. The canonical parser retains
each component and its source span; source admission resolves the exact trait,
self type, associated type, and expected type identities, then uses the existing
exact projection database before code generation. Unknown identities, missing or
ambiguous implementations, mismatched values, duplicate predicates, and capacity
exhaustion fail closed. Generic projections, projection types in signatures or
bodies, and associated constraints on generic binders remain unsupported.
Windows gnullvm and native Arch Linux WSL each pass 572 library tests, one
component probe, 10 conformance tests, and 335 replacement tests: 918 compiler
tests per host.

The concrete source-trait-argument milestone admits up to eight positional type
parameters on trait declarations and the same bounded number of concrete type
arguments on exact implementations, implemented-trait predicates, and concrete
projection equalities. Exact header selection includes every argument, so
different concrete instantiations remain distinct and their associated values
normalize through the selected implementation. Duplicate parameter names,
wrong arity, unsupported argument types, overlap, unknown types, and capacity
exhaustion fail closed. Generic implementations, inferred arguments, defaults,
bounds, lifetimes, and const parameters remain unsupported. Windows gnullvm and
native Arch Linux WSL each pass 575 library tests, one component probe, 10
conformance tests, and 335 replacement tests: 921 compiler tests per host.

The flat generic source-implementation milestone admits up to eight implementation
type parameters when each parameter appears as a complete self or trait-argument
head position. Concrete source obligations use the existing exact-plus-generic
proof path, and parameter or concrete associated values use the existing generic
projection normalizer. Exact/generic and generic/generic overlap, duplicate or
unconstrained parameters, wrong arity, missing associated values, generic
supertraits, and unsupported compound parameter positions fail closed. Generic
where-premises, nested type constructors, bounds, inference in source
signatures, specialization, and methods remain unsupported. Windows gnullvm and
native Arch Linux WSL each pass 578 library tests, one component probe, 10
conformance tests, and 335 replacement tests: 924 compiler tests per host.

The generic source-premise milestone admits up to eight implemented-trait
predicates after a flat generic implementation head. Each premise may use the
implementation parameters or supported concrete nominal types in complete self
and trait-argument positions. Admission resolves trait identity and arity,
rejects duplicates, and stores the predicates on the existing bounded generic
clause; concrete proof and generic associated-value normalization recursively
discharge them through the existing 16-frame solver. Missing premises fail
closed before code generation. Projection-equality premises, exact-implementation
premises, nested parameter constructors, and bounds remain unsupported. Windows
gnullvm and native Arch Linux WSL each pass 581 library tests, one component
probe, 10 conformance tests, and 335 replacement tests: 927 compiler tests per
host.

The generic source projection-premise milestone admits concrete or parameter-
bearing equalities such as `where <T as Parent<T>>::Output = u8` after flat
generic implementation heads. Source lowering resolves the projected trait,
arguments, associated identity, and expected bound type, then stores the equality
on the existing generic clause. Concrete source obligations now use the existing
projection-aware proof environment, so selected implementations must satisfy
both implemented-trait and projection premises before code generation. Unknown,
duplicate, mismatched, cyclic, and over-depth premises fail closed. Nested
projection terms and compound generic type constructors remain unsupported.
Windows gnullvm and native Arch Linux WSL each pass 583 library tests, one
component probe, 10 conformance tests, and 335 replacement tests: 929 compiler
tests per host.

The premise-bearing exact source-implementation milestone lowers a concrete
implementation with one or more `where` predicates as a zero-parameter bounded
clause rather than an unconditional exact fact. It therefore reuses generic
clause coherence, recursive implemented/projection premise proof, and generic
associated-value normalization while preserving a fully concrete head. Missing
premises make the implementation unavailable, and an unconditional exact fact
with the same head is rejected as overlap. Conditional implementations of traits
with source supertraits remain unsupported. Windows gnullvm and native Arch
Linux WSL each pass 586 library tests, one component probe, 10 conformance tests,
and 335 replacement tests: 932 compiler tests per host.

The projection-valued generic associated-type milestone decomposes values such
as `type Output = <T as Parent<T>>::Output`, resolves the projected trait,
arguments, and associated identity, and stores the result in the existing
bounded generic projection representation. Concrete source obligations then
reuse recursive implementation proof and the 16-frame projection normalizer.
Missing projected implementations fail closed; malformed projections, unknown
identities, wrong arity, and unsupported compound positions are rejected.
Windows gnullvm and native
Arch Linux WSL each pass 589 library tests, one component probe, 10 conformance
tests, and 335 replacement tests: 935 compiler tests per host.

The exact projection-valued associated-type milestone lowers an unconditional
concrete implementation containing a projection value as a zero-parameter
bounded clause. This preserves existing exact/generic coherence while reusing
the same recursive implementation proof and projection normalization as the
generic source form. A missing projected implementation remains unavailable
before code generation. Windows gnullvm and native Arch Linux WSL each pass 590
library tests, one component probe, 10 conformance tests, and 335 replacement
tests: 936 compiler tests per host.

The inherited source-supertrait milestone lowers each direct marker supertrait
of a generic, conditional concrete, or projection-valued implementation as a
deduplicated bounded premise over the same self type. Selected child
implementations therefore remain unavailable unless every declared parent can
be proved; explicit equivalent premises do not consume authority or duplicate
solver work. Parameterized supertrait paths remain unsupported and fail on
arity rather than being guessed. Windows gnullvm and native Arch Linux WSL each
pass 592 library tests, one component probe, 10 conformance tests, and 335
replacement tests: 938 compiler tests per host.

The exact-child generic-parent milestone validates supertraits of unconditional
exact child facts through the same projection-aware exact-plus-generic proof
environment used by source obligations. A parent may therefore come from a
generic or conditional implementation, but every instantiated parent premise
must prove before the child fact is admitted; unavailable parents still fail
closed. Windows gnullvm and native Arch Linux WSL each pass 593 library tests,
one component probe, 10 conformance tests, and 335 replacement tests: 939
compiler tests per host.

The parameterized source-supertrait milestone admits paths such as
`trait Child<T>: Parent<T>` when every parent argument is a complete parameter
of the child declaration. Declaration admission resolves stable parent identity,
checks arity, records parameter indexes, and rejects concrete or compound
positions. Exact validation and generic/conditional inherited premises
instantiate those indexes from the implementation head, including transitive
parents. Windows gnullvm and native Arch Linux WSL each pass 596 library tests,
one component probe, 10 conformance tests, and 335 replacement tests: 942
compiler tests per host.

The concrete source-supertrait argument milestone distinguishes complete child
parameters from complete concrete nominal types in each parent path. Concrete
arguments intern in the bounded source type table and instantiate identically
through generic, exact, and transitive supertrait proof; a missing exact match
remains unavailable. The type-argument scanner also accounts for a nested
generic close adjacent to the enclosing close so compound terms reach semantic
admission and fail for the intended unsupported-position reason. Windows
gnullvm and native Arch Linux WSL each pass 597 library tests, one component
probe, 10 conformance tests, and 335 replacement tests: 943 compiler tests per
host.

The source-supertrait `Self` milestone gives `Self` an explicit argument
identity rather than interning it as an unrelated nominal type. Generic and
conditional inherited premises substitute the bound implementation self term;
exact and transitive validation substitute the concrete implementation self
identity. Missing matching parent implementations still fail before code
generation. Windows gnullvm and native Arch Linux WSL each pass 598 library
tests, one component probe, 10 conformance tests, and 335 replacement tests:
944 compiler tests per host.

The distinct source-supertrait instantiation milestone defines duplicate
identity over the parent trait plus its semantic bounded arguments rather than
the parent trait alone. A declaration may require `Parent<u8> + Parent<u16>`;
both exact or inherited goals remain separate and both must prove. Repeating
the same instantiated requirement still fails during declaration admission.
Windows gnullvm and native Arch Linux WSL each pass 599 library tests, one
component probe, 10 conformance tests, and 335 replacement tests: 945 compiler
tests per host.

The trait-declaration requirement milestone admits up to eight implemented-
trait predicates after a declaration's `where` keyword. Requirements may use
`Self`, a complete declaration parameter, or a concrete nominal type in each
flat self/argument position. Every implementation of the declared trait lowers
those requirements into its bounded clause premises, including unconditional
exact implementations, so a missing prerequisite makes the resulting trait
goal unavailable. Unknown traits, wrong arity, duplicate requirements, and
compound terms fail during declaration admission. Declaration projection-
equality requirements now resolve the associated identity and lower their flat
self, arguments, and expected type through the same implementation substitution
before using the existing projection-aware premise solver; unknown associated
types also fail during admission. Windows gnullvm and native Arch Linux WSL each
pass 604 library tests, one component probe, 10 conformance tests, and 335
replacement tests: 950 compiler tests per host.

The trait-parameter-bound milestone desugars implemented-trait bounds such as
`trait Child<T: Parent<T> + Visible>` into the same bounded declaration
requirements before semantic admission. Inline and explicit `where`
requirements share the eight-predicate capacity and semantic duplicate check;
their implementation proof and projection behavior therefore cannot diverge.
Defaults, lifetime/const parameters, `?Sized`, associated constraints, and
compound type terms remain unsupported. Windows gnullvm and native Arch Linux
WSL each pass 607 library tests, one component probe, 10 conformance tests, and
335 replacement tests: 953 compiler tests per host.

The implementation-parameter-bound milestone likewise desugars bounds such as
`impl<T: Parent<T> + Visible> Child<T> for T` into the implementation's existing
bounded premises. Inline bounds and an explicit implementation `where` clause
share the eight-entry capacity and semantic duplicate rejection, and selected
implementations recursively prove them through the existing projection-aware
environment. Defaults, lifetime/const parameters, `?Sized`, associated
constraints, and compound type terms remain unsupported. Windows gnullvm and
native Arch Linux WSL each pass 610 library tests, one component probe, 10
conformance tests, and 335 replacement tests: 956 compiler tests per host.

The associated-type-default milestone admits flat defaults such as
`type Output = Self`, a complete declaration parameter, or a concrete nominal
type. Missing implementation values substitute the default through the exact
or generic implementation head; explicit implementation values override it,
and projection obligations observe the resulting stable associated value.
Projection-valued defaults with flat `Self`/parameter/concrete projection
positions now resolve their trait and associated identities after the forward
identity phase and reuse generic projection normalization. Missing projected
implementations remain unavailable; compound defaults remain fail-closed.
Windows gnullvm and native Arch Linux WSL each pass 617 library tests, one
component probe, 10 conformance tests, and 335 replacement tests: 963 compiler
tests per host.

The forward associated-identity milestone separates declaration admission into
trait-identity, associated-identity, and relational-validation phases. A
projection requirement may therefore name an associated type declared later in
the module without becoming source-order dependent; unknown identities still
fail in the validation phase. Windows gnullvm and native Arch Linux WSL each
pass 615 library tests, one component probe, 10 conformance tests, and 335
replacement tests: 961 compiler tests per host.

The inline associated-binding milestone accepts bounds such as
`T: Iterator<Item = T>` or `T: Convert<u8, Output = T>` on trait and implementation type
parameters. It desugars each bound into one implemented-trait predicate plus
one projection-equality predicate per binding, sharing the existing eight-entry
capacity, identity admission, duplicate rejection, and projection-aware proof.
Positional arguments are preserved on both generated predicates, so mixed
lists retain one semantic trait instantiation. The same parser now handles
equivalent explicit declaration and implementation `where` predicates, so
inline and explicit bindings cannot diverge. Supertrait bindings lower their
positional arguments into the parent edge and their associated equalities into
`Self` declaration requirements, preserving both transitive ancestry and
projection proof. Windows gnullvm and native Arch Linux WSL each pass 627
library tests, one component probe, 10 conformance tests, and 335 replacement
tests: 973 compiler tests per host.

The trailing trait-default milestone admits defaults such as
`trait Convert<Input = u8, Output = Input>` and materializes omitted arguments consistently in
exact and generic implementation heads, supertraits, declaration and
implementation premises, projection values/defaults, and function obligations.
Only a trailing run of complete concrete nominal defaults, `Self`, or references
to an earlier trait type parameter is accepted; forward/self-referential type-
parameter, lifetime/const, and compound defaults fail closed. `Self` and
earlier-parameter defaults copy already materialized typed terms rather than
introducing inference.
Predicate duplicate admission compares materialized argument tuples, so
`Parent` and `Parent<u8, u8>` are the same requirement for
`trait Parent<T = u8, U = T>` and cannot bypass duplicate rejection through
different spelling.
Windows gnullvm and native Arch Linux WSL each pass 630 library tests, one
component probe, 10 conformance tests, and 335 replacement tests: 976 compiler
tests per host.

The restricted naked-function milestone admits repeated modern unsafe
attributes including `#[unsafe(naked)]` and directly emits a bounded x86-64
`naked_asm!` body without entering ordinary function lowering. The initial
instruction set includes `nop`, `ret`, `int3`, `ud2`, `cli`, `sti`, `hlt`,
`swapgs`, `iretq`, validated 64-bit GPR `push`/`pop` and register-indirect
`jmp`, register-to-register `mov`, checked signed `push` immediates whose
architectural sign extension preserves the requested `i32` value, and
full-width signed-or-unsigned `mov r64, imm64`. Base-register memory operands support 64-bit
`mov` loads/stores, memory-indirect `jmp`, and `lgdt`, `lidt`, and `invlpg`,
including required SIB and zero-displacement encodings for `rsp`/`r12` and
`rbp`/`r13`. The same typed address path accepts one optional index GPR at
scale 1/2/4/8 and an optional checked signed `i32` displacement, selecting
canonical disp8 or disp32 encodings, with at most eight string-literal instructions. A quote-aware
bounded template scanner preserves operand commas without accepting escapes. A naked function must be
unsafe, use the C ABI, have no parameters or where predicates, return unit or
never, and end in an explicit terminating instruction. Exact machine-code tests
prove that no prologue or epilogue bytes are inserted. A bounded two-pass layout
resolves numeric local definitions `2:` through `9:` and direction-checked
`jmp 2f`/`2b` references to checked rel32 displacements; duplicate, missing,
and wrong-direction labels fail closed. Trailing `options(raw)` and
`options(att_syntax)` markers are accepted alone or together in accordance with
the exact dated oracle. The separate AT&T grammar covers `%` registers, `$`
immediates, source-first moves, `disp(base,index,scale)` addresses, and indirect
`*` jumps for the supported instruction set; cross-syntax, unsupported,
repeated, or misplaced options fail closed. RIP-relative/base-less memory
operands and external symbols/relocations,
additional architectures, and general inline assembly remain fail-closed.
The object layer separately emits one typed checked x86-64 PC-relative external
relocation as ELF64 `.rela.text`/`R_X86_64_PLT32` with addend `-4` or COFF
`IMAGE_REL_AMD64_REL32`; exact structural tests cover undefined symbols, string
tables, relocation entries, and invalid patch ranges without changing existing
relocation-free output. One validated direct `jmp symbol` now returns code plus
a typed external-branch record; ordinary `MachineCode` compilation rejects it,
while the object pipeline immediately consumes it. Multiple externals and
invalid identifiers fail closed in Intel and AT&T modes. Windows gnullvm and
native Arch Linux WSL each pass 635 library tests,
one component probe, 10 conformance tests, and 335 replacement tests: 981
compiler tests per host.

The first ordinary inline-assembly increment admits only statement-position
`asm!("nop")` in unsafe x86-64 functions, optionally with unique `nomem`,
`nostack`, and `preserves_flags` options observed against ORACLE-0002. It emits
the no-op through ordinary function lowering and retains the existing prologue,
return, and epilogue. Safe use, operands, other templates, and invalid options
fail closed. Windows gnullvm and native Arch Linux WSL each pass 639 library
tests, one component-interface probe, 10 conformance tests, and 335 replacement
tests: 985 compiler tests per host. This is **PARTIAL** inline-assembly evidence,
not a clobber, register-allocation, memory-effect, control-flow, or general
assembly claim.

One exact explicit-input form is also admitted in unsafe x86-64 functions:
`asm!("cmp rax, rax", in("rax") value)` requires a typed `u64` expression,
evaluates it through ordinary lowering into RAX, includes its reads in the
ownership facts, and then emits the fixed compare encoding. Unique `nomem` and
`nostack` options are accepted; `preserves_flags`, wrong types, missing inputs,
other registers/templates, and safe use fail closed. The same Windows and Arch
suites pass 985 compiler tests per host. Outputs, inout operands, register
classes/allocation, clobbers, arbitrary effects, and general inline assembly
remain absent.

The next bounded output form is
`asm!("mov rax, 7", lateout("rax") value)` for a mutable `u64` local in an
unsafe x86-64 function. It resolves one exact destination identity, records the
write in ownership facts, emits the fixed immediate move, and stores RAX into
the checked local stack slot. The fixed move admits unique `nomem`, `nostack`,
and `preserves_flags` options. Immutable locals, parameters, unknown names,
wrong types, other registers/templates, and malformed operands fail closed.
Windows gnullvm and native Arch Linux WSL each pass 985 compiler tests. This is
**PARTIAL** output-operand evidence, not an inout, register-allocation, output-
projection, clobber, arbitrary-effect, or general assembly claim.

The bounded inout form is
`asm!("inc rax", inout("rax") value)` for a mutable `u64` local. It records one
read-modify-write ownership effect, loads the destination's checked stack slot,
emits the fixed 64-bit increment, and writes RAX back to the same slot. Unique
`nomem` and `nostack` options are accepted; `preserves_flags` is rejected.
Immutable locals, parameters, wrong types, other registers/templates, and
malformed operands fail closed. Both canonical hosts pass 985 compiler tests.
This remains **PARTIAL** inout evidence; register classes/allocation, distinct
input/output expressions, projections, clobbers, arbitrary effects, and general
assembly remain absent.

Distinct inout places are admitted as
`asm!("inc rax", inout("rax") input => output)`: the input may be any supported
typed `u64` expression and the output must be a mutable `u64` local. The
ownership model records the expression reads followed by a separate output
write; emission evaluates the input once, increments RAX, and stores only to
the checked output slot. Empty/repeated arrows, wrong types, immutable or
parameter outputs, unsupported registers, and invalid options fail closed.
Windows gnullvm and native Arch Linux WSL each pass 985 compiler tests. This is
**PARTIAL** distinct-inout evidence, not register allocation, output projection,
general clobber/effect, or general assembly support.

One named register-class operand is supported in the oracle-observed form
`asm!("inc {value}", value = inout(reg) ...)`. The bounded parser requires one
matching identifier placeholder/declaration, accepts the existing same-place or
distinct-place `u64` inout shapes, and deterministically selects RAX for the
sole class operand before reusing the checked ownership and writeback paths.
Positional, missing, mismatched, or repeated placeholders, other classes,
additional operands, and invalid options fail closed. Windows gnullvm and
native Arch Linux WSL each pass 985 compiler tests. This is **PARTIAL** single-
operand class-allocation evidence, not multi-operand allocation, other-class,
projection, clobber/effect, or general assembly support.

The output-bearing fixed forms accept the exact-oracle-observed effect sets
`pure+nomem`, `pure+readonly`, and standalone `readonly`. `pure` without an
output or without either memory declaration fails closed, as does combining
`nomem` with `readonly`; options remain unique and `preserves_flags` remains
template-specific. Windows gnullvm and native Arch Linux WSL each pass 985
compiler tests. This validates declarations for the fixed templates only and
does not claim actual assembly memory accesses, optimizer integration, general
clobbers/effects, or general assembly.

The exact named `add {left}, {right}` template admits a mutable `u64
inout(reg)` left local and a typed `u64 in(reg)` right expression. The bounded
allocator assigns RAX and RCX without aliasing, preserves the first live value
across lowering the second expression, emits the fixed add, and writes back
only to the left stack slot. Ownership facts retain right-expression reads and
the left read-modify-write effect. Invalid names, types, mutability, surplus
operands, classes, templates, and effects fail closed. Both canonical hosts pass
985 compiler tests. This is **PARTIAL** two-operand allocation evidence.

The exact `asm!("nop", clobber_abi("C"))` form has a distinct typed clobber
case. Statement boundaries keep language values in checked stack storage, so no
register-resident value silently survives the declared C clobber. Unknown ABI
names, generic outputs with a clobber ABI, extra declarations, and non-no-op
clobber templates fail closed. Both canonical hosts pass 985 compiler tests.
Other ABI sets, explicit clobber outputs, and general clobber integration remain
absent.

Explicit RAX `lateout`, same-place `inout`, and a distinct `inout` output also
accept one numeric field of a mutable tuple local when the selected element is
exactly `u64`. Their ownership facts retain the tuple local identity and a
`TupleField` projection, and load or writeback uses bounded, checked stack-slot
selection. A distinct input remains a typed expression evaluated once before
increment and projected writeback. Immutable tuples, missing or out-of-range
fields, and non-`u64` elements fail closed. Windows gnullvm and native Arch Linux
WSL each pass 639 library tests, one component-interface probe, 10 conformance
tests, and 335 replacement tests: 985 compiler tests per host. Nested, indexed,
or dereferenced places remain unsupported.

The same three explicit RAX output forms also accept one compile-time numeric
element of a mutable `[u64; N]`. The resolver validates exact `u64` element type,
mutability, and bounds, records the base array plus `ArrayElement` ownership
projection, and selects the load/writeback stack slot with checked arithmetic.
The pinned oracle accepted original `lateout`, same-place `inout`, and split
`inout` probes using `values[1]`. Both canonical hosts continue to pass 985
compiler tests. Dynamic indexes, nested aggregates, dereference outputs, and
general place lowering remain unsupported.

Static inline outputs now use one typed place record for scalar locals, tuple
fields, and constant array elements. It carries the resolved local, bounded
projection sequence, and checked stack offset through shared preanalysis and
emission boundaries, including exact assignment-fact ordering. The consolidation
removed 561 duplicated lines without broadening accepted syntax. Windows and
native Arch Linux WSL each pass the unchanged 985-test compiler suite. Dynamic
indexes and dereference outputs remain fail-closed.

The typed place now distinguishes direct stack storage from an indirect pointer
slot. Exact `*name` outputs accept a local or parameter with base type `&mut
u64` or `*mut u64`, retain its base identity plus `Dereference` ownership
projection, and perform indirect load/writeback for explicit RAX `lateout`,
same-place `inout`, and split `inout`. Shared/immutable references, const raw
pointers, other pointee types, malformed names, and unknown bases fail closed.
The pinned oracle accepted all three original mutable-reference probes; Windows
and native Arch Linux WSL each pass 985 compiler tests. Dynamic indexes, nested
projections, and general memory-effect assembly remain unsupported.

Dynamic inline output indexing accepts a supported `usize` expression in
`values[expression]` for a mutable `[u64; N]` local. The typed place carries an
`Index` projection and dynamic-array storage; preanalysis records the expression
reads, while emission evaluates it once, traps unless it is below `N`, preserves
it across the fixed operation, and reuses the existing bounded element selector.
Explicit RAX `lateout`, same-place `inout`, and split `inout` are covered. The
pinned oracle accepted all three probes, and both canonical hosts pass 985
compiler tests. Mutable fixed-array reference parameters and locals now reuse
the same path with ordered `Dereference` and `Index` ownership projections and
the existing checked reference-array address helpers; shared references and
non-`u64` elements fail closed. Index expressions outside the existing bounded
expression subset, deeper nested projections, and general assembly remain
unsupported.

Mutable `&mut [u64]` parameters and locals are also valid indexed output bases.
Their resolved storage retains separate pointer and runtime-length slots. The
index is evaluated once, compared unsigned against the stored length, preserved
across the fixed RAX operation, and used by the existing scaled reference load/
store path. Slice ownership uses the established direct `Index` projection;
shared slices and non-`u64` elements fail closed. The pinned oracle accepted all
three forms and both canonical hosts pass 985 compiler tests. Deeper places and
general assembly remain unsupported.

The fixed explicit-output node now carries its register identity. Exact
`asm!("mov rcx, 7", lateout("rcx") place)` reuses every typed RAX destination;
after the declared RCX write, the value enters the common writeback channel.
`lateout("rcx") _` omits that transfer and place effect. The exact dated oracle
accepted both forms, and both canonical hosts pass 985 compiler tests. Other
explicit registers and general allocation remain unsupported.

The fixed explicit-inout node now carries the same RAX-or-RCX identity. Exact
`asm!("inc rcx", inout("rcx") ...)` accepts both same-place and split `u64`
forms and reuses every typed destination, ownership effect, bounds check, and
writeback path. Input lowering transfers the value to RCX before the declared
increment and returns it to the common writeback channel afterward. The exact
dated oracle accepted both original Rust 2024 forms, and both canonical hosts
pass 985 compiler tests. Other explicit registers, generic allocation, and
general assembly remain unsupported.

The fixed explicit-input node likewise carries RAX-or-RCX identity. Exact
`asm!("cmp rcx, rcx", in("rcx") value)` accepts the existing checked `u64`
expression subset, transfers the result to RCX, and emits the declared compare.
The exact dated oracle accepted the original Rust 2024 form, and both canonical
hosts pass 985 compiler tests. Other explicit registers and general assembly
remain unsupported.

The typed fixed-register node now also carries RDX identity across the exact
input, output, and inout families: `cmp rdx, rdx` with `in("rdx")`,
`mov rdx, 7` with stored or discarded `lateout("rdx")`, and `inc rdx` with
same-place or split `inout("rdx")`. RDX values use the common RAX expression and
writeback channel only outside the declared instruction, so all existing typed
places, ownership effects, bounds checks, and single-evaluation guarantees are
reused. The exact dated oracle accepted all five independently authored Rust
2024 forms, and both canonical hosts pass 985 compiler tests. Other explicit
registers, generic allocation, and general assembly remain unsupported.

The fixed explicit-GPR parser and encoder now admit the oracle-supported set
RAX, RCX, RDX, RSI, RDI, and R8 through R15 for the same exact `cmp reg, reg`
input, `mov reg, 7` output, and `inc reg` inout families. One bounded register
code computes conventional REX/ModRM bytes for low and extended registers while
all typed expression, place, ownership, bounds, discard, and writeback behavior
remains shared. RBX, RSP, and RBP are rejected as the pinned oracle rejects them.
Original low/extended-register probes and stored, discarded, same-place, and
split R15 probes passed; both canonical hosts pass 985 compiler tests. General
templates, register classes/allocation, and general assembly remain unsupported.

Exact `asm!("mov rax, 7", lateout("rax") _)` is a discarded explicit output.
Preanalysis records no language-place access, while emission still performs the
declared RAX write. The exact dated oracle accepted the original Rust 2024 form,
and both canonical hosts pass 985 compiler tests. Other explicit clobbers and
general assembly remain unsupported.

The projection-bearing term milestone uses a fixed 64-node arena for flat leaf
terms and associated-type projections whose trait self/argument positions refer
only to earlier nodes. Identical nodes intern to one stable identity; invalid
forward references and capacity overflow fail explicitly. A separate 16-frame
walk normalizes nested terms through the projection-aware environment and
returns the resulting flat type plus inference substitution. Nested argument
projection, inference refinement, invalid references, arena bounds, and depth
overflow have focused tests. Windows gnullvm and native Arch Linux WSL each pass
518 library tests, one component-interface probe, 10 conformance tests, and 335
replacement tests: 864 compiler tests per host. Whole term-bearing goal
selection, projection terms in binders, concrete/rigid projection-premise proof,
backtracking, caching, coinduction, source syntax, and general normalization
remain unsupported.

The projection-bearing goal milestone normalizes each self and argument term in
one shared inference state before sending the resulting flat implemented-trait
goal through exact, generic, or clause selection and projection-aware premise
proof. A projection nested in an argument can therefore refine a root inference
variable and determine the selected implementation. Windows gnullvm and native
Arch Linux WSL each pass 519 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 865 compiler tests per host.
Projection terms in binders, clause heads, and premise type positions,
concrete/rigid projection-premise proof, backtracking, caching, coinduction,
source syntax, and general normalization remain unsupported.

The existential projection-term binder milestone adds a parallel fixed bound-
term arena whose leaves contain concrete types or indexed generic parameters.
Admission validates every parameter and backward reference; instantiation maps
parameters to distinct universe-aware inference variables and remaps interned
term identities before invoking projection-bearing goal proof. Windows gnullvm
and native Arch Linux WSL each pass 520 library tests, one component-interface
probe, 10 conformance tests, and 335 replacement tests: 866 compiler tests per
host. Higher-ranked term binders, projection terms in clause heads and premise
type positions, concrete/rigid projection-premise proof, backtracking, caching,
coinduction, source syntax, and general normalization remain unsupported.

The projection-bearing logical clause-head milestone keeps up to 64 identified
bound heads in a separate fixed database. Direct leaf positions must constrain
every parameter before the complete instantiated head is normalized through
the projection-aware environment and unified with the existential query. A
parameter occurring only beneath a projection fails closed as ambiguous.
Windows gnullvm and native Arch Linux WSL each pass 522 library tests, one
component-interface probe, 10 conformance tests, and 335 replacement tests: 868
compiler tests per host. A head may carry up to eight flat implemented-trait
premises; the selected substitution instantiates them and the existing depth-
and cycle-bounded projection-aware proof must discharge them. The opt-in
recursive solver threads the database, copied candidate constraint states, and
shared proof stack through nested premises. Windows gnullvm and native Arch
Linux WSL each pass 525 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 871 compiler tests per host.
Nested success, ambiguity, cycle, and depth overflow have focused tests. A
separate 64-entry projection-bearing generic-implementation admission table
proves disjointness only from trait/arity mismatch or an unequal direct
concrete leaf; unresolved parameter or projection relationships fail closed as
overlap, including against exact and flat-generic heads. Windows gnullvm and
native Arch Linux WSL each pass 526 library tests, one component-interface
probe, 10 conformance tests, and 335 replacement tests: 872 compiler tests per
host. Existential selection copies the root constraint state, normalizes the
complete admitted head, proves flat premises, and returns the stable
implementation identity and inferred substitution. Windows gnullvm and native
Arch Linux WSL each pass 527 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 873 compiler tests per host. The
opt-in general proof entry point threads the admitted implementation table
through nested premises before logical-clause fallback, sharing copied
inference state and the 16-frame proof stack. Windows gnullvm and native Arch
Linux WSL each pass 528 library tests, one component-interface probe, 10
conformance tests, and 335 replacement tests: 874 compiler tests per host.
Nested proof, cycles, and depth overflow have focused tests. Projection-bearing
implemented-trait premises reuse the head's validated term arena, instantiate
from the selected substitution, normalize in the shared root state, and then
enter flat recursive proof. Both hosts pass the same 874 compiler tests. Flat
predicates are now proved first so their root-state constraints can make a
term-bearing predicate uniquely normalizable in the second phase. Windows
gnullvm and native Arch Linux WSL each pass 529 library tests, one component-
interface probe, 10 conformance tests, and 335 replacement tests: 875 compiler
tests per host. A mixed fixed-capacity scheduler now retries ambiguous flat and
term-bearing premises after any sibling proves, rolls back each ambiguous
attempt, and returns ambiguity when a pass makes no progress. Windows gnullvm
and native Arch Linux WSL each pass 530 library tests, one component-interface
probe, 10 conformance tests, and 335 replacement tests: 876 compiler tests per
host; focused tests cover refinement in both directions. Direct leaf positions now use the fixed equality unifier during
coherence admission, allowing repeated parameters and conflicting concrete
tuples to prove disjointness against peer, exact, and flat-generic heads while
projection positions remain opaque. Both hosts pass the same 875 compiler
tests. Complete projection-equation coherence, higher-ranked term
binders, backtracking, caching, coinduction, and source
syntax remain unsupported.

The nested conditional tuple-origin milestone walks each leaf's bounded
conditional-parent chain to the outermost generation before grouping reference
origins by field ordinal. The exact oracle rejects a three-leaf returned field
when one nested leaf references local storage and accepts the all-parameter
equivalent. Distinct top-level conditional groups and later reference fields
remain separate. Windows gnullvm and native Arch Linux WSL each pass the same
766 compiler tests. This is bounded conditional ancestry, not arbitrary
expression-origin partitioning, named lifetime inference, or complete Polonius
semantics.

The branch-reaching projected-return milestone validates the tuple field's
original generation and every assignment generation that can reach the exact
return. It separately reconstructs fresh shared/mutable borrow RHS origins and
reference-value copy/move RHS origins, while conditional expression generations
reuse their already enumerated all-branch facts. The oracle rejects a local-
backed branch, a sequential local-backed generation, and an old local-backed
initialization even after later replacement; all-parameter branch and sequential
controls are accepted. Windows gnullvm and native Arch Linux WSL each pass the
same 766 compiler tests. This remains bounded projected-field outlives analysis,
not general regions, named lifetime inference, or complete Polonius semantics.

The loop-carried projected-return milestone filters each candidate field write
through both sides of the ownership CFG: it must be reachable from function
entry and must reach the exact return. The oracle rejects a reachable local-
backed loop generation even when the loop may execute zero times or a later
same-iteration write restores the parameter; it accepts the parameter-backed
loop and a disconnected local-backed write after unconditional `break`. Windows
gnullvm and native Arch Linux WSL each pass the same 766 compiler tests. This is
bounded CFG reachability for exact projected generations, not general regions or
complete Polonius semantics.

The repeated projected-source loan milestone extends that bounded relation
across another directly initialized tuple whose selected reference field is
later moved and reborrowed. The pinned oracle rejects shared and mutable live-
child owner mutation with E0503 and accepts the equivalent post-last-use case.
MRML applies the same exact tuple-value count/order, reference-mutability,
one-step numeric-field, and no-intervening-replacement checks at the later hop;
failure to prove that origin remains conservative. The Windows native compiler
suite and native Arch Linux WSL suite each pass 420 library tests, one component-
interface probe, 10 conformance tests, and 335 original replacement tests; both
hosts also pass the two driver tests, for 768 compiler and driver tests per host.
The same traversal now selects a direct tuple-field reassignment generation
before its older initialization origin when that field is later moved. The
pinned oracle rejects shared and mutable live-child mutation of the reassigned
owner with E0503, preserves the original owner's independently retained borrow,
and accepts unrelated-owner and post-last-use controls. Both native core suites
remain green at the counts above after this extension.
Warnings-denied Clippy was not exercised by the current native frontend. This
does not claim nested projections, general aggregate provenance, named regions,
or complete Polonius semantics. The `no_std`/allocation/unsafe hygiene scan
remained empty.

The scoped unsafe ordinary-assembly milestone at `46ee91d8` preserves one
`unsafe { asm!(...); }` statement as an explicitly authorized bounded statement
rather than leaking authority to adjacent assembly. The typed terminal assembly
milestones add exact x86-64 `int3`, seven-register `int 0x80`, and the first-
party `cli`/`hlt` loop. Terminal forms omit fabricated returns; returning
syscalls evaluate seven `u64` inputs left-to-right, preserve every result before
writing mutable named-local outputs, and discard only explicit `_` outputs.
Unsupported scopes, registers, operand types/orders, output places, labels,
options, and nonterminal noreturn forms fail closed.

The pinned ORACLE-0002 toolchain accepted independently authored probes for all
four source families. ELF64 and COFF replacements cover native object admission;
the interrupt and privileged instructions were not executed. After commit
`9a312d4e`, Windows gnullvm and native Arch Linux WSL each pass 646 library
tests, one component-interface probe, 10 conformance tests, and 342 replacement
tests: 999 compiler tests per host. General unsafe statement blocks, arbitrary
assembly, general labels, unrestricted output places, runtime interrupt
behavior, and physical privileged-mode evidence remain unsupported.

The definite syscall-output initialization milestone at `21e1d328` adds an
explicit initialized property to parsed scalar locals. `let name: u64;` creates
the bounded local and move path but no initialization event. The existing
initializedness dataflow rejects a read until the returning syscall's named
output writes that path; immutable locals admit only their first write. The
pinned oracle accepts the assembly-initialized form and rejects a direct read
with E0381. Windows gnullvm and native Arch Linux WSL each pass 647 library
tests, one component-interface probe, 10 conformance tests, and 342 replacement
tests: 1,000 compiler tests per host. Other types, ordinary delayed assignment,
branches, loops, and general assembly-output places remain unsupported.

The bounded function-return outlives milestone at `962aedcc` passed all 764
compiler and driver tests on Windows gnullvm and all 764 in release mode on
native Arch Linux WSL, plus warnings-denied compiler-only Clippy on both hosts
using pinned rustc commit
`f7d782a3be46d6bb4b9792fe69a61db389ba1769`. Declared reference-return
functions now reject exact returned values whose active, event-decreasing
ancestry terminates in local storage. The pinned oracle rejected direct tail,
explicit, conditional, and conditionally reaching local generations with E0515,
while accepting direct parameters, explicit parameter reborrows, unconditional
latest-generation replacement, and a moved mutable parameter. Existing tests
also preserve cyclic reborrows and tuple-field initialization/reassignment
origins. Unsupported or ambiguous ancestry fails closed. This is the first
bounded escape/outlives slice, not named lifetime inference, general regions, or
complete Polonius semantics. The `no_std`/allocation/unsafe hygiene scan remained
empty.

The shared-reference return-copy milestone at `c5d007d9` passed all 764 compiler
and driver tests on Windows gnullvm and all 764 in release mode on native Arch
Linux WSL, plus warnings-denied compiler-only Clippy on both hosts using pinned
rustc commit `f7d782a3be46d6bb4b9792fe69a61db389ba1769`. The pinned
oracle accepted parameter-backed return ancestry through one and two ordinary
shared-reference copies and rejected the same copy chain rooted in local storage
with E0515. The outlives-private trace accepts only an exact immediately
preceding `Copy` or `Move` at the matching initialization expression; reference
mutability must match, and mutable references still require `Move`. Missing or
ambiguous ancestry remains fail-closed. This is bounded direct copy ancestry,
not general alias analysis, named lifetime inference, or complete Polonius
semantics. The `no_std`/allocation/unsafe hygiene scan remained empty.

The loop conditional-terminal outlives milestone at `f307c1b3` passed all 766
compiler and driver tests on Windows gnullvm and all 766 in release mode on
native Arch Linux WSL, plus warnings-denied compiler-only Clippy on both hosts
using pinned rustc commit
`f7d782a3be46d6bb4b9792fe69a61db389ba1769`. The pinned oracle rejected
an identity-call return backed by loop-local storage with E0515 and accepted the
equivalent parameter-backed return. The existing shape-validated
`LoopConditionalTerminal` location already maps to an exact CFG return edge;
primary and else-arm `Return` terminals now use return-context preanalysis.
Ordinary terminal actions and `break` are not promoted. This does not claim
nested-loop return coverage, general regions, named lifetime inference, or
complete Polonius semantics. The `no_std`/allocation/unsafe hygiene scan
remained empty.

The conditional delayed-initialization milestone at `d032d92c` treats first
writes in different arms of the same bounded conditional assignment as mutually
exclusive. The existing CFG initializedness intersection admits a post-join
read only when every reachable arm, including `else`, initializes the path.
Same-arm, preceding, and post-join repeated writes remain immutable-assignment
errors. The pinned ORACLE-0002 toolchain accepted the exhaustive two-arm probe
and rejected the missing-else form with E0381. ELF64 and COFF replacements
passed. Windows and native Arch Linux WSL each passed 647 library tests, 1
component probe, 10 conformance tests, and 344 replacement tests: 1,002 compiler
tests per host. This does not claim nested/general joins, loop-carried
initialization, other types, or complete Rust definite-assignment semantics.

The direct delayed-initialization milestone at `b02037df` permits an ordinary
direct `=` to perform the first write to an explicitly uninitialized `u64`
local. The bounded move-path write event is the semantic initialization;
storage allocation does not manufacture an initialization fact. An immutable
binding permits exactly one direct root write and rejects a repeated write,
while projected and compound first writes fail closed. The pinned ORACLE-0002
toolchain accepted the straight-line initialization and rejected the repeated
immutable assignment with E0384. ELF64 and COFF replacements passed. Windows
and native Arch Linux WSL each passed 647 library tests, 1 component probe, 10
conformance tests, and 343 replacement tests: 1,001 compiler tests per host.
This does not claim conditional joins, loop-carried initialization, other
uninitialized types, or complete Rust definite-assignment semantics.

The nested-loop return outlives milestone at `885ba7b7` passed all 767 compiler
and driver tests on Windows gnullvm and all 767 in release mode on native Arch
Linux WSL, plus warnings-denied compiler-only Clippy on both hosts using pinned
rustc commit `f7d782a3be46d6bb4b9792fe69a61db389ba1769`. The pinned
oracle rejected a conditional nested return of a loop-local identity-call
result with E0515 and accepted the parameter-backed equivalent. Independently
authored MRML cases cover unconditional and conditional nested returns in ELF64
and COFF output. Their existing shape-validated action and ordered-control
location maps to an exact CFG return edge, and only return controls carry a
`NestedLoopControlValue`. Conditions, `break`, `continue`, and ordinary nested
actions are not promoted. This remains bounded return escape analysis, not
general regions, named lifetime inference, or complete Polonius semantics. The
`no_std`/allocation/unsafe hygiene scan remained empty.
