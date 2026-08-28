# MRML linker

Status: **PARTIALLY IMPLEMENTED**.

Engineering Constitution record:

```text
Complexity impact: MEDIUM
TCB impact: NONE
New parser boundary: YES
New authority model: NO
New persistent state: NO
External dependency: NO
Failure isolated: YES
Existing-object reuse: HIGH
```

The linker adds adversarial object, archive, and executable-format parser
boundaries, but remains an isolated build tool with bounded allocation and no
runtime authority. It reuses the compiler's existing object contracts and the
public platform formats rather than adding a package or loading architecture.

The first MRML-owned linker increment is a dependency-free, bounded x86-64
static-link core in `packages/compiler/core/src/linker.rs`. It accepts already
decoded code and read-only-data fragments, resolves one defined symbol per
input plus up to 256 additional checked text-offset definitions, freezes a
deterministic 16-byte-aligned layout, copies disjoint ranges,
and applies checked signed 32-bit PC-relative relocations. Duplicate or missing
symbols, malformed names, invalid relocation fields, arithmetic overflow,
capacity exhaustion, and displacement overflow fail closed.

The core also decodes the exact bounded x86-64 COFF subset currently emitted by
`mrml-rustc`: one `.text`, an optional `.rdata`, short or string-table symbol
names, bounded external text definitions and undefined symbols, and
`IMAGE_REL_AMD64_REL32` relocations. Machine, section, symbol, string-table,
range, relocation-type, and truncation checks precede linking. This is compiler
object ingestion, not general COFF compatibility.

The extended COFF and ELF64 decoders retain multiple external/global text
definitions from one object with checked section-relative offsets. Relocations
to any definition in the originating text section use a separate typed local
target, so local and section symbols never enter the global namespace or
collide across objects. Archive selection considers every global definition;
entry lookup and cross-object relocations resolve to the definition's exact
text offset. The original single-definition decoder entry points remain as
fail-closed compatibility surfaces, while the driver uses the extended bounded
entry points. Weak definitions, COMDAT groups, symbol versions, and general
visibility/preemption semantics remain unsupported.

The bounded COFF decoder additionally accepts one nonempty long-name
`.text$...` code section, uses its actual section number for definitions and
internal relocations, and ignores only validated empty `.text`, `.data`, and
`.bss` placeholders plus conventional file/feature records. The archive driver
skips exactly `lib.rmeta` and `lib.rmeta-link` metadata members. In a controlled
Windows probe, exact `nightly-2026-08-24` gnullvm rustc with
`-C embed-bitcode=no` emitted a 2,452-byte no-std `.rlib` containing one such
COMDAT object. MRML linked its exact mangled entry to a 1,024-byte PE and Windows
returned 42. This establishes one simple hosted pinned-rustc `.rlib` shape only;
multiple COMDAT sections, COMDAT selection, writable/BSS data, unwind sections,
embedded bitcode sections, general metadata naming, and representative Rust
libraries remain unsupported.

The same format-neutral link core now decodes the exact bounded ELF64
relocatable subset emitted by `mrml-rustc`: x86-64 little-endian ET_REL,
`.text`, optional `.rodata`, `.rela.text`, `.symtab`, and their linked string
tables. It accepts the compiler's `R_X86_64_PC32` and `R_X86_64_PLT32` records,
retains explicit RELA addends, types local read-only targets separately, and
rejects unknown sections, machines, relocation types, malformed links,
truncation, and range or capacity violations. This is not general ELF input or
an ELF executable claim.

The linker serializes decoded inputs as a deterministic, fixed-address,
import-free x86-64 ELF ET_EXEC image. It emits a read-only header load, a
page-separated RX text load, and an optional page-separated R/NX read-only-data
load; section headers and dynamic metadata are absent. An Arch Linux WSL
controlled probe normalized an independently assembled syscall-only object to
the bounded five-section input subset, linked it through
`mrml-rustc-driver --link-elf`, and `readelf` observed entry `0x401000` plus
separate R and RX loads. Linux executed the 4,112-byte result and returned exit
code 42. This is hosted Arch WSL loader evidence, not the unavailable MRML Linux
test target, KVM, boot, or physical-hardware evidence.

Relocation targets are typed as either a named code symbol or a bounded offset
within the originating input's read-only data. COFF `.rdata` section-symbol
relocations therefore retain their exact local data identity without inventing
a public symbol or entering the global name-resolution path.

The linker can serialize those inputs as a deterministic, import-free x86-64
PE32+ executable. It links with page-separated code and data before applying
relocations, then emits a fixed-base image with zero timestamps, an RX `.text`,
an R/NX `.rdata`, bounded file/section alignment, and no data directories. A
Windows gnullvm-hosted test executes a generated six-byte entry function in a
child process and requires exit code 42. This is controlled hosted Windows
loader evidence, not Secure Boot, recovery, UEFI, or physical-hardware evidence.

`mrml-rustc-driver --emit pe` selects this path explicitly. The driver compiles
the requested function to MRML COFF in memory, decodes it, links it, and writes
the bounded PE image without spawning `rust-lld`. Existing `--emit coff` and
`--emit elf64` modes retain object-only behavior; an unknown emit kind fails
rather than falling back. A release-driver controlled probe compiled an
independent constant-return source through `--emit pe`, produced a 1,024-byte
single-section image, and the Windows host observed exit code 42. Empty
read-only data omits `.rdata` rather than emitting a loader-invalid zero-sized
section.

`mrml-rustc-driver --link-coff INPUT... --entry NAME -o OUTPUT` exposes the same
bounded path without compilation. It accepts one through 256 ordered inputs,
loads every bounded object before decoding, gives each input independent
relocation storage, and retains the input order through deterministic layout.
Object-data and relocation-storage lifetimes are distinct in the core API, so
the driver can safely retain all decoded inputs without self-references or raw
pointer assembly. A release-driver probe compiled two separately named objects,
linked both, produced a 1,024-byte PE, and Windows observed exit code 42. This
linker-only mode is the comparison surface for identical-input cold-process
measurements against the pinned gnullvm `rust-lld`; it does not accept arbitrary
COFF extensions outside the documented MRML subset.

The corresponding explicit Linux-family selections are
`--emit elf-executable` and `--link-elf INPUT... --entry NAME -o OUTPUT`. They use
ELF64 object emission/decoding and the MRML ELF serializer without silently
invoking a system linker.

The linker also has an allocation-free Unix archive container decoder bounded
to 256 object members. It validates the global magic, every fixed header,
decimal size arithmetic, member terminators, payload ranges, and even-byte
padding. Ordinary names, GNU `//` long-name tables and `/offset` references,
and BSD `#1/length` embedded names are decoded; conventional symbol-index
members are treated as metadata. The driver decodes candidate members in order
under the same total 256-input bound, always admits explicit objects, and admits
an archive member only when it defines the entry or a named relocation target
from an already selected input. A stable fixed point follows transitive archive
dependencies while the first selected definition suppresses later unused
duplicates. The result does not depend on trusting archive index metadata.
The driver assigns each archive a bounded identity and applies left-to-right
ordering: explicit objects are admitted when encountered, one archive rescans
only its own contiguous members to a fixed point, and it is not revisited for
undefined symbols introduced by later inputs. Index-accelerated extraction,
explicit start/end archive groups, thin archives, other non-object metadata
members, and general `.rlib` admission remain unimplemented, so this is not yet
the ordinary Rust static-library path. Thin
archive magic fails with an explicit unsupported-feature diagnostic rather
than being misclassified as a malformed ordinary archive; BSD extended-name
symbol indexes are skipped only after their embedded names are validated.

The ordered selector also has an explicit bounded object-member identity. A
selected nonzero `(archive, member)` pair admits all of that object's fragments
atomically, while explicit inputs must retain member identity zero. This is the
selection foundation required for gnullvm COFF objects whose `.text$...`,
`.xdata$...`, and `.pdata$...` sections must remain distinct; the current COFF
decoder still rejects that multi-section shape until fragment-relative symbols,
relocations, and PE exception metadata are represented end to end.

On 2026-08-28, the controlled Windows cold-process probe linked the same
93-byte MRML COFF object 50 times after five interleaved warmups. MRML produced
a 1,024-byte PE with a 10.196 ms median and 10.323 ms mean; pinned
`nightly-2026-08-24` gnullvm `rust-lld` produced a 1,024-byte PE with a
26.870 ms median and 27.184 ms mean. Both executables returned 42. This is a
2.64x median speedup for one tiny import-free object on this host. It is not a
large-program, archive, debug-info, parallel-scaling, or general superiority
claim. `docs/compiler/linker/benchmark-windows.ps1` preserves the identical-
input procedure.

After the input ceiling rose to 256, using the maximum multi-megabyte output
arrays for every link regressed this same single-object median to 15.232 ms.
The driver now selects one of three compile-time-bounded output tiers from the
validated selected text/read-only payload plus conservative alignment
headroom. Repeating the exact 50-iteration procedure after that change measured
MRML at 9.465 ms median and 9.550 ms mean versus rust-lld at 26.888 ms median
and 27.065 ms mean. Both outputs remained 1,024 bytes and returned 42. This is a
2.84x median result for the same narrow workload and demonstrates removal of
the measured zero-initialization regression; it is not a general superiority
claim.

The same controlled procedure also measured eight distinct 93-byte MRML COFF
objects (744 input bytes total), 50 times after five interleaved warmups. MRML's
median was 10.677 ms and mean was 10.813 ms; the pinned gnullvm `rust-lld`
median was 27.524 ms and mean was 27.594 ms. Both 1,024-byte executables returned
42. This is a 2.58x median speedup for a still-small, import-free eight-object
workload. It broadens the input-count evidence but remains neither a
large-program nor general linker-superiority claim.

After multi-definition decoding and payload-sized tiers, a further controlled
probe compiled 32 distinct functions into 32 separate 93-byte COFF objects
(2,976 input bytes total). Across 50 iterations after five interleaved warmups,
MRML measured 10.514 ms median and 10.769 ms mean; pinned gnullvm rust-lld
measured 28.747 ms median and 29.012 ms mean. Both 1,024-byte executables
returned 42. This is a 2.73x median result for a small 32-object, import-free
workload, not archive, large-program, debug-information, or general superiority
evidence.

The pass structure is informed by mold's public design notes: establish output
layout early, run a small sequence of understandable passes, and keep per-input
validation, copying, and per-relocation work independent so a hosted driver can
later use data-parallel loops. MRML does not copy mold source or claim mold
compatibility or performance. The cited design note warns that its 2020 object
preloading proposal is outdated, so MRML does not adopt that proposal.

This increment does **not** emit PE imports/exports/exception metadata/base
relocations/debug data, emit ELF dynamic metadata/interpreter/PIE/sections,
accelerate archive extraction through symbol indexes, read thin archives or
general `.rlib` contents, perform section GC or ICF, link dynamically, run work
in parallel, or integrate linker selection into the public `mrml` build
frontend.
Those are separate milestones and the current upstream linker remains the
production linker for ordinary package builds as required by
`docs/build/BUILD_SYSTEM.md`.

Research source:

- Rui Ueyama, [Design and implementation of mold](https://github.com/rui314/mold/blob/main/docs/design.md).
