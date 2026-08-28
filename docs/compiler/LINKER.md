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

The core now inventories up to 16 COFF sections and can decode a requested
nonempty `.text`/`.text$...` fragment by section order. Cross-fragment external
REL32 targets remain named symbols, while same-fragment targets remain checked
local offsets. The legacy one-input decoder explicitly rejects multiple text
fragments and any nonempty `.pdata$...` or `.xdata$...` section, preventing
metadata loss. A synthetic two-fragment object test resolves and links an entry
call to its sibling helper. The driver now expands each COFF object into its
bounded text-fragment count, allocates relocation and definition arenas to the
exact expanded count, and propagates the source `(archive, member)` identity to
every fragment before object-atomic selection. Objects with unwind sections
still reject before expansion, so ordinary unwind-bearing gnullvm objects are
not yet admitted.

The PE serializer now accepts up to 256 typed AMD64 runtime-function records.
It resolves checked begin/end symbols and offsets, rejects empty unwind data or
non-increasing ranges, places unwind bytes in the read-only NX section, sorts
12-byte function-table records by begin RVA, and publishes the exact `.pdata`
range through data-directory entry 3. The existing PE API delegates with an
empty record set and remains byte-compatible. COFF `ADDR32NB` decoding and
driver transport are still required before gnullvm unwind sections are admitted.

The COFF core now decodes bounded `.pdata$...` records into that typed form.
Each 12-byte record must have exactly three `IMAGE_REL_AMD64_ADDR32NB`
relocations at offsets 0, 4, and 8. Begin/end targets must resolve to one
zero-offset external definition in a bounded text section; the third target
must resolve at offset zero in a nonempty `.xdata$...` section. Section indices,
symbol records, addends, payloads, and record capacity are checked.

The PE driver now transports unwind records only from source objects whose
`(archive, member)` identity survived object-atomic selection. One reusable
bounded scratch arena decodes each selected object, copied typed records retain
only references to immutable object bytes, and payload-tier selection includes
unwind bytes plus aligned runtime-function entries. The exact pinned
`nightly-2026-08-24` gnullvm two-function no-std `.rlib` linked to a 1,536-byte
PE; Windows returned 42. Its exception directory identified one 12-byte record
covering RVA `0x1000..0x100f` with unwind data at RVA `0x2000`. This proves that
one exact unwind-bearing rlib shape works on the hosted Windows environment,
not general Rust library or exception-semantics coverage.

The COFF fragment decoder also accepts one nonempty `.rdata$...` COMDAT as the
input's typed read-only bytes. Existing same-object REL32 handling maps an
external definition at offset zero to `ReadonlyData`, so long-name rustc static
data does not become a global text symbol or executable content. Multiple
nonempty read-only sections remain rejected. The pinned volatile-static probe
also emitted a writable `.data$...` COMDAT with an `ADDR64` relocation; that
section still fails closed pending an explicit writable layout and fixed-base
relocation model, so the complete probe does not yet link.

The PE serializer now has an explicit bounded writable-data input. It emits a
separate page-aligned `.data` section with read/write and non-executable
characteristics, validates every eight-byte field, and resolves typed `ADDR64`
targets to absolute addresses in an owning input's checked read-only layout.
The image remains fixed at its declared base and intentionally emits no base
relocation table. The existing PE APIs delegate with no writable inputs and
retain their prior output. COFF writable-section decoding and driver transport
remain separate gates.

The COFF core now decodes one nonempty initialized RW/non-executable
`.data$...` section into typed writable bytes. Every relocation must be an
eight-byte AMD64 `ADDR64` field whose checked symbol and addend resolve inside
the object's single admitted read-only section. Text-fragment decoding
recognizes the section without folding it into code, while the legacy decoder
explicitly rejects it to prevent silent data loss. Multiple writable sections,
other target classes, and driver transport remain unsupported.

The PE driver now decodes writable data only for selected source-object
identities, retains each object's independent relocation arena, includes the
bytes in payload-tier selection, and passes the typed views to the fixed-base
serializer. The exact pinned volatile-static object linked to a 2,048-byte PE;
Windows returned 42. The image has three sections, `.data` is at RVA `0x3000`
with `0xc0000040` RW/NX characteristics, and its pointer field contains the
exact fixed address `0x140002000` of the read-only value.

The controlled 93-byte no-data benchmark measured MRML at 9.577 ms median and
9.759 ms mean versus pinned gnullvm rust-lld at 26.952 ms median and 27.186 ms
mean over 50 iterations after five warmups. Both 1,024-byte outputs returned
42. These hosted probes establish one static-data shape and narrow regression
evidence, not general writable-data, COMDAT, or performance coverage.

The later bounded fragment milestone supersedes the earlier single-section
limits for the pinned COFF shape. Adjacent nonempty `.rdata$...` sections form
one zero-copy read-only span, and each `.data$...` section is decoded by index
with an independent checked relocation arena. Static functions in separate
`.text$...` sections use their section identity as a local relocation target;
those targets resolve after atomic object-member selection but do not make an
archive member eligible or expose the static Rust symbol as a global
definition. Duplicate section identities fail closed.

An exact ORACLE-0002 object containing two text fragments, two statics, entry
unwind metadata, two adjacent read-only fragments, and two writable pointer
fragments linked to a 2,048-byte PE and returned 42 on Windows. On the same
1,536-byte input, 50 iterations after five warmups measured MRML at 9.590 ms
median and 9.822 ms mean versus pinned gnullvm rust-lld at 27.162 ms median and
27.249 ms mean. Both outputs were 2,048 bytes and returned 42. This is narrow
hosted evidence for that object shape, not representative-library or general
performance superiority evidence.

Pinned gnullvm rlibs may also carry `.llvmbc` and `.llvmcmd` sections marked
`IMAGE_SCN_LNK_REMOVE`. The COFF decoder now admits only those exact names when
the remove bit is present and the section has no relocations; their bytes and
symbols never enter the linked image. Missing remove semantics or any metadata
relocation fails closed. An exact 7,946-byte rlib containing three text
fragments and three runtime-function records linked to a 1,536-byte PE and
returned 42. Over 50 iterations after five warmups, MRML measured 9.751 ms
median and 9.820 ms mean versus pinned rust-lld at 27.283 ms median and 27.384
ms mean. rust-lld's output was 1,024 bytes while MRML's was 1,536 bytes, so the
measurement establishes executable agreement and a narrow timing observation,
not byte identity or a general performance claim.

The COFF parser's explicit section bound is now 256 rather than the earlier
incidental 16. All per-section classification arrays use the same bound, while
text fragments, total link inputs, definitions, relocations, runtime functions,
and writable fragments retain their independent existing limits. A synthetic
control rejects section count 257 before reading section headers. An exact
ORACLE-0002 14,606-byte rlib with a 9,519-byte, 32-section object member, eight
static framed helpers, nine text fragments, and nine runtime-function records
linked to a 1,536-byte PE and returned 42. The same-input benchmark measured
MRML at 9.807 ms median and 10.055 ms mean versus pinned rust-lld at 27.483 ms
median and 27.500 ms mean over 50 iterations after five warmups. Output sizes
were 1,536 and 1,024 bytes respectively; this remains a small hosted scaling
probe, not representative-library or general superiority evidence.

After this integration, the controlled 93-byte no-unwind object benchmark ran
50 iterations after five warmups. MRML measured 10.081 ms median and 10.260 ms
mean versus pinned gnullvm rust-lld at 27.632 ms median and 27.791 ms mean. Both
1,024-byte outputs returned 42. This is narrow regression evidence, not a
general performance claim.

After driver fragment expansion, the controlled one-object procedure measured
MRML at 9.275 ms median and 9.361 ms mean versus pinned gnullvm rust-lld at
26.598 ms median and 26.981 ms mean across 50 iterations after five warmups.
Both 1,024-byte outputs returned 42. This confirms that exact-count arena
allocation preserved the narrow fast path; it is not multi-fragment,
archive-scale, or general superiority evidence.

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

The bounded ELF decoder now also admits one nonempty pinned-rustc
`.text.<symbol>` section and its exact `.rela.text.<symbol>` table, an empty
base `.text`, local absolute file metadata symbols, non-allocating `.comment`,
an empty `.note.GNU-stack`, and excluded `.llvmbc`/`.llvmcmd` metadata. These
sections are validated but never copied into loadable output. With the explicit
static relocation and no-unwind profile, two independently compiled objects
linked through `R_X86_64_PLT32`; a naked process entry called the later helper,
issued Linux `exit`, and returned status 42 from the 4,118-byte ELF image under
the exact ORACLE-0002 Arch WSL environment. Windows and Linux each passed 707
core tests and four driver tests.

The default-PIC external call/jump subset now admits `R_X86_64_GOTPCREL` only
for the exact six-byte `ff /2` or `ff /4` RIP-relative indirect instruction and
only when static selection resolves the symbol inside the final fixed image.
The linker rewrites that checked shape to size-preserving `nop; call rel32` or
`nop; jmp rel32`; other GOT uses, opcodes, defined-section targets, and dynamic
interposition remain rejected. A focused test checks the exact bytes,
displacement, symbol-driven selection, and malformed-opcode rejection. The
pinned default-PIC Linux probe called a later-object helper and exited 42 from
a 4,134-byte image. Over 50 same-input iterations after five warmups, MRML
measured 5.467 ms median and 5.601 ms mean versus pinned rust-lld at 5.997 ms
median and 5.947 ms mean; rust-lld emitted 1,376 bytes. This small WSL process-
startup-heavy result is regression evidence only, not a general speed claim.
`.eh_frame` and relocated debug sections remain fail-closed at this point.

The next ELF milestone combines multiple split `.text.*` payloads from one
object into one zero-copy span when their file ranges are ordered and every
alignment gap is present and all-zero. Symbols and relocation fields receive
checked section-relative offsets into that span; every matching
`.rela.text.*` table is validated and appended under the existing 256-record
bound. A first local fragment uses its section name as internal ownership while
later external definitions remain selectable archive symbols. Nonzero gaps and
non-text relocation targets still fail closed.

An exact ORACLE-0002 13,586-byte rlib containing eight static helpers, nine
split text sections, and eight internal calls linked with a separate process-
entry object to a 4,349-byte ELF image and exited 42 under Arch WSL. Windows and
Linux each passed 708 core tests and four driver tests. Over 50 same-input
iterations after five warmups, MRML measured 5.460 ms median and 5.480 ms mean
versus pinned rust-lld at 6.079 ms median and 6.111 ms mean; rust-lld emitted
2,072 bytes. This is small hosted regression evidence, not general superiority.
`.eh_frame`, relocated debug sections, noncontiguous text payloads, and more
than 256 combined relocations remain fail-closed.

The bounded ELF decoder now also coalesces multiple ordered `.rodata.*`
payloads through the same present-and-zero alignment-gap rule. Defined
read-only symbols retain checked offsets within that combined view. For the
exact pinned-rustc `R_X86_64_GOTPCREL` load shape (`REX.W; mov r64,
[rip+disp32]`), a resolved local read-only target is relaxed in place to the
corresponding `lea`; the ModRM register field is preserved, and every other
opcode/addressing shape remains rejected. Both System V and GNU ELF OSABI tags
are admitted with ABI version zero because the pinned LLVM emitter uses GNU
OSABI when retained read-only sections are present. This still constructs no
GOT and provides no dynamic interposition semantics.

An exact ORACLE-0002 object with two retained static `u64` values produced two
`.rodata.*` sections and two such relocations. Linked with the existing
syscall-only process entry, MRML emitted an 8,208-byte ELF that exited 42 under
Arch WSL; pinned rust-lld emitted 1,624 bytes and also exited 42. Windows and
Linux each passed 709 compiler-core tests and four driver tests. Over 50
same-input iterations after five warmups, MRML measured 5.609 ms median and
5.607 ms mean versus pinned rust-lld at 5.954 ms median and 5.997 ms mean. This
single hosted, process-startup-heavy probe is regression evidence only, not a
general speed or compatibility claim.

The driver no longer requires default pinned-rustc ELF inputs to suppress
unwind-table emission. It separately decodes one conventional `.eh_frame` and
its `.rela.eh_frame` table per selected object, validates the x86-64 unwind
section type, allocation flags, alignment, RELA links, `R_X86_64_PC32` records,
field bounds, symbol indices, and split-text targets, and retains at most 256
combined unwind relocations. Selected inputs carry their exact source-object
indices, so multiple explicit objects cannot alias through the archive-origin
sentinel. The serializer copies each selected frame fragment into the R/NX
load and applies checked function-relative displacements after final layout.

An exact default ORACLE-0002 object with two retained statics linked and exited
42 from an 8,256-byte ELF. A default 9,180-byte rlib with nine functions, a
256-byte `.eh_frame`, and nine frame relocations linked to an 8,448-byte ELF
and exited 42 under Arch WSL. Windows and Linux each passed 710 compiler-core
tests and four driver tests. Over 50 same-input rlib iterations after five
warmups, MRML measured 4.787 ms median and 4.813 ms mean versus pinned rust-lld
at 5.149 ms median and 5.179 ms mean; rust-lld emitted 2,440 bytes. This remains
narrow hosted regression evidence. This first frame-data milestone did not yet
establish runtime discovery or language-level panic/unwind behavior.

The serializer now derives the bounded GNU frame search header directly from
the validated FDE relocation fields: version 1, PC-relative signed four-byte
frame pointer, unsigned four-byte count, and data-relative signed four-byte
sorted table entries. Before table generation the decoder verifies each
relocation addresses the initial-location field of a bounded 32-bit-length FDE,
resolves its backward CIE reference to a bounded zero-identity CIE, and requires
strictly increasing relocation fields. The R/NX load contains the generated
header and relocated frames, and a read-only `PT_GNU_EH_FRAME` program header
identifies the exact search-table range. This interprets record boundaries and
CIE identity only; it does not interpret CFI instructions.

On the same nine-function default rlib, `readelf -lW` recognized MRML's fourth
program header as `GNU_EH_FRAME`, covering the 84-byte generated table. The
8,536-byte executable exited 42. Over 50 identical-input iterations after five
warmups, MRML measured 4.432 ms median and 4.453 ms mean; pinned rust-lld with
the equivalent `--eh-frame-hdr` option measured 4.971 ms median and 5.000 ms
mean and emitted 2,656 bytes. Windows and Linux each passed 710 compiler-core
tests and four driver tests. Actual stack unwinding, panic propagation, and
backtrace behavior remain unverified and are not claimed.

The bounded ELF path now also separates selected writable storage from text,
read-only data, and frame data. A dedicated decoder admits ordered initialized
`.data.*` PROGBITS and `.bss.*` NOBITS sections with exact WA flags, bounded
power-of-two alignment, checked symbol values, and text-side
`R_X86_64_PC32` references. Initialized and zero-fill targets have distinct
typed identities. The serializer lays every selected initialized fragment
before all zero-fill memory, preserves each alignment, applies references only
after final layout, and emits a page-separated RW/NX load whose file size
excludes BSS while its memory size includes it. Writable records do not enter
the global symbol namespace or archive-selection authority path.

An independently authored volatile-static ORACLE-0002 object contained one
8-byte `.data.*`, one 8-byte `.bss.*`, three writable PC-relative references,
and one frame record. Linked with the syscall entry, MRML emitted a 12,296-byte
ELF with distinct R, RX, R/NX, and RW/NX loads; `readelf -lW` reported an
8-byte writable file payload and 24-byte writable memory extent, and execution
exited 42 under Arch WSL. Windows and Linux each passed 712 compiler-core tests
and four driver tests. Over 50 same-input iterations after five warmups, MRML
measured 5.004 ms median and 5.016 ms mean versus pinned rust-lld with
`--eh-frame-hdr` at 5.090 ms median and 5.137 ms mean; rust-lld emitted 2,040
bytes. This is narrow hosted evidence only. ELF TLS, COMMON symbols,
copy/dynamic relocations, constructors, and general writable Rust runtime state
remain unsupported or unverified.

Initialized ELF writable storage can now also carry bounded `R_X86_64_64`
relocations to text or read-only data in the same selected input. The decoder
requires a conventional allocated RELA table linked to the exact symbol table,
an initialized `.data.*` target, a defined local text/read-only target, an
eight-byte in-bounds field, and no more than 256 combined absolute relocations.
The serializer writes the checked final virtual address only after RX, R/NX,
and RW/NX layout is fixed. Unsupported relocation kinds and targets continue
to fail closed; this is static absolute-address support, not dynamic relocation
or position-independent loading.

An independently authored optimized ORACLE-0002 object stored a `&[u8]` fat
pointer in `.data.*`, with one `R_X86_64_64` relocation to a local
`.rodata.*` string and two text-side references to the writable record. MRML
emitted a 12,304-byte ELF whose writable pointer resolved to `0x402000`; the
program exited 42 under Arch WSL and `readelf -lW` showed separate R, RX, R/NX,
and RW/NX loads. Linux passed 714 compiler-core tests and four driver tests.
Windows passed all four driver tests and 713 of 714 compiler-core tests; the
remaining failure is in concurrently modified MRML ABI codegen and reports
`UnsupportedRuntimeType`, outside the linker files. Over 50 identical-input
iterations after five warmups, MRML measured 4.768 ms median and 4.853 ms mean
versus pinned rust-lld with `--eh-frame-hdr` and the same entry at 5.003 ms
median and 4.972 ms mean; rust-lld emitted 1,984 bytes. This is narrow hosted,
process-startup-heavy regression evidence, not a general performance or
compatibility claim.

The same bounded initialized-data relocation path now accepts typed targets in
the selected input's initialized and zero-fill storage. Section-symbol values
are translated through the existing checked data/BSS layouts; the serializer
then patches absolute addresses from the exact per-input initialized or BSS
base. Target offsets are revalidated against their distinct storage extents,
so an initialized target cannot be confused with a zero-fill target.

An independently authored optimized ORACLE-0002 object contained two
initialized pointer records: one targeting an initialized `u64`, and one
targeting a zero-fill `u64`. Its two `R_X86_64_64` records and two text-side
references linked into a 12,312-byte MRML ELF and executed with exit 42 under
Arch WSL. Windows and Linux each passed 714 compiler-core tests and four driver
tests. Over 50 identical-input iterations after five warmups, MRML measured
4.859 ms median and 4.912 ms mean versus pinned rust-lld with
`--eh-frame-hdr` at 4.869 ms median and 4.909 ms mean; rust-lld emitted 2,200
bytes. The 0.010 ms median difference is within ordinary process-startup noise
and is retained only as narrow regression evidence, not a speed claim.

Initialized-data `R_X86_64_64` records may now target a named text definition
in another selected object. The primary ELF decoder records each undefined
absolute target as a typed non-text dependency: it participates in ordinary
left-to-right archive selection and missing/duplicate-symbol validation but
does not pretend to own a PC-relative text field. The writable decoder retains
the borrowed symbol identity, and final serialization resolves it through the
same frozen global text layout used by calls. Both dependency and patch records
remain under the existing 256-relocation bounds.

An independently authored ORACLE-0002 consumer stored an external `helper`
function in an initialized function-pointer static; the provider was placed in
a later ordinary archive. The absolute dependency selected that archive member,
the final pointer resolved to its checked text definition, and the 12,304-byte
MRML ELF exited 42 under Arch WSL. Windows and Linux each passed 715
compiler-core tests and four driver tests. Over 50 identical-input iterations
after five warmups, MRML measured 4.690 ms median and 4.717 ms mean versus
pinned rust-lld with `--eh-frame-hdr` and the same entry at 5.019 ms median and
5.054 ms mean; rust-lld emitted 2,008 bytes. This single tiny archive workload
is narrow process-startup-heavy regression evidence, not a general linker-speed
or Rust-library compatibility claim. Named absolute targets outside text,
symbol preemption, weak definitions, and dynamic relocations remain unsupported.
After the final symbol-table-link and global-binding validation was added, both
platform driver checks and the exact Linux execution probe passed again. A
later Windows full-core rerun could not compile because concurrent unrelated
`codegen/tests.rs` work lacked the `format!` macro; no linker failure was
reported, and those user changes were left untouched.

Global definitions are now typed as text or read-only-data locations rather
than assuming every public name begins at text offset zero. This admits an ELF
object with empty `.text` whose primary global definition resides in ordered
`.rodata.*`, validates both primary and additional targets against their own
extents, selects such data-only archive members through the existing non-text
dependency path, and resolves named PC-relative or absolute references through
the frozen text/read-only layout. Names continue to identify definitions only;
the build tool gains no runtime authority from a symbol.

An independently authored ORACLE-0002 consumer stored a pointer to external
`VALUE`, while the later archive provider contained only empty `.text` and an
8-byte global `.rodata.VALUE`. MRML selected the provider, emitted a 12,304-byte
ELF with the value in its R/NX load, and exited 42 under Arch WSL. Windows and
Linux each passed 716 compiler-core tests and four driver tests. Over 50
identical-input iterations after five warmups, MRML measured 4.681 ms median
and 4.720 ms mean versus pinned rust-lld with `--eh-frame-hdr` and the same
entry at 4.841 ms median and 4.857 ms mean; rust-lld emitted 2,080 bytes. This
tiny archive probe is narrow hosted regression evidence, not a general speed
or compatibility claim. Global writable/TLS definitions, weak/versioned
symbols, preemption, and dynamic relocations remain unsupported.

Allocated zero-sized `.rodata.*` sections are now retained as typed local
read-only identities even though they contribute no bytes. A zero-valued
reference is mapped to the owning input's read-only base only when the section
has conventional PROGBITS/A identity and power-of-two alignment no greater than
16; nonzero offsets or stronger unrepresented alignment fail closed. This
supports Rust zero-sized static identities without fabricating payload bytes or
trusting their original file offsets.

An independently authored optimized ORACLE-0002 trait-object probe emitted a
zero-byte `ANSWER` section, a 32-byte vtable in `.data.rel.ro.*`, an initialized
fat pointer, three absolute relocations, two writable text references, and two
frame records. MRML linked it into a 12,344-byte ELF with separate RX, R/NX,
and RW/NX loads, and virtual dispatch exited 42 under Arch WSL. Windows and
Linux each passed 717 compiler-core tests and four driver tests. Over 50
identical-input iterations after five warmups, MRML measured 5.092 ms median
and 5.097 ms mean versus pinned rust-lld with `--eh-frame-hdr` at 5.241 ms
median and 5.218 ms mean; rust-lld emitted 2,128 bytes. This is one hosted
trait-object regression probe, not general trait/vtable, speed, or ABI coverage.

The archive decoder now validates and exposes conventional GNU `/` and
`/SYM64/` symbol indexes under a separate 4,096-entry bound. Big-endian counts
and member offsets, offset-table extent, UTF-8 NUL-terminated nonempty names,
exact payload consumption, duplicate index members, and offset correspondence
to independently parsed ordinary member headers are checked. An index entry is
only a lookup hint: it neither defines a symbol nor makes its referenced member
eligible without subsequent object decoding and definition validation. BSD
indexes remain ignored metadata.

An exact ORACLE-0002 `.rlib` containing `lib.rmeta`, `lib.rmeta-link`, a GNU
index, and one data-only object linked with the external-data consumer to a
12,304-byte ELF and exited 42 under Arch WSL. Windows passed 718 compiler-core
tests and Linux passed 720; both passed four driver tests. Over 50
identical-input iterations after five warmups, MRML measured 4.745 ms median
and 4.746 ms mean versus pinned rust-lld with `--eh-frame-hdr` at 5.659 ms
median and 5.617 ms mean; rust-lld emitted 2,080 bytes. This tiny indexed-rlib
probe is narrow hosted evidence. The driver still eagerly expands candidate
members, so index-guided lazy extraction and archives exceeding 256 ordinary
members remain separate incomplete gates.

The hosted driver now uses a validated GNU index to compute a bounded
left-to-right unresolved-symbol closure before admitting archive members to the
full decode and layout pipeline. Explicit objects and each admitted member are
scanned for exact definitions and named relocations; a selected index mapping
must be confirmed by the referenced object definition. Members are emitted in
original archive order. An archive without a usable index disables later lazy
pruning for that command, preserving the established eager selection semantics
instead of inferring completeness from absent metadata. A focused test places
an invalid unindexed member beside the indexed entry object and proves that the
invalid member is never decoded.

The exact ORACLE-0002 indexed data-provider `.rlib` continued to link and exit
42 under Arch Linux WSL. Windows and Linux each passed 720 compiler-core tests
and five driver tests. Over 50 identical-input iterations after five warmups,
MRML measured 4.680 ms median and 4.720 ms mean versus pinned rust-lld with
`--eh-frame-hdr` at 4.887 ms median and 4.899 ms mean; outputs remained 12,304
and 2,080 bytes. This one-member archive does not demonstrate the intended
scaling benefit and is only correctness/regression evidence; representative
multi-member `.rlib` measurements remain required.

Indexed archive inventory is now separate from the 256 selected-link-input
limit: the decoder admits at most 1,024 independently framed ordinary members
while the final link still admits at most 256 selected objects/fragments. This
allows the index-guided path to skip large irrelevant tails without allocating
them as link inputs or weakening the existing output-work bound. A focused
301-member archive containing one valid indexed entry object and 300
unreferenced invalid payloads selected only the entry on both Windows and Linux;
both platforms retained 720 compiler-core passes and five driver passes. This
is bounded synthetic scaling evidence, not general `.rlib` compatibility.

A controlled 319,802-byte archive then combined one real provider object with
300 copies of a real unreferenced ELF object. MRML selected the provider,
emitted 12,304 bytes, and the result exited 42. Over 50 iterations after five
warmups, MRML measured 5.063 ms median and 5.100 ms mean versus pinned rust-lld
with `--eh-frame-hdr` at 5.302 ms median and 5.327 ms mean; rust-lld emitted
2,080 bytes. Repeating one unused object is useful scaling regression evidence
but is not representative Rust-library diversity or a general speed claim.

A separate pinned-rustc probe uses 32 independently exported functions spread
across 16 codegen units. Its genuine 85,332-byte `.rlib` contains `lib.rmeta`,
`lib.rmeta-link`, and 16 distinct rustc object members; the consumer references
two functions in different members. MRML selected the required members, emitted
8,432 bytes, and exited 42, matching rust-lld's 2,120-byte output behavior. Over
50 iterations after five warmups, MRML measured 4.306 ms median and 4.360 ms
mean versus pinned rust-lld with `--eh-frame-hdr` at 4.981 ms median and 5.028
ms mean. This is materially more diverse archive evidence than the repeated-
object probe, but it remains one small no-std hosted workload and does not prove
general rustc `.rlib` compatibility or speed superiority.

Index closure now consumes each newly discovered unresolved reference through a
bounded work-queue cursor instead of repeatedly rescanning every archive-index
entry against all accumulated references. Each name still performs an exact
validated index lookup; selecting a member appends its newly decoded named
relocations to the same queue, so transitive dependencies reach a fixed point
without changing archive ordering or treating index data as a definition.

The 16-codegen-unit probe was changed so the consumer references only
`diverse_31`, whose archive member calls `diverse_11` in a different member.
MRML selected both transitively, emitted 8,344 bytes, and exited 42 like
rust-lld's 1,880-byte result. Over 50 iterations after five warmups, the queued
MRML path measured 4.577 ms median and 4.678 ms mean versus pinned rust-lld at
4.700 ms median and 4.747 ms mean. On the 301-object controlled archive MRML
measured 4.902 ms median versus rust-lld at 4.886 ms in the same run, so that
case is a near tie and provides no superiority evidence. These are hosted
regression measurements, not broad performance claims.

Large ordinary linker inputs now have an explicit 64 MiB per-file read bound
instead of inheriting the earlier 1 MiB small-object aggregate. The shared
bounded reader uses validated file length to reject oversized inputs before
allocation, reserve exactly once, and fill the known prefix directly before
checking for concurrent growth. GNU index decoding also accepts LLVM's exact
single NUL needed to align an otherwise odd-length name area; the padding is
allowed only after every declared name, only when the consumed length is odd,
and arbitrary trailing bytes remain invalid.

Those changes admit the exact ORACLE-0002 `libcore` archive: 3,150,398 bytes,
551 indexed symbols, metadata members, and one 3,104,472-byte rustc object.
When appended to an independently authored entry that needs no core symbol,
MRML skipped the object, emitted 8,264 bytes, and exited 42; rust-lld emitted
1,664 bytes with the same behavior. A 50-iteration/five-warmup measurement
recorded MRML at 6.769 ms median and 6.742 ms mean versus pinned rust-lld at
5.634 ms median and 5.661 ms mean. MRML is slower on this metadata-dominated
case, so faster large-file ingestion remains an explicit optimization gate.
Windows passed 721 core unit tests, all integration suites, 44 runtime tests,
and five driver tests. Linux passed the 721 core unit tests, 44 runtime tests,
and five driver tests; one concurrently modified wide-integer semantic
integration probe failed with `RuntimeExpressionUnsupported`, outside linker
and runtime files, and was preserved untouched.

The hosted linker now keeps each bounded input in an owning read-only file
mapping rather than copying the entire file into a growing vector. The mapping
retains its file lifetime, validates the exact length against the 64 MiB bound
before mapping, represents empty files without an OS mapping, exposes only an
immutable byte slice, and unmaps exactly once on drop. Both existing Windows
and Linux native mapping backends are covered through one runtime abstraction;
ordinary non-linker bounded reads retain their prior behavior.

With mapped inputs, the identical 3,150,398-byte pinned `libcore` probe measured
MRML at 4.835 ms median and 4.852 ms mean versus rust-lld at 5.251 ms median and
5.301 ms mean over 50 iterations after five warmups. The transitive 16-codegen-
unit `.rlib` measured 4.869 ms versus 5.205 ms, and the controlled 301-object
archive measured 4.921 ms versus 5.372 ms. Every MRML and rust-lld output kept
its expected exit-42 behavior. Windows and Linux each passed 45 runtime tests
and five driver tests. These three current hosted samples are positive
regression evidence, not proof that MRML is generally faster than rust-lld.

ELF and COFF section inventory limits are now distinct. COFF remains capped at
256 sections, while ELF64 relocatables admit at most 2,048 section headers in
the primary, unwind, and writable-data passes. This covers the exact pinned
`libcore` object's 1,702-section table without broadening the PE/COFF surface or
removing fixed-capacity validation. Archive-selection diagnostics now preserve
the exact bounded linker error instead of collapsing every member failure into
one generic driver message.

An independently authored consumer with a retained pointer to exact exported
core symbol `_RNvNtCs5erv4YX8a5g_4core3fmt17pointer_fmt_inner` causes the pinned
core object to be selected. It now passes archive, file-size, index, and section-
count gates before failing closed on the next unsupported ELF feature. Inspection
shows the object contains relocated read-only section families among its 1,702
sections; supporting it correctly requires section-level dependency/GC and
read-only relocation modeling, not blindly copying the entire 3.10 MiB member.
Windows and Linux each passed 722 core unit tests, all integration suites, and
five driver tests. Actual core-symbol extraction remains incomplete.

This increment does **not** emit PE imports/exports/base
relocations/debug data, emit ELF dynamic metadata/interpreter/PIE/sections,
read thin archives or general `.rlib` contents, perform section GC or ICF, link
dynamically, run work in parallel, or integrate linker selection into the
public `mrml` build frontend. Index-guided extraction remains bounded to 1,024
ordinary archive members, 4,096 index symbols, and 256 admitted link inputs and
has not yet been optimized against large representative Rust libraries.
Those are separate milestones and the current upstream linker remains the
production linker for ordinary package builds as required by
`docs/build/BUILD_SYSTEM.md`.

Research source:

- Rui Ueyama, [Design and implementation of mold](https://github.com/rui314/mold/blob/main/docs/design.md).
