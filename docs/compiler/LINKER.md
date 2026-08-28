# MRML linker

Status: **PARTIALLY IMPLEMENTED**.

The first MRML-owned linker increment is a dependency-free, bounded x86-64
static-link core in `packages/compiler/core/src/linker.rs`. It accepts already
decoded code and read-only-data fragments, resolves one defined symbol per
input, freezes a deterministic 16-byte-aligned layout, copies disjoint ranges,
and applies checked signed 32-bit PC-relative relocations. Duplicate or missing
symbols, malformed names, invalid relocation fields, arithmetic overflow,
capacity exhaustion, and displacement overflow fail closed.

The core also decodes the exact bounded x86-64 COFF subset currently emitted by
`mrml-rustc`: one `.text`, an optional `.rdata`, short or string-table symbol
names, one defined function symbol, bounded undefined symbols, and
`IMAGE_REL_AMD64_REL32` relocations. Machine, section, symbol, string-table,
range, relocation-type, and truncation checks precede linking. This is compiler
object ingestion, not general COFF compatibility.

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

`mrml-rustc-driver --link-coff INPUT --entry NAME -o OUTPUT` exposes the same
bounded path without compilation. This linker-only mode is the comparison
surface for identical-input cold-process measurements against the pinned
gnullvm `rust-lld`; it does not accept arbitrary COFF extensions outside the
documented MRML subset.

On 2026-08-28, the controlled Windows cold-process probe linked the same
93-byte MRML COFF object 50 times after five interleaved warmups. MRML produced
a 1,024-byte PE with a 10.196 ms median and 10.323 ms mean; pinned
`nightly-2026-08-24` gnullvm `rust-lld` produced a 1,024-byte PE with a
26.870 ms median and 27.184 ms mean. Both executables returned 42. This is a
2.64x median speedup for one tiny import-free object on this host. It is not a
large-program, archive, debug-info, parallel-scaling, or general superiority
claim. `docs/compiler/linker/benchmark-windows.ps1` preserves the identical-
input procedure.

The pass structure is informed by mold's public design notes: establish output
layout early, run a small sequence of understandable passes, and keep per-input
validation, copying, and per-relocation work independent so a hosted driver can
later use data-parallel loops. MRML does not copy mold source or claim mold
compatibility or performance. The cited design note warns that its 2020 object
preloading proposal is outdated, so MRML does not adopt that proposal.

This increment does **not** decode ELF input, write ELF executables, emit PE
imports/exports/exception metadata/base relocations/debug data, read archives,
perform section GC or ICF, link dynamically, run work in parallel, or integrate
linker selection into the public `mrml` build frontend. Those are separate
milestones and the current upstream linker remains the production linker for
ordinary package builds as required by `docs/build/BUILD_SYSTEM.md`.

Research source:

- Rui Ueyama, [Design and implementation of mold](https://github.com/rui314/mold/blob/main/docs/design.md).
