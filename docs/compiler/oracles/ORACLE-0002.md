# MRML Rust oracle generation 0002

## Identity

- rustup toolchain: `nightly-2026-08-24`
- rustc version: `rustc 1.100.0-nightly`
- full commit: `fb6531d550e0075b9eb9a51464f404805eec87d9`
- source/build date: `2026-08-23`
- MRML verification date: `2026-08-25`
- verified host: `x86_64-pc-windows-gnullvm`
- LLVM version: `23.1.0`
- edition/default behavior: MRML probes use Rust 2024 syntax where applicable;
  individual mapped upstream tests retain their own declared/default edition.

This exact dated nightly is the repository's default upstream build toolchain
and current behavioral oracle. ORACLE-0001 remains an immutable prior generation.
Neither record promises compatibility with every behavior of its compiler.

## Relevant feature state

- Polonius: no complete Polonius compatibility claim is established; the MRML
  corpus covers only its independently implemented and documented borrowing
  subset.
- trait solver: no complete next-generation trait-solver compatibility claim is
  established.
- unstable features: only features exercised by independently authored MRML
  source and probes are adopted; the nightly as a whole is not an MRML contract.
- unsupported borrowing, trait, provenance, unsafe, ABI, assembly, const, or
  metadata behavior continues to fail closed as documented.

## Delta from ORACLE-0001

ORACLE-0001 used rustc commit
`f7d782a3be46d6bb4b9792fe69a61db389ba1769` from 2026-08-19. Generation 0002
advances the default to the nightly distributed on 2026-08-24. The existing
MRML compiler corpus passed unchanged on the verified Windows gnullvm host; no
corpus-visible semantic or diagnostic delta was observed. This is bounded
evidence, not a claim that the upstream compilers are globally equivalent.

## Conformance result

All 767 `mrml-rustc` and `mrml-rustc-driver` tests passed on Windows gnullvm.
Clippy with warnings denied also passed. A previous Arch Linux release build of
the same rustc commit crashed in LLVM `PromotePass`; Linux is therefore recorded
as a toolchain regression/blocker, not passing oracle evidence. The default pin
does not convert that failure into a cross-host support claim.

Generation 0002 is accepted as the current build/oracle for the documented
subset on the verified host. Future generations must preserve both prior
records, rerun the corpus, classify observed deltas, and retain independently
authored regression probes.

## Component-interface follow-up

On 2026-08-25, the canonical native MRML action added and passed one independently
authored component-interface probe on Windows gnullvm and Arch Linux. Pinned
upstream rustc executed the explicit Zstd ABI-3 generation/operation/size
identity check, while `mrml-rustc` emitted nonempty COFF and ELF objects for the
same bounded scalar projection. The full core action passed 420 library, one
component-interface, 10 conformance, and 335 nightly-replacement tests on each
host. This does not revise the earlier Linux release-build regression, claim
full binding-source compatibility, compare object semantics byte-for-byte, or
make Rust/C ABI part of the stable MRML interface.
