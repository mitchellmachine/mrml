# Universal build migration inventory

**Status: PARTIALLY IMPLEMENTED.** The authoritative machine-readable inventory
is [`../../MRML.workspace`](../../MRML.workspace). All 42 current components are
classified and reachable through the Cargo bridge. `mrml-math` and
`mrml-percent-encoding`, `mrml-tokenizer`, `mrml-zstd`, `mrml-zim`, and
`mrml-json` have moved under
`packages/libraries/`, and stage-zero
lives at `tools/mrml`; other source remains under `crates/`. No claim is made
that semantic moves or Cargo bridge removal are complete.

## Implemented first gate

- dependency-free Rust `tools/mrml`, bootstrapped with pinned Cargo/rustc;
- versioned native component inventory with distinct identity, path, Cargo bridge,
  class, target families, default selection, dependencies, features, outputs,
  and per-component input policies;
- Windows/Linux host recognition and MRML/Windows/Linux/UEFI/CUDA target families;
- structured list, doctor, build, test, target/toolchain failure, and planned-
  command results;
- bounded Cargo metadata parsing and `mrml audit` verification of component
  names, manifest paths, local dependencies, features, outputs, build scripts,
  procedural macros, and direct source-input sites; see
  [BRIDGE_INVENTORY.md](BRIDGE_INVENTORY.md);
- stage1 `mrml` selection, `mrml-rustc-driver`, current-host WHP/KVM selection,
  x86-64 UEFI routing, and lazy CUDA/PTX routing;
- duplicate `mrml-opus` root workspace member removed.
- dependency-free `mrml-math` moved to its semantic library home with all three
  consumer paths and the native graph updated; its Cargo bridge remains.
- `mrml-percent-encoding` moved with its runtime dependency and sole tools
  consumer updated; its malformed-input tests and Cargo bridge remain.
- `mrml-tokenizer` moved with its runtime dependency and sole trainer consumer
  updated; its UTF-8 round-trip/training tests and Cargo bridge remain.
- `mrml-zstd` moved with its runtime dependency, Wikipedia consumer, and patent
  source reference updated; its eight decoder tests and Cargo bridge remain.
- `mrml-zim` moved with its runtime dependency and Wikipedia consumer updated;
  its four archive/parser tests and Cargo bridge remain.
- `mrml-json` moved with its runtime dependency and six consumers updated; its
  four parser/writer tests and Cargo bridge remain.

`package`, `release`, `image`, and `publish` deliberately fail as `PLANNED`.
Linux, KVM, cross-host equivalence, physical UEFI/GPU, and release functionality
were not exercised by the Windows implementation environment.

## Current semantic classes

| Class | Current components/direction |
| --- | --- |
| `BOOTSTRAP_ONLY` | `tools/mrml`; Cargo stage zero, then self-build graph |
| `COMPILER` | `mrml-rustc`, driver; future clear `compiler/` hierarchy |
| `MRML_NATIVE` | kernel, service image, configuration, storage |
| `UEFI` | kernel-image bootloader artifact; `mrml-uefi` is shared support |
| `HOST_WINDOWS_LINUX` | CLI/server/tools/sign/Git/trainer and VMM launchers |
| `GPU` | tensor/CUDA compatibility path; native GPU remains separate |
| `TEST` | kernel benchmark |
| `SHARED` | reusable crypto/runtime/protocol/media/model/platform libraries |

The exact 42 entries live in `MRML.workspace`; this table must not become a
second inventory.

## Cargo-removal blockers

- Every component still has Cargo dependency metadata; all except the six moved
  libraries and stage-zero remain beneath `crates/`. The root Cargo workspace
  still contains every component so the bridge resolves today’s exact graph.
- `crates/mrml-tensor/build.rs` invokes rustc for CUDA PTX and is the one current
  build script. It must become an explicit structured build action.
- Dependency, feature, output, and source-input facts are persisted and fail
  closed on Cargo metadata or lexical-audit drift. Lexical discovery still
  cannot prove that arbitrary macro expansion introduces no additional input.
- Direct-rustc graph construction needs target-aware resolved externs, features,
  build order, lock/digest validation, and cycle diagnostics before Cargo can be
  removed behind migrated nodes.
- Moving all paths requires updating Cargo dependencies, docs, scripts, fixtures,
  and CI together and verifying both Windows/WHP and Linux/KVM. The present task
  intentionally establishes the graph before that high-churn move.

## Next safe migration order

1. Move the next dependency-light leaf into `packages/libraries/`, update every
   reference, and prove Cargo-bridge and `mrml` builds agree.
2. Expand by semantic groups: shared libraries, services, system, host tools;
   keep compiler and bootstrap roots distinct.
3. Prove Windows WHP and Linux KVM matrices, then remove generic `crates/` only
   after repository-wide stale-path search returns none.
4. Add direct-rustc nodes/native resolver, leaving Cargo required only for clean-
   source stage-zero `mrml` bootstrap.

Patent review: `NOT_TRIGGERED` for this incremental implementation—the parser,
process orchestration, explicit graph inventory, target dispatch, and structured
errors are conventional build-tool mechanisms. Package/cache/resolver mechanisms
remain under the existing triggered review in
[`../patents/REVIEW_LOG.md`](../patents/REVIEW_LOG.md).
