# Cargo bridge inventory

**Status: IMPLEMENTED NATIVE AUDIT / TRANSITIONAL COMPILATION BRIDGE.** The
dependency-free `mrml` frontend resolves version-3 `MRML.workspace` declarations
without invoking Cargo metadata. It rejects duplicate MRML/path/Cargo-stage
identities while loading, then rejects missing dependencies, self-dependencies,
cycles, unknown targets, and empty output sets with bounded structured errors.
Its deterministic dependency-first order is repository-owned. Input policies
are compared with the bounded source scan. Cargo remains only as the current
compilation bridge while direct-rustc actions are made exact; Cargo identity is
not MRML package identity or runtime authority.

Run the human or stable structured inventory with the pinned toolchain:

```text
mrml audit
mrml audit --output structured
```

The 2026-08-25 Windows gnullvm result is:

```text
42 components
118 deduplicated local dependency records
72 feature names
64 declared outputs
1 custom build target
0 procedural-macro targets
9 native-link source sites
31 compile-time environment source sites
1 included-file source site
48 external-command source sites
```

The structured output emits every native component, dependency list, feature
list, output declaration, and source-input location before its final summary. Source
scanning is bounded to declared component roots, rejects symlinks, caps paths and
file sizes, and reports exact repository-relative file and line locations.

## Exact exceptional mechanisms

- `mrml-tensor` owns the sole custom build target. Its `build.rs` invokes the
  pinned rustc CUDA target and materializes PTX consumed through `include_bytes!`.
- There are no procedural-macro targets.
- Native link attributes occur only in the Windows/Linux platform layers, KVM,
  WHP, `mrml-math`, the hosted kernel benchmark, and the Opus differential
  example. They are host/compatibility inputs, not MRML-native application ABI.
- Compile-time environment and external-command sites remain bridge inputs and
  must become explicit per-node declarations before direct-rustc execution.

This inventory is lexical risk discovery, not proof that arbitrary macro output
cannot create another input. The native resolver covers declared graph facts;
the source scan identifies known direct sites. Both must pass before a direct-
rustc or Cargo-removal step.

## Next gate

All 42 tracked components now live in semantic `apps/`, `compiler/`, `packages/`,
`services/`, `system/`, `tests/`, or `tools/` homes; no tracked component remains
under generic `crates/`. The next gate makes source roots, crate types, editions,
target cfgs, feature activation, extern names/artifacts, build actions, compiler
flags, and lock/digest inputs exact enough for direct rustc. The dependency-free
`mrml-math`, `mrml-windows`, and `mrml-linux` leaves are the first exact native
build/test actions and do not invoke Cargo. Windows execution covers math and
the Windows leaf; Arch Linux WSL2 execution covers math and the Linux leaf.
This does not establish bare-metal Linux or KVM parity. Cargo must then be
confined to clean-source stage-zero bootstrap only after Windows/Linux build
equivalence is demonstrated. Treat input-policy changes as explicit review items,
never automatically accepted count updates.

`mrml-runtime` is the first dependent native action. Its two declared package/
crate extern bindings are target-scoped, dependency-first, and wired by exact
native artifact path. Windows passed 38 direct runtime tests; Arch Linux WSL2
passed 37 direct runtime tests. No inactive platform rlib is supplied to rustc.

Eight featureless runtime consumers now use the same native path:
`mrml-percent-encoding`, `mrml-tokenizer`, `mrml-zstd`, `mrml-zim`, `mrml-json`,
`mrml-wikipedia`, `mrml-error`, and `mrml-terminal-style`. Each host passed 31
direct tests across the layer. Twelve of 42 components now have explicit native
actions; 30 remain `cargo-transition`.

The dependency-free `mrml-rustc` core is the first exact multi-output native
action. Its two integration-test sources and self-extern requirement are explicit
and checked against the declared `:test` outputs. A bounded 32 MiB test-stack
policy is linked on Windows and applied to the Linux child process limit before
exec. Both hosts pass 420 inline, 10 conformance, and 335 nightly-replacement
tests. Thirteen components are native; 29 remain transitional.

Native example outputs are now explicit and checked against every declared
`:example` output. `mrml-opus` directly builds its library, runs 179 inline
tests, and links all three examples on Windows and Arch Linux WSL2. The Linux
C-reference differential example requires the distribution's `opus` package;
the first run failed closed when `-lopus` was absent and passed after the explicit
test dependency was installed. Fourteen components are native; 28 remain
transitional.

Native actions now bind one exact feature set and may gate an extern by both
target family and selected feature. `mrml-av1` declares the empty default set,
so its `nvidia` platform extern is inactive while `mrml-runtime` remains active.
The library and `decode_ivf` example build directly on Windows and Arch Linux
WSL2. A 32 MiB executable-stack policy eliminates sixteen Windows harness
overflows; both native hosts match the pinned Cargo baseline's two remaining
source failures (273 passed, 2 failed). Fifteen components are native; 27 remain
transitional.

`mrml-crypto` records its resolved default set as `runtime`; that selected gate
activates the exact `mrml_runtime` extern on both supported hosts. Windows and
Arch Linux WSL2 each pass all 27 direct cryptography tests. Sixteen components
are native; 26 remain transitional.

`mrml-tls` directly consumes the native crypto and runtime rlibs. Windows and
Arch Linux WSL2 each pass all 11 inline tests; configured live-peer and external
certificate-fixture paths were not supplied. Seventeen components are native;
25 remain transitional.

`mrml-http` directly binds the native runtime and TLS rlibs. Windows and Arch
Linux WSL2 each pass all three inline tests; the environment-selected live URL
and range probes were not supplied. Eighteen components are native; 24 remain
transitional.

`mrml-ssh` directly binds the native crypto and runtime rlibs. Windows and Arch
Linux WSL2 each pass all 23 inline tests, including loopback transport; no live
remote or external signing operation was supplied. Nineteen components are
native; 23 remain transitional.

Native actions now declare exact binary output names, crate names, source roots,
self-library bindings, binary test harnesses, and compile-time environment
values. `mrml-git` builds its library and executable on Windows and Arch Linux
WSL2 and passes 51 library tests plus one binary test on each. No live remote
operation was exercised. Twenty components are native; 22 remain transitional.

Patent review: `TRIGGERED`. This increment implements the first native dependency
resolver, within the package/cache/resolver review already recorded in
[`../patents/REVIEW_LOG.md`](../patents/REVIEW_LOG.md).
