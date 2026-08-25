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
42 external-command source sites
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
flags, and lock/digest inputs exact enough for direct rustc. Cargo must then be
confined to clean-source stage-zero bootstrap only after Windows/Linux build
equivalence is demonstrated. Treat input-policy changes as explicit review items,
never automatically accepted count updates.

Patent review: `TRIGGERED`. This increment implements the first native dependency
resolver, within the package/cache/resolver review already recorded in
[`../patents/REVIEW_LOG.md`](../patents/REVIEW_LOG.md).
