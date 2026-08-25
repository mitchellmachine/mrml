# Cargo bridge inventory

**Status: IMPLEMENTED AUDIT / TRANSITIONAL BRIDGE.** The dependency-free `mrml`
frontend obtains Cargo's locked version-1 metadata, parses it with a bounded
repository-owned JSON parser, and verifies one-to-one package/name/manifest-path
coverage against `MRML.workspace`. Version 3 persists exact dependency, feature,
output, and per-component input-policy declarations. Cargo facts are compared
with locked metadata; input policies are compared with the bounded source scan;
and every local dependency must resolve to another declared MRML component.
Cargo metadata does not become MRML package identity or runtime authority.

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
64 Cargo targets
1 custom build target
0 procedural-macro targets
9 native-link source sites
31 compile-time environment source sites
1 included-file source site
43 external-command source sites
```

The structured output emits every Cargo package, dependency list, feature list,
target name/kind, and source-input location before its final summary. Source
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
cannot create another input. The Cargo metadata comparison covers declared
targets; the source scan identifies known direct sites. Both must pass before a
semantic path move or Cargo-removal step.

## Next gate

The first four leaves have moved: dependency-free `mrml-math` to
`packages/libraries/math`, and `mrml-percent-encoding` to
`packages/libraries/percent-encoding`, and `mrml-tokenizer` to
`packages/libraries/tokenizer`, and `mrml-zstd` to `packages/libraries/zstd`.
Their Cargo bridges remain. Extend moves one
dependency-light leaf at a time after checking every path reference and the v3
graph/audit. Do not remove Cargo bridge entries until Windows/Linux build
equivalence is demonstrated. Treat input-policy changes as explicit review items,
never automatically accepted count updates.

Patent review: `NOT_TRIGGERED`. This increment adds conventional bounded metadata
parsing, graph consistency checks, and lexical source inventory. It does not
implement the future cache, package, resolver, provenance, or publication
mechanisms already marked `TRIGGERED` in
[`../patents/REVIEW_LOG.md`](../patents/REVIEW_LOG.md).
