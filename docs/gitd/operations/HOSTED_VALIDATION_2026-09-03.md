# Git production-hardening evidence — 2026-09-03

This record is additive; it does not replace the 2026-09-02 evidence.

## Continuation baseline

- Commit: `f7d8d12cc0b586f58d9ad2d16aac2d1b676ceba34a6f2f42911bd8b8c66668e2`
- Branch: `main`
- Checkout: dirty with pre-existing HTTP and Gitd service edits plus untracked
  `Archive.zip`; those files were not staged or overwritten by this increment.
- VPS: Docker Engine 29.6.1/Compose 5.3.1 had no running or stopped containers.
  The stopped host retained 22 global named volumes and the `aba80e24` authority
  and Gitd images. Production configuration, keys, DNS, and certificates were
  incomplete, so no public service was started.
- Readiness remains **PARTIALLY IMPLEMENTED**, except for the narrow components
  explicitly classified **IMPLEMENTED** in their own documents. This baseline
  is not a production-readiness claim.

Baseline gates passed `git fsck --full --no-reflogs --no-dangling`, manifest
validation (71 components/214 dependencies), lock validation (71 packages/5
interfaces), `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D
warnings`, and `git diff --check`. Sequential native tests passed 492 tests: Git
228 library + 4 CLI + 4 signer, SSH 29, HTTP 75, TLS 34, crypto 54, OpenPGP 16,
and runtime 48. `mrml assurance check` retained the pre-existing failure for the
unadmitted unsafe boundary
`docs/compiler/probes/pinned_std_thread_tls_execution.rs`.

## Selected arrival-pack read correction

The baseline reproduced complete installed-pack validation and index parsing
inside every selected object read, preceded by a linear scan of manifest
entries. The corrected repository view installs an authenticated immutable
selected-generation snapshot and an ordered exact object locator. Full pack and
index authentication occurs on snapshot activation; unchanged-generation reads
perform indexed lookup plus an independent canonical Git object hash only.

The focused regression performs repeated selected-object reads and requires one
complete validation, one index parse, at least ten lookups, a hash for every
successful read, and nonzero byte accounting. It also modifies an extracted
selected object after snapshot activation and requires fail-closed object
validation. The Git test suite and production Gitd build passed:

```text
./target/debug/mrml test org.mrml.tool.git --target linux
  PASS: 229 library, 4 CLI, 4 protected-signer tests
./target/debug/mrml build org.mrml.service.gitd --target linux
  PASS
```

The exact 268,456,731-byte loopback container clone and before/after profile are
still pending for this increment. The prior measured baseline remains 8,133 s,
33,008 source bytes/s, Gitd peak cgroup memory 146,104,320 bytes, and one full
CPU. No improved throughput claim is made until the same fixture is rerun.

## Production full-buffer cache exclusion

The legacy cache remains available only to `cfg(test)` compatibility tests.
Production compilation removes its field, constructor, precomputation methods,
complete-object collection, complete-pack encoding, cache lookup/insertion, and
response-vector branch. The production request path unconditionally selects the
fixed-chunk `PackStreamEncoder` path. A regression asserts the exported
production capability constant is false, and the non-test Gitd build passes.

Patent review: **NOT_TRIGGERED**. The change uses a conventional authenticated
immutable-generation snapshot and ordered exact-key locator, while retaining
full content authentication. It introduces no cryptographic primitive,
compression/delta-selection method, similarity mechanism, or adaptive cache
policy. See `docs/patents/REVIEW_LOG.md`.

## Graph membership correction

Complete-history verification and upload-pack want/have traversal no longer use
repeated linear `Vector::contains` membership checks. A bounded, growable exact
object-ID set now deduplicates existing, visiting, verified, excluded, and
scheduled nodes with amortized constant-time lookup; deterministic result order
remains in separate vectors. Removal closes probe clusters, maximum cardinality
fails closed, and every key comparison still uses the complete SHA-1/SHA-256 ID.
The focused suite passes 233 library, 4 CLI, and 4 signer tests, including set
growth, duplicate insertion, deletion across displaced entries, and exact
linear parent-read/proof-check counts. Separate debug test-process timings on
this hosted Linux machine were 0.04 s for 1,000 nodes, 0.07 s for 2,000, and
0.14 s for 4,000. That is consistent with linear growth for the tested deep
history. Wide/criss-cross million-scale timing and independent peak-memory
measurements remain to be recorded; this increment therefore does not yet claim
completion of the full graph scaling acceptance gate.

## Delta dependency resolution

File-backed pack validation no longer makes repeated full passes over pending
deltas or linearly scans all resolved objects for each base. It uses the pack's
static ordered offsets, a bounded exact object-ID map, sorted reverse dependency
tables, and a ready queue. Dependency-edge insertion, lookup attempts, and
dependency releases are charged to the existing work budget. Missing or
unreleasable bases fail closed after the queue drains; OFS bases still require
an exact prior offset, REF bases are independently rehashed, maximum depth 50 is
unchanged, and duplicate resolved IDs are rejected.

Reverse-ordered REF chains at depths 10, 25, and 50 pass and assert exactly one
base load per delta. The complete focused result is 236 Git library, 4 CLI, and
4 signer tests. These small debug runs each rounded to 0.01 s in the shell timer;
larger wide-fanout scaling and peak-memory measurements remain pending.
