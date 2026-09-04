# Trust-transition verifier retention — 2026-09-04

Status: **PARTIALLY IMPLEMENTED** and verified in focused Linux tests. This
increment closes the authority restart gap between policy selection and public
verifier availability. It does not complete the required containerized
old-signer/overlap/new-signer lifecycle or signer trust-generation handoff.

## Implementation

Signed functional commit `d31ef509` changes the normal `transition-policy`
operation so it durably installs the next OpenPGP-v6 and ML-DSA-65 public pair
before selecting the next trust policy. Files are retained beneath the exact
repository policy capability as:

```text
verification-keys/trust-GENERATION.openpgp.asc
verification-keys/trust-GENERATION.ml-dsa.bin
```

Creation is exclusive. Existing files must match the exact expected owner,
group, mode `0444`, one-link identity, length, and content. Each new file and
the keyring directory are synchronized before policy transition. A crash before
policy selection can therefore leave only inactive public material; a selected
policy never depends on transition-upload files that the wrapper subsequently
removes.

Authority startup retains one descriptor-relative policy-directory capability.
It uses the configured bootstrap pair only while the exact current policy
authorizes that pair at trusted validation time. If the bootstrap pair is no
longer active, startup opens only the exact current trust generation's retained
files beneath that capability, parses both keys, binds their complete hybrid
identity, and rechecks policy authorization. Missing, stale-generation,
substituted, malformed, wrongly owned, writable, linked, or inactive keys fail
closed.

## Verification

```text
cargo fmt --all -- --check                                PASS
cargo clippy --all-targets -- -D warnings                 PASS
git diff --check                                          PASS
./target/debug/mrml test org.mrml.service.git-authority \
  --target linux                                          PASS
  authority library: 13 passed
  authority binary:   8 passed
```

The binary test uses two independent real OpenPGP/ML-DSA pairs and real hybrid
key-rotation signatures. It selects overlap policy generation 2, verifies the
generation-2 public files and their filesystem invariants, selects retirement
policy generation 3, proves the old pair is rejected, and proves restart
selection resolves the exact generation-3 next pair even though the configured
bootstrap pair remains old. A separate test preinstalls generation-2 material,
attempts a same-generation substitution, observes failure, and verifies the
retained bytes did not change.

This is unit/integration test evidence, not a controlled container lifecycle.
Remaining Phase 24 gates include generation-bound policy construction tooling,
authenticated signer trust-generation handoff, pushes during overlap and after
retirement, explicit old-signer rejection, rollback rejection after daemon
restarts, and process-kill injection around every transition phase.

Patent review: **NOT_TRIGGERED**. This uses conventional immutable public-key
files, exact metadata/content validation, directory capabilities, and ordered
filesystem synchronization; it introduces no cryptographic algorithm or novel
key-rotation construction. See
[`docs/patents/REVIEW_LOG.md`](../../patents/REVIEW_LOG.md).
