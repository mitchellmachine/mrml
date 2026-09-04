# Trust-transition verifier retention — 2026-09-04

Status: **PARTIALLY IMPLEMENTED** and verified in focused Linux tests. These
increments close the authority restart gap between policy selection and public
verifier availability and add an authenticated signer trust-generation handoff.
They do not complete the required containerized old-signer/overlap/new-signer
lifecycle.

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

The deployment input contract carries the exact previous public pair for every
transition. The networkless transition process does not substitute the
authority bootstrap files for that pair. This is required for normal
generation 2-to-3 retirement and every later rotation after the bootstrap pair
ceases to be active. Both supplied pairs remain public, immutable,
owner-checked transition inputs; neither grants authority without matching
policy status and hybrid signatures.

## Verification

```text
cargo fmt --all -- --check                                PASS
cargo clippy --all-targets -- -D warnings                 PASS
git diff --check                                          PASS
./target/debug/mrml test org.mrml.service.git-authority \
  --target linux                                          PASS
  authority library: 13 passed
  authority binary:   8 passed
./target/debug/mrml test org.mrml.tool.git --target linux PASS
  Git library:        274 passed
  Git CLI:            5 passed
  protected signer:   9 passed
  credential agent:   2 passed
```

The binary test uses two independent real OpenPGP/ML-DSA pairs and real hybrid
key-rotation signatures. It selects overlap policy generation 2, verifies the
generation-2 public files and their filesystem invariants, selects retirement
policy generation 3, proves the old pair is rejected, and proves restart
selection resolves the exact generation-3 next pair even though the configured
bootstrap pair remains old. A separate test preinstalls generation-2 material,
attempts a same-generation substitution, observes failure, and verifies the
retained bytes did not change.

Signed functional commit `61d39118` adds a pure normal-successor verifier and
the signer's cold `advance-trust` operation. The operation reads the actual
already selected policy from the policy volume, verifies exact ownership and
canonical encoding, verifies both real hybrid transition authorizations, binds
the current private signer material to the previous active pair, and atomically
updates only trust and revocation fields in the checksummed state. Its test uses
two independent real hybrid pairs, preserves repository generation 7, advances
trust 1 to 2, reopens the result, and rejects replay.

Signed deployment commits `bbe9d3d3` and `8bb2bf07` add the networkless,
read-only-root, capability-dropped signer admin profile and sequence it after
authority selection. All three daemons must be stopped. The transition input
set now contains the exact previous policy. Inputs are removed only after signer
state reopens; `--resume-signer` safely resumes an interruption after selection.
Both static Compose tests, shell syntax checks, and the combined
Git/ACME/signer admin Podman Compose render passed.

This is unit/integration test evidence, not a controlled container lifecycle.
Remaining Phase 24 gates include generation-bound policy construction tooling,
candidate-signer volume selection/handoff, pushes during overlap and after
retirement, explicit old-signer rejection, rollback rejection after daemon
restarts, and process-kill injection around every transition phase.

Patent review: **NOT_TRIGGERED**. This uses conventional immutable public-key
files, exact metadata/content validation, directory capabilities, and ordered
filesystem synchronization; it introduces no cryptographic algorithm or novel
key-rotation construction. See
[`docs/patents/REVIEW_LOG.md`](../../patents/REVIEW_LOG.md).
