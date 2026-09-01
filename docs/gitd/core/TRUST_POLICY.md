# Gitd trust policy

Status: **PARTIALLY IMPLEMENTED**.

The versioned policy must bind repository identity, monotonic generation,
previous-policy digest, protected refs, allowed object formats, required
signature profile, legacy checkpoint, hybrid cutover, complete active/retired/
revoked key identities, exact OpenPGP/ML-DSA pair bindings, validity intervals,
revocation generation, and emergency recovery policy.

`TrustPolicyState` now provides a bounded, canonical in-memory policy core. It
binds repository identity, monotonic generation, previous-policy SHA3-512
digest, protected full refs, allowed object formats, hybrid-required state,
exact active key pairs, complete revoked OpenPGP fingerprints, complete revoked
ML-DSA public-key digests, and a revocation generation. Lists are bounded and
must be strictly ordered, so duplicate or alternate-order encodings cannot
produce competing canonical policy digests.

Repository policy may narrow an externally pinned owner trust root but cannot
broaden it: an update cannot add an object format or remove an already
protected ref. Normal rotation requires `KeyRotation` verification typestates
from both a currently active hybrid pair at the old generation and a proposed
active pair at the new generation. A transition cannot lower a generation,
break the previous-policy digest chain, remove a revocation, reactivate a
revoked key, or downgrade hybrid-required policy.

The persisted policy encoding/parser, explicit retired-key validity intervals,
legacy checkpoint and hybrid-cutover object IDs, authenticated emergency
recovery policy, and canonical key-revocation statement are not yet
implemented. The current state therefore cannot activate protected refs.

`verify_introduced_history` now deterministically walks every commit introduced
by `old..new`, including all merge-side parents, in parent-before-child order.
It excludes only the authenticated old history, requires the exact old commit
to be reached for fast-forward acceptance, bounds both existing and introduced
walks (5,000 introduced commits by default), bounds parents per commit, rejects
mixed object formats, missing objects, cycles, and verifier failure, and returns
a private-field `VerifiedCommitRange`. Tests prove that an invalid merge-side
intermediate cannot hide beneath an otherwise accepted tip.

The range typestate is not yet wired into an atomic `VerifiedRefTransaction`,
and the policy parser remains open, so protected ref activation remains
unavailable.
