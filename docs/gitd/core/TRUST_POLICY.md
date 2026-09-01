# Gitd trust policy

Status: **PLANNED**.

The versioned policy must bind repository identity, monotonic generation,
previous-policy digest, protected refs, allowed object formats, required
signature profile, legacy checkpoint, hybrid cutover, complete active/retired/
revoked key identities, exact OpenPGP/ML-DSA pair bindings, validity intervals,
revocation generation, and emergency recovery policy.

Repository policy may narrow an externally pinned owner trust root but cannot
broaden it. Normal rotation requires authorization by both the previous trusted
hybrid pair and proposed pair. A transition cannot lower a generation, remove a
revocation, reactivate a revoked key, or downgrade hybrid-required policy.

Every commit introduced by `old..new`, including merge side ancestry, must be
verified deterministically. A valid tip cannot hide an invalid intermediate
commit. Until this range verifier and policy parser exist, protected ref
activation remains unavailable.

