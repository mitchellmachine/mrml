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

The first-party persisted `MRMLGTP1` encoding/parser is implemented and capped
at 512 KiB. It uses fixed-width big-endian generations and counts, two-byte
length-prefixed validated repository/ref identifiers, explicit format and
hybrid flags, complete 32-byte OpenPGP v6 fingerprints, 64-byte MRML OpenPGP
key digests, and 64-byte ML-DSA key digests. The parser checks every addition
and slice boundary before access or allocation, caps all collection counts,
reuses typed identifier validation, rejects unknown flag bits and non-Boolean
values, requires strict collection order, rejects trailing bytes, and
byte-for-byte re-encodes the result before acceptance. Every truncation of the
golden policy fixture fails closed.

The canonical state now also carries optional exact-format Git object IDs for
the final legacy checkpoint and hybrid-required cutover, plus an optional
64-byte digest naming a separately authenticated emergency-recovery policy.
Hybrid-required state is invalid without a cutover. Checkpoint and cutover IDs
must be nonzero and use an allowed repository object format. Once established,
normal rotation cannot move either checkpoint/cutover or replace the emergency
policy digest; those changes require a distinct future emergency-transition
typestate rather than piggybacking on daily-key rotation.

Repository policy may narrow an externally pinned owner trust root but cannot
broaden it: an update cannot add an object format or remove an already
protected ref. Normal rotation requires `KeyRotation` verification typestates
from both a currently active hybrid pair at the old generation and a proposed
active pair at the new generation. A transition cannot lower a generation,
break the previous-policy digest chain, remove a revocation, reactivate a
revoked key, or downgrade hybrid-required policy.

Explicit retired-key validity intervals, authenticated emergency recovery
execution, and canonical key-revocation statement are not yet
implemented. The current state therefore cannot activate protected refs.

`verify_introduced_history` now deterministically walks every commit introduced
by `old..new`, including all merge-side parents, in parent-before-child order.
It excludes only the authenticated old history, requires the exact old commit
to be reached for fast-forward acceptance, bounds both existing and introduced
walks (5,000 introduced commits by default), bounds parents per commit, rejects
mixed object formats, missing objects, cycles, and verifier failure, and returns
a private-field `VerifiedCommitRange`. Tests prove that an invalid merge-side
intermediate cannot hide beneath an otherwise accepted tip. Deterministic
functional tests execute exact linear introduced ranges of 1, 100, 1,000, and
5,000 commits and reject 5,001 at the default limit on Linux and the pinned
Wine-hosted Windows target. These cases establish bounded behavior at the
configured boundary; they are not production throughput, peak-memory, or
native-Windows evidence.

Protected-history admission now exposes only
`verify_protected_introduced_history`. Its verifier must return a private
`VerifiedCommitProof` for every newly introduced commit in deterministic
parent-before-child order, including every merge-side parent. The proof is
minted only by hashing the exact authenticated commit payload as a Git commit
object, requiring that hash to equal the requested commit ID, and binding the
successful hybrid verification to the exact repository identity, repository
generation, trust generation, revocation generation, `GitCommit` purpose, and
object format. A callback that
merely returns success cannot construct the proof.

`DetachedCommitProofStore` is the concrete bounded source for this path. It
accepts at most 5,000 strictly object-ID-ordered records, rejects duplicates,
bounds OpenPGP armor, and requires the exact ML-DSA-65 signature width. Stored
records remain untrusted data: `DetachedHybridCommitVerifier` authenticates
both signatures over the supplied exact commit contents and full context before
the Git object hash is bound and an opaque proof is returned. Missing,
substituted, malformed, oversized, or context-mismatched records fail closed.

The resulting private `VerifiedCommitRange` carries that same context into the
atomic `VerifiedRefTransaction` constructor. A range from another repository,
generation, purpose, format, or object ID is rejected. The unbound graph walker
is crate-private and retained only for internal/test graph fixtures; it is not a
public protected-ref authorization boundary. This proof path currently consumes
detached signatures over the exact commit contents. The installed-as-`git`
commit/tag path does not yet encode and self-verify the complete
`MRML-GIT-HYBRID-V1` result before its local ref update. Protected receive can
now consume a caller-provisioned bounded proof store through its verifier
boundary. Durable proof-record storage and its authorization policy remain open;
records gain no authority merely by being stored. End-to-end protected ref
activation therefore remains unavailable.
