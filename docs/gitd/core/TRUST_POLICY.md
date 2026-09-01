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

The first-party persisted `MRMLGTP3` encoding/parser is implemented and capped
at 512 KiB. It uses fixed-width big-endian generations and counts, two-byte
length-prefixed validated repository/ref identifiers, explicit format and
hybrid flags, complete 32-byte OpenPGP v6 fingerprints, 64-byte MRML OpenPGP
key digests, and 64-byte ML-DSA key digests. The parser checks every addition
and slice boundary before access or allocation, caps all collection counts,
reuses typed identifier validation, rejects unknown flag bits and non-Boolean
values, requires strict collection order, rejects trailing bytes, and
byte-for-byte re-encodes the result before acceptance. Every truncation of the
golden policy fixture fails closed.

`MRMLGTP3` adds a bounded, strictly full-fingerprint-ordered legacy OpenPGP v4
ledger. Each `LegacyV4KeyStatus` records the complete 20-byte fingerprint, an
inclusive `valid_from`, exclusive `valid_until`, and optional retirement time;
no short key ID is encoded or compared. A separate strictly ordered complete
v4 revocation list is bound into both the canonical bytes and V3 policy digest.
Legacy statuses must be nonempty exactly when a legacy checkpoint exists, and
legacy revocations cannot exist without that checkpoint. Lookup at a caller-
supplied trusted time rejects absent, expired, retired, or revoked identities.

Normal transitions cannot remove a legacy status, move its start, widen its
end, reverse or delay retirement, remove a revocation, or reactivate a revoked
identity. Adding a legacy revocation requires a strictly newer revocation
generation. Focused tests cover V3 byte-for-byte re-encoding, every truncation,
alternate ordering, full-fingerprint suffix collisions, expiry, retirement,
revocation, and transition narrowing. This is only the canonical schema
prerequisite: it does not classify commit ancestry or activate a v4-signed
protected history. Such activation remains fail closed pending an authenticated
graph proof for the exact legacy checkpoint and hybrid cutover.

Each exact OpenPGP/ML-DSA pair also has one canonical `PolicyPairStatus` with
an inclusive `valid_from`, exclusive `valid_until`, and optional `retired_at`.
Statuses are strictly ordered by the complete pair identity. The active-pair
list must exactly equal the ordered non-retired status subset; retired records
remain present for bounded historical verification. `pair_authorized_at`
accepts only times in the half-open validity interval and, after retirement,
only times strictly before the retirement instant.
`active_verification_policy_at` is the fail-closed bridge from that canonical
ledger to cryptographic verification: it requires the complete pair to be in
the active subset, unrevoked, and authorized at the trusted validation time,
then binds the exact trust/revocation generations and effective exclusive end
to the `HybridTrustPolicy`. Merely retaining a retired identity for historical
description cannot mint current signing authority.

Normal transitions cannot remove an existing status, move its start, widen its
end, undo retirement, or delay a recorded retirement. They may narrow the end
or retire an active pair earlier. This makes expiry and retirement monotonic
restrictions on authority rather than mutable descriptive metadata.

Key revocation is a separate purpose-bound transition, not policy rotation or
emergency recovery. The canonical `MRGREV01` statement is capped at 64 KiB and
binds repository identity, exact previous and strictly greater next revocation
generations, nonzero effective time, a bounded printable reason, and strictly
ordered complete OpenPGP v6 fingerprints and ML-DSA public-key digests. Empty
identity sets, duplicates, alternate ordering, malformed text, truncation, and
trailing bytes fail closed. Its SHA3-512 digest covers the complete canonical
encoding.

Application requires a `VerifiedHybridSignature` over those exact bytes with
the `KeyRevocation` purpose and object type, current trust and revocation
generations, the exact repository, and a currently time-authorized active pair.
It only unions new revocations. Affected pair-status identities remain recorded
and are retired no later than the statement's effective time; earlier expiry or
retirement is preserved. Revocations cannot disappear, reactivate a pair, or
be replayed as a generation transition. Revoking every active pair fails closed;
emergency recovery remains a distinct future authority path.

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

Authenticated emergency recovery execution is not yet implemented. The current
state therefore cannot activate protected refs through that transition path.

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
