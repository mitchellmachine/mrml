# MRML-GIT-HYBRID-V1

Status: **PARTIALLY IMPLEMENTED**. The existing nested signature format is not
this profile. The OpenPGP library now parses the exact RFC 9580 v6 Ed25519
primary-key packet shape and computes the full 32-byte SHA-256 fingerprint,
with the RFC Appendix A certificate as a byte-exact vector. V6 detached
signing and verification now use algorithm-sized salts before all other hash
input, four-byte subpacket lengths, complete v6 issuer fingerprints, and native
64-byte Ed25519 signatures. Focused regressions distinguish correct,
omitted/wrong-sized, and payload-before-salt hashing. Independent detached-v6
interoperability evidence and SHA3-512 interface support remain open.

Protected history will require an AND decision over an authorized OpenPGP v6
Ed25519 signature, an authorized ML-DSA-65 signature, and an authorized binding
between those exact full public-key identities. Conventional-only signatures
must not satisfy hybrid-required policy.

The future canonical signed transcript must length-prefix and domain-separate:

- profile version and one of `GitCommit`, `GitAnnotatedTag`, `SourceManifest`,
  `SourceLock`, `BuildReceipt`, `KeyRotation`, or `KeyRevocation`;
- canonical repository identity, Git object format and object type;
- trust-policy generation;
- complete RFC 9580 OpenPGP fingerprint;
- MRML digest of the canonical OpenPGP public key;
- MRML digest of the canonical ML-DSA public key; and
- canonical payload length and exact payload bytes.

Unknown critical fields, duplicates, reordering, alternate line endings,
invalid continuation/base64 data, trailing data, algorithm or digest
substitution, and all context mismatches must fail closed.

No byte encoding or test vector is declared normative here yet. RFC 9580 v6
fingerprints/salts and final FIPS 204 ML-DSA-65 require exact positive,
negative, official, and independent-oracle evidence before this status can be
promoted.
