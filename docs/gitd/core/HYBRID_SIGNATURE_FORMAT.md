# MRML-GIT-HYBRID-V1

Status: **PLANNED**. The existing nested signature format is not this profile.

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

