# MRML-GIT-HYBRID-V1

Status: **PARTIALLY IMPLEMENTED**. The canonical transcript and exact-pair AND
verifier are implemented in `trust_policy.rs`; the existing nested commit
format is not this profile and does not satisfy it. The OpenPGP library parses
the exact RFC 9580 v6 Ed25519
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

Both signatures cover this byte-exact canonical transcript. Integers are
unsigned big-endian and text is exact ASCII already validated by its typed
constructor:

```text
"MRML-GIT-HYBRID-V1" 00
purpose:u8
repository_length:u16 repository:bytes
object_format:u8 object_type:u8
trust_generation:u64
openpgp_v6_fingerprint:32
sha3_512(canonical_openpgp_primary_key_body):64
sha3_512(ml_dsa_65_public_key):64
payload_length:u64 payload:bytes
```

Purpose codes 1 through 7 respectively identify `GitCommit`,
`GitAnnotatedTag`, `SourceManifest`, `SourceLock`, `BuildReceipt`,
`KeyRotation`, and `KeyRevocation`. Object-type codes use the same ordering.
Object-format 1 is SHA-1 compatibility and 2 is SHA-256. A purpose/object-type
mismatch is rejected before cryptographic verification. The canonical OpenPGP
primary-key body is version 6, creation time, algorithm 27, four-byte key
material length 32, and the exact Ed25519 public bytes. Its SHA3-512 value is an
MRML public-key digest, never an OpenPGP fingerprint.

The transcript therefore binds:

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

The zero-identity golden transcript for `owner/repository`, SHA-256 commit,
generation 4, and payload `payload` is 223 bytes and has SHA3-512 digest
`99acd226d5b49f391265c3143c2c9f7df4a113a4dde77e234dd5d96932826d71017e02e8fd170ff18aee338b2939d1b6d30eb8c2dce80c6ab339bff4ef7a1b48`.

The verifier independently recomputes both public-key digests, requires the
exact authorized pair, checks exact trust and revocation generations, verifies
the salted OpenPGP v6 signature, then verifies ML-DSA-65. Its success typestate
has private fields. Canonical generational policy parsing, normal two-pair
rotation constraints, and complete introduced-history range verification are
implemented. Canonical revocation/emergency execution, independent
interoperability evidence, and final FIPS 204 ML-DSA-65 evidence remain open,
so the status cannot be promoted.

ML-DSA-65 signing reconstructs the public key from decoded secret polynomials,
checks the stored public-key transcript hash, and verifies every generated
signature before returning it. The caller's signature buffer is
volatile-zeroed before work and on every error path; decoded long-lived secret
arrays are volatile-zeroed before return. This is source-level output-hygiene
evidence only. Matrix, eta, and challenge rejection sampling uses finite
buffers and now fails with a classified `SamplingLimit` error if those buffers
cannot produce the required coefficients; no release-build debug assertion or
unchecked challenge cursor is a correctness dependency. Key generation clears
caller outputs before work and volatile-zeroes its expanded seed and temporary
polynomial state on success and classified sampler failure. Tests cover the
255-byte context boundary, fail-closed 256-byte rejection with cleared output,
and noncanonical hint ordering. Official final FIPS 204/correction vectors, a
complete rejected-attempt intermediate-zeroization review, timing evidence,
and independent cryptographic review remain open.

The test-only independent oracle is OpenSSL 3.6.4, built 2026-08-25, default
provider `ML-DSA-65`. The pinned differential case uses key-generation seed
`000102...1f`, per-signature test entropy `202122...3f`, context
`mrml-oracle`, and message `MRML ML-DSA oracle message`. OpenSSL verifies its
signature, while the environment-gated MRML test requires byte-exact agreement
for the 1952-byte public key, 4032-byte private key, and 3309-byte signature and
then verifies the OpenSSL signature independently. Fixture SHA-256 digests are:

- public key: `d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9`;
- private key: `9f1e24f47795fe50040384e3d6183988047170fa2d866406b70fe0a3f8216063`;
- signature: `74e9f990ff6705244aec107745630ea37b308d0f8172329bb34382e6efc6d710`;
- message: `446d923689f069cdc13682c7414e211b85bda1cba245a3c363adace52d4316c7`.

This is a pinned hosted-Linux differential probe, not an official NIST ACVP
vector, validation certificate, constant-time result, or independent audit.
