# Git backup stream

Status: **PARTIALLY IMPLEMENTED**. The bounded authenticated-encryption framing
primitive and hostile frame tests are implemented. Canonical inventory records,
the stopped one-shot backup/restore service, named-volume Compose wiring, and a
destructive disposable-namespace restore test remain acceptance gates.

## Security boundary

A Git backup key is a distinct 32-byte nonzero secret capability. It is not a
receipt key, token pepper, authority channel key, protected signer key, image
signing key, environment variable, or image content. The one-shot service will
receive it through a read-only secret volume and erase derived key material.
Possession authorizes backup sealing/opening only; it does not authorize Git
refs, policy transitions, candidate completion, or deployment activation.

The stream starts with a fixed 44-byte `MRGBKP01` header containing:

- format version 1;
- nonzero backup generation;
- a bounded nonzero plaintext chunk size, at most 1 MiB;
- a random 128-bit salt; and
- a random nonzero 32-bit nonce prefix.

Reserved header bytes must be zero. A per-archive AES-128-GCM key is derived by
HMAC-SHA-256 from the backup key, a purpose-separated domain, and the complete
header. Each frame carries an exact monotonically expected 64-bit sequence,
plaintext length, final flag, and zero reserved bytes. The 96-bit GCM nonce is
the archive nonce prefix followed by that sequence. The complete stream header
and frame header are additional authenticated data.

Nonterminal frames contain 1 through the declared chunk-size bytes. The sole
terminal frame contains zero plaintext and has the final flag set. It is still
authenticated. Readers reject the wrong key, header substitution, duplicate or
reordered sequences, unknown flags, nonzero reserved fields, oversized frames,
noncanonical final frames, tag changes, and truncation. Authentication failure
clears the affected plaintext output.

This framing alone is not a backup. The subsequent inventory layer must bind
all required logical named volumes, canonical ordered paths, types, modes,
owners, sizes, content digests, repository generations, authority generations,
and the excluded disposable cache. Restore must authenticate the complete
stream before publishing any target namespace and must reject missing, extra,
duplicated, reordered, stale, or corrupt records.

Patent review: **NOT_TRIGGERED**. This increment composes standardized
AES-GCM, HMAC-SHA-256 key derivation, explicit sequence numbers, bounded chunks,
and authenticated EOF in a conventional encrypted-record stream. It introduces
no substantial new mechanism. See
[`docs/patents/REVIEW_LOG.md`](../../patents/REVIEW_LOG.md).
