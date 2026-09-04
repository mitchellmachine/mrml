# Git backup stream

Status: **PARTIALLY IMPLEMENTED**. The bounded authenticated-encryption framing,
canonical inventory/generation records, and hostile parser tests are
implemented. The stopped one-shot backup/restore service, named-volume Compose
wiring, and a destructive disposable-namespace restore test remain acceptance
gates.

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

The canonical inventory declares the complete fixed mask of ten authoritative
logical volumes; cache is deliberately absent. It binds a nonzero backup
generation, ordered unique repository identities, repository/pack/trust/
revocation generations, the matching authority generation when protected, and
up to 1,000,000 ordered unique filesystem entries. Each entry binds its logical
volume, bounded safe UTF-8 relative path, directory-or-regular-file type, mode,
UID, GID, size, and SHA-256 content digest. Directories have zero size and
digest. The inventory is limited to 64 MiB and ends in a digest that detects
internal corruption independently of the enclosing encrypted frames.

Protected authority generations are read with the same bounded `MRAGEN01`
codec used by the live authority store. The checksum domain, repository
identity, and nonzero generation therefore cannot drift between online writes
and offline inventory collection; a record for another repository is rejected.

Restore must still authenticate the complete stream before publishing any
target namespace and reject a runtime source/target that does not exact-match
the manifest. The service layer remains responsible for proving every declared
volume was mounted, generating the inventory from a cold consistent snapshot,
streaming file bytes, and ensuring no missing or extra entry exists.

Patent review: **NOT_TRIGGERED**. This increment composes standardized
AES-GCM, HMAC-SHA-256 key derivation, explicit sequence numbers, bounded chunks,
and authenticated EOF in a conventional encrypted-record stream. It introduces
no substantial new mechanism. See
[`docs/patents/REVIEW_LOG.md`](../../patents/REVIEW_LOG.md).
