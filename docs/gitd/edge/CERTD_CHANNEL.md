# Gitd certificate-service channel

Status: **PARTIALLY IMPLEMENTED**.

Gitd now has a concrete client for the shared certd version-1 Unix channel. It
connects with the exported bounded transport, authenticates the observed certd
peer and the claimed peer with the purpose-limited channel capability, enforces
the Gitd role's operation allowlist, binds every response to the exact operation
and monotonically increasing request identifier, and rejects sequence
exhaustion. Health succeeds only for the exact authenticated `ready` payload.

The Gitd client now also constructs a canonical hostname-bound identity request
and strictly decodes the bounded `MRGIDS01` snapshot payload. The response must
contain the exact requested lowercase DNS name, a nonzero identity generation,
one to eight bounded DER chain entries, a nonzero leaf-SPKI SHA-256 digest, an
ordered validity interval, one to eight strictly ordered nonzero signature
schemes, a nonzero publication digest, and the exact ready state, with no
trailing bytes. These fields are decoded data, not yet trusted identity:
independent certificate/chain/hostname/time/SPKI/signature validation and
monotonic publication are still required before listener use.

The CertificateVerify client operation is purpose-limited to the active
identity generation, TLS `ecdsa_secp256r1_sha256`, one exact 32-byte transcript
hash, and a nonzero logical request identifier in addition to the authenticated
channel sequence. Its response must repeat the generation, scheme, and logical
request and contain one bounded canonical ECDSA DER signature. Long-form,
negative, redundantly padded, oversized, truncated, substituted, or trailing
signature encodings fail closed. The client offers no generic signing method.

Generation notification is a bounded request containing the exact current
nonzero generation and a 1–30,000 ms wait. The authenticated response either
reports an unchanged generation as a timeout or a strictly greater generation
as a change. Zero, rollback, inconsistent state, and trailing bytes fail closed;
the notification itself does not publish identity material.

The current certd executable does not yet dispatch identity snapshot,
CertificateVerify, or generation-wait requests. Gitd therefore remains
non-ready and does not bind public listeners. There is no PEM, embedded-key,
self-signed, plaintext, or development-identity fallback.

The daemon's native dependency check composes certd health with authority
health only after configuration and storage validation. Authority and certd use
separate monotonic request counters and separately owned capability files; one
service's success cannot substitute for the other's failure.

Focused hosted Linux evidence:

- `./target/debug/mrml test org.mrml.service.gitd --target linux`: 15 tests
  passed, including real authenticated authority and certd Unix socket
  exchanges with kernel-observed peer credentials, plus exact snapshot parsing,
  hostname substitution, rollback-generation, trailing-byte, and canonical-name
  refusal, and generation/scheme/request/canonical-DER CertificateVerify
  response binding, plus distinct bounded timeout/change and rollback refusal
  for identity-generation waits.
- `./target/debug/mrml manifest lock --check`: 70 packages, 5 interfaces, 205
  compile edges, and 185 package edges passed after adding the explicit certd
  dependency.

Patent review: **NOT_TRIGGERED**. This increment composes the existing bounded
Unix-domain transport, peer credentials, HMAC authentication, role allowlist,
and monotonic request binding. See `docs/patents/REVIEW_LOG.md`.
