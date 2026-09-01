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
trailing bytes. Gitd then independently verifies the system-trusted chain,
server-auth purpose, exact hostname, current certificate validity, snapshot
validity interval, leaf SPKI digest, exact P-256/SHA-256 scheme policy, and
canonical publication digest. A previous published generation must be strictly
lower.

The CertificateVerify client operation is purpose-limited to the active
identity generation, TLS `ecdsa_secp256r1_sha256`, one exact 32-byte transcript
hash, and a nonzero logical request identifier in addition to the authenticated
channel sequence. Its response must repeat the generation, scheme, and logical
request and contain one bounded canonical ECDSA DER signature. Long-form,
negative, redundantly padded, oversized, truncated, substituted, or trailing
signature encodings fail closed. The client offers no generic signing method.

Before dependency readiness, Gitd derives a domain-separated test transcript
from the snapshot generation, publication digest, and hostname, requests the
purpose-limited CertificateVerify operation, and verifies the returned
canonical DER signature with the leaf certificate under the TLS library's fixed
TLS 1.3 server context. The TLS verifier itself constructs that context; neither
side gains a generic-message signing or verification shortcut.

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

- `./target/debug/mrml test org.mrml.service.gitd --target linux`: 16 tests
  passed, including real authenticated authority and certd Unix socket
  exchanges with kernel-observed peer credentials, plus exact snapshot parsing,
  hostname substitution, rollback-generation, trailing-byte, and canonical-name
  refusal, and generation/scheme/request/canonical-DER CertificateVerify
  response binding, plus distinct bounded timeout/change and rollback refusal
  for identity-generation waits.
- `./target/debug/mrml test org.mrml.library.tls --target linux`: 33 tests
  passed after adding the fixed-context leaf verification boundary. Optional
  externally configured certificate tests remain environment-dependent and are
  not claimed as exercised here.
- `./target/debug/mrml manifest lock --check`: 70 packages, 5 interfaces, 205
  compile edges, and 185 package edges passed after adding the explicit certd
  dependency.

Patent review: **NOT_TRIGGERED**. This increment composes the existing bounded
Unix-domain transport, peer credentials, HMAC authentication, role allowlist,
and monotonic request binding. See `docs/patents/REVIEW_LOG.md`.
