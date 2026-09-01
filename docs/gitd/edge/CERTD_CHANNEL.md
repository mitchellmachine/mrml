# Gitd certificate-service channel

Status: **PARTIALLY IMPLEMENTED**.

Gitd now has a concrete client for the shared certd version-1 Unix channel. It
connects with the exported bounded transport, authenticates the observed certd
peer and the claimed peer with the purpose-limited channel capability, enforces
the Gitd role's operation allowlist, binds every response to the exact operation
and monotonically increasing request identifier, and rejects sequence
exhaustion. Health succeeds only for the exact authenticated `ready` payload.

The current certd executable does not yet dispatch identity snapshot,
CertificateVerify, or generation-wait requests. Gitd therefore remains
non-ready and does not bind public listeners. There is no PEM, embedded-key,
self-signed, plaintext, or development-identity fallback.

Focused hosted Linux evidence:

- `./target/debug/mrml test org.mrml.service.gitd --target linux`: 6 tests
  passed, including real authenticated authority and certd Unix socket
  exchanges with kernel-observed peer credentials.
- `./target/debug/mrml manifest lock --check`: 70 packages, 5 interfaces, 205
  compile edges, and 185 package edges passed after adding the explicit certd
  dependency.

Patent review: **NOT_TRIGGERED**. This increment composes the existing bounded
Unix-domain transport, peer credentials, HMAC authentication, role allowlist,
and monotonic request binding. See `docs/patents/REVIEW_LOG.md`.
