# Gitd authority client

Status: **PARTIALLY IMPLEMENTED**. The production Unix client and native health
command are implemented; the full Gitd daemon configuration and receive route
composition remain in progress.

`GitAuthorityChannelClient` is the concrete transport for
`RemoteProtectedReceiveAuthority`. It opens one bounded Unix session per
operation, validates the authority's Linux peer credentials, authenticates the
entire response frame with the purpose-limited channel capability, and requires
the exact operation and request identifier it sent. Nonzero service status,
unknown operations, response substitution, payload overflow, I/O failure, and
request-counter exhaustion fail closed.

Request identifiers advance across calls and never wrap. Production
configuration must restore the next identifier from authenticated Gitd state;
the authority maintains its replay window across accepted connections. A Gitd
restart must therefore continue with a value greater than the last committed
request rather than resetting to one.

The `mrml-gitd authority-health` command uses the same authenticated channel and
is suitable for a container health check without a shell or HTTP client. It
loads the channel capability with `O_NOFOLLOW`, checks single-link regular-file
type, exact 32-byte size, expected owner, and mode `0400`, `0440`, or `0600`,
then erases temporary key buffers. The receipt signer identity is an explicit
nonzero 64-byte pin.

Receipt authentication uses a purpose-separated Ed25519 signature. The
authority retains the 32-byte private seed and exposes only the public verifier
through the bounded `describe-receipt-verifier` administrative command. This
permits clients and the protected signer to verify durable activation receipts
without receiving symmetric receipt-forging authority. The authenticated
receipt container and its canonical transcript parser are shared library
interfaces; a checksum alone is never treated as authority.

Repository generation is no longer accepted as mutable process-local state.
Production startup opens an owner-only durable generation catalog in the
authority state volume and holds an exclusive advisory lock for the daemon
lifetime. Each record binds the canonical repository identity, current nonzero
generation, format version, and checksum under a purpose-separated domain. The
bootstrap generation is only a creation value and rollback floor; reopening a
newer durable value does not reset it.

Receipt signing first parses the nested canonical audit-receipt transcript and
requires the authority's exact repository, current generation, next generation,
trust generation, and revocation generation. The signature is not returned
until the catalog has atomically replaced, directory-synced, and reopened the
exact next generation. Replays, skips, and rollback attempts fail closed. The
current process still loads one repository's policy and proof directories at
startup; a complete dynamic multi-repository catalog and candidate transaction
state remain required before production-candidate classification.

The authority library now has a durable candidate journal foundation. Every
record binds a nonzero 128-bit candidate identifier to the exact repository,
current and next repository generations, trust and revocation generations,
policy digest, ref-update digest, introduced-commit-set digest, arrival-pack
digest, proof-set digest, and activation digest. Candidate state advances only
through the ordered `receiving`, `proofs-sealed`, `authorized`,
`activation-started`, `activated`, `receipt-persisted`, and `completed` states;
an abort is accepted only before durable activation. Records are owner-only,
checksum-bound, atomically replaced, directory-synced, and re-read after every
transition. Reusing an identifier with another repository or context fails
closed, and exact repeated operations are idempotent.

This journal is not yet connected to the authority RPC operations or proof
directory, so candidate-local proof visibility, activation-evidence validation,
and recovery-driven receipt finalization remain required. Until that wiring and
its failure-path tests exist, protected receive is not candidate-transactional.

Patent review: **NOT_TRIGGERED**. This is conventional authenticated local RPC
composition and replay sequencing. See `docs/patents/REVIEW_LOG.md`.
