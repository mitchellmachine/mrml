# Git authority channel

Status: **PARTIALLY IMPLEMENTED**. The authenticated Unix transport, native
health exchange, exact policy/ref authorization, detached hybrid proof
verification, and purpose-separated receipt authentication are implemented.
Gitd's client adapter and multi-repository production configuration remain to
be composed.

`mrml-git-authority` owns a version-1, length-prefixed Unix-domain channel. Each
frame is bounded to 64 KiB, contains an exact operation and monotonically
nonzero request identifier, authenticates the complete SHA-256 payload digest,
and carries an HMAC-SHA-256 tag under a purpose-limited 256-bit channel
capability. Unknown versions, operations, frame kinds, malformed lengths,
payload changes, zero capabilities, peer substitutions, and replay within a
session fail closed.

The listener validates Linux peer credentials before reading a frame. Socket
paths must be absolute, may not contain `.` or `..`, and every existing parent
is rechecked as a real directory rather than a symlink. An existing socket path
is never replaced. Reads and writes have two-second deadlines.

The hosted executable provides both the long-running `serve` operation and a
native `healthcheck`; it does not need a shell or HTTP client. The capability
file is opened with `O_NOFOLLOW`, must be a single-link regular file of exactly
32 bytes, and must have mode `0400`, `0440`, or `0600`. Capability bytes are
erased after transfer into the redacted, non-cloneable channel type and again
when that type is dropped.

The daemon rereads the canonical policy for each operation. It binds receive
and ref approval to the repository and exact repository, trust, revocation, and
policy generations; only explicitly protected, non-delete ref updates are
accepted. Commit verification loads the exact-context detached record and
checks both OpenPGP v6 and ML-DSA evidence under the active, time-bounded pair.
Legacy proof verification remains unavailable. Receipt signing is an isolated
HMAC operation with a dedicated key and domain; verify is independently called
before the caller may complete activation. Startup refuses unavailable policy,
inactive keys, zero generations, malformed public keys, or insecure secret
files. This remains a fail-closed dependency gate rather than production
readiness until the Gitd adapter and deployment configuration are complete.

Patent review: **NOT_TRIGGERED**. This change uses conventional bounded Unix
socket framing, peer credentials, SHA-256, and HMAC authentication rather than
a new substantial mechanism. See `docs/patents/REVIEW_LOG.md`.
