# Git authority channel

Status: **PARTIALLY IMPLEMENTED**. The authenticated Unix transport and native
health exchange are implemented; protected-policy, proof-verification, and
receipt operations are not yet connected to the daemon and therefore return an
unavailable status.

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

The current daemon answers only authenticated empty `Health` requests. Every
security-sensitive operation is explicitly unavailable until canonical policy
state and the corresponding exact-context handlers are composed. This is a
fail-closed dependency gate, not production readiness.

Patent review: **NOT_TRIGGERED**. This change uses conventional bounded Unix
socket framing, peer credentials, SHA-256, and HMAC authentication rather than
a new substantial mechanism. See `docs/patents/REVIEW_LOG.md`.
