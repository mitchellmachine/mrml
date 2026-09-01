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

Patent review: **NOT_TRIGGERED**. This is conventional authenticated local RPC
composition and replay sequencing. See `docs/patents/REVIEW_LOG.md`.
