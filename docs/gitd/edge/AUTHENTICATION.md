# Gitd authentication and repository profiles

The transport-neutral Gitd edge implements keyed Bearer-token verification
before repository generation lookup or receive-body consumption. Tokens contain
256 random bits and are displayed once. The server retains only a purpose-bound
HMAC verifier plus an authenticated metadata record; token plaintext is not part
of `TokenRecord`, its `Debug` output, or error output.

Each authenticated record binds the exact repository, read/write/administration
scope bits, activation time, expiry, revocation generation, bounded
authority-neutral label, and token verifier. A separate record MAC detects scope,
repository, time, generation, label, or verifier substitution. Verification
compares tags without data-dependent early exit. Duplicate Authorization headers,
unknown schemes, malformed/noncanonical tokens, duplicate matching records,
wrong-repository tokens, missing scope, expiry, and stale revocation generations
all fail with the same denial.

Repository profiles are deployment-owned:

- `PublicRead` permits anonymous reads but still requires an authorized token for
  writes and administration.
- `Private` requires authorization for every action.
- `Protected` requires authorization for every action and does not itself bypass
  protected-history or receive-authority checks.

The Smart Git path maps discovery/upload-pack to read and receive-pack to write.
It authenticates before invoking `repository_generation` or the streaming
backend, so an unauthorized receive consumes no body and creates no quarantine
state. Missing authentication configuration fails closed.

Durable authenticated token-record storage, one-shot administration commands,
and deployment configuration loading remain daemon responsibilities and are not
claimed by this module.

Patent review: **NOT_TRIGGERED**. This is conventional random bearer-token,
keyed-verifier, authenticated-record, scope, expiry, and revocation handling; no
new cryptographic primitive or protocol mechanism is introduced. See
[`docs/patents/REVIEW_LOG.md`](../../patents/REVIEW_LOG.md).
