# Gitd production configuration

Status: **PARTIALLY IMPLEMENTED**. The strict version-1 parser, secure hosted
loader, storage-layout validation, and authority health client are implemented.
Listener, certd, recovery, and repository catalog startup stages remain to be
composed into the executable.

Gitd accepts a bounded ASCII `key=value` configuration with an explicit
`version=1`. Every security-sensitive field is required exactly once. Unknown
fields, duplicates, whitespace aliases, noncanonical numbers, zero identities,
relative or dot-component paths, invalid DNS names, out-of-range resource
limits, and overlapping authoritative/cache roots fail startup.

The configuration identifies separate repository, state, quarantine, cache,
receipt, and policy roots; an exact repository catalog and protection-profile
catalog directly under the policy root; authenticated token records directly
under the state root; a token-verifier pepper restricted to `/run/secrets`;
authority and certd sockets and capability files; the Gitd, authority, and certd
numeric identities; nonzero persisted next authority and certd request
identifiers; connection/upload/receive/body limits; one unprivileged shared
TCP/UDP port; and a bounded drain interval. Paths identify deployment objects
but do not grant authority. Startup must subsequently open and validate each as
the appropriate capability before admitting traffic.

The hosted loader opens an absolute config path with `O_NOFOLLOW`, requires one
bounded regular file owned by root or the configured Gitd UID, and rejects
group/world-writable modes. The native `mrml-gitd validate-config CONFIG`
command also validates every authoritative storage path before reporting
success: each path component must be a directory rather than a symlink, unsafe
writable parents are rejected, leaf ownership must exactly match the configured
Gitd UID/GID, and writable roots must have owner write authority without
group/world write. The policy root may be owner-read-only. This command does not
report service readiness; authority and certd authentication remain later
startup gates.

`deploy/compose/gitd.example.conf` is a non-secret template. Production
provisioning must install a completed copy as a root- or Gitd-owned,
non-group/world-writable regular file; the template itself is never a runtime
credential or an authorization record.

`mrml-gitd dependencies-health CONFIG SIGNER_IDENTITY_HEX` composes these
startup gates without binding a listener. It validates configuration and
storage, securely loads the two separately owned 32-byte capability files,
erases transient key copies, and authenticates exact health responses from both
authority and certd using independent configured request sequences. Failure of
either dependency yields no partial-ready result.

The default production identities remain Gitd `21001:21001`, authority
`21002:21002`, and certd `21003:21003`. The parser permits explicit deployment
values so host provisioning can allocate equivalents, while zero/root identity
is always rejected.

Patent review: **NOT_TRIGGERED**. Strict configuration parsing and bounded
numeric/path validation are conventional defensive mechanisms. See
`docs/patents/REVIEW_LOG.md`.
