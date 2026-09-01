# Gitd production configuration

Status: **PARTIALLY IMPLEMENTED**. The strict version-1 parser and authority
health client are implemented. Listener, certd, recovery, and repository
catalog startup stages remain to be composed into the executable.

Gitd accepts a bounded ASCII `key=value` configuration with an explicit
`version=1`. Every security-sensitive field is required exactly once. Unknown
fields, duplicates, whitespace aliases, noncanonical numbers, zero identities,
relative or dot-component paths, invalid DNS names, out-of-range resource
limits, and overlapping authoritative/cache roots fail startup.

The configuration identifies separate repository, state, quarantine, cache,
receipt, and policy roots; authority and certd sockets and capability files;
the Gitd, authority, and certd numeric identities; a nonzero persisted next
authority request identifier; connection/upload/receive/body limits; one
unprivileged shared TCP/UDP port; and a bounded drain interval. Paths identify
deployment objects but do not grant authority. Startup must subsequently open
and validate each as the appropriate capability before admitting traffic.

The default production identities remain Gitd `21001:21001`, authority
`21002:21002`, and certd `21003:21003`. The parser permits explicit deployment
values so host provisioning can allocate equivalents, while zero/root identity
is always rejected.

Patent review: **NOT_TRIGGERED**. Strict configuration parsing and bounded
numeric/path validation are conventional defensive mechanisms. See
`docs/patents/REVIEW_LOG.md`.
