# DDoS and resource profile

Implemented bounds cover packet history, ACK ranges, sparse stream gaps and
chunks, connection/stream receive credit, HTTP/3 active and completed streams,
Retry token size and replay storage, half-open count, per-IPv4 source count,
handshake memory, and handshake lifetime. Under configured pressure,
unauthenticated clients receive Retry; exhausted state rejects without growth.

`GitdResourceController` now provides a fixed-capacity source table, integer
token buckets, IPv4 identity and IPv6 `/64` aggregation, independent concurrent
work-class ceilings, the 40 GiB disk reserve, and hysteretic NORMAL, PRESSURE,
SIEGE, and RECOVERY transitions. Table or permit exhaustion rejects without
growth. PRESSURE/RECOVERY reject large diffs; SIEGE admits only cached pages and
Git reads. Reactor wiring must supply trusted resource snapshots and call
completion for every admitted permit.

Distributed-source tests, sustained soak, endpoint-wide established-connection
quotas, reactor wiring, and production load measurements remain open gates.
These deterministic unit tests are not DDoS-resistance evidence.
