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

Endpoint wiring now consumes and releases exact handshake and open-connection
permits, including rollback and timeout reconciliation. Deterministic tests fill
and reject the next slot at 8,000 open connections, 1,000 lightweight requests,
128 handshakes, 64 cached streams, 64 Git reads, 16 pushes, 8 renders, and 4
Zstandard jobs. Endpoint counters cover received packets/bytes, drops, new
Initials, handshakes, established routes, and candidate paths.

Distributed-source tests, sustained soak, the socket-independent encrypted
reactor, and production CPU/RSS/latency measurements remain open gates. These
deterministic unit tests establish exact bounds, not DDoS resistance or host
capacity.
