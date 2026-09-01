# DDoS and resource profile

Implemented bounds cover packet history, ACK ranges, sparse stream gaps and
chunks, connection/stream receive credit, HTTP/3 active and completed streams,
Retry token size and replay storage, half-open count, per-IPv4 source count,
handshake memory, and handshake lifetime. Under configured pressure,
unauthenticated clients receive Retry; exhausted state rejects without growth.

Distributed-source tests, sustained soak, CPU token buckets, endpoint-wide
established-connection quotas, IPv6 `/64`, and production load measurements are
open gates. These unit tests are not DDoS-resistance evidence.
