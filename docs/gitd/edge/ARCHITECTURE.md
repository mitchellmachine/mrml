# Gitd public edge architecture

Status: **PARTIALLY IMPLEMENTED**. The edge owns transport, HTTP routing,
rendering, representation caching, and admission. It consumes `GitdBackend` and
never opens repository storage. Names identify repositories; the backend must
independently authorize every operation.

Implemented: bounded replay ranges and sparse streams, persistent HTTP/3 stream
state, enforced receive credit, a generic server-rendered router, an in-memory
precompressed representation cache, Retry-token and admission primitives, and
fail-closed application-key limits. The current `QuicServerListener` still
consumes its socket for one connection. A persistent connection-ID-demultiplexed
endpoint is a production blocker.
