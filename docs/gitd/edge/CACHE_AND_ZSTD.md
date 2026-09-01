# Cache and Zstandard profile

The L1 cache stores ready-to-send identity and Zstandard representations with
separate ETags. Hits do not recompress. Negotiation honors `zstd;q=0`, varies on
`Accept-Encoding`, and supports representation-specific `If-None-Match`.

`PersistentRepresentationCache` defines the L2 authority boundary over an
injected `CacheStore`. Domain-separated SHA-256 storage keys, exact record
lengths, independent body digests, Zstandard decode validation, atomic-write
delegation, and corruption removal are implemented. L2 loads reuse the stored
ready-to-send compressed bytes rather than recompressing.
`RepresentationSingleFlight` is integrated into the HTTP server. It bounds
active generations, elects one generator per exact cache key, suppresses
duplicate work, and rejects stale or repeated completion permits.

The encoder is a deterministic bounded raw/RLE Zstandard profile, not level 22.
General compressed blocks, Huffman/FSE encoding, a concrete Linux filesystem
store with atomic rename and directory fsync, and quota GC are production
blockers. Git pack bodies must remain
identity encoded at HTTP representation level unless an explicit measured
policy says otherwise.
