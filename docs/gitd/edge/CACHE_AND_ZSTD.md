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

On Linux, `LinuxFilesystemCacheStore` provides the concrete L2 adapter. It uses
content-addressed names, refuses final-component symlinks when reading, bounds
records before allocation, writes through exclusive temporary files, syncs the
file, atomically renames it, syncs the containing directory, and prunes regular
cache records to configured entry and byte quotas. Cache files remain
disposable; deletion is a miss and never changes authoritative results. The
focused test exercises round trips, quota eviction, and absence of leftover
temporary files. Filesystem crash injection and production-disk exhaustion have
not been exercised.

The encoder is a deterministic bounded raw/RLE Zstandard profile, not level 22.
General compressed blocks and Huffman/FSE encoding remain production blockers.
Git pack bodies must remain identity encoded at HTTP representation level unless
an explicit measured policy says otherwise.

Patent review: **NOT_TRIGGERED**. This increment applies conventional bounded
file I/O, atomic rename, directory synchronization, and quota deletion; it adds
no new substantial compression or cache-replacement mechanism. See
[`docs/patents/REVIEW_LOG.md`](../../patents/REVIEW_LOG.md).
