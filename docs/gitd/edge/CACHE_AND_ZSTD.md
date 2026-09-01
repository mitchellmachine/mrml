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

Representation lookup keys are length-delimited, versioned, then reduced to a
domain-labeled SHA-256 digest. They independently bind repository identity,
object format, repository generation, page kind, complete route/path and
revision context, exact object ID, Markdown/renderer/template/theme/sanitizer/
highlighter/encoding versions, trust generation, revocation generation,
verifier version, and hybrid-profile version. Trust and revocation are never
combined arithmetically; the regression covers the former XOR-collision pair
`(1,2)` and `(2,1)`. Static pages use the same versioned renderer/template/theme/
encoding namespace.

On Linux, `LinuxFilesystemCacheStore` provides the concrete L2 adapter. It uses
content-addressed names, refuses final-component symlinks when reading, bounds
records before allocation, writes through exclusive temporary files, syncs the
file, atomically renames it, syncs the containing directory, and prunes regular
cache records to configured entry and byte quotas. Cache files remain
disposable; deletion is a miss and a later write recreates the root without
changing authoritative results. Construction removes bounded regular `.tmp-`
records left by interrupted writes while refusing directory and symlink targets.
Focused tests exercise round trips, quota eviction, interrupted-write cleanup,
root deletion/recreation, and absence of leftover temporary files. Filesystem
crash injection and production-disk exhaustion have not been exercised.

The encoder is currently a deterministic bounded raw/RLE Zstandard profile,
not level 22. Encoder-side bounded forward and RFC-reverse bit writers and RFC
normalized-count serialization are implemented and round-trip against the
existing independent decoders, including zero runs and low-probability `-1`
symbols. CTable/state emission, compressed sequence blocks, and Huffman payloads
remain the next production gates; these helpers are not yet selected by HTTP.
General compressed blocks and Huffman/FSE encoding remain production blockers.
Git pack bodies must remain identity encoded at HTTP representation level unless
an explicit measured policy says otherwise.

Patent review: **NOT_TRIGGERED**. This increment applies conventional bounded
file I/O, atomic rename, directory synchronization, and quota deletion; it adds
no new substantial compression or cache-replacement mechanism. See
[`docs/patents/REVIEW_LOG.md`](../../patents/REVIEW_LOG.md).
