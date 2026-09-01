# Cache and Zstandard profile

The L1 cache stores ready-to-send identity and Zstandard representations with
separate ETags. Hits do not recompress. Negotiation honors `zstd;q=0`, varies on
`Accept-Encoding`, and supports representation-specific `If-None-Match`.

The encoder is a deterministic bounded raw/RLE Zstandard profile, not level 22.
General compressed blocks, Huffman/FSE encoding, a content-addressed persistent
L2, checksummed records, atomic rename, corruption eviction, quota GC, and
single-flight generation are production blockers. Git pack bodies must remain
identity encoded at HTTP representation level unless an explicit measured
policy says otherwise.
