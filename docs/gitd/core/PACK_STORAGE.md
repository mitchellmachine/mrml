# Git pack storage

Status: **PARTIALLY IMPLEMENTED**. Existing bounded whole-buffer pack parsing
and the first-party authenticated pack-index v2 module are implemented.

The pack encoder now emits a deterministic first-party zlib stream with one
fixed-Huffman DEFLATE block and bounded LZ77 matching. Its hash chains retain a
32 KiB window, inspect no more than 256 candidates at each input position, and
emit matches no longer than 258 bytes. Empty, incompressible, repetitive, and
window-boundary inputs round-trip through the first-party inflater on Linux and
through the pinned Windows Rust oracle under Wine. Wine is a hosted
compatibility probe, not Windows-native evidence.

Dynamic Huffman construction, canonical block selection, lazy level-9 match
selection, and pack delta selection remain open, so this does not yet satisfy
the canonical storage profile. The completed profile also requires a
250-object delta candidate window, maximum delta depth 50, OFS deltas, no reuse
of lower-compression streams, and recomputed canonical deltas.

Receive must stream into an isolated quarantine under checked byte, object,
expanded-size, delta, memory, and work limits. Whole-repository repacking is not
part of push latency. Immutable arrival packs are activated first; a bounded
low-priority compactor later creates and verifies canonical cold packs against
one consistent repository generation.

`pack_index.rs` constructs and parses Git pack index v2 for both SHA-1
compatibility and SHA-256 repositories. It validates monotonic fanout tables,
strictly sorted full object IDs, duplicates, CRC fields, 32-bit and canonical
large-offset indirection, exact pack-checksum binding, the trailing index
checksum, object-count limits, truncation, and trailing data. Construction uses
deterministic allocation-free heapsort after one bounded entry copy and emits
the exact repository hash width. This provides the immutable random-access
index representation; it is not yet connected to quarantine installation.

Thin-pack completion, disk reservation, arrival packs, generation switching,
caching, and compaction are not implemented by this change. No outer
Zstandard layer belongs in Git pack storage.
