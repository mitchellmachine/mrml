# Git pack storage

Status: **PARTIALLY IMPLEMENTED**. Existing bounded whole-buffer pack parsing
and the first-party authenticated pack-index v2 module are implemented.

The current encoder emits stored DEFLATE blocks and performs no delta
selection. It is interoperable but does not satisfy the canonical storage
profile. The future profile is deterministic level-9 first-party zlib/DEFLATE,
a 250-object delta candidate window, maximum delta depth 50, OFS deltas, no
reuse of lower-compression streams, and recomputed canonical deltas.

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
