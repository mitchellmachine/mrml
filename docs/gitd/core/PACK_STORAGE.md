# Git pack storage

Status: **PLANNED**, except existing bounded whole-buffer pack parsing.

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

Pack indexes, thin-pack completion, disk reservation, arrival packs,
generation switching, caching, and compaction are not implemented by this
change. No outer Zstandard layer belongs in Git pack storage.

