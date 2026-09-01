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

The pack validation pass now retains each object's exact packed start/end
span, computes the Git index CRC-32 over those original packed bytes, and
returns `PackIndexEntry` values alongside fully authenticated objects. The
same pass therefore supplies object IDs, offsets, CRCs, and the authenticated
pack trailer needed by the first-party v2 index builder without a second
untrusted parse. A SHA-256 two-object test builds and reparses the index and
resolves both IDs. Independent `git index-pack` byte comparison remains open.

Hosted Linux now has an isolated `ArrivalPackStore`. It exact-matches the
transaction's reserved incoming byte/object counts, authenticates and expands
the pack, derives and reparses its v2 index, writes both as new regular files,
fsyncs each file and the staging directory, and then installs the pair with one
transaction-directory rename followed by fsync of both arrival and quarantine
parents. Post-stage and post-install verification reopens regular files without
following final symlinks, revalidates pack checksum/object IDs and every index
ID/CRC/offset/trailer binding, and rejects re-use of a transaction ID. The
arrival directory is outside normal active reads until ref generation
activation. Windows remains fail-closed pending directory flush support.

Thin-pack completion, pack-generation switching, clone/fetch caching, dynamic
Huffman level-9 encoding, delta selection, and compaction remain open. No outer
Zstandard layer belongs in Git pack storage.
