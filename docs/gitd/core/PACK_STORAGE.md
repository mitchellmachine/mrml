# Git pack storage

Status: **PARTIALLY IMPLEMENTED**. Existing bounded whole-buffer compatibility
parsing, a constant-memory file authentication scan, and the first-party
authenticated pack-index v2 module are implemented.

The pack encoder now emits a deterministic first-party zlib stream with one
fixed-Huffman DEFLATE block and bounded LZ77 matching. Its hash chains retain a
32 KiB window, inspect no more than 256 candidates at each input position, and
emit matches no longer than 258 bytes. Empty, incompressible, repetitive, and
window-boundary inputs round-trip through the first-party inflater on Linux and
through the pinned Windows Rust oracle under Wine. Wine is a hosted
compatibility probe, not Windows-native evidence.

A hosted-Linux functional concurrency test opens the same SHA-256 repository in
six simultaneous process-local workers and requires every worker to generate a
byte-identical reachable fetch pack. This exercises deterministic concurrent
read/generation behavior only. It does not establish multi-process service
isolation, peak memory, foreground latency under compaction, or production
throughput.

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

The receive path now performs an initial sequential `scan_pack_file` pass over
the reopened regular quarantine file. It snapshots and bounds the length,
incrementally hashes at most 64 KiB at a time, validates `PACK`, v2/v3, the
nonzero bounded object count, and the exact SHA-1 or SHA-256 trailer, and charges
one work unit per admitted byte. The trailer is excluded from the pack hash and
mixed-width IDs fail closed. This detects truncation, replacement, count-limit,
and checksum failure before the compatibility parser allocates the pack. Entry
inflation and delta resolution are not yet streaming, so this pass alone does
not satisfy the production receive memory gate.

For direct commit/tree/blob/tag entries, the second pass is now file-backed as
well: it parses headers bytewise, decodes zlib through a one-byte reader boundary
with an exact configured output ceiling, retains at most one object, charges
compressed and expanded bytes as work, hashes the canonical loose-object form,
and emits exact CRC/offset/index metadata. Installed-directory verification uses
the same path instead of reloading the pack. The validator now defers OFS and
REF deltas as bounded metadata and resolves them deterministically through exact
scratch-object identities. OFS bases must name an earlier exact pack offset.
REF bases may appear later or come from a caller-supplied exact-generation view;
external bases are re-hashed by full object ID and copied into the transaction's
private scratch set so reopen verification does not depend on mutable ambient
state. Missing, forged, cyclic/no-progress, and depth-greater-than-50 chains
fail closed.

Delta programs, bases, and results are each capped by the individual-object
limit. Aggregate reconstructed bytes, instructions, and copied output consume
explicit limits. The whole pack is never allocated, although one base, one
delta program, and one result may be resident during a resolution step.

Each authenticated direct object is now written as a new, fsynced scratch object
under the transaction-derived quarantine directory using its recomputed full ID
as the filename and an internal type byte. Duplicate IDs cannot overwrite an
existing scratch object. The crate-private resolver reopens a regular file,
bounds its size, decodes the type, recomputes the canonical Git object ID, and
returns bytes only to the protected receive compositor. These scratch objects
remain outside normal repository reads and move only with the immutable arrival
transaction directory.

`pack_index.rs` constructs and parses Git pack index v2 for both SHA-1
compatibility and SHA-256 repositories. It validates monotonic fanout tables,
strictly sorted full object IDs, duplicates, CRC fields, 32-bit and canonical
large-offset indirection, exact pack-checksum binding, the trailing index
checksum, object-count limits, truncation, and trailing data. Construction uses
deterministic allocation-free heapsort after one bounded entry copy and emits
the exact repository hash width. Immutable arrival-pack installation now writes
and reopens this index together with its authenticated pack. The index is not
yet connected to the normal active pack-set read path or canonical compaction
generation.

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

Protected receive now supplies thin REF bases only through the repository view
whose object format and exact active ref/repository generation were checked
before the request. The active ref state is re-read after the body and must
still byte-match before any base lookup; each returned base is independently
size-bounded and re-hashed before it enters transaction-private scratch. The
later durable activation still performs its immediate generation/ref re-read.
Thin-pack capability advertisement remains disabled pending concurrent receive
tests and production active-pack-set integration.

Pack-generation switching, clone/fetch caching, dynamic Huffman level-9
encoding, delta selection, and compaction remain open. No outer Zstandard layer
belongs in Git pack storage.

Active arrival-pack reads remain fail closed for an immediate authority reason.
`MRREFS01` authenticates only a scalar `PackGeneration`, and verified receive
preserves that value unchanged. No persisted object binds the generation to an
ordered list of arrival transaction IDs, exact object counts, pack checksums,
and index checksums. Journals identify individual transactions and counts, and
each installed index authenticates its own pack checksum, but neither grants
membership in an active pack set. Directory entries and transaction-derived
names identify files only; a reader must not scan or promote them into
authority.

`MRPKSET1` now implements the non-authoritative manifest prerequisite. Its
private validated construction consumes authenticated index summaries and binds
repository identity, repository and pack generations, object format, strictly
ordered unique transaction IDs, nonzero exact counts, pack/index checksums,
pack/index/work quantities, and each index's strictly ordered object IDs.
Aggregate pack, object, byte, index-byte, work, and encoded-size limits are
checked. Cross-pack duplicate object IDs are rejected as ambiguous. The parser
checks its terminal SHA-256 integrity digest, exact widths, truncation, trailing
data, canonical order, and byte-exact re-encoding.

`MRREFS02` now carries the exact SHA-256 digest of its selected `MRPKSET1`, and
the checked pack-set transition advances the repository generation and pack
generation together only when repository identity, object format, and both
next generations match. A manifest not selected by that record remains inert.
The receive storage compositor does not yet persist and supply this manifest,
so active reads, directory discovery, lookup, and generation switching remain
disabled. Once that durable compositor gate is complete, a reader may reopen exactly
the enumerated regular files, revalidate every index/pack/object binding, reject
duplicate ambiguity, and recheck active generations. This prerequisite is
independent of compaction and does not authorize patent-gated delta selection.
