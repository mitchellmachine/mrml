# Git pack storage

Status: **PARTIALLY IMPLEMENTED**. Existing bounded whole-buffer compatibility
parsing, a constant-memory file authentication scan, and the first-party
authenticated pack-index v2 module are implemented.

The pack encoder now emits a deterministic first-party zlib level-9 stream with
one dynamic-Huffman DEFLATE block and bounded LZ77 matching. Its hash chains
retain a 32 KiB window, inspect no more than 4,096 candidates at each input
position, and emit matches no longer than 258 bytes. The canonical dynamic
literal/length, distance, and code-length tables are deterministic fixed
profile parameters rather than workload-selected codecs. Empty,
incompressible, repetitive, and window-boundary inputs round-trip through the
first-party inflater on Linux. A controlled Python zlib probe also decompressed
a loose object emitted by the first-party encoder. Upstream Git 2.55.0
`index-pack --stdin --strict -v` accepted a generated two-object pack containing
the dynamic streams and an OFS delta and resolved that delta. These are
controlled interoperability oracles, not runtime dependencies.

A hosted-Linux functional concurrency test opens the same SHA-256 repository in
six simultaneous process-local workers and requires every worker to generate a
byte-identical reachable fetch pack. This exercises deterministic concurrent
read/generation behavior only. It does not establish multi-process service
isolation, peak memory, foreground latency under compaction, or production
throughput.

The pack encoder now applies deterministic same-kind delta selection over the
exact preceding 250-object window. It constructs Git copy/insert programs with
fixed hash-chain bounds, ranks candidates by raw delta length then complete
object ID, caps aggregate comparison work, emits OFS deltas, and never exceeds
depth 50. Budget exhaustion deterministically falls back to a whole-object
representation. No lower-compression stream is reused. Cross-pack canonical
recomputation remains part of the compactor gate.

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

The immutable cache core uses a canonical full key containing object format,
exact ordered wants and haves, repository generation, pack-profile version, and
encoder version. Its SHA-256 digest is only a rejection accelerator: a hit also
requires full-key equality, and cached representation bytes are rehashed on
every lookup. Inserts cannot overwrite or reinsert a key. This in-memory core
does not yet claim durable precomputation or filesystem cache recovery.

The reachability compaction core accepts an exact repository/pack-generation
snapshot and caller-authenticated reachable objects, sorts only by complete
object ID, applies the fixed level-9/window-250/depth-50 encoder, reparses the
result, and requires exact object equality. It pauses for active pushes or core
pressure, rejects estimates over the 4 GiB memory budget, preserves 40 GiB free
space after the estimated output, and advances exactly one pack generation.
Its journal admits only planned, staged, stage-synced, activated, and retired
transitions and classifies crashes without treating an unactivated stage as
authoritative. The current implementation is a pure state-machine core;
filesystem staging, fsync, atomic generation activation, and retirement remain
to be composed and physically tested.

Dynamic-Huffman level-9 encoding, direct-window OFS delta selection, exact-key
cache semantics, and the generation-safe compaction planner are implemented.
No outer Zstandard layer belongs in Git pack storage.

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

`MRREFS02` carries the exact SHA-256 digest of its selected `MRPKSET1`, and the
checked pack-set transition advances the repository generation and pack
generation together only when repository identity, object format, and both
next generations match. `ActiveRefFile::activate_with_pack_set` writes and
fsyncs the immutable content-addressed manifest before replacing the active
record; an interrupted pre-selection write is inert. Selected-manifest reads
open only that digest-derived regular file and recheck the digest, repository,
format, and generations. A manifest not selected by the active record grants
no read authority.

The hosted-Linux durable receive compositor now reopens the installed pack and
index, derives an authenticated summary, extends the previously selected
manifest without duplicate objects, and calls this transition. An exact empty
manifest represents a repository with no arrival packs and gives bootstrap a
real digest instead of a sentinel. The end-to-end receive test reopens the
selected next generation and its exact transaction/object membership.

The receive store can now resolve an exact object from the selected arrival set:
it finds the single manifest entry, reauthenticates that installed pack/index
summary byte-for-byte, opens only the transaction's bounded scratch object, and
rehashes its Git identity. Thin-pack validation consults this selected view
before the separately authenticated baseline repository, so sequential receives
can use prior active arrivals without directory scanning. Protected-history
traversal uses the same selected view, and the end-to-end receive test prepares
a second commit whose parent exists only in the first selected arrival. General
repository view and upload-pack composition still need to route through this
selected arrival reader. This membership authority remains independent of the
guarded delta selector and future compaction policy.
