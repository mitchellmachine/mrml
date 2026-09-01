# Transactions and recovery

Status: **PARTIALLY IMPLEMENTED** as a storage-neutral admission, lifecycle,
ordered durable-receive coordinator, and hosted-Linux filesystem composition.
The protected Smart Git receive backend and signed receipt authority remain
unimplemented.

The required state sequence is candidate received, objects quarantined,
objects validated, history verified, ref updates prepared, objects durably
installed, refs atomically activated, and audit receipt appended. The state
machine never permits a phase to be skipped or replayed. Quarantine must remain
invisible to ordinary reads when the storage backend is added.

`reserve_push_disk_before_body` performs conservative admission before
consuming a request body. Because standard receive-pack does not declare the
expanded size or object count before its pack header, it reserves the configured
maxima and the later validation phase binds the exact nonzero object count and
expanded bytes without increasing authority. `reserve_push_disk` remains the
lower-level exact-forecast operation. The default limits are 2 GiB incoming
pack, 8 GiB expanded objects,
128 MiB individual objects, one million objects, 32 refs, and a retained
40 GiB ordinary free-space reserve. Checked arithmetic reserves quarantine
bytes, expanded validation material, a second immutable arrival-pack extent,
index, staged metadata, receipt, and emergency reserve. Limit overflow,
arithmetic overflow, and insufficient space are distinct failures.

`QuarantineTransaction` binds a nonzero transaction ID, exact repository
identity and repository/trust/revocation generations, the private disk
reservation, the exact validated object count, and a `VerifiedRefTransaction`.
The validated count may only attenuate the pre-body maximum. It permits only the eight required
phases in order. Failures before durable installation become `Aborted`;
failures after installation/activation and receipt failures become `Uncertain`,
retaining the exact phase, transaction identity, and cause for recovery. This
state machine does not itself claim fsync or atomic-rename evidence.

`ArrivalPackStore::receive_pack_body` copies the exact admitted body through
`BoundedRead` in 64-KiB chunks directly into a transaction-derived, inaccessible
quarantine directory, fsyncs the file and directories, and only then records
`ObjectsQuarantined`. `validate_received_pack` authenticates the pack and every
object, enforces the reserved count/expanded/individual-object ceilings and
required tips, writes and fsyncs the v2 index, renames the validated pack within
quarantine, and records the exact count. The validation pass still materializes
the bounded pack and expanded objects in memory, so the default 2-GiB profile
remains disabled until parsing and object expansion are fully streaming under
the memory/work permits.

Immediately before activation, the engine must re-read every old object ID and
exact repository/trust/revocation generation. Protected refs are fast-forward
only unless a separate owner-authorized history-replacement policy applies.
Deletion is explicit policy. Multiple updates advertised as atomic have one
activation outcome.

Disk-full, short-write, fsync, rename, stale-lock, verifier-crash, and uncertain
commit outcomes must be explicit recovery states. A crash before activation
leaves the prior generation authoritative. An uncertain outcome retains exact
transaction identity and state and is never reported as safely retryable.

`VerifiedRefUpdate` and `VerifiedRefTransaction` have private fields at the
public boundary. The fast-forward constructor requires exact verified commit
ranges whose opaque per-commit proofs match the candidate's exact repository,
repository/trust/revocation generations, `GitCommit` purpose, object format,
and old/new IDs. Every introduced merge-side commit is covered; an unsigned
intermediate or a no-op verifier cannot mint the range. A concrete bounded
detached-proof store and hybrid verifier now feed this boundary; stored bytes
remain untrusted until both signatures, exact contents, and full context verify.
Creation, deletion, history replacement, durable proof-record storage, and audit
signing remain unavailable until their policy-specific implementations exist.

`prepare_protected_receive` now composes the pre-activation protected path for
existing refs: it parses only atomic `report-status-v2` commands, exact-matches
repository/object-format/generations and every active old ID, reserves disk
before body consumption, streams and validates the quarantine pack, charges
wire plus two file passes plus expanded bytes against the work permit, and
walks every introduced commit using authenticated quarantine scratch objects or
the exact active object generation. A `ProtectedCommitVerifier` can return the
opaque proof only through crate verification APIs; it receives exact commit
bytes and public context and has no signing operation. The opaque prepared
result stops at `HistoryVerified`, and a hosted-Linux test proves refs remain
unchanged. Signed receipt authorization and final report/activation composition
remain the next fail-closed gate; creation, deletion, and history replacement
are still rejected.

`durably_activate_verified_receive` now makes the storage ordering
non-bypassable through `DurableReceiveStore`. It persists and fsyncs the
prepared journal, installs and fsyncs the immutable arrival pack, persists the
installed phase, re-reads all three authority generations and every expected
old ref, invokes exactly one atomic activation-and-fsync operation, persists
activation, appends and fsyncs a bounded typed receipt, then persists
completion. A stale re-read never calls activation. Activation, post-activation
journal, receipt, and final-journal failures are retained as uncertain rather
than reported as retry-safe. Focused mock-backend tests prove ordering, stale
old-ID rejection, one-call atomic activation, receipt sequencing, and explicit
failure injection at the initial journal, arrival install, post-install
journal, authority reread, activation, post-activation journal, receipt, and
final-journal boundaries. Pre-install failures are aborted; every failure after
durable installation remains uncertain and no failure is reported as success.
These tests prove coordinator behavior only; they are not process-kill,
filesystem, power-loss, or physical-storage evidence.

The coordinator journal callback now receives both the lifecycle record and
the private verified transaction, preventing an implementation from persisting
a phase without the exact ref set that phase authorizes. `MRGJNL01` is a
deterministic, 16-KiB-bounded binary journal record containing the transaction
and repository identities, all authority generations, phase/failure, and every
full ref with exact old/new object IDs. A terminal SHA-256 record checksum
detects torn or accidentally corrupted records; it is not a signature or a
defense against a storage authority deliberately rewriting the journal.

The bounded parser rejects unknown versions, zero generations/identities,
invalid or duplicate refs, mixed/zero object IDs, inconsistent terminal state,
truncation, trailing bytes, and checksum changes. Recovery compares the full
live generation/ref snapshot to the journal. Exact-old installed state requires
complete verification again before any activation typestate can be rebuilt;
exact-new state recovers the audit receipt; an exact-new receipt state can be
marked complete. Any generation change, partial update, or third ref value is
`ManualUncertain`. Mock crash-state tests exercise these decisions, but a
filesystem journal writer, directory fsync, process restart, injected power
loss, and physical-storage evidence remain open.

On Linux, `ReceiveJournalDirectory` now persists these records through an
exclusive `.new` file, complete write, file fsync, atomic rename over the prior
phase, and journal-directory fsync. Record names are derived only from the
128-bit transaction ID. Reload uses a bounded regular-file/no-final-symlink
open, validates the embedded transaction ID, rejects noncanonical filenames,
symlinks, directories, unrelated entries, and stale temporary records, and
orders recovered transactions deterministically. A stale `.new` record is
preserved and blocks mutation for explicit recovery instead of being silently
deleted. Focused hosted-Linux tests persist two phases and reopen exact state.
The Windows build deliberately returns fsync failure because the runtime does
not yet expose Windows directory-handle flush; Wine proves compilation and
fail-closed availability, not Windows crash durability. Arrival-pack install,
atomic ref-generation persistence, audit-receipt storage, process-kill fault
injection, real power-loss testing, and physical media evidence remain open.

`MRREFS01` is the canonical bounded active-ref generation record used to make
multi-ref activation a single replacement rather than a sequence of loose-ref
writes. It binds repository identity, repository/trust/revocation/pack
generations, object format, default branch, and up to 65,536 strictly sorted
full refs with exact nonzero object IDs, followed by a SHA-256 integrity
checksum. Its parser rejects unknown formats, invalid identities, unsorted or
duplicate refs, width/format mismatches, truncation, trailing data, and
corruption. `apply_verified_ref_transaction` accepts only the private verified
typestate, rechecks all generations and every old ID, applies the complete set
to a clone, and advances repository generation exactly once. It never exposes
a raw protected-ref mutation API.

Hosted Linux now has `ActiveRefFile`. Initialization and activation write the
complete next record to an exclusive temporary regular file, fsync it, rename
it over the active generation, fsync the directory, and re-read and re-parse
the exact result. Activation holds an exclusive, fsynced directory lock across
the authoritative state re-read, verified update, and replacement. This stops
two pushes from committing against the same old generation. A stale/crash lock
blocks mutation; pre-rename stale/resource/short-write failures may release the
live lock, while rename, fsync, or post-rename verification failures retain it
because the outcome may be durable and uncertain. Focused hosted-Linux tests
cover reopen, exact one-generation advancement, stale old-generation retry,
and a simulated crash-stale lock. Windows remains fail-closed pending a runtime
directory flush primitive. Process-kill at every syscall boundary, power-loss,
and physical-filesystem atomicity evidence remain open.

Canonical compaction uses the same active-ref lock and `MRPKSET1`/`MRREFS02`
authority as receive rather than a parallel selector. The replacement pack and
index are fully authenticated and durably installed before the next manifest is
written. Activation re-reads the exact repository and pack generations,
preserves refs/trust/revocations, advances both repository and pack generations
once, fsyncs the new active record and directory, and reopens the selected state
and manifest. A stale or preactivation failure leaves the old record selected;
successful activation retains the old arrival and manifest for later recovery-
aware retirement. This is hosted Linux evidence only. Process-kill, power-loss,
native-Windows directory flush, and physical-storage evidence remain open.

The controlled concurrency test starts three native joinable workers together:
two target one repository and exact expected generation while one targets a
different repository identity and storage root. Exactly one same-repository
transaction succeeds, one fails stale, the independent transaction succeeds,
and both repositories reopen at exactly their next generation and ref value.
This is process-local hosted-Linux transaction serialization evidence, not a
multi-process kill or distributed-concurrency claim.

`MRRCPT01` is a deterministic receipt transcript binding the transaction and
repository identities, pre-activation and exactly-next repository generations,
trust and revocation generations, and a strictly sorted exact old/new ref set.
It is bounded to 16 KiB and checksum-protected; malformed ordering, mixed hash
formats, zero/equal IDs, generation skips, corruption, and trailing data fail
closed. Hosted Linux persists each receipt once as an immutable regular file,
fsyncs it and the receipt directory, then reopens and compares the exact
record. Duplicate transaction receipts are rejected. The checksum makes the
record auditable for accidental/torn-storage detection but is not a signature.

Protected activation instead requires `AuthenticatedReceiveStore`. It passes a
purpose-separated `MRML-GIT-AUDIT-RECEIPT-V1` transcript to an
`AuditReceiptAuthority`, whose interface exposes signing and verification
operations plus a public 64-byte signer identity but no private key bytes. The
bounded `MRARCP01` container binds the canonical receipt, full signer identity,
and at most 32 KiB of signature bytes, adds a storage-integrity checksum, writes
the result as a new immutable file, fsyncs the file and directory, and reopens
and independently verifies it before reporting success. The protected receive
preparation is consumed exactly once by
`activate_prepared_protected_receive`, and that API accepts only this
authenticated store wrapper. Stale authority, abort-before-activation, and an
uncertain post-activation failure remain distinct results. Hosted-Linux tests
exercise prepare-through-activation and reopen the authenticated receipt;
Windows compilation and non-filesystem behavior are exercised under Wine.
Production key-service integration, native-Windows directory durability,
process-kill injection, power-loss, and physical-storage evidence remain open.

`LinuxDurableReceiveStore` composes the concrete journal, immutable arrival
pack/index, active-ref generation, and receipt directories behind the same
`DurableReceiveStore` ordering interface used by the mock fault tests. Staging
now requires the exact verified proposed tips to be present in the validated
arrival pack, preventing an unrelated pack from being activated with a valid
ref typestate. The end-to-end hosted-Linux test stages and installs a SHA-256
pack/index, persists each journal phase, re-reads old refs, atomically advances
the active generation, appends the receipt, and independently reopens and
validates all four durable artifacts. A separate protected-path test uses the
authenticated receipt wrapper and reopens its signature-bound receipt. These
are concrete filesystem-ordering tests, not process-kill, power-loss,
physical-storage, production-key-service, or production-read-path evidence.

Recovery enumeration re-reads the canonical active-ref file for every bounded
journal and classifies it using the old repository generation before activation
or exactly the next generation after activation. A journal whose refs are
exactly new may reconstruct and immutably append the checksum-protected receipt;
an existing byte-exact receipt makes that operation idempotent. Pre-activation
installed objects still require complete history and policy re-verification,
and any generation/ref divergence remains `ManualUncertain`. This does not yet
durably advance the recovered journal to a terminal phase or provide the
required isolated receipt signature.
