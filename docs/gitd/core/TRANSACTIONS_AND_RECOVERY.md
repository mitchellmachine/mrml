# Transactions and recovery

Status: **PARTIALLY IMPLEMENTED** as a storage-neutral admission, lifecycle,
and ordered durable-receive coordinator. A concrete filesystem backend is not
implemented.

The required state sequence is candidate received, objects quarantined,
objects validated, history verified, ref updates prepared, objects durably
installed, refs atomically activated, and audit receipt appended. The state
machine never permits a phase to be skipped or replayed. Quarantine must remain
invisible to ordinary reads when the storage backend is added.

`reserve_push_disk` performs conservative admission before consuming a request
body. The default limits are 2 GiB incoming pack, 8 GiB expanded objects,
128 MiB individual objects, one million objects, 32 refs, and a retained
40 GiB ordinary free-space reserve. Checked arithmetic reserves quarantine
bytes, expanded validation material, a second immutable arrival-pack extent,
index, staged metadata, receipt, and emergency reserve. Limit overflow,
arithmetic overflow, and insufficient space are distinct failures.

`QuarantineTransaction` binds a nonzero transaction ID, exact repository
identity and repository/trust/revocation generations, the private disk
reservation, and a `VerifiedRefTransaction`. It permits only the eight required
phases in order. Failures before durable installation become `Aborted`;
failures after installation/activation and receipt failures become `Uncertain`,
retaining the exact phase, transaction identity, and cause for recovery. This
state machine does not itself claim fsync or atomic-rename evidence.

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
ranges. Creation, deletion, history replacement, actual quarantine isolation,
and audit signing remain unavailable until their policy-specific concrete
storage implementations exist.

`durably_activate_verified_receive` now makes the storage ordering
non-bypassable through `DurableReceiveStore`. It persists and fsyncs the
prepared journal, installs and fsyncs the immutable arrival pack, persists the
installed phase, re-reads all three authority generations and every expected
old ref, invokes exactly one atomic activation-and-fsync operation, persists
activation, appends and fsyncs a bounded typed receipt, then persists
completion. A stale re-read never calls activation. Activation, post-activation
journal, receipt, and final-journal failures are retained as uncertain rather
than reported as retry-safe. Focused mock-backend tests prove ordering, stale
old-ID rejection, one-call atomic activation, receipt sequencing, and uncertain
activation failure. These tests prove coordinator behavior only; they are not
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

`MRRCPT01` is a deterministic receipt transcript binding the transaction and
repository identities, pre-activation and exactly-next repository generations,
trust and revocation generations, and a strictly sorted exact old/new ref set.
It is bounded to 16 KiB and checksum-protected; malformed ordering, mixed hash
formats, zero/equal IDs, generation skips, corruption, and trailing data fail
closed. Hosted Linux persists each receipt once as an immutable regular file,
fsyncs it and the receipt directory, then reopens and compares the exact
record. Duplicate transaction receipts are rejected. The checksum makes the
record auditable for accidental/torn-storage detection but is not a signature.
Receipt signing through isolated key custody and independent signature
verification remains open; this filesystem store must not be used as the final
protected-repository receipt authority until that interface is connected.
