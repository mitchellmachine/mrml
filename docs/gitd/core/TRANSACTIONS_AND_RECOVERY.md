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
