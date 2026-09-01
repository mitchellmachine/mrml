# Transactions and recovery

Status: **PARTIALLY IMPLEMENTED** as a storage-neutral admission and lifecycle
core. Durable filesystem activation is not implemented.

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
old-ID re-read, multi-ref atomic persistence, fsync/rename, audit signing, and
crash recovery remain unavailable until their policy-specific and storage
verifiers are implemented.
