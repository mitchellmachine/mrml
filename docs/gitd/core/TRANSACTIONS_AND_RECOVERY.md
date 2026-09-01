# Transactions and recovery

Status: **PLANNED**.

The required state sequence is candidate received, objects quarantined,
objects validated, history verified, ref updates prepared, objects durably
installed, refs atomically activated, and audit receipt appended. Quarantine is
not visible to ordinary reads.

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
public boundary. Construction remains intentionally unavailable until the
range, signature, policy, quarantine, and storage verifiers are implemented.

