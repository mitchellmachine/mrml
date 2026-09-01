# Gitd deployment catalogs

Status: **PARTIALLY IMPLEMENTED**. Canonical authenticated catalog loading is
implemented and is a native startup gate. Repository backend construction and
durable token-record loading remain to be composed.

Gitd accepts two distinct bounded version-1 catalogs. The profile catalog maps
a canonical deployment-owned profile name to `public-read`, `private`, or
`protected` and an exact per-object byte ceiling. The repository catalog maps a
canonical `owner/repository` identity to one profile plus nonzero repository,
trust, and revocation generations. Records must be strictly sorted and unique;
unknown profiles, aliases, leading-zero numbers, empty records, unknown fields,
oversized catalogs, and malformed identities fail startup.

The paths are constrained by typed configuration and opened with `O_NOFOLLOW`.
Each must be one bounded regular file owned by root or Gitd and not writable by
group or world. SHA-256 is recomputed over the exact bytes and must equal the
canonical digest in trusted configuration before parsing. Repository names and
profile labels identify authenticated records; neither grants authority by
itself. Git object-format enforcement remains an independent authenticated
repository-state check and is never inferred from a `.git` suffix or other
name.

Focused hosted Linux evidence:

- `./target/debug/mrml test org.mrml.service.gitd --target linux`: 9 tests pass,
  covering canonical resolution, generation binding, ordering, duplicate and
  unknown-profile rejection, malformed identities, digest substitution,
  symlink refusal, and insecure mode refusal, plus real authority/certd Unix
  exchanges.

Patent review: **NOT_TRIGGERED**. Canonical bounded text parsing, SHA-256 byte
binding, file metadata validation, and deployment-owned ACL/profile lookup are
conventional defensive mechanisms. See `docs/patents/REVIEW_LOG.md`.
