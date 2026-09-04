# Git backup and destructive restore validation — 2026-09-04

Status: hosted Linux rootless-Podman evidence using generated/disposable test
state. This is not production-key, public-network, physical-hardware, power-loss,
or complete protected-push evidence.

The validation used Podman 6.1.1, Linux/amd64 images, Docker-managed named
volumes only, and no host bind directory. The current Gitd one-shot initializer
created `owner/project` at repository generation 4, trust generation 1, and
revocation generation 1 with initial SHA-256 tip
`eff5a40ef7f3b72a26c9ea5d203f87c71896c68cab1938f6bff65c7f90f43380`.
The authority-generation record was independently encoded for the same exact
repository and generation. Controlled public OpenPGP-v6 and ML-DSA-65 keys were
used to initialize a hybrid-required policy; no private key entered the backup
administrator.

The one-shot administrator created and reverified encrypted generation 9001.
All eleven disposable source volumes, including the deliberately excluded
cache, were then deleted. Generation 9001 restored into ten new authoritative
volumes. After initializing the fixture's authenticated token store and policy,
generation 9002 was created and reverified. That first restore namespace and
its rebuilt cache were deleted, and generation 9002 restored into a second new
namespace.

The final implementation also received an eleventh empty cache target. Restore
derived only `owner/project` from the authenticated inventory, created the
cache root and both descendants as `21001:21001` mode `0700`, and synced them.
No cache bytes were present in either archive. Gitd then reopened the restored
repository, authenticated token store and policy and reported:

```text
recovery-status-v1 receipt=0 complete=0 discard=0 reverify=0 uncertain=0
```

Archive evidence:

```text
generation 9001: 5,645 bytes, root:root, mode 0600, links 1
sha256 83b361c81f9e6b122b5dd716ec6e50aa3dab26826c5fd4d19772fbf45fb1607d
generation 9002: 9,664 bytes, root:root, mode 0600, links 1
sha256 4c05cd949422ec5fd48a148af1039d320ae70f2ad7f96167b42889b2b1bb1ca3
```

Runtime image evidence:

```text
mrml/gitd:backup-e2e
  id 0dbc6363964b4a5b5d10290a6c09451a66358c2a9e6653e94038ad1863356ab2
  linux/amd64, user 21001:21001, entrypoint /usr/bin/mrml-gitd
mrml/git-backup:dev
  id 9d8c19ef0f9b6fb1ce112d04e2788ea12fac49f7b35e7bb85e8f9b1859db00a9
  linux/amd64, user 0:0, entrypoint /usr/bin/mrml-git-backup
```

Read-only inspection of the final Gitd image rootfs proved private data roots
as `21001:21001` mode `0700`, the public policy root as `21001:21001` mode
`0755`, and the authority socket root as `21002:21901` mode `2770`. This found
and corrected a Dockerfile defect where separate directory `COPY` operations
created final targets with default mode `0755`.

The run also proved that valid rootless Podman volume directories report link
count 1. Directory type, retained capability, owner, group and mode checks are
preserved; the nonportable directory-link-count condition was removed. Exact
regular-file link-count checks remain and continue rejecting hard-linked keys,
configuration, state, manifests, archives and repository content.

Focused gates after these changes:

```text
target/release/mrml test org.mrml.tool.git --target linux
  PASS: 266 library, 4 CLI, 7 protected-signer tests
target/release/mrml test org.mrml.service.gitd --target linux
  PASS: 47 library, 6 daemon, 1 backup-administrator tests
deploy/compose/test-git-images.sh
  PASS
deploy/compose/test-compose-git.sh
  PASS
```

This validates archive creation, complete cryptographic verification,
destruction of disposable sources, restoration into fresh named volumes,
automatic excluded-cache reconstruction, and cold recovery. It does not claim
the mission's clone/fetch/multiple-protected-push/receipt portion: the run used
an initialized repository without a live authority, signer, certd fixture, or
HTTP/2 stack. That remaining transaction sequence must be performed before the
broader destructive-restore acceptance item is complete.

A later activation audit found that the restore model originally named its
authority secret and configuration targets `NAMESPACE-authority-secrets` and
`NAMESPACE-authority-config`, while production and subsequent backups resolve
`NAMESPACE-git-authority-secrets` and
`NAMESPACE-git-authority-config`. The archive content and logical restore roots
were correct, but the namespace could not be activated or backed up again by
selecting it as `MRML_VOLUME_PREFIX`. The restore script and Compose external
volume names now use the canonical production suffixes. A profile-enabled
Podman Compose render with distinct source and target prefixes resolved all
eleven targets, including the corrected authority volumes. The full live
transaction sequence remains required and will use the corrected names.

The same activation audit found that the operator scripts invoked Docker
directly and used Docker Compose's `ps --status` syntax. That made the declared
Podman runtime unusable and, for manually created containers, could miss a live
volume consumer. Backup and restore now route both engine and Compose operations
through the exact `MRML_CONTAINER_RUNTIME` selection and determine cold state
from engine-level consumers of the prefix's Gitd-state and authority-state
named volumes. The check is independent of Compose project names and does not
depend on ACME Compose rendering. Every one-shot invocation explicitly enables
the `admin` profile, which is required by Podman Compose even when the service
is named directly.

The real Podman cold-backup continuation then exposed two further fail-closed
portability and coherence defects before any archive was accepted. Podman does
not accept redundant `uid=0,gid=0` options on the root-run administrator
tmpfs; backup and restore now rely on the root default while preserving
`rw,noexec,nosuid,nodev,size=8m,mode=0700`, and static tests forbid the rejected
form. After that correction, generation collection rejected protected forward
progress because it still applied conventional exact catalog admission. It now
matches the already implemented protected startup rule: the catalog repository
generation is a floor, trust and revocation generations remain exact, and the
repository generation must exact-match the authenticated authority record.
Focused tests accept only authority-confirmed forward progress, reject a stale
authority record, catalog rollback, and trust/revocation drift, and preserve
exact conventional admission. The live encrypted archive and destructive
restore sequence remain pending after this correction.

Patent review: **NOT_TRIGGERED**. The changes use conventional container image
layout, filesystem metadata validation, encrypted streaming backup, and cache
directory reconstruction. See `docs/patents/REVIEW_LOG.md`.
