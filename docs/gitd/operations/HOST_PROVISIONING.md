# Git host provisioning

Status: **PARTIALLY IMPLEMENTED**. Git-owned directories and shared Gitd socket
directories have an idempotent host provisioner. Image-only Compose validation,
offline image bundling, cold backup/restore, and immutable image
upgrade/rollback are separate implemented operators. Native one-shot repository,
token, trust-transition, and recovery administration remains incomplete.

Run `deploy/compose/provision-git-host.sh` as root. The deployment root defaults
to `/mnt/mrml`; fixed production identities and socket groups default to the
values in the Gitd deployment contract and can be overridden with the named
numeric environment variables in the script.

The provisioner creates only Gitd, Git authority, shared Gitd socket, channel
secret-parent, and backup paths. Existing paths are never silently re-owned or
re-moded: type, symlink absence, exact owner, and exact mode must already match.
Unsafe writable non-sticky ancestors fail. A final probe requires file and
directory sync, hard links, and same-filesystem atomic rename before the host is
accepted. The probe contains no secret or repository data and is removed.

On a new root the script creates paired Gitd/authority and Gitd/certd channel
capabilities, a receipt key, token pepper, and QUIC Retry key exactly once, then
revalidates type, owner, mode, link count, and exact length on every run. It
never creates certificates, repositories, access tokens, trust policies,
detached proofs, or publisher keys. Those require explicit authority-bearing
administration so provisioning cannot replace selected policy or repository
state.

Hosted evidence is limited to shell syntax, static invariants, and negative
argument tests because the current runner is neither root nor Docker-enabled.
It does not establish a successful production-host provision, image run,
backup/restore cycle, or filesystem behavior on the target VPS.

Patent review: **NOT_TRIGGERED**. Directory provisioning, ownership/mode checks,
hard-link and rename probes, and filesystem sync are conventional deployment
mechanisms. See `docs/patents/REVIEW_LOG.md`.
