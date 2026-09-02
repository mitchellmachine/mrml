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

After installing the production environment and policy/catalog files, run
`deploy/compose/initialize-git.sh` exactly once. It starts the preloaded Gitd
image as a network-unpublished one-shot process with `--no-deps`, reads the
mounted pepper through the same strict loader as the daemon, and creates an
authenticated empty `tokens.v1`. Creation uses a private same-directory
temporary file, file sync, a no-overwrite hard-link activation, temporary
unlink, and directory sync. It refuses an existing destination and creates no
access token.

`token-git.sh issue` and `token-git.sh revoke` are cold one-shot operations:
they refuse a running Gitd so its authenticated in-memory snapshot cannot race
the durable store. Issuance accepts an exact repository identity, the bounded
`read`, `write`, or `admin` scope profile, validity interval, revocation
generation, and non-authoritative label. It displays the 256-bit token exactly
once and stores only a keyed verifier plus authenticated metadata. Revocation
accepts the token only on standard input, never an argument or environment
variable, uses constant-time verifier comparison, and atomically replaces the
authenticated store with file and directory sync. Restart Gitd after either
operation so startup reauthenticates the complete store.

Hosted evidence is limited to shell syntax, static invariants, and negative
argument tests because the current runner is neither root nor Docker-enabled.
It does not establish a successful production-host provision, image run,
backup/restore cycle, or filesystem behavior on the target VPS.

Patent review: **NOT_TRIGGERED**. Directory provisioning, ownership/mode checks,
hard-link and rename probes, and filesystem sync are conventional deployment
mechanisms. See `docs/patents/REVIEW_LOG.md`.
