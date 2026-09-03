# Git host provisioning

Status: **PARTIALLY IMPLEMENTED**. Git-owned Docker-managed data, socket,
secret, and configuration volumes have an idempotent host provisioner.
Image-only Compose validation,
offline image bundling, cold backup/restore, and immutable image
upgrade/rollback are separate implemented operators. Native one-shot repository
and initial protected-policy creation, token administration, and bounded recovery
operations exist. Authenticated normal and emergency trust-transition
administration remains incomplete.

Run `deploy/compose/provision-git-host.sh` as root with Docker available. The
deployment root defaults to `/mnt/mrml` and now contains only operator inputs,
deployment metadata, and backup outputs; it is not mounted into a production
container. Durable data, secrets, configuration, and Unix-socket directories
are separately scoped explicit `mrml-*` Docker volumes. Fixed
production identities and socket groups default to the values in the Gitd
deployment contract and can be overridden with the named numeric environment
variables in the script.

The provisioner creates only the declared Gitd, Git authority, secret,
configuration, and shared socket volumes plus operator backup/input paths.
New volumes receive their exact numeric owner and mode through the Docker volume
mountpoint; an existing volume is only inspected and is never silently re-owned
or re-moded. Unsafe volume names/mountpoints, paths, types, symlinks, owners, or
modes fail closed. A final probe requires file and directory sync, hard links,
and same-filesystem atomic rename before the host is accepted. The probe contains
no secret or repository data and is removed.

On a new host the scripts create paired Gitd/authority and Gitd/certd channel
capabilities in separate service-scoped secret volumes, plus a receipt key,
token pepper, and QUIC Retry key exactly once, then
revalidate type, owner, mode, link count, and exact length on every run.
`install-volume-inputs.sh` is the stopped-service, no-overwrite installer for
reviewed Gitd/certd/acmed configuration, authority public keys, trust roots, and
the DNS-provider token; it rejects running consumers and unsafe inputs. It
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

With Gitd and the authority stopped, `initialize-git-repository.sh` creates one
exact authenticated-catalog repository and prints its deterministic initial
SHA-256 tip and generations. For a catalog entry classified `protected`, install
the owner-selected OpenPGP v6 and ML-DSA-65 public keys as authority-owned
mode-`0444` regular files, then run
`initialize-git-protected-policy.sh OWNER/REPOSITORY VALID_FROM VALID_UNTIL`.
The second one-shot command requires the repository to equal
`MRML_PROTECTED_REPOSITORY`, reopens and admits its exact catalog generations,
binds `refs/heads/main` and the admitted initial tip as the hybrid cutover, and
creates the policy beneath a Gitd-owned mode-`0755` path. Policy state contains
public verification material and is non-writable to other identities so the
networkless authority can read the same authenticated bytes; repositories,
proofs, tokens, receipts, and secrets remain private. It permits SHA-256 and
requires the exact hybrid pair; it neither reads nor creates private signing
keys. Existing policy state is never overwritten. An ambiguous storage failure
is retained for inspection instead of being represented as safely retryable.

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

`recovery-git.sh status` is a cold, read-only scan of every authenticated
repository journal. It reports only bounded aggregate counts for receipt
recovery, completion cleanup, pre-activation discard/reverification, and manual
uncertainty; it exposes no repository, ref, object, proof, or filesystem
identity. `recovery-git.sh complete-safe` requires Gitd stopped and the
authenticated authority/certd dependencies available, then performs only the
existing provably safe receipt recovery and completion cleanup. Reverification
and manual-uncertain states remain unavailable rather than being guessed.

`backup-git.sh` requires root so it can read the Docker-managed volume
mountpoints after confirming their exact names, bounded mountpoint shape, and
absence of symlinks. It writes the same deterministic, numeric-owner archive
namespace as before, combining the separately scoped data, secret, and
configuration volumes. `restore-git.sh` refuses any pre-existing target data
volume, validates the archive before extraction, provisions fresh volumes, and
extracts each subtree into only its exact volume before a final structural
revalidation. Runtime socket volumes and the rebuildable cache are not restored.

Normal receive completion now re-reads the exact final journal, removes it, and
syncs the journal directory after the durable receipt and final journal phase.
If cleanup alone fails, the receive remains definitely activated and successful;
the authenticated journal stays present for the same completion operation at
startup. Recovery likewise removes only an exact re-read recognized journal
after its receipt has been recovered and verified.

On 2026-09-02 the provisioners ran twice, unchanged, through rootful Docker
29.6.1 on the authorized `mrml.ca` Ubuntu x86_64 VPS. Both passes succeeded and
the second pass proved idempotence across all 22 declared managed volumes. The
combined all-volume Compose model also rendered successfully under Docker
Compose 5.3.1 without connecting the Docker Snap `removable-media` interface.
The cold Git archive was created from those volumes, its sidecar checksum
verified, and its logical volume roots inspected. The restore preflight verified
that archive and rejected an existing target volume before mutation. This is
real VPS provisioning/filesystem/backup evidence; a destructive restore
roundtrip, successful image start, public TLS exchange, and application
transaction remain unproven on that VPS.

Patent review: **NOT_TRIGGERED**. Docker volume provisioning, ownership/mode
checks, hard-link and rename probes, and filesystem sync are conventional
deployment mechanisms. See `docs/patents/REVIEW_LOG.md`.
