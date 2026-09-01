# Linux deployment adapter

Status: **PARTIALLY IMPLEMENTED**. A safe host-layout provisioner and separate
minimal Gitd/Git-authority image definitions exist. The production process must bind UDP 443, retain sole
ownership of the socket reactor, load non-exportable signing/token operations,
drop ambient privilege, enforce file and memory quotas, expose bounded health
metrics, and stop accepting work before graceful drain.

A bounded filesystem-backed persistent cache adapter is implemented with
file-and-directory durability barriers and quota pruning. Its root is supplied
by deployment policy; the adapter does not select a host path or grant access to
one. No systemd unit, namespace/seccomp profile, privileged-port handoff, cache
directory provisioning/confinement policy, log retention policy, or public-host
deployment has been verified. Hosted Linux package tests do not establish
production deployment.

`Dockerfile.gitd` and `Dockerfile.git-authority` use digest-pinned verification
and distroless runtime stages, copy only their respective prebuilt executable,
and run as fixed unprivileged `21001:21001` and `21002:21002` identities. They
do not embed configuration, repository data, trust/proof state, receipt keys,
certd material, ACME credentials, or build tools. The static
`deploy/compose/test-git-images.sh` gate verifies pinned stages, intended users
and entrypoints, and rejects representative cross-service secret/binary
references. It passed under hosted Linux. No image build or runtime execution
was performed in this evidence, and no production Git Compose service is yet
claimed because `mrml-gitd` still lacks its public serve/listener mode.

`build-offline-git-bundle.sh` is the offline release recipe for those two
images. It requires a canonical version and new absolute output, exact local
Cosign key files, clean manifest checks, focused authority/Gitd tests, release
builds, network-disabled/no-pull image builds, image identity records, SPDX JSON
SBOMs, offline blob-signature bundles, and a deterministic tar containing the
provisioner and Gitd configuration template. The matching verifier checks every
recorded SHA-256 checksum, requires each identity/SBOM artifact, and verifies
both image archives with the bundled public key. Hosted shell evidence covers
syntax and early invalid-version/output refusal only; Docker, Syft, Cosign, and
the complete offline recipe have not yet run in this environment.

Patent review: **NOT_TRIGGERED**. Digest-pinned multistage containers,
unprivileged users, minimal copied artifacts, and static image-policy checks are
conventional deployment hardening. See `docs/patents/REVIEW_LOG.md`.
