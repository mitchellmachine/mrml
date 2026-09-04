# Gitd pre-activation recovery validation — 2026-09-04

This additive record covers retained pre-activation cleanup, exact-commit image
construction, SBOM generation, and stopped image loading on the owner-authorized
`mrml.ca` VPS. It is not a production-start record, a public-service test, a
Cosign-signed release, physical-hardware evidence, or independent review.

## Source and recovery result

- Branch: `main`.
- Exact image source commit: `2c403c0e` (`gitd recovery: discard retained
  preactivation state`).
- The ordinary worktree contained pre-existing unrelated Gitd and HTTP edits.
  Release binaries and images were built from `/tmp/mrml-release-2c403c0e`,
  populated by `git archive 2c403c0e`; those unrelated edits were excluded.
- The source commit was signed locally. No repository push was performed.

Gitd can now reconcile `DiscardBeforeActivation` journals at both durable crash
positions: while the transaction directory remains in `quarantine`, and after
it has moved to `arrivals` but before refs activate. Cleanup re-reads the exact
journal and live ref state, proves an installed arrival is absent from the
authenticated selected pack set, enumerates through retained directory
capabilities with explicit bounds, validates the complete expected layout before
mutation, rejects symlinks and unknown entries, fsyncs the affected parent, and
then removes the exact journal. Protected recovery exact-matches the authority
candidate generations and aborts only pre-activation authority states; activated
or completed authority state is contradictory and fails closed.

`ReverifyBeforeActivation` remains a separate fail-closed gate. This increment
does not reinterpret durable installed objects as newly verified authorization.

## Native verification

| Command | Result |
| --- | --- |
| `./target/debug/mrml test org.mrml.tool.git --target linux` | PASS: 258 library, 4 CLI, 7 signer tests |
| `./target/debug/mrml test org.mrml.service.gitd --target linux` | PASS: 43 library, 6 binary tests; loopback tests ran outside the filesystem/network sandbox |
| `./target/debug/mrml test org.mrml.library.runtime --target linux` | PASS: 50 tests; loopback tests ran outside the filesystem/network sandbox |
| `target/release/mrml manifest lock --check` in the exact snapshot | PASS: 71 packages, 5 interfaces |
| `target/release/mrml manifest check` in the exact snapshot | PASS: 71 components, 214 dependencies |
| Release builds for authority, Gitd, and Git/signer in the exact snapshot | PASS |

## Offline images and server state

Images were built with Podman for `linux/amd64` using `--network=none` and
`--pull=never` from digest-pinned base images. Syft 1.51.0 scanned each exported
Docker archive to SPDX JSON.

| Image | Local Podman ID | Archive SHA-256 | SPDX JSON SHA-256 |
| --- | --- | --- | --- |
| `mrml/git-authority:2c403c0e` | `cc414ce7577052dbfb4f75b5b31a52066489788cc7c070f7bdd2454dd77319aa` | `798bdad3f77d974ad325156c7ec2fdedee1dad6e10779732d5d2294c4ca5b761` | `9a82260149d916aa1d23eb03f61185c49c1249dca5d33afa38e48852934441c9` |
| `mrml/gitd:2c403c0e` | `5dc3aa6029e29189724cab28121c648435e7ae3eb64396f3def5de5e90f1112c` | `0a749ca51259fcd43e8b81df0a2210c27f87647775abfd82fff515416d0148fd` | `9e9dddd7633508b1628267cc52582f219e0969e36855cf539f6ec77d507882c9` |
| `mrml/git-protected-signer:2c403c0e` | `09a49e69348766af4dd5f55a9d5bf1ff12513c891e2537f04230c9449c302748` | `c323a7463189a2116bf38a8f421e42969a63174e1229c76ea54b7e82bc51b8c7` | `0deab1e1bea9ac74dbf2e95a5c3e811729e4a4ca85d3387babd80fa39174cff5` |

The archives were streamed directly over the approved SSH connection into
Docker 29.6.1 with `docker load`; no source checkout, build toolchain, registry,
or bind-mounted host data was used on the VPS. Docker's loaded runtime image IDs
are `92fab5e8e2c06458f09e9edbb5178ebec18f7608b2015a4a86ba95c03165cc9b`,
`3f00d8245d798db2a01059079b6c83fe0952956f1531dce4cf7a2e4724ed93a9`,
and `e980b251f947657f93da25ac734ade7b04b6510b2a1ad3941078f73dd5d9eb87`.
Their configured identities are respectively `21002:21002`, `21001:21001`,
and `21006:21006`, with their narrow daemon entrypoints.

No container or Compose project exists after loading. The host retains the
expected `mrml-*` Docker named volumes, including repository, state, quarantine,
cache, receipt, policy, authority, secret, configuration, and runtime-channel
volumes. Production startup remains fail closed until the owner supplies the
repository catalog, OpenPGP and ML-DSA public keys and policy, certificate
identity, and production Cosign key. No test or invented trust material was
substituted.

Patent review: **NOT_TRIGGERED**. This increment uses conventional
descriptor-relative enumeration, exact state-machine reconciliation, immutable
pack-set selection, Docker named volumes, image archives, and SBOM generation;
it introduces no substantial new mechanism. See
[`docs/patents/REVIEW_LOG.md`](../../patents/REVIEW_LOG.md).
