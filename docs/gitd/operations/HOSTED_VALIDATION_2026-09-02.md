# Git/Gitd hosted validation — 2026-09-02

Status: **PARTIALLY IMPLEMENTED**. This record is hosted Linux evidence from
the repository at commit
`9b954520cad99bf66d622bbe4358574587cf58d0175bd5509ad1fa30408415d9`.
It is not public-network, physical-host, real-VPS, power-loss, or independent
security-review evidence.

## Tool and build evidence

The host used Podman 6.1.0 through its Docker-compatible CLI, podman-compose
1.6.0, Buildah 1.45.0, crun, Syft 1.51.0, Cosign 3.1.0, Valgrind 3.25.1, and
cargo-fuzz 0.13.2. The exact digest-pinned Debian verification and distroless
runtime images were pulled before the required network-disabled builds.

The following commands passed:

```text
./target/debug/mrml build org.mrml.service.git-authority --target linux --release
./target/debug/mrml build org.mrml.service.gitd --target linux --release
docker buildx build --platform linux/amd64 --network=none --pull=false --load -f deploy/compose/Dockerfile.git-authority -t mrml/git-authority:b4041d82 .
docker buildx build --platform linux/amd64 --network=none --pull=false --load -f deploy/compose/Dockerfile.gitd -t mrml/gitd:b4041d82 .
./target/debug/mrml build org.mrml.service.certificate --target linux --release
./target/debug/mrml build org.mrml.service.acme --target linux --release
docker buildx build --platform linux/amd64 --network=none --pull=false --load -f deploy/compose/Dockerfile.certd -t mrml/certd:9b954520 .
docker buildx build --platform linux/amd64 --network=none --pull=false --load -f deploy/compose/Dockerfile.acmed -t mrml/acmed:9b954520 .
```

The Git image build inputs and resulting image identities were:

```text
mrml-git-authority binary sha256:56e1d5e46ea549c6b2f53172240894deb165c213d9a04241f74c6fba8a972fcf
mrml-gitd binary sha256:2e63fda9e9edb68199f61a112c0eaaf3b92dbf2fb78f758c57452ee68830b1c8
mrml/git-authority:b4041d82 image id sha256:37eea4cbb47f9525b2ddc3a7ca4f368995ecb9432591b898356321058fe7b0b2
mrml/git-authority:b4041d82 manifest sha256:fc2e231baca762cbdfd44a5c04beb6c2a3457f2087d10956be4c8d9b1b3fbe23
mrml/gitd:b4041d82 image id sha256:10d4ca4f00a61f93f9d5f1fc369fc57ed676f2c0ae2b4c16166ed116e00e3452
mrml/gitd:b4041d82 manifest sha256:77a2cd03476464828f0bf645c8ed41155fc2d745a553ce4a788cab0610e83947
```

Inspection reported Linux/amd64, fixed users `21002:21002` and `21001:21001`,
and only the intended authority or Gitd entrypoint. The exported archives were
successfully scanned rather than relying on a daemon-specific image-store API.
Temporary hosted outputs had these digests:

```text
authority archive sha256:de23d6e3831c221b33d8355183b112c2f19c3b76d129d3423fe469425a5f1bfa
authority SPDX JSON sha256:f7fa414531a15c89c6c8540d9d73dcb0263a1505cb8e51fab417a9c91bf3bd8c
Gitd archive sha256:454f31af03b698ddfcb784083071c350d846a3b19d81d3cc0f222f08b9ce132e
Gitd SPDX JSON sha256:f3186adaa30e1edf4d0d783ef923abfdb004372679c5436d74b38f13a1929fea
```

These temporary artifacts are evidence inputs, not final release artifacts.
The offline builder now scans the exact exported archive. Cosign 3.1.0
successfully signed and key-verified a test archive using an explicit signing
configuration containing no Fulcio, OIDC, Rekor, or TSA service. The keypair
was temporary and test-only; it is not release authority.

## Tests and runtime configuration

AddressSanitizer passed all 215 Git library tests, 4 Git CLI tests, 74 HTTP
tests, and 29 Gitd tests. The Gitd run included its real Unix-socket and
loopback tests. Valgrind with full leak checking and a nonzero error exit passed
2 deterministic hostile Git parser tests, 3 token/profile authentication tests,
and 2 HTTP/2 streaming adapter tests. No repository cargo-fuzz target exists,
so no coverage-guided fuzz campaign is claimed.

The following static gates passed:

```text
deploy/compose/test-compose-git.sh deploy/compose/compose.git.yaml
deploy/compose/test-git-images.sh
sh -n deploy/compose/build-offline-git-bundle.sh deploy/compose/verify-offline-git-bundle.sh deploy/compose/test-compose-git.sh
```

Podman Compose successfully rendered the combined `compose.git.yaml` and
`compose.acme.yaml` model with exact release variables. The rendered model kept
Git authority and certd at `network_mode: none`, published only Gitd TCP/UDP
443, retained non-root users, dropped all capabilities, set read-only roots and
`no-new-privileges`, and retained the declared resource limits and bind mounts.

## Catalog and protected-policy bootstrap follow-up

Follow-up validation used a clean detached worktree at commit
`c54c1763630189cf6f65bff70b52e86be7c0f214` so unrelated edits in the shared
checkout could not enter the binaries or images. Network-disabled pinned image
builds produced:

```text
mrml-git-authority binary sha256:02612a450350f0dd79584a7fa27a4d1ffad02f399ca4521c3bf6f50afc531b8c
mrml-gitd binary sha256:a76a95511c7c72f2020f2bf8cb9c84a3743e76d666d73539606183747b444177
mrml/git-authority:c54c1763 image id sha256:bb621b8b2031e42d4819abba9fc872452f2c235892415920ea14c73084ecb505
mrml/git-authority:c54c1763 manifest sha256:c28e9eb729f90987377abfcb94327fc617cdc61624ee88cba09461a8b79ce476
mrml/gitd:c54c1763 image id sha256:c4ae793b2082df1c40a38305d4e9d2d1a7e3c9f8818996d7c6ccde36f262138e
mrml/gitd:c54c1763 manifest sha256:6de5c3bf53aacee9c6f12217d8fdc0d39774276e7a80510255b6f0bc94c8cb13
```

A rootless Podman helper established production numeric ownership inside an
isolated `/tmp` deployment; no production `/mnt` state was used. The clean Gitd
image authenticated exact profile/repository catalogs, created the SHA-256
`owner/project` repository at deterministic tip
`eff5a40ef7f3b72a26c9ea5d203f87c71896c68cab1938f6bff65c7f90f43380`,
and established the hybrid-required protected policy at that same cutover with
trust/revocation generation 1. A second policy creation failed closed. The
inputs were repository test-only OpenPGP v6 and ML-DSA-65 public fixtures; no
private signing key entered either image. The authority image then opened and
validated the exact same Gitd-owned policy through the read-only shared mount.
An initial authority attempt against mode-`0700` policy directories failed
closed, directly exposing and motivating the owner-writable/public-readable
authenticated-policy directory correction in `c54c1763`.

## Protected receive proof-wire follow-up

The protected proof carriage and authority-install integration was validated
from the shared checkout based on `721d4bb6` with the reviewed proof-wire diff
still uncommitted. This is development evidence, not immutable release
evidence. The canonical Git test command passed 216 library and 4 CLI tests:

```text
./target/debug/mrml test org.mrml.tool.git --target linux
```

Network-disabled Podman builds from the locally available digest-pinned base
images also passed. The resulting development artifacts were:

```text
mrml-git-authority binary sha256:e9be7323a90d5bda9ce7e762eb9e97c8efade5f97ee32c0aecdf6cfe6fd81068
mrml-gitd binary sha256:9211a22b8f29539c63bb41efed6e364cdbb478871d79f83f861e2f6c1f306a5e
mrml/git-authority:proof-wire-test image id sha256:99ccdb49b6df7cc1abdc5d9221274f572f060ef4ac08d9803466b19e7fc6ce41
mrml/gitd:proof-wire-test image id sha256:f09eb51f20ec8782a10f4ddbd585f302328cd86f1e2a7c138c316c9181d4aa92
authority archive sha256:e6ad177a8420ea9730ad3710f553f8270ea409d246dff7291712a1a391a39ec5
Gitd archive sha256:6f4a1d26f804df04554fea20fcd48556171cf22331970c5b1e102a82d9b5d4cb
authority SPDX JSON sha256:155ee1ee5a0154ba7e015ea64edb3be03cc95a646e4feb19fc331e55697e808d
Gitd SPDX JSON sha256:d1a17731b1343f376011d67cd14d7c9cdb986349ed602836db64ab197cb87bd2
```

Image inspection reported users `21002:21002` and `21001:21001` with only
the intended exec-form entrypoints. Syft 1.51.0 scanned the exact exported
archives and emitted valid SPDX 2.3 JSON containing 12 package records per
image. Its optional update check failed because the sandbox had no DNS; archive
scanning itself completed and the outputs parsed successfully.

The authority lifecycle was subsequently exercised from another uncommitted
development build. Its network-disabled image ID was
`sha256:5f9a1dd387cfabb45ade05248af5d49426384761c244392261fd1391f7acbe6a`.
The first container run authenticated its native health request but exposed
that SIGTERM required a forced kill and left `authority.sock`, preventing a
secure restart. After adding synchronous SIGINT/SIGTERM handling and
identity-checked socket cleanup, the hardened container reported `ready`,
stopped within the five-second test bound without SIGKILL, left no socket, then
started, healthchecked, and stopped cleanly a second time. The test used
`network=none`, UID/GID `21002:21002`, a read-only root, empty capabilities,
`no-new-privileges`, and the isolated `/tmp` policy/state tree. This proves the
tested authority lifecycle only; Gitd drain and the combined stack remain
separate required evidence.

## Remaining evidence boundary

The session ran as UID 1000 and `sudo -n` required a password, so the root-only
host provisioners were not executed directly on the host. The isolated helper
evidence above is not a real VPS or host-provisioner run. The combined containers
were not started and no real
clone/fetch/pull/push, process-kill recovery, backup/restore, upgrade/rollback,
or 256 MiB streaming measurement was performed in this run. Those acceptance
items remain required. The real certd integration and rotation test also
remains required before any complete-stack production-readiness claim.

Patent review: **NOT_TRIGGERED**. This change records test evidence and uses
conventional container archive scanning and offline signature configuration;
it introduces no new protected mechanism. See `docs/patents/REVIEW_LOG.md`.

## Protected signer and clean image follow-up

The local-only signed commit `d2737102` was checked in the clean detached
worktree `/tmp/mrml-protected-743e2b11`. Manifest lock and manifest validation
passed. With host-local socket access enabled, all 7 Linux-library tests, 48
runtime tests, 223 Git-library tests, 4 Git CLI tests, 2 protected-signer daemon
tests, 4 authority-library tests, 1 authority-binary test, 29 Gitd-library
tests, and 1 Gitd-binary test passed. Initial sandboxed runs of the socket tests
failed at local bind, then passed unchanged with local socket access; this is an
execution-environment distinction rather than claimed network evidence.

The exact clean commit produced network-disabled, digest-pinned production
images with these identities:

```text
mrml-git-authority binary sha256:b0c30159d42772c2c1d344201caf299a7e1acf7e0de5983e8901a49a74537e16
mrml-gitd binary sha256:272d68092a37de52217d43de0cb221680dac42b62999a535cc65d6cfc5455a68
mrml/git-authority:d2737102 image id sha256:5f9a1dd387cfabb45ade05248af5d49426384761c244392261fd1391f7acbe6a
mrml/git-authority:d2737102 manifest sha256:233c4cfba68683dad4567298029239b5447448b600a1fda36b24a3ed64548e57
mrml/gitd:d2737102 image id sha256:638eb9b592b0447fa1d26143dc82b53b3a549ba023b752130d672423486001fb
mrml/gitd:d2737102 manifest sha256:6e79d91be8c2c093703a4cc3bdd161ccae3adce8aa65ab7dc9b7f3ba4e8dd203
authority archive sha256:2213d42c4dd9b015a313c7e2e4868a6b5a3c71ef8c6411ca30e9e8b0be1a73b0
authority SPDX JSON sha256:382e279fb635e9102c3c59ede2ab45ae313477bc3eb6e3cb9d95ed1058fe31df
Gitd archive sha256:35e8a9d9fc303839ff7157f379050b26506b173b37d6cb9fdad32992211b1e2c
Gitd SPDX JSON sha256:2d1a9784058b41fa817cf7f95bf9f0f146b2f7f9b53f63e9e9ea6843adc02af1
```

Image policy, Compose static invariants, and shell syntax checks passed. Podman
reported the exact fixed users and entrypoints. Syft 1.51.0 scanned each exact
exported archive into valid SPDX 2.3 JSON with 12 package records. The package
inventory contained the distroless runtime set and no Rust toolchain, Git,
OpenSSH, GnuPG, curl, wget, Python, Perl, or package manager.

This follow-up adds a separate purpose-limited protected signer and completes
the client proof-generation route, but it does not change the remaining real
VPS, full certd-backed stack, or 256 MiB transfer evidence boundary above.

## Gitd local capability ownership correction

The production provisioner creates distinct Gitd-side authority and certd
channel-capability copies as UID/GID `21001:21001`, and Compose mounts those
copies read-only into Gitd. A startup audit found that Gitd nevertheless asked
its secure file loader to require the remote service UID for each local copy.
Both dependency-health and serve paths now require the configured Gitd UID for
the local files. Unix peer credentials remain independently checked against the
authority and certd UIDs; this change does not weaken remote peer identity.

The hosted Gitd suite passed 29 library and 2 binary tests with local Unix,
TCP, and UDP socket access. An initial sandboxed run passed the 26 non-socket
tests and failed only the three denied bind operations; the unchanged suite
then passed with local socket access. The production Compose static-invariant
test also passed.

Patent review: **NOT_TRIGGERED**. This is an ownership-consistency correction
for an existing local secret-file check and introduces no new mechanism. See
`docs/patents/REVIEW_LOG.md`.

## Authority Compose health correction

The production Compose healthcheck previously opened the authenticated
authority protocol from inside the authority container as UID 21002, while the
listener correctly admits only Gitd UID 21001. That self-check could never
succeed. Compose now uses a non-signing `listener-health` command that requires
the exact Unix socket type, authority UID 21002, shared socket GID 21901, and
mode `0660`. Gitd still completes the HMAC-authenticated, peer-credential-bound
authority health operation before public listener startup.

The authority suite passed four library and two binary tests with local Unix
socket access. The production Compose invariant test passed.

Patent review: **NOT_TRIGGERED**. This is a conventional local Unix-socket
readiness check and introduces no new cryptographic or authorization mechanism.
See `docs/patents/REVIEW_LOG.md`.

## Authority signer-identity bootstrap

The authority binary now provides `describe-signer` with the same bounded,
owner-checked inputs as `check-config`. It loads and validates the complete
authority configuration, derives the receipt signer identity from the private
receipt key, and emits only the 128-character lowercase hexadecimal public
identity required by Gitd. It does not print or export the receipt key.

The authority suite passed four library and three binary tests, including exact
lowercase identity encoding.

Patent review: **NOT_TRIGGERED**. This exposes an already derived public
identifier through a bounded administrative command and introduces no new
mechanism. See `docs/patents/REVIEW_LOG.md`.

## Category-only startup diagnostics

Gitd now emits non-sensitive operational categories after certificate identity
authentication and for composition failures in authentication, repository
admission, recovery, backend construction, or cache construction. The recovery
inspection command reports only its bounded error enum. Repository identities,
paths, tokens, keys, request bodies, and object content remain absent.

The hosted Gitd suite passed 29 library and 2 binary tests with local socket
access.

Patent review: **NOT_TRIGGERED**. This adds only bounded operational event
classification. See `docs/patents/REVIEW_LOG.md`.
