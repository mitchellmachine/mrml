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

## Remaining evidence boundary

The session ran as UID 1000 and `sudo -n` required a password, so the root-only
host provisioners could not establish and validate the exact numeric ownership
layout. Consequently the combined containers were not started and no real
clone/fetch/pull/push, process-kill recovery, backup/restore, upgrade/rollback,
or 256 MiB streaming measurement was performed in this run. Those acceptance
items remain required. The real certd integration and rotation test also
remains required before any complete-stack production-readiness claim.

Patent review: **NOT_TRIGGERED**. This change records test evidence and uses
conventional container archive scanning and offline signature configuration;
it introduces no new protected mechanism. See `docs/patents/REVIEW_LOG.md`.
