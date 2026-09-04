# Hosted Git credential-agent evidence — 2026-09-04

Status: **IMPLEMENTED** scoped credential IPC and daemon; hosted Linux and
local Podman build evidence only. This is not a production-token, public-network,
VPS activation, or independent-review claim.

Source commits:

- `84f05aa6` — authenticated scope-bound client/daemon implementation.
- `3da7a4f4` — isolated image, named-volume Compose model, and offline bundle
  integration.

## Implemented boundary

`mrml-git-credential-agent` owns one exact Gitd-issued bearer token. Its command
line contains paths and non-secret policy only; the token is read from an
owner-only regular single-link file opened with `O_NOFOLLOW`. The client and
agent receive separately owned copies of a random 256-bit channel capability.

For each use, the agent creates a fresh random five-second session. HMAC-SHA-256
authenticates the session, request, and response. The request binds the exact
host, port, `.git` repository path, read/write action, credential generation,
request ID, and session. The client authenticates agent UID/GID and the agent
authenticates client UID/GID using kernel Unix peer credentials. One connection
serves one request. Wrong capabilities, peers, sessions, scope, action,
generation, expiry, and frame bounds fail closed. Secret-bearing input, token,
response, and authorization buffers receive volatile erasure.

The daemon is fixed at UID/GID `21007:21007`; socket group `21907` is distinct.
Its production Compose fragment has `network_mode: none`, no ports, read-only
root, all capabilities dropped, no-new-privileges, and explicit memory, CPU,
PID, descriptor, and log bounds. Token, channel, client channel-copy, and Unix
socket storage use namespace-prefixed named volumes. No host data directory is
mounted.

Server-side Gitd token revocation remains authoritative and live: a revoked
token returned by an agent is rejected by Gitd. Credential rotation provisions
a replacement token and higher generation with the agent stopped, then
recreates the container; clients pinned to the old generation fail closed.

## Exact checks

```text
MRML_CREDENTIAL_AGENT_SOCKET_TEST=1 target/release/mrml test org.mrml.tool.git --target linux
  PASS: 273 library + 5 CLI + 7 signer + 2 credential-agent = 287 tests

target/release/mrml manifest check
  PASS: 71 components, 214 dependencies
target/release/mrml manifest lock --check
  PASS: 71 packages, 5 interfaces
deploy/compose/test-compose-git.sh
  PASS
deploy/compose/test-compose-signer.sh
  PASS
deploy/compose/test-compose-credential-agent.sh
  PASS
deploy/compose/test-git-images.sh
  PASS
cargo fmt --all -- --check
  PASS
cargo clippy --all-targets -- -D warnings
  PASS
git diff --check
  PASS
```

The socket test required execution outside the filesystem sandbox because that
sandbox denies Unix socket creation. It exercised a real `UnixListener` and
`UnixStream`, fresh entropy, peer credentials in both directions, authenticated
framing, exact scope policy, and returned-token construction.

## Image and Compose evidence

The image was built locally with networking disabled from the two digest-pinned
bases:

```text
podman build --network none --pull=never \
  -f deploy/compose/Dockerfile.git-credential-agent \
  -t mrml/git-credential-agent:test .
```

- Image ID:
  `62b366e0ee72a09e4f1e445165de475787ffef51a4e4f0b235cc9b1db3374ecd`.
- User: `21007:21007`.
- Entrypoint: `/usr/bin/mrml-git-credential-agent`.
- Exported test archive SHA-256:
  `81eaf65fa3fef73ec5003fe789e8e8707765da2fba54ee35d4d7df1efe2ac5ba`.
- Syft SPDX JSON SHA-256:
  `a6b3e9e2ced67672878a729aa2e2b9bae0a7bcf1c791b447a9ab46e93ac18688`.

Podman Compose 1.5.0 accepted the complete model with non-secret test values.
A disposable, non-running runtime container inspection reported:

```text
user=21007:21007 network=none readonly_root=true pids=16 memory=67108864
cap_drop=all security_opt=no-new-privileges
```

The exact inspection container was removed afterward. The archive and generated
SBOM are disposable `/tmp` evidence, not signed release artifacts. The offline
builder now includes this fifth image in `mrml-images-git-v5`, generates its
Syft SBOM, signs its exported archive through the existing offline Cosign path,
and locks its expected user and entrypoint. A fresh complete signed bundle has
not yet been produced at these commits.

Patent review: **NOT_TRIGGERED**. This is conventional scope attenuation,
authenticated local IPC, peer-credential enforcement, bearer-token custody, and
container confinement using existing primitives. See
[`docs/patents/REVIEW_LOG.md`](../../patents/REVIEW_LOG.md).
