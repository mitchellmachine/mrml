# Protected signer volume-native key generation — 2026-09-04

Status: implemented and verified with controlled non-production keys on local
Linux/rootless Podman and the authorized `mrml.ca` Linux/rootful Podman host.
This is not production-key, public-service, current protected-push, key-rotation,
physical-hardware, or independent-review evidence. No repository push was
performed.

## Implementation

Signed functional commit `4cdf8150` adds the signer binary's one-shot
`generate-key-material` operation and packages
`generate-git-signer-keys.sh` in the offline Git bundle. It draws independent
runtime entropy for the OpenPGP v6 seed and ML-DSA-65 keypair, derives the
OpenPGP public key inside the signer process, and writes only four fixed names
to one exact owner-controlled absolute directory. Outputs use exclusive create,
single-link regular-file checks, exact UID `21006`, exact `0400` private and
`0444` public modes, file synchronization, and directory synchronization.
Failure removes only outputs created in the initially empty trusted directory;
an existing output makes the operation fail closed without replacement.
Secret buffers and the OpenPGP signing-key object are erased on drop.

Signed commits `0c26f6cb` and `6970d8d9` make the wrapper use Docker's
`volume-nocopy` spelling or Podman's `:nocopy` spelling and require an explicit
`MRML_CONTAINER_RUNTIME=docker|podman` selection when the default Docker store
is not the intended store. There is no registry, bind mount, source checkout,
compiler, private-key upload, or general-purpose shell in the runtime image.

## Focused verification

```text
cargo fmt --all -- --check                                      PASS
cargo clippy --all-targets -- -D warnings                       PASS
git diff --check                                                PASS
sh -n deploy/compose/generate-git-signer-keys.sh                 PASS
deploy/compose/test-compose-signer.sh                           PASS
./target/debug/mrml test org.mrml.tool.git --target linux       PASS
  Git library: 273 passed
  Git CLI: 5 passed
  protected signer: 8 passed
  credential agent: 2 passed
```

The added signer test independently parses the generated OpenPGP public key,
re-derives it from the protected seed, signs and verifies with the generated
ML-DSA pair, verifies every exact size/owner/mode/link invariant, and proves a
second generation attempt neither succeeds nor replaces the seed.

## Exact container probes

The release signer binary was built from a clean detached worktree at
`4cdf8150`. The network-disabled image build produced:

```text
image: localhost/mrml/git-protected-signer:4cdf8150
ID:    542831ea16c66b61cd7a6d282070eddf0508be5fcf52d84136a56337c7ee940e
user:  21006:21006
entry: /usr/bin/mrml-git-protected-signer
```

A local isolated invocation used a fresh named volume, `network=none`, a
read-only root, all capabilities dropped, `no-new-privileges`, 16 PIDs,
256 MiB, half a CPU, and only the named key volume as writable storage. It
created a 32-byte mode-`0400` OpenPGP seed, 140-byte mode-`0444` OpenPGP public
key, 1,952-byte mode-`0444` ML-DSA public key, and 4,032-byte mode-`0400`
ML-DSA secret, all owned by `21006:21006` with one link. A second invocation
returned exit 78 and the generic fail-closed diagnostic.

The same exact image was streamed over authenticated SSH directly into the VPS
Podman store. The image ID, configured user, and entrypoint matched locally.
Two fresh rootful Podman namespaces then exercised both the direct command and
the packaged wrapper. The retained controlled key volume is
`mrml-podman0c26-git-signer-keys`; the wrapper-specific disposable volume is
`mrml-podmanscript-git-signer-keys`. Both are Podman named volumes, not host
bind directories. The first volume reproduced the exact metadata above and its
overwrite attempt returned exit 78. The wrapper succeeded only after explicitly
selecting `MRML_CONTAINER_RUNTIME=podman`, proving it addressed the host's
separate Docker Snap and rootful Podman stores without guessing.

No private key or secret file content crossed SSH, appeared in arguments or
environment variables, or was printed. The current-image live signer
sign/restart/generation-advance sequence and a fresh end-to-end protected
receive remain separate pending gates and are not claimed here.

Patent review: **NOT_TRIGGERED**. This increment adds conventional local key
generation, exclusive filesystem creation, and container-volume orchestration;
it introduces no new signature algorithm or cryptographic construction. See
[`docs/patents/REVIEW_LOG.md`](../../patents/REVIEW_LOG.md).
