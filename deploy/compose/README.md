# MRML certificate deployment

This directory defines the isolated Linux/amd64 certificate and ACME worker
images and the image-only Compose fragment. It does not redefine Gitd or the Git
authority. The certificate daemon has no network namespace; the ACME worker has
outbound connectivity but no published port. Neither service receives the
Docker socket or a repository mount.

The runtime base is the shell-free `distroless/cc-debian12` amd64 manifest
`sha256:777e96cf322c46bc32aca926c263624c4dc8d7cf37e2fa65ba2c7e697318ebbb`.
The throwaway binary-verification stage is Debian bookworm-slim amd64 manifest
`sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867`.
Re-verify both digests against their authoritative registries before an
intentional base update.

On a trusted offline build workstation, first run the repository's complete
gates and build the two release binaries, then build the images from the
repository root:

```text
target/release/mrml build org.mrml.service.certificate --target linux --release
target/release/mrml build org.mrml.service.acme --target linux --release
docker buildx build --platform linux/amd64 --network=none --load \
  -f deploy/compose/Dockerfile.certd -t mrml/certd:VERSION .
docker buildx build --platform linux/amd64 --network=none --load \
  -f deploy/compose/Dockerfile.acmed -t mrml/acmed:VERSION .
```

Set `COSIGN_KEY` and `COSIGN_PUBLIC_KEY` to an offline signing keypair, then use
the bounded bundle builder (the output path must not already exist):

```text
COSIGN_KEY=/secure/cosign.key COSIGN_PUBLIC_KEY=/secure/cosign.pub \
  deploy/compose/build-offline-acme-bundle.sh VERSION /absolute/mrml-acme-VERSION.tar
```

The production VPS consumes that separately checksummed offline bundle containing
the two saved images, the Compose file, configuration, SBOMs, signatures, and
verification material. It must not receive the source tree, Rust toolchain,
Cargo cache, private keys, provider credential, account metadata, certificate
state, challenge state, or test-CA material.

Provision and verify host paths as root. `MRML_DEPLOY_ROOT` defaults to
`/mnt/mrml` and may only select another path below `/mnt`:

```text
sudo deploy/compose/provision-acme-host.sh
```

The script creates a fresh certd unlock key, acmed state-authentication key, and
paired channel capability files. It deliberately does not invent the Cloudflare API token or
production policy files. Install `cloudflare-api-token` as `21004:21004` mode
`0400`; install `certd.json` and `acmed.json` as `0:0` mode `0444`; then rerun
the script. Docker Compose bind mounts do not encrypt secrets.

On the VPS, extract the bundle into a new empty directory, verify it before
loading either image, and inspect the recorded image identities:

```text
./verify-offline-acme-bundle.sh .
docker load -i images/certd.tar
docker load -i images/acmed.tar
cat images/certd.identity images/acmed.identity
```

After installing and rechecking configuration and secrets:

```text
export MRML_ACME_VERSION=VERSION
docker compose -f compose.acme.yml config
docker compose -f compose.acme.yml up -d --no-build --pull never
```

Compose cannot enforce a destination-aware outbound firewall. Apply host or
upstream egress policy for the configured ACME and DNS-provider origins. The
networkless certd design ensures that compromise of acmed does not reveal an
exportable TLS or ACME account private key.
