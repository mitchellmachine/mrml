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
paired channel capability files. It also creates a distinct backup-authentication
key owned only by the one-shot administration identity; that key is not mounted
into certd or acmed. It deliberately does not invent the Cloudflare API token or
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
install -m 0600 .env.production.example .env.production
# Edit .env.production and set the exact release version.
./validate-acme.sh
./start-acme.sh
./status-acme.sh
```

For an image-only upgrade or rollback, preload both images for the exact
version, then run the corresponding command as root. Both services must become
healthy before the new immutable version receipt is committed. Rollback changes
only the container images; authenticated certificate and ACME lifecycle state
is never rolled backward:

```text
sudo ./upgrade-acme.sh NEW_VERSION
sudo ./rollback-acme.sh PREVIOUS_VERSION
```

To force an authenticated renewal without editing durable state by hand, first
obtain a preview. The commit form stops the long-running worker, revalidates the
preview against the current authenticated schedule in a one-shot container,
commits the immediate schedule, and restarts the worker:

```text
./renew-acme.sh preview
./renew-acme.sh commit APPROVAL_SHA256_FROM_PREVIEW
```

A stale preview is rejected. This command does not bypass candidate validation
or activation policy; it only advances the next renewal attempt to the current
time.

After an interrupted order, exact DNS-01 values recorded in authenticated
challenge receipts can be cleaned with the worker stopped. The provider removes
only the matching value and preserves unrelated TXT values:

```text
./cleanup-acme-dns.sh confirm-exact-records
```

Certificate revocation uses an active-generation preview and an exact approval
digest. The commit form stops acmed while the durable revocation transaction is
submitted and restarts it on both success and failure:

```text
./revoke-acme.sh preview key-compromise
./revoke-acme.sh commit key-compromise APPROVAL_SHA256_FROM_PREVIEW
```

Do not retire or destroy the corresponding key merely because revocation was
requested; first confirm the terminal revocation state with `status-acme.sh`.

Compose cannot enforce a destination-aware outbound firewall. Apply host or
upstream egress policy for the configured ACME and DNS-provider origins. The
networkless certd design ensures that compromise of acmed does not reveal an
exportable TLS or ACME account private key.
