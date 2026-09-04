# Gitd Podman VPS validation — 2026-09-04

This additive record covers an owner-authorized, loopback-only deployment on
`mrml.ca`. It is controlled test evidence, not public production activation,
production-key evidence, real ACME/certd evidence, or independent review.

## Source and release inputs

- Branch: `main`.
- Listener-test commit: `cd5adc7f` (`http2: test hostile sequences on a TLS
  listener`). No repository push was performed.
- Runtime image source: signed offline bundle version `1796bfe2`.
- `SHA256SUMS` reverified every retained bundle artifact before loading.
- Podman loaded the four archives directly into its image store. The producer
  image identifiers were `57b17819b295` (authority), `5db461d2d671` (Gitd),
  `0316bcf7c33c` (protected signer), and `e3b17d9f1dd9` (backup).
- The test-only certd fixture was `f629c07db740`. It is not present in the
  production Compose model.

The exact release-snapshot `mrml-git` binary was placed in a disposable client
image tagged `mrml/git-client:1796bfe2`; that client image is test apparatus and
is not part of the signed daemon bundle.

## Runtime selection and volume handling

Docker Snap 29.6.1 remained installed and its four pre-existing controlled
containers remained running. Its AppArmor policy had previously rejected the
production `no-new-privileges` setting before process entry. Podman 5.7.0 and
podman-compose 1.5.0 were therefore installed alongside Docker Snap; Docker was
not removed, restarted, or reconfigured.

All Gitd, authority, fixture, public-CA, runtime-socket, and client-checkout data
used newly created `mrml-podman1796-*` named volumes. Controlled fixture data was
streamed directly from source Docker named volumes to distinct Podman named
volumes with numeric ownership preserved. No container data used a host bind
mount. Authority and certd runtime-socket volumes were newly initialized rather
than copying stale sockets.

The checked-in Git and signer Compose static gates passed. The combined Git and
ACME Compose model also rendered successfully under workstation Podman using
non-secret placeholders. Podman's direct `run` CLI rejected Compose's Docker
style `uid=` tmpfs option, so this VPS probe omitted `/tmp` tmpfs mounts rather
than weakening the read-only root or substituting a host directory. It is not a
claim that podman-compose exactly implements every production Compose option.

## Confinement and startup

The three server-side containers reached running state with fixed identities:

- authority `21002:21002`, `network=none`;
- test certd `21003:21003`, `network=none`;
- Gitd `21001:21001`, bridge network, with only
  `127.0.0.1:18445 -> 8443/tcp` published.

All three reported read-only roots, `no-new-privileges`, and every default
capability in Podman's drop set. Limits were 64/32/192 processes and
512 MiB/256 MiB/2 GiB respectively. Gitd logged, in order, valid startup
configuration, authenticated dependencies, authenticated identity, completed
recovery, bound listeners, and readiness. `listener-health` returned `ready`.

An independent OpenSSL probe verified TLS 1.3, `TLS_AES_128_GCM_SHA256`, the
`git.example.invalid` certificate, the fixture root, and X25519MLKEM768 key
agreement. The real listener HTTP library suite also passed 83 tests, including
the environment-gated hostile sequence campaign, in 70.11 seconds.

## Authenticated HTTP/2 clone

A one-hour, read-only `owner/project` token was issued by the isolated Gitd
administrator path and passed only over the client's standard input. It did not
appear in arguments, environment variables, or captured output. Native
`mrml-git` cloned through TLS 1.3/HTTP/2 into a fresh named volume and reported:

```text
Cloned https://git.example.invalid:18445/owner/project.git into checkout on branch main
head a1bdb799ebe94e9f6fabb16123ff212ca62ed432adaf376d832e6b4ab136a895
track origin/main  0 ahead  0 behind
clean — index matches working tree
```

The four checked-out payload hashes were:

```text
e5f33295c59bad4a81151b18b1a1d855c8743030e217d7f7195f674146181711  e2e.txt
e920fd08bf05fa56582314ae3348bb7e4365ebef014190aa0866013b5c803e10  e2e-generation-6.txt
a3692fee14be1e9a2e3c26b89df1dc8f04611808829a15681e9ba024fe4180d8  e2e-generation-7.txt
9c44ceb0c8adf0ac769598754ca095fe040a49186153d41dfc668a7dd41bfd09  e2e-generation-8.txt
```

Restarting only the authority preserved its named state and both dependency
health probes returned `dependencies-ready` without restarting Gitd. A forced
test-certd stop made dependency health fail closed while Gitd stayed running;
Gitd emitted bounded, jittered channel-retry delays up to the configured
30-second cap. Podman had to SIGKILL the fixture after its five-second stop
deadline, and that deliberately minimal fixture then failed its accept loop on
live reconnect. Recreating certd and Gitd with a fresh ephemeral
`runtime-certd-gitd-recovered` named volume restored `dependencies-ready` while
preserving every authoritative volume. This is exact authority-restart and
fail-closed outage evidence, but it is not a successful no-Gitd-restart certd
recovery claim; the native controlled outage test remains the evidence for that
behavior.

Podman's bridge DNS stalled and a disconnect/reconnect attempt left bridge data
delivery unreliable. The successful disposable client therefore used host
networking solely to reach Gitd's host-loopback publication, with an
`/etc/hosts` entry mapping the unchanged certificate name to `127.0.0.1`.
Certificate and hostname verification remained enabled. This limits the result:
it proves the confined server containers, named-volume persistence, real TLS/H2
listener, authentication, pack transfer, and native checkout, but does not prove
Podman inter-container DNS or a byte-for-byte podman-compose production start.

Public port 443 remains unbound. Production owner keys, production certificate
identity, a current production Cosign key, public DNS, real certd renewal, and
external security/cryptographic review remain required before activation.

Patent review: **NOT_TRIGGERED**. This increment uses conventional container
runtime isolation, named volumes, loopback publication, TLS, and HTTP/2 testing;
it introduces no substantial new mechanism. See
[`docs/patents/REVIEW_LOG.md`](../../patents/REVIEW_LOG.md).
