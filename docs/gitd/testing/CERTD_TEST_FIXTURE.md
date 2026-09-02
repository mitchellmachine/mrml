# Gitd certd test fixture

Status: **IMPLEMENTED** for hosted Linux testing only.

`org.mrml.test.gitd-certd-fixture` is a bounded real-process fixture for the
Gitd-to-certd version-1 Unix channel. Its package kind, executable names, and
diagnostics all contain `test-fixture` or `test-probe`. Neither production
Dockerfile nor `deploy/compose/compose.git.yaml` references this package.
Production deployments must use `mrml-certd`.

The fixture exists only to test Gitd independently while certificate issuance
and lifecycle work remains separately owned. It implements exactly the four
operations allowed to the Gitd role: health, identity snapshot,
TLS 1.3 CertificateVerify, and bounded generation wait. It does not implement
ACME, renewal, revocation, key export, arbitrary signing, or certificate
activation.

The `serve` process requires an absolute Unix-socket path, a single-link
32-byte capability file, exact nonzero peer identities, a lowercase DNS name,
a nonzero identity generation, a bounded request count, a DER leaf and issuer,
and a single-link 32-byte P-256 scalar file. Secret inputs must be owned by the
configured fixture owner and mode `0400` or `0600`. Before binding, the fixture
parses the leaf, checks its hostname, and proves that its P-256 public key is
the one in the certificate. The socket parent must be owner-controlled and
non-writable by group or others. Socket removal exact-matches the bound device
and inode.

The companion `mrml-gitd-certd-test-probe` uses the production Gitd certd
client. It checks health, obtains and independently validates the system-trusted
chain and publication digest, verifies a purpose-limited TLS 1.3 signing proof,
and checks the unchanged-generation wait response. A local test CA must be
provided through `MRML_CA_BUNDLE`; this is test process configuration and is
not a Gitd production identity fallback.

Evidence on 2026-09-02 used an ephemeral OpenSSL-generated P-256 CA and
`git.example` leaf under a mode-`0700` directory in `/tmp`. The fixture and
probe ran as UID/GID 1000 over a real Unix socket. The probe reported:

```text
mrml-gitd-certd-test-probe PASS generation=1
```

The fixture served exactly four authenticated exchanges and exited normally,
removing its socket. This proves the isolated hosted protocol path only. It is
not ACME, renewal/rotation, production-container, VPS, or public-network
evidence.

Focused command:

```text
./target/debug/mrml test org.mrml.test.gitd-certd-fixture --target linux
```

Result: one library test, two server-binary tests, and one probe-binary test
passed.

Patent review: **NOT_TRIGGERED**. The fixture composes already documented Unix
peer credentials, bounded HMAC-authenticated framing, X.509 parsing, SHA-256,
and TLS 1.3 ECDSA proof verification solely for testing. See
`docs/patents/REVIEW_LOG.md`.
