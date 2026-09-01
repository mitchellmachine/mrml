# ACME certificate service

**Status: PARTIALLY IMPLEMENTED.** The shared bounded semantic foundation exists;
the deployed certificate lifecycle service does not. MRML must not yet be used
to obtain or deploy a public certificate.

The initial `org.mrml.library.acme` package is one logical package with MRML,
Windows, and Linux targets. It currently provides allocation-free bounded types
for normalized ASCII DNS identifiers, explicitly authorized wildcards,
HTTPS ACME endpoint origins, directory-generation-bound one-use nonces,
directory-generation-bound profile identities, ARI renewal windows, and
fail-closed account/order transitions. It also implements strict unpadded
Base64url, P-256 public-point admission, canonical EC JWK thumbprints,
deterministic ACME protected headers with exactly one of `jwk` or `kid`, raw
ES256 scalar bounds, purpose-typed signing approval, and flattened JWS output.
It parses a bounded ACME directory, rejects duplicate or cross-origin endpoint
authority, records current profile advertisements by directory generation, and
supports non-exporting HS256 external-account binding. The account lifecycle
separates staging and production policy, binds Terms-of-Service approval and
EAB presence to creation, and uses generation-bound prepare/commit receipts for
creation, contact updates, key rollover, deactivation, and uncertain-result
reconciliation.
Orders bind a sorted exact identifier set, account and directory generations,
profile generation, same-origin order/finalization/certificate URLs, bounded
poll retries and deadlines, and one authorization URL per identifier. Stale or
substituted authorization responses fail closed; wildcard authorization selects
DNS-01; finalization requires every exact authorization to be valid and uses a
one-use CSR-digest receipt.
Challenge publication now has a shared capability-oriented contract binding the
exact order URL digest, authorization URL digest, identifier, challenge kind,
token, key-authorization digest, policy generation, activation window, and
publisher receipt. Publication and cleanup are prepare/commit operations;
uncertain cleanup remains represented until authoritative publisher re-read.
Wine exercises the Windows target; Wine is not a separate platform
implementation or native-Windows evidence.

The bounded PKCS#10 encoder now emits an empty subject, exact P-256 SPKI, and an
extension-request containing only the sorted owner-approved SAN identifiers.
An experimental P-256 signing path implements rejection-sampled keys, RFC 6979,
low-S output, strict DER, self-verification, and volatile buffer clearing, but it
is excluded from ordinary feature profiles because the inherited curve
arithmetic remains variable-time and has not passed independent cryptographic
review.

General JOSE response and problem-document parsing, X.509 issuance validation,
ACME transport, concrete HTTP/TLS-ALPN/DNS publishers, durable recovery,
certificate publication, renewal,
revocation, backup/restore, CLI administration, gitd hot reload, and the MRML
certificate service remain **PLANNED**. The shared state machine must
remain independent of `std::fs`, `std::net`, Win32 handles, and syscall numbers.
Future platform adapters belong inside these logical packages and must not fork
their public semantics.

The owner supplied a Canada-first claim screen and applicable IETF-disclosure
review dated 2026-09-01 with engineering classification
`REVIEWED_NOT_BLOCKING`; the exact disposition and re-review triggers are in
`docs/patents/REVIEW_LOG.md`. Formal legal freedom-to-operate review was not
performed. Cryptographic implementation still requires its independent
security-review plan and exact constant-time/zeroization evidence. Failure of
those gates is fail closed: there is no fallback to Certbot, a third-party ACME
client, RSA certificate keys, raw production key files, or a self-signed
production identity.

Let’s Encrypt issues public TLS certificates. It does not sign MRML Git commits,
tags, packages, applications, or source locks. ACME account keys, certificate
keys, Git signing keys, and audit-receipt keys are separate roles and must never
share key material.
