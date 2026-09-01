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
Typed ACME problem documents and bounded subproblems are parsed with duplicate
singleton rejection, bounded body/token/depth/text limits, strict HTTP status
ranges, trailing-data rejection, and explicit `badNonce` classification.
Challenge publication now has a shared capability-oriented contract binding the
exact order URL digest, authorization URL digest, identifier, challenge kind,
token, key-authorization digest, policy generation, activation window, and
publisher receipt. Publication and cleanup are prepare/commit operations;
uncertain cleanup remains represented until authoritative publisher re-read.
The bounded HTTP-01 request validator accepts only an exact `GET` challenge
path and exact Host (optionally port 80), rejects percent/query/path ambiguity,
duplicate Host fields, oversized requests, and excess headers, and compares the
active token without data-dependent early exit.
The TLS-ALPN-01 encoder emits a bounded P-256 self-signed certificate with an
empty subject, one critical dNSName SAN, and the exact critical RFC 8737
`acmeIdentifier` OCTET STRING. Signing is purpose- and generation-bound. ALPN
selection rejects `acme-tls/1` unless the exact active SNI is present and never
falls back to an ordinary production identity.

`org.mrml.service.certificate` is now one Manifest V2 service package targeting
MRML, Windows, and Linux. Its first confined runtime role is a bounded,
non-recursive authoritative DNS-01 challenge zone. The shared implementation
serves SOA, NS, TXT, and nameserver A responses over DNS UDP messages and TCP
framing, supports concurrent TXT values, binds mutations to policy and record
generations, expires records, rejects malformed/compression-loop input, refuses
out-of-zone recursion, and returns truncated UDP responses when necessary.
The DNS role implements the shared challenge-publisher contract: preparation
does not publish, activation inserts the exact TXT digest, cleanup removes the
exact record generation, and successful removal releases bounded publisher
capacity. Multiple authorization-bound records remain independently scoped.
Certificate-chain retrieval has a strict fixed-capacity PEM decoder and a
shared validation policy/receipt. The hosted first-party X.509 adapter verifies
the exact P-256 SPKI, exact sorted SAN set with no extra GeneralNames, TLS server
purpose, explicit validity bounds, supported critical extensions, bounded path
length, signatures to explicitly supplied owner-approved roots, CA class,
profile, order digest, policy generation, and trust-store digest before issuing
a verified-chain receipt. The MRML target builds the same policy and verifier
interface without inheriting a host ambient trust store. Checked-in leaf/root
fixtures were independently generated with the OpenSSL CLI solely as a test
oracle; no fixture private key is retained or shipped.
The identity manager exposes an identity-scoped consumer capability for
description, bounded chain reads, generation observation, and acquisition of a
use-only TLS signing route. The route binds identity generation, key identity,
route generation, and an opaque capability identifier; TLS 1.3
CertificateVerify approval binds the exact transcript digest and standard
server context. Deployment persists a prepared candidate before publication,
requires separate TLS 1.3 and HTTP/3-over-QUIC-v2 test evidence, activates only
the exact prepared generation, retains the previous generation, and represents
ambiguous activation until authoritative target re-read resolves it.
Wine exercises the Windows target; Wine is not a separate platform
implementation or native-Windows evidence.

The bounded PKCS#10 encoder now emits an empty subject, exact P-256 SPKI, and an
extension-request containing only the sorted owner-approved SAN identifiers.
An experimental P-256 signing path implements rejection-sampled keys, RFC 6979,
low-S output, strict DER, self-verification, and volatile buffer clearing, but it
is excluded from ordinary feature profiles because the inherited curve
arithmetic remains variable-time and has not passed independent cryptographic
review.

General JOSE response parsing, ACME transport, concrete socket adapters and
propagation observation, durable recovery, alternate-chain selection,
durable identity-state serialization, renewal, revocation, backup/restore, CLI
administration, concrete gitd hot reload, and the MRML
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
