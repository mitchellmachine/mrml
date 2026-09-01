# ACME certificate service

**Status: PARTIALLY IMPLEMENTED.** The shared bounded semantic foundation exists;
the deployed certificate lifecycle service does not. MRML must not yet be used
to obtain or deploy a public certificate.

The initial `org.mrml.library.acme` package is one logical package with MRML,
Windows, and Linux targets. It currently provides allocation-free bounded types
for normalized ASCII DNS identifiers, explicitly authorized wildcards,
HTTPS ACME endpoint origins, directory-generation-bound one-use nonces,
directory-generation-bound profile identities, ARI renewal windows, and
fail-closed account/order transitions. Wine exercises the Windows target; Wine
is not a separate platform implementation or native-Windows evidence.

Private-key operations, JOSE/JWS/JWK, PKCS#10, X.509 issuance validation, ACME
transport, accounts, challenges, durable recovery, certificate publication,
renewal, revocation, backup/restore, CLI administration, gitd hot reload, and
the MRML certificate service remain **PLANNED**. The shared state machine must
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
