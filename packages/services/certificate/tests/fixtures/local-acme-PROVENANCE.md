# Local ACME PKIX fixture provenance

These independently generated test certificates were created on 2026-09-01
with the system OpenSSL command-line oracle. The root and leaf use P-256 and
ECDSA with SHA-256. The leaf has the sole SAN `git.example`, critical digital
signature key usage, TLS server-auth EKU, a non-CA basic constraint, subject
and authority key identifiers, and serial 2. The root has serial 1, a critical
CA/path-length constraint, and critical certificate-signing/CRL-signing usage.

The private fixture keys were generated in a temporary directory and were not
copied into the repository. These public certificates are test inputs only;
OpenSSL is not a runtime dependency or part of the authoritative ACME path.
