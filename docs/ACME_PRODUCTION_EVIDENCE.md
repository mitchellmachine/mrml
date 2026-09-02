# ACME and TLS identity production evidence

Evidence date: 2026-09-01  
Target: Linux x86_64, Docker Compose  
Component classification: **production candidate pending external runtime gates**

This file records executed evidence, unavailable environments, and remaining
implementation work. An unavailable gate is not a pass. Unit, deterministic
local-authority, hosted-process, container, public-CA, combined-stack, and
physical evidence are distinct.

## Executed gates

| Gate | Command | Result |
| --- | --- | --- |
| Manifest lock | `./target/debug/mrml manifest lock --check` | PASS: 70 packages, 5 interfaces |
| Manifest graph | `./target/debug/mrml manifest check` | PASS: 70 components, 209 dependencies |
| Certificate release build | `./target/debug/mrml build org.mrml.service.certificate --target linux --release` | PASS |
| Certificate focused tests | `./target/debug/mrml test org.mrml.service.certificate --target linux --release` | PASS: 133, fail: 0 |
| ACME service release build | `./target/debug/mrml build org.mrml.service.acme --target linux --release` | PASS |
| ACME service focused tests | `./target/debug/mrml test org.mrml.service.acme --target linux --release` | PASS: 14, fail: 0 |
| ACME library release build | `./target/debug/mrml build org.mrml.library.acme --target linux --release` | PASS |
| ACME library focused tests | `./target/debug/mrml test org.mrml.library.acme --target linux --release` | PASS: 81, fail: 0 |
| Security fuzz release build | `./target/debug/mrml build org.mrml.test.security-fuzz --target linux --release` | PASS with unrelated GPU warnings |
| Security fuzz tests | `./target/debug/mrml test org.mrml.test.security-fuzz --target linux --release` | PASS: 9, fail: 0 |
| Compose static policy | `deploy/compose/test-compose-acme.sh` | PASS |

The ACME library tests include a deterministic first-party local authority and
cover complete issuance, fresh-nonce rebuilding after `badNonce`, lost-response
recovery, account lookup/update/rollover, EAB, revocation replay, DNS-01 binding,
and strict origin/redirect handling. This is local in-process protocol evidence,
not a real-container or public-CA result.

Certificate tests cover keyed durable records, encrypted use-only P-256 keys,
candidate validation and activation, constrained TLS signing, Unix peer and
channel authentication, renewal/ARI/backoff, crash-boundary recovery, backup
container creation/verification/clean-target restoration, and generation hot
reload. Hosted Unix-socket tests ran with explicit sandbox elevation. They do
not prove the Docker namespace or mount configuration.

## Unavailable external gates

| Required gate | Classification | Exact reason |
| --- | --- | --- |
| Image build and inspection | NOT RUN — ENVIRONMENT UNAVAILABLE | `docker` is not installed on this host. No image ID or runtime inspection evidence exists. |
| SBOM production | NOT RUN — TOOL UNAVAILABLE | `syft` is not installed. |
| Offline image signing | NOT RUN — TOOL/CREDENTIAL UNAVAILABLE | `cosign` and an offline signing key are unavailable. |
| ShellCheck | NOT RUN — TOOL UNAVAILABLE | `shellcheck` is not installed; POSIX `sh -n` and focused behavior checks were run instead. |
| Root host provisioning | NOT RUN — AUTHORITY UNAVAILABLE | `sudo` requires an interactive password. The explicit disposable `/tmp` attempt created no files. |
| Public-CA staging issuance | NOT RUN — CONFIGURATION/CREDENTIAL UNAVAILABLE | No explicitly approved staging account, domain, authoritative DNS zone, or scoped provider credential was supplied. |
| Combined Gitd/certd Compose gate | NOT RUN — ENVIRONMENT UNAVAILABLE | Docker and the real combined running stack are unavailable. Static interface tests do not substitute for TLS handshakes, clone/fetch/push, hot rotation, or restart evidence. |
| Image upgrade/rollback runtime exercise | NOT RUN — ENVIRONMENT UNAVAILABLE | Immutable images cannot be loaded or started without Docker. |
| Native Windows production certification | DEFERRED | Outside this Linux production target and explicitly deferred by the task. |
| Physical hardware | NOT RUN / NOT APPLICABLE | No physical-hardware claim is made for this hosted Linux service. |

## Remaining implementation gate

The shared certificate library implements authenticated backup containers,
bounded transfer, verification, and clean-target restore with focused tests.
The production Compose topology does not yet wire a real multi-principal
one-shot backup provider spanning certd-owned encrypted key state, acmed-owned
authenticated lifecycle state, publication records, and channel metadata.
`backup-auth.key` is separately provisioned as equal mode-`0400` copies for the
certd, acmed, and administration identities. The service copies are mounted
only into future stopped-service backup operations, never either daemon. A root `tar` wrapper is not an acceptable
substitute because it would bypass the use-only provider boundary and would not
prove record/key/generation consistency before activation.

Until this provider and the external container gates are exercised, the
accurate classification is **ACME/certd production candidate pending backup and
Gitd integration**, not complete-stack production-ready.

## Security and IPR residuals

No independent security audit or independent cryptographic review has been
performed. Avoidable secret copies are erased and production keys are use-only,
but no independent constant-time claim is made. Compose cannot enforce
destination-aware egress; deployment requires host or upstream policy for the
approved ACME and DNS-provider origins.

Patent review: **NOT_TRIGGERED** for continued scoped engineering. See
[`patents/ACME_CERTIFICATE_REVIEW_2026-09-01.md`](patents/ACME_CERTIFICATE_REVIEW_2026-09-01.md)
and [`patents/REVIEW_LOG.md`](patents/REVIEW_LOG.md). Formal legal FTO was not
performed.
