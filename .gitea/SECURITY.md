# MRML Security Policy

## Supported versions

MRML is experimental research software and does not currently publish stable,
production-supported releases. Security fixes are made on a best-effort basis
to the current `main` branch. Older commits, forks, and locally modified builds
are not supported.

| Version | Supported |
| --- | --- |
| Current `main` branch | Best effort |
| Older commits or releases | No |

MRML must not be treated as a production-secure operating system, trusted
compiler, cryptographic product, confidential-computing boundary, or complete
codec and protocol implementation. See the repository README and the relevant
design documents for the current threat models, security claims, and known
limitations.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's
**Security** tab by selecting **Report a vulnerability**:

<https://github.com/mitchellrenouf/mrml/security/advisories/new>

If private vulnerability reporting is unavailable, open a public issue asking
the maintainer to establish a private contact channel. Do not include exploit
details, secrets, personal data, or other sensitive information in that issue.

Include enough information to reproduce and assess the problem when possible:

- the affected commit, crate, component, feature set, and platform;
- the expected and observed behavior;
- a minimal reproducer or precise reproduction steps;
- the security impact and the trust boundary that is crossed;
- relevant logs or diagnostics with credentials and private data removed; and
- any known mitigations or prerequisites.

Reports about memory safety, cryptography, signing and artifact admission,
parsers, virtualization boundaries, protected execution, boot, kernel
isolation, capability enforcement, network protocols, model or device inputs,
and secret handling are especially useful.

## Disclosure and response

Please allow time for the report to be reproduced, scoped, and corrected before
public disclosure. The maintainer may request additional information, discuss a
coordinated disclosure date, and credit the reporter if requested. No response
time, remediation deadline, bounty, or production support commitment is
currently guaranteed.

Reports that demonstrate a gap between documented claims and actual behavior
are welcome. Claims that depend on physical hardware, Linux, Windows VBS, VTL1,
TPM, IOMMU, KVM, WHP, or bare-metal execution must identify the environment and
evidence used; simulated or controlled probes are not hardware verification.
