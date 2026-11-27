# MRML

MRML—the **Mitchell Renouf Machine Learning Library**—is an experimental
operating-system, compiler, and machine-learning project written from first
principles in dependency-free Rust.

MRML is AI-led and human-directed. Its goals include owner sovereignty,
capability-based security, accessible computing, isolated services, and a small
trusted dependency surface. It is research software, not a production-ready
operating system or a complete replacement for Rust, established codecs, or
existing inference systems. MRML’s only supported operating mode is strict
[Total MicroVM isolation](docs/ISOLATION_PLACEMENT.md): ordinary services and
applications run in supervised microVMs, without native fallback. Full-system
Total operation is not yet implemented.

The [MRML Gigakernel](docs/GIGAKERNEL.md) is named after Gigachad. It is the
capability-based kernel at the center of Total MicroVM isolation. It shares a
microkernel's small privileged core and Hyperkernel's use of hardware
virtualization, but MRML's defining rule is to require admitted microVMs for
ordinary apps and services, with no native fallback. See the
[architecture comparison](docs/GIGAKERNEL.md#how-the-gigakernel-compares).

The project is dedicated to the public domain under [CC0](LICENSE).

## Documentation

The following documents are written for people and form the recommended reading
order.

| Document | Purpose |
| --- | --- |
| [Project overview](docs/human/OVERVIEW.md) | What MRML is, its goals, maturity, and current platform limits |
| [Project status](docs/PROJECT_STATUS.md) | What is implemented, what has been tested, and what remains open across the project |
| [Getting started](docs/human/GETTING_STARTED.md) | How to obtain the source and prepare the supported local toolchain |
| [UEFI USB bring-up](docs/platform/UEFI_BOOT_MANAGEMENT.md#bare-metal-usb-bring-up) | How to verify the firmware handoff and embedded FAT32 test on a spare USB stick |
| [Verify every commit](docs/human/VERIFY_COMMITS.md) | How to verify every commit on GitHub with the project’s Ed25519 SSH signing key |
| [Contributing](docs/human/CONTRIBUTING.md) | The practical rules for making and reviewing changes |
| [Documentation map](docs/human/DOCUMENTATION.md) | Architecture, security, compiler, platform, and evidence records |

Detailed technical records intended primarily for tools, maintainers, and
auditors are indexed separately in the
[machine documentation](docs/machine/README.md). Those records preserve exact
invariants and evidence without making this README difficult to read.

## Homepage, source, and contact

- Homepage: [mrml.ca](https://mrml.ca)
- Source: [github.com/mitchellmachine/mrml](https://github.com/mitchellmachine/mrml)
- Releases: [MRML releases](https://github.com/mitchellmachine/mrml/releases)
- Contact:
  [mitchellrenouf@mrml.ca](mailto:mitchellrenouf@mrml.ca)

MRML is now hosted on GitHub at [mitchellmachine/mrml](https://github.com/mitchellmachine/mrml).

## Security review

MRML maintainer Mitchell Renouf has access to OpenAI Daybreak, which can
automatically scan connected code for potential security flaws. Automated
findings are leads for review, not proof of a vulnerability or a guarantee
of security. See [MRML's security model](docs/SECURITY.md) for scope and limits.

## Important limitations

MRML does not currently claim production security, complete compiler or codec
compatibility, physical GPU isolation, formally verified behavior, confidential
computing, or broad physical-hardware support. Every support claim must identify
the exact environment and test that produced its evidence.

For detailed status and evidence, begin with the
[documentation map](docs/human/DOCUMENTATION.md).
