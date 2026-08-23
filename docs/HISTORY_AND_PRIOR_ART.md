# History and Prior Art

MRML is a clean-slate operating-system project, but its ideas did not appear
in isolation.

Many of MRML's individual architectural principles have important historical
predecessors. This document records those influences and distinguishes prior
work from the particular combination MRML is exploring.

It is not intended to establish patent freedom, legal novelty, or priority of
invention.

## Capability systems

Capability-based operating systems long predate MRML.

KeyKOS, EROS, and CapROS developed operating-system architectures in which
authority is represented through capabilities rather than conventional ambient
identity-based access.

CapROS continues the EROS line and combines capability security with a small,
reliable operating-system architecture and persistent objects.

MRML inherits the broad lesson that possession of an object name should not
itself grant authority to that object.

MRML's rule:

> Names identify. Capabilities authorize.

should therefore be understood as part of a long capability-system tradition,
not as an invention unique to MRML.

References:

- CapROS: https://www.capros.org/
- CapROS architecture/background: https://www.capros.org/overview.html

## seL4

seL4 demonstrates that a capability microkernel can simultaneously pursue
fine-grained authority, high performance, and unusually strong formal
assurance.

MRML does not claim to originate capability microkernels or high-assurance
microkernel isolation.

MRML differs in scope: it is attempting to build a complete general computing
environment above its kernel, including native applications, virtualization,
graphics, accessibility, AI interaction, and a first-party compiler.

Reference:

- https://sel4.org/

## Genode and Sculpt OS

Genode is one of the closest predecessors to MRML's broader security
architecture.

Genode combines microkernels, capability-based security, least-authority
components, userspace device drivers and system services, hierarchical
sandboxing, virtualization, and GUI infrastructure.

Its architecture demonstrates that filesystems, network stacks, drivers,
virtual machines, and applications can exist as separately isolated components
rather than as one monolithic privileged operating system.

MRML shares many of these goals.

MRML differs by making its capability-bound object system, memory-safe native
application policy, semantic desktop, accessibility model, and AI authority
model parts of one integrated native architecture.

References:

- https://genode.org/
- https://genode.org/documentation/genode-foundations/

## Qubes OS

Qubes OS is an important predecessor for application compartmentalization and
secure GUI composition.

Qubes executes applications in distinct VM security domains while projecting
their windows onto a common desktop. Host-controlled domain indicators prevent
an untrusted VM from freely impersonating a more trusted domain.

MRML deliberately carries forward the principle that strong isolation should
not require users to operate a collection of disconnected desktops.

MRML differs by placing this idea inside a capability-native operating system
rather than building primarily around conventional guest operating systems.

References:

- https://www.qubes-os.org/
- https://doc.qubes-os.org/en/latest/developer/system/architecture.html

## Microsoft Research Singularity

Microsoft Research's Singularity project is important prior art for
language-based operating-system safety.

Singularity used type-safe languages, software-isolated processes,
contract-based communication, sealed processes, compiler/runtime validation,
and executable metadata to improve operating-system reliability and security.

It demonstrates that compiler-established properties can participate directly
in an operating system's security architecture.

MRML therefore does not claim to have invented compiler/OS security co-design.

MRML's planned distinction is to combine a first-party Rust compiler and
compiler-derived executable properties with capability-native authority,
hardware isolation, VM compartmentalization, and its application admission
model.

References:

- https://www.microsoft.com/en-us/research/project/singularity/
- https://www.microsoft.com/en-us/research/publication/sealing-os-processes-to-improve-dependability-and-security/

## Theseus

Theseus explores an operating system written in Rust whose architecture uses
language-level mechanisms to let the compiler enforce operating-system
invariants.

This "intralingual" approach is an important predecessor to MRML's interest in
allowing a compiler and operating system to reinforce one another.

MRML differs in authority, process, virtualization, GUI, and AI architecture.

Reference:

- https://www.usenix.org/conference/osdi20/presentation/boos

## Oberon and whole-system design

The Oberon system is an important example of vertically integrated computing.

Niklaus Wirth and Jürg Gutknecht designed the language, compiler, operating
system, and user environment as a coherent system.

Oberon demonstrates that operating-system and language/toolchain design need
not be treated as unrelated projects.

MRML similarly values whole-system understandability while pursuing a
substantially different security and hardware architecture.

## TempleOS

TempleOS and Terry A. Davis are acknowledged separately in
[`EULOGY.md`](../EULOGY.md).

The TempleOS influence on MRML is whole-system coherence and the demonstration
that an unusually large portion of a computing environment can be understood
and implemented as one intentional system.

MRML does not adopt TempleOS's privilege or isolation model.

MRML deliberately chooses memory safety, capability security, hardware
isolation, userspace services, virtualization, and defensive engineering.

## Semantic accessibility interfaces

Semantic user-interface representations also predate MRML.

Microsoft UI Automation exposes desktop user-interface elements as a semantic
hierarchy containing properties, control roles, supported actions, and events.
Accessibility technologies and automation tools can consume that tree.

Web accessibility standards likewise define mappings from web semantics into
platform accessibility APIs.

MRML does not claim to have invented semantic accessibility trees.

References:

- Microsoft UI Automation: https://learn.microsoft.com/en-us/windows/win32/winauto/ui-automation-specification
- W3C Core Accessibility API Mappings: https://www.w3.org/TR/core-aam/

## Semantic interfaces for AI

Recent AI systems increasingly reuse accessibility and automation metadata to
avoid relying exclusively on screenshots and coordinate-based interaction.

LUMOS, published in 2026, describes a semantic operating-system layer that
converts native accessibility metadata and browser UI structures into compact
machine-readable representations for language-model agents.

This is important prior work for the idea that accessibility semantics can
also make computers easier for AI to understand.

MRML's intended distinction is architectural.

Rather than treating semantic information as a compatibility layer extracted
from an otherwise visual operating system, MRML intends for semantic state to
be a native part of its graphical/application architecture.

Conceptually:

```text
                 application state
                        |
                 semantic objects
                        |
          +-------------+-------------+
          |             |             |
        visual        Braille        speech
          |
          +------------------------- AI
```

Presentation differs between these consumers, but the underlying semantic
truth should remain shared.

Reference:

- [LUMOS: A Semantic Operating-System Layer for Accessibility-Grounded AI Agents](https://arxiv.org/abs/2606.30697)

## Agent-native operating systems

MRML is also not the only contemporary project exploring operating systems for
AI agents.

Projects including Oxide OS and agentOS explore kernel-enforced capabilities,
agent isolation, IPC, supervision, and resource-specific authority.

MRML therefore does not claim to be the first capability-oriented or
microkernel-oriented operating system intended for AI agents.

MRML differs in treating AI as one class of principal within a general
human-computing architecture rather than making agents inherently privileged
or making agent execution the sole purpose of the system.

An AI may be highly intelligent while possessing very little authority.

MRML summarizes this as:

> Intelligence does not imply authority.

References:

- Oxide OS: https://github.com/gkganesh12/oxide-os
- agentOS: https://github.com/jordanhubbard/agentos

## AI-developed operating systems

The use of coding agents to construct operating systems is itself no longer
unique.

Projects such as SlopOS demonstrate that modern coding agents can construct
substantial Rust kernels and userspace systems.

MRML therefore should not define its identity around being "AI-written" or
"vibe-coded."

How MRML is implemented is less important than the resulting architecture and
its demonstrated properties.

Reference:

- https://slopos.sloplabs.net/

## The combination MRML is exploring

MRML's possible novelty lies primarily in combination rather than in any one
component.

The project combines:

1. capability-bound objects as the common authority model;
2. memory-safe ordinary native applications;
3. explicit VM containment for unsafe and legacy application environments;
4. a small isolated-service operating-system structure;
5. a trusted compositor and semantic scene graph;
6. visual, keyboard, speech, Braille, automation, and AI interfaces derived
   from common semantic state;
7. capability-constrained local and remote AI principals;
8. secret use authority separable from secret extraction;
9. a first-party forward-looking Rust compiler intended eventually to emit
   security properties consumed by the OS loader.

We have not identified an earlier operating system combining all of these
properties as one native architecture.

That statement is deliberately narrower than claiming that MRML invented
capabilities, memory-safe operating systems, virtualization, semantic
accessibility, AI computer control, or compiler/OS co-design.

If earlier work is discovered, this document should be updated to credit it.

Historical accuracy is more important than preserving a novelty claim.

## Novelty is not the success criterion

Being first is not a security property.

A predecessor does not make an architecture less useful, and novelty does not
make an implementation correct.

MRML's important claims must ultimately be demonstrated through:

- working code;
- tests;
- measurements;
- adversarial testing;
- hardware evidence;
- accessibility testing; and
- where appropriate, formal analysis.

The project's goal is not to win a historical-first claim.

The goal is to build the system.
