# MRML history and bounded prior-art comparisons

This document records inspiration and comparison boundaries. It does not claim
compatibility, equivalence, endorsement, or novelty over the systems named
here. Current implementation and evidence are reported separately in
[STATUS.md](STATUS.md), [MICROKERNEL.md](MICROKERNEL.md), and the source tree.

## Project origin

MRML began as a repository-owned local machine-learning runtime. Its scope grew
outward into codecs, cryptography, network protocols, development tools,
virtualization, verified boot, and an experimental operating system. The
consistent objective is a coherent stack with explicit authority, bounded
inputs, memory-safe implementation, reproducible artifacts, and evidence that
distinguishes design from execution.

## TempleOS

TempleOS is historical inspiration for whole-system coherence, directness, and
the possibility of understanding a large personal computing system end to end.
MRML does not reuse TempleOS code or adopt its single-address-space design,
privilege model, language, or hardware assumptions. The dedicated
[EULOGY.md](../EULOGY.md) records this inspiration without making it
architectural policy.

## Qubes OS

Qubes demonstrates security-oriented compartmentalization and trusted desktop
composition. MRML shares the goal of visible isolation and mediated interaction,
but it is not a Qubes derivative and does not claim Qubes compatibility. MRML's
planned model combines capability-mediated objects, optional microVM placement,
repository-owned services, and an accessibility/AI semantic interface.

## Genode and capability microkernels

Genode and capability-oriented microkernel research demonstrate how small
trusted mechanisms, explicit authority, and userspace services can structure an
operating system. MRML independently applies those broad principles through its
own interfaces, package model, policy language, and implementation. Similar
terminology is not evidence of identical semantics or assurance.

## Android

Android is relevant as a comparison for application identities, per-user or
profile-separated state, immutable system generations, and independently
updated system components. MRML does not implement the Android framework, Linux
kernel ABI, APK runtime, or Android security model. Its package, principal,
capability, and VM-placement contracts are repository-specific.

## Windows

Windows informs usability goals such as a consistent high-DPI desktop,
administration tooling, broad hardware management, and familiar system
workflows. MRML does not promise Win32 compatibility and does not treat visual
familiarity as authority. Its GUI composition, application API, package model,
and security boundaries are distinct.

## OpenBSD, GrapheneOS, seL4, and related work

These projects are useful reference points for simplicity, exploit mitigation,
mobile hardening, formal reasoning, and fail-closed engineering. MRML may learn
from public ideas and documented outcomes, but repository contributions must be
original and compatible with the project's CC0 provenance rules. Comparison is
used to identify questions and evidence gaps, not to inherit another project's
assurance claims.

## Comparison rule

Any future comparison must name the exact property being compared, identify the
relevant MRML implementation and evidence level, and state material differences.
Avoid phrases such as “equivalent to,” “as secure as,” or “replacement for”
without independent evidence supporting that precise claim.
