# MRML Engineering Constitution

This document is normative project policy. It governs substantial architectural
and engineering decisions; detailed architecture, status, security boundaries,
and evidence remain in their existing canonical documents. Routine edits do not
need ceremony, but major mechanisms must be tested against these rules.

## Authority and objects

> Everything meaningful is an object, and authority to an object is represented
> by capabilities.

> Names identify. Capabilities authorize.

Object identity, paths, PIDs, URLs, service names, signatures, publishers,
users, AI identities, and reputation never confer authority by themselves.
Objects are appropriate where identity, lifetime, ownership, delegation,
observation, or authority matter; meaningless implementation details must not
become objects merely for uniformity.

There is no ambient authority. Processes, services, applications, VMs, drivers,
userspace components, users, and AI agents receive explicit capabilities.
First-party origin, signatures, user launch, system membership, administrator-
equivalent identity, AI status, or reputation does not imply unrestricted
authority.

MRML uses one authority vocabulary across files, directories, windows,
processes, VMs, connections, devices, secrets, debuggers, AI agents,
configuration, graphics, audio, and services:

```text
object  capability  rights  derive  delegate  restrict  revoke  expire
```

Subsystems may define specialized rights, but not casual parallel authorization
architectures. Human GUI/CLI/SDK use, automation, local AI, and remote AI should
operate on the same underlying objects. AI is another principal, never a hidden
root automation channel.

## Memory safety and containment

Ordinary native applications are memory-safe by admission policy, with safe
Rust as the primary direction. The language's support for unsafe systems work
does not authorize ordinary applications to use unsafe code. Unsafe Rust is
reserved for system components where justified and audited. Memory-unsafe
legacy software belongs behind explicit compatibility/isolation boundaries,
normally VMs. WebAssembly remains browser content, not a general native
application format.

Keep the trusted computing base small. Security-related work does not belong in
the TCB merely because it is security-related. Every proposed TCB addition must
explain why its compromise must have broader consequences; without a strong
answer, redesign it as a narrowly capable isolated service.

> One compromise should remain one compromise.

> One crash should remain one crash.

Where practical, detect a failed service, revoke its authority, clean derived
state, destroy it, and restart a clean instance. Unsupported, malformed,
ambiguous, or security-sensitive states fail explicitly, especially in the
compiler, capability validation, IPC, virtual devices, VGPU, USB, storage,
networking, executable admission, boot verification, and AI tool execution.

Simplicity is a security and maintainability property, but it must never be
obtained by removing necessary isolation, validation, or correctness.

## Whole-system understandability

> MRML should remain understandable as a complete computer.

A competent developer should be able to trace important behavior approximately:

```text
source
  -> mrml-rustc
  -> executable and security metadata
  -> loader
  -> capability assignment
  -> process or service
  -> IPC
  -> kernel mechanism
  -> driver, VMM, or backend
  -> hardware
```

This does not require trivial components. It requires every layer and piece of
complexity to have a reason. Avoid opaque indirection and wrapper-to-wrapper-to-
adapter-to-manager stacks when a direct object or protocol is clearer.

An abstraction normally exists because it enforces a security invariant,
isolates failure, hides genuine backend differences, stabilizes an ABI or
protocol, removes meaningful duplication, enables testing, or reduces greater
complexity elsewhere. If it does none of these, question it.

When the system already knows structured information, expose it as structured
objects—such as diagnostics, processes, windows, capability graphs, compiler
diagnostics, and security events—rather than forcing software or AI to parse
free-form logs. Human-readable rendering is a view over that state.

## Complexity is a budget

Complexity is a resource like CPU, memory, latency, and attack surface. Every
subsystem, abstraction, dependency, compatibility layer, service, parser,
protocol, and persistent state machine consumes a permanent budget.

Before a substantial mechanism, answer:

- What problem does it solve, and can an existing object/service solve it?
- Does it introduce another authority model or global mutable state?
- Does it enlarge the TCB or add an untrusted-input parser?
- Could bounded storage replace dynamic allocation?
- Does it duplicate a concept or admit a smaller design?
- Is compatibility value worth permanent maintenance?
- Can failure be isolated and the mechanism fuzzed/tested independently?
- Can a future developer understand why it exists?

Major subsystem proposals record:

```text
Complexity impact: LOW | MEDIUM | HIGH
TCB impact: NONE | LOW | MEDIUM | HIGH
New parser boundary: YES | NO
New authority model: YES | NO
New persistent state: YES | NO
External dependency: YES | NO
Failure isolated: YES | PARTIAL | NO
Existing-object reuse: HIGH | MEDIUM | LOW
```

This is a design aid, not paperwork for routine implementation.

## Dependencies, compatibility, and readability

MRML remains aggressively dependency-minimized. For core components prefer
MRML-owned implementation, `no_std`, bounded memory, fixed-capacity structures,
explicit failure, deterministic behavior, small interfaces, and auditable unsafe
boundaries where practical.

Dependency minimization is not dependency elimination at any cost. Do not
recreate an enormous mature security-sensitive component when that would
materially reduce correctness or security. A significant core dependency must
justify its purpose, security and TCB impact, transitive dependencies, unsafe
exposure, update policy, and replacement feasibility.

Compatibility must pay rent. POSIX, Windows, legacy ABIs/hardware, C/C++
expectations, and historical filesystem semantics do not dictate the native
architecture. Put justified compatibility behind explicit VMs, adapters,
services, import/export paths, or emulated devices, and account for its lasting
maintenance cost.

Security-sensitive source favors explicit state machines, small modules,
bounded structures, clear invariants, deterministic control flow, and documented
unsafe boundaries over cleverness, metaprogramming, or generic abstraction that
obscures behavior.

## Development speed and evidence

Preserve a rapid secure loop:

```text
edit -> compile -> load or restart -> test -> inspect
```

Measure development latency. Services should restart independently when
isolation permits; compiler and loader speed must not bypass admission or
security checks.

Do not justify complexity by asserting it will be faster, safer, or smaller.
Measure relevant latency, throughput, memory, binary size, compiler time, IPC
cost, VM startup, GUI latency, and attack-surface proxies. Security claims stay
tied to exact evidence and retain their category:

```text
DESIGN GOAL  IMPLEMENTED  TESTED  MEASURED  AUDITED  PROVEN
```

No claim—memory safety, complete revocation, CET/IBT, DMA isolation,
fingerprint resistance, rollback protection, or prompt-injection containment—
is promoted without corresponding evidence.

## Precedence and inspiration

Future contributors and agents must consult this constitution before major
architecture. If a proposal conflicts with it, identify the conflict, explain
why the rule is insufficient, propose an explicit amendment, and do not bypass
the rule silently. The constitution may evolve only deliberately.

[EULOGY.md](../EULOGY.md) records Terry A. Davis and TempleOS as historical
inspiration for whole-system coherence and understandability. It is not
normative policy. TempleOS's conceptual directness does not override MRML's
memory safety, capabilities, privilege separation, microkernel isolation,
userspace services, VM compartments, or modern hardware protections.
