# MRML values

These values guide architecture, implementation, security decisions, and
project claims. Normative engineering rules live in
[docs/ENGINEERING_CONSTITUTION.md](docs/ENGINEERING_CONSTITUTION.md).

## Authority serves people

> **Power should be explicit, limited, inspectable, and revocable.**

- **Explicit:** authority is deliberately granted.
- **Limited:** authority is narrowly scoped.
- **Inspectable:** authority and its provenance can be understood.
- **Revocable:** authority can be withdrawn when semantics permit.

Names identify; capabilities authorize. Human intent and individual dignity
come before institutional convenience, application reputation, or automated
preference. Security should protect people without requiring them to surrender
agency over their own computer.

> **Intelligence does not imply authority.**

AI is a capability-constrained principal. Intelligence, autonomy, model size,
provider reputation, or convenience never creates authority. Secret use and
export remain separate, remote disclosure is explicit, and users retain visible
control and revocation.

> **Not every human problem is a computing problem.**

MRML should not turn judgment, relationships, dignity, care, or social choices
into software merely because computation is available. Technology should serve
human purposes and remain modest about what it can understand or resolve.

## Accessibility is a platform property

> **Access to the computer should not depend on one particular human sense, physical ability, or method of interaction.**

Accessibility is not optional polish, an application-specific feature, a
third-party add-on, or a post-release compatibility layer. Essential operations
should have equivalent meaningful semantic access through appropriate visual,
keyboard, pointer, touch, pen, Braille, speech, switch-device, automation, and
AI interfaces where technically practical. Disabled users are intended users,
not exceptional edge cases.

One shared semantic object system should support accessibility, automation, UI
testing, and AI while granting each consumer only its own inspection and
interaction capabilities. Accessibility does not imply unrestricted observation
or secret access. Core accessibility must retain a viable local/offline path.

## Durable project commitments

- **Privacy by architecture:** minimize disclosure; separately authorize
  microphone, media, semantic inspection, and remote transport; redact secrets
  consistently across visual, speech, Braille, automation, and AI.
- **User control and local capability:** useful core operation, including
  accessibility, must not depend on a particular cloud or AI provider.
- **Freedom to understand:** preserve whole-system traceability, readable source,
  structured state, and inspectable authority.
- **Security without surrendering agency:** trusted prompts explain meaningful
  choices and support multiple appropriate interaction modes.
- **Compatibility without architectural surrender:** isolate legacy behavior
  rather than letting it define native semantics.
- **Evidence over marketing:** distinguish goals, implementation, tests,
  measurements, audits, and proofs.
- **Bounded failure:** contain crashes and compromises, revoke authority, and
  clean derived state.
- **Simplicity without lost protection:** reduce duplication through shared
  semantics, never by removing necessary isolation, validation, accessibility,
  or correctness.
