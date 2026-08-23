# MRML accessibility architecture

**Status: PLANNED.** This is durable architecture, not a claim that MRML
currently implements a desktop, screen reader, speech recognizer, or Braille
device stack.

> Accessibility belongs in the architecture, not on top of it.

```text
Complexity impact: MEDIUM
TCB impact: LOW
New parser boundary: YES
New authority model: NO
New persistent state: YES
External dependency: NO
Failure isolated: YES
Existing-object reuse: HIGH
```

The parser and persistent-state answers cover planned bounded semantic/device
transports and session/focus state, not current implementation. Reusing the
object, capability, Semantic Scene Graph, audio, and trusted-input architecture
avoids a parallel accessibility stack.

## One semantic system, many interfaces

```text
                  MRML objects
                       |
              Semantic Scene Graph
                       |
       +---------------+----------------+
       |               |                |
       v               v                v
    Visual           Braille          Speech
      GUI            interface        interface
       |
       +-------- Keyboard / HID
       +-------- Accessibility tools
       +-------- Text-only AI
       +-------- Multimodal AI
```

Visual GUI, Braille, speech, keyboard, accessibility devices, automation,
testing, and AI project the same object identity, role, state, actions, focus,
and authority where practical. They must not become routinely divergent
semantic systems. Consumers do not receive identical authority: semantic
inspection, interaction, raw input, media, speech capture, device routing, and
remote disclosure remain separately capability-controlled.

Logical objects and coordinates are independent of framebuffer resolution and
HiDPI scale. Rendering failure or GOP/VGPU transition must not destroy semantic
identity. Where relevant services remain operational, Braille, speech, keyboard,
and semantic interaction should continue without GPU acceleration or framebuffer
inspection.

## Semantic actions and input

Ordinary controls expose `focus`, `activate`, `select`, `expand`, `collapse`,
`increment`, `decrement`, `set_value`, and `scroll` independently of pointer
coordinates. Keyboard-first operation and deterministic focus order are
platform requirements where practical.

Adaptive keyboards, switch controls, alternative pointing devices, eye
tracking, sip-and-puff devices, Braille keyboards, and other accessibility HID
devices translate through trusted services into semantic input/actions. They do
not each need a special kernel authority model.

## Braille output and input

Refreshable Braille is a first-class system interface, not framebuffer scraping:

```text
Semantic Scene Graph -> accessibility service -> Braille presentation
                     -> refreshable Braille device
```

The representation should carry focus, text, selection, cursor, headings,
links, buttons, forms, lists, tables, status, notifications, and trusted prompts.
Routing keys invoke authorized semantic actions, not pixels.

Braille input enters the trusted input architecture and targets the focused
semantic object under normal isolation and capability rules. A focused app or
VM never receives global Braille input. Prefer interoperable protocols and a
narrow device/interface capability over raw USB authority.

## Speech output, input, and privacy

```text
Semantic Scene Graph -> accessibility speech service -> speech synthesis
                     -> MRML audio service -> audio output

microphone -> trusted capture -> speech recognition/interpretation
           -> semantic command -> MRML object operation
```

Speech output should describe controls, text, focus/window changes, menus,
notifications, trusted prompts, security state, errors, configuration, and
recovery. A blind user must not need the framebuffer to understand a trusted
prompt. Trusted speech output is distinct from application playback, VM audio,
and notifications, and applications cannot capture it by default.

Prefer semantic voice actions over simulated coordinates. Speech recognition,
deterministic command interpretation, and AI reasoning are separate layers.
Basic voice control must work locally without an LLM or Internet connection.
Remote services are optional and require an explicit trusted boundary; privacy
claims require evidence.

Trusted accessibility capture, application microphone capture, VM capture, and
AI microphone access are distinct authorities. Voice control never exposes raw
audio to apps or remote AI automatically.

## Capabilities, secrets, and trusted prompts

Potential future objects include `AccessibilitySession`, `SemanticView`,
`BrailleDisplay`, `SpeechInputSession`, `SpeechOutputSession`, and `InputRoute`;
names are not yet ABI. Rights remain separable:

```text
semantic.inspect   semantic.interact
speech.capture     speech.control
braille.output     braille.input
```

There is no `ACCESSIBILITY_ROOT`. Broad screen-reader visibility is explicit,
inspectable, and auditable. Redaction applies identically to visual, Braille,
speech, automation, and AI. A password field may expose role and `populated`
state while its value remains `REDACTED`.

Capability elevation, credential use/export, device assignment, microphone or
camera permission, AI/debug authority, security exceptions, login, recovery,
and update approval must eventually have equivalent meaningful visual, Braille,
speech, keyboard, and appropriate-device semantics. No trusted decision may
require only color, sound, icon, animation, position, or pixels. Host-owned
domain identity accompanies untrusted content in every interface.

## VMs, browser, media, boot, and recovery

Application VMs project authenticated, bounded guest GUI semantics into the
host graph. Guest semantics are untrusted content and cannot forge compositor-
owned domain/security identity. Compatibility VMs may bridge guest accessibility
APIs under the same validation rule.

The browser's sanitized interactive document tree is the common accessibility,
keyboard, automation, and AI representation. Web content remains untrusted.
Media objects may expose captions, transcripts, audio descriptions, chapters,
semantic descriptions, language, and timing; multimodal inspection remains lazy
and authorized.

Architecture must permit accessibility before the full desktop where hardware
and service prerequisites allow. Long-term targets include boot errors, rollback
selection, security warnings, login, recovery, and repair. This is not a claim
of current early-boot support.

## Testing

Future tests cover semantic completeness, focus order, keyboard-only workflows,
Braille/speech representations, redaction, trusted prompts, VM/browser
projection, render-backend and HiDPI independence, and capability enforcement.
Dogfood workflows without a pointer or framebuffer inspection, through the
semantic tree, speech, and Braille representation. Claim physical Braille
support only after physical-device tests; label simulation honestly.
