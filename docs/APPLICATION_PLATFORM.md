# MRML application-platform architecture

This document preserves the intended application-platform design. Unless a
section explicitly says otherwise, it is **PLANNED** or **ASPIRATIONAL**, not an
implementation claim. Status terms follow [ARCHITECTURE.md](ARCHITECTURE.md).
Security boundaries remain normative in [SECURITY.md](SECURITY.md), dependency
order in [ROADMAP.md](ROADMAP.md), and recovery procedure in
[RECOVERY.md](RECOVERY.md).

## Current status

**IMPLEMENTED:** the repository has capability, IPC, task/address-space,
executable-loading, WHP/KVM, and experimental Rust-subset compiler mechanisms
that can support later application work.

**PARTIALLY IMPLEMENTED:** signed PE loading and isolated CPL3 service probes
exercise low-level execution and service mechanisms. They are not a stable
application ABI, SDK, GUI, or complete application lifecycle.

**EXPERIMENTAL:** `mrml-rustc` compiles a documented Rust subset and itself
forbids unsafe code. It is not a complete Rust compiler, application admission
system, or proof that arbitrary top-level Rust applications and dependencies
are memory-safe. `mrml-tools` can automate installed host browsers; it is not an
MRML browser engine or OS browser security boundary.

**PLANNED:** safe native application admission and SDK, stable service
protocols, application microVM projection, trusted compositor, semantic scene
graph, HiDPI desktop, browser, and capability-mediated AI control plane.

**ASPIRATIONAL:** a polished, broadly compatible, empirically fingerprint-
resistant application ecosystem with local and remote LLM control that retains
strict least authority.

There is currently no MRML OS GUI/compositor, semantic scene graph, native
application ABI, application microVM system, browser engine, JavaScript or
WebAssembly runtime, or CET/IBT application-admission enforcement.

## Foundational application model

The future platform combines memory safety, capability authority, process
isolation, optional stronger VM isolation, stable application-facing contracts,
a trusted compositor, machine-readable GUI state, first-class HiDPI, local and
remote LLM control, explicit security boundaries, and minimal ambient authority.
Historical POSIX/C security and ABI conventions and legacy compatibility do not
dictate the foundation.

```text
native MRML application
    -> approved memory-safe language/runtime
    -> safe MRML SDK
    -> versioned MRML service protocols
    -> capability IPC
```

Safe Rust is the primary intended native systems/application language. Ordinary
third-party native applications do not receive a general-purpose C/C++ ABI.
Rust's compiler-internal/native ABI is also not MRML's stable application ABI.
Stability belongs in explicit, bounded, versioned service protocols beneath
safe SDKs. The kernel ABI remains extremely small; filesystem, network, GUI,
configuration, AI, and media functionality normally comes from services.

### Unsafe-code policy

- Ordinary native applications: unsafe code prohibited by default.
- System services: unsafe strongly discouraged and permitted only when
  technically necessary.
- Drivers, VMM, kernel, compiler, and hardware boundaries: unsafe permitted only
  when necessary, with documented safety invariants and adversarial review.

Application build/admission should eventually enforce `#![forbid(unsafe_code)]`
or an equivalent transitive property. A safe top-level Rust crate is not enough:
native FFI or unsafe dependencies can defeat memory safety and must not enter the
ordinary application ecosystem silently.

### Execution classes

1. A native safe application is a memory-safe, isolated CPL3 process controlled
   by capabilities.
2. A strongly isolated MRML application, or small related group, runs inside a
   microVM with MRML application interfaces projected across the VM boundary.
3. A compatibility application runs in an explicit legacy guest environment,
   potentially Linux or Windows where lawful and technically appropriate.

Unsafe and legacy ecosystems remain inside their VM trust boundary. MRML does
not weaken native policy to make legacy binaries appear native. WebAssembly is
not a fourth system application class.

Where practical, native and microVM applications use the same high-level SDK.
Native calls reach direct service IPC; microVM calls use a paravirtualized,
capability-preserving transport. The security boundary changes, not the
conceptual API. VM transport must not manufacture, widen, or confuse authority.

## WebAssembly and browser execution

WebAssembly is browser content, not an MRML native application format. There is
no system-wide WASI/WebAssembly runtime unless a future explicit architecture
and security decision changes this rule. Browser-hosted WebAssembly receives
only origin-specific authority mediated by the browser and cannot bypass native
admission or capability policy.

The planned browser operates without a JavaScript or WebAssembly JIT. Web
execution must not introduce writable-and-executable memory. Interpretation or
appropriately reviewed ahead-of-time-safe mechanisms preserve W^X. No-JIT is an
intentional security decision, not a temporary performance defect; changing it
requires explicit architecture and security review rather than benchmark
pressure.

### Fingerprint resistance

The browser should expose cohort-normalized properties for equivalent
configurations and avoid unnecessary machine uniqueness. Relevant surfaces
include user agent and version granularity, platform, fonts, locale/timezone,
screen/logical viewport/DPI, GPU and graphics capabilities, canvas, WebGL/WebGPU,
audio, timing precision, CPU/core and memory information, input devices, media
and codecs, installed features, and extensions/plugins. Avoid stable per-user
randomization that becomes its own fingerprint. Document privacy, performance,
and compatibility tradeoffs and test real fingerprinting suites before making
strong claims. Perfect anonymity is not promised.

### Hardware authority

Browser possession of a capability never automatically delegates it to a site.
Camera, microphone, location, USB, Bluetooth, HID, serial, filesystem,
clipboard, screen capture, and GPU APIs require separate origin-specific policy
and explicit authority.

## Trusted compositor and desktop

The planned trusted compositor owns the final display. Applications and VMs
submit surfaces; they never own the physical display or trusted decorations.
The compositor controls composition, placement, decorations, trusted identity
indicators, focus, keyboard/pointer/touch/pen routing, clipboard and drag/drop,
secure prompts, accessibility semantics, capture policy, display configuration,
and HiDPI mapping.

Applications cannot spoof compositor-owned security surfaces. Isolation-domain
indicators may show application identity, trust/VM domain, isolation class, and
security state using labels, symbols, trusted decoration, and optional accents;
they never rely on color alone. This borrows the value of visibly distinct
domains without copying Qubes UI.

The visual direction is a polished, modern, accessible desktop with original
MRML identity: clean geometry, rounded surfaces, restrained translucency,
coherent and reduced-motion-aware animation, configurable launch surfaces,
quick settings, notifications, settings, light/dark appearance, keyboard
navigation, and strong HiDPI. Familiarity is useful; copying trademarks,
proprietary assets, names, icons, or another OS's exact design is forbidden.

### HiDPI and coordinates

Logical coordinates, not framebuffer pixels, are canonical. Each output exposes
validated physical resolution/dimensions, logical dimensions, scale, refresh,
orientation, color-space, and HDR capability where available. Scaling is
fractional and per-monitor; it is not restricted to a hard-coded list.
Applications operate in logical space and the compositor performs physical
mapping.

Automation uses the same logical space and identifies every spatial reference
with the appropriate display, window, surface, and object identities. Changing
DPI must not invalidate semantic automation.

## MRML Semantic Scene Graph

The GUI is never only pixels. Every native GUI maintains synchronized visual
and semantic representations. The semantic representation serves accessibility,
testing, automation, local/remote LLMs, and debugging. Pixels remain a fallback
and an explicitly requested multimodal resource.

Each semantic object should expose only appropriate information such as stable
object identity, role, parent/children, window, application and trust domain,
logical bounds, visible region, z-order, text/value/state, available actions,
focus, enabled state, selection, and description. Stable object actions such as
`activate`, `set_value`, `move`, and `launch` are preferred over pointer
coordinates and keystrokes.

Inspection and interaction are separate capabilities, conceptually
`gui.inspect` and `gui.interact`. Global raw HID injection, such as
`input.pointer.inject` or `input.keyboard.inject`, is a substantially stronger,
separately privileged fallback and is not automatically granted to AI agents.

The graph is incremental. Typed deltas include object add/remove, bounds, text,
value, state and focus changes, and window open/close. Consumers maintain a
synchronized bounded view instead of repeatedly receiving the whole desktop.
This reduces latency, tokens, remote API cost, and local context use. Object
identities, generations, visibility, actions, ordering, delta loss/recovery,
and subscription authorization require adversarial validation.

## AI and multimodal access

Semantic/text state is the default AI path. Screenshots, image bytes, or video
frames are requested lazily only when semantics are insufficient and the agent
has the relevant capability. Images, video, and audio are capability-controlled
semantic objects that can expose inexpensive metadata, descriptions, captions,
transcripts, chapters, duration, and current time before bytes or sampled
frames. Text-only models need not receive media bytes.

AI control never implies broad machine authority. Semantic inspection,
interaction, media access, network use, filesystem access, and raw input remain
separate capabilities. Remote LLM transport additionally requires explicit
disclosure policy so secrets and private UI state are not exported implicitly.

### Browser semantic interface

The browser exposes a sanitized interactive document tree combining document
structure, accessibility semantics, actual layout, visibility, hit testing, and
interactive state. This is the primary LLM browsing interface. Normal AI web
control uses deliberate navigation, inspection, find, activation, value-setting,
scrolling, and authorized media-inspection operations—not arbitrary DOM code,
JavaScript execution, browser memory, debugger/root interfaces, or continuous
screenshots.

Photographs, maps, canvas, WebGL, charts, games, and video appear as semantic
media objects when ordinary semantics cannot represent them. Visual inspection
is explicit, scoped, lazy, and capability checked.
