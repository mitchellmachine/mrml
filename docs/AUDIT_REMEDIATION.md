# Audit remediation record

This records work following the repository-wide first pass at `39b8bf7f`.
It is not an independent security audit or a claim of full semantic review.

- 81 newly discovered build-input sites were reviewed by category and declared
  with their exact path, kind and token fingerprint. Confirmed test fixtures,
  optional oracles, test child processes and offline release tooling remain
  distinguished. No runtime inputs were enabled by these declarations.
- Tracked shell sources are marked LF for a Windows checkout shared with WSL.
- The freestanding and UEFI crypto paths select the software AES-GCM
  implementation when the target ABI lacks SSE2. Hardware paths remain available
  on SSE2 hosts after runtime CPU feature detection.
- The existing shared, bounded volatile-erasure helper replaces duplicate
  unsafe loops in HTTP, SSH, OpenPGP and Git code. The runtime stdin helper
  reserves its bounded capacity before reading, clears scratch between reads,
  and clears the initialized accumulation on rejection or read failure.
  No guarantee is made about registers, compiler-created copies or old data
  written before handing control to the runtime.
- Unsafe-boundary diagnostics only count immediately preceding line comments
  as local safety notes, and enumerate recognized unsafe attributes for review.
  A comment is not proof of a site's contract. Existing count limits were not
  widened. The two narrow erasure sites have explicit one-block policy entries.
- [CI coverage](build/CI.md) separates Linux/Windows execution, MRML/UEFI
  compilation, host models, and the authenticated guest boot fixture.

## Remaining review

`mrml assurance check` is not green. Review remaining unadmitted or above-budget
files with `mrml assurance inspect`; it cannot grant policy approval. Do not
approve a bulk baseline from measured counts. Start with kernel/boot/VMM
ownership, pointer lifetimes and revocation, followed by storage/DMA teardown,
Windows/Linux FFI and the hosted service/signing boundaries. Record each
reviewed function and caller, invariant, platform evidence, finding, and
disposition. Existing aggregate test counts do not establish that these
boundaries are sound or replace the repository's independent audit requirement.
