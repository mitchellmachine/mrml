# Gitd core architecture

Status: **PARTIALLY IMPLEMENTED**.

The first-party Git edge is a transport adapter, not a repository authority.
It passes validated identifiers and bounded streams to `GitdCoreBackend`; it
does not open repository paths, manufacture verified ref updates, or receive
private keys. Repository names identify an owner-selected repository. An
independent capability held by the eventual service authorizes access.

The intended dependency direction is:

```text
HTTP/3 or local transport edge
  -> gitd_core (validation, generations, budgets, typed results)
  -> smart protocol / repository view
  -> quarantine and verification
  -> durable object installation
  -> atomic ref activation
  -> audit receipt and recovery state
```

Object parsing, signature/policy verification, and ref activation remain
separate. No data obtained from Git, a manifest, a signature, or a repository
name grants authority. Reads report an exact repository generation and exact
object IDs. Protected mutation will require a privately constructed
`VerifiedRefTransaction`.

The transport-neutral boundary, trust-policy verification, pack indexing,
quarantine admission/lifecycle, and ordered durable-receive coordinator are
implemented. The coordinator accepts only a private `VerifiedRefTransaction`
and delegates concrete fsync/atomic primitives through a narrow storage trait.
Concrete filesystem durability and recovery, server-side Smart Git, canonical
compaction, and repository-view implementations remain open and must fail
closed until implemented.

Complexity score for the eventual subsystem: high security sensitivity, high
failure-recovery cost, and multiple independently useful components. The split
above is therefore required; it is not permission to place these mechanisms in
the kernel or grant first-party code hidden authority.

Patent review: NOT_TRIGGERED for the implemented identifier validation and
trait boundary. Compression and delta-selection work is separately triggered
and remains paused as described in [PATENT_SCREEN.md](PATENT_SCREEN.md).
