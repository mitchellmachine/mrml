# Gitd core adapter contract

The edge-local `GitdBackend` mirrors the core's typed query boundary. The thin
adapter must map repository identity/generation, limits, object IDs, paths,
trust and revocation generations, verification results, and Smart Git budgets
without weakening either side. It must stream Smart Git through `BoundedRead`
and `BoundedWrite`; buffering an entire pack is forbidden.

Each call independently authorizes the repository and exact generation. A
generation change maps to `StaleGeneration`; private and absent repositories are
indistinguishable publicly. Core errors must not leak storage paths or secrets.
Golden edge tests currently use an in-memory backend. Integration is blocked
because `docs/gitd/core/READY` is absent.
