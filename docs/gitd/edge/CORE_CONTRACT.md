# Gitd core adapter contract

The edge-local `GitdBackend` mirrors the core's typed query boundary. The thin
adapter must map repository identity/generation, limits, object IDs, paths,
trust and revocation generations, verification results, and Smart Git budgets
without weakening either side. It must stream Smart Git through `BoundedRead`
and `BoundedWrite`; buffering an entire pack is forbidden.

Each call independently authorizes the repository and exact generation. A
generation change maps to `StaleGeneration`; private and absent repositories are
indistinguishable publicly. Core errors must not leak storage paths or secrets.
Golden edge tests currently use an in-memory backend. The core READY record now
exists. The adapter implements edge-owned protocol-v2 discovery only after an
exact SHA-256 repository summary/generation check; upload-pack and receive-pack
remain delegated through the same bounded stream contract. Production remains
blocked on deployment-owned authentication, ACL, protected receive authority,
certificate-service integration, and live listener composition.
