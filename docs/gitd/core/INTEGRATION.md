# Gitd core integration delta

Base: `cf1f75755e6961737d6c1972959aac9a8dcea061ec26b7f7e43b20ab261868c2`.

The edge branch can import the public `mrml_git::GitdCoreBackend` contract
without a dependency on HTTP, TLS, or Zstandard packages. A concrete backend is
still required; transport code must retain fail-closed route disablement until
one exists.

No package or workspace manifests were changed. No dependency is requested by
this change.

The detached-signing service interface currently enumerates SHA-256, SHA-384,
and SHA-512 only. Adding policy-controlled OpenPGP SHA3-512 requires a separate
interface-generation change outside this branch's allowed files before the Git
CLI/service route can expose it. The first-party v6 implementation therefore
fails closed instead of advertising SHA3-512 prematurely.

Shared generated assurance inventories may need regeneration after integration
because three focused package tests were added. This branch is forbidden from
editing those inventories; run the repository-supported assurance regeneration
and inspect the exact diff rather than copying generated output by hand.

The source object database initially failed the mandatory pre-work `git fsck
--full --no-reflogs` because six loose objects were zero-length. After external
repair, both the primary checkout and this worktree passed `git fsck --full
--no-reflogs --no-dangling` on 2026-09-01. Full fsck reports only unreachable
objects. This branch did not delete or repair Git objects.

`docs/gitd/core/READY` is intentionally absent: the cryptographic, pack,
quarantine, transaction, Smart Git server, repository view, interoperability,
fuzz, crash, benchmark, native-Windows, and independent-review gates remain
open. The focused Windows Git package completed under Wine using the pinned
`nightly-2026-08-29-x86_64-pc-windows-gnullvm` toolchain at rustc commit
`17fd5b8a37b6667b6cc137f3cc35f09759768a3b`; this is Wine toolchain/runtime
evidence, not native Windows evidence.
