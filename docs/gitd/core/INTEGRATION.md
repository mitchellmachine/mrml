# Gitd core integration delta

Base: `cf1f75755e6961737d6c1972959aac9a8dcea061ec26b7f7e43b20ab261868c2`.

The edge branch can import the public `mrml_git::GitdCoreBackend` contract
without a dependency on HTTP, TLS, or Zstandard packages. A concrete backend is
still required; transport code must retain fail-closed route disablement until
one exists.

No package or workspace manifests were changed. No dependency is requested by
this change.

The installed CLI now accepts the standard spellings `git add`, `git reset`
(index reset only), `git checkout` (existing local branches), `git remote add`,
`git remote set-url`, `git commit -m`, `git commit -S -m`, `git verify-commit`,
`git verify-tag`, `git rev-parse`, `git ls-tree`, and `git show-ref` through
first-party repository operations. Native `git rm` and `git mv` validate
bounded repository-relative paths, require tracked regular-file sources, and
stage the resulting deletion/addition. Native `git fsck` authenticates every
object reachable from local branch, tag, and HEAD tips with bounded graph and
object parsing. These paths never fall back to an external Git executable.
Destructive reset modes, detached checkout, pathspec-rich forms, unreachable
object enumeration, and the remaining explicitly listed command gaps stay fail
closed until their native semantics are implemented and tested.

`git cat-file -t`, `-s`, and `-p` are native. Type and size work for every
authenticated object kind. Pretty mode emits parsed tree entries or exact UTF-8
commit, tag, and blob contents; binary pretty-printing fails explicitly because
the current runtime output interface is text-only. It never performs lossy
conversion or invokes an external Git process.

`git pull --ff-only [remote] [branch]` is accepted exactly; unknown pull
options remain rejected. The SSH fetch client parses and authenticates the
bounded pack, then traverses every advertised commit, tree, and blob against
the isolated parsed candidate plus the existing object database before any
candidate object is installed or any remote ref is updated. A malformed,
wrong-kind, incomplete, or over-budget candidate therefore leaves both the
object database and refs unchanged. This is controlled client-path evidence;
it does not claim the stronger production file-backed quarantine durability of
the server receive path.

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

`docs/gitd/core/READY` records the focused green gates and deliberately
classifies the result `CORE_BLOCKED`: canonical level-9/delta compaction,
native-Windows durability, process-kill fault injection, scale/concurrency
benchmarks, sanitizer/fuzz campaigns, and independent review remain open. The
focused Windows Git package completed under Wine using the pinned
`nightly-2026-08-29-x86_64-pc-windows-gnullvm` toolchain at rustc commit
`17fd5b8a37b6667b6cc137f3cc35f09759768a3b`; this is Wine toolchain/runtime
evidence, not native Windows evidence.

The ML-DSA-65 key-generation, signature-generation, and signature-verification
tests now consume checked-in bytes from NIST ACVP-Server commit
`975de31eb83d87039ec88934fdc47d8c312b892d`. A separate checked-in signature
generated and self-verified by OpenSSL 3.6.4's default provider is always
verified by the first-party implementation. These tests no longer silently
pass when fixture environment variables are absent; OpenSSL remains a test
oracle and is not a runtime dependency.
