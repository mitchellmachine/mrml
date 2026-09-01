# Gitd edge integration and evidence

Actual repaired baseline used for the edge worktree:
`cf1f75755e6961737d6c1972959aac9a8dcea061ec26b7f7e43b20ab261868c2`.
The original dirty checkout was not reset, cleaned, or edited for edge work.

Reproduced baseline findings:

- one-shot socket-owning listener: **CONFIRMED**;
- incomplete application replay policy: **CONFIRMED**, then fixed with bounded
  authenticated ranges;
- insufficient HTTP/3 stream persistence: **CONFIRMED**, then fixed;
- incomplete receive credit and sparse buffering: **CONFIRMED**, then fixed;
- malformed datagrams escaping accept/active paths: **CONFIRMED** for relevant
  decode errors; active receive now ignores unauthenticated malformed traffic;
- decoder-only Zstandard package: **CONFIRMED**; bounded raw/RLE encoder added,
  production encoder remains open;
- obsolete Gitea website text: **CONFIRMED**, then removed;
- absent first-party dynamic UI/cache: **CONFIRMED**, bounded router/L1 added.

The HTTP manifest gained `org.mrml.zstd`; root `mrml.lock` was intentionally not
edited because it is outside this branch's ownership. Focused evidence through
2026-09-01: `mrml test org.mrml.library.http --target linux`, 45 passed. This is
hosted Linux unit/loopback evidence, not native Windows, public Internet,
physical hardware, production load, or independent audit evidence.

`READY.md` is intentionally absent. Persistent endpoint, full TLS/OCSP gates,
production Zstandard/L2, Smart Git adapter, Linux deployment, load/fuzz matrix,
Windows evidence, and independent review remain open.

Additional hosted Linux gates on 2026-09-01:

- `mrml test org.mrml.library.crypto --target linux`: 42 passed;
- `mrml test org.mrml.zstd --target linux`: 29 passed;
- `mrml test org.mrml.library.tls --target linux`: 26 passed.

The first TLS invocation ran concurrently with other packages sharing the same
build directory and failed while reading a transient zero-length runtime object.
The sequential rerun rebuilt the dependency and passed; only the sequential
result is test evidence. `mrml test org.mrml.library.http --target windows`
initially stopped before compilation with `ToolchainUnavailable` because the
pinned Windows cross-host toolchain was not installed.

After installing the Wine-local pinned toolchain, commit
`17fd5b8a37b6667b6cc137f3cc35f09759768a3b`, the following Windows-target suites
passed under Wine 11.16: HTTP 47 after endpoint routing integration, TLS 25,
crypto 42, and Zstandard 29. The matching hosted Linux HTTP suite passed 47.
This is Windows toolchain and Wine runtime coverage. It is not native Windows, WHP,
physical-network, or production evidence.

After delegated OCSP responder validation, the TLS suites passed 28 hosted Linux
tests and 27 Windows-target tests under Wine. Coverage includes exact OCSP EKU
and same-serial/different-issuer hash rejection. No public delegated-responder
fixture or native Windows execution was exercised.
