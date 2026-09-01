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
