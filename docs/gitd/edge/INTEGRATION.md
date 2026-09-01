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

After endpoint Retry/admission integration, the hosted Linux HTTP suite passed
48 tests. Token authentication precedes bounded half-open permit creation;
wrong-peer and replay attempts reject in the focused regression.

After persistent cache-record integration, HTTP passed 49 tests on hosted Linux
and 49 Windows-target tests under Wine. Corruption eviction used an in-memory
`CacheStore`; no filesystem crash or disk-quota evidence was exercised.

After integrating bounded single-flight generation into the HTTP server, HTTP
passed 50 tests on hosted Linux and 50 Windows-target tests under Wine.

After adding the Linux filesystem L2 adapter and the supporting runtime
directory-sync primitive, HTTP passed 51 tests on hosted Linux and the unchanged
50 Windows-target tests under the pinned toolchain under Wine. The Linux test
exercised bounded no-follow reads, exclusive temporary creation, file sync,
atomic rename, directory sync, and entry-quota eviction. No crash-injection,
native Windows, physical disk, or production filesystem evidence was produced.
The supporting `org.mrml.library.runtime` Linux suite passed 44 tests and failed
2 loopback network tests (`loopback_udp_preserves_datagram_and_peer_identity`
and `loopback_listener_exchanges_bytes`) with `BindFailed` in the restricted
sandbox; its filesystem tests passed. Those network failures are not evidence
against the cache path.

After adding bounded per-source/work-class resource admission and hysteretic
pressure modes, the hosted Linux HTTP suite passed 53 tests. The focused tests
exercise IPv4 identity, IPv6 `/64` aggregation, fixed source-table exhaustion,
render concurrency exhaustion, the 40 GiB reserve, SIEGE restrictions, and
three-observation recovery. Reactor integration and production load evidence
remain open.

The Linux L2 recovery regression subsequently raised hosted Linux HTTP coverage
to 54 tests. It creates and syncs a partial temporary record, verifies bounded
startup cleanup, deletes the exact cache root, then verifies a later atomic store
recreates it and round-trips the representation. This is controlled filesystem
testing, not power-loss or physical-media crash evidence.

Repository image handling now has a hosted Linux regression within the 54-test
HTTP suite: relative images become exact-object `raw.mrml.ca` URLs, remote
images remain non-fetching labeled links, and traversal, active-data, and
absolute-host-path forms fail closed. Raw-origin deployment headers are not yet
public-host evidence.

The same hosted Linux Markdown regression now covers strong/emphasis/strike,
HTTP(S) autolinks, block quotes, horizontal rules, ordered lists, accessible
task-list state, and the expanded fixed language-label allowlist. These are
renderer unit fixtures, not assistive-hardware evidence.

The 2026-09-01 settled edge gates passed `mrml manifest check`, `mrml manifest
lock --check`, 44 Linux and Wine/Windows Zstandard tests, 56 Linux and 54
Wine/Windows HTTP tests, 28 Linux TLS tests, and 48 Linux crypto tests. Wine is
hosted compatibility evidence, not native Windows evidence. `mrml assurance
check` remains blocked by the pre-existing unadmitted boundary
`docs/compiler/probes/pinned_std_thread_tls_execution.rs`; the edge work neither
changes nor suppresses that repository-wide policy failure.

Bounded semantic pipe-table rendering and the 64-column rejection case are also
covered by that hosted Linux HTTP regression.

The legacy `gitea-custom` templates and theme were removed after confirming the
first-party static site carries the intended charcoal, amber, and warm-white
visual language. `python3 website/check_static.py` passes two static pages and
checks canonical/Open Graph metadata, initial-HTML Organization/WebSite JSON-LD,
landmarks, skip navigation, local assets, focus/reduced-motion CSS hooks, and
the absence of executable scripts and legacy Gitea runtime customization. This
is deterministic markup inspection, not browser, screen-reader, assistive-device,
contrast-laboratory, or disabled-user evidence.

Cache-key construction now binds every renderer and verification input as
separate length-delimited fields before a domain-labeled SHA-256 digest. The
hosted Linux HTTP regression covers the previous trust/revocation XOR collision
and distinct route/path contexts. Static `/projects` also now emits its own
canonical URL instead of incorrectly canonicalizing to `/`.

ACK recovery now independently uses checked interval construction. The focused
HTTP suite covers first-range, gap-addition, gap-subtraction, and range
underflow plus a valid discontiguous interval; malformed authenticated ACK data
cannot reach subtraction with wrapping or panic semantics.

The client and server handshake implementations now use separate bounded
`PacketReceiveState` instances for Initial and Handshake spaces instead of
scalar expected counters. Authentication precedes recording, and only `New`
packets reach CRYPTO/TLS assembly; ACK frames derive from the authenticated
ranges. Application-space state remains independently owned by the established
connection.

The authorized RFC 8878 encoder work began with bounded forward/reverse bit
writers and normalized-count table-description serialization. The hosted Linux
Zstandard suite passes 33 tests, including exact writer/reader round trips,
zero-run and `-1` normalized counts, invalid totals, and bit-budget rejection.
This is encoder-foundation evidence only; HTTP still selects raw/RLE V1.
