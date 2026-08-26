# MRML configuration service foundation

`mrml-config` is the allocation-free policy/configuration state and wire-format
foundation for the userspace system service. It is not persistent storage, a
registry clone, a secret store, or a completed production service.

Implemented boundaries:

- a configuration-specific placement adapter with distinct native-service and
  microVM launch/revocation boundaries, exact generational binding preservation,
  and fail-closed no-fallback tests; its native form now owns a real accounted
  task runtime and service supervisor and retains uncertain cleanup for exact
  retry, while the VMM launcher and interface transport remain planned;
- fixed, typed schemas for Boolean, bounded unsigned, and bounded byte values;
- root-CONTROL-authorized bounded schema admission that freezes after commit;
- exact capability-object authorization for reads and every transaction write;
- atomic bounded commits tied to an expected monotonic revision;
- bounded audit retention with explicit sequence-gap reporting;
- canonical capability-controlled checkpoints preserving schemas, values,
  revisions, and the retained audit window with an expected SHA3-256 digest;
- canonical version-1 configuration request/response encoding; and
- canonical version-1 service-supervision request/response encoding carrying
  opaque generational handles;
- kernel-message decoders that require zero authority placeholders and resolve
  every operation from the exact receiver-space capabilities derived by IPC;
- bounded configuration dispatch with detail-free authorization rejection; and
- a supervision adapter that composes query/restart requests with exact kernel
  authority, cleanup, backoff, restart-limit, and trusted-context gates;
- canonical service-bound restart-policy records whose application explicitly
  rechecks setting READ and service CONTROL; and
- bounded dynamic policy replacement that preserves consumed restart budget
  and existing deadlines and invalidates pre-replacement restart plans.
- one canonical authority-free isolation-policy edit shared by planned Settings,
  object-shell, recovery, accessibility, automation, and test projections; the
  bytes bind exact setting/object/scope/native class/selection/revision while
  commit still requires root CONTROL and setting WRITE.

Setting IDs and service tokens identify records but never grant authority.
Secrets are intentionally outside this value model. The adapters are
simulation-tested through the kernel's real capability-transfer path. Each
signed service generation starts with a trusted root identity and no settings.
The client first sends a canonical schema-admission request and delegates only
root CONTROL; after exact kernel authorization the service admits the Boolean
setting. A separate commit request has zero authority fields and independently
delegates fresh root CONTROL and setting WRITE. The service validates both
opaque handles, commits revision 1 atomically, and returns a canonical 112-byte
response. The supervised replacement repeats admission and commit from fresh
volatile state; persistence is not implied. The reusable storage composition
now stages through a bounded `BlockFileSession` over the exact-block
`BlockVolume`, including its capability-selected MRML block-service adapter. A
deterministic test publishes one checkpoint by exact COW receipt, recovers only
the selected file generation, and reloads its service-bound restart policy. A
derived read-only block session reaches no write, and parent revocation stales
the complete session lineage. This is simulation evidence; the expected digest
still requires authenticated native-storage selection and is not self-
authentication. Live persistent restoration, reboot-time authority
reconstruction, and physical durability remain pending.

Patent review: **NOT_TRIGGERED** for the bounded caller-selected adapter and
native lifecycle under the [supervised-lifecycle review](../../../docs/patents/REVIEW_LOG.md#2026-08-25--supervised-native-configuration-placement-lifecycle).
Automated placement/provider/VM/resource selection and transparent transport
remain **TRIGGERED**.
