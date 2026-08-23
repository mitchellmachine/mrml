# MRML configuration service foundation

`mrml-config` is the allocation-free policy/configuration state and wire-format
foundation for the userspace system service. It is not persistent storage, a
registry clone, a secret store, or a completed production service.

Implemented boundaries:

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
  authority, cleanup, backoff, restart-limit, and trusted-context gates.

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
volatile state; persistence is not implied. Native-storage persistence and
recovery remain next. The storage-neutral checkpoint codec is
implemented and adversarially tested, but its expected digest still requires a
future authenticated native-storage commit; the embedded digest is not treated
as self-authentication.
