# MRML configuration service foundation

`mrml-config` is the allocation-free policy/configuration state and wire-format
foundation for the planned userspace system service. It is not persistent
storage, a registry clone, a secret store, or a completed CPL3 service.

Implemented boundaries:

- fixed, typed schemas for Boolean, bounded unsigned, and bounded byte values;
- exact capability-object authorization for reads and every transaction write;
- atomic bounded commits tied to an expected monotonic revision;
- bounded audit retention with explicit sequence-gap reporting;
- canonical version-1 configuration request/response encoding; and
- canonical version-1 service-supervision request/response encoding carrying
  opaque generational handles;
- kernel-message decoders that require zero authority placeholders and resolve
  every operation from the exact receiver-space capabilities derived by IPC;
- bounded configuration dispatch with detail-free authorization rejection; and
- a supervision adapter that composes query/restart requests with exact kernel
  authority, cleanup, backoff, restart-limit, and trusted-context gates.

Setting IDs and service tokens identify records but never grant authority.
Secrets are intentionally outside this value model. The dispatch adapters are
simulation-tested through the kernel's real capability-transfer path. The
kernel's bounded CPL3 buffer ABI is now exercised by a signed 48-byte service
probe under WHP and KVM, but this configuration dispatcher is not yet linked
into that image. That integration remains next, followed by signed schema
admission, persistent export/import, and native-storage recovery.
