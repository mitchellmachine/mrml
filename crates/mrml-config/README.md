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
  opaque generational handles.

Setting IDs and service tokens identify records but never grant authority.
Secrets are intentionally outside this value model. Signed schema admission,
CPL3 IPC dispatch, persistent export/import, native-storage recovery, and the
kernel supervision adapter remain dependency-ordered follow-up work.
