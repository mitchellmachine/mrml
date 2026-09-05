# Disposable real-Compose diagnostic scripts — 2026-09-05

These preserve the exact public orchestration for the diagnostic continuation
in `CURRENT_COMPLETION.md`. They are hard-coded to the disposable
`mrml-completion-f-20260905` namespace and its host configuration directory.
They are not a general production installer or the final continuous acceptance
runner. Real daemon images are built locally, externally authenticated and
loaded before execution. No source checkout is needed on the test host.

Private tokens and capabilities are referenced by host-local paths only; no
secret values are embedded. The image/signing artifacts are separately bound
by their recorded manifests. Read the matching outcome before using a script:

- Recovery preserved Gitd but the old deadlocked certd required forced stop.
- Rotation succeeded; the immediate fetch raced the bounded refresh interval.
- The original malformed helper failed its too-narrow expected error check;
  server proof-denial evidence plus unchanged refs and immediate valid push
  established the actual rejection. The helper was subsequently corrected.
- Response loss passed automatic native reconciliation.
- Token replacement requires the separate persisted client-generation update;
  environment variables alone do not override an existing clone.
- Text transfer observer resume measures clone/fetch after an already successful
  push whose client accounting failed. It must not be reported as a measured
  256 MiB push or a complete clean-source sequence.

Do not run these against production state or silently change namespaces. They
retain the existing confined Compose files and use native MRML Git operations.
