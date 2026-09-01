# Linux deployment adapter

Status: **PLANNED**. The production process must bind UDP 443, retain sole
ownership of the socket reactor, load non-exportable signing/token operations,
drop ambient privilege, enforce file and memory quotas, expose bounded health
metrics, and stop accepting work before graceful drain.

No systemd unit, namespace/seccomp profile, privileged-port handoff, persistent
cache directory, log retention policy, or public-host deployment has been
verified. Hosted Linux package tests do not establish production deployment.
