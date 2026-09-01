# Linux deployment adapter

Status: **PLANNED**. The production process must bind UDP 443, retain sole
ownership of the socket reactor, load non-exportable signing/token operations,
drop ambient privilege, enforce file and memory quotas, expose bounded health
metrics, and stop accepting work before graceful drain.

A bounded filesystem-backed persistent cache adapter is implemented with
file-and-directory durability barriers and quota pruning. Its root is supplied
by deployment policy; the adapter does not select a host path or grant access to
one. No systemd unit, namespace/seccomp profile, privileged-port handoff, cache
directory provisioning/confinement policy, log retention policy, or public-host
deployment has been verified. Hosted Linux package tests do not establish
production deployment.
