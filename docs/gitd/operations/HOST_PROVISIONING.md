# Git host provisioning

Status: **PARTIALLY IMPLEMENTED**. Git-owned directories and shared Gitd socket
directories have an idempotent host provisioner. Secret installation, container
images, Compose validation, backup, restore, and upgrade workflows remain
separate gates.

Run `deploy/compose/provision-git-host.sh` as root. The deployment root defaults
to `/mnt/mrml`; fixed production identities and socket groups default to the
values in the Gitd deployment contract and can be overridden with the named
numeric environment variables in the script.

The provisioner creates only Gitd, Git authority, shared Gitd socket, channel
secret-parent, and backup paths. Existing paths are never silently re-owned or
re-moded: type, symlink absence, exact owner, and exact mode must already match.
Unsafe writable non-sticky ancestors fail. A final probe requires file and
directory sync, hard links, and same-filesystem atomic rename before the host is
accepted. The probe contains no secret or repository data and is removed.

The script does not create capability files, authority keys, tokens,
certificates, or repositories. Those require explicit one-shot administration
workflows so provisioning cannot accidentally replace authority-bearing state.

Patent review: **NOT_TRIGGERED**. Directory provisioning, ownership/mode checks,
hard-link and rename probes, and filesystem sync are conventional deployment
mechanisms. See `docs/patents/REVIEW_LOG.md`.
