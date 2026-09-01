# MRML Git key-provider boundary

`mrml-git` does not automatically interpret legacy `ssh.privateKey`,
`user.signingkey`, or `gpg.openpgp.privateSeedFile` values as private-key file
authority. Repository configuration may select a credential or signer provider
and a key identity, but ordinary production operation must route the exact SSH
authentication or Git-signing operation to that provider.

The current host-file bridge is development-only. It is disabled unless the
operator deliberately sets `MRML_GIT_DEVELOPMENT_KEY_FILES=1`; configuration
must additionally select `development-key-file`. The loader opens the final
component without following a link, requires an already-open regular file owned
by the effective user with mode `0400` or `0600`, bounds the descriptor read,
and performs volatile erasure of the loaded byte buffer. RSA private-key values
are non-cloneable, expose no private fields, render only
`RsaPrivateKey(<redacted>)`, and erase the private exponent with volatile stores
on drop.

This bridge is not a production signer, credential daemon, HSM integration, or
claim that compiler-created copies, registers, caches, swap, or hardware traces
are erased. Production protected operation must reject it and use a narrow
capability-selected provider. The remaining provider transport and production
credential service are not yet implemented.

Patent review: **NOT_TRIGGERED**. This change is conventional local secret-file
confinement, provider selection, diagnostic redaction, and memory erasure; it
introduces no new protocol or cryptographic mechanism. See
[`docs/patents/REVIEW_LOG.md`](../../patents/REVIEW_LOG.md).
