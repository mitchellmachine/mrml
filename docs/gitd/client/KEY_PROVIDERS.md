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
capability-selected provider.

Native HTTPS now has a non-cloneable scoped Bearer credential boundary. Each
use is bound to the exact host, port, repository path, and read/write action;
only canonical lowercase 256-bit token encodings are accepted. Diagnostics are
redacted and the sole authorization buffer is erased with volatile stores on
drop. H2 and H3-v2 add exactly one Authorization header only while borrowing a
matching scoped credential. Anonymous operations never synthesize one.

The CLI's `standard-input` provider is an explicit non-persistent bridge for
deployment secret injection. It reads at most 66 bytes through a dedicated
byte-buffer API, accepts one canonical token with an optional line ending,
stores neither token nor token path in repository configuration, and erases its
input and retained token buffers. Clone selects it with the non-secret
`MRML_GIT_CREDENTIAL_PROVIDER=standard-input`; an existing repository selects
it with `http.credentialProvider=standard-input`. Token plaintext is supplied
only on standard input. A capability-selected OS credential service and HSM or
desktop-vault integration remain future providers behind the same interface;
they are not claimed by this bridge.

The native SSH proposal advertises `rsa-sha2-256` only; the SHA-1 `ssh-rsa`
signature algorithm is not negotiable. Duplicate algorithm-list entries fail
closed, and independent inbound/outbound encrypted packet state refuses another
packet before a 32-bit sequence could wrap under one key. Full byte/age-based
rekey orchestration and independent constant-time cryptographic review remain
open, so the optional SSH transport is not classified as production-ready.

Patent review: **NOT_TRIGGERED**. This change is conventional local secret-file
confinement, provider selection, diagnostic redaction, and memory erasure; it
introduces no new protocol or cryptographic mechanism. See
[`docs/patents/REVIEW_LOG.md`](../../patents/REVIEW_LOG.md).
