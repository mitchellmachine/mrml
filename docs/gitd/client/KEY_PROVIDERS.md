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
are erased. Production protected operation rejects it and uses the narrow
`unix-v1` protected signer described below.

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
only on standard input. An OS credential service remains a future provider
behind the same interface; it is not claimed by this bridge.

## Protected hybrid signer

On Linux, `mrml-git-protected-signer` owns the reusable OpenPGP v6 seed and
ML-DSA-65 secret. `mrml-git` receives neither secret. Its Unix connection is
authenticated with the server's exact UID/GID and a distinct 256-bit channel
capability. Each bounded request is restricted to one SHA-256 Git commit and
binds the repository identity, commit ID, exact commit bytes, repository
generation, trust generation, and revocation generation. The daemon recomputes
the commit ID and exact hybrid transcript before signing. The client verifies
both returned signatures against its independently loaded active trust policy
before any upload.

The repository selects this route using only non-secret configuration:

```ini
[gpg "protected"]
    signerProvider = unix-v1
    signerSocket = /run/user/1000/mrml-git-signer.sock
    signerCapabilityFile = /run/user/1000/mrml-git-signer.cap
    signerUid = 1000
    signerGid = 1000
    trustPolicyDirectory = /absolute/trusted/policy/owner/project
    openpgpPublicKeyFile = /absolute/trusted/keys/openpgp-v6.asc
    mlDsaPublicKeyFile = /absolute/trusted/keys/ml-dsa-65.pub
```

The capability file and both daemon secret files must be regular, single-link,
owner-controlled files opened without following the final symlink. Capability
and secret files require mode `0400` or `0600`; public material must not be
group/world writable. Start the daemon as the key-owning non-root user:

```text
mrml-git-protected-signer serve SOCKET CAPABILITY CLIENT_UID CLIENT_GID OWNER_UID REPOSITORY REPOSITORY_GENERATION TRUST_GENERATION REVOCATION_GENERATION OPENPGP_SEED OPENPGP_CREATED_AT ML_DSA_PUBLIC ML_DSA_SECRET
```

The socket path and key paths identify resources but grant no signing authority.
The channel capability and exact daemon policy do. The daemon accepts no generic
message-signing, key-export, lifecycle, or repository-write operation. SIGINT or
SIGTERM wakes the listener, erases loaded secret buffers, and removes only the
exact socket inode created by that process.

The same binary provides a cold, offline owner operation for policy rotation:

```text
mrml-git-protected-signer sign-key-rotation OWNER_UID REPOSITORY TRUST_GENERATION OPENPGP_SEED OPENPGP_CREATED_AT ML_DSA_PUBLIC ML_DSA_SECRET NEXT_POLICY OPENPGP_PUBLIC_OUTPUT OPENPGP_SIGNATURE_OUTPUT ML_DSA_SIGNATURE_OUTPUT
```

It parses the complete canonical next policy, requires its repository to match,
constructs only the `KeyRotation`/SHA-256 hybrid transcript at the explicit trust
generation, verifies that the ML-DSA public and secret inputs agree, and writes a
bare OpenPGP-v6 public key plus both detached signatures. Outputs are absolute,
owner-controlled, mode-`0600`, no-overwrite files followed by file and directory
sync. The operation has no socket, network, repository-write, generic-signing,
or private-key-export path. Run it once with the currently authorized signer and
once with the candidate signer; the two OpenPGP public outputs identify which
signature came from which generation. The candidate policy remains data until
the separately stopped, volume-fed authority transition independently verifies
both hybrid authorizations and durably selects it.

The native SSH proposal advertises `rsa-sha2-256` only; the SHA-1 `ssh-rsa`
signature algorithm is not negotiable. Duplicate algorithm-list entries fail
closed, and independent inbound/outbound encrypted packet state refuses another
packet before a 32-bit sequence could wrap under one key. Full byte/age-based
rekey orchestration and independent constant-time cryptographic review remain
open, so the optional SSH transport is not classified as production-ready.

Patent review: **NOT_TRIGGERED**. These changes use conventional local
secret-file confinement, a purpose-limited authenticated Unix channel, provider
selection, diagnostic redaction, and memory erasure around already-reviewed
OpenPGP v6 and ML-DSA-65 primitives. They introduce no new cryptographic
primitive or patent-sensitive selection mechanism. See
[`docs/patents/REVIEW_LOG.md`](../../patents/REVIEW_LOG.md).
