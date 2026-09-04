# Trust-transition verifier retention — 2026-09-04

Status: **PARTIALLY IMPLEMENTED** and verified in focused Linux tests. These
increments close the authority restart gap between policy selection and public
verifier availability and add an authenticated signer trust-generation handoff.
They include a controlled Podman named-volume overlap, retirement, restart, and
old-key rejection exercise. This is hosted server evidence, not physical
hardware or complete production-readiness evidence.

## Implementation

Signed functional commit `d31ef509` changes the normal `transition-policy`
operation so it durably installs the next OpenPGP-v6 and ML-DSA-65 public pair
before selecting the next trust policy. Files are retained beneath the exact
repository policy capability as:

```text
verification-keys/trust-GENERATION.openpgp.asc
verification-keys/trust-GENERATION.ml-dsa.bin
```

Creation is exclusive. Existing files must match the exact expected owner,
group, mode `0444`, one-link identity, length, and content. Each new file and
the keyring directory are synchronized before policy transition. A crash before
policy selection can therefore leave only inactive public material; a selected
policy never depends on transition-upload files that the wrapper subsequently
removes.

Authority startup retains one descriptor-relative policy-directory capability.
It uses the configured bootstrap pair only while the exact current policy
authorizes that pair at trusted validation time. If the bootstrap pair is no
longer active, startup opens only the exact current trust generation's retained
files beneath that capability, parses both keys, binds their complete hybrid
identity, and rechecks policy authorization. Missing, stale-generation,
substituted, malformed, wrongly owned, writable, linked, or inactive keys fail
closed.

The deployment input contract carries the exact previous public pair for every
transition. The networkless transition process does not substitute the
authority bootstrap files for that pair. This is required for normal
generation 2-to-3 retirement and every later rotation after the bootstrap pair
ceases to be active. Both supplied pairs remain public, immutable,
owner-checked transition inputs; neither grants authority without matching
policy status and hybrid signatures.

Named-volume operator tooling now separates canonical policy construction
(UID 21001), current and candidate signing (UID 21006), public transition
staging (UID 21002), and durable policy selection (UID 21001). The selected and
candidate signer key slots are explicit environment state. They may name the
two initially provisioned volumes or a lowercase, prefix-scoped, MRML-managed
additional slot, and must be distinct. Successful handoff swaps their logical
roles, consumes and synchronizes only the exact public workspace files; all
private-key volumes remain intact for
rollback analysis and deliberate later destruction under a separate operation.

Signer state format v2 additionally binds a SHA3-512 identity over the exact
OpenPGP-v6 and ML-DSA-65 public pair. Ordinary startup requires that identity
to match the supplied private material. The authenticated dual-signature trust
advance is the only v1-to-v2 migration path and persists the successor pair's
identity atomically with the generations.

Signed commits `91404cb9` and `9dd6ee54` preserve bounded authority startup
failure categories and correct authenticated health so the Gitd-owned split
capability is opened as UID 21001, not as the authority UID. Signed commits
`862f09da`, `dbbfdd22`, and `cba45d4f` add classified Gitd admission failures,
an atomic named-volume catalog updater, and the authenticated startup handoff.
The handoff admits a catalog that is behind only in trust or revocation
generation, queries the authority through its split capability, requires the
exact repository generation and catalog-selected trust tuple, and advances the
durable ref state monotonically before reopening it. Repository refs and pack
identity remain unchanged; a catalog or local state ahead of authenticated
authority state fails closed.

## Verification

```text
cargo fmt --all -- --check                                PASS
cargo clippy --all-targets -- -D warnings                 PASS
git diff --check                                          PASS
./target/debug/mrml test org.mrml.service.git-authority \
  --target linux                                          PASS
  authority library: 13 passed
  authority binary:   9 passed
./target/debug/mrml test org.mrml.tool.git --target linux PASS
  Git library:        276 passed
  Git CLI:            5 passed
  protected signer:   9 passed
  credential agent:   2 passed
./target/debug/mrml test org.mrml.service.gitd --target linux PASS
  Gitd library:       53 passed
  Gitd binary:        7 passed
  Gitd backup:        1 passed
```

The binary test uses two independent real OpenPGP/ML-DSA pairs and real hybrid
key-rotation signatures. It selects overlap policy generation 2, verifies the
generation-2 public files and their filesystem invariants, selects retirement
policy generation 3, proves the old pair is rejected, and proves restart
selection resolves the exact generation-3 next pair even though the configured
bootstrap pair remains old. A separate test preinstalls generation-2 material,
attempts a same-generation substitution, observes failure, and verifies the
retained bytes did not change.

Signed functional commit `61d39118` adds a pure normal-successor verifier and
the signer's cold `advance-trust` operation. The operation reads the actual
already selected policy from the policy volume, verifies exact ownership and
canonical encoding, verifies both real hybrid transition authorizations, binds
the current private signer material to the previous active pair, and atomically
updates only trust and revocation fields in the checksummed state. Its test uses
two independent real hybrid pairs, preserves repository generation 7, advances
trust 1 to 2, reopens the result, and rejects replay.

Signed deployment commits `bbe9d3d3` and `8bb2bf07` add the networkless,
read-only-root, capability-dropped signer admin profile and sequence it after
authority selection. All three daemons must be stopped. The transition input
set now contains the exact previous policy. Inputs are removed only after signer
state reopens; `--resume-signer` safely resumes an interruption after selection.
Both static Compose tests, shell syntax checks, and the combined
Git/ACME/signer admin Podman Compose render passed.

## Controlled hosted Podman exercise

The Ubuntu server at `mrml.ca` was exercised through rootful Podman. Every
signer key, state, split capability, construction, signature, transition,
policy, and runtime object used by the containers was held in a named volume;
no host bind directory held container state or keys. The operator scripts used
the `mrml-podman140f-fresh` volume scope.

The initial overlap selected generation 2, digest
`dc79cfacba14818d8e2c97397ed0456d2fc73a6cbc053ccfcdca3926ad8c716bde2aab6b9d48b02ee97b99f4af2e7dc25a5730b1fc48ce7d4da062371ff01828`.
Retirement at Unix time `1788543295` selected generation 3, digest
`6c04da45f70ef35a9e1fc394da475f3640e0d0e8a20ba104ed3478283c06278fb325eaa18d566121e8758c9d4ed65cbc95a3a3a33593d75a86bd7d274399049c`.
Both selections were reopened from the durable authority store before signer
advancement, and each successful operation consumed its public workspace.

The first explicit retired-key restart unexpectedly reached `ready`. This
exposed that signer state v1 bound generations but not key identity. Commit
`4078ec22` introduced the v2 binding; that first attempt is not counted as a
passing rejection test. To migrate without an operator-authorized key
substitution, a third key pair was generated inside the separately managed
named volume
`mrml-podman140f-fresh-git-signer-key-slot-generation-4`. A normal overlap,
authorized by the generation-3 and generation-4 pairs, selected generation 4
at validation time `1788544145`, digest
`ea4bad82847538d4effe8d736aeb0acb4ccea02e5c5a73da8170fd7e9ee52da53425de83abe9e6ccf839f994a571a419d2d9c5fbcfa212b849e7ba546f06f151`,
and atomically rewrote the 64-byte v1 state as the 128-byte v2 state.

Image `localhost/mrml/git-protected-signer:trust-4078ec22` had image ID
`3818ecc285bbebfe03249a8db6b79d0494570c134d22ffab44577aa511c04807`.
Its transferred OCI archive SHA-256 was
`0c6bc3d55a3592cae57017222b6abd66fec4f0c6b02d3aecd9b82f8afd2d8cdd`.
The selected generation-4 signer passed the authenticated split-channel socket
health exchange. Starting the previous generation-3 key against the same v2
state failed closed with exit 78. The valid generation-4 signer was then
restored and passed authenticated health again.

The first authority restart with trusted time after generation 4 failed closed
before creating its socket. Classified diagnostics identified
`proof_directory`; the imported test volume had a legacy extra `state/`
component. The source volume was preserved. Its contents were copied into the
current layout in the new named volume
`mrml-podman140f-fresh-authority-state-layout-v2`, and `check-catalog` passed.
Authority image `localhost/mrml/git-authority:trust-9dd6ee54` had image ID
`6654e1ba55b188174ae28965e2c22e54d4fbe63996303a1162eb57db6057af8e`;
its OCI archive SHA-256 was
`73bc324b327c5692d7bd08337c7c87f79485f6532ad0c0ac13853af735fa2276`.
It restarted, bound its listener, and passed an authenticated Gitd-side health
request. This corrects the earlier unresolved observation without erasing it.

The repository catalog was then atomically advanced from trust generation 1 to
4 with digest
`cf545335a68aeebb57621fd2314d85f9daef5350693964c7ce821dfc4077fab2`.
Gitd image `localhost/mrml/gitd:trust-cba45d4f` had image ID
`4f85e070666a3b25e9a0445054c308a07512391435e2b291c06bcb2379fbed30`;
its OCI archive SHA-256 was
`400a2ee44a9cbd518f499f42bbc90e23c9a2b87b857b3ebbc05123d7eabcc5a0`.
The exact archive checksum matched after SSH transfer. Gitd authenticated both
dependencies, advanced the durable trust tuple, completed recovery, bound only
server loopback `127.0.0.1:28443`, and reached `ready`.

A validation-only client was built from the same clean signed commit. Image
`localhost/mrml/git-client:trust-cba45d4f` had image ID
`109f3694273ebc901737adf82ee9ea6db442c0e857f22ac7c85f61b01a68810f`;
its OCI archive SHA-256 was
`76b906f78fb4c081155288a8a3dbfce80b54b00faea3a66a4f79a3408aabae96`.
It is test apparatus, not a production client image. The retained client first
failed closed because it still held generation-1 public trust inputs. After the
selected generation-4 policy and generation-4 public verification pair were
copied exactly between named volumes, the client completed protected push
`d8532f795f18` to `a0317a551b96`. Gitd active-ref and signer-state hashes both
changed. Gitd then shut down cleanly, restarted on the same named volumes, and
again passed all six startup gates. A fresh authenticated fetch advertised the
pushed objects and left local `main` and `origin/main` at zero ahead and zero
behind.

All client, Gitd, authority, signer, certificate, policy, key, state, and
runtime container mounts in this exercise were named volumes. Older Podman
rejected its `subpath=socket` option, so the signer runtime named volume was
mounted at its root and the non-secret socket path included the `socket/`
component. No bind-directory fallback was used. Several repository-scoped
one-hour test tokens were issued while diagnosing a missing Podman stdin flag
and the stale client policy. Their plaintext was never printed or stored, they
cannot be individually recovered for revocation, and they expire at Unix time
`1788550023`; this fixture limitation is not production token-lifecycle
evidence.

Older Podman copy-up changed the runtime volume root group on first mount. The
test restored the provisioned `21006:21906` owner/group and mode `2770` before
the authenticated client probe; the socket subdirectory and socket were
`21006:21906` modes `2770` and `0660`. This Podman-host workaround is evidence
of a compatibility gap, not evidence that Compose automatically preserves
those invariants on that older provider.

Remaining Phase 24 gates include a protected push during the overlap interval,
explicit stale-policy rollback rejection across daemon restarts, process-kill
injection around every transition phase, and a supported old-Podman startup
path that does not require manual runtime-volume metadata repair. This exercise
used a controlled certificate fixture, loopback publication, and test keys; it
does not establish public-service, real-certificate-renewal, production-key, or
physical-hardware evidence.

Patent review: **NOT_TRIGGERED**. This uses conventional immutable public-key
files, exact metadata/content validation, directory capabilities, and ordered
filesystem synchronization; it introduces no cryptographic algorithm or novel
key-rotation construction. See
[`docs/patents/REVIEW_LOG.md`](../../patents/REVIEW_LOG.md).
