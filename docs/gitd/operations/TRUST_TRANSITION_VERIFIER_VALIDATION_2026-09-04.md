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

## Verification

```text
cargo fmt --all -- --check                                PASS
cargo clippy --all-targets -- -D warnings                 PASS
git diff --check                                          PASS
./target/debug/mrml test org.mrml.service.git-authority \
  --target linux                                          PASS
  authority library: 13 passed
  authority binary:   8 passed
./target/debug/mrml test org.mrml.tool.git --target linux PASS
  Git library:        274 passed
  Git CLI:            5 passed
  protected signer:   9 passed
  credential agent:   2 passed
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

An authority restart with trusted time after generation 4 failed closed before
creating its socket. The same retained state also failed the non-listening
`check-catalog` path. Retained trust-2, trust-3, and trust-4 verifier files were
present with UID/GID `21001:21001`, mode `0444`, one link, and exact expected
OpenPGP and ML-DSA sizes. The cause remains unresolved, so authority restart and
post-retirement protected-push evidence are explicitly not claimed.

Older Podman copy-up changed the runtime volume root group on first mount. The
test restored the provisioned `21006:21906` owner/group and mode `2770` before
the authenticated client probe; the socket subdirectory and socket were
`21006:21906` modes `2770` and `0660`. This Podman-host workaround is evidence
of a compatibility gap, not evidence that Compose automatically preserves
those invariants on that older provider.

Remaining Phase 24 gates include a protected push during overlap and after
retirement with Gitd and authority restarted together, explicit stale-policy
rollback rejection across daemon restarts, process-kill injection around every
transition phase, and a supported old-Podman startup path that does not require
manual runtime-volume metadata repair.

Patent review: **NOT_TRIGGERED**. This uses conventional immutable public-key
files, exact metadata/content validation, directory capabilities, and ordered
filesystem synchronization; it introduces no cryptographic algorithm or novel
key-rotation construction. See
[`docs/patents/REVIEW_LOG.md`](../../patents/REVIEW_LOG.md).
