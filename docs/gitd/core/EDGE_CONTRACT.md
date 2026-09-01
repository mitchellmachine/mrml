# Gitd edge contract

Status: **IMPLEMENTED** as a transport-neutral Rust API; no production backend
implementation is claimed.

The public API is exported from `mrml_git` and centered on
`GitdCoreBackend`. It provides repository generation and summary queries, exact
ref resolution, paginated commit/tree/blob reads, generation-bound verification
summaries, and a bounded streaming Smart Git call.

Security-sensitive values use validated types:

- `RepositoryIdentity` is exactly `owner/name`, bounded to 257 ASCII bytes;
- `FullRefName` is a bounded full `refs/...` name and rejects Git-dangerous
  sequences, control bytes, backslashes, and `.lock` aliases;
- `RepositoryPath` is a bounded relative tree path and rejects absolute paths,
  empty components, `.`, `..`, NUL, non-ASCII, and backslashes;
- repository, trust, and revocation generations are distinct types; and
- verified ref types expose only getters and have private fields.

`build_verified_fast_forward_transaction` is the only public constructor for
the current protected fast-forward transaction profile. It accepts at most 32
distinct full refs and requires one exact `VerifiedCommitRange` for every
`expected_old -> proposed_new` pair. Zero IDs, mixed formats, missing ranges,
creates, deletes, and history replacements fail closed. Creation, deletion, and
replacement will require separate policy-specific typestate builders rather
than optional IDs being interpreted as ambient authority.

`BoundedRead` and `BoundedWrite` expose remaining capacity. `WorkBudget`
separately limits input, output, memory, and work units. Implementations must
enforce the smaller of transport and backend limits and use checked arithmetic.

The shared pkt-line codec accepts lowercase hexadecimal canonical framing,
streams fragmented reads and writes, supports flush/delimiter/response-end
control packets, and caps total packet length at 65,520 bytes. Input, output,
and work budgets are charged for the four-byte header and payload before the
operation can continue. Invalid lengths, noncanonical hexadecimal, truncation,
and exhausted limits fail without invoking repository mutation.

The protocol-v2 core emits an exact capability advertisement for `ls-refs`,
`fetch=thin-pack ofs-delta sideband-all`, and the selected SHA-1 or SHA-256
object format. Its bounded request parser accepts `ls-refs` options and exact-
width fetch wants/haves for that format. Duplicate flags, malformed client
capabilities, unknown commands, and unsupported shallow, deepen, filter,
want-ref, packfile-URI, and future arguments fail closed. These parser tests do
not constitute a fetch backend: object negotiation, pack generation, side-band
response production and object negotiation are still disabled.

The receive-pack command boundary parses at most 32 exact-width SHA-1 or
SHA-256 old/new IDs and validated full ref names, requires `report-status-v2`
and `atomic`, rejects duplicate refs and unadvertised capabilities, and stops at
the command flush without consuming the pack body. SHA-256 commands must bind
`object-format=sha256`. A zero new ID is represented only as a deletion
candidate and is rejected unless the backend explicitly enabled deletion
candidates when it advertised `delete-refs`; the client cannot grant that
authority by echoing the server-only capability. Authorization still belongs
to a separate policy-specific verified transaction builder. The
parser cannot activate refs; receive pack-body quarantine and end-to-end
backend wiring remain open.

The bounded report-status-v2 writer emits the standard `unpack`, ordered `ok`
or `ng`, and flush packets. Since MRML does not use `proc-receive` rewriting,
it emits no option lines. Status names must exactly match every requested ref
in order; an atomic transaction can report all success or all failure, never a
mixed result. Error text is limited to 512 printable ASCII bytes and cannot
inject framing. When `side-band-64k` was selected, the complete inner report is
carried on band 1 in bounded outer packets followed by an outer flush. Golden
tests round-trip both plain and side-band output through the existing
first-party client parser. Pack-body quarantine and complete backend wiring
remain open.

Errors distinguish malformed input/identifiers/refs/paths, authorization,
object validation, ancestry, signature, policy, resources, storage, stale
generation, unsupported behavior, and uncertain durable outcomes. No private
key material is accepted by this API.

Golden validation examples:

```text
RepositoryIdentity  mitchellrenouf/mrml  -> accept
RepositoryIdentity  ../mrml              -> malformed identifier
FullRefName          refs/heads/main      -> accept
FullRefName          refs/heads/../main   -> malformed ref
RepositoryPath       src/lib.rs           -> accept
RepositoryPath       src/../secret        -> malformed path
```

The edge must never open repository files. It resolves application routes to a
repository capability and invokes this interface. Protocol capabilities must
be advertised only by a backend that completely implements them.
