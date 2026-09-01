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

`BoundedRead` and `BoundedWrite` expose remaining capacity. `WorkBudget`
separately limits input, output, memory, and work units. Implementations must
enforce the smaller of transport and backend limits and use checked arithmetic.

The shared pkt-line codec accepts lowercase hexadecimal canonical framing,
streams fragmented reads and writes, supports flush/delimiter/response-end
control packets, and caps total packet length at 65,520 bytes. Input, output,
and work budgets are charged for the four-byte header and payload before the
operation can continue. Invalid lengths, noncanonical hexadecimal, truncation,
and exhausted limits fail without invoking repository mutation.

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
