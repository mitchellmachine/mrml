# MRML HTTP library

**Status: IMPLEMENTED for the bounded Canadian baseline; not production-ready.**
The library provides HTTPS/1.1, authenticated HTTP/2 client/server connections,
and single-path QUIC v1/v2 plus HTTP/3 client/server connections.

`Http2Client` and `Http2Server` encode and decode the HTTP/2 connection preface,
SETTINGS, HEADERS, DATA, PING, GOAWAY, and WINDOW_UPDATE frame envelopes. Their
HPACK profile uses the RFC static table, accepts the RFC Huffman code, advertises
a zero dynamic-table capacity, validates SETTINGS and flow-control fields, and
enforces continuation sequencing. `Http2ClientConnection` and
`Http2ServerConnection` require TLS 1.3 `h2` ALPN.

`Http3Client` and `Http3Server` encode and decode HTTP/3 control-stream SETTINGS
and request-stream HEADERS/DATA frame envelopes. Their QPACK profile uses the
RFC static table and Huffman code with dynamic capacity and blocked streams set
to zero. Critical control/QPACK streams, SETTINGS-first ordering, descending
GOAWAY identifiers, and request-stream frame ordering are checked.
`Http3WorkerPool` prepares independent response streams on a bounded number of
native workers with bounded queues and backpressure. The authoritative caller
alone applies prepared frames to QUIC, so packet numbers, recovery, congestion
control, path state, and UDP I/O remain single-owner. This accelerates QPACK and
response framing without introducing multipath or shared mutable QUIC state.

`QuicClientConnection` and `QuicServerListener` bind the protocol to bounded UDP
I/O. They implement RFC 9000 v1 and RFC 9369 v2 Initial, Handshake, and 1-RTT
packet protection; version-specific salts, HKDF labels, wire codepoints, and
long-header types; authenticated RFC 9368 `version_information` validation;
CRYPTO and STREAM reassembly; TLS 1.3 `h3` ALPN and transport parameters; the
anti-amplification limit; ACK processing; NewReno-like congestion accounting;
bounded timeout retransmission; flow control; server HANDSHAKE_DONE; and
PATH_CHALLENGE/PATH_RESPONSE validation before accepting a rebound address.
Initial datagrams are padded to at least 1200 bytes, and the hybrid TLS
ClientHello is fragmented across CRYPTO frames when needed.
Authenticated application packet numbers are classified through bounded receive
ranges before frame side effects; duplicates and too-old packets are suppressed.
Sparse stream chunks, gaps, buffered bytes, stream counts, final sizes, and
connection/per-stream receive credit are bounded before allocation. HTTP/3
retains request and completed-stream state so one stream delivers at most one
request.
Servers accept direct v1 and v2 connections. Clients retain v1 as the
compatibility default and expose `connect_v2`/`connect_version` for an explicit
v2 first flight. Missing or inconsistent version information fails closed for
v2; legacy v1-only peers may omit it. The implementation does not claim 0-RTT,
compatible-version switching during one handshake, or session tickets.

Reusable Retry-token and half-open admission primitives are implemented but are
not yet connected to `QuicServerListener`. Tokens bind the exact IPv4 endpoint,
original destination connection ID, issue time, purpose, and rotating key
generation, with bounded replay state. Admission is bounded by global count,
IPv4 source, memory, and lifetime and can require Retry under pressure. IPv6
`/64` policy awaits an IPv6-capable runtime address ABI. `QuicServerEndpoint`
persistently owns UDP and bounds handshake, established, and retired connection
ID routing before decryption. The one-shot listener remains non-production until
handshake and established protocol state move into that endpoint reactor.
Application traffic closes before conservative per-key packet/byte limits; full
QUIC key update is not implemented.

All TLS clients request and require a current stapled OCSP response by default,
so the policy applies equally to HTTP/1.1, HTTP/2, and HTTP/3. Responses may be
issuer-signed or signed by one bounded embedded delegated responder that chains
to the issuer, is time-valid, matches responderID byName, has the OCSP-signing
EKU, and has no unsupported critical extension. responderID byKey remains
unsupported because this profile has no SHA-1 identity primitive and therefore
fails closed. Servers can attach the staple through `TlsServerConfig`. Clients
and servers try X25519MLKEM768 first and retain standard X25519 as the negotiated
fallback.

`CrlSet` provides a bounded supplementary hard-deny import for a CRX-verified
Chromium CRLSet. It checks format/version, freshness, monotonic sequence,
blocked SPKIs, issuer hashes, serials, and allocation ceilings. `Unknown` is
never treated as approval and stapled OCSP remains mandatory. The opt-in
`ChromiumCrlSetUpdater` POSTs an Omaha request to Chromium's official component
endpoint and derives the current HTTPS CRX URL and advertised SHA-256 hash. It
does not install an artifact: the updater service must verify the CRX3
signature against the pinned CRLSet component key, verify the package hash,
parse freshness/sequence, and atomically commit owner-approved state.

The profile deliberately disables 0-RTT and excludes simultaneous multipath,
packet striping, MASQUE, QUIC-aware proxying, CDN/cross-server migration,
policy-encoded connection IDs, DATAGRAM retransmission, FEC, alternative
congestion controllers, bespoke TLS identity extensions, and hardware offload.

The focused Linux test is:

```text
./target/debug/mrml test org.mrml.library.http --target linux
```

Authenticated independent-client probes use the generated certificate, issuer,
private-key, and OCSP fixtures with `MRML_HTTP2_LOOPBACK_*` or
`MRML_HTTP3_LOOPBACK_*`, plus `MRML_HTTP2_CURL` or `MRML_HTTP3_CURL`. The curl
HTTP/2 probe also covers TLS 1.3 compatibility ChangeCipherSpec handling and
the default OpenSSL X25519MLKEM768-first negotiation.
Setting `MRML_HTTP3_LOOPBACK_V2=1` uses the MRML client for a direct,
authenticated end-to-end QUIC v2 HTTP/3 loopback.

Live HTTP/1.1 URL and range tests remain opt-in through their existing
environment variables. The focused tests exercise codecs, RFC vectors,
adversarial bounds, state machines, packet protection, and loopback UDP. They do
establish hosted Linux interoperability from independent curl 8.21.0/nghttp2
and curl 8.21.0/ngtcp2/nghttp3 clients to the MRML HTTP/2 and HTTP/3 servers.
A public Cloudflare HTTP/3 probe validated its ECDSA chain through the trusted
cross-signed root identity and then failed closed because the peer supplied no
stapled OCSP response; that is revocation-policy evidence, not a successful
public HTTP/3 request. The tests do not establish Windows-native, physical
network, Internet-loss, public-client success, or production evidence.

Patent review: **TRIGGERED**, disposition **CONDITIONAL_PROCEED** for the exact
Canada-only bounded profile recorded in
[`../../../docs/patents/REVIEW_LOG.md`](../../../docs/patents/REVIEW_LOG.md).
