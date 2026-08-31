# MRML HTTP library

**Status: IMPLEMENTED for the bounded Canadian baseline; not production-ready.**
The library provides HTTPS/1.1, authenticated HTTP/2 client/server connections,
and single-path QUIC v1 plus HTTP/3 client/server connections.

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

`QuicClientConnection` and `QuicServerListener` bind the protocol to bounded UDP
I/O. They implement v1 Initial, Handshake, and 1-RTT packet protection; CRYPTO
and STREAM reassembly; TLS 1.3 `h3` ALPN and transport parameters; the
anti-amplification limit; ACK processing; NewReno-like congestion accounting;
bounded timeout retransmission; flow control; server HANDSHAKE_DONE; and
PATH_CHALLENGE/PATH_RESPONSE validation before accepting a rebound address.
Initial datagrams are padded to at least 1200 bytes, and the hybrid TLS
ClientHello is fragmented across CRYPTO frames when needed.

All TLS clients request and require a current issuer-signed stapled OCSP
response by default, so the policy applies equally to HTTP/1.1, HTTP/2, and
HTTP/3. Servers can attach the staple through `TlsServerConfig`. Clients and
servers try X25519MLKEM768 first and retain standard X25519 as the negotiated
fallback.

The profile deliberately disables 0-RTT and excludes simultaneous multipath,
packet striping, MASQUE, QUIC-aware proxying, CDN/cross-server migration,
policy-encoded connection IDs, DATAGRAM retransmission, FEC, alternative
congestion controllers, bespoke TLS identity extensions, and hardware offload.

The focused Linux test is:

```text
./target/debug/mrml test org.mrml.library.http --target linux
```

Live HTTP/1.1 URL and range tests remain opt-in through their existing
environment variables. The focused tests exercise codecs, RFC vectors,
adversarial bounds, state machines, packet protection, and loopback UDP. They do
not establish external HTTP/2/HTTP/3 interoperability, Windows-native, physical
network, Internet-loss, or production evidence.

Patent review: **TRIGGERED**, disposition **CONDITIONAL_PROCEED** for the exact
Canada-only bounded profile recorded in
[`../../../docs/patents/REVIEW_LOG.md`](../../../docs/patents/REVIEW_LOG.md).
