# MRML HTTP library

**Status: PARTIALLY IMPLEMENTED.** The library provides the existing HTTPS/1.1
client plus bounded, transport-independent HTTP/2 and HTTP/3 client/server
protocol engines.

`Http2Client` and `Http2Server` encode and decode the HTTP/2 connection preface,
SETTINGS, HEADERS, DATA, PING, GOAWAY, and WINDOW_UPDATE frame envelopes. Their
HPACK profile emits and accepts non-Huffman literal fields without dynamic-table
state. Unsupported HPACK representations fail closed.

`Http3Client` and `Http3Server` encode and decode HTTP/3 control-stream SETTINGS
and request-stream HEADERS/DATA frame envelopes. Their QPACK profile uses a zero
required-insert-count literal field section, avoiding a dynamic table and its
blocking state. Unsupported QPACK representations fail closed.

These are protocol-stream APIs, not socket APIs. The repository does not yet
provide UDP, QUIC, TLS ALPN, QUIC loss recovery, congestion control, connection
migration, or HTTP/3 datagrams. Consequently this milestone does not claim
end-to-end interoperability with arbitrary HTTP/2 or HTTP/3 peers. A caller must
supply the authenticated transport, stream identities, flow control, and
lifecycle rules appropriate to the protocol. The existing `Client` continues to
use HTTPS/1.1 over the current TLS/TCP implementation.

The focused Linux test is:

```text
./target/debug/mrml test org.mrml.library.http --target linux
```

Live HTTP/1.1 URL and range tests remain opt-in through their existing
environment variables. No external HTTP/2 or QUIC peer, Windows-native host, or
physical network device is exercised by the unit tests.

Patent review: **TRIGGERED** — implementing HTTP/2 HPACK and HTTP/3 QPACK wire
mechanisms requires the protocol and IETF declaration screening recorded in
[`../../../docs/patents/REVIEW_LOG.md`](../../../docs/patents/REVIEW_LOG.md).
