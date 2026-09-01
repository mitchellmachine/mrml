# QUIC v2 security state

QUIC v2 constants, packet types, Initial secrets, authenticated version
information, bounded packet history, receive flow control, sparse reassembly,
anti-amplification, and path validation are **IMPLEMENTED** with focused hosted
tests. Gitd must select v2 explicitly; no silent v1 downgrade is allowed.

Retry tokens bind the exact IPv4 address and port, original destination ID,
issuance time, purpose, and rotating key generation. Tokens are AEAD protected,
single-use within bounded replay storage, and limited to 256 bytes. Half-open
admission is bounded globally, per IPv4 address, by memory, and by lifetime.

Application traffic closes before conservative packet or byte limits and on an
unsupported key-phase change. Full key update, reordered old-phase handling, a
persistent endpoint, connection-ID lifecycle tables, and IPv6 `/64` admission
are **PLANNED**. The runtime address ABI is currently IPv4-only.
