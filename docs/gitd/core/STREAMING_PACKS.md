# Streaming pack production

Status: **PARTIALLY IMPLEMENTED**.

The Git library can write a no-delta pack directly to a caller-owned output
sink. Pack headers, stored-DEFLATE blocks, Adler-32 values, and the Git pack
trailer are produced incrementally. Each content write is at most 65,535 bytes,
and the SHA-1 or SHA-256 trailer authenticates the exact bytes accepted by the
sink. Object identifiers are recomputed before any object is emitted, so a
mixed-format or mislabeled object fails closed.

This removes the second whole-pack allocation from the bounded production
profile. The current interface still receives caller-owned `PackObject`
contents; repository traversal and Smart Git response wiring must be converted
to a pull source before end-to-end constant-memory or network-backpressure
claims are warranted. Delta selection remains available through the existing
in-memory encoder and is deliberately not part of this bounded profile.

Focused evidence on hosted Linux:

- `./target/debug/mrml test org.mrml.tool.git --target linux`: 193 library and
  3 CLI tests passed, including a 200,000-byte SHA-256 object streamed in fixed
  writes and reparsed with an independently recomputed trailer.

Patent review: **NOT_TRIGGERED**. This increment composes the conventional Git
pack version 2 format, stored DEFLATE blocks, Adler-32, and existing SHA-1/SHA-256
trailer rules without adding a new compression, transport, or scheduling
mechanism. See [`docs/patents/REVIEW_LOG.md`](../../patents/REVIEW_LOG.md).
