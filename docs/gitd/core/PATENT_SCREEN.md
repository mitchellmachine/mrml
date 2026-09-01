# Gitd core branch patent screen

This is technical screening, not legal advice, patent clearance, or an
infringement conclusion.

The implemented change is limited to conventional bounded identifier
validation, typed generations, streaming traits, classified errors, and opaque
verified-transaction types. Patent review: NOT_TRIGGERED for that boundary.

The bounded fixed-Huffman LZ77/DEFLATE encoder now triggers the repository
process. Patent review: TRIGGERED. The implementation follows only RFC 1951's
general hash-chain compressor shape: a 32 KiB window, a fixed 256-candidate
search ceiling, standard fixed codes, and standard length/distance symbols. It
does not copy an implementation or add specialized parsing, hardware, media,
dictionary, or protocol-specific compression mechanisms.

The technical screen checked the IETF disclosure search for RFC 1951 on
2026-09-01; it reported no disclosures submitted directly against RFC 1951 or
its predecessor draft. RFC 1951 itself warns that LZ77 variations may be
patented and describes its general algorithm as known not to be patented per
se. Those statements are discovery context, not authoritative Canadian status
and not a royalty-free grant. No CIPO number was identified by this bounded
mechanism search, and no patent-clearance, non-infringement, validity, or legal
conclusion is made. Search confidence is LOW, technical-overlap confidence is
MEDIUM for the exact general RFC mechanism, and legal-status confidence is LOW.

Dynamic Huffman construction, bounded delta selection, cross-pack
recomputation, pack caching, and compaction remain `REMAINS_OPEN` and require
their own mechanism-level Canadian search and CIPO verification before
implementation. The shared review log must be updated during integration;
Agent A's file boundary does not authorize editing it here. Follow
`docs/patents/README.md`.

The OFS/REF validation path only decodes Git's standard copy/insert form,
follows exact offsets or full object IDs, and enforces work and depth limits. It
does not search for similar objects, select bases, or construct deltas. Patent
review: NOT_TRIGGERED for this bounded interoperability resolver. Delta
selection and cross-pack recomputation retain the separate `REMAINS_OPEN`
trigger above.
