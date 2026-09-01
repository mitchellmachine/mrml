# Markdown and repository content safety

The bounded renderer escapes raw HTML, rejects traversal and malformed percent
encoding, rejects unsafe URI schemes, and resolves relative links through exact
repository object context. Heading identifiers are deterministic and unique;
inline/fenced code is escaped, and fenced language classes use a fixed allowlist.
Repository content is data and cannot create policy, authority, scripts, active
HTML, or privileged fetches.

The current renderer is deliberately small. Full CommonMark coverage, bounded
syntax highlighting, image-origin isolation, and broader golden hostile-content
fixtures remain **PLANNED**.
