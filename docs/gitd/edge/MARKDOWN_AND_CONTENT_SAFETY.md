# Markdown and repository content safety

The bounded renderer escapes raw HTML, rejects traversal and malformed percent
encoding, rejects unsafe URI schemes, and resolves relative links through exact
repository object context. Repository content is data and cannot create policy,
authority, scripts, active HTML, or privileged fetches.

The current renderer is deliberately small. Full CommonMark coverage, unique
heading identifiers, bounded syntax highlighting, image-origin isolation, and
golden hostile-content fixtures remain **PLANNED**.
