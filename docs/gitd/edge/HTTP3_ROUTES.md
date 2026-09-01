# HTTP/3 route contract

`GitdHttp3Server<B>` implements `/`, `/projects`, repository overview, tree,
blob, commits, commit, branches, tags, releases, signatures, `/api/v1/`,
`robots.txt`, `sitemap.xml`, and `security.txt` against a generic backend.
Inputs are bounded validated identifiers, paths, and revisions.

Smart Git route names and media types exist, but return 503 until a bounded
streaming adapter is connected. This is deliberate fail-closed behavior. API
responses are currently minimal and **PARTIALLY IMPLEMENTED**.
