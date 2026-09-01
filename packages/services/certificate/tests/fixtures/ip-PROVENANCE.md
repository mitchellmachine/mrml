# IP certificate fixture provenance

Generated on 2026-09-01 solely as an independently structured test oracle with
`OpenSSL 3.6.4 25 Aug 2026`. The root and leaf use independently generated P-256
keys. The leaf has critical `CA:false`, critical digital-signature key usage,
TLS Web Server Authentication EKU, and the exact SAN set `git.example`,
`192.0.2.1`, and `2001:db8::1`. Private keys and the CSR were not retained.

Commands used:

```text
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -x509 -sha256 -days 3650 -config root.cnf -keyout root.key -out root.pem
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 -config leaf.cnf -keyout leaf.key -out leaf.csr
openssl x509 -req -in leaf.csr -CA root.pem -CAkey root.key -CAcreateserial -days 365 -sha256 -extfile leaf.cnf -extensions leaf_ext -out leaf-only.pem
```

SHA-256 of the PEM files:

```text
f3af80d9b7263579025bc9423e61327ef846afb9e80fc6ab69c564bd297e223b  ip-leaf.pem
4d58ae9b55f8814d5f3374ac64590158899f073c4d9e898394deae2f35753aec  ip-root.pem
```
