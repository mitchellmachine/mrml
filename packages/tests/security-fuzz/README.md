# MRML adversarial parser corpus

This package is a dependency-free, deterministic adversarial regression suite.
It runs structural, splice, poison-byte, truncation, and seeded pseudorandom
mutations over valid and minimized-invalid GGUF, ZIM, X.509 DER, ACME JSON,
URL, Base64url, ARI, HTTP-01, DNS packet/compression, PEM certificate-chain, and
certificate durable-record corpora.
Every failure is reproducible from source and suitable for minimization into a
normal regression test.

Run it on either supported host through the repository frontend:

```text
mrml test org.mrml.test.security-fuzz --target linux
mrml test org.mrml.test.security-fuzz --target windows
```

This is corpus-driven mutation and regression evidence, not a claim of compiler-
instrumented coverage-guided fuzzing. Sanitized Linux execution is provided by:

```text
mrml test org.mrml.test.security-fuzz --target linux --sanitizer address
```
