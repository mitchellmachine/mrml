#!/bin/sh
set -eu
cd /home/ubuntu/mrml-git-completion-20260905-config
MRML_GIT_VERSION=completion-f2-20260905 /usr/bin/docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -p mrml-completion-f-20260905 run --rm --no-deps -T git-client -C /work/first fetch origin
openssl s_client -connect 127.0.0.1:32443 -servername git.example -CAfile acme-trust-roots.pem -verify_return_error -alpn h2 </dev/null 2> /tmp/mrml-completion-f2-tls-oracle-errors | openssl x509 -noout -serial -subject -issuer
