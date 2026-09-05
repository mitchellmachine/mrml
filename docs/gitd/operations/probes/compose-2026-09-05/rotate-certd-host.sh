#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-completion-20260905-config
prefix=mrml-completion-f-20260905
compose() { MRML_GIT_VERSION=completion-f2-20260905 docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -p "$prefix" "$@"; }
compose run --rm --no-deps -T git-certd-enroll enroll-activate /run/mrml/certd-acmed/certd.sock /run/secrets/certd-acmed.cap 21004 /config/config.json 1 2 4444444444444444444444444444444444444444444444444444444444444444 /enrollment/chain2.pem
compose exec -T certd /usr/bin/mrml-certd health
compose run --rm --no-deps -T git-client -C /work/first fetch origin
openssl s_client -connect 127.0.0.1:32443 -servername git.example -CAfile acme-trust-roots.pem -verify_return_error -alpn h2 </dev/null 2> /tmp/mrml-completion-f2-tls-oracle-errors | openssl x509 -noout -serial -subject -issuer
