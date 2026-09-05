#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-final3-20260905-config
prefix=mrml-completion-final3-20260905
compose() { docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -p "$prefix" "$@"; }
before=$(docker inspect --format '{{.Id}} {{.State.Pid}} {{.State.StartedAt}}' "$prefix-gitd-1")
deadline=$(($(date +%s) + 40))
while :; do
 serial=$(openssl s_client -connect 127.0.0.1:32443 -servername git.example -CAfile acme-trust-roots.pem -verify_return_error -tls1_3 -alpn h2 </dev/null 2>/mnt/$prefix/measure-private/tls-oracle-errors | openssl x509 -noout -serial) || serial=
 [ "$serial" != 'serial=0BBA' ] || break
 [ "$(date +%s)" -lt "$deadline" ] || exit 1
 sleep 1
done
printf '%s\n' "$serial"
compose run --rm --no-deps -T git-client -C /work/first fetch origin
[ "$before" = "$(docker inspect --format '{{.Id}} {{.State.Pid}} {{.State.StartedAt}}' "$prefix-gitd-1")" ]
printf '%s\n' 'real certd generation 2 on new verified TLS 1.3/H2 connection PASS'
