#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-final3-20260905-config
prefix=mrml-completion-final3-20260905
compose() { docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -p "$prefix" "$@"; }
before=$(docker inspect --format '{{.Id}} {{.State.Pid}} {{.State.StartedAt}}' "$prefix-gitd-1")
exchange=$(docker volume inspect --format '{{.Mountpoint}}' "$prefix-git-certificate-exchange")
install -m 0444 /home/ubuntu/mrml-git-completion-20260905-config/chain-clean2.pem "$exchange/chain2.pem"
compose run --rm --no-deps -T git-certd-enroll enroll-activate /run/mrml/certd-acmed/certd.sock /run/secrets/certd-acmed.cap 21004 /config/config.json 101 2 4444444444444444444444444444444444444444444444444444444444444444 /enrollment/chain2.pem
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
