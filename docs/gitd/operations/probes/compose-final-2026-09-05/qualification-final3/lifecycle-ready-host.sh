#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
prefix=mrml-completion-final3-20260905
input=/home/ubuntu/mrml-git-final3-20260905-config
cd "$input"
volume() { docker volume inspect --format '{{.Mountpoint}}' "$prefix-$1"; }
# No identity exists yet; lifecycle enrollment must nevertheless be ready.
compose() { docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -p "$prefix" "$@"; }
deadline=$(($(date +%s) + 40))
until compose exec -T certd /usr/bin/mrml-certd lifecycle-health; do
 [ "$(date +%s)" -lt "$deadline" ] || exit 1
 sleep 1
done
compose run --rm --no-deps -T git-certd-enroll enroll-csr /run/mrml/certd-acmed/certd.sock /run/secrets/certd-acmed.cap 21004 /config/config.json 1 /enrollment/csr.der
exchange=$(volume git-certificate-exchange)
install -m 0444 "$exchange/csr.der" "$input/csr.der"
printf '%s\n' 'fresh real-certd lifecycle enrollment CSR ready for local test CA signing'
