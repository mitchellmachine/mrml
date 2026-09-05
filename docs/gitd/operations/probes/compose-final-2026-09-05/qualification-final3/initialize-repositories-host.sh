#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-final3-20260905-config
prefix=mrml-completion-final3-20260905
compose() { docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -p "$prefix" "$@"; }
signer() { docker compose --env-file acceptance.env -f compose.signer.yaml -p "$prefix-signer" "$@"; }
volume() { docker volume inspect --format '{{.Mountpoint}}' "$prefix-$1"; }
signer run --rm --no-deps -T -v "$prefix-git-signer-keys:/key-generation:rw" git-trust-sign-current generate-key-material 21006 1788580000 /key-generation
keys=$(volume git-signer-keys)
auth=$(volume git-authority-config)
for name in openpgp-public.asc ml-dsa-public.bin; do
  [ ! -e "$auth/$name" ]
  install -m 0444 "$keys/$name" "$auth/$name"
  chown 21002:21002 "$auth/$name"
done
install -m 0444 authority-repositories.v1 "$auth/repositories.v1"
chown 21002:21002 "$auth/repositories.v1"
compose run --rm --no-deps -T gitd initialize-token-store /mnt/mrml/gitd/state/tokens.v2 /run/secrets/gitd-token-pepper 21001
for repository in owner/first owner/second; do
  compose run --rm --no-deps -T gitd initialize-repository /etc/mrml/gitd.conf "$repository"
  docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -f compose.git-policy-init.yaml -p "$prefix" run --rm --no-deps -T gitd initialize-protected-policy /etc/mrml/gitd.conf "$repository" /run/mrml-bootstrap/openpgp-public.asc /run/mrml-bootstrap/ml-dsa-public.bin 1788580000 1796356000
done
