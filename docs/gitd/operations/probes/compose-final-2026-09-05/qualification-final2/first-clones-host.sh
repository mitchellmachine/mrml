#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-final2-20260905-config
prefix=mrml-completion-final2-20260905
compose() { docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -p "$prefix" "$@"; }
for attempt in $(seq 1 40); do
 if [ "$(docker inspect --format '{{.State.Health.Status}}' "$prefix-gitd-1")" = healthy ]; then break; fi
 sleep 1
done
[ "$(docker inspect --format '{{.State.Health.Status}}' "$prefix-gitd-1")" = healthy ]
compose run --rm --no-deps -T git-client clone https://git.example:8443/owner/first.git /work/first
compose run --rm --no-deps -T git-client clone https://git.example:8443/owner/first.git /work/first-before-three
compose run --rm --no-deps -T git-client -C /work/first fetch origin
