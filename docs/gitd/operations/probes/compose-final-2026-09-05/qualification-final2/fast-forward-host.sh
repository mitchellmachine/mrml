#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-final2-20260905-config
prefix=mrml-completion-final2-20260905
compose() { docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -p "$prefix" "$@"; }
compose run --rm --no-deps -T git-client -C /work/first-before-three pull origin main
work=$(docker volume inspect --format '{{.Mountpoint}}' "$prefix-git-client-work")
cmp "$work/first/acceptance.txt" "$work/first-before-three/acceptance.txt"
printf '%s\n' 'native fast-forward pull preserved exact file bytes'
