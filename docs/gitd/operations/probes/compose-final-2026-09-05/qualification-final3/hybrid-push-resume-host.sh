#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-final3-20260905-config
export MRML_ENV_FILE=$PWD/hybrid-g.env MRML_CONTAINER_RUNTIME=docker
prefix=mrml-git-restore-clean-20260905
old=mrml-completion-final3-20260905
compose() { MRML_RETAINED_CUSTODY_PREFIX=$old MRML_SECOND_CLIENT_PREFIX=$prefix docker compose --env-file hybrid-g.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -f compose.git.restore-acceptance.yaml -f compose.git.acceptance-second.yaml -p "$prefix" "$@"; }
work=$(docker volume inspect --format '{{.Mountpoint}}' "$prefix-git-client-work")
printf '%s\n' 'protected push with generation-2 overlapping hybrid key' >> "$work/restored-first/acceptance.txt"
compose run --rm --no-deps -T git-client -C /work/restored-first add acceptance.txt
compose run --rm --no-deps -T git-client -C /work/restored-first commit -m 'Compose hybrid overlap push'
compose run --rm --no-deps -T git-client -C /work/restored-first push origin main
