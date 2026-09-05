#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-final3-20260905-config
prefix=mrml-completion-final3-20260905
install -m 0444 /var/snap/docker/common/mrml-completion-20260905/payload-final-candidate/deploy/compose.git-response-loss.yaml compose.git-response-loss.yaml
compose() { MRML_GIT_VERSION=completion-final-20260905 docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -p "$prefix" "$@"; }
fault() { MRML_GIT_VERSION=completion-final-20260905 docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -f compose.git-response-loss.yaml -p "$prefix" "$@"; }
work=$(docker volume inspect --format '{{.Mountpoint}}' "$prefix-git-client-work")
printf '%s\n' 'drop encrypted response and reconcile exact protected candidate' >> "$work/first/acceptance.txt"
compose run --rm --no-deps -T git-client -C /work/first add acceptance.txt
compose run --rm --no-deps -T git-client -C /work/first commit -m 'Compose response loss reconciliation'
fault config --quiet
fault up -d --no-build --pull never --no-deps git-response-loss
fault run --rm --no-deps -T git-client -C /work/first push origin main
docker logs "$prefix-git-response-loss-1"
compose run --rm --no-deps -T git-client -C /work/first fetch origin
compose run --rm --no-deps -T git-client -C /work/first status
