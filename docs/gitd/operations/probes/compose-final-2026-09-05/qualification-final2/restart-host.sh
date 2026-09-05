#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-final2-20260905-config
prefix=mrml-completion-final2-20260905
compose() { docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -p "$prefix" "$@"; }
before=$(docker inspect --format '{{.Id}} {{.State.Pid}} {{.State.StartedAt}}' "$prefix-gitd-1")
compose restart git-authority
compose run --rm --no-deps -T git-client -C /work/first fetch origin
docker compose --env-file acceptance.env -f compose.signer.yaml -p "$prefix-signer" restart git-protected-signer
compose run --rm --no-deps -T git-client -C /work/first fetch origin
docker compose --env-file acceptance.env -f compose.credential-agent.yaml -p "$prefix-credential" restart git-credential-agent
compose run --rm --no-deps -T git-client -C /work/first fetch origin
compose stop certd
[ "$(docker inspect --format '{{.State.ExitCode}}' "$prefix-certd-1")" = 0 ]
if compose run --rm --no-deps -T git-client -C /work/first fetch origin; then echo 'new work incorrectly accepted without certd' >&2; exit 1; fi
[ "$before" = "$(docker inspect --format '{{.Id}} {{.State.Pid}} {{.State.StartedAt}}' "$prefix-gitd-1")" ]
compose up -d --no-build --pull never --no-deps certd
compose exec -T certd /usr/bin/mrml-certd health
deadline=$(($(date +%s) + 40))
until compose exec -T gitd /usr/bin/mrml-gitd listener-health /etc/mrml/gitd.conf >/dev/null 2>&1; do
 [ "$(date +%s)" -lt "$deadline" ] || exit 1
 sleep 1
done
compose run --rm --no-deps -T git-client -C /work/first fetch origin
[ "$before" = "$(docker inspect --format '{{.Id}} {{.State.Pid}} {{.State.StartedAt}}' "$prefix-gitd-1")" ]
work=$(docker volume inspect --format '{{.Mountpoint}}' "$prefix-git-client-work")
printf '%s\n' 'native protected push after independent daemon restarts' >> "$work/first/acceptance.txt"
compose run --rm --no-deps -T git-client -C /work/first add acceptance.txt
compose run --rm --no-deps -T git-client -C /work/first commit -m 'Independent daemon restart recovery'
compose run --rm --no-deps -T git-client -C /work/first push origin main
printf '%s\n' 'authority, signer, credential and real-certd restart recovery PASS; Gitd process unchanged'
