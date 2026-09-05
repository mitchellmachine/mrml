#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-completion-20260905-config
prefix=mrml-completion-f-20260905
compose() { docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -p "$prefix" "$@"; }
gitd_before=$(docker inspect --format '{{.Id}} {{.State.Pid}} {{.State.StartedAt}}' "$prefix-gitd-1")
compose stop certd
docker inspect --format 'old certd exit={{.State.ExitCode}} finished={{.State.FinishedAt}}' "$prefix-certd-1"
sed 's/^MRML_ACME_VERSION=.*/MRML_ACME_VERSION=completion-f2-20260905/' acceptance.env > acceptance.env.new
chmod 0600 acceptance.env.new
mv acceptance.env.new acceptance.env
compose up -d --no-build --pull never --no-deps certd
compose exec -T certd /usr/bin/mrml-certd health
gitd_after=$(docker inspect --format '{{.Id}} {{.State.Pid}} {{.State.StartedAt}}' "$prefix-gitd-1")
[ "$gitd_before" = "$gitd_after" ]
printf 'Gitd preserved: %s\n' "$gitd_after"
MRML_GIT_VERSION=completion-f2-20260905 compose run --rm --no-deps -T git-client -C /work/first fetch origin
