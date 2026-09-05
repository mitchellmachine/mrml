#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-final2-20260905-config
prefix=mrml-completion-final2-20260905
second=mrml-completion-final2-second-20260905
compose() { docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -p "$prefix" "$@"; }
started=$(date +%s)
docker compose --env-file acceptance.env -f compose.signer.yaml -p "$prefix-signer" stop git-protected-signer
docker compose --env-file second.env -f compose.signer.yaml -p "$second-signer" stop git-protected-signer
docker compose --env-file acceptance.env -f compose.credential-agent.yaml -p "$prefix-credential" stop git-credential-agent
docker compose --env-file second.env -f compose.credential-agent.yaml -p "$second-credential" stop git-credential-agent
compose stop gitd git-authority
compose stop certd
for container in "$prefix-signer-git-protected-signer-1" "$second-signer-git-protected-signer-1" "$prefix-credential-git-credential-agent-1" "$second-credential-git-credential-agent-1" "$prefix-gitd-1" "$prefix-git-authority-1" "$prefix-certd-1"; do
 docker inspect --format '{{.Name}} exit={{.State.ExitCode}} finished={{.State.FinishedAt}}' "$container"
 [ "$(docker inspect --format '{{.State.ExitCode}}' "$container")" -eq 0 ]
done
printf 'seven clean stops elapsed_seconds=%s\n' "$(($(date +%s)-started))"
# Real certd is an independent custody service; retain it for restored Gitd.
docker compose --env-file acceptance.env -f compose.acme.yaml -p "$prefix" up -d --no-build --pull never --no-deps certd
compose exec -T certd /usr/bin/mrml-certd health
trusted=/var/snap/docker/common/mrml-completion-20260905/payload-final-candidate/deploy
MRML_ENV_FILE=$PWD/acceptance.env MRML_GIT_BACKUP_COMPOSE_FILE=$trusted/compose.git-backup.yaml sh "$trusted/backup-git.sh" 2026090501
