#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-completion-20260905-config
prefix=mrml-completion-f-20260905
restore=mrml-git-restore-f-20260905
trusted=/var/snap/docker/common/mrml-completion-20260905/payload-f4-diagnostic/deploy
# Reverify the encrypted backup immediately before destroying only disposable
# source volumes. Independent certd custody, signer keys/state and backup keys
# remain retained; no other project is selected by any command below.
docker compose --env-file acceptance.env --profile admin -f "$trusted/compose.git-backup.yaml" run --rm --no-deps git-backup verify 2026090501
for service in gitd git-authority; do
 [ "$(docker inspect --format '{{.State.Status}} {{.State.ExitCode}}' "$prefix-$service-1")" = 'exited 0' ]
done
suffixes='gitd-repos gitd-state gitd-quarantine gitd-cache gitd-receipts gitd-policies gitd-secrets gitd-config authority-state git-authority-secrets git-authority-config'
for suffix in $suffixes; do
 volume=$prefix-$suffix
 [ "$(docker volume inspect --format '{{index .Labels "org.mrml.managed"}}' "$volume")" = true ]
 [ -z "$(docker ps -q --filter volume="$volume")" ]
 if docker volume inspect "$restore-$suffix" >/dev/null 2>&1; then
  echo 'restore target already exists' >&2; exit 1
 fi
done
docker rm "$prefix-gitd-1" "$prefix-git-authority-1"
for suffix in $suffixes; do docker volume rm "$prefix-$suffix"; done
for suffix in $suffixes; do
 if docker volume inspect "$prefix-$suffix" >/dev/null 2>&1; then exit 1; fi
done
printf '%s\n' 'eleven disposable source volumes absent; verified encrypted archive and independent custody retained'
MRML_ENV_FILE=$PWD/acceptance.env MRML_GIT_RESTORE_COMPOSE_FILE=$trusted/compose.git-restore.yaml sh "$trusted/restore-git.sh" 2026090501 "$restore"
