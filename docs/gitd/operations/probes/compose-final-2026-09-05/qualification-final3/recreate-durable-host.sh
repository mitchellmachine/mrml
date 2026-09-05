#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-final3-20260905-config
prefix=mrml-git-restore-clean-20260905
old=mrml-completion-final3-20260905
compose() { MRML_RETAINED_CUSTODY_PREFIX=$old MRML_SECOND_CLIENT_PREFIX=$prefix docker compose --env-file hybrid-g.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -f compose.git.restore-acceptance.yaml -f compose.git.acceptance-second.yaml -p "$prefix" "$@"; }
second=mrml-completion-final3-second-20260905
docker compose --env-file second.env -f compose.signer.yaml -p "$second-signer" up -d --no-build --pull never --no-deps git-protected-signer
docker compose --env-file second.env -f compose.credential-agent.yaml -p "$second-credential" up -d --no-build --pull never --no-deps git-credential-agent
started=$(date +%s)
docker stop -t 15 "$prefix-gitd-1" "$prefix-git-authority-1" "$prefix-signer-git-protected-signer-1" "$prefix-credential-git-credential-agent-1" "$old-certd-1" "$second-signer-git-protected-signer-1" "$second-credential-git-credential-agent-1"
for container in "$prefix-gitd-1" "$prefix-git-authority-1" "$prefix-signer-git-protected-signer-1" "$prefix-credential-git-credential-agent-1" "$old-certd-1" "$second-signer-git-protected-signer-1" "$second-credential-git-credential-agent-1"; do
 [ "$(docker inspect --format '{{.State.ExitCode}}' "$container")" -eq 0 ]
 docker inspect --format '{{.Name}} exit={{.State.ExitCode}} finished={{.State.FinishedAt}}' "$container"
done
printf 'seven clean stops elapsed_seconds=%s\n' "$(($(date +%s)-started))"
# The ACME-only project cannot instantiate any deleted original Git volumes.
docker compose --env-file acceptance.env -f compose.acme.yaml -p "$old" up -d --force-recreate --no-build --pull never --no-deps certd
docker compose --env-file acceptance.env -f compose.acme.yaml -p "$old" exec -T certd /usr/bin/mrml-certd health
compose up -d --force-recreate --no-build --pull never --no-deps git-authority
docker compose --env-file hybrid-g.env -f compose.signer.yaml -p "$prefix-signer" up -d --force-recreate --no-build --pull never --no-deps git-protected-signer
docker compose --env-file hybrid-g.env -f compose.credential-agent.yaml -p "$prefix-credential" up -d --force-recreate --no-build --pull never --no-deps git-credential-agent
compose up -d --force-recreate --no-build --pull never gitd
ready=false
for attempt in $(seq 1 40); do
 if [ "$(docker inspect --format '{{.State.Health.Status}}' "$prefix-gitd-1")" = healthy ]; then ready=true; break; fi
 sleep 1
done
[ "$ready" = true ]
compose run --rm --no-deps -T git-client -C /work/restored-first fetch origin
compose run --rm --no-deps -T git-client -C /work/restored-first status
second=mrml-completion-final3-second-20260905
docker compose --env-file second.env -f compose.signer.yaml -p "$second-signer" up -d --no-build --pull never --no-deps git-protected-signer
docker compose --env-file second.env -f compose.credential-agent.yaml -p "$second-credential" up -d --no-build --pull never --no-deps git-credential-agent
MRML_RETAINED_CUSTODY_PREFIX=$old MRML_SECOND_CLIENT_PREFIX=$second MRML_GIT_CREDENTIAL_GENERATION=1 docker compose --env-file hybrid-g.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -f compose.git.restore-acceptance.yaml -f compose.git.acceptance-second.yaml -p "$prefix" run --rm --no-deps -T git-client clone https://git.example:8443/owner/second.git /work/durable-second
work=$(docker volume inspect --format '{{.Mountpoint}}' "$prefix-git-client-work")
(cd "$work/durable-second/random256" && sha256sum -c /mnt/mrml-completion-final3-20260905/measurements-random-v2/content.sha256)
for suffix in gitd-repos gitd-state gitd-quarantine gitd-cache gitd-receipts gitd-policies gitd-secrets gitd-config authority-state git-authority-secrets git-authority-config; do
 if docker volume inspect "$old-$suffix" >/dev/null 2>&1; then echo 'deleted source unexpectedly recreated' >&2; exit 1; fi
done
printf '%s\n' 'container recreation preserved native durable generations and original source absence'
