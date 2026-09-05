#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-final2-20260905-config
export MRML_ENV_FILE=$PWD/hybrid-g.env MRML_CONTAINER_RUNTIME=docker
prefix=mrml-git-restore-final-20260905
old=mrml-completion-final2-20260905
oldkeys=$(docker volume inspect --format '{{.Mountpoint}}' "$old-git-signer-keys")
MRML_VOLUME_PREFIX=$prefix ./install-volume-inputs.sh signer-receipt current "$oldkeys/authority-receipt-public.bin"
MRML_VOLUME_PREFIX=$prefix ./install-volume-inputs.sh signer-receipt next "$oldkeys/authority-receipt-public.bin"
compose() { MRML_RETAINED_CUSTODY_PREFIX=$old MRML_SECOND_CLIENT_PREFIX=$prefix docker compose --env-file hybrid-g.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -f compose.git.restore-acceptance.yaml -f compose.git.acceptance-second.yaml -p "$prefix" "$@"; }
work=$(docker volume inspect --format '{{.Mountpoint}}' "$prefix-git-client-work")
policies=$(docker volume inspect --format '{{.Mountpoint}}' "$prefix-gitd-policies")
selected=$(sed -n 's/^MRML_GIT_SIGNER_KEYS_VOLUME=//p' hybrid-g.env)
keys=$(docker volume inspect --format '{{.Mountpoint}}' "$selected")
install -m 0444 "$policies/owner/first/trust-policy.current" "$work/trust-first/trust-policy.current"
for name in openpgp-public.asc ml-dsa-public.bin; do install -m 0444 "$keys/$name" "$work/$name"; done
compose config --quiet
compose up -d --no-build --pull never --no-deps git-authority
docker compose --env-file hybrid-g.env -f compose.signer.yaml -p "$prefix-signer" up -d --no-build --pull never --no-deps git-protected-signer
docker compose --env-file hybrid-g.env -f compose.credential-agent.yaml -p "$prefix-credential" up -d --no-build --pull never --no-deps git-credential-agent
compose up -d --no-build --pull never gitd
# Wait for the real listener health gate, bounded by the configured startup grace.
ready=false
for attempt in $(seq 1 30); do
 if [ "$(docker inspect --format '{{.State.Health.Status}}' "$prefix-gitd-1")" = healthy ]; then ready=true; break; fi
 sleep 1
done
[ "$ready" = true ]
compose run --rm --no-deps -T git-client -C /work/restored-first fetch origin
printf '%s\n' 'protected push with generation-2 overlapping hybrid key' >> "$work/restored-first/acceptance.txt"
compose run --rm --no-deps -T git-client -C /work/restored-first add acceptance.txt
compose run --rm --no-deps -T git-client -C /work/restored-first commit -m 'Compose hybrid overlap push'
compose run --rm --no-deps -T git-client -C /work/restored-first push origin main
