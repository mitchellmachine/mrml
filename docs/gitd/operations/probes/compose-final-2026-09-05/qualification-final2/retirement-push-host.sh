#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-final2-20260905-config
prefix=mrml-git-restore-final-20260905
old=mrml-completion-final2-20260905
created=$(sed -n 's/^MRML_OPENPGP_CREATED_AT=//p' acceptance.env)
state=$(docker volume inspect --format '{{.Mountpoint}}' "$prefix-git-signer-state")
before=$(sha256sum "$state/generation.state" | awk '{print $1}')
status=0
MRML_OPENPGP_CREATED_AT=$created MRML_GIT_SIGNER_KEYS_VOLUME=$prefix-git-signer-keys docker compose --env-file hybrid-g.env -f compose.signer.yaml -p "$prefix-retired-exact" run --rm --no-deps -T git-protected-signer || status=$?
[ "$status" -eq 78 ]
[ "$(sha256sum "$state/generation.state" | awk '{print $1}')" = "$before" ]
printf '%s\n' 'exact retired private pair and original creation time rejected with exit 78; state unchanged'
compose() { MRML_RETAINED_CUSTODY_PREFIX=$old MRML_SECOND_CLIENT_PREFIX=$prefix docker compose --env-file hybrid-g.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -f compose.git.restore-acceptance.yaml -f compose.git.acceptance-second.yaml -p "$prefix" "$@"; }
work=$(docker volume inspect --format '{{.Mountpoint}}' "$prefix-git-client-work")
policies=$(docker volume inspect --format '{{.Mountpoint}}' "$prefix-gitd-policies")
install -m 0444 "$policies/owner/first/trust-policy.current" "$work/trust-first/trust-policy.current"
compose up -d --no-build --pull never --no-deps git-authority
docker compose --env-file hybrid-g.env -f compose.signer.yaml -p "$prefix-signer" up -d --no-build --pull never --no-deps git-protected-signer
compose up -d --no-build --pull never gitd
ready=false
for attempt in $(seq 1 40); do
 if [ "$(docker inspect --format '{{.State.Health.Status}}' "$prefix-gitd-1")" = healthy ]; then ready=true; break; fi
 sleep 1
done
[ "$ready" = true ]
printf '%s\n' 'protected push after retirement with the surviving hybrid pair' >> "$work/restored-first/acceptance.txt"
compose run --rm --no-deps -T git-client -C /work/restored-first add acceptance.txt
compose run --rm --no-deps -T git-client -C /work/restored-first commit -m 'Compose surviving hybrid key after retirement'
compose run --rm --no-deps -T git-client -C /work/restored-first push origin main
compose run --rm --no-deps -T git-client -C /work/restored-first fetch origin
compose run --rm --no-deps -T git-client -C /work/restored-first status
