#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-final3-20260905-config
source_prefix=mrml-completion-final3-20260905
restore=mrml-git-restore-clean-20260905
trusted=/var/snap/docker/common/mrml-completion-20260905/payload-final-candidate/deploy
[ ! -e restore-g.env ]
umask 077
sed -e "s/^MRML_VOLUME_PREFIX=.*/MRML_VOLUME_PREFIX=$restore/" -e 's/^MRML_GIT_VERSION=.*/MRML_GIT_VERSION=completion-final-20260905/' acceptance.env > restore-g.env
chmod 0600 restore-g.env
MRML_VOLUME_PREFIX=$restore MRML_DEPLOY_ROOT=/mnt/mrml-git-restore-clean-20260905 sh "$trusted/provision-git-host.sh"
MRML_VOLUME_PREFIX=$restore sh "$trusted/provision-git-acceptance-host.sh"
install -m 0444 "$trusted/compose.git.restore-acceptance.yaml" compose.git.restore-acceptance.yaml

compose() { MRML_RETAINED_CUSTODY_PREFIX=$source_prefix docker compose --env-file restore-g.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -f compose.git.restore-acceptance.yaml -p "$restore" "$@"; }
compose config --quiet
compose run --rm --no-deps -T gitd validate-config /etc/mrml/gitd.conf
compose up -d --no-build --pull never --no-deps git-authority
compose run --rm --no-deps -T gitd recovery-status /etc/mrml/gitd.conf
compose up -d --no-build --pull never gitd
# Independent client key/state custody survives a Git/authority disaster.
docker compose --env-file acceptance.env -f compose.signer.yaml -p "$source_prefix-signer" up -d --no-build --pull never --no-deps git-protected-signer
docker compose --env-file acceptance.env -f compose.credential-agent.yaml -p "$source_prefix-credential" up -d --no-build --pull never --no-deps git-credential-agent
for attempt in $(seq 1 40); do
 if [ "$(docker inspect --format '{{.State.Health.Status}}' "$restore-gitd-1")" = healthy ]; then break; fi
 sleep 1
done
[ "$(docker inspect --format '{{.State.Health.Status}}' "$restore-gitd-1")" = healthy ]
compose run --rm --no-deps -T git-client clone https://git.example:8443/owner/first.git /work/restored-first
work=$(docker volume inspect --format '{{.Mountpoint}}' "$restore-git-client-work")
policies=$(docker volume inspect --format '{{.Mountpoint}}' "$restore-gitd-policies")
auth=$(docker volume inspect --format '{{.Mountpoint}}' "$restore-git-authority-config")
mkdir "$work/trust-first"
chown 21005:21005 "$work/trust-first"
chmod 0700 "$work/trust-first"
install -m 0444 "$policies/owner/first/trust-policy.current" "$work/trust-first/trust-policy.current"
for name in openpgp-public.asc ml-dsa-public.bin; do install -m 0444 "$auth/$name" "$work/$name"; done
cat >> "$work/restored-first/.git/config" <<'CONFIG'
[user]
 name = MRML Compose Test
 email = compose-test@git.example
[gpg.protected]
 signerProvider = unix-v1
 signerSocket = /run/mrml/git-protected-signer/signer.sock
 signerCapabilityFile = /run/mrml/client-signer/signer-channel
 signerUid = 21006
 signerGid = 21006
 trustPolicyDirectory = /work/trust-first
 openpgpPublicKeyFile = /work/openpgp-public.asc
 mlDsaPublicKeyFile = /work/ml-dsa-public.bin
CONFIG
(cd "$work/restored-first/text256" && sha256sum -c /mnt/mrml-completion-final3-20260905/measurements-text-v2/content.sha256)
printf '%s\n' 'native protected push after encrypted destructive restore' >> "$work/restored-first/acceptance.txt"
compose run --rm --no-deps -T git-client -C /work/restored-first add acceptance.txt
compose run --rm --no-deps -T git-client -C /work/restored-first commit -m 'Compose encrypted destructive restore push'
compose run --rm --no-deps -T git-client -C /work/restored-first push origin main
for suffix in gitd-repos gitd-state gitd-quarantine gitd-cache gitd-receipts gitd-policies gitd-secrets gitd-config authority-state git-authority-secrets git-authority-config; do
 if docker volume inspect "$source_prefix-$suffix" >/dev/null 2>&1; then echo 'source volume unexpectedly recreated' >&2; exit 1; fi
done
printf '%s\n' 'fresh clone hashes and isolated protected push passed with every old server source volume absent'
