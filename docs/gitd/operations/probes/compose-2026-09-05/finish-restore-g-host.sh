#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-completion-20260905-config
source_prefix=mrml-completion-f-20260905
restore=mrml-git-restore-g-20260905
trusted=/var/snap/docker/common/mrml-completion-20260905/payload-f5-diagnostic/deploy
compose() { MRML_RETAINED_CUSTODY_PREFIX=$source_prefix docker compose --env-file restore-g.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -f compose.git.restore-acceptance.yaml -p "$restore" "$@"; }
work=$(docker volume inspect --format '{{.Mountpoint}}' "$restore-git-client-work")
policies=$(docker volume inspect --format '{{.Mountpoint}}' "$restore-gitd-policies")
auth=$(docker volume inspect --format '{{.Mountpoint}}' "$restore-git-authority-config")
mkdir "$work/trust-first"
chown 21005:21005 "$work/trust-first"
chmod 0700 "$work/trust-first"
install -m 0444 "$policies/owner/first/trust-policy.current" "$work/trust-first/trust-policy.current"
for name in openpgp-public.asc ml-dsa-public.bin; do install -m 0444 "$auth/$name" "$work/$name"; done
cat >> "$work/restored-first-attempt3/.git/config" <<'CONFIG'
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
(cd "$work/restored-first-attempt3/text256" && sha256sum -c /mnt/mrml-completion-f-20260905/measurements-text-v1/content.sha256)
printf '%s\n' 'native protected push after encrypted destructive restore' >> "$work/restored-first-attempt3/acceptance.txt"
compose run --rm --no-deps -T git-client -C /work/restored-first-attempt3 add acceptance.txt
compose run --rm --no-deps -T git-client -C /work/restored-first-attempt3 commit -m 'Compose encrypted destructive restore push'
compose run --rm --no-deps -T git-client -C /work/restored-first-attempt3 push origin main
for suffix in gitd-repos gitd-state gitd-quarantine gitd-cache gitd-receipts gitd-policies gitd-secrets gitd-config authority-state git-authority-secrets git-authority-config; do
 if docker volume inspect "$source_prefix-$suffix" >/dev/null 2>&1; then echo 'source volume unexpectedly recreated' >&2; exit 1; fi
done
printf '%s\n' 'fresh clone hashes and isolated protected push passed with every old server source volume absent'
