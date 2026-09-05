#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-final2-20260905-config
prefix=mrml-completion-final2-20260905
compose() { docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -p "$prefix" "$@"; }
volume() { docker volume inspect --format '{{.Mountpoint}}' "$prefix-$1"; }
work=$(volume git-client-work)
policies=$(volume gitd-policies)
auth=$(volume git-authority-config)
mkdir "$work/trust-first"
chown 21005:21005 "$work/trust-first"
chmod 0700 "$work/trust-first"
install -m 0444 "$policies/owner/first/trust-policy.current" "$work/trust-first/trust-policy.current"
for name in openpgp-public.asc ml-dsa-public.bin; do install -m 0444 "$auth/$name" "$work/$name"; done
cat >> "$work/first/.git/config" <<'CONFIG'
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
for sequence in 1 2 3; do
  printf 'MRML exact Compose protected push %s\n' "$sequence" > "$work/first/acceptance.txt"
  chown 21005:21005 "$work/first/acceptance.txt"
  compose run --rm --no-deps -T git-client -C /work/first add acceptance.txt
  compose run --rm --no-deps -T git-client -C /work/first commit -m "Compose protected push $sequence"
  compose run --rm --no-deps -T git-client -C /work/first push origin main
done
compose run --rm --no-deps -T git-client -C /work/first fetch origin
compose run --rm --no-deps -T git-client clone https://git.example:8443/owner/first.git /work/first-after-three
