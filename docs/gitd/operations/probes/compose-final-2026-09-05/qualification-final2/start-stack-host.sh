#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-final2-20260905-config
prefix=mrml-completion-final2-20260905
compose() { docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -p "$prefix" "$@"; }
volume() { docker volume inspect --format '{{.Mountpoint}}' "$prefix-$1"; }
private=/mnt/mrml-completion-final2-20260905/secrets/admin
umask 077
describe() {
  compose run --rm --no-deps -T git-authority "$1" /run/mrml/git-authority/authority.sock /run/secrets/git-authority-channel 21001 21001 21002 21002 /var/lib/mrml/git-policies /var/lib/mrml/authority/proofs /var/lib/mrml/authority/generations owner/first /etc/mrml/authority/openpgp-public.asc /etc/mrml/authority/ml-dsa-public.bin /run/secrets/receipt.key 1788580000 1
}
describe describe-signer > "$private/signer-identity.hex"
describe describe-receipt-verifier > "$private/receipt-public.hex"
identity=$(cat "$private/signer-identity.hex")
[ "${#identity}" -eq 128 ]
sed "s/^MRML_AUTHORITY_SIGNER_IDENTITY=.*/MRML_AUTHORITY_SIGNER_IDENTITY=$identity/" acceptance.env > acceptance.env.new
chmod 0600 acceptance.env.new
mv acceptance.env.new acceptance.env
keys=$(volume git-signer-keys)
[ ! -e "$keys/authority-receipt-public.bin" ]
xxd -r -p "$private/receipt-public.hex" > "$keys/authority-receipt-public.bin"
chown 21006:21006 "$keys/authority-receipt-public.bin"
chmod 0444 "$keys/authority-receipt-public.bin"
[ "$(stat -c %s "$keys/authority-receipt-public.bin")" -eq 32 ]
compose run --rm --no-deps -T gitd issue-token /mnt/mrml/gitd/state/tokens.v2 /run/secrets/gitd-token-pepper 21001 owner/first write 1788580000 1791172000 1 completion-first > "$private/first-token.line"
token=$(volume git-credential-agent-token)
[ ! -e "$token/token" ]
tr -d '\n' < "$private/first-token.line" > "$token/token"
chown 21009:21009 "$token/token"
chmod 0400 "$token/token"
[ "$(stat -c %s "$token/token")" -eq 64 ]
compose up -d --no-build --pull never git-authority gitd
docker compose --env-file acceptance.env -f compose.signer.yaml -p "$prefix-signer" up -d --no-build --pull never git-protected-signer
docker compose --env-file acceptance.env -f compose.credential-agent.yaml -p "$prefix-credential" up -d --no-build --pull never git-credential-agent
