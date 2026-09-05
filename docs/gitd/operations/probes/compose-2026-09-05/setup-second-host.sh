#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-completion-20260905-config
prefix=mrml-completion-f-20260905
second=mrml-completion-s-20260905
[ ! -e second.env ]
umask 077
sed -e "s/^MRML_VOLUME_PREFIX=.*/MRML_VOLUME_PREFIX=$second/" -e 's/^MRML_PROTECTED_REPOSITORY=.*/MRML_PROTECTED_REPOSITORY=owner\/second/' -e 's|^MRML_GIT_CREDENTIAL_REPOSITORY_PATH=.*|MRML_GIT_CREDENTIAL_REPOSITORY_PATH=/owner/second.git|' -e 's/^MRML_GIT_CREDENTIAL_GENERATION=.*/MRML_GIT_CREDENTIAL_GENERATION=1/' acceptance.env > second.env
chmod 0600 second.env
MRML_VOLUME_PREFIX=$second sh ./provision-git-signer-host.sh 21005 21005
MRML_VOLUME_PREFIX=$second sh ./provision-git-credential-agent-host.sh 21005 21005
# The already selected disposable test signing keys are intentionally shared
# read-only; generation state and channel capabilities remain independent.
docker compose --env-file second.env -f compose.signer.yaml -p "$second-signer" up -d --no-build --pull never git-protected-signer
compose() { MRML_GIT_VERSION=completion-f4-20260905 docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -p "$prefix" "$@"; }
private=/mnt/mrml-completion-f-20260905/secrets/admin
compose run --rm --no-deps -T gitd issue-token /mnt/mrml/gitd/state/tokens.v2 /run/secrets/gitd-token-pepper 21001 owner/second write 1788580000 1791172000 1 completion-second > "$private/second-token.line"
token=$(docker volume inspect --format '{{.Mountpoint}}' "$second-git-credential-agent-token")
[ ! -e "$token/token" ]
tr -d '\n' < "$private/second-token.line" > "$token/token"
chown 21009:21009 "$token/token"
chmod 0400 "$token/token"
[ "$(stat -c %s "$token/token")" -eq 64 ]
docker compose --env-file second.env -f compose.credential-agent.yaml -p "$second-credential" up -d --no-build --pull never git-credential-agent
cat > compose.git.acceptance-second.yaml <<'YAML'
# The second protected repository uses distinct signer/credential state and
# channels while talking to the same real multi-repository authority and Gitd.
# Merge after compose.git.acceptance.yaml; only the test client is selected.
services:
  git-client:
    volumes:
      - "second-runtime-signer:/run/mrml/git-protected-signer:ro"
      - "second-client-signer:/run/mrml/client-signer:ro"
      - "second-runtime-credential:/run/mrml/git-credential-agent:ro"
      - "second-client-credential:/run/mrml/client-credential:ro"
volumes:
  second-runtime-signer:
    name: "${MRML_SECOND_CLIENT_PREFIX:?set MRML_SECOND_CLIENT_PREFIX}-runtime-git-signer"
    external: true
  second-client-signer:
    name: "${MRML_SECOND_CLIENT_PREFIX:?set MRML_SECOND_CLIENT_PREFIX}-git-client-signer-channel"
    external: true
  second-runtime-credential:
    name: "${MRML_SECOND_CLIENT_PREFIX:?set MRML_SECOND_CLIENT_PREFIX}-runtime-git-credential-agent"
    external: true
  second-client-credential:
    name: "${MRML_SECOND_CLIENT_PREFIX:?set MRML_SECOND_CLIENT_PREFIX}-git-client-credential-agent-channel"
    external: true
YAML
chmod 0444 compose.git.acceptance-second.yaml
client() { MRML_SECOND_CLIENT_PREFIX=$second MRML_GIT_CREDENTIAL_GENERATION=1 MRML_GIT_VERSION=completion-f4-20260905 docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -f compose.git.acceptance-second.yaml -p "$prefix" "$@"; }
client config --quiet
client run --rm --no-deps -T git-client clone https://git.example:8443/owner/second.git /work/second
client run --rm --no-deps -T git-client clone https://git.example:8443/owner/second.git /work/second-before-random
work=$(docker volume inspect --format '{{.Mountpoint}}' "$prefix-git-client-work")
policies=$(docker volume inspect --format '{{.Mountpoint}}' "$prefix-gitd-policies")
mkdir "$work/trust-second"
chown 21005:21005 "$work/trust-second"
chmod 0700 "$work/trust-second"
install -m 0444 "$policies/owner/second/trust-policy.current" "$work/trust-second/trust-policy.current"
cat >> "$work/second/.git/config" <<'CONFIG'
[user]
 name = MRML Compose Test
 email = compose-test@git.example
[gpg.protected]
 signerProvider = unix-v1
 signerSocket = /run/mrml/git-protected-signer/signer.sock
 signerCapabilityFile = /run/mrml/client-signer/signer-channel
 signerUid = 21006
 signerGid = 21006
 trustPolicyDirectory = /work/trust-second
 openpgpPublicKeyFile = /work/openpgp-public.asc
 mlDsaPublicKeyFile = /work/ml-dsa-public.bin
CONFIG
