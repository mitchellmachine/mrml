#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-final2-20260905-config
prefix=mrml-completion-final2-20260905
private=/mnt/mrml-completion-final2-20260905/secrets/admin
compose() { MRML_GIT_VERSION=completion-final-20260905 docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -p "$prefix" "$@"; }
credential() { docker compose --env-file acceptance.env -f compose.credential-agent.yaml -p "$prefix-credential" "$@"; }
before=$(docker inspect --format '{{.Id}} {{.State.Pid}} {{.State.StartedAt}}' "$prefix-gitd-1")
compose run --rm --no-deps -T gitd revoke-token /mnt/mrml/gitd/state/tokens.v2 /run/secrets/gitd-token-pepper 21001 < "$private/first-token.line"
# The production reload interval is one second; a bounded read-only health
# command and process startup may be shorter, so explicitly wait that interval.
sleep 2
if compose run --rm --no-deps -T git-client -C /work/first fetch origin; then
 echo 'ERROR revoked token accepted' >&2; exit 1
fi
printf '%s\n' 'revoked token rejected while original Gitd stayed running'
umask 077
compose run --rm --no-deps -T gitd issue-token /mnt/mrml/gitd/state/tokens.v2 /run/secrets/gitd-token-pepper 21001 owner/first write 1788580000 1791172000 1 completion-first-replacement > "$private/first-token-replacement.line"
credential stop git-credential-agent
token=$(docker volume inspect --format '{{.Mountpoint}}' "$prefix-git-credential-agent-token")
[ ! -e "$token/token.next" ]
tr -d '\n' < "$private/first-token-replacement.line" > "$token/token.next"
chown 21009:21009 "$token/token.next"
chmod 0400 "$token/token.next"
[ "$(stat -c %s "$token/token.next")" -eq 64 ]
mv "$token/token.next" "$token/token"
sync -f "$token"
sed 's/^MRML_GIT_CREDENTIAL_GENERATION=.*/MRML_GIT_CREDENTIAL_GENERATION=2/' acceptance.env > acceptance.env.new
chmod 0600 acceptance.env.new
mv acceptance.env.new acceptance.env
credential up -d --no-build --pull never git-credential-agent
if MRML_GIT_CREDENTIAL_GENERATION=1 compose run --rm --no-deps -T git-client -C /work/first fetch origin; then
 echo 'ERROR stale credential generation accepted' >&2; exit 1
fi
work=$(/usr/bin/docker volume inspect --format '{{.Mountpoint}}' "$prefix-git-client-work")
for repository in first first-after-three; do
 config="$work/$repository/.git/config"
 [ "$(grep -c 'credentialGeneration = 1' "$config")" -eq 1 ]
 sed 's/credentialGeneration = 1/credentialGeneration = 2/' "$config" > "$config.new"
 chown 21005:21005 "$config.new"
 chmod --reference="$config" "$config.new"
 mv "$config.new" "$config"
 sync -f "$config"
done
compose run --rm --no-deps -T git-client -C /work/first fetch origin
after=$(docker inspect --format '{{.Id}} {{.State.Pid}} {{.State.StartedAt}}' "$prefix-gitd-1")
[ "$before" = "$after" ]
printf '%s\n' 'replacement generation 2 accepted; Gitd process unchanged'
