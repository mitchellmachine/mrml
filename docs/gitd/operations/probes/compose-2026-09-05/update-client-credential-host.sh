#!/bin/sh
set -eu
cd /home/ubuntu/mrml-git-completion-20260905-config
prefix=mrml-completion-f-20260905
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
MRML_GIT_VERSION=completion-f2-20260905 /usr/bin/docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -p "$prefix" run --rm --no-deps -T git-client -C /work/first fetch origin
/usr/bin/docker inspect --format 'Gitd preserved: {{.Id}} {{.State.Pid}} {{.State.StartedAt}}' "$prefix-gitd-1"
