#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-completion-20260905-config
prefix=mrml-completion-f-20260905
compose() { MRML_GIT_VERSION=completion-f2-20260905 docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -p "$prefix" "$@"; }
work=$(docker volume inspect --format '{{.Mountpoint}}' "$prefix-git-client-work")
printf '%s\n' 'malformed proof followed by an immediate valid protected push' >> "$work/first/acceptance.txt"
compose run --rm --no-deps -T git-client -C /work/first add acceptance.txt
compose run --rm --no-deps -T git-client -C /work/first commit -m 'Compose malformed proof recovery'
compose run --rm --no-deps -T --entrypoint /usr/bin/mrml-gitd-certd-test-probe git-client malformed-push /work/first https://git.example:8443/owner/first.git /run/mrml/git-credential-agent/agent.sock /run/mrml/client-credential/channel /work/malformed-proof.pack
compose run --rm --no-deps -T git-client -C /work/first push origin main
