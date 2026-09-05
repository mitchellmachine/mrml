#!/bin/sh
set -eu
cd /home/ubuntu/mrml-git-completion-20260905-config
compose() { MRML_GIT_VERSION=completion-f2-20260905 /usr/bin/docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -p mrml-completion-f-20260905 "$@"; }
compose run --rm --no-deps -T git-client -C /work/first fetch origin
compose run --rm --no-deps -T git-client -C /work/first status
compose run --rm --no-deps -T git-client -C /work/first push origin main
