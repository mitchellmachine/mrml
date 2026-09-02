#!/bin/sh
set -eu

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
git_compose=${MRML_GIT_COMPOSE_FILE:-$directory/compose.git.yaml}
acme_compose=${MRML_ACME_COMPOSE_FILE:-$directory/compose.acme.yaml}

[ -f "$environment" ] && [ ! -L "$environment" ] && [ "$(stat -c %a "$environment")" = 600 ] || {
  echo "missing or unsafe mode-0600 production environment file: $environment" >&2
  exit 1
}
[ -z "$(docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" ps --status running -q gitd)" ] || {
  echo "recovery administration requires stopped Gitd" >&2
  exit 1
}

case "${1-}" in
  status)
    [ "$#" -eq 1 ] || exit 64
    docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" \
      run --rm --no-deps --entrypoint /usr/bin/mrml-gitd gitd \
      recovery-status /etc/mrml/gitd.conf
    ;;
  complete-safe)
    [ "$#" -eq 1 ] || exit 64
    signer=$(sed -n 's/^MRML_AUTHORITY_SIGNER_IDENTITY=//p' "$environment")
    case "$signer" in ''|*[!0-9A-Fa-f]*) signer_valid=false ;; *) signer_valid=true ;; esac
    [ "$signer_valid" = true ] && [ "$(printf '%s' "$signer" | wc -c)" -eq 128 ] || {
      echo "environment must contain one exact authority signer identity" >&2
      exit 1
    }
    docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" \
      run --rm --no-deps --entrypoint /usr/bin/mrml-gitd gitd \
      recover-safe /etc/mrml/gitd.conf "$signer"
    ;;
  *) echo "usage: $0 status|complete-safe" >&2; exit 64 ;;
esac
