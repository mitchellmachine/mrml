#!/bin/sh
set -eu

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
git_compose=${MRML_GIT_COMPOSE_FILE:-$directory/compose.git.yaml}
acme_compose=${MRML_ACME_COMPOSE_FILE:-$directory/compose.acme.yaml}
signer_compose=${MRML_SIGNER_COMPOSE_FILE:-$directory/compose.signer.yaml}
volume_prefix=${MRML_VOLUME_PREFIX:-mrml}
runtime=${MRML_CONTAINER_RUNTIME:-docker}

[ "$#" -eq 4 ] || { echo "usage: $0 current|next OPENPGP_CREATED_AT TRUST_GENERATION REVOCATION_GENERATION" >&2; exit 64; }
[ "$(id -u)" -eq 0 ] || { echo "signer key selection must run as root" >&2; exit 1; }
[ -f "$environment" ] && [ ! -L "$environment" ] && [ "$(stat -c %a "$environment")" = 600 ] || exit 1
case $volume_prefix in ''|*[!a-z0-9-]*|-*|*-|*--*) echo "invalid MRML_VOLUME_PREFIX" >&2; exit 2 ;; esac
case $runtime in docker|podman) ;; *) echo "container runtime must be docker or podman" >&2; exit 2 ;; esac
case $1 in current) selected_volume=$volume_prefix-git-signer-keys ;; next) selected_volume=$volume_prefix-git-signer-next-keys ;; *) exit 64 ;; esac
case $2:$3:$4 in *[!0-9:]*|:*|*:) exit 64 ;; esac
[ "$2" -gt 0 ] && [ "$3" -gt 0 ] && [ "$4" -gt 0 ] || exit 64
if [ "$runtime" = podman ]; then
  for volume in "$volume_prefix-gitd-policies" "$volume_prefix-authority-state" "$volume_prefix-git-signer-state"; do
    running=$(podman ps -q --filter volume="$volume") || exit 1
    [ -z "$running" ] || { echo "signer key selection requires stopped Gitd, authority, and signer" >&2; exit 1; }
  done
else
  for service in gitd git-authority git-protected-signer; do
    running=$(docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" -f "$signer_compose" ps --status running -q "$service") || { echo "cannot query service state for $service" >&2; exit 1; }
    [ -z "$running" ] || { echo "signer key selection requires stopped Gitd, authority, and signer" >&2; exit 1; }
  done
fi
"$runtime" volume inspect "$selected_volume" >/dev/null

for name in MRML_GIT_SIGNER_KEYS_VOLUME MRML_OPENPGP_CREATED_AT MRML_TRUST_GENERATION MRML_REVOCATION_GENERATION; do
  [ "$(grep -c "^$name=" "$environment")" -eq 1 ] || { echo "environment must contain exactly one $name assignment" >&2; exit 1; }
done
temporary=$(mktemp "$environment.new.XXXXXX")
trap 'rm -f "$temporary"' EXIT HUP INT TERM
sed \
  -e "s|^MRML_GIT_SIGNER_KEYS_VOLUME=.*|MRML_GIT_SIGNER_KEYS_VOLUME=$selected_volume|" \
  -e "s|^MRML_OPENPGP_CREATED_AT=.*|MRML_OPENPGP_CREATED_AT=$2|" \
  -e "s|^MRML_TRUST_GENERATION=.*|MRML_TRUST_GENERATION=$3|" \
  -e "s|^MRML_REVOCATION_GENERATION=.*|MRML_REVOCATION_GENERATION=$4|" \
  "$environment" >"$temporary"
chown --reference="$environment" "$temporary"
chmod 0600 "$temporary"
sync -f "$temporary"
mv -f "$temporary" "$environment"
sync -f "$(dirname "$environment")"
trap - EXIT HUP INT TERM
echo "selected protected signer key volume $selected_volume at trust generation $3"
