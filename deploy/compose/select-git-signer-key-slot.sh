#!/bin/sh
set -eu

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
git_compose=${MRML_GIT_COMPOSE_FILE:-$directory/compose.git.yaml}
acme_compose=${MRML_ACME_COMPOSE_FILE:-$directory/compose.acme.yaml}
signer_compose=${MRML_SIGNER_COMPOSE_FILE:-$directory/compose.signer.yaml}
runtime=${MRML_CONTAINER_RUNTIME:-docker}

[ "$#" -eq 4 ] || { echo "usage: $0 current|next OPENPGP_CREATED_AT TRUST_GENERATION REVOCATION_GENERATION" >&2; exit 64; }
[ "$(id -u)" -eq 0 ] || { echo "signer key selection must run as root" >&2; exit 1; }
[ -f "$environment" ] && [ ! -L "$environment" ] && [ "$(stat -c %a "$environment")" = 600 ] || exit 1
read_environment_value() {
  [ "$(grep -c "^$1=" "$environment")" -eq 1 ] || { echo "environment must contain exactly one $1 assignment" >&2; exit 1; }
  sed -n "s/^$1=//p" "$environment"
}
volume_prefix=$(read_environment_value MRML_VOLUME_PREFIX)
[ -z "${MRML_VOLUME_PREFIX+x}" ] || [ "$MRML_VOLUME_PREFIX" = "$volume_prefix" ] || {
  echo "MRML_VOLUME_PREFIX does not match the production environment" >&2
  exit 1
}
case $volume_prefix in ''|*[!a-z0-9-]*|-*|*-|*--*) echo "invalid MRML_VOLUME_PREFIX" >&2; exit 2 ;; esac
case $runtime in docker|podman) ;; *) echo "container runtime must be docker or podman" >&2; exit 2 ;; esac
configured_selected=$(read_environment_value MRML_GIT_SIGNER_KEYS_VOLUME)
configured_candidate=$(read_environment_value MRML_GIT_SIGNER_CANDIDATE_KEYS_VOLUME)
configured_created_at=$(read_environment_value MRML_OPENPGP_CREATED_AT)
configured_trust_generation=$(read_environment_value MRML_TRUST_GENERATION)
configured_revocation_generation=$(read_environment_value MRML_REVOCATION_GENERATION)
case $1 in
  current) selected_volume=$volume_prefix-git-signer-keys; candidate_volume=$volume_prefix-git-signer-next-keys ;;
  next) selected_volume=$configured_candidate; candidate_volume=$configured_selected ;;
  *) exit 64 ;;
esac
case $2:$3:$4 in *[!0-9:]*|:*|*:) exit 64 ;; esac
[ "$2" -gt 0 ] && [ "$3" -gt 0 ] && [ "$4" -gt 0 ] || exit 64
# Client signer containers may belong to a separate Compose project.
# Check every running consumer of the selected state volumes in this engine.
for volume in "$volume_prefix-gitd-policies" "$volume_prefix-authority-state" "$volume_prefix-git-signer-state"; do
  running=$("$runtime" ps -q --filter volume="$volume") || exit 1
  [ -z "$running" ] || { echo "signer key selection requires stopped Gitd, authority, and signer" >&2; exit 1; }
done
for volume in "$selected_volume" "$candidate_volume"; do
  case $volume in ''|*[!a-z0-9-]*|-*|*-|*--*) echo "invalid signer key volume name" >&2; exit 1 ;; esac
  [ "$(printf %s "$volume" | wc -c)" -le 127 ] || { echo "signer key volume name is too long" >&2; exit 1; }
  case $volume in
    "$volume_prefix-git-signer-keys"|"$volume_prefix-git-signer-next-keys"|"$volume_prefix-git-signer-key-slot-"[a-z0-9]* ) ;;
    *) echo "signer key volume is outside the managed key slots" >&2; exit 1 ;;
  esac
  [ "$("$runtime" volume inspect --format '{{index .Labels "org.mrml.managed"}}' "$volume")" = true ] || {
    echo "signer key volume is not MRML-managed" >&2
    exit 1
  }
done
[ "$selected_volume" != "$candidate_volume" ] || { echo "selected and candidate signer key volumes must differ" >&2; exit 1; }

case $configured_created_at:$configured_trust_generation:$configured_revocation_generation in
  *[!0-9:]*|:*|*:) echo "configured signer generations must be decimal integers" >&2; exit 1 ;;
esac
[ "$configured_created_at" -gt 0 ] && [ "$configured_trust_generation" -gt 0 ] \
  && [ "$configured_revocation_generation" -gt 0 ] || exit 1
if [ "$configured_created_at" = "$2" ] \
  && [ "$configured_trust_generation" = "$3" ] \
  && [ "$configured_revocation_generation" = "$4" ]; then
  echo "protected signer key selection already matches trust generation $3"
  exit 0
fi
[ "$3" -gt "$configured_trust_generation" ] || {
  echo "signer trust generation must advance monotonically" >&2
  exit 1
}
[ "$4" -ge "$configured_revocation_generation" ] || {
  echo "signer revocation generation must not roll back" >&2
  exit 1
}
temporary=$(mktemp "$environment.new.XXXXXX")
trap 'rm -f "$temporary"' EXIT HUP INT TERM
sed \
  -e "s|^MRML_GIT_SIGNER_KEYS_VOLUME=.*|MRML_GIT_SIGNER_KEYS_VOLUME=$selected_volume|" \
  -e "s|^MRML_GIT_SIGNER_CANDIDATE_KEYS_VOLUME=.*|MRML_GIT_SIGNER_CANDIDATE_KEYS_VOLUME=$candidate_volume|" \
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
