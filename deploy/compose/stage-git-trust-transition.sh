#!/bin/sh
set -eu

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
runtime=${MRML_CONTAINER_RUNTIME:-docker}
[ "$#" -eq 1 ] || { echo "usage: $0 overlap|retirement" >&2; exit 64; }
mode=$1
case $mode in overlap|retirement) ;; *) echo "trust staging mode must be overlap or retirement" >&2; exit 64 ;; esac
[ "$(id -u)" -eq 0 ] || { echo "trust transition staging must run as root" >&2; exit 1; }
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
selected_volume=$(read_environment_value MRML_GIT_SIGNER_KEYS_VOLUME)
candidate_volume=$(read_environment_value MRML_GIT_SIGNER_CANDIDATE_KEYS_VOLUME)
validate_key_volume() {
  case $1 in ''|*[!a-z0-9-]*|-*|*-|*--*) echo "invalid signer key volume name" >&2; exit 1 ;; esac
  [ "$(printf %s "$1" | wc -c)" -le 127 ] || { echo "signer key volume name is too long" >&2; exit 1; }
  case $1 in
    "$volume_prefix-git-signer-keys"|"$volume_prefix-git-signer-next-keys"|"$volume_prefix-git-signer-key-slot-"[a-z0-9]* ) ;;
    *) echo "signer key volume is outside the managed key slots" >&2; exit 1 ;;
  esac
  [ "$("$runtime" volume inspect --format '{{index .Labels "org.mrml.managed"}}' "$1")" = true ] || {
    echo "signer key volume is not MRML-managed" >&2
    exit 1
  }
}
validate_key_volume "$selected_volume"
validate_key_volume "$candidate_volume"
[ "$candidate_volume" != "$selected_volume" ] || { echo "selected and candidate signer key volumes must differ" >&2; exit 1; }

volume_path() {
  [ -z "$("$runtime" ps -q --filter volume="$1")" ] || { echo "volume is in use: $1" >&2; exit 1; }
  path=$("$runtime" volume inspect --format '{{.Mountpoint}}' "$1")
  case $path in /*/_data) ;; *) echo "unsafe volume mountpoint: $1" >&2; exit 1 ;; esac
  [ -d "$path" ] && [ ! -L "$path" ] || exit 1
  printf '%s\n' "$path"
}
construction=$(volume_path "$volume_prefix-git-trust-construction")
signatures=$(volume_path "$volume_prefix-git-trust-signatures")
current_keys=$(volume_path "$selected_volume")
next_keys=$(volume_path "$candidate_volume")
if [ "$mode" = retirement ]; then
  next_keys=$current_keys
fi

MRML_CONTAINER_RUNTIME=$runtime MRML_VOLUME_PREFIX=$volume_prefix "$directory/install-volume-inputs.sh" authority-transition \
  "$construction/previous-policy.bin" "$construction/next-policy.bin" \
  "$signatures/previous-openpgp-public.asc" "$current_keys/ml-dsa-public.bin" \
  "$signatures/next-openpgp-public.asc" "$next_keys/ml-dsa-public.bin" \
  "$signatures/previous-openpgp.sig" "$signatures/previous-ml-dsa.sig" \
  "$signatures/next-openpgp.sig" "$signatures/next-ml-dsa.sig"
echo "staged exact public trust-transition inputs in named volume $volume_prefix-git-authority-transition"
