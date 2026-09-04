#!/bin/sh
set -eu

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
volume_prefix=${MRML_VOLUME_PREFIX:-mrml}
[ "$#" -eq 0 ] || { echo "usage: $0" >&2; exit 64; }
[ "$(id -u)" -eq 0 ] || { echo "trust transition staging must run as root" >&2; exit 1; }
[ -f "$environment" ] && [ ! -L "$environment" ] && [ "$(stat -c %a "$environment")" = 600 ] || exit 1
case $volume_prefix in ''|*[!a-z0-9-]*|-*|*-|*--*) echo "invalid MRML_VOLUME_PREFIX" >&2; exit 2 ;; esac
selected_volume=$(sed -n 's/^MRML_GIT_SIGNER_KEYS_VOLUME=//p' "$environment")
[ -n "$selected_volume" ] || selected_volume=$volume_prefix-git-signer-keys
case $selected_volume in
  "$volume_prefix-git-signer-keys"|"$volume_prefix-git-signer-next-keys") ;;
  *) echo "selected signer key volume is outside the managed key slots" >&2; exit 1 ;;
esac

volume_path() {
  [ -z "$(docker ps -q --filter volume="$1")" ] || { echo "volume is in use: $1" >&2; exit 1; }
  path=$(docker volume inspect --format '{{.Mountpoint}}' "$1")
  case $path in /*/_data) ;; *) echo "unsafe volume mountpoint: $1" >&2; exit 1 ;; esac
  [ -d "$path" ] && [ ! -L "$path" ] || exit 1
  printf '%s\n' "$path"
}
construction=$(volume_path "$volume_prefix-git-trust-construction")
signatures=$(volume_path "$volume_prefix-git-trust-signatures")
current_keys=$(volume_path "$selected_volume")
next_keys=$(volume_path "$volume_prefix-git-signer-next-keys")

MRML_VOLUME_PREFIX=$volume_prefix "$directory/install-volume-inputs.sh" authority-transition \
  "$construction/previous-policy.bin" "$construction/next-policy.bin" \
  "$signatures/previous-openpgp-public.asc" "$current_keys/ml-dsa-public.bin" \
  "$signatures/next-openpgp-public.asc" "$next_keys/ml-dsa-public.bin" \
  "$signatures/previous-openpgp.sig" "$signatures/previous-ml-dsa.sig" \
  "$signatures/next-openpgp.sig" "$signatures/next-ml-dsa.sig"
echo "staged exact public trust-transition inputs in named volume $volume_prefix-git-authority-transition"
