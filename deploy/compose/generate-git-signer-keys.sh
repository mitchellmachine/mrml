#!/bin/sh
set -eu

[ "$#" -eq 2 ] || [ "$#" -eq 3 ] || {
  echo "usage: $0 VERSION OPENPGP_CREATED_AT [current|next]" >&2
  exit 2
}
version=$1
openpgp_created_at=$2
volume_prefix=${MRML_VOLUME_PREFIX:-mrml}
slot=${3:-current}
case $slot in current) suffix=git-signer-keys ;; next) suffix=git-signer-next-keys ;; *) echo "key slot must be current or next" >&2; exit 2 ;; esac
signer_volume=${volume_prefix}-${suffix}
runtime=${MRML_CONTAINER_RUNTIME:-docker}

case $version in ''|*[!a-zA-Z0-9._-]*) echo "invalid image version" >&2; exit 2 ;; esac
case $openpgp_created_at in ''|*[!0-9]*|0) echo "OpenPGP creation time must be nonzero decimal" >&2; exit 2 ;; esac
case $volume_prefix in ''|*[!a-z0-9-]*|-*|*-|*--*) echo "invalid MRML_VOLUME_PREFIX" >&2; exit 2 ;; esac
[ "$(printf %s "$volume_prefix" | wc -c)" -le 63 ] || { echo "MRML_VOLUME_PREFIX is too long" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "signer key generation must run as root" >&2; exit 1; }
case $runtime in docker|podman) ;; *) echo "container runtime must be docker or podman" >&2; exit 2 ;; esac
command -v "$runtime" >/dev/null 2>&1 || { echo "$runtime is required" >&2; exit 1; }
"$runtime" volume inspect "$signer_volume" >/dev/null
[ -z "$("$runtime" ps -q --filter volume="$signer_volume")" ] || {
  echo "refusing to generate keys in a volume used by a running container" >&2
  exit 1
}

if [ "$runtime" = podman ] || "$runtime" --version 2>/dev/null | grep -qi podman; then
  volume_option=--volume
  volume_spec=$signer_volume:/keys:nocopy
else
  volume_option=--mount
  volume_spec=type=volume,source=$signer_volume,target=/keys,volume-nocopy
fi

"$runtime" run --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 16 \
  --memory 256m \
  --cpus 0.5 \
  --user 21006:21006 \
  "$volume_option" "$volume_spec" \
  "mrml/git-protected-signer:$version" \
  generate-key-material 21006 "$openpgp_created_at" /keys

mountpoint=$("$runtime" volume inspect --format '{{.Mountpoint}}' "$signer_volume")
case $mountpoint in /*/_data) ;; *) echo "unsafe Docker volume mountpoint" >&2; exit 1 ;; esac
[ -d "$mountpoint" ] && [ ! -L "$mountpoint" ]
[ "$(stat -c '%u:%g %a %s %h' "$mountpoint/openpgp.seed")" = "21006:21006 400 32 1" ]
[ "$(stat -c '%u:%g %a %s %h' "$mountpoint/ml-dsa-public.bin")" = "21006:21006 444 1952 1" ]
[ "$(stat -c '%u:%g %a %s %h' "$mountpoint/ml-dsa-secret.bin")" = "21006:21006 400 4032 1" ]
openpgp_size=$(stat -c %s "$mountpoint/openpgp-public.asc")
[ "$openpgp_size" -gt 0 ] && [ "$openpgp_size" -le 1048576 ]
[ "$(stat -c '%u:%g %a %h' "$mountpoint/openpgp-public.asc")" = "21006:21006 444 1" ]

echo "protected signer key material generated directly in named volume $signer_volume"
