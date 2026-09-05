#!/bin/sh
set -eu

[ "$#" -eq 2 ] || { echo "usage: $0 CLIENT_UID CLIENT_GID" >&2; exit 2; }
client_uid=$1
client_gid=$2
signer_uid=21006
signer_gid=21006
socket_gid=21906
volume_prefix=${MRML_VOLUME_PREFIX:-mrml}

case $client_uid in ''|*[!0-9]*|0) echo "client UID must be nonzero decimal" >&2; exit 2 ;; esac
case $client_gid in ''|*[!0-9]*|0) echo "client GID must be nonzero decimal" >&2; exit 2 ;; esac
[ "$client_uid" != "$signer_uid" ] || { echo "client and signer UID must differ" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "signer provisioning must run as root" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 1; }
case $volume_prefix in ''|*[!a-z0-9-]*|-*|*-|*--*) echo "invalid MRML_VOLUME_PREFIX" >&2; exit 2 ;; esac
[ "$(printf %s "$volume_prefix" | wc -c)" -le 63 ] || { echo "MRML_VOLUME_PREFIX is too long" >&2; exit 2; }

volume_name() { printf '%s-%s\n' "$volume_prefix" "$1"; }

ensure_volume() {
  name=$1 uid=$2 gid=$3 mode=$4
  created=false
  if ! docker volume inspect "$name" >/dev/null 2>&1; then
    docker volume create --label org.mrml.managed=true "$name" >/dev/null
    created=true
  fi
  path=$(docker volume inspect --format '{{.Mountpoint}}' "$name")
  case $path in /*/_data) ;; *) echo "unsafe Docker volume mountpoint: $name" >&2; exit 1 ;; esac
  [ -d "$path" ] && [ ! -L "$path" ]
  if [ "$created" = true ]; then
    chown "$uid:$gid" "$path"
    chmod "$mode" "$path"
    # Suppress image-directory copy-up, which otherwise replaces metadata on
    # an empty named volume during its first Docker or Podman mount.
    install -m 0400 /dev/null "$path/.mrml-volume"
    chown "$uid:$gid" "$path/.mrml-volume"
  fi
  [ "$(stat -c '%u:%g %a' "$path")" = "$uid:$gid $mode" ]
}

ensure_volume "$(volume_name git-signer-state)" "$signer_uid" "$signer_gid" 700
ensure_volume "$(volume_name git-signer-keys)" "$signer_uid" "$signer_gid" 700
ensure_volume "$(volume_name git-signer-next-keys)" "$signer_uid" "$signer_gid" 700
ensure_volume "$(volume_name git-trust-signatures)" "$signer_uid" "$signer_gid" 700
ensure_volume "$(volume_name git-signer-channel)" "$signer_uid" "$signer_gid" 700
ensure_volume "$(volume_name git-client-signer-channel)" "$client_uid" "$client_gid" 700
ensure_volume "$(volume_name runtime-git-signer)" "$signer_uid" "$socket_gid" 2770

signer_channel=$(docker volume inspect --format '{{.Mountpoint}}' "$(volume_name git-signer-channel)")/signer-channel
client_channel=$(docker volume inspect --format '{{.Mountpoint}}' "$(volume_name git-client-signer-channel)")/signer-channel
if { [ -e "$signer_channel" ] && [ ! -e "$client_channel" ]; } ||
   { [ ! -e "$signer_channel" ] && [ -e "$client_channel" ]; }; then
  echo "incomplete signer channel pair" >&2
  exit 1
fi
if [ ! -e "$signer_channel" ]; then
  temporary=$(mktemp)
  trap 'rm -f "$temporary"' EXIT HUP INT TERM
  dd if=/dev/urandom of="$temporary" bs=32 count=1 status=none
  install -m 0400 "$temporary" "$signer_channel"
  chown "$signer_uid:$signer_gid" "$signer_channel"
  install -m 0400 "$temporary" "$client_channel"
  chown "$client_uid:$client_gid" "$client_channel"
  rm -f "$temporary"
  trap - EXIT HUP INT TERM
fi
[ "$(stat -c '%u:%g %a %s %h' "$signer_channel")" = "$signer_uid:$signer_gid 400 32 1" ]
[ "$(stat -c '%u:%g %a %s %h' "$client_channel")" = "$client_uid:$client_gid 400 32 1" ]
cmp -s "$signer_channel" "$client_channel" || { echo "signer channel copies differ" >&2; exit 1; }

echo "protected signer named volumes and split channel copies verified"
