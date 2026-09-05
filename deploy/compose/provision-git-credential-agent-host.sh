#!/bin/sh
set -eu

[ "$#" -eq 2 ] || { echo "usage: $0 CLIENT_UID CLIENT_GID" >&2; exit 2; }
client_uid=$1
client_gid=$2
agent_uid=21009
agent_gid=21009
socket_gid=21909
volume_prefix=${MRML_VOLUME_PREFIX:-mrml}

case $client_uid in ''|*[!0-9]*|0) echo "client UID must be nonzero decimal" >&2; exit 2 ;; esac
case $client_gid in ''|*[!0-9]*|0) echo "client GID must be nonzero decimal" >&2; exit 2 ;; esac
[ "$client_uid" != "$agent_uid" ] || { echo "client and credential-agent UID must differ" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "credential-agent provisioning must run as root" >&2; exit 1; }
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
    install -m 0400 /dev/null "$path/.mrml-volume"
    chown "$uid:$gid" "$path/.mrml-volume"
  fi
  [ "$(stat -c '%u:%g %a' "$path")" = "$uid:$gid $mode" ]
}

ensure_volume "$(volume_name git-credential-agent-token)" "$agent_uid" "$agent_gid" 700
ensure_volume "$(volume_name git-credential-agent-channel)" "$agent_uid" "$agent_gid" 700
ensure_volume "$(volume_name git-client-credential-agent-channel)" "$client_uid" "$client_gid" 700
ensure_volume "$(volume_name runtime-git-credential-agent)" "$agent_uid" "$socket_gid" 2770

agent_channel=$(docker volume inspect --format '{{.Mountpoint}}' "$(volume_name git-credential-agent-channel)")/channel
client_channel=$(docker volume inspect --format '{{.Mountpoint}}' "$(volume_name git-client-credential-agent-channel)")/channel
if { [ -e "$agent_channel" ] && [ ! -e "$client_channel" ]; } ||
   { [ ! -e "$agent_channel" ] && [ -e "$client_channel" ]; }; then
  echo "incomplete credential-agent channel pair" >&2
  exit 1
fi
if [ ! -e "$agent_channel" ]; then
  temporary_directory=$(mktemp -d)
  trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM
  chmod 0700 "$temporary_directory"
  dd if=/dev/urandom of="$temporary_directory/channel" bs=32 count=1 status=none
  chmod 0600 "$temporary_directory/channel"
  install -m 0400 "$temporary_directory/channel" "$agent_channel"
  chown "$agent_uid:$agent_gid" "$agent_channel"
  install -m 0400 "$temporary_directory/channel" "$client_channel"
  chown "$client_uid:$client_gid" "$client_channel"
  rm -rf "$temporary_directory"
  trap - EXIT HUP INT TERM
fi
[ "$(stat -c '%u:%g %a %s %h' "$agent_channel")" = "$agent_uid:$agent_gid 400 32 1" ]
[ "$(stat -c '%u:%g %a %s %h' "$client_channel")" = "$client_uid:$client_gid 400 32 1" ]
cmp -s "$agent_channel" "$client_channel" || { echo "credential-agent channel copies differ" >&2; exit 1; }

echo "credential-agent named volumes and split channel copies verified"
