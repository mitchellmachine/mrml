#!/bin/sh
# Only the two scratch volumes used by compose.git.acceptance.yaml.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "acceptance provisioning requires root" >&2; exit 1; }
prefix=${MRML_VOLUME_PREFIX:?set an isolated acceptance prefix}
case $prefix in mrml|''|*[!a-z0-9-]*|-*|*-|*--*) exit 2 ;; esac
[ "${#prefix}" -le 63 ] || exit 2
for specification in git-client-work:21005 git-certificate-exchange:21004; do
  suffix=${specification%:*}
  uid=${specification#*:}
  name=$prefix-$suffix
  created=false
  if ! docker volume inspect "$name" >/dev/null 2>&1; then
    docker volume create --label org.mrml.disposable-acceptance=true "$name" >/dev/null
    created=true
  fi
  path=$(docker volume inspect --format '{{.Mountpoint}}' "$name")
  case $path in /*/_data) ;; *) exit 1 ;; esac
  [ -d "$path" ] && [ ! -L "$path" ] || exit 1
  if [ "$created" = true ]; then
    chown "$uid:$uid" "$path"
    chmod 0700 "$path"
  fi
  [ "$(stat -c '%u:%g %a' "$path")" = "$uid:$uid 700" ] || exit 1
done
echo "disposable acceptance scratch volume ownership verified"
