#!/bin/sh
set -eu

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
runtime=${MRML_CONTAINER_RUNTIME:-docker}

[ "$#" -eq 3 ] || { echo "usage: $0 OWNER/REPOSITORY TRUST_GENERATION REVOCATION_GENERATION" >&2; exit 64; }
[ "$(id -u)" -eq 0 ] || { echo "Git trust catalog update must run as root" >&2; exit 1; }
[ -f "$environment" ] && [ ! -L "$environment" ] && [ "$(stat -c %a "$environment")" = 600 ] || exit 1
read_environment_value() {
  [ "$(grep -c "^$1=" "$environment")" -eq 1 ] || { echo "environment must contain exactly one $1 assignment" >&2; exit 1; }
  sed -n "s/^$1=//p" "$environment"
}
volume_prefix=$(read_environment_value MRML_VOLUME_PREFIX)
case $volume_prefix in ''|*[!a-z0-9-]*|-*|*-|*--*) echo "invalid MRML_VOLUME_PREFIX" >&2; exit 2 ;; esac
case $runtime in docker|podman) ;; *) echo "container runtime must be docker or podman" >&2; exit 2 ;; esac
case $1 in *[!a-zA-Z0-9._/-]*|.*|*/.*|*./|*.|*//*|*/*/*) echo "invalid repository identity" >&2; exit 64 ;; esac
case $2:$3 in *[!0-9:]*|:*|*:) echo "generations must be decimal integers" >&2; exit 64 ;; esac
[ "$2" -gt 0 ] && [ "$3" -gt 0 ] || exit 64
[ "$(read_environment_value MRML_PROTECTED_REPOSITORY)" = "$1" ] || { echo "repository does not match production environment" >&2; exit 1; }
[ "$(read_environment_value MRML_TRUST_GENERATION)" = "$2" ] || { echo "trust generation does not match selected signer environment" >&2; exit 1; }
[ "$(read_environment_value MRML_REVOCATION_GENERATION)" = "$3" ] || { echo "revocation generation does not match selected signer environment" >&2; exit 1; }

for volume in "$volume_prefix-gitd-policies" "$volume_prefix-authority-state" "$volume_prefix-git-signer-state"; do
  running=$("$runtime" ps -q --filter volume="$volume") || exit 1
  [ -z "$running" ] || { echo "Git trust catalog update requires stopped Gitd, authority, and signer" >&2; exit 1; }
done

volume_path() {
  path=$("$runtime" volume inspect --format '{{.Mountpoint}}' "$1") || exit 1
  case $path in /*/_data) ;; *) echo "unsafe managed volume mountpoint: $1" >&2; exit 1 ;; esac
  [ -d "$path" ] && [ ! -L "$path" ] || exit 1
  printf '%s\n' "$path"
}
policy_root=$(volume_path "$volume_prefix-gitd-policies")
config_root=$(volume_path "$volume_prefix-gitd-config")
catalog=$policy_root/repositories.v1
config=$config_root/gitd.conf
for input in "$catalog" "$config"; do
  [ -f "$input" ] && [ ! -L "$input" ] && [ "$(stat -c %h "$input")" -eq 1 ] || exit 1
done
[ "$(stat -c '%u:%g %a' "$catalog")" = "21001:21001 444" ] || exit 1
[ "$(stat -c '%u:%g %a' "$config")" = "0:0 444" ] || exit 1

catalog_temporary=$catalog.new.$$
config_temporary=$config.new.$$
trap 'rm -f "$catalog_temporary" "$config_temporary"' EXIT HUP INT TERM
awk -F '|' -v repository="$1" -v trust="$2" -v revocation="$3" '
  BEGIN { count = 0 }
  $1 == "repository=" repository {
    if ($2 != "protected" || $3 !~ /^[1-9][0-9]*$/ || NF != 5) exit 65
    print $1 "|" $2 "|" $3 "|" trust "|" revocation
    count++
    next
  }
  { print }
  END { if (count != 1) exit 66 }
' "$catalog" >"$catalog_temporary" || { echo "protected repository catalog entry is not exact" >&2; exit 1; }
chown 21001:21001 "$catalog_temporary"
chmod 0444 "$catalog_temporary"
sync -f "$catalog_temporary"
if ! cmp -s "$catalog" "$catalog_temporary"; then
  mv -f "$catalog_temporary" "$catalog"
  sync -f "$policy_root"
else
  rm -f "$catalog_temporary"
fi
catalog_digest=$(sha256sum "$catalog" | awk '{print $1}')
[ "${#catalog_digest}" -eq 64 ] || exit 1
[ "$(grep -c '^repository_catalog_sha256=' "$config")" -eq 1 ] || exit 1
sed "s/^repository_catalog_sha256=.*/repository_catalog_sha256=$catalog_digest/" "$config" >"$config_temporary"
chown 0:0 "$config_temporary"
chmod 0444 "$config_temporary"
sync -f "$config_temporary"
if ! cmp -s "$config" "$config_temporary"; then
  mv -f "$config_temporary" "$config"
  sync -f "$config_root"
else
  rm -f "$config_temporary"
fi
trap - EXIT HUP INT TERM
echo "Gitd catalog selected trust generation $2 revocation generation $3"
