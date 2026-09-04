#!/bin/sh
set -eu

usage() {
  echo "usage: $0 gitd CONFIG | authority REPOSITORY_CATALOG OPENPGP_PUBLIC ML_DSA_PUBLIC | signer OPENPGP_SEED ML_DSA_PUBLIC ML_DSA_SECRET AUTHORITY_RECEIPT_PUBLIC | credential-agent TOKEN | authority-transition NEXT_POLICY NEXT_OPENPGP NEXT_ML_DSA PREVIOUS_OPENPGP_SIGNATURE PREVIOUS_ML_DSA_SIGNATURE NEXT_OPENPGP_SIGNATURE NEXT_ML_DSA_SIGNATURE | certd CONFIG TRUST_ROOTS | acmed CONFIG | cloudflare-token TOKEN" >&2
  exit 2
}

[ "$(id -u)" -eq 0 ] || { echo "volume input installation must run as root" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 1; }
volume_prefix=${MRML_VOLUME_PREFIX:-mrml}
case $volume_prefix in ''|*[!a-z0-9-]*|-*|*-|*--*) echo "invalid MRML_VOLUME_PREFIX" >&2; exit 2 ;; esac
[ "$(printf %s "$volume_prefix" | wc -c)" -le 63 ] || { echo "MRML_VOLUME_PREFIX is too long" >&2; exit 2; }
git_volume() { printf '%s-%s\n' "$volume_prefix" "$1"; }

volume_path() {
  volume=$1
  [ -z "$(docker ps -q --filter volume="$volume")" ] || {
    echo "refusing to update a volume used by a running container: $volume" >&2
    exit 1
  }
  path=$(docker volume inspect --format '{{.Mountpoint}}' "$volume") || exit 1
  case $path in /*/_data) ;; *) echo "unsafe Docker volume mountpoint: $volume" >&2; exit 1 ;; esac
  [ -d "$path" ] && [ ! -L "$path" ] || exit 1
  printf '%s\n' "$path"
}

install_file() {
  source=$1 destination=$2 uid=$3 gid=$4 mode=$5 maximum=$6
  case $source in /*) ;; *) echo "input path must be absolute: $source" >&2; exit 1 ;; esac
  [ -f "$source" ] && [ ! -L "$source" ] || { echo "input must be a regular non-symlink file" >&2; exit 1; }
  size=$(stat -c %s "$source")
  [ "$size" -gt 0 ] && [ "$size" -le "$maximum" ] || { echo "input size rejected" >&2; exit 1; }
  [ ! -e "$destination" ] && [ ! -L "$destination" ] || { echo "destination already exists: $destination" >&2; exit 1; }
  temporary=$destination.new.$$
  trap 'rm -f "$temporary"' EXIT HUP INT TERM
  umask 077
  cp "$source" "$temporary"
  chown "$uid:$gid" "$temporary"
  chmod "$mode" "$temporary"
  sync -f "$temporary"
  mv "$temporary" "$destination"
  sync -f "$(dirname "$destination")"
  trap - EXIT HUP INT TERM
}

case ${1:-} in
  gitd)
    [ "$#" -eq 2 ] || usage
    destination=$(volume_path "$(git_volume gitd-config)")
    install_file "$2" "$destination/gitd.conf" 0 0 0444 65536
    ;;
  authority)
    [ "$#" -eq 4 ] || usage
    destination=$(volume_path "$(git_volume git-authority-config)")
    install_file "$2" "$destination/repositories.v1" 21002 21002 0444 8388608
    install_file "$3" "$destination/openpgp-public.asc" 21002 21002 0444 1048576
    install_file "$4" "$destination/ml-dsa-public.bin" 21002 21002 0444 1048576
    ;;
  signer)
    [ "$#" -eq 5 ] || usage
    destination=$(volume_path "$(git_volume git-signer-keys)")
    install_file "$2" "$destination/openpgp.seed" 21006 21006 0400 32
    install_file "$3" "$destination/ml-dsa-public.bin" 21006 21006 0444 1952
    install_file "$4" "$destination/ml-dsa-secret.bin" 21006 21006 0400 4032
    install_file "$5" "$destination/authority-receipt-public.bin" 21006 21006 0444 32
    ;;
  credential-agent)
    [ "$#" -eq 2 ] || usage
    [ "$(stat -c %s "$2")" -eq 64 ] &&
      [ "$(LC_ALL=C tr -d '0-9a-f' < "$2" | wc -c)" -eq 0 ] || {
      echo "credential token must be exactly 64 lowercase hexadecimal bytes" >&2
      exit 1
    }
    destination=$(volume_path "$(git_volume git-credential-agent-token)")
    install_file "$2" "$destination/token" 21009 21009 0400 64
    ;;
  authority-transition)
    [ "$#" -eq 8 ] || usage
    destination=$(volume_path "$(git_volume git-authority-transition)")
    install_file "$2" "$destination/next-policy.bin" 21002 21002 0444 524288
    install_file "$3" "$destination/next-openpgp-public.asc" 21002 21002 0444 1048576
    install_file "$4" "$destination/next-ml-dsa-public.bin" 21002 21002 0444 1048576
    install_file "$5" "$destination/previous-openpgp.sig" 21002 21002 0444 1024
    install_file "$6" "$destination/previous-ml-dsa.sig" 21002 21002 0444 3309
    install_file "$7" "$destination/next-openpgp.sig" 21002 21002 0444 1024
    install_file "$8" "$destination/next-ml-dsa.sig" 21002 21002 0444 3309
    ;;
  certd)
    [ "$#" -eq 3 ] || usage
    destination=$(volume_path mrml-certd-config)
    install_file "$2" "$destination/config.json" 0 0 0444 16384
    install_file "$3" "$destination/acme-trust-roots.pem" 0 0 0444 1048576
    ;;
  acmed)
    [ "$#" -eq 2 ] || usage
    destination=$(volume_path mrml-acmed-config)
    install_file "$2" "$destination/config.json" 0 0 0444 16384
    ;;
  cloudflare-token)
    [ "$#" -eq 2 ] || usage
    destination=$(volume_path mrml-acmed-secrets)
    install_file "$2" "$destination/cloudflare-api-token" 21004 21004 0400 4096
    ;;
  *) usage ;;
esac

echo "installed immutable input into its scoped managed volume"
