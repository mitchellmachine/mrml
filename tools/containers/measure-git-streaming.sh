#!/bin/sh
set -eu

volume_prefix=${MRML_VOLUME_PREFIX:-mrml}
case $volume_prefix in ''|*[!a-z0-9-]*|-*|*-|*--*) echo "invalid MRML_VOLUME_PREFIX" >&2; exit 2 ;; esac
[ "$(printf %s "$volume_prefix" | wc -c)" -le 63 ] || { echo "MRML_VOLUME_PREFIX is too long" >&2; exit 2; }

[ "$#" -ge 3 ] || {
  echo "usage: $0 /absolute/evidence-directory SOURCE_BYTES COMMAND [ARG ...]" >&2
  exit 64
}
output=$1
source_bytes=$2
shift 2
case "$output" in /*) ;; *) echo "evidence directory must be absolute" >&2; exit 64 ;; esac
case "$source_bytes" in ''|*[!0-9]*) echo "SOURCE_BYTES must be canonical decimal bytes" >&2; exit 64 ;; esac
[ "${source_bytes#0}" = "$source_bytes" ] || { echo "SOURCE_BYTES must not have leading zeroes" >&2; exit 64; }
[ "$source_bytes" -ge 268435456 ] || { echo "transfer must be at least 256 MiB" >&2; exit 1; }
[ ! -e "$output" ] || { echo "evidence destination already exists" >&2; exit 1; }

directory=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
compose_directory=$directory/deploy/compose
environment=${MRML_ENV_FILE:-$compose_directory/.env.production}
git_compose=${MRML_GIT_COMPOSE_FILE:-$compose_directory/compose.git.yaml}
acme_compose=${MRML_ACME_COMPOSE_FILE:-$compose_directory/compose.acme.yaml}

for tool in docker awk sed wc du date git find sha256sum sleep xargs id; do
  command -v "$tool" >/dev/null || { echo "missing measurement tool: $tool" >&2; exit 1; }
done
[ "$(id -u)" -eq 0 ] || { echo "managed-volume measurement must run as root" >&2; exit 1; }
[ -f "$environment" ] && [ ! -L "$environment" ] || exit 1
mkdir -m 0700 "$output"
trap 'if [ -n "${child_pid-}" ]; then kill "$child_pid" 2>/dev/null || true; fi' EXIT HUP INT TERM

volume_mount() {
  measured_volume=$1
  measured_mount=$(docker volume inspect --format '{{.Mountpoint}}' "$measured_volume") || {
    echo "required measurement volume is absent: $measured_volume" >&2
    exit 1
  }
  case $measured_mount in /*/_data) ;; *) echo "unsafe measurement volume mountpoint: $measured_volume" >&2; exit 1 ;; esac
  [ -d "$measured_mount" ] && [ ! -L "$measured_mount" ] || {
    echo "unsafe measurement volume path: $measured_volume" >&2
    exit 1
  }
  printf '%s\n' "$measured_mount"
}

config_mount=$(volume_mount "$volume_prefix-gitd-config")
repos_mount=$(volume_mount "$volume_prefix-gitd-repos")
quarantine_mount=$(volume_mount "$volume_prefix-gitd-quarantine")
cache_mount=$(volume_mount "$volume_prefix-gitd-cache")
config_file=$config_mount/gitd.conf
[ -f "$config_file" ] && [ ! -L "$config_file" ] || {
  echo "Gitd configuration volume does not contain a safe gitd.conf" >&2
  exit 1
}

git -C "$directory" rev-parse --verify HEAD >"$output/source.commit"
printf 'format=mrml-git-streaming-evidence-v1\nsource_bytes=%s\n' "$source_bytes" >"$output/metadata"
sed -n '/^max_connections=/p;/^max_uploads=/p;/^max_receives=/p;/^max_body_bytes=/p;/^minimum_free_space_bytes=/p;/^drain_seconds=/p' \
  "$config_file" >"$output/configured-limits"

gitd_container=$(docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" ps -q gitd)
authority_container=$(docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" ps -q git-authority)
[ -n "$gitd_container" ] && [ -n "$authority_container" ] || { echo "Git stack is not running" >&2; exit 1; }
gitd_pid=$(docker inspect -f '{{.State.Pid}}' "$gitd_container")
authority_pid=$(docker inspect -f '{{.State.Pid}}' "$authority_container")
case "$gitd_pid:$authority_pid" in *[!0-9:]*) exit 1 ;; esac

started=$(date +%s)
"$@" >/dev/null 2>/dev/null &
child_pid=$!
printf 'sample\tclient_rss_kib\tclient_fds\tgitd_rss_kib\tgitd_fds\tauthority_rss_kib\tauthority_fds\trepos_bytes\tquarantine_bytes\tcache_bytes\n' >"$output/process.tsv"
sample=0
while kill -0 "$child_pid" 2>/dev/null; do
  sample=$((sample + 1))
  rss() { awk '/^VmRSS:/ {print $2; found=1} END {if (!found) print 0}' "/proc/$1/status" 2>/dev/null || printf 0; }
  fds() { find "/proc/$1/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l; }
  bytes() { du -sb "$1" 2>/dev/null | awk '{print $1}' || printf 0; }
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$sample" "$(rss "$child_pid")" "$(fds "$child_pid")" \
    "$(rss "$gitd_pid")" "$(fds "$gitd_pid")" \
    "$(rss "$authority_pid")" "$(fds "$authority_pid")" \
    "$(bytes "$repos_mount")" "$(bytes "$quarantine_mount")" \
    "$(bytes "$cache_mount")" >>"$output/process.tsv"
  docker stats --no-stream --format '{{json .}}' "$gitd_container" "$authority_container" \
    >>"$output/docker-stats.jsonl"
  sleep 1
done
status=0
wait "$child_pid" || status=$?
child_pid=
ended=$(date +%s)
elapsed=$((ended - started))
printf 'exit_status=%s\nelapsed_seconds=%s\n' "$status" "$elapsed" >>"$output/metadata"
[ "$status" -eq 0 ] || { echo "measured transfer failed" >&2; exit "$status"; }
[ "$sample" -gt 0 ] || { echo "transfer completed before one resource sample" >&2; exit 1; }
[ "$elapsed" -gt 0 ] || elapsed=1
printf 'throughput_bytes_per_second=%s\n' "$((source_bytes / elapsed))" >>"$output/metadata"
awk -F '\t' '
  NR == 2 {client_base=$2; gitd_base=$4; authority_base=$6}
  NR > 1 {
    if ($2 > client_peak) client_peak=$2
    if ($3 > client_fds) client_fds=$3
    if ($4 > gitd_peak) gitd_peak=$4
    if ($5 > gitd_fds) gitd_fds=$5
    if ($6 > authority_peak) authority_peak=$6
    if ($7 > authority_fds) authority_fds=$7
    if ($8 > repos_peak) repos_peak=$8
    if ($9 > quarantine_peak) quarantine_peak=$9
    if ($10 > cache_peak) cache_peak=$10
    samples++
  }
  END {
    printf "samples=%d\nclient_peak_rss_kib=%d\nclient_rss_growth_kib=%d\nclient_peak_fds=%d\n", samples, client_peak, client_peak-client_base, client_fds
    printf "gitd_peak_rss_kib=%d\ngitd_rss_growth_kib=%d\ngitd_peak_fds=%d\n", gitd_peak, gitd_peak-gitd_base, gitd_fds
    printf "authority_peak_rss_kib=%d\nauthority_rss_growth_kib=%d\nauthority_peak_fds=%d\n", authority_peak, authority_peak-authority_base, authority_fds
    printf "repos_peak_bytes=%d\nquarantine_peak_bytes=%d\ncache_peak_bytes=%d\n", repos_peak, quarantine_peak, cache_peak
  }
' "$output/process.tsv" >"$output/summary"
(
  cd "$output"
  find . -type f ! -name SHA256SUMS -print | LC_ALL=C sort | xargs sha256sum >SHA256SUMS
)
echo "streaming evidence recorded: $output"
