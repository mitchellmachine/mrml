#!/bin/sh
set -eu

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
git_compose=${MRML_GIT_COMPOSE_FILE:-$directory/compose.git.yaml}
acme_compose=${MRML_ACME_COMPOSE_FILE:-$directory/compose.acme.yaml}
signer_compose=${MRML_SIGNER_COMPOSE_FILE:-$directory/compose.signer.yaml}
volume_prefix=${MRML_VOLUME_PREFIX:-mrml}
runtime=${MRML_CONTAINER_RUNTIME:-docker}

[ "$(id -u)" -eq 0 ] || { echo "trust policy construction must run as root" >&2; exit 1; }
[ -f "$environment" ] && [ ! -L "$environment" ] && [ "$(stat -c %a "$environment")" = 600 ] || {
  echo "missing or unsafe mode-0600 production environment file: $environment" >&2
  exit 1
}
case $volume_prefix in ''|*[!a-z0-9-]*|-*|*-|*--*) echo "invalid MRML_VOLUME_PREFIX" >&2; exit 2 ;; esac
[ "$(printf %s "$volume_prefix" | wc -c)" -le 63 ] || { echo "MRML_VOLUME_PREFIX is too long" >&2; exit 2; }
case $runtime in docker|podman) ;; *) echo "container runtime must be docker or podman" >&2; exit 2 ;; esac

operation=${1:-}
repository=${2:-}
case $repository in
  */*) ;;
  *) echo "repository must be OWNER/REPOSITORY" >&2; exit 64 ;;
esac
case $repository in
  *[!a-zA-Z0-9._/-]*|.*|*/.*|*./|*.|*//*|*/*/*) echo "invalid repository identity" >&2; exit 64 ;;
esac
case $operation in
  overlap)
    [ "$#" -eq 4 ] || { echo "usage: $0 overlap OWNER/REPOSITORY VALID_FROM VALID_UNTIL" >&2; exit 64; }
    case $3:$4 in *[!0-9:]*|:*|*:) echo "validity times must be decimal integers" >&2; exit 64 ;; esac
    set -- construct-overlap-policy /var/lib/mrml/git-policies "$repository" /run/mrml-trust-construction/candidate-openpgp-public.asc /run/mrml-trust-construction/candidate-ml-dsa-public.bin 21001 "$3" "$4" /run/mrml-trust-construction/previous-policy.bin /run/mrml-trust-construction/next-policy.bin 21001
    ;;
  retirement)
    [ "$#" -eq 3 ] || { echo "usage: $0 retirement OWNER/REPOSITORY RETIRED_AT" >&2; exit 64; }
    case $3 in ''|*[!0-9]*) echo "retirement time must be a decimal integer" >&2; exit 64 ;; esac
    set -- construct-retirement-policy /var/lib/mrml/git-policies "$repository" /run/mrml-trust-construction/candidate-openpgp-public.asc /run/mrml-trust-construction/candidate-ml-dsa-public.bin 21001 "$3" /run/mrml-trust-construction/previous-policy.bin /run/mrml-trust-construction/next-policy.bin 21001
    ;;
  *) echo "usage: $0 overlap OWNER/REPOSITORY VALID_FROM VALID_UNTIL | retirement OWNER/REPOSITORY RETIRED_AT" >&2; exit 64 ;;
esac
selected_repository=$(sed -n 's/^MRML_PROTECTED_REPOSITORY=//p' "$environment")
[ "$selected_repository" = "$repository" ] || { echo "repository does not match MRML_PROTECTED_REPOSITORY" >&2; exit 1; }
if [ "$runtime" = podman ]; then
  for volume in "$volume_prefix-gitd-policies" "$volume_prefix-authority-state" "$volume_prefix-git-signer-state"; do
    running=$(podman ps -q --filter volume="$volume") || exit 1
    [ -z "$running" ] || { echo "trust policy construction requires stopped Gitd, authority, and signer" >&2; exit 1; }
  done
else
  for service in gitd git-authority git-protected-signer; do
    running=$(docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" -f "$signer_compose" ps --status running -q "$service") || { echo "cannot query service state for $service" >&2; exit 1; }
    [ -z "$running" ] || { echo "trust policy construction requires stopped Gitd, authority, and signer" >&2; exit 1; }
  done
fi

"$runtime" compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" \
  --profile admin run --rm --no-deps git-trust-policy-construct "$@"

construction_volume=$("$runtime" volume inspect --format '{{.Mountpoint}}' "$volume_prefix-git-trust-construction")
case $construction_volume in /*/_data) ;; *) echo "unsafe construction volume mountpoint" >&2; exit 1 ;; esac
[ -d "$construction_volume" ] && [ ! -L "$construction_volume" ] || exit 1
for output in previous-policy.bin next-policy.bin; do
  [ "$(stat -c '%u:%g %a %h' "$construction_volume/$output")" = "21001:21001 444 1" ] || exit 1
done
echo "canonical trust policies written to named volume $volume_prefix-git-trust-construction"
