#!/bin/sh
set -eu

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
git_compose=${MRML_GIT_COMPOSE_FILE:-$directory/compose.git.yaml}
acme_compose=${MRML_ACME_COMPOSE_FILE:-$directory/compose.acme.yaml}
signer_compose=${MRML_SIGNER_COMPOSE_FILE:-$directory/compose.signer.yaml}
volume_prefix=${MRML_VOLUME_PREFIX:-mrml}
case $volume_prefix in ''|*[!a-z0-9-]*|-*|*-|*--*) echo "invalid MRML_VOLUME_PREFIX" >&2; exit 2 ;; esac
[ "$(printf %s "$volume_prefix" | wc -c)" -le 63 ] || { echo "MRML_VOLUME_PREFIX is too long" >&2; exit 2; }

phase=select-and-advance
if [ "${1:-}" = --resume-signer ]; then
  phase=resume-signer
  shift
fi
[ "$#" -eq 4 ] || {
  echo "usage: $0 [--resume-signer] OWNER/REPOSITORY VALIDATION_TIME EXPECTED_GENERATION EXPECTED_POLICY_DIGEST" >&2
  exit 64
}
[ "$(id -u)" -eq 0 ] || { echo "trust transition must run as root" >&2; exit 1; }
[ -f "$environment" ] && [ ! -L "$environment" ] && [ "$(stat -c %a "$environment")" = 600 ] || {
  echo "missing or unsafe mode-0600 production environment file: $environment" >&2
  exit 1
}
case $2:$3 in
  *[!0-9:]*|:*|*:) echo "validation time and generation must be decimal integers" >&2; exit 64 ;;
esac
[ "$2" -gt 0 ] && [ "$3" -gt 0 ] || { echo "validation time and generation must be nonzero" >&2; exit 64; }
case $4 in
  *[!0-9a-f]*) echo "expected policy digest must be lowercase hexadecimal" >&2; exit 64 ;;
esac
[ "${#4}" -eq 128 ] || { echo "expected policy digest must contain 128 lowercase hexadecimal digits" >&2; exit 64; }
selected_repository=$(sed -n 's/^MRML_PROTECTED_REPOSITORY=//p' "$environment")
[ "$selected_repository" = "$1" ] || { echo "repository does not match MRML_PROTECTED_REPOSITORY" >&2; exit 1; }
for service in gitd git-authority git-protected-signer; do
  [ -z "$(docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" -f "$signer_compose" ps --status running -q "$service")" ] || {
    echo "trust transition requires stopped Gitd, authority, and signer" >&2
    exit 1
  }
done

if [ "$phase" = select-and-advance ]; then
  docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" \
    --profile admin run --rm --no-deps git-trust-transition \
    transition-policy /var/lib/mrml/git-policies "$1" \
    /run/mrml-transition/next-policy.bin \
    /run/mrml-transition/previous-openpgp-public.asc /run/mrml-transition/previous-ml-dsa-public.bin \
    /run/mrml-transition/previous-openpgp.sig /run/mrml-transition/previous-ml-dsa.sig \
    /run/mrml-transition/next-openpgp-public.asc /run/mrml-transition/next-ml-dsa-public.bin \
    /run/mrml-transition/next-openpgp.sig /run/mrml-transition/next-ml-dsa.sig \
    "$2" "$3" "$4" 21002
fi

docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" -f "$signer_compose" \
  --profile admin run --rm --no-deps git-signer-trust-advance \
  advance-trust 21006 21001 21002 "$1" \
  /var/lib/mrml/git-protected-signer/state/generation.state \
  /run/mrml-transition/previous-policy.bin \
  "/var/lib/mrml/git-policies/$1/trust-policy.current" \
  /var/lib/mrml/git-protected-signer/keys/openpgp.seed \
  "${MRML_OPENPGP_CREATED_AT:?set MRML_OPENPGP_CREATED_AT}" \
  /var/lib/mrml/git-protected-signer/keys/ml-dsa-public.bin \
  /var/lib/mrml/git-protected-signer/keys/ml-dsa-secret.bin \
  /run/mrml-transition/previous-openpgp.sig \
  /run/mrml-transition/previous-ml-dsa.sig \
  /run/mrml-transition/next-openpgp-public.asc \
  /run/mrml-transition/next-ml-dsa-public.bin \
  /run/mrml-transition/next-openpgp.sig \
  /run/mrml-transition/next-ml-dsa.sig

transition_volume=$(docker volume inspect --format '{{.Mountpoint}}' "$volume_prefix-git-authority-transition")
case $transition_volume in /*/_data) ;; *) echo "unsafe transition volume mountpoint" >&2; exit 1 ;; esac
[ -d "$transition_volume" ] && [ ! -L "$transition_volume" ] || exit 1
for input in previous-policy.bin next-policy.bin previous-openpgp-public.asc previous-ml-dsa-public.bin next-openpgp-public.asc next-ml-dsa-public.bin previous-openpgp.sig previous-ml-dsa.sig next-openpgp.sig next-ml-dsa.sig; do
  [ -f "$transition_volume/$input" ] && [ ! -L "$transition_volume/$input" ] || exit 1
  rm -- "$transition_volume/$input"
done
sync -f "$transition_volume"

construction_volume=$(docker volume inspect --format '{{.Mountpoint}}' "$volume_prefix-git-trust-construction")
signature_volume=$(docker volume inspect --format '{{.Mountpoint}}' "$volume_prefix-git-trust-signatures")
case $construction_volume:$signature_volume in /*/_data:/*/_data) ;; *) echo "unsafe trust workspace mountpoint" >&2; exit 1 ;; esac
for input in candidate-openpgp-public.asc candidate-ml-dsa-public.bin previous-policy.bin next-policy.bin; do
  [ -f "$construction_volume/$input" ] && [ ! -L "$construction_volume/$input" ] || exit 1
  rm -- "$construction_volume/$input"
done
for input in previous-openpgp-public.asc previous-openpgp.sig previous-ml-dsa.sig next-openpgp-public.asc next-openpgp.sig next-ml-dsa.sig; do
  [ -f "$signature_volume/$input" ] && [ ! -L "$signature_volume/$input" ] || exit 1
  rm -- "$signature_volume/$input"
done
sync -f "$construction_volume"
sync -f "$signature_volume"
echo "trust transition selected; consumed public transition and workspace inputs removed"
