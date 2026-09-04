#!/bin/sh
set -eu

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
git_compose=${MRML_GIT_COMPOSE_FILE:-$directory/compose.git.yaml}
acme_compose=${MRML_ACME_COMPOSE_FILE:-$directory/compose.acme.yaml}
signer_compose=${MRML_SIGNER_COMPOSE_FILE:-$directory/compose.signer.yaml}
volume_prefix=${MRML_VOLUME_PREFIX:-mrml}

[ "$#" -eq 5 ] || { echo "usage: $0 OWNER/REPOSITORY CURRENT_TRUST_GENERATION NEXT_TRUST_GENERATION CURRENT_OPENPGP_CREATED_AT NEXT_OPENPGP_CREATED_AT" >&2; exit 64; }
[ "$(id -u)" -eq 0 ] || { echo "trust policy signing must run as root" >&2; exit 1; }
[ -f "$environment" ] && [ ! -L "$environment" ] && [ "$(stat -c %a "$environment")" = 600 ] || exit 1
case $volume_prefix in ''|*[!a-z0-9-]*|-*|*-|*--*) echo "invalid MRML_VOLUME_PREFIX" >&2; exit 2 ;; esac
case $1 in *[!a-zA-Z0-9._/-]*|.*|*/.*|*./|*.|*//*|*/*/*) echo "invalid repository identity" >&2; exit 64 ;; esac
case $2:$3:$4:$5 in *[!0-9:]*|:*|*:) echo "generations and creation times must be decimal integers" >&2; exit 64 ;; esac
[ "$2" -gt 0 ] && [ "$3" -eq "$(( $2 + 1 ))" ] && [ "$4" -gt 0 ] && [ "$5" -gt 0 ] || exit 64
selected_repository=$(sed -n 's/^MRML_PROTECTED_REPOSITORY=//p' "$environment")
[ "$selected_repository" = "$1" ] || exit 1
for service in gitd git-authority git-protected-signer; do
  [ -z "$(docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" -f "$signer_compose" ps --status running -q "$service")" ] || {
    echo "trust policy signing requires stopped Gitd, authority, and signer" >&2
    exit 1
  }
done

docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" -f "$signer_compose" \
  --profile admin run --rm --no-deps git-trust-sign-current \
  sign-key-rotation 21006 21001 "$1" "$2" /keys/openpgp.seed "$4" /keys/ml-dsa-public.bin /keys/ml-dsa-secret.bin \
  /policies/next-policy.bin /signatures/previous-openpgp-public.asc /signatures/previous-openpgp.sig /signatures/previous-ml-dsa.sig
docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" -f "$signer_compose" \
  --profile admin run --rm --no-deps git-trust-sign-next \
  sign-key-rotation 21006 21001 "$1" "$3" /keys/openpgp.seed "$5" /keys/ml-dsa-public.bin /keys/ml-dsa-secret.bin \
  /policies/next-policy.bin /signatures/next-openpgp-public.asc /signatures/next-openpgp.sig /signatures/next-ml-dsa.sig

signature_volume=$(docker volume inspect --format '{{.Mountpoint}}' "$volume_prefix-git-trust-signatures")
case $signature_volume in /*/_data) ;; *) echo "unsafe signature volume mountpoint" >&2; exit 1 ;; esac
for output in previous-openpgp-public.asc previous-openpgp.sig previous-ml-dsa.sig next-openpgp-public.asc next-openpgp.sig next-ml-dsa.sig; do
  [ "$(stat -c '%u:%g %a %h' "$signature_volume/$output")" = "21006:21006 444 1" ] || exit 1
done
echo "hybrid transition authorizations written to named volume $volume_prefix-git-trust-signatures"
