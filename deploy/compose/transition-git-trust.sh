#!/bin/sh
set -eu

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
git_compose=${MRML_GIT_COMPOSE_FILE:-$directory/compose.git.yaml}
acme_compose=${MRML_ACME_COMPOSE_FILE:-$directory/compose.acme.yaml}
signer_compose=${MRML_SIGNER_COMPOSE_FILE:-$directory/compose.signer.yaml}
runtime=${MRML_CONTAINER_RUNTIME:-docker}
case $runtime in docker|podman) ;; *) echo "container runtime must be docker or podman" >&2; exit 2 ;; esac

phase=select-and-advance
if [ "${1:-}" = --resume-signer ]; then
  phase=resume-signer
  shift
fi
[ "$#" -eq 4 ] || {
  echo "usage: $0 [--resume-signer] OWNER/REPOSITORY VALIDATION_TIME CURRENT_GENERATION CURRENT_POLICY_DIGEST" >&2
  exit 64
}
[ "$(id -u)" -eq 0 ] || { echo "trust transition must run as root" >&2; exit 1; }
[ -f "$environment" ] && [ ! -L "$environment" ] && [ "$(stat -c %a "$environment")" = 600 ] || {
  echo "missing or unsafe mode-0600 production environment file: $environment" >&2
  exit 1
}
read_environment_value() {
  [ "$(grep -c "^$1=" "$environment")" -eq 1 ] || { echo "environment must contain exactly one $1 assignment" >&2; exit 1; }
  sed -n "s/^$1=//p" "$environment"
}
volume_prefix=$(read_environment_value MRML_VOLUME_PREFIX)
[ -z "${MRML_VOLUME_PREFIX+x}" ] || [ "$MRML_VOLUME_PREFIX" = "$volume_prefix" ] || {
  echo "MRML_VOLUME_PREFIX does not match the production environment" >&2
  exit 1
}
case $volume_prefix in ''|*[!a-z0-9-]*|-*|*-|*--*) echo "invalid MRML_VOLUME_PREFIX" >&2; exit 2 ;; esac
[ "$(printf %s "$volume_prefix" | wc -c)" -le 63 ] || { echo "MRML_VOLUME_PREFIX is too long" >&2; exit 2; }
openpgp_created_at=$(read_environment_value MRML_OPENPGP_CREATED_AT)
case $openpgp_created_at in ''|*[!0-9]*) echo "invalid MRML_OPENPGP_CREATED_AT" >&2; exit 1 ;; esac
[ "$openpgp_created_at" -gt 0 ] || { echo "invalid MRML_OPENPGP_CREATED_AT" >&2; exit 1; }
case $2:$3 in
  *[!0-9:]*|:*|*:) echo "validation time and generation must be decimal integers" >&2; exit 64 ;;
esac
[ "$2" -gt 0 ] && [ "$3" -gt 0 ] || { echo "validation time and generation must be nonzero" >&2; exit 64; }
case $4 in
  *[!0-9a-f]*) echo "expected policy digest must be lowercase hexadecimal" >&2; exit 64 ;;
esac
[ "${#4}" -eq 128 ] || { echo "expected policy digest must contain 128 lowercase hexadecimal digits" >&2; exit 64; }
selected_repository=$(read_environment_value MRML_PROTECTED_REPOSITORY)
[ "$selected_repository" = "$1" ] || { echo "repository does not match MRML_PROTECTED_REPOSITORY" >&2; exit 1; }
transition_volume=$("$runtime" volume inspect --format '{{.Mountpoint}}' "$volume_prefix-git-authority-transition")
case $transition_volume in /*/_data) ;; *) echo "unsafe transition volume mountpoint" >&2; exit 1 ;; esac
[ -d "$transition_volume" ] && [ ! -L "$transition_volume" ] || exit 1
transition_id=$(printf '%s\n%s\n%s\n%s\n' "$1" "$2" "$3" "$4" | sha256sum | sed 's/ .*//')
case $transition_id in *[!0-9a-f]*|'') echo "cannot derive transition identity" >&2; exit 1 ;; esac
completion_marker=$transition_volume/.signer-trust-advance.$transition_id.complete
advance_complete=false
if [ -e "$completion_marker" ] || [ -L "$completion_marker" ]; then
  [ -f "$completion_marker" ] && [ ! -L "$completion_marker" ] \
    && [ "$(stat -c %u:%g:%a:%s:%h "$completion_marker")" = "0:0:600:65:1" ] \
    && [ "$(cat "$completion_marker")" = "$transition_id" ] \
    || { echo "invalid or stale signer trust-advance completion marker" >&2; exit 1; }
  advance_complete=true
fi
# Client signer containers may belong to a separate Compose project.
# Check every running consumer of the selected state volumes in this engine.
for volume in "$volume_prefix-gitd-policies" "$volume_prefix-authority-state" "$volume_prefix-git-signer-state"; do
  running=$("$runtime" ps -q --filter volume="$volume") || exit 1
  [ -z "$running" ] || { echo "trust transition requires stopped Gitd, authority, and signer" >&2; exit 1; }
done

if [ "$advance_complete" = false ]; then
  if [ "$phase" = select-and-advance ]; then
    "$runtime" compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" \
      --profile admin run --rm --no-deps git-trust-transition \
      transition-policy /var/lib/mrml/git-policies "$1" \
      /run/mrml-transition/next-policy.bin \
      /run/mrml-transition/previous-openpgp-public.asc /run/mrml-transition/previous-ml-dsa-public.bin \
      /run/mrml-transition/previous-openpgp.sig /run/mrml-transition/previous-ml-dsa.sig \
      /run/mrml-transition/next-openpgp-public.asc /run/mrml-transition/next-ml-dsa-public.bin \
      /run/mrml-transition/next-openpgp.sig /run/mrml-transition/next-ml-dsa.sig \
      "$2" "$3" "$4" 21002
  fi
fi

if [ "$advance_complete" = false ]; then
  "$runtime" compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" \
    --profile admin run --rm --no-deps git-trust-transition \
    verify-selected-policy /var/lib/mrml/git-policies "$1" \
    /run/mrml-transition/next-policy.bin 21002

  "$runtime" compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" -f "$signer_compose" \
    --profile admin run --rm --no-deps git-signer-trust-advance \
    advance-trust 21006 21002 21002 "$1" \
    /var/lib/mrml/git-protected-signer/state/generation.state \
    /run/mrml-transition/previous-policy.bin \
    /run/mrml-transition/next-policy.bin \
    /var/lib/mrml/git-protected-signer/keys/openpgp.seed \
    "$openpgp_created_at" \
    /var/lib/mrml/git-protected-signer/keys/ml-dsa-public.bin \
    /var/lib/mrml/git-protected-signer/keys/ml-dsa-secret.bin \
    /run/mrml-transition/previous-openpgp.sig \
    /run/mrml-transition/previous-ml-dsa.sig \
    /run/mrml-transition/next-openpgp-public.asc \
    /run/mrml-transition/next-ml-dsa-public.bin \
    /run/mrml-transition/next-openpgp.sig \
    /run/mrml-transition/next-ml-dsa.sig

  temporary_marker=$completion_marker.next
  if [ -e "$temporary_marker" ] || [ -L "$temporary_marker" ]; then
    [ -f "$temporary_marker" ] && [ ! -L "$temporary_marker" ] \
      || { echo "unsafe signer trust-advance marker temporary" >&2; exit 1; }
    rm -- "$temporary_marker"
    sync -f "$transition_volume"
  fi
  (umask 077; printf '%s\n' "$transition_id" > "$temporary_marker")
  sync -f "$temporary_marker"
  mv -- "$temporary_marker" "$completion_marker"
  sync -f "$transition_volume"
fi

for input in previous-policy.bin next-policy.bin previous-openpgp-public.asc previous-ml-dsa-public.bin next-openpgp-public.asc next-ml-dsa-public.bin previous-openpgp.sig previous-ml-dsa.sig next-openpgp.sig next-ml-dsa.sig; do
  if [ -e "$transition_volume/$input" ] || [ -L "$transition_volume/$input" ]; then
    [ -f "$transition_volume/$input" ] && [ ! -L "$transition_volume/$input" ] || exit 1
    rm -- "$transition_volume/$input"
  fi
done
sync -f "$transition_volume"

construction_volume=$("$runtime" volume inspect --format '{{.Mountpoint}}' "$volume_prefix-git-trust-construction")
signature_volume=$("$runtime" volume inspect --format '{{.Mountpoint}}' "$volume_prefix-git-trust-signatures")
case $construction_volume:$signature_volume in /*/_data:/*/_data) ;; *) echo "unsafe trust workspace mountpoint" >&2; exit 1 ;; esac
for input in candidate-openpgp-public.asc candidate-ml-dsa-public.bin previous-policy.bin next-policy.bin; do
  if [ -e "$construction_volume/$input" ] || [ -L "$construction_volume/$input" ]; then
    [ -f "$construction_volume/$input" ] && [ ! -L "$construction_volume/$input" ] || exit 1
    rm -- "$construction_volume/$input"
  fi
done
for input in previous-openpgp-public.asc previous-openpgp.sig previous-ml-dsa.sig next-openpgp-public.asc next-openpgp.sig next-ml-dsa.sig; do
  if [ -e "$signature_volume/$input" ] || [ -L "$signature_volume/$input" ]; then
    [ -f "$signature_volume/$input" ] && [ ! -L "$signature_volume/$input" ] || exit 1
    rm -- "$signature_volume/$input"
  fi
done
sync -f "$construction_volume"
sync -f "$signature_volume"
echo "trust transition selected; consumed public transition and workspace inputs removed"
