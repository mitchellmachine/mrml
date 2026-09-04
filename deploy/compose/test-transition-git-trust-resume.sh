#!/bin/sh
set -eu

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM
mkdir -p "$temporary/bin" "$temporary/transition/_data" "$temporary/construction/_data" "$temporary/signatures/_data"

cat > "$temporary/bin/id" <<'EOF'
#!/bin/sh
if [ "${1:-}" = -u ]; then
  echo 0
else
  exec /usr/bin/id "$@"
fi
EOF
cat > "$temporary/bin/stat" <<'EOF'
#!/bin/sh
if [ "${1:-}" = -c ] && [ "${2:-}" = %u:%g:%a:%s:%h ]; then
  shift 2
  printf '0:0:'
  exec /usr/bin/stat -c %a:%s:%h "$@"
fi
exec /usr/bin/stat "$@"
EOF
cat > "$temporary/bin/podman" <<'EOF'
#!/bin/sh
case ${1:-} in
  ps) exit 0 ;;
  volume)
    eval "volume=\${$#}"
    case $volume in
      *-git-authority-transition) echo "$TEST_TRANSITION_ROOT" ;;
      *-git-trust-construction) echo "$TEST_CONSTRUCTION_ROOT" ;;
      *-git-trust-signatures) echo "$TEST_SIGNATURE_ROOT" ;;
      *) echo "unexpected volume: $volume" >&2; exit 2 ;;
    esac
    ;;
  compose)
    [ -f "$TEST_TRANSITION_ROOT/next-policy.bin" ] || exit 55
    printf '%s\n' "$*" >> "$TEST_COMPOSE_LOG"
    ;;
  *) echo "unexpected podman operation: ${1:-}" >&2; exit 2 ;;
esac
EOF
cat > "$temporary/bin/rm" <<'EOF'
#!/bin/sh
eval "target=\${$#}"
if [ ! -e "$TEST_KILL_ONCE" ] && [ "$target" = "$TEST_TRANSITION_ROOT/previous-policy.bin" ]; then
  : > "$TEST_KILL_ONCE"
  kill -KILL "$PPID"
  exit 137
fi
exec /usr/bin/rm "$@"
EOF
chmod 0755 "$temporary/bin/id" "$temporary/bin/stat" "$temporary/bin/podman" "$temporary/bin/rm"

environment=$temporary/environment
cat > "$environment" <<'EOF'
MRML_VOLUME_PREFIX=test-transition
MRML_OPENPGP_CREATED_AT=1700000000
MRML_PROTECTED_REPOSITORY=owner/project
EOF
chmod 0600 "$environment"

for input in previous-policy.bin next-policy.bin previous-openpgp-public.asc previous-ml-dsa-public.bin next-openpgp-public.asc next-ml-dsa-public.bin previous-openpgp.sig previous-ml-dsa.sig next-openpgp.sig next-ml-dsa.sig; do
  : > "$temporary/transition/_data/$input"
done
for input in candidate-openpgp-public.asc candidate-ml-dsa-public.bin previous-policy.bin next-policy.bin; do
  : > "$temporary/construction/_data/$input"
done
for input in previous-openpgp-public.asc previous-openpgp.sig previous-ml-dsa.sig next-openpgp-public.asc next-openpgp.sig next-ml-dsa.sig; do
  : > "$temporary/signatures/_data/$input"
done

export PATH="$temporary/bin:$PATH"
export TEST_TRANSITION_ROOT=$temporary/transition/_data
export TEST_CONSTRUCTION_ROOT=$temporary/construction/_data
export TEST_SIGNATURE_ROOT=$temporary/signatures/_data
export TEST_COMPOSE_LOG=$temporary/compose.log
export TEST_KILL_ONCE=$temporary/kill-once
export MRML_ENV_FILE=$environment
export MRML_CONTAINER_RUNTIME=podman
digest=$(printf '%0128d' 0)

set +e
"$directory/transition-git-trust.sh" owner/project 1700000100 2 "$digest"
status=$?
set -e
[ "$status" -gt 128 ] || { echo "transition was not killed after signer completion" >&2; exit 1; }
[ "$(wc -l < "$TEST_COMPOSE_LOG")" -eq 3 ] || { echo "initial transition did not run three admin operations" >&2; exit 1; }
marker=$(find "$temporary/transition/_data" -maxdepth 1 -name '.signer-trust-advance.*.complete' -print)
[ -f "$marker" ] || { echo "completion marker was not durable before injected kill" >&2; exit 1; }

"$directory/transition-git-trust.sh" --resume-signer owner/project 1700000100 2 "$digest"
[ "$(wc -l < "$TEST_COMPOSE_LOG")" -eq 3 ] || { echo "resume repeated an authority or signer operation" >&2; exit 1; }
for root in "$temporary/transition/_data" "$temporary/construction/_data" "$temporary/signatures/_data"; do
  [ -z "$(find "$root" -maxdepth 1 -type f ! -name '.signer-trust-advance.*.complete' -print -quit)" ] \
    || { echo "resume left public transition input behind" >&2; exit 1; }
done

printf '%064d\n' 1 > "$marker"
set +e
"$directory/transition-git-trust.sh" --resume-signer owner/project 1700000100 2 "$digest" >/dev/null 2>&1
status=$?
set -e
[ "$status" -ne 0 ] || { echo "tampered completion marker was accepted" >&2; exit 1; }

echo "trust transition process-kill resume PASS"
