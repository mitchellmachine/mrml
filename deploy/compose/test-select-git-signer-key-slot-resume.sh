#!/bin/sh
set -eu

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM
mkdir -p "$temporary/bin"

cat > "$temporary/bin/id" <<'EOF'
#!/bin/sh
if [ "${1:-}" = -u ]; then
  echo 0
else
  exec /usr/bin/id "$@"
fi
EOF
cat > "$temporary/bin/podman" <<'EOF'
#!/bin/sh
case ${1:-} in
  ps) exit 0 ;;
  volume)
    [ "${2:-}" = inspect ] || exit 2
    case $* in
      *'index .Labels "org.mrml.managed"'*) echo true ;;
      *) exit 2 ;;
    esac
    ;;
  *) exit 2 ;;
esac
EOF
cat > "$temporary/bin/mv" <<'EOF'
#!/bin/sh
/usr/bin/mv "$@"
if [ ! -e "$TEST_MOVE_KILLED" ]; then
  : > "$TEST_MOVE_KILLED"
  kill -KILL "$PPID"
fi
EOF
chmod 0755 "$temporary/bin/id" "$temporary/bin/podman" "$temporary/bin/mv"

environment=$temporary/environment
cat > "$environment" <<'EOF'
MRML_VOLUME_PREFIX=test-selection
MRML_GIT_SIGNER_KEYS_VOLUME=test-selection-git-signer-keys
MRML_GIT_SIGNER_CANDIDATE_KEYS_VOLUME=test-selection-git-signer-next-keys
MRML_OPENPGP_CREATED_AT=1700000000
MRML_TRUST_GENERATION=4
MRML_REVOCATION_GENERATION=1
EOF
chmod 0600 "$environment"

export PATH="$temporary/bin:$PATH"
export TEST_MOVE_KILLED=$temporary/move-killed
export MRML_ENV_FILE=$environment
export MRML_CONTAINER_RUNTIME=podman

set +e
"$directory/select-git-signer-key-slot.sh" next 1800000000 5 1
status=$?
set -e
[ "$status" -gt 128 ] || { echo "selection was not killed after atomic replacement" >&2; exit 1; }
grep -Fx 'MRML_GIT_SIGNER_KEYS_VOLUME=test-selection-git-signer-next-keys' "$environment" >/dev/null
grep -Fx 'MRML_GIT_SIGNER_CANDIDATE_KEYS_VOLUME=test-selection-git-signer-keys' "$environment" >/dev/null
grep -Fx 'MRML_OPENPGP_CREATED_AT=1800000000' "$environment" >/dev/null
grep -Fx 'MRML_TRUST_GENERATION=5' "$environment" >/dev/null
grep -Fx 'MRML_REVOCATION_GENERATION=1' "$environment" >/dev/null

"$directory/select-git-signer-key-slot.sh" next 1800000000 5 1 >/dev/null
grep -Fx 'MRML_GIT_SIGNER_KEYS_VOLUME=test-selection-git-signer-next-keys' "$environment" >/dev/null
grep -Fx 'MRML_GIT_SIGNER_CANDIDATE_KEYS_VOLUME=test-selection-git-signer-keys' "$environment" >/dev/null

cp "$environment" "$temporary/before-stale"
set +e
"$directory/select-git-signer-key-slot.sh" next 1700000000 4 1 >/dev/null 2>&1
status=$?
set -e
[ "$status" -ne 0 ] || { echo "stale signer selection was accepted" >&2; exit 1; }
cmp "$temporary/before-stale" "$environment"

set +e
"$directory/select-git-signer-key-slot.sh" next 1900000000 6 0 >/dev/null 2>&1
status=$?
set -e
[ "$status" -ne 0 ] || { echo "revocation rollback was accepted" >&2; exit 1; }
cmp "$temporary/before-stale" "$environment"

echo "signer key selection process-kill recovery PASS"
