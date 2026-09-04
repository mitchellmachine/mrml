#!/bin/sh
set -eu

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM
mkdir -p "$temporary/bin" "$temporary/signatures/_data"

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
if [ "${1:-}" = -c ] && [ "${2:-}" = "%u:%g %a %h" ]; then
  shift 2
  printf '21006:21006 '
  exec /usr/bin/stat -c '%a %h' "$@"
fi
exec /usr/bin/stat "$@"
EOF
cat > "$temporary/bin/podman" <<'EOF'
#!/bin/sh
case ${1:-} in
  ps) exit 0 ;;
  volume) echo "$TEST_SIGNATURE_ROOT" ;;
  compose)
    printf '%s|%s|%s\n' "$MRML_GIT_SIGNER_KEYS_VOLUME" "$MRML_GIT_SIGNER_CANDIDATE_KEYS_VOLUME" "$*" >> "$TEST_SIGN_LOG"
    for output in previous-openpgp-public.asc previous-openpgp.sig previous-ml-dsa.sig next-openpgp-public.asc next-openpgp.sig next-ml-dsa.sig; do
      /usr/bin/rm -f "$TEST_SIGNATURE_ROOT/$output"
      : > "$TEST_SIGNATURE_ROOT/$output"
      chmod 0444 "$TEST_SIGNATURE_ROOT/$output"
    done
    ;;
  *) echo "unexpected podman operation: ${1:-}" >&2; exit 2 ;;
esac
EOF
chmod 0755 "$temporary/bin/id" "$temporary/bin/stat" "$temporary/bin/podman"

environment=$temporary/environment
cat > "$environment" <<'EOF'
MRML_VOLUME_PREFIX=test-signing
MRML_PROTECTED_REPOSITORY=owner/project
MRML_GIT_SIGNER_KEYS_VOLUME=test-signing-current
MRML_GIT_SIGNER_CANDIDATE_KEYS_VOLUME=test-signing-candidate
EOF
chmod 0600 "$environment"

export PATH="$temporary/bin:$PATH"
export TEST_SIGNATURE_ROOT=$temporary/signatures/_data
export TEST_SIGN_LOG=$temporary/sign.log
export MRML_ENV_FILE=$environment
export MRML_CONTAINER_RUNTIME=podman

"$directory/sign-git-trust-policy.sh" overlap owner/project 4 5 1700000000 1800000000 >/dev/null
[ "$(sed -n '1s/|.*//p' "$TEST_SIGN_LOG")" = test-signing-current ]
[ "$(sed -n '1s/^[^|]*|\([^|]*\)|.*$/\1/p' "$TEST_SIGN_LOG")" = test-signing-candidate ]
[ "$(sed -n '2s/^[^|]*|\([^|]*\)|.*$/\1/p' "$TEST_SIGN_LOG")" = test-signing-candidate ]

"$directory/sign-git-trust-policy.sh" retirement owner/project 5 6 1800000000 1800000000 >/dev/null
[ "$(sed -n '3s/|.*//p' "$TEST_SIGN_LOG")" = test-signing-current ]
[ "$(sed -n '3s/^[^|]*|\([^|]*\)|.*$/\1/p' "$TEST_SIGN_LOG")" = test-signing-candidate ]
[ "$(sed -n '4s/^[^|]*|\([^|]*\)|.*$/\1/p' "$TEST_SIGN_LOG")" = test-signing-current ]

before=$(wc -l < "$TEST_SIGN_LOG")
set +e
"$directory/sign-git-trust-policy.sh" retirement owner/project 6 7 1800000000 1900000000 >/dev/null 2>&1
status=$?
set -e
[ "$status" -eq 64 ] || { echo "retirement accepted distinct key creation times" >&2; exit 1; }
[ "$(wc -l < "$TEST_SIGN_LOG")" -eq "$before" ] || { echo "invalid retirement started a container" >&2; exit 1; }

echo "trust policy signing modes PASS"
