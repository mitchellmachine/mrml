#!/bin/sh
set -eu

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM
mkdir -p "$temporary/bin" "$temporary/construction/_data"

cat > "$temporary/bin/id" <<'EOF'
#!/bin/sh
if [ "${1:-}" = -u ]; then echo 0; else exec /usr/bin/id "$@"; fi
EOF
cat > "$temporary/bin/stat" <<'EOF'
#!/bin/sh
if [ "${1:-}" = -c ] && [ "${2:-}" = %a ]; then
  echo 600
elif [ "${1:-}" = -c ] && [ "${2:-}" = '%u:%g %a %h' ]; then
  echo '21001:21001 444 1'
else
  exec /usr/bin/stat "$@"
fi
EOF
cat > "$temporary/bin/podman" <<'EOF'
#!/bin/sh
case ${1:-} in
  ps) exit 0 ;;
  volume) echo "$TEST_CONSTRUCTION_PARENT/_data" ;;
  compose)
    previous=$TEST_CONSTRUCTION_PARENT/_data/previous-policy.bin
    next=$TEST_CONSTRUCTION_PARENT/_data/next-policy.bin
    if [ -e "$previous" ] && [ "$(cat "$previous")" != exact-previous ]; then exit 78; fi
    if [ ! -e "$previous" ]; then
      printf '%s\n' exact-previous > "$previous"
      sync -f "$previous"
      sync -f "$TEST_CONSTRUCTION_PARENT/_data"
      if [ ! -e "$TEST_KILL_ONCE" ]; then
        : > "$TEST_KILL_ONCE"
        kill -KILL "$PPID"
        exit 137
      fi
    fi
    if [ -e "$next" ] && [ "$(cat "$next")" != exact-next ]; then exit 78; fi
    if [ ! -e "$next" ]; then
      printf '%s\n' exact-next > "$next"
      sync -f "$next"
      sync -f "$TEST_CONSTRUCTION_PARENT/_data"
    fi
    ;;
  *) exit 2 ;;
esac
EOF
chmod 0755 "$temporary/bin/id" "$temporary/bin/stat" "$temporary/bin/podman"

environment=$temporary/environment
cat > "$environment" <<'EOF'
MRML_VOLUME_PREFIX=test-construction
MRML_PROTECTED_REPOSITORY=owner/project
EOF
chmod 0600 "$environment"

export PATH="$temporary/bin:$PATH"
export TEST_CONSTRUCTION_PARENT=$temporary/construction
export TEST_KILL_ONCE=$temporary/kill-once
export MRML_ENV_FILE=$environment
export MRML_CONTAINER_RUNTIME=podman

set +e
"$directory/construct-git-trust-policy.sh" overlap owner/project 1700000000 1800000000
status=$?
set -e
[ "$status" -gt 128 ] || { echo "construction was not killed after the first durable policy write" >&2; exit 1; }
[ "$(cat "$temporary/construction/_data/previous-policy.bin")" = exact-previous ] || exit 1
[ ! -e "$temporary/construction/_data/next-policy.bin" ] || { echo "next policy existed before injected kill" >&2; exit 1; }

"$directory/construct-git-trust-policy.sh" overlap owner/project 1700000000 1800000000 >/dev/null
[ "$(cat "$temporary/construction/_data/previous-policy.bin")" = exact-previous ] || exit 1
[ "$(cat "$temporary/construction/_data/next-policy.bin")" = exact-next ] || exit 1

rm -- "$temporary/construction/_data/next-policy.bin"
printf '%s\n' conflicting-previous > "$temporary/construction/_data/previous-policy.bin"
set +e
"$directory/construct-git-trust-policy.sh" overlap owner/project 1700000000 1800000000 >/dev/null 2>&1
status=$?
set -e
[ "$status" -ne 0 ] || { echo "conflicting partial construction output was accepted" >&2; exit 1; }
[ ! -e "$temporary/construction/_data/next-policy.bin" ] || { echo "conflicting resume wrote a successor" >&2; exit 1; }

echo "trust policy construction process-kill recovery PASS"
