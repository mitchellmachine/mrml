#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-final2-20260905-config
prefix=mrml-completion-final2-20260905
compose() { MRML_SECOND_CLIENT_PREFIX=mrml-completion-final2-second-20260905 MRML_GIT_CREDENTIAL_GENERATION=1 MRML_GIT_VERSION=completion-final-20260905 docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -f compose.git.acceptance-second.yaml -p "$prefix" "$@"; }
work=$(docker volume inspect --format '{{.Mountpoint}}' "$prefix-git-client-work")
evidence=/mnt/mrml-completion-final2-20260905/measurements-random-v2
[ ! -e "$evidence" ]
mkdir -m 0700 "$evidence"
compose run --rm --no-deps -T --entrypoint /usr/bin/mrml-gitd-certd-test-probe git-client fixture-create /work/second/random256 random > "$evidence/content.sha256"
cmp "$evidence/content.sha256" /mnt/mrml-completion-f-20260905/measurements-random-v1/content.sha256
(cd "$work/second/random256" && sha256sum -c "$evidence/content.sha256")
compose run --rm --no-deps -T git-client -C /work/second add random256/object-00.bin random256/object-01.bin random256/object-02.bin random256/object-03.bin random256/object-04.bin random256/object-05.bin random256/object-06.bin random256/object-07.bin
compose run --rm --no-deps -T git-client -C /work/second commit -m 'Compose 256 MiB random transfer fixture'
server=$(docker inspect --format '{{.State.Pid}}' "$prefix-gitd-1")
authority=$(docker inspect --format '{{.State.Pid}}' "$prefix-git-authority-1")
snapshot() {
 for pair in "gitd:$server" "authority:$authority"; do
  component=${pair%:*}; pid=${pair#*:}
  cat "/proc/$pid/io" > "$evidence/$1-$component-io"
  awk '{printf "user_ticks=%s\nsystem_ticks=%s\nstart_ticks=%s\n", $14, $15, $22}' "/proc/$pid/stat" > "$evidence/$1-$component-cpu-ticks"
  sed -n '/^VmRSS:/p;/^VmHWM:/p;/^Threads:/p' "/proc/$pid/status" > "$evidence/$1-$component-memory"
  cat "/proc/$pid/net/dev" > "$evidence/$1-$component-net"
 done
}
measure() {
 operation=$1; shift
 snapshot "$operation-before"
 compose run --rm --no-deps -T --name "$prefix-measure-random-$operation" -e MRML_ACCOUNTING_HOST_OBSERVER=1 --entrypoint /usr/bin/mrml-gitd-certd-test-probe git-client measure-native "/work/random-$operation-accounting" /usr/bin/mrml-git "$@" > "$evidence/$operation.log" 2>&1 &
 job=$!
 while kill -0 "$job" 2>/dev/null; do
  observer_output="$work/random-$operation-accounting"
  if [ -f "$observer_output" ] && grep -q '^observer_state=zombie$' "$observer_output" && [ ! -e "$observer_output.host-io" ]; then
   observer_namespace_pid=$(sed -n 's/^child_namespace_pid=//p' "$observer_output")
   case $observer_namespace_pid in ''|*[!0-9]*) exit 1 ;; esac
   observer_init_pid=$(docker inspect --format '{{.State.Pid}}' "$prefix-measure-random-$operation")
   set -- $(cat "/proc/$observer_init_pid/task/$observer_init_pid/children")
   [ "$#" -eq 1 ]
   observer_child_pid=$1
   [ "$(awk '/^PPid:/ {print $2}' "/proc/$observer_child_pid/status")" = "$observer_init_pid" ]
   [ "$(awk '/^NSpid:/ {print $NF}' "/proc/$observer_child_pid/status")" = "$observer_namespace_pid" ]
   observer_temporary=$(mktemp "/mnt/$prefix/measure-private/accounting.XXXXXX")
   { printf 'child_namespace_pid=%s\n' "$observer_namespace_pid"; cat "/proc/$observer_child_pid/io"; } > "$observer_temporary"
   chmod 0400 "$observer_temporary"
   chown 21005:21005 "$observer_temporary"
   [ "$(stat -c %d "$observer_temporary")" = "$(stat -c %d "$work")" ]
   mv -T "$observer_temporary" "$observer_output.host-io"
  fi
  date +%s >> "$evidence/$operation-server-samples"
  sed -n '/^VmRSS:/p;/^VmHWM:/p' "/proc/$server/status" >> "$evidence/$operation-server-samples"
  sleep 1
 done
 result=0; wait "$job" || result=$?
 snapshot "$operation-after"
 cat "$evidence/$operation.log"
 [ "$result" -eq 0 ]
 cp "$work/random-$operation-accounting" "$evidence/$operation-accounting"
}
measure push -C /work/second push origin main
measure clone clone https://git.example:8443/owner/second.git /work/clone-random256
(cd "$work/clone-random256/random256" && sha256sum -c "$evidence/content.sha256")
measure fetch -C /work/second-before-random fetch origin
compose run --rm --no-deps -T git-client -C /work/second-before-random pull origin main
(cd "$work/second-before-random/random256" && sha256sum -c "$evidence/content.sha256")
repos=$(docker volume inspect --format '{{.Mountpoint}}' "$prefix-gitd-repos")
du -sb "$repos" "$work/second/.git" "$work/clone-random256/.git" > "$evidence/storage-bytes"
cat "$evidence/push-accounting" "$evidence/clone-accounting" "$evidence/fetch-accounting" "$evidence/storage-bytes"
