#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-final3-20260905-config
prefix=mrml-completion-final3-20260905
compose() { docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -p "$prefix" "$@"; }
work=$(docker volume inspect --format '{{.Mountpoint}}' "$prefix-git-client-work")
evidence=/mnt/$prefix/measurements-text-v2
[ ! -e "$evidence" ]
mkdir -m 0700 "$evidence"
compose run --rm --no-deps -T git-client clone https://git.example:8443/owner/first.git /work/first-before-text
compose run --rm --no-deps -T --entrypoint /usr/bin/mrml-gitd-certd-test-probe git-client fixture-create /work/first/text256 text > "$evidence/content.sha256"
cmp "$evidence/content.sha256" /mnt/mrml-completion-f-20260905/measurements-text-v1/content.sha256
(cd "$work/first/text256" && sha256sum -c "$evidence/content.sha256")
compose run --rm --no-deps -T git-client -C /work/first add text256/object-00.bin text256/object-01.bin text256/object-02.bin text256/object-03.bin text256/object-04.bin text256/object-05.bin text256/object-06.bin text256/object-07.bin
compose run --rm --no-deps -T git-client -C /work/first commit -m 'Compose 256 MiB text transfer fixture'
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
 compose run --rm --no-deps -T --name "$prefix-measure-text-$operation" -e MRML_ACCOUNTING_HOST_OBSERVER=1 --entrypoint /usr/bin/mrml-gitd-certd-test-probe git-client measure-native "/work/text-$operation-accounting" /usr/bin/mrml-git "$@" > "$evidence/$operation.log" 2>&1 &
 job=$!
 while kill -0 "$job" 2>/dev/null; do
  observer_output="$work/text-$operation-accounting"
  if [ -f "$observer_output" ] && grep -q '^observer_state=zombie$' "$observer_output" && [ ! -e "$observer_output.host-io" ]; then
   observer_namespace_pid=$(sed -n 's/^child_namespace_pid=//p' "$observer_output")
   case $observer_namespace_pid in ''|*[!0-9]*) exit 1 ;; esac
   observer_init_pid=$(docker inspect --format '{{.State.Pid}}' "$prefix-measure-text-$operation")
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
 cp "$work/text-$operation-accounting" "$evidence/$operation-accounting"
}
measure push -C /work/first push origin main
measure clone clone https://git.example:8443/owner/first.git /work/clone-text256
(cd "$work/clone-text256/text256" && sha256sum -c "$evidence/content.sha256")
measure fetch -C /work/first-before-text fetch origin
compose run --rm --no-deps -T git-client -C /work/first-before-text pull origin main
(cd "$work/first-before-text/text256" && sha256sum -c "$evidence/content.sha256")
for suffix in gitd-repos gitd-state gitd-quarantine gitd-cache gitd-receipts authority-state; do
 mount=$(docker volume inspect --format '{{.Mountpoint}}' "$prefix-$suffix")
 printf '%s ' "$suffix" >> "$evidence/storage-bytes"
 du -sb "$mount" | awk '{print $1}' >> "$evidence/storage-bytes"
done
du -sb "$work/first/.git" "$work/clone-text256/.git" >> "$evidence/storage-bytes"
cat "$evidence/push-accounting" "$evidence/clone-accounting" "$evidence/fetch-accounting" "$evidence/storage-bytes"
