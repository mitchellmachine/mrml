#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-final3-20260905-config
prefix=mrml-completion-final3-20260905
second_prefix=mrml-completion-final3-second-20260905
compose() { docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -p "$prefix" "$@"; }
second() { MRML_SECOND_CLIENT_PREFIX=$second_prefix MRML_GIT_CREDENTIAL_GENERATION=1 docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -f compose.git.acceptance-second.yaml -p "$prefix" "$@"; }
record=/mnt/$prefix/measure-private
work=$(docker volume inspect --format '{{.Mountpoint}}' "$prefix-git-client-work")
before=$(docker inspect --format '{{.Id}} {{.State.Pid}} {{.State.StartedAt}}' "$prefix-gitd-1")
second run --rm --no-deps -T --name "$prefix-established-clone" git-client clone https://git.example:8443/owner/second.git /work/established-random > "$record/established-clone.log" 2>&1 &
clone_job=$!
deadline=$(($(date +%s) + 120))
while :; do
 client_pid=$(docker inspect --format '{{.State.Pid}}' "$prefix-established-clone" 2>/dev/null || true)
 received=0
 if [ -n "$client_pid" ] && [ "$client_pid" != 0 ] && [ -r "/proc/$client_pid/net/dev" ]; then
  received=$(awk '/eth0:/ {print $2}' "/proc/$client_pid/net/dev")
 fi
 if [ "${received:-0}" -ge 8388608 ]; then break; fi
 kill -0 "$clone_job"
 [ "$(date +%s)" -lt "$deadline" ] || exit 1
 sleep 1
done
[ "$received" -lt 134217728 ]
printf 'established_transfer_received_before_outage=%s\n' "$received"
compose stop certd
[ "$(docker inspect --format '{{.State.ExitCode}}' "$prefix-certd-1")" = 0 ]
if compose exec -T gitd /usr/bin/mrml-gitd listener-health /etc/mrml/gitd.conf; then
 echo 'new TLS handshake incorrectly accepted while certd unavailable' >&2; exit 1
fi
wait "$clone_job"
cat "$record/established-clone.log"
(cd "$work/established-random/random256" && sha256sum -c /mnt/$prefix/measurements-random-v2/content.sha256)
[ "$(docker inspect --format '{{.State.Running}}' "$prefix-certd-1")" = false ]
[ "$before" = "$(docker inspect --format '{{.Id}} {{.State.Pid}} {{.State.StartedAt}}' "$prefix-gitd-1")" ]
printf '%s\n' 'established native 256 MiB clone completed and verified while real certd remained stopped'
compose up -d --no-build --pull never --no-deps certd
deadline=$(($(date +%s) + 40))
until compose exec -T gitd /usr/bin/mrml-gitd listener-health /etc/mrml/gitd.conf >/dev/null 2>&1; do
 [ "$(date +%s)" -lt "$deadline" ] || exit 1
 sleep 1
done
compose run --rm --no-deps -T git-client -C /work/first fetch origin
[ "$before" = "$(docker inspect --format '{{.Id}} {{.State.Pid}} {{.State.StartedAt}}' "$prefix-gitd-1")" ]
# Observe only connect metadata on the test daemon, never RPC payloads. Host
# tracing adds no capability or tracing permission to any container.
gitd_pid=$(docker inspect --format '{{.State.Pid}}' "$prefix-gitd-1")
read_ticks() { awk '{print $14, $15}' "/proc/$gitd_pid/stat"; }
ticks_before=$(read_ticks)
fds_before=$(find "/proc/$gitd_pid/fd" -mindepth 1 -maxdepth 1 | wc -l)
started=$(date +%s%N)
trace_status=0
timeout -s INT 15 /usr/bin/strace -f -ttt -e trace=connect -p "$gitd_pid" -o "$record/certd-connects.trace" 2> "$record/certd-connects.stderr" || trace_status=$?
[ "$trace_status" -eq 124 ] || [ "$trace_status" -eq 0 ]
ended=$(date +%s%N)
ticks_after=$(read_ticks)
fds_after=$(find "/proc/$gitd_pid/fd" -mindepth 1 -maxdepth 1 | wc -l)
connects=$(sed -n '/connect(.*certd-gitd\/certd.sock.*= 0/p' "$record/certd-connects.trace" | wc -l)
printf 'unchanged_observation_nanoseconds=%s\ncertd_successful_connects=%s\ngitd_ticks_before=%s\ngitd_ticks_after=%s\nfds_before=%s\nfds_after=%s\n' "$((ended-started))" "$connects" "$ticks_before" "$ticks_after" "$fds_before" "$fds_after"
[ "$connects" -ge 30 ] && [ "$connects" -le 60 ]
[ "$before" = "$(docker inspect --format '{{.Id}} {{.State.Pid}} {{.State.StartedAt}}' "$prefix-gitd-1")" ]
printf '%s\n' 'real-certd established-work preservation, recovery and bounded unchanged polling PASS'
