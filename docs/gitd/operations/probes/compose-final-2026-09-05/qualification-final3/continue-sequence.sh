#!/bin/sh
set -eu
root=/tmp/mrml-completion-continuous-20260905
remote() { ssh -F /dev/null -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes -i /home/m/.ssh/server_ed25519 -p 42069 ubuntu@mrml.ca 'sudo -n sh -s'; }
for stage in rotate-ready text-benchmark setup-second random-benchmark; do
 remote < "$root/$stage-host.sh" > "$root/$stage.log" 2>&1
 if [ "$stage" = malformed ]; then
  remote > "$root/malformed-server-evidence.log" <<'SERVER'
set -eu
events=$(/usr/bin/docker logs mrml-completion-final3-20260905-gitd-1 2>&1 | sed -n '/event=authority_proof_verify_denied/p')
[ -n "$events" ]
printf '%s\n' "$events"
SERVER
 fi
done
remote < "$root/export-counters-host.sh" > "$root/counters.tar"
mkdir -m 0700 "$root/counters"
tar -xf "$root/counters.tar" -C "$root/counters"
for stage in cold-backup destructive-restore activate-restore prepare-hybrid overlap hybrid-push retirement retirement-push recreate-durable final-metadata; do
 remote < "$root/$stage-host.sh" > "$root/$stage.log" 2>&1
done
printf '%s\n' 'PASS: continuous clean-source two-repository hardened Docker acceptance'
