#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
prefix=mrml-completion-final3-20260905
public=/mnt/$prefix/public-counters
[ ! -e "$public" ]
mkdir -m 0700 "$public"
for fixture in text random; do
 input=/mnt/$prefix/measurements-$fixture-v2
 mkdir -m 0700 "$public/$fixture"
 for name in content.sha256 storage-bytes; do install -m 0444 "$input/$name" "$public/$fixture/$name"; done
 for operation in push clone fetch; do
  for suffix in accounting server-samples; do
   install -m 0444 "$input/$operation-$suffix" "$public/$fixture/$operation-$suffix"
  done
  for phase in before after; do
   for component in gitd authority; do
    for counter in cpu-ticks io memory net; do
     name=$operation-$phase-$component-$counter
     install -m 0444 "$input/$name" "$public/$fixture/$name"
    done
   done
  done
 done
done
for suffix in gitd-repos gitd-state gitd-quarantine gitd-cache gitd-receipts authority-state; do
 mount=$(docker volume inspect --format '{{.Mountpoint}}' "$prefix-$suffix")
 printf '%s ' "$suffix" >> "$public/final-storage"
 du -sb "$mount" | awk '{print $1}' >> "$public/final-storage"
done
getconf CLK_TCK > "$public/clock-ticks"
tar -C "$public" -cf - text random clock-ticks final-storage
