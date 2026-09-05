#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-final2-20260905-config
export MRML_ENV_FILE=$PWD/hybrid-g.env MRML_CONTAINER_RUNTIME=docker
prefix=mrml-git-restore-final-20260905
created=$(sed -n 's/^MRML_OPENPGP_CREATED_AT=//p' hybrid-g.env)
next_created=$((created + 1))
docker compose --env-file hybrid-g.env -f compose.signer.yaml -p "$prefix-hybrid-admin" run --rm --no-deps -T -v "$prefix-git-signer-next-keys:/key-generation:rw" git-trust-sign-next generate-key-material 21006 "$next_created" /key-generation
next=$(docker volume inspect --format '{{.Mountpoint}}' "$prefix-git-signer-next-keys")
MRML_VOLUME_PREFIX=$prefix ./install-volume-inputs.sh trust-construction "$next/openpgp-public.asc" "$next/ml-dsa-public.bin"
record=/mnt/mrml-completion-final2-20260905/measure-private/overlap-construction.txt
./construct-git-trust-policy.sh overlap owner/first 1788580000 1791172000 > "$record"
cat "$record"
previous=$(sed -n 's/^previous_generation=1 previous_digest=\([0-9a-f]*\) generation=2 digest=.*/\1/p' "$record")
[ "${#previous}" -eq 128 ]
./sign-git-trust-policy.sh overlap owner/first 1 2 "$created" "$next_created"
./stage-git-trust-transition.sh overlap
./transition-git-trust.sh owner/first "$(date +%s)" 1 "$previous"
./select-git-signer-key-slot.sh next "$next_created" 2 1
./update-git-trust-generation.sh owner/first 2 1
printf '%s\n' 'native dual-authorized overlap selected and signer/catalog advanced'
