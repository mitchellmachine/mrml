#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-final3-20260905-config
export MRML_ENV_FILE=$PWD/hybrid-g.env MRML_CONTAINER_RUNTIME=docker
prefix=mrml-git-restore-clean-20260905
docker stop -t 15 "$prefix-gitd-1" "$prefix-git-authority-1" "$prefix-signer-git-protected-signer-1"
retired=$(docker volume inspect --format '{{.Mountpoint}}' "$prefix-git-signer-keys")
MRML_VOLUME_PREFIX=$prefix ./install-volume-inputs.sh trust-construction "$retired/openpgp-public.asc" "$retired/ml-dsa-public.bin"
record=/mnt/mrml-completion-final3-20260905/measure-private/retirement-construction.txt
./construct-git-trust-policy.sh retirement owner/first "$(date +%s)" > "$record"
cat "$record"
previous=$(sed -n 's/^previous_generation=2 previous_digest=\([0-9a-f]*\) generation=3 digest=.*/\1/p' "$record")
[ "${#previous}" -eq 128 ]
created=$(sed -n 's/^MRML_OPENPGP_CREATED_AT=//p' hybrid-g.env)
./sign-git-trust-policy.sh retirement owner/first 2 3 "$created" "$created"
./stage-git-trust-transition.sh retirement
./transition-git-trust.sh owner/first "$(date +%s)" 2 "$previous"
# Record the native transition result in public startup configuration only.
umask 077
sed 's/^MRML_TRUST_GENERATION=2$/MRML_TRUST_GENERATION=3/' hybrid-g.env > hybrid-g.env.next
[ "$(grep -c '^MRML_TRUST_GENERATION=3$' hybrid-g.env.next)" -eq 1 ]
chmod 0600 hybrid-g.env.next
sync -f hybrid-g.env.next
mv hybrid-g.env.next hybrid-g.env
sync -f .
./update-git-trust-generation.sh owner/first 3 1
