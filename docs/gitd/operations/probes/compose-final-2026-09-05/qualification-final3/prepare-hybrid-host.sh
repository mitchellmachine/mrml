#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-final3-20260905-config
old=mrml-completion-final3-20260905
prefix=mrml-git-restore-clean-20260905
trusted=/var/snap/docker/common/mrml-completion-20260905/payload-final-candidate/deploy
[ ! -e hybrid-g.env ]
docker stop -t 15 "$prefix-gitd-1" "$prefix-git-authority-1" "$old-signer-git-protected-signer-1" "$old-credential-git-credential-agent-1"
MRML_VOLUME_PREFIX=$prefix sh "$trusted/provision-git-signer-host.sh" 21005 21005
MRML_VOLUME_PREFIX=$prefix sh "$trusted/provision-git-credential-agent-host.sh" 21005 21005
copy_exact() {
 suffix=$1; shift
 from=$(docker volume inspect --format '{{.Mountpoint}}' "$old-$suffix")
 to=$(docker volume inspect --format '{{.Mountpoint}}' "$prefix-$suffix")
 [ -z "$(docker ps -q --filter volume="$old-$suffix")" ]
 [ -z "$(docker ps -q --filter volume="$prefix-$suffix")" ]
 for file in "$@"; do
  [ -f "$from/$file" ] && [ ! -L "$from/$file" ] && [ "$(stat -c %h "$from/$file")" -eq 1 ]
  [ ! -e "$to/$file" ] && [ ! -L "$to/$file" ]
  cp --preserve=mode,ownership,timestamps --no-clobber "$from/$file" "$to/$file"
  cmp -s "$from/$file" "$to/$file"
  [ "$(stat -c '%u:%g:%a:%s:%h' "$from/$file")" = "$(stat -c '%u:%g:%a:%s:%h' "$to/$file")" ]
  sync -f "$to/$file"
 done
 sync -f "$to"
}
copy_exact git-signer-keys openpgp.seed openpgp-public.asc ml-dsa-public.bin ml-dsa-secret.bin
copy_exact git-signer-state generation.state
copy_exact git-credential-agent-token token
umask 077
sed -e "s/^MRML_GIT_SIGNER_KEYS_VOLUME=.*/MRML_GIT_SIGNER_KEYS_VOLUME=$prefix-git-signer-keys/" -e "s/^MRML_GIT_SIGNER_CANDIDATE_KEYS_VOLUME=.*/MRML_GIT_SIGNER_CANDIDATE_KEYS_VOLUME=$prefix-git-signer-next-keys/" restore-g.env > hybrid-g.env
chmod 0600 hybrid-g.env
# The old client custody is retained stopped. No generation bytes were edited.
printf '%s\n' 'exact cold client custody copied into fresh restored namespace; original custody retained stopped'
