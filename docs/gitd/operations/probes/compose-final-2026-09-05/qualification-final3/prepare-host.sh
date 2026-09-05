#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
prefix=mrml-completion-final3-20260905
input=/home/ubuntu/mrml-git-final3-20260905-config
verified=/var/snap/docker/common/mrml-completion-20260905/payload-final-candidate/deploy
[ ! -e "$input" ]
mkdir -m 0700 "$input"
cp "$verified"/* "$input/"
for name in profiles.v1 repositories.v1 authority-repositories.v1 gitd.conf certd.json acme-trust-roots.pem; do
 install -m 0444 "/home/ubuntu/mrml-git-completion-20260905-config/$name" "$input/$name"
done
cd "$input"
# This namespace starts with empty, independently provisioned daemon custody.
MRML_VOLUME_PREFIX=$prefix MRML_DEPLOY_ROOT=/mnt/$prefix sh ./provision-git-host.sh
MRML_VOLUME_PREFIX=$prefix MRML_DEPLOY_ROOT=/mnt/$prefix sh ./provision-acme-host.sh
MRML_VOLUME_PREFIX=$prefix sh ./provision-git-signer-host.sh 21005 21005
MRML_VOLUME_PREFIX=$prefix sh ./provision-git-credential-agent-host.sh 21005 21005
MRML_VOLUME_PREFIX=$prefix sh ./provision-git-acceptance-host.sh
MRML_VOLUME_PREFIX=$prefix sh ./install-volume-inputs.sh certd "$input/certd.json" "$input/acme-trust-roots.pem"
install -d -m 0700 /mnt/$prefix/measure-private
volume() { docker volume inspect --format '{{.Mountpoint}}' "$prefix-$1"; }
policies=$(volume gitd-policies)
for name in profiles.v1 repositories.v1; do
  [ ! -e "$policies/$name" ]
  install -m 0444 "$input/$name" "$policies/$name"
  chown 21001:21001 "$policies/$name"
done
config=$(volume gitd-config)
# Correct only the not-yet-used disposable public config before initialization.
install -m 0444 "$input/gitd.conf" "$config/gitd.conf.new"
mv "$config/gitd.conf.new" "$config/gitd.conf"
sync -f "$config"
umask 077
cat > "$input/acceptance.env" <<'ENV'
MRML_GIT_VERSION=completion-final-20260905
MRML_ACME_VERSION=completion-final-20260905
MRML_VOLUME_PREFIX=mrml-completion-final3-20260905
MRML_DEPLOY_ROOT=/mnt/mrml-completion-final3-20260905
MRML_GIT_CLIENT_UID=21005
MRML_GIT_CLIENT_GID=21005
MRML_PROTECTED_REPOSITORY=owner/first
MRML_REPOSITORY_GENERATION=1
MRML_TRUST_GENERATION=1
MRML_REVOCATION_GENERATION=1
MRML_OPENPGP_CREATED_AT=1788580000
MRML_AUTHORITY_VALIDATION_TIME=1788580000
MRML_AUTHORITY_SIGNER_IDENTITY=11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
MRML_GIT_SIGNER_KEYS_VOLUME=mrml-completion-final3-20260905-git-signer-keys
MRML_GIT_SIGNER_CANDIDATE_KEYS_VOLUME=mrml-completion-final3-20260905-git-signer-next-keys
MRML_GIT_CREDENTIAL_HOST=git.example
MRML_GIT_CREDENTIAL_PORT=8443
MRML_GIT_CREDENTIAL_REPOSITORY_PATH=/owner/first.git
MRML_GIT_CREDENTIAL_ACTIONS=read-write
MRML_GIT_CREDENTIAL_GENERATION=1
ENV
chmod 0600 "$input/acceptance.env"
cd "$input"
docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -p "$prefix" config --quiet
docker compose --env-file acceptance.env -f compose.signer.yaml -p "$prefix-signer" config --quiet
docker compose --env-file acceptance.env -f compose.credential-agent.yaml -p "$prefix-credential" config --quiet
docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -p "$prefix" up -d --no-build --pull never certd

# No identity exists yet; lifecycle enrollment must nevertheless be ready.
compose() { docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -p "$prefix" "$@"; }
deadline=$(($(date +%s) + 40))
until compose exec -T certd /usr/bin/mrml-certd lifecycle-health; do
 [ "$(date +%s)" -lt "$deadline" ] || exit 1
 sleep 1
done
compose run --rm --no-deps -T git-certd-enroll enroll-csr /run/mrml/certd-acmed/certd.sock /run/secrets/certd-acmed.cap 21004 /config/config.json 1 /enrollment/csr.der
exchange=$(volume git-certificate-exchange)
install -m 0444 "$exchange/csr.der" "$input/csr.der"
printf '%s\n' 'fresh real-certd lifecycle enrollment CSR ready for local test CA signing'
