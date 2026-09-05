#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-completion-20260905-config
export MRML_ENV_FILE=$PWD/hybrid-g.env MRML_CONTAINER_RUNTIME=docker
prefix=mrml-git-restore-g-20260905
created=$(sed -n 's/^MRML_OPENPGP_CREATED_AT=//p' hybrid-g.env)
next_created=$((created + 1))
./transition-git-trust.sh owner/first "$(date +%s)" 1 8c16eb118bcbe4e687c07e97818407ab4071865727c42d80c8699e22fecf3f69d7174ea08befdad6d400e977bd6d1dc4111f6c6792d22559cc3856e9f4357147
./select-git-signer-key-slot.sh next "$next_created" 2 1
./update-git-trust-generation.sh owner/first 2 1
printf '%s\n' 'overlap selected by both hybrid authorizations and signer/catalog advanced through native operator paths'
