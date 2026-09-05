#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
cd /home/ubuntu/mrml-git-final2-20260905-config
trusted=/var/snap/docker/common/mrml-completion-20260905/payload-final-candidate/deploy
MRML_ENV_FILE=$PWD/acceptance.env MRML_GIT_RESTORE_COMPOSE_FILE=$trusted/compose.git-restore.yaml sh "$trusted/restore-git.sh" 2026090501 mrml-git-restore-final-20260905
