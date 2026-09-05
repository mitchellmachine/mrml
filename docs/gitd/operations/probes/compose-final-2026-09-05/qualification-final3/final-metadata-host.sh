#!/bin/sh
set -eu
export PATH=/usr/bin:/bin
docker version --format 'engine={{.Server.Version}} platform={{.Server.Os}}/{{.Server.Arch}}'
docker compose version
docker context show
docker info --format 'data_root={{.DockerRootDir}}'
for container in mrml-git-restore-clean-20260905-gitd-1 mrml-git-restore-clean-20260905-git-authority-1 mrml-git-restore-clean-20260905-signer-git-protected-signer-1 mrml-git-restore-clean-20260905-credential-git-credential-agent-1 mrml-completion-final3-20260905-certd-1 mrml-completion-final3-second-20260905-signer-git-protected-signer-1 mrml-completion-final3-second-20260905-credential-git-credential-agent-1; do
 docker inspect --format 'name={{.Name}} configured={{.Config.Image}} image={{.Image}} user={{.Config.User}} readonly={{.HostConfig.ReadonlyRootfs}} privileged={{.HostConfig.Privileged}} cap_drop={{json .HostConfig.CapDrop}} cap_add={{json .HostConfig.CapAdd}} security={{json .HostConfig.SecurityOpt}} network={{.HostConfig.NetworkMode}} pids={{.HostConfig.PidsLimit}} memory={{.HostConfig.Memory}} nano_cpus={{.HostConfig.NanoCpus}} ports={{json .NetworkSettings.Ports}}' "$container"
 [ "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}} {{.HostConfig.Privileged}}' "$container")" = 'true false' ]
done
backup=$(docker volume inspect --format '{{.Mountpoint}}' mrml-completion-final3-20260905-git-backups)
stat -c 'encrypted_backup bytes=%s mode=%a links=%h' "$backup/git-2026090501.mrb"
sha256sum "$backup/git-2026090501.mrb"
for prefix in mrml-completion-f-20260905 mrml-completion-final3-20260905; do
 for suffix in gitd-repos gitd-state gitd-quarantine gitd-cache gitd-receipts gitd-policies gitd-secrets gitd-config authority-state git-authority-secrets git-authority-config; do
  if docker volume inspect "$prefix-$suffix" >/dev/null 2>&1; then exit 1; fi
 done
done
printf '%s\n' 'both sets of eleven deleted disposable source volumes remain absent'
