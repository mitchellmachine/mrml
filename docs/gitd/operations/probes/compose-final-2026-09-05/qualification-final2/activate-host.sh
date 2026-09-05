#!/bin/sh
set -eu
cd /home/ubuntu/mrml-git-final2-20260905-config
path=$(/usr/bin/docker volume inspect --format '{{.Mountpoint}}' mrml-completion-final2-20260905-git-certificate-exchange)
[ ! -e "$path/chain.pem" ]
install -m 0444 /home/ubuntu/mrml-git-completion-20260905-config/chain-final.pem "$path/chain.pem"
/usr/bin/docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -p mrml-completion-final2-20260905 run --rm --no-deps -T git-certd-enroll enroll-activate /run/mrml/certd-acmed/certd.sock /run/secrets/certd-acmed.cap 21004 /config/config.json 3 1 3333333333333333333333333333333333333333333333333333333333333333 /enrollment/chain.pem
/usr/bin/docker compose --env-file acceptance.env -f compose.acme.yaml -f compose.git.yaml -f compose.git.acceptance.yaml -p mrml-completion-final2-20260905 exec -T certd /usr/bin/mrml-certd health
