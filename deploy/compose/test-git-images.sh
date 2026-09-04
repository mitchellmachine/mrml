#!/bin/sh
set -eu

gitd=${1:-deploy/compose/Dockerfile.gitd}
authority=${2:-deploy/compose/Dockerfile.git-authority}
signer=${3:-deploy/compose/Dockerfile.git-protected-signer}
backup=${4:-deploy/compose/Dockerfile.git-backup}

require() {
    grep -F "$1" "$2" >/dev/null || {
        printf '%s\n' "missing required image policy in $2: $1" >&2
        exit 1
    }
}

reject() {
    if grep -F "$1" "$2" >/dev/null; then
        printf '%s\n' "forbidden image content in $2: $1" >&2
        exit 1
    fi
}

for dockerfile in "$gitd" "$authority" "$signer" "$backup"; do
    [ -f "$dockerfile" ] || exit 1
    [ "$(grep -c '^FROM .*@sha256:' "$dockerfile")" -eq 2 ] || {
        printf '%s\n' "every image stage must use a digest-pinned base: $dockerfile" >&2
        exit 1
    }
    require "RUN test -x" "$dockerfile"
    reject "apt-get" "$dockerfile"
    reject "curl" "$dockerfile"
    reject "COPY . " "$dockerfile"
    reject "gitd-certd-test-fixture" "$dockerfile"
done

require "USER 21001:21001" "$gitd"
require 'ENTRYPOINT ["/usr/bin/mrml-gitd"]' "$gitd"
reject "mrml-git-authority" "$gitd"
reject "receipt.key" "$gitd"
reject "certd-unlock" "$gitd"
reject "cloudflare" "$gitd"

require "USER 21002:21002" "$authority"
require 'ENTRYPOINT ["/usr/bin/mrml-git-authority"]' "$authority"
reject "mrml-gitd /" "$authority"
reject "certd-unlock" "$authority"
reject "cloudflare" "$authority"

require "USER 21006:21006" "$signer"
require 'ENTRYPOINT ["/usr/bin/mrml-git-protected-signer"]' "$signer"
reject "mrml-gitd /" "$signer"
reject "mrml-git-authority" "$signer"
reject "curl" "$signer"
reject "openssh" "$signer"
reject "gnupg" "$signer"

require "USER 0:0" "$backup"
require 'ENTRYPOINT ["/usr/bin/mrml-git-backup"]' "$backup"
require "/payload/backup /backup" "$backup"
require "/payload/backup-key /backup-key" "$backup"
reject "mrml-gitd /" "$backup"
reject "mrml-git-authority" "$backup"
reject "curl" "$backup"
reject "openssh" "$backup"
reject "gnupg" "$backup"

printf '%s\n' "Git image policies PASS"
