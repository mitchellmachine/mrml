#!/bin/sh
set -eu

gitd=${1:-deploy/compose/Dockerfile.gitd}
authority=${2:-deploy/compose/Dockerfile.git-authority}

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

for dockerfile in "$gitd" "$authority"; do
    [ -f "$dockerfile" ] || exit 1
    [ "$(grep -c '^FROM .*@sha256:' "$dockerfile")" -eq 2 ] || {
        printf '%s\n' "every image stage must use a digest-pinned base: $dockerfile" >&2
        exit 1
    }
    require "RUN test -x" "$dockerfile"
    reject "apt-get" "$dockerfile"
    reject "curl" "$dockerfile"
    reject "COPY . " "$dockerfile"
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

printf '%s\n' "Git image policies PASS"
