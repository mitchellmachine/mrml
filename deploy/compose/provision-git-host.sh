#!/bin/sh
set -eu

deployment_root=${MRML_DEPLOY_ROOT:-${MRML_DEPLOYMENT_ROOT:-/mnt/mrml}}
gitd_uid=${MRML_GITD_UID:-21001}
gitd_gid=${MRML_GITD_GID:-21001}
authority_uid=${MRML_GIT_AUTHORITY_UID:-21002}
authority_gid=${MRML_GIT_AUTHORITY_GID:-21002}
authority_socket_gid=${MRML_GIT_AUTHORITY_SOCKET_GID:-21901}
certd_socket_gid=${MRML_CERTD_GITD_SOCKET_GID:-21902}
certd_uid=${MRML_CERTD_UID:-21003}
admin_uid=${MRML_ADMIN_UID:-21005}
admin_gid=${MRML_ADMIN_GID:-21005}
minimum_free_kib=${MRML_MINIMUM_FREE_KIB:-1048576}

fail() {
    printf '%s\n' "provision-git-host: $1" >&2
    exit 1
}

require_number() {
    case $2 in
        ''|*[!0-9]*) fail "$1 must be a nonzero decimal integer" ;;
        0) fail "$1 must be nonzero" ;;
    esac
}

require_number MRML_GITD_UID "$gitd_uid"
require_number MRML_GITD_GID "$gitd_gid"
require_number MRML_GIT_AUTHORITY_UID "$authority_uid"
require_number MRML_GIT_AUTHORITY_GID "$authority_gid"
require_number MRML_GIT_AUTHORITY_SOCKET_GID "$authority_socket_gid"
require_number MRML_CERTD_GITD_SOCKET_GID "$certd_socket_gid"
require_number MRML_CERTD_UID "$certd_uid"
require_number MRML_ADMIN_UID "$admin_uid"
require_number MRML_ADMIN_GID "$admin_gid"
require_number MRML_MINIMUM_FREE_KIB "$minimum_free_kib"

case $deployment_root in
    /mnt/*) ;;
    *) fail "deployment root must be an absolute path below /mnt" ;;
esac
[ "$(id -u)" -eq 0 ] || fail "must run as root"

verify_components() {
    current=
    old_ifs=$IFS
    IFS=/
    set -- $1
    IFS=$old_ifs
    for component do
        [ -n "$component" ] || continue
        current=$current/$component
        [ ! -L "$current" ] || fail "symlink path component: $current"
        if [ -e "$current" ]; then
            [ -d "$current" ] || fail "non-directory path component: $current"
            component_mode=$(stat -c '%a' "$current") || fail "cannot inspect $current"
            if [ $((0$component_mode & 0022)) -ne 0 ]; then
                sticky=$(stat -c '%A' "$current") || fail "cannot inspect $current"
                case $sticky in
                    *t|*T) ;;
                    *) fail "unsafe writable path component: $current" ;;
                esac
            fi
        fi
    done
}

ensure_dir() {
    path=$1
    uid=$2
    gid=$3
    desired_mode=$4
    verify_components "$(dirname "$path")"
    if [ -e "$path" ] || [ -L "$path" ]; then
        [ ! -L "$path" ] || fail "refusing symlink: $path"
        [ -d "$path" ] || fail "expected directory: $path"
    else
        mkdir -- "$path" || fail "cannot create $path"
        chown "$uid:$gid" "$path" || fail "cannot set owner on $path"
        chmod "$desired_mode" "$path" || fail "cannot set mode on $path"
    fi
    actual_owner=$(stat -c '%u:%g' "$path") || fail "cannot inspect owner: $path"
    actual_mode=$(stat -c '%a' "$path") || fail "cannot inspect mode: $path"
    [ "$actual_owner" = "$uid:$gid" ] || fail "wrong owner on $path: $actual_owner"
    [ "$actual_mode" = "$desired_mode" ] || fail "wrong mode on $path: $actual_mode"
}

verify_components "$(dirname "$deployment_root")"
ensure_dir "$deployment_root" 0 0 755
ensure_dir "$deployment_root/backups" "$admin_uid" "$admin_gid" 711
ensure_dir "$deployment_root/backups/git" "$admin_uid" "$admin_gid" 700
ensure_dir "$deployment_root/config" 0 0 750

command -v docker >/dev/null 2>&1 || fail "docker is required to provision managed volumes"

ensure_volume() {
    name=$1
    uid=$2
    gid=$3
    mode=$4
    created=false
    if ! docker volume inspect "$name" >/dev/null 2>&1; then
        docker volume create --label org.mrml.managed=true "$name" >/dev/null ||
            fail "cannot create Docker volume $name"
        created=true
    fi
    mountpoint=$(docker volume inspect --format '{{.Mountpoint}}' "$name") ||
        fail "cannot inspect Docker volume $name"
    case $mountpoint in /*/_data) ;; *) fail "unsafe Docker volume mountpoint for $name" ;; esac
    [ ! -L "$mountpoint" ] && [ -d "$mountpoint" ] || fail "unsafe Docker volume path for $name"
    if [ "$created" = true ]; then
        chown "$uid:$gid" "$mountpoint" || fail "cannot set owner on Docker volume $name"
        chmod "$mode" "$mountpoint" || fail "cannot set mode on Docker volume $name"
    fi
    [ "$(stat -c '%u:%g' "$mountpoint")" = "$uid:$gid" ] || fail "wrong owner on Docker volume $name"
    [ "$(stat -c '%a' "$mountpoint")" = "$mode" ] || fail "wrong mode on Docker volume $name"
}

ensure_volume mrml-gitd-repos "$gitd_uid" "$gitd_gid" 700
ensure_volume mrml-gitd-state "$gitd_uid" "$gitd_gid" 700
ensure_volume mrml-gitd-quarantine "$gitd_uid" "$gitd_gid" 700
ensure_volume mrml-gitd-cache "$gitd_uid" "$gitd_gid" 700
ensure_volume mrml-gitd-receipts "$gitd_uid" "$gitd_gid" 700
ensure_volume mrml-gitd-policies "$gitd_uid" "$gitd_gid" 755
ensure_volume mrml-authority-state "$authority_uid" "$authority_gid" 700
ensure_volume mrml-runtime-git-authority "$authority_uid" "$authority_socket_gid" 2770
ensure_volume mrml-runtime-certd-gitd "$certd_uid" "$certd_socket_gid" 2770
ensure_volume mrml-git-authority-secrets "$authority_uid" "$authority_gid" 700
ensure_volume mrml-git-authority-config 0 0 755
ensure_volume mrml-gitd-secrets "$gitd_uid" "$gitd_gid" 700
ensure_volume mrml-gitd-config 0 0 755

authority_mount=$(docker volume inspect --format '{{.Mountpoint}}' mrml-authority-state) ||
    fail "cannot inspect authority state volume"
ensure_dir "$authority_mount/policies" "$authority_uid" "$authority_gid" 700
ensure_dir "$authority_mount/proofs" "$authority_uid" "$authority_gid" 700

ensure_secret() {
    path=$1
    uid=$2
    gid=$3
    length=$4
    verify_components "$(dirname "$path")"
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        temporary=$path.new.$$
        umask 077
        dd if=/dev/urandom of="$temporary" bs="$length" count=1 status=none || fail "cannot create $path"
        chown "$uid:$gid" "$temporary" || fail "cannot set owner on $path"
        chmod 0400 "$temporary" || fail "cannot set mode on $path"
        mv "$temporary" "$path" || fail "cannot install $path"
    fi
    [ ! -L "$path" ] && [ -f "$path" ] || fail "unsafe secret: $path"
    [ "$(stat -c '%u:%g' "$path")" = "$uid:$gid" ] || fail "wrong secret owner: $path"
    [ "$(stat -c '%a' "$path")" = 400 ] || fail "wrong secret mode: $path"
    [ "$(stat -c '%h' "$path")" = 1 ] || fail "secret must have one link: $path"
    [ "$(stat -c '%s' "$path")" = "$length" ] || fail "wrong secret length: $path"
}

create_channel_pair() {
    authority_secrets=$(docker volume inspect --format '{{.Mountpoint}}' mrml-git-authority-secrets)
    gitd_secrets=$(docker volume inspect --format '{{.Mountpoint}}' mrml-gitd-secrets)
    authority_copy=$authority_secrets/git-authority-channel
    gitd_copy=$gitd_secrets/git-authority-channel
    if { [ -e "$authority_copy" ] && [ ! -e "$gitd_copy" ]; } ||
       { [ ! -e "$authority_copy" ] && [ -e "$gitd_copy" ]; }; then
        fail "incomplete Git authority channel pair"
    fi
    if [ ! -e "$authority_copy" ] && [ ! -e "$gitd_copy" ]; then
        seed=$deployment_root/secrets/channels/.git-authority.seed.$$
        umask 077
        dd if=/dev/urandom of="$seed" bs=32 count=1 status=none || fail "cannot create channel seed"
        cp "$seed" "$authority_copy"
        chown "$authority_uid:$authority_gid" "$authority_copy"
        chmod 0400 "$authority_copy"
        cp "$seed" "$gitd_copy"
        chown "$gitd_uid:$gitd_gid" "$gitd_copy"
        chmod 0400 "$gitd_copy"
        rm -f "$seed"
    fi
    ensure_secret "$authority_copy" "$authority_uid" "$authority_gid" 32
    ensure_secret "$gitd_copy" "$gitd_uid" "$gitd_gid" 32
    cmp -s "$authority_copy" "$gitd_copy" || fail "Git authority channel copies differ"
}

create_channel_pair
authority_secrets=$(docker volume inspect --format '{{.Mountpoint}}' mrml-git-authority-secrets)
gitd_secrets=$(docker volume inspect --format '{{.Mountpoint}}' mrml-gitd-secrets)
ensure_secret "$authority_secrets/receipt.key" "$authority_uid" "$authority_gid" 32
ensure_secret "$gitd_secrets/gitd-token-pepper" "$gitd_uid" "$gitd_gid" 32
ensure_secret "$gitd_secrets/gitd-quic-retry-key" "$gitd_uid" "$gitd_gid" 16

available_kib=$(df -Pk "$deployment_root" | awk 'NR == 2 {print $4}')
case $available_kib in
    ''|*[!0-9]*) fail "cannot determine free filesystem space" ;;
esac
[ "$available_kib" -ge "$minimum_free_kib" ] || fail "insufficient free filesystem space"

probe=$(mktemp -d "$deployment_root/.git-provision-probe.XXXXXX") || fail "cannot create filesystem probe"
trap 'rm -f "$probe/source" "$probe/link" "$probe/renamed"; rmdir "$probe" 2>/dev/null || true' EXIT HUP INT TERM
printf '%s' probe >"$probe/source" || fail "cannot write filesystem probe"
sync -f "$probe/source" || fail "filesystem does not support file sync"
ln "$probe/source" "$probe/link" || fail "filesystem does not support hard links"
mv "$probe/source" "$probe/renamed" || fail "filesystem does not support atomic rename"
sync -f "$probe" || fail "filesystem does not support directory sync"
rm -f "$probe/link" "$probe/renamed"
rmdir "$probe"
trap - EXIT HUP INT TERM

printf '%s\n' "provision-git-host: verified $deployment_root"
