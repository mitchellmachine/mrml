#!/bin/sh
set -eu

deployment_root=${MRML_DEPLOYMENT_ROOT:-/mnt/mrml}
gitd_uid=${MRML_GITD_UID:-21001}
gitd_gid=${MRML_GITD_GID:-21001}
authority_uid=${MRML_GIT_AUTHORITY_UID:-21002}
authority_gid=${MRML_GIT_AUTHORITY_GID:-21002}
authority_socket_gid=${MRML_GIT_AUTHORITY_SOCKET_GID:-21901}
certd_socket_gid=${MRML_CERTD_GITD_SOCKET_GID:-21902}
certd_uid=${MRML_CERTD_UID:-21003}

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

case $deployment_root in
    /*) ;;
    *) fail "MRML_DEPLOYMENT_ROOT must be absolute" ;;
esac
case $deployment_root in
    /|/mnt|/tmp|*/.|*/..|*/../*|*/./*) fail "unsafe deployment root" ;;
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
            mode=$(stat -c '%a' "$current") || fail "cannot inspect $current"
            if [ $((0$mode & 0022)) -ne 0 ]; then
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
    mode=$4
    verify_components "$(dirname "$path")"
    if [ -e "$path" ] || [ -L "$path" ]; then
        [ ! -L "$path" ] || fail "refusing symlink: $path"
        [ -d "$path" ] || fail "expected directory: $path"
    else
        mkdir -- "$path" || fail "cannot create $path"
        chown "$uid:$gid" "$path" || fail "cannot set owner on $path"
        chmod "$mode" "$path" || fail "cannot set mode on $path"
    fi
    actual_owner=$(stat -c '%u:%g' "$path") || fail "cannot inspect owner: $path"
    actual_mode=$(stat -c '%a' "$path") || fail "cannot inspect mode: $path"
    [ "$actual_owner" = "$uid:$gid" ] || fail "wrong owner on $path: $actual_owner"
    [ "$actual_mode" = "$mode" ] || fail "wrong mode on $path: $actual_mode"
}

verify_components "$(dirname "$deployment_root")"
ensure_dir "$deployment_root" 0 0 755
ensure_dir "$deployment_root/gitd" 0 0 755
ensure_dir "$deployment_root/gitd/repos" "$gitd_uid" "$gitd_gid" 700
ensure_dir "$deployment_root/gitd/state" "$gitd_uid" "$gitd_gid" 700
ensure_dir "$deployment_root/gitd/quarantine" "$gitd_uid" "$gitd_gid" 700
ensure_dir "$deployment_root/gitd/cache" "$gitd_uid" "$gitd_gid" 700
ensure_dir "$deployment_root/gitd/receipts" "$gitd_uid" "$gitd_gid" 700
ensure_dir "$deployment_root/gitd/policies" "$gitd_uid" "$gitd_gid" 700
ensure_dir "$deployment_root/authority" 0 0 755
ensure_dir "$deployment_root/authority/state" "$authority_uid" "$authority_gid" 700
ensure_dir "$deployment_root/runtime" 0 0 755
ensure_dir "$deployment_root/runtime/git-authority" "$authority_uid" "$authority_socket_gid" 750
ensure_dir "$deployment_root/runtime/certd-gitd" "$certd_uid" "$certd_socket_gid" 750
ensure_dir "$deployment_root/secrets" 0 0 700
ensure_dir "$deployment_root/secrets/git-authority" "$authority_uid" "$authority_gid" 700
ensure_dir "$deployment_root/secrets/channels" 0 0 700
ensure_dir "$deployment_root/backups" 0 0 700

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
