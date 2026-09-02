#!/bin/sh
set -eu

root=${MRML_DEPLOY_ROOT:-/mnt/mrml}
minimum_kib=${MRML_MINIMUM_FREE_KIB:-1048576}

case "$root" in
  /mnt/*) ;;
  *) echo "deployment root must be an absolute path below /mnt" >&2; exit 1 ;;
esac

require_no_symlink_path() {
  target=$1
  current=/
  old_ifs=$IFS
  IFS=/
  set -- $target
  IFS=$old_ifs
  for component do
    [ -n "$component" ] || continue
    current=${current%/}/$component
    if [ -L "$current" ]; then
      echo "symlink path component rejected: $current" >&2
      exit 1
    fi
  done
}

make_dir() {
  path=$1 uid=$2 gid=$3 mode=$4
  displayed_mode=${mode#0}
  require_no_symlink_path "$path"
  install -d -o "$uid" -g "$gid" -m "$mode" "$path"
  [ "$(stat -c %u:%g "$path")" = "$uid:$gid" ] || exit 1
  [ "$(stat -c %a "$path")" = "$displayed_mode" ] || exit 1
}

make_secret() {
  path=$1 uid=$2 gid=$3
  require_no_symlink_path "$path"
  if [ ! -e "$path" ]; then
    temporary=$path.new.$$
    umask 077
    dd if=/dev/urandom of="$temporary" bs=32 count=1 status=none
    chown "$uid:$gid" "$temporary"
    chmod 0400 "$temporary"
    mv -n "$temporary" "$path"
    [ ! -e "$temporary" ] || { rm -f "$temporary"; exit 1; }
  fi
  [ -f "$path" ] && [ ! -L "$path" ] || exit 1
  [ "$(stat -c %u:%g "$path")" = "$uid:$gid" ] || exit 1
  [ "$(stat -c %a "$path")" = 400 ] || exit 1
  [ "$(stat -c %h "$path")" = 1 ] || exit 1
  [ "$(stat -c %s "$path")" = 32 ] || exit 1
}

make_dir "$root" 0 0 0755
make_dir "$root/certd" 21003 21003 0700
make_dir "$root/certd/state" 21003 21003 0700
make_dir "$root/certd/publications" 21003 21003 0750
make_dir "$root/acmed" 21004 21004 0700
make_dir "$root/acmed/state" 21004 21004 0700
make_dir "$root/acmed/challenges" 21004 21004 0700
make_dir "$root/runtime" 0 0 0755
make_dir "$root/runtime/certd-gitd" 21003 21902 2770
make_dir "$root/runtime/certd-acmed" 21003 21903 2770
make_dir "$root/secrets" 0 0 0700
make_dir "$root/secrets/certd" 21003 21003 0700
make_dir "$root/secrets/acmed" 21004 21004 0700
make_dir "$root/secrets/channels" 0 0 0700
make_dir "$root/secrets/admin" 21005 21005 0700
make_dir "$root/config" 0 0 0750
make_dir "$root/backups" 21005 21005 0711
make_dir "$root/backups/certd" 21003 21005 0750
make_dir "$root/backups/acmed" 21004 21005 0750

make_secret "$root/secrets/certd/certd-unlock.key" 21003 21003
make_secret "$root/secrets/acmed/acmed-state.key" 21004 21004

create_backup_key_copies() {
  admin_copy=$root/secrets/admin/backup-auth.key
  certd_copy=$root/secrets/certd/backup-auth.key
  acmed_copy=$root/secrets/acmed/backup-auth.key
  if [ ! -e "$admin_copy" ]; then
    [ ! -e "$certd_copy" ] && [ ! -e "$acmed_copy" ] || {
      echo "backup authentication copies are incomplete" >&2
      exit 1
    }
    temporary=$root/secrets/admin/backup-auth.key.new.$$
    umask 077
    dd if=/dev/urandom of="$temporary" bs=32 count=1 status=none
    chown 21005:21005 "$temporary"
    chmod 0400 "$temporary"
    mv -n "$temporary" "$admin_copy"
    [ ! -e "$temporary" ] || { rm -f "$temporary"; exit 1; }
  elif { [ -e "$certd_copy" ] && [ ! -e "$acmed_copy" ]; } ||
       { [ ! -e "$certd_copy" ] && [ -e "$acmed_copy" ]; }; then
    echo "backup authentication copies are incomplete" >&2
    exit 1
  fi
  if [ ! -e "$certd_copy" ]; then
    install -o 21003 -g 21003 -m 0400 "$admin_copy" "$certd_copy"
  fi
  if [ ! -e "$acmed_copy" ]; then
    install -o 21004 -g 21004 -m 0400 "$admin_copy" "$acmed_copy"
  fi
  make_secret "$admin_copy" 21005 21005
  make_secret "$certd_copy" 21003 21003
  make_secret "$acmed_copy" 21004 21004
  cmp -s "$admin_copy" "$certd_copy" || { echo "certd backup authentication copy differs" >&2; exit 1; }
  cmp -s "$admin_copy" "$acmed_copy" || { echo "acmed backup authentication copy differs" >&2; exit 1; }
}

create_backup_key_copies

create_channel_pair() {
  name=$1 peer_uid=$2 peer_gid=$3
  certd_copy=$root/secrets/channels/$name.cap.certd
  peer_copy=$root/secrets/channels/$name.cap.$4
  if { [ -e "$certd_copy" ] && [ ! -e "$peer_copy" ]; } ||
     { [ ! -e "$certd_copy" ] && [ -e "$peer_copy" ]; }; then
    echo "incomplete channel pair rejected: $name" >&2
    exit 1
  fi
  if [ ! -e "$certd_copy" ] && [ ! -e "$peer_copy" ]; then
    seed=$root/secrets/channels/$name.seed.$$
    umask 077
    dd if=/dev/urandom of="$seed" bs=32 count=1 status=none
    install -o 21003 -g 21003 -m 0400 "$seed" "$certd_copy"
    install -o "$peer_uid" -g "$peer_gid" -m 0400 "$seed" "$peer_copy"
    rm -f "$seed"
  fi
  make_secret "$certd_copy" 21003 21003
  make_secret "$peer_copy" "$peer_uid" "$peer_gid"
  cmp -s "$certd_copy" "$peer_copy" || { echo "channel copies differ: $name" >&2; exit 1; }
}

create_channel_pair certd-gitd 21001 21001 gitd
create_channel_pair certd-acmed 21004 21004 acmed

token=$root/secrets/acmed/cloudflare-api-token
if [ -e "$token" ]; then
  require_no_symlink_path "$token"
  [ -f "$token" ] && [ ! -L "$token" ] || exit 1
  [ "$(stat -c %u:%g "$token")" = 21004:21004 ] || exit 1
  [ "$(stat -c %a "$token")" = 400 ] || exit 1
  [ "$(stat -c %h "$token")" = 1 ] || exit 1
else
  echo "Cloudflare token not created; install it at $token as 21004:21004 mode 0400" >&2
fi

verify_config() {
  path=$1
  if [ ! -e "$path" ]; then
    echo "configuration not installed: $path" >&2
    return
  fi
  require_no_symlink_path "$path"
  [ -f "$path" ] && [ ! -L "$path" ] || exit 1
  [ "$(stat -c %u:%g "$path")" = 0:0 ] || exit 1
  [ "$(stat -c %a "$path")" = 444 ] || exit 1
  [ "$(stat -c %h "$path")" = 1 ] || exit 1
  size=$(stat -c %s "$path")
  [ "$size" -gt 0 ] && [ "$size" -le 16384 ] || exit 1
}

verify_config "$root/config/certd.json"
verify_config "$root/config/acmed.json"

available_kib=$(df -Pk "$root" | awk 'NR==2 {print $4}')
[ "$available_kib" -ge "$minimum_kib" ] || { echo "insufficient free space" >&2; exit 1; }

probe=$root/certd/state/.fs-probe.$$
printf x > "$probe"
sync "$probe"
ln "$probe" "$probe.link"
[ "$(stat -c %h "$probe")" = 2 ] || { rm -f "$probe" "$probe.link"; exit 1; }
rm -f "$probe" "$probe.link"

echo "MRML ACME host paths verified at $root"
