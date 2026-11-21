#!/bin/sh
# Repair the legacy F50 Pro boot sequence without touching the live USB gadget.
set -eu

root=''
if [ "$#" -ne 0 ]; then
    root=$1
fi
late="$root/etc/init.d/f50pro-usb"
early="$root/usr/sbin/u30pro-usb-boot"

if [ "$(cat "$root/etc/mu300/model" 2>/dev/null)" != f50pro ]; then
    echo 'This repair requires an F50 Pro OpenWrt root.' >&2
    exit 1
fi
if [ ! -f "$late" ]; then
    echo 'Legacy F50 Pro USB init script absent.'
    exit 0
fi

stop_line='    /usr/sbin/u30pro-usb stop >/dev/null 2>&1'
start_line='    /usr/sbin/u30pro-usb start rndis >/dev/null 2>&1'
fixed_line='    # The early USB boot policy configures the gadget before serial login.'
if grep -Fqx "$fixed_line" "$late"; then
    if grep -qx 'mode=rndis' "$early"; then
        echo 'F50 Pro USB boot repair already applied.'
        exit 0
    fi
elif [ "$(grep -Fxc "$stop_line" "$late" || true)" != 1 ] ||
     [ "$(grep -Fxc "$start_line" "$late" || true)" != 1 ]; then
    echo 'Unrecognized legacy F50 Pro USB init script.' >&2
    exit 1
fi

if [ ! -f "$early" ] ||
   [ "$(grep -Exc 'mode=(ncm|rndis)' "$early" || true)" != 1 ]; then
    echo 'Unrecognized early USB boot policy.' >&2
    exit 1
fi

early_tmp=''
late_tmp=''
trap 'for file in "$early_tmp" "$late_tmp"; do [ -z "$file" ] || rm -f "$file"; done' EXIT
early_tmp=$(mktemp "$early.f50pro.XXXXXX")
late_tmp=$(mktemp "$late.f50pro.XXXXXX")
sed 's/^mode=ncm$/mode=rndis/' "$early" > "$early_tmp"
awk -v stop="$stop_line" -v start="$start_line" -v fixed="$fixed_line" '
    $0 == stop { print fixed; next }
    $0 == start { next }
    { print }
' "$late" > "$late_tmp"
sh -n "$early_tmp"
sh -n "$late_tmp"
chmod 0755 "$early_tmp" "$late_tmp"

# Remove the blocking late step first so an interrupted repair is safe to retry.
mv -f "$late_tmp" "$late"
mv -f "$early_tmp" "$early"
echo 'F50 Pro USB boot repair applied. It takes effect at the next boot.'
