#!/system/bin/sh
# Headless ADB + Magisk bootstrap with RSA public-key authentication.
[ -e /dev/.f50pro-usb-root-ready ] && exit 0
TASK_DIR=${0%/*}
if [ -x "$TASK_DIR/magisk" ]; then
    MAGISK="$TASK_DIR/magisk"
else
    MAGISK=/debug_ramdisk/magisk
fi

LOG=/dev/null
if [ -d /cache ]; then
    if : >> /cache/f50pro-usb-root.log 2>/dev/null; then
        LOG=/cache/f50pro-usb-root.log
        chmod 0644 "$LOG" 2>/dev/null || true
    fi
fi
exec >> "$LOG" 2>&1

SLOT=$(getprop ro.boot.slot_suffix)
echo "stage=start slot=${SLOT:-unset} magisk=$MAGISK"
[ "$SLOT" = "_a" ] || exit 1
[ -d /data/misc ] || exit 1

mkdir -p /data/adb/magisk
chmod 0700 /data/adb
cp "$MAGISK" /data/adb/magisk/magisk
chmod 0755 /data/adb/magisk/magisk
ln -sf /data/adb/magisk/magisk /data/adb/magisk/resetprop

KEY_FILE=/data/misc/adb/adb_keys
mkdir -p /data/misc/adb
KEY_LINE=$(cat "$TASK_DIR/f50pro-adb-authorized-key.pub")
if [ -n "$KEY_LINE" ] && ! grep -qxF "$KEY_LINE" "$KEY_FILE" 2>/dev/null; then
    printf '%s\n' "$KEY_LINE" >> "$KEY_FILE"
fi
chown 1000:2000 "$KEY_FILE" 2>/dev/null || true
chmod 0640 "$KEY_FILE" 2>/dev/null || true
restorecon "$KEY_FILE" 2>/dev/null || true

if [ ! -f /data/adb/f50pro-usb-config-before-root.txt ]; then
    getprop persist.sys.usb.config > /data/adb/f50pro-usb-config-before-root.txt 2>/dev/null || true
fi

/data/adb/magisk/resetprop -n ro.debuggable 1
/data/adb/magisk/resetprop -n ro.adb.secure 1
setprop persist.adb.tcp.port -1
setprop service.adb.tcp.port -1
setprop service.adb.root 1

TARGET_USB="__USB_MODE__"
setprop persist.sys.usb.config "$TARGET_USB"
setprop sys.usb.config none
i=0
while [ "$(getprop sys.usb.state)" != "none" ] && [ "$i" -lt 10 ]; do
    sleep 1
    i=$((i + 1))
done
setprop sys.usb.config "$TARGET_USB"
start adbd
touch /dev/.f50pro-usb-root-ready
echo "usb_adb_requested=1 mode=$TARGET_USB auth=1"

(
    j=0
    while [ "$j" -lt 15 ]; do
        if "$MAGISK" --sqlite "INSERT OR REPLACE INTO settings (key,value) VALUES ('root_access',3);" 2>/dev/null && \
           "$MAGISK" --sqlite "INSERT OR REPLACE INTO policies (uid,policy,until,logging,notification) VALUES (2000,2,0,1,1);" 2>/dev/null; then
            echo "magisk_policy_seeded=1 attempt=$j"
            break
        fi
        sleep 1
        j=$((j + 1))
    done
    settings put global adb_enabled 1 >/dev/null 2>&1 || true
) &
