#!/system/bin/sh
export PATH=/system/bin:/vendor/bin:/system/xbin:"$PATH"
setsid /system/bin/sh /data/adb/ufi-tools-daemon.sh </dev/null >/cache/ufi-tools-launch.log 2>&1 &
