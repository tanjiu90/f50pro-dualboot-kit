#!/system/bin/sh
# Bounded 480s safety rollback to verified B bootloader_control block at misc+2048.
[ "__ENABLE_RETURN_B_TIMER__" = "1" ] || exit 0
[ -e /dev/.f50pro-return-timer-armed ] && exit 0
[ "$(getprop ro.boot.slot_suffix)" = "_a" ] || exit 1
touch /dev/.f50pro-return-timer-armed
TASK_DIR=${0%/*}
KEEP=/data/local/tmp/f50pro-keep-android-test
DONE=/data/adb/f50pro-android-test-complete
TOKEN="__ROLLBACK_TOKEN__"
is_disarmed() {
    [ -f "$DONE" ] || return 1
    [ -z "$TOKEN" ] && return 0
    [ "$(cat "$DONE" 2>/dev/null)" = "$TOKEN" ]
}
is_disarmed && exit 0
[ -f "$TASK_DIR/f50pro-known-good-b-bcab.bin" ] || exit 0
sleep 480
[ -e "$KEEP" ] && exit 0
is_disarmed && exit 0
MISC=/dev/block/by-name/misc
[ -b "$MISC" ] || exit 1
[ "$(/system/bin/dd if="$MISC" bs=1 skip=2052 count=4 2>/dev/null)" = "BCAB" ] || exit 1
/system/bin/dd if="$TASK_DIR/f50pro-known-good-b-bcab.bin" of="$MISC" bs=1 seek=2048 count=32 conv=notrunc 2>/dev/null
sync
/system/bin/dd if="$MISC" bs=1 skip=2048 count=32 2>/dev/null | \
    /system/bin/cmp -s "$TASK_DIR/f50pro-known-good-b-bcab.bin" - || exit 1
/system/bin/reboot
