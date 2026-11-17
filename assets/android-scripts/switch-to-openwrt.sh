#!/system/bin/sh
export PATH=/system/bin:/vendor/bin:/system/xbin:"$PATH"
LOG=/cache/ufi-tools-key.log
DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

log() {
  echo "[$(date)] $*" >> "$LOG"
  echo "$*"
}

[ "$(getprop ro.boot.slot_suffix)" = "_a" ] || { log "ABORT: not on _a slot"; exit 1; }

MISC=/dev/block/by-name/misc
BOOT_A=/dev/block/by-name/boot_a
BOOT_B=/dev/block/by-name/boot_b
BC_BIN=/data/adb/known-good-b-bcab.bin

[ -b "$MISC" ] && [ -b "$BOOT_A" ] && [ -b "$BOOT_B" ] && [ -s "$BC_BIN" ] || { log "ABORT: missing block dev or control bin"; exit 1; }
[ "$(wc -c < "$BC_BIN")" -eq 32 ] || { log "ABORT: invalid control bin size"; exit 1; }
[ "$(dd if="$MISC" bs=1 skip=2052 count=4 2>/dev/null)" = "BCAB" ] || { log "ABORT: misc+2052 is not BCAB"; exit 1; }
[ "$(dd if="$BOOT_B" bs=1 count=8 2>/dev/null)" = "ANDROID!" ] || { log "ABORT: boot_b is not ANDROID!"; exit 1; }

HA=$(dd if="$BOOT_A" bs=4096 count=16 2>/dev/null | md5sum | cut -d' ' -f1)
HB=$(dd if="$BOOT_B" bs=4096 count=16 2>/dev/null | md5sum | cut -d' ' -f1)
[ -n "$HA" ] && [ -n "$HB" ] && [ "$HA" != "$HB" ] || { log "ABORT: boot_a and boot_b match or unreadable ($HA vs $HB)"; exit 1; }

if [ "$DRY" -eq 1 ]; then
  log "DRY_RUN_OK boot_a=$HA boot_b=$HB bc=$(od -An -tx1 -v "$BC_BIN" | tr -d ' \n')"
  exit 0
fi

log "SWITCH_TO_OPENWRT_B triggered (5s long press)"
for l in wifi_red wifi_green wifi_blue net_red net_green net_blue; do
  [ -w "/sys/class/leds/$l/brightness" ] && echo 0 > "/sys/class/leds/$l/brightness" 2>/dev/null || true
done
[ -w /sys/class/leds/wifi_green/brightness ] && echo 255 > /sys/class/leds/wifi_green/brightness 2>/dev/null || true
[ -w /sys/class/leds/net_green/brightness ] && echo 255 > /sys/class/leds/net_green/brightness 2>/dev/null || true

touch /cache/.f50pro-switch-linux || true
sync

dd if="$BC_BIN" of="$MISC" bs=1 seek=2048 count=32 conv=notrunc 2>/dev/null || { log "ABORT: misc write failed"; rm -f /cache/.f50pro-switch-linux; exit 1; }
sync
dd if="$MISC" bs=1 skip=2048 count=32 2>/dev/null | cmp -s "$BC_BIN" - || { log "ABORT: misc readback verify failed"; rm -f /cache/.f50pro-switch-linux; exit 1; }

log "misc+2048 verified OK; rebooting to OpenWrt _b"
sync
exec /system/bin/reboot
