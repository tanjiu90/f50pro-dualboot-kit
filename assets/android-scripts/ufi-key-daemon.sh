#!/system/bin/sh
export PATH=/system/bin:/vendor/bin:/system/xbin:"$PATH"
LOG=/cache/ufi-tools-key.log
echo "=== key daemon start $(date) ===" >> "$LOG"
while true; do
  /data/adb/mu300-keys -l 5000 2>>"$LOG" | while read -r code kind; do
    if [ "$code" = "102" ] && [ "$kind" = "long" ]; then
      /system/bin/sh /data/adb/switch-to-openwrt.sh >>"$LOG" 2>&1 || true
    fi
  done
  echo "mu300-keys exited $(date); restarting in 2s" >> "$LOG"
  sleep 2
done
