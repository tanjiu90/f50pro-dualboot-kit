#!/system/bin/sh
export PATH=/system/bin:/vendor/bin:/system/xbin:"$PATH"
LOG=/cache/ufi-tools-boot.log
exec >>"$LOG" 2>&1
echo "=== UFI-TOOLS daemon start $(date) ==="

rm -f /cache/.f50pro-switch-linux

# Optional 45s USB isolation guard when configured for USB-only ADB (charging,adb)
if [ "$(getprop persist.sys.usb.config)" = "charging,adb" ]; then
  (
    u=0
    while [ "$u" -lt 45 ]; do
      st="$(getprop sys.usb.state)"
      cfg="$(getprop sys.usb.config)"
      if [ "$st" != "charging,adb" ] || [ "$cfg" != "charging,adb" ]; then
        echo "[$(date +%T)] guard restore charging,adb (was state=$st config=$cfg)" >>/cache/ufi-tools-usb-guard.log 2>&1
        setprop persist.adb.tcp.port -1
        setprop service.adb.tcp.port -1
        setprop persist.sys.usb.config charging,adb
        setprop sys.usb.config none
        sleep 1
        setprop sys.usb.config charging,adb
        start adbd
      fi
      sleep 1
      u=$((u + 1))
    done
  ) </dev/null >/dev/null 2>&1 &
fi

# Dual-boot physical 5s long-press switcher (key 102 long -> switch back to OpenWrt _b)
if [ "__ENABLE_KEY_SWITCH_DAEMON__" = "1" ] && [ -x /data/adb/mu300-keys ] && [ -x /data/adb/ufi-key-daemon.sh ] && ! pgrep -f "/data/adb/mu300-keys" >/dev/null 2>&1; then
  setsid /system/bin/sh /data/adb/ufi-key-daemon.sh </dev/null >/dev/null 2>&1 &
fi

i=0
while [ "$(getprop sys.boot_completed)" != "1" ] && [ "$i" -lt 90 ]; do
  sleep 2
  i=$((i + 1))
done

FILES_DIR="/data/data/com.minikano.f50_sms/files"
j=0
while [ ! -d "$FILES_DIR" ] && [ "$j" -lt 30 ]; do
  sleep 1
  j=$((j + 1))
done
sleep 3

SOCK="$FILES_DIR/kano_root_shell.sock"

dumpsys deviceidle whitelist +com.minikano.f50_sms >/dev/null 2>&1 || true
cmd app_hibernation set-state com.minikano.f50_sms false >/dev/null 2>&1 || true
appops set com.minikano.f50_sms AUTO_REVOKE_PERMISSIONS_IF_UNUSED ignore >/dev/null 2>&1 || true
settings put global settings_enable_monitor_phantom_procs false >/dev/null 2>&1 || true

for port in 2333 1146 5201 5555; do
  iptables -C INPUT -i sipa+ -p tcp --dport "$port" -j DROP >/dev/null 2>&1 || \
    iptables -I INPUT 1 -i sipa+ -p tcp --dport "$port" -j DROP >/dev/null 2>&1 || true
  ip6tables -C INPUT -i sipa+ -p tcp --dport "$port" -j DROP >/dev/null 2>&1 || \
    ip6tables -I INPUT 1 -i sipa+ -p tcp --dport "$port" -j DROP >/dev/null 2>&1 || true
done

if [ -x "$FILES_DIR/socat" ] && ! pgrep -f "$SOCK" >/dev/null 2>&1; then
  rm -f "$SOCK"
  setsid "$FILES_DIR/socat" -d UNIX-LISTEN:"$SOCK",fork,reuseaddr,unlink-early,mode=0666 EXEC:/system/bin/sh </dev/null >>/cache/ufi-tools-socat.log 2>&1 &
  sleep 1
fi
[ -S "$SOCK" ] && chmod 0666 "$SOCK" >/dev/null 2>&1 || true

if [ -x "$FILES_DIR/ttyd" ] && ! pgrep -f "ttyd --writable --port 1146" >/dev/null 2>&1; then
  PATH="$FILES_DIR:$PATH" setsid "$FILES_DIR/ttyd" --writable --port 1146 "$FILES_DIR/login.sh" </dev/null >>/cache/ufi-tools-ttyd.log 2>&1 &
fi

k=0
while [ "$k" -lt 4 ]; do
  if ss -tln 2>/dev/null | grep -q ":2333 "; then
    break
  fi
  am start -n com.minikano.f50_sms/.MainActivity >/dev/null 2>&1 || true
  sleep 2
  if ! ss -tln 2>/dev/null | grep -q ":2333 "; then
    am start-foreground-service -n com.minikano.f50_sms/.WebService >/dev/null 2>&1 || \
      am startservice -n com.minikano.f50_sms/.WebService >/dev/null 2>&1 || true
    sleep 3
  fi
  k=$((k + 1))
done

sleep 5
if [ "$(getprop persist.sys.usb.config)" = "charging,adb" ] && [ "$(getprop sys.usb.state)" != "charging,adb" ]; then
  setprop persist.adb.tcp.port -1
  setprop service.adb.tcp.port -1
  setprop sys.usb.config none
  sleep 1
  setprop sys.usb.config charging,adb
  start adbd
fi

echo "--- status $(date) ---"
ls -la "$SOCK" 2>&1 || true
ps -ef | grep -E "socat|ttyd|minikano|mu300-keys" | grep -v grep 2>&1 || true
ss -tln 2>/dev/null | grep -E ":2333 |:1146 " 2>&1 || true
getprop sys.usb.config; getprop sys.usb.state
echo "=== UFI-TOOLS daemon ready ==="
