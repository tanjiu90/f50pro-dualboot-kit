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
SOCK="$FILES_DIR/kano_root_shell.sock"
LOGIN_SCRIPT="/data/adb/ufi-ttyd-login.sh"

dumpsys deviceidle whitelist +com.minikano.f50_sms >/dev/null 2>&1 || true
cmd app_hibernation set-state com.minikano.f50_sms false >/dev/null 2>&1 || true
appops set com.minikano.f50_sms AUTO_REVOKE_PERMISSIONS_IF_UNUSED ignore >/dev/null 2>&1 || true
settings put global settings_enable_monitor_phantom_procs false >/dev/null 2>&1 || true

FW_OK=1
for port in 2333 1146 5201 5555; do
  if ! iptables -C INPUT -i sipa+ -p tcp --dport "$port" -j DROP >/dev/null 2>&1; then
    iptables -I INPUT 1 -i sipa+ -p tcp --dport "$port" -j DROP >/dev/null 2>&1 || FW_OK=0
  fi
  if command -v ip6tables >/dev/null 2>&1; then
    if ! ip6tables -C INPUT -i sipa+ -p tcp --dport "$port" -j DROP >/dev/null 2>&1; then
      ip6tables -I INPUT 1 -i sipa+ -p tcp --dport "$port" -j DROP >/dev/null 2>&1 || FW_OK=0
    fi
  elif [ -f /proc/net/if_inet6 ]; then
    FW_OK=0
  fi
done

k=0
while [ "$k" -lt 12 ]; do
  if ss -tln 2>/dev/null | grep -q ":2333 " && [ -x "$FILES_DIR/socat" ] && [ -x "$FILES_DIR/ttyd" ]; then
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

UFI_OWNER="$(stat -c '%u:%g' "$FILES_DIR" 2>/dev/null || true)"
if [ -x "$FILES_DIR/socat" ] && ! pgrep -f "$SOCK" >/dev/null 2>&1; then
  rm -f "$SOCK"
  setsid "$FILES_DIR/socat" -d UNIX-LISTEN:"$SOCK",fork,reuseaddr,unlink-early,mode=0600 EXEC:/system/bin/sh </dev/null >>/cache/ufi-tools-socat.log 2>&1 &
  sleep 1
fi
if [ -S "$SOCK" ]; then
  if [ -z "$UFI_OWNER" ] || ! chown "$UFI_OWNER" "$SOCK" 2>/dev/null || ! chmod 0600 "$SOCK" 2>/dev/null; then
    echo "ERROR: failed to restrict $SOCK ownership/mode; stopping socat and removing socket"
    pkill -f "$SOCK" >/dev/null 2>&1 || true
    rm -f "$SOCK"
  fi
fi

# Start ttyd only when cellular firewall guard succeeded, a non-cellular bind interface exists,
# AND hardened zero-backdoor login script + valid 64-hex password hash source exist.
TTYD_BIND_IFACE=""
for cand_if in br0 rndis0 wlan0 ap0 lo; do
  if [ -d "/sys/class/net/$cand_if" ]; then
    if [ "$cand_if" = "lo" ]; then
      TTYD_BIND_IFACE="$cand_if"
      break
    elif command -v ip >/dev/null 2>&1; then
      if ip -4 -o addr show dev "$cand_if" 2>/dev/null | grep -q 'inet '; then
        TTYD_BIND_IFACE="$cand_if"
        break
      fi
    else
      TTYD_BIND_IFACE="$cand_if"
      break
    fi
  fi
done

# Terminate EVERY legacy, unbound, or stale-interface ttyd instance on port 1146 (exact cmdline match).
EXPECTED_TTYD_ARGS="--writable --port 1146 --interface $TTYD_BIND_IFACE $LOGIN_SCRIPT"
TTYD_RUNNING=0
for pid in $(pgrep -f "ttyd" 2>/dev/null || true); do
  [ -r "/proc/$pid/cmdline" ] || continue
  cmdline="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)"
  cmdline="${cmdline% }"
  case " $cmdline " in
    *" ttyd "*" 1146 "*|*"/ttyd "*" 1146 "*)
      if [ -z "$TTYD_BIND_IFACE" ]; then
        kill "$pid" >/dev/null 2>&1 || true
      else
        case "$cmdline" in
          "$FILES_DIR/ttyd $EXPECTED_TTYD_ARGS"|"ttyd $EXPECTED_TTYD_ARGS")
            TTYD_RUNNING=1
            ;;
          *)
            kill "$pid" >/dev/null 2>&1 || true
            ;;
        esac
      fi
      ;;
  esac
done
sleep 1
HAS_TTYD_HASH=0
if [ -s /data/adb/ufi-ttyd.sha256 ] && head -n 1 /data/adb/ufi-ttyd.sha256 | tr -d '\r\n ' | grep -Eq '^[0-9a-fA-F]{64}$'; then
  HAS_TTYD_HASH=1
elif grep -Eq '<string name="login_token">[0-9a-fA-F]{64}</string>' /data/data/com.minikano.f50_sms/shared_prefs/kano_ZTE_store.xml 2>/dev/null; then
  HAS_TTYD_HASH=1
fi
if [ "$FW_OK" != "1" ]; then
  echo "ERROR: cellular firewall DROP rule setup failed; refusing to start ttyd on port 1146"
elif [ -z "$TTYD_BIND_IFACE" ]; then
  echo "ERROR: no safe non-cellular bind interface available; refusing to start unbound ttyd on port 1146"
elif [ ! -x "$LOGIN_SCRIPT" ]; then
  echo "ERROR: hardened login script $LOGIN_SCRIPT missing; refusing to invoke APK login.sh with hardcoded fallback password"
elif [ "$HAS_TTYD_HASH" != "1" ]; then
  echo "ERROR: no configured ttyd password hash; refusing to start ttyd on port 1146"
elif [ -x "$FILES_DIR/ttyd" ] && [ "$TTYD_RUNNING" != "1" ]; then
  PATH="$FILES_DIR:$PATH" setsid "$FILES_DIR/ttyd" --writable --port 1146 --interface "$TTYD_BIND_IFACE" "$LOGIN_SCRIPT" </dev/null >>/cache/ufi-tools-ttyd.log 2>&1 &
  t=0
  while [ "$t" -lt 10 ]; do
    if ss -tln 2>/dev/null | grep -q ":1146 "; then
      break
    fi
    sleep 1
    t=$((t + 1))
  done
fi

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
