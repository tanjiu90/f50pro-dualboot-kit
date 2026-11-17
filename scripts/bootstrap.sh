#!/usr/bin/env bash
set -euo pipefail

# Cross-platform host bootstrap for f50pro-dualboot-kit (Linux x86_64/arm64, macOS Universal, Android Termux).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

HOST_PLATFORM="auto"
PROFILE="all"
PACKS=""
NO_OPENCLASH=0
LIST_PACKS=0
INTERACTIVE=0
SKIP_VENV=0

usage() {
  cat <<'EOF'
Usage: scripts/bootstrap.sh [options]

Options:
  --platform <id>     auto | linux-x64 | linux-arm64 | macos | android-arm64 | win64 | all | none
  --profile <id>      all | 1-android-ufi | 2-dual-stock-openwrt | 3-dual-full | none
  --packs <a,b,...>   Explicit manifest pack keys (comma-separated)
  --no-openclash      Skip optional OpenClash offline archive (~36 MiB)
  --list-packs        Show available release packs, sizes, SHA-256 digests, and exit
  -i, --interactive   Launch interactive download selection menu
  --skip-venv         Use system python3 instead of creating .venv
  -h, --help          Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --platform) HOST_PLATFORM="${2:-}"; shift 2 ;;
    --profile) PROFILE="${2:-}"; shift 2 ;;
    --packs) PACKS="${2:-}"; shift 2 ;;
    --no-openclash) NO_OPENCLASH=1; shift ;;
    --list-packs) LIST_PACKS=1; shift ;;
    -i|--interactive) INTERACTIVE=1; shift ;;
    --skip-venv) SKIP_VENV=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

detect_plat() {
  if [[ -n "${TERMUX_VERSION:-}" || -d "/data/data/com.termux/files/usr" || -f "/system/build.prop" ]]; then
    echo "android-arm64"
    return
  fi
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os" in
    Darwin) echo "macos" ;;
    Linux)
      case "$arch" in
        aarch64|arm64) echo "linux-arm64" ;;
        *) echo "linux-x64" ;;
      esac
      ;;
    *) echo "linux-x64" ;;
  esac
}

DETECTED="$(detect_plat)"
PY_BIN="$(command -v python3 || command -v python || true)"
if [[ -z "$PY_BIN" ]]; then
  echo "ERROR: python3 is required (Python 3.10+)." >&2
  exit 1
fi

if [[ "$LIST_PACKS" -eq 1 ]]; then
  exec "$PY_BIN" "$ROOT/scripts/fetch_assets.py" --list-packs
fi

if [[ "$SKIP_VENV" -eq 1 ]]; then
  VENV_PY="$PY_BIN"
else
  VENV_DIR="$ROOT/.venv"
  if [[ ! -x "$VENV_DIR/bin/python" ]]; then
    if [[ "$DETECTED" == "android-arm64" ]]; then
      "$PY_BIN" -m venv --system-site-packages "$VENV_DIR"
    else
      "$PY_BIN" -m venv "$VENV_DIR"
    fi
  fi
  VENV_PY="$VENV_DIR/bin/python"
  if ! "$VENV_PY" -c "import paramiko, serial, pytest" >/dev/null 2>&1; then
    "$VENV_PY" -m pip install --upgrade pip >/dev/null 2>&1 || true
    if ! "$VENV_PY" -m pip install paramiko pyserial pytest; then
      if [[ "$DETECTED" == "android-arm64" ]]; then
        echo "" >&2
        echo "Termux pip install hint: install prebuilt crypto packages first:" >&2
        echo "  pkg update && pkg install -y python python-cryptography python-pip clang rust libffi openssl android-tools termux-api" >&2
      fi
      exit 1
    fi
  fi
fi

FETCH_ARGS=("$ROOT/scripts/fetch_assets.py")
if [[ "$INTERACTIVE" -eq 1 ]]; then
  FETCH_ARGS+=("--interactive")
else
  FETCH_ARGS+=("--host-platform" "$HOST_PLATFORM" "--profile" "$PROFILE")
  if [[ -n "$PACKS" ]]; then
    IFS=',' read -r -a pack_arr <<< "$PACKS"
    FETCH_ARGS+=("--packs" "${pack_arr[@]}")
  fi
  if [[ "$NO_OPENCLASH" -eq 1 ]]; then
    FETCH_ARGS+=("--no-openclash")
  fi
fi

"$VENV_PY" "${FETCH_ARGS[@]}"

ADB_KEY_DIR="$HOME/.android"
ADB_PUB="$ADB_KEY_DIR/adbkey.pub"
if [[ ! -f "$ADB_PUB" ]]; then
  ADB_BIN=""
  for cand in \
    "$ROOT/build/runtime-tools/host-tools-linux-x64/platform-tools/adb" \
    "$ROOT/build/runtime-tools/host-tools-macos/platform-tools/adb" \
    "$(command -v adb 2>/dev/null || true)" \
    "$(command -v termux-adb 2>/dev/null || true)"; do
    if [[ -n "$cand" && -x "$cand" ]]; then
      ADB_BIN="$cand"
      break
    fi
  done
  if [[ -n "$ADB_BIN" ]]; then
    mkdir -p "$ADB_KEY_DIR"
    "$ADB_BIN" keygen "$ADB_KEY_DIR/adbkey"
  fi
fi

echo ""
echo "Bootstrap completed on detected platform: $DETECTED"
case "$DETECTED" in
  linux-x64|linux-arm64)
    echo "Linux tip: install udev rules for non-root USB flashing & RNDIS/NCM:"
    echo "  sudo cp assets/udev/99-unisoc-f50pro.rules /etc/udev/rules.d/ && sudo udevadm control --reload-rules && sudo udevadm trigger"
    if [[ "$DETECTED" == "linux-arm64" ]] && ! command -v adb >/dev/null 2>&1; then
      echo "Linux ARM64 note: install system adb (e.g., sudo apt-get install -y android-tools-adb)."
    fi
    ;;
  macos)
    echo "macOS tip: macOS raw USB BootROM/AutoD claiming requires root (sudo). Example:"
    echo "  sudo .venv/bin/python scripts/kit.py backup --output-dir build/device-session/backup"
    ;;
  android-arm64)
    echo "Android Termux note:"
    echo "  - Rooted host phone: full BROM/SPRD4 (--kickto 2) supported via --spd-mode su."
    echo "  - Non-root host phone: install Termux:API + termux-adb; --spd-mode termux-usb (--usb-fd) is experimental and requires target already in 1782:4d00 autodloader mode (no auto --kickto 2 reconnect)."
    ;;
esac
echo "Next: $VENV_PY scripts/kit.py preflight"
