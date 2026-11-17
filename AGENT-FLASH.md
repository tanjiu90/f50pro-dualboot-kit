# Autonomous AI Agent Flashing SOP (`AGENT-FLASH.md`)

This document defines the strict deterministic execution protocol for any AI coding Agent given `https://github.com/tanjiu90/f50pro-dualboot-kit` to flash and provision a **brand-new ZTE F50 Pro (`MU3356`)** in a clean environment.

---

## 0. Mandatory Agent Guardrails (Non-Negotiable)

1. **NEVER touch `FORBIDDEN_PARTITIONS`**: Never read-modify-write or flash `splloader`, `prodnv`, `calinv`, `ztecfg`, `ztepersist`, `persist`, `miscdata`, `super`, `userdata`, or modem NV/calibration partitions.
2. **Mandatory Full Verified BROM Backup First**: Never proceed to `flash` or `provision` without a verified local BROM backup (`verification_report.json` with `checks_passed: true`) dumped from **this exact physical device**. Live `kit.py backup` enters `SPRD4:AutoD` and resets the device, so it explicitly requires `--authorize-device-reboot`; offline `kit.py plan` / `kit.py auto` (without `--execute`) never triggers `REBOOT_DEVICE`, downloads, or device mutations.
3. **Never Flash Foreign Images (Per-Unit Identity Bound)**: Always run `kit.py inspect` and `kit.py build` against the target device's own backup so `flash_plan.json` embeds the cryptographic `unit_identity_digest` (`ztecfg`/`persist` SHA-256 + GPT), `trustos_noavb.img` derives from its own `sml_a` + `trustos_a`, and `vendor_boot_b` retains its exact DTB. `flash_images.py` refuses mismatched targets unless explicitly acknowledged.
4. **Dry-Run & Failure Recovery Gate**: Execute `kit.py plan` (or `kit.py auto` **without `--execute`**) and `kit.py flash --plan ...` (without `--execute`) first, present the partition allowlist/summary, `unit_identity_digest`, detected `board_id`, and selected profile to the user, and obtain explicit approval before `--execute`. If any write/readback/GPT check fails during `flash --execute`, the tool **stops immediately without calling `reset` or switching slots** and records state in `flash_state.json` — inspect `flash_failure_report.json` before touching hardware.
5. **Host Network & USB Mode Preservation**: Only verified F50 Pro USB interfaces (`1D6B:0104`) are isolated by `host_network.py` (using snapshots and never modifying phone USB tethering, USB-C docks, or Wi-Fi `192.168.0.1`). `provision-openwrt` preserves working USB modes (`ncm`/`ecm`/`rndis`) unless `--usb-net-mode` explicitly changes it.
6. **Zero PII / Credentials in Commits**: Never commit anything under `build/`, `bundle-cache/`, `dist/`, `.venv/`, backup directories, `openwrt-credentials.json`, or personal subscriptions into Git.
7. **Download Mode Boundary (`SPRD4:AutoD` vs `SPRD3`)**: `kit.py backup` and `kit.py flash` use **`SPRD4:AutoD`** (U-Boot `autodloader`), which requires intact on-device `SPL + U-Boot`. Bare-metal `SPRD3` BootROM unbricking if `SPL` or active `U-Boot` fails to load is **not bundled** (no `UMS9632` signed `FDL1/FDL2` or factory `.pac`), and `r all` does not dump `splloader_bak` (`eMMC boot1`). Verify `uboot_b` readback succeeds before switching slots.

---

## Step 1: Pinned Clone, Bootstrap (Per-Platform Selectable) & Strict Preflight

Pin an explicit Release tag (or verified commit SHA) — never pull mutable `main` unpinned in automated flashing — and select **only** the packs needed by the current host OS and requested profile *(note: `release-manifest.json` validates SHA-256 integrity, not cryptographic publisher signatures)*:

- **Windows PC**:
  ```powershell
  git clone --branch v1.1.0 --depth 1 https://github.com/tanjiu90/f50pro-dualboot-kit.git
  cd f50pro-dualboot-kit
  .\scripts\bootstrap.ps1 -Profile <PROFILE_ID>  # add -SkipOpenClash if unused
  .\.venv\Scripts\python.exe -m pytest -v
  .\.venv\Scripts\python.exe scripts\kit.py preflight --strict --operation auto --profile <PROFILE_ID>
  ```
- **Linux (`x86_64` / `arm64`) / macOS (`Universal`) / Android Termux (`arm64`)**:
  ```bash
  git clone --branch v1.1.0 --depth 1 https://github.com/tanjiu90/f50pro-dualboot-kit.git
  cd f50pro-dualboot-kit
  bash scripts/bootstrap.sh --profile <PROFILE_ID>  # add --no-openclash if unused
  .venv/bin/python -m pytest -v
  .venv/bin/python scripts/kit.py preflight --strict --operation auto --profile <PROFILE_ID>
  ```

Expected assertions before proceeding:
- All `pytest` unit/safety/sanitization tests pass (`0` failures).
- `preflight` confirms `paramiko=true`, `serial=true`, `spd_dump` resolved (`spd_dump_termux_usb` also checked on `android-arm64`), `adb` resolved, and `adb_pubkey_present=true`.
- Host-specific USB access checks:
  - **Windows**: `host-tools-win64\qmk_driver_installer\install_connected_drivers.bat` (or `install_unisoc_drivers.bat`) installs WinUSB for `1782:4D00` / `1782:4D03`.
  - **Linux**: install `assets/udev/99-unisoc-f50pro.rules` into `/etc/udev/rules.d/` (or pass `--spd-mode sudo` in Steps 2 & 5). On `linux-arm64`, install distro `adb` (`android-tools-adb`).
  - **macOS**: pass `--spd-mode sudo` (or run under `sudo`) during Steps 2 & 5 because macOS `libusb` requires root to claim `1782:4D00`.
  - **Android Termux**: use `--spd-mode su` on rooted phones (full `--kickto 2` support); `--spd-mode termux-usb` on non-root phones is **EXPERIMENTAL** and requires target already enumerated in `1782:4D00` autodloader mode + `--adb-serial 192.168.0.1:5555` (or `termux-adb`).

---

## Step 2: Capture & Verify Device Backup (Read-Only BROM Dump)

Ask the user for:
- Which profile they want: `1-android-ufi`, `2-dual-stock-openwrt`, or `3-dual-full` (default recommendation: `3-dual-full`)
- Whether to include clean offline OpenClash (`--openclash`)
- Stock ZTE WebUI password (if automated reboot-into-BROM is desired; otherwise instruct user to trigger BROM physically when `Waiting for boot_diag` appears)

Run read-only BROM dump (on macOS or Linux without udev rules add `--spd-mode sudo`; on rooted Android Termux add `--spd-mode su`; on non-root Termux add `--spd-mode termux-usb --usb-dev /dev/bus/usb/XXX/YYY` with target already in `1782:4d00` autodloader):

```powershell
.\.venv\Scripts\python.exe scripts\kit.py backup `
  --output-dir build\device-session\backup `
  --authorize-device-reboot `
  --webui-password "<WEBUI_PASSWORD>"
```

Verify output JSON shows `"checks_passed": true` and `SHA256SUMS.txt` was written.

---

## Step 3: Inspect Device Variant & Build Offline Images

```powershell
.\.venv\Scripts\python.exe scripts\kit.py inspect `
  --backup-dir build\device-session\backup `
  --out build\device-session\build\hardware_facts.json

.\.venv\Scripts\python.exe scripts\kit.py build `
  --backup-dir build\device-session\backup `
  --profile <PROFILE_ID> `
  --out-dir build\device-session\build
```

Inspect `hardware_facts.json` and confirm:
- `trustos_a.patch_code_offset` found cleanly (typically `0x981ec` on `board_id=1` 内置双 eSIM 版 or `0x9856c` on `board_id=6` 插卡版; both valid if unique match == 1).
- `init_boot_a.sdk == "35"` (Android 15).
- `misc.suffix == "_a"`.

---

## Step 4: Safety Gate (Mandatory Dry-Run Check)

```powershell
.\.venv\Scripts\python.exe scripts\kit.py flash `
  --plan build\device-session\build\flash_plan.json
```

Present the dry-run JSON output to the user:
- Profile ID (`1-android-ufi` / `2-dual-stock-openwrt` / `3-dual-full`)
- Partition write list & total MiB (`0` writes to `FORBIDDEN_PARTITIONS`, `0` slot `_a` writes if Profile 2)
- Backup directory location

Wait for confirmation, then proceed to Step 5.

---

## Step 5: Flash with Readback Verification

```powershell
.\.venv\Scripts\python.exe scripts\kit.py flash `
  --plan build\device-session\build\flash_plan.json `
  --webui-password "<WEBUI_PASSWORD>" `
  --execute
```

> Pass `--spd-mode sudo` (macOS/Linux without udev) or `--spd-mode su` / `--spd-mode termux-usb` (Android Termux) matching Step 2.

Confirm output reports `"status": "FLASH_AND_READBACK_VERIFIED"`. Every written partition is automatically read back and SHA-256 verified before moving `misc+2048` (`BCAB`).

---

## Step 6: OS Provisioning

### If Profile `2-dual-stock-openwrt` or `3-dual-full` (OpenWrt `_b`):

```powershell
.\.venv\Scripts\python.exe scripts\kit.py provision-openwrt `
  --profile <PROFILE_ID> `
  --wifi-ssid F50Pro-OpenWrt `
  --generate-password `
  --out-dir build\device-session\build `
  --openclash   # include only if requested
```

Confirm:
- `board_id` reported (`1` or `6`).
- `rootfs_grow.filesystem_bytes == 2147483648` (`2 GiB`).
- `wifi_device == "phy0-ap0"` and `f50pro-leds` active.
- `buttons.long_action == "system-switch"` (`5s` physical button configured).
- Live `known-good-b-bcab.bin` captured (`suffix == "_b"`).
- Report saved `openwrt-credentials.json` path (NEVER paste raw secrets into Git).

### If Profile `1-android-ufi` or `3-dual-full` (Android `_a`):

```powershell
.\.venv\Scripts\python.exe scripts\kit.py provision-android `
  --plan build\device-session\build\flash_plan.json `
  --credentials-file build\device-session\build\openwrt-credentials.json
```

Confirm:
- Magisk 28103 10+1 runtime staged & SQLite policy seeded (`uid=2000` + `com.minikano.f50_sms` UID).
- `UFI-TOOLS` `:2333` & `ttyd` `:1146` verified listening **after cold reboot**.
- For `3-dual-full`: `/data/adb/switch-to-openwrt.sh --dry-run` succeeded and device returned cleanly to OpenWrt `_b` (unless `--stay-android` was explicitly requested).

---

## Step 7: Final Live E2E Audit (Strict Non-Zero Exit Code on Failure)

```powershell
.\.venv\Scripts\python.exe scripts\kit.py verify `
  --profile <PROFILE_ID> `
  --credentials-file build\device-session\build\openwrt-credentials.json `
  --openclash `
  --out build\device-session\final_verify_report.json
```

Verify in final output (`exit code == 0` and `overall_status == "PASS"`):
1. `checks.host_route_isolation.status == "PASS"` (`host_routes.usb_default_route_leak == false`)
2. Real boot evidence checked (`/proc/cmdline` or `bootargs`, never `wifi_device` spoofed as slot; inactive slot under `3-dual-full` marked `NOT_TESTED`, unused profile sides marked `NOT_APPLICABLE`)
3. Report final summary concisely with profile, `board_id`, backup path, credentials file path (if generated), and live switch instructions (`5s` long press physical key).
